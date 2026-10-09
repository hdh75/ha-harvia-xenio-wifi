from pycognito import Cognito
import boto3
import logging
import json
import re
import base64
import botocore.exceptions
from urllib.parse import quote
from typing import Any, Dict, Optional
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .constants import DOMAIN, REGION

_LOGGER = logging.getLogger(__name__)


class HarviaApiError(Exception):
    """Raised when the Harvia cloud API returns an unexpected response."""


class HarviaAuthError(HarviaApiError):
    """Raised when authentication/authorization fails."""


class HarviaSaunaAPI:
    def __init__(self, username, password, hass):
        self.username  = username
        self.password  = password
        self.hass = hass
        self.endpoints = None
        self.client = None
        self.token_data = None

    async def getEndpoints(self):
        """Fetch endpoints and cache them if they do not already exist."""
        _LOGGER.debug("Fetching endpoints.")

        if self.endpoints is None:
            self.endpoints = {}
            session = async_get_clientsession(self.hass)
            endpoints = ["users", "device", "events", "data"]
            for endpoint in endpoints:
                url = f'https://prod.myharvia-cloud.net/{endpoint}/endpoint'
                _LOGGER.debug(f"Fetching endpoint: {url}")
                async with session.get(url) as response:
                    self.endpoints[endpoint] = await response.json()
                    data_string = json.dumps(self.endpoints[endpoint], indent=4)
                    _LOGGER.debug(f"Received data: {data_string}")

            _LOGGER.info("Endpoints successfully fetched and saved.")
        else:
            _LOGGER.info("Endpoints already exist and were not fetched.")
            data_string = json.dumps(self.endpoints, indent=4)
            _LOGGER.debug(f"Endpoint data: {data_string}")

        return self.endpoints

    async def authenticate(self):
        """Authenticate with the service and cache tokens."""
        if self.token_data is not None:
            return True

        u = await self.getClient()
        _LOGGER.debug("Authenticating")

        try:
            await self.hass.async_add_executor_job(

                lambda: u.authenticate(password=self.password)
            )
        except botocore.exceptions.ClientError as e:
            _LOGGER.info("Authentication failed: " + str(e))
            return False

        self.token_data = {
            "access_token": u.access_token,
            "refresh_token": u.refresh_token,
            "id_token": u.id_token,
        }

        _LOGGER.info("Authentication successful, tokens saved.")

        return True

    async def getClient(self) -> Cognito:
        if self.client is None:

            endpoints = await self.getEndpoints()
            user_pool_id = endpoints["users"]["userPoolId"]
            client_id = endpoints["users"]["clientId"]
            id_token = endpoints["users"]["identityPoolId"]

            username =self.username
            u = await self.hass.async_add_executor_job(
                lambda: Cognito(user_pool_id, client_id, username=username, user_pool_region=REGION, id_token=id_token)
            )
            self.client = u

        return self.client

    async def getAuthenticatedClient(self) -> Cognito:
        client = await self.getClient()
        await self.authenticate()
        return client

    async def checkAndRenewTokens(self):
        client = await self.getAuthenticatedClient()
        current_id_token = self.token_data['id_token']
        await self.hass.async_add_executor_job(
            lambda: client.check_token(renew=True)
        )
        self.token_data = {
            "access_token": client.access_token,
            "refresh_token": client.refresh_token,
            "id_token": client.id_token,
        }

        if current_id_token != client.id_token:
            _LOGGER.debug("Token renewed (id_token changed).")

    async def getIdToken(self) -> str:
        await self.checkAndRenewTokens()
        return self.token_data['id_token']

    async def getHeaders(self) -> Dict[str, str]:
        idToken = await self.getIdToken()
        headers = {
            'authorization': idToken
        }
        return headers

    async def endpoint(self, endpoint: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """Call a Harvia GraphQL endpoint and return the parsed JSON response."""
        if self.endpoints is None:
            await self.getEndpoints()

        session = async_get_clientsession(self.hass)
        url = self.endpoints[endpoint]['endpoint']

        queryDump = json.dumps(query, indent=4)
        _LOGGER.debug("Endpoint request on '%s':", url)
        _LOGGER.debug("\tQuery: %s", queryDump)

        async def _do_request() -> Dict[str, Any]:
            headers = await self.getHeaders()
            async with session.post(url, json=query, headers=headers) as response:
                # Read body once so we can log useful info on errors.
                text = await response.text()

                if response.status in (401, 403):
                    raise HarviaAuthError(f"Unauthorized ({response.status}) calling {endpoint}")

                if response.status < 200 or response.status >= 300:
                    raise HarviaApiError(
                        f"HTTP {response.status} calling {endpoint}: {text[:500]}"
                    )

                try:
                    data = json.loads(text) if text else {}
                except json.JSONDecodeError as e:
                    raise HarviaApiError(
                        f"Invalid JSON from {endpoint} (HTTP {response.status}): {text[:500]}"
                    ) from e

                dataString = json.dumps(data, indent=4)
                _LOGGER.debug("\tReturned data: %s", dataString)
                return data

        # First attempt
        try:
            return await _do_request()
        except HarviaAuthError:
            # Tokens may have expired; force renewal and retry once.
            _LOGGER.info("Authorization failed; renewing token and retrying once.")
            await self.checkAndRenewTokens()
            return await _do_request()

    async def getWebsocketEndpoint(self, endpoint: str) -> dict:
        endpoint = self.endpoints[endpoint]['endpoint']
        regex = r"^https:\/\/(.+)\.appsync-api\.(.+)\/graphql$"
        regexReplace = r"wss://\1.appsync-realtime-api.\2/graphql"
        regexReplaceHost = r"\1.appsync-api.\2"
        wssUrl = re.sub(regex, regexReplace, endpoint)
        host = re.sub(regex, regexReplaceHost, endpoint)
        return { 'wssUrl': wssUrl, 'host': host}

    async def getWebsockUrlByEndpoint(self, endpoint) -> str:
        websockEndpoint = await self.getWebsocketEndpoint(endpoint)
        id_token = await self.getIdToken()
        headerPayload = {"Authorization":id_token,"host":websockEndpoint['host']}
        encoded_header = base64.b64encode(json.dumps(headerPayload).encode())
        wssUrl = websockEndpoint['wssUrl']+ '?header='+ quote(encoded_header)+'&payload=e30='
        return wssUrl

    async def get_appsync_ws_start_message(
        self,
        query: str,
        variables: Optional[Dict[str, Any]],
        host: str,
        operation_id: str,
        *,
        operation_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build an AWS AppSync websocket `start` message.

        We keep this logic centralized so we can reuse it for Device/Data/Events
        subscriptions and so logging/redaction can be applied consistently.

        Args:
            query: GraphQL subscription string.
            variables: Variables dict (or None).
            host: The AppSync API host (e.g. `xxxxx.appsync-api.eu-west-1.amazonaws.com`).
            operation_id: Websocket operation id to correlate ACK/data.
            operation_name: Optional GraphQL operation name.

        Returns:
            Dict representing the websocket frame to send.
        """
        id_token = await self.getIdToken()

        # NOTE: AWS Amplify adds an x-amz-user-agent in the extensions. It is
        # not required for AppSync, but some backends/logs may expect it.
        # We keep it for maximum compatibility.
        extensions = {
            "authorization": {
                "Authorization": id_token,
                "host": host,
                "x-amz-user-agent": "aws-amplify/2.0.5 react-native",
            }
        }

        payload_obj: Dict[str, Any] = {
            "query": query,
            "variables": variables or {},
        }
        if operation_name:
            payload_obj["operationName"] = operation_name

        return {
            "id": operation_id,
            "type": "start",
            "payload": {
                # AppSync expects `data` to be a JSON *string* containing the gql payload.
                "data": json.dumps(payload_obj),
                "extensions": extensions,
            },
        }

    async def get_ws_connection_params(self, endpoint: str) -> Dict[str, str]:
        """Return websocket URL + host for an endpoint key in `self.endpoints`.

        Example endpoint keys: 'device', 'data', 'events'.
        """
        if self.endpoints is None:
            await self.getEndpoints()

        websock = await self.getWebsocketEndpoint(endpoint)
        wss_url = await self.getWebsockUrlByEndpoint(endpoint)
        return {"wssUrl": wss_url, "host": websock["host"]}
