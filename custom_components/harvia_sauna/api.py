from pycognito import Cognito
import asyncio
import base64
import json
import logging
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import quote

import aiohttp
import botocore.exceptions
from pycognito import Cognito

from home.helpers.aiohttp_client import async_get_clientsession

from .constants import DOMAIN, REGION

_LOGGER = logging.getLogger(____)

# Timeout for all outgoing HTTP requests.
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)

# Renew the id_token when it expires within this many seconds.
_TOKEN_RENEW_MARGIN = 300  # 5 minutes

ITIVE_KEYS = ("token", "authorization", "password", "secret", "credential")


def _redact(obj: Any) -> Any:
    """Recursively redact sensitive-looking values before logging."""
    if isinstance(obj, dict):
        return {
            k: ("***REDACTED***" if any(s in.lower() for s in _SENSITIVE_KEYS) else _redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


def _jwt_exp(token: str) -> Optional[float]:
    """Extract the `exp` claim from a JWT without verifying the signature.

    Safe here because the token was obtained directly from Cognito and we
    only use it to decide *when* to renew, not to trust the contents.
    """
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except Exception:  # noqa: BLE001 - malformed token should never crash HA
        return None


class HarviaApiError(Exception):
    """Raised when the Harvia cloud API returns an unexpected response."""


class HarviaAuthError(HarviaApiError):
    """Raised when authentication/authorization fails."""


class HarviaSaunaAPI:
    def __init__(self, username: str, password: str, hass) -> None:
        self.username = username
        self.password = password
        self.hass = hass
        self.endpoints: Optional[Dict[str, Any]] = None
        self.client:[Cognito] = None
        self.token_data: Optional[Dict[str, str]] = None

        # Guards against concurrent endpoint fetching / token renewal.
        self._endpoints_lock = asyncio.Lock()
        self._token_lock = asyncio.Lock()

        # Cache for websocket connection parameters per endpoint key.
        self._ws_params: Dict[str, Dict[str, str]] = {}

    # ------------------------------------------------------------------
    # Endpoint discovery
    # ------------------------------------------------------------------

    async def getEndpoints(self) -> Dict[str, Any]:
        """Fetch endpoints concurrently and cache them."""
        if self.endpoints is not None:
            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "Endpoints already exist and were not fetched: %s",
                    json.dumps(_redact(self.endpoints), indent=4),
                )
            return self.endpoints

        async with self._endpoints_lock:
            # Re-check after acquiring the lock (another task may have won).
            if self.endpoints is not None:
                return self.endpoints

            _LOGGER.debug("Fetching endpoints.")
            session = async_get_clientsession(self.hass)

            async def _fetch(ep: str) -> tuple:
                url = f"https://prod.myharvia-cloud.net/{ep}/endpoint"
                _LOGGER.debug("Fetching endpoint: %s", url)
                async with session.get(url, timeout=_HTTP_TIMEOUT) as response:
                    if response.status < 200 or response.status >= 300:
                        raise HarviaApiError(
                            f"HTTP {response.status} while fetching endpoint '{ep}'"
                        )
                    return ep, await response.json()

            # Fetch all endpoints in parallel; a failure raises before anything
            # is cached, so we never end up with a half-pop dict.
            results = await asyncio.gather(
                *(_fetch(ep) for ep in ("users", "device", "events", "data"))
            )
            self.endpoints = dict(results)

            # Basic schema validation of the discovery response.
            required = {"userPoolId", "clientId", "identityPoolId"}
            if not required.issubset(self.endpoints.get("users", {})):
                raise HarviaApiError(
 "Unexpected endpoint discovery response: missing required keys in 'users'"
                )

            _LOGGER.info("Endpoints successfully fetched and saved.")
            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "Endpoint data: %s", json.dumps(_redact(self.endpoints), indent=4)
                )

        return self.endpoints

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def getClient(self) -> Cognito:
        if self.client is None:
            endpoints = await self.getEndpoints()
            user_pool_id = endpoints["users"]["userPoolId"]
            client_id = endpoints["users"]["clientId"]
            # NOTE: variable kept for manual review — identityPoolId is a pool
            # identifier, not an id_token; verify whether it belongs here.
            id_token = endpoints["users"]["identityPoolId"]

            u = await self.hass.async_add_executor_job(
                lambda: Cognito(
                    user_pool_id,
                    client_id,
                    username=self.username,
                    user_pool_region=REGION,
                    id_token=id_token,
                )
            )
            self.client = u

        return self.client

    async def authenticate(self) -> bool:
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
            _LOGGER.info("Authentication failed: %s", e)
            return False

        self.token_data = {
            "access_token": u.access_token,
            "refresh_token": u.refresh_token,
            "id_token": u.id_token,
        }

        _LOGGER.info("Authentication successful, tokens saved.")
        return True

    async def getAuthenticatedClient(self) -> Cognito:
        client = await self.getClient()
        if not await self.authenticate():
            raise HarviaAuthError("Authentication failed")
        return client

    async def checkAndRenewTokens(self) -> None:
        """Renew tokens if needed; serialized to avoid concurrent renewals."""
        async with self._token_lock:
            client = await self.getAuthenticatedClient()
            current_id_token = self.token_data["id_token"] if self.token_data else None

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

    def _token_expires_soon(self) -> bool:
        """Return True if the cached id_token is missing or near expiry."""
        if.token_data is None or "id_token" not in self.token_data:
            return True
        exp = _jwt_exp(self.token_data["id_token"])
        if exp is None:
            return True
        return time.time() + _TOKEN_RENEW_MARGIN >= exp

    async def getIdToken(self) -> str:
        """Return a valid id_token, renewing only when to expiry."""
        if self._token_expires_soon():
            await self.checkAndewTokens()
        return self.token_data["id_token"]

    async def getHeaders(self) -> Dict[str, str]:
        idToken = await self.getIdToken()
        return {"authorization": idToken}

    # ------------------------------------------------------------------
    # GraphQL requests
    # ------------------------------------------------------------------

    async def endpoint(self, endpoint: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """Call a Harvia GraphQL endpoint and return the parsed JSON response."""
        if self.endpoints is None:
            await self.getEndpoints()

        session = async_get_clientsession(self.hass)
        url = self.endpoints[endpoint]["endpoint"]

        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug("Endpoint on '%s'", url)
            _LOGGER.debug("\tQuery: %s", json.dumps(_redact(query), indent=4        async def _do_request() -> Dict[str, Any]:
            headers = await self.getHeaders()
            async with session.post(
                url, json=query, headers=headers, timeout=_HTTP_TIMEOUT
            ) as response:
                # Read body once so we can log useful info on errors.
                text = await response.text()

                if response.status in (401, 403):
                    raise HarviaAuthError(
                        f"Unauthorized ({response.status}) calling {endpoint}"
                    )

                if response.status< 200 or response.status >= 300:
                    raise HarviaApiError(
                        f"HTTP {response.status} calling {endpoint}: {text[:500]}"
                    )

                try:
                    data = json.loads(text) if text else {}
                except json.JSONDecodeError as e:
                    raise HarviaApiError(
                        f"Invalid JSON from {endpoint} (HTTP {response.status}): {text[:500]}"
                    ) from e

                if _LOGGER.isEnabledFor(logging.DEBUG):
                    _LOGGER.debug(
                        "\tReturned data: %s",.dumps(_redact(data), indent=4)
                    )
                return data

        # First attempt; on auth failure, force renewal and retry once.
        try:
            return await _do_request()
        except HarviaAuthError:
            _LOGGER.info("Authorization failed; renewing token and retrying once.")
            try:
                # Force renewal even if local exp check thinks it's fine.
                self.token_data = None
                await self.checkAndRenewTokens()
            except HarviaAuthError:
                raise
            except Exception as e:  # noqa: BLE001
                raise HarviaAuthError(f"Token renewal failed: {e}") from e
            return await _do_request()

    # ------------------------------------------------------------------
    # Websocket helpers
    # ------------------------------------------------------------------

    async def getWebsocketEndpoint(self, endpoint: str) -> dict:
        ep = self.endpoints[endpoint]["endpoint"]
        regex = r"^https:\/\/(.+)\.appsync-api\.(.+)\/graphql$"
        regexReplace = r"wss://\1.appsync-realtime-api.\2/graphql"
        regexReplaceHost = r"\1.appsync-api.\2"
        wssUrl = re.sub(regex, regexReplace, ep)
        host = re.sub(regex, regexReplaceHost, ep)
        return {"wssUrl": wssUrl, "host": host}

    async def getWebsockUrlByEndpoint(self, endpoint: str) -> str:
        websockEndpoint = await.getWebsocketEndpoint(endpoint)
        id_token = await self.getIdToken()
        headerPayload = {"Authorization": id_token, "host": websockEndpoint["host"]}
        encoded_header = base64.b64encode(json.dumps(headerPayload).encode())
        wssUrl = (
            websockEndpoint["wssUrl"]
            + "?header="
            + quote(encoded_header.decode("utf-8"))
            + "&payload=e30="
        )
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
        """
        id_token = await self.getIdToken()

        # NOTE: AWS Amplify adds an x-amz-user-agent in the extensions. It is
        # not required for AppSync, but some backends/logs may expect it.
        # We keep it for maximum compatibility.
        extensions = {
            "authorization": {
                "Authorization": id_token,
                "host": host,
                "x-amz-user-agent": "aws-amplify2.0.5 react-native",
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

        The host part is deterministic per endpoint and cached; only the
        (token-bearing) URL is rebuilt so it always uses a fresh token.

        Example endpoint keys: 'device', 'data', 'events'.
        """
        if self.endpoints is None:
            await self.getEndpoints()

        if endpoint not in self._ws_params:
            websock = await self.getWebsocketEndpoint(endpoint)
            self._ws_params[endpoint] = {"host": websock["host"]}

        wss_url = await self.getWebsockUrlByEndpoint(endpoint)
        return {"wssUrl": wss_url, "host": self._ws_params[endpoint]["host"]}
        return {"wssUrl": wss_url, "host": self._ws_params[endpoint]["host"]}
