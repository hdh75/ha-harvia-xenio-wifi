from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import HVACMode, ClimateEntityFeature
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.helpers.device_registry import DeviceInfo
from .constants import DOMAIN, _LOGGER

class HarviaThermostat(ClimateEntity):
    def __init__(self, device, name, sauna):
        self._device = device
        self._name = name + ' Thermostat'
        self._current_temperature = None
        self._target_temperature = None
        self._hvac_mode = HVACMode.OFF
        self._device_id = device.id + '_termostat'
        self._sauna = sauna
        self._attr_unique_id = device.id + '_termostat'
        # Bind this entity to a Home Assistant device
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.id)},
            name=getattr(device, "name", None) or name,
            manufacturer="Harvia",
            model=getattr(device, "model", None) or "Xenio WiFi",
        )

    @property
    def min_temp(self):
        # Use device minTemp if available, else default to 40
        min_temp = getattr(self._device, 'minTemp', None)
        try:
            return float(min_temp) if min_temp is not None else 40
        except Exception:
            return 40

    @property
    def max_temp(self):
        # Use device maxTemp if available, else default to 110
        max_temp = getattr(self._device, 'maxTemp', None)
        try:
            return float(max_temp) if max_temp is not None else 110
        except Exception:
            return 110

    @property
    def name(self):
        return self._name

    @property
    def temperature_unit(self):
        return UnitOfTemperature.CELSIUS

    @property
    def current_temperature(self):
        return self._current_temperature

    @property
    def target_temperature(self):
        return self._target_temperature

    @property
    def hvac_mode(self):
        return self._hvac_mode

    @property
    def hvac_modes(self):
        return [HVACMode.OFF, HVACMode.HEAT]

    async def async_added_to_hass(self):
        """Actions to perform when the entity is added to Home Assistant."""
        self._device.thermostat = self
        await self._device.update_ha_devices()

    async def async_set_temperature(self, **kwargs):
        """Set the target temperature."""
        if (temperature := kwargs.get(ATTR_TEMPERATURE)) is not None:
            self._target_temperature = temperature
            # Add logic here to change the target temperature on the device
            await self._device.set_target_temperature(temperature)
            if self.enabled:
                self.async_write_ha_state()

    async def async_set_hvac_mode(self, hvac_mode):
        """Set the HVAC mode."""
        active = False
        self._hvac_mode = hvac_mode
        if self.enabled:
            self.async_write_ha_state()

        if hvac_mode == HVACMode.HEAT:
            await self._device.set_active(True)
            active = True
        elif hvac_mode == HVACMode.OFF:
            await self._device.set_active(False)
            active = False

        if self._device.powerSwitch is not None:
            self._device.powerSwitch._is_on = active
            await self._device.powerSwitch.update_state()

    @property
    def supported_features(self):
        return ClimateEntityFeature.TARGET_TEMPERATURE

    async def update_state(self):
        # Avoid writing state for disabled entities (HA 2026+ warns about this)
        if not self.enabled:
            return
        self.async_write_ha_state()

    async def async_update(self):
        """Update the current state of the thermostat."""
        # ClimateEntity is polled by Home Assistant. Read the values from the
        # device here so they are refreshed independently of light/service calls.
        fetch_current = getattr(self._device, "fetch_current_temperature", None)
        if callable(fetch_current):
            current_temperature = await fetch_current()
            if current_temperature is not None:
                self._current_temperature = float(current_temperature)

        fetch_target = getattr(self._device, "fetch_target_temperature", None)
        if callable(fetch_target):
            target_temperature = await fetch_target()
            if target_temperature is not None:
                self._target_temperature = float(target_temperature)

async def async_setup_entry(hass, entry, async_add_entities):
    """Set up the Harvia thermostats."""
    # Add logic here to retrieve your devices.
    # For now we manually add thermostats as an example.
    devices = await hass.data[DOMAIN]['api'].get_devices()
    theromostats = []

    for device in devices:
        _LOGGER.debug(f"Loading thermostats for device: {device.name}")
        device_theromostats = await device.get_thermostats()
        for device_theromostat in device_theromostats:
            theromostats.append(device_theromostat)

    async_add_entities(theromostats, True)
