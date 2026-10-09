# Harvia Sauna integration for Home Assistant

Unofficial Home Assistant component for Harvia Sauna (working with Xenio Wifi), using the same API as the MyHarvia App.


## WARNING: Pre-alpha development release

*This component is still in 'pre-alpha' and can exhibit unpredictable behavior. I have tested the component for a few days now and it seems to be quite stable. I have now managed to run the component for a day without it breaking. I would appreciate it if you install the component so that I can gather information and feedback to improve the component. After all, I only have one sauna and without extensive testing it won't get better. Keep an eye on this page..* 

(updated at February 15, 2026)

Components support at the moment:

- Light switch
- Power switch (enables heater)
- Fan switch
- Termostat (current and target temp)
- Door sensor (safety circuit)

## Compatibility
Component has been tested with the Harvia Xenio Wifi (CX001WIFI) and Harvia Cilindro PC90XE, but may also work with other sauna's compatible with the MyHarvia app, as it uses the same API.

## Installation


### Easy Installation via HACS

You can quickly add this repository to HACS by clicking the button below:

[![Open your Home Assistant instance and show the add repository dialog with a specific repository pre-filled.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=hdh75&repository=ha-harvia-xenio-wifi)

**Manual Installation Steps:**

1. Go to HACS in your Home Assistant instance.
2. Click the three dots in the top right and select "Custom repositories".
3. Add this repository URL: `https://github.com/hdh75/ha-harvia-xenio-wifi` as an Integration.
4. Search for "Harvia Sauna" in HACS and install.
5. Restart Home Assistant after installation.

## Configuration

Go to settings, integrations and add 'Harvia Sauna'
Your username and password is corresponding with the MyHarvia app.

## Credits

This integration was developed by Ruben Harms. It uses the unofficial API of Harvia Xenio WiFi controllers and is not directly associated with Harvia.

[home-assistant-harvia-sauna]: https://github.com/hdh75/ha-harvia-xenio-wifi
