"""Select entities for Scent Diffuser."""
from __future__ import annotations

import logging

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, DeviceType, GIZ_MODE_PL, GIZ_MODE_PE
from .device import ScentDiffuserDevice

_LOGGER = logging.getLogger(__name__)

MODE_CUSTOM = "Custom"
MODE_LEVEL = "Level"

GIZ_MODE_GEAR = "Gear"
GIZ_MODE_TIMER = "Timer"

GIZ_ENERGY_SPORT = "Sport"
GIZ_ENERGY_COMFORT = "Comfort"
GIZ_ENERGY_ECO = "Eco"
GIZ_ENERGY_OPTIONS = [GIZ_ENERGY_SPORT, GIZ_ENERGY_COMFORT, GIZ_ENERGY_ECO]

GIZ_CONCENTRATION_LOW = "Low"
GIZ_CONCENTRATION_MEDIUM = "Medium"
GIZ_CONCENTRATION_HIGH = "High"
GIZ_CONCENTRATION_OPTIONS = [
    GIZ_CONCENTRATION_LOW, GIZ_CONCENTRATION_MEDIUM, GIZ_CONCENTRATION_HIGH,
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up select entities."""
    device: ScentDiffuserDevice = hass.data[DOMAIN][entry.entry_id]

    entities: list[SelectEntity] = []
    # The Custom/Level schedule mode is an AK V3 concept. The entity stays
    # unavailable until the device identifies as V3 on first connect, so it's
    # safe to register for the whole AK family (V2 simply never exposes it).
    if device.device_type == DeviceType.SCENT_MARKETING_AK:
        entities.append(ScheduleModeSelect(device, entry))

    if device.device_type == DeviceType.GIZWITS_BLE:
        entities.append(GizModeSelect(device, entry))
        entities.append(GizEnergyModeSelect(device, entry))
        entities.append(GizConcentrationSelect(device, entry))

    async_add_entities(entities)


class ScheduleModeSelect(SelectEntity):
    """Custom vs Level schedule-mode selector for AK V3 (@Mins95, #8).

    The integration already switches mode implicitly (setting a Work/Pause
    Duration selects Custom, setting Intensity selects Level). This makes the
    mode an explicit control so the user can pin it without accidentally
    flipping it via a side-effect of another change.
    """

    _attr_has_entity_name = True
    _attr_name = "Schedule mode"
    _attr_icon = "mdi:tune-variant"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_options = [MODE_LEVEL, MODE_CUSTOM]

    def __init__(self, device: ScentDiffuserDevice, entry: ConfigEntry) -> None:
        self._device = device
        self._attr_unique_id = f"{device.unique_id}_schedule_mode"
        self._attr_device_info = device.device_info
        device.register_state_callback(self._on_state_update)

    def _on_state_update(self) -> None:
        if self.hass is None:
            return
        self.async_write_ha_state()

    @property
    def current_option(self) -> str | None:
        mode = self._device.state.schedule_custom_mode
        if mode is None:
            return None
        return MODE_CUSTOM if mode else MODE_LEVEL

    @property
    def available(self) -> bool:
        return (
            self._device.available
            and self._device.protocol_is_v3
            and self._device.state.schedule_custom_mode is not None
        )

    async def async_select_option(self, option: str) -> None:
        await self._device.set_schedule_mode(option == MODE_CUSTOM)


class GizModeSelect(SelectEntity):
    """Schedule engine selector for Gizwits BLE (`devMode`): PL "Gear"
    (fixed intensity per slot) vs PE "Timer" (work/pause seconds per
    slot). Setting Intensity implicitly selects Gear; setting Work/Pause
    Duration implicitly selects Timer — this makes the choice explicit.
    """

    _attr_has_entity_name = True
    _attr_name = "Schedule mode"
    _attr_icon = "mdi:tune-variant"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_options = [GIZ_MODE_GEAR, GIZ_MODE_TIMER]

    def __init__(self, device: ScentDiffuserDevice, entry: ConfigEntry) -> None:
        self._device = device
        self._attr_unique_id = f"{device.unique_id}_giz_mode"
        self._attr_device_info = device.device_info
        device.register_state_callback(self._on_state_update)

    def _on_state_update(self) -> None:
        if self.hass is None:
            return
        self.async_write_ha_state()

    @property
    def current_option(self) -> str | None:
        mode = self._device.state.spray_mode
        if mode is None:
            return None
        return GIZ_MODE_GEAR if mode == GIZ_MODE_PL else GIZ_MODE_TIMER

    @property
    def available(self) -> bool:
        return self._device.available

    async def async_select_option(self, option: str) -> None:
        mode = GIZ_MODE_PL if option == GIZ_MODE_GEAR else GIZ_MODE_PE
        await self._device.set_spray_mode(mode)


class GizEnergyModeSelect(SelectEntity):
    """Sport/Comfort/Eco mode selector (Gizwits BLE `devEnergyStatus`)."""

    _attr_has_entity_name = True
    _attr_name = "Energy mode"
    _attr_icon = "mdi:leaf"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_options = GIZ_ENERGY_OPTIONS

    def __init__(self, device: ScentDiffuserDevice, entry: ConfigEntry) -> None:
        self._device = device
        self._attr_unique_id = f"{device.unique_id}_energy_mode"
        self._attr_device_info = device.device_info
        device.register_state_callback(self._on_state_update)

    def _on_state_update(self) -> None:
        if self.hass is None:
            return
        self.async_write_ha_state()

    @property
    def current_option(self) -> str | None:
        mode = self._device.state.energy_mode
        if mode is None or not (0 <= mode < len(GIZ_ENERGY_OPTIONS)):
            return None
        return GIZ_ENERGY_OPTIONS[mode]

    @property
    def available(self) -> bool:
        return self._device.available

    async def async_select_option(self, option: str) -> None:
        await self._device.set_energy_mode(GIZ_ENERGY_OPTIONS.index(option))


class GizConcentrationSelect(SelectEntity):
    """Fragrance concentration selector (Gizwits BLE `oilDepthMode`,
    1=low, 2=medium, 3=high)."""

    _attr_has_entity_name = True
    _attr_name = "Concentration"
    _attr_icon = "mdi:water-percent"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_options = GIZ_CONCENTRATION_OPTIONS

    def __init__(self, device: ScentDiffuserDevice, entry: ConfigEntry) -> None:
        self._device = device
        self._attr_unique_id = f"{device.unique_id}_concentration"
        self._attr_device_info = device.device_info
        device.register_state_callback(self._on_state_update)

    def _on_state_update(self) -> None:
        if self.hass is None:
            return
        self.async_write_ha_state()

    @property
    def current_option(self) -> str | None:
        mode = self._device.state.concentration
        if mode is None or not (1 <= mode <= len(GIZ_CONCENTRATION_OPTIONS)):
            return None
        return GIZ_CONCENTRATION_OPTIONS[mode - 1]

    @property
    def available(self) -> bool:
        return self._device.available

    async def async_select_option(self, option: str) -> None:
        await self._device.set_concentration(GIZ_CONCENTRATION_OPTIONS.index(option) + 1)
