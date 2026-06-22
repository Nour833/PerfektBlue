"""BlueZ D-Bus discovery backend using dbus-next."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextlib import suppress
from typing import Any, cast

from perfektblue.bluetooth.base import BluetoothBackend
from perfektblue.errors import BackendUnavailableError, DiscoveryError
from perfektblue.models import Adapter, Device, Service

BLUEZ_SERVICE = "org.bluez"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
PROPERTIES = "org.freedesktop.DBus.Properties"
ADAPTER_INTERFACE = "org.bluez.Adapter1"
DEVICE_INTERFACE = "org.bluez.Device1"
GATT_SERVICE_INTERFACE = "org.bluez.GattService1"
GATT_CHARACTERISTIC_INTERFACE = "org.bluez.GattCharacteristic1"


def _unwrap(value: Any) -> Any:
    if hasattr(value, "value"):
        return _unwrap(value.value)
    if isinstance(value, Mapping):
        return {str(key): _unwrap(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_unwrap(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


def _adapter_from_properties(path: str, properties: Mapping[str, Any]) -> Adapter:
    data = _unwrap(properties)
    return Adapter(
        id=path,
        address=data.get("Address"),
        name=data.get("Alias") or data.get("Name"),
        powered=bool(data.get("Powered", False)),
        discoverable=bool(data.get("Discoverable", False)),
        pairable=bool(data.get("Pairable", False)),
        discovering=bool(data.get("Discovering", False)),
        uuids=list(data.get("UUIDs", [])),
        capabilities={
            "modalias": data.get("Modalias"),
            "roles": data.get("Roles", []),
            "class": data.get("Class"),
        },
    )


def _device_from_properties(path: str, properties: Mapping[str, Any]) -> Device:
    data = _unwrap(properties)
    manufacturer = {
        str(key): value for key, value in dict(data.get("ManufacturerData", {})).items()
    }
    service_data = {str(key): value for key, value in dict(data.get("ServiceData", {})).items()}
    return Device(
        address=str(data.get("Address", "")),
        name=data.get("Name"),
        alias=data.get("Alias"),
        adapter_id=data.get("Adapter"),
        address_type=data.get("AddressType"),
        device_class=data.get("Class"),
        appearance=data.get("Appearance"),
        rssi=data.get("RSSI"),
        paired=bool(data.get("Paired", False)),
        bonded=bool(data.get("Bonded", data.get("Paired", False))),
        trusted=bool(data.get("Trusted", False)),
        connected=bool(data.get("Connected", False)),
        service_uuids=list(data.get("UUIDs", [])),
        manufacturer_data=manufacturer,
        service_data=service_data,
        backend="bluez",
        metadata={
            "path": path,
            "services_resolved": bool(data.get("ServicesResolved", False)),
            "legacy_pairing": data.get("LegacyPairing"),
            "icon": data.get("Icon"),
            "modalias": data.get("Modalias"),
            "tx_power": data.get("TxPower"),
        },
    )


def _gatt_services_for_device(
    device_path: str,
    objects: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> list[Service]:
    services: dict[str, Service] = {}
    for path, interfaces in objects.items():
        if GATT_SERVICE_INTERFACE not in interfaces:
            continue
        properties = _unwrap(interfaces[GATT_SERVICE_INTERFACE])
        if properties.get("Device") != device_path:
            continue
        services[path] = Service(
            uuid=str(properties.get("UUID", "")),
            name=None,
            transport="gatt",
            metadata={
                "path": path,
                "primary": bool(properties.get("Primary", False)),
                "handle": properties.get("Handle"),
            },
        )
    for path, interfaces in objects.items():
        if GATT_CHARACTERISTIC_INTERFACE not in interfaces:
            continue
        properties = _unwrap(interfaces[GATT_CHARACTERISTIC_INTERFACE])
        service_path = properties.get("Service")
        service = services.get(str(service_path))
        if service is None:
            continue
        characteristic_uuid = str(properties.get("UUID", ""))
        if characteristic_uuid:
            service.characteristics.append(characteristic_uuid)
        flags = service.metadata.setdefault("characteristic_flags", {})
        flags[characteristic_uuid] = list(properties.get("Flags", []))
        handles = service.metadata.setdefault("characteristic_handles", {})
        handles[characteristic_uuid] = properties.get("Handle")
        service.metadata.setdefault("characteristic_paths", {})[characteristic_uuid] = path
    return sorted(services.values(), key=lambda item: item.uuid)


def _devices_from_objects(
    objects: Mapping[str, Mapping[str, Mapping[str, Any]]],
    adapter_id: str | None = None,
) -> list[Device]:
    devices: list[Device] = []
    for path, interfaces in objects.items():
        if DEVICE_INTERFACE not in interfaces:
            continue
        device = _device_from_properties(path, interfaces[DEVICE_INTERFACE])
        if adapter_id is not None and device.adapter_id != adapter_id:
            continue
        device.services = _gatt_services_for_device(path, objects)
        known = {uuid.lower() for uuid in device.service_uuids}
        for service in device.services:
            if service.uuid and service.uuid.lower() not in known:
                device.service_uuids.append(service.uuid)
                known.add(service.uuid.lower())
        devices.append(device)
    return devices


class BlueZBackend(BluetoothBackend):
    name = "bluez"

    def __init__(self) -> None:
        self._bus: Any = None

    async def _connect(self) -> Any:
        if self._bus is not None:
            return self._bus
        try:
            from dbus_next.aio.message_bus import MessageBus
            from dbus_next.constants import BusType
        except ImportError as exc:
            raise BackendUnavailableError(
                "dbus-next is not installed; install PerfektBlue runtime dependencies"
            ) from exc
        try:
            self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            return self._bus
        except Exception as exc:
            raise BackendUnavailableError(f"cannot connect to the system D-Bus: {exc}") from exc

    async def _managed_objects(self) -> dict[str, dict[str, dict[str, Any]]]:
        bus = await self._connect()
        try:
            introspection = await bus.introspect(BLUEZ_SERVICE, "/")
            proxy = bus.get_proxy_object(BLUEZ_SERVICE, "/", introspection)
            manager = proxy.get_interface(OBJECT_MANAGER)
            result = await manager.call_get_managed_objects()
            return cast(dict[str, dict[str, dict[str, Any]]], result)
        except Exception as exc:
            raise BackendUnavailableError(
                f"BlueZ is unavailable on the system D-Bus: {exc}"
            ) from exc

    async def adapters(self) -> list[Adapter]:
        objects = await self._managed_objects()
        return [
            _adapter_from_properties(path, interfaces[ADAPTER_INTERFACE])
            for path, interfaces in objects.items()
            if ADAPTER_INTERFACE in interfaces
        ]

    async def _adapter_interface(self, adapter_path: str) -> Any:
        bus = await self._connect()
        introspection = await bus.introspect(BLUEZ_SERVICE, adapter_path)
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, adapter_path, introspection)
        return proxy.get_interface(ADAPTER_INTERFACE)

    async def discover(
        self,
        adapter_id: str | None,
        duration: float,
        settle_seconds: float,
    ) -> list[Device]:
        adapters = await self.adapters()
        if not adapters:
            raise DiscoveryError("BlueZ reported no Bluetooth adapters")
        selected = next((item for item in adapters if item.id == adapter_id), None)
        if adapter_id and selected is None:
            raise DiscoveryError(f"Bluetooth adapter not found: {adapter_id}")
        selected = selected or next((item for item in adapters if item.powered), adapters[0])
        if not selected.powered:
            raise DiscoveryError(
                f"adapter {selected.id} is powered off; enable it before discovery"
            )
        interface = await self._adapter_interface(selected.id)
        started = False
        try:
            if not selected.discovering:
                await interface.call_set_discovery_filter(
                    {
                        "Transport": self._variant("s", "auto"),
                        "DuplicateData": self._variant("b", False),
                    }
                )
                await interface.call_start_discovery()
                started = True
            await asyncio.sleep(duration)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise DiscoveryError(f"Bluetooth discovery failed: {exc}") from exc
        finally:
            if started:
                with suppress(Exception):
                    await interface.call_stop_discovery()
        if settle_seconds:
            await asyncio.sleep(settle_seconds)
        objects = await self._managed_objects()
        devices = _devices_from_objects(objects, selected.id)
        devices.sort(key=lambda item: item.rssi if item.rssi is not None else -999, reverse=True)
        return devices

    @staticmethod
    def _variant(signature: str, value: Any) -> Any:
        try:
            from dbus_next.signature import Variant
        except ImportError as exc:
            raise BackendUnavailableError("dbus-next is not installed") from exc
        return Variant(signature, value)

    async def inspect(self, address: str, adapter_id: str | None = None) -> Device:
        normalized = address.upper()
        objects = await self._managed_objects()
        for device in _devices_from_objects(objects, adapter_id):
            if device.address.upper() == normalized and (
                adapter_id is None or device.adapter_id == adapter_id
            ):
                return device
        raise DiscoveryError(
            f"device {address} is not known to BlueZ; run discovery before inspection"
        )
