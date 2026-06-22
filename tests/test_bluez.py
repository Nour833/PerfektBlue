from __future__ import annotations

import unittest
from unittest.mock import AsyncMock

from perfektblue.bluetooth.bluez import (
    ADAPTER_INTERFACE,
    DEVICE_INTERFACE,
    GATT_CHARACTERISTIC_INTERFACE,
    GATT_SERVICE_INTERFACE,
    BlueZBackend,
    _adapter_from_properties,
    _device_from_properties,
)
from perfektblue.errors import DiscoveryError
from perfektblue.models import Adapter


class Variant:
    def __init__(self, value: object) -> None:
        self.value = value


class BlueZMappingTests(unittest.TestCase):
    def test_adapter_mapping(self) -> None:
        adapter = _adapter_from_properties(
            "/org/bluez/hci0",
            {
                "Address": Variant("00:11:22:33:44:55"),
                "Alias": Variant("Lab adapter"),
                "Powered": Variant(True),
                "UUIDs": Variant(["service"]),
            },
        )
        self.assertTrue(adapter.powered)
        self.assertEqual(adapter.name, "Lab adapter")

    def test_device_mapping_unwraps_binary_data(self) -> None:
        device = _device_from_properties(
            "/org/bluez/hci0/dev_00_11_22_33_44_55",
            {
                "Address": Variant("00:11:22:33:44:55"),
                "Adapter": Variant("/org/bluez/hci0"),
                "ManufacturerData": Variant({76: Variant(bytes.fromhex("0102"))}),
                "UUIDs": Variant(["abcd"]),
            },
        )
        self.assertEqual(device.manufacturer_data["76"], "0102")
        self.assertEqual(device.service_uuids, ["abcd"])


class BlueZBackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.backend = BlueZBackend()
        self.adapter = Adapter(
            id="/org/bluez/hci0",
            address="00:11:22:33:44:55",
            powered=True,
        )
        self.objects = {
            "/org/bluez/hci0": {
                ADAPTER_INTERFACE: {
                    "Address": "00:11:22:33:44:55",
                    "Powered": True,
                }
            },
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF": {
                DEVICE_INTERFACE: {
                    "Address": "AA:BB:CC:DD:EE:FF",
                    "Adapter": "/org/bluez/hci0",
                    "Name": "Fixture",
                    "RSSI": -42,
                    "UUIDs": ["abcd"],
                }
            },
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0001": {
                GATT_SERVICE_INTERFACE: {
                    "Device": "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF",
                    "UUID": "1234",
                    "Primary": True,
                    "Handle": 1,
                }
            },
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0001/char0002": {
                GATT_CHARACTERISTIC_INTERFACE: {
                    "Service": "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0001",
                    "UUID": "5678",
                    "Flags": ["read"],
                    "Handle": 2,
                }
            },
        }

    async def test_adapters_discovery_and_inspection(self) -> None:
        self.backend._managed_objects = AsyncMock(return_value=self.objects)
        adapters = await self.backend.adapters()
        self.assertEqual(adapters[0].id, "/org/bluez/hci0")

        interface = unittest.mock.Mock()
        interface.call_set_discovery_filter = AsyncMock()
        interface.call_start_discovery = AsyncMock()
        interface.call_stop_discovery = AsyncMock()
        self.backend._adapter_interface = AsyncMock(return_value=interface)
        devices = await self.backend.discover("/org/bluez/hci0", 0, 0)
        self.assertEqual(devices[0].name, "Fixture")
        self.assertEqual(devices[0].services[0].uuid, "1234")
        self.assertEqual(devices[0].services[0].characteristics, ["5678"])
        interface.call_start_discovery.assert_awaited_once()
        interface.call_stop_discovery.assert_awaited_once()

        device = await self.backend.inspect("aa:bb:cc:dd:ee:ff")
        self.assertEqual(device.address, "AA:BB:CC:DD:EE:FF")

    async def test_discovery_preconditions_and_missing_device(self) -> None:
        self.backend.adapters = AsyncMock(return_value=[])
        with self.assertRaises(DiscoveryError):
            await self.backend.discover(None, 0, 0)

        self.backend.adapters = AsyncMock(return_value=[self.adapter])
        with self.assertRaises(DiscoveryError):
            await self.backend.discover("/org/bluez/hci9", 0, 0)

        self.backend.adapters = AsyncMock(
            return_value=[Adapter(id="/org/bluez/hci0", address=None, powered=False)]
        )
        with self.assertRaises(DiscoveryError):
            await self.backend.discover(None, 0, 0)

        self.backend._managed_objects = AsyncMock(return_value=self.objects)
        with self.assertRaises(DiscoveryError):
            await self.backend.inspect("00:00:00:00:00:00")
