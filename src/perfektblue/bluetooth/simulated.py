"""Deterministic Bluetooth simulator used by CI and module authors."""

from __future__ import annotations

from perfektblue.bluetooth.base import BluetoothBackend
from perfektblue.errors import DiscoveryError
from perfektblue.models import Adapter, Device, Service


class SimulatedBackend(BluetoothBackend):
    name = "simulated"

    def __init__(self, scenario: str = "vulnerable") -> None:
        self.scenario = scenario

    async def adapters(self) -> list[Adapter]:
        return [
            Adapter(
                id="/org/bluez/hci-sim",
                address="02:00:00:00:00:01",
                name="PerfektBlue simulator",
                powered=True,
                discoverable=True,
                pairable=True,
                capabilities={"roles": ["central", "peripheral"], "simulated": True},
            )
        ]

    def _device(self) -> Device:
        if self.scenario == "unknown":
            return Device(
                address="02:00:00:00:10:FF",
                name="Unknown Lab Device",
                alias="Unknown Lab Device",
                adapter_id="/org/bluez/hci-sim",
                address_type="random",
                rssi=-61,
                service_uuids=["00001800-0000-1000-8000-00805f9b34fb"],
                backend="simulated",
                metadata={"scenario": "unknown", "simulated": True},
            )
        patched = self.scenario == "patched"
        return Device(
            address="02:00:00:00:20:01" if not patched else "02:00:00:00:20:02",
            name="PB Lab Head Unit",
            alias="PB Lab Head Unit",
            adapter_id="/org/bluez/hci-sim",
            address_type="public",
            device_class=0x200428,
            rssi=-37,
            paired=True,
            bonded=True,
            trusted=True,
            service_uuids=[
                "0000110e-0000-1000-8000-00805f9b34fb",
                "0000110c-0000-1000-8000-00805f9b34fb",
                "8d7f0001-4b1c-4f17-a6ec-54c0117a1100",
            ],
            manufacturer_data={"65535": "50424c414202" if patched else "50424c414201"},
            services=[
                Service(
                    uuid="8d7f0001-4b1c-4f17-a6ec-54c0117a1100",
                    name="PerfektBlue lab control",
                    transport="gatt",
                    characteristics=["8d7f0002-4b1c-4f17-a6ec-54c0117a1100"],
                    metadata={"authenticated": True},
                )
            ],
            backend="simulated",
            metadata={
                "scenario": self.scenario,
                "simulated": True,
                "firmware": "1.0.0" if not patched else "1.1.0",
                "canary_behavior": "accept" if not patched else "reject",
            },
        )

    async def discover(
        self,
        adapter_id: str | None,
        duration: float,
        settle_seconds: float,
    ) -> list[Device]:
        if adapter_id not in {None, "/org/bluez/hci-sim"}:
            raise DiscoveryError(f"simulated adapter not found: {adapter_id}")
        return [self._device()]

    async def inspect(self, address: str, adapter_id: str | None = None) -> Device:
        device = self._device()
        if device.address.upper() != address.upper():
            raise DiscoveryError(f"simulated device not found: {address}")
        return device
