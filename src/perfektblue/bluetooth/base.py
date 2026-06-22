"""Bluetooth backend interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from perfektblue.models import Adapter, Device


class BluetoothBackend(ABC):
    name: str

    @abstractmethod
    async def adapters(self) -> list[Adapter]:
        """Return available Bluetooth adapters."""

    @abstractmethod
    async def discover(
        self,
        adapter_id: str | None,
        duration: float,
        settle_seconds: float,
    ) -> list[Device]:
        """Discover nearby devices."""

    @abstractmethod
    async def inspect(self, address: str, adapter_id: str | None = None) -> Device:
        """Return the best available metadata for one device."""
