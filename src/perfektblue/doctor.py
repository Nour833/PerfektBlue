"""Environment capability checks."""

from __future__ import annotations

import importlib.util
import platform
import shutil
from dataclasses import asdict, dataclass

from perfektblue.bluetooth.base import BluetoothBackend


@dataclass(slots=True)
class Check:
    name: str
    ok: bool
    detail: str
    required: bool = True


async def run_checks(backend: BluetoothBackend | None = None) -> list[Check]:
    checks = [
        Check(
            name="operating-system",
            ok=platform.system() == "Linux",
            detail=f"{platform.system()} {platform.release()}",
        ),
        Check(
            name="dbus-next",
            ok=importlib.util.find_spec("dbus_next") is not None,
            detail="Python BlueZ D-Bus client dependency",
        ),
        Check(
            name="rich",
            ok=importlib.util.find_spec("rich") is not None,
            detail="Enhanced terminal output dependency",
        ),
        Check(
            name="bluetoothctl",
            ok=shutil.which("bluetoothctl") is not None,
            detail="Optional BlueZ diagnostic command",
            required=False,
        ),
    ]
    if backend is not None:
        try:
            adapters = await backend.adapters()
            checks.append(
                Check(
                    name="bluetooth-adapter",
                    ok=bool(adapters),
                    detail=f"{len(adapters)} adapter(s) reported by {backend.name}",
                )
            )
            checks.append(
                Check(
                    name="powered-adapter",
                    ok=any(item.powered for item in adapters),
                    detail=(
                        "At least one adapter is powered"
                        if any(item.powered for item in adapters)
                        else "No adapter is powered"
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                Check(
                    name="bluez-dbus",
                    ok=False,
                    detail=str(exc),
                )
            )
    return checks


def checks_to_dict(checks: list[Check]) -> list[dict[str, object]]:
    return [asdict(item) for item in checks]
