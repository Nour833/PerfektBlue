"""Validated configuration with CLI, environment, user, and system precedence."""

from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any

from perfektblue.errors import ConfigurationError
from perfektblue.models import RiskLevel
from perfektblue.paths import AppPaths, get_paths


@dataclass(frozen=True, slots=True)
class Config:
    backend: str = "bluez"
    adapter: str | None = None
    scan_seconds: float = 12.0
    settle_seconds: float = 2.0
    command_timeout: float = 30.0
    max_retries: int = 2
    max_concurrency: int = 4
    minimum_auto_match: float = 80.0
    minimum_suggested_match: float = 50.0
    risk_policy: RiskLevel = RiskLevel.PASSIVE
    redact_identifiers: bool = False
    simulated_scenario: str = "vulnerable"

    def validate(self) -> Config:
        if self.backend not in {"bluez", "simulated"}:
            raise ConfigurationError("backend must be 'bluez' or 'simulated'")
        if not 1 <= self.scan_seconds <= 300:
            raise ConfigurationError("scan_seconds must be between 1 and 300")
        if not 0 <= self.settle_seconds <= 30:
            raise ConfigurationError("settle_seconds must be between 0 and 30")
        if not 1 <= self.command_timeout <= 600:
            raise ConfigurationError("command_timeout must be between 1 and 600")
        if not 0 <= self.max_retries <= 10:
            raise ConfigurationError("max_retries must be between 0 and 10")
        if not 1 <= self.max_concurrency <= 32:
            raise ConfigurationError("max_concurrency must be between 1 and 32")
        if not 0 <= self.minimum_suggested_match <= self.minimum_auto_match <= 100:
            raise ConfigurationError("profile confidence thresholds are inconsistent")
        if self.simulated_scenario not in {"vulnerable", "patched", "unknown"}:
            raise ConfigurationError("simulated_scenario must be vulnerable, patched, or unknown")
        return self

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["risk_policy"] = self.risk_policy.value
        return result


def _coerce(name: str, value: Any) -> Any:
    template = getattr(Config(), name)
    if name == "risk_policy":
        return RiskLevel(str(value))
    if isinstance(template, bool):
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ConfigurationError(f"{name} must be a boolean")
    if isinstance(template, int):
        return int(value)
    if isinstance(template, float):
        return float(value)
    if value is None:
        return None
    return str(value)


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"cannot read configuration {path}: {exc}") from exc
    section = parsed.get("perfektblue", parsed)
    if not isinstance(section, dict):
        raise ConfigurationError(f"configuration {path} must contain a table")
    return section


def load_config(
    cli_overrides: dict[str, Any] | None = None,
    config_path: Path | None = None,
    paths: AppPaths | None = None,
) -> Config:
    paths = paths or get_paths()
    values: dict[str, Any] = {}
    known = {item.name for item in fields(Config)}
    for path in (Path("/etc/perfektblue/config.toml"), config_path or paths.config_file):
        values.update({key: value for key, value in _read_toml(path).items() if key in known})
    for name in known:
        env_name = f"PERFEKTBLUE_{name.upper()}"
        if env_name in os.environ:
            values[name] = os.environ[env_name]
    if cli_overrides:
        values.update(
            {
                key: value
                for key, value in cli_overrides.items()
                if key in known and value is not None
            }
        )
    config = Config()
    for name, value in values.items():
        try:
            config = replace(config, **{name: _coerce(name, value)})
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"invalid value for {name}: {value}") from exc
    return config.validate()
