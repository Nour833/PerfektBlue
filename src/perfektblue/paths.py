"""XDG-compliant application paths."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppPaths:
    config_dir: Path
    data_dir: Path
    cache_dir: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def database(self) -> Path:
        return self.data_dir / "sessions.sqlite3"

    @property
    def sessions_dir(self) -> Path:
        return self.data_dir / "sessions"

    def ensure(self) -> None:
        for path in (self.config_dir, self.data_dir, self.cache_dir, self.sessions_dir):
            path.mkdir(parents=True, exist_ok=True)


def get_paths() -> AppPaths:
    home = Path.home()
    config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "perfektblue"
    data = Path(os.environ.get("XDG_DATA_HOME", home / ".local/share")) / "perfektblue"
    cache = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache")) / "perfektblue"
    return AppPaths(config, data, cache)
