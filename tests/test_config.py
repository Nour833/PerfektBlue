from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from perfektblue.config import ConfigurationError, load_config
from perfektblue.models import RiskLevel
from perfektblue.paths import AppPaths


class ConfigTests(unittest.TestCase):
    def test_precedence_cli_over_environment_over_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_file = root / "config.toml"
            config_file.write_text(
                "[perfektblue]\nscan_seconds = 20\nbackend = 'bluez'\n",
                encoding="utf-8",
            )
            paths = AppPaths(root, root / "data", root / "cache")
            with patch.dict(
                os.environ,
                {
                    "PERFEKTBLUE_SCAN_SECONDS": "25",
                    "PERFEKTBLUE_RISK_POLICY": "active-safe",
                },
                clear=False,
            ):
                config = load_config(
                    {"scan_seconds": 30, "backend": "simulated"},
                    config_path=config_file,
                    paths=paths,
                )
            self.assertEqual(config.scan_seconds, 30)
            self.assertEqual(config.backend, "simulated")
            self.assertEqual(config.risk_policy, RiskLevel.ACTIVE_SAFE)

    def test_invalid_thresholds_are_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_config({"minimum_suggested_match": 90, "minimum_auto_match": 50})

    def test_boolean_and_numeric_environment_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = AppPaths(root / "config", root / "data", root / "cache")
            with patch.dict(
                os.environ,
                {
                    "PERFEKTBLUE_REDACT_IDENTIFIERS": "yes",
                    "PERFEKTBLUE_MAX_RETRIES": "4",
                    "PERFEKTBLUE_COMMAND_TIMEOUT": "45.5",
                },
                clear=False,
            ):
                config = load_config(paths=paths)
            self.assertTrue(config.redact_identifiers)
            self.assertEqual(config.max_retries, 4)
            self.assertEqual(config.command_timeout, 45.5)

    def test_invalid_toml_and_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = root / "invalid.toml"
            invalid.write_text("[perfektblue\n", encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                load_config(config_path=invalid)
            with self.assertRaises(ConfigurationError):
                load_config({"redact_identifiers": "sometimes"})
            with self.assertRaises(ConfigurationError):
                load_config({"backend": "invalid"})
