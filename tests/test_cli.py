from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from perfektblue.cli import main


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        directory = self.temporary.name
        self.environment = {
            "XDG_CONFIG_HOME": f"{directory}/config",
            "XDG_DATA_HOME": f"{directory}/data",
            "XDG_CACHE_HOME": f"{directory}/cache",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(self, arguments: list[str]) -> tuple[int, str, str]:
        output = io.StringIO()
        error = io.StringIO()
        with (
            patch.dict(os.environ, self.environment, clear=False),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            code = main(arguments)
        return code, output.getvalue(), error.getvalue()

    def simulated(self, *arguments: str, json_mode: bool = False) -> list[str]:
        result = ["--backend", "simulated", "--scenario", "vulnerable"]
        if json_mode:
            result.append("--json")
        result.extend(arguments)
        return result

    def test_simulated_discovery_and_adapter_json(self) -> None:
        code, output, _ = self.run_cli(self.simulated("discover", json_mode=True))
        self.assertEqual(code, 0)
        self.assertIn("PB Lab Head Unit", output)
        code, output, _ = self.run_cli(self.simulated("adapters", json_mode=True))
        self.assertEqual(code, 0)
        self.assertIn("hci-sim", output)

    def test_inspect_fingerprint_and_plan(self) -> None:
        target = "02:00:00:00:20:01"
        for command in ("inspect", "fingerprint", "plan"):
            code, output, _ = self.run_cli(self.simulated(command, target, json_mode=True))
            self.assertEqual(code, 0)
            self.assertIn(target, output)

    def test_profile_and_module_commands(self) -> None:
        target = "02:00:00:00:20:01"
        commands = [
            self.simulated("profiles", "list", json_mode=True),
            self.simulated("profiles", "validate", json_mode=True),
            self.simulated("profiles", "match", target, json_mode=True),
            self.simulated("modules", "list", json_mode=True),
            self.simulated("modules", "validate", json_mode=True),
            self.simulated(
                "modules",
                "describe",
                "bluetooth.service-exposure",
                json_mode=True,
            ),
        ]
        for command in commands:
            code, output, _ = self.run_cli(command)
            self.assertEqual(code, 0)
            self.assertTrue(output.strip())
        code, _, _ = self.run_cli(self.simulated("modules", "describe", "missing.module"))
        self.assertEqual(code, 3)

    def test_assessment_session_and_reports(self) -> None:
        target = "02:00:00:00:20:01"
        code, output, _ = self.run_cli(
            [
                "--backend",
                "simulated",
                "--scenario",
                "vulnerable",
                "--risk",
                "lab-active",
                "--json",
                "assess",
                "--authorized",
                target,
            ]
        )
        self.assertEqual(code, 0)
        result = json.loads(output)
        session_id = result["session_id"]
        self.assertEqual(result["injection_verdict"], "confirmed-injectable")

        code, output, _ = self.run_cli(self.simulated("sessions", "list", json_mode=True))
        self.assertEqual(code, 0)
        self.assertIn(session_id, output)
        code, output, _ = self.run_cli(
            self.simulated("sessions", "show", session_id, json_mode=True)
        )
        self.assertEqual(code, 0)
        self.assertIn(session_id, output)

        root = Path(self.temporary.name)
        export_path = root / "export.json"
        code, _, _ = self.run_cli(
            self.simulated(
                "sessions",
                "export",
                session_id,
                "--output",
                str(export_path),
            )
        )
        self.assertEqual(code, 0)
        self.assertTrue(export_path.exists())

        html_path = root / "report.html"
        code, _, _ = self.run_cli(
            self.simulated(
                "report",
                session_id,
                "--output",
                str(html_path),
            )
        )
        self.assertEqual(code, 0)
        self.assertIn("confirmed-injectable", html_path.read_text(encoding="utf-8"))

    def test_doctor_wizard_and_migration(self) -> None:
        code, output, _ = self.run_cli(self.simulated("doctor", json_mode=True))
        self.assertEqual(code, 0)
        self.assertIn("bluetooth-adapter", output)

        with patch("sys.stdin", io.StringIO("")):
            code, output, _ = self.run_cli(self.simulated("wizard"))
        self.assertEqual(code, 0)
        self.assertIn("Verdict:", output)

        legacy = Path(self.temporary.name) / "legacy.json"
        legacy.write_text('{"0x123": [1, 2]}', encoding="utf-8")
        code, output, _ = self.run_cli(
            self.simulated("migrate", "legacy-can", str(legacy), json_mode=True)
        )
        self.assertEqual(code, 0)
        self.assertIn("legacy-can-frame", output)

    def test_lab_active_requires_authorization(self) -> None:
        code, _, _ = self.run_cli(
            [
                "--backend",
                "simulated",
                "--risk",
                "lab-active",
                "assess",
            ]
        )
        self.assertEqual(code, 2)

    def test_default_command_opens_styled_main_menu(self) -> None:
        with patch("builtins.input", side_effect=["q"]):
            code, output, _ = self.run_cli(["--backend", "simulated", "--scenario", "vulnerable"])
        self.assertEqual(code, 0)
        self.assertIn("PERFEKTBLUE", output)
        self.assertIn("Target discovery", output)
        self.assertIn("Settings & safety", output)

    def test_menu_discovery_selects_target_and_returns_home(self) -> None:
        with patch("builtins.input", side_effect=["1", "1", "q"]):
            code, output, _ = self.run_cli(
                ["--backend", "simulated", "--scenario", "vulnerable", "menu"]
            )
        self.assertEqual(code, 0)
        self.assertIn("Discovered targets", output)
        self.assertIn("PB Lab Head Unit", output)
        self.assertIn("Target selected", output)

    def test_menu_target_workspace_navigation(self) -> None:
        choices = ["1", "1", "2", "1", "2", "3", "b", "q"]
        with patch("builtins.input", side_effect=choices):
            code, output, _ = self.run_cli(
                ["--backend", "simulated", "--scenario", "vulnerable", "menu"]
            )
        self.assertEqual(code, 0)
        self.assertIn("Observed target evidence", output)
        self.assertIn("Ranked profile matches", output)
        self.assertIn("Module decisions", output)

    def test_menu_assessment_and_session_navigation(self) -> None:
        choices = ["1", "1", "3", "y", "5", "1", "b", "b", "q"]
        with patch("builtins.input", side_effect=choices):
            code, output, _ = self.run_cli(
                ["--backend", "simulated", "--scenario", "patched", "menu"]
            )
        self.assertEqual(code, 0)
        self.assertIn("ASSESSMENT COMPLETE", output)
        self.assertIn("Recent sessions", output)
        self.assertIn("SESSION DETAIL", output)

    def test_menu_secondary_sections_and_invalid_action(self) -> None:
        choices = ["4", "6", "1", "2", "3", "b", "7", "8", "h", "invalid", "q"]
        with patch("builtins.input", side_effect=choices):
            code, output, _ = self.run_cli(
                ["--backend", "simulated", "--scenario", "unknown", "menu"]
            )
        self.assertEqual(code, 0)
        self.assertIn("System readiness", output)
        self.assertIn("Library status", output)
        self.assertIn("Current runtime", output)
        self.assertIn("Optional CAN plugin", output)
        self.assertIn("Verdict language", output)
        self.assertIn("Unknown action", output)

    def test_menu_lab_active_authorization(self) -> None:
        choices = ["1", "1", "3", "y", "AUTHORIZED", "q"]
        with patch("builtins.input", side_effect=choices):
            code, output, _ = self.run_cli(
                [
                    "--backend",
                    "simulated",
                    "--scenario",
                    "vulnerable",
                    "--risk",
                    "lab-active",
                    "menu",
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("CONFIRMED-INJECTABLE", output)
