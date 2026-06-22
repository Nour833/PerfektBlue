from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from perfektblue.bluetooth.simulated import SimulatedBackend
from perfektblue.config import Config
from perfektblue.engine import AssessmentEngine
from perfektblue.errors import SessionError
from perfektblue.models import RiskLevel
from perfektblue.modules import ModuleRegistry
from perfektblue.paths import AppPaths
from perfektblue.profiles import ProfileRegistry
from perfektblue.reporting import write_html_report, write_json_report
from perfektblue.storage import SessionStore


class StorageReportingTests(unittest.IsolatedAsyncioTestCase):
    async def test_session_round_trip_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = SessionStore(AppPaths(root / "config", root / "data", root / "cache"))
            engine = AssessmentEngine(
                SimulatedBackend("patched"),
                Config(
                    backend="simulated",
                    simulated_scenario="patched",
                    risk_policy=RiskLevel.LAB_ACTIVE,
                    scan_seconds=1,
                    settle_seconds=0,
                ),
                ProfileRegistry(),
                ModuleRegistry(load_external=False),
                store,
            )
            result = await engine.assess(await engine.resolve_target(), authorized=True)
            loaded = store.load_result(result.session_id)
            self.assertEqual(loaded["session_id"], result.session_id)
            html_path = write_html_report(loaded, root / "report.html")
            json_path = write_json_report(loaded, root / "report.json")
            self.assertIn("blocked", html_path.read_text(encoding="utf-8"))
            self.assertTrue(json_path.exists())
            self.assertEqual(store.get_session(result.session_id)["verdict"], "blocked")
            self.assertEqual(len(store.list_sessions()), 1)
            text = store.add_artifact(result.session_id, "../note.txt", "evidence")
            binary = store.add_artifact(result.session_id, "capture.bin", b"\x01", binary=True)
            self.assertEqual(text.name, "note.txt")
            self.assertEqual(binary.read_bytes(), b"\x01")

    def test_legacy_can_import_is_evidence_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = SessionStore(AppPaths(root / "config", root / "data", root / "cache"))
            source = root / "can_command_db.json"
            source.write_text('{"0x123": [1, 2, 3]}', encoding="utf-8")
            evidence = store.import_legacy_can(source)
            self.assertEqual(evidence[0].kind, "legacy-can-frame")

    def test_storage_rejects_missing_corrupt_and_invalid_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = SessionStore(AppPaths(root / "config", root / "data", root / "cache"))
            with self.assertRaises(SessionError):
                store.load_result("missing")
            invalid = root / "invalid.json"
            invalid.write_text("[]", encoding="utf-8")
            with self.assertRaises(SessionError):
                store.import_legacy_can(invalid)
            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaises(SessionError):
                store.import_legacy_can(malformed)
            with self.assertRaises(SessionError):
                store.add_artifact("session", "capture.bin", "not bytes", binary=True)
