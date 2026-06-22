from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from perfektblue.bluetooth.simulated import SimulatedBackend
from perfektblue.config import Config
from perfektblue.engine import AssessmentEngine
from perfektblue.models import InjectionVerdict, RiskLevel
from perfektblue.modules import ModuleRegistry
from perfektblue.paths import AppPaths
from perfektblue.profiles import ProfileRegistry
from perfektblue.storage import SessionStore


class EngineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.store = SessionStore(AppPaths(root / "config", root / "data", root / "cache"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def engine(self, scenario: str, policy: RiskLevel = RiskLevel.PASSIVE) -> AssessmentEngine:
        config = Config(
            backend="simulated",
            simulated_scenario=scenario,
            risk_policy=policy,
            scan_seconds=1,
            settle_seconds=0,
        )
        return AssessmentEngine(
            SimulatedBackend(scenario),
            config,
            ProfileRegistry(),
            ModuleRegistry(load_external=False),
            self.store,
        )

    async def test_passive_plan_gates_canary(self) -> None:
        engine = self.engine("vulnerable")
        device = await engine.resolve_target()
        plan, _ = engine.plan(device)
        canary = next(item for item in plan.modules if item.module_id == "lab.simulated-canary")
        self.assertFalse(canary.selected)
        self.assertIn("requires lab-active", canary.reason)
        result = await engine.assess(device)
        self.assertEqual(result.injection_verdict, InjectionVerdict.INCONCLUSIVE)

    async def test_authorized_simulated_canary_confirms_injectable(self) -> None:
        engine = self.engine("vulnerable", RiskLevel.LAB_ACTIVE)
        device = await engine.resolve_target()
        result = await engine.assess(device, authorized=True)
        self.assertEqual(
            result.injection_verdict,
            InjectionVerdict.CONFIRMED_INJECTABLE,
        )
        canary_evidence = [item for item in result.evidence if item.kind == "canary-result"]
        self.assertEqual(len(canary_evidence), 1)
        self.assertFalse(canary_evidence[0].value["executable"])

    async def test_patched_simulator_reports_blocked(self) -> None:
        engine = self.engine("patched", RiskLevel.LAB_ACTIVE)
        device = await engine.resolve_target()
        result = await engine.assess(device, authorized=True)
        self.assertEqual(result.injection_verdict, InjectionVerdict.BLOCKED)

    async def test_unknown_target_never_selects_canary(self) -> None:
        engine = self.engine("unknown", RiskLevel.LAB_ACTIVE)
        device = await engine.resolve_target()
        plan, _ = engine.plan(device)
        canary = next(item for item in plan.modules if item.module_id == "lab.simulated-canary")
        self.assertFalse(canary.selected)
        result = await engine.assess(device, authorized=True)
        self.assertEqual(result.injection_verdict, InjectionVerdict.UNSUPPORTED)
