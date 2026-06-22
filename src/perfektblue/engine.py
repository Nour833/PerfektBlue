"""Adaptive Bluetooth assessment planning and execution."""

from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

from perfektblue.bluetooth.base import BluetoothBackend
from perfektblue.config import Config
from perfektblue.errors import ModuleError
from perfektblue.fingerprint import fingerprint
from perfektblue.models import (
    AssessmentPlan,
    AssessmentResult,
    Device,
    Evidence,
    Finding,
    FindingStatus,
    InjectionVerdict,
    PlannedModule,
    ProfileMatch,
    RiskLevel,
    TargetProfile,
    utc_now,
)
from perfektblue.modules import ModuleContext, ModuleRegistry
from perfektblue.policy import enforce_execution, risk_allowed
from perfektblue.profiles import ProfileRegistry
from perfektblue.storage import SessionStore


class AssessmentEngine:
    def __init__(
        self,
        backend: BluetoothBackend,
        config: Config,
        profiles: ProfileRegistry | None = None,
        modules: ModuleRegistry | None = None,
        store: SessionStore | None = None,
    ) -> None:
        self.backend = backend
        self.config = config
        self.profiles = profiles or ProfileRegistry()
        self.modules = modules or ModuleRegistry()
        self.store = store

    async def discover(self) -> list[Device]:
        return await self.backend.discover(
            self.config.adapter,
            self.config.scan_seconds,
            self.config.settle_seconds,
        )

    async def resolve_target(self, address: str | None = None) -> Device:
        if address:
            try:
                return await self.backend.inspect(address, self.config.adapter)
            except Exception:
                devices = await self.discover()
                match = next(
                    (item for item in devices if item.address.casefold() == address.casefold()),
                    None,
                )
                if match:
                    return match
                raise
        devices = await self.discover()
        if not devices:
            raise ModuleError("no Bluetooth targets were discovered")
        return devices[0]

    def _selected_profile(
        self, matches: list[ProfileMatch]
    ) -> tuple[TargetProfile | None, ProfileMatch | None]:
        if not matches or matches[0].confidence < self.config.minimum_suggested_match:
            return None, None
        return self.profiles.get(matches[0].profile_id), matches[0]

    def plan(self, device: Device) -> tuple[AssessmentPlan, list[Evidence]]:
        matches, evidence = fingerprint(device, self.profiles)
        profile, profile_match = self._selected_profile(matches)
        planned: list[PlannedModule] = []
        context = ModuleContext(
            device=device,
            config=self.config,
            profile=profile,
            profile_match=profile_match,
            evidence=evidence,
        )
        for module in self.modules.all():
            compatible, reason = module.compatible(context)
            if not compatible:
                planned.append(
                    PlannedModule(
                        module_id=module.manifest.id,
                        selected=False,
                        reason=reason,
                        risk=module.manifest.risk,
                    )
                )
                continue
            if profile and profile.compatible_modules:
                is_generic = not module.manifest.supported_profiles
                if not is_generic and module.manifest.id not in profile.compatible_modules:
                    planned.append(
                        PlannedModule(
                            module_id=module.manifest.id,
                            selected=False,
                            reason="module is not enabled by the matched profile",
                            risk=module.manifest.risk,
                        )
                    )
                    continue
            if not risk_allowed(module.manifest.risk, self.config.risk_policy):
                planned.append(
                    PlannedModule(
                        module_id=module.manifest.id,
                        selected=False,
                        reason=(
                            f"requires {module.manifest.risk.value}; "
                            f"current policy is {self.config.risk_policy.value}"
                        ),
                        risk=module.manifest.risk,
                    )
                )
                continue
            if (
                module.manifest.risk != RiskLevel.PASSIVE
                and profile_match
                and profile_match.confidence < self.config.minimum_auto_match
            ):
                planned.append(
                    PlannedModule(
                        module_id=module.manifest.id,
                        selected=False,
                        reason=(
                            f"active module requires profile confidence "
                            f"{self.config.minimum_auto_match:.1f} or greater"
                        ),
                        risk=module.manifest.risk,
                    )
                )
                continue
            planned.append(
                PlannedModule(
                    module_id=module.manifest.id,
                    selected=True,
                    reason=reason,
                    risk=module.manifest.risk,
                )
            )
        return (
            AssessmentPlan(
                target=device.address,
                profile_matches=matches,
                modules=planned,
                policy=self.config.risk_policy,
            ),
            evidence,
        )

    async def assess(self, device: Device, authorized: bool = False) -> AssessmentResult:
        started = utc_now()
        session_id = str(uuid4())
        plan, evidence = self.plan(device)
        profile, profile_match = self._selected_profile(plan.profile_matches)
        findings: list[Finding] = []
        verdict: InjectionVerdict | None = None
        verdict_reason: str | None = None
        interrupted = False

        context = ModuleContext(
            device=device,
            config=self.config,
            profile=profile,
            profile_match=profile_match,
            evidence=evidence,
            authorized=authorized,
        )
        try:
            for planned in plan.modules:
                if not planned.selected:
                    continue
                module = self.modules.get(planned.module_id)
                if module is None:
                    continue
                try:
                    enforce_execution(
                        module.manifest.risk,
                        self.config.risk_policy,
                        authorized,
                    )
                    outcome = await module.run(context)
                    evidence.extend(outcome.evidence)
                    findings.extend(outcome.findings)
                    if outcome.injection_verdict is not None:
                        verdict = outcome.injection_verdict
                        verdict_reason = outcome.verdict_reason
                except Exception as exc:
                    failure = Evidence(
                        kind="module-failure",
                        source=module.manifest.id,
                        value={"error": type(exc).__name__, "message": str(exc)},
                        confidence=100.0,
                        detail="The module failed and did not produce a vulnerability verdict.",
                        target=device.address,
                    )
                    evidence.append(failure)
                    findings.append(
                        Finding(
                            module_id=module.manifest.id,
                            title=f"{module.manifest.name} failed",
                            status=FindingStatus.FAILED,
                            summary=str(exc),
                            confidence=100.0,
                            evidence_ids=[failure.id],
                        )
                    )
                finally:
                    await module.cleanup(context)
        except KeyboardInterrupt:
            interrupted = True

        if verdict is None:
            verdict, verdict_reason = self._derive_unverified_verdict(profile, profile_match, plan)
        assert verdict_reason is not None
        result = AssessmentResult(
            session_id=session_id,
            target=device,
            plan=plan,
            evidence=evidence,
            findings=findings,
            injection_verdict=verdict,
            verdict_reason=verdict_reason,
            started_at=started,
            completed_at=utc_now(),
            interrupted=interrupted,
        )
        (self.store or SessionStore()).save(result)
        return result

    def _derive_unverified_verdict(
        self,
        profile: TargetProfile | None,
        profile_match: ProfileMatch | None,
        plan: AssessmentPlan,
    ) -> tuple[InjectionVerdict, str]:
        if profile is None or profile_match is None:
            return (
                InjectionVerdict.UNSUPPORTED,
                "No target profile reached the minimum suggested confidence; "
                "generic reconnaissance completed without an injection claim.",
            )
        if profile_match.confidence < self.config.minimum_auto_match:
            return (
                InjectionVerdict.INCONCLUSIVE,
                "A possible profile matched, but confidence is too low for automatic "
                "injection-path selection.",
            )
        gated = [
            item
            for item in plan.modules
            if not item.selected
            and item.module_id in profile.injection_paths
            and "requires lab-active" in item.reason
        ]
        if profile.injection_paths and gated:
            return (
                InjectionVerdict.INCONCLUSIVE,
                "A compatible verification path exists, but it was not executed under "
                "the current risk policy.",
            )
        if not profile.injection_paths:
            return (
                InjectionVerdict.NO_KNOWN_PATH,
                "The matched profile declares no verified injection path.",
            )
        return (
            InjectionVerdict.INCONCLUSIVE,
            "Injection prerequisites were recognized, but no module produced "
            "verification evidence.",
        )

    def with_policy(self, policy: RiskLevel) -> AssessmentEngine:
        return AssessmentEngine(
            backend=self.backend,
            config=replace(self.config, risk_policy=policy),
            profiles=self.profiles,
            modules=self.modules,
            store=self.store,
        )
