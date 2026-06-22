"""Built-in passive modules and simulator-only canary verification."""

from __future__ import annotations

from perfektblue.models import (
    Evidence,
    Finding,
    FindingStatus,
    InjectionVerdict,
    ModuleManifest,
    RiskLevel,
)
from perfektblue.modules.base import AssessmentModule, ModuleContext, ModuleOutcome

LAB_SERVICE = "8d7f0001-4b1c-4f17-a6ec-54c0117a1100"


class ServiceExposureModule(AssessmentModule):
    manifest = ModuleManifest(
        id="bluetooth.service-exposure",
        name="Bluetooth service exposure",
        version="1.0.0",
        description="Inventories advertised services without claiming vulnerability.",
        risk=RiskLevel.PASSIVE,
        supported_profiles=[],
    )

    async def run(self, context: ModuleContext) -> ModuleOutcome:
        services = sorted(set(context.device.service_uuids))
        evidence = Evidence(
            kind="service-exposure",
            source=self.manifest.id,
            value=services,
            confidence=90.0 if services else 35.0,
            detail=(
                "Advertised Bluetooth services were inventoried."
                if services
                else "No advertised services were available; service discovery may be incomplete."
            ),
            target=context.device.address,
        )
        finding = Finding(
            module_id=self.manifest.id,
            title="Bluetooth service inventory",
            status=FindingStatus.CONFIRMED if services else FindingStatus.INCONCLUSIVE,
            summary=(
                f"{len(services)} advertised service UUIDs were observed."
                if services
                else "No service UUIDs were observed."
            ),
            confidence=evidence.confidence,
            evidence_ids=[evidence.id],
            remediation="Disable unused Bluetooth profiles and restrict discoverability.",
        )
        return ModuleOutcome(evidence=[evidence], findings=[finding])


class SecurityPostureModule(AssessmentModule):
    manifest = ModuleManifest(
        id="bluetooth.security-posture",
        name="Bluetooth link security posture",
        version="1.0.0",
        description="Reviews pairing, bonding, trust, and connection state reported by BlueZ.",
        risk=RiskLevel.PASSIVE,
        supported_profiles=[],
    )

    async def run(self, context: ModuleContext) -> ModuleOutcome:
        state = {
            "paired": context.device.paired,
            "bonded": context.device.bonded,
            "trusted": context.device.trusted,
            "connected": context.device.connected,
            "address_type": context.device.address_type,
        }
        evidence = Evidence(
            kind="security-posture",
            source=self.manifest.id,
            value=state,
            confidence=90.0,
            detail=(
                "Link state reported by the Bluetooth backend; transport encryption "
                "is not inferred."
            ),
            target=context.device.address,
        )
        if context.device.trusted and not context.device.bonded:
            status = FindingStatus.PROBABLE
            summary = (
                "The target is trusted without a reported bond; verify BlueZ policy "
                "and pairing state."
            )
            remediation = "Require authenticated bonding before assigning persistent trust."
        else:
            status = FindingStatus.CONFIRMED
            summary = "Bluetooth pairing, bonding, and trust state was recorded."
            remediation = "Review trusted-device entries and remove stale bonds regularly."
        finding = Finding(
            module_id=self.manifest.id,
            title="Bluetooth link security state",
            status=status,
            summary=summary,
            confidence=85.0,
            evidence_ids=[evidence.id],
            remediation=remediation,
        )
        return ModuleOutcome(evidence=[evidence], findings=[finding])


class SimulatedCanaryModule(AssessmentModule):
    manifest = ModuleManifest(
        id="lab.simulated-canary",
        name="Simulated canary injection verification",
        version="1.0.0",
        description="Validates exploitability verdict handling against the bundled simulator.",
        risk=RiskLevel.LAB_ACTIVE,
        supported_profiles=[
            "perfektblue.lab-head-unit.v1",
            "perfektblue.lab-head-unit.v1-patched",
        ],
        required_services=[LAB_SERVICE],
        minimum_profile_confidence=90.0,
        side_effects=["Writes a non-executable canary to the in-memory simulator only."],
    )

    def compatible(self, context: ModuleContext) -> tuple[bool, str]:
        compatible, reason = super().compatible(context)
        if not compatible:
            return compatible, reason
        if context.device.backend != "simulated" or not context.device.metadata.get("simulated"):
            return False, "the bundled canary module is restricted to the simulator"
        return True, "exact simulated profile and service match"

    async def run(self, context: ModuleContext) -> ModuleOutcome:
        behavior = context.device.metadata.get("canary_behavior")
        accepted = behavior == "accept"
        evidence = Evidence(
            kind="canary-result",
            source=self.manifest.id,
            value={
                "marker": "PERFEKTBLUE-CANARY-V1",
                "accepted": accepted,
                "executable": False,
                "backend": context.device.backend,
            },
            confidence=100.0,
            detail="Deterministic simulator response to a non-executable canary marker.",
            target=context.device.address,
        )
        if accepted:
            finding = Finding(
                module_id=self.manifest.id,
                title="Simulated injection path accepted a canary",
                status=FindingStatus.CONFIRMED,
                summary="The certified simulator accepted and acknowledged the inert canary.",
                confidence=100.0,
                evidence_ids=[evidence.id],
                remediation=(
                    "Apply the patched simulator profile and reject unauthenticated control writes."
                ),
            )
            return ModuleOutcome(
                evidence=[evidence],
                findings=[finding],
                injection_verdict=InjectionVerdict.CONFIRMED_INJECTABLE,
                verdict_reason="A profile-compatible inert canary was accepted and verified.",
            )
        finding = Finding(
            module_id=self.manifest.id,
            title="Simulated injection path blocked",
            status=FindingStatus.CONFIRMED,
            summary="The patched simulator rejected the inert canary.",
            confidence=100.0,
            evidence_ids=[evidence.id],
            remediation="Retain the patched validation behavior and regression test it.",
        )
        return ModuleOutcome(
            evidence=[evidence],
            findings=[finding],
            injection_verdict=InjectionVerdict.BLOCKED,
            verdict_reason=(
                "The known simulated path was tested and rejected by the patched target."
            ),
        )
