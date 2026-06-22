"""Public module contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from perfektblue.config import Config
from perfektblue.models import (
    Device,
    Evidence,
    Finding,
    InjectionVerdict,
    ModuleManifest,
    ProfileMatch,
    TargetProfile,
)


@dataclass(slots=True)
class ModuleContext:
    device: Device
    config: Config
    profile: TargetProfile | None
    profile_match: ProfileMatch | None
    evidence: list[Evidence]
    authorized: bool = False


@dataclass(slots=True)
class ModuleOutcome:
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    injection_verdict: InjectionVerdict | None = None
    verdict_reason: str | None = None


class AssessmentModule(ABC):
    manifest: ModuleManifest

    def compatible(self, context: ModuleContext) -> tuple[bool, str]:
        manifest = self.manifest
        if manifest.supported_profiles:
            if context.profile is None:
                return False, "requires a matched target profile"
            if context.profile.id not in manifest.supported_profiles:
                return False, f"profile {context.profile.id} is not supported"
        if (
            context.profile_match
            and context.profile_match.confidence < manifest.minimum_profile_confidence
        ):
            return (
                False,
                f"profile confidence {context.profile_match.confidence:.1f} is below "
                f"{manifest.minimum_profile_confidence:.1f}",
            )
        available = {item.lower() for item in context.device.service_uuids}
        missing = [uuid for uuid in manifest.required_services if uuid.lower() not in available]
        if missing:
            return False, f"required services are absent: {', '.join(missing)}"
        return True, "module requirements are satisfied"

    @abstractmethod
    async def run(self, context: ModuleContext) -> ModuleOutcome:
        """Execute the module and return evidence-backed outcomes."""

    async def cleanup(self, context: ModuleContext) -> None:
        """Release resources after execution."""
        return None
