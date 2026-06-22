"""Versioned domain models for discovery, evidence, planning, and findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class RiskLevel(StrEnum):
    PASSIVE = "passive"
    ACTIVE_SAFE = "active-safe"
    LAB_ACTIVE = "lab-active"


class FindingStatus(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not-applicable"
    FAILED = "failed"


class InjectionVerdict(StrEnum):
    CONFIRMED_INJECTABLE = "confirmed-injectable"
    LIKELY_INJECTABLE = "likely-injectable"
    BLOCKED = "blocked"
    NO_KNOWN_PATH = "no-known-path"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"


@dataclass(slots=True)
class Adapter:
    id: str
    address: str | None = None
    name: str | None = None
    powered: bool = False
    discoverable: bool = False
    pairable: bool = False
    discovering: bool = False
    uuids: list[str] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Service:
    uuid: str
    name: str | None = None
    transport: str = "unknown"
    channel: int | None = None
    psm: int | None = None
    characteristics: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Device:
    address: str
    name: str | None = None
    alias: str | None = None
    adapter_id: str | None = None
    address_type: str | None = None
    device_class: int | None = None
    appearance: int | None = None
    rssi: int | None = None
    paired: bool = False
    bonded: bool = False
    trusted: bool = False
    connected: bool = False
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[str, str] = field(default_factory=dict)
    service_data: dict[str, str] = field(default_factory=dict)
    services: list[Service] = field(default_factory=list)
    backend: str = "bluez"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Evidence:
    kind: str
    source: str
    value: Any
    confidence: float
    detail: str
    target: str | None = None
    artifact: str | None = None
    timestamp: str = field(default_factory=utc_now)
    id: str = field(default_factory=lambda: str(uuid4()))


@dataclass(slots=True)
class MatchRule:
    field: str
    operator: str
    value: Any
    weight: float
    required: bool = False


@dataclass(slots=True)
class TargetProfile:
    id: str
    name: str
    vendor: str
    product_family: str
    firmware_ranges: list[str]
    rules: list[MatchRule]
    expected_services: list[str] = field(default_factory=list)
    compatible_modules: list[str] = field(default_factory=list)
    injection_paths: list[str] = field(default_factory=list)
    simulated: bool = False
    references: list[str] = field(default_factory=list)
    schema_version: int = 1


@dataclass(slots=True)
class ProfileMatch:
    profile_id: str
    profile_name: str
    confidence: float
    matched_weight: float
    total_weight: float
    reasons: list[str]
    contradictions: list[str]


@dataclass(slots=True)
class ModuleManifest:
    id: str
    name: str
    version: str
    description: str
    risk: RiskLevel
    supported_profiles: list[str]
    required_services: list[str] = field(default_factory=list)
    minimum_profile_confidence: float = 0.0
    side_effects: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PlannedModule:
    module_id: str
    selected: bool
    reason: str
    risk: RiskLevel


@dataclass(slots=True)
class AssessmentPlan:
    target: str
    profile_matches: list[ProfileMatch]
    modules: list[PlannedModule]
    policy: RiskLevel
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class Finding:
    module_id: str
    title: str
    status: FindingStatus
    summary: str
    confidence: float
    evidence_ids: list[str] = field(default_factory=list)
    remediation: str | None = None
    timestamp: str = field(default_factory=utc_now)


@dataclass(slots=True)
class AssessmentResult:
    session_id: str
    target: Device
    plan: AssessmentPlan
    evidence: list[Evidence]
    findings: list[Finding]
    injection_verdict: InjectionVerdict
    verdict_reason: str
    started_at: str
    completed_at: str
    interrupted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
