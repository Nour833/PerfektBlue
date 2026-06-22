"""Risk-policy enforcement for module planning and execution."""

from __future__ import annotations

from perfektblue.errors import SafetyPolicyError
from perfektblue.models import RiskLevel

RISK_ORDER = {
    RiskLevel.PASSIVE: 0,
    RiskLevel.ACTIVE_SAFE: 1,
    RiskLevel.LAB_ACTIVE: 2,
}


def risk_allowed(requested: RiskLevel, policy: RiskLevel) -> bool:
    return RISK_ORDER[requested] <= RISK_ORDER[policy]


def enforce_execution(risk: RiskLevel, policy: RiskLevel, authorized: bool) -> None:
    if not risk_allowed(risk, policy):
        raise SafetyPolicyError(f"{risk.value} operation exceeds {policy.value} policy")
    if risk == RiskLevel.LAB_ACTIVE and not authorized:
        raise SafetyPolicyError(
            "lab-active operation requires explicit authorized-session confirmation"
        )
