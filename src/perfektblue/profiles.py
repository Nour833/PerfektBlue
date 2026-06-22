"""Target profile loading, validation, and matching."""

from __future__ import annotations

import json
from dataclasses import fields
from importlib.resources import files
from pathlib import Path
from typing import Any

from perfektblue.errors import ProfileError
from perfektblue.models import Device, MatchRule, ProfileMatch, TargetProfile


def _normalize_uuid(value: str) -> str:
    return value.strip().lower()


def _nested_value(device: Device, field_name: str) -> Any:
    current: Any = device
    for part in field_name.split("."):
        if hasattr(current, part):
            current = getattr(current, part)
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _matches(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "equals":
        if isinstance(actual, str) and isinstance(expected, str):
            return actual.casefold() == expected.casefold()
        return bool(actual == expected)
    if operator == "contains":
        if isinstance(actual, str):
            return str(expected).casefold() in actual.casefold()
        if isinstance(actual, (list, tuple, set)):
            if isinstance(expected, str):
                return _normalize_uuid(expected) in {_normalize_uuid(str(item)) for item in actual}
            return expected in actual
        if isinstance(actual, dict):
            return str(expected) in {str(key) for key in actual}
        return False
    if operator == "starts_with":
        return isinstance(actual, str) and actual.casefold().startswith(str(expected).casefold())
    if operator == "present":
        return actual not in (None, "", [], {})
    if operator == "truthy":
        return bool(actual) is bool(expected)
    raise ProfileError(f"unknown profile match operator: {operator}")


def profile_from_dict(payload: dict[str, Any]) -> TargetProfile:
    required = {"id", "name", "vendor", "product_family", "firmware_ranges", "rules"}
    missing = required.difference(payload)
    if missing:
        raise ProfileError(f"profile is missing fields: {', '.join(sorted(missing))}")
    rules_payload = payload["rules"]
    if not isinstance(rules_payload, list) or not rules_payload:
        raise ProfileError("profile rules must be a non-empty list")
    rules: list[MatchRule] = []
    for raw in rules_payload:
        if not isinstance(raw, dict):
            raise ProfileError("each profile rule must be an object")
        try:
            rule = MatchRule(
                field=str(raw["field"]),
                operator=str(raw["operator"]),
                value=raw.get("value"),
                weight=float(raw["weight"]),
                required=bool(raw.get("required", False)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProfileError(f"invalid profile rule: {raw}") from exc
        if rule.weight <= 0:
            raise ProfileError("profile rule weights must be positive")
        rules.append(rule)
    known = {item.name for item in fields(TargetProfile)}
    values = {key: value for key, value in payload.items() if key in known and key != "rules"}
    return TargetProfile(rules=rules, **values)


class ProfileRegistry:
    def __init__(self, extra_paths: list[Path] | None = None) -> None:
        self.extra_paths = extra_paths or []
        self._profiles: dict[str, TargetProfile] = {}
        self.reload()

    def reload(self) -> None:
        self._profiles.clear()
        builtin = files("perfektblue").joinpath("data/profiles")
        for item in builtin.iterdir():
            if item.name.endswith(".json"):
                self._load_text(item.read_text(encoding="utf-8"), item.name)
        for path in self.extra_paths:
            if path.is_dir():
                for item in sorted(path.glob("*.json")):
                    self._load_text(item.read_text(encoding="utf-8"), str(item))
            elif path.exists():
                self._load_text(path.read_text(encoding="utf-8"), str(path))

    def _load_text(self, text: str, source: str) -> None:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProfileError(f"invalid JSON in {source}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ProfileError(f"profile {source} must be a JSON object")
        profile = profile_from_dict(payload)
        if profile.id in self._profiles:
            raise ProfileError(f"duplicate profile id: {profile.id}")
        self._profiles[profile.id] = profile

    def all(self) -> list[TargetProfile]:
        return sorted(self._profiles.values(), key=lambda item: item.id)

    def get(self, profile_id: str) -> TargetProfile | None:
        return self._profiles.get(profile_id)

    def match(self, device: Device) -> list[ProfileMatch]:
        matches: list[ProfileMatch] = []
        for profile in self.all():
            total = sum(rule.weight for rule in profile.rules)
            matched = 0.0
            reasons: list[str] = []
            contradictions: list[str] = []
            required_failed = False
            for rule in profile.rules:
                actual = _nested_value(device, rule.field)
                if _matches(actual, rule.operator, rule.value):
                    matched += rule.weight
                    reasons.append(
                        f"{rule.field} {rule.operator} {rule.value!r} (+{rule.weight:g})"
                    )
                elif rule.required:
                    required_failed = True
                    contradictions.append(
                        f"required {rule.field} did not satisfy {rule.operator} {rule.value!r}"
                    )
            confidence = 0.0 if required_failed else round((matched / total) * 100, 2)
            matches.append(
                ProfileMatch(
                    profile_id=profile.id,
                    profile_name=profile.name,
                    confidence=confidence,
                    matched_weight=matched,
                    total_weight=total,
                    reasons=reasons,
                    contradictions=contradictions,
                )
            )
        return sorted(matches, key=lambda item: item.confidence, reverse=True)

    def validate(self) -> list[str]:
        errors: list[str] = []
        for profile in self.all():
            if profile.schema_version != 1:
                errors.append(f"{profile.id}: unsupported schema version")
            if len({rule.field for rule in profile.rules}) != len(profile.rules):
                errors.append(f"{profile.id}: duplicate match fields")
            for module_id in profile.compatible_modules:
                if not module_id.strip():
                    errors.append(f"{profile.id}: blank module id")
        return errors
