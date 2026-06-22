"""Evidence extraction and explainable target fingerprinting."""

from __future__ import annotations

from perfektblue.models import Device, Evidence, ProfileMatch
from perfektblue.profiles import ProfileRegistry


def collect_device_evidence(device: Device) -> list[Evidence]:
    evidence = [
        Evidence(
            kind="bluetooth-address",
            source=device.backend,
            value=device.address,
            confidence=100.0,
            detail="Address reported by the Bluetooth backend.",
            target=device.address,
        ),
        Evidence(
            kind="service-inventory",
            source=device.backend,
            value=sorted(device.service_uuids),
            confidence=85.0 if device.service_uuids else 30.0,
            detail=(
                "Service UUIDs reported by BlueZ."
                if device.service_uuids
                else "No service UUIDs were available; discovery may be incomplete."
            ),
            target=device.address,
        ),
    ]
    if device.name:
        evidence.append(
            Evidence(
                kind="device-name",
                source=device.backend,
                value=device.name,
                confidence=55.0,
                detail="Device names are useful hints but are user-changeable.",
                target=device.address,
            )
        )
    if device.device_class is not None:
        evidence.append(
            Evidence(
                kind="class-of-device",
                source=device.backend,
                value=device.device_class,
                confidence=65.0,
                detail="Bluetooth class-of-device value.",
                target=device.address,
            )
        )
    if device.manufacturer_data:
        evidence.append(
            Evidence(
                kind="manufacturer-data",
                source=device.backend,
                value=device.manufacturer_data,
                confidence=80.0,
                detail="Manufacturer-specific advertisement data.",
                target=device.address,
            )
        )
    evidence.append(
        Evidence(
            kind="link-security-state",
            source=device.backend,
            value={
                "paired": device.paired,
                "bonded": device.bonded,
                "trusted": device.trusted,
                "connected": device.connected,
            },
            confidence=90.0,
            detail="Security and connection state reported by the backend.",
            target=device.address,
        )
    )
    return evidence


def profile_match_evidence(device: Device, matches: list[ProfileMatch]) -> list[Evidence]:
    return [
        Evidence(
            kind="profile-match",
            source="fingerprint-engine",
            value={
                "profile_id": match.profile_id,
                "confidence": match.confidence,
                "reasons": match.reasons,
                "contradictions": match.contradictions,
            },
            confidence=match.confidence,
            detail=f"Explainable profile score for {match.profile_name}.",
            target=device.address,
        )
        for match in matches
    ]


def fingerprint(
    device: Device, registry: ProfileRegistry
) -> tuple[list[ProfileMatch], list[Evidence]]:
    matches = registry.match(device)
    evidence = collect_device_evidence(device)
    evidence.extend(profile_match_evidence(device, matches))
    return matches, evidence
