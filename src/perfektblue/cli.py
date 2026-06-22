"""PerfektBlue command-line interface and guided wizard."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from perfektblue import __version__
from perfektblue.bluetooth import BluetoothBackend, BlueZBackend, SimulatedBackend
from perfektblue.config import Config, load_config
from perfektblue.doctor import checks_to_dict, run_checks
from perfektblue.engine import AssessmentEngine
from perfektblue.errors import PerfektBlueError
from perfektblue.fingerprint import fingerprint
from perfektblue.models import Device, RiskLevel
from perfektblue.modules import ModuleRegistry
from perfektblue.output import Output
from perfektblue.profiles import ProfileRegistry
from perfektblue.reporting import write_html_report, write_json_report
from perfektblue.storage import SessionStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="perfektblue",
        description="Bluetooth-first adaptive security assessment framework",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=Path, help="Path to a TOML configuration file")
    parser.add_argument("--backend", choices=["bluez", "simulated"])
    parser.add_argument("--adapter", help="BlueZ object path for the adapter")
    parser.add_argument("--scan-seconds", type=float)
    parser.add_argument("--risk", choices=[item.value for item in RiskLevel])
    parser.add_argument(
        "--scenario",
        choices=["vulnerable", "patched", "unknown"],
        help="Simulator scenario",
    )
    parser.add_argument("--json", action="store_true", help="Emit stable JSON output")
    parser.add_argument("--no-color", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("wizard", help="Run the guided Bluetooth assessment workflow")
    subparsers.add_parser("doctor", help="Check runtime capabilities")
    subparsers.add_parser("adapters", help="List Bluetooth adapters")
    subparsers.add_parser("discover", help="Discover nearby Bluetooth devices")

    inspect_parser = subparsers.add_parser("inspect", help="Inspect a known Bluetooth target")
    inspect_parser.add_argument("target")

    fingerprint_parser = subparsers.add_parser("fingerprint", help="Fingerprint a Bluetooth target")
    fingerprint_parser.add_argument("target")

    plan_parser = subparsers.add_parser("plan", help="Build an evidence-driven assessment plan")
    plan_parser.add_argument("target")

    assess_parser = subparsers.add_parser("assess", help="Assess a Bluetooth target")
    assess_parser.add_argument("target", nargs="?")
    assess_parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm written authorization for lab-active modules",
    )

    profiles_parser = subparsers.add_parser("profiles", help="Inspect target profiles")
    profiles_sub = profiles_parser.add_subparsers(dest="profiles_command", required=True)
    profiles_sub.add_parser("list")
    profiles_sub.add_parser("validate")
    profile_match = profiles_sub.add_parser("match")
    profile_match.add_argument("target")

    modules_parser = subparsers.add_parser("modules", help="Inspect assessment modules")
    modules_sub = modules_parser.add_subparsers(dest="modules_command", required=True)
    modules_sub.add_parser("list")
    modules_sub.add_parser("validate")
    module_describe = modules_sub.add_parser("describe")
    module_describe.add_argument("module_id")

    sessions_parser = subparsers.add_parser("sessions", help="Inspect stored sessions")
    sessions_sub = sessions_parser.add_subparsers(dest="sessions_command", required=True)
    sessions_sub.add_parser("list")
    session_show = sessions_sub.add_parser("show")
    session_show.add_argument("session_id")
    session_export = sessions_sub.add_parser("export")
    session_export.add_argument("session_id")
    session_export.add_argument("--output", required=True, type=Path)

    report_parser = subparsers.add_parser("report", help="Generate a session report")
    report_parser.add_argument("session_id")
    report_parser.add_argument("--format", choices=["html", "json"], default="html")
    report_parser.add_argument("--output", type=Path)

    migrate_parser = subparsers.add_parser("migrate", help="Import legacy data")
    migrate_sub = migrate_parser.add_subparsers(dest="migrate_command", required=True)
    migrate_can = migrate_sub.add_parser("legacy-can")
    migrate_can.add_argument("path", type=Path)

    can_parser = subparsers.add_parser("can", help="Optional CAN plugin; install perfektblue-can")
    can_parser.add_argument("can_args", nargs=argparse.REMAINDER)
    return parser


def _config_from_args(args: argparse.Namespace) -> Config:
    overrides = {
        "backend": args.backend,
        "adapter": args.adapter,
        "scan_seconds": args.scan_seconds,
        "risk_policy": args.risk,
        "simulated_scenario": args.scenario,
    }
    return load_config(overrides, config_path=args.config)


def _backend(config: Config) -> BluetoothBackend:
    if config.backend == "simulated":
        return SimulatedBackend(config.simulated_scenario)
    return BlueZBackend()


def _device_rows(devices: list[Device]) -> list[list[Any]]:
    return [
        [
            item.address,
            item.name or item.alias or "Unnamed",
            item.rssi if item.rssi is not None else "",
            len(item.service_uuids),
            "yes" if item.paired else "no",
        ]
        for item in devices
    ]


async def _resolve(engine: AssessmentEngine, target: str) -> Device:
    return await engine.resolve_target(target)


async def _wizard(engine: AssessmentEngine, output: Output) -> int:
    output.print("PerfektBlue guided Bluetooth assessment", style="bold cyan")
    devices = await engine.discover()
    if not devices:
        output.print("No Bluetooth devices were discovered.", style="yellow")
        return 3
    output.table(
        "Discovered devices",
        ["Index", "Address", "Name", "RSSI", "Services"],
        [
            [
                index,
                item.address,
                item.name or item.alias or "Unnamed",
                item.rssi if item.rssi is not None else "",
                len(item.service_uuids),
            ]
            for index, item in enumerate(devices)
        ],
    )
    if not sys.stdin.isatty():
        selected = devices[0]
    else:
        choice = input("Select target index [0]: ").strip() or "0"
        try:
            selected = devices[int(choice)]
        except (ValueError, IndexError):
            output.print("Invalid target selection.", style="red")
            return 2
    plan, _ = engine.plan(selected)
    output.table(
        "Assessment plan",
        ["Module", "Risk", "Decision", "Reason"],
        [
            [
                item.module_id,
                item.risk.value,
                "run" if item.selected else "skip",
                item.reason,
            ]
            for item in plan.modules
        ],
    )
    authorized = False
    if engine.config.risk_policy == RiskLevel.LAB_ACTIVE:
        if not sys.stdin.isatty():
            output.print(
                "Non-interactive lab-active wizard requires the assess command with --authorized.",
                style="red",
            )
            return 2
        confirmation = input(
            "Confirm written authorization for this lab target by typing AUTHORIZED: "
        ).strip()
        authorized = confirmation == "AUTHORIZED"
        if not authorized:
            output.print("Lab-active modules were not authorized.", style="yellow")
    result = await engine.assess(selected, authorized=authorized)
    output.print(f"Verdict: {result.injection_verdict.value}", style="bold cyan")
    output.print(result.verdict_reason)
    output.print(f"Session: {result.session_id}")
    return 0


async def _run(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    output = Output(json_mode=args.json, no_color=args.no_color)
    backend = _backend(config)
    profiles = ProfileRegistry()
    modules = ModuleRegistry()
    needs_store = args.command in {"wizard", "assess", "sessions", "report", "migrate"}
    store = SessionStore() if needs_store else None
    engine = AssessmentEngine(backend, config, profiles, modules, store)

    if args.command == "wizard":
        return await _wizard(engine, output)
    if args.command == "doctor":
        checks = await run_checks(backend)
        check_payload = checks_to_dict(checks)
        if args.json:
            output.emit_json(check_payload)
        else:
            output.table(
                "Environment checks",
                ["Check", "Result", "Required", "Detail"],
                [
                    [
                        item.name,
                        "ok" if item.ok else "failed",
                        "yes" if item.required else "no",
                        item.detail,
                    ]
                    for item in checks
                ],
            )
        return 0 if all(item.ok or not item.required for item in checks) else 4
    if args.command == "adapters":
        adapters = await backend.adapters()
        if args.json:
            output.emit_json([asdict(item) for item in adapters])
        else:
            output.table(
                "Bluetooth adapters",
                ["ID", "Address", "Name", "Powered", "Discovering"],
                [
                    [
                        item.id,
                        item.address or "",
                        item.name or "",
                        item.powered,
                        item.discovering,
                    ]
                    for item in adapters
                ],
            )
        return 0
    if args.command == "discover":
        devices = await engine.discover()
        if args.json:
            output.emit_json([asdict(item) for item in devices])
        else:
            output.table(
                "Discovered Bluetooth devices",
                ["Address", "Name", "RSSI", "Services", "Paired"],
                _device_rows(devices),
            )
        return 0 if devices else 3
    if args.command == "inspect":
        device = await _resolve(engine, args.target)
        if args.json:
            output.emit_json(asdict(device))
        else:
            output.table(
                "Target details",
                ["Field", "Value"],
                [[key, json.dumps(value)] for key, value in asdict(device).items()],
            )
        return 0
    if args.command == "fingerprint":
        device = await _resolve(engine, args.target)
        matches, evidence = fingerprint(device, profiles)
        fingerprint_payload = {
            "target": asdict(device),
            "matches": [asdict(item) for item in matches],
            "evidence": [asdict(item) for item in evidence],
        }
        if args.json:
            output.emit_json(fingerprint_payload)
        else:
            output.table(
                "Profile matches",
                ["Profile", "Confidence", "Matched", "Contradictions"],
                [
                    [
                        item.profile_name,
                        f"{item.confidence:.1f}%",
                        f"{item.matched_weight:g}/{item.total_weight:g}",
                        "; ".join(item.contradictions),
                    ]
                    for item in matches
                ],
            )
        return 0
    if args.command == "plan":
        device = await _resolve(engine, args.target)
        plan, evidence = engine.plan(device)
        plan_payload = {
            "plan": asdict(plan),
            "evidence": [asdict(item) for item in evidence],
        }
        if args.json:
            output.emit_json(plan_payload)
        else:
            output.table(
                "Assessment plan",
                ["Module", "Risk", "Decision", "Reason"],
                [
                    [
                        item.module_id,
                        item.risk.value,
                        "run" if item.selected else "skip",
                        item.reason,
                    ]
                    for item in plan.modules
                ],
            )
        return 0
    if args.command == "assess":
        if config.risk_policy == RiskLevel.LAB_ACTIVE and not args.authorized:
            output.print(
                "lab-active policy requires --authorized after verifying written authorization",
                style="red",
            )
            return 2
        device = await engine.resolve_target(args.target)
        assessment_result = await engine.assess(device, authorized=args.authorized)
        if args.json:
            output.emit_json(assessment_result.to_dict())
        else:
            output.print(
                f"Injection assessment: {assessment_result.injection_verdict.value}",
                style="bold cyan",
            )
            output.print(assessment_result.verdict_reason)
            output.table(
                "Findings",
                ["Module", "Status", "Title", "Confidence"],
                [
                    [
                        item.module_id,
                        item.status.value,
                        item.title,
                        f"{item.confidence:.1f}%",
                    ]
                    for item in assessment_result.findings
                ],
            )
            output.print(f"Session: {assessment_result.session_id}")
        return 0
    if args.command == "profiles":
        if args.profiles_command == "list":
            profile_items = profiles.all()
            if args.json:
                output.emit_json([asdict(item) for item in profile_items])
            else:
                output.table(
                    "Target profiles",
                    ["ID", "Name", "Vendor", "Firmware", "Simulated"],
                    [
                        [
                            item.id,
                            item.name,
                            item.vendor,
                            ", ".join(item.firmware_ranges),
                            item.simulated,
                        ]
                        for item in profile_items
                    ],
                )
            return 0
        if args.profiles_command == "validate":
            errors = profiles.validate()
            if args.json:
                output.emit_json({"valid": not errors, "errors": errors})
            else:
                output.print("Profiles valid." if not errors else "\n".join(errors))
            return 0 if not errors else 5
        device = await _resolve(engine, args.target)
        matches = profiles.match(device)
        if args.json:
            output.emit_json([asdict(item) for item in matches])
        else:
            output.table(
                "Profile matches",
                ["Profile", "Confidence", "Reasons"],
                [
                    [item.profile_name, f"{item.confidence:.1f}%", "; ".join(item.reasons)]
                    for item in matches
                ],
            )
        return 0
    if args.command == "modules":
        if args.modules_command == "list":
            module_items = modules.all()
            if args.json:
                output.emit_json([asdict(item.manifest) for item in module_items])
            else:
                output.table(
                    "Assessment modules",
                    ["ID", "Name", "Version", "Risk"],
                    [
                        [
                            item.manifest.id,
                            item.manifest.name,
                            item.manifest.version,
                            item.manifest.risk.value,
                        ]
                        for item in module_items
                    ],
                )
            return 0
        if args.modules_command == "validate":
            errors = modules.validate()
            if args.json:
                output.emit_json({"valid": not errors, "errors": errors})
            else:
                output.print("Modules valid." if not errors else "\n".join(errors))
            return 0 if not errors else 5
        module = modules.get(args.module_id)
        if module is None:
            output.print(f"Unknown module: {args.module_id}", style="red")
            return 3
        if args.json:
            output.emit_json(asdict(module.manifest))
        else:
            output.table(
                module.manifest.name,
                ["Field", "Value"],
                [
                    [key, json.dumps(value, default=str)]
                    for key, value in asdict(module.manifest).items()
                ],
            )
        return 0
    if args.command == "sessions":
        assert store is not None
        if args.sessions_command == "list":
            sessions = store.list_sessions()
            if args.json:
                output.emit_json(sessions)
            else:
                output.table(
                    "Assessment sessions",
                    ["ID", "Target", "Verdict", "Started"],
                    [
                        [
                            item["id"],
                            item["target_name"] or item["target_address"],
                            item["verdict"],
                            item["started_at"],
                        ]
                        for item in sessions
                    ],
                )
            return 0
        session_result = store.load_result(args.session_id)
        if args.sessions_command == "show":
            if args.json:
                output.emit_json(session_result)
            else:
                output.print(json.dumps(session_result, indent=2))
            return 0
        write_json_report(session_result, args.output)
        output.print(str(args.output))
        return 0
    if args.command == "report":
        assert store is not None
        report_result = store.load_result(args.session_id)
        destination = args.output
        if destination is None:
            suffix = "html" if args.format == "html" else "json"
            destination = Path(f"perfektblue-report-{args.session_id}.{suffix}")
        if args.format == "html":
            write_html_report(report_result, destination)
        else:
            write_json_report(report_result, destination)
        if args.json:
            output.emit_json({"output": str(destination), "format": args.format})
        else:
            output.print(str(destination))
        return 0
    if args.command == "migrate":
        assert store is not None
        evidence = store.import_legacy_can(args.path)
        migration_payload = [asdict(item) for item in evidence]
        if args.json:
            output.emit_json(migration_payload)
        else:
            output.print(f"Validated {len(evidence)} legacy CAN records.")
            output.print(
                "CAN records are returned as evidence only; install perfektblue-can "
                "to create CAN sessions."
            )
        return 0
    if args.command == "can":
        try:
            can_cli = importlib.import_module("perfektblue_can.cli")
        except ImportError:
            output.print(
                "The CAN plugin is not installed. Install the separate perfektblue-can package.",
                style="yellow",
            )
            return 6
        return int(can_cli.run(args.can_args))
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except PerfektBlueError as exc:
        if getattr(args, "json", False):
            print(json.dumps({"error": type(exc).__name__, "message": str(exc)}))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
