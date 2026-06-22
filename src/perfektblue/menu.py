"""Interactive terminal workspace for PerfektBlue."""

from __future__ import annotations

import importlib.util
from datetime import datetime
from pathlib import Path
from typing import Any

from perfektblue import __version__
from perfektblue.config import Config
from perfektblue.doctor import run_checks
from perfektblue.engine import AssessmentEngine
from perfektblue.models import AssessmentPlan, Device, ProfileMatch, RiskLevel
from perfektblue.modules import ModuleRegistry
from perfektblue.output import Output
from perfektblue.profiles import ProfileRegistry
from perfektblue.reporting import write_html_report, write_json_report
from perfektblue.storage import SessionStore

ACCENT = "bright_cyan"
MUTED = "grey62"
PANEL = "grey23"


def _device_name(device: Device) -> str:
    return device.name or device.alias or "Unnamed Bluetooth device"


def _risk_style(risk: RiskLevel) -> str:
    return {
        RiskLevel.PASSIVE: "green",
        RiskLevel.ACTIVE_SAFE: "yellow",
        RiskLevel.LAB_ACTIVE: "bold red",
    }[risk]


def _signal_label(rssi: int | None) -> str:
    if rssi is None:
        return "unknown"
    if rssi >= -50:
        return f"{rssi} dBm · strong"
    if rssi >= -70:
        return f"{rssi} dBm · good"
    return f"{rssi} dBm · weak"


class InteractiveMenu:
    """Stateful, keyboard-driven terminal navigation."""

    def __init__(
        self,
        engine: AssessmentEngine,
        output: Output,
        profiles: ProfileRegistry,
        modules: ModuleRegistry,
        store: SessionStore,
        config: Config,
    ) -> None:
        self.engine = engine
        self.output = output
        self.profiles = profiles
        self.modules = modules
        self.store = store
        self.config = config
        self.target: Device | None = None

    async def run(self) -> int:
        while True:
            self._dashboard()
            choice = self.output.prompt("Navigate", "1").casefold()
            if choice in {"1", "d", "discover"}:
                await self._discover()
            elif choice in {"2", "t", "target"}:
                await self._target_workspace()
            elif choice in {"3", "a", "assess"}:
                await self._guided_assessment()
            elif choice in {"4", "e", "environment", "doctor"}:
                await self._doctor()
            elif choice in {"5", "s", "sessions"}:
                self._sessions()
            elif choice in {"6", "l", "library", "profiles", "modules"}:
                self._library()
            elif choice in {"7", "c", "config", "settings"}:
                self._settings()
            elif choice in {"8", "can"}:
                self._can_status()
            elif choice in {"h", "help", "?"}:
                self._help()
            elif choice in {"q", "quit", "exit", "0", ""}:
                self._goodbye()
                return 0
            else:
                self._notice("Unknown action", "Use a number, shortcut letter, or `h` for help.")

    def _dashboard(self) -> None:
        self.output.clear()
        if self.output.console is None:
            self.output.print(f"PerfektBlue {__version__}")
            self.output.print("Bluetooth intelligence console")
            self.output.print(
                "1 Discover  2 Target  3 Assess  4 Doctor  5 Sessions  "
                "6 Library  7 Settings  8 CAN  H Help  Q Quit"
            )
            return

        from rich.align import Align
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        brand = Text()
        brand.append("PERFEKT", style="bold white")
        brand.append("BLUE", style="bold bright_cyan")
        brand.append(f"  {__version__}", style="grey62")
        subtitle = Text(
            "BLUETOOTH INTELLIGENCE CONSOLE",
            style="bold bright_cyan",
            justify="center",
        )
        self.output.render(
            Panel(
                Align.center(Group(brand, subtitle)),
                border_style=ACCENT,
                padding=(1, 2),
            )
        )

        target_value = (
            f"{_device_name(self.target)}\n[grey62]{self.target.address}[/]"
            if self.target
            else "[grey62]No target selected[/]"
        )
        cards = [
            self._status_card("BACKEND", self.config.backend.upper(), "BlueZ transport"),
            self._status_card(
                "POLICY",
                self.config.risk_policy.value.upper(),
                "Execution ceiling",
                _risk_style(self.config.risk_policy),
            ),
            self._status_card("TARGET", target_value, "Current workspace"),
            self._status_card(
                "SESSIONS",
                str(len(self.store.list_sessions())),
                "Stored assessments",
            ),
        ]
        status_grid = Table.grid(expand=True, padding=(0, 1))
        status_grid.add_column(ratio=1)
        status_grid.add_column(ratio=1)
        status_grid.add_row(cards[0], cards[1])
        status_grid.add_row(cards[2], cards[3])
        self.output.render(status_grid)

        menu = Table.grid(expand=True, padding=(0, 1))
        menu.add_column(width=5, justify="right", style="bold bright_cyan")
        menu.add_column(ratio=1, style="bold white")
        menu.add_column(ratio=2, style=MUTED)
        entries = [
            ("01", "Target discovery", "Scan, compare, and select a Bluetooth device"),
            ("02", "Target workspace", "Inspect evidence, fingerprint, and plan"),
            ("03", "Guided assessment", "Run compatible modules and save a report"),
            ("04", "Environment doctor", "Check BlueZ, adapters, and dependencies"),
            ("05", "Sessions & reports", "Review results and export HTML or JSON"),
            ("06", "Intelligence library", "Inspect installed profiles and modules"),
            ("07", "Settings & safety", "Review backend, thresholds, and policy"),
            ("08", "Optional CAN plugin", "Check isolated CAN analysis support"),
        ]
        for index, title, detail in entries:
            menu.add_row(index, title, detail)
        menu.add_row("H", "Help & shortcuts", "Navigation and verdict reference")
        menu.add_row("Q", "Exit", "Close the console safely")
        self.output.render(
            Panel(
                menu,
                title="[bold]Main workspace[/]",
                subtitle="[grey62]number or shortcut letter[/]",
                border_style=PANEL,
                padding=(1, 1),
            )
        )
        self.output.render(
            Align.center(
                Text(
                    "Passive by default · evidence before claims · Ctrl+C exits safely",
                    style="grey50",
                )
            )
        )

    def _status_card(
        self,
        label: str,
        value: str,
        detail: str,
        value_style: str = "bright_cyan",
    ) -> Any:
        from rich.console import Group
        from rich.panel import Panel
        from rich.text import Text

        return Panel(
            Group(
                Text(label, style="bold grey62"),
                Text.from_markup(f"[{value_style}]{value}[/]"),
                Text(detail, style="grey50"),
            ),
            border_style=PANEL,
            padding=(0, 1),
        )

    def _heading(self, section: str, detail: str) -> None:
        self.output.clear()
        if self.output.console is None:
            self.output.print(f"PerfektBlue / {section}")
            self.output.print(detail)
            return
        from rich.panel import Panel
        from rich.text import Text

        breadcrumb = Text("PERFEKTBLUE", style="bold bright_cyan")
        breadcrumb.append("  /  ", style="grey42")
        breadcrumb.append(section.upper(), style="bold white")
        body = Text(detail, style=MUTED)
        self.output.render(
            Panel(
                body,
                title=breadcrumb,
                title_align="left",
                border_style=ACCENT,
                padding=(1, 2),
            )
        )

    async def _discover(self) -> None:
        self._heading(
            "Target discovery",
            "Scanning through the configured Bluetooth backend. "
            "Keep the authorized target discoverable.",
        )
        if self.output.console is not None:
            with self.output.console.status(
                "[bright_cyan]Scanning Bluetooth environment…[/]",
                spinner="dots12",
            ):
                devices = await self.engine.discover()
        else:
            devices = await self.engine.discover()
        if not devices:
            self._notice(
                "No devices found",
                "Confirm the adapter is powered, open the target pairing screen, and scan again.",
            )
            return

        rows = [
            [
                str(index + 1),
                _device_name(device),
                device.address,
                _signal_label(device.rssi),
                len(device.service_uuids),
                "paired" if device.paired else "new",
            ]
            for index, device in enumerate(devices)
        ]
        self.output.table(
            "Discovered targets",
            ["#", "Device", "Address", "Signal", "Services", "State"],
            rows,
        )
        choice = self.output.prompt("Select target · B back", "1").casefold()
        if choice in {"b", "back", "q"}:
            return
        try:
            self.target = devices[int(choice) - 1]
        except (ValueError, IndexError):
            self._notice("Invalid selection", "Choose one of the displayed target numbers.")
            return
        self._target_summary(self.target, "Target selected")
        self.output.pause()

    async def _ensure_target(self) -> bool:
        if self.target is not None:
            return True
        self._notice(
            "Target required",
            "Select a Bluetooth device before opening the target workspace.",
            pause=False,
        )
        await self._discover()
        return self.target is not None

    async def _target_workspace(self) -> None:
        if not await self._ensure_target():
            return
        assert self.target is not None
        while True:
            self._heading(
                "Target workspace",
                f"{_device_name(self.target)} · {self.target.address}",
            )
            self._target_summary(self.target)
            self.output.table(
                "Actions",
                ["Key", "Action", "Purpose"],
                [
                    ["1", "Evidence overview", "Review discovered target properties"],
                    ["2", "Fingerprint", "Rank compatible target profiles"],
                    ["3", "Assessment plan", "Preview selected and skipped modules"],
                    ["4", "Run assessment", "Execute the current policy-safe plan"],
                    ["5", "Change target", "Return to Bluetooth discovery"],
                    ["B", "Back", "Return to the main workspace"],
                ],
            )
            choice = self.output.prompt("Target action", "2").casefold()
            if choice in {"1", "overview", "o"}:
                self._target_details(self.target)
            elif choice in {"2", "fingerprint", "f"}:
                self._show_fingerprint(self.target)
            elif choice in {"3", "plan", "p"}:
                self._show_plan(self.target)
            elif choice in {"4", "assess", "a"}:
                await self._assess(self.target)
            elif choice in {"5", "change", "d"}:
                await self._discover()
                if self.target is None:
                    return
            elif choice in {"b", "back", "q", ""}:
                return
            else:
                self._notice("Unknown action", "Choose one of the target workspace actions.")

    async def _guided_assessment(self) -> None:
        if not await self._ensure_target():
            return
        assert self.target is not None
        self._heading(
            "Guided assessment",
            "Reviewing compatibility and risk before any module executes.",
        )
        self._show_plan(self.target, pause=False)
        choice = self.output.prompt("Run selected modules? Y yes · B back", "y").casefold()
        if choice not in {"y", "yes"}:
            return
        await self._assess(self.target)

    async def _assess(self, target: Device) -> None:
        authorized = False
        if self.config.risk_policy == RiskLevel.LAB_ACTIVE:
            self._notice(
                "Lab-active policy",
                "Continue only with written authorization and an isolated lab target.",
                pause=False,
            )
            authorized = (
                self.output.prompt("Type AUTHORIZED to arm lab-active modules").strip()
                == "AUTHORIZED"
            )
            if not authorized:
                self._notice(
                    "Assessment not armed",
                    "Lab-active modules require exact authorization confirmation.",
                )
                return
        if self.output.console is not None:
            with self.output.console.status(
                "[bright_cyan]Executing compatible assessment modules…[/]",
                spinner="dots12",
            ):
                result = await self.engine.assess(target, authorized=authorized)
        else:
            result = await self.engine.assess(target, authorized=authorized)
        self._heading("Assessment complete", _device_name(target))
        verdict_style = {
            "confirmed-injectable": "bold red",
            "blocked": "bold green",
            "no-known-path": "yellow",
            "inconclusive": "yellow",
            "unsupported": "grey62",
        }.get(result.injection_verdict.value, "white")
        self._verdict_panel(
            result.injection_verdict.value,
            result.verdict_reason,
            result.session_id,
            verdict_style,
        )
        self.output.table(
            "Findings",
            ["Status", "Finding", "Confidence", "Module"],
            [
                [
                    finding.status.value,
                    finding.title,
                    f"{finding.confidence:.1f}%",
                    finding.module_id,
                ]
                for finding in result.findings
            ],
        )
        self.output.pause()

    async def _doctor(self) -> None:
        self._heading(
            "Environment doctor",
            "Validating local runtime, BlueZ access, and adapter readiness.",
        )
        if self.output.console is not None:
            with self.output.console.status("[bright_cyan]Running diagnostics…[/]"):
                checks = await run_checks(self.engine.backend)
        else:
            checks = await run_checks(self.engine.backend)
        self.output.table(
            "System readiness",
            ["State", "Check", "Required", "Detail"],
            [
                [
                    "READY" if check.ok else "ISSUE",
                    check.name,
                    "yes" if check.required else "optional",
                    check.detail,
                ]
                for check in checks
            ],
        )
        required_ok = all(check.ok or not check.required for check in checks)
        self._notice(
            "Environment ready" if required_ok else "Action required",
            (
                "All required checks passed."
                if required_ok
                else "Resolve required issues before assessing real targets."
            ),
        )

    def _sessions(self) -> None:
        while True:
            self._heading(
                "Sessions & reports",
                "Stored evidence remains available across PerfektBlue runs.",
            )
            sessions = self.store.list_sessions(limit=20)
            if not sessions:
                self._notice(
                    "No sessions yet",
                    "Run a guided assessment to create the first evidence record.",
                )
                return
            self.output.table(
                "Recent sessions",
                ["#", "Target", "Verdict", "Started", "Session"],
                [
                    [
                        str(index + 1),
                        item["target_name"] or item["target_address"],
                        item["verdict"],
                        self._short_time(str(item["started_at"])),
                        str(item["id"])[:8],
                    ]
                    for index, item in enumerate(sessions)
                ],
            )
            choice = self.output.prompt("Open session number · B back", "b").casefold()
            if choice in {"b", "back", "q", ""}:
                return
            try:
                session = sessions[int(choice) - 1]
            except (ValueError, IndexError):
                self._notice("Invalid selection", "Choose a displayed session number.")
                continue
            self._session_detail(str(session["id"]))

    def _session_detail(self, session_id: str) -> None:
        result = self.store.load_result(session_id)
        target = result["target"]
        self._heading(
            "Session detail",
            f"{target.get('name') or target['address']} · {session_id}",
        )
        self._verdict_panel(
            str(result["injection_verdict"]),
            str(result["verdict_reason"]),
            session_id,
            "bright_cyan",
        )
        findings = result.get("findings", [])
        self.output.table(
            "Recorded findings",
            ["Status", "Finding", "Confidence"],
            [
                [
                    item["status"],
                    item["title"],
                    f"{float(item['confidence']):.1f}%",
                ]
                for item in findings
            ],
        )
        action = self.output.prompt("H HTML report · J JSON export · B back", "b").casefold()
        if action in {"h", "html"}:
            destination = Path(f"perfektblue-report-{session_id}.html")
            write_html_report(result, destination)
            self._notice("HTML report created", str(destination.resolve()))
        elif action in {"j", "json"}:
            destination = Path(f"perfektblue-report-{session_id}.json")
            write_json_report(result, destination)
            self._notice("JSON report created", str(destination.resolve()))

    def _library(self) -> None:
        while True:
            profile_errors = self.profiles.validate()
            module_errors = self.modules.validate()
            self._heading(
                "Profile & module library",
                "Installed intelligence is explicit, versioned, and independently validated.",
            )
            self.output.table(
                "Library status",
                ["Collection", "Installed", "Validation"],
                [
                    [
                        "Target profiles",
                        len(self.profiles.all()),
                        "valid" if not profile_errors else f"{len(profile_errors)} issues",
                    ],
                    [
                        "Assessment modules",
                        len(self.modules.all()),
                        "valid" if not module_errors else f"{len(module_errors)} issues",
                    ],
                ],
            )
            self.output.table(
                "Actions",
                ["Key", "View"],
                [
                    ["1", "Target profiles"],
                    ["2", "Assessment modules"],
                    ["3", "Validation details"],
                    ["B", "Back"],
                ],
            )
            choice = self.output.prompt("Library action", "1").casefold()
            if choice in {"1", "profiles", "p"}:
                self.output.table(
                    "Target profiles",
                    ["Profile", "Vendor", "Firmware", "Mode"],
                    [
                        [
                            profile.name,
                            profile.vendor,
                            ", ".join(profile.firmware_ranges),
                            "simulation" if profile.simulated else "hardware",
                        ]
                        for profile in self.profiles.all()
                    ],
                )
                self.output.pause()
            elif choice in {"2", "modules", "m"}:
                self.output.table(
                    "Assessment modules",
                    ["Module", "Version", "Risk", "Profiles"],
                    [
                        [
                            module.manifest.name,
                            module.manifest.version,
                            module.manifest.risk.value,
                            len(module.manifest.supported_profiles) or "generic",
                        ]
                        for module in self.modules.all()
                    ],
                )
                self.output.pause()
            elif choice in {"3", "validate", "v"}:
                errors = profile_errors + module_errors
                self._notice(
                    "Library valid" if not errors else "Validation issues",
                    "All installed profiles and modules passed validation."
                    if not errors
                    else "\n".join(errors),
                )
            elif choice in {"b", "back", "q", ""}:
                return
            else:
                self._notice("Unknown action", "Choose profiles, modules, validation, or back.")

    def _settings(self) -> None:
        self._heading(
            "Settings & safety",
            "Runtime values follow CLI → environment → user TOML → system TOML → defaults.",
        )
        self.output.table(
            "Current runtime",
            ["Setting", "Value", "Meaning"],
            [
                ["Backend", self.config.backend, "Bluetooth provider"],
                ["Adapter", self.config.adapter or "automatic", "Selected controller"],
                ["Scan duration", f"{self.config.scan_seconds:g}s", "Discovery window"],
                ["Timeout", f"{self.config.command_timeout:g}s", "Operation ceiling"],
                ["Risk policy", self.config.risk_policy.value, "Maximum module risk"],
                [
                    "Auto-match",
                    f"{self.config.minimum_auto_match:g}%",
                    "Active selection threshold",
                ],
                [
                    "Suggested match",
                    f"{self.config.minimum_suggested_match:g}%",
                    "Profile suggestion threshold",
                ],
                [
                    "Identifier redaction",
                    "enabled" if self.config.redact_identifiers else "disabled",
                    "Export privacy",
                ],
            ],
        )
        self._notice(
            "Configuration is read-only in the menu",
            "Use `perfektblue --help` or ~/.config/perfektblue/config.toml "
            "to make deliberate, reproducible changes.",
        )

    def _can_status(self) -> None:
        self._heading(
            "Optional CAN plugin",
            "CAN remains isolated from the Bluetooth-first core framework.",
        )
        installed = importlib.util.find_spec("perfektblue_can") is not None
        self._notice(
            "perfektblue-can installed" if installed else "perfektblue-can not installed",
            (
                "Use `perfektblue can --help` for passive capture analysis."
                if installed
                else (
                    "Install the separate perfektblue-can package only when CAN analysis is needed."
                )
            ),
        )

    def _help(self) -> None:
        self._heading(
            "Help & shortcuts",
            "Every interactive action also has a stable automation command.",
        )
        self.output.table(
            "Navigation",
            ["Shortcut", "Action", "CLI equivalent"],
            [
                ["D", "Discover targets", "perfektblue discover"],
                ["T", "Target workspace", "inspect / fingerprint / plan"],
                ["A", "Guided assessment", "perfektblue assess TARGET"],
                ["E", "Environment doctor", "perfektblue doctor"],
                ["S", "Sessions", "perfektblue sessions list"],
                ["L", "Profile/module library", "profiles / modules"],
                ["B", "Back", "Return one level"],
                ["Q", "Quit", "Exit safely"],
            ],
        )
        self.output.table(
            "Verdict language",
            ["Verdict", "Meaning"],
            [
                ["confirmed-injectable", "A compatible module produced required proof"],
                ["blocked", "A known tested path was rejected"],
                ["no-known-path", "No installed path exists for the matched profile"],
                ["inconclusive", "Evidence or authorization was insufficient"],
                ["unsupported", "No target profile matched"],
            ],
        )
        self.output.pause()

    def _target_summary(self, device: Device, title: str = "Target context") -> None:
        self.output.table(
            title,
            ["Device", "Address", "Signal", "Services", "Security"],
            [
                [
                    _device_name(device),
                    device.address,
                    _signal_label(device.rssi),
                    len(device.service_uuids),
                    "paired" if device.paired else "unpaired",
                ]
            ],
        )

    def _target_details(self, device: Device) -> None:
        self._heading("Evidence overview", f"{_device_name(device)} · {device.address}")
        rows: list[list[Any]] = [
            ["Address type", device.address_type or "unknown"],
            ["Class", hex(device.device_class) if device.device_class is not None else "unknown"],
            ["Appearance", device.appearance if device.appearance is not None else "unknown"],
            ["RSSI", _signal_label(device.rssi)],
            ["Paired", device.paired],
            ["Bonded", device.bonded],
            ["Trusted", device.trusted],
            ["Connected", device.connected],
            ["Advertised services", len(device.service_uuids)],
            ["Resolved GATT services", len(device.services)],
            ["Manufacturer records", len(device.manufacturer_data)],
        ]
        self.output.table("Observed target evidence", ["Property", "Value"], rows)
        if device.service_uuids:
            self.output.table(
                "Service UUIDs",
                ["#", "UUID"],
                [[index + 1, uuid] for index, uuid in enumerate(device.service_uuids)],
            )
        self.output.pause()

    def _show_fingerprint(self, device: Device, pause: bool = True) -> None:
        matches = self.profiles.match(device)
        self._heading("Target fingerprint", f"{_device_name(device)} · explainable confidence")
        self.output.table(
            "Ranked profile matches",
            ["Profile", "Confidence", "Evidence", "Contradictions"],
            [
                [
                    match.profile_name,
                    f"{match.confidence:.1f}%",
                    f"{match.matched_weight:g}/{match.total_weight:g}",
                    len(match.contradictions),
                ]
                for match in matches
            ],
        )
        if matches:
            self._match_detail(matches[0])
        if pause:
            self.output.pause()

    def _match_detail(self, match: ProfileMatch) -> None:
        detail = (
            "\n".join(f"• {reason}" for reason in match.reasons) or "No matching evidence rules."
        )
        if match.contradictions:
            detail += "\n\nContradictions:\n" + "\n".join(
                f"• {item}" for item in match.contradictions
            )
        self._notice(
            f"Top candidate · {match.profile_name} · {match.confidence:.1f}%",
            detail,
            pause=False,
        )

    def _show_plan(self, device: Device, pause: bool = True) -> AssessmentPlan:
        plan, _ = self.engine.plan(device)
        self._heading("Assessment plan", f"{_device_name(device)} · policy-aware execution")
        self.output.table(
            "Module decisions",
            ["Decision", "Module", "Risk", "Reason"],
            [
                [
                    "RUN" if item.selected else "SKIP",
                    item.module_id,
                    item.risk.value,
                    item.reason,
                ]
                for item in plan.modules
            ],
        )
        selected = sum(item.selected for item in plan.modules)
        self._notice(
            f"{selected} selected · {len(plan.modules) - selected} skipped",
            "Skipped modules remain visible so the assessment is auditable.",
            pause=pause,
        )
        return plan

    def _verdict_panel(
        self,
        verdict: str,
        reason: str,
        session_id: str,
        style: str,
    ) -> None:
        if self.output.console is None:
            self.output.print(f"Verdict: {verdict}")
            self.output.print(reason)
            self.output.print(f"Session: {session_id}")
            return
        from rich.panel import Panel
        from rich.text import Text

        body = Text()
        body.append(verdict.upper(), style=style)
        body.append("\n")
        body.append(reason, style="white")
        body.append(f"\n\nSession  {session_id}", style="grey62")
        self.output.render(
            Panel(
                body,
                title="[bold]Evidence-backed verdict[/]",
                border_style=style,
                padding=(1, 2),
            )
        )

    def _notice(
        self,
        title: str,
        message: str,
        pause: bool = True,
    ) -> None:
        if self.output.console is None:
            self.output.print(title)
            self.output.print(message)
        else:
            from rich.panel import Panel

            self.output.render(
                Panel(
                    message,
                    title=f"[bold]{title}[/]",
                    title_align="left",
                    border_style=PANEL,
                    padding=(1, 2),
                )
            )
        if pause:
            self.output.pause()

    def _goodbye(self) -> None:
        self.output.clear()
        self.output.rule("Session closed")
        self.output.print(
            "No background operations remain. Evidence is stored in the session workspace.",
            style=MUTED,
        )

    @staticmethod
    def _short_time(value: str) -> str:
        try:
            return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return value
