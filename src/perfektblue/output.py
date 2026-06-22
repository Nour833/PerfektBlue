"""Terminal output with a dependency-free fallback."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, is_dataclass
from typing import Any, cast


def serializable(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(cast(Any, value))
    if hasattr(value, "value"):
        return value.value
    return value


class Output:
    def __init__(self, json_mode: bool = False, no_color: bool = False) -> None:
        self.json_mode = json_mode
        try:
            from rich.console import Console

            self.console: Any = Console(no_color=no_color)
        except ImportError:
            self.console = None

    def emit_json(self, value: Any) -> None:
        print(json.dumps(value, default=serializable, indent=2, sort_keys=True))

    def print(self, message: str, style: str | None = None) -> None:
        if self.console is not None:
            self.console.print(message, style=style)
        else:
            print(message)

    def render(self, renderable: Any) -> None:
        if self.console is not None:
            self.console.print(renderable)
        else:
            print(str(renderable))

    def clear(self) -> None:
        if self.console is not None and sys.stdout.isatty():
            self.console.clear()

    def rule(self, title: str = "") -> None:
        if self.console is not None:
            self.console.rule(title, style="bright_cyan")
        else:
            self.print(f"── {title} ──" if title else "─" * 48)

    def prompt(self, label: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default is not None else ""
        try:
            value = input(f"{label}{suffix}: ").strip()
        except EOFError:
            return ""
        return value or (default or "")

    def pause(self, message: str = "Press Enter to continue") -> None:
        if not sys.stdin.isatty():
            return
        try:
            input(f"\n{message}")
        except EOFError:
            return

    def table(self, title: str, columns: list[str], rows: list[list[Any]]) -> None:
        if self.console is not None:
            from rich.table import Table

            table = Table(title=title)
            for column in columns:
                table.add_column(column)
            for row in rows:
                table.add_row(*(str(item) for item in row))
            self.console.print(table)
            return
        self.print(title)
        self.print(" | ".join(columns))
        for row in rows:
            self.print(" | ".join(str(item) for item in row))
