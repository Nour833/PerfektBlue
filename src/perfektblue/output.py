"""Terminal output with a dependency-free fallback."""

from __future__ import annotations

import json
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
