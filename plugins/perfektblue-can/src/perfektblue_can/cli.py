"""CLI for the optional passive CAN plugin."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from perfektblue_can.analysis import analyze_file


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="perfektblue-can")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a candump text capture")
    analyze_parser.add_argument("capture", type=Path)
    interfaces_parser = subparsers.add_parser(
        "interfaces", help="List python-can configuration candidates"
    )
    interfaces_parser.add_argument("--json", action="store_true")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "analyze":
        print(json.dumps(analyze_file(args.capture), indent=2, sort_keys=True))
        return 0
    try:
        import can

        configurations = can.detect_available_configs()
    except Exception as exc:
        print(json.dumps({"error": str(exc), "interfaces": []}))
        return 1
    print(json.dumps({"interfaces": configurations}, indent=2, sort_keys=True))
    return 0


def main() -> int:
    return run()
