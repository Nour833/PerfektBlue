#!/usr/bin/env python3
"""Verify release-tag and package-version alignment."""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path


def project_version(path: Path) -> str:
    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    return str(payload["project"]["version"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        raise SystemExit(f"invalid stable release tag: {args.tag}")
    expected = args.tag.removeprefix("v")
    versions = {
        "core": project_version(Path("pyproject.toml")),
        "can-plugin": project_version(Path("plugins/perfektblue-can/pyproject.toml")),
    }
    mismatched = {name: version for name, version in versions.items() if version != expected}
    if mismatched:
        details = ", ".join(f"{name}={version}" for name, version in mismatched.items())
        raise SystemExit(f"tag {args.tag} does not match: {details}")
    print(f"version alignment valid: {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
