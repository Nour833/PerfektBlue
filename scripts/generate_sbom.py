#!/usr/bin/env python3
"""Generate a compact SPDX 2.3 JSON SBOM for release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
from datetime import UTC, datetime
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    with Path("pyproject.toml").open("rb") as handle:
        version = str(tomllib.load(handle)["project"]["version"])
    namespace_hash = hashlib.sha256(
        "".join(sorted(str(item) + sha256(item) for item in args.artifacts)).encode()
    ).hexdigest()
    files = [
        {
            "SPDXID": f"SPDXRef-File-{index}",
            "fileName": path.name,
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(path)}],
        }
        for index, path in enumerate(args.artifacts, 1)
    ]
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"PerfektBlue-{version}",
        "documentNamespace": f"https://github.com/Nour833/PerfektBlue/sbom/{namespace_hash}",
        "creationInfo": {
            "created": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: PerfektBlue generate_sbom.py"],
        },
        "packages": [
            {
                "name": "perfektblue",
                "SPDXID": "SPDXRef-Package-PerfektBlue",
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
            }
        ],
        "files": files,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-Package-PerfektBlue",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": item["SPDXID"],
            }
            for item in files
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
