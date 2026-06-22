#!/usr/bin/env python3
"""Build a reproducible Debian binary package without a checked-in staging tree."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import shutil
import stat
import subprocess
import tomllib
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def source_epoch() -> int:
    configured = os.environ.get("SOURCE_DATE_EPOCH")
    if configured:
        return int(configured)
    result = subprocess.run(
        ["git", "log", "-1", "--pretty=%ct"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return int(result.stdout.strip())


def write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def gzip_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (
        source.open("rb") as input_handle,
        destination.open("wb") as output_handle,
        gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=output_handle,
            compresslevel=9,
            mtime=0,
        ) as compressed,
    ):
        shutil.copyfileobj(input_handle, compressed)


def gzip_text(content: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (
        destination.open("wb") as output_handle,
        gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=output_handle,
            compresslevel=9,
            mtime=0,
        ) as compressed,
    ):
        compressed.write(content.encode("utf-8"))


def debian_changelog(app_version: str, revision: str, epoch: int) -> str:
    released = format_datetime(datetime.fromtimestamp(epoch, UTC))
    return (
        f"perfektblue ({app_version}-{revision}) stable; urgency=medium\n\n"
        "  * Release PerfektBlue 2.0 as a Bluetooth-first adaptive framework.\n"
        "  * Add BlueZ discovery, evidence-driven profiles, reports, and simulations.\n"
        "  * Replace checked-in package staging with reproducible release builds.\n\n"
        f" -- Nour833 <nourelislem84@outlook.fr>  {released}\n"
    )


def generate_md5sums(stage: Path) -> None:
    entries: list[str] = []
    for path in sorted(stage.rglob("*")):
        if not path.is_file() or "DEBIAN" in path.parts:
            continue
        digest = hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()
        entries.append(f"{digest}  {path.relative_to(stage)}")
    write(stage / "DEBIAN/md5sums", "\n".join(entries) + "\n")


def write_distribution_metadata(stage: Path, app_version: str) -> None:
    metadata_dir = stage / "usr/lib/python3/dist-packages" / f"perfektblue-{app_version}.dist-info"
    write(
        metadata_dir / "METADATA",
        (
            "Metadata-Version: 2.4\n"
            "Name: perfektblue\n"
            f"Version: {app_version}\n"
            "Summary: Bluetooth-first adaptive security assessment framework\n"
            "License-Expression: MIT\n"
            "Requires-Python: >=3.11\n"
        ),
    )
    write(
        metadata_dir / "entry_points.txt",
        "[console_scripts]\nperfektblue = perfektblue.cli:main\n",
    )
    write(metadata_dir / "top_level.txt", "perfektblue\n")


def normalize_metadata(stage: Path, epoch: int) -> None:
    for path in sorted(stage.rglob("*")):
        os.utime(path, (epoch, epoch), follow_symlinks=False)
        if path.is_dir():
            path.chmod(0o755)
        elif path.name == "perfektblue":
            current = path.stat().st_mode
            path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--revision", default="1")
    args = parser.parse_args()

    app_version = version()
    deb_version = f"{app_version}-{args.revision}"
    epoch = source_epoch()
    build_root = ROOT / "build/debian"
    stage = build_root / "root"
    if build_root.exists():
        shutil.rmtree(build_root)
    stage.mkdir(parents=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    control = f"""Package: perfektblue
Version: {deb_version}
Section: utils
Priority: optional
Architecture: all
Maintainer: Nour833 <nourelislem84@outlook.fr>
Depends: python3 (>= 3.11), python3-dbus-next, python3-rich, bluez
Description: Bluetooth-first adaptive security assessment framework
 Discovers Bluetooth targets through BlueZ, matches evidence-backed profiles,
 plans compatible assessment modules, and produces reproducible reports.
"""
    write(stage / "DEBIAN/control", control)

    package_destination = stage / "usr/lib/python3/dist-packages/perfektblue"
    copy_tree(ROOT / "src/perfektblue", package_destination)
    write_distribution_metadata(stage, app_version)
    launcher = """#!/usr/bin/python3
from perfektblue.cli import main

raise SystemExit(main())
"""
    write(stage / "usr/bin/perfektblue", launcher, 0o755)
    copy_file(
        ROOT / "assets/perfektblue.desktop",
        stage / "usr/share/applications/perfektblue.desktop",
    )
    copy_file(
        ROOT / "logo.png",
        stage / "usr/share/icons/hicolor/512x512/apps/perfektblue.png",
    )
    gzip_copy(
        ROOT / "docs/perfektblue.1",
        stage / "usr/share/man/man1/perfektblue.1.gz",
    )
    copy_file(ROOT / "README.md", stage / "usr/share/doc/perfektblue/README.md")
    gzip_text(
        debian_changelog(app_version, args.revision, epoch),
        stage / "usr/share/doc/perfektblue/changelog.Debian.gz",
    )
    copy_file(ROOT / "LICENSE", stage / "usr/share/doc/perfektblue/copyright")
    generate_md5sums(stage)
    normalize_metadata(stage, epoch)

    destination = args.output_dir / f"perfektblue_{deb_version}_all.deb"
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = str(epoch)
    subprocess.run(
        ["dpkg-deb", "--root-owner-group", "--build", str(stage), str(destination)],
        check=True,
        env=environment,
    )
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
