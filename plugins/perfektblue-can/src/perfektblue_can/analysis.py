"""Passive CAN capture analysis."""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

CANDUMP_PATTERN = re.compile(
    r"^\s*(?:\((?P<timestamp>\d+(?:\.\d+)?)\)\s+)?"
    r"(?P<interface>[A-Za-z0-9_.:-]+)\s+"
    r"(?P<identifier>[0-9A-Fa-f]{3,8})#(?P<data>[0-9A-Fa-f]*)\s*$"
)


@dataclass(slots=True)
class CanFrame:
    timestamp: float | None
    interface: str
    arbitration_id: int
    data: bytes
    extended: bool


@dataclass(slots=True)
class IdentifierStats:
    arbitration_id: str
    frame_count: int
    payload_lengths: list[int]
    unique_payloads: int
    byte_entropy: list[float]
    changing_bytes: list[int]


def parse_candump(lines: Iterable[str]) -> list[CanFrame]:
    frames: list[CanFrame] = []
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        match = CANDUMP_PATTERN.match(stripped)
        if not match:
            raise ValueError(f"invalid candump line {line_number}: {stripped}")
        identifier_text = match.group("identifier")
        data_text = match.group("data")
        frames.append(
            CanFrame(
                timestamp=(float(match.group("timestamp")) if match.group("timestamp") else None),
                interface=match.group("interface"),
                arbitration_id=int(identifier_text, 16),
                data=bytes.fromhex(data_text),
                extended=len(identifier_text) > 3,
            )
        )
    return frames


def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return round(
        -sum((count / total) * math.log2(count / total) for count in counts.values()),
        4,
    )


def analyze(frames: list[CanFrame]) -> list[IdentifierStats]:
    grouped: dict[int, list[CanFrame]] = defaultdict(list)
    for frame in frames:
        grouped[frame.arbitration_id].append(frame)
    results: list[IdentifierStats] = []
    for arbitration_id, items in sorted(grouped.items()):
        max_length = max((len(item.data) for item in items), default=0)
        columns = [
            [item.data[index] for item in items if index < len(item.data)]
            for index in range(max_length)
        ]
        results.append(
            IdentifierStats(
                arbitration_id=f"0x{arbitration_id:X}",
                frame_count=len(items),
                payload_lengths=sorted({len(item.data) for item in items}),
                unique_payloads=len({item.data for item in items}),
                byte_entropy=[_entropy(column) for column in columns],
                changing_bytes=[
                    index for index, column in enumerate(columns) if len(set(column)) > 1
                ],
            )
        )
    return results


def analyze_file(path: Path) -> dict[str, object]:
    frames = parse_candump(path.read_text(encoding="utf-8").splitlines())
    return {
        "source": str(path),
        "frame_count": len(frames),
        "identifiers": [asdict(item) for item in analyze(frames)],
    }
