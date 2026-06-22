from __future__ import annotations

import sys
import unittest
from pathlib import Path

PLUGIN_SOURCE = Path(__file__).resolve().parents[1] / "plugins" / "perfektblue-can" / "src"
sys.path.insert(0, str(PLUGIN_SOURCE))

from perfektblue_can.analysis import analyze, parse_candump  # noqa: E402


class CanPluginTests(unittest.TestCase):
    def test_passive_capture_analysis(self) -> None:
        frames = parse_candump(
            [
                "(1.000000) vcan0 123#0102",
                "(1.100000) vcan0 123#0103",
                "(1.200000) vcan0 456#FF",
            ]
        )
        stats = analyze(frames)
        first = next(item for item in stats if item.arbitration_id == "0x123")
        self.assertEqual(first.frame_count, 2)
        self.assertEqual(first.changing_bytes, [1])
