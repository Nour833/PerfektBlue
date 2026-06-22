from __future__ import annotations

import unittest

from perfektblue.bluetooth.simulated import SimulatedBackend
from perfektblue.profiles import ProfileRegistry


class ProfileTests(unittest.IsolatedAsyncioTestCase):
    async def test_vulnerable_simulator_matches_exact_profile(self) -> None:
        device = await SimulatedBackend("vulnerable").inspect("02:00:00:00:20:01")
        matches = ProfileRegistry().match(device)
        self.assertEqual(matches[0].profile_id, "perfektblue.lab-head-unit.v1")
        self.assertEqual(matches[0].confidence, 100.0)

    async def test_unknown_target_has_no_confident_match(self) -> None:
        device = await SimulatedBackend("unknown").inspect("02:00:00:00:10:FF")
        matches = ProfileRegistry().match(device)
        self.assertTrue(all(item.confidence == 0 for item in matches))

    def test_bundled_profiles_validate(self) -> None:
        self.assertEqual(ProfileRegistry().validate(), [])
