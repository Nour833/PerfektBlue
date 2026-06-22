from __future__ import annotations

import unittest

from perfektblue.modules import ModuleRegistry


class ModuleTests(unittest.TestCase):
    def test_bundled_modules_validate(self) -> None:
        registry = ModuleRegistry(load_external=False)
        self.assertEqual(registry.validate(), [])
        self.assertIsNotNone(registry.get("bluetooth.service-exposure"))
        self.assertIsNotNone(registry.get("lab.simulated-canary"))
