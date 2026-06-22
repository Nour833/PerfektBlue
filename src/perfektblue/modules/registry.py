"""Built-in and third-party assessment module discovery."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from perfektblue.errors import ModuleError
from perfektblue.modules.base import AssessmentModule
from perfektblue.modules.builtin import (
    SecurityPostureModule,
    ServiceExposureModule,
    SimulatedCanaryModule,
)


class ModuleRegistry:
    def __init__(self, load_external: bool = True) -> None:
        self._modules: dict[str, AssessmentModule] = {}
        for module_type in (
            ServiceExposureModule,
            SecurityPostureModule,
            SimulatedCanaryModule,
        ):
            self.register(module_type())
        if load_external:
            self._load_external()

    def register(self, module: AssessmentModule) -> None:
        module_id = module.manifest.id
        if module_id in self._modules:
            existing = self._modules[module_id]
            if type(existing) is type(module):
                return
            raise ModuleError(f"duplicate module id: {module_id}")
        self._modules[module_id] = module

    def _load_external(self) -> None:
        try:
            candidates = entry_points(group="perfektblue.modules")
        except TypeError:
            candidates = entry_points().select(group="perfektblue.modules")
        for candidate in candidates:
            try:
                loaded: Any = candidate.load()
                module = loaded() if isinstance(loaded, type) else loaded
                if not isinstance(module, AssessmentModule):
                    raise TypeError("entry point did not return AssessmentModule")
                self.register(module)
            except Exception as exc:
                raise ModuleError(
                    f"cannot load module entry point {candidate.name}: {exc}"
                ) from exc

    def all(self) -> list[AssessmentModule]:
        return sorted(self._modules.values(), key=lambda item: item.manifest.id)

    def get(self, module_id: str) -> AssessmentModule | None:
        return self._modules.get(module_id)

    def validate(self) -> list[str]:
        errors: list[str] = []
        for module in self.all():
            manifest = module.manifest
            if not manifest.id or "." not in manifest.id:
                errors.append(f"{manifest.id or '<blank>'}: module id must be namespaced")
            if not manifest.version:
                errors.append(f"{manifest.id}: version is required")
            if not 0 <= manifest.minimum_profile_confidence <= 100:
                errors.append(f"{manifest.id}: minimum confidence must be 0-100")
        return errors
