"""PerfektBlue public package."""

from importlib.metadata import PackageNotFoundError, version

from perfektblue.models import (
    AssessmentPlan,
    Device,
    Evidence,
    Finding,
    InjectionVerdict,
    TargetProfile,
)

__all__ = [
    "AssessmentPlan",
    "Device",
    "Evidence",
    "Finding",
    "InjectionVerdict",
    "TargetProfile",
]

try:
    __version__ = version("perfektblue")
except PackageNotFoundError:
    __version__ = "0+unknown"
