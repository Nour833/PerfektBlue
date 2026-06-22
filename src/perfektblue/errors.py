"""Typed errors used across PerfektBlue."""


class PerfektBlueError(Exception):
    """Base application error."""


class ConfigurationError(PerfektBlueError):
    """Configuration is invalid."""


class BackendUnavailableError(PerfektBlueError):
    """A requested transport backend is unavailable."""


class DiscoveryError(PerfektBlueError):
    """Bluetooth discovery failed."""


class ProfileError(PerfektBlueError):
    """A target profile is invalid."""


class ModuleError(PerfektBlueError):
    """An assessment module failed."""


class SafetyPolicyError(PerfektBlueError):
    """An operation was denied by the safety policy."""


class SessionError(PerfektBlueError):
    """Session persistence failed."""
