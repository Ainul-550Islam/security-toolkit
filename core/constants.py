"""Shared non-secret constants for the foundation layer.

Nothing in this module is a credential, a hostname or an environment-specific
value. Anything that differs per deployment belongs in ``config/settings.py``
and is read from the environment.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Deployment modes
# ---------------------------------------------------------------------------
ENV_DEVELOPMENT: Final[str] = "development"
ENV_TEST: Final[str] = "test"
ENV_PRODUCTION: Final[str] = "production"
ENVIRONMENTS: Final[tuple[str, ...]] = (ENV_DEVELOPMENT, ENV_TEST, ENV_PRODUCTION)

# ---------------------------------------------------------------------------
# Language layers (see docs/LANGUAGE_BOUNDARIES.md)
# ---------------------------------------------------------------------------
LANG_PYTHON: Final[str] = "python"
LANG_RUST: Final[str] = "rust"
LANG_CPP: Final[str] = "cpp"
LANG_TYPESCRIPT: Final[str] = "typescript"
LANGUAGES: Final[tuple[str, ...]] = (LANG_PYTHON, LANG_RUST, LANG_CPP, LANG_TYPESCRIPT)

# ---------------------------------------------------------------------------
# Health vocabulary (closed set; mirrored in schemas/health.schema.json,
# native/rust/.../health.rs and native/cpp/.../engine.hpp)
# ---------------------------------------------------------------------------
HEALTH_HEALTHY: Final[str] = "healthy"
HEALTH_DEGRADED: Final[str] = "degraded"
HEALTH_UNAVAILABLE: Final[str] = "unavailable"
HEALTH_UNKNOWN: Final[str] = "unknown"
HEALTH_STATES: Final[tuple[str, ...]] = (
    HEALTH_HEALTHY,
    HEALTH_DEGRADED,
    HEALTH_UNAVAILABLE,
    HEALTH_UNKNOWN,
)

# Ordering used to fold component states into an overall verdict. A parent is
# never healthier than its unhealthiest required dependency.
HEALTH_SEVERITY_ORDER: Final[dict[str, int]] = {
    HEALTH_HEALTHY: 0,
    HEALTH_UNKNOWN: 1,
    HEALTH_DEGRADED: 2,
    HEALTH_UNAVAILABLE: 3,
}

# ---------------------------------------------------------------------------
# Engine execution modes
# ---------------------------------------------------------------------------
MODE_IN_PROCESS: Final[str] = "in_process"
MODE_SUBPROCESS: Final[str] = "subprocess"
MODE_FFI: Final[str] = "ffi"
MODE_REMOTE: Final[str] = "remote"
EXECUTION_MODES: Final[tuple[str, ...]] = (
    MODE_IN_PROCESS,
    MODE_SUBPROCESS,
    MODE_FFI,
    MODE_REMOTE,
)

# ---------------------------------------------------------------------------
# Severity vocabulary for canonical cross-language events
# ---------------------------------------------------------------------------
SEVERITIES: Final[tuple[str, ...]] = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)

# ---------------------------------------------------------------------------
# Bounds. Every externally influenced value is bounded so a hostile or
# malfunctioning producer cannot exhaust memory or disk.
# ---------------------------------------------------------------------------
MAX_EVENT_BYTES: Final[int] = 256 * 1024
MAX_METADATA_KEYS: Final[int] = 64
MAX_METADATA_VALUE_LEN: Final[int] = 4096
MAX_NAME_LEN: Final[int] = 200
MAX_LOG_VALUE_LEN: Final[int] = 2048

# Redaction placeholder used by config/logging.py.
REDACTED: Final[str] = "[REDACTED]"

__all__ = [
    "ENV_DEVELOPMENT",
    "ENV_TEST",
    "ENV_PRODUCTION",
    "ENVIRONMENTS",
    "LANG_PYTHON",
    "LANG_RUST",
    "LANG_CPP",
    "LANG_TYPESCRIPT",
    "LANGUAGES",
    "HEALTH_HEALTHY",
    "HEALTH_DEGRADED",
    "HEALTH_UNAVAILABLE",
    "HEALTH_UNKNOWN",
    "HEALTH_STATES",
    "HEALTH_SEVERITY_ORDER",
    "MODE_IN_PROCESS",
    "MODE_SUBPROCESS",
    "MODE_FFI",
    "MODE_REMOTE",
    "EXECUTION_MODES",
    "SEVERITIES",
    "MAX_EVENT_BYTES",
    "MAX_METADATA_KEYS",
    "MAX_METADATA_VALUE_LEN",
    "MAX_NAME_LEN",
    "MAX_LOG_VALUE_LEN",
    "REDACTED",
]
