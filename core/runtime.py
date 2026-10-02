"""Runtime and environment discovery.

This module is the reason the ``python/platform.py`` collision mattered: it
needs the standard library's :mod:`platform` module to report the OS and
interpreter. While the project shipped its own top-level ``platform`` module,
``import platform`` inside any process that had ``python/`` on ``sys.path``
resolved to the project's service class and ``platform.system()`` raised
AttributeError.

After the PART 01 rename the import below is unambiguous. The regression test
``tests/test_foundation_runtime.py`` pins that behaviour so the collision
cannot silently return.
"""

from __future__ import annotations

import os
import platform as stdlib_platform  # stdlib; see module docstring
import sys
from typing import Any, Final

from core import version
from core.constants import ENV_DEVELOPMENT, ENV_PRODUCTION, ENV_TEST, ENVIRONMENTS

ENV_VAR: Final[str] = "SECTOOLKIT_ENV"


def python_version() -> str:
    """Interpreter version as ``major.minor.patch``."""
    return stdlib_platform.python_version()


def python_version_tuple() -> tuple[int, int, int]:
    """Interpreter version as integers."""
    info = sys.version_info
    return (info.major, info.minor, info.micro)


def meets_minimum_python() -> bool:
    """True when the interpreter satisfies :data:`core.version.MIN_PYTHON`."""
    return python_version_tuple()[:2] >= version.MIN_PYTHON


def operating_system() -> str:
    """Host OS name, e.g. ``Linux``. Proves the stdlib module is reachable."""
    return stdlib_platform.system()


def machine() -> str:
    """Host architecture, e.g. ``x86_64``."""
    return stdlib_platform.machine()


def current_environment(default: str = ENV_DEVELOPMENT) -> str:
    """Deployment mode from ``SECTOOLKIT_ENV``.

    An unrecognised value falls back to the SAFEST interpretation rather than
    silently running as production: unknown input must never select
    production behaviour by accident. Recognised values are returned as-is.
    """
    raw = os.environ.get(ENV_VAR, "").strip().lower()
    if raw in ENVIRONMENTS:
        return raw
    return default if default in ENVIRONMENTS else ENV_DEVELOPMENT


def is_production() -> bool:
    return current_environment() == ENV_PRODUCTION


def is_test() -> bool:
    return current_environment() == ENV_TEST


def runtime_info() -> dict[str, Any]:
    """Non-sensitive runtime facts.

    Deliberately excluded: hostname, username, full interpreter path,
    environment variables and working directory. Those identify the host or
    leak deployment layout and have no place in a health or metadata
    response.
    """
    return {
        "python_version": python_version(),
        "python_supported": meets_minimum_python(),
        "os": operating_system(),
        "machine": machine(),
        "environment": current_environment(),
        "app_version": version.VERSION,
    }


def stdlib_platform_module() -> Any:
    """Return the standard-library ``platform`` module.

    Exposed so tests can assert which module the name resolves to without
    re-importing it themselves.
    """
    return stdlib_platform


__all__ = [
    "ENV_VAR",
    "python_version",
    "python_version_tuple",
    "meets_minimum_python",
    "operating_system",
    "machine",
    "current_environment",
    "is_production",
    "is_test",
    "runtime_info",
    "stdlib_platform_module",
    "ENV_DEVELOPMENT",
    "ENV_TEST",
    "ENV_PRODUCTION",
]
