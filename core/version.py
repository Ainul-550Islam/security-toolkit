"""Central application and version metadata.

Single source of truth for the version reported by the CLI, the API metadata
endpoint, structured log records and native engine handshakes. Nothing here
reads the environment, touches the filesystem or performs I/O: importing this
module must always be safe and side-effect free.
"""

from __future__ import annotations

from typing import Final

APP_NAME: Final[str] = "security-toolkit"
APP_TITLE: Final[str] = "SecuToolkit"

# Semantic version of the Python application layer.
#
# PART 01 establishes the foundation layer; the existing security phases
# (1-13) shipped before this versioning scheme existed, so the foundation
# starts its own explicit series rather than retroactively claiming one.
VERSION_MAJOR: Final[int] = 0
VERSION_MINOR: Final[int] = 1
VERSION_PATCH: Final[int] = 0
VERSION: Final[str] = f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}"

# Contract version for cross-language payloads (schemas/, Rust, C++).
# Bump this ONLY when a schema change is not backwards compatible.
SCHEMA_VERSION: Final[str] = "1"

# API surface version. Mirrors the api/v1 package name.
API_VERSION: Final[str] = "v1"

# Minimum Python runtime the foundation layer is tested against.
MIN_PYTHON: Final[tuple[int, int]] = (3, 11)


def version_info() -> dict[str, str]:
    """Return non-sensitive version metadata.

    Safe to expose over the API and to embed in logs: contains no host
    details, no configuration values and no secrets.
    """
    return {
        "app": APP_NAME,
        "title": APP_TITLE,
        "version": VERSION,
        "schema_version": SCHEMA_VERSION,
        "api_version": API_VERSION,
    }
