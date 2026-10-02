"""Foundation core: version, errors, results, ids, clock, paths, runtime.

Importing this package must stay side-effect free: no I/O, no environment
reads, no logging configuration. Submodules are imported explicitly by
callers so that a lightweight consumer (for example the health endpoint) does
not pay for the whole package.
"""

from __future__ import annotations

from core.version import API_VERSION, APP_NAME, SCHEMA_VERSION, VERSION

__all__ = ["APP_NAME", "VERSION", "SCHEMA_VERSION", "API_VERSION"]
