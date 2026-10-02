"""API version 1.

Handlers are plain functions returning ``(status_code, body)``. They depend
on no web framework, so they can be mounted on the existing dashboard server,
tested directly, or served by a future ASGI app without rewriting logic.
"""

from core.version import API_VERSION

__all__ = ["API_VERSION"]
