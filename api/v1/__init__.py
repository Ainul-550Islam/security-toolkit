"""API version 1 package and deterministic route registration entrypoint.

Endpoint modules remain framework-neutral; the top-level ``api.router`` owns
HTTP route matching and middleware integration. The lazy factory avoids a
circular import while keeping a stable public package import.
"""

from __future__ import annotations

from typing import Any

from core.version import API_VERSION
from api.v1 import (
    admin,
    analytics,
    assets,
    assets_discovery,
    audit,
    evidence,
    findings,
    health,
    integrations,
    metadata,
    metrics,
    notifications,
    organizations,
    projects,
    remediation,
    reports,
    risk,
    roles,
    scans,
    search,
    sessions,
    tenants,
    users,
)


def create_v1_router(services: Any) -> Any:
    """Create the registered version-1 router around existing service objects."""
    from api.router import create_router

    return create_router(services)


__all__ = [
    "API_VERSION",
    "create_v1_router",
    "admin",
    "analytics",
    "assets",
    "assets_discovery",
    "audit",
    "evidence",
    "findings",
    "health",
    "integrations",
    "metadata",
    "metrics",
    "notifications",
    "organizations",
    "projects",
    "remediation",
    "reports",
    "risk",
    "roles",
    "scans",
    "search",
    "sessions",
    "tenants",
    "users",
]
