"""Health endpoints for ``/api/v1``.

Three distinct endpoints because orchestrators need distinct answers:

* ``/livez``  -> process alive. Never fails on a dependency outage.
* ``/readyz`` -> safe to route traffic. Fails closed.
* ``/healthz``-> operator detail. Still contains no credentials.

Status codes follow probe conventions: 200 ready, 503 not ready.
"""

from __future__ import annotations

from typing import Any

from core.constants import HEALTH_HEALTHY
from services.health_service import HealthService

HTTP_OK = 200
HTTP_SERVICE_UNAVAILABLE = 503


def livez(service: HealthService) -> tuple[int, dict[str, Any]]:
    """Liveness probe. Always 200 while the process can execute code."""
    return HTTP_OK, service.liveness()


def readyz(service: HealthService) -> tuple[int, dict[str, Any]]:
    """Readiness probe. 503 when a required dependency is not healthy."""
    body = service.readiness()
    code = HTTP_OK if body.get("ready") else HTTP_SERVICE_UNAVAILABLE
    return code, body


def healthz(service: HealthService) -> tuple[int, dict[str, Any]]:
    """Detailed operator health report."""
    body = service.full_report()
    code = HTTP_OK if body.get("ready") else HTTP_SERVICE_UNAVAILABLE
    return code, body


def is_serving(service: HealthService) -> bool:
    """Convenience predicate used by the CLI."""
    return service.readiness().get("status") in (HEALTH_HEALTHY, "degraded")


ROUTES: dict[str, str] = {
    "/api/v1/livez": "livez",
    "/api/v1/readyz": "readyz",
    "/api/v1/healthz": "healthz",
}

__all__ = ["livez", "readyz", "healthz", "is_serving", "ROUTES",
           "HTTP_OK", "HTTP_SERVICE_UNAVAILABLE"]
