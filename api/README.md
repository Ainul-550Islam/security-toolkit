# api/

Versioned, transport-agnostic API handlers.

## Design

Handlers are plain functions returning `(status_code, body_dict)`:

```python
from api.v1 import health
code, body = health.readyz(health_service)
```

They import no web framework. That keeps them testable without a server, and
mountable on the existing dashboard, a future ASGI app, or a CLI command
without rewriting any logic.

## Versioning

`api/v1` is the stable surface. Additive changes (a new endpoint, a new
optional response field) stay in `v1`. Removing or renaming a field, or
changing a type, requires `api/v2`; both are served during the migration
window.

## Endpoints

| Route | Handler | Purpose |
|---|---|---|
| `/api/v1/livez` | `health.livez` | Liveness. Never consults dependencies. |
| `/api/v1/readyz` | `health.readyz` | Readiness. 503 when a required dependency is unhealthy. |
| `/api/v1/healthz` | `health.healthz` | Operator detail. |
| `/api/v1/metadata` | `metadata.metadata` | Service, versions, capabilities, flags. |
| `/api/v1/version` | `metadata.version_endpoint` | Version only; needs no service instance. |
| `/api/v1/capabilities` | `metadata.capabilities` | Available vs declared-unavailable engines. |
| `/api/v1/features` | `metadata.features` | Resolved feature-flag state. |

## Disclosure rules

Responses contain **no** credentials, connection strings, hostnames,
filesystem paths, environment variables or raw exception text. Dependency
failures are reported by category only. `metadata.FORBIDDEN_KEYS` lists the
field names that must never appear, and `tests/test_engine_registry.py`
asserts it.

Authentication is **not** implemented here. `allow_anonymous_health` is
enabled by default because the health payload is non-sensitive by
construction; every other endpoint must be protected by the mounting
application.
