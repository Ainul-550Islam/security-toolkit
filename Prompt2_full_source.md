# Prompt 2 — complete changed file contents

Complete source copied from the final workspace files. No sections are omitted.

## `api/router.py`

```python
"""Deterministic, strict route registry for the versioned HTTP API."""

from __future__ import annotations

import importlib
import re
import sys
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from api.errors import ApiProblem
from api.middleware import HttpRequest, HttpResponse
from core.paths import REPO_ROOT
from core.version import API_VERSION
from services.capability_service import CapabilityService
from services.engine_registry import EngineRegistry
from services.health_service import HealthService

_HANDLER = Callable[[HttpRequest, dict[str, str]], HttpResponse]
_METHOD_RE = re.compile(r"^[A-Z]{3,16}$")
_PARAM_RE = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")
_PARAM_VALUE_PATTERN = r"[A-Za-z0-9_.~-]{1,128}"
_PARAM_VALUE_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.~-"
)
_PATH_SEGMENT_PATTERN = r"(?:[A-Za-z0-9_.-]|\{[A-Za-z][A-Za-z0-9_]*\})+"
_PATH_RE = re.compile(rf"^/api/v1(?:/{_PATH_SEGMENT_PATTERN})*$")


def _effective_methods(methods: frozenset[str]) -> frozenset[str]:
    """Return methods accepted by a route, including implicit HEAD for GET."""
    return methods.union({"HEAD"}) if "GET" in methods else methods


@dataclass(frozen=True, slots=True)
class _SegmentNfa:
    """Small NFA for intersecting bounded route-parameter templates."""

    transitions: tuple[tuple[tuple[frozenset[str], int], ...], ...]
    epsilon: tuple[tuple[int, ...], ...]
    accept: int


@lru_cache(maxsize=512)
def _segment_template_pattern(template: str) -> re.Pattern[str]:
    """Compile one already-validated path segment for static intersection."""
    expression: list[str] = []
    previous = 0
    for match in _PARAM_RE.finditer(template):
        expression.append(re.escape(template[previous:match.start()]))
        expression.append(_PARAM_VALUE_PATTERN)
        previous = match.end()
    expression.append(re.escape(template[previous:]))
    return re.compile("".join(expression))


@lru_cache(maxsize=512)
def _segment_nfa(template: str) -> _SegmentNfa:
    """Build a bounded character automaton for one valid path segment."""
    transitions: list[list[tuple[frozenset[str], int]]] = [[]]
    epsilon: list[list[int]] = [[]]

    def add_state() -> int:
        transitions.append([])
        epsilon.append([])
        return len(transitions) - 1

    current = 0
    previous = 0
    for match in _PARAM_RE.finditer(template):
        for character in template[previous:match.start()]:
            target = add_state()
            transitions[current].append((frozenset({character}), target))
            current = target

        accepted_states: list[int] = []
        parameter_state = current
        for _ in range(128):
            target = add_state()
            transitions[parameter_state].append((_PARAM_VALUE_CHARACTERS, target))
            accepted_states.append(target)
            parameter_state = target

        continuation = add_state()
        for accepted_state in accepted_states:
            epsilon[accepted_state].append(continuation)
        current = continuation
        previous = match.end()

    for character in template[previous:]:
        target = add_state()
        transitions[current].append((frozenset({character}), target))
        current = target

    return _SegmentNfa(
        transitions=tuple(tuple(edges) for edges in transitions),
        epsilon=tuple(tuple(edges) for edges in epsilon),
        accept=current,
    )


def _segment_nfas_overlap(first: _SegmentNfa, second: _SegmentNfa) -> bool:
    """Return whether two segment NFAs accept any common string."""
    pending: deque[tuple[int, int]] = deque([(0, 0)])
    visited = {(0, 0)}
    while pending:
        first_state, second_state = pending.popleft()
        if first_state == first.accept and second_state == second.accept:
            return True

        next_pairs = (
            *((target, second_state) for target in first.epsilon[first_state]),
            *((first_state, target) for target in second.epsilon[second_state]),
        )
        for pair in next_pairs:
            if pair not in visited:
                visited.add(pair)
                pending.append(pair)

        for first_characters, first_target in first.transitions[first_state]:
            for second_characters, second_target in second.transitions[second_state]:
                if first_characters.isdisjoint(second_characters):
                    continue
                pair = (first_target, second_target)
                if pair not in visited:
                    visited.add(pair)
                    pending.append(pair)
    return False


def _segment_templates_overlap(first: str, second: str) -> bool:
    """Return whether two validated segment templates accept a common value."""
    if first == second:
        return True
    first_has_parameters = _PARAM_RE.search(first) is not None
    second_has_parameters = _PARAM_RE.search(second) is not None
    if not first_has_parameters and not second_has_parameters:
        return False
    if not first_has_parameters:
        return _segment_template_pattern(second).fullmatch(first) is not None
    if not second_has_parameters:
        return _segment_template_pattern(first).fullmatch(second) is not None
    if _PARAM_RE.sub("{}", first) == _PARAM_RE.sub("{}", second):
        return True
    return _segment_nfas_overlap(_segment_nfa(first), _segment_nfa(second))


def _path_templates_overlap(first: str, second: str) -> bool:
    """Return whether two validated route templates can match one path."""
    first_segments = first.split("/")[1:]
    second_segments = second.split("/")[1:]
    if len(first_segments) != len(second_segments):
        return False
    return all(
        _segment_templates_overlap(first_segment, second_segment)
        for first_segment, second_segment in zip(first_segments, second_segments, strict=True)
    )


@dataclass(slots=True)
class ApiServices:
    """Existing domain services injected into API adapters, never duplicated."""

    platform: Any
    identity: Any
    authorization: Any
    health: HealthService
    capabilities: CapabilityService
    jobs: Any = None
    reports: Any = None
    analytics: Any = None
    integrations: Any = None
    notifications: Any = None
    ticketing: Any = None
    clouds: Any = None
    audit: Any = None
    admin: Any = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True, slots=True)
class RouteSpec:
    """One concrete API operation with its authorization and OpenAPI metadata."""

    path: str
    methods: frozenset[str]
    handler: _HANDLER
    operation_id: str
    summary: str
    tags: tuple[str, ...] = ()
    auth_required: bool = True
    security_scheme: str = ""
    permission: str = ""
    scope_kind: str = ""
    scope_parameter: str = ""
    request_schema: dict[str, Any] | None = None
    response_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object"})
    responses: dict[str, str] = field(default_factory=dict)
    _pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)
    _parameter_names: tuple[str, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, str)
            or len(self.path) > 2048
            or not _PATH_RE.fullmatch(self.path)
            or any(segment in {".", ".."} for segment in self.path.split("/"))
        ):
            raise ValueError("route path is not a strict /api/v1 path")
        if not callable(self.handler):
            raise ValueError("route handler must be callable")
        methods = frozenset(str(method).upper() for method in self.methods)
        if not methods or any(not _METHOD_RE.fullmatch(method) for method in methods):
            raise ValueError("route methods must be valid uppercase HTTP methods")
        if not self.operation_id or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,96}", self.operation_id):
            raise ValueError("operation_id is invalid")
        if self.scope_kind not in {"", "organization", "project"}:
            raise ValueError("scope_kind is invalid")
        if self.security_scheme and not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]{1,63}", self.security_scheme
        ):
            raise ValueError("security_scheme is invalid")
        if bool(self.scope_kind) != bool(self.scope_parameter):
            raise ValueError("scope kind and parameter must be specified together")
        names = tuple(_PARAM_RE.findall(self.path))
        if len(names) != len(set(names)):
            raise ValueError("route parameter names must be unique")
        expression: list[str] = []
        previous = 0
        for match in _PARAM_RE.finditer(self.path):
            expression.append(re.escape(self.path[previous:match.start()]))
            expression.append(f"(?P<{match.group(1)}>{_PARAM_VALUE_PATTERN})")
            previous = match.end()
        expression.append(re.escape(self.path[previous:]))
        object.__setattr__(self, "methods", methods)
        object.__setattr__(self, "_pattern", re.compile("^" + "".join(expression) + "$"))
        object.__setattr__(self, "_parameter_names", names)

    @property
    def api_version(self) -> str:
        """Return the single API version accepted by this router."""
        return str(API_VERSION)

    @property
    def parameter_names(self) -> tuple[str, ...]:
        """Expose template parameter names for middleware and documentation."""
        return self._parameter_names


@dataclass(frozen=True, slots=True)
class RouteMatch:
    route: RouteSpec
    path_params: dict[str, str]


class ApiRouter:
    """Route registry whose matching is exact and never prefix-based."""

    def __init__(self, services: ApiServices) -> None:
        self.services = services
        self._routes: list[RouteSpec] = []
        self._route_shapes: dict[str, frozenset[str]] = {}
        self._operations: set[str] = set()

    @property
    def routes(self) -> tuple[RouteSpec, ...]:
        return tuple(self._routes)

    def register(self, route: RouteSpec) -> None:
        """Register a unique route and operation in deterministic order."""
        shape = _PARAM_RE.sub("{}", route.path)
        effective_methods = _effective_methods(route.methods)
        existing_methods = self._route_shapes.get(shape, frozenset())
        if existing_methods.intersection(effective_methods):
            raise ValueError("route path and method are already registered")
        if route.operation_id in self._operations:
            raise ValueError("operation_id is already registered")
        if route.scope_parameter and route.scope_parameter not in route.parameter_names:
            raise ValueError("scope parameter is not present in the route path")
        for existing_route in self._routes:
            if _effective_methods(existing_route.methods).isdisjoint(effective_methods):
                continue
            if _path_templates_overlap(existing_route.path, route.path):
                raise ValueError("route path patterns overlap for the same method")
        self._route_shapes[shape] = existing_methods.union(effective_methods)
        self._operations.add(route.operation_id)
        self._routes.append(route)
        self._routes.sort(key=lambda item: (-len(item.path.replace("{", "")), item.path, sorted(item.methods)))

    def resolve(self, method: str, path: str) -> RouteMatch | HttpResponse:
        """Resolve only an exact static path or a declared bounded path template."""
        normalized_method = str(method or "").upper()
        candidate = str(path or "")
        if (
            len(candidate) > 2048
            or not candidate.startswith("/api/v1")
            or "?" in candidate
            or "#" in candidate
            or "\\" in candidate
            or "%" in candidate
            or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate)
        ):
            return self._error(404, "not_found", "Resource not found")
        if candidate != "/api/v1" and not candidate.startswith("/api/v1/"):
            return self._error(404, "not_found", "Resource not found")
        if any(segment in {".", ".."} for segment in candidate.split("/")):
            return self._error(404, "not_found", "Resource not found")
        method_matches: list[tuple[RouteSpec, dict[str, str]]] = []
        path_matches: list[RouteSpec] = []
        for route in self._routes:
            match = route._pattern.fullmatch(candidate)
            if match is None:
                continue
            path_matches.append(route)
            if normalized_method in _effective_methods(route.methods):
                method_matches.append((route, match.groupdict()))
        if len(method_matches) == 1:
            route, params = method_matches[0]
            return RouteMatch(route, params)
        if len(method_matches) > 1:
            return self._error(500, "route_conflict", "The API route registry is invalid")
        if path_matches:
            allowed = sorted({
                method
                for route in path_matches
                for method in _effective_methods(route.methods)
            })
            response = self._error(405, "method_not_allowed", "The method is not allowed")
            response.add_header("Allow", ", ".join(allowed))
            return response
        return self._error(404, "not_found", "Resource not found")

    @staticmethod
    def _error(status: int, code: str, message: str) -> HttpResponse:
        problem = ApiProblem(status, code, message)
        return HttpResponse(status, problem.body(""))

    def dispatch(self, request: HttpRequest, match: RouteMatch) -> HttpResponse:
        """Execute the selected handler; authorization is enforced by middleware."""
        return match.route.handler(request, match.path_params)


def _require_object_body(request: HttpRequest) -> dict[str, Any]:
    if not isinstance(request.body, dict):
        from api.errors import ApiException, validation_problem
        raise ApiException(validation_problem(
            field="request", code="invalid_type", message="A JSON object is required"
        ))
    return request.body


def _login_handler(auth_adapter: Any) -> _HANDLER:
    def handler(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        from api.errors import ApiException, validation_problem

        body = _require_object_body(request)
        if set(body) - {"identifier", "password"}:
            raise ApiException(validation_problem(
                field="request", code="unknown_field", message="Unexpected field"
            ))
        identifier = body.get("identifier")
        password = body.get("password")
        if not isinstance(identifier, str) or not 1 <= len(identifier.strip()) <= 256:
            raise ApiException(validation_problem(
                field="identifier", code="invalid", message="A valid identifier is required"
            ))
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise ApiException(validation_problem(
                field="password", code="invalid", message="A valid password is required"
            ))
        grant = auth_adapter.login(
            identifier.strip(),
            password,
            source_ip=request.remote_addr,
            user_agent=request.header("user-agent")[:256],
        )
        return HttpResponse(200, {
            "access_token": grant.token,
            "token_type": grant.token_type,
            "expires_at": grant.expires_at,
            "mfa_required": grant.mfa_required,
            "mfa_status": grant.mfa_status,
            "principal": grant.principal.safe_dict(),
        })
    return handler


def _session_handler(services: ApiServices) -> _HANDLER:
    def handler(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        context = request.context
        if context is None or context.principal is None:
            from api.errors import ApiException, ApiProblem
            raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
        response: dict[str, Any] = {"principal": context.principal.safe_dict()}
        if context.authorization_context is not None:
            response["mfa_status"] = str(getattr(context.authorization_context, "mfa_status", "none"))
            response["step_up_until"] = str(getattr(context.authorization_context, "step_up_until", ""))
        return HttpResponse(200, {"data": response})
    return handler


def _logout_handler(auth_adapter: Any) -> _HANDLER:
    def handler(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        from api.errors import ApiException, ApiProblem

        context = request.context
        if context is None or context.principal is None:
            raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
        if context.principal.subject_type != "user" or not context.principal.session_id:
            raise ApiException(ApiProblem(403, "forbidden", "Only user sessions can be revoked by logout"))
        auth_adapter.logout(context.authorization_context)
        return HttpResponse(204, b"")
    return handler


def _refresh_handler(auth_adapter: Any) -> _HANDLER:
    def handler(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        if request.context is None or request.context.principal is None:
            return HttpResponse(401, {"error": {"code": "authentication_failed", "message": "Authentication required or invalid", "request_id": request.request_id}})
        grant = auth_adapter.refresh(request.header("authorization"))
        return HttpResponse(200, {
            "access_token": grant.token,
            "token_type": grant.token_type,
            "expires_at": grant.expires_at,
            "mfa_required": grant.mfa_required,
            "mfa_status": grant.mfa_status,
            "principal": grant.principal.safe_dict(),
        })
    return handler


def _register_core_routes(router: ApiRouter, auth_adapter: Any) -> None:
    """Register only health, metadata, and identity routes backed by real services."""
    from api.v1 import health, metadata

    services = router.services
    router.register(RouteSpec(
        path="/api/v1/livez", methods=frozenset({"GET"}),
        handler=lambda request, _params: HttpResponse(*health.livez(services.health)),
        operation_id="livez", summary="Process liveness probe", tags=("health",),
        auth_required=False, response_schema={"type": "object"},
        responses={"200": "Process is alive"},
    ))
    router.register(RouteSpec(
        path="/api/v1/readyz", methods=frozenset({"GET"}),
        handler=lambda request, _params: HttpResponse(*health.readyz(services.health)),
        operation_id="readyz", summary="Dependency-aware readiness probe", tags=("health",),
        auth_required=False, response_schema={"type": "object"},
        responses={"200": "Ready", "503": "A required dependency is unavailable"},
    ))
    router.register(RouteSpec(
        path="/api/v1/healthz", methods=frozenset({"GET"}),
        handler=lambda request, _params: HttpResponse(*health.healthz(services.health)),
        operation_id="healthz", summary="Safe operator health report", tags=("health",),
        auth_required=False, response_schema={"type": "object"},
        responses={"200": "Health report", "503": "A required dependency is unavailable"},
    ))
    router.register(RouteSpec(
        path="/api/v1/metadata", methods=frozenset({"GET"}),
        handler=lambda request, _params: HttpResponse(*metadata.metadata(services.capabilities)),
        operation_id="getMetadata", summary="Service metadata and supported capabilities",
        tags=("metadata",), permission="configuration.read",
        response_schema={"type": "object"}, responses={"200": "Service metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/version", methods=frozenset({"GET"}),
        handler=lambda request, _params: HttpResponse(*metadata.version_endpoint()),
        operation_id="getVersion", summary="Application and contract versions",
        tags=("metadata",), permission="configuration.read",
        response_schema={"type": "object"}, responses={"200": "Version metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/capabilities", methods=frozenset({"GET"}),
        handler=lambda request, _params: HttpResponse(*metadata.capabilities(services.capabilities)),
        operation_id="getCapabilities", summary="Available and unavailable engine capabilities",
        tags=("metadata",), permission="configuration.read",
        response_schema={"type": "object"}, responses={"200": "Capability metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/features", methods=frozenset({"GET"}),
        handler=lambda request, _params: HttpResponse(*metadata.features()),
        operation_id="getFeatures", summary="Resolved feature flag availability",
        tags=("metadata",), permission="configuration.read",
        response_schema={"type": "object"}, responses={"200": "Feature metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/auth/login", methods=frozenset({"POST"}),
        handler=_login_handler(auth_adapter),
        operation_id="login", summary="Establish a user session",
        tags=("authentication",), auth_required=False,
        request_schema={
            "type": "object", "required": ["identifier", "password"],
            "additionalProperties": False,
            "properties": {
                "identifier": {"type": "string", "minLength": 1, "maxLength": 256},
                "password": {"type": "string", "minLength": 1, "maxLength": 1024},
            },
        },
        response_schema={"type": "object", "required": ["access_token", "token_type", "expires_at"]},
        responses={"200": "Authenticated session", "401": "Credentials are invalid", "429": "Rate limited"},
    ))
    router.register(RouteSpec(
        path="/api/v1/auth/session", methods=frozenset({"GET"}),
        handler=_session_handler(services),
        operation_id="getSession", summary="Current safe principal and session state",
        tags=("authentication",), permission="identity.read",
        response_schema={"type": "object"}, responses={"200": "Current session"},
    ))
    router.register(RouteSpec(
        path="/api/v1/auth/refresh", methods=frozenset({"POST"}),
        handler=_refresh_handler(auth_adapter),
        operation_id="refreshSession", summary="Rotate the current session token",
        tags=("authentication",), permission="identity.read",
        response_schema={"type": "object"}, responses={"200": "Rotated session", "401": "Session is invalid"},
    ))
    router.register(RouteSpec(
        path="/api/v1/auth/logout", methods=frozenset({"POST"}),
        handler=_logout_handler(auth_adapter),
        operation_id="logout", summary="Revoke the current session",
        tags=("authentication",), permission="identity.read",
        response_schema={"type": "object"}, responses={"204": "Session revoked"},
    ))
    from api.openapi import OpenApiDocument

    def openapi_handler(_request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        return HttpResponse(200, OpenApiDocument(router).generate())

    router.register(RouteSpec(
        path="/api/v1/openapi.json", methods=frozenset({"GET"}),
        handler=openapi_handler, operation_id="getOpenApiDocument",
        summary="OpenAPI contract for implemented routes", tags=("metadata",),
        permission="configuration.read", response_schema={"type": "object"},
        responses={"200": "OpenAPI 3.1 document"},
    ))


def create_router(services: ApiServices) -> ApiRouter:
    """Build the version-1 route table using the existing service instances."""
    from api.auth import AuthenticationAdapter

    router = ApiRouter(services)
    auth_adapter = AuthenticationAdapter(services.authorization, services.identity)
    _register_core_routes(router, auth_adapter)
    from api.v1 import (
        admin,
        analytics,
        assets,
        audit,
        findings,
        integrations,
        metrics,
        reports,
        scans,
        tenants,
        users,
    )
    tenants.register(router)
    users.register(router)
    assets.register(router)
    findings.register(router)
    scans.register(router)
    reports.register(router)
    analytics.register(router)
    audit.register(router)
    integrations.register(router)
    metrics.register(router)
    admin.register(router)
    return router


def build_default_services(db_path: str | None = None) -> ApiServices:
    """Construct production adapters around the repository's existing engine."""
    python_directory = (REPO_ROOT / "python").resolve()
    if not python_directory.is_dir():
        raise RuntimeError("legacy domain modules are not available")
    python_entry = str(python_directory)
    if python_entry not in sys.path:
        sys.path.insert(0, python_entry)
    stdlib_platform = importlib.import_module("platform")
    platform_module_path = Path(str(getattr(stdlib_platform, "__file__", ""))).resolve()
    if python_directory == platform_module_path or python_directory in platform_module_path.parents:
        raise RuntimeError("legacy path shadowed the standard-library platform module")

    platform_module = importlib.import_module("platform_service")
    identity_module = importlib.import_module("identity")
    authz_module = importlib.import_module("authz")
    sec_config = importlib.import_module("sec_config")

    selected_db_path = str(db_path) if db_path else sec_config.platform_db_path()
    platform_service = platform_module.PlatformService(selected_db_path)
    identity_service = identity_module.IdentityService(platform_service)
    authorization_service = authz_module.AuthorizationService(platform_service, identity_service)

    registry = EngineRegistry()
    registry.register_declared_native()
    capability_service = CapabilityService(registry)
    health_service = HealthService(registry=registry)
    health_service.register_dependency(
        "database",
        lambda: bool(platform_service.db.query("SELECT 1 AS healthy", limit=1)),
        required=True,
        description="SQLite persistence",
    )

    # Public routes adapt the repository's canonical services; no second
    # scanning, report, analytics, cloud, or integration engines are made.
    scanner_module = importlib.import_module("scanners")
    jobs_module = importlib.import_module("jobs")
    analytics_module = importlib.import_module("analytics")
    reporting_module = importlib.import_module("reporting")
    cloud_module = importlib.import_module("cloud_security")
    integrations_module = importlib.import_module("integrations")
    scanner_registry = scanner_module.ScannerRegistry()
    job_service = jobs_module.JobService(platform_service, scanner_registry)
    analytics_service = analytics_module.AnalyticsService(platform_service)
    report_service = reporting_module.ReportService(platform_service)
    cloud_service = cloud_module.CloudSecurityService(platform_service)
    integration_service = integrations_module.EnterpriseIntegrationService(platform_service)
    from services.notifications import NotificationService as NotificationFacade
    from services.ticketing import TicketingService
    notification_service = NotificationFacade(platform_service)
    ticketing_service = TicketingService(platform_service)
    from api.idempotency import IdempotencyStore
    idempotency_store = IdempotencyStore(platform_service.db)

    return ApiServices(
        platform=platform_service,
        identity=identity_service,
        authorization=authorization_service,
        health=health_service,
        capabilities=capability_service,
        jobs=job_service,
        reports=report_service,
        analytics=analytics_service,
        integrations=integration_service,
        notifications=notification_service,
        ticketing=ticketing_service,
        clouds=cloud_service,
        extra={
            "scanner_registry": scanner_registry,
            "idempotency_store": idempotency_store,
        },
    )


__all__ = [
    "ApiRouter",
    "ApiServices",
    "RouteMatch",
    "RouteSpec",
    "build_default_services",
    "create_router",
]
```

## `tests/test_api_router.py`

```python
from __future__ import annotations

import os
import re
import sys
import unittest
from typing import Any, cast

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_DIR = os.path.join(ROOT, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from api.middleware import HttpResponse  # noqa: E402
from api.router import ApiRouter, ApiServices, RouteMatch, RouteSpec, create_router  # noqa: E402


def _services() -> ApiServices:
    return ApiServices(
        platform=object(),
        identity=object(),
        authorization=object(),
        health=object(),
        capabilities=object(),
    )


def _route(
    path: str,
    methods: tuple[str, ...] = ("GET",),
    *,
    operation_id: str = "getItem",
    scope_kind: str = "",
    scope_parameter: str = "",
) -> RouteSpec:
    return RouteSpec(
        path=path,
        methods=frozenset(methods),
        handler=lambda _request, _params: HttpResponse(200, {"ok": True}),
        operation_id=operation_id,
        summary=operation_id,
        scope_kind=scope_kind,
        scope_parameter=scope_parameter,
    )


class ApiRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = ApiRouter(_services())

    def test_route_parameter_matches_one_bounded_segment(self) -> None:
        self.router.register(_route("/api/v1/items/{item_id}"))

        result = self.router.resolve("get", "/api/v1/items/item_123-abc")

        self.assertIsInstance(result, RouteMatch)
        self.assertEqual(result.path_params, {"item_id": "item_123-abc"})
        self.assertEqual(result.route.parameter_names, ("item_id",))
        self.assertEqual(result.route.api_version, "v1")
        self.assertIsInstance(self.router.resolve("GET", "/api/v1/items/a/b"), HttpResponse)

    def test_dot_segments_are_not_captured_as_route_parameters(self) -> None:
        self.router.register(_route("/api/v1/{collection}/items/{item_id}"))

        for path in (
            "/api/v1/../items/item-1",
            "/api/v1/records/items/.",
            "/api/v1/records/items/..",
        ):
            with self.subTest(path=path):
                result = self.router.resolve("GET", path)
                self.assertIsInstance(result, HttpResponse)
                self.assertEqual(result.status, 404)
                self.assertEqual(result.body["error"]["code"], "not_found")

    def test_encoded_and_malformed_percent_paths_are_never_decoded(self) -> None:
        self.router.register(_route("/api/v1/items/{item_id}"))

        rejected_paths = (
            "/api/v1/items/%2f",
            "/api/v1/items/%2F",
            "/api/v1/items/%ZZ",
            "/api/v1/items/%",
            "/api/v1/items/%252e%252e",
            "/api/v1/items//item-1",
            "/api/v1/items/",
        )
        for path in rejected_paths:
            with self.subTest(path=path):
                result = self.router.resolve("GET", path)
                self.assertIsInstance(result, HttpResponse)
                self.assertEqual(result.status, 404)

    def test_malformed_route_parameter_expressions_are_rejected(self) -> None:
        invalid_paths = (
            "/api/v1/items/{bad-name}",
            "/api/v1/items/{item_id",
            "/api/v1/items/item_id}",
            "/api/v1/items/{}",
            "/api/v1/items//{item_id}",
            "/api/v1/items/{item_id}/",
        )

        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    _route(path)

    def test_valid_embedded_route_parameters_remain_supported(self) -> None:
        self.router.register(_route(
            "/api/v1/items/prefix-{item_id}.json",
            operation_id="getItemDocument",
        ))

        result = self.router.resolve("GET", "/api/v1/items/prefix-record_123.json")

        self.assertIsInstance(result, RouteMatch)
        self.assertEqual(result.path_params, {"item_id": "record_123"})

    def test_oversized_route_template_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _route("/api/v1/" + "a" * 2049)

    def test_non_callable_route_handler_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "handler must be callable"):
            RouteSpec(
                path="/api/v1/items",
                methods=frozenset({"GET"}),
                handler=cast(Any, None),
                operation_id="getItems",
                summary="Get items",
            )

    def test_static_dot_segments_are_rejected_at_registration(self) -> None:
        for path in ("/api/v1/items/.", "/api/v1/items/.."):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    _route(path)

    def test_same_method_static_and_parameter_route_shadowing_is_rejected(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}", operation_id="getItemById"
        ))

        with self.assertRaisesRegex(ValueError, "overlap"):
            self.router.register(_route(
                "/api/v1/items/featured", operation_id="getFeaturedItems"
            ))
        self.assertEqual(len(self.router.routes), 1)

    def test_overlapping_embedded_templates_are_rejected(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}.json", operation_id="getItemJson"
        ))

        with self.assertRaisesRegex(ValueError, "overlap"):
            self.router.register(_route(
                "/api/v1/items/archive.{extension}",
                operation_id="getArchivedItem",
            ))

    def test_disjoint_embedded_templates_with_same_method_are_allowed(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}.json", operation_id="getItemJson"
        ))
        self.router.register(_route(
            "/api/v1/items/{item_id}.xml", operation_id="getItemXml"
        ))

        json_result = self.router.resolve("GET", "/api/v1/items/record-1.json")
        xml_result = self.router.resolve("GET", "/api/v1/items/record-1.xml")

        self.assertIsInstance(json_result, RouteMatch)
        self.assertEqual(json_result.route.operation_id, "getItemJson")
        self.assertIsInstance(xml_result, RouteMatch)
        self.assertEqual(xml_result.route.operation_id, "getItemXml")

    def test_implicit_head_is_included_when_detecting_route_conflicts(self) -> None:
        self.router.register(_route("/api/v1/items/{item_id}", operation_id="getItem"))

        with self.assertRaises(ValueError):
            self.router.register(_route(
                "/api/v1/items/{item_id}",
                ("HEAD",),
                operation_id="headItem",
            ))

    def test_duplicate_route_shape_and_method_are_rejected_atomically(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}", operation_id="getItemById"
        ))

        with self.assertRaisesRegex(ValueError, "already registered"):
            self.router.register(_route(
                "/api/v1/items/{record_id}", operation_id="getRecordById"
            ))
        self.assertEqual(len(self.router.routes), 1)

        self.router.register(_route(
            "/api/v1/other", operation_id="getRecordById"
        ))
        self.assertEqual(len(self.router.routes), 2)

    def test_duplicate_operation_id_is_rejected(self) -> None:
        self.router.register(_route("/api/v1/items", operation_id="listItems"))

        with self.assertRaisesRegex(ValueError, "operation_id"):
            self.router.register(_route("/api/v1/records", operation_id="listItems"))
        self.assertEqual(len(self.router.routes), 1)

    def test_overlapping_paths_with_disjoint_methods_remain_supported(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}", operation_id="getItemById"
        ))
        self.router.register(_route(
            "/api/v1/items/featured", ("POST",), operation_id="createFeaturedItem"
        ))

        get_result = self.router.resolve("GET", "/api/v1/items/featured")
        post_result = self.router.resolve("POST", "/api/v1/items/featured")

        self.assertIsInstance(get_result, RouteMatch)
        self.assertEqual(get_result.route.operation_id, "getItemById")
        self.assertIsInstance(post_result, RouteMatch)
        self.assertEqual(post_result.route.operation_id, "createFeaturedItem")

    def test_405_allow_header_includes_implicit_head_and_all_declared_methods(self) -> None:
        self.router.register(_route("/api/v1/items", operation_id="getItems"))
        self.router.register(_route(
            "/api/v1/items", ("POST",), operation_id="createItems"
        ))

        result = self.router.resolve("DELETE", "/api/v1/items")

        self.assertIsInstance(result, HttpResponse)
        self.assertEqual(result.status, 405)
        self.assertEqual(result.body["error"]["code"], "method_not_allowed")
        self.assertEqual(dict(result.headers)["Allow"], "GET, HEAD, POST")

    def test_unknown_route_is_a_safe_404(self) -> None:
        self.router.register(_route("/api/v1/livez", operation_id="livez"))

        result = self.router.resolve("GET", "/api/v1/unknown")

        self.assertIsInstance(result, HttpResponse)
        self.assertEqual(result.status, 404)
        self.assertEqual(result.body["error"]["code"], "not_found")

    def test_unknown_version_prefix_is_a_safe_404(self) -> None:
        self.router.register(_route("/api/v1/livez", operation_id="livez"))

        result = self.router.resolve("GET", "/api/v10/livez")

        self.assertIsInstance(result, HttpResponse)
        self.assertEqual(result.status, 404)
        self.assertEqual(result.body["error"]["code"], "not_found")

    def test_scope_metadata_must_reference_a_declared_parameter(self) -> None:
        scoped_route = _route(
            "/api/v1/projects/{project_id}/assets",
            operation_id="listProjectAssets",
            scope_kind="project",
            scope_parameter="tenant_id",
        )

        with self.assertRaisesRegex(ValueError, "scope parameter"):
            self.router.register(scoped_route)
        self.assertEqual(self.router.routes, ())

    def test_registered_health_admin_and_tenant_scope_metadata_is_preserved(self) -> None:
        router = create_router(_services())
        second_router = create_router(_services())
        self.assertEqual(len(router.routes), 74)
        self.assertTrue(all(route.path.startswith("/api/v1/") for route in router.routes))
        self.assertTrue(all(route.api_version == "v1" for route in router.routes))
        self.assertTrue(all(callable(route.handler) for route in router.routes))
        for route in router.routes:
            sample_path = re.sub(r"\{[A-Za-z][A-Za-z0-9_]*\}", "route-param", route.path)
            methods = set(route.methods)
            if "GET" in route.methods:
                methods.add("HEAD")
            for method in sorted(methods):
                with self.subTest(path=route.path, method=method):
                    resolved = router.resolve(method, sample_path)
                    self.assertIsInstance(resolved, RouteMatch)
                    self.assertIs(resolved.route, route)
        self.assertEqual(
            len({route.operation_id for route in router.routes}),
            len(router.routes),
        )
        self.assertEqual(
            tuple((route.path, tuple(sorted(route.methods)), route.operation_id)
                  for route in router.routes),
            tuple((route.path, tuple(sorted(route.methods)), route.operation_id)
                  for route in second_router.routes),
        )

        public_health_paths = {
            "/api/v1/livez",
            "/api/v1/readyz",
            "/api/v1/healthz",
        }
        for path in public_health_paths:
            with self.subTest(path=path):
                route = next(
                    route for route in router.routes
                    if route.path == path and "GET" in route.methods
                )
                self.assertFalse(route.auth_required)
                self.assertFalse(route.security_scheme)
                self.assertFalse(route.scope_kind)

        metadata_route = next(
            route for route in router.routes if route.path == "/api/v1/metadata"
        )
        self.assertTrue(metadata_route.auth_required)
        self.assertEqual(metadata_route.permission, "configuration.read")

        admin_health = next(
            route for route in router.routes if route.path == "/api/v1/admin/health"
        )
        self.assertFalse(admin_health.auth_required)
        self.assertEqual(admin_health.security_scheme, "platformAdminKey")

        tenant_projects = [
            route for route in router.routes
            if route.path == "/api/v1/tenants/{tenant_id}/projects"
        ]
        project_assets = [
            route for route in router.routes
            if route.path == "/api/v1/projects/{project_id}/assets"
        ]
        self.assertEqual(len(tenant_projects), 2)
        self.assertEqual(len(project_assets), 2)
        for route in tenant_projects:
            self.assertEqual((route.scope_kind, route.scope_parameter), ("organization", "tenant_id"))
        for route in project_assets:
            self.assertEqual((route.scope_kind, route.scope_parameter), ("project", "project_id"))
        for route in router.routes:
            if route.scope_kind:
                self.assertIn("{" + route.scope_parameter + "}", route.path)


if __name__ == "__main__":
    unittest.main()
```

## `tests/run_tests.py`

```python
#!/usr/bin/env python3
# ============================================================================
#  SecuToolkit Test Suite — runs every module end-to-end (stdlib unittest)
#  Usage: python3 tests/run_tests.py
# ============================================================================

import json
import os
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "python")
sys.path.insert(0, PY)
sys.path.insert(0, HERE)

# Phase-1 foundation test suite (org/project/asset/scan/finding/evidence/
# scope/audit/persistence/normalization + security regressions) — runs as
# part of the SAME suite so total = existing + foundation.
from test_foundation import *  # noqa: F401,F403,E402

# Phase-2 security-control test suite (identity, RBAC, tenant isolation,
# API credentials, audit integrity, rate limiting, password reset, dashboard
# hardening, secret-leak regressions) — same-suite integration.
from test_security import *  # noqa: F401,F403,E402

# Phase-3 orchestration suite (job queue, atomic claiming, retry/stale,
# pause/resume/cancel, checkpoints, execution-time revalidation, subprocess
# safety, payload security, tenant isolation, CLI smoke) — same suite.
from test_orchestration import *  # noqa: F401,F403,E402

# Phase-4 intelligence suite (asset intelligence, canonical identity +
# fingerprint + cross-scanner dedup, lifecycle, confidence, risk + snapshots,
# correlation/root-cause/clusters/remediation, evidence graph, temporal
# scan diffs, security + idempotency regressions) — same suite.
from test_intelligence import *  # noqa: F401,F403,E402

# Phase-5/6/7 suites (monitoring, reporting, devsecops) + Phase-8 identity
# (MFA, step-up, OIDC/SAML SSO, SCIM, session hardening) — same suite.
from test_monitoring import *  # noqa: F401,F403,E402
from test_reporting import *  # noqa: F401,F403,E402
from test_devsecops import *  # noqa: F401,F403,E402
from test_identity import *  # noqa: F401,F403,E402

# Phase-9 enterprise-security suite (cloud / container / Kubernetes / IaC:
# provider + fixture determinism, exposure invariant, credential
# encryption-at-rest, CLOUD/CONT/K8S/IAC rules, digest identity, Secret
# metadata-only, secret redaction, explicit failure taxonomy, tenant
# isolation (BOLA), RBAC matrix, in-process job profiles, DevSecOps gate +
# SARIF interop, dashboard isolation, §44 concurrency, §49 failure
# injection, §50 deterministic scale) — same suite.
from test_cloud_security import *  # noqa: F401,F403,E402

# Phase-10 security-operations suite (IOC catalog + safe feed import,
# external attack surface + certificate intelligence, TI correlation
# -> findings, prioritization, threat clusters, investigation cases,
# event enrichment, tenant isolation + rate limits) — same suite.
from test_security_operations import *  # noqa: F401,F403,E402

# Phase-11 data-protection / privacy / secrets / compliance-governance
# suite (classification allowlist + downgrade guard, minimization +
# redaction, secret metadata registry, retention + holds, controlled
# deletion, privacy request workflow, secure exports, compliance evidence
# governance + policy exceptions, audit + tenant isolation, CLI/RBAC,
# dashboard panel, concurrency, deterministic scale) — same suite.
from test_data_governance import *  # noqa: F401,F403,E402

# Phase-12 enterprise data-federation / evidence-exchange / bulk-operations
# / external-integration-governance suite (peer trust lifecycle + SoD
# approval, exchange policies with the never-exportable sensitive classes,
# deterministic provider-neutral packages with canonical sha256 integrity,
# the 12-gate inbound validation chain, provenance-preserving imports
# through the existing finding/asset/evidence/case/IOC pipelines, idempotent
# re-import + collision strategies, bulk ops on the existing job engine,
# the redacted/bounded/audited integration boundary, RBAC where viewers and
# analysts get nothing, tenant isolation, audit-chain verification,
# dashboard/API panels, CLI smoke, failure injection, concurrency and
# bounded scale) — same suite.
from test_federation import *  # noqa: F401,F403,E402

# PART-01 enterprise-foundation suite. Every module below exercises the new
# root-level foundation packages (core/, config/, interfaces/, services/,
# api/, schemas/) that ship OUTSIDE python/ — they are import-only-sibling
# checks, fail-closed configuration checks, engine-registry/health checks,
# JSON-schema contract checks and the repo-wide security baseline. Each
# module inserts the repository ROOT on sys.path itself, so importing them
# here is enough to bring the foundation into this single suite:
#   test_foundation_runtime — injectable UTC clock, Result/Err, ids,
#                             path-safety (traversal/absolute/control-char/
#                             workspace escape), version_info, stdlib
#                             `platform` coexistence after the rename.
#   test_configuration      — fail-closed defaults, unset/empty/invalid
#                             distinction, production refusals, secret
#                             redaction in logs, feature-flag gating.
#   test_engine_registry    — Python/Rust/C++/unavailable/degraded modelling,
#                             capability reporting, health service liveness/
#                             readiness/dependency semantics, api.v1 handlers.
#   test_schemas            — event/finding/health JSON schemas: stability,
#                             required fields, UTC timestamps, trace ids,
#                             enum agreement with core.constants.
#   test_security_baseline  — repo-wide hygiene: no hard-coded secrets, no
#                             dangerous dynamic imports, no insecure default
#                             bindings, redaction coverage, dependency
#                             hygiene, and no offensive automation in the
#                             foundation layer.
from test_foundation_runtime import *  # noqa: F401,F403,E402
from test_configuration import *  # noqa: F401,F403,E402
from test_engine_registry import *  # noqa: F401,F403,E402
from test_schemas import *  # noqa: F401,F403,E402
from test_security_baseline import *  # noqa: F401,F403,E402
from test_api_http import *  # noqa: F401,F403,E402
from test_api_router import *  # noqa: F401,F403,E402
from test_identity_refresh import *  # noqa: F401,F403,E402
from test_api_idempotency import *  # noqa: F401,F403,E402
from test_api_resources import *  # noqa: F401,F403,E402
from test_product_integrations import *  # noqa: F401,F403,E402
from test_cloud_adapters import *  # noqa: F401,F403,E402
from test_crypto import *  # noqa: F401,F403,E402
from test_database_migrations import *  # noqa: F401,F403,E402

import password_audit
import phishing_detector
import log_analyzer
import template_engine
import spider
import sarif_export
import active_fuzzer
import waf_detect
import subdomain_enum
import cloud_check
import dashboard
import workflow


class TestPasswordAudit(unittest.TestCase):
    def test_weak_common(self):
        r = password_audit.analyze("password123")
        self.assertLess(r["score"], 40)
        self.assertIn("Very Weak", r["strength"])

    def test_strong_random(self):
        r = password_audit.analyze("Xk9#mQz!vR2$tLp7@Wq")
        self.assertGreaterEqual(r["score"], 90)
        self.assertIn("Excellent", r["strength"])

    def test_name_year_style(self):
        r = password_audit.analyze("Rahim2019")
        self.assertTrue(any("year" in f.lower() for f in r["findings"]))

    def test_breached_list_hit(self):
        r = password_audit.analyze("qwerty")
        self.assertTrue(any("breached" in f.lower() for f in r["findings"]))


class TestPhishing(unittest.TestCase):
    def test_obvious_phish(self):
        r = phishing_detector.analyze_url("https://paypa1-secure-verify.tk/login/update-account")
        self.assertGreaterEqual(r["phishing_score"], 55)

    def test_bkash_lookalike(self):
        r = phishing_detector.analyze_url("https://bkash-verify-account.xyz/otp")
        self.assertGreaterEqual(r["phishing_score"], 60)

    def test_safe_url(self):
        r = phishing_detector.analyze_url("https://www.google.com/search?q=django")
        self.assertLess(r["phishing_score"], 35)

    def test_at_trick(self):
        r = phishing_detector.analyze_url("https://www.google.com@evil-site.tk/login")
        self.assertGreaterEqual(r["phishing_score"], 50)
        self.assertTrue(any("@" in x for x in r["indicators"]))


class TestLogAnalyzer(unittest.TestCase):
    SAMPLE = [
        '103.94.153.21 - - [03/Sep/2026:10:15:22 +0000] "GET /index.php?id=1 UNION SELECT '
        'username,password FROM users HTTP/1.1" 200 1532 "-" "sqlmap/1.7"',
        '203.0.113.77 - - [03/Sep/2026:10:15:24 +0000] "POST /login HTTP/1.1" 401 512 "-" '
        '"Mozilla/5.0"',
        '198.51.100.9 - - [03/Sep/2026:10:17:01 +0000] "GET / HTTP/1.1" 200 9021 "-" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    ]

    def test_detects_sqlmap(self):
        r = log_analyzer.analyze(self.SAMPLE)
        self.assertIsNotNone(r)
        self.assertIn("SQLMap scanner", r["attack_classes"])

    def test_counts(self):
        r = log_analyzer.analyze(self.SAMPLE)
        self.assertEqual(r["total_requests"], 3)
        self.assertEqual(r["unique_ips"], 3)


class TestWebAudit(unittest.TestCase):
    """Runs the full web auditor against a local temp server."""

    def test_local_http_server(self):
        import http.server
        import socketserver
        import threading
        import io

        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<h1>test</h1>")
        with open(os.path.join(root, ".env"), "w") as f:
            f.write("SECRET=x")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            import subprocess
            out = tempfile.mktemp(suffix=".html")
            r = subprocess.run(
                [sys.executable, os.path.join(PY, "web_security_audit.py"),
                 "--url", f"http://127.0.0.1:{port}", "--out", out,
                 "--json", tempfile.mktemp(suffix=".json"), "--timeout", "3"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, encoding="utf-8") as fh:
                html = fh.read()
            self.assertIn("SECURITY AUDIT REPORT", html)
            self.assertIn("GRADE", html)
            httpd.shutdown()


class TestApiAudit(unittest.TestCase):
    def test_api_auditor_local(self):
        import http.server
        import socketserver
        import threading
        import subprocess
        import tempfile as tf

        root = tf.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write('{"status":"ok"}')

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            out = tf.mktemp(suffix=".json")
            r = subprocess.run(
                [sys.executable, os.path.join(PY, "api_security_audit.py"),
                 "--url", f"http://127.0.0.1:{port}", "--json", out,
                 "--timeout", "3"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("findings", data)
            self.assertIn("score", data)
            httpd.shutdown()


class TestPdfReport(unittest.TestCase):
    def test_pdf_generation(self):
        import subprocess
        data = {"tool": "SecuAudit", "target": "https://example.com",
                "scan_date": "2026-09-04T00:00:00", "score": 38.0, "grade": "E",
                "summary": {"High": 1, "Medium": 2},
                "findings": [
                    {"severity": "High", "title": "Test finding",
                     "evidence": "evidence line here", "remediation": "fix it"},
                ],
                "disclaimer": "authorized only"}
        jf = tempfile.mktemp(suffix=".json")
        pf = tempfile.mktemp(suffix=".pdf")
        with open(jf, "w") as f:
            json.dump(data, f)
        r = subprocess.run(
            [sys.executable, os.path.join(PY, "pdf_report.py"), "--json", jf,
             "--out", pf, "--title", "Test"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        data_bytes = open(pf, "rb").read()
        self.assertTrue(data_bytes.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", data_bytes)
        self.assertGreater(len(data_bytes), 1000)


class TestCveMiniDb(unittest.TestCase):
    def test_mini_db_lookup(self):
        import cve_lookup
        entries = cve_lookup.mini_db_lookup("nginx", "nginx")
        self.assertGreater(len(entries), 0)
        self.assertTrue(any(e["id"].startswith("CVE") for e in entries))
        entries2 = cve_lookup.mini_db_lookup("", "log4j")
        self.assertGreater(len(entries2), 0)
        self.assertGreater(entries2[0]["cvss"]["score"], 0)


class TestMainCli(unittest.TestCase):
    def test_main_help(self):
        import subprocess
        r = subprocess.run([sys.executable, os.path.join(ROOT, "main.py"), "--help"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        for sub in ("web", "api", "ports", "fuzz", "phishing", "cve", "logs",
                    "passwd", "report", "audit", "demo", "scan", "spider", "sarif",
                    "active", "waf", "subdomain", "cloud", "dashboard", "hunt",
                    "platform"):
            self.assertIn(sub, r.stdout)


class TestActiveFuzzer(unittest.TestCase):
    """Active fuzzing against a local 'vulnerable' app (fully controlled)."""

    def _serve(self, handler_cls):
        import http.server, socketserver, threading
        httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, port

    def test_sqli_error_detection(self):
        import http.server
        import urllib.parse

        class Vuln(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                val = q.get("id", [""])[0]
                if "'" in val or "OR" in val.upper() or "UNION" in val.upper():
                    body = b"You have an error in your SQL syntax; check the manual"
                    self.send_response(500)
                else:
                    body = b"OK"
                    self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._serve(Vuln)
        try:
            result = active_fuzzer.run(
                f"http://127.0.0.1:{port}/?id=1", "id", "sqli", 0.0, 10,
                None, {}, 5, True)
            types = [f["type"] for f in result["findings"]]
            self.assertTrue(any("SQL Injection" in t for t in types), types)
        finally:
            httpd.shutdown()

    def test_xss_reflection(self):
        import http.server, urllib.parse

        class Vuln(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                val = q.get("q", [""])[0]
                body = ("<html>" + val + "</html>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._serve(Vuln)
        try:
            result = active_fuzzer.run(
                f"http://127.0.0.1:{port}/?q=hello", "q", "xss", 0.0, 10,
                None, {}, 5, True)
            types = [f["type"] for f in result["findings"]]
            self.assertTrue(any("XSS" in t for t in types), types)
        finally:
            httpd.shutdown()

    def test_waf_block_flagged(self):
        import http.server

        class BlockSrv(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if "OR" in self.path or "'" in self.path:
                    self.send_response(403)
                    body = b"Request blocked by ModSecurity"
                else:
                    self.send_response(200)
                    body = b"OK"
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._serve(BlockSrv)
        try:
            result = waf_detect.detect(f"http://127.0.0.1:{port}/", 3)
            vendors = [w["vendor"] for w in result["waf"]]
            self.assertTrue(any("ModSecurity" in v for v in vendors), vendors)
        finally:
            httpd.shutdown()


class TestWafDetect(unittest.TestCase):
    def test_cloudflare_headers(self):
        import http.server

        class CF(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"OK"
                self.send_response(200)
                self.send_header("cf-ray", "7a1f2b3c4d5e6f78-SIN")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with socketserver.TCPServer(("127.0.0.1", 0), CF) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            result = waf_detect.detect(f"http://127.0.0.1:{port}/", 3)
            vendors = [w["vendor"] for w in result["waf"]]
            self.assertIn("Cloudflare", vendors)
            httpd.shutdown()


class TestCveTemplates(unittest.TestCase):
    def test_template_count(self):
        templates = template_engine.load_templates(os.path.join(ROOT, "templates"))
        self.assertGreaterEqual(len(templates), 25)

    def test_mini_db_kev(self):
        import cve_lookup
        for product, cve in (("react", "CVE-2025-55182"), ("citrix", "CVE-2025-5777")):
            entries = cve_lookup.mini_db_lookup("", product)
            self.assertTrue(any(e["id"] == cve for e in entries), f"{cve} missing")


class TestTemplateEngine(unittest.TestCase):
    def test_all_templates_parse(self):
        templates = template_engine.load_templates(os.path.join(ROOT, "templates"))
        self.assertGreaterEqual(len(templates), 14)
        for t in templates:
            self.assertIn("id", t)
            self.assertIn("requests", t)

    def test_version_compare(self):
        self.assertEqual(template_engine.ver_compare("1.13.2", "1.13.2"), 0)
        self.assertEqual(template_engine.ver_compare("1.13.3", "1.13.2"), 1)
        self.assertEqual(template_engine.ver_compare("1.12.1", "1.13.0"), -1)

    def test_mini_yaml(self):
        data = template_engine.parse_yaml(
            'id: test\ninfo:\n  name: "T: x"\n  severity: high\n'
            'requests:\n  - method: GET\n    path: "/x"\n'
            '    matchers:\n      - type: status\n        value: 200\n')
        self.assertEqual(data["id"], "test")
        self.assertEqual(data["info"]["name"], "T: x")
        self.assertEqual(data["requests"][0]["path"], "/x")
        self.assertEqual(data["requests"][0]["matchers"][0]["value"], 200)

    def test_git_template_matches_local_server(self):
        import http.server, socketserver, threading, tempfile
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        os.makedirs(os.path.join(root, ".git"), exist_ok=True)
        with open(os.path.join(root, ".git", "HEAD"), "w") as f:
            f.write("ref: refs/heads/main\n")
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<h1>x</h1>")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            tpl = template_engine.load_templates(os.path.join(ROOT, "templates", "misconfig"))
            findings = []
            for t in tpl:
                if t["id"] != "misconfig-git-exposure":
                    continue
                findings.extend(template_engine.run_template(
                    t, f"http://127.0.0.1:{port}", 5, {}))
            self.assertTrue(any(f["id"] == "misconfig-git-exposure" for f in findings))
            httpd.shutdown()

    def test_hsts_missing_template(self):
        import http.server, socketserver, threading, tempfile
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<h1>no headers here</h1>")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            tpls = template_engine.load_templates(os.path.join(ROOT, "templates", "headers"))
            hits = []
            for t in tpls:
                if t["id"] != "header-hsts-missing":
                    continue
                hits.extend(template_engine.run_template(t, f"http://127.0.0.1:{port}", 5, {}))
            self.assertTrue(any(f["id"] == "header-hsts-missing" for f in hits))
            httpd.shutdown()


class TestSpider(unittest.TestCase):
    def test_spider_discovers_links(self):
        import http.server, socketserver, threading, tempfile
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write('<a href="/about">About</a><a href="/api/users">Users</a>'
                    '<form action="/login" method="post"><input name="user"></form>')
        with open(os.path.join(root, "about.html"), "w") as f:
            f.write('<a href="/">home</a>')
        os.makedirs(os.path.join(root, "api"), exist_ok=True)
        with open(os.path.join(root, "api", "users"), "w") as f:
            f.write("[]")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            stats, endpoints, param_urls, api_candidates, pages = spider.crawl(
                f"http://127.0.0.1:{port}/", depth=2, limit=20, timeout=5)
            self.assertGreaterEqual(stats["pages_crawled"], 2)
            apis = [e["url"] for e in api_candidates]
            self.assertTrue(any("api" in u for u in apis))
            self.assertTrue(any(e.get("form") for e in endpoints))
            httpd.shutdown()


class TestSubdomainEnum(unittest.TestCase):
    def test_crt_parser(self):
        """Verify name extraction from the crt.sh JSON structure."""
        sample = [
            {"name_value": "*.example.com\nwww.example.com"},
            {"name_value": "api.example.com"},
        ]
        names = sorted({n for e in sample
                        for n in str(e["name_value"]).splitlines()
                        if n.strip() and "*" not in n and " " not in n})
        self.assertIn("www.example.com", names)
        self.assertIn("api.example.com", names)
        self.assertNotIn("*.example.com", names)

    def test_default_wordlist_has_core_entries(self):
        self.assertIn("www", subdomain_enum.DEFAULT_WORDS)
        self.assertIn("api", subdomain_enum.DEFAULT_WORDS)
        self.assertIn("admin", subdomain_enum.DEFAULT_WORDS)

    def test_domain_validation(self):
        bad = "not_a_domain"
        with self.assertRaises(SystemExit):
            subdomain_enum.enumerate(bad, False, [], 10, False)


class TestCloudScope(unittest.TestCase):
    def _http_server(self, handler_cls):
        import http.server
        httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, port

    def test_s3_public_listing(self):
        import http.server

        class S3(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = (b'<?xml version="1.0"?><ListBucketResult>'
                        b'<Name>demo</Name><Contents><Key>secret.zip</Key></Contents>'
                        b'</ListBucketResult>')
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._http_server(S3)
        try:
            r = cloud_check.probe_s3_url(f"http://127.0.0.1:{port}/")
            self.assertIn("PUBLIC LISTING", r["status"])
            self.assertEqual(r["severity"], "High")
        finally:
            httpd.shutdown()

    def test_s3_private_via_403(self):
        import http.server

        class S3(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"<Error><Code>AccessDenied</Code></Error>"
                self.send_response(403)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._http_server(S3)
        try:
            r = cloud_check.probe_s3_url(f"http://127.0.0.1:{port}/")
            self.assertIn("private", r["status"])
            self.assertEqual(r["severity"], "Info")
        finally:
            httpd.shutdown()

    def test_redis_noauth(self):
        import socketserver as ss

        class Redis(ss.StreamRequestHandler):
            def handle(self):
                data = self.rfile.readline()
                if data.strip().upper() == b"PING":
                    self.wfile.write(b"+PONG\r\n")
                else:
                    self.wfile.write(b"-ERR unknown\r\n")

        httpd = ss.TCPServer(("127.0.0.1", 0), Redis)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            r = cloud_check.check_redis("127.0.0.1", port)
            self.assertEqual(r["severity"], "Critical")
            self.assertIn("NO AUTH", r["status"])
        finally:
            httpd.shutdown()

    def test_redis_authrequired(self):
        import socketserver as ss

        class Redis(ss.StreamRequestHandler):
            def handle(self):
                data = self.rfile.readline()
                self.wfile.write(b"-NOAUTH Authentication required.\r\n")

        httpd = ss.TCPServer(("127.0.0.1", 0), Redis)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            r = cloud_check.check_redis("127.0.0.1", port)
            self.assertEqual(r["severity"], "Info")
            self.assertIn("auth required", r["status"].lower())
        finally:
            httpd.shutdown()


class TestDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="secupulse_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        cls.port = _free_port()
        # two "clients" (tenants) with one scan each
        os.makedirs(os.path.join(cls.tmp, "acme-corp"), exist_ok=True)
        os.makedirs(os.path.join(cls.tmp, "globex"), exist_ok=True)
        with open(os.path.join(cls.tmp, "acme-corp", "audit.json"), "w") as fh:
            json.dump({"tool": "SecuAudit", "target": "https://shop.acme.test",
                       "scan_date": "2026-09-04T10:00:00", "score": 63, "grade": "C",
                       "findings": [
                           {"id": "SQLI-1", "title": "Boolean-based SQL injection",
                            "severity": "Critical", "evidence": "?id=1 AND 1=1→200",
                            "remediation": "Parameterised queries."},
                           {"id": "XSS-1", "title": "Reflected XSS", "severity": "High",
                            "evidence": "<script>alert(1)</script> reflected",
                            "remediation": "Output-encode."}],
                       "summary": {"Critical": 1, "High": 1}}, fh)
        with open(os.path.join(cls.tmp, "globex", "cloud.json"), "w") as fh:
            json.dump({"tool": "CloudScope", "target": "s3://globex-assets",
                       "scan_date": "2026-09-03T09:00:00",
                       "checks": [{"service": "S3", "status": "PUBLIC LISTING ENABLED",
                                   "severity": "High", "evidence": "ListBucketResult",
                                   "remediation": "Block public access"},
                                  {"service": "Redis", "status": "OPEN — NO AUTH (CRITICAL)",
                                   "severity": "Critical", "evidence": "+PONG",
                                   "remediation": "requirepass"}]}, fh)
        cls.scans, cls.tenants = dashboard.discover(cls.tmp)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", cls.port), dashboard.Handler)
        dashboard.Handler.root = cls.tmp
        dashboard.Handler.scans = cls.scans
        dashboard.Handler.tenants = cls.tenants
        dashboard.Handler.token = None
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _get(self, path, token=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "ignore")

    def test_discover_tenants(self):
        self.assertIn("acme-corp", self.tenants)
        self.assertIn("globex", self.tenants)
        self.assertEqual(len(self.scans), 2)

    def test_normalize_web_findings(self):
        sc = next(s for s in self.scans if s["tool"] == "SecuAudit")
        self.assertEqual(len(sc["findings"]), 2)
        self.assertEqual(sc["summary"]["Critical"], 1)
        self.assertEqual(sc["score"], 63)

    def test_normalize_cloud_checks(self):
        sc = next(s for s in self.scans if s["tool"] == "CloudScope")
        self.assertEqual(sc["kind"], "cloud")
        crit = [f for f in sc["findings"] if f["severity"] == "Critical"]
        self.assertEqual(len(crit), 1)
        self.assertIn("NO AUTH", crit[0]["title"])

    def test_api_scans(self):
        code, body = self._get("/api/scans")
        self.assertEqual(code, 200)
        data = json.loads(body)
        self.assertEqual(data["count"], 2)

    def test_api_tenant_scan(self):
        code, body = self._get("/api/tenant/acme-corp/scan/audit")
        self.assertEqual(code, 200)
        data = json.loads(body)
        self.assertEqual(data["findings"][0]["id"], "SQLI-1")
        code, _ = self._get("/api/tenant/acme-corp/scan/does-not-exist")
        self.assertEqual(code, 404)

    def test_status_roundtrip(self):
        body = ("/api/status?t=acme-corp&s=audit&f=SQLI-1&status=mitigated&note=fix+deployed")
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{body}", method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            self.assertEqual(r.status, 200)
        st = dashboard.load_status(self.tmp)
        self.assertEqual(st["acme-corp/audit/SQLI-1"]["status"], "mitigated")

    def test_html_pages_render(self):
        code, body = self._get("/")
        self.assertEqual(code, 200)
        self.assertIn("SecuPulse", body)
        self.assertIn("acme-corp", body)
        code, body = self._get("/t/acme-corp/s/audit")
        self.assertEqual(code, 200)
        self.assertIn("Boolean-based SQL injection", body)
        self.assertIn("Parameterised queries", body)

    def test_path_traversal_denied(self):
        code, _ = self._get("/export/acme-corp/..%2f..%2fetc%2fpasswd")
        self.assertIn(code, (400, 404))


class TestDiscoverMisc(unittest.TestCase):
    def test_tool_less_json_and_subdomain_normalisation(self):
        tmp = tempfile.mkdtemp(prefix="secupulse2_")
        try:
            with open(os.path.join(tmp, "subs.json"), "w") as fh:
                json.dump({"domain": "example.com", "count": 3,
                           "subdomains": {
                               "www.example.com": {"sources": ["crt.sh"],
                                                   "ips": ["93.184.216.34"]},
                               "mail.example.com": {"sources": ["crt.sh"], "ips": []}}}, fh)
            scans, tenants = dashboard.discover(tmp)
            self.assertEqual(len(scans), 1)
            sc = scans[0]
            self.assertEqual(sc["kind"], "subdomain")
            self.assertEqual(sc["tool"], "subs")          # falls back to filename
            self.assertEqual(sum(sc["summary"].values()), 2)
            by_title = {f["title"]: f["severity"] for f in sc["findings"]}
            self.assertTrue(any("www.example.com" in t and s == "Low"
                                for t, s in by_title.items()))      # live host
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestWorkflow(unittest.TestCase):
    """End-to-end workflow chain against local servers (no internet needed)."""

    def _vuln_site(self):
        """Site with: homepage links, a param URL (SQLi-vulnerable), /admin."""
        import http.server

        class V(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                path = urllib.parse.urlparse(self.path).path
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                v = q.get("id", [""])[0]
                if path == "/":
                    body = (b"<html><head><title>Acme Shop</title></head><body>"
                            b"<a href='/item?id=1'>item</a>"
                            b"<a href='/admin'>admin</a></body></html>")
                elif path == "/item":
                    if "'" in v or " AND " in v.upper():
                        body = (b"You have an error in your SQL syntax; "
                                b"check the manual for MySQL")
                    else:
                        body = b"product page"
                elif path == "/admin":
                    body = b"<html><title>Admin</title><body>login</body></html>"
                else:
                    body = b"404"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd = socketserver.TCPServer(("127.0.0.1", 0), V)
        httpd.timeout = 1
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd

    def test_dns_cname_parser(self):
        # encoding/decoding round-trip through the raw DNS helpers
        self.assertEqual(
            workflow._decode_name(b"\x03www\x07example\x03com\x00", 0),
            "www.example.com")

    def test_full_chain_local(self):
        httpd = self._vuln_site()
        port = httpd.server_address[1]
        try:
            out_dir = tempfile.mkdtemp(prefix="hunter_")
            self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
            r = workflow.run_workflow(
                "acme.test",
                use_crt=False, do_brute=False, do_takeover=False, do_waf=False,
                active=True, payloads=4, delay=0.05, timeout=5,
                hosts_override=[f"127.0.0.1:{port}"],
                out_dir=out_dir)
            self.assertEqual(r["host_count"], 1)
            self.assertEqual(r["hosts"][0]["title"], "Acme Shop")
            self.assertEqual(r["hosts"][0]["status"], 200)
            # spider found param + template scan + active fuzz all produced findings
            sevs = [f.get("severity") for f in r["findings"]]
            self.assertIn("Critical", sevs)
            titles = " ".join(f.get("title", "") for f in r["findings"])
            self.assertIn("SQL", titles)
            self.assertIn("param_urls", r)
            self.assertTrue(any("item" in u for u in r["param_urls"]))
            self.assertGreaterEqual(len(r["findings"]), 1)
            # Critical SQLi (weight 25 each) + template findings deducted → ≤ 75
            self.assertGreaterEqual(r["score"], 0.0)
            self.assertLessEqual(r["score"], 75.0)
            self.assertIn(r["grade"], "ABCDEF")
            self.assertTrue(r["active_mode"])
        finally:
            httpd.shutdown()

    def test_takeover_detection_local(self):
        """Dangling CNAME → known service marker on the HTTP response."""
        import http.server

        class G(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"<html><body>There isn't a GitHub Pages site here.</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd = socketserver.TCPServer(("127.0.0.1", 0), G)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        try:
            # fake a dangling CNAME: sub.foo.github.io
            res = workflow.takeover_check(f"127.0.0.1:{port}",
                                          cname="evil.foo.github.io", timeout=4)
            self.assertTrue(res["takeover"])
            self.assertIn("github.io", res["service"])
            self.assertIn("GitHub Pages", res["evidence"])
        finally:
            httpd.shutdown()

    def test_probe_local(self):
        httpd = self._vuln_site()
        port = httpd.server_address[1]
        try:
            p = workflow.probe(f"127.0.0.1:{port}", timeout=5)
            self.assertIsNotNone(p)
            self.assertEqual(p["status"], 200)
            self.assertEqual(p["title"], "Acme Shop")
        finally:
            httpd.shutdown()


class TestSarif(unittest.TestCase):
    def test_sarif_structure(self):
        data = {"tool": "Nucleus", "target": "https://example.com",
                "scan_date": "2026-09-04T00:00:00",
                "findings": [
                    {"id": "header-hsts-missing", "title": "Missing HSTS",
                     "severity": "High", "evidence": "no header",
                     "remediation": "add HSTS", "description": "desc",
                     "tags": "header,hardening"},
                    {"id": "misconfig-git-exposure", "title": "Git exposed",
                     "severity": "Critical", "evidence": "200", "remediation": "block"},
                ]}
        sarif = sarif_export.to_sarif(data)
        self.assertEqual(sarif["version"], "2.1.0")
        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(len(driver["rules"]), 2)
        self.assertEqual(len(sarif["runs"][0]["results"]), 2)
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")


def load_tests(loader, standard_tests, pattern):
    """Load every test module without star-import name collisions.

    The legacy runner imports modules with ``from test_x import *`` because
    its local integration tests reuse helpers from those modules. That keeps
    those helpers available, but repeated TestCase names in separate modules
    overwrite one another in this module's global namespace. Load each module
    independently here, then add only the TestCase classes defined locally.
    """
    module_names = (
        "test_foundation",
        "test_security",
        "test_orchestration",
        "test_intelligence",
        "test_monitoring",
        "test_reporting",
        "test_devsecops",
        "test_identity",
        "test_cloud_security",
        "test_security_operations",
        "test_data_governance",
        "test_federation",
        "test_foundation_runtime",
        "test_configuration",
        "test_engine_registry",
        "test_schemas",
        "test_security_baseline",
        "test_api_http",
        "test_api_router",
        "test_identity_refresh",
        "test_api_idempotency",
        "test_api_resources",
        "test_product_integrations",
        "test_cloud_adapters",
        "test_crypto",
        "test_database_migrations",
    )
    missing_modules = [name for name in module_names if name not in sys.modules]
    if missing_modules:
        raise RuntimeError(
            "custom test runner did not import required modules: "
            + ", ".join(missing_modules)
        )

    suite = unittest.TestSuite()
    for module_name in module_names:
        suite.addTests(loader.loadTestsFromModule(sys.modules[module_name]))

    local_test_cases = {}
    for candidate in globals().values():
        if (
            isinstance(candidate, type)
            and issubclass(candidate, unittest.TestCase)
            and candidate is not unittest.TestCase
            and candidate.__module__ == __name__
        ):
            local_test_cases.setdefault(candidate, None)
    for test_case in local_test_cases:
        suite.addTests(loader.loadTestsFromTestCase(test_case))
    return suite


if __name__ == "__main__":
    print("SecuToolkit test suite — web, api, phishing, logs, cve, pdf, cli\n")
    unittest.main(verbosity=2)
```
