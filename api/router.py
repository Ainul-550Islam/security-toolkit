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
        assets_discovery,
        audit,
        evidence,
        findings,
        integrations,
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
    tenants.register(router)
    users.register(router)
    projects.register(router)
    organizations.register(router)
    roles.register(router)
    sessions.register(router)
    assets.register(router)
    assets_discovery.register(router)
    findings.register(router)
    evidence.register(router)
    scans.register(router)
    reports.register(router)
    risk.register(router)
    remediation.register(router)
    search.register(router)
    analytics.register(router)
    audit.register(router)
    integrations.register(router)
    notifications.register(router)
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
    from services.customer_resource_service import CustomerResourceService
    mfa_module = importlib.import_module("mfa_service")
    remedy_module = importlib.import_module("remedy")
    notification_service = NotificationFacade(platform_service)
    ticketing_service = TicketingService(platform_service)
    customer_resource_service = CustomerResourceService(
        platform_service, identity_service
    )
    mfa_service = mfa_module.MfaService(
        platform_service, identity_svc=identity_service
    )
    remediation_engine = remedy_module.RemediationService(
        platform_service,
        registry=scanner_registry,
        jobs=job_service,
        limiter=identity_service.limiter,
    )
    from api.idempotency import IdempotencyStore
    idempotency_store = IdempotencyStore(platform_service.db)

    intel_module = importlib.import_module("intel")
    correlate_module = importlib.import_module("correlate")
    governance_module = importlib.import_module("data_governance")
    intel_service = intel_module.IntelService(platform_service)
    correlation_service = correlate_module.CorrelationService(platform_service)

    from services.asset_service import AssetService as AssetDomainService
    from services.scan_service import ScanService as ScanDomainService
    from services.finding_service import FindingService as FindingDomainService
    from services.risk_service import RiskService as RiskDomainService
    from services.evidence_service import EvidenceService as EvidenceDomainService
    from services.report_service import ReportService as ReportDomainService
    from services.search_service import SearchService as SearchDomainService
    from services.remediation_service import RemediationService as RemediationDomainService
    from services.notification_service import NotificationService as NotificationDomainService
    from services.integration_service import IntegrationService as IntegrationDomainService

    asset_domain_service = AssetDomainService(
        platform_service, intel=intel_service, identity=identity_service
    )
    scan_domain_service = ScanDomainService(
        platform_service, job_service, idempotency=idempotency_store,
        authorization=authorization_service,
    )
    remediation_domain_service = RemediationDomainService(
        platform_service, remediation_engine, identity=identity_service
    )
    finding_domain_service = FindingDomainService(
        platform_service, correlation=correlation_service,
        remediation=remediation_domain_service, identity=identity_service,
    )
    risk_domain_service = RiskDomainService(
        platform_service, analytics=analytics_service,
        correlation=correlation_service,
    )
    compliance_evidence_engine = reporting_module.EvidenceService(platform_service)
    retention_service = governance_module.RetentionService(platform_service)
    evidence_domain_service = EvidenceDomainService(
        platform_service, reports=report_service,
        compliance_engine=compliance_evidence_engine, retention=retention_service,
    )
    report_domain_service = ReportDomainService(
        platform_service, report_service, jobs=job_service,
        scans=scan_domain_service, idempotency=idempotency_store,
    )
    notification_facade = notification_service
    notification_domain_service = NotificationDomainService(
        platform_service, facade=notification_facade
    )
    integration_domain_service = IntegrationDomainService(
        platform_service, integration_service
    )
    search_domain_service = SearchDomainService(
        platform_service,
        assets=asset_domain_service,
        findings=finding_domain_service,
        scans=scan_domain_service,
        reports=report_domain_service,
        evidence=evidence_domain_service,
        integrations=integration_domain_service,
    )

    return ApiServices(
        platform=platform_service,
        identity=identity_service,
        authorization=authorization_service,
        health=health_service,
        capabilities=capability_service,
        jobs=job_service,
        reports=report_service,
        analytics=analytics_service,
        integrations=integration_domain_service,
        notifications=notification_domain_service,
        ticketing=ticketing_service,
        clouds=cloud_service,
        extra={
            "scanner_registry": scanner_registry,
            "idempotency_store": idempotency_store,
            "customer_resources": customer_resource_service,
            "mfa_service": mfa_service,
            "asset_service": asset_domain_service,
            "scan_service": scan_domain_service,
            "finding_service": finding_domain_service,
            "risk_service": risk_domain_service,
            "evidence_service": evidence_domain_service,
            "report_service": report_domain_service,
            "search_service": search_domain_service,
            "remediation_service": remediation_domain_service,
            "remediation_engine": remediation_engine,
            "notification_service": notification_domain_service,
            "integration_service": integration_domain_service,
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
