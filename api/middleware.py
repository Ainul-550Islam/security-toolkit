"""Framework-neutral HTTP middleware and transport request/response models."""

from __future__ import annotations

import ipaddress
import logging
import math
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from api.errors import ApiException, ApiProblem, problem_from_exception
from api.request_context import RequestContext

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$")


@dataclass(slots=True, repr=False)
class HttpRequest:
    """Parsed HTTP request; its representation deliberately hides credentials and body."""

    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: dict[str, Any]
    remote_addr: str
    scheme: str
    request_id: str = ""
    context: RequestContext | None = None
    route_match: Any = None

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def __repr__(self) -> str:
        return (
            f"HttpRequest(method={self.method!r}, path={self.path!r}, "
            f"request_id={self.request_id!r}, body=[REDACTED])"
        )


@dataclass(slots=True)
class HttpResponse:
    """JSON-oriented response object used by route handlers and middleware."""

    status: int
    body: Any = field(default_factory=dict)
    headers: list[tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.status, int) or not 100 <= self.status <= 599:
            raise ValueError("HTTP response status is invalid")
        safe_headers: list[tuple[str, str]] = []
        for name, value in self.headers:
            n, v = str(name), str(value)
            if not n or any(ch in n for ch in "\r\n:"):
                raise ValueError("HTTP response header name is invalid")
            if "\r" in v or "\n" in v:
                raise ValueError("HTTP response header value is invalid")
            safe_headers.append((n, v))
        self.headers = safe_headers

    def add_header(self, name: str, value: str) -> None:
        n, v = str(name), str(value)
        if not n or any(ch in n for ch in "\r\n:") or "\r" in v or "\n" in v:
            raise ValueError("HTTP response header is invalid")
        self.headers.append((n, v))

    def replace_header(self, name: str, value: str) -> None:
        lowered = name.lower()
        self.headers = [item for item in self.headers if item[0].lower() != lowered]
        self.add_header(name, value)


class RouteResolver(Protocol):
    """The part of the router consumed by the middleware."""

    def resolve(self, method: str, path: str) -> Any:
        """Return a route match or an HTTP response for 404/405."""
        ...


class SafeSlidingWindowLimiter:
    """Bounded process-local sliding-window limiter suitable as an API hook."""

    def __init__(
        self,
        *,
        limit: int = 120,
        window_seconds: float = 60.0,
        max_keys: int = 20_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("rate limiter bounds must be positive")
        self.limit = int(limit)
        self.window_seconds = float(window_seconds)
        self.max_keys = int(max_keys)
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}
        self._last_sweep = 0.0

    def allow(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry-after-seconds), without growing state unboundedly."""
        now = float(self._clock())
        if not math.isfinite(now):
            return False, max(1, math.ceil(self.window_seconds))
        safe_key = str(key)[:256]
        if not safe_key:
            safe_key = "unknown"
        cutoff = now - self.window_seconds
        with self._lock:
            if now - self._last_sweep >= min(self.window_seconds, 30.0):
                expired = [
                    item_key for item_key, hits in self._hits.items()
                    if not hits or hits[-1] <= cutoff
                ]
                for item_key in expired:
                    self._hits.pop(item_key, None)
                self._last_sweep = now
            hits = self._hits.get(safe_key)
            if hits is None:
                if len(self._hits) >= self.max_keys:
                    return False, max(1, math.ceil(self.window_seconds))
                hits = deque()
                self._hits[safe_key] = hits
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False, max(1, math.ceil(self.window_seconds - (now - hits[0])))
            hits.append(now)
            return True, 0


class ApiMiddleware:
    """Request IDs, auth/RBAC, tenant checks, rate hooks and safe error handling."""

    def __init__(
        self,
        router: RouteResolver,
        auth_adapter: Any,
        *,
        require_tls: bool = True,
        request_timeout_seconds: float = 30.0,
        rate_limiter: SafeSlidingWindowLimiter | None = None,
        logger: logging.Logger | None = None,
        hsts: bool | None = None,
    ) -> None:
        if not math.isfinite(float(request_timeout_seconds)) or request_timeout_seconds <= 0:
            raise ValueError("request timeout must be finite and positive")
        self.router = router
        self.auth_adapter = auth_adapter
        self.require_tls = bool(require_tls)
        self.request_timeout_seconds = float(request_timeout_seconds)
        self.rate_limiter = rate_limiter or SafeSlidingWindowLimiter()
        self.logger = logger or logging.getLogger("security_toolkit.api")
        self.hsts = self.require_tls if hsts is None else bool(hsts)

    def handle(self, request: HttpRequest) -> HttpResponse:
        """Process one parsed request and always return a redacted response."""
        started = time.monotonic()
        request.request_id = self._request_id(request.header("x-request-id"))
        match: Any = None
        response: HttpResponse
        try:
            if self.require_tls and request.scheme.lower() != "https":
                raise ApiException(
                    ApiProblem(426, "https_required", "HTTPS is required")
                )
            allow, retry_after = self.rate_limiter.allow(
                "ip:" + self._numeric_source(request.remote_addr)
            )
            if not allow:
                raise ApiException(
                    ApiProblem(429, "rate_limited", "Too many requests", retry_after=retry_after)
                )
            resolved = self.router.resolve(request.method, request.path)
            if isinstance(resolved, HttpResponse):
                response = resolved
                if isinstance(response.body, dict):
                    error_body = response.body.get("error")
                    if isinstance(error_body, dict):
                        error_body["request_id"] = request.request_id
                return self._finalize(request, response, started, "unmatched")
            match = resolved
            request.route_match = match
            route = match.route
            if getattr(route, "auth_required", True):
                try:
                    principal, auth_context = self.auth_adapter.authenticate(
                        request.header("authorization")
                    )
                except ValueError:
                    raise ApiException(
                        ApiProblem(401, "authentication_failed", "Authentication required or invalid")
                    ) from None
                request.context = RequestContext(
                    request_id=request.request_id,
                    principal=principal,
                    tenant_id=principal.tenant_id,
                    roles=principal.roles,
                    permissions=principal.permissions,
                    deadline_monotonic=started + self.request_timeout_seconds,
                    source_ip=self._valid_source(request.remote_addr),
                    authorization_context=auth_context,
                )
                principal_key = "principal:" + principal.principal_id
                allowed, retry_after = self.rate_limiter.allow(principal_key)
                if not allowed:
                    raise ApiException(
                        ApiProblem(429, "rate_limited", "Too many requests", retry_after=retry_after)
                    )
                permission = str(getattr(route, "permission", "") or "")
                if permission:
                    self.auth_adapter.require(auth_context, permission)
                scope_kind = str(getattr(route, "scope_kind", "") or "")
                scope_parameter = str(getattr(route, "scope_parameter", "") or "")
                if scope_kind and scope_parameter:
                    scope_id = match.path_params.get(scope_parameter, "")
                    if scope_id:
                        if scope_kind == "organization":
                            self.auth_adapter.require_org(auth_context, scope_id)
                        elif scope_kind == "project":
                            self.auth_adapter.require_project(auth_context, scope_id)
                        else:
                            raise RuntimeError("unsupported route scope")
            else:
                request.context = RequestContext(
                    request_id=request.request_id,
                    deadline_monotonic=started + self.request_timeout_seconds,
                    source_ip=self._valid_source(request.remote_addr),
                )
            if request.context.remaining_seconds(time.monotonic()) <= 0:
                raise ApiException(
                    ApiProblem(504, "deadline_exceeded", "The request deadline has expired")
                )
            response = route.handler(request, match.path_params)
            if not isinstance(response, HttpResponse):
                raise TypeError("route returned an invalid response")
        except Exception as exc:
            problem = problem_from_exception(exc)
            response = HttpResponse(problem.status, problem.body(request.request_id))
            if problem.retry_after:
                response.add_header("Retry-After", str(problem.retry_after))
            if problem.status == 401:
                response.add_header("WWW-Authenticate", 'Bearer realm="secutoolkit-api"')
            if not isinstance(exc, ApiException) and problem.status == 500:
                self.logger.error(
                    "api_request_failed",
                    extra={
                        "api_event": "request_failed",
                        "request_id": request.request_id,
                        "exception_type": type(exc).__name__[:80],
                    },
                )
        route_name = getattr(getattr(match, "route", None), "path", "unmatched")
        return self._finalize(request, response, started, str(route_name))

    def _request_id(self, supplied: str) -> str:
        candidate = str(supplied or "").strip()
        if _REQUEST_ID_RE.fullmatch(candidate):
            return candidate
        return uuid.uuid4().hex

    @staticmethod
    def _numeric_source(raw: str) -> str:
        try:
            return str(ipaddress.ip_address(str(raw or "")))
        except ValueError:
            return "unknown"

    @classmethod
    def _valid_source(cls, raw: str) -> str:
        source = cls._numeric_source(raw)
        return source if source != "unknown" else ""

    def _finalize(
        self,
        request: HttpRequest,
        response: HttpResponse,
        started: float,
        route_name: str,
    ) -> HttpResponse:
        response.replace_header("X-Request-ID", request.request_id)
        response.replace_header("X-Content-Type-Options", "nosniff")
        response.replace_header("X-Frame-Options", "DENY")
        response.replace_header("Referrer-Policy", "no-referrer")
        response.replace_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.replace_header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        response.replace_header("Cache-Control", "no-store")
        if self.hsts:
            response.replace_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if response.status == 401 and not any(
            name.lower() == "www-authenticate" for name, _ in response.headers
        ):
            response.add_header("WWW-Authenticate", 'Bearer realm="secutoolkit-api"')
        duration_ms = max(0.0, (time.monotonic() - started) * 1000.0)
        safe_method = request.method if request.method.isalpha() and len(request.method) <= 16 else "OTHER"
        safe_route = route_name if route_name.startswith("/") and len(route_name) <= 256 else "unmatched"
        self.logger.info(
            "api_request",
            extra={
                "api_event": "request_complete",
                "request_id": request.request_id,
                "method": safe_method,
                "route": safe_route,
                "status": response.status,
                "duration_ms": round(duration_ms, 3),
            },
        )
        return response


__all__ = [
    "ApiMiddleware",
    "HttpRequest",
    "HttpResponse",
    "RouteResolver",
    "SafeSlidingWindowLimiter",
]
