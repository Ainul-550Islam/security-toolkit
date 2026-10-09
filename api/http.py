"""Production WSGI-compatible HTTP adapter for the Security Toolkit API.

The adapter uses only the Python standard library for transport parsing. It
accepts bounded JSON requests, routes them through the central API middleware,
serializes safe JSON responses, and exposes ``application`` for WSGI servers.
The bundled ``wsgiref`` runner is intended only for local development; a
hardened production WSGI server and TLS-terminating ingress should be used in
deployments.
"""

from __future__ import annotations

import json
import logging
import math
import re
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import fields
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs

from api.errors import ApiException, ApiProblem, problem_from_exception
from api.middleware import ApiMiddleware, HttpRequest, HttpResponse, SafeSlidingWindowLimiter
from api.router import ApiServices, build_default_services, create_router

_DEFAULT_MAX_BODY_BYTES = 1_048_576
_MAX_QUERY_BYTES = 8_192
_MAX_QUERY_FIELDS = 100
_MAX_HEADER_COUNT = 100
_MAX_HEADER_VALUE_LENGTH = 8_192
_MAX_HEADER_BYTES = 65_536
_MAX_RESPONSE_HEADER_COUNT = 100
_MAX_RESPONSE_HEADER_BYTES = 65_536
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$")
_METHOD_RE = re.compile(r"^[A-Za-z]{1,16}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_BAD_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_HOP_BY_HOP_RESPONSE_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})
_NO_CONTENT_STATUSES = frozenset({204, 205, 304})


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError("non-finite JSON values are not accepted")


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON numbers are not accepted")
    return parsed


def _validate_json_unicode(value: Any) -> None:
    """Reject unpaired escaped surrogates before they reach service code."""
    if isinstance(value, str):
        value.encode("utf-8", "strict")
    elif isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8", "strict")
            _validate_json_unicode(item)
    elif isinstance(value, list):
        for item in value:
            _validate_json_unicode(item)


def _request_problem(status: int, code: str, message: str) -> ApiException:
    return ApiException(ApiProblem(status, code, message))


def _safe_header_value(value: Any) -> bool:
    """Return whether a bounded value is safe for a WSGI header field."""
    if not isinstance(value, str) or len(value) > _MAX_HEADER_VALUE_LENGTH:
        return False
    try:
        value.encode("latin-1", "strict")
    except UnicodeEncodeError:
        return False
    return all(
        character == "\t" or (ord(character) >= 0x20 and ord(character) != 0x7F)
        for character in value
    )


def _valid_max_body_bytes(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= 10_485_760
    )


def parse_wsgi_request(
    environ: Mapping[str, Any],
    *,
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
) -> HttpRequest:
    """Parse a WSGI environment while bounding all client-controlled input.

    WSGI servers may collapse duplicate wire headers before constructing the
    environ mapping. This adapter rejects conflicting framing values visible in
    the mapping; the upstream HTTP server must also reject ambiguous raw framing.
    """
    if not _valid_max_body_bytes(max_body_bytes):
        raise ValueError("max_body_bytes is outside the supported range")

    method_value = environ.get("REQUEST_METHOD", "GET")
    if not isinstance(method_value, str):
        raise _request_problem(400, "invalid_method", "The HTTP method is invalid")
    method = method_value.upper()
    if not _METHOD_RE.fullmatch(method):
        raise _request_problem(400, "invalid_method", "The HTTP method is invalid")

    path_value = environ.get("PATH_INFO", "/")
    if not isinstance(path_value, str):
        raise _request_problem(400, "invalid_path", "The request path is invalid")
    path = path_value
    if not path or len(path) > 2048 or not path.startswith("/"):
        raise _request_problem(400, "invalid_path", "The request path is invalid")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        raise _request_problem(400, "invalid_path", "The request path is invalid")
    try:
        path.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise _request_problem(400, "invalid_path", "The request path is invalid") from None

    headers: dict[str, str] = {}
    header_count = 0
    header_bytes = 0
    for key, value in environ.items():
        if not isinstance(key, str) or not key.startswith("HTTP_"):
            continue
        header_count += 1
        if header_count > _MAX_HEADER_COUNT:
            raise _request_problem(400, "invalid_header", "The request headers exceed the configured limit")
        if not isinstance(value, (str, bytes)):
            raise _request_problem(400, "invalid_header", "A request header is invalid")
        header_name = key[5:].replace("_", "-").lower()
        if not header_name or len(header_name) > 128 or not _HEADER_NAME_RE.fullmatch(header_name):
            raise _request_problem(400, "invalid_header", "A request header is invalid")
        if header_name == "content-length":
            # This field has a dedicated WSGI environ key. Accepting the HTTP_*
            # form as well would leave duplicate framing ambiguous.
            raise _request_problem(400, "ambiguous_content_length", "The request framing is ambiguous")
        if header_name == "content-type":
            # WSGI exposes Content-Type through CONTENT_TYPE, not HTTP_*.
            raise _request_problem(400, "invalid_header", "A request header is invalid")
        header_value = value.decode("latin-1") if isinstance(value, bytes) else value
        if not _safe_header_value(header_value):
            if header_name == "x-request-id" and len(header_value) <= _MAX_HEADER_VALUE_LENGTH:
                # An unsafe correlation value is discarded rather than reflected;
                # the middleware will generate a fresh request ID.
                header_value = ""
            else:
                raise _request_problem(400, "invalid_header", "A request header is invalid")
        header_bytes += len(header_name) + len(header_value)
        if header_bytes > _MAX_HEADER_BYTES:
            raise _request_problem(400, "invalid_header", "The request headers exceed the configured limit")
        if header_name in headers:
            raise _request_problem(400, "invalid_header", "A duplicate request header is not allowed")
        headers[header_name] = header_value

    content_type_value = environ.get("CONTENT_TYPE", "")
    if content_type_value is None:
        content_type_value = ""
    elif isinstance(content_type_value, bytes):
        content_type_value = content_type_value.decode("latin-1")
    elif not isinstance(content_type_value, str):
        raise _request_problem(400, "invalid_header", "A request header is invalid")
    if not _safe_header_value(content_type_value):
        raise _request_problem(400, "invalid_header", "A request header is invalid")
    if content_type_value:
        header_bytes += len("content-type") + len(content_type_value)
        if header_bytes > _MAX_HEADER_BYTES:
            raise _request_problem(400, "invalid_header", "The request headers exceed the configured limit")
        headers["content-type"] = content_type_value

    content_length_value = environ.get("CONTENT_LENGTH", "")
    if content_length_value is None:
        content_length_value = ""
    elif isinstance(content_length_value, bytes):
        try:
            content_length_value = content_length_value.decode("ascii", "strict")
        except UnicodeDecodeError:
            raise _request_problem(400, "invalid_content_length", "The request length is invalid") from None
    elif not isinstance(content_length_value, str):
        raise _request_problem(400, "invalid_content_length", "The request length is invalid")
    content_length_text = content_length_value
    if content_length_text and (
        len(content_length_text) > 10
        or any(character < "0" or character > "9" for character in content_length_text)
    ):
        raise _request_problem(400, "invalid_content_length", "The request length is invalid")
    content_length = int(content_length_text) if content_length_text else 0
    if content_length > max_body_bytes:
        raise _request_problem(413, "request_too_large", "The request body exceeds the configured limit")
    if headers.get("transfer-encoding", ""):
        raise _request_problem(400, "invalid_transfer_encoding", "Transfer encoding is not accepted by this WSGI adapter")
    if environ.get("wsgi.input_terminated") is True and not content_length_text:
        raise _request_problem(400, "unsupported_body_framing", "The request body framing is not supported")

    body: dict[str, Any] = {}
    if content_length:
        if method in {"GET", "HEAD", "DELETE"}:
            raise _request_problem(400, "unexpected_body", "This method does not accept a request body")
        media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise _request_problem(415, "unsupported_media_type", "Content-Type must be application/json")
        stream = environ.get("wsgi.input")
        if stream is None or not hasattr(stream, "read"):
            raise _request_problem(400, "invalid_body", "The request body is invalid")
        try:
            raw = stream.read(content_length)
        except Exception:
            raise _request_problem(400, "invalid_body", "The request body is invalid") from None
        if not isinstance(raw, bytes) or len(raw) != content_length:
            raise _request_problem(400, "invalid_body", "The request body is incomplete")
        try:
            parsed = json.loads(
                raw.decode("utf-8", "strict"),
                object_pairs_hook=_duplicate_rejecting_object,
                parse_constant=_reject_nonfinite,
                parse_float=_finite_json_float,
            )
            _validate_json_unicode(parsed)
        except (UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError, ValueError, OverflowError, RecursionError):
            raise _request_problem(400, "invalid_json", "The request body is not valid JSON") from None
        if not isinstance(parsed, dict):
            raise _request_problem(400, "invalid_json_shape", "The JSON request body must be an object")
        body = parsed

    query_value = environ.get("QUERY_STRING", "")
    if query_value is None:
        query_value = ""
    if not isinstance(query_value, str):
        raise _request_problem(400, "invalid_query", "The query string is invalid")
    query_text = query_value
    if len(query_text) > _MAX_QUERY_BYTES:
        raise _request_problem(400, "query_too_large", "The query string exceeds the configured limit")
    if not query_text.isascii():
        raise _request_problem(400, "invalid_query", "The query string is invalid")
    if _BAD_PERCENT_ESCAPE_RE.search(query_text):
        raise _request_problem(400, "invalid_query", "The query string is invalid")
    try:
        query = parse_qs(
            query_text,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=_MAX_QUERY_FIELDS,
            encoding="utf-8",
            errors="strict",
        ) if query_text else {}
    except (ValueError, UnicodeDecodeError):
        raise _request_problem(400, "invalid_query", "The query string is invalid") from None

    remote_value = environ.get("REMOTE_ADDR", "")
    remote_addr = remote_value[:128] if isinstance(remote_value, str) else ""
    scheme_value = environ.get("wsgi.url_scheme", "http")
    scheme = scheme_value.lower() if isinstance(scheme_value, str) else "http"
    if scheme not in {"http", "https"}:
        scheme = "http"
    supplied_id = headers.get("x-request-id", "")
    request_id = supplied_id if _REQUEST_ID_RE.fullmatch(supplied_id) else uuid.uuid4().hex
    return HttpRequest(
        method=method,
        path=path,
        query=query,
        headers=headers,
        body=body,
        remote_addr=remote_addr,
        scheme=scheme,
        request_id=request_id,
    )


class ResponseSerializationError(Exception):
    """Raised when a route returned a value outside the JSON contract."""


def _response_bytes(response: HttpResponse) -> tuple[bytes, str]:
    if 100 <= response.status < 200 or response.status in _NO_CONTENT_STATUSES or response.body is None or response.body == b"":
        return b"", ""
    if isinstance(response.body, bytes):
        return response.body, "application/octet-stream"
    try:
        encoded = json.dumps(
            response.body,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
        return encoded, "application/json; charset=utf-8"
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError, RecursionError):
        raise ResponseSerializationError() from None


def _request_id_from_environ(environ: Mapping[str, Any]) -> str:
    supplied = environ.get("HTTP_X_REQUEST_ID", "")
    if isinstance(supplied, bytes):
        try:
            supplied = supplied.decode("ascii", "strict")
        except UnicodeDecodeError:
            return uuid.uuid4().hex
    if not isinstance(supplied, str) or len(supplied) > 98:
        return uuid.uuid4().hex
    candidate = supplied.strip(" \t")
    return candidate if _REQUEST_ID_RE.fullmatch(candidate) else uuid.uuid4().hex


def _request_method_from_environ(environ: Mapping[str, Any]) -> str:
    method = environ.get("REQUEST_METHOD", "GET")
    return method.upper() if isinstance(method, str) else ""


def _replace_response_header(response: HttpResponse, name: str, value: str) -> None:
    target = name.lower()
    current = getattr(response, "headers", [])
    retained: list[Any] = []
    if isinstance(current, (list, tuple)):
        for item in current:
            if (
                isinstance(item, (list, tuple))
                and len(item) == 2
                and isinstance(item[0], str)
                and item[0].lower() == target
            ):
                continue
            retained.append(item)
    response.headers = retained
    response.headers.append((name, value))


def _apply_transport_security_headers(
    response: HttpResponse,
    request_id: str,
    *,
    hsts: bool,
) -> None:
    """Apply the same request/security headers to success and error responses."""
    safe_request_id = request_id if _REQUEST_ID_RE.fullmatch(request_id) else uuid.uuid4().hex
    for name, value in (
        ("X-Request-ID", safe_request_id),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
        ("Cache-Control", "no-store"),
    ):
        _replace_response_header(response, name, value)
    if hsts:
        _replace_response_header(response, "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    else:
        current = getattr(response, "headers", [])
        if isinstance(current, (list, tuple)):
            response.headers = [
                item for item in current
                if not (
                    isinstance(item, (list, tuple))
                    and len(item) == 2
                    and isinstance(item[0], str)
                    and item[0].lower() == "strict-transport-security"
                )
            ]
    if response.status == 401 and not any(
        isinstance(item, (list, tuple))
        and len(item) == 2
        and isinstance(item[0], str)
        and item[0].lower() == "www-authenticate"
        for item in getattr(response, "headers", [])
    ):
        _replace_response_header(response, "WWW-Authenticate", 'Bearer realm="secutoolkit-api"')


def _safe_headers(
    response: HttpResponse,
    content_type: str,
    body: bytes,
    *,
    representation_length: int | None = None,
) -> list[tuple[str, str]]:
    """Serialize only bounded, syntactically safe response headers.

    Application-supplied framing headers are discarded: WSGI owns transfer
    framing and this adapter computes Content-Length from the serialized body.
    """
    raw_headers = getattr(response, "headers", [])
    validated: list[tuple[str, str]] = []
    counts: dict[str, int] = {}
    total_bytes = 0
    if isinstance(raw_headers, (list, tuple)):
        for item in raw_headers:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            name, value = item
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            if not name or len(name) > 128 or not _HEADER_NAME_RE.fullmatch(name):
                continue
            if not _safe_header_value(value):
                continue
            lowered_name = name.lower()
            if lowered_name == "content-length" or lowered_name in _HOP_BY_HOP_RESPONSE_HEADERS:
                continue
            added_bytes = len(name) + len(value)
            if (
                len(validated) >= _MAX_RESPONSE_HEADER_COUNT - 2
                or total_bytes + added_bytes > _MAX_RESPONSE_HEADER_BYTES - _MAX_HEADER_VALUE_LENGTH - 64
            ):
                break
            total_bytes += added_bytes
            validated.append((name, value))
            counts[lowered_name] = counts.get(lowered_name, 0) + 1

    headers = [
        (name, value)
        for name, value in validated
        if name.lower() == "set-cookie" or counts[name.lower()] == 1
    ]
    lowered = {name.lower() for name, _value in headers}
    if content_type and "content-type" not in lowered and _safe_header_value(content_type):
        headers.append(("Content-Type", content_type))
    if not (100 <= response.status < 200 or response.status in _NO_CONTENT_STATUSES):
        length = len(body) if representation_length is None else representation_length
        if not isinstance(length, int) or isinstance(length, bool) or length < 0:
            length = len(body)
        headers.append(("Content-Length", str(length)))
    return headers


def _status_line(status: int) -> str:
    try:
        phrase = HTTPStatus(status).phrase
    except ValueError:
        phrase = "Unknown"
    return f"{status} {phrase}"


def _write_wsgi_response(
    response: HttpResponse,
    payload: bytes,
    content_type: str,
    start_response: Callable[..., Any],
    *,
    method: str,
) -> list[bytes]:
    representation_length = len(payload)
    body = b"" if method == "HEAD" else payload
    headers = _safe_headers(
        response,
        content_type,
        body,
        representation_length=representation_length,
    )
    start_response(_status_line(response.status), headers)
    return [body]


class WSGIApplication:
    """Callable WSGI application with explicit close/shutdown behavior."""

    def __init__(
        self,
        services: ApiServices,
        *,
        require_tls: bool,
        max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
        request_timeout_seconds: float = 30.0,
        rate_limiter: SafeSlidingWindowLimiter | None = None,
        hsts: bool | None = None,
    ) -> None:
        if not _valid_max_body_bytes(max_body_bytes):
            raise ValueError("max_body_bytes is outside the supported range")
        self.services = services
        self.max_body_bytes = max_body_bytes
        self.router = create_router(services)
        self.middleware = ApiMiddleware(
            self.router,
            self.router_auth_adapter,
            require_tls=require_tls,
            request_timeout_seconds=request_timeout_seconds,
            rate_limiter=rate_limiter,
            hsts=hsts,
        )
        self._closed = False
        self._close_lock = threading.Lock()

    @property
    def router_auth_adapter(self) -> Any:
        """Return the adapter installed by the same deterministic router factory."""
        from api.auth import AuthenticationAdapter

        return AuthenticationAdapter(self.services.authorization, self.services.identity)

    def __call__(self, environ: Mapping[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        if self._closed:
            request_id = _request_id_from_environ(environ)
            response = HttpResponse(503, {
                "error": {
                    "code": "service_unavailable",
                    "message": "The service is shutting down",
                    "request_id": request_id,
                }
            })
            _apply_transport_security_headers(response, request_id, hsts=self.middleware.hsts)
            payload, content_type = _response_bytes(response)
            return _write_wsgi_response(
                response,
                payload,
                content_type,
                start_response,
                method=_request_method_from_environ(environ),
            )

        try:
            request = parse_wsgi_request(environ, max_body_bytes=self.max_body_bytes)
        except ApiException as exc:
            request_id = _request_id_from_environ(environ)
            problem = exc.problem
            response = HttpResponse(problem.status, problem.body(request_id))
            _apply_transport_security_headers(response, request_id, hsts=self.middleware.hsts)
            payload, content_type = _response_bytes(response)
            return _write_wsgi_response(
                response,
                payload,
                content_type,
                start_response,
                method=_request_method_from_environ(environ),
            )

        try:
            response = self.middleware.handle(request)
            _apply_transport_security_headers(response, request.request_id, hsts=self.middleware.hsts)
            payload, content_type = _response_bytes(response)
        except Exception as exc:
            logging.getLogger("security_toolkit.api").error(
                "api_transport_failed",
                extra={
                    "api_event": "transport_failed",
                    "request_id": request.request_id,
                    "exception_type": type(exc).__name__[:80],
                },
            )
            problem = problem_from_exception(exc)
            response = HttpResponse(problem.status, problem.body(request.request_id))
            _apply_transport_security_headers(response, request.request_id, hsts=self.middleware.hsts)
            payload, content_type = _response_bytes(response)
        return _write_wsgi_response(
            response,
            payload,
            content_type,
            start_response,
            method=request.method,
        )

    @staticmethod
    def _status_line(status: int) -> str:
        return _status_line(status)

    def close(self) -> None:
        """Release owned services and nested database resources once only."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        closed: set[int] = set()
        for service_field in fields(self.services):
            service = getattr(self.services, service_field.name)
            if service is None or id(service) in closed:
                continue
            closed.add(id(service))
            try:
                close_method = getattr(service, "close", None)
            except Exception as exc:
                logging.getLogger("security_toolkit.api").error(
                    "api_shutdown_failed",
                    extra={
                        "api_event": "shutdown_failed",
                        "service": service_field.name,
                        "exception_type": type(exc).__name__[:80],
                    },
                )
                continue
            resources = [service] if callable(close_method) else []
            if not callable(close_method):
                try:
                    database = getattr(service, "db", None)
                except Exception as exc:
                    logging.getLogger("security_toolkit.api").error(
                        "api_shutdown_failed",
                        extra={
                            "api_event": "shutdown_failed",
                            "service": service_field.name,
                            "exception_type": type(exc).__name__[:80],
                        },
                    )
                    database = None
                if database is not None:
                    resources.append(database)
            for resource in resources:
                if id(resource) in closed:
                    continue
                closed.add(id(resource))
                try:
                    resource_close = getattr(resource, "close", None)
                except Exception as exc:
                    logging.getLogger("security_toolkit.api").error(
                        "api_shutdown_failed",
                        extra={
                            "api_event": "shutdown_failed",
                            "service": service_field.name,
                            "exception_type": type(exc).__name__[:80],
                        },
                    )
                    continue
                if not callable(resource_close):
                    continue
                try:
                    resource_close()
                except Exception as exc:
                    logging.getLogger("security_toolkit.api").error(
                        "api_shutdown_failed",
                        extra={
                            "api_event": "shutdown_failed",
                            "service": service_field.name,
                            "exception_type": type(exc).__name__[:80],
                        },
                    )


def create_app(
    services: ApiServices | None = None,
    *,
    db_path: str | None = None,
    require_tls: bool | None = None,
    max_body_bytes: int | None = None,
    request_timeout_seconds: float = 30.0,
    rate_limiter: SafeSlidingWindowLimiter | None = None,
    hsts: bool | None = None,
) -> WSGIApplication:
    """Build a WSGI application, loading validated settings when unspecified."""
    from config.settings import get_int, load_settings

    settings = load_settings()
    active_services = services or build_default_services(db_path=db_path)
    tls_required = settings.tls_required if require_tls is None else bool(require_tls)
    body_limit = max_body_bytes
    if body_limit is None:
        body_limit = get_int(
            "SECTOOLKIT_API_MAX_BODY_BYTES",
            default=_DEFAULT_MAX_BODY_BYTES,
            minimum=1024,
            maximum=10_485_760,
        )
    return WSGIApplication(
        active_services,
        require_tls=tls_required,
        max_body_bytes=body_limit,
        request_timeout_seconds=request_timeout_seconds,
        rate_limiter=rate_limiter,
        hsts=hsts,
    )


class LazyApplication:
    """Lazy WSGI target for servers importing ``api.http:application``."""

    def __init__(self, factory: Callable[[], WSGIApplication] = create_app) -> None:
        self._factory = factory
        self._delegate: WSGIApplication | None = None
        self._lock = threading.Lock()
        self._closed = False

    def _get_delegate(self) -> WSGIApplication:
        if self._closed:
            raise RuntimeError("WSGI application is closed")
        if self._delegate is not None:
            return self._delegate
        with self._lock:
            if self._closed:
                raise RuntimeError("WSGI application is closed")
            if self._delegate is None:
                self._delegate = self._factory()
        return self._delegate

    def __call__(self, environ: Mapping[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        try:
            delegate = self._get_delegate()
        except Exception as exc:
            request_id = _request_id_from_environ(environ)
            logging.getLogger("security_toolkit.api").error(
                "api_startup_failed",
                extra={
                    "api_event": "startup_failed",
                    "request_id": request_id,
                    "exception_type": type(exc).__name__[:80],
                },
            )
            problem = ApiProblem(503, "service_unavailable", "The service is not available")
            response = HttpResponse(503, problem.body(request_id))
            _apply_transport_security_headers(response, request_id, hsts=False)
            payload, content_type = _response_bytes(response)
            return _write_wsgi_response(
                response,
                payload,
                content_type,
                start_response,
                method=_request_method_from_environ(environ),
            )
        return delegate(environ, start_response)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            delegate = self._delegate
            self._delegate = None
        if delegate is not None:
            delegate.close()


application = LazyApplication()


def main() -> int:
    """Run the standard-library development server on the configured address."""
    from wsgiref.simple_server import make_server

    from config.settings import load_settings

    settings = load_settings()
    app = create_app(require_tls=settings.tls_required)
    server = make_server(settings.bind_host, settings.bind_port, app)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
        app.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "LazyApplication",
    "WSGIApplication",
    "application",
    "create_app",
    "main",
    "parse_wsgi_request",
]
