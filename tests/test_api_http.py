from __future__ import annotations

import io
import json
import os
import sys
import unittest
from types import SimpleNamespace
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_DIR = os.path.join(ROOT, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import errors  # noqa: E402
import rbac  # noqa: E402

from api.http import LazyApplication, WSGIApplication, _safe_headers, create_app  # noqa: E402
from api.middleware import HttpResponse, SafeSlidingWindowLimiter  # noqa: E402
from api.router import ApiServices  # noqa: E402
from services.capability_service import CapabilityService  # noqa: E402
from services.engine_registry import EngineRegistry  # noqa: E402
from services.health_service import HealthService  # noqa: E402


class FakeIdentity:
    def __init__(self) -> None:
        self.revoked: list[tuple[str, str]] = []
        self.refresh_count = 0

    def login(self, identifier: str, password: str, **_kwargs: Any) -> dict[str, Any]:
        if identifier != "analyst@example.test" or password != "correct-password":
            raise errors.AuthenticationError("a private failure detail")
        user = SimpleNamespace(
            id="user-12345678",
            org_id="org-12345678",
            username="analyst",
            display_name="Analyst",
        )
        session = SimpleNamespace(
            id="session-12345678",
            user_id=user.id,
            expires_at="2030-01-01T00:00:00Z",
            auth_method="password",
            mfa_status="none",
        )
        return {"user": user, "session": session, "secret": "stk_session_one_time_secret", "mfa_required": False}

    def user_roles(self, user_id: str) -> tuple[str, ...]:
        if user_id != "user-12345678":
            raise errors.NotFoundError("private id detail")
        return ("owner",)

    def session_refresh(self, _secret: str) -> dict[str, Any]:
        self.refresh_count += 1
        user = SimpleNamespace(id="user-12345678", org_id="org-12345678")
        session = SimpleNamespace(
            id="session-12345678",
            user_id=user.id,
            expires_at="2030-01-01T00:00:00Z",
            auth_method="password",
            mfa_status="none",
        )
        return {"user": user, "session": session, "secret": "stk_session_rotated_secret"}

    def user_get(self, user_id: str) -> Any:
        if user_id != "user-12345678":
            raise errors.NotFoundError("private id detail")
        return SimpleNamespace(id=user_id, org_id="org-12345678")

    def session_revoke_id(self, session_id: str, *, reason: str = "") -> None:
        self.revoked.append((session_id, reason))


class FakeAuthorization:
    def __init__(self) -> None:
        self.permissions = rbac.permissions_for(("owner",))

    def context_from_secret(self, secret: str) -> Any:
        if secret not in {"stk_session_valid_secret", "stk_credential_valid_secret"}:
            raise errors.AuthenticationError("private credential detail")
        credential = secret.startswith("stk_credential_")
        return SimpleNamespace(
            user_id="user-12345678" if not credential else "",
            org_id="org-12345678",
            roles=("owner",) if not credential else (),
            permissions=self.permissions,
            credential_id="credential-12345678" if credential else "",
            session_id="session-12345678" if not credential else "",
            auth_method="password",
            mfa_status="none",
            step_up_until="",
        )

    def require(self, context: Any, permission: str) -> None:
        if permission not in context.permissions:
            raise errors.AuthorizationError("private permission detail")

    def require_org(self, context: Any, org_id: str) -> None:
        if context.org_id != org_id:
            raise errors.AuthorizationError("private tenant detail")

    def require_project(self, context: Any, _project_id: str) -> Any:
        if context.org_id != "org-12345678":
            raise errors.AuthorizationError("private tenant detail")
        return SimpleNamespace(org_id=context.org_id)

    def mfa_required_for(self, _context: Any) -> bool:
        return False


class ApiHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = FakeIdentity()
        self.authorization = FakeAuthorization()
        registry = EngineRegistry()
        registry.register_declared_native()
        self.health = HealthService(registry=registry)
        self.capabilities = CapabilityService(registry)
        self.services = ApiServices(
            platform=object(),
            identity=self.identity,
            authorization=self.authorization,
            health=self.health,
            capabilities=self.capabilities,
        )
        self.app: WSGIApplication = create_app(
            self.services,
            require_tls=False,
            max_body_bytes=4096,
            rate_limiter=SafeSlidingWindowLimiter(limit=100, max_keys=1000),
        )

    def tearDown(self) -> None:
        self.app.close()

    def make_environ(
        self,
        method: str,
        path: str,
        *,
        raw_body: bytes = b"",
        headers: dict[str, str] | None = None,
        query: str = "",
        scheme: str = "https",
        remote: str = "127.0.0.1",
        environ_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        environ: dict[str, Any] = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_LENGTH": str(len(raw_body)),
            "CONTENT_TYPE": "application/json" if raw_body else "",
            "REMOTE_ADDR": remote,
            "wsgi.url_scheme": scheme,
            "wsgi.input": io.BytesIO(raw_body),
        }
        for name, value in (headers or {}).items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value
        if environ_overrides:
            environ.update(environ_overrides)
        return environ

    def invoke_wsgi(
        self,
        app: Any,
        environ: dict[str, Any],
    ) -> tuple[int, dict[str, str], bytes]:
        captured: dict[str, Any] = {}

        def start_response(status: str, response_headers: list[tuple[str, str]], exc_info: Any = None) -> None:
            if exc_info is not None:
                raise exc_info[1]
            captured["status"] = int(status.split(" ", 1)[0])
            captured["headers"] = {name.lower(): value for name, value in response_headers}

        result = b"".join(app(environ, start_response))
        return captured["status"], captured["headers"], result

    def call(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
        query: str = "",
        scheme: str = "https",
        remote: str = "127.0.0.1",
    ) -> tuple[int, dict[str, str], bytes]:
        if raw_body is None and body is not None:
            raw_body = json.dumps(body).encode("utf-8")
        raw_body = raw_body or b""
        environ = self.make_environ(
            method,
            path,
            raw_body=raw_body,
            headers=headers,
            query=query,
            scheme=scheme,
            remote=remote,
        )
        return self.invoke_wsgi(self.app, environ)

    @staticmethod
    def decode(raw: bytes) -> dict[str, Any]:
        return json.loads(raw.decode("utf-8")) if raw else {}

    def test_liveness_is_public_and_has_security_headers(self) -> None:
        status, headers, body = self.call("GET", "/api/v1/livez")
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(body)["status"], "healthy")
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn("access-control-allow-origin", headers)

    def test_tls_is_required_when_configured(self) -> None:
        secure_app = create_app(
            self.services,
            require_tls=True,
            rate_limiter=SafeSlidingWindowLimiter(limit=100),
        )
        try:
            environ: dict[str, Any] = {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/livez",
                "QUERY_STRING": "",
                "CONTENT_LENGTH": "0",
                "REMOTE_ADDR": "127.0.0.1",
                "wsgi.url_scheme": "http",
                "wsgi.input": io.BytesIO(b""),
            }
            captured: dict[str, Any] = {}

            def start_response(status: str, response_headers: list[tuple[str, str]], exc_info: Any = None) -> None:
                captured["status"] = int(status.split(" ", 1)[0])
                captured["headers"] = {name.lower(): value for name, value in response_headers}

            body = b"".join(secure_app(environ, start_response))
            self.assertEqual(captured["status"], 426)
            self.assertEqual(self.decode(body)["error"]["code"], "https_required")
            self.assertIn("strict-transport-security", captured["headers"])
        finally:
            secure_app.close()

    def test_protected_metadata_requires_authentication(self) -> None:
        status, _headers, raw = self.call("GET", "/api/v1/metadata")
        self.assertEqual(status, 401)
        self.assertEqual(self.decode(raw)["error"]["code"], "authentication_failed")

    def test_authenticated_metadata_reports_real_capabilities(self) -> None:
        status, _headers, raw = self.call(
            "GET",
            "/api/v1/metadata",
            headers={"Authorization": "Bearer stk_session_valid_secret"},
        )
        self.assertEqual(status, 200)
        body = self.decode(raw)
        self.assertIn("build_identity", body)
        self.assertEqual(body["supported_capabilities"]["available"], {})
        self.assertEqual(len(body["supported_capabilities"]["declared"]), 2)

    def test_bad_bearer_is_generic_and_does_not_echo_token(self) -> None:
        status, _headers, raw = self.call(
            "GET",
            "/api/v1/metadata",
            headers={"Authorization": "Bearer attacker-supplied-secret"},
        )
        self.assertEqual(status, 401)
        self.assertNotIn(b"attacker-supplied-secret", raw)
        self.assertNotIn(b"private credential detail", raw)

    def test_invalid_bearer_syntax_does_not_become_server_error(self) -> None:
        status, _headers, raw = self.call(
            "GET",
            "/api/v1/metadata",
            headers={"Authorization": "Basic abc"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(self.decode(raw)["error"]["code"], "authentication_failed")

    def test_request_id_is_validated_and_returned(self) -> None:
        status, headers, raw = self.call(
            "GET",
            "/api/v1/metadata",
            headers={"Authorization": "Bearer stk_session_valid_secret", "X-Request-ID": "req-safe-1234"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-request-id"], "req-safe-1234")
        bad_status, bad_headers, bad_raw = self.call(
            "GET",
            "/api/v1/metadata",
            headers={"X-Request-ID": "bad\r\nforged", "Authorization": "Bearer bad"},
        )
        self.assertEqual(bad_status, 401)
        self.assertRegex(bad_headers["x-request-id"], r"^[0-9a-f]{32}$")
        self.assertEqual(self.decode(bad_raw)["error"]["request_id"], bad_headers["x-request-id"])

    def test_unknown_path_returns_safe_404(self) -> None:
        status, _headers, raw = self.call("GET", "/api/v1/not-implemented")
        self.assertEqual(status, 404)
        self.assertEqual(self.decode(raw)["error"]["code"], "not_found")

    def test_wrong_method_returns_allow_header_and_request_id(self) -> None:
        status, headers, raw = self.call(
            "POST", "/api/v1/livez", headers={"X-Request-ID": "req-method-123"}
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers["allow"], "GET, HEAD")
        self.assertEqual(self.decode(raw)["error"]["request_id"], "req-method-123")

    def test_path_prefix_and_encoded_path_are_not_matched(self) -> None:
        for path in ("/api/v10/livez", "/api/v1/livez/extra", "/api/v1/%6civez"):
            status, _headers, _body = self.call("GET", path)
            self.assertEqual(status, 404)

    def test_invalid_unicode_path_is_rejected(self) -> None:
        status, _headers, raw = self.call("GET", "/api/v1/" + chr(0xDCFF))
        self.assertEqual(status, 400)
        self.assertEqual(self.decode(raw)["error"]["code"], "invalid_path")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        status, _headers, raw = self.call(
            "POST",
            "/api/v1/auth/login",
            raw_body=b'{"identifier":"a","identifier":"b","password":"p"}',
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.decode(raw)["error"]["code"], "invalid_json")

    def test_non_object_json_is_rejected(self) -> None:
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login", raw_body=b'["not", "an", "object"]'
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.decode(raw)["error"]["code"], "invalid_json_shape")

    def test_invalid_utf8_and_unpaired_surrogate_json_are_rejected(self) -> None:
        raw_bodies = (
            b'{"name":"' + bytes((0xFF,)) + b'"}',
            b'{"name":"' + bytes((0x5C,)) + b'ud800"}',
        )
        for raw_body in raw_bodies:
            with self.subTest(raw_body=raw_body):
                status, _headers, raw = self.call(
                    "POST", "/api/v1/auth/login", raw_body=raw_body
                )
                self.assertEqual(status, 400)
                self.assertEqual(self.decode(raw)["error"]["code"], "invalid_json")

    def test_non_finite_json_values_are_rejected(self) -> None:
        for raw_body in (b'{"identifier":NaN}', b'{"amount":1e999}'):
            with self.subTest(raw_body=raw_body):
                status, _headers, raw = self.call(
                    "POST", "/api/v1/auth/login", raw_body=raw_body
                )
                self.assertEqual(status, 400)
                self.assertEqual(self.decode(raw)["error"]["code"], "invalid_json")

    def test_invalid_content_length_values_are_safe_and_correlated(self) -> None:
        invalid_values: tuple[str | bytes, ...] = (
            "١",
            " 2 ",
            "+2",
            "2, 2",
            b"\xff",
        )
        for invalid_value in invalid_values:
            with self.subTest(content_length=invalid_value):
                environ = self.make_environ(
                    "POST",
                    "/api/v1/auth/login",
                    raw_body=b"{}",
                    headers={"X-Request-ID": "req-invalid-length"},
                    environ_overrides={"CONTENT_LENGTH": invalid_value},
                )
                status, response_headers, raw = self.invoke_wsgi(self.app, environ)
                self.assertEqual(status, 400)
                self.assertEqual(self.decode(raw)["error"]["code"], "invalid_content_length")
                self.assertEqual(response_headers["x-request-id"], "req-invalid-length")
                self.assertEqual(response_headers["x-content-type-options"], "nosniff")
                self.assertEqual(response_headers["x-frame-options"], "DENY")
                self.assertEqual(response_headers["referrer-policy"], "no-referrer")
                self.assertEqual(response_headers["cache-control"], "no-store")
                self.assertIn("content-security-policy", response_headers)
                self.assertIn("permissions-policy", response_headers)

    def test_content_length_environ_conflicts_are_rejected(self) -> None:
        for standard_value, http_value in (("2", "2"), ("2", "3"), ("", "2")):
            with self.subTest(content_length=standard_value, http_content_length=http_value):
                environ = self.make_environ(
                    "POST",
                    "/api/v1/auth/login",
                    raw_body=b"{}",
                    environ_overrides={
                        "CONTENT_LENGTH": standard_value,
                        "HTTP_CONTENT_LENGTH": http_value,
                    },
                )
                status, _headers, raw = self.invoke_wsgi(self.app, environ)
                self.assertEqual(status, 400)
                self.assertEqual(self.decode(raw)["error"]["code"], "ambiguous_content_length")

    def test_transfer_encoding_and_unknown_length_streams_are_rejected(self) -> None:
        transfer_environ = self.make_environ(
            "POST",
            "/api/v1/auth/login",
            environ_overrides={
                "CONTENT_LENGTH": "0",
                "HTTP_TRANSFER_ENCODING": "chunked",
            },
        )
        status, _headers, raw = self.invoke_wsgi(self.app, transfer_environ)
        self.assertEqual(status, 400)
        self.assertEqual(self.decode(raw)["error"]["code"], "invalid_transfer_encoding")

        terminated_environ = self.make_environ(
            "POST",
            "/api/v1/auth/login",
            environ_overrides={
                "CONTENT_LENGTH": "",
                "wsgi.input_terminated": True,
            },
        )
        status, _headers, raw = self.invoke_wsgi(self.app, terminated_environ)
        self.assertEqual(status, 400)
        self.assertEqual(self.decode(raw)["error"]["code"], "unsupported_body_framing")

    def test_malformed_query_escapes_are_rejected(self) -> None:
        for query in ("value=%ZZ", "value=%FF"):
            with self.subTest(query=query):
                status, _headers, raw = self.call("GET", "/api/v1/livez", query=query)
                self.assertEqual(status, 400)
                self.assertEqual(self.decode(raw)["error"]["code"], "invalid_query")

    def test_response_headers_cannot_override_safe_framing_or_inject_fields(self) -> None:
        response = HttpResponse(200, {"ok": True})
        response.headers = [
            ("Content-Type", "text/plain"),
            ("content-type", "text/html"),
            ("Content-Length", "1"),
            ("content-length", "999"),
            ("Transfer-Encoding", "chunked"),
            ("Connection", "close"),
            ("X-Injected", "safe" + chr(13) + chr(10) + "X-Evil: yes"),
            ("Bad Header", "invalid name"),
            ("X-Unicode", "snowman " + chr(0x2603)),
            ("X-Safe", "retained"),
        ]
        payload = b'{"ok":true}'
        headers = _safe_headers(response, "application/json; charset=utf-8", payload)
        lowered = {name.lower(): value for name, value in headers}
        self.assertEqual(lowered["content-type"], "application/json; charset=utf-8")
        self.assertEqual(lowered["content-length"], str(len(payload)))
        self.assertEqual(sum(name.lower() == "content-length" for name, _value in headers), 1)
        self.assertNotIn("transfer-encoding", lowered)
        self.assertNotIn("connection", lowered)
        self.assertNotIn("x-injected", lowered)
        self.assertNotIn("bad header", lowered)
        self.assertNotIn("x-unicode", lowered)
        self.assertEqual(lowered["x-safe"], "retained")

    def test_body_size_is_bounded_before_read(self) -> None:
        raw_body = b" " * 5000
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login", raw_body=raw_body
        )
        self.assertEqual(status, 413)
        self.assertEqual(self.decode(raw)["error"]["code"], "request_too_large")

    def test_content_type_is_required_for_json_body(self) -> None:
        environ: dict[str, Any] = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/v1/auth/login",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": "2",
            "CONTENT_TYPE": "text/plain",
            "REMOTE_ADDR": "127.0.0.1",
            "wsgi.url_scheme": "https",
            "wsgi.input": io.BytesIO(b"{}"),
        }
        captured: dict[str, Any] = {}

        def start_response(status: str, response_headers: list[tuple[str, str]], exc_info: Any = None) -> None:
            captured["status"] = int(status.split(" ", 1)[0])
            captured["headers"] = {name.lower(): value for name, value in response_headers}

        raw = b"".join(self.app(environ, start_response))
        self.assertEqual(captured["status"], 415)
        self.assertEqual(self.decode(raw)["error"]["code"], "unsupported_media_type")

    def test_get_request_body_is_rejected(self) -> None:
        status, _headers, raw = self.call("GET", "/api/v1/livez", body={"x": 1})
        self.assertEqual(status, 400)
        self.assertEqual(self.decode(raw)["error"]["code"], "unexpected_body")

    def test_query_field_count_is_bounded(self) -> None:
        query = "&".join(f"k{i}=v" for i in range(101))
        status, _headers, raw = self.call("GET", "/api/v1/livez", query=query)
        self.assertEqual(status, 400)
        self.assertEqual(self.decode(raw)["error"]["code"], "invalid_query")

    def test_head_has_no_body(self) -> None:
        status, headers, raw = self.call("HEAD", "/api/v1/livez")
        self.assertEqual(status, 200)
        self.assertEqual(raw, b"")
        self.assertGreater(int(headers["content-length"]), 0)

    def test_login_returns_scoped_one_time_session(self) -> None:
        status, headers, raw = self.call(
            "POST",
            "/api/v1/auth/login",
            body={"identifier": "analyst@example.test", "password": "correct-password"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        body = self.decode(raw)
        self.assertEqual(body["token_type"], "Bearer")
        self.assertEqual(body["access_token"], "stk_session_one_time_secret")
        self.assertEqual(body["principal"]["tenant_id"], "org-12345678")

    def test_login_never_reflects_password_or_identity_failure(self) -> None:
        status, _headers, raw = self.call(
            "POST",
            "/api/v1/auth/login",
            body={"identifier": "analyst@example.test", "password": "wrong-private-password"},
        )
        self.assertEqual(status, 401)
        self.assertNotIn(b"wrong-private-password", raw)
        self.assertNotIn(b"private failure detail", raw)

    def test_login_rejects_unknown_fields_and_invalid_types(self) -> None:
        status, _headers, raw = self.call(
            "POST",
            "/api/v1/auth/login",
            body={"identifier": "a", "password": "b", "tenant_id": "forged"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.decode(raw)["error"]["fields"][0]["code"], "unknown_field")
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login", body={"identifier": 8, "password": "x"}
        )
        self.assertEqual(status, 400)

    def test_session_route_returns_only_safe_identity_context(self) -> None:
        status, _headers, raw = self.call(
            "GET",
            "/api/v1/auth/session",
            headers={"Authorization": "Bearer stk_session_valid_secret"},
        )
        self.assertEqual(status, 200)
        body = self.decode(raw)
        self.assertEqual(body["data"]["principal"]["principal_id"], "user-12345678")
        self.assertNotIn("token", json.dumps(body).lower())

    def test_refresh_rotates_token_without_logging_it(self) -> None:
        status, _headers, raw = self.call(
            "POST",
            "/api/v1/auth/refresh",
            headers={"Authorization": "Bearer stk_session_valid_secret"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["access_token"], "stk_session_rotated_secret")
        self.assertEqual(self.identity.refresh_count, 1)

    def test_logout_revokes_only_a_user_session(self) -> None:
        status, _headers, raw = self.call(
            "POST",
            "/api/v1/auth/logout",
            headers={"Authorization": "Bearer stk_session_valid_secret"},
        )
        self.assertEqual(status, 204)
        self.assertEqual(raw, b"")
        self.assertEqual(self.identity.revoked, [("session-12345678", "api_logout")])
        status, _headers, raw = self.call(
            "POST",
            "/api/v1/auth/logout",
            headers={"Authorization": "Bearer stk_credential_valid_secret"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.decode(raw)["error"]["code"], "forbidden")

    def test_openapi_lists_registered_routes_only(self) -> None:
        status, _headers, raw = self.call(
            "GET",
            "/api/v1/openapi.json",
            headers={"Authorization": "Bearer stk_session_valid_secret"},
        )
        self.assertEqual(status, 200)
        document = self.decode(raw)
        self.assertEqual(document["openapi"], "3.1.0")
        self.assertIn("/api/v1/livez", document["paths"])
        self.assertIn("/api/v1/auth/login", document["paths"])
        self.assertNotIn("/api/v1/scans", document["paths"])
        self.assertEqual(
            document["paths"]["/api/v1/metadata"]["get"]["security"],
            [{"bearerAuth": []}],
        )

    def test_unexpected_handler_error_is_redacted(self) -> None:
        class BrokenHealth:
            def liveness(self) -> dict[str, Any]:
                raise RuntimeError("database password=do-not-disclose at /secret/path")

        broken_services = ApiServices(
            platform=self.services.platform,
            identity=self.identity,
            authorization=self.authorization,
            health=BrokenHealth(),
            capabilities=self.capabilities,
        )
        app = create_app(
            broken_services,
            require_tls=False,
            rate_limiter=SafeSlidingWindowLimiter(limit=100),
        )
        try:
            environ: dict[str, Any] = {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/livez",
                "QUERY_STRING": "",
                "CONTENT_LENGTH": "0",
                "REMOTE_ADDR": "127.0.0.1",
                "wsgi.url_scheme": "https",
                "wsgi.input": io.BytesIO(b""),
            }
            captured: dict[str, Any] = {}

            def start_response(status: str, response_headers: list[tuple[str, str]], exc_info: Any = None) -> None:
                captured["status"] = int(status.split(" ", 1)[0])

            raw = b"".join(app(environ, start_response))
            self.assertEqual(captured["status"], 500)
            self.assertNotIn(b"do-not-disclose", raw)
            self.assertNotIn(b"/secret/path", raw)
        finally:
            app.close()

    def test_lazy_startup_failure_is_redacted_and_hardened(self) -> None:
        def fail_factory() -> WSGIApplication:
            raise RuntimeError("database password=private-value at /secret/path")

        app = LazyApplication(factory=fail_factory)
        self.addCleanup(app.close)
        environ = self.make_environ(
            "GET",
            "/api/v1/livez",
            headers={"X-Request-ID": "req-startup-123"},
        )
        status, headers, raw = self.invoke_wsgi(app, environ)
        self.assertEqual(status, 503)
        self.assertEqual(headers["x-request-id"], "req-startup-123")
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertEqual(headers["referrer-policy"], "no-referrer")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertIn("content-security-policy", headers)
        self.assertIn("permissions-policy", headers)
        self.assertEqual(self.decode(raw)["error"]["code"], "service_unavailable")
        self.assertNotIn(b"private-value", raw)
        self.assertNotIn(b"/secret/path", raw)

    def test_close_releases_nested_database_resources_once(self) -> None:
        class CloseableDatabase:
            def __init__(self) -> None:
                self.close_count = 0

            def close(self) -> None:
                self.close_count += 1

        database = CloseableDatabase()
        services = ApiServices(
            platform=SimpleNamespace(db=database),
            identity=self.identity,
            authorization=self.authorization,
            health=self.health,
            capabilities=self.capabilities,
        )
        app = create_app(
            services,
            require_tls=False,
            rate_limiter=SafeSlidingWindowLimiter(limit=100),
        )
        self.addCleanup(app.close)
        app.close()
        app.close()
        self.assertEqual(database.close_count, 1)

    def test_close_is_idempotent_and_rejects_later_requests(self) -> None:
        self.app.close()
        self.app.close()
        environ = self.make_environ("GET", "/api/v1/livez")
        status, headers, raw = self.invoke_wsgi(self.app, environ)
        self.assertEqual(status, 503)
        self.assertEqual(self.decode(raw)["error"]["code"], "service_unavailable")
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertEqual(headers["referrer-policy"], "no-referrer")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertIn("content-security-policy", headers)
        self.assertIn("permissions-policy", headers)
        head_environ = self.make_environ("HEAD", "/api/v1/livez")
        head_status, head_headers, head_raw = self.invoke_wsgi(self.app, head_environ)
        self.assertEqual(head_status, 503)
        self.assertEqual(head_raw, b"")
        self.assertGreater(int(head_headers["content-length"]), 0)


if __name__ == "__main__":
    unittest.main()
