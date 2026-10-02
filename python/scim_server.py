#!/usr/bin/env python3
"""scim_server.py — SCIM 2.0 HTTP surface (Phase 8, spec §36).

A small stdlib-only HTTP front-end over the existing `ScimService` (the
service layer already owns all parsing/validation/audit/RBAC-capped logic;
this module ONLY maps HTTP <-> service calls). Properties:

  - tenant selection is ALWAYS the credential's org (the request can never
    name a tenant); Basic auth is validated per request.
  - discovery endpoints (ServiceProviderConfig / ResourceTypes / Schemas)
    are public per RFC 7643; everything else requires a valid credential.
  - responses use application/scim+json; errors use the SCIM error envelope.
  - bodies are bounded (1 MiB); unknown paths return 404; no internals in
    error messages; no secrets are ever logged.

Run via `main.py scim-server` (or programmatically with serve()).
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import errors


def _json_body(raw: bytes):
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise errors.ValidationError("Body is not valid JSON") from None


class ScimServer:
    """Binds a ScimService to an HTTP listener."""

    def __init__(self, service, *, host: str = "127.0.0.1", port: int = 8801,
                 threads: int = 8, quiet: bool = False):
        self.service = service
        self.host = str(host)
        self.port = int(port)
        self.threads = max(1, min(int(threads or 8), 64))
        self.quiet = bool(quiet)

    def serve(self) -> int:
        handler = self._handler()
        try:
            httpd = ThreadingHTTPServer((self.host, self.port), handler)
        except OSError as e:
            print(f"[!] Cannot bind {self.host}:{self.port}: {e}")
            return 7
        httpd.daemon_threads = True
        print(f"[✓] SCIM 2.0 listening on http://{self.host}:{self.port}"
              f"  (threads={self.threads})")
        print("    discovery: /scim/v2/ServiceProviderConfig "
              "| /scim/v2/ResourceTypes | /scim/v2/Schemas")
        print("    resources: /scim/v2/Users  /scim/v2/Groups "
              "(HTTP Basic: <key prefix>:<secret>)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[✓] SCIM server stopped")
        finally:
            httpd.server_close()
        return 0

    # ------------------------------------------------------------ dispatch
    @staticmethod
    def _param(path: str, name: str) -> str:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        return (q.get(name) or [""])[0]

    @staticmethod
    def _actor(remote: str) -> str:
        return f"scim:{str(remote)[:64]}"

    def _handle(self, method: str, full_path: str, auth_header: str,
                body: bytes, remote: str):
        svc = self.service
        path = urllib.parse.urlparse(full_path).path
        # ---- discovery (public, RFC 7643 §2) ------------------------------
        if method == "GET" and path.rstrip("/") in (
                "/scim/v2/ServiceProviderConfig",
                "/scim/v2/ResourceTypes", "/scim/v2/Schemas"):
            name = path.rstrip("/").rsplit("/", 1)[-1]
            res = {"ServiceProviderConfig": svc.service_provider_config(),
                   "ResourceTypes": svc.resource_types(),
                   "Schemas": svc.schemas()}[name]
            return 200, res

        # ---- everything else: authenticated --------------------------------
        cred = svc.authenticate(auth_header)
        org = cred["org_id"]

        parts = [p for p in path.split("/") if p]
        if (len(parts) not in (3, 4) or parts[0] != "scim"
                or parts[1] != "v2" or parts[2] not in ("Users", "Groups")):
            raise svc._error(404, "noTarget", "Unknown SCIM endpoint")
        kind, ident = parts[2], (parts[3] if len(parts) > 3 else "")
        max_role = cred["cred"].get("max_role", "analyst")
        actor = self._actor(remote)

        if kind == "Users":
            if not ident:
                if method == "GET":
                    return 200, svc.users_list(
                        org, filter=self._param(full_path, "filter"),
                        start_index=int(self._param(full_path, "startIndex")
                                        or 1),
                        count=int(self._param(full_path, "count") or 0))
                if method == "POST":
                    return 201, svc.user_create(org, _json_body(body),
                                                max_role=max_role,
                                                actor=actor)
                raise svc._error(405, "methodNotAllowed",
                                 "Method not allowed")
            if method == "GET":
                try:
                    return 200, svc.user_get(org, ident)
                except Exception as e:
                    # SCIM clients may address the resource by its
                    # externalId — resolve through the tenant mapping.
                    if (getattr(e, "status", None) not in (404, None)
                            and not isinstance(e, errors.NotFoundError)):
                        raise
                    try:
                        mapped = svc._user_map(org, ident)
                    except Exception:
                        mapped = None
                    if mapped:
                        return 200, svc.user_get(org, mapped["user_id"])
                    raise
            if method == "PUT":
                return 200, svc.user_replace(org, ident, _json_body(body),
                                             max_role=max_role, actor=actor)
            if method == "PATCH":
                return 200, svc.user_patch(org, ident, _json_body(body),
                                           actor=actor)
            if method == "DELETE":
                return 200, svc.user_delete(org, ident, actor=actor)
            raise svc._error(405, "methodNotAllowed", "Method not allowed")

        # ---- Groups ----------------------------------------------------------
        if not ident:
            if method == "GET":
                return 200, svc.groups_list(
                    org, filter=self._param(full_path, "filter"),
                    start_index=int(self._param(full_path, "startIndex") or 1),
                    count=int(self._param(full_path, "count") or 0))
            if method == "POST":
                return 201, svc.group_create(org, _json_body(body),
                                             max_role=max_role, actor=actor)
            raise svc._error(405, "methodNotAllowed", "Method not allowed")
        if method == "GET":
            return 200, svc.group_get(org, ident)
        if method == "PUT":
            return 200, svc.group_replace(org, ident, _json_body(body),
                                          max_role=max_role, actor=actor)
        if method == "PATCH":
            return 200, svc.group_patch(org, ident, _json_body(body),
                                        actor=actor)
        if method == "DELETE":
            return 200, svc.group_delete(org, ident, actor=actor)
        raise svc._error(405, "methodNotAllowed", "Method not allowed")

    def _handler(self):
        scim_server = self
        state = {"busy": 0}
        lock = threading.Lock()
        max_body = 1024 * 1024

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "SecuToolkit-SCIM/1.0"

            def log_message(self, fmt, *args):  # never log secrets
                if not scim_server.quiet:
                    print(f"[scim] {self.client_address[0]} {fmt % args}")

            def _send(self, status: int, payload: dict, *, extra=None):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(int(status))
                self.send_header("Content-Type", "application/scim+json")
                self.send_header("Content-Length", str(len(body)))
                if status == 401:
                    self.send_header("WWW-Authenticate",
                                     'Basic realm="scim"')
                for k, v in (extra or {}).items():
                    self.send_header(k, str(v))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _error(self, status: int, scim_type: str, detail: str):
                self._send(status, {
                    "schemas": [
                        "urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": str(status), "detail": detail[:300],
                    "scimType": scim_type})

            def _dispatch(self, method: str):
                with lock:
                    if state["busy"] >= scim_server.threads:
                        self._error(503, "slowDown", "Server busy")
                        return
                    state["busy"] += 1
                try:
                    raw = b""
                    try:
                        length = int(self.headers.get("Content-Length") or 0)
                    except (TypeError, ValueError):
                        length = 0
                    if length > max_body:
                        self._error(413, "tooMany", "Request body too large")
                        return
                    if length:
                        raw = self.rfile.read(length)
                    status, payload = scim_server._handle(
                        method, self.path,
                        self.headers.get("Authorization", ""), raw,
                        str(self.client_address[0]))
                    self._send(status, payload)
                except errors.RateLimitedError as e:
                    self._error(429, "slowDown", "Too many requests",
                                extra={"Retry-After": max(
                                    int(getattr(e, "retry_after", 1) or 1), 1)})
                except Exception as e:
                    scim_type = getattr(e, "scim_type", "")
                    if scim_type:
                        self._error(int(getattr(e, "status", 500) or 500),
                                    scim_type, str(e))
                    elif isinstance(e, errors.NotFoundError):
                        self._error(404, "notFound", "Resource not found")
                    elif isinstance(e, errors.ValidationError):
                        self._error(400, "invalidValue", str(e))
                    else:
                        # generic 500 — no internals, no stack traces
                        self._error(500, "internalServerError",
                                    "Internal error")
                finally:
                    with lock:
                        state["busy"] -= 1

            def do_GET(self):
                self._dispatch("GET")

            def do_POST(self):
                self._dispatch("POST")

            def do_PUT(self):
                self._dispatch("PUT")

            def do_PATCH(self):
                self._dispatch("PATCH")

            def do_DELETE(self):
                self._dispatch("DELETE")

            def do_HEAD(self):
                self._dispatch("GET")

        return Handler


def serve(service, **kwargs) -> int:
    """Run the SCIM HTTP surface (spawns listener, returns 0 on success)."""
    return ScimServer(service, **kwargs).serve()


if __name__ == "__main__":
    sys.path.insert(0, ".")
    sys.path.insert(0, "python")
    import identity as _id
    import platform_service as _pf
    import scim_service as _ss
    _p = _pf.PlatformService(None)
    _i = _id.IdentityService(_p)
    _s = _ss.ScimService(_p, identity_svc=_i)
    _rc = serve(_s, host="127.0.0.1",
                port=int(sys.argv[1]) if len(sys.argv) > 1 else 8801)
    sys.exit(_rc)
