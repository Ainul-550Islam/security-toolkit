#!/usr/bin/env python3
# ============================================================================
#  sso_service.py — Phase 8 enterprise SSO: provider-neutral OIDC + SAML,
#  domain discovery, JIT provisioning and group→RBAC mapping.
#  ---------------------------------------------------------------------------
#  Extends the EXISTING identity model: SSO logins produce the SAME users,
#  roles and sessions as password login. No second authentication system.
#
#  Security properties:
#    - Provider config: secret fields (OIDC client_secret) encrypted at rest
#      with the existing key-file wrap; never returned by any view path.
#    - OIDC: discovery + token/JWKS fetches go through the SSRF-safe
#      validator (HTTPS only, no redirects, bounded timeout/size, public
#      addresses only); ID tokens require crypto validation (signature,
#      issuer, audience, exp/nbf, nonce); state/nonce are single-use and
#      short-lived; PKCE S256 supported; alg confusion blocked (alg allowlist
#      and key-type separation).
#    - SAML: assertions require a valid XMLDSIG signature against the
#      CONFIGURED key (never the response's own certificate); XXE/DTD
#      rejected; audience/recipient/destination/issuer/temporal validation;
#      replay protection via assertion digest table.
#    - JIT: deterministic external-identity keys (provider, subject); no
#      cross-tenant link/creation; IdP cannot inject org ids or role names
#      (roles come from tenant-scoped mappings with allowlisted RBAC roles).
#    - Domain discovery: normalized, tenant-scoped, no existence leak.
# ============================================================================

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

import errors
import identity as identity_mod
import models
import notify
import pki
import rbac
import redact

PROVIDER_TYPES = ("oidc", "saml")
MAX_CONFIG_BYTES = 8192
MAX_DOMAIN_LEN = 253
STATE_TTL_SECONDS = 300
JWKS_CACHE_SECONDS = 300
FETCH_TIMEOUT = 6
FETCH_MAX_BYTES = 262144
_ALGS_RSA = ("RS256", "RS384", "RS512")
_SECRET_FIELDS = ("client_secret",)
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]"
                        r"([a-z0-9-]{0,61}[a-z0-9])?)+$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,253}$")
_MAX_GROUPS = 50


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _epoch() -> float:
    return time.time()


def _parse_ts(ts: str) -> float:
    try:
        return time.mktime(time.strptime(str(ts)[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def _iso_from_epoch(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


# ---------------------------------------------------------------------------
# SSRF-safe outbound fetch (reuses the Phase-5 validator — no second SSRF
# implementation)
# ---------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused",
                                     headers, fp)


def safe_https_fetch(url: str, *, method: str = "GET", body: bytes = b"",
                     headers: dict | None = None) -> dict:
    """Bounded HTTPS GET/POST to a PUBLIC endpoint only. Raise ValidationError
    on protocol/SSRF violations; raise NetworkError on transport failures;
    enforce timeout + response size + redirect refusal."""
    notify.validate_webhook_url(url)           # same rules as Phase-5 webhooks
    hdrs = {"User-Agent": "SecuToolkit-SSO/1.0",
            "Accept": "application/json, application/xml, text/plain"}
    hdrs.update({k: str(v) for k, v in (headers or {}).items()})
    req = urllib.request.Request(url, data=body if method == "POST" else None,
                                 headers=hdrs, method=method.upper())
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=FETCH_TIMEOUT) as resp:
            status = int(resp.status)
            if status >= 300:
                raise errors.NetworkError(f"http {status}")
            data = resp.read(FETCH_MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise errors.NetworkError(f"http {int(e.code)}") from None
    except (urllib.error.URLError, socket.timeout, TimeoutError,
            ConnectionError, OSError) as e:
        raise errors.NetworkError(f"fetch failed: {e}") from None
    if len(data) > FETCH_MAX_BYTES:
        raise errors.NetworkError("response exceeds size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise errors.NetworkError("response is not UTF-8") from None
    return {"status": status, "body": text}


def _b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(str(value) + "=" * (-len(value) % 4))


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sha256_b64u(text: str) -> str:
    return _b64u_encode(hashlib.sha256(text.encode("utf-8")).digest())


def normalize_domain(domain: str) -> str:
    d = str(domain or "").strip().lower().rstrip(".")
    if not d or len(d) > MAX_DOMAIN_LEN:
        raise errors.ValidationError("domain_invalid: out of bounds")
    if not _DOMAIN_RE.match(d):
        raise errors.ValidationError("domain_invalid: malformed domain")
    return d


def normalize_email(email: str) -> str:
    e = str(email or "").strip().lower()
    if not e or len(e) > 254 or not _EMAIL_RE.match(e):
        raise errors.ValidationError("email_invalid")
    return e


def normalize_issuer(value: str) -> str:
    raw = str(value or "").strip()
    if len(raw) > 512:
        raise errors.ValidationError("issuer_invalid: too long")
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme != "https":
        raise errors.ValidationError("issuer_invalid: https required")
    if parts.username or parts.password:
        raise errors.ValidationError("issuer_invalid: userinfo forbidden")
    if parts.fragment:
        raise errors.ValidationError("issuer_invalid: fragment forbidden")
    if not (parts.hostname or ""):
        raise errors.ValidationError("issuer_invalid: empty host")
    return raw.rstrip("/")


class SsoService:
    """SSO providers, domains, mappings, OIDC + SAML flows, JIT provisioning.
    Provider-neutral: NO Okta/Azure/Auth0/Google-specific logic anywhere."""

    def __init__(self, platform, *, identity_svc=None):
        self.svc = platform
        self.db = platform.db
        self.identity = identity_svc or identity_mod.IdentityService(platform)
        self.limiter = self.identity.limiter
        self._jwks_cache: dict[str, tuple[float, dict]] = {}
        self._discovery_cache: dict[str, tuple[float, dict]] = {}

    # ------------------------------------------------------------ helpers
    def _throttle(self, kind: str, key: str) -> None:
        limit, window = identity_mod.RL_LIMITS.get(kind, (60, 60))
        ok, retry = self.limiter.allowed(f"identity:{kind}:{key}", limit,
                                         window)
        if not ok:
            raise errors.RateLimitedError("Too many attempts",
                                          retry_after=retry)

    def _audit(self, action: str, *, object_type: str, object_id: str,
               org_id: str = "", actor: str = "identity",
               metadata: dict | None = None):
        try:
            self.svc.audit(action, object_type=object_type,
                           object_id=object_id, org_id=org_id,
                           actor=str(actor)[:128],
                           metadata=redact.redact(dict(metadata or {})))
        except Exception:
            pass

    def _event(self, org_id: str, event_type: str, *, actor="",
               detail: dict | None = None):
        """Operational identity telemetry (complementary; the immutable
        audit log remains authoritative — failures only bump a metric)."""
        import metrics
        try:
            self.db.execute(
                "INSERT INTO identity_events (id, org_id, actor, event_type,"
                " detail, ts) VALUES (?,?,?,?,?,?)",
                (models.stable_id(models.NS_IEVENT,
                                  f"{org_id}|{event_type}|{_now()}|"
                                  f"{secrets.token_hex(8)}"),
                 org_id, str(actor)[:128], str(event_type)[:64],
                 json.dumps(redact.redact(dict(detail or {}))), _now()))
        except Exception:
            metrics.inc("identity_telemetry_failures")

    def _provider_row(self, provider_id: str) -> dict:
        row = self.db.query_one("SELECT * FROM sso_providers WHERE id=? "
                                "LIMIT 1", (provider_id,))
        if not row:
            raise errors.NotFoundError("no such provider")
        row["config"] = json.loads(row["config"] or "{}")
        row["default_roles"] = json.loads(row["default_roles"] or "[]")
        return row

    # --------------------------------------------------------- providers
    def _validate_config(self, ptype: str, cfg: dict) -> dict:
        if not isinstance(cfg, dict):
            raise errors.ValidationError("provider_invalid: config must be "
                                         "an object")
        allowed = {
            "oidc": {"issuer", "authorization_endpoint", "token_endpoint",
                     "jwks_uri", "client_id", "client_secret",
                     "redirect_uri", "scope", "pkce"},
            "saml": {"issuer", "sso_url", "acs_url", "cert_pem",
                     "audience", "client_secret"},
        }
        extra = set(cfg.keys()) - allowed[ptype]
        if extra:
            raise errors.ValidationError(
                f"provider_invalid: unknown config field(s) {sorted(extra)}")
        out = {}
        if ptype == "oidc":
            out["issuer"] = normalize_issuer(cfg.get("issuer", ""))
            for key, label in (("authorization_endpoint", "authn_url"),
                               ("token_endpoint", "token_url"),
                               ("jwks_uri", "jwks_url")):
                v = str(cfg.get(key) or "").strip()
                if v:
                    if len(v) > 512:
                        raise errors.ValidationError(f"{label}_invalid")
                    notify.validate_webhook_url(v, resolve=False)
                out[key] = v
            client_id = str(cfg.get("client_id") or "").strip()
            if not client_id or len(client_id) > 256:
                raise errors.ValidationError(
                    "provider_invalid: client_id required")
            out["client_id"] = client_id
            out["redirect_uri"] = str(cfg.get("redirect_uri") or "")[:512]
            out["scope"] = str(cfg.get("scope") or "openid email profile")[:256]
            out["pkce"] = bool(cfg.get("pkce", False))
            secret = str(cfg.get("client_secret") or "")
            out["client_secret_enc"] = notify._encrypt_secret(
                secret, self.svc.db_path) if secret else ""
        else:
            issuer = str(cfg.get("issuer") or "").strip()
            if not issuer or len(issuer) > 512:
                raise errors.ValidationError(
                    "provider_invalid: saml issuer required")
            out["issuer"] = issuer
            sso_url = str(cfg.get("sso_url") or "").strip()
            if not sso_url or len(sso_url) > 512:
                raise errors.ValidationError(
                    "provider_invalid: sso_url required")
            notify.validate_webhook_url(sso_url, resolve=False)
            out["sso_url"] = sso_url
            out["acs_url"] = str(cfg.get("acs_url") or "")[:512]
            cert = str(cfg.get("cert_pem") or "")
            if not cert or "BEGIN CERTIFICATE" not in cert:
                raise errors.ValidationError(
                    "provider_invalid: signing certificate required")
            try:
                cert_info = pki.parse_x509_cert_pem(cert)
            except errors.ValidationError:
                raise errors.ValidationError(
                    "provider_invalid: certificate unreadable") from None
            out["cert_pem"] = cert
            out["cert_subject"] = redact.redact_text(
                str(cert_info.get("subject", ""))[:128])
            out["audience"] = str(cfg.get("audience") or "")[:512]
        raw = json.dumps(out, sort_keys=True)
        if len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise errors.ValidationError("provider_invalid: config exceeds "
                                         "size limit")
        return out

    def _provider_view(self, row: dict) -> dict:
        """Redacted provider view — secrets NEVER leave through this path."""
        cfg = dict(row.get("config") or {})
        for k in list(cfg.keys()):
            if k in _SECRET_FIELDS or k.endswith("_enc") or k == "cert_pem":
                cfg[k] = redact.REDACTED
            elif isinstance(cfg[k], str):
                cfg[k] = redact.redact_text(cfg[k])
        return {"id": row["id"], "org_id": row["org_id"],
                "provider_type": row["provider_type"],
                "enabled": bool(row["enabled"]),
                "display_name": row["display_name"],
                "config": cfg, "version": int(row["version"]),
                "jit": bool(row["jit"]),
                "default_roles": list(row.get("default_roles") or []),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "created_by": row["created_by"]}

    def provider_create(self, org_id: str, provider_type: str, *,
                        display_name: str, enabled: bool = False,
                        config: dict | None = None, jit: bool = False,
                        default_roles=(), actor: str = "identity") -> dict:
        self.svc.org_require(org_id)
        if provider_type not in PROVIDER_TYPES:
            raise errors.ValidationError(
                f"provider_type_unknown: {provider_type!r}")
        name = str(display_name or "").strip()
        if not name or len(name) > 96:
            raise errors.ValidationError("provider_invalid: display_name "
                                         "1-96 chars")
        cfg = self._validate_config(provider_type, config or {})
        roles = self._validate_roles(default_roles)
        provider_id = models.stable_id(
            models.NS_SSOPROV, f"{org_id}|{provider_type}|{name.lower()}")
        now = _now()
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO sso_providers (id, org_id, provider_type, "
                "enabled, display_name, config, version, jit, default_roles, "
                "created_at, updated_at, created_by) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?)",
                (provider_id, org_id, provider_type, 1 if enabled else 0,
                 name, json.dumps(cfg), 1, 1 if jit else 0,
                 json.dumps(list(roles)), now, now, str(actor)[:128]))
            self._provider_history(conn, provider_id, org_id, 1, "created",
                                   {}, actor)
        self._audit("identity.sso.created", object_type="sso_provider",
                    object_id=provider_id, org_id=org_id, actor=actor,
                    metadata={"provider_type": provider_type,
                              "display_name": name[:64]})
        self._event(org_id, "sso.provider_created", actor=actor,
                    detail={"provider_id": provider_id})
        return self._provider_view(self._provider_row(provider_id))

    def _provider_history(self, conn, provider_id: str, org_id: str,
                          version: int, change_type: str, diff: dict,
                          actor: str) -> None:
        conn.execute(
            "INSERT INTO sso_provider_history (id, provider_id, org_id, "
            "version, change_type, diff, changed_by, changed_at) VALUES "
            "(?,?,?,?,?,?,?,?)",
            (models.stable_id(models.NS_SSOHIST,
                              f"{provider_id}|{version}|{change_type}"),
             provider_id, org_id, int(version), str(change_type)[:64],
             json.dumps(redact.redact(diff)), str(actor)[:128], _now()))

    def _validate_roles(self, roles) -> tuple:
        out = []
        for r in (roles or ())[:8]:
            out.append(rbac.validate_role(r))
        return tuple(dict.fromkeys(out))

    def provider_list(self, org_id: str, *, limit: int = 100,
                      offset: int = 0) -> dict:
        self.svc.org_require(org_id)
        limit = max(1, min(500, int(limit)))
        offset = max(0, min(100000, int(offset)))
        rows = self.db.query(
            "SELECT * FROM sso_providers WHERE org_id=? ORDER BY created_at "
            "LIMIT ? OFFSET ?", (org_id, limit, offset))
        total = int(self.db.query_one(
            "SELECT COUNT(*) n FROM sso_providers WHERE org_id=?",
            (org_id,))["n"])
        views = []
        for r in rows:
            r = dict(r)
            r["config"] = json.loads(r.get("config") or "{}")
            r["default_roles"] = json.loads(r.get("default_roles") or "[]")
            views.append(self._provider_view(r))
        return {"count": len(rows), "total": total, "limit": limit,
                "offset": offset, "providers": views}

    def provider_get(self, provider_id: str) -> dict:
        return self._provider_view(self._provider_row(provider_id))

    def provider_update(self, provider_id: str, *, display_name: str = "",
                        enabled: bool | None = None, config: dict | None = None,
                        jit: bool | None = None, default_roles=None,
                        version: int = 0, actor: str = "identity") -> dict:
        row = self._provider_row(provider_id)
        if int(version) != 0 and int(version) != int(row["version"]):
            raise errors.ValidationError(
                "provider_conflict: version mismatch (concurrent update)")
        old = dict(row["config"])
        diff = {}
        if display_name:
            name = str(display_name).strip()
            if not name or len(name) > 96:
                raise errors.ValidationError("provider_invalid: display_name")
            diff["display_name"] = [row["display_name"], name[:96]]
            row["display_name"] = name
        if enabled is not None:
            diff["enabled"] = [bool(row["enabled"]), bool(enabled)]
            row["enabled"] = 1 if enabled else 0
        if config is not None:
            new_cfg = self._validate_config(row["provider_type"], config)
            for k in sorted(set(new_cfg) | set(old)):
                if new_cfg.get(k) != old.get(k):
                    if k.endswith("_enc") or k in _SECRET_FIELDS:
                        diff[k] = [redact.REDACTED, redact.REDACTED]
                    else:
                        diff[k] = [str(old.get(k, ""))[:200],
                                   str(new_cfg.get(k, ""))[:200]]
            row["config"] = new_cfg
        if jit is not None:
            diff["jit"] = [bool(row["jit"]), bool(jit)]
            row["jit"] = 1 if jit else 0
        if default_roles is not None:
            roles = self._validate_roles(default_roles)
            diff["default_roles"] = [list(row["default_roles"]),
                                     list(roles)]
            row["default_roles"] = roles
        row["version"] = int(row["version"]) + 1
        row["updated_at"] = _now()
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE sso_providers SET enabled=?, display_name=?, config=?,"
                " version=?, jit=?, default_roles=?, updated_at=? WHERE id=?",
                (row["enabled"], row["display_name"], json.dumps(row["config"]),
                 row["version"], row["jit"], json.dumps(list(row["default_roles"])),
                 row["updated_at"], provider_id))
            self._provider_history(conn, provider_id, row["org_id"],
                                   row["version"], "updated", diff, actor)
        self._audit("identity.sso.updated", object_type="sso_provider",
                    object_id=provider_id, org_id=row["org_id"], actor=actor,
                    metadata={"version": row["version"],
                              "changed": sorted(diff.keys())})
        self._event(row["org_id"], "sso.provider_updated", actor=actor,
                    detail={"provider_id": provider_id})
        return self._provider_view(self._provider_row(provider_id))

    def provider_delete(self, provider_id: str, *, actor: str = "identity") -> dict:
        row = self._provider_row(provider_id)
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM sso_providers WHERE id=?",
                         (provider_id,))
            conn.execute("DELETE FROM sso_identities WHERE provider_id=?",
                         (provider_id,))
            conn.execute(
                "UPDATE sso_domains SET provider_id='' WHERE provider_id=?",
                (provider_id,))
            self._provider_history(conn, provider_id, row["org_id"],
                                   int(row["version"]), "deleted", {}, actor)
        self._audit("identity.sso.deleted", object_type="sso_provider",
                    object_id=provider_id, org_id=row["org_id"], actor=actor,
                    metadata={"provider_type": row["provider_type"]})
        self._event(row["org_id"], "sso.provider_deleted", actor=actor,
                    detail={"provider_id": provider_id})
        return {"deleted": provider_id}

    # ------------------------------------------------------------ domains
    def domain_add(self, org_id: str, provider_id: str, domain: str, *,
                   actor: str = "identity") -> dict:
        self.svc.org_require(org_id)
        provider = self._provider_row(provider_id)
        if provider["org_id"] != org_id:
            raise errors.NotFoundError("no such provider")
        d = normalize_domain(domain)
        dom_id = models.stable_id(models.NS_SSODOM, f"{org_id}|{d}")
        inserted = self.db.execute_affected(
            "INSERT OR IGNORE INTO sso_domains (id, org_id, provider_id, "
            "domain, created_at, created_by) VALUES (?,?,?,?,?,?)",
            (dom_id, org_id, provider_id, d, _now(), str(actor)[:128]))
        if inserted == 0:
            owner_rows = self.db.query(
                "SELECT org_id FROM sso_domains WHERE domain=? LIMIT 1", (d,))
            owner = owner_rows[0] if owner_rows else None
            if not owner or owner["org_id"] != org_id:
                # generic error: no cross-tenant existence or ownership leak
                raise errors.ValidationError("domain_unavailable")
            return {"id": owner.get("id") or dom_id, "org_id": org_id,
                    "provider_id": provider_id, "domain": d}
        self._audit("identity.sso.domain_added", object_type="sso_provider",
                    object_id=provider_id, org_id=org_id, actor=actor,
                    metadata={"domain": d})
        self._event(org_id, "sso.domain_added", actor=actor,
                    detail={"domain": d})
        return {"id": dom_id, "org_id": org_id, "provider_id": provider_id,
                "domain": d}

    def domain_list(self, org_id: str, *, limit: int = 200) -> list:
        self.svc.org_require(org_id)
        rows = self.db.query(
            "SELECT id, org_id, provider_id, domain, created_at FROM "
            "sso_domains WHERE org_id=? ORDER BY domain LIMIT ?",
            (org_id, max(1, min(1000, int(limit)))))
        return [dict(r) for r in rows]

    def domain_remove(self, org_id: str, domain: str, *,
                      actor: str = "identity") -> dict:
        self.svc.org_require(org_id)
        d = normalize_domain(domain)
        row = self.db.query_one(
            "SELECT id, provider_id FROM sso_domains WHERE org_id=? AND "
            "domain=? LIMIT 1", (org_id, d))
        if not row:
            raise errors.NotFoundError("no such domain")
        self.db.execute("DELETE FROM sso_domains WHERE id=?", (row["id"],))
        self._audit("identity.sso.domain_removed", object_type="sso_provider",
                    object_id=row["provider_id"], org_id=org_id, actor=actor,
                    metadata={"domain": d})
        return {"removed": d}

    def resolve_domain(self, email: str) -> dict:
        """Domain → provider discovery. Raises the SAME generic error for
        unknown domain, unassigned domain, disabled provider, and
        cross-tenant domains (no existence leak)."""
        e = normalize_email(email)
        domain = e.rsplit("@", 1)[1]
        rows = self.db.query(
            "SELECT d.provider_id, d.org_id, p.provider_type, p.enabled FROM "
            "sso_domains d JOIN sso_providers p ON p.id=d.provider_id WHERE "
            "d.domain=? LIMIT 1", (domain,))
        if not rows:
            raise errors.NotFoundError("no provider for this domain")
        row = rows[0]
        if not row["enabled"]:
            raise errors.NotFoundError("no provider for this domain")
        return {"domain": domain, "provider_id": row["provider_id"],
                "org_id": row["org_id"],
                "provider_type": row["provider_type"]}

    # ---------------------------------------------------------- mappings
    def mapping_list(self, org_id: str, *, provider_id: str = "") -> list:
        self.svc.org_require(org_id)
        if provider_id:
            p = self._provider_row(provider_id)
            if p["org_id"] != org_id:
                raise errors.NotFoundError("no such provider")
        where = "org_id=?"
        params: list = [org_id]
        if provider_id:
            where += " AND provider_id=?"
            params.append(provider_id)
        rows = self.db.query(
            "SELECT id, org_id, provider_id, idp_group, role, created_at, "
            "updated_at, created_by FROM group_role_mappings WHERE " + where +
            " ORDER BY idp_group LIMIT 500", tuple(params))
        return [dict(r) for r in rows]

    def mapping_set(self, org_id: str, idp_group: str, role: str, *,
                    provider_id: str = "", actor: str = "identity") -> dict:
        """Map an IdP group to an EXISTING RBAC role (tenant scoped;
        unknown roles fail closed; mappings are audited)."""
        self.svc.org_require(org_id)
        group = str(idp_group or "").strip()
        if not group or len(group) > 200 or any(ord(c) < 32 for c in group):
            raise errors.ValidationError("mapping_invalid: group name")
        if provider_id:
            p = self._provider_row(provider_id)
            if p["org_id"] != org_id:
                raise errors.NotFoundError("no such provider")
        role = rbac.validate_role(role)
        mid = models.stable_id(models.NS_GRM, f"{org_id}|{provider_id}|{group}")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO group_role_mappings (id, org_id, provider_id, "
                "idp_group, role, created_at, updated_at, created_by) VALUES "
                "(?,?,?,?,?,?,?,?) ON CONFLICT(org_id, provider_id, idp_group)"
                " DO UPDATE SET role=excluded.role, updated_at=excluded."
                "updated_at, created_by=excluded.created_by",
                (mid, org_id, provider_id, group, role, _now(), _now(),
                 str(actor)[:128]))
        self._audit("identity.sso.mapping_updated", object_type="organization",
                    object_id=org_id, org_id=org_id, actor=actor,
                    metadata={"idp_group": group[:64], "role": role})
        self._event(org_id, "sso.mapping_updated", actor=actor,
                    detail={"idp_group": group[:64], "role": role})
        return {"id": mid, "org_id": org_id, "provider_id": provider_id,
                "idp_group": group, "role": role}

    def mapping_remove(self, org_id: str, idp_group: str, *,
                       provider_id: str = "", actor: str = "identity") -> dict:
        self.svc.org_require(org_id)
        group = str(idp_group or "").strip()
        row = self.db.query_one(
            "SELECT id FROM group_role_mappings WHERE org_id=? AND "
            "idp_group=? AND provider_id=? LIMIT 1",
            (org_id, group, provider_id))
        if not row:
            raise errors.NotFoundError("no such mapping")
        self.db.execute("DELETE FROM group_role_mappings WHERE id=?",
                        (row["id"],))
        self._audit("identity.sso.mapping_updated", object_type="organization",
                    object_id=org_id, org_id=org_id, actor=actor,
                    metadata={"idp_group": group[:64], "removed": True})
        return {"removed": group}

    def _map_roles(self, provider: dict, groups) -> tuple:
        """IdP groups → existing RBAC roles. Unknown groups are skipped
        (explicit safe default); every mapped role is validated."""
        groups = [str(g)[:200] for g in (groups or [])[:_MAX_GROUPS]]
        if not groups:
            return tuple(provider.get("default_roles") or ())
        placeholders = ",".join("?" for _ in groups)
        # org-wide mappings (provider_id='') apply to EVERY provider of the
        # tenant; provider-specific mappings apply to that provider only.
        rows = self.db.query(
            "SELECT idp_group, role FROM group_role_mappings WHERE org_id=? "
            "AND (provider_id=? OR provider_id='') AND idp_group IN ("
            + placeholders + ")",
            (provider["org_id"], provider["id"], *groups))
        roles = [r["role"] for r in rows]
        for r in roles:
            rbac.validate_role(r)
        return tuple(dict.fromkeys(roles)) or \
            tuple(provider.get("default_roles") or ())

    # --------------------------------------------------------------- OIDC
    def oidc_discover(self, provider_id: str) -> dict:
        """Get discovery metadata for an OIDC provider (cached; SSRF-safe).
        Provider must be OIDC and enabled; issuer is validated against the
        configured issuer before any metadata is trusted."""
        provider = self._provider_row(provider_id)
        if provider["provider_type"] != "oidc":
            raise errors.ValidationError("provider_not_oidc")
        if not provider["enabled"]:
            raise errors.NotFoundError("provider disabled")
        cfg = provider["config"]
        issuers = {cfg.get("issuer", "").rstrip("/")}
        cached = self._discovery_cache.get(provider_id)
        if cached and _epoch() - cached[0] < 300:
            meta = cached[1]
        else:
            url = cfg["issuer"].rstrip("/") + "/.well-known/openid-configuration"
            meta = json.loads(safe_https_fetch(url)["body"])
            disc_issuer = str(meta.get("issuer") or "").rstrip("/")
            if disc_issuer not in issuers:
                raise errors.ValidationError(
                    "oidc_invalid: discovery issuer mismatch")
            if len(json.dumps(meta)) > FETCH_MAX_BYTES:
                raise errors.ValidationError("oidc_invalid: metadata too big")
            self._discovery_cache[provider_id] = (_epoch(), meta)
        return meta

    def oidc_start(self, provider_id: str, *, redirect_uri: str = "",
                   state: str = "", nonce: str = "",
                   login_hint: str = "") -> dict:
        """SP-side authorization request: single-use state + nonce (and an
        optional PKCE challenge) are persisted and returned."""
        self._throttle("sso_start", provider_id)
        provider = self._provider_row(provider_id)
        if provider["provider_type"] != "oidc" or not provider["enabled"]:
            raise errors.NotFoundError("no such provider")
        cfg = provider["config"]
        authn_url = cfg.get("authorization_endpoint") or ""
        if not authn_url and provider["config"].get("issuer"):
            try:
                meta = self.oidc_discover(provider_id)
                authn_url = str(meta.get("authorization_endpoint") or "")
                if authn_url:
                    notify.validate_webhook_url(authn_url, resolve=False)
            except Exception:
                authn_url = ""
        if not authn_url:
            raise errors.ValidationError(
                "provider_invalid: authorization endpoint unavailable")
        cfg_redirect = str(cfg.get("redirect_uri") or "")
        effective_redirect = str(redirect_uri or "") or cfg_redirect
        if cfg_redirect and effective_redirect != cfg_redirect:
            raise errors.ValidationError(
                "provider_invalid: redirect_uri mismatch with provider "
                "config (fail-closed)")
        state = str(state or "") or secrets.token_urlsafe(24)
        nonce = str(nonce or "") or secrets.token_urlsafe(24)
        code_verifier = ""
        code_challenge = ""
        code_method = ""
        if cfg.get("pkce"):
            from hashlib import sha256
            code_verifier = secrets.token_urlsafe(48)
            code_challenge = _sha256_b64u(code_verifier)
            code_method = "S256"
        now = _now()
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM idp_state WHERE expires_at<?", (now,))
            conn.execute(
                "INSERT INTO idp_state (state, provider_id, org_id, nonce, "
                "code_challenge, code_method, redirect_uri, created_at, "
                "expires_at, used_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (state, provider_id, provider["org_id"], nonce,
                 code_challenge, code_method,
                 str(effective_redirect)[:512],
                 now, _iso_from_epoch(_epoch() + STATE_TTL_SECONDS), ""))
        params = {
            "response_type": "code",
            "client_id": cfg["client_id"],
            "redirect_uri": effective_redirect,
            "scope": cfg.get("scope") or "openid email profile",
            "state": state,
            "nonce": nonce,
        }
        if login_hint:
            params["login_hint"] = str(login_hint)[:254]
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_method
        url = authn_url + ("&" if "?" in authn_url else "?") + \
            urllib.parse.urlencode(params)
        return {"authorization_url": url, "state": state, "nonce": nonce,
                "code_verifier": code_verifier}

    def _consume_state(self, state: str, provider_id: str) -> dict:
        if not state or len(state) > 256:
            raise errors.ValidationError("oidc_invalid: missing state")
        rows = self.db.query("SELECT * FROM idp_state WHERE state=? "
                             "LIMIT 1", (state,))
        row = rows[0] if rows else None
        if not row:
            raise errors.ValidationError("oidc_invalid: unknown state")
        if row["provider_id"] != provider_id:
            raise errors.ValidationError("oidc_invalid: state provider "
                                         "mismatch")
        if row["used_at"]:
            raise errors.ValidationError("oidc_invalid: state already used")
        if _parse_ts(row["expires_at"]) < _epoch():
            raise errors.ValidationError("oidc_invalid: state expired")
        claimed = self.db.execute_affected(
            "UPDATE idp_state SET used_at=? WHERE state=? AND used_at=''",
            (_now(), state))
        if claimed != 1:
            raise errors.ValidationError("oidc_invalid: state already used")
        return dict(row)

    def oidc_callback(self, provider_id: str, *, state: str, code: str = "",
                      id_token: str = "", access_token: str = "",
                      code_verifier: str = "", redirect_uri: str = "",
                      ip: str = "", actor: str = "sso") -> dict:
        """Authorization-code callback: consume the single-use state, obtain
        the ID token (token exchange OR the explicit `id_token` test/deployed
        path), then FULLY validate it (signature, issuer, audience, exp/nbf,
        nonce) before any identity mapping. Fail closed at every step."""
        self._throttle("sso_callback", provider_id)
        provider = self._provider_row(provider_id)
        if provider["provider_type"] != "oidc" or not provider["enabled"]:
            raise errors.NotFoundError("no such provider")
        # Fail-closed redirect binding: a callback that advertises a
        # redirect_uri must match the one recorded at start time (never
        # trusts an unbound value). Check before consuming state so a
        # mismatch probe cannot burn a legitimate session either.
        if str(redirect_uri or ""):
            rows = self.db.query(
                "SELECT redirect_uri FROM idp_state WHERE state=? AND "
                "provider_id=? LIMIT 1", (str(state), provider_id))
            if not rows:
                raise errors.ValidationError("oidc_invalid: unknown state")
            stored = str(rows[0]["redirect_uri"] or "")
            if not stored or str(redirect_uri) != stored:
                raise errors.ValidationError(
                    "oidc_invalid: redirect_uri mismatch (fail-closed)")
        st = self._consume_state(state, provider_id)
        cfg = provider["config"]
        if not id_token:
            if not code:
                raise errors.ValidationError("oidc_invalid: missing code")
            token_endpoint = cfg.get("token_endpoint") or ""
            if not token_endpoint:
                meta = self.oidc_discover(provider_id)
                token_endpoint = str(meta.get("token_endpoint") or "")
            form = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": st.get("redirect_uri") or "",
                "client_id": cfg["client_id"],
            }
            if st.get("code_challenge") and code_verifier:
                form["code_verifier"] = code_verifier
            secret = notify._decrypt_secret(
                str(cfg.get("client_secret_enc") or ""), self.svc.db_path)
            headers = {}
            body = urllib.parse.urlencode(form).encode("utf-8")
            if secret:
                headers["Authorization"] = "Basic " + _b64u_encode(
                    f"{cfg['client_id']}:{secret}".encode("utf-8"))
            resp = json.loads(safe_https_fetch(
                token_endpoint, method="POST", body=body,
                headers=headers)["body"])
            id_token = str(resp.get("id_token") or "")
            if not id_token:
                raise errors.ValidationError("oidc_invalid: no id_token in "
                                             "token response")
        claims = self.oidc_validate_id_token(provider, id_token,
                                             nonce=str(st.get("nonce") or ""),
                                             client_id=cfg["client_id"])
        return self._sso_login(provider, {
            "subject": str(claims.get("sub") or ""),
            "email": str(claims.get("email") or ""),
            "name": str(claims.get("name") or ""),
            "groups": list(claims.get("groups") or []),
        }, ip=ip, actor=actor, method="oidc")

    def oidc_validate_id_token(self, provider: dict, token: str, *,
                               nonce: str = "", client_id: str = "",
                               now: float | None = None) -> dict:
        """Full ID-token validation. Rejects unsigned/altered tokens, alg
        confusion (HS256 only allowed with a configured symmetric secret),
        wrong issuer/audience/expiry/nonce — any failure raises."""
        parts = str(token or "").split(".")
        if len(parts) != 3:
            raise errors.ValidationError("oidc_invalid: not a JWT")
        try:
            header = json.loads(_b64u_decode(parts[0]).decode("utf-8"))
            payload = json.loads(_b64u_decode(parts[1]).decode("utf-8"))
        except Exception:
            raise errors.ValidationError("oidc_invalid: malformed JWT") from None
        alg = str(header.get("alg") or "")
        cfg = provider["config"]
        if alg not in _ALGS_RSA and alg != "HS256":
            raise errors.ValidationError(
                f"oidc_invalid: algorithm {alg!r} not allowed") from None
        signing_input = (parts[0] + "." + parts[1]).encode("utf-8")
        try:
            sig = _b64u_decode(parts[2])
        except binascii.Error:
            raise errors.ValidationError("oidc_invalid: bad signature "
                                         "encoding") from None
        if alg in _ALGS_RSA:
            keys = self._provider_jwks(provider)
            kid = str(header.get("kid") or "")
            key = keys.get(kid) if kid else next(iter(keys.values()), None)
            if not key:
                raise errors.ValidationError("oidc_invalid: no matching key")
            hash_name = {"RS256": "sha256", "RS384": "sha384",
                         "RS512": "sha512"}[alg]
            if not pki.rsa_verify_pkcs1v15(key["n"], key["e"], sig,
                                           signing_input, hash_name):
                raise errors.ValidationError("oidc_invalid: signature "
                                             "verification failed")
        else:
            secret = notify._decrypt_secret(
                str(cfg.get("client_secret_enc") or ""), self.svc.db_path)
            if not secret:
                raise errors.ValidationError(
                    "oidc_invalid: HS256 requires a configured secret")
            expect = hmac.new(secret.encode("utf-8"), signing_input,
                              hashlib.sha256).digest()
            if not hmac.compare_digest(expect, sig):
                raise errors.ValidationError("oidc_invalid: signature "
                                             "verification failed")
        iss = str(payload.get("iss") or "").rstrip("/")
        if iss != str(cfg.get("issuer") or "").rstrip("/"):
            raise errors.ValidationError("oidc_invalid: issuer mismatch")
        aud = payload.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if client_id and client_id not in [str(a) for a in auds]:
            raise errors.ValidationError("oidc_invalid: audience mismatch")
        now_f = now or _epoch()
        try:
            exp = int(payload.get("exp") or 0)
            iat = int(payload.get("iat") or 0)
        except (TypeError, ValueError):
            raise errors.ValidationError("oidc_invalid: bad time claims") \
                from None
        if exp and exp <= now_f:
            raise errors.ValidationError("oidc_invalid: token expired")
        nbf = payload.get("nbf")
        if nbf is not None:
            try:
                if int(nbf) > now_f + 60:
                    raise errors.ValidationError(
                        "oidc_invalid: token not yet valid")
            except (TypeError, ValueError):
                raise errors.ValidationError("oidc_invalid: bad nbf") from None
        if iat and iat > now_f + 300:
            raise errors.ValidationError("oidc_invalid: iat in the future")
        if nonce and str(payload.get("nonce") or "") != nonce:
            raise errors.ValidationError("oidc_invalid: nonce mismatch")
        sub = str(payload.get("sub") or "")
        if not sub or len(sub) > 256:
            raise errors.ValidationError("oidc_invalid: missing subject")
        return payload

    def _provider_jwks(self, provider: dict) -> dict:
        """{kid: {n, e}} from the provider JWKS (cached, bounded, SSRF-safe).
        Only RSA keys are accepted (alg-confusion defense)."""
        cfg = provider["config"]
        jwks_uri = cfg.get("jwks_uri") or ""
        if not jwks_uri:
            meta = self.oidc_discover(provider["id"])
            jwks_uri = str(meta.get("jwks_uri") or "")
        cached = self._jwks_cache.get(provider["id"])
        if cached and _epoch() - cached[0] < JWKS_CACHE_SECONDS:
            return cached[1]
        doc = json.loads(safe_https_fetch(jwks_uri)["body"])
        keys = {}
        for jwk in (doc.get("keys") or [])[:50]:
            if str(jwk.get("kty")) != "RSA":
                continue
            if jwk.get("alg") and str(jwk["alg"]) not in _ALGS_RSA:
                continue
            try:
                n = int.from_bytes(_b64u_decode(str(jwk.get("n") or "")), "big")
                e = int.from_bytes(_b64u_decode(str(jwk.get("e") or "")), "big")
            except (binascii.Error, ValueError):
                continue
            if n.bit_length() < 2048:
                continue
            keys[str(jwk.get("kid") or "")] = {"n": n, "e": e}
        if not keys:
            raise errors.ValidationError("oidc_invalid: no usable JWKS keys")
        self._jwks_cache[provider["id"]] = (_epoch(), keys)
        return keys

    # --------------------------------------------------------------- SAML
    def saml_start(self, provider_id: str, *, relay_state: str = "") -> dict:
        """SP-initiated SSO: build the AuthnRequest URL and a single-use
        request ID tracked in the state table (used for InResponseTo)."""
        self._throttle("sso_start", provider_id)
        provider = self._provider_row(provider_id)
        if provider["provider_type"] != "saml" or not provider["enabled"]:
            raise errors.NotFoundError("no such provider")
        cfg = provider["config"]
        request_id = "_" + secrets.token_hex(16)
        now = _now()
        state = request_id
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM idp_state WHERE expires_at<?", (now,))
            conn.execute(
                "INSERT INTO idp_state (state, provider_id, org_id, nonce, "
                "code_challenge, code_method, redirect_uri, created_at, "
                "expires_at, used_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (state, provider_id, provider["org_id"], "", "", "", "",
                 now, _iso_from_epoch(_epoch() + STATE_TTL_SECONDS), ""))
        acs = cfg.get("acs_url") or ""
        authn = ("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:"
                 "2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:"
                 "assertion\" ID=\"" + request_id + "\" Version=\"2.0\" "
                 "IssueInstant=\"" + now + "\" Destination=\"" +
                 _xml_escape(cfg["sso_url"]) + "\""
                 + (" AssertionConsumerServiceURL=\"" + _xml_escape(acs) + "\""
                    if acs else "") + ">"
                 "<samlp:NameIDPolicy AllowCreate=\"true\" Format=\""
                 "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"/>"
                 "</samlp:AuthnRequest>")
        url = cfg["sso_url"] + ("&" if "?" in cfg["sso_url"] else "?") + \
            urllib.parse.urlencode({"SAMLRequest":
                                    _b64u_encode(authn.encode("utf-8")),
                                    "RelayState": relay_state or state})
        return {"authorization_url": url, "request_id": request_id,
                "relay_state": relay_state or state}

    def saml_process(self, provider_id: str, response_xml: str, *,
                     request_id: str = "", ip: str = "",
                     actor: str = "sso") -> dict:
        """Validate a SAMLResponse fully, then map the identity. Any XML or
        assertion violation raises (fail closed); the response is NEVER
        trusted without a valid signature from the configured key."""
        self._throttle("sso_callback", provider_id)
        provider = self._provider_row(provider_id)
        if provider["provider_type"] != "saml" or not provider["enabled"]:
            raise errors.NotFoundError("no such provider")
        cfg = provider["config"]
        root = pki.safe_xml_root(response_xml)
        if root.localName != "Response":
            raise errors.ValidationError("saml_invalid: not a Response")
        if root.namespaceURI != "urn:oasis:names:tc:SAML:2.0:protocol":
            raise errors.ValidationError("saml_invalid: wrong namespace")
        if request_id:
            st_rows = self.db.query(
                "SELECT state, used_at, expires_at FROM idp_state WHERE "
                "state=? LIMIT 1", (request_id,))
            st = st_rows[0] if st_rows else None
            if not st:
                raise errors.ValidationError("saml_invalid: unknown request")
            if st["used_at"]:
                raise errors.ValidationError("saml_invalid: request reused")
            if _parse_ts(st["expires_at"]) < _epoch():
                raise errors.ValidationError("saml_invalid: request expired")
        in_response = root.getAttribute("InResponseTo") or ""
        if request_id and in_response != request_id:
            raise errors.ValidationError("saml_invalid: InResponseTo mismatch")
        dest = root.getAttribute("Destination") or ""
        if cfg.get("acs_url") and dest and dest != cfg["acs_url"]:
            raise errors.ValidationError("saml_invalid: destination mismatch")
        issuer_el = pki.find_child(root,
                                   "urn:oasis:names:tc:SAML:2.0:assertion",
                                   "Issuer")
        resp_issuer = pki.xml_text(issuer_el).strip() if issuer_el else ""
        if resp_issuer and resp_issuer != cfg["issuer"]:
            raise errors.ValidationError("saml_invalid: issuer mismatch")
        status_el = pki.find_child(root,
                                   "urn:oasis:names:tc:SAML:2.0:protocol",
                                   "Status")
        if status_el is not None:
            code_el = pki.find_child(status_el,
                                     "urn:oasis:names:tc:SAML:2.0:protocol",
                                     "StatusCode")
            status_value = code_el.getAttribute("Value") if code_el else ""
            if status_value and status_value not in (
                    "urn:oasis:names:tc:SAML:2.0:status:Success", ""):
                raise errors.ValidationError(
                    "saml_invalid: provider status is not success")
        assertions = pki.find_all(root,
                                  "urn:oasis:names:tc:SAML:2.0:assertion",
                                  "Assertion")
        if len(assertions) != 1:
            raise errors.ValidationError("saml_invalid: exactly one "
                                         "assertion required")
        assertion = assertions[0]
        a_id = assertion.getAttribute("ID") or ""
        if not a_id or len(a_id) > 256:
            raise errors.ValidationError("saml_invalid: assertion ID missing")
        # replay protection (assertion digest)
        digest = hashlib.sha256(
            (provider_id + "|" + a_id).encode("utf-8")).hexdigest()
        dupe_rows = self.db.query(
            "SELECT id FROM saml_replay WHERE digest=? LIMIT 1", (digest,))
        if dupe_rows:
            raise errors.ValidationError("saml_invalid: assertion replay")
        # signature against the CONFIGURED certificate
        cert = cfg["cert_pem"]
        n, e = pki.load_rsa_public_key(cert)
        sig = pki.verify_xmldsig(assertion, n, e, require=True)
        if not sig["verified"]:
            raise errors.ValidationError(
                "saml_invalid: signature verification failed")
        # temporal validity
        conds = pki.find_child(assertion,
                               "urn:oasis:names:tc:SAML:2.0:assertion",
                               "Conditions")
        if conds is not None:
            nb = conds.getAttribute("NotBefore") or ""
            na = conds.getAttribute("NotOnOrAfter") or ""
            now_f = _epoch()
            if nb and _parse_ts(nb) > now_f + 120:
                raise errors.ValidationError("saml_invalid: not yet valid")
            if na and _parse_ts(na) + 5 < now_f:
                # 5s clock-skew tolerance (documented); fail closed beyond
                raise errors.ValidationError("saml_invalid: assertion expired")
            audiences = pki.find_all(conds,
                                     "urn:oasis:names:tc:SAML:2.0:assertion",
                                     "Audience")
            for aud_el in audiences:
                aud = pki.xml_text(aud_el).strip()
                if cfg.get("audience") and aud != cfg["audience"]:
                    raise errors.ValidationError(
                        "saml_invalid: audience mismatch")
                break
        # subject confirmation (recipient + InResponseTo + not-on-or-after)
        subj = pki.find_child(assertion,
                              "urn:oasis:names:tc:SAML:2.0:assertion",
                              "Subject")
        nameid = ""
        if subj is not None:
            nid_el = pki.find_child(subj,
                                    "urn:oasis:names:tc:SAML:2.0:assertion",
                                    "NameID")
            nameid = pki.xml_text(nid_el).strip() if nid_el else ""
            confirmations = pki.find_all(subj,
                                         "urn:oasis:names:tc:SAML:2.0:"
                                         "assertion", "SubjectConfirmation")
            ok_confirm = False
            for conf in confirmations:
                data_el = pki.find_child(conf,
                                         "urn:oasis:names:tc:SAML:2.0:"
                                         "assertion",
                                         "SubjectConfirmationData")
                if data_el is None:
                    continue
                if cfg.get("acs_url"):
                    rec = data_el.getAttribute("Recipient") or ""
                    if rec and rec != cfg["acs_url"]:
                        continue
                in_resp = data_el.getAttribute("InResponseTo") or ""
                if request_id and in_resp and in_resp != request_id:
                    continue
                na = data_el.getAttribute("NotOnOrAfter") or ""
                if na and _parse_ts(na) + 5 < _epoch():
                    continue
                ok_confirm = True
                break
            if not ok_confirm:
                raise errors.ValidationError(
                    "saml_invalid: no valid subject confirmation")
        attributes = {}
        groups = []
        attr_stmt = pki.find_child(assertion,
                                   "urn:oasis:names:tc:SAML:2.0:assertion",
                                   "AttributeStatement")
        if attr_stmt is not None:
            for attr_el in pki.find_all(attr_stmt,
                                        "urn:oasis:names:tc:SAML:2.0:"
                                        "assertion", "Attribute"):
                aname = attr_el.getAttribute("Name") or ""
                vals = [pki.xml_text(v).strip() for v in pki.find_all(
                    attr_el, "urn:oasis:names:tc:SAML:2.0:assertion",
                    "AttributeValue") if v]
                if vals:
                    attributes[aname[:64]] = vals
            for g in attributes.get("groups", attributes.get("Groups", [])):
                groups.append(str(g)[:200])
        if not nameid:
            raise errors.ValidationError("saml_invalid: NameID missing")
        if len(nameid) > 256 or any(ord(c) < 32 for c in nameid):
            raise errors.ValidationError("saml_invalid: bad NameID")
        self.db.execute(
            "INSERT INTO saml_replay (id, digest, ts) VALUES (?,?,?)",
            (models.stable_id(models.NS_SAMLRP, digest), digest, _now()))
        if request_id:
            self.db.execute(
                "UPDATE idp_state SET used_at=? WHERE state=? AND used_at=''",
                (_now(), request_id))
        email = ""
        for key in ("email", "mail", "EmailAddress", "urn:oid:0.9.2342."
                    "19200300.100.1.3"):
            vals = attributes.get(key)
            if vals:
                email = str(vals[0])
                break
        return self._sso_login(provider, {
            "subject": nameid, "email": email,
            "name": (attributes.get("displayName") or
                     attributes.get("cn") or [""])[0],
            "groups": groups,
        }, ip=ip, actor=actor, method="saml")

    # ------------------------------------------------------------ JIT login
    def _sso_login(self, provider: dict, claims: dict, *, ip: str = "",
                   actor: str = "sso", method: str = "oidc") -> dict:
        """Validated identity → existing user or JIT-provisioned user →
        groups→roles → MFA policy → session. Never crosses tenants; the IdP
        can never choose an org, user id, or role directly."""
        subject = str(claims.get("subject") or "").strip()
        if not subject or len(subject) > 256 or any(ord(c) < 32
                                                    for c in subject):
            raise errors.ValidationError("sso_invalid: bad subject")
        email = str(claims.get("email") or "").strip().lower()
        name = str(claims.get("name") or "").strip()[:128]
        groups = [str(g)[:200] for g in (claims.get("groups") or [])
                  ][:_MAX_GROUPS]
        org_id = provider["org_id"]
        jit = bool(provider["jit"])
        id_rows = self.db.query(
            "SELECT user_id FROM sso_identities WHERE provider_id=? AND "
            "subject=? LIMIT 1", (provider["id"], subject))
        user_id = id_rows[0]["user_id"] if id_rows else ""
        if not user_id and email:
            e = None
            try:
                e = normalize_email(email)
            except errors.ValidationError:
                e = None
            if e:
                rows = self.db.query(
                    "SELECT id, org_id FROM users WHERE email=? LIMIT 2",
                    (e,))
                if len(rows) == 1 and rows[0]["org_id"] == org_id:
                    user_id = rows[0]["id"]
                    self.db.execute(
                        "INSERT OR IGNORE INTO sso_identities (id, user_id, "
                        "org_id, provider_id, subject, created_at, "
                        "updated_at, last_login_at) VALUES (?,?,?,?,?,?,?,?)",
                        (models.stable_id(models.NS_SSOIDENT,
                                          f"{provider['id']}|{subject}"),
                         user_id, org_id, provider["id"], subject, _now(),
                         _now(), _now()))
                    self._audit("identity.jit.linked", object_type="user",
                                object_id=user_id, org_id=org_id, actor=actor,
                                metadata={"provider": provider["provider_type"]})
                    self._event(org_id, "sso.linked", actor=actor,
                                detail={"user_id": user_id})
        created = False
        if not user_id:
            if not jit:
                raise errors.AuthenticationError("Invalid credentials")
            # JIT: email is required (username derives from its local part)
            if not email:
                raise errors.AuthenticationError("Invalid credentials")
            e = normalize_email(email)
            user = self._jit_create(provider, e, name, subject, actor)
            user_id = user.id
            created = True
        mapped_roles = self._map_roles(provider, groups)
        my_user = self.identity.user_get(user_id)
        if my_user.status != "active":
            raise errors.AuthenticationError("Invalid credentials")
        # UNION semantics: IdP mappings add roles; they never strip roles
        # granted by an admin or by SCIM (removal is explicit elsewhere).
        roles = tuple(dict.fromkeys(
            list(self.identity.user_roles(user_id)) + list(mapped_roles)))
        if mapped_roles:
            try:
                self.identity.user_set_roles(user_id, roles,
                                             allow_any_role=True)
            except Exception:
                raise errors.AuthenticationError("Invalid credentials") \
                    from None
        import mfa_service as _ms
        mfs = _ms.MfaService(self.svc, identity_svc=self.identity)
        user_roles = self.identity.user_roles(user_id)
        mfa_status = mfs.mfa_status(user_id)
        mfa_need = mfs.policy_requires(org_id, user_roles) or \
            bool(mfa_status.get("enabled"))
        created_sess = self.identity.session_create(
            user_id, ip=ip, actor=actor, auth_method=method,
            mfa_status="pending" if mfa_need else "none",
            idp_subject=subject, provider_id=provider["id"])
        sess = created_sess["session"]
        secret = created_sess["secret"]
        if created:
            self._audit("identity.jit.provisioned", object_type="user",
                        object_id=user_id, org_id=org_id, actor=actor,
                        metadata={"provider": provider["provider_type"],
                                  "roles": list(roles),
                                  "email_verified": True})
            self._event(org_id, "sso.jit_provisioned", actor=actor,
                        detail={"user_id": user_id, "roles": list(roles)})
        elif not roles:
            self._event(org_id, "sso.mapping_skipped", actor=actor,
                        detail={"user_id": user_id})
        self._audit("identity.sso.login", object_type="user",
                    object_id=user_id, org_id=org_id, actor=actor,
                    metadata={"provider": provider["provider_type"],
                              "method": method, "roles": list(roles),
                              "jit": created})
        self._event(org_id, "sso.login_success", actor=actor,
                    detail={"user_id": user_id, "provider": provider["id"]})
        return {"user": self.identity.user_get(user_id), "session": sess,
                "secret": secret, "mfa_required": mfa_need,
                "jit_provisioned": created,
                "identity": {"subject": subject, "email": email}}

    def _jit_create(self, provider: dict, email: str, name: str,
                    subject: str, actor: str) -> models.User:
        """Create a user bound to the IdP identity. Username derives from the
        email local-part (normalized + uniquified); the password is a random
        128-bit value (SSO-only login; password login cannot be guessed)."""
        import identity as _id
        base = re.sub(r"[^a-z0-9._-]", "", email.split("@")[0].lower())[:20] \
            or "sso"
        username = base
        if len(username) < 3:
            username = (base + "user")[:32]
        attempt = 0
        while True:
            dup_rows = self.db.query(
                "SELECT id FROM users WHERE org_id=? AND username=? LIMIT 1",
                (provider["org_id"], username))
            if not dup_rows:
                break
            attempt += 1
            if attempt > 50:
                raise errors.PersistenceError("jit_username_exhausted")
            username = (base + str(attempt))[:32]
        # users.email is UNIQUE globally; if this identity's email already
        # belongs to another tenant's user, alias it deterministically so
        # tenant isolation never depends on a shared attribute (the external
        # identity key remains (provider_id, subject)).
        taken = self.db.query(
            "SELECT id FROM users WHERE email=? AND org_id<>? LIMIT 1",
            (email, provider["org_id"]))
        if taken:
            local, _, domain = email.partition("@")
            suffix = provider["org_id"].replace("-", "")[:8]
            alias = f"{local}+{suffix}@{domain}"
            attempt = 0
            while self.db.query("SELECT id FROM users WHERE email=? LIMIT 1",
                                (alias,)):
                attempt += 1
                if attempt > 20:
                    raise errors.PersistenceError("jit_email_exhausted")
                alias = f"{local}+{suffix}{attempt}@{domain}"
            email = alias
        default_roles = tuple(provider.get("default_roles") or ())
        password = secrets.token_hex(16)
        user = self.identity.user_create(
            provider["org_id"], username, email, password,
            roles=default_roles or ("viewer",),
            display_name=name or username, allow_any_role=True,
            actor=actor)
        # SSO identities of a JIT user: one per provider (idempotent)
        self.db.execute(
            "INSERT OR IGNORE INTO sso_identities (id, user_id, org_id, "
            "provider_id, subject, created_at, updated_at, last_login_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (models.stable_id(models.NS_SSOIDENT,
                              f"{provider['id']}|{subject}"),
             user.id, provider["org_id"], provider["id"], subject, _now(),
             _now(), _now()))
        return user


def _xml_escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
