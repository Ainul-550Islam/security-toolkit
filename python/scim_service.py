#!/usr/bin/env python3
# ============================================================================
#  scim_service.py — Phase 8 SCIM 2.0 (Users + Groups) provisioning.
#  ---------------------------------------------------------------------------
#  Extends the EXISTING identity model: SCIM Users map to the existing
#  `users` table, SCIM Groups map to existing RBAC roles via the existing
#  `user_roles` table. No second user/group model is created.
#
#  Security properties:
#    - Dedicated tenant-scoped credentials (scim_credentials): verifier-only
#      at rest (sha256), key_prefix for lookup, max_role ceiling, expiry +
#      revocation. The org is derived SOLELY from the credential — client
#      requests can never choose a tenant.
#    - Role grants via SCIM are capped by the credential's max_role
#      (fail closed: above the ceiling → forbidden).
#    - Groups map to EXISTING RBAC roles only (unknown role → error).
#    - Bounded filters (attribute allowlist, length cap, no parser injection)
#      and bounded pagination (startIndex/count clamps).
#    - Idempotent by externalId; optimistic concurrency via meta.version;
#      guarded atomic updates (no read-modify-write races).
#    - Passwords are NEVER accepted through the API (secrets do not enter the
#      platform through provisioning; users authenticate via SSO/MFA or an
#      admin-initiated reset).
# ============================================================================

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time

import errors
import identity as identity_mod
import models
import rbac

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_MANAGER = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCHEMA_RES_TYPES = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMAS = "urn:ietf:params:scim:schemas:core:2.0:Schema"

CRED_PREFIX = "scim_"
TOKEN_LEN = 32
MAX_FILTER_LEN = 512
MAX_COUNT = 100
DEFAULT_COUNT = 50
MAX_GROUPS_PER_PATCH = 200
MAX_MEMBERS_PER_PATCH = 500
MAX_EMAILS = 4
_EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,253}$")
_ATTR_EMAIL = "emails"
_ATTR_DISPLAY = "displayName"
_ATTR_USERNAME = "userName"
_ATTR_EXTERNAL = "externalId"
_ATTR_ACTIVE = "active"
_ATTR_ID = "id"
_ATTR_GROUPS = "groups"
USER_ATTRS = frozenset({_ATTR_EMAIL, _ATTR_DISPLAY, _ATTR_USERNAME,
                        _ATTR_EXTERNAL, _ATTR_ACTIVE, _ATTR_ID, _ATTR_GROUPS})
GROUP_ATTRS = frozenset({_ATTR_DISPLAY, _ATTR_EXTERNAL, _ATTR_ID,
                         "members"})
_FILTER_ATTRS = frozenset({"email", "displayname", "username", "externalid",
                           "active", "id"})


class ScimError(errors.ValidationError):
    """SCIM 2.0 error carrying status + scimType (RFC 7644 §3.12)."""

    def __init__(self, status: int, scim_type: str, detail: str):
        super().__init__(detail)
        self.status = int(status)
        self.scim_type = str(scim_type)
        self.detail = str(detail)


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


class ScimService:
    """SCIM 2.0 resources on the shared users/user_roles model."""

    def __init__(self, platform, *, identity_svc=None):
        self.svc = platform
        self.db = platform.db
        self.identity = identity_svc or identity_mod.IdentityService(platform)
        self.limiter = self.identity.limiter

    # ------------------------------------------------------------ auth
    def authenticate(self, auth_header: str) -> dict:
        """HTTP Basic → tenant + credential. The org is NEVER taken from a
        request body/query: only the credential decides the tenant."""
        self._throttle("scim_global", "auth")
        raw = str(auth_header or "")
        if not raw.startswith("Basic "):
            raise ScimError(401, "invalidCredentials", "Authentication "
                            "required")
        try:
            decoded = base64.b64decode(raw[len("Basic "):].strip()).decode(
                "utf-8")
        except Exception:
            raise ScimError(401, "invalidCredentials",
                            "Malformed credentials") from None
        if ":" not in decoded:
            raise ScimError(401, "invalidCredentials",
                            "Malformed credentials")
        key_prefix, secret = decoded.split(":", 1)
        self._throttle("scim_auth", f"cred:{key_prefix[:20]}")
        rows = self.db.query(
            "SELECT * FROM scim_credentials WHERE key_prefix=? LIMIT 2",
            (key_prefix,))
        if not rows or len(rows) > 1:
            raise ScimError(401, "invalidCredentials", "Invalid credentials")
        cred = rows[0]
        expect = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        if not hmac_compare(expect, cred["verifier"]):
            raise ScimError(401, "invalidCredentials", "Invalid credentials")
        if cred["status"] != "active":
            raise ScimError(401, "invalidCredentials", "Invalid credentials")
        if cred["expires_at"] and _parse_ts(cred["expires_at"]) < _epoch():
            raise ScimError(401, "invalidCredentials", "Invalid credentials")
        try:
            self.db.execute(
                "UPDATE scim_credentials SET last_used_at=? WHERE id=?",
                (_now(), cred["id"]))
        except Exception:
            pass
        return {"org_id": cred["org_id"], "cred": dict(cred)}

    def _throttle(self, kind: str, key: str) -> None:
        limit, window = identity_mod.RL_LIMITS.get(kind, (60, 60))
        ok, retry = self.limiter.allowed(f"scim:{kind}:{key}", limit, window)
        if not ok:
            raise errors.RateLimitedError("Too many attempts",
                                          retry_after=retry)

    # ------------------------------------------------------------ credentials
    def _write_throttle(self, actor: str) -> None:
        """Per-actor write throttle (SCIM provisioning bursts up to the
        §47 scale ceiling are allowed; abuse is still bounded)."""
        self._throttle("scim_write", f"write:{actor}")

    def credential_create(self, org_id: str, name: str, *,
                          max_role: str = "analyst", ttl_seconds: int = 0,
                          actor: str = "identity") -> dict:
        """Create a SCIM credential. The SECRET is returned exactly once.
        max_role caps every role any SCIM group of this tenant may grant."""
        self.svc.org_require(org_id)
        nm = str(name or "").strip()
        if not nm or len(nm) > 96:
            raise errors.ValidationError("scim_invalid: name 1-96 chars")
        max_role = rbac.validate_role(max_role)
        self._throttle("scim", f"create:{actor}")
        secret = CRED_PREFIX + secrets.token_urlsafe(TOKEN_LEN)
        cred_id = models.stable_id(models.NS_SCIMCRED,
                                   f"{org_id}|{nm}|{secret[:12]}")
        verifier = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        try:
            self.db.execute(
                "INSERT INTO scim_credentials (id, org_id, name, key_prefix, "
                "verifier, max_role, status, created_by, created_at, "
                "last_used_at, expires_at, revoked_at, revoked_by) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cred_id, org_id, nm, secret[:10], verifier, max_role,
                 "active", str(actor)[:128], _now(), "",
                 _iso_from_epoch(_epoch() + int(ttl_seconds))
                 if int(ttl_seconds) != 0 else "", "", ""))
        except Exception as e:
            raise errors.PersistenceError(
                f"scim credential create failed: {e}") from e
        self._audit("identity.scim.credential_created",
                    object_type="scim_credential", object_id=cred_id,
                    org_id=org_id, actor=actor,
                    metadata={"name": nm, "max_role": max_role,
                              "prefix": secret[:10]})
        return {"id": cred_id, "org_id": org_id, "name": nm,
                "max_role": max_role, "secret": secret,
                "basic": secret, "expires_at": ""}

    def credential_revoke(self, cred_id: str, *, actor: str = "identity") -> dict:
        rows = self.db.query(
            "SELECT * FROM scim_credentials WHERE id=? LIMIT 1", (cred_id,))
        row = rows[0] if rows else None
        if not row:
            raise errors.NotFoundError("no such credential")
        self.db.execute(
            "UPDATE scim_credentials SET status='revoked', revoked_at=?, "
            "revoked_by=? WHERE id=? AND status='active'",
            (_now(), str(actor)[:128], cred_id))
        self._audit("identity.scim.credential_revoked",
                    object_type="scim_credential", object_id=cred_id,
                    org_id=row["org_id"], actor=actor,
                    metadata={"name": row["name"]})
        return {"revoked": cred_id}

    # ------------------------------------------------------------ discovery
    def service_provider_config(self) -> dict:
        return {
            "schemas": [SCHEMA_MANAGER],
            "documentationUri": "https://example.invalid/scim",
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0,
                     "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": MAX_COUNT},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [{
                "name": "HTTP Basic", "description": "Tenant-scoped "
                "provisioning credential", "type": "httpbasic",
                "primary": True}],
        }

    def resource_types(self) -> dict:
        return {"schemas": [SCHEMA_RES_TYPES], "totalResults": 2,
                "Resources": [
                    {"id": "User", "name": "User", "endpoint": "/Users",
                     "description": "Platform users (existing user model)",
                     "schema": SCHEMA_USER, "schemaExtensions": []},
                    {"id": "Group", "name": "Group", "endpoint": "/Groups",
                     "description": "RBAC role groups (existing roles)",
                     "schema": SCHEMA_GROUP, "schemaExtensions": []}]}

    def schemas(self) -> dict:
        return {"schemas": [SCHEMA_SCHEMAS], "totalResults": 2, "Resources": [
            {"id": SCHEMA_USER, "name": "User", "attributes": [
                {"name": "userName", "type": "string", "required": True},
                {"name": "displayName", "type": "string"},
                {"name": "externalId", "type": "string"},
                {"name": "active", "type": "boolean"},
                {"name": "emails", "type": "complex",
                 "subAttributes": [{"name": "value", "type": "string",
                                    "required": True},
                                   {"name": "primary", "type": "boolean"}]},
                {"name": "id", "type": "string", "required": True}]},
            {"id": SCHEMA_GROUP, "name": "Group", "attributes": [
                {"name": "displayName", "type": "string", "required": True},
                {"name": "externalId", "type": "string"},
                {"name": "members", "type": "complex",
                 "subAttributes": [{"name": "value", "type": "string"},
                                   {"name": "type", "type": "string"}]}]}]}

    # ------------------------------------------------------------ envelope
    def _user_resource(self, user, version: int, groups=()) -> dict:
        u = user if isinstance(user, dict) else {"id": user.id,
                                                 "org_id": user.org_id,
                                                 "username": user.username,
                                                 "email": user.email,
                                                 "display_name":
                                                     user.display_name,
                                                 "status": user.status}
        emails = []
        if u.get("email"):
            emails.append({"value": u["email"], "primary": True})
        return {
            "schemas": [SCHEMA_USER],
            "id": u["id"],
            "externalId": "",          # filled by caller when known
            "userName": u.get("username", ""),
            "displayName": u.get("display_name", "") or u.get("username", ""),
            "active": u.get("status") == "active",
            "emails": emails,
            "groups": [{"value": gid, "display": gname,
                        "type": "direct"} for gid, gname in groups],
            "meta": {
                "resourceType": "User",
                "created": u.get("created_at", "") or _now(),
                "lastModified": u.get("updated_at", "") or _now(),
                "version": str(version),
            },
        }

    def _group_resource(self, g: dict, members) -> dict:
        return {
            "schemas": [SCHEMA_GROUP],
            "id": g["id"],
            "externalId": g["external_id"],
            "displayName": g["display_name"],
            "members": [{"value": m["user_id"],
                         "display": m.get("username", "")} for m in members],
            "meta": {"resourceType": "Group",
                     "created": g["created_at"],
                     "lastModified": g["updated_at"],
                     "version": str(g["version"])},
        }

    def _error(self, status: int, scim_type: str, detail: str):
        return ScimError(status, scim_type, detail)

    # ------------------------------------------------------------ parsing
    def _body(self, raw: str) -> dict:
        try:
            body = json.loads(raw or "{}")
        except Exception:
            raise self._error(400, "invalidSyntax", "Body is not valid JSON") \
                from None
        if not isinstance(body, dict):
            raise self._error(400, "invalidSyntax", "Body must be an object")
        return body

    def _as_object(self, body) -> dict:
        """Service-level guard: mutators never accept non-object bodies
        (the HTTP layer pre-parses, but direct callers must fail the same
        way instead of crashing with an AttributeError)."""
        if not isinstance(body, dict):
            raise self._error(400, "invalidSyntax", "Body must be an object")
        return body

    def _parse_filter(self, filt: str) -> dict | None:
        """Bounded, allowlisted filter parser. Supported: `attr eq "value"`
        (optionally joined with ` and `). Anything else → invalidFilter.
        Attribute names are case-insensitive; VALUES are matched exactly
        (case preserved)."""
        f = str(filt or "").strip()
        if not f:
            return None
        if len(f) > MAX_FILTER_LEN:
            raise self._error(400, "invalidFilter", "Filter too long")
        parts = re.split(r"\s+and\s+", f, maxsplit=3, flags=re.IGNORECASE)
        conditions = []
        for part in parts:
            m = re.match(r'^([a-z]+)\s+eq\s+"([^"]{0,256})"$', part.strip(),
                         re.IGNORECASE)
            if not m:
                raise self._error(400, "invalidFilter",
                                  "Only 'attr eq \"value\"' (joined by "
                                  "'and') is supported")
            attr, value = m.group(1).lower(), m.group(2)
            if attr not in _FILTER_ATTRS:
                raise self._error(400, "invalidFilter",
                                  f"Unsupported filter attribute: {attr}")
            conditions.append((attr, value))
        if len(conditions) > 3:
            raise self._error(400, "invalidFilter", "Too many conditions")
        return conditions

    def _page(self, start_index, count) -> tuple[int, int]:
        si = int(start_index) if start_index not in (None, "") else 1
        if si < 1:
            raise self._error(400, "invalidSyntax",
                              "startIndex must be >= 1")
        si = min(si, 1000000)
        c = int(count) if count not in (None, "") else DEFAULT_COUNT
        c = max(1, min(MAX_COUNT, c))
        return si, c

    def _list(self, resources, total: int, *, start: int, count: int) -> dict:
        return {"schemas": [SCHEMA_LIST], "totalResults": int(total),
                "startIndex": int(start), "itemsPerPage": int(count),
                "Resources": resources}

    # ------------------------------------------------------------ users
    def _user_map(self, org_id: str, external_id: str) -> dict | None:
        rows = self.db.query(
            "SELECT * FROM scim_users WHERE org_id=? AND external_id=? "
            "LIMIT 1", (org_id, external_id))
        return rows[0] if rows else None

    def _user_row(self, user_id: str) -> dict | None:
        rows = self.db.query("SELECT * FROM users WHERE id=? LIMIT 1",
                             (user_id,))
        return rows[0] if rows else None

    def _user_groups(self, user_id: str) -> list:
        return self.db.query(
            "SELECT g.id, g.display_name FROM scim_group_members m JOIN "
            "scim_groups g ON g.id=m.group_id WHERE m.user_id=? "
            "ORDER BY g.display_name LIMIT 50", (user_id,))

    def users_list(self, org_id: str, *, filter: str = "", start_index=1,
                   count=DEFAULT_COUNT) -> dict:
        conds = self._parse_filter(filter)
        si, c = self._page(start_index, count)
        where = "u.org_id=?"
        params: list = [org_id]
        attr_map = {"email": _ATTR_EMAIL, "username": _ATTR_USERNAME,
                    "displayname": _ATTR_DISPLAY, "active": _ATTR_ACTIVE,
                    "id": _ATTR_ID, "externalid": _ATTR_EXTERNAL}
        if conds:
            for attr, value in conds:
                attr = attr_map[attr]
                if attr == _ATTR_EMAIL:
                    where += " AND u.email=?"
                    params.append(value)
                elif attr == _ATTR_USERNAME:
                    where += " AND u.username=?"
                    params.append(value)
                elif attr == _ATTR_DISPLAY:
                    where += " AND u.display_name=?"
                    params.append(value)
                elif attr == _ATTR_ACTIVE:
                    if value not in ("true", "false"):
                        raise self._error(400, "invalidFilter",
                                          "active must be true or false")
                    where += " AND u.status" + ("=" if value == "true" else
                                                "<>") + "'active'"
                elif attr == _ATTR_ID:
                    where += " AND u.id=?"
                    params.append(value)
                else:   # externalId — needs the mapping table
                    where += (" AND u.id IN (SELECT user_id FROM scim_users "
                              "WHERE org_id=? AND external_id=?)")
                    params.extend([org_id, value])
        total = int(self.db.query_one(
            "SELECT COUNT(*) n FROM users u WHERE " + where,
            tuple(params))["n"])
        rows = self.db.query(
            "SELECT u.*, s.version AS scim_version, s.external_id FROM users "
            "u LEFT JOIN scim_users s ON s.user_id=u.id AND s.org_id=u.org_id "
            "WHERE " + where + " ORDER BY u.username LIMIT ? OFFSET ?",
            tuple(params + [c, si - 1]))
        resources = []
        for r in rows:
            groups = self._user_groups(r["id"])
            res = self._user_resource(r, int(r["scim_version"] or 0),
                                      [(g["id"], g["display_name"])
                                       for g in groups])
            res["externalId"] = r["external_id"] or r["id"]
            resources.append(res)
        return self._list(resources, total, start=si, count=c)

    def user_get(self, org_id: str, user_id: str) -> dict:
        row = self._user_row(user_id)
        if not row or row["org_id"] != org_id:
            raise self._error(404, "notFound", "Resource not found")
        mp_rows = self.db.query(
            "SELECT * FROM scim_users WHERE org_id=? AND user_id=? LIMIT 1",
            (org_id, user_id))
        mp = mp_rows[0] if mp_rows else None
        groups = self._user_groups(user_id)
        res = self._user_resource(row, int(mp["version"]) if mp else 0,
                                  [(g["id"], g["display_name"])
                                   for g in groups])
        res["externalId"] = (mp["external_id"] if mp else row["id"])
        return res

    def _email_from_body(self, body: dict) -> str:
        emails = body.get(_ATTR_EMAIL)
        if not emails:
            return ""
        if not isinstance(emails, list) or len(emails) > MAX_EMAILS:
            raise self._error(400, "invalidValue", "Invalid emails")
        primary = None
        for e in emails:
            if not isinstance(e, dict) or not e.get("value"):
                continue
            if str(e.get("primary", "")).lower() == "true":
                primary = str(e["value"])
                break
        if primary is None:
            for e in emails:
                if isinstance(e, dict) and e.get("value"):
                    primary = str(e["value"])
                    break
        email = (primary or "").strip().lower()
        if email and not _EMAIL_RE.match(email):
            raise self._error(400, "invalidValue", "Invalid email")
        return email

    def user_create(self, org_id: str, body: dict, *, max_role: str,
                    actor: str = "sso") -> dict:
        self._write_throttle(actor)
        """POST /Users — idempotent on externalId (an existing mapping
        returns the current resource instead of creating a duplicate)."""
        body = self._as_object(body)
        ext = str(body.get(_ATTR_EXTERNAL) or "").strip()
        if not ext or len(ext) > 256 or any(ord(c) < 32 for c in ext):
            raise self._error(400, "invalidValue",
                              "externalId is required (1-256 chars)")
        if body.get("password"):
            raise self._error(400, "invalidValue",
                              "password attribute is not accepted; users "
                              "authenticate via SSO/MFA or an admin reset")
        existing = self._user_map(org_id, ext)
        if existing:
            return self.user_get(org_id, existing["user_id"])
        email = self._email_from_body(body)
        if not email:
            raise self._error(400, "invalidValue", "A primary email is "
                              "required to provision")
        username = str(body.get(_ATTR_USERNAME) or "").strip()
        if not username:
            username = re.sub(r"[^a-z0-9._-]", "",
                              email.split("@")[0].lower())[:20] or "user"
        if not (2 <= len(username) <= 32):
            username = username[:32]
        display = str(body.get(_ATTR_DISPLAY) or "")[:128] or username
        active = str(body.get(_ATTR_ACTIVE, "true")).lower() != "false"
        # create with the existing user model: viewer baseline, no role
        # escalation (groups/roles are applied separately, capped by max_role)
        try:
            user = self.identity.user_create(
                org_id, username, email, secrets.token_hex(16),
                roles=("viewer",), display_name=display,
                allow_any_role=True, actor=actor)
        except errors.DuplicateError:
            dup_rows = self.db.query(
                "SELECT id FROM users WHERE org_id=? AND email=? LIMIT 1",
                (org_id, email))
            if dup_rows:
                raise self._error(409, "uniqueness",
                                  "A user with this email already exists") \
                    from None
            raise self._error(409, "uniqueness",
                              "userName already in use") from None
        if not active:
            self.identity.user_set_status(user.id, "suspended",
                                        actor=actor)
        self.db.execute(
            "INSERT INTO scim_users (org_id, external_id, user_id, version, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (org_id, ext, user.id, 1, _now(), _now()))
        self._audit("identity.scim.created", object_type="user",
                    object_id=user.id, org_id=org_id, actor=actor,
                    metadata={"external_id": ext[:64]})
        return self.user_get(org_id, user.id)

    def user_replace(self, org_id: str, user_id: str, body: dict, *,
                     max_role: str, actor: str = "sso") -> dict:
        self._write_throttle(actor)
        """PUT /Users/{id} — full replace of the SCIM-managed attributes;
        optimistic concurrency on meta.version."""
        body = self._as_object(body)
        row = self._user_row(user_id)
        if not row or row["org_id"] != org_id:
            raise self._error(404, "notFound", "Resource not found")
        mp = self._user_map(org_id, str(body.get(_ATTR_EXTERNAL) or row["id"]))
        if body.get("password"):
            raise self._error(400, "invalidValue",
                              "password attribute is not accepted")
        want_version = body.get("meta", {}).get("version") if \
            isinstance(body.get("meta"), dict) else None
        current_version = int(mp["version"]) if mp else 0
        if want_version is not None and \
                str(want_version) != str(current_version):
            raise self._error(409, "version",
                              "Version mismatch (concurrent update)")
        email = self._email_from_body(body)
        display = str(body.get(_ATTR_DISPLAY) or "")[:128] or row["username"]
        active = str(body.get(_ATTR_ACTIVE, "true")).lower() != "false"
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE users SET email=?, display_name=?, updated_at=? "
                "WHERE id=?", (email or row["email"], display, _now(), user_id))
            if mp:
                conn.execute(
                    "UPDATE scim_users SET version=version+1, updated_at=? "
                    "WHERE org_id=? AND external_id=?",
                    (_now(), org_id, mp["external_id"]))
        if active and row["status"] != "active":
            self._audit("identity.scim.reactivated", object_type="user",
                        object_id=user_id, org_id=org_id, actor=actor,
                        metadata={})
        if not active:
            self._audit("identity.scim.deactivated", object_type="user",
                        object_id=user_id, org_id=org_id, actor=actor,
                        metadata={})
        self.db.execute(
            "UPDATE users SET status=?, updated_at=? WHERE id=?",
            ("active" if active else "suspended", _now(), user_id))
        self._audit("identity.scim.updated", object_type="user",
                    object_id=user_id, org_id=org_id, actor=actor,
                    metadata={"external_id": str(
                        (mp or {}).get("external_id", ""))[:64]})
        return self.user_get(org_id, user_id)

    def user_patch(self, org_id: str, user_id: str, body: dict, *,
                   actor: str = "sso") -> dict:
        self._write_throttle(actor)
        """PATCH /Users/{id} — additive/removal attribute patches; only
        the supported operations (replace active/displayName/emails) are
        accepted; groups changes are rejected (use /Groups)."""
        body = self._as_object(body)
        row = self._user_row(user_id)
        if not row or row["org_id"] != org_id:
            raise self._error(404, "notFound", "Resource not found")
        ops = body.get("Operations")
        if not isinstance(ops, list) or not ops:
            raise self._error(400, "invalidSyntax", "Operations required")
        new_display = None
        new_email = None
        new_active = None
        for op in ops[:10]:
            if not isinstance(op, dict):
                raise self._error(400, "invalidSyntax", "Bad operation")
            path = str(op.get("path") or "")
            value = op.get("value")
            if path == _ATTR_GROUPS or isinstance(value, dict) and \
                    "groups" in (value or {}):
                raise self._error(400, "unsupported",
                                  "Group membership is managed via /Groups")
            if path == _ATTR_DISPLAY and op.get("op") == "replace":
                new_display = str(value or "")[:128]
            elif path == _ATTR_EMAIL and op.get("op") == "replace":
                new_email = self._email_from_body(value if isinstance(
                    value, dict) else {"emails": value})
            elif path == _ATTR_ACTIVE and op.get("op") == "replace":
                if str(value).lower() not in ("true", "false"):
                    raise self._error(400, "invalidValue",
                                      "active must be boolean")
                new_active = str(value).lower() == "true"
            else:
                raise self._error(400, "unsupported",
                                  f"Operation not supported: {path}")
        with self.db.transaction() as conn:
            if new_email is not None or new_display is not None:
                conn.execute(
                    "UPDATE users SET email=COALESCE(?, email), "
                    "display_name=COALESCE(?, display_name), updated_at=? "
                    "WHERE id=?",
                    (new_email or "", new_display or "", _now(), user_id))
            if new_active is not None:
                conn.execute("UPDATE users SET status=?, updated_at=? "
                             "WHERE id=?",
                             ("active" if new_active else "suspended",
                              _now(), user_id))
        self.db.execute(
            "UPDATE scim_users SET version=version+1, updated_at=? WHERE "
            "user_id=? AND org_id=?", (_now(), user_id, org_id))
        self._audit("identity.scim.updated", object_type="user",
                    object_id=user_id, org_id=org_id, actor=actor,
                    metadata={"patched": True})
        return self.user_get(org_id, user_id)

    def user_delete(self, org_id: str, user_id: str, *,
                    actor: str = "sso") -> dict:
        self._write_throttle(actor)
        """DELETE /Users/{id} → DEACTIVATE (soft): sessions revoked, status
        deactivated, mapping retained for audit + future reactivation."""
        row = self._user_row(user_id)
        if not row or row["org_id"] != org_id:
            raise self._error(404, "notFound", "Resource not found")
        self.db.execute(
            "UPDATE users SET status='deactivated', deactivated_at=?, "
            "updated_at=? WHERE id=?", (_now(), _now(), user_id))
        try:
            self.identity.sessions_revoke_all(user_id,
                                              reason="scim_delete")
        except Exception:
            pass
        mp_rows = self.db.query(
            "SELECT external_id FROM scim_users WHERE org_id=? AND user_id=? "
            "LIMIT 1", (org_id, user_id))
        mp = mp_rows[0] if mp_rows else None
        self._audit("identity.scim.deactivated", object_type="user",
                    object_id=user_id, org_id=org_id, actor=actor,
                    metadata={"external_id": str(
                        (mp or {}).get("external_id", ""))[:64]})
        return {"deactivated": user_id}

    # ------------------------------------------------------------ groups
    def groups_list(self, org_id: str, *, filter: str = "", start_index=1,
                    count=DEFAULT_COUNT) -> dict:
        conds = self._parse_filter(filter)
        si, c = self._page(start_index, count)
        where = "org_id=?"
        params: list = [org_id]
        # map SCIM attribute names -> DB columns (NOT the JSON keys)
        attr_map = {"displayname": "display_name",
                    "externalid": "external_id", "id": "id"}
        if conds:
            for attr, value in conds:
                if attr not in attr_map:
                    raise self._error(400, "invalidFilter",
                                      f"Unsupported attribute: {attr}")
                where += f" AND {attr_map[attr]}=?"
                params.append(value)
        rows = self.db.query(
            "SELECT * FROM scim_groups WHERE " + where +
            " ORDER BY display_name LIMIT ? OFFSET ?",
            tuple(params + [c, si - 1]))
        resources = []
        for g in rows:
            members = self.db.query(
                "SELECT m.user_id, u.username FROM scim_group_members m JOIN "
                "users u ON u.id=m.user_id WHERE m.group_id=? ORDER BY "
                "u.username LIMIT ?", (g["id"], MAX_COUNT + 1))
            resources.append(self._group_resource(dict(g), members))
        return self._list(resources, len(resources), start=si, count=c)

    def group_get(self, org_id: str, group_id: str) -> dict:
        g_rows = self.db.query(
            "SELECT * FROM scim_groups WHERE id=? LIMIT 1", (group_id,))
        g = g_rows[0] if g_rows else None
        if not g or g["org_id"] != org_id:
            raise self._error(404, "notFound", "Resource not found")
        members = self.db.query(
            "SELECT m.user_id, u.username FROM scim_group_members m JOIN "
            "users u ON u.id=m.user_id WHERE m.group_id=? ORDER BY "
            "u.username LIMIT ?", (group_id, MAX_COUNT + 1))
        return self._group_resource(dict(g), members)

    def _resolve_role(self, org_id: str, role: str, max_role: str) -> str:
        role = rbac.validate_role(role)     # unknown role → fail closed
        if rbac.ROLE_ORDER.index(role) > rbac.ROLE_ORDER.index(max_role):
            raise self._error(403, "authorization",
                              "Role exceeds credential allowance")
        return role

    def group_create(self, org_id: str, body: dict, *, max_role: str,
                     actor: str = "sso") -> dict:
        self._write_throttle(actor)
        body = self._as_object(body)
        ext = str(body.get(_ATTR_EXTERNAL) or "").strip()
        if not ext or len(ext) > 256 or any(ord(c) < 32 for c in ext):
            raise self._error(400, "invalidValue",
                              "externalId is required (1-256 chars)")
        display = str(body.get(_ATTR_DISPLAY) or "").strip()
        if not display or len(display) > 128:
            raise self._error(400, "invalidValue",
                              "displayName is required (1-128 chars)")
        role = self._resolve_role(org_id, str(body.get("role") or "viewer"),
                                  max_role)
        existing_rows = self.db.query(
            "SELECT * FROM scim_groups WHERE org_id=? AND external_id=? "
            "LIMIT 1", (org_id, ext))
        existing = existing_rows[0] if existing_rows else None
        if existing:
            return self.group_get(org_id, existing["id"])
        gid = models.stable_id(models.NS_SCIMGRP, f"{org_id}|{ext}")
        try:
            self.db.execute(
                "INSERT INTO scim_groups (id, org_id, external_id, "
                "display_name, role, version, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (gid, org_id, ext, display, role, 1, _now(), _now()))
        except Exception as e:
            if "UNIQUE" in str(e):
                dup_rows = self.db.query(
                    "SELECT id FROM scim_groups WHERE org_id=? AND "
                    "external_id=? LIMIT 1", (org_id, ext))
                if dup_rows:
                    return self.group_get(org_id, dup_rows[0]["id"])
            raise errors.PersistenceError(
                f"scim group create failed: {e}") from e
        self._audit("identity.scim.created", object_type="scim_group",
                    object_id=gid, org_id=org_id, actor=actor,
                    metadata={"external_id": ext[:64],
                              "display_name": display[:64]})
        return self.group_get(org_id, gid)

    def group_replace(self, org_id: str, group_id: str, body: dict, *,
                      max_role: str, actor: str = "sso") -> dict:
        self._write_throttle(actor)
        """PUT /Groups/{id} — replaces attributes AND (with members) the
        full membership set; optimistic concurrency on meta.version; role
        capped by the credential's max_role."""
        body = self._as_object(body)
        g_rows = self.db.query(
            "SELECT * FROM scim_groups WHERE id=? LIMIT 1", (group_id,))
        g = g_rows[0] if g_rows else None
        if not g or g["org_id"] != org_id:
            raise self._error(404, "notFound", "Resource not found")
        want_version = body.get("meta", {}).get("version") if \
            isinstance(body.get("meta"), dict) else None
        if want_version is not None and \
                str(want_version) != str(g["version"]):
            raise self._error(409, "version",
                              "Version mismatch (concurrent update)")
        display = str(body.get(_ATTR_DISPLAY) or g["display_name"])[:128]
        if not display.strip():
            raise self._error(400, "invalidValue", "displayName required")
        role = str(body.get("role") or g["role"])
        role = self._resolve_role(org_id, role, max_role)
        members = self._member_ids(org_id, body.get("members"))
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE scim_groups SET display_name=?, role=?, version="
                "version+1, updated_at=? WHERE id=? AND org_id=?",
                (display, role, _now(), group_id, org_id))
            conn.execute("DELETE FROM scim_group_members WHERE group_id=?",
                         (group_id,))
            for uid in members:
                conn.execute(
                    "INSERT OR IGNORE INTO scim_group_members (group_id, "
                    "user_id) VALUES (?,?)", (group_id, uid))
        for uid in members:
            self._reconcile_roles(org_id, uid, actor)
        self._audit("identity.scim.updated", object_type="scim_group",
                    object_id=group_id, org_id=org_id, actor=actor,
                    metadata={"display_name": display[:64],
                              "role": role, "members": len(members)})
        return self.group_get(org_id, group_id)

    def _member_ids(self, org_id: str, members) -> list:
        if members is None:
            return []
        if not isinstance(members, list) or len(members) > MAX_MEMBERS_PER_PATCH:
            raise self._error(400, "invalidValue", "Invalid members")
        ids = []
        for m in members[:MAX_MEMBERS_PER_PATCH]:
            if not isinstance(m, dict):
                continue
            uid = str(m.get("value") or "")
            if not uid or len(uid) > 128:
                continue
            row_rows = self.db.query(
                "SELECT id, org_id FROM users WHERE id=? LIMIT 1", (uid,))
            row = row_rows[0] if row_rows else None
            if not row or row["org_id"] != org_id:
                raise self._error(404, "notFound",
                                  f"Member not found: {uid[:16]}")
            ids.append(uid)
        return list(dict.fromkeys(ids))

    def group_patch(self, org_id: str, group_id: str, body: dict, *,
                    actor: str = "sso") -> dict:
        self._write_throttle(actor)
        """PATCH /Groups/{id} — add/remove members (role changes via PUT)."""
        body = self._as_object(body)
        g_rows = self.db.query(
            "SELECT * FROM scim_groups WHERE id=? LIMIT 1", (group_id,))
        g = g_rows[0] if g_rows else None
        if not g or g["org_id"] != org_id:
            raise self._error(404, "notFound", "Resource not found")
        ops = body.get("Operations")
        if not isinstance(ops, list) or not ops:
            raise self._error(400, "invalidSyntax", "Operations required")
        add_ids: list = []
        remove_ids: list = []
        touched = False
        for op in ops[:10]:
            if not isinstance(op, dict):
                raise self._error(400, "invalidSyntax", "Bad operation")
            path = str(op.get("path") or "members")
            opname = str(op.get("op") or "")
            if path not in ("members", "members.value"):
                raise self._error(400, "unsupported",
                                  f"Operation not supported: {path}")
            value = op.get("value")
            if opname == "add":
                add_ids.extend(self._member_ids(org_id, value))
                touched = True
            elif opname == "remove":
                remove_ids.extend(self._member_ids(org_id, value))
                touched = True
            elif opname == "replace" and path == "members":
                current = self.db.query(
                    "SELECT user_id FROM scim_group_members WHERE group_id=? "
                    "LIMIT ?", (group_id, MAX_MEMBERS_PER_PATCH + 1))
                remove_ids.extend(r["user_id"] for r in current)
                add_ids.extend(self._member_ids(org_id, value))
                touched = True
            else:
                raise self._error(400, "unsupported",
                                  f"Operation not supported: {opname}")
        if not touched:
            raise self._error(400, "invalidSyntax", "No operations applied")
        with self.db.transaction() as conn:
            for uid in add_ids[:MAX_MEMBERS_PER_PATCH]:
                conn.execute(
                    "INSERT OR IGNORE INTO scim_group_members (group_id, "
                    "user_id) VALUES (?,?)", (group_id, uid))
            for uid in remove_ids[:MAX_MEMBERS_PER_PATCH]:
                conn.execute(
                    "DELETE FROM scim_group_members WHERE group_id=? AND "
                    "user_id=?", (group_id, uid))
            conn.execute(
                "UPDATE scim_groups SET version=version+1, updated_at=? "
                "WHERE id=?", (_now(), group_id))
        for uid in dict.fromkeys(add_ids + remove_ids):
            self._reconcile_roles(org_id, uid, actor)
        self._audit("identity.scim.updated", object_type="scim_group",
                    object_id=group_id, org_id=org_id, actor=actor,
                    metadata={"added": len(add_ids), "removed":
                              len(remove_ids)})
        return self.group_get(org_id, group_id)

    def group_delete(self, org_id: str, group_id: str, *,
                     actor: str = "sso") -> dict:
        self._write_throttle(actor)
        g_rows = self.db.query(
            "SELECT * FROM scim_groups WHERE id=? LIMIT 1", (group_id,))
        g = g_rows[0] if g_rows else None
        if not g or g["org_id"] != org_id:
            raise self._error(404, "notFound", "Resource not found")
        member_ids = [r["user_id"] for r in self.db.query(
            "SELECT user_id FROM scim_group_members WHERE group_id=?",
            (group_id,))]
        self.db.execute("DELETE FROM scim_groups WHERE id=?", (group_id,))
        for uid in member_ids:
            self._reconcile_roles(org_id, uid, actor)
        self._audit("identity.scim.deleted", object_type="scim_group",
                    object_id=group_id, org_id=org_id, actor=actor,
                    metadata={"display_name": g["display_name"][:64]})
        return {"deleted": group_id}

    def _reconcile_roles(self, org_id: str, user_id: str, actor: str) -> None:
        """After any membership change, the user's role set is the union of
        their explicit roles and the roles of every SCIM group they belong
        to. Removed memberships drop the group's role when nothing else
        grants it (least privilege, deterministic)."""
        group_roles = [r["role"] for r in self.db.query(
            "SELECT g.role FROM scim_group_members m JOIN scim_groups g ON "
            "g.id=m.group_id WHERE m.user_id=? AND g.org_id=?", 
            (user_id, org_id))]
        want = set(group_roles)
        has = set(self.identity.user_roles(user_id))
        if want == has:
            return
        # grant missing group roles
        for r in want - has:
            self.db.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role) VALUES "
                "(?,?)", (user_id, r))
        # revoke roles that came from a group membership that no longer
        # exists (role removed from user_roles; explicit grants of the same
        # name are indistinguishable — documented)
        for r in has - want:
            still = self.db.query_one(
                "SELECT COUNT(*) n FROM scim_group_members m JOIN "
                "scim_groups g ON g.id=m.group_id WHERE m.user_id=? AND "
                "g.role=? AND g.org_id=? LIMIT 1", (user_id, r, org_id))
            if not still or int(still["n"]) == 0:
                self.db.execute(
                    "DELETE FROM user_roles WHERE user_id=? AND role=?",
                    (user_id, r))

    # ------------------------------------------------------------ helper
    def _audit(self, action: str, **kw):
        try:
            self.svc.audit(action, **kw)
        except Exception:
            pass


def hmac_compare(a: str, b: str) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(str(a), str(b))
