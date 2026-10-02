#!/usr/bin/env python3
# ============================================================================
#  identity.py — Phase 2 identity & credential service.
#  ---------------------------------------------------------------------------
#  Users, password security (scrypt via hashlib — stdlib, vetted KDF),
#  sessions, API credentials (verifier-only storage), password resets,
#  bounded rate limiting and security-sensitive audit events.
#
#  Security properties:
#    - passwords: scrypt (N=2**14 default, r=8, p=1, 16-byte random salt),
#      constant-time verification (hmac.compare_digest). NEVER plaintext,
#      never logged, never serialized.
#    - API/session/reset tokens: 256-bit secrets.random; only a SHA-256
#      VERIFIER is stored (high-entropy tokens ⇒ unsalted digest is sound).
#    - raw secrets are returned exactly once at creation; every other code
#      path sees only prefixes and metadata.
#    - Failure responses are GENERIC (no user/credential existence oracle).
#    - brute force: bounded rate limiting + temporary lockout (never
#      permanent — no trivial self-DoS).
# ============================================================================

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time

import errors
import models
import rbac

# --- token prefixes (type-tagged, never secret themselves) -------------------
TOKEN_PREFIXES = {"session": "ses_", "credential": "stk_", "reset": "rst_",
                  "breakglass": "bg_"}

# secure defaults
SCRYPT_N_DEFAULT = 2 ** 14        # 16 MiB memory, ~50-100 ms — reasonable CLI
SCRYPT_R = 8
SCRYPT_P = 1
DK_LEN = 32
SALT_LEN = 16

MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 256
SESSION_TTL_SECONDS = 12 * 3600
RESET_TTL_SECONDS = 30 * 60
AUTH_LOCK_MAX_FAILURES = 5
AUTH_LOCK_SECONDS = 15 * 60

# Phase-8 session hardening: idle timeout (existing SESSION_TTL_SECONDS is
# kept as the IDLE timeout for backwards compatibility) plus a hard absolute
# lifetime ceiling; MFA-pending sessions get a short expiry.
ABSOLUTE_SESSION_TTL_SECONDS = 30 * 24 * 3600
PENDING_MFA_TTL_SECONDS = 10 * 60

# rate-limit windows: (limit, window_seconds)
RL_LIMITS = {
    "auth": (5, 60),             # per identifier(+ip) — brute-force gate
    "auth_ip": (20, 60),         # per IP across identifiers
    "api": (120, 60),            # per API credential
    "credential_create": (10, 3600),
    "scan_create": (30, 3600),
    "session_create": (12, 300),
    # Phase 8 identity-specific gates (same limiter implementation)
    "mfa_enroll": (10, 3600),
    "mfa_verify": (8, 300),
    "recovery_use": (5, 300),
    "mfa_reset": (5, 3600),
    # Phase 8 break-glass: explicit emergency access is both throttled and
    # audited; the grant ALSO carries an absolute expiry (fail closed).
    "break_glass": (5, 300),
    # Phase 8 SCIM HTTP: per-credential and global ceilings sized for the
    # §47 provisioning scale test (250+ operations per minute), while the
    # administrative `scim` (200/60) gate stays unchanged.
    "scim_auth": (600, 60),
    "scim_write": (600, 60),
    "scim_global": (2000, 60),
    "sso_callback": (30, 300),
    "sso_start": (10, 300),
    "scim": (200, 60),
    "session_revoke": (60, 60),
}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _epoch() -> float:
    return time.time()


def _parse_ts(ts: str) -> float:
    if not ts:
        return 0.0
    try:
        return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return 0.0


def _iso_from_epoch(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


def subject_hash(identifier: str) -> str:
    """Pseudonymous, non-reversible tag for failed-auth audit records.
    Never stores the identifier itself."""
    return hashlib.sha256(("auth:" + str(identifier).strip().lower())
                          .encode("utf-8")).hexdigest()[:16]


def token_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_token(kind: str) -> str:
    return TOKEN_PREFIXES.get(kind, "") + secrets.token_urlsafe(32)


class PasswordHasher:
    """scrypt password hashing (stdlib hashlib — no custom cryptography)."""

    def __init__(self, n: int = SCRYPT_N_DEFAULT, r: int = SCRYPT_R,
                 p: int = SCRYPT_P):
        self.n = int(n)
        self.r = int(r)
        self.p = int(p)
        self._dummy: str | None = None

    def dummy_hash(self) -> str:
        """Fixed-format hash used to keep unknown-user logins constant-time."""
        if self._dummy is None:
            self._dummy = self.hash("dummy-password-for-timing")
        return self._dummy

    def _derive(self, password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                              n=self.n, r=self.r, p=self.p,
                              dklen=DK_LEN)

    def hash(self, password: str) -> str:
        salt = secrets.token_bytes(SALT_LEN)
        dk = self._derive(password, salt)
        return ("scrypt$%d$%d$%d$%s$%s" % (
            self.n, self.r, self.p,
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(dk).decode("ascii")))

    def verify(self, stored: str, password: str) -> bool:
        """Constant-time verification; unknown/malformed schemes → False."""
        if not stored or not isinstance(stored, str):
            return False
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        try:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            salt = base64.b64decode(parts[4])
            want = base64.b64decode(parts[5])
        except Exception:
            return False
        try:
            got = self._derive(password, salt) if (n, r, p) == \
                (self.n, self.r, self.p) else hashlib.scrypt(
                password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                dklen=len(want))
        except Exception:
            return False
        return hmac.compare_digest(got, want)


def validate_password_policy(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise errors.ValidationError(
            f"Password must be at least {MIN_PASSWORD_LEN} characters")
    if len(password) > MAX_PASSWORD_LEN:
        raise errors.ValidationError(
            f"Password must be at most {MAX_PASSWORD_LEN} characters")
    if password.strip() != password:
        raise errors.ValidationError("Password must not start/end with space")


class RateLimiter:
    """Bounded in-memory sliding-window throttle (foundation).
    Thread-safe; keys expire; global size capped (oldest purged first) so a
    hostile peer cannot exhaust memory. Not a distributed limiter."""

    def __init__(self, max_keys: int = 4096):
        self.max_keys = int(max_keys)
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _purge(self, key: str, window: float, now: float) -> list[float]:
        hits = self._hits.get(key)
        if not hits:
            return []
        cutoff = now - window
        keep = [t for t in hits if t > cutoff]
        self._hits[key] = keep
        return keep

    def allowed(self, key: str, limit: int, window: int,
                cost: int = 1) -> tuple[bool, int]:
        """Record `cost` hits for key; return (allowed, retry_after_secs)."""
        now = _epoch()
        with self._lock:
            hits = self._purge(key, float(window), now)
            if len(hits) + cost > limit:
                retry = int(max(1.0, window - (now - (hits[0] if hits else now))))
                self._evict_if_full(key)
                return False, retry
            self._hits.setdefault(key, []).extend([now] * cost)
            self._evict_if_full(key)
            return True, 0

    def _evict_if_full(self, key: str) -> None:
        """Memory bound: never exceed max_keys (drop the stalest keys)."""
        if len(self._hits) <= self.max_keys:
            return
        try:
            stale = sorted(self._hits, key=lambda k: self._hits[k][-1])
            for victim in stale[: len(self._hits) - self.max_keys]:
                self._hits.pop(victim, None)
        except Exception:
            self._hits.clear()


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------
class IdentityService:
    """Identity/credential operations on the shared platform database.
    `platform` provides the store + audit + org/project lookups; every
    security-sensitive event lands in the audit trail through it."""

    def __init__(self, platform, *, scrypt_n: int = SCRYPT_N_DEFAULT,
                 session_ttl: int = SESSION_TTL_SECONDS,
                 reset_ttl: int = RESET_TTL_SECONDS,
                 rl: RateLimiter | None = None):
        self.platform = platform
        self.db = platform.db
        self.hasher = PasswordHasher(n=scrypt_n)
        self.session_ttl = int(session_ttl)
        self.reset_ttl = int(reset_ttl)
        self.limiter = rl or RateLimiter()

    # ---------------------------------------------------------- audit helper
    def _audit(self, action: str, **kw):
        """Audit never breaks identity operations; never contains secrets."""
        try:
            self.platform.audit(action, **kw)
        except Exception:
            pass

    def _audit_actor(self, actor: str) -> str:
        return str(actor or "identity")[:128]

    # ------------------------------------------------------------- rate limit
    def _throttle(self, kind: str, key: str) -> None:
        limit, window = RL_LIMITS.get(kind, (60, 60))
        ok, retry = self.limiter.allowed(f"{kind}:{key}", limit, window)
        if not ok:
            self._audit("auth.rate_limited", actor="identity",
                        metadata={"kind": kind})
            raise errors.RateLimitedError("Too many attempts",
                                          retry_after=retry)

    # ---------------------------------------------------------------- users
    def user_create(self, org_id: str, username: str, email: str,
                    password: str, roles=("viewer",), *,
                    display_name: str = "", as_roles=None,
                    as_permissions=None,
                    allow_any_role: bool = False,
                    actor: str = "identity") -> models.User:
        """Create a user. Role grants are guarded by `as_roles` (caller's
        roles) — escalation attempts raise AuthorizationError; and when
        `as_permissions` is supplied the caller must actually hold the
        `user.create` permission (defense in depth). Pass
        allow_any_role=True ONLY for the explicit local bootstrap path."""
        self.platform.org_require(org_id)
        roles = tuple(rbac.validate_role(r) for r in (roles or ("viewer",)))
        if not allow_any_role:
            if as_permissions is not None and \
                    "user.create" not in as_permissions:
                raise errors.AuthorizationError("Forbidden")
            if not rbac.can_assign_role(as_roles or (), roles[0]):
                raise errors.AuthorizationError("Forbidden")
            for r in roles:
                if not rbac.can_assign_role(as_roles or (), r):
                    raise errors.AuthorizationError("Forbidden")
        validate_password_policy(password)
        user = models.User(org_id=org_id, username=username, email=email,
                           display_name=display_name or username)
        user.finalize()
        user.password_hash = self.hasher.hash(password)
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO users (id, org_id, username, email, "
                    "display_name, status, password_hash, failed_attempts, "
                    "locked_until, created_at, updated_at, last_auth_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (user.id, user.org_id, user.username, user.email,
                     user.display_name, user.status, user.password_hash, 0,
                     "", user.created_at, user.updated_at, ""))
                for r in roles:
                    conn.execute(
                        "INSERT OR IGNORE INTO user_roles (user_id, role) "
                        "VALUES (?,?)", (user.id, r))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise errors.DuplicateError(
                    "Username or email already registered") from e
            raise errors.PersistenceError(f"user create failed: {e}") from e
        self._audit("user.created", object_type="user", object_id=user.id,
                    org_id=org_id, actor=self._audit_actor(actor),
                    metadata={"username": user.username, "roles": roles})
        return user

    def user_get(self, user_id: str) -> models.User:
        row = self.db.query_one("SELECT * FROM users WHERE id=?",
                                (user_id,))
        return models.User.from_dict(row)

    def user_roles(self, user_id: str):
        rows = self.db.query("SELECT role FROM user_roles WHERE user_id=?",
                             (user_id,))
        return tuple(r["role"] for r in rows)

    def user_list(self, org_id: str, limit: int = 500) -> list[models.User]:
        self.platform.org_require(org_id)
        rows = self.db.query(
            "SELECT * FROM users WHERE org_id=? ORDER BY created_at",
            (org_id,), limit=limit)
        return [models.User.from_dict(r) for r in rows]

    def user_set_roles(self, user_id: str, roles, *, as_roles=None,
                       as_permissions=None,
                       allow_any_role: bool = False,
                       actor: str = "identity") -> tuple:
        roles = tuple(rbac.validate_role(r) for r in (roles or ()))
        if not allow_any_role:
            if as_permissions is not None and \
                    "role.assign" not in as_permissions:
                raise errors.AuthorizationError("Forbidden")
            if not roles or not rbac.can_assign_role(as_roles or (), roles[0]) \
                    or any(not rbac.can_assign_role(as_roles or (), r)
                           for r in roles):
                raise errors.AuthorizationError("Forbidden")
        user = self.user_get(user_id)
        try:
            with self.db.transaction() as conn:
                conn.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
                for r in roles:
                    conn.execute(
                        "INSERT OR IGNORE INTO user_roles (user_id, role) "
                        "VALUES (?,?)", (user_id, r))
                conn.execute("UPDATE users SET updated_at=? WHERE id=?",
                             (models.utcnow(), user_id))
        except Exception as e:
            raise errors.PersistenceError(f"role update failed: {e}") from e
        self._audit("user.role_changed", object_type="user", object_id=user_id,
                    org_id=user.org_id, actor=self._audit_actor(actor),
                    metadata={"roles": list(roles)})
        return roles

    def user_set_status(self, user_id: str, status: str,
                        actor: str = "identity") -> models.User:
        if status not in models.USER_STATUSES:
            raise errors.ValidationError(f"Invalid user status: {status}")
        user = self.user_get(user_id)
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE users SET status=?, updated_at=?, deactivated_at=?"
                " WHERE id=?", (status, models.utcnow(),
                                models.utcnow() if status == "deactivated"
                                else "", user_id))
            if status in ("disabled", "deactivated", "suspended"):
                # invalidate every active session immediately (with a
                # durable revocation reason for reporting/audit)
                conn.execute(
                    "UPDATE sessions SET revoked_at=?, revoke_reason=? "
                    "WHERE user_id=? AND revoked_at=''",
                    (models.utcnow(), "user_status:" + status, user_id))
        self._audit("user.disabled" if status == "disabled" else "user.enabled",
                    object_type="user", object_id=user_id, org_id=user.org_id,
                    actor=self._audit_actor(actor))
        return self.user_get(user_id)

    def user_set_password(self, user_id: str, new_password: str,
                          actor: str = "identity") -> None:
        validate_password_policy(new_password)
        user = self.user_get(user_id)
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE users SET password_hash=?, updated_at=?, "
                "failed_attempts=0, locked_until='' WHERE id=?",
                (self.hasher.hash(new_password), models.utcnow(), user_id))
            conn.execute(
                "UPDATE sessions SET revoked_at=? WHERE user_id=? "
                "AND revoked_at=''",
                (models.utcnow(), user_id))
        self._audit("user.password_changed", object_type="user",
                    object_id=user_id, org_id=user.org_id,
                    actor=self._audit_actor(actor))

    # --------------------------------------------------------- membership
    def member_set(self, user_id: str, project_id: str, role: str, *,
                   as_roles=None, allow_any_role: bool = False,
                   actor: str = "identity") -> None:
        """Project-scoped membership (role applies to that project only).
        The project must belong to the user's own organization."""
        project = self.platform.project_require(project_id)
        user = self.user_get(user_id)
        if project.org_id != user.org_id:
            raise errors.AuthorizationError("Forbidden")
        rbac.validate_role(role)
        if not allow_any_role and not rbac.can_assign_role(as_roles or (), role):
            raise errors.AuthorizationError("Forbidden")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO project_members "
                "(user_id, project_id, role) VALUES (?,?,?)",
                (user_id, project_id, role))
        self._audit("user.role_changed", object_type="project",
                    object_id=project_id, org_id=user.org_id,
                    project_id=project_id, actor=self._audit_actor(actor),
                    metadata={"user": user_id, "role": role})

    def memberships_of(self, user_id: str) -> list[dict]:
        rows = self.db.query(
            "SELECT project_id, role FROM project_members WHERE user_id=?",
            (user_id,))
        return [{"project_id": r["project_id"], "role": r["role"]} for r in rows]

    # ---------------------------------------------------------- auth/session
    def login(self, identifier: str, password: str, *,
              ip: str = "", actor: str = "login",
              mfa_required=None) -> dict:
        """Authenticate a user. ALL failure modes produce the identical
        generic error (no account/token enumeration). Returns
        {user, session, secret, mfa_required} on success.

        `mfa_required` is an optional injected callable
        (user, roles) -> bool supplied by the enterprise identity layer so
        MFA-policy evaluation happens AT session establishment without this
        module depending on Phase-8 policy code. A session created under a
        required policy is PARTIALLY authenticated (mfa_status='pending',
        short TTL) until MFA completes."""
        ident = str(identifier or "").strip().lower()
        self._throttle("auth", f"{subject_hash(ident)}|{ip}")
        self._throttle("auth_ip", ip or "0.0.0.0")
        user = self._resolve_login_user(ident)
        if user is not None:
            if user.status != "active":
                user = None
            elif _parse_ts(user.locked_until) > _epoch():
                user = None
        # constant-time shape even for unknown users (no timing oracle):
        # verify against a fixed dummy hash when there is no user.
        if user is None:
            ok = self.hasher.verify(self.hasher.dummy_hash(),
                                    str(password or ""))
        else:
            ok = self.hasher.verify(user.password_hash, str(password or ""))
        if not ok:
            self._audit("login_failure", actor=self._audit_actor(actor),
                        metadata={"subject": subject_hash(ident),
                                  "ip": str(ip)[:64]})
            if user is not None:
                self._bump_lockout(user.id)
            raise errors.AuthenticationError("Invalid credentials")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts=0, locked_until='', "
                "last_auth_at=?, updated_at=? WHERE id=?",
                (models.utcnow(), models.utcnow(), user.id))
        self._audit("login_success", object_type="user", object_id=user.id,
                    org_id=user.org_id, actor=self._audit_actor(actor),
                    metadata={"roles": list(self.user_roles(user.id))})
        roles = self.user_roles(user.id)
        mfa_need = bool(mfa_required(user, roles)) if mfa_required else False
        sess = self.session_create(user.id, ip=ip, actor=actor,
                                   auth_method="password",
                                   mfa_status="pending" if mfa_need
                                   else "none")
        return {"user": self.user_get(user.id), "session": sess["session"],
                "secret": sess["secret"], "mfa_required": mfa_need}

    def _resolve_login_user(self, ident: str) -> models.User | None:
        if not ident:
            return None
        rows = self.db.query(
            "SELECT * FROM users WHERE email=? LIMIT 2", (ident,))
        if len(rows) == 1:
            return models.User.from_dict(rows[0])
        rows = self.db.query(
            "SELECT * FROM users WHERE username=? LIMIT 2", (ident,))
        if len(rows) == 1:
            return models.User.from_dict(rows[0])
        return None

    def _bump_lockout(self, user_id: str) -> None:
        rows = self.db.query(
            "SELECT failed_attempts FROM users WHERE id=?", (user_id,))
        if not rows:
            return
        attempts = int(rows[0].get("failed_attempts", 0) or 0) + 1
        locked_until = ""
        if attempts >= AUTH_LOCK_MAX_FAILURES:
            locked_until = _iso_from_epoch(_epoch() + AUTH_LOCK_SECONDS)
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? "
                "WHERE id=?", (attempts, locked_until, user_id))

    def session_create(self, user_id: str, *, ip: str = "",
                       user_agent: str = "", actor: str = "identity",
                       auth_method: str = "password",
                       mfa_status: str = "none",
                       idp_subject: str = "", provider_id: str = "",
                       step_up: bool = False) -> dict:
        """Create a hardened session. `mfa_status` is one of
        none|pending|verified; pending sessions (MFA policy not yet
        satisfied) get the short pending TTL. `absolute_expires_at` is set
        to the hard lifetime ceiling regardless of refreshes."""
        user = self.user_get(user_id)          # validates existence
        if user.status != "active":
            raise errors.AuthenticationError("Invalid credentials")
        self._throttle("session_create", user_id)
        secret = generate_token("session")
        now = models.utcnow()
        sess = models.SessionRecord(
            user_id=user_id, token_hash=token_hash(secret),
            ip=str(ip)[:64], user_agent=str(user_agent)[:256],
            auth_method=str(auth_method)[:32],
            mfa_status=mfa_status if mfa_status in ("none", "pending",
                                                    "verified") else "none",
            idp_subject=str(idp_subject)[:256],
            provider_id=str(provider_id)[:96])
        sess.finalize()
        if sess.mfa_status == "pending":
            sess.expires_at = _iso_from_epoch(
                _epoch() + PENDING_MFA_TTL_SECONDS)
        else:
            sess.expires_at = _iso_from_epoch(_epoch() + self.session_ttl)
        if sess.mfa_status == "verified":
            sess.step_up_until = _iso_from_epoch(
                _epoch() + self.session_ttl)
        sess.absolute_expires_at = _iso_from_epoch(
            _epoch() + ABSOLUTE_SESSION_TTL_SECONDS)
        try:
            self.db.execute(
                "INSERT INTO sessions (id, user_id, token_hash, ip, "
                "user_agent, created_at, last_seen_at, expires_at, "
                "revoked_at, auth_method, mfa_status, step_up_until, "
                "idp_subject, provider_id, absolute_expires_at, "
                "revoke_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sess.id, sess.user_id, sess.token_hash, sess.ip,
                 sess.user_agent, sess.created_at, sess.last_seen_at,
                 sess.expires_at, "", sess.auth_method, sess.mfa_status,
                 sess.step_up_until, sess.idp_subject, sess.provider_id,
                 sess.absolute_expires_at, ""))
        except Exception as e:
            raise errors.PersistenceError(f"session create failed: {e}") from e
        self._audit("session.created", object_type="session",
                    object_id=sess.id, org_id=user.org_id,
                    actor=self._audit_actor(actor),
                    metadata={"method": sess.auth_method,
                              "mfa": sess.mfa_status})
        return {"session": sess, "secret": secret}

    def session_authenticate(self, secret: str) -> models.SessionRecord:
        if not secret or not secret.startswith(TOKEN_PREFIXES["session"]):
            raise errors.AuthenticationError("Invalid credentials")
        rows = self.db.query(
            "SELECT * FROM sessions WHERE token_hash=? LIMIT 1",
            (token_hash(secret),))
        if not rows:
            raise errors.AuthenticationError("Invalid credentials")
        sess = models.SessionRecord.from_dict(rows[0])
        if sess.revoked_at:
            raise errors.AuthenticationError("Invalid credentials")
        now = _epoch()
        user = self.user_get(sess.user_id)
        if user.status != "active":
            self.session_revoke_id(sess.id, reason="identity_inactive")
            raise errors.AuthenticationError("Invalid credentials")
        if _parse_ts(sess.expires_at) < now:
            self.session_revoke_id(sess.id, reason="expired")
            raise errors.AuthenticationError("Invalid credentials")
        abs_exp = _parse_ts(sess.absolute_expires_at)
        if abs_exp and abs_exp < now:
            self.session_revoke_id(sess.id, reason="absolute_expiry")
            raise errors.AuthenticationError("Invalid credentials")
        # idle timeout: a session unused longer than the idle window is
        # revoked even though its original TTL may not have elapsed
        idle_at = _parse_ts(sess.last_seen_at)
        if idle_at and (now - idle_at) > self.session_ttl:
            self.session_revoke_id(sess.id, reason="idle_timeout")
            raise errors.AuthenticationError("Invalid credentials")
        with self.db.transaction() as conn:
            conn.execute("UPDATE sessions SET last_seen_at=? WHERE id=?",
                         (models.utcnow(), sess.id))
        return sess

    def session_revoke_id(self, session_id: str, *, reason: str = "") -> None:
        try:
            self.db.execute(
                "UPDATE sessions SET revoked_at=?, revoke_reason=? WHERE id=?",
                (models.utcnow(), str(reason or "")[:64], session_id))
            self._audit("session.revoked", object_type="session",
                        object_id=session_id, actor=self._audit_actor(
                            "identity"),
                        metadata={"reason": str(reason or "")[:64]})
        except Exception:
            pass

    def session_step_up(self, session_id: str, *, ttl_seconds: int = 600,
                        actor: str = "identity") -> None:
        """Short-lived elevated window for a session (time-bounded, session
        scoped). Revoked/expired sessions cannot be elevated."""
        ttl = max(60, min(3600, int(ttl_seconds)))
        sess = self.db.query_one(
            "SELECT id, revoked_at, expires_at, absolute_expires_at "
            "FROM sessions WHERE id=? LIMIT 1", (session_id,))
        if not sess or sess.get("revoked_at"):
            raise errors.NotFoundError("no such session")
        until = _iso_from_epoch(_epoch() + ttl)
        abs_exp = _parse_ts(sess.get("absolute_expires_at", ""))
        if abs_exp and _parse_ts(until) > abs_exp:
            until = _iso_from_epoch(abs_exp)
        self.db.execute(
            "UPDATE sessions SET step_up_until=? WHERE id=?",
            (until, session_id))
        self._audit("identity.session.step_up", object_type="session",
                    object_id=session_id, actor=self._audit_actor(actor),
                    metadata={"ttl": ttl})

    def session_mfa_complete(self, session_id: str, *, actor: str = "identity"):
        """Mark a session fully authenticated after a successful MFA
        challenge (idempotent)."""
        row = self.db.query_one(
            "SELECT id, mfa_status FROM sessions WHERE id=? LIMIT 1",
            (session_id,))
        if not row:
            raise errors.NotFoundError("no such session")
        if row["mfa_status"] == "verified":
            return
        self.db.execute(
            "UPDATE sessions SET mfa_status='verified', step_up_until=?, "
            "expires_at=?, last_seen_at=? WHERE id=?",
            (_iso_from_epoch(_epoch() + self.session_ttl),
             _iso_from_epoch(_epoch() + self.session_ttl),
             models.utcnow(), session_id))
        self._audit("session.updated", object_type="session",
                    object_id=session_id, actor=self._audit_actor(actor),
                    metadata={"mfa": "verified"})

    def sessions_revoke_all(self, user_id: str, *, reason: str = "revoked",
                            actor: str = "identity") -> int:
        """Revoke every non-revoked session of a user (password reset / MFA
        reset / deactivation). Returns the number revoked."""
        rows = self.db.query(
            "SELECT id FROM sessions WHERE user_id=? AND revoked_at=''",
            (user_id,))
        n = 0
        for r in rows:
            self.session_revoke_id(r["id"], reason=reason)
            n += 1
        if n:
            self._audit("identity.session.revoked_all", object_type="user",
                        object_id=user_id, actor=self._audit_actor(actor),
                        metadata={"reason": reason[:64], "count": n})
        return n

    def sessions_revoke_org(self, org_id: str, *, reason: str = "org_revoke",
                            actor: str = "identity") -> int:
        """Organization-wide emergency revocation (bounded per call)."""
        self.platform.org_require(org_id)
        rows = self.db.query(
            "SELECT s.id FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE u.org_id=? AND s.revoked_at='' LIMIT 500", (org_id,))
        n = 0
        for r in rows:
            self.session_revoke_id(r["id"], reason=reason)
            n += 1
        self._audit("identity.session.revoked_all", object_type="organization",
                    object_id=org_id, org_id=org_id,
                    actor=self._audit_actor(actor),
                    metadata={"reason": reason[:64], "count": n})
        return n

    def sessions_list_org(self, org_id: str, *, limit: int = 100,
                          offset: int = 0,
                          status: str = "active") -> dict:
        """Admin view of an organization's sessions (no token material)."""
        self.platform.org_require(org_id)
        limit = max(1, min(500, int(limit)))
        offset = max(0, min(100000, int(offset)))
        where = "u.org_id=?"
        params: list = [org_id]
        if status == "active":
            where += " AND s.revoked_at=''"
        elif status == "revoked":
            where += " AND s.revoked_at<>''"
        elif status:
            raise errors.ValidationError(
                f"session_status_unknown: {status!r}")
        rows = self.db.query(
            "SELECT s.id, s.user_id, u.username, u.email, s.ip, "
            "s.auth_method, s.mfa_status, s.provider_id, s.created_at, "
            "s.last_seen_at, s.expires_at, s.absolute_expires_at, "
            "s.revoked_at, s.revoke_reason FROM sessions s JOIN users u "
            "ON u.id=s.user_id WHERE " + where +
            " ORDER BY s.last_seen_at DESC LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset))
        total = int(self.db.query_one(
            "SELECT COUNT(*) n FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE " + where, tuple(params))["n"])
        return {"count": len(rows), "total": total, "limit": limit,
                "offset": offset, "sessions": [dict(r) for r in rows]}

    def logout(self, secret: str, actor: str = "identity") -> None:
        if not secret:
            return
        try:
            sess = self.session_authenticate(secret)
            self.session_revoke_id(sess.id)
            self._audit("logout", object_type="session", object_id=sess.id,
                        actor=self._audit_actor(actor))
        except errors.AuthenticationError:
            pass   # logout of an unknown session: silent, generic

    def sessions_list(self, user_id: str, limit: int = 50):
        rows = self.db.query(
            "SELECT id, user_id, ip, created_at, last_seen_at, expires_at, "
            "revoked_at FROM sessions WHERE user_id=? ORDER BY last_seen_at "
            "DESC", (user_id,), limit=limit)
        return [models.SessionRecord.from_dict(r) for r in rows]

    # --------------------------------------------------------- API credentials
    def credential_create(self, org_id: str, name: str, scopes, *,
                          created_by: str = "", project_id: str = "",
                          ttl_seconds: int = 0, as_permissions=None,
                          actor: str = "identity") -> dict:
        """Create an API credential. Secret is returned exactly once.
        `as_permissions` (caller's effective permission set) gates the
        requested scopes so a key can never carry a broader grant than its
        creator. ttl_seconds=0 ⇒ no expiry."""
        self.platform.org_require(org_id)
        scopes = tuple(str(s) for s in (scopes or ()))
        unknown = [s for s in scopes if s not in rbac.PERMISSIONS]
        if unknown:
            raise errors.ValidationError(
                f"Unknown credential scope(s): {unknown}")
        if as_permissions is not None:
            extra = set(scopes) - set(as_permissions)
            if extra:
                raise errors.AuthorizationError("Forbidden")
        if project_id:
            project = self.platform.project_require(project_id)
            if project.org_id != org_id:
                raise errors.AuthorizationError("Forbidden")
        secret = generate_token("credential")
        cred = models.ApiCredential(
            org_id=org_id, name=name, key_prefix=secret[:10],
            verifier=token_hash(secret), scopes=list(scopes),
            created_by=str(created_by)[:128], project_id=project_id or "")
        cred.finalize()
        cred.expires_at = (_iso_from_epoch(_epoch() + ttl_seconds)
                           if ttl_seconds and ttl_seconds > 0 else "")
        try:
            self.db.execute(
                "INSERT INTO api_credentials (id, org_id, project_id, name, "
                "key_prefix, verifier, scopes, status, created_by, "
                "created_at, last_used_at, expires_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (cred.id, cred.org_id, cred.project_id or None, cred.name,
                 cred.key_prefix, cred.verifier, self.db_json(cred.scopes),
                 cred.status, cred.created_by, cred.created_at, "",
                 cred.expires_at))
        except Exception as e:
            raise errors.PersistenceError(
                f"credential create failed: {e}") from e
        self._audit("credential.created", object_type="credential",
                    object_id=cred.id, org_id=org_id,
                    actor=self._audit_actor(actor),
                    metadata={"name": cred.name,
                              "scopes": list(scopes),
                              "prefix": cred.key_prefix})
        return {"credential": cred, "secret": secret}

    def credential_authenticate(self, secret: str) -> models.ApiCredential:
        if not secret or not secret.startswith(TOKEN_PREFIXES["credential"]):
            raise errors.AuthenticationError("Invalid credentials")
        rows = self.db.query(
            "SELECT * FROM api_credentials WHERE verifier=? LIMIT 1",
            (token_hash(secret),))
        if not rows:
            raise errors.AuthenticationError("Invalid credentials")
        cred = models.ApiCredential.from_dict(rows[0])
        # documented policy: API keys of a non-active owner are rejected at
        # authentication time (machine credentials remain non-human, but a
        # deactivated human account must not keep working through its keys)
        if cred.created_by:
            owner = self.db.query_one(
                "SELECT status FROM users WHERE id=? LIMIT 1",
                (cred.created_by,))
            if not owner or owner["status"] != "active":
                raise errors.AuthenticationError("Invalid credentials")
        if cred.status == "revoked":
            raise errors.AuthenticationError("Invalid credentials")
        if cred.status == "expired":
            raise errors.AuthenticationError("Invalid credentials")
        if cred.expires_at and _parse_ts(cred.expires_at) < _epoch():
            try:
                self.db.execute(
                    "UPDATE api_credentials SET status='expired' WHERE id=?",
                    (cred.id,))
            except Exception:
                pass
            self._audit("credential.expired", object_type="credential",
                        object_id=cred.id, org_id=cred.org_id,
                        actor="identity",
                        metadata={"name": cred.name,
                                  "prefix": cred.key_prefix})
            raise errors.AuthenticationError("Invalid credentials")
        last_used = models.utcnow()
        try:
            self.db.execute(
                "UPDATE api_credentials SET last_used_at=? WHERE id=?",
                (last_used, cred.id))
        except Exception:
            pass
        cred.last_used_at = last_used
        return cred

    def credential_list(self, org_id: str, limit: int = 200) \
            -> list[models.ApiCredential]:
        self.platform.org_require(org_id)
        rows = self.db.query(
            "SELECT * FROM api_credentials WHERE org_id=? "
            "ORDER BY created_at", (org_id,), limit=limit)
        return [models.ApiCredential.from_dict(r) for r in rows]

    def credential_get(self, credential_id: str) -> models.ApiCredential:
        rows = self.db.query(
            "SELECT * FROM api_credentials WHERE id=? LIMIT 1",
            (credential_id,))
        if not rows:
            raise errors.NotFoundError("Credential not found")
        return models.ApiCredential.from_dict(rows[0])

    def credential_revoke(self, credential_id: str, *,
                          actor: str = "identity") -> models.ApiCredential:
        cred = self.credential_get(credential_id)
        self.db.execute(
            "UPDATE api_credentials SET status='revoked' WHERE id=?",
            (credential_id,))
        self._audit("credential.revoked", object_type="credential",
                    object_id=credential_id, org_id=cred.org_id,
                    actor=self._audit_actor(actor),
                    metadata={"name": cred.name, "prefix": cred.key_prefix})
        return self.credential_get(credential_id)

    def credential_rotate(self, credential_id: str, *,
                          as_permissions=None,
                          actor: str = "identity") -> dict:
        """Issue a new secret for the same credential. Scopes are carried
        over VERBATIM — rotation never silently broadens permissions."""
        cred = self.credential_get(credential_id)
        if cred.status != "active":
            raise errors.AuthenticationError("Invalid credentials")
        if as_permissions is not None:
            extra = set(cred.scopes) - set(as_permissions)
            if extra:
                raise errors.AuthorizationError("Forbidden")
        secret = generate_token("credential")
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "UPDATE api_credentials SET verifier=? WHERE id=?",
                    (token_hash(secret), credential_id))
        except Exception as e:
            raise errors.PersistenceError(f"credential rotate failed: {e}") from e
        self._audit("credential.rotated", object_type="credential",
                    object_id=credential_id, org_id=cred.org_id,
                    actor=self._audit_actor(actor),
                    metadata={"name": cred.name, "prefix": cred.key_prefix})
        return {"credential": self.credential_get(credential_id), "secret": secret}

    # ---------------------------------------------------------- password reset
    def password_reset_request(self, identifier: str, *,
                               actor: str = "identity") -> dict:
        """Generic response ALWAYS (no account enumeration). Returns the
        one-time token to the SERVICE boundary (caller decides delivery).
        No email infrastructure is faked in this phase."""
        ident = str(identifier or "").strip().lower()
        user = self._resolve_login_user(ident)
        if user is None or user.status != "active":
            self._audit("password.reset_requested", actor=actor,
                        metadata={"requested": True})
            return {"requested": True, "token": ""}
        self._throttle("session_create", user.id)   # reuse bounded bucket
        secret = generate_token("reset")
        rec = models.PasswordReset(user_id=user.id,
                                   token_hash=token_hash(secret))
        rec.finalize()
        rec.expires_at = _iso_from_epoch(_epoch() + self.reset_ttl)
        self.db.execute(
            "INSERT INTO password_resets (id, user_id, token_hash, "
            "created_at, expires_at, used_at) VALUES (?,?,?,?,?,?)",
            (rec.id, rec.user_id, rec.token_hash, rec.created_at,
             rec.expires_at, ""))
        self._audit("password.reset_requested", object_type="user",
                    object_id=user.id, org_id=user.org_id,
                    actor=self._audit_actor(actor))
        return {"requested": True, "token": secret}

    def password_reset_consume(self, token: str, new_password: str, *,
                               actor: str = "identity") -> None:
        if not token or not token.startswith(TOKEN_PREFIXES["reset"]):
            raise errors.AuthenticationError("Invalid credentials")
        validate_password_policy(new_password)
        rows = self.db.query(
            "SELECT * FROM password_resets WHERE token_hash=? LIMIT 1",
            (token_hash(token),))
        if not rows:
            raise errors.AuthenticationError("Invalid credentials")
        rec = models.PasswordReset.from_dict(rows[0])
        if rec.used_at:
            raise errors.AuthenticationError("Invalid credentials")
        if _parse_ts(rec.expires_at) < _epoch():
            raise errors.AuthenticationError("Invalid credentials")
        user = self.user_get(rec.user_id)
        with self.db.transaction() as conn:
            conn.execute("UPDATE password_resets SET used_at=? WHERE id=?",
                         (models.utcnow(), rec.id))
            conn.execute(
                "UPDATE users SET password_hash=?, updated_at=?, "
                "failed_attempts=0, locked_until='' WHERE id=?",
                (self.hasher.hash(new_password), models.utcnow(), user.id))
            conn.execute(
                "UPDATE sessions SET revoked_at=? WHERE user_id=? "
                "AND revoked_at=''", (models.utcnow(), user.id))
        self._audit("password.reset_consumed", object_type="user",
                    object_id=user.id, org_id=user.org_id,
                    actor=self._audit_actor(actor))

    # ------------------------------------------------------------------ misc
    @staticmethod
    def db_json(value) -> str:
        import json as _json
        return _json.dumps(value, ensure_ascii=False, separators=(",", ":"))
