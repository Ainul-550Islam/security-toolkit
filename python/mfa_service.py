#!/usr/bin/env python3
# ============================================================================
#  mfa_service.py — Phase 8 enterprise MFA (TOTP + recovery codes + policy).
#  ---------------------------------------------------------------------------
#  Extends the EXISTING identity model (users/sessions are the one truth).
#  No second authentication architecture: the challenge completes a session
#  that password/SSO authentication already created.
#
#  Security properties:
#    - TOTP seeds: 160-bit random, stored ENCRYPTED at rest via the existing
#      notify key-file wrap (never plaintext, never in audit/logs/exports).
#    - Activation REQUIRES a successful TOTP verification at enrollment time
#      (generating a secret never enables MFA).
#    - Replay resistance: the accepted time-step is persisted; an already
#      used step (or an older one) is never accepted again.
#    - Recovery codes: 128-bit random, shown exactly once, stored salted
#      HMAC-SHA256 verifiers only, single-use, regenerating invalidates all
#      previous codes.
#    - Brute force: rate limits + per-user code attempt lockout.
#    - MFA policy: optional | roles | required; evaluation is deterministic
#      and FAILS CLOSED (invalid stored policy is treated as "required").
#    - Step-up: time-bounded elevation written on the session row, enforced
#      centrally by authz (never scattered through handlers).
# ============================================================================

from __future__ import annotations

import json
import secrets
import time

import errors
import identity as identity_mod
import models
import notify
import redact
import totp

# policy modes
POLICY_MODES = ("optional", "roles", "required")
_DEFAULT_POLICY = {"mode": "optional", "roles": [], "step_up_ttl": 600,
                   "require_recent": 900}

MAX_ATTEMPTS = 5
LOCK_SECONDS = 15 * 60
RECOVERY_COUNT = totp.RECOVERY_CODE_COUNT
MAX_RECOVERY_COUNT = 20


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


class MfaService:
    """MFA lifecycle on the shared platform (extend-only; sessions/users are
    the existing ones)."""

    def __init__(self, platform, *, identity_svc=None):
        self.svc = platform
        self.db = platform.db
        self.identity = identity_svc or identity_mod.IdentityService(platform)
        self.limiter = self.identity.limiter

    # ------------------------------------------------------------ helpers
    def _throttle(self, kind: str, key: str) -> None:
        limit, window = identity_mod.RL_LIMITS.get(kind, (60, 60))
        ok, retry = self.limiter.allowed(f"{kind}:{key}", limit, window)
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
            pass    # auditing never breaks identity operations

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

    def _user(self, user_id: str) -> dict | None:
        rows = self.db.query("SELECT * FROM users WHERE id=? LIMIT 1",
                             (user_id,))
        return rows[0] if rows else None

    def _seed_encrypt(self, seed: str) -> str:
        return notify._encrypt_secret(seed, self.svc.db_path)

    def _seed_decrypt(self, blob: str) -> str:
        return notify._decrypt_secret(blob, self.svc.db_path)

    # ------------------------------------------------------------- policy
    def policy_get(self, org_id: str) -> dict:
        rows = self.db.query("SELECT * FROM mfa_policy WHERE org_id=? "
                             "LIMIT 1", (org_id,))
        row = rows[0] if rows else None
        if not row:
            return dict(_DEFAULT_POLICY, org_id=org_id, version=0)
        return {"org_id": org_id, "mode": row["mode"],
                "roles": json.loads(row["roles"] or "[]"),
                "step_up_ttl": int(row["step_up_ttl"]),
                "require_recent": int(row["require_recent"]),
                "version": int(row["version"]),
                "updated_at": row["updated_at"],
                "updated_by": row["updated_by"]}

    def policy_validate(self, policy: dict) -> dict:
        """Deterministic, fail-closed validation: any deviation raises and
        an INVALID STORED policy is later treated as 'required' by
        policy_requires (invalid config never disables MFA)."""
        if not isinstance(policy, dict):
            raise errors.ValidationError("policy_invalid: must be an object")
        allowed = {"mode", "roles", "step_up_ttl", "require_recent"}
        extra = set(policy.keys()) - allowed
        if extra:
            raise errors.ValidationError(
                f"policy_invalid: unknown field(s) {sorted(extra)}")
        mode = str(policy.get("mode", "optional"))
        if mode not in POLICY_MODES:
            raise errors.ValidationError(
                f"policy_invalid: mode must be one of {POLICY_MODES}")
        roles = policy.get("roles", [])
        if not isinstance(roles, list) or len(roles) > 10:
            raise errors.ValidationError("policy_invalid: roles must be a "
                                         "list (max 10)")
        import rbac
        roles = tuple(sorted({rbac.validate_role(r) for r in roles}))
        try:
            step_up_ttl = int(policy.get("step_up_ttl", 600))
            require_recent = int(policy.get("require_recent", 900))
        except (TypeError, ValueError):
            raise errors.ValidationError("policy_invalid: ttl must be an "
                                         "integer") from None
        if not (60 <= step_up_ttl <= 3600):
            raise errors.ValidationError("policy_invalid: step_up_ttl out "
                                         "of range")
        if not (60 <= require_recent <= 86400):
            raise errors.ValidationError("policy_invalid: require_recent out "
                                         "of range")
        return {"mode": mode, "roles": list(roles),
                "step_up_ttl": step_up_ttl,
                "require_recent": require_recent}

    def policy_set(self, org_id: str, policy: dict, *, version: int = 0,
                   actor: str = "identity") -> dict:
        self.svc.org_require(org_id)
        norm = self.policy_validate(policy)
        if int(version) != 0 and int(version) != \
                self.policy_get(org_id)["version"]:
            raise errors.ValidationError(
                "policy_conflict: version mismatch (concurrent update)")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO mfa_policy (org_id, mode, roles, step_up_ttl, "
                "require_recent, version, updated_at, updated_by) VALUES "
                "(?,?,?,?,?,?,?,?) ON CONFLICT(org_id) DO UPDATE SET "
                "mode=excluded.mode, roles=excluded.roles, "
                "step_up_ttl=excluded.step_up_ttl, "
                "require_recent=excluded.require_recent, "
                "version=mfa_policy.version+1, "
                "updated_at=excluded.updated_at, "
                "updated_by=excluded.updated_by",
                (org_id, norm["mode"], json.dumps(norm["roles"]),
                 norm["step_up_ttl"], norm["require_recent"],
                 self.policy_get(org_id)["version"] + 1, _now(),
                 str(actor)[:128]))
        self._audit("identity.policy.updated", object_type="organization",
                    object_id=org_id, org_id=org_id, actor=actor,
                    metadata={"mode": norm["mode"],
                              "roles": list(norm["roles"])})
        self._event(org_id, "mfa_policy.updated", actor=actor,
                    detail={"mode": norm["mode"]})
        return self.policy_get(org_id)

    def policy_requires(self, org_id: str, roles=()) -> bool:
        """Deterministic evaluation at authentication time. FAIL CLOSED:
        an unreadable/invalid stored policy is treated as REQUIRED (never
        silently disabling MFA)."""
        rows = self.db.query("SELECT * FROM mfa_policy WHERE org_id=? "
                             "LIMIT 1", (org_id,))
        row = rows[0] if rows else None
        if not row:
            return False                        # no policy → optional
        mode = str(row["mode"])
        if mode == "required":
            return True
        if mode == "optional":
            return False
        if mode == "roles":
            try:
                roles_p = json.loads(row["roles"] or "[]")
            except Exception:
                return True                     # corrupt → fail closed
            if not isinstance(roles_p, list):
                return True
            return any(str(r) in set(str(x) for x in (roles or ()))
                       for r in roles_p)
        return True                             # unknown mode → REQUIRED

    # ---------------------------------------------------------- enrollment
    def enroll_start(self, user_id: str, *, issuer: str = "SecuToolkit",
                     actor: str = "identity", verified: bool = False) -> dict:
        """Create (or rotate) a TOTP secret. MFA does NOT become active —
        activation requires a successful verification (enroll_verify).

        Security guard (§42): rotating an ACTIVE, verified enrollment is an
        MFA-rebinding vector — a stolen password plus a pending session must
        never let an attacker enroll their own seed. Re-enrollment therefore
        requires a verified step-up context (`verified=True`); a first-time
        enrollment (no existing verified row) remains available so users can
        set up MFA without a prior factor."""
        self._throttle("mfa_enroll", user_id)
        user = self._user(user_id)
        if not user:
            raise errors.NotFoundError("no such user")
        if user["status"] != "active":
            raise errors.ValidationError("user_not_active")
        existing = self.db.query(
            "SELECT enabled FROM mfa_secrets WHERE user_id=? LIMIT 1",
            (user_id,))
        if existing and existing[0]["enabled"] and not verified:
            raise errors.AuthorizationError(
                "mfa_rebind_blocked: MFA is active — re-enrollment requires "
                "an MFA-verified session (login + mfa-challenge first, or "
                "an administrative mfa-reset)")
        seed = totp.generate_seed()
        label = str(user.get("email") or user.get("username") or "user")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO mfa_secrets (user_id, org_id, seed_enc, digits, "
                "step, algorithm, label, last_used_step, attempts, "
                "locked_until, enabled, created_at, verified_at, updated_at, "
                "created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(user_id) DO UPDATE SET seed_enc=excluded."
                "seed_enc, label=excluded.label, enabled=0, "
                "verified_at='', last_used_step=-1, attempts=0, "
                "locked_until='', updated_at=excluded.updated_at",
                (user_id, user["org_id"], self._seed_encrypt(seed),
                 totp.DIGITS, totp.TIME_STEP, "SHA1", label[:128], -1, 0, "",
                 0, _now(), "", _now(), str(actor)[:128]))
        self._audit("identity.mfa.enrolled", object_type="user",
                    object_id=user_id, org_id=user["org_id"], actor=actor,
                    metadata={"active": False})
        self._event(user["org_id"], "mfa.enrolled", actor=actor,
                    detail={"user_id": user_id})
        return {"user_id": user_id, "seed": seed,
                "otpauth": totp.otpauth_uri(issuer, label, seed),
                "enabled": False,
                "verify_required": True}

    def enroll_verify(self, user_id: str, code: str, *, actor: str = "identity",
                      session_id: str = "") -> dict:
        """Verify the enrollment code; ONLY this activates MFA."""
        self._throttle("mfa_verify", user_id)
        user = self._user(user_id)
        if not user:
            raise errors.NotFoundError("no such user")
        rows = self.db.query("SELECT * FROM mfa_secrets WHERE user_id=? "
                             "LIMIT 1", (user_id,))
        row = rows[0] if rows else None
        if not row:
            raise errors.ValidationError("mfa_not_enrolled")
        if _parse_ts(row["locked_until"]) > _epoch():
            raise errors.RateLimitedError(
                "Too many attempts", retry_after=max(
                    1, int(_parse_ts(row["locked_until"]) - _epoch())))
        try:
            seed = self._seed_decrypt(row["seed_enc"])
            ok, step = totp.verify(
                seed, code,
                last_used_step=int(row["last_used_step"]))
        except errors.AuthenticationError:
            raise
        except Exception:
            # corrupt/undecryptable seed: fail CLOSED, never surface
            # crypto internals, never leak the blob
            raise errors.AuthenticationError("Invalid code") from None
        if not ok:
            self._bump_fail(user_id)
            self._audit("identity.mfa.challenge_failure", object_type="user",
                        object_id=user_id, org_id=user["org_id"], actor=actor,
                        metadata={"phase": "enrollment"})
            raise errors.AuthenticationError("Invalid code")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE mfa_secrets SET enabled=1, verified_at=?, "
                "last_used_step=?, attempts=0, locked_until='', "
                "updated_at=? WHERE user_id=?",
                (_now(), step, _now(), user_id))
            conn.execute("UPDATE users SET last_mfa_at=?, updated_at=? "
                         "WHERE id=?", (_now(), _now(), user_id))
        if session_id:
            try:
                self.identity.session_mfa_complete(session_id, actor=actor)
            except Exception:
                pass
        self._audit("identity.mfa.enabled", object_type="user",
                    object_id=user_id, org_id=user["org_id"], actor=actor,
                    metadata={"method": "totp"})
        self._event(user["org_id"], "mfa.enabled", actor=actor,
                    detail={"user_id": user_id})
        return {"user_id": user_id, "enabled": True, "verified_at": _now()}

    def _bump_fail(self, user_id: str) -> None:
        rows = self.db.query(
            "SELECT attempts FROM mfa_secrets WHERE user_id=? LIMIT 1",
            (user_id,))
        row = rows[0] if rows else None
        attempts = int(row["attempts"]) + 1 if row else 1
        locked = _iso_from_epoch(_epoch() + LOCK_SECONDS) if \
            attempts >= MAX_ATTEMPTS else ""
        self.db.execute(
            "UPDATE mfa_secrets SET attempts=?, locked_until=?, updated_at=? "
            "WHERE user_id=?", (attempts, locked, _now(), user_id))

    def mfa_status(self, user_id: str) -> dict:
        rows = self.db.query("SELECT * FROM mfa_secrets WHERE user_id=? "
                             "LIMIT 1", (user_id,))
        row = rows[0] if rows else None
        if not row:
            return {"user_id": user_id, "enabled": False, "method": "none",
                    "enrolled": False, "recovery_codes": 0}
        crows = self.db.query(
            "SELECT COUNT(*) n FROM mfa_recovery_codes WHERE user_id=? "
            "AND used_at=''", (user_id,))
        codes = crows[0] if crows else {"n": 0}
        return {"user_id": user_id, "enabled": bool(row["enabled"]),
                "method": "totp", "enrolled": True,
                "label": row["label"],
                "created_at": row["created_at"],
                "verified_at": row["verified_at"],
                "recovery_codes": int(codes["n"] if codes else 0)}

    def disable(self, user_id: str, *, actor: str = "identity") -> dict:
        user = self._user(user_id)
        if not user:
            raise errors.NotFoundError("no such user")
        self.db.execute("DELETE FROM mfa_secrets WHERE user_id=?", (user_id,))
        self.db.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",
                        (user_id,))
        self.db.execute(
            "UPDATE users SET mfa_reenroll_required=0, updated_at=? "
            "WHERE id=?", (_now(), user_id))
        self._audit("identity.mfa.disabled", object_type="user",
                    object_id=user_id, org_id=user["org_id"], actor=actor,
                    metadata={"method": "totp"})
        self._event(user["org_id"], "mfa.disabled", actor=actor,
                    detail={"user_id": user_id})
        return {"user_id": user_id, "enabled": False}

    # ----------------------------------------------------- recovery codes
    def recovery_codes_generate(self, user_id: str, *,
                                count: int = RECOVERY_COUNT,
                                actor: str = "identity") -> dict:
        """Generate new single-use recovery codes. The PLAINTEXT codes are
        returned exactly once; previous codes are invalidated at once."""
        self._throttle("mfa_enroll", user_id)
        user = self._user(user_id)
        if not user:
            raise errors.NotFoundError("no such user")
        rows = self.db.query("SELECT enabled FROM mfa_secrets WHERE "
                             "user_id=? LIMIT 1", (user_id,))
        row = rows[0] if rows else None
        if not row or not row["enabled"]:
            raise errors.ValidationError("mfa_not_enabled")
        n = max(4, min(MAX_RECOVERY_COUNT, int(count)))
        salt = secrets.token_hex(16)
        codes = totp.generate_recovery_codes(n)
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",
                         (user_id,))
            for c in codes:
                conn.execute(
                    "INSERT INTO mfa_recovery_codes (id, user_id, salt, "
                    "code_hmac, used_at, created_at) VALUES (?,?,?,?,?,?)",
                    (models.stable_id(models.NS_MFACODE,
                                      f"{user_id}|{c[:16]}"), user_id, salt,
                     totp.hash_recovery_code(c, salt), "", _now()))
        self._audit("identity.recovery_code.generated", object_type="user",
                    object_id=user_id, org_id=user["org_id"], actor=actor,
                    metadata={"count": n})
        return {"user_id": user_id, "count": n, "codes": codes,
                "previous_invalidated": True}

    def recovery_codes_use(self, user_id: str, code: str, *,
                           actor: str = "identity") -> bool:
        """Single-use verification; the matched code is marked used in the
        same transaction. Returns True when the MFA challenge passes."""
        self._throttle("recovery_use", user_id)
        user = self._user(user_id)
        if not user:
            raise errors.NotFoundError("no such user")
        code = str(code or "").strip()
        rows = self.db.query(
            "SELECT id, salt, code_hmac, used_at FROM mfa_recovery_codes "
            "WHERE user_id=? AND used_at='' LIMIT 50", (user_id,))
        matched = None
        for r in rows:
            if totp.verify_recovery_code(code, r["salt"], r["code_hmac"]):
                matched = r
                break
        if matched is None:
            self._audit("identity.mfa.challenge_failure", object_type="user",
                        object_id=user_id, org_id=user["org_id"], actor=actor,
                        metadata={"method": "recovery"})
            raise errors.AuthenticationError("Invalid code")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE mfa_recovery_codes SET used_at=? WHERE id=? AND "
                "used_at=''", (_now(), matched["id"]))
        self._audit("identity.recovery_code.used", object_type="user",
                    object_id=user_id, org_id=user["org_id"], actor=actor,
                    metadata={})
        self._event(user["org_id"], "mfa.recovery_code_used", actor=actor,
                    detail={"user_id": user_id})
        self._audit("identity.mfa.challenge_success", object_type="user",
                    object_id=user_id, org_id=user["org_id"], actor=actor,
                    metadata={"method": "recovery"})
        return True

    def recovery_codes_list(self, user_id: str) -> dict:
        """Metadata only — plaintext codes can never be listed."""
        user = self._user(user_id)
        if not user:
            raise errors.NotFoundError("no such user")
        rows = self.db.query(
            "SELECT COUNT(*) n, SUM(CASE WHEN used_at<>'' THEN 1 ELSE 0 END) "
            "u FROM mfa_recovery_codes WHERE user_id=?", (user_id,))
        row = rows[0] if rows else {"n": 0, "u": 0}
        n = int(row["n"] or 0)
        used = int(row["u"] or 0)
        return {"user_id": user_id, "issued": n,
                "unused": max(0, n - used), "used": used, "codes": None}

    # ------------------------------------------------------------ challenge
    def challenge(self, user_id: str, code: str, *, actor: str = "identity",
                  session_id: str = "") -> dict:
        """Complete an MFA challenge on an existing (partial) session:
        TOTP first, recovery code second. A verified session is returned
        (session row is upgraded to fully authenticated)."""
        self._throttle("mfa_verify", user_id)
        user = self._user(user_id)
        if not user:
            raise errors.NotFoundError("no such user")
        rows = self.db.query("SELECT * FROM mfa_secrets WHERE user_id=? "
                             "LIMIT 1", (user_id,))
        row = rows[0] if rows else None
        if not row or not row["enabled"]:
            raise errors.ValidationError("mfa_not_enabled")
        code = str(code or "").strip()
        if code.startswith(totp.RECOVERY_CODE_PREFIX):
            self.recovery_codes_use(user_id, code, actor=actor)
            self._complete(user_id, session_id, actor, "recovery")
            return {"user_id": user_id, "verified": True,
                    "method": "recovery", "session_id": session_id}
        if _parse_ts(row["locked_until"]) > _epoch():
            raise errors.RateLimitedError(
                "Too many attempts", retry_after=max(
                    1, int(_parse_ts(row["locked_until"]) - _epoch())))
        try:
            seed = self._seed_decrypt(row["seed_enc"])
            ok, step = totp.verify(
                seed, code,
                last_used_step=int(row["last_used_step"]))
        except errors.AuthenticationError:
            raise
        except Exception:
            # corrupt/undecryptable seed: fail CLOSED, never surface
            # crypto internals, never leak the blob
            raise errors.AuthenticationError("Invalid code") from None
        if not ok:
            self._bump_fail(user_id)
            self._audit("identity.mfa.challenge_failure", object_type="user",
                        object_id=user_id, org_id=user["org_id"], actor=actor,
                        metadata={"method": "totp"})
            self._event(user["org_id"], "mfa.challenge_failed", actor=actor,
                        detail={"user_id": user_id})
            raise errors.AuthenticationError("Invalid code")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE mfa_secrets SET last_used_step=?, attempts=0, "
                "locked_until='', updated_at=? WHERE user_id=?",
                (step, _now(), user_id))
            conn.execute("UPDATE users SET last_mfa_at=? WHERE id=?",
                         (_now(), user_id))
        self._complete(user_id, session_id, actor, "totp")
        return {"user_id": user_id, "verified": True, "method": "totp",
                "session_id": session_id}

    def _complete(self, user_id: str, session_id: str, actor: str,
                  method: str) -> None:
        self._audit("identity.mfa.challenge_success", object_type="user",
                    object_id=user_id, org_id=self._user(user_id)["org_id"],
                    actor=actor, metadata={"method": method})
        self._event(self._user(user_id)["org_id"], "mfa.challenge_success",
                    actor=actor, detail={"user_id": user_id})
        if session_id:
            self.identity.session_mfa_complete(session_id, actor=actor)

    # ------------------------------------------------------------- reset
    def reset(self, user_id: str, *, actor: str = "identity",
              reenroll: bool = True) -> dict:
        """Administrative recovery: disable MFA, void recovery codes, force
        re-enrollment, revoke every session. NEVER creates a session for the
        target user (no impersonation) and NEVER returns a secret."""
        user = self._user(user_id)
        if not user:
            raise errors.NotFoundError("no such user")
        self._throttle("mfa_reset", actor)
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM mfa_secrets WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",
                         (user_id,))
            conn.execute(
                "UPDATE users SET mfa_reenroll_required=?, updated_at=? "
                "WHERE id=?", (1 if reenroll else 0, _now(), user_id))
        try:
            self.identity.sessions_revoke_all(user_id, reason="mfa_reset")
        except Exception:
            pass
        self._audit("identity.mfa.reset", object_type="user",
                    object_id=user_id, org_id=user["org_id"], actor=actor,
                    metadata={"reenroll": bool(reenroll)})
        self._event(user["org_id"], "mfa.reset", actor=actor,
                    detail={"user_id": user_id})
        return {"user_id": user_id, "enabled": False,
                "reenroll_required": bool(reenroll),
                "sessions_revoked": True}
