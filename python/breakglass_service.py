#!/usr/bin/env python3
"""breakglass_service.py — Phase 8 emergency administrative access.

Explicitly invoked, reason-required, short-lived, tenant-bound access grants
used when normal administrative access is unavailable. A grant is minted
ONLY for a user whose current session already satisfies the step-up policy
(MFA verified) and who holds the `identity.break_glass` permission; the
grant token then acts as a verified step-up context bound to the SAME actor
and organization. It NEVER grants roles or permissions the actor does not
already hold — there is no hidden superuser, master password, or universal
bypass token (spec §15).

Security properties:
  - reason is mandatory and recorded (actor, org, reason, start/expiry).
  - short lifetime (default 600s, hard cap 3600s).
  - one active grant per (actor, org): starting a new one voids the old.
  - token is high-entropy, hashed at rest (sha256), and never returned
    after issuance; never logged/audited/serialized in views.
  - every start/end is audited via the existing immutable audit log and
    recorded in identity_events; secrets never enter either channel.
  - fail closed: unknown/expired/ended/superseded grants and inactive
    actors all produce the identical generic AuthenticationError.
"""

from __future__ import annotations

import json
import secrets
import time

import errors
import identity as identity_mod
import models
import redact

DEFAULT_TTL_SECONDS = 600          # 10 minutes
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 3600
REASON_MIN_LEN = 8
REASON_MAX_LEN = 200
LIST_LIMIT = 100


# ------------------------------------------------------------- time helpers
def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _epoch() -> float:
    return time.time()


def _parse_ts(ts: str) -> float:
    if not ts:
        return 0.0
    try:
        return time.mktime(time.strptime(str(ts)[:19],
                                         "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except (ValueError, TypeError):
        return 0.0


def _iso_from_epoch(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(ep, 0)))


class BreakGlassService:
    """Emergency administrative access service (spec §15, §32, §33, §42, §44)."""

    def __init__(self, platform, identity_svc=None, *,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.svc = platform
        self.db = platform.db
        self.identity = (identity_svc or
                         identity_mod.IdentityService(platform))
        self.ttl = int(ttl_seconds or DEFAULT_TTL_SECONDS)

    # ------------------------------------------------------------- plumbing
    def _audit(self, action: str, *, object_type: str, object_id: str,
               org_id: str = "", actor: str = "identity",
               metadata: dict | None = None):
        """Immutable audit (existing system). Never contains secrets."""
        try:
            self.svc.audit(action, object_type=object_type,
                           object_id=object_id, org_id=org_id,
                           actor=str(actor)[:128],
                           metadata=redact.redact(dict(metadata or {})))
        except Exception:
            # Repository-wide convention (sso/mfa/scim): the audit log must
            # never break identity operations; verification decisions are
            # taken BEFORE any audit write and fail closed independently.
            pass

    def _event(self, org_id: str, event_type: str, *, actor="",
               detail: dict | None = None):
        """Operational identity telemetry (complementary; immutable audit
        remains authoritative — failures only bump a metric)."""
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
            try:
                metrics.inc("identity_events", 1)
            except Exception:
                pass

    def _throttle(self, kind: str, key: str) -> None:
        """Reuse the EXISTING rate limiter (no second limiter, spec §33)."""
        self.identity._throttle(kind, key)

    def _sweep_expired(self, conn) -> int:
        """Housekeeping: mark naturally-expired grants as ended (never an
        error path; active checks still verify expiry at use time)."""
        now = _now()
        return conn.execute(
            "UPDATE break_glass_grants SET ended_at=?, end_reason='expired' "
            "WHERE ended_at='' AND expires_at<?",
            (now, now)).rowcount

    # ------------------------------------------------------------------ ops
    def start(self, user_id: str, org_id: str, *, reason: str,
              created_by_session: str = "", verified: bool = False,
              actor: str = "identity", ttl_seconds: int | None = None) -> dict:
        """Mint an emergency grant. `verified` MUST reflect a positive
        step-up decision for `user_id` (MFA verified, unexpired window).
        Raises without creating anything when verification fails (fail
        closed) or the actor/org/tenant checks do not line up."""
        self._throttle("break_glass", f"{user_id}|{org_id}")
        reason = str(reason or "").strip()
        if not (REASON_MIN_LEN <= len(reason) <= REASON_MAX_LEN):
            raise errors.ValidationError(
                f"break_glass_invalid: reason must be "
                f"{REASON_MIN_LEN}-{REASON_MAX_LEN} chars")
        ttl = int(ttl_seconds or self.ttl)
        if not (MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS):
            raise errors.ValidationError(
                f"break_glass_invalid: ttl must be "
                f"{MIN_TTL_SECONDS}-{MAX_TTL_SECONDS}s")
        if not verified:
            raise errors.AuthorizationError("MFA step-up required")
        # tenant + actor truth: the grant owner must exist, be active and
        # belong to the org it is minted for (no cross-tenant grants).
        user = self.identity.user_get(user_id)          # NotFoundError
        if user.org_id != org_id:
            raise errors.AuthorizationError("Forbidden")
        if user.status != "active":
            raise errors.AuthenticationError("Invalid credentials")
        self.svc.org_require(org_id)
        secret = identity_mod.generate_token("breakglass")
        grant = models.BreakGlassGrant(
            org_id=org_id, user_id=user_id, reason=reason,
            token_hash=identity_mod.token_hash(secret),
            created_by_session=str(created_by_session or "")[:128])
        grant.finalize()
        grant.expires_at = _iso_from_epoch(_epoch() + ttl)
        superseded = 0
        with self.db.transaction() as conn:
            superseded = self._sweep_expired(conn)
            superseded += conn.execute(
                "UPDATE break_glass_grants SET ended_at=?, "
                "end_reason='superseded' WHERE user_id=? AND org_id=? "
                "AND ended_at=''",
                (_now(), user_id, org_id)).rowcount
            conn.execute(
                "INSERT INTO break_glass_grants (id, org_id, user_id, "
                "reason, token_hash, created_at, expires_at, last_seen_at, "
                "ended_at, end_reason, created_by_session) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?)",
                (grant.id, grant.org_id, grant.user_id, grant.reason,
                 grant.token_hash, grant.created_at, grant.expires_at,
                 grant.last_seen_at, grant.ended_at, grant.end_reason,
                 grant.created_by_session))
        rev_history = {"reason": reason[:120], "ttl_seconds": ttl,
                       "actor": str(actor)[:128],
                       "superseded_or_expired": int(superseded)}
        self._audit("identity.break_glass.started",
                    object_type="break_glass", object_id=grant.id,
                    org_id=org_id, actor=actor, metadata=rev_history)
        self._event(org_id, "break_glass.started", actor=actor,
                    detail={"grant_id": grant.id, "reason": reason[:120]})
        return {"grant_id": grant.id, "secret": secret,
                "expires_at": grant.expires_at, "ttl_seconds": ttl}

    def _row_to_grant(self, row) -> models.BreakGlassGrant:
        return models.BreakGlassGrant.from_dict(dict(row))

    def authenticate(self, secret: str) -> models.BreakGlassGrant:
        """Validate a bg_ secret. EVERY failure raises the identical generic
        AuthenticationError (no existence/enumeration leaks)."""
        if not secret or not secret.startswith(
                identity_mod.TOKEN_PREFIXES.get("breakglass", "bg_")):
            raise errors.AuthenticationError("Invalid credentials")
        rows = self.db.query(
            "SELECT * FROM break_glass_grants WHERE token_hash=? LIMIT 1",
            (identity_mod.token_hash(secret),))
        if not rows:
            raise errors.AuthenticationError("Invalid credentials")
        grant = self._row_to_grant(rows[0])
        now = _epoch()
        if grant.ended_at or _parse_ts(grant.expires_at) < now:
            raise errors.AuthenticationError("Invalid credentials")
        user = self.identity.user_get(grant.user_id)
        if user.status != "active" or user.org_id != grant.org_id:
            raise errors.AuthenticationError("Invalid credentials")
        self.svc.org_require(grant.org_id)
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE break_glass_grants SET last_seen_at=? WHERE id=?",
                (_now(), grant.id))
        grant.last_seen_at = _now()
        return grant

    def end(self, grant_id: str, *, actor: str = "identity",
            reason: str = "") -> dict:
        """Explicitly end a grant (idempotent-safe: ending an ended grant
        reports ended=False without error)."""
        if not grant_id:
            raise errors.ValidationError("break_glass_invalid: grant id "
                                         "required")
        rows = self.db.query(
            "SELECT * FROM break_glass_grants WHERE id=? LIMIT 1",
            (grant_id,))
        if not rows:
            raise errors.NotFoundError("no such break-glass grant")
        grant = self._row_to_grant(rows[0])
        reason = str(reason or "").strip()[:200]
        with self.db.transaction() as conn:
            claimed = conn.execute(
                "UPDATE break_glass_grants SET ended_at=?, end_reason=? "
                "WHERE id=? AND ended_at=''",
                (_now(), reason or "ended manually", grant_id)).rowcount
        if claimed == 1:
            self._audit("identity.break_glass.ended",
                        object_type="break_glass", object_id=grant.id,
                        org_id=grant.org_id, actor=actor,
                        metadata={"reason": reason or "ended manually",
                                  "user_id": grant.user_id})
            self._event(grant.org_id, "break_glass.ended", actor=actor,
                        detail={"grant_id": grant.id})
        return {"id": grant.id, "ended": bool(claimed)}

    def list_org(self, org_id: str, *, limit: int = LIST_LIMIT,
                 status: str = "all") -> list[dict]:
        """Bounded admin view. Never returns token hashes or any secret."""
        limit = max(1, min(int(limit or LIST_LIMIT), LIST_LIMIT))
        cond, params = "org_id=?", [org_id]
        if status in ("active", "ended"):
            cond += " AND ended_at" + ("=''" if status == "active"
                                       else "<>''")
        rows = self.db.query(
            "SELECT * FROM break_glass_grants WHERE " + cond +
            " ORDER BY created_at DESC LIMIT ?",
            tuple(params + [limit]))
        out = []
        now = _now()
        for r in rows:
            g = self._row_to_grant(r)
            state = ("ended" if g.ended_at and g.ended_at != now
                     else ("expired" if _parse_ts(g.expires_at) < _epoch()
                           and not g.ended_at else "active"))
            out.append(g.to_dict())
            out[-1]["state"] = state
        return out

    def org_status(self, org_id: str) -> dict:
        """Aggregate, bounded status counts (no identifiers beyond counts)."""
        with self.db.transaction() as conn:
            self._sweep_expired(conn)
        rows = self.db.query(
            "SELECT COUNT(*) n, "
            "CASE WHEN ended_at<>'' THEN 'ended' "
            "     WHEN expires_at<? THEN 'expired' "
            "     ELSE 'active' END st "
            "FROM break_glass_grants WHERE org_id=? GROUP BY st",
            (_now(), org_id))
        out = {"org_id": org_id, "active": 0, "expired": 0, "ended": 0}
        for r in rows:
            out[str(r["st"])] = int(r["n"])
        return out

    def user_grant_status(self, user_id: str, org_id: str) -> dict:
        """Status of the (at most one) active grant for an actor+org."""
        with self.db.transaction() as conn:
            self._sweep_expired(conn)
        rows = self.db.query(
            "SELECT * FROM break_glass_grants WHERE user_id=? AND org_id=? "
            "AND ended_at='' ORDER BY created_at DESC LIMIT 1",
            (user_id, org_id))
        if not rows:
            return {"active": False}
        g = self._row_to_grant(rows[0])
        return {"active": True, "grant_id": g.id,
                "reason": g.reason, "expires_at": g.expires_at,
                "created_at": g.created_at, "last_seen_at": g.last_seen_at}
