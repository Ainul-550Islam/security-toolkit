#!/usr/bin/env python3
# ============================================================================
#  authz.py — ONE reusable authorization layer (Phase 2).
#  ---------------------------------------------------------------------------
#  authenticate(request) → resolve context → check permission →
#  check object ownership → allow / deny.
#
#  Properties:
#    - FAIL CLOSED: unknown user/org/role/permission/ownership ⇒ DENY.
#    - generic errors only (AuthorizationError("Forbidden")) — no ids, no
#      missing-permission names in user-facing messages.
#    - tenant isolation: every object walk passes through the organization
#      boundary; cross-org objects are denied before any data is read.
#    - audit: every denial records an `authorization.denied` event with
#      safe metadata only (never object ids, never secrets).
#    - efficiency: object lookups are single indexed queries; never loads
#      an organization's whole dataset to authorize one record.
#
#  This module is the ONLY place authorization decisions are made.
# ============================================================================

from __future__ import annotations

from dataclasses import dataclass, field

import time

import errors
import identity as identity_mod
import rbac


@dataclass
class AuthContext:
    """Validated security context passed to protected operations.
    Never derived from raw client-supplied ids without verification."""
    user_id: str = ""
    org_id: str = ""
    roles: tuple = ()
    memberships: dict = field(default_factory=dict)   # project_id -> role
    permissions: frozenset = frozenset()
    session_id: str = ""
    credential_id: str = ""
    actor: str = "unknown"
    org_scope: bool = False    # org-wide credential without project binding
    # --- Phase-8 session hardening (defaults keep pre-Phase-8 behaviour) ---
    mfa_status: str = "none"       # none | pending | verified
    step_up_until: str = ""        # elevated window (ISO) for this session
    auth_method: str = ""          # password | oidc | saml | mfa | credential
    provider_id: str = ""          # SSO provider that established the session
    idp_subject: str = ""          # external subject at the IdP

    @property
    def is_authenticated(self) -> bool:
        return bool(self.user_id)

    @property
    def has_org_role(self) -> bool:
        return bool(self.roles)

    def label(self) -> str:
        if self.credential_id:
            return f"key:{self.credential_id[:8]}"
        if self.user_id:
            return self.actor or f"user:{self.user_id[:8]}"
        return "anonymous"


class AuthorizationService:
    """Binds IdentityService + PlatformService object ownership checks."""

    def __init__(self, platform, identity: identity_mod.IdentityService):
        self.platform = platform
        self.identity = identity
        self.db = platform.db

    # ------------------------------------------------------- authenticate
    def context_from_bearer(self, header_value: str) -> AuthContext:
        """Parse `Authorization: Bearer <secret>`; accept session AND API
        credentials. Any failure → generic AuthenticationError."""
        raw = str(header_value or "")
        if not raw.startswith("Bearer "):
            raise errors.AuthenticationError("Invalid credentials")
        secret = raw[len("Bearer "):].strip()
        if not secret or " " in secret:
            raise errors.AuthenticationError("Invalid credentials")
        return self.context_from_secret(secret)

    def context_from_secret(self, secret: str) -> AuthContext:
        """Session secret or API credential secret → validated context."""
        if secret.startswith(identity_mod.TOKEN_PREFIXES["session"]):
            sess = self.identity.session_authenticate(secret)
            return self._context_for_user(
                sess.user_id, session_id=sess.id, actor="session",
                mfa_status=getattr(sess, "mfa_status", "none"),
                step_up_until=getattr(sess, "step_up_until", ""),
                auth_method=getattr(sess, "auth_method", ""),
                provider_id=getattr(sess, "provider_id", ""),
                idp_subject=getattr(sess, "idp_subject", ""))
        if secret.startswith(identity_mod.TOKEN_PREFIXES["credential"]):
            cred = self.identity.credential_authenticate(secret)
            return self._context_for_credential(cred)
        if secret.startswith(
                identity_mod.TOKEN_PREFIXES.get("breakglass", "bg_")):
            # Emergency access grant (spec §15): validated by the
            # BreakGlassService (expiry / revocation / actor status — all
            # fail closed) and mapped to a VERIFIED step-up context bound
            # to the grant's actor+org. It adds NO permissions of its own.
            import breakglass_service as _bg
            grant = _bg.BreakGlassService(
                self.platform, self.identity).authenticate(secret)
            return self._context_for_user(
                grant.user_id, session_id="", actor="break_glass",
                mfa_status="verified", step_up_until=grant.expires_at,
                auth_method="break_glass", provider_id="break_glass")
        raise errors.AuthenticationError("Invalid credentials")

    def _context_for_user(self, user_id: str, *, session_id: str = "",
                          actor: str = "session", mfa_status: str = "none",
                          step_up_until: str = "",
                          auth_method: str = "", provider_id: str = "",
                          idp_subject: str = "") -> AuthContext:
        try:
            user = self.identity.user_get(user_id)
        except errors.NotFoundError:
            raise errors.AuthenticationError("Invalid credentials") from None
        if user.status != "active":
            raise errors.AuthenticationError("Invalid credentials")
        roles = self.identity.user_roles(user_id)
        members = {m["project_id"]: m["role"]
                   for m in self.identity.memberships_of(user_id)}
        return AuthContext(
            user_id=user.id, org_id=user.org_id, roles=roles,
            memberships=members,
            permissions=rbac.permissions_for(roles)
            | rbac.permissions_for(members.values()),
            session_id=session_id, actor=actor,
            mfa_status=mfa_status if mfa_status in ("none", "pending",
                                                    "verified") else "none",
            step_up_until=str(step_up_until or ""),
            auth_method=str(auth_method or "")[:32],
            provider_id=str(provider_id or "")[:96],
            idp_subject=str(idp_subject or "")[:256])

    def _context_for_credential(self, cred) -> AuthContext:
        if cred.project_id:
            memberships = {cred.project_id: "analyst"}
            org_scope = False
        else:
            memberships = {}
            org_scope = True
        return AuthContext(
            user_id=cred.created_by, org_id=cred.org_id,
            roles=(), memberships=memberships,
            permissions=rbac.permissions_for(("viewer",))
            | frozenset(cred.scopes),
            credential_id=cred.id, actor=f"key:{cred.key_prefix}",
            org_scope=org_scope)

    # -------------------------------------------------------- fail-closed
    # ------------------------------------------------- Phase-8 step-up gate
    # Read-only identity permissions remain usable by any authenticated
    # session; every identity WRITE permission is step-up gated here.
    IDENTITY_READ = frozenset({
        "identity.read", "identity.mfa.read", "identity.sso.read",
        "identity.scim.read", "identity.sessions.read",
        "identity.policy.read",
    })

    # A partial (MFA-pending) session may only observe its own identity
    # state. ANY OTHER permission is denied centrally — handlers never
    # re-implement this rule.
    PENDING_SESSION_SAFE = frozenset({"identity.mfa.read",
                                      "identity.sessions.read"})

    @staticmethod
    def _ts_valid(ts: str, now: float | None = None) -> bool:
        if not ts:
            return False
        try:
            parsed = time.mktime(time.strptime(str(ts)[:19],
                                               "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            return False
        return parsed > (now if now is not None else time.time())

    def _mfa_enabled(self, user_id: str) -> bool:
        rows = self.db.query(
            "SELECT enabled FROM mfa_secrets WHERE user_id=? LIMIT 1",
            (user_id,))
        return bool(rows and rows[0]["enabled"])

    def mfa_required_for(self, ctx: AuthContext) -> bool:
        """Org MFA policy evaluated ONCE here (deterministic; fail closed:
        an unreadable policy is treated as MFA-required)."""
        if not ctx.org_id:
            return False
        try:
            import mfa_service as mfa_mod
            svc = mfa_mod.MfaService(self.platform,
                                     identity_svc=self.identity)
            return bool(svc.policy_requires(ctx.org_id, ctx.roles))
        except Exception:
            return True

    def step_up_ok(self, ctx: AuthContext) -> bool:
        """True when `ctx` may perform a step-up-gated action right now.
        Rules (deterministic, fail closed):
          - API credentials are a distinct privileged channel: exempt.
          - MFA-pending sessions are never step-up sufficient.
          - A user WITH an enrolled MFA secret needs mfa_status=verified
            and an unexpired step-up window.
          - A user WITHOUT MFA is fine only when the org policy does not
            require MFA for their roles (pre-Phase-8 baseline behaviour)."""
        if ctx.credential_id or not ctx.session_id:
            return True
        if ctx.mfa_status == "pending":
            return False
        if ctx.mfa_status == "verified":
            return self._ts_valid(ctx.step_up_until)
        if self._mfa_enabled(ctx.user_id):
            return False      # MFA exists but this session never did it
        return not self.mfa_required_for(ctx)

    def require_step_up(self, ctx: AuthContext, *, purpose: str = "") -> None:
        """Centralized step-up enforcement. Raises AuthorizationError with a
        stable message; callers surface it as a step-up challenge. Never
        returns without a positive decision."""
        if not self.step_up_ok(ctx):
            self._deny(ctx, "identity.step_up", purpose or "write")
            raise errors.AuthorizationError("MFA step-up required")

    def require_own_session(self, ctx: AuthContext, session_id: str) -> None:
        """A user may only act on their OWN sessions (used by the MFA
        challenge path while a session is still pending)."""
        rows = self.db.query(
            "SELECT user_id FROM sessions WHERE id=? LIMIT 1", (session_id,))
        row = rows[0] if rows else None
        if not row or row["user_id"] != ctx.user_id:
            self._deny(ctx, "identity.session.own", "session")
            raise errors.AuthorizationError("Forbidden")

    def require(self, ctx: AuthContext, permission: str) -> None:
        if permission not in rbac.PERMISSIONS:
            raise errors.ValidationError(f"Unknown permission: {permission}")
        if permission not in ctx.permissions:
            self._deny(ctx, permission, "")
            raise errors.AuthorizationError("Forbidden")
        if not ctx.credential_id:
            if ctx.mfa_status == "pending" and permission not in \
                    self.PENDING_SESSION_SAFE:
                self._deny(ctx, permission, "mfa_pending")
                raise errors.AuthorizationError("MFA step-up required")
            if permission not in self.IDENTITY_READ and \
                    permission.startswith("identity."):
                self.require_step_up(ctx, purpose=permission)

    def require_org(self, ctx: AuthContext, org_id: str) -> None:
        try:
            if not ctx.org_id or ctx.org_id != org_id:
                raise errors.AuthorizationError("Forbidden")
            # Project memberships grant access only through require_project.
            # Treating any membership as tenant-wide here lets a project-bound
            # credential or membership-only user cross the organization boundary.
            if not (ctx.roles or ctx.org_scope):
                raise errors.AuthorizationError("Forbidden")
        except errors.AuthorizationError:
            self._deny(ctx, "organization.access", "org")
            raise

    def require_project(self, ctx: AuthContext, project_id: str) -> None:
        try:
            project = self._project(project_id)
            if ctx.org_id != project.org_id:
                raise errors.AuthorizationError("Forbidden")
            if not self._project_accessible(ctx, project_id):
                raise errors.AuthorizationError("Forbidden")
            return project
        except errors.AuthorizationError:
            self._deny(ctx, "project.access", "project")
            raise

    def _project(self, project_id: str):
        try:
            return self.platform.project_require(project_id)
        except errors.NotFoundError:
            raise errors.AuthorizationError("Forbidden") from None

    def _project_accessible(self, ctx: AuthContext, project_id: str) -> bool:
        """Org roles/org-wide credentials grant org access; membership-only
        users are scoped to their member projects (tighter)."""
        if ctx.roles or ctx.org_scope:
            return True
        return project_id in ctx.memberships

    def visible_projects(self, ctx: AuthContext) -> list:
        """Projects the context may enumerate (never cross-tenant)."""
        if ctx.roles or ctx.org_scope:
            return self.platform.project_list(ctx.org_id)
        out = []
        for pid in ctx.memberships:
            try:
                out.append(self._project(pid))
            except errors.AuthorizationError:
                continue
        return out

    # ------------------------------------------------- object-level checks
    def require_asset(self, ctx: AuthContext, asset_id: str):
        try:
            asset = self.platform.asset_get(asset_id)
            self.require_project(ctx, asset.project_id)
            self.require(ctx, "asset.read")
            return asset
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "asset.access", "asset")
            raise errors.AuthorizationError("Forbidden") from None

    def require_scan(self, ctx: AuthContext, scan_id: str):
        try:
            scan = self.platform.scan_get(scan_id)
            self.require_project(ctx, scan.project_id)
            return scan
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "scan.access", "scan")
            raise errors.AuthorizationError("Forbidden") from None

    def require_report(self, ctx: AuthContext, report_id: str):
        """Require report ownership before exposing any report metadata or payload."""
        rows = self.db.query(
            "SELECT id, org_id, project_id FROM report_runs WHERE id=? LIMIT 1",
            (report_id,),
        )
        if not rows or rows[0]["org_id"] != ctx.org_id:
            self._deny(ctx, "report.access", "report")
            raise errors.AuthorizationError("Forbidden")
        try:
            self.require_project(ctx, rows[0]["project_id"])
        except errors.AuthorizationError:
            self._deny(ctx, "report.access", "report")
            raise errors.AuthorizationError("Forbidden") from None
        return rows[0]

    def require_finding(self, ctx: AuthContext, finding_id: str):
        try:
            finding = self.platform.finding_get(finding_id)
            self.require_project(ctx, finding.project_id)
            return finding
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "finding.access", "finding")
            raise errors.AuthorizationError("Forbidden") from None

    def require_user(self, ctx: AuthContext, user_id: str):
        """Require an organization administrator context for user records.

        A project membership is not a tenant-wide identity grant. The lookup
        verifies the row's organization before the safe user projection is
        returned to a route.
        """
        rows = self.db.query(
            "SELECT id, org_id FROM users WHERE id=? LIMIT 1", (user_id,))
        if not rows or rows[0]["org_id"] != ctx.org_id:
            self._deny(ctx, "user.access", "user")
            raise errors.AuthorizationError("Forbidden")
        self.require_org(ctx, rows[0]["org_id"])
        return self.identity.user_get(user_id)

    def require_evidence(self, ctx: AuthContext, evidence_id: str):
        try:
            rows = self.db.query(
                "SELECT e.id, f.project_id FROM evidence e "
                "JOIN findings f ON f.id = e.finding_id "
                "WHERE e.id=? LIMIT 1", (evidence_id,))
            if not rows:
                raise errors.NotFoundError("no evidence")
            self.require_project(ctx, rows[0]["project_id"])
            return rows[0]["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "evidence.access", "evidence")
            raise errors.AuthorizationError("Forbidden") from None

    def require_audit(self, ctx: AuthContext, org_id: str) -> None:
        self.require(ctx, "audit.read")
        self.require_org(ctx, org_id)

    def require_credential(self, ctx: AuthContext, credential_id: str) -> None:
        try:
            cred = self.identity.credential_get(credential_id)
            if cred.org_id != ctx.org_id:
                raise errors.AuthorizationError("Forbidden")
            return cred
        except errors.AuthorizationError:
            self._deny(ctx, "credentials.access", "credential")
            raise
        except errors.NotFoundError:
            self._deny(ctx, "credentials.access", "credential")
            raise errors.AuthorizationError("Forbidden") from None

    def audit_visible_rows(self, ctx: AuthContext, org_id: str,
                           limit: int = 100):
        """Audit rows limited to the context's own organization."""
        self.require_audit(ctx, org_id)
        return self.platform.audit_list_org(org_id, limit=min(limit, 500))

    # -------------------------------------------------- Phase 5 objects
    def require_monitoring_policy(self, ctx: AuthContext, policy_id: str):
        try:
            rows = self.db.query(
                "SELECT id, project_id FROM monitoring_policies WHERE id=? "
                "LIMIT 1", (policy_id,))
            if not rows:
                raise errors.NotFoundError("no monitoring policy")
            self.require_project(ctx, rows[0]["project_id"])
            return rows[0]["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "monitoring.access", "policy")
            raise errors.AuthorizationError("Forbidden") from None

    def require_alert(self, ctx: AuthContext, alert_id: str):
        try:
            rows = self.db.query(
                "SELECT id, project_id FROM alerts WHERE id=? LIMIT 1",
                (alert_id,))
            if not rows:
                raise errors.NotFoundError("no alert")
            self.require_project(ctx, rows[0]["project_id"])
            return rows[0]["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "alert.access", "alert")
            raise errors.AuthorizationError("Forbidden") from None

    def require_notification(self, ctx: AuthContext, notification_id: str):
        try:
            rows = self.db.query(
                "SELECT id, project_id FROM notifications WHERE id=? LIMIT 1",
                (notification_id,))
            if not rows:
                raise errors.NotFoundError("no notification")
            self.require_project(ctx, rows[0]["project_id"])
            return rows[0]["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "notification.access", "notification")
            raise errors.AuthorizationError("Forbidden") from None

    def require_remediation(self, ctx: AuthContext, ticket_id: str):
        """Ownership chain: ticket → finding → project → org."""
        try:
            rows = self.db.query(
                "SELECT r.id, f.project_id FROM remediation_tickets r "
                "JOIN findings f ON f.id = r.finding_id WHERE r.id=? LIMIT 1",
                (ticket_id,))
            if not rows:
                raise errors.NotFoundError("no remediation ticket")
            self.require_project(ctx, rows[0]["project_id"])
            return rows[0]["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "remediation.access", "ticket")
            raise errors.AuthorizationError("Forbidden") from None

    def require_security_event(self, ctx: AuthContext, event_id: str):
        try:
            rows = self.db.query(
                "SELECT id, project_id FROM security_events WHERE id=? "
                "LIMIT 1", (event_id,))
            if not rows:
                raise errors.NotFoundError("no security event")
            self.require_project(ctx, rows[0]["project_id"])
            return rows[0]["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "monitoring.access", "event")
            raise errors.AuthorizationError("Forbidden") from None

    # -------------------------------------------------- Phase 7 objects
    def _phase7_row(self, table: str, record_id: str):
        # static allowlist — SQL identifiers are NEVER taken from user input
        if table not in ("security_gates", "ci_runs", "gate_results"):
            raise errors.ValidationError("unknown table")
        rows = self.db.query(
            "SELECT id, project_id FROM " + table + " WHERE id=? LIMIT 1",
            (record_id,))
        if not rows:
            raise errors.NotFoundError("no such record")
        return rows[0]

    def require_gate(self, ctx: AuthContext, gate_id: str):
        """Ownership chain: gate -> project -> organization (fail closed;
        unknown ids never reveal existence)."""
        try:
            row = self._phase7_row("security_gates", gate_id)
            self.require_project(ctx, row["project_id"])
            return row["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "devsecops.access", "gate")
            raise errors.AuthorizationError("Forbidden") from None

    def require_ci_run(self, ctx: AuthContext, run_id: str):
        """Ownership chain: CI run -> project -> organization."""
        try:
            row = self._phase7_row("ci_runs", run_id)
            self.require_project(ctx, row["project_id"])
            return row["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "devsecops.access", "ci_run")
            raise errors.AuthorizationError("Forbidden") from None

    def require_gate_result(self, ctx: AuthContext, result_id: str):
        """Ownership chain: gate result -> project -> organization."""
        try:
            row = self._phase7_row("gate_results", result_id)
            self.require_project(ctx, row["project_id"])
            return row["id"]
        except (errors.AuthorizationError, errors.NotFoundError):
            self._deny(ctx, "devsecops.access", "result")
            raise errors.AuthorizationError("Forbidden") from None

    # ================================================================
    # Phase 11 — data-protection / privacy / compliance authorization.
    # Object-scope resolution go through the SAME ownership chains as the
    # rest of the platform (asset/scan/finding/case/ioc + secrets), and the
    # permission vocabulary lives in rbac.py. Fail closed everywhere.
    # ================================================================
    def require_governance_org(self, ctx: AuthContext, org_id: str,
                               permission: str) -> None:
        """Organization-scoped governance operation (permission + tenant)."""
        self.require(ctx, permission)
        self.require_org(ctx, org_id)

    def require_governance_project(self, ctx: AuthContext, project_id: str,
                                   permission: str) -> None:
        """Project-scoped governance operation (permission + tenant +
        project accessibility)."""
        self.require(ctx, permission)
        return self.require_project(ctx, project_id)

    def require_data_object(self, ctx: AuthContext, object_type: str,
                            object_id: str, permission: str):
        """Resolve a governance object's ownership chain and enforce the
        permission. Returns (org_id, project_id) when accessible; any
        mismatch or unknown object raises AuthorizationError/NotFoundError
        (fail closed, no cross-tenant information)."""
        self.require(ctx, permission)
        if object_type in ("finding", "evidence", "scan"):
            row = self._gov_row_ids(object_type, object_id)
            return self.require_project(ctx, row["project_id"])
        if object_type in ("case", "ioc", "secret", "export_record"):
            row = self._gov_row_ids(object_type, object_id)
            self.require_org(ctx, row["org_id"])
            return row["org_id"], row.get("project_id", "")
        if object_type in ("privacy_request", "retention_policy",
                           "retention_hold", "policy_exception"):
            row = self._gov_row_ids(object_type, object_id)
            self.require_org(ctx, row["org_id"])
            return row["org_id"], row.get("project_id", "")
        raise errors.ValidationError("unknown governance object type")

    def require_secret_registry(self, ctx: AuthContext, secret_id: str):
        """Secret-registry metadata rows: tenant-scoped read (org chain)."""
        row = self._gov_row_ids("secret", secret_id)
        self.require_org(ctx, row["org_id"])
        return row

    def _gov_row_ids(self, object_type: str, record_id: str) -> dict:
        # static allowlist — SQL identifiers are NEVER taken from user input
        tables = {
            "finding": ("findings", "project_id"),
            "evidence": ("evidence", "finding_id"),
            "scan": ("scans", "project_id"),
            "case": ("investigation_cases", "org_id"),
            "ioc": ("threat_indicators", "org_id"),
            "secret": ("secrets_registry", "org_id"),
            "export_record": ("data_exports", "org_id"),
            "privacy_request": ("privacy_requests", "org_id"),
            "retention_policy": ("retention_policies", "org_id"),
            "retention_hold": ("retention_holds", "org_id"),
            "policy_exception": ("policy_exceptions", "org_id"),
        }
        if object_type not in tables:
            raise errors.ValidationError("unknown governance object type")
        table, col = tables[object_type]
        rows = self.db.query(
            "SELECT * FROM " + table + " WHERE id=? LIMIT 1", (record_id,))
        if not rows:
            raise errors.NotFoundError("no such record")
        row = dict(rows[0])
        out = {"id": row["id"]}
        out["org_id"] = str(row.get("org_id") or "")
        out["project_id"] = str(row.get("project_id") or "")
        if object_type == "finding":
            out["project_id"] = str(row.get("project_id") or "")
        elif object_type == "evidence":
            frows = self.db.query(
                "SELECT project_id FROM findings WHERE id=? LIMIT 1",
                (row.get("finding_id") or "",))
            if not frows:
                raise errors.NotFoundError("no such record")
            out["project_id"] = str(frows[0]["project_id"])
            forr = self.db.query(
                "SELECT org_id FROM projects WHERE id=? LIMIT 1",
                (out["project_id"],))
            if not forr:
                raise errors.NotFoundError("no such record")
            out["org_id"] = str(forr[0]["org_id"])
        return out

    # -------------------------------------------------------------- deny log
    def _deny(self, ctx: AuthContext, permission: str, kind: str) -> None:
        try:
            self.platform.audit(
                "authorization.denied", actor=ctx.label(),
                org_id=ctx.org_id or "",
                metadata={"perm": permission, "kind": kind})
        except Exception:
            pass  # denial auditing must never mask the denial itself
