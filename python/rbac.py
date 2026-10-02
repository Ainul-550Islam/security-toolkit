#!/usr/bin/env python3
# ============================================================================
#  rbac.py — deterministic role/permission policy (Phase 2).
#  ---------------------------------------------------------------------------
#  Single source of truth for roles, permissions and the role→permission
#  matrix. Nothing else in the codebase compares role names as scattered
#  strings: authorization goes through authz.AuthorizationService, which
#  consults THIS module.
#
#  Roles (increasing authority):
#      viewer            read-only
#      analyst           read + asset/scan/finding/report analysis work
#      security_manager  analyst + scope & risk decisions (accept risk)
#      admin             org/user administration + credentials + project mgmt
#      owner             everything (no organization.delete / purge yet)
#
#  Rules:
#    - explicit permission sets (a role's set is immutable by construction)
#    - role assignment may never exceed the caller's own authority
#    - unknown role or unknown permission ⇒ deny (fail closed)
#    - no secret material anywhere in this module
# ============================================================================

from __future__ import annotations

import errors

# role names, weakest → strongest (index = authority level)
ROLE_ORDER = ("viewer", "analyst", "security_manager", "admin", "owner")
ROLES = frozenset(ROLE_ORDER)

# The complete permission vocabulary. Keep it the smallest set required by
# the platform surface; any permission added here MUST get a matrix entry.
PERMISSIONS = frozenset({
    "organization.read", "organization.update",
    "user.read", "user.create", "user.update", "user.disable",
    "role.read", "role.assign",
    "project.read", "project.create", "project.update", "project.delete",
    "asset.read", "asset.create", "asset.update", "asset.delete",
    "asset.criticality",
    "scope.read", "scope.update",
    "scan.read", "scan.create", "scan.start", "scan.pause", "scan.cancel",
    "finding.read", "finding.update", "finding.resolve",
    "finding.accept_risk",
    "report.read", "report.generate", "report.export",
    "analytics.read", "compliance_evidence.read",
    "audit.read",
    "credentials.create", "credentials.revoke",
    "configuration.read", "configuration.update",
    # Phase 5 — continuous monitoring (viewer reads; analyst operates;
    # security_manager gets the sensitive controls; admin/owner inherit)
    "monitoring.read", "monitoring.create", "monitoring.update",
    "monitoring.run", "monitoring.delete",
    "alert.read", "alert.update", "alert.suppress",
    "remediation.read", "remediation.update", "remediation.assign",
    "remediation.verify",
    "notification.read", "notification.retry",
    # Phase 7 — DevSecOps security gates & CI runs
    "devsecops.read", "devsecops.create", "devsecops.update",
    "devsecops.run", "devsecops.export", "devsecops.delete",
    # Phase 8 — enterprise identity (read-mostly; sensitive write ops are
    # security_manager+; identity administration is admin/owner only)
    "identity.read", "identity.update",
    "identity.mfa.read", "identity.mfa.manage",
    "identity.sso.read", "identity.sso.create", "identity.sso.update",
    "identity.sso.delete",
    "identity.scim.read", "identity.scim.manage",
    "identity.sessions.read", "identity.sessions.revoke",
    "identity.policy.read", "identity.policy.update",
    # §15: emergency administrative access. Grant minting requires BOTH this
    # permission AND a verified step-up context (enforced in the service).
    "identity.break_glass",
    # Phase 9 — cloud / container / kubernetes / IaC security
    "cloud.read", "cloud.scan.run", "cloud.inventory.run",
    "cloud.account.create", "cloud.account.update",
    "cloud.account.manage_credentials", "cloud.account.delete",
    "container.read", "container.scan.run", "container.image.register",
    "container.image.delete",
    "kubernetes.read", "kubernetes.scan.run",
    "kubernetes.cluster.create", "kubernetes.cluster.update",
    "kubernetes.cluster.delete",
    "iac.read", "iac.scan.run", "iac.source.manage", "iac.record.delete",
    # Phase 10 — security operations / threat intelligence / cases
    # (§27: only the permissions the implementation requires; analyst+ may
    # operate, security_manager+ may import/export feeds and close cases)
    "threat_intel.read", "threat_intel.create", "threat_intel.import",
    "threat_intel.export",
    "attack_surface.read", "attack_surface.scan",
    "cases.read", "cases.create", "cases.update", "cases.assign",
    "cases.close",
    # Phase 11 — data protection / privacy / secrets / compliance
    # governance (minimum set; every new permission has a matrix entry;
    # viewers get read-only evidence views ONLY — never holds/secrets/
    # deletion/exports, which are sensitive privileges)
    "data.classifications.view", "data.classify", "data.downgrade",
    "data.retention.view", "data.retention.manage",
    "data.holds.view", "data.holds.manage",
    "data.delete", "data.export",
    "secrets.registry.view", "secrets.registry.manage", "secrets.detect",
    "privacy.requests.view", "privacy.requests.manage",
    "privacy.subject.manage",
    "compliance.controls.read", "compliance.exceptions.view",
    "compliance.exceptions.manage",
    # Phase 12 — cross-organization federation / evidence exchange / bulk
    # operations / external integration boundary. Approval and revocation
    # are strictly stronger than read/create: establishing or ending a
    # cross-organization trust relationship is admin/owner only, and the
    # service additionally enforces creator != approver (separation of
    # duties). Viewers get read-only visibility and NOTHING else.
    "federation.read", "federation.create", "federation.update",
    "federation.approve", "federation.revoke",
    "federation.export", "federation.import",
    "federation.manage_policy", "federation.bulk", "federation.audit",
    "integration.read", "integration.create", "integration.update",
    "integration.disable", "integration.export",
    # Phase 13 — enterprise security integration pipeline. Extends the
    # Phase-12 integration.* surface; read/disable/create/update/export
    # above are REUSED, never duplicated. `integration.enable` (activating
    # outbound data flow to an external provider) and `integration.manage`
    # (administrative lifecycle: deletion, credential-reference rotation,
    # boundary changes) are the high-impact pair — admin/owner only, and
    # the service additionally enforces creator != approver on high-impact
    # activation (separation of duties, mirroring federation.approve).
    # The six operational permissions sit at security_manager, matching
    # the Phase-12 placement of the integration boundary. Viewers and
    # analysts keep ZERO integration permissions (§34/Phase-12 decision).
    "integration.manage", "integration.configure", "integration.test",
    "integration.enable", "integration.send", "integration.ingest",
    "integration.audit", "integration.health",
})

# ---------------------------------------------------------------------------
# Role → permission matrix (explicit, deterministic, documented)
# ---------------------------------------------------------------------------
_VIEWER = frozenset({
    "organization.read", "user.read", "role.read",
    "project.read", "asset.read", "scope.read", "scan.read",
    "finding.read", "report.read", "report.export",
    "analytics.read", "compliance_evidence.read",
    "audit.read", "configuration.read",
    # Phase 5 read-only monitoring visibility
    "monitoring.read", "alert.read", "remediation.read",
    "notification.read",
    # Phase 7: gates and CI history are visible + exportable read-only
    "devsecops.read", "devsecops.export",
    # Phase 11: read-only governed views of compliance control state and
    # classification allowlist (never holds/secrets/deletion/exports)
    "data.classifications.view", "compliance.controls.read",
    # Phase 8: identity state is visible read-only (never administered)
    "identity.read", "identity.mfa.read", "identity.sso.read",
    "identity.scim.read", "identity.sessions.read", "identity.policy.read",
    # Phase 9: assessment state is visible read-only
    "cloud.read", "container.read", "kubernetes.read", "iac.read",
    # Phase 10: threat intelligence / attack surface / cases visible read-only
    "threat_intel.read", "attack_surface.read", "cases.read",
    # Phase 12: viewers get NO federation/integration permissions (§34) —
    # cross-organization data sharing state is analyst-and-above only
})

_ANALYST = (_VIEWER | {
    "asset.create", "asset.update",
    "scan.create", "scan.start", "scan.pause", "scan.cancel",
    "finding.update", "finding.resolve",
    "report.generate",
    # Phase 5 operational monitoring + remediation work
    "monitoring.create", "monitoring.update", "monitoring.run",
    "alert.update", "remediation.update",
    # Phase 7: analysts create gate policies, update them and run CI scans
    "devsecops.create", "devsecops.update", "devsecops.run",
    # Phase 9: analysts run cloud/container/kubernetes/IaC assessments
    "cloud.scan.run", "cloud.inventory.run",
    "container.scan.run", "kubernetes.scan.run", "iac.scan.run",
    # Phase 10: analysts create indicators, scan attack surface, work cases
    "threat_intel.create", "attack_surface.scan",
    "cases.create", "cases.update",
    # Phase 11: analysts classify data and run secret-shape detection over
    # evidence (the values are never stored or returned)
    "data.classify", "secrets.detect",
})

_SECURITY_MANAGER = (_ANALYST | {
    "scope.update", "finding.accept_risk", "asset.criticality",
    # Phase 5 sensitive controls (never implicitly granted below this level)
    "monitoring.delete", "alert.suppress",
    "remediation.assign", "remediation.verify", "notification.retry",
    # Phase 8: identity security operations (MFA resets, SSO config, SCIM
    # provisioning use the existing RBAC roles — no second permission system)
    "identity.update",
    "identity.mfa.read", "identity.mfa.manage",
    "identity.sso.create", "identity.sso.update",
    "identity.scim.manage",
    "identity.sessions.revoke",
    "identity.policy.update",
    # §15: emergency administrative access (security_manager+ AND verified
    # step-up; owner/admin inherit through the hierarchy)
    "identity.break_glass",
    # Phase 9: register/manage security sources (cloud accounts, images,
    # clusters, IaC uploads) — credential material is never in RBAC scope
    "cloud.account.create", "cloud.account.update",
    "cloud.account.manage_credentials",
    "container.image.register",
    "kubernetes.cluster.create", "kubernetes.cluster.update",
    "iac.source.manage",
    # Phase 10: feed import/export (sensitive data handling, analyst-visible
    # but never below security_manager) + case assignment/closure
    "threat_intel.import", "threat_intel.export",
    "cases.assign", "cases.close",
    # Phase 11: sensitive governance privileges (never viewer-level):
    # downgrades, retention/hold management, controlled deletion, data
    # export, secret registry visibility, privacy request handling and
    # compliance-exception visibility
    "data.downgrade",
    "data.retention.view", "data.holds.view", "data.holds.manage",
    "data.delete", "data.export",
    "secrets.registry.view",
    "privacy.requests.view", "privacy.requests.manage",
    "compliance.exceptions.view",
    # Phase 12: viewers AND analysts get no federation/integration
    # permissions (§34 — cross-organization data sharing is not day-to-day
    # analyst surface). Security managers operate federation end-to-end
    # (read, peers, policies, packages, imports, bulk jobs, integration
    # boundary) — but NEVER approval/revocation of trust relationships
    # (admin/owner only, plus creator != approver separation of duties)
    "federation.read", "integration.read",
    "federation.create", "federation.update",
    "federation.export", "federation.import",
    "federation.manage_policy", "federation.bulk", "federation.audit",
    "integration.create", "integration.update",
    "integration.disable", "integration.export",
    # Phase 13: operational integration surface (configure connections,
    # run connectivity tests, send outbound events, ingest inbound
    # events, read integration audit/health views). NEVER manage/enable —
    # high-impact activation is admin/owner only with SoD enforcement.
    "integration.configure", "integration.test", "integration.send",
    "integration.ingest", "integration.audit", "integration.health",
})

_ADMIN = (_SECURITY_MANAGER | {
    "organization.update",
    "user.create", "user.update", "user.disable",
    "role.assign",
    "project.create", "project.update", "project.delete",
    "asset.delete",
    "credentials.create", "credentials.revoke",
    "configuration.update",
    # Phase 7: only admins may delete security gates (destructive)
    "devsecops.delete",
    # Phase 11: administrative governance (retention policy config, secret
    # registry management, subject-level privacy operations, compliance
    # exceptions) — inherited by owner
    "data.retention.manage", "secrets.registry.manage",
    "privacy.subject.manage", "compliance.exceptions.manage",
    # Phase 8: identity administration (providers, domains, SCIM creds)
    "identity.sso.delete",
    # Phase 9: destructive source removal (accounts/images/clusters/records)
    "cloud.account.delete", "container.image.delete",
    "kubernetes.cluster.delete", "iac.record.delete",
    # Phase 12: trust-relationship lifecycle (approve/suspend/revoke a
    # cross-organization federation peer) is administrative; the service
    # ALSO enforces creator != approver on approval (separation of duties)
    "federation.approve", "federation.revoke",
    # Phase 13: high-impact integration lifecycle — enabling outbound data
    # flow to an external provider and administrative connection management
    # (deletion, credential-reference rotation, boundary changes). The
    # service ALSO enforces creator != approver on high-impact activation
    # (separation of duties, same pattern as federation.approve above).
    "integration.manage", "integration.enable",
})

# owner keeps every permission; future destructive/purge permissions must be
# granted explicitly and are NOT implied by this line.
_OWNER = _ADMIN

ROLE_PERMISSIONS: dict[str, frozenset] = {
    "viewer": _VIEWER,
    "analyst": _ANALYST,
    "security_manager": _SECURITY_MANAGER,
    "admin": _ADMIN,
    "owner": _OWNER,
}


def validate_role(role: str) -> str:
    r = str(role).strip().lower()
    if r not in ROLES:
        raise errors.ValidationError(f"Unknown role: {role!r}")
    return r


def permissions_for(roles) -> frozenset:
    """Union of permissions for a set of roles (fail closed on unknowns)."""
    out: set[str] = set()
    for r in roles or ():
        if r not in ROLES:
            raise errors.ValidationError(f"Unknown role: {r!r}")
        out |= ROLE_PERMISSIONS[r]
    return frozenset(out)


def has_permission(roles, permission: str) -> bool:
    """True only when `permission` is part of the roles' explicit matrix.
    Query-shaped helper: unknown roles/permissions resolve to False (fail
    closed) instead of raising."""
    if permission not in PERMISSIONS:
        return False
    try:
        return permission in permissions_for(roles)
    except errors.ValidationError:
        return False


def authority(role: str) -> int:
    """0 (viewer) .. 4 (owner). Unknown roles raise (fail closed)."""
    r = validate_role(role)
    return ROLE_ORDER.index(r)


def can_assign_role(caller_roles, target_role: str) -> bool:
    """Privilege-escalation guard.

    A caller may only grant a role whose authority is <= the caller's own
    maximum authority. Owner can assign everything; admin can never create
    another owner; analysts cannot mint admins; viewers cannot assign
    anything (they have no role.assign permission anyway).
    """
    target_authority = authority(target_role)          # fails closed
    if not caller_roles:
        return False
    max_caller = max(authority(r) for r in caller_roles)
    return target_authority <= max_caller


def max_role(roles) -> str:
    """Highest role among a set (for actor labels). Unknown → viewer."""
    if not roles:
        return "viewer"
    try:
        return max(ROLE_ORDER, key=lambda r: authority(r)
                   if r in roles else -1)
    except Exception:
        return "viewer"
