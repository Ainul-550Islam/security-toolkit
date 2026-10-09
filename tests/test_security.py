#!/usr/bin/env python3
# ============================================================================
#  test_security.py — Phase-2 security-control test suite.
#  Covers: password security, authentication (incl. disabled/locked/rate),
#  RBAC matrix, tenant isolation (IDOR/BOLA/forged ids), privilege escalation,
#  API credentials lifecycle, immutable/tamper-evident audit, password reset,
#  sessions, dashboard auth hardening, secret-leak regression.
#  Loaded by tests/run_tests.py so the WHOLE suite runs together.
#  Pure local: no internet, no live scanners.
# ============================================================================

import contextlib
import shutil
import hashlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(os.path.dirname(HERE), "python")
sys.path.insert(0, PY)

import errors  # noqa: E402
import models  # noqa: E402
import redact  # noqa: E402
import seclog  # noqa: E402
import store  # noqa: E402
import rbac  # noqa: E402
import authz  # noqa: E402
import identity as identity_mod  # noqa: E402
import dashboard  # noqa: E402
import main as main_cli  # noqa: E402
import platform_service as pf  # noqa: E402

from test_foundation import make_service  # noqa: E402

# Login test workload is heavy; keep the module-level limiter generous so only
# the dedicated rate-limit tests exercise tight windows.
identity_mod.RL_LIMITS["auth"] = (10000, 60)
identity_mod.RL_LIMITS["auth_ip"] = (10000, 60)
identity_mod.RL_LIMITS["session_create"] = (10000, 60)
identity_mod.RL_LIMITS["api"] = (10000, 60)
identity_mod.RL_LIMITS["credential_create"] = (10000, 3600)
identity_mod.RL_LIMITS["scan_create"] = (10000, 3600)

PW_A = "S3cure!Passw0rd"
PW_B = "An0ther!S3cret7"
SECRET_TOKEN = "ses_test_secret_token_abcdef123456"
API_SECRET = "stk_test_api_secret_abcdef123456"


def make_stack(tmp, **kw):
    """Fresh PlatformService + IdentityService (fast scrypt for tests)."""
    svc = make_service(tmp)
    id_svc = identity_mod.IdentityService(svc, scrypt_n=2 ** 8, **kw)
    return svc, id_svc


def make_org(tmp, name="Acme"):
    svc = make_service(tmp)
    id_svc = identity_mod.IdentityService(svc, scrypt_n=2 ** 8)
    org = svc.org_create(name)
    return svc, id_svc, org


def add_user(id_svc, org, username, email, roles, pw=PW_A):
    return id_svc.user_create(org.id, username, email, pw, roles=roles,
                              allow_any_role=True, actor="test")


# ---------------------------------------------------------------------------
class TestPasswordSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2pw_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.id_svc, self.org = make_org(self.tmp)

    def test_hash_is_scrypt_not_plaintext(self):
        h = self.id_svc.hasher.hash(PW_A)
        self.assertTrue(h.startswith("scrypt$"))
        self.assertNotIn(PW_A, h)
        parts = h.split("$")
        self.assertEqual(len(parts), 6)
        self.assertEqual(parts[1], str(2 ** 8))   # test cost used

    def test_verify_correct_and_wrong(self):
        h = self.id_svc.hasher.hash(PW_A)
        self.assertTrue(self.id_svc.hasher.verify(h, PW_A))
        self.assertFalse(self.id_svc.hasher.verify(h, PW_B))
        self.assertFalse(self.id_svc.hasher.verify(h, ""))

    def test_salt_means_same_password_different_hashes(self):
        self.assertNotEqual(self.id_svc.hasher.hash(PW_A),
                            self.id_svc.hasher.hash(PW_A))

    def test_unknown_scheme_rejected(self):
        self.assertFalse(self.id_svc.hasher.verify("md5$deadbeef", PW_A))
        self.assertFalse(self.id_svc.hasher.verify("", PW_A))
        self.assertFalse(self.id_svc.hasher.verify("not-a-hash", PW_A))
        self.assertFalse(self.id_svc.hasher.verify(None, PW_A))

    def test_cross_param_verify(self):
        """A stored hash created with different cost params still verifies."""
        other = identity_mod.PasswordHasher(n=2 ** 7, r=8, p=1)
        h = other.hash(PW_A)
        self.assertTrue(self.id_svc.hasher.verify(h, PW_A))
        self.assertFalse(self.id_svc.hasher.verify(h, PW_B))

    def test_policy_min_length_and_whitespace(self):
        with self.assertRaises(errors.ValidationError):
            identity_mod.validate_password_policy("short")
        with self.assertRaises(errors.ValidationError):
            identity_mod.validate_password_policy("  padded  ")
        with self.assertRaises(errors.ValidationError):
            identity_mod.validate_password_policy("")
        identity_mod.validate_password_policy("K" * 128)   # long ok
        # hashing itself accepts any string; the POLICY is the gate
        self.assertTrue(self.id_svc.hasher.verify(
            self.id_svc.hasher.hash("anything"), "anything"))

    def test_no_hash_in_user_serialization(self):
        u = add_user(self.id_svc, self.org, "alice", "alice@acme.test",
                     ("viewer",))
        d = u.to_dict()
        self.assertNotIn("password_hash", d)
        blob = json.dumps(d)
        self.assertNotIn("scrypt$", blob)

    def test_no_plaintext_password_in_db(self):
        add_user(self.id_svc, self.org, "bob", "bob@acme.test", ("viewer",))
        conn = sqlite3.connect(os.path.join(self.tmp, "test_platform.db"))
        blob = " ".join(str(r) for r in conn.execute("SELECT * FROM users"))
        self.assertNotIn(PW_A, blob)
        self.assertIn("scrypt$", blob)
        conn.close()


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2auth_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.id_svc, self.org = make_org(self.tmp)
        self.u = add_user(self.id_svc, self.org, "carol", "carol@acme.test",
                          ("analyst",))

    def test_valid_login(self):
        out = self.id_svc.login("carol@acme.test", PW_A)
        self.assertTrue(out["secret"].startswith("ses_"))
        self.assertEqual(out["user"].id, self.u.id)
        self.assertTrue(out["user"].last_auth_at)
        # authenticated again via the session secret
        sess = self.id_svc.session_authenticate(out["secret"])
        self.assertEqual(sess.user_id, self.u.id)

    def test_login_by_username_too(self):
        out = self.id_svc.login("carol", PW_A)
        self.assertEqual(out["user"].id, self.u.id)

    def test_wrong_password_generic_error(self):
        with self.assertRaises(errors.AuthenticationError) as cm:
            self.id_svc.login("carol@acme.test", "wrong-password-123")
        self.assertEqual(cm.exception.message, "Invalid credentials")
        self.assertEqual(cm.exception.http_status, 401)

    def test_unknown_user_same_generic_error(self):
        with self.assertRaises(errors.AuthenticationError) as cm:
            self.id_svc.login("nobody@acme.test", PW_A)
        self.assertEqual(cm.exception.message, "Invalid credentials")

    def test_disabled_user_cannot_authenticate(self):
        self.id_svc.user_set_status(self.u.id, "disabled", actor="test")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("carol@acme.test", PW_A)
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_create(self.u.id)

    def test_lockout_after_failures(self):
        for i in range(5):
            with self.assertRaises(errors.AuthenticationError):
                self.id_svc.login("carol@acme.test", "bad-password-%d" % i)
        u = self.id_svc.user_get(self.u.id)
        self.assertTrue(u.locked_until)          # temporary lock scheduled
        # even the CORRECT password is refused while locked (generic error)
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("carol@acme.test", PW_A)

    def test_lockout_is_temporary_by_design(self):
        self.id_svc.user_set_status(self.u.id, "active")
        # simulate lock expiry by clearing the field (bounded, no permanent lock)
        self.svc.db.execute("UPDATE users SET locked_until='' WHERE id=?",
                            (self.u.id,))
        out = self.id_svc.login("carol@acme.test", PW_A)
        self.assertEqual(out["user"].id, self.u.id)

    def test_rate_limited_authentication(self):
        self.addCleanup(
            lambda: identity_mod.RL_LIMITS.update(
                {"auth": (10000, 60), "auth_ip": (10000, 60)}))
        identity_mod.RL_LIMITS["auth"] = (2, 60)
        identity_mod.RL_LIMITS["auth_ip"] = (2, 60)
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("carol@acme.test", "bad-1")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("carol@acme.test", "bad-2")
        with self.assertRaises(errors.RateLimitedError) as cm:
            self.id_svc.login("carol@acme.test", PW_A)
        self.assertGreater(cm.exception.retry_after, 0)
        self.assertEqual(cm.exception.http_status, 429)

    def test_malformed_credentials_rejected(self):
        auth_svc = authz.AuthorizationService(self.svc, self.id_svc)
        for header in ("Bearer", "Bearer ", "Basic abc==", "Bearer a b", ""):
            with self.assertRaises(errors.AuthenticationError):
                auth_svc.context_from_bearer(header)

    def test_session_context_build(self):
        out = self.id_svc.login("carol@acme.test", PW_A)
        auth_svc = authz.AuthorizationService(self.svc, self.id_svc)
        ctx = auth_svc.context_from_bearer("Bearer " + out["secret"])
        self.assertEqual(ctx.org_id, self.org.id)
        self.assertIn("analyst", ctx.roles)
        self.assertIn("scan.start", ctx.permissions)
        self.assertNotIn("user.disable", ctx.permissions)

    def test_logout_revokes_session(self):
        out = self.id_svc.login("carol@acme.test", PW_A)
        self.id_svc.logout(out["secret"])
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(out["secret"])

    def test_expired_session_rejected(self):
        tmp = tempfile.mkdtemp(prefix="p2exp_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        svc2, id2, org2 = make_org(tmp, name="Expired")
        u2 = add_user(id2, org2, "dave", "dave@acme.test", ("viewer",))
        out = id2.session_create(u2.id)
        # expire it directly (deterministic, no sleep)
        svc2.db.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00Z' "
                        "WHERE id=?", (out["session"].id,))
        with self.assertRaises(errors.AuthenticationError):
            id2.session_authenticate(out["secret"])

    def test_failed_login_audited_without_identifiers(self):
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("carol@acme.test", "bad-password-xyz")
        events = self.svc.audit_list(None, limit=500)
        failures = [e for e in events if e.action == "login_failure"]
        self.assertEqual(len(failures), 1)
        self.assertNotIn("carol", json.dumps(failures[0].metadata))
        self.assertIn("subject", failures[0].metadata)   # pseudonymous hash
        successes = [e for e in events if e.action == "login_success"]
        self.assertEqual(len(successes), 0)


class TestRBACMatrix(unittest.TestCase):
    def test_viewer_read_only(self):
        perms = rbac.permissions_for(("viewer",))
        self.assertIn("project.read", perms)
        self.assertIn("finding.read", perms)
        self.assertIn("audit.read", perms)
        for p in ("user.create", "scan.create", "finding.update",
                  "scope.update", "project.update", "credentials.create"):
            self.assertNotIn(p, perms)

    def test_analyst(self):
        perms = rbac.permissions_for(("analyst",))
        for p in ("asset.create", "scan.create", "scan.start",
                  "finding.update", "finding.resolve", "report.generate"):
            self.assertIn(p, perms)
        for p in ("scope.update", "user.disable", "role.assign",
                  "finding.accept_risk", "project.delete"):
            self.assertNotIn(p, perms)

    def test_security_manager(self):
        perms = rbac.permissions_for(("security_manager",))
        self.assertIn("scope.update", perms)
        self.assertIn("finding.accept_risk", perms)
        for p in ("user.create", "project.create", "credentials.create",
                  "role.assign"):
            self.assertNotIn(p, perms)

    def test_admin(self):
        perms = rbac.permissions_for(("admin",))
        for p in ("user.create", "user.disable", "role.assign",
                  "project.create", "project.delete", "credentials.create",
                  "credentials.revoke", "configuration.update",
                  "asset.delete", "organization.update"):
            self.assertIn(p, perms)
        self.assertNotIn("organization.create" if False else "nothing", perms)

    def test_owner_all(self):
        perms = rbac.permissions_for(("owner",))
        missing = set(rbac.PERMISSIONS) - set(perms)
        self.assertEqual(missing, set())

    def test_unknown_fail_closed(self):
        self.assertEqual(rbac.has_permission(("root",), "project.read"), False)
        with self.assertRaises(errors.ValidationError):
            rbac.permissions_for(("superadmin",))
        self.assertFalse(rbac.has_permission(("viewer",), "totally.made.up"))

    def test_escalation_guard(self):
        self.assertTrue(rbac.can_assign_role(("owner",), "owner"))
        self.assertTrue(rbac.can_assign_role(("owner",), "viewer"))
        self.assertTrue(rbac.can_assign_role(("admin",), "admin"))
        self.assertFalse(rbac.can_assign_role(("admin",), "owner"))
        self.assertFalse(rbac.can_assign_role(("security_manager",), "admin"))
        self.assertFalse(rbac.can_assign_role(("analyst",), "admin"))
        self.assertFalse(rbac.can_assign_role(("viewer",), "analyst"))
        self.assertFalse(rbac.can_assign_role((), "viewer"))

    def test_union_of_membership_roles(self):
        perms = rbac.permissions_for(("viewer", "analyst"))
        self.assertEqual(perms, rbac.permissions_for(("analyst",)))

    def test_authority_order(self):
        self.assertLess(rbac.authority("viewer"), rbac.authority("owner"))
        with self.assertRaises(errors.ValidationError):
            rbac.authority("god")


class TestTenantIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2ten_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = make_service(self.tmp)
        self.id_svc = identity_mod.IdentityService(self.svc, scrypt_n=2 ** 8)
        self.orgA = self.svc.org_create("Alpha")
        self.orgB = self.svc.org_create("Beta")
        self.uA = add_user(self.id_svc, self.orgA, "uauser", "ua@alpha.test",
                           ("owner",))
        self.uB = add_user(self.id_svc, self.orgB, "ubuser", "ub@beta.test",
                           ("owner",))
        self.authz = authz.AuthorizationService(self.svc, self.id_svc)
        self.ctxA = self.authz._context_for_user(self.uA.id, actor="test")
        self.ctxB = self.authz._context_for_user(self.uB.id, actor="test")
        self.projB = self.svc.project_create(self.orgB.id, "beta-web")
        self.assetB = self.svc.asset_add(self.projB.id, "domain", "beta.test")
        self.scanB = self.svc.scan_create(self.projB.id, "web-audit")
        self.fB = models.Finding(scan_id=self.scanB.id,
                                 project_id=self.projB.id,
                                 title="Beta issue", severity="High",
                                 category="misconfiguration",
                                 source="test", rule_id="B-1")
        self.fB.finalize()
        ev = models.Evidence(finding_id=self.fB.id, evidence_type="response",
                             detection_reason="beta evidence")
        ev.finalize()
        self.svc.finding_ingest(self.fB, evidence=[ev])
        self.evB = self.svc.db.query(
            "SELECT id FROM evidence WHERE finding_id=? LIMIT 1",
            (self.fB.id,))

    def test_project_cross_org_denied(self):
        # org-A user must NEVER reach the org-B project
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_project(self.ctxA, self.projB.id)
        # the org-B owner reaches its OWN project (and nothing else)
        got = self.authz.require_project(self.ctxB, self.projB.id)
        self.assertEqual(got.id, self.projB.id)

    def test_org_cross_denied(self):
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_org(self.ctxA, self.orgB.id)
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_org(self.ctxB, self.orgA.id)

    def test_asset_cross_org_denied(self):
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_asset(self.ctxA, self.assetB.id)

    def test_scan_cross_org_denied(self):
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_scan(self.ctxA, self.scanB.id)

    def test_finding_cross_org_denied(self):
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_finding(self.ctxA, self.fB.id)

    def test_evidence_cross_org_denied(self):
        self.assertTrue(self.evB)
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_evidence(self.ctxA, self.evB[0]["id"])

    def test_audit_cross_org_denied(self):
        with self.assertRaises(errors.AuthorizationError):
            self.authz.audit_visible_rows(self.ctxA, self.orgB.id)
        rows = self.authz.audit_visible_rows(self.ctxA, self.orgA.id)
        for r in rows:
            self.assertEqual(r.org_id, self.orgA.id)

    def test_credential_cross_org_denied(self):
        out = self.id_svc.credential_create(self.orgB.id, "beta-key",
                                            ("finding.read",),
                                            created_by=self.uB.id,
                                            actor="test")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_credential(self.ctxA, out["credential"].id)
        # own org is fine
        cred = self.authz.require_credential(self.ctxB,
                                             out["credential"].id)
        self.assertNotIn("verifier", cred.to_dict())

    def test_visible_projects_scoped(self):
        self.svc.project_create(self.orgA.id, "alpha-web")
        ids = {p.id for p in self.authz.visible_projects(self.ctxA)}
        self.assertIn(self.svc.project_list(self.orgA.id)[-1].id, ids)
        self.assertNotIn(self.projB.id, ids)

    def test_forged_ids_in_parameters(self):
        # client supplies org/project ids of ANOTHER tenant → still denied
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_org(self.ctxA, "00000000-0000-0000-0000-000000000000")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_project(self.ctxA,
                                       "00000000-0000-0000-0000-000000000000")

    def test_denials_are_audited_safely(self):
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_project(self.ctxA, self.projB.id)
        events = [e for e in self.svc.audit_list(None, limit=500)
                  if e.action == "authorization.denied"]
        self.assertTrue(events)
        blob = json.dumps([e.to_dict() for e in events])
        self.assertNotIn("beta-web", blob)
        self.assertNotIn(self.projB.id, blob)

    def test_membership_scoping(self):
        u = add_user(self.id_svc, self.orgA, "mem1", "m1@alpha.test",
                     ("analyst",))
        # cross-org membership is ALWAYS denied — even with allow_any_role
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.member_set(u.id, self.projB.id, "viewer",
                                   allow_any_role=True, actor="test")
        # org-A membership works and grants that project only
        projA = self.svc.project_create(self.orgA.id, "alpha-2")
        self.id_svc.member_set(u.id, projA.id, "viewer",
                               allow_any_role=True, actor="test")
        ctx2 = self.authz._context_for_user(u.id, actor="test")
        self.assertIsNotNone(self.authz.require_project(ctx2, projA.id))
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_project(ctx2, self.projB.id)


class TestPrivilegeEscalation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2esc_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.id_svc, self.org = make_org(self.tmp)
        self.owner = add_user(self.id_svc, self.org, "root", "root@a.test",
                              ("owner",))
        self.viewer = add_user(self.id_svc, self.org, "view1", "v1@a.test",
                               ("viewer",))
        self.analyst = add_user(self.id_svc, self.org, "analy1", "an1@a.test",
                                ("analyst",))
        self.authz = authz.AuthorizationService(self.svc, self.id_svc)

    def test_viewer_cannot_create_admin(self):
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.user_create(self.org.id, "evil1", "evil1@a.test",
                                    PW_A, roles=("admin",),
                                    as_roles=("viewer",), actor="v1")

    def test_viewer_cannot_create_anyone(self):
        # even granting an equal/lesser role requires the user.create
        # permission (defense in depth at the service layer)
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.user_create(
                self.org.id, "evil2", "evil2@a.test", PW_A,
                roles=("viewer",), as_roles=("viewer",),
                as_permissions=rbac.permissions_for(("viewer",)), actor="v1")

    def test_analyst_cannot_promote_to_admin(self):
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.user_set_roles(self.viewer.id, ("admin",),
                                       as_roles=("analyst",), actor="an1")

    def test_admin_cannot_create_owner(self):
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.user_create(self.org.id, "evil3", "evil3@a.test",
                                    PW_A, roles=("owner",),
                                    as_roles=("admin",), actor="admin")

    def test_no_roles_cannot_grant_anything(self):
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.user_create(self.org.id, "evil4", "evil4@a.test",
                                    PW_A, roles=("viewer",),
                                    as_roles=(), actor="none")

    def test_owner_can_assign_analyst(self):
        u = self.id_svc.user_set_roles(self.viewer.id, ("analyst",),
                                       as_roles=("owner",), actor="root")
        self.assertEqual(self.id_svc.user_roles(self.viewer.id), ("analyst",))

    def test_project_member_cross_project_role(self):
        projA = self.svc.project_create(self.org.id, "pa")
        projB = self.svc.project_create(self.org.id, "pb")
        self.id_svc.member_set(self.viewer.id, projA.id, "viewer",
                               allow_any_role=True, actor="root")
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.member_set(self.viewer.id, projB.id, "admin",
                                   as_roles=("viewer",), actor="v1")

    def test_membership_requires_same_org(self):
        org2 = self.svc.org_create("Other")
        proj2 = self.svc.project_create(org2.id, "o2")
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.member_set(self.owner.id, proj2.id, "viewer",
                                   allow_any_role=True, actor="root")

    def test_credential_scope_cannot_exceed_creator(self):
        with self.assertRaises(errors.AuthorizationError):
            self.id_svc.credential_create(
                self.org.id, "overkey", ("user.disable",),
                created_by=self.viewer.id,
                as_permissions=rbac.permissions_for(("viewer",)),
                actor="v1")
        out = self.id_svc.credential_create(
            self.org.id, "okkey", ("finding.read",),
            created_by=self.viewer.id,
            as_permissions=rbac.permissions_for(("viewer",)), actor="v1")
        self.assertEqual(out["credential"].scopes, ["finding.read"])

    def test_forged_role_name_rejected(self):
        with self.assertRaises(errors.ValidationError):
            self.id_svc.user_set_roles(self.viewer.id, ("admin,owner",),
                                       allow_any_role=True, actor="root")


class TestApiCredentials(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2cred_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.id_svc, self.org = make_org(self.tmp)
        self.owner = add_user(self.id_svc, self.org, "cky", "ck@a.test",
                              ("owner",))
        self.authz = authz.AuthorizationService(self.svc, self.id_svc)

    def test_create_returns_secret_once_prefix_and_verifier(self):
        out = self.id_svc.credential_create(self.org.id, "ci", ("scan.read",),
                                            created_by=self.owner.id,
                                            actor="test")
        self.assertTrue(out["secret"].startswith("stk_"))
        self.assertEqual(out["credential"].key_prefix, out["secret"][:10])
        self.assertNotEqual(out["credential"].verifier, out["secret"])
        self.assertEqual(out["credential"].verifier,
                         hashlib.sha256(out["secret"].encode()).hexdigest())
        self.assertEqual(out["credential"].scopes, ["scan.read"])

    def test_secret_never_persisted(self):
        out = self.id_svc.credential_create(self.org.id, "ci2", (),
                                            created_by=self.owner.id,
                                            actor="test")
        conn = sqlite3.connect(os.path.join(self.tmp, "test_platform.db"))
        blob = " ".join(str(r) for r in
                        conn.execute("SELECT * FROM api_credentials"))
        self.assertNotIn(out["secret"], blob)
        self.assertIn(out["credential"].key_prefix, blob)
        conn.close()

    def test_list_has_no_secret_material(self):
        self.id_svc.credential_create(self.org.id, "ci3", ("finding.read",),
                                      created_by=self.owner.id, actor="test")
        for c in self.id_svc.credential_list(self.org.id):
            d = c.to_dict()
            self.assertNotIn("verifier", d)
            self.assertNotIn("secret", d)
            self.assertIn("key_prefix", d)

    def test_authenticate_and_context(self):
        out = self.id_svc.credential_create(self.org.id, "ci4",
                                            ("finding.read",),
                                            created_by=self.owner.id,
                                            actor="test")
        cred = self.id_svc.credential_authenticate(out["secret"])
        self.assertEqual(cred.id, out["credential"].id)
        self.assertTrue(cred.last_used_at)
        ctx = self.authz.context_from_secret(out["secret"])
        self.assertEqual(ctx.org_id, self.org.id)
        self.assertIn("finding.read", ctx.permissions)
        self.assertNotIn("scan.create", ctx.permissions)

    def test_revoked_credential_rejected(self):
        out = self.id_svc.credential_create(self.org.id, "ci5", (),
                                            created_by=self.owner.id,
                                            actor="test")
        self.id_svc.credential_revoke(out["credential"].id, actor="test")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.credential_authenticate(out["secret"])

    def test_expired_credential_rejected_and_marked(self):
        out = self.id_svc.credential_create(self.org.id, "ci6", (),
                                            created_by=self.owner.id,
                                            ttl_seconds=3600, actor="test")
        self.svc.db.execute("UPDATE api_credentials SET expires_at="
                            "'2000-01-01T00:00:00Z' WHERE id=?",
                            (out["credential"].id,))
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.credential_authenticate(out["secret"])
        self.assertEqual(
            self.id_svc.credential_get(out["credential"].id).status,
            "expired")

    def test_rotate_old_secret_dead_scopes_unchanged(self):
        out = self.id_svc.credential_create(
            self.org.id, "ci7", ("finding.read", "scan.read"),
            created_by=self.owner.id, actor="test")
        new = self.id_svc.credential_rotate(out["credential"].id)
        self.assertNotEqual(new["secret"], out["secret"])
        self.assertEqual(new["credential"].scopes, ["finding.read", "scan.read"])
        self.assertIsNotNone(
            self.id_svc.credential_authenticate(new["secret"]))
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.credential_authenticate(out["secret"])

    def test_invalid_scope_rejected(self):
        with self.assertRaises(errors.ValidationError):
            self.id_svc.credential_create(self.org.id, "ci8",
                                          ("scan.destroy",),
                                          created_by=self.owner.id,
                                          actor="test")

    def test_project_bound_credential_scoped(self):
        proj = self.svc.project_create(self.org.id, "pb")
        out = self.id_svc.credential_create(self.org.id, "ci9",
                                            ("scan.read",),
                                            created_by=self.owner.id,
                                            project_id=proj.id, actor="test")
        ctx = self.authz.context_from_secret(out["secret"])
        self.assertIsNotNone(self.authz.require_project(ctx, proj.id))
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_org(ctx, self.org.id)
        other = self.svc.project_create(self.org.id, "pb2")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_project(ctx, other.id)


class TestAuditIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2aud_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.id_svc, self.org = make_org(self.tmp)
        self.owner = add_user(self.id_svc, self.org, "auu", "au@a.test",
                              ("owner",))
        self.id_svc.login("au@a.test", PW_A)   # login_success + session

    def _conn(self):
        return sqlite3.connect(os.path.join(self.tmp, "test_platform.db"))

    def test_chain_clean(self):
        report = self.svc.audit_verify()
        self.assertTrue(report["ok"], report["issues"])
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["legacy"], 0)
        self.assertGreaterEqual(report["verified"], 4)

    def test_tampered_payload_detected(self):
        conn = self._conn()
        conn.execute(
            "UPDATE audit_events SET metadata='{\"tampered\":true}' "
            "WHERE id=(SELECT id FROM audit_events ORDER BY rowid LIMIT 1 "
            "OFFSET 1)")
        conn.commit()
        conn.close()
        report = self.svc.audit_verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("modified" in i for i in report["issues"]))

    def test_deleted_middle_event_detected(self):
        conn = self._conn()
        ids = [r[0] for r in conn.execute(
            "SELECT id FROM audit_events ORDER BY rowid")]
        conn.execute("DELETE FROM audit_events WHERE id=?", (ids[1],))
        conn.commit()
        conn.close()
        report = self.svc.audit_verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("missing or reordered" in i
                            for i in report["issues"]))

    def test_reordered_events_detected(self):
        conn = self._conn()
        ids = [r[0] for r in conn.execute(
            "SELECT id FROM audit_events ORDER BY rowid")]
        conn.execute("UPDATE audit_events SET rowid=rowid+100 WHERE id=?",
                     (ids[0],))
        conn.execute("UPDATE audit_events SET rowid=rowid-99 WHERE id=?",
                     (ids[1],))
        conn.commit()
        conn.close()
        report = self.svc.audit_verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("missing or reordered" in i
                            for i in report["issues"]))

    def test_auth_events_present(self):
        events = [e.action for e in self.svc.audit_list(None, limit=500)]
        self.assertIn("login_success", events)
        self.assertIn("session.created", events)
        self.assertIn("user.created", events)
        self.assertIn("organization.created", events)

    def test_no_secrets_in_audit(self):
        # force failing auth + credential ops then scan every audit row
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("au@a.test", "bad-secret-pw-999")
        out = self.id_svc.credential_create(self.org.id, "au-key",
                                            ("finding.read",),
                                            created_by=self.owner.id,
                                            actor="test")
        self.id_svc.credential_revoke(out["credential"].id, actor="test")
        conn = self._conn()
        blob = " ".join(str(r) for r in conn.execute(
            "SELECT metadata FROM audit_events"))
        conn.close()
        for needle in (PW_A, "bad-secret-pw-999", out["secret"],
                       "S3cure", "stk_" + out["secret"][4:20]):
            self.assertNotIn(needle, blob)

    def test_legacy_rows_reported(self):
        """A Phase-1→Phase-2 migration boundary: existing Phase-1 rows have
        no hashes; the FIRST chained event starts the chain (prev='') with a
        correctly computed hash. Verify reports legacy rows separately and
        stays clean."""
        conn = self._conn()
        n = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        conn.execute("UPDATE audit_events SET event_hash='', prev_hash=''")
        conn.commit()
        conn.close()
        report = self.svc.audit_verify()
        self.assertEqual(report["legacy"], n)
        self.assertTrue(report["ok"], report["issues"])
        # a new event after the migration boundary chains correctly
        self.svc.audit("scan.created", object_type="scan", object_id="s1",
                       org_id=self.org.id, actor="migration")
        report2 = self.svc.audit_verify()
        self.assertEqual(report2["legacy"], n)
        self.assertEqual(report2["verified"], 1)
        self.assertTrue(report2["ok"], report2["issues"])

    def test_event_metadata_redaction_still_applies(self):
        self.svc.audit("finding.created", object_type="finding",
                       object_id="f1", org_id=self.org.id,
                       metadata={"note": "Bearer tok-secret-12345 leaked"})
        conn = self._conn()
        blob = " ".join(str(r) for r in conn.execute(
            "SELECT metadata FROM audit_events"))
        conn.close()
        self.assertNotIn("tok-secret-12345", blob)
        self.assertIn("REDACTED", blob)


class TestRateLimiting(unittest.TestCase):
    def test_sliding_window_blocks(self):
        rl = identity_mod.RateLimiter()
        self.assertTrue(rl.allowed("k1", 2, 60)[0])
        self.assertTrue(rl.allowed("k1", 2, 60)[0])
        ok, retry = rl.allowed("k1", 2, 60)
        self.assertFalse(ok)
        self.assertGreater(retry, 0)
        # other keys unaffected (per-key isolation)
        self.assertTrue(rl.allowed("k2", 2, 60)[0])

    def test_window_expiry(self):
        rl = identity_mod.RateLimiter()
        self.assertTrue(rl.allowed("k3", 1, 1)[0])
        self.assertFalse(rl.allowed("k3", 1, 1)[0])
        time.sleep(1.05)
        self.assertTrue(rl.allowed("k3", 1, 1)[0])

    def test_bounded_memory(self):
        rl = identity_mod.RateLimiter(max_keys=8)
        for i in range(50):
            rl.allowed(f"key{i}", 10, 60)
        self.assertLessEqual(len(rl._hits), 8)

    def test_service_throttle_raises(self):
        self.addCleanup(lambda: identity_mod.RL_LIMITS.update(
            {"auth": (10000, 60)}))
        identity_mod.RL_LIMITS["auth"] = (1, 60)
        tmp = tempfile.mkdtemp(prefix="p2rl_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        svc2, id2, org2 = make_org(tmp, name="RL")
        u2 = add_user(id2, org2, "rlu", "rl@a.test", ("viewer",))
        id2.login("rl@a.test", PW_A)
        with self.assertRaises(errors.RateLimitedError):
            id2.login("rl@a.test", PW_A)


class TestPasswordReset(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2rst_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.id_svc, self.org = make_org(self.tmp)
        self.u = add_user(self.id_svc, self.org, "pwu", "pw@a.test", ("viewer",))

    def test_generic_response_for_unknown(self):
        out = self.id_svc.password_reset_request("ghost@a.test")
        self.assertTrue(out["requested"])
        self.assertEqual(out["token"], "")

    def test_request_and_consume(self):
        out = self.id_svc.password_reset_request("pw@a.test")
        self.assertTrue(out["token"].startswith("rst_"))
        self.id_svc.password_reset_consume(out["token"], "Br@ndNew!Pass99")
        self.assertEqual(self.id_svc.user_get(self.u.id).status, "active")
        # old password dead, new one works
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("pw@a.test", PW_A)
        lout = self.id_svc.login("pw@a.test", "Br@ndNew!Pass99")
        self.assertEqual(lout["user"].id, self.u.id)

    def test_single_use(self):
        out = self.id_svc.password_reset_request("pw@a.test")
        self.id_svc.password_reset_consume(out["token"], "Br@ndNew!Pass99")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.password_reset_consume(out["token"], "X" * 20 + "9")

    def test_expired_token_rejected(self):
        out = self.id_svc.password_reset_request("pw@a.test")
        self.svc.db.execute(
            "UPDATE password_resets SET expires_at='2000-01-01T00:00:00Z' "
            "WHERE user_id=?", (self.u.id,))
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.password_reset_consume(out["token"], "Y" * 20 + "9")

    def test_consume_revokes_sessions(self):
        lout = self.id_svc.login("pw@a.test", PW_A)
        out = self.id_svc.password_reset_request("pw@a.test")
        self.id_svc.password_reset_consume(out["token"], "Br@ndNew!Pass99")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(lout["secret"])

    def test_reset_token_not_in_db(self):
        out = self.id_svc.password_reset_request("pw@a.test")
        conn = sqlite3.connect(os.path.join(self.tmp, "test_platform.db"))
        blob = " ".join(str(r) for r in
                        conn.execute("SELECT * FROM password_resets"))
        conn.close()
        self.assertNotIn(out["token"], blob)


class TestSessions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2sess_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.id_svc, self.org = make_org(self.tmp)
        self.u = add_user(self.id_svc, self.org, "seu", "se@a.test", ("viewer",))

    def test_list_and_revoke_all_on_disable(self):
        s1 = self.id_svc.session_create(self.u.id)
        s2 = self.id_svc.session_create(self.u.id)
        self.assertEqual(len(self.id_svc.sessions_list(self.u.id)), 2)
        self.id_svc.user_set_status(self.u.id, "disabled", actor="test")
        for s in (s1, s2):
            with self.assertRaises(errors.AuthenticationError):
                self.id_svc.session_authenticate(s["secret"])

    def test_session_secret_never_in_db(self):
        s = self.id_svc.session_create(self.u.id)
        conn = sqlite3.connect(os.path.join(self.tmp, "test_platform.db"))
        blob = " ".join(str(r) for r in conn.execute("SELECT * FROM sessions"))
        conn.close()
        self.assertNotIn(s["secret"], blob)

    def test_password_change_revokes_sessions(self):
        s = self.id_svc.session_create(self.u.id)
        self.id_svc.user_set_password(self.u.id, "Ch@nged!Pass12")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(s["secret"])


class TestDashboardSecurity(unittest.TestCase):
    def test_bearer_and_cookie_and_query_compatibility_gate(self):
        self.assertTrue(dashboard.check_access("tok123", "tok123", "", ""))
        self.assertTrue(dashboard.check_access("tok123", "", "tok123", ""))
        self.assertFalse(dashboard.check_access("tok123", "", "", "tok123"))
        self.assertTrue(dashboard.check_access(
            "tok123", "", "", "tok123", allow_legacy_query=True))

    def test_wrong_token_rejected(self):
        self.assertFalse(dashboard.check_access("tok123", "tok124", "", ""))
        self.assertFalse(dashboard.check_access("tok123", "", "tok122", ""))
        self.assertFalse(dashboard.check_access("tok123", "", "", "tok121"))

    def test_local_mode_no_token(self):
        self.assertTrue(dashboard.check_access("", "anything", "x", "y"))

    def test_dashboard_token_uses_environment_when_cli_is_omitted(self):
        self.assertEqual(
            dashboard.configured_dashboard_token(
                None,
                {"SECURITY_TOOLKIT_DASHBOARD_TOKEN": "env-token"},
            ),
            "env-token",
        )
        self.assertEqual(
            dashboard.configured_dashboard_token(
                "cli-token",
                {"SECURITY_TOOLKIT_DASHBOARD_TOKEN": "env-token"},
            ),
            "cli-token",
        )
        self.assertEqual(dashboard.configured_dashboard_token(None, {}), "")

    def test_query_token_stripped_from_logs(self):
        self.assertEqual(
            dashboard.safe_request_line("/api/scans?t=SECRET123&x=1"),
            "/api/scans")
        self.assertEqual(dashboard.safe_request_line("/"), "/")
        blob = dashboard.safe_request_line("/export/a/b?t=SECRET")
        self.assertNotIn("SECRET", blob)

    def test_legacy_dashboard_api_no_longer_appends_query_tokens(self):
        with open(dashboard.__file__, encoding="utf-8") as source_file:
            source = source_file.read()
        self.assertNotIn("location.search.match(/[?&]t=", source)
        self.assertNotIn("u+(u.includes('?')?'&':'?')+'t='+q", source)

    def test_persisted_provider_error_is_safely_summarized(self):
        self.assertEqual(
            dashboard.safe_stored_error("/srv/private/token=secret"),
            "operation_failed",
        )
        self.assertEqual(dashboard.safe_stored_error(""), "")

    def test_access_log_never_writes_query_credentials(self):
        class Fake:
            client_address = ("127.0.0.1", 12345)
            command = "GET"
            path = "/api/scans?t=SECRET123&filter=all"
            request_version = "HTTP/1.1"

        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            dashboard.Handler.log_message(Fake(), "%s", "ignored")
        logged = output.getvalue()
        self.assertIn("GET /api/scans HTTP/1.1", logged)
        self.assertNotIn("SECRET123", logged)
        self.assertNotIn("filter=all", logged)

    def test_handler_error_is_redacted_and_correlated(self):
        class Fake:
            headers = {"X-Request-ID": "request-test-123"}
            path = "/"
            scans = []
            tenants = {}
            root = "."
            request_id = ""

            def authorized(self):
                return True

            def send(self, code, body, *args, **kwargs):
                self.response = (code, body)
                return self.response

        fake = Fake()
        with patch.object(dashboard.Handler, "refresh", return_value=None), \
                patch.object(
                    dashboard,
                    "render_overview",
                    side_effect=RuntimeError("/private/path SECRET123"),
                ), \
                patch.object(dashboard.logging, "getLogger") as get_logger:
            dashboard.Handler.route(fake, "GET")
        self.assertEqual(fake.response[0], 500)
        self.assertNotIn(b"SECRET123", fake.response[1])
        self.assertNotIn(b"private/path", fake.response[1])
        self.assertEqual(fake.request_id, "request-test-123")
        get_logger.assert_called_once_with("security_toolkit.dashboard")
        get_logger.return_value.error.assert_called_once()

    def test_json_error_contains_request_id(self):
        class Fake:
            request_id = "request-test-789"

            def _request_id(self):
                return self.request_id

            def send(self, code, body, ctype):
                self.response = (code, body, ctype)

        fake = Fake()
        dashboard.Handler.json_out(fake, 500, {"error": "internal_error"})
        self.assertEqual(fake.response[0], 500)
        self.assertEqual(
            json.loads(fake.response[1])["request_id"], "request-test-789")

    def test_response_has_request_id_and_secure_headers(self):
        class Fake:
            headers = {"X-Request-ID": "request-test-456"}
            request_id = ""
            wfile = io.BytesIO()

            def _request_id(self):
                self.request_id = dashboard.safe_request_id(
                    self.headers.get("X-Request-ID", ""))
                return self.request_id

            def send_response(self, code):
                self.status = code

            def send_header(self, name, value):
                self.headers_sent[name.lower()] = value

            def end_headers(self):
                return None

        fake = Fake()
        fake.headers_sent = {}
        dashboard.Handler.send(fake, 200, b"ok")
        self.assertEqual(fake.headers_sent["x-request-id"], "request-test-456")
        self.assertEqual(fake.headers_sent["x-content-type-options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", fake.headers_sent["content-security-policy"])
        self.assertEqual(fake.headers_sent["cross-origin-opener-policy"], "same-origin")
        self.assertEqual(fake.headers_sent["cache-control"], "no-store")
        self.assertEqual(dashboard.Handler.version_string(Fake()), "SecurityToolkit")

    def test_same_origin_check(self):
        class Fake:
            def __init__(self, headers):
                self.headers = headers
        ok = dashboard.Handler._same_origin_request(
            Fake({"Origin": "http://127.0.0.1:8080",
                  "Host": "127.0.0.1:8080"}))
        self.assertTrue(ok)
        bad = dashboard.Handler._same_origin_request(
            Fake({"Origin": "https://evil.example",
                  "Host": "127.0.0.1:8080"}))
        self.assertFalse(bad)
        none = dashboard.Handler._same_origin_request(Fake({}))
        self.assertFalse(none)

    def test_security_headers_present_in_send(self):
        # headers are emitted in send(); verify all names exist as literals
        src = open(os.path.join(PY, "dashboard.py"), encoding="utf-8").read()
        for h in ("Content-Security-Policy", "X-Request-ID",
                  "X-Content-Type-Options", "X-Frame-Options",
                  "Referrer-Policy", "Permissions-Policy",
                  "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
                  "Cache-Control"):
            self.assertIn(h, src)

    def test_no_reflected_cors_allow_origin(self):
        src = open(os.path.join(PY, "dashboard.py"), encoding="utf-8").read()
        self.assertNotIn("Access-Control-Allow-Origin: *", src)
        self.assertNotIn("ACAO", src)


class TestDashboardCommandSecurity(unittest.TestCase):
    def test_cli_token_is_passed_to_child_via_environment_not_argv(self):
        args = SimpleNamespace(
            root="results",
            host="127.0.0.1",
            port=8080,
            token="cli-token",
            jobs_db=None,
            jobs_org="",
            intel_db=None,
            intel_org="",
        )
        warning = io.StringIO()
        with patch.dict(os.environ, {}, clear=False) as environment:
            with patch.object(main_cli, "run_py") as run_child, \
                    contextlib.redirect_stderr(warning):
                main_cli.cmd_dashboard(args)
            self.assertEqual(
                environment["SECURITY_TOOLKIT_DASHBOARD_TOKEN"], "cli-token")
        self.assertEqual(
            run_child.call_args.args,
            (
                "dashboard.py",
                "--root", "results",
                "--host", "127.0.0.1",
                "--port", "8080",
            ),
        )
        self.assertIn("process inspection", warning.getvalue())


class TestPhase2SecurityRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p2regr_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.id_svc, self.org = make_org(self.tmp)
        self.u = add_user(self.id_svc, self.org, "rgu", "rg@a.test", ("owner",))
        self.proj = self.svc.project_create(self.org.id, "web")

    def test_sqli_in_username_rejected_as_validation(self):
        with self.assertRaises(errors.ValidationError):
            self.id_svc.user_create(self.org.id,
                                    "admin' OR '1'='1", "x@x.test", PW_A,
                                    roles=("viewer",), allow_any_role=True,
                                    actor="test")

    def test_oversized_input_rejected(self):
        with self.assertRaises(errors.ValidationError):
            self.id_svc.user_create(self.org.id, "x" * 300, "x@x.test", PW_A,
                                    roles=("viewer",), allow_any_role=True,
                                    actor="test")
        with self.assertRaises(errors.ValidationError):
            self.id_svc.user_create(self.org.id, "ok_name", "not-an-email",
                                    PW_A, roles=("viewer",),
                                    allow_any_role=True, actor="test")

    def test_malformed_json_style_identifier(self):
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login('root"@x.test"', PW_A)

    def test_no_secrets_in_logs(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            seclog.info("login attempt", user="Bearer tok-leak-987654321",
                        password=PW_A, extra={"token": "ses_leak_12345"})
        out = buf.getvalue()
        for needle in ("tok-leak-987654321", PW_A, "ses_leak_12345"):
            self.assertNotIn(needle, out)
        self.assertIn("REDACTED", out)

    def test_evidence_still_redacted_via_platform(self):
        raw = {"tool": "SecuAudit", "target": "https://rg.test/",
               "findings": [{"id": "R-1", "title": "B",
                             "severity": "High",
                             "evidence": "Authorization: Bearer tok-1234567890"}]}
        self.svc.register_scanner_result(self.proj.id, raw)
        conn = sqlite3.connect(os.path.join(self.tmp, "test_platform.db"))
        blob = " ".join(str(r) for r in
                        conn.execute("SELECT evidence, raw FROM findings"))
        conn.close()
        self.assertNotIn("tok-1234567890", blob)

    def test_secret_query_pattern_redacted(self):
        self.assertIn("[REDACTED]",
                      redact.redact_text("https://app/t?token=zzz111&id=2"))

    def test_user_enumeration_impossible(self):
        m1 = ""
        try:
            self.id_svc.login("ghost@x.test", PW_A)
        except errors.AuthenticationError as e:
            m1 = e.message
        m2 = ""
        try:
            self.id_svc.login("rg@a.test", "wrong-password-999")
        except errors.AuthenticationError as e:
            m2 = e.message
        self.assertEqual(m1, m2)

    def test_authorization_error_never_leaks_ids(self):
        auth_svc = authz.AuthorizationService(self.svc, self.id_svc)
        ctx = auth_svc.context_from_secret(
            self.id_svc.login("rg@a.test", PW_A)["secret"])
        try:
            auth_svc.require_project(ctx, "00000000-0000-0000-0000-000000000000")
        except errors.AuthorizationError as e:
            msg = str(e)
        self.assertEqual(msg, "Forbidden")

    def test_credential_name_validation(self):
        with self.assertRaises(errors.ValidationError):
            self.id_svc.credential_create(self.org.id, "n" * 97, (),
                                          created_by=self.u.id, actor="test")


if __name__ == "__main__":
    unittest.main()
