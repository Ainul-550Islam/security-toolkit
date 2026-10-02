#!/usr/bin/env python3
# ============================================================================
#  test_identity.py — Phase 8 enterprise identity & access (adversarial).
#  ---------------------------------------------------------------------------
#  Covers: TOTP MFA lifecycle, recovery codes, MFA policy (fail-closed),
#  session hardening (pending/absolute/idle/step-up), centralized step-up
#  gating, OIDC crypto validation, SAML XMLDSIG validation, JIT + group
#  mapping, SCIM 2.0 (Users/Groups), lifecycle + revocation, tenant
#  isolation, failure injection, concurrency, and scale.
#
#  The network is never touched: OIDC discovery/token/JWKS fetches are
#  replaced by the in-process JWKS cache; SAML responses are signed locally
#  with the committed test key (openssl CLI only produces test vectors).
# ============================================================================
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
sys.path.insert(0, os.path.dirname(__file__))

import authz as authz_mod
import errors
import identity as identity_mod
import mfa_service
import pki
import platform_service
import rbac as rbac_mod
import scim_service
import sso_service
import totp

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
P8_KEY = os.path.join(FIX, "p8test.key")
P8_PUB = os.path.join(FIX, "p8test.pub")
P8_CRT = os.path.join(FIX, "p8test.crt")

DSIG = "http://www.w3.org/2000/09/xmldsig#"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"

PASSWD = "Str0ng!Passw0rd-x9"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def make_jwt(payload: dict, *, alg: str = "RS256", kid: str = "testkey"):
    """Sign a JWT with the committed TEST private key (openssl CLI)."""
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    signing = (_b64u(json.dumps(header).encode("utf-8")) + "." +
               _b64u(json.dumps(payload).encode("utf-8"))).encode("utf-8")
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", P8_KEY],
                         input=signing, capture_output=True, check=True).stdout
    return signing.decode("ascii") + "." + _b64u(sig)


def saml_response(**overrides) -> str:
    """A minimal unsigned SAMLResponse; callers sign/digest it."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    aid = overrides.pop("assertion_id", "a-" + uuid.uuid4().hex[:16])
    rid = overrides.pop("request_id", "")
    nb = overrides.pop("not_before", now)
    na = overrides.pop("not_on_or_after", now)
    issuer = overrides.pop("issuer", "https://saml-idp.example.com")
    resp_issuer = overrides.pop("resp_issuer", issuer)
    dest = overrides.pop("destination", "https://app.example.com/saml/acs")
    audience = overrides.pop("audience", "https://app.example.com")
    recipient = overrides.pop("recipient", "https://app.example.com/saml/acs")
    nameid = overrides.pop("nameid", "saml-subj-1")
    email = overrides.pop("email", "sam.saml@acme.test")
    groups = overrides.pop("groups", ["security", "devops"])
    extra_assertions = int(overrides.pop("extra_assertions", 0))
    in_resp = (' InResponseTo="%s"' % rid) if rid else ""
    groups_xml = "".join("<saml:AttributeValue>%s</saml:AttributeValue>" % g
                         for g in groups)
    assertion = (
        '<saml:Assertion ID="%s" Version="2.0" IssueInstant="%s">'
        "<saml:Issuer>%s</saml:Issuer>"
        '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:'
        'nameid-format:persistent">%s</saml:NameID>'
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:'
        'bearer">'
        '<saml:SubjectConfirmationData Recipient="%s"%s NotOnOrAfter="%s"/>'
        "</saml:SubjectConfirmation></saml:Subject>"
        '<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">'
        "<saml:AudienceRestriction><saml:Audience>%s</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions>"
        '<saml:AttributeStatement>'
        '<saml:Attribute Name="email"><saml:AttributeValue>%s'
        "</saml:AttributeValue></saml:Attribute>"
        '<saml:Attribute Name="groups">%s</saml:Attribute>'
        "</saml:AttributeStatement></saml:Assertion>") % (
        aid, now, issuer, nameid, recipient, in_resp, na, nb, na, audience,
        email, groups_xml)
    extra = ""
    for i in range(extra_assertions):
        extra += assertion.replace(aid, "a-extra-%d" % i, 1)
    return (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="resp-x"'
        '%s Version="2.0" IssueInstant="%s" Destination="%s">'
        "<saml:Issuer>%s</saml:Issuer>"
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:'
        'status:Success"/></samlp:Status>%s%s</samlp:Response>') % (
        in_resp, now, dest, resp_issuer, assertion, extra)


def sign_saml(xml: str, *, key: str = P8_KEY, cert: str = P8_CRT,
              digest_b64: str | None = None) -> str:
    """Insert an enveloped signature as the LAST child of the single
    assertion and sign the exclusive-C14N SignedInfo (exactly what
    pki.verify_xmldsig checks). `digest_b64` substitutes a wrong digest."""
    root = pki.safe_xml_root(xml)
    assertion = pki.find_child(root, SAML_NS, "Assertion")
    digest = digest_b64 if digest_b64 is not None else _b64std(
        hashlib.sha256(pki.exc_c14n(assertion).encode("utf-8")).digest())
    aid = assertion.getAttribute("ID")
    sig_blob = (
        '<ds:Signature xmlns:ds="%s">'
        '<ds:SignedInfo>'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/'
        'xml-exc-c14n#"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/'
        'xmldsig-more#rsa-sha256"/>'
        '<ds:Reference URI="#%s"><ds:Transforms>'
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#'
        'enveloped-signature"/>'
        '</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/'
        '04/xmlenc#sha256"/>'
        "<ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        "<ds:SignatureValue>__SIG__</ds:SignatureValue>"
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo></ds:Signature>") % (
        DSIG, aid, digest, "".join(open(cert).read().splitlines()[1:-1]))
    out = xml.replace("</saml:AttributeStatement>",
                      "</saml:AttributeStatement>" + sig_blob, 1)
    root2 = pki.safe_xml_root(out)
    sig_el = pki.find_child(pki.find_child(root2, SAML_NS, "Assertion"),
                            DSIG, "Signature")
    si_el = pki.find_child(sig_el, DSIG, "SignedInfo")
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key],
                         input=pki.exc_c14n(si_el).encode("utf-8"),
                         capture_output=True, check=True).stdout
    return out.replace("__SIG__", _b64std(sig), 1)


def build_signed_response(request_id: str = "", **kwargs) -> str:
    """saml_response() + envelope signature (no network, no shared state)."""
    return sign_saml(saml_response(request_id=request_id, **kwargs))


def rbac_full(id_svc, user_id):
    """Effective permission set of a user (for credential scoping)."""
    return rbac_mod.permissions_for(id_svc.user_roles(user_id))


class IdentityTestCase(unittest.TestCase):
    """Fresh database + services per test (isolation; no shared state)."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.svc = platform_service.PlatformService(self.tmp.name)
        self.limiter = identity_mod.RateLimiter(max_keys=8192)
        self.id_svc = identity_mod.IdentityService(self.svc, rl=self.limiter)
        self.authz = authz_mod.AuthorizationService(self.svc, self.id_svc)
        self.mfa = mfa_service.MfaService(self.svc,
                                          identity_svc=self.id_svc)
        self.sso = sso_service.SsoService(self.svc,
                                          identity_svc=self.id_svc)
        self.scim = scim_service.ScimService(self.svc,
                                             identity_svc=self.id_svc)
        self.org = self.svc.org_create("acme")
        self.owner = self.id_svc.user_create(
            self.org.id, "owner", "owner@acme.test", PASSWD,
            roles=("owner",), allow_any_role=True, actor="test")
        self.user = self.id_svc.user_create(
            self.org.id, "analyst", "analyst@acme.test", PASSWD,
            roles=("analyst",), allow_any_role=True, actor="test")

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def login(self, ident: str = "owner@acme.test", pw: str = PASSWD):
        return self.id_svc.login(
            ident, pw, ip="203.0.113.9", actor="test",
            mfa_required=lambda u, roles:
                self.mfa.policy_requires(self.org.id, roles))

    def enroll_and_activate(self, user_id: str):
        enr = self.mfa.enroll_start(user_id)
        self.mfa.enroll_verify(user_id, totp.code_for(enr["seed"]))
        return enr
# ============================================================================
# MFA lifecycle + policy
# ============================================================================
class TestMfaLifecycle(IdentityTestCase):

    def test_seed_not_active_until_verified(self):
        enr = self.mfa.enroll_start(self.user.id)
        self.assertFalse(enr["enabled"])
        self.assertTrue(enr["verify_required"])
        self.assertFalse(self.mfa.mfa_status(self.user.id)["enabled"])
        with self.assertRaises(errors.AuthenticationError):
            self.mfa.enroll_verify(self.user.id, "000000")
        self.assertFalse(self.mfa.mfa_status(self.user.id)["enabled"])

    def test_verify_activates_mfa(self):
        enr = self.enroll_and_activate(self.user.id)
        st = self.mfa.mfa_status(self.user.id)
        self.assertTrue(st["enabled"])
        self.assertEqual(st["method"], "totp")
        self.assertTrue(st["verified_at"])

    def test_seed_encrypted_at_rest(self):
        enr = self.mfa.enroll_start(self.user.id)
        row = self.svc.db.query(
            "SELECT seed_enc FROM mfa_secrets WHERE user_id=? LIMIT 1",
            (self.user.id,))[0]
        self.assertNotIn(enr["seed"], row["seed_enc"])
        blob = b""
        for suffix in ("", "-wal", "-journal"):
            try:
                with open(self.tmp.name + suffix, "rb") as fh:
                    blob += fh.read()
            except OSError:
                pass
        self.assertNotIn(enr["seed"].encode("utf-8"), blob)

    def test_recovery_codes_single_use_and_rotation(self):
        self.enroll_and_activate(self.user.id)
        rc = self.mfa.recovery_codes_generate(self.user.id, count=6)
        self.assertEqual(len(rc["codes"]), 6)
        self.assertTrue(all(c.startswith(totp.RECOVERY_CODE_PREFIX)
                            for c in rc["codes"]))
        st = self.mfa.recovery_codes_list(self.user.id)
        self.assertEqual(st["unused"], 6)
        self.assertIsNone(st["codes"])            # codes are never re-listed
        out = self.mfa.challenge(self.user.id, rc["codes"][0])
        self.assertEqual(out["method"], "recovery")
        with self.assertRaises(errors.AuthenticationError):
            self.mfa.challenge(self.user.id, rc["codes"][0])   # single-use
        st = self.mfa.recovery_codes_list(self.user.id)
        self.assertEqual(st["unused"], 5)
        self.assertEqual(st["used"], 1)
        rc2 = self.mfa.recovery_codes_generate(self.user.id, count=4)
        self.assertTrue(rc2["previous_invalidated"])
        # old batch is dead on arrival (spot-check 3; recovery_use is
        # rate-limited to 5/5min per user by design)
        for c in rc["codes"][:3]:
            with self.assertRaises(errors.AuthenticationError):
                self.mfa.challenge(self.user.id, c)
        self.assertEqual(self.mfa.recovery_codes_list(self.user.id)["unused"],
                         4)

    def test_recovery_codes_random_and_only_hmac_stored(self):
        self.enroll_and_activate(self.user.id)
        codes = self.mfa.recovery_codes_generate(self.user.id,
                                                 count=10)["codes"]
        self.assertEqual(len(set(codes)), 10)
        for c in codes:
            self.assertGreaterEqual(len(c), 30)
        rows = self.svc.db.query(
            "SELECT salt, code_hmac FROM mfa_recovery_codes WHERE user_id=? "
            "LIMIT 10", (self.user.id,))
        for r in rows:
            self.assertNotIn(r["code_hmac"], codes)
            for c in codes:
                self.assertNotIn(c, r["salt"] + r["code_hmac"])

    def test_totp_replay_rejected(self):
        enr = self.enroll_and_activate(self.user.id)
        # the activation code belongs to the current time-step; reset the
        # anti-replay marker so the SAME step can be asserted twice
        self.svc.db.execute(
            "UPDATE mfa_secrets SET last_used_step=0 WHERE user_id=?",
            (self.user.id,))
        code = totp.code_for(enr["seed"])
        self.assertTrue(self.mfa.challenge(self.user.id, code)["verified"])
        with self.assertRaises(errors.AuthenticationError):
            self.mfa.challenge(self.user.id, code)     # same period reused
        # a FUTURE step is never admitted either (replay of past steps)
        self.svc.db.execute(
            "UPDATE mfa_secrets SET last_used_step=? WHERE user_id=?",
            (totp.current_step() + 50, self.user.id))
        with self.assertRaises(errors.AuthenticationError):
            self.mfa.challenge(self.user.id, totp.code_for(enr["seed"]))

    def test_wrong_code_lockout(self):
        enr = self.mfa.enroll_start(self.user.id)
        self.mfa.enroll_verify(self.user.id, totp.code_for(enr["seed"]))
        # MAX_ATTEMPTS failures → the account's TOTP is locked (fail closed):
        # even the CORRECT code is refused until the lock expires
        for _ in range(5):
            with self.assertRaises(errors.AuthenticationError):
                self.mfa.challenge(self.user.id, "111111")
        with self.assertRaises(errors.RateLimitedError):
            self.mfa.challenge(self.user.id, totp.code_for(enr["seed"]))

    def test_reset_voids_everything_and_revokes_sessions(self):
        self.enroll_and_activate(self.user.id)
        self.mfa.recovery_codes_generate(self.user.id)
        self.mfa.policy_set(self.org.id, {"mode": "required"})
        out = self.login("analyst@acme.test")
        self.assertTrue(out["mfa_required"])
        res = self.mfa.reset(self.user.id)
        self.assertTrue(res["sessions_revoked"])
        self.assertTrue(res["reenroll_required"])
        self.assertFalse(self.mfa.mfa_status(self.user.id)["enabled"])
        self.assertEqual(self.mfa.recovery_codes_list(self.user.id)["issued"],
                         0)
        rows = self.svc.db.query(
            "SELECT revoked_at FROM sessions WHERE user_id=? AND "
            "revoke_reason='mfa_reset' LIMIT 3", (self.user.id,))
        self.assertTrue(rows)
        for r in rows:
            self.assertTrue(r["revoked_at"])

    def test_user_without_mfa_cannot_challenge(self):
        with self.assertRaises(errors.ValidationError):
            self.mfa.challenge(self.user.id, "123456")
        with self.assertRaises(errors.ValidationError):
            self.mfa.recovery_codes_generate(self.user.id)

    def test_policy_deterministic_and_fail_closed(self):
        self.mfa.policy_set(self.org.id, {"mode": "roles",
                                          "roles": ["admin"]})
        self.assertFalse(self.mfa.policy_requires(self.org.id, ("viewer",)))
        self.assertTrue(self.mfa.policy_requires(self.org.id, ("admin",)))
        self.svc.db.execute(
            "UPDATE mfa_policy SET mode='surprise' WHERE org_id=?",
            (self.org.id,))
        self.assertTrue(self.mfa.policy_requires(self.org.id, ("viewer",)))
        self.mfa.policy_set(self.org.id, {"mode": "roles", "roles": []})
        self.svc.db.execute(
            "UPDATE mfa_policy SET roles='not-json' WHERE org_id=?",
            (self.org.id,))
        self.assertTrue(self.mfa.policy_requires(self.org.id, ("viewer",)))

    def test_policy_validation_rejects_unknown_fields(self):
        with self.assertRaises(errors.ValidationError):
            self.mfa.policy_set(self.org.id, {"mode": "optional",
                                              "junk": True})
        with self.assertRaises(errors.ValidationError):
            self.mfa.policy_set(self.org.id, {"mode": "sometimes"})
        with self.assertRaises(errors.ValidationError):
            self.mfa.policy_set(self.org.id, {"mode": "optional",
                                              "roles": ["superuser"]})
        with self.assertRaises(errors.ValidationError):
            self.mfa.policy_set(self.org.id, {"mode": "optional",
                                              "step_up_ttl": 5})

    def test_policy_version_conflict(self):
        p = self.mfa.policy_set(self.org.id, {"mode": "optional"})
        self.assertEqual(p["version"], 1)
        with self.assertRaises(errors.ValidationError):
            self.mfa.policy_set(self.org.id, {"mode": "required"},
                                version=p["version"] + 7)
        # the CORRECT version is the only path to an update
        p2 = self.mfa.policy_set(self.org.id, {"mode": "required"},
                                 version=p["version"])
        self.assertEqual(p2["version"], 2)

    def test_seed_never_in_audit(self):
        enr = self.mfa.enroll_start(self.user.id)
        rows = self.svc.db.query(
            "SELECT action, metadata FROM audit_events LIMIT 200")
        self.assertGreater(len(rows), 0)
        for r in rows:
            self.assertNotIn(enr["seed"], r["metadata"])
            self.assertNotIn(enr["seed"], r["action"])


# ============================================================================
# Session hardening + centralized step-up gating
# ============================================================================
class TestSessionHardening(IdentityTestCase):

    def test_login_under_required_policy_creates_pending_session(self):
        self.mfa.policy_set(self.org.id, {"mode": "required"})
        out = self.login("owner@acme.test")
        self.assertTrue(out["mfa_required"])
        sess = out["session"]
        self.assertEqual(sess.mfa_status, "pending")
        self.assertEqual(sess.auth_method, "password")
        self.assertLess(
            identity_mod._parse_ts(sess.expires_at) - time.time(),
            identity_mod.PENDING_MFA_TTL_SECONDS + 5)

    def test_pending_session_cannot_act(self):
        self.mfa.policy_set(self.org.id, {"mode": "required"})
        out = self.login("owner@acme.test")
        ctx = self.authz.context_from_secret(out["secret"])
        self.assertEqual(ctx.mfa_status, "pending")
        for perm in ("identity.policy.update", "identity.sso.create",
                     "identity.scim.manage", "user.read", "scan.create"):
            with self.assertRaises(errors.AuthorizationError):
                self.authz.require(ctx, perm)
        self.authz.require(ctx, "identity.mfa.read")
        self.authz.require(ctx, "identity.sessions.read")

    def test_mfa_complete_upgrades_and_step_up_ok(self):
        self.mfa.policy_set(self.org.id, {"mode": "required"})
        out = self.login("owner@acme.test")
        self.enroll_and_activate(self.owner.id)
        self.id_svc.session_mfa_complete(out["session"].id)
        ctx = self.authz.context_from_secret(out["secret"])
        self.assertEqual(ctx.mfa_status, "verified")
        self.assertTrue(self.authz.step_up_ok(ctx))
        self.authz.require(ctx, "identity.policy.update")

    def test_step_up_expires_and_requires_refresh(self):
        self.mfa.policy_set(self.org.id, {"mode": "required"})
        out = self.login("owner@acme.test")
        self.enroll_and_activate(self.owner.id)
        self.id_svc.session_mfa_complete(out["session"].id)
        ctx = self.authz.context_from_secret(out["secret"])
        self.assertTrue(self.authz.step_up_ok(ctx))
        # an EXPIRED step-up window behaves like no step-up at all
        self.svc.db.execute(
            "UPDATE sessions SET step_up_until='2020-01-01T00:00:00Z' "
            "WHERE id=?", (out["session"].id,))
        ctx = self.authz.context_from_secret(out["secret"])
        self.assertEqual(ctx.mfa_status, "verified")
        self.assertFalse(self.authz.step_up_ok(ctx))
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx, "identity.sso.create")
        # a fresh step-up restores the window (re-auth, not implicit)
        self.id_svc.session_step_up(out["session"].id, ttl_seconds=600)
        ctx = self.authz.context_from_secret(out["secret"])
        self.assertTrue(self.authz.step_up_ok(ctx))

    def test_api_credential_channel_is_exempt(self):
        cred = self.id_svc.credential_create(
            self.org.id, "svc", ("identity.policy.update",),
            created_by=self.owner.id,
            as_permissions=rbac_full(self.id_svc, self.owner.id),
            actor="test")
        ctx = self.authz.context_from_secret(cred["secret"])
        self.assertTrue(ctx.credential_id)
        self.assertTrue(self.authz.step_up_ok(ctx))
        self.assertTrue(self.id_svc.credential_authenticate(cred["secret"]))

    def test_absolute_session_ttl_enforced(self):
        out = self.login("analyst@acme.test")
        self.id_svc.session_step_up(out["session"].id, ttl_seconds=600)
        self.svc.db.execute(
            "UPDATE sessions SET absolute_expires_at='2020-01-01T00:00:00Z' "
            "WHERE id=?", (out["session"].id,))
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(out["secret"])

    def test_idle_timeout_revokes(self):
        out = self.login("analyst@acme.test")
        self.svc.db.execute(
            "UPDATE sessions SET last_seen_at='2020-01-01T00:00:00Z' "
            "WHERE id=?", (out["session"].id,))
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(out["secret"])

    def test_revocation_reasons_and_org_scope(self):
        out = self.login("owner@acme.test")
        self.id_svc.session_revoke_id(out["session"].id, reason="compromise")
        row = self.svc.db.query_one(
            "SELECT revoke_reason, revoked_at FROM sessions WHERE id=?",
            (out["session"].id,))
        self.assertEqual(row["revoke_reason"], "compromise")
        self.assertTrue(row["revoked_at"])
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(out["secret"])
        out2 = self.login("owner@acme.test")
        n = self.id_svc.sessions_revoke_org(self.org.id,
                                            reason="org_emergency")
        self.assertGreaterEqual(n, 1)
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(out2["secret"])
        self.assertTrue(
            self.svc.db.query(
                "SELECT 1 FROM sessions WHERE revoke_reason='org_emergency'"))

    def test_sessions_list_org_scoped_and_token_free(self):
        self.login("owner@acme.test")
        self.login("analyst@acme.test")
        rows = self.id_svc.sessions_list_org(self.org.id, status="active")
        self.assertEqual(rows["total"], 2)
        for s in rows["sessions"]:
            self.assertNotIn("token_hash", s)
        org2 = self.svc.org_create("beta")
        self.assertEqual(self.id_svc.sessions_list_org(org2.id)["total"], 0)

    def test_require_own_session(self):
        out = self.login("owner@acme.test")
        ctx = self.authz.context_from_secret(out["secret"])
        self.authz.require_own_session(ctx, out["session"].id)
        out2 = self.login("analyst@acme.test")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_own_session(ctx, out2["session"].id)
# ============================================================================
# OIDC SSO — cryptographic validation
# ============================================================================
class TestOidc(IdentityTestCase):

    def _provider(self, issuer="https://idp.example.com",
                  client_id="client-1", enabled=True, jit=True, **cfg):
        base = {"issuer": issuer, "client_id": client_id,
                "authorization_endpoint": "https://idp.example.com/auth",
                "token_endpoint": "https://idp.example.com/token",
                "jwks_uri": "https://idp.example.com/jwks"}
        base.update(cfg)
        prov = self.sso.provider_create(
            self.org.id, "oidc", display_name="Test IdP", enabled=enabled,
            config=base, jit=jit, default_roles=("viewer",), actor="test")
        n, e = pki.load_rsa_public_key(open(P8_PUB).read())
        self.sso._jwks_cache[prov["id"]] = (time.time() + 600,
                                            {"testkey": {"n": n, "e": e}})
        return prov

    def _claims(self, **kw):
        now = int(time.time())
        out = {"iss": "https://idp.example.com", "sub": "subj-42",
               "aud": "client-1", "exp": now + 600, "iat": now,
               "nonce": "nonce-1", "email": "jit@acme.test",
               "groups": ["security"]}
        out.update(kw)
        return out

    def test_validation_matrix(self):
        prov = self._provider()
        pv = self.sso._provider_row(prov["id"])
        self.sso.oidc_validate_id_token(pv, make_jwt(self._claims()),
                                        nonce="nonce-1", client_id="client-1")
        for c in (dict(nonce="wrong"), dict(aud="other-client"),
                  dict(iss="https://evil.example.com"),
                  dict(exp=int(time.time()) - 10), dict(sub="")):
            tok = make_jwt(self._claims(**c))
            with self.assertRaises(errors.ValidationError):
                self.sso.oidc_validate_id_token(pv, tok, nonce="nonce-1",
                                                client_id="client-1")
        with self.assertRaises(errors.ValidationError):
            self.sso.oidc_validate_id_token(pv, make_jwt(self._claims(),
                                                         alg="HS256"),
                                            nonce="nonce-1")
        with self.assertRaises(errors.ValidationError):
            self.sso.oidc_validate_id_token(pv, "aaaa.bbbb.cccc",
                                            nonce="nonce-1")
        with self.assertRaises(errors.ValidationError):
            self.sso.oidc_validate_id_token(pv, "not-a-jwt", nonce="nonce-1")

    def test_tampered_payload_rejected(self):
        prov = self._provider()
        pv = self.sso._provider_row(prov["id"])
        head, _payload, sig = make_jwt(self._claims()).split(".")
        evil = _b64u(json.dumps(dict(self._claims(), sub="attacker"))
                     .encode("utf-8"))
        with self.assertRaises(errors.ValidationError):
            self.sso.oidc_validate_id_token(pv, head + "." + evil + "." + sig,
                                            nonce="nonce-1")

    def test_state_single_use_and_expiry(self):
        prov = self._provider()
        start = self.sso.oidc_start(prov["id"])
        self.assertIn("state=" + start["state"], start["authorization_url"])
        self.assertIn("nonce=" + start["nonce"],
                      start["authorization_url"])
        st = self.sso._consume_state(start["state"], prov["id"])
        self.assertFalse(st["used_at"])
        with self.assertRaises(errors.ValidationError):
            self.sso._consume_state(start["state"], prov["id"])
        start2 = self.sso.oidc_start(prov["id"])
        self.svc.db.execute(
            "UPDATE idp_state SET expires_at='2020-01-01T00:00:00Z' "
            "WHERE state=?", (start2["state"],))
        with self.assertRaises(errors.ValidationError):
            self.sso._consume_state(start2["state"], prov["id"])

    def test_pkce_verifier_binding(self):
        prov = self._provider(pkce=True)
        start = self.sso.oidc_start(prov["id"])
        self.assertTrue(start["code_verifier"])
        self.assertIn("code_challenge_method=S256",
                      start["authorization_url"])
        self.assertIn("code_challenge=", start["authorization_url"])

    def test_oidc_start_rejects_redirect_mismatch(self):
        # Fail-closed: an authorization URL may only carry the redirect URI
        # registered on the provider config — never a caller-chosen one.
        prov = self._provider(redirect_uri="https://app.example.com/cb")
        with self.assertRaises(errors.ValidationError):
            self.sso.oidc_start(prov["id"],
                                redirect_uri="https://evil.example.com/cb")
        ok = self.sso.oidc_start(
            prov["id"], redirect_uri="https://app.example.com/cb")
        self.assertIn(
            "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
            ok["authorization_url"])
        # No config redirect_uri -> caller's value becomes the binding.
        prov2 = self.sso.provider_create(
            self.org.id, "oidc", display_name="Test IdP B", enabled=True,
            config={"issuer": "https://idp.example.com",
                    "client_id": "client-1",
                    "authorization_endpoint": "https://idp.example.com/auth",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks"},
            jit=True, default_roles=("viewer",), actor="test")
        ok2 = self.sso.oidc_start(
            prov2["id"], redirect_uri="https://sp.example.com/cb")
        self.assertIn("redirect_uri=https%3A%2F%2Fsp.example.com%2Fcb",
                      ok2["authorization_url"])

    def test_oidc_callback_rejects_redirect_mismatch(self):
        # A callback advertising a redirect_uri that was not bound at start
        # time is rejected before the state is consumed.
        prov = self._provider(redirect_uri="https://app.example.com/cb")
        start = self.sso.oidc_start(prov["id"])
        tok = make_jwt(self._claims(nonce=start["nonce"]))
        with self.assertRaises(errors.ValidationError):
            self.sso.oidc_callback(
                prov["id"], state=start["state"], id_token=tok,
                redirect_uri="https://evil.example.com/cb")
        # The state is still valid for the bound redirect (never burned by
        # the rejected probe).
        out = self.sso.oidc_callback(
            prov["id"], state=start["state"], id_token=tok,
            redirect_uri="https://app.example.com/cb")
        self.assertIn("session", out)
        with self.assertRaises(errors.ValidationError):
            self.sso.oidc_callback(
                prov["id"], state=start["state"], id_token=tok,
                redirect_uri="https://app.example.com/cb")

    def test_provider_config_redaction(self):
        prov = self._provider(client_secret="super-secret-value")
        view = json.dumps(self.sso.provider_get(prov["id"]))
        self.assertNotIn("super-secret-value", view)
        self.assertIn("[REDACTED]", view)

    def test_provider_version_conflict_and_history(self):
        prov = self._provider()
        with self.assertRaises(errors.ValidationError):
            self.sso.provider_update(prov["id"], enabled=True, version=99)
        upd = self.sso.provider_update(prov["id"], enabled=True, version=1)
        self.assertEqual(upd["version"], 2)
        hist = self.svc.db.query(
            "SELECT change_type, diff FROM sso_provider_history WHERE "
            "provider_id=? ORDER BY version DESC LIMIT 3", (prov["id"],))
        self.assertEqual(len(hist), 2)
        blob = json.dumps([dict(h) for h in hist])
        self.assertNotIn("verysecret", blob)

    def test_jit_tenant_safety(self):
        prov = self._provider()
        pv = self.sso._provider_row(prov["id"])
        res = self.sso._sso_login(pv, {"subject": "same-subject",
                                       "email": "one@acme.test",
                                       "groups": []}, method="oidc")
        org2 = self.svc.org_create("beta")
        prov2 = self.sso.provider_create(
            org2.id, "oidc", display_name="Beta IdP", enabled=True,
            config={"issuer": "https://idp.example.com",
                    "client_id": "client-1",
                    "authorization_endpoint":
                        "https://idp.example.com/auth",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks"},
            jit=True, default_roles=("viewer",), actor="test")
        res2 = self.sso._sso_login(self.sso._provider_row(prov2["id"]),
                                   {"subject": "same-subject",
                                    "email": "one@acme.test",
                                    "groups": []}, method="oidc")
        self.assertNotEqual(res["user"].id, res2["user"].id)
        self.assertNotEqual(res["user"].org_id, res2["user"].org_id)
        linked = self.svc.db.query(
            "SELECT user_id FROM sso_identities WHERE subject='same-subject'")
        self.assertEqual(len(linked), 2)

    def test_jit_username_derived_and_deduplicated(self):
        prov = self._provider()
        pv = self.sso._provider_row(prov["id"])
        # same tenant + same email, different IdP subjects → ONE account
        # (the email is the tenant-level identity; never a duplicate)
        a = self.sso._sso_login(pv, {"subject": "s1",
                                     "email": "same@acme.test"}, method="oidc")
        b = self.sso._sso_login(pv, {"subject": "s2",
                                     "email": "same@acme.test"}, method="oidc")
        self.assertEqual(a["user"].id, b["user"].id)
        self.assertEqual(a["user"].username, b["user"].username)
        # an email that belongs to an existing tenant user LINKS to it
        linked = self.sso._sso_login(pv, {"subject": "s3",
                                          "email": "analyst@acme.test"},
                                     method="oidc")
        self.assertEqual(linked["user"].id, self.user.id)
        # same local part, different domains → distinct, uniquified usernames
        x = self.sso._sso_login(pv, {"subject": "s4",
                                     "email": "dup@acme.test"}, method="oidc")
        y = self.sso._sso_login(pv, {"subject": "s5",
                                     "email": "dup@other.test"}, method="oidc")
        self.assertEqual(x["user"].username, "dup")
        self.assertEqual(y["user"].username, "dup1")
        self.assertNotEqual(x["user"].id, y["user"].id)

    def test_group_mapping_only_existing_roles(self):
        prov = self._provider()
        pv = self.sso._provider_row(prov["id"])
        with self.assertRaises(errors.ValidationError):
            self.sso.mapping_set(self.org.id, "hackers", "superuser")
        self.sso.mapping_set(self.org.id, "security", "analyst",
                             provider_id=prov["id"])
        self.sso.mapping_set(self.org.id, "devops", "security_manager",
                             provider_id=prov["id"])
        res = self.sso._sso_login(pv, {"subject": "g1",
                                       "email": "g1@acme.test",
                                       "groups": ["security"]}, method="oidc")
        self.assertIn("analyst", self.id_svc.user_roles(res["user"].id))
        res2 = self.sso._sso_login(pv, {"subject": "g2",
                                        "email": "g2@acme.test",
                                        "groups": ["unknown"]}, method="oidc")
        roles = self.id_svc.user_roles(res2["user"].id)
        self.assertIn("viewer", roles)
        self.assertNotIn("security_manager", roles)

    def test_domain_discovery_no_existence_leak(self):
        prov = self._provider()
        self.sso.domain_add(self.org.id, prov["id"], "acme.test")
        found = self.sso.resolve_domain("someone@acme.test")
        self.assertEqual(found["provider_id"], prov["id"])
        with self.assertRaises(errors.NotFoundError):
            self.sso.resolve_domain("x@nothere.test")
        self.sso.provider_update(prov["id"], enabled=False)
        with self.assertRaises(errors.NotFoundError):
            self.sso.resolve_domain("someone@acme.test")

    def test_domain_normalization_and_uniqueness(self):
        prov = self._provider()
        self.sso.domain_add(self.org.id, prov["id"], "ACME.Test.")
        self.assertEqual(self.sso.resolve_domain("a@acme.test")["domain"],
                         "acme.test")
        # a domain claimed by ANOTHER tenant is refused with a generic
        # error (a second tenant must create its own provider to try)
        org2 = self.svc.org_create("beta")
        prov2 = self.sso.provider_create(
            org2.id, "oidc", display_name="Beta", enabled=True,
            config={"issuer": "https://idp.example.com",
                    "client_id": "client-1",
                    "authorization_endpoint":
                        "https://idp.example.com/auth",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks"},
            jit=True, actor="test")
        with self.assertRaises(errors.ValidationError):
            self.sso.domain_add(org2.id, prov2["id"], "acme.test")
        with self.assertRaises(errors.ValidationError):
            self.sso.domain_add(self.org.id, prov["id"],
                                "bad_domain!!.test")
        # removing the domain frees it for the other tenant
        self.sso.domain_remove(self.org.id, "acme.test")
        self.sso.domain_add(org2.id, prov2["id"], "acme.test")
        self.assertEqual(self.sso.resolve_domain("a@acme.test")["org_id"],
                         org2.id)

    def test_provider_delete_cleans_links(self):
        prov = self._provider()
        self.sso.domain_add(self.org.id, prov["id"], "acme.test")
        self.sso.mapping_set(self.org.id, "grp", "analyst",
                             provider_id=prov["id"])
        self.sso._sso_login(self.sso._provider_row(prov["id"]),
                            {"subject": "x1", "email": "x1@acme.test",
                             "groups": ["grp"]}, method="oidc")
        self.sso.provider_delete(prov["id"])
        self.assertEqual(len(self.sso.provider_list(self.org.id)
                             ["providers"]), 0)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM sso_identities WHERE provider_id=?",
            (prov["id"],))[0]["n"], 0)

    def test_sso_login_mfa_binding(self):
        self.mfa.policy_set(self.org.id, {"mode": "required"})
        res = self.sso._sso_login(self.sso._provider_row(
            self._provider()["id"]),
            {"subject": "m1", "email": "m1@acme.test", "groups": []},
            method="oidc")
        self.assertTrue(res["mfa_required"])
        self.assertEqual(res["session"].mfa_status, "pending")
        ctx = self.authz.context_from_secret(res["secret"])
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx, "identity.sso.create")

    def test_sso_login_rejects_inactive_user(self):
        prov = self._provider()
        res = self.sso._sso_login(self.sso._provider_row(prov["id"]),
                                  {"subject": "z1", "email": "z1@acme.test",
                                   "groups": []}, method="oidc")
        self.id_svc.user_set_status(res["user"].id, "suspended")
        with self.assertRaises(errors.AuthenticationError):
            self.sso._sso_login(self.sso._provider_row(prov["id"]),
                                {"subject": "z1", "email": "z1@acme.test",
                                 "groups": []}, method="oidc")


# ============================================================================
# SAML SSO — secure XML / signature validation
# ============================================================================
class TestSaml(IdentityTestCase):

    def _provider(self, audience="https://app.example.com",
                  issuer="https://saml-idp.example.com", **cfg):
        base = {"issuer": issuer,
                "sso_url": "https://saml-idp.example.com/sso",
                "acs_url": "https://app.example.com/saml/acs",
                "cert_pem": open(P8_CRT).read(), "audience": audience}
        base.update(cfg)
        return self.sso.provider_create(
            self.org.id, "saml", display_name="SAML IdP", enabled=True,
            config=base, jit=True, default_roles=("viewer",), actor="test")

    def test_valid_signed_assertion(self):
        prov = self._provider()
        self.sso.mapping_set(self.org.id, "security", "analyst",
                             provider_id=prov["id"])
        req = self.sso.saml_start(prov["id"])
        out = self.sso.saml_process(
            prov["id"], build_signed_response(request_id=req["request_id"]),
            request_id=req["request_id"], ip="203.0.113.7")
        self.assertEqual(out["user"].email, "sam.saml@acme.test")
        self.assertIn("analyst", self.id_svc.user_roles(out["user"].id))

    def test_replay_rejected(self):
        prov = self._provider()
        req = self.sso.saml_start(prov["id"])
        signed = build_signed_response(request_id=req["request_id"])
        self.sso.saml_process(prov["id"], signed,
                              request_id=req["request_id"])
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(prov["id"], signed,
                                  request_id=req["request_id"])

    def test_signature_tamper_detected(self):
        prov = self._provider()
        tampered = build_signed_response().replace("sam.saml@acme.test",
                                                   "evil@acme.test", 1)
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(prov["id"], tampered)
        wrong = sign_saml(saml_response(), digest_b64=_b64std(b"\x00" * 32))
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(prov["id"], wrong)

    def test_wrong_signing_key_rejected(self):
        prov = self._provider()
        tmp_key = os.path.join(tempfile.gettempdir(),
                               "p8other_%s.key" % uuid.uuid4().hex[:8])
        subprocess.run(["openssl", "genrsa", "-out", tmp_key, "2048"],
                       check=True, capture_output=True)
        try:
            with self.assertRaises(errors.ValidationError):
                self.sso.saml_process(prov["id"], sign_saml(
                    saml_response(), key=tmp_key))
        finally:
            os.unlink(tmp_key)

    def test_unsigned_rejected(self):
        prov = self._provider()
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(prov["id"], saml_response())

    def test_xxe_and_dtd_rejected(self):
        prov = self._provider()
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(
                prov["id"],
                '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                + saml_response())
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(
                prov["id"],
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "oops">]>'
                '&e;<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:'
                '2.0:protocol"/>')

    def test_audience_recipient_destination_issuer_checks(self):
        prov = self._provider(audience="https://app.example.com")
        for kw in (dict(audience="https://evil.example.com"),
                   dict(recipient="https://evil.example.com/saml/acs"),
                   dict(destination="https://evil.example.com/saml/acs"),
                   dict(issuer="https://evil-idp.example.com"),
                   dict(resp_issuer="https://evil-idp.example.com")):
            with self.assertRaises(errors.ValidationError, msg=kw):
                self.sso.saml_process(prov["id"],
                                      build_signed_response(**kw))

    def test_temporal_validity(self):
        prov = self._provider()
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(
                prov["id"], build_signed_response(
                    not_on_or_after="2020-01-01T00:00:00Z"))
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(
                prov["id"], build_signed_response(
                    not_before="2100-01-01T00:00:00Z"))

    def test_in_response_to_and_request_binding(self):
        prov = self._provider()
        req = self.sso.saml_start(prov["id"])
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(
                prov["id"], build_signed_response(request_id="_wrong"),
                request_id=req["request_id"])
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(
                prov["id"],
                build_signed_response(request_id=req["request_id"]),
                request_id="_never-issued")

    def test_multiple_assertions_rejected(self):
        prov = self._provider()
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(prov["id"],
                                  saml_response(extra_assertions=1))

    def test_nameid_validation(self):
        prov = self._provider()
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(prov["id"],
                                  build_signed_response(nameid="bad\x00name"))

    def test_oversized_and_deep_xml_rejected(self):
        prov = self._provider()
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(prov["id"],
                                  saml_response() + "x" * (600 * 1024))
        deep = ('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:'
                'protocol">' + "<a>" * 100 + "x" + "</a>" * 100 +
                "</samlp:Response>")
        with self.assertRaises(errors.ValidationError):
            self.sso.saml_process(prov["id"], deep)
# ============================================================================
# SCIM 2.0 — Users/Groups on existing identity foundation
# ============================================================================
class TestScim(IdentityTestCase):

    def _cred(self, max_role="analyst", ttl=0):
        out = self.scim.credential_create(self.org.id, "prov",
                                          max_role=max_role,
                                          ttl_seconds=ttl, actor="test")
        self.cred_secret = out["secret"]
        return out

    def _auth(self, secret=None):
        secret = secret or self.cred_secret
        return self.scim.authenticate(
            "Basic " + _b64std(("%s:%s" % (secret[:10], secret))
                               .encode("utf-8")))

    def _user_body(self, ext="emp-1", email="emp1@acme.test", **kw):
        body = {"schemas": [scim_service.SCHEMA_USER], "externalId": ext,
                "userName": ext.replace("-", ""),
                "displayName": "Emp " + ext,
                "emails": [{"value": email, "primary": True}]}
        body.update(kw)
        return body

    def test_authentication_is_tenant_scoped(self):
        cred = self._cred()
        self.assertEqual(self._auth()["org_id"], self.org.id)
        with self.assertRaises(scim_service.ScimError) as cm:
            self._auth(secret="scim_" + "x" * 40)
        self.assertEqual(cm.exception.status, 401)
        self.scim.credential_revoke(cred["id"], actor="test")
        with self.assertRaises(scim_service.ScimError) as cm:
            self._auth()
        self.assertEqual(cm.exception.status, 401)

    def test_expired_credential_rejected(self):
        self._cred(ttl=-10)
        with self.assertRaises(scim_service.ScimError) as cm:
            self._auth()
        self.assertEqual(cm.exception.status, 401)

    def test_provisioning_idempotent_by_external_id(self):
        self._cred()
        u1 = self.scim.user_create(self.org.id, self._user_body(),
                                   max_role="analyst", actor="scim")
        u2 = self.scim.user_create(self.org.id, self._user_body(),
                                   max_role="analyst", actor="scim")
        self.assertEqual(u1["id"], u2["id"])

    def test_password_attribute_rejected(self):
        self._cred()
        with self.assertRaises(scim_service.ScimError) as cm:
            self.scim.user_create(self.org.id,
                                  self._user_body(ext="emp-pw",
                                                  password="hunter2"),
                                  max_role="analyst", actor="scim")
        self.assertEqual(cm.exception.status, 400)

    def test_max_role_cap_enforced(self):
        self._cred(max_role="viewer")
        with self.assertRaises(scim_service.ScimError) as cm:
            self.scim.group_create(
                self.org.id, {"externalId": "g-adm",
                              "displayName": "Admins", "role": "admin"},
                max_role="viewer", actor="scim")
        self.assertEqual(cm.exception.status, 403)

    def test_tenant_isolation_forged_ids(self):
        self._cred()
        u = self.scim.user_create(self.org.id, self._user_body(),
                                  max_role="analyst", actor="scim")
        org2 = self.svc.org_create("beta")
        cred2 = self.scim.credential_create(org2.id, "prov2",
                                            max_role="analyst", actor="test")
        auth2 = self.scim.authenticate(
            "Basic " + _b64std(("%s:%s" % (cred2["secret"][:10],
                                           cred2["secret"]))
                               .encode("utf-8")))
        self.assertEqual(auth2["org_id"], org2.id)
        for fn, args in ((self.scim.user_get, (org2.id, u["id"])),
                         (self.scim.user_get, (org2.id, "forged-id-123")),
                         (self.scim.group_get, (org2.id, "forged-id-999"))):
            with self.assertRaises(scim_service.ScimError) as cm:
                fn(*args)
            self.assertEqual(cm.exception.status, 404)

    def test_filter_allowlist_and_bounds(self):
        self._cred()
        self.scim.user_create(self.org.id, self._user_body("emp-1",
                                                           "a@acme.test"),
                              max_role="analyst", actor="scim")
        self.scim.user_create(self.org.id, self._user_body("emp-2",
                                                           "b@acme.test"),
                              max_role="analyst", actor="scim")
        self.assertEqual(self.scim.users_list(
            self.org.id, filter='userName eq "emp1"')["totalResults"], 1)
        self.assertEqual(self.scim.users_list(
            self.org.id, filter='active eq "false"')["totalResults"], 0)
        self.assertEqual(self.scim.users_list(
            self.org.id, filter='displayName eq "Emp emp-1" '
                                'and active eq "true"')["totalResults"], 1)
        for bad in ('password eq "x"', 'userName co "a"',
                    'userName eq "a" or userName eq "b"', '"x"'):
            with self.assertRaises(scim_service.ScimError) as cm:
                self.scim.users_list(self.org.id, filter=bad)
            self.assertEqual(cm.exception.status, 400)
        with self.assertRaises(scim_service.ScimError) as cm:
            self.scim.users_list(self.org.id, filter="a" * 600)
        self.assertEqual(cm.exception.status, 400)

    def test_pagination_bounds(self):
        # a fresh tenant: exactly the 5 provisioned users exist there
        org2 = self.svc.org_create("beta")
        cred2 = self.scim.credential_create(org2.id, "prov",
                                            max_role="analyst",
                                            actor="test")
        for i in range(5):
            self.scim.user_create(org2.id,
                                  self._user_body("emp-%d" % i,
                                                  "e%d@acme.test" % i),
                                  max_role="analyst", actor="scim")
        lst = self.scim.users_list(org2.id, start_index=1, count=2)
        self.assertEqual(len(lst["Resources"]), 2)
        self.assertEqual(lst["itemsPerPage"], 2)
        self.assertEqual(lst["totalResults"], 5)
        self.assertEqual(lst["startIndex"], 1)
        self.assertTrue(cred2["secret"].startswith("scim_"))
        with self.assertRaises(scim_service.ScimError):
            self.scim.users_list(org2.id, start_index=0)

    def test_group_membership_reconciles_roles(self):
        self._cred()
        u = self.scim.user_create(self.org.id, self._user_body(),
                                  max_role="analyst", actor="scim")
        g = self.scim.group_create(self.org.id,
                                   {"externalId": "g-sec",
                                    "displayName": "Security",
                                    "role": "analyst"},
                                   max_role="analyst", actor="scim")
        self.scim.group_patch(self.org.id, g["id"],
                              {"Operations": [{"op": "add", "path": "members",
                                               "value": [{"value": u["id"]}]}]},
                              actor="scim")
        self.assertIn("analyst", self.id_svc.user_roles(u["id"]))
        self.scim.group_patch(self.org.id, g["id"],
                              {"Operations": [{"op": "remove",
                                               "path": "members",
                                               "value": [{"value": u["id"]}]}]},
                              actor="scim")
        self.assertNotIn("analyst", self.id_svc.user_roles(u["id"]))
        self.scim.group_patch(self.org.id, g["id"],
                              {"Operations": [{"op": "add", "path": "members",
                                               "value": [{"value": u["id"]}]}]},
                              actor="scim")
        self.scim.group_delete(self.org.id, g["id"], actor="scim")
        self.assertNotIn("analyst", self.id_svc.user_roles(u["id"]))

    def test_group_replace_semantics_and_version(self):
        self._cred()
        u = self.scim.user_create(self.org.id, self._user_body(),
                                  max_role="analyst", actor="scim")
        g = self.scim.group_create(self.org.id,
                                   {"externalId": "g1",
                                    "displayName": "G1",
                                    "role": "viewer"},
                                   max_role="analyst", actor="scim")
        body = {"displayName": "G1-upd", "role": "analyst",
                "meta": {"version": "99"},
                "members": [{"value": u["id"]}]}
        with self.assertRaises(scim_service.ScimError) as cm:
            self.scim.group_replace(self.org.id, g["id"], body,
                                    max_role="analyst", actor="scim")
        self.assertEqual(cm.exception.status, 409)
        version = g["meta"]["version"]
        body["meta"]["version"] = version
        out = self.scim.group_replace(self.org.id, g["id"], body,
                                      max_role="analyst", actor="scim")
        self.assertEqual(len(out["members"]), 1)
        self.assertEqual(int(out["meta"]["version"]), int(version) + 1)
        self.assertIn("analyst", self.id_svc.user_roles(u["id"]))

    def test_user_delete_deactivates_and_revokes(self):
        self._cred()
        u = self.scim.user_create(self.org.id, self._user_body(),
                                  max_role="analyst", actor="scim")
        sess = self.id_svc.session_create(u["id"], ip="203.0.113.11",
                                          actor="scim")
        self.scim.user_delete(self.org.id, u["id"], actor="scim")
        row = self.svc.db.query_one("SELECT status FROM users WHERE id=?",
                                    (u["id"],))
        self.assertEqual(row["status"], "deactivated")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(sess["secret"])
        revoked = self.svc.db.query_one(
            "SELECT revoke_reason FROM sessions WHERE id=?",
            (sess["session"].id,))
        self.assertEqual(revoked["revoke_reason"], "scim_delete")

    def test_patch_active_and_display(self):
        self._cred()
        u = self.scim.user_create(self.org.id, self._user_body(),
                                  max_role="analyst", actor="scim")
        out = self.scim.user_patch(
            self.org.id, u["id"],
            {"Operations": [{"op": "replace", "path": "active",
                             "value": False}]}, actor="scim")
        self.assertFalse(out["active"])
        out = self.scim.user_patch(
            self.org.id, u["id"],
            {"Operations": [{"op": "replace", "path": "displayName",
                             "value": "New Name"}]}, actor="scim")
        self.assertEqual(out["displayName"], "New Name")
        with self.assertRaises(scim_service.ScimError) as cm:
            self.scim.user_patch(
                self.org.id, u["id"],
                {"Operations": [{"op": "add", "path": "groups",
                                 "value": [{"value": "g1"}]}]}, actor="scim")
        self.assertEqual(cm.exception.status, 400)

    def test_concurrent_group_patch_no_double_grant(self):
        self._cred()
        u = self.scim.user_create(self.org.id, self._user_body(),
                                  max_role="analyst", actor="scim")
        g = self.scim.group_create(self.org.id,
                                   {"externalId": "gc", "displayName": "GC",
                                    "role": "analyst"},
                                   max_role="analyst", actor="scim")
        errs = []

        def worker():
            try:
                self.scim.group_patch(
                    self.org.id, g["id"],
                    {"Operations": [{"op": "add", "path": "members",
                                     "value": [{"value": u["id"]}]}]},
                    actor="scim")
            except Exception as e:      # pragma: no cover
                errs.append(e)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errs, [])
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM scim_group_members WHERE group_id=?",
            (g["id"],))[0]["n"], 1)
        self.assertEqual(self.id_svc.user_roles(u["id"]).count("analyst"), 1)

    def test_malformed_json_and_capabilities(self):
        self._cred()
        with self.assertRaises(scim_service.ScimError) as cm:
            self.scim.user_create(self.org.id, "not-an-object",
                                  max_role="analyst", actor="scim")
        self.assertEqual(cm.exception.status, 400)
        self.assertTrue(self.scim.service_provider_config()["schemas"])
        self.assertEqual(len(self.scim.resource_types()["Resources"]), 2)


# ============================================================================
# Lifecycle + failure injection
# ============================================================================
class TestLifecycleAndFailureInjection(IdentityTestCase):

    def test_suspended_user_cannot_authenticate(self):
        out = self.login("analyst@acme.test")
        self.id_svc.user_set_status(self.user.id, "suspended")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("analyst@acme.test", PASSWD)
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.session_authenticate(out["secret"])

    def test_deactivated_user_and_api_key_owner(self):
        cred = self.id_svc.credential_create(
            self.org.id, "legacy", ("asset.read",),
            created_by=self.user.id,
            as_permissions=rbac_full(self.id_svc, self.user.id),
            actor="test")
        self.id_svc.user_set_status(self.user.id, "deactivated")
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.credential_authenticate(cred["secret"])
        with self.assertRaises(errors.AuthenticationError):
            self.id_svc.login("analyst@acme.test", PASSWD)

    def test_corrupt_policy_never_disables_mfa(self):
        self.mfa.policy_set(self.org.id, {"mode": "optional"})
        self.svc.db.execute(
            "UPDATE mfa_policy SET mode='total-garbage' WHERE org_id=?",
            (self.org.id,))
        out = self.id_svc.login(
            "owner@acme.test", PASSWD,
            mfa_required=lambda u, roles:
                self.mfa.policy_requires(self.org.id, roles))
        self.assertTrue(out["mfa_required"])

    def test_corrupt_seed_fails_closed(self):
        self.enroll_and_activate(self.user.id)
        self.svc.db.execute(
            "UPDATE mfa_secrets SET seed_enc='not-a-valid-blob' "
            "WHERE user_id=?", (self.user.id,))
        with self.assertRaises(errors.AuthenticationError):
            self.mfa.challenge(self.user.id, "123456")

    def test_garbage_jwks_rejected(self):
        prov_id = self.sso.provider_create(
            self.org.id, "oidc", display_name="X", enabled=True,
            config={"issuer": "https://idp.example.com",
                    "client_id": "c1",
                    "authorization_endpoint":
                        "https://idp.example.com/auth",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks"},
            jit=True, actor="test")["id"]
        self.sso._jwks_cache[prov_id] = (time.time() + 600, {})
        pv = self.sso._provider_row(prov_id)
        now = int(time.time())
        claims = {"iss": "https://idp.example.com", "sub": "s1", "aud": "c1",
                  "exp": now + 600, "iat": now, "nonce": "n"}
        with self.assertRaises(errors.ValidationError):
            self.sso.oidc_validate_id_token(pv, make_jwt(claims), nonce="n")

    def test_identity_events_never_contain_secrets(self):
        enr = self.mfa.enroll_start(self.user.id)
        for r in self.svc.db.query("SELECT detail FROM identity_events "
                                   "LIMIT 20"):
            self.assertNotIn(enr["seed"], r["detail"])

    def test_secrets_absent_from_all_views(self):
        prov = self.sso.provider_create(
            self.org.id, "oidc", display_name="S", enabled=False,
            config={"issuer": "https://idp.example.com",
                    "client_id": "c1",
                    "client_secret": "very-secret-xyz",
                    "authorization_endpoint":
                        "https://idp.example.com/auth"},
            jit=False, actor="test")
        self.assertNotIn("very-secret-xyz",
                         json.dumps(self.sso.provider_get(prov["id"])))
        cred = self.scim.credential_create(self.org.id, "p",
                                           max_role="analyst",
                                           actor="test")
        audit = json.dumps([dict(r) for r in
                            self.svc.db.query("SELECT * FROM audit_events "
                                              "LIMIT 200")])
        self.assertNotIn(cred["secret"], audit)
        self.assertNotIn("very-secret-xyz", audit)


# ============================================================================
# Break-glass emergency administrative access (§15)
# ============================================================================
class TestBreakGlass(IdentityTestCase):

    def _bg(self):
        import breakglass_service as _bg
        return _bg.BreakGlassService(self.svc, self.id_svc)

    def test_start_requires_reason_ttl_and_verified(self):
        bg = self._bg()
        # distinct actors keep the per-actor+org throttle (5/300) from
        # masking the validation assertions below
        def fresh_user(tag):
            return self.id_svc.user_create(
                self.org.id, "bgv%s" % tag, "bgv%s@acme.test" % tag, PASSWD,
                roles=("viewer",), allow_any_role=True, actor="test")
        u1, u2, u3 = fresh_user("1"), fresh_user("2"), fresh_user("3")
        for bad in ("", "short", "x" * 201):
            with self.assertRaises(errors.ValidationError):
                bg.start(u1.id, self.org.id, reason=bad, verified=True)
        for ttl in (10, 99999):
            with self.assertRaises(errors.ValidationError):
                bg.start(u2.id, self.org.id, reason="valid reason here",
                         verified=True, ttl_seconds=ttl)
        with self.assertRaises(errors.AuthorizationError):
            bg.start(u3.id, self.org.id, reason="valid reason here",
                     verified=False)

    def test_start_binds_tenant(self):
        org2 = self.svc.org_create("beta")
        bg = self._bg()
        # owner belongs to org1 only: minting for org2 must fail closed
        for target in (org2.id, ""):
            with self.assertRaises((errors.AuthorizationError,
                                    errors.ValidationError)):
                bg.start(self.owner.id, target,
                         reason="valid reason here", verified=True)

    def test_grant_authenticates_then_expires(self):
        bg = self._bg()
        g = bg.start(self.owner.id, self.org.id,
                     reason="valid reason here", verified=True,
                     ttl_seconds=60)
        grant = bg.authenticate(g["secret"])
        self.assertEqual(grant.user_id, self.owner.id)
        self.assertTrue(grant.active())
        # unknown / malformed secrets: identical generic failure
        for bad in ("", "bg_" + "x" * 40, "ses_" + "x" * 40):
            with self.assertRaises(errors.AuthenticationError):
                bg.authenticate(bad)
        # expiry is enforced at use time (fail closed)
        self.svc.db.execute(
            "UPDATE break_glass_grants SET expires_at="
            "'1970-01-01T00:00:00Z' WHERE id=?", (g["grant_id"],))
        with self.assertRaises(errors.AuthenticationError):
            bg.authenticate(g["secret"])

    def test_one_active_grant_per_actor_supersedes(self):
        bg = self._bg()
        g1 = bg.start(self.owner.id, self.org.id,
                      reason="first window", verified=True)
        g2 = bg.start(self.owner.id, self.org.id,
                      reason="second window", verified=True)
        with self.assertRaises(errors.AuthenticationError):
            bg.authenticate(g1["secret"])      # superseded
        self.assertEqual(bg.authenticate(g2["secret"]).user_id,
                         self.owner.id)
        # ending an already-ended grant is safe and reports ended=False
        out = bg.end(g1["grant_id"], reason="ended manually")
        self.assertFalse(out["ended"])
        out = bg.end(g2["grant_id"])
        self.assertTrue(out["ended"])
        with self.assertRaises(errors.AuthenticationError):
            bg.authenticate(g2["secret"])
        with self.assertRaises(errors.NotFoundError):
            bg.end("no-such-grant")

    def test_views_and_logs_never_contain_secrets(self):
        bg = self._bg()
        g = bg.start(self.owner.id, self.org.id,
                     reason="very important reason", verified=True)
        for v in bg.list_org(self.org.id):
            self.assertNotIn(g["secret"], json.dumps(v))
            self.assertNotIn("token_hash", v)
        # audit + identity events keep the immutable trail secret-free
        for r in self.svc.db.query("SELECT action, metadata FROM audit_events"):
            blob = str(r["action"]) + str(r["metadata"] or "")
            self.assertNotIn(g["secret"], blob)
        for r in self.svc.db.query("SELECT detail FROM identity_events"):
            self.assertNotIn(g["secret"], str(r["detail"] or ""))
        st = bg.org_status(self.org.id)
        self.assertEqual(st["active"], 1)
        us = bg.user_grant_status(self.owner.id, self.org.id)
        self.assertTrue(us["active"])
        self.assertEqual(us["reason"], "very important reason")

    def test_inactive_actor_cannot_use_grant(self):
        bg = self._bg()
        g = bg.start(self.user.id, self.org.id,
                     reason="drill window", verified=True)
        self.id_svc.user_set_status(self.user.id, "disabled", actor="test")
        with self.assertRaises(errors.AuthenticationError):
            bg.authenticate(g["secret"])
        with self.assertRaises(errors.AuthenticationError):
            bg.start(self.user.id, self.org.id,
                     reason="drill window two", verified=True)

    def test_grant_context_is_verified_step_up_with_no_extra_perms(self):
        bg = self._bg()
        ga = bg.start(self.user.id, self.org.id,
                      reason="analyst drill", verified=True)
        ctx = self.authz.context_from_secret(ga["secret"])
        self.assertEqual(ctx.mfa_status, "verified")
        self.assertEqual(ctx.actor, "break_glass")
        self.assertTrue(ctx.step_up_until)
        # the grant adds NOTHING: exactly the analyst role permissions
        self.assertEqual(ctx.permissions,
                         rbac_mod.permissions_for(("analyst",)))
        self.assertNotIn("identity.break_glass", ctx.permissions)

    def test_rbac_permission_gate(self):
        bg = self._bg()
        ga = bg.start(self.user.id, self.org.id,
                      reason="analyst drill", verified=True)
        go = bg.start(self.owner.id, self.org.id,
                      reason="owner drill", verified=True)
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(self.authz.context_from_secret(ga["secret"]),
                               "identity.break_glass")
        # owner inherits identity.break_glass through the hierarchy
        self.authz.require(self.authz.context_from_secret(go["secret"]),
                           "identity.break_glass")

    def test_break_glass_is_throttled(self):
        bg = self._bg()
        for _ in range(5):
            bg.start(self.user.id, self.org.id,
                     reason="throttle drill", verified=True)
        with self.assertRaises(errors.RateLimitedError):
            bg.start(self.user.id, self.org.id,
                     reason="throttle drill", verified=True)


# ============================================================================
# SCIM 2.0 HTTP surface (§36) — routing, auth, tenant isolation
# ============================================================================
class TestScimHttp(IdentityTestCase):

    def setUp(self):
        super().setUp()
        import scim_server as _srv
        self.http = _srv.ScimServer(self.scim, quiet=True)

    def _call(self, method, path, body=None, auth="", raw=None):
        """Direct routing call; SCIM errors are returned as (status, dict)
        exactly like the HTTP layer would serialize them."""
        data = raw
        if data is None:
            data = json.dumps(body).encode() if body is not None else None
        try:
            return self.http._handle(method, path, auth, data,
                                     "203.0.113.5")
        except Exception as e:
            scim_type = getattr(e, "scim_type", "")
            if scim_type:
                return (getattr(e, "status", 500) or 500,
                        {"scimType": scim_type, "detail": str(e)})
            raise

    def _cred(self, name="h1", max_role="analyst"):
        c = self.scim.credential_create(self.org.id, name,
                                        max_role=max_role, actor="test")
        secret = c["secret"]
        basic = "Basic " + base64.b64encode(
            f"{secret[:10]}:{secret}".encode()).decode()
        return secret, basic

    def _user_body(self, ext="emp-1", name="scimuser"):
        return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "externalId": ext, "userName": name,
                "emails": [{"value": f"{name}@acme.test", "primary": True}],
                "active": True}

    def test_discovery_is_public(self):
        st, body = self._call("GET", "/scim/v2/ServiceProviderConfig",
                              auth="")
        self.assertEqual(st, 200)
        self.assertIn("ServiceProviderConfig", body["schemas"][0])
        for p in ("/scim/v2/ResourceTypes", "/scim/v2/Schemas"):
            st, _ = self._call("GET", p, auth="")
            self.assertEqual(st, 200)

    def test_auth_is_required_for_resources(self):
        for auth in ("", "Basic " + base64.b64encode(b"nope:wrong").decode()):
            st, body = self._call("GET", "/scim/v2/Users", auth=auth)
            self.assertEqual(st, 401)
            self.assertEqual(body["scimType"], "invalidCredentials")

    def test_unknown_path_and_method_return_scim_errors(self):
        _, auth = self._cred()
        st, body = self._call("GET", "/scim/v2/Nope", auth=auth)
        self.assertEqual(st, 404)
        self.assertEqual(body["scimType"], "noTarget")
        st, body = self._call("PUT", "/scim/v2/Users", body={}, auth=auth)
        self.assertEqual(st, 405)
        self.assertEqual(body["scimType"], "methodNotAllowed")
        st, body = self._call("POST", "/scim/v2/Users",
                              body={"externalId": "x"}, auth=auth)
        self.assertEqual(st, 400)
        self.assertEqual(body["scimType"], "invalidValue")

    def test_user_crud_roundtrip_over_http(self):
        _, auth = self._cred("crud")
        st, body = self._call("POST", "/scim/v2/Users",
                              body=self._user_body(), auth=auth)
        self.assertEqual(st, 201)
        uid = body["id"]
        self.assertEqual(body["externalId"], "emp-1")
        # GET by platform id AND by externalId
        st, body = self._call("GET", f"/scim/v2/Users/{uid}", auth=auth)
        self.assertEqual(st, 200)
        self.assertEqual(body["userName"], "scimuser")
        st, body = self._call("GET", "/scim/v2/Users/emp-1", auth=auth)
        self.assertEqual(st, 200)
        # list + filter
        st, body = self._call(
            "GET", "/scim/v2/Users?filter=userName%20eq%20%22scimuser%22",
            auth=auth)
        self.assertEqual(st, 200)
        self.assertEqual(body["totalResults"], 1)
        # deactivate via PATCH, reactivate via PUT
        st, body = self._call("PATCH", f"/scim/v2/Users/{uid}",
                              body={"schemas": [
                                  "urn:ietf:params:scim:api:messages:2.0:"
                                  "PatchOp"],
                              "Operations": [{"op": "replace",
                                              "path": "active",
                                              "value": False}]},
                              auth=auth)
        self.assertEqual(st, 200)
        self.assertFalse(body["active"])
        self.assertEqual(self.id_svc.user_get(uid).status, "suspended")
        st, body = self._call("PUT", f"/scim/v2/Users/{uid}",
                              body=self._user_body(), auth=auth)
        self.assertEqual(st, 200)
        self.assertTrue(body["active"])

    def test_tenant_isolation(self):
        org2 = self.svc.org_create("beta")
        bob = self.id_svc.user_create(
            org2.id, "bob2", "bob2@beta.test", PASSWD,
            roles=("viewer",), allow_any_role=True, actor="test")
        _, auth = self._cred("iso")
        # a tenant-1 credential can NEVER see tenant-2 objects
        st, body = self._call("GET", f"/scim/v2/Users/{bob.id}", auth=auth)
        self.assertEqual(st, 404)
        self.assertEqual(body["scimType"], "notFound")
        st, body = self._call("GET", "/scim/v2/Users", auth=auth)
        self.assertEqual(st, 200)
        for r in body["Resources"]:
            self.assertNotEqual(r["id"], bob.id)

    def test_group_flow_and_role_cap(self):
        _, auth = self._cred("grp", max_role="security_manager")
        st, u = self._call("POST", "/scim/v2/Users",
                           body=self._user_body(), auth=auth)
        uid = u["id"]
        # owners/managers cannot be granted beyond the credential cap
        st, body = self._call(
            "POST", "/scim/v2/Groups",
            body={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                  "externalId": "eng", "displayName": "Engineering",
                  "role": "owner"}, auth=auth)
        # role beyond the credential cap is refused (SCIM 403 semantics)
        self.assertEqual(st, 403)
        st, body = self._call(
            "POST", "/scim/v2/Groups",
            body={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                  "externalId": "eng", "displayName": "Engineering",
                  "role": "security_manager"}, auth=auth)
        self.assertEqual(st, 201)
        gid = body["id"]
        st, body = self._call("PATCH", f"/scim/v2/Groups/{gid}",
                              body={"schemas": [
                                  "urn:ietf:params:scim:api:messages:2.0:"
                                  "PatchOp"],
                              "Operations": [{"op": "add", "path": "members",
                                              "value": [{"type": "User",
                                                         "value": uid}]}]},
                              auth=auth)
        self.assertEqual(st, 200)
        self.assertEqual(len(body["members"]), 1)
        self.assertIn("security_manager",
                      self.id_svc.user_roles(uid))
        st, body = self._call("GET",
                              "/scim/v2/Groups?filter=displayName%20eq%20"
                              "%22Engineering%22", auth=auth)
        self.assertEqual(st, 200)
        self.assertEqual(body["totalResults"], 1)

    def test_bad_json(self):
        _, auth = self._cred("json")
        with self.assertRaises(errors.ValidationError):
            self._call("POST", "/scim/v2/Users", raw=b"{not json",
                       auth=auth)


# ============================================================================
# Scale (bounded; hangs/explosions fail loudly)
# ============================================================================
class TestScale(IdentityTestCase):

    def test_bulk_jit_provisioning_150(self):
        n, e = pki.load_rsa_public_key(open(P8_PUB).read())
        prov = self.sso.provider_create(
            self.org.id, "oidc", display_name="Bulk", enabled=True,
            config={"issuer": "https://idp.example.com",
                    "client_id": "c1",
                    "authorization_endpoint":
                        "https://idp.example.com/auth",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks"},
            jit=True, default_roles=("viewer",), actor="test")
        self.sso._jwks_cache[prov["id"]] = (time.time() + 600,
                                            {"k": {"n": n, "e": e}})
        pv = self.sso._provider_row(prov["id"])
        started = time.time()
        last = None
        for i in range(150):
            last = self.sso._sso_login(
                pv, {"subject": "bulk-%d" % i,
                     "email": "bulk%d@acme.test" % i, "groups": []},
                ip="203.0.113.10", method="oidc")
        self.assertEqual(last["user"].org_id, self.org.id)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM users WHERE org_id=?",
            (self.org.id,))[0]["n"], 152)          # + owner + analyst
        self.assertLess(time.time() - started, 30,
                        "bulk JIT must stay bounded")

    def test_recovery_code_churn(self):
        self.enroll_and_activate(self.user.id)
        for _ in range(5):
            self.assertEqual(len(self.mfa.recovery_codes_generate(
                self.user.id, count=20)["codes"]), 20)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM mfa_recovery_codes WHERE user_id=?",
            (self.user.id,))[0]["n"], 20)          # only latest batch kept
        self.assertEqual(self.mfa.recovery_codes_list(self.user.id)["unused"],
                         20)

    def test_session_list_scale(self):
        # session_create is rate-limited per user (12/5min); spread 40
        # sessions across 4 users to exercise the listing at scale
        extra = []
        for i in range(3):
            extra.append(self.id_svc.user_create(
                self.org.id, "scale%d" % i, "scale%d@acme.test" % i,
                PASSWD, roles=("analyst",), allow_any_role=True,
                actor="test"))
        for uid in [self.user.id, self.owner.id] + [u.id for u in extra]:
            for _ in range(10):
                self.id_svc.session_create(uid, ip="203.0.113.20",
                                           actor="scale")
        rows = self.id_svc.sessions_list_org(self.org.id)
        self.assertGreaterEqual(rows["total"], 40)

    def test_scim_http_bulk_provision_250(self):
        import scim_server as _srv
        http = _srv.ScimServer(self.scim, quiet=True)
        cred = self.scim.credential_create(self.org.id, "bulk",
                                           max_role="analyst", actor="test")
        secret = cred["secret"]
        auth = "Basic " + base64.b64encode(
            f"{secret[:10]}:{secret}".encode()).decode()
        started = time.time()
        for i in range(250):
            st, _ = http._handle(
                "POST", "/scim/v2/Users", auth,
                json.dumps({"schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User"],
                    "externalId": "emp-%d" % i,
                    "userName": "emp%d" % i,
                    "emails": [{"value": "emp%d@acme.test" % i,
                                "primary": True}],
                    "active": True}).encode(), "203.0.113.6")
            self.assertEqual(st, 201)
        st, body = http._handle(
            "GET", "/scim/v2/Users?startIndex=1&count=100", auth, None,
            "203.0.113.6")
        self.assertEqual(st, 200)
        self.assertEqual(body["totalResults"], 252)  # 250 + owner + analyst
        self.assertEqual(len(body["Resources"]), 100)
        st, body = http._handle(
            "GET", "/scim/v2/Users?startIndex=201&count=100", auth, None,
            "203.0.113.6")
        self.assertEqual(len(body["Resources"]), 52)  # 50 bulk + 2 fixtures
        n = self.svc.db.query(
            "SELECT COUNT(DISTINCT email) n FROM users WHERE org_id=?",
            (self.org.id,))[0]["n"]
        self.assertEqual(n, 252)          # + owner + analyst
        self.assertLess(time.time() - started, 60,
                        "bulk SCIM over HTTP must stay bounded")

    def test_break_glass_batch_100(self):
        import breakglass_service as _bg
        bg = _bg.BreakGlassService(self.svc, self.id_svc)
        users = []
        for i in range(100):
            users.append(self.id_svc.user_create(
                self.org.id, "bg%d" % i, "bg%d@acme.test" % i, PASSWD,
                roles=("viewer",), allow_any_role=True, actor="test"))
        started = time.time()
        for u in users:
            g = bg.start(u.id, self.org.id, reason="batch drill",
                         verified=True)
            self.assertTrue(g["secret"].startswith("bg_"))
        self.assertEqual(bg.org_status(self.org.id)["active"], 100)
        self.assertEqual(len(bg.list_org(self.org.id, limit=100)), 100)
        self.assertLess(time.time() - started, 60,
                        "bulk break-glass minting must stay bounded")

    def test_saml_attribute_scale(self):
        prov = self.sso.provider_create(
            self.org.id, "saml", display_name="BigSAML", enabled=True,
            config={"issuer": "https://saml-idp.example.com",
                    "sso_url": "https://saml-idp.example.com/sso",
                    "acs_url": "https://app.example.com/saml/acs",
                    "cert_pem": open(P8_CRT).read(),
                    "audience": "https://app.example.com"},
            jit=True, actor="test")
        out = self.sso.saml_process(
            prov["id"],
            sign_saml(saml_response(groups=["g%d" % i for i in range(40)])),
            ip="203.0.113.8")
        self.assertEqual(out["user"].email, "sam.saml@acme.test")


# ============================================================================
# Dashboard / API read-only identity panel
# ============================================================================
class TestDashboardIdentity(IdentityTestCase):

    def test_snapshot_redacted_and_counts(self):
        import dashboard as _db
        enr = self.mfa.enroll_start(self.user.id)
        self.mfa.enroll_verify(self.user.id, totp.code_for(enr["seed"]))
        self.mfa.recovery_codes_generate(self.user.id, count=6)
        self.mfa.policy_set(self.org.id, {"mode": "required"})
        cred = self.scim.credential_create(self.org.id, "prov1",
                                           max_role="analyst",
                                           actor="test")
        snap = _db.load_identity_snapshot(self.svc.db_path, self.org.id)
        self.assertTrue(snap["configured"])
        self.assertFalse(snap["empty"])
        self.assertEqual(snap["orgs"][0]["id"], self.org.id)
        self.assertEqual(snap["policy"][self.org.id]["mode"], "required")
        self.assertEqual(int(snap["mfa_enrolled"][self.org.id]), 1)
        self.assertEqual(snap["recovery"][self.org.id]["unused"], 6)
        self.assertEqual(snap["scim"][0]["name"], "prov1")
        self.assertTrue(any(e["event_type"] for e in snap["events"]))
        blob = json.dumps(snap, default=str)
        for secret in (enr["seed"], cred["secret"], cred["basic"]):
            self.assertNotIn(secret, blob)
        self.assertNotIn("verifier", blob)
        # org isolation: another tenant sees a different snapshot
        org2 = self.svc.org_create("beta")
        snap2 = _db.load_identity_snapshot(self.svc.db_path, org2.id)
        self.assertNotEqual(snap2["orgs"][0]["id"], self.org.id)
        self.assertEqual(len(snap2["users"]), 0)

    def test_snapshot_empty_and_unconfigured(self):
        import dashboard as _db
        self.assertIsNone(_db.load_identity_snapshot("", self.org.id))
        # a filter that matches NO org → empty snapshot; a fresh org →
        # configured with zero identity rows (never cross-tenant data)
        snap = _db.load_identity_snapshot(self.svc.db_path,
                                          "no-such-org-id")
        self.assertTrue(snap["empty"])
        org2 = self.svc.org_create("beta")
        snap2 = _db.load_identity_snapshot(self.svc.db_path, org2.id)
        self.assertFalse(snap2["empty"])
        self.assertEqual(len(snap2["users"]), 0)

    def test_page_renders_without_secrets(self):
        import dashboard as _db
        enr = self.mfa.enroll_start(self.user.id)
        snap = _db.load_identity_snapshot(self.svc.db_path, self.org.id)
        html = _db.identity_page(snap)
        self.assertIn("Identity", html)
        self.assertIn("MFA policy", html)
        self.assertNotIn(enr["seed"], html)
        self.assertNotIn("client_secret", html.lower())
        self.assertIn("Identity panel not configured",
                      _db.identity_page(None))
        empty = _db.identity_page({"configured": True, "empty": True,
                                   "orgs": []})
        self.assertIn("No organizations", empty)


class TestIdentityCli(unittest.TestCase):
    """CLI regression for the Phase-8 auth surface: bootstrap-owner, then a
    full user lifecycle driven by username/email (not only the platform user
    ID), using a verified-step-up-free session under the default (optional)
    policy on a throwaway database."""

    def test_cli_bootstrap_and_lifecycle_by_username(self):
        import re as _re
        import shutil
        import subprocess
        import tempfile

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        tmp = tempfile.mkdtemp(prefix="sectk8cli_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        db = os.path.join(tmp, "cli.db")
        env = dict(os.environ, SECTOOLKIT_DB=db,
                   SECTOOLKIT_PLATFORM_DB=db,
                   SECTOOLKIT_PASSWORD="Str0ng!CliPass-77",
                   SECTOOLKIT_DATA_DIR=tmp)
        base = [sys.executable, os.path.join(root, "main.py")]

        def run(*args):
            r = subprocess.run(base + list(args), capture_output=True,
                               text=True, timeout=120, env=env, cwd=root)
            return r.returncode, (r.stdout or "") + (r.stderr or "")

        code, out = run("platform", "init")
        self.assertEqual(code, 0, out)
        code, out = run("platform", "org-create", "cli-org-1")
        self.assertEqual(code, 0, out)
        om = _re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12})", out)
        self.assertTrue(om, out)
        org_id = om.group(1)

        code, out = run("auth", "bootstrap-owner", "--org", org_id,
                        "--username", "root", "--email", "root@cli.test")
        self.assertEqual(code, 0, out)
        self.assertIn("owner", out.lower())

        code, out = run("auth", "login", "root@cli.test")
        self.assertEqual(code, 0, out)
        m = _re.search(r"session: (\S+)", out)
        self.assertTrue(m, out)
        token = m.group(1)

        code, out = run("auth", "user-create", "--org", org_id,
                        "--username", "alice", "--email", "alice@cli.test",
                        "--roles", "analyst", "--as", token)
        self.assertEqual(code, 0, out)
        self.assertIn("User created", out)

        # Lifecycle commands accept the username (regression: these used to
        # require the platform user ID).
        code, out = run("auth", "role-set", "alice", "--roles", "viewer",
                        "--as", token)
        self.assertEqual(code, 0, out)
        self.assertIn("Roles for alice", out)
        code, out = run("auth", "set-password", "alice",
                        "--password", "Temp!CliPass-88", "--as", token)
        self.assertEqual(code, 0, out)

        code, out = run("auth", "user-disable", "alice", "--as", token)
        self.assertEqual(code, 0, out)
        self.assertIn("User disabled: alice", out)
        code, out = run("auth", "login", "alice@cli.test",
                        "--password", "Temp!CliPass-88")
        self.assertNotEqual(code, 0, out)
        self.assertIn("Invalid credentials", out)

        code, out = run("auth", "user-enable", "alice", "--as", token)
        self.assertEqual(code, 0, out)
        self.assertIn("User enabled: alice", out)
        code, out = run("auth", "login", "alice@cli.test",
                        "--password", "Temp!CliPass-88")
        self.assertEqual(code, 0, out)
        self.assertIn("Logged in as alice", out)

        # Secrets never appear in any listing surface.
        code, out = run("auth", "user-list", "--org", org_id,
                        "--as", token)
        self.assertEqual(code, 0, out)
        self.assertNotIn("Temp!CliPass-88", out)
        self.assertNotIn("Str0ng!CliPass-77", out)

    def test_cli_password_prompt_crash_regression(self):
        """Regression: _read_secret used os.stdin (AttributeError). With no
        --password and no SECTOOLKIT_PASSWORD, a non-tty CLI must fail
        cleanly (message + exit 2), never a traceback."""
        import re as _re
        import shutil
        import subprocess
        import tempfile
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        tmp = tempfile.mkdtemp(prefix="sectk8pw_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        db = os.path.join(tmp, "pw.db")
        env = dict(os.environ, SECTOOLKIT_DB=db,
                   SECTOOLKIT_PLATFORM_DB=db, SECTOOLKIT_DATA_DIR=tmp)
        env.pop("SECTOOLKIT_PASSWORD", None)
        base = [sys.executable, os.path.join(root, "main.py")]

        def run(*args):
            r = subprocess.run(base + list(args), capture_output=True,
                               text=True, timeout=120, env=env, cwd=root)
            return r.returncode, (r.stdout or "") + (r.stderr or "")

        code, out = run("platform", "init")
        self.assertEqual(code, 0, out)
        code, out = run("platform", "org-create", "pw-org")
        self.assertEqual(code, 0, out)
        om = _re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12})", out)
        self.assertTrue(om, out)
        code, out = run("auth", "user-create", "--org", om.group(1),
                        "--username", "nopass", "--email", "nopass@pw.test")
        self.assertNotEqual(code, 0, out)
        self.assertIn("No password supplied", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("has no attribute", out)

    def test_cli_break_glass_gates(self):
        """Break-glass CLI: without a verified step-up context the mint MUST
        be refused; status listing works for an identity.break_glass holder."""
        import re as _re
        import shutil
        import subprocess
        import tempfile
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        tmp = tempfile.mkdtemp(prefix="sectk8bg_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        db = os.path.join(tmp, "bg.db")
        env = dict(os.environ, SECTOOLKIT_DB=db,
                   SECTOOLKIT_PLATFORM_DB=db,
                   SECTOOLKIT_PASSWORD="Str0ng!CliPass-77",
                   SECTOOLKIT_DATA_DIR=tmp)
        base = [sys.executable, os.path.join(root, "main.py")]

        def run(*args):
            r = subprocess.run(base + list(args), capture_output=True,
                               text=True, timeout=120, env=env, cwd=root)
            return r.returncode, (r.stdout or "") + (r.stderr or "")

        code, out = run("platform", "init")
        self.assertEqual(code, 0, out)
        code, out = run("platform", "org-create", "bg-org")
        om = _re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12})", out)
        self.assertTrue(om, out)
        org_id = om.group(1)
        code, out = run("auth", "bootstrap-owner", "--org", org_id,
                        "--username", "root", "--email", "root@bg.test")
        self.assertEqual(code, 0, out)
        code, out = run("auth", "login", "root@bg.test")
        self.assertEqual(code, 0, out)
        token = _re.search(r"session: (\S+)", out).group(1)
        # no context at all -> refused
        code, out = run("auth", "break-glass-start", "root", "--org",
                        org_id, "--reason", "cli gate drill")
        self.assertNotEqual(code, 0, out)
        self.assertIn("MFA step-up required", out)
        # enforce the step-up policy, then an UNVERIFIED session MUST be
        # refused (only a verified MFA/credential context may mint a grant)
        code, out = run("auth", "policy-set", "--org", org_id,
                        "--mode", "required", "--as", token)
        self.assertEqual(code, 0, out)
        code, out = run("auth", "break-glass-start", "root", "--org",
                        org_id, "--reason", "cli gate drill", "--as", token)
        self.assertNotEqual(code, 0, out)
        self.assertIn("MFA step-up required", out)
        # the whole break-glass surface is step-up-gated (fail closed):
        # even status listing is refused to an unverified session
        code, out = run("auth", "break-glass-status", "--org", org_id,
                        "--as", token)
        self.assertNotEqual(code, 0, out)
        self.assertIn("MFA step-up required", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
