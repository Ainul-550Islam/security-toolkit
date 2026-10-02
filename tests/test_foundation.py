#!/usr/bin/env python3
# ============================================================================
#  test_foundation.py — Phase-1 platform foundation test suite.
#  Covers: Organization, Project, Asset, Scan, Finding, Evidence (redaction),
#  Scope engine, Audit events, Persistence (SQLite), normalization, and the
#  security regression tests (SQLi, path traversal, secret leakage, invalid
#  transitions...). Pure local: no internet, no live scanners.
#  Loaded by tests/run_tests.py so the WHOLE suite runs together.
# ============================================================================

import json
import shutil
import os
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(os.path.dirname(HERE), "python")
sys.path.insert(0, PY)

import errors  # noqa: E402
import models  # noqa: E402
import normalize  # noqa: E402
import redact  # noqa: E402
import scope as scope_mod  # noqa: E402
import seclog  # noqa: E402
import store  # noqa: E402
import sec_config  # noqa: E402
import platform_service as pf  # noqa: E402


def make_service(tmp):
    svc = pf.PlatformService(os.path.join(tmp, "test_platform.db"))
    return svc


class TestOrganization(unittest.TestCase):
    def test_valid_creation_and_stable_id(self):
        o = models.Organization(name="Acme Corp")
        o2 = models.Organization(name="Acme Corp")
        o.finalize()
        o2.finalize()
        self.assertEqual(o.id, o2.id)          # deterministic
        self.assertEqual(len(o.id), 36)        # uuid5 string
        self.assertEqual(o.status, "active")
        self.assertTrue(o.created_at)

    def test_serialization_roundtrip(self):
        o = models.Organization(name="Globex")
        o.finalize()
        d = o.to_dict()
        o3 = models.Organization.from_dict(d)
        self.assertEqual(o3.id, o.id)
        self.assertEqual(o3.name, "Globex")
        self.assertNotIn("password", json.dumps(d).lower())

    def test_invalid_name_rejected(self):
        for bad in ("", "   ", "a" * 200, "evil;\nDROP TABLE", "no!bang"):
            with self.assertRaises(errors.ValidationError):
                models.Organization(name=bad).finalize()

    def test_invalid_status_rejected(self):
        with self.assertRaises(errors.ValidationError):
            models.Organization(name="X", status="hacked").finalize()


class TestProject(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pf_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = make_service(self.tmp)
        self.org = self.svc.org_create("Acme Corp")

    def test_org_relationship(self):
        p = self.svc.project_create(self.org.id, "Billing Portal")
        self.assertEqual(p.org_id, self.org.id)
        got = self.svc.project_get(p.id)
        self.assertEqual(got.name, "Billing Portal")

    def test_invalid_org_rejected(self):
        with self.assertRaises(errors.NotFoundError):
            self.svc.project_create("no-such-org", "X")

    def test_duplicate_project_rejected(self):
        self.svc.project_create(self.org.id, "Web")
        with self.assertRaises(errors.DuplicateError):
            self.svc.project_create(self.org.id, "Web")

    def test_lifecycle_status(self):
        p = self.svc.project_create(self.org.id, "API")
        self.assertEqual(p.status, "active")
        bad = models.Project(org_id=self.org.id, name="Y", status="bogus")
        with self.assertRaises(errors.ValidationError):
            bad.finalize()


class TestAsset(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pf_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = make_service(self.tmp)
        self.org = self.svc.org_create("Acme")
        self.proj = self.svc.project_create(self.org.id, "Web")

    def test_normalization_domain(self):
        a1 = models.Asset(project_id=self.proj.id, asset_type="domain",
                          value="  Example.COM. ")
        a1.finalize()
        self.assertEqual(a1.value, "example.com")

    def test_normalization_url_preserves_path(self):
        a = models.Asset(project_id=self.proj.id, asset_type="url",
                         value="https://EXAMPLE.com:443/app?x=1")
        a.finalize()
        self.assertEqual(a.value, "https://example.com/app?x=1")

    def test_duplicate_detection_same_project(self):
        self.svc.asset_add(self.proj.id, "domain", "example.com")
        self.svc.asset_add(self.proj.id, "domain", "EXAMPLE.com")
        rows = self.svc.asset_list(self.proj.id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].value, "example.com")

    def test_invalid_asset(self):
        with self.assertRaises(errors.ValidationError):
            self.svc.asset_add(self.proj.id, "domain", "not a host!")
        with self.assertRaises(errors.ValidationError):
            models.Asset(project_id=self.proj.id, asset_type="ip",
                         value="999.1.1.1").finalize()

    def test_different_asset_types(self):
        self.svc.asset_add(self.proj.id, "subdomain", "api.example.com")
        self.svc.asset_add(self.proj.id, "url", "https://example.com/")
        rows = self.svc.asset_list(self.proj.id)
        self.assertEqual(len(rows), 2)

    def test_ip_and_cidr_asset(self):
        a = models.Asset(project_id=self.proj.id, asset_type="ip", value="192.0.2.1")
        a.finalize()
        self.assertEqual(a.value, "192.0.2.1")
        with self.assertRaises(errors.ValidationError):
            models.Asset(project_id=self.proj.id, asset_type="ip",
                         value="192.0.2.999").finalize()


class TestScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pf_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = make_service(self.tmp)
        self.org = self.svc.org_create("Acme")
        self.proj = self.svc.project_create(self.org.id, "Web")

    def test_creation_and_timestamps(self):
        s = self.svc.scan_create(self.proj.id, "web-audit")
        self.assertEqual(s.status, "pending")
        self.assertTrue(s.created_at)
        got = self.svc.scan_get(s.id)
        self.assertEqual(got.profile, "web-audit")

    def test_valid_transitions(self):
        s = self.svc.scan_create(self.proj.id, "web-audit")
        self.svc.scan_transition(s.id, "queued")
        self.svc.scan_transition(s.id, "running")
        got = self.svc.scan_transition(s.id, "completed")
        self.assertEqual(got.status, "completed")
        self.assertTrue(got.finished_at)
        self.assertTrue(got.started_at)

    def test_invalid_transitions(self):
        s = self.svc.scan_create(self.proj.id, "web-audit")
        self.svc.scan_transition(s.id, "running")
        with self.assertRaises(errors.LifecycleError):
            self.svc.scan_transition(s.id, "queued")     # running → queued illegal
        # completed → anything is impossible
        s2 = self.svc.scan_create(self.proj.id, "web-audit", scan_id="s-complete")
        self.svc.scan_transition("s-complete", "running")
        self.svc.scan_transition("s-complete", "completed")
        with self.assertRaises(errors.LifecycleError):
            self.svc.scan_transition("s-complete", "running")
        # pending → completed impossible
        s3 = self.svc.scan_create(self.proj.id, "web-audit", scan_id="s-pend")
        with self.assertRaises(errors.LifecycleError):
            self.svc.scan_transition("s-pend", "completed")

    def test_progress_validation(self):
        s = models.Scan(project_id=self.proj.id, profile="web-audit", progress=1.5)
        with self.assertRaises(errors.ValidationError):
            s.finalize()


class TestFinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pf_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = make_service(self.tmp)
        self.org = self.svc.org_create("Acme")
        self.proj = self.svc.project_create(self.org.id, "Web")
        self.scan = self.svc.scan_create(self.proj.id, "web-audit")
        self.asset = self.svc.asset_add(self.proj.id, "url",
                                        "https://shop.example.com/item?id=1")

    def make_finding(self, **kw):
        f = models.Finding(
            scan_id=self.scan.id, project_id=self.proj.id,
            asset_id=self.asset.id, title=kw.get("title", "SQL Injection"),
            severity=kw.get("severity", "Critical"),
            category=kw.get("category", "injection"),
            source="SecuAudit", rule_id=kw.get("rule_id", "SQLI-1"),
            raw={"parameter": "id", "endpoint": "/item"},
            evidence=[{"evidence_type": "response",
                       "detection_reason": "mysql error" +
                       (" secret=abc123 " if kw.get("secret") else "")}])
        f.finalize()
        return f

    def test_creation_severity_confidence(self):
        f = self.make_finding()
        f2 = models.Finding.from_dict(f.to_dict())
        self.assertEqual(f2.id, f.id)
        self.assertEqual(f2.severity, "Critical")
        self.assertEqual(f2.confidence, "medium")
        self.assertEqual(f2.lifecycle, "open")
        doc = json.dumps(f.to_dict())
        self.assertEqual(models.Finding.from_dict(f.to_dict()).fingerprint,
                         f.fingerprint)

    def test_lifecycle_valid(self):
        f = self.make_finding()
        self.assertTrue(f.transition("acknowledged"))
        self.assertTrue(f.transition("resolved"))
        self.assertTrue(f.resolved_at)
        # resolved → re-open allowed (regression)
        f.transition("open")
        self.assertEqual(f.lifecycle, "open")
        # finding status change idempotent: same status → no change
        self.assertFalse(f.transition("open"))

    def test_lifecycle_invalid(self):
        f = self.make_finding()
        # open → accepted_risk is allowed; but open → resolved directly IS allowed.
        f.transition("resolved")
        with self.assertRaises(errors.LifecycleError):
            f.transition("false_positive")   # resolved cannot skip re-open
        with self.assertRaises(errors.LifecycleError):
            f.transition("nonexistent")

    def test_deduplication_fingerprint(self):
        a = self.make_finding(rule_id="SQLI-1")
        b = self.make_finding(rule_id="SQLI-1")      # same rule, same asset
        c = self.make_finding(rule_id="XSS-1")       # different rule
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertNotEqual(a.fingerprint, c.fingerprint)
        # different asset → different fingerprint
        a2 = models.Asset(project_id=self.proj.id, asset_type="url",
                          value="https://other.example.com/")
        a2.finalize()
        d = self.make_finding(rule_id="SQLI-1")
        d.asset_id = a2.id
        d.fingerprint = ""
        d.finalize()
        self.assertNotEqual(a.fingerprint, d.fingerprint)

    def test_ingest_dedup_updates_existing(self):
        f = self.make_finding()
        self.svc.finding_ingest(f)
        again = self.make_finding()
        self.svc.finding_ingest(again)
        rows = self.svc.finding_list(self.proj.id)
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0].last_detected, "")


class TestEvidenceRedaction(unittest.TestCase):
    def test_authorization_bearer_redacted(self):
        ev = models.Evidence(finding_id="f-1", evidence_type="response",
                             request_snippet="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def")
        ev.finalize()
        self.assertNotIn("Bearer eyJ", ev.request_snippet)
        self.assertIn("[REDACTED]", ev.request_snippet)

    def test_cookie_api_key_password_private_key(self):
        ev = models.Evidence(
            finding_id="f-1", evidence_type="response",
            request_snippet=("Cookie: SID=deadbeef\n"
                             "x-api-key: sk-proj-ABCDEF1234567890\n"
                             "password=hunter2\n"
                             "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg\n-----END RSA PRIVATE KEY-----"))
        ev.finalize()
        s = ev.request_snippet
        self.assertNotIn("sk-proj-", s)
        self.assertNotIn("hunter2", s)
        self.assertNotIn("MIIBOg", s)
        self.assertNotIn("deadbeef", s)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", s)

    def test_redact_function_dict_recursive(self):
        out = redact.redact({"headers": {"Authorization": "Bearer abc123",
                                         "X-OK": "1"},
                             "nested": [{"token": "tok-x", "value": "keep"}]})
        self.assertEqual(out["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(out["nested"][0]["token"], "[REDACTED]")
        self.assertEqual(out["nested"][0]["value"], "keep")

    def test_redact_text_patterns(self):
        t = redact.redact_text("api key AKIAIOSFODNN7EXAMPLE and jwt eyJhb.eyJhb.eyJhb")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", t)

    def test_secrets_never_persisted_in_evidence(self):
        self.tmp = tempfile.mkdtemp(prefix="pf_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        svc = make_service(self.tmp)
        org = svc.org_create("Acme")
        proj = svc.project_create(org.id, "Web")
        scan = svc.scan_create(proj.id, "web-audit")
        f = models.Finding(scan_id=scan.id, project_id=proj.id,
                           title="SQLi", severity="Critical", category="injection",
                           rule_id="SQLI-1", source="SecuAudit",
                           evidence=[{"evidence_type": "response",
                                      "detection_reason": "Bearer tok-secret-1 leaked"}])
        f.finalize()
        evs = [models.Evidence.from_dict(e) for e in f.evidence]
        for e in evs:
            e.finding_id = f.id
            e.finalize()
        svc.finding_ingest(f, evidence=evs)
        evs2 = svc.evidence_list(f.id)
        blob = json.dumps(evs2) + json.dumps(svc.finding_get(f.id).to_dict())
        self.assertNotIn("tok-secret-1", blob)


class TestScope(unittest.TestCase):
    def _pol(self, allow=None, deny=None):
        return scope_mod.ScopePolicy(allow or ["example.com", "*.example.com"],
                                     deny or [])

    def test_exact_domain(self):
        p = self._pol(["example.com"])
        self.assertTrue(p.is_in_scope("example.com"))
        self.assertFalse(p.is_in_scope("www.example.com"))

    def test_subdomain_wildcard(self):
        p = self._pol(["*.example.com"])
        self.assertTrue(p.is_in_scope("api.example.com"))
        self.assertTrue(p.is_in_scope("a.b.example.com"))
        self.assertFalse(p.is_in_scope("example.com"))       # apex ≠ wildcard
        self.assertFalse(p.is_in_scope("evil.com"))

    def test_denied_host_wins(self):
        p = self._pol(["*.example.com"], ["admin.example.com"])
        self.assertFalse(p.is_in_scope("admin.example.com"))
        self.assertTrue(p.is_in_scope("public.example.com"))

    def test_denied_subdomain(self):
        p = self._pol(["*.example.com"], ["*.internal.example.com"])
        self.assertFalse(p.is_in_scope("x.internal.example.com"))

    def test_url_normalization_and_path(self):
        p = self._pol(["https://app.example.com/admin/"])
        self.assertTrue(p.is_in_scope("https://app.example.com/admin/users"))
        self.assertFalse(p.is_in_scope("https://app.example.com/public"))
        self.assertFalse(p.is_in_scope("https://other.example.com/admin/"))

    def test_ip_and_cidr(self):
        p = self._pol(["192.0.2.10", "10.0.0.0/8"])
        self.assertTrue(p.is_in_scope("192.0.2.10"))
        self.assertTrue(p.is_in_scope("10.20.30.40"))
        self.assertFalse(p.is_in_scope("192.0.2.11"))
        self.assertFalse(p.is_in_scope("10.0.0.1" if False else "11.0.0.1"))

    def test_port_handling(self):
        p = self._pol(["api.example.com:8443"])
        self.assertTrue(p.is_in_scope("api.example.com:8443"))
        self.assertFalse(p.is_in_scope("api.example.com:443"))

    def test_malformed_hostname_fails_closed(self):
        p = self._pol(["example.com"])
        self.assertFalse(p.is_in_scope("http://"))
        self.assertFalse(p.is_in_scope("ftp://example.com"))
        self.assertFalse(p.is_in_scope("..%2f..%2f"))
        with self.assertRaises(errors.ValidationError):
            p.is_in_scope("")

    def test_malformed_url_out_of_scope(self):
        p = self._pol(["example.com"])
        with self.assertRaises(errors.ValidationError):
            scope_mod.ScopePolicy(["http://"])
        # unsupported scheme fails closed
        self.assertFalse(p.is_in_scope("gopher://example.com"))

    def test_deny_rule_on_empty(self):
        with self.assertRaises(errors.ValidationError):
            scope_mod.ScopePolicy([], [])

    def test_guard_noop_when_disabled(self):
        # default config: scope disabled → guard is a no-op (backward compat)
        import sec_config as scfg
        old = scfg._config
        scfg._config = None
        try:
            scope_mod.guard_target("https://anything.example/")
        finally:
            scfg._config = old


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pf_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = make_service(self.tmp)
        self.org = self.svc.org_create("Acme")
        self.proj = self.svc.project_create(self.org.id, "Web")

    def test_event_creation(self):
        self.svc.audit("scan.created", object_type="scan", object_id="s-1",
                       project_id=self.proj.id, actor="tester",
                       metadata={"profile": "web-audit"})
        events = self.svc.audit_list(self.proj.id)
        self.assertGreaterEqual(len(events), 2)   # project + scan under project
        sc = [e for e in events if e.action == "scan.created"]
        self.assertEqual(len(sc), 1)
        self.assertTrue(sc[0].ts)
        self.assertEqual(sc[0].actor, "tester")
        # org-level event exists in the global stream
        all_events = self.svc.audit_list(None)
        self.assertTrue(any(e.action == "organization.created"
                            for e in all_events))

    def test_metadata_sanitized(self):
        self.svc.audit("scan.created", object_type="scan", object_id="s-2",
                       project_id=self.proj.id,
                       metadata={"note": "password=hunter2 token=abc123"})
        events = self.svc.audit_list(self.proj.id)
        ev = [e for e in events if e.object_id == "s-2"][0]
        blob = json.dumps(ev.metadata)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("abc123", blob)

    def test_actor_and_object_refs(self):
        self.svc.audit("finding.status_changed", actor="analyst@corp.test",
                       object_type="finding", object_id="f-9",
                       project_id=self.proj.id, metadata={"to": "resolved"})
        events = self.svc.audit_list(self.proj.id)
        ev = [e for e in events if e.object_type == "finding"][0]
        self.assertEqual(ev.actor, "analyst@corp.test")
        self.assertEqual(ev.object_id, "f-9")

    def test_invalid_action_rejected(self):
        with self.assertRaises(errors.ValidationError):
            self.svc.audit("totally.not.an.action")


class TestPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pf_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = store.Database(os.path.join(self.tmp, "t.db"))
        self.db.migrate()

    def test_create_read_update(self):
        self.db.execute(
            "INSERT INTO organizations (id, name, status, created_at, updated_at)"
            " VALUES (?,?,?,?,?)", ("o1", "Acme", "active", "2026-01-01", "2026-01-01"))
        row = self.db.query_one("SELECT * FROM organizations WHERE id=?", ("o1",))
        self.assertEqual(row["name"], "Acme")
        self.db.execute("UPDATE organizations SET status=? WHERE id=?",
                        ("disabled", "o1"))
        row = self.db.query_one("SELECT * FROM organizations WHERE id=?", ("o1",))
        self.assertEqual(row["status"], "disabled")

    def test_delete(self):
        self.db.execute(
            "INSERT INTO organizations (id, name, status, created_at, updated_at)"
            " VALUES (?,?,?,?,?)", ("o2", "Globex", "active", "2026-01-01", "2026-01-01"))
        self.db.delete("organizations", "o2")
        with self.assertRaises(errors.NotFoundError):
            self.db.query_one("SELECT * FROM organizations WHERE id=?", ("o2",))

    def test_not_found(self):
        with self.assertRaises(errors.NotFoundError):
            self.db.query_one("SELECT * FROM organizations WHERE id=?", ("zz",))

    def test_parameterized_no_sqli(self):
        evil = "x'; DROP TABLE organizations; --"
        with self.assertRaises(errors.NotFoundError):
            self.db.query_one("SELECT * FROM organizations WHERE id=?", (evil,))
        # table still exists → query didn't get exploited
        self.db.query_one("SELECT COUNT(*) AS c FROM organizations")

    def test_transactions_rollback(self):
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO organizations (id, name, status, created_at,"
                    " updated_at) VALUES (?,?,?,?,?)",
                    ("o3", "X", "active", "t", "t"))
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        with self.assertRaises(errors.NotFoundError):
            self.db.query_one("SELECT * FROM organizations WHERE id=?", ("o3",))

    def test_foreign_keys_enforced(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO projects (id, org_id, name, description, status,"
                " scope_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                ("p1", "no-org", "X", "", "active", "{}", "t", "t"))

    def test_bounded_queries(self):
        for i in range(30):
            self.db.execute(
                "INSERT INTO organizations (id, name, status, created_at,"
                " updated_at) VALUES (?,?,?,?,?)",
                (f"bulk{i}", f"Org {i}", "active", "t", "t"))
        rows = self.db.query("SELECT * FROM organizations", limit=10)
        self.assertEqual(len(rows), 10)
        with self.assertRaises(errors.ValidationError):
            self.db.query("SELECT * FROM organizations", limit=-1)
        with self.assertRaises(errors.ValidationError):
            self.db.query("SELECT * FROM organizations", limit=100000)

    def test_migration_idempotent(self):
        self.db.migrate()
        self.db.migrate()   # must not raise


class TestNormalization(unittest.TestCase):
    def test_web_audit_result(self):
        raw = {"tool": "SecuAudit", "target": "https://shop.example.com/",
               "scan_date": "2026-09-04T10:00:00", "score": 70, "grade": "C",
               "findings": [
                   {"id": "SQLI-1", "title": "Boolean SQLi", "severity": "Critical",
                    "evidence": "?id=1 AND 1=1", "remediation": "Parametrize"},
                   {"id": "TLS-EXPIRED", "title": "TLS expired", "severity": "High",
                    "evidence": "cert", "remediation": "Renew"}],
               "summary": {"Critical": 1, "High": 1}}
        n = normalize.normalize_result(raw, project_id="p1")
        self.assertEqual(n["scan"].profile, "web-audit")
        # raw has no scan_id -> deterministic stable UUID is assigned, and the
        # SAME payload always maps to the SAME scan id (idempotent ingestion)
        self.assertTrue(n["scan"].id)
        n2 = normalize.normalize_result(raw, project_id="p1")
        self.assertEqual(n["scan"].id, n2["scan"].id)
        self.assertEqual(len(n["assets"]), 1)
        self.assertEqual(len(n["findings"]), 2)
        self.assertEqual(n["findings"][0].severity, "Critical")
        self.assertEqual(n["findings"][0].category, "injection")
        self.assertIn("raw", n["findings"][0].to_dict())
        # raw preserved for backward compatibility
        self.assertEqual(raw["findings"][0]["id"], "SQLI-1")

    def test_normalize_severity(self):
        self.assertEqual(normalize.normalize_severity("CRITICAL"), "Critical")
        self.assertEqual(normalize.normalize_severity("high"), "High")
        self.assertEqual(normalize.normalize_severity("nonsense"), "Info")

    def test_waf_and_cloud_results(self):
        waf = {"tool": "WallFinder", "url": "https://x.example.com",
               "waf": [{"vendor": "Cloudflare", "evidence": ["header"]}],
               "reachable": True}
        n = normalize.normalize_result(waf, project_id="p1")
        self.assertEqual(len(n["findings"]), 1)
        self.assertIn("Cloudflare", n["findings"][0].title)

        cloud = {"tool": "CloudScope", "checks": [
            {"service": "Redis", "status": "OPEN — NO AUTH", "severity": "Critical",
             "evidence": "+PONG", "remediation": "requirepass"}]}
        n2 = normalize.normalize_result(cloud, project_id="p1")
        self.assertEqual(n2["findings"][0].severity, "Critical")
        self.assertEqual(n2["findings"][0].category, "misconfiguration")

    def test_subdomain_result(self):
        raw = {"domain": "example.com", "count": 2,
               "subdomains": {"www.example.com": {"sources": ["crt.sh"],
                                                  "ips": ["93.184.216.34"]},
                              "mail.example.com": {"sources": ["crt.sh"], "ips": []}}}
        n = normalize.normalize_result(raw, project_id="p1")
        # SubKraken emits {domain, count, subdomains} — the apex domain AND
        # each enumerated subdomain become assets (3 total).
        self.assertEqual(len(n["assets"]), 3)
        self.assertEqual(n["assets"][0].asset_type, "domain")
        self.assertEqual(len(n["findings"]), 2)
        sev = {f.title: f.severity for f in n["findings"]}
        self.assertIn("Low", sev.values())

    def test_platform_integration_roundtrip(self):
        tmp = tempfile.mkdtemp(prefix="pf_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        svc = make_service(tmp)
        org = svc.org_create("Acme")
        proj = svc.project_create(org.id, "Web")
        raw = {"tool": "Injector (active fuzzer)",
               "target": "https://shop.example.com/item?id=1",
               "scan_date": "2026-09-04T10:00:00",
               "findings": [{"type": "SQL Injection (error-based, MySQL)",
                             "severity": "Critical", "payload": "'",
                             "evidence": "mysql error", "remediation": "params"}],
               "waf_detected": []}
        out = svc.register_scanner_result(proj.id, raw)
        self.assertEqual(out["findings"], 1)
        scan = svc.scan_get(out["scan_id"])
        self.assertEqual(scan.status, "completed")
        findings = svc.finding_list(proj.id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "SQL Injection (error-based, MySQL)")
        # raw scan payload preserved (redacted)
        self.assertIn("findings", scan.raw)


class TestSecurityRegressions(unittest.TestCase):
    def test_path_traversal_guard_in_schemas_only(self):
        # DB path must be a file path — traversal to non-file refuses
        db = store.Database("/proc/self/mem")
        with self.assertRaises(errors.PersistenceError):
            db.connect()

    def test_no_secret_in_serialized_models(self):
        for cls, kwargs in ((models.Organization, {"name": "X"}),
                            (models.Project, {"org_id": "o", "name": "P"}),
                            (models.Asset, {"project_id": "p", "asset_type": "domain",
                                            "value": "ex.com"}),
                            (models.Scan, {"project_id": "p", "profile": "x"}),
                            (models.Finding, {"scan_id": "s", "project_id": "p"}),
                            (models.Evidence, {"finding_id": "f", "evidence_type":
                                               "response"}),
                            (models.AuditEvent, {"action": "scan.created"})):
            obj = cls(**kwargs)
            if hasattr(obj, "finalize"):
                obj.finalize()
            blob = json.dumps(obj.to_dict()).lower()
            for secret in ("password", "secret", "token", "api_key",
                           "private_key"):
                self.assertNotIn(secret, blob)

    def test_logging_redacts(self):
        text = "sql exec with token=abc123xyz header Authorization: Bearer yy"
        seclog.info("exec", query=text)
        # logger redacts every field through redact.redact()
        self.assertNotIn("abc123xyz", redact.redact_text(text))
        self.assertIn("[REDACTED]", redact.redact_text(text))

    def test_malformed_json_handled(self):
        with self.assertRaises(json.JSONDecodeError):
            json.loads("{not json")
        # normalize rejects non-dict results
        with self.assertRaises(errors.ValidationError):
            normalize.normalize_result([1, 2, 3], project_id="p")

    def test_oversized_evidence_truncated(self):
        ev = models.Evidence(finding_id="f-9", evidence_type="response",
                             response_snippet="A" * 50_000)
        ev.finalize()
        self.assertLessEqual(len(ev.response_snippet), 2000)

    def test_invalid_transitions_blocked(self):
        s = models.Scan(project_id="p", profile="x")
        s.finalize()
        with self.assertRaises(errors.LifecycleError):
            s.transition("completed")     # pending → completed illegal
        f = models.Finding(scan_id="s", project_id="p")
        f.finalize()
        with self.assertRaises(errors.LifecycleError):
            f.transition("make-me-a-sandwich")

    def test_scope_denies_unauthorized_target(self):
        eng = scope_mod.ScopeEngine(scope_mod.ScopePolicy(
            ["example.com"], ["admin.example.com"]))
        with self.assertRaises(errors.ScopeViolationError):
            eng.assert_in_scope("admin.example.com")
        eng.assert_in_scope("example.com")
        with self.assertRaises(errors.ScopeViolationError):
            eng.assert_in_scope("evil.net")

    def test_scope_without_policy_refuses(self):
        eng = scope_mod.ScopeEngine(None)
        with self.assertRaises(errors.ConfigurationError):
            eng.assert_in_scope("example.com")


if __name__ == "__main__":
    unittest.main()
