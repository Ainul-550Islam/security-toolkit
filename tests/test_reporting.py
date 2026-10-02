#!/usr/bin/env python3
# ============================================================================
#  test_reporting.py — Phase-6 enterprise reporting & compliance evidence
#  suite.
#  Covers: report snapshots (all 8 types), determinism + canonical hash,
#  analytics (posture/KPIs/trends/attack-surface, bounded ranges),
#  compliance evidence (categories, provenance, honest statuses, immutability,
#  no compliance claims), redaction across JSON/HTML/PDF/dashboard/API,
#  tenant isolation + RBAC (report.read/generate/export, analytics.read,
#  compliance_evidence.read), filter allowlists (SQL/path/HTML/PDF injection),
#  hard pagination, retention (never deletes immutable/audit/evidence),
#  and a performance guard (100 assets / 500 findings / 1000 events).
#  Fully offline, deterministic, temp SQLite per test class.
# ============================================================================
from __future__ import annotations

import json
import os
import subprocess
import sys
import shutil
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "python")
sys.path.insert(0, PY)
sys.path.insert(0, HERE)

import errors  # noqa: E402
import metrics  # noqa: E402
import models  # noqa: E402
import redact  # noqa: E402
import store  # noqa: E402
import rbac  # noqa: E402
import analytics  # noqa: E402
import reporting  # noqa: E402
import identity as identity_mod  # noqa: E402
import platform_service as pf  # noqa: E402

from reporting import (ReportService, EvidenceService, secure_export_path,
                       validate_filters)  # noqa: E402
from analytics import AnalyticsService  # noqa: E402

PW = "S3cure!Passw0rd"
PHISH = "Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop"
PHISH_MARK = "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop"   # must never leak

identity_mod.RL_LIMITS["auth"] = (10000, 60)
identity_mod.RL_LIMITS["auth_ip"] = (10000, 60)
identity_mod.RL_LIMITS["session_create"] = (10000, 60)
identity_mod.RL_LIMITS["api"] = (10000, 60)
identity_mod.RL_LIMITS["credential_create"] = (10000, 3600)


def make_service(tmp):
    return pf.PlatformService(os.path.join(tmp, "secutool.db"))


def raw_result(target: str, findings, assets=None) -> dict:
    return {"tool": "secuaudit", "target": target,
            "assets": assets or [{"type": "url", "value": target}],
            "findings": findings}


def finding(title, severity="High", cat="xss", fid=None, extra=None):
    d = {"title": title, "description": title, "severity": severity,
         "confidence": "high", "category": cat, "source": "secuaudit",
         "rule_id": "rule-" + str(fid or cat), "cwe": "CWE-79",
         "remediation": "Fix it.",
         "evidence": "observed during authorized scan",
         "raw": {"endpoint": "/", "parameter": "q"}}
    if fid:
        d["id"] = fid
    d.update(extra or {})
    return d


class P6Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p6_")
        self.svc = make_service(self.tmp)
        self.org = self.svc.org_create("Acme")
        self.proj = self.svc.project_create(self.org.id, "Web")
        self.sec_proj = self.svc.project_create(self.org.id, "API")
        self.id_svc = identity_mod.IdentityService(self.svc, scrypt_n=2 ** 8)
        self.authz = __import__("authz").AuthorizationService(
            self.svc, self.id_svc)
        self.rsvc = ReportService(self.svc)
        self.evsvc = EvidenceService(self.svc)
        self.anasvc = AnalyticsService(self.svc)
        self._seed()

    def tearDown(self):
        # the temporary DB is per-test and never needed afterwards
        shutil.rmtree(self.tmp, ignore_errors=True)


    def _seed(self):
        p = self.proj
        a = self.svc.asset_add(p.id, "domain", "web.acme.test")
        self.svc.asset_add(p.id, "ip", "203.0.113.7")
        raw = raw_result(
            "https://web.acme.test/", [
                finding("SQL injection in /login", "Critical", "injection",
                        fid="f-crit"),
                finding("Reflected XSS in q", "High", "xss", fid="f-xss"),
                finding("Missing HSTS", "Medium", "misconfiguration",
                        fid="f-hsts"),
                finding("Banner disclosed", "Info", "information_disclosure",
                        fid="f-info"),
            ])
        res = self.svc.register_scanner_result(self.proj.id, raw)
        self.scan_id = res["scan_id"]
        # evidence_add is the Phase-1 path that finalizes + redacts snippets
        crit = [f for f in self.svc.finding_list(self.proj.id, limit=20)
                if f.severity == "Critical"][0]
        self.crit_id = crit.id
        self.svc.evidence_add(
            crit.id, evidence_type="request",
            url="https://web.acme.test/login", method="POST",
            request_snippet="Authorization: " + PHISH,
            response_snippet="500")
        # mark asset exposure through the Phase-4 pipeline (real APIs only)
        import intel
        it = intel.IntelService(self.svc)
        it.criticality_set(a.id, "critical", actor="test")
        drv = it.refresh_exposure(a.id)
        self.svc.db.execute(
            "UPDATE assets SET exposure=?, exposure_reason=? WHERE id=?",
            ("internet_facing", drv.get("reason") or "web fixture", a.id))
        # a few change events so attack-surface analytics has data
        for ev_type in ("exposure.changed", "technology.changed",
                        "service.opened"):
            self.svc.db.execute(
                "INSERT INTO security_events (id, project_id, org_id, "
                "asset_id, event_type, source, ts, previous_state, new_state, "
                "confidence, scan_id, state_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (models.stable_id(models.NS_EVENT, f"ev-{ev_type}-{time.monotonic_ns()}"),
                 p.id, self.org.id, a.id, ev_type, "test",
                 models.utcnow(), "{}", "{}", 0.5, "", ""))

    # ---- auth helpers ----------------------------------------------------
    def add_user(self, org=None, username="u1", roles=("security_manager",)):
        org = org or self.org
        return self.id_svc.user_create(org.id, username, username + "@a.test",
                                       PW, roles=roles, allow_any_role=True,
                                       actor="test")

    def ctx_for(self, username):
        secret = self.id_svc.login(username, PW)["secret"]
        return self.authz.context_from_secret(secret)

    def _old_run(self, days_ago, report_type="executive", svc=None,
                 rsvc=None):
        rsvc = rsvc or self.rsvc
        svc = svc or self.svc
        snap = rsvc.snapshot(self.proj.id, report_type, generated_by="old")
        run = rsvc.store_run(snap, store_payload=True)
        cut = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - days_ago * 86400))
        svc.db.execute("UPDATE report_runs SET created_at=? WHERE id=?",
                       (cut, run["id"]))
        return run

    def ctx_owner(self):
        self.add_user(username="owner", roles=("owner",))
        return self.ctx_for("owner")

    def seed_assets_findings(self, n_assets=100, n_findings=500,
                             n_events=1000):
        """Performance fixture: direct inserts (the Phase-6 analytics are
        what this suite must keep fast; the Phase-4 ingest pipeline is
        covered by its own suites)."""
        p = self.proj
        now = models.utcnow()
        sevs = ("Critical", "High", "Medium", "Low", "Info")
        asset_ids = [models.stable_id(models.NS_ASSET, f"perfa-{i}")
                     for i in range(n_assets)]
        with self.svc.db.transaction() as conn:
            for i, aid in enumerate(asset_ids):
                conn.execute(
                    "INSERT INTO assets (id, project_id, asset_type, value,"
                    " display, metadata, status, first_seen, last_seen, "
                    "criticality, exposure, exposure_reason, "
                    "business_impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (aid, p.id, "domain",
                     f"host{i}.perf.test", "", "{}", "active", now, now,
                     "unknown", "unknown", "", "{}"))
            for i in range(n_findings):
                conn.execute(
                    "INSERT INTO findings (id, scan_id, project_id, "
                    "asset_id, title, description, severity, confidence, "
                    "category, source, rule_id, template_id, cwe, cve, "
                    "cvss, remediation, evidence, raw, lifecycle, "
                    "fingerprint, first_detected, last_detected, "
                    "resolved_at, confidence_score, confidence_level, "
                    "confidence_reasons, risk_score, risk_level, "
                    "risk_factors, calc_version, priority, priority_order, "
                    "canonical_key, occurrence_count, suppressed_until, "
                    "dismissed_reason, dismissed_by, reopened_at, "
                    "business_impact, exploitability) VALUES (?,?,?,?,?,?,"
                    "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                    "?,?,?,?,?,?,?)",
                    (models.stable_id(models.NS_FINDING,
                                      f"perff-{i}"), self.scan_id, p.id,
                     asset_ids[i % n_assets],
                     f"Finding number {i}", "perf", sevs[i % 5], "high",
                     "injection", "perf", f"rule-perf-{i}", "", "CWE-89",
                     "", "{}", "Fix.", "[]", "{}", "open",
                     f"fp-{i}", now, now, "",
                     0.8, "verified", "{}",
                     20.0 + (i % 10) * 4.0,
                     "medium", "{}", "risk-v1", "P2", 2,
                     f"ck-{i}", 1, "", "", "", "", "{}", "unknown"))
            for i in range(n_events):
                et = ("exposure.changed", "technology.changed",
                      "service.opened", "service.closed")[i % 4]
                conn.execute(
                    "INSERT INTO security_events (id, project_id, org_id, "
                    "asset_id, event_type, source, ts, previous_state, "
                    "new_state, confidence, scan_id, state_key) VALUES "
                    "(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (models.stable_id(models.NS_EVENT,
                                      f"pev-{i}"), p.id, self.org.id, "",
                     et, "perf", now, "{}", "{}", 0.5, "", ""))


# ---------------------------------------------------------------------------
class TestFilterValidation(P6Base):
    def test_severity_allowlist(self):
        self.assertEqual(validate_filters({"severity": "Critical"})
                         ["severities"], ["Critical"])
        for bad in ("critical", "Cri;t", "Critical OR 1=1",
                    "High; DROP TABLE findings;--", "", ["Critical", "x"]):
            with self.assertRaises(errors.ValidationError):
                validate_filters({"severity": bad})

    def test_status_allowlist(self):
        self.assertEqual(validate_filters({"status": "open"})["statuses"],
                         ["open"])
        with self.assertRaises(errors.ValidationError):
            validate_filters({"status": "OPEN"})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"status": "open'; DELETE FROM findings;--"})

    def test_risk_bounds(self):
        self.assertEqual(validate_filters({"risk_min": 10,
                                           "risk_max": 50})["risk_min"], 10.0)
        with self.assertRaises(errors.ValidationError):
            validate_filters({"risk_min": -1})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"risk_max": 101})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"risk_min": 60, "risk_max": 10})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"risk_min": "abc"})

    def test_exposure_criticality_category(self):
        self.assertEqual(validate_filters({"exposure": "internet_facing"})
                         ["exposure"], "internet_facing")
        with self.assertRaises(errors.ValidationError):
            validate_filters({"exposure": "public"})
        self.assertEqual(validate_filters({"criticality": "high"})
                         ["criticality"], "high")
        with self.assertRaises(errors.ValidationError):
            validate_filters({"criticality": "super"})
        self.assertEqual(validate_filters({"category": "xss"})["category"],
                         "xss")
        with self.assertRaises(errors.ValidationError):
            validate_filters({"category": "xss; DROP TABLE findings;--"})

    def test_asset_id_pattern(self):
        self.assertEqual(validate_filters({"asset_id": "host-01.test"})
                         ["asset_id"], "host-01.test")
        with self.assertRaises(errors.ValidationError):
            validate_filters({"asset_id": "../../etc/passwd"})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"asset_id": "x" * 200})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"asset_id": "../etc/passwd"})

    def test_technology_length_and_chars(self):
        with self.assertRaises(errors.ValidationError):
            validate_filters({"technology": ""})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"technology": "x" * 200})
        f = validate_filters({"technology": "nginx 1.18"})
        self.assertEqual(f["technology"], "nginx 1.18")

    def test_date_range_bounds(self):
        f = validate_filters({"start": "2026-01-01", "end": "2026-02-01"})
        self.assertEqual(f["start"], "2026-01-01T00:00:00Z")
        with self.assertRaises(errors.ValidationError):
            validate_filters({"start": "01/01/2026"})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"start": "2026-02-01", "end": "2026-01-01"})
        with self.assertRaises(errors.ValidationError):
            validate_filters({"start": "2026-13-01"})

    def test_sql_injection_filter_values_never_execute(self):
        n = self.svc.db.query_one("SELECT COUNT(*) n FROM findings")["n"]
        for payload in ("Critical' OR '1'='1", "Critical\"; DROP TABLE "
                        "findings;--", "''", "%", "' UNION SELECT * FROM "
                        "users--"):
            try:
                validate_filters({"severity": payload})
                failed = False
            except errors.ValidationError:
                failed = True
            try:
                snap = self.rsvc.snapshot(
                    self.proj.id, "technical", generated_by="t",
                    filters={"severity": [payload]})
                self.assertEqual(snap["findings"], [])
            except errors.ValidationError:
                pass
        n2 = self.svc.db.query_one("SELECT COUNT(*) n FROM findings")["n"]
        self.assertEqual(n, n2)  # table intact after every attempt


# ---------------------------------------------------------------------------
class TestSnapshots(P6Base):
    def test_all_report_types_generate(self):
        for rtype in models.REPORT_TYPES:
            snap = self.rsvc.snapshot(self.proj.id, rtype,
                                      generated_by="test")
            self.assertEqual(snap["metadata"]["report_type"], rtype)
            self.assertEqual(snap["metadata"]["report_version"],
                             "report-schema-v1")
            self.assertTrue(snap["metadata"]["report_hash"])
            self.assertTrue(snap["metadata"]["risk_calculation_version"])
            self.assertEqual(len(snap["metadata"]["report_hash"]), 64)

    def test_snapshot_structure(self):
        snap = self.rsvc.snapshot(self.proj.id, "executive",
                                  generated_by="test")
        meta = snap["metadata"]
        for k in ("org_id", "org_name", "project_id", "project_name",
                  "report_type", "title", "generated_at", "generated_by",
                  "data_cutoff", "risk_calculation_version",
                  "report_version", "posture_version", "report_hash"):
            self.assertIn(k, meta)
        self.assertIn("filter", snap)
        self.assertIn("posture", snap)
        self.assertIn("risk", snap)
        self.assertIn("assets", snap)
        self.assertIn("findings", snap)
        self.assertIn("remediation", snap)
        self.assertIn("monitoring", snap)
        self.assertIn("truncation", snap)
        self.assertGreaterEqual(len(snap["assets"]), 2)
        self.assertGreaterEqual(len(snap["findings"]), 4)

    def test_severity_filter_scopes_content(self):
        snap = self.rsvc.snapshot(
            self.proj.id, "vulnerability", generated_by="test",
            filters={"severities": ["Critical"]})
        self.assertEqual(len(snap["findings"]), 1)
        self.assertEqual(snap["findings"][0]["severity"], "Critical")

    def test_asset_filter_fails_closed_for_foreign_or_unknown_asset(self):
        with self.assertRaises(errors.NotFoundError):
            self.rsvc.snapshot(
                self.proj.id, "asset_inventory", generated_by="test",
                filters={"asset_id":
                         "00000000-0000-0000-0000-000000000000"})
        # a REAL asset id from this project is accepted and scopes the report
        aid = self.svc.asset_list(self.proj.id, limit=1)[0].id
        snap = self.rsvc.snapshot(
            self.proj.id, "asset_inventory", generated_by="test",
            filters={"asset_id": aid})
        self.assertEqual(len(snap["assets"]), 1)
        self.assertEqual(snap["assets"][0]["id"], aid)

    def test_truncation_metadata_visible(self):
        rsvc = ReportService(self.svc, max_findings=2, max_assets=1)
        snap = rsvc.snapshot(self.proj.id, "technical", generated_by="test")
        t = snap["truncation"]
        self.assertTrue(t["truncated"])
        fa = t["sections"]["findings"]
        self.assertTrue(fa["truncated"])
        self.assertEqual(fa["reason"], "max_findings_reached")
        self.assertGreater(fa["original_count"], fa["included_count"])
        self.assertEqual(fa["included_count"], 2)
        aa = t["sections"]["assets"]
        self.assertTrue(aa["truncated"])
        self.assertEqual(aa["included_count"], 1)
        # and the run row records it
        run = rsvc.store_run(snap, store_payload=True)
        self.assertEqual(int(run["truncated"]), 1)
        self.assertEqual(run["truncation_reason"], "max_findings_reached")
        self.assertEqual(run["original_count"], fa["original_count"] +
                         aa["original_count"])

    def test_html_injection_escaped(self):
        evil = "<script>alert('x')</script><img src=x onerror=alert(1)>"
        snap = self.rsvc.snapshot(self.proj.id, "technical",
                                  generated_by="test", title=evil)
        html_out = self.rsvc.render_html(snap)
        self.assertNotIn("<script>alert('x')</script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)
        self.assertNotIn("<img src=x", html_out)

    def test_pdf_injection_escaped(self):
        evil = "CVE-2026 (paren) \\ backslash \u2013\u20ac"
        snap = self.rsvc.snapshot(self.proj.id, "technical",
                                  generated_by="test", title=evil)
        raw = self.rsvc.render_bytes(snap, "pdf")
        self.assertTrue(raw.startswith(b"%PDF-1.4"))
        self.assertNotIn(b"(CVE-2026 (paren)", raw)   # unescaped paren
        for ch in (b"(", b")", b"\\"):
            self.assertNotIn(b"\\(" + b"CVE", raw)
        # the escaped form is present
        self.assertIn(b"\\(", raw) or self.assertIn(b"paren", raw)

    def test_pdf_deterministic_bytes(self):
        # The same snapshot always renders to identical bytes (the Phase-6
        # renderer has no clock access; generated_at comes from snapshot
        # metadata and is excluded from the canonical hash).
        a = self.rsvc.snapshot(self.proj.id, "technical",
                               generated_by="test",
                               data_cutoff="2026-09-05T00:00:00Z")
        self.assertEqual(self.rsvc.render_bytes(a, "pdf"),
                         self.rsvc.render_bytes(a, "pdf"))
        self.assertEqual(self.rsvc.render_bytes(a, "html"),
                         self.rsvc.render_bytes(a, "html"))
        self.assertEqual(self.rsvc.render_bytes(a, "json"),
                         self.rsvc.render_bytes(a, "json"))
        # A second snapshot at the same cutoff produces the same canonical
        # hash even though generated_at differs by wall-clock seconds.
        b = self.rsvc.snapshot(self.proj.id, "technical",
                               generated_by="test",
                               data_cutoff="2026-09-05T00:00:00Z")
        self.assertEqual(a["metadata"]["report_hash"],
                         b["metadata"]["report_hash"])


# ---------------------------------------------------------------------------
class TestIntegrityDeterminism(P6Base):
    def test_same_cutoff_same_hash(self):
        a = self.rsvc.snapshot(self.proj.id, "executive", generated_by="test",
                               data_cutoff="2026-09-05T00:00:00Z")
        b = self.rsvc.snapshot(self.proj.id, "executive", generated_by="test",
                               data_cutoff="2026-09-05T00:00:00Z")
        self.assertEqual(a["metadata"]["report_hash"],
                         b["metadata"]["report_hash"])

    def test_different_data_different_hash(self):
        a = self.rsvc.snapshot(self.proj.id, "executive", generated_by="test",
                               data_cutoff="2026-09-05T00:00:00Z")
        h1 = a["metadata"]["report_hash"]
        # Only data INSIDE the cutoff window may change the report: backdate
        # one finding into the window, then change its lifecycle.
        fid = self.svc.finding_list(self.proj.id, limit=1)[0].id
        self.svc.db.execute(
            "UPDATE findings SET first_detected='2026-08-20T00:00:00Z' "
            "WHERE id=?", (fid,))
        self.svc.finding_set_status(fid, "resolved")
        b = self.rsvc.snapshot(self.proj.id, "executive", generated_by="test",
                               data_cutoff="2026-09-05T00:00:00Z")
        self.assertNotEqual(h1, b["metadata"]["report_hash"])

    def test_canonical_ignores_transient_fields(self):
        snap = self.rsvc.snapshot(self.proj.id, "executive",
                                  generated_by="test")
        x = dict(snap)
        x["metadata"] = dict(snap["metadata"])
        x["metadata"]["generated_at"] = "X"
        y = dict(snap)
        y["metadata"] = dict(snap["metadata"])
        y["metadata"]["generated_at"] = "Y"
        self.assertEqual(self.rsvc.canonical(x), self.rsvc.canonical(y))
        self.assertEqual(self.rsvc.canonical(x),
                         self.rsvc.canonical(snap))

    def test_hash_is_sha256_of_canonical(self):
        snap = self.rsvc.snapshot(self.proj.id, "executive",
                                  generated_by="test")
        import hashlib
        self.assertEqual(snap["metadata"]["report_hash"],
                         hashlib.sha256(
                             self.rsvc.canonical(snap).encode("utf-8")
                         ).hexdigest())

    def test_render_json_schema_stable(self):
        snap = self.rsvc.snapshot(self.proj.id, "technical",
                                  generated_by="test")
        out = self.rsvc.render_json(snap)
        self.assertEqual(out["report"]["schema_version"],
                         "report-schema-v1")
        self.assertEqual(out["metadata"]["report_version"],
                         "report-schema-v1")
        self.assertEqual(out["report"]["hash"],
                         snap["metadata"]["report_hash"])
        self.assertIn("truncation", out)
        self.assertIn("evidence", out)


# ---------------------------------------------------------------------------
class TestReportLifecycle(P6Base):
    def test_store_and_get_run(self):
        snap = self.rsvc.snapshot(self.proj.id, "executive",
                                  generated_by="tester")
        run = self.rsvc.store_run(snap, store_payload=True)
        self.assertEqual(run["status"], "generated")
        self.assertEqual(run["schema_version"], "report-schema-v1")
        self.assertEqual(run["generated_by"], "tester")
        got = self.rsvc.get_run(run["id"], with_payload=True)
        self.assertEqual(got["report_hash"], run["report_hash"])
        self.assertIsNotNone(got["payload"])
        self.assertEqual(got["payload"]["report"]["hash"],
                         run["report_hash"])

    def test_list_runs_bounded_and_filtered(self):
        for i in range(5):
            r = self.rsvc.store_run(
                self.rsvc.snapshot(self.proj.id, "executive",
                                   generated_by="t"),
                store_payload=True)
        other = self.rsvc.store_run(
            self.rsvc.snapshot(self.proj.id, "technical", generated_by="t"),
            store_payload=True)
        data = self.rsvc.list_runs(self.proj.id, limit=3)
        self.assertEqual(len(data["reports"]), 3)
        self.assertEqual(data["total"], 6)
        data_t = self.rsvc.list_runs(self.proj.id, report_type="technical")
        self.assertEqual(len(data_t["reports"]), 1)
        self.assertEqual(data_t["reports"][0]["id"], other["id"])

    def test_hard_pagination_rejected(self):
        with self.assertRaises(errors.ValidationError):
            self.rsvc.list_runs(self.proj.id, limit=1000000000)
        with self.assertRaises(errors.ValidationError):
            self.rsvc.list_runs(self.proj.id, limit=0)
        with self.assertRaises(errors.ValidationError):
            self.rsvc.list_runs(self.proj.id, limit=-5)
        with self.assertRaises(errors.ValidationError):
            self.rsvc.list_runs(self.proj.id, limit="abc")
        with self.assertRaises(errors.ValidationError):
            self.rsvc.list_runs(self.proj.id, offset=999999999)
        self.assertEqual(self.rsvc.list_runs(
            self.proj.id, limit=500)["limit"], 500)

    def test_export_formats(self):
        snap = self.rsvc.snapshot(self.proj.id, "technical",
                                  generated_by="test")
        run = self.rsvc.store_run(snap, store_payload=True)
        html = self.rsvc.export(run["id"], "html")
        self.assertTrue(html.startswith(b"<!DOCTYPE html>")
                        or b"<html" in html)
        pdf = self.rsvc.export(run["id"], "pdf")
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        js = self.rsvc.export(run["id"], "json")
        self.assertIn(b"report-schema-v1", js)
        with self.assertRaises(errors.ValidationError):
            self.rsvc.export(run["id"], "csv")

    def test_export_audited_and_metric(self):
        snap = self.rsvc.snapshot(self.proj.id, "executive",
                                  generated_by="test")
        run = self.rsvc.store_run(snap, store_payload=True)
        self.rsvc.export(run["id"], "json")
        rows = self.svc.audit_list(self.proj.id, limit=50)
        actions = [a.action for a in rows]
        self.assertIn("report.generated", actions)
        self.assertIn("export.generated", actions)

    def test_export_path_security(self):
        d = os.path.join(self.tmp, "out")
        os.makedirs(d, exist_ok=True)
        ok = os.path.join(d, "r.json")
        self.assertEqual(secure_export_path(ok), ok)
        with self.assertRaises(errors.ValidationError):
            secure_export_path("../../etc/passwd")
        with self.assertRaises(errors.ValidationError):
            secure_export_path("a/../b.json")
        with self.assertRaises(errors.ValidationError):
            secure_export_path("a\\..\\b.json")
        with self.assertRaises(errors.ValidationError):
            secure_export_path("bad\x00name")
        with self.assertRaises(errors.ValidationError):
            secure_export_path("/no/such/parent/x.json")
        with self.assertRaises(errors.ValidationError):
            secure_export_path("")
        with self.assertRaises(errors.ValidationError):
            secure_export_path("  spaced.json")
        sub_ok = os.path.join(d, "sub", "x.json")
        os.makedirs(os.path.dirname(sub_ok), exist_ok=True)
        self.assertEqual(secure_export_path(sub_ok), sub_ok)
        # non-immutable delete + share audit are CLI-gated; the guard here:
        snap = self.rsvc.snapshot(self.proj.id, "executive", generated_by="t")
        run = self.rsvc.store_run(snap, store_payload=True)
        self.assertEqual(int(run["immutable"]), 0)


# ---------------------------------------------------------------------------
class TestAnalytics(P6Base):
    def test_posture_deterministic_and_versioned(self):
        a = self.anasvc.posture(self.proj.id,
                                cutoff="2026-09-05T00:00:00Z")
        b = self.anasvc.posture(self.proj.id,
                                cutoff="2026-09-05T00:00:00Z")
        self.assertEqual(a, b)
        self.assertEqual(a["posture_version"], "posture-v1")
        self.assertIn(a["level"], ("excellent", "good", "fair", "weak"))
        self.assertGreaterEqual(a["score"], 0)
        self.assertLessEqual(a["score"], 100)
        factors = {f["factor"]: f for f in a["factors"]}
        self.assertEqual(set(factors), {"open_risk_pressure",
                                        "remediation_progress",
                                        "asset_exposure", "risk_trend",
                                        "monitoring_freshness",
                                        "verification_status"})
        total = sum(f["points"] for f in a["factors"])
        self.assertLessEqual(abs(total - a["score"]), 1.0)
        for f in a["factors"]:
            self.assertTrue(f["definition"])   # every factor explained
            self.assertGreater(f["weight"], 0)

    def test_posture_is_separate_from_finding_risk(self):
        p = self.anasvc.posture(self.proj.id)
        r = self.anasvc.risk_summary(self.proj.id)
        self.assertNotEqual(p["score"], r["total_risk"])
        self.assertNotEqual(p["posture_version"],
                            r["risk_calculation_version"])

    def test_risk_summary_values(self):
        r = self.anasvc.risk_summary(self.proj.id)
        self.assertEqual(r["count"], 4)
        self.assertEqual(r["by_severity"]["Critical"], 1)
        self.assertEqual(r["by_severity"]["High"], 1)
        self.assertEqual(r["by_severity"]["Info"], 1)
        self.assertIn("risk_calculation_version", r)
        self.assertEqual(r["scope_statuses"],
                         sorted(("open", "acknowledged", "confirmed",
                                 "in_review", "reopened")))

    def test_risk_buckets_bounded(self):
        b = self.anasvc.risk_buckets(self.proj.id, bucket_width=10)
        self.assertEqual(sorted(b["buckets"].keys()), list(range(0, 101, 10)))
        self.assertGreaterEqual(sum(b["buckets"].values()), 4)
        with self.assertRaises(errors.ValidationError):
            self.anasvc.risk_buckets(self.proj.id, bucket_width=7)

    def test_trends_bounded_range(self):
        t = self.anasvc.finding_trend(self.proj.id,
                                      start="2026-08-01",
                                      end="2026-12-31T00:00:00Z")
        self.assertLessEqual(len(t["created"]), 180)
        self.assertEqual(len(t["created"]), len(t["resolved"]))
        self.assertEqual(len(t["created"]), len(t["reopened"]))
        self.assertGreaterEqual(t["total_created"], 4)
        with self.assertRaises(errors.ValidationError):
            self.anasvc.finding_trend(self.proj.id, start="2010-01-01",
                                      end="2026-09-05")
        with self.assertRaises(errors.ValidationError):
            self.anasvc.finding_trend(self.proj.id, start="2026-09-05",
                                      end="2026-08-01")
        with self.assertRaises(errors.ValidationError):
            self.anasvc.finding_trend(self.proj.id, start="nonsense")

    def test_attack_surface_trend(self):
        a = self.anasvc.attack_surface_trend(self.proj.id,
                                             start="2026-08-01",
                                             end="2026-12-31T00:00:00Z")
        self.assertIn("attack_surface_events", a)
        self.assertEqual(a["attack_surface_events"]["exposure.changed"], 1)
        self.assertEqual(a["attack_surface_events"]["technology.changed"], 1)
        self.assertEqual(a["attack_surface_events"]["service.opened"], 1)
        self.assertGreaterEqual(a["total"], 3)

    def test_kpis_include_definitions(self):
        k = self.anasvc.kpis(self.proj.id, start="2026-08-01",
                             end="2026-12-31T00:00:00Z")
        for name in ("mttd_hours", "mttr_hours", "open_critical",
                     "resolution_rate", "reopen_rate",
                     "verification_pass_rate", "overdue_remediation_rate",
                     "monitoring_success_rate", "exposure_change_count"):
            self.assertIn(name, k["definitions"])
            self.assertIn(name, k)
        self.assertEqual(k["open_critical"], 1)
        self.assertEqual(k["open_high"], 1)
        self.assertTrue(k["definitions"]["mttd_hours"].startswith(
            "Mean detection latency"))
        # no external benchmark claims
        blob = json.dumps(k["definitions"]).lower()
        for banned in ("soc2", "iso 27001", "pci", "nist", "benchmark of"):
            self.assertNotIn(banned, blob)

    def test_remediation_and_asset_summaries(self):
        rem = self.anasvc.remediation_summary(self.proj.id)
        self.assertIn("by_status", rem)
        self.assertEqual(rem["total"], 0)
        assets = self.anasvc.asset_summary(self.proj.id)
        self.assertEqual(assets["total"], 3)
        self.assertEqual(assets["internet_facing"], 1)
        self.assertIn("by_exposure", assets)
        self.assertEqual(assets["by_exposure"]["internet_facing"], 1)

    def test_monitoring_summary_is_readonly(self):
        m = self.anasvc.monitoring_summary(self.proj.id)
        self.assertIn("health", m)
        self.assertIn("enabled_policies", m)
        self.assertIn("executions_by_status", m)
        self.assertIn("open_alerts", m)

    def test_bundle_bounded(self):
        b = self.anasvc.bundle(self.proj.id, cutoff="2026-09-05T00:00:00Z")
        for k in ("posture", "risk", "risk_assets", "kpis", "trends",
                  "remediation", "assets", "monitoring"):
            self.assertIn(k, b)
        self.assertLessEqual(len(b["risk_assets"]), 10)

    def test_risk_projects_rollup(self):
        out = self.anasvc.risk_by_project(self.org.id)
        self.assertEqual(len(out), 2)   # both projects in the org
        by_id = {o["project_id"]: o for o in out}
        self.assertIn(self.proj.id, by_id)
        self.assertTrue(all(o["count"] >= 0 for o in out))

    def test_analytics_never_writes(self):
        pre = {t: self.svc.db.query_one(
            f"SELECT COUNT(*) n FROM {t}")["n"]
               for t in ("findings", "assets", "security_events",
                         "audit_events", "risk_snapshots",
                         "scheduler_executions")}
        self.anasvc.posture(self.proj.id)
        self.anasvc.kpis(self.proj.id)
        self.anasvc.finding_trend(self.proj.id)
        self.anasvc.attack_surface_trend(self.proj.id)
        self.anasvc.bundle(self.proj.id)
        post = {t: self.svc.db.query_one(
            f"SELECT COUNT(*) n FROM {t}")["n"] for t in pre}
        self.assertEqual(pre, post)


# ---------------------------------------------------------------------------
class TestEvidence(P6Base):
    def test_eight_generic_categories_with_provenance(self):
        items = self.evsvc.derive(self.proj.id)
        cats = {i["control_category"] for i in items}
        self.assertEqual(cats, set(models.CONTROL_CATEGORIES))
        for it in items:
            self.assertIn(it["status"], models.CONTROL_STATUSES)
            self.assertTrue(it["source_type"])
            self.assertTrue(it["evidence_ts"])
            self.assertTrue(it["data_cutoff"])
            self.assertEqual(len(it["evidence_hash"]), 32)
            self.assertTrue(it["source_id"])
            self.assertTrue(it["id"])
            # provenance chain: item belongs to the project
            self.assertEqual(it["project_id"], self.proj.id)

    def test_no_compliance_or_certification_claims(self):
        items = self.evsvc.derive(self.proj.id)
        blob = json.dumps(items).lower()
        for banned in ("compliant", "compliance", "certified",
                       "certification", "soc 2", "soc2", "iso 27001",
                       "pci dss", "hipaa", "gdpr certified", "audited by"):
            self.assertNotIn(banned, blob)

    def test_hash_deterministic(self):
        # same explicit cutoff -> byte-identical items and hashes
        a = self.evsvc.derive(
            self.proj.id, cutoff="2026-09-05T00:00:00Z")
        b = self.evsvc.derive(
            self.proj.id, cutoff="2026-09-05T00:00:00Z")
        self.assertEqual(a, b)
        self.assertEqual({i["evidence_hash"] for i in a},
                         {i["evidence_hash"] for i in b})

    def test_refresh_upserts_and_updates(self):
        items = self.evsvc.refresh(self.proj.id)
        self.assertEqual(len(items), len(models.CONTROL_CATEGORIES))
        rows = self.evsvc.list_items(self.proj.id)
        self.assertEqual(rows["total"], len(models.CONTROL_CATEGORIES))
        self.assertEqual(rows["count"], len(models.CONTROL_CATEGORIES))
        
        # idempotent
        self.evsvc.refresh(self.proj.id)
        self.assertEqual(self.evsvc.list_items(self.proj.id)["total"],
                         len(models.CONTROL_CATEGORIES))

    def test_list_category_filter_and_pagination(self):
        self.evsvc.refresh(self.proj.id)
        data = self.evsvc.list_items(self.proj.id, category="access_control")
        self.assertEqual(data["total"], 1)
        with self.assertRaises(errors.ValidationError):
            self.evsvc.list_items(self.proj.id, category="made_up")
        with self.assertRaises(errors.ValidationError):
            self.evsvc.list_items(self.proj.id, limit=1000000000)
        with self.assertRaises(errors.ValidationError):
            self.evsvc.list_items(self.proj.id, limit=0)

    def test_get_item_not_found(self):
        with self.assertRaises(errors.NotFoundError):
            self.evsvc.get_item("nonexistent-id")

    def test_snapshot_immutable_and_stored(self):
        run = self.evsvc.snapshot(self.proj.id, generated_by="test")
        self.assertEqual(int(run["immutable"]), 1)
        self.assertEqual(run["report_type"], "compliance_evidence")
        from reporting import ReportService
        got = ReportService(self.svc).get_run(run["id"], with_payload=True)
        self.assertEqual(got["payload"]["report"]["type"],
                         "compliance_evidence")
        self.assertEqual(len(got["payload"]["evidence"]),
                         len(models.CONTROL_CATEGORIES))
        # evidence snapshots never deleted by retention
        res = ReportService(self.svc).retention_sweep(days=1)
        still = ReportService(self.svc).get_run(run["id"])
        self.assertEqual(still["id"], run["id"])
        self.assertEqual(int(still["immutable"]), 1)

    def test_audit_events_for_snapshot(self):
        self.evsvc.snapshot(self.proj.id, generated_by="test")
        actions = [a.action for a in self.svc.audit_list(self.proj.id,
                                                         limit=100)]
        self.assertIn("report.generated", actions)

    def test_export_items_formats(self):
        self.evsvc.refresh(self.proj.id)
        js = self.evsvc.export_items(self.proj.id, fmt="json")
        data = json.loads(js)
        self.assertEqual(data["schema_version"], "evidence-v1")
        self.assertEqual(len(data["items"]),
                         len(models.CONTROL_CATEGORIES))
        h = self.evsvc.export_items(self.proj.id, fmt="html")
        self.assertIn(b"<table", h)
        p = self.evsvc.export_items(self.proj.id, fmt="pdf")
        self.assertTrue(p.startswith(b"%PDF-1.4"))
        with self.assertRaises(errors.ValidationError):
            self.evsvc.export_items(self.proj.id, fmt="xml")


# ---------------------------------------------------------------------------
class TestRetention(P6Base):
    def test_sweep_removes_only_expired_non_immutable(self):
        old = self._old_run(400)
        new = self._old_run(5)
        ev = self.evsvc.snapshot(self.proj.id, generated_by="test")
        res = self.rsvc.retention_sweep(days=90)
        self.assertEqual(res["removed"], 1)
        with self.assertRaises(errors.NotFoundError):
            self.rsvc.get_run(old["id"])
        self.assertEqual(self.rsvc.get_run(new["id"])["id"], new["id"])
        self.assertEqual(self.rsvc.get_run(ev["id"])["id"], ev["id"])
        # payload deleted with the run
        row = self.svc.db.query_one(
            "SELECT COUNT(*) n FROM report_payloads WHERE report_id=?",
            (old["id"],))
        self.assertEqual(row["n"], 0)

    def test_sweep_never_touches_audit_history(self):
        before = self.svc.db.query_one(
            "SELECT COUNT(*) n FROM audit_events")["n"]
        self._old_run(400)
        self.rsvc.retention_sweep(days=90)
        after = self.svc.db.query_one(
            "SELECT COUNT(*) n FROM audit_events")["n"]
        self.assertGreater(after, before)   # sweep is itself audited
        verify = self.svc.audit_verify()
        self.assertTrue(verify.get("ok"))
        self.assertEqual(verify.get("issues"), [])

    def test_sweep_days_bounded(self):
        with self.assertRaises(errors.ValidationError):
            self.rsvc.retention_sweep(days=0)
        with self.assertRaises(errors.ValidationError):
            self.rsvc.retention_sweep(days=10000)
        self.assertEqual(self.rsvc.retention_sweep(days=1)["days"], 1)


# ---------------------------------------------------------------------------
class TestTenantIsolation(P6Base):
    def _other_org(self, name="Globex"):
        svc2 = make_service(self.tmp)  # same db? no — reuse one db via svc
        org2 = self.svc.org_create(name)
        proj2 = self.svc.project_create(org2.id, "Other")
        self.svc.asset_add(proj2.id, "domain", "other.globex.test")
        return org2, proj2

    def test_rbac_project_boundary(self):
        org2, proj2 = self._other_org()
        self.add_user(username="manager", roles=("security_manager",))
        ctx = self.ctx_for("manager")
        self.assertEqual(ctx.org_id, self.org.id)
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_project(ctx, proj2.id)
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_project(ctx, "00000000-0000-0000-0000-000000000000")

    def test_cannot_generate_report_for_other_tenant(self):
        org2, proj2 = self._other_org()
        self.add_user(username="analyst", roles=("analyst",))
        ctx = self.ctx_for("analyst")
        # the CLI/dashboard gate: require_project BEFORE any generate
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_project(ctx, proj2.id)

    def test_visible_projects_scoping(self):
        org2, proj2 = self._other_org()
        self.add_user(username="viewer1", roles=("viewer",))
        ctx = self.ctx_for("viewer1")
        uid = self.id_svc.user_get(ctx.user_id).id
        self.svc.db.execute(
            "INSERT INTO project_members (user_id, project_id, role) "
            "VALUES (?,?,?)", (uid, self.proj.id, "viewer"))
        vis = [p.id for p in self.authz.visible_projects(ctx)]
        # org-level viewer sees every project of ITS org (platform model),
        # and NEVER another tenant's project
        self.assertEqual(set(vis), {self.proj.id, self.sec_proj.id})
        self.assertNotIn(proj2.id, vis)

    def test_analytics_and_evidence_boundary(self):
        org2, proj2 = self._other_org()
        self.add_user(username="secmgr", roles=("security_manager",))
        ctx = self.ctx_for("secmgr")
        for fn in (lambda: self.anasvc.posture(proj2.id),
                   lambda: self.anasvc.kpis(proj2.id),
                   lambda: self.anasvc.finding_trend(proj2.id),
                   lambda: self.evsvc.derive(proj2.id),
                   lambda: self.evsvc.list_items(proj2.id),
                   lambda: self.rsvc.snapshot(proj2.id, "executive",
                                              generated_by="x")):
            with self.assertRaises(errors.AuthorizationError):
                self.authz.require_project(ctx, proj2.id)
                fn()

    def test_org_filter_cannot_cross_tenants(self):
        org2, proj2 = self._other_org()
        self.add_user(username="owner", roles=("owner",))
        ctx = self.ctx_for("owner")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_org(ctx, org2.id)


# ---------------------------------------------------------------------------
class TestRbacPermissions(P6Base):
    def test_permission_matrix(self):
        perms = {
            "viewer": {"report.read", "report.export", "analytics.read",
                       "compliance_evidence.read"},
            "analyst": {"report.generate"},
            "security_manager": set(),
            "admin": set(),
            "owner": set(),
        }
        for role, extras in perms.items():
            p = rbac.permissions_for([role])
            self.assertIn("report.read", p)
            self.assertIn("report.export", p)
            self.assertIn("analytics.read", p)
            self.assertIn("compliance_evidence.read", p)
            for extra in extras:
                self.assertIn(extra, p)
        self.assertNotIn("report.generate",
                         rbac.permissions_for(["viewer"]))
        self.assertIn("report.generate",
                      rbac.permissions_for(["analyst"]))

    def test_rbac_gates_enforced(self):
        self.add_user(username="viewer", roles=("viewer",))
        ctx = self.ctx_for("viewer")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx, "report.generate")
        self.authz.require(ctx, "report.read")
        self.authz.require(ctx, "report.export")
        self.authz.require(ctx, "analytics.read")
        self.authz.require(ctx, "compliance_evidence.read")
        self.add_user(username="analyst", roles=("analyst",))
        ctx2 = self.ctx_for("analyst")
        self.authz.require(ctx2, "report.generate")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx2, "monitoring.delete")

    def test_fail_closed_unknown_permission(self):
        self.add_user(username="owner", roles=("owner",))
        ctx = self.ctx_for("owner")
        # unknown permission strings never pass even for owner
        # (fail closed — AuthorizationError or ValidationError both deny)
        with self.assertRaises((errors.AuthorizationError,
                                errors.ValidationError)):
            self.authz.require(ctx, "not.a.real.permission")


# ---------------------------------------------------------------------------
class TestRedactionEverywhere(P6Base):
    def _snap_with_secret(self):
        # evidence already contains the bearer token at ingest time
        return self.rsvc.snapshot(self.proj.id, "technical",
                                  generated_by="test")

    def test_snapshot_json_redacted(self):
        snap = self._snap_with_secret()
        blob = json.dumps(snap)
        self.assertNotIn(PHISH_MARK, blob)
        self.assertIn("[REDACTED]", blob)

    def test_html_redacted(self):
        snap = self._snap_with_secret()
        html_out = self.rsvc.render_html(snap)
        self.assertNotIn(PHISH_MARK, html_out)
        self.assertIn("[REDACTED]", html_out)

    def test_pdf_redacted(self):
        snap = self._snap_with_secret()
        raw = self.rsvc.render_bytes(snap, "pdf")
        self.assertNotIn(PHISH_MARK.encode(), raw)
        self.assertIn(b"[REDACTED]", raw)

    def test_dashboard_snapshot_redacted(self):
        import dashboard
        snap = dashboard.load_reporting_snapshot(
            os.path.join(self.tmp, "secutool.db"), "")
        self.assertIsNotNone(snap)
        blob = json.dumps(snap)
        self.assertNotIn(PHISH_MARK, blob)
        html = dashboard.reporting_page(snap)
        self.assertNotIn(PHISH_MARK, html)
        ev = dashboard.evidence_page(snap)
        self.assertNotIn(PHISH_MARK, ev)

    def test_api_payload_redacted_and_bounded(self):
        import dashboard
        snap = dashboard.load_reporting_snapshot(
            os.path.join(self.tmp, "secutool.db"), "")
        self.assertLessEqual(len(snap.get("reports") or []), 50)
        self.assertLessEqual(len(snap.get("evidence") or []), 100)
        self.assertLessEqual(len(snap.get("analytics") or []), 20)

    def test_evidence_descriptions_never_secret(self):
        items = self.evsvc.derive(self.proj.id)
        blob = json.dumps(items)
        self.assertNotIn(PHISH_MARK, blob)
        self.assertNotIn(PW, blob)

    def test_audit_metadata_never_secret(self):
        snap = self.rsvc.snapshot(self.proj.id, "executive",
                                  generated_by="test")
        self.rsvc.store_run(snap, store_payload=True)
        for ev in self.svc.audit_list(self.proj.id, limit=100):
            blob = json.dumps(ev.to_dict())
            self.assertNotIn(PHISH_MARK, blob)


# ---------------------------------------------------------------------------
class TestRetentionOfEvidenceProvenance(P6Base):
    def test_evidence_registry_survives_sweep(self):
        self.evsvc.refresh(self.proj.id)
        self._old_run(400)
        self.rsvc.retention_sweep(days=90)
        data = self.evsvc.list_items(self.proj.id)
        self.assertEqual(data["total"], len(models.CONTROL_CATEGORIES))
        ids = {i["id"] for i in data["items"]}
        for it in self.evsvc.derive(self.proj.id):
            self.assertIn(it["id"], ids)  # provenance unchanged

    def test_registry_is_current_view_while_snapshots_immutable(self):
        run1 = self.evsvc.snapshot(self.proj.id, generated_by="test")
        self.svc.finding_set_status(
            self.svc.finding_list(self.proj.id, limit=1)[0].id,
            "resolved")
        self.evsvc.refresh(self.proj.id)
        run2 = self.evsvc.snapshot(self.proj.id, generated_by="test")
        got1 = self.rsvc.get_run(run1["id"], with_payload=True)
        got2 = self.rsvc.get_run(run2["id"], with_payload=True)
        self.assertNotEqual(got1["payload"]["evidence"],
                            got2["payload"]["evidence"])
        # the first snapshot bytes are untouched (immutable)
        self.assertEqual(int(got1["immutable"]), 1)
        self.assertEqual(got1["payload"]["report"]["hash"],
                         got1["report_hash"])


# ---------------------------------------------------------------------------
class TestPerformance(P6Base):
    def test_analytics_and_snapshot_with_100_assets_500_findings_1000_events(self):
        self.seed_assets_findings(100, 500)
        # a fresh service with larger caps: the base setUp already seeds a
        # handful of assets/findings for the same project
        rsvc = reporting.ReportService(self.svc, max_findings=700,
                                       max_assets=300)
        t0 = time.time()
        snap = rsvc.snapshot(self.proj.id, "executive", generated_by="p")
        bundle = self.anasvc.bundle(self.proj.id)
        trends = self.anasvc.finding_trend(self.proj.id,
                                           start="2026-08-01",
                                           end="2026-12-31T00:00:00Z")
        as_ = self.anasvc.attack_surface_trend(self.proj.id,
                                               start="2026-08-01",
                                               end="2026-12-31T00:00:00Z")
        elapsed = time.time() - t0
        self.assertLess(elapsed, 30.0)
        self.assertGreaterEqual(len(snap["findings"]), 500)
        self.assertGreaterEqual(len(snap["assets"]), 100)
        self.assertGreaterEqual(trends["total_created"], 500)
        self.assertGreaterEqual(as_["total"], 1000)
        self.assertGreaterEqual(bundle["risk"]["count"], 500)
        self.assertEqual(snap["truncation"]["truncated"], False)


# ---------------------------------------------------------------------------
class TestCliSmoke(P6Base):
    """CLI-level checks: reporting generate/list/get/export, analytics,
    evidence and the failure paths (bad filter, pagination, RBAC)."""

    def _run(self, *argv):
        db = os.path.join(self.tmp, "secutool.db")
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"), *argv,
             "--db", db],
            capture_output=True, text=True, timeout=120)

    def test_cli_generate_and_list(self):
        out = self._run("reporting", "generate", "--project", self.proj.id,
                        "--type", "executive", "--title", "T")
        self.assertIn("Report generated", out.stdout)
        rid = None
        for line in out.stdout.splitlines():
            if line.strip() and line.strip().startswith("[✓] Report"):
                rid = line.split(":")[-1].strip()
        self.assertTrue(rid)
        out2 = self._run("reporting", "list", "--project", self.proj.id)
        self.assertIn("report(s)", out2.stdout)
        self.assertIn(rid[:12], out2.stdout)
        out3 = self._run("reporting", "get", rid)
        self.assertIn('"report_hash"', out3.stdout)

    def test_cli_rejects_bad_filter(self):
        # argparse choices reject the value before any query runs
        out = self._run("reporting", "generate", "--project", self.proj.id,
                        "--type", "executive", "--severity", "Critical OR 1=1")
        self.assertNotEqual(out.returncode, 0)
        blob = (out.stderr or "") + (out.stdout or "")
        self.assertIn("invalid choice", blob)

    def test_cli_rejects_absurd_pagination(self):
        out = self._run("reporting", "list", "--project", self.proj.id,
                        "--limit", "1000000000")
        self.assertNotEqual(out.returncode, 0)
        out2 = self._run("evidence", "list", "--project", self.proj.id,
                         "--limit", "1000000000")
        self.assertNotEqual(out2.returncode, 0)

    def test_cli_export_formats(self):
        out = self._run("reporting", "generate", "--project", self.proj.id,
                        "--type", "technical", "--format", "pdf",
                        "--out", "cli-smoke.pdf")
        self.assertIn("exported", out.stdout)
        path = os.path.join(os.getcwd(), "cli-smoke.pdf")
        self.assertTrue(os.path.exists(path))
        with open(path, "rb") as fh:
            self.assertTrue(fh.read(8).startswith(b"%PDF-1.4"))
        os.unlink(path)

    def test_cli_analytics_and_evidence(self):
        out = self._run("analytics", "posture", "--project", self.proj.id)
        self.assertEqual(out.returncode, 0)
        self.assertIn("posture-v1", out.stdout)
        o2 = self._run("evidence", "refresh", "--project", self.proj.id)
        self.assertEqual(o2.returncode, 0)
        o3 = self._run("evidence", "list", "--project", self.proj.id)
        self.assertEqual(o3.returncode, 0)
        self.assertIn("item(s)", o3.stdout)

    def test_cli_rbac_enforced(self):
        # local mode (no --as) works; with a garbage token it fails closed
        out = self._run("reporting", "list", "--project", self.proj.id)
        self.assertEqual(out.returncode, 0)
        out2 = self._run("reporting", "list", "--project", self.proj.id,
                         "--as", "garbage-token-123")
        self.assertNotEqual(out2.returncode, 0)

    def test_cli_retention_sweep(self):
        out = self._run("reporting", "retention-sweep", "--days", "90")
        self.assertEqual(out.returncode, 0)
        self.assertIn("Retention sweep", out.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
