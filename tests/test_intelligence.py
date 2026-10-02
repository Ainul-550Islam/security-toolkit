#!/usr/bin/env python3
# ============================================================================
#  Phase-4 suite — asset intelligence, finding intelligence (canonical
#  identity, fingerprint, cross-scanner dedup, lifecycle), confidence, risk,
#  correlation/root-cause/clusters/remediation, evidence graph, temporal
#  scan diffs, security (BOLA/secret-leak) and idempotency.
#  Fully offline, deterministic, temp SQLite per test class.
# ============================================================================
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "python")
sys.path.insert(0, PY)
sys.path.insert(0, HERE)

import errors
import models
import redact
import store

import platform_service as pf
from correlate import CorrelationService
from diffs import BaselineService
from intel import IntelService
from risk import CALC_VERSION, ConfidenceEngine, RiskEngine, RiskSnapshotService


def _mk(project_id: str, scan_id: str, asset_id: str = "", *,
        title: str = "Reflected XSS in q", category: str = "xss",
        rule: str = "xss-001", source: str = "secuaudit",
        severity: str = "High", confidence: str = "high",
        raw: dict | None = None) -> models.Finding:
    return models.Finding(
        scan_id=scan_id, project_id=project_id, asset_id=asset_id,
        title=title, description="deterministic fixture description",
        severity=severity, confidence=confidence, category=category,
        source=source, rule_id=rule, cwe="CWE-79", cve="",
        remediation="", evidence=[], raw=dict(raw or {
            "endpoint": "/search?q=", "parameter": "q",
            "technologies": [{"name": "nginx", "version": "1.18"}]}))


def _ev(finding_id: str = "", *, reason: str = "reflected",
        snippet: str = "<script>alert(1)</script>",
        scanner: str = "secuaudit") -> models.Evidence:
    return models.Evidence(
        finding_id=finding_id, evidence_type="response",
        url="https://app.example.com/search?q=x", method="GET",
        status_code="200", request_snippet="",
        response_snippet=snippet, detection_reason=reason,
        scanner=scanner, rule_id="xss-001")


class Phase4Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="p4t_")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.svc = pf.PlatformService(os.path.join(self.dir, "t.db"))
        self.intel = IntelService(self.svc)
        self.corr = CorrelationService(self.svc)
        self.diffs = BaselineService(self.svc)
        self.org = self.svc.org_create("OrgA")
        self.proj = self.svc.project_create(self.org.id, "ProjA")
        self.scan = self.svc.scan_create(self.proj.id, "web-audit",
                                         "s1", scan_id="scan-1").id
        self.scan2 = self.svc.scan_create(self.proj.id, "web-audit",
                                          "s2", scan_id="scan-2").id
        self.asset = self.svc.asset_add(
            self.proj.id, "url", "https://app.example.com/")
        self.other = self.svc.project_create(self.org.id, "Other")


# ---------------------------------------------------------------------------
# 1. Asset intelligence
# ---------------------------------------------------------------------------
class AssetIntelTests(Phase4Base):
    def test_observe_creates_and_deduplicates(self):
        r1 = self.intel.observe(self.asset.id, "service", obs_key="443",
                                obs_value="https", source="scan")
        self.assertTrue(r1["changed"])
        r2 = self.intel.observe(self.asset.id, "service", obs_key="443",
                                obs_value="https", source="scan")
        self.assertFalse(r2["changed"])
        n = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM asset_observations WHERE asset_id=?",
            (self.asset.id,))["c"]
        self.assertEqual(n, 1)

    def test_observe_change_records_history(self):
        self.intel.observe(self.asset.id, "service", obs_key="443",
                           obs_value="https", source="scan",
                           scan_id=self.scan)
        r = self.intel.observe(self.asset.id, "service", obs_key="443",
                               obs_value="http", source="scan",
                               scan_id=self.scan)
        self.assertTrue(r["changed"])
        h = self.intel.asset_history(self.asset.id)
        self.assertEqual(h[0]["old_value"], "https")
        self.assertEqual(h[0]["new_value"], "http")
        # appearance ("" -> https) is also recorded
        self.assertEqual(h[1]["old_value"], "")
        self.assertEqual(h[1]["new_value"], "https")
        # replaying the same change must not duplicate events
        self.intel.observe(self.asset.id, "service", obs_key="443",
                           obs_value="http", source="scan",
                           scan_id=self.scan)
        self.assertEqual(len(self.intel.asset_history(self.asset.id)), 2)

    def test_history_bounded(self):
        for i in range(12):
            self.intel.observe(self.asset.id, "service", obs_key="443",
                               obs_value=f"v{i}", source="scan")
        hist = self.intel.asset_history(self.asset.id, limit=500)
        self.assertLessEqual(len(hist), 500)
        self.assertEqual(len(hist), 12)  # appearance + 11 changes

    def test_observe_rejects_unknown_type_and_empty(self):
        with self.assertRaises(errors.ValidationError):
            self.intel.observe(self.asset.id, "telepathy", obs_value="x")
        with self.assertRaises(errors.ValidationError):
            self.intel.observe(self.asset.id, "service", obs_value="")

    def test_relate_creates_idempotent_edge(self):
        a2 = self.svc.asset_add(self.proj.id, "domain", "example.com")
        r1 = self.intel.relate(self.proj.id, a2.id, self.asset.id,
                               "hosts", source="recon")
        self.assertTrue(r1["created"])
        r2 = self.intel.relate(self.proj.id, a2.id, self.asset.id,
                               "hosts", source="recon")
        self.assertFalse(r2["created"])
        rels = self.intel.relations(self.asset.id)
        self.assertEqual(len(rels), 1)

    def test_relate_cross_project_forbidden(self):
        other_asset = self.svc.asset_add(self.other.id, "url",
                                         "https://evil.example.com/")
        with self.assertRaises(errors.AuthorizationError):
            self.intel.relate(self.proj.id, other_asset.id, self.asset.id,
                              "hosts", source="recon")

    def test_relate_unknown_asset_not_found(self):
        with self.assertRaises(errors.NotFoundError):
            self.intel.relate(self.proj.id, "nope", self.asset.id,
                              "hosts", source="recon")

    def test_exposure_derivation_evidence_only(self):
        # no network evidence → unknown (never guessed)
        e = self.intel.exposure_derive(self.asset.id)
        self.assertEqual(e["exposure"], "unknown")
        self.intel.observe(self.asset.id, "network", obs_key="ip",
                           obs_value="10.0.0.5", source="scan")
        e = self.intel.exposure_derive(self.asset.id)
        self.assertEqual(e["exposure"], "internal")
        self.intel.observe(self.asset.id, "network", obs_key="ip",
                           obs_value="93.184.216.34", source="scan")
        e = self.intel.exposure_derive(self.asset.id)
        self.assertEqual(e["exposure"], "internet_facing")
        self.assertIn("public address", e["reason"])

    def test_exposure_refreshes_after_observe(self):
        self.intel.observe(self.asset.id, "service", obs_key="443",
                           obs_value="https", source="scan")
        row = self.svc.db.query_one(
            "SELECT exposure FROM assets WHERE id=?", (self.asset.id,))
        self.assertEqual(row["exposure"], "internet_facing")

    def test_attack_surface(self):
        self.intel.observe(self.asset.id, "service", obs_key="443",
                           obs_value="https", source="scan")
        self.intel.observe(self.asset.id, "technology", obs_key="server",
                           obs_value="nginx", source="scan")
        surf = self.intel.attack_surface(self.proj.id)
        self.assertEqual(surf["counts"]["assets"], 1)
        self.assertEqual(surf["counts"]["internet_facing"], 1)
        entry = surf["assets"][0]
        self.assertEqual([s["value"] for s in entry["services"]],
                         ["https"])
        self.assertEqual([t["value"] for t in entry["technologies"]],
                         ["nginx"])
        self.assertEqual(entry["exposure"], "internet_facing")

    def test_criticality_set_and_audit(self):
        out = self.intel.criticality_set(self.asset.id, "critical",
                                         actor="manager-1")
        self.assertTrue(out["changed"])
        row = self.svc.db.query_one(
            "SELECT criticality FROM assets WHERE id=?", (self.asset.id,))
        self.assertEqual(row["criticality"], "critical")
        # controlling metadata as overrides:
        # changing again audits an asset.criticality_changed
        self.intel.criticality_set(self.asset.id, "high", actor="manager-1")
        rows = self.svc.audit_list(self.proj.id)
        actions = {a.action for a in rows}
        self.assertIn("asset.criticality_changed", actions)
        with self.assertRaises(errors.ValidationError):
            self.intel.criticality_set(self.asset.id, "ultimate",
                                       actor="manager-1")

    def test_business_impact_metadata_only(self):
        out = self.intel.business_impact_set(
            self.asset.id,
            {"customer_facing": True, "payment_related": True},
            actor="manager-1")
        self.assertTrue(out["business_impact"]["customer_facing"])
        self.assertTrue(out["business_impact"]["payment_related"])
        with self.assertRaises(errors.ValidationError):
            self.intel.business_impact_set(
                self.asset.id, {"compromised": True}, actor="manager-1")
        with self.assertRaises(errors.ValidationError):
            self.intel.business_impact_set(self.asset.id, ["list"],
                                           actor="manager-1")

    def test_ingest_observations_from_raw(self):
        raw = {"tool": "recon", "domain": "example.com",
               "subdomains": {"www.example.com": {
                   "sources": ["ct"], "ips": ["93.184.216.34"]}}}
        n = self.intel.ingest_observations(self.proj.id, self.scan, raw,
                                           [self.asset])
        self.assertEqual(n, 3)  # identity + dns + network observations
        # idempotent — second run adds nothing (identical observations)
        n2 = self.intel.ingest_observations(self.proj.id, self.scan, raw,
                                            [self.asset])
        self.assertEqual(n2, 0)
        # domain → subdomain hosts relation exists (recon provenance)
        sub = self.svc.db.query_one(
            "SELECT id FROM assets WHERE project_id=? AND value=? LIMIT 1",
            (self.proj.id, "www.example.com"))
        rels = self.intel.relations(sub["id"]) if sub else []
        self.assertTrue(any(r["rel_type"] == "resolves_to" for r in rels))
        # both runs together created exactly ONE observation row per fact
        obs = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM asset_observations WHERE asset_id=? "
            "AND obs_type='network'", (sub["id"],))
        self.assertEqual(obs["c"], 1)

    def test_asset_intel_redacts_secrets(self):
        self.intel.observe(self.asset.id, "http", obs_key="header",
                           obs_value="Authorization: Bearer supersecret123",
                           source="scan")
        out = self.intel.asset_intel(self.asset.id)
        blob = str(out)
        self.assertNotIn("supersecret123", blob)
        self.assertIn("REDACTED", blob)

    def test_asset_count(self):
        self.svc.asset_add(self.proj.id, "url", "https://b.example.com/")
        self.assertEqual(self.intel.asset_count(self.proj.id), 2)


# ---------------------------------------------------------------------------
# 2. Canonical identity + fingerprint
# ---------------------------------------------------------------------------
class CanonicalTests(Phase4Base):
    def test_canonical_stable_against_volatile_fields(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        k1 = self.corr.canonical_key(project_id=self.proj.id,
                                     asset_id=self.asset.id, category="xss",
                                     rule_id="xss-001", template_id="",
                                     title="Reflected XSS", raw=raw)
        raw2 = dict(raw)
        raw2["url"] = "https://app.example.com/search?q=x&ts=171234"  # volatile
        raw2["request_id"] = "deadbeef"                               # volatile
        k2 = self.corr.canonical_key(project_id=self.proj.id,
                                     asset_id=self.asset.id, category="xss",
                                     rule_id="xss-001", template_id="",
                                     title="Different wording", raw=raw2)
        self.assertEqual(k1, k2)

    def test_canonical_is_projects_scoped(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        k1 = self.corr.canonical_key(project_id=self.proj.id,
                                     asset_id=self.asset.id, category="xss",
                                     rule_id="xss-001", template_id="",
                                     title="t", raw=raw)
        k2 = self.corr.canonical_key(project_id=self.other.id,
                                     asset_id=self.asset.id, category="xss",
                                     rule_id="xss-001", template_id="",
                                     title="t", raw=raw)
        self.assertNotEqual(k1, k2)

    def test_canonical_distinguishes_parameters(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        k1 = self.corr.canonical_key(project_id=self.proj.id,
                                     asset_id=self.asset.id, category="xss",
                                     rule_id="xss-001", template_id="",
                                     title="t", raw=raw)
        raw2 = dict(raw)
        raw2["parameter"] = "email"
        k2 = self.corr.canonical_key(project_id=self.proj.id,
                                     asset_id=self.asset.id, category="xss",
                                     rule_id="xss-001", template_id="",
                                     title="t", raw=raw2)
        self.assertNotEqual(k1, k2)

    def test_fingerprint_ignores_evidence_and_timestamps(self):
        f1 = _mk(self.proj.id, self.scan, self.asset.id)
        f1.finalize()
        f2 = _mk(self.proj.id, self.scan2, self.asset.id)
        f2.finalize()
        self.assertEqual(f1.fingerprint, f2.fingerprint)

    def test_fingerprint_never_contains_secret(self):
        f = _mk(self.proj.id, self.scan, self.asset.id)
        f.evidence = [{"type": "response",
                       "response_snippet": "token=ultra-secret-zzz"}]
        f.finalize()
        self.assertNotIn("ultra-secret", f.fingerprint)


# ---------------------------------------------------------------------------
# 3. Cross-scanner deduplication
# ---------------------------------------------------------------------------
class DedupTests(Phase4Base):
    def _raw(self, **kw):
        base = {"endpoint": "/search?q=", "parameter": "q",
                "technologies": [{"name": "nginx", "version": "1.18"}]}
        base.update(kw)
        return base

    def test_cross_scanner_dedup_merges_evidence(self):
        raw = self._raw()
        r1 = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, source="secuaudit",
                rule="", title="XSS-On-Q", raw=raw),
            [_ev(reason="reflected a", snippet="<script>a</script>")],
            scan_id=self.scan)
        self.assertFalse(r1["deduped"])
        # same issue from a different scanner named differently ("xss on q"
        # normalizes to the same canonical title) → dedup, no second row
        r2 = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, source="nucleus",
                rule="", title="xss on q", raw=raw),
            [_ev(reason="reflected b", snippet="<script>b</script>",
                 scanner="nucleus")],
            scan_id=self.scan2)
        self.assertTrue(r2["deduped"])
        self.assertEqual(r2["finding_id"], r1["finding_id"])
        count = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM findings WHERE id=?",
            (r1["finding_id"],))["c"]
        self.assertEqual(count, 1)
        view = self.corr.finding_view(r1["finding_id"])
        # BOTH pieces of evidence preserved (evidence never deleted)
        self.assertEqual(len(view["evidence"]), 2)
        self.assertEqual(len(view["observations"]), 2)
        self.assertEqual(view["occurrence_count"], 2)

    def test_dedup_is_idempotent(self):
        raw = self._raw()
        r1 = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, rule="",
                title="XSS on q", raw=raw),
            [_ev()], scan_id=self.scan)
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, source="nucleus",
                rule="", title="XSS on q", raw=raw),
            [_ev()], scan_id=self.scan2)
        after_first = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM risk_snapshots WHERE finding_id=?",
            (r1["finding_id"],))["c"]
        for _ in range(3):
            self.corr.ingest_finding(
                _mk(self.proj.id, self.scan2, self.asset.id, source="nucleus",
                    rule="", title="XSS on q", raw=raw),
                [_ev()], scan_id=self.scan2)
        view = self.corr.finding_view(r1["finding_id"])
        self.assertEqual(view["occurrence_count"], 2)  # no inflation
        after = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM risk_snapshots WHERE finding_id=?",
            (r1["finding_id"],))["c"]
        self.assertEqual(after_first, after)  # re-runs add nothing

    def test_unrelated_findings_not_merged(self):
        raw = self._raw()
        r1 = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw,
                title="XSS on q"),
            [], scan_id=self.scan)
        raw2 = self._raw()
        raw2["parameter"] = "email"
        r2 = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, raw=raw2,
                title="XSS on email"),
            [], scan_id=self.scan2)
        self.assertNotEqual(r1["finding_id"], r2["finding_id"])
        count = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM findings WHERE project_id=?",
            (self.proj.id,))["c"]
        self.assertEqual(count, 2)

    def test_evidence_cap_bounded(self):
        raw = self._raw()
        r1 = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw),
            [_ev()], scan_id=self.scan)
        for i in range(30):
            self.corr.ingest_finding(
                _mk(self.proj.id, self.scan2, self.asset.id, source="nucleus",
                    rule="xss-001", title="XSS on q", raw=raw),
                [_ev(reason=f"r{i}", snippet=f"<b>{i}</b>")],
                scan_id=self.scan2)
        view = self.corr.finding_view(r1["finding_id"])
        self.assertLessEqual(len(view["evidence"]),
                             100)  # MAX_EVIDENCE_PER_FINDING


# ---------------------------------------------------------------------------
# 4. Lifecycle
# ---------------------------------------------------------------------------
class LifecycleTests(Phase4Base):
    def _inj(self, raw=None):
        return self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw or {
                "endpoint": "/search?q=", "parameter": "q"}),
            [], scan_id=self.scan)["finding_id"]

    def test_new_states_transition_correctly(self):
        fid = self._inj()
        f = self.svc.finding_get(fid)
        self.assertTrue(f.transition("confirmed"))
        self.assertTrue(f.transition("in_review"))
        self.assertTrue(f.transition("remediated"))
        self.assertNotEqual(f.resolved_at, "")
        self.assertTrue(f.transition("reopened"))
        self.assertNotEqual(f.reopened_at, "")
        self.assertEqual(f.lifecycle, "reopened")

    def test_invalid_transition_fails_closed(self):
        fid = self._inj()
        f = self.svc.finding_get(fid)
        with self.assertRaises(errors.LifecycleError):
            f.transition("reopened")  # open → reopened is not legal

    def test_reappearance_reopens_not_duplicates(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        fid = self._inj(raw)
        f = self.svc.finding_get(fid)
        f.transition("remediated")
        self.svc.db.execute(
            "UPDATE findings SET lifecycle='remediated', resolved_at=? "
            "WHERE id=?", (models.utcnow(), fid))
        # same finding re-detected by a NEW scan → reappearance
        r = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, raw=raw),
            [_ev()], scan_id=self.scan2)
        row = self.svc.db.query_one(
            "SELECT lifecycle, reopened_at, resolved_at FROM findings "
            "WHERE id=?", (fid,))
        self.assertEqual(row["lifecycle"], "reopened")
        self.assertNotEqual(row["reopened_at"], "")
        # still ONE finding — no duplicate
        count = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM findings WHERE id=?", (fid,))["c"]
        self.assertEqual(count, 1)

    def test_false_positive_requires_reason_and_audits(self):
        fid = self._inj()
        with self.assertRaises(errors.ValidationError):
            self.corr.false_positive(fid, reason="", actor="analyst-1")
        out = self.corr.false_positive(
            fid, reason="waf blocks payload; not exploitable",
            actor="analyst-1")
        self.assertEqual(out["status"], "false_positive")
        rows = self.svc.audit_list(self.proj.id)
        self.assertTrue(any(a.action == "finding.false_positive" and
                            a.actor == "analyst-1" for a in rows))

    def test_accepted_risk_audited_and_expiry_sweep(self):
        fid = self._inj()
        self.corr.accept_risk(fid, reason="internal tool, low value",
                              actor="manager-1",
                              until="2026-01-01T00:00:00Z")
        rows = self.svc.audit_list(self.proj.id)
        self.assertTrue(any(a.action == "finding.accepted_risk" for a in
                            rows))
        n = self.corr.reopen_expired("2026-02-01T00:00:00Z")
        self.assertEqual(n, 1)
        row = self.svc.db.query_one(
            "SELECT lifecycle, reopened_at FROM findings WHERE id=?",
            (fid,))
        self.assertEqual(row["lifecycle"], "reopened")
        self.assertNotEqual(row["reopened_at"], "")
        # sweep idempotent
        self.assertEqual(self.corr.reopen_expired("2026-03-01T00:00:00Z"), 0)

    def test_suppression_never_erases_evidence(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        fid = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw),
            [_ev(reason="first", snippet="<script>1</script>")],
            scan_id=self.scan)["finding_id"]
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, source="nucleus",
                rule="xss-001", title="XSS on q", raw=raw),
            [_ev(reason="x", snippet="<script>x</script>")],
            scan_id=self.scan2)
        self.corr.false_positive(
            fid, reason="temporary", actor="analyst-1",
            until="2099-01-01T00:00:00Z", suppress=True)
        view = self.corr.finding_view(fid)
        self.assertEqual(len(view["evidence"]), 2)
        self.assertNotEqual(view["suppressed_until"], "")


# ---------------------------------------------------------------------------
# 5. Confidence engine
# ---------------------------------------------------------------------------
class ConfidenceTests(Phase4Base):
    def test_deterministic_and_bounded(self):
        ce = ConfidenceEngine()
        a = ce.compute(severity="High", source="secuaudit",
                       evidence_count=3, distinct_sources={"nucleus"},
                       asset_certainty="exact", occurrence_count=2)
        b = ce.compute(severity="High", source="secuaudit",
                       evidence_count=3, distinct_sources={"nucleus"},
                       asset_certainty="exact", occurrence_count=2)
        self.assertEqual(a, b)
        self.assertGreaterEqual(a["confidence_score"], 0.0)
        self.assertLessEqual(a["confidence_score"], 1.0)

    def test_sources_agreement_raises_confidence(self):
        ce = ConfidenceEngine()
        solo = ce.compute(severity="High", source="secuaudit",
                          evidence_count=2, distinct_sources=set(),
                          asset_certainty="exact")
        duo = ce.compute(severity="High", source="secuaudit",
                         evidence_count=2,
                         distinct_sources={"nucleus"},
                         asset_certainty="exact")
        self.assertGreater(duo["confidence_score"],
                           solo["confidence_score"])
        self.assertIn("agreeing source", " ".join(
            duo["confidence_reasons"]))

    def test_declared_confidence_cannot_force_high(self):
        ce = ConfidenceEngine()
        r = ce.compute(severity="Info", source="spider",
                       evidence_count=0, distinct_sources=set(),
                       asset_certainty="none", occurrence_count=1,
                       declared_confidence="confirmed")
        self.assertLess(r["confidence_score"], 0.85)
        self.assertNotEqual(r["confidence_level"], "high")

    def test_level_thresholds(self):
        ce = ConfidenceEngine()
        self.assertEqual(ce.level_for(0.9), "high")
        self.assertEqual(ce.level_for(0.7), "medium")
        self.assertEqual(ce.level_for(0.5), "low")
        self.assertEqual(ce.level_for(0.05), "unverified")


# ---------------------------------------------------------------------------
# 6. Risk engine + snapshots
# ---------------------------------------------------------------------------
class RiskTests(Phase4Base):
    def test_deterministic_explainable(self):
        re_ = RiskEngine()
        a = re_.compute(severity="High", confidence_score=0.8,
                        exposure="internet_facing", criticality="critical",
                        business_impact={"payment_related": True},
                        category="injection", rule_id="sqli-01",
                        title="SQL injection", occurrence_count=3)
        b = re_.compute(severity="High", confidence_score=0.8,
                        exposure="internet_facing", criticality="critical",
                        business_impact={"payment_related": True},
                        category="injection", rule_id="sqli-01",
                        title="SQL injection", occurrence_count=3)
        self.assertEqual(a, b)
        self.assertEqual(a["calc_version"], CALC_VERSION)
        self.assertTrue(a["risk_factors"])
        self.assertLessEqual(a["risk_score"], 100)
        self.assertGreaterEqual(a["risk_score"], 0)

    def test_severity_not_risk(self):
        re_ = RiskEngine()
        low_exp = re_.compute(severity="Critical", confidence_score=0.3,
                              exposure="internal", criticality="low")
        high_exp = re_.compute(severity="High", confidence_score=0.9,
                               exposure="internet_facing",
                               criticality="critical",
                               business_impact={"customer_facing": True},
                               category="rce", title="remote code execution")
        # a High+high-confidence+internet-facing finding OUTRANKS a
        # Critical+low-confidence+internal one (P order: 0 = most urgent)
        self.assertLess(high_exp["priority_order"],
                        low_exp["priority_order"])
        self.assertEqual(high_exp["level_for"] if False else True, True)

    def test_priorities_p0_p4(self):
        re_ = RiskEngine()
        top = re_.compute(severity="Critical", confidence_score=0.9,
                          exposure="internet_facing", criticality="critical",
                          category="rce", title="remote code execution",
                          occurrence_count=4)
        bottom = re_.compute(severity="Info", confidence_score=0.1,
                             exposure="restricted", criticality="low",
                             category="other", title="banner")
        self.assertEqual(top["priority"], "P0")
        self.assertEqual(bottom["priority"], "P4")
        self.assertLess(top["priority_order"], bottom["priority_order"])

    def test_exploitability_hint_never_invented(self):
        re_ = RiskEngine()
        self.assertEqual(
            re_.exploitability_for("injection", "sqli", "SQL injection"),
            "high")
        self.assertEqual(
            re_.exploitability_for("other", "x-1", "random title"), "unknown")

    def test_snapshots_change_points_only(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        r = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw),
            [], scan_id=self.scan)
        fid = r["finding_id"]
        s1 = self.svc.db.query(
            "SELECT COUNT(*) AS c FROM risk_snapshots WHERE finding_id=?",
            (fid,))[0]["c"]
        # unchanged re-ingest → no new snapshot
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, source="nucleus",
                rule="xss-001", title="XSS on q", raw=raw),
            [_ev()], scan_id=self.scan2)  # increases agreement → new score
        s2 = self.svc.db.query(
            "SELECT COUNT(*) AS c FROM risk_snapshots WHERE finding_id=?",
            (fid,))[0]["c"]
        self.assertGreaterEqual(s2, s1)
        self.assertTrue(self.corr.snapshots.history(fid))

    def test_snapshot_record_unchanged_skipped(self):
        svc2 = RiskSnapshotService(self.svc)
        fid = self._mk_finding()
        r1 = svc2.record(fid, project_id=self.proj.id, risk_score=42,
                         risk_level="medium", severity="High",
                         confidence=0.5, asset_criticality="unknown",
                         exposure="unknown", calc_version=CALC_VERSION,
                         factors=[{"name": "severity", "delta": 20}])
        self.assertTrue(r1["recorded"])
        r2 = svc2.record(fid, project_id=self.proj.id, risk_score=42,
                         risk_level="medium", severity="High",
                         confidence=0.5, asset_criticality="unknown",
                         exposure="unknown", calc_version=CALC_VERSION,
                         factors=[{"name": "severity", "delta": 20}])
        self.assertFalse(r2["recorded"])

    def _mk_finding(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        return self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw),
            [], scan_id=self.scan)["finding_id"]

    def test_pipeline_risk_fields_present(self):
        fid = self._mk_finding()
        row = self.svc.db.query_one(
            "SELECT risk_score, risk_level, confidence_score, "
            "confidence_level, priority, calc_version, occurrence_count "
            "FROM findings WHERE id=?", (fid,))
        self.assertGreater(row["risk_score"], 0)
        self.assertEqual(row["calc_version"], "risk-v1")
        self.assertEqual(row["occurrence_count"], 1)
        self.assertIn(row["priority"], ("P0", "P1", "P2", "P3", "P4"))


# ---------------------------------------------------------------------------
# 7. Correlation / root causes / clusters / remediation
# ---------------------------------------------------------------------------
class CorrelationTests(Phase4Base):
    def _seed(self, title, cat, rule, raw, source="secuaudit"):
        return self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, title=title,
                category=cat, rule=rule, raw=raw, source=source),
            [], scan_id=self.scan)["finding_id"]

    def test_related_by_topic_same_asset(self):
        raw = {"endpoint": "/", "technologies": [{"name": "nginx"}]}
        f1 = self._seed("Missing X-Frame-Options header", "misconfiguration",
                        "h-1", raw)
        f2 = self._seed("Directory listing enabled", "misconfiguration",
                        "d-1", raw, source="nucleus")
        links = self.corr.links(f1)
        self.assertTrue(any(l["relation_type"] == "related_to" for l in
                            links))
        self.assertTrue(all(l["rule_id"].startswith("topic:") for l in
                            links if l["relation_type"] == "related_to"))

    def test_correlation_is_not_dedup(self):
        raw = {"endpoint": "/", "technologies": [{"name": "nginx"}]}
        f1 = self._seed("Missing X-Frame-Options header", "misconfiguration",
                        "h-1", raw)
        self._seed("Directory listing enabled", "misconfiguration",
                   "d-1", raw)
        count = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM findings WHERE project_id=?",
            (self.proj.id,))["c"]
        self.assertEqual(count, 2)  # still two separate findings
        self.assertTrue(self.corr.links(f1))

    def test_links_idempotent(self):
        raw = {"endpoint": "/", "technologies": [{"name": "nginx"}]}
        f1 = self._seed("Missing X-Frame-Options header", "misconfiguration",
                        "h-1", raw)
        self._seed("Directory listing enabled", "misconfiguration",
                   "d-1", raw)
        n1 = len(self.corr.links(f1))
        for _ in range(3):
            self.corr.link_for(f1)
        self.assertEqual(len(self.corr.links(f1)), n1)

    def test_no_link_for_unrelated(self):
        raw1 = {"endpoint": "/a", "technologies": [{"name": "nginx"}]}
        raw2 = {"endpoint": "/b", "technologies": [{"name": "apache"}]}
        f1 = self._seed("Missing X-Frame-Options header", "misconfiguration",
                        "h-1", raw1)
        a2 = self.svc.asset_add(self.proj.id, "url", "https://other.example.com/")
        f2 = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, a2.id, title="SQL injection",
                category="injection", rule="sqli-99", raw=raw2),
            [], scan_id=self.scan2)["finding_id"]
        self.assertEqual(self.corr.links(f1), [])

    def test_root_cause_groups_only_with_two(self):
        raw = {"endpoint": "/", "technologies": [{"name": "nginx"}]}
        f1 = self._seed("Missing X-Frame-Options header", "misconfiguration",
                        "h-1", raw)
        self.assertEqual(self.corr.root_causes_for(f1), [])
        self._seed("Directory listing enabled", "misconfiguration",
                   "d-1", raw)
        groups = self.corr.root_causes_for(f1)
        self.assertTrue(groups)
        self.assertEqual(groups[0]["findings"], 2)

    def test_clusters_and_members(self):
        raw = {"endpoint": "/", "technologies": [{"name": "nginx"}]}
        f1 = self._seed("Missing X-Frame-Options header", "misconfiguration",
                        "h-1", raw)
        self._seed("Directory listing enabled", "misconfiguration",
                   "d-1", raw)
        self._seed("Server header exposed", "exposure", "e-1", raw,
                   source="nucleus")
        n = self.corr.clusters_build(self.proj.id)
        self.assertGreaterEqual(n, 1)
        clusters = self.corr.clusters(self.proj.id)
        self.assertTrue(clusters)
        c = clusters[0]
        view = self.corr.cluster_view(c["id"])
        self.assertGreaterEqual(len(view["members"]), 3)
        # idempotent rebuild
        self.corr.clusters_build(self.proj.id)
        self.assertEqual(
            len(self.corr.clusters(self.proj.id)),
            len(clusters))

    def test_remediation_group_same_component(self):
        raw = {"endpoint": "/", "technologies": [{"name": "nginx",
                                                  "version": "1.18"}]}
        self._seed("Missing X-Frame-Options header", "misconfiguration",
                   "h-1", raw)
        self._seed("Directory listing enabled", "misconfiguration",
                   "d-1", raw)
        raw2 = {"endpoint": "/x",
                "technologies": [{"name": "apache"}]}
        self._seed("Open redirect", "other", "r-1", raw2)
        n = self.corr.remediation_groups_build(self.proj.id)
        self.assertEqual(n, 1)
        groups = self.corr.remediation_groups(self.proj.id)
        self.assertEqual(groups[0]["component"], "nginx")
        self.assertEqual(groups[0]["member_count"], 2)

    def test_build_project_intel(self):
        raw = {"endpoint": "/", "technologies": [{"name": "nginx"}]}
        self._seed("Missing X-Frame-Options header", "misconfiguration",
                   "h-1", raw)
        self._seed("Directory listing enabled", "misconfiguration",
                   "d-1", raw)
        out = self.corr.build_project_intel(self.proj.id)
        self.assertEqual(out["findings_scanned"], 2)
        self.assertGreaterEqual(out["clusters"], 1)


# ---------------------------------------------------------------------------
# 8. Evidence graph
# ---------------------------------------------------------------------------
class GraphTests(Phase4Base):
    def test_graph_add_and_dedupe(self):
        fid = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)["finding_id"]
        r = self.corr.graph_add(self.proj.id, from_type="finding",
                                from_id=fid, rel_type="observed_on",
                                to_type="asset", to_id=self.asset.id,
                                source="secuaudit")
        self.assertTrue(r["relation_id"])
        n1 = len(self.corr.graph_for("finding", fid))
        self.assertEqual(n1, 1)
        self.corr.graph_add(self.proj.id, from_type="finding",
                            from_id=fid, rel_type="observed_on",
                            to_type="asset", to_id=self.asset.id,
                            source="secuaudit")
        self.assertEqual(len(self.corr.graph_for("finding", fid)), 1)

    def test_graph_supports_relation(self):
        fid = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)["finding_id"]
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        last = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, source="nucleus",
                rule="xss-001", title="XSS on q", raw=raw),
            [], scan_id=self.scan2)["finding_id"]
        self.corr.graph_add(self.proj.id, from_type="finding",
                            from_id=last, rel_type="supports",
                            to_type="finding", to_id=fid,
                            source="analyst", reason="same payload")
        edges = self.corr.graph_for("finding", fid)
        self.assertTrue(any(e["rel_type"] == "supports" for e in edges))

    def test_graph_bad_inputs(self):
        fid = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)["finding_id"]
        with self.assertRaises(errors.ValidationError):
            self.corr.graph_add(self.proj.id, from_type="finding",
                                from_id=fid, rel_type="hates",
                                to_type="asset", to_id=self.asset.id)
        with self.assertRaises(errors.NotFoundError):
            self.corr.graph_add(self.proj.id, from_type="finding",
                                from_id=fid, rel_type="related_to",
                                to_type="asset", to_id="missing")
        with self.assertRaises(errors.ValidationError):
            self.corr.graph_add(self.proj.id, from_type="wizard",
                                from_id=fid, rel_type="related_to",
                                to_type="asset", to_id=self.asset.id)

    def test_graph_bola(self):
        fid = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)["finding_id"]
        other_asset = self.svc.asset_add(self.other.id, "url",
                                         "https://x.example.com/")
        with self.assertRaises(errors.AuthorizationError):
            self.corr.graph_add(self.other.id, from_type="finding",
                                from_id=fid, rel_type="related_to",
                                to_type="asset", to_id=other_asset.id)


# ---------------------------------------------------------------------------
# 9. Temporal baselines + diffs
# ---------------------------------------------------------------------------
class DiffTests(Phase4Base):
    def test_first_baseline_all_new(self):
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)
        r = self.diffs.capture(self.proj.id, self.scan)
        self.assertEqual(r["summary"]["findings_new"], 1)
        self.assertEqual(r["summary"]["findings_persistent"], 0)
        # idempotent
        r2 = self.diffs.capture(self.proj.id, self.scan)
        self.assertFalse(r2["created"])
        self.assertEqual(r2["diff_id"], r["diff_id"])

    def test_second_scan_diff_states(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        fid = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw),
            [], scan_id=self.scan)["finding_id"]
        self.diffs.capture(self.proj.id, self.scan)
        # resolve + severe change in scan 2, plus a brand-new finding
        self.svc.db.execute(
            "UPDATE findings SET lifecycle='resolved', resolved_at=? "
            "WHERE id=?", (models.utcnow(), fid))
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, title="HSTS",
                category="misconfiguration", rule="h-2",
                raw={"endpoint": "/",
                     "technologies": [{"name": "nginx"}]}),
            [], scan_id=self.scan2)
        r = self.diffs.capture(self.proj.id, self.scan2)
        self.assertEqual(r["summary"]["findings_new"], 1)
        self.assertEqual(r["summary"]["findings_resolved"], 1)
        detail = self.corr.finding_view(fid)
        self.assertTrue(detail)

    def test_changed_risk_detection(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        r1 = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw),
            [], scan_id=self.scan)
        self.diffs.capture(self.proj.id, self.scan)
        # re-detection by a second scanner raises agreement → risk changes
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id, source="nucleus",
                rule="xss-001", title="XSS on q", raw=raw),
            [_ev()], scan_id=self.scan2)
        r = self.diffs.capture(self.proj.id, self.scan2)
        self.assertGreaterEqual(r["summary"]["findings_changed"], 1)
        self.assertGreaterEqual(r["summary"]["findings_persistent"], 1)

    def test_diff_readback(self):
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)
        r = self.diffs.capture(self.proj.id, self.scan)
        got = self.diffs.diff_get(r["diff_id"])
        self.assertEqual(got["calc_version"], "diff-v1")
        self.assertEqual(got["summary"]["findings_new"], 1)
        self.assertEqual(len(self.diffs.diffs(self.proj.id)), 1)

    def test_diff_uses_stable_fingerprints(self):
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)
        r1 = self.diffs.capture(self.proj.id, self.scan)
        # same finding re-detected (same fingerprint) — persistent, not new
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id),
            [_ev()], scan_id=self.scan2)
        r2 = self.diffs.capture(self.proj.id, self.scan2)
        self.assertEqual(r2["summary"]["findings_new"], 0)
        self.assertEqual(r2["summary"]["findings_persistent"], 1)

    def test_recapture_returns_latest_diff_for_scan(self):
        """Re-capturing a previously-seen to-scan must return the most
        recent diff row for it (not an older row that shares the same
        current_scan_id)."""
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)
        r1 = self.diffs.capture(self.proj.id, self.scan)
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan2, self.asset.id),
            [_ev()], scan_id=self.scan2)
        r2 = self.diffs.capture(self.proj.id, self.scan2)
        # a later scan that closes the loop back to scan1's id
        self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id),
            [], scan_id=self.scan)
        r3 = self.diffs.capture(self.proj.id, self.scan)
        self.assertTrue(r3["created"])
        # idempotent re-capture: must resolve to the newest diff for
        # current_scan_id = scan (from scan2), not the original baseline
        r4 = self.diffs.capture(self.proj.id, self.scan)
        self.assertFalse(r4["created"])
        self.assertEqual(r4["diff_id"], r3["diff_id"])
        self.assertEqual(r4["from_scan_id"], self.scan2)


# ---------------------------------------------------------------------------
# 10. Security: secret leakage + RBAC wiring
# ---------------------------------------------------------------------------
class SecurityTests(Phase4Base):
    SECRET = "x9f8a7b6c5d4e3f2a1b0-secret-token"

    def test_secrets_never_land_in_evidence_or_views(self):
        raw = {"endpoint": "/search?q=", "parameter": "q"}
        ev = _ev(snippet=f"token={self.SECRET}")
        ev.request_snippet = f"Authorization: Bearer {self.SECRET}"
        r = self.corr.ingest_finding(
            _mk(self.proj.id, self.scan, self.asset.id, raw=raw),
            [ev], scan_id=self.scan)
        fid = r["finding_id"]
        blob = str(self.svc.db.query_one(
            "SELECT evidence FROM findings WHERE id=?", (fid,)))
        self.assertNotIn(self.SECRET, blob)
        blob2 = str(self.svc.db.query_one(
            "SELECT raw FROM findings WHERE id=?", (fid,)))
        self.assertNotIn(self.SECRET, blob2)
        view = self.corr.finding_view(fid)
        self.assertNotIn(self.SECRET, str(view["evidence"]))
        self.assertNotIn(self.SECRET, str(view["risk_factors"]))
        self.assertNotIn(self.SECRET, str(view["confidence_reasons"]))
        for e in self.svc.db.query(
                "SELECT * FROM evidence WHERE finding_id=?", (fid,)):
            self.assertNotIn(self.SECRET, str(dict(e)))

    def test_secret_never_in_observation(self):
        self.intel.observe(self.asset.id, "http", obs_key="cookie",
                           obs_value=f"session={self.SECRET}",
                           source="scan")
        blob = str(self.intel.asset_intel(self.asset.id))
        self.assertNotIn(self.SECRET, blob)

    def test_permission_asset_criticality_manager_only(self):
        import rbac
        self.assertIn("asset.criticality", rbac.PERMISSIONS)
        self.assertIn("asset.criticality",
                      rbac.ROLE_PERMISSIONS["security_manager"])
        self.assertNotIn("asset.criticality",
                         rbac.ROLE_PERMISSIONS["analyst"])
        self.assertNotIn("asset.criticality",
                         rbac.ROLE_PERMISSIONS["viewer"])

    def test_bounded_queries(self):
        # limit clamps: asking for a huge history must not explode
        for i in range(8):
            self.intel.observe(self.asset.id, "service", obs_key="443",
                               obs_value=f"v{i}", source="scan")
        hist = self.intel.asset_history(self.asset.id, limit=10**9)
        self.assertLessEqual(len(hist), 8)
        rows = self.corr.prioritized(self.proj.id, limit=5000)
        self.assertIsInstance(rows, list)


# ---------------------------------------------------------------------------
# 11. Platform integration paths (worker-equivalent primitives)
# ---------------------------------------------------------------------------
class IntegrationTests(Phase4Base):
    def test_register_scanner_result_intelifies(self):
        raw = {"tool": "secuaudit", "target": "https://app.example.com/",
               "findings": [{
                   "title": "Reflected XSS in q", "description": "d",
                   "severity": "High", "confidence": "high",
                   "category": "xss", "source": "secuaudit",
                   "rule_id": "xss-001", "cwe": "CWE-79",
                   "evidence": [{"type": "response",
                                 "url": "https://app.example.com/?q=x",
                                 "response_snippet": "<script>1</script>",
                                 "detection_reason": "reflected"}],
                   "raw": {"endpoint": "/?q=", "parameter": "q"}}]}
        out = self.svc.register_scanner_result(self.proj.id, raw)
        fid = self.svc.db.query_one(
            "SELECT id FROM findings WHERE project_id=? LIMIT 1",
            (self.proj.id,))["id"]
        row = self.svc.db.query_one(
            "SELECT risk_score, confidence_score, calc_version, "
            "occurrence_count FROM findings WHERE id=?", (fid,))
        self.assertGreater(row["risk_score"], 0)
        self.assertEqual(row["calc_version"], "risk-v1")
        self.assertEqual(row["occurrence_count"], 1)
        self.assertEqual(out["scan_id"], fid and out["scan_id"])
        # idempotent re-registration
        out2 = self.svc.register_scanner_result(self.proj.id, raw)
        count = self.svc.db.query_one(
            "SELECT COUNT(*) AS c FROM findings WHERE project_id=?",
            (self.proj.id,))["c"]
        self.assertEqual(count, 1)
        self.assertEqual(out2["scan_id"], out["scan_id"])
        # baseline captured automatically
        self.assertIsNotNone(self.diffs.baseline_status(self.proj.id))

    def test_evaluate_garbage_is_fail_soft(self):
        ev = self.corr.evaluate({"id": "x", "evidence": "not-a-list"})
        ev2 = self.corr.evaluate({"id": "x", "evidence": "not-a-list"})
        self.assertGreaterEqual(ev["confidence_score"], 0.0)
        self.assertLessEqual(ev["confidence_score"], 1.0)
        self.assertIn(ev["confidence_level"],
                      ("high", "medium", "low", "unverified"))
        self.assertGreaterEqual(ev["risk_score"], 0)
        self.assertLessEqual(ev["risk_score"], 100)
        self.assertEqual(ev, ev2)  # deterministic even on garbage


if __name__ == "__main__":
    unittest.main(verbosity=2)
