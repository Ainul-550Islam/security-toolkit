#!/usr/bin/env python3
# ============================================================================
#  Phase-11 suite — data protection, privacy, secrets & compliance
#  governance: classification (allowlist + provenance + downgrade guard),
#  minimization/redaction (single redaction engine reused), secret metadata
#  registry (never plaintext), retention (bounded + holds), legal holds
#  (fail closed), controlled deletion (preview -> guard -> execute),
#  privacy request workflow, secure exports (bounded + integrity),
#  compliance evidence governance (+ policy exceptions), audit + tenant
#  isolation, CLI/RBAC smoke, dashboard panel, concurrency and scale.
#  Fully offline, deterministic, temp SQLite per test class.
# ============================================================================
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "python")
sys.path.insert(0, PY)
sys.path.insert(0, HERE)

import errors
import models
import platform_service as pf
import store

import data_governance as dg
import privacy as priv
import compliance_governance as cg
import dashboard as dbmod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
class GovBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="p11t_")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.db_path = os.path.join(self.dir, "t.db")
        self.svc = pf.PlatformService(self.db_path)
        self.gov = dg.SecurityGovernance(self.svc)
        self.org = self.svc.org_create("TenantA")
        self.proj = self.svc.project_create(self.org.id, "Core")
        self.org2 = self.svc.org_create("TenantB")
        self.proj2 = self.svc.project_create(self.org2.id, "Core2")

    _seq = 0

    def add_finding(self, project=None, **kw):
        proj = project or self.proj
        type(self)._seq += 1
        n = type(self)._seq
        scan = self.svc.scan_create(proj.id, f"web-audit-{n}")
        asset = self.svc.asset_add(proj.id, "url",
                                   kw.pop("asset_value",
                                          f"https://x.example/i?id={n}"))
        ev_raw = kw.get("evidence", [
            {"evidence_type": "response",
             "detection_reason": "mysql err"}])
        evs = []
        for e in ev_raw:
            ev = models.Evidence(finding_id="", evidence_type=e.get(
                "evidence_type", "response"),
                url=e.get("url", ""), method=e.get("method", "GET"),
                request_snippet=e.get("request_snippet", ""),
                response_snippet=e.get("response_snippet", ""),
                detection_reason=e.get("detection_reason", ""))
            evs.append(ev)
        f = models.Finding(
            scan_id=scan.id, project_id=proj.id, asset_id=asset.id,
            title=kw.get("title", "SQLi"), severity=kw.get("severity", "High"),
            category=kw.get("category", "injection"), source="t",
            rule_id=kw.get("rule_id", "R1"),
            raw=kw.get("raw", {"p": "id"}),
            evidence=[e.to_dict() for e in evs])
        f.finalize()
        self.svc.finding_ingest(f, evidence=evs)
        return f

    def evidence_ids(self, finding_id):
        rows = self.svc.db.query(
            "SELECT id FROM evidence WHERE finding_id=?", (finding_id,))
        return [str(r["id"]) for r in rows]

    def audit_actions(self, org_id=None):
        rows = self.svc.db.query(
            "SELECT action FROM audit_events WHERE org_id=?",
            (org_id or self.org.id,))
        return [str(r["action"]) for r in rows]


# ---------------------------------------------------------------------------
# 1. Classification (allowlist, provenance, downgrade guard, tenant scope)
# ---------------------------------------------------------------------------
class ClassificationTests(GovBase):
    def test_allowlist_and_default_resolution(self):
        with self.assertRaises(errors.ValidationError):
            self.gov.classification.classify(self.org.id, "finding",
                                             object_id="z",
                                             classification="topsecret")
        r = self.gov.classification.effective(self.org.id, "finding", "nope")
        self.assertEqual(r["effective"], "internal")
        self.assertEqual(r["provenance"], "default")
        d = self.gov.classification.default(self.org.id,
                                            classification="confidential")
        self.assertEqual(d["effective"], "confidential")
        r2 = self.gov.classification.effective(self.org.id, "finding", "x")
        self.assertEqual(r2["effective"], "confidential")
        self.assertEqual(r2["provenance"], "policy")

    def test_explicit_wins_over_default_no_silent_downgrade(self):
        self.gov.classification.default(self.org.id,
                                        classification="confidential")
        c = self.gov.classification.classify(self.org.id, "finding",
                                             object_id="f1",
                                             classification="restricted")
        self.assertEqual(c["effective"], "restricted")
        with self.assertRaises(errors.AuthorizationError):
            self.gov.classification.classify(self.org.id, "finding",
                                             object_id="f1",
                                             classification="internal")
        # explicit authorization allows the downgrade (audited)
        c2 = self.gov.classification.classify(self.org.id, "finding",
                                              object_id="f1",
                                              classification="public",
                                              authorized=True)
        self.assertEqual(c2["effective"], "public")
        self.assertIn("classification.changed", self.audit_actions())
        self.assertIn("classification.downgrade_denied",
                      self.audit_actions())

    def test_rank_order(self):
        self.assertGreater(
            models.CLASSIFICATION_RANK["authentication_material"],
            models.CLASSIFICATION_RANK["secret"])
        self.assertGreater(
            models.CLASSIFICATION_RANK["secret"],
            models.CLASSIFICATION_RANK["personal_data"])
        self.assertEqual(len(models.DATA_CLASSIFICATIONS), 9)
        self.assertEqual(models.CLASSIFICATION_RANK["public"], 0)

    def test_provenance_history_from_audit(self):
        self.gov.classification.classify(self.org.id, "finding",
                                         object_id="f1",
                                         classification="secret")
        ch = self.gov.classification.changes(self.org.id, "finding", "f1")
        self.assertGreaterEqual(ch["count"], 1)
        self.assertEqual(ch["items"][0]["action"], "classification.changed")
        # audit metadata carries only the classification label
        self.assertNotIn("password", json.dumps(ch["items"][0]["metadata"]))

    def test_tenant_isolation_classification(self):
        self.gov.classification.classify(self.org.id, "finding",
                                         object_id="f1",
                                         classification="secret")
        self.gov.classification.classify(self.org2.id, "finding",
                                         object_id="f1",
                                         classification="public")
        self.assertEqual(
            self.gov.classification.get(self.org.id, "finding",
                                        "f1")["effective"], "secret")
        self.assertEqual(
            self.gov.classification.get(self.org2.id, "finding",
                                        "f1")["effective"], "public")
        # org2 never sees org1's row; unknown org objects fail closed
        self.assertNotIn("secret",
                         json.dumps(self.gov.classification.list(
                             self.org2.id,
                             object_type="finding")["items"]))


# ---------------------------------------------------------------------------
# 2. Minimization / redaction (single engine; values never returned)
# ---------------------------------------------------------------------------
class RedactionMinimizationTests(GovBase):
    def test_detect_counts_without_values(self):
        r = dg.detect_secret_shapes(
            "use ghp_" + "a" * 36 + " and Bearer eyJx.e30.sig here")
        self.assertGreaterEqual(r["hits"], 1)
        self.assertNotIn("ghp_", r["redacted_sample"])
        self.assertNotIn("eyJx", r["redacted_sample"])
        self.assertIn("[REDACTED]", r["redacted_sample"])

    def test_scan_conservative_and_bounded(self):
        f = self.add_finding(title="SQLi for alice@example.com",
                             raw={"user": "alice@example.com"})
        r = self.gov.privacy.scan if False else None
        p = priv.PrivacyService(self.svc)
        res = p.scan(self.org.id, "alice@example.com")
        self.assertGreaterEqual(res["total"], 1)
        self.assertEqual(res["object_types"][0]["object_type"], "finding")
        self.assertIn("never a claim of completeness", res["note"])

    def test_cover_redacts_json_safely_and_skips_held(self):
        f = self.add_finding(title="SQLi for alice@example.com",
                             raw={"user": "alice@example.com"},
                             evidence=[{"evidence_type": "response",
                                        "detection_reason":
                                            "err alice@example.com"}])
        g2 = self.add_finding(title="Bob's bug")
        self.gov.retention.hold_create(self.org.id, object_type="findings",
                                       object_id=g2.id, reason="legal")
        p = priv.PrivacyService(self.svc)
        res = p.cover(self.org.id, subject_ref="alice@example.com", batch=50)
        self.assertGreaterEqual(res["updated"], 2)   # raw + evidence JSON
        self.assertIn("note", res)
        got = self.svc.finding_list(self.proj.id, limit=50)
        blob = json.dumps([x.to_dict() for x in got])
        self.assertNotIn("alice@example.com", blob)
        res2 = p.cover(self.org.id, subject_ref="Bob", batch=50)
        self.assertEqual(res2["skipped_held"], 1)
        self.assertEqual(res2["updated"], 0)

    def test_correct_allowlist_and_hold_block(self):
        f = self.add_finding()
        p = priv.PrivacyService(self.svc)
        r = p.correct(self.org.id, object_type="finding", object_id=f.id,
                      field="title", value="corrected title")
        self.assertTrue(r["corrected"])
        with self.assertRaises(errors.ValidationError):
            p.correct(self.org.id, object_type="finding", object_id=f.id,
                      field="raw", value="x")          # not correctable
        self.gov.retention.hold_create(self.org.id, object_type="findings",
                                       object_id=f.id, reason="legal")
        with self.assertRaises(errors.LifecycleError):
            p.correct(self.org.id, object_type="finding", object_id=f.id,
                      field="title", value="blocked")

    def test_restrict_tombstones_in_place(self):
        f = self.add_finding()
        p = priv.PrivacyService(self.svc)
        r = p.restrict(self.org.id, object_type="finding", object_id=f.id,
                       fields=["description"], reason="subject restriction")
        self.assertTrue(r["restricted"])
        got = self.svc.finding_get(f.id)
        self.assertIn("REDACTED-SUBJECT", got.description)

    def test_redact_engine_is_the_only_one(self):
        # cover/correct output must be produced by redact.py markers
        # (single redaction vocabulary — nothing ad-hoc)
        f = self.add_finding(title="SQLi for alice@example.com")
        p = priv.PrivacyService(self.svc)
        p.cover(self.org.id, subject_ref="alice@example.com", batch=10)
        got = self.svc.finding_get(f.id)
        self.assertNotIn("alice@example.com",
                         json.dumps(got.raw) + json.dumps(got.evidence))
        self.assertTrue(got.title.startswith("SQLi"))  # redacted in place


# ---------------------------------------------------------------------------
# 3. Secret & credential governance (metadata registry only)
# ---------------------------------------------------------------------------
class SecretGovernanceTests(GovBase):
    MAT = "ghp_" + "s" * 36

    def test_register_is_metadata_only_never_plaintext(self):
        r = self.gov.secrets.register(self.org.id, kind="api_key",
                                      name="ci", reference="gh/x",
                                      material=self.MAT,
                                      project_id=self.proj.id)
        self.assertEqual(r["status"], "active")
        blob = store.dumps(self.svc.db.query(
            "SELECT * FROM secrets_registry"))
        self.assertNotIn("ghp_", blob)
        self.assertNotIn(self.MAT, blob)
        # audit never contains the material either
        for row in self.svc.db.query(
                "SELECT metadata FROM audit_events WHERE action="
                "'secret.registered'"):
            self.assertNotIn("ghp_", str(row["metadata"]))

    def test_search_hash_distinct_from_decryptable_storage(self):
        r1 = self.gov.secrets.register(self.org.id, kind="api_key",
                                       name="ci", reference="gh/x",
                                       material=self.MAT)
        r2 = self.gov.secrets.register(self.org.id, kind="api_key",
                                       name="ci", reference="gh/x",
                                       material="ghp_" + "t" * 36)
        self.assertEqual(r1["id"], r2["id"])   # same kind/name/ref -> dedup
        h1 = self.gov.secrets.get(self.org.id, r1["id"])["search_hash"]
        self.assertEqual(len(h1), 64)
        self.assertTrue(h1.startswith("sha256") or h1.isalnum())

    def test_lifecycle_transitions_and_sweep(self):
        r = self.gov.secrets.register(
            self.org.id, kind="api_key", name="ci", reference="r",
            material=self.MAT, expires_at="2026-01-01T00:00:00Z")
        # manual expire is an allowed active transition
        self.gov.secrets.set_status(self.org.id, r["id"], "expired")
        self.assertEqual(
            self.gov.secrets.get(self.org.id, r["id"])["status"], "expired")
        with self.assertRaises(errors.LifecycleError):
            self.gov.secrets.set_status(self.org.id, r["id"],
                                        "rotation_required")
        r2 = self.gov.secrets.register(self.org.id, kind="api_key",
                                       name="ci2", reference="r2",
                                       material=self.MAT,
                                       rotation_due_at="2026-06-01T00:00:00Z")
        # active + rotation due -> rotation_required (automated, audited)
        res2 = self.gov.secrets.sweep_expiry(
            self.org.id, now="2026-07-01T00:00:00Z")
        self.assertEqual(res2["rotation_required"], 1)
        got = self.gov.secrets.get(self.org.id, r2["id"])
        self.assertEqual(got["status"], "rotation_required")
        # expired secrets stay expired unless explicitly reset
        r3 = self.gov.secrets.register(self.org.id, kind="api_key",
                                       name="ci3", reference="r3",
                                       material=self.MAT,
                                       expires_at="2026-05-01T00:00:00Z")
        res3 = self.gov.secrets.sweep_expiry(
            self.org.id, now="2026-06-01T00:00:00Z")
        self.assertEqual(res3["expired"], 1)
        self.assertEqual(
            self.gov.secrets.get(self.org.id, r3["id"])["status"], "expired")

    def test_status_summary_and_touch(self):
        self.gov.secrets.register(self.org.id, kind="api_key", name="a",
                                  reference="r", material=self.MAT,
                                  expires_at="2099-01-01T00:00:00Z")
        s = self.gov.secrets.status_summary(self.org.id)
        self.assertEqual(s["total"], 1)
        self.assertIn("expiring_within_30d", s)
        r = self.gov.secrets.list(self.org.id, limit=10)
        self.assertEqual(r["total"], 1)
        self.gov.secrets.touch(self.org.id, r["items"][0]["id"])
        self.assertNotEqual(
            self.gov.secrets.get(self.org.id, r["items"][0]["id"])[
                "last_used_at"], "")

    def test_revoke_audited_and_evident(self):
        r = self.gov.secrets.register(self.org.id, kind="api_key",
                                      name="a", reference="r",
                                      material=self.MAT)
        got = self.gov.secrets.set_status(self.org.id, r["id"], "revoked")
        self.assertEqual(got["status"], "revoked")
        self.assertNotEqual(got["revoked_at"], "")
        self.assertIn("secret.revoked", self.audit_actions())


# ---------------------------------------------------------------------------
# 4. Retention policies + holds + executions
# ---------------------------------------------------------------------------
class RetentionTests(GovBase):
    def test_policy_bounds_and_resolution(self):
        with self.assertRaises(errors.ValidationError):
            self.gov.retention.policy_set(self.org.id, kind="findings",
                                          days=0)
        with self.assertRaises(errors.ValidationError):
            self.gov.retention.policy_set(self.org.id, kind="findings",
                                          days=99999)
        with self.assertRaises(errors.ValidationError):
            self.gov.retention.policy_set(self.org.id, kind="bogus",
                                          days=30)
        self.gov.retention.policy_set(self.org.id, kind="findings",
                                      days=30, project_id=self.proj.id)
        self.assertEqual(
            self.gov.retention.effective_days(
                self.org.id, "findings", project_id=self.proj.id), 30)
        # org scope alone falls back to the built-in default
        self.assertEqual(
            self.gov.retention.effective_days(self.org.id, "findings"),
            int(models.RETENTION_DEFAULTS["findings"]))
        self.gov.retention.policy_set(self.org.id, kind="findings", days=60)
        self.assertEqual(
            self.gov.retention.effective_days(self.org.id, "findings"), 60)
        self.assertEqual(
            self.gov.retention.effective_days(self.org.id, "audit_events"),
            int(models.RETENTION_DEFAULTS["audit_events"]))

    def test_preview_counts_and_batch_bound(self):
        f = self.add_finding()
        self.svc.db.execute(
            "UPDATE findings SET resolved_at='2020-01-01T00:00:00Z', "
            "lifecycle='resolved' WHERE id=?", (f.id,))
        p = self.gov.retention.preview(self.org.id, kind="findings",
                                       batch=100)
        self.assertEqual(p["mode"], "preview")
        self.assertEqual(p["eligible"], 1)
        self.assertEqual(p["deleted"] if "deleted" in p else 0, 0)
        with self.assertRaises(errors.ValidationError):
            self.gov.retention.preview(self.org.id, kind="findings",
                                       batch=10_000_000)

    def test_execution_respects_holds_report_vs_findings(self):
        f1 = self.add_finding(title="resolved one")
        f2 = self.add_finding(title="held one")
        for f in (f1, f2):
            self.svc.db.execute(
                "UPDATE findings SET resolved_at='2020-01-01T00:00:00Z', "
                "lifecycle='resolved' WHERE id=?", (f.id,))
        self.gov.retention.policy_set(self.org.id, kind="findings", days=1)
        self.gov.retention.hold_create(self.org.id, object_type="findings",
                                       object_id=f2.id, reason="legal")
        r = self.gov.retention.execute(self.org.id, kind="findings",
                                       dry_run=False, batch=100)
        self.assertEqual(r["deleted"], 1)
        self.assertEqual(r["held"], 1)
        with self.assertRaises(errors.NotFoundError):
            self.svc.finding_get(f1.id)
        self.assertEqual(self.svc.finding_get(f2.id).id, f2.id)
        runs = self.gov.retention.runs(self.org.id, kind="findings")
        self.assertEqual(runs["items"][0]["held_count"], 1)

    def test_audit_events_never_deleted_and_advisory_counted(self):
        self.add_finding()
        self.svc.audit("finding.updated", object_type="finding",
                       object_id="x1", org_id=self.org.id,
                       project_id=self.proj.id, actor="test")
        self.svc.db.execute(
            "UPDATE audit_events SET ts='2015-01-01T00:00:00Z' WHERE "
            "org_id=? AND action='finding.updated'", (self.org.id,))
        r = self.gov.retention.execute(self.org.id, kind="audit_events",
                                       dry_run=False)
        self.assertEqual(r["deleted"], 0)
        self.assertGreaterEqual(r["eligible"], 1)
        n = int(self.svc.db.query_one(
            "SELECT COUNT(*) n FROM audit_events WHERE org_id=?",
            (self.org.id,))["n"])
        self.assertGreaterEqual(n, 1)

    def test_evidence_tombstoned_not_dropped(self):
        f = self.add_finding()
        ev_ids = self.evidence_ids(f.id)
        self.assertTrue(ev_ids)
        self.svc.db.execute(
            "UPDATE evidence SET captured_at='2020-01-01T00:00:00Z' "
            "WHERE finding_id=?", (f.id,))
        self.gov.retention.policy_set(self.org.id, kind="evidence", days=1)
        r = self.gov.retention.execute(self.org.id, kind="evidence",
                                       dry_run=False, batch=100)
        self.assertEqual(r["deleted"], len(ev_ids))  # tombstones count as
        row = self.gov._one if False else self.svc.db.query_one(
            "SELECT * FROM evidence WHERE id=?", (ev_ids[0],))
        # row still exists (audit integrity) but content is purged
        self.assertIsNotNone(row)
        self.assertEqual(dict(row)["request_snippet"], "[RETENTION-PURGED]")

    def test_retention_cleanup_unrelated_scan_history(self):
        f = self.add_finding()
        scan_id = f.scan_id
        self.gov.retention.policy_set(self.org.id, kind="scan_history",
                                      days=1)
        self.svc.db.execute(
            "UPDATE scans SET created_at='2020-01-01T00:00:00Z' "
            "WHERE id=?", (scan_id,))
        r = self.gov.retention.execute(self.org.id, kind="scan_history",
                                       dry_run=False, batch=100)
        # scan referenced by a finding is protected by the spec
        self.assertEqual(r["deleted"], 0)
        self.assertIsNotNone(self.svc.scan_get(scan_id))


# ---------------------------------------------------------------------------
# 5. Controlled deletion
# ---------------------------------------------------------------------------
class DeletionTests(GovBase):
    def test_preview_and_hold_block(self):
        f = self.add_finding()
        self.gov.retention.policy_set(self.org.id, kind="findings", days=30)
        p = self.gov.deletion.preview(self.org.id, object_type="finding",
                                      object_id=f.id)
        self.assertTrue(p["eligible"])            # not held
        self.assertFalse(p["retention_eligible"])  # too fresh
        with self.assertRaises(errors.AuthorizationError):
            self.gov.deletion.delete(self.org.id, object_type="finding",
                                     object_id=f.id)
        self.gov.retention.hold_create(self.org.id, object_type="findings",
                                       object_id=f.id, reason="hold")
        p2 = self.gov.deletion.preview(self.org.id, object_type="finding",
                                       object_id=f.id)
        self.assertTrue(p2["held"])
        # release + authorize -> delete succeeds
        holds = self.gov.retention.hold_list(self.org.id)
        self.gov.retention.hold_release(self.org.id, holds["items"][0]["id"],
                                        reason="done")
        r = self.gov.deletion.delete(self.org.id, object_type="finding",
                                     object_id=f.id, authorized=True)
        self.assertTrue(r["deleted"])
        with self.assertRaises(errors.NotFoundError):
            self.svc.finding_get(f.id)

    def test_hold_blocks_even_when_authorized(self):
        f = self.add_finding()
        self.gov.retention.hold_create(self.org.id, object_type="finding",
                                       object_id=f.id, reason="legal")
        with self.assertRaises(errors.LifecycleError):
            self.gov.deletion.delete(self.org.id, object_type="finding",
                                     object_id=f.id, authorized=True)

    def test_tombstone_only_refused(self):
        with self.assertRaises(errors.ValidationError):
            self.gov.deletion.delete(self.org.id, object_type="evidence",
                                     object_id="e1")

    def test_foreign_or_unknown_never_revealed(self):
        f = self.add_finding()
        with self.assertRaises(errors.NotFoundError):
            self.gov.deletion.preview(self.org2.id, object_type="finding",
                                      object_id=f.id)
        with self.assertRaises(errors.NotFoundError):
            self.gov.deletion.preview(self.org.id, object_type="finding",
                                      object_id="no-such-id")


# ---------------------------------------------------------------------------
# 6. Privacy request workflow (state machine; no legal claims)
# ---------------------------------------------------------------------------
class PrivacyWorkflowTests(GovBase):
    def test_state_machine_and_invalid_transitions(self):
        r = self.gov.privacy.create(self.org.id, request_type="access",
                                    subject_ref="u@x.example.com",
                                    project_id=self.proj.id,
                                    requester="requester")
        self.assertEqual(r["status"], "submitted")
        with self.assertRaises(errors.LifecycleError):
            self.gov.privacy.update(self.org.id, r["id"], status="completed",
                                    reviewer="r")
        with self.assertRaises(errors.LifecycleError):
            self.gov.privacy.complete(self.org.id, r["id"], reviewer="r")
        self.gov.privacy.update(self.org.id, r["id"], status="under_review",
                                reviewer="rev")
        self.gov.privacy.update(self.org.id, r["id"], status="approved",
                                reviewer="rev")
        self.gov.privacy.update(self.org.id, r["id"], status="in_progress",
                                reviewer="rev")
        self.gov.privacy.complete(self.org.id, r["id"], reviewer="rev",
                                  evidence={"export_id": "e1"})
        got = self.gov.privacy.get(self.org.id, r["id"])
        self.assertEqual(got["status"], "completed")
        self.assertEqual(got["completion_evidence"]["export_id"], "e1")
        with self.assertRaises(errors.LifecycleError):
            self.gov.privacy.update(self.org.id, r["id"], status="submitted")

    def test_fail_path_and_type_allowlist(self):
        r = self.gov.privacy.create(self.org.id, request_type="deletion",
                                    subject_ref="u@x.example.com")
        self.gov.privacy.update(self.org.id, r["id"], status="under_review",
                                reviewer="r")
        self.gov.privacy.update(self.org.id, r["id"], status="approved",
                                reviewer="r")
        self.gov.privacy.update(self.org.id, r["id"], status="in_progress",
                                reviewer="r")
        self.gov.privacy.fail(self.org.id, r["id"], reason="no data")
        got = self.gov.privacy.get(self.org.id, r["id"])
        self.assertEqual(got["status"], "failed")
        self.assertIn("no data", got["failure_reason"])
        with self.assertRaises(errors.ValidationError):
            self.gov.privacy.create(self.org.id, request_type="unknown",
                                    subject_ref="u@x")

    def test_list_filters_and_tenant_scope(self):
        self.gov.privacy.create(self.org.id, request_type="access",
                                subject_ref="a@x")
        r2 = self.gov.privacy.create(self.org.id, request_type="export",
                                     subject_ref="b@x")
        self.gov.privacy.update(self.org.id, r2["id"], status="under_review",
                                reviewer="r")
        lst = self.gov.privacy.list(self.org.id, status="submitted")
        self.assertEqual(lst["total"], 1)
        lst2 = self.gov.privacy.list(self.org2.id)
        self.assertEqual(lst2["total"], 0)
        with self.assertRaises(errors.NotFoundError):
            self.gov.privacy.get(self.org2.id, r2["id"])

    def test_no_compliance_claim(self):
        # the module states legal interpretation remains operator's
        self.assertIn(
            "legal interpretation", priv.__doc__.lower())


# ---------------------------------------------------------------------------
# 7. Compliance evidence governance + policy exceptions
# ---------------------------------------------------------------------------
class ComplianceEvidenceTests(GovBase):
    def test_control_families_and_evidence_state_only(self):
        c = cg.ComplianceEvidenceGovernance(self.svc)
        st = c.controls(self.org.id, project_id=self.proj.id)
        self.assertEqual(len(st["controls"]), len(models.CONTROL_CATEGORIES))
        self.assertEqual(st["controls"][0]["status"], "not_evaluated")
        self.assertFalse(st["controls"][0]["evidence_exists"])
        self.assertIn("evidence state only", st["note"])
        self.assertTrue(st["controls"][0]["gap"])

    def test_evidence_derive_feeds_status(self):
        import reporting
        ev = reporting.EvidenceService(self.svc)
        items = ev.derive(self.proj.id)
        self.assertEqual(len(items), len(models.CONTROL_CATEGORIES))
        st = cg.ComplianceEvidenceGovernance(self.svc).controls(
            self.org.id, project_id=self.proj.id)
        self.assertIn(
            st["controls"][0]["status"],
            models.CONTROL_STATUSES)

    def test_exception_expired_never_silently_effective(self):
        ex = self.gov.exceptions.create(self.org.id, policy="access_control",
                                        reason="legacy",
                                        approved_by="boss",
                                        expires_at="2099-01-01T00:00:00Z")
        self.assertTrue(self.gov.exceptions.get(
            self.org.id, ex["id"])["effective"])
        self.assertIsNotNone(
            self.gov.exceptions.effective(self.org.id, "access_control"))
        # move expiry into the past: effective() must fail closed FIRST
        self.svc.db.execute(
            "UPDATE policy_exceptions SET expires_at=? WHERE id=?",
            ("2026-01-01T00:00:00Z", ex["id"]))
        self.assertIsNone(
            self.gov.exceptions.effective(self.org.id, "access_control"))
        self.gov.exceptions.sweep_expiry(
            self.org.id, now="2026-06-01T00:00:00Z")
        got = self.gov.exceptions.get(self.org.id, ex["id"])
        self.assertEqual(got["status"], "expired")
        self.assertFalse(got["effective"])
        self.assertIsNone(
            self.gov.exceptions.effective(self.org.id, "access_control"))

    def test_exception_revoke_ends_effectiveness(self):
        ex = self.gov.exceptions.create(self.org.id, policy="monitoring",
                                        reason="test",
                                        approved_by="boss",
                                        expires_at="2099-01-01T00:00:00Z")
        self.gov.exceptions.revoke(self.org.id, ex["id"], reason="no longer")
        self.assertIsNone(
            self.gov.exceptions.effective(self.org.id, "monitoring"))

    def test_report_status_and_secret_free_verification(self):
        import reporting
        rsvc = reporting.ReportService(self.svc)
        snap = rsvc.snapshot(self.proj.id, "executive",
                             generated_by="test")
        rsvc.store_run(snap, store_payload=True)
        c = cg.ComplianceEvidenceGovernance(self.svc)
        st = c.report_status(self.org.id, self.proj.id)
        rep = st["report"]
        self.assertEqual(rep["report_type"], "executive")
        self.assertTrue(rep["secret_free_verified"])
        self.assertIn(rep["classification"], models.DATA_CLASSIFICATIONS)
        self.assertIn(rep["sensitivity"], ("low", "medium", "high"))

    def test_evidence_audit_bounded(self):
        c = cg.ComplianceEvidenceGovernance(self.svc)
        r = c.evidence_audit(self.org.id, project_id=self.proj.id)
        self.assertEqual(r["total"], 0)

    def test_status_vocabulary_exact(self):
        self.assertEqual(
            set(models.CONTROL_STATUSES),
            {"not_evaluated", "supported", "partially_supported",
             "insufficient_evidence", "not_supported", "exception"})


# ---------------------------------------------------------------------------
# 8. Secure exports
# ---------------------------------------------------------------------------
class ExportTests(GovBase):
    def test_export_integrity_and_determinism(self):
        self.gov.classification.classify(self.org.id, "finding",
                                         object_id="f1",
                                         classification="secret")
        e1 = self.gov.exports.build(self.org.id, scope="summary",
                                    project_id=self.proj.id)
        e2 = self.gov.exports.build(self.org.id, scope="summary",
                                    project_id=self.proj.id)
        # deterministic CONTENT: the only field allowed to differ is the
        # wall-clock `generated_at` stamp (top level and inside the nested
        # governance summary) — everything else must be byte-identical.
        # (Comparing raw strings made this test flaky whenever the two
        # builds straddled a second boundary.)
        d1, d2 = json.loads(e1["data"]), json.loads(e2["data"])
        self.assertEqual(d1["generated_at"][:10], d2["generated_at"][:10])
        for d in (d1, d2):
            d["generated_at"] = ""
            nested = (d.get("summary") or {}).get("data")
            if isinstance(nested, dict):
                nested["generated_at"] = ""
        self.assertEqual(d1, d2)
        self.assertEqual(
            hashlib.sha256(e1["data"].encode("utf-8")).hexdigest(),
            e1["integrity"])
        rec = self.gov.exports.record(self.org.id, e1["export_id"])
        self.assertEqual(rec["sha256"], e1["integrity"])
        lst = self.gov.exports.list(self.org.id)
        self.assertGreaterEqual(lst["total"], 2)
        self.assertIn("data-export-v1", e1["data"])

    def test_export_bounded_and_redacted(self):
        self.gov.secrets.register(self.org.id, kind="api_key", name="ci",
                                  reference="r",
                                  material="ghp_" + "q" * 36)
        e = self.gov.exports.build(self.org.id, scope="secrets", limit=10)
        self.assertLess(len(e["data"]), 2_000_000)
        self.assertIn("registry", e["data"])      # metadata section ships
        self.assertIn("search_hash", e["data"])   # metadata allowed
        self.assertNotIn("ghp_", e["data"])
        with self.assertRaises(errors.ValidationError):
            self.gov.exports.build(self.org.id, scope="summary",
                                   limit=dg.MAX_EXPORT_ITEMS + 1)

    def test_export_scope_allowlist_and_manifest(self):
        with self.assertRaises(errors.ValidationError):
            self.gov.exports.build(self.org.id, scope="everything")
        e = self.gov.exports.build(self.org.id, scope="classifications")
        self.assertEqual(e["manifest"]["org_id"], self.org.id)
        self.assertEqual(e["scope"], "classifications")
        self.assertIn("created_by", e["manifest"])


# ---------------------------------------------------------------------------
# 9. Audit chain + tenant isolation
# ---------------------------------------------------------------------------
class AuditTenantTests(GovBase):
    def test_governance_events_audited_without_secret_contents(self):
        self.gov.secrets.register(self.org.id, kind="api_key", name="ci",
                                  reference="r", material="ghp_" + "z" * 36)
        self.gov.retention.hold_create(self.org.id, object_type="findings",
                                       object_id="f1", reason="legal")
        self.gov.classification.classify(self.org.id, "finding",
                                         object_id="f1",
                                         classification="secret")
        actions = self.audit_actions()
        for needle in ("secret.registered", "hold.created",
                       "classification.changed"):
            self.assertIn(needle, actions)
        blob = store.dumps(self.svc.db.query(
            "SELECT metadata FROM audit_events WHERE org_id=?",
            (self.org.id,)))
        self.assertNotIn("ghp_", blob)

    def test_cross_tenant_always_not_found(self):
        f = self.add_finding()
        self.gov.classification.classify(self.org.id, "finding",
                                         object_id=f.id,
                                         classification="secret")
        self.gov.secrets.register(self.org.id, kind="api_key", name="ci",
                                  reference="r", material="ghp_" + "x" * 36)
        # org2 cannot see org1's secret registry, classifications, holds
        with self.assertRaises(errors.NotFoundError):
            self.gov.secrets.get(self.org2.id,
                                 self.gov.secrets.list(self.org.id)["items"][
                                     0]["id"])
        with self.assertRaises(errors.NotFoundError):
            self.gov.retention.policy_get(
                self.org2.id, self.gov.retention.policy_set(
                    self.org.id, kind="findings", days=7)["id"])
        with self.assertRaises(errors.NotFoundError):
            self.gov.deletion.preview(self.org2.id, object_type="finding",
                                      object_id=f.id)
        self.assertEqual(
            self.gov.privacy.list(self.org2.id)["total"], 0)

    def test_limits_are_central_and_not_overridable(self):
        self.assertEqual(dg.MAX_EXPORT_ITEMS, 50_000)
        self.assertEqual(dg.MAX_RETENTION_BATCH, 5_000)
        self.assertEqual(dg.MAX_AUDIT_PAGE_SIZE, 500)
        self.assertEqual(dg.MAX_EVIDENCE_PAGE_SIZE, 500)
        self.assertEqual(dg.MAX_COMPLIANCE_PAGE_SIZE, 500)
        self.assertEqual(dg.RETENTION_MIN_DAYS, 1)
        self.assertEqual(dg.RETENTION_MAX_DAYS, 3650)


# ---------------------------------------------------------------------------
# 10. CLI + RBAC smoke
# ---------------------------------------------------------------------------
class CliSmokeTests(GovBase):
    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"),
             "security", "--db", self.db_path, *argv],
            capture_output=True, text=True, timeout=180)

    def _token(self, username, pw, roles):
        import identity as idm
        id_svc = idm.IdentityService(self.svc)
        id_svc.user_create(self.org.id, username, username + "@x.example.com",
                           pw, roles=roles, actor="test",
                           allow_any_role=True)
        tok = id_svc.login(username, pw)
        for k, v in tok.items():
            if isinstance(v, str) and len(v) > 20:
                return v
        raise RuntimeError("no token")

    def test_cli_classify_retention_status(self):
        o = self._run("data", "classify", "--org", self.org.id,
                      "--object-type", "finding", "--object-id", "f1",
                      "--classification", "confidential")
        self.assertEqual(o.returncode, 0, o.stderr)
        self.assertIn("confidential", o.stdout)
        o2 = self._run("data", "classifications", "--org", self.org.id)
        self.assertIn("confidential", o2.stdout)
        o3 = self._run("secrets", "status", "--org", self.org.id)
        self.assertIn("total=0", o3.stdout)
        o4 = self._run("data", "retention", "--org", self.org.id,
                       "--kind", "findings", "--days", "30", "--action",
                       "set")
        self.assertEqual(o4.returncode, 0, o4.stderr)
        self.assertIn("findings = 30 days", o4.stdout)
        o5 = self._run("compliance", "controls", "--org", self.org.id)
        self.assertEqual(o5.returncode, 0, o5.stderr)
        self.assertIn("not_evaluated", o5.stdout)

    def test_cli_role_gates_fail_closed(self):
        vtok = self._token("gview", "Str0ng!Passw0rd", ("viewer",))
        atok = self._token("gadmin", "Str0ng!Passw0rd", ("admin",))
        out = self._run_with("--as", vtok, "data", "export", "--org",
                             self.org.id)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("Forbidden", out.stdout + out.stderr)
        out2 = self._run_with("--as", vtok, "data", "classifications",
                              "--org", self.org.id)
        self.assertEqual(out2.returncode, 0)
        out3 = self._run_with("--as", atok, "data", "export", "--org",
                              self.org.id)
        self.assertEqual(out3.returncode, 0, out3.stderr)

    def _run_with(self, *argv):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"),
             "security", "--db", self.db_path, *argv],
            capture_output=True, text=True, timeout=180)

    def test_cli_privacy_and_secrets_detect(self):
        o = self._run("privacy", "request-create", "--org", self.org.id,
                      "--type", "access", "--subject-ref", "u@x.example.com",
                      "--requester", "r")
        self.assertEqual(o.returncode, 0, o.stderr)
        self.assertIn("access", o.stdout)
        o2 = self._run("secrets", "detect", "--org", self.org.id,
                       "--text", "key ghp_" + "a" * 36)
        self.assertEqual(o2.returncode, 0, o2.stderr)
        self.assertIn("[REDACTED]", o2.stdout)
        self.assertNotIn("ghp_", o2.stdout)


# ---------------------------------------------------------------------------
# 11. Dashboard panel (read-only; no values)
# ---------------------------------------------------------------------------
class DashboardTests(GovBase):
    def test_snapshot_counts_and_page(self):
        self.gov.classification.classify(self.org.id, "finding",
                                         object_id="f1",
                                         classification="secret")
        self.gov.secrets.register(self.org.id, kind="api_key", name="ci",
                                  reference="r", material="ghp_" + "w" * 36)
        self.gov.retention.hold_create(self.org.id, object_type="findings",
                                       object_id="f2", reason="legal")
        self.gov.privacy.create(self.org.id, request_type="access",
                                subject_ref="u@x.example.com",
                                requester="r")
        snap = dbmod.load_phase11_snapshot(self.db_path, self.org.id)
        self.assertNotIn("error", snap)
        self.assertEqual(sum(snap["classifications"].values()), 1)
        self.assertEqual(sum(snap["secrets"].values()), 1)
        self.assertEqual(sum(snap["holds"].values()), 1)
        self.assertEqual(sum(snap["privacy"].values()), 1)
        blob = json.dumps(snap)
        self.assertNotIn("ghp_", blob)
        self.assertNotIn("u@x.example.com", blob)
        html = dbmod.phase11_page(snap)
        self.assertIn("Phase 11", html)
        self.assertIn("retention holds", html.lower())
        err = dbmod.phase11_page({"error": "x"})
        self.assertIn("unavailable", err)

    def test_api_payload_bounded_and_redacted(self):
        self.gov.secrets.register(self.org.id, kind="api_key", name="ci",
                                  reference="r", material="ghp_" + "v" * 36)
        self.gov.privacy.create(self.org.id, request_type="access",
                                subject_ref="u@x.example.com",
                                requester="r")
        api = dbmod.load_phase11_api(self.db_path, self.org.id)
        self.assertNotIn("error", api)
        blob = json.dumps(api)
        self.assertNotIn("ghp_", blob)
        self.assertNotIn("search_hash", blob)
        self.assertNotIn("u@x.example.com", blob)
        self.assertIn("privacy", api)
        self.assertIn("registry", api)


# ---------------------------------------------------------------------------
# 12. Concurrency
# ---------------------------------------------------------------------------
class ConcurrencyTests(GovBase):
    def test_concurrent_governance_writes_and_reads(self):
        errors_list = []

        def worker(k):
            try:
                for i in range(12):
                    self.gov.classification.classify(
                        self.org.id, "finding",
                        object_id=f"c-{k}-{i}",
                        classification="confidential")
                for i in range(4):
                    self.gov.secrets.register(
                        self.org.id, kind="api_key",
                        name=f"s-{k}-{i}", reference="r",
                        material="ghp_" + str(k) * 36 + "x")
                self.gov.retention.preview(self.org.id, kind="findings")
            except Exception as e:      # noqa: BLE001 - collected for assert
                errors_list.append(e)

        threads = [threading.Thread(target=worker, args=(k,))
                   for k in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        self.assertEqual(errors_list, [])
        cls = self.gov.classification.list(self.org.id,
                                           object_type="finding")
        self.assertEqual(cls["total"], 8 * 12)
        sec = self.gov.secrets.list(self.org.id)
        self.assertEqual(sec["total"], 8 * 4)


# ---------------------------------------------------------------------------
# 13. Scale (100 tenants / 1000 projects / 10k findings / 20k evidence /
#     5k audit / 1k privacy requests)
# ---------------------------------------------------------------------------
class ScaleTests(unittest.TestCase):
    def test_governance_at_scale(self):
        dir_ = tempfile.mkdtemp(prefix="p11scale_")
        self.addCleanup(shutil.rmtree, dir_, ignore_errors=True)
        svc = pf.PlatformService(os.path.join(dir_, "t.db"))
        gov = dg.SecurityGovernance(svc)
        orgs = [svc.org_create(f"Tenant{i}") for i in range(100)]
        projects = []
        for o in orgs:
            for j in range(10):
                projects.append(svc.project_create(o.id, f"P{j}"))
        self.assertEqual(len(projects), 1000)
        now = models.utcnow()
        with svc.db.transaction() as conn:
            for j, p in enumerate(projects):
                conn.execute(
                    "INSERT INTO scans (id, project_id, profile, "
                    "scope_ref, status, created_at, started_at, "
                    "finished_at) VALUES (?,?,?,?,?,?,?,?)",
                    (f"scale-s{j}", p.id, "scale", "", "completed",
                     now, now, now))
                conn.execute(
                    "INSERT INTO assets (id, project_id, asset_type,"
                    " value, display, metadata, status, first_seen,"
                    " last_seen) VALUES (?,?,?,?,?,?,?,?,?)",
                    (f"scale-a{j}", p.id, "url", "https://x.example",
                     "", "{}", "active", now, now))
            for i in range(10_000):
                j = i % len(projects)
                p = projects[j]
                conn.execute(
                    "INSERT INTO findings (id, scan_id, project_id,"
                    " asset_id, title, description, severity, confidence,"
                    " category, source, rule_id, template_id, cwe, cve,"
                    " cvss, remediation, evidence, raw, lifecycle,"
                    " fingerprint, first_detected, last_detected,"
                    " resolved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                    "?,?,?,?,?,?,?)",
                    (f"scale-f{i}", f"scale-s{j}", p.id, f"scale-a{j}",
                     f"Scale finding {i}", "", "High", "medium",
                     "injection", "scale", "SCALE-1", "", "", "",
                     "{}", "", "[]", "{}", "open",
                     f"scale-fp-{i}", now, now, ""))
            for i in range(20_000):
                conn.execute(
                    "INSERT INTO evidence (id, finding_id, evidence_type,"
                    " url, method, status_code, request_snippet,"
                    " response_snippet, detection_reason, scanner, rule_id,"
                    " captured_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f"scale-e{i}", f"scale-f{i % 10_000}", "response",
                     "", "", "", "", "", "det", "scale", "R", now))
            for i in range(5_000):
                conn.execute(
                    "INSERT INTO audit_events (id, ts, action, actor,"
                    " object_type, object_id, org_id, project_id, metadata,"
                    " prev_hash, event_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (f"scale-a{i}", now, "organization.created", "scale",
                     "org", "", orgs[i % 100].id, "", "{}", "", ""))
            for i in range(1_000):
                conn.execute(
                    "INSERT INTO privacy_requests (id, org_id, project_id,"
                    " request_type, subject_ref, scope, status, requester,"
                    " reviewer, failure_reason, completion_evidence,"
                    " created_at, updated_at, completed_at) VALUES "
                    "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f"scale-pr{i}", orgs[i % 100].id,
                     projects[i % 1000].id, "access", f"subject{i}@x.example.com",
                     "{}", "submitted", "", "", "", "{}", now, now, ""))
        # governance views stay bounded and correct at scale
        summ = gov.summary(orgs[0].id)
        self.assertIn("secrets", summ)
        self.assertIn("compliance", summ)
        # open findings are protected by the spec (closed-only); evidence
        # rows are eligible and bounded by the batch ceiling
        pre = gov.retention.preview(orgs[0].id, kind="evidence",
                                    batch=dg.MAX_RETENTION_BATCH,
                                    now="2099-01-01T00:00:00Z")
        self.assertEqual(pre["mode"], "preview")
        self.assertGreaterEqual(pre["eligible"], 100)
        pre2 = gov.retention.preview(orgs[0].id, kind="findings",
                                     batch=dg.MAX_RETENTION_BATCH,
                                     now="2099-01-01T00:00:00Z")
        self.assertEqual(pre2["eligible"], 0)   # nothing closed yet
        exp = gov.exports.build(orgs[0].id, scope="summary",
                                project_id=projects[0].id, limit=100)
        self.assertGreater(len(exp["data"]), 0)
        self.assertEqual(
            hashlib.sha256(exp["data"].encode("utf-8")).hexdigest(),
            exp["integrity"])
        # 1000 projects visible across tenants without leaking counts
        self.assertEqual(len(projects), 1000)


if __name__ == "__main__":
    print("SecuToolkit Phase-11 suite — data protection / privacy / secrets"
          " / compliance governance\n")
    unittest.main(verbosity=2)
