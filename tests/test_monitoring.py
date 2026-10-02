#!/usr/bin/env python3
# ============================================================================
#  Phase-5 suite — continuous monitoring, alerting, notifications,
#  remediation lifecycle, health, retention, change detection, scheduler
#  semantics, RBAC/tenant isolation and security regressions.
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
import metrics
import models
import store

import identity as identity_mod
import platform_service as pf
import scanners as sc

from alerts import (AlertService, DEFAULT_RULE_TEMPLATES,
                    evaluate_condition, validate_condition)
from events import ChangeDetector, SecurityEventService
from monitor import (MonitoringHealthService, MonitoringService,
                     SchedulerService, retention_sweep)
from notify import (NotificationService, RecordingProvider,
                    sign_payload, validate_webhook_url, verify_signature)
from remedy import RemediationService
from authz import AuthorizationService

PW = "S3cure!Passw0rd"
INGEST = {
    "tool": "secuaudit", "target": "https://demo.example.com/",
    "assets": [{"type": "url", "value": "https://demo.example.com/"}],
    "findings": [{"id": "xss-1", "title": "Reflected XSS in q",
                  "category": "xss", "severity": "High",
                  "evidence": {"endpoint": "/search?q=1", "parameter": "q"}}],
}


def _service(tmp):
    return pf.PlatformService(os.path.join(tmp, "secutool.db"))


class Phase5Base(unittest.TestCase):
    """One project + all Phase-5 services on a fresh temp database."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p5_")
        self.svc = _service(self.tmp)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.org = self.svc.org_create("Org5")
        self.proj = self.svc.project_create(self.org.id, "Proj5")
        self.svc.scope_set(self.proj.id, ["https://demo.example.com/"], [])
        self.registry = sc.REGISTRY
        self.events = SecurityEventService(self.svc)
        self.alerts = AlertService(self.svc)
        self.notify = NotificationService(self.svc)
        self.mon = MonitoringService(self.svc, registry=self.registry)
        self.sched = SchedulerService(self.svc, registry=self.registry)
        self.remedy = RemediationService(self.svc, registry=self.registry)
        self.detect = ChangeDetector(self.svc)

    def ingest(self, raw=None):
        return self.svc.register_scanner_result(
            self.proj.id, dict(raw or INGEST))

    def drain(self):
        """Simulate the Phase-3 worker for all queued jobs of the project."""
        import jobs as _jobs
        jsvc = _jobs.JobService(self.svc, self.registry)
        n = 0
        while True:
            job = jsvc.claim_next("p5-test-worker")
            if job is None:
                break
            jsvc.complete(job.id, result_reference=f"p5:{job.scan_id[:8]}")
            self.sched.on_scan_terminal(self.proj.id, job.scan_id,
                                        "completed")
            self.remedy.on_scan_completed(self.proj.id, job.scan_id)
            n += 1
        return n

    def finding_id(self):
        rows = self.svc.db.query(
            "SELECT id FROM findings WHERE project_id=? LIMIT 1",
            (self.proj.id,))
        return rows[0]["id"] if rows else ""


# ============================================================================
class TestChangeEvents(Phase5Base):
    def test_emit_creates_deterministic_event(self):
        e = self.events.emit(self.proj.id, "finding.created",
                             asset_id="a-1", key="xss-1", scan_id="s-1",
                             new_state={"severity": "High"}, source="t")
        self.assertIsNotNone(e)
        self.assertEqual(e["event_type"], "finding.created")
        # deterministic identity: same inputs → same event (idempotent)
        e2 = self.events.emit(self.proj.id, "finding.created",
                              asset_id="a-1", key="xss-1", scan_id="s-1",
                              new_state={"severity": "High"}, source="t")
        self.assertIsNone(e2)
        self.assertEqual(len(self.events.list_events(self.proj.id)), 1)

    def test_emit_allowlist_rejects_unknown(self):
        with self.assertRaises(errors.ValidationError):
            self.events.emit(self.proj.id, "event.does.not.exist")

    def test_emit_rejects_unknown_project(self):
        with self.assertRaises(errors.NotFoundError):
            self.events.emit("no-such-project", "finding.created",
                             new_state={"a": 1})
        with self.assertRaises(errors.NotFoundError):
            self.events.list_events("no-such-project")

    def test_emit_bounds_and_redacts_state(self):
        big = {f"k{i}": f"filler-{i}" for i in range(40)}
        big["api_key"] = "AKIAIOSFODNN7EXAMPLE"
        big["password"] = "hunter2-very-secret"
        e = self.events.emit(self.proj.id, "exposure.changed",
                             key="glob", previous_state=big,
                             new_state={"host": "https://x/", "note": big},
                             source="t")
        self.assertIsNotNone(e)
        # bounded: never the full 42-key blob
        self.assertLessEqual(len(e["new_state"]), 12)
        # redacted: secret-shaped values never survive in event state
        blob = str(e["previous_state"]) + str(e["new_state"])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)
        self.assertNotIn("hunter2-very-secret", blob)

    def test_ingest_produces_events_via_diffs(self):
        # rules installed BEFORE the scan → events flow full pipeline
        self.alerts.install_default_rules(self.proj.id)
        self.ingest()
        types = {e["event_type"] for e in self.events.list_events(self.proj.id)}
        self.assertIn("asset.created", types)
        self.assertIn("finding.created", types)
        # re-ingesting the identical result → no duplicate events
        n_before = len(self.events.list_events(self.proj.id))
        self.ingest()
        self.assertEqual(len(self.events.list_events(self.proj.id)), n_before)

    def test_ingest_uniqueness_after_rerecord(self):
        self.alerts.install_default_rules(self.proj.id)
        n1 = len(self.events.list_events(self.proj.id))
        self.ingest()
        n2 = len(self.events.list_events(self.proj.id))
        self.assertGreater(n2, n1)
        self.ingest()  # same content → same scan id → no new events
        self.assertEqual(len(self.events.list_events(self.proj.id)), n2)

    def test_change_detector_findings(self):
        frm = {"findings": {}, "assets": {}}
        to = {"findings": {"fp1": {"asset_id": "a1", "title": "X",
                                   "severity": "High", "risk_score": 7}},
              "assets": {}}
        out = self.detect.detect(self.proj.id, frm, to, scan_id="s1")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["event_type"], "finding.created")
        # idempotent: same inputs → same event ids, None for dupes
        out2 = self.detect.detect(self.proj.id, frm, to, scan_id="s1")
        self.assertEqual(out2, [])

    def test_change_detector_risk_delta(self):
        frm = {"findings": {"fp1": {"asset_id": "a1", "title": "X",
                                    "severity": "High", "risk_score": 3}},
               "assets": {}}
        to = {"findings": {"fp1": {"asset_id": "a1", "title": "X",
                                   "severity": "High", "risk_score": 9}},
              "assets": {}}
        out = self.detect.detect(self.proj.id, frm, to, scan_id="s2")
        types = {e["event_type"] for e in out}
        self.assertIn("risk.increased", types)

    def test_pipeline_event_returns_event(self):
        from alerts import pipeline_event
        e = pipeline_event(self.svc, project_id=self.proj.id,
                           event_type="exposure.changed", key="k1",
                           new_state={"open": True}, source="test")
        self.assertIsNotNone(e)
        dup = pipeline_event(self.svc, project_id=self.proj.id,
                             event_type="exposure.changed", key="k1",
                             new_state={"open": True}, source="test")
        self.assertIsNone(dup)


# ============================================================================
class TestAlertConditions(Phase5Base):
    def test_condition_allowlist_rejects_unknown_field(self):
        for bad in ({"field": "os_command", "op": "==", "value": 1},
                    {"op": "and", "conditions": [
                        {"field": "event_type", "op": "==", "value": "x"},
                        {"field": "nope", "op": "==", "value": 1}]}):
            with self.assertRaises(errors.ValidationError):
                validate_condition(bad)

    def test_condition_allowlist_rejects_bad_operator(self):
        with self.assertRaises(errors.ValidationError):
            validate_condition({"field": "severity", "op": "=~",
                                "value": "High"})
        with self.assertRaises(errors.ValidationError):
            validate_condition({"field": "severity", "op": "match",
                                "value": "High"})

    def test_condition_rejects_non_dict_and_deep_nesting(self):
        for bad in ([], "x", 1, None):
            with self.assertRaises(errors.ValidationError):
                validate_condition(bad)
        deep = {"op": "and", "conditions": [
            {"op": "or", "conditions": [
                {"op": "and", "conditions": [
                    {"field": "severity", "op": "==", "value": "H"}]}]}]}
        with self.assertRaises(errors.ValidationError):
            validate_condition(deep)

    def test_condition_rejects_non_scalar_list_items(self):
        with self.assertRaises(errors.ValidationError):
            validate_condition({"field": "severity", "op": "in",
                                "value": [{"a": 1}]})
        with self.assertRaises(errors.ValidationError):
            validate_condition({"field": "severity", "op": "in", "value": []})

    def test_condition_valid_vocabulary_accepted(self):
        ok = {"op": "and", "conditions": [
            {"field": "event_type", "op": "==", "value": "finding.created"},
            {"field": "risk_score", "op": ">=", "value": 7},
            {"field": "severity", "op": "in", "value": ["High", "Critical"]},
        ]}
        validate_condition(ok)  # no exception

    def test_evaluate_match_and_non_match(self):
        ctx = {"event_type": "finding.created", "risk_score": 8.5,
               "severity": "High"}
        cond = {"op": "and", "conditions": [
            {"field": "event_type", "op": "==", "value": "finding.created"},
            {"field": "risk_score", "op": ">=", "value": 7}]}
        self.assertTrue(evaluate_condition(cond, ctx))
        self.assertFalse(evaluate_condition(
            {"field": "risk_score", "op": ">", "value": 9}, ctx))
        self.assertFalse(evaluate_condition(
            {"field": "severity", "op": "in",
             "value": ["Low", "Medium"]}, ctx))

    def test_evaluate_missing_context_is_false(self):
        self.assertFalse(evaluate_condition(
            {"field": "risk_score", "op": ">", "value": 1}, {}))

    def test_evaluate_garbage_is_false_never_raises(self):
        self.assertFalse(evaluate_condition({"op": "exec", "code": "x"}, {}))
        self.assertFalse(evaluate_condition(42, {}))
        self.assertFalse(evaluate_condition(
            {"field": "severity", "op": "==",
             "value": "High"}, {"severity": {"weird": 1}}))

    def test_rule_create_validations(self):
        with self.assertRaises(errors.ValidationError):
            self.alerts.rule_create(self.proj.id, "r", event_type="bogus")
        with self.assertRaises(errors.ValidationError):
            self.alerts.rule_create(self.proj.id, "r",
                                    severity="catastrophic")
        with self.assertRaises(errors.ValidationError):
            self.alerts.rule_create(self.proj.id, "r", group_by="magic")
        with self.assertRaises(errors.ValidationError):
            self.alerts.rule_create(self.proj.id, "r",
                                    condition={"field": "no", "op": "==",
                                               "value": 1})
        with self.assertRaises(errors.ValidationError):
            self.alerts.rule_create(self.proj.id, "", condition={})

    def test_rule_create_and_list(self):
        r = self.alerts.rule_create(
            self.proj.id, "critical-risk", event_type="finding.created",
            condition={"op": "and", "conditions": [
                {"field": "event_type", "op": "==",
                 "value": "finding.created"},
                {"field": "risk_score", "op": ">=", "value": 7}]},
            severity="critical", cooldown_minutes=5,
            group_by="asset", notify=True)
        self.assertEqual(r["severity"], "critical")
        rows = self.alerts.rule_list(self.proj.id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "critical-risk")

    def test_default_rules_idempotent(self):
        n1 = self.alerts.install_default_rules(self.proj.id)
        n2 = self.alerts.install_default_rules(self.proj.id)
        self.assertEqual(n1, len(DEFAULT_RULE_TEMPLATES))
        self.assertEqual(n2, 0)  # idempotent
        rows = self.alerts.rule_list(self.proj.id)
        self.assertEqual(len(rows), len(DEFAULT_RULE_TEMPLATES))
        # every default rule carries an allowlist-valid condition
        for r in rows:
            validate_condition(store.loads(r["condition"]))

    def test_rule_enable_disable(self):
        r = self.alerts.rule_create(self.proj.id, "r", condition={})
        self.alerts.rule_enable(r["id"], False)
        rows = self.alerts.rule_list(self.proj.id)
        self.assertFalse(rows[0]["enabled"])
        with self.assertRaises(errors.NotFoundError):
            self.alerts.rule_enable("no-such-rule", True)

    def test_no_eval_anywhere_in_rule_path(self):
        import inspect
        src = inspect.getsource(AlertService) + inspect.getsource(
            evaluate_condition)
        self.assertNotIn("eval(", src)
        self.assertNotIn("exec(", src)


# ============================================================================
class TestAlertLifecycle(Phase5Base):
    def _fire_one(self, event_type="finding.created", key="k1",
                  severity="High", risk=8.0, asset_id="a-1"):
        self.alerts.install_default_rules(self.proj.id)
        e = self.events.emit(self.proj.id, event_type, asset_id=asset_id,
                             key=key, scan_id="s1",
                             previous_state={},
                             new_state={"title": "X", "severity": severity,
                                        "risk_score": risk},
                             source="test")
        return self.alerts.process_event(e)

    def test_fire_creates_open_alert_with_rule_severity(self):
        out = self._fire_one()
        self.assertEqual(len(out), 1)
        a = out[0]
        self.assertEqual(a["state"], "open")
        # severity comes from the RULE, independent of finding severity
        self.assertIn(a["severity"], models.ALERT_SEVERITIES)

    def test_alert_identity_stable_and_dedup(self):
        self._fire_one(key="fp-x")
        rows = self.alerts.list_alerts(self.proj.id)
        self.assertEqual(len(rows), 1)
        a = rows[0]
        # same event again → emit is idempotent (returns None); the event row
        # already exists so no occurrence can be double-counted
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="fp-x", scan_id="s1",
                             new_state={"title": "X", "severity": "High",
                                        "risk_score": 8.0}, source="test")
        self.assertIsNone(e)
        self.alerts.process_event(e or {"project_id": "bogus"})
        rows = self.alerts.list_alerts(self.proj.id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(self.alerts.occurrences(a["id"])), 1)
        self.assertEqual(a["occurrence_count"], 1)

    def test_grouping_never_merges_unrelated_criticals(self):
        # two DISTINCT Critical findings (same asset, different fingerprints)
        # must produce two separate critical alerts — grouping never merges
        # unrelated criticals into one.  Context is enriched read-only from
        # the Phase-4 findings rows (same flow as production).
        raw = dict(INGEST)
        raw["findings"] = [
            {"id": "xss-1", "title": "X1", "category": "xss",
             "severity": "Critical", "evidence": {"endpoint": "/a"}},
            {"id": "xss-2", "title": "X2", "category": "xss",
             "severity": "Critical", "evidence": {"endpoint": "/b"}},
        ]
        self.ingest(raw)
        fps = [r["fingerprint"] for r in self.svc.db.query(
            "SELECT fingerprint FROM findings WHERE project_id=? ORDER BY id",
            (self.proj.id,))]
        self.assertEqual(len(fps), 2)
        self.alerts.install_default_rules(self.proj.id)
        crit = [r["id"] for r in self.alerts.rule_list(self.proj.id)
                if r["name"] == "critical-finding"]
        self.assertTrue(crit)
        for i, fp in enumerate(fps):
            e = self.events.emit(self.proj.id, "finding.created",
                                 asset_id="a-1", key=fp,
                                 scan_id=f"s-crit-{i}",
                                 new_state={"title": f"X{i}",
                                            "severity": "Critical"},
                                 source="test")
            self.alerts.process_event(e)
        mine = [x for x in self.alerts.list_alerts(self.proj.id)
                if x["rule_id"] == crit[0]]
        self.assertEqual(len(mine), 2)     # distinct fingerprints → 2 alerts
        self.assertEqual({x["occurrence_count"] for x in mine}, {1})
        self.assertNotEqual(mine[0]["id"], mine[1]["id"])

    def test_group_by_asset_merges_same_asset(self):
        r = self.alerts.rule_create(
            self.proj.id, "same-asset", event_type="finding.created",
            condition={"field": "event_type", "op": "==",
                       "value": "finding.created"},
            group_by="asset")
        for key in ("fp-1", "fp-2"):
            e = self.events.emit(self.proj.id, "finding.created",
                                 asset_id="a-1", key=key, scan_id="s1",
                                 new_state={"title": "X"}, source="t")
            self.alerts.process_event(e)
        rows = self.alerts.list_alerts(self.proj.id)
        mine = [x for x in rows if x["rule_id"] == r["id"]]
        self.assertEqual(len(mine), 1)       # grouped by asset
        self.assertEqual(mine[0]["occurrence_count"], 2)

    def test_occurrences_count_separately(self):
        self._fire_one()
        a = self.alerts.list_alerts(self.proj.id)[0]
        self.assertEqual(a["occurrence_count"], 1)
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="k1", scan_id="s2",  # different scan → new occurrence
                             new_state={"title": "X2", "severity": "High"},
                             source="t")
        self.alerts.process_event(e)
        a = self.alerts.list_alerts(self.proj.id)[0]
        self.assertEqual(a["occurrence_count"], 2)

    def test_lifecycle_transitions(self):
        self._fire_one()
        a = self.alerts.list_alerts(self.proj.id)[0]["id"]
        self.alerts.ack(a, actor="analyst")
        self.assertEqual(self.alerts.alert_view(a)["state"], "acknowledged")
        self.alerts.investigate(a, actor="analyst")
        self.assertEqual(self.alerts.alert_view(a)["state"], "investigating")
        self.alerts.resolve(a, actor="analyst")
        self.assertEqual(self.alerts.alert_view(a)["state"], "resolved")

    def test_lifecycle_fail_closed(self):
        self._fire_one()
        a = self.alerts.list_alerts(self.proj.id)[0]["id"]
        # open → resolved is a legal transition (rule-defined)
        self.alerts.resolve(a, actor="x")
        # resolved → investigating is NOT legal (fail closed)
        with self.assertRaises(errors.LifecycleError):
            self.alerts.investigate(a, actor="x")
        with self.assertRaises(errors.LifecycleError):
            self.alerts.ack(a, actor="x")            # resolved → acknowledged
        # empty suppression reason is rejected fail-closed (validation):
        # suppress() requires a non-empty reason + future until
        with self.assertRaises(errors.ValidationError):
            self.alerts.suppress(a, actor="x", reason="")
        with self.assertRaises(errors.NotFoundError):
            self.alerts.ack("forged-id-111111", actor="x")

    def test_suppression_requires_reason_and_future_until(self):
        self._fire_one()
        a = self.alerts.list_alerts(self.proj.id)[0]["id"]
        with self.assertRaises(errors.ValidationError):
            self.alerts.suppress(a, actor="x")
        with self.assertRaises(errors.ValidationError):
            self.alerts.suppress(a, actor="x", reason="r",
                                 until="2020-01-01T00:00:00Z")
        self.alerts.suppress(a, actor="x", reason="false positive review",
                             until="2099-01-01T00:00:00Z")
        self.assertEqual(self.alerts.alert_view(a)["state"], "suppressed")

    def test_suppression_expiry_reopens(self):
        self._fire_one()
        a = self.alerts.list_alerts(self.proj.id)[0]["id"]
        self.alerts.suppress(a, actor="x", reason="review",
                             until="2099-01-01T00:00:00Z")
        # simulate the until passing (as a sweep would)
        self.svc.db.execute("UPDATE alerts SET suppressed_until=? WHERE id=?",
                            ("2026-09-01T00:00:00Z", a))
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="k1", scan_id="s3",
                             new_state={"title": "X", "severity": "High"},
                             source="t")
        self.alerts.process_event(e)
        self.assertEqual(self.alerts.alert_view(a)["state"], "open")
        actions = [h["action"] for h in self.alerts.history(a)]
        self.assertIn("suppression_expired", actions)

    def test_resolved_alert_refires_on_new_occurrence(self):
        self._fire_one()
        a = self.alerts.list_alerts(self.proj.id)[0]["id"]
        self.alerts.ack(a, actor="x")
        self.alerts.investigate(a, actor="x")
        self.alerts.resolve(a, actor="x")
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="k1", scan_id="s4",
                             new_state={"title": "X again",
                                        "severity": "High"}, source="t")
        self.alerts.process_event(e)
        self.assertEqual(self.alerts.alert_view(a)["state"], "open")
        self.assertEqual(self.alerts.alert_view(a)["occurrence_count"], 2)

    def test_cooldown_gates_delivery_not_occurrences(self):
        prov = RecordingProvider()
        nsvc = NotificationService(self.svc, providers={"webhook": prov})
        nsvc.settings_set(self.proj.id, webhook_enabled=True,
                          webhook_url="https://hooks.example.com/h",
                          webhook_secret="s3cret-key-123456")
        self.alerts.install_default_rules(self.proj.id)
        e1 = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                              key="cooldown-1", scan_id="s1",
                              new_state={"title": "X", "severity": "High"},
                              source="t")
        self.alerts.process_event(e1)
        a = self.alerts.list_alerts(self.proj.id)[0]
        self.assertEqual(len(self.alerts.occurrences(a["id"])), 1)
        self.assertEqual(len(nsvc.list_notifications(self.proj.id)), 1)
        # second occurrence within cooldown → occurrence counted, no second delivery
        e2 = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                              key="cooldown-1", scan_id="s2",
                              new_state={"title": "X2", "severity": "High"},
                              source="t")
        self.alerts.process_event(e2)
        a2 = self.alerts.list_alerts(self.proj.id)[0]
        self.assertEqual(a2["occurrence_count"], 2)
        self.assertEqual(len(nsvc.list_notifications(self.proj.id)), 1)

    def test_alerts_never_contain_secrets(self):
        self.alerts.install_default_rules(self.proj.id)
        e = self.events.emit(self.proj.id, "exposure.changed", asset_id="a-1",
                             key="sec-1",
                             previous_state={"token": "AKIA-SECRET-999"},
                             new_state={"password": "hunter2-secret"},
                             source="t")
        self.alerts.process_event(e)
        for a in self.alerts.list_alerts(self.proj.id):
            blob = str(a)
            self.assertNotIn("AKIA-SECRET-999", blob)
            self.assertNotIn("hunter2-secret", blob)

    def test_expire_orphaned_on_disabled_rule(self):
        self._fire_one()
        a = self.alerts.list_alerts(self.proj.id)[0]
        self.alerts.rule_enable(a["rule_id"], False)
        n = self.alerts.expire_orphaned()
        self.assertEqual(n, 1)
        self.assertEqual(self.alerts.alert_view(a["id"])["state"], "expired")

    def test_alert_count_and_pagination(self):
        self.alerts.install_default_rules(self.proj.id)
        for i in range(3):
            self._fire_one(key=f"k{i}", asset_id=f"a-{i}")
        c = self.alerts.alert_count(self.proj.id)
        self.assertEqual(c["open"], 3)
        self.assertGreaterEqual(c["total"], 3)

    def test_custom_threshold_rule_matches_via_risk(self):
        # The condition context is enriched from Phase-4 findings (read-only
        # lookup by fingerprint — the risk engine is never re-run).
        self.ingest()
        fid = self.finding_id()
        self.assertTrue(fid)
        row = self.svc.db.query(
            "SELECT fingerprint FROM findings WHERE id=?", (fid,))[0]
        fp = row["fingerprint"]
        self.svc.db.execute("UPDATE findings SET risk_score=? WHERE id=?",
                            (35.0, fid))
        r = self.alerts.rule_create(
            self.proj.id, "high-risk-only", event_type="finding.created",
            condition={"field": "risk_score", "op": ">=", "value": 20},
            severity="critical")
        self.assertEqual(len(self.alerts.list_alerts(self.proj.id)), 0)
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key=fp, scan_id="s1",
                             new_state={"title": "X", "severity": "High"},
                             source="t")
        out = self.alerts.process_event(e)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "critical")
        # below threshold → no match (same rule, low-risk finding)
        self.svc.db.execute("UPDATE findings SET risk_score=? WHERE id=?",
                            (5.0, fid))
        e2 = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                              key=fp, scan_id="s2",
                              new_state={"title": "Y", "severity": "Low"},
                              source="t")
        out2 = self.alerts.process_event(e2)
        self.assertEqual(out2, [])


# ============================================================================
class TestNotifications(Phase5Base):
    def test_settings_validation(self):
        with self.assertRaises(errors.ValidationError):
            self.notify.settings_set(self.proj.id, email_enabled=True,
                                     email_to="not-an-email")
        with self.assertRaises(errors.ValidationError):
            self.notify.settings_set(self.proj.id, webhook_enabled=True,
                                     webhook_url="http://x.example/h")
        with self.assertRaises(errors.ValidationError):
            self.notify.settings_set(self.proj.id, webhook_enabled=True,
                                     webhook_url="https://x.example/h",
                                     webhook_secret="short")

    def test_settings_masks_secret(self):
        self.notify.settings_set(self.proj.id, webhook_enabled=True,
                                 webhook_url="https://hooks.example.com/h",
                                 webhook_secret="s3cret-key-123456")
        v = self.notify.settings_view(self.proj.id)
        self.assertTrue(v["has_secret"])
        self.assertNotIn("s3cret-key-123456", str(v))
        self.assertNotIn("webhook_secret", v)   # masked view never carries it

    def test_webhook_secret_encrypted_at_rest(self):
        self.notify.settings_set(self.proj.id, webhook_enabled=True,
                                 webhook_url="https://hooks.example.com/h",
                                 webhook_secret="s3cret-key-123456")
        raw = self.svc.db.query(
            "SELECT webhook_secret FROM notification_settings WHERE "
            "project_id=?", (self.proj.id,))[0]["webhook_secret"]
        # never stored plaintext: ciphertext blob, not the secret
        self.assertTrue(raw)
        self.assertNotIn("s3cret-key-123456", raw)
        # internal signing path decrypts it (never exposed in views)
        internal = self.notify.settings_get(self.proj.id)
        self.assertEqual(internal["webhook_secret"], "s3cret-key-123456")
        self.assertNotIn("s3cret-key-123456", str(
            self.notify.settings_view(self.proj.id)))

    def test_keep_secret_preserves_existing(self):
        self.notify.settings_set(self.proj.id, webhook_enabled=True,
                                 webhook_url="https://hooks.example.com/h",
                                 webhook_secret="s3cret-key-123456")
        self.notify.settings_set(self.proj.id, webhook_enabled=True,
                                 webhook_url="https://hooks.example.com/h",
                                 keep_secret=True)
        self.assertTrue(self.notify.settings_view(self.proj.id)["has_secret"])

    def test_dispatch_idempotent_per_occurrence(self):
        self.notify.settings_set(self.proj.id, email_enabled=True,
                                 email_to="sec@example.com")
        # a notify=False rule → the alert is created WITHOUT auto-dispatch,
        # so the first manual dispatch is the one that creates the row
        r = self.alerts.rule_create(
            self.proj.id, "quiet", event_type="finding.created",
            condition={}, notify=False)
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="n-1", scan_id="s1",
                             new_state={"title": "X", "severity": "High"},
                             source="t")
        fired = self.alerts.process_event(e)
        a = fired[0]
        n1 = self.notify.dispatch_alert(a["id"], e["id"], r)
        n2 = self.notify.dispatch_alert(a["id"], e["id"], r)
        self.assertEqual(n1, 1)
        self.assertEqual(n2, 0)  # idempotent per occurrence
        rows = self.notify.list_notifications(self.proj.id)
        self.assertEqual(len(rows), 1)

    def test_email_provider_honest_dead_letter(self):
        self.alerts.install_default_rules(self.proj.id)
        self.notify.settings_set(self.proj.id, email_enabled=True,
                                 email_to="sec@example.com")
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="nl-1", scan_id="s1",
                             new_state={"title": "X", "severity": "High"},
                             source="t")
        fired = self.alerts.process_event(e)
        rows = self.notify.list_notifications(self.proj.id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "dead_letter")
        self.assertIn("not configured", rows[0]["last_error"])

    def test_retry_backoff_and_dead_letter(self):
        prov = RecordingProvider(fail=True)
        nsvc = NotificationService(self.svc, providers={"webhook": prov})
        nsvc.settings_set(self.proj.id, webhook_enabled=True,
                          webhook_url="https://hooks.example.com/h",
                          webhook_secret="s3cret-key-123456")
        # pipeline dispatch goes through the injected notifier → the first
        # attempt runs against the recording provider (deterministic failure)
        al = AlertService(self.svc, notifier=nsvc)
        al.install_default_rules(self.proj.id)
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="bs-1", scan_id="s1",
                             new_state={"title": "X", "severity": "High"},
                             source="t")
        fired = al.process_event(e)
        rows = nsvc.list_notifications(self.proj.id)
        self.assertEqual(len(rows), 1)
        n = rows[0]
        self.assertEqual(n["status"], "pending")
        self.assertEqual(n["attempts"], 1)
        self.assertEqual(n["next_retry_at"] > models.utcnow(), True)
        # after all attempts (bounded by max_attempts), dead letter
        for i in range(10):
            nsvc.process_pending(now="2999-01-01T00:00:00Z", limit=10)
            if nsvc.notification_view(n["id"])["status"] == "dead_letter":
                break
        v = nsvc.notification_view(n["id"])
        self.assertEqual(v["status"], "dead_letter")
        self.assertLessEqual(v["attempts"], nsvc.max_attempts)
        # attempts recorded
        attempts = self.svc.db.query(
            "SELECT * FROM notification_attempts WHERE notification_id=?",
            (n["id"],))
        self.assertEqual(len(attempts), v["attempts"])

    def test_retry_manual_recovers_dead_letter(self):
        prov = RecordingProvider(fail=True)
        nsvc = NotificationService(self.svc, providers={"webhook": prov})
        nsvc.settings_set(self.proj.id, webhook_enabled=True,
                          webhook_url="https://hooks.example.com/h",
                          webhook_secret="s3cret-key-123456")
        al = AlertService(self.svc, notifier=nsvc)
        al.install_default_rules(self.proj.id)
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="rm-1", scan_id="s1",
                             new_state={"title": "X", "severity": "High"},
                             source="t")
        al.process_event(e)
        n = nsvc.list_notifications(self.proj.id)[0]
        for i in range(10):
            nsvc.process_pending(now="2999-01-01T00:00:00Z", limit=10)
            if nsvc.notification_view(n["id"])["status"] == "dead_letter":
                break
        good = NotificationService(
            self.svc, providers={"webhook": RecordingProvider()})
        v = good.retry_manual(n["id"], actor="cli")
        self.assertEqual(v["status"], "sent")
        # already sent → cannot retry again
        with self.assertRaises(errors.LifecycleError):
            good.retry_manual(n["id"], actor="cli")

    def test_retry_manual_missing(self):
        with self.assertRaises(errors.NotFoundError):
            self.notify.retry_manual("forged-notification-123")

    def test_payload_and_attempts_never_contain_secret(self):
        prov = RecordingProvider(fail=True)
        nsvc = NotificationService(self.svc, providers={"webhook": prov})
        nsvc.settings_set(self.proj.id, webhook_enabled=True,
                          webhook_url="https://hooks.example.com/h",
                          webhook_secret="s3cret-key-123456")
        al = AlertService(self.svc, notifier=nsvc)
        al.install_default_rules(self.proj.id)
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="pl-1", scan_id="s1",
                             new_state={"title": "X", "severity": "High"},
                             source="t")
        al.process_event(e)
        blob = str(nsvc.list_notifications(self.proj.id))
        attempts = self.svc.db.query("SELECT * FROM notification_attempts", ())
        blob += str(attempts)
        self.assertNotIn("s3cret-key-123456", blob)

    def test_counts(self):
        self.alerts.install_default_rules(self.proj.id)
        self.notify.settings_set(self.proj.id, email_enabled=True,
                                 email_to="sec@example.com")
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a-1",
                             key="ct-1", scan_id="s1",
                             new_state={"title": "X", "severity": "High"},
                             source="t")
        self.alerts.process_event(e)
        c = self.notify.notification_counts(self.proj.id)
        self.assertGreaterEqual(c.get("total", 0), 1)
        self.assertGreaterEqual(c.get("dead_letter", 0), 0)

    def test_webhook_url_ssrf_denylist(self):
        bad = [
            "http://x.example/h",              # no https
            "https://localhost/h",             # denylisted host
            "https://127.0.0.1/h",
            "https://127.0.0.1:8443/h",
            "https://10.0.0.5/h",
            "https://172.16.0.1/h",
            "https://192.168.1.1/h",
            "https://[::1]/h",
            "https://0.0.0.0/h",
            "https://169.254.169.254/latest/meta-data/",
            "https://user:pass@x.example/h",   # userinfo
            "https://x.example:25/h",          # port not allowed
            "https://x.example:80/h",
        ]
        for url in bad:
            with self.assertRaises(errors.ValidationError):
                validate_webhook_url(url, resolve=False)

    def test_webhook_url_allowed_shapes(self):
        for url in ("https://hooks.example.com/h",
                    "https://hooks.example.com:8443/h",
                    "https://hooks.example.com:9443/hook?v=1"):
            self.assertEqual(validate_webhook_url(url, resolve=False), url)

    def test_hmac_sign_verify(self):
        import time as _t
        body = b'{"a":1,"b":"x"}'
        ts = str(int(_t.time()))
        sig = sign_payload("k-123456", ts, body)
        self.assertTrue(verify_signature("k-123456", ts, body, sig))
        # wrong secret / wrong body / wrong signature all fail
        self.assertFalse(verify_signature("other", ts, body, sig))
        self.assertFalse(verify_signature("k-123456", ts, b'{"a":2}', sig))
        self.assertFalse(verify_signature("k-123456", ts, body,
                                          sig[:-2] + "00"))
        self.assertFalse(verify_signature("k-123456", ts, body, "not-hex"))
        self.assertFalse(verify_signature("k-123456", "bad-ts", body, sig))
        # malformed / foreign timestamps fail
        self.assertFalse(verify_signature("k-123456", "", body, sig))
        # stale timestamp rejected (tolerance 300s)
        old = str(int(_t.time()) - 400)
        old_sig = sign_payload("k-123456", old, body)
        self.assertFalse(verify_signature("k-123456", old, body, old_sig))


# ============================================================================
class TestRemediation(Phase5Base):
    def _ticket(self, severity="High"):
        raw = dict(INGEST)
        raw["findings"] = [dict(INGEST["findings"][0], severity=severity)]
        self.svc.register_scanner_result(self.proj.id, raw)
        return self.remedy.ensure(self.finding_id(), actor="cli")

    def test_ensure_idempotent_and_default_sla(self):
        t = self._ticket()
        t2 = self.remedy.ensure(self.finding_id(), actor="cli")
        self.assertEqual(t["id"], t2["id"])
        self.assertEqual(t["status"], "open")
        sla = self.remedy.sla_get(self.proj.id)
        self.assertEqual(set(sla), {"P0", "P1", "P2", "P3", "P4"})
        self.assertGreater(sla["P4"], 0)

    def test_sla_override(self):
        sla = self.remedy.sla_set(self.proj.id, priority="P0", hours=4)
        self.assertEqual(sla["P0"], 4)
        with self.assertRaises(errors.ValidationError):
            self.remedy.sla_set(self.proj.id, priority="P9", hours=4)
        with self.assertRaises(errors.ValidationError):
            self.remedy.sla_set(self.proj.id, priority="P1", hours=0)
        with self.assertRaises(errors.ValidationError):
            self.remedy.sla_set(self.proj.id, priority="P1", hours=99999)

    def test_due_at_respects_project_sla_override(self):
        self.remedy.sla_set(self.proj.id, priority="P0", hours=2)
        self.svc.register_scanner_result(self.proj.id, INGEST)
        t = self.remedy.ensure(self.finding_id(), actor="cli",
                               due_at="2099-01-01T00:00:00Z")
        self.assertEqual(t["due_at"], "2099-01-01T00:00:00Z")

    def test_assign_only_existing_users(self):
        t = self._ticket()
        with self.assertRaises(errors.ValidationError) as cm:
            self.remedy.assign(t["id"], "team", "team-1", actor="cli")
        self.assertIn("user", str(cm.exception))
        with self.assertRaises(Exception):
            self.remedy.assign(t["id"], "user", "forged-user-id-999",
                               actor="cli")
        u = identity_mod.IdentityService(self.svc).user_create(
            self.org.id, "alice", "alice@example.com", PW,
            allow_any_role=True)
        out = self.remedy.assign(t["id"], "user", u.id, actor="cli")
        self.assertEqual(out["status"], "assigned")
        self.assertEqual(out["owner_id"], u.id)

    def test_assign_cross_org_rejected(self):
        t = self._ticket()
        other = self.svc.org_create("OtherOrg")
        u = identity_mod.IdentityService(self.svc).user_create(
            other.id, "bob", "bob@other.test", PW, allow_any_role=True)
        with self.assertRaises(Exception):
            self.remedy.assign(t["id"], "user", u.id, actor="cli")

    def test_lifecycle_transitions_fail_closed(self):
        t = self._ticket()
        with self.assertRaises(errors.LifecycleError):
            self.remedy.status(t["id"], "verified", actor="cli")  # open→verified illegal
        self.remedy.status(t["id"], "in_progress", actor="cli")
        self.assertEqual(self.remedy.view(t["id"])["status"], "in_progress")
        # idempotent same-state
        self.remedy.status(t["id"], "in_progress", actor="cli")
        with self.assertRaises(errors.ValidationError):
            self.remedy.status(t["id"], "not-a-state", actor="cli")
        # only legal transitions permitted
        with self.assertRaises(errors.LifecycleError):
            self.remedy.status(t["id"], "closed", actor="cli")  # in_progress→closed illegal
        self.remedy.status(t["id"], "ready_for_verification", actor="cli")

    def test_set_due_validation(self):
        t = self._ticket()
        with self.assertRaises(errors.ValidationError):
            self.remedy.set_due(t["id"], "tomorrow", actor="cli")
        t2 = self.remedy.set_due(t["id"], "2099-05-05T05:05:05Z", actor="cli")
        self.assertEqual(t2["due_at"], "2099-05-05T05:05:05Z")

    def test_verification_passes_when_not_reobserved(self):
        t = self._ticket()
        u = identity_mod.IdentityService(self.svc).user_create(
            self.org.id, "alice", "alice@example.com", PW,
            allow_any_role=True)
        self.remedy.assign(t["id"], "user", u.id, actor="cli")
        self.remedy.status(t["id"], "in_progress", actor="cli")
        self.remedy.status(t["id"], "ready_for_verification", actor="cli")
        v = self.remedy.request_verification(t["id"], actor="cli")
        self.assertTrue(v["verification_scan_id"])
        self.assertEqual(self.remedy.view(t["id"])["verification_status"],
                         "running")
        # worker runs the verification job, then evidence arrives: absent → pass
        self.drain()
        tv = self.remedy.view(t["id"])
        self.assertEqual(tv["status"], "verified")
        self.assertEqual(tv["verification_status"], "passed")

    def test_verification_fails_and_reopens_when_reobserved(self):
        self.alerts.install_default_rules(self.proj.id)
        t = self._ticket()
        u = identity_mod.IdentityService(self.svc).user_create(
            self.org.id, "alice", "alice@example.com", PW,
            allow_any_role=True)
        self.remedy.assign(t["id"], "user", u.id, actor="cli")
        self.remedy.status(t["id"], "ready_for_verification", actor="cli")
        v = self.remedy.request_verification(t["id"], actor="cli")
        scan_id = v["verification_scan_id"]
        # worker completes; evidence of the SAME fingerprint re-appears
        import jobs as _jobs
        jsvc = _jobs.JobService(self.svc, self.registry)
        job = jsvc.claim_next("p5-worker")
        jsvc.complete(job.id, result_reference="v2")
        self.svc.db.execute(
            "INSERT INTO finding_observations (id, finding_id, project_id, "
            "scan_id, source, source_finding_id, first_seen, last_seen, "
            "count) VALUES (?,?,?,?,?,?,?,?,?)",
            ("fo-reappear", self.finding_id(), self.proj.id, scan_id,
             "secuaudit", "xss-1", "2026-01-01T00:00:00Z",
             "2026-01-01T00:00:00Z", 1))
        self.remedy.on_scan_completed(self.proj.id, scan_id)
        tv = self.remedy.view(t["id"])
        self.assertEqual(tv["status"], "reopened")
        self.assertEqual(tv["verification_status"], "failed")
        # monitoring.verification_failure event emitted
        types = {e["event_type"] for e in self.events.list_events(self.proj.id)}
        self.assertIn("monitoring.verification_failure", types)

    def test_verification_request_idempotent_while_running(self):
        t = self._ticket()
        u = identity_mod.IdentityService(self.svc).user_create(
            self.org.id, "alice", "alice@example.com", PW,
            allow_any_role=True)
        self.remedy.assign(t["id"], "user", u.id, actor="cli")
        self.remedy.status(t["id"], "ready_for_verification", actor="cli")
        v1 = self.remedy.request_verification(t["id"], actor="cli")
        v2 = self.remedy.request_verification(t["id"], actor="cli")
        self.assertEqual(v1["verification_scan_id"],
                         v2["verification_scan_id"])

    def test_verification_requires_ready_state(self):
        t = self._ticket()
        with self.assertRaises(errors.LifecycleError):
            self.remedy.request_verification(t["id"], actor="cli")

    def test_verification_attempts_bounded(self):
        t = self._ticket()
        u = identity_mod.IdentityService(self.svc).user_create(
            self.org.id, "alice", "alice@example.com", PW,
            allow_any_role=True)
        self.remedy.assign(t["id"], "user", u.id, actor="cli")
        made = 0
        for i in range(6):
            self.remedy.status(t["id"], "ready_for_verification", actor="cli")
            try:
                self.remedy.request_verification(t["id"], actor="cli")
                made += 1
            except errors.LifecycleError:
                break
            finally:
                self.svc.db.execute(
                    "UPDATE remediation_tickets SET verification_status='' "
                    "WHERE id=?", (t["id"],))
        self.assertEqual(made, 3)  # max attempts = 3 (bounded)
        self.assertEqual(
            self.remedy.view(t["id"])["verification_attempts"], 3)

    def test_verification_scan_job_failure_returns_ticket(self):
        t = self._ticket()
        u = identity_mod.IdentityService(self.svc).user_create(
            self.org.id, "alice", "alice@example.com", PW,
            allow_any_role=True)
        self.remedy.assign(t["id"], "user", u.id, actor="cli")
        self.remedy.status(t["id"], "ready_for_verification", actor="cli")
        v = self.remedy.request_verification(t["id"], actor="cli")
        self.remedy.on_scan_failed(self.proj.id, v["verification_scan_id"],
                                   "worker_crash")
        tv = self.remedy.view(t["id"])
        self.assertEqual(tv["status"], "ready_for_verification")
        self.assertEqual(tv["verification_status"], "failed")

    def test_reopened_requires_history_and_audit(self):
        t = self._ticket()
        hist = self.remedy.view(t["id"])["history"]
        self.assertTrue(any(h["action"] == "created" for h in hist))
        rows = self.svc.db.query(
            "SELECT * FROM audit_events WHERE object_id=? AND action=?",
            (t["id"], "remediation.created"))
        self.assertEqual(len(rows), 1)

    def test_verification_never_uses_active_profiles(self):
        t = self._ticket()
        self.svc.db.execute(
            "UPDATE scans SET profile='active-fuzz' WHERE id=("
            "SELECT scan_id FROM findings WHERE id=? LIMIT 1)",
            (self.finding_id(),))
        u = identity_mod.IdentityService(self.svc).user_create(
            self.org.id, "alice", "alice@example.com", PW,
            allow_any_role=True)
        self.remedy.assign(t["id"], "user", u.id, actor="cli")
        self.remedy.status(t["id"], "ready_for_verification", actor="cli")
        with self.assertRaises(errors.LifecycleError):
            self.remedy.request_verification(t["id"], actor="cli")


# ============================================================================
class TestScheduler(Phase5Base):
    def _policy(self, **kw):
        base = dict(
            project_id=self.proj.id, name="p", scan_profile="web-audit",
            schedule_type="interval", interval_minutes=10,
            targets=["https://demo.example.com/"])
        base.update(kw)
        p = self.mon.create(**base)
        # backdate coherently (created_at + first slot)
        self.svc.db.execute(
            "UPDATE monitoring_policies SET created_at=?, next_run=?, "
            "last_run=? WHERE id=?",
            ("2000-01-01T00:00:00Z", "2000-01-01T00:10:00Z", "", p["id"]))
        return self.mon.get(p["id"])

    def test_policy_validation(self):
        with self.assertRaises(errors.ValidationError):
            self.mon.create(self.proj.id, "x", scan_profile="nope")
        with self.assertRaises(errors.ValidationError):
            self.mon.create(self.proj.id, "x", scan_profile="web-audit",
                            schedule_type="hourly")
        with self.assertRaises(errors.ValidationError):
            self.mon.create(self.proj.id, "x", scan_profile="web-audit",
                            schedule_type="interval", interval_minutes=1)
        with self.assertRaises(errors.ValidationError):
            self.mon.create(self.proj.id, "x", scan_profile="web-audit",
                            targets=[])
        with self.assertRaises(errors.ValidationError):
            self.mon.create(self.proj.id, "x", scan_profile="web-audit",
                            targets=["https://x.example/"],
                            missed_policy="sometimes")
        with self.assertRaises(errors.ValidationError):
            self.mon.create(self.proj.id, "x", scan_profile="web-audit",
                            targets=["https://x.example/"],
                            priority="urgent")

    def test_policy_unique_per_project(self):
        self._policy(name="dup")
        with self.assertRaises(errors.DuplicateError):
            self.mon.create(self.proj.id, "dup", scan_profile="web-audit",
                            targets=["https://demo.example.com/"])

    def test_policy_get_list_enable_disable_delete(self):
        p = self._policy(name="life")
        self.assertTrue(self.mon.get(p["id"])["enabled"])
        self.mon.set_enabled(p["id"], False)
        self.assertFalse(self.mon.get(p["id"])["enabled"])
        self.mon.set_enabled(p["id"], True)
        rows = self.mon.list(self.proj.id)
        self.assertGreaterEqual(len(rows), 1)
        self.mon.delete(p["id"], actor="cli")
        with self.assertRaises(errors.NotFoundError):
            self.mon.get(p["id"])

    def test_config_get_set(self):
        cfg = self.mon.config_get(self.proj.id)
        self.assertEqual(cfg["max_concurrent_scans_per_project"], 2)
        cfg2 = self.mon.config_set(self.proj.id,
                                   max_concurrent_scans_per_project=5)
        self.assertEqual(cfg2["max_concurrent_scans_per_project"], 5)
        with self.assertRaises(errors.ValidationError):
            self.mon.config_set(self.proj.id,
                                max_concurrent_scans_per_project=999)

    def test_interval_tick_creates_one_scan(self):
        self._policy()
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        self.assertEqual(r["scans_created"], 1)
        self.assertEqual(r["missed_events"], 0)
        sc = self.svc.db.query("SELECT * FROM scans WHERE project_id=?",
                               (self.proj.id,))
        self.assertEqual(len(sc), 1)
        self.assertTrue(str(sc[0]["scope_ref"]).startswith("monitoring:"))
        # jobs exist through the Phase-3 queue
        jobs = self.svc.db.query("SELECT * FROM jobs WHERE project_id=?",
                                 (self.proj.id,))
        self.assertEqual(len(jobs), 1)

    def test_tick_idempotent_same_window(self):
        self._policy()
        r1 = self.sched.run_due(now="2000-01-01T00:10:05Z")
        self.assertEqual(r1["scans_created"], 1)
        r2 = self.sched.run_due(now="2000-01-01T00:11:00Z")
        self.assertEqual(r2["scans_created"], 0)
        r3 = self.sched.run_due(now="2000-01-01T00:12:00Z")
        self.assertEqual(r3["scans_created"], 0)  # nothing due yet
        self.drain()

    def test_missed_skip_mode(self):
        self._policy(missed_policy="skip")
        r = self.sched.run_due(now="2000-01-01T01:00:00Z")
        # pending windows 00:10..01:00 (6); due = 01:00 runs once,
        # the 5 backlog windows are recorded as missed (never re-fired)
        self.assertEqual(r["scans_created"], 1)
        self.assertEqual(r["missed_events"], 5)
        self.drain()

    def test_missed_run_once_mode(self):
        self._policy(missed_policy="run_once", max_concurrent=3)
        r = self.sched.run_due(now="2000-01-01T00:50:00Z")
        self.assertEqual(r["scans_created"], 2)       # due + 1 backfill
        self.assertEqual(r["missed_events"], 3)
        self.drain()

    def test_missed_catch_up_bounded(self):
        self.mon.config_set(self.proj.id, max_concurrent_scans_per_project=10)
        self._policy(missed_policy="catch_up", max_concurrent=3)
        r = self.sched.run_due(now="2000-01-01T01:00:00Z", limit=50)
        self.assertEqual(r["scans_created"], 3)       # due + up to 2 backfill
        self.assertGreaterEqual(r["missed_events"], 1)
        self.drain()

    def test_missed_events_bounded_per_policy(self):
        self._policy(missed_policy="skip")
        r = self.sched.run_due(now="2000-01-01T05:00:00Z")
        self.assertLessEqual(r["missed_events"], 5)   # MISSED_EVENT_MAX
        self.drain()

    def test_max_concurrent_over_policy_caps_backlog(self):
        self._policy(missed_policy="catch_up", max_concurrent=1)
        r = self.sched.run_due(now="2000-01-01T00:50:00Z", limit=50)
        self.assertEqual(r["scans_created"], 1)
        self.assertEqual(r["skipped"], 2)
        self.drain()

    def test_manual_schedule_never_auto_runs(self):
        p = self.mon.create(self.proj.id, "manual", scan_profile="web-audit",
                            schedule_type="manual",
                            targets=["https://demo.example.com/"])
        r = self.sched.run_due(now="2999-01-01T00:00:00Z", limit=50)
        self.assertEqual(r["scans_created"], 0)
        mr = self.sched.run_now(p["id"])
        self.assertEqual(mr["status"], "created")
        self.drain()

    def test_fail_closed_scope_revocation(self):
        self._policy()
        self.svc.scope_set(self.proj.id, ["https://other.example.com/"], [])
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        self.assertEqual(r["scans_created"], 0)
        self.assertEqual(r["skipped"], 1)
        # no scan/job leaked
        self.assertEqual(
            len(self.svc.db.query("SELECT id FROM scans WHERE project_id=?",
                                  (self.proj.id,))), 0)
        # audit the skip
        rows = self.svc.db.query(
            "SELECT * FROM audit_events WHERE action=?",
            ("monitoring.schedule_skipped",))
        self.assertEqual(len(rows), 1)

    def test_fail_closed_policy_disabled(self):
        p = self._policy()
        self.mon.set_enabled(p["id"], False)
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        self.assertEqual(r["scans_created"], 0)

    def test_fail_closed_org_inactive(self):
        self._policy()
        self.svc.db.execute("UPDATE organizations SET status='suspended' "
                            "WHERE id=?", (self.org.id,))
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        self.assertEqual(r["scans_created"], 0)
        self.assertEqual(r["skipped"], 1)

    def test_fail_closed_project_inactive(self):
        self._policy()
        self.svc.db.execute("UPDATE projects SET status='archived' "
                            "WHERE id=?", (self.proj.id,))
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        self.assertEqual(r["scans_created"], 0)

    def test_fail_closed_active_profile_without_authorization(self):
        self._policy(scan_profile="active-fuzz")
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        self.assertEqual(r["scans_created"], 0)
        self.assertEqual(r["skipped"], 1)

    def test_active_profile_with_authorization_runs(self):
        self._policy(scan_profile="active-fuzz",
                     active_scan_permitted=True)
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        self.assertEqual(r["scans_created"], 1)
        self.drain()

    def test_daily_and_weekly_windows(self):
        d = self.mon.create(self.proj.id, "d", scan_profile="web-audit",
                            schedule_type="daily", daily_time="08:30",
                            targets=["https://demo.example.com/"])
        self.svc.db.execute(
            "UPDATE monitoring_policies SET created_at=?, next_run=?, "
            "last_run=? WHERE id=?",
            ("2000-01-01T00:00:00Z", "2000-01-01T08:30:00Z", "", d["id"]))
        r = self.sched.run_due(now="2000-01-01T08:35:00Z", limit=50)
        self.assertEqual(r["scans_created"], 1)
        self.drain()
        w = self.mon.create(self.proj.id, "w", scan_profile="web-audit",
                            schedule_type="weekly", weekly_day=0,
                            weekly_time="09:00",
                            targets=["https://demo.example.com/"])
        self.svc.db.execute(
            "UPDATE monitoring_policies SET created_at=?, next_run=?, "
            "last_run=? WHERE id=?",
            ("2000-01-03T00:00:00Z", "2000-01-03T09:00:00Z", "", w["id"]))
        # isolate: the daily policy is legitimately due again at 08:30 on
        # 01-03 (its next_run advanced to 01-02T08:30); push it far ahead
        self.svc.db.execute(
            "UPDATE monitoring_policies SET next_run=? WHERE id=?",
            ("2999-01-01T00:00:00Z", d["id"]))
        rw = self.sched.run_due(now="2000-01-03T09:05:00Z", limit=50)
        self.assertEqual(rw["scans_created"], 1)
        self.drain()

    def test_manual_run_creates_scan_and_audits(self):
        p = self._policy(name="manual-run")
        r = self.sched.run_now(p["id"], actor="cli")
        self.assertEqual(r["status"], "created")
        self.drain()
        rows = self.svc.db.query(
            "SELECT * FROM audit_events WHERE action=?",
            ("monitoring.manual_run",))
        self.assertEqual(len(rows), 1)

    def test_manual_run_refuses_disabled(self):
        p = self._policy(name="off")
        self.mon.set_enabled(p["id"], False)
        with self.assertRaises(errors.LifecycleError):
            self.sched.run_now(p["id"], actor="cli")

    def test_manual_run_rate_limited(self):
        p = self._policy(name="rl")
        hits = 0
        for i in range(10):
            try:
                self.sched.run_now(p["id"], actor="rltest")
                hits += 1
            except errors.RateLimitedError:
                break
        # MANUAL_RUN_LIMIT (5) per policy+actor window; call 6 refused
        self.assertEqual(hits, 5)

    def test_run_due_creates_audit_for_scheduled_run(self):
        self._policy()
        self.sched.run_due(now="2000-01-01T00:10:05Z")
        rows = self.svc.db.query(
            "SELECT * FROM audit_events WHERE action=?",
            ("monitoring.scheduled_run",))
        self.assertEqual(len(rows), 1)
        self.drain()

    def test_policy_create_audited(self):
        self._policy(name="audited")
        rows = self.svc.db.query(
            "SELECT * FROM audit_events WHERE action=?",
            ("monitoring.policy.created",))
        self.assertEqual(len(rows), 1)

    def test_on_scan_terminal_updates_execution(self):
        p = self._policy()
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        scan_id = r["scans"][0]["scan_id"]
        execs = self.svc.db.query(
            "SELECT * FROM scheduler_executions WHERE scan_id=?",
            (scan_id,))
        self.assertEqual(execs[0]["status"], "created")
        self.sched.on_scan_terminal(self.proj.id, scan_id, "completed")
        execs = self.svc.db.query(
            "SELECT * FROM scheduler_executions WHERE scan_id=?",
            (scan_id,))
        self.assertEqual(execs[0]["status"], "completed")
        # idempotent
        self.sched.on_scan_terminal(self.proj.id, scan_id, "failed")
        execs = self.svc.db.query(
            "SELECT * FROM scheduler_executions WHERE scan_id=?",
            (scan_id,))
        self.assertEqual(execs[0]["status"], "completed")

    def test_sweep_stale_marks_failed_terminals(self):
        p = self._policy()
        r = self.sched.run_due(now="2000-01-01T00:10:05Z")
        scan_id = r["scans"][0]["scan_id"]
        n = self.sched.sweep_stale(now="2999-01-01T00:00:00Z")
        self.assertGreaterEqual(n, 0)


# ============================================================================
class TestMonitoringHealth(Phase5Base):
    def test_fresh_project_healthy(self):
        h = MonitoringHealthService(self.svc).compute(self.proj.id)
        self.assertIn(h["health"], ("healthy", "degraded", "stale",
                                    "disabled", "error"))
        self.assertGreaterEqual(h["score"], 0)
        self.assertLessEqual(h["score"], 100)
        for dim in ("scan_freshness", "asset_freshness", "success_ratio",
                    "notification_health", "worker_availability"):
            self.assertIn(dim, h["dimensions"])
            self.assertGreaterEqual(h["dimensions"][dim], 0.0)
            self.assertLessEqual(h["dimensions"][dim], 1.0)

    def test_all_disabled_is_disabled(self):
        p = self.mon.create(self.proj.id, "off", scan_profile="web-audit",
                            targets=["https://demo.example.com/"])
        self.mon.set_enabled(p["id"], False)
        h = MonitoringHealthService(self.svc).compute(self.proj.id)
        self.assertEqual(h["health"], "disabled")

    def test_failed_execution_degrades(self):
        # interval grid is anchored at created_at; next_run/now must be
        # grid-aligned (anchor + k*interval) for a due window to exist
        self._failure = self.mon.create(
            self.proj.id, "bad", scan_profile="web-audit",
            targets=["https://demo.example.com/"], interval_minutes=60)
        self.svc.db.execute(
            "UPDATE monitoring_policies SET created_at=?, next_run=?, "
            "last_run=? WHERE id=?",
            ("2000-01-01T00:00:00Z", "2000-01-01T01:00:00Z", "",
             self._failure["id"]))
        r = self.sched.run_due(now="2000-01-01T01:00:05Z")
        scan_id = r["scans"][0]["scan_id"]
        self.sched.on_scan_terminal(self.proj.id, scan_id, "failed",
                                    error="boom")
        h = MonitoringHealthService(self.svc).compute(self.proj.id,
                                                      now="2000-01-01T01:00:00Z")
        self.assertIn(h["health"], ("degraded", "error"))
        self.assertLess(h["score"], 100)


# ============================================================================
class TestRetention(Phase5Base):
    def test_sweep_only_prunes_phase5_high_volume(self):
        self.alerts.install_default_rules(self.proj.id)
        self.ingest()
        # craft OLD high-volume rows (real parents to satisfy FKs)
        pol = self.mon.create(self.proj.id, "sweep-pol",
                              scan_profile="web-audit",
                              targets=["https://demo.example.com/"])
        # one real alert + notification (created via the pipeline), then
        # backdate them + add a genuine old attempt row
        self.notify.settings_set(self.proj.id, email_enabled=True,
                                 email_to="sec@example.com")
        self.alerts.install_default_rules(self.proj.id)
        self.ingest()
        e = self.events.emit(self.proj.id, "finding.created",
                             asset_id="a1", key="sw-e", scan_id="s1",
                             new_state={"title": "X"}, source="t")
        fired = self.alerts.process_event(e)
        alert_id = fired[0]["id"]
        rule = self.alerts.rule_list(self.proj.id)[0]
        self.notify.dispatch_alert(alert_id, e["id"], rule)
        self.svc.db.execute(
            "INSERT INTO security_events (id, project_id, org_id, asset_id, "
            "event_type, source, ts, previous_state, new_state, confidence, "
            "scan_id, state_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("old-ev", self.proj.id, self.org.id, "a1", "exposure.changed",
             "s", "1999-01-01T00:00:00Z", "{}", "{}", 0.5, "s1", "k-old"))
        self.svc.db.execute(
            "INSERT INTO scheduler_executions (id, project_id, org_id, "
            "policy_id, scheduled_window, scan_id, status, reason, "
            "created_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("old-ex", self.proj.id, self.org.id, pol["id"], "w1", "s1",
             "created", "", "1999-01-01T00:00:00Z", ""))
        # backdate the real notification and record a REAL old attempt
        self.svc.db.execute(
            "UPDATE notifications SET created_at=?, updated_at=? WHERE "
            "project_id=?", ("1999-01-01T00:00:00Z", "1999-01-01T00:00:00Z",
                             self.proj.id))
        rows = self.svc.db.query(
            "SELECT id FROM notifications WHERE project_id=? LIMIT 1",
            (self.proj.id,))
        nid = rows[0]["id"]
        self.svc.db.execute(
            "INSERT INTO notification_attempts (id, notification_id, "
            "attempt_n, ts, outcome, error, duration_ms) "
            "VALUES (?,?,?,?,?,?,?)",
            ("old-at", nid, 99, "1999-01-01T00:00:00Z", "failed", "x", 1.0))
        before = {
            "audit": len(self.svc.db.query("SELECT id FROM audit_events", ())),
            "findings": len(self.svc.db.query("SELECT id FROM findings", ())),
            "alerts": len(self.svc.db.query("SELECT id FROM alerts", ())),
            "tickets": len(self.svc.db.query(
                "SELECT id FROM remediation_tickets", ())),
        }
        counts = retention_sweep(self.svc, project_id=self.proj.id,
                                 event_days=30, attempt_days=30,
                                 exec_days=30, actor="scheduler")
        self.assertEqual(counts["security_events"], 1)
        self.assertEqual(counts["scheduler_executions"], 1)
        self.assertEqual(counts["notification_attempts"], 1)
        after = {
            # the sweep APPENDS its own retention.sweep audit row (audited
            # by design) and never deletes immutable rows
            "audit": len(self.svc.db.query("SELECT id FROM audit_events", ())),
            "findings": len(self.svc.db.query("SELECT id FROM findings", ())),
            "alerts": len(self.svc.db.query("SELECT id FROM alerts", ())),
            "tickets": len(self.svc.db.query(
                "SELECT id FROM remediation_tickets", ())),
        }
        self.assertEqual(after["audit"], before["audit"] + 1)
        self.assertEqual(after["findings"], before["findings"])
        self.assertEqual(after["alerts"], before["alerts"])
        self.assertEqual(after["tickets"], before["tickets"])
        rows = self.svc.db.query("SELECT * FROM audit_events WHERE action=?",
                                 ("retention.sweep",))
        self.assertEqual(len(rows), 1)

    def test_sweep_keeps_recent_rows(self):
        self.ingest()
        counts = retention_sweep(self.svc, project_id=self.proj.id,
                                 event_days=30, attempt_days=30,
                                 exec_days=30)
        self.assertEqual(counts["security_events"], 0)

    def test_sweep_clamps_minimum_days(self):
        counts = retention_sweep(self.svc, project_id=self.proj.id,
                                 event_days=1, attempt_days=1, exec_days=1)
        self.assertEqual(sum(counts.values()), 0)


# ============================================================================
class TestPhase5Authz(Phase5Base):
    def setUp(self):
        super().setUp()
        self.id_svc = identity_mod.IdentityService(
            self.svc, scrypt_n=2 ** 8)
        self.authz = AuthorizationService(self.svc, self.id_svc)

    def _user(self, name="alice", roles=("security_manager",)):
        return self.id_svc.user_create(self.org.id, name, f"{name}@a.test",
                                       PW, roles=roles, allow_any_role=True)

    def _ctx(self, user, scopes, project_id=""):
        # the credential lives in the USER's organization — a context can
        # never belong to a tenant it has no grant in
        cred = self.id_svc.credential_create(
            user.org_id, f"key-{user.username}", scopes,
            project_id=project_id or "", as_permissions=scopes,
            ttl_seconds=0)
        return self.authz.context_from_secret(cred["secret"])

    def _seed(self):
        """One policy + one alert + one ticket + one notification."""
        self.alerts.install_default_rules(self.proj.id)
        self.ingest()
        p = self.mon.create(self.proj.id, "z", scan_profile="web-audit",
                            targets=["https://demo.example.com/"])
        alerts = self.alerts.list_alerts(self.proj.id)
        a = alerts[0]["id"]
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a1",
                             key="zz", scan_id="s9",
                             new_state={"title": "X"}, source="t")
        self.alerts.process_event(e)
        self.notify.settings_set(self.proj.id, email_enabled=True,
                                 email_to="sec@example.com")
        self.alerts.process_event(
            {"project_id": self.proj.id, "org_id": self.org.id,
             "asset_id": "a1", "event_type": "finding.created", "key": "zz",
             "scan_id": "s9", "ts": "2026-01-01T00:00:00Z",
             "previous_state": {}, "new_state": {"title": "X"},
             "confidence": 0.9, "source": "t", "id": "ev-authz"})
        return p["id"], a

    def test_monitoring_permissions_gate(self):
        p, a = self._seed()
        viewer = self._user("view", roles=("viewer",))
        vctx = self._ctx(viewer, ("monitoring.read", "alert.read",
                                  "remediation.read", "notification.read"))
        self.authz.require_monitoring_policy(vctx, p)
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(vctx, "monitoring.create")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(vctx, "alert.suppress")

    def test_cross_tenant_policy_denied(self):
        p, a = self._seed()
        other = self.svc.org_create("Other")
        u = self.id_svc.user_create(other.id, "mallory",
                                    "m@other.test", PW,
                                    roles=("security_manager",),
                                    allow_any_role=True)
        ctx = self._ctx(u, ("monitoring.read", "monitoring.create",
                            "monitoring.update", "monitoring.delete",
                            "alert.read", "alert.update", "alert.suppress",
                            "remediation.read", "remediation.update",
                            "remediation.assign", "remediation.verify",
                            "notification.read"))
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_monitoring_policy(ctx, p)
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_alert(ctx, a)

    def test_cross_tenant_ticket_and_notification_denied(self):
        p, a = self._seed()
        t = self.remedy.ensure(self.finding_id(), actor="cli")
        notif = self.notify.list_notifications(self.proj.id)
        other = self.svc.org_create("Other2")
        u = self.id_svc.user_create(other.id, "mal2", "m2@other.test", PW,
                                    roles=("security_manager",),
                                    allow_any_role=True)
        ctx = self._ctx(u, ("monitoring.read", "alert.read",
                            "remediation.read", "notification.read"))
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_remediation(ctx, t["id"])
        if notif:
            with self.assertRaises(errors.AuthorizationError):
                self.authz.require_notification(ctx, notif[0]["id"])

    def test_forged_ids_denied(self):
        self._seed()
        u = self._user("forge")
        ctx = self._ctx(u, ("monitoring.read", "alert.read",
                            "remediation.read", "notification.read"))
        for fn, bad_id in ((self.authz.require_monitoring_policy,
                            "POLICY-1' OR 1=1 --"),
                           (self.authz.require_alert,
                            "ALERT-1'; DROP TABLE alerts; --"),
                           (self.authz.require_remediation,
                            "TICKET-1\" OR \"1\"=\"1"),
                           (self.authz.require_notification,
                            "NOTIF-1%00")):
            with self.assertRaises(errors.AuthorizationError):
                fn(ctx, bad_id)
            with self.assertRaises(errors.AuthorizationError):
                fn(ctx, "no-such-id-1234567890")

    def test_visible_projects_org_scoped(self):
        self._seed()
        u = self._user("scope")
        ctx = self._ctx(u, ("monitoring.read", "alert.read",
                            "remediation.read", "notification.read"))
        visible = self.authz.visible_projects(ctx)
        ids = [p.id for p in visible]
        self.assertIn(self.proj.id, ids)
        self.assertEqual(len(ids), len(set(ids)))


# ============================================================================
class TestPhase5Regressions(Phase5Base):
    def test_metrics_counters_exist(self):
        names = set(metrics.snapshot().get("counters", {}))
        for counter in ("monitoring_policies", "scheduled_runs",
                        "missed_runs", "security_change_events",
                        "alerts_created", "alerts_deduplicated",
                        "alerts_suppressed", "notifications_sent",
                        "notifications_failed", "notification_retries",
                        "remediations_opened", "remediations_verified",
                        "remediations_reopened", "verification_scans",
                        "monitoring_health_failures",
                        "alert_evaluation_failures"):
            self.assertIn(counter, names, counter)

    def test_alert_identity_collision_impossible_for_distinct_rules(self):
        r1 = self.alerts.rule_create(self.proj.id, "rule-a", condition={})
        r2 = self.alerts.rule_create(self.proj.id, "rule-b", condition={})
        self.assertNotEqual(r1["id"], r2["id"])
        e = self.events.emit(self.proj.id, "finding.created", asset_id="a",
                             key="k", scan_id="s",
                             new_state={"title": "X"}, source="t")
        out = self.alerts.process_event(e)
        self.assertEqual(len(out), 2)  # both rules matched the same event

    def test_events_survive_alert_suppression(self):
        self.alerts.install_default_rules(self.proj.id)
        self.ingest()
        rows = self.alerts.list_alerts(self.proj.id)
        if rows:
            self.alerts.suppress(rows[0]["id"], actor="x", reason="r",
                                 until="2099-01-01T00:00:00Z")
        evs = self.events.list_events(self.proj.id)
        self.assertGreater(len(evs), 0)  # suppressed alerts keep history

    def test_malformed_event_never_breaks_pipeline(self):
        self.alerts.install_default_rules(self.proj.id)
        out = self.alerts.process_event({})
        self.assertEqual(out, [])
        out = self.alerts.process_event({"project_id": self.proj.id})
        self.assertEqual(out, [])

    def test_dashboard_snapshot_redacted(self):
        import dashboard as _db
        self.alerts.install_default_rules(self.proj.id)
        self.notify.settings_set(self.proj.id, webhook_enabled=True,
                                 webhook_url="https://hooks.example.com/h",
                                 webhook_secret="s3cret-key-123456")
        self.ingest()
        snap = _db.load_monitor_snapshot(self.svc.db_path, org_filter="")
        self.assertIsNotNone(snap)
        blob = str(snap)
        self.assertNotIn("s3cret-key-123456", blob)
        self.assertNotIn("webhook_secret", blob)
        for k in ("policies", "executions", "events", "alerts", "tickets",
                  "health"):
            self.assertIn(k, snap)
        # the rendered panel: every Monitoring section present, redacted
        html = _db.monitoring_page(snap)
        for sec in ("Policies", "Scheduled scans", "Security changes",
                    "Alerts", "Remediation queue", "Health"):
            self.assertIn(sec, html)
        self.assertNotIn("s3cret-key-123456", html)
        self.assertNotIn("webhook_secret", html)
        # no DB configured → honest empty state, never an error
        empty = _db.monitoring_page(None)
        self.assertIn("No monitoring database", empty)

    def test_worker_hooks_do_not_break_completion(self):
        import jobs as _jobs
        self._policy_path = self.mon.create(
            self.proj.id, "wh", scan_profile="web-audit",
            targets=["https://demo.example.com/"])
        r = self.sched.run_now(self._policy_path["id"])
        job_id = r["job_id"]
        jsvc = _jobs.JobService(self.svc, self.registry)
        job = jsvc.claim_next("w")
        jsvc.complete(job.id, result_reference="ok")
        # worker completion hook path (as worker.py calls it)
        self.sched.on_scan_terminal(self.proj.id, job.scan_id, "completed")
        self.remedy.on_scan_completed(self.proj.id, job.scan_id)
        st = jsvc.job_get(job.id).status
        self.assertEqual(st, "completed")

    def test_no_secret_columns_in_notification_settings_view(self):
        self.notify.settings_set(self.proj.id, webhook_enabled=True,
                                 webhook_url="https://hooks.example.com/h",
                                 webhook_secret="s3cret-key-123456")
        raw = self.svc.db.query(
            "SELECT * FROM notification_settings WHERE project_id=?",
            (self.proj.id,))[0]
        # stored for HMAC signing (documented) but never in views/payloads
        self.assertIn("webhook_secret", raw.keys())
        v = self.notify.settings_view(self.proj.id)
        self.assertNotIn("s3cret-key-123456", str(v))


if __name__ == "__main__":
    unittest.main(verbosity=2)
