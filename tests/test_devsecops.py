#!/usr/bin/env python3
# ============================================================================
#  test_devsecops.py — Phase-7 DevSecOps / CI-CD security-gate suite.
#  Covers: allowlisted policy language (fields/operators/depth/size, no
#  eval/exec), deterministic condition evaluation (PASS/FAIL/WARN),
#  gate CRUD + versioning, CI run lifecycle + idempotency + metadata bounds,
#  fail-closed gate evaluation (scan failure / missing baseline / missing
#  risk NEVER become PASS), existing-engine reuse (scan/job/fingerprint/
#  risk/baseline-diff/SARIF/remediation-reporting/audit), tenant isolation +
#  RBAC (devsecops.*), secrets/redaction, SARIF validity, report input,
#  retention (immutable evidence untouched), concurrency (duplicate CI
#  submission + concurrent evaluation), rate limiting and performance.
#  Fully offline, deterministic, temp SQLite per test.
# ============================================================================
from __future__ import annotations

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
sys.path.insert(0, ROOT)

import errors  # noqa: E402
import metrics  # noqa: E402
import models  # noqa: E402
import redact  # noqa: E402
import rbac  # noqa: E402
import identity as identity_mod  # noqa: E402
import devsecops as ds_mod  # noqa: E402
import platform_service as pf  # noqa: E402
import diffs  # noqa: E402

from devsecops import (DevSecOpsService, validate_policy, policy_hash,
                       evaluate_conditions)  # noqa: E402

PW = "S3cure!Passw0rd"
PHISH = "Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop"
PHISH_MARK = "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop"
SK = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

identity_mod.RL_LIMITS["auth"] = (10000, 60)
identity_mod.RL_LIMITS["auth_ip"] = (10000, 60)
identity_mod.RL_LIMITS["session_create"] = (10000, 60)
identity_mod.RL_LIMITS["api"] = (10000, 60)
identity_mod.RL_LIMITS["credential_create"] = (10000, 3600)

POLICY_OK = {
    "version": 1,
    "description": "production gate",
    "conditions": [
        {"key": "max_open_critical", "op": "<=", "value": 0,
         "blocking": True},
        {"key": "max_new_findings", "op": "<=", "value": 5,
         "blocking": False},
        {"key": "require_scan_success", "op": "==", "value": True,
         "blocking": True},
    ],
}


def make_service(tmp):
    return pf.PlatformService(os.path.join(tmp, "secutool.db"))


def raw_result(target, findings, assets=None):
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


class D7Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p7_")
        self.svc = make_service(self.tmp)
        self.org = self.svc.org_create("Acme")
        self.proj = self.svc.project_create(self.org.id, "Web")
        self.org2 = self.svc.org_create("OtherCo")
        self.proj2 = self.svc.project_create(self.org2.id, "OtherApp")
        self.id_svc = identity_mod.IdentityService(self.svc, scrypt_n=2 ** 8)
        self.authz = __import__("authz").AuthorizationService(
            self.svc, self.id_svc)
        self.reg = __import__("scanners").ScannerRegistry()
        self.dso = DevSecOpsService(self.svc, registry=self.reg)
        # generous in-memory limits for the suite (rate limiting has its own
        # dedicated test with explicit tight limits)
        for k in self.dso.rl:
            self.dso.rl[k] = (100000, 60)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def gate(self, policy=None, name="prod-gate"):
        return self.dso.gate_create(self.proj.id, name,
                                    policy or dict(POLICY_OK), actor="test")

    def scan_run(self, gate_id, *, pipe="pl-1", sha="a" * 40, findings=None,
                 submit=False, target="https://web.acme.test/"):
        out = self.dso.run_create(
            self.proj.id, gate_id, "crawler", provider="github",
            repository="acme/web", branch="main", commit_sha=sha,
            commit_ref="refs/heads/main", pipeline_id=pipe,
            pipeline_url="https://ci.example/run/1", actor="ci-bot",
            trigger="pull_request", target=target, run_key="",
            submit=submit, run_actor="test")
        run = out["run"]
        if findings is not None:
            self.svc.register_scanner_result(
                self.proj.id, raw_result(target, findings),
                scan_id=run["scan_id"], profile="crawler")
        return run

    def add_user(self, org=None, username="u1", roles=("security_manager",)):
        org = org or self.org
        return self.id_svc.user_create(org.id, username, username + "@a.test",
                                       PW, roles=roles, allow_any_role=True,
                                       actor="test")

    def ctx_for(self, username):
        secret = self.id_svc.login(username, PW)["secret"]
        return self.authz.context_from_secret(secret)

    def bulk_seed(self, n_assets=100, n_findings=500, n_events=1000):
        p = self.proj
        now = models.utcnow()
        sevs = ("Critical", "High", "Medium", "Low", "Info")
        scan_id = models.stable_id(models.NS_SCAN, f"pd7seed|{p.id}")
        try:
            self.svc.scan_create(p.id, "crawler", scope_ref="perf-seed",
                                 scan_id=scan_id)
        except errors.DuplicateError:
            pass
        asset_ids = [models.stable_id(models.NS_ASSET, f"pd7a-{i}")
                     for i in range(n_assets)]
        with self.svc.db.transaction() as conn:
            for i, aid in enumerate(asset_ids):
                conn.execute(
                    "INSERT INTO assets (id, project_id, asset_type, value,"
                    " display, metadata, status, first_seen, last_seen, "
                    "criticality, exposure, exposure_reason, "
                    "business_impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (aid, p.id, "domain", f"host{i}.d7.test", "", "{}",
                     "active", now, now, "unknown", "unknown", "", "{}"))
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
                                      f"pd7f-{i}"), scan_id, p.id,
                     asset_ids[i % n_assets],
                     f"Finding {i}", "d7", sevs[i % 5], "high",
                     "injection", "d7", f"rule-d7-{i}", "", "CWE-89",
                     "", "{}", "Fix.", "[]", "{}", "open",
                     f"pd7fp-{i}", now, now, "",
                     0.8, "verified", "{}",
                     20.0 + (i % 10) * 4.0,
                     "medium", "{}", "risk-v1", "P2", 2,
                     f"ck7-{i}", 1, "", "", "", "", "{}", "unknown"))
            for i in range(n_events):
                et = ("exposure.changed", "technology.changed",
                      "service.opened", "service.closed")[i % 4]
                conn.execute(
                    "INSERT INTO security_events (id, project_id, org_id, "
                    "asset_id, event_type, source, ts, previous_state, "
                    "new_state, confidence, scan_id, state_key) VALUES "
                    "(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (models.stable_id(models.NS_EVENT, f"pd7e-{i}"),
                     p.id, self.org.id, "", et, "d7", now, "{}", "{}",
                     0.5, "", ""))


# ---------------------------------------------------------------------------
class TestPolicyValidation(D7Base):
    def test_valid_policy_normalized_and_sorted(self):
        p = validate_policy({
            "conditions": [{"key": "max_new_findings", "op": "<=",
                            "value": 5, "blocking": False},
                           {"key": "max_open_critical", "op": "<=",
                            "value": 0}],
            "version": 2})
        self.assertEqual(p["version"], 2)
        self.assertEqual(p["description"], "")
        self.assertEqual([c["key"] for c in p["conditions"]],
                         ["max_new_findings", "max_open_critical"])
        self.assertTrue(p["conditions"][0]["blocking"] is False)
        self.assertTrue(p["conditions"][1]["blocking"] is True)

    def test_hash_deterministic_regardless_of_order(self):
        a = policy_hash({"conditions": [{"key": "max_open_critical",
                                         "op": "<=", "value": 1}],
                         "version": 1})
        b = policy_hash({"version": 1, "conditions": [
            {"value": 1, "blocking": True, "key": "max_open_critical",
             "op": "<="}]})
        self.assertEqual(a, b)

    def test_unknown_condition_key_rejected(self):
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": [{"key": "max_widgets", "op": "<=",
                                             "value": 1}]})

    def test_unknown_operator_rejected(self):
        for op in ("=~", "LIKE", "in", "&&", "=>", "eval", "->"):
            with self.assertRaises(errors.ValidationError):
                validate_policy({"conditions": [{"key": "max_open_critical",
                                                 "op": op, "value": 1}]})

    def test_unknown_policy_fields_rejected(self):
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": [], "arbitrary": 1})
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": [{"key": "max_open_critical",
                                             "op": "<=", "value": 1,
                                             "whitelist_all": True}]})

    def test_value_type_validation(self):
        for bad in ({"max_risk": "abc"}, {"max_risk": True},
                    {"max_open_critical": "1"}, {"max_open_critical": 1.5},
                    {"max_severity": "Fatal"},
                    {"require_minimum_confidence": "very"},
                    {"block_active_findings": "yes"},
                    {"require_scan_success": 1}):
            key = list(bad)[0]
            with self.assertRaises(errors.ValidationError):
                validate_policy({"conditions": [
                    {"key": key, "op": "<=", "value": bad[key]}]})

    def test_boolean_keys_reject_non_equality_ops(self):
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": [{"key": "require_scan_success",
                                             "op": ">", "value": True}]})

    def test_depth_limits_flat_only(self):
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": [{"key": "max_open_critical",
                                             "op": "<=",
                                             "value": {"nested": 1}}]})
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": [{"key": "max_open_critical",
                                             "op": "<=", "value": [1, 2]}]})

    def test_condition_count_cap(self):
        conds = [{"key": "max_open_critical", "op": "<=", "value": i}
                 for i in range(21)]
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": conds})

    def test_policy_size_cap(self):
        big_desc = "x" * 5000
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": [], "description": big_desc})

    def test_no_eval_or_exec_in_policy_engine(self):
        src = open(os.path.join(PY, "devsecops.py"), encoding="utf-8").read()
        self.assertNotIn("eval(", src)
        self.assertNotIn("exec(", src)
        self.assertNotIn("__import__(", src)

    def test_secrets_removed_from_policy_description(self):
        p = validate_policy({"conditions": [], "description":
                             "token " + SK + " in text"})
        self.assertNotIn(SK, json.dumps(p))
        self.assertIn(redact.REDACTED, p["description"])

    def test_policy_rejected_still_throws_for_non_object(self):
        for bad in ("[]", "x", 5, None, ["max_risk"]):
            with self.assertRaises(errors.ValidationError):
                validate_policy(bad)


# ---------------------------------------------------------------------------
class TestPolicyEvaluation(D7Base):
    def _base(self, **over):
        ev = {"max_risk": 120.0, "max_severity": "High",
              "max_open_critical": 1, "max_open_high": 3,
              "max_new_findings": 2, "max_reopened_findings": 0,
              "max_increased_risk": 1, "block_active_findings": 1,
              "block_internet_facing_critical": 0,
              "require_no_regression": 1, "require_scan_success": 1,
              "require_minimum_confidence": "high"}
        ev.update(over)
        return ev

    def test_pass(self):
        pol = validate_policy(dict(POLICY_OK))
        status, viol = evaluate_conditions(pol, self._base(
            max_open_critical=0, max_new_findings=1))
        self.assertEqual(status, "pass")
        self.assertEqual(viol, [])

    def test_fail_blocking(self):
        pol = validate_policy(dict(POLICY_OK))
        status, viol = evaluate_conditions(pol, self._base(
            max_open_critical=2))
        self.assertEqual(status, "fail")
        self.assertEqual(viol[0]["key"], "max_open_critical")
        self.assertTrue(viol[0]["blocking"])

    def test_warn_non_blocking(self):
        pol = validate_policy({
            "conditions": [{"key": "max_new_findings", "op": "<=",
                            "value": 1, "blocking": False},
                           {"key": "max_open_critical", "op": "<=",
                            "value": 5, "blocking": True}]})
        status, viol = evaluate_conditions(pol, self._base(
            max_new_findings=9))
        self.assertEqual(status, "warn")
        self.assertEqual(len(viol), 1)
        self.assertFalse(viol[0]["blocking"])

    def test_operators(self):
        for op, ev, val, expect in (("==", 1, 1, True), ("!=", 1, 2, True),
                                    (">", 3, 2, True), (">=", 2, 2, True),
                                    ("<", 1, 2, True), ("<=", 2, 2, True),
                                    ("==", 1, 2, False), (">", 1, 2, False)):
            pol = validate_policy({"conditions": [
                {"key": "max_open_critical", "op": op, "value": val}]})
            status, viol = evaluate_conditions(pol, self._base(
                max_open_critical=ev))
            self.assertEqual(status, "pass" if expect else "fail", (op, ev))

    def test_severity_gate(self):
        pol = validate_policy({"conditions": [
            {"key": "max_severity", "op": "<=", "value": "High"}]})
        status, _ = evaluate_conditions(pol, self._base(max_severity="High"))
        self.assertEqual(status, "pass")
        status, viol = evaluate_conditions(pol,
                                           self._base(max_severity="Critical"))
        self.assertEqual(status, "fail")
        self.assertEqual(viol[0]["actual"], "Critical")

    def test_confidence_gate(self):
        pol = validate_policy({"conditions": [
            {"key": "require_minimum_confidence", "op": ">=",
             "value": "high"}]})
        status, _ = evaluate_conditions(pol,
                                        self._base(require_minimum_confidence=
                                                   "confirmed"))
        self.assertEqual(status, "pass")
        status, _ = evaluate_conditions(pol,
                                        self._base(require_minimum_confidence=
                                                   "medium"))
        self.assertEqual(status, "fail")

    def test_bool_requirements(self):
        pol = validate_policy({"conditions": [
            {"key": "require_no_regression", "op": "==", "value": True},
            {"key": "require_scan_success", "op": "==", "value": True},
            {"key": "block_internet_facing_critical", "op": "==",
             "value": True}]})
        # derived booleans: True means "nothing to block"/requirement holds
        status, _ = evaluate_conditions(pol, self._base(
            require_no_regression=0,
            block_internet_facing_critical=0))
        self.assertEqual(status, "fail")
        status, _ = evaluate_conditions(pol, self._base(
            require_no_regression=1,
            block_internet_facing_critical=1))
        self.assertEqual(status, "pass")
        # missing boolean evidence fails closed (never PASS)
        ev = self._base()
        ev.pop("require_scan_success")
        status, viol = evaluate_conditions(pol, ev)
        self.assertEqual(status, "fail")
        self.assertIn("require_scan_success", {v["key"] for v in viol})

    def test_deterministic_output(self):
        pol = validate_policy(dict(POLICY_OK))
        e = self._base()
        a = evaluate_conditions(pol, dict(e))
        b = evaluate_conditions(pol, dict(e))
        self.assertEqual(a, b)
        self.assertEqual(policy_hash(pol),
                         policy_hash(validate_policy(dict(POLICY_OK))))


# ---------------------------------------------------------------------------
class TestGateCrud(D7Base):
    def test_create_list_get(self):
        g = self.gate()
        self.assertTrue(g["enabled"])
        self.assertEqual(g["policy_version"], 1)
        self.assertEqual(len(g["policy_hash"]), 64)
        lst = self.dso.gate_list(self.proj.id)
        self.assertEqual(lst["total"], 1)
        got = self.dso.gate_get(g["id"])
        self.assertEqual(got["name"], "prod-gate")
        self.assertEqual(len(got["policy"]["conditions"]), 3)
        with self.assertRaises(errors.NotFoundError):
            self.dso.gate_get("no-such-gate")

    def test_duplicate_name_rejected(self):
        self.gate(name="dup")
        with self.assertRaises(errors.DuplicateError):
            self.gate(name="dup")

    def test_invalid_names_rejected(self):
        for bad in ("", "a" * 200, "x; rm -rf /", "my gate\x01"):
            with self.assertRaises(errors.ValidationError):
                self.dso.gate_create(self.proj.id, bad, dict(POLICY_OK),
                                     actor="test")

    def test_create_rejects_bad_policy(self):
        with self.assertRaises(errors.ValidationError):
            self.dso.gate_create(self.proj.id, "g",
                                 {"conditions": [{"key": "nope", "op": "<=",
                                                  "value": 1}]}, actor="test")

    def test_update_bumps_hash_keeps_history_frozen(self):
        g = self.gate()
        g2 = self.dso.gate_update(
            g["id"], policy={"conditions": [{"key": "max_open_critical",
                                             "op": "<=", "value": 0}],
                             "version": 2}, actor="test")
        self.assertEqual(g2["policy_version"], 2)
        self.assertNotEqual(g2["policy_hash"], g["policy_hash"])
        lst = self.dso.gate_list(self.proj.id)
        self.assertEqual(lst["total"], 1)      # same row, versioned

    def test_update_noop_does_not_change_version(self):
        g = self.gate()
        g2 = self.dso.gate_update(g["id"], name="prod-gate",
                                  enabled=True, actor="test")
        self.assertEqual(g2["policy_version"], g["policy_version"])
        self.assertEqual(g2["policy_hash"], g["policy_hash"])

    def test_toggle_disabled(self):
        g = self.gate()
        g2 = self.dso.gate_update(g["id"], enabled=False, actor="test")
        self.assertFalse(g2["enabled"])
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                pipeline_id="p1", run_actor="test")

    def test_delete_keeps_results(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info")])
        res = self.dso.evaluate(run["id"], actor="test")
        self.dso.gate_delete(g["id"], actor="test")
        with self.assertRaises(errors.NotFoundError):
            self.dso.gate_get(g["id"])
        self.assertEqual(self.dso.result_get(res["id"])["status"],
                         "pass")  # historical result survives gate deletion

    def test_gate_audited(self):
        g = self.gate()
        self.dso.gate_update(g["id"], name="renamed", actor="test")
        self.dso.gate_delete(g["id"], actor="test")
        actions = [e.action for e in self.svc.audit_list(self.proj.id,
                                                         limit=200)]
        for want in ("devsecops.gate.created", "devsecops.gate.updated",
                     "devsecops.gate.deleted"):
            self.assertIn(want, actions)


# ---------------------------------------------------------------------------
class TestCiRun(D7Base):
    def test_create_reuses_scan_and_job(self):
        g = self.gate()
        out = self.dso.run_create(
            self.proj.id, g["id"], "crawler", provider="gitlab",
            repository="acme/web", branch="main", commit_sha="a" * 40,
            pipeline_id="pl-77", commit_ref="refs/heads/main",
            pipeline_url="https://ci.example/77", actor="ci-bot",
            trigger="merge_request", target="https://web.acme.test/",
            submit=True, run_actor="test")
        run = out["run"]
        self.assertEqual(run["status"], "scanning")
        self.assertEqual(out["scan_id"], run["scan_id"])
        self.assertTrue(out["job_id"])
        scan = self.svc.scan_get(run["scan_id"])
        self.assertEqual(scan.profile, "crawler")
        self.assertEqual(scan.initiator.get("ci_run_id"), run["id"])
        records = self.svc.db.query(
            "SELECT id, status, profile, job_type FROM jobs WHERE id=?",
            (out["job_id"],))
        self.assertEqual(len(records), 1)      # existing Phase-3 jobs table
        self.assertEqual(records[0]["profile"], "crawler")
        self.assertEqual(records[0]["status"], "queued")
        st = self.dso.run_status(run["id"])
        self.assertEqual(st["job"]["status"], "queued")
        self.assertEqual(st["scan"]["profile"], "crawler")

    def test_provider_allowlist(self):
        g = self.gate()
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                provider="bitbucket", pipeline_id="p1",
                                run_actor="test")

    def test_trigger_allowlist(self):
        g = self.gate()
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                trigger="tag_push", pipeline_id="p1",
                                run_actor="test")

    def test_commit_validation(self):
        g = self.gate()
        for bad_sha in ("short", "z" * 40, "a" * 65, "abc def",
                        "a" * 40 + ";"):
            with self.assertRaises(errors.ValidationError):
                self.dso.run_create(self.proj.id, g["id"], "crawler",
                                    commit_sha=bad_sha, pipeline_id="p1",
                                    run_actor="test")

    def test_metadata_bounds(self):
        g = self.gate()
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                repository="x" * 400, pipeline_id="p1",
                                run_actor="test")
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                repository="repo; rm -rf /", pipeline_id="p1",
                                run_actor="test")
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                pipeline_url="ftp://x/1", pipeline_id="p1",
                                run_actor="test")
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                actor="bot\x07", pipeline_id="p1",
                                run_actor="test")

    def test_run_key_required_when_no_ci_identity(self):
        g = self.gate()
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                run_actor="test")

    def test_idempotent_duplicate_submission(self):
        g = self.gate()
        kwargs = dict(provider="github", repository="acme/web",
                      branch="main", commit_sha="b" * 40,
                      pipeline_id="pl-9", run_actor="test")
        a = self.dso.run_create(self.proj.id, g["id"], "crawler", **kwargs)
        b = self.dso.run_create(self.proj.id, g["id"], "crawler", **kwargs)
        self.assertEqual(a["run"]["id"], b["run"]["id"])
        self.assertTrue(b["reused"])
        rows = self.svc.db.query("SELECT id FROM ci_runs WHERE project_id=?",
                                 (self.proj.id,))
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            len(self.svc.db.query("SELECT id FROM scans WHERE project_id=?",
                                  (self.proj.id,))), 1)

    def test_different_commit_different_run(self):
        g = self.gate()
        a = self.dso.run_create(self.proj.id, g["id"], "crawler",
                                pipeline_id="pl-9", commit_sha="c" * 40,
                                run_actor="test")
        b = self.dso.run_create(self.proj.id, g["id"], "crawler",
                                pipeline_id="pl-9", commit_sha="d" * 40,
                                run_actor="test")
        self.assertNotEqual(a["run"]["id"], b["run"]["id"])

    def test_list_bounded_and_status_filter(self):
        g = self.gate()
        for i in range(3):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                pipeline_id=f"pl-{i}", commit_sha="e" * 40,
                                run_actor="test")
        data = self.dso.ci_list(self.proj.id, limit=2)
        self.assertEqual(len(data["runs"]), 2)
        self.assertEqual(data["total"], 3)
        with self.assertRaises(errors.ValidationError):
            self.dso.ci_list(self.proj.id, limit=1000000000)
        with self.assertRaises(errors.ValidationError):
            self.dso.ci_list(self.proj.id, status="bogus")

    def test_profile_allowlist(self):
        g = self.gate()
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "nmap",
                                pipeline_id="p1", run_actor="test")

    def test_unknown_gate_fails_closed(self):
        with self.assertRaises(errors.NotFoundError):
            self.dso.run_create(self.proj.id, "deadbeef-0000-0000-0000-"
                                "deadbeef0000", "crawler", pipeline_id="p1",
                                run_actor="test")


# ---------------------------------------------------------------------------
class TestGateEvaluation(D7Base):
    def test_pass(self):
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[
            finding("Low info leak", "Low", "information_disclosure", "fix")
        ])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "pass")
        self.assertEqual(res["violations"], [])
        self.assertEqual(res["result_version"], "gate-v1")
        self.assertEqual(len(res["result_hash"]), 64)
        st = self.dso.run_status(run["id"])
        self.assertEqual(st["run"]["status"], "completed")

    def test_fail_blocking_violation(self):
        g = self.gate(POLICY_OK)   # max_open_critical <= 0 (blocking)
        run = self.scan_run(g["id"], findings=[
            finding("SQLi", "Critical", "injection", "crit")
        ])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "fail")
        keys = {v["key"] for v in res["violations"]}
        self.assertIn("max_open_critical", keys)
        st = self.dso.run_status(run["id"])
        self.assertEqual(st["run"]["status"], "failed")

    def test_warn_non_blocking_only(self):
        g = self.gate({"conditions": [
            {"key": "max_new_findings", "op": "<=", "value": 0,
             "blocking": False}]})
        run = self.scan_run(g["id"], findings=[finding("X", "Info", "xss",
                                                       "x1")])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "warn")

    def test_severity_gate(self):
        g = self.gate({"conditions": [{"key": "max_severity", "op": "<=",
                                       "value": "High"}]})
        run = self.scan_run(g["id"], findings=[finding("RCE", "Critical",
                                                       "rce", "rce1")])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["summary"]["worst_severity"], "Critical")

    def test_risk_gate(self):
        g = self.gate({"conditions": [{"key": "max_risk", "op": "<=",
                                       "value": 10.0}]})
        run = self.scan_run(g["id"], findings=[
            finding("SQLi", "Critical", "injection", "risky")])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "fail")
        self.assertGreater(res["summary"]["total_risk"], 10.0)

    def test_confidence_gate(self):
        g = self.gate({"conditions": [{"key": "require_minimum_confidence",
                                       "op": ">=", "value": "high"}]})
        run = self.scan_run(g["id"], findings=[
            finding("Low conf", "High", "misconfiguration", "lc",
                    extra={"confidence": "low"})])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["violations"][0]["key"],
                         "require_minimum_confidence")

    def test_new_findings_gate(self):
        g = self.gate({"conditions": [{"key": "max_new_findings", "op": "<=",
                                       "value": 0}]})
        # first baseline: scan containing A only (never evaluated)
        self.scan_run(g["id"], pipe="pl-seed", findings=[
            finding("A", "Info", "xss", "a1")])
        run1 = self.scan_run(g["id"], pipe="pl-a", findings=[
            finding("A", "Info", "xss", "a1")])
        self.assertEqual(self.dso.evaluate(run1["id"], actor="test")["status"],
                         "pass")
        run2 = self.scan_run(g["id"], pipe="pl-b", findings=[
            finding("A", "Info", "xss", "a1"),
            finding("B", "Medium", "xss", "b1")])
        res = self.dso.evaluate(run2["id"], actor="test")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["summary"]["new_findings"], 1)

    def test_reopened_regression_gate(self):
        g = self.gate({"conditions": [{"key": "require_no_regression",
                                       "op": "==", "value": True}]})
        # run1 establishes the project baseline (first baseline counts every
        # finding as new → the no-regression gate correctly fails)
        run1 = self.scan_run(g["id"], pipe="pl-r1", findings=[
            finding("Regression A", "High", "xss", "ra")])
        self.assertEqual(self.dso.evaluate(run1["id"], actor="test")["status"],
                         "fail")
        self.assertEqual(self.dso.evaluate(run1["id"], actor="test")
                         ["summary"]["new_findings"], 1)
        # resolve the finding, then let the SAME fingerprint re-appear:
        # the Phase-4 fingerprint diff detects the regression (reopened)
        f = self.svc.finding_list(self.proj.id, limit=20)[0]
        self.svc.finding_set_status(f.id, "resolved")
        run2 = self.scan_run(g["id"], pipe="pl-r2", findings=[
            finding("Regression A", "High", "xss", "ra")])
        res = self.dso.evaluate(run2["id"], actor="test")
        self.assertEqual(res["status"], "fail")   # reopened regression caught
        self.assertEqual(res["summary"]["reopened_findings"], 1)
        ann = {a["annotation"] for a in res["annotations"]}
        self.assertEqual(ann, {"reopened"})

    def test_scan_failed_is_inconclusive_never_pass(self):
        g = self.gate(POLICY_OK)
        run = self.dso.run_create(self.proj.id, g["id"], "crawler",
                                  pipeline_id="pl-f1", commit_sha="f" * 40,
                                  submit=False, run_actor="test")
        self.svc.scan_transition(run["run"]["scan_id"], "failed")
        res = self.dso.evaluate(run["run"]["id"], actor="test")
        self.assertEqual(res["status"], "inconclusive")
        self.assertEqual(res["reason"], "scan_failed")

    def test_baseline_missing_is_inconclusive(self):
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "bm")])
        self.svc.db.execute(
            "DELETE FROM scan_diffs WHERE current_scan_id=?",
            (run["scan_id"],))
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "inconclusive")
        self.assertEqual(res["reason"], "baseline_unavailable")

    def test_risk_unavailable_is_inconclusive(self):
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[finding("A", "High", "xss",
                                                       "ru")])
        self.svc.db.execute(
            "UPDATE findings SET calc_version='' WHERE project_id=?",
            (self.proj.id,))
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "inconclusive")
        self.assertEqual(res["reason"], "risk_unavailable")

    def test_block_active_findings(self):
        g = self.gate({"conditions": [{"key": "block_active_findings",
                                       "op": "==", "value": True}]})
        run = self.scan_run(g["id"], findings=[finding("Open issue", "Low",
                                                       "xss", "oa")])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "fail")
        self.assertGreaterEqual(res["summary"]["active_findings"], 1)

    def test_block_internet_facing_critical(self):
        g = self.gate({"conditions": [
            {"key": "block_internet_facing_critical", "op": "==",
             "value": True}]}, name="ifc-gate")
        a = self.svc.asset_add(self.proj.id, "domain", "edge.acme.test")
        self.svc.db.execute(
            "UPDATE assets SET exposure='internet_facing' WHERE id=?", (a.id,))
        run = self.scan_run(g["id"], pipe="pl-ifc", findings=[
            {"title": "Edge flaw", "description": "d", "severity": "Critical",
             "confidence": "high", "category": "rce", "source": "s",
             "rule_id": "rule-ifc", "cwe": "CWE-94",
             "remediation": "Patch", "evidence": [], "raw": {},
             "target": "edge.acme.test"}])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["violations"][0]["key"],
                         "block_internet_facing_critical")
        self.assertGreaterEqual(res["summary"]["internet_facing_critical"], 1)
        # the same condition on a different project with no such finding
        # passes (nothing to block)
        g2 = self.dso.gate_create(self.proj2.id, "ifc-clean", {"conditions": [
            {"key": "block_internet_facing_critical", "op": "==",
             "value": True}]}, actor="test")
        run2 = self.dso.run_create(
            self.proj2.id, g2["id"], "crawler", pipeline_id="pl-ifc2",
            commit_sha="c" * 40, submit=False, run_actor="test")
        self.svc.register_scanner_result(
            self.proj2.id,
            raw_result("https://other.acme.test/",
                       [finding("B", "Info", "xss", "ifc2")]),
            scan_id=run2["run"]["scan_id"], profile="crawler")
        self.assertEqual(self.dso.evaluate(run2["run"]["id"], actor="test")[
            "status"], "pass")

    def test_gate_disabled_after_run_is_inconclusive(self):
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "gd")])
        self.dso.gate_update(g["id"], enabled=False, actor="test")
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "inconclusive")
        self.assertEqual(res["reason"], "gate_disabled")

    def test_policy_frozen_at_evaluation_time(self):
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "pf")])
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(res["status"], "pass")
        self.dso.gate_update(g["id"], policy={"conditions": [
            {"key": "max_open_critical", "op": "<=", "value": 0}],
            "version": 2}, actor="test")
        again = self.dso.result_get(res["id"])     # frozen
        self.assertEqual(again["status"], "pass")
        self.assertEqual(again["policy_version"], 1)

    def test_repeat_evaluation_returns_stored_result(self):
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "re1")])
        a = self.dso.evaluate(run["id"], actor="test")
        b = self.dso.evaluate(run["id"], actor="test")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(a["result_hash"], b["result_hash"])
        lst = self.dso.results_list(self.proj.id)
        self.assertEqual(lst["total"], 1)

    def test_audit_and_metrics_on_evaluation(self):
        metrics.reset()
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "am")])
        self.dso.evaluate(run["id"], actor="test")
        actions = [e.action for e in self.svc.audit_list(self.proj.id,
                                                         limit=200)]
        self.assertIn("devsecops.gate.passed", actions)
        snap = metrics.snapshot()
        self.assertEqual(snap["counters"]["devsecops_gate_passed"], 1)
        self.assertEqual(snap["counters"]["devsecops_runs_completed"], 1)

    def test_audit_metadata_never_contains_secret(self):
        g = self.gate({"conditions": [], "description": "token " + SK})
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "sf")])
        self.dso.evaluate(run["id"], actor="test")
        for ev in self.svc.audit_list(self.proj.id, limit=200):
            blob = json.dumps(ev.to_dict())
            self.assertNotIn(SK, blob)

    def test_rate_limit_applied(self):
        self.dso.rl["evaluate"] = (2, 60)
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "rl")])
        self.dso.evaluate(run["id"], actor="test")
        self.dso.evaluate(run["id"], actor="test")
        with self.assertRaises(errors.RateLimitedError):
            self.dso.evaluate(run["id"], actor="test")


# ---------------------------------------------------------------------------
class TestTenantIsolation(D7Base):
    def _other_ctx(self):
        self.add_user(org=self.org2, username="other", roles=("owner",))
        return self.ctx_for("other")

    def test_org_a_cannot_read_org_b_gate(self):
        g = self.gate()
        ctx = self._other_ctx()
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_gate(ctx, g["id"])

    def test_org_a_cannot_read_org_b_run(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[])
        ctx = self._other_ctx()
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_ci_run(ctx, run["id"])

    def test_org_a_cannot_read_org_b_result(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "tr")])
        res = self.dso.evaluate(run["id"], actor="test")
        ctx = self._other_ctx()
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_gate_result(ctx, res["id"])

    def test_forged_ids_never_leak_existence(self):
        ctx = self._other_ctx()
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_gate(ctx, "deadbeef-0000-0000-0000-00000000")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_ci_run(ctx, "deadbeef-0000-0000-0000-00000000")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_gate_result(
                ctx, "deadbeef-0000-0000-0000-00000000")

    def test_cannot_reference_foreign_project_in_run(self):
        gate2 = self.dso.gate_create(self.proj2.id, "other-gate",
                                     dict(POLICY_OK), actor="test")
        # org scope: create the run INSIDE org2 (allowed) then try to read
        # it from org1 — authz denies; also service refuses foreign project
        with self.assertRaises(errors.NotFoundError):
            self.dso.run_create(self.proj.id, gate2["id"], "crawler",
                                pipeline_id="p1", run_actor="test")

    def test_dashboard_snapshot_org_filtered(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "ds")])
        self.dso.evaluate(run["id"], actor="test")
        snap_all = self.dso.snapshot("")
        self.assertGreaterEqual(len(snap_all["gates"]), 1)
        snap_org1 = self.dso.snapshot(self.org.id)
        self.assertEqual(len(snap_org1["gates"]), 1)
        snap_org2 = self.dso.snapshot(self.org2.id)
        self.assertEqual(len(snap_org2["gates"]), 0)
        blob = json.dumps(snap_org1)
        self.assertNotIn(self.org2.id, blob)


# ---------------------------------------------------------------------------
class TestRbacPermissions(D7Base):
    def test_permission_matrix(self):
        p = rbac.permissions_for(["viewer"])
        self.assertIn("devsecops.read", p)
        self.assertIn("devsecops.export", p)
        self.assertNotIn("devsecops.create", p)
        self.assertNotIn("devsecops.run", p)
        self.assertNotIn("devsecops.delete", p)
        a = rbac.permissions_for(["analyst"])
        for perm in ("devsecops.read", "devsecops.export", "devsecops.create",
                     "devsecops.update", "devsecops.run"):
            self.assertIn(perm, a)
        self.assertNotIn("devsecops.delete", a)
        adm = rbac.permissions_for(["admin"])
        self.assertIn("devsecops.delete", adm)
        self.assertEqual(rbac.permissions_for(["owner"]), adm)

    def test_gates_enforced(self):
        self.add_user(username="viewer", roles=("viewer",))
        ctx = self.ctx_for("viewer")
        self.authz.require(ctx, "devsecops.read")
        self.authz.require(ctx, "devsecops.export")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx, "devsecops.create")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx, "devsecops.run")
        self.add_user(username="analyst", roles=("analyst",))
        ctx2 = self.ctx_for("analyst")
        self.authz.require(ctx2, "devsecops.run")
        self.authz.require(ctx2, "devsecops.update")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx2, "devsecops.delete")
        self.add_user(username="admin", roles=("admin",))
        ctx3 = self.ctx_for("admin")
        self.authz.require(ctx3, "devsecops.delete")

    def test_unknown_permission_fails_closed(self):
        self.add_user(username="owner", roles=("owner",))
        ctx = self.ctx_for("owner")
        with self.assertRaises((errors.AuthorizationError,
                                errors.ValidationError)):
            self.authz.require(ctx, "devsecops.arbitrary")

    def test_denial_audited_without_secrets(self):
        self.add_user(username="viewer", roles=("viewer",))
        ctx = self.ctx_for("viewer")
        g = self.gate()
        # same-org viewer MAY read (tenant isolation is per-org)
        self.authz.require_gate(ctx, g["id"])
        # cross-tenant viewer is denied and the denial is audited, with no
        # secrets and no existence leak
        self.add_user(org=self.org2, username="view2", roles=("viewer",))
        ctx2 = self.ctx_for("view2")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_gate(ctx2, g["id"])
        evs = self.svc.audit_list(None, limit=400)
        actions = [e.action for e in evs]
        self.assertIn("authorization.denied", actions)
        for ev in evs:
            blob = json.dumps(ev.to_dict())
            self.assertNotIn(PW, blob)
            self.assertNotIn(PHISH_MARK, blob)
            self.assertNotIn(SK, blob)


# ---------------------------------------------------------------------------
class TestSecretsRedaction(D7Base):
    def test_export_json_never_leaks(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[
            {"title": "leak", "description": "d", "severity": "Critical",
             "confidence": "high", "category": "injection", "source": "s",
             "rule_id": "rule-secret", "cwe": "CWE-89",
             "remediation": "Fix", "evidence": "Authorization: " + PHISH,
             "raw": {}, "id": "sec1"}])
        res = self.dso.evaluate(run["id"], actor="test")
        raw = self.dso.export_result(res["id"], "json")
        self.assertNotIn(PHISH_MARK, raw.decode("utf-8"))

    def test_sarif_never_leaks(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[
            {"title": "x", "description": "pw=" + SK, "severity": "High",
             "confidence": "high", "category": "xss", "source": "s",
             "rule_id": "rule-s2", "cwe": "CWE-79",
             "remediation": "Fix", "evidence": "Bearer " + PHISH_MARK,
             "raw": {}, "id": "sec2"}])
        res = self.dso.evaluate(run["id"], actor="test")
        raw = self.dso.export_result(res["id"], "sarif")
        blob = raw.decode("utf-8")
        self.assertNotIn(PHISH_MARK, blob)
        self.assertNotIn(SK, blob)

    def test_result_and_run_metadata_redacted(self):
        g = self.gate({"conditions": [],
                       "description": "Bearer " + PHISH_MARK})
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "sr")])
        res = self.dso.evaluate(run["id"], actor="test")
        blob = json.dumps(res) + json.dumps(self.dso.run_get(run["id"]))
        self.assertNotIn(PHISH_MARK, blob)

    def test_ci_metadata_rejects_secret_shaped_input(self):
        g = self.gate()
        with self.assertRaises(errors.ValidationError):
            self.dso.run_create(self.proj.id, g["id"], "crawler",
                                repository="repo; token=" + SK,
                                pipeline_id="p1", run_actor="test")


# ---------------------------------------------------------------------------
class TestSarifAndOutput(D7Base):
    def test_sarif_is_valid_2_1_0(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[
            finding("SQLi", "Critical", "injection", "sarif1")])
        res = self.dso.evaluate(run["id"], actor="test")
        sarif = json.loads(self.dso.export_result(res["id"], "sarif"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        run1 = sarif["runs"][0]
        self.assertIn("results", run1)
        self.assertIn("tool", run1)
        self.assertEqual(run1["tool"]["driver"]["name"], "SecuToolkit")
        inv = run1["invocations"][0]
        sg = inv["properties"]["securityGate"]
        self.assertEqual(sg["status"], res["status"])
        self.assertEqual(sg["result_hash"], res["result_hash"])
        self.assertEqual(sg["gate_id"], res["gate_id"])
        self.assertEqual(sg["ci_run_id"], res["run_id"])
        self.assertEqual(sg["scan_id"], res["scan_id"])
        lev = {r["level"] for r in run1["results"]}
        self.assertIn("error", lev)

    def test_json_export_deterministic(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "jd")])
        res = self.dso.evaluate(run["id"], actor="test")
        a = self.dso.export_result(res["id"], "json")
        b = self.dso.export_result(res["id"], "json")
        self.assertEqual(a, b)
        obj = json.loads(a)
        self.assertEqual(obj["status"], res["status"])
        self.assertEqual(obj["ci_run_id"], res["run_id"])
        self.assertEqual(obj["result_version"], "gate-v1")
        for k in ("project_id", "scan_id", "gate_id", "policy_id",
                  "summary", "violations", "result_hash"):
            self.assertIn(k, obj)

    def test_export_path_security(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "ep")])
        res = self.dso.evaluate(run["id"], actor="test")
        with self.assertRaises(errors.ValidationError):
            self.dso.export_result(res["id"], "json", out_path="a/../b.json")
        ok = os.path.join(self.tmp, "out.json")
        raw = self.dso.export_result(res["id"], "json", out_path=ok)
        self.assertTrue(os.path.exists(ok))
        self.assertEqual(json.loads(open(ok, encoding="utf-8").read())["status"],
                         res["status"])
        with self.assertRaises(errors.ValidationError):
            self.dso.export_result(res["id"], "xml")

    def test_export_audited(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "ea")])
        res = self.dso.evaluate(run["id"], actor="test")
        self.dso.export_result(res["id"], "json", actor="test")
        actions = [e.action for e in self.svc.audit_list(self.proj.id,
                                                         limit=200)]
        self.assertIn("devsecops.exported", actions)


# ---------------------------------------------------------------------------
class TestReportingIntegration(D7Base):
    def test_snapshot_accepts_ci_provenance(self):
        import reporting as _rp
        rsvc = _rp.ReportService(self.svc)
        snap = rsvc.snapshot(self.proj.id, "technical", generated_by="t",
                             ci={"ci_run_id": "run-1", "gate_id": "g-1",
                                 "result_id": "r-1", "status": "pass",
                                 "result_hash": "a" * 64})
        ci = snap["metadata"]["ci"]
        self.assertEqual(ci["ci_run_id"], "run-1")
        self.assertEqual(ci["status"], "pass")
        with self.assertRaises(errors.ValidationError):
            rsvc.snapshot(self.proj.id, "technical",
                          ci={"sneaky": "x"})

    def test_ci_report_stores_phase6_snapshot(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "ri1")])
        res = self.dso.evaluate(run["id"], actor="test")
        stored = self.dso.ci_report(res["id"], report_type="technical",
                                    generated_by="ci")
        row = self.svc.db.query_one(
            "SELECT report_type, report_hash FROM report_runs WHERE id=?",
            (stored["id"],))
        self.assertEqual(row["report_type"], "technical")
        import reporting as _rp
        rsvc = _rp.ReportService(self.svc)
        got = rsvc.get_run(stored["id"], with_payload=True)
        self.assertEqual(got["payload"]["metadata"]["ci"]["result_id"],
                         res["id"])
        self.assertEqual(got["payload"]["metadata"]["ci"]["result_hash"],
                         res["result_hash"])

    def test_ci_deterministic_hash_matches_stored(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "dh")])
        res = self.dso.evaluate(run["id"], actor="test")
        body = {"status": res["status"], "reason": res["reason"],
                "project_id": res["project_id"], "gate_id": res["gate_id"],
                "scan_id": res["scan_id"], "run_id": res["run_id"],
                "policy_hash": res["policy_hash"],
                "policy_version": res["policy_version"],
                "summary": res["summary"], "violations": res["violations"]}
        import hashlib
        h = hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        self.assertEqual(h, res["result_hash"])


# ---------------------------------------------------------------------------
class TestRetention(D7Base):
    def test_days_bounded(self):
        with self.assertRaises(errors.ValidationError):
            self.dso.retention_sweep(0, actor="test")
        with self.assertRaises(errors.ValidationError):
            self.dso.retention_sweep(10000, actor="test")

    def test_sweep_removes_only_old_non_immutable_runs(self):
        g = self.gate()
        old = self.scan_run(g["id"], pipe="pl-old", findings=[])
        new = self.scan_run(g["id"], pipe="pl-new", findings=[])
        self.dso.evaluate(old["id"], actor="test")
        self.dso.evaluate(new["id"], actor="test")
        cut = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(time.time() - 400 * 86400))
        self.svc.db.execute("UPDATE ci_runs SET created_at=? WHERE id=?",
                            (cut, old["id"]))
        res = self.dso.retention_sweep(90, actor="test")
        self.assertEqual(res["removed"], 1)
        rows = self.svc.db.query("SELECT id FROM ci_runs")
        self.assertEqual([r["id"] for r in rows], [new["id"]])
        # gate results (immutable evidence) survive
        self.assertEqual(self.dso.results_list(self.proj.id)["total"], 2)
        # audit never deleted
        self.assertGreaterEqual(
            len(self.svc.audit_list(self.proj.id, limit=500)), 1)

    def test_sweep_tenant_scoped_and_audited(self):
        g = self.gate()
        old = self.scan_run(g["id"], pipe="pl-scope", findings=[])
        self.dso.evaluate(old["id"], actor="test")   # terminal status
        cut = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(time.time() - 400 * 86400))
        self.svc.db.execute("UPDATE ci_runs SET created_at=? WHERE id=?",
                            (cut, old["id"]))
        # sweeping another tenant's project must not touch this run
        other = self.dso.retention_sweep(90, project_id=self.proj2.id,
                                         actor="test")
        self.assertEqual(other["removed"], 0)
        self.assertEqual(
            len(self.svc.db.query("SELECT id FROM ci_runs WHERE id=?",
                                  (old["id"],))), 1)
        out = self.dso.retention_sweep(90, project_id=self.proj.id,
                                       actor="test")
        self.assertEqual(out["removed"], 1)
        actions = [e.action for e in self.svc.audit_list(self.proj.id,
                                                         limit=300)]
        self.assertIn("devsecops.retention", actions)
        blobs = "".join(json.dumps(ev.to_dict()) for ev in
                        self.svc.audit_list(self.proj.id, limit=300))
        self.assertNotIn(PHISH_MARK, blobs)   # never secrets in audit


# ---------------------------------------------------------------------------
class TestConcurrency(D7Base):
    def test_concurrent_duplicate_ci_submission(self):
        g = self.gate()
        results = []
        errors_found = []

        def worker():
            try:
                out = self.dso.run_create(
                    self.proj.id, g["id"], "crawler", pipeline_id="pl-cc",
                    commit_sha="c" * 40, run_actor="test")
                results.append(out["run"]["id"])
            except Exception as e:          # pragma: no cover
                errors_found.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors_found, [])
        self.assertEqual(len(set(results)), 1)          # one logical run
        rows = self.svc.db.query("SELECT id FROM ci_runs WHERE project_id=?",
                                 (self.proj.id,))
        self.assertEqual(len(rows), 1)
        scans = self.svc.db.query("SELECT id FROM scans WHERE project_id=?",
                                  (self.proj.id,))
        self.assertEqual(len(scans), 1)                 # one scan

    def test_concurrent_evaluate_single_result(self):
        g = self.gate()
        run = self.scan_run(g["id"], findings=[finding("A", "Info", "xss",
                                                       "ce")])
        results = []
        errors_found = []

        def worker():
            try:
                results.append(self.dso.evaluate(run["id"], actor="test"))
            except Exception as e:          # pragma: no cover
                errors_found.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors_found, [])
        self.assertEqual(len({r["id"] for r in results}), 1)
        self.assertEqual(len({r["result_hash"] for r in results}), 1)
        rows = self.svc.db.query("SELECT id FROM gate_results")
        self.assertEqual(len(rows), 1)                  # no lost/no dup
        audit = [e.action for e in
                 self.svc.audit_list(self.proj.id, limit=300)]
        self.assertEqual(audit.count("devsecops.gate.passed"), 1)


# ---------------------------------------------------------------------------
class TestFailureInjection(D7Base):
    def test_missing_finding_table_state_never_passes(self):
        """A scan whose findings cannot be proven (risk wiped) must not pass."""
        g = self.gate(POLICY_OK)
        run = self.scan_run(g["id"], findings=[finding("A", "High", "xss",
                                                       "fi1")])
        self.svc.db.execute(
            "UPDATE findings SET calc_version='' WHERE project_id=?",
            (self.proj.id,))
        res = self.dso.evaluate(run["id"], actor="test")
        self.assertNotEqual(res["status"], "pass")
        self.assertEqual(res["status"], "inconclusive")

    def test_orphan_scan_never_passes(self):
        g = self.gate(POLICY_OK)
        run = self.dso.run_create(self.proj.id, g["id"], "crawler",
                                  pipeline_id="pl-orphan", commit_sha="0" * 40,
                                  submit=False, run_actor="test")
        self.svc.db.execute("DELETE FROM scans WHERE id=?",
                            (run["run"]["scan_id"],))
        res = self.dso.evaluate(run["run"]["id"], actor="test")
        self.assertEqual(res["status"], "inconclusive")
        self.assertEqual(res["reason"], "scan_not_found")

    def test_policy_validation_failure_fails_closed(self):
        with self.assertRaises(errors.ValidationError):
            validate_policy({"conditions": [{"key": "a", "op": "<=",
                                             "value": 1}]})
        g = self.gate()
        bad = {"conditions": [{"key": "max_open_critical", "op": "LIKE",
                               "value": 1}]}
        with self.assertRaises(errors.ValidationError):
            self.dso.gate_create(self.proj.id, "bad", bad, actor="test")


# ---------------------------------------------------------------------------
class TestPerformance(D7Base):
    def test_scale_100_500_1000_100runs_50eval(self):
        self.bulk_seed(100, 500, 1000)
        g = self.gate({"conditions": [
            {"key": "max_open_critical", "op": "<=", "value": 1000}]})
        # 100 CI runs (existing scan rows; no workers)
        t0 = time.time()
        run_ids = []
        for i in range(100):
            out = self.dso.run_create(
                self.proj.id, g["id"], "crawler",
                pipeline_id=f"perf-{i}", commit_sha="a" * 40,
                run_actor="test")
            run_ids.append(out["run"]["id"])
        # one real scan + evaluation on top of the seeded state
        real = self.scan_run(g["id"], pipe="perf-real",
                             findings=[finding("P", "Info", "xss", "perf1")])
        res = self.dso.evaluate(real["id"], actor="test")
        self.assertEqual(res["status"], "pass")
        # 50 gate evaluations (idempotent, stored-result path for 49)
        for _ in range(50):
            self.dso.evaluate(real["id"], actor="test")
        elapsed = time.time() - t0
        self.assertLess(elapsed, 30.0)
        self.assertEqual(self.dso.ci_list(self.proj.id, limit=500)["total"],
                         101)
        self.assertEqual(self.dso.results_list(self.proj.id)["total"], 1)
        # record the measured runtime (documented in README, honest number)
        print(f"\n[perf] 100 assets/500 findings/1000 events + 100 CI runs "
              f"+ 50 evaluations: {elapsed:.2f}s")


# ---------------------------------------------------------------------------
class TestCliSmoke(D7Base):
    def run_cli(self, *args, expect=0):
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"), *args],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(out.returncode, expect,
                         f"cmd {' '.join(args)} -> {out.returncode}\n"
                         f"{out.stdout}\n{out.stderr}")
        return out

    def cli_env(self, db):
        svc = pf.PlatformService(db)
        org = svc.org_create("CliOrg")
        proj = svc.project_create(org.id, "CliProj")
        return svc, org, proj

    def test_gate_crud_cli(self):
        db = os.path.join(self.tmp, "cli.db")
        svc, org, proj = self.cli_env(db)
        self.run_cli("devsecops", "gate-create", "--db", db,
                     "--project", proj.id, "--name", "cli-gate",
                     "--policy", json.dumps(POLICY_OK))
        out = self.run_cli("devsecops", "gate-list", "--db", db,
                           "--project", proj.id)
        self.assertIn("cli-gate", out.stdout)
        gid = ds_mod.DevSecOpsService(svc).gate_list(proj.id)["gates"][0]["id"]
        out = self.run_cli("devsecops", "gate-show", "--db", db, gid)
        self.assertIn("cli-gate", out.stdout)
        self.run_cli("devsecops", "gate-update", "--db", db, gid,
                     "--enabled", "false")
        out = self.run_cli("devsecops", "gate-list", "--db", db,
                           "--project", proj.id)
        self.assertIn("off", out.stdout)
        self.run_cli("devsecops", "gate-delete", "--db", db, gid)
        out = self.run_cli("devsecops", "gate-list", "--db", db,
                           "--project", proj.id)
        self.assertIn("0 gate(s)", out.stdout)

    def test_evaluate_ci_cli_exit_codes(self):
        db = os.path.join(self.tmp, "cli2.db")
        svc, org, proj = self.cli_env(db)
        self.run_cli("devsecops", "gate-create", "--db", db,
                     "--project", proj.id, "--name", "g",
                     "--policy", json.dumps({"conditions": [
                         {"key": "max_open_critical", "op": "<=",
                          "value": 0}]}))
        gate = ds_mod.DevSecOpsService(svc).gate_list(proj.id)["gates"][0]["id"]
        # CI run cannot complete without a worker in CLI smoke; use the
        # service to materialize a completed scan for the SAME run id, then
        # drive the CLI evaluate against it.
        get = subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"), "devsecops",
             "ci-create", "--db", db, "--project", proj.id,
             "--gate", gate, "--profile", "crawler",
             "--pipeline-id", "pl-cli", "--commit-sha", "c" * 40],
            capture_output=True, text=True, timeout=180)
        self.assertIn("CI run", get.stdout)
        run_id = [l for l in get.stdout.splitlines() if "CI run:" in l][0]
        run_id = run_id.split()[-1]
        # scan has no worker: the gate must fail closed -> inconclusive (2)
        self.run_cli("devsecops", "evaluate", "--db", db, run_id, expect=2)

    def test_rbac_cli_denied(self):
        db = os.path.join(self.tmp, "cli3.db")
        svc, org, proj = self.cli_env(db)
        ids = identity_mod.IdentityService(svc, scrypt_n=2 ** 8)
        ids.user_create(org.id, "viewer", "v@a.test", PW,
                        roles=("viewer",), allow_any_role=True, actor="test")
        secret = ids.login("viewer", PW)["secret"]
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"), "devsecops",
             "gate-create", "--db", db, "--as", secret,
             "--project", proj.id, "--name", "x",
             "--policy", json.dumps(POLICY_OK)],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(out.returncode, 11)   # AuthorizationError
        self.assertIn("Forbidden", out.stdout + out.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
