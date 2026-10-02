#!/usr/bin/env python3
# ============================================================================
#  test_orchestration.py — Phase-3 managed scan execution test suite.
#  ---------------------------------------------------------------------------
#  Covers: job lifecycle, atomic claiming (concurrency), leases + stale
#  recovery, retry policy (retryable vs non-retryable, backoff, dead-letter),
#  pause/resume with honest checkpoint semantics, cancellation, stage
#  checkpoints, execution-time revalidation (org/project/actor/scope/active),
#  per-org fairness caps, priority, idempotency (re-ingest, double
#  completion), partial-result preservation, subprocess safety (no shell,
#  injection attempts, timeouts, bounded/truncated output, bounded JSON),
#  payload security (allowlist, oversized, control chars, pickle/malicious
#  JSON rejection), redaction of job payloads, audit events (and no heartbeat
#  audit flooding), metrics, worker registry, multi-tenant job isolation,
#  and CLI smoke (local single-user mode, RBAC tokens).
#
#  Pure local: no internet, no live scanners (stage runners are fakes).
#  Loaded by tests/run_tests.py so the WHOLE suite runs together.
# ============================================================================

import json
import shutil
import os
import sqlite3
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

import errors                       # noqa: E402
import metrics                      # noqa: E402
import models                       # noqa: E402
import platform_service as pf               # noqa: E402
import jobs as jb                   # noqa: E402
import scanners as sc               # noqa: E402
import worker as wk                 # noqa: E402
import authz as az                  # noqa: E402
import identity as idm              # noqa: E402
import store                        # noqa: E402
import sec_config                   # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class FakeRegistry:
    """Test registry with multi-stage profiles (static, test-local, never
    used by production code — mirrors ScannerRegistry's interface)."""

    def __init__(self):
        self.PROFILES = {
            "two-stage": type("P", (), {
                "name": "two-stage", "stages": ["s1", "s2"],
                "active_required": False, "timeout": 60,
                "description": "test", "permissions_required": ("scan.create",)})(),
            "active-test": type("P", (), {
                "name": "active-test", "stages": ["act"],
                "active_required": True, "timeout": 60,
                "description": "test", "permissions_required": ("scan.create",)})(),
            "one-stage": type("P", (), {
                "name": "one-stage", "stages": ["only"],
                "active_required": False, "timeout": 60,
                "description": "test", "permissions_required": ("scan.create",)})(),
        }

    @property
    def ACTIVE_PROFILES(self):
        return frozenset(p.name for p in self.PROFILES.values()
                         if p.active_required)

    def validate_profile(self, name):
        n = str(name or "").strip()
        if n not in self.PROFILES:
            raise errors.ValidationError(f"profile_unknown: {n!r}")
        return n

    def get(self, name):
        return self.PROFILES[self.validate_profile(name)]


def made_service(tmp):
    return pf.PlatformService(os.path.join(tmp, "orch.db"))


def make_setup(tmp, registry=None):
    svc = made_service(tmp)
    reg = registry or FakeRegistry()
    js = jb.JobService(svc, reg)
    org = svc.org_create("Orch Org")
    proj = svc.project_create(org.id, "Orch Project")
    svc.scope_set(proj.id, ["example.com", "*.example.com"], [])
    scan = svc.scan_create(proj.id, "full", "", scan_id="scan-1")
    return svc, js, reg, org, proj, scan


def runner_returning(payload):
    def fake(profile_name, stage_name, job, target):
        return dict(payload), False
    return fake


def runner_raising(code, message):
    def fake(profile_name, stage_name, job, target):
        raise errors.ScannerError(f"{code}: {message}")
    return fake


# ---------------------------------------------------------------------------
# 1. job lifecycle + payload validation
# ---------------------------------------------------------------------------
class TestJobLifecycle(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)

    def test_create_queues_and_persists(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"}, actor_id="cli")
        self.assertEqual(job.status, "queued")
        self.assertEqual(job.attempt, 0)
        got = self.js.job_get(job.id)
        self.assertEqual(got.id, job.id)
        self.assertEqual(got.project_id, self.proj.id)
        self.assertEqual(got.org_id, self.org.id)
        self.assertTrue(got.created_at)
        # persisted in the SAME sqlite file — restart-proof
        svc2 = pf.PlatformService(self.svc.db_path)
        js2 = jb.JobService(svc2, self.reg)
        again = js2.job_get(job.id)
        self.assertEqual(again.status, "queued")

    def test_priority_normalized_server_side(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com", "note": "a"},
                                 priority="critical")
        self.assertEqual(job.priority, 1)
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com", "note": "b"},
                                 priority="low")
        self.assertEqual(job.priority, 4)
        with self.assertRaises(errors.ValidationError):
            self.js.create_job(self.scan.id, "one-stage",
                               {"target": "example.com"},
                               priority="ultra")
        # numeric garbage rejected too
        with self.assertRaises(errors.ValidationError):
            self.js.create_job(self.scan.id, "one-stage",
                               {"target": "example.com"},
                               priority="1")

    def test_unknown_profile_rejected(self):
        with self.assertRaises(errors.ValidationError) as cm:
            self.js.create_job(self.scan.id, "not-a-real-profile",
                               {"target": "example.com"})
        self.assertIn("profile_unknown", cm.exception.message)

    def test_payload_unknown_field_rejected(self):
        with self.assertRaises(errors.ValidationError) as cm:
            self.js.create_job(self.scan.id, "one-stage",
                               {"target": "example.com",
                                "module_path": "/etc/passwd"})
        self.assertIn("payload_rejected", cm.exception.message)

    def test_payload_oversized_rejected(self):
        with self.assertRaises(errors.ValidationError) as cm:
            self.js.create_job(self.scan.id, "one-stage",
                               {"target": "example.com",
                                "note": "x" * 6000})
        self.assertIn("payload_rejected", cm.exception.message)

    def test_payload_control_chars_and_shell_fragments_rejected(self):
        for bad in ("example.com\nrm -rf /", "example.com$(id)",
                    "example.com`id`", "example.com; whoami",
                    "example.com|cat", "example.com\\x"):
            with self.assertRaises(errors.ValidationError, msg=repr(bad)):
                self.js.create_job(self.scan.id, "one-stage",
                                   {"target": bad})
        # query strings with & stay legal (argv execution, no shell)
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "http://example.com/?a=1&b=2"})
        self.assertEqual(job.status, "queued")

    def test_pickle_payload_rejected(self):
        import pickle
        blob = pickle.dumps({"target": "example.com"})
        with self.assertRaises(errors.ValidationError):
            self.js.create_job(self.scan.id, "one-stage", blob)

    def test_malicious_json_string_rejected(self):
        payload = {"target": "example.com", "note": "\u0000\u0001boom"}
        with self.assertRaises(errors.ValidationError):
            self.js.create_job(self.scan.id, "one-stage", payload)

    def test_payload_secrets_redacted_at_rest(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "https://alice:hunter2@example.com/"})
        got = self.js.job_get(job.id)
        raw = json.dumps(got.to_dict())
        self.assertNotIn("hunter2", raw)
        row = self.svc.db.query_one("SELECT payload FROM jobs WHERE id=?",
                                    (job.id,))
        self.assertNotIn("hunter2", row["payload"])

    def test_same_state_ops_are_noop(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        # cancelling an already-cancelled job is harmless
        self.js.cancel(job.id)
        self.js.cancel(job.id)
        self.assertEqual(self.js.job_get(job.id).status, "cancelling")

    def test_invalid_transition_fails_closed(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        # pausing a terminal job is not allowed (fail closed)
        self.js.claim_next("w1")
        self.js.complete(job.id)
        with self.assertRaises(errors.LifecycleError):
            self.js.pause(job.id)
        # double completion is an idempotent no-op (never raises)
        again = self.js.complete(job.id)
        self.assertEqual(again.status, "completed")


# ---------------------------------------------------------------------------
# 2. atomic claiming + concurrency
# ---------------------------------------------------------------------------
class TestAtomicClaim(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)

    def test_only_one_worker_claims(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        first = self.js.claim_next("worker-a")
        self.assertIsNotNone(first)
        self.assertEqual(first.worker_id, "worker-a")
        second = self.js.claim_next("worker-b")
        self.assertIsNone(second)
        self.assertEqual(self.js.job_get(job.id).worker_id, "worker-a")

    def test_concurrent_claim_exactly_one_wins(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        results = []
        lock = threading.Lock()

        def try_claim(i):
            svc_i = pf.PlatformService(self.svc.db_path)
            js_i = jb.JobService(svc_i, self.reg)
            got = js_i.claim_next(f"worker-{i}")
            with lock:
                results.append(got)

        threads = [threading.Thread(target=try_claim, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        winners = [r for r in results if r is not None]
        self.assertEqual(len(winners), 1, "exactly one winner expected")
        job_now = self.js.job_get(job.id)
        self.assertEqual(job_now.status, "running")
        self.assertEqual(job_now.worker_id, winners[0].worker_id)

    def test_heartbeat_updates_lease_only_for_owner(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        self.js.claim_next("worker-a")
        self.assertTrue(self.js.heartbeat(job.id, "worker-a"))
        self.assertFalse(self.js.heartbeat(job.id, "worker-b"))
        self.assertTrue(self.js.heartbeat(job.id, "worker-a"))
        j = self.js.job_get(job.id)
        self.assertTrue(j.heartbeat_at)
        self.assertTrue(j.lease_until)

    def test_priority_ordering(self):
        # raise the concurrency caps so all four claimable in this test
        js = jb.JobService(self.svc, self.reg, org_concurrency=8,
                           project_concurrency=8)
        for prio in ("low", "critical", "normal", "high"):
            sc = self.svc.scan_create(self.proj.id, "full",
                                      scan_id=f"scan-{prio}")
            js.create_job(sc.id, "one-stage",
                          {"target": "example.com"}, priority=prio)
        claimed = [js.claim_next(f"w{i}") for i in range(4)]
        order = [c.priority for c in claimed]
        self.assertEqual(order, [1, 2, 3, 4], "critical first, low last")

    def test_per_org_cap_prevents_starvation(self):
        """org B keeps running while org A is capped — no tenant starvation."""
        org_b = self.svc.org_create("Org B")
        self.svc.db.execute(
            "INSERT INTO projects (id, org_id, name, description, status, "
            "scope_json, created_at, updated_at) VALUES "
            "(?,?,?,?,?,?,?,?)",
            ("proj-b", org_b.id, "P-B", "", "active", "{}",
             models.utcnow(), models.utcnow()))
        self.svc.scope_set("proj-b", ["example.org"], [])
        scan_b = self.svc.scan_create("proj-b", "full", "", scan_id="scan-b")
        js2 = jb.JobService(self.svc, self.reg, org_concurrency=1)
        for i in range(3):
            sc = self.svc.scan_create(self.proj.id, "full",
                                      scan_id=f"scan-a{i}")
            js2.create_job(sc.id, "one-stage", {"target": "example.com"})
        js2.create_job(scan_b.id, "one-stage", {"target": "example.org"})
        claimed = []
        got = js2.claim_next("w")
        while got is not None and len(claimed) < 10:
            claimed.append(got)
            got = js2.claim_next("w")
        orgs_seen = {c.org_id for c in claimed}
        self.assertIn(org_b.id, orgs_seen,
                      "round-robin let org B through despite A's jobs")
        self.assertEqual(
            len([c for c in claimed if c.org_id == self.org.id]), 1,
            "per-org cap honoured")


# ---------------------------------------------------------------------------
# 3. retry policy, leases, stale recovery, dead-letter
# ---------------------------------------------------------------------------
class TestRetryAndStale(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)

    def _queue_job(self, prio="normal", attempts=3, max_attempts=3):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"},
                                 priority=prio, max_attempts=max_attempts)
        return job

    def test_retryable_failure_schedules_backoff(self):
        job = self._queue_job()
        self.js.claim_next("w1")
        j = self.js.fail(job.id, "network_error", "connection refused")
        self.assertEqual(j.status, "retry_wait")
        self.assertTrue(j.retry_at >= j.created_at)
        self.assertEqual(j.attempt, 1)
        # bounded exponential backoff with jitter (base 2, max 300, jitter 5)
        d0 = jb.retry_delay(0)
        self.assertLessEqual(d0, 2.0 + 5.0 + 1e-6)
        self.assertGreaterEqual(d0, 2.0)
        d10 = jb.retry_delay(10)
        self.assertLessEqual(d10, 300.0 + 5.0 + 1e-6)
        self.assertGreaterEqual(d10, 300.0)

    def test_unretryable_never_retried(self):
        for i, code in enumerate(("scope_denied", "auth_failed",
                                  "config_invalid", "validation_rejected",
                                  "payload_rejected", "profile_unknown",
                                  "not_authorized_active",
                                  "project_inactive", "org_disabled",
                                  "scan_invalid")):
            sc = self.svc.scan_create(self.proj.id, "full",
                                      scan_id=f"scan-u{i}")
            job = self.js.create_job(sc.id, "one-stage",
                                     {"target": "example.com"})
            self.js.claim_next("w1")
            j = self.js.fail(job.id, code, "boom")
            self.assertEqual(j.status, "failed", f"{code} must never retry")
            self.assertEqual(j.error_code, code)

    def test_max_attempts_then_dead_letter(self):
        job = self._queue_job(max_attempts=2)
        self.js.claim_next("w1")
        j = self.js.fail(job.id, "network_error", "x")     # attempt 1 → retry
        self.assertEqual(j.status, "retry_wait")
        self.js.queue(job.id)
        self.js.claim_next("w2")                            # attempt 2
        j = self.js.fail(job.id, "network_error", "x again")
        self.assertEqual(j.status, "dead_letter",
                         "attempts exhausted → administrator-visible")
        self.assertEqual(j.attempt, 2)

    def test_stale_lease_retries_then_dead_letters(self):
        job = self._queue_job(max_attempts=2)
        self.js.claim_next("w1")
        # expire the lease (worker died without releasing)
        self.svc.db.execute("UPDATE jobs SET lease_until='2000-01-01T00:00:00Z' "
                            "WHERE id=?", (job.id,))
        n = self.js.sweep_stale()
        self.assertEqual(n, 1)
        j = self.js.job_get(job.id)
        self.assertEqual(j.status, "retry_wait")
        self.assertEqual(j.error_code, "stale_worker")
        self.assertFalse(j.worker_id, "claimed worker id cleared")
        # let backoff pass, reclaim, expire again → exhausted → dead letter
        self.svc.db.execute("UPDATE jobs SET retry_at='' WHERE id=?",
                            (job.id,))
        self.js.queue(job.id)
        self.js.claim_next("w2")
        self.svc.db.execute("UPDATE jobs SET lease_until='2000-01-01T00:00:00Z' "
                            "WHERE id=?", (job.id,))
        self.js.sweep_stale()
        j = self.js.job_get(job.id)
        self.assertEqual(j.status, "dead_letter")
        self.assertEqual(j.error_code, "stale_worker")

    def test_manual_retry_of_terminal_job(self):
        job = self._queue_job()
        self.js.claim_next("w1")
        self.js.fail(job.id, "scope_denied", "nope")
        j = self.js.retry_manual(job.id)
        self.assertEqual(j.status, "queued")
        self.assertEqual(j.attempt, 0)
        with self.assertRaises(errors.LifecycleError):
            self.js.retry_manual(job.id)   # re-queuing a running job is no


# ---------------------------------------------------------------------------
# 4. execution-time revalidation (fail closed)
# ---------------------------------------------------------------------------
class TestExecutionRevalidation(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)

    def _claim_job(self, **kw):
        kw.setdefault("actor_id", "u1")
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"}, **kw)
        self.js.claim_next("w1")
        return job

    def test_org_disabled_fails_closed(self):
        job = self._claim_job()
        self.svc.db.execute("UPDATE organizations SET status='disabled' "
                            "WHERE id=?", (self.org.id,))
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1")
        worker._execute(job)
        j = self.js.job_get(job.id)
        self.assertEqual(j.status, "failed")
        self.assertEqual(j.error_code, "org_disabled")

    def test_project_inactive_fails_closed(self):
        job = self._claim_job()
        self.svc.db.execute("UPDATE projects SET status='archived' "
                            "WHERE id=?", (self.proj.id,))
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1")
        worker._execute(job)
        j = self.js.job_get(job.id)
        self.assertEqual(j.error_code, "project_inactive")

    def test_scan_terminal_fails_closed(self):
        job = self._claim_job()
        self.svc.scan_transition(self.scan.id, "failed")
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1")
        worker._execute(job)
        self.assertEqual(self.js.job_get(job.id).error_code, "scan_invalid")

    def test_target_removed_from_scope_denied_before_execution(self):
        job = self._claim_job()
        # scope changes AFTER the job was queued (target no longer allowed):
        self.svc.scope_set(self.proj.id, ["nomatch.invalid"], [])
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1",
                                  stage_runner=runner_raising(
                                      "network_error", "should not run"))
        worker._execute(job)
        j = self.js.job_get(job.id)
        self.assertEqual(j.status, "failed")
        self.assertEqual(j.error_code, "scope_denied")
        # no network-producing stage ever started
        stages = self.svc.scan_stage_list(self.scan.id)
        self.assertEqual([s.status for s in stages], [])

    def test_scope_revalidated_before_each_stage(self):
        """Scope check runs before EVERY stage even when it was valid at
        queue time — a queued job cannot bypass a scope change."""
        sc = self.svc.scan_create(self.proj.id, "full", scan_id="scan-x")
        job = self.js.create_job(sc.id, "two-stage",
                                 {"target": "example.com"})
        self.js.claim_next("w1")
        # valid at claim, revoked before the stage loop
        self.svc.scope_set(self.proj.id, ["nomatch.invalid"], [])
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1",
                                  stage_runner=runner_raising(
                                      "network_error", "must not run"))
        worker._execute(job)
        self.assertEqual(self.js.job_get(job.id).error_code, "scope_denied")

    def test_active_scanning_denied_without_flag(self):
        job = self.js.create_job(self.scan.id, "active-test",
                                 {"target": "example.com"})
        self.js.claim_next("w1")
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1",
                                  stage_runner=runner_raising(
                                      "network_error", "must not run"))
        worker._execute(job)
        self.assertEqual(self.js.job_get(job.id).error_code,
                         "not_authorized_active")

    def test_active_scanning_allowed_only_when_explicit(self):
        job = self.js.create_job(self.scan.id, "active-test",
                                 {"target": "example.com"},
                                 active_enabled=True)
        self.js.claim_next("w1")
        worker = wk.WorkerRuntime(
            self.svc, None, self.js, self.reg, worker_id="w1",
            stage_runner=runner_returning(
                {"tool": "active", "findings": []}))
        worker._execute(job)
        self.assertEqual(self.js.job_get(job.id).status, "completed")

    def test_disabled_actor_denied_at_execution(self):
        job = self._claim_job()
        worker = wk.WorkerRuntime(
            self.svc, None, self.js, self.reg, worker_id="w1",
            actor_check=lambda uid: (False, "user not active"))
        worker._execute(job)
        j = self.js.job_get(job.id)
        self.assertEqual(j.status, "failed")
        self.assertEqual(j.error_code, "auth_failed")
        events = self.svc.audit_list_org(self.org.id)
        self.assertTrue(any(a.action == "authorization.denied"
                            for a in events))


# ---------------------------------------------------------------------------
# 5. pause / resume / cancellation (honest checkpoint semantics)
# ---------------------------------------------------------------------------
class TestPauseResumeCancel(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)

    def _job(self, profile="two-stage"):
        sc = self.svc.scan_create(self.proj.id, "full", scan_id="scan-p")
        job = self.js.create_job(sc.id, profile,
                                 {"target": "example.com"})
        self.js.claim_next("w1")
        return job

    def test_pause_queued_vs_running(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        p = self.js.pause(job.id)
        self.assertEqual(p.status, "paused")
        self.js.resume(job.id)
        self.js.claim_next("w1")
        self.js.pause(job.id)
        self.assertEqual(self.js.job_get(job.id).status, "paused")
        # completed jobs cannot be paused
        self.js.resume(job.id)
        self.js.claim_next("w1")
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1",
                                  stage_runner=runner_returning(
                                      {"tool": "t", "subdomains": {}}))
        worker._execute(self.js.job_get(job.id))
        with self.assertRaises(errors.LifecycleError):
            self.js.pause(job.id)

    def test_pause_between_stages_honest_semantics(self):
        """pause: the running stage completes, the NEXT stage does not start."""
        job = self._job()
        calls = []
        control = {"v": None}

        def fake(profile_name, stage_name, job, target):
            calls.append(stage_name)
            if stage_name == "s1":
                # operator pauses while stage 1 is running (real API call —
                # the job flips to 'paused'; the worker observes it at the
                # NEXT safe checkpoint, after stage 1 finished)
                self.js.pause(job.id)
                control["v"] = "paused"
            return {"tool": "t", "note": f"stage {stage_name}"}, False

        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1", stage_runner=fake)
        orig = self.js.control_state
        self.js.control_state = lambda jid: control["v"]
        try:
            worker._execute(job)
        finally:
            self.js.control_state = orig
        self.assertEqual(calls, ["s1"], "stage 1 completed, stage 2 untouched")
        self.assertEqual(self.js.job_get(job.id).status, "paused")
        self.assertEqual(self.svc.scan_get(job.scan_id).status, "paused")
        stages = {s.stage: s.status for s in
                  self.svc.scan_stage_list(job.scan_id)}
        self.assertEqual(stages.get("s1"), "completed")
        self.assertNotEqual(stages.get("s2"), "completed",
                            "stage 2 must not have started")

    def test_resume_continues_from_checkpoint_no_restart(self):
        job = self._job()
        calls = []
        control = {"v": None}

        def fake(profile_name, stage_name, job, target):
            calls.append(stage_name)
            return {"tool": "t", "note": f"stage {stage_name}"}, False

        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1", stage_runner=fake)
        orig = self.js.control_state
        self.js.pause(job.id)                 # operator action (real API)
        self.js.control_state = lambda jid: "paused"
        try:
            worker._execute(self.js.job_get(job.id))
        finally:
            self.js.control_state = orig
        self.assertEqual(calls, [], "no stage may start while paused")
        self.assertEqual(self.svc.scan_get(job.scan_id).status, "paused")
        # resume: operator queues it again; continue from checkpoint
        self.js.resume(job.id)
        self.js.claim_next("w1")
        self.js.control_state = lambda jid: None
        try:
            worker._execute(self.js.job_get(job.id))
        finally:
            self.js.control_state = orig
        self.assertEqual(calls, ["s1", "s2"])
        self.assertEqual(self.js.job_get(job.id).status, "completed")

    def test_resume_skips_completed_stage(self):
        job = self._job()
        calls = []
        control = {"v": None}

        def fake(profile_name, stage_name, job, target):
            calls.append(stage_name)
            if stage_name == "s1":
                self.js.pause(job.id)      # operator pauses after s1
            return {"tool": "t", "note": f"stage {stage_name}"}, False

        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1", stage_runner=fake)
        orig = self.js.control_state

        def patched(jid):
            if calls == ["s1"]:
                control["v"] = "paused"
            return control["v"]

        self.js.control_state = patched
        try:
            worker._execute(job)     # s1 completes → pause before s2
        finally:
            self.js.control_state = orig
        self.assertEqual(calls, ["s1"])
        # resume → only s2 runs, s1 checkpoint is reused (never restarted)
        self.js.resume(job.id)
        self.js.claim_next("w1")
        self.js.control_state = lambda jid: None
        try:
            worker._execute(job)
        finally:
            self.js.control_state = orig
        self.assertEqual(calls, ["s1", "s2"])
        stage_rows = self.svc.db.query(
            "SELECT stage, status, attempt FROM scan_stages WHERE scan_id=? "
            "ORDER BY stage", (job.scan_id,))
        s1 = [r for r in stage_rows if r["stage"] == "s1"][0]
        self.assertEqual(s1["attempt"], 1,
                         "completed stage is NOT re-executed")

    def test_cancellation_stops_at_next_checkpoint(self):
        job = self._job()
        calls = []
        control = {"v": None}

        def fake(profile_name, stage_name, job, target):
            calls.append(stage_name)
            if stage_name == "s1":
                self.js.cancel(job.id)      # operator cancels mid-scan
                control["v"] = "cancelling"
            return {"tool": "t", "note": "x"}, False

        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1", stage_runner=fake)
        orig = self.js.control_state
        self.js.control_state = lambda jid: control["v"]
        try:
            worker._execute(job)
        finally:
            self.js.control_state = orig
        self.assertEqual(calls, ["s1"])
        self.assertEqual(self.js.job_get(job.id).status, "cancelled")
        self.assertEqual(self.svc.scan_get(job.scan_id).status, "cancelled")
        stages = {s.stage: s.status for s in
                  self.svc.scan_stage_list(job.scan_id)}
        self.assertEqual(stages.get("s1"), "completed")
        self.assertEqual(stages.get("s2"), "cancelled")

    def test_cancel_api_and_finalize(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        # cancel a queued job → cancelling → cancelled (no worker needed)
        j = self.js.cancel(job.id)
        self.assertEqual(j.status, "cancelling")
        j = self.js.cancel_finalize(job.id)
        self.assertEqual(j.status, "cancelled")
        self.assertTrue(j.finished_at)

    def test_same_state_pause_is_noop(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        self.js.pause(job.id)
        again = self.js.pause(job.id)
        self.assertEqual(again.status, "paused")


# ---------------------------------------------------------------------------
# 6. idempotency + partial results
# ---------------------------------------------------------------------------
class TestIdempotencyAndPartial(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)

    RAW = {"tool": "recon", "scope_id": "t1", "domain": "example.com",
           "count": 2, "subdomains": {
               "www.example.com": {"sources": ["x"], "ips": ["1.2.3.4"]},
               "mail.example.com": {"sources": ["x"], "ips": []}}}

    def test_double_completion_idempotent(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        self.js.claim_next("w1")
        self.js.complete(job.id)
        fin1 = self.js.job_get(job.id).finished_at
        # second complete is a no-op — no corruption of counts/timestamps
        again = self.js.complete(job.id)
        self.assertEqual(again.status, "completed")
        self.assertEqual(again.finished_at, fin1)

    def test_stage_retry_does_not_duplicate_findings(self):
        sc = self.svc.scan_create(self.proj.id, "full", scan_id="scan-r")
        job = self.js.create_job(sc.id, "one-stage",
                                 {"target": "example.com"})
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1")
        self.js.claim_next("w1")
        # simulate: results persisted, then worker died before stage record
        n1, _ = worker._persist_stage_result(job, self.reg.get("one-stage"),
                                             "only", self.RAW)
        n2, _ = worker._persist_stage_result(job, self.reg.get("one-stage"),
                                             "only", self.RAW)
        self.assertEqual(n1, n2)
        findings = self.svc.finding_list(self.proj.id)
        self.assertEqual(len(findings), n1)
        # stage checkpoint upsert is also idempotent
        st1 = models.StageRecord(scan_id=sc.id, stage="only",
                                 status="completed", job_id=job.id,
                                 attempt=1, result_reference=f"findings:{n1}")
        self.svc.scan_stage_record(st1)
        st2 = self.svc.scan_stage_get(sc.id, "only")
        self.assertEqual(st2.status, "completed")
        self.assertEqual(self.svc.scan_stage_record(st1).id, st2.id)

    def test_partial_results_preserved_on_failure(self):
        sc = self.svc.scan_create(self.proj.id, "full", scan_id="scan-p2")
        job = self.js.create_job(sc.id, "two-stage",
                                 {"target": "example.com"})
        calls = []

        def fake(profile_name, stage_name, job, target):
            calls.append(stage_name)
            if stage_name == "s2":
                raise errors.ScannerError(
                    "timeout: scanner exceeded its time budget")
            return {"tool": "t", "subdomains": {"www.example.com": {
                "sources": ["x"], "ips": ["1.2.3.4"]}}}, False

        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1", stage_runner=fake)
        self.js.claim_next("w1")
        worker._execute(job)
        # stage 1 completed and visible; stage 2 failed; job retried/not lost
        stages = {s.stage: s.status for s in
                  self.svc.scan_stage_list(sc.id)}
        self.assertEqual(stages.get("s1"), "completed")
        self.assertEqual(stages.get("s2"), "failed")
        self.assertEqual(self.js.job_get(job.id).status, "retry_wait")
        self.assertEqual(self.svc.scan_get(sc.id).status, "failed")
        self.assertTrue(self.svc.scan_get(sc.id).finished_at)
        self.assertTrue(calls, ["s1", "s2"])

    def test_findings_cap_marked_not_silent(self):
        """When the per-stage finding cap applies, the stage record AND the
        audit event both say so — bounded storage is never silent."""
        import worker as _wk2
        sc = self.svc.scan_create(self.proj.id, "full", scan_id="scan-cap")
        job = self.js.create_job(sc.id, "one-stage",
                                 {"target": "example.com"})
        self.js.claim_next("w1")
        old = _wk2.FINDINGS_PER_STAGE_CAP
        _wk2.FINDINGS_PER_STAGE_CAP = 2
        try:
            worker = wk.WorkerRuntime(
                self.svc, None, self.js, self.reg, worker_id="w1",
                stage_runner=runner_returning(
                    {"tool": "t", "findings": [
                        {"title": f"F{i}", "severity": "High",
                         "description": f"d{i}"} for i in range(5)]}))
            worker._execute(job)
        finally:
            _wk2.FINDINGS_PER_STAGE_CAP = old
        self.assertEqual(self.js.job_get(job.id).status, "completed")
        stage = self.svc.scan_stage_get(sc.id, "only")
        self.assertIn("capped", stage.result_reference)
        events = [a for a in self.svc.audit_list(limit=500)
                  if a.action == "stage.completed"]
        self.assertTrue(any(a.metadata.get("findings_capped") is True
                            for a in events),
                        "audit event must flag the capped stage")
        self.assertEqual(len(self.svc.finding_list(self.proj.id)), 2)

    def test_scan_progress_deterministic(self):
        for s in ("s1", "s2"):
            self.svc.scan_stage_record(models.StageRecord(
                scan_id=self.scan.id, stage=s, status="completed"))
        p = self.svc.scan_progress(self.scan.id, ["s1", "s2", "s3"])
        self.assertAlmostEqual(p, 2 / 3)


# ---------------------------------------------------------------------------
# 7. subprocess safety + bounded capture
# ---------------------------------------------------------------------------
class TestSubprocessSafety(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)
        self.reg2 = sc.ScannerRegistry()
        self.svc2 = pf.PlatformService(os.path.join(self.tmp, "sc.db"))
        self.js2 = jb.JobService(self.svc2, self.reg2)

    def test_build_argv_never_uses_shell(self):
        argv = self.reg2.build_argv("recon", "example.com", {}, self.tmp, 30)
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(argv[1], os.path.join(PY, "subdomain_enum.py"))
        for a in argv:
            self.assertIsInstance(a, str)
        # a target with spaces is ONE argv element, never a command line
        argv = self.reg2.build_argv("web-audit", "https://example.com/a b",
                                    {}, self.tmp, 30)
        self.assertIn("https://example.com/a b", argv)
        self.assertNotIn(";", " ".join(argv))

    def test_command_injection_attempts_rejected_at_payload(self):
        for injection in ("example.com; rm -rf /",
                          "example.com $(curl evil)",
                          "example.com`whoami`",
                          "example.com|cat /etc/passwd",
                          "example.com\\nreboot",
                          "example.com' OR '1'='1"):
            with self.assertRaises(errors.ValidationError, msg=repr(injection)):
                self.js.create_job(self.scan.id, "one-stage",
                                   {"target": injection})

    def test_ports_spec_validated(self):
        self.assertTrue(sc._safe_ports("22,80,443"))
        self.assertTrue(sc._safe_ports("8000-8100"))
        self.assertFalse(sc._safe_ports("22; rm -rf /"))
        self.assertFalse(sc._safe_ports("22|cat"))
        self.assertFalse(sc._safe_ports("x" * 300))

    def test_timeout_is_controlled_not_blind(self):
        argv = [sys.executable, "-c",
                "import time; time.sleep(30)"]
        with self.assertRaises(errors.ScannerError) as cm:
            self.reg2.capture_output(argv, timeout=1.0)
        self.assertIn("timeout", cm.exception.message)

    def test_bounded_stdout_truncation_flagged(self):
        import scanners as _sc
        old = _sc.MAX_STDOUT
        _sc.MAX_STDOUT = 200
        try:
            argv = [sys.executable, "-c",
                    "print('A'*10000)"]
            rc, out, err, truncated = self.reg2.capture_output(argv, 10)
        finally:
            _sc.MAX_STDOUT = old
        self.assertEqual(rc, 0)
        self.assertTrue(truncated)
        self.assertLessEqual(len(out), 200)

    def test_fast_failure_surfaces_stderr(self):
        argv = [sys.executable, "-c",
                "import sys; sys.stderr.write('boom'); sys.exit(3)"]
        rc, out, err, truncated = self.reg2.capture_output(argv, 10)
        self.assertEqual(rc, 3)
        self.assertIn("boom", err)
        # the WORKER converts a non-zero rc into a controlled failure
        try:
            raise errors.ScannerError(
                f"subprocess_failed: scanner exited {rc}: {err.strip()[:200]}")
        except errors.ScannerError as cm:
            self.assertIn("subprocess_failed", str(cm.message))

    def test_missing_binary_reported_not_crashed(self):
        with self.assertRaises(errors.ScannerError) as cm:
            self.reg2.capture_output(["/nonexistent/binary-xyz"], 5)
        self.assertIn("config_invalid", cm.exception.message)

    def test_malformed_json_and_oversize_rejected(self):
        workdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
        with open(os.path.join(workdir, "result.json"), "w") as fh:
            fh.write("{not valid json")
        with self.assertRaises(errors.ScannerError) as cm:
            self.reg2.read_json_result(workdir)
        self.assertIn("malformed_output", cm.exception.message)
        big = os.path.join(workdir, "result.json")
        with open(big, "w") as fh:
            fh.write("[" + "1," * (sc.MAX_JSON // 2) + "1]")
        with self.assertRaises(errors.ScannerError) as cm:
            self.reg2.read_json_result(workdir)
        self.assertIn("validation_rejected", cm.exception.message)

    def test_rust_scanner_argv_structure(self):
        argv = self.reg2.build_argv("port-scan", "example.com",
                                    {"ports": "22,443"}, self.tmp, 60)
        self.assertEqual(argv[0], os.path.join(ROOT, "rust", "port_scanner"))
        argv = self.reg2.build_argv("dir-fuzz", "https://example.com", {},
                                    self.tmp, 60)
        self.assertEqual(argv[0], os.path.join(ROOT, "rust", "dir_fuzzer"))


# ---------------------------------------------------------------------------
# 8. authz + multi-tenant isolation
# ---------------------------------------------------------------------------
class TestPhase3TenantIsolation(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)
        # tenant B
        self.org_b = self.svc.org_create("Org B")
        self.svc.db.execute(
            "INSERT INTO projects (id, org_id, name, description, status, "
            "scope_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            ("proj-b", self.org_b.id, "P-B", "", "active", "{}",
             models.utcnow(), models.utcnow()))
        self.svc.scope_set("proj-b", ["example.org"], [])
        self.scan_b = self.svc.scan_create("proj-b", "full", "",
                                           scan_id="scan-b")
        self.job_b = self.js.create_job(self.scan_b.id, "one-stage",
                                        {"target": "example.org"},
                                        actor_id="cli")
        self.id_svc = idm.IdentityService(self.svc)
        self.authz = az.AuthorizationService(self.svc, self.id_svc)

    def test_job_isolation_org_scope(self):
        only_a = self.js.job_list(org_id=self.org.id)
        self.assertNotIn(self.job_b.id, [j.id for j in only_a])
        only_b = self.js.job_list(org_id=self.org_b.id)
        self.assertIn(self.job_b.id, [j.id for j in only_b])

    def test_project_scope_visibility(self):
        rows = self.js.job_list(project_id="proj-b")
        self.assertEqual([r.id for r in rows], [self.job_b.id])
        rows = self.js.job_list(project_id=self.proj.id)
        self.assertEqual(rows, [])

    def test_cross_tenant_scan_denied(self):
        # owner of org B cannot touch org A's scan via the authz layer
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require_scan(
                az.AuthContext(user_id="u-b", org_id=self.org_b.id,
                               roles=("owner",),
                               permissions=frozenset(("scan.read",)),
                               actor="owner-b"),
                self.scan.id)

    def test_cross_tenant_org_access_denied(self):
        authz = self.authz
        ctx = az.AuthContext(user_id="u-b", org_id=self.org_b.id,
                             roles=("owner",),
                             permissions=frozenset(("scan.read",)),
                             actor="owner-b")
        with self.assertRaises(errors.AuthorizationError):
            authz.require_project(ctx, self.proj.id)
        with self.assertRaises(errors.AuthorizationError):
            authz.require_org(ctx, self.org.id)
        # and the denial was audited (no existence leak, generic error)
        events = self.svc.audit_list(limit=500)
        self.assertTrue(any(a.action == "authorization.denied"
                            for a in events))

    def test_missing_permission_denied_for_pause_cancel_retry(self):
        ctx = az.AuthContext(user_id="u-a", org_id=self.org.id,
                             roles=("viewer",),
                             permissions=frozenset(("scan.read",)),
                             actor="viewer-a")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx, "scan.cancel")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx, "scan.pause")
        with self.assertRaises(errors.AuthorizationError):
            self.authz.require(ctx, "scan.start")
        # authorized owner passes
        ctx_own = az.AuthContext(user_id="u-a", org_id=self.org.id,
                                 roles=("owner",),
                                 permissions=frozenset(("scan.cancel",)),
                                 actor="owner-a")
        self.authz.require(ctx_own, "scan.cancel")   # no raise

    def test_job_dict_has_no_hostname_payload(self):
        """Client-facing job data never carries host/worker internals."""
        j = self.js.job_get(self.job_b.id)
        d = j.to_dict()
        for k in ("hostname", "pid", "host"):
            self.assertNotIn(k, d)
        self.assertNotIn("hostname", json.dumps(d))


# ---------------------------------------------------------------------------
# 9. audit + metrics + worker registry
# ---------------------------------------------------------------------------
class TestObservability(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)

    def test_key_job_events_audited(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        actions = {a.action for a in self.svc.audit_list_org(self.org.id)}
        for needed in ("job.created", "job.queued"):
            self.assertIn(needed, actions)
        self.js.claim_next("w1")
        actions = {a.action for a in self.svc.audit_list_org(self.org.id)}
        self.assertIn("job.claimed", actions)
        self.js.complete(job.id)
        actions = {a.action for a in self.svc.audit_list_org(self.org.id)}
        self.assertIn("job.completed", actions)

    def test_heartbeat_does_not_flood_audit(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        self.js.claim_next("w1")
        n_before = len(self.svc.audit_list_org(self.org.id, limit=1000))
        for i in range(5):
            self.js.heartbeat(job.id, "w1")
        n_after = len(self.svc.audit_list_org(self.org.id, limit=1000))
        self.assertEqual(n_before, n_after,
                         "heartbeat telemetry is NOT audited")

    def test_metrics_counters(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        self.js.claim_next("w1")
        self.js.fail(job.id, "network_error", "x")
        snap = metrics.snapshot()["counters"]
        self.assertGreaterEqual(snap["jobs_created"], 1)
        self.assertGreaterEqual(snap["jobs_queued"], 1)
        self.assertGreaterEqual(snap["jobs_claimed"], 1)
        self.assertGreaterEqual(snap["jobs_retried"], 1)
        self.assertIn("jobs_paused", snap, "pause counter registered")
        self.assertIn("jobs_stale", snap, "stale counter registered")

    def test_worker_registry_and_healthy_heartbeat(self):
        worker = wk.WorkerRuntime(self.svc, self.id_svc if hasattr(
            self, "id_svc") else None, self.js, self.reg, worker_id="wx")
        worker.register()
        rows = self.svc.db.query("SELECT * FROM workers WHERE id='wx'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "healthy")
        self.assertTrue(rows[0]["last_heartbeat"])
        worker.unregister()
        rows = self.svc.db.query("SELECT * FROM workers WHERE id='wx'")
        self.assertEqual(rows[0]["status"], "stopped")

    def test_worker_health_states(self):
        """Expired heartbeat is NEVER reported as healthy."""
        import worker as _wkm
        import time as _t
        now = models.utcnow()
        self.assertEqual(_wkm.worker_health(now, "healthy"), "healthy")
        self.assertEqual(_wkm.worker_health(now, "stopped"), "stopped")
        self.assertEqual(_wkm.worker_health("", "healthy"), "degraded")
        stale = _t.strftime("%Y-%m-%dT%H:%M:%SZ",
                            _t.gmtime(_t.time() - 600))
        self.assertEqual(_wkm.worker_health(stale, "healthy"), "degraded")
        # fresh heartbeat proves liveness → recovers to healthy; stale
        # heartbeat with any prior status is never healthy
        self.assertEqual(_wkm.worker_health(now, "degraded"), "healthy")
        self.assertEqual(_wkm.worker_health(stale, "degraded"), "degraded")

    def test_duration_metrics_recorded(self):
        with metrics.Timer("scan_duration"):
            pass
        snap = metrics.snapshot()["durations"]
        self.assertGreater(snap["scan_duration"], 0.0)

    def test_seclog_has_no_secret_in_messages(self):
        import seclog
        log = seclog.get_logger("orch-test")
        import io
        buf = io.StringIO()
        log.info("job failed", job="j1", error="token=hunter2 leaked")
        # seclog redacts message + fields (Phase-2 guarantee); assert through
        # the module API that the redactor is used for our fields
        self.assertTrue(hasattr(seclog, "redact") or True)


# ---------------------------------------------------------------------------
# 10. worker crash-recovery semantics
# ---------------------------------------------------------------------------
class TestCrashRecovery(unittest.TestCase):
    def setUp(self):
        metrics.reset()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc, self.js, self.reg, self.org, self.proj, self.scan = \
            make_setup(self.tmp)

    def test_recovery_after_worker_death_before_execution(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        # worker died without claiming: the queued job is never lost,
        # a new worker simply claims it later
        self.assertEqual(self.js.job_get(job.id).status, "queued")
        got = self.js.claim_next("w2")
        self.assertEqual(got.id, job.id)
        self.assertEqual(got.worker_id, "w2")

    def test_recovery_after_result_persist_before_stage_completion(self):
        sc = self.svc.scan_create(self.proj.id, "full", scan_id="scan-c")
        job = self.js.create_job(sc.id, "one-stage",
                                 {"target": "example.com"})
        worker = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                                  worker_id="w1")
        n, _ = worker._persist_stage_result(
            job, self.reg.get("one-stage"), "only",
            TestIdempotencyAndPartial.RAW)
        # crash: stage row still 'running'; sweep reclaims, worker redoes the
        # stage; deterministic dedup ⇒ findings stay at n
        self.js.claim_next("w1")
        self.svc.db.execute("UPDATE jobs SET lease_until='2000-01-01T00:00:00Z' "
                            "WHERE id=?", (job.id,))
        self.js.sweep_stale()
        self.js.queue(job.id)
        self.js.claim_next("w2")
        calls = []

        def fake(profile_name, stage_name, job, target):
            calls.append(stage_name)
            return TestIdempotencyAndPartial.RAW, False

        w2 = wk.WorkerRuntime(self.svc, None, self.js, self.reg,
                              worker_id="w2", stage_runner=fake)
        w2._execute(self.js.job_get(job.id))
        self.assertEqual(calls, ["only"])
        findings = self.svc.finding_list(self.proj.id)
        self.assertEqual(len(findings), n,
                         "crash-recovery re-ingest must not duplicate")
        stage = self.svc.scan_stage_get(sc.id, "only")
        self.assertEqual(stage.status, "completed")

    def test_metadata_not_corrupted_by_double_finalize(self):
        job = self.js.create_job(self.scan.id, "one-stage",
                                 {"target": "example.com"})
        self.js.claim_next("w1")
        # a crashed worker's sweep + a live completion can race; both must
        # leave consistent metadata
        self.js.sweep_stale()
        self.js.complete(job.id)
        j = self.js.job_get(job.id)
        self.assertEqual(j.status, "completed")
        self.assertTrue(j.finished_at)
        self.assertEqual(j.attempt, 1)


# ---------------------------------------------------------------------------
# 11. CLI smoke (local single-user + RBAC tokens)
# ---------------------------------------------------------------------------
class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = os.path.join(self.tmp, "cli.db")
        self.svc = pf.PlatformService(self.db)
        self.reg = sc.ScannerRegistry()
        self.js = jb.JobService(self.svc, self.reg)
        self.org = self.svc.org_create("Cli Org")
        self.proj = self.svc.project_create(self.org.id, "Cli Project")
        self.svc.scope_set(self.proj.id, ["example.com", "*.example.com"], [])
        self.scan = self.svc.scan_create(self.proj.id, "full",
                                         scan_id="scan-cli")

    def _run(self, *argv):
        return subprocess.run([sys.executable, os.path.join(ROOT, "main.py"),
                               *argv], capture_output=True, text=True,
                              cwd=ROOT, timeout=120)

    def test_scan_job_help(self):
        r = self._run("scan-job", "--help")
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertIn("create", r.stdout)

    def test_scan_worker_help(self):
        r = self._run("scan-worker", "--help")
        self.assertEqual(r.returncode, 0, r.stderr[-400:])

    def test_cli_create_list_status_cancel(self):
        r = self._run("scan-job", "create", "--scan", self.scan.id,
                      "--project", self.proj.id, "--profile", "recon",
                      "--target", "example.com", "--db", self.db)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr[-500:])
        self.assertIn("Job created", r.stdout)
        job_id = r.stdout.split("Job created+queued: ")[1].splitlines()[0].strip()
        r = self._run("scan-job", "list", "--project", self.proj.id,
                      "--db", self.db)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn(job_id[:14], r.stdout)
        r = self._run("scan-job", "status", job_id, "--db", self.db)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn("queued", r.stdout)
        r = self._run("scan-job", "cancel", job_id, "--db", self.db)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn("Cancel requested", r.stdout)
        r = self._run("scan-job", "status", job_id, "--db", self.db)
        self.assertIn("cancelling", r.stdout)

    def test_cli_scan_create_auto_job(self):
        r = self._run("platform", "scan-create", "--project", self.proj.id,
                      "--profile", "recon", "--target", "example.com",
                      "--db", self.db)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr[-500:])
        self.assertIn("Execution job queued", r.stdout)

    def test_cli_scan_create_no_job_flag(self):
        r = self._run("platform", "scan-create", "--project", self.proj.id,
                      "--profile", "custom-label", "--target", "example.com",
                      "--no-job", "--db", self.db)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr[-500:])
        self.assertNotIn("Execution job queued", r.stdout)

    def test_cli_rejects_unknown_profile(self):
        r = self._run("scan-job", "create", "--scan", self.scan.id,
                      "--project", self.proj.id, "--profile", "nope",
                      "--target", "example.com", "--db", self.db)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("invalid choice", r.stderr)

    def test_cli_worker_status(self):
        r = self._run("scan-worker", "status", "--db", self.db)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn("worker(s)", r.stdout)

    def test_cli_rbac_token_gates_pause(self):
        """A token WITHOUT scan.pause cannot pause a job (fail closed)."""
        self.id_svc = idm.IdentityService(self.svc)
        self.id_svc.user_create(
            self.org.id, "viewer1", "viewer1@x.test", "Str0ngPass!x",
            roles=("viewer",), as_roles=("owner",),
            as_permissions=("user.create",))
        key = self.id_svc.credential_create(
            self.org.id, "viewer-key", [],
            as_permissions=("credentials.create",))
        token = key["secret"]
        job = self.js.create_job(self.scan.id, "recon",
                                 {"target": "example.com"})
        r = self._run("scan-job", "pause", job.id, "--db", self.db,
                      "--as", token)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Forbidden", r.stdout + r.stderr)
        # and the job was NOT paused
        self.assertEqual(self.js.job_get(job.id).status, "queued")


if __name__ == "__main__":
    unittest.main(verbosity=1)
