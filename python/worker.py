#!/usr/bin/env python3
# ============================================================================
#  worker.py — Phase 3 worker runtime.
#  ---------------------------------------------------------------------------
#  Each runtime thread claims ONE job at a time (atomic claim in jobs.py),
#  revalidates authorization/scope AT EXECUTION TIME, executes the profile's
#  stages through the scanner adapters, persists partial results per stage,
#  and respects pause/cancel at safe checkpoints.
#
#  Honest semantics (documented in README):
#    - pause: current stage completes, next stage does not start, scan
#      becomes paused (a running network request is not interrupted)
#    - cancel: current subprocess is terminated through a CONTROL-
#      LED terminate → grace → escalate path (never blind SIGKILL first)
#    - a queued job may wait minutes/hours ⇒ every execution re-checks
#      org/project/scan validity, actor validity and scope
#
#  Heartbeat telemetry is NOT written to the immutable audit trail — it
#  lives in the jobs/workers rows + structured logs only.
# ============================================================================

from __future__ import annotations

import os
import socket
import threading
import time
import uuid

import errors
import metrics
import models
import normalize
import redact
import seclog

log = seclog.get_logger("worker")

FINDINGS_PER_STAGE_CAP = 500
POLL_INTERVAL = 0.5            # seconds between claim attempts
HEALTH_THRESHOLD_SECONDS = 45.0   # 3× default heartbeat interval


def worker_health(last_heartbeat: str, status: str, *,
                  threshold_seconds: float = HEALTH_THRESHOLD_SECONDS) -> str:
    """Worker health state: healthy / degraded / stopped.
    An expired heartbeat is NEVER 'healthy' — the worker may be alive but
    is not proving it; degraded is the honest state until it heartbeats."""
    if status == "stopped":
        return "stopped"
    if not last_heartbeat:
        return "degraded"
    try:
        import time as _t
        age = _t.mktime(_t.strptime(models.utcnow(),
                                    "%Y-%m-%dT%H:%M:%SZ")) - \
            _t.mktime(_t.strptime(last_heartbeat, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return "degraded"
    return "healthy" if 0 <= age <= float(threshold_seconds) else "degraded"


WorkerStopped = errors.WorkerStopped


class WorkerRuntime:
    """One execution thread. `stage_runner` may be replaced (tests) with a
    fake runner; the production default drives the real scanner adapters."""

    def __init__(self, svc, id_svc, jobs, registry, *,
                 worker_id: str = "", actor_check=None,
                 stage_runner=None, heartbeat_interval: float = 15.0):
        self.svc = svc                      # PlatformService
        self.id_svc = id_svc                # IdentityService (may be None)
        self.jobs = jobs                    # JobService
        self.registry = registry            # ScannerRegistry
        self.worker_id = worker_id or uuid.uuid4().hex[:12]
        self.actor_check = actor_check
        self.stage_runner = stage_runner or self._default_stage_runner
        self.heartbeat_interval = float(heartbeat_interval)
        self._stop = threading.Event()
        self._current_job_id = ""
        self._current_job_worker = ""

    # ---------------------------------------------------------- identity
    def register(self) -> None:
        self.svc.db.execute(
            "INSERT OR REPLACE INTO workers (id, hostname, pid, status, "
            "started_at, last_heartbeat, stopped_at) VALUES (?,?,?,?,?,?,?)",
            (self.worker_id, socket.gethostname()[:64], os.getpid(),
             "healthy", models.utcnow(), models.utcnow(), ""))
        self.svc.audit("worker.started", object_type="worker",
                       object_id=self.worker_id,
                       metadata={"hostname": socket.gethostname()[:64]})
        log.info("worker started", worker=self.worker_id,
                 hostname=socket.gethostname()[:64], pid=os.getpid())

    def unregister(self, status: str = "stopped") -> None:
        try:
            self.svc.db.execute(
                "UPDATE workers SET status=?, stopped_at=? WHERE id=?",
                (status, models.utcnow(), self.worker_id))
            self.svc.audit("worker.stopped", object_type="worker",
                           object_id=self.worker_id)
        except Exception:
            pass
        log.info("worker stopped", worker=self.worker_id)

    def heartbeat(self) -> None:
        now = models.utcnow()
        try:
            self.svc.db.execute(
                "UPDATE workers SET last_heartbeat=?, status='healthy' "
                "WHERE id=?", (now, self.worker_id))
            if self._current_job_id:
                self.jobs.heartbeat(self._current_job_id, self.worker_id,
                                    now=now)
        except Exception:
            pass

    # -------------------------------------------------------------- loop
    def run_forever(self, max_jobs: int = 0) -> None:
        """Claim and execute jobs until stopped or `max_jobs` exhausted."""
        done = 0
        self.register()
        hb = threading.Thread(target=self._heartbeat_loop, daemon=True)
        hb.start()
        try:
            while not self._stop.is_set():
                self.jobs.sweep_stale(actor=self.worker_id)
                job = self.jobs.claim_next(self.worker_id)
                if job is None:
                    if max_jobs and done >= max_jobs:
                        break
                    time.sleep(POLL_INTERVAL)
                    continue
                self._current_job_id = job.id
                try:
                    self._execute(job)
                except Exception as e:      # never let the loop die
                    log.error("job execution error", job=job.id,
                              error=str(e)[:300])
                    try:
                        self.jobs.fail(job.id, "worker_error",
                                       f"internal worker error: {e}",
                                       actor=self.worker_id)
                    except Exception:
                        pass
                finally:
                    self._current_job_id = ""
                done += 1
                if max_jobs and done >= max_jobs:
                    break
        finally:
            self._current_job_id = ""
            self.unregister()
            hb.join(timeout=3)

    def stop(self) -> None:
        self._stop.set()

    def _heartbeat_loop(self):
        while not self._stop.is_set():
            self.heartbeat()
            time.sleep(self.heartbeat_interval)

    # ----------------------------------------------------------- execute
    def _execute(self, job: models.Job) -> None:
        profile = self.registry.get(job.profile)
        # ---- execution-time authorization revalidation (spec §18) ----
        if job.actor_id and self.actor_check:
            ok, reason = self.actor_check(job.actor_id)
            if not ok:
                self.svc.audit("authorization.denied", actor=job.actor_id,
                               org_id=job.org_id,
                               metadata={"perm": "scan.execute",
                                         "kind": "actor"})
                self.jobs.fail(job.id, "auth_failed",
                               f"actor no longer authorized ({reason})",
                               actor=self.worker_id)
                return
        try:
            ctx = self.jobs.validate_execution(job)
        except errors.ValidationError as e:
            code = str(e.message).split(":", 1)[0]
            self.svc.audit("authorization.denied"
                           if code == "scope_denied" else "scan.failed",
                           actor=self.worker_id, org_id=job.org_id,
                           project_id=job.project_id,
                           metadata={"perm": "scan.execute",
                                     "kind": code[:32]})
            self.jobs.fail(job.id, code, e.message, actor=self.worker_id)
            return
        target = ctx["target"]
        self.svc.audit("job.started", object_type="job", object_id=job.id,
                       org_id=job.org_id, project_id=job.project_id,
                       actor=self.worker_id,
                       metadata={"profile": job.profile})
        # scan: pending/queued/paused → running (legal transitions)
        scan = self.svc.scan_get(job.scan_id)
        if scan.status in ("pending", "queued", "paused"):
            self.svc.scan_transition(job.scan_id, "running")
        stages = list(profile.stages)
        completed = {s.stage for s in self.svc.scan_stage_list(job.scan_id)
                     if s.status == "completed"}
        for stage_name in stages:
            control = self.jobs.control_state(job.id)
            if control == "cancelling":
                self._cancel_stage(job, stage_name,
                                   "cancelled before stage start")
                return
            if control == "paused":
                self._pause_scan(job)
                return
            if stage_name in completed:
                metrics.inc("stages_skipped")
                continue
            # ---- scope REVALIDATION before every network stage (§19) ----
            # (Phase 9 in-process profiles address registered tenant
            # entities — org scoping applies; network scope does not)
            if not getattr(self.registry.get(profile.name),
                              "in_process", False):
                check = self.svc.scope_check(job.project_id, target)
                if not check["in_scope"]:
                    self._stage_fail(job, stage_name, "scope_denied",
                                     "target left scope before execution")
                    return
            proceed = self._run_stage(job, profile, stage_name, target,
                                      stages)
            if proceed == "paused":
                self._pause_scan(job)
                return
            if proceed == "cancelled":
                return     # cancellation already finalized by _cancel_stage
            if proceed == "failed":
                return     # already recorded by _run_stage
        # ---- all stages done: finalize scan + job (idempotent) ----
        stage_recs = self.svc.scan_stage_list(job.scan_id)
        done_names = [s.stage for s in stage_recs if s.status == "completed"]
        self.svc.scan_update_summary(
            job.scan_id,
            {"profile": profile.name, "stages": len(stages),
             "completed_stages": len(
                 [s for s in stages if s in set(done_names)])},
            progress=1.0)
        try:
            if self.svc.scan_get(job.scan_id).status in \
                    ("running", "paused", "queued", "pending"):
                self.svc.scan_transition(job.scan_id, "completed")
        except errors.LifecycleError:
            pass
        self.jobs.complete(job.id, result_reference=f"scan:{job.scan_id}",
                           actor=self.worker_id)
        metrics.inc("scans_completed")
        log.info("job completed", job=job.id, scan=job.scan_id,
                 profile=profile.name)

    # ---------------------------------------------------------- stages
    def _run_stage(self, job, profile, stage_name, target,
                   stage_names) -> str:
        """Execute ONE stage. Returns 'ok' | 'paused' | 'cancelled' |
        'failed'."""
        stage = self.svc.scan_stage_get(job.scan_id, stage_name) or \
            models.StageRecord(scan_id=job.scan_id, stage=stage_name)
        stage.job_id = job.id
        stage.status = "running"
        stage.attempt = int(stage.attempt or 0) + 1
        stage.started_at = stage.started_at or models.utcnow()
        stage.error_code = ""
        stage.error_message = ""
        self.svc.scan_stage_record(stage)
        log.info("stage started", job=job.id, stage=stage_name,
                 attempt=stage.attempt)
        try:
            with metrics.Timer("stage_duration"):
                raw, truncated = self.stage_runner(
                    profile.name, stage_name, job, target)
        except errors.ScannerError as e:
            code = str(e.message).split(":", 1)[0]
            self._stage_fail(job, stage_name, code, e.message)
            return "failed"
        except WorkerStopped as e:
            self._cancel_stage(job, stage_name,
                               str(e) or "cancelled at checkpoint")
            return "cancelled"
        # persist normalized results (deterministic dedupe ⇒ idempotent)
        findings_n, findings_capped = self._persist_stage_result(
            job, profile, stage_name, raw)
        ref = f"findings:{findings_n}" + \
            ("|capped" if findings_capped else "")
        # Phase 9 in-process stages persist through the Phase-9 pipeline
        # (assets/findings/evidence) — surface those counters on the stage
        # as well so the operation is never recorded as a silent zero.
        if isinstance(raw, dict) and isinstance(raw.get("_phase9"), dict):
            for k, v in sorted(raw["_phase9"].items()):
                if isinstance(v, (int, float)):
                    ref += f"|phase9.{k}:{v}"
        # Phase 12 federation-bulk stages persist through the federation
        # pipeline (packages/imports/classifications) — surface those
        # counters the same way so a bulk run is never a silent zero.
        if isinstance(raw, dict) and isinstance(raw.get("_phase12"), dict):
            for k, v in sorted(raw["_phase12"].items()):
                if isinstance(v, (int, float, bool)):
                    ref += f"|phase12.{k}:{v}"
        # Phase 13 integration-delivery stages surface their receipt
        # counters the same way — a delivery is never a silent zero.
        if isinstance(raw, dict) and isinstance(raw.get("_phase13"), dict):
            for k, v in sorted(raw["_phase13"].items()):
                if isinstance(v, (int, float, bool)):
                    ref += f"|phase13.{k}:{v}"
        stage = models.StageRecord(
            scan_id=job.scan_id, stage=stage_name, status="completed",
            job_id=job.id, attempt=stage.attempt,
            created_at=stage.created_at, started_at=stage.started_at,
            finished_at=models.utcnow(),
            result_reference=ref)
        self.svc.scan_stage_record(stage)
        done = self.svc.scan_progress(job.scan_id, list(stage_names))
        self.svc.scan_set_progress(job.scan_id, done)
        if done >= 1.0:
            # Phase 4: one idempotent correlation/root-cause/cluster pass at
            # scan completion (bounded; never blocks stage completion)
            try:
                self._correlator().build_project_intel(job.project_id)
            except Exception as e:
                log.warn("project intel build failed", job=job.id,
                            error=str(e)[:200])
            # Phase 4: temporal snapshot — new baseline + diff vs the
            # previous one (stable identities, idempotent)
            try:
                self._baselines().capture(job.project_id, job.scan_id,
                                          actor="scanner")
            except Exception as e:
                log.warn("scan baseline/diff failed", job=job.id,
                            error=str(e)[:200])
            # Phase 5: scheduled-run bookkeeping + verification resolution
            # (monitoring metadata + evidence-based verification; failures
            # are logged and counted, never break scan completion)
            try:
                mon = self._monitoring()
                mon.on_scan_terminal(job.project_id, job.scan_id, "completed")
            except Exception as e:
                log.warn("monitoring update failed", job=job.id,
                            error=str(e)[:200])
            try:
                self._remedy().on_scan_completed(job.project_id,
                                                 job.scan_id)
            except Exception as e:
                log.warn("verification resolution failed", job=job.id,
                            error=str(e)[:200])
        self.svc.audit("stage.completed", object_type="scan",
                       object_id=job.scan_id, org_id=job.org_id,
                       project_id=job.project_id,
                       metadata={"stage": stage_name,
                                 "findings": findings_n,
                                 "findings_capped": bool(findings_capped),
                                 "truncated": bool(truncated)})
        metrics.inc("stages_completed")
        phase9 = (dict(raw.get("_phase9")) if isinstance(raw, dict)
                  and isinstance(raw.get("_phase9"), dict) else {})
        phase12 = (dict(raw.get("_phase12")) if isinstance(raw, dict)
                   and isinstance(raw.get("_phase12"), dict) else {})
        log.info("stage completed", job=job.id, stage=stage_name,
                 findings=findings_n, capped=findings_capped,
                 phase9=phase9, phase12=phase12)
        return "ok"

    def _stage_fail(self, job, stage_name, code, message) -> None:
        stage = self.svc.scan_stage_get(job.scan_id, stage_name) or \
            models.StageRecord(scan_id=job.scan_id, stage=stage_name)
        stage.status = "failed"
        stage.job_id = job.id
        stage.finished_at = models.utcnow()
        stage.error_code = str(code)[:64]
        stage.error_message = str(redact.redact_text(message))[:500]
        self.svc.scan_stage_record(stage)
        self.svc.audit("stage.failed", object_type="scan",
                       object_id=job.scan_id, org_id=job.org_id,
                       project_id=job.project_id,
                       metadata={"stage": stage_name, "error": code})
        metrics.inc("stages_failed")
        # partial results stay; the scan itself becomes failed/retried
        try:
            scan = self.svc.scan_get(job.scan_id)
            if scan.status in ("running", "queued", "pending", "paused"):
                self.svc.scan_transition(job.scan_id, "failed")
            self.svc.scan_set_error(job.scan_id, code, message)
        except Exception:
            pass
        self.jobs.fail(job.id, code, message, actor=self.worker_id)
        # Phase 5: scheduled-run failure bookkeeping + monitoring failure
        # events (idempotent; never affects queue semantics)
        try:
            self._monitoring().on_scan_terminal(job.project_id, job.scan_id,
                                                "failed", error=code)
        except Exception as e:
            log.warn("monitoring failure update failed", job=job.id,
                        error=str(e)[:200])
        # Phase 5: a failed verification scan returns the ticket to
        # ready_for_verification (attempts were already counted)
        try:
            self._remedy().on_scan_failed(job.project_id, job.scan_id,
                                          error=code)
        except Exception as e:
            log.warn("verification failure update failed", job=job.id,
                        error=str(e)[:200])
        log.warn("stage failed", job=job.id, stage=stage_name, error=code)

    def _cancel_stage(self, job, stage_name, message: str) -> None:
        stage = self.svc.scan_stage_get(job.scan_id, stage_name) or \
            models.StageRecord(scan_id=job.scan_id, stage=stage_name)
        stage.status = "cancelled"
        stage.job_id = job.id
        stage.finished_at = models.utcnow()
        stage.error_code = "cancelled"
        stage.error_message = str(message)[:500]
        self.svc.scan_stage_record(stage)
        self.jobs.cancel_finalize(job.id, actor=self.worker_id)
        try:
            scan = self.svc.scan_get(job.scan_id)
            if scan.status in ("running", "queued", "pending", "paused",
                               "cancelling"):
                self.svc.scan_transition(job.scan_id, "cancelled")
        except Exception:
            pass
        log.info("job cancelled at checkpoint", job=job.id,
                 stage=stage_name)

    def _pause_scan(self, job) -> None:
        try:
            scan = self.svc.scan_get(job.scan_id)
            if scan.status == "running":
                self.svc.scan_transition(job.scan_id, "paused")
        except Exception:
            pass
        log.info("job paused at checkpoint", job=job.id)

    # --------------------------------------------------- result persistence
    def _persist_stage_result(self, job, profile, stage_name, raw) -> tuple:
        """Normalize + ingest stage output. Deterministic finding ids from
        fingerprints mean a retried stage NEVER duplicates findings.
        Returns (findings_count, findings_capped) — capping is always
        surfaced to the operator, never silent."""
        if not isinstance(raw, dict):
            return 0, False
        capped = dict(raw)
        findings = capped.get("findings")
        trunc = isinstance(findings, list) and \
            len(findings) > FINDINGS_PER_STAGE_CAP
        if trunc:
            capped["findings"] = findings[:FINDINGS_PER_STAGE_CAP]
        normalized = normalize.normalize_result(capped,
                                                project_id=job.project_id)
        # persist discovered assets (deterministic ids ⇒ INSERT OR IGNORE,
        # repeated ingest can never duplicate an asset row)
        index = {}
        saved_assets = []
        for a in normalized["assets"]:
            try:
                saved = self.svc.asset_add(job.project_id, a.asset_type,
                                           a.value)
            except Exception:
                saved = None
            if saved is not None:
                saved_assets.append(saved)
            index[a.value] = (saved.id if saved else a.id)
        # Phase 4: asset intelligence from the same raw payload (idempotent;
        # never blocks finding persistence — failures are logged + counted)
        try:
            intel_svc = self._intel()
            intel_svc.ingest_observations(job.project_id, job.scan_id,
                                          capped, saved_assets)
        except Exception as e:
            log.warn("asset intel ingest failed", job=job.id,
                        stage=stage_name, error=str(e)[:200])
        count = 0
        correlator = None
        for f in normalized["findings"]:
            f.scan_id = job.scan_id
            f.project_id = job.project_id
            if not f.asset_id:
                f.asset_id = index.get(
                    str(f.raw.get("target") or f.raw.get("url") or ""), "")
            evs = []
            for e in f.evidence:
                ev = e if isinstance(e, models.Evidence) else \
                    models.Evidence.from_dict(dict(e))
                ev.finding_id = f.id
                ev.finalize()
                evs.append(ev)
            try:
                if correlator is None:
                    correlator = self._correlator()
                correlator.ingest_finding(f, evs,
                                          scan_id=job.scan_id,
                                          raw=f.raw, job_id=job.id)
            except Exception as e:
                log.warn("finding intelligence ingest failed",
                            job=job.id, stage=stage_name,
                            error=str(e)[:200])
                self.svc.finding_ingest(f, evidence=evs)
            count += 1
        return count, trunc

    def _intel(self):
        if getattr(self, "_intel_svc", None) is None:
            from intel import IntelService
            self._intel_svc = IntelService(self.svc)
        return self._intel_svc

    def _correlator(self):
        if getattr(self, "_correlator_svc", None) is None:
            from correlate import CorrelationService
            self._correlator_svc = CorrelationService(self.svc)
        return self._correlator_svc

    def _baselines(self):
        if getattr(self, "_baseline_svc", None) is None:
            from diffs import BaselineService
            self._baseline_svc = BaselineService(self.svc)
        return self._baseline_svc

    def _monitoring(self):
        if getattr(self, "_monitor_svc", None) is None:
            from monitor import SchedulerService
            self._monitor_svc = SchedulerService(self.svc, registry=self.registry)
        return self._monitor_svc

    def _remedy(self):
        if getattr(self, "_remedy_svc", None) is None:
            from remedy import RemediationService
            self._remedy_svc = RemediationService(self.svc, registry=self.registry)
        return self._remedy_svc

    # ------------------------------------------------------ default runner
    def _default_stage_runner(self, profile_name, stage_name, job, target):
        if getattr(self.registry.get(profile_name), "in_process",
                    False):
            return self._in_process_stage_runner(profile_name, stage_name,
                                                 job, target)
        import tempfile
        workdir = tempfile.mkdtemp(prefix="stg_")
        timeout = float(self.registry.get(profile_name).timeout
                        if not job.timeout_seconds else job.timeout_seconds)
        argv = self.registry.build_argv(profile_name, target, job.payload,
                                        workdir, timeout)
        rc, out, err, truncated = self.registry.capture_output(
            argv, timeout=min(timeout, 120.0),
            poll=lambda: self.jobs.control_state(job.id))
        if rc != 0:
            raise errors.ScannerError(
                f"subprocess_failed: scanner exited {rc}: "
                f"{err.strip()[:200] or 'no stderr'}")
        raw = self.registry.read_json_result(workdir)
        if raw is None:
            # scanners that print human-readable output (e.g. Rust tools)
            # keep their bounded stdout attached for the operator
            if out.strip():
                raw = {"tool": profile_name, "note":
                       "no structured JSON; adapter captured stdout",
                       "stdout_excerpt": out[:2000]}
            else:
                raw = {"tool": profile_name, "note": "empty result"}
        return raw, truncated

    # ------------------------------------------------------- Phase 9
    # In-process (no subprocess/shell) Phase-9 dispatch. Every runner
    # persists through the EXISTING asset/finding/evidence pipeline via
    # cloud_security.persist_result, using the JOB's scan identity
    # (scan_id=job.scan_id) so the umbrella scan carries its results.
    # Missing material is an EXPLICIT failure — never a silent 0/PASS.
    def _in_process_stage_runner(self, profile_name, stage_name, job,
                                 target):
        import cloud_security as cs
        import container_security as csec
        import kubernetes_security as ksec
        import iac_security as isec
        payload = dict(job.payload or {})

        def _require(key, reason):
            v = str(payload.get(key) or "").strip()
            if not v:
                raise errors.ScannerError(
                    f"phase9_payload_required: {key} is required for "
                    f"{profile_name} ({reason})")
            return v

        actor = f"job:{job.id}"
        if profile_name == "federation-bulk":
            # Phase 12 bulk federation operations run in-process through
            # the SAME engine (no subprocess, no second scheduler); their
            # counters are separate from the Phase-9 assessment metrics.
            out = self._federation_bulk_stage(job, actor)
            return ({"tool": "phase12-federation-bulk",
                     "stage": stage_name,
                     "target": target or "",
                     "assets": [], "findings": [],
                     "note": "in-process Phase-12 bulk federation "
                             "operation; persisted through the existing "
                             "federation pipeline under the job scan",
                     "_phase12": out},
                    False)
        if profile_name == "integration-delivery":
            # Phase 13 outbound integration deliveries run in-process
            # through the SAME engine (no subprocess, no second scheduler,
            # no second retry engine); receipts/circuit state live on the
            # integration tables, the engine keeps leases/backoff/cancel/
            # dead-letter semantics.
            out = self._integration_delivery_stage(job, actor)
            return ({"tool": "phase13-integration-delivery",
                     "stage": stage_name,
                     "target": target or "",
                     "assets": [], "findings": [],
                     "note": "in-process Phase-13 integration delivery; "
                             "receipt persisted on the delivery row and "
                             "the canonical integration_events record",
                     "_phase13": out},
                    False)
        try:
            out = self._dispatch_in_process(profile_name, stage_name, job,
                                            target, payload, actor,
                                            _require)
        except Exception:
            metrics.inc("phase9_scan_failures")
            raise
        metrics.inc("phase9_scans")
        return ({"tool": f"phase9-{profile_name}",
                 "stage": stage_name,
                 "target": target or "",
                 "assets": [], "findings": [],
                 "note": "in-process Phase-9 assessment; persisted through "
                         "the existing pipeline under the job scan",
                 "_phase9": {k: out.get(k) for k in
                             ("assets", "findings", "capped", "documents",
                              "files", "resources", "packages",
                              "secrets_detected", "secrets_observed",
                              "open_findings", "risk_score",
                              "risk_level")}},
                False)

    def _dispatch_in_process(self, profile_name, stage_name, job, target,
                             payload, actor, _require):
        import cloud_security as cs
        import container_security as csec
        import kubernetes_security as ksec
        import iac_security as isec
        if profile_name == "cloud-inventory":
            acct = _require("account_id", "registered cloud account")
            svc = cs.CloudSecurityService(self.svc)
            inv = svc.inventory(job.org_id, acct)
            out = {"resources": len(inv)}
        elif profile_name == "cloud-scan":
            acct = _require("account_id", "registered cloud account")
            svc = cs.CloudSecurityService(self.svc)
            out = svc.scan(job.org_id, job.project_id, acct,
                           scan_id=job.scan_id, actor=actor)
        elif profile_name == "container-scan":
            image_id = _require("image_id", "registered container image")
            mat = self._scan_material(job)
            svc = csec.ContainerSecurityService(self.svc)
            out = svc.scan(job.org_id, job.project_id, image_id,
                           packages=mat.get("packages"),
                           vulnerabilities=mat.get("vulnerabilities"),
                           image_metadata=mat.get("image_metadata"),
                           scan_id=job.scan_id, actor=actor)
        elif profile_name == "kubernetes-scan":
            cluster_id = _require("cluster_id", "registered cluster")
            mat = self._scan_material(job)
            manifests = mat.get("manifests")
            if not manifests:
                raise errors.ScannerError(
                    "phase9_payload_required: kubernetes-scan needs "
                    "manifests staged in the scan record "
                    "(scan_save_raw {'manifests': [...]})")
            svc = ksec.KubernetesSecurityService(self.svc)
            out = svc.scan(job.org_id, job.project_id, cluster_id,
                           manifests=manifests,
                           namespace=str(payload.get("namespace") or ""),
                           scan_id=job.scan_id, actor=actor)
        elif profile_name == "iac-scan":
            mat = self._scan_material(job)
            files = mat.get("files")
            if not files:
                raise errors.ScannerError(
                    "phase9_payload_required: iac-scan needs files staged "
                    "in the scan record (scan_save_raw {'files': [...]})")
            svc = isec.IacSecurityService(self.svc)
            out = svc.scan(
                job.org_id, job.project_id, files=files,
                source_name=str(payload.get("source_name")
                                or "repository")[:128],
                fmt=str(payload.get("fmt") or "auto")[:32],
                scan_id=job.scan_id, actor=actor)
        elif profile_name == "posture-snapshot":
            out = self._posture_snapshot(job)
        else:
            raise errors.ScannerError(
                f"phase9_in_process_unregistered: {profile_name!r}")
        return out

    # ------------------------------------------------------- phase 12
    def _federation_bulk_stage(self, job, actor: str) -> dict:
        """Execute one chunked bulk federation operation (export / import /
        classify / retention-preview) inside the EXISTING job engine.

        BulkRunner polls the job's control state (cancel/pause) and
        heartbeats through JobService, so every Phase-3 semantic applies
        unchanged: checkpoints, bounded retries, cancellation, stale-lease
        recovery, audit, idempotency. Bulk material (a foreign package
        envelope / operation params) is staged on the job's scan record —
        job payloads remain scalar-only (§22).

        Error mapping is deliberate:
          WorkerStopped        -> clean cancellation (_cancel_stage)
          DuplicateError       -> retryable (concurrency claim race; the
                                  next attempt reports the winner's
                                  outcome via the idempotency shortcut)
          Validation/NotFound  -> NON-retryable `validation_rejected`
                                  (deterministic refusal: re-running the
                                  identical input cannot change it)
          AuthorizationError   -> NON-retryable `auth_failed`
          other toolkit errors -> retryable `bulk_failed`
        """
        import federation as fed
        payload = dict(job.payload or {})
        op = str(payload.get("op") or "").strip().lower()
        if op not in models.BULK_OPERATIONS:
            raise errors.ScannerError(
                "validation_rejected: federation-bulk payload op must be "
                f"one of {', '.join(models.BULK_OPERATIONS)} (got {op!r})")
        runner = fed.BulkRunner(self.svc)
        try:
            out = runner.run_for_job(job)
        except errors.WorkerStopped:
            raise
        except errors.DuplicateError as e:
            raise errors.ScannerError(f"bulk_duplicate: {e}") from e
        except (errors.ValidationError, errors.NotFoundError) as e:
            raise errors.ScannerError(f"validation_rejected: {e}") from e
        except errors.AuthorizationError as e:
            raise errors.ScannerError(f"auth_failed: {e}") from e
        except errors.SecurityToolkitError as e:
            raise errors.ScannerError(f"bulk_failed: {e}") from e
        counters = {k: v for k, v in out.items()
                    if isinstance(v, (int, bool, str))}
        counters.setdefault("op", op)
        return counters

    def _integration_delivery_stage(self, job, actor: str) -> dict:
        """Execute ONE bounded outbound integration delivery attempt
        (Phase 13) inside the EXISTING job engine.

        The DeliveryRunner owns the delivery lifecycle (envelope from the
        staged scan record, real provider interaction through the EXISTING
        notify SSRF guard, receipt row, circuit breaker, canonical
        integration_events record); this stage owns the engine-facing
        contract. One job = ONE delivery attempt: every provider-side
        outcome RETURNS a receipt (stage completes; the delivery row owns
        the retry loop with engine-formula backoff, drained by
        process_due under an atomic claim). Raises are contract
        violations and cancellation only:
          WorkerStopped        -> clean cancellation (_cancel_stage)
          validation_rejected  -> NON-retryable (job without a delivery
                                  target — deterministic refusal)
          delivery_failed      -> unexpected platform error; the runner
                                  already returned the delivery row to
                                  its retry state machine before raising
        """
        import integrations as ig
        runner = ig.DeliveryRunner(ig.OutboundService(self.svc))
        try:
            out = runner.run_for_job(job)
        except errors.WorkerStopped:
            raise
        except errors.ScannerError:
            raise
        except (errors.ValidationError, errors.NotFoundError) as e:
            raise errors.ScannerError(f"validation_rejected: {e}") from e
        except errors.AuthorizationError as e:
            raise errors.ScannerError(f"auth_failed: {e}") from e
        except errors.SecurityToolkitError as e:
            raise errors.ScannerError(f"delivery_failed: {e}") from e
        return {k: v for k, v in out.items()
                if isinstance(v, (int, bool, str))}

    def _scan_material(self, job) -> dict:
        """Bounded input material staged in the scan record before enqueue
        (job payloads are scalar-only by design)."""
        try:
            scan = self.svc.scan_get(job.scan_id)
            raw = dict(scan.raw or {})
        except Exception:
            raise errors.ScannerError(
                "phase9_material_unavailable: scan record not readable")
        for key in ("packages", "vulnerabilities", "image_metadata",
                    "manifests", "files"):
            v = raw.get(key)
            if v is not None and not isinstance(v, (list, dict)):
                raise errors.ScannerError(
                    f"phase9_material_invalid: {key} must be a list/dict")
        return raw

    def _posture_snapshot(self, job) -> dict:
        """Read-only posture summary from EXISTING findings (no new stores,
        no second system)."""
        from risk import RiskEngine
        rows = self.svc.db.query(
            "SELECT severity, lifecycle, COUNT(*) AS n FROM findings "
            "WHERE project_id=? GROUP BY severity, lifecycle",
            (job.project_id,))
        sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        open_count = 0
        for r in rows:
            if r["lifecycle"] not in ("resolved", "false_positive",
                                      "accepted_risk", "remediated"):
                open_count += int(r["n"])
                sev[r["severity"]] = sev.get(r["severity"], 0) + int(r["n"])
        score = min(100.0,
                    sev["Critical"] * 20 + sev["High"] * 10 +
                    sev["Medium"] * 4 + sev["Low"] * 1)
        totals = {r["severity"]: int(r["n"]) for r in rows}
        return {"open_findings": open_count, "by_severity": sev,
                "totals": totals,
                "risk_level": RiskEngine.level_for(score),
                "risk_score": score,
                "project_id": job.project_id}

    # ------------------------------------------------------------ snapshot
    def export_snapshot(self, path: str) -> dict:
        """Bounded, redacted job snapshot (dashboard readability)."""
        rows = self.svc.db.query(
            "SELECT id, org_id, project_id, scan_id, profile, status, "
            "attempt, max_attempts, priority, worker_id, error_code, "
            "error_message, created_at, started_at, finished_at, "
            "heartbeat_at FROM jobs ORDER BY created_at DESC LIMIT 100")
        jobs = [{"id": r["id"], "profile": r["profile"], "status": r["status"],
                 "attempt": r["attempt"], "max_attempts": r["max_attempts"],
                 "priority": r["priority"], "worker": r["worker_id"],
                 "project_id": r["project_id"],
                 "error_code": r["error_code"],
                 "created_at": r["created_at"],
                 "started_at": r["started_at"],
                 "finished_at": r["finished_at"]} for r in rows]
        counts = {r["status"]: r["n"] for r in self.svc.db.query(
            "SELECT status, COUNT(*) AS n FROM jobs GROUP BY status")}
        snap = {"generated_at": models.utcnow(),
                "metrics": metrics.snapshot(),
                "job_counts": counts, "recent_jobs": jobs}
        with open(path, "w", encoding="utf-8") as fh:
            import json as _json
            _json.dump(redact.redact(snap), fh, ensure_ascii=False,
                       indent=1)
        return snap
