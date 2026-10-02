#!/usr/bin/env python3
# ============================================================================
#  jobs.py — Phase 3 persistent job queue & lifecycle service.
#  ---------------------------------------------------------------------------
#  Zero-external-dependency orchestration on the existing SQLite platform:
#    - jobs survive worker restarts (queued work is in the database)
#    - ATOMIC claiming via guarded UPDATE (row-count check) — two workers
#      can never claim the same job (race-safe, single-writer SQLite)
#    - lease model: lease_until + heartbeat_at; expiring leases become
#      reclaimable; stale jobs are retried or dead-lettered deterministically
#    - deterministic state machine (models.JOB_TRANSITIONS) — transitions
#      are centralized HERE, never scattered in worker code
#    - bounded exponential backoff + jitter; bounded max_attempts
#    - strict payload validation (allowlist keys, no control chars, size cap)
#      — payloads are JSON only, redacted before storage, never pickled
#    - non-retryable vs retryable error taxonomy (authorization failures,
#      out-of-scope targets and malformed jobs are NEVER retried)
#
#  Authorization stays in authz.py — this module enforces EXECUTION-TIME
#  revalidation (scope/org/project/target) at the boundary of the worker.
# ============================================================================

from __future__ import annotations

import random
import re
import time

import errors
import metrics
import models
import redact
import store

# ---------------------------------------------------------------------------
# Error taxonomy: a job failing with one of these codes is NEVER retried.
# ---------------------------------------------------------------------------
NON_RETRYABLE = frozenset({
    "scope_denied", "auth_failed", "config_invalid", "validation_rejected",
    "payload_rejected", "profile_unknown", "not_authorized_active",
    "project_inactive", "org_disabled", "scan_invalid",
})

# bounded backoff configuration (seconds)
BACKOFF_BASE = 2.0
BACKOFF_MAX = 300.0
BACKOFF_JITTER = 5.0
LEASE_SECONDS = 60.0

_PAYLOAD_KEYS = frozenset({
    "target", "bucket", "service", "param", "depth", "limit", "max",
    "threads", "timeout", "note", "asset",
    # Phase 9 in-process profiles: registered-entity references (scalars
    # only — bulk material (manifests/files/inventories) is staged via
    # the scan record, never the job payload)
    "account_id", "image_id", "cluster_id", "source_name", "fmt",
    "namespace",
    # Phase 12 federation bulk operations (same rule: scalars only; the
    # object selection is derived server-side from the policy scope, never
    # carried as an unbounded payload list)
    "op", "peer_id", "policy_id", "package_id", "strategy", "object_types",
})
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
# printable ASCII only; rejects shell metacharacters that have no place in
# a target/parameter value (; | $ ` \ " ' newlines). '&' and '=' stay legal
# so real query strings pass — execution is argv-based, never shell-based.
_SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f;|$`\\\"']{1,512}$")
MAX_PAYLOAD_BYTES = 4096


def _now() -> str:
    return models.utcnow()


def _epoch(ts: str) -> float:
    if not ts:
        return 0.0
    try:
        return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return 0.0


def _iso(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


def retry_delay(attempt: int, *, base: float = BACKOFF_BASE,
                max_delay: float = BACKOFF_MAX,
                jitter: float = BACKOFF_JITTER) -> float:
    """Bounded exponential backoff with jitter:
    delay = min(max_delay, base * 2**attempt) + rand(0, jitter)."""
    raw = min(max_delay, base * (2 ** max(0, int(attempt))))
    return raw + random.uniform(0.0, jitter)


def validate_payload(payload) -> None:
    """Strict JSON payload schema — the ONLY entry point for job payloads.
    Rejects unknown keys, oversized fields, control characters and shell
    metacharacters (argv is never shell-interpreted, this is depth-in-
    depth). Never unpickles anything."""
    if not isinstance(payload, dict):
        raise errors.ValidationError(
            "payload_rejected: job payload must be a JSON object")
    try:
        import json as _json
        size = len(_json.dumps(payload, ensure_ascii=False))
    except Exception as e:
        raise errors.ValidationError(
            f"payload_rejected: unencodable payload ({e})") from e
    if size > MAX_PAYLOAD_BYTES:
        raise errors.ValidationError(
            "payload_rejected: payload exceeds 4096 bytes")
    for k, v in payload.items():
        if k not in _PAYLOAD_KEYS:
            raise errors.ValidationError(
                f"payload_rejected: unknown field {k!r}")
        if isinstance(v, (dict, list)):
            raise errors.ValidationError(
                f"payload_rejected: field {k!r} must be a scalar")
        if isinstance(v, str):
            if not _SAFE_TEXT_RE.match(v):
                raise errors.ValidationError(
                    f"payload_rejected: field {k!r} contains unsafe "
                    "characters")
            if _CTRL_RE.search(v):
                raise errors.ValidationError(
                    f"payload_rejected: field {k!r} contains control chars")
        elif isinstance(v, bool):
            pass
        elif isinstance(v, (int, float)):
            if not (-2 ** 31 < v < 2 ** 31):
                raise errors.ValidationError(
                    f"payload_rejected: field {k!r} out of range")
        else:
            raise errors.ValidationError(
                f"payload_rejected: field {k!r} has invalid type {type(v).__name__}")


class JobService:
    """Queue operations on the shared platform DB. `platform` provides the
    store + audit; `registry` provides the static scanner-profile allowlist."""

    def __init__(self, platform, registry, *,
                 lease_seconds: float = LEASE_SECONDS,
                 backoff_base: float = BACKOFF_BASE,
                 backoff_max: float = BACKOFF_MAX,
                 backoff_jitter: float = BACKOFF_JITTER,
                 max_candidates: int = 200,
                 org_concurrency: int = 3,
                 project_concurrency: int = 2,
                 scan_concurrency: int = 1):
        self.platform = platform
        self.svc = platform
        self.db = platform.db
        self.registry = registry
        self.lease_seconds = float(lease_seconds)
        self.backoff_base = float(backoff_base)
        self.backoff_max = float(backoff_max)
        self.backoff_jitter = float(backoff_jitter)
        self.max_candidates = int(max_candidates)
        self.org_concurrency = int(org_concurrency)
        self.project_concurrency = int(project_concurrency)
        self.scan_concurrency = int(scan_concurrency)
        self._rr_org: str | None = None      # round-robin fairness pointer

    # ----------------------------------------------------------- audit
    def _audit(self, action: str, job, **kw):
        try:
            self.svc.audit(action, object_type="job", object_id=job.id,
                           org_id=job.org_id, project_id=job.project_id,
                           metadata={"profile": job.profile, **kw})
        except Exception:
            pass  # auditing never breaks queue operations

    # ----------------------------------------------------------- create
    def create_job(self, scan_id: str, profile: str, payload=None, *,
                   job_type: str = "scan", priority="normal",
                   active_enabled: bool = False, max_attempts: int = 3,
                   timeout_seconds: int = 300, actor_id: str = "",
                   actor: str = "cli", queue_now: bool = True) -> models.Job:
        profile = self.registry.validate_profile(profile)
        validate_payload(payload or {})
        scan = self.svc.scan_get(scan_id)
        project = self.svc.project_require(scan.project_id)
        prio = models.JOB_PRIORITIES.get(str(priority).strip().lower())
        if not prio:
            raise errors.ValidationError(
                f"validation_rejected: unknown priority {priority!r} "
                f"(use critical/high/normal/low)")
        job = models.Job(
            org_id=project.org_id, project_id=project.id, scan_id=scan.id,
            job_type=job_type, profile=profile, priority=prio,
            max_attempts=int(max_attempts),
            active_enabled=bool(active_enabled),
            timeout_seconds=int(timeout_seconds),
            payload=redact.redact(dict(payload or {})),
            actor_id=str(actor_id)[:128])
        job.finalize()
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO jobs (id, org_id, project_id, scan_id, "
                    "job_type, profile, status, priority, attempt, "
                    "max_attempts, active_enabled, timeout_seconds, "
                    "created_at, queued_at, started_at, finished_at, "
                    "heartbeat_at, lease_until, retry_at, worker_id, "
                    "actor_id, error_code, error_message, payload, "
                    "result_reference) VALUES "
                    "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (job.id, job.org_id, job.project_id, job.scan_id,
                     job.job_type, job.profile, "created", job.priority,
                     job.attempt, job.max_attempts,
                     1 if job.active_enabled else 0, job.timeout_seconds,
                     job.created_at, "", "", "", "", "", "", "", job.actor_id,
                     "", "", store.dumps(job.payload), ""))
        except Exception as e:
            raise errors.PersistenceError(f"job create failed: {e}") from e
        metrics.inc("jobs_created")
        self._audit("job.created", job)
        if queue_now:
            self.queue(job.id, actor=actor)
        return self.job_get(job.id)

    # ----------------------------------------------------------- queueing
    def queue(self, job_id: str, *, actor: str = "cli") -> models.Job:
        """created|retry_wait → queued (guarded, idempotent-safe)."""
        job = self.job_get(job_id)
        now = _now()
        target = "queued"
        if job.status == "paused":
            target = "paused"
        n = self.db.execute_affected(
            "UPDATE jobs SET status=?, queued_at=CASE WHEN queued_at='' "
            "THEN ? ELSE queued_at END, retry_at='', error_code='', "
            "error_message='' WHERE id=? AND status IN "
            "('created','retry_wait','paused')",
            (target, now, job_id))
        if n != 1:
            raise errors.LifecycleError(
                f"validation_rejected: cannot queue job in state "
                f"{job.status}")
        metrics.inc("jobs_queued")
        self._audit("job.queued", self.job_get(job_id), actor=actor)
        return self.job_get(job_id)

    def job_get(self, job_id: str) -> models.Job:
        row = self.svc.db.query_one(
            "SELECT * FROM jobs WHERE id=?", (job_id,))
        row["payload"] = store.loads(row.get("payload", "{}"))
        return models.Job.from_dict(row)

    def job_list(self, project_id: str | None = None, org_id: str | None = None,
                 status: str | None = None, limit: int = 200) -> list[models.Job]:
        limit = max(1, min(int(limit), 1000))
        clauses, params = [], []
        if project_id:
            clauses.append("project_id=?")
            params.append(project_id)
        if org_id:
            clauses.append("org_id=?")
            params.append(org_id)
        if status:
            clauses.append("status=?")
            params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.query(
            f"SELECT * FROM jobs {where} ORDER BY priority, queued_at, "
            f"created_at LIMIT ?", tuple(params) + (limit,))
        for r in rows:
            r["payload"] = store.loads(r.get("payload", "{}"))
        return [models.Job.from_dict(r) for r in rows]

    # ----------------------------------------------------------- claiming
    _COUNT_COLUMNS = ("org_id", "project_id", "scan_id")

    def _running_count(self, column: str, value: str) -> int:
        # column is an INTERNAL whitelisted constant — never user input
        if column not in self._COUNT_COLUMNS:
            raise errors.PersistenceError("bad count column")
        rows = self.db.query(
            f"SELECT COUNT(*) AS n FROM jobs WHERE status='running' AND "
            f"{column}=?", (value,))
        return int(rows[0]["n"]) if rows else 0

    def _candidate_ids(self, now_ts: str) -> list[dict]:
        rows = self.db.query(
            "SELECT id, org_id, project_id, scan_id, priority, queued_at "
            "FROM jobs WHERE status='queued' AND "
            "(retry_at='' OR retry_at<=?) "
            "ORDER BY priority, queued_at, created_at LIMIT ?",
            (now_ts, self.max_candidates))
        return rows

    def _pick_candidate(self, now_ts: str) -> dict | None:
        """Fairness: round-robin among organizations that have eligible jobs,
        priority within an organization, then per-org/project/scan caps."""
        cands = self._candidate_ids(now_ts)
        if not cands:
            return None
        by_org: dict[str, list[dict]] = {}
        for c in cands:
            by_org.setdefault(c["org_id"], []).append(c)
        orgs = sorted(by_org.keys())
        if self._rr_org in by_org:
            idx = orgs.index(self._rr_org)
            orgs = orgs[idx:] + orgs[:idx]
        for org in orgs:                      # rotate starting point
            for c in by_org[org]:
                if self._running_count("org_id", c["org_id"]) >= \
                        self.org_concurrency:
                    break
                if self._running_count("project_id", c["project_id"]) >= \
                        self.project_concurrency:
                    continue
                if self._running_count("scan_id", c["scan_id"]) >= \
                        self.scan_concurrency:
                    continue
                self._rr_org = org
                return c
        return None

    def claim_next(self, worker_id: str, now: str | None = None) -> models.Job | None:
        """Atomically claim ONE eligible job. Two workers concurrently
        picking the same candidate: only the first UPDATE wins (guarded
        WHERE status), so exactly one claim ever succeeds."""
        now_ts = now or _now()
        cand = self._pick_candidate(now_ts)
        if not cand:
            return None
        lease = _iso(_epoch(now_ts) + self.lease_seconds)
        n = self.db.execute_affected(
            "UPDATE jobs SET status='running', worker_id=?, "
            "started_at=CASE WHEN started_at='' THEN ? ELSE started_at END, "
            "heartbeat_at=?, lease_until=?, attempt=attempt+1 "
            "WHERE id=? AND status='queued' AND "
            "(retry_at='' OR retry_at<=?)",
            (worker_id, now_ts, now_ts, lease, cand["id"], now_ts))
        if n != 1:
            return None          # lost the race — another worker claimed it
        job = self.job_get(cand["id"])
        metrics.inc("jobs_claimed")
        self._audit("job.claimed", job, worker=worker_id[:64])
        return job

    # ----------------------------------------------------- runtime control
    def heartbeat(self, job_id: str, worker_id: str,
                  now: str | None = None) -> bool:
        now_ts = now or _now()
        lease = _iso(_epoch(now_ts) + self.lease_seconds)
        n = self.db.execute_affected(
            "UPDATE jobs SET heartbeat_at=?, lease_until=? "
            "WHERE id=? AND status='running' AND worker_id=?",
            (now_ts, lease, job_id, worker_id))
        return n == 1

    def control_state(self, job_id: str) -> str | None:
        """Called at safe checkpoints: returns 'paused' or 'cancelling'
        when the operator asked for a stop, None when the job may proceed."""
        rows = self.db.query(
            "SELECT status FROM jobs WHERE id=? LIMIT 1", (job_id,))
        if not rows:
            return "cancelling"
        st = rows[0]["status"]
        return st if st in ("paused", "cancelling") else None

    # ------------------------------------------------------- lifecycle ops
    def pause(self, job_id: str, *, actor: str = "cli") -> models.Job:
        n = self.db.execute_affected(
            "UPDATE jobs SET status='paused' WHERE id=? AND status IN "
            "('queued','running')", (job_id,))
        if n != 1:
            job = self.job_get(job_id)
            if job.status == "paused":
                return job                       # idempotent
            raise errors.LifecycleError(
                f"validation_rejected: cannot pause job in state "
                f"{job.status}")
        metrics.inc("jobs_paused")
        self._audit("job.paused", self.job_get(job_id), actor=actor)
        return self.job_get(job_id)

    def resume(self, job_id: str, *, actor: str = "cli") -> models.Job:
        n = self.db.execute_affected(
            "UPDATE jobs SET status='queued', retry_at='' WHERE id=? "
            "AND status='paused'", (job_id,))
        if n != 1:
            job = self.job_get(job_id)
            if job.status in ("queued", "running", "retry_wait"):
                return job                       # idempotent / already going
            raise errors.LifecycleError(
                f"validation_rejected: cannot resume job in state "
                f"{job.status}")
        self._audit("job.resumed", self.job_get(job_id), actor=actor)
        return self.job_get(job_id)

    def cancel(self, job_id: str, *, actor: str = "cli") -> models.Job:
        n = self.db.execute_affected(
            "UPDATE jobs SET status='cancelling' WHERE id=? AND status IN "
            "('created','queued','running','paused','retry_wait')",
            (job_id,))
        if n != 1:
            job = self.job_get(job_id)
            if job.status in ("cancelled", "cancelling", "completed",
                              "dead_letter"):
                return job                       # idempotent terminal stop
            raise errors.LifecycleError(
                f"validation_rejected: cannot cancel job in state "
                f"{job.status}")
        self._audit("job.cancel_requested", self.job_get(job_id), actor=actor)
        return self.job_get(job_id)

    def cancel_finalize(self, job_id: str, *, actor: str = "worker") -> models.Job:
        """cancelling → cancelled (worker checkpoint or API completion)."""
        n = self.db.execute_affected(
            "UPDATE jobs SET status='cancelled', finished_at=?, "
            "worker_id=CASE WHEN worker_id='' THEN ? ELSE worker_id END "
            "WHERE id=? AND status='cancelling'",
            (_now(), actor, job_id))
        if n != 1:
            return self.job_get(job_id)
        job = self.job_get(job_id)
        metrics.inc("jobs_cancelled")
        self._audit("job.cancelled", job, actor=actor)
        return job

    def fail(self, job_id: str, code: str, message: str, *,
             actor: str = "worker") -> models.Job:
        """Deterministic failure handling: non-retryable codes go straight to
        `failed`; retryable ones are rescheduled with backoff or dead-
        lettered when attempts are exhausted."""
        job = self.job_get(job_id)
        code = str(code)[:64]
        message = str(redact.redact_text(message))[:500]
        if code in NON_RETRYABLE:
            target = "failed"          # authorization/scope/config NEVER retried
        elif job.attempt >= job.max_attempts:
            target = "dead_letter"     # exhausted: administrator-visible
        else:
            target = "retry_wait"
        delay = retry_delay(job.attempt, base=self.backoff_base,
                            max_delay=self.backoff_max,
                            jitter=self.backoff_jitter)
        retry_at = _iso(_epoch(_now()) + delay)
        n = self.db.execute_affected(
            "UPDATE jobs SET status=?, error_code=?, error_message=?, "
            "retry_at=?, finished_at=CASE WHEN ? IN ('failed','dead_letter') "
            "THEN ? ELSE finished_at END WHERE id=? AND status='running'",
            (target, code, message, retry_at, target, _now(), job_id))
        if n != 1:
            return self.job_get(job_id)
        if target in ("failed", "dead_letter"):
            self._audit("job.failed" if target == "failed"
                        else "job.dead_lettered",
                        self.job_get(job_id), actor=actor, error=code)
            metrics.inc("jobs_failed" if target == "failed"
                        else "jobs_dead_lettered")
        else:
            self._audit("job.retry_scheduled", self.job_get(job_id),
                        actor=actor, error=code,
                        retry_in_seconds=round(delay, 1))
            metrics.inc("jobs_retried")
        return self.job_get(job_id)

    def dead_letter(self, job_id: str, code: str, message: str, *,
                    actor: str = "worker") -> models.Job:
        n = self.db.execute_affected(
            "UPDATE jobs SET status='dead_letter', error_code=?, "
            "error_message=?, finished_at=? WHERE id=? AND status IN "
            "('running','retry_wait')",
            (str(code)[:64], str(redact.redact_text(message))[:500],
             _now(), job_id))
        if n != 1:
            return self.job_get(job_id)
        job = self.job_get(job_id)
        metrics.inc("jobs_dead_lettered")
        self._audit("job.dead_lettered", job, actor=actor, error=code)
        return job

    def complete(self, job_id: str, *, result_reference: str = "",
                 actor: str = "worker") -> models.Job:
        """Idempotent completion: a duplicate completion is a no-op."""
        n = self.db.execute_affected(
            "UPDATE jobs SET status='completed', finished_at=?, "
            "result_reference=CASE WHEN ?='' THEN result_reference ELSE ? "
            "END WHERE id=? AND status='running'",
            (_now(), result_reference, result_reference, job_id))
        if n != 1:
            return self.job_get(job_id)      # already completed/failed etc.
        job = self.job_get(job_id)
        metrics.inc("jobs_completed")
        self._audit("job.completed", job, actor=actor)
        return job

    def retry_manual(self, job_id: str, *, actor: str = "cli") -> models.Job:
        """Operator-initiated retry of a terminal job: failed/dead_letter →
        queued with reset attempt budget."""
        n = self.db.execute_affected(
            "UPDATE jobs SET status='queued', attempt=0, retry_at='', "
            "error_code='', error_message='', queued_at=? "
            "WHERE id=? AND status IN ('failed','dead_letter')",
            (_now(), job_id))
        if n != 1:
            job = self.job_get(job_id)
            raise errors.LifecycleError(
                f"validation_rejected: cannot retry job in state "
                f"{job.status}")
        self._audit("job.queued", self.job_get(job_id), actor=actor,
                    note="manual_retry")
        return self.job_get(job_id)

    # ------------------------------------------------------- stale recovery
    def sweep_stale(self, now: str | None = None, *,
                    actor: str = "worker") -> int:
        """Reclaim jobs whose lease expired (worker died). Expired lease +
        attempts remaining → retry_wait (backoff); attempts exhausted →
        dead_letter. Never silently completes or drops anything."""
        now_ts = now or _now()
        rows = self.db.query(
            "SELECT id FROM jobs WHERE status='running' AND lease_until<>'' "
            "AND lease_until<? LIMIT 100", (now_ts,))
        reclaimed = 0
        for r in rows:
            job = self.job_get(r["id"])
            if job.attempt >= job.max_attempts:
                self.dead_letter(job.id, "stale_worker",
                                 "worker lease expired, attempts exhausted",
                                 actor=actor)
            else:
                delay = retry_delay(job.attempt, base=self.backoff_base,
                                    max_delay=self.backoff_max,
                                    jitter=self.backoff_jitter)
                retry_at = _iso(_epoch(now_ts) + delay)
                n = self.db.execute_affected(
                    "UPDATE jobs SET status='retry_wait', retry_at=?, "
                    "error_code='stale_worker', error_message='worker "
                    "lease expired', worker_id='' WHERE id=? AND "
                    "status='running' AND lease_until<?",
                    (retry_at, job.id, now_ts))
                if n == 1:
                    self._audit("job.retry_scheduled", self.job_get(job.id),
                                actor=actor, error="stale_worker",
                                retry_in_seconds=round(delay, 1))
                    metrics.inc("jobs_stale")
                    metrics.inc("jobs_retried")
            reclaimed += 1
        return reclaimed

    # ------------------------------------------- execution-time revalidation
    def validate_execution(self, job: models.Job) -> dict:
        """FAIL-CLOSED execution context validation. Called by the worker
        right before executing — a queued job may have waited hours while:
        org/project/scan/target/scope/profile all changed.

        Returns {scope, target}; raises errors.ValidationError with a
        NON_RETRYABLE prefix code on failure (never retried)."""
        profile = self.registry.validate_profile(job.profile)  # profile_unknown
        try:
            org = self.svc.org_get(job.org_id)
        except errors.NotFoundError:
            raise errors.ValidationError(
                "scan_invalid: organization no longer exists") from None
        if org.status != "active":
            raise errors.ValidationError(
                "org_disabled: organization is disabled")
        project = self.svc.project_require(job.project_id)
        if project.org_id != job.org_id:
            raise errors.ValidationError("scan_invalid: project/org mismatch")
        if project.status != "active":
            raise errors.ValidationError(
                "project_inactive: project is not active")
        scan = self.svc.scan_get(job.scan_id)
        if scan.project_id != job.project_id:
            raise errors.ValidationError("scan_invalid: scan/org mismatch")
        if scan.status in ("completed", "failed", "cancelled"):
            raise errors.ValidationError(
                "scan_invalid: scan is already terminal")
        target = str(job.payload.get("target")
                     or job.payload.get("bucket")
                     or job.payload.get("service") or "")
        # Phase 9 in-process profiles address REGISTERED tenant entities
        # (account/image/cluster/…): the authorization boundary is the org
        # itself (the services are org-scoped), not the network scope, so
        # the target is derived from the entity id and scope_check does not
        # apply. Missing entity ids still fail explicitly.
        in_process = getattr(self.registry.get(job.profile),
                          "in_process", False)
        if in_process:
            if not target:
                target = str(job.payload.get("account_id")
                             or job.payload.get("image_id")
                             or job.payload.get("cluster_id")
                             or job.payload.get("source_name") or "")
            if not target and job.profile == "posture-snapshot":
                target = "project:" + project.id
            if not target:
                raise errors.ValidationError(
                    "payload_rejected: no target/entity id supplied")
        else:
            if not target:
                raise errors.ValidationError(
                    "payload_rejected: no target supplied")
            check_scope = self.svc.scope_check(project.id, target)
            if not check_scope["in_scope"]:
                raise errors.ValidationError(
                    "scope_denied: target out of scope")
        if profile in self.registry.ACTIVE_PROFILES and \
                not job.active_enabled:
            raise errors.ValidationError(
                "not_authorized_active: active profile requires explicit "
                "active_enabled on the job")
        return {"target": target,
                "scope_ref": project.scope_policy.get("name", "")}
