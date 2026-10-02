#!/usr/bin/env python3
# ============================================================================
#  monitor.py — Phase 5 monitoring policies, deterministic scheduler,
#               monitoring health and retention.
#  ---------------------------------------------------------------------------
#  - MonitoringPolicy CRUD reuses the existing Scan model (no duplicate scan
#    model): a policy is a schedule + profile + targets, and every execution
#    creates an ordinary Phase-1 scan + Phase-3 job through the EXISTING
#    queue — the scheduler never runs scanners itself.
#  - Deterministic time-window scheduling: interval grid (anchored at policy
#    creation), daily, weekly; each window has a stable key so repeated
#    scheduler ticks can never duplicate a run (UNIQUE(policy, window)).
#  - Missed-schedule handling is bounded (skip / run_once / catch_up ≤ 3);
#    downtime never back-fills hundreds of jobs.
#  - Execution-time revalidation is mandatory and fail-closed: org/project
#    active, policy enabled, targets still in scope, profile registered,
#    active-scan authorization still explicit.
#  - Concurrency uses the Phase-3 job queue's own limits plus explicit
#    per-project / per-policy caps (monitoring_config).
#  - Monitoring health is METADATA (healthy/degraded/stale/disabled/error +
#    0-100 score) and is never confused with cybersecurity risk.
#  - Retention is explicit, configurable, tenant-scoped and audited; it never
#    touches immutable audit records or finding/evidence/alerts history.
# ============================================================================

from __future__ import annotations

import re
import time

import errors
import metrics
import models
import redact
import store

_KIND = {"interval", "daily", "weekly", "manual"}

_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
PROFILE_TIMEOUT_DEFAULT = 300
LIST_LIMIT_MAX = 500
MAX_TARGETS = 50
TARGET_LEN = 200
INTERVAL_MIN = 5
INTERVAL_MAX = 10080
CATCH_UP_MAX = 3             # bounded catch-up executions per policy per tick
MISSED_EVENT_MAX = 5         # bounded missed-run events per policy per tick
SLOT_SCAN_MAX = 32           # bounded window computation
HEALTH_HISTORY_KEEP = 200
DEFAULT_CONCURRENCY_PROJECT = 2
DEFAULT_CONCURRENCY_POLICY = 1
MANUAL_RUN_LIMIT = 5             # per policy+actor per window
MANUAL_RUN_WINDOW = 300          # seconds
_WORKER_GRACE_SECONDS = 120
_STALE_GRACE_FACTOR = 2.0    # expected-run grace for "stale"


def _epoch(ts: str) -> float:
    try:
        return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def _iso(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


def _window_key(policy: dict, slot_epoch: float) -> str:
    """Deterministic scheduled-window key (identity of one execution)."""
    return _iso(slot_epoch)


def _slot_after(policy: dict, anchor_epoch: float, after_epoch: float,
                *, count: int = 1) -> list[float]:
    """Next `count` schedule slots strictly after `after_epoch`.
    Interval windows are anchored at the policy's creation time so the grid
    is deterministic and reproducible."""
    kind = policy.get("schedule_type", "interval")
    if kind == "manual":
        return []
    if kind == "interval":
        step = float(policy.get("interval_minutes") or INTERVAL_MIN) * 60
        if step < INTERVAL_MIN * 60:
            step = INTERVAL_MIN * 60
        first = anchor_epoch + step
        if after_epoch >= anchor_epoch:
            k = max(1.0, (after_epoch - anchor_epoch) // step + 1)
            first = anchor_epoch + k * step
        return [first + i * step for i in range(count)]
    # daily / weekly: slots at the configured local-clock time (UTC clock;
    # documented as UTC — predictable, timezone-free determinism)
    hh, mm = _time_of(policy)
    day = int(policy.get("weekly_day") or 0) if kind == "weekly" else None
    slots = []
    cand = after_epoch + 60
    tries = 0
    while len(slots) < count and tries < SLOT_SCAN_MAX * 4:
        t = time.gmtime(cand)
        if kind == "daily" or (t.tm_wday == day):
            slot = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, hh, mm, 0,
                                0, 0, -1))
            if slot > after_epoch:
                slots.append(slot)
                cand = slot + 1
            else:
                cand += 86400
        else:
            cand += 86400
        tries += 1
    return slots


def _time_of(policy: dict) -> tuple:
    kind = policy.get("schedule_type", "interval")
    if kind == "weekly":
        clock = str(policy.get("weekly_time") or "00:00")
    else:
        clock = str(policy.get("daily_time") or "00:00")
    m = _TIME_RE.match(clock)
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


def _slots_between(policy: dict, anchor_epoch: float, after_epoch: float,
                   before_epoch: float) -> list[float]:
    out = []
    slot = anchor_epoch
    for _ in range(SLOT_SCAN_MAX * 2):
        nxt = _slot_after(policy, anchor_epoch, max(slot, after_epoch),
                          count=1)
        if not nxt:
            break
        slot = nxt[0]
        if slot > before_epoch + 1:
            break
        if slot > after_epoch:
            out.append(slot)
        if len(out) >= SLOT_SCAN_MAX:
            break
    return out


class MonitoringService:
    """Monitoring-policy configuration (one layer over existing scans)."""

    def __init__(self, platform, *, registry=None, limiter=None):
        self.svc = platform
        self.db = platform.db
        self._registry_obj = registry
        self.limiter = limiter

    def _registry(self):
        if self._registry_obj is None:
            import scanners as _sc
            self._registry_obj = _sc.REGISTRY
        return self._registry_obj

    def _acquire(self, key: str, limit: int, window: int) -> None:
        """Rate-limit gate (existing in-memory RateLimiter). Bounded:
        refuses overload rather than expanding."""
        if self.limiter is None:
            import identity as _id
            self.limiter = _id.RateLimiter()
        ok, retry = self.limiter.allowed(key, limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"rate_limited: retry after {retry}s ({limit}/{window}s)")

    # --------------------------------------------------------- validation
    def _validate(self, project_id: str, *, name: str, scan_profile: str,
                  schedule_type: str, interval_minutes: int, daily_time: str,
                  weekly_day: int, weekly_time: str, targets, active_scan,
                  priority: str, timeout_minutes: int, missed_policy: str,
                  max_concurrent: int) -> None:
        self.svc.project_require(project_id)
        if not str(name or "").strip():
            raise errors.ValidationError("name_required")
        if schedule_type not in _KIND:
            raise errors.ValidationError(
                f"schedule_unknown: {schedule_type!r} "
                f"(use {','.join(sorted(_KIND))})")
        try:
            self._registry().validate_profile(scan_profile)
        except errors.ValidationError as e:
            raise errors.ValidationError(str(e)) from e
        if schedule_type == "interval" and (
                int(interval_minutes) < INTERVAL_MIN or
                int(interval_minutes) > INTERVAL_MAX):
            raise errors.ValidationError(
                f"interval_rejected: {INTERVAL_MIN}..{INTERVAL_MAX} minutes")
        if schedule_type == "daily" and not _TIME_RE.match(str(daily_time)):
            raise errors.ValidationError(
                "daily_time_rejected: expected HH:MM (UTC)")
        if schedule_type == "weekly":
            if not _TIME_RE.match(str(weekly_time)):
                raise errors.ValidationError(
                    "weekly_time_rejected: expected HH:MM (UTC)")
            if not 0 <= int(weekly_day) <= 6:
                raise errors.ValidationError(
                    "weekly_day_rejected: 0 (Mon) .. 6 (Sun)")
        if missed_policy not in models.MISSED_POLICIES:
            raise errors.ValidationError(
                f"missed_unknown: {missed_policy!r}")
        if priority not in models.JOB_PRIORITIES:
            raise errors.ValidationError(
                f"priority_unknown: {priority!r}")
        if not isinstance(targets, list) or not targets or \
                len(targets) > MAX_TARGETS:
            raise errors.ValidationError(
                f"targets_rejected: 1..{MAX_TARGETS} targets")
        for t in targets:
            if not isinstance(t, str) or not t.strip() or \
                    len(t) > TARGET_LEN:
                raise errors.ValidationError(
                    "targets_rejected: target must be a short string")
        if not 0 <= int(max_concurrent) <= 10:
            raise errors.ValidationError(
                "max_concurrent_rejected: 0..10")

    # ------------------------------------------------------------- create
    def create(self, project_id: str, name: str, *, scan_profile: str,
               schedule_type: str = "interval", interval_minutes: int = 1440,
               daily_time: str = "08:00", weekly_day: int = 1,
               weekly_time: str = "08:00", targets=None,
               scope_json: dict | None = None,
               active_scan_permitted: bool = False,
               priority: str = "normal", timeout_minutes: int = 0,
               missed_policy: str = "skip", max_concurrent: int = 1,
               actor: str = "cli") -> dict:
        self._validate(
            project_id, name=name, scan_profile=scan_profile,
            schedule_type=schedule_type, interval_minutes=interval_minutes,
            daily_time=daily_time, weekly_day=weekly_day,
            weekly_time=weekly_time, targets=targets or [],
            active_scan=active_scan_permitted, priority=priority,
            timeout_minutes=timeout_minutes, missed_policy=missed_policy,
            max_concurrent=max_concurrent)
        project = self.svc.project_get(project_id)
        policy_id = models.stable_id(
            models.NS_POLICY, f"{project_id}|{str(name).strip()}|monitor-v1")
        now = models.utcnow()
        targets = [str(t)[:TARGET_LEN] for t in (targets or [])]
        scope_json = dict(scope_json or {})
        policy = {
            "id": policy_id, "project_id": project_id,
            "org_id": project.org_id, "name": str(name).strip()[:120],
            "enabled": 1, "scan_profile": scan_profile,
            "schedule_type": schedule_type,
            "interval_minutes": int(interval_minutes),
            "daily_time": str(daily_time)[:5],
            "weekly_day": int(weekly_day),
            "weekly_time": str(weekly_time)[:5],
            "targets": targets, "scope_json": scope_json,
            "active_scan_permitted": 1 if active_scan_permitted else 0,
            "priority": priority, "timeout_minutes": int(timeout_minutes),
            "missed_policy": missed_policy,
            "max_concurrent": int(max_concurrent),
            "last_run": "", "last_success": "", "last_failure": "",
            "consecutive_failures": 0,
            "next_run": "", "created_at": now, "updated_at": now,
        }
        anchor = _epoch(now)
        if schedule_type != "manual":
            slots = _slot_after(policy, anchor, anchor, count=1)
            policy["next_run"] = _iso(slots[0]) if slots else ""
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO monitoring_policies (id, project_id, org_id, "
                    "name, enabled, scan_profile, schedule_type, "
                    "interval_minutes, daily_time, weekly_day, weekly_time, "
                    "targets, scope_json, active_scan_permitted, priority, "
                    "timeout_minutes, missed_policy, max_concurrent, "
                    "last_run, last_success, last_failure, "
                    "consecutive_failures, next_run, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (policy_id, project_id, project.org_id,
                     policy["name"], 1, scan_profile, schedule_type,
                     policy["interval_minutes"], policy["daily_time"],
                     policy["weekly_day"], policy["weekly_time"],
                     store.dumps(targets), store.dumps(scope_json),
                     policy["active_scan_permitted"], priority,
                     policy["timeout_minutes"], missed_policy,
                     policy["max_concurrent"], "", "", "", 0,
                     policy["next_run"], now, now))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise errors.DuplicateError(
                    f"policy already exists: {name}") from e
            raise errors.PersistenceError(f"policy failed: {e}") from e
        metrics.inc("monitoring_policies")
        self.svc.audit("monitoring.policy.created",
                       object_type="monitoring_policy",
                       object_id=policy_id, org_id=project.org_id,
                       project_id=project_id, actor=actor,
                       metadata={"name": policy["name"],
                                 "schedule": schedule_type,
                                 "profile": scan_profile})
        return self.get(policy_id)

    # -------------------------------------------------------------- reads
    def get(self, policy_id: str) -> dict:
        rows = self.db.query("SELECT * FROM monitoring_policies WHERE id=? "
                             "LIMIT 1", (policy_id,))
        if not rows:
            raise errors.NotFoundError("monitoring policy not found")
        p = dict(rows[0])
        p["targets"] = store.loads(p.get("targets", "[]"))
        p["scope_json"] = store.loads(p.get("scope_json", "{}"))
        return p

    def list(self, project_id: str, *, enabled: bool | None = None,
             limit: int = 100) -> list[dict]:
        self.svc.project_require(project_id)
        limit = min(max(int(limit), 1), LIST_LIMIT_MAX)
        if enabled is None:
            rows = self.db.query(
                "SELECT * FROM monitoring_policies WHERE project_id=? "
                "ORDER BY name LIMIT ?", (project_id, limit))
        else:
            rows = self.db.query(
                "SELECT * FROM monitoring_policies WHERE project_id=? AND "
                "enabled=? ORDER BY name LIMIT ?",
                (project_id, 1 if enabled else 0, limit))
        out = []
        for r in rows:
            r["targets"] = store.loads(r.get("targets", "[]"))
            r["scope_json"] = store.loads(r.get("scope_json", "{}"))
            out.append(dict(r))
        return out

    # ---------------------------------------------------------- controls
    def set_enabled(self, policy_id: str, enabled: bool, *,
                    actor: str = "cli") -> dict:
        p = self.get(policy_id)
        now = models.utcnow()
        next_run = p.get("next_run", "")
        if enabled and not next_run and p.get("schedule_type") != "manual":
            slots = _slot_after(p, _epoch(p.get("created_at", now)),
                                _epoch(now), count=1)
            next_run = _iso(slots[0]) if slots else ""
        self.db.execute(
            "UPDATE monitoring_policies SET enabled=?, next_run=?, "
            "updated_at=? WHERE id=?",
            (1 if enabled else 0, next_run if enabled else "", now,
             policy_id))
        self.svc.audit("monitoring.policy." +
                       ("enabled" if enabled else "disabled"),
                       object_type="monitoring_policy", object_id=policy_id,
                       org_id=p["org_id"], project_id=p["project_id"],
                       actor=actor)
        return self.get(policy_id)

    def delete(self, policy_id: str, *, actor: str = "cli") -> dict:
        p = self.get(policy_id)
        self.db.execute("DELETE FROM monitoring_policies WHERE id=?",
                        (policy_id,))
        self.svc.audit("monitoring.policy.deleted",
                       object_type="monitoring_policy", object_id=policy_id,
                       org_id=p["org_id"], project_id=p["project_id"],
                       actor=actor, metadata={"name": p["name"]})
        return {"deleted": True, "policy_id": policy_id}

    # ------------------------------------------------------ concurrency
    def config_get(self, project_id: str) -> dict:
        self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT * FROM monitoring_config WHERE project_id=? LIMIT 1",
            (project_id,))
        if not rows:
            return {"project_id": project_id,
                    "max_concurrent_scans_per_project":
                        DEFAULT_CONCURRENCY_PROJECT,
                    "max_concurrent_scans_per_policy":
                        DEFAULT_CONCURRENCY_POLICY}
        r = rows[0]
        return {"project_id": project_id,
                "max_concurrent_scans_per_project":
                    int(r.get("max_concurrent_scans_per_project") or
                        DEFAULT_CONCURRENCY_PROJECT),
                "max_concurrent_scans_per_policy":
                    int(r.get("max_concurrent_scans_per_policy") or
                        DEFAULT_CONCURRENCY_POLICY)}

    def config_set(self, project_id: str, *,
                   max_concurrent_scans_per_project: int = 0,
                   max_concurrent_scans_per_policy: int = 0,
                   actor: str = "cli") -> dict:
        self.svc.project_require(project_id)
        project = self.svc.project_get(project_id)
        cur = self.config_get(project_id)
        proj_c = int(max_concurrent_scans_per_project or
                     cur["max_concurrent_scans_per_project"])
        pol_c = int(max_concurrent_scans_per_policy or
                    cur["max_concurrent_scans_per_policy"])
        if not 1 <= proj_c <= 50 or not 1 <= pol_c <= 10:
            raise errors.ValidationError(
                "concurrency_rejected: project 1..50, policy 1..10")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO monitoring_config (project_id, org_id, "
                "max_concurrent_scans_per_project, "
                "max_concurrent_scans_per_policy, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET "
                "max_concurrent_scans_per_project="
                "excluded.max_concurrent_scans_per_project, "
                "max_concurrent_scans_per_policy="
                "excluded.max_concurrent_scans_per_policy, "
                "updated_at=excluded.updated_at",
                (project_id, project.org_id, proj_c, pol_c,
                 models.utcnow(), models.utcnow()))
        self.svc.audit("monitoring.config.updated", object_type="project",
                       object_id=project_id, org_id=project.org_id,
                       project_id=project_id, actor=actor,
                       metadata={"project": proj_c, "policy": pol_c})
        return self.config_get(project_id)

    def _concurrency_ok(self, policy: dict) -> bool:
        cfg = self.config_get(policy["project_id"])
        proj = self.db.query_one(
            "SELECT COUNT(*) AS n FROM jobs WHERE project_id=? AND status IN "
            "('created','queued','running','retry_wait')",
            (policy["project_id"],))
        if proj and int(proj["n"]) >= int(
                cfg["max_concurrent_scans_per_project"]):
            return False
        # Per-policy in-flight cap: the policy's own max_concurrent wins;
        # the config value is the default for policies that did not set one.
        limit = int(policy.get("max_concurrent") or
                    cfg["max_concurrent_scans_per_policy"] or
                    DEFAULT_CONCURRENCY_POLICY)
        pol = self.db.query_one(
            "SELECT COUNT(*) AS n FROM scheduler_executions WHERE "
            "policy_id=? AND status IN ('scheduled','created')",
            (policy["id"],))
        if pol and int(pol["n"]) >= max(1, limit):
            return False
        return True


class SchedulerService:
    """Deterministic scheduler: creates ordinary Scan + Job records through
    the existing Phase-3 queue (never executes scanners itself)."""

    def __init__(self, platform, *, registry=None, limiter=None,
                 catch_up_max: int = CATCH_UP_MAX):
        self.svc = platform
        self.db = platform.db
        self.monitor = MonitoringService(platform, registry=registry,
                                         limiter=limiter)
        self.limiter = limiter
        self._registry_obj = registry
        self.catch_up_max = int(catch_up_max)
        self._max_exec_reason = 200

    def _registry(self):
        if self._registry_obj is None:
            import scanners as _sc
            self._registry_obj = _sc.REGISTRY
        return self._registry_obj

    def _acquire(self, key: str, limit: int, window: int) -> None:
        """Rate-limit gate for manual runs (scheduler ticks are windowed by
        design and never rate-limited)."""
        if self.limiter is None:
            import identity as _id
            self.limiter = _id.RateLimiter()
        ok, retry = self.limiter.allowed(key, limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"rate_limited: retry after {retry}s ({limit}/{window}s)")

    # ----------------------------------------------------- revalidation
    def _revalidate(self, policy: dict) -> str:
        """Fail-closed execution-time validation. Returns "" or a reason."""
        try:
            org = self.svc.org_get(policy["org_id"])
        except errors.NotFoundError:
            return "org_missing"
        if str(org.status).lower() != "active":
            return "org_inactive"
        try:
            project = self.svc.project_get(policy["project_id"])
        except errors.NotFoundError:
            return "project_missing"
        if str(project.status).lower() != "active":
            return "project_inactive"
        if not policy.get("enabled"):
            return "policy_disabled"
        try:
            self._registry().validate_profile(policy["scan_profile"])
        except errors.ValidationError:
            return "profile_unknown"
        scope_json = policy.get("scope_json") or {}
        for target in (policy.get("targets") or []):
            check = self.svc.scope_check(policy["project_id"], target)
            if not check["in_scope"]:
                return "target_out_of_scope"
        if policy["scan_profile"] in self._registry().ACTIVE_PROFILES:
            if not policy.get("active_scan_permitted"):
                return "active_scan_not_authorized"
        return ""

    def _run(self, policy: dict, window: str, *, actor: str = "scanner") -> dict:
        """Create ONE scheduled execution (scan + job) for a policy+window.
        Idempotent: the UNIQUE(policy, window) execution row is the lock."""
        reason = self._revalidate(policy)
        project_id = policy["project_id"]
        execution_id = models.stable_id(
            models.NS_MONRUN, f"{policy['id']}|{window}")
        if reason:
            try:
                with self.db.transaction() as conn:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO scheduler_executions (id, "
                        "project_id, org_id, policy_id, scheduled_window, "
                        "scan_id, status, reason, created_at, finished_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (execution_id, project_id, policy["org_id"],
                         policy["id"], window, "", "skipped",
                         reason[:self._max_exec_reason], models.utcnow(),
                         models.utcnow()))
                    if cur.rowcount != 1:
                        return {"status": "already_recorded",
                                "execution_id": execution_id}
            except Exception as e:
                raise errors.PersistenceError(
                    f"scheduler record failed: {e}") from e
            self.svc.audit("monitoring.schedule_skipped",
                           object_type="monitoring_policy",
                           object_id=policy["id"], org_id=policy["org_id"],
                           project_id=project_id, actor=actor,
                           metadata={"window": window, "reason": reason})
            return {"status": "skipped", "execution_id": execution_id,
                    "reason": reason}
        if not self.monitor._concurrency_ok(policy):
            try:
                with self.db.transaction() as conn:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO scheduler_executions (id, "
                        "project_id, org_id, policy_id, scheduled_window, "
                        "scan_id, status, reason, created_at, finished_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (execution_id, project_id, policy["org_id"],
                         policy["id"], window, "", "skipped",
                         "concurrency_limit_reached",
                         models.utcnow(), models.utcnow()))
                    if cur.rowcount != 1:
                        return {"status": "already_recorded",
                                "execution_id": execution_id}
            except Exception as e:
                raise errors.PersistenceError(
                    f"scheduler record failed: {e}") from e
            return {"status": "skipped", "execution_id": execution_id,
                    "reason": "concurrency_limit_reached"}
        # create the deterministic scan + job (existing Phase-1/3 objects)
        scan_id = models.stable_id(models.NS_MONRUN,
                                   f"{policy['id']}|scan|{window}")
        exists = self.db.query("SELECT id FROM scans WHERE id=? LIMIT 1",
                               (scan_id,))
        try:
            if not exists:
                self.svc.scan_create(
                    project_id, policy["scan_profile"],
                    scope_ref=f"monitoring:{policy['id']}",
                    initiator={"actor": "scheduler", "policy_id":
                               policy["id"], "window": window},
                    scan_id=scan_id)
        except Exception as e:
            if "UNIQUE" not in str(e):
                return {"status": "failed", "reason": f"scan_create: {e}"}
        job = None
        try:
            import jobs as _jb
            jsvc = _jb.JobService(self.svc, self._registry())
            job = jsvc.create_job(
                scan_id, policy["scan_profile"],
                {"target": (policy.get("targets") or [""])[0],
                 "note": f"monitoring policy {policy['id']} window {window}"},
                job_type="scan", priority=policy["priority"],
                active_enabled=bool(policy.get("active_scan_permitted")),
                max_attempts=3,
                timeout_seconds=int(policy.get("timeout_minutes") or 0) * 60
                or int(self._registry().get(policy["scan_profile"]).timeout),
                actor="scheduler", queue_now=True)
        except Exception as e:
            try:
                with self.db.transaction() as conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO scheduler_executions (id, "
                        "project_id, org_id, policy_id, scheduled_window, "
                        "scan_id, status, reason, created_at, finished_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (execution_id, project_id, policy["org_id"],
                         policy["id"], window, scan_id, "failed",
                         f"job_create: {str(e)[:120]}", models.utcnow(),
                         models.utcnow()))
            except Exception:
                pass
            return {"status": "failed",
                    "reason": f"job_create: {str(e)[:120]}"}
        try:
            self.db.execute(
                "INSERT OR IGNORE INTO scheduler_executions (id, project_id, "
                "org_id, policy_id, scheduled_window, scan_id, status, "
                "reason, created_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (execution_id, project_id, policy["org_id"], policy["id"],
                 window, scan_id, "created", "", models.utcnow(), ""))
        except Exception:
            pass
        metrics.inc("scheduled_runs")
        self.svc.audit("monitoring.scheduled_run", object_type="scan",
                       object_id=scan_id, org_id=policy["org_id"],
                       project_id=project_id, actor=actor,
                       metadata={"policy_id": policy["id"],
                                 "window": window, "job": job.id})
        return {"status": "created", "scan_id": scan_id,
                "job_id": job.id, "execution_id": execution_id}

    # ------------------------------------------------------- run_due
    def run_due(self, now: str | None = None, *, limit: int = 20) -> dict:
        """Scheduler tick: bounded, idempotent, missed-run safe."""
        now = now or models.utcnow()
        now_ep = _epoch(now)
        created, skipped, missed = [], 0, 0
        rows = self.db.query(
            "SELECT * FROM monitoring_policies WHERE enabled=1 AND "
            "next_run<>'' AND next_run<=? ORDER BY next_run LIMIT ?",
            (now, min(max(int(limit), 1), 200)))
        for raw in rows:
            policy = dict(raw)
            policy["targets"] = store.loads(policy.get("targets", "[]"))
            policy["scope_json"] = store.loads(policy.get("scope_json", "{}"))
            anchor = _epoch(policy.get("created_at", now))
            # Due window = next_run itself. Backlog = schedule windows
            # strictly between next_run and now (windows the ticker never
            # got to; they are stale by at least one full slot). The due
            # window ALWAYS runs when the policy is due — a monitoring
            # policy must never silently stop because its ticker ran a few
            # seconds late.
            slots = _slots_between(policy, anchor,
                                   _epoch(policy["next_run"]) - 1.0, now_ep)
            executed = {r["scheduled_window"] for r in self.db.query(
                "SELECT scheduled_window FROM scheduler_executions "
                "WHERE policy_id=?", (policy["id"],))}
            pending = [s for s in slots
                       if _window_key(policy, s) not in executed]
            missed_this_policy = 0
            if pending:
                due = pending[-1]          # most recent → current state
                backlog = pending[:-1]     # older → missed-policy domain
                mode = policy.get("missed_policy", "skip")
                if mode == "skip":
                    run_slots = [due]
                    missed_slots = backlog
                elif mode == "run_once":
                    run_slots = [due] + backlog[-1:]
                    missed_slots = backlog[:-1]
                else:  # catch_up — total runs bounded by catch_up_max (<=3)
                    back = backlog[-(max(0, self.catch_up_max - 1)):]
                    run_slots = [due] + back
                    missed_slots = [s for s in backlog if s not in back]
                for s in run_slots:
                    res = self._run(
                        policy, _window_key(policy, s), actor="scheduler")
                    if res.get("status") == "created":
                        created.append(res)
                    elif res.get("status") == "skipped":
                        skipped += 1
                for s in missed_slots[:MISSED_EVENT_MAX]:
                    missed += 1
                    missed_this_policy += 1
                    self._missed_event(policy, s, "missed_schedule")
            # advance next_run past now (backlog was consumed above)
            upcoming = _slot_after(policy, anchor, now_ep, count=1)
            if upcoming:
                self.db.execute(
                    "UPDATE monitoring_policies SET next_run=?, updated_at=? "
                    "WHERE id=?", (_iso(upcoming[0]), models.utcnow(),
                                   policy["id"]))
            if missed_this_policy:
                self.svc.audit(
                    "monitoring.missed_runs",
                    object_type="monitoring_policy",
                    object_id=policy["id"], org_id=policy["org_id"],
                    project_id=policy["project_id"], actor="scheduler",
                    metadata={"missed": missed_this_policy,
                              "window": now})
        return {"scans_created": len(created), "skipped": skipped,
                "missed_events": missed, "scans": created}

    def _missed_event(self, policy: dict, slot_epoch: float,
                      kind: str) -> None:
        try:
            from alerts import pipeline_event
            pipeline_event(
                self.svc, project_id=policy["project_id"],
                event_type="monitoring.missed_scan",
                key=f"missed|{_window_key(policy, slot_epoch)}",
                scan_id="", previous_state={"next_run": _iso(slot_epoch)},
                new_state={"policy_id": policy["id"], "kind": kind},
                source="scheduler", confidence=0.9, actor="scheduler",
                org_id=policy["org_id"])
            metrics.inc("missed_runs")
        except Exception:
            pass

    def run_now(self, policy_id: str, *, actor: str = "cli") -> dict:
        """Manual run: same validation, same queue, no schedule advance."""
        self._acquire(f"monitor:manual:{policy_id}:{actor}",
                      MANUAL_RUN_LIMIT, MANUAL_RUN_WINDOW)
        policy = self.monitor.get(policy_id)
        if not policy.get("enabled"):
            raise errors.LifecycleError(
                "validation_rejected: policy is disabled")
        window = f"manual-{int(time.time())}"
        res = self._run(policy, window, actor=actor)
        if res.get("status") == "created":
            self.db.execute(
                "UPDATE monitoring_policies SET last_run=?, updated_at=? "
                "WHERE id=?", (models.utcnow(), models.utcnow(), policy_id))
            self.svc.audit("monitoring.manual_run", object_type="scan",
                           object_id=res.get("scan_id", ""),
                           org_id=policy["org_id"],
                           project_id=policy["project_id"], actor=actor,
                           metadata={"policy_id": policy_id})
        return res

    # ------------------------------------------------- sweep / terminal
    def on_scan_terminal(self, project_id: str, scan_id: str,
                         outcome: str, *, error: str = "") -> None:
        """Worker hook: record scheduled-run outcome + health (idempotent)."""
        rows = self.db.query(
            "SELECT * FROM scheduler_executions WHERE scan_id=? LIMIT 1",
            (scan_id,))
        if not rows:
            return
        exec_row = rows[0]
        if exec_row["status"] in ("completed", "failed"):
            return  # already resolved
        new_status = "completed" if outcome == "completed" else "failed"
        self.db.execute(
            "UPDATE scheduler_executions SET status=?, finished_at=? "
            "WHERE id=?", (new_status, models.utcnow(), exec_row["id"]))
        pol = self.db.query(
            "SELECT * FROM monitoring_policies WHERE id=? LIMIT 1",
            (exec_row["policy_id"],))
        if pol:
            policy = pol[0]
            now = models.utcnow()
            if outcome == "completed":
                self.db.execute(
                    "UPDATE monitoring_policies SET last_run=?, last_success="
                    "?, consecutive_failures=0, updated_at=? WHERE id=?",
                    (now, now, now, policy["id"]))
                metrics.inc("successful_runs")
            else:
                self.db.execute(
                    "UPDATE monitoring_policies SET last_run=?, last_failure="
                    "?, consecutive_failures=consecutive_failures+1, "
                    "updated_at=? WHERE id=?",
                    (now, now, now, policy["id"]))
                metrics.inc("failed_runs")
                try:
                    from alerts import pipeline_event
                    pipeline_event(
                        self.svc, project_id=project_id,
                        event_type="monitoring.scan_failure",
                        key=f"exec|{exec_row['id']}", scan_id=scan_id,
                        previous_state={"window": exec_row["scheduled_window"]},
                        new_state={"policy_id": policy["id"],
                                   "error": redact.redact_text(error)[:160]},
                        source="worker", confidence=0.9, actor="worker",
                        org_id=policy["org_id"])
                except Exception:
                    pass
        try:
            MonitoringHealthService(self.svc).compute(project_id)
        except Exception:
            pass

    def sweep_stale(self, now: str | None = None, *, limit: int = 50) -> int:
        """Emit monitoring.stale events for policies past their grace."""
        now = now or models.utcnow()
        n = 0
        rows = self.db.query(
            "SELECT * FROM monitoring_policies WHERE enabled=1 AND "
            "next_run<>'' AND next_run<=? ORDER BY next_run LIMIT ?",
            (now, int(limit)))
        for raw in rows:
            policy = dict(raw)
            if not policy.get("last_success"):
                continue
            interval = float(policy.get("interval_minutes") or 1440) * 60
            grace = max(interval * _STALE_GRACE_FACTOR, 86400)
            if _epoch(now) - _epoch(policy.get("last_success", now)) > grace:
                try:
                    from alerts import pipeline_event
                    ev = pipeline_event(
                        self.svc, project_id=policy["project_id"],
                        event_type="monitoring.stale",
                        key=f"stale|{policy['id']}",
                        new_state={"policy_id": policy["id"],
                                   "last_success":
                                       policy.get("last_success", "")},
                        source="scheduler", confidence=0.9, actor="scheduler")
                    if ev is not None:
                        n += 1
                except Exception:
                    pass
        return n


class MonitoringHealthService:
    """Monitoring health (METADATA — never security risk)."""

    def __init__(self, platform):
        self.svc = platform
        self.db = platform.db

    def compute(self, project_id: str, *, now: str | None = None) -> dict:
        now = now or models.utcnow()
        project = self.svc.project_require(project_id)
        policies = self.db.query(
            "SELECT * FROM monitoring_policies WHERE project_id=? ORDER BY "
            "name LIMIT 50", (project_id,))
        enabled = [p for p in policies if p.get("enabled")]
        execs = self.db.query(
            "SELECT * FROM scheduler_executions WHERE project_id=? ORDER BY "
            "created_at DESC LIMIT 20", (project_id,))
        successes = sum(1 for e in execs if e["status"] == "completed")
        failures = sum(1 for e in execs if e["status"] == "failed")
        total = successes + failures
        ratio = (successes / total) if total else 1.0
        pol_fail = self.db.query(
            "SELECT MAX(consecutive_failures) AS c FROM "
            "monitoring_policies WHERE project_id=? LIMIT 1", (project_id,))
        consecutive = int(pol_fail[0]["c"]) if pol_fail and \
            pol_fail[0].get("c") is not None else 0
        next_run = ""
        last_success = ""
        last_failure = ""
        for e in execs:
            if e["status"] == "completed" and not last_success:
                last_success = e.get("created_at", "")
            if e["status"] == "failed" and not last_failure:
                last_failure = e.get("created_at", "")
        # worker availability (Phase-3 heartbeat)
        worker_rows = self.db.query(
            "SELECT status, last_heartbeat FROM workers ORDER BY "
            "last_heartbeat DESC LIMIT 3")
        worker_ok = 0.0
        for w in worker_rows:
            hb_age = _epoch(now) - _epoch(w.get("last_heartbeat", ""))
            if w.get("status") == "running" and 0 <= hb_age <= \
                    _WORKER_GRACE_SECONDS:
                worker_ok = 1.0
                break
        # notification health (24h window)
        notif_fail = self.db.query_one(
            "SELECT COUNT(*) AS n FROM notifications WHERE project_id=? AND "
            "status IN ('failed','dead_letter') AND created_at>=?",
            (project_id, _iso(_epoch(now) - 86400)))
        notif_sent = self.db.query_one(
            "SELECT COUNT(*) AS n FROM notifications WHERE project_id=? AND "
            "status='sent' AND created_at>=?",
            (project_id, _iso(_epoch(now) - 86400)))
        nf = int(notif_fail["n"]) if notif_fail else 0
        ns = int(notif_sent["n"]) if notif_sent else 0
        notif_health = 1.0 if (nf + ns) == 0 else \
            max(0.0, ns / (nf + ns))
        # asset freshness (Phase-4 last observation)
        asset_rows = self.db.query(
            "SELECT MAX(last_seen) AS m FROM asset_observations WHERE "
            "project_id=? LIMIT 1", (project_id,))
        asset_fresh = 1.0
        if asset_rows and asset_rows[0].get("m"):
            age = _epoch(now) - _epoch(asset_rows[0]["m"])
            hours = max(1.0, (enabled[0].get("interval_minutes") or 1440)
                        * 4.0)
            asset_fresh = max(0.0, 1.0 - age / (hours * 3600))
        # score: bounded, deterministic weights (health ≠ risk)
        scan_fresh = 1.0
        if enabled:
            next_run = enabled[0].get("next_run", "")
            if next_run:
                overdue = max(0.0, _epoch(now) - _epoch(next_run))
                grace = max(float(enabled[0].get("interval_minutes") or 1440)
                            * 120, 3600)
                scan_fresh = max(0.0, 1.0 - overdue / grace)
        score = round(100 * (0.30 * scan_fresh + 0.20 * asset_fresh +
                             0.25 * ratio + 0.15 * notif_health +
                             0.10 * worker_ok), 1)
        # classification (deterministic, monotonic)
        if not enabled:
            state = "disabled"
        elif failures >= 1 and worker_ok == 0.0:
            state = "error"
        elif consecutive >= 2 or ratio < 0.5:
            state = "degraded"
        elif enabled and next_run and _epoch(now) > _epoch(next_run) + \
                max(float(enabled[0].get("interval_minutes") or 1440) * 60 *
                    _STALE_GRACE_FACTOR, 86400):
            state = "stale"
        else:
            state = "healthy"
        if state == "error":
            metrics.inc("monitoring_health_failures")
        payload = {
            "project_id": project_id, "org_id": project.org_id,
            "health": state, "score": score,
            "dimensions": {
                "scan_freshness": round(scan_fresh, 3),
                "asset_freshness": round(asset_fresh, 3),
                "success_ratio": round(ratio, 3),
                "consecutive_failures": consecutive,
                "notification_health": round(notif_health, 3),
                "worker_availability": round(worker_ok, 3),
            },
            "last_success": last_success, "last_failure": last_failure,
            "consecutive_failures": consecutive,
            "next_expected_run": (enabled[0].get("next_run", "")
                                  if enabled else ""),
        }
        rows = self.db.query("SELECT last_alert FROM monitoring_health "
                             "WHERE project_id=? LIMIT 1", (project_id,))
        payload["last_alert"] = rows[0]["last_alert"] if rows else ""
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO monitoring_health (project_id, org_id, health, "
                "score, dimensions, last_success, last_failure, "
                "consecutive_failures, last_change, last_alert, "
                "next_expected_run, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(project_id) DO UPDATE SET health="
                "excluded.health, score=excluded.score, dimensions="
                "excluded.dimensions, last_success=excluded.last_success, "
                "last_failure=excluded.last_failure, consecutive_failures="
                "excluded.consecutive_failures, next_expected_run="
                "excluded.next_expected_run, updated_at=excluded.updated_at",
                (project_id, project.org_id, state, score,
                 store.dumps(payload["dimensions"]), last_success,
                 last_failure, consecutive, now, payload["last_alert"],
                 payload["next_expected_run"], now))
            conn.execute(
                "INSERT OR IGNORE INTO monitoring_health_history (id, "
                "project_id, ts, health, score) VALUES (?,?,?,?,?)",
                (models.stable_id(models.NS_MONCFG,
                                  f"{project_id}|{now}|{state}"),
                 project_id, now, state, score))
        # bounded retention of health history (never audit/finding tables)
        old = self.db.query(
            "SELECT id FROM monitoring_health_history WHERE project_id=? "
            "ORDER BY ts DESC LIMIT -1 OFFSET ?", (project_id,
                                                   HEALTH_HISTORY_KEEP))
        for r in old:
            self.db.execute("DELETE FROM monitoring_health_history "
                            "WHERE id=?", (r["id"],))
        return payload

    def get(self, project_id: str, *, now: str | None = None) -> dict:
        rows = self.db.query("SELECT * FROM monitoring_health WHERE "
                             "project_id=? LIMIT 1", (project_id,))
        if rows:
            r = dict(rows[0])
            r["dimensions"] = store.loads(r.get("dimensions", "{}"))
            return r
        return self.compute(project_id, now=now)

    def history(self, project_id: str, *, limit: int = 30) -> list[dict]:
        self.svc.project_require(project_id)
        limit = min(max(int(limit), 1), 200)
        return [dict(r) for r in self.db.query(
            "SELECT * FROM monitoring_health_history WHERE project_id=? "
            "ORDER BY ts DESC LIMIT ?", (project_id, limit))]


# ---------------------------------------------------------------------------
# Retention (bounded; explicit; configurable; tenant-scoped; audited)
# ---------------------------------------------------------------------------
def retention_sweep(svc, *, project_id: str = "", event_days: int = 180,
                    attempt_days: int = 90, exec_days: int = 365,
                    actor: str = "scheduler") -> dict:
    """Prune high-volume monitoring history. NEVER touches audit_events,
    findings, evidence, alerts/occurrences or tickets (traceability)."""
    now = models.utcnow()
    ev_cut = _iso(_epoch(now) - float(max(30, int(event_days))) * 86400)
    at_cut = _iso(_epoch(now) - float(max(30, int(attempt_days))) * 86400)
    ex_cut = _iso(_epoch(now) - float(max(30, int(exec_days))) * 86400)
    counts = {"security_events": 0, "notification_attempts": 0,
              "scheduler_executions": 0}
    with svc.db.transaction() as conn:
        if project_id:
            rows = conn.execute(
                "DELETE FROM security_events WHERE project_id=? AND ts<? "
                "AND id NOT IN (SELECT o.event_id FROM alert_occurrences o "
                "WHERE o.event_id<>'')",
                (project_id, ev_cut)).rowcount
        else:
            rows = conn.execute(
                "DELETE FROM security_events WHERE ts<? AND id NOT IN "
                "(SELECT o.event_id FROM alert_occurrences o WHERE "
                "o.event_id<>'')", (ev_cut,)).rowcount
        counts["security_events"] = rows
        if project_id:
            rows = conn.execute(
                "DELETE FROM notification_attempts WHERE ts<? AND "
                "notification_id IN (SELECT id FROM notifications WHERE "
                "project_id=?)", (at_cut, project_id)).rowcount
        else:
            rows = conn.execute(
                "DELETE FROM notification_attempts WHERE ts<?", (at_cut,)
            ).rowcount
        counts["notification_attempts"] = rows
        if project_id:
            rows = conn.execute(
                "DELETE FROM scheduler_executions WHERE project_id=? AND "
                "created_at<?", (project_id, ex_cut)).rowcount
        else:
            rows = conn.execute(
                "DELETE FROM scheduler_executions WHERE created_at<?",
                (ex_cut,)).rowcount
        counts["scheduler_executions"] = rows
    if sum(counts.values()):
        try:
            svc.audit("retention.sweep", object_type="project",
                      object_id=(project_id or "all"), actor=actor,
                      metadata={"window": f"{event_days}d/{attempt_days}d/"
                                          f"{exec_days}d", **counts})
        except Exception:
            pass
    return counts
