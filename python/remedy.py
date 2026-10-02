#!/usr/bin/env python3
# ============================================================================
#  remedy.py — Phase 5 remediation lifecycle + verification scans.
#  ---------------------------------------------------------------------------
#  - Remediation tickets are provider-neutral records OVER the existing
#    Phase-1 finding / Phase-4 remediation-group concepts (no second
#    ticketing platform, no team subsystem).
#  - Status machine is centralized (models.REMEDIATION_TRANSITIONS); invalid
#    transitions fail closed; every user-driven change is audited + recorded
#    in remediation_history (assignments, status, due dates, verification).
#  - SLA due dates are DETERMINISTIC from priority + explicit configurable
#    hours (DEFAULT_SLA_HOURS, per-project override). No regulatory claims.
#  - Verification NEVER marks a finding resolved: a "ready" ticket queues a
#    REAL scan through the existing Phase-3 job queue; on completion the
#    Phase-4 observation provenance decides passed/failed (a reappearance of
#    the same fingerprint ⇒ failed + reopened; absence ⇒ passed). The
#    finding's own lifecycle is left to the Phase-4 pipeline.
#  - Idempotent: one ticket per finding (UNIQUE), one verification request
#    per (ticket, scan), on_scan_completed processes each request once.
#  - Secrets never appear in tickets, history or audit payloads.
# ============================================================================

from __future__ import annotations

import re
import time

import errors
import metrics
import models
import redact
import store

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
VERIFY_REQUEST_LIMIT = 10      # per ticket+actor per window
VERIFY_REQUEST_WINDOW = 300    # seconds
MAX_TICKET_HISTORY = 100
MAX_VERIFICATION_ATTEMPTS = 3
LIST_LIMIT_MAX = 500
_HOURS_INT_RE = re.compile(r"^\d{1,4}$")


def _epoch(ts: str) -> float:
    try:
        import time
        return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def _iso(ep: float) -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


def _add_hours(ts: str, hours: float) -> str:
    return _iso(_epoch(ts) + float(hours) * 3600)


class RemediationService:
    """Remediation tickets, SLA due dates and evidence-based verification."""

    def __init__(self, platform, *, registry=None, jobs=None, limiter=None,
                 max_attempts: int = MAX_VERIFICATION_ATTEMPTS):
        self.svc = platform
        self.db = platform.db
        self._registry_obj = registry
        self._jobs_obj = jobs
        self.limiter = limiter
        self.max_attempts = int(max_attempts)

    def _acquire(self, key: str, limit: int, window: int) -> None:
        """Rate-limit gate for user-driven remediation operations."""
        if self.limiter is None:
            import identity as _id
            self.limiter = _id.RateLimiter()
        ok, retry = self.limiter.allowed(key, limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"rate_limited: retry after {retry}s ({limit}/{window}s)")

    # ------------------------------------------------------------ SLA
    def sla_get(self, project_id: str) -> dict:
        """Explicit SLA configuration (hours per priority) for a project."""
        self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT sla_json FROM remediation_sla WHERE project_id=? LIMIT 1",
            (project_id,))
        overrides = {}
        if rows:
            overrides = store.loads(rows[0].get("sla_json", "{}"))
            overrides = {k: v for k, v in overrides.items()
                         if k in _PRIORITIES and isinstance(v, (int, float))
                         and 1 <= float(v) <= 8760}
        out = dict(models.DEFAULT_SLA_HOURS)
        out.update(overrides)
        return out

    def sla_set(self, project_id: str, *, priority: str, hours: float,
                actor: str = "cli") -> dict:
        self.svc.project_require(project_id)
        project = self.svc.project_get(project_id)
        priority = str(priority or "").strip().upper()
        if priority not in _PRIORITIES:
            raise errors.ValidationError(
                f"priority_unknown: {priority!r} (use P0..P4)")
        if not _HOURS_INT_RE.match(str(hours)) or not 1 <= int(hours) <= 8760:
            raise errors.ValidationError(
                "sla_rejected: hours must be 1..8760")
        current = self.sla_get(project_id)
        current[str(priority)] = int(hours)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO remediation_sla (project_id, org_id, sla_json, "
                "updated_at) VALUES (?,?,?,?) ON CONFLICT(project_id) DO "
                "UPDATE SET sla_json=excluded.sla_json, "
                "updated_at=excluded.updated_at",
                (project_id, project.org_id, store.dumps(current),
                 models.utcnow()))
        self.svc.audit("remediation.sla.updated", object_type="project",
                       object_id=project_id, org_id=project.org_id,
                       project_id=project_id, actor=actor,
                       metadata={"priority": priority, "hours": int(hours)})
        return self.sla_get(project_id)

    # ---------------------------------------------------------- tickets
    def ensure(self, finding_id: str, *, actor: str = "cli",
               due_at: str = "") -> dict:
        """Create (idempotent) the remediation ticket for a finding."""
        finding = self.svc.finding_get(finding_id)
        project = self.svc.project_get(finding.project_id)
        ticket_id = models.stable_id(
            models.NS_TICKET, f"{finding.project_id}|{finding_id}|remed-v1")
        existing = self.db.query("SELECT * FROM remediation_tickets WHERE "
                                 "id=? LIMIT 1", (ticket_id,))
        if existing:
            return dict(existing[0])
        group_id = ""
        g = self.db.query(
            "SELECT group_id FROM remediation_group_findings WHERE "
            "finding_id=? LIMIT 1", (finding_id,))
        if g:
            group_id = g[0]["group_id"]
        priority = str(getattr(finding, "priority", "") or "P4").upper()
        if priority not in _PRIORITIES:
            priority = "P4"
        sla = self.sla_get(finding.project_id)
        created = models.utcnow()
        if not _ISO_RE.match(str(due_at)):
            due_at = _add_hours(created, float(sla.get(priority, 720)))
        with self.db.transaction() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO remediation_tickets (id, project_id, "
                "org_id, finding_id, remediation_group_id, title, owner_type, "
                "owner_id, owner_name, status, priority, due_at, created_at, "
                "updated_at, resolved_at, verification_status, "
                "verification_scan_id, verification_attempts) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ticket_id, finding.project_id, project.org_id, finding_id,
                 group_id, str(finding.title)[:200], "", "", "", "open",
                 priority, due_at, created, created, "", "pending", "", 0))
            if cur.rowcount != 1:
                returns = self.db.query(
                    "SELECT * FROM remediation_tickets WHERE id=? LIMIT 1",
                    (ticket_id,))
                return dict(returns[0]) if returns else {}
            conn.execute(
                "INSERT INTO remediation_history (id, ticket_id, actor, "
                "action, ts, detail) VALUES (?,?,?,?,?,?)",
                (models.stable_id(models.NS_THIST,
                                  f"{ticket_id}|created|{created}"),
                 ticket_id, str(actor)[:80], "created", created,
                 store.dumps({"priority": priority, "due_at": due_at})))
        metrics.inc("remediations_opened")
        self.svc.audit("remediation.created", object_type="remediation",
                       object_id=ticket_id, org_id=project.org_id,
                       project_id=finding.project_id, actor=actor,
                       metadata={"finding_id": finding_id,
                                 "priority": priority, "due_at": due_at})
        return dict(self.db.query(
            "SELECT * FROM remediation_tickets WHERE id=? LIMIT 1",
            (ticket_id,))[0])

    def _ticket(self, ticket_id: str) -> dict:
        rows = self.db.query("SELECT * FROM remediation_tickets WHERE id=? "
                             "LIMIT 1", (ticket_id,))
        if not rows:
            raise errors.NotFoundError("remediation ticket not found")
        return dict(rows[0])

    def _history(self, ticket_id: str, action: str, actor: str,
                 detail: dict) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO remediation_history (id, ticket_id, actor, "
                "action, ts, detail) VALUES (?,?,?,?,?,?)",
                (models.stable_id(
                    models.NS_THIST,
                    f"{ticket_id}|{action}|{models.utcnow()}|"
                    f"{time.monotonic_ns()}"),
                 ticket_id, str(actor)[:80], action, models.utcnow(),
                 store.dumps(redact.redact(dict(detail)))))

    # ------------------------------------------------------ assignment
    def assign(self, ticket_id: str, owner_type: str, owner_id: str, *,
               actor: str = "cli") -> dict:
        ticket = self._ticket(ticket_id)
        if str(owner_type).strip().lower() not in models.REMEDY_OWNER_TYPES:
            raise errors.ValidationError(
                "owner_unknown: only 'user' ownership exists (no team "
                "subsystem — assignment refused rather than invented)")
        rows = self.db.query(
            "SELECT id, username FROM users WHERE id=? AND org_id=? LIMIT 1",
            (str(owner_id), ticket["org_id"]))
        if not rows:
            raise errors.ValidationError(
                "owner_unknown: user does not exist in this organization")
        owner_name = rows[0].get("username", "") or str(owner_id)[:64]
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE remediation_tickets SET owner_type='user', owner_id=?,"
                " owner_name=?, status=CASE WHEN status IN ('open','blocked',"
                "'reopened','in_progress') THEN 'assigned' ELSE status END, "
                "updated_at=? WHERE id=?", (str(owner_id), str(owner_name)[:80],
                                            models.utcnow(), ticket_id))
        out = self._ticket(ticket_id)
        self._history(ticket_id, "assigned", actor,
                      {"owner_id": str(owner_id)[:64],
                       "owner_name": owner_name,
                       "from_status": ticket["status"],
                       "to_status": out["status"]})
        self.svc.audit("remediation.assigned", object_type="remediation",
                       object_id=ticket_id, org_id=ticket["org_id"],
                       project_id=ticket["project_id"], actor=actor,
                       metadata={"owner_id": str(owner_id)[:64],
                                 "owner_name": owner_name})
        return out

    # -------------------------------------------------------- lifecycle
    def status(self, ticket_id: str, new_status: str, *,
               actor: str = "cli", reason: str = "") -> dict:
        ticket = self._ticket(ticket_id)
        new_status = str(new_status or "").strip()
        if new_status not in models.REMEDIATION_STATUSES:
            raise errors.ValidationError(
                f"remediation_status_unknown: {new_status!r}")
        old = ticket["status"]
        if old == new_status:
            return ticket  # idempotent no-op
        if new_status not in models.REMEDIATION_TRANSITIONS.get(old, set()):
            raise errors.LifecycleError(
                f"validation_rejected: remediation {old} → {new_status} is "
                f"not a legal transition")
        now = models.utcnow()
        self.db.execute(
            "UPDATE remediation_tickets SET status=?, updated_at=?, "
            "resolved_at=CASE WHEN ?='closed' THEN ? ELSE resolved_at END "
            "WHERE id=?", (new_status, now, new_status, now, ticket_id))
        out = self._ticket(ticket_id)
        self._history(ticket_id, "status", actor,
                      {"from": old, "to": new_status,
                       "reason": redact.redact_text(str(reason))[:200]})
        self.svc.audit("remediation.status_changed",
                       object_type="remediation", object_id=ticket_id,
                       org_id=ticket["org_id"],
                       project_id=ticket["project_id"], actor=actor,
                       metadata={"from": old, "to": new_status,
                                 "reason": redact.redact_text(
                                     str(reason))[:200]})
        return out

    def set_due(self, ticket_id: str, due_at: str, *, actor: str = "cli") -> dict:
        ticket = self._ticket(ticket_id)
        if not _ISO_RE.match(str(due_at)):
            raise errors.ValidationError(
                "due_rejected: expected ISO timestamp")
        self.db.execute("UPDATE remediation_tickets SET due_at=?, "
                        "updated_at=? WHERE id=?",
                        (str(due_at), models.utcnow(), ticket_id))
        self._history(ticket_id, "due_changed", actor,
                      {"from": ticket["due_at"], "to": str(due_at)})
        self.svc.audit("remediation.due_changed", object_type="remediation",
                       object_id=ticket_id, org_id=ticket["org_id"],
                       project_id=ticket["project_id"], actor=actor,
                       metadata={"from": ticket["due_at"],
                                 "to": str(due_at)})
        return self._ticket(ticket_id)

    # ------------------------------------------------------ verification
    def _registry(self):
        if self._registry_obj is None:
            import scanners as _sc
            self._registry_obj = _sc.REGISTRY
        return self._registry_obj

    def _jobs(self):
        if self._jobs_obj is None:
            import jobs as _jb
            self._jobs_obj = _jb.JobService(self.svc, self._registry())
        return self._jobs_obj

    def request_verification(self, ticket_id: str, *, actor: str = "cli") -> dict:
        """Queue a REAL verification scan through the Phase-3 job queue."""
        self._acquire(f"remedy:verify:{ticket_id}:{actor}",
                      VERIFY_REQUEST_LIMIT, VERIFY_REQUEST_WINDOW)
        ticket = self._ticket(ticket_id)
        project = self.svc.project_get(ticket["project_id"])
        if ticket["status"] != "ready_for_verification":
            raise errors.LifecycleError(
                "validation_rejected: ticket must be "
                "ready_for_verification before verification")
        if int(ticket.get("verification_attempts") or 0) >= self.max_attempts:
            raise errors.LifecycleError(
                "validation_rejected: verification attempts exhausted")
        if ticket.get("verification_status") == "running":
            # Idempotent recovery: if the verification scan + job for this
            # ticket already exist, return the in-flight verification
            # instead of queueing a duplicate.
            reqs = self.db.query(
                "SELECT * FROM verification_requests WHERE ticket_id=? AND "
                "status IN ('pending','running') ORDER BY rowid DESC LIMIT 1",
                (ticket_id,))
            if reqs:
                out = self._ticket(ticket_id)
                out["verification_scan_id"] = reqs[0]["scan_id"]
                out["verification_request_id"] = reqs[0]["id"]
                return out
            raise errors.LifecycleError(
                "validation_rejected: verification already in progress")
        # find the original scan profile (evidence-based, deterministic)
        profile = "web-audit"
        rows = self.db.query(
            "SELECT s.profile FROM scans s JOIN findings f ON f.scan_id=s.id "
            "WHERE f.id=? LIMIT 1", (ticket["finding_id"],))
        if rows:
            profile = rows[0]["profile"]
        try:
            profile = self._registry().validate_profile(profile)
        except errors.ValidationError:
            profile = "web-audit"
        if profile in self._registry().ACTIVE_PROFILES:
            raise errors.LifecycleError(
                "validation_rejected: active profiles are never used for "
                "verification scans")
        asset_rows = self.db.query(
            "SELECT value FROM assets WHERE id=? LIMIT 1",
            (ticket.get("finding_id") and self._finding_asset(ticket),))
        target = asset_rows[0]["value"] if asset_rows else ""
        if not target:
            raise errors.ValidationError(
                "verification_rejected: finding has no target asset")
        attempt = int(ticket.get("verification_attempts") or 0) + 1
        scan_id = models.stable_id(models.NS_VSCAN,
                                   f"{ticket_id}|verification|{attempt}")
        try:
            scan = self.svc.scan_create(
                project.id, profile, scope_ref=f"verification:{ticket_id}",
                initiator={"actor": str(actor)[:80], "purpose": "verification",
                           "ticket_id": ticket_id},
                scan_id=scan_id)
        except Exception as e:
            if "UNIQUE" in str(e):
                pass  # idempotent re-request after a crash
            else:
                raise errors.PersistenceError(
                    f"verification scan failed: {e}") from e
        try:
            job = self._jobs().create_job(
                scan_id, profile, {"target": target},
                job_type="verification", priority="high",
                max_attempts=2, timeout_seconds=600,
                actor=str(actor)[:80], actor_id="", queue_now=True)
        except Exception as e:
            self.svc.scan_set_error(
                scan_id, "verification_job_failed", str(e)[:200])
            raise errors.PersistenceError(
                f"verification job failed: {e}") from e
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO verification_requests (id, ticket_id, "
                "scan_id, requested_by, requested_at, completed_at, status, "
                "note) VALUES (?,?,?,?,?,?,?,?)",
                (models.stable_id(models.NS_VSCAN,
                                  f"{ticket_id}|{scan_id}"),
                 ticket_id, scan_id, str(actor)[:80], models.utcnow(), "",
                 "pending", ""))
            conn.execute(
                "UPDATE remediation_tickets SET verification_status='running',"
                " verification_scan_id=?, verification_attempts=?, "
                "updated_at=? WHERE id=?",
                (scan_id, attempt, models.utcnow(), ticket_id))
        self._history(ticket_id, "verification_requested", actor,
                      {"scan_id": scan_id, "profile": profile,
                       "attempt": attempt})
        self.svc.audit("remediation.verification_requested",
                       object_type="remediation", object_id=ticket_id,
                       org_id=ticket["org_id"],
                       project_id=ticket["project_id"], actor=actor,
                       metadata={"scan_id": scan_id, "profile": profile,
                                 "target": redact.redact_text(target)[:120]})
        metrics.inc("verification_scans")
        out = self._ticket(ticket_id)
        out["verification_scan_id"] = scan_id
        return out

    def _finding_asset(self, ticket: dict) -> str:
        rows = self.db.query("SELECT asset_id FROM findings WHERE id=? "
                             "LIMIT 1", (ticket["finding_id"],))
        return rows[0]["asset_id"] if rows else ""

    def on_scan_failed(self, project_id: str, scan_id: str,
                       error: str = "") -> int:
        """Verification job FAILED (infra error, not evidence). The ticket
        returns to ready_for_verification so the operator can retry; the
        attempt was already counted at request time (bounded by
        max_attempts) — no retry loop is possible from this hook."""
        reqs = self.db.query(
            "SELECT * FROM verification_requests WHERE scan_id=? AND status "
            "IN ('pending','running') LIMIT ?", (scan_id, 5))
        n = 0
        now = models.utcnow()
        for req in reqs:
            with self.db.transaction() as conn:
                cur = conn.execute(
                    "UPDATE verification_requests SET status=?, "
                    "completed_at=?, note=? WHERE id=? AND status IN "
                    "('pending','running')",
                    ("failed", now, f"scan job failed: {str(error)[:120]}",
                     req["id"]))
                if cur.rowcount != 1:
                    continue
                conn.execute(
                    "UPDATE remediation_tickets SET verification_status="
                    "'failed', status='ready_for_verification', updated_at=? "
                    "WHERE id=? AND status='ready_for_verification'",
                    (now, req["ticket_id"]))
            n += 1
            metrics.inc("monitoring_health_failures")
        return n

    def on_scan_completed(self, project_id: str, scan_id: str) -> int:
        """Verification resolution: evidence-based, idempotent."""
        reqs = self.db.query(
            "SELECT * FROM verification_requests WHERE scan_id=? AND status "
            "IN ('pending','running') LIMIT ?", (scan_id, 5))
        n = 0
        for req in reqs:
            if self._resolve_verification(dict(req)):
                n += 1
        return n

    def _resolve_verification(self, req: dict) -> bool:
        ticket = self._ticket(req["ticket_id"])
        rows = self.db.query(
            "SELECT 1 FROM finding_observations WHERE finding_id=? AND "
            "scan_id=? LIMIT 1", (ticket["finding_id"], req["scan_id"]))
        reappeared = bool(rows)
        now = models.utcnow()
        with self.db.transaction() as conn:
            cur = conn.execute(
                "UPDATE verification_requests SET status=?, completed_at=?, "
                "note=? WHERE id=? AND status IN ('pending','running')",
                ("failed" if reappeared else "passed", now,
                 "same fingerprint re-observed" if reappeared else
                 "fingerprint not re-observed", req["id"]))
            if cur.rowcount != 1:
                return False  # idempotent: already resolved
            if reappeared:
                conn.execute(
                    "UPDATE remediation_tickets SET verification_status="
                    "'failed', status='reopened', updated_at=? WHERE id=?",
                    (now, ticket["id"]))
            else:
                conn.execute(
                    "UPDATE remediation_tickets SET verification_status="
                    "'passed', status='verified', resolved_at=?, "
                    "updated_at=? WHERE id=?", (now, now, ticket["id"]))
        out = self._ticket(ticket["id"])
        self._history(ticket["id"], "verification_result", "worker",
                      {"passed": not reappeared, "scan_id": req["scan_id"]})
        self.svc.audit("remediation.verification_result",
                       object_type="remediation",
                       object_id=ticket["id"], org_id=ticket["org_id"],
                       project_id=ticket["project_id"], actor="worker",
                       metadata={"passed": not reappeared,
                                 "scan_id": req["scan_id"]})
        if reappeared:
            metrics.inc("remediations_reopened")
        else:
            metrics.inc("remediations_verified")
        try:
            from alerts import pipeline_event
            pipeline_event(
                self.svc, project_id=ticket["project_id"],
                event_type=("monitoring.verification_failure" if reappeared
                            else "monitoring.verification_passed"),
                asset_id=self._finding_asset(ticket),
                key=f"ticket|{ticket['id']}", scan_id=req["scan_id"],
                previous_state={"verification_status":
                                ticket.get("verification_status", "")},
                new_state={"status": out["status"],
                           "verification_status":
                               out.get("verification_status", "")},
                source="verification", confidence=0.8, actor="worker")
        except Exception:
            pass
        return True

    # ------------------------------------------------------------- reads
    def view(self, ticket_id: str, *, history_limit: int = 50) -> dict:
        t = self._ticket(ticket_id)
        t["history"] = [dict(h) for h in self.db.query(
            "SELECT * FROM remediation_history WHERE ticket_id=? ORDER BY "
            "ts DESC, id DESC LIMIT ?", (ticket_id,
                                         min(max(int(history_limit), 1),
                                             MAX_TICKET_HISTORY)))]
        for h in t["history"]:
            h["detail"] = store.loads(h.get("detail", "{}"))
        t["sla"] = self.sla_get(t["project_id"])
        return t

    def list_tickets(self, project_id: str, *, status: str = "",
                     limit: int = 100) -> list[dict]:
        self.svc.project_require(project_id)
        limit = min(max(int(limit), 1), LIST_LIMIT_MAX)
        if status:
            if status not in models.REMEDIATION_STATUSES:
                raise errors.ValidationError(
                    f"remediation_status_unknown: {status!r}")
            rows = self.db.query(
                "SELECT * FROM remediation_tickets WHERE project_id=? AND "
                "status=? ORDER BY due_at, created_at LIMIT ?",
                (project_id, status, limit))
        else:
            rows = self.db.query(
                "SELECT * FROM remediation_tickets WHERE project_id=? "
                "ORDER BY due_at, created_at LIMIT ?", (project_id, limit))
        return [dict(r) for r in rows]

    def list_verifications(self, project_id: str, *, limit: int = 100,
                           status: str = "") -> list[dict]:
        self.svc.project_require(project_id)
        limit = min(max(int(limit), 1), LIST_LIMIT_MAX)
        if status:
            if status not in models.VERIFICATION_STATUSES:
                raise errors.ValidationError(
                    f"verification_status_unknown: {status!r}")
            rows = self.db.query(
                "SELECT v.*, t.finding_id FROM verification_requests v JOIN "
                "remediation_tickets t ON t.id=v.ticket_id WHERE "
                "t.project_id=? AND v.status=? ORDER BY v.requested_at DESC "
                "LIMIT ?", (project_id, status, limit))
        else:
            rows = self.db.query(
                "SELECT v.*, t.finding_id FROM verification_requests v JOIN "
                "remediation_tickets t ON t.id=v.ticket_id WHERE "
                "t.project_id=? ORDER BY v.requested_at DESC LIMIT ?",
                (project_id, limit))
        return [dict(r) for r in rows]
