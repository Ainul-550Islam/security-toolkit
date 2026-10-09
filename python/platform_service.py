#!/usr/bin/env python3
# ============================================================================
#  platform_service.py — PlatformService: the Phase-1 domain service layer.
#  ---------------------------------------------------------------------------
#  Ties together models + scope + evidence sanitization + persistence +
#  audit logging. It OWNS every write path so that:
#    - all evidence/audit data passes centralized redaction,
#    - scan/finding lifecycle transitions are validated,
#    - asset normalization and finding fingerprints are deterministic,
#    - every state change produces a sanitized audit event,
#    - raw scanner payloads are preserved verbatim.
#
#  This is the ONLY module the workflow/scanner integrations talk to.
#
#  ── MODULE NAMING (PART 01) ────────────────────────────────────────────────
#  This module was previously named `python/platform.py`, which SHADOWED the
#  Python standard-library `platform` module for every process that put
#  `python/` on sys.path. Under that shadowing, `platform.system()` and the
#  rest of the stdlib API were unreachable, so any dependency performing the
#  ordinary `import platform; platform.system()` would fail with
#  AttributeError. The module is now `platform_service.py`; `import platform`
#  resolves to the standard library again, everywhere, deterministically.
#
#  `python/platform.py` remains ONLY as a thin deprecation shim re-exporting
#  this module for backward compatibility. New code MUST import
#  `platform_service`. See tests/test_foundation_runtime.py.
# ============================================================================

from __future__ import annotations

import hashlib
import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from services.database import DatabaseService
from services.migrations import MigrationRunner

import errors
import models
import normalize
import redact
import scope as scope_mod
import sec_config
import store


class PlatformService:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or sec_config.platform_db_path()
        backend = store.Database(self.db_path)
        self.db = DatabaseService(backend)
        self.migration_report = MigrationRunner(
            self.db, expected_version=len(store.MIGRATIONS)
        ).run()

    # ------------------------------------------------------------------ org
    def org_create(self, name: str) -> models.Organization:
        org = models.Organization(name=name)
        org.finalize()
        try:
            self.db.execute(
                "INSERT INTO organizations (id, name, status, created_at, "
                "updated_at) VALUES (?,?,?,?,?)",
                (org.id, org.name, org.status, org.created_at, org.updated_at))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise errors.DuplicateError(
                    f"Organization already exists: {org.name}") from e
            raise errors.PersistenceError(f"org create failed: {e}") from e
        self.audit("organization.created", object_type="organization",
                   object_id=org.id, org_id=org.id,
                   metadata={"name": org.name})
        return org

    def org_get(self, org_id: str) -> models.Organization:
        row = self._one("organizations", org_id, "organization")
        return models.Organization.from_dict(row)

    def org_list(self) -> list[models.Organization]:
        rows = self.db.query(
            "SELECT * FROM organizations ORDER BY created_at DESC", limit=1000)
        return [models.Organization.from_dict(r) for r in rows]

    def org_require(self, org_id: str) -> None:
        self.org_get(org_id)

    # ------------------------------------------------------------- project
    def project_create(self, org_id: str, name: str, description: str = "",
                       scope_policy: dict | None = None,
                       actor: str = "cli") -> models.Project:
        self.org_require(org_id)
        proj = models.Project(org_id=org_id, name=name, description=description,
                              scope_policy=dict(scope_policy or {}))
        proj.finalize()
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO projects (id, org_id, name, description, "
                    "status, scope_json, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (proj.id, proj.org_id, proj.name, proj.description,
                     proj.status, store.dumps(proj.scope_policy),
                     proj.created_at, proj.updated_at))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise errors.DuplicateError(
                    f"Project already exists in org: {name}") from e
            raise errors.PersistenceError(f"project create failed: {e}") from e
        self.audit("project.created", object_type="project", object_id=proj.id,
                   org_id=proj.org_id, project_id=proj.id, actor=actor,
                   metadata={"name": proj.name})
        return proj

    def project_get(self, project_id: str) -> models.Project:
        row = self._one("projects", project_id, "project")
        row["scope_policy"] = store.loads(row.pop("scope_json", "{}"))
        return models.Project.from_dict(row)

    def project_list(self, org_id: str | None = None) -> list[models.Project]:
        if org_id:
            self.org_require(org_id)
            rows = self.db.query(
                "SELECT * FROM projects WHERE org_id=? ORDER BY created_at DESC",
                (org_id,), limit=1000)
        else:
            rows = self.db.query(
                "SELECT * FROM projects ORDER BY created_at DESC", limit=1000)
        out = []
        for r in rows:
            r["scope_policy"] = store.loads(r.pop("scope_json", "{}"))
            out.append(models.Project.from_dict(r))
        return out

    def project_require(self, project_id: str) -> models.Project:
        return self.project_get(project_id)

    # --------------------------------------------------------------- scope
    def scope_set(self, project_id: str, allow, deny, *,
                  actor: str = "cli") -> dict:
        self.project_require(project_id)
        project = self.project_get(project_id)
        policy = scope_mod.ScopePolicy(allow, deny,
                                       name=f"project:{project_id}")
        data = policy.to_dict()
        with self.db.transaction() as conn:
            conn.execute("UPDATE projects SET scope_json=?, updated_at=? "
                         "WHERE id=? AND org_id=?",
                         (store.dumps(data), models.utcnow(), project_id,
                          project.org_id))
        self.audit("scope.changed", object_type="project", object_id=project_id,
                   org_id=project.org_id, project_id=project_id, actor=actor,
                   metadata={"scope": data})
        return data

    def scope_get(self, project_id: str) -> scope_mod.ScopePolicy:
        proj = self.project_require(project_id)
        return scope_mod.ScopePolicy.from_dict(proj.scope_policy,
                                               name=f"project:{project_id}")

    def scope_check(self, project_id: str, target: str) -> dict:
        policy = self.scope_get(project_id)
        in_scope, reason = policy.is_in_scope(target), ""
        if not in_scope:
            reason = "denied or not allowed"
        self.audit("scope.checked" if in_scope else "scope.denied",
                   object_type="project", object_id=project_id,
                   project_id=project_id,
                   metadata={"target": str(target)[:300], "result": reason})
        return {"in_scope": in_scope, "target": target, "reason": reason}

    # ---------------------------------------------------------------- asset
    def asset_add(self, project_id: str, asset_type: str, value: str,
                  metadata: dict | None = None, display: str = "",
                  actor: str = "cli") -> models.Asset:
        self.project_require(project_id)
        asset = models.Asset(project_id=project_id, asset_type=asset_type,
                             value=value, display=display,
                             metadata=dict(metadata or {}))
        asset.finalize()
        try:
            self.db.execute(
                "INSERT OR IGNORE INTO assets (id, project_id, asset_type, "
                "value, display, metadata, status, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (asset.id, asset.project_id, asset.asset_type, asset.value,
                 asset.display, store.dumps(asset.metadata), asset.status,
                 asset.first_seen, asset.last_seen))
        except Exception as e:
            raise errors.PersistenceError(f"asset add failed: {e}") from e
        self.audit("asset.created", object_type="asset", object_id=asset.id,
                   project_id=project_id, actor=actor,
                   metadata={"asset_type": asset.asset_type,
                             "value": asset.value})
        return asset

    def asset_get(self, asset_id: str) -> models.Asset:
        row = self._one("assets", asset_id, "asset")
        row["metadata"] = store.loads(row.get("metadata", "{}"))
        return models.Asset.from_dict(row)

    def asset_list(self, project_id: str, asset_type: str | None = None,
                   limit: int = 500) -> list[models.Asset]:
        self.project_require(project_id)
        if asset_type:
            rows = self.db.query(
                "SELECT * FROM assets WHERE project_id=? AND asset_type=? "
                "ORDER BY last_seen DESC", (project_id, asset_type), limit=limit)
        else:
            rows = self.db.query(
                "SELECT * FROM assets WHERE project_id=? ORDER BY last_seen DESC",
                (project_id,), limit=limit)
        out = []
        for r in rows:
            r["metadata"] = store.loads(r.get("metadata", "{}"))
            out.append(models.Asset.from_dict(r))
        return out

    # ----------------------------------------------------------------- scan
    def scan_create(self, project_id: str, profile: str,
                    scope_ref: str = "", initiator: dict | None = None,
                    scan_id: str = "", actor: str = "cli") -> models.Scan:
        self.project_require(project_id)
        scan = models.Scan(project_id=project_id, profile=profile,
                           scope_ref=scope_ref, initiator=dict(initiator or {}),
                           id=scan_id)
        scan.finalize()
        if not scan.id:
            scan.id = models.stable_id(
                models.NS_SCAN,
                f"{scan.project_id}|{scan.profile}|{scan.created_at}")
        self.db.execute(
            "INSERT INTO scans (id, project_id, profile, scope_ref, status, "
            "created_at, started_at, finished_at, initiator, progress, stages, "
            "summary, error, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan.id, scan.project_id, scan.profile, scan.scope_ref,
             scan.status, scan.created_at, scan.started_at or "",
             scan.finished_at or "", store.dumps(scan.initiator), scan.progress,
             store.dumps(scan.stages), store.dumps(scan.summary),
             store.dumps(scan.error), "{}"))
        self.audit("scan.created", object_type="scan", object_id=scan.id,
                   project_id=project_id, actor=actor,
                   metadata={"profile": scan.profile})
        return scan

    def scan_get(self, scan_id: str) -> models.Scan:
        row = self._one("scans", scan_id, "scan")
        for k in ("initiator", "stages", "summary", "error", "raw"):
            row[k] = store.loads(row.get(k, ""))
        return models.Scan.from_dict(row)

    def scan_list(self, project_id: str, limit: int = 200) -> list[models.Scan]:
        self.project_require(project_id)
        rows = self.db.query(
            "SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC",
            (project_id,), limit=limit)
        out = []
        for r in rows:
            for k in ("initiator", "stages", "summary", "error", "raw"):
                r[k] = store.loads(r.get(k, ""))
            out.append(models.Scan.from_dict(r))
        return out

    def scan_transition(self, scan_id: str, new_status: str) -> models.Scan:
        scan = self.scan_get(scan_id)
        old = scan.status
        scan.transition(new_status)
        self.db.execute(
            "UPDATE scans SET status=?, started_at=?, finished_at=?, "
            "progress=? WHERE id=?",
            (scan.status, scan.started_at or "", scan.finished_at or "",
             scan.progress, scan.id))
        action = {
            "running": "scan.started", "paused": "scan.paused", "completed":
                "scan.completed", "failed": "scan.failed", "cancelled":
                "scan.cancelled", "cancelling": "scan.cancelled",
        }.get(new_status, "scan.updated")
        self.audit(action, object_type="scan", object_id=scan_id,
                   project_id=scan.project_id,
                   metadata={"from": old, "to": new_status})
        return scan

    def scan_save_raw(self, scan_id: str, raw: dict):
        scan = self.scan_get(scan_id)
        safe = redact.redact(raw)
        self.db.execute("UPDATE scans SET raw=? WHERE id=?",
                        (store.dumps(safe), scan_id))
        if isinstance(safe.get("summary"), dict):
            self.scan_update_summary(scan_id, safe.get("summary"))
        return scan

    def scan_update_summary(self, scan_id: str, summary: dict, progress: float | None = None):
        self.db.execute("UPDATE scans SET summary=?, progress=? WHERE id=?",
                        (store.dumps(dict(summary or {})),
                         float(progress) if progress is not None else 0.0,
                         scan_id))

    def scan_set_progress(self, scan_id: str, progress: float) -> None:
        """Deterministic progress (stages completed / total stages)."""
        self.db.execute("UPDATE scans SET progress=? WHERE id=?",
                        (min(1.0, max(0.0, float(progress))), scan_id))

    def scan_set_error(self, scan_id: str, code: str, message: str) -> None:
        self.db.execute("UPDATE scans SET error=? WHERE id=?",
                        (store.dumps({"code": str(code)[:64],
                                      "message": str(message)[:500]}),
                         scan_id))

    # -------------------------------------------------------- stage checkpoints
    def scan_stage_record(self, stage: models.StageRecord) -> models.StageRecord:
        """Upsert one persisted stage-checkpoint (idempotent per scan+stage)."""
        stage.finalize()
        self.db.upsert("scan_stages", {
            "id": stage.id, "scan_id": stage.scan_id, "job_id": stage.job_id,
            "stage": stage.stage, "status": stage.status,
            "attempt": stage.attempt, "created_at": stage.created_at,
            "started_at": stage.started_at, "finished_at": stage.finished_at,
            "result_reference": stage.result_reference,
            "error_code": stage.error_code,
            "error_message": stage.error_message})
        return stage

    def scan_stage_get(self, scan_id: str, stage: str) -> models.StageRecord | None:
        rows = self.db.query(
            "SELECT * FROM scan_stages WHERE scan_id=? AND stage=? LIMIT 1",
            (scan_id, stage))
        return models.StageRecord.from_dict(rows[0]) if rows else None

    def scan_stage_list(self, scan_id: str) -> list[models.StageRecord]:
        rows = self.db.query(
            "SELECT * FROM scan_stages WHERE scan_id=? ORDER BY created_at, id",
            (scan_id,))
        return [models.StageRecord.from_dict(r) for r in rows]

    def scan_progress(self, scan_id: str, stage_names: list[str]) -> float:
        """Simple weighted-by-count progress over the profile's stages."""
        if not stage_names:
            return 0.0
        done = self.db.query(
            "SELECT stage FROM scan_stages WHERE scan_id=? AND status=?",
            (scan_id, "completed"))
        completed = {r["stage"] for r in done}
        return len([s for s in stage_names if s in completed]) / len(stage_names)

    # -------------------------------------------------------------- finding
    def finding_ingest(self, finding: models.Finding,
                       evidence: list[models.Evidence] | None = None) -> models.Finding:
        """Insert or update a finding by deterministic id (dedup foundation).
        Existing finding re-detected: last_detected refreshed; lifecycle kept.
        New finding: lifecycle 'open' + full evidence."""
        finding.finalize()
        existing = None
        try:
            existing = self.finding_get(finding.id)
        except errors.NotFoundError:
            pass
        now = models.utcnow()
        if existing:
            existing.last_detected = now
            existing.raw = finding.raw
            existing.asset_id = existing.asset_id or finding.asset_id
            if existing.lifecycle not in ("resolved", "false_positive",
                                          "accepted_risk"):
                existing.title = finding.title or existing.title
                existing.remediation = finding.remediation or existing.remediation
            self.db.execute(
                "UPDATE findings SET last_detected=?, raw=?, asset_id=?, "
                "title=?, remediation=? WHERE id=?",
                (now, store.dumps(redact.redact(existing.raw)),
                 existing.asset_id or None, existing.title,
                 existing.remediation, existing.id))
            return existing
        evidence_records = []
        for ev in (evidence or []):
            ev.finding_id = finding.id
            ev.finalize()
            evidence_records.append(ev)
        self.db.execute(
            "INSERT INTO findings (id, scan_id, project_id, asset_id, title, "
            "description, severity, confidence, category, source, rule_id, "
            "template_id, cwe, cve, cvss, remediation, evidence, raw, "
            "lifecycle, fingerprint, first_detected, last_detected, resolved_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (finding.id, finding.scan_id, finding.project_id,
             finding.asset_id or None,     # '' would violate the FK
             finding.title, finding.description, finding.severity,
             finding.confidence, finding.category, finding.source,
             finding.rule_id, finding.template_id, finding.cwe, finding.cve,
             store.dumps(finding.cvss), finding.remediation,
             store.dumps([e.to_dict() for e in evidence_records]),
             store.dumps(redact.redact(finding.raw)), finding.lifecycle,
             finding.fingerprint, finding.first_detected, finding.last_detected,
             finding.resolved_at or ""))
        for ev in evidence_records:
            self.db.execute(
                "INSERT OR IGNORE INTO evidence (id, finding_id, evidence_type, "
                "url, method, status_code, request_snippet, response_snippet, "
                "detection_reason, scanner, rule_id, captured_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ev.id, ev.finding_id, ev.evidence_type, ev.url, ev.method,
                 ev.status_code, ev.request_snippet, ev.response_snippet,
                 ev.detection_reason, ev.scanner, ev.rule_id, ev.captured_at))
        self.audit("finding.created", object_type="finding",
                   object_id=finding.id, project_id=finding.project_id,
                   metadata={"severity": finding.severity,
                             "title": str(finding.title)[:120],
                             "fingerprint": finding.fingerprint})
        return finding

    def finding_get(self, finding_id: str) -> models.Finding:
        row = self._one("findings", finding_id, "finding")
        for k in ("cvss", "raw"):
            row[k] = store.loads(row.get(k, "{}"))
        row["evidence"] = store.loads(row.get("evidence", "[]"), default=[])
        return models.Finding.from_dict(row)

    def finding_list(self, project_id: str, severity: str | None = None,
                     lifecycle: str | None = None, limit: int = 500) \
            -> list[models.Finding]:
        self.project_require(project_id)
        sql, params = "SELECT * FROM findings WHERE project_id=?", [project_id]
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if lifecycle:
            sql += " AND lifecycle=?"
            params.append(lifecycle)
        sql += " ORDER BY last_detected DESC"
        rows = self.db.query(sql, tuple(params), limit=limit)
        out = []
        for r in rows:
            for k in ("cvss", "raw"):
                r[k] = store.loads(r.get(k, "{}"))
            r["evidence"] = store.loads(r.get("evidence", "[]"), default=[])
            out.append(models.Finding.from_dict(r))
        return out

    def finding_set_status(self, finding_id: str, new_status: str,
                           actor: str = "cli") -> models.Finding:
        f = self.finding_get(finding_id)
        changed = f.transition(new_status)
        self.db.execute(
            "UPDATE findings SET lifecycle=?, resolved_at=?, last_detected=? "
            "WHERE id=?",
            (f.lifecycle, f.resolved_at or "", f.last_detected, f.id))
        if changed:
            self.audit("finding.status_changed", object_type="finding",
                       object_id=finding_id, project_id=f.project_id,
                       actor=actor,
                       metadata={"to": new_status})
        else:
            self.audit("finding.updated", object_type="finding",
                       object_id=finding_id, project_id=f.project_id,
                       actor=actor, metadata={"status": new_status})
        return f

    # ------------------------------------------------------------- evidence
    def evidence_add(self, finding_id: str, *, evidence_type: str, url: str = "",
                     method: str = "", status_code: str = "",
                     request_snippet: str = "", response_snippet: str = "",
                     detection_reason: str = "", scanner: str = "",
                     rule_id: str = "") -> models.Evidence:
        ev = models.Evidence(finding_id=finding_id, evidence_type=evidence_type,
                             url=url, method=method, status_code=status_code,
                             request_snippet=request_snippet,
                             response_snippet=response_snippet,
                             detection_reason=detection_reason,
                             scanner=scanner, rule_id=rule_id)
        ev.finalize()   # ← centralized sanitization happens here
        try:
            self.finding_get(finding_id)
        except errors.NotFoundError:
            raise errors.NotFoundError(
                f"Cannot attach evidence; finding {finding_id} not found") \
                from None
        self.db.execute(
            "INSERT OR IGNORE INTO evidence (id, finding_id, evidence_type, "
            "url, method, status_code, request_snippet, response_snippet, "
            "detection_reason, scanner, rule_id, captured_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev.id, ev.finding_id, ev.evidence_type, ev.url, ev.method,
             ev.status_code, ev.request_snippet, ev.response_snippet,
             ev.detection_reason, ev.scanner, ev.rule_id, ev.captured_at))
        f = self.finding_get(finding_id)
        self.audit("evidence.created", object_type="evidence", object_id=ev.id,
                   project_id=f.project_id,
                   metadata={"type": ev.evidence_type, "finding_id": finding_id})
        return ev

    def evidence_list(self, finding_id: str, limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM evidence WHERE finding_id=? ORDER BY captured_at",
            (finding_id,), limit=limit)
        return rows

    # ---------------------------------------------------------------- audit
    def audit(self, action: str, *,
              object_type: str = "", object_id: str = "",
              org_id: str = "", project_id: str = "",
              actor: str = "cli", metadata: dict | None = None):
        ev = models.AuditEvent(action=action, actor=actor,
                               object_type=object_type, object_id=object_id,
                               org_id=org_id, project_id=project_id,
                               metadata=dict(metadata or {}))
        ev.finalize()   # ← sanitize + validate + id
        try:
            prev = ""
            last = self.db.query(
                "SELECT event_hash FROM audit_events WHERE event_hash<>'' "
                "ORDER BY rowid DESC LIMIT 1")
            if last:
                prev = last[0]["event_hash"]
            event_hash = self._chain_hash(ev, prev)
            self.db.execute(
                "INSERT INTO audit_events (id, ts, action, actor, "
                "object_type, object_id, org_id, project_id, metadata, "
                "prev_hash, event_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (ev.id, ev.ts, ev.action, ev.actor, ev.object_type,
                 ev.object_id, ev.org_id, ev.project_id,
                 store.dumps(ev.metadata), prev, event_hash))
        except Exception:
            pass  # auditing must never break the primary operation
        return ev

    # ------------------------------------------------------ audit integrity
    @staticmethod
    def _chain_canonical(row: dict) -> str:
        """Deterministic canonical JSON for one audit row (sorted keys).
        Secrets can never appear: AuditEvent.sanitize() redacts metadata.
        Accepts metadata as a serialized string (DB row) or a dict
        (in-memory AuditEvent)."""
        meta = row.get("metadata", "{}")
        if isinstance(meta, str):
            meta = store.loads(meta)
        payload = {"id": row["id"], "ts": row["ts"], "action": row["action"],
                   "actor": row["actor"], "object_type": row["object_type"],
                   "object_id": row["object_id"], "org_id": row["org_id"],
                   "project_id": row["project_id"],
                   "metadata": meta}
        return json.dumps(payload, ensure_ascii=False, default=str,
                          sort_keys=True, separators=(",", ":"))

    @classmethod
    def _chain_hash(cls, event, prev_hash: str) -> str:
        row = {"id": event.id, "ts": event.ts, "action": event.action,
               "actor": event.actor, "object_type": event.object_type,
               "object_id": event.object_id, "org_id": event.org_id,
               "project_id": event.project_id,
               "metadata": event.metadata}
        canon = cls._chain_canonical(row)
        return hashlib.sha256((canon + "|" + prev_hash)
                              .encode("utf-8")).hexdigest()

    def audit_verify(self) -> dict:
        """Tamper-evidence check of the audit chain. Detects modified event
        payloads, deleted events (middle of the chain), reordered events and
        broken links. Rows written before the Phase-2 migration carry no
        hash (reported as `legacy` and not verifiable); deleting the very
        LAST event cannot be detected (no successor) — documented limit."""
        rows = self.db.query("SELECT * FROM audit_events ORDER BY rowid")
        issues: list[str] = []
        expected_prev = ""
        verified = 0
        legacy = 0
        for r in rows:
            if not r.get("event_hash"):
                legacy += 1
                continue
            if r.get("prev_hash", "") != expected_prev:
                issues.append(
                    f"chain break / missing or reordered event before "
                    f"{r['id']}")
            recomputed = hashlib.sha256(
                (self._chain_canonical(r) + "|" + r.get("prev_hash", ""))
                .encode("utf-8")).hexdigest()
            if recomputed != r.get("event_hash"):
                issues.append(f"payload modified at {r['id']}")
            expected_prev = r.get("event_hash", "")
            verified += 1
        return {"ok": not issues, "issues": issues, "verified": verified,
                "legacy": legacy, "total": len(rows)}

    def audit_list_org(self, org_id: str, limit: int = 100) \
            -> list[models.AuditEvent]:
        """Audit events scoped to one organization (tenant-safe listing)."""
        rows = self.db.query(
            "SELECT * FROM audit_events WHERE org_id=? ORDER BY rowid DESC",
            (org_id,), limit=limit)
        out = []
        for r in rows:
            r["metadata"] = store.loads(r.get("metadata", "{}"))
            out.append(models.AuditEvent.from_dict(r))
        return out

    def audit_list(self, project_id: str | None = None, limit: int = 100) \
            -> list[models.AuditEvent]:
        if project_id:
            rows = self.db.query(
                "SELECT * FROM audit_events WHERE project_id=? "
                "ORDER BY ts DESC", (project_id,), limit=limit)
        else:
            rows = self.db.query(
                "SELECT * FROM audit_events ORDER BY ts DESC", limit=limit)
        out = []
        for r in rows:
            r["metadata"] = store.loads(r.get("metadata", "{}"))
            out.append(models.AuditEvent.from_dict(r))
        return out

    # --------------------------------------------------- integration (one-shot)
    def register_scanner_result(self, project_id: str, raw: dict,
                                *, profile: str = "", scan_id: str = "",
                                mark_completed: bool = True) -> dict:
        """Ingest ANY existing scanner JSON into the platform:
        normalized scan + assets + findings + sanitized evidence, while the
        RAW payload is preserved (redacted) on the scan record."""
        self.project_require(project_id)
        normalized = normalize.normalize_result(raw, project_id=project_id)
        if profile:
            normalized["scan"].profile = profile
        scan = normalized["scan"] if not scan_id else \
            self.scan_get(scan_id)
        if scan_id:
            # findings were normalized against a freshly computed scan id;
            # rebind them to the PERSISTED scan so provenance (and the
            # findings.scan_id foreign key) follow the real scan row.
            for f in normalized["findings"]:
                f.scan_id = scan.id
        if not scan_id:
            # scan.id already normalized deterministically (project|profile|
            # created_at) — findings carry the SAME id, so this is the single
            # source of truth; re-ingesting the same payload upserts the same
            # scan instead of violating the primary key.
            created = False
            try:
                self.scan_get(scan.id)
            except errors.NotFoundError:
                created = True
            self.db.upsert("scans", {
                "id": scan.id, "project_id": scan.project_id,
                "profile": scan.profile, "scope_ref": scan.scope_ref,
                "status": scan.status, "created_at": scan.created_at,
                "started_at": scan.started_at or "", "finished_at": "",
                "initiator": store.dumps(scan.initiator), "progress": 0.0,
                "stages": store.dumps(scan.stages),
                "summary": store.dumps(scan.summary),
                "error": store.dumps(scan.error), "raw": "{}"})
            if created:
                self.audit("scan.created", object_type="scan", object_id=scan.id,
                           project_id=project_id,
                           metadata={"profile": scan.profile})
        self.audit("scan.started", object_type="scan", object_id=scan.id,
                   project_id=project_id)
        saved_assets = []
        for asset in normalized["assets"]:
            try:
                saved_assets.append(
                    self.asset_add(project_id, asset.asset_type, asset.value,
                                   asset.metadata, asset.display))
            except errors.DuplicateError:
                pass
        index = {a.value: a.id for a in self.asset_list(project_id, limit=2000)}
        # Phase 4: asset intelligence (idempotent; never breaks ingestion)
        try:
            from intel import IntelService
            IntelService(self).ingest_observations(project_id, scan.id,
                                                   raw, saved_assets)
        except Exception:
            pass
        # Phase 4: per-finding intelligence (canonical identity, confidence,
        # risk, snapshots, correlation) — same ingestion guarantees
        correlator = None
        for f in normalized["findings"]:
            if not f.asset_id:
                f.asset_id = index.get(str(f.raw.get("target") or
                                           f.raw.get("url") or ""), "")
                f.project_id = project_id
            evs = [models.Evidence.from_dict(dict(e)) for e in f.evidence]
            for e in evs:
                e.finding_id = f.id  # set for finalize
                e.finalize()
            try:
                if correlator is None:
                    from correlate import CorrelationService
                    correlator = CorrelationService(self)
                correlator.ingest_finding(f, evs, scan_id=scan.id, raw=f.raw)
            except Exception:
                self.finding_ingest(f, evidence=evs)
        if mark_completed:
            self.db.execute(
                "UPDATE scans SET status='completed', finished_at=?, "
                "summary=? WHERE id=?",
                (models.utcnow(), store.dumps(
                    {"findings": len(normalized["findings"]),
                     "score": raw.get("score"),
                     "grade": raw.get("grade")}), scan.id))
            self.audit("scan.completed", object_type="scan", object_id=scan.id,
                       project_id=project_id,
                       metadata={"findings": len(normalized["findings"])})
            try:
                from diffs import BaselineService
                BaselineService(self).capture(project_id, scan.id)
            except Exception:
                pass
        self.scan_save_raw(scan.id, raw)
        return {"scan_id": scan.id, "assets": len(normalized["assets"]),
                "findings": len(normalized["findings"])}

    # --------------------------------------------------------------- internals
    def _one(self, table: str, record_id: str, label: str) -> dict:
        row = self.db.query_one(f"SELECT * FROM {table} WHERE id=?", (record_id,))
        if row is None:
            raise errors.NotFoundError(f"{label} not found: {record_id}")
        return row


# ---------------------------------------------------------------------------
# Optional one-call integration used by workflow.py (opt-in, never breaks
# existing CLI behaviour)
# ---------------------------------------------------------------------------
def maybe_register_scan_result(project_id: str | None, raw: dict) -> dict | None:
    """No-op unless platform persistence is enabled in configuration.
    Called by workflow.py at the end of a run."""
    try:
        cfg = sec_config.load()
        if not cfg.get("platform", {}).get("enabled"):
            return None
        if not project_id:
            return None
        svc = PlatformService()
        return svc.register_scanner_result(project_id, raw)
    except Exception:
        return None   # integrations must never break the scanner itself
