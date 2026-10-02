#!/usr/bin/env python3
# ============================================================================
#  diffs.py — Phase 4 project baselines + temporal scan diffs.
#
#  MODEL (matches the Phase-4 schema exactly):
#    - project_baselines holds ONE row per project: the (baseline_scan_id,
#      current_scan_id) pair being tracked, the FROZEN snapshot payload of
#      the current scan (findings keyed by stable fingerprint, assets by
#      stable id) and updated_at.
#    - scan_diffs materializes the deterministic diff of each pair:
#      id (stable), baseline_scan_id, current_scan_id, calc_version,
#      summary (counts + bounded detail, JSON), created_at.
#      UNIQUE(project_id, baseline_scan_id, current_scan_id, calc_version)
#      makes re-runs idempotent.
#    - Findings are compared by STABLE fingerprint; assets by stable id;
#      services/technologies by observation values per scan_id.
#    - A missing previous snapshot means "all_new" (first baseline).
#    - Payloads bounded + redacted; append-only; snapshots stay
#      interpretable forever (the scans' findings remain in the DB).
# ============================================================================

from __future__ import annotations

import models
import metrics
import redact
import store

DIFF_CALC_VERSION = "diff-v1"
MAX_DIFF_FINDINGS = 500
MAX_DIFF_ASSETS = 1000
MAX_DIFF_DETAIL = 400


class BaselineService:
    """Project baselines + current-vs-previous scan diffs."""

    def __init__(self, platform):
        self.svc = platform
        self.db = platform.db

    def _audit(self, action, *, object_type, object_id, project_id, actor,
               metadata):
        try:
            self.svc.audit(action, object_type=object_type,
                           object_id=object_id, project_id=project_id,
                           actor=actor, metadata=metadata)
        except Exception:
            pass

    # ------------------------------------------------------- scan snapshot
    def _scan_snapshot(self, scan_id: str) -> tuple:
        """(findings_by_fingerprint, assets_by_id) DETECTED by one scan
        (via observation provenance — stable, not random ids)."""
        findings = self.db.query(
            "SELECT f.id, f.fingerprint, f.title, f.severity, f.category, "
            "f.lifecycle, f.asset_id, f.risk_score, f.risk_level, "
            "f.priority, f.source FROM findings f JOIN finding_observations "
            "o ON o.finding_id=f.id WHERE o.scan_id=? ORDER BY "
            "f.fingerprint LIMIT ?", (scan_id, MAX_DIFF_FINDINGS))
        f_rows = {}
        for f in findings:
            if not f["fingerprint"]:
                continue
            if f["fingerprint"] in f_rows:
                continue  # same finding twice in one scan → once
            f_rows[str(f["fingerprint"])] = {
                "finding_id": f["id"], "title": str(f["title"])[:200],
                "severity": f["severity"], "category": f["category"],
                "lifecycle": f["lifecycle"], "asset_id": f["asset_id"],
                "risk_score": f["risk_score"],
                "risk_level": f["risk_level"],
                "priority": f["priority"],
                "source": str(f["source"])[:60]}
        assets = self.db.query(
            "SELECT DISTINCT asset_id, asset_type, value, criticality, "
            "exposure, status FROM (SELECT o.asset_id, a.asset_type, "
            "a.value, a.criticality, a.exposure, a.status FROM "
            "asset_observations o JOIN assets a ON a.id=o.asset_id WHERE "
            "o.scan_id=? ORDER BY o.asset_id) LIMIT ?",
            (scan_id, MAX_DIFF_ASSETS))
        a_rows = {}
        for a in assets:
            if not a["asset_id"]:
                continue
            services = self.db.query(
                "SELECT DISTINCT obs_value FROM asset_observations WHERE "
                "asset_id=? AND obs_type='service' ORDER BY obs_value "
                "LIMIT 200", (a["asset_id"],))
            techs = self.db.query(
                "SELECT DISTINCT obs_value FROM asset_observations WHERE "
                "asset_id=? AND obs_type='technology' ORDER BY obs_value "
                "LIMIT 200", (a["asset_id"],))
            a_rows[str(a["asset_id"])] = {
                "asset_type": a["asset_type"], "value": a["value"],
                "criticality": a["criticality"],
                "exposure": a["exposure"], "status": a["status"],
                "services": [s["obs_value"] for s in services],
                "technologies": [t["obs_value"] for t in techs]}
        return f_rows, a_rows

    # ------------------------------------------------------------ capture
    def capture(self, project_id: str, scan_id: str, *,
                actor: str = "scanner") -> dict:
        """Register a completed scan as the project's new current state and
        materialize the diff vs the FROZEN previous snapshot. Idempotent per
        scan; repeated calls never recompute or duplicate rows."""
        if not scan_id:
            raise ValueError("scan_id required")
        row = self.db.query(
            "SELECT * FROM project_baselines WHERE project_id=? LIMIT 1",
            (project_id,))
        baseline_scan = ""
        current_scan = ""
        from_payload = {}
        if row:
            baseline_scan = row[0]["baseline_scan_id"]
            current_scan = row[0]["current_scan_id"]
            from_payload = store.loads(row[0]["payload"] or "{}")
        if current_scan == scan_id:
            stored = self.db.query(
                "SELECT id, created_at FROM scan_diffs WHERE project_id=? "
                "AND current_scan_id=? ORDER BY created_at DESC, rowid DESC "
                "LIMIT 1",
                (project_id, scan_id))
            if stored:
                return {"diff_id": stored[0]["id"],
                        "from_scan_id": baseline_scan,
                        "to_scan_id": scan_id, "created": False}
        to_f, to_a = self._scan_snapshot(scan_id)
        to_payload = {"findings": to_f, "assets": to_a,
                      "truncated": (len(to_f) >= MAX_DIFF_FINDINGS or
                                    len(to_a) >= MAX_DIFF_ASSETS)}
        result = self._compare_payloads(
            project_id, from_payload, to_payload,
            from_label=current_scan, to_label=scan_id, actor=actor)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO project_baselines (project_id, "
                "baseline_scan_id, current_scan_id, updated_at, payload) "
                "VALUES (?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET "
                "baseline_scan_id=excluded.baseline_scan_id, "
                "current_scan_id=excluded.current_scan_id, "
                "updated_at=excluded.updated_at, "
                "payload=excluded.payload",
                (project_id, current_scan, scan_id, models.utcnow(),
                 store.dumps(to_payload)))
        result["created"] = True
        # Phase 5: change detection → normalized security events → alert
        # evaluation + notifications. Deterministic event ids make re-runs
        # idempotent; failures never break baseline capture.
        try:
            from events import ChangeDetector
            emitted = ChangeDetector(self.svc).detect(
                project_id, from_payload, to_payload, scan_id=scan_id,
                source="change-detector", actor=actor)
            if emitted:
                try:
                    from alerts import AlertService
                    for ev in emitted:
                        AlertService(self.svc).process_event(ev, actor=actor)
                except Exception:
                    metrics.inc("alert_evaluation_failures")
        except Exception:
            pass
        return result

    # ------------------------------------------------------------ diff
    def diff_between(self, project_id: str, from_scan: str,
                     to_scan: str, *, actor: str = "scanner") -> dict:
        """Explicit diff between two scans (live row state at call time).
        The capture() path uses frozen snapshots; this convenience path is
        for ad-hoc comparisons (deterministic for the same DB state)."""
        from_f, from_a = self._scan_snapshot(from_scan)
        to_f, to_a = self._scan_snapshot(to_scan)
        return self._compare_payloads(
            project_id,
            {"findings": from_f, "assets": from_a}, {"findings": to_f,
                                                     "assets": to_a},
            from_label=from_scan, to_label=to_scan, actor=actor)

    def _compare_payloads(self, project_id: str, fr: dict, to: dict, *,
                          from_label: str, to_label: str,
                          actor: str) -> dict:
        """Deterministic snapshot comparison (stable identities only)."""
        ff = (fr or {}).get("findings", {})
        fa = (fr or {}).get("assets", {})
        tf = (to or {}).get("findings", {})
        ta = (to or {}).get("assets", {})
        if not ff:
            summary = {
                "findings_new": len(tf), "findings_resolved": 0,
                "findings_persistent": 0, "findings_reopened": 0,
                "findings_changed": 0, "assets_new": len(ta),
                "assets_removed": 0, "asset_service_changes": 0}
            detail = {"reason": "first baseline for this project",
                      "findings_new": [
                          {"fingerprint": k, "finding_id": v["finding_id"],
                           "title": v["title"]}
                          for k, v in sorted(tf.items())[:MAX_DIFF_DETAIL]],
                      "truncated": len(tf) > MAX_DIFF_DETAIL}
        else:
            fk, tk = set(ff), set(tf)
            new_f = sorted(tk - fk)          # in TO, not in FROM
            resolved_f = sorted(fk - tk)     # in FROM, not in TO
            persistent_f = sorted(fk & tk)
            reopened = sorted([k for k in persistent_f
                               if tf[k].get("lifecycle") == "reopened"
                               and ff[k].get("lifecycle") != "reopened"])
            changed = []
            for k in persistent_f:
                a, b = ff[k], tf[k]
                if (a.get("severity") != b.get("severity") or
                        a.get("risk_score") != b.get("risk_score") or
                        a.get("risk_level") != b.get("risk_level")):
                    changed.append({
                        "fingerprint": k,
                        "finding_id": b.get("finding_id"),
                        "title": b.get("title"),
                        "from": {"severity": a.get("severity"),
                                 "risk_score": a.get("risk_score"),
                                 "risk_level": a.get("risk_level")},
                        "to": {"severity": b.get("severity"),
                               "risk_score": b.get("risk_score"),
                               "risk_level": b.get("risk_level")}})
            ak, bkt = set(fa), set(ta)
            new_a = sorted(bkt - ak)         # in TO, not in FROM
            removed_a = sorted(ak - bkt)     # in FROM, not in TO
            svc_changes = []
            for aid in sorted(ak & bkt):
                a, b = fa[aid], ta[aid]
                s_a, s_b = set(a.get("services", [])), \
                    set(b.get("services", []))
                t_a, t_b = (set(a.get("technologies", [])),
                            set(b.get("technologies", [])))
                if s_a != s_b or t_a != t_b:
                    svc_changes.append({
                        "asset_id": aid, "value": b.get("value"),
                        "services_added": sorted(s_b - s_a),
                        "services_removed": sorted(s_a - s_b),
                        "technologies_added": sorted(t_b - t_a),
                        "technologies_removed": sorted(t_a - t_b)})
            summary = {
                "findings_new": len(new_f),
                "findings_resolved": len(resolved_f),
                "findings_persistent": len(persistent_f),
                "findings_reopened": len(reopened),
                "findings_changed": len(changed),
                "assets_new": len(new_a),
                "assets_removed": len(removed_a),
                "asset_service_changes": len(svc_changes)}
            detail = {
                "findings_new": [{"fingerprint": k,
                                  "finding_id": tf[k]["finding_id"],
                                  "title": tf[k]["title"]}
                                 for k in new_f[:MAX_DIFF_DETAIL]],
                "findings_resolved": [
                    {"fingerprint": k,
                     "finding_id": ff[k]["finding_id"],
                     "title": ff[k]["title"]}
                    for k in resolved_f[:MAX_DIFF_DETAIL]],
                "findings_reopened": [
                    {"fingerprint": k,
                     "finding_id": tf[k]["finding_id"],
                     "title": tf[k]["title"]}
                    for k in reopened[:MAX_DIFF_DETAIL]],
                "findings_changed": changed[:MAX_DIFF_DETAIL],
                "assets_new": [{"asset_id": k,
                                "value": ta[k]["value"]}
                               for k in new_a[:MAX_DIFF_DETAIL]],
                "assets_removed": [{"asset_id": k,
                                    "value": fa[k]["value"]}
                                   for k in removed_a[:MAX_DIFF_DETAIL]],
                "service_changes": svc_changes[:MAX_DIFF_DETAIL],
                "truncated": bool(
                    len(new_f) > MAX_DIFF_DETAIL or
                    len(resolved_f) > MAX_DIFF_DETAIL or
                    len(changed) > MAX_DIFF_DETAIL or
                    len(svc_changes) > MAX_DIFF_DETAIL)}
        return self._store_diff(project_id, from_label, to_label, summary,
                                redact.redact(detail), actor=actor)

    def _store_diff(self, project_id: str, from_id: str, to_id: str,
                    summary: dict, detail: dict, *, actor: str) -> dict:
        ts = models.utcnow()
        diff_id = models.stable_id(
            models.NS_DIFF,
            f"{project_id}|{from_id}|{to_id}|{DIFF_CALC_VERSION}")
        payload = {"summary": summary, "detail": detail,
                   "calc_version": DIFF_CALC_VERSION}
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scan_diffs (id, project_id, "
                "baseline_scan_id, current_scan_id, calc_version, summary, "
                "created_at) VALUES (?,?,?,?,?,?,?)",
                (diff_id, project_id, str(from_id)[:64], str(to_id)[:64],
                 DIFF_CALC_VERSION, store.dumps(payload), ts))
        metrics.inc("scan_diffs")
        self._audit("scan.diff", object_type="project",
                    object_id=project_id, project_id=project_id,
                    actor=actor,
                    metadata={"diff_id": diff_id, "from_scan": from_id,
                              "to_scan": to_id, "summary": summary})
        return {"diff_id": diff_id, "project_id": project_id,
                "from_scan_id": from_id, "to_scan_id": to_id,
                "created_at": ts, "summary": summary, "detail": detail}

    # -------------------------------------------------------------- reads
    def diffs(self, project_id: str, limit: int = 50) -> list:
        rows = self.db.query(
            "SELECT id, project_id, baseline_scan_id, current_scan_id, "
            "calc_version, created_at, summary FROM scan_diffs WHERE "
            "project_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (project_id, limit))
        out = []
        for r in rows:
            r["summary"] = store.loads(r.get("summary", "{}"))
            out.append(dict(r))
        return out

    def diff_get(self, diff_id: str) -> dict | None:
        rows = self.db.query("SELECT * FROM scan_diffs WHERE id=? LIMIT 1",
                             (diff_id,))
        if not rows:
            return None
        r = dict(rows[0])
        payload = store.loads(r.get("summary", "{}"))
        r["summary"] = payload.get("summary", {})
        r["detail"] = payload.get("detail", {})
        r["calc_version_used"] = payload.get("calc_version",
                                             r.get("calc_version", ""))
        return r

    def baseline_status(self, project_id: str) -> dict | None:
        rows = self.db.query(
            "SELECT project_id, baseline_scan_id, current_scan_id, "
            "updated_at FROM project_baselines WHERE project_id=? LIMIT 1",
            (project_id,))
        return dict(rows[0]) if rows else None
