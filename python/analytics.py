#!/usr/bin/env python3
# ============================================================================
#  analytics.py — Phase 6 security analytics engine.
#  ---------------------------------------------------------------------------
#  Deterministic analytics OVER EXISTING platform data. This module NEVER
#  recalculates risk (it reads Phase-4 risk columns and risk_snapshots),
#  NEVER duplicates findings/assets/events, and NEVER writes to the domain
#  tables. Everything is:
#
#    - project-scoped / tenant-scoped (every query carries project_id)
#    - parameterized SQL with allowlisted identifiers only
#    - bounded (hard caps on date ranges, buckets, rows, returned payloads)
#    - deterministic (same data + same cutoff ⇒ same numbers)
#    - redacted before it leaves this module (redact.redact on outputs)
#
#  Posture score: a separate, versioned EXECUTIVE metric (posture-v1). It is
#  deliberately NOT the Phase-4 finding risk score: finding risk stays
#  untouched; posture measures programme health (open risk pressure,
#  remediation progress, exposure, trend, monitoring freshness, verification)
#  and returns per-factor explanations.
#
#  No industry benchmark claims: KPIs are CONDITIONED on documented, local
#  definitions (see KPI_DEFS) — never compared to external baselines.
# ============================================================================

from __future__ import annotations

import re
import time

import errors
import metrics
import models
import redact
import store

# ---------------------------------------------------------------------------
# Limits (explicit, documented; never silent truncation)
# ---------------------------------------------------------------------------
MAX_TREND_DAYS = 3660        # absolute ceiling for any analytics range
MAX_TREND_BUCKETS = 180      # buckets in a time series (deterministic width)
DEFAULT_TREND_DAYS = 30      # default window when no range is given
MAX_ASSET_ROWS = 500         # per query cap
MAX_FINDING_ROWS = 1000
MAX_PROJECT_ROWS = 100
MAX_KPI_HISTORY_DAYS = 3660
_CACHE_MAX = 256

# Finding-status sets (documented, single source of truth for "open risk").
ACTIVE_FINDING_STATUSES = frozenset({
    "open", "acknowledged", "confirmed", "in_review", "reopened"})
CLOSED_FINDING_STATUSES = frozenset({
    "resolved", "remediated", "false_positive", "accepted_risk"})

# Posture weights (sum == 1.0) — deterministic and versioned.
POSTURE_FACTORS = (
    {"key": "open_risk_pressure", "weight": 0.30,
     "definition": "1 - min(1, (3*open_critical + open_high) / 30). Open "
                   "critical findings weigh 3x; the pressure is saturated at "
                   "30 weighted open findings."},
    {"key": "remediation_progress", "weight": 0.20,
     "definition": "0.6 * closed_or_verified_ratio + 0.4 * (1 - overdue_ratio)"
                   " over remediation tickets (no tickets => neutral 0.5)."},
    {"key": "asset_exposure", "weight": 0.15,
     "definition": "1 - internet_facing_ratio over known assets (unknown "
                   "exposure is treated as neutral 0.5; no assets => 1.0)."},
    {"key": "risk_trend", "weight": 0.15,
     "definition": "1 when no net risk increase in the window; decays to 0 "
                   "as (risk.increased - risk.decreased) events approach 20."},
    {"key": "monitoring_freshness", "weight": 0.10,
     "definition": "Phase-5 monitoring health score / 100 (reused, never "
                   "recomputed differently)."},
    {"key": "verification_status", "weight": 0.10,
     "definition": "verification pass rate over completed verifications "
                   "(none => neutral 0.5)."},
)
POSTURE_WEIGHTS = {f["key"]: f["weight"] for f in POSTURE_FACTORS}

# Allowlisted sort keys for finding analytics (key -> SQL expression).
SORT_FIELDS = {
    "risk": "f.risk_score",
    "severity": "f.severity",
    "first_detected": "f.first_detected",
    "last_detected": "f.last_detected",
    "title": "f.title",
    "asset": "f.asset_id",
}
SORT_DIRECTIONS = ("asc", "desc")

_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-()&]{0,127}$")
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z?)?$")


def _bounded(value, lo: int, hi: int, label: str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise errors.ValidationError(f"{label}_invalid: not an integer")
    if v < lo or v > hi:
        raise errors.ValidationError(
            f"{label}_invalid: must be {lo}..{hi} (bounded)")
    return v


from datetime import datetime, timezone  # noqa: E402


def _epoch(ts: str) -> float:
    """UTC-exact epoch (never local time — report determinism must not
    depend on the host timezone)."""
    s = str(ts).replace("T", " ").replace("Z", "")[:19]
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=timezone.utc).timestamp()


def _iso(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


def validate_ts(value: str, *, label: str) -> str:
    """Validate an ISO timestamp (date or datetime). Fail closed."""
    s = str(value or "").strip()
    if not _ISO_RE.match(s):
        raise errors.ValidationError(
            f"{label}_invalid: expected YYYY-MM-DD or ISO datetime")
    return s + ("T00:00:00Z" if len(s) == 10 and "T" not in s else "")


def bounded_range(start: str = "", end: str = "", *,
                  max_days: int = MAX_TREND_DAYS) -> tuple[str, str]:
    """Validate + bound a date range. Defaults: [now - 30d, now]. Never
    allows unbounded historical queries."""
    now = _iso(time.time())
    if not start and not end:
        return _iso(_epoch(now) - DEFAULT_TREND_DAYS * 86400), now
    s = validate_ts(start, label="start") if start else \
        _iso(_epoch(now) - DEFAULT_TREND_DAYS * 86400)
    e = validate_ts(end, label="end") if end else now
    if _epoch(s) > _epoch(e):
        raise errors.ValidationError(
            "range_invalid: start must be before end")
    if _epoch(e) - _epoch(s) > max_days * 86400 + 1:
        raise errors.ValidationError(
            f"range_invalid: range exceeds {max_days} days (bounded)")
    return s, e


def _buckets(start: str, end: str, *, max_buckets: int = MAX_TREND_BUCKETS) \
        -> tuple[int, list[str]]:
    """Deterministic bucket width: day buckets up to max_buckets, then
    proportional multi-day buckets (never more than max_buckets points)."""
    span = _epoch(end) - _epoch(start)
    days = max(1, int(span // 86400) + 1)
    width = max(1, (days + max_buckets - 1) // max_buckets)
    labels = []
    ep = _epoch(start)
    while ep < _epoch(end) and len(labels) < max_buckets:
        labels.append(_iso(ep)[:10])
        ep += width * 86400
    return width, labels


# ---------------------------------------------------------------------------
class AnalyticsService:
    """Read-only analytics over the existing platform (no writes)."""

    def __init__(self, platform, *, cache_max: int = _CACHE_MAX):
        self.svc = platform
        self.db = platform.db
        self._cache: dict = {}
        self._cache_max = int(cache_max)

    # ------------------------------------------------------------ helpers
    def _cache_get(self, key):
        v = self._cache.get(key)
        if v is not None:
            return v
        return None

    def _cache_put(self, key, value):
        if len(self._cache) >= self._cache_max:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = value
        return value

    def _cutoff(self, cutoff: str = "") -> str:
        c = str(cutoff or "").strip()
        if not c:
            return models.utcnow()
        return validate_ts(c, label="cutoff")

    def project_require(self, project_id: str):
        return self.svc.project_require(project_id)

    def _q(self, sql: str, params=()):
        return [dict(r) for r in self.db.query(sql, tuple(params))]

    def _one(self, sql: str, params=()):
        rows = self._q(sql, params)
        return rows[0] if rows else None

    # ---------------------------------------------------- risk analytics
    def risk_summary(self, project_id: str, *, cutoff: str = "",
                     statuses: tuple = ()) -> dict:
        """Risk distribution + aggregate stats. Reads Phase-4 risk columns
        only (never recalculates). `statuses` filters findings (default:
        active statuses)."""
        key = ("risk_summary", project_id, cutoff, tuple(statuses))
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            status_sql = f"AND f.lifecycle IN ({placeholders})"
            status_params = tuple(statuses)
        else:
            status_sql = ("AND f.lifecycle IN "
                          "(" + ",".join("?" for _ in ACTIVE_FINDING_STATUSES)
                          + ")")
            status_params = tuple(ACTIVE_FINDING_STATUSES)
        base = ("FROM findings f LEFT JOIN assets a ON a.id=f.asset_id "
                "WHERE f.project_id=? AND f.first_detected<=? " + status_sql)
        param = (project_id, co) + status_params

        by_sev = self._q(
            "SELECT f.severity, COUNT(*) n, COALESCE(SUM(f.risk_score),0) r "
            + base + " GROUP BY f.severity", param)
        by_level = self._q(
            "SELECT f.risk_level, COUNT(*) n " + base + " GROUP BY f.risk_level",
            param)
        by_priority = self._q(
            "SELECT f.priority, COUNT(*) n " + base + " GROUP BY f.priority",
            param)
        by_exposure = self._q(
            "SELECT COALESCE(a.exposure,'unknown') ex, COUNT(*) n " + base +
            " GROUP BY ex", param)
        by_criticality = self._q(
            "SELECT COALESCE(a.criticality,'unknown') cr, COUNT(*) n " + base +
            " GROUP BY cr", param)
        by_confidence = self._q(
            "SELECT f.confidence_level cl, COUNT(*) n " + base +
            " GROUP BY cl", param)
        agg = self._one(
            "SELECT COUNT(*) n, COALESCE(AVG(f.risk_score),0) avg_risk, "
            "COALESCE(MAX(f.risk_score),0) max_risk, "
            "COALESCE(SUM(f.risk_score),0) total_risk " + base, param)
        out = {
            "project_id": project_id,
            "data_cutoff": co,
            "risk_calculation_version":
                self._risk_version(project_id),
            "scope_statuses": sorted(statuses) if statuses else
                sorted(ACTIVE_FINDING_STATUSES),
            "count": int(agg["n"] if agg else 0),
            "total_risk": round(float(agg["total_risk"] if agg else 0), 1),
            "avg_risk": round(float(agg["avg_risk"] if agg else 0), 1),
            "max_risk": round(float(agg["max_risk"] if agg else 0), 1),
            "by_severity": {r["severity"]: int(r["n"]) for r in by_sev},
            "by_risk_level": {r["risk_level"]: int(r["n"])
                              for r in by_level},
            "by_priority": {r["priority"]: int(r["n"]) for r in by_priority},
            "by_exposure": {r["ex"]: int(r["n"]) for r in by_exposure},
            "by_criticality": {r["cr"]: int(r["n"]) for r in by_criticality},
            "by_confidence": {r["cl"]: int(r["n"]) for r in by_confidence},
            "severity_risk": {r["severity"]: round(float(r["r"]), 1)
                              for r in by_sev},
        }
        return redact.redact(self._cache_put(key, out))

    def _risk_version(self, project_id: str) -> str:
        row = self._one(
            "SELECT rs.calc_version FROM risk_snapshots rs JOIN findings f "
            "ON f.id=rs.finding_id WHERE f.project_id=? ORDER BY rs.ts DESC "
            "LIMIT 1", (project_id,))
        if row and row.get("calc_version"):
            return str(row["calc_version"])
        row = self._one(
            "SELECT calc_version FROM findings WHERE project_id=? AND "
            "calc_version<>'' ORDER BY last_detected DESC LIMIT 1",
            (project_id,))
        return str(row["calc_version"]) if row else "risk-v1"

    def risk_buckets(self, project_id: str, *, cutoff: str = "",
                     bucket_width: int = 10) -> dict:
        """0-100 histogram (deterministic 10-point buckets)."""
        if int(bucket_width) not in (5, 10, 20):
            raise errors.ValidationError(
                "bucket_width_invalid: use 5, 10 or 20")
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        rows = self._q(
            "SELECT CAST(f.risk_score / ? AS INTEGER) * ? AS bucket, "
            "COUNT(*) n FROM findings f WHERE f.project_id=? AND "
            "f.first_detected<=? AND f.lifecycle IN (" +
            ",".join("?" for _ in ACTIVE_FINDING_STATUSES) + ") "
            "GROUP BY bucket", (int(bucket_width), int(bucket_width),
                                project_id, co) + tuple(ACTIVE_FINDING_STATUSES))
        out = {i: 0 for i in range(0, 101, int(bucket_width))}
        for r in rows:
            out[int(r["bucket"])] = int(r["n"])
        return redact.redact({"project_id": project_id, "data_cutoff": co,
                              "bucket_width": int(bucket_width),
                              "buckets": out})

    def risk_by_asset(self, project_id: str, *, cutoff: str = "",
                      limit: int = 20) -> list[dict]:
        """Top risky assets (grouped by Phase-4 asset identity)."""
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        limit = _bounded(limit, 1, 500, "limit")
        rows = self._q(
            "SELECT COALESCE(f.asset_id,'') asset_id, COUNT(*) findings, "
            "COALESCE(SUM(f.risk_score),0) risk_total, "
            "SUM(CASE WHEN f.severity='Critical' THEN 1 ELSE 0 END) crit, "
            "SUM(CASE WHEN f.severity='High' THEN 1 ELSE 0 END) high "
            "FROM findings f WHERE f.project_id=? AND f.first_detected<=? "
            "AND f.lifecycle IN (" +
            ",".join("?" for _ in ACTIVE_FINDING_STATUSES) + ") "
            "GROUP BY asset_id ORDER BY risk_total DESC LIMIT ?",
            (project_id, co) + tuple(ACTIVE_FINDING_STATUSES) + (limit,))
        names = self._q(
            "SELECT id, value, asset_type FROM assets WHERE project_id=?",
            (project_id,))
        nmap = {a["id"]: a for a in names}
        out = []
        for r in rows:
            a = nmap.get(r["asset_id"]) or {}
            out.append({"asset_id": r["asset_id"],
                        "asset_value": str(a.get("value", ""))[:120],
                        "asset_type": a.get("asset_type", ""),
                        "findings": int(r["findings"]),
                        "risk_total": round(float(r["risk_total"]), 1),
                        "critical": int(r["crit"]), "high": int(r["high"])})
        return redact.redact(out)

    def risk_by_project(self, org_id: str, *, cutoff: str = "",
                        limit: int = 50) -> list[dict]:
        """Org-level risk rollup across visible projects (bounded)."""
        self.svc.org_require(org_id)
        co = self._cutoff(cutoff)
        limit = _bounded(limit, 1, MAX_PROJECT_ROWS, "limit")
        projects = self.svc.project_list(org_id)[:limit]
        out = []
        for p in projects:
            s = self.risk_summary(p.id, cutoff=co)
            out.append({"project_id": p.id, "project_name": p.name,
                        "count": s["count"], "total_risk": s["total_risk"],
                        "avg_risk": s["avg_risk"],
                        "critical": s["by_severity"].get("Critical", 0),
                        "high": s["by_severity"].get("High", 0)})
        return redact.redact(out)

    def risk_delta(self, project_id: str, *, start: str = "",
                   end: str = "") -> dict:
        """Risk change signals (event-count based; never recalculated)."""
        s, e = bounded_range(start, end)
        self.project_require(project_id)
        rows = self._q(
            "SELECT event_type, COUNT(*) n FROM security_events WHERE "
            "project_id=? AND ts>=? AND ts<=? AND event_type IN "
            "('risk.increased','risk.decreased') GROUP BY event_type",
            (project_id, s, e))
        inc = sum(int(r["n"]) for r in rows if r["event_type"] == "risk.increased")
        dec = sum(int(r["n"]) for r in rows if r["event_type"] == "risk.decreased")
        return redact.redact({"project_id": project_id, "start": s, "end": e,
                              "risk_increased": inc, "risk_decreased": dec,
                              "net": inc - dec})

    # ------------------------------------------------------ trend engine
    def _series(self, project_id: str, sql: str, params: tuple, *,
                start: str, end: str, bucket_field: str) -> dict:
        """Bucket any timestamped count query into a deterministic series."""
        width, labels = _buckets(start, end)
        counts = {label: [] for label in labels}
        rows = self.db.query(sql, (project_id, start, end) + tuple(params))
        for r in rows:
            vals = list(r.values())
            idx = min(int((_epoch(vals[0]) - _epoch(start)) //
                          (width * 86400)), len(labels) - 1)
            if idx >= 0:
                counts[labels[idx]].append(int(vals[1]))
        return {"bucket_days": width, "start": start, "end": end,
                "points": [{labels[i]: sum(counts[labels[i]])}
                           for i in range(len(labels))]}

    def finding_trend(self, project_id: str, *, start: str = "",
                      end: str = "") -> dict:
        """Findings created / resolved / reopened per bucket."""
        s, e = bounded_range(start, end)
        self.project_require(project_id)
        cr = self._series(
            project_id,
            "SELECT first_detected, COUNT(*) FROM findings WHERE "
            "project_id=? AND first_detected>=? AND first_detected<=? "
            "GROUP BY first_detected", (), start=s, end=e,
            bucket_field="first_detected")
        rs = self._series(
            project_id,
            "SELECT resolved_at, COUNT(*) FROM findings WHERE "
            "project_id=? AND resolved_at<>'' AND resolved_at>=? AND "
            "resolved_at<=? GROUP BY resolved_at", (), start=s, end=e,
            bucket_field="resolved_at")
        rp = self._series(
            project_id,
            "SELECT reopened_at, COUNT(*) FROM findings WHERE "
            "project_id=? AND reopened_at<>'' AND reopened_at>=? AND "
            "reopened_at<=? GROUP BY reopened_at", (), start=s, end=e,
            bucket_field="reopened_at")
        return redact.redact({
            "project_id": project_id, "bucket_days": cr["bucket_days"],
            "start": s, "end": e,
            "created": cr["points"], "resolved": rs["points"],
            "reopened": rp["points"],
            "total_created": sum(p.get(list(p)[0], 0) for p in cr["points"]),
            "total_resolved": sum(p.get(list(p)[0], 0) for p in rs["points"]),
            "total_reopened": sum(p.get(list(p)[0], 0) for p in rp["points"]),
        })

    def asset_trend(self, project_id: str, *, start: str = "",
                    end: str = "") -> dict:
        """Assets discovered / removed + exposure changes per bucket."""
        s, e = bounded_range(start, end)
        self.project_require(project_id)
        disc = self._series(
            project_id,
            "SELECT first_seen, COUNT(*) FROM assets WHERE project_id=? "
            "AND first_seen>=? AND first_seen<=? GROUP BY first_seen",
            (), start=s, end=e, bucket_field="created_at")
        rem = self._series(
            project_id,
            "SELECT ts, COUNT(*) FROM security_events WHERE project_id=? "
            "AND ts>=? AND ts<=? AND event_type='asset.removed' "
            "GROUP BY ts", (), start=s, end=e, bucket_field="ts")
        exp = self._series(
            project_id,
            "SELECT ts, COUNT(*) FROM security_events WHERE project_id=? "
            "AND ts>=? AND ts<=? AND event_type='exposure.changed' "
            "GROUP BY ts", (), start=s, end=e, bucket_field="ts")
        return redact.redact({
            "project_id": project_id, "bucket_days": disc["bucket_days"],
            "start": s, "end": e,
            "discovered": disc["points"], "removed": rem["points"],
            "exposure_changes": exp["points"],
            "total_discovered":
                sum(p.get(list(p)[0], 0) for p in disc["points"]),
            "total_exposure_changes":
                sum(p.get(list(p)[0], 0) for p in exp["points"]),
        })

    def attack_surface_trend(self, project_id: str, *, start: str = "",
                             end: str = "") -> dict:
        """Attack-surface movement from security events + Phase-4
        observation history (bounded; no duplicate storage)."""
        s, e = bounded_range(start, end)
        self.project_require(project_id)
        ev = self._q(
            "SELECT event_type, COUNT(*) n FROM security_events WHERE "
            "project_id=? AND ts>=? AND ts<=? AND event_type IN "
            "('service.opened','service.closed','technology.changed',"
            "'version.changed','exposure.changed','asset.created',"
            "'asset.removed') GROUP BY event_type ORDER BY event_type",
            (project_id, s, e))
        obs = self._q(
            "SELECT obs_type, COUNT(*) n FROM asset_observation_events "
            "WHERE project_id=? AND ts>=? AND ts<=? AND obs_type IN "
            "('tls','dns','http','service','technology','port') "
            "GROUP BY obs_type ORDER BY obs_type", (project_id, s, e))
        events = {str(r["event_type"]): int(r["n"]) for r in ev}
        obs_out = {str(r["obs_type"]): int(r["n"]) for r in obs}
        return redact.redact({
            "project_id": project_id, "start": s, "end": e,
            "attack_surface_events": events,
            "observation_changes": obs_out,
            "total": sum(events.values()) + sum(obs_out.values()),
        })

    def exposure_trend(self, project_id: str, *, start: str = "",
                       end: str = "") -> dict:
        return self.attack_surface_trend(project_id, start=start, end=end)

    # ------------------------------------------------------- KPI engine
    def kpis(self, project_id: str, *, cutoff: str = "", start: str = "",
             end: str = "") -> dict:
        """Deterministic KPIs with documented local definitions (no external
        benchmark claims). All values are computed from platform rows."""
        key = ("kpis", project_id, cutoff, start, end)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        s, e = bounded_range(start, end, max_days=MAX_KPI_HISTORY_DAYS)
        # --- finding stock -------------------------------------------------
        act = self.risk_summary(project_id, cutoff=co)
        open_crit = int(act["by_severity"].get("Critical", 0))
        open_high = int(act["by_severity"].get("High", 0))
        all_findings = int(self._one(
            "SELECT COUNT(*) n FROM findings WHERE project_id=? "
            "AND first_detected<=?", (project_id, co))["n"])
        resolved_in = int(self._one(
            "SELECT COUNT(*) n FROM findings WHERE project_id=? AND "
            "resolved_at<>'' AND resolved_at>=? AND resolved_at<=?",
            (project_id, s, e))["n"])
        reopened_in = int(self._one(
            "SELECT COUNT(*) n FROM findings WHERE project_id=? AND "
            "reopened_at<>'' AND reopened_at>=? AND reopened_at<=?",
            (project_id, s, e))["n"])
        # --- MTTR / MTTD (documented local definitions) ---------------------
        mttr_rows = self._q(
            "SELECT (julianday(resolved_at) - julianday(first_detected)) "
            "* 24.0 AS h FROM findings WHERE project_id=? AND "
            "resolved_at<>'' AND resolved_at>=? AND resolved_at<=? LIMIT ?",
            (project_id, s, e, 200))
        mttr_h = (sum(float(r["h"]) for r in mttr_rows) / len(mttr_rows)
                  if mttr_rows else 0.0)
        mttd_rows = self._q(
            "SELECT (julianday(f.first_detected) - julianday(sc.created_at)) "
            "* 24.0 AS h FROM findings f JOIN scans sc "
            "ON sc.id=f.scan_id WHERE f.project_id=? AND f.first_detected>=? "
            "AND f.first_detected<=? AND sc.created_at<>'' LIMIT ?",
            (project_id, s, e, 200))
        mttd_h = (sum(float(r["h"]) for r in mttd_rows) / len(mttd_rows)
                  if mttd_rows else 0.0)
        # --- remediation ----------------------------------------------------
        tickets = self._q(
            "SELECT status, priority, due_at FROM remediation_tickets WHERE "
            "project_id=? LIMIT ?", (project_id, MAX_FINDING_ROWS))
        total_t = len(tickets)
        closed_t = sum(1 for t in tickets
                       if t["status"] in ("closed", "verified"))
        overdue = sum(1 for t in tickets
                      if t["status"] not in ("closed", "verified")
                      and t["due_at"] and t["due_at"] < co)
        verif = self._q(
            "SELECT v.status, COUNT(*) n FROM verification_requests v JOIN "
            "remediation_tickets t ON t.id=v.ticket_id WHERE t.project_id=? "
            "GROUP BY v.status", (project_id,))
        vmap = {str(r["status"]): int(r["n"]) for r in verif}
        done_v = vmap.get("passed", 0) + vmap.get("failed", 0)
        pass_v = (vmap.get("passed", 0) / done_v) if done_v else None
        # --- monitoring -----------------------------------------------------
        mrows = self._q(
            "SELECT status, COUNT(*) n FROM scheduler_executions WHERE "
            "project_id=? GROUP BY status", (project_id,))
        mmap = {str(r["status"]): int(r["n"]) for r in mrows}
        mon_done = mmap.get("completed", 0) + mmap.get("failed", 0)
        mon_ok = (mmap.get("completed", 0) / mon_done) if mon_done else None
        # --- assets ---------------------------------------------------------
        assets = self._q(
            "SELECT exposure FROM assets WHERE project_id=? LIMIT ?",
            (project_id, MAX_ASSET_ROWS))
        total_a = len(assets)
        disc_w = self._q(
            "SELECT (julianday(?) - julianday(first_seen)) / 7.0 AS w, "
            "COUNT(*) n FROM assets WHERE project_id=? AND first_seen>=? "
            "GROUP BY w ORDER BY w DESC LIMIT 1",
            (co, project_id, _iso(_epoch(co) - 30 * 86400)))
        out = {
            "project_id": project_id,
            "data_cutoff": co,
            "window_start": s, "window_end": e,
            "definitions": KPI_DEFS,
            "open_critical": open_crit,
            "open_high": open_high,
            "open_total": act["count"],
            "resolution_rate":
                round(resolved_in / all_findings, 4) if all_findings else 0.0,
            "reopen_rate":
                round(reopened_in / all_findings, 4) if all_findings else 0.0,
            "mttd_hours": round(mttd_h, 2),
            "mttr_hours": round(mttr_h, 2),
            "verification_pass_rate":
                round(pass_v, 4) if pass_v is not None else None,
            "overdue_remediation_rate":
                round(overdue / total_t, 4) if total_t else 0.0,
            "monitoring_success_rate":
                round(mon_ok, 4) if mon_ok is not None else None,
            "asset_discovery_rate_30d":
                (round(int(disc_w[0]["n"]) /
                       max(1.0, float(disc_w[0]["w"])), 4)
                 if disc_w and total_a else 0.0),
            "exposure_change_count": self._count_events(
                project_id, ("exposure.changed",), s, e),
        }
        return redact.redact(self._cache_put(key, out))

    def _count_events(self, project_id, types, s, e) -> int:
        ph = ",".join("?" for _ in types)
        row = self._one(
            "SELECT COUNT(*) n FROM security_events WHERE project_id=? AND "
            f"event_type IN ({ph}) AND ts>=? AND ts<=?", 
            (project_id,) + tuple(types) + (s, e))
        return int(row["n"]) if row else 0

    # ---------------------------------------------------- posture score
    def posture(self, project_id: str, *, cutoff: str = "") -> dict:
        """Deterministic executive posture score (posture-v1). Separate from
        finding risk; per-factor explanations included."""
        key = ("posture", project_id, cutoff)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        s, e = bounded_range("", co)  # trend window = [co-30d, co]
        rs = self.risk_summary(project_id, cutoff=co)
        kpi = self.kpis(project_id, cutoff=co, start=s, end=e)
        # f1 open risk pressure
        open_crit = int(rs["by_severity"].get("Critical", 0))
        open_high = int(rs["by_severity"].get("High", 0))
        pressure = min(1.0, (3 * open_crit + open_high) / 30.0)
        f1 = 1.0 - pressure
        # f2 remediation progress
        tickets = self._q(
            "SELECT status, due_at FROM remediation_tickets WHERE "
            "project_id=? LIMIT ?", (project_id, MAX_FINDING_ROWS))
        total_t = len(tickets)
        closed_t = sum(1 for t in tickets
                       if t["status"] in ("closed", "verified"))
        overdue = sum(1 for t in tickets
                      if t["status"] not in ("closed", "verified")
                      and t["due_at"] and t["due_at"] < co)
        if total_t:
            prog = closed_t / total_t
            over_r = overdue / total_t
            f2 = max(0.0, min(1.0, 0.6 * prog + 0.4 * (1.0 - over_r)))
        else:
            f2 = 0.5  # neutral: no remediation work exists yet
        # f3 asset exposure
        assets = self._q(
            "SELECT exposure FROM assets WHERE project_id=? LIMIT ?",
            (project_id, MAX_ASSET_ROWS))
        total_a = len(assets)
        if total_a:
            exposed = sum(1 for a in assets
                          if a["exposure"] == "internet_facing")
            f3 = 1.0 - (exposed / total_a)
        else:
            f3 = 1.0
        # f4 risk trend (event-count based; bounded window)
        delta = self.risk_delta(project_id, start=s, end=e)
        net = delta["risk_increased"] - delta["risk_decreased"]
        f4 = 1.0 if net <= 0 else max(0.0, 1.0 - net / 20.0)
        # f5 monitoring freshness (Phase-5 health REUSED, not recomputed)
        try:
            import monitor as _mon
            h = _mon.MonitoringHealthService(self.svc).compute(
                project_id, now=co)
            f5 = min(1.0, max(0.0, float(h.get("score") or 0) / 100.0))
        except Exception:
            metrics.inc("monitoring_health_failures")
            f5 = 0.5
        # f6 verification status
        verif = self._q(
            "SELECT v.status, COUNT(*) n FROM verification_requests v JOIN "
            "remediation_tickets t ON t.id=v.ticket_id WHERE t.project_id=? "
            "GROUP BY v.status", (project_id,))
        vmap = {str(r["status"]): int(r["n"]) for r in verif}
        done_v = vmap.get("passed", 0) + vmap.get("failed", 0)
        f6 = (vmap.get("passed", 0) / done_v) if done_v else 0.5
        values = {"open_risk_pressure": round(f1, 4),
                  "remediation_progress": round(f2, 4),
                  "asset_exposure": round(f3, 4),
                  "risk_trend": round(f4, 4),
                  "monitoring_freshness": round(f5, 4),
                  "verification_status": round(f6, 4)}
        factors = []
        total = 0.0
        for f in POSTURE_FACTORS:
            v = values[f["key"]]
            pts = round(v * f["weight"] * 100, 2)
            total += pts
            factors.append({"factor": f["key"], "weight": f["weight"],
                            "value": v, "points": pts,
                            "definition": f["definition"]})
        score = round(min(100.0, max(0.0, total)), 1)
        level = ("excellent" if score >= 85 else "good" if score >= 70 else
                 "fair" if score >= 50 else "weak")
        out = {"project_id": project_id, "data_cutoff": co,
               "posture_version": models.POSTURE_VERSION, "score": score,
               "level": level, "factors": factors,
               "basis": {"open_critical": open_crit, "open_high": open_high,
                         "open_findings": rs["count"],
                         "tickets": total_t, "assets": total_a,
                         "risk_net_delta": net,
                         "monitoring_health_score": round(f5 * 100, 1)}}
        return redact.redact(self._cache_put(key, out))

    # ------------------------------------------------ analytic summaries
    def remediation_summary(self, project_id: str, *, cutoff: str = "") -> dict:
        """Remediation backlog analytics (existing tickets; read-only)."""
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        rows = self._q(
            "SELECT status, priority, due_at, created_at FROM "
            "remediation_tickets WHERE project_id=? AND created_at<=? "
            "LIMIT ?", (project_id, co, MAX_FINDING_ROWS))
        by_status = {s: 0 for s in models.REMEDIATION_STATUSES}
        for r in rows:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        now_ep = _epoch(co)
        ages, overdue, risk_w, crit_back = [], 0, 0.0, 0
        order = {"P0": 4, "P1": 3, "P2": 2, "P3": 1, "P4": 0}
        for r in rows:
            age = max(0.0, (now_ep - _epoch(r["created_at"])) / 86400.0)
            ages.append(age)
            if r["status"] not in ("closed", "verified"):
                risk_w += float(order.get(r["priority"], 0))
                if r["priority"] == "P0":
                    crit_back += 1
                if r["due_at"] and r["due_at"] < co:
                    overdue += 1
        verif = self._q(
            "SELECT v.status, COUNT(*) n FROM verification_requests v JOIN "
            "remediation_tickets t ON t.id=v.ticket_id WHERE t.project_id=? "
            "GROUP BY v.status", (project_id,))
        vmap = {str(r["status"]): int(r["n"]) for r in verif}
        done_v = vmap.get("passed", 0) + vmap.get("failed", 0)
        return redact.redact({
            "project_id": project_id, "data_cutoff": co,
            "by_status": by_status,
            "total": len(rows),
            "avg_remediation_age_days":
                round(sum(ages) / len(ages), 2) if ages else 0.0,
            "max_remediation_age_days":
                round(max(ages), 2) if ages else 0.0,
            "overdue_count": overdue,
            "overdue_rate": round(overdue / len(rows), 4) if rows else 0.0,
            "risk_weighted_backlog": round(risk_w, 1),
            "critical_backlog": crit_back,
            "verification_failure_rate":
                (round(vmap.get("failed", 0) / done_v, 4) if done_v else None),
            "reopen_count": int(self._count_events(
                project_id, ("finding.reopened",),
                _iso(now_ep - 3660 * 86400), co)),
        })

    def asset_summary(self, project_id: str, *, cutoff: str = "") -> dict:
        """Asset analytics from Phase-4 intelligence (read-only)."""
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        assets = self._q(
            "SELECT id, asset_type, exposure, criticality, first_seen FROM "
            "assets WHERE project_id=? AND first_seen<=? LIMIT ?",
            (project_id, co, MAX_ASSET_ROWS))
        by_exposure = {k: 0 for k in models.EXPOSURE_LEVELS}
        by_criticality = {k: 0 for k in
                          ("unknown", "low", "medium", "high", "critical")}
        by_type = {}
        recent_cut = _iso(max(0.0, _epoch(co) - 30 * 86400))
        discovered = changed = removed = 0
        for a in assets:
            by_exposure[a["exposure"]] = by_exposure.get(
                a["exposure"], 0) + 1
            by_criticality[a["criticality"]] = by_criticality.get(
                a["criticality"], 0) + 1
            by_type[a["asset_type"]] = by_type.get(a["asset_type"], 0) + 1
            if a["first_seen"] >= recent_cut:
                discovered += 1
        changed = int(self._count_events(
            project_id, ("service.opened", "service.closed",
                         "technology.changed", "version.changed",
                         "exposure.changed"), recent_cut, co))
        removed = int(self._count_events(
            project_id, ("asset.removed",), recent_cut, co))
        tech = self._q(
            "SELECT obs_value v, COUNT(*) n FROM asset_observations WHERE "
            "project_id=? AND obs_type='technology' GROUP BY v ORDER BY n "
            "DESC LIMIT 30", (project_id,))
        serv = self._q(
            "SELECT obs_value v, COUNT(*) n FROM asset_observations WHERE "
            "project_id=? AND obs_type='service' GROUP BY v ORDER BY n DESC "
            "LIMIT 30", (project_id,))
        return redact.redact({
            "project_id": project_id, "data_cutoff": co,
            "total": len(assets),
            "by_exposure": by_exposure,
            "by_criticality": by_criticality,
            "by_type": by_type,
            "internet_facing": by_exposure.get("internet_facing", 0),
            "recently_discovered_30d": discovered,
            "recently_changed_30d": changed,
            "recently_removed_30d": removed,
            "technologies": [{"value": r["v"][:120], "count": int(r["n"])}
                             for r in tech],
            "services": [{"value": r["v"][:120], "count": int(r["n"])}
                         for r in serv],
        })

    def monitoring_summary(self, project_id: str, *, cutoff: str = "") -> dict:
        """Monitoring analytics (policies/executions/alerts/notifications +
        Phase-5 health; read-only)."""
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        import monitor as _mon
        try:
            h = _mon.MonitoringHealthService(self.svc).compute(
                project_id, now=co)
            health = {"health": h.get("health"), "score": h.get("score"),
                      "consecutive_failures": h.get("consecutive_failures"),
                      "next_expected_run": h.get("next_expected_run")}
        except Exception:
            health = {"health": "error", "score": 0}
        pol = self._one(
            "SELECT COUNT(*) n FROM monitoring_policies WHERE project_id=? "
            "AND enabled=1", (project_id,))
        exec_rows = self._q(
            "SELECT status, COUNT(*) n FROM scheduler_executions WHERE "
            "project_id=? AND created_at<=? GROUP BY status",
            (project_id, co))
        alerts = self._q(
            "SELECT state, COUNT(*) n FROM alerts WHERE project_id=? AND "
            "created_at<=? GROUP BY state", (project_id, co))
        alerts_open = int(self._one(
            "SELECT COUNT(*) n FROM alerts WHERE project_id=? AND "
            "state IN ('open','acknowledged','investigating')",
            (project_id,))["n"])
        notif = self._one(
            "SELECT COUNT(*) n FROM notifications WHERE project_id=? AND "
            "created_at<=?", (project_id, co))
        return redact.redact({
            "project_id": project_id, "data_cutoff": co, "health": health,
            "enabled_policies": int(pol["n"]),
            "executions_by_status": {str(r["status"]): int(r["n"])
                                     for r in exec_rows},
            "alerts_by_state": {str(r["state"]): int(r["n"])
                               for r in alerts},
            "open_alerts": alerts_open,
            "notifications": int(notif["n"]),
        })

    def threat_summary(self, project_id: str, *, cutoff: str = "") -> dict:
        """Phase-10 threat-intel analytics: IOC counts, matches, clusters,
        cases + open TI findings by severity (read-only, bounded, per
        project; no indicator payloads beyond counts)."""
        self.project_require(project_id)
        co = self._cutoff(cutoff)
        iocs = self._one(
            "SELECT COUNT(*) n FROM threat_indicators ti JOIN projects p "
            "ON p.org_id=ti.org_id WHERE p.id=? AND ti.first_seen<=?",

            (project_id, co))
        by_type = self._q(
            "SELECT ti.ioc_type, ti.status, COUNT(*) n FROM "

            "threat_indicators ti JOIN projects p ON p.org_id=ti.org_id "

            "WHERE p.id=? AND ti.first_seen<=? GROUP BY ti.ioc_type, "

            "ti.status", (project_id, co))
        by_tt = {}
        for r in by_type:
            by_tt.setdefault(str(r["ioc_type"]), {})[str(r["status"])] = \
                int(r["n"])
        matches = int(self._one(
            "SELECT COUNT(*) n FROM threat_matches WHERE project_id=? "

            "AND first_seen<=?", (project_id, co))["n"])
        clusters = int(self._one(
            "SELECT COUNT(*) n FROM threat_clusters WHERE project_id=? "

            "AND last_seen<=?", (project_id, co))["n"])
        cases = self._q(
            "SELECT status, COUNT(*) n FROM investigation_cases WHERE "

            "project_id=? AND created_at<=? GROUP BY status", (project_id, co))
        ti_find = self._q(
            "SELECT severity, lifecycle, COUNT(*) n FROM findings WHERE "

            "project_id=? AND rule_id LIKE 'TI-%' AND last_detected<=? "

            "GROUP BY severity, lifecycle", (project_id, co))
        open_sev = {}
        for r in ti_find:
            if str(r["lifecycle"]) not in ("resolved", "false_positive",

                                           "accepted_risk", "remediated"):
                open_sev[str(r["severity"])] = \
                    int(open_sev.get(str(r["severity"]), 0)) + int(r["n"])
        trusted = 0
        for r in by_type:
            if r["status"] in ("active",):
                trusted += int(r["n"])
        return redact.redact({
            "iocs": int(iocs["n"]),
            "iocs_active": trusted,
            "iocs_by_type": by_tt,
            "matches": matches,
            "clusters": clusters,
            "cases_by_status": {str(r["status"]): int(r["n"])
                                 for r in cases},
            "open_ti_findings": sum(open_sev.values()),
            "open_ti_by_severity": open_sev,
        })

    def bundle(self, project_id: str, *, cutoff: str = "",
               start: str = "", end: str = "") -> dict:
        """One-shot dashboard bundle (bounded; a handful of aggregate
        queries — no per-row queries, no N+1)."""
        return redact.redact({
            "project_id": project_id,
            "data_cutoff": self._cutoff(cutoff),
            "posture": self.posture(project_id, cutoff=cutoff),
            "risk": self.risk_summary(project_id, cutoff=cutoff),
            "risk_assets": self.risk_by_asset(project_id, limit=10),
            "kpis": self.kpis(project_id, cutoff=cutoff, start=start,
                              end=end),
            "trends": {
                "findings": self.finding_trend(project_id, start=start,
                                               end=end),
                "assets": self.asset_trend(project_id, start=start, end=end),
            },
            "remediation": self.remediation_summary(project_id, cutoff=cutoff),
            "assets": self.asset_summary(project_id, cutoff=cutoff),
            "monitoring": self.monitoring_summary(project_id, cutoff=cutoff),
        })


# ---------------------------------------------------------------------------
# Dashboard snapshot loader (read-only, org-filtered, bounded, redacted)
# ---------------------------------------------------------------------------
def analytics_snapshot(db_path: str, org_filter: str = "", *,
                       max_projects: int = 50,
                       cutoff: str = "") -> dict | None:
    """Per-project analytics bundle for the dashboard. `db_path` empty →
    None (panel hidden). Bounded; never crosses tenants."""
    if not db_path:
        return None
    try:
        import platform_service as pf
        svc = pf.PlatformService(db_path)
        if org_filter:
            projects = svc.project_list(org_filter)
        else:
            projects = [p for o in svc.org_list()
                        for p in svc.project_list(o.id)]
        projects = projects[: int(max_projects)]
        if not projects:
            return {"org": org_filter or "", "empty": True, "projects": [],
                    "bundles": []}
        svc_a = AnalyticsService(svc)
        bundles = []
        for p in projects:
            b = svc_a.bundle(p.id, cutoff=cutoff)
            b["project_name"] = p.name
            bundles.append(b)
        return {"org": org_filter or "", "empty": False,
                "projects": [{"id": p.id, "name": p.name} for p in projects],
                "bundles": bundles}
    except Exception:
        return None


KPI_DEFS = {
    "mttd_hours": "Mean detection latency: average hours between the "
                  "underlying scan creation and the finding's first_detected "
                  "for findings first seen inside the window (<=200 rows). "
                  "Local definition only — NOT benchmarked against any "
                  "industry figure.",
    "mttr_hours": "Mean time to resolve: average hours from first_detected "
                  "to resolved_at for findings resolved inside the window "
                  "(<=200 rows). Local definition only — NOT benchmarked.",
    "open_critical": "Findings with severity Critical whose lifecycle is in "
                     "the active set (open/acknowledged/confirmed/in_review/"
                     "reopened) at the cutoff.",
    "open_high": "Same as open_critical for High severity.",
    "open_total": "Active findings at the cutoff (active status set only).",
    "resolution_rate": "Findings resolved inside the window / all findings "
                       "first seen <= cutoff.",
    "reopen_rate": "Findings reopened inside the window / all findings "
                   "first seen <= cutoff.",
    "verification_pass_rate": "Verification requests marked passed / all "
                              "completed verifications (passed+failed). "
                              "None when no verification has completed.",
    "overdue_remediation_rate": "Open (non-closed/non-verified) tickets "
                                "with due_at < cutoff / all tickets.",
    "monitoring_success_rate": "Scheduler executions completed / "
                               "(completed+failed). None when none finished.",
    "asset_discovery_rate_30d": "Assets created in the last 30 days per "
                                "week, normalized by total assets.",
    "exposure_change_count": "exposure.changed security events inside the "
                             "window.",
}
