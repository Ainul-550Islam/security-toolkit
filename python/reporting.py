#!/usr/bin/env python3
# ============================================================================
#  reporting.py — Phase 6 enterprise reporting + compliance evidence layer.
#  ---------------------------------------------------------------------------
#  Provider-neutral reporting OVER existing platform data:
#
#    ReportRequest → ReportSnapshot → Analytics → Evidence Selection →
#    Risk Summary → Finding Details → Remediation Status → Monitoring Status
#    → Renderer (HTML / PDF / JSON)
#
#  Guarantees:
#    - deterministic: identical data + same cutoff ⇒ identical content + hash
#    - reproducible: every snapshot records exactly what data was used
#      (filter definition, data_cutoff, risk_calculation_version,
#      report_version, generated_by, generated_at)
#    - tenant-safe: every query is project-scoped; callers must authorize
#      BEFORE calling (this module never bypasses authz)
#    - auditable: generation/export/retention go through svc.audit()
#    - evidence-backed: findings reference existing evidence records
#    - bounded: hard caps with explicit truncation metadata (never silent)
#    - redacted: every output passes redact.redact()
#
#  Compliance evidence is a GENERIC mapping layer with honest statuses
#  (supported / partially_supported / not_supported / insufficient_evidence).
#  This module NEVER claims compliance or certification — those words are
#  excluded from all descriptions by construction (regression-tested).
#
#  No PKI: reports expose report_hash + generated_at + schema_version +
#  risk_version so a future signing workflow can be layered on without
#  pretending the report is cryptographically signed today.
# ============================================================================

from __future__ import annotations

import hashlib
import html
import json
import re
import time
from datetime import datetime, timezone

import analytics as _an
import errors
import metrics
import models
import redact
import store

# ---------------------------------------------------------------------------
# Bounded limits (explicit + configurable per call; never silent truncation)
# ---------------------------------------------------------------------------
DEFAULT_MAX_FINDINGS = 500
DEFAULT_MAX_ASSETS = 200
DEFAULT_MAX_EVIDENCE_PER_FINDING = 20
DEFAULT_MAX_EVIDENCE_ITEMS = 300
MAX_REPORT_INTEGRATIONS = 200
DEFAULT_MAX_TREND_DAYS = 3660
DEFAULT_MAX_REPORT_BYTES = 8_000_000
DEFAULT_RETENTION_DAYS = 90
_PAGE_MAX = 500            # pagination hard cap (rejected beyond this)
_IN_CHUNK = 200            # batching chunk for related-row lookups (no N+1)

REPORT_SCHEMA_VERSION = models.REPORT_SCHEMA_VERSION
POSTURE_VERSION = models.POSTURE_VERSION

# Filter allowlists (nothing outside these is accepted; identifiers are
# validated, values are parameterized, SQL is fixed template only).
SEVERITIES = set(models.SEVERITIES)
FINDING_STATUSES = set(models.FINDING_STATUSES)
CATEGORIES = set(models.CATEGORIES)
EXPOSURES = set(models.EXPOSURE_LEVELS)
CRITICALITIES = {"unknown", "low", "medium", "high", "critical"}
REPORT_TYPES = set(models.REPORT_TYPES)
CONTROL_CATEGORIES = set(models.CONTROL_CATEGORIES)
CONTROL_STATUSES = set(models.CONTROL_STATUSES)
REDACTED_DESC_WORDS = re.compile(
    r"\b(compliant|compliance|certified|certification)\b", re.IGNORECASE)

_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-()&]{0,127}$")
_PATH_BAD = re.compile(r"[\x00-\x1f\x7f\\]")  # control chars + backslash (no "/" — POSIX paths are fine)


def _utcnow() -> str:
    return models.utcnow()


def _iso_ts(ts: str) -> str:
    return str(ts or "")[:19]


def _bounded(value, lo: int, hi: int, label: str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise errors.ValidationError(f"{label}_invalid: not an integer")
    if v < lo or v > hi:
        raise errors.ValidationError(
            f"{label}_invalid: must be {lo}..{hi} (bounded)")
    return v


_CI_KEYS = ("ci_run_id", "gate_id", "result_id", "status", "result_hash",
            "policy_version", "policy_hash")


def _sanitize_ci(ci: dict) -> dict:
    """Allowlisted, bounded, redacted CI provenance for report metadata.
    Unknown keys fail closed (never stored)."""
    if not isinstance(ci, dict):
        raise errors.ValidationError("ci_invalid: must be an object")
    unknown = set(ci.keys()) - set(_CI_KEYS)
    if unknown:
        raise errors.ValidationError(
            f"ci_invalid: unknown field(s) {sorted(unknown)}")
    out = {}
    for k in _CI_KEYS:
        v = ci.get(k)
        if v is None:
            continue
        if not isinstance(v, (str, int)):
            raise errors.ValidationError(f"ci_{k}_invalid")
        out[k] = str(v)[:128]
    return redact.redact(out)


def _valid_ts(value: str, label: str) -> str:
    s = str(value or "").strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z?)?$", s):
        raise errors.ValidationError(
            f"{label}_invalid: expected YYYY-MM-DD or ISO datetime")
    try:
        datetime.strptime(s[:10], "%Y-%m-%d")
        if len(s) > 10:
            datetime.strptime(s[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise errors.ValidationError(f"{label}_invalid: calendar date out "
                                     "of range")
    return s if len(s) > 10 else s + "T00:00:00Z"


def validate_filters(filters: dict) -> dict:
    """Validate + normalize a report filter definition. Every field is
    allowlisted; no SQL fragments, no caller-controlled column names."""
    out: dict = {}
    f = dict(filters or {})
    if f.get("asset_id"):
        if not _TAG_RE.match(str(f["asset_id"])):
            raise errors.ValidationError("asset_id_invalid")
        out["asset_id"] = str(f["asset_id"])
    sev = f.get("severities") if f.get("severities") is not None \
        else f.get("severity")
    if sev is not None:
        if isinstance(sev, str):
            sev = [sev]
        sev = [str(s) for s in sev]
        if not sev or any(s not in SEVERITIES for s in sev):
            raise errors.ValidationError("severity_invalid")
        out["severities"] = sev
    st = f.get("statuses") if f.get("statuses") is not None \
        else f.get("status")
    if st is not None:
        if isinstance(st, str):
            st = [st]
        st = [str(s) for s in st]
        if not st or any(s not in FINDING_STATUSES for s in st):
            raise errors.ValidationError("status_invalid")
        out["statuses"] = st
    rmin = f.get("risk_min")
    if rmin is not None:
        try:
            rmin = float(rmin)
        except (TypeError, ValueError):
            raise errors.ValidationError("risk_min_invalid")
        if rmin < 0 or rmin > 100:
            raise errors.ValidationError("risk_min_invalid: 0..100")
        out["risk_min"] = rmin
    rmax = f.get("risk_max")
    if rmax is not None:
        try:
            rmax = float(rmax)
        except (TypeError, ValueError):
            raise errors.ValidationError("risk_max_invalid")
        if rmax < 0 or rmax > 100:
            raise errors.ValidationError("risk_max_invalid: 0..100")
        out["risk_max"] = rmax
    if out.get("risk_min") is not None and out.get("risk_max") is not None \
            and out["risk_min"] > out["risk_max"]:
        raise errors.ValidationError("risk_range_invalid: min > max")
    if f.get("exposure"):
        if str(f["exposure"]) not in EXPOSURES:
            raise errors.ValidationError("exposure_invalid")
        out["exposure"] = str(f["exposure"])
    if f.get("criticality"):
        if str(f["criticality"]) not in CRITICALITIES:
            raise errors.ValidationError("criticality_invalid")
        out["criticality"] = str(f["criticality"])
    if f.get("technology") is not None:
        t = str(f["technology"]).strip()
        if not t or len(t) > 120:
            raise errors.ValidationError("technology_invalid")
        out["technology"] = t
    if f.get("category"):
        if str(f["category"]) not in CATEGORIES:
            raise errors.ValidationError("category_invalid")
        out["category"] = str(f["category"])
    if f.get("start") or f.get("end"):
        start = _valid_ts(f.get("start", ""), "start") if f.get("start") else ""
        end = _valid_ts(f.get("end", ""), "end") if f.get("end") else ""
        if start and end and start > end:
            raise errors.ValidationError("range_invalid: start > end")
        out["start"] = start
        out["end"] = end
    return out


# ---------------------------------------------------------------------------
class ReportService:
    """Snapshot-based report generation over existing platform data."""

    def __init__(self, platform, *,
                 max_findings: int = DEFAULT_MAX_FINDINGS,
                 max_assets: int = DEFAULT_MAX_ASSETS,
                 max_evidence_per_finding: int =
                 DEFAULT_MAX_EVIDENCE_PER_FINDING,
                 max_report_bytes: int = DEFAULT_MAX_REPORT_BYTES):
        self.svc = platform
        self.db = platform.db
        self.analytics = _an.AnalyticsService(platform)
        self.max_findings = int(max_findings)
        self.max_assets = int(max_assets)
        self.max_evidence_per_finding = int(max_evidence_per_finding)
        self.max_report_bytes = int(max_report_bytes)

    # ------------------------------------------------------------ queries
    def _q(self, sql, params=()):
        return [dict(r) for r in self.db.query(sql, tuple(params))]

    def _one(self, sql, params=()):
        rows = self._q(sql, params)
        return rows[0] if rows else None

    def _asset(self, project_id: str, asset_id: str) -> dict:
        rows = self._q(
            "SELECT id, project_id FROM assets WHERE id=? AND project_id=? "
            "LIMIT 1", (asset_id, project_id))
        if not rows:
            raise errors.NotFoundError("no asset")
        return rows[0]

    def _finding(self, project_id: str, finding_id: str) -> dict:
        rows = self._q(
            "SELECT id, project_id FROM findings WHERE id=? AND "
            "project_id=? LIMIT 1", (finding_id, project_id))
        if not rows:
            raise errors.NotFoundError("no finding")
        return rows[0]

    # ------------------------------------------------------------- build
    def snapshot(self, project_id: str, report_type: str, *,
                 title: str = "", generated_by: str = "cli",
                 data_cutoff: str = "", filters: dict | None = None,
                 start: str = "", end: str = "",
                 store_payload: bool = False,
                 ci: dict | None = None) -> dict:
        """Build the reproducible report snapshot (no storage — see
        store_run). `store_payload=True` persists the payload (required for
        compliance_evidence snapshots). `ci` optionally embeds Phase-7
        security-gate provenance (allowlisted keys only, bounded, redacted)
        so CI gate results are available as report input — no second report
        engine is created."""
        if report_type not in REPORT_TYPES:
            raise errors.ValidationError(f"report_type_unknown: {report_type!r}")
        project = self.svc.project_require(project_id)
        org = self.svc.org_get(project.org_id)
        co = _valid_ts(data_cutoff, "data_cutoff") if data_cutoff else _utcnow()
        title = str(title or f"{report_type.replace('_',' ').title()} — "
                             f"{project.name}")[:200]
        gby = str(generated_by or "cli")[:128]
        flt = validate_filters(filters)
        f_start, f_end = start, end
        if flt.get("start"):
            f_start = f_start or flt["start"]
        if flt.get("end"):
            f_end = f_end or flt["end"]
        s, e = ("", "")
        if f_start or f_end:
            s, e = _an.bounded_range(f_start, f_end,
                                     max_days=DEFAULT_MAX_TREND_DAYS)
        elif co:
            # no explicit range: anchor the trend window AT the data cutoff
            # instead of wall-clock "now", so the same cutoff always yields
            # the same canonical report (deterministic report_hash — the
            # window never drifts between runs)
            s = _an._iso(_an._epoch(co) -
                         _an.DEFAULT_TREND_DAYS * 86400)
            e = co
        # asset filter must be project-owned (fail closed)
        if flt.get("asset_id"):
            self._asset(project_id, flt["asset_id"])
        assets, asset_trunc = self._collect_assets(project_id, flt, co)
        findings, find_trunc = self._collect_findings(project_id, flt, co)
        analytics_bundle = self.analytics.bundle(
            project_id, cutoff=co, start=s, end=e) if \
            report_type in ("executive", "trend", "technical",
                            "vulnerability", "asset_inventory") else None
        evidence_items = []
        if report_type == "compliance_evidence":
            evidence_items = EvidenceService(self.svc).derive(
                project_id, cutoff=co)
        federation_summary = None
        if report_type == "federation":
            federation_summary = self._federation_summary(org.id, co)
        integration_summary = self._integrations_summary(org.id, project.id)
        snap = {
            "metadata": {
                "org_id": org.id, "org_name": org.name,
                "project_id": project.id, "project_name": project.name,
                "report_type": report_type, "title": title,
                "generated_at": _utcnow(), "generated_by": gby,
                "data_cutoff": co,
                "risk_calculation_version":
                    self.analytics._risk_version(project_id),
                "report_version": REPORT_SCHEMA_VERSION,
                "posture_version": POSTURE_VERSION,
                "report_hash": "",
                "ci": _sanitize_ci(ci) if ci else None,
            },
            "filter": dict(flt) | {"start": s, "end": e},
            "posture": (analytics_bundle or {}).get("posture"),
            "risk": (analytics_bundle or {}).get("risk"),
            "assets": assets,
            "findings": findings,
            "remediation":
                self.analytics.remediation_summary(project_id, cutoff=co),
            "monitoring":
                self.analytics.monitoring_summary(project_id, cutoff=co),
            "threat_intel":
                self.analytics.threat_summary(project_id, cutoff=co),
            "trends": (analytics_bundle or {}).get("trends"),
            "evidence": evidence_items,
            "federation": federation_summary,
            "integrations": integration_summary,
            "truncation": {"sections": {"assets": asset_trunc,
                                        "findings": find_trunc,
                                        "integrations": {
                                            "truncated": integration_summary[
                                                "truncated"],
                                            "included_count": integration_summary[
                                                "included_count"],
                                            "original_count": integration_summary[
                                                "count"]}},
                           "truncated": bool(asset_trunc["truncated"] or
                                             find_trunc["truncated"] or
                                             integration_summary["truncated"])}, 
        }
        snap["metadata"]["report_hash"] = self.report_hash(snap)
        return redact.redact(snap)

    # --------------------------------------------------- integrations
    def _integrations_summary(self, org_id: str, project_id: str) -> dict:
        """Bounded project + organization-level integration posture.
        Uses the existing Phase-13 validator (no network test) and an
        explicit output allowlist: endpoint URLs, config JSON, credential
        references, payloads and provider errors are never report fields."""
        import integrations as _integrations

        where = ("org_id=? AND connector_kind<>'' AND "
                 "(project_id=? OR project_id='')")
        params = (org_id, project_id)
        total_row = self.db.query_one(
            "SELECT COUNT(*) n FROM external_integrations WHERE " + where,
            params)
        total = int(total_row["n"]) if total_row else 0
        rows = self.db.query(
            "SELECT id, org_id, project_id, name, connector_kind, status, "
            "health_state, last_health_check_at, circuit_state FROM "
            "external_integrations WHERE " + where +
            " ORDER BY name, id LIMIT ?", params + (MAX_REPORT_INTEGRATIONS,))
        validator = _integrations.EnterpriseIntegrationService(
            self.svc).connections
        items = []
        by_connection_status = {}
        by_health_state = {}
        for row in rows:
            status = str(row.get("status") or "unknown")
            health = str(row.get("health_state") or "unchecked")
            if health not in models.INTEGRATION_HEALTH_STATES:
                health = "unknown"
            try:
                validation = validator.validate(org_id, str(row["id"]))
                config_valid = validation["configuration_status"] == "valid"
                issues = list(validation.get("issues") or [])
            except errors.SecurityToolkitError:
                config_valid = False
                issues = ["configuration_validation_unavailable"]
            circuit = str(row.get("circuit_state") or "closed")
            reasons = []
            if not config_valid:
                reasons.extend(issues or ["configuration_invalid"])
            if circuit == "open":
                reasons.append("circuit_open")
            if health in ("degraded", "misconfigured", "unreachable",
                          "rate_limited"):
                reasons.append(health)
            if status != "enabled":
                reasons.append("connection_disabled")
            elif health in ("unchecked", "unknown"):
                reasons.append("health_not_observed")
            if not config_valid:
                security_status = "attention_required"
            elif circuit == "open" or health in (
                    "degraded", "misconfigured", "unreachable",
                    "rate_limited"):
                security_status = "degraded"
            elif status != "enabled":
                security_status = "disabled"
            elif health != "healthy":
                security_status = "not_validated"
            else:
                security_status = "operational"
            connector_kind = str(row.get("connector_kind") or "")
            items.append({
                "id": str(row["id"])[:36],
                "name": redact.redact_text(str(row.get("name") or ""))[:120],
                "integration_type": connector_kind,
                "capabilities": list(_integrations.CONNECTOR_CAPABILITIES.get(
                    connector_kind, ())),
                "enabled": status == "enabled",
                "connection_status": status,
                "health_state": health,
                "configuration_valid": bool(config_valid),
                "configuration_issues": issues[:20],
                "last_validation": str(
                    row.get("last_health_check_at") or ""),
                "security_status": security_status,
                "degraded_reason": ", ".join(dict.fromkeys(reasons))[:200],
            })
            by_connection_status[status] = \
                by_connection_status.get(status, 0) + 1
            by_health_state[health] = by_health_state.get(health, 0) + 1
        return {
            "count": total,
            "included_count": len(items),
            "enabled": sum(1 for item in items if item["enabled"]),
            "disabled": sum(1 for item in items if not item["enabled"]),
            "by_connection_status": by_connection_status,
            "by_health_state": by_health_state,
            "truncated": total > len(items),
            "items": items,
        }

    # ------------------------------------------------------ federation
    def _federation_summary(self, org_id: str, cutoff: str) -> dict:
        """Phase-12 federation report section (org-scoped; the report is
        anchored at a project but federation state is tenant-level).
        Counts + bounded recent transfers ONLY: never package payloads,
        never secret material, never webhook endpoints/credentials."""
        co = cutoff or _utcnow()
        horizon = _an._iso(_an._epoch(co) + 30 * 86400)
        out: dict = {
            "peers_by_status": {}, "active_peers": 0, "expiring_peers": 0,
            "policies_by_status": {},
            "packages": {"total": 0, "recent": []},
            "imports": {"by_status": {}, "recent_rejected": []},
            "integrity_failures": 0, "policy_violations": 0,
            "bulk_jobs_by_status": {},
            "integrations_by_status": {},
            "integration_events_by_status": {},
        }
        for r in self._q(
                "SELECT status, COUNT(*) AS n FROM federation_peers WHERE "
                "org_id=? AND created_at<=? GROUP BY status", (org_id, co)):
            out["peers_by_status"][str(r["status"])] = int(r["n"])
        out["active_peers"] = int(out["peers_by_status"].get("active", 0))
        row = self._one(
            "SELECT COUNT(*) AS n FROM federation_peers WHERE org_id=? AND "
            "status IN ('active','suspended') AND expires_at<>'' AND "
            "expires_at>? AND expires_at<=?", (org_id, co, horizon))
        out["expiring_peers"] = int(row["n"]) if row else 0
        for r in self._q(
                "SELECT status, COUNT(*) AS n FROM federation_policies WHERE "
                "org_id=? AND created_at<=? GROUP BY status", (org_id, co)):
            out["policies_by_status"][str(r["status"])] = int(r["n"])
        row = self._one(
            "SELECT COUNT(*) AS n FROM federation_packages WHERE org_id=? "
            "AND created_at<=?", (org_id, co))
        out["packages"]["total"] = int(row["n"]) if row else 0
        for r in self._q(
                "SELECT id, destination_org_id, object_count, byte_size, "
                "trust_mode, classification, status, created_at FROM "
                "federation_packages WHERE org_id=? AND created_at<=? "
                "ORDER BY created_at DESC, id DESC LIMIT 20", (org_id, co)):
            out["packages"]["recent"].append({
                "id": str(r["id"])[:36],
                "destination_org_id": str(r["destination_org_id"])[:36],
                "object_count": int(r["object_count"]),
                "byte_size": int(r["byte_size"]),
                "trust_mode": str(r["trust_mode"]),
                "classification": str(r["classification"]),
                "status": str(r["status"]),
                "created_at": str(r["created_at"])})
        for r in self._q(
                "SELECT status, COUNT(*) AS n FROM federation_imports WHERE "
                "org_id=? AND created_at<=? GROUP BY status", (org_id, co)):
            out["imports"]["by_status"][str(r["status"])] = int(r["n"])
        for r in self._q(
                "SELECT id, source_org_id, package_hash, error, created_at "
                "FROM federation_imports WHERE org_id=? AND status='rejected' "
                "AND created_at<=? ORDER BY created_at DESC, id DESC LIMIT 20",
                (org_id, co)):
            out["imports"]["recent_rejected"].append({
                "id": str(r["id"])[:36],
                "source_org_id": str(r["source_org_id"])[:36],
                "package_hash": str(r["package_hash"])[:16],
                "error": str(r["error"])[:120],
                "created_at": str(r["created_at"])})
        row = self._one(
            "SELECT COUNT(*) AS n FROM federation_imports WHERE org_id=? AND "
            "created_at<=? AND error LIKE 'integrity_%'", (org_id, co))
        out["integrity_failures"] = int(row["n"]) if row else 0
        row = self._one(
            "SELECT COUNT(*) AS n FROM federation_imports WHERE org_id=? AND "
            "created_at<=? AND error LIKE 'policy_%'", (org_id, co))
        out["policy_violations"] = int(row["n"]) if row else 0
        for r in self._q(
                "SELECT status, COUNT(*) AS n FROM jobs WHERE org_id=? AND "
                "profile='federation-bulk' AND created_at<=? GROUP BY status",
                (org_id, co)):
            out["bulk_jobs_by_status"][str(r["status"])] = int(r["n"])
        for r in self._q(
                "SELECT status, COUNT(*) AS n FROM external_integrations "
                "WHERE org_id=? AND created_at<=? GROUP BY status",
                (org_id, co)):
            out["integrations_by_status"][str(r["status"])] = int(r["n"])
        for r in self._q(
                "SELECT e.status AS st, COUNT(*) AS n FROM "
                "integration_events e WHERE e.org_id=? AND e.created_at<=? "
                "GROUP BY e.status", (org_id, co)):
            out["integration_events_by_status"][str(r["st"])] = int(r["n"])
        return out

    # ------------------------------------------------------ collections
    def _collect_assets(self, project_id: str, flt: dict,
                        co: str) -> tuple[list, dict]:
        where = ["a.project_id=?", "a.first_seen<=?"]
        params = [project_id, co]
        if flt.get("asset_id"):
            where.append("a.id=?")
            params.append(flt["asset_id"])
        if flt.get("exposure"):
            where.append("a.exposure=?")
            params.append(flt["exposure"])
        if flt.get("criticality"):
            where.append("a.criticality=?")
            params.append(flt["criticality"])
        rows = self._q(
            "SELECT a.id, a.asset_type, a.value, a.exposure, a.criticality, "
            "a.first_seen, a.last_seen FROM assets a WHERE " +
            " AND ".join(where) + f" ORDER BY a.value LIMIT "
            f"{self.max_assets + 1}", tuple(params))
        original = len(rows)
        truncated = original > self.max_assets
        rows = rows[: self.max_assets]
        # observations summary: ONE grouped query per type (no N+1)
        ids = [r["id"] for r in rows]
        obs = {}
        for chunk in _chunks(ids, _IN_CHUNK):
            ph = ",".join("?" for _ in chunk)
            for r in self._q(
                    "SELECT asset_id, obs_type, obs_value FROM "
                    "asset_observations WHERE asset_id IN (" + ph + ") "
                    "AND obs_type IN ('technology','service') LIMIT 2000",
                    tuple(chunk)):
                obs.setdefault(r["asset_id"], []).append(
                    {"type": r["obs_type"], "value": str(r["obs_value"])[:120]})
        assets = []
        for r in rows:
            d = {"id": r["id"], "asset_type": r["asset_type"],
                 "value": str(r["value"])[:200], "exposure": r["exposure"],
                 "criticality": r["criticality"],
                 "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                 "technologies": [o["value"] for o in obs.get(r["id"], [])
                                  if o["type"] == "technology"][:10],
                 "services": [o["value"] for o in obs.get(r["id"], [])
                              if o["type"] == "service"][:10]}
            assets.append(d)
        return assets, {"truncated": truncated,
                        "reason": "max_assets_reached" if truncated else "",
                        "original_count": original,
                        "included_count": len(assets)}

    def _collect_findings(self, project_id: str, flt: dict,
                          co: str) -> tuple[list, dict]:
        where = ["f.project_id=?", "f.first_detected<=?"]
        params = [project_id, co]
        if flt.get("asset_id"):
            where.append("f.asset_id=?")
            params.append(flt["asset_id"])
        if flt.get("severities"):
            where.append("f.severity IN (" +
                         ",".join("?" for _ in flt["severities"]) + ")")
            params.extend(flt["severities"])
        if flt.get("statuses"):
            where.append("f.lifecycle IN (" +
                         ",".join("?" for _ in flt["statuses"]) + ")")
            params.extend(flt["statuses"])
        if flt.get("risk_min") is not None:
            where.append("f.risk_score>=?")
            params.append(flt["risk_min"])
        if flt.get("risk_max") is not None:
            where.append("f.risk_score<=?")
            params.append(flt["risk_max"])
        if flt.get("exposure"):
            where.append("a.exposure=?")
            params.append(flt["exposure"])
        if flt.get("criticality"):
            where.append("a.criticality=?")
            params.append(flt["criticality"])
        if flt.get("category"):
            where.append("f.category=?")
            params.append(flt["category"])
        if flt.get("technology"):
            where.append(
                "EXISTS (SELECT 1 FROM asset_observations o WHERE "
                "o.asset_id=f.asset_id AND o.obs_type='technology' AND "
                "o.obs_value LIKE ?)")
            params.append("%" + flt["technology"] + "%")
        if flt.get("start"):
            where.append("f.first_detected>=?")
            params.append(flt["start"])
        if flt.get("end") and not flt.get("start"):
            where.append("f.first_detected<=?")
            params.append(flt["end"])
        elif flt.get("end"):
            where.append("f.first_detected<=?")
            params.append(flt["end"])
        sql = ("SELECT f.id, f.fingerprint, f.canonical_key, f.title, "
               "f.severity, f.confidence, f.confidence_level, f.risk_score, "
               "f.risk_level, f.priority, f.category, f.source, f.rule_id, "
               "f.template_id, f.cwe, f.cve, f.cvss, f.asset_id, f.lifecycle, "
               "f.first_detected, f.last_detected, f.resolved_at, "
               "f.reopened_at, f.occurrence_count, f.remediation, f.calc_version, "
               "a.value asset_value, a.asset_type, a.exposure, a.criticality "
               "FROM findings f LEFT JOIN assets a ON a.id=f.asset_id WHERE " +
               " AND ".join(where) + " ORDER BY f.risk_score DESC, "
               f"f.last_detected DESC LIMIT {self.max_findings + 1}")
        rows = self._q(sql, tuple(params))
        original = len(rows)
        truncated = original > self.max_findings
        rows = rows[: self.max_findings]
        ids = [r["id"] for r in rows]
        # --- batched related rows (no N+1) ---------------------------------
        evmap, tickmap, linkmap, snapmap, rootmap = {}, {}, {}, {}, {}
        for chunk in _chunks(ids, _IN_CHUNK):
            ph = ",".join("?" for _ in chunk)
            for r in self._q(
                    "SELECT e.finding_id, e.evidence_type, e.url, e.method, "
                    "e.status_code, e.request_snippet, e.response_snippet, "
                    "e.detection_reason, e.scanner, e.rule_id, e.captured_at "
                    "FROM evidence e WHERE e.finding_id IN (" + ph +
                    ") ORDER BY e.captured_at", tuple(chunk)):
                evmap.setdefault(r["finding_id"], []).append(r)
            for r in self._q(
                    "SELECT t.id, t.status, t.priority, t.owner_type, "
                    "t.owner_id, t.due_at, t.verification_status, "
                    "t.verification_attempts, t.resolved_at, "
                    "t.updated_at, t.created_at "
                    "FROM remediation_tickets t WHERE t.finding_id IN (" +
                    ph + ")", tuple(chunk)):
                tickmap[r["finding_id"]] = r
            for r in self._q(
                    "SELECT l.finding_a_id, f2.title, f2.severity, "
                    "l.relation_type, l.confidence FROM finding_links l "
                    "JOIN findings f2 ON f2.id=l.finding_b_id WHERE "
                    "l.finding_a_id IN (" + ph + ") LIMIT 2000",
                    tuple(chunk)):
                linkmap.setdefault(r["finding_a_id"], []).append(r)
            for r in self._q(
                    "SELECT s.finding_id, s.ts, s.risk_score FROM "
                    "risk_snapshots s WHERE s.finding_id IN (" + ph +
                    ") ORDER BY s.ts LIMIT 2000", tuple(chunk)):
                snapmap.setdefault(r["finding_id"], []).append(r)
            for r in self._q(
                    "SELECT rf.finding_id, rc.title, rc.confidence FROM "
                    "root_cause_findings rf JOIN root_causes rc " 
                    "ON rc.id=rf.root_cause_id WHERE rf.finding_id IN (" +
                    ph + ") LIMIT 500", tuple(chunk)):
                rootmap[r["finding_id"]] = r
        findings = []
        for r in rows:
            evs = evmap.get(r["id"], [])[: self.max_evidence_per_finding]
            ticket = tickmap.get(r["id"])
            links = linkmap.get(r["id"], [])
            snaps = snapmap.get(r["id"], [])
            root = rootmap.get(r["id"])
            findings.append({
                "id": r["id"], "fingerprint": r["fingerprint"],
                "title": str(r["title"])[:240],
                "severity": r["severity"],
                "risk_score": round(float(r["risk_score"] or 0), 1),
                "risk_level": r["risk_level"],
                "priority": r["priority"],
                "confidence": r["confidence"], "confidence_level":
                r["confidence_level"],
                "category": r["category"], "source": r["source"],
                "rule_id": r["rule_id"], "template_id": r["template_id"],
                "cwe": r["cwe"], "cve": r["cve"],
                "cvss": r["cvss"] if isinstance(r["cvss"], dict) else {},
                "asset_id": r["asset_id"],
                "asset_value": str(r["asset_value"] or "")[:200],
                "asset_type": r["asset_type"],
                "exposure": r["exposure"],
                "criticality": r["criticality"],
                "lifecycle": r["lifecycle"],
                "first_seen": r["first_detected"],
                "last_seen": r["last_detected"],
                "resolved_at": r["resolved_at"], "reopened_at":
                r["reopened_at"],
                "occurrence_count": int(r["occurrence_count"] or 1),
                "remediation": str(r["remediation"] or "")[:2000],
                "risk_calculation_version": r["calc_version"],
                "evidence": [{
                    "type": e["evidence_type"],
                    "url": str(e["url"])[:300],
                    "method": str(e["method"])[:20],
                    "status_code": str(e["status_code"])[:20],
                    "request_snippet": str(e["request_snippet"])[:800],
                    "response_snippet": str(e["response_snippet"])[:800],
                    "detection_reason": str(e["detection_reason"])[:400],
                    "scanner": str(e["scanner"])[:80],
                    "rule_id": str(e["rule_id"])[:120],
                    "captured_at": e["captured_at"],
                } for e in evs] + ([] if len(evs) < self.max_evidence_per_finding
                                   else []),
                "evidence_count": len(evmap.get(r["id"], [])),
                "remediation_ticket": None if not ticket else {
                    "id": ticket["id"], "status": ticket["status"],
                    "priority": ticket["priority"],
                    "owner_type": ticket["owner_type"],
                    "owner_id": ticket["owner_id"],
                    "updated_at": ticket["updated_at"],
                    "due_at": ticket["due_at"],
                    "verification_status": ticket["verification_status"],
                    "verification_attempts":
                        int(ticket["verification_attempts"] or 0),
                    "resolved_at": ticket["resolved_at"],
                    "created_at": ticket["created_at"]},
                "related_findings": [
                    {"id": l["finding_a_id"], "title": str(l["title"])[:200],
                     "severity": l["severity"],
                     "relation_type": l["relation_type"],
                     "confidence": round(float(l["confidence"] or 0), 2)}
                    for l in links[:10]],
                "root_cause": None if not root else {
                    "title": str(root["title"])[:200],
                    "confidence": round(float(root["confidence"] or 0), 2)},
                "risk_history": {
                    "points": len(snaps),
                    "first": round(float(snaps[0]["risk_score"]), 1)
                    if snaps else None,
                    "last": round(float(snaps[-1]["risk_score"]), 1)
                    if snaps else None},
            })
        return findings, {"truncated": truncated,
                          "reason": "max_findings_reached" if truncated
                          else "",
                          "original_count": original,
                          "included_count": len(findings)}

    # ------------------------------------------------------ renderers
    def render_json(self, snap: dict) -> dict:
        """Machine-readable report (stable schema version; redacted)."""
        meta = dict(snap.get("metadata") or {})
        payload = {
            "report": {
                "schema_version": REPORT_SCHEMA_VERSION,
                "type": meta.get("report_type", ""),
                "title": meta.get("title", ""),
                "hash": meta.get("report_hash", ""),
            },
            "metadata": {
                "organization": meta.get("org_name", ""),
                "project": meta.get("project_name", ""),
                "project_id": meta.get("project_id", ""),
                "report_type": meta.get("report_type", ""),
                "generated_at": meta.get("generated_at", ""),
                "generated_by": meta.get("generated_by", ""),
                "data_cutoff": meta.get("data_cutoff", ""),
                "risk_calculation_version":
                    meta.get("risk_calculation_version", ""),
                "report_version": REPORT_SCHEMA_VERSION,
                "posture_version": meta.get("posture_version", ""),
                "report_hash": meta.get("report_hash", ""),
                **({"ci": meta.get("ci")}
                   if meta.get("ci") is not None else {}),
            },
            "filter": snap.get("filter", {}),
            "posture": snap.get("posture"),
            "risk": snap.get("risk"),
            "assets": snap.get("assets", []),
            "findings": snap.get("findings", []),
            "remediation": snap.get("remediation"),
            "monitoring": snap.get("monitoring"),
            "trends": snap.get("trends"),
            "evidence": snap.get("evidence", []),
            "federation": snap.get("federation"),
            "integrations": snap.get("integrations"),
            "truncation": snap.get("truncation", {}),
        }
        return redact.redact(payload)

    def render_html(self, snap: dict) -> str:
        """Professional, printable, dependency-free HTML report."""
        meta = snap.get("metadata", {})
        title = html.escape(str(meta.get("title", "Security Report")))
        sections = []
        # cover ------------------------------------------------------------
        sections.append(
            f"<div class='cover'><div class='logo'>Secu<span>Pulse</span>"
            f"</div><h1>{title}</h1>"
            f"<p class='mut'>Organization: {html.escape(str(meta.get('org_name','')))}"
            f"<br>Project: {html.escape(str(meta.get('project_name','')))} "
            f"({html.escape(str(meta.get('project_id','')[:12]))})"
            f"<br>Report type: {html.escape(str(meta.get('report_type','')))}"
            f"<br>Generated: {html.escape(str(meta.get('generated_at','')))} "
            f"by {html.escape(str(meta.get('generated_by','')))}"
            f"<br>Data cutoff: {html.escape(str(meta.get('data_cutoff','')))}"
            f"<br>Risk engine: {html.escape(str(meta.get('risk_calculation_version','')))}"
            f" · Report schema: {html.escape(str(meta.get('report_version','')))}"
            f"<br>Report hash: <span class='mono'>{html.escape(str(meta.get('report_hash',''))[:24])}…</span>"
            f"</p></div>")
        # executive summary -------------------------------------------------
        posture = snap.get("posture")
        risk = snap.get("risk") or {}
        if posture or risk:
            rows = []
            sevs = risk.get("by_severity", {})
            for s in ("Critical", "High", "Medium", "Low", "Info"):
                if sevs.get(s):
                    rows.append(f"<tr><td>{html.escape(s)}</td>"
                                f"<td>{int(sevs[s])}</td></tr>")
            rows = "".join(rows) or \
                "<tr><td colspan=2 class='mut'>no active findings</td></tr>"
            sections.append(
                "<section><h2>Executive summary</h2>"
                "<div class='grid g3'>"
                f"<div class='card'><div class='small mut'>POSTURE SCORE "
                f"(posture-v1)</div><div class='big'>"
                f"{html.escape(str(posture.get('score','-')))}"
                f"</div><div class='small'>"
                f"{html.escape(str(posture.get('level','')))}</div></div>"
                f"<div class='card'><div class='small mut'>OPEN FINDINGS</div>"
                f"<div class='big'>{int(risk.get('count', 0))}</div>"
                f"<div class='small'>active status set</div></div>"
                f"<div class='card'><div class='small mut'>TOTAL RISK</div>"
                f"<div class='big'>{html.escape(str(risk.get('total_risk','0')))}"
                f"</div><div class='small'>cutoff "
                f"{html.escape(str(risk.get('data_cutoff',''))[:10])}</div></div>"
                "</div><h3>Open risk by severity</h3><table><tr><th>Severity"
                "</th><th>Count</th></tr>" + rows + "</table>"
                "<p class='mut'>Posture score is a programme-health metric "
                "(posture-v1) and is separate from finding risk scores.</p>"
                "</section>")
        # security posture ---------------------------------------------------
        if posture:
            rows = "".join(
                f"<tr><td>{html.escape(str(f['factor']))}</td>"
                f"<td>{float(f['weight'])}</td><td>{float(f['value'])}</td>"
                f"<td>{float(f['points'])}</td>"
                f"<td class='mut'>{html.escape(str(f['definition']))[:160]}</td>"
                f"</tr>" for f in posture.get("factors", []))
            sections.append(
                "<section><h2>Security posture</h2><table><tr><th>Factor</th>"
                "<th>Weight</th><th>Value</th><th>Points</th><th>Definition"
                "</th></tr>" + rows + "</table>"
                f"<p class='mut'>Basis: "
                f"{html.escape(str(posture.get('basis', {})))[:300]}</p>"
                "</section>")
        # risk overview ------------------------------------------------------
        if risk:
            buckets = " ".join(
                f"<span class='chip' "
                f"style='background:{_sev_color(k)}'>{v} {html.escape(str(k))}"
                f"</span>" for k, v in risk.get("by_severity", {}).items())
            sections.append(
                "<section><h2>Risk overview</h2>"
                f"<div class='card'><h3>Distribution</h3>" +
                (buckets if buckets else "<span class='mut'>none</span>") +
                "</div>"
                "<h3>Risk by asset</h3><table><tr><th>Asset</th><th>Findings"
                "</th><th>Risk</th><th>Crit</th><th>High</th></tr>"
                + "".join(
                    f"<tr><td class='mono'>{html.escape(str(a.get('asset_value','')))}"
                    f"</td><td>{int(a['findings'])}</td>"
                    f"<td>{float(a['risk_total'])}</td>"
                    f"<td>{int(a['critical'])}</td><td>{int(a['high'])}</td>"
                    f"</tr>" for a in (snap.get('_risk_assets') or
                                       self.analytics.risk_by_asset(
                                           meta.get("project_id", ""),
                                           limit=10))) +
                "</table></section>")
        # asset overview -----------------------------------------------------
        assets = snap.get("assets", [])
        sections.append(
            "<section><h2>Asset overview</h2><table><tr><th>Asset</th>"
            "<th>Type</th><th>Exposure</th><th>Criticality</th>"
            "<th>Technologies</th></tr>"
            + "".join(
                f"<tr><td class='mono'>{html.escape(str(a.get('value','')))}"
                f"</td><td>{html.escape(str(a.get('asset_type','')))}</td>"
                f"<td>{html.escape(str(a.get('exposure','')))}</td>"
                f"<td>{html.escape(str(a.get('criticality','')))}</td>"
                f"<td class='mut'>{html.escape(', '.join(a.get('technologies', []))[:120])}"
                f"</td></tr>" for a in assets[:200]) or
            "<tr><td colspan=5 class='mut'>no assets in scope</td></tr>"
            + "</table></section>")
        # findings -----------------------------------------------------------
        findings = snap.get("findings", [])
        rows = "".join(
            f"<tr><td><span class='chip' "
            f"style='background:{_sev_color(f['severity'])}'>"
            f"{html.escape(str(f['severity']))}</span></td>"
            f"<td>{html.escape(str(f['title']))[:90]}</td>"
            f"<td>{round(float(f.get('risk_score') or 0), 1)}</td>"
            f"<td>{html.escape(str(f.get('lifecycle','')))}</td>"
            f"<td class='mono mut'>{html.escape(str(f.get('asset_value',''))[:40])}"
            f"</td></tr>" for f in findings[:200])
        sections.append(
            "<section><h2>Critical & high findings</h2>"
            "<h3>Open by risk</h3><table><tr><th>Severity</th><th>Title</th>"
            "<th>Risk</th><th>Status</th><th>Asset</th></tr>" +
            (rows or "<tr><td colspan=5 class='mut'>none</td></tr>") +
            "</table></section>")
        # finding details -----------------------------------------------------
        details = []
        for f in findings[: self.max_findings]:
            evs = f.get("evidence", [])
            ev_html = "".join(
                f"<div class='ev'><b>{html.escape(str(e.get('type','')))}"
                f"</b> — {html.escape(str(e.get('url','')))} "
                f"<span class='mut'>({html.escape(str(e.get('method','')))} "
                f"{html.escape(str(e.get('status_code','')))})</span>"
                + (f"<br>{html.escape(str(e.get('request_snippet',''))[:200])}"
                   + (" …" if len(str(e.get('request_snippet', ''))) > 200
                      else "")) +
                f"<br>{html.escape(str(e.get('detection_reason','')))}</div>"
                for e in evs[:10]) or "<div class='mut'>no evidence records" \
                "</div>"
            tick = f.get("remediation_ticket")
            tick_html = ("<span class='mut'>no remediation ticket</span>" if
                         not tick else
                         f"ticket {html.escape(str(tick['id'])[:12])} · "
                         f"{html.escape(str(tick['status']))} · "
                         f"due {html.escape(str(tick['due_at']))} · "
                         f"verification "
                         f"{html.escape(str(tick.get('verification_status') or '—'))} "
                         f"({int(tick.get('verification_attempts') or 0)} "
                         f"attempts)")
            details.append(
                f"<details class='find'><summary>"
                f"<span class='chip' style='background:"
                f"{_sev_color(f['severity'])}'>{html.escape(str(f['severity']))}"
                f"</span><span class='t'>{html.escape(str(f['title']))}</span>"
                f"<span class='mono mut'>{html.escape(str(f['fingerprint']))[:16]}</span>"
                f"</summary><div class='body'>"
                f"<div class='small mut'>ASSET</div><div class='mono'>"
                f"{html.escape(str(f.get('asset_value','')))} "
                f"({html.escape(str(f.get('exposure','')))})</div>"
                f"<div class='small mut'>RISK · CONFIDENCE</div><div>"
                f"{round(float(f.get('risk_score') or 0),1)} "
                f"{html.escape(str(f.get('risk_level','')))} · "
                f"{html.escape(str(f.get('confidence','')))}</div>"
                f"<div class='small mut'>LIFECYCLE</div><div>"
                f"{html.escape(str(f.get('lifecycle','')))} · first seen "
                f"{html.escape(str(f.get('first_seen',''))[:10])} · last seen "
                f"{html.escape(str(f.get('last_seen',''))[:10])} · "
                f"{int(f.get('occurrence_count') or 1)} occurrence(s)"
                f"{' · reopened ' + html.escape(str(f.get('reopened_at',''))[:10]) if f.get('reopened_at') else ''}"
                f"</div>"
                f"<div class='small mut'>REMEDIATION</div>"
                f"<div class='ev'>{html.escape(str(f.get('remediation','')))}</div>"
                f"<div class='small mut'>EVIDENCE</div>{ev_html}"
                f"<div class='small mut'>TRACKING</div><div>{tick_html}</div>"
                f"</div></details>")
        sections.append(
            "<section><h2>Finding details</h2>" +
            ("".join(details) if details else
             "<div class='card mut'>no findings in scope</div>") +
            "</section>")
        # remediation --------------------------------------------------------
        rem = snap.get("remediation") or {}
        rrows = "".join(
            f"<tr><td>{html.escape(str(k))}</td><td>{int(v)}</td></tr>"
            for k, v in sorted((rem.get("by_status") or {}).items()))
        sections.append(
            "<section><h2>Remediation status</h2><div class='grid g3'>"
            f"<div class='card'><div class='small mut'>TICKETS</div>"
            f"<div class='big'>{int(rem.get('total', 0))}</div></div>"
            f"<div class='card'><div class='small mut'>OVERDUE</div>"
            f"<div class='big'>{int(rem.get('overdue_count', 0))}</div></div>"
            f"<div class='card'><div class='small mut'>AVG AGE (DAYS)</div>"
            f"<div class='big'>{html.escape(str(rem.get('avg_remediation_age_days','0')))}"
            f"</div></div></div>"
            "<table><tr><th>Status</th><th>Count</th></tr>"
            + (rrows or "<tr><td colspan=2 class='mut'>no tickets</td></tr>")
            + "</table></section>")
        # monitoring ---------------------------------------------------------
        mon = snap.get("monitoring") or {}
        health = mon.get("health") or {}
        mrows = "".join(
            f"<tr><td>{html.escape(str(k))}</td><td>{int(v)}</td></tr>"
            for k, v in sorted((mon.get("executions_by_status") or {}).items()))
        sections.append(
            "<section><h2>Monitoring status</h2><div class='grid g3'>"
            f"<div class='card'><div class='small mut'>HEALTH</div>"
            f"<div class='big'>{html.escape(str(health.get('health','-')))}"
            f"</div><div class='small'>score "
            f"{html.escape(str(health.get('score','-')))}</div></div>"
            f"<div class='card'><div class='small mut'>POLICIES ENABLED</div>"
            f"<div class='big'>{int(mon.get('enabled_policies', 0))}</div></div>"
            f"<div class='card'><div class='small mut'>OPEN ALERTS</div>"
            f"<div class='big'>{int(mon.get('open_alerts', 0))}</div></div>"
            "</div><h3>Scheduled executions</h3><table><tr><th>Status</th>"
            "<th>Count</th></tr>" +
            (mrows or "<tr><td colspan=2 class='mut'>none</td></tr>") +
            "</table></section>")
        # trend --------------------------------------------------------------
        trends = snap.get("trends") or {}
        finding_t = (trends.get("findings") or {}).get("created") or []
        trend_rows = "".join(
            f"<tr><td>{html.escape(str(next(iter(p))))}</td>"
            f"<td>{int(next(iter(p.values())))}</td></tr>"
            for p in finding_t[-30:])
        if trend_rows:
            sections.append(
                "<section><h2>Trend (findings created)</h2><table><tr><th>"
                "Bucket</th><th>Created</th></tr>" + trend_rows +
                "</table></section>")
        # compliance evidence -------------------------------------------------
        evidence = snap.get("evidence") or []
        if evidence:
            erows = "".join(
                f"<tr><td>{html.escape(str(e.get('control_category','')))}"
                f"</td><td>{html.escape(str(e.get('status','')))}</td>"
                f"<td>{html.escape(str(e.get('source_type','')))}</td>"
                f"<td class='mono mut'>{html.escape(str(e.get('source_id',''))[:24])}"
                f"</td><td class='mut'>{html.escape(str(e.get('description','')))[:140]}</td>"
                f"</tr>" for e in evidence[:100])
            sections.append(
                "<section><h2>Compliance evidence (generic controls)</h2>"
                "<p class='mut'>Evidence categories only — this report does "
                "not claim compliance with any standard or certification.</p>"
                "<table><tr><th>Category</th><th>Status</th><th>Source</th>"
                "<th>Source id</th><th>Description</th></tr>" + erows +
                "</table></section>")
        # integrations (Phase 13) ---------------------------------------------
        integrations = snap.get("integrations")
        if isinstance(integrations, dict):
            integration_rows = "".join(
                "<tr>"
                f"<td>{html.escape(str(i.get('name', '')))}</td>"
                f"<td>{html.escape(str(i.get('integration_type', '')))}</td>"
                f"<td>{'yes' if i.get('enabled') else 'no'}</td>"
                f"<td>{html.escape(str(i.get('health_state', '')))}</td>"
                f"<td class='mut'>{html.escape(str(i.get('last_validation', '')))}</td>"
                f"<td>{'valid' if i.get('configuration_valid') else 'invalid'}</td>"
                f"<td>{html.escape(str(i.get('security_status', '')))}</td>"
                f"<td class='mut'>{html.escape(str(i.get('degraded_reason', '')))}</td>"
                "</tr>"
                for i in integrations.get("items", [])[:MAX_REPORT_INTEGRATIONS])
            if not integration_rows:
                integration_rows = (
                    "<tr><td colspan='8' class='mut'>no integration "
                    "connections in this project or organization scope</td></tr>")
            trunc_note = ("<p class='mut'>Connection list truncated at "
                          f"{MAX_REPORT_INTEGRATIONS} entries.</p>"
                          if integrations.get("truncated") else "")
            sections.append(
                "<section><h2>Enterprise integrations</h2>"
                "<p class='mut'>Provider-neutral connection metadata only. "
                "Endpoint URLs, configuration values, credentials and event "
                "payloads are excluded. Health is not inferred from "
                "configuration validation.</p>"
                f"<p>Connections: {int(integrations.get('count', 0))}; "
                f"enabled: {int(integrations.get('enabled', 0))}; "
                f"disabled: {int(integrations.get('disabled', 0))}</p>"
                "<table><tr><th>Name</th><th>Type</th><th>Enabled</th>"
                "<th>Health</th><th>Last validation</th>"
                "<th>Configuration</th><th>Security status</th>"
                "<th>Degraded reason</th></tr>" + integration_rows +
                "</table>" + trunc_note + "</section>")
        # federation (Phase 12) ----------------------------------------------
        fed = snap.get("federation") or {}
        if fed:
            def _kv_table(d):
                return "".join(
                    f"<tr><td>{html.escape(str(k))}</td>"
                    f"<td>{int(v)}</td></tr>"
                    for k, v in sorted((d or {}).items()))
            prow = "".join(
                f"<tr><td class='mono mut'>{html.escape(str(p.get('id',''))[:12])}…"
                f"</td><td class='mono mut'>{html.escape(str(p.get('destination_org_id',''))[:12])}…"
                f"</td><td>{int(p.get('object_count', 0))}</td>"
                f"<td>{int(p.get('byte_size', 0))}</td>"
                f"<td>{html.escape(str(p.get('trust_mode','')))}</td>"
                f"<td>{html.escape(str(p.get('classification','')))}</td>"
                f"<td>{html.escape(str(p.get('status','')))}</td>"
                f"<td class='mut'>{html.escape(str(p.get('created_at','')))}</td></tr>"
                for p in (fed.get("packages") or {}).get("recent", [])[:20])
            rrow = "".join(
                f"<tr><td class='mono mut'>{html.escape(str(r.get('package_hash',''))[:16])}…"
                f"</td><td class='mono mut'>{html.escape(str(r.get('source_org_id',''))[:12])}…"
                f"</td><td class='mut'>{html.escape(str(r.get('error','')))}</td>"
                f"<td class='mut'>{html.escape(str(r.get('created_at','')))}</td></tr>"
                for r in (fed.get("imports") or {}).get(
                    "recent_rejected", [])[:20])
            sections.append(
                "<section><h2>Federation &amp; evidence exchange</h2>"
                "<p class='mut'>Cross-organization transfer state "
                "(counts and identifiers only — never package payloads or "
                "secret material). Active peers: "
                f"{int(fed.get('active_peers', 0))} · expiring ≤30d: "
                f"{int(fed.get('expiring_peers', 0))} · packages: "
                f"{int((fed.get('packages') or {}).get('total', 0))} · "
                f"integrity failures: {int(fed.get('integrity_failures', 0))}"
                f" · policy violations: {int(fed.get('policy_violations', 0))}"
                "</p>"
                "<h3>Peers by status</h3><table><tr><th>Status</th>"
                "<th>Count</th></tr>" +
                _kv_table(fed.get("peers_by_status")) + "</table>"
                "<h3>Policies by status</h3><table><tr><th>Status</th>"
                "<th>Count</th></tr>" +
                _kv_table(fed.get("policies_by_status")) + "</table>"
                "<h3>Imports by status</h3><table><tr><th>Status</th>"
                "<th>Count</th></tr>" +
                _kv_table((fed.get("imports") or {}).get("by_status")) +
                "</table><h3>Bulk jobs by status</h3><table>"
                "<tr><th>Status</th><th>Count</th></tr>" +
                _kv_table(fed.get("bulk_jobs_by_status")) + "</table>"
                "<h3>Recent packages</h3><table><tr><th>Package</th>"
                "<th>Destination</th><th>Objects</th><th>Bytes</th>"
                "<th>Trust</th><th>Class</th><th>Status</th><th>Created</th>"
                "</tr>" + (prow or "<tr><td colspan='8' class='mut'>none</td></tr>") +
                "</table><h3>Recent rejected imports</h3><table>"
                "<tr><th>Package hash</th><th>Source org</th><th>Reason</th>"
                "<th>Created</th></tr>" +
                (rrow or "<tr><td colspan='4' class='mut'>none</td></tr>") +
                "</table></section>")
        # appendix -----------------------------------------------------------
        trunc = snap.get("truncation", {})
        appendix = ""
        if trunc.get("truncated"):
            parts = []
            for sec, info in (trunc.get("sections") or {}).items():
                if info.get("truncated"):
                    parts.append(
                        f"<tr><td>{html.escape(str(sec))}</td><td>"
                        f"{int(info.get('original_count', 0))}</td><td>"
                        f"{int(info.get('included_count', 0))}</td><td>"
                        f"{html.escape(str(info.get('reason','')))}</td></tr>")
            appendix = ("<section><h2>Appendix — limits</h2><p>Bounded "
                        "report limits were reached. Nothing was hidden "
                        "silently:</p><table><tr><th>Section</th>"
                        "<th>Original</th><th>Included</th><th>Reason</th></tr>"
                        + "".join(parts) + "</table></section>")
        page = (f"<html><head><meta charset='utf-8'><title>{title}</title>"
                "<style>" + _CSS + "</style></head><body><div class='wrap'>" +
                "".join(sections) + appendix +
                "<footer>Generated by SecuPulse reporting (deterministic, "
                "snapshot-based). Evidence-backed; no compliance claims. "
                f"Report hash: {html.escape(str(meta.get('report_hash',''))[:24])}"
                "…</footer></div></body></html>")
        return page

    # -------------------------------------------------------- integrity
    def canonical(self, snap: dict) -> str:
        """Canonical payload for the report hash. Drops nondeterministic
        metadata (generated_at, generated_by, byte-size, report_hash) so
        identical data always yields the same hash."""
        import copy
        c = copy.deepcopy(snap)
        c.pop("generated_at", None)
        m = dict(c.get("metadata", {}))
        m.pop("generated_at", None)
        m.pop("generated_by", None)
        m.pop("report_hash", None)
        c["metadata"] = m
        return json.dumps(c, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)

    def report_hash(self, snap: dict) -> str:
        return hashlib.sha256(self.canonical(snap).encode("utf-8")).hexdigest()

    # ---------------------------------------------------------- lifecycle
    def store_run(self, snap: dict, *, store_payload: bool = False,
                  evidence_snapshot: bool = False) -> dict:
        """Persist report metadata (+ payload when requested). Evidence
        snapshots are always stored and marked immutable."""
        meta = snap.get("metadata", {})
        keep_payload = bool(store_payload) or bool(evidence_snapshot) or \
            meta.get("report_type") == "compliance_evidence"
        immutable_flag = 1 if evidence_snapshot else 0
        import time as _t
        run_id = models.stable_id(
            models.NS_REPORT,
            f"{meta.get('project_id','')}|{meta.get('report_type','')}|"
            f"{meta.get('generated_at','')}|"
            f"{str(meta.get('report_hash',''))[:16]}|{_t.monotonic_ns()}")
        payload = self.render_json(snap)
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
        trunc = snap.get("truncation", {})
        original = incl = 0
        reason = ""
        for info in (trunc.get("sections") or {}).values():
            original += int(info.get("original_count", 0))
            incl += int(info.get("included_count", 0))
            if info.get("truncated"):
                reason = str(info.get("reason", ""))
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO report_runs (id, org_id, project_id, "
                "report_type, title, status, schema_version, risk_version, "
                "data_cutoff, report_hash, generated_at, generated_by, "
                "truncated, truncation_reason, original_count, "
                "included_count, byte_size, immutable, created_at) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, meta.get("org_id", ""), meta.get("project_id", ""),
                 meta.get("report_type", ""), str(meta.get("title", ""))[:200],
                 "generated", REPORT_SCHEMA_VERSION,
                 meta.get("risk_calculation_version", ""),
                 meta.get("data_cutoff", ""), meta.get("report_hash", ""),
                 meta.get("generated_at", ""),
                 str(meta.get("generated_by", ""))[:128],
                 1 if trunc.get("truncated") else 0, reason[:200], original,
                 incl, len(raw), immutable_flag, _utcnow()))
            if keep_payload:
                conn.execute(
                    "INSERT OR REPLACE INTO report_payloads (report_id, "
                    "payload, payload_hash, created_at) VALUES (?,?,?,?)",
                    (run_id, raw.decode("utf-8"),
                     hashlib.sha256(raw).hexdigest(), _utcnow()))
        self.svc.audit("report.generated",
                       object_type="report", object_id=run_id,
                       org_id=meta.get("org_id", ""),
                       project_id=meta.get("project_id", ""),
                       actor=meta.get("generated_by", "cli"),
                       metadata={"report_type": meta.get("report_type", ""),
                                 "report_hash":
                                 str(meta.get("report_hash", ""))[:32],
                                 "findings": incl,
                                 "truncated": bool(trunc.get("truncated"))})
        metrics.inc("reports_generated")
        return self.get_run(run_id)

    def get_run(self, report_id: str, *, with_payload: bool = False) -> dict:
        rows = self._q("SELECT * FROM report_runs WHERE id=? LIMIT 1",
                       (report_id,))
        if not rows:
            raise errors.NotFoundError("no report")
        out = dict(rows[0])
        if with_payload:
            p = self._one("SELECT payload, payload_hash FROM "
                          "report_payloads WHERE report_id=?", (report_id,))
            out["payload"] = store.loads(p["payload"]) if p else None
            out["payload_hash"] = p["payload_hash"] if p else ""
        return redact.redact(out)

    def list_runs(self, project_id: str, *, limit: int = 50,
                  offset: int = 0, report_type: str = "") -> dict:
        self.svc.project_require(project_id)
        limit = _bounded(limit, 1, _PAGE_MAX, "limit")
        offset = _bounded(offset, 0, 100000, "offset")
        if report_type:
            if report_type not in REPORT_TYPES:
                raise errors.ValidationError(
                    f"report_type_unknown: {report_type!r}")
            rows = self._q(
                "SELECT * FROM report_runs WHERE project_id=? AND "
                "report_type=? ORDER BY created_at DESC, id DESC LIMIT ? "
                "OFFSET ?", (project_id, report_type, limit, offset))
        else:
            rows = self._q(
                "SELECT * FROM report_runs WHERE project_id=? ORDER BY "
                "created_at DESC, id DESC LIMIT ? OFFSET ?",
                (project_id, limit, offset))
        total = int(self._one(
            "SELECT COUNT(*) n FROM report_runs WHERE project_id=?",
            (project_id,))["n"])
        return {"count": len(rows), "total": total, "limit": limit,
                "offset": offset, "reports": [redact.redact(dict(r))
                                              for r in rows]}

    def render_bytes(self, snap: dict, fmt: str) -> bytes:
        fmt = str(fmt or "json").lower()
        if fmt == "json":
            raw = json.dumps(self.render_json(snap), sort_keys=True,
                             separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        elif fmt == "html":
            raw = self.render_html(snap).encode("utf-8")
        elif fmt == "pdf":
            import pdf_report as _pdf
            raw = _pdf.render_report_pdf(snap)
        else:
            raise errors.ValidationError(f"format_unknown: {fmt!r}")
        if len(raw) > self.max_report_bytes:
            raise errors.ValidationError(
                "report_too_large: bounded at "
                f"{self.max_report_bytes} bytes — narrow the filters or "
                "reduce the finding limit")
        return raw

    def export(self, report_id: str, fmt: str, *,
               out_path: str = "") -> bytes:
        """Export a stored report. `out_path` optional; when given it must
        be a safe filename under an existing directory (no traversal, no
        absolute paths, no control characters)."""
        run = self.get_run(report_id)
        payload = run.get("payload")
        if payload is None:
            snap = self._rebuild_from_run(run)
        else:
            snap = payload
        raw = self.render_bytes(snap if isinstance(snap, dict) else snap, fmt)
        if out_path:
            target = secure_export_path(out_path)
            with open(target, "wb") as fh:
                fh.write(raw)
        self.svc.audit("export.generated", object_type="report",
                       object_id=report_id, org_id=run["org_id"],
                       project_id=run["project_id"],
                       actor="cli",
                       metadata={"format": fmt, "size": len(raw)})
        metrics.inc("reports_exported")
        return raw

    def _rebuild_from_run(self, run: dict) -> dict:
        """Rebuild a snapshot for reports stored without payload: the
        metadata is authoritative; data sections are empty placeholders and
        the truncation flag explains what is available."""
        return {
            "metadata": {
                "org_id": run["org_id"], "org_name": "", 
                "project_id": run["project_id"], "project_name": "",
                "report_type": run["report_type"], "title": run["title"],
                "generated_at": run["generated_at"],
                "generated_by": run["generated_by"],
                "data_cutoff": run["data_cutoff"],
                "risk_calculation_version": run["risk_version"],
                "report_version": run["schema_version"],
                "posture_version": POSTURE_VERSION,
                "report_hash": run["report_hash"],
            },
            "filter": {}, "posture": None, "risk": None, "assets": [],
            "findings": [], "remediation": None, "monitoring": None,
            "trends": None, "evidence": [],
            "truncation": {"sections": {},
                           "truncated": bool(run["truncated"]),
                           "note": "payload not retained; metadata only"},
        }

    # --------------------------------------------------------- retention
    def retention_sweep(self, *, days: int = DEFAULT_RETENTION_DAYS,
                        now: str = "", project_id: str = "") -> dict:
        """Delete expired, NON-immutable report runs (evidence snapshots and
        immutable payloads are never deleted). Audited once per sweep."""
        days = _bounded(days, 1, 3650, "days")
        cutoff = _iso_ts(now) if now else _utcnow()
        ep = (datetime.strptime(cutoff[:19].replace("T", " "),
                                "%Y-%m-%d %H:%M:%S")
              .replace(tzinfo=timezone.utc).timestamp()) - days * 86400
        old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))
        where = ["created_at<?", "immutable=0", "report_type<>?"]
        params: list = [old, "compliance_evidence"]
        if project_id:
            self.svc.project_require(project_id)
            where.append("project_id=?")
            params.append(project_id)
        rows = self._q(
            "SELECT id, org_id, project_id FROM report_runs WHERE " +
            " AND ".join(where), tuple(params))
        n = 0
        for r in rows:
            with self.db.transaction() as conn:
                cur = conn.execute("DELETE FROM report_runs WHERE id=? AND "
                                   "immutable=0 AND report_type<>?",
                                   (r["id"], "compliance_evidence"))
                n += max(0, cur.rowcount)
        if n:
            self.svc.audit("retention.sweep", object_type="organization",
                           object_id=project_id or
                           (rows[0]["org_id"] if rows else ""),
                           org_id=rows[0]["org_id"] if rows else "",
                           project_id=project_id or "", actor="scheduler",
                           metadata={"kind": "reports", "removed": n,
                                     "days": days})
            metrics.inc("reports_retained")
        return {"removed": n, "days": days, "cutoff": old}


# ---------------------------------------------------------------------------
class EvidenceService:
    """Generic compliance evidence mapping. Maps ACTUAL platform data to
    generic control categories with honest statuses. NEVER claims
    compliance/certification; descriptions are sanitized against those
    words. Every item carries provenance + a deterministic hash."""

    def __init__(self, platform):
        self.svc = platform
        self.db = platform.db
        self.analytics = _an.AnalyticsService(platform)

    def _q(self, sql, params=()):
        return [dict(r) for r in self.db.query(sql, tuple(params))]

    def _one(self, sql, params=()):
        rows = self._q(sql, params)
        return rows[0] if rows else None

    def derive(self, project_id: str, *, cutoff: str = "") -> list[dict]:
        """Derive evidence items from current platform state. Each item is
        traceable (source_type/source_id/project/timestamp/cutoff/hash)."""
        self.svc.project_require(project_id)
        project = self.svc.project_get(project_id)
        co = _valid_ts(cutoff, "data_cutoff") if cutoff else _utcnow()
        out = []
        for builder in (self._ev_access_control, self._ev_asset_management,
                        self._ev_vulnerability_management,
                        self._ev_logging_monitoring,
                        self._ev_change_management,
                        self._ev_incident_response,
                        self._ev_data_protection,
                        self._ev_security_testing,
                        self._ev_authentication,
                        self._ev_retention,
                        self._ev_secrets_management,
                        self._ev_monitoring):
            item = builder(project_id, project, co)
            if item:
                item["project_id"] = project_id
                item["org_id"] = project.org_id
                item["data_cutoff"] = co
                item["id"] = models.stable_id(
                    models.NS_CEVID,
                    f"{project_id}|{item['control_category']}|"
                    f"{item['source_type']}|{item.get('source_id','')}")
                item["description"] = _sanitize_desc(item["description"])
                item["evidence_hash"] = self._hash_of(item)
                out.append(item)
        return redact.redact(out)

    def _ev_authentication(self, project_id, project, co):
        mfa = self._one(
            "SELECT COUNT(*) n FROM mfa_secrets WHERE org_id=? AND enabled=1",
            (project.org_id,))
        sess = self._one(
            "SELECT COUNT(*) n FROM sessions WHERE user_id IN "
            "(SELECT id FROM users WHERE org_id=?) AND expires_at>?",
            (project.org_id, co))
        sso = self._one(
            "SELECT COUNT(*) n FROM sso_providers WHERE org_id=? AND "
            "enabled=1", (project.org_id,))
        has_any = int(sess["n"]) > 0
        supported = has_any and int(mfa["n"]) > 0
        status = "supported" if supported else \
            "partially_supported" if has_any else "not_supported"
        return {"control_category": "authentication",
                "source_type": "identity_records", "source_id": project.org_id,
                "evidence_ts": co,
                "description": "Authentication evidence (Phase-2/8): %d "
                "active MFA enrollment(s), %d live session(s), %d enabled SSO "
                "provider(s). Sessions are stored as hashes only."
                % (int(mfa["n"]), int(sess["n"]), int(sso["n"])),
                "status": status,
                "counts": {"mfa_enrollments": int(mfa["n"]),
                           "live_sessions": int(sess["n"]),
                           "sso_providers": int(sso["n"])}}

    def _ev_retention(self, project_id, project, co):
        pol = self._one(
            "SELECT COUNT(*) n FROM retention_policies WHERE org_id=? AND "
            "(project_id=? OR project_id='') AND enabled=1",
            (project.org_id, project_id))
        holds = self._one(
            "SELECT COUNT(*) n FROM retention_holds WHERE org_id=? AND "
            "released_at=''", (project.org_id,))
        runs = self._one(
            "SELECT COUNT(*) n FROM retention_runs WHERE org_id=? AND "
            "started_at<=?", (project.org_id, co))
        has_any = int(pol["n"]) > 0
        status = "supported" if has_any else \
            "partially_supported" if int(holds["n"]) > 0 else "not_supported"
        return {"control_category": "retention",
                "source_type": "retention_policies", "source_id": project_id,
                "evidence_ts": co,
                "description": "Retention governance (Phase-11): %d enabled "
                "retention policy(ies), %d active legal/regulatory hold(s), "
                "%d retention execution record(s) (dry-run/preview audited)."
                % (int(pol["n"]), int(holds["n"]), int(runs["n"])),
                "status": status,
                "counts": {"policies": int(pol["n"]),
                           "active_holds": int(holds["n"]),
                           "runs": int(runs["n"])}}

    def _ev_secrets_management(self, project_id, project, co):
        reg = self._one(
            "SELECT COUNT(*) n FROM secrets_registry WHERE org_id=? AND "
            "created_at<=?", (project.org_id, co))
        cred_ev = self._one(
            "SELECT COUNT(*) n FROM audit_events WHERE org_id=? AND action "
            "IN ('credential.created','credential.revoked',"
            "'credential.rotated','secret.registered','secret.revoked') "
            "AND ts<=?", (project.org_id, co))
        has_any = int(reg["n"]) > 0
        status = "supported" if has_any else \
            "partially_supported" if int(cred_ev["n"]) > 0 else "not_supported"
        return {"control_category": "secrets_management",
                "source_type": "secrets_registry", "source_id": project.org_id,
                "evidence_ts": co,
                "description": "Secret/credential governance (Phase-11): %d "
                "metadata-registered secret(s) (search hashes only — material "
                "never stored by the registry) and %d credential lifecycle "
                "audit event(s) across the platform."
                % (int(reg["n"]), int(cred_ev["n"])),
                "status": status,
                "counts": {"registered_secrets": int(reg["n"]),
                           "credential_events": int(cred_ev["n"])}}

    def _ev_monitoring(self, project_id, project, co):
        ex = self._one(
            "SELECT COUNT(*) n FROM scheduler_executions WHERE project_id=? "
            "AND created_at<=?", (project_id, co))
        health = self._one(
            "SELECT COUNT(*) n FROM monitoring_health WHERE project_id=?",
            (project_id,))
        notif = self._one(
            "SELECT COUNT(*) n FROM notifications WHERE project_id=? AND "
            "created_at<=?", (project_id, co))
        has_any = int(ex["n"]) > 0
        status = "supported" if has_any and int(health["n"]) > 0 else \
            "partially_supported" if has_any else "not_supported"
        return {"control_category": "monitoring",
                "source_type": "scheduler_records", "source_id": project_id,
                "evidence_ts": co,
                "description": "Continuous-monitoring evidence (Phase-5): %d "
                "scheduled execution(s), %d health record(s), %d "
                "notification(s) — no second scheduler was introduced."
                % (int(ex["n"]), int(health["n"]), int(notif["n"])),
                "status": status,
                "counts": {"executions": int(ex["n"]),
                           "health_records": int(health["n"]),
                           "notifications": int(notif["n"])}}

    def _hash_of(self, item: dict) -> str:
        body = {k: v for k, v in item.items()
                if k not in ("id", "evidence_hash", "project_id", "org_id")}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    # -- each builder returns {control_category, source_type, source_id,
    #    evidence_ts, description, status, counts} or None ---------------
    def _categorize(self, *, supported: bool, partial: bool, has_any: bool,
                    diagnostic: str) -> str:
        if not has_any:
            return "not_supported"
        if supported:
            return "supported"
        if partial:
            return "partially_supported"
        return "insufficient_evidence" if not diagnostic else \
            "partially_supported"

    def _ev_access_control(self, project_id, project, co):
        users = self._one(
            "SELECT COUNT(*) n FROM users WHERE org_id=? AND status='active'",
            (project.org_id,))
        members = self._one(
            "SELECT COUNT(*) n FROM project_members WHERE project_id=?",
            (project_id,))
        roles = self._one(
            "SELECT COUNT(DISTINCT role) n FROM project_members WHERE "
            "project_id=?", (project_id,))
        has_any = int(members["n"]) > 0
        supported = int(roles["n"]) >= 2
        partial = int(members["n"]) > 0
        status = "supported" if supported else "partially_supported" \
            if partial else "not_supported"
        return {"control_category": "access_control",
                "source_type": "rbac_config", "source_id": project_id,
                "evidence_ts": co,
                "description": "Project membership and role assignment "
                "records (RBAC, Phase-2): %d member(s), %d distinct role(s) "
                "assigned; org has %d active user account(s)."
                % (int(members["n"]), int(roles["n"]), int(users["n"])),
                "status": status,
                "counts": {"members": int(members["n"]),
                           "distinct_roles": int(roles["n"]),
                           "org_active_users": int(users["n"])}}

    def _ev_asset_management(self, project_id, project, co):
        assets = self._one(
            "SELECT COUNT(*) n FROM assets WHERE project_id=? AND "
            "first_seen<=?", (project_id, co))
        obs = self._one(
            "SELECT COUNT(*) n FROM asset_observations WHERE project_id=? "
            "AND first_seen<=?", (project_id, co))
        has_any = int(assets["n"]) > 0
        status = "supported" if has_any and int(obs["n"]) > 0 else \
            "partially_supported" if has_any else "not_supported"
        return {"control_category": "asset_management",
                "source_type": "asset_inventory", "source_id": project_id,
                "evidence_ts": co,
                "description": "Asset inventory (Phase-1/4): %d asset(s) "
                "with %d intelligence observation(s) (technology/service/"
                "TLS/DNS provenance records)."
                % (int(assets["n"]), int(obs["n"])),
                "status": status,
                "counts": {"assets": int(assets["n"]),
                           "observations": int(obs["n"])}}

    def _ev_vulnerability_management(self, project_id, project, co):
        find = self._one(
            "SELECT COUNT(*) n FROM findings WHERE project_id=? AND "
            "first_detected<=?", (project_id, co))
        resolved = self._one(
            "SELECT COUNT(*) n FROM findings WHERE project_id=? AND "
            "resolved_at<>'' AND resolved_at<=?", (project_id, co))
        reopened = self._one(
            "SELECT COUNT(*) n FROM findings WHERE project_id=? AND "
            "reopened_at<>'' AND reopened_at<=?", (project_id, co))
        tickets = self._one(
            "SELECT COUNT(*) n FROM remediation_tickets WHERE project_id=? "
            "AND created_at<=?", (project_id, co))
        has_any = int(find["n"]) > 0
        status = "supported" if has_any else "not_supported"
        if has_any and int(tickets["n"]) == 0:
            status = "partially_supported"
        return {"control_category": "vulnerability_management",
                "source_type": "finding_history", "source_id": project_id,
                "evidence_ts": co,
                "description": "Finding lifecycle history + remediation "
                "tickets (Phase-1/4/5): %d finding(s), %d resolved, %d "
                "reopened, %d ticket(s)."
                % (int(find["n"]), int(resolved["n"]), int(reopened["n"]),
                   int(tickets["n"])),
                "status": status,
                "counts": {"findings": int(find["n"]),
                           "resolved": int(resolved["n"]),
                           "reopened": int(reopened["n"]),
                           "tickets": int(tickets["n"])}}

    def _ev_logging_monitoring(self, project_id, project, co):
        audit = self._one(
            "SELECT COUNT(*) n FROM audit_events WHERE org_id=? AND ts<=?",
            (project.org_id, co))
        verify = {"valid": False, "checked": 0}
        try:
            verify = self.svc.audit_verify()
        except Exception:
            verify = {"valid": False, "checked": 0}
        policies = self._one(
            "SELECT COUNT(*) n FROM monitoring_policies WHERE project_id=? "
            "AND enabled=1", (project_id,))
        alerts = self._one(
            "SELECT COUNT(*) n FROM alerts WHERE project_id=? AND "
            "created_at<=?", (project_id, co))
        has_any = int(audit["n"]) > 0
        status = "supported" if has_any and verify.get("valid") else \
            "partially_supported" if has_any else "not_supported"
        return {"control_category": "logging_monitoring",
                "source_type": "immutable_audit", "source_id": project.org_id,
                "evidence_ts": co,
                "description": "Immutable hash-chained audit log "
                "(Phase-2): %d event(s); chain integrity %s; %d enabled "
                "monitoring policy(ies), %d alert(s)."
                % (int(audit["n"]), "valid" if verify.get("valid")
                   else "unverified", int(policies["n"]), int(alerts["n"])),
                "status": status,
                "counts": {"audit_events": int(audit["n"]),
                           "audit_chain_valid": bool(verify.get("valid")),
                           "policies": int(policies["n"]),
                           "alerts": int(alerts["n"])}}

    def _ev_change_management(self, project_id, project, co):
        diffs = self._one(
            "SELECT COUNT(*) n FROM scan_diffs WHERE project_id=? "
            "AND created_at<=?", (project_id, co))
        baselines = self._one(
            "SELECT COUNT(*) n FROM project_baselines WHERE project_id=?",
            (project_id,))
        changes = self._one(
            "SELECT COUNT(*) n FROM security_events WHERE project_id=? AND "
            "ts<=? AND event_type IN ('technology.changed','version.changed',"
            "'exposure.changed','service.opened','service.closed')",
            (project_id, co))
        has_any = int(diffs["n"]) > 0 or int(changes["n"]) > 0
        status = "supported" if has_any and int(diffs["n"]) > 0 else \
            "partially_supported" if has_any else "not_supported"
        return {"control_category": "change_management",
                "source_type": "scan_diffs", "source_id": project_id,
                "evidence_ts": co,
                "description": "Change tracking (Phase-4 baselines/diffs + "
                "Phase-5 change events): %d baseline(s), %d scan diff(s), %d "
                "recorded change event(s)."
                % (int(baselines["n"]), int(diffs["n"]), int(changes["n"])),
                "status": status,
                "counts": {"baselines": int(baselines["n"]),
                           "scan_diffs": int(diffs["n"]),
                           "change_events": int(changes["n"])}}

    def _ev_incident_response(self, project_id, project, co):
        alerts = self._one(
            "SELECT COUNT(*) n FROM alerts WHERE project_id=? AND "
            "created_at<=?", (project_id, co))
        actions = self._one(
            "SELECT COUNT(*) n FROM alert_events WHERE alert_id IN "
            "(SELECT id FROM alerts WHERE project_id=?) AND action IN "
            "('acknowledged','investigating','resolved','suppressed') "
            "AND ts<=?",
            (project_id, co))
        has_any = int(alerts["n"]) > 0
        status = "supported" if has_any and int(actions["n"]) > 0 else \
            "partially_supported" if has_any else "not_supported"
        return {"control_category": "incident_response",
                "source_type": "alert_history", "source_id": project_id,
                "evidence_ts": co,
                "description": "Alert handling history (Phase-5): %d "
                "alert(s) generated, %d analyst action(s) recorded (ack/"
                "investigate/resolve/suppress)."
                % (int(alerts["n"]), int(actions["n"])),
                "status": status,
                "counts": {"alerts": int(alerts["n"]),
                           "actions": int(actions["n"])}}

    def _ev_data_protection(self, project_id, project, co):
        evrecs = self._one(
            "SELECT COUNT(*) n FROM evidence WHERE finding_id IN "
            "(SELECT id FROM findings WHERE project_id=?) AND captured_at<=?",
            (project_id, co))
        creds = self._one(
            "SELECT COUNT(*) n FROM audit_events WHERE org_id=? AND action "
            "IN ('credential.created','credential.revoked',"
            "'credential.rotated') AND ts<=?", (project.org_id, co))
        scans = self._one(
            "SELECT COUNT(*) n FROM scans WHERE project_id=? AND "
            "status='completed'", (project_id,))
        has_any = int(evrecs["n"]) > 0 or int(creds["n"]) > 0
        status = "supported" if has_any else \
            "partially_supported" if int(scans["n"]) > 0 else "not_supported"
        return {"control_category": "data_protection",
                "source_type": "evidence_records", "source_id": project_id,
                "evidence_ts": co,
                "description": "Data-protection artifacts: %d structured "
                "evidence record(s) for findings, %d credential lifecycle "
                "audit event(s); all outputs pass the platform's central "
                "redaction layer (secrets never stored in findings/evidence/"
                "audit)." % (int(evrecs["n"]), int(creds["n"])),
                "status": status,
                "counts": {"evidence_records": int(evrecs["n"]),
                           "credential_events": int(creds["n"]),
                           "completed_scans": int(scans["n"])}}

    def _ev_security_testing(self, project_id, project, co):
        scans = self._one(
            "SELECT COUNT(*) n FROM scans WHERE project_id=? AND "
            "status='completed' AND created_at<=?", (project_id, co))
        verif = self._one(
            "SELECT COUNT(*) n FROM verification_requests WHERE ticket_id IN "
            "(SELECT id FROM remediation_tickets WHERE project_id=?) AND "
            "requested_at<=?", (project_id, co))
        passed = self._one(
            "SELECT COUNT(*) n FROM verification_requests WHERE ticket_id IN "
            "(SELECT id FROM remediation_tickets WHERE project_id=?) AND "
            "status='passed'", (project_id,))
        has_any = int(scans["n"]) > 0
        status = "supported" if int(verif["n"]) > 0 else \
            "partially_supported" if has_any else "not_supported"
        return {"control_category": "security_testing",
                "source_type": "verification_scans", "source_id": project_id,
                "evidence_ts": co,
                "description": "Security testing evidence: %d completed "
                "scan(s), %d verification request(s), %d passed; all scans "
                "ran through the managed Phase-3 execution queue with "
                "scope revalidation." % (int(scans["n"]), int(verif["n"]),
                                         int(passed["n"])),
                "status": status,
                "counts": {"completed_scans": int(scans["n"]),
                           "verifications": int(verif["n"]),
                           "passed": int(passed["n"])}}

    # ------------------------------------------------------------ storage
    def refresh(self, project_id: str, *, cutoff: str = "") -> list[dict]:
        """Re-derive + upsert the evidence registry (current view; the
        registry is NOT the snapshot — snapshots are immutable)."""
        items = self.derive(project_id, cutoff=cutoff)
        now = _utcnow()
        for it in items:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO compliance_evidence (id, org_id, project_id,"
                    " control_category, source_type, source_id, evidence_ts,"
                    " data_cutoff, description, status, counts,"
                    " evidence_hash, created_at, updated_at) VALUES "
                    "(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET data_cutoff=excluded."
                    "data_cutoff, evidence_ts=excluded.evidence_ts, "
                    "description=excluded.description, status=excluded."
                    "status, counts=excluded.counts, "
                    "evidence_hash=excluded.evidence_hash, "
                    "updated_at=excluded.updated_at",
                    (it["id"], it["org_id"], it["project_id"],
                     it["control_category"], it["source_type"],
                     it["source_id"], it["evidence_ts"], it["data_cutoff"],
                     it["description"], it["status"],
                     json.dumps(it["counts"], sort_keys=True),
                     it["evidence_hash"], now, now))
        return items

    def snapshot(self, project_id: str, *, generated_by: str = "cli",
                 cutoff: str = "", title: str = "") -> dict:
        """Generate + store an IMMUTABLE compliance evidence snapshot."""
        items = self.refresh(project_id, cutoff=cutoff)
        report = ReportService(self.svc)
        snap = report.snapshot(
            project_id, "compliance_evidence", generated_by=generated_by,
            data_cutoff=cutoff, title=title or
            f"Compliance evidence — {project_id}")
        snap["evidence"] = items
        snap["metadata"]["report_hash"] = report.report_hash(snap)
        run = report.store_run(snap, evidence_snapshot=True)
        run["evidence_count"] = len(items)
        return run

    def list_items(self, project_id: str, *, category: str = "",
                   limit: int = 100, offset: int = 0) -> dict:
        self.svc.project_require(project_id)
        limit = _bounded(limit, 1, _PAGE_MAX, "limit")
        offset = _bounded(offset, 0, 100000, "offset")
        params = [project_id]
        extra = ""
        if category:
            if category not in CONTROL_CATEGORIES:
                raise errors.ValidationError(
                    f"control_category_unknown: {category!r}")
            extra = " AND control_category=?"
            params.append(category)
        rows = self._q(
            "SELECT * FROM compliance_evidence WHERE project_id=?" + extra +
            " ORDER BY control_category, id LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset))
        total = int(self._one(
            "SELECT COUNT(*) n FROM compliance_evidence WHERE project_id=?"
            + extra, tuple(params))["n"])
        return {"count": len(rows), "total": total, "limit": limit,
                "offset": offset,
                "items": [redact.redact(dict(r)) for r in rows]}

    def get_item(self, evidence_id: str) -> dict:
        rows = self._q("SELECT * FROM compliance_evidence WHERE id=? LIMIT 1",
                       (evidence_id,))
        if not rows:
            raise errors.NotFoundError("no evidence")
        return redact.redact(dict(rows[0]))

    def export_items(self, project_id: str, *, fmt: str = "json",
                     category: str = "", out_path: str = "") -> bytes:
        """Export the current evidence registry (provenance preserved).
        Snapshots keep their own immutable copy in report_payloads."""
        data = self.list_items(project_id, category=category, limit=_PAGE_MAX)
        payload = {
            "schema_version": "evidence-v1",
            "project_id": project_id,
            "generated_at": _utcnow(),
            "note": "Generic control categories — evidence only, no "
                    "compliance claim.",
            "items": data["items"],
        }
        payload = redact.redact(payload)
        if fmt == "json":
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        elif fmt == "html":
            rows = "".join(
                f"<tr><td>{html.escape(str(i.get('control_category','')))}</td>"
                f"<td>{html.escape(str(i.get('status','')))}</td>"
                f"<td>{html.escape(str(i.get('source_type','')))}</td>"
                f"<td class='mono'>{html.escape(str(i.get('source_id','')))}</td>"
                f"<td class='mono mut'>{html.escape(str(i.get('evidence_hash','')))}</td>"
                f"<td>{html.escape(str(i.get('description','')))[:180]}</td>"
                f"</tr>" for i in data["items"]) or \
                "<tr><td colspan=6 class='mut'>no evidence items</td></tr>"
            raw = (_H_HEAD + "<h1>Compliance evidence — " +
                   html.escape(str(project_id[:16])) + "</h1><p class='mut'>"
                   + html.escape(str(payload["note"])) +
                   "</p><table><tr><th>Category</th><th>Status</th>"
                   "<th>Source</th><th>Source id</th><th>Hash</th>"
                   "<th>Description</th></tr>" + rows + "</table>" +
                   _H_FOOT).encode("utf-8")
        elif fmt == "pdf":
            import pdf_report as _pdf
            raw = _pdf.render_evidence_pdf(payload)
        else:
            raise errors.ValidationError(f"format_unknown: {fmt!r}")
        if out_path:
            target = secure_export_path(out_path)
            with open(target, "wb") as fh:
                fh.write(raw)
        return raw


# ---------------------------------------------------------------------------
_DESC_NEUTRAL = {
    "compliant": "covered", "compliance": "evidence",
    "certified": "documented", "certification": "documentation",
}


def _sanitize_desc(text: str) -> str:
    """Guarantee no compliance/certification claims in evidence
    descriptions (regression-tested)."""
    s = str(text or "")[:800]
    def _sub(m):
        return _DESC_NEUTRAL.get(m.group(0).lower(), m.group(0))
    return REDACTED_DESC_WORDS.sub(_sub, s)


def _chunks(items, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def secure_export_path(path: str) -> str:
    """Validate a user-supplied export path: rejects NUL/control chars,
    backslashes, '..' traversal components and whitespace-only/empty
    components. Absolute paths are permitted only when the parent directory
    already exists (writer never creates directories)."""
    p = str(path or "").strip()
    if not p:
        raise errors.ValidationError("out_path_required")
    if p != str(path):
        raise errors.ValidationError("out_path_rejected: leading/trailing "
                                     "whitespace")
    if "\x00" in p or _PATH_BAD.search(p):
        raise errors.ValidationError("out_path_rejected: unsafe characters")
    import os as _os
    raw_parts = [part for part in _os.path.normpath(p).split(_os.sep)]
    for part in str(p).replace("\\", "/").split("/"):
        if part in ("..", "."):
            raise errors.ValidationError("out_path_rejected: traversal")
    if any(part == ".." for part in raw_parts):
        raise errors.ValidationError("out_path_rejected: traversal")
    parent = _os.path.dirname(_os.path.abspath(p))
    if not _os.path.isdir(parent):
        raise errors.ValidationError(
            "out_path_rejected: parent directory does not exist")
    return p


def file_name_for(report_id: str, fmt: str) -> str:
    f = str(fmt or "json").lower()
    if f not in ("json", "html", "pdf"):
        f = "json"
    return f"report-{str(report_id)[:12]}-{_utcnow()[:10]}.{f}"


def _sev_color(sev: str) -> str:
    return {"Critical": "#ff3b5c", "High": "#ff8a3d", "Medium": "#ffd23d",
            "Low": "#4da3ff", "Info": "#7d8590"}.get(sev, "#888888")


_CSS = """
:root{--bg:#0b0f17;--panel:#121826;--line:#1e2838;--txt:#e6ebf4;--mut:#8a94a6;
--acc:#3ddc97;--acc2:#9d6bff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.55 -apple-system,'Segoe UI',Roboto,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:24px}
.cover{border:1px solid var(--line);border-radius:14px;padding:34px;
background:var(--panel);margin-bottom:22px}
.cover .logo{font-weight:800;font-size:20px}.cover .logo span{color:var(--acc2)}
.cover h1{margin:14px 0 8px;font-size:26px}
h2{color:var(--acc);border-bottom:1px solid var(--line);padding-bottom:6px;
margin:28px 0 12px;font-size:18px}
h3{color:var(--mut);font-size:14px;text-transform:uppercase;letter-spacing:.8px}
table{width:100%;border-collapse:collapse;margin:8px 0 14px}
th{text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase;
letter-spacing:.7px;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid #161e2e;vertical-align:top;
font-size:13px}
.grid{display:grid;gap:14px}.g3{grid-template-columns:repeat(auto-fit,
minmax(200px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:16px;margin:6px 0}
.card .big{font-size:32px;font-weight:800}
.small{color:var(--mut);font-size:12px}.mut{color:var(--mut)}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:12px}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;
font-weight:700;letter-spacing:.4px;color:#0b0f17;margin:2px}
.ev{background:#0a0e16;border:1px solid var(--line);border-radius:8px;
padding:10px;font-size:12px;word-break:break-word;margin:6px 0;color:#c8d3e5}
.find{border:1px solid var(--line);border-radius:10px;padding:10px 14px;
margin:8px 0;background:var(--panel)}
.find summary{cursor:pointer;font-weight:600;margin-bottom:4px}
.find .body{padding-left:4px}
footer{margin-top:30px;color:#5c6675;font-size:11px;text-align:center;
border-top:1px solid var(--line);padding-top:14px}
@media print{body{background:#fff;color:#111}.card,.find,.cover{background:#fff;
border-color:#ccc}.cover h1{color:#111}h2{color:#0a4a35}}
"""

_H_HEAD = ("<html><head><meta charset='utf-8'><title>Compliance evidence</title>"
           "<style>body{font:14px/1.5 sans-serif;margin:24px;color:#111}"
           "table{width:100%;border-collapse:collapse}th,td{border:1px solid "
           "#999;padding:6px 8px;text-align:left;font-size:12px}"
           "h1{font-size:20px}.mut{color:#666}.mono{font-family:monospace}"
           "</style></head><body>")

_H_FOOT = "</body></html>"
