"""Versioned, explainable risk reads over persisted findings and asset context.

Risk formulas and event snapshots are owned by the existing RiskEngine,
CorrelationService, RiskSnapshotService, and AnalyticsService. The service
never substitutes an in-memory scan result for persisted platform records.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
redact = _domain_module("redact")
store = _domain_module("store")

_CATEGORY_SAMPLE_MAX = 500


class RiskService:
    """Tenant-safe facade for reproducible risk summaries and explanations."""

    def __init__(
        self,
        platform: Any,
        *,
        analytics: Any = None,
        correlation: Any = None,
        snapshots: Any = None,
    ) -> None:
        self.platform = platform
        self.db = platform.db
        self.analytics = analytics
        self.correlation = correlation
        if snapshots is None and correlation is not None:
            snapshots = getattr(correlation, "snapshots", None)
        self.snapshots = snapshots

    def _project(self, org_id: str, project_id: str) -> Any:
        if not org_id or not project_id:
            raise errors.ValidationError("tenant and project scope are required")
        try:
            project = self.platform.project_get(project_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("project not found") from None
        if project.org_id != org_id:
            raise errors.NotFoundError("project not found")
        return project

    def _finding(self, org_id: str, finding_id: str) -> dict[str, Any]:
        if not finding_id:
            raise errors.ValidationError("finding identifier is required")
        rows = self.db.query(
            "SELECT f.* FROM findings f JOIN projects p ON p.id=f.project_id "
            "WHERE f.id=? AND p.org_id=? LIMIT 1",
            (finding_id, org_id),
            limit=1,
        )
        if not rows:
            raise errors.NotFoundError("finding not found")
        return dict(rows[0])

    def _top_categories(self, project_id: str, summary: dict[str, Any], limit: int) -> dict[str, Any]:
        statuses = sorted({
            str(status) for status in summary.get("scope_statuses", [])
            if isinstance(status, str) and status
        })
        cutoff = str(summary.get("data_cutoff", ""))
        clauses = ["project_id=?"]
        params: list[Any] = [project_id]
        if statuses:
            clauses.append("lifecycle IN (" + ",".join("?" for _ in statuses) + ")")
            params.extend(statuses)
        if cutoff:
            clauses.append("first_detected<=?")
            params.append(cutoff)
        rows = self.db.query(
            "SELECT category, severity, risk_score FROM findings WHERE "
            + " AND ".join(clauses)
            + " ORDER BY last_detected DESC, id LIMIT ?",
            tuple(params + [_CATEGORY_SAMPLE_MAX]),
            limit=_CATEGORY_SAMPLE_MAX,
        )
        buckets: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "risk_total": 0.0, "by_severity": defaultdict(int)}
        )
        for row in rows:
            category = str(redact.redact_text(row.get("category") or "other"))[:128] or "other"
            entry = buckets[category]
            try:
                score = float(row.get("risk_score") or 0)
            except (TypeError, ValueError, OverflowError):
                score = 0.0
            entry["count"] += 1
            entry["risk_total"] += score
            severity = str(row.get("severity") or "unknown")[:32]
            entry["by_severity"][severity] += 1
        result = []
        for category, value in buckets.items():
            count = int(value["count"])
            total = float(value["risk_total"])
            result.append({
                "category": category,
                "count": count,
                "persisted_risk_total": round(total, 1),
                "persisted_risk_average": round(total / max(1, count), 1),
                "by_severity": dict(sorted(value["by_severity"].items())),
            })
        result.sort(key=lambda item: (-item["persisted_risk_total"], item["category"].casefold()))
        return {
            "data": result[:limit],
            "source": "persisted_findings",
            "sample_size": len(rows),
            "truncated": len(rows) == _CATEGORY_SAMPLE_MAX,
        }

    def project_summary(
        self,
        org_id: str,
        project_id: str,
        *,
        cutoff: str = "",
        start: str = "",
        end: str = "",
        category_limit: int = 10,
    ) -> dict[str, Any]:
        """Return a deterministic project risk view using stored risk columns."""
        self._project(org_id, project_id)
        if self.analytics is None:
            raise errors.ConfigurationError("risk analytics service is unavailable")
        if type(category_limit) is not int or not 1 <= category_limit <= 20:
            raise errors.ValidationError("risk category limit is outside the allowed range")
        summary = self.analytics.risk_summary(project_id, cutoff=cutoff)
        risk_assets = self.analytics.risk_by_asset(
            project_id, cutoff=summary["data_cutoff"], limit=10
        )
        buckets = self.analytics.risk_buckets(
            project_id, cutoff=summary["data_cutoff"], bucket_width=10
        )
        category_data = self._top_categories(project_id, summary, category_limit)
        trends = self.project_trends(org_id, project_id, start=start, end=end)
        return {
            "project_id": project_id,
            "data_cutoff": summary["data_cutoff"],
            "risk_calculation_version": summary["risk_calculation_version"],
            "aggregate": summary,
            "severity_distribution": summary["by_severity"],
            "risk_level_distribution": summary["by_risk_level"],
            "risk_score_histogram": buckets,
            "top_assets": risk_assets,
            "top_categories": category_data,
            "score_components": {
                "persisted_risk_total": {
                    "value": summary["total_risk"],
                    "source": "sum of persisted finding risk_score values for the reported active statuses",
                },
                "persisted_risk_average": {
                    "value": summary["avg_risk"],
                    "source": "average of persisted finding risk_score values for the reported active statuses",
                },
                "maximum_persisted_risk": {
                    "value": summary["max_risk"],
                    "source": "maximum persisted finding risk_score value",
                },
                "by_priority": summary["by_priority"],
                "by_exposure": summary["by_exposure"],
                "by_criticality": summary["by_criticality"],
                "by_confidence": summary["by_confidence"],
                "recalculated": False,
            },
            "trends": trends,
        }

    def project_trends(
        self,
        org_id: str,
        project_id: str,
        *,
        start: str = "",
        end: str = "",
    ) -> dict[str, Any]:
        """Return persisted lifecycle and risk-event trends, not a synthetic series."""
        self._project(org_id, project_id)
        if self.analytics is None:
            raise errors.ConfigurationError("risk analytics service is unavailable")
        lifecycle = self.analytics.finding_trend(project_id, start=start, end=end)
        risk_events = self.analytics.risk_delta(project_id, start=start, end=end)
        return {
            "finding_lifecycle": lifecycle,
            "persisted_risk_events": {
                **risk_events,
                "definition": "Counts persisted risk.increased and risk.decreased security events; this is not a recalculated score time series.",
            },
        }

    def finding_explanation(self, org_id: str, finding_id: str) -> dict[str, Any]:
        """Read the stored risk score, formula version, and explanation factors."""
        row = self._finding(org_id, finding_id)
        factors = store.loads(row.get("risk_factors", "[]"), [])
        if not isinstance(factors, list):
            factors = []
        try:
            score = int(row.get("risk_score") or 0)
        except (TypeError, ValueError, OverflowError):
            score = 0
        return redact.redact({
            "finding_id": finding_id,
            "project_id": str(row.get("project_id", "")),
            "risk_score": max(0, min(100, score)),
            "risk_level": str(row.get("risk_level") or "unknown")[:32],
            "priority": str(row.get("priority") or "")[:16],
            "risk_calculation_version": str(row.get("calc_version") or "risk-v1")[:64],
            "factors": factors[:100],
            "source": "persisted_finding",
            "recalculated": False,
        })

    def recalculate_finding(self, org_id: str, finding_id: str) -> dict[str, Any]:
        """Re-evaluate one persisted finding using the canonical versioned engine.

        This method is read-only; snapshots are written only through
        :meth:`record_snapshot` or the existing correlation ingest pipeline.
        """
        row = self._finding(org_id, finding_id)
        if self.correlation is None:
            raise errors.ConfigurationError("canonical finding risk engine is unavailable")
        try:
            evaluation = self.correlation.evaluate(row)
        except Exception:
            raise errors.PersistenceError("persisted finding risk could not be evaluated") from None
        return redact.redact({
            "finding_id": finding_id,
            "project_id": str(row.get("project_id", "")),
            **evaluation,
            "source": "persisted_finding_and_asset_context",
            "recalculated": True,
        })

    def record_snapshot(self, org_id: str, finding_id: str, *, force: bool = False) -> dict[str, Any]:
        """Persist one canonical risk change-point snapshot for an owned finding."""
        row = self._finding(org_id, finding_id)
        if self.correlation is None or self.snapshots is None:
            raise errors.ConfigurationError("risk snapshot service is unavailable")
        evaluation = self.recalculate_finding(org_id, finding_id)
        asset_context = self.correlation._asset_ctx(str(row.get("asset_id") or ""))
        return self.snapshots.record(
            finding_id,
            project_id=str(row.get("project_id", "")),
            risk_score=int(evaluation["risk_score"]),
            risk_level=str(evaluation["risk_level"]),
            severity=str(row.get("severity", "Info")),
            confidence=float(row.get("confidence_score") or 0),
            asset_criticality=str(asset_context.get("criticality", "unknown")),
            exposure=str(asset_context.get("exposure", "unknown")),
            calc_version=str(evaluation.get("calc_version", "risk-v1")),
            factors=list(evaluation.get("risk_factors", [])),
            force=force,
        )

    def snapshot_history(self, org_id: str, finding_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        self._finding(org_id, finding_id)
        if self.snapshots is None:
            raise errors.ConfigurationError("risk snapshot service is unavailable")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise errors.ValidationError("risk history limit is outside the allowed range")
        return self.snapshots.history(finding_id, limit=limit)


__all__ = ["RiskService"]
