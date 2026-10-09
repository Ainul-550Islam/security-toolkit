"""Bounded tenant-scoped structured search over existing security records.

Queries use parameterized predicates and fixed per-source limits. Search is a
read abstraction only: it does not execute free-form SQL, parse query
languages, or scan unbounded tables.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
models = _domain_module("models")
redact = _domain_module("redact")

SEARCH_TYPES = ("assets", "findings", "scans", "reports", "evidence", "integrations")
_SOURCE_LIMIT = 500
_MAX_WINDOW = 500
_TYPE_TO_RESULT = {
    "assets": "asset",
    "findings": "finding",
    "scans": "scan",
    "reports": "report",
    "evidence": "evidence",
    "integrations": "integration",
}


def _bounded_types(values: Iterable[str], label: str) -> tuple[str, ...]:
    """Consume only the closed, small source-type vocabulary."""
    if isinstance(values, (str, bytes)):
        raise errors.ValidationError(f"{label} must be a list of source types")
    try:
        iterator = iter(values)
    except TypeError:
        raise errors.ValidationError(f"{label} must be a list of source types") from None
    output: list[str] = []
    for _ in range(len(SEARCH_TYPES) + 1):
        try:
            value = next(iterator)
        except StopIteration:
            break
        if len(output) >= len(SEARCH_TYPES) or not isinstance(value, str):
            raise errors.ValidationError(f"{label} is invalid")
        output.append(value)
    return tuple(output)


class SearchService:
    """Structured search facade with per-tenant/project ownership checks."""

    def __init__(
        self,
        platform: Any,
        *,
        assets: Any = None,
        findings: Any = None,
        scans: Any = None,
        reports: Any = None,
        evidence: Any = None,
        integrations: Any = None,
    ) -> None:
        self.platform = platform
        self.db = platform.db
        self.assets = assets
        self.findings = findings
        self.scans = scans
        self.reports = reports
        self.evidence = evidence
        self.integrations = integrations

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

    @staticmethod
    def _text(value: Any, maximum: int) -> str:
        return str(redact.redact_text(value if value is not None else ""))[:maximum]

    @classmethod
    def _result(
        cls,
        kind: str,
        identifier: Any,
        title: Any,
        summary: Any,
        updated_at: Any,
        *,
        status: Any = "",
        severity: Any = "",
        asset_type: Any = "",
        report_type: Any = "",
        source_id: Any = "",
    ) -> dict[str, Any]:
        return {
            "type": kind,
            "id": cls._text(identifier, 128),
            "title": cls._text(title, 240),
            "summary": cls._text(summary, 500),
            "status": cls._text(status, 64),
            "severity": cls._text(severity, 32),
            "asset_type": cls._text(asset_type, 64),
            "report_type": cls._text(report_type, 64),
            "updated_at": str(updated_at or "")[:64],
            "source_id": cls._text(source_id, 128),
        }

    @staticmethod
    def _contains(result: dict[str, Any], needle: str) -> bool:
        if not needle:
            return True
        haystack = " ".join(str(result.get(key, "")) for key in (
            "type", "id", "title", "summary", "status", "severity", "asset_type", "report_type"
        )).casefold()
        return needle.casefold() in haystack

    def _finding_rows(self, org_id: str, project_id: str, severity: str) -> list[Any]:
        if self.findings is not None:
            return self.findings.list_findings(
                org_id, project_id, severity=severity, limit=_SOURCE_LIMIT
            )
        return self.platform.finding_list(
            project_id, severity=severity or None, limit=_SOURCE_LIMIT
        )

    def search(
        self,
        org_id: str,
        project_id: str,
        *,
        query: str = "",
        types: Iterable[str] | None = None,
        status: str = "",
        severity: str = "",
        asset_type: str = "",
        report_type: str = "",
        limit: int = 50,
        offset: int = 0,
        excluded_types: Iterable[str] = (),
    ) -> dict[str, Any]:
        """Search only the caller-authorized source types in bounded windows.

        Authorization of each requested type remains centralized in the API
        boundary; ``types`` must therefore be the already-authorized subset.
        The service still validates every type and independently verifies the
        tenant/project ownership chain before reading records.
        """
        self._project(org_id, project_id)
        if not isinstance(query, str) or len(query) > 256:
            raise errors.ValidationError("search query exceeds the allowed length")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise errors.ValidationError("search page limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset < _MAX_WINDOW or offset + limit > _MAX_WINDOW:
            raise errors.ValidationError("search result window is limited")
        selected = (
            SEARCH_TYPES
            if types is None
            else _bounded_types(types, "search types")
        )
        if len(set(selected)) != len(selected):
            raise errors.ValidationError("search types are invalid")
        if any(kind not in SEARCH_TYPES for kind in selected):
            raise errors.ValidationError("search type is not supported")
        if any(not isinstance(value, str) for value in (status, severity, asset_type, report_type)):
            raise errors.ValidationError("search filter type is invalid")
        if len(status) > 64 or len(severity) > 32 or len(asset_type) > 64 or len(report_type) > 64:
            raise errors.ValidationError("search filter exceeds the allowed length")
        if severity and severity not in models.SEVERITIES:
            raise errors.ValidationError("search severity is not supported")
        if asset_type and asset_type not in models.ASSET_TYPES:
            raise errors.ValidationError("search asset type is not supported")
        if report_type and report_type not in models.REPORT_TYPES:
            raise errors.ValidationError("search report type is not supported")
        supplied_excluded = _bounded_types(excluded_types, "excluded search types")
        if any(kind not in SEARCH_TYPES for kind in supplied_excluded):
            raise errors.ValidationError("excluded search types are invalid")
        excluded = tuple(dict.fromkeys(supplied_excluded))

        results: list[dict[str, Any]] = []
        source_states: dict[str, str] = {}
        truncated_sources: list[str] = []
        findings: list[Any] | None = None

        def get_findings() -> list[Any]:
            nonlocal findings
            if findings is None:
                findings = self._finding_rows(org_id, project_id, severity)
                if len(findings) == _SOURCE_LIMIT:
                    truncated_sources.append("findings")
            return findings

        if "assets" in selected:
            if self.assets is not None:
                assets = self.assets.list_assets(
                    org_id, project_id, asset_type=asset_type, limit=_SOURCE_LIMIT
                )
            else:
                assets = self.platform.asset_list(
                    project_id, asset_type=asset_type or None, limit=_SOURCE_LIMIT
                )
            source_states["assets"] = "AVAILABLE"
            if len(assets) == _SOURCE_LIMIT:
                truncated_sources.append("assets")
            for asset in assets:
                results.append(self._result(
                    "asset", asset.id, asset.display or asset.value,
                    f"{asset.asset_type} · {asset.status}", asset.last_seen,
                    status=asset.status, asset_type=asset.asset_type,
                ))

        if "findings" in selected:
            finding_items = get_findings()
            source_states["findings"] = "AVAILABLE"
            for finding in finding_items:
                if status and str(finding.lifecycle).casefold() != status.casefold():
                    continue
                results.append(self._result(
                    "finding", finding.id, finding.title,
                    f"{finding.severity} · {finding.category} · {finding.lifecycle}",
                    finding.last_detected,
                    status=finding.lifecycle,
                    severity=finding.severity,
                    source_id=finding.asset_id,
                ))

        if "scans" in selected:
            if self.scans is not None:
                scan_items = self.scans.list_scans(org_id, project_id, limit=_SOURCE_LIMIT)
            else:
                scan_items = self.platform.scan_list(project_id, limit=_SOURCE_LIMIT)
            source_states["scans"] = "AVAILABLE"
            if len(scan_items) == _SOURCE_LIMIT:
                truncated_sources.append("scans")
            for scan in scan_items:
                if status and str(scan.status).casefold() != status.casefold():
                    continue
                try:
                    progress = min(1.0, max(0.0, float(scan.progress)))
                except (TypeError, ValueError, OverflowError):
                    progress = 0.0
                results.append(self._result(
                    "scan", scan.id, scan.profile,
                    f"{scan.status} · {progress:.0%}", scan.created_at,
                    status=scan.status,
                ))

        if "reports" in selected:
            if self.reports is None:
                source_states["reports"] = "NOT_CONFIGURED"
            else:
                if hasattr(self.reports, "list_reports"):
                    report_data = self.reports.list_reports(
                        org_id, project_id, limit=_SOURCE_LIMIT, offset=0,
                        report_type=report_type,
                    )
                else:
                    report_data = self.reports.list_runs(
                        project_id, limit=_SOURCE_LIMIT, offset=0,
                        report_type=report_type,
                    )
                report_items = report_data.get("reports", [])
                source_states["reports"] = "AVAILABLE"
                if int(report_data.get("total", len(report_items))) > _SOURCE_LIMIT:
                    truncated_sources.append("reports")
                for report in report_items:
                    if status and str(report.get("status", "")).casefold() != status.casefold():
                        continue
                    results.append(self._result(
                        "report", report.get("id"), report.get("title"),
                        f"{report.get('report_type', '')} · {report.get('status', '')}",
                        report.get("created_at"),
                        status=report.get("status"),
                        report_type=report.get("report_type"),
                    ))

        if "evidence" in selected:
            source_states["evidence"] = "AVAILABLE"
            params: list[Any] = [project_id]
            clauses = ["f.project_id=?"]
            if severity:
                clauses.append("f.severity=?")
                params.append(severity)
            rows = self.db.query(
                "SELECT e.id, e.finding_id, e.evidence_type, e.url, "
                "e.detection_reason, e.captured_at FROM evidence e "
                "JOIN findings f ON f.id=e.finding_id WHERE "
                + " AND ".join(clauses)
                + " ORDER BY e.captured_at DESC, e.id LIMIT ?",
                tuple(params + [_SOURCE_LIMIT + 1]),
                limit=_SOURCE_LIMIT + 1,
            )
            if len(rows) > _SOURCE_LIMIT:
                truncated_sources.append("evidence")
                rows = rows[:_SOURCE_LIMIT]
            for item in rows:
                if status and status.casefold() not in {"captured", "available"}:
                    continue
                results.append(self._result(
                    "evidence", item.get("id"), item.get("evidence_type"),
                    f"{item.get('detection_reason', '')} · {item.get('url', '')}",
                    item.get("captured_at"), status="captured",
                    source_id=item.get("finding_id", ""),
                ))

        if "integrations" in selected:
            if self.integrations is None:
                source_states["integrations"] = "NOT_CONFIGURED"
            else:
                connections = getattr(self.integrations, "connections", None)
                if connections is None:
                    source_states["integrations"] = "NOT_CONFIGURED"
                else:
                    integration_data = connections.list(
                        org_id, project_id=project_id, limit=_SOURCE_LIMIT, offset=0
                    )
                    integration_items = integration_data.get("items", [])
                    source_states["integrations"] = "AVAILABLE"
                    if int(integration_data.get("total", len(integration_items))) > _SOURCE_LIMIT:
                        truncated_sources.append("integrations")
                    for item in integration_items:
                        if status and str(item.get("status", "")).casefold() != status.casefold():
                            continue
                        results.append(self._result(
                            "integration", item.get("id"), item.get("name"),
                            f"{item.get('provider', '')} · {item.get('health_state', '')}",
                            item.get("updated_at", item.get("created_at")),
                            status=item.get("status"),
                        ))

        if status:
            results = [item for item in results if item.get("status", "").casefold() == status.casefold()]
        if severity:
            results = [item for item in results if item.get("severity", "").casefold() == severity.casefold()]
        if asset_type:
            results = [item for item in results if item.get("asset_type", "").casefold() == asset_type.casefold()]
        if report_type:
            results = [item for item in results if item.get("report_type", "").casefold() == report_type.casefold()]
        results = [item for item in results if self._contains(item, query)]
        results.sort(
            key=lambda item: (str(item.get("updated_at", "")), item["type"], item["id"]),
            reverse=True,
        )
        page = results[offset:offset + limit]
        return {
            "data": page,
            "count": len(page),
            "total": len(results),
            "limit": limit,
            "offset": offset,
            "total_is_lower_bound": bool(truncated_sources),
            "truncated_sources": sorted(set(truncated_sources)),
            "source_states": source_states,
            "excluded_types": list(excluded),
        }


__all__ = ["SearchService", "SEARCH_TYPES"]
