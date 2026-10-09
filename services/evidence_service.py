"""Tenant-scoped evidence references, integrity metadata, and safe retrieval.

The platform currently persists bounded finding evidence metadata and report
payload snapshots; it does not store binary evidence artifacts. This service
therefore returns honest integrity/download states and never opens caller-
provided paths or fabricates content.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
models = _domain_module("models")
redact = _domain_module("redact")
store = _domain_module("store")

_MAX_LIMIT = 100
_MAX_WINDOW = 500
_MAX_OFFSET = 100_000
_INTEGRITY_FIELDS = (
    "id", "finding_id", "evidence_type", "url", "method", "status_code",
    "request_snippet", "response_snippet", "detection_reason", "scanner",
    "rule_id", "captured_at",
)
_EVIDENCE_COLUMNS = tuple("e." + field for field in _INTEGRITY_FIELDS)


class EvidenceService:
    """Read and export safe evidence references from existing domain stores."""

    def __init__(
        self,
        platform: Any,
        *,
        reports: Any = None,
        compliance_engine: Any = None,
        retention: Any = None,
    ) -> None:
        self.platform = platform
        self.db = platform.db
        self.reports = reports
        self.compliance_engine = compliance_engine
        self.retention = retention

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
    def _page(limit: int, offset: int) -> tuple[int, int]:
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("evidence page limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset < _MAX_WINDOW:
            raise errors.ValidationError("evidence page offset is outside the allowed range")
        if offset + limit > _MAX_WINDOW:
            raise errors.ValidationError("evidence result window is limited")
        return limit, offset

    @staticmethod
    def _integrity_hash(row: dict[str, Any]) -> str:
        """Hash the canonical persisted evidence fields without exposing them.

        This is a deterministic SHA-256 digest computed from the record as
        read. The repository does not persist an independent evidence digest,
        so this value is not presented as a tamper-evident stored checksum.
        """
        canonical_record = {
            field: str(row.get(field) or "")
            for field in _INTEGRITY_FIELDS
        }
        canonical = json.dumps(
            canonical_record,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _safe_record(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": str(row.get("id", "")),
            "finding_id": str(row.get("finding_id", "")),
            "evidence_type": str(redact.redact_text(row.get("evidence_type", "")))[:64],
            "url": str(redact.redact_text(row.get("url", "")))[:2048],
            "method": str(row.get("method", ""))[:16],
            "status_code": str(row.get("status_code", ""))[:16],
            "detection_reason": str(redact.redact_text(row.get("detection_reason", "")))[:500],
            "scanner": str(redact.redact_text(row.get("scanner", "")))[:128],
            "rule_id": str(redact.redact_text(row.get("rule_id", "")))[:128],
            "captured_at": str(row.get("captured_at", ""))[:64],
            "integrity_reference": {
                "record_id": str(row.get("id", "")),
                "algorithm": "sha256",
                "sha256": EvidenceService._integrity_hash(row),
                "scope": "canonical_persisted_evidence_fields",
                "hash_status": "COMPUTED_AT_READ",
                "hash_persisted": False,
            },
            "download": {
                "status": "NOT_AVAILABLE",
                "reason": "binary_evidence_store_not_configured",
            },
        }

    def list_finding_evidence(
        self,
        org_id: str,
        finding_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("evidence page limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset <= _MAX_OFFSET:
            raise errors.ValidationError("evidence page offset is outside the allowed range")
        finding_rows = self.db.query(
            "SELECT f.id FROM findings f JOIN projects p ON p.id=f.project_id "
            "WHERE f.id=? AND p.org_id=? LIMIT 1",
            (finding_id, org_id),
            limit=1,
        )
        if not finding_rows:
            raise errors.NotFoundError("finding not found")
        rows = self.db.query(
            "SELECT " + ", ".join(_INTEGRITY_FIELDS) + " FROM evidence "
            "WHERE finding_id=? ORDER BY captured_at DESC, id LIMIT ? OFFSET ?",
            (finding_id, limit, offset),
            limit=limit,
        )
        return {
            "data": [self._safe_record(dict(row)) for row in rows],
            "count": len(rows),
            "limit": limit,
            "offset": offset,
            "truncated": len(rows) == limit,
            "download_state": "NOT_AVAILABLE",
        }

    def get_evidence(self, org_id: str, evidence_id: str) -> dict[str, Any]:
        columns = ", ".join("e." + field for field in _INTEGRITY_FIELDS)
        rows = self.db.query(
            "SELECT " + columns + " FROM evidence e "
            "JOIN findings f ON f.id=e.finding_id "
            "JOIN projects p ON p.id=f.project_id "
            "WHERE e.id=? AND p.org_id=? LIMIT 1",
            (evidence_id, org_id),
            limit=1,
        )
        if not rows:
            raise errors.NotFoundError("evidence not found")
        return self._safe_record(dict(rows[0]))

    def list_scan_evidence(
        self,
        org_id: str,
        scan_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        limit, offset = self._page(limit, offset)
        rows = self.db.query(
            "SELECT " + ", ".join(_EVIDENCE_COLUMNS) + " FROM evidence e "
            "JOIN findings f ON f.id=e.finding_id "
            "JOIN scans s ON s.id=f.scan_id "
            "JOIN projects p ON p.id=s.project_id "
            "WHERE s.id=? AND p.org_id=? "
            "ORDER BY e.captured_at DESC, e.id LIMIT ? OFFSET ?",
            (scan_id, org_id, limit + 1, offset),
            limit=limit + 1,
        )
        if not rows and not self.db.query(
            "SELECT s.id FROM scans s JOIN projects p ON p.id=s.project_id "
            "WHERE s.id=? AND p.org_id=? LIMIT 1",
            (scan_id, org_id),
            limit=1,
        ):
            raise errors.NotFoundError("scan not found")
        truncated = len(rows) > limit
        page = rows[:limit]
        return {
            "data": [self._safe_record(dict(row)) for row in page],
            "count": len(page),
            "limit": limit,
            "offset": offset,
            "truncated": truncated,
            "download_state": "NOT_AVAILABLE",
        }

    @staticmethod
    def _report_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        explicit = payload.get("evidence", [])
        if isinstance(explicit, list):
            items.extend(item for item in explicit[:_MAX_WINDOW] if isinstance(item, dict))
        if len(items) >= _MAX_WINDOW:
            return items[:_MAX_WINDOW]
        findings = payload.get("findings", [])
        if isinstance(findings, list):
            for finding in findings[:_MAX_WINDOW]:
                if not isinstance(finding, dict):
                    continue
                evidence = finding.get("evidence", [])
                if not isinstance(evidence, list):
                    continue
                for item in evidence:
                    if len(items) >= _MAX_WINDOW:
                        return items
                    if not isinstance(item, dict):
                        continue
                    safe_item = dict(item)
                    safe_item.setdefault("finding_id", finding.get("id", ""))
                    items.append(safe_item)
        return items[:_MAX_WINDOW]

    def list_report_evidence(
        self,
        org_id: str,
        report_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        limit, offset = self._page(limit, offset)
        if self.reports is None:
            raise errors.ConfigurationError("report service is unavailable")
        try:
            report = self.reports.get_run(report_id, with_payload=True)
        except errors.NotFoundError:
            raise errors.NotFoundError("report not found") from None
        if str(report.get("org_id", "")) != org_id:
            raise errors.NotFoundError("report not found")
        payload = report.get("payload")
        common = {
            "report_id": report_id,
            "project_id": str(report.get("project_id", "")),
            "report_hash": str(report.get("report_hash", ""))[:128],
            "download_state": "NOT_AVAILABLE",
        }
        if not isinstance(payload, dict):
            return {
                "data": [],
                "count": 0,
                "limit": limit,
                "offset": offset,
                "state": "NOT_AVAILABLE",
                "reason": "report_payload_not_persisted",
                **common,
            }
        items = self._report_items(payload)
        page = items[offset:offset + limit]
        report_hash = str(report.get("report_hash", ""))[:128]
        safe_items = []
        for item in page:
            safe_items.append({
                "evidence_id": str(item.get("id", ""))[:128],
                "finding_id": str(item.get("finding_id", ""))[:128],
                "evidence_type": str(redact.redact_text(item.get("type", item.get("evidence_type", ""))))[:64],
                "url": str(redact.redact_text(item.get("url", "")))[:2048],
                "method": str(item.get("method", ""))[:16],
                "status_code": str(item.get("status_code", ""))[:16],
                "detection_reason": str(redact.redact_text(item.get("detection_reason", "")))[:500],
                "scanner": str(redact.redact_text(item.get("scanner", "")))[:128],
                "rule_id": str(redact.redact_text(item.get("rule_id", "")))[:128],
                "captured_at": str(item.get("captured_at", item.get("evidence_ts", "")))[:64],
                "integrity_reference": {
                    "report_id": report_id,
                    "report_hash": report_hash,
                    "status": "REPORT_HASH_ONLY" if report_hash else "NOT_AVAILABLE",
                },
                "download": {
                    "status": "NOT_AVAILABLE",
                    "reason": "binary_evidence_store_not_configured",
                },
            })
        return {
            "data": safe_items,
            "count": len(safe_items),
            "limit": limit,
            "offset": offset,
            "state": "AVAILABLE",
            "truncated": len(items) >= _MAX_WINDOW,
            **common,
        }

    def download_status(self, org_id: str, evidence_id: str) -> dict[str, str]:
        self.get_evidence(org_id, evidence_id)
        return {
            "status": "NOT_AVAILABLE",
            "reason": "binary_evidence_store_not_configured",
        }

    def retention_info(self, org_id: str, project_id: str) -> dict[str, Any]:
        self._project(org_id, project_id)
        if self.retention is None:
            return {
                "kind": "evidence",
                "days": int(models.RETENTION_DEFAULTS.get("evidence", 365)),
                "source": "documented_default",
                "policy_configured": False,
            }
        policy_rows = self.db.query(
            "SELECT project_id FROM retention_policies WHERE org_id=? "
            "AND kind='evidence' AND enabled=1 AND project_id IN (?, '') "
            "ORDER BY CASE WHEN project_id=? THEN 0 ELSE 1 END LIMIT 1",
            (org_id, project_id, project_id),
            limit=1,
        )
        days = self.retention.effective_days(org_id, "evidence", project_id=project_id)
        if not policy_rows:
            source = "documented_default"
        elif str(policy_rows[0].get("project_id", "")) == project_id:
            source = "project_retention_policy"
        else:
            source = "organization_retention_policy"
        return {
            "kind": "evidence",
            "days": int(days),
            "source": source,
            "policy_configured": bool(policy_rows),
        }

    def compliance_items(
        self,
        org_id: str,
        project_id: str,
        *,
        category: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        if self.compliance_engine is None:
            raise errors.ConfigurationError("compliance evidence engine is unavailable")
        return self.compliance_engine.list_items(
            project_id, category=category, limit=limit, offset=offset
        )

    def create_compliance_snapshot(
        self,
        org_id: str,
        project_id: str,
        *,
        actor: str = "api",
        cutoff: str = "",
        title: str = "",
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        if self.compliance_engine is None:
            raise errors.ConfigurationError("compliance evidence engine is unavailable")
        result = self.compliance_engine.snapshot(
            project_id, generated_by=actor, cutoff=cutoff, title=title
        )
        if str(result.get("org_id", "")) != org_id:
            raise errors.PersistenceError("evidence snapshot tenant scope mismatch")
        return result


__all__ = ["EvidenceService"]
