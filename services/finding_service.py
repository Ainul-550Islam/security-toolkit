"""Tenant-scoped finding lifecycle and correlation facade.

Finding identity, deduplication, severity evaluation, and risk persistence
remain in the repository's canonical ``CorrelationService``. This module adds
explicit ownership checks around those operations and links assignment to the
existing remediation workflow rather than adding parallel finding fields.
"""

from __future__ import annotations

from typing import Any

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
models = _domain_module("models")
store = _domain_module("store")

_MAX_LIMIT = 500
_MAX_OFFSET = 100_000
_MAX_EVIDENCE_PER_INGEST = 100


class FindingService:
    """Domain service for persisted finding records and lifecycle operations."""

    def __init__(
        self,
        platform: Any,
        *,
        correlation: Any = None,
        remediation: Any = None,
        identity: Any = None,
    ) -> None:
        self.platform = platform
        self.db = platform.db
        self.correlation = correlation
        self.remediation = remediation
        self.identity = identity

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

    def _finding(self, org_id: str, finding_id: str) -> Any:
        try:
            finding = self.platform.finding_get(finding_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("finding not found") from None
        self._project(org_id, finding.project_id)
        return finding

    def _asset_in_project(self, project_id: str, asset_id: str) -> None:
        if not asset_id:
            return
        rows = self.db.query(
            "SELECT id FROM assets WHERE id=? AND project_id=? LIMIT 1",
            (asset_id, project_id),
            limit=1,
        )
        if not rows:
            raise errors.ValidationError("finding asset is not in the scan project")

    def list_findings(
        self,
        org_id: str,
        project_id: str,
        *,
        severity: str = "",
        lifecycle: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[Any]:
        self._project(org_id, project_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("finding page limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset <= _MAX_OFFSET:
            raise errors.ValidationError("finding page offset is outside the allowed range")
        if severity and severity not in models.SEVERITIES:
            raise errors.ValidationError("finding severity is not supported")
        if lifecycle and lifecycle not in models.FINDING_STATUSES:
            raise errors.ValidationError("finding lifecycle is not supported")
        clauses = ["project_id=?"]
        params: list[Any] = [project_id]
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if lifecycle:
            clauses.append("lifecycle=?")
            params.append(lifecycle)
        rows = self.db.query(
            "SELECT * FROM findings WHERE " + " AND ".join(clauses)
            + " ORDER BY last_detected DESC, id LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
            limit=limit,
        )
        output = []
        for row in rows:
            item = dict(row)
            for field in ("cvss", "raw"):
                item[field] = store.loads(item.get(field, "{}"), {})
            item["evidence"] = store.loads(item.get("evidence", "[]"), [])
            output.append(models.Finding.from_dict(item))
        return output

    def get_finding(self, org_id: str, finding_id: str) -> Any:
        return self._finding(org_id, finding_id)

    def ingest(
        self,
        org_id: str,
        finding: Any,
        evidence: list[Any] | None = None,
        *,
        scan_id: str = "",
        raw: dict[str, Any] | None = None,
        job_id: str = "",
    ) -> dict[str, Any]:
        """Normalize and correlate scanner data only within its owned scan."""
        if not isinstance(finding, models.Finding):
            raise errors.ValidationError("finding record is invalid")
        if evidence is None:
            evidence = []
        if not isinstance(evidence, list) or len(evidence) > _MAX_EVIDENCE_PER_INGEST:
            raise errors.ValidationError("finding evidence list exceeds the allowed bound")
        try:
            finding.finalize()
        except Exception:
            raise errors.ValidationError("finding record is invalid") from None
        try:
            scan = self.platform.scan_get(scan_id or finding.scan_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("scan not found") from None
        project = self._project(org_id, scan.project_id)
        if project.id != finding.project_id or scan.project_id != finding.project_id:
            raise errors.AuthorizationError("finding scan scope does not match its project")
        self._asset_in_project(project.id, finding.asset_id)
        if self.correlation is None:
            return {"finding_id": self.platform.finding_ingest(finding, evidence=evidence).id, "deduped": False}
        result = self.correlation.ingest_finding(
            finding,
            evidence,
            scan_id=scan.id,
            raw=raw if isinstance(raw, dict) else finding.raw,
            job_id=job_id,
        )
        if not isinstance(result, dict) or not result.get("finding_id"):
            raise errors.PersistenceError("finding correlation returned an invalid result")
        return result

    def set_status(
        self,
        org_id: str,
        finding_id: str,
        new_status: str,
        *,
        actor: str = "api",
    ) -> Any:
        finding = self._finding(org_id, finding_id)
        if new_status not in models.FINDING_STATUSES:
            raise errors.ValidationError("finding lifecycle is not supported")
        return self.platform.finding_set_status(finding.id, new_status, actor=actor)

    def assign(
        self,
        org_id: str,
        finding_id: str,
        owner_id: str,
        *,
        actor: str = "api",
    ) -> dict[str, Any]:
        """Assign a finding through its canonical remediation ticket."""
        finding = self._finding(org_id, finding_id)
        if self.remediation is None:
            raise errors.ConfigurationError("remediation workflow is unavailable")
        ticket = self.remediation.ensure(finding.id, actor=actor, org_id=org_id)
        assigned = self.remediation.assign(
            ticket["id"], "user", owner_id, actor=actor, org_id=org_id
        )
        return assigned

    def remediation_link(self, org_id: str, finding_id: str) -> dict[str, Any] | None:
        finding = self._finding(org_id, finding_id)
        rows = self.db.query(
            "SELECT id, org_id, project_id, finding_id, status, owner_type, "
            "owner_id, due_at, verification_status, verification_scan_id "
            "FROM remediation_tickets WHERE org_id=? AND project_id=? "
            "AND finding_id=? ORDER BY created_at DESC, id LIMIT 1",
            (org_id, finding.project_id, finding.id),
            limit=1,
        )
        return dict(rows[0]) if rows else None

    def observations(self, org_id: str, finding_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        finding = self._finding(org_id, finding_id)
        if self.correlation is None:
            return []
        if type(limit) is not int or not 1 <= limit <= 500:
            raise errors.ValidationError("finding observation limit is outside the allowed range")
        return self.correlation.observations(finding.id, limit=limit)

    def evidence_list(self, org_id: str, finding_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        finding = self._finding(org_id, finding_id)
        if type(limit) is not int or not 1 <= limit <= 500:
            raise errors.ValidationError("finding evidence limit is outside the allowed range")
        return self.platform.evidence_list(finding.id, limit=limit)


__all__ = ["FindingService"]
