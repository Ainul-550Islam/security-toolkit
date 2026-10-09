"""Tenant-safe report orchestration around the canonical report engine.

Report snapshots, hashes, renderers, immutable evidence snapshots, and
retention mechanics stay in ``python.reporting.ReportService``. This service
adds owned-project checks and uses the existing scan/job/idempotency services
for asynchronous customer report requests.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
models = _domain_module("models")

_SUPPORTED_FORMATS = frozenset({"json", "html", "pdf"})


class ReportService:
    """Authorization-aware report lifecycle facade over existing engines."""

    def __init__(
        self,
        platform: Any,
        engine: Any,
        *,
        jobs: Any = None,
        scans: Any = None,
        idempotency: Any = None,
    ) -> None:
        self.platform = platform
        self.db = platform.db
        self.engine = engine
        self.jobs = jobs
        self.scans = scans
        self.idempotency = idempotency

    @property
    def supported_formats(self) -> tuple[str, ...]:
        return tuple(sorted(_SUPPORTED_FORMATS))

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

    def _report(self, org_id: str, report_id: str, *, with_payload: bool = False) -> dict[str, Any]:
        try:
            report = self.engine.get_run(report_id, with_payload=with_payload)
        except errors.NotFoundError:
            raise errors.NotFoundError("report not found") from None
        if not isinstance(report, dict) or str(report.get("org_id", "")) != org_id:
            raise errors.NotFoundError("report not found")
        self._project(org_id, str(report.get("project_id", "")))
        return report

    def list_reports(
        self,
        org_id: str,
        project_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
        report_type: str = "",
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        if type(limit) is not int or not 1 <= limit <= 500:
            raise errors.ValidationError("report page limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset <= 100_000:
            raise errors.ValidationError("report page offset is outside the allowed range")
        if report_type and report_type not in models.REPORT_TYPES:
            raise errors.ValidationError("report type is not supported")
        return self.engine.list_runs(
            project_id, limit=limit, offset=offset, report_type=report_type
        )

    def get_report(self, org_id: str, report_id: str, *, with_payload: bool = False) -> dict[str, Any]:
        return self._report(org_id, report_id, with_payload=with_payload)

    def export_report(self, org_id: str, report_id: str, fmt: str, *, actor: str = "api") -> bytes:
        self._report(org_id, report_id)
        normalized = str(fmt or "").strip().lower()
        if normalized not in _SUPPORTED_FORMATS:
            raise errors.ValidationError("report export format is not supported")
        return self.engine.export(report_id, normalized, actor=actor)

    def create_snapshot(
        self,
        org_id: str,
        project_id: str,
        report_type: str,
        *,
        generated_by: str = "api",
        data_cutoff: str = "",
        filters: dict[str, Any] | None = None,
        title: str = "",
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        if report_type not in models.REPORT_TYPES:
            raise errors.ValidationError("report type is not supported")
        if filters is not None and not isinstance(filters, Mapping):
            raise errors.ValidationError("report filters must be an object")
        snapshot = self.engine.snapshot(
            project_id,
            report_type,
            generated_by=generated_by,
            data_cutoff=data_cutoff,
            filters=dict(filters or {}),
            title=title,
        )
        metadata = snapshot.get("metadata", {}) if isinstance(snapshot, dict) else {}
        if str(metadata.get("org_id", "")) != org_id or str(metadata.get("project_id", "")) != project_id:
            raise errors.PersistenceError("report snapshot ownership mismatch")
        return snapshot

    def store_snapshot(
        self,
        org_id: str,
        project_id: str,
        snapshot: dict[str, Any],
        *,
        store_payload: bool = False,
        evidence_snapshot: bool = False,
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        if not isinstance(snapshot, dict):
            raise errors.ValidationError("report snapshot is invalid")
        metadata = snapshot.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("org_id") != org_id or metadata.get("project_id") != project_id:
            raise errors.AuthorizationError("report snapshot scope does not match the project")
        run = self.engine.store_run(
            snapshot, store_payload=store_payload, evidence_snapshot=evidence_snapshot
        )
        if str(run.get("org_id", "")) != org_id or str(run.get("project_id", "")) != project_id:
            raise errors.PersistenceError("stored report ownership mismatch")
        return run

    def retention_sweep(
        self,
        org_id: str,
        project_id: str,
        *,
        days: int = 90,
        now: str = "",
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        if type(days) is not int or not 1 <= days <= 3650:
            raise errors.ValidationError("report retention days are outside the allowed range")
        return self.engine.retention_sweep(days=days, now=now, project_id=project_id)

    def generate_async(
        self,
        org_id: str,
        project_id: str,
        report_type: str,
        *,
        title: str = "",
        store_payload: bool = False,
        actor: str = "api",
        actor_id: str = "",
        idempotency_key: str = "",
        request_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Claim an idempotency key and hand off report work to the worker."""
        project = self._project(org_id, project_id)
        if self.jobs is None or self.scans is None:
            raise errors.ConfigurationError("asynchronous report service is unavailable")
        if report_type not in models.REPORT_TYPES:
            raise errors.ValidationError("report type is not supported")
        if not isinstance(title, str) or len(title) > 200:
            raise errors.ValidationError("report title is invalid")
        if type(store_payload) is not bool:
            raise errors.ValidationError("store_payload must be a boolean")
        try:
            profile = self.jobs.registry.get("report-generation")
        except Exception:
            raise errors.ConfigurationError("asynchronous report profile is unavailable") from None
        payload: dict[str, Any] = {
            "target": "project:" + project_id,
            "report_type": report_type,
            "store_payload": store_payload,
        }
        if title:
            payload["title"] = title
        try:
            self.jobs.validate_payload(payload)
        except Exception:
            raise errors.ValidationError("report options are invalid for the job engine") from None
        if self.idempotency is None:
            raise errors.ConfigurationError("report idempotency store is unavailable")
        if request_body is not None and not isinstance(request_body, Mapping):
            raise errors.ValidationError("report request body must be an object")
        body = dict(request_body) if request_body is not None else {
            "report_type": report_type,
            "title": title,
            "store_payload": store_payload,
        }
        claim = self.idempotency.claim(
            org_id,
            "report.generate:" + project_id,
            idempotency_key,
            {"project_id": project_id, "body": body},
        )
        if claim.is_replay:
            return {
                "replayed": True,
                "status_code": claim.status_code,
                "response": claim.response,
                "scan_id": str((claim.response or {}).get("data", {}).get("scan_id", "")),
            }

        scan = None
        try:
            scan, job = self.scans.queue_report_job(
                org_id,
                project_id,
                payload,
                actor=actor,
                actor_id=actor_id,
                timeout_seconds=min(900, int(profile.timeout)),
            )
            response = {
                "data": {
                    "report_type": report_type,
                    "status": "queued",
                    "scan_id": scan.id,
                    "job_id": job.id,
                    "job_status": job.status,
                }
            }
            self.idempotency.complete(claim, status_code=202, response=response)
        except Exception:
            try:
                self.idempotency.fail(claim)
            except Exception:
                pass
            if scan is not None:
                try:
                    current = self.platform.scan_get(scan.id)
                    if current.status in {"pending", "queued"}:
                        self.platform.scan_set_error(
                            scan.id,
                            "report_job_create_failed",
                            "The report job could not be queued",
                        )
                        self.platform.scan_transition(scan.id, "failed")
                except Exception:
                    pass
            raise
        return {
            "replayed": False,
            "status_code": 202,
            "response": response,
            "scan_id": scan.id,
        }


__all__ = ["ReportService"]
