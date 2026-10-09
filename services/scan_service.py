"""Tenant-scoped scan orchestration over the canonical job and scan engines.

This adapter owns API-facing validation, scope enforcement, idempotency
claims, scan/job handoff, and synchronized control operations. Execution itself
remains in the existing worker and scanner registry.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
models = _domain_module("models")

_INTERNAL_PROFILES = frozenset({"federation-bulk", "integration-delivery", "report-generation"})
_MATERIAL_REQUIRED_PROFILES = frozenset({"container-scan", "kubernetes-scan", "iac-scan"})


class ScanService:
    """Coordinates scan lifecycle and execution handoff without a second queue."""

    def __init__(
        self,
        platform: Any,
        jobs: Any,
        *,
        idempotency: Any = None,
        authorization: Any = None,
    ) -> None:
        self.platform = platform
        self.db = platform.db
        self.jobs = jobs
        self.registry = getattr(jobs, "registry", None)
        self.idempotency = idempotency
        self.authorization = authorization

    def _project(self, org_id: str, project_id: str) -> Any:
        if not isinstance(org_id, str) or not org_id or not isinstance(project_id, str) or not project_id:
            raise errors.ValidationError("tenant and project scope are required")
        try:
            project = self.platform.project_get(project_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("project not found") from None
        if project.org_id != org_id:
            raise errors.NotFoundError("project not found")
        return project

    def _scan(self, org_id: str, scan_id: str) -> tuple[Any, Any]:
        if not isinstance(scan_id, str) or not scan_id:
            raise errors.ValidationError("scan identifier is required")
        try:
            scan = self.platform.scan_get(scan_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("scan not found") from None
        project = self._project(org_id, scan.project_id)
        if project.id != scan.project_id:
            raise errors.NotFoundError("scan not found")
        return scan, project

    def _profile(self, profile_name: str, *, allow_internal: bool = False) -> Any:
        if self.registry is None:
            raise errors.ConfigurationError("scan profile registry is unavailable")
        if not isinstance(profile_name, str) or not 1 <= len(profile_name) <= 64:
            raise errors.ValidationError("scan profile is invalid")
        try:
            profile = self.registry.get(profile_name)
        except Exception:
            raise errors.ValidationError("scan profile is not supported") from None
        if profile_name in _INTERNAL_PROFILES and not allow_internal:
            raise errors.AuthorizationError("scan profile is available only through its dedicated service")
        if profile_name in _MATERIAL_REQUIRED_PROFILES:
            raise errors.ValidationError("scan profile requires a staged input API that is not configured")
        return profile

    def claim_create(self, org_id: str, project_id: str, key: str, body: dict[str, Any]) -> Any:
        """Reserve an API scan request key in the shared persistent store."""
        self._project(org_id, project_id)
        if self.idempotency is None:
            raise errors.ConfigurationError("scan idempotency store is unavailable")
        return self.idempotency.claim(
            org_id,
            "scan.create:" + project_id,
            key,
            {"project_id": project_id, "body": body},
        )

    def complete_create(self, claim: Any, *, status_code: int, response: dict[str, Any]) -> None:
        if self.idempotency is None:
            raise errors.ConfigurationError("scan idempotency store is unavailable")
        self.idempotency.complete(claim, status_code=status_code, response=response)

    def fail_create(self, claim: Any) -> None:
        if self.idempotency is None:
            raise errors.ConfigurationError("scan idempotency store is unavailable")
        self.idempotency.fail(claim)

    def _queue(
        self,
        org_id: str,
        project_id: str,
        profile_name: str,
        payload: dict[str, Any],
        *,
        actor: str,
        actor_id: str = "",
        active_enabled: bool = False,
        max_attempts: int = 3,
        timeout_seconds: int | None = None,
        job_type: str = "scan",
        internal_report: bool = False,
    ) -> tuple[Any, Any]:
        project = self._project(org_id, project_id)
        if self.jobs is None:
            raise errors.ConfigurationError("scan job service is unavailable")
        if not isinstance(payload, dict):
            raise errors.ValidationError("scan payload must be an object")
        profile = self._profile(profile_name, allow_internal=internal_report)
        if internal_report and (profile_name != "report-generation" or job_type != "report"):
            raise errors.AuthorizationError("internal scan handoff is not allowed")
        try:
            self.jobs.validate_payload(payload)
        except Exception:
            raise errors.ValidationError("scan payload is invalid for the job engine") from None
        if type(active_enabled) is not bool:
            raise errors.ValidationError("active_enabled must be a boolean")
        if profile.active_required and not active_enabled:
            raise errors.ValidationError("active scan profile requires explicit authorization")
        if active_enabled and not profile.active_required:
            raise errors.ValidationError("active scanning is not supported by this profile")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
            raise errors.ValidationError("max_attempts must be between 1 and 5")
        configured_timeout = max(1, min(3600, int(profile.timeout)))
        timeout = configured_timeout if timeout_seconds is None else timeout_seconds
        if type(timeout) is not int or not 1 <= timeout <= configured_timeout:
            raise errors.ValidationError("timeout_seconds exceeds the profile's configured limit")

        if profile.in_process:
            required_field = {"cloud-scan": "account_id", "cloud-inventory": "account_id"}.get(profile_name, "")
            if required_field and not payload.get(required_field):
                raise errors.ValidationError("a registered in-process entity reference is required")
            if profile_name == "posture-snapshot" and payload.get("target"):
                raise errors.ValidationError("posture snapshot does not accept a target")
        elif not internal_report:
            target = str(payload.get("target") or payload.get("bucket") or payload.get("service") or "")
            if not target:
                raise errors.ValidationError("a scan target is required")
            try:
                scope_result = self.platform.scope_check(project_id, target)
            except errors.SecurityToolkitError:
                raise
            except Exception:
                raise errors.AuthorizationError("scan target scope could not be verified") from None
            if not isinstance(scope_result, dict) or scope_result.get("in_scope") is not True:
                raise errors.AuthorizationError("scan target is outside the project's authorized scope")

        scope_ref = str(project.scope_policy.get("name", ""))[:128]
        scan_id = models.stable_id(
            models.NS_SCAN,
            f"{org_id}|{project_id}|{profile_name}|{uuid4().hex}",
        )
        scan = None
        try:
            scan = self.platform.scan_create(
                project_id,
                profile_name,
                scope_ref=scope_ref,
                initiator={"actor": str(actor)[:128]},
                scan_id=scan_id,
                actor=actor,
            )
            self.platform.scan_transition(scan.id, "queued")
            job = self.jobs.create_job(
                scan.id,
                profile_name,
                payload,
                job_type=job_type,
                active_enabled=active_enabled,
                max_attempts=max_attempts,
                timeout_seconds=timeout,
                actor_id=actor_id,
                actor=actor,
            )
        except Exception:
            if scan is not None:
                try:
                    current = self.platform.scan_get(scan.id)
                    if current.status in {"pending", "queued"}:
                        failure_code = "report_job_create_failed" if internal_report else "job_create_failed"
                        failure_message = "The report job could not be queued" if internal_report else "The scan job could not be queued"
                        self.platform.scan_set_error(scan.id, failure_code, failure_message)
                        self.platform.scan_transition(scan.id, "failed")
                except Exception:
                    pass
            raise
        return self.platform.scan_get(scan.id), job

    def queue_scan(
        self,
        org_id: str,
        project_id: str,
        profile_name: str,
        payload: dict[str, Any],
        *,
        actor: str,
        actor_id: str = "",
        active_enabled: bool = False,
        max_attempts: int = 3,
        timeout_seconds: int | None = None,
    ) -> tuple[Any, Any]:
        """Validate, scope-check, persist, and hand off a customer scan."""
        return self._queue(
            org_id,
            project_id,
            profile_name,
            payload,
            actor=actor,
            actor_id=actor_id,
            active_enabled=active_enabled,
            max_attempts=max_attempts,
            timeout_seconds=timeout_seconds,
        )

    def queue_report_job(
        self,
        org_id: str,
        project_id: str,
        payload: dict[str, Any],
        *,
        actor: str,
        actor_id: str = "",
        timeout_seconds: int | None = None,
    ) -> tuple[Any, Any]:
        """Restricted internal handoff for the existing report worker profile."""
        return self._queue(
            org_id,
            project_id,
            "report-generation",
            payload,
            actor=actor,
            actor_id=actor_id,
            active_enabled=False,
            max_attempts=3,
            timeout_seconds=timeout_seconds,
            job_type="report",
            internal_report=True,
        )

    def get_scan(self, org_id: str, scan_id: str) -> Any:
        return self._scan(org_id, scan_id)[0]

    def list_scans(
        self,
        org_id: str,
        project_id: str,
        *,
        status: str = "",
        profile: str = "",
        limit: int = 100,
    ) -> list[Any]:
        self._project(org_id, project_id)
        if type(limit) is not int or not 1 <= limit <= 500:
            raise errors.ValidationError("scan list limit is outside the allowed range")
        if status and status not in models.SCAN_STATUSES:
            raise errors.ValidationError("scan status is not supported")
        if profile:
            self._profile(profile, allow_internal=True)
        scans = self.platform.scan_list(project_id, limit=limit)
        if status:
            scans = [scan for scan in scans if scan.status == status]
        if profile:
            scans = [scan for scan in scans if scan.profile == profile]
        return scans

    def _job_for_scan(self, org_id: str, project_id: str, scan_id: str) -> Any:
        rows = self.db.query(
            "SELECT id FROM jobs WHERE org_id=? AND project_id=? AND scan_id=? "
            "ORDER BY created_at DESC, id DESC LIMIT 1",
            (org_id, project_id, scan_id),
            limit=1,
        )
        if not rows:
            raise errors.NotFoundError("scan job not found")
        try:
            job = self.jobs.job_get(str(rows[0]["id"]))
        except Exception:
            raise errors.NotFoundError("scan job not found") from None
        if job.org_id != org_id or job.project_id != project_id or job.scan_id != scan_id:
            raise errors.NotFoundError("scan job not found")
        return job

    def cancel_scan(self, org_id: str, scan_id: str, *, actor: str) -> tuple[Any, Any]:
        scan, _project = self._scan(org_id, scan_id)
        job = self._job_for_scan(org_id, scan.project_id, scan.id)
        cancelled = self.jobs.cancel(job.id, actor=actor)
        if cancelled.status == "cancelling" and not cancelled.worker_id and not cancelled.started_at:
            cancelled = self.jobs.cancel_finalize(job.id, actor=actor)
            current = self.platform.scan_get(scan.id)
            if current.status not in {"cancelled", "completed", "failed"}:
                self.platform.scan_transition(scan.id, "cancelled")
        else:
            current = self.platform.scan_get(scan.id)
            if current.status in {"pending", "queued", "running", "paused"}:
                self.platform.scan_transition(scan.id, "cancelling")
        return self.platform.scan_get(scan.id), cancelled

    def pause_scan(self, org_id: str, scan_id: str, *, actor: str) -> tuple[Any, Any]:
        scan, _project = self._scan(org_id, scan_id)
        job = self._job_for_scan(org_id, scan.project_id, scan.id)
        paused = self.jobs.pause(job.id, actor=actor)
        current = self.platform.scan_get(scan.id)
        if paused.status == "paused" and current.status in {"pending", "queued", "running"}:
            self.platform.scan_transition(scan.id, "paused")
        return self.platform.scan_get(scan.id), paused

    def resume_scan(self, org_id: str, scan_id: str, *, actor: str) -> tuple[Any, Any]:
        scan, _project = self._scan(org_id, scan_id)
        job = self._job_for_scan(org_id, scan.project_id, scan.id)
        resumed = self.jobs.resume(job.id, actor=actor)
        current = self.platform.scan_get(scan.id)
        if current.status == "paused":
            resumed_scan_state = {
                "queued": "queued",
                "running": "running",
            }.get(resumed.status, "")
            if resumed_scan_state:
                self.platform.scan_transition(scan.id, resumed_scan_state)
        return self.platform.scan_get(scan.id), resumed


__all__ = ["ScanService"]
