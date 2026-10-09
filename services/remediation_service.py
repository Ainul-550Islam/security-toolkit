"""Tenant-scoped remediation workflow facade over the canonical remedy engine.

State transitions, due-date rules, verification scan creation, history, and
immutable audit writes remain in ``python.remedy.RemediationService``. This
adapter verifies the tenant/project/finding ownership chain before every
customer-facing read or mutation.
"""

from __future__ import annotations

from typing import Any

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
models = _domain_module("models")

_MAX_LIMIT = 500


class RemediationService:
    """Tenant-enforcing facade around an existing remediation workflow engine."""

    def __init__(self, platform: Any, engine: Any, *, identity: Any = None) -> None:
        self.platform = platform
        self.db = platform.db
        self.engine = engine
        self.identity = identity

    def _project(self, org_id: str, project_id: str) -> Any:
        if not project_id:
            raise errors.ValidationError("project scope is required")
        try:
            project = self.platform.project_get(project_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("project not found") from None
        if org_id and project.org_id != org_id:
            raise errors.NotFoundError("project not found")
        return project

    def _ticket(self, ticket_id: str, org_id: str | None = None) -> dict[str, Any]:
        if not isinstance(ticket_id, str) or not ticket_id:
            raise errors.ValidationError("remediation identifier is required")
        if org_id:
            rows = self.db.query(
                "SELECT id, org_id, project_id, finding_id FROM remediation_tickets "
                "WHERE id=? AND org_id=? LIMIT 1",
                (ticket_id, org_id),
                limit=1,
            )
        else:
            rows = self.db.query(
                "SELECT id, org_id, project_id, finding_id FROM remediation_tickets "
                "WHERE id=? LIMIT 1",
                (ticket_id,),
                limit=1,
            )
        if not rows:
            raise errors.NotFoundError("remediation ticket not found")
        row = dict(rows[0])
        project = self._project(str(row["org_id"]), str(row["project_id"]))
        if project.org_id != str(row["org_id"]):
            raise errors.NotFoundError("remediation ticket not found")
        finding_rows = self.db.query(
            "SELECT id FROM findings WHERE id=? AND project_id=? LIMIT 1",
            (str(row["finding_id"]), str(row["project_id"])),
            limit=1,
        )
        if not finding_rows:
            raise errors.NotFoundError("remediation ticket not found")
        return row

    def _finding(self, finding_id: str, org_id: str | None = None) -> tuple[Any, Any]:
        try:
            finding = self.platform.finding_get(finding_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("finding not found") from None
        project = self._project(org_id or "", finding.project_id)
        if org_id and project.org_id != org_id:
            raise errors.NotFoundError("finding not found")
        return finding, project

    def _resolve_org_for_project(self, project_id: str, org_id: str | None) -> str:
        project = self._project(org_id or "", project_id)
        return project.org_id

    def list_tickets(
        self,
        project_id: str,
        *,
        status: str = "",
        limit: int = 100,
        offset: int = 0,
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self._resolve_org_for_project(project_id, org_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("remediation page limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset < _MAX_LIMIT or offset + limit > _MAX_LIMIT:
            raise errors.ValidationError("remediation result window is limited")
        if status and status not in models.REMEDIATION_STATUSES:
            raise errors.ValidationError("remediation status is not supported")
        return self.engine.list_tickets(project_id, status=status, limit=limit + offset)[offset:]

    def ensure(
        self,
        finding_id: str,
        *,
        actor: str = "api",
        org_id: str | None = None,
    ) -> dict[str, Any]:
        _finding, project = self._finding(finding_id, org_id)
        ticket = self.engine.ensure(finding_id, actor=actor)
        if str(ticket.get("org_id", "")) != project.org_id or str(ticket.get("project_id", "")) != project.id:
            raise errors.PersistenceError("remediation ticket ownership mismatch")
        return ticket

    def view(
        self,
        ticket_id: str,
        *,
        history_limit: int = 50,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        self._ticket(ticket_id, org_id)
        if type(history_limit) is not int or not 1 <= history_limit <= 100:
            raise errors.ValidationError("remediation history limit is outside the allowed range")
        return self.engine.view(ticket_id, history_limit=history_limit)

    def status(
        self,
        ticket_id: str,
        new_status: str,
        *,
        actor: str = "api",
        reason: str = "",
        org_id: str | None = None,
    ) -> dict[str, Any]:
        self._ticket(ticket_id, org_id)
        if new_status not in models.REMEDIATION_STATUSES:
            raise errors.ValidationError("remediation status is not supported")
        return self.engine.status(ticket_id, new_status, actor=actor, reason=reason)

    def assign(
        self,
        ticket_id: str,
        owner_type: str,
        owner_id: str,
        *,
        actor: str = "api",
        org_id: str | None = None,
    ) -> dict[str, Any]:
        ticket = self._ticket(ticket_id, org_id)
        if str(owner_type).strip().lower() == "user" and self.identity is not None:
            try:
                user = self.identity.user_get(owner_id)
            except Exception:
                raise errors.NotFoundError("remediation owner not found") from None
            if user.org_id != ticket["org_id"] or user.status != "active":
                raise errors.NotFoundError("remediation owner not found")
        assigned = self.engine.assign(ticket_id, owner_type, owner_id, actor=actor)
        if str(assigned.get("org_id", "")) != ticket["org_id"]:
            raise errors.PersistenceError("remediation assignment scope mismatch")
        return assigned

    def set_due(
        self,
        ticket_id: str,
        due_at: str,
        *,
        actor: str = "api",
        org_id: str | None = None,
    ) -> dict[str, Any]:
        self._ticket(ticket_id, org_id)
        return self.engine.set_due(ticket_id, due_at, actor=actor)

    def add_comment(
        self,
        ticket_id: str,
        comment: str,
        *,
        actor: str = "api",
        org_id: str | None = None,
    ) -> dict[str, Any]:
        self._ticket(ticket_id, org_id)
        return self.engine.add_comment(ticket_id, comment, actor=actor)

    def request_verification(
        self,
        ticket_id: str,
        *,
        actor: str = "api",
        org_id: str | None = None,
    ) -> dict[str, Any]:
        ticket = self._ticket(ticket_id, org_id)
        result = self.engine.request_verification(ticket_id, actor=actor)
        if str(result.get("org_id", "")) != ticket["org_id"]:
            raise errors.PersistenceError("verification request scope mismatch")
        return result

    def list_verifications(
        self,
        project_id: str,
        *,
        limit: int = 100,
        status: str = "",
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self._resolve_org_for_project(project_id, org_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("verification page limit is outside the allowed range")
        if status and status not in models.VERIFICATION_STATUSES:
            raise errors.ValidationError("verification status is not supported")
        return self.engine.list_verifications(project_id, limit=limit, status=status)

    def sla_get(self, project_id: str, *, org_id: str | None = None) -> dict[str, Any]:
        self._resolve_org_for_project(project_id, org_id)
        return self.engine.sla_get(project_id)

    def sla_set(
        self,
        project_id: str,
        *,
        priority: str,
        hours: float,
        actor: str = "api",
        org_id: str | None = None,
    ) -> dict[str, Any]:
        self._resolve_org_for_project(project_id, org_id)
        return self.engine.sla_set(project_id, priority=priority, hours=hours, actor=actor)


__all__ = ["RemediationService"]
