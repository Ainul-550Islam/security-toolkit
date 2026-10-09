"""Customer notification orchestration above the canonical provider adapter.

Preferences, encrypted webhook secrets, notification deduplication, delivery
attempts, retries, and provider calls remain in the existing notification
engine. This wrapper supplies tenant checks, safe templates, and explicit
availability/delivery state without pretending that unavailable providers
have delivered anything.
"""

from __future__ import annotations

from typing import Any, Mapping

from .customer_resource_service import _domain_module
from .notifications import NotificationService as TenantNotificationFacade

errors = _domain_module("errors")
redact = _domain_module("redact")

_MAX_LIMIT = 500
_TEMPLATE_FIELDS = frozenset({"alert_id", "title", "severity", "state", "project_id", "occurrence_count"})
_TEMPLATES = {
    "security_alert_v1": {
        "subject_prefix": "Security alert",
        "description": "A security alert was recorded for the authorized project.",
    },
}


class NotificationService:
    """Tenant-aware orchestration facade that reuses an existing notifier."""

    def __init__(self, platform: Any, *, facade: Any = None) -> None:
        self.platform = platform
        self.db = platform.db
        self.facade = facade if facade is not None else TenantNotificationFacade(platform)

    def __getattr__(self, name: str) -> Any:
        """Keep the established API adapter surface while centralizing checks."""
        return getattr(self.facade, name)

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

    def available_channels(self) -> dict[str, str]:
        return self.facade.available_channels()

    def template_catalog(self) -> dict[str, Any]:
        """Describe the small built-in template set without provider claims."""
        return {
            "templates": [
                {
                    "id": template_id,
                    "subject_prefix": details["subject_prefix"],
                    "description": details["description"],
                    "fields": sorted(_TEMPLATE_FIELDS),
                }
                for template_id, details in sorted(_TEMPLATES.items())
            ],
            "source": "built_in_safe_templates",
        }

    def render_template(self, template_id: str, values: Mapping[str, Any]) -> dict[str, str]:
        """Render a bounded, redacted text template; never sends a message."""
        template = _TEMPLATES.get(str(template_id or ""))
        if template is None:
            raise errors.ValidationError("notification template is not supported")
        if not isinstance(values, Mapping) or set(values) - _TEMPLATE_FIELDS:
            raise errors.ValidationError("notification template variables are invalid")
        title = str(redact.redact_text(values.get("title", "Security event")))[:200]
        severity = str(redact.redact_text(values.get("severity", "unknown")))[:32]
        project_id = str(redact.redact_text(values.get("project_id", "")))[:128]
        alert_id = str(redact.redact_text(values.get("alert_id", "")))[:128]
        subject = f"{template['subject_prefix']}: {title}"[:240]
        body = (
            f"{template['description']} Severity: {severity}. "
            f"Project reference: {project_id or 'not provided'}. "
            f"Alert reference: {alert_id or 'not provided'}."
        )[:1000]
        return {"template_id": str(template_id), "subject": subject, "body": body}

    def settings_view(self, project_id: str, *, org_id: str | None = None) -> dict[str, Any]:
        project = self._project(str(org_id or ""), project_id)
        return self.facade.settings_view(project_id, org_id=project.org_id)

    def configure(
        self,
        org_id: str,
        project_id: str,
        *,
        email_enabled: bool = False,
        email_to: str = "",
        webhook_enabled: bool = False,
        webhook_url: str = "",
        webhook_secret: str = "",
        keep_secret: bool = False,
        actor: str = "api",
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        return self.facade.configure(
            org_id,
            project_id,
            email_enabled=email_enabled,
            email_to=email_to,
            webhook_enabled=webhook_enabled,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            keep_secret=keep_secret,
            actor=actor,
        )

    def update_settings(
        self,
        org_id: str,
        project_id: str,
        changes: Mapping[str, Any],
        *,
        actor: str = "api",
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        return self.facade.update_settings(org_id, project_id, changes, actor=actor)

    def dispatch_alert(
        self,
        alert_id: str,
        occurrence_event_id: str,
        rule: dict[str, Any],
        *,
        org_id: str,
        actor: str = "scheduler",
    ) -> int:
        rows = self.db.query(
            "SELECT project_id FROM alerts WHERE id=? AND org_id=? LIMIT 1",
            (alert_id, org_id),
            limit=1,
        )
        if not rows:
            raise errors.NotFoundError("alert not found")
        self._project(org_id, str(rows[0]["project_id"]))
        return self.facade.dispatch_alert(
            alert_id,
            occurrence_event_id,
            rule,
            org_id=org_id,
            actor=actor,
        )

    def process_pending(self, org_id: str, *, limit: int = 10, now: str | None = None) -> int:
        if not org_id or type(limit) is not int or not 1 <= limit <= 100:
            raise errors.ValidationError("notification processing scope or limit is invalid")
        self.platform.org_require(org_id)
        return self.facade.process_pending(org_id, limit=limit, now=now)

    def retry_due(self, org_id: str, *, limit: int = 20, now: str | None = None) -> int:
        if not org_id or type(limit) is not int or not 1 <= limit <= 100:
            raise errors.ValidationError("notification retry scope or limit is invalid")
        self.platform.org_require(org_id)
        return self.facade.retry_due(org_id, limit=limit, now=now)

    def notification_view(
        self,
        org_id: str,
        project_id: str,
        notification_id: str,
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        return self.facade.notification_view(org_id, project_id, notification_id)

    def retry(
        self,
        org_id: str,
        notification_id: str,
        *,
        project_id: str | None = None,
        actor: str = "api",
    ) -> dict[str, Any]:
        if project_id is not None:
            self._project(org_id, project_id)
        return self.facade.retry(
            org_id, notification_id, project_id=project_id, actor=actor
        )

    def list_notifications(
        self,
        org_id: str,
        project_id: str,
        *,
        status: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self._project(org_id, project_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("notification page limit is outside the allowed range")
        return self.facade.list_notifications(org_id, project_id, status=status, limit=limit)

    def notification_counts(self, org_id: str, project_id: str) -> dict[str, int]:
        self._project(org_id, project_id)
        return self.facade.notification_counts(org_id, project_id)


__all__ = ["NotificationService"]
