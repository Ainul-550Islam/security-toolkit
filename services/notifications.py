"""Tenant-scoped facade over the repository's canonical notification service.

The facade does not add a second delivery queue or secret store. It delegates
configuration, AES-GCM secret handling, provider delivery, deduplication,
retry/backoff, and audit writes to ``python/notify.py`` while requiring tenant
scope for every operation exposed here.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any, Mapping


def _domain_module(name: str) -> Any:
    """Load one existing domain module without shadowing standard libraries."""
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
        legacy_directory = str(Path(__file__).resolve().parents[1] / "python")
        if legacy_directory not in sys.path:
            sys.path.append(legacy_directory)
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError:
            raise ImportError("legacy platform dependency is unavailable") from None


errors = _domain_module("errors")


class NotificationService:
    """Safe tenant boundary for the existing notification engine."""

    def __init__(
        self,
        platform: Any,
        *,
        providers: Mapping[str, Any] | None = None,
        limiter: Any = None,
    ) -> None:
        self.svc = platform
        self.db = platform.db
        try:
            import notify
        except ImportError:
            raise errors.ConfigurationError(
                "notification delivery service is unavailable"
            ) from None
        self._engine = notify.NotificationService(
            platform,
            providers=dict(providers) if providers is not None else None,
            limiter=limiter,
        )

    def _project(self, org_id: str, project_id: str) -> Any:
        try:
            project = self.svc.project_require(project_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("project not found") from None
        if project.org_id != org_id:
            raise errors.NotFoundError("project not found")
        return project

    def available_channels(self) -> dict[str, str]:
        """Return provider availability without endpoint or secret values."""
        providers = getattr(self._engine, "providers", {})
        return {
            channel: "CONFIGURED" if provider is not None else "UNAVAILABLE"
            for channel, provider in sorted(providers.items())
            if isinstance(channel, str) and 1 <= len(channel) <= 32
        }

    def settings_view(self, project_id: str, *, org_id: str | None = None) -> dict[str, Any]:
        if org_id is None:
            project = self.svc.project_require(project_id)
            org_id = project.org_id
        self._project(org_id, project_id)
        return self._engine.settings_view(project_id)

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
        self._engine.settings_set(
            project_id,
            email_enabled=email_enabled,
            email_to=email_to,
            webhook_enabled=webhook_enabled,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            keep_secret=keep_secret,
            actor=actor,
        )
        return self._engine.settings_view(project_id)

    def update_settings(
        self,
        org_id: str,
        project_id: str,
        changes: Mapping[str, Any],
        *,
        actor: str = "api",
    ) -> dict[str, Any]:
        """Apply a partial settings update without exposing persisted secrets.

        The existing engine owns persistence and secret migration. This
        adapter reads its internal settings once to preserve omitted values,
        then returns only the engine's safe, secret-free view.
        """
        self._project(org_id, project_id)
        allowed = frozenset({
            "email_enabled", "email_to", "webhook_enabled", "webhook_url",
            "webhook_secret", "keep_secret",
        })
        if not isinstance(changes, Mapping) or set(changes) - allowed:
            raise errors.ValidationError("notification_settings_invalid")
        for field in ("email_enabled", "webhook_enabled", "keep_secret"):
            if field in changes and type(changes[field]) is not bool:
                raise errors.ValidationError("notification_settings_invalid")
        for field, maximum in (("email_to", 200), ("webhook_url", 512), ("webhook_secret", 4096)):
            if field not in changes:
                continue
            value = changes[field]
            if not isinstance(value, str):
                raise errors.ValidationError("notification_settings_invalid")
            try:
                size = len(value.encode("utf-8", "strict"))
            except UnicodeEncodeError:
                raise errors.ValidationError("notification_settings_invalid") from None
            if size > maximum:
                raise errors.ValidationError("notification_settings_invalid")
        current = self._engine.settings_get(project_id)
        has_secret = bool(current.get("has_secret"))
        has_new_secret = "webhook_secret" in changes
        if "keep_secret" in changes:
            keep_secret = bool(changes["keep_secret"])
        else:
            keep_secret = has_secret and not has_new_secret
        return self.configure(
            org_id,
            project_id,
            email_enabled=changes.get(
                "email_enabled", bool(current.get("email_enabled"))
            ),
            email_to=changes.get("email_to", str(current.get("email_to", ""))),
            webhook_enabled=changes.get(
                "webhook_enabled", bool(current.get("webhook_enabled"))
            ),
            webhook_url=changes.get("webhook_url", str(current.get("webhook_url", ""))),
            webhook_secret=changes.get("webhook_secret", ""),
            keep_secret=keep_secret,
            actor=actor,
        )

    def dispatch_alert(
        self,
        alert_id: str,
        occurrence_event_id: str,
        rule: dict[str, Any],
        *,
        org_id: str,
        actor: str = "scheduler",
    ) -> int:
        if not org_id:
            raise errors.ValidationError("tenant scope is required")
        rows = self.db.query(
            "SELECT id, org_id, project_id FROM alerts WHERE id=? AND org_id=? LIMIT 1",
            (alert_id, org_id),
        )
        if not rows:
            raise errors.NotFoundError("alert not found")
        self._project(org_id, str(rows[0]["project_id"]))
        return self._engine.dispatch_alert(
            alert_id,
            occurrence_event_id,
            dict(rule or {}),
            actor=actor,
            org_id=org_id,
        )

    def process_pending(
        self,
        org_id: str,
        *,
        limit: int = 10,
        now: str | None = None,
    ) -> int:
        if not org_id:
            raise errors.ValidationError("tenant scope is required")
        return self._engine.process_pending(
            limit=limit,
            now=now,
            org_id=org_id,
        )

    def retry_due(
        self,
        org_id: str,
        *,
        limit: int = 20,
        now: str | None = None,
    ) -> int:
        if not org_id:
            raise errors.ValidationError("tenant scope is required")
        return self._engine.retry_due(
            limit=limit,
            now=now,
            org_id=org_id,
        )

    def notification_view(
        self,
        org_id: str,
        project_id: str,
        notification_id: str,
    ) -> dict[str, Any]:
        self._project(org_id, project_id)
        rows = self.db.query(
            "SELECT id FROM notifications WHERE id=? AND org_id=? "
            "AND project_id=? LIMIT 1",
            (notification_id, org_id, project_id),
        )
        if not rows:
            raise errors.NotFoundError("notification not found")
        return self._engine.notification_view(notification_id, org_id=org_id)

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
            rows = self.db.query(
                "SELECT project_id FROM notifications WHERE id=? AND org_id=? "
                "AND project_id=? LIMIT 1",
                (notification_id, org_id, project_id),
            )
        else:
            rows = self.db.query(
                "SELECT project_id FROM notifications WHERE id=? AND org_id=? LIMIT 1",
                (notification_id, org_id),
            )
        if not rows:
            raise errors.NotFoundError("notification not found")
        self._project(org_id, str(rows[0]["project_id"]))
        return self._engine.retry_manual(
            notification_id,
            actor=actor,
            org_id=org_id,
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
        return self._engine.list_notifications(
            project_id,
            status=status,
            limit=limit,
        )

    def notification_counts(self, org_id: str, project_id: str) -> dict[str, int]:
        self._project(org_id, project_id)
        return self._engine.notification_counts(project_id)


__all__ = ["NotificationService"]
