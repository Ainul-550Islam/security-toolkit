"""Tenant-safe support operations for the customer resource API.

This adapter extends the repository's existing organization, project, and
identity stores without creating a parallel persistence model. All writes are
parameterized, transactional, bounded, and audited through PlatformService or
IdentityService. It is intentionally narrow; scan, finding, evidence, risk,
notification, and report rules remain owned by their existing domain engines.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _domain_module(name: str) -> Any:
    """Import an existing legacy domain module without shadowing stdlib names."""
    import importlib
    import sys
    from pathlib import Path

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
models = _domain_module("models")

_LOCALE_RE = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")
_PROJECT_FIELDS = frozenset({"name", "description", "status"})


class CustomerResourceService:
    """Safe lifecycle/read helpers used by the customer-facing API adapters."""

    def __init__(self, platform: Any, identity: Any) -> None:
        self.platform = platform
        self.identity = identity
        self.db = platform.db

    def _project(self, org_id: str, project_id: str) -> Any:
        try:
            project = self.platform.project_get(project_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("project not found") from None
        if project.org_id != org_id:
            raise errors.AuthorizationError("Forbidden")
        return project

    def project_update(
        self,
        org_id: str,
        project_id: str,
        changes: Mapping[str, Any],
        *,
        actor: str,
    ) -> Any:
        """Update the mutable project profile/status fields atomically."""
        if not isinstance(changes, Mapping) or not changes:
            raise errors.ValidationError("project_update_invalid")
        if set(changes) - _PROJECT_FIELDS:
            raise errors.ValidationError("project_update_invalid")
        current = self._project(org_id, project_id)
        data = current.to_dict()
        data.update(dict(changes))
        candidate = models.Project.from_dict(data)
        candidate.finalize()
        if candidate.status == "archived" and current.status != "archived":
            action = "project.archived"
        elif current.status == "archived" and candidate.status != "archived":
            action = "project.restored"
        else:
            action = "project.updated"
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "UPDATE projects SET name=?, description=?, status=?, "
                    "updated_at=? WHERE id=? AND org_id=?",
                    (candidate.name, candidate.description, candidate.status,
                     candidate.updated_at, project_id, org_id),
                )
                if cursor.rowcount != 1:
                    raise errors.NotFoundError("project not found")
        except sqlite3.IntegrityError:
            raise errors.DuplicateError("project name already exists") from None
        self.platform.audit(
            action,
            object_type="project",
            object_id=project_id,
            org_id=org_id,
            project_id=project_id,
            actor=actor,
            metadata={
                "name": candidate.name,
                "description_changed": candidate.description != current.description,
                "status": candidate.status,
            },
        )
        return self.platform.project_get(project_id)

    def project_archive(self, org_id: str, project_id: str, *, actor: str) -> Any:
        current = self._project(org_id, project_id)
        if current.status == "archived":
            return current
        return self.project_update(
            org_id, project_id, {"status": "archived"}, actor=actor
        )

    def project_restore(self, org_id: str, project_id: str, *, actor: str) -> Any:
        current = self._project(org_id, project_id)
        if current.status != "archived":
            raise errors.LifecycleError("project is not archived")
        return self.project_update(
            org_id, project_id, {"status": "active"}, actor=actor
        )

    def organization_update(
        self,
        org_id: str,
        changes: Mapping[str, Any],
        *,
        actor: str,
    ) -> Any:
        """Update only the existing organization profile field(s)."""
        if not isinstance(changes, Mapping) or not changes or set(changes) != {"name"}:
            raise errors.ValidationError("organization_update_invalid")
        try:
            current = self.platform.org_get(org_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("organization not found") from None
        candidate = models.Organization.from_dict(current.to_dict())
        candidate.name = changes["name"]
        candidate.finalize()
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "UPDATE organizations SET name=?, updated_at=? WHERE id=?",
                    (candidate.name, candidate.updated_at, org_id),
                )
                if cursor.rowcount != 1:
                    raise errors.NotFoundError("organization not found")
        except sqlite3.IntegrityError:
            raise errors.DuplicateError("organization name already exists") from None
        self.platform.audit(
            "organization.updated",
            object_type="organization",
            object_id=org_id,
            org_id=org_id,
            actor=actor,
            metadata={"name": candidate.name},
        )
        return self.platform.org_get(org_id)

    def organization_preferences_get(self, org_id: str) -> dict[str, Any]:
        self.platform.org_require(org_id)
        rows = self.db.query(
            "SELECT timezone, locale, updated_at FROM organization_preferences "
            "WHERE org_id=? LIMIT 1",
            (org_id,),
        )
        if not rows:
            return {
                "org_id": org_id,
                "timezone": "UTC",
                "locale": "en",
                "configured": False,
                "updated_at": "",
            }
        row = rows[0]
        return {
            "org_id": org_id,
            "timezone": str(row["timezone"]),
            "locale": str(row["locale"]),
            "configured": True,
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _validate_timezone(value: Any) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 64:
            raise errors.ValidationError("organization_timezone_invalid")
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise errors.ValidationError("organization_timezone_invalid") from None
        return value

    @staticmethod
    def _validate_locale(value: Any) -> str:
        if not isinstance(value, str) or len(value) > 35 or not _LOCALE_RE.fullmatch(value):
            raise errors.ValidationError("organization_locale_invalid")
        return value

    def organization_preferences_update(
        self,
        org_id: str,
        changes: Mapping[str, Any],
        *,
        actor: str,
    ) -> dict[str, Any]:
        """Persist validated timezone/locale preferences on the shared DB."""
        if not isinstance(changes, Mapping) or not changes:
            raise errors.ValidationError("organization_preferences_invalid")
        if set(changes) - {"timezone", "locale"}:
            raise errors.ValidationError("organization_preferences_invalid")
        current = self.organization_preferences_get(org_id)
        timezone_value = (
            self._validate_timezone(changes["timezone"])
            if "timezone" in changes else str(current["timezone"])
        )
        locale_value = (
            self._validate_locale(changes["locale"])
            if "locale" in changes else str(current["locale"])
        )
        updated_at = models.utcnow()
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO organization_preferences "
                "(org_id, timezone, locale, updated_at) VALUES (?,?,?,?) "
                "ON CONFLICT(org_id) DO UPDATE SET timezone=excluded.timezone, "
                "locale=excluded.locale, updated_at=excluded.updated_at",
                (org_id, timezone_value, locale_value, updated_at),
            )
        self.platform.audit(
            "organization.preferences.updated",
            object_type="organization",
            object_id=org_id,
            org_id=org_id,
            actor=actor,
            metadata={"fields": sorted(changes)},
        )
        return self.organization_preferences_get(org_id)

    def finding_ids_for_scan(
        self,
        org_id: str,
        project_id: str,
        scan_id: str,
        *,
        limit: int = 500,
    ) -> list[str]:
        """Return bounded finding IDs only after verifying the ownership chain."""
        if type(limit) is not int or not 1 <= limit <= 500:
            raise errors.ValidationError("finding_limit_invalid")
        self._project(org_id, project_id)
        try:
            scan = self.platform.scan_get(scan_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("scan not found") from None
        if scan.project_id != project_id:
            raise errors.AuthorizationError("Forbidden")
        rows = self.db.query(
            "SELECT id FROM findings WHERE project_id=? AND scan_id=? "
            "ORDER BY last_detected DESC, id LIMIT ?",
            (project_id, scan_id, limit),
        )
        return [str(row["id"]) for row in rows]

    def session_get(
        self,
        org_id: str,
        user_id: str,
        session_id: str,
    ) -> dict[str, Any]:
        """Read one user's safe session metadata under an explicit tenant check."""
        user = self.identity.user_get(user_id)
        if user.org_id != org_id:
            raise errors.AuthorizationError("Forbidden")
        rows = self.db.query(
            "SELECT id, user_id, ip, user_agent, auth_method, mfa_status, "
            "provider_id, created_at, last_seen_at, expires_at, "
            "absolute_expires_at, revoked_at, revoke_reason FROM sessions "
            "WHERE id=? AND user_id=? LIMIT 1",
            (session_id, user_id),
        )
        if not rows:
            raise errors.NotFoundError("session not found")
        return dict(rows[0])

    def sessions_list(
        self,
        org_id: str,
        user_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        status: str = "active",
    ) -> dict[str, Any]:
        """List a user's safe device/session metadata with tenant predicates."""
        user = self.identity.user_get(user_id)
        if user.org_id != org_id:
            raise errors.AuthorizationError("Forbidden")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise errors.ValidationError("session_limit_invalid")
        if type(offset) is not int or not 0 <= offset <= 10_000:
            raise errors.ValidationError("session_offset_invalid")
        if status not in {"active", "revoked", "all"}:
            raise errors.ValidationError("session_status_invalid")
        where = "user_id=?"
        params: list[Any] = [user_id]
        if status == "active":
            where += " AND revoked_at=''"
        elif status == "revoked":
            where += " AND revoked_at<>''"
        rows = self.db.query(
            "SELECT id, user_id, ip, user_agent, auth_method, mfa_status, "
            "provider_id, created_at, last_seen_at, expires_at, "
            "absolute_expires_at, revoked_at, revoke_reason FROM sessions "
            "WHERE " + where + " ORDER BY last_seen_at DESC, id LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset),
        )
        total_rows = self.db.query(
            "SELECT COUNT(*) AS n FROM sessions WHERE " + where,
            tuple(params),
            limit=1,
        )
        total = int(total_rows[0]["n"]) if total_rows else 0
        return {
            "sessions": [dict(row) for row in rows],
            "count": len(rows),
            "total": total,
            "limit": limit,
            "offset": offset,
        }


__all__ = ["CustomerResourceService"]
