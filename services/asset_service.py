"""Tenant-scoped asset inventory operations over the canonical platform store.

Asset identity and value normalization remain owned by ``models.Asset`` and
``PlatformService``'s schema. This service adds a tenant boundary, bounded
inventory queries, duplicate-safe ingestion, and lifecycle/ownership helpers;
it does not create a second asset database or invent discovery observations.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
models = _domain_module("models")
redact = _domain_module("redact")
store = _domain_module("store")

_MAX_LIMIT = 500
_MAX_OFFSET = 100_000
_MAX_METADATA_BYTES = 16_384


class AssetService:
    """Domain facade for normalized, project-owned asset inventory."""

    def __init__(
        self,
        platform: Any,
        *,
        intel: Any = None,
        identity: Any = None,
    ) -> None:
        self.platform = platform
        self.db = platform.db
        self.intel = intel
        self.identity = identity

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

    def _asset(self, org_id: str, asset_id: str) -> Any:
        try:
            asset = self.platform.asset_get(asset_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("asset not found") from None
        project = self._project(org_id, asset.project_id)
        if project.id != asset.project_id:
            raise errors.NotFoundError("asset not found")
        return asset

    @staticmethod
    def _page(limit: int, offset: int = 0) -> tuple[int, int]:
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("asset page limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset <= _MAX_OFFSET:
            raise errors.ValidationError("asset page offset is outside the allowed range")
        return limit, offset

    def list_assets(
        self,
        org_id: str,
        project_id: str,
        *,
        asset_type: str = "",
        status: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[Any]:
        """Return a deterministic bounded page after validating tenant ownership."""
        self._project(org_id, project_id)
        limit, offset = self._page(limit, offset)
        if asset_type and asset_type not in models.ASSET_TYPES:
            raise errors.ValidationError("asset type is not supported")
        if status and status not in models.ASSET_STATUS:
            raise errors.ValidationError("asset status is not supported")
        clauses = ["project_id=?"]
        parameters: list[Any] = [project_id]
        if asset_type:
            clauses.append("asset_type=?")
            parameters.append(asset_type)
        if status:
            clauses.append("status=?")
            parameters.append(status)
        rows = self.db.query(
            "SELECT * FROM assets WHERE " + " AND ".join(clauses)
            + " ORDER BY last_seen DESC, id LIMIT ? OFFSET ?",
            tuple(parameters + [limit, offset]),
            limit=limit,
        )
        output = []
        for row in rows:
            item = dict(row)
            item["metadata"] = store.loads(item.get("metadata", "{}"), {})
            output.append(models.Asset.from_dict(item))
        return output

    def get_asset(self, org_id: str, asset_id: str) -> Any:
        """Read one asset only after resolving its project-to-tenant chain."""
        if not isinstance(asset_id, str) or not asset_id:
            raise errors.ValidationError("asset identifier is required")
        return self._asset(org_id, asset_id)

    def upsert_asset(
        self,
        org_id: str,
        project_id: str,
        asset_type: str,
        value: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        display: str = "",
        actor: str = "api",
    ) -> dict[str, Any]:
        """Normalize and persist an asset, returning explicit duplicate state.

        Re-observation of a canonical identity preserves its lifecycle and
        first-seen time, refreshes last-seen, and only fills missing metadata
        keys. The stable ID plus the table's natural-key constraint make this
        safe under concurrent callers.
        """
        self._project(org_id, project_id)
        if metadata is not None and not isinstance(metadata, Mapping):
            raise errors.ValidationError("asset metadata must be an object")
        if not isinstance(display, str) or len(display) > 2048:
            raise errors.ValidationError("asset display value is invalid")
        try:
            incoming_metadata = redact.redact(dict(metadata or {}))
            serialized_metadata = store.dumps(incoming_metadata)
        except (TypeError, ValueError, OverflowError):
            raise errors.ValidationError("asset metadata is invalid") from None
        if len(serialized_metadata.encode("utf-8")) > _MAX_METADATA_BYTES:
            raise errors.ValidationError("asset metadata exceeds the allowed size")
        try:
            candidate = models.Asset(
                project_id=project_id,
                asset_type=asset_type,
                value=value,
                display=display,
                metadata=incoming_metadata,
            )
            candidate.finalize()
        except errors.SecurityToolkitError:
            raise
        except (TypeError, ValueError, UnicodeError):
            raise errors.ValidationError("asset identity is invalid") from None

        now = models.utcnow()
        created = False
        with self.db.transaction() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO assets "
                "(id, project_id, asset_type, value, display, metadata, status, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    candidate.id,
                    candidate.project_id,
                    candidate.asset_type,
                    candidate.value,
                    candidate.display,
                    serialized_metadata,
                    candidate.status,
                    candidate.first_seen,
                    candidate.last_seen,
                ),
            )
            created = cursor.rowcount == 1
            rows = connection.execute(
                "SELECT * FROM assets WHERE project_id=? AND asset_type=? AND value=? LIMIT 1",
                (project_id, candidate.asset_type, candidate.value),
            ).fetchall()
            if not rows:
                raise errors.PersistenceError("asset could not be persisted")
            row = dict(rows[0])
            if not created:
                existing_metadata = store.loads(row.get("metadata", "{}"), {})
                if not isinstance(existing_metadata, dict):
                    existing_metadata = {}
                merged = dict(existing_metadata)
                for key, item in incoming_metadata.items():
                    merged.setdefault(key, item)
                connection.execute(
                    "UPDATE assets SET last_seen=?, metadata=? WHERE id=? AND project_id=?",
                    (now, store.dumps(redact.redact(merged)), row["id"], project_id),
                )
                row["last_seen"] = now
                row["metadata"] = store.dumps(redact.redact(merged))
        if created:
            self.platform.audit(
                "asset.created",
                object_type="asset",
                object_id=str(row["id"]),
                org_id=org_id,
                project_id=project_id,
                actor=actor,
                metadata={"asset_type": candidate.asset_type, "value": candidate.value},
            )
        row["metadata"] = store.loads(row.get("metadata", "{}"), {})
        asset = models.Asset.from_dict(row)
        return {"asset": asset, "created": created, "duplicate": not created}

    def add_asset(
        self,
        org_id: str,
        project_id: str,
        asset_type: str,
        value: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        display: str = "",
        actor: str = "api",
    ) -> Any:
        """Add or re-observe an asset, returning the canonical asset model."""
        return self.upsert_asset(
            org_id,
            project_id,
            asset_type,
            value,
            metadata=metadata,
            display=display,
            actor=actor,
        )["asset"]

    def create_asset(self, *args: Any, **kwargs: Any) -> Any:
        """Compatibility-named alias for :meth:`add_asset`."""
        return self.add_asset(*args, **kwargs)

    def asset_add(self, *args: Any, **kwargs: Any) -> Any:
        """PlatformService-style alias with tenant scope required."""
        return self.add_asset(*args, **kwargs)

    def set_status(
        self,
        org_id: str,
        asset_id: str,
        status: str,
        *,
        actor: str = "api",
    ) -> Any:
        """Apply an allowlisted asset lifecycle status and audit the change."""
        if status not in models.ASSET_STATUS:
            raise errors.ValidationError("asset status is not supported")
        current = self._asset(org_id, asset_id)
        if current.status == status:
            return current
        changed = self.db.execute_affected(
            "UPDATE assets SET status=? WHERE id=? AND project_id=?",
            (status, asset_id, current.project_id),
        )
        if changed != 1:
            raise errors.NotFoundError("asset not found")
        self.platform.audit(
            "configuration.changed",
            object_type="asset",
            object_id=asset_id,
            org_id=org_id,
            project_id=current.project_id,
            actor=actor,
            metadata={"resource": "asset", "field": "status", "from": current.status, "to": status},
        )
        return self.platform.asset_get(asset_id)

    def assign_owner(
        self,
        org_id: str,
        asset_id: str,
        owner_id: str,
        *,
        actor: str = "api",
    ) -> Any:
        """Assign an active tenant-local user in existing asset metadata.

        The schema has no separate asset-owner column. The reference is stored
        as ``metadata.owner_user_id``; no user profile, credentials, or contact
        details are copied into the asset record.
        """
        asset = self._asset(org_id, asset_id)
        normalized_owner = str(owner_id or "").strip()
        if len(normalized_owner) > 128:
            raise errors.ValidationError("asset owner reference is invalid")
        if normalized_owner:
            if self.identity is None:
                raise errors.ConfigurationError("asset owner directory is unavailable")
            try:
                user = self.identity.user_get(normalized_owner)
            except Exception:
                raise errors.NotFoundError("asset owner not found") from None
            if user.org_id != org_id or user.status != "active":
                raise errors.NotFoundError("asset owner not found")
        metadata = dict(asset.metadata if isinstance(asset.metadata, dict) else {})
        old_owner = str(metadata.get("owner_user_id", ""))
        if old_owner == normalized_owner:
            return asset
        if normalized_owner:
            metadata["owner_user_id"] = normalized_owner
        else:
            metadata.pop("owner_user_id", None)
        with self.db.transaction() as connection:
            changed = connection.execute(
                "UPDATE assets SET metadata=? WHERE id=? AND project_id=?",
                (store.dumps(redact.redact(metadata)), asset_id, asset.project_id),
            ).rowcount
            if changed != 1:
                raise errors.NotFoundError("asset not found")
        self.platform.audit(
            "configuration.changed",
            object_type="asset",
            object_id=asset_id,
            org_id=org_id,
            project_id=asset.project_id,
            actor=actor,
            metadata={"resource": "asset", "field": "owner_user_id", "changed": True},
        )
        return self.platform.asset_get(asset_id)

    def set_criticality(self, org_id: str, asset_id: str, level: str, *, actor: str = "api") -> dict[str, Any]:
        """Use the canonical audited IntelService criticality operation."""
        self._asset(org_id, asset_id)
        if self.intel is None:
            raise errors.ConfigurationError("asset intelligence service is unavailable")
        return self.intel.criticality_set(asset_id, level, actor=actor)

    def history(self, org_id: str, asset_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        self._asset(org_id, asset_id)
        if self.intel is None:
            raise errors.ConfigurationError("asset intelligence service is unavailable")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise errors.ValidationError("asset history limit is outside the allowed range")
        return self.intel.asset_history(asset_id, limit=limit)

    def aggregate_inventory(self, org_id: str, project_id: str) -> dict[str, Any]:
        """Aggregate persisted inventory counts without loading asset rows."""
        self._project(org_id, project_id)
        rows = self.db.query(
            "SELECT asset_type, status, COUNT(*) AS count FROM assets "
            "WHERE project_id=? GROUP BY asset_type, status ORDER BY asset_type, status",
            (project_id,),
        )
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        total = 0
        for row in rows:
            count = int(row.get("count", 0))
            asset_type = str(row.get("asset_type", ""))
            status = str(row.get("status", ""))
            by_type[asset_type] = by_type.get(asset_type, 0) + count
            by_status[status] = by_status.get(status, 0) + count
            total += count
        return {
            "org_id": org_id,
            "project_id": project_id,
            "total": total,
            "by_type": dict(sorted(by_type.items())),
            "by_status": dict(sorted(by_status.items())),
            "source": "persisted_assets",
        }


__all__ = ["AssetService"]
