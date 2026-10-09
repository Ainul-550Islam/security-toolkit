"""Repeat-safe schema migration orchestration and startup validation.

This runner delegates SQL execution to the database backend's canonical
migration implementation. It adds version checks, bounded metadata, and a
serialization hook without maintaining a second migration catalogue.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator


class MigrationError(Exception):
    """Safe migration lifecycle failure; contains no SQL or filesystem data."""

    def __init__(self, code: str) -> None:
        self.code = code if code in {
            "migration_version_unavailable",
            "migration_version_invalid",
            "migration_downgrade_detected",
            "migration_target_mismatch",
        } else "migration_failed"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class MigrationReport:
    """Safe result from applying or validating the canonical migrations."""

    previous_version: int
    current_version: int
    expected_version: int
    applied_versions: tuple[int, ...]
    state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_version": self.previous_version,
            "current_version": self.current_version,
            "expected_version": self.expected_version,
            "applied_versions": list(self.applied_versions),
            "state": self.state,
        }


class MigrationRunner:
    """Run the existing backend migrations once and verify their target version."""

    def __init__(self, database: Any, expected_version: int) -> None:
        if type(expected_version) is not int or expected_version < 0:
            raise ValueError("expected migration version must be a nonnegative integer")
        self.database = database
        self.expected_version = expected_version
        self._lock = threading.RLock()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        backend_lock = getattr(self.database, "migration_lock", None)
        if callable(backend_lock):
            with backend_lock():
                yield
            return
        with self._lock:
            yield

    def current_version(self) -> int:
        """Read schema_version; only a genuinely absent table means version 0.

        Query failures after the existence check are unavailable state, not an
        empty schema. Treating them as version zero could incorrectly run every
        migration after a transient database error.
        """
        try:
            tables = self.database.query(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name=?",
                ("schema_version",),
                limit=1,
            )
        except Exception:
            raise MigrationError("migration_version_unavailable") from None
        if not tables:
            return 0
        try:
            rows = self.database.query(
                "SELECT MAX(version) AS version FROM schema_version",
                (),
                limit=1,
            )
        except Exception:
            raise MigrationError("migration_version_unavailable") from None
        if not rows:
            return 0
        raw = rows[0].get("version")
        if raw is None:
            return 0
        if type(raw) is not int or raw < 0:
            raise MigrationError("migration_version_invalid")
        return raw

    def run(self) -> MigrationReport:
        """Apply only through the backend's repeat-safe migration method."""
        with self._locked():
            before = self.current_version()
            if before > self.expected_version:
                raise MigrationError("migration_target_mismatch")
            self.database.migrate()
            after = self.current_version()
            if after < before:
                raise MigrationError("migration_downgrade_detected")
            if after != self.expected_version:
                raise MigrationError("migration_target_mismatch")
            applied = tuple(range(before + 1, after + 1))
            return MigrationReport(
                previous_version=before,
                current_version=after,
                expected_version=self.expected_version,
                applied_versions=applied,
                state="upgraded" if applied else "current",
            )

    def validate_current(self) -> MigrationReport:
        """Validate startup schema without applying or exposing SQL details."""
        with self._locked():
            current = self.current_version()
            if current != self.expected_version:
                raise MigrationError("migration_target_mismatch")
            return MigrationReport(
                previous_version=current,
                current_version=current,
                expected_version=self.expected_version,
                applied_versions=(),
                state="current",
            )


__all__ = ["MigrationError", "MigrationReport", "MigrationRunner"]
