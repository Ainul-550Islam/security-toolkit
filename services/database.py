"""Database abstraction over the repository's canonical persistence backend.

The adapter preserves the existing store API: operations retain their
parameterized query and transaction behavior, while transactions/migrations
receive an in-process serialization hook and a safe health probe. A future
RDBMS adapter must implement ``DatabaseBackend``; SQL dialect changes remain
an explicit migration rather than being guessed here.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Iterator, Protocol


class DatabaseBackend(Protocol):
    """Behavior required from SQLite or a future production RDBMS backend."""

    path: str

    def connect(self) -> Any:
        """Open a managed backend connection."""

    def migrate(self) -> None:
        """Apply the backend's canonical schema migrations."""

    def transaction(self) -> Any:
        """Return a commit/rollback transaction context manager."""

    def execute(self, sql: str, params: tuple = ()) -> Any:
        """Execute a parameterized write."""

    def execute_affected(self, sql: str, params: tuple = ()) -> int:
        """Execute a guarded write and return the affected-row count."""

    def query(self, sql: str, params: tuple = (), limit: int | None = None) -> list[dict[str, Any]]:
        """Return bounded rows as plain mappings."""

    def query_one(self, sql: str, params: tuple = ()) -> dict[str, Any]:
        """Return exactly one row or raise a backend not-found error."""

    def upsert(self, table: str, record: dict[str, Any]) -> str:
        """Perform the canonical idempotent upsert."""

    def delete(self, table: str, record_id: str) -> Any:
        """Delete one record using the backend's existing contract."""


class _LockedTransaction:
    """Hold the adapter's reentrant transaction lock until commit/rollback."""

    def __init__(self, service: "DatabaseService") -> None:
        self._service = service
        self._inner: Any = None

    def __enter__(self) -> Any:
        self._service._lock.acquire()
        try:
            self._inner = self._service._backend.transaction()
            return self._inner.__enter__()
        except BaseException:
            self._service._lock.release()
            raise

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        try:
            return bool(self._inner.__exit__(exc_type, exc, traceback))
        finally:
            self._service._lock.release()


class DatabaseService:
    """Connection/transaction facade that delegates all persistence behavior."""

    def __init__(self, backend: DatabaseBackend) -> None:
        required = (
            "connect", "migrate", "transaction", "execute",
            "execute_affected", "query", "query_one", "upsert", "delete",
        )
        missing = [name for name in required if not callable(getattr(backend, name, None))]
        if missing:
            raise TypeError("database backend does not implement the required contract")
        if not str(getattr(backend, "path", "") or ""):
            raise ValueError("database backend path is required")
        self._backend = backend
        self._lock = threading.RLock()

    @property
    def path(self) -> str:
        """Return the configured backend path for existing compatibility callers."""
        return str(self._backend.path)

    def __repr__(self) -> str:
        return "DatabaseService(backend=[REDACTED])"

    def connect(self) -> Any:
        """Open one backend-managed connection; the caller owns its closure."""
        return self._backend.connect()

    def migrate(self) -> None:
        with self.migration_lock():
            self._backend.migrate()

    def transaction(self) -> _LockedTransaction:
        return _LockedTransaction(self)

    @contextmanager
    def migration_lock(self) -> Iterator[None]:
        """Serialize migrations against local transactions in this instance."""
        self._lock.acquire()
        try:
            yield
        finally:
            self._lock.release()

    def execute(self, sql: str, params: tuple = ()) -> Any:
        return self._backend.execute(sql, params)

    def execute_affected(self, sql: str, params: tuple = ()) -> int:
        return self._backend.execute_affected(sql, params)

    def query(self, sql: str, params: tuple = (), limit: int | None = None) -> list[dict[str, Any]]:
        return self._backend.query(sql, params, limit=limit)

    def query_one(self, sql: str, params: tuple = ()) -> dict[str, Any]:
        return self._backend.query_one(sql, params)

    def upsert(self, table: str, record: dict[str, Any]) -> str:
        return self._backend.upsert(table, record)

    def delete(self, table: str, record_id: str) -> Any:
        return self._backend.delete(table, record_id)

    def health_check(self) -> bool:
        """Run a constant, read-only probe; no SQL or path is returned."""
        try:
            rows = self._backend.query("SELECT 1 AS healthy", (), limit=1)
            return bool(rows and rows[0].get("healthy") == 1)
        except Exception:
            return False

    def health_status(self) -> dict[str, str | bool]:
        healthy = self.health_check()
        return {
            "status": "healthy" if healthy else "unavailable",
            "ready": healthy,
        }

    def close(self) -> None:
        """Delegate optional pool cleanup; per-operation backends need no action."""
        close = getattr(self._backend, "close", None)
        if callable(close):
            close()


__all__ = ["DatabaseBackend", "DatabaseService"]
