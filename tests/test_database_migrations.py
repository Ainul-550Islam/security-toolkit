"""Database adapter, locking, health, and repeat-safe migration tests."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "python"))

import store
from services.database import DatabaseService
from services.migrations import MigrationError, MigrationRunner


class DatabaseMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="database_service_")
        self.addCleanup(self.tmp.cleanup)
        backend = store.Database(os.path.join(self.tmp.name, "platform.db"))
        self.database = DatabaseService(backend)
        self.runner = MigrationRunner(
            self.database, expected_version=len(store.MIGRATIONS)
        )

    def test_migrations_are_repeat_safe_and_validated(self) -> None:
        self.assertEqual(self.runner.current_version(), 0)
        first = self.runner.run()
        self.assertEqual(first.state, "upgraded")
        self.assertEqual(first.current_version, len(store.MIGRATIONS))
        self.assertEqual(first.applied_versions, tuple(range(1, len(store.MIGRATIONS) + 1)))

        second = self.runner.run()
        self.assertEqual(second.state, "current")
        self.assertEqual(second.applied_versions, ())
        self.assertEqual(self.runner.validate_current().state, "current")

        stale = MigrationRunner(self.database, expected_version=len(store.MIGRATIONS) - 1)
        with self.assertRaises(MigrationError):
            stale.run()
        with self.assertRaises(MigrationError):
            MigrationRunner(self.database, expected_version=len(store.MIGRATIONS) - 1).validate_current()

    def test_query_failure_is_not_misreported_as_an_empty_schema(self) -> None:
        class BrokenDatabase:
            def query(self, _sql, _params=(), limit=None):
                raise RuntimeError("database path and driver detail")

        runner = MigrationRunner(BrokenDatabase(), expected_version=0)
        with self.assertRaises(MigrationError) as raised:
            runner.current_version()
        self.assertEqual(raised.exception.code, "migration_version_unavailable")
        self.assertNotIn("database path", str(raised.exception))

    def test_transaction_context_commits_and_rolls_back(self) -> None:
        self.runner.run()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO organizations (id,name,status,created_at,updated_at) "
                "VALUES (?,?,?,?,?)",
                ("tx-commit", "Committed", "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
        with self.assertRaisesRegex(RuntimeError, "rollback test"):
            with self.database.transaction() as connection:
                connection.execute(
                    "INSERT INTO organizations (id,name,status,created_at,updated_at) "
                    "VALUES (?,?,?,?,?)",
                    ("tx-rollback", "Rolled Back", "active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
                )
                raise RuntimeError("rollback test")
        rows = self.database.query(
            "SELECT id FROM organizations WHERE id IN (?,?) ORDER BY id",
            ("tx-commit", "tx-rollback"),
        )
        self.assertEqual([row["id"] for row in rows], ["tx-commit"])

    def test_transaction_lock_serializes_threaded_read_modify_write(self) -> None:
        self.runner.run()
        self.database.execute(
            "CREATE TABLE counter_probe (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)"
        )
        self.database.execute("INSERT INTO counter_probe (id,value) VALUES (?,?)", (1, 0))
        errors: list[BaseException] = []

        def increment() -> None:
            try:
                for _ in range(20):
                    with self.database.transaction() as connection:
                        value = int(connection.execute(
                            "SELECT value FROM counter_probe WHERE id=1"
                        ).fetchone()[0])
                        time.sleep(0.0005)
                        connection.execute(
                            "UPDATE counter_probe SET value=? WHERE id=1",
                            (value + 1,),
                        )
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=increment) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        row = self.database.query_one("SELECT value FROM counter_probe WHERE id=1")
        self.assertEqual(row["value"], 120)

    def test_health_and_debug_representation_are_safe(self) -> None:
        self.runner.run()
        self.assertTrue(self.database.health_check())
        self.assertEqual(self.database.health_status(), {"status": "healthy", "ready": True})
        self.assertNotIn(self.tmp.name, repr(self.database))


if __name__ == "__main__":
    unittest.main()
