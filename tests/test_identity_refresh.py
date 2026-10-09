from __future__ import annotations

import concurrent.futures
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIR = str(ROOT / "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import errors
import identity
import platform_service


class IdentitySessionRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = os.path.join(self.temporary_directory.name, "identity.sqlite3")
        self.platform = platform_service.PlatformService(database_path)
        self.identity = identity.IdentityService(self.platform)
        self.organization = self.platform.org_create("Session Refresh Test")
        self.user = self.identity.user_create(
            self.organization.id,
            "refresh-user",
            "refresh-user@example.test",
            "Correct Horse Battery 729!",
            roles=("owner",),
            allow_any_role=True,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _login(self) -> dict:
        return self.identity.login(
            "refresh-user@example.test",
            "Correct Horse Battery 729!",
            ip="192.0.2.10",
        )

    def test_refresh_rotates_bearer_and_preserves_absolute_expiry(self) -> None:
        grant = self._login()
        original = grant["session"]
        result = self.identity.session_refresh(grant["secret"])
        refreshed = result["session"]

        self.assertNotEqual(result["secret"], grant["secret"])
        self.assertEqual(refreshed.id, original.id)
        self.assertEqual(refreshed.absolute_expires_at, original.absolute_expires_at)
        self.assertEqual(refreshed.mfa_status, original.mfa_status)
        with self.assertRaises(errors.AuthenticationError):
            self.identity.session_authenticate(grant["secret"])
        self.assertEqual(
            self.identity.session_authenticate(result["secret"]).id,
            original.id,
        )

    def test_concurrent_refresh_has_one_winner(self) -> None:
        grant = self._login()

        def refresh() -> str:
            try:
                return self.identity.session_refresh(grant["secret"])["secret"]
            except errors.AuthenticationError:
                return "rejected"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _index: refresh(), range(2)))
        self.assertEqual(sum(outcome != "rejected" for outcome in outcomes), 1)
        self.assertEqual(sum(outcome == "rejected" for outcome in outcomes), 1)

    def test_revoked_session_cannot_be_refreshed(self) -> None:
        grant = self._login()
        self.identity.session_revoke_id(grant["session"].id, reason="test")
        with self.assertRaises(errors.AuthenticationError):
            self.identity.session_refresh(grant["secret"])

    def test_expired_absolute_lifetime_cannot_be_extended(self) -> None:
        grant = self._login()
        self.platform.db.execute(
            "UPDATE sessions SET absolute_expires_at=? WHERE id=?",
            ("2000-01-01T00:00:00Z", grant["session"].id),
        )
        with self.assertRaises(errors.AuthenticationError):
            self.identity.session_refresh(grant["secret"])

    def test_utc_timestamp_parsing_is_timezone_independent(self) -> None:
        import time

        previous = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "Pacific/Honolulu"
            if hasattr(time, "tzset"):
                time.tzset()
            parsed = identity._parse_ts("2030-01-01T00:00:00Z")
            self.assertEqual(parsed, 1893456000.0)
            self.assertEqual(identity._parse_ts("2030-01-01T00:00:00"), 0.0)
        finally:
            if previous is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous
            if hasattr(time, "tzset"):
                time.tzset()


if __name__ == "__main__":
    unittest.main()
