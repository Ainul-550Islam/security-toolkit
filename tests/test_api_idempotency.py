"""Focused checks for tenant-scoped API idempotency records."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "python"))

from api.errors import ApiException
from api.idempotency import IdempotencyStore
from platform_service import PlatformService


class IdempotencyStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="api_idem_")
        self.addCleanup(self.tmp.cleanup)
        self.platform = PlatformService(os.path.join(self.tmp.name, "db.sqlite"))
        self.org = self.platform.org_create("Idempotency Test")
        self.store = IdempotencyStore(self.platform.db)

    def test_new_request_completes_and_replays_same_response(self) -> None:
        request = {"project_id": "p-12345678", "profile": "basic"}
        claim = self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0001", request)
        self.assertFalse(claim.is_replay)
        response = {"id": "scan-12345678", "status": "queued"}
        self.store.complete(claim, status_code=202, response=response)

        replay = self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0001", request)
        self.assertTrue(replay.is_replay)
        self.assertEqual(replay.status_code, 202)
        self.assertEqual(replay.response, response)

    def test_key_cannot_be_reused_for_a_different_request(self) -> None:
        claim = self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0002", {"profile": "basic"})
        self.store.complete(claim, status_code=202, response={"id": "scan-1"})
        with self.assertRaises(ApiException) as caught:
            self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0002", {"profile": "deep"})
        self.assertEqual(caught.exception.problem.code, "idempotency_conflict")

    def test_in_progress_and_failed_requests_are_not_replayed_as_success(self) -> None:
        claim = self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0003", {"profile": "basic"})
        with self.assertRaises(ApiException) as in_progress:
            self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0003", {"profile": "basic"})
        self.assertEqual(in_progress.exception.problem.code, "idempotent_request_in_progress")
        self.store.fail(claim)
        with self.assertRaises(ApiException) as failed:
            self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0003", {"profile": "basic"})
        self.assertEqual(failed.exception.problem.code, "idempotent_request_failed")

    def test_same_client_key_is_isolated_by_tenant(self) -> None:
        other = self.platform.org_create("Other Tenant")
        first = self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0004", {"profile": "basic"})
        second = self.store.claim(other.id, "scan.create:p-12345678", "client-key-0004", {"profile": "basic"})
        self.assertFalse(first.is_replay)
        self.assertFalse(second.is_replay)

    def test_expired_key_can_be_claimed_again(self) -> None:
        claim = self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0005", {"profile": "basic"})
        self.store.complete(claim, status_code=202, response={"id": "scan-old"})
        self.platform.db.execute(
            "UPDATE api_idempotency_records SET expires_at='2000-01-01T00:00:00Z' "
            "WHERE org_id=? AND scope=? AND key_hash=?",
            (claim.org_id, claim.scope, claim.key_hash),
        )
        renewed = self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0005", {"profile": "basic"})
        self.assertFalse(renewed.is_replay)

    def test_invalid_key_and_non_json_request_are_rejected(self) -> None:
        with self.assertRaises(ApiException):
            self.store.claim(self.org.id, "scan.create:p-12345678", "short", {})
        with self.assertRaises(ApiException):
            self.store.claim(self.org.id, "scan.create:p-12345678", "client-key-0006", {"bad": object()})


if __name__ == "__main__":
    unittest.main()
