"""Focused tests for tenant-scoped notifications and Jira ticketing boundaries."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from typing import Any
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "python"))

import models
from alerts import AlertService
from events import SecurityEventService
from platform_service import PlatformService
from services.notifications import NotificationService as NotificationFacade
from services.ticketing import (
    JiraCloudAdapter,
    TicketingError,
    TicketingResult,
    TicketingService,
)
from notify import RecordingProvider
import integrations as legacy_integrations

_TEST_KEY = base64.b64encode(b"N" * 32).decode("ascii")


class ProductIntegrationBase(unittest.TestCase):
    def setUp(self) -> None:
        self._key_patch = patch.dict(os.environ, {
            "SECURITY_TOOLKIT_ENCRYPTION_ACTIVE_KEY_ID": "product-integration-test",
            "SECURITY_TOOLKIT_ENCRYPTION_KEY": _TEST_KEY,
        })
        self._key_patch.start()
        self.addCleanup(self._key_patch.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="product_integrations_")
        self.addCleanup(self.temp.cleanup)
        self.platform = PlatformService(os.path.join(self.temp.name, "platform.db"))
        self.org = self.platform.org_create("Integration Tenant A")
        self.project = self.platform.project_create(self.org.id, "integration-project-a")
        self.other_org = self.platform.org_create("Integration Tenant B")
        self.other_project = self.platform.project_create(self.other_org.id, "integration-project-b")


class NotificationFacadeTests(ProductIntegrationBase):
    def setUp(self) -> None:
        super().setUp()
        self.provider = RecordingProvider()
        self.notifications = NotificationFacade(
            self.platform,
            providers={"webhook": self.provider},
        )
        self.events = SecurityEventService(self.platform)
        self.alerts = AlertService(self.platform, notifier=self.notifications)

    def test_partial_settings_are_write_only_encrypted_and_tenant_scoped(self) -> None:
        secret = "notification-secret-sentinel-987654"
        endpoint = "https://hooks.example.com/notify?token=endpoint-sentinel-123456"
        first = self.notifications.update_settings(
            self.org.id,
            self.project.id,
            {
                "webhook_enabled": True,
                "webhook_url": endpoint,
                "webhook_secret": secret,
            },
            actor="test-user",
        )
        serialized = json.dumps(first, sort_keys=True)
        self.assertTrue(first["has_secret"])
        self.assertNotIn("webhook_secret", first)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("endpoint-sentinel-123456", serialized)

        stored = self.platform.db.query(
            "SELECT org_id, webhook_url, webhook_secret FROM notification_settings "
            "WHERE project_id=? LIMIT 1",
            (self.project.id,),
        )
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["org_id"], self.org.id)
        self.assertEqual(stored[0]["webhook_url"], endpoint)
        self.assertNotIn(secret, stored[0]["webhook_secret"])
        from services.crypto import CryptoService

        associated_data = f"notification-settings:webhook-secret:v1:{self.org.id}:{self.project.id}"
        self.assertEqual(
            CryptoService().decrypt_text(
                stored[0]["webhook_secret"], associated_data=associated_data
            ),
            secret,
        )

        # Omitted settings are preserved byte-for-byte, including a sensitive
        # query value that the public response intentionally masks.
        second = self.notifications.update_settings(
            self.org.id,
            self.project.id,
            {"email_enabled": False},
            actor="test-user",
        )
        self.assertNotIn("endpoint-sentinel-123456", json.dumps(second))
        after = self.platform.db.query(
            "SELECT webhook_url, webhook_secret FROM notification_settings "
            "WHERE project_id=? LIMIT 1",
            (self.project.id,),
        )[0]
        self.assertEqual(after["webhook_url"], endpoint)
        self.assertEqual(after["webhook_secret"], stored[0]["webhook_secret"])

        with self.assertRaises(Exception) as wrong_tenant:
            self.notifications.settings_view(self.project.id, org_id=self.other_org.id)
        self.assertEqual(type(wrong_tenant.exception).__name__, "NotFoundError")
        with self.assertRaises(Exception) as wrong_project_update:
            self.notifications.update_settings(
                self.other_org.id,
                self.project.id,
                {"email_enabled": True},
            )
        self.assertEqual(type(wrong_project_update.exception).__name__, "NotFoundError")

    def test_alert_dispatch_is_tenant_bound_idempotent_and_audited(self) -> None:
        self.notifications.update_settings(
            self.org.id,
            self.project.id,
            {
                "webhook_enabled": True,
                "webhook_url": "https://hooks.example.com/security-toolkit",
                "webhook_secret": "dispatch-secret-sentinel-123456",
            },
        )
        rule = self.alerts.rule_create(
            self.project.id,
            "product-integration-rule",
            event_type="finding.created",
            condition={},
            severity="high",
            cooldown_minutes=0,
            notify=True,
        )
        event = self.events.emit(
            self.project.id,
            "finding.created",
            asset_id="asset-integration-a",
            key="finding-integration-a",
            scan_id="scan-integration-a",
            new_state={"title": "Integration-boundary test", "severity": "high"},
            source="test",
        )
        self.assertIsNotNone(event)
        self.alerts.process_event(event)
        alert_rows = self.platform.db.query(
            "SELECT id, org_id FROM alerts WHERE project_id=? LIMIT 1",
            (self.project.id,),
        )
        self.assertEqual(len(alert_rows), 1)
        self.assertEqual(alert_rows[0]["org_id"], self.org.id)

        # AlertService calls the facade with explicit tenant scope; repeated
        # delivery for the same alert occurrence is idempotent.
        created_again = self.notifications.dispatch_alert(
            alert_rows[0]["id"],
            event["id"],
            rule,
            org_id=self.org.id,
        )
        self.assertEqual(created_again, 0)
        rows = self.notifications.list_notifications(self.org.id, self.project.id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "sent")
        self.assertEqual(len(self.provider.deliveries), 1)
        self.assertNotIn("dispatch-secret-sentinel-123456", str(rows))

        self.assertEqual(
            self.notifications.list_notifications(self.other_org.id, self.other_project.id),
            [],
        )
        with self.assertRaises(Exception) as wrong_tenant_dispatch:
            self.notifications.dispatch_alert(
                alert_rows[0]["id"],
                event["id"],
                rule,
                org_id=self.other_org.id,
            )
        self.assertEqual(type(wrong_tenant_dispatch.exception).__name__, "NotFoundError")
        with self.assertRaises(Exception) as wrong_tenant_read:
            self.notifications.notification_view(
                self.other_org.id,
                self.project.id,
                rows[0]["id"],
            )
        self.assertEqual(type(wrong_tenant_read.exception).__name__, "NotFoundError")

    def test_retry_records_redacted_errors_and_checks_tenant_project(self) -> None:
        class MutableProvider:
            name = "mutable-test-provider"

            def __init__(self) -> None:
                self.fail = True
                self.calls = 0

            def send(self, settings: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
                self.calls += 1
                if self.fail:
                    return {
                        "ok": False,
                        "outcome": "failed",
                        "error": "api_token=delivery-secret-sentinel-123456 /srv/private/provider-error",
                    }
                return {"ok": True, "outcome": "sent", "status": 200, "duration_ms": 1}

        provider = MutableProvider()
        notifier = NotificationFacade(self.platform, providers={"webhook": provider})
        alerts = AlertService(self.platform, notifier=notifier)
        events = SecurityEventService(self.platform)
        notifier.update_settings(
            self.org.id,
            self.project.id,
            {
                "webhook_enabled": True,
                "webhook_url": "https://hooks.example.com/retry",
                "webhook_secret": "retry-secret-sentinel-123456",
            },
        )
        rule = alerts.rule_create(
            self.project.id,
            "retry-integration-rule",
            event_type="finding.created",
            condition={},
            severity="high",
            cooldown_minutes=0,
            notify=True,
        )
        event = events.emit(
            self.project.id,
            "finding.created",
            asset_id="asset-retry-a",
            key="finding-retry-a",
            scan_id="scan-retry-a",
            new_state={"title": "Retry test", "severity": "high"},
            source="test",
        )
        alerts.process_event(event)
        row = notifier.list_notifications(self.org.id, self.project.id)[0]
        self.assertEqual(row["status"], "pending")
        self.assertNotIn("delivery-secret-sentinel-123456", json.dumps(row))
        self.assertNotIn("/srv/private", json.dumps(row))

        for _ in range(4):
            notifier.retry_due(self.org.id, now="2999-01-01T00:00:00Z")
        dead_letter = notifier.notification_view(
            self.org.id,
            self.project.id,
            row["id"],
        )
        self.assertEqual(dead_letter["status"], "dead_letter")
        self.assertNotIn("delivery-secret-sentinel-123456", json.dumps(dead_letter))
        self.assertNotIn("/srv/private", json.dumps(dead_letter))
        provider.fail = False
        sent = notifier.retry(
            self.org.id,
            row["id"],
            project_id=self.project.id,
            actor="security-manager",
        )
        self.assertEqual(sent["status"], "sent")

        with self.assertRaises(Exception) as cross_tenant_retry:
            notifier.retry(
                self.other_org.id,
                row["id"],
                project_id=self.other_project.id,
                actor="other-tenant",
            )
        self.assertEqual(type(cross_tenant_retry.exception).__name__, "NotFoundError")


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self._payload = json.dumps(payload).encode("utf-8")
        self._status = status

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        return False

    def getcode(self) -> int:
        return self._status

    def read(self, limit: int = -1) -> bytes:
        return self._payload if limit < 0 else self._payload[:limit]


class JiraCloudAdapterTests(unittest.TestCase):
    def test_site_validation_rejects_lookalikes_and_unsafe_url_parts(self) -> None:
        self.assertEqual(JiraCloudAdapter._site("https://acme.atlassian.net/"), "https://acme.atlassian.net")
        self.assertEqual(JiraCloudAdapter._site("https://a.atlassian.net"), "https://a.atlassian.net")
        invalid = (
            "https://atlassian.net",
            "https://acme.atlassian.net.evil.test",
            "https://acme.atlassian.net.evil",
            "http://acme.atlassian.net",
            "https://user@acme.atlassian.net",
            "https://acme.atlassian.net:8443",
            "https://acme.atlassian.net/rest/api/3",
            "https://acme.atlassian.net/?redirect=https://evil.test",
            "https://acme..atlassian.net",
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                with self.assertRaises(TicketingError):
                    JiraCloudAdapter._site(candidate)

    def test_upsert_redacts_payload_and_uses_stable_finding_reference(self) -> None:
        class Transport:
            def __init__(self) -> None:
                self.requests: list[tuple[str, str, dict[str, Any] | None]] = []
                self.searches = 0

            def __call__(self, request: Any, *, timeout: float) -> _FakeResponse:
                parsed = urllib.parse.urlsplit(request.full_url)
                payload = json.loads(request.data.decode("utf-8")) if request.data else None
                self.requests.append((request.get_method(), parsed.path, payload))
                if parsed.path == "/rest/api/3/search/jql":
                    self.searches += 1
                    return _FakeResponse({"issues": []} if self.searches == 1 else {"issues": [{"key": "SEC-17"}]})
                if parsed.path == "/rest/api/3/issue" and request.get_method() == "POST":
                    return _FakeResponse({"key": "SEC-17"})
                if parsed.path == "/rest/api/3/issue/SEC-17" and request.get_method() == "PUT":
                    return _FakeResponse({})
                raise AssertionError("unexpected provider request")

        transport = Transport()
        adapter = JiraCloudAdapter(
            transport=transport,
            url_validator=lambda _url: None,
            sleeper=lambda _seconds: None,
        )
        token = "ghp_" + "A" * 40
        finding = {
            "id": "finding-17",
            "title": "Leaked api_key=" + token,
            "description": "Authorization: Bearer " + "B" * 40,
            "remediation": "password=remediation-sentinel-123456",
            "severity": "high",
            "lifecycle": "open",
        }
        first = adapter.upsert_finding(
            site_url="https://acme.atlassian.net",
            credentials={"email": "security@example.test", "api_token": "jira-token-sentinel-123456"},
            project_key="SEC",
            issue_type="Task",
            org_id="tenant-a",
            project_id="project-a",
            finding=finding,
        )
        second = adapter.upsert_finding(
            site_url="https://acme.atlassian.net",
            credentials={"email": "security@example.test", "api_token": "jira-token-sentinel-123456"},
            project_key="SEC",
            issue_type="Task",
            org_id="tenant-a",
            project_id="project-a",
            finding=finding,
        )
        self.assertEqual((first.key, first.operation), ("SEC-17", "created"))
        self.assertEqual((second.key, second.operation), ("SEC-17", "updated"))
        self.assertEqual(transport.searches, 2)
        create_payload = next(
            payload for method, path, payload in transport.requests
            if method == "POST" and path == "/rest/api/3/issue"
        )
        serialized = json.dumps(create_payload, sort_keys=True)
        for sensitive_value in (token, "B" * 40, "remediation-sentinel-123456", "jira-token-sentinel-123456"):
            self.assertNotIn(sensitive_value, serialized)
        self.assertIn("[REDACTED]", serialized)
        labels = create_payload["fields"]["labels"]
        self.assertEqual(labels, [adapter._reference_label("tenant-a", "project-a", "finding-17")])
        self.assertTrue(first.url.startswith("https://acme.atlassian.net/browse/SEC-17"))

    def test_provider_retry_and_error_mapping_never_return_raw_exception_text(self) -> None:
        delay_values: list[float] = []

        class RetryTransport:
            def __init__(self) -> None:
                self.search_calls = 0

            def __call__(self, request: Any, *, timeout: float) -> _FakeResponse:
                path = urllib.parse.urlsplit(request.full_url).path
                if path == "/rest/api/3/search/jql":
                    self.search_calls += 1
                    if self.search_calls == 1:
                        raise urllib.error.HTTPError(
                            request.full_url,
                            503,
                            "api_token=provider-error-sentinel",
                            {},
                            None,
                        )
                    return _FakeResponse({"issues": []})
                if path == "/rest/api/3/issue":
                    return _FakeResponse({"key": "SEC-18"})
                raise AssertionError("unexpected provider request")

        adapter = JiraCloudAdapter(
            transport=RetryTransport(),
            url_validator=lambda _url: None,
            sleeper=delay_values.append,
        )
        result = adapter.upsert_finding(
            site_url="https://acme.atlassian.net",
            credentials={"email": "security@example.test", "api_token": "jira-token-sentinel-123456"},
            project_key="SEC",
            issue_type="Task",
            org_id="tenant-a",
            project_id="project-a",
            finding={"id": "finding-18", "title": "Safe title"},
        )
        self.assertEqual(result.key, "SEC-18")
        self.assertEqual(delay_values, [0.25])

        def unauthorized(request: Any, *, timeout: float) -> _FakeResponse:
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "api_token=provider-error-sentinel",
                {},
                None,
            )

        failing = JiraCloudAdapter(
            transport=unauthorized,
            url_validator=lambda _url: None,
            sleeper=lambda _seconds: None,
        )
        with self.assertRaises(TicketingError) as raised:
            failing.upsert_finding(
                site_url="https://acme.atlassian.net",
                credentials={"email": "security@example.test", "api_token": "jira-token-sentinel-123456"},
                project_key="SEC",
                issue_type="Task",
                org_id="tenant-a",
                project_id="project-a",
                finding={"id": "finding-19", "title": "Safe title"},
            )
        self.assertEqual(str(raised.exception), "auth_failed")
        self.assertNotIn("provider-error-sentinel", str(raised.exception))


class TicketingServiceTests(ProductIntegrationBase):
    def _finding(self) -> str:
        asset = self.platform.asset_add(self.project.id, "domain", "example.test")
        scan = self.platform.scan_create(self.project.id, "web-audit")
        finding = models.Finding(
            scan_id=scan.id,
            project_id=self.project.id,
            asset_id=asset.id,
            title="Ticketing isolation finding",
            description="A safe description for the Jira adapter test.",
            severity="Medium",
            source="unit-test",
            rule_id="ticketing-test-rule",
            remediation="Apply the safe test remediation.",
        )
        return self.platform.finding_ingest(finding).id

    def _integration_id(self) -> str:
        connections = legacy_integrations.ConnectionService(self.platform)
        connection = connections.create(
            self.org.id,
            project_id=self.project.id,
            name="Jira ticketing adapter test",
            connector_kind="ticketing",
            auth_mode="api_key",
            endpoint_url="https://acme.atlassian.net",
            provider="jira_cloud",
            credential_ref="vault://jira/test-reference",
            config={"project_key": "SEC", "issue_type": "Task"},
            actor="creator-user",
        )
        connections.enable(
            self.org.id,
            connection["id"],
            approved_by="independent-approver",
            actor="independent-approver",
        )
        return str(connection["id"])

    def test_service_scopes_findings_credentials_and_success_audit(self) -> None:
        finding_id = self._finding()
        integration_id = self._integration_id()

        class Adapter:
            def __init__(self) -> None:
                self.calls = 0
                self.credentials: dict[str, str] = {}

            def upsert_finding(self, **kwargs: Any) -> TicketingResult:
                self.calls += 1
                self.credentials = dict(kwargs["credentials"])
                return TicketingResult(
                    "jira_cloud",
                    "SEC-31",
                    "https://acme.atlassian.net/browse/SEC-31",
                    "created",
                )

        adapter = Adapter()
        secret = "resolved-jira-api-token-sentinel-123456"
        service = TicketingService(
            self.platform,
            credential_resolver=lambda org_id, reference: {
                "email": "security@example.test",
                "api_token": secret,
            },
            adapters={"jira_cloud": adapter},
        )
        result = service.upsert_finding(
            self.org.id,
            self.project.id,
            integration_id,
            finding_id,
        )
        self.assertEqual(result["key"], "SEC-31")
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(adapter.credentials["api_token"], secret)
        self.assertIn(
            "ticketing.issue.created",
            {event.action for event in self.platform.audit_list_org(self.org.id)},
        )

        with self.assertRaises(Exception) as cross_tenant:
            service.upsert_finding(
                self.other_org.id,
                self.project.id,
                integration_id,
                finding_id,
            )
        self.assertEqual(type(cross_tenant.exception).__name__, "NotFoundError")
        self.assertEqual(adapter.calls, 1)

    def test_service_maps_adapter_exception_to_safe_closed_error(self) -> None:
        finding_id = self._finding()
        integration_id = self._integration_id()

        class BrokenAdapter:
            def upsert_finding(self, **kwargs: Any) -> TicketingResult:
                raise RuntimeError("api_token=raw-provider-secret /srv/customer/private")

        service = TicketingService(
            self.platform,
            credential_resolver=lambda _org, _reference: {
                "email": "security@example.test",
                "api_token": "resolved-jira-api-token-sentinel-123456",
            },
            adapters={"jira_cloud": BrokenAdapter()},
        )
        with self.assertRaises(TicketingError) as raised:
            service.upsert_finding(
                self.org.id,
                self.project.id,
                integration_id,
                finding_id,
            )
        self.assertEqual(str(raised.exception), "provider_unavailable")
        self.assertNotIn("raw-provider-secret", str(raised.exception))
        self.assertNotIn("/srv/customer/private", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
