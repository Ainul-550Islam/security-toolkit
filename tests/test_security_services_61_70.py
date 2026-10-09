"""Focused service and integration checks for Files 61–70.

These tests exercise the new domain facades against the canonical persistence
and workflow services; they intentionally do not mock tenant checks or claim
that external scans, providers, or downloads ran.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "python"))

import errors
import models
from api.router import build_default_services
from data_governance import SecretGovernanceService

_PASSWORD = "S3cure!Passw0rd"


class SecurityServices61To70Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="domain_services_61_70_")
        self.addCleanup(self.tmp.cleanup)
        self.services = build_default_services(os.path.join(self.tmp.name, "platform.db"))
        self.org = self.services.platform.org_create("Domain Service Test Org")
        self.owner = self.services.identity.user_create(
            self.org.id,
            "domain-service-owner",
            "domain-service-owner@example.test",
            _PASSWORD,
            ("owner",),
            allow_any_role=True,
            actor="test",
        )
        self.project = self.services.platform.project_create(
            self.org.id, "domain-service-project", actor="test"
        )
        self.services.platform.scope_set(
            self.project.id, ["example.test"], [], actor="test"
        )
        self.other_org = self.services.platform.org_create("Other Domain Service Org")
        self.other_project = self.services.platform.project_create(
            self.other_org.id, "other-domain-service-project", actor="test"
        )
        self.services.platform.scope_set(
            self.other_project.id, ["other.test"], [], actor="test"
        )

    def make_asset(self, value: str = "example.test", *, project_id: str | None = None) -> Any:
        project_id = project_id or self.project.id
        org_id = self.org.id if project_id == self.project.id else self.other_org.id
        return self.services.extra["asset_service"].add_asset(
            org_id,
            project_id,
            "domain",
            value,
            metadata={"source": "service-test"},
            actor="test",
        )

    def make_scan(self, *, project_id: str | None = None, target: str = "example.test") -> tuple[Any, Any]:
        project_id = project_id or self.project.id
        org_id = self.org.id if project_id == self.project.id else self.other_org.id
        return self.services.extra["scan_service"].queue_scan(
            org_id,
            project_id,
            "web-audit",
            {"target": target},
            actor="test",
            actor_id=self.owner.id if org_id == self.org.id else "other-actor",
        )

    def make_finding(self, *, title: str = "Domain service finding") -> tuple[Any, Any, dict[str, Any]]:
        asset = self.make_asset()
        scan, _job = self.make_scan()
        finding = models.Finding(
            scan_id=scan.id,
            project_id=self.project.id,
            asset_id=asset.id,
            title=title,
            description="Persisted test finding.",
            severity="High",
            category="web",
            source="service-test",
            rule_id="domain-service-rule",
            remediation="Use the existing remediation workflow.",
            raw={"url": "https://example.test/path"},
        )
        evidence = models.Evidence(
            finding_id="",
            evidence_type="response",
            url="https://example.test/path?token=EVIDENCE_SECRET_SENTINEL",
            method="GET",
            status_code="200",
            request_snippet="Authorization: Bearer EVIDENCE_SECRET_SENTINEL",
            response_snippet="Persisted response evidence.",
            detection_reason="A service test fixture.",
            scanner="service-test",
            rule_id="domain-service-rule",
        )
        result = self.services.extra["finding_service"].ingest(
            self.org.id, finding, [evidence], scan_id=scan.id
        )
        return asset, scan, result

    def test_asset_normalization_duplicate_ownership_lifecycle_and_tenant_scope(self) -> None:
        service = self.services.extra["asset_service"]
        created = service.upsert_asset(
            self.org.id,
            self.project.id,
            "domain",
            "EXAMPLE.TEST.",
            metadata={"source": "first"},
            actor="test",
        )
        asset = created["asset"]
        self.assertTrue(created["created"])
        self.assertEqual(asset.value, "example.test")
        duplicate = service.upsert_asset(
            self.org.id,
            self.project.id,
            "domain",
            "example.test",
            metadata={"source": "second"},
            actor="test",
        )
        self.assertEqual(duplicate["asset"].id, asset.id)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(service.aggregate_inventory(self.org.id, self.project.id)["total"], 1)

        assigned = service.assign_owner(
            self.org.id, asset.id, self.owner.id, actor="test"
        )
        self.assertEqual(assigned.metadata["owner_user_id"], self.owner.id)
        inactive = service.set_status(
            self.org.id, asset.id, "inactive", actor="test"
        )
        self.assertEqual(inactive.status, "inactive")
        self.assertEqual(service.list_assets(self.org.id, self.project.id)[0].status,
                         "inactive")
        other_asset = self.make_asset("other.test", project_id=self.other_project.id)
        with self.assertRaises(errors.NotFoundError):
            service.get_asset(self.org.id, other_asset.id)

    def test_scan_queue_idempotency_controls_and_scope_validation(self) -> None:
        service = self.services.extra["scan_service"]
        body = {"profile": "web-audit", "target": "example.test"}
        claim = service.claim_create(self.org.id, self.project.id, "scan-key-0001", body)
        self.assertFalse(claim.is_replay)
        replay_response = {"data": {"scan": {"id": "stable-scan-reference"}}}
        service.complete_create(claim, status_code=202, response=replay_response)
        replay = service.claim_create(self.org.id, self.project.id, "scan-key-0001", body)
        self.assertTrue(replay.is_replay)
        self.assertEqual(replay.response, replay_response)

        scan, job = service.queue_scan(
            self.org.id,
            self.project.id,
            "web-audit",
            {"target": "example.test"},
            actor="test",
            actor_id=self.owner.id,
        )
        self.assertEqual(scan.status, "queued")
        self.assertTrue(job.id)
        paused_scan, paused_job = service.pause_scan(
            self.org.id, scan.id, actor="test"
        )
        self.assertEqual(paused_scan.status, "paused")
        self.assertEqual(paused_job.status, "paused")
        resumed_scan, resumed_job = service.resume_scan(
            self.org.id, scan.id, actor="test"
        )
        self.assertEqual(resumed_scan.status, "queued")
        self.assertEqual(resumed_job.status, "queued")
        cancelled_scan, cancelled_job = service.cancel_scan(
            self.org.id, scan.id, actor="test"
        )
        self.assertEqual(cancelled_scan.status, "cancelled")
        self.assertEqual(cancelled_job.status, "cancelled")
        with self.assertRaises(errors.AuthorizationError):
            service.queue_scan(
                self.org.id,
                self.project.id,
                "web-audit",
                {"target": "outside.test"},
                actor="test",
                actor_id=self.owner.id,
            )

    def test_finding_normalization_correlation_status_and_tenant_isolation(self) -> None:
        asset, scan, result = self.make_finding()
        service = self.services.extra["finding_service"]
        finding_id = result["finding_id"]
        finding = service.get_finding(self.org.id, finding_id)
        self.assertEqual(finding.lifecycle, "open")
        self.assertTrue(finding.id)

        changed = service.set_status(
            self.org.id, finding_id, "acknowledged", actor="test"
        )
        self.assertEqual(changed.lifecycle, "acknowledged")
        duplicate_scan, _job = self.make_scan()
        duplicate = models.Finding(
            scan_id=duplicate_scan.id,
            project_id=self.project.id,
            asset_id=asset.id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            category=finding.category,
            source=finding.source,
            rule_id=finding.rule_id,
            remediation=finding.remediation,
            raw={"endpoint": "https://example.test/path"},
        )
        deduped = service.ingest(
            self.org.id, duplicate, [], scan_id=duplicate_scan.id
        )
        self.assertEqual(deduped["finding_id"], finding_id)
        self.assertTrue(deduped["deduped"])
        self.assertNotEqual(scan.id, duplicate_scan.id)
        with self.assertRaises(errors.NotFoundError):
            service.get_finding(self.other_org.id, finding_id)

    def test_risk_is_versioned_explainable_and_uses_persisted_findings(self) -> None:
        _asset, _scan, result = self.make_finding(title="Risk domain finding")
        service = self.services.extra["risk_service"]
        summary = service.project_summary(self.org.id, self.project.id)
        self.assertEqual(summary["aggregate"]["count"], 1)
        self.assertEqual(summary["score_components"]["recalculated"], False)
        self.assertTrue(summary["risk_calculation_version"])
        explanation = service.finding_explanation(self.org.id, result["finding_id"])
        self.assertEqual(explanation["finding_id"], result["finding_id"])
        self.assertTrue(explanation["risk_calculation_version"])
        first = service.recalculate_finding(self.org.id, result["finding_id"])
        second = service.recalculate_finding(self.org.id, result["finding_id"])
        self.assertEqual(first["risk_score"], second["risk_score"])
        self.assertTrue(first["calc_version"])
        with self.assertRaises(errors.NotFoundError):
            service.project_summary(self.other_org.id, self.project.id)

    def test_evidence_references_integrity_metadata_and_fail_closed_download(self) -> None:
        _asset, scan, result = self.make_finding(title="Evidence domain finding")
        service = self.services.extra["evidence_service"]
        finding_evidence = service.list_finding_evidence(
            self.org.id, result["finding_id"]
        )
        self.assertEqual(finding_evidence["count"], 1)
        evidence_id = finding_evidence["data"][0]["id"]
        evidence = service.get_evidence(self.org.id, evidence_id)
        serialized = str(evidence)
        self.assertNotIn("EVIDENCE_SECRET_SENTINEL", serialized)
        integrity = evidence["integrity_reference"]
        self.assertEqual(integrity["algorithm"], "sha256")
        self.assertEqual(integrity["hash_status"], "COMPUTED_AT_READ")
        self.assertFalse(integrity["hash_persisted"])
        self.assertRegex(integrity["sha256"], re.compile(r"^[0-9a-f]{64}$"))
        scan_evidence = service.list_scan_evidence(self.org.id, scan.id)
        self.assertEqual(scan_evidence["count"], 1)
        download = service.download_status(self.org.id, evidence_id)
        self.assertEqual(download["status"], "NOT_AVAILABLE")
        default_retention = service.retention_info(self.org.id, self.project.id)
        self.assertEqual(default_retention["source"], "documented_default")
        self.assertFalse(default_retention["policy_configured"])
        service.retention.policy_set(
            self.org.id,
            kind="evidence",
            days=720,
            project_id=self.project.id,
            actor="test",
        )
        configured_retention = service.retention_info(self.org.id, self.project.id)
        self.assertEqual(configured_retention["source"], "project_retention_policy")
        self.assertTrue(configured_retention["policy_configured"])
        self.assertEqual(configured_retention["days"], 720)
        with self.assertRaises(errors.NotFoundError):
            service.get_evidence(self.other_org.id, evidence_id)

    def test_report_snapshots_async_idempotency_and_report_evidence_view(self) -> None:
        self.make_finding(title="Report domain finding")
        service = self.services.extra["report_service"]
        request_body = {"report_type": "technical", "title": "Service report"}
        first = service.generate_async(
            self.org.id,
            self.project.id,
            "technical",
            title="Service report",
            store_payload=True,
            actor="test",
            actor_id=self.owner.id,
            idempotency_key="report-key-0001",
            request_body=request_body,
        )
        replay = service.generate_async(
            self.org.id,
            self.project.id,
            "technical",
            title="Service report",
            store_payload=True,
            actor="test",
            actor_id=self.owner.id,
            idempotency_key="report-key-0001",
            request_body=request_body,
        )
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["status_code"], 202)
        self.assertEqual(first["response"], replay["response"])

        with self.assertRaises(errors.ValidationError):
            service.create_snapshot(
                self.org.id,
                self.project.id,
                "technical",
                filters=["not", "an", "object"],
            )
        snapshot = service.create_snapshot(
            self.org.id,
            self.project.id,
            "technical",
            filters={"status": "open"},
            title="Immutable service snapshot",
        )
        stored = service.store_snapshot(
            self.org.id,
            self.project.id,
            snapshot,
            store_payload=True,
            evidence_snapshot=True,
        )
        self.assertTrue(stored["id"])
        self.assertEqual(stored["project_id"], self.project.id)
        self.assertTrue(bool(stored["immutable"]))
        self.assertIn("json", service.supported_formats)
        self.assertIsInstance(service.export_report(self.org.id, stored["id"], "json"), bytes)
        evidence_view = self.services.extra["evidence_service"].list_report_evidence(
            self.org.id, stored["id"]
        )
        self.assertIn(evidence_view["state"], ("AVAILABLE", "NOT_AVAILABLE"))
        with self.assertRaises(errors.NotFoundError):
            service.get_report(self.other_org.id, stored["id"])

    def test_search_is_bounded_structured_and_tenant_scoped(self) -> None:
        self.make_asset()
        _asset, scan, finding = self.make_finding(title="Searchable domain finding")
        service = self.services.extra["search_service"]
        result = service.search(
            self.org.id,
            self.project.id,
            query="Searchable domain",
            types=("findings",),
            limit=20,
        )
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["data"][0]["id"], finding["finding_id"])
        scans = service.search(
            self.org.id,
            self.project.id,
            query=scan.id,
            types=("scans",),
            limit=20,
        )
        self.assertEqual(scans["total"], 1)
        with self.assertRaises(errors.ValidationError):
            service.search(self.org.id, self.project.id, limit=100, offset=401)
        with self.assertRaises(errors.ValidationError):
            service.search(self.org.id, self.project.id, types=({"assets": True},))
        with self.assertRaises(errors.ValidationError):
            service.search(self.org.id, self.project.id, excluded_types="assets")
        with self.assertRaises(errors.NotFoundError):
            service.search(self.other_org.id, self.project.id, query="Searchable")

    def test_remediation_assignment_deadline_verification_and_tenant_scope(self) -> None:
        _asset, _scan, result = self.make_finding(title="Remediation domain finding")
        service = self.services.extra["remediation_service"]
        ticket = service.ensure(result["finding_id"], org_id=self.org.id, actor="test")
        assigned = service.assign(
            ticket["id"],
            "user",
            self.owner.id,
            org_id=self.org.id,
            actor="test",
        )
        self.assertEqual(assigned["owner_id"], self.owner.id)
        working = service.status(
            ticket["id"], "in_progress", org_id=self.org.id, actor="test"
        )
        self.assertEqual(working["status"], "in_progress")
        due = service.set_due(
            ticket["id"], "2030-01-02T03:04:05Z", org_id=self.org.id, actor="test"
        )
        self.assertEqual(due["due_at"], "2030-01-02T03:04:05Z")
        comment = service.add_comment(
            ticket["id"], "Please verify the completed change.",
            org_id=self.org.id, actor="test",
        )
        self.assertEqual(comment["id"], ticket["id"])
        ready = service.status(
            ticket["id"], "ready_for_verification", org_id=self.org.id, actor="test"
        )
        self.assertEqual(ready["status"], "ready_for_verification")
        verification = service.request_verification(
            ticket["id"], org_id=self.org.id, actor="test"
        )
        self.assertTrue(verification["verification_scan_id"])
        linked = self.services.extra["finding_service"].remediation_link(
            self.org.id, result["finding_id"]
        )
        self.assertEqual(linked["id"], ticket["id"])
        with self.assertRaises(errors.NotFoundError):
            service.view(ticket["id"], org_id=self.other_org.id)

    def test_notification_preferences_templates_and_delivery_state(self) -> None:
        service = self.services.notifications
        settings = service.settings_view(self.project.id, org_id=self.org.id)
        self.assertNotIn("webhook_secret", settings)
        updated = service.update_settings(
            self.org.id,
            self.project.id,
            {"email_enabled": True, "email_to": "domain-service-owner@example.test"},
            actor="test",
        )
        self.assertTrue(updated["email_enabled"])
        rendered = service.render_template(
            "security_alert_v1",
            {"title": "Service test alert", "severity": "Bearer NOTIFICATION_SECRET_SENTINEL"},
        )
        self.assertTrue(rendered["subject"])
        self.assertNotIn("NOTIFICATION_SECRET_SENTINEL", str(rendered))
        self.assertNotIn("EVIDENCE_SECRET_SENTINEL", str(rendered))
        self.assertEqual(service.notification_counts(self.org.id, self.project.id)["total"], 0)
        self.assertEqual(service.list_notifications(self.org.id, self.project.id), [])
        self.assertEqual(service.process_pending(self.org.id, limit=10), 0)
        self.assertEqual(service.retry_due(self.org.id, limit=10), 0)
        with self.assertRaises(errors.NotFoundError):
            service.settings_view(self.other_project.id, org_id=self.org.id)

    def test_integration_lifecycle_health_capabilities_and_credential_reference_guard(self) -> None:
        service = self.services.integrations
        capabilities = service.provider_capabilities()
        self.assertIn("siem", capabilities["capabilities"])
        secret = SecretGovernanceService(self.services.platform).register(
            self.org.id,
            kind="webhook_secret",
            name="Domain service test credential",
            reference="vault://domain-service/integration",
            material="INTEGRATION_SERVICE_SECRET_SENTINEL",
            actor="test",
        )
        connection = service.create_connection(
            self.org.id,
            project_id=self.project.id,
            name="Domain service webhook",
            connector_kind="generic_webhook",
            auth_mode="hmac",
            endpoint_url="https://hooks.example.com/security",
            credential_ref=secret["id"],
            actor="creator-identity",
        )
        integration_id = connection["id"]
        self.assertTrue(integration_id)
        health = service.health(self.org.id, integration_id=integration_id)
        self.assertEqual(health["items"][0]["health_state"], "disabled")
        with self.assertRaises(errors.ValidationError):
            service.rotate_credential_reference(
                self.org.id,
                integration_id,
                "nonexistent-credential-reference",
                actor="test",
            )
        unchanged = service.get_connection(self.org.id, integration_id)
        self.assertEqual(unchanged["credential_ref"], secret["id"])
        self.assertNotIn("INTEGRATION_SERVICE_SECRET_SENTINEL", str(unchanged))
        rotated_secret = SecretGovernanceService(self.services.platform).register(
            self.org.id,
            kind="webhook_secret",
            name="Domain service rotated credential",
            reference="vault://domain-service/integration-rotated",
            material="INTEGRATION_SERVICE_ROTATED_SECRET_SENTINEL",
            actor="test",
        )
        rotated = service.rotate_credential_reference(
            self.org.id, integration_id, rotated_secret["id"], actor="test"
        )
        self.assertEqual(rotated["credential_ref"], rotated_secret["id"])
        self.assertNotIn("INTEGRATION_SERVICE_ROTATED_SECRET_SENTINEL", str(rotated))
        validation = service.validate(self.org.id, integration_id)
        self.assertEqual(validation["configuration_status"], "valid")
        enabled = service.enable(
            self.org.id,
            integration_id,
            approved_by="separate-approver",
            actor="test",
        )
        self.assertEqual(enabled["status"], "enabled")
        delivery = service.send_event(
            self.org.id,
            integration_id,
            event_type="finding",
            payload={"finding_id": "test-finding-reference", "severity": "High"},
            idempotency_key="external-event-key-0001",
            actor="test",
        )
        self.assertEqual(delivery["status"], "queued")
        delivery_state = service.delivery_state(
            self.org.id, integration_id=integration_id
        )
        self.assertEqual(delivery_state["total"], 1)
        self.assertEqual(delivery_state["items"][0]["status"], "queued")
        self.assertEqual(delivery_state["items"][0]["external_event_id"],
                         "external-event-key-0001")
        disabled = service.disable(self.org.id, integration_id, actor="test")
        self.assertEqual(disabled["status"], "disabled")
        with self.assertRaises(errors.NotFoundError):
            service.get_connection(self.other_org.id, integration_id)


if __name__ == "__main__":
    unittest.main()
