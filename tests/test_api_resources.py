"""End-to-end checks for the first tenant-scoped customer API resources."""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "python"))

import models
import rbac
from api.http import create_app
from api.middleware import SafeSlidingWindowLimiter
from api.router import build_default_services
from data_governance import SecretGovernanceService
from worker import WorkerRuntime

_PASSWORD = "S3cure!Passw0rd"


class ApiResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="api_resources_")
        self.addCleanup(self.tmp.cleanup)
        self.services = build_default_services(os.path.join(self.tmp.name, "platform.db"))
        self.org = self.services.platform.org_create("API Resource Test")
        self.owner = self.services.identity.user_create(
            self.org.id,
            "api-owner",
            "owner@example.test",
            _PASSWORD,
            ("owner",),
            allow_any_role=True,
            actor="test",
        )
        self.app = create_app(
            self.services,
            require_tls=False,
            rate_limiter=SafeSlidingWindowLimiter(limit=500, max_keys=1000),
        )
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login",
            body={"identifier": "owner@example.test", "password": _PASSWORD},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        login_body = self.decode(raw)
        self.token = login_body["access_token"]
        self.session_id = login_body["principal"]["session_id"]
        self.headers = {"Authorization": "Bearer " + self.token}
        self.project = self.services.platform.project_create(self.org.id, "api-project")
        self.services.platform.scope_set(self.project.id, ["example.test"], [])

    def tearDown(self) -> None:
        self.app.close()

    def call(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        headers: dict[str, str] | None = None,
        query: str = "",
    ) -> tuple[int, dict[str, str], bytes]:
        raw_body = json.dumps(body).encode("utf-8") if body is not None else b""
        environ: dict[str, Any] = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_LENGTH": str(len(raw_body)),
            "CONTENT_TYPE": "application/json" if raw_body else "",
            "REMOTE_ADDR": "127.0.0.1",
            "wsgi.url_scheme": "https",
            "wsgi.input": io.BytesIO(raw_body),
        }
        for name, value in (headers or {}).items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value
        captured: dict[str, Any] = {}

        def start_response(status: str, response_headers: list[tuple[str, str]], exc_info: Any = None) -> None:
            if exc_info is not None:
                raise exc_info[1]
            captured["status"] = int(status.split(" ", 1)[0])
            captured["headers"] = {name.lower(): value for name, value in response_headers}

        response = b"".join(self.app(environ, start_response))
        return captured["status"], captured["headers"], response

    @staticmethod
    def decode(raw: bytes) -> dict[str, Any]:
        return json.loads(raw.decode("utf-8")) if raw else {}

    def test_tenant_project_and_user_routes(self) -> None:
        status, _headers, raw = self.call("GET", "/api/v1/tenants", headers=self.headers)
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["id"], self.org.id)

        status, _headers, raw = self.call(
            "POST", f"/api/v1/tenants/{self.org.id}/projects",
            headers=self.headers,
            body={"name": "api-created-project", "description": "Created through the v1 API"},
        )
        self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))
        project_id = self.decode(raw)["data"]["id"]
        self.assertEqual(self.decode(raw)["data"]["org_id"], self.org.id)

        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/users", headers=self.headers,
        )
        self.assertEqual(status, 200)
        users = self.decode(raw)["data"]
        self.assertEqual([user["username"] for user in users], ["api-owner"])
        self.assertNotIn("password_hash", raw.decode("utf-8"))

        new_user_body = {
            "username": "api-reader",
            "email": "reader@example.test",
            "password": "Initial!Password123",
            "display_name": "API Reader",
            "roles": ["viewer"],
        }
        status, _headers, raw = self.call(
            "POST", f"/api/v1/tenants/{self.org.id}/users",
            headers=self.headers,
            body=new_user_body,
        )
        self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))
        user = self.decode(raw)["data"]
        self.assertEqual(user["username"], "api-reader")
        self.assertEqual(user["roles"], ["viewer"])
        self.assertNotIn("Initial!Password123", raw.decode("utf-8"))
        self.assertNotIn("password_hash", raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "PATCH", f"/api/v1/tenants/{self.org.id}/users/{user['id']}",
            headers=self.headers,
            body={"status": "suspended"},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["status"], "suspended")
        audit_actions = {event.action for event in self.services.platform.audit_list_org(self.org.id)}
        self.assertIn("user.suspended", audit_actions)

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{project_id}/assets", headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"], [])

    def test_tenant_session_list_and_revocation(self) -> None:
        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/sessions",
            headers=self.headers,
            query="status=active&limit=20",
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        sessions = self.decode(raw)["data"]
        self.assertEqual([session["id"] for session in sessions], [self.session_id])
        self.assertNotIn("ip", sessions[0])
        self.assertNotIn("token_hash", raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "POST", f"/api/v1/tenants/{self.org.id}/sessions/{self.session_id}/revoke",
            headers=self.headers,
        )
        self.assertEqual(status, 204, raw.decode("utf-8", errors="replace"))
        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/sessions",
            headers=self.headers,
        )
        self.assertEqual(status, 401)

    def test_assets_findings_evidence_are_project_scoped_and_minimized(self) -> None:
        status, _headers, raw = self.call(
            "POST", f"/api/v1/projects/{self.project.id}/assets",
            headers=self.headers,
            body={"asset_type": "domain", "value": "WWW.Example.test"},
        )
        self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))
        asset_id = self.decode(raw)["data"]["id"]
        self.assertEqual(self.decode(raw)["data"]["value"], "www.example.test")
        self.assertNotIn("raw", self.decode(raw)["data"])

        status, _headers, raw = self.call(
            "GET", f"/api/v1/assets/{asset_id}", headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["id"], asset_id)

        scan = self.services.platform.scan_create(self.project.id, "web-audit")
        finding = models.Finding(
            scan_id=scan.id,
            project_id=self.project.id,
            asset_id=asset_id,
            title="Authorization: Bearer TOPSECRET should be redacted",
            description="Sensitive evidence stays out of raw API fields.",
            severity="High",
            source="test-scanner",
            rule_id="test-rule",
            raw={"authorization": "Bearer TOPSECRET", "endpoint": "/vulnerable"},
        )
        saved = self.services.platform.finding_ingest(finding)
        evidence = self.services.platform.evidence_add(
            saved.id,
            evidence_type="response",
            url="https://www.example.test/vulnerable?token=TOPSECRET",
            method="GET",
            status_code="200",
            request_snippet="Authorization: Bearer TOPSECRET",
            response_snippet="no sensitive bytes returned",
            detection_reason="A bounded test evidence record",
            scanner="test-scanner",
            rule_id="test-rule",
        )

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/findings",
            headers=self.headers,
            query="severity=High",
        )
        self.assertEqual(status, 200)
        data = self.decode(raw)["data"]
        self.assertEqual([item["id"] for item in data], [saved.id])
        self.assertNotIn("raw", data[0])
        self.assertNotIn("evidence", data[0])
        self.assertNotIn("TOPSECRET", raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/findings/{saved.id}/evidence", headers=self.headers,
        )
        self.assertEqual(status, 200)
        evidence_view = self.decode(raw)["data"][0]
        self.assertEqual(evidence_view["id"], evidence.id)
        self.assertNotIn("request_snippet", evidence_view)
        self.assertNotIn("response_snippet", evidence_view)
        self.assertEqual(
            evidence_view["integrity_reference"]["hash_status"],
            "COMPUTED_AT_READ",
        )
        self.assertNotIn("TOPSECRET", raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "PATCH", f"/api/v1/findings/{saved.id}",
            headers=self.headers,
            body={"lifecycle": "accepted_risk"},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["lifecycle"], "accepted_risk")

    def test_scan_creation_is_scoped_queued_and_idempotent(self) -> None:
        body = {"profile": "web-audit", "target": "https://example.test"}
        request_headers = {**self.headers, "Idempotency-Key": "scan-create-0001"}
        status, response_headers, raw = self.call(
            "POST", f"/api/v1/projects/{self.project.id}/scans",
            headers=request_headers,
            body=body,
        )
        self.assertEqual(status, 202, raw.decode("utf-8", errors="replace"))
        response = self.decode(raw)
        scan_id = response["data"]["scan"]["id"]
        self.assertEqual(response["data"]["scan"]["status"], "queued")
        self.assertEqual(response["data"]["job"]["status"], "queued")
        self.assertNotIn("payload", response["data"]["job"])
        self.assertNotIn("raw", response["data"]["scan"])
        self.assertEqual(response_headers["location"], f"/api/v1/scans/{scan_id}")

        status, replay_headers, replay_raw = self.call(
            "POST", f"/api/v1/projects/{self.project.id}/scans",
            headers=request_headers,
            body=body,
        )
        self.assertEqual(status, 202)
        self.assertEqual(replay_headers["idempotency-replayed"], "true")
        self.assertEqual(self.decode(replay_raw)["data"]["scan"]["id"], scan_id)
        scans = self.services.platform.scan_list(self.project.id, limit=10)
        self.assertEqual([item.id for item in scans], [scan_id])

        status, _headers, raw = self.call(
            "POST", f"/api/v1/projects/{self.project.id}/scans",
            headers=request_headers,
            body={"profile": "web-audit", "target": "https://example.test/other"},
        )
        self.assertEqual(status, 409)
        self.assertEqual(self.decode(raw)["error"]["code"], "idempotency_conflict")

        status, _headers, raw = self.call(
            "GET", f"/api/v1/scans/{scan_id}", headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["jobs"][0]["status"], "queued")

        status, _headers, raw = self.call(
            "POST", f"/api/v1/scans/{scan_id}/cancel", headers=self.headers,
        )
        self.assertEqual(status, 202, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["job"]["status"], "cancelled")
        self.assertEqual(self.decode(raw)["data"]["scan"]["status"], "cancelled")

    def test_analytics_bundle_and_async_report_generation_use_existing_services(self) -> None:
        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/dashboard",
            headers=self.headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        dashboard = self.decode(raw)["data"]
        self.assertEqual(dashboard["project_id"], self.project.id)
        self.assertIn("posture", dashboard)
        self.assertIn("risk", dashboard)

        request_headers = {**self.headers, "Idempotency-Key": "report-create-0001"}
        status, response_headers, raw = self.call(
            "POST", f"/api/v1/projects/{self.project.id}/reports",
            headers=request_headers,
            body={"report_type": "executive", "title": "API Executive Report"},
        )
        self.assertEqual(status, 202, raw.decode("utf-8", errors="replace"))
        queued = self.decode(raw)["data"]
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(response_headers["location"], f"/api/v1/scans/{queued['scan_id']}")

        replay_status, replay_headers, replay_raw = self.call(
            "POST", f"/api/v1/projects/{self.project.id}/reports",
            headers=request_headers,
            body={"report_type": "executive", "title": "API Executive Report"},
        )
        self.assertEqual(replay_status, 202)
        self.assertEqual(replay_headers["idempotency-replayed"], "true")
        self.assertEqual(self.decode(replay_raw)["data"]["job_id"], queued["job_id"])

        job = self.services.jobs.job_get(queued["job_id"])
        worker = WorkerRuntime(
            self.services.platform,
            self.services.identity,
            self.services.jobs,
            self.services.jobs.registry,
            worker_id="api-report-test",
        )
        claimed = self.services.jobs.claim_next("api-report-test")
        self.assertIsNotNone(claimed)
        worker._execute(claimed)
        completed = self.services.jobs.job_get(job.id)
        self.assertEqual(completed.status, "completed")
        self.assertTrue(completed.result_reference.startswith("report:"))
        report_id = completed.result_reference.partition(":")[2]

        status, _headers, raw = self.call(
            "GET", f"/api/v1/reports/{report_id}", headers=self.headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["report_type"], "executive")

        status, headers, raw = self.call(
            "GET", f"/api/v1/reports/{report_id}/export",
            headers=self.headers,
            query="format=json",
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        exported = json.loads(raw.decode("utf-8"))
        self.assertEqual(exported["metadata"]["report_type"], "executive")

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/reports",
            headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["count"], 1)

    def test_platform_admin_routes_require_out_of_band_operator_token(self) -> None:
        status, _headers, raw = self.call(
            "GET", "/api/v1/admin/health", headers=self.headers,
        )
        self.assertEqual(status, 503)
        self.assertEqual(self.decode(raw)["error"]["code"], "platform_admin_unavailable")

        token = "P" * 48
        with patch.dict(os.environ, {"SECURITY_TOOLKIT_PLATFORM_ADMIN_TOKEN": token}):
            status, _headers, raw = self.call("GET", "/api/v1/admin/jobs")
            self.assertEqual(status, 401)

            operator_headers = {"X-Platform-Admin-Token": token}
            scan = self.services.platform.scan_create(
                self.project.id, "web-audit", actor="admin-test"
            )
            job = self.services.jobs.create_job(
                scan.id,
                "web-audit",
                payload={},
                actor_id=self.owner.id,
                actor="admin-test",
            )
            claimed = self.services.jobs.claim_next("admin-api-test-worker")
            self.assertIsNotNone(claimed)
            self.services.jobs.fail(
                job.id,
                "config_invalid",
                "private-path-secret should never be exposed",
                actor="admin-test-worker",
            )

            status, _headers, raw = self.call(
                "GET", "/api/v1/admin/jobs",
                headers=operator_headers,
                query="status=failed&limit=20&offset=0",
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
            jobs_response = self.decode(raw)
            job_rows = jobs_response["data"]
            self.assertEqual(jobs_response["total"], 1)
            self.assertEqual(job_rows[0]["id"], job.id)
            self.assertNotIn("payload", job_rows[0])
            self.assertNotIn("error_message", job_rows[0])
            self.assertNotIn("private-path-secret", raw.decode("utf-8"))

            status, _headers, raw = self.call(
                "POST", f"/api/v1/admin/jobs/{job.id}/retry",
                headers=operator_headers,
                body={},
            )
            self.assertEqual(status, 202, raw.decode("utf-8", errors="replace"))
            self.assertEqual(self.decode(raw)["data"]["status"], "queued")

            status, _headers, raw = self.call(
                "GET", "/api/v1/admin/integration-diagnostics",
                headers=operator_headers,
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
            self.assertEqual(self.decode(raw)["data"]["total"], 0)

            status, _headers, raw = self.call(
                "GET", "/api/v1/admin/features", headers=operator_headers,
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))

            status, _headers, raw = self.call(
                "POST", "/api/v1/admin/maintenance/jobs/sweep-stale",
                headers=operator_headers,
                body={},
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
            actions = {
                row["action"]
                for row in self.services.platform.db.query(
                    "SELECT action FROM audit_events WHERE action=?",
                    ("platform.maintenance.jobs_swept",),
                    limit=10,
                )
            }
            self.assertIn("platform.maintenance.jobs_swept", actions)

            status, _headers, raw = self.call(
                "GET", "/api/v1/openapi.json", headers=self.headers,
            )
            self.assertEqual(status, 200)
            openapi = self.decode(raw)
            self.assertEqual(
                openapi["paths"]["/api/v1/admin/jobs"]["get"]["security"],
                [{"platformAdminKey": []}],
            )
            self.assertEqual(
                openapi["components"]["securitySchemes"]["platformAdminKey"]["name"],
                "X-Platform-Admin-Token",
            )

        with patch.dict(os.environ, {"SECURITY_TOOLKIT_PLATFORM_ADMIN_TOKEN": ""}):
            status, _headers, raw = self.call(
                "GET", "/api/v1/admin/health",
            )
            self.assertEqual(status, 503)
            self.assertEqual(self.decode(raw)["error"]["code"], "platform_admin_unavailable")

    def test_tenant_metrics_are_aggregate_and_isolated(self) -> None:
        status, _headers, raw = self.call(
            "POST", f"/api/v1/projects/{self.project.id}/assets",
            headers=self.headers,
            body={"asset_type": "domain", "value": "metrics.example.test"},
        )
        self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/metrics",
            headers=self.headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        result = self.decode(raw)["data"]
        self.assertEqual(result["tenant_id"], self.org.id)
        self.assertEqual(result["scope"], "tenant_aggregate")
        self.assertEqual(result["metrics"]["projects"], 1)
        self.assertEqual(result["metrics"]["assets"], 1)
        self.assertNotIn("api-owner", raw.decode("utf-8"))
        self.assertNotIn(self.project.id, raw.decode("utf-8"))

        other_org = self.services.platform.org_create("Metrics Isolation Tenant")
        self.services.identity.user_create(
            other_org.id,
            "metrics-isolation-owner",
            "metrics-isolation-owner@example.test",
            _PASSWORD,
            ("owner",),
            allow_any_role=True,
            actor="test",
        )
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login",
            body={"identifier": "metrics-isolation-owner@example.test", "password": _PASSWORD},
        )
        self.assertEqual(status, 200)
        other_headers = {"Authorization": "Bearer " + self.decode(raw)["access_token"]}
        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/metrics",
            headers=other_headers,
        )
        self.assertEqual(status, 403)
        self.assertNotIn(self.project.id, raw.decode("utf-8"))

    def test_cloud_account_credential_routes_encrypt_redact_and_enforce_tenant_scope(self) -> None:
        secret = "CLOUD_CREDENTIAL_SENTINEL_123456789"
        rotated_secret = "CLOUD_CREDENTIAL_ROTATED_987654321"
        encoded_key = base64.b64encode(b"K" * 32).decode("ascii")
        key_environment = {
            "SECURITY_TOOLKIT_ENCRYPTION_ACTIVE_KEY_ID": "api-test-cloud-key",
            "SECURITY_TOOLKIT_ENCRYPTION_KEY": encoded_key,
        }
        with patch.dict(os.environ, key_environment):
            status, _headers, raw = self.call(
                "POST", f"/api/v1/tenants/{self.org.id}/cloud-accounts",
                headers=self.headers,
                body={
                    "provider": "fixture",
                    "account_identifier": "cloud-account-api-1",
                    "display_name": "API test account",
                    "region_scope": ["test-region-1"],
                    "credential_ref": "vault://cloud/api-test",
                    "credential_secret": secret,
                },
            )
            self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))
            created = self.decode(raw)["data"]
            account_id = created["id"]
            response_text = raw.decode("utf-8")
            self.assertTrue(created["credential_configured"])
            self.assertNotIn("credential_ref", created)
            self.assertNotIn("credential_hint", created)
            self.assertNotIn("credential_enc", created)
            self.assertNotIn(secret, response_text)
            self.assertNotIn("vault://cloud/api-test", response_text)

            stored = self.services.platform.db.query(
                "SELECT credential_enc, credential_ref, credential_hint "
                "FROM cloud_accounts WHERE id=? AND org_id=?",
                (account_id, self.org.id),
            )
            self.assertEqual(len(stored), 1)
            self.assertNotIn(secret, stored[0]["credential_enc"])
            from services.crypto import CryptoService, EncryptedValueError

            crypto = CryptoService()
            aad = f"cloud-account-credential:v1:{self.org.id}:{account_id}"
            self.assertEqual(
                crypto.decrypt_text(stored[0]["credential_enc"], associated_data=aad),
                secret,
            )
            with self.assertRaises(EncryptedValueError):
                crypto.decrypt_text(
                    stored[0]["credential_enc"],
                    associated_data=f"cloud-account-credential:v1:other-tenant:{account_id}",
                )

            status, _headers, raw = self.call(
                "PATCH", f"/api/v1/tenants/{self.org.id}/cloud-accounts/{account_id}",
                headers=self.headers,
                body={"credential_secret": rotated_secret},
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
            self.assertTrue(self.decode(raw)["data"]["credential_configured"])
            self.assertNotIn(rotated_secret, raw.decode("utf-8"))
            updated = self.services.platform.db.query(
                "SELECT credential_enc FROM cloud_accounts WHERE id=? AND org_id=?",
                (account_id, self.org.id),
            )[0]
            self.assertNotEqual(stored[0]["credential_enc"], updated["credential_enc"])
            self.assertEqual(crypto.decrypt_text(updated["credential_enc"], associated_data=aad), rotated_secret)

        other_org = self.services.platform.org_create("Cloud Account Isolation Tenant")
        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{other_org.id}/cloud-accounts/{account_id}",
            headers=self.headers,
        )
        self.assertEqual(status, 403)
        self.assertNotIn(account_id, raw.decode("utf-8"))

    def test_integration_routes_redact_credentials_and_enforce_scope_and_approval(self) -> None:
        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/integration-catalog",
            headers=self.headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        catalog = self.decode(raw)["data"]
        self.assertTrue(catalog)
        self.assertIn("generic_webhook", str(catalog))

        secret = SecretGovernanceService(self.services.platform).register(
            self.org.id,
            kind="webhook_secret",
            name="API integration credential",
            reference="vault://integration/credential",
            material="INTEGRATION_SECRET_SENTINEL",
            actor="integration-test",
        )
        create_body = {
            "project_id": self.project.id,
            "name": "API test webhook",
            "connector_kind": "generic_webhook",
            "auth_mode": "hmac",
            "endpoint_url": "https://hooks.example.com/security-toolkit",
            "provider": "generic-test-provider",
            "credential_ref": secret["id"],
            "config": {"adapter": "generic_webhook"},
            "max_attempts": 2,
        }
        status, _headers, raw = self.call(
            "POST", f"/api/v1/tenants/{self.org.id}/integrations",
            headers=self.headers,
            body=create_body,
        )
        self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))
        created = self.decode(raw)["data"]
        integration_id = created["id"]
        response_text = raw.decode("utf-8")
        self.assertTrue(created["credential_reference_configured"])
        self.assertNotIn("credential_ref", created)
        self.assertNotIn(secret["id"], response_text)
        self.assertNotIn("vault://integration/credential", response_text)
        self.assertNotIn("INTEGRATION_SECRET_SENTINEL", response_text)
        self.assertEqual(created["status"], "disabled")

        status, _headers, raw = self.call(
            "POST", f"/api/v1/tenants/{self.org.id}/integrations",
            headers=self.headers,
            body={**create_body, "name": "Raw secret rejected", "credential_secret": "DO_NOT_STORE"},
        )
        self.assertEqual(status, 400)
        self.assertNotIn("DO_NOT_STORE", raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/integrations/{integration_id}", headers=self.headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertNotIn(secret["id"], raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/integrations",
            headers=self.headers,
            query=f"project_id={self.project.id}&status=disabled&limit=20&offset=0",
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["count"], 1)
        self.assertNotIn(secret["id"], raw.decode("utf-8"))

        missing_reference_body = dict(create_body)
        missing_reference_body.pop("credential_ref")
        missing_reference_body["name"] = "Missing credential webhook"
        status, _headers, raw = self.call(
            "POST", f"/api/v1/tenants/{self.org.id}/integrations",
            headers=self.headers,
            body=missing_reference_body,
        )
        self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))
        missing_reference_id = self.decode(raw)["data"]["id"]
        self.assertFalse(self.decode(raw)["data"]["credential_reference_configured"])

        status, _headers, raw = self.call(
            "POST", f"/api/v1/integrations/{integration_id}/enable",
            headers=self.headers,
            body={},
        )
        self.assertEqual(status, 403)
        self.assertNotIn("separation_of_duties", raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "PATCH", f"/api/v1/integrations/{integration_id}",
            headers=self.headers,
            body={"provider": "updated-test-provider"},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["provider"], "updated-test-provider")
        self.assertNotIn(secret["id"], raw.decode("utf-8"))

        other_org = self.services.platform.org_create("Other Integration Tenant")
        other_owner = self.services.identity.user_create(
            other_org.id,
            "other-integration-owner",
            "other-integration-owner@example.test",
            _PASSWORD,
            ("owner",),
            allow_any_role=True,
            actor="test",
        )
        self.assertTrue(other_owner.id)
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login",
            body={"identifier": "other-integration-owner@example.test", "password": _PASSWORD},
        )
        self.assertEqual(status, 200)
        other_headers = {"Authorization": "Bearer " + self.decode(raw)["access_token"]}
        status, _headers, raw = self.call(
            "GET", f"/api/v1/integrations/{integration_id}", headers=other_headers,
        )
        self.assertEqual(status, 404)
        self.assertNotIn(secret["id"], raw.decode("utf-8"))

        approver = self.services.identity.user_create(
            self.org.id,
            "integration-approver",
            "integration-approver@example.test",
            _PASSWORD,
            ("owner",),
            allow_any_role=True,
            actor="test",
        )
        self.assertTrue(approver.id)
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login",
            body={"identifier": "integration-approver@example.test", "password": _PASSWORD},
        )
        self.assertEqual(status, 200)
        approver_headers = {"Authorization": "Bearer " + self.decode(raw)["access_token"]}
        status, _headers, raw = self.call(
            "POST", f"/api/v1/integrations/{integration_id}/enable",
            headers=approver_headers,
            body={},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["status"], "enabled")
        self.assertNotIn(secret["id"], raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "POST", f"/api/v1/integrations/{missing_reference_id}/enable",
            headers=approver_headers,
            body={},
        )
        self.assertEqual(status, 409, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["error"]["code"], "integration_misconfigured")

        status, _headers, raw = self.call(
            "GET", f"/api/v1/integrations/{integration_id}/health",
            headers=approver_headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertNotIn(secret["id"], raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/integrations/{integration_id}/deliveries",
            headers=approver_headers,
            query="limit=20&offset=0",
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertNotIn(secret["id"], raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/integration-health",
            headers=approver_headers,
            query="limit=20",
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))

        status, _headers, raw = self.call(
            "POST", f"/api/v1/integrations/{integration_id}/disable",
            headers=approver_headers,
            body={},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["status"], "disabled")

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/notifications/settings",
            headers=self.headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertNotIn("webhook_secret", self.decode(raw)["data"])

        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/cloud-accounts",
            headers=self.headers,
            query="limit=20",
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"], [])

    def test_notification_settings_are_write_only_and_ticketing_fails_closed(self) -> None:
        webhook_secret = "API_WEBHOOK_SECRET_SENTINEL_123456789"
        endpoint_token = "API_WEBHOOK_QUERY_SENTINEL_987654321"
        encoded_key = base64.b64encode(b"P" * 32).decode("ascii")
        key_environment = {
            "SECURITY_TOOLKIT_ENCRYPTION_ACTIVE_KEY_ID": "api-notification-test-key",
            "SECURITY_TOOLKIT_ENCRYPTION_KEY": encoded_key,
        }
        with patch.dict(os.environ, key_environment):
            status, _headers, raw = self.call(
                "PATCH",
                f"/api/v1/projects/{self.project.id}/notifications/settings",
                headers=self.headers,
                body={
                    "webhook_enabled": True,
                    "webhook_url": f"https://hooks.example.com/notify?token={endpoint_token}",
                    "webhook_secret": webhook_secret,
                },
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
            response_text = raw.decode("utf-8")
            self.assertNotIn(webhook_secret, response_text)
            self.assertNotIn(endpoint_token, response_text)
            self.assertNotIn("webhook_secret", response_text)
            setting_row = self.services.platform.db.query(
                "SELECT webhook_url, webhook_secret FROM notification_settings "
                "WHERE org_id=? AND project_id=? LIMIT 1",
                (self.org.id, self.project.id),
            )[0]
            self.assertEqual(
                setting_row["webhook_url"],
                f"https://hooks.example.com/notify?token={endpoint_token}",
            )
            self.assertNotIn(webhook_secret, setting_row["webhook_secret"])

            status, _headers, raw = self.call(
                "GET",
                f"/api/v1/projects/{self.project.id}/notifications/settings",
                headers=self.headers,
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
            self.assertNotIn(webhook_secret, raw.decode("utf-8"))
            self.assertNotIn(endpoint_token, raw.decode("utf-8"))

            status, _headers, raw = self.call(
                "PATCH",
                f"/api/v1/projects/{self.project.id}/notifications/settings",
                headers=self.headers,
                body={"email_enabled": False},
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
            preserved = self.services.platform.db.query(
                "SELECT webhook_url, webhook_secret FROM notification_settings "
                "WHERE org_id=? AND project_id=? LIMIT 1",
                (self.org.id, self.project.id),
            )[0]
            self.assertEqual(preserved["webhook_url"], setting_row["webhook_url"])
            self.assertEqual(preserved["webhook_secret"], setting_row["webhook_secret"])

        asset = self.services.platform.asset_add(
            self.project.id,
            "domain",
            "ticketing-api.example.test",
        )
        scan = self.services.platform.scan_create(self.project.id, "web-audit")
        finding = models.Finding(
            scan_id=scan.id,
            project_id=self.project.id,
            asset_id=asset.id,
            title="Ticketing API configuration test",
            description="The API must not fabricate a provider credential.",
            severity="Medium",
            source="api-test",
            rule_id="ticketing-api-rule",
        )
        saved_finding = self.services.platform.finding_ingest(finding)
        connection = self.services.integrations.connections.create(
            self.org.id,
            project_id=self.project.id,
            name="Jira API fail-closed test",
            connector_kind="ticketing",
            auth_mode="api_key",
            endpoint_url="https://acme.atlassian.net",
            provider="jira_cloud",
            credential_ref="vault://test/unresolved-jira-reference",
            config={"project_key": "SEC"},
            actor="ticketing-test-creator",
        )
        self.services.integrations.connections.enable(
            self.org.id,
            connection["id"],
            approved_by="independent-test-approver",
            actor="independent-test-approver",
        )
        status, _headers, raw = self.call(
            "POST",
            f"/api/v1/projects/{self.project.id}/findings/{saved_finding.id}/ticket",
            headers=self.headers,
            body={"integration_id": connection["id"]},
        )
        self.assertEqual(status, 503, raw.decode("utf-8", errors="replace"))
        error_text = raw.decode("utf-8")
        self.assertEqual(self.decode(raw)["error"]["code"], "ticketing_not_configured")
        self.assertNotIn("vault://test/unresolved-jira-reference", error_text)
        self.assertNotIn("traceback", error_text.lower())

    def test_audit_route_is_tenant_filtered_and_bounded(self) -> None:
        other = self.services.platform.org_create("Isolated Audit Tenant")
        self.services.platform.audit(
            "user.created",
            object_type="user",
            object_id="other-user",
            org_id=other.id,
            actor="other-actor",
            metadata={"access_token": "OTHERSECRET"},
        )
        self.services.platform.audit(
            "asset.created",
            object_type="asset",
            object_id="local-asset",
            org_id=self.org.id,
            project_id=self.project.id,
            actor="api-test",
            metadata={"api_key": "LOCALSECRET", "kind": "asset"},
        )
        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/audit-events",
            headers=self.headers,
            query="limit=20&offset=0",
        )
        self.assertEqual(status, 200)
        data = self.decode(raw)["data"]
        self.assertTrue(data)
        self.assertTrue(all(event["org_id"] == self.org.id for event in data))
        self.assertNotIn(other.id, raw.decode("utf-8"))
        self.assertNotIn("OTHERSECRET", raw.decode("utf-8"))
        self.assertNotIn("LOCALSECRET", raw.decode("utf-8"))

    def test_notification_permissions_are_granted_and_settings_route_enforces_them(self) -> None:
        self.assertIn("notification.configure", rbac.PERMISSIONS)
        for role in ("viewer", "analyst"):
            with self.subTest(role=role):
                self.assertTrue(rbac.has_permission((role,), "notification.read"))
                self.assertFalse(rbac.has_permission((role,), "notification.configure"))
                self.assertFalse(rbac.has_permission((role,), "notification.retry"))
        for role in ("security_manager", "admin", "owner"):
            with self.subTest(role=role):
                self.assertTrue(rbac.has_permission((role,), "notification.read"))
                self.assertTrue(rbac.has_permission((role,), "notification.configure"))
                self.assertTrue(rbac.has_permission((role,), "notification.retry"))

        security_manager = self.services.identity.user_create(
            self.org.id,
            "notification-security-manager",
            "notification-security-manager@example.test",
            _PASSWORD,
            ("security_manager",),
            allow_any_role=True,
            actor="test",
        )
        self.assertTrue(security_manager.id)
        status, _headers, raw = self.call(
            "POST",
            "/api/v1/auth/login",
            body={"identifier": "notification-security-manager@example.test", "password": _PASSWORD},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        manager_headers = {"Authorization": "Bearer " + self.decode(raw)["access_token"]}
        status, _headers, raw = self.call(
            "PATCH",
            f"/api/v1/projects/{self.project.id}/notifications/settings",
            headers=manager_headers,
            body={"email_enabled": True, "email_to": "security@example.test"},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertTrue(self.decode(raw)["data"]["email_enabled"])

        viewer = self.services.identity.user_create(
            self.org.id,
            "notification-viewer",
            "notification-viewer@example.test",
            _PASSWORD,
            ("viewer",),
            allow_any_role=True,
            actor="test",
        )
        self.assertTrue(viewer.id)
        status, _headers, raw = self.call(
            "POST",
            "/api/v1/auth/login",
            body={"identifier": "notification-viewer@example.test", "password": _PASSWORD},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        viewer_headers = {"Authorization": "Bearer " + self.decode(raw)["access_token"]}
        status, _headers, raw = self.call(
            "GET",
            f"/api/v1/projects/{self.project.id}/notifications/settings",
            headers=viewer_headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertTrue(self.decode(raw)["data"]["email_enabled"])
        status, _headers, raw = self.call(
            "PATCH",
            f"/api/v1/projects/{self.project.id}/notifications/settings",
            headers=viewer_headers,
            body={"email_enabled": False},
        )
        self.assertEqual(status, 403, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["error"]["code"], "forbidden")

    def test_project_bound_credential_cannot_use_tenant_user_routes(self) -> None:
        key = self.services.identity.credential_create(
            self.org.id,
            "project-only-api-test",
            (),
            created_by=self.owner.id,
            project_id=self.project.id,
            actor="test",
        )
        credential_headers = {"Authorization": "Bearer " + key["secret"]}
        status, _headers, raw = self.call(
            "GET", f"/api/v1/tenants/{self.org.id}/users",
            headers=credential_headers,
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.decode(raw)["error"]["code"], "forbidden")

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/assets",
            headers=credential_headers,
        )
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
