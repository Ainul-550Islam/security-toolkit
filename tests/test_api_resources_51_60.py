"""End-to-end API checks for customer security resources 51–60."""

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

_PASSWORD = "S3cure!Passw0rd"


class ApiResources51To60Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="api_resources_51_60_")
        self.addCleanup(self.tmp.cleanup)
        self.services = build_default_services(os.path.join(self.tmp.name, "platform.db"))
        self.org = self.services.platform.org_create("API Resources 51-60")
        self.owner = self.services.identity.user_create(
            self.org.id,
            "resource-owner",
            "resource-owner@example.test",
            _PASSWORD,
            ("owner",),
            allow_any_role=True,
            actor="test",
        )
        self.project = self.services.platform.project_create(
            self.org.id, "resource-project", actor="test"
        )
        self.services.platform.scope_set(
            self.project.id, ["example.test"], [], actor="test"
        )
        self.app = create_app(
            self.services,
            require_tls=False,
            rate_limiter=SafeSlidingWindowLimiter(limit=1000, max_keys=2000),
        )
        self.addCleanup(self.app.close)
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login",
            body={"identifier": self.owner.email, "password": _PASSWORD},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        login = self.decode(raw)
        self.token = login["access_token"]
        self.session_id = login["principal"]["session_id"]
        self.headers = {"Authorization": "Bearer " + self.token}

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

    def make_finding(self, *, project_id: str | None = None,
                     title: str = "Searchable test finding") -> tuple[Any, Any, Any, Any]:
        project_id = project_id or self.project.id
        asset = self.services.platform.asset_add(
            project_id,
            "domain",
            "example.test",
            metadata={"source": "test-fixture", "owner": "asset-owner"},
            actor="test",
        )
        scan = self.services.platform.scan_create(project_id, "web-audit", actor="test")
        finding = models.Finding(
            scan_id=scan.id,
            project_id=project_id,
            asset_id=asset.id,
            title=title,
            description="A persisted test finding for customer-resource API coverage.",
            severity="High",
            category="web",
            source="test-fixture",
            rule_id="test-rule",
            remediation="Use the supported remediation workflow.",
        )
        saved = self.services.platform.finding_ingest(finding)
        evidence = self.services.platform.evidence_add(
            saved.id,
            evidence_type="response",
            url="https://example.test/vulnerable?token=TOPSECRET_SENTINEL",
            method="GET",
            status_code="200",
            request_snippet="Authorization: Bearer TOPSECRET_SENTINEL",
            response_snippet="bounded test evidence",
            detection_reason="A persisted test evidence record",
            scanner="test-fixture",
            rule_id="test-rule",
        )
        return asset, scan, saved, evidence

    def make_other_tenant(self) -> tuple[Any, Any]:
        other_org = self.services.platform.org_create("Other Resources Tenant")
        other_project = self.services.platform.project_create(
            other_org.id, "other-resources-project", actor="test"
        )
        self.services.platform.scope_set(
            other_project.id, ["other.example.test"], [], actor="test"
        )
        return other_org, other_project

    def test_project_crud_archive_scope_and_tenant_isolation(self) -> None:
        status, _headers, raw = self.call(
            "GET", "/api/v1/projects", headers=self.headers, query="limit=10&offset=0"
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["total"], 1)
        self.assertEqual(self.decode(raw)["data"][0]["id"], self.project.id)

        status, _headers, raw = self.call(
            "POST", "/api/v1/projects", headers=self.headers,
            body={"name": "created-through-v1", "description": "customer project"},
        )
        self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))
        created_id = self.decode(raw)["data"]["id"]
        self.assertEqual(self.decode(raw)["data"]["org_id"], self.org.id)

        status, _headers, raw = self.call(
            "POST", "/api/v1/projects", headers=self.headers,
            body={"name": "cross-tenant-attempt", "tenant_id": "not-authoritative"},
        )
        self.assertEqual(status, 400)

        status, _headers, raw = self.call(
            "PATCH", f"/api/v1/projects/{created_id}", headers=self.headers,
            body={"name": "renamed-project", "description": "updated", "status": "paused"},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["name"], "renamed-project")
        self.assertEqual(self.decode(raw)["data"]["status"], "paused")

        status, _headers, raw = self.call(
            "PUT", f"/api/v1/projects/{created_id}/scope", headers=self.headers,
            body={"allow": ["*.example.test"], "deny": ["admin.example.test"]},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{created_id}/scope", headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["deny"], ["admin.example.test"])

        status, _headers, raw = self.call(
            "POST", f"/api/v1/projects/{created_id}/archive", headers=self.headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["status"], "archived")
        status, _headers, raw = self.call(
            "POST", f"/api/v1/projects/{created_id}/restore", headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["status"], "active")

        other_org, other_project = self.make_other_tenant()
        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{other_project.id}", headers=self.headers,
        )
        self.assertEqual(status, 403)
        actions = {event.action for event in self.services.platform.audit_list_org(self.org.id)}
        self.assertIn("project.archived", actions)
        self.assertIn("scope.changed", actions)
        self.assertNotEqual(other_org.id, self.org.id)

    def test_organization_profile_preferences_and_mfa_policy(self) -> None:
        path = f"/api/v1/organizations/{self.org.id}"
        status, _headers, raw = self.call("GET", path, headers=self.headers)
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        organization = self.decode(raw)["data"]
        self.assertEqual(organization["status"], "active")
        self.assertFalse(organization["preferences"]["configured"])

        status, _headers, raw = self.call(
            "PATCH", path, headers=self.headers, body={"name": "Updated Resource Tenant"}
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["name"], "Updated Resource Tenant")

        preferences_path = path + "/preferences"
        status, _headers, raw = self.call(
            "PATCH", preferences_path, headers=self.headers,
            body={"timezone": "Asia/Dhaka", "locale": "bn-BD"},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        preferences = self.decode(raw)["data"]
        self.assertEqual(preferences["timezone"], "Asia/Dhaka")
        self.assertEqual(preferences["locale"], "bn-BD")
        self.assertTrue(preferences["configured"])

        status, _headers, raw = self.call(
            "PATCH", preferences_path, headers=self.headers, body={"timezone": "Not/A_Zone"}
        )
        self.assertEqual(status, 400)
        self.assertNotIn("zoneinfo", raw.decode("utf-8").lower())

        posture_path = path + "/security-posture"
        status, _headers, raw = self.call(
            "PATCH", posture_path, headers=self.headers,
            body={
                "version": 0,
                "policy": {"mode": "required", "roles": ["admin"], "step_up_ttl": 600, "require_recent": 900},
            },
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["mfa_policy"]["mode"], "required")
        status, _headers, raw = self.call("GET", posture_path, headers=self.headers)
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["state"], "CONFIGURED")
        actions = {event.action for event in self.services.platform.audit_list_org(self.org.id)}
        self.assertIn("organization.updated", actions)
        self.assertIn("organization.preferences.updated", actions)
        self.assertIn("identity.policy.updated", actions)

    def test_roles_assignment_removal_and_escalation_guard(self) -> None:
        target = self.services.identity.user_create(
            self.org.id, "role-target", "role-target@example.test", _PASSWORD,
            ("viewer",), allow_any_role=True, actor="test",
        )
        status, _headers, raw = self.call("GET", "/api/v1/roles", headers=self.headers)
        self.assertEqual(status, 200)
        self.assertIn("owner", [role["name"] for role in self.decode(raw)["data"]])

        roles_path = f"/api/v1/tenants/{self.org.id}/users/{target.id}/roles"
        status, _headers, raw = self.call(
            "PUT", roles_path, headers=self.headers, body={"roles": ["analyst"]}
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.services.identity.user_roles(target.id), ("analyst",))

        status, _headers, raw = self.call(
            "PUT", roles_path, headers=self.headers, body={"roles": ["analyst", "viewer"]}
        )
        self.assertEqual(status, 200)
        status, _headers, raw = self.call(
            "DELETE", roles_path + "/analyst", headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.services.identity.user_roles(target.id), ("viewer",))
        status, _headers, raw = self.call(
            "DELETE", roles_path + "/viewer", headers=self.headers,
        )
        self.assertEqual(status, 409)

        admin = self.services.identity.user_create(
            self.org.id, "role-admin", "role-admin@example.test", _PASSWORD,
            ("admin",), allow_any_role=True, actor="test",
        )
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login",
            body={"identifier": admin.email, "password": _PASSWORD},
        )
        self.assertEqual(status, 200)
        admin_headers = {"Authorization": "Bearer " + self.decode(raw)["access_token"]}
        status, _headers, raw = self.call(
            "PUT", roles_path, headers=admin_headers, body={"roles": ["owner"]}
        )
        self.assertEqual(status, 403)
        actions = {event.action for event in self.services.platform.audit_list_org(self.org.id)}
        self.assertIn("user.role_changed", actions)
        self.assertTrue(rbac.can_assign_role(("owner",), "owner"))

    def test_sessions_are_self_scoped_and_revocation_is_effective(self) -> None:
        status, _headers, raw = self.call("GET", "/api/v1/sessions", headers=self.headers)
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        data = self.decode(raw)["data"]
        self.assertEqual([item["id"] for item in data], [self.session_id])
        self.assertTrue(data[0]["current"])
        self.assertNotIn("token_hash", raw.decode("utf-8"))
        self.assertNotIn(self.token, raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "GET", "/api/v1/sessions/current", headers=self.headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["session"]["id"], self.session_id)

        status, _headers, raw = self.call(
            "POST", "/api/v1/sessions/current/revoke", headers=self.headers
        )
        self.assertEqual(status, 204)
        status, _headers, raw = self.call("GET", "/api/v1/sessions", headers=self.headers)
        self.assertEqual(status, 401)

    def test_notification_preferences_channels_and_secret_redaction(self) -> None:
        secret = "API_NOTIFICATION_SECRET_123456789"
        endpoint_token = "QUERY_TOKEN_NOTIFICATION_SENTINEL"
        key_environment = {
            "SECURITY_TOOLKIT_ENCRYPTION_ACTIVE_KEY_ID": "api-resource-notification-key",
            "SECURITY_TOOLKIT_ENCRYPTION_KEY": base64.b64encode(b"N" * 32).decode("ascii"),
        }
        prefs_path = f"/api/v1/projects/{self.project.id}/notifications/preferences"
        with patch.dict(os.environ, key_environment):
            status, _headers, raw = self.call(
                "PATCH", prefs_path, headers=self.headers,
                body={
                    "webhook_enabled": True,
                    "webhook_url": f"https://hooks.example.com/notify?token={endpoint_token}",
                    "webhook_secret": secret,
                },
            )
            self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
            response_text = raw.decode("utf-8")
            self.assertNotIn(secret, response_text)
            self.assertNotIn(endpoint_token, response_text)
            self.assertNotIn("webhook_secret", response_text)

            status, _headers, raw = self.call("GET", prefs_path, headers=self.headers)
            self.assertEqual(status, 200)
            self.assertNotIn(secret, raw.decode("utf-8"))
            self.assertNotIn(endpoint_token, raw.decode("utf-8"))

            status, _headers, raw = self.call(
                "GET", f"/api/v1/projects/{self.project.id}/notifications/channels",
                headers=self.headers,
            )
            self.assertEqual(status, 200)
            self.assertIn("channels", self.decode(raw)["data"])

            status, _headers, raw = self.call(
                "GET", f"/api/v1/projects/{self.project.id}/notifications", headers=self.headers
            )
            self.assertEqual(status, 200)
            self.assertEqual(self.decode(raw)["data"], [])

    def test_scan_report_evidence_metadata_and_download_fail_closed(self) -> None:
        _asset, scan, finding, evidence = self.make_finding(
            title="Evidence API sentinel finding"
        )
        status, _headers, raw = self.call(
            "GET", f"/api/v1/scans/{scan.id}/evidence", headers=self.headers
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        evidence_list = self.decode(raw)["data"]
        self.assertEqual(evidence_list[0]["id"], evidence.id)
        self.assertNotIn("request_snippet", evidence_list[0])
        self.assertNotIn("response_snippet", evidence_list[0])
        self.assertNotIn("TOPSECRET_SENTINEL", raw.decode("utf-8"))

        snapshot = self.services.reports.snapshot(
            self.project.id, "technical", generated_by="api-test"
        )
        report = self.services.reports.store_run(snapshot, store_payload=True)
        status, _headers, raw = self.call(
            "GET", f"/api/v1/reports/{report['id']}/evidence", headers=self.headers
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"][0]["finding_id"], finding.id)
        self.assertEqual(self.decode(raw)["data"][0]["integrity_reference"]["report_hash"], report["report_hash"])
        self.assertNotIn("TOPSECRET_SENTINEL", raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/evidence/{evidence.id}/download", headers=self.headers
        )
        self.assertEqual(status, 503)
        self.assertEqual(self.decode(raw)["error"]["code"], "evidence_download_unavailable")

    def test_asset_discovery_uses_persisted_scan_jobs_and_asset_metadata(self) -> None:
        asset = self.services.platform.asset_add(
            self.project.id, "domain", "example.test",
            metadata={"source": "recon-fixture", "owner": "security-team"},
            actor="test",
        )
        status, _headers, raw = self.call(
            "POST", f"/api/v1/projects/{self.project.id}/scans",
            headers={**self.headers, "Idempotency-Key": "resources-51-60-discovery"},
            body={"profile": "recon", "target": "example.test"},
        )
        self.assertEqual(status, 202, raw.decode("utf-8", errors="replace"))
        scan_id = self.decode(raw)["data"]["scan"]["id"]
        path_sentinel = "/tmp/API_DISCOVERY_PATH_SENTINEL"
        self.services.platform.db.execute(
            "UPDATE scans SET scope_ref=? WHERE id=?", (path_sentinel, scan_id)
        )
        self.services.platform.db.execute(
            "UPDATE jobs SET result_reference=? WHERE scan_id=?",
            (path_sentinel, scan_id),
        )

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/assets/discovery/jobs",
            headers=self.headers,
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"][0]["id"], scan_id)
        self.assertEqual(self.decode(raw)["data"][0]["jobs"][0]["status"], "queued")
        self.assertTrue(self.decode(raw)["data"][0]["jobs"][0]["result_reference_available"])
        self.assertTrue(self.decode(raw)["data"][0]["scope_reference_available"])
        self.assertNotIn(path_sentinel, raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/assets/discovery/assets",
            headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"][0]["id"], asset.id)
        self.assertEqual(self.decode(raw)["data"][0]["source"], "recon-fixture")
        self.assertEqual(self.decode(raw)["data"][0]["owner"], "security-team")

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/assets/discovery/jobs/{scan_id}",
            headers=self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["discovery_job"]["id"], scan_id)

    def test_risk_summary_and_trends_use_persisted_finding_scores(self) -> None:
        self.make_finding(title="Risk API persisted-score finding")
        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/risk", headers=self.headers
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        data = self.decode(raw)["data"]
        self.assertGreaterEqual(data["aggregate"]["count"], 1)
        self.assertIn("High", data["severity_distribution"])
        self.assertEqual(data["score_components"]["recalculated"], False)
        self.assertEqual(data["top_categories"]["source"], "persisted_findings")
        self.assertEqual(data["top_categories"]["data"][0]["category"], "web")
        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/risk/trends", headers=self.headers
        )
        self.assertEqual(status, 200)
        self.assertIn("finding_lifecycle", self.decode(raw)["data"])
        self.assertIn("persisted_risk_events", self.decode(raw)["data"])

    def test_remediation_assignment_comments_due_date_and_verification(self) -> None:
        _asset, _scan, finding, _evidence = self.make_finding(
            title="Remediation API test finding"
        )
        assignee = self.services.identity.user_create(
            self.org.id, "remediation-assignee", "remediation-assignee@example.test",
            _PASSWORD, ("analyst",), allow_any_role=True, actor="test",
        )
        path = f"/api/v1/projects/{self.project.id}/findings/{finding.id}/remediation"
        status, _headers, raw = self.call("POST", path, headers=self.headers, body={})
        self.assertEqual(status, 201, raw.decode("utf-8", errors="replace"))
        ticket_id = self.decode(raw)["data"]["id"]

        status, _headers, raw = self.call(
            "POST", f"/api/v1/remediations/{ticket_id}/assignment",
            headers=self.headers, body={"owner_id": assignee.id},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["owner_id"], assignee.id)

        status, _headers, raw = self.call(
            "PATCH", f"/api/v1/remediations/{ticket_id}/status",
            headers=self.headers, body={"status": "in_progress", "reason": "Work started"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.decode(raw)["data"]["status"], "in_progress")

        status, _headers, raw = self.call(
            "PATCH", f"/api/v1/remediations/{ticket_id}/due-date",
            headers=self.headers, body={"due_at": "2030-01-02T03:04:05Z"},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertEqual(self.decode(raw)["data"]["due_at"], "2030-01-02T03:04:05Z")
        status, _headers, raw = self.call(
            "PATCH", f"/api/v1/remediations/{ticket_id}/due-date",
            headers=self.headers, body={"due_at": "2030-02-31T03:04:05Z"},
        )
        self.assertEqual(status, 400)

        comment_secret = "Bearer COMMENT_SECRET_SENTINEL"
        status, _headers, raw = self.call(
            "POST", f"/api/v1/remediations/{ticket_id}/comments",
            headers=self.headers, body={"comment": "Please investigate " + comment_secret},
        )
        self.assertEqual(status, 201)
        self.assertNotIn("COMMENT_SECRET_SENTINEL", raw.decode("utf-8"))

        status, _headers, raw = self.call(
            "PATCH", f"/api/v1/remediations/{ticket_id}/status",
            headers=self.headers, body={"status": "ready_for_verification"},
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        status, _headers, raw = self.call(
            "POST", f"/api/v1/remediations/{ticket_id}/verification",
            headers=self.headers, body={},
        )
        self.assertEqual(status, 202, raw.decode("utf-8", errors="replace"))
        self.assertTrue(self.decode(raw)["data"]["verification_scan_id"])
        actions = {event.action for event in self.services.platform.audit_list_org(self.org.id)}
        self.assertIn("remediation.assigned", actions)
        self.assertIn("remediation.comment_added", actions)

    def test_search_is_bounded_filtered_and_tenant_scoped(self) -> None:
        self.make_finding(title="UniqueSearchFindingToken")
        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/search", headers=self.headers,
            query="q=UniqueSearchFindingToken&type=findings,evidence&limit=20&offset=0",
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        data = self.decode(raw)["data"]
        self.assertTrue(any(item["type"] == "finding" for item in data))
        self.assertTrue(all("TOPSECRET_SENTINEL" not in json.dumps(item) for item in data))
        self.assertLessEqual(self.decode(raw)["count"], 20)

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/search", headers=self.headers,
            query="type=unknown",
        )
        self.assertEqual(status, 400)

    def test_search_explicit_source_checks_only_that_source_permission(self) -> None:
        self.make_finding(title="AnalystSearchPermissionToken")
        analyst = self.services.identity.user_create(
            self.org.id, "search-analyst", "search-analyst@example.test", _PASSWORD,
            ("analyst",), allow_any_role=True, actor="test",
        )
        status, _headers, raw = self.call(
            "POST", "/api/v1/auth/login",
            body={"identifier": analyst.email, "password": _PASSWORD},
        )
        self.assertEqual(status, 200)
        analyst_headers = {"Authorization": "Bearer " + self.decode(raw)["access_token"]}

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/search",
            headers=analyst_headers,
            query="q=AnalystSearchPermissionToken&type=findings&limit=20",
        )
        self.assertEqual(status, 200, raw.decode("utf-8", errors="replace"))
        self.assertTrue(any(item["type"] == "finding" for item in self.decode(raw)["data"]))

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/search",
            headers=analyst_headers, query="type=integrations",
        )
        self.assertEqual(status, 403)

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{self.project.id}/search",
            headers=analyst_headers, query="q=AnalystSearchPermissionToken",
        )
        self.assertEqual(status, 200)
        self.assertIn("integrations", self.decode(raw)["excluded_types"])

    def test_cross_tenant_evidence_report_remediation_and_search_are_denied(self) -> None:
        other_org, other_project = self.make_other_tenant()
        _asset, _scan, other_finding, other_evidence = self.make_finding(
            project_id=other_project.id, title="Other tenant finding",
        )
        ticket = self.services.extra["remediation_service"].ensure(
            other_finding.id, actor="test"
        )
        snapshot = self.services.reports.snapshot(
            other_project.id, "technical", generated_by="test"
        )
        other_report = self.services.reports.store_run(snapshot, store_payload=True)

        status, _headers, raw = self.call(
            "GET", f"/api/v1/projects/{other_project.id}/search", headers=self.headers
        )
        self.assertEqual(status, 403)
        status, _headers, raw = self.call(
            "GET", f"/api/v1/evidence/{other_evidence.id}/download", headers=self.headers
        )
        self.assertEqual(status, 403)
        status, _headers, raw = self.call(
            "GET", f"/api/v1/reports/{other_report['id']}/evidence", headers=self.headers
        )
        self.assertEqual(status, 403)
        status, _headers, raw = self.call(
            "GET", f"/api/v1/remediations/{ticket['id']}", headers=self.headers
        )
        self.assertEqual(status, 403)
        self.assertNotIn(other_org.id, raw.decode("utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
