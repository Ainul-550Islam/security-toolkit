"""Provider-neutral, tenant-scoped ticketing boundary with a Jira Cloud adapter.

The service stores no ticket credentials and creates no parallel ticket table.
It reads existing finding and integration rows with tenant predicates, resolves
write-only credentials through an injected secret resolver, and communicates
only with configured Jira Cloud sites over HTTPS. The adapter never reports a
success until Jira returns a successful response.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol

def _legacy_module(name: str) -> Any:
    """Load one existing platform module without shadowing stdlib imports."""
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
        legacy_directory = str(Path(__file__).resolve().parents[1] / "python")
        if legacy_directory not in sys.path:
            sys.path.append(legacy_directory)
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError:
            raise ImportError("legacy platform dependency is unavailable") from None


errors = _legacy_module("errors")

_MAX_RESPONSE_BYTES = 1_048_576
_MAX_REQUEST_BYTES = 32_768
_MAX_ATTEMPTS = 3
_TIMEOUT_SECONDS = 8
_PROJECT_KEY_RE = re.compile(r"^[A-Z][A-Z0-9]{0,15}$")
_ISSUE_KEY_RE = re.compile(r"^[A-Z][A-Z0-9]{0,15}-[0-9]{1,10}$")
_EMAIL_RE = re.compile(r"^[^\s@]{1,128}@[^\s@]{1,190}$")


class TicketingError(Exception):
    """Safe, bounded ticketing failure code."""

    _CODES = frozenset({
        "not_configured",
        "credentials_unavailable",
        "integration_disabled",
        "provider_not_supported",
        "invalid_configuration",
        "invalid_credentials",
        "auth_failed",
        "permission_denied",
        "provider_unavailable",
        "rate_limited",
        "provider_rejected",
        "response_invalid",
        "duplicate_external_reference",
        "issue_not_found",
        "transition_unavailable",
        "scope_mismatch",
    })

    def __init__(self, code: str) -> None:
        self.code = code if code in self._CODES else "provider_unavailable"
        super().__init__(self.code)

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class TicketingResult:
    """External ticket reference safe to expose to authorized callers."""

    provider: str
    key: str
    url: str
    operation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "key": self.key,
            "url": self.url,
            "operation": self.operation,
        }


class CredentialResolver(Protocol):
    """Deployment-injected source for secret-reference resolution."""

    def resolve(self, org_id: str, reference: str) -> Mapping[str, str]:
        """Resolve an active credential without persisting it in this service."""


class TicketingAdapter(Protocol):
    """Provider operations required by the customer workflow."""

    def upsert_finding(
        self,
        *,
        site_url: str,
        credentials: Mapping[str, str],
        project_key: str,
        issue_type: str,
        org_id: str,
        project_id: str,
        finding: Mapping[str, Any],
    ) -> TicketingResult:
        """Create or update one external issue idempotently."""

    def close_finding(
        self,
        *,
        site_url: str,
        credentials: Mapping[str, str],
        project_key: str,
        org_id: str,
        project_id: str,
        finding_id: str,
    ) -> TicketingResult:
        """Transition the existing issue linked to one local finding."""

    def link_findings(
        self,
        *,
        site_url: str,
        credentials: Mapping[str, str],
        project_key: str,
        org_id: str,
        project_id: str,
        finding_id: str,
        related_finding_id: str,
    ) -> TicketingResult:
        """Link two existing external issues for local findings."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> NoReturn:
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


class JiraCloudAdapter:
    """Read/write Jira Cloud issues using a resolved API-token reference."""

    provider = "jira_cloud"

    def __init__(
        self,
        *,
        transport: Callable[..., Any] | None = None,
        url_validator: Callable[[str], str] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        timeout_seconds: int = _TIMEOUT_SECONDS,
        max_attempts: int = _MAX_ATTEMPTS,
    ) -> None:
        self._transport = transport
        self._url_validator = url_validator
        self._sleep = sleeper
        self._timeout = max(1, min(int(timeout_seconds), _TIMEOUT_SECONDS))
        self._max_attempts = max(1, min(int(max_attempts), _MAX_ATTEMPTS))
        self._opener = urllib.request.build_opener(_NoRedirect())

    @staticmethod
    def _site(site_url: str) -> str:
        raw = str(site_url or "").strip().rstrip("/")
        if len(raw) > 512:
            raise TicketingError("invalid_configuration")
        try:
            parts = urllib.parse.urlsplit(raw)
            hostname = (parts.hostname or "").lower().rstrip(".")
            port = parts.port
        except ValueError:
            raise TicketingError("invalid_configuration") from None
        valid_host = bool(re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+atlassian\.net",
            hostname,
        ))
        if (
            parts.scheme != "https"
            or not valid_host
            or parts.username
            or parts.password
            or port not in (None, 443)
            or parts.path not in ("", "/")
            or parts.query
            or parts.fragment
        ):
            raise TicketingError("invalid_configuration")
        return f"https://{hostname}"

    def _validate_destination(self, url: str) -> None:
        if self._url_validator is not None:
            try:
                self._url_validator(url)
            except Exception:
                raise TicketingError("invalid_configuration") from None
            return
        try:
            import notify
            notify.validate_webhook_url(url, resolve=True)
        except Exception:
            raise TicketingError("invalid_configuration") from None

    @staticmethod
    def _auth(credentials: Mapping[str, str]) -> str:
        email = credentials.get("email", "")
        token = credentials.get("api_token", "")
        if not isinstance(email, str) or not _EMAIL_RE.fullmatch(email):
            raise TicketingError("invalid_credentials")
        if not isinstance(token, str) or not 16 <= len(token) <= 4096:
            raise TicketingError("invalid_credentials")
        raw = base64.b64encode(f"{email}:{token}".encode("utf-8")).decode("ascii")
        return "Basic " + raw

    def _open(self, request: urllib.request.Request) -> Any:
        if self._transport is not None:
            return self._transport(request, timeout=self._timeout)
        return self._opener.open(request, timeout=self._timeout)

    @staticmethod
    def _status_code(exc: urllib.error.HTTPError) -> str:
        status = int(getattr(exc, "code", 0) or 0)
        if status in (401, 403):
            return "auth_failed" if status == 401 else "permission_denied"
        if status == 429:
            return "rate_limited"
        if status in (408, 500, 502, 503, 504):
            return "provider_unavailable"
        if 300 <= status < 400:
            return "provider_rejected"
        return "provider_rejected"

    def _request(
        self,
        *,
        site_url: str,
        method: str,
        path: str,
        credentials: Mapping[str, str],
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        site = self._site(site_url)
        if not path.startswith("/rest/api/3/") or ".." in path or "?" in path or "#" in path:
            raise TicketingError("invalid_configuration")
        url = site + path
        self._validate_destination(url)
        body = b""
        headers = {
            "Accept": "application/json",
            "Authorization": self._auth(credentials),
            "User-Agent": "security-toolkit-ticketing/1",
        }
        if payload is not None:
            try:
                body = json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8", "strict")
            except (TypeError, ValueError, UnicodeEncodeError):
                raise TicketingError("invalid_configuration") from None
            if len(body) > _MAX_REQUEST_BYTES:
                raise TicketingError("invalid_configuration")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body if payload is not None else None, headers=headers, method=method)
        for attempt in range(self._max_attempts):
            try:
                response = self._open(request)
                with response:
                    status = int(response.getcode() or 0)
                    raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise TicketingError("response_invalid")
                if not 200 <= status < 300:
                    code = "rate_limited" if status == 429 else (
                        "provider_unavailable" if status in (408, 500, 502, 503, 504)
                        else "provider_rejected"
                    )
                    if code in {"rate_limited", "provider_unavailable"} and attempt + 1 < self._max_attempts:
                        self._sleep(min(0.25 * (2 ** attempt), 1.0))
                        continue
                    raise TicketingError(code)
                if not raw:
                    return {}
                try:
                    result = json.loads(raw.decode("utf-8", "strict"))
                except (UnicodeDecodeError, ValueError):
                    raise TicketingError("response_invalid") from None
                if not isinstance(result, dict):
                    raise TicketingError("response_invalid")
                return result
            except urllib.error.HTTPError as exc:
                code = self._status_code(exc)
                if code in {"rate_limited", "provider_unavailable"} and attempt + 1 < self._max_attempts:
                    self._sleep(min(0.25 * (2 ** attempt), 1.0))
                    continue
                raise TicketingError(code) from None
            except TicketingError:
                raise
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt + 1 < self._max_attempts:
                    self._sleep(min(0.25 * (2 ** attempt), 1.0))
                    continue
                raise TicketingError("provider_unavailable") from None
            except Exception:
                raise TicketingError("provider_unavailable") from None
        raise TicketingError("provider_unavailable")

    @staticmethod
    def _reference_label(org_id: str, project_id: str, finding_id: str) -> str:
        digest = hashlib.sha256(
            f"{org_id}|{project_id}|{finding_id}".encode("utf-8")
        ).hexdigest()[:24]
        return "security-toolkit-" + digest

    @staticmethod
    def _redacted_text(value: Any, limit: int) -> str:
        try:
            redaction = _legacy_module("redact")
            safe = redaction.redact_text(str(value or ""))
        except Exception:
            raise TicketingError("response_invalid") from None
        return str(safe)[:limit]

    @staticmethod
    def _finding_description(finding: Mapping[str, Any]) -> dict[str, Any]:
        description = JiraCloudAdapter._redacted_text(finding.get("description", ""), 4000)
        remediation = JiraCloudAdapter._redacted_text(finding.get("remediation", ""), 2000)
        finding_id = JiraCloudAdapter._redacted_text(finding.get("id", ""), 160)
        severity = JiraCloudAdapter._redacted_text(finding.get("severity", ""), 32)
        lifecycle = JiraCloudAdapter._redacted_text(finding.get("lifecycle", ""), 32)
        text = (
            f"Finding ID: {finding_id}\n"
            f"Severity: {severity}\n"
            f"Status: {lifecycle}\n\n"
            f"{description}\n\n"
            f"Remediation: {remediation}"
        )[:7000]
        return {
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{"type": "text", "text": text}],
            }],
        }

    def _search(
        self,
        *,
        site_url: str,
        credentials: Mapping[str, str],
        project_key: str,
        label: str,
    ) -> str:
        response = self._request(
            site_url=site_url,
            method="POST",
            path="/rest/api/3/search/jql",
            credentials=credentials,
            payload={
                "jql": f'project = "{project_key}" AND labels = "{label}"',
                "fields": ["key"],
                "maxResults": 2,
            },
        )
        issues = response.get("issues", [])
        if not isinstance(issues, list):
            raise TicketingError("response_invalid")
        if len(issues) > 1:
            raise TicketingError("duplicate_external_reference")
        if not issues:
            return ""
        key = issues[0].get("key", "") if isinstance(issues[0], Mapping) else ""
        if not isinstance(key, str) or not _ISSUE_KEY_RE.fullmatch(key):
            raise TicketingError("response_invalid")
        if not key.startswith(project_key + "-"):
            raise TicketingError("scope_mismatch")
        return key

    @staticmethod
    def _ticket_result(key: str, operation: str, site_url: str) -> TicketingResult:
        site = JiraCloudAdapter._site(site_url)
        if not _ISSUE_KEY_RE.fullmatch(key):
            raise TicketingError("response_invalid")
        return TicketingResult(
            provider="jira_cloud",
            key=key,
            url=site + "/browse/" + urllib.parse.quote(key, safe="-"),
            operation=operation,
        )

    def upsert_finding(
        self,
        *,
        site_url: str,
        credentials: Mapping[str, str],
        project_key: str,
        issue_type: str,
        org_id: str,
        project_id: str,
        finding: Mapping[str, Any],
    ) -> TicketingResult:
        if not _PROJECT_KEY_RE.fullmatch(project_key):
            raise TicketingError("invalid_configuration")
        issue_type = str(issue_type or "Task").strip()
        if not issue_type or len(issue_type) > 64 or any(ord(ch) < 0x20 for ch in issue_type):
            raise TicketingError("invalid_configuration")
        finding_id = str(finding.get("id", "") or "")
        if not finding_id or len(finding_id) > 160:
            raise TicketingError("scope_mismatch")
        label = self._reference_label(org_id, project_id, finding_id)
        key = self._search(
            site_url=site_url,
            credentials=credentials,
            project_key=project_key,
            label=label,
        )
        fields = {
            "summary": self._redacted_text(finding.get("title", "Security finding"), 240),
            "description": self._finding_description(finding),
        }
        if key:
            self._request(
                site_url=site_url,
                method="PUT",
                path="/rest/api/3/issue/" + urllib.parse.quote(key, safe="-"),
                credentials=credentials,
                payload={"fields": fields},
            )
            return self._ticket_result(key, "updated", site_url)
        fields.update({
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "labels": [label],
        })
        created = self._request(
            site_url=site_url,
            method="POST",
            path="/rest/api/3/issue",
            credentials=credentials,
            payload={"fields": fields},
        )
        key = created.get("key", "")
        if not isinstance(key, str) or not _ISSUE_KEY_RE.fullmatch(key):
            raise TicketingError("response_invalid")
        if not key.startswith(project_key + "-"):
            raise TicketingError("scope_mismatch")
        return self._ticket_result(key, "created", site_url)

    def _transition_key(
        self,
        *,
        site_url: str,
        credentials: Mapping[str, str],
        project_key: str,
        label: str,
    ) -> str:
        key = self._search(
            site_url=site_url,
            credentials=credentials,
            project_key=project_key,
            label=label,
        )
        if not key:
            raise TicketingError("issue_not_found")
        return key

    def close_finding(
        self,
        *,
        site_url: str,
        credentials: Mapping[str, str],
        project_key: str,
        org_id: str,
        project_id: str,
        finding_id: str,
    ) -> TicketingResult:
        if not _PROJECT_KEY_RE.fullmatch(project_key):
            raise TicketingError("invalid_configuration")
        label = self._reference_label(org_id, project_id, finding_id)
        key = self._transition_key(
            site_url=site_url,
            credentials=credentials,
            project_key=project_key,
            label=label,
        )
        issue = self._request(
            site_url=site_url,
            method="GET",
            path=f"/rest/api/3/issue/{urllib.parse.quote(key, safe='-')}",
            credentials=credentials,
        )
        fields = issue.get("fields", {})
        current_status = fields.get("status", {}) if isinstance(fields, Mapping) else {}
        category = current_status.get("statusCategory", {}) if isinstance(current_status, Mapping) else {}
        if isinstance(category, Mapping) and str(category.get("key", "")).lower() == "done":
            return self._ticket_result(key, "closed", site_url)
        response = self._request(
            site_url=site_url,
            method="GET",
            path=f"/rest/api/3/issue/{urllib.parse.quote(key, safe='-')}/transitions",
            credentials=credentials,
        )
        transitions = response.get("transitions", [])
        if not isinstance(transitions, list):
            raise TicketingError("response_invalid")
        transition_id = ""
        for transition in transitions:
            if not isinstance(transition, Mapping):
                continue
            destination = transition.get("to", {})
            category = destination.get("statusCategory", {}) if isinstance(destination, Mapping) else {}
            if isinstance(category, Mapping) and str(category.get("key", "")).lower() == "done":
                candidate = str(transition.get("id", ""))
                if candidate.isdigit():
                    transition_id = candidate
                    break
        if not transition_id:
            raise TicketingError("transition_unavailable")
        self._request(
            site_url=site_url,
            method="POST",
            path=f"/rest/api/3/issue/{urllib.parse.quote(key, safe='-')}/transitions",
            credentials=credentials,
            payload={"transition": {"id": transition_id}},
        )
        return self._ticket_result(key, "closed", site_url)

    def link_findings(
        self,
        *,
        site_url: str,
        credentials: Mapping[str, str],
        project_key: str,
        org_id: str,
        project_id: str,
        finding_id: str,
        related_finding_id: str,
    ) -> TicketingResult:
        if not _PROJECT_KEY_RE.fullmatch(project_key) or finding_id == related_finding_id:
            raise TicketingError("invalid_configuration")
        first_label = self._reference_label(org_id, project_id, finding_id)
        second_label = self._reference_label(org_id, project_id, related_finding_id)
        first = self._transition_key(
            site_url=site_url, credentials=credentials,
            project_key=project_key, label=first_label,
        )
        second = self._transition_key(
            site_url=site_url, credentials=credentials,
            project_key=project_key, label=second_label,
        )
        existing_issue = self._request(
            site_url=site_url,
            method="GET",
            path=f"/rest/api/3/issue/{urllib.parse.quote(first, safe='-')}",
            credentials=credentials,
        )
        fields = existing_issue.get("fields", {})
        links = fields.get("issuelinks", []) if isinstance(fields, Mapping) else []
        if not isinstance(links, list):
            raise TicketingError("response_invalid")
        for link in links:
            if not isinstance(link, Mapping):
                continue
            for direction in ("inwardIssue", "outwardIssue"):
                related_issue = link.get(direction, {})
                if isinstance(related_issue, Mapping) and related_issue.get("key") == second:
                    return self._ticket_result(first, "linked", site_url)
        self._request(
            site_url=site_url,
            method="POST",
            path="/rest/api/3/issueLink",
            credentials=credentials,
            payload={
                "type": {"name": "Relates"},
                "inwardIssue": {"key": first},
                "outwardIssue": {"key": second},
            },
        )
        return self._ticket_result(first, "linked", site_url)


class TicketingService:
    """Tenant-filtered facade connecting findings to real Jira Cloud tickets."""

    def __init__(
        self,
        platform: Any,
        *,
        credential_resolver: CredentialResolver | Callable[[str, str], Mapping[str, str]] | None = None,
        adapters: Mapping[str, TicketingAdapter] | None = None,
    ) -> None:
        self.svc = platform
        self.db = platform.db
        self.credential_resolver = credential_resolver
        self.adapters: dict[str, TicketingAdapter] = {"jira_cloud": JiraCloudAdapter()}
        if adapters:
            self.adapters.update(dict(adapters))

    def _connection(self, org_id: str, integration_id: str) -> dict[str, Any]:
        rows = self.db.query(
            "SELECT id, org_id, project_id, connector_kind, provider, status, "
            "endpoint_url, credential_ref, config_json FROM external_integrations "
            "WHERE id=? AND org_id=? AND connector_kind='ticketing' LIMIT 1",
            (integration_id, org_id),
        )
        if not rows:
            raise errors.NotFoundError("ticketing integration not found")
        row = dict(rows[0])
        if row.get("status") != "enabled":
            raise TicketingError("integration_disabled")
        provider = str(row.get("provider", "") or "")
        if provider not in self.adapters:
            raise TicketingError("provider_not_supported")
        return row

    def _adapter(self, row: Mapping[str, Any]) -> TicketingAdapter:
        provider = str(row.get("provider", "") or "")
        adapter = self.adapters.get(provider)
        if adapter is None:
            raise TicketingError("provider_not_supported")
        return adapter

    def _credentials(self, org_id: str, reference: str) -> dict[str, str]:
        if not reference or self.credential_resolver is None:
            raise TicketingError("credentials_unavailable")
        resolver = self.credential_resolver
        try:
            if callable(resolver):
                value = resolver(org_id, reference)
            else:
                value = resolver.resolve(org_id, reference)
        except Exception:
            raise TicketingError("credentials_unavailable") from None
        if not isinstance(value, Mapping):
            raise TicketingError("credentials_unavailable")
        result: dict[str, str] = {}
        for key in ("email", "api_token"):
            candidate = value.get(key)
            if not isinstance(candidate, str) or not candidate:
                raise TicketingError("invalid_credentials")
            result[key] = candidate
        return result

    def _finding(self, org_id: str, project_id: str, finding_id: str) -> dict[str, Any]:
        try:
            project = self.svc.project_require(project_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("finding not found") from None
        if project.org_id != org_id:
            raise errors.NotFoundError("finding not found")
        rows = self.db.query(
            "SELECT f.id, f.project_id, f.title, f.description, f.severity, "
            "f.lifecycle, f.remediation FROM findings f JOIN projects p "
            "ON p.id=f.project_id WHERE f.id=? AND f.project_id=? AND p.org_id=? LIMIT 1",
            (finding_id, project_id, org_id),
        )
        if not rows:
            raise errors.NotFoundError("finding not found")
        return dict(rows[0])

    @staticmethod
    def _config(row: Mapping[str, Any]) -> dict[str, Any]:
        try:
            value = json.loads(str(row.get("config_json", "") or "{}"))
        except (TypeError, ValueError):
            raise TicketingError("invalid_configuration") from None
        if not isinstance(value, dict):
            raise TicketingError("invalid_configuration")
        project_key = value.get("project_key")
        if not isinstance(project_key, str) or not _PROJECT_KEY_RE.fullmatch(project_key):
            raise TicketingError("invalid_configuration")
        issue_type = value.get("issue_type", "Task")
        if not isinstance(issue_type, str) or not 1 <= len(issue_type) <= 64:
            raise TicketingError("invalid_configuration")
        return {"project_key": project_key, "issue_type": issue_type}

    def upsert_finding(
        self,
        org_id: str,
        project_id: str,
        integration_id: str,
        finding_id: str,
    ) -> dict[str, str]:
        finding = self._finding(org_id, project_id, finding_id)
        row = self._connection(org_id, integration_id)
        scoped_project = str(row.get("project_id", "") or "")
        if scoped_project and scoped_project != project_id:
            raise errors.NotFoundError("ticketing integration not found")
        config = self._config(row)
        credentials = self._credentials(org_id, str(row.get("credential_ref", "") or ""))
        try:
            adapter = self._adapter(row)
            result = adapter.upsert_finding(
                site_url=str(row.get("endpoint_url", "") or ""),
                credentials=credentials,
                project_key=config["project_key"],
                issue_type=config["issue_type"],
                org_id=org_id,
                project_id=project_id,
                finding=finding,
            )
        except TicketingError:
            raise
        except Exception:
            raise TicketingError("provider_unavailable") from None
        finally:
            credentials.clear()
        self._audit_result(org_id, project_id, finding_id, integration_id, result)
        return result.to_dict()

    def close_finding(
        self,
        org_id: str,
        project_id: str,
        integration_id: str,
        finding_id: str,
    ) -> dict[str, str]:
        self._finding(org_id, project_id, finding_id)
        row = self._connection(org_id, integration_id)
        if row.get("project_id") and row["project_id"] != project_id:
            raise errors.NotFoundError("ticketing integration not found")
        config = self._config(row)
        credentials = self._credentials(org_id, str(row.get("credential_ref", "") or ""))
        try:
            result = self._adapter(row).close_finding(
                site_url=str(row.get("endpoint_url", "") or ""),
                credentials=credentials,
                project_key=config["project_key"],
                org_id=org_id,
                project_id=project_id,
                finding_id=finding_id,
            )
        except TicketingError:
            raise
        except Exception:
            raise TicketingError("provider_unavailable") from None
        finally:
            credentials.clear()
        self._audit_result(org_id, project_id, finding_id, integration_id, result)
        return result.to_dict()

    def link_findings(
        self,
        org_id: str,
        project_id: str,
        integration_id: str,
        finding_id: str,
        related_finding_id: str,
    ) -> dict[str, str]:
        self._finding(org_id, project_id, finding_id)
        self._finding(org_id, project_id, related_finding_id)
        row = self._connection(org_id, integration_id)
        if row.get("project_id") and row["project_id"] != project_id:
            raise errors.NotFoundError("ticketing integration not found")
        config = self._config(row)
        credentials = self._credentials(org_id, str(row.get("credential_ref", "") or ""))
        try:
            result = self._adapter(row).link_findings(
                site_url=str(row.get("endpoint_url", "") or ""),
                credentials=credentials,
                project_key=config["project_key"],
                org_id=org_id,
                project_id=project_id,
                finding_id=finding_id,
                related_finding_id=related_finding_id,
            )
        except TicketingError:
            raise
        except Exception:
            raise TicketingError("provider_unavailable") from None
        finally:
            credentials.clear()
        self._audit_result(org_id, project_id, finding_id, integration_id, result)
        return result.to_dict()

    def _audit_result(
        self,
        org_id: str,
        project_id: str,
        finding_id: str,
        integration_id: str,
        result: TicketingResult,
    ) -> None:
        action = {
            "created": "ticketing.issue.created",
            "updated": "ticketing.issue.updated",
            "closed": "ticketing.issue.closed",
            "linked": "ticketing.issue.linked",
        }.get(result.operation)
        if not action:
            raise TicketingError("response_invalid")
        self.svc.audit(
            action,
            object_type="finding",
            object_id=finding_id,
            org_id=org_id,
            project_id=project_id,
            actor="integration:" + integration_id[:128],
            metadata={
                "provider": result.provider,
                "external_key": result.key,
                "operation": result.operation,
            },
        )


__all__ = [
    "CredentialResolver",
    "JiraCloudAdapter",
    "TicketingAdapter",
    "TicketingError",
    "TicketingResult",
    "TicketingService",
]
