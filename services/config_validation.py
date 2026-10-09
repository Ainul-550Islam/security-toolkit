"""Fail-closed startup/runtime validation for security-sensitive settings.

Reports contain stable field names and reason codes only. Values are never
copied into errors, logs, or serialized validation results.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

_ENVIRONMENTS = frozenset({"development", "test", "staging", "production"})
_ALLOWED_PROVIDER_STATES = frozenset({
    "LIVE", "NOT_CONFIGURED", "UNAVAILABLE", "TIMEOUT", "RATE_LIMITED",
    "AUTHENTICATION_FAILED", "PERMISSION_DENIED", "ERROR",
})
_ALLOWED_FIELDS = frozenset({
    "environment", "debug", "auth_required", "tls_required",
    "database_configured", "database_tls_required", "database_tls_enabled",
    "migrations_current", "encryption_required", "key_management_state",
    "session_cookie_secure", "hsts_enabled", "public_base_url",
    "provider_states", "rate_limit_backend", "trusted_proxy_configured",
    "admin_token_configured",
})


@dataclass(frozen=True, slots=True)
class ConfigurationIssue:
    """Safe configuration finding without an offending value."""

    field: str
    code: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return {"field": self.field, "code": self.code, "severity": self.severity}


@dataclass(frozen=True, slots=True)
class ConfigurationValidationReport:
    """Immutable validation summary suitable for startup diagnostics."""

    environment: str
    valid: bool
    issues: tuple[ConfigurationIssue, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "valid": self.valid,
            "issues": [issue.to_dict() for issue in self.issues],
        }


class ConfigurationValidationError(Exception):
    """Safe startup failure carrying only reviewed issue codes."""

    def __init__(self, report: ConfigurationValidationReport) -> None:
        self.report = report
        self.codes = tuple(issue.code for issue in report.issues if issue.severity == "error")
        super().__init__("security_configuration_invalid")


class ConfigurationValidator:
    """Validate application settings without retaining secret values."""

    def validate(self, values: Mapping[str, Any]) -> ConfigurationValidationReport:
        if not isinstance(values, Mapping):
            raise TypeError("configuration values must be a mapping")
        issues: list[ConfigurationIssue] = []
        unknown = set(values) - _ALLOWED_FIELDS
        for field in sorted(unknown):
            safe_field = field if isinstance(field, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", field) else "configuration"
            issues.append(ConfigurationIssue(safe_field, "unknown_setting"))
        environment = str(values.get("environment", "development"))
        if environment not in _ENVIRONMENTS:
            issues.append(ConfigurationIssue("environment", "unsupported_environment"))
            environment = "invalid"
        production = environment == "production"

        def require_bool(field: str, *, expected: bool, code: str) -> None:
            raw = values.get(field, expected if production else False)
            if type(raw) is not bool or raw is not expected:
                issues.append(ConfigurationIssue(field, code))

        require_bool("auth_required", expected=True, code="authentication_must_be_enabled")
        require_bool("debug", expected=False, code="debug_must_be_disabled")
        if production:
            require_bool("tls_required", expected=True, code="tls_must_be_required")
            require_bool("database_configured", expected=True, code="database_must_be_configured")
            require_bool("migrations_current", expected=True, code="database_migrations_not_current")
            require_bool("encryption_required", expected=True, code="encryption_must_be_required")
            require_bool("session_cookie_secure", expected=True, code="secure_session_cookie_required")
            require_bool("hsts_enabled", expected=True, code="hsts_must_be_enabled")
            require_bool("admin_token_configured", expected=True, code="platform_admin_token_required")
            if values.get("key_management_state") != "CONFIGURED":
                issues.append(ConfigurationIssue("key_management_state", "encryption_key_unavailable"))
        else:
            for field in (
                "tls_required", "database_configured", "database_tls_required",
                "database_tls_enabled", "migrations_current", "encryption_required",
                "session_cookie_secure", "hsts_enabled", "trusted_proxy_configured",
                "admin_token_configured",
            ):
                if field in values and type(values[field]) is not bool:
                    issues.append(ConfigurationIssue(field, "boolean_setting_invalid"))
            if values.get("database_tls_required") is True and values.get("database_tls_enabled") is not True:
                issues.append(ConfigurationIssue("database_tls_enabled", "database_tls_required"))
            if values.get("encryption_required") is True and values.get("key_management_state") != "CONFIGURED":
                issues.append(ConfigurationIssue("key_management_state", "encryption_key_unavailable"))

        public_url = values.get("public_base_url")
        if public_url is not None:
            if not isinstance(public_url, str) or len(public_url) > 2048:
                issues.append(ConfigurationIssue("public_base_url", "public_url_invalid"))
            else:
                try:
                    parts = urlsplit(public_url)
                    valid_url = (
                        parts.scheme == "https"
                        and bool(parts.hostname)
                        and not parts.username
                        and not parts.password
                        and not parts.query
                        and not parts.fragment
                        and not any(ord(ch) < 32 for ch in public_url)
                    )
                except ValueError:
                    valid_url = False
                if not valid_url:
                    issues.append(ConfigurationIssue("public_base_url", "public_url_must_be_https_origin"))

        provider_states = values.get("provider_states", {})
        if not isinstance(provider_states, Mapping):
            issues.append(ConfigurationIssue("provider_states", "provider_state_invalid"))
        else:
            if len(provider_states) > 64:
                issues.append(ConfigurationIssue("provider_states", "provider_state_limit_exceeded"))
            for name, state in provider_states.items():
                if (
                    not isinstance(name, str)
                    or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", name)
                    or not isinstance(state, str)
                    or state not in _ALLOWED_PROVIDER_STATES
                ):
                    issues.append(ConfigurationIssue("provider_states", "provider_state_invalid"))
                    break

        backend = values.get("rate_limit_backend")
        if backend is not None:
            if not isinstance(backend, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,31}", backend):
                issues.append(ConfigurationIssue("rate_limit_backend", "rate_limit_backend_invalid"))
            elif production and backend == "LOCAL_PROCESS":
                issues.append(ConfigurationIssue("rate_limit_backend", "rate_limit_backend_not_shared", "warning"))

        error_count = sum(issue.severity == "error" for issue in issues)
        return ConfigurationValidationReport(
            environment=environment,
            valid=error_count == 0,
            issues=tuple(issues),
        )

    def validate_application(
        self,
        settings: Any,
        *,
        database_configured: bool,
        migrations_current: bool,
        key_management: Any = None,
        session_cookie_secure: bool | None = None,
        hsts_enabled: bool | None = None,
        admin_token_configured: bool | None = None,
        rate_limit_backend: str = "LOCAL_PROCESS",
    ) -> ConfigurationValidationReport:
        """Adapt a typed settings object and safe dependency statuses."""
        environment = str(getattr(settings, "environment", "development"))
        if key_management is None:
            key_state = "NOT_CONFIGURED"
        else:
            try:
                status = key_management.status()
                key_state = str(status.get("state", "NOT_CONFIGURED")) if isinstance(status, Mapping) else "NOT_CONFIGURED"
            except Exception:
                key_state = "UNAVAILABLE"
        tls_required = bool(getattr(settings, "tls_required", False))
        values = {
            "environment": environment,
            "debug": bool(getattr(settings, "debug", False)),
            "auth_required": bool(getattr(settings, "auth_required", False)),
            "tls_required": tls_required,
            "database_configured": bool(database_configured),
            "migrations_current": bool(migrations_current),
            "encryption_required": environment == "production",
            "key_management_state": key_state,
            "session_cookie_secure": tls_required if session_cookie_secure is None else bool(session_cookie_secure),
            "hsts_enabled": tls_required if hsts_enabled is None else bool(hsts_enabled),
            "admin_token_configured": (
                bool(admin_token_configured) if admin_token_configured is not None
                else bool(getattr(settings, "is_production", False))
            ),
            "rate_limit_backend": rate_limit_backend,
        }
        return self.validate(values)

    def require_valid(self, values: Mapping[str, Any]) -> ConfigurationValidationReport:
        """Return the report or raise a value-free startup exception."""
        report = self.validate(values)
        if not report.valid:
            raise ConfigurationValidationError(report)
        return report

    def require_application_valid(self, settings: Any, **dependencies: Any) -> ConfigurationValidationReport:
        report = self.validate_application(settings, **dependencies)
        if not report.valid:
            raise ConfigurationValidationError(report)
        return report


__all__ = [
    "ConfigurationIssue",
    "ConfigurationValidationError",
    "ConfigurationValidationReport",
    "ConfigurationValidator",
]
