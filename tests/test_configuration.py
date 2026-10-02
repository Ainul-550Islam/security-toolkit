"""Configuration, logging-redaction and feature-flag tests.

Focus: the security-relevant behaviour. Defaults must be restrictive,
production must refuse weakening, and no code path may write a secret to a
log record.

TestCase names are globally unique (``tests/run_tests.py`` star-imports).
"""

from __future__ import annotations

import io
import json
import logging
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from config import feature_flags  # noqa: E402
from config.logging import (  # noqa: E402
    JsonFormatter,
    RedactionFilter,
    configure_logging,
    is_sensitive_key,
    redact_mapping,
    redact_text,
)
from config.settings import (  # noqa: E402
    Settings,
    get_bool,
    get_int,
    get_str,
    load_settings,
)
from core.errors import ConfigurationError  # noqa: E402


class ConfigurationDefaultsTests(unittest.TestCase):
    """Defaults must be the safe ones."""

    def test_defaults_are_restrictive(self) -> None:
        settings = load_settings(env={})
        self.assertEqual(settings.bind_host, "127.0.0.1")
        self.assertTrue(settings.auth_required)
        self.assertTrue(settings.tls_required)
        self.assertFalse(settings.debug)
        self.assertFalse(settings.allow_insecure_bind)
        self.assertFalse(settings.enable_rust_engine)
        self.assertFalse(settings.enable_cpp_engine)
        self.assertEqual(settings.environment, "development")

    def test_default_bind_is_not_all_interfaces(self) -> None:
        self.assertNotIn(load_settings(env={}).bind_host, ("0.0.0.0", "::", "*"))


class ConfigurationProductionGuardTests(unittest.TestCase):
    """Production refuses insecure combinations rather than warning."""

    def _reason(self, env: dict[str, str]) -> str:
        with self.assertRaises(ConfigurationError) as caught:
            load_settings(env=env)
        return str(caught.exception.context.get("reason", ""))

    def test_debug_is_refused_in_production(self) -> None:
        self.assertEqual(
            self._reason({"SECTOOLKIT_ENV": "production", "SECTOOLKIT_DEBUG": "true"}),
            "debug_in_production",
        )

    def test_disabling_auth_is_refused_in_production(self) -> None:
        self.assertEqual(
            self._reason(
                {"SECTOOLKIT_ENV": "production", "SECTOOLKIT_AUTH_REQUIRED": "false"}
            ),
            "auth_disabled_in_production",
        )

    def test_disabling_tls_is_refused_in_production(self) -> None:
        self.assertEqual(
            self._reason(
                {"SECTOOLKIT_ENV": "production", "SECTOOLKIT_TLS_REQUIRED": "false"}
            ),
            "tls_disabled_in_production",
        )

    def test_binding_all_interfaces_is_refused_in_production(self) -> None:
        self.assertEqual(
            self._reason(
                {"SECTOOLKIT_ENV": "production", "SECTOOLKIT_BIND_HOST": "0.0.0.0"}
            ),
            "insecure_bind_production",
        )

    def test_binding_all_interfaces_needs_opt_in_outside_production(self) -> None:
        self.assertEqual(
            self._reason({"SECTOOLKIT_BIND_HOST": "0.0.0.0"}),
            "insecure_bind_not_allowed",
        )
        allowed = load_settings(
            env={
                "SECTOOLKIT_BIND_HOST": "0.0.0.0",
                "SECTOOLKIT_ALLOW_INSECURE_BIND": "true",
            }
        )
        self.assertEqual(allowed.bind_host, "0.0.0.0")

    def test_secure_production_configuration_is_accepted(self) -> None:
        settings = load_settings(
            env={"SECTOOLKIT_ENV": "production", "SECTOOLKIT_BIND_HOST": "127.0.0.1"}
        )
        self.assertTrue(settings.is_production)
        self.assertTrue(settings.auth_required)


class ConfigurationValueParsingTests(unittest.TestCase):
    """Unset, empty and invalid are three different things."""

    def test_unset_required_string_raises_unset(self) -> None:
        with self.assertRaises(ConfigurationError) as caught:
            get_str("X_MISSING", required=True, env={})
        self.assertEqual(caught.exception.context["reason"], "unset")

    def test_empty_string_is_not_treated_as_unset(self) -> None:
        with self.assertRaises(ConfigurationError) as caught:
            get_str("X_EMPTY", required=True, env={"X_EMPTY": ""})
        self.assertEqual(caught.exception.context["reason"], "empty")

    def test_empty_with_default_falls_back(self) -> None:
        self.assertEqual(get_str("X", default="d", env={"X": ""}), "d")

    def test_invalid_boolean_is_rejected_not_defaulted_to_false(self) -> None:
        with self.assertRaises(ConfigurationError) as caught:
            get_bool("X_BOOL", default=True, env={"X_BOOL": "maybe"})
        self.assertEqual(caught.exception.context["reason"], "invalid_bool")

    def test_boolean_spellings(self) -> None:
        for truthy in ("1", "true", "TRUE", "yes", "on", "enabled"):
            self.assertTrue(get_bool("B", default=False, env={"B": truthy}))
        for falsy in ("0", "false", "FALSE", "no", "off", "disabled"):
            self.assertFalse(get_bool("B", default=True, env={"B": falsy}))

    def test_integer_bounds_are_enforced(self) -> None:
        self.assertEqual(get_int("N", default=5, env={"N": "7"}), 7)
        with self.assertRaises(ConfigurationError):
            get_int("N", default=5, minimum=1, maximum=10, env={"N": "99"})
        with self.assertRaises(ConfigurationError):
            get_int("N", default=5, env={"N": "not-a-number"})

    def test_invalid_choice_message_excludes_the_value(self) -> None:
        with self.assertRaises(ConfigurationError) as caught:
            get_str("SECRETISH", choices=("a", "b"), env={"SECRETISH": "s3cr3t"})
        self.assertNotIn("s3cr3t", str(caught.exception))

    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_settings(env={"SECTOOLKIT_BIND_PORT": "70000"})


class ConfigurationRedactionOfSettingsTests(unittest.TestCase):
    """Settings must never render secret-looking fields."""

    def test_safe_dump_is_json_serialisable(self) -> None:
        json.dumps(load_settings(env={}).safe_dump())

    def test_repr_does_not_leak(self) -> None:
        text = repr(load_settings(env={}))
        self.assertIn("Settings(", text)
        self.assertNotIn("hunter2", text)

    def test_sensitive_field_names_are_redacted_by_name(self) -> None:
        from config.settings import is_sensitive_name

        for name in ("api_key", "db_password", "client_secret", "auth_token"):
            self.assertTrue(is_sensitive_name(name))
        for name in ("bind_host", "log_level", "environment"):
            self.assertFalse(is_sensitive_name(name))


class LoggingRedactionTests(unittest.TestCase):
    """Automatic redaction of secret material in logs."""

    def test_authorization_header_is_redacted(self) -> None:
        out = redact_text("Authorization: Bearer abcdef1234567890")
        self.assertNotIn("abcdef1234567890", out)
        self.assertIn("[REDACTED]", out)

    def test_bare_bearer_token_is_redacted(self) -> None:
        out = redact_text("sent with bearer abcdef1234567890 ok")
        self.assertNotIn("abcdef1234567890", out)

    def test_password_assignments_are_redacted(self) -> None:
        for text in (
            "password=hunter2",
            "db_password: hunter2",
            'api_key="hunter2"',
            "client_secret = hunter2",
        ):
            with self.subTest(text=text):
                self.assertNotIn("hunter2", redact_text(text))

    def test_cookies_are_redacted(self) -> None:
        self.assertNotIn("sessionid=abc", redact_text("Cookie: sessionid=abc123"))

    def test_private_keys_are_redacted(self) -> None:
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA1234567890\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertNotIn("MIIEowIBAAKCAQEA", redact_text(pem))

    def test_known_token_formats_are_redacted(self) -> None:
        for token in (
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "xoxb-1234567890-abcdefghij",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcd",
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, redact_text(f"value {token} end"))

    def test_sensitive_keys_are_detected(self) -> None:
        for key in ("Authorization", "api-key", "X_API_KEY", "webhook_secret"):
            self.assertTrue(is_sensitive_key(key))
        for key in ("bind_host", "count", "status"):
            self.assertFalse(is_sensitive_key(key))

    def test_nested_mapping_is_redacted(self) -> None:
        redacted = redact_mapping(
            {"outer": {"password": "hunter2", "safe": "value"}, "token": "abc"}
        )
        self.assertEqual(redacted["outer"]["password"], "[REDACTED]")
        self.assertEqual(redacted["outer"]["safe"], "value")
        self.assertEqual(redacted["token"], "[REDACTED]")

    def test_non_sensitive_text_is_preserved(self) -> None:
        self.assertEqual(redact_text("scan completed with 3 findings"),
                         "scan completed with 3 findings")

    def test_handler_redacts_end_to_end(self) -> None:
        stream = io.StringIO()
        logger = configure_logging(level="INFO", fmt="json", stream=stream)
        logger.info("login for user=bob password=hunter2")
        logger.info("context", extra={"api_key": "sk_live_abcdefghijklmn"})
        output = stream.getvalue()
        self.assertNotIn("hunter2", output)
        self.assertNotIn("sk_live_abcdefghijklmn", output)
        self.assertIn("[REDACTED]", output)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)

    def test_json_formatter_emits_utc_and_required_fields(self) -> None:
        record = logging.LogRecord(
            name="security_toolkit.test", level=logging.INFO,
            pathname=__file__, lineno=1, msg="hello", args=(), exc_info=None,
        )
        RedactionFilter().filter(record)
        payload = json.loads(JsonFormatter().format(record))
        self.assertTrue(payload["ts"].endswith("Z"))
        self.assertEqual(payload["level"], "INFO")
        self.assertEqual(payload["message"], "hello")

    def test_exception_records_expose_type_only(self) -> None:
        stream = io.StringIO()
        logger = configure_logging(level="INFO", fmt="json", stream=stream)
        try:
            raise ValueError("password=hunter2")
        except ValueError:
            logger.exception("operation failed")
        output = stream.getvalue()
        self.assertNotIn("hunter2", output)
        self.assertIn("ValueError", output)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)


class FeatureFlagTests(unittest.TestCase):
    """Deny-by-default flag resolution."""

    def test_unknown_flag_is_disabled(self) -> None:
        self.assertFalse(feature_flags.is_enabled("does_not_exist", env={}))

    def test_security_flags_default_off(self) -> None:
        flags = feature_flags.all_flags(environment="development", env={})
        self.assertFalse(flags["experimental_api"])
        self.assertFalse(flags["verbose_errors"])
        self.assertFalse(flags["rust_engine"])
        self.assertFalse(flags["cpp_engine"])

    def test_production_locked_flags_cannot_be_enabled_by_env(self) -> None:
        env = {
            "SECTOOLKIT_FEATURE_VERBOSE_ERRORS": "true",
            "SECTOOLKIT_FEATURE_EXPERIMENTAL_API": "true",
        }
        self.assertFalse(
            feature_flags.is_enabled("verbose_errors", environment="production", env=env)
        )
        self.assertFalse(
            feature_flags.is_enabled("experimental_api", environment="production", env=env)
        )
        # ...but are honoured in development.
        self.assertTrue(
            feature_flags.is_enabled("verbose_errors", environment="development", env=env)
        )

    def test_invalid_flag_value_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            feature_flags.is_enabled(
                "rust_engine", env={"SECTOOLKIT_FEATURE_RUST_ENGINE": "perhaps"}
            )

    def test_describe_flags_documents_every_flag(self) -> None:
        described = feature_flags.describe_flags()
        self.assertEqual(len(described), len(feature_flags.FLAGS))
        for entry in described:
            self.assertTrue(entry["description"])
            self.assertTrue(entry["env_var"].startswith("SECTOOLKIT_FEATURE_"))


if __name__ == "__main__":
    unittest.main()
