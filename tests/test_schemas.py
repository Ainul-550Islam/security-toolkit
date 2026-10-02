"""JSON schema and interface-contract tests.

Validates the schema documents themselves (well-formed, versioned, closed
enums, UTC timestamp patterns) AND that the Python dataclasses actually
produce documents matching the declared shape. A schema that has drifted from
its producer is worse than no schema, because consumers trust it.

TestCase names are globally unique (``tests/run_tests.py`` star-imports).
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCHEMA_DIR = REPO_ROOT / "schemas"

from core.clock import utcnow_iso  # noqa: E402
from core.constants import HEALTH_STATES, SEVERITIES  # noqa: E402
from core.errors import ValidationError  # noqa: E402
from interfaces.policy import (  # noqa: E402
    DenyAllPolicyEngine,
    PolicyRequest,
    allow,
    deny_by_default,
)
from interfaces.scanner import (  # noqa: E402
    Finding as ScannerFinding,
)
from interfaces.scanner import (  # noqa: E402
    ScanResult,
    ScanTarget,
    assert_defensive,
)
from interfaces.secrets import (  # noqa: E402
    EnvironmentSecretProvider,
    NullSecretProvider,
    SecretRef,
)
from interfaces.storage import InMemoryStore, KeyValueStore  # noqa: E402
from interfaces.telemetry import NullTelemetrySink, TelemetryEvent  # noqa: E402
from services.health_service import HealthService  # noqa: E402

UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


class SchemaDocumentTests(unittest.TestCase):
    """Every schema file is well-formed and properly versioned."""

    SCHEMA_FILES = ("event.schema.json", "finding.schema.json", "health.schema.json")

    def test_all_schema_files_exist_and_parse(self) -> None:
        for name in self.SCHEMA_FILES:
            with self.subTest(schema=name):
                path = SCHEMA_DIR / name
                self.assertTrue(path.exists(), f"missing schema {name}")
                self.assertIsInstance(_load(name), dict)

    def test_schemas_declare_draft_and_id_and_title(self) -> None:
        for name in self.SCHEMA_FILES:
            with self.subTest(schema=name):
                schema = _load(name)
                self.assertIn("2020-12", schema["$schema"])
                self.assertTrue(schema["$id"].startswith("https://"))
                self.assertIn("/v1/", schema["$id"], "schemas must be version-scoped")
                self.assertTrue(schema["title"])
                self.assertTrue(schema["description"])

    def test_schemas_are_closed_to_unknown_properties(self) -> None:
        for name in self.SCHEMA_FILES:
            with self.subTest(schema=name):
                self.assertFalse(_load(name)["additionalProperties"])

    def test_every_property_is_documented(self) -> None:
        for name in self.SCHEMA_FILES:
            schema = _load(name)
            for prop, definition in schema["properties"].items():
                with self.subTest(schema=name, prop=prop):
                    self.assertTrue(
                        definition.get("description") or definition.get("enum")
                        or definition.get("type"),
                        f"{name}:{prop} is undocumented",
                    )

    def test_timestamp_fields_require_utc_z(self) -> None:
        checks = [
            ("event.schema.json", "timestamp"),
            ("finding.schema.json", "detected_at"),
            ("health.schema.json", "checked_at"),
        ]
        for name, field in checks:
            with self.subTest(schema=name, field=field):
                definition = _load(name)["properties"][field]
                self.assertEqual(definition["format"], "date-time")
                self.assertTrue(definition["pattern"].endswith("Z$"))

    def test_no_schema_declares_a_credential_field(self) -> None:
        forbidden = ("password", "secret", "token", "api_key", "private_key",
                     "credential")
        for name in self.SCHEMA_FILES:
            for prop in _load(name)["properties"]:
                with self.subTest(schema=name, prop=prop):
                    self.assertFalse(
                        any(bad in prop.lower() for bad in forbidden),
                        f"{name} declares credential-shaped field {prop}",
                    )


class SchemaVocabularyAlignmentTests(unittest.TestCase):
    """Schema enums must match the Python constants and the native layers."""

    def test_severity_enum_matches_core_constants(self) -> None:
        for name, field in (
            ("event.schema.json", "severity"),
            ("finding.schema.json", "severity"),
        ):
            with self.subTest(schema=name):
                self.assertEqual(
                    tuple(_load(name)["properties"][field]["enum"]), SEVERITIES
                )

    def test_health_enum_matches_core_constants(self) -> None:
        schema = _load("health.schema.json")
        self.assertEqual(
            sorted(schema["properties"]["status"]["enum"]), sorted(HEALTH_STATES)
        )

    def test_schema_version_is_one_everywhere(self) -> None:
        from core.version import SCHEMA_VERSION

        self.assertEqual(SCHEMA_VERSION, "1")
        self.assertEqual(
            _load("event.schema.json")["properties"]["schema_version"]["enum"], ["1"]
        )

    def test_rust_and_cpp_declare_the_same_schema_version(self) -> None:
        rust = (REPO_ROOT / "native/rust/crates/engine_core/src/version.rs").read_text()
        cpp = (REPO_ROOT / "native/cpp/include/security_engine/version.hpp").read_text()
        self.assertIn('SCHEMA_VERSION: &str = "1"', rust)
        self.assertIn('kSchemaVersion = "1"', cpp)


class TelemetryEventContractTests(unittest.TestCase):
    def test_valid_event_matches_schema_shape(self) -> None:
        event = TelemetryEvent(event_type="engine.registered", source="services").validate()
        payload = event.to_dict()
        declared = set(_load("event.schema.json")["properties"])
        self.assertTrue(set(payload).issubset(declared),
                        f"unexpected keys: {set(payload) - declared}")
        for required in _load("event.schema.json")["required"]:
            self.assertIn(required, payload)

    def test_event_timestamp_is_utc(self) -> None:
        event = TelemetryEvent(event_type="a.b", source="s")
        self.assertRegex(event.timestamp, UTC_PATTERN)

    def test_event_id_matches_schema_pattern(self) -> None:
        pattern = _load("event.schema.json")["properties"]["event_id"]["pattern"]
        event = TelemetryEvent(event_type="a.b", source="s")
        self.assertRegex(event.event_id, re.compile(pattern))

    def test_event_type_matches_schema_pattern(self) -> None:
        pattern = _load("event.schema.json")["properties"]["event_type"]["pattern"]
        self.assertRegex("engine.registered", re.compile(pattern))

    def test_invalid_severity_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            TelemetryEvent(event_type="a.b", source="s", severity="apocalyptic").validate()

    def test_invalid_kind_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            TelemetryEvent(event_type="a.b", source="s", kind="gossip").validate()

    def test_credential_metadata_keys_are_rejected(self) -> None:
        for key in ("password", "api_key", "authorization", "PRIVATE_KEY", "cookie"):
            with self.subTest(key=key):
                with self.assertRaises(ValidationError):
                    TelemetryEvent(
                        event_type="a.b", source="s", metadata={key: "x"}
                    ).validate()

    def test_metadata_bounds_are_enforced(self) -> None:
        with self.assertRaises(ValidationError):
            TelemetryEvent(
                event_type="a.b", source="s",
                metadata={f"k{i}": "v" for i in range(100)},
            ).validate()

    def test_null_sink_counts_without_raising(self) -> None:
        sink = NullTelemetrySink()
        sink.emit(TelemetryEvent(event_type="a.b", source="s"))
        self.assertEqual(sink.count, 1)


class FindingContractTests(unittest.TestCase):
    def test_valid_finding_matches_schema_shape(self) -> None:
        finding = ScannerFinding(rule_id="CFG-001", title="Debug enabled").validate()
        declared = set(_load("finding.schema.json")["properties"])
        self.assertTrue(set(finding.to_dict()).issubset(declared))

    def test_rule_id_matches_schema_pattern(self) -> None:
        pattern = _load("finding.schema.json")["properties"]["rule_id"]["pattern"]
        self.assertRegex("CFG-001", re.compile(pattern))

    def test_invalid_severity_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ScannerFinding(rule_id="R", title="T", severity="spicy").validate()

    def test_empty_rule_id_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ScannerFinding(rule_id="", title="T").validate()

    def test_incomplete_scan_is_never_reported_as_clean(self) -> None:
        target = ScanTarget(kind="path", identifier="core/").validate()
        failed = ScanResult(scanner="s", target=target, completed=False,
                            failure_reason="permission denied")
        self.assertFalse(failed.clean)
        finished = ScanResult(scanner="s", target=target, completed=True)
        self.assertTrue(finished.clean)

    def test_offensive_scanner_registration_is_refused(self) -> None:
        from core.errors import SecurityViolation

        for name in ("exploit_runner", "bruteforce_ssh", "reverse_shell_helper"):
            with self.subTest(name=name):
                with self.assertRaises(SecurityViolation):
                    assert_defensive(name, "static_analysis")

    def test_defensive_scanner_names_are_accepted(self) -> None:
        for name in ("iac_config_audit", "dependency_sbom", "secret_detection"):
            assert_defensive(name, "static_analysis")

    def test_invalid_target_kind_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ScanTarget(kind="satellite", identifier="x").validate()


class HealthSchemaContractTests(unittest.TestCase):
    def test_health_report_matches_schema_shape(self) -> None:
        service = HealthService()
        service.register_dependency("database", lambda: True)
        report = service.full_report()
        declared = set(_load("health.schema.json")["properties"])
        self.assertTrue(set(report).issubset(declared),
                        f"unexpected keys: {set(report) - declared}")

    def test_dependency_entries_match_schema_shape(self) -> None:
        service = HealthService()
        service.register_dependency("database", lambda: True)
        declared = set(
            _load("health.schema.json")["properties"]["dependencies"]["items"]["properties"]
        )
        for dependency in service.full_report()["dependencies"]:
            self.assertTrue(set(dependency).issubset(declared))

    def test_checked_at_matches_schema_pattern(self) -> None:
        self.assertRegex(HealthService().liveness()["checked_at"], UTC_PATTERN)
        self.assertRegex(utcnow_iso(), UTC_PATTERN)


class SecretsInterfaceContractTests(unittest.TestCase):
    """The secrets interface must not leak and must not invent crypto."""

    def test_secret_value_repr_and_str_are_redacted(self) -> None:
        provider = EnvironmentSecretProvider(
            env={"SECTOOLKIT_SECRET_WEBHOOK": "super-secret-value"}
        )
        value = provider.get(SecretRef("webhook"))
        self.assertNotIn("super-secret-value", repr(value))
        self.assertNotIn("super-secret-value", str(value))
        self.assertIn("[REDACTED]", repr(value))
        self.assertEqual(value.reveal(), "super-secret-value")

    def test_secret_value_is_not_hashable(self) -> None:
        provider = EnvironmentSecretProvider(env={"SECTOOLKIT_SECRET_A": "v"})
        with self.assertRaises(TypeError):
            hash(provider.get(SecretRef("a")))

    def test_missing_and_empty_secrets_are_distinguished_and_both_raise(self) -> None:
        from core.errors import SecretError

        provider = EnvironmentSecretProvider(env={"SECTOOLKIT_SECRET_EMPTY": ""})
        with self.assertRaises(SecretError) as missing:
            provider.get(SecretRef("absent"))
        self.assertEqual(missing.exception.context["reason"], "unset")
        with self.assertRaises(SecretError) as empty:
            provider.get(SecretRef("empty"))
        self.assertEqual(empty.exception.context["reason"], "empty")

    def test_null_provider_fails_closed(self) -> None:
        from core.errors import SecretError

        self.assertFalse(NullSecretProvider().has(SecretRef("x")))
        with self.assertRaises(SecretError):
            NullSecretProvider().get(SecretRef("x"))

    def test_secret_ref_rejects_injection_characters(self) -> None:
        for bad in ("a b", "a;b", "a\nb", "a$b", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    SecretRef(bad).validate()

    def test_secret_ref_string_form_contains_no_material(self) -> None:
        self.assertEqual(str(SecretRef("webhook")), "env:webhook")

    def test_module_defines_no_custom_cryptography(self) -> None:
        """No hand-rolled crypto in the secrets interface.

        Inspected via the AST rather than raw text: the module docstring
        legitimately mentions XOR and base64 while explaining why they are
        NOT used, and a substring scan would flag that prose.
        """
        import ast

        tree = ast.parse((REPO_ROOT / "interfaces/secrets.py").read_text(encoding="utf-8"))

        banned_functions = {"encrypt", "decrypt", "obfuscate", "cipher", "xor_bytes"}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertNotIn(
                    node.name.lower(), banned_functions,
                    f"secrets interface must not implement {node.name}",
                )

        banned_imports = {"base64", "hashlib", "hmac", "cryptography", "Crypto"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name.split(".")[0], banned_imports)
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotIn(node.module.split(".")[0], banned_imports)


class PolicyInterfaceContractTests(unittest.TestCase):
    def test_default_decision_is_deny(self) -> None:
        self.assertFalse(deny_by_default().allowed)

    def test_deny_all_engine_denies_everything(self) -> None:
        request = PolicyRequest(subject="u", action="delete", resource="r").validate()
        self.assertFalse(DenyAllPolicyEngine().evaluate(request).allowed)

    def test_allow_requires_a_reason(self) -> None:
        with self.assertRaises(ValidationError):
            allow("")
        self.assertTrue(allow("explicitly granted by rule 7", "rule-7").allowed)

    def test_invalid_effect_is_rejected(self) -> None:
        from interfaces.policy import PolicyDecision

        with self.assertRaises(ValidationError):
            PolicyDecision(effect="maybe").validate()

    def test_empty_request_fields_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            PolicyRequest(subject="", action="read", resource="r").validate()


class StorageInterfaceContractTests(unittest.TestCase):
    def test_in_memory_store_satisfies_the_protocol(self) -> None:
        self.assertIsInstance(InMemoryStore(), KeyValueStore)

    def test_crud_round_trip(self) -> None:
        store = InMemoryStore()
        store.put("engines", "rust", {"status": "unavailable"})
        self.assertEqual(store.get("engines", "rust"), {"status": "unavailable"})
        self.assertTrue(store.delete("engines", "rust"))
        self.assertIsNone(store.get("engines", "rust"))

    def test_missing_key_returns_none_rather_than_raising(self) -> None:
        self.assertIsNone(InMemoryStore().get("nope", "nope"))

    def test_list_is_bounded(self) -> None:
        store = InMemoryStore()
        for index in range(50):
            store.put("c", str(index), {"i": index})
        self.assertEqual(len(store.list("c", limit=10)), 10)
        self.assertLessEqual(len(store.list("c", limit=99999)), 1000)


if __name__ == "__main__":
    unittest.main()
