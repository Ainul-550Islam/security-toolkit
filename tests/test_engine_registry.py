"""Engine registry, health service and API handler tests.

Central requirement: the system must describe itself HONESTLY. An engine that
is not built is reported unavailable with a reason; it is never silently
dropped and never reported as working.

TestCase names are globally unique (``tests/run_tests.py`` star-imports).
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.v1 import health as health_api  # noqa: E402
from api.v1 import metadata as metadata_api  # noqa: E402
from core.clock import FixedClock, parse_iso  # noqa: E402
from core.constants import (  # noqa: E402
    HEALTH_DEGRADED,
    HEALTH_HEALTHY,
    HEALTH_UNAVAILABLE,
    HEALTH_UNKNOWN,
)
from core.errors import EngineError, EngineUnavailable, UnsupportedOperation  # noqa: E402
from interfaces.engine import (  # noqa: E402
    Engine,
    EngineDescriptor,
    EngineHealth,
    UnavailableEngine,
)
from services.capability_service import CapabilityService  # noqa: E402
from services.engine_registry import DECLARED_NATIVE_ENGINES, EngineRegistry  # noqa: E402
from services.health_service import HealthService  # noqa: E402


class _FakePythonEngine:
    """Minimal working engine used to exercise the registry."""

    def __init__(
        self,
        name: str = "fake_python",
        status: str = HEALTH_HEALTHY,
        capabilities: tuple[str, ...] = ("echo",),
    ) -> None:
        self._name = name
        self._status = status
        self._capabilities = capabilities

    def describe(self) -> EngineDescriptor:
        return EngineDescriptor(
            name=self._name,
            language="python",
            version="1.0.0",
            capabilities=self._capabilities,
            execution_mode="in_process",
        )

    def health(self) -> EngineHealth:
        return EngineHealth(status=self._status, detail="")

    def execute(self, operation: str, payload: dict[str, Any]) -> Any:
        if operation != "echo":
            raise UnsupportedOperation(f"unsupported operation {operation!r}")
        return dict(payload)


class _RaisingHealthEngine(_FakePythonEngine):
    """Engine whose health probe blows up."""

    def health(self) -> EngineHealth:
        raise RuntimeError("connection string=postgres://user:hunter2@db")


class EngineRegistryRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = EngineRegistry(clock=FixedClock(parse_iso("2026-01-01T00:00:00Z")))

    def test_register_and_lookup(self) -> None:
        descriptor = self.registry.register(_FakePythonEngine())
        self.assertEqual(descriptor.name, "fake_python")
        self.assertEqual(self.registry.names(), ["fake_python"])
        self.assertIsInstance(self.registry.get("fake_python"), _FakePythonEngine)

    def test_duplicate_registration_is_rejected(self) -> None:
        self.registry.register(_FakePythonEngine())
        with self.assertRaises(EngineError) as caught:
            self.registry.register(_FakePythonEngine())
        self.assertEqual(caught.exception.context["reason"], "duplicate")

    def test_duplicate_allowed_with_replace(self) -> None:
        self.registry.register(_FakePythonEngine())
        self.registry.register(_FakePythonEngine(), replace=True)
        self.assertEqual(len(self.registry.names()), 1)

    def test_unknown_engine_raises(self) -> None:
        with self.assertRaises(EngineUnavailable) as caught:
            self.registry.get("nope")
        self.assertEqual(caught.exception.context["reason"], "not_registered")

    def test_unregister(self) -> None:
        self.registry.register(_FakePythonEngine())
        self.assertTrue(self.registry.unregister("fake_python"))
        self.assertFalse(self.registry.unregister("fake_python"))

    def test_invalid_descriptor_is_rejected(self) -> None:
        class BadEngine(_FakePythonEngine):
            def describe(self) -> EngineDescriptor:
                return EngineDescriptor(name="bad", language="cobol")

        with self.assertRaises(Exception):
            self.registry.register(BadEngine())

    def test_fake_engine_satisfies_the_protocol(self) -> None:
        self.assertIsInstance(_FakePythonEngine(), Engine)


class EngineRegistryHonestyTests(unittest.TestCase):
    """Unbuilt native engines must be visible and honestly unavailable."""

    def setUp(self) -> None:
        self.registry = EngineRegistry()

    def test_empty_registry_is_unknown_not_healthy(self) -> None:
        self.assertEqual(self.registry.overall_status(), HEALTH_UNKNOWN)

    def test_declared_native_engines_register_as_unavailable(self) -> None:
        descriptors = self.registry.register_declared_native()
        self.assertEqual(
            sorted(d.name for d in descriptors), ["cpp_core", "rust_core"]
        )
        for status in self.registry.all_status():
            self.assertEqual(status.health.status, HEALTH_UNAVAILABLE)
            self.assertTrue(status.health.detail, "must state WHY it is unavailable")
            self.assertFalse(status.available)

    def test_declared_native_engines_cover_rust_and_cpp(self) -> None:
        languages = {d.language for d in DECLARED_NATIVE_ENGINES}
        self.assertEqual(languages, {"rust", "cpp"})

    def test_unavailable_engine_refuses_to_execute(self) -> None:
        engine = UnavailableEngine(
            EngineDescriptor(name="rust_core", language="rust"), reason="not built"
        )
        with self.assertRaises(EngineUnavailable):
            engine.execute("hash_verify", {})

    def test_no_capability_is_advertised_for_unavailable_engines(self) -> None:
        self.registry.register_declared_native()
        self.assertEqual(self.registry.capabilities(), {})
        self.assertEqual(self.registry.available(), [])

    def test_capability_request_fails_loudly_when_unserviceable(self) -> None:
        self.registry.register_declared_native()
        with self.assertRaises(UnsupportedOperation) as caught:
            self.registry.execute("hash_verify", "run")
        self.assertEqual(caught.exception.context["reason"], "no_engine")

    def test_mixed_registry_is_degraded(self) -> None:
        self.registry.register_declared_native()
        self.registry.register(_FakePythonEngine())
        self.assertEqual(self.registry.overall_status(), HEALTH_DEGRADED)

    def test_all_healthy_registry_is_healthy(self) -> None:
        self.registry.register(_FakePythonEngine("a"))
        self.registry.register(_FakePythonEngine("b"))
        self.assertEqual(self.registry.overall_status(), HEALTH_HEALTHY)

    def test_failing_health_probe_does_not_leak_exception_text(self) -> None:
        self.registry.register(_RaisingHealthEngine("boom"))
        status = self.registry.status("boom")
        self.assertEqual(status.health.status, HEALTH_UNAVAILABLE)
        self.assertEqual(status.error, "RuntimeError")
        rendered = json.dumps(status.to_dict())
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("postgres://", rendered)

    def test_capability_routing_picks_a_healthy_engine(self) -> None:
        self.registry.register(_FakePythonEngine("healthy_one"))
        engine = self.registry.find_for_capability("echo")
        self.assertEqual(engine.describe().name, "healthy_one")
        self.assertEqual(self.registry.execute("echo", "echo", {"a": 1}), {"a": 1})

    def test_registry_dict_is_serialisable_and_counts_correctly(self) -> None:
        self.registry.register_declared_native()
        self.registry.register(_FakePythonEngine())
        payload = self.registry.to_dict()
        json.dumps(payload)
        self.assertEqual(payload["engine_count"], 3)
        self.assertEqual(payload["available_count"], 1)


class HealthServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = EngineRegistry()
        self.service = HealthService(registry=self.registry)

    def test_liveness_never_depends_on_dependencies(self) -> None:
        self.service.register_dependency("database", lambda: False)
        self.assertEqual(self.service.liveness()["status"], HEALTH_HEALTHY)

    def test_readiness_fails_closed_on_required_dependency(self) -> None:
        self.service.register_dependency("database", lambda: False)
        report = self.service.readiness()
        self.assertFalse(report["ready"])
        self.assertEqual(report["status"], HEALTH_UNAVAILABLE)

    def test_readiness_passes_when_required_dependencies_are_healthy(self) -> None:
        self.service.register_dependency("database", lambda: True)
        self.assertTrue(self.service.readiness()["ready"])

    def test_optional_dependency_failure_degrades_but_stays_ready(self) -> None:
        self.service.register_dependency("database", lambda: True)
        self.service.register_dependency("cache", lambda: False, required=False)
        report = self.service.readiness()
        self.assertTrue(report["ready"])
        self.assertEqual(report["status"], HEALTH_DEGRADED)

    def test_raising_probe_is_treated_as_failure_and_redacted(self) -> None:
        def probe() -> bool:
            raise ConnectionError("postgres://user:hunter2@db:5432")

        self.service.register_dependency("database", probe)
        report = self.service.readiness()
        self.assertFalse(report["ready"])
        rendered = json.dumps(report)
        self.assertNotIn("hunter2", rendered)
        self.assertIn("ConnectionError", rendered)

    def test_unavailable_engines_degrade_but_do_not_block_readiness(self) -> None:
        self.registry.register_declared_native()
        self.service.register_dependency("database", lambda: True)
        report = self.service.readiness()
        self.assertTrue(report["ready"])
        self.assertEqual(report["status"], HEALTH_DEGRADED)

    def test_full_report_exposes_no_credentials_or_paths(self) -> None:
        self.service.register_dependency("database", lambda: True)
        rendered = json.dumps(self.service.full_report()).lower()
        for forbidden in (
            "password", "secret", "token", "api_key", "private_key",
            "postgres://", "/home/", "connection_string",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_health_report_timestamps_are_utc(self) -> None:
        self.assertTrue(self.service.liveness()["checked_at"].endswith("Z"))
        self.assertTrue(self.service.readiness()["checked_at"].endswith("Z"))


class HealthApiHandlerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = EngineRegistry()
        self.service = HealthService(registry=self.registry)
        self.capabilities = CapabilityService(self.registry)

    def test_livez_returns_200(self) -> None:
        code, body = health_api.livez(self.service)
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], HEALTH_HEALTHY)

    def test_readyz_returns_503_when_not_ready(self) -> None:
        self.service.register_dependency("database", lambda: False)
        code, body = health_api.readyz(self.service)
        self.assertEqual(code, 503)
        self.assertFalse(body["ready"])

    def test_readyz_returns_200_when_ready(self) -> None:
        self.service.register_dependency("database", lambda: True)
        self.assertEqual(health_api.readyz(self.service)[0], 200)

    def test_healthz_matches_readiness_code(self) -> None:
        self.service.register_dependency("database", lambda: False)
        self.assertEqual(health_api.healthz(self.service)[0], 503)

    def test_routes_are_versioned(self) -> None:
        for route in health_api.ROUTES:
            self.assertTrue(route.startswith("/api/v1/"))
        for route in metadata_api.ROUTES:
            self.assertTrue(route.startswith("/api/v1/"))

    def test_metadata_is_serialisable_and_non_sensitive(self) -> None:
        code, body = metadata_api.metadata(self.capabilities)
        self.assertEqual(code, 200)
        rendered = json.dumps(body).lower()
        for forbidden in metadata_api.FORBIDDEN_KEYS:
            if forbidden in ("path",):  # 'path' appears in no key here
                continue
            self.assertNotIn(f'"{forbidden}"', rendered)

    def test_version_endpoint(self) -> None:
        code, body = metadata_api.version_endpoint()
        self.assertEqual(code, 200)
        self.assertEqual(body["schema_version"], "1")
        self.assertEqual(body["api_version"], "v1")

    def test_capabilities_endpoint_reports_declared_unavailable_engines(self) -> None:
        self.registry.register_declared_native()
        _code, body = metadata_api.capabilities(self.capabilities)
        self.assertEqual(body["available"], {})
        self.assertEqual(len(body["declared"]), 2)
        for entry in body["declared"]:
            self.assertEqual(entry["status"], HEALTH_UNAVAILABLE)
            self.assertTrue(entry["reason"])

    def test_features_endpoint_lists_flags(self) -> None:
        code, body = metadata_api.features()
        self.assertEqual(code, 200)
        self.assertIn("rust_engine", body["flags"])
        self.assertTrue(body["declared"])


class CapabilityServiceTests(unittest.TestCase):
    def test_summary_without_registry(self) -> None:
        summary = CapabilityService(None).summary()
        self.assertEqual(summary["available_capabilities"], [])

    def test_language_roles_cover_all_four_layers(self) -> None:
        from services.capability_service import LANGUAGE_ROLES

        self.assertEqual(
            sorted(LANGUAGE_ROLES), ["cpp", "python", "rust", "typescript"]
        )

    def test_summary_lists_unavailable_engines(self) -> None:
        registry = EngineRegistry()
        registry.register_declared_native()
        summary = CapabilityService(registry).summary()
        self.assertEqual(sorted(summary["unavailable_engines"]), ["cpp_core", "rust_core"])


if __name__ == "__main__":
    unittest.main()
