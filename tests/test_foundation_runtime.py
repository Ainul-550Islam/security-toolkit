"""Foundation runtime tests.

The headline case is the ``platform`` collision regression: this module proves
that the standard library's :mod:`platform` and the project's
``platform_service`` coexist, with ``python/`` on ``sys.path`` exactly as every
CLI entrypoint arranges it.

TestCase names are globally unique because ``tests/run_tests.py`` star-imports
every module into one namespace.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PY_DIR = REPO_ROOT / "python"

for _p in (str(REPO_ROOT), str(PY_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import platform as stdlib_platform  # noqa: E402  (after sys.path setup, deliberately)

from core import clock as core_clock  # noqa: E402
from core import ids as core_ids  # noqa: E402
from core import paths as core_paths  # noqa: E402
from core import runtime as core_runtime  # noqa: E402
from core import version as core_version  # noqa: E402
from core.errors import SecurityViolation, ValidationError  # noqa: E402
from core.result import Err, Ok  # noqa: E402


class FoundationPlatformCollisionRegressionTests(unittest.TestCase):
    """The exact defect PART 01 was asked to fix must not return."""

    def test_stdlib_platform_resolves_to_the_standard_library(self) -> None:
        # python/ IS on sys.path here (see module header), which is the
        # condition under which the old python/platform.py shadowed stdlib.
        self.assertIn(str(PY_DIR), sys.path)
        module_file = getattr(stdlib_platform, "__file__", "") or ""
        self.assertNotIn(
            os.sep + "python" + os.sep + "platform.py",
            module_file,
            "stdlib 'platform' is being shadowed by a project module",
        )
        self.assertTrue(
            module_file.endswith("platform.py"),
            f"unexpected platform module location: {module_file}",
        )

    def test_stdlib_platform_api_is_callable(self) -> None:
        # platform.system() raised AttributeError before the rename.
        self.assertTrue(stdlib_platform.system())
        self.assertTrue(stdlib_platform.python_version())
        self.assertTrue(stdlib_platform.machine())

    def test_stdlib_platform_has_no_project_symbols(self) -> None:
        for symbol in ("PlatformService", "maybe_register_scan_result"):
            self.assertFalse(
                hasattr(stdlib_platform, symbol),
                f"stdlib platform unexpectedly exposes {symbol}",
            )

    def test_project_platform_service_is_importable_under_its_new_name(self) -> None:
        import platform_service

        self.assertTrue(hasattr(platform_service, "PlatformService"))
        service_file = getattr(platform_service, "__file__", "") or ""
        self.assertTrue(service_file.endswith("platform_service.py"))

    def test_the_colliding_module_file_no_longer_exists(self) -> None:
        # A backward-compat shim at this path would recreate the collision.
        self.assertFalse(
            (PY_DIR / "platform.py").exists(),
            "python/platform.py must not be recreated; it shadows the stdlib",
        )

    def test_both_modules_are_usable_in_the_same_process(self) -> None:
        import platform_service

        self.assertIsNot(stdlib_platform, platform_service)
        self.assertTrue(stdlib_platform.system())
        self.assertTrue(callable(platform_service.PlatformService))

    def test_subprocess_with_python_dir_first_on_path_sees_stdlib(self) -> None:
        """End-to-end check in a clean interpreter, not just this process."""
        code = (
            "import sys; sys.path.insert(0, %r);"
            "import platform;"
            "print(platform.system());"
            "print('PlatformService' in dir(platform))" % str(PY_DIR)
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=60, cwd=str(REPO_ROOT),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.strip().splitlines()
        self.assertTrue(lines[0])
        self.assertEqual(lines[1], "False")


class FoundationRuntimeInfoTests(unittest.TestCase):
    """core.runtime reports correct, non-sensitive facts."""

    def test_runtime_info_fields(self) -> None:
        info = core_runtime.runtime_info()
        for key in ("python_version", "os", "machine", "environment", "app_version"):
            self.assertIn(key, info)
        self.assertTrue(info["python_supported"])

    def test_runtime_info_excludes_host_identifying_data(self) -> None:
        info = core_runtime.runtime_info()
        for forbidden in ("hostname", "user", "username", "cwd", "executable", "path"):
            self.assertNotIn(forbidden, info)

    def test_unknown_environment_never_selects_production(self) -> None:
        original = os.environ.get(core_runtime.ENV_VAR)
        try:
            os.environ[core_runtime.ENV_VAR] = "prodction"  # typo on purpose
            self.assertNotEqual(core_runtime.current_environment(), "production")
            self.assertFalse(core_runtime.is_production())
        finally:
            if original is None:
                os.environ.pop(core_runtime.ENV_VAR, None)
            else:
                os.environ[core_runtime.ENV_VAR] = original

    def test_version_constants(self) -> None:
        self.assertEqual(core_version.SCHEMA_VERSION, "1")
        self.assertEqual(core_version.API_VERSION, "v1")
        self.assertGreaterEqual(core_version.MIN_PYTHON, (3, 11))


class FoundationClockTests(unittest.TestCase):
    """UTC-aware injectable clock."""

    def test_system_clock_is_timezone_aware_utc(self) -> None:
        now = core_clock.SystemClock().now()
        self.assertIsNotNone(now.tzinfo)
        self.assertEqual(now.utcoffset().total_seconds(), 0.0)

    def test_iso_output_ends_with_z(self) -> None:
        self.assertTrue(core_clock.utcnow_iso().endswith("Z"))

    def test_naive_datetime_is_rejected(self) -> None:
        from datetime import datetime

        with self.assertRaises(Exception):
            core_clock.ensure_utc(datetime(2026, 1, 1, 12, 0, 0))

    def test_parse_iso_rejects_timezone_less_input(self) -> None:
        with self.assertRaises(Exception):
            core_clock.parse_iso("2026-01-01T12:00:00")

    def test_parse_iso_round_trip(self) -> None:
        parsed = core_clock.parse_iso("2026-01-01T12:00:00Z")
        self.assertEqual(core_clock.to_iso(parsed), "2026-01-01T12:00:00Z")

    def test_fixed_clock_is_deterministic_and_advances(self) -> None:
        fixed = core_clock.FixedClock(core_clock.parse_iso("2026-01-01T00:00:00Z"))
        self.assertEqual(fixed.now(), fixed.now())
        fixed.advance(60)
        self.assertEqual(core_clock.to_iso(fixed.now()), "2026-01-01T00:01:00Z")

    def test_expiry_uses_utc_and_fails_closed(self) -> None:
        past = core_clock.parse_iso("2020-01-01T00:00:00Z")
        future = core_clock.parse_iso("2099-01-01T00:00:00Z")
        self.assertTrue(core_clock.is_expired(past))
        self.assertFalse(core_clock.is_expired(future))

    def test_to_epoch_is_utc_not_local(self) -> None:
        # time.mktime() would interpret this as local time; the epoch value
        # for midnight UTC 1970-01-02 is exactly 86400.
        self.assertEqual(
            core_clock.to_epoch(core_clock.parse_iso("1970-01-02T00:00:00Z")),
            86400.0,
        )


class FoundationPathSafetyTests(unittest.TestCase):
    """Path traversal and escape defences."""

    def test_normal_join_is_allowed(self) -> None:
        joined = core_paths.safe_join(REPO_ROOT, "core", "clock.py")
        self.assertTrue(str(joined).endswith(os.path.join("core", "clock.py")))

    def test_traversal_is_rejected(self) -> None:
        for bad in ("..", "../etc/passwd", "a/../../b", "..\\windows"):
            with self.subTest(bad=bad):
                with self.assertRaises(SecurityViolation):
                    core_paths.safe_join(REPO_ROOT, bad)

    def test_absolute_component_is_rejected(self) -> None:
        for bad in ("/etc/passwd", "/tmp/x"):
            with self.subTest(bad=bad):
                with self.assertRaises(SecurityViolation):
                    core_paths.safe_join(REPO_ROOT, bad)

    def test_control_characters_are_rejected(self) -> None:
        for bad in ("report\x00.png", "a\nb", "a\tb"):
            with self.subTest(bad=bad):
                with self.assertRaises(SecurityViolation):
                    core_paths.safe_join(REPO_ROOT, bad)

    def test_is_within_detects_escape(self) -> None:
        self.assertTrue(core_paths.is_within(REPO_ROOT / "core", REPO_ROOT))
        self.assertFalse(core_paths.is_within("/etc", REPO_ROOT))

    def test_safe_filename_strips_directories(self) -> None:
        self.assertEqual(core_paths.safe_filename("../../etc/passwd"), "passwd")
        self.assertEqual(core_paths.safe_filename("/abs/report.pdf"), "report.pdf")
        self.assertEqual(core_paths.safe_filename(".."), "unnamed")
        self.assertNotIn("/", core_paths.safe_filename("a/b/c.txt"))


class FoundationIdentifierTests(unittest.TestCase):
    """Identifier generation and comparison."""

    def test_ids_are_unique(self) -> None:
        self.assertEqual(len({core_ids.new_id() for _ in range(500)}), 500)

    def test_stable_id_is_deterministic(self) -> None:
        first = core_ids.stable_id(core_ids.NS_ENGINE, "rust_core")
        second = core_ids.stable_id(core_ids.NS_ENGINE, "rust_core")
        self.assertEqual(first, second)
        self.assertNotEqual(first, core_ids.stable_id(core_ids.NS_ENGINE, "cpp_core"))

    def test_correlation_id_sanitisation_strips_injection(self) -> None:
        cleaned = core_ids.sanitize_correlation_id("abc\r\nInjected: header")
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\r", cleaned)

    def test_constant_time_equals(self) -> None:
        self.assertTrue(core_ids.constant_time_equals("abc", "abc"))
        self.assertFalse(core_ids.constant_time_equals("abc", "abd"))
        self.assertFalse(core_ids.constant_time_equals("abc", "ab"))


class FoundationResultTests(unittest.TestCase):
    """Ok/Err result type."""

    def test_ok_and_err_basics(self) -> None:
        self.assertTrue(Ok(1).is_ok)
        self.assertFalse(Ok(1).is_err)
        self.assertEqual(Ok(5).unwrap(), 5)

        err = Err("internal_error", "boom")
        self.assertFalse(err.is_ok)
        self.assertTrue(err.is_err)
        self.assertEqual(err.unwrap_or(7), 7)
        with self.assertRaises(Exception):
            err.unwrap()

    def test_map_applies_only_on_ok(self) -> None:
        self.assertEqual(Ok(2).map(lambda v: v * 3).unwrap(), 6)
        err = Err("internal_error", "boom")
        self.assertTrue(err.map(lambda v: v * 3).is_err)

    def test_to_dict_shape(self) -> None:
        self.assertEqual(Ok("v").to_dict(), {"ok": True, "value": "v"})
        payload = Err("bad_input", "nope").to_dict()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "bad_input")

    def test_err_from_exception_leaks_only_the_type(self) -> None:
        err = Err.from_exception(ValueError("password=hunter2"))
        rendered = str(err.to_dict())
        self.assertNotIn("hunter2", rendered)
        self.assertIn("ValueError", rendered)


if __name__ == "__main__":
    unittest.main()
