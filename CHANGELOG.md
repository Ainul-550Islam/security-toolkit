# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

* **Standard-library shadowing (`platform`).** `python/platform.py` shadowed
  the stdlib `platform` module for every process that put `python/` on
  `sys.path` — which every CLI entrypoint does. `platform.system()` raised
  `AttributeError: module 'platform' has no attribute 'system'`. The module is
  renamed to `python/platform_service.py` and all 26 import sites across 17
  files were updated. `python/platform.py` was **deleted** rather than kept as
  a compatibility shim, because a module at that path recreates the exact
  collision. Covered by
  `tests/test_foundation_runtime.py::FoundationPlatformCollisionRegressionTests`.
* **Configuration variable collision.** `SECTOOLKIT_SECRET_PROVIDER` shared the
  `SECTOOLKIT_SECRET_` prefix that `interfaces/secrets.py` reserves for secret
  *material*, so it would have been resolvable as a secret named `provider`.
  Renamed to `SECTOOLKIT_SECRETS_PROVIDER`, with a regression test.
* **Silently shadowed CLI command (`cmd_report`).** `main.py` defined
  `cmd_report` twice: a 3-line legacy definition (PDF from findings JSON,
  line 139) and a later 134-line Phase-6 definition (snapshot reports, line
  841). Python keeps the last one, so the documented command
  `python3 main.py report --json results.json` dispatched into the Phase-6
  function and died with
  `AttributeError: 'Namespace' object has no attribute 'action'` — the legacy
  subparser never defines `action`. The legacy function is renamed to
  `cmd_report_pdf` and its own subparser is pointed at it; the Phase-6
  `reporting` subcommand is unchanged. Both commands were re-run and exit 0.
  This was found by the new duplicate-definition baseline check, not by the
  test suite — there was no coverage of the `report` CLI path at all.
* **The new foundation suites were not actually running.** `tests/run_tests.py`
  builds its suite from an explicit list of star-imports, and a
  `python3 -m unittest discover` run does not execute the custom runner's
  integration cases. The five PART-01 modules were absent from the canonical
  run while green in isolation; they were added to its import list.
* **The custom runner also hid 34 existing tests.** Star-importing every module
  into one namespace overwrote duplicate `TestCase` names (`TestCliSmoke`,
  `TestPerformance`, `TestRbacPermissions`, `TestRetention`,
  `TestTenantIsolation`). `tests/run_tests.py` now loads all 17 modules
  independently through `load_tests` and then adds its 48 runner-local tests.
  The final custom run is **1181 OK**; standard discovery is **1133 OK** (it
  intentionally omits the 48 cases in `run_tests.py`).
* **Legacy dashboard exposure recorded.** The unchanged Phase 1–12 dashboard
  still defaults to `0.0.0.0` with optional, unset-by-default bearer auth.
  PART 01 documents this as a high-priority follow-up rather than changing
  legacy behavior under the preservation constraint.

### Added

* **`core/`** — foundation primitives: `version`, `constants`, `errors`,
  `result`, `ids`, `clock` (UTC-aware injectable clock; no `time.mktime()`),
  `paths` (traversal/escape-safe joining), `runtime`.
* **`config/`** — `settings` (validating, fail-closed, distinguishes
  unset/empty/invalid, never logs secrets), `logging` (structured JSON with
  automatic redaction of Authorization headers, bearer tokens, cookies,
  passwords, API keys, private keys and webhook secrets), `feature_flags`
  (deny-by-default, production-locked flags).
* **`interfaces/`** — language-neutral contracts: `engine`, `scanner`
  (defensive-only, rejects offensive registrations), `telemetry`, `storage`,
  `secrets` (interface only — no fake encryption, no custom crypto), `policy`
  (deny-by-default decisions).
* **`services/`** — `engine_registry` (Python/Rust/C++ engines with
  health, capabilities and execution mode; unbuilt engines are reported
  `unavailable` with a reason rather than hidden or faked), `health_service`
  (liveness vs readiness, dependency probes, no credential disclosure),
  `capability_service`.
* **`api/v1/`** — transport-agnostic `health` (`/livez`, `/readyz`,
  `/healthz`) and `metadata` (`/metadata`, `/version`, `/capabilities`,
  `/features`) handlers.
* **`schemas/`** — versioned JSON Schemas (draft 2020-12) for events,
  findings and health reports, with UTC-only timestamps and closed enums.
* **`native/rust/`** — zero-dependency `engine_core` crate with
  `#![forbid(unsafe_code)]`: bounded byte primitives, constant-time
  comparison, Shannon entropy, health vocabulary. 20 unit tests.
* **`native/cpp/`** — C++17 `security_engine` library using RAII and
  bounds-checked access, built with hardened flags. 42 self-test checks.
* **Tests** — `test_foundation_runtime.py` (33), `test_configuration.py` (36),
  `test_engine_registry.py` (38), `test_schemas.py` (46),
  `test_security_baseline.py` (39) — 192 tests total. The baseline module also
  gained an import-integrity check (every foundation import resolves, and the
  foundation never imports legacy `python/`) and a duplicate-definition check
  (which is what surfaced the `cmd_report` bug).
* **Lint and type gates** — the foundation is clean under `mypy --strict`
  (28 source files, no issues) and `ruff check` (all checks passed). Two rules
  are suppressed in place with a stated reason: `S105` on a provider *name* and
  `S104` on the all-interface literal inside the guard that rejects it. Legacy
  `python/` code is not lint-clean yet (880 findings, tracked as debt).
* **Project metadata** — `pyproject.toml` (mypy + ruff configuration),
  `requirements.txt` (empty by design), `requirements-dev.txt`,
  `.python-version`, `.gitignore`, `.env.example`, `SECURITY.md`,
  `CONTRIBUTING.md`, `docs/`.

### Notes

* Existing functionality was preserved. Historical runs reported 955 tests
  before PART 01 and 1147 after the five new modules were wired in; a later
  audit found that the star-import runner had silently shadowed 34 pre-existing
  tests. After fixing the loader, `python3 -m unittest discover -s tests -p
  'test_*.py' -v` reports **1133 tests, OK** (394.755s), and
  `python3 tests/run_tests.py` reports **1181 tests, OK** (436.566s): 1133
  module tests plus 48 runner-local integration tests. No assertions were
  weakened to obtain these totals. The final custom log contained 46 existing
  `ResourceWarning` instances (unclosed legacy/test resources), but no test
  failures.
