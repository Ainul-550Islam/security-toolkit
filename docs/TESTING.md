# Testing

## Running the suite

```sh
# 1. Everything compiles
python3 -m compileall .

# 2. Foundation + legacy tests via unittest discovery
python3 -m unittest discover -s tests -p 'test_*.py'

# 3. The project's own runner
python3 tests/run_tests.py

# 4. Rust
cargo check --manifest-path native/rust/Cargo.toml
cargo test  --manifest-path native/rust/Cargo.toml

# 5. C++
cmake -S native/cpp -B native/cpp/build
cmake --build native/cpp/build
./native/cpp/build/security_engine_tests
```

No test requires network access, a running database, or credentials.

## Runner name-collision trap (fixed)

`tests/run_tests.py` retains star imports for legacy helper access, but its
`load_tests` hook now loads each test module separately, then adds only the
runner-local test classes. Duplicate `TestCase` names can no longer silently
shadow another module's tests. The audit found five repeated names that had
hidden 34 existing tests; all modules now run independently.

Keep new class names descriptive and preferably unique (for example,
`FoundationClockTests`, `SecurityBaselineArtifactHygieneTests`), but the custom
runner no longer relies on global uniqueness for correctness.

## Foundation test modules

| Module | Covers |
|---|---|
| `test_foundation_runtime.py` | stdlib `platform` collision regression, runtime info, clock, paths, ids, result |
| `test_configuration.py` | Settings validation, production fail-closed rules, log redaction, feature flags |
| `test_engine_registry.py` | Engine registration, honest unavailability, health service, API handlers |
| `test_schemas.py` | JSON schema documents, contract alignment, secrets/policy/storage interfaces |
| `test_security_baseline.py` | Repo-wide audit: import collisions, hard-coded secrets, dynamic execution, insecure defaults, artifact hygiene, type hints |

## What a good test asserts here

Not just the happy path. For security code the interesting assertions are:

* a secret does **not** appear in output (`assertNotIn("hunter2", ...)`);
* a traversal **raises** rather than returning a path;
* production **refuses** a weakened setting;
* a failed probe leaves the service **not ready**;
* an unavailable engine **raises** instead of returning an empty result;
* an exception message does not leak into a log or an API response.

## Regression discipline

The pre-PART-01 custom runner historically reported **955** tests, but a
follow-up audit found it was missing 34 existing module tests because duplicate
`TestCase` names were overwritten by star imports. Do not treat that historical
count as a complete module-suite baseline. Never weaken assertions to make a
test pass; fix the code or report the failure.

## Current exact results — 2026-10-03

* `python3 -m compileall -q api core config interfaces services python tests` —
  passed.
* `python3 tests/run_tests.py` — **1,279 tests ran; 0 failures, 0 errors** in
  498.504 seconds. The suite emits some non-fatal `ResourceWarning`s for
  existing test/legacy resources.
* Targeted test groups passed: API resources (13), product integrations (8),
  dashboard/security (106), cloud adapters (8), crypto (6), database
  migrations (5), and identity refresh (5).
* `cd web && npm ci --no-audit --no-fund` succeeded; `npm run typecheck`,
  `npm run lint`, `npm test` (**6 tests passed**), and `npm run build` passed.
* `cd web && npm audit --audit-level=high` reported **0 vulnerabilities**.

The custom runner loads modules independently to prevent star-import name
collisions. Its explicit list includes the API, cloud-adapter, crypto,
database-migration, identity-refresh, and integration test modules; add any
future module to both the imports and the `load_tests` list. No live cloud or
external ticketing provider call was made, and visual browser verification was
not performed.
