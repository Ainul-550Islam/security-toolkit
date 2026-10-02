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

Current exact results:

* `python3 -m unittest discover -s tests -p 'test_*.py' -v` — **1133 tests,
  OK** (394.755s). This discovers the 17 `test_*.py` modules.
* `python3 tests/run_tests.py` — **1181 tests, OK** (436.566s): the same 1133
  module tests plus 48 runner-local integration tests in `run_tests.py`. The
  existing suite logged 46 `ResourceWarning` instances for unclosed resources;
  they did not fail tests and remain a hygiene backlog.

The new foundation modules contribute 192 tests: `test_foundation_runtime.py`
33, `test_configuration.py` 36, `test_engine_registry.py` 38,
`test_schemas.py` 46, `test_security_baseline.py` 39. Thus 941 existing module
tests + 192 new module tests = 1133 discovered; + 48 runner-local tests = 1181.

### `run_tests.py` is an explicit list — add new modules to it

The runner still has a hand-written list of imported test modules, so a new
module must be added there as well as being discoverable by unittest. PART 01
initially missed five new modules; after wiring them in, a second audit found
and fixed the duplicate-class shadowing described above. Always confirm both
totals and reconcile them; do not infer success from a focused run alone.

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v  # 1133 module tests
python3 tests/run_tests.py                                # 1181 incl. runner-local tests
```
