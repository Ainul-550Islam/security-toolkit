# Contributing

## Ground rules

1. **No placeholders that claim to work.** A function that returns an empty
   result while implying success is worse than one that raises. If something
   is not implemented, it reports `unavailable` with a reason.
2. **Every production component has tests.** Not a smoke test — tests for the
   failure paths and the security properties.
3. **Security defaults fail closed.** New settings default to the restrictive
   value, and production refuses to run with them weakened.
4. **Defensive only.** No exploitation, brute-forcing or intrusive probing.
5. **Never claim a test passed without running it.** Paste real output.

## Layer responsibilities

See `docs/LANGUAGE_BOUNDARIES.md`. In short: Python orchestrates, Rust does
memory-safe CPU-bound primitives, C++ handles low-level buffer work where an
existing library requires it, TypeScript renders UI and makes no security
decisions.

## Before opening a pull request

```sh
# Compile everything
python3 -m compileall .

# Full Python suite
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tests/run_tests.py

# Native layers
cargo check --manifest-path native/rust/Cargo.toml
cargo test  --manifest-path native/rust/Cargo.toml
cmake -S native/cpp -B native/cpp/build && cmake --build native/cpp/build
./native/cpp/build/security_engine_tests

# Optional static analysis (requirements-dev.txt)
mypy
ruff check .
```

## Adding a dependency

The runtime dependency list is **empty on purpose**. To add one:

1. Justify it in `docs/SECURITY_MODEL.md`: what it does, why the standard
   library is insufficient, and its transitive tree.
2. Pin a version range in `requirements.txt`.
3. Development-only tooling goes in `requirements-dev.txt` and must never be
   imported by runtime code.

## Module naming

Never name a top-level module after a standard-library module. `platform`,
`types`, `json`, `logging`, `secrets`, `queue`, `select` and similar names
shadow the stdlib for any process that puts the directory on `sys.path`. This
caused a real defect (see `CHANGELOG.md`), and
`tests/test_security_baseline.py::SecurityBaselineImportCollisionTests`
now fails the build if it recurs.

## Writing tests

* `tests/run_tests.py` **star-imports** every test module into one namespace,
  so **TestCase class names must be globally unique** across the whole suite.
  Prefix them with the area under test.
* Tests must not require network access or a pre-existing database.
* Assert on security behaviour, not only on happy paths: that a secret is
  redacted, that a traversal is rejected, that production refuses debug mode.

## Commit hygiene

Never commit: `.env`, private keys, databases, logs, build output, CVs, or
personal data. `.gitignore` covers these; do not use `git add -f` to bypass it.
