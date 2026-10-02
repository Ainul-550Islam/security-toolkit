# Language Boundaries

Four languages are used, each for a reason. Mixing responsibilities is how a
polyglot codebase becomes unmaintainable, so the split is explicit.

## Python — orchestration and policy

**Owns:** workflow orchestration, policy evaluation, persistence, reporting,
the API surface, the CLI, and all integrations.

**Why:** the work is I/O-bound and logic-heavy, where readability and the
standard library matter more than raw speed.

**Never:** hot inner loops over large buffers, and anything requiring manual
memory control.

## Rust — memory-safe CPU-bound primitives

**Owns:** hashing, constant-time comparison, byte pattern matching, bounded
parsing, entropy calculation.

**Why:** these run over untrusted input in tight loops. Rust gives C-class
performance with compiler-enforced memory safety, and `#![forbid(unsafe_code)]`
means that guarantee cannot be locally waived.

**Never:** network I/O, filesystem access, process execution, or business
logic. The crate is pure computation with zero dependencies.

## C++ — low-level buffer inspection

**Owns:** buffer inspection where an existing C/C++ library is required.

**Why:** the security ecosystem's parsers and format libraries are C/C++. When
one must be linked, this is where it goes — isolated behind a RAII wrapper.

**Never:** new functionality that Rust could provide instead. C++ is used
where an ecosystem dependency forces it, not by preference. No listeners, no
process execution, no manual memory management.

## TypeScript — user interface only

**Owns:** rendering the web interface.

**Why:** it is the browser's language.

**Never:** security decisions. Authorization, redaction, validation and policy
evaluation happen server-side. Client-side checks are usability affordances
that an attacker simply skips; the server must re-validate everything.

## Cross-language contracts

Languages communicate through the versioned JSON Schemas in `schemas/`, not
through shared code. Each language mirrors the vocabulary:

| Concept | Python | Rust | C++ | Schema |
|---|---|---|---|---|
| Health states | `core/constants.py` | `health.rs::HealthStatus` | `engine.hpp::HealthStatus` | `health.schema.json` |
| Schema version | `core/version.py` | `version.rs::SCHEMA_VERSION` | `version.hpp::kSchemaVersion` | `$id` path |
| Severity | `core/constants.py` | — | — | `event`/`finding` |

`tests/test_schemas.py` asserts these stay aligned, so a drift between the
Rust, C++ and Python views fails the Python suite rather than surfacing later
as a confusing cross-language bug.

## Current integration status

The Rust crate and the C++ library **build and pass their tests**, but neither
has a Python binding yet: no `cdylib`, no PyO3, no ctypes bridge.
`services/engine_registry.py` therefore reports both as `unavailable` with
that reason. This is deliberate — shipping a stub that pretends to call native
code would be a lie the health endpoint repeats to operators.
