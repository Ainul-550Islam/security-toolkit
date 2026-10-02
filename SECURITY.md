# Security Policy

## Honest scope statement

This project is a **defensive** security assessment and governance toolkit. It
inspects configuration, dependencies and policy, and it records findings. It
does **not** exploit, brute-force or attack systems, and contributions adding
offensive automation are rejected (`interfaces/scanner.py::assert_defensive`
refuses such registrations at the boundary).

**This project holds no certifications.** It is not SOC 2, ISO 27001, PCI DSS
or FedRAMP certified or audited. It has not been penetration-tested by a third
party. It can help you *work toward* such programmes by collecting evidence,
but it does not confer compliance, and nothing in this repository should be
presented to an auditor as proof that a control is certified.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes (pre-1.0; interfaces may change) |

This is pre-1.0 software. The API and schema contracts are versioned
(`api/v1`, `schema_version: "1"`) but may evolve before 1.0.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the repository maintainers
through your organisation's established security contact. Please include
reproduction steps, affected version and impact. Do not open a public issue
for an unpatched vulnerability.

No public disclosure timeline or bug-bounty programme is promised, because
none currently exists. Overstating that would be dishonest.

## Security properties the codebase actually enforces

Each item below is covered by a test in `tests/test_security_baseline.py`,
`tests/test_configuration.py` or `tests/test_schemas.py`.

| Property | Where | Enforcement |
|---|---|---|
| Secure defaults | `config/settings.py` | Loopback bind, auth on, TLS on, debug off |
| Production fail-closed | `config/settings.py::Settings.validate` | Refuses debug / no-auth / no-TLS / all-interface bind in production |
| Secret redaction in logs | `config/logging.py::RedactionFilter` | Filter on the handler, by key name and by value pattern |
| Secrets never stored | `interfaces/secrets.py` | Interface only; no persistence, no custom crypto |
| Secret values unprintable | `interfaces/secrets.py::SecretValue` | `repr`/`str` redacted; unhashable; timing-safe compare |
| Deny-by-default policy | `interfaces/policy.py` | Every decision is explicit; `DenyAllPolicyEngine` is the default |
| Path traversal defence | `core/paths.py::safe_join` | Rejects `..`, absolute paths, control characters, symlink escape |
| UTC-only time | `core/clock.py` | Naive datetimes rejected; no `time.mktime()` |
| No stdlib shadowing | `tests/test_security_baseline.py` | Asserts no project module shadows a stdlib name |
| Memory safety (Rust) | `native/rust/.../lib.rs` | `#![forbid(unsafe_code)]`, zero dependencies, no I/O |
| Memory safety (C++) | `native/cpp` | RAII, no `new`/`malloc`, bounds-checked access, hardened flags |
| Health discloses nothing | `services/health_service.py` | No credentials, hosts or paths; exception *types* only |

## Known limitations

Stated plainly rather than omitted:

* **`EnvironmentSecretProvider` is not a hardened secret store.** Environment
  variables are readable by the process tree and can appear in crash dumps.
  A Vault or KMS provider implementing the same interface is the production
  path; it is not yet written.
* **No encryption at rest is implemented.** There is deliberately no
  home-grown crypto. Use full-disk or database-level encryption provided by
  your platform.
* **The native engines are not wired to Python.** The Rust crate and C++
  library build and pass their tests, but no FFI bridge exists, so
  `services/engine_registry.py` reports them as `unavailable`.
* **No authentication or authorization implementation ships in the foundation
  layer.** `interfaces/policy.py` defines the contract and denies by default;
  enforcement lives in the application layer.
* **The legacy `python/` package predates these boundaries** and is not yet
  type-checked or covered by the foundation's security tests.

## Handling of credentials in this repository

* `.env` is git-ignored; only `.env.example` with placeholders is tracked.
* `tests/fixtures/p8test.key` is a throwaway keypair generated solely for
  offline JWT-signing tests. It protects nothing.
* `data/` (which the runtime writes generated keys into) is git-ignored.
