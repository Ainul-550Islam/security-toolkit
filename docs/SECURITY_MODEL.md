# Security Model

## What this system defends

A defensive assessment platform holds two sensitive things: **credentials for
the systems it inspects**, and **findings describing where those systems are
weak**. A leak of the second is nearly as damaging as a leak of the first — a
findings database is a target map.

## Trust boundaries

| Boundary | Untrusted input | Control |
|---|---|---|
| Environment -> config | Env vars | `config/settings.py` validates, bounds and fails closed |
| Caller -> path handling | Filenames, archive members | `core/paths.py::safe_join` |
| Producer -> telemetry | Event metadata | `interfaces/telemetry.py` rejects credential-shaped keys |
| Engine -> registry | Health probes | Exceptions caught; only the exception *type* recorded |
| Service -> logs | Any logged value | `config/logging.py::RedactionFilter` on the handler |
| API -> client | Response bodies | Health/metadata schemas contain no credential fields |

## Fail-closed decisions in the PART-01 foundation

The following guarantees apply to the new `core/`, `config/`, `interfaces/`
and `services/` layer; PART 01 does not retrofit every legacy Phase 1–12
module. In this foundation, weakening paths are explicit and refused in
production:

* Bind host defaults to `127.0.0.1`. `0.0.0.0` requires
  `SECTOOLKIT_ALLOW_INSECURE_BIND=true` and is rejected outright in production.
* `auth_required` and `tls_required` default true and cannot be disabled in
  production.
* `debug` defaults false and cannot be enabled in production.
* Unknown feature flags resolve to **false**, never true.
* Production-locked flags (`verbose_errors`, `experimental_api`) ignore an
  environment override in production rather than honouring it.
* An unrecognised `SECTOOLKIT_ENV` value never resolves to `production`.
* Policy decisions start from `deny`; an allow must be constructed explicitly
  with a stated reason.
* An unchecked engine or dependency is `unknown`, which is never folded into
  "healthy".
* A missing or empty secret raises; it never returns `""`, which a caller
  could mistake for "no authentication required".

**Known legacy exception:** `main.py dashboard` and direct
`python/dashboard.py` still default to `0.0.0.0`; the bearer token is optional
and unset by default. This pre-existing Phase 1–12 behavior was not changed in
PART 01. Do not expose that dashboard on an untrusted network: explicitly bind
to `127.0.0.1` for local use, or set a strong token and use a trusted TLS
proxy. A later compatibility-reviewed change should make loopback the default
and require authentication for non-loopback binds.

## Secret handling

**We do not implement cryptography.** There is no home-grown encryption,
obfuscation or base64 "encoding" masquerading as protection — that invites
false confidence and is worse than storing plaintext knowingly.

`interfaces/secrets.py` provides resolution only:

* `SecretRef` is a name, safe to log.
* `SecretValue.__repr__` and `__str__` are redacted; the type is unhashable
  (hashing would expose material through hash-ordered structures); equality is
  timing-safe.
* `reveal()` is the single conspicuous way to get plaintext, so misuse is
  greppable in review.
* `NullSecretProvider` is the fail-closed default.

`EnvironmentSecretProvider` is honest about its limits: env vars are visible
to the process tree and may appear in crash dumps. A Vault/KMS provider
implementing the same interface is the production path and is **not yet
written**.

## Log redaction

Redaction is enforced by a handler filter, so it applies to every record
including ones written by code that never considered secrets. It matches:

* **By key:** `authorization`, `password`, `token`, `api_key`, `private_key`,
  `cookie`, `session`, `client_secret`, `webhook_secret`, `dsn`,
  `connection_string`, and any field name containing those substrings.
* **By value shape:** `Authorization:` headers, bare `Bearer <token>`, PEM
  private-key blocks, `key=value` credential pairs, `Set-Cookie`, AWS access
  key IDs, GitHub/Slack/Stripe token prefixes, JWTs.

Exception logging records the exception **type** only.

## Memory safety in native code

* **Rust:** `#![forbid(unsafe_code)]` — the compiler rejects `unsafe`. Zero
  dependencies, so no third-party supply chain at that layer. No `std::net`,
  `std::process` or `std::fs`; a component that cannot reach the network
  cannot exfiltrate.
* **C++:** RAII throughout (`std::vector` owns all storage). No `new`,
  `delete`, `malloc` or `free`. Bounds enforced at construction, so any
  `Buffer` that exists is already within limits; lookups return
  `std::optional` rather than reading out of range. Built with
  `-Wall -Wextra -Wpedantic -Wconversion -Wold-style-cast
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro -Wl,-z,now`.

Both are verified by `tests/test_security_baseline.py`, which fails if
`unsafe`, a socket header, `system(`, `new ` or `malloc(` appears.

## Dependency policy

The runtime dependency list is **empty**. Every third-party package in a
security tool runs with that tool's privileges. Adding one requires written
justification here, a pinned version and a review of its transitive tree.
Development tooling (`mypy`, `ruff`) is confined to `requirements-dev.txt`.

## Explicitly out of scope

No exploitation, brute-forcing, credential stuffing, C2, implants or intrusive
third-party probing. `interfaces/scanner.py::assert_defensive` refuses to
register a scanner whose name or kind describes offensive automation.

## What is NOT claimed

* No certifications (SOC 2, ISO 27001, PCI DSS, FedRAMP). None. See
  `SECURITY.md`.
* No third-party penetration test has been performed.
* No encryption at rest is implemented.
* No authentication implementation ships in the foundation layer — only the
  deny-by-default policy contract.
