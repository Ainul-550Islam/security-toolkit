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

**Legacy dashboard boundary:** `main.py dashboard` and direct
`python/dashboard.py` bind to loopback by default and refuse non-loopback binds
without a token. Prefer `SECURITY_TOOLKIT_DASHBOARD_TOKEN` over the legacy
`--token` CLI argument, which can be visible to process inspection. The portal
emits request IDs and security headers, redacts internal exceptions, and
rejects query-string token authentication by default. The explicit
`--allow-legacy-query-token` switch is temporary and unsafe; it prints a warning
and should be used only for a controlled migration. The stdlib dashboard does
not terminate TLS; remote access requires a trusted TLS proxy. Its legacy
cookie-based HTML session is separate from the React app, which keeps its
bearer token in memory only.

## Secret handling

**Cryptographic primitives are delegated to pyca/cryptography.**
`services/crypto.py` uses AES-256-GCM with 96-bit random nonces, a 128-bit
authentication tag, a versioned ciphertext envelope, key identifiers, and
required associated data. Ciphertext fails closed on malformed formats,
unknown key IDs, context mismatch, or authentication failure. The code does
not implement a cipher, keystream, padding scheme, or MAC.

`services/key_management.py` provides an injectable key-provider contract and
an environment-backed provider. Keys are strict base64 encodings of exactly
32 bytes. Configure `SECURITY_TOOLKIT_ENCRYPTION_ACTIVE_KEY_ID` and
`SECURITY_TOOLKIT_ENCRYPTION_KEY`; retain old key IDs in
`SECURITY_TOOLKIT_ENCRYPTION_KEY_<ID>` while ciphertext still refers to them.
No local key is generated when configuration is missing. Vault/KMS providers
can implement the same contract but are not included or claimed as configured.
Environment keys are visible to the process and should be supplied through a
secret manager or protected process environment, never committed to source.
Existing XOR-wrapped notification values have decrypt-only migration support:
the old key is read only when it already exists, and each value is immediately
rewritten as authenticated ciphertext with tenant/project-bound associated
data. The old XOR format is never written; migration fails closed if its key
or the new AEAD key is unavailable. The legacy key file is not created by the
new code.

Cloud-account credentials use the same `CryptoService`, with associated data
`cloud-account-credential:v1:<tenant-id>:<account-id>` so ciphertext copied to
another tenant or account cannot be authenticated. Cloud credential writes
fail closed without a configured active key. Provider adapters receive
plaintext only in memory for the bounded read-only request; API views and audit
metadata expose neither ciphertext, credential references, nor credential
hints derived from secret material. Rows in the old notification-wrapper
format are migrated by compare-and-swap only after successful decryption and
AEAD encryption.

Platform-operator routes use a separate `SECURITY_TOOLKIT_PLATFORM_ADMIN_TOKEN`
header credential, not tenant roles or tenant API credentials. The token is
compared in constant time, never persisted or logged, and admin routes return
bounded metadata only. If the variable is missing or invalid, operator access
is unavailable; tenant owners cannot reach platform-admin operations through
ordinary RBAC.

The runtime pin `cryptography==50.0.2` is required for AES-GCM. This is a
reviewed cryptographic recipe library; using its high-level AEAD API is
materially safer than the previous custom XOR-based notification-secret
wrapper. Its runtime dependency tree is pinned as `cffi==2.1.0` and
`pycparser==3.0` in both `requirements.txt` and `pyproject.toml`. These three
packages are the base runtime dependencies for authenticated encryption. The
optional cloud extras add only the selected provider SDKs; they are never
installed by the base `requirements.txt` and do not imply live credentials or
provider connectivity.

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

## Cloud and ticketing adapters

Live cloud inventory is disabled unless an explicit account credential
reference or encrypted provider credential is configured and the matching SDK
extra is installed. AWS, Azure and GCP adapters issue read-only, bounded,
scoped requests and return only provider-confirmed resources. AWS validates
STS account identity; Azure and GCP use subscription/project-scoped inventory
requests and reject mismatched resource scope. Pagination, request timeouts,
SDK retries and resource ceilings are bounded. SDK failures map to safe error
codes and never become an empty-success inventory. The deterministic
`fixture` provider remains test/demo-only and is not used as a live fallback.

Install only the required exact-pinned optional extra, for example
`pip install '.[cloud-aws]'`, `pip install '.[cloud-azure]'` or
`pip install '.[cloud-gcp]'`. The pins are `boto3==1.43.108`,
`azure-identity==1.26.0`, `azure-mgmt-resource==26.0.0`,
`google-auth==2.59.1` and `google-cloud-asset==4.5.0`. Provider SDK versions
and their resolved transitive dependencies must be reviewed and updated as a
unit; cloud calls are not exercised against live customer accounts in the
repository test suite.

Ticketing currently supports an opt-in Jira Cloud adapter over HTTPS. It
requires a deployment-provided secret-reference resolver; this project does
not treat the metadata-only secret registry as a credential vault. Jira
issue identity uses a stable finding label for create/update idempotency,
linking checks for an existing issue relation, and close operations select a
provider-confirmed `done` transition. No external ticket is claimed as created,
updated, linked or closed before Jira returns success. No live Jira site or
credential is configured in this repository.

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

The base runtime dependency list contains three exact pins:
`cryptography==50.0.2` for AES-256-GCM and its transitive dependencies
`cffi==2.1.0` and `pycparser==3.0`. Optional `cloud-aws`, `cloud-azure`, and
`cloud-gcp` extras are pinned separately in `pyproject.toml`; deploy only the
SDK families required by the account scopes being scanned. Every third-party
package in a security tool runs with that tool's privileges; additions require
written justification, an exact version pin and review of the resolved
transitive tree. Development tooling (`mypy`, `ruff`) is confined to
`requirements-dev.txt`.

## Explicitly out of scope

No exploitation, brute-forcing, credential stuffing, C2, implants or intrusive
third-party probing. `interfaces/scanner.py::assert_defensive` refuses to
register a scanner whose name or kind describes offensive automation.

## What is NOT claimed

* No certifications (SOC 2, ISO 27001, PCI DSS, FedRAMP). None. See
  `SECURITY.md`.
* No third-party penetration test has been performed.
* Authenticated encryption protects the notification webhook-secret field;
  it does not encrypt the entire database, backups, or other platform data.
* No hosted Vault/KMS key provider is included. Deployments must supply and
  rotate keys through a protected environment or an injected provider.
* No authentication implementation ships in the foundation layer — only the
  deny-by-default policy contract.
