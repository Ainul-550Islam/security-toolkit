# MASTER PROMPT — IMPLEMENT FIRST 50 FILES

Work inside the existing project:

`/home/user/security-toolkit`

Use `/first.md` as the authoritative specification.

The goal is to turn the existing security engine into a deployable, customer-facing security application and API.

Do NOT create a replacement project.
Do NOT create a separate marketing/e-commerce website.
Do NOT duplicate the existing security engine.
Do NOT discard working logic.
Do NOT invent fake integrations, fake scan results, fake credentials, fake cloud responses, fake billing state, fake IDs, or fake production data.

---

# ABSOLUTE CODE RULES

For every file:

1. Inspect the existing repository before creating/modifying it.
2. Search all imports and usages of the target file or related interfaces.
3. Inspect related tests before changing implementation.
4. Preserve existing public behavior unless a verified defect requires a change.
5. Preserve all existing useful logic.
6. Never silently remove an existing class, function, route, export, data model, or compatibility interface.
7. If compatibility changes are required, create an explicit compatibility layer and tests.
8. Never use:

```text
...
# ... existing code ...
# rest of file
# omitted
TODO
FIXME
pass
```

for omitted production implementation.

9. Every NEW or MODIFY file must exist as a COMPLETE FILE.
10. Every changed file must be returned as the COMPLETE FINAL FILE, not a diff.
11. Include every import.
12. Include every class.
13. Include every function.
14. Include every validation path.
15. Include every required error path.
16. Include every required helper.
17. Never shorten a file to save tokens.
18. Never replace real logic with pseudocode.
19. Never replace real logic with placeholder implementations.
20. Do not claim anything is verified unless it was actually executed.

---

# SECURITY RULES

Security-sensitive functionality must fail closed.

Never expose to clients:

```text
passwords
API keys
tokens
session secrets
private keys
cloud credentials
provider credentials
database credentials
encryption keys
raw SQL errors
Python tracebacks
filesystem paths
internal exception strings
debug information
```

Every API/service/storage boundary must preserve tenant isolation.

Tenant A must never:

```text
read tenant B data
modify tenant B data
export tenant B data
query tenant B findings
see tenant B credentials
see tenant B audit events
see tenant B metrics
```

Replace the current custom XOR secret protection with authenticated encryption backed by a vetted cryptographic implementation.

Do NOT implement cryptographic primitives manually.

All external integrations must have explicit states such as:

```text
NOT_CONFIGURED
UNAVAILABLE
TIMEOUT
RATE_LIMITED
ERROR
```

when the real service is unavailable.

Do not fake successful external calls.

---

# IMPLEMENTATION ORDER

Implement in this exact order:

```text
01–10  HTTP/API foundation
11–20  customer-facing API
21–30  crypto/persistence/cloud/integration hardening
31–38  existing-module hardening
39–50  frontend
```

Do not skip a file because another file appears easier.

If a later file depends on an earlier file, implement the dependency first.

If an existing architecture conflicts with `/first.md`, inspect actual usages and preserve compatibility rather than blindly replacing it.

---

# FILES 01–50

## 01

`api/http.py`
# NEW — Real HTTP entrypoint/WSGI-compatible adapter; request parsing, response serialization, method handling, content type, request IDs, bounded body sizes, secure defaults, and graceful shutdown.

## 02

`api/router.py`
# NEW — Central `/api/v1` route registry and dispatcher; strict path matching, method handling, route parameters, authentication/tenant metadata, 404/405 behavior.

## 03

`api/middleware.py`
# NEW — Middleware pipeline for request IDs, security headers, authentication enforcement, tenant context, rate-limit hooks, deadlines/timeouts, access logging, and safe exception translation.

## 04

`api/request_context.py`
# NEW — Typed per-request context containing request ID, authenticated principal, tenant ID, roles/permissions, deadline, source metadata, and safe correlation fields; never raw secrets.

## 05

`api/errors.py`
# NEW — Stable API error model and exception mapping; validation, authentication, authorization, not-found, conflict, rate-limit, unavailable, and redacted server errors.

## 06

`api/auth.py`
# NEW — Adapter around existing identity/RBAC/MFA/SSO behavior; authenticate requests, construct minimal principal context, enforce tenant scope, and preserve existing authorization semantics.

## 07

`api/openapi.py`
# NEW — OpenAPI generator/registry based only on actual implemented routes, schemas, authentication requirements, tenant requirements, permissions, and version metadata.

## 08

`api/v1/__init__.py`
# MODIFY — Preserve current API-v1 behavior while exposing deterministic registration for new endpoint modules and existing endpoints.

## 09

`api/v1/health.py`
# MODIFY — Preserve liveness/readiness/health semantics and expose them through the real API with dependency-aware status and safe responses.

## 10

`api/v1/metadata.py`
# MODIFY — Preserve metadata/capability behavior while exposing stable customer-facing version/build/capability/feature information without secrets.

---

## 11

`api/v1/tenants.py`
# NEW — Tenant lifecycle and read APIs; settings/status/configuration surfaces using existing tenant models/storage; no duplicate tenant model.

## 12

`api/v1/users.py`
# NEW — Tenant-scoped user list/invite/status/role/session management surfaces using existing identity/RBAC services.

## 13

`api/v1/assets.py`
# NEW — Customer asset inventory API for supported domains, hosts, services, cloud resources, repositories, containers, Kubernetes/IaC assets; never fabricate unavailable fields.

## 14

`api/v1/scans.py`
# NEW — Scan create/list/detail/cancel APIs integrated with existing orchestration/jobs/scanner engine; idempotency, authorization, tenant isolation, bounded input, state transitions, audit linkage.

## 15

`api/v1/findings.py`
# NEW — Finding list/detail/filter/update APIs using existing risk/correlation/remediation/evidence logic and tenant-safe serialization.

## 16

`api/v1/reports.py`
# NEW — Customer report generation/status/download APIs using existing reporting/PDF/SARIF functionality with authorization and immutable references.

## 17

`api/v1/integrations.py`
# NEW — Integration catalog/config/status APIs for notifications, SIEM/syslog/webhooks/ticketing/cloud integrations; secrets are write-only.

## 18

`api/v1/audit.py`
# NEW — Tenant audit-event query/export API with pagination, filtering, redaction, immutable references, and tenant isolation.

## 19

`api/v1/metrics.py`
# NEW — Tenant-safe aggregate security/operational metrics API; no cross-tenant leakage or internal process disclosure.

## 20

`api/v1/admin.py`
# NEW — Restricted platform-operator API for diagnostics, feature flags, job inspection, integration diagnostics, and controlled maintenance; strictly separate platform-admin from tenant-admin.

---

## 21

`services/crypto.py`
# NEW — Central authenticated encryption service using a vetted implementation; versioned ciphertext, unique nonces, integrity verification, key IDs, failure handling, and migration support.

## 22

`services/key_management.py`
# NEW — Environment/KMS/Vault key-management abstraction; key resolution, IDs, rotation metadata, validation, cleanup/zeroization where supported, and zero key logging.

## 23

`services/database.py`
# NEW — Production database abstraction preserving existing storage behavior while providing transaction boundaries, connection management, locking hooks, health checks, and PostgreSQL migration seam.

## 24

`services/migrations.py`
# NEW — Explicit schema migration/version runner with repeat-safe execution, locking, startup validation, and documented rollback strategy.

## 25

`services/cloud_aws.py`
# NEW — Real AWS integration boundary for account/resource/security inventory; least privilege, pagination, timeout, retry/backoff, throttling handling, redaction, and explicit unavailable states.

## 26

`services/cloud_azure.py`
# NEW — Real Azure subscription/resource/security integration with tenant/subscription isolation, pagination, retry/backoff, bounded calls, timeout, and secure credentials.

## 27

`services/cloud_gcp.py`
# NEW — Real GCP project/resource/IAM/security integration with scoped credentials, pagination, quotas, retries/backoff, timeout handling, and safe error mapping.

## 28

`services/ticketing.py`
# NEW — Provider-neutral ticketing service and first supported provider adapters; create/update/link/close operations, idempotency, finding references, authorization and tenant isolation.

## 29

`services/notifications.py`
# NEW — Provider-neutral notification service integrating existing alerts/notification logic; email/webhook/chat support, delivery state, retry/backoff, deduplication, tenant safety, and audit records.

## 30

`python/notify.py`
# MODIFY — Preserve current notification behavior while removing custom XOR protection and routing secret handling through the new crypto/key-management services; migration compatibility and safe error redaction required.

---

## 31

`python/dashboard.py`
# MODIFY — Preserve existing dashboard functionality while integrating API/service boundaries, fixing raw exception disclosure, adding request IDs/security headers, enforcing authorization, and protecting state-changing flows.

## 32

`python/store.py`
# MODIFY — Preserve SQLite behavior and all current callers while hardening transactions, concurrency, tenant isolation, integrity checks, migrations, timeouts, backups, and database abstraction compatibility.

## 33

`python/cloud_security.py`
# MODIFY — Preserve fixture/static analysis behavior while adding real-provider adapter integration; clearly distinguish LIVE, FIXTURE, NOT_CONFIGURED, UNAVAILABLE, and ERROR states.

## 34

`python/integrations.py`
# MODIFY — Preserve webhook/syslog/CEF/JSON integrations while adding provider abstraction, credential lifecycle, retries, timeout, idempotency, delivery state, and tenant-safe configuration.

## 35

`python/identity.py`
# MODIFY — Preserve authentication/identity semantics while exposing minimal principal information to the API, strengthening session/token lifecycle, revocation, audit linkage, and tenant enforcement.

## 36

`python/rbac.py`
# MODIFY — Preserve current permission semantics while adding explicit API scopes, platform-admin/tenant-admin separation, deny-by-default behavior, and privilege-change auditability.

## 37

`python/jobs.py`
# MODIFY — Preserve job orchestration while adding API-safe states, idempotency, cancellation authorization, bounded retries/backoff, tenant scope, and durable status tracking.

## 38

`python/worker.py`
# MODIFY — Preserve worker execution while adding graceful shutdown, bounded concurrency, leases/heartbeats, retry classification, dead-letter handling, tenant scope, and structured telemetry.

---

# FRONTEND

## 39

`web/package.json`
# NEW — Production React/TypeScript frontend dependency manifest with pinned versions and scripts for development, build, testing, linting, typechecking, and dependency audit.

## 40

`web/tsconfig.json`
# NEW — Strict TypeScript configuration with strict null checking, no implicit any, production-safe compilation and module settings.

## 41

`web/vite.config.ts`
# NEW — Deterministic Vite configuration with local API proxying, environment validation, secure asset handling, and production build output.

## 42

`web/index.html`
# NEW — Minimal production HTML shell with security-conscious metadata, viewport, theme, title, and no secrets.

## 43

`web/src/main.tsx`
# NEW — React bootstrap, strict mode, router, global error boundary, auth/session initialization, API client/provider setup.

## 44

`web/src/app/App.tsx`
# NEW — Top-level application shell with authentication routing, tenant context, navigation, route guards, loading/error states, and server-backed permissions.

## 45

`web/src/lib/api.ts`
# NEW — Typed `/api/v1` HTTP client with request IDs, auth/session handling, JSON/error decoding, timeout/abort support, pagination helpers, and no hard-coded secrets.

## 46

`web/src/lib/auth.ts`
# NEW — Secure frontend session/auth state management; login, refresh, logout, permission context, CSRF/token handling consistent with backend, and no unsafe privileged-secret storage.

## 47

`web/src/pages/OverviewPage.tsx`
# NEW — Real customer security overview dashboard: risk summary, active scans, findings, assets, integrations, health, recent activity; real API data only.

## 48

`web/src/pages/ScansPage.tsx`
# NEW — Scan creation/history/detail/progress/cancellation interface using real API state, authorization, validation, loading/empty/error states.

## 49

`web/src/pages/FindingsPage.tsx`
# NEW — Findings search/filter/sort/detail/remediation UI with evidence, risk, status, assignment where supported, and permission-aware actions.

## 50

`web/src/pages/SettingsPage.tsx`
# NEW — Customer settings UI for organization, users/roles, integrations, notification destinations, security preferences, API access, and audit visibility; secrets remain write-only.

---

# IMPORTANT DEPENDENCY RULE

Do not create a frontend mock API merely to make the frontend appear complete.

The frontend must consume the actual `/api/v1` contracts.

If an API endpoint is unavailable because its backend implementation is not yet complete:

```text
show an explicit unavailable/not-configured state
```

Do not fabricate data.

---

# EXISTING LOGIC PRESERVATION

Before modifying each existing file:

```text
search imports
search usages
search tests
inspect callers
inspect public exports
inspect configuration
inspect persistence interactions
inspect security assumptions
```

Then modify only what is necessary.

For:

```text
api/v1/__init__.py
api/v1/health.py
api/v1/metadata.py
python/notify.py
python/dashboard.py
python/store.py
python/cloud_security.py
python/integrations.py
python/identity.py
python/rbac.py
python/jobs.py
python/worker.py
```

the existing functionality must continue to work.

---

# TEST REQUIREMENT

Every logical group must be tested before moving to the next group.

## Group 01–10

Run:

```text
API unit tests
HTTP tests
router tests
middleware tests
authentication tests
health tests
metadata tests
OpenAPI tests
```

## Group 11–20

Run:

```text
tenant tests
user/RBAC tests
asset tests
scan tests
finding tests
report tests
integration tests
audit tests
metrics tests
admin authorization tests
```

## Group 21–30

Run:

```text
crypto tests
tamper-detection tests
key-rotation/version tests
database transaction/concurrency tests
migration tests
AWS adapter tests
Azure adapter tests
GCP adapter tests
ticketing tests
notification tests
legacy secret migration tests
```

## Group 31–38

Run all affected legacy tests plus:

```text
dashboard security tests
store isolation tests
cloud provider state tests
integration regression tests
identity regression tests
RBAC regression tests
job idempotency/cancellation tests
worker lifecycle tests
```

## Group 39–50

Run:

```text
frontend typecheck
frontend lint
frontend unit tests
frontend production build
frontend dependency audit
API-client tests
auth-state tests
page tests
```

---

# FULL REGRESSION

After all 50 files are implemented, run the repository's complete available regression suite.

Use the project's actual commands.

Do NOT invent a test command if the repository already defines one.

Report exact:

```text
tests run
passed
failed
errors
skipped
duration
```

Also report frontend:

```text
typecheck
lint
test count
build
dependency audit
```

Do not state:

```text
100% complete
100% production ready
all green
enterprise ready
```

unless those claims are actually supported by the executed verification.

---

# REQUIRED OUTPUT FOR EACH FILE

For each file print:

```text
FILE:
<exact path>

ACTION:
NEW / MODIFY

STATUS:
COMPLETE / BLOCKED

EXISTING LOGIC INSPECTED:
<actual files/usages>

DEPENDENCIES:
<actual dependencies>

FULL CONTENT:
<complete file content, no omitted sections>

TESTS:
<exact tests>

VERIFICATION:
<exact commands and results>

SECURITY NOTES:
<verified security changes>

UNVERIFIED:
<anything not actually verified>
```

For every file, the full final source must be preserved in the workspace.

Never return a shortened file.

Never return a diff instead of the complete file.

Never use:

```text
...
# existing code
# omitted
# rest of file
TODO
FIXME
```

as a substitute for implementation.

---

# STOP CONDITIONS

If an implementation cannot safely be completed because an existing contract is unclear:

1. inspect more repository code;
2. inspect tests;
3. inspect configuration;
4. preserve the existing interface;
5. implement the smallest compatible solution;
6. clearly report what remains unverified.

Do not invent behavior merely to make tests pass.

Do not bypass security checks merely to make a test pass.

Do not weaken a test merely because the new implementation fails it.

---

# FINAL ACCEPTANCE CONDITION

Files 01–50 are considered implemented only when:

```text
all 50 files exist in the correct paths
+
all required modifications preserve existing behavior
+
no required production branch is placeholder code
+
no fake external integration exists
+
tenant isolation is tested
+
secret redaction is tested
+
crypto migration path is tested
+
API contracts are tested
+
frontend builds successfully
+
complete available regression suite has been executed
+
exact verification results are reported
```

If any condition is not satisfied, report the exact unmet condition instead of claiming completion.