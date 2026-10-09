# Security Toolkit — Productization / Sell-Ready Upgrade — FIRST 50 FILES

## Coding-agent instructions

Work inside the existing `security-toolkit` project. Do NOT create a replacement project, duplicate the existing security engine, or discard working logic.

1. Preserve all existing behavior and public interfaces unless a change is required to fix a verified security/product defect.
2. For every file below, inspect the existing repository and related imports/usages/tests before editing or creating it.
3. **Do not skip any code. Provide the full file content with my existing logic preserved. Do not use comments like `# ... existing code ...`, `# rest of file`, `# omitted`, `TODO`, `FIXME`, `pass`, or placeholder blocks in production code.**
4. When modifying an existing file, return the COMPLETE final file, not a diff and not a partial snippet.
5. When creating a new file, provide the COMPLETE file content with all imports, classes, functions, validation, error handling, logging, and tests required by that file's contract.
6. Do not silently remove an existing class/function/route/export. If a compatibility change is necessary, add an explicit compatibility layer and tests.
7. Do not invent fake integrations, fake credentials, fake scan results, fake cloud responses, fake billing state, or fake IDs in production paths. Use explicit `UNAVAILABLE` / `NOT_CONFIGURED` / `ERROR` states where a real external service is not configured.
8. Security-sensitive operations must fail closed. Never return secrets, tokens, passwords, private keys, raw provider credentials, SQL errors, Python tracebacks, filesystem paths, or internal exception strings to clients.
9. Replace the current home-grown XOR secret protection with authenticated encryption backed by a well-reviewed cryptographic implementation. Do not write new home-grown cryptography.
10. Keep tenant isolation explicit at every API/service/storage boundary. A request scoped to tenant A must never read, mutate, export, or expose tenant B data.
11. Keep the current standard-library runtime philosophy unless a dependency is genuinely required. Any new runtime dependency must be pinned, documented, security-justified, and covered by tests. Frontend dependencies are allowed in `web/`.
12. Add or update tests for every behavior changed by these files. Do not delete existing tests to make the suite pass.
13. Run targeted tests after each logical group, then run the complete available regression suite and report exact results.
14. Do not claim “100% production ready”, “all tests pass”, “enterprise ready”, or similar unless it is actually verified in the current checkout.
15. Keep implementation defensive, typed where practical, deterministic, observable, and backward-compatible.
16. Do not add unrelated features. These first 50 files are specifically for turning the current security engine into a deployable, customer-facing security platform.

## First 50 files

### 01–10 — Production HTTP/API foundation

1. `api/http.py` # NEW — Real production HTTP entrypoint/WSGI-compatible application adapter; request parsing, response serialization, method handling, content type, request IDs, bounded body sizes, secure defaults, and clean shutdown integration with the existing services.

2. `api/router.py` # NEW — Central route registration and dispatch layer; versioned routing for `/api/v1`, health endpoints, authentication boundary, tenant extraction, 404/405 handling, and strict route matching without duplicating business logic.

3. `api/middleware.py` # NEW — HTTP middleware chain for request IDs, security headers, authentication enforcement, tenant context, rate limiting hooks, timeout/deadline propagation, structured access logging, and safe exception translation.

4. `api/request_context.py` # NEW — Typed per-request context object containing request ID, authenticated principal, tenant ID, roles/permissions, deadline, source metadata, and safe correlation fields; must never store raw secret material.

5. `api/errors.py` # NEW — Public API error model and exception-to-response mapping; stable machine-readable error codes, safe user messages, field validation errors, authorization errors, not-found errors, conflict errors, and server-error redaction.

6. `api/auth.py` # NEW — Authentication/authorization adapter for the existing identity/RBAC/MFA/SSO logic; verifies credentials/tokens, builds the principal, enforces tenant scope, and returns only the minimum identity context required by services.

7. `api/openapi.py` # NEW — OpenAPI document generator/registry describing every implemented `/api/v1` route, request schema, response schema, auth requirement, tenant requirement, error code, and version metadata without inventing unsupported endpoints.

8. `api/v1/__init__.py` # MODIFY — Preserve the existing API-v1 package behavior while exporting the new router/endpoint modules and keeping route registration deterministic.

9. `api/v1/health.py` # MODIFY — Preserve the existing liveness/readiness/health semantics and expose them through the real HTTP layer with dependency-aware status reporting and safe response bodies.

10. `api/v1/metadata.py` # MODIFY — Preserve metadata/capability behavior and expose a stable customer-facing API contract containing version, build identity, supported capabilities, and feature availability without leaking host/configuration secrets.

### 11–20 — Core customer-facing API resources

11. `api/v1/tenants.py` # NEW — Tenant lifecycle/read APIs, tenant settings, tenant status, and safe tenant-scoped configuration surfaces; integrate existing tenant/storage models instead of creating duplicate tenant concepts.

12. `api/v1/users.py` # NEW — Tenant-scoped user listing, invitation/status flows, role assignment hooks, session/revocation surfaces, and secure user serialization; delegate authorization to existing identity/RBAC services.

13. `api/v1/assets.py` # NEW — Customer asset inventory API for domains, hosts, services, cloud resources, repositories, containers, and Kubernetes/IaC assets supported by the current scanners; never fabricate unavailable asset attributes.

14. `api/v1/scans.py` # NEW — Scan create/list/detail/cancel APIs integrated with the existing orchestration/jobs/scanner engine; idempotency, tenant isolation, bounded parameters, job state transitions, and audit events are required.

15. `api/v1/findings.py` # NEW — Findings list/detail/filter/update APIs using the existing models, correlation, risk, remedy, and evidence logic; include authorization checks and safe field serialization.

16. `api/v1/reports.py` # NEW — Customer report APIs for existing reporting/PDF/SARIF capabilities; support asynchronous report generation, status polling, download metadata, authorization, and immutable report references.

17. `api/v1/integrations.py` # NEW — Integration catalog/configuration/status APIs for notifications, SIEM/syslog/webhooks/ticketing/cloud providers; credentials must be write-only and never returned after storage.

18. `api/v1/audit.py` # NEW — Tenant audit-event query/export API using existing audit/security-operation data; pagination, filters, immutable event references, redaction, and strict tenant scoping.

19. `api/v1/metrics.py` # NEW — Tenant-safe operational/security metrics API mapped to existing monitoring/metrics logic; expose aggregate metrics only and prevent cross-tenant leakage or internal process details.

20. `api/v1/admin.py` # NEW — Restricted platform-operator/admin API for health diagnostics, feature flags, job inspection, integration diagnostics, and controlled maintenance operations; separate platform-admin privileges from tenant-admin privileges.

### 21–30 — Security, persistence, cloud, and integration hardening

21. `services/crypto.py` # NEW — Central authenticated-encryption service using a vetted cryptographic primitive/library; versioned ciphertext format, unique nonces, integrity verification, key identifiers, explicit failure states, and migration support for existing encrypted values. Do not implement cryptographic primitives manually.

22. `services/key_management.py` # NEW — Key lifecycle abstraction for environment/KMS/Vault-backed key resolution, key IDs, rotation metadata, validation, and zeroization/cleanup where supported; never log key material.

23. `services/database.py` # NEW — Production persistence abstraction that preserves current store behavior while introducing connection management, transaction boundaries, locking/concurrency hooks, health checks, and a migration seam for PostgreSQL or another production RDBMS.

24. `services/migrations.py` # NEW — Explicit schema/version migration runner and migration metadata model; must support repeat-safe upgrades, rollback strategy documentation, locking, and validation before application startup.

25. `services/cloud_aws.py` # NEW — Real AWS integration boundary for account/resource inventory and security metadata using least-privilege credentials; explicit `NOT_CONFIGURED`/`UNAVAILABLE` states, pagination, timeouts, retries, rate-limit handling, and credential redaction.

26. `services/cloud_azure.py` # NEW — Real Azure integration boundary for subscription/resource inventory and security metadata with tenant/subscription isolation, bounded API calls, retries/backoff, pagination, and safe credential handling.

27. `services/cloud_gcp.py` # NEW — Real GCP integration boundary for project/resource/IAM/security metadata with scoped credentials, pagination, retries/backoff, quotas, and safe error mapping.

28. `services/ticketing.py` # NEW — Provider-neutral ticketing interface plus secure adapters for the first supported ticketing systems; create/update/link/close workflows must reference real finding IDs and preserve idempotency.

29. `services/notifications.py` # NEW — Provider-neutral notifications service integrating existing alerts/notify logic; support email/webhook/chat targets, delivery state, retry/backoff, deduplication, tenant isolation, secret-safe configuration, and audit records.

30. `python/notify.py` # MODIFY — Preserve existing notification routing and delivery behavior, but remove the custom XOR encryption path, route secret protection through `services/crypto.py`/`services/key_management.py`, redact failures, and maintain backward compatibility plus migration handling for existing stored secret material.

### 31–38 — Production operations and existing critical-module hardening

31. `python/dashboard.py` # MODIFY — Preserve all existing dashboard functionality while routing through the new API/service boundaries, fixing raw exception disclosure, adding request IDs, secure error responses, authorization enforcement, CSRF-safe state-changing flows where applicable, and production-safe headers.

32. `python/store.py` # MODIFY — Preserve current SQLite-backed behavior and all existing callers, but harden transactions/concurrency, tenant scoping, integrity checks, migration hooks, timeout handling, backup-safe operations, and introduce a clean database abstraction compatible with the new `services/database.py` layer.

33. `python/cloud_security.py` # MODIFY — Preserve existing fixture/static analysis behavior while integrating the new real-provider adapters through explicit provider interfaces; retain deterministic fixture mode for tests and clearly separate live, fixture, unavailable, and error states.

34. `python/integrations.py` # MODIFY — Preserve existing generic webhook/syslog/CEF/JSON integration capabilities while adding the new provider abstraction, credential lifecycle hooks, timeout/retry rules, delivery state, idempotency, and tenant-safe configuration.

35. `python/identity.py` # MODIFY — Preserve existing authentication/identity behavior while exposing the minimal principal contract needed by the API layer, improving token/session lifecycle controls, revocation, audit linkage, and tenant boundary enforcement.

36. `python/rbac.py` # MODIFY — Preserve existing permission semantics while adding explicit API-scope permissions, tenant-admin/platform-admin separation, deny-by-default behavior, permission caching rules, and auditability for privilege changes.

37. `python/jobs.py` # MODIFY — Preserve existing job model/orchestration semantics while adding API-safe job states, idempotency keys, cancellation authorization, retries/backoff, bounded execution, tenant scope, and durable status tracking.

38. `python/worker.py` # MODIFY — Preserve existing worker execution paths while adding production worker lifecycle, graceful shutdown, bounded concurrency, job lease/heartbeat semantics, retry classification, dead-letter behavior, and structured telemetry.

### 39–50 — Customer-facing frontend and product delivery

39. `web/package.json` # NEW — Production frontend package manifest for a TypeScript React application; pin exact dependency versions, scripts for dev/build/test/lint/typecheck, and avoid unnecessary dependencies.

40. `web/tsconfig.json` # NEW — Strict TypeScript configuration for the customer-facing frontend; no implicit any, strict null checks, module resolution, source maps, and production-safe compiler settings.

41. `web/vite.config.ts` # NEW — Deterministic frontend build/dev configuration with API proxying for local development, environment validation, secure asset handling, and production build output suitable for deployment.

42. `web/index.html` # NEW — Minimal production HTML shell with CSP-compatible metadata, viewport settings, application title, theme metadata, and no embedded secrets or environment-specific credentials.

43. `web/src/main.tsx` # NEW — React application bootstrap, strict mode, router initialization, global error boundary hookup, auth/session bootstrap, API client initialization, and application-level providers.

44. `web/src/app/App.tsx` # NEW — Top-level application shell with authenticated/unauthenticated routing, tenant context, loading/error states, navigation structure, and route guards based on server-issued identity/permissions.

45. `web/src/lib/api.ts` # NEW — Typed HTTP client for `/api/v1`; request IDs, authentication/session handling, JSON parsing, timeout/abort support, stable error decoding, pagination helpers, and no hard-coded secrets.

46. `web/src/lib/auth.ts` # NEW — Frontend authentication/session state management that never stores privileged secrets in unsafe browser storage; handles login/session refresh/logout, CSRF/token strategy agreed with the backend, and permission-aware route state.

47. `web/src/pages/OverviewPage.tsx` # NEW — Customer security overview dashboard using real API data: risk summary, active scans, findings, assets, integrations, health state, and recent security activity; include loading/empty/error states instead of fake data.

48. `web/src/pages/ScansPage.tsx` # NEW — Scan management UI for creating scans, selecting supported scope types, viewing scan state/progress, cancelling authorized jobs, filtering history, and opening scan details with server-backed data only.

49. `web/src/pages/FindingsPage.tsx` # NEW — Findings management UI with search/filter/sort, severity/risk display, status transitions, evidence links, remediation workflow, assignment where supported, and strict permission-aware actions.

50. `web/src/pages/SettingsPage.tsx` # NEW — Customer settings UI for organization profile, users/roles, integrations, notification destinations, security preferences, API access, and audit visibility; sensitive credentials are write-only and must never be rendered back to the browser.

## Implementation order

Implement in this exact order unless a dependency requires an adjacent file first. Do not jump directly to the UI before the backend contracts exist.

1. Files 1–10: HTTP/API foundation.
2. Files 11–20: customer-facing API resources.
3. Files 21–30: crypto, persistence, cloud, integrations.
4. Files 31–38: harden and connect existing production modules.
5. Files 39–50: frontend and customer workflows.

## Required verification after these 50 files

Run all relevant existing tests plus new tests for every changed/created module. At minimum verify:

- Python syntax/compile success.
- Existing targeted unit tests for all touched modules.
- API route and authorization tests.
- Cross-tenant isolation tests.
- Secret redaction tests.
- Crypto encrypt/decrypt/tamper/key-version tests.
- Concurrent transaction/store tests.
- Cloud adapter unavailable/timeout/retry tests.
- Job idempotency/cancellation/retry tests.
- Frontend typecheck, lint, unit tests, and production build.
- Existing dashboard behavior regression tests.
- Full regression suite with exact pass/fail/skip/error counts and runtime.

## Required output from the coding agent

For every file completed, report:

- `FILE:` exact path
- `ACTION:` NEW or MODIFY
- `FULL CONTENT:` complete final file content, with no omissions
- `DEPENDENCIES:` files/modules it relies on
- `TESTS:` exact tests added/updated
- `VERIFICATION:` exact command(s) run and exact result
- `SECURITY NOTES:` concrete security-sensitive changes

Never report a file as complete if it contains placeholder code, an unimplemented required branch, a fake external integration, silently dropped existing logic, or an unverified claim.
