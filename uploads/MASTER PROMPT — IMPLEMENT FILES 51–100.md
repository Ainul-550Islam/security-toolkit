# MASTER PROMPT — IMPLEMENT FILES 51–100

Work inside:

`/home/user/security-toolkit`

Use `/first.md` and the completed Files 01–50 implementation as the authoritative baseline.

Files 01–50 already established the HTTP/API foundation, customer API, security hardening, cloud/integration boundaries, persistence improvements, and initial customer-facing frontend.

Now implement **Files 51–100 only**, extending the existing system.

Do NOT create:

- marketing website
- e-commerce website
- unrelated SaaS
- duplicate security engine
- replacement architecture
- fake cloud integrations
- fake scan results
- fake customer data
- fake credentials
- fake provider responses

Preserve all verified behavior from Files 01–50.

---

# ABSOLUTE SOURCE RULE

For every file:

1. Inspect the complete existing repository before changing it.
2. Search imports/usages/callers.
3. Search relevant tests.
4. Preserve existing public interfaces.
5. Preserve working domain logic.
6. Never silently delete functionality.
7. Never invent behavior simply to satisfy a test.
8. Never weaken security controls.
9. Never return a shortened source file.

NEVER use:

```text
...
# ... existing code ...
# existing implementation
# rest of file
# omitted
TODO
FIXME
pass
```

as a substitute for implementation.

Every NEW/MODIFY file must be complete.

For every changed file, return the **entire final file content**.

---

# SECURITY BASELINE

Maintain all protections introduced by Files 01–50:

```text
tenant isolation
authentication
RBAC
permission checks
request IDs
safe errors
secret redaction
authenticated encryption
bounded requests
auditability
idempotency
rate limits
timeouts
retry limits
```

No endpoint may bypass the central authentication/middleware boundary.

No service may accept tenant identifiers and blindly trust them.

No customer-visible API may expose internal stack traces.

No logs may contain:

```text
password
access token
refresh token
private key
API secret
cloud credential
encryption key
session secret
```

---

# IMPLEMENTATION GROUPS

```text
51–60  Customer security resource APIs
61–70  Core security/domain services
71–80  Production operations/security controls
81–90  Customer-facing frontend
91–100 Testing, deployment, observability, and API documentation
```

Complete each group before starting the next.

---

# CUSTOMER SECURITY RESOURCE API

## 51

`api/v1/projects.py`
# NEW — Tenant/project API for creating, listing, updating, archiving, and viewing project scope; strict tenant ownership and RBAC integration.

## 52

`api/v1/organizations.py`
# NEW — Customer organization API for organization profile, security posture settings, timezone/locale preferences, and organization lifecycle metadata.

## 53

`api/v1/roles.py`
# NEW — Customer RBAC management API for role listing, permission inspection, role assignment/removal, and privilege-change audit events.

## 54

`api/v1/sessions.py`
# NEW — Authenticated session management API for current session listing/revocation, device/session metadata, forced logout, and secure session lifecycle.

## 55

`api/v1/notifications.py`
# NEW — Customer notification API for notification history, delivery status, preferences, channel configuration, and retry state.

## 56

`api/v1/evidence.py`
# NEW — Security evidence API for finding/scan/report evidence retrieval, metadata, integrity references, safe download authorization, and tenant-scoped evidence access.

## 57

`api/v1/assets_discovery.py`
# NEW — Asset discovery API for discovery jobs, discovered assets, ownership/status, source attribution, and discovery history.

## 58

`api/v1/risk.py`
# NEW — Customer risk API for aggregated risk score, severity distribution, risk trends, top risk categories, and explainable score components based only on persisted findings.

## 59

`api/v1/remediation.py`
# NEW — Remediation workflow API for assigning findings, changing remediation state, comments, due dates, verification requests, and audit-linked status transitions.

## 60

`api/v1/search.py`
# NEW — Tenant-scoped security search API for assets, findings, scans, reports, evidence, and integrations with bounded filters and pagination.

---

# CORE SECURITY / DOMAIN SERVICES

## 61

`services/asset_service.py`
# NEW — Domain service for asset inventory aggregation, normalization, ownership, lifecycle, duplicate handling, and tenant isolation.

## 62

`services/scan_service.py`
# NEW — Domain service coordinating scan creation, validation, execution handoff, cancellation, idempotency, state transitions, and audit events.

## 63

`services/finding_service.py`
# NEW — Finding lifecycle service for normalization, correlation, severity, deduplication, status changes, assignment, and remediation linkage.

## 64

`services/risk_service.py`
# NEW — Deterministic risk calculation service using persisted findings/assets/context; explainable scoring, versioned formulas, and reproducible outputs.

## 65

`services/evidence_service.py`
# NEW — Evidence service for storage references, integrity hashes, metadata, retention rules, authorization, and safe export/download.

## 66

`services/report_service.py`
# NEW — Report orchestration service for report creation, generation state, immutable snapshots, format selection, retention, and authorization.

## 67

`services/search_service.py`
# NEW — Bounded tenant-scoped search abstraction supporting structured filtering without unrestricted SQL or unbounded scans.

## 68

`services/remediation_service.py`
# NEW — Remediation workflow service implementing state transitions, assignment, deadlines, verification, reopen behavior, and audit records.

## 69

`services/notification_service.py`
# NEW — Higher-level customer notification orchestration above provider adapters; preferences, templates, deduplication, retries, and delivery tracking.

## 70

`services/integration_service.py`
# NEW — Central integration lifecycle service for configuration, validation, health checks, enable/disable, secret rotation, delivery state, and provider capability metadata.

---

# PRODUCTION OPERATIONS / SECURITY

## 71

`services/audit_service.py`
# NEW — Central audit service for immutable security/customer/admin events, actor identity, tenant scope, correlation IDs, event versioning, and safe metadata.

## 72

`services/rate_limit_service.py`
# NEW — Central rate-limit abstraction for authentication, API, scan creation, exports, integration calls, and high-cost operations with tenant-aware limits.

## 73

`services/idempotency_service.py`
# NEW — Persistent idempotency service for API operations and external side effects with bounded retention, request fingerprinting, conflict handling, and replay-safe responses.

## 74

`services/health_service.py`
# MODIFY — Extend dependency health checks for database, worker, queue/job state, integration subsystem, crypto/key management, and external provider availability without leaking secrets.

## 75

`services/observability.py`
# NEW — Structured logging, metrics, tracing/correlation helpers, latency measurements, operation counters, failure classification, and secret-safe event emission.

## 76

`services/backup_service.py`
# NEW — Production-safe backup abstraction for application data/evidence metadata with integrity checks, retention, encryption integration, backup verification, and restore metadata.

## 77

`services/recovery_service.py`
# NEW — Disaster-recovery orchestration for restore validation, dependency recovery, consistency checks, job reconciliation, and recovery-state auditing.

## 78

`services/config_validation.py`
# NEW — Startup/runtime configuration validation for security-sensitive settings, key configuration, database, TLS, authentication, integrations, and production environment requirements.

## 79

`services/retention_service.py`
# NEW — Tenant-aware retention and deletion service for findings, evidence, logs, sessions, jobs, audit data, and integration events while preserving legal/security invariants.

## 80

`services/export_service.py`
# NEW — Secure export service for customer data/security records with authorization, bounded output size, streaming where appropriate, redaction, integrity metadata, and audit logging.

---

# FRONTEND APPLICATION

## 81

`web/src/components/layout/AppShell.tsx`
# NEW — Main authenticated application shell: sidebar/top navigation, tenant context, responsive layout, breadcrumbs, global alerts, and permission-aware navigation.

## 82

`web/src/components/ui/ErrorBoundary.tsx`
# NEW — React error boundary preventing raw internal errors from reaching users; safe fallback UI plus request/correlation identifier where available.

## 83

`web/src/components/ui/LoadingState.tsx`
# NEW — Shared loading/skeleton primitives for pages, tables, cards, detail views, and asynchronous API operations.

## 84

`web/src/components/ui/EmptyState.tsx`
# NEW — Shared empty-state components distinguishing “no data”, “not configured”, “unavailable”, and permission-restricted states.

## 85

`web/src/components/security/RiskSummary.tsx`
# NEW — Customer security risk summary cards/charts using real `/api/v1/risk` data and explicit loading/error/unavailable states.

## 86

`web/src/components/security/FindingTable.tsx`
# NEW — Reusable paginated/filterable finding table with severity, status, asset, owner, due date, timestamps, and permission-aware actions.

## 87

`web/src/components/security/AssetTable.tsx`
# NEW — Reusable asset inventory table with source, type, status, ownership, last-seen data, filtering, pagination, and safe detail navigation.

## 88

`web/src/components/security/ScanStatus.tsx`
# NEW — Scan lifecycle/progress component using real scan API state, cancellation support, failure states, and polling/backoff behavior without fake progress.

## 89

`web/src/components/security/FindingDetail.tsx`
# NEW — Finding detail/evidence/remediation view with severity explanation, affected assets, evidence references, timeline, permissions, and workflow actions.

## 90

`web/src/pages/ReportsPage.tsx`
# NEW — Customer reports page for listing, filtering, generating, viewing status, and authorized downloading of real security reports.

---

# TESTING / DEPLOYMENT / OBSERVABILITY / DOCUMENTATION

## 91

`tests/test_api_resources_51_60.py`
# NEW — Complete API tests for projects, organizations, roles, sessions, notifications, evidence, asset discovery, risk, remediation, and search endpoints.

## 92

`tests/test_security_services_61_70.py`
# NEW — Complete service-level tests for assets, scans, findings, risk, evidence, reports, search, remediation, notifications, and integration lifecycle.

## 93

`tests/test_operations_71_80.py`
# NEW — Tests for audit, rate limiting, idempotency, health, observability, backup, recovery, configuration validation, retention, and exports.

## 94

`tests/test_tenant_isolation_end_to_end.py`
# NEW — Cross-service/API end-to-end tenant isolation tests proving tenant A cannot access tenant B resources, evidence, reports, scans, integrations, metrics, or audit records.

## 95

`tests/test_security_regressions_51_100.py`
# NEW — Security regression suite covering secret leakage, privilege escalation, path manipulation, malformed requests, replay/idempotency abuse, rate-limit bypass, unauthorized exports, and unsafe provider behavior.

## 96

`tests/test_frontend_security_51_100.tsx`
# NEW — Frontend tests for route guards, permission-aware rendering, API error handling, session expiration, tenant switching prevention, and sensitive-data rendering.

## 97

`web/src/pages/AssetsPage.tsx`
# NEW — Customer asset inventory page with discovery controls, filtering, pagination, details, ownership/state, and safe empty/error/unavailable states.

## 98

`web/src/pages/IntegrationsPage.tsx`
# NEW — Customer integrations page for configuring supported integrations, status/health, enable/disable, secret rotation, validation, and provider capability display.

## 99

`web/src/pages/UsersPage.tsx`
# NEW — Customer user-management page for members, roles, invitations/status where supported, session controls, permission visibility, and audit-linked privilege changes.

## 100

`web/src/pages/AuditPage.tsx`
# NEW — Customer audit/security-event explorer with bounded search, actor/action/resource filters, timestamps, request IDs, pagination, safe metadata display, and export permissions.

---

# API CONTRACT RULE

Every new API endpoint must:

- use the central API router;
- use central authentication/middleware;
- enforce tenant scope;
- enforce permission checks;
- use stable response/error structures;
- use request IDs;
- support bounded pagination;
- validate user input;
- reject unknown fields where appropriate;
- avoid arbitrary SQL;
- avoid arbitrary filesystem access;
- avoid unbounded exports;
- write security-sensitive mutations to the audit trail.

No endpoint may instantiate a second authentication/tenant system.

---

# SERVICE LAYER RULE

Business logic belongs in the service layer.

API modules must NOT:

- duplicate database algorithms;
- calculate risk independently;
- directly manipulate provider credentials;
- bypass audit logging;
- bypass authorization;
- implement their own retry systems;
- implement their own encryption;
- create alternate persistence formats.

Use:

```text
API
 ↓
middleware/auth
 ↓
service
 ↓
existing domain engine / repository
 ↓
storage/provider
```

not:

```text
API
 ↓
custom direct database logic
```

---

# FRONTEND RULES

The frontend must consume actual API responses.

Never use hard-coded mock security data in production components.

Acceptable UI states:

```text
loading
empty
configured
not_configured
unavailable
error
forbidden
success
```

Do not render:

```text
passwords
tokens
private keys
cloud secrets
encryption keys
```

Do not store privileged long-lived secrets in insecure browser storage.

Preserve the authentication/session model implemented in Files 01–50.

Every customer-facing page must support:

```text
loading
error
empty
unauthorized/forbidden
responsive layout
```

where applicable.

---

# DATABASE / PERSISTENCE RULE

Do not assume SQLite is sufficient merely because existing tests use it.

The implementation should preserve current SQLite compatibility while keeping clean boundaries for production PostgreSQL.

Do not introduce a second independent ORM/database architecture unless required by the existing repository.

All mutations must maintain transaction integrity.

All tenant-scoped queries must include explicit tenant constraints.

---

# EXTERNAL PROVIDER RULE

AWS/Azure/GCP/ticketing/notification integrations must distinguish:

```text
LIVE
NOT_CONFIGURED
UNAVAILABLE
TIMEOUT
RATE_LIMITED
AUTHENTICATION_FAILED
PERMISSION_DENIED
ERROR
```

Never convert provider failure into fake successful data.

Tests may use deterministic fixtures/mocks, but production code must clearly identify fixture/mock mode.

---

# EXPORT RULE

All exports must:

- be tenant scoped;
- be permission checked;
- have bounded size;
- have audit records;
- avoid arbitrary filesystem paths;
- avoid arbitrary SQL;
- redact secrets;
- preserve integrity metadata.

---

# OBSERVABILITY RULE

All high-value customer operations should have:

```text
request_id
tenant_id
operation
actor/principal
start time
duration
result state
safe error class
```

Do not log credentials.

Do not log raw authorization headers.

Do not log full request bodies when they may contain secrets.

---

# TESTING RULE

After Files 51–60:

```text
Run API/resource tests.
Run existing API regression tests.
Run tenant/RBAC tests.
```

After Files 61–70:

```text
Run all affected service tests.
Run database/persistence tests.
Run integration tests.
```

After Files 71–80:

```text
Run security/operations tests.
Run crypto/secret tests.
Run backup/recovery/configuration tests.
```

After Files 81–90:

```text
Run frontend typecheck.
Run lint.
Run frontend unit tests.
Run production build.
```

After Files 91–100:

```text
Run the complete available backend suite.
Run the complete available frontend suite.
Run dependency audit.
Run compile/static checks.
Run git diff --check.
```

Do not claim a test suite passed unless it actually ran.

---

# FULL FILE OUTPUT RULE

For every NEW/MODIFY file:

```text
FILE:
<exact path>

ACTION:
NEW / MODIFY

STATUS:
COMPLETE / BLOCKED

EXISTING LOGIC INSPECTED:
<actual relevant files/usages/tests>

DEPENDENCIES:
<actual dependencies>

FULL CONTENT:
<complete entire final file>

TESTS:
<exact tests>

VERIFICATION:
<exact commands and results>

SECURITY NOTES:
<only verified changes>

UNVERIFIED:
<only what was not actually verified>
```

Never provide only a patch.

Never omit source sections.

Never use ellipsis.

Never claim “complete” when only part of the file was implemented.

---

# FINAL ACCEPTANCE

Files 51–100 are accepted only when:

```text
all requested files exist
+
existing functionality remains intact
+
all APIs use central authentication
+
tenant isolation is tested
+
service logic is centralized
+
secret handling remains secure
+
no fake production integration exists
+
frontend uses real API contracts
+
frontend builds
+
tests execute successfully
+
security regressions are covered
+
all unverified items are explicitly reported
```

The final report must distinguish:

```text
VERIFIED
PARTIALLY VERIFIED
NOT VERIFIED
BLOCKED
```

Never use marketing language as a substitute for test evidence.