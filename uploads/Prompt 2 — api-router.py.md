# PROMPT 2 — Implement `api/router.py` only

Work inside the existing `security-toolkit` repository.

Follow `/first.md` as the master specification. Do NOT create a replacement architecture, duplicate the existing security engine, or add unrelated functionality.

## Target file

`api/router.py` # NEW — Central production route registration and dispatch layer for `/api/v1`; strict path matching, method validation, authentication boundary, tenant extraction, route metadata, 404/405 handling, and deterministic dispatch to existing/new endpoint handlers without duplicating business logic.

## Mandatory workflow

Before writing `api/router.py`:

1. Read `/first.md` completely.
2. Inspect the entire existing API implementation.
3. Inspect:
   - `api/v1/health.py`
   - `api/v1/metadata.py`
   - all existing API modules
   - dashboard route handling
   - authentication/identity code
   - tenant-related code
   - RBAC/permission checks
   - request/response conventions
   - existing tests
4. Search the entire repository for:
   - existing route registration
   - URL/path dispatch
   - HTTP method dispatch
   - `/api/v1`
   - health endpoints
   - metadata endpoints
   - authentication entrypoints
   - tenant extraction
5. Identify every existing public interface that could be affected.
6. Preserve all compatible existing behavior.

Do not assume that files 11–20 already exist. This router must be designed so later endpoint modules can register cleanly without fake endpoints being created now.

## Core requirements

Implement a typed central router that:

- accepts the normalized request representation from `api/http.py`;
- returns a deterministic route match;
- separates route matching from business logic;
- supports `/api/v1/...`;
- supports existing health endpoints;
- supports existing metadata endpoints;
- supports future resource modules without requiring router redesign;
- rejects unknown routes with safe `404`;
- rejects unsupported methods with safe `405`;
- exposes an `Allow` header where appropriate;
- performs strict path matching;
- does not accidentally prefix-match unrelated routes;
- normalizes only what is safe and explicitly supported;
- does not perform unsafe URL decoding;
- prevents path traversal-style ambiguities;
- preserves route parameters in structured form;
- supports query strings separately from path matching;
- keeps query/body parsing outside the route matcher where possible.

## Route registration

Provide a deterministic route registration mechanism.

Each route should have enough metadata to support:

- HTTP method(s)
- normalized path/template
- handler
- route name
- API version
- authentication requirement
- tenant requirement
- required permission/scope
- allowed content types if applicable
- route parameter definitions

Do not create fake handlers for resources that do not yet exist.

For future routes, expose a clean registration interface so files such as:

```text
api/v1/tenants.py
api/v1/users.py
api/v1/assets.py
api/v1/scans.py
api/v1/findings.py
api/v1/reports.py
api/v1/integrations.py
api/v1/audit.py
api/v1/metrics.py
api/v1/admin.py
```

can register their real handlers when they are implemented.

## Existing endpoints

Preserve and register the real existing endpoints discovered during repository inspection.

At minimum investigate:

```text
/api/v1/health/...
/api/v1/metadata/...
```

Do not invent endpoint paths merely because they appear desirable in `/first.md`.

The final route table must reflect actual implemented handlers only.

## Authentication boundary

The router must not implement a second authentication system.

It must expose route metadata allowing `api/middleware.py` and `api/auth.py` to enforce:

- public route;
- authenticated route;
- tenant-scoped route;
- platform-admin route.

Do not bypass existing identity/RBAC logic.

Do not put raw tokens, passwords, API keys, session secrets, or credentials into route metadata.

## Tenant boundary

Tenant requirements must be explicit.

A tenant-scoped route must provide enough metadata for downstream middleware/service layers to enforce:

```text
authenticated principal
        +
tenant context
        +
permission/scope
```

Never infer tenant identity from an arbitrary client-controlled value without validating it against the authenticated principal.

Never allow a route to silently switch tenant context.

## Method handling

Correctly distinguish:

- `404 Not Found`
- `405 Method Not Allowed`

Examples:

```text
GET /api/v1/unknown
→ 404

POST /api/v1/existing-get-only-route
→ 405
Allow: GET
```

Do not reveal whether unrelated private/internal routes exist.

## Trailing slash behavior

Inspect current repository conventions first.

Then implement one deterministic policy.

Do not silently accept unlimited path variants.

Do not make route matching ambiguous between:

```text
/api/v1/example
/api/v1/example/
```

Preserve an existing compatibility behavior only when it is actually present and tested.

## Route parameters

Support structured path parameters where required, for example:

```text
/api/v1/tenants/{tenant_id}
/api/v1/scans/{scan_id}
/api/v1/findings/{finding_id}
```

But do not add these routes until corresponding handlers actually exist.

Validate parameter syntax at the routing boundary where appropriate.

Do not convert arbitrary path text into UUID/int/etc. unless the endpoint contract actually requires that type.

## Security requirements

The router must defend against:

- path traversal ambiguity
- double decoding
- encoded slash ambiguity
- malformed percent-encoding
- empty path segments
- duplicate/ambiguous route registrations
- route shadowing
- accidental catch-all routes
- unsafe wildcard routes
- route parameter injection
- host-dependent routing
- unauthorized internal endpoints
- method confusion
- inconsistent trailing-slash matching

Do not perform security filtering that belongs in HTTP parsing or middleware unless a minimal route-level check is required.

## Error behavior

The router should return structured route errors that `api/errors.py` can later translate.

Do not expose:

- traceback
- filesystem paths
- Python exception strings
- database details
- internal module names
- credentials

Do not hard-code final public JSON formatting if the repository already has a response/error abstraction.

## API versioning

Keep:

```text
/api/v1
```

as an explicit version boundary.

Do not create `/api/v2`.

Do not mix unversioned customer API routes into the new versioned router unless an existing compatibility route requires it.

Make version metadata deterministic so `api/openapi.py` can later inspect the same route registry.

## OpenAPI compatibility

The route structure must expose enough metadata for:

`api/openapi.py`

to later generate:

- path
- method
- operation/route name
- authentication requirement
- tenant requirement
- permissions/scopes
- parameter names
- handler identity

Do not duplicate OpenAPI documents manually inside this file.

## Performance

Route matching should be deterministic and reasonably efficient.

Avoid:

- scanning the entire application state on every request when avoidable;
- database access during route matching;
- network calls during route matching;
- loading large security datasets;
- expensive regex processing on attacker-controlled paths.

The router must remain a pure/near-pure dispatch layer.

## Compatibility

Do not silently delete existing exports/functions.

If an old route system exists:

1. inspect all callers;
2. preserve compatible behavior;
3. introduce a compatibility wrapper if required;
4. add regression tests;
5. document the compatibility path in the implementation.

Do not rewrite unrelated dashboard routes.

## Tests

Create/update the complete relevant test file(s).

At minimum verify:

1. exact route match;
2. unknown route → 404;
3. unsupported method → 405;
4. correct `Allow` methods;
5. existing health route;
6. existing metadata route;
7. route parameter extraction;
8. encoded-path edge cases;
9. malformed percent-encoding;
10. duplicate route registration detection;
11. route shadowing detection;
12. tenant-required metadata;
13. authentication-required metadata;
14. platform-admin-only metadata;
15. deterministic route table;
16. future endpoint registration API;
17. no fake/unimplemented handler registration;
18. regression for every existing route discovered during inspection.

Do not weaken any existing test.

## Full-file rule

When returning the result:

- provide the COMPLETE `api/router.py`;
- never use `...`;
- never use `# existing code`;
- never use `# rest of file`;
- never use `# omitted`;
- never use `TODO`;
- never use `FIXME`;
- never use placeholder handlers;
- do not omit imports;
- do not omit types;
- do not provide only a diff.

If tests are changed, provide the COMPLETE changed test file(s).

## Verification

Run:

1. targeted router tests;
2. existing API tests;
3. health/metadata tests;
4. authentication/RBAC tests affected by routing;
5. Python syntax/compile checks;
6. any existing HTTP/API regression suite that the repository provides.

Do not claim the complete backend suite passes unless you actually run it.

Report exact:

- command;
- number of tests;
- failures;
- errors;
- skips;
- runtime.

## Required final response from the coding agent

Use:

FILE:
`api/router.py`

ACTION:
`NEW`

EXISTING CODE INSPECTED:
List the actual route/API/auth/tenant/RBAC files inspected.

ROUTES REGISTERED:
List only routes that actually exist in the current implementation.

FULL CONTENT:
Provide the complete final `api/router.py`.

TESTS:
List exact test files/cases created or modified.

VERIFICATION:
Provide exact commands and exact results.

SECURITY NOTES:
Describe only implemented and verified protections.

UNVERIFIED:
Explicitly list anything not tested or not verifiable.

Do not claim “complete”, “production-ready”, or “all green” unless current execution proves it.