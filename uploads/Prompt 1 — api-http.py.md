# PROMPT 1 — Implement `api/http.py` only

Work inside the existing `security-toolkit` repository.

Follow `/first.md` as the master specification. Do NOT redesign the project, create a replacement architecture, or add unrelated features.

## Target file

`api/http.py` # NEW — Real production HTTP entrypoint/WSGI-compatible application adapter; request parsing, response serialization, method handling, content type, request IDs, bounded body sizes, secure defaults, and clean shutdown integration with the existing services.

## Mandatory workflow

Before writing `api/http.py`:

1. Inspect the entire existing API structure.
2. Inspect all existing imports/usages related to:
   - `api.v1`
   - existing health/metadata handlers
   - dashboard HTTP handling
   - authentication/identity
   - tenant context
   - existing request/response helpers
   - logging
   - jobs/workers/services
3. Search the whole repository for every current HTTP entrypoint and every caller that could depend on the new adapter.
4. Inspect relevant existing tests before changing anything.
5. Determine the current Python version and supported runtime assumptions from the repository.
6. Preserve the existing standard-library runtime philosophy unless a dependency is genuinely required.
7. Do not duplicate business logic that already exists elsewhere.

## Required implementation

Create the complete `api/http.py` implementation.

It must provide a production-safe HTTP application adapter that:

- supports the repository's existing Python/runtime constraints;
- provides a real HTTP entrypoint around the versioned API;
- integrates with the existing `api.v1` handlers/router contracts rather than duplicating business logic;
- parses HTTP method, path, query string, headers, and body safely;
- enforces a bounded request-body size;
- validates `Content-Length` safely;
- handles malformed requests deterministically;
- generates or propagates a request ID;
- makes the request ID available to downstream processing;
- serializes JSON responses consistently;
- supports explicit content type handling;
- returns correct status codes;
- handles `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, and `HEAD` only where the existing route contract permits them;
- returns clean `404` and `405` responses;
- does not expose Python tracebacks;
- does not expose raw exception strings;
- does not expose filesystem paths;
- does not expose SQL/database/provider errors;
- does not expose authentication secrets;
- adds appropriate security headers;
- keeps error responses machine-readable and stable;
- supports clean application shutdown;
- does not create fake authentication, fake tenants, fake scan results, or fake provider data;
- fails closed on security-sensitive failures;
- preserves existing API behavior where it already exists.

## Request context requirements

The implementation should integrate with `api/request_context.py` when that file exists later, but do not fabricate an incompatible interface.

For this file, keep the request handling boundary clean enough that the following data can be propagated:

- request ID
- authenticated principal
- tenant ID
- method
- normalized path
- source metadata
- deadline/timeout information

Never place raw:

- password
- API secret
- token
- private key
- provider credential

inside logs or serialized response data.

## Error handling

Define a clear internal exception boundary.

Expected client errors should produce safe structured responses such as:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Invalid request."
  },
  "request_id": "..."
}
```

Do NOT hard-code an error contract that conflicts with an existing repository contract. First inspect existing API response conventions and preserve them when possible.

For unexpected internal failures:

- log the detailed exception internally;
- attach the request ID;
- return a generic server error;
- never return `str(exception)` to the client;
- never return traceback text to the client.

## Security requirements

At minimum account for:

- request smuggling-safe parsing assumptions;
- oversized request bodies;
- malformed `Content-Length`;
- conflicting `Content-Length` headers;
- unsupported transfer/body handling;
- header injection;
- response header injection;
- path normalization issues;
- encoded path traversal;
- invalid UTF-8 where relevant;
- unsafe JSON parsing;
- request timeout/deadline propagation;
- authentication boundary enforcement;
- tenant boundary preservation;
- secret-safe logging.

Do not claim complete RFC compliance unless it is actually implemented and tested.

## Compatibility requirements

Before changing behavior:

- inspect all existing callers;
- inspect any existing WSGI/HTTP adapter;
- inspect dashboard behavior;
- inspect health and metadata endpoints;
- inspect existing API tests.

If an existing behavior must be preserved, preserve it.

Do not silently delete or replace existing exports.

## Tests

Create/update only the tests that are genuinely required for `api/http.py`.

At minimum test:

1. basic valid request;
2. JSON request parsing;
3. JSON response serialization;
4. unsupported method;
5. missing route;
6. malformed JSON;
7. oversized request body;
8. invalid `Content-Length`;
9. request ID generation;
10. supplied request ID propagation, subject to the repository's safe-header rules;
11. unexpected exception redaction;
12. security headers;
13. authentication failure behavior;
14. tenant-scope propagation;
15. clean shutdown behavior;
16. regression behavior for any existing HTTP compatibility path discovered during inspection.

Do not delete or weaken existing tests.

## Full-file rule

When returning the result:

- provide the COMPLETE `api/http.py`;
- do not use `...`;
- do not use `# existing code`;
- do not use `# rest of file`;
- do not use `TODO`;
- do not use `FIXME`;
- do not leave required branches as `pass`;
- do not omit imports;
- do not omit helper classes/functions;
- do not provide a diff instead of the full file.

If tests are changed, provide the COMPLETE changed test file(s) as well.

## Verification

Run:

1. the targeted `api/http.py` tests;
2. related API tests;
3. any existing dashboard/API regression tests affected by the implementation;
4. Python compilation/type/syntax checks used by the repository.

Do not claim full-suite success unless the full suite is actually executed.

Report exact:

- commands;
- test counts;
- failures;
- errors;
- skips;
- runtime.

## Required final report

Use exactly this structure:

FILE:
`api/http.py`

ACTION:
`NEW`

DEPENDENCIES:
List the actual modules inspected and used.

FULL CONTENT:
Provide the complete final `api/http.py`.

TESTS:
List exact test files/cases added or modified.

VERIFICATION:
List exact commands and exact results.

SECURITY NOTES:
List only security changes that were actually implemented and verified.

UNVERIFIED:
Explicitly state anything that could not be verified.

Do not claim the file is production-ready unless the verification actually supports that statement.