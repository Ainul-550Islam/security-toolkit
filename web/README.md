# SecuToolkit customer web application

This folder contains the React and TypeScript customer UI for the existing SecuToolkit API. It uses real `/api/v1` resources and does not include mock scan results, demo findings, fabricated integration health, or client-side authorization decisions.

## Development

Prerequisites: Node.js 20.19 or newer and npm.

```sh
cd web
npm ci
npm run dev
```

The development server binds to `0.0.0.0`. API requests remain relative to the browser origin and the Vite development server proxies `/api/v1` to `SECURITY_TOOLKIT_API_PROXY`. The default proxy origin is `http://127.0.0.1:8080`; set the environment variable to an HTTP(S) origin if the API listens elsewhere. The value must not contain credentials, a path, query, or fragment.

```sh
SECURITY_TOOLKIT_API_PROXY=http://127.0.0.1:8080 npm run dev
```

Useful checks:

```sh
npm run typecheck
npm run lint
npm test
npm run build
```

`npm run build` writes the static application to `dist/`. A deployed web server or reverse proxy must serve the static files and route `/api/v1` to the API on the same origin. The production bundle does not contain an API origin or credentials. `vite preview` serves the static build; configure a real same-origin API reverse proxy for a deployed environment.

## Customer workflows

- **Overview:** project dashboard, recent scans, assets, findings, integration health, and tenant-filtered audit activity.
- **Scans:** API-supported scan profile discovery, authorized scan creation, queue/history filters, status details, and permission-gated pause, resume, and cancel operations.
- **Findings:** server-filtered findings, search and sort, detail/evidence metadata, server-validated lifecycle updates, and ticket upsert/close when an enabled ticketing integration and permissions are available.
- **Settings:** tenant/project metadata, tenant user and session views, user creation/role/status actions, integrations, notification destinations, security/API-access visibility, and tenant audit events. Capabilities without a corresponding API operation are explicitly read-only or unavailable.

The browser does not invent provider credentials, mark an unconfigured integration healthy, or simulate unsupported organization/security preference and API-credential-management operations. Email delivery depends on a deployment adapter. MFA-required sign-in fails closed because this API session flow does not expose an MFA challenge/verification route.

## Authentication and data handling

- Bearer access tokens are held in JavaScript module memory only. They are not written to local storage, session storage, IndexedDB, or cookies; refreshing/closing the page requires a new sign-in.
- Requests use relative `/api/v1` paths, omit browser credentials/cookies, disable caching, reject redirects, use bounded timeouts, and carry request IDs.
- API errors are rendered from a local code-to-message map. Server-supplied exception and field-message strings are not displayed. Server-side RBAC, tenant/project ownership, validation, and secret redaction remain authoritative.
- Notification secrets are write-only. Integration forms accept credential references, not raw provider credentials.
- The HTML shell sets a restrictive CSP meta policy. Production deployments should also send appropriate security headers, including CSP, from the serving HTTP server.

## Dependencies

All direct package versions are pinned exactly in `package.json`; `package-lock.json` records the resolved dependency tree. React/Vite/TypeScript provide the UI and build, Vitest verifies the API client, auth/session behavior, and customer-page states in a browser-like DOM, and ESLint plus the React Hooks plugin enforce source checks. The pinned `jsdom` package is development-only and is not included in the production bundle. No CDN, font service, or additional runtime frontend library is required.
