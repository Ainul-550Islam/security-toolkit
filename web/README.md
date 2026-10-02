# web/

Reserved for the TypeScript user interface. **No implementation exists yet.**

This directory is a placeholder with a documented contract, not a stub that
pretends to work. There is no build, no `package.json` and no dependency tree
to audit at this time.

## Planned responsibilities

Rendering only: dashboards, findings lists, engine status, health.

## Rules the UI will follow

* **No security decisions client-side.** Authorization, redaction, validation
  and policy evaluation happen on the server. A client-side check is a
  usability affordance an attacker skips.
* **No secrets in the bundle.** No API keys, tokens or credentials in
  TypeScript source, environment files or the build output. Anything shipped
  to a browser is public.
* **Consume `api/v1` only**, through the versioned JSON contracts in
  `schemas/`.
* **Render, never evaluate.** No `eval`, no `dangerouslySetInnerHTML` with
  server data, no dynamic script injection.

## Status

Nothing here is implemented. When work begins, this README is replaced with
real setup instructions and the dependency tree is justified in
`docs/SECURITY_MODEL.md`.
