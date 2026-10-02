# Operations

## Configuration

All configuration comes from environment variables prefixed `SECTOOLKIT_`.
See `.env.example` for the full list. Every security-relevant setting defaults
to the restrictive value.

| Variable | Default | Notes |
|---|---|---|
| `SECTOOLKIT_ENV` | `development` | `development` \| `test` \| `production` |
| `SECTOOLKIT_BIND_HOST` | `127.0.0.1` | `0.0.0.0` needs an opt-in; refused in production |
| `SECTOOLKIT_BIND_PORT` | `8000` | 1-65535 |
| `SECTOOLKIT_AUTH_REQUIRED` | `true` | Cannot be false in production |
| `SECTOOLKIT_TLS_REQUIRED` | `true` | Cannot be false in production |
| `SECTOOLKIT_DEBUG` | `false` | Cannot be true in production |
| `SECTOOLKIT_LOG_LEVEL` | `INFO` | |
| `SECTOOLKIT_LOG_FORMAT` | `json` | `json` in production |
| `SECTOOLKIT_SECRETS_PROVIDER` | `env` | Note the plural — see below |

**Naming note:** the provider selector is `SECTOOLKIT_SECRETS_PROVIDER`
(plural). The singular `SECTOOLKIT_SECRET_` prefix is reserved for secret
*material* resolved by `interfaces/secrets.py`, so a setting under that prefix
would be indistinguishable from a secret.

Invalid configuration raises at startup rather than degrading silently. An
empty value for a required setting is an **error**, not a request for the
default.

## Health probes

| Endpoint | Purpose | Codes |
|---|---|---|
| `/api/v1/livez` | Process alive. Never consults dependencies. | 200 |
| `/api/v1/readyz` | Safe to route traffic. Fails closed. | 200 / 503 |
| `/api/v1/healthz` | Operator detail. | 200 / 503 |

Wire **liveness** to the restart probe and **readiness** to the traffic probe.
Pointing the liveness probe at a dependency-checking endpoint turns a brief
database outage into a restart storm.

Statuses: `healthy`, `degraded` (serving with reduced function — e.g. native
engines unavailable), `unavailable`, `unknown` (nothing checked yet; never
treated as healthy).

Health responses contain no credentials, connection strings, hostnames or
paths. Dependency failures are reported by category ("probe raised
ConnectionError"), never as raw exception text.

## Logging

JSON to stderr by default, with UTC timestamps and automatic redaction. Ship
stderr to your log aggregator; do not add a second handler to the
`security_toolkit` logger, since a handler without `RedactionFilter` would
emit unredacted records.

`propagate` is disabled deliberately to prevent duplicate, unredacted output
through an inherited root handler.

## Native engines

The Rust crate and C++ library build independently of the Python application
and are **not loaded at runtime** in this release. `/api/v1/capabilities`
reports them as `unavailable` with a reason. Readiness is unaffected — their
absence yields `degraded`, not a failed probe.

## Filesystem

Runtime directories are created with mode `0o700` (`core/paths.ensure_directory`).
`data/` holds databases and generated keys and is git-ignored; back it up and
restrict its permissions like any credential store.

## Upgrades

Schemas are versioned (`schema_version: "1"`, `api/v1`). Additive changes keep
the version; breaking changes introduce `v2` and both are served during the
overlap. Check `CHANGELOG.md` before upgrading.
