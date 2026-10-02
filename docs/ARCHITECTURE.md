# Architecture

## Layers

```
                 +-------------------------------+
   clients  -->  |  api/v1  (transport-agnostic) |
                 +---------------+---------------+
                                 |
                 +---------------v---------------+
                 |  services/  (orchestration)   |
                 |  engine_registry, health,     |
                 |  capability                   |
                 +---------------+---------------+
                                 |
        +------------------------+------------------------+
        |                        |                        |
+-------v--------+     +---------v---------+    +---------v---------+
|  interfaces/   |     |     config/       |    |      core/        |
|  contracts     |     |  settings, flags, |    |  clock, paths,    |
|  (Protocols)   |     |  logging          |    |  ids, errors      |
+-------+--------+     +-------------------+    +-------------------+
        |
        | implemented by
        |
+-------v-----------------------------------------------------------+
|  python/ (legacy domain services)   native/rust   native/cpp       |
+--------------------------------------------------------------------+
```

Dependencies point **inward**. `core/` imports nothing from the project.
`interfaces/` imports only `core/`. `services/` imports `interfaces/`,
`config/` and `core/`. `api/` imports `services/`. Nothing in the foundation
imports the legacy `python/` package, which is why `core/errors.py` is
separate from `python/errors.py` rather than replacing it.

## Why the foundation is independent of `python/`

The existing `python/` package is a working system covering scanning,
findings, cases, integrations and federation. Rewriting it would risk
regressions across 955 passing tests for no functional gain. Instead the
foundation sits beside it:

* new code depends on the foundation contracts;
* legacy code keeps working untouched;
* migration happens module by module, each step verifiable.

## Key components

### `core/clock.py`

Time is injectable. `SystemClock` in production, `FixedClock` in tests. All
instants are timezone-aware UTC; naive datetimes are rejected rather than
assumed. Expiry uses `to_epoch()` (UTC) — never `time.mktime()`, which
interprets its argument as **local** time and therefore shifts every
expiry check by the host's timezone offset.

### `core/paths.py`

`safe_join()` resolves symlinks *before* the containment check, so a symlink
inside the workspace pointing outside it cannot pass. Rejects `..`, absolute
components, drive-qualified paths and control characters (a NUL can truncate
a path at the OS boundary).

### `config/logging.py`

Redaction lives in a `logging.Filter` on the handler, not at call sites. Call
sites are forgotten; a handler filter scrubs every record regardless of who
emitted it. Two strategies: by key name, and by value shape (bearer tokens,
PEM blocks, cookies, provider token prefixes, JWTs).

### `services/engine_registry.py`

Models engines across languages with name, version, language, capabilities,
health, error and execution mode. Registration is explicit — there is no
import-scanning auto-discovery, because importing modules to find engines is
a code-execution surface. An engine that cannot load is registered as
`unavailable` **with a reason**.

### `services/health_service.py`

Liveness never consults dependencies (a database blip must not restart every
pod). Readiness does, and fails closed. Optional dependency failures produce
`degraded`, not `unavailable`.

## Error handling

`core/errors.py` defines one hierarchy under `FoundationError`, each carrying
a machine-readable `code` and a `context` dict. `core/result.py` offers
`Ok`/`Err` for paths where exceptions are the wrong control flow.
`Err.from_exception` records the exception **type** only, so an arbitrary
exception message cannot carry a connection string into a log.
