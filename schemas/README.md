# Schemas

Language-neutral JSON Schemas (draft 2020-12) defining the contracts shared by
the Python, Rust, C++ and TypeScript layers.

| File | Contract | Python mirror |
|---|---|---|
| `event.schema.json` | Canonical telemetry/audit event | `interfaces/telemetry.py` |
| `finding.schema.json` | Defensive assessment result | `interfaces/scanner.py` |
| `health.schema.json` | Health / readiness report | `services/health_service.py` |

## Versioning

`schema_version` is the **major** version and appears in every event.

* **Additive, backward-compatible** changes (a new optional property, a new
  enum member that older consumers may ignore) keep the same `$id` and the
  same `schema_version`.
* **Breaking** changes (removing or renaming a property, tightening a type,
  removing an enum member) require a new directory and a new `$id`
  (`.../v2/...`) and a new `schema_version` value. Producers and consumers
  are then migrated independently; both versions are served during the
  overlap.

`additionalProperties: false` is set deliberately: an unexpected key is a
contract violation and is far more likely to be a bug or an injection attempt
than a useful extension. Extensions belong under `metadata`.

## Time

Every timestamp is UTC, RFC 3339, with a literal trailing `Z`. The regex
patterns enforce this, so a local or naive timestamp fails validation rather
than being silently misinterpreted across timezones.

## Secrets

No schema has a field intended for credential material.
`finding.evidence_excerpt` is the closest and is explicitly documented as
requiring masking before population. `interfaces/telemetry.py` actively
rejects credential-shaped metadata keys at the producer.

## Validation

`tests/test_schemas.py` validates the schemas themselves (well-formed JSON,
required metadata, closed enums) and checks that the Python dataclasses
produce documents matching the declared shape. A full `jsonschema` validator
is not a runtime dependency; the structural checks are hand-written so the
foundation stays dependency-free.
