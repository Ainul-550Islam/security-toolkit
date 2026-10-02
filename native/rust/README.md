# native/rust

Memory-safe, CPU-bound primitives for the security toolkit.

## Scope

**In scope:** pure computation — hashing, constant-time comparison, byte
pattern matching, bounded parsing.

**Explicitly out of scope, enforced by lint and by review:**

* no network listeners or outbound connections
* no process execution
* no filesystem access
* no `unsafe` (`#![forbid(unsafe_code)]` at the crate root)

The crate has **zero dependencies**, so there is no third-party supply chain
to audit at this layer.

## Build and test

```sh
cargo check --manifest-path native/rust/Cargo.toml
cargo test  --manifest-path native/rust/Cargo.toml
```

## Status

PART 01 ships the crate and its tests only. There is **no** Python binding
yet: no `cdylib`, no PyO3, no ctypes bridge. `services/engine_registry.py`
therefore reports `rust_core` as `unavailable` with that reason rather than
pretending the engine is wired up.
