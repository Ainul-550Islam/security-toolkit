# native/cpp

Minimal, buildable C++ foundation library (`security_engine`).

## Scope

**In scope:** bounded buffer inspection — safe indexed access, substring
search, Shannon entropy, hex rendering, constant-time comparison.

**Explicitly out of scope:**

* no network listeners or connections
* no process execution (`system`, `exec`, `popen`)
* no filesystem access
* no fake scanning: nothing here claims to detect a vulnerability it does not
  actually compute

## Safety posture

* **RAII / rule of zero.** `Buffer` owns a `std::vector`; there is no `new`,
  `delete`, `malloc` or `free` anywhere in the library.
* **Bounds enforced at construction.** A `Buffer` over 1 MiB throws
  `std::length_error`, so any `Buffer` that exists is already within bounds.
* **No raw pointer arithmetic.** Lookups return `std::optional`, so an
  out-of-range read is a `nullopt`, not undefined behaviour.
* **Hardened build flags.** `-Wall -Wextra -Wpedantic -Wconversion
  -Wold-style-cast -fstack-protector-strong -D_FORTIFY_SOURCE=2`, plus
  `-Wl,-z,relro -Wl,-z,now`. The library builds warning-free under these.
* C++17, no external dependencies.

## Build and test

```sh
cmake -S native/cpp -B native/cpp/build
cmake --build native/cpp/build
./native/cpp/build/security_engine_tests    # or: ctest --test-dir native/cpp/build
```

`build/` is a generated directory and is git-ignored.

## Status

Like the Rust crate, this library has **no Python binding** in PART 01.
`security_engine::health()` therefore returns `kUnavailable` with that exact
reason, and `services/engine_registry.py` reports `cpp_core` as unavailable.
