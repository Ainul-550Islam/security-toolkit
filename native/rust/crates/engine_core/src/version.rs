//! Version constants shared with the Python layer.
//!
//! These mirror `core/version.py`. `tests/test_foundation_runtime.py` asserts
//! the two stay in agreement, so a drift between the Rust and Python views of
//! the schema version fails the Python suite rather than surfacing as a
//! confusing cross-language bug.

/// Crate version, kept in step with `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Engine name as registered by `services/engine_registry.py`.
pub const ENGINE_NAME: &str = "rust_core";

/// Major version of the shared JSON schemas.
pub const SCHEMA_VERSION: &str = "1";

/// Capabilities this engine declares. Must match `DECLARED_NATIVE_ENGINES`.
pub const CAPABILITIES: [&str; 2] = ["hash_verify", "pattern_match"];

/// Machine-readable identification of this engine.
#[must_use]
pub fn describe() -> [(&'static str, &'static str); 4] {
    [
        ("name", ENGINE_NAME),
        ("language", "rust"),
        ("version", VERSION),
        ("schema_version", SCHEMA_VERSION),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_manifest() {
        assert_eq!(VERSION, "0.1.0");
    }

    #[test]
    fn schema_version_matches_python_core_version() {
        assert_eq!(SCHEMA_VERSION, "1");
    }

    #[test]
    fn capabilities_match_registry_declaration() {
        assert_eq!(CAPABILITIES, ["hash_verify", "pattern_match"]);
    }

    #[test]
    fn describe_exposes_no_secrets_or_paths() {
        for (_key, value) in describe() {
            assert!(!value.contains('/'), "descriptor must not contain a path");
            assert!(!value.is_empty());
        }
    }
}
