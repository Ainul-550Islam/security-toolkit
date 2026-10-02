//! Foundation primitives for the security toolkit.
//!
//! # Scope
//!
//! Pure, deterministic computation. This crate performs **no** I/O: no
//! sockets, no files, no process execution, no environment access. That is a
//! deliberate security boundary, not an accident of the current feature set —
//! a component that cannot reach the network cannot exfiltrate, and a
//! component that cannot spawn a process cannot be turned into a shell.
//!
//! `unsafe` is forbidden at the crate root, so the compiler enforces memory
//! safety for everything here.

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    unused_must_use,
    clippy::all
)]
#![warn(rust_2018_idioms)]

pub mod bytes;
pub mod health;
pub mod version;

pub use health::{EngineHealth, HealthStatus};
pub use version::{ENGINE_NAME, SCHEMA_VERSION, VERSION};

/// Errors produced by this crate.
///
/// Variants deliberately carry bounded, non-sensitive context: an error that
/// echoes attacker-controlled input back into a log is its own problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// An input exceeded a configured bound.
    InputTooLarge {
        /// Size supplied by the caller, in bytes.
        actual: usize,
        /// Maximum accepted size, in bytes.
        limit: usize,
    },
    /// An input was empty where content is required.
    EmptyInput,
    /// A pattern was longer than the haystack, or otherwise unusable.
    InvalidPattern,
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EngineError::InputTooLarge { actual, limit } => {
                write!(f, "input of {actual} bytes exceeds the {limit} byte limit")
            }
            EngineError::EmptyInput => write!(f, "input is empty"),
            EngineError::InvalidPattern => write!(f, "pattern is invalid for this input"),
        }
    }
}

impl std::error::Error for EngineError {}

/// Result alias used across the crate.
pub type Result<T> = core::result::Result<T, EngineError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_are_bounded_and_descriptive() {
        let err = EngineError::InputTooLarge { actual: 10, limit: 5 };
        assert_eq!(err.to_string(), "input of 10 bytes exceeds the 5 byte limit");
        assert_eq!(EngineError::EmptyInput.to_string(), "input is empty");
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(EngineError::EmptyInput, EngineError::EmptyInput);
        assert_ne!(EngineError::EmptyInput, EngineError::InvalidPattern);
    }
}
