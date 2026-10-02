//! Engine health vocabulary, mirroring `core/constants.py` and
//! `schemas/health.schema.json`.

/// Health of an engine. `Unknown` is the honest initial state: nothing has
/// been checked yet, and it is never folded into "healthy".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthStatus {
    /// Fully operational.
    Healthy,
    /// Not yet checked.
    Unknown,
    /// Operating with reduced function.
    Degraded,
    /// Not usable.
    Unavailable,
}

impl HealthStatus {
    /// Wire representation used by the JSON schemas.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Unknown => "unknown",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unavailable => "unavailable",
        }
    }

    /// True only for `Healthy`. Anything else, including `Unknown`, is not.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
}

impl Default for HealthStatus {
    /// Fail-closed default: an unchecked engine is `Unknown`, not `Healthy`.
    fn default() -> Self {
        HealthStatus::Unknown
    }
}

/// Health of the engine together with a short, non-sensitive explanation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineHealth {
    /// Current status.
    pub status: HealthStatus,
    /// Short human-readable detail. Never contains credentials or paths.
    pub detail: String,
}

impl EngineHealth {
    /// Construct a healthy report.
    #[must_use]
    pub fn healthy() -> Self {
        Self { status: HealthStatus::Healthy, detail: String::new() }
    }

    /// Construct an unavailable report with a stated reason.
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self { status: HealthStatus::Unavailable, detail: reason.into() }
    }

    /// Fold two reports, keeping the worse of the two.
    #[must_use]
    pub fn worst_of(self, other: Self) -> Self {
        if other.status > self.status { other } else { self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_unknown_not_healthy() {
        assert_eq!(HealthStatus::default(), HealthStatus::Unknown);
        assert!(!HealthStatus::default().is_healthy());
        assert!(!EngineHealth::default().status.is_healthy());
    }

    #[test]
    fn wire_strings_match_the_json_schema_enum() {
        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Unavailable.as_str(), "unavailable");
        assert_eq!(HealthStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn folding_keeps_the_worst_status() {
        let folded = EngineHealth::healthy().worst_of(EngineHealth::unavailable("no binding"));
        assert_eq!(folded.status, HealthStatus::Unavailable);
        assert_eq!(folded.detail, "no binding");
    }

    #[test]
    fn folding_a_healthy_into_healthy_stays_healthy() {
        let folded = EngineHealth::healthy().worst_of(EngineHealth::healthy());
        assert!(folded.status.is_healthy());
    }
}
