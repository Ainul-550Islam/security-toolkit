#!/usr/bin/env python3
# ============================================================================
#  metrics.py — lightweight in-process metrics foundation (Phase 3).
#  ---------------------------------------------------------------------------
#  NOT Prometheus/Grafana: simple monotonic counters + duration accumulators
#  used by the worker for observability and by `scan-worker status`. Thread
#  safe, bounded (fixed vocabulary), no external dependencies.
# ============================================================================

from __future__ import annotations

import threading
import time

_COUNTERS = {
    "jobs_created": 0,
    "jobs_queued": 0,
    "jobs_claimed": 0,
    "jobs_completed": 0,
    "jobs_failed": 0,
    "jobs_retried": 0,
    "jobs_cancelled": 0,
    "jobs_paused": 0,
    "jobs_resumed": 0,
    "jobs_stale": 0,
    "jobs_dead_lettered": 0,
    "stages_completed": 0,
    "stages_failed": 0,
    "stages_skipped": 0,
    "scans_completed": 0,
    "scans_failed": 0,
    "audit_failures": 0,
    # Phase 10 — security operations / threat intelligence counters
    "phase10_indicators": 0,
    "phase10_feed_imports": 0,
    "phase10_feed_import_failures": 0,
    "phase10_matches": 0,
    "phase10_match_deduped": 0,
    "phase10_match_failures": 0,
    "phase10_surface_observations": 0,
    "phase10_clusters": 0,
    "phase10_cases_created": 0,
    "phase10_cases_closed": 0,
    # Phase 9 — enterprise security counters (values only, never secrets)
    "phase9_scans": 0,
    "phase9_scan_failures": 0,
    "cloud_accounts_registered": 0,
    "cloud_resources_inventoried": 0,
    "container_images_registered": 0,
    "kubernetes_clusters_registered": 0,
    "iac_scans": 0,
    # Phase 4 — intelligence pipeline counters (values only, never secrets)
    "assets_ingested": 0,
    "asset_observations": 0,
    "findings_ingested": 0,
    "findings_deduplicated": 0,
    "correlation_matches": 0,
    "clusters_created": 0,
    "false_positives": 0,
    "accepted_risks": 0,
    "findings_reopened": 0,
    "risk_calculations": 0,
    "risk_calculation_failures": 0,
    "scan_diffs": 0,
    "asset_criticality_changes": 0,
    # Phase 5 — continuous monitoring pipeline counters (values only, never
    # secrets): policies, scheduler runs, change events, alerts, notifications,
    # remediations and monitoring health failures.
    "monitoring_policies": 0,
    "scheduled_runs": 0,
    "missed_runs": 0,
    "successful_runs": 0,
    "failed_runs": 0,
    "security_change_events": 0,
    "alerts_created": 0,
    "alerts_deduplicated": 0,
    "alerts_suppressed": 0,
    "notifications_sent": 0,
    "notifications_failed": 0,
    "notification_retries": 0,
    "remediations_opened": 0,
    "remediations_verified": 0,
    "remediations_reopened": 0,
    "verification_scans": 0,
    "monitoring_health_failures": 0,
    "alert_evaluation_failures": 0,
    # Phase 6 — reporting / evidence counters (values only, never secrets)
    "reports_generated": 0,
    "reports_exported": 0,
    "reports_retained": 0,
    "evidence_snapshots": 0,
    # Phase 7 — DevSecOps gate/CI counters (values only, never secrets; no
    # user-controlled values used as metric names or labels)
    "devsecops_runs_created": 0,
    "devsecops_runs_completed": 0,
    "devsecops_runs_failed": 0,
    "devsecops_gate_passed": 0,
    "devsecops_gate_failed": 0,
    "devsecops_gate_warned": 0,
    "devsecops_gate_inconclusive": 0,
    "devsecops_policy_rejected": 0,
    "devsecops_authorization_denied": 0,
    "devsecops_runs_retained": 0,
    # Phase 11 — data protection / privacy / seamless governance counters
    # (counts only; never secret values, never PII)
    "governance_classifications": 0,
    "governance_secrets_registered": 0,
    "governance_holds_created": 0,
    "governance_holds_released": 0,
    "governance_deletions": 0,
    "governance_privacy_requests": 0,
    "governance_privacy_completed": 0,
    "governance_exceptions": 0,
    "governance_exports": 0,
    "governance_retention_errors": 0,
    "governance_audit_failures": 0,
    # Phase 12 — federation / evidence exchange / bulk / integration
    # counters (counts only; never package payloads, never secrets)
    "federation_peers_created": 0,
    "federation_policies_created": 0,
    "federation_packages_created": 0,
    "federation_packages_imported": 0,
    "federation_imports_rejected": 0,
    "federation_integrity_failures": 0,
    "federation_bulk_jobs": 0,
    "federation_bulk_event_dropped": 0,
    "federation_bulk_progress_errors": 0,
    "federation_integrations_created": 0,
    "federation_integration_events": 0,
    "federation_integration_failures": 0,
    "federation_audit_failures": 0,
    # Phase 13 — enterprise security integration pipeline counters
    # (counts ONLY; never payload bytes, never provider responses, never
    # credentials, never user-controlled values as metric names — the
    # vocabulary is closed and `inc` fails closed on unknown names).
    # Connection lifecycle:
    "integrations_created": 0,
    "integrations_updated": 0,
    "integrations_enabled": 0,
    "integrations_disabled": 0,
    "integrations_tests": 0,
    "integrations_test_failures": 0,
    "integrations_config_rejected": 0,
    "integrations_config_expired": 0,
    "integrations_authorization_denied": 0,
    # Outbound delivery pipeline (normalize → policy → adapter → job →
    # retry/backoff → receipt):
    "integrations_outbound_queued": 0,
    "integrations_outbound_sent": 0,
    "integrations_outbound_failed": 0,
    "integrations_outbound_retried": 0,
    "integrations_outbound_skipped": 0,
    "integrations_outbound_cancelled": 0,
    "integrations_policy_violations": 0,
    "integrations_minimization_applied": 0,
    # Inbound ingestion pipeline (auth → HMAC/token → schema → rate limit
    # → tenant resolution → normalization → dedup):
    "integrations_inbound_received": 0,
    "integrations_inbound_accepted": 0,
    "integrations_inbound_rejected": 0,
    "integrations_inbound_duplicates": 0,
    "integrations_inbound_failed": 0,
    "integrations_schema_rejected": 0,
    "integrations_auth_failures": 0,
    "integrations_replay_blocked": 0,
    "integrations_integrity_failures": 0,
    "integrations_rate_limited": 0,
    "integrations_abnormal_volume": 0,
    # Health checks + local circuit breaker:
    "integrations_health_checks": 0,
    "integrations_health_degraded": 0,
    "integrations_circuit_opened": 0,
    "integrations_circuit_closed": 0,
    # Internal reliability (audit-chain write degradation, mirrors
    # federation_audit_failures):
    "integrations_audit_failures": 0,
}
_DURATIONS = {"scan_duration": 0.0, "stage_duration": 0.0,
              # Phase 13 — outbound delivery latency (provider round-trip
              # via the job engine; seconds, monotonic-clock based)
              "integrations_delivery_duration": 0.0}
_lock = threading.Lock()


def inc(name: str, amount: int = 1) -> None:
    if name not in _COUNTERS:
        raise KeyError(f"Unknown metric: {name}")
    with _lock:
        _COUNTERS[name] += int(amount)


def add_duration(name: str, seconds: float) -> None:
    if name not in _DURATIONS:
        raise KeyError(f"Unknown duration metric: {name}")
    with _lock:
        _DURATIONS[name] += max(0.0, float(seconds))


def snapshot() -> dict:
    with _lock:
        return {"counters": dict(_COUNTERS), "durations": dict(_DURATIONS)}


def reset() -> None:
    with _lock:
        for k in _COUNTERS:
            _COUNTERS[k] = 0
        for k in _DURATIONS:
            _DURATIONS[k] = 0.0


class Timer:
    """Context manager timing a block into a duration metric."""

    def __init__(self, name: str):
        self.name = name
        self._t0 = 0.0

    def __enter__(self):
        self._t0 = time.monotonic()
        return self

    def __exit__(self, *exc):
        add_duration(self.name, time.monotonic() - self._t0)
        return False
