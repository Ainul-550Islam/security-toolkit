#!/usr/bin/env python3
# ============================================================================
#  models.py — Phase-1 domain model: Organization, Project, Asset, Scan,
#              Finding, Evidence, AuditEvent (+ ScopePolicy, Risk metadata).
#  ---------------------------------------------------------------------------
#  - Immutable-by-convention dataclasses with `validate()` and deterministic
#    `to_dict()`/`from_dict()` serialization.
#  - Stable, deterministic IDs via uuid5 (namespace per entity type).
#  - Explicit lifecycle state machines with transition validation.
#  - NO secret fields in any model. Secrets never enter these objects.
#  - Finding identity (`fingerprint`) is deterministic so multiple scanners
#    can be recognized as the same underlying issue (dedup foundation).
# ============================================================================

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field

import errors

# --- stable namespaces ---------------------------------------------------------
NS_ORG = uuid.UUID("b4f8c3a1-9d1e-4f37-9bf0-2a5c6d7e8f90")
NS_PROJECT = uuid.UUID("5e3a0c2f-7d14-4b98-a1c3-9f0e2d4b6c81")
NS_ASSET = uuid.UUID("c27d1e4a-6b58-4f09-8e3d-5a1b7c9d0e2f")
NS_SCAN = uuid.UUID("8a91b2c3-4d5e-4f67-8a9b-0c1d2e3f4a5b")
NS_FINDING = uuid.UUID("1f2e3d4c-5b6a-4978-8c9d-0e1f2a3b4c5d")
NS_EVIDENCE = uuid.UUID("9ab8c7d6-5e4f-4a3b-8c1d-2e3f4a5b6c7d")
NS_EVENT = uuid.UUID("0d9c8b7a-6f5e-4d3c-8b2a-1e0f3d4c5b6a")
NS_SCOPE = uuid.UUID("7a6b5c4d-3e2f-4a1b-8c0d-9e8f7a6b5c4d")
NS_USER = uuid.UUID("c3d4e5f6-7a8b-4c9d-8e0f-1a2b3c4d5e6f")
NS_CREDENTIAL = uuid.UUID("d4e5f6a7-8b9c-4d0e-9f1a-2b3c4d5e6f7a")
NS_SESSION = uuid.UUID("e5f6a7b8-9c0d-4e1f-8a2b-3c4d5e6f7a8b")
NS_RESET = uuid.UUID("f6a7b8c9-0d1e-4f2a-9b3c-4d5e6f7a8b9c")
NS_BREAKGLASS = uuid.UUID("7c8d9e0f-2b3a-4c4d-9e5f-7a8b9c0d1e2f")
# --- Phase 9 cloud/container/Kubernetes/IaC namespaces --------------------
NS_CLOUDACCOUNT = uuid.UUID("b36617c2-d38b-5cc1-aadf-8f1f20d71020")
NS_IMAGE = uuid.UUID("5532bff6-3ec2-59d5-b9e6-cb3845ad907b")
NS_K8SCLUSTER = uuid.UUID("6eaa7bad-9767-57aa-a166-a471c07735d3")
NS_IACSCAN = uuid.UUID("db7ae79e-b1b5-5be4-908e-5eb4db7c6480")
# Phase 10 — security operations / threat intelligence / cases
NS_TI_IOC = uuid.UUID("a1c2e3d4-5f6a-4b7c-8d9e-0f1a2b3c4d5e")
NS_TI_MATCH = uuid.UUID("b2d3e4f5-6a7b-4c8d-9e0f-1a2b3c4d5e6f")
NS_CASE = uuid.UUID("c3e4f5a6-7b8c-4d9e-8f0a-2b3c4d5e6f7a")
NS_CASE_REF = uuid.UUID("d4f5a6b7-8c9d-4e0f-9a1b-3c4d5e6f7a8b")
NS_CASE_ENTRY = uuid.UUID("e5a6b7c8-9d0e-4f1a-8b2c-4d5e6f7a8b9c")
NS_THREAT_CLUSTER = uuid.UUID("f6b7c8d9-0e1f-4a2b-9c3d-5e6f7a8b9c0d")
NS_THREAT_MEMBER = uuid.UUID("a7c8d9e0-1f2a-4b3c-8d4e-6f7a8b9c0d1e")
# --- Phase 11 data governance / privacy / compliance namespaces ---------
NS_CLASSIFICATION = uuid.UUID("b81c2e4f-1a3b-4d5c-8e6f-2a4c6e8f0a1b")
NS_SECRET = uuid.UUID("c92d3f5a-2b4c-4e6d-9f7a-3b5d7f9a1b2c")
NS_RETENTION_POLICY = uuid.UUID("da3e4a6b-3c5d-4f7e-8a8b-4c6e8a9b2c3d")
NS_RETENTION_HOLD = uuid.UUID("eb4f5b7c-4d6e-4a8f-9b9c-5d7f9b8c3d4e")
NS_RETENTION_RUN = uuid.UUID("fc5a6c8d-5e7f-4b9a-8cad-6e8a9c9d4e5f")
NS_PRIVACY_REQUEST = uuid.UUID("ad6b7d9e-6f8a-4cab-9dbe-7f9bad0e5f6a")
NS_DATA_EXPORT = uuid.UUID("be7c8eaf-7a9b-4dbc-8ecf-8a0cbe1f6a7b")
NS_POLICY_EXCEPTION = uuid.UUID("cf8d9fba-8bac-4ecd-9fd0-9b1dcf2a7b8c")
# --- Phase 12 federation namespaces ---------------------------------------
NS_FED_PEER = uuid.UUID("1e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a5c")
NS_FED_POLICY = uuid.UUID("2f3a4b5c-6d7e-4f8a-9b0c-1d2e3f4a5b6d")
NS_FED_PACKAGE = uuid.UUID("3a4b5c6d-7e8f-4a9b-8c0d-2e3f4a5b6c7e")
NS_FED_IMPORT = uuid.UUID("4b5c6d7e-8f9a-4b0c-9d1e-3f4a5b6c7d8f")
NS_INTEGRATION = uuid.UUID("5c6d7e8f-9a0b-4c1d-8e2f-4a5b6c7d8e9f")
NS_INTEGRATION_EVENT = uuid.UUID("6d7e8f9a-0b1c-4d2e-9f3a-5b6c7d8e9f0a")
# --- Phase 13 enterprise security integration namespaces ----------------
NS_INTEGRATION_CONNECTION = uuid.UUID("7e8f9a0b-1c2d-4e3f-8a4b-6c7d8e9f0a1b")
NS_INTEGRATION_DELIVERY = uuid.UUID("8f9a0b1c-2d3e-4f4a-9b5c-7d8e9f0a1b2c")
NS_INTEGRATION_INBOUND = uuid.UUID("9a0b1c2d-3e4f-4a5b-8c6d-8e9f0a1b2c3d")
NS_INTEGRATION_REPLAY = uuid.UUID("0b1c2d3e-4f5a-4b6c-9d7e-9f0a1b2c3d4e")
NS_JOB = uuid.UUID("0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
NS_STAGE = uuid.UUID("1b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e")
# --- Phase 4 intelligence namespaces -------------------------------------
NS_OBSERVATION = uuid.UUID("2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f")
NS_OBSEVENT = uuid.UUID("3d4e5f6a-7b8c-4d9e-8f0a-2b3c4d5e6f7a")
NS_RELATION = uuid.UUID("4e5f6a7b-8c9d-4e0f-9a1b-3c4d5e6f7a8b")
NS_FOBS = uuid.UUID("5f6a7b8c-9d0e-4f1a-8b2c-4d5e6f7a8b9c")
NS_RISK = uuid.UUID("6a7b8c9d-0e1f-4a2b-9c3d-5e6f7a8b9c0d")
NS_LINK = uuid.UUID("7b8c9d0e-1f2a-4b3c-8d4e-6f7a8b9c0d1e")
NS_ROOT = uuid.UUID("8c9d0e1f-2a3b-4c4d-9e5f-7a8b9c0d1e2f")
NS_CLUSTER = uuid.UUID("9d0e1f2a-3b4c-4d5e-8f6a-8b9c0d1e2f3a")
NS_REGROUP = uuid.UUID("ae1f2a3b-4c5d-4e6f-9a7b-9c0d1e2f3a4b")
NS_DIFF = uuid.UUID("bf2a3b4c-5d6e-4f7a-8b8c-0d1e2f3a4b5c")
# --- Phase 5 monitoring namespaces -------------------------------------
NS_POLICY = uuid.UUID("c0d1e2f3-4a5b-4c6d-8e7f-9a8b7c6d5e4f")
NS_MONRUN = uuid.UUID("d1e2f3a4-5b6c-4d7e-9f8a-8b9c0d1e2f3a")
NS_SECEVENT = uuid.UUID("e2f3a4b5-6c7d-4e8f-8a9b-9c0d1e2f3a4b")
NS_ALERTRULE = uuid.UUID("f3a4b5c6-7d8e-4f9a-8b0c-0d1e2f3a4b5c")
NS_ALERT = uuid.UUID("0a4b5c6d-7e8f-4a9b-8c1d-1e2f3a4b5c6d")
NS_ALOCC = uuid.UUID("1b5c6d7e-8f9a-4b0c-8d2e-2f3a4b5c6d7e")
NS_ALEVENT = uuid.UUID("2c6d7e8f-9a0b-4c1d-8e3f-3a4b5c6d7e8f")
NS_NOTIF = uuid.UUID("3d7e8f9a-0b1c-4d2e-8f4a-4b5c6d7e8f9a")
NS_NATT = uuid.UUID("4e8f9a0b-1c2d-4e3f-8a5b-5c6d7e8f9a0b")
NS_TICKET = uuid.UUID("5f9a0b1c-2d3e-4f4a-8b6c-6d7e8f9a0b1c")
NS_THIST = uuid.UUID("6a0b1c2d-3e4f-4a5b-8c7d-7e8f9a0b1c2d")
NS_VSCAN = uuid.UUID("7b1c2d3e-4f5a-4b6c-8d8e-8f9a0b1c2d3e")
NS_MONCFG = uuid.UUID("8c2d3e4f-5a6b-4c7d-8e9f-9a0b1c2d3e4f")
# --- Phase 6 reporting / compliance-evidence namespaces ----------------
NS_REPORT = uuid.UUID("9e3f4a5b-6c7d-4f8a-9a0b-0d1e2f3a4b5c")
NS_CEVID = uuid.UUID("af4a5b6c-7d8e-4f9a-8b0c-1e2f3a4b5c6d")
# --- Phase 7 DevSecOps / CI-CD namespaces -------------------------------
NS_GATE = uuid.UUID("b05c6d7e-8f9a-4b0d-9e1f-0a2b3c4d5e6f")
NS_CIRUN = uuid.UUID("c16d7e8f-9a0b-4c1e-8f2a-1b3c4d5e6f7a")
NS_GATERT = uuid.UUID("d27e8f9a-0b1c-4d2f-9a3b-2c4d5e6f7a8b")
NS_MFA = uuid.UUID("e38f9a0b-1c2d-4e3a-8b4c-3d5e6f7a8b92")
NS_MFACODE = uuid.UUID("f49a0b1c-2d3e-4f4b-8c5d-4e6f7a8b9ca3")
NS_SSOPROV = uuid.UUID("0a5b1c2d-3e4f-4a5c-8d6e-5f7a8b9c0db4")
NS_SSOHIST = uuid.UUID("1b6c2d3e-4f5a-4b6d-8e7f-6a8b9c0d1ec5")
NS_SSODOM = uuid.UUID("2c7d3e4f-5a6b-4c7e-8f8a-7b9c0d1e2fd6")
NS_SSOIDENT = uuid.UUID("3d8e4f5a-6b7c-4d8f-8a9b-8c0d1e2f3ae7")
NS_IDPSTATE = uuid.UUID("4e9f5a6b-7c8d-4e9a-8bac-9d0e1f2a4bf8")
NS_GRM = uuid.UUID("5faa6b7c-8d9e-4fab-8cbd-ae0f1a2b5c09")
NS_SCIMCRED = uuid.UUID("6abb7c8d-9eaf-4bac-8dce-bf1a2b3c6d10")
NS_IEVENT = uuid.UUID("7bcc8d9e-afb0-4cbd-8edf-c02b3c4d7e21")
NS_SAMLRP = uuid.UUID("8cdd9eaf-b0c1-4dce-8fe0-d13c4d5e8f32")
NS_SCIMGRP = uuid.UUID("9deeafb0-c1d2-4edf-8ff1-e24d5e6f9043")

# --- Phase 6 reporting vocabulary ---------------------------------------
# Report types (all bounded; snapshot-based; never secrets).
REPORT_TYPES = ("executive", "technical", "asset_inventory", "vulnerability",
                "remediation", "monitoring", "trend", "compliance_evidence",
                "federation")
REPORT_STATUSES = ("generated", "exported", "retained")
# Deterministic, versioned report + posture formats (no ad-hoc schemas).
REPORT_SCHEMA_VERSION = "report-schema-v1"
POSTURE_VERSION = "posture-v1"
# Generic compliance-evidence CONTROL CATEGORIES — evidence categories only,
# NEVER certifications. Statuses are honest: nothing here claims compliance.
CONTROL_CATEGORIES = ("access_control", "asset_management",
                      "vulnerability_management", "logging_monitoring",
                      "change_management", "incident_response",
                      "data_protection", "security_testing")
CONTROL_STATUSES = ("supported", "partially_supported", "not_supported",
                    "insufficient_evidence")
# Exposure levels (as derived by Phase-4 asset intelligence).
EXPOSURE_LEVELS = ("internet_facing", "internal", "restricted", "unknown")
# --- Phase 7 DevSecOps / CI-CD vocabulary -------------------------------
# Provider-neutral CI identity: a CI integration references an existing
# platform project; ONLY these providers are accepted (fail closed).
CI_PROVIDERS = ("github", "gitlab", "jenkins", "generic", "local")
# Trigger metadata (metadata only — never used to authorize anything).
CI_TRIGGERS = ("pull_request", "merge_request", "branch_push", "manual",
               "scheduled")
CI_RUN_STATUSES = ("created", "scanning", "evaluating", "completed", "failed",
                  "cancelled")
# Explicit gate-result states (PASS/FAIL/WARN/INCONCLUSIVE semantics are
# documented in devsecops.py; INCONCLUSIVE never becomes PASS).
GATE_RESULT_STATUSES = ("pass", "fail", "warn", "inconclusive")
GATE_RESULT_VERSION = "gate-v1"

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-()&]{0,127}$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ASSET_TYPES = ("domain", "subdomain", "hostname", "ip", "ipv6", "url", "api",
               "service", "certificate", "cloud_resource")

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
CONFIDENCE = ("low", "medium", "high", "confirmed")
ASSET_STATUS = ("active", "inactive", "archived", "suspected")
CATEGORIES = ("injection", "xss", "csrf", "auth", "access_control", "tls",
              "misconfiguration", "exposure", "information_disclosure",
              "crypto", "deserialization", "ssrf", "rce", "dos", "other")

SCAN_STATUSES = ("pending", "queued", "running", "paused", "cancelling",
                 "completed", "failed", "cancelled")
SCAN_TRANSITIONS = {
    "pending": {"queued", "running", "paused", "failed", "cancelled", "cancelling"},
    "queued": {"running", "paused", "failed", "cancelled", "cancelling"},
    "running": {"paused", "completed", "failed", "cancelled", "cancelling"},
    "paused": {"queued", "running", "failed", "cancelled", "cancelling"},
    "cancelling": {"cancelled", "failed"},
    "completed": set(),
    "failed": {"running"},       # retry allowed
    "cancelled": set(),
}

# Phase-3 orchestration: job state machine (single source of truth).
JOB_STATUSES = ("created", "queued", "running", "paused", "retry_wait",
                "cancelling", "completed", "failed", "cancelled",
                "dead_letter")
JOB_TRANSITIONS = {
    "created": {"queued", "cancelled"},
    "queued": {"running", "paused", "cancelling", "cancelled"},
    "running": {"paused", "completed", "failed", "cancelling", "cancelled",
                "retry_wait"},
    "paused": {"queued", "running", "cancelling", "cancelled"},
    "retry_wait": {"queued", "cancelling", "cancelled", "dead_letter"},
    "cancelling": {"cancelled", "failed"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
    "dead_letter": set(),
}
STAGE_STATUSES = ("pending", "running", "completed", "failed", "cancelled",
                  "skipped")
# normalized priority: 1=critical 2=high 3=normal 4=low (stored as-is)
JOB_PRIORITIES = {"critical": 1, "high": 2, "normal": 3, "low": 4}

# --- Phase 5: continuous monitoring vocabulary ---------------------------
# Monitoring policy schedule (deterministic windows; manual = never auto).
SCHEDULE_TYPES = ("interval", "daily", "weekly", "manual")
# Missed-schedule handling (bounded — never hundreds of back-fill jobs).
MISSED_POLICIES = ("skip", "run_once", "catch_up")
# Monitoring health is MONITORING metadata — never confused with security risk.
MONITORING_HEALTH = ("healthy", "degraded", "stale", "disabled", "error")
# Security change event vocabulary (allowlist; nothing else is stored).
EVENT_TYPES = (
    "asset.created", "asset.removed",
    "service.opened", "service.closed",
    "technology.changed", "version.changed",
    "exposure.changed",
    "finding.created", "finding.reopened", "finding.resolved",
    "risk.increased", "risk.decreased",
    # monitoring-lifecycle events (alert sources; never secrets)
    "monitoring.missed_scan", "monitoring.scan_failure",
    "monitoring.stale", "monitoring.worker_unavailable",
    "monitoring.notification_failure", "monitoring.verification_failure",
    "monitoring.verification_passed",
    # Phase 10 — security operations / threat intelligence / attack surface
    # (data-only signals; never secrets, never raw malicious payloads)
    "ioc.matched", "ioc.updated", "ioc.revoked", "feed.imported",
    "domain.discovered", "subdomain.discovered", "hostname.discovered",
    "ip.discovered", "service.discovered", "port.discovered",
    "certificate.discovered", "certificate.expiring", "certificate.expired",
    "technology.discovered", "cloud_resource.discovered",
    "attack_surface.scanned", "attack_surface.changed",
    "case.created", "case.updated", "case.assigned", "case.closed",
    "threat_cluster.updated",
    # Phase 11 — data governance / privacy / compliance signals (data-only;
    # never secret values, never PII payloads)
    "secret.expiring", "secret.expired", "secret.revoked",
    "secret.rotation_required",
    "sensitive.exported", "sensitive.data_accessed",
    "privacy.requested", "privacy.completed", "privacy.failed",
    "retention.executed", "retention.violation",
    "hold.created", "hold.released",
    "policy_exception.expired", "classification.changed",
    "data.deleted",
    # Phase 12 — federation / evidence exchange / bulk operations /
    # external integrations (counts + identifiers only; never package
    # payloads, never secret material, never PII beyond existing refs)
    "federation.peer_created", "federation.peer_approved",
    "federation.peer_suspended", "federation.peer_revoked",
    "federation.peer_expired",
    "federation.policy_created", "federation.policy_updated",
    "federation.policy_expired",
    "federation.package_created", "federation.package_exported",
    "federation.package_imported", "federation.package_rejected",
    "federation.integrity_failure",
    "bulk.started", "bulk.completed", "bulk.failed",
    "integration.created", "integration.disabled", "integration.delivered",
    "integration.failed",
    # Phase 13 — enterprise security integration pipeline (data-only
    # signals: identifiers, counts, statuses, hashes — never credentials,
    # never authorization headers, never payload bodies). Delivery
    # failures REUSE the Phase-12 "integration.failed" event above — no
    # duplicate delivery_failed name is registered.
    "integration.auth_failure", "integration.replay_detected",
    "integration.integrity_failure", "integration.policy_violation",
    "integration.abnormal_volume", "integration.health_degraded",
    "integration.rate_limited", "integration.config_expired",
)

# ---------------------------------------------------------------------------
# Phase 10 — threat intelligence / investigation constants
# ---------------------------------------------------------------------------
# IOC types supported by the deterministic normalizer (§13/§14).
IOC_TYPES = (
    "ipv4", "ipv6", "domain", "hostname", "url",
    "hash_md5", "hash_sha1", "hash_sha256",
    "email", "cert_fingerprint",
)

# Threat-intelligence confidence (§15) — a SEPARATE axis from finding
# severity and risk. Numeric mapping is deterministic and documented.
TI_CONFIDENCE_LEVELS = ("unknown", "low", "medium", "high", "confirmed")
TI_CONFIDENCE_SCORES = {
    "unknown": 0.15, "low": 0.30, "medium": 0.50,
    "high": 0.75, "confirmed": 0.95,
}

# Feed source metadata (§16) — provider-neutral classification only.
TI_SOURCE_TYPES = ("feed", "manual", "import", "partner", "internal", "osint")

# IOC lifecycle (§13): an indicator is active/expired/revoked.
IOC_STATUSES = ("active", "expired", "revoked")

# Investigation cases (§25).
CASE_STATUSES = ("open", "investigating", "contained", "resolved", "closed")
CASE_PRIORITIES = ("low", "medium", "high", "critical")

# Case reference kinds (§25) — all point at EXISTING records.
# Phase 12: "federation_package" references a locally stored evidence
# package (tenant-verified like every other ref kind — a foreign package
# id is NotFound, never a cross-tenant window).
CASE_REF_TYPES = (
    "finding", "asset", "observation", "ioc", "evidence",
    "alert", "remediation", "federation_package",
)

# ---------------------------------------------------------------------------
# Phase 11 — data classification vocabulary (documented allowlist only).
# NEVER free-form: unknown values are rejected by ClassificationService.
# The rank drives downgrade protection: a transition to a strictly lower
# rank requires explicit `authorized=True` on the change call.
# ---------------------------------------------------------------------------
DATA_CLASSIFICATIONS = (
    "public", "internal", "confidential", "restricted", "secret",
    "personal_data", "security_sensitive", "authentication_material",
    "financial_data",
)
CLASSIFICATION_RANK = {
    "public": 0, "internal": 1, "confidential": 2, "personal_data": 3,
    "security_sensitive": 4, "financial_data": 5, "restricted": 6,
    "secret": 7, "authentication_material": 8,
}
# Data that is sensitive BY VOCABULARY (minimization never downgrades it).
SENSITIVE_CLASSIFICATIONS = frozenset({
    "confidential", "restricted", "secret", "personal_data",
    "security_sensitive", "authentication_material", "financial_data",
})

# Phase 11 — secret governance: METADATA ONLY. The registry stores NEVER
# the material: only a search hash (sha256) for dedup, clearly distinguished
# from decryptable storage (which the platform already handles per kind).
SECRET_KINDS = (
    "api_key", "access_token", "refresh_token", "webhook_secret",
    "provider_credential", "oauth_client_secret", "saml_signing_material",
    "scim_token", "cloud_credential", "database_credential", "session_token",
)
SECRET_STATUSES = ("active", "expired", "revoked", "rotation_required")
SECRET_TRANSITIONS = {
    "active": {"revoked", "rotation_required", "expired"},
    "rotation_required": {"active", "revoked", "expired"},
    "expired": {"active", "revoked"},
    "revoked": {"active"},
}

# Canonical retention vocabulary + documented default bounds. Phases 11–13
# share the single data_governance.RETENTION_SPEC engine; no parallel
# retention system is introduced. Immutable audit/security history keeps its
# existing long default (never shortened by the integration merge).
RETENTION_KINDS = (
    "evidence", "reports", "audit_events", "findings", "scan_history",
    "monitoring_history", "security_events", "case_history",
    "threat_intel_data", "asset_observations",
    "federation_packages", "federation_imports", "integration_events",
    "integration_deliveries", "integration_inbound_events",
    "integration_replay_claims",
)
RETENTION_DEFAULTS = {
    "evidence": 365, "reports": 365, "audit_events": 2555,
    "findings": 1095, "scan_history": 365, "monitoring_history": 180,
    "security_events": 365, "case_history": 1095,
    "threat_intel_data": 180, "asset_observations": 365,
    "federation_packages": 365, "federation_imports": 1095,
    "integration_events": 180,
    "integration_deliveries": 180,
    "integration_inbound_events": 365,
    "integration_replay_claims": 30,
}
HOLD_KINDS = ("legal", "investigation", "regulatory", "other")

# Phase 11 — privacy requests (provider-neutral workflow; NEVER a legal
# compliance claim — that remains the customer/operator responsibility).
PRIVACY_REQUEST_TYPES = ("access", "export", "deletion", "correction",
                         "restriction")
PRIVACY_REQUEST_STATUSES = ("submitted", "under_review", "approved",
                            "rejected", "in_progress", "completed", "failed",
                            "cancelled")
PRIVACY_TRANSITIONS = {
    "submitted": {"under_review", "cancelled"},
    "under_review": {"approved", "rejected", "cancelled"},
    "approved": {"in_progress", "cancelled"},
    "rejected": {"submitted", "cancelled"},
    "in_progress": {"completed", "failed", "cancelled"},
    "failed": {"in_progress", "cancelled"},
    "completed": set(),
    "cancelled": set(),
}

# Phase 11 — policy exceptions (controlled deviations; status is
# deterministic: an expired exception is NEVER silently effective).
POLICY_EXCEPTION_STATUSES = ("active", "expired", "revoked")

# Phase 11 — personal-data categories (CONSERVATIVE detection only; a weak
# string pattern never auto-promotes an object to personal_data).
PERSONAL_DATA_CATEGORIES = (
    "email", "ip_address", "hostname", "username", "user_agent",
    "device_identifier", "account_identifier", "contact_metadata",
)

# ---------------------------------------------------------------------------
# Phase 12 — federation / evidence-exchange vocabulary (documented
# allowlists only; NEVER free-form). Trust is always explicit: a peer is
# created `pending` and only an approval transition makes it `active`;
# `expired`/`revoked` fail closed (no silent renewal, no implicit trust).
# ---------------------------------------------------------------------------
FEDERATION_SCHEMA_VERSION = "fed-package-v1"
FEDERATION_PEER_STATUSES = ("pending", "active", "suspended", "expired",
                            "revoked")
FEDERATION_PEER_TRANSITIONS = {
    "pending": {"active", "revoked"},
    "active": {"suspended", "revoked", "expired"},
    "suspended": {"active", "revoked", "expired"},
    # expired → pending is the ONLY renewal path: an explicit re-request
    # that requires a fresh approval (never expired → active directly).
    "expired": {"pending"},
    "revoked": set(),
}
FEDERATION_DIRECTIONS = ("outbound", "inbound", "bidirectional")
# Object types a federation policy may allow for EXPORT (snapshot side).
FEDERATION_OBJECT_TYPES = (
    "organization", "project", "asset", "finding", "evidence", "report",
    "case", "threat_intel_match", "security_event",
)
# Subset with a real IMPORT merge path (existing local systems: asset_add,
# finding fingerprint/dedup, evidence_add, case service, IOC catalog).
# Other types are export-only by design — importing one is an explicit
# rejection, never a silent drop (documented limitation).
FEDERATION_IMPORTABLE_TYPES = ("asset", "finding", "evidence", "case",
                               "threat_intel_match")
FEDERATION_COLLISION_STRATEGIES = ("skip", "link", "merge_metadata",
                                   "reject")
# Package trust modes. `unsigned` never claims cryptographic signing;
# `integrity_verified` = sha256 over the canonical payload; `externally_
# signed` = an external signature REFERENCE is recorded — local code never
# fabricates verification success for it.
FEDERATION_TRUST_MODES = ("unsigned", "integrity_verified",
                          "externally_signed")
FEDERATION_POLICY_STATUSES = ("active", "disabled", "expired")
FEDERATION_PACKAGE_STATUSES = ("created", "purged")
# `in_progress` is the concurrency claim row: UNIQUE(org_id, package_hash)
# makes duplicate/concurrent imports of the same package deterministic
# (second caller sees the claim and never double-applies).
FEDERATION_IMPORT_STATUSES = ("in_progress", "completed", "rejected",
                              "failed")
# Classifications that may NEVER be federation-shared by default: a policy
# including them requires an explicit acknowledgment at creation time, and
# even then raw secret material is never exportable (metadata only).
FEDERATION_SENSITIVE_BY_DEFAULT = frozenset({"secret",
                                             "authentication_material"})
# External-integration boundary (SIEM/ticketing/data-lake/GRC/webhook).
# These are delivery BOUNDARIES only — no vendor platform is implemented.
INTEGRATION_KINDS = ("siem_export", "ticketing_export", "data_lake_export",
                     "grc_ingestion", "webhook")
INTEGRATION_STATUSES = ("enabled", "disabled")
INTEGRATION_EVENT_STATUSES = ("sent", "failed", "invalid", "skipped")
# Bulk operations executed through the EXISTING Phase-3 job engine
# (in-process profile `federation-bulk`); no second scheduler.
BULK_OPERATIONS = ("bulk_export", "bulk_import", "bulk_classify",
                   "bulk_retention_preview")

# ---------------------------------------------------------------------------
# Phase 13 — enterprise security integrations & external event pipeline.
# Provider-neutral connector vocabulary built AROUND the existing systems
# (Phase-12 external_integrations/integration_events boundary, findings,
# alerts, cases, threat intel, audit, jobs) — never replacing them. Every
# vocabulary below is CLOSED: services must reject unknown values fail
# closed (ValidationError), never silently normalize them into valid ones.
# ---------------------------------------------------------------------------
# Connector categories (§7). Deliberately distinct from the Phase-12
# INTEGRATION_KINDS above, which name the federation-delivery boundary
# kinds stored on external_integrations rows and are pinned by existing
# behavior/tests (unchanged). CONNECTOR_BOUNDARY_MAP deterministically
# projects a connector category onto its Phase-12 delivery-boundary kind
# where one exists; edr/xdr/soar are event-exchange categories with NO
# Phase-12 export boundary ("") — connectors for them must never claim
# legacy boundary semantics, and no vendor platform is implemented.
INTEGRATION_CONNECTOR_KINDS = (
    "siem", "edr", "xdr", "soar", "ticketing", "grc", "data_lake",
    "notification", "generic_webhook",
)
CONNECTOR_BOUNDARY_MAP = {
    "siem": "siem_export",
    "ticketing": "ticketing_export",
    "data_lake": "data_lake_export",
    "grc": "grc_ingestion",
    "notification": "webhook",
    "generic_webhook": "webhook",
    "edr": "",
    "xdr": "",
    "soar": "",
}
# Provider-neutral authentication modes (§16). `mtls_reference` is a
# credential/configuration REFERENCE concept only — this platform
# implements no PKI and never fabricates certificate trust. Secret
# VALUES are never stored on integration rows, in logs, audit, errors,
# dashboards, reports or API responses (Phase-11 credential governance).
INTEGRATION_AUTH_MODES = ("bearer_token", "hmac", "api_key",
                          "mtls_reference")
# HMAC signing allowlist (§17): closed algorithm set for inbound/outbound
# signature validation — reuses the EXISTING notify.sign_payload scheme
# (HMAC-SHA256 over timestamp|body, constant-time compare). Never
# free-form algorithm names; no MD5/SHA1.
INTEGRATION_HMAC_ALGORITHMS = ("sha256",)
# Deterministic health states (§29). A connector that never performed a
# real protocol interaction can never report "healthy" — stubs and
# unimplemented vendors surface honest states (service-level
# configured/test_stub/unsupported semantics resolve into THIS closed
# result set; "unsupported" is terminal and never claims success).
INTEGRATION_HEALTH_STATES = (
    "healthy", "degraded", "misconfigured", "disabled", "rate_limited",
    "unreachable", "unsupported",
)
# Outbound delivery-receipt states (§27/§28). Distinct from the Phase-12
# INTEGRATION_EVENT_STATUSES above (sent/failed/invalid/skipped — the
# emission outcome on integration_events rows, unchanged): a delivery is
# a job-backed lifecycle record with retry/backoff/cancel semantics.
# Overlapping literals intentionally reuse the identical strings so the
# two vocabularies never diverge on shared outcomes.
INTEGRATION_DELIVERY_STATUSES = (
    "queued", "sending", "sent", "failed", "retrying", "skipped",
    "rejected", "cancelled",
)
# Inbound ingestion outcome states (§15/§18). `duplicate` is the replay-
# claim outcome: a duplicate event never creates a duplicate finding,
# alert, case or threat match (Phase-4/5/10 dedup remains authoritative).
INTEGRATION_INBOUND_STATUSES = ("accepted", "rejected", "duplicate",
                                "failed")
# Local deterministic circuit breaker (§31): bounded per-integration
# failure semantics — NOT a distributed breaker infrastructure.
CIRCUIT_BREAKER_STATES = ("closed", "open", "half_open")
# Normalized inbound security event (§19): closed field vocabulary for
# the provider-neutral model (no database table is defined in this file).
# Provider-specific metadata travels under a bounded namespaced
# structure enforced by the ingestion service — never arbitrary giant
# blobs. severity/confidence/risk remain SEPARATE axes (§20).
INBOUND_EVENT_FIELDS = (
    "event_id", "event_type", "event_time", "severity", "confidence",
    "source", "source_asset", "destination_asset", "indicator",
    "description", "raw_reference", "external_reference",
)
# Normalized inbound event types — each maps onto an EXISTING local
# system (finding_ingest / alerts + security events / investigation
# cases / IOC catalog / security events). Never a parallel store.
INBOUND_EVENT_TYPES = ("finding", "alert", "case", "threat_intel_match",
                       "security_event")
# Deterministic external→local severity mapping (§20). The canonical five
# labels are IDENTICAL to normalize.SEV_MAP; aliases are a closed set.
# Unknown/unmappable external severities fall back to "Info" — the
# established safe default (normalize.normalize_severity); a mapping
# never invents severity strings outside SEVERITIES, and never touches
# confidence (CONFIDENCE) or risk (the local risk engine stays
# authoritative).
EXTERNAL_SEVERITY_MAP = {
    # canonical (identical values to normalize.SEV_MAP)
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info",
    # closed vendor-alias set
    "urgent": "Critical", "emergency": "Critical",
    "severe": "High", "major": "High", "error": "High",
    "moderate": "Medium", "warning": "Medium", "warn": "Medium",
    "minor": "Low",
    "informational": "Info", "information": "Info", "debug": "Info",
    "trace": "Info", "none": "Info",
}
# Numeric external severities are interpreted on the documented 0–10
# scale (CVSS-like); bands are closed and deterministic (first match
# wins, highest band first). Adapters for other scales must normalize to
# 0–10 BEFORE this mapping — the map itself never guesses scales.
EXTERNAL_SEVERITY_BANDS = (
    (9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"),
)


def normalize_external_severity(value) -> str:
    """Deterministic external→local severity (§20). Accepts a canonical
    label, a closed vendor alias, or a numeric 0–10 value (number or
    numeric string); EVERYTHING else maps to "Info" — the documented
    safe default. Never raises, never invents strings outside
    SEVERITIES, never conflates severity with confidence or risk."""
    if value is None or isinstance(value, bool):
        return "Info"
    if isinstance(value, (int, float)):
        n = float(value)
    else:
        s = str(value).strip()
        low = s.lower()
        if low in EXTERNAL_SEVERITY_MAP:
            return EXTERNAL_SEVERITY_MAP[low]
        try:
            n = float(s)
        except (TypeError, ValueError):
            return "Info"
    if n != n or n in (float("inf"), float("-inf")):   # NaN/inf guard
        return "Info"
    if n > 10.0:
        n = 10.0        # deterministic documented clamp, never silent drop
    for floor_value, sev in EXTERNAL_SEVERITY_BANDS:
        if n >= floor_value:
            return sev
    return "Info"


# Phase-13 compatibility aliases. RETENTION_KINDS and RETENTION_DEFAULTS are
# the sole policy sources; the legacy names are derived views, not a second
# manually maintained retention registry. Keep the historical tuple shape and
# its Phase-13 scope (the older integration_events kind is intentionally not
# part of this alias).
def _derive_integration_retention_kinds(kinds):
    return tuple(
        kind for kind in kinds
        if kind.startswith("integration_") and kind != "integration_events"
    )


INTEGRATION_RETENTION_KINDS = _derive_integration_retention_kinds(
    RETENTION_KINDS)


class _ReadOnlyRetentionDefaults(dict):
    """Dict-compatible, JSON-serializable read-only legacy defaults view."""

    @staticmethod
    def _reject_mutation(*args, **kwargs):
        raise TypeError("integration retention defaults are read-only")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    clear = _reject_mutation
    pop = _reject_mutation
    popitem = _reject_mutation
    setdefault = _reject_mutation
    update = _reject_mutation
    __ior__ = _reject_mutation


INTEGRATION_RETENTION_DEFAULTS = _ReadOnlyRetentionDefaults({
    kind: RETENTION_DEFAULTS[kind] for kind in INTEGRATION_RETENTION_KINDS
})

# Phase 11 — compliance control families: additive extension of the Phase-6
# CONTROL_CATEGORIES below (authentication / retention / secrets_management /
# monitoring). Statuses gain "not_evaluated" + "exception" — both describe
# EVIDENCE STATE, never a compliance certification.
CONTROL_CATEGORIES = CONTROL_CATEGORIES + (
    "authentication", "retention", "secrets_management", "monitoring",
)
CONTROL_STATUSES = CONTROL_STATUSES + ("not_evaluated", "exception")

# Neutral, non-attributing cluster labels (§21/§47).
THREAT_CLUSTER_KINDS = ("related_activity", "campaign_like", "indicator_cluster")
THREAT_CLUSTER_LABELS = {
    "related_activity": "related activity cluster",
    "campaign_like": "campaign-like cluster",
    "indicator_cluster": "indicator cluster",
}
# Alert severity is INDEPENDENT of finding severity (rule-declared).
ALERT_SEVERITIES = ("info", "low", "medium", "high", "critical")
ALERT_STATES = ("open", "acknowledged", "investigating", "resolved",
                "suppressed", "expired")
ALERT_TRANSITIONS = {
    "open": {"acknowledged", "investigating", "resolved", "suppressed",
             "expired"},
    "acknowledged": {"investigating", "resolved", "suppressed", "expired",
                     "open"},
    "investigating": {"acknowledged", "resolved", "suppressed", "expired"},
    "resolved": {"open", "suppressed", "expired"},
    "suppressed": {"open", "expired", "resolved"},
    "expired": set(),
}
# Alert grouping keys (project/root-cause/remediation-group/asset).
ALERT_GROUP_KEYS = ("none", "root_cause", "remediation_group", "asset")
# Notification channel/provider statuses + attempt outcomes.
NOTIFICATION_STATUSES = ("pending", "sent", "failed", "dead_letter",
                         "skipped")
NOTIFICATION_OUTCOMES = ("sent", "failed", "invalid", "timeout", "redirect",
                         "skipped")
# Remediation ticket lifecycle (explicit, fail-closed transitions).
REMEDIATION_STATUSES = ("open", "assigned", "in_progress", "blocked",
                        "ready_for_verification", "verified", "closed",
                        "reopened")
REMEDIATION_TRANSITIONS = {
    "open": {"assigned", "in_progress", "blocked", "reopened",
             "ready_for_verification"},
    "assigned": {"open", "in_progress", "blocked", "ready_for_verification",
                 "reopened"},
    "in_progress": {"open", "assigned", "blocked", "reopened",
                    "ready_for_verification"},
    "blocked": {"open", "assigned", "in_progress", "reopened",
                "ready_for_verification"},
    "ready_for_verification": {"open", "assigned", "in_progress", "blocked",
                               "verified", "reopened"},
    "verified": {"closed", "reopened"},
    "closed": {"reopened"},
    "reopened": {"open", "assigned", "in_progress", "blocked",
                 "ready_for_verification"},
}
VERIFICATION_STATUSES = ("pending", "running", "passed", "failed", "skipped")
# Remedy ownership: user-level only (no team subsystem exists; DO NOT invent
# one — assignment of a team is rejected until a team model exists).
REMEDY_OWNER_TYPES = ("user",)
# Explicit, configurable service-level SLA (hours by priority). Plain
# configuration — NO regulatory claim of any kind.
DEFAULT_SLA_HOURS = {"P0": 24, "P1": 72, "P2": 168, "P3": 336, "P4": 720}
# Scheduler run outcomes.
EXECUTION_STATUSES = ("scheduled", "created", "completed", "failed",
                      "skipped", "cancelled")

# Phase-4 lifecycle: Phase-1 states preserved; review workflow states added.
# Every old edge is retained — Phase-4 only ADDS edges, never removes.
FINDING_STATUSES = ("open", "acknowledged", "resolved", "false_positive",
                    "accepted_risk", "confirmed", "in_review", "remediated",
                    "reopened")
FINDING_TRANSITIONS = {
    "open": {"acknowledged", "resolved", "false_positive", "accepted_risk",
             "confirmed", "in_review", "remediated"},
    "acknowledged": {"open", "resolved", "false_positive", "accepted_risk",
                     "confirmed", "in_review", "remediated"},
    "resolved": {"open", "acknowledged", "reopened"},
    "false_positive": {"open", "acknowledged", "reopened"},
    "accepted_risk": {"open", "acknowledged", "resolved", "reopened"},
    "confirmed": {"open", "acknowledged", "in_review", "false_positive",
                  "accepted_risk", "remediated", "resolved"},
    "in_review": {"open", "acknowledged", "confirmed", "false_positive",
                  "accepted_risk", "remediated", "resolved"},
    "remediated": {"open", "acknowledged", "reopened"},
    "reopened": {"open", "acknowledged", "confirmed", "in_review",
                 "false_positive", "accepted_risk", "remediated", "resolved"},
}


def utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def stable_id(namespace: uuid.UUID, key: str) -> str:
    """Deterministic uuid5 id for domain objects."""
    return str(uuid.uuid5(namespace, key))


def slug(text: str, maxlen: int = 64) -> str:
    """Safe filesystem/DB-agnostic identifier from arbitrary text."""
    out = re.sub(r"[^A-Za-z0-9._-]+", "-", text.lower()).strip("-")
    return out[:maxlen] or "item"


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------
@dataclass
class Organization:
    name: str
    status: str = "active"
    id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def validate(self):
        if not isinstance(self.name, str) or not NAME_RE.match(self.name.strip()):
            raise errors.ValidationError(
                f"Invalid organization name: {self.name!r} (1-128 chars, "
                "letters/digits/spaces/._-&() only)")
        if self.status not in ("active", "disabled"):
            raise errors.ValidationError(f"Invalid org status: {self.status}")
        if self.id and not TAG_RE.match(self.id):
            raise errors.ValidationError(f"Invalid organization id: {self.id}")

    def finalize(self):
        self.validate()
        self.name = self.name.strip()
        if not self.id:
            self.id = stable_id(NS_ORG, self.name.lower())
        self.created_at = self.created_at or utcnow()
        self.updated_at = utcnow()

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "status": self.status,
                "created_at": self.created_at, "updated_at": self.updated_at}

    @classmethod
    def from_dict(cls, d: dict) -> "Organization":
        return cls(**{k: d.get(k, "") for k in
                      ("name", "status", "id", "created_at", "updated_at")})


# ---------------------------------------------------------------------------
# Project
# ---------------------------------------------------------------------------
@dataclass
class Project:
    org_id: str
    name: str
    description: str = ""
    status: str = "active"
    id: str = ""
    scope_policy: dict = field(default_factory=dict)   # {"allow": [], "deny": []}
    created_at: str = ""
    updated_at: str = ""

    def validate(self):
        if not self.org_id or not TAG_RE.match(self.org_id):
            raise errors.ValidationError(f"Invalid organization id: {self.org_id}")
        if not isinstance(self.name, str) or not NAME_RE.match(self.name.strip()):
            raise errors.ValidationError(f"Invalid project name: {self.name!r}")
        if self.status not in ("active", "archived", "paused"):
            raise errors.ValidationError(f"Invalid project status: {self.status}")
        if self.id and not TAG_RE.match(self.id):
            raise errors.ValidationError(f"Invalid project id: {self.id}")
        if not isinstance(self.scope_policy, dict):
            raise errors.ValidationError("scope_policy must be a dict")

    def finalize(self):
        self.validate()
        self.name = self.name.strip()
        if not self.id:
            self.id = stable_id(NS_PROJECT, f"{self.org_id}|{self.name.lower()}")
        self.created_at = self.created_at or utcnow()
        self.updated_at = utcnow()

    def to_dict(self) -> dict:
        return {"id": self.id, "org_id": self.org_id, "name": self.name,
                "description": self.description, "status": self.status,
                "scope_policy": self.scope_policy,
                "created_at": self.created_at, "updated_at": self.updated_at}

    @classmethod
    def from_dict(cls, d: dict) -> "Project":
        return cls(org_id=d.get("org_id", ""), name=d.get("name", ""),
                   description=d.get("description", ""), status=d.get("status", "active"),
                   id=d.get("id", ""),
                   scope_policy=d.get("scope_policy") or {},
                   created_at=d.get("created_at", ""), updated_at=d.get("updated_at", ""))


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------
def normalize_hostname(host: str) -> str:
    """Lowercase, strip trailing dot, ASCII-IDNA-encode, validate."""
    if not isinstance(host, str):
        raise errors.ValidationError("Hostname must be a string")
    h = host.strip().strip(".").lower()
    try:
        h = h.encode("idna").decode("ascii")
    except Exception as e:
        raise errors.ValidationError(f"Malformed hostname: {host!r}") from e
    if len(h) > 253 or not re.fullmatch(
            r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+",
            h):
        raise errors.ValidationError(f"Malformed hostname: {host!r}")
    return h


def _normalize_ip(v: str) -> str:
    import ipaddress
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError as e:
        raise errors.ValidationError(f"Invalid IP address: {v!r}") from e


def normalize_asset_value(atype: str, value: str) -> str:
    """Canonical value per asset type (dedup foundation)."""
    if not isinstance(value, str) or not value.strip():
        raise errors.ValidationError("Asset value must be a non-empty string")
    v = value.strip()
    if atype in ("domain", "subdomain"):
        return normalize_hostname(v)
    if atype == "ip":
        return _normalize_ip(v)
    if atype in ("url", "api"):
        parsed = _parse_url(v)
        host = (parsed.hostname or "").lower()
        if not host:
            raise errors.ValidationError(f"Invalid URL: {value!r}")
        default_port = 443 if parsed.scheme == "https" else 80
        port_part = ""
        if parsed.port and parsed.port != default_port:
            port_part = f":{parsed.port}"
        return (f"{parsed.scheme}://{host}{port_part}"
                f"{parsed.path or '/'}"
                + (f"?{parsed.query}" if parsed.query else ""))
    if atype == "service":
        host, _, port = v.rpartition(":")
        if ":" in v and port.isdigit():
            return f"{normalize_hostname(host)}:{int(port)}"
        return normalize_hostname(v)
    return v  # certificate, cloud_resource: verbatim (caller validates)


def _parse_url(url: str):
    from urllib.parse import urlparse
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.netloc:
            raise ValueError(url)
        return p
    except Exception as e:
        raise errors.ValidationError(f"Invalid URL: {url!r}") from e


@dataclass
class Asset:
    project_id: str
    asset_type: str
    value: str                      # canonical
    display: str = ""               # human-facing
    metadata: dict = field(default_factory=dict)
    status: str = "active"
    id: str = ""
    first_seen: str = ""
    last_seen: str = ""

    def validate(self):
        if not self.project_id or not TAG_RE.match(self.project_id):
            raise errors.ValidationError("Asset requires a valid project_id")
        if self.asset_type not in ASSET_TYPES:
            raise errors.ValidationError(f"Unknown asset type: {self.asset_type}")
        if self.status not in ASSET_STATUS:
            raise errors.ValidationError(f"Invalid asset status: {self.status}")
        # validate canonical value eagerly
        normalize_asset_value(self.asset_type, self.value)

    def finalize(self):
        self.validate()
        self.value = normalize_asset_value(self.asset_type, self.value)
        self.display = self.display or self.value
        now = utcnow()
        self.first_seen = self.first_seen or now
        self.last_seen = now
        if not self.id:
            self.id = stable_id(NS_ASSET,
                                f"{self.project_id}|{self.asset_type}|{self.value}")

    def to_dict(self) -> dict:
        return {"id": self.id, "project_id": self.project_id,
                "asset_type": self.asset_type, "value": self.value,
                "display": self.display, "metadata": self.metadata,
                "status": self.status, "first_seen": self.first_seen,
                "last_seen": self.last_seen}

    @classmethod
    def from_dict(cls, d: dict) -> "Asset":
        return cls(project_id=d.get("project_id", ""),
                   asset_type=d.get("asset_type", ""), value=d.get("value", ""),
                   display=d.get("display", ""), metadata=d.get("metadata") or {},
                   status=d.get("status", "active"), id=d.get("id", ""),
                   first_seen=d.get("first_seen", ""), last_seen=d.get("last_seen", ""))


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
@dataclass
class Scan:
    project_id: str
    profile: str
    scope_ref: str = ""                     # scope policy id/snapshot ref
    status: str = "pending"
    id: str = ""
    created_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    initiator: dict = field(default_factory=dict)
    progress: float = 0.0                   # 0.0 .. 1.0
    stages: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)   # preserved scanner payload

    def validate(self):
        if not self.project_id or not TAG_RE.match(self.project_id):
            raise errors.ValidationError("Scan requires a valid project_id")
        if not self.profile or not TAG_RE.match(self.profile.replace(" ", "-")):
            raise errors.ValidationError(f"Invalid scan profile: {self.profile!r}")
        if self.status not in SCAN_STATUSES:
            raise errors.ValidationError(f"Invalid scan status: {self.status}")
        if not 0.0 <= float(self.progress) <= 1.0:
            raise errors.ValidationError("Scan progress must be in [0, 1]")

    def finalize(self):
        self.validate()
        self.created_at = self.created_at or utcnow()

    def transition(self, new_status: str):
        if new_status not in SCAN_STATUSES:
            raise errors.LifecycleError(f"Unknown scan status: {new_status}")
        allowed = SCAN_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise errors.LifecycleError(
                f"Invalid scan transition: {self.status} -> {new_status}")
        now = utcnow()
        if new_status in ("running",):
            self.started_at = self.started_at or now
            self.status = new_status
        elif new_status in ("completed", "failed", "cancelled"):
            self.finished_at = now
            self.status = new_status
        else:
            self.status = new_status

    def to_dict(self) -> dict:
        return {"id": self.id, "project_id": self.project_id, "profile": self.profile,
                "scope_ref": self.scope_ref, "status": self.status,
                "created_at": self.created_at, "started_at": self.started_at,
                "finished_at": self.finished_at, "initiator": self.initiator,
                "progress": self.progress, "stages": self.stages,
                "summary": self.summary, "error": self.error, "raw": self.raw}

    @classmethod
    def from_dict(cls, d: dict) -> "Scan":
        return cls(project_id=d.get("project_id", ""), profile=d.get("profile", ""),
                   scope_ref=d.get("scope_ref", ""), status=d.get("status", "pending"),
                   id=d.get("id", ""), created_at=d.get("created_at", ""),
                   started_at=d.get("started_at", ""), finished_at=d.get("finished_at", ""),
                   initiator=d.get("initiator") or {}, progress=d.get("progress", 0.0),
                   stages=d.get("stages") or [], summary=d.get("summary") or {},
                   error=d.get("error") or {}, raw=d.get("raw") or {})


# ---------------------------------------------------------------------------
# Finding + deterministic identity
# ---------------------------------------------------------------------------
def finding_fingerprint(*, asset_id: str, category: str, rule_id: str,
                        parameter: str = "", endpoint: str = "") -> str:
    """Deterministic identity of a finding (dedup across scanners).

    Uses ONLY fields that exist in scanner output. Two findings with the same
    asset + category + rule (id/template/type) + parameter are the same issue.
    """
    key = "|".join([asset_id, (category or "other").lower(),
                    (rule_id or "unknown").strip().lower(),
                    (parameter or "").strip().lower(),
                    (endpoint or "").strip().lower()])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


@dataclass
class Finding:
    scan_id: str
    project_id: str
    asset_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "Info"
    confidence: str = "medium"
    category: str = "other"
    source: str = ""                     # scanner name
    rule_id: str = ""
    template_id: str = ""
    cwe: str = ""
    cve: str = ""
    cvss: dict = field(default_factory=dict)
    remediation: str = ""
    evidence: list = field(default_factory=list)   # evidence dicts
    raw: dict = field(default_factory=dict)
    lifecycle: str = "open"
    id: str = ""
    fingerprint: str = ""
    first_detected: str = ""
    last_detected: str = ""
    resolved_at: str = ""
    reopened_at: str = ""          # Phase 4: last re-open timestamp

    def validate(self):
        if not self.scan_id or not TAG_RE.match(self.scan_id):
            raise errors.ValidationError("Finding requires a valid scan_id")
        if not self.project_id or not TAG_RE.match(self.project_id):
            raise errors.ValidationError("Finding requires a valid project_id")
        if self.severity not in SEVERITIES:
            raise errors.ValidationError(f"Unknown severity: {self.severity}")
        if self.confidence not in CONFIDENCE:
            raise errors.ValidationError(f"Unknown confidence: {self.confidence}")
        if self.lifecycle not in FINDING_STATUSES:
            raise errors.ValidationError(f"Unknown finding status: {self.lifecycle}")
        if self.title and len(self.title) > 300:
            raise errors.ValidationError("Finding title too long (max 300)")

    def finalize(self):
        self.validate()
        now = utcnow()
        self.first_detected = self.first_detected or now
        self.last_detected = now
        if not self.fingerprint:
            self.fingerprint = finding_fingerprint(
                asset_id=self.asset_id, category=self.category,
                rule_id=self.rule_id or self.template_id or self.title,
                parameter=str(self.raw.get("parameter", "")),
                endpoint=str(self.raw.get("endpoint", "")))
        if not self.id:
            self.id = stable_id(NS_FINDING, self.fingerprint)

    def transition(self, new_status: str) -> bool:
        """Returns True when the status actually changed (re-open included)."""
        if new_status not in FINDING_STATUSES:
            raise errors.LifecycleError(f"Unknown finding status: {new_status}")
        if new_status == self.lifecycle:
            return False
        allowed = FINDING_TRANSITIONS.get(self.lifecycle, set())
        if new_status not in allowed:
            raise errors.LifecycleError(
                f"Invalid finding transition: {self.lifecycle} -> {new_status}")
        if new_status == self.lifecycle:
            return False
        now = utcnow()
        self.lifecycle = new_status
        self.last_detected = now
        self.resolved_at = now if new_status in ("resolved", "false_positive",
                                                 "accepted_risk",
                                                 "remediated") else ""
        self.reopened_at = now if new_status == "reopened" else self.reopened_at
        return True

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in
                ("id", "scan_id", "project_id", "asset_id", "title", "description",
                 "severity", "confidence", "category", "source", "rule_id",
                 "template_id", "cwe", "cve", "cvss", "remediation", "evidence",
                 "raw", "lifecycle", "fingerprint", "first_detected",
                 "last_detected", "resolved_at", "reopened_at")}

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**{k: d.get(k, {}) if k in ("cvss", "raw") else
                      d.get(k, []) if k == "evidence" else d.get(k, "")
                      for k in ("scan_id", "project_id", "asset_id", "title",
                                "description", "severity", "confidence", "category",
                                "source", "rule_id", "template_id", "cwe", "cve",
                                "cvss", "remediation", "evidence", "raw",
                                "lifecycle", "id", "fingerprint", "first_detected",
                                "last_detected", "resolved_at", "reopened_at")})


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
EVIDENCE_TYPES = ("response", "request", "header", "dns", "behavioral",
                  "configuration", "log", "other")

_SAFE_EXCERPT_MAX = 2000


@dataclass
class Evidence:
    finding_id: str
    evidence_type: str
    url: str = ""
    method: str = ""
    status_code: str = ""
    request_snippet: str = ""
    response_snippet: str = ""
    detection_reason: str = ""
    scanner: str = ""
    rule_id: str = ""
    captured_at: str = ""
    id: str = ""

    def sanitize(self):
        """Centralized redaction — the ONLY place evidence is cleaned."""
        import redact
        self.url = str(redact.redact_text(self.url))[:2000]
        self.method = str(self.method or "GET")[:16]
        self.status_code = str(self.status_code or "")[:16]
        self.request_snippet = str(redact.redact_text(self.request_snippet))[
            :_SAFE_EXCERPT_MAX]
        self.response_snippet = str(redact.redact_text(self.response_snippet))[
            :_SAFE_EXCERPT_MAX]
        self.detection_reason = str(redact.redact_text(self.detection_reason))[:500]

    def validate(self):
        if not self.finding_id or not TAG_RE.match(self.finding_id):
            raise errors.ValidationError("Evidence requires a valid finding_id")
        if self.evidence_type not in EVIDENCE_TYPES:
            raise errors.ValidationError(f"Unknown evidence type: {self.evidence_type}")

    def finalize(self):
        self.validate()
        self.sanitize()
        self.captured_at = self.captured_at or utcnow()
        if not self.id:
            self.id = stable_id(NS_EVIDENCE,
                                f"{self.finding_id}|{self.captured_at}|{self.url}")

    def to_dict(self) -> dict:
        return {"id": self.id, "finding_id": self.finding_id,
                "evidence_type": self.evidence_type, "url": self.url,
                "method": self.method, "status_code": self.status_code,
                "request_snippet": self.request_snippet,
                "response_snippet": self.response_snippet,
                "detection_reason": self.detection_reason,
                "scanner": self.scanner, "rule_id": self.rule_id,
                "captured_at": self.captured_at}

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        return cls(**{k: d.get(k, "") for k in
                      ("finding_id", "evidence_type", "url", "method", "status_code",
                       "request_snippet", "response_snippet", "detection_reason",
                       "scanner", "rule_id", "captured_at", "id")})


# ---------------------------------------------------------------------------
# Audit event
# ---------------------------------------------------------------------------
@dataclass
class AuditEvent:
    action: str
    actor: str = "cli"
    object_type: str = ""
    object_id: str = ""
    org_id: str = ""
    project_id: str = ""
    metadata: dict = field(default_factory=dict)
    id: str = ""
    ts: str = ""

    ACTIONS = frozenset({
        "organization.created", "organization.updated",
        "organization.preferences.updated",
        "project.created", "project.updated", "project.archived",
        "project.restored", "asset.created",
        "scope.changed", "scope.checked", "scope.denied",
        "scan.created", "scan.started", "scan.paused", "scan.resumed",
        "scan.cancelled", "scan.completed", "scan.failed",
        "finding.created", "finding.updated", "finding.status_changed",
        "evidence.created", "report.generated", "export.generated",
        "configuration.changed", "authentication.denied", "scan.updated",
        # --- Phase 2 identity / RBAC / auth events (no secrets ever) ---
        "user.created", "user.updated", "user.disabled", "user.enabled",
        "user.suspended", "user.deactivated", "user.pending",
        "user.role_changed", "user.password_changed",
        "login_success", "login_failure", "logout",
        "session.created", "session.revoked", "session.expired",
        "credential.created", "credential.revoked", "credential.expired",
        "credential.rotated", "password.reset_requested",
        "password.reset_consumed", "authorization.denied",
        "auth.rate_limited",
        # --- Phase 3 orchestration events (heartbeats are NOT audited) ---
        "job.created", "job.queued", "job.claimed", "job.started",
        "job.paused", "job.resumed", "job.retry_scheduled", "job.failed",
        "job.cancel_requested", "job.cancelled", "job.completed",
        "job.dead_lettered", "stage.completed", "stage.failed",
        "worker.started", "worker.stopped",
        "platform.maintenance.jobs_swept",
        # --- Phase 4 intelligence events (user-driven changes only; the
        # automatic correlation/cluster/risk pipeline uses metrics, never
        # floods the immutable audit log) -------------------------------
        "finding.confirmed", "finding.review", "finding.remediated",
        "finding.reopened", "finding.false_positive",
        "finding.accepted_risk", "finding.suppressed",
        "finding.unsuppressed", "asset.criticality_changed",
        "asset.business_impact_changed", "baseline.created",
        # --- Phase 5 continuous monitoring events (scheduler ticks record
        # per-run rows + metrics; only user-driven and discrete events are
        # audited — no heartbeat flood) ------------------------------
        "monitoring.policy.created", "monitoring.policy.enabled",
        "monitoring.policy.disabled", "monitoring.policy.deleted",
        "monitoring.config.updated", "monitoring.manual_run",
        "monitoring.schedule_skipped", "monitoring.scheduled_run",
        "monitoring.missed_runs",
        "alert.rule.created", "alert.rule.updated",
        "alert.created", "alert.ack", "alert.investigate",
        "alert.resolve", "alert.suppress", "alert.expire",
        "alert.suppression_expired", "alert.reopened", "alert.open",
        "alert.acknowledged", "alert.investigating", "alert.resolved",
        "alert.suppressed", "alert.expired",
        "notification.settings.updated", "notification.secret.migrated",
        "notification.retried",
        "remediation.created", "remediation.assigned",
        "remediation.status_changed", "remediation.due_changed",
        "remediation.comment_added", "remediation.verification_requested",
        "remediation.verification_result", "remediation.sla.updated",
        "retention.sweep",
        # --- Phase 6 reporting / compliance evidence (metadata only) ----
        "report.deleted", "report.shared", "evidence.snapshot",
        # --- Phase 7 DevSecOps gates / CI runs / gate results ----------
        "devsecops.gate.created", "devsecops.gate.updated",
        "devsecops.gate.deleted", "devsecops.run.created",
        "devsecops.run.started", "devsecops.run.completed",
        "devsecops.gate.passed", "devsecops.gate.failed",
        "devsecops.gate.warned", "devsecops.gate.inconclusive",
        "devsecops.exported", "devsecops.retention",
        # --- Phase 8 enterprise identity (metadata-level only) ----------
        "identity.login.success", "identity.login.failure",
        "identity.mfa.enrolled", "identity.mfa.enabled",
        "identity.mfa.disabled", "identity.mfa.challenge_success",
        "identity.mfa.challenge_failure", "identity.mfa.reset",
        "identity.mfa.reenroll_required", "identity.recovery_code.generated",
        "identity.recovery_code.used", "identity.recovery_code.regenerated",
        "identity.sso.created", "identity.sso.updated",
        "identity.sso.deleted", "identity.sso.domain_added",
        "identity.sso.domain_removed", "identity.sso.login",
        "identity.sso.failure", "identity.sso.mapping_updated",
        "identity.jit.provisioned", "identity.jit.linked",
        "identity.jit.mapping_skipped", "identity.scim.created",
        "identity.scim.updated", "identity.scim.deactivated",
        "identity.scim.reactivated", "identity.scim.deleted",
        "identity.scim.credential_created", "identity.scim.credential_revoked",
        "identity.scim.credential_rotated", "identity.scim.unauthorized",
        "identity.session.revoked", "identity.session.revoked_all",
        "identity.session.step_up", "identity.policy.updated",
        "identity.lifecycle.changed", "identity.event.swept",
        "identity.break_glass.started", "identity.break_glass.ended",
        # --- Phase 9 cloud / container / Kubernetes / IaC (metadata) ------
        "cloud.account.created", "cloud.account.updated",
        "cloud.account.deleted", "cloud.credentials.updated",
        "cloud.credentials.migrated",
        "cloud.scan.started", "cloud.scan.completed",
        "cloud.inventory.refreshed",
        "container.image_registered", "container.scan.started",
        "container.scan.completed",
        "kubernetes.cluster_registered", "kubernetes.scan.started",
        "kubernetes.scan.completed",
        "iac.scan.started", "iac.scan.completed", "iac.scan.failed",
        # --- Phase 10 security operations / threat intelligence ----------
        "ioc.created", "ioc.updated", "ioc.revoked", "ioc.expired",
        "feed.imported", "ioc.matched",
        "threat.cluster_built", "attack_surface.scan",
        "certificate.registered",
        "case.created", "case.updated", "case.assigned",
        "case.open", "case.investigating", "case.contained",
        "case.resolved", "case.closed",
        "case.reference_added", "case.reference_removed",
        # --- Phase 11 data protection / privacy / compliance governance ---
        "classification.changed", "classification.downgrade_denied",
        "secret.registered", "secret.accessed", "secret.revoked",
        "secret.updated", "secret.rotation_required", "secret.expired",
        "secret.detection",
        "retention.policy_set", "retention.preview", "retention.execution",
        "retention.sweep11",
        "hold.created", "hold.released",
        "data.delete.preview", "data.delete_blocked", "data.deleted",
        "privacy.created", "privacy.updated", "privacy.completed",
        "exception.created", "exception.revoked", "exception.expired",
        "sensitive.exported",
        # --- Phase 12 federation / evidence exchange / bulk / integration
        # (identifiers, counts and hashes only — never package payloads,
        # never secret values)
        "federation.peer.created", "federation.peer.approved",
        "federation.peer.suspended", "federation.peer.resumed",
        "federation.peer.revoked", "federation.peer.re_requested",
        "federation.peer.expired",
        "federation.policy.created", "federation.policy.updated",
        "federation.policy.disabled", "federation.policy.expired",
        "federation.package.created", "federation.package.exported",
        "federation.package.imported", "federation.package.rejected",
        "federation.integrity_failure",
        "federation.bulk.started",
        # Phase-12 defect fix (2026-09-11 acceptance review):
        # BulkRunner._bulk_event always attempted these two audit records,
        # but they were never registered in this closed vocabulary — the
        # attempts raised and degraded into the federation_audit_failures
        # metric instead of the immutable chain. Registering them makes
        # the existing emission path record real audit events; the
        # identically-named Phase-12 SECURITY EVENTS ("bulk.completed" /
        # "bulk.failed" in EVENT_TYPES) are a different namespace and
        # remain untouched.
        "federation.bulk.completed", "federation.bulk.failed",
        "integration.created", "integration.updated",
        "integration.disabled", "integration.emitted",
        # --- Phase 13 enterprise security integration pipeline. Reuses
        # the existing integration.created/updated/disabled/emitted above
        # where semantics match (never duplicated); identifiers, counts
        # and hashes only — never credentials, never payload bodies.
        "integration.enabled", "integration.tested",
        "integration.delivery.queued", "integration.delivery.sent",
        "integration.delivery.failed",
        "integration.inbound.accepted", "integration.inbound.rejected",
        "integration.replay_blocked", "integration.health_changed",
        "ticketing.issue.created", "ticketing.issue.updated",
        "ticketing.issue.closed", "ticketing.issue.linked",
    })

    def validate(self):
        if self.action not in self.ACTIONS:
            raise errors.ValidationError(f"Unknown audit action: {self.action}")

    def sanitize(self):
        """Audit metadata must be sanitized — never secrets."""
        import redact
        self.metadata = redact.redact(self.metadata)
        self.actor = str(redact.redact_text(self.actor))[:128]

    def finalize(self):
        self.validate()
        self.sanitize()
        self.ts = self.ts or utcnow()
        if not self.id:
            # ts is second-precision; rapid same-action sequences on the same
            # object (e.g. Phase-5 remediation status steps) must not collide
            # and silently drop an immutable audit row.
            self.id = stable_id(NS_EVENT,
                                f"{self.ts}|{self.action}|{self.object_id}|"
                                f"{time.monotonic_ns()}")

    def to_dict(self) -> dict:
        return {"id": self.id, "ts": self.ts, "action": self.action,
                "actor": self.actor, "object_type": self.object_type,
                "object_id": self.object_id, "org_id": self.org_id,
                "project_id": self.project_id, "metadata": self.metadata}

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEvent":
        return cls(**{k: d.get(k, "") for k in
                      ("action", "actor", "object_type", "object_id", "org_id",
                       "project_id", "id", "ts")},
                   metadata=d.get("metadata") or {})


# ---------------------------------------------------------------------------
# Phase-2 identity models.
# NOTE: password hashes / verifiers are held as attributes ONLY — to_dict()
# NEVER serializes them, so API/CLI responses can't leak them.
# ---------------------------------------------------------------------------
USER_STATUSES = ("active", "suspended", "deactivated", "pending",
                 "disabled")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$")


@dataclass
class User:
    org_id: str
    username: str
    email: str
    display_name: str = ""
    status: str = "active"
    password_hash: str = ""          # NEVER serialized to_dict()
    id: str = ""
    created_at: str = ""
    updated_at: str = ""
    last_auth_at: str = ""
    failed_attempts: int = 0
    locked_until: str = ""
    login_count: int = 0
    last_mfa_at: str = ""
    deactivated_at: str = ""
    mfa_reenroll_required: int = 0

    def validate(self):
        if not self.org_id or not TAG_RE.match(self.org_id):
            raise errors.ValidationError("User requires a valid org_id")
        if not USERNAME_RE.match(self.username):
            raise errors.ValidationError(
                f"Invalid username: {self.username!r} (3-32 chars, "
                "letters/digits/._- only)")
        if not EMAIL_RE.match(self.email):
            raise errors.ValidationError(f"Invalid email: {self.email!r}")
        if self.status not in USER_STATUSES:
            raise errors.ValidationError(f"Invalid user status: {self.status}")
        if self.id and not TAG_RE.match(self.id):
            raise errors.ValidationError(f"Invalid user id: {self.id}")

    def finalize(self):
        self.validate()
        self.username = self.username.strip().lower()
        self.email = self.email.strip().lower()
        self.display_name = self.display_name.strip()[:128]
        if not self.id:
            self.id = stable_id(NS_USER, f"{self.org_id}|{self.username}")
        self.created_at = self.created_at or utcnow()
        self.updated_at = utcnow()

    def to_dict(self) -> dict:
        """API-safe: password material, lock counters and id internals are
        intentionally excluded."""
        return {"id": self.id, "org_id": self.org_id,
                "username": self.username, "email": self.email,
                "display_name": self.display_name, "status": self.status,
                "created_at": self.created_at, "updated_at": self.updated_at,
                "last_auth_at": self.last_auth_at}

    @classmethod
    def from_dict(cls, d: dict) -> "User":
        return cls(org_id=d.get("org_id", ""), username=d.get("username", ""),
                   email=d.get("email", ""),
                   display_name=d.get("display_name", ""),
                   status=d.get("status", "active"),
                   password_hash=d.get("password_hash", ""),
                   id=d.get("id", ""), created_at=d.get("created_at", ""),
                   updated_at=d.get("updated_at", ""),
                   login_count=int(d.get("login_count", 0) or 0),
                   last_mfa_at=d.get("last_mfa_at", ""),
                   deactivated_at=d.get("deactivated_at", ""),
                   mfa_reenroll_required=int(
                       d.get("mfa_reenroll_required", 0) or 0),
                   last_auth_at=d.get("last_auth_at", ""),
                   failed_attempts=int(d.get("failed_attempts", 0) or 0),
                   locked_until=d.get("locked_until", ""))


CRED_STATUSES = ("active", "revoked", "expired")


@dataclass
class ApiCredential:
    org_id: str
    name: str
    key_prefix: str
    verifier: str                 # sha256(token) — NEVER serialized
    scopes: list = field(default_factory=list)
    status: str = "active"
    created_by: str = ""
    project_id: str = ""          # "" ⇒ org-wide credential
    id: str = ""
    created_at: str = ""
    last_used_at: str = ""
    expires_at: str = ""
    purpose: str = ""

    def validate(self):
        if not self.org_id or not TAG_RE.match(self.org_id):
            raise errors.ValidationError("Credential requires a valid org_id")
        if not self.name or len(self.name) > 96:
            raise errors.ValidationError("Credential name must be 1-96 chars")
        if self.status not in CRED_STATUSES:
            raise errors.ValidationError(
                f"Invalid credential status: {self.status}")
        if not self.verifier or len(self.verifier) != 64:
            raise errors.ValidationError("Credential verifier is malformed")
        if self.project_id and not TAG_RE.match(self.project_id):
            raise errors.ValidationError(
                f"Invalid credential project_id: {self.project_id}")

    def finalize(self):
        self.validate()
        self.name = self.name.strip()
        if not self.id:
            self.id = stable_id(NS_CREDENTIAL,
                                f"{self.org_id}|{self.name}|{self.created_at}")
        self.created_at = self.created_at or utcnow()

    def to_dict(self) -> dict:
        """API-safe: verifier and the raw secret are NEVER returned."""
        return {"id": self.id, "org_id": self.org_id, "name": self.name,
                "key_prefix": self.key_prefix, "scopes": list(self.scopes),
                "status": self.status, "project_id": self.project_id,
                "created_by": self.created_by,
                "created_at": self.created_at,
                "last_used_at": self.last_used_at,
                "expires_at": self.expires_at, "purpose": self.purpose}

    @classmethod
    def from_dict(cls, d: dict) -> "ApiCredential":
        import json as _json
        scopes = d.get("scopes", [])
        if isinstance(scopes, str):
            try:
                scopes = _json.loads(scopes)
            except Exception:
                scopes = []
        return cls(org_id=d.get("org_id", ""), name=d.get("name", ""),
                   key_prefix=d.get("key_prefix", ""),
                   verifier=d.get("verifier", ""),
                   scopes=list(scopes or []),
                   status=d.get("status", "active"),
                   created_by=d.get("created_by", ""),
                   project_id=d.get("project_id", ""),
                   id=d.get("id", ""), created_at=d.get("created_at", ""),
                   last_used_at=d.get("last_used_at", ""),
                   expires_at=d.get("expires_at", ""),
                   purpose=d.get("purpose", ""))


@dataclass
class SessionRecord:
    user_id: str
    token_hash: str               # sha256(session secret) — NEVER serialized
    ip: str = ""
    user_agent: str = ""
    id: str = ""
    created_at: str = ""
    last_seen_at: str = ""
    expires_at: str = ""
    revoked_at: str = ""
    # --- Phase-8 hardening fields (defaults keep Phase-2 behaviour) -------
    auth_method: str = ""          # password | oidc | saml | mfa | ...
    mfa_status: str = "none"       # none | pending | verified
    step_up_until: str = ""        # short-lived elevated window (ISO)
    idp_subject: str = ""          # provider subject (external id)
    provider_id: str = ""          # SSO provider used to establish session
    absolute_expires_at: str = ""  # hard lifetime ceiling (ISO)
    revoke_reason: str = ""

    def validate(self):
        if not self.user_id or not TAG_RE.match(self.user_id):
            raise errors.ValidationError("Session requires a valid user_id")
        if not self.token_hash or len(self.token_hash) != 64:
            raise errors.ValidationError("Session token hash is malformed")

    def finalize(self):
        self.validate()
        if not self.id:
            # token fingerprints are part of the identity space — sessions
            # created within the same second must NOT collide.
            self.id = stable_id(NS_SESSION,
                                f"{self.user_id}|{self.created_at}|"
                                f"{self.token_hash[:16]}")
        self.created_at = self.created_at or utcnow()
        self.last_seen_at = self.last_seen_at or self.created_at

    def to_dict(self) -> dict:
        return {"id": self.id, "user_id": self.user_id, "ip": self.ip,
                "created_at": self.created_at,
                "last_seen_at": self.last_seen_at,
                "expires_at": self.expires_at,
                "revoked_at": self.revoked_at,
                "auth_method": self.auth_method,
                "mfa_status": self.mfa_status,
                "step_up_until": self.step_up_until,
                "provider_id": self.provider_id,
                "idp_subject": self.idp_subject,
                "absolute_expires_at": self.absolute_expires_at,
                "revoke_reason": self.revoke_reason}

    @classmethod
    def from_dict(cls, d: dict) -> "SessionRecord":
        return cls(user_id=d.get("user_id", ""),
                   token_hash=d.get("token_hash", ""),
                   ip=d.get("ip", ""), user_agent=d.get("user_agent", ""),
                   id=d.get("id", ""), created_at=d.get("created_at", ""),
                   last_seen_at=d.get("last_seen_at", ""),
                   expires_at=d.get("expires_at", ""),
                   revoked_at=d.get("revoked_at", ""),
                   auth_method=d.get("auth_method", ""),
                   mfa_status=d.get("mfa_status", "none"),
                   step_up_until=d.get("step_up_until", ""),
                   idp_subject=d.get("idp_subject", ""),
                   provider_id=d.get("provider_id", ""),
                   absolute_expires_at=d.get("absolute_expires_at", ""),
                   revoke_reason=d.get("revoke_reason", ""))


@dataclass
class BreakGlassGrant:
    """Explicitly invoked, reason-required, short-lived emergency access.
    token_hash (sha256 of the bg_ secret) is NEVER serialized in views."""

    org_id: str
    user_id: str
    reason: str
    token_hash: str
    id: str = ""
    created_at: str = ""
    expires_at: str = ""
    last_seen_at: str = ""
    ended_at: str = ""
    end_reason: str = ""
    created_by_session: str = ""

    def validate(self):
        if not self.user_id:
            raise errors.ValidationError(
                "Break-glass grant requires a user_id")
        if not self.org_id:
            raise errors.ValidationError(
                "Break-glass grant requires an org_id")
        if not self.token_hash or len(self.token_hash) != 64:
            raise errors.ValidationError(
                "Break-glass token hash is malformed")

    def finalize(self):
        self.validate()
        if not self.id:
            self.id = stable_id(
                NS_BREAKGLASS, f"{self.user_id}|{self.org_id}|"
                               f"{self.created_at}|{self.token_hash[:16]}")
        self.created_at = self.created_at or utcnow()
        self.last_seen_at = self.last_seen_at or self.created_at

    def active(self) -> bool:
        return not self.ended_at

    def to_dict(self, *, include_token_hash: bool = False) -> dict:
        out = {"id": self.id, "org_id": self.org_id,
               "user_id": self.user_id, "reason": self.reason,
               "created_at": self.created_at, "expires_at": self.expires_at,
               "last_seen_at": self.last_seen_at,
               "ended_at": self.ended_at, "end_reason": self.end_reason,
               "created_by_session": self.created_by_session}
        if include_token_hash:
            out["token_hash"] = self.token_hash
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "BreakGlassGrant":
        return cls(org_id=d.get("org_id", ""), user_id=d.get("user_id", ""),
                   reason=d.get("reason", ""),
                   token_hash=d.get("token_hash", ""),
                   id=d.get("id", ""), created_at=d.get("created_at", ""),
                   expires_at=d.get("expires_at", ""),
                   last_seen_at=d.get("last_seen_at", ""),
                   ended_at=d.get("ended_at", ""),
                   end_reason=d.get("end_reason", ""),
                   created_by_session=d.get("created_by_session", ""))


# ============================================================================
# Phase 9 — cloud / container / Kubernetes / IaC registration entities.
# Registration ONLY: discovered assets, findings, evidence, risk, remediation
# all reuse the Phase-1 models and tables (no second asset/finding model).
# Credential material is NEVER a field of any model that leaves the service:
# CloudAccount keeps a reference + wrapped blob + hint, and to_dict() strips
# every credential field.
# ============================================================================
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IAC_SCAN_STATUSES = frozenset({"pending", "completed", "failed",
                               "inconclusive"})


@dataclass
class CloudAccount:
    """Tenant-bound cloud account registration (spec §7).

    `credential_enc` is an encrypted blob (existing secrets-at-rest
    convention when the adapter supports static credentials); it is never
    part of to_dict()/from_dict() serialization and never logged."""

    org_id: str
    provider: str
    account_identifier: str
    display_name: str = ""
    enabled: int = 1
    region_scope: list = field(default_factory=list)
    credential_ref: str = ""      # name of the secret/env reference
    credential_enc: str = ""      # wrapped blob (internal use only)
    credential_hint: str = ""     # short non-secret prefix for show views
    status: str = "active"
    last_inventory_at: str = ""
    last_scan_at: str = ""
    created_by: str = ""
    id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def validate(self):
        if not self.org_id:
            raise errors.ValidationError(
                "Cloud account requires an org_id")
        if not self.provider or not re.match(r"^[a-z][a-z0-9_-]{1,23}$",
                                             self.provider):
            raise errors.ValidationError(
                "Cloud account provider must be 2-24 chars "
                "[a-z0-9_-]")
        if not (self.account_identifier or "").strip() or \
                len(self.account_identifier) > 256:
            raise errors.ValidationError(
                "Cloud account requires an account_identifier (1-256)")
        if len(self.credential_hint) > 160:
            raise errors.ValidationError("credential_hint too long")
        if len(self.credential_ref) > 128:
            raise errors.ValidationError("credential_ref too long")

    def finalize(self):
        # normalize BEFORE validation so 'AWS'/'aws' both map to 'aws'
        self.provider = str(self.provider or "").strip().lower()
        self.account_identifier = str(self.account_identifier or "").strip()
        self.validate()
        if isinstance(self.region_scope, (list, tuple)):
            self.region_scope = [str(r)[:64] for r in self.region_scope][:64]
        else:
            self.region_scope = []
        now = utcnow()
        self.created_at = self.created_at or now
        self.updated_at = now
        if not self.id:
            self.id = stable_id(
                NS_CLOUDACCOUNT,
                f"{self.org_id}|{self.provider}|{self.account_identifier}")

    def to_dict(self) -> dict:
        """Serialization view. NEVER exposes credential material."""
        import redact
        return redact.redact({
            "id": self.id, "org_id": self.org_id,
            "provider": self.provider,
            "account_identifier": self.account_identifier,
            "display_name": self.display_name,
            "enabled": bool(self.enabled),
            "region_scope": list(self.region_scope),
            "credential_ref": self.credential_ref,
            "credential_hint": self.credential_hint,
            "status": self.status,
            "last_inventory_at": self.last_inventory_at,
            "last_scan_at": self.last_scan_at,
            "created_by": self.created_by,
            "created_at": self.created_at, "updated_at": self.updated_at})

    @classmethod
    def from_row(cls, row) -> "CloudAccount":
        import store as _store
        d = dict(row)
        d["region_scope"] = _store.loads(d.get("region_scope", "[]"))
        return cls(org_id=d.get("org_id", ""),
                   provider=d.get("provider", ""),
                   account_identifier=d.get("account_identifier", ""),
                   display_name=d.get("display_name", ""),
                   enabled=int(d.get("enabled", 1) or 1),
                   region_scope=d.get("region_scope") or [],
                   credential_ref=d.get("credential_ref", ""),
                   credential_enc=d.get("credential_enc", ""),
                   credential_hint=d.get("credential_hint", ""),
                   status=d.get("status", "active"),
                   last_inventory_at=d.get("last_inventory_at", ""),
                   last_scan_at=d.get("last_scan_at", ""),
                   created_by=d.get("created_by", ""),
                   id=d.get("id", ""),
                   created_at=d.get("created_at", ""),
                   updated_at=d.get("updated_at", ""))


@dataclass
class ContainerImage:
    """Container image registration — identity is the immutable DIGEST
    (registry/repository@sha256:...); tags are mutable metadata only
    (spec §19)."""

    org_id: str
    repository: str
    digest: str
    registry: str = ""
    tags: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    package_count: int = 0
    vuln_count: int = 0
    id: str = ""
    created_at: str = ""
    scanned_at: str = ""

    def validate(self):
        if not self.org_id or not self.repository:
            raise errors.ValidationError(
                "Container image requires org_id and repository")
        if not _DIGEST_RE.match(self.digest or ""):
            raise errors.ValidationError(
                "Container image digest must be sha256:<64 hex> "
                "(immutable identity — tags are not identity)")

    def finalize(self):
        self.validate()
        self.repository = self.repository.strip()
        self.digest = self.digest.strip().lower()
        self.created_at = self.created_at or utcnow()
        if not self.id:
            self.id = stable_id(
                NS_IMAGE, f"{self.org_id}|{self.repository}|{self.digest}")

    def to_dict(self) -> dict:
        """Serialization view. metadata is redacted (callers must not put
        credentials there; belt-and-braces redaction applies)."""
        import redact
        return redact.redact({
            "id": self.id, "org_id": self.org_id,
            "registry": self.registry, "repository": self.repository,
            "digest": self.digest, "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "package_count": int(self.package_count),
            "vuln_count": int(self.vuln_count),
            "created_at": self.created_at, "scanned_at": self.scanned_at})

    @classmethod
    def from_row(cls, row) -> "ContainerImage":
        import store as _store
        d = dict(row)
        return cls(org_id=d.get("org_id", ""),
                   registry=d.get("registry", ""),
                   repository=d.get("repository", ""),
                   digest=d.get("digest", ""),
                   tags=_store.loads(d.get("tags", "[]")),
                   metadata=_store.loads(d.get("metadata", "{}")),
                   package_count=int(d.get("package_count", 0) or 0),
                   vuln_count=int(d.get("vuln_count", 0) or 0),
                   id=d.get("id", ""),
                   created_at=d.get("created_at", ""),
                   scanned_at=d.get("scanned_at", ""))


@dataclass
class KubernetesCluster:
    """Tenant-bound Kubernetes cluster registration (spec §21)."""

    org_id: str
    name: str
    provider: str = "k8s"
    api_ref: str = ""          # credentials REFERENCE only (no secrets)
    context: dict = field(default_factory=dict)   # redacted connection ctx
    id: str = ""
    created_at: str = ""
    scanned_at: str = ""

    def validate(self):
        if not self.org_id or not (self.name or "").strip():
            raise errors.ValidationError(
                "Kubernetes cluster requires org_id and name")

    def finalize(self):
        self.validate()
        self.name = self.name.strip()
        self.created_at = self.created_at or utcnow()
        if not self.id:
            self.id = stable_id(NS_K8SCLUSTER, f"{self.org_id}|{self.name}")

    def to_dict(self) -> dict:
        import redact
        return redact.redact({
            "id": self.id, "org_id": self.org_id, "name": self.name,
            "provider": self.provider, "api_ref": self.api_ref,
            "context": dict(self.context),
            "created_at": self.created_at, "scanned_at": self.scanned_at})

    @classmethod
    def from_row(cls, row) -> "KubernetesCluster":
        import store as _store
        d = dict(row)
        return cls(org_id=d.get("org_id", ""), name=d.get("name", ""),
                   provider=d.get("provider", "k8s"),
                   api_ref=d.get("api_ref", ""),
                   context=_store.loads(d.get("context", "{}")),
                   id=d.get("id", ""),
                   created_at=d.get("created_at", ""),
                   scanned_at=d.get("scanned_at", ""))


@dataclass
class IacScanRecord:
    """One bounded IaC assessment (spec §26/§27): scan provenance, file
    counts and explicit status — an unavailable/failed parse is NEVER
    reported as '0 findings / PASS' (status stays failed/inconclusive)."""

    org_id: str
    project_id: str
    scan_id: str = ""
    source_name: str = ""      # e.g. repo name or upload label
    file_name: str = ""        # single-file mode (archive scans expand)
    format: str = "auto"       # auto | terraform | k8s_yaml | cloudformation | helm
    files_parsed: int = 0
    resource_count: int = 0
    secret_count: int = 0
    finding_count: int = 0
    status: str = "completed"  # completed | failed | inconclusive | pending
    error_code: str = ""       # §47 explicit failure codes
    created_by: str = ""
    id: str = ""
    created_at: str = ""

    def validate(self):
        if not self.org_id or not self.project_id:
            raise errors.ValidationError(
                "IaC scan requires org_id and project_id")
        if self.status not in IAC_SCAN_STATUSES:
            raise errors.ValidationError(f"Invalid IaC scan status: "
                                         f"{self.status}")

    def finalize(self):
        self.validate()
        self.created_at = self.created_at or utcnow()
        if not self.id:
            self.id = stable_id(
                NS_IACSCAN,
                f"{self.org_id}|{self.project_id}|{self.created_at}|"
                f"{self.source_name}|{self.file_name}")

    def to_dict(self) -> dict:
        return {"id": self.id, "org_id": self.org_id,
                "project_id": self.project_id, "scan_id": self.scan_id,
                "source_name": self.source_name,
                "file_name": self.file_name, "format": self.format,
                "files_parsed": int(self.files_parsed),
                "resource_count": int(self.resource_count),
                "secret_count": int(self.secret_count),
                "finding_count": int(self.finding_count),
                "status": self.status, "error_code": self.error_code,
                "created_by": self.created_by,
                "created_at": self.created_at}

    @classmethod
    def from_row(cls, row) -> "IacScanRecord":
        d = dict(row)
        return cls(org_id=d.get("org_id", ""),
                   project_id=d.get("project_id", ""),
                   scan_id=d.get("scan_id", ""),
                   source_name=d.get("source_name", ""),
                   file_name=d.get("file_name", ""),
                   format=d.get("format", "auto"),
                   files_parsed=int(d.get("files_parsed", 0) or 0),
                   resource_count=int(d.get("resource_count", 0) or 0),
                   secret_count=int(d.get("secret_count", 0) or 0),
                   finding_count=int(d.get("finding_count", 0) or 0),
                   status=d.get("status", "completed"),
                   error_code=d.get("error_code", ""),
                   created_by=d.get("created_by", ""),
                   id=d.get("id", ""),
                   created_at=d.get("created_at", ""))


@dataclass
class PasswordReset:
    user_id: str
    token_hash: str               # sha256(one-time token) — NEVER serialized
    id: str = ""
    created_at: str = ""
    expires_at: str = ""
    used_at: str = ""

    def validate(self):
        if not self.user_id or not TAG_RE.match(self.user_id):
            raise errors.ValidationError("Password reset requires a user_id")
        if not self.token_hash or len(self.token_hash) != 64:
            raise errors.ValidationError("Reset token hash is malformed")

    def finalize(self):
        self.validate()
        if not self.id:
            self.id = stable_id(NS_RESET,
                                f"{self.user_id}|{self.created_at}|"
                                f"{self.token_hash[:16]}")
        self.created_at = self.created_at or utcnow()
        self.expires_at = self.expires_at or self.created_at

    def to_dict(self) -> dict:
        return {"id": self.id, "user_id": self.user_id,
                "created_at": self.created_at, "expires_at": self.expires_at,
                "used_at": self.used_at}

    @classmethod
    def from_dict(cls, d: dict) -> "PasswordReset":
        return cls(user_id=d.get("user_id", ""),
                   token_hash=d.get("token_hash", ""),
                   id=d.get("id", ""), created_at=d.get("created_at", ""),
                   expires_at=d.get("expires_at", ""),
                   used_at=d.get("used_at", ""))


# ---------------------------------------------------------------------------
# Phase-3 orchestration models (persistent queue, stage checkpoints).
# Payloads pass through redact.redact() before they are ever stored.
# ---------------------------------------------------------------------------
@dataclass
class Job:
    org_id: str
    project_id: str
    scan_id: str
    job_type: str = "scan"
    profile: str = ""
    status: str = "created"
    priority: int = 3
    attempt: int = 0
    max_attempts: int = 3
    active_enabled: bool = False
    timeout_seconds: int = 300
    id: str = ""
    created_at: str = ""
    queued_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    heartbeat_at: str = ""
    lease_until: str = ""
    retry_at: str = ""
    worker_id: str = ""
    actor_id: str = ""
    error_code: str = ""
    error_message: str = ""
    payload: dict = field(default_factory=dict)
    result_reference: str = ""

    def validate(self):
        if not self.org_id or not TAG_RE.match(self.org_id):
            raise errors.ValidationError("Job requires a valid org_id")
        if not self.project_id or not TAG_RE.match(self.project_id):
            raise errors.ValidationError("Job requires a valid project_id")
        if not self.scan_id or not TAG_RE.match(self.scan_id):
            raise errors.ValidationError("Job requires a valid scan_id")
        if self.status not in JOB_STATUSES:
            raise errors.ValidationError(f"Invalid job status: {self.status}")
        if not isinstance(self.priority, int) or self.priority not in (1, 2, 3, 4):
            raise errors.ValidationError(
                "Job priority must be 1(critical)..4(low)")
        if not 1 <= int(self.max_attempts) <= 20:
            raise errors.ValidationError(
                "Job max_attempts must be in 1..20")
        if not 1 <= int(self.timeout_seconds) <= 86400:
            raise errors.ValidationError(
                "Job timeout_seconds must be in 1..86400")
        if not isinstance(self.payload, dict):
            raise errors.ValidationError("Job payload must be a JSON object")

    def finalize(self):
        self.validate()
        if not self.id:
            self.id = stable_id(NS_JOB,
                                f"{self.scan_id}|{self.job_type}|"
                                f"{self.created_at}|{self.payload_hash()}")
        self.created_at = self.created_at or utcnow()

    def payload_hash(self) -> str:
        import json as _json
        return hashlib.sha256(
            _json.dumps(self.payload, sort_keys=True,
                        default=str).encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {"id": self.id, "org_id": self.org_id,
                "project_id": self.project_id, "scan_id": self.scan_id,
                "job_type": self.job_type, "profile": self.profile,
                "status": self.status, "priority": self.priority,
                "attempt": self.attempt, "max_attempts": self.max_attempts,
                "active_enabled": bool(self.active_enabled),
                "timeout_seconds": self.timeout_seconds,
                "created_at": self.created_at, "queued_at": self.queued_at,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "heartbeat_at": self.heartbeat_at,
                "worker_id": self.worker_id,
                "error_code": self.error_code,
                "error_message": self.error_message,
                "result_reference": self.result_reference,
                "payload": self.payload}

    @classmethod
    def from_dict(cls, d: dict) -> "Job":
        return cls(org_id=d.get("org_id", ""), project_id=d.get("project_id", ""),
                   scan_id=d.get("scan_id", ""),
                   job_type=d.get("job_type", "scan"),
                   profile=d.get("profile", ""),
                   status=d.get("status", "created"),
                   priority=int(d.get("priority", 3) or 3),
                   attempt=int(d.get("attempt", 0) or 0),
                   max_attempts=int(d.get("max_attempts", 3) or 3),
                   active_enabled=bool(int(d.get("active_enabled", 0) or 0)),
                   timeout_seconds=int(d.get("timeout_seconds", 300) or 300),
                   id=d.get("id", ""), created_at=d.get("created_at", ""),
                   queued_at=d.get("queued_at", ""),
                   started_at=d.get("started_at", ""),
                   finished_at=d.get("finished_at", ""),
                   heartbeat_at=d.get("heartbeat_at", ""),
                   lease_until=d.get("lease_until", ""),
                   retry_at=d.get("retry_at", ""),
                   worker_id=d.get("worker_id", ""),
                   actor_id=d.get("actor_id", ""),
                   error_code=d.get("error_code", ""),
                   error_message=d.get("error_message", ""),
                   payload=d.get("payload") or {},
                   result_reference=d.get("result_reference", ""))


@dataclass
class StageRecord:
    scan_id: str
    stage: str
    status: str = "pending"
    job_id: str = ""
    attempt: int = 0
    id: str = ""
    created_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    result_reference: str = ""
    error_code: str = ""
    error_message: str = ""

    def validate(self):
        if not self.scan_id or not TAG_RE.match(self.scan_id):
            raise errors.ValidationError("Stage requires a valid scan_id")
        if not self.stage or len(self.stage) > 64 or not re.match(
                r"^[a-z0-9_]{1,64}$", self.stage):
            raise errors.ValidationError(f"Invalid stage name: {self.stage!r}")
        if self.status not in STAGE_STATUSES:
            raise errors.ValidationError(f"Invalid stage status: {self.status}")

    def finalize(self):
        self.validate()
        self.created_at = self.created_at or utcnow()
        if not self.id:
            self.id = stable_id(NS_STAGE, f"{self.scan_id}|{self.stage}")

    def to_dict(self) -> dict:
        return {"id": self.id, "scan_id": self.scan_id, "stage": self.stage,
                "status": self.status, "job_id": self.job_id,
                "attempt": self.attempt, "created_at": self.created_at,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "result_reference": self.result_reference,
                "error_code": self.error_code,
                "error_message": self.error_message}

    @classmethod
    def from_dict(cls, d: dict) -> "StageRecord":
        return cls(scan_id=d.get("scan_id", ""), stage=d.get("stage", ""),
                   status=d.get("status", "pending"),
                   job_id=d.get("job_id", ""),
                   attempt=int(d.get("attempt", 0) or 0),
                   id=d.get("id", ""), created_at=d.get("created_at", ""),
                   started_at=d.get("started_at", ""),
                   finished_at=d.get("finished_at", ""),
                   result_reference=d.get("result_reference", ""),
                   error_code=d.get("error_code", ""),
                   error_message=d.get("error_message", ""))


# ---------------------------------------------------------------------------
# Risk metadata (foundation only — no fake scoring)
# ---------------------------------------------------------------------------
def risk_metadata(*, severity: str, confidence: str = "medium",
                  asset_criticality: str = "medium",
                  internet_exposure: bool | None = None,
                  cvss: dict | None = None,
                  cwe: str = "", cve: str = "") -> dict:
    """Normalized risk metadata. Deliberately NOT a score: later phases may
    add exploitability/vuln-intelligence with real sources."""
    if severity not in SEVERITIES:
        raise errors.ValidationError(f"Unknown severity: {severity}")
    if confidence not in CONFIDENCE:
        raise errors.ValidationError(f"Unknown confidence: {confidence}")
    if asset_criticality not in ("low", "medium", "high", "critical"):
        raise errors.ValidationError(
            f"Unknown asset criticality: {asset_criticality}")
    return {"severity": severity, "confidence": confidence,
            "asset_criticality": asset_criticality,
            "internet_exposure": internet_exposure,
            "cvss": dict(cvss or {}), "cwe": cwe, "cve": cve,
            "scored": False,
            "note": "risk metadata carried forward; scoring is a later phase"}
