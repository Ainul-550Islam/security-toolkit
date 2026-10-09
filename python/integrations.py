#!/usr/bin/env python3
# ============================================================================
#  integrations.py — Phase 13: enterprise security integrations & external
#  event pipeline (provider-neutral connector framework).
#  ---------------------------------------------------------------------------
#  WHAT THIS MODULE IS:
#    The operational layer for outbound event delivery and inbound security
#    event ingestion across SIEM / EDR / XDR / SOAR / ticketing / GRC /
#    data-lake / notification / generic-webhook connector categories.
#
#  WHAT IT REUSES (never replaces — no parallel architectures):
#    - Phase-12 `external_integrations` / `integration_events` tables are
#      the connection identity and canonical high-level emission record;
#      schema v15 extended them in place (no second connection table).
#    - Phase-3 job engine (jobs.JobService): delivery jobs run through the
#      EXISTING retry taxonomy, backoff+jitter, leases, heartbeat, cancel
#      and dead-letter semantics. Bulk material staging follows the
#      federation BulkRunner precedent (envelope staged on the job's scan
#      record via scan_save_raw — payloads stay scalar-only and redacted).
#      The `integration-delivery` profile is registered on the registry
#      instance this module builds; the canonical ScannerRegistry/worker
#      wiring lands with the worker extension (same in-process contract as
#      federation-bulk: run_for_job(job)).
#    - notify.sign_payload / verify_signature: HMAC-SHA256 over
#      timestamp|body with constant-time compare and a bounded timestamp
#      window — the ONLY signing/verification scheme (closed allowlist
#      models.INTEGRATION_HMAC_ALGORITHMS).
#    - notify.validate_webhook_url: the EXISTING SSRF guard (https-only,
#      private-network/refused-suffix blocking, no redirects, timeouts,
#      bounded responses) for every outbound endpoint, at configuration
#      time AND before every delivery attempt.
#    - redact (Phase-11 single redaction engine) before ANY persistence,
#      audit, event or provider handoff; secrets_registry via
#      data_governance for credential REFERENCES (never values).
#    - Phase-4 finding_ingest (fingerprint/dedup/risk), Phase-5 security
#      events + alert-rule inputs, Phase-10 IOC catalog + investigation
#      cases, existing audit hash chain, existing per-key rate limiter.
#
#  HARD BOUNDARIES (enforced in code, visible in every serialization):
#    - EDR/XDR connectors are VISIBILITY ONLY: inbound events; no endpoint
#      control of any kind is representable (no kill/isolate/remove/
#      registry/command/agent concepts exist in this module).
#    - SOAR connectors are HANDOFF ONLY: the platform sends a case handoff
#      and may receive signed, replay-protected, idempotent, audited
#      callbacks; it NEVER executes playbooks and no playbook construct
#      exists here.
#    - Ticketing/GRC connectors exchange EXTERNAL REFERENCES only (local
#      findings/cases remain the source of truth; no second ticket DB).
#    - Data-lake connectors are a bounded export interface (capped,
#      hashed, idempotent) — no Hadoop/Spark/Kafka integration exists.
#    - NO fake vendor connectivity: a delivery is only "sent" after a real
#      provider interaction returned success. The test_stub adapter always
#      reports outcome "test_stub" and never produces healthy state;
#      health_state becomes "healthy" only after a real successful
#      protocol interaction (outbound receipt or accepted inbound event).
#    - NO autonomous remediation, NO LLM-driven decisions, NO eval/exec/
#      shell/pickle/unsafe-YAML, NO unbounded queries or payloads, NO
#      silent exception swallowing, NO secret material in logs, audit,
#      events, errors, metrics, receipts or stored rows.
#
#  RBAC: permissions (integration.manage/configure/read/test/enable/
#  disable/send/ingest/audit/health) are defined in rbac.py and enforced
#  at the API/CLI boundary (Phase-12 precedent); this service enforces
#  tenant isolation, separation of duties (creator != approver on
#  high-impact enable), closed vocabularies and rate limits itself.
# ============================================================================

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import errors
import metrics
import models
import redact
import store

import events as _events_mod
import identity as _id_mod
import notify as _notify

# ---------------------------------------------------------------------------
# Bounded constants (canonical; services must reject anything beyond them)
# ---------------------------------------------------------------------------
MAX_LIST_LIMIT = 200            # same page cap as the Phase-12 boundary
MAX_CONFIG_BYTES = 16384        # 16 KiB cap on connection config_json
MAX_OUTBOUND_BYTES = 16384      # 16 KiB cap per outbound envelope (Phase-12
                                # webhook payload cap, unchanged)
MAX_INBOUND_BYTES = 262144      # 256 KiB hard cap per inbound event body
MAX_NAME_LEN = 120
MAX_TEXT_LEN = 200
MAX_DESC_LEN = 2000
MAX_EXTERNAL_ID_LEN = 190
MAX_PROVIDER_LEN = 80

REPLAY_WINDOW_SECONDS = 300     # ±5 min timestamp window for signed inbound
CIRCUIT_FAILURE_THRESHOLD = 5   # consecutive delivery failures → open
CIRCUIT_OPEN_SECONDS = 300      # open → half-open probe after this window
DEFAULT_MAX_ATTEMPTS = 3
MAX_MAX_ATTEMPTS = 10           # bounded retry ceiling (job engine taxonomy)

ABNORMAL_VOLUME_WINDOW_SECONDS = 60
ABNORMAL_VOLUME_THRESHOLD = 120  # inbound events per integration per window

DELIVERY_PROFILE = "integration-delivery"
DELIVERY_JOB_TYPE = "integration_delivery"
DELIVERY_STAGE = "integration_delivery"
INTEGRATIONS_SCAN_KIND = "integrations"

# Per-operation rate limits (limit, window_seconds) — the EXISTING
# identity.RateLimiter is the only rate-limiting engine.
RATE = {
    "connection": (60, 60),
    "test": (20, 60),
    "send": (120, 60),
    "ingest": (240, 60),
    "health": (30, 60),
}

# Provider-neutral payload adapters (§11). Closed set; unknown rejected.
ADAPTER_KINDS = ("generic_webhook", "syslog_like", "cef_like",
                 "json_security_event", "test_stub")

# Deterministic default adapter per connector category (config may override
# within ADAPTER_KINDS, except test_stub which is NEVER a default — it must
# always be an explicit, visible choice).
DEFAULT_ADAPTER_BY_KIND = {
    "siem": "json_security_event",
    "edr": "json_security_event",
    "xdr": "json_security_event",
    "soar": "json_security_event",
    "ticketing": "generic_webhook",
    "grc": "generic_webhook",
    "data_lake": "json_security_event",
    "notification": "generic_webhook",
    "generic_webhook": "generic_webhook",
}

# Capability boundaries per connector category (§7). Enforced on every
# outbound send / inbound ingest and serialized into every connection view
# so the boundary is obvious in UI/CLI/API.
CONNECTOR_CAPABILITIES = {
    "siem": ("outbound_events", "inbound_events"),
    "edr": ("inbound_events",),
    "xdr": ("inbound_events",),
    "soar": ("outbound_handoff", "inbound_callback"),
    "ticketing": ("outbound_reference", "inbound_status"),
    "grc": ("outbound_reference", "inbound_status"),
    "data_lake": ("outbound_export",),
    "notification": ("outbound_events",),
    "generic_webhook": ("outbound_events", "inbound_events"),
}

# Closed outbound business-event vocabulary (service-level, mirrors the
# Phase-12 WEBHOOK_EVENTS pattern — never free-form event names).
OUTBOUND_EVENT_TYPES = (
    "security_event", "finding", "alert", "health_ping",
    "case_handoff", "ticket_reference", "export_batch",
)

# Each outbound event type requires one capability; the connector category
# must hold it (policy-violation signal + rejection otherwise).
EVENT_REQUIRED_CAPABILITY = {
    "security_event": "outbound_events",
    "finding": "outbound_events",
    "alert": "outbound_events",
    "health_ping": "outbound_events",
    "case_handoff": "outbound_handoff",
    "ticket_reference": "outbound_reference",
    "export_batch": "outbound_export",
}

# Inbound event types allowed per inbound capability (§8/§9 boundaries).
INBOUND_ALLOWED_BY_CAPABILITY = {
    "inbound_events": frozenset({"finding", "alert", "security_event",
                                 "threat_intel_match"}),
    "inbound_callback": frozenset({"case", "security_event"}),
    "inbound_status": frozenset({"security_event"}),
}

# Inbound routing targets — every route lands in an EXISTING system:
#   finding / alert / security_event → Phase-4 finding_ingest (fingerprint,
#       dedup, risk engine authoritative; categories keep provenance)
#   case                             → Phase-10 investigation cases
#   threat_intel_match               → Phase-10 IOC catalog (deterministic
#       stable ids — repeated indicators never duplicate)
FINDING_CATEGORY_BY_INBOUND_TYPE = {
    "finding": "external_finding",
    "alert": "external_alert",
    "security_event": "external_security_event",
}

# Phase-10 security-operations finding rule ids raised by pipeline signals
# (spec observability matrix — closed set).
RULE_AUTH_FAILURE = "integration-auth-failure"
RULE_REPLAY = "integration-replay"
RULE_INTEGRITY = "integration-integrity-failure"
RULE_POLICY = "integration-policy-violation"
RULE_VOLUME = "integration-abnormal-volume"

# Error classes for delivery failures — mirror the Phase-3 job taxonomy:
# configuration/authorization/validation/unsupported are NEVER retryable.
NON_RETRYABLE_OUTCOME_CODES = frozenset({
    "config_invalid", "validation_rejected", "auth_failed", "scope_denied",
    "payload_rejected", "unsupported_provider",
})


# ---------------------------------------------------------------------------
# Small deterministic helpers (same shapes as the federation module)
# ---------------------------------------------------------------------------
def _now() -> str:
    return models.utcnow()


def _epoch(ts) -> float:
    """ISO-8601 UTC → epoch seconds. Unparsable/empty → 0.0 (never raises;
    comparisons against '' sentinels must stay deterministic)."""
    s = str(ts or "").strip()
    if not s:
        return 0.0
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _bounded(value, limit: int) -> str:
    s = str(value if value is not None else "")
    return s[:limit]


def _safe_error(value, limit: int = 200) -> str:
    """Bound and redact an untrusted provider/operator error before it can
    be persisted, audited, logged or returned through any read model."""
    return _bounded(redact.redact_text(str(value or "")), limit)


def _bound_int(value, *, lo: int, hi: int, default: int, label: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if n < lo or n > hi:
        raise errors.ValidationError(f"{label} must be between {lo} and {hi}")
    return n


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(obj) -> str:
    """Deterministic canonical JSON (the hashing/serialization form used by
    every envelope, digest and signature in this module)."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)


def _printable_line(text: str, limit: int) -> str:
    """Single-line, printable-ASCII-safe rendering (syslog/CEF bodies must
    never contain control characters or line breaks — log-injection guard)."""
    out = []
    for ch in str(text):
        o = ord(ch)
        if ch in ("\\", "|"):
            out.append("\\" + ch)
        elif o == 10:
            out.append("\\n")
        elif o == 13:
            out.append("\\r")
        elif 32 <= o < 127:
            out.append(ch)
        else:
            out.append(f"\\x{o:02x}")
    return "".join(out)[:limit]


# ---------------------------------------------------------------------------
# Provider-neutral payload adapters (§11) — format only, never transport.
# Transport is the injected provider (.send(settings, payload)), i.e. the
# EXISTING notify WebhookProvider (real HTTPS + SSRF guard + HMAC signing)
# or RecordingProvider (tests). No adapter ever claims success by itself.
# ---------------------------------------------------------------------------
class GenericWebhookAdapter:
    """Plain bounded JSON envelope (redaction already applied upstream)."""

    kind = "generic_webhook"

    def format(self, event: dict) -> dict:
        return {"schema": "secutoolk-integration-v1", "format": "json",
                "event": event}


class SyslogLikeAdapter:
    """RFC3164-shaped single line. This is a syslog-LIKE textual format
    handed to the configured transport — no syslog daemon is bundled and
    none is simulated."""

    kind = "syslog_like"

    def format(self, event: dict) -> dict:
        sev = str(event.get("severity") or "Info")
        pri = {"Critical": 130, "High": 131, "Medium": 132,
               "Low": 133, "Info": 134}.get(sev, 134)
        line = (f"<{pri}>{event.get('event_time', '')} SecuToolkit "
                f"integration[{event.get('connector_kind', '')}]: "
                f"{event.get('event_type', '')} "
                f"{_canonical(event.get('data') or {})}")
        return {"schema": "secutoolk-integration-v1", "format": "syslog",
                "event": {k: v for k, v in event.items() if k != "data"},
                "body": _printable_line(line, MAX_OUTBOUND_BYTES)}


class CefLikeAdapter:
    """CEF:0-style line (ArcSight-compatible SHAPE). This is a CEF-LIKE
    textual format only — no vendor product is implemented or implied."""

    kind = "cef_like"

    def format(self, event: dict) -> dict:
        sev_num = {"Critical": 10, "High": 8, "Medium": 6, "Low": 3,
                   "Info": 1}.get(str(event.get("severity") or "Info"), 1)
        head = "|".join(_printable_line(part, 120) for part in (
            "CEF:0", "SecuToolkit", "IntegrationPipeline", "13",
            str(event.get("event_type") or ""),
            str(event.get("integration_id") or "")[:64], str(sev_num)))
        ext = (f" externalId={_printable_line(event.get('event_id', ''), 64)}"
               f" cs1Label=connectorKind"
               f" cs1={_printable_line(event.get('connector_kind', ''), 40)}"
               f" cn1Label=confidence"
               f" cn1={_printable_line(event.get('confidence', ''), 20)}"
               f" msg={_printable_line(_canonical(event.get('data') or {}), 1024)}")
        # header separators stay RAW '|' (CEF format); every VALUE was
        # already escaped by _printable_line above — never re-escape the
        # assembled line (that would corrupt the delimiters)
        body = (head + ext)[:MAX_OUTBOUND_BYTES]
        return {"schema": "secutoolk-integration-v1", "format": "cef",
                "event": {k: v for k, v in event.items() if k != "data"},
                "body": body}


class JsonSecurityEventAdapter:
    """Normalized JSON security-event schema (the data-lake/SIEM export
    shape): fixed top-level fields + bounded data object."""

    kind = "json_security_event"

    def format(self, event: dict) -> dict:
        return {"schema": "security-event-v1",
                "event_id": event.get("event_id", ""),
                "event_type": event.get("event_type", ""),
                "event_time": event.get("event_time", ""),
                "severity": event.get("severity", "Info"),
                "confidence": event.get("confidence", ""),
                "source_organization": event.get("source_organization", ""),
                "connector_kind": event.get("connector_kind", ""),
                "data": event.get("data") or {}}


class TestStubAdapter:
    """Honest test stub: formats like the generic adapter but the service
    ALWAYS reports outcome `test_stub` for it — never `sent`, never
    healthy. It exists so configuration can be exercised without any
    protocol interaction being faked."""

    kind = "test_stub"

    def format(self, event: dict) -> dict:
        return {"schema": "secutoolk-integration-v1", "format": "test_stub",
                "event": event}


ADAPTERS = {a.kind: a for a in (
    GenericWebhookAdapter(), SyslogLikeAdapter(), CefLikeAdapter(),
    JsonSecurityEventAdapter(), TestStubAdapter())}


def adapter_for(connector_kind: str, config: dict):
    """Deterministic adapter selection: explicit closed-vocabulary config
    override, else the per-category default. test_stub is never implicit."""
    explicit = str((config or {}).get("adapter") or "").strip().lower()
    if explicit:
        if explicit not in ADAPTER_KINDS:
            raise errors.ValidationError(
                f"unknown adapter: {explicit!r} "
                f"(allowlist: {', '.join(ADAPTER_KINDS)})")
        return ADAPTERS[explicit]
    return ADAPTERS[DEFAULT_ADAPTER_BY_KIND[connector_kind]]


# ---------------------------------------------------------------------------
# Shared service base — the same shape as the Phase-10/11/12 services.
# ---------------------------------------------------------------------------
class _Base:
    """Platform handle, bounded queries, tenant guards, rate limiting,
    audit + security-event emission through the EXISTING systems."""

    def __init__(self, platform, *, limiter=None, provider=None, gov=None):
        self.svc = platform
        self.db = platform.db
        self.limiter = limiter or _id_mod.RateLimiter(max_keys=4096)
        self.provider = provider or _notify.PROVIDERS["webhook"]
        self.gov = gov

    # ------------------------------------------------------------- guards
    def _acquire(self, key: str, op: str) -> None:
        limit, window = RATE[op]
        ok, retry = self.limiter.allowed(key, limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"{op} rate limit exceeded", retry_after=retry)

    def _org(self, org_id: str):
        return self.svc.org_require(org_id) or self.svc.org_get(org_id)

    def _project_owned(self, org_id: str, project_id: str) -> None:
        if project_id:
            proj = self.svc.project_require(project_id)
            if proj.org_id != org_id:
                raise errors.NotFoundError("project not found")

    # ------------------------------------------------------------- audit
    def _audit(self, action: str, *, object_type: str, object_id: str,
               org_id: str, project_id: str = "", actor: str = "api",
               metadata: dict | None = None) -> None:
        try:
            self.svc.audit(
                action, object_type=object_type, object_id=object_id,
                org_id=org_id, project_id=project_id or "",
                actor=str(actor)[:128],
                metadata=redact.redact(dict(metadata or {})))
        except Exception:
            # auditing must never break the primary operation (same rule as
            # platform.audit / Phase-11/12 services); the failure stays
            # observable through metrics
            metrics.inc("integrations_audit_failures")

    def _emit(self, project_id: str, event_type: str, *, key: str = "",
              source: str = "integration", confidence: float = 0.6,
              new_state=None, actor: str = "system", org_id: str = ""):
        if not project_id:
            return None
        try:
            return _events_mod.SecurityEventService(self.svc).emit(
                project_id, event_type, asset_id="",
                key=_bounded(key, 160), scan_id="", source=source,
                confidence=confidence, previous_state=None,
                new_state=new_state, actor=actor, org_id=org_id)
        except (errors.ValidationError, errors.NotFoundError):
            return None

    # ------------------------------------------------------------- queries
    def _q(self, sql, params=()):
        return self.db.query(sql, tuple(params))

    def _one(self, sql, params=()):
        return self.db.query_one(sql, tuple(params))

    def _maybe(self, sql, params=()):
        try:
            return self.db.query_one(sql, tuple(params))
        except errors.NotFoundError:
            return None

    def _page_limit(self, value, *, default: int = 100) -> int:
        return _bound_int(value, lo=1, hi=MAX_LIST_LIMIT, default=default,
                          label="limit")

    # ------------------------------------------------------------- jobs
    def _jobs(self):
        """JobService over a registry carrying the in-process
        `integration-delivery` profile (federation-bulk precedent). The
        canonical scanners.py/worker wiring is added by the worker
        extension file; run_for_job below is the identical contract."""
        import jobs as _jobs
        import scanners as _scanners
        reg = _scanners.ScannerRegistry()
        if DELIVERY_PROFILE not in reg.PROFILES:
            # conditional: once the canonical registration lands in
            # scanners.py (worker wiring file), this becomes a no-op
            reg._add(_scanners.Profile(
                DELIVERY_PROFILE,
                "Integration delivery (in-process; bounded outbound "
                "delivery attempts with the existing retry taxonomy, "
                "backoff, leases, heartbeat, cancel and dead-letter)",
                [DELIVERY_STAGE], timeout=300, in_process=True,
                permissions_required=("integration.send",)))
        return _jobs.JobService(self.svc, reg)

    def _delivery_scan(self, project_id: str, delivery_id: str):
        """One deterministic scan record per delivery — the staged-envelope
        anchor (bulk material staging precedent; job payloads stay
        scalar-only)."""
        sid = models.stable_id(
            models.NS_SCAN, f"{project_id}|{DELIVERY_PROFILE}|{delivery_id}")
        try:
            return self.svc.scan_get(sid)
        except errors.NotFoundError:
            return self.svc.scan_create(project_id, DELIVERY_PROFILE,
                                        scope_ref=_bounded(delivery_id, 60),
                                        scan_id=sid)

    # --------------------------------------------------- findings / scans
    def _integ_scan(self, project_id: str) -> str:
        """Deterministic per-project 'integrations' scan — findings raised
        by pipeline anomalies or imported from external providers reference
        it (findings REQUIRE a scan_id; federation/threat-intel precedent)."""
        sid = models.stable_id(models.NS_SCAN,
                               f"{project_id}|{INTEGRATIONS_SCAN_KIND}")
        try:
            return self.svc.scan_get(sid).id
        except errors.NotFoundError:
            return self.svc.scan_create(
                project_id, INTEGRATIONS_SCAN_KIND, scope_ref="",
                scan_id=sid).id

    def _security_finding(self, project_id: str, *, rule_id: str, title: str,
                          description: str, severity: str,
                          raw: dict | None = None):
        """Raise a REAL platform finding through the EXISTING normalization,
        fingerprint and dedup pipeline — repeated signals never duplicate.
        Values are redacted before they ever reach the finding."""
        f = models.Finding(
            scan_id=self._integ_scan(project_id),
            project_id=project_id,
            asset_id="",
            title=_bounded(redact.redact_text(title), 200),
            description=_bounded(redact.redact_text(description), 2000),
            severity=severity if severity in models.SEVERITIES else "Medium",
            confidence="medium",
            category="integration",
            source="integrations",
            rule_id=_bounded(rule_id, 64),
            remediation="Review the integration connection configuration, "
                        "credentials and provider health; disable the "
                        "connection if the anomaly persists.",
            evidence=[], raw=redact.redact(dict(raw or {})))
        return self.svc.finding_ingest(f)

    # -------------------------------------------------------- connections
    _CONN_COLS = ("id, org_id, project_id, name, kind, endpoint_url, status, "
                  "created_by, created_at, updated_at, disabled_at, "
                  "last_delivery_at, connector_kind, provider, auth_mode, "
                  "credential_ref, config_json, health_state, "
                  "last_health_check_at, circuit_state, circuit_opened_at, "
                  "circuit_failure_count")

    def _connection(self, org_id: str, integration_id: str) -> dict:
        row = self._maybe(
            f"SELECT {self._CONN_COLS} FROM external_integrations "
            "WHERE id=? AND org_id=?", (integration_id, org_id))
        if row is None:
            raise errors.NotFoundError("integration not found")
        if not str(row.get("connector_kind") or ""):
            # Phase-12 boundary row without a Phase-13 connector category:
            # visible, but the Phase-13 pipeline never operates on it.
            raise errors.ValidationError(
                "not a Phase-13 connector connection (no connector_kind)")
        return row

    def catalog(self) -> dict:
        """Return the canonical closed connector and capability vocabulary."""
        return {
            "connector_kinds": list(models.INTEGRATION_CONNECTOR_KINDS),
            "auth_modes": list(models.INTEGRATION_AUTH_MODES),
            "health_states": list(models.INTEGRATION_HEALTH_STATES),
            "capabilities": {
                kind: list(CONNECTOR_CAPABILITIES.get(kind, ()))
                for kind in models.INTEGRATION_CONNECTOR_KINDS
            },
            "default_adapters": {
                kind: DEFAULT_ADAPTER_BY_KIND.get(kind, "")
                for kind in models.INTEGRATION_CONNECTOR_KINDS
            },
        }

    def _public(self, row: dict) -> dict:
        """Serialization for API/CLI/dashboard: closed vocabularies only,
        config parsed + redacted, capability boundary always visible.
        NEVER contains secret material (credential_ref is a registry
        REFERENCE, like secrets_registry.reference itself)."""
        ck = str(row.get("connector_kind") or "")
        config = store.loads(row.get("config_json") or "", {})
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "project_id": row.get("project_id") or "",
            "name": row["name"],
            "boundary_kind": row.get("kind") or "",
            "connector_kind": ck,
            "capabilities": list(CONNECTOR_CAPABILITIES.get(ck, ())),
            "provider": row.get("provider") or "",
            "endpoint_url": redact.redact_text(
                row.get("endpoint_url") or ""),
            "auth_mode": row.get("auth_mode") or "",
            "credential_ref": row.get("credential_ref") or "",
            "config": redact.redact(dict(config or {})),
            "adapter": str((config or {}).get("adapter") or "")
                       or DEFAULT_ADAPTER_BY_KIND.get(ck, ""),
            "status": row["status"],
            "health_state": row.get("health_state") or "",
            "last_health_check_at": row.get("last_health_check_at") or "",
            "circuit_state": row.get("circuit_state") or "closed",
            "circuit_opened_at": row.get("circuit_opened_at") or "",
            "circuit_failure_count": int(row.get("circuit_failure_count")
                                         or 0),
            "created_by": row.get("created_by") or "",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "disabled_at": row.get("disabled_at") or "",
            "last_delivery_at": row.get("last_delivery_at") or "",
        }

    # ------------------------------------------------------------ circuit
    def _circuit_allows(self, row: dict) -> tuple:
        """(allowed: bool, effective_state: str). Deterministic local
        circuit breaker — bounded failure semantics, no distributed
        infrastructure. open → half_open probe once the window elapsed."""
        state = str(row.get("circuit_state") or "closed")
        if state == "closed":
            return True, "closed"
        opened = _epoch(row.get("circuit_opened_at"))
        if state == "open":
            if opened and (_epoch(_now()) - opened) >= CIRCUIT_OPEN_SECONDS:
                return True, "half_open"
            return False, "open"
        # half_open: a single probe is in flight; further attempts wait
        return False, "half_open"

    def _circuit_success(self, row: dict) -> None:
        self.db.execute(
            "UPDATE external_integrations SET circuit_state='closed', "
            "circuit_failure_count=0, circuit_opened_at='', updated_at=? "
            "WHERE id=?", (_now(), row["id"]))

    def _circuit_failure(self, row: dict) -> None:
        count = int(row.get("circuit_failure_count") or 0) + 1
        now = _now()
        if count >= CIRCUIT_FAILURE_THRESHOLD or \
                str(row.get("circuit_state") or "") == "half_open":
            self.db.execute(
                "UPDATE external_integrations SET circuit_state='open', "
                "circuit_failure_count=?, circuit_opened_at=?, updated_at=? "
                "WHERE id=?", (count, now, now, row["id"]))
            metrics.inc("integrations_circuit_opened")
            self._emit(row.get("project_id") or "",
                       "integration.health_degraded", key=row["id"],
                       org_id=row["org_id"],
                       new_state={"circuit": "open", "failures": count})
        else:
            self.db.execute(
                "UPDATE external_integrations SET circuit_failure_count=?, "
                "updated_at=? WHERE id=?", (count, now, row["id"]))

    def _mark_health(self, row: dict, state: str) -> None:
        """Persist a health state from the closed vocabulary and surface
        degradation transitions as events + audit (never credentials,
        never payloads)."""
        if state not in models.INTEGRATION_HEALTH_STATES:
            raise errors.ValidationError(f"unknown health state: {state!r}")
        now = _now()
        prev = str(row.get("health_state") or "")
        self.db.execute(
            "UPDATE external_integrations SET health_state=?, "
            "last_health_check_at=?, updated_at=? WHERE id=?",
            (state, now, now, row["id"]))
        row["health_state"] = state
        row["last_health_check_at"] = now
        if state != prev:
            self._audit("integration.health_changed",
                        object_type="integration", object_id=row["id"],
                        org_id=row["org_id"],
                        project_id=row.get("project_id") or "",
                        metadata={"from": prev or "unchecked", "to": state})
            if state in ("degraded", "misconfigured", "unreachable") and \
                    prev not in ("degraded", "misconfigured", "unreachable"):
                metrics.inc("integrations_health_degraded")
                self._emit(row.get("project_id") or "",
                           "integration.health_degraded", key=row["id"],
                           org_id=row["org_id"],
                           new_state={"health_state": state})

    def _record_event(self, row: dict, *, event_type: str, status: str,
                      digest: str, byte_size: int, outcome: str,
                      error: str) -> None:
        """Canonical high-level emission record in the EXISTING Phase-12
        integration_events table (§26 — never a second event table)."""
        now = _now()
        eid = models.stable_id(
            models.NS_INTEGRATION_EVENT,
            f"{row['id']}|{event_type}|{digest[:16]}|{time.monotonic_ns()}")
        self.db.execute(
            "INSERT INTO integration_events (id, org_id, project_id, "
            "integration_id, event_type, status, payload_sha256, byte_size, "
            "provider_outcome, error, created_at) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?)",
            (eid, row["org_id"], row.get("project_id") or "", row["id"],
             _bounded(event_type, 64), status, digest, int(byte_size),
             _safe_error(outcome, 40), _safe_error(error, 200), now))
        metrics.inc("federation_integration_events")

    def _signing_secret(self, row: dict, ephemeral: str = "") -> str:
        """Outbound signing secret: the ephemeral operator-provided value
        (in-memory only, never persisted/logged) or the project's EXISTING
        notification webhook secret (Phase-12 emit precedent). Empty when
        neither exists — providers then send unsigned, which the receipt
        records honestly."""
        if ephemeral:
            return str(ephemeral)
        project_id = str(row.get("project_id") or "")
        if not project_id:
            return ""
        try:
            settings = _notify.NotificationService(self.svc) \
                .settings_get(project_id)
            return str(settings.get("webhook_secret") or "")
        except errors.NotFoundError:
            return ""


# ===========================================================================
# Connections — lifecycle over the EXTENDED Phase-12 table (§6/§27)
# ===========================================================================
class ConnectionService(_Base):

    def create(self, org_id: str, *, project_id: str = "", name: str,
               connector_kind: str, auth_mode: str, endpoint_url: str = "",
               provider: str = "", credential_ref: str = "",
               config: dict | None = None, max_attempts: int = 3,
               actor: str = "api") -> dict:
        """Register a connector connection. Created DISABLED — activation
        is a separate high-impact step (enable) with separation of duties.
        Every input is closed-vocabulary validated; the endpoint passes the
        EXISTING SSRF guard at configuration time."""
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"connection:{org_id}", "connection")
        ck = str(connector_kind or "").strip().lower()
        if ck not in models.INTEGRATION_CONNECTOR_KINDS:
            metrics.inc("integrations_config_rejected")
            raise errors.ValidationError(
                f"unknown connector kind: {connector_kind!r} "
                f"(allowlist: {', '.join(models.INTEGRATION_CONNECTOR_KINDS)})")
        am = str(auth_mode or "").strip().lower()
        if am not in models.INTEGRATION_AUTH_MODES:
            metrics.inc("integrations_config_rejected")
            raise errors.ValidationError(
                f"unknown auth mode: {auth_mode!r} "
                f"(allowlist: {', '.join(models.INTEGRATION_AUTH_MODES)})")
        nm = _bounded(redact.redact_text(str(name or "").strip()),
                      MAX_NAME_LEN)
        if len(nm) < 3:
            raise errors.ValidationError("connection name too short")
        url = str(endpoint_url or "").strip()
        if url:
            # SSRF guard reused verbatim (https-only, allowlist semantics,
            # private-network blocking); resolve=False at config time like
            # the Phase-12 boundary, re-resolved before every delivery.
            url = _notify.validate_webhook_url(url, resolve=False)
        prov = _bounded(redact.redact_text(str(provider or "")),
                        MAX_PROVIDER_LEN)
        cref = _bounded(str(credential_ref or "").strip(), MAX_TEXT_LEN)
        cfg = self._validate_config(ck, config or {})
        attempts = _bound_int(max_attempts, lo=1, hi=MAX_MAX_ATTEMPTS,
                              default=DEFAULT_MAX_ATTEMPTS,
                              label="max_attempts")
        cfg["max_attempts"] = attempts
        boundary = models.CONNECTOR_BOUNDARY_MAP[ck]
        iid = models.stable_id(
            models.NS_INTEGRATION_CONNECTION,
            f"{org_id}|{project_id}|{nm}|{ck}")
        now = _now()
        try:
            self.db.execute(
                "INSERT INTO external_integrations (id, org_id, project_id, "
                "name, kind, endpoint_url, status, created_by, created_at, "
                "updated_at, disabled_at, last_delivery_at, connector_kind, "
                "provider, auth_mode, credential_ref, config_json, "
                "health_state, last_health_check_at, circuit_state, "
                "circuit_opened_at, circuit_failure_count) VALUES "
                "(?,?,?, ?,?, ?, 'disabled', ?,?,?, '', '', ?,?,?,?,?, '', '', "
                "'closed', '', 0)",
                (iid, org_id, project_id or "", nm, boundary, url,
                 _bounded(actor, 128), now, now, ck, prov, am, cref,
                 store.dumps(cfg)))
        except sqlite3.IntegrityError:
            raise errors.DuplicateError(
                f"integration already exists: {nm}") from None
        self._audit("integration.created", object_type="integration",
                    object_id=iid, org_id=org_id, project_id=project_id,
                    actor=actor,
                    metadata={"connector_kind": ck, "auth_mode": am,
                              "boundary_kind": boundary,
                              "has_endpoint": bool(url)})
        self._emit(project_id, "integration.created", key=iid,
                   org_id=org_id, new_state={"connector_kind": ck},
                   actor=actor)
        metrics.inc("integrations_created")
        return self.get(org_id, iid)

    def _validate_config(self, connector_kind: str, config: dict) -> dict:
        """Bounded, redacted, closed-vocabulary config. `adapter` must be
        in ADAPTER_KINDS; unknown keys are kept (provider metadata) but
        the whole object is size-capped and redaction-scrubbed."""
        if not isinstance(config, dict):
            raise errors.ValidationError("config must be an object")
        cfg = redact.redact(dict(config))
        adapter_name = str(cfg.get("adapter") or "").strip().lower()
        if adapter_name:
            if adapter_name not in ADAPTER_KINDS:
                metrics.inc("integrations_config_rejected")
                raise errors.ValidationError(
                    f"unknown adapter: {adapter_name!r} "
                    f"(allowlist: {', '.join(ADAPTER_KINDS)})")
            cfg["adapter"] = adapter_name
        text = _canonical(cfg)
        if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
            metrics.inc("integrations_config_rejected")
            raise errors.ValidationError(
                f"config too large (max {MAX_CONFIG_BYTES} bytes)")
        if redact.contains_secret(cfg):
            metrics.inc("integrations_config_rejected")
            raise errors.ValidationError(
                "config_rejected_secret_shape: secret material is never "
                "stored on connections — register it in the credential "
                "governance registry and reference it")
        return cfg

    def get(self, org_id: str, integration_id: str) -> dict:
        self._org(org_id)
        return self._public(self._connection(org_id, integration_id))

    def validate(self, org_id: str, integration_id: str) -> dict:
        """Validate stored configuration without network activity or a
        health claim. Returns only closed reason codes and metadata; endpoint,
        credential references and secret values are never included."""
        self._org(org_id)
        row = self._connection(org_id, integration_id)
        project_id = str(row.get("project_id") or "")
        if project_id:
            self._project_owned(org_id, project_id)
        caps = CONNECTOR_CAPABILITIES.get(row["connector_kind"], ())
        issues = []
        if row.get("status") not in models.INTEGRATION_STATUSES:
            issues.append("connection_status_invalid")
        auth_mode = str(row.get("auth_mode") or "")
        if auth_mode not in models.INTEGRATION_AUTH_MODES:
            issues.append("auth_mode_invalid")
        try:
            config = json.loads(row.get("config_json") or "{}")
        except (TypeError, ValueError):
            config = {}
            issues.append("config_invalid")
        try:
            self._validate_config(row["connector_kind"], config)
        except errors.SecurityToolkitError:
            issues.append("config_invalid")
        endpoint = str(row.get("endpoint_url") or "")
        outbound_caps = {"outbound_events", "outbound_handoff",
                         "outbound_export", "outbound_reference"}
        if outbound_caps.intersection(caps) and not endpoint:
            issues.append("endpoint_required")
        if endpoint:
            try:
                _notify.validate_webhook_url(endpoint, resolve=False)
            except errors.ValidationError:
                issues.append("endpoint_invalid")
        inbound = any(cap in ("inbound_events", "inbound_callback",
                              "inbound_status") for cap in caps)
        if inbound and not project_id:
            issues.append("project_scope_required")
        if "inbound_callback" in caps and auth_mode != "hmac":
            issues.append("callback_requires_hmac")
        if auth_mode == "mtls_reference":
            issues.append("mtls_not_implemented")
        credential_ref = str(row.get("credential_ref") or "")
        if auth_mode in ("bearer_token", "hmac", "api_key") and not credential_ref:
            issues.append("credential_reference_required")
        credential_reference_active = (
            self._credential_ok(row) if credential_ref else None)
        if credential_ref and not credential_reference_active:
            issues.append("credential_reference_inactive")
        issues = list(dict.fromkeys(issues))
        return {
            "integration_id": row["id"],
            "connector_kind": row["connector_kind"],
            "capabilities": list(caps),
            "connection_status": row.get("status") or "",
            "configuration_status": "valid" if not issues else "invalid",
            "issues": issues,
            "credential_reference_configured": bool(credential_ref),
            "credential_reference_active": credential_reference_active,
            "credential_material_verified": False,
            "network_checked": False,
            "protocol_checked": False,
            "health_state": row.get("health_state") or "unchecked",
            "checked_at": _now(),
        }

    def list(self, org_id: str, *, project_id: str = "", status: str = "",
             connector_kind: str = "", health_state: str = "",
             limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit, default=100)
        offset = _bound_int(offset, lo=0, hi=10 ** 9, default=0,
                            label="offset")
        where, args = ["org_id=?", "connector_kind != ''"], [org_id]
        if project_id:
            where.append("project_id=?"); args.append(project_id)
        if status:
            s = str(status).strip().lower()
            if s not in models.INTEGRATION_STATUSES:
                raise errors.ValidationError(f"unknown status: {status!r}")
            where.append("status=?"); args.append(s)
        if connector_kind:
            ck = str(connector_kind).strip().lower()
            if ck not in models.INTEGRATION_CONNECTOR_KINDS:
                raise errors.ValidationError(
                    f"unknown connector kind: {connector_kind!r}")
            where.append("connector_kind=?"); args.append(ck)
        if health_state:
            hs = str(health_state).strip().lower()
            if hs not in models.INTEGRATION_HEALTH_STATES:
                raise errors.ValidationError(
                    f"unknown health state: {health_state!r}")
            where.append("health_state=?"); args.append(hs)
        total = int(self._one(
            "SELECT COUNT(*) n FROM external_integrations WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            f"SELECT {self._CONN_COLS} FROM external_integrations WHERE " +
            " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        return {"total": total, "count": len(rows),
                "items": [self._public(r) for r in rows]}

    def update(self, org_id: str, integration_id: str, *,
               endpoint_url: str | None = None, name: str | None = None,
               provider: str | None = None, auth_mode: str | None = None,
               credential_ref: str | None = None,
               config: dict | None = None, actor: str = "api") -> dict:
        """Configuration updates (integration.configure). Closed
        vocabularies, SSRF re-validation, redaction, secret-shape
        rejection — status/health transitions are NOT part of update."""
        self._org(org_id)
        self._acquire(f"connection:{org_id}", "connection")
        row = self._connection(org_id, integration_id)
        sets, args = [], []
        if name is not None:
            nm = _bounded(redact.redact_text(str(name).strip()), MAX_NAME_LEN)
            if len(nm) < 3:
                raise errors.ValidationError("connection name too short")
            sets.append("name=?"); args.append(nm)
        if endpoint_url is not None:
            url = str(endpoint_url).strip()
            if url:
                url = _notify.validate_webhook_url(url, resolve=False)
            sets.append("endpoint_url=?"); args.append(url)
        if provider is not None:
            sets.append("provider=?")
            args.append(_bounded(redact.redact_text(str(provider)),
                                 MAX_PROVIDER_LEN))
        if auth_mode is not None:
            am = str(auth_mode).strip().lower()
            if am not in models.INTEGRATION_AUTH_MODES:
                raise errors.ValidationError(
                    f"unknown auth mode: {auth_mode!r}")
            sets.append("auth_mode=?"); args.append(am)
        if credential_ref is not None:
            sets.append("credential_ref=?")
            args.append(_bounded(str(credential_ref).strip(), MAX_TEXT_LEN))
        if config is not None:
            cfg = self._validate_config(row["connector_kind"], dict(config))
            existing = store.loads(row.get("config_json") or "", {})
            existing.pop("max_attempts", None)
            cfg.setdefault("max_attempts",
                           int(existing.get("max_attempts")
                               or DEFAULT_MAX_ATTEMPTS))
            sets.append("config_json=?"); args.append(store.dumps(cfg))
        if not sets:
            raise errors.ValidationError("nothing to update")
        args.append(_now()); args.append(integration_id)
        self.db.execute(
            "UPDATE external_integrations SET " + ", ".join(sets) +
            ", updated_at=? WHERE id=?", args)
        # configuration changed → the last health verdict is stale
        self.db.execute(
            "UPDATE external_integrations SET health_state='', "
            "last_health_check_at='' WHERE id=?", (integration_id,))
        row["health_state"] = ""
        self._audit("integration.updated", object_type="integration",
                    object_id=integration_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"fields": sorted(
                        s.split("=")[0] for s in sets)})
        metrics.inc("integrations_updated")
        return self.get(org_id, integration_id)

    def enable(self, org_id: str, integration_id: str, *,
               approved_by: str = "", actor: str = "api") -> dict:
        """disabled → enabled. HIGH-IMPACT activation (outbound data flow
        to an external provider becomes possible): requires an approver
        identity DIFFERENT from the creator (separation of duties — the
        federation approve() precedent). The integration.enable permission
        itself (admin/owner) is enforced at the API/CLI boundary."""
        self._org(org_id)
        self._acquire(f"connection:{org_id}", "connection")
        row = self._connection(org_id, integration_id)
        if row["status"] == "enabled":
            raise errors.LifecycleError("connection already enabled")
        approver = _bounded(str(approved_by or actor or ""), 128)
        if not approver:
            raise errors.ValidationError("approver identity required")
        creator = str(row.get("created_by") or "")
        if creator and creator == approver:
            raise errors.AuthorizationError(
                "separation_of_duties: approver must differ from creator")
        now = _now()
        self.db.execute(
            "UPDATE external_integrations SET status='enabled', "
            "disabled_at='', updated_at=? WHERE id=?", (now, integration_id))
        self._audit("integration.enabled", object_type="integration",
                    object_id=integration_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"approved_by": approver,
                              "connector_kind": row["connector_kind"]})
        self._emit(row.get("project_id") or "", "integration.created",
                   key=integration_id, org_id=org_id,
                   new_state={"status": "enabled"}, actor=actor)
        metrics.inc("integrations_enabled")
        return self.get(org_id, integration_id)

    def disable(self, org_id: str, integration_id: str, *,
                actor: str = "api") -> dict:
        """enabled → disabled (fail-safe direction: always allowed for
        operators of the connection; no SoD needed to STOP data flow)."""
        self._org(org_id)
        self._acquire(f"connection:{org_id}", "connection")
        row = self._connection(org_id, integration_id)
        if row["status"] == "disabled":
            raise errors.LifecycleError("connection already disabled")
        now = _now()
        self.db.execute(
            "UPDATE external_integrations SET status='disabled', "
            "disabled_at=?, health_state='disabled', updated_at=? "
            "WHERE id=?", (now, now, integration_id))
        self._audit("integration.disabled", object_type="integration",
                    object_id=integration_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"connector_kind": row["connector_kind"]})
        self._emit(row.get("project_id") or "", "integration.disabled",
                   key=integration_id, org_id=org_id, actor=actor)
        metrics.inc("integrations_disabled")
        return self.get(org_id, integration_id)

    def test(self, org_id: str, integration_id: str, *,
             secret_material: str = "", actor: str = "api") -> dict:
        """Connectivity/configuration test (integration.test). Honest
        outcomes only:
          - test_stub adapter       → outcome 'test_stub' (never healthy)
          - inbound-only connector  → outcome 'configured' (configuration
                                      validated; NO protocol interaction,
                                      so health is never set to healthy)
          - no endpoint             → outcome 'not_configured' →
                                      health 'misconfigured'
          - outbound-capable        → REAL provider interaction with a
                                      bounded health_ping envelope; the
                                      receipt decides healthy/unreachable.
        """
        self._org(org_id)
        self._acquire(f"test:{org_id}", "test")
        row = self._connection(org_id, integration_id)
        cfg = store.loads(row.get("config_json") or "", {})
        ad = adapter_for(row["connector_kind"], cfg)
        metrics.inc("integrations_tests")
        now = _now()
        result = {"integration_id": integration_id,
                  "connector_kind": row["connector_kind"],
                  "adapter": ad.kind, "tested_at": now}
        if row["status"] != "enabled":
            result.update(ok=False, outcome="disabled",
                          error="connection is disabled")
            self._mark_health(row, "disabled")
        elif ad.kind == "test_stub":
            # honest stub: configuration is exercised, NOTHING is sent and
            # no health claim is made
            result.update(ok=False, outcome="test_stub",
                          error="test stub adapter: no real protocol "
                                "interaction performed")
        elif "outbound_events" not in CONNECTOR_CAPABILITIES[
                row["connector_kind"]] and \
                "outbound_handoff" not in CONNECTOR_CAPABILITIES[
                row["connector_kind"]] and \
                "outbound_export" not in CONNECTOR_CAPABILITIES[
                row["connector_kind"]] and \
                "outbound_reference" not in CONNECTOR_CAPABILITIES[
                row["connector_kind"]]:
            # inbound-only (EDR/XDR): configuration validation only
            if not self._config_valid(row):
                result.update(ok=False, outcome="not_configured",
                              error="configuration incomplete")
                self._mark_health(row, "misconfigured")
                metrics.inc("integrations_test_failures")
            else:
                result.update(ok=True, outcome="configured",
                              error="")
        elif not str(row.get("endpoint_url") or ""):
            result.update(ok=False, outcome="not_configured",
                          error="connection has no endpoint configured")
            self._mark_health(row, "misconfigured")
            metrics.inc("integrations_test_failures")
        else:
            envelope = self._test_envelope(row)
            settings = {"webhook_url": str(row["endpoint_url"]),
                        "webhook_secret": self._signing_secret(
                            row, secret_material)}
            try:
                res = self.provider.send(settings, envelope)
            except errors.SecurityToolkitError as e:
                res = {"ok": False, "outcome": "invalid",
                       "error": _safe_error(e)}
            ok = bool(res.get("ok"))
            outcome = _safe_error(
                res.get("outcome") or ("sent" if ok else "failed"), 40)
            result.update(ok=ok, outcome=outcome,
                          error=_safe_error(res.get("error") or "", 200))
            if ok:
                # a REAL protocol interaction succeeded → healthy is honest
                self._mark_health(row, "healthy")
                self._circuit_success(row)
            else:
                self._mark_health(
                    row, "misconfigured" if outcome == "invalid"
                    else "unreachable")
                self._circuit_failure(row)
                metrics.inc("integrations_test_failures")
        self._audit("integration.tested", object_type="integration",
                    object_id=integration_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"outcome": result["outcome"],
                              "adapter": ad.kind})
        return result

    def _test_envelope(self, row: dict) -> dict:
        cfg = store.loads(row.get("config_json") or "", {})
        ad = adapter_for(row["connector_kind"], cfg)
        now = _now()
        return ad.format({
            "event_id": models.stable_id(models.NS_INTEGRATION_DELIVERY,
                                         f"{row['id']}|health_ping|{now}"),
            "event_type": "health_ping",
            "event_time": now,
            "severity": "Info",
            "confidence": "",
            "source_organization": row["org_id"],
            "integration_id": row["id"],
            "connector_kind": row["connector_kind"],
            "data": {"test": True},
        })

    def _config_valid(self, row: dict) -> bool:
        """Bounded configuration completeness check (no network)."""
        if row["status"] != "enabled":
            return False
        auth_mode = str(row.get("auth_mode") or "")
        if auth_mode not in models.INTEGRATION_AUTH_MODES:
            return False
        if auth_mode == "mtls_reference":
            return False
        credential_ref = str(row.get("credential_ref") or "")
        if auth_mode in ("bearer_token", "hmac", "api_key") and not credential_ref:
            return False
        endpoint = str(row.get("endpoint_url") or "")
        if endpoint:
            try:
                _notify.validate_webhook_url(endpoint, resolve=False)
            except errors.ValidationError:
                return False
        return self._credential_ok(row)

    def _credential_ok(self, row: dict) -> bool:
        """credential_ref (when set) must resolve to an ACTIVE, unexpired
        secrets_registry entry — checked through the EXISTING Phase-11
        governance data (no second secret store, values never loaded)."""
        cref = str(row.get("credential_ref") or "")
        if not cref:
            return True
        hit = self._maybe(
            "SELECT status, expires_at FROM secrets_registry WHERE id=? "
            "AND org_id=?", (cref, row["org_id"]))
        if hit is None:
            return False
        if str(hit["status"]) != "active":
            return False
        exp = str(hit.get("expires_at") or "")
        if exp and _epoch(exp) <= _epoch(_now()):
            return False
        return True

    def health(self, org_id: str, *, integration_id: str = "",
               limit: int = 100, actor: str = "api") -> dict:
        """Evaluate connection health WITHOUT protocol interaction:
        configuration validity, credential-expiry, circuit state, recent
        delivery outcomes. Sets states from the closed vocabulary only;
        'healthy' is never manufactured here (it requires a real receipt —
        test/send/ingest paths). Bounded page."""
        self._org(org_id)
        self._acquire(f"health:{org_id}", "health")
        where, args = ["org_id=?", "connector_kind != ''"], [org_id]
        if integration_id:
            where.append("id=?"); args.append(integration_id)
        rows = self._q(
            f"SELECT {self._CONN_COLS} FROM external_integrations WHERE " +
            " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ?",
            args + [self._page_limit(limit, default=100)])
        items, counts = [], {}
        for row in rows:
            metrics.inc("integrations_health_checks")
            if row["status"] != "enabled":
                state = "disabled"
            elif not self._config_valid(row):
                if str(row.get("credential_ref") or "") and \
                        not self._credential_ok(row):
                    metrics.inc("integrations_config_expired")
                    # standing condition → closed-vocabulary event so the
                    # Phase-5 `integration-config-expired` rule can fire
                    # (deterministic event identity keeps it idempotent:
                    # repeated health checks never flood the operator)
                    self._emit(row.get("project_id") or "",
                               "integration.config_expired",
                               key=f"{row['id']}|"
                                   f"{row.get('credential_ref') or ''}",
                               org_id=row["org_id"],
                               new_state={"credential_ref":
                                          str(row.get("credential_ref")
                                              or "")[:64],
                                          "reason": "revoked_or_expired"})
                state = "misconfigured"
            else:
                allowed, effective = self._circuit_allows(row)
                if not allowed and effective == "open":
                    state = "degraded"
                elif int(row.get("circuit_failure_count") or 0) > 0:
                    state = str(row.get("health_state") or "") or "degraded"
                    if state not in models.INTEGRATION_HEALTH_STATES:
                        state = "degraded"
                else:
                    # keep the last verdict from a real interaction; '' when
                    # nothing has interacted yet (never invents 'healthy')
                    state = str(row.get("health_state") or "")
                    if state and state not in \
                            models.INTEGRATION_HEALTH_STATES:
                        state = ""
            if state:
                self._mark_health(row, state)
            pub = self._public(row)
            counts[pub["health_state"] or "unchecked"] = \
                counts.get(pub["health_state"] or "unchecked", 0) + 1
            items.append({"id": pub["id"], "name": pub["name"],
                          "connector_kind": pub["connector_kind"],
                          "status": pub["status"],
                          "health_state": pub["health_state"],
                          "circuit_state": pub["circuit_state"],
                          "circuit_failure_count":
                              pub["circuit_failure_count"]})
        return {"total": len(items), "count": len(items),
                "states": counts, "items": items}

    # ------------------------------------------------------- read models
    def deliveries_list(self, org_id: str, *, integration_id: str = "",
                        status: str = "", limit: int = 50,
                        offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit, default=50)
        offset = _bound_int(offset, lo=0, hi=10 ** 9, default=0,
                            label="offset")
        where, args = ["org_id=?"], [org_id]
        if integration_id:
            where.append("integration_id=?"); args.append(integration_id)
        if status:
            s = str(status).strip().lower()
            if s not in models.INTEGRATION_DELIVERY_STATUSES:
                raise errors.ValidationError(
                    f"unknown delivery status: {status!r}")
            where.append("status=?"); args.append(s)
        total = int(self._one(
            "SELECT COUNT(*) n FROM integration_deliveries WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            "SELECT id, integration_id, project_id, event_id, "
            "external_event_id, status, attempt, max_attempts, queued_at, "
            "started_at, completed_at, next_attempt_at, payload_sha256, "
            "byte_size, provider_outcome, error_code, error_class, "
            "retryable, job_id, created_at, updated_at FROM "
            "integration_deliveries WHERE " + " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        for r in rows:
            r["payload_sha256"] = str(r["payload_sha256"])[:16]
            r["external_event_id"] = redact.redact_text(
                r.get("external_event_id") or "")
            r["provider_outcome"] = _safe_error(
                r.get("provider_outcome") or "", 40)
        return {"total": total, "count": len(rows), "items": rows}

    def inbound_list(self, org_id: str, *, integration_id: str = "",
                     status: str = "", limit: int = 50,
                     offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit, default=50)
        offset = _bound_int(offset, lo=0, hi=10 ** 9, default=0,
                            label="offset")
        where, args = ["org_id=?"], [org_id]
        if integration_id:
            where.append("integration_id=?"); args.append(integration_id)
        if status:
            s = str(status).strip().lower()
            if s not in models.INTEGRATION_INBOUND_STATUSES:
                raise errors.ValidationError(
                    f"unknown inbound status: {status!r}")
            where.append("status=?"); args.append(s)
        total = int(self._one(
            "SELECT COUNT(*) n FROM integration_inbound_events WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            "SELECT id, integration_id, project_id, provider, "
            "external_event_id, event_type, event_time, received_at, "
            "payload_sha256, byte_size, status, source_reference, "
            "normalized_reference, error, created_at FROM "
            "integration_inbound_events WHERE " + " AND ".join(where) +
            " ORDER BY received_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        for r in rows:
            r["payload_sha256"] = str(r["payload_sha256"])[:16]
            r["external_event_id"] = redact.redact_text(
                r.get("external_event_id") or "")
            r["source_reference"] = _bounded(
                redact.redact_text(r.get("source_reference") or ""), 200)
            r["error"] = _safe_error(r.get("error") or "", 200)
        return {"total": total, "count": len(rows), "items": rows}

    def replays_list(self, org_id: str, *, integration_id: str = "",
                     limit: int = 50, offset: int = 0) -> dict:
        """Replay/idempotency claim view (integration.audit). Claim rows
        only — hashes truncated, never payload material."""
        self._org(org_id)
        limit = self._page_limit(limit, default=50)
        offset = _bound_int(offset, lo=0, hi=10 ** 9, default=0,
                            label="offset")
        where, args = ["org_id=?"], [org_id]
        if integration_id:
            where.append("integration_id=?"); args.append(integration_id)
        total = int(self._one(
            "SELECT COUNT(*) n FROM integration_replay_claims WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            "SELECT id, integration_id, provider, external_event_id, "
            "payload_sha256, status, claimed_at, completed_at, failed_at, "
            "result_reference, created_at FROM integration_replay_claims "
            "WHERE " + " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        for r in rows:
            r["payload_sha256"] = str(r["payload_sha256"])[:16]
            r["external_event_id"] = redact.redact_text(
                r.get("external_event_id") or "")
            r["result_reference"] = _bounded(
                redact.redact_text(r.get("result_reference") or ""), 64)
        return {"total": total, "count": len(rows), "items": rows}


# ===========================================================================
# Outbound pipeline (§12): normalize → classify → tenant/RBAC → minimize →
# policy → adapter → delivery job (Phase-3 engine) → retry/backoff →
# receipt → observability → audit
# ===========================================================================
class OutboundService(_Base):

    def send(self, org_id: str, integration_id: str, *, event_type: str,
             payload: dict, external_event_id: str = "",
             secret_material: str = "", queue: bool = True,
             priority: str = "normal", actor: str = "api") -> dict:
        """Deliver ONE bounded, redacted, deterministic event through a
        connector connection. Project-scoped connections run through the
        Phase-3 job engine (retry/backoff/cancel/dead-letter); connections
        without a project are single-attempt synchronous (the job engine
        requires project scope — documented, honest, bounded)."""
        self._org(org_id)
        self._acquire(f"send:{org_id}", "send")
        ev = str(event_type or "").strip().lower()
        if ev not in OUTBOUND_EVENT_TYPES:
            metrics.inc("integrations_config_rejected")
            raise errors.ValidationError(
                f"unknown outbound event type: {event_type!r} "
                f"(allowlist: {', '.join(OUTBOUND_EVENT_TYPES)})")
        row = self._connection(org_id, integration_id)
        ck = row["connector_kind"]

        # --- policy layer: capability boundary + status + circuit ---------
        required = EVENT_REQUIRED_CAPABILITY[ev]
        if required not in CONNECTOR_CAPABILITIES[ck]:
            self._signal_policy_violation(
                row, f"capability {required!r} not supported by connector "
                     f"kind {ck!r}", actor=actor)
            raise errors.ValidationError(
                f"policy_violation: connector kind {ck!r} does not support "
                f"{required} (capabilities: "
                f"{', '.join(CONNECTOR_CAPABILITIES[ck]) or 'none'})")
        if row["status"] != "enabled":
            return self._terminal_skip(row, ev, "disabled",
                                       "connection is disabled", actor=actor)
        allowed, effective = self._circuit_allows(row)
        if not allowed:
            return self._terminal_skip(
                row, ev, f"circuit_{effective}",
                f"circuit breaker is {effective}", actor=actor)
        if effective == "half_open":
            # probe in flight: mark so concurrent sends wait
            self.db.execute(
                "UPDATE external_integrations SET circuit_state='half_open',"
                " updated_at=? WHERE id=?", (_now(), row["id"]))
            row["circuit_state"] = "half_open"

        # --- normalize + minimize (Phase-11 redaction engine) -------------
        if not isinstance(payload, dict):
            raise errors.ValidationError("payload must be an object")
        minimized = redact.redact(dict(payload))
        if minimized != payload:
            metrics.inc("integrations_minimization_applied")
        if redact.contains_secret(minimized):
            # redaction already scrubbed shapes; a surviving hit means the
            # caller tried to smuggle secret material — refuse, signal.
            self._signal_policy_violation(
                row, "payload rejected: secret material is never exported",
                actor=actor)
            raise errors.ValidationError(
                "payload_rejected: secret material detected after "
                "minimization")

        # --- adapter format → canonical envelope → digest ------------------
        cfg = store.loads(row.get("config_json") or "", {})
        ad = adapter_for(ck, cfg)
        now = _now()
        ext_id = _bounded(
            redact.redact_text(str(external_event_id or "").strip()),
            MAX_EXTERNAL_ID_LEN)
        event = {
            "event_id": "",   # filled below (digest-dependent)
            "event_type": ev,
            "event_time": now,
            "severity": models.normalize_external_severity(
                minimized.pop("severity", "Info")),
            "confidence": str(minimized.pop("confidence", "") or "")[:20],
            "source_organization": org_id,
            "integration_id": integration_id,
            "connector_kind": ck,
            "data": minimized,
        }
        if ext_id:
            event["external_event_id"] = ext_id
        provisional = _canonical(event)
        delivery_id = models.stable_id(
            models.NS_INTEGRATION_DELIVERY,
            f"{integration_id}|{ev}|{_sha256(provisional)[:16]}|"
            f"{time.monotonic_ns()}")
        event["event_id"] = delivery_id
        envelope = ad.format(event)
        text = _canonical(envelope)
        size = len(text.encode("utf-8"))
        if size > MAX_OUTBOUND_BYTES:
            metrics.inc("integrations_outbound_skipped")
            raise errors.ValidationError(
                f"payload too large: {size} bytes (max {MAX_OUTBOUND_BYTES})")
        digest = _sha256(text)

        # --- delivery row (queued) ----------------------------------------
        max_attempts = _bound_int(cfg.get("max_attempts"),
                                  lo=1, hi=MAX_MAX_ATTEMPTS,
                                  default=DEFAULT_MAX_ATTEMPTS,
                                  label="max_attempts")
        project_id = str(row.get("project_id") or "")
        if ad.kind == "test_stub":
            max_attempts = 1   # a stub never retries — nothing is real
        self.db.execute(
            "INSERT INTO integration_deliveries (id, org_id, project_id, "
            "integration_id, event_id, external_event_id, status, attempt, "
            "max_attempts, queued_at, started_at, completed_at, "
            "next_attempt_at, payload_sha256, byte_size, provider_outcome, "
            "error_code, error_class, retryable, job_id, created_at, "
            "updated_at) VALUES (?,?,?, ?,?, ?, 'queued', 0, ?, ?, '', '', "
            "'', ?, ?, '', '', '', 0, '', ?, ?)",
            (delivery_id, org_id, project_id, integration_id, ev, ext_id,
             max_attempts, now, digest, size, now, now))
        metrics.inc("integrations_outbound_queued")
        self._audit("integration.delivery.queued",
                    object_type="integration_delivery",
                    object_id=delivery_id, org_id=org_id,
                    project_id=project_id, actor=actor,
                    metadata={"integration_id": integration_id,
                              "event_type": ev, "adapter": ad.kind,
                              "byte_size": size})

        # --- test_stub honesty gate: never a real send ---------------------
        if ad.kind == "test_stub":
            return self._finish(
                row, delivery_id, ev, digest, size, ok=False,
                status="skipped", outcome="test_stub",
                error="test stub adapter: no real protocol interaction",
                error_code="unsupported_provider", error_class="configuration",
                retryable=False, actor=actor, job_id="", envelope=None,
                secret="", started=now)

        # --- job engine (project-scoped) or synchronous single attempt -----
        if project_id and queue:
            scan = self._delivery_scan(project_id, delivery_id)
            self.svc.scan_save_raw(scan.id, {"envelope": envelope})
            js = self._jobs()
            # job payloads are a CLOSED scalar whitelist (jobs._PAYLOAD_KEYS)
            # — the delivery reference rides in `target` (the in-process
            # execution target), never as an unknown field
            job = js.create_job(
                scan.id, DELIVERY_PROFILE,
                {"op": "deliver", "target": f"delivery:{delivery_id}"},
                job_type=DELIVERY_JOB_TYPE, priority=priority,
                max_attempts=max_attempts, timeout_seconds=300,
                actor=actor, queue_now=True)
            self.db.execute(
                "UPDATE integration_deliveries SET job_id=?, updated_at=? "
                "WHERE id=?", (job.id, _now(), delivery_id))
            return {"delivery_id": delivery_id, "status": "queued",
                    "job_id": job.id, "integration_id": integration_id,
                    "event_type": ev, "payload_sha256": digest[:16],
                    "byte_size": size, "adapter": ad.kind,
                    "mode": "job_engine"}
        ok, res, started = self._attempt(row, envelope, secret_material)
        return self._finish(
            row, delivery_id, ev, digest, size, ok=ok,
            status="sent" if ok else "failed",
            outcome=str(res.get("outcome") or ("sent" if ok else "failed")),
            error=_bounded(res.get("error") or "", 200),
            error_code="" if ok else "delivery_failed",
            error_class="" if ok else "transient",
            retryable=False, actor=actor, job_id="", envelope=envelope,
            secret=secret_material, started=started)

    # ------------------------------------------------------------ attempt
    def _attempt(self, row: dict, envelope: dict, secret: str):
        """ONE real provider interaction. The SSRF guard re-validates the
        endpoint at send time (resolve=True default inside the provider)."""
        started = _now()
        settings = {"webhook_url": str(row.get("endpoint_url") or ""),
                    "webhook_secret": self._signing_secret(row, secret)}
        with metrics.Timer("integrations_delivery_duration"):
            try:
                res = self.provider.send(settings, envelope)
            except errors.SecurityToolkitError as e:
                res = {"ok": False, "outcome": "invalid",
                       "error": str(e)[:200]}
        return bool(res.get("ok")), res, started

    def _finish(self, row: dict, delivery_id: str, ev: str, digest: str,
                size: int, *, ok: bool, status: str, outcome: str,
                error: str, error_code: str, error_class: str,
                retryable: bool, actor: str, job_id: str, envelope,
                secret: str, started: str) -> dict:
        """Terminal receipt handling for the synchronous path: delivery
        row + canonical integration_events record + circuit + metrics +
        audit + security event. Returns the receipt (never the payload)."""
        now = _now()
        error = _safe_error(error, 200)
        outcome = _safe_error(outcome, 40)
        self.db.execute(
            "UPDATE integration_deliveries SET status=?, attempt=1, "
            "started_at=?, completed_at=?, provider_outcome=?, "
            "error_code=?, error_class=?, retryable=?, updated_at=? "
            "WHERE id=?",
            (status, started, now, _bounded(outcome, 40), error_code,
             error_class, 1 if retryable else 0, now, delivery_id))
        self._record_event(row, event_type=ev,
                           status="sent" if ok else
                           ("skipped" if status == "skipped" else "failed"),
                           digest=digest, byte_size=size, outcome=outcome,
                           error=error)
        if ok:
            self.db.execute(
                "UPDATE external_integrations SET last_delivery_at=?, "
                "updated_at=? WHERE id=?", (now, now, row["id"]))
            self._circuit_success(row)
            # health 'healthy' only after a REAL successful interaction
            if str(row.get("health_state") or "") != "healthy":
                self._mark_health(row, "healthy")
            metrics.inc("integrations_outbound_sent")
            self._audit("integration.delivery.sent",
                        object_type="integration_delivery",
                        object_id=delivery_id, org_id=row["org_id"],
                        project_id=row.get("project_id") or "", actor=actor,
                        metadata={"integration_id": row["id"],
                                  "event_type": ev, "outcome": outcome})
            self._emit(row.get("project_id") or "", "integration.delivered",
                       key=delivery_id, org_id=row["org_id"],
                       new_state={"event_type": ev}, actor=actor)
        else:
            if status == "failed":
                self._circuit_failure(row)
                metrics.inc("integrations_outbound_failed")
            else:
                metrics.inc("integrations_outbound_skipped")
            self._audit("integration.delivery.failed",
                        object_type="integration_delivery",
                        object_id=delivery_id, org_id=row["org_id"],
                        project_id=row.get("project_id") or "", actor=actor,
                        metadata={"integration_id": row["id"],
                                  "event_type": ev, "outcome": outcome,
                                  "error_code": error_code,
                                  "status": status})
            if status == "failed":
                self._emit(row.get("project_id") or "", "integration.failed",
                           key=delivery_id, org_id=row["org_id"],
                           new_state={"event_type": ev,
                                      "error_code": error_code},
                           actor=actor)
        return {"delivery_id": delivery_id, "status": status,
                "integration_id": row["id"], "event_type": ev,
                "outcome": outcome, "error": error,
                "payload_sha256": digest[:16], "byte_size": size,
                "job_id": job_id, "mode": "synchronous"}

    def _terminal_skip(self, row: dict, ev: str, outcome: str, error: str,
                       *, actor: str) -> dict:
        """Disabled/circuit-open sends: recorded as skipped deliveries +
        canonical events (never silently dropped)."""
        now = _now()
        outcome = _safe_error(outcome, 40)
        error = _safe_error(error, 200)
        delivery_id = models.stable_id(
            models.NS_INTEGRATION_DELIVERY,
            f"{row['id']}|{ev}|skip|{outcome}|{time.monotonic_ns()}")
        self.db.execute(
            "INSERT INTO integration_deliveries (id, org_id, project_id, "
            "integration_id, event_id, external_event_id, status, attempt, "
            "max_attempts, queued_at, started_at, completed_at, "
            "next_attempt_at, payload_sha256, byte_size, provider_outcome, "
            "error_code, error_class, retryable, job_id, created_at, "
            "updated_at) VALUES (?,?,?, ?,?, '', 'skipped', 0, 1, ?, ?, ?, "
            "'', '', 0, ?, '', 'configuration', 0, '', ?, ?)",
            (delivery_id, row["org_id"], row.get("project_id") or "",
             row["id"], ev, now, now, now, _bounded(outcome, 40), now, now))
        self._record_event(row, event_type=ev, status="skipped", digest="",
                           byte_size=0, outcome=outcome, error=error)
        metrics.inc("integrations_outbound_skipped")
        self._audit("integration.delivery.failed",
                    object_type="integration_delivery",
                    object_id=delivery_id, org_id=row["org_id"],
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"integration_id": row["id"], "event_type": ev,
                              "outcome": outcome, "status": "skipped"})
        return {"delivery_id": delivery_id, "status": "skipped",
                "integration_id": row["id"], "event_type": ev,
                "outcome": outcome, "error": error, "mode": "skipped"}

    def _signal_policy_violation(self, row: dict, reason: str, *,
                                 actor: str) -> None:
        metrics.inc("integrations_policy_violations")
        self._emit(row.get("project_id") or "",
                   "integration.policy_violation", key=row["id"],
                   org_id=row["org_id"],
                   new_state={"reason": _bounded(reason, 120)}, actor=actor)
        if row.get("project_id"):
            self._security_finding(
                row["project_id"], rule_id=RULE_POLICY,
                title="Integration policy violation",
                description=f"Blocked outbound/inbound operation on "
                            f"connection {row['id'][:16]}: "
                            f"{_bounded(reason, 200)}",
                severity="Medium",
                raw={"integration_id": row["id"],
                     "connector_kind": row["connector_kind"]})


# ===========================================================================
# Delivery execution — Phase-3 job-engine contract (federation BulkRunner
# precedent): run_for_job(job) for the worker path, run_delivery for the
# synchronous/CLI path, process_due for bounded in-process draining.
# ===========================================================================
class DeliveryRunner:

    def __init__(self, outbound: OutboundService):
        self.svc = outbound.svc
        self.db = outbound.db
        self.out = outbound

    # ------------------------------------------------------------ entries
    def run_for_job(self, job) -> dict:
        """Worker/job-engine entry — one job executes ONE delivery attempt
        (the profile's documented contract).

        Engine-facing semantics: RETURN the receipt for every provider-
        side outcome (sent / retrying / skipped / failed) — the attempt
        itself is the stage's work product, honestly recorded on the
        delivery row, the canonical integration_events record and the
        stage reference; the engine then completes the job. Raises are
        reserved for contract violations (missing target →
        validation_rejected) and cancellation (WorkerStopped). The
        delivery-level retry loop (next_attempt_at backoff computed with
        the engine's OWN jobs.retry_delay formula — never a second
        backoff implementation) is owned by the delivery row and drained
        by process_due with an atomic claim, so a transient provider
        failure never dead-ends in an un-rerunnable retry_wait job. The
        delivery reference rides in the payload's closed `target` field
        ("delivery:<id>") — job payloads never carry unknown keys."""
        js = self.out._jobs()
        target = str((job.payload or {}).get("target") or "")
        delivery_id = target.split(":", 1)[1] \
            if target.startswith("delivery:") else ""
        if not delivery_id:
            raise errors.ScannerError(
                "validation_rejected: delivery job without a delivery "
                "target")
        ctl = js.control_state(job.id)
        if ctl in ("cancelling", "paused"):
            if ctl == "cancelling":
                self._set_status(delivery_id, "cancelled",
                                 outcome="cancelled", error="job cancelled")
                metrics.inc("integrations_outbound_cancelled")
            raise errors.WorkerStopped(f"delivery {ctl} before attempt")
        js.heartbeat(job.id, job.worker_id)
        try:
            receipt = self._execute(job.org_id, delivery_id,
                                    actor=job.actor_id or "worker")
        except errors.SecurityToolkitError as e:
            # unexpected platform error mid-attempt: the row was atomically
            # claimed ('sending') — return it to the retry state machine
            # (never stranded), then let the engine record the failure
            self._reschedule_after_error(delivery_id)
            raise errors.ScannerError(f"delivery_failed: {e}") from e
        if receipt.get("status") == "cancelled":
            raise errors.WorkerStopped("delivery cancelled")
        return receipt

    def _reschedule_after_error(self, delivery_id: str) -> None:
        """Return a claimed ('sending') delivery to the retry state machine
        after an unexpected platform error — a delivery is never silently
        stranded mid-attempt. Uses the engine's own retry_delay formula;
        exhaustion is terminal and counted (never a silent drop)."""
        import jobs as _jobs
        row = self.out._maybe(
            "SELECT attempt, max_attempts, status FROM "
            "integration_deliveries WHERE id=?", (delivery_id,))
        if row is None or row["status"] != "sending":
            return
        now = _now()
        attempt = int(row["attempt"])
        if attempt >= int(row["max_attempts"]):
            self.db.execute(
                "UPDATE integration_deliveries SET status='failed', "
                "provider_outcome='error', error_code='delivery_failed', "
                "error_class='transient', retryable=0, completed_at=?, "
                "updated_at=? WHERE id=? AND status='sending'",
                (now, now, delivery_id))
            metrics.inc("integrations_outbound_failed")
            return
        try:
            next_at = (datetime.fromisoformat(now) +
                       timedelta(seconds=_jobs.retry_delay(attempt))
                       ).isoformat()
        except ValueError:
            next_at = now
        self.db.execute(
            "UPDATE integration_deliveries SET status='retrying', "
            "provider_outcome='error', error_code='delivery_failed', "
            "error_class='transient', retryable=1, next_attempt_at=?, "
            "updated_at=? WHERE id=? AND status='sending'",
            (next_at, now, delivery_id))
        metrics.inc("integrations_outbound_retried")

    def run_delivery(self, org_id: str, delivery_id: str, *,
                     actor: str = "cli") -> dict:
        """Synchronous execution of one queued/retrying delivery."""
        self.out._org(org_id)
        row = self._delivery_row(org_id, delivery_id)
        if row["status"] not in ("queued", "retrying"):
            return self._receipt(row)   # idempotent: terminal is terminal
        return self._execute(org_id, delivery_id, actor=actor)

    def process_due(self, org_id: str, *, limit: int = 50,
                    actor: str = "worker") -> dict:
        """Bounded drain of due deliveries (CLI/worker-tick path). Safe
        alongside the job engine: every attempt goes through the atomic
        claim in _execute, so a row whose job is still in flight is either
        won by the worker (this drain reads the receipt) or won here (the
        worker's runner reads the terminal receipt) — never sent twice.
        Never unbounded."""
        self.out._org(org_id)
        lim = self.out._page_limit(limit, default=50)
        now = _now()
        rows = self.out._q(
            "SELECT id FROM integration_deliveries WHERE org_id=? AND "
            "status IN ('queued','retrying') AND "
            "(next_attempt_at='' OR next_attempt_at<=?) "
            "ORDER BY next_attempt_at, id LIMIT ?",
            (org_id, now, lim))
        done, failed = 0, 0
        for r in rows:
            rec = self._execute(org_id, r["id"], actor=actor)
            if rec.get("status") == "sent":
                done += 1
            else:
                failed += 1
        return {"processed": len(rows), "sent": done, "failed": failed}

    # ------------------------------------------------------------ internals
    def _delivery_row(self, org_id: str, delivery_id: str) -> dict:
        row = self.out._maybe(
            "SELECT id, org_id, project_id, integration_id, event_id, "
            "status, attempt, max_attempts, job_id, payload_sha256, "
            "byte_size FROM integration_deliveries WHERE id=? AND org_id=?",
            (delivery_id, org_id))
        if row is None:
            raise errors.NotFoundError("delivery not found")
        return row

    def _receipt(self, row: dict) -> dict:
        r = self.out._one(
            "SELECT status, provider_outcome, error_code, error_class, "
            "attempt, completed_at FROM integration_deliveries WHERE id=?",
            (row["id"],))
        return {"delivery_id": row["id"], "status": r["status"],
                "outcome": r["provider_outcome"],
                "error_code": r["error_code"],
                "error_class": r["error_class"], "attempt": r["attempt"]}

    def _execute(self, org_id: str, delivery_id: str, *, actor: str) -> dict:
        row = self._delivery_row(org_id, delivery_id)
        if row["status"] not in ("queued", "retrying"):
            return self._receipt(row)   # idempotent: terminal is terminal
        # job cancellation wins over any attempt: cancel() on a queued job
        # leaves it 'cancelling' (never claimed by a worker) — without this
        # guard a drain-path execution could deliver a send the operator
        # already cancelled. Finalization keeps the engine lifecycle
        # honest (cancelling -> cancelled with its own audit + metric).
        job_id = str(row.get("job_id") or "")
        if job_id:
            jrow = self.out._maybe(
                "SELECT status FROM jobs WHERE id=?", (job_id,))
            if jrow and str(jrow["status"]) in ("cancelling", "cancelled"):
                self._set_status(delivery_id, "cancelled",
                                 outcome="cancelled", error="job cancelled")
                metrics.inc("integrations_outbound_cancelled")
                if jrow["status"] == "cancelling":
                    self.out._jobs().cancel_finalize(job_id, actor=actor)
                return self._receipt(
                    self._delivery_row(org_id, delivery_id))
        now = _now()
        attempt = int(row["attempt"]) + 1
        # Atomic attempt claim (the jobs.claim_next guarded-UPDATE
        # pattern): concurrent executors (worker / CLI / process_due)
        # race safely — exactly ONE wins the attempt, losers read the
        # winner's receipt. Never a SELECT-then-INSERT/UPDATE race.
        n = self.db.execute_affected(
            "UPDATE integration_deliveries SET status='sending', "
            "attempt=?, started_at=?, updated_at=? WHERE id=? AND "
            "status IN ('queued','retrying')",
            (attempt, now, now, row["id"]))
        if n != 1:
            return self._receipt(self._delivery_row(org_id, delivery_id))
        conn = self.out._connection(org_id, row["integration_id"])
        if conn["status"] != "enabled":
            return self._terminate(row, conn, "skipped", "disabled",
                                   "connection is disabled",
                                   error_code="config_invalid",
                                   error_class="configuration",
                                   retryable=False, actor=actor,
                                   attempt=attempt, started=now)
        allowed, effective = self.out._circuit_allows(conn)
        if not allowed:
            return self._terminate(row, conn, "skipped",
                                   f"circuit_{effective}",
                                   f"circuit breaker is {effective}",
                                   error_code="config_invalid",
                                   error_class="configuration",
                                   retryable=False, actor=actor,
                                   attempt=attempt, started=now)
        # envelope: staged on the job's scan record (bulk-material
        # precedent). Reconstruct from stage; never from a payload column.
        envelope = self._staged_envelope(row)
        if envelope is None:
            return self._terminate(row, conn, "failed", "no_envelope",
                                   "staged delivery envelope not found",
                                   error_code="validation_rejected",
                                   error_class="validation",
                                   retryable=False, actor=actor,
                                   attempt=attempt, started=now)
        cfg = store.loads(conn.get("config_json") or "", {})
        ad = adapter_for(conn["connector_kind"], cfg)
        if ad.kind == "test_stub":
            return self._terminate(row, conn, "skipped", "test_stub",
                                   "test stub adapter: no real protocol "
                                   "interaction",
                                   error_code="unsupported_provider",
                                   error_class="configuration",
                                   retryable=False, actor=actor,
                                   attempt=attempt, started=now)
        ok, res, started = self.out._attempt(conn, envelope, "")
        outcome = _safe_error(res.get("outcome") or
                              ("sent" if ok else "failed"), 40)
        err = _safe_error(res.get("error") or "", 200)
        if ok:
            return self._terminate(row, conn, "sent", outcome, "",
                                   error_code="", error_class="",
                                   retryable=False, actor=actor,
                                   attempt=attempt, started=started)
        # failure classification — the Phase-3 retry taxonomy decides
        if outcome == "invalid":
            error_code, error_class, retryable = \
                "config_invalid", "configuration", False
        elif outcome == "redirect":
            error_code, error_class, retryable = \
                "validation_rejected", "validation", False
        else:
            error_code, error_class, retryable = \
                "delivery_failed", "transient", True
        max_attempts = int(row["max_attempts"])
        if not retryable or attempt >= max_attempts:
            return self._terminate(row, conn, "failed", outcome, err,
                                   error_code=error_code,
                                   error_class=error_class,
                                   retryable=False, actor=actor,
                                   attempt=attempt, started=started)
        # a failed attempt is a REAL provider interaction: the circuit
        # breaker counts it and the canonical event/audit record carries
        # it even though the delivery itself continues under backoff
        self.out._circuit_failure(conn)
        self.out._record_event(
            conn, event_type=str(row.get("event_id") or ""),
            status="failed", digest=str(row.get("payload_sha256") or ""),
            byte_size=int(row.get("byte_size") or 0),
            outcome=outcome, error=err)
        self.out._audit("integration.delivery.failed",
                        object_type="integration_delivery",
                        object_id=row["id"], org_id=conn["org_id"],
                        project_id=conn.get("project_id") or "",
                        actor=actor,
                        metadata={"integration_id": conn["id"],
                                  "status": "retrying", "outcome": outcome,
                                  "error_code": error_code,
                                  "attempt": attempt,
                                  "retry_scheduled": True})
        import jobs as _jobs
        delay = _jobs.retry_delay(attempt)
        retry_at = _now()
        try:
            next_at = (datetime.fromisoformat(retry_at) +
                       timedelta(seconds=delay)).isoformat()
        except ValueError:
            next_at = retry_at
        self.db.execute(
            "UPDATE integration_deliveries SET status='retrying', "
            "provider_outcome=?, error_code=?, error_class=?, retryable=1, "
            "next_attempt_at=?, updated_at=? WHERE id=?",
            (outcome, error_code, error_class, next_at, _now(), row["id"]))
        metrics.inc("integrations_outbound_retried")
        return {"delivery_id": row["id"], "status": "retrying",
                "outcome": outcome, "error": err,
                "error_code": error_code, "error_class": error_class,
                "attempt": attempt, "next_attempt_at": next_at}

    def _staged_envelope(self, row: dict):
        job_id = str(row.get("job_id") or "")
        if not job_id:
            return None
        job_row = self.out._maybe(
            "SELECT scan_id FROM jobs WHERE id=?", (job_id,))
        if not job_row:
            return None
        try:
            staged = dict(self.svc.scan_get(job_row["scan_id"]).raw or {})
        except errors.SecurityToolkitError:
            return None
        envelope = staged.get("envelope")
        return envelope if isinstance(envelope, dict) else None

    def _terminate(self, row: dict, conn: dict, status: str, outcome: str,
                   error: str, *, error_code: str, error_class: str,
                   retryable: bool, actor: str, attempt: int | None = None,
                   started: str = "") -> dict:
        now = _now()
        outcome = _safe_error(outcome, 40)
        error = _safe_error(error, 200)
        att = int(row["attempt"]) if attempt is None else int(attempt)
        self.db.execute(
            "UPDATE integration_deliveries SET status=?, started_at=?, "
            "completed_at=?, provider_outcome=?, error_code=?, "
            "error_class=?, retryable=?, updated_at=? WHERE id=?",
            (status, started or now, now, _bounded(outcome, 40), error_code,
             error_class, 1 if retryable else 0, now, row["id"]))
        self.out._record_event(
            conn, event_type=str(row.get("event_id") or ""),
            status="sent" if status == "sent" else
            ("skipped" if status == "skipped" else "failed"),
            digest=str(row.get("payload_sha256") or ""),
            byte_size=int(row.get("byte_size") or 0),
            outcome=outcome, error=error)
        if status == "sent":
            self.db.execute(
                "UPDATE external_integrations SET last_delivery_at=?, "
                "updated_at=? WHERE id=?", (now, now, conn["id"]))
            self.out._circuit_success(conn)
            if str(conn.get("health_state") or "") != "healthy":
                self.out._mark_health(conn, "healthy")
            metrics.inc("integrations_outbound_sent")
            self.out._audit("integration.delivery.sent",
                            object_type="integration_delivery",
                            object_id=row["id"], org_id=conn["org_id"],
                            project_id=conn.get("project_id") or "",
                            actor=actor,
                            metadata={"integration_id": conn["id"],
                                      "outcome": outcome, "attempt": att})
            self.out._emit(conn.get("project_id") or "",
                           "integration.delivered", key=row["id"],
                           org_id=conn["org_id"],
                           new_state={"outcome": outcome}, actor=actor)
        else:
            if status == "failed":
                self.out._circuit_failure(conn)
                metrics.inc("integrations_outbound_failed")
                self.out._emit(conn.get("project_id") or "",
                               "integration.failed", key=row["id"],
                               org_id=conn["org_id"],
                               new_state={"outcome": outcome,
                                          "error_code": error_code},
                               actor=actor)
            else:
                metrics.inc("integrations_outbound_skipped")
            self.out._audit("integration.delivery.failed",
                            object_type="integration_delivery",
                            object_id=row["id"], org_id=conn["org_id"],
                            project_id=conn.get("project_id") or "",
                            actor=actor,
                            metadata={"integration_id": conn["id"],
                                      "status": status, "outcome": outcome,
                                      "error_code": error_code,
                                      "attempt": att})
        return {"delivery_id": row["id"], "status": status,
                "outcome": outcome, "error": error,
                "error_code": error_code, "error_class": error_class,
                "attempt": att}

    def _set_status(self, delivery_id: str, status: str, *, outcome: str,
                    error: str) -> None:
        self.db.execute(
            "UPDATE integration_deliveries SET status=?, "
            "provider_outcome=?, completed_at=?, updated_at=? WHERE id=?",
            (status, _bounded(outcome, 40), _now(), _now(), delivery_id))


# ===========================================================================
# Inbound pipeline (§15-§20): endpoint → auth → HMAC/token → schema →
# rate limit → tenant resolution → normalization → EXISTING systems →
# dedup/replay → audit. Tenant is NEVER self-selected by the request.
# ===========================================================================
class InboundService(_Base):

    def ingest(self, integration_id: str, *, event_type: str,
               payload: dict, external_event_id: str,
               timestamp: str = "", signature: str = "",
               presented_token: str = "", raw_body: bytes | None = None,
               source_reference: str = "", received_at: str = "",
               actor: str = "provider") -> dict:
        """Process ONE inbound external event. Returns a bounded receipt —
        never echoes the payload. Provider-side problems return rejection
        receipts (auditable, observable); platform misuse raises.

        Security sequence (fail closed at every step):
          1. connection lookup BY ID ONLY → tenant derived from the row
          2. per-org rate limit (existing limiter)
          3. status + capability + circuit checks
          4. bounded schema validation (size, type vocabulary, fields)
          5. authentication per auth_mode (HMAC constant-time + window /
             bearer / api_key; mtls_reference is honestly unsupported —
             this platform implements no PKI)
          6. integrity check when the event declares its own hash
          7. replay claim — DB-enforced UNIQUE boundary
          8. normalization (severity mapped deterministically; confidence
             kept SEPARATE; risk engine stays authoritative downstream)
          9. routing into the EXISTING finding/case/IOC systems
        """
        row = self._maybe(
            f"SELECT {self._CONN_COLS} FROM external_integrations "
            "WHERE id=?", (integration_id,))
        if row is None or not str(row.get("connector_kind") or ""):
            # no tenant information is trusted from the request; an unknown
            # connection is an authentication failure, not a 404 oracle
            metrics.inc("integrations_auth_failures")
            raise errors.AuthenticationError(
                "integration_authentication_failed")
        org_id = row["org_id"]
        project_id = str(row.get("project_id") or "")
        now = received_at or _now()
        received_at = now

        # --- 2. rate limit (existing engine, per org+integration) ---------
        try:
            self._acquire(f"ingest:{org_id}", "ingest")
        except errors.RateLimitedError:
            metrics.inc("integrations_rate_limited")
            self._emit(project_id, "integration.rate_limited",
                       key=integration_id, org_id=org_id)
            self._reject(row, "", "rate_limited", "rate limit exceeded",
                         received_at, actor)
            raise

        # --- 3. status / capability / circuit ------------------------------
        ck = row["connector_kind"]
        caps = CONNECTOR_CAPABILITIES[ck]
        et = str(event_type or "").strip().lower()
        if row["status"] != "enabled":
            return self._rejected(row, et, "", "disabled",
                                  "connection is disabled", received_at,
                                  actor)
        allowed_inbound = set()
        for cap in caps:
            allowed_inbound |= INBOUND_ALLOWED_BY_CAPABILITY.get(cap,
                                                                 frozenset())
        if not allowed_inbound:
            return self._rejected(row, et, "", "unsupported",
                                  f"connector kind {ck!r} accepts no "
                                  "inbound events (capability boundary)",
                                  received_at, actor)
        if et not in models.INBOUND_EVENT_TYPES:
            metrics.inc("integrations_schema_rejected")
            return self._rejected(row, et, "", "schema_rejected",
                                  "unknown inbound event type "
                                  f"(allowlist: "
                                  f"{', '.join(models.INBOUND_EVENT_TYPES)})",
                                  received_at, actor)
        if et not in allowed_inbound:
            self._signal(row, "integration.policy_violation", RULE_POLICY,
                         "Integration policy violation",
                         f"Inbound event type {et!r} is not permitted for "
                         f"connector kind {ck!r}", "Medium", received_at,
                         actor)
            metrics.inc("integrations_policy_violations")
            return self._rejected(row, et, "", "policy_violation",
                                  f"event type {et!r} not allowed for this "
                                  "connector capability", received_at, actor)
        if "inbound_callback" in caps and \
                str(row.get("auth_mode") or "") != "hmac":
            # SOAR callbacks REQUIRE signed + replay-protected transport
            return self._rejected(row, et, "", "auth_not_configured",
                                  "callback ingestion requires auth_mode "
                                  "'hmac' (signed, replay-protected)",
                                  received_at, actor)
        allowed, effective = self._circuit_allows(row)
        if not allowed:
            metrics.inc("integrations_rate_limited")
            return self._rejected(row, et, "", f"circuit_{effective}",
                                  f"circuit breaker is {effective}",
                                  received_at, actor)
        if not project_id:
            # every inbound route lands in a project-scoped existing
            # system — a projectless connection is a configuration error,
            # rejected BEFORE any idempotency claim is consumed
            return self._rejected(row, et, "", "not_configured",
                                  "connection has no project — inbound "
                                  "routing requires project scope",
                                  received_at, actor)

        # --- 4. bounded schema validation ----------------------------------
        ext_id = _bounded(
            redact.redact_text(str(external_event_id or "").strip()),
            MAX_EXTERNAL_ID_LEN)
        if not ext_id:
            metrics.inc("integrations_schema_rejected")
            return self._rejected(row, et, "", "schema_rejected",
                                  "external_event_id is required "
                                  "(idempotency boundary)", received_at,
                                  actor)
        if not isinstance(payload, dict):
            metrics.inc("integrations_schema_rejected")
            return self._rejected(row, et, ext_id, "schema_rejected",
                                  "payload must be a JSON object",
                                  received_at, actor)
        body = raw_body if raw_body is not None else \
            _canonical(payload).encode("utf-8")
        if len(body) > MAX_INBOUND_BYTES:
            metrics.inc("integrations_schema_rejected")
            return self._rejected(row, et, ext_id, "schema_rejected",
                                  f"payload too large (max "
                                  f"{MAX_INBOUND_BYTES} bytes)",
                                  received_at, actor)
        metrics.inc("integrations_inbound_received")
        digest = hashlib.sha256(body).hexdigest()
        provider_name = _bounded(str(row.get("provider") or "") or ck,
                                 MAX_PROVIDER_LEN)

        # --- 5. authentication per closed auth_mode vocabulary -------------
        auth_ok, auth_err = self._authenticate(row, body=body,
                                               timestamp=timestamp,
                                               signature=signature,
                                               presented=presented_token)
        if not auth_ok:
            metrics.inc("integrations_auth_failures")
            self._signal(row, "integration.auth_failure", RULE_AUTH_FAILURE,
                         "Integration authentication failure",
                         f"Inbound authentication failed for connection "
                         f"{integration_id[:16]} ({auth_err})", "High",
                         received_at, actor)
            return self._rejected(row, et, ext_id, "auth_failure", auth_err,
                                  received_at, actor, digest=digest,
                                  size=len(body),
                                  provider_name=provider_name,
                                  source_reference=source_reference)

        # --- 6. declared-integrity check (when present) --------------------
        declared = str(payload.get("integrity_sha256") or "").strip().lower()
        if declared:
            check = dict(payload)
            check.pop("integrity_sha256", None)
            computed = hashlib.sha256(
                _canonical(check).encode("utf-8")).hexdigest()
            if not hmac.compare_digest(declared, computed):
                metrics.inc("integrations_integrity_failures")
                self._signal(row, "integration.integrity_failure",
                             RULE_INTEGRITY,
                             "Integration integrity failure",
                             f"Declared payload hash mismatch on inbound "
                             f"event {ext_id[:32]} for connection "
                             f"{integration_id[:16]}", "High", received_at,
                             actor)
                return self._rejected(row, et, ext_id, "integrity_failure",
                                      "declared integrity hash mismatch",
                                      received_at, actor, digest=digest,
                                      size=len(body),
                                      provider_name=provider_name)

        # --- 7. replay claim (DB-enforced UNIQUE boundary) ------------------
        claim_id = models.stable_id(
            models.NS_INTEGRATION_REPLAY,
            f"{provider_name}|{integration_id}|{ext_id}|{digest}")
        try:
            self.db.execute(
                "INSERT INTO integration_replay_claims (id, org_id, "
                "provider, integration_id, external_event_id, "
                "payload_sha256, status, claimed_at, completed_at, "
                "failed_at, result_reference, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,'',?,'','','',?,?)",
                (claim_id, org_id, provider_name, integration_id, ext_id,
                 digest, received_at, received_at, received_at))
        except sqlite3.IntegrityError:
            # duplicate: classify from the existing claim (§19 semantics) —
            # a duplicate NEVER creates a second finding/alert/case/match
            claim = self._maybe(
                "SELECT id, status, completed_at, failed_at, "
                "result_reference FROM integration_replay_claims WHERE "
                "provider=? AND integration_id=? AND external_event_id=? "
                "AND payload_sha256=?",
                (provider_name, integration_id, ext_id, digest))
            metrics.inc("integrations_inbound_duplicates")
            metrics.inc("integrations_replay_blocked")
            self._emit(project_id, "integration.replay_detected",
                       key=integration_id, org_id=org_id,
                       new_state={"external_event_id": ext_id[:32]})
            if claim is not None and not str(claim.get("completed_at")) \
                    and not str(claim.get("failed_at")):
                self._secops_finding(
                    row, RULE_REPLAY, "Integration replay detected",
                    f"Replayed inbound event {ext_id[:32]} on connection "
                    f"{integration_id[:16]} while a claim is in progress",
                    "Medium", received_at, actor)
            self._audit("integration.replay_blocked",
                        object_type="integration_inbound",
                        object_id=claim_id, org_id=org_id,
                        project_id=project_id, actor=actor,
                        metadata={"external_event_id": ext_id[:32],
                                  "integration_id": integration_id,
                                  "claim_status":
                                      (claim or {}).get("status", "")})
            inbound_id = self._record_inbound(
                row, et, ext_id, "duplicate", digest, len(body),
                provider_name, received_at,
                normalized_reference=str((claim or {}).get(
                    "result_reference") or ""), error="duplicate event "
                "(idempotency claim exists)", actor=actor,
                source_reference=source_reference)
            return {"status": "duplicate", "inbound_id": inbound_id,
                    "integration_id": integration_id,
                    "external_event_id": ext_id,
                    "normalized_reference": str((claim or {}).get(
                        "result_reference") or ""),
                    "claim_status": str((claim or {}).get("status") or "")}

        # --- 8/9. normalize + route into EXISTING systems -------------------
        try:
            normalized = self._normalize(row, et, payload, ext_id)
            ref, route = self._route(row, et, normalized, received_at,
                                     actor)
        except errors.SecurityToolkitError as e:
            self._fail_claim(claim_id)
            metrics.inc("integrations_inbound_failed")
            self._audit("integration.inbound.rejected",
                        object_type="integration_inbound",
                        object_id=ext_id, org_id=org_id,
                        project_id=project_id, actor=actor,
                        metadata={"reason": "processing_failed",
                                  "integration_id": integration_id})
            return self._rejected(row, et, ext_id, "failed",
                                  _bounded(str(e), 200), received_at,
                                  actor, digest=digest, size=len(body),
                                  provider_name=provider_name,
                                  source_reference=source_reference)
        self._complete_claim(claim_id, ref)
        inbound_id = self._record_inbound(
            row, et, ext_id, "accepted", digest, len(body), provider_name,
            received_at, normalized_reference=ref, error="", actor=actor,
            event_time=normalized["event_time"],
            source_reference=source_reference)
        # a REAL accepted inbound interaction is honest health evidence
        if str(row.get("health_state") or "") != "healthy" and \
                row["status"] == "enabled":
            self._mark_health(row, "healthy")
        metrics.inc("integrations_inbound_accepted")
        self._audit("integration.inbound.accepted",
                    object_type="integration_inbound", object_id=inbound_id,
                    org_id=org_id, project_id=project_id, actor=actor,
                    metadata={"integration_id": integration_id,
                              "event_type": et, "route": route,
                              "external_event_id": ext_id[:32]})
        self._abnormal_volume_check(row, received_at, actor)
        return {"status": "accepted", "inbound_id": inbound_id,
                "integration_id": integration_id,
                "external_event_id": ext_id,
                "normalized_reference": ref, "route": route}

    # ------------------------------------------------------------ auth
    def _authenticate(self, row: dict, *, body: bytes, timestamp: str,
                      signature: str, presented: str) -> tuple:
        """Closed auth-mode vocabulary; constant-time comparisons; bounded
        timestamp window; NEVER stores or logs presented material."""
        mode = str(row.get("auth_mode") or "")
        if mode == "hmac":
            ts = str(timestamp or "").strip()
            sig = str(signature or "").strip().lower()
            if not ts or not sig:
                return False, "missing timestamp or signature"
            try:
                skew = abs(time.time() - float(ts))
            except (TypeError, ValueError):
                return False, "malformed timestamp"
            if skew > REPLAY_WINDOW_SECONDS:
                return False, "timestamp outside replay window"
            secret = self._signing_secret(row)
            if not secret:
                return False, "signing secret not configured"
            if not _notify.verify_signature(secret, ts, body, sig):
                return False, "signature mismatch"
            return True, ""
        if mode in ("bearer_token", "api_key"):
            expected = self._signing_secret(row)
            if not expected:
                return False, "credential not configured"
            presented_s = str(presented or "")
            if not presented_s:
                return False, "credential not presented"
            if not hmac.compare_digest(expected, presented_s):
                return False, "credential mismatch"
            return True, ""
        if mode == "mtls_reference":
            # honest boundary: no PKI is implemented — mutual-TLS trust is
            # terminated by the deployment's infrastructure; this service
            # never fabricates certificate validation.
            return False, ("mtls_reference authentication is not "
                           "implemented by this platform (no PKI) — "
                           "terminate mTLS at the infrastructure layer "
                           "and use hmac/bearer_token/api_key here")
        return False, f"unknown auth mode {mode!r}"

    # ------------------------------------------------------------ normalize
    def _normalize(self, row: dict, et: str, payload: dict,
                   external_event_id: str = "") -> dict:
        """Provider-neutral normalization (§19/§20): severity mapped
        deterministically into the EXISTING vocabulary, confidence kept as
        a SEPARATE axis, timestamps bounded, text redacted. Local risk
        engines remain authoritative — nothing here computes risk."""
        if row.get("project_id") is not None and \
                not str(row.get("project_id") or ""):
            raise errors.ValidationError(
                "connection has no project — inbound routing requires "
                "project scope (configuration error)")
        data = redact.redact({k: v for k, v in payload.items()
                              if k in models.INBOUND_EVENT_FIELDS or
                              k == "integrity_sha256"})
        title = _bounded(redact.redact_text(
            str(payload.get("description") or et)), 200)
        severity = models.normalize_external_severity(
            payload.get("severity"))
        conf_raw = str(payload.get("confidence") or "").strip().lower()
        confidence = conf_raw if conf_raw in models.CONFIDENCE else "medium"
        event_time = _bounded(str(payload.get("event_time") or ""), 40)
        if event_time and _epoch(event_time) == 0.0:
            event_time = ""
        return {"event_type": et, "title": title, "severity": severity,
                "confidence": confidence, "event_time": event_time,
                # provider-side event identity: carried through so routed
                # targets can key their own deterministic dedup on it
                "external_event_id": _bounded(
                    str(external_event_id or ""), MAX_EXTERNAL_ID_LEN),
                "source": _bounded(str(payload.get("source") or ""), 120),
                "indicator": _bounded(str(payload.get("indicator") or ""),
                                      200),
                "description": _bounded(redact.redact_text(
                    str(payload.get("description") or "")), MAX_DESC_LEN),
                "data": data}

    # ------------------------------------------------------------ routing
    def _route(self, row: dict, et: str, normalized: dict,
               received_at: str, actor: str) -> tuple:
        """Route into the EXISTING systems. Returns (reference_id,
        route_name). Dedup/fingerprint/risk all belong to those systems —
        this layer never reimplements them."""
        org_id = row["org_id"]
        project_id = str(row.get("project_id") or "")
        provider_name = _bounded(str(row.get("provider") or "") or
                                 row["connector_kind"], MAX_PROVIDER_LEN)
        if et in ("finding", "alert", "security_event"):
            f = models.Finding(
                scan_id=self._integ_scan(project_id),
                project_id=project_id,
                asset_id="",
                title=normalized["title"] or f"external {et}",
                description=normalized["description"] or
                f"External {et} received via integration "
                f"{row['id'][:16]}",
                severity=normalized["severity"],
                confidence=normalized["confidence"],
                category=FINDING_CATEGORY_BY_INBOUND_TYPE[et],
                source=f"integration:{provider_name}",
                rule_id=_bounded(f"external-{et}", 64),
                remediation="Triage the externally reported event; local "
                            "risk scoring and deduplication remain "
                            "authoritative.",
                evidence=[],
                raw={"received_at": received_at,
                     "event_time": normalized["event_time"],
                     "external_source": normalized["source"],
                     "data": normalized["data"]})
            finding = self.svc.finding_ingest(f)
            return finding.id, "finding_ingest"
        if et == "case":
            import security_operations as _so
            cases = _so.InvestigationCaseService(self.svc)
            prio = {"Critical": "high", "High": "high"}.get(
                normalized["severity"], "medium")
            if normalized["severity"] in ("Low", "Info"):
                prio = "low"
            # dedup identity = this connection + the provider's event id.
            # Two distinct external events that share a title on the same
            # day stay DISTINCT cases; a replay of the same external event
            # re-resolves to the same case (the replay claim already blocks
            # the duplicate before routing — this is defence in depth).
            case = cases.create(
                org_id, project_id,
                title=normalized["title"] or "external case handoff",
                description=normalized["description"],
                priority=prio,
                dedup_key=f"integration:{row['id']}:"
                          f"{normalized['external_event_id']}",
                actor=actor)
            return str(case.get("id") or ""), "investigation_case"
        # threat_intel_match → EXISTING IOC catalog (deterministic ids;
        # repeated indicators never duplicate)
        indicator = normalized["indicator"]
        if not indicator:
            raise errors.ValidationError(
                "threat_intel_match requires an 'indicator' field")
        import security_operations as _so
        iocs = _so.IocCatalogService(self.svc)
        level = normalized["confidence"]
        conf = level if level in ("low", "medium", "high") else \
            ("high" if level == "confirmed" else "medium")
        rec = iocs.add(org_id, indicator,
                       source=f"integration:{provider_name}",
                       confidence_level=conf,
                       reference=_bounded(row["id"], 64), actor=actor)
        return str(rec.get("id") or ""), "ioc_catalog"

    # ------------------------------------------------------------ claims
    def _complete_claim(self, claim_id: str, reference: str) -> None:
        now = _now()
        self.db.execute(
            "UPDATE integration_replay_claims SET status='accepted', "
            "completed_at=?, result_reference=?, updated_at=? WHERE id=?",
            (now, _bounded(reference, 64), now, claim_id))

    def _fail_claim(self, claim_id: str) -> None:
        now = _now()
        self.db.execute(
            "UPDATE integration_replay_claims SET status='failed', "
            "failed_at=?, updated_at=? WHERE id=?", (now, now, claim_id))

    # ------------------------------------------------------------ records
    def _record_inbound(self, row: dict, et: str, ext_id: str, status: str,
                        digest: str, size: int, provider_name: str,
                        received_at: str, *, normalized_reference: str,
                        error: str, actor: str, event_time: str = "",
                        source_reference: str = "") -> str:
        inbound_id = models.stable_id(
            models.NS_INTEGRATION_INBOUND,
            f"{row['id']}|{ext_id}|{digest[:16]}|{status}")
        self.db.execute(
            "INSERT INTO integration_inbound_events (id, org_id, "
            "project_id, integration_id, provider, external_event_id, "
            "event_type, event_time, received_at, payload_sha256, "
            "byte_size, status, source_reference, normalized_reference, "
            "error, created_at) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO NOTHING",
            (inbound_id, row["org_id"], row.get("project_id") or "",
             row["id"], provider_name, ext_id,
             _bounded(et if et in models.INBOUND_EVENT_TYPES else
                      "security_event", 40),
             _bounded(event_time, 40), received_at, digest, int(size),
             status,
             _bounded(redact.redact_text(str(source_reference or "")), 200),
             _bounded(normalized_reference, 64), _safe_error(error, 200),
             received_at))
        return inbound_id

    def _rejected(self, row: dict, et: str, ext_id: str, reason: str,
                  detail: str, received_at: str, actor: str, *,
                  digest: str = "", size: int = 0,
                  provider_name: str = "",
                  source_reference: str = "") -> dict:
        """Persist + audit + count a rejection. Provider-caused rejections
        RETURN receipts (observable, auditable) instead of raising."""
        metrics.inc("integrations_inbound_rejected")
        safe_reason = _safe_error(reason, 80)
        safe_detail = _safe_error(detail, 200)
        if ext_id:
            inbound_id = self._record_inbound(
                row, et, ext_id, "rejected", digest, size,
                provider_name or _bounded(str(row.get("provider") or ""),
                                          MAX_PROVIDER_LEN),
                received_at, normalized_reference="",
                error=f"{safe_reason}: {_bounded(safe_detail, 160)}",
                actor=actor, source_reference=source_reference)
        else:
            inbound_id = ""
        self._audit("integration.inbound.rejected",
                    object_type="integration_inbound",
                    object_id=inbound_id or ext_id or row["id"],
                    org_id=row["org_id"],
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"reason": safe_reason,
                              "integration_id": row["id"]})
        return {"status": "rejected", "inbound_id": inbound_id,
                "integration_id": row["id"],
                "external_event_id": redact.redact_text(ext_id),
                "reason": safe_reason, "error": safe_detail}

    def _reject(self, row: dict, ext_id: str, reason: str, detail: str,
                received_at: str, actor: str) -> None:
        """Rate-limit rejection bookkeeping (the caller re-raises the
        RateLimitedError so HTTP semantics stay correct)."""
        metrics.inc("integrations_inbound_rejected")
        self._audit("integration.inbound.rejected",
                    object_type="integration_inbound",
                    object_id=ext_id or row["id"], org_id=row["org_id"],
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"reason": reason,
                              "integration_id": row["id"]})

    # ------------------------------------------------------------ signals
    def _signal(self, row: dict, event_type: str, rule_id: str, title: str,
                description: str, severity: str, received_at: str,
                actor: str) -> None:
        self._emit(row.get("project_id") or "", event_type, key=row["id"],
                   org_id=row["org_id"],
                   new_state={"integration_id": row["id"][:16]},
                   actor=actor)
        self._secops_finding(row, rule_id, title, description, severity,
                             received_at, actor)

    def _secops_finding(self, row: dict, rule_id: str, title: str,
                        description: str, severity: str, received_at: str,
                        actor: str) -> None:
        """Phase-10 security-operations finding through the EXISTING
        finding pipeline (dedup keeps repeated signals bounded)."""
        project_id = str(row.get("project_id") or "")
        if not project_id:
            return
        self._security_finding(
            project_id, rule_id=rule_id, title=title, description=description,
            severity=severity,
            raw={"integration_id": row["id"],
                 "connector_kind": row["connector_kind"]})

    def _abnormal_volume_check(self, row: dict, received_at: str,
                               actor: str) -> None:
        """Bounded sliding-window volume anomaly (§30 signal). Count-only;
        never inspects payload content."""
        cutoff_epoch = _epoch(received_at) - ABNORMAL_VOLUME_WINDOW_SECONDS
        try:
            cutoff = datetime.fromtimestamp(
                cutoff_epoch, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return
        n = int(self._one(
            "SELECT COUNT(*) n FROM integration_inbound_events WHERE "
            "integration_id=? AND received_at>?",
            (row["id"], cutoff))["n"])
        if n > ABNORMAL_VOLUME_THRESHOLD:
            metrics.inc("integrations_abnormal_volume")
            self._signal(row, "integration.abnormal_volume", RULE_VOLUME,
                         "Abnormal integration inbound volume",
                         f"{n} inbound events on connection "
                         f"{row['id'][:16]} within "
                         f"{ABNORMAL_VOLUME_WINDOW_SECONDS}s",
                         "Medium", received_at, actor)


# ===========================================================================
# Facade — one construction point (federation.FederationService precedent)
# ===========================================================================
class EnterpriseIntegrationService:
    """Phase-13 integration pipeline facade.

    Construction mirrors FederationService:
        EnterpriseIntegrationService(platform, provider=..., limiter=...,
                                     gov=...)
    Sub-services share ONE limiter, ONE provider and ONE platform handle —
    no parallel engines, no second databases, no second audit chains.
    """

    def __init__(self, platform, *, limiter=None, provider=None, gov=None):
        shared_limiter = limiter or _id_mod.RateLimiter(max_keys=4096)
        shared_provider = provider or _notify.PROVIDERS["webhook"]
        self.svc = platform
        self.db = platform.db
        self.connections = ConnectionService(
            platform, limiter=shared_limiter, provider=shared_provider,
            gov=gov)
        self.outbound = OutboundService(
            platform, limiter=shared_limiter, provider=shared_provider,
            gov=gov)
        self.inbound = InboundService(
            platform, limiter=shared_limiter, provider=shared_provider,
            gov=gov)
        self.delivery_runner = DeliveryRunner(self.outbound)
