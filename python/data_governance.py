#!/usr/bin/env python3
# ============================================================================
#  data_governance.py — Phase 11: data protection, privacy, secrets and
#  compliance-evidence governance.
#  ---------------------------------------------------------------------------
#  Provider-neutral governance layer on top of the EXISTING platform. It
#  REUSES (never duplicates): identity/RBAC authorization (enforced by the
#  CLI/API layer), tenant isolation (org/project checks, fail closed),
#  the immutable audit chain (every sensitive operation is audited), the
#  centralized secret-redaction engine (redact.py — no second redaction
#  implementation), security events (models.EVENT_TYPES + events service),
#  Phase-6 compliance-evidence derivation (reporting.EvidenceService) and
#  Phase-5 alert rules (governance events flow through alerts.process_event).
#
#  Hard rules encoded here:
#    - classifications are an ALLOWLIST (nothing free-form), transitions to
#      a strictly lower rank require `authorized=True` (caller must hold
#      data.downgrade; enforced + audited);
#    - the secrets registry stores METADATA + a search hash (sha256) ONLY —
#      never the material, and never a decryptable copy; search hashes are
#      explicitly distinguished from the platform's existing encryptable
#      credential stores (notify.py secret encryption, scim creds, cloud
#      credential_enc columns);
#    - retention NEVER deletes audit_events (immutable chain integrity);
#      evidence rows are tombstoned (redacted in place), never dropped with
#      their finding reference;
#    - a record covered by an active hold is NEVER deleted (fail closed);
#    - controlled deletion requires tenant scope + hold check + retention
#      eligibility (or explicit authorization);
#    - exports are bounded (items + serialized bytes), deterministic, 
#      redacted and hash-verified (sha256 of the canonical JSON);
#    - compliance statuses describe EVIDENCE STATE only; nothing here ever
#      claims a certification or legal compliance;
#    - no eval/exec/shell, no pickle, no unbounded queries, no secret
#      material in audit events, errors, logs or exports.
# ============================================================================

from __future__ import annotations

import hashlib
import io
import json
import re
import time
from datetime import datetime, timezone

import errors
import metrics
import models
import redact
import store

import identity as _id_mod
import events as _events_mod

# ---------------------------------------------------------------------------
# Central bounded limits (spec §34/§35) — no caller may override upward.
# ---------------------------------------------------------------------------
MAX_EXPORT_ITEMS = 50_000
MAX_EXPORT_BYTES = 64 * 1024 * 1024        # 64 MiB serialized ceiling
MAX_RETENTION_BATCH = 5_000
MAX_AUDIT_PAGE_SIZE = 500
MAX_EVIDENCE_PAGE_SIZE = 500
MAX_COMPLIANCE_PAGE_SIZE = 500
MAX_LIST_LIMIT = 500
RETENTION_MIN_DAYS = 1
RETENTION_MAX_DAYS = 3650                  # 10 years — documented ceiling
EXPORT_TTL_DAYS = 30

# ops -> (limit, window) rate buckets (identity.RateLimiter reuse)
RATE = {
    "classify": (120, 60),
    "secret": (60, 60),
    "retention": (30, 60),
    "hold": (60, 60),
    "delete": (30, 60),
    "privacy": (60, 60),
    "export": (20, 60),
    "exception": (60, 60),
    "compliance": (60, 60),
}

# ---------------------------------------------------------------------------
# Retention spec — ONE deterministic mapping (dead simple to audit).
#   apply=delete    hard delete rows (children cascade by schema)
#   apply=tombstone keep the row, redact the data columns in place
#   apply=advisory  NEVER delete (immutable chain) — counted + reported only
# Every spec carries its own tenant-scope clause (tables differ: some carry
# org_id directly, some only project_id, phase-4 evidence reaches org via
# findings -> projects). Deterministic on purpose.
# ---------------------------------------------------------------------------
RETENTION_SPEC = {
    "evidence": {
        "table": "evidence", "apply": "tombstone",
        "cutoff_expr": "evidence.captured_at",
        "org_clause": "evidence.finding_id IN (SELECT f.id FROM findings f "
                      "JOIN projects p ON f.project_id=p.id WHERE p.org_id=?)",
        "project_clause": "evidence.finding_id IN (SELECT f.id FROM "
                          "findings f WHERE f.project_id=?)",
        "tombstone_cols": ("url", "method", "request_snippet",
                           "response_snippet", "detection_reason"),
        "where_extra": "",
    },
    "reports": {
        "table": "report_runs", "apply": "delete",
        "cutoff_expr": "report_runs.created_at",
        "org_clause": "report_runs.org_id=?",
        "project_clause": "report_runs.project_id=?",
        "children": (("report_payloads", "report_id"),),
        "where_extra": "report_runs.immutable=0 AND "
                       "report_runs.report_type<>'compliance_evidence'",
    },
    "audit_events": {
        "table": "audit_events", "apply": "advisory",
        "minimum_days": 2555,
        "cutoff_expr": "audit_events.ts",
        "org_clause": "audit_events.org_id=?",
        "project_clause": "audit_events.project_id=?",
        "where_extra": "",
    },
    "findings": {
        "table": "findings", "apply": "delete",
        "cutoff_expr": "COALESCE(NULLIF(findings.resolved_at,''),"
                       "findings.last_detected)",
        "org_clause": "findings.project_id IN (SELECT id FROM projects "
                      "WHERE org_id=?)",
        "project_clause": "findings.project_id=?",
        "where_extra": "findings.lifecycle IN ('resolved','false_positive',"
                       "'accepted_risk','remediated','closed')",
    },
    "scan_history": {
        "table": "scans", "apply": "delete",
        "cutoff_expr": "scans.created_at",
        "org_clause": "scans.project_id IN (SELECT id FROM projects "
                      "WHERE org_id=?)",
        "project_clause": "scans.project_id=?",
        "where_extra": "scans.status='completed' AND scans.id NOT IN "
                       "(SELECT DISTINCT scan_id FROM findings)",
    },
    "monitoring_history": {
        "table": "monitoring_health_history", "apply": "delete",
        "cutoff_expr": "monitoring_health_history.ts",
        "org_clause": "monitoring_health_history.project_id IN (SELECT id "
                      "FROM projects WHERE org_id=?)",
        "project_clause": "monitoring_health_history.project_id=?",
        "where_extra": "",
    },
    "security_events": {
        "table": "security_events", "apply": "delete",
        "minimum_days": 365,
        "cutoff_expr": "security_events.ts",
        "org_clause": "security_events.org_id=?",
        "project_clause": "security_events.project_id=?",
        "where_extra": "",
    },
    "case_history": {
        "table": "investigation_cases", "apply": "delete",
        "cutoff_expr": "COALESCE(NULLIF(investigation_cases.closed_at,''),"
                       "investigation_cases.updated_at)",
        "org_clause": "investigation_cases.org_id=?",
        "project_clause": "investigation_cases.project_id=?",
        "where_extra": "investigation_cases.status IN ('closed','resolved')",
    },
    "threat_intel_data": {
        "table": "threat_indicators", "apply": "delete",
        "cutoff_expr": "threat_indicators.last_seen",
        "org_clause": "threat_indicators.org_id=?",
        "project_clause": None,   # org-scoped only (no project column)
        "where_extra": "threat_indicators.status IN ('expired','revoked')",
    },
    "asset_observations": {
        "table": "asset_observations", "apply": "delete",
        "cutoff_expr": "asset_observations.first_seen",
        "org_clause": "asset_observations.project_id IN (SELECT id FROM "
                      "projects WHERE org_id=?)",
        "project_clause": "asset_observations.project_id=?",
        "where_extra": "",
    },
    # --- Phase 12: federation packages / imports / integration events ---
    # SAME engine, SAME hold protection, SAME bounded windows — no second
    # retention system. Packages tombstone in place: the (already minimized
    # + redacted) payload is purged but id/hash/counts metadata survives so
    # the audit trail stays coherent. Import provenance tombstones its
    # detail blob but keeps the package hash + counts. Integration delivery
    # events are operational logs → hard delete (children cascade by
    # schema: none).
    "federation_packages": {
        "table": "federation_packages", "apply": "tombstone",
        "cutoff_expr": "federation_packages.created_at",
        "org_clause": "federation_packages.org_id=?",
        "project_clause": "federation_packages.project_id=?",
        "tombstone_cols": ("payload", "external_signature_ref"),
        "where_extra": "",
    },
    "federation_imports": {
        "table": "federation_imports", "apply": "tombstone",
        "cutoff_expr": "federation_imports.created_at",
        "org_clause": "federation_imports.org_id=?",
        "project_clause": "federation_imports.target_project_id=?",
        "tombstone_cols": ("detail_json", "error"),
        "where_extra": "",
    },
    "integration_events": {
        "table": "integration_events", "apply": "delete",
        "cutoff_expr": "integration_events.created_at",
        "org_clause": "integration_events.org_id=?",
        "project_clause": "integration_events.project_id=?",
        "where_extra": "",
    },
    # Phase-13 pipeline rows contain hashes/references and bounded metadata,
    # not webhook payloads or credential material. Never expire work that is
    # still active, and never expire a replay claim that has not reached a
    # terminal result.
    "integration_deliveries": {
        "table": "integration_deliveries", "apply": "delete",
        "cutoff_expr": "integration_deliveries.created_at",
        "org_clause": "integration_deliveries.org_id=?",
        "project_clause": "integration_deliveries.project_id=?",
        "where_extra": "integration_deliveries.status IN "
                       "('sent','failed','skipped','rejected','cancelled')",
    },
    "integration_inbound_events": {
        "table": "integration_inbound_events", "apply": "delete",
        "cutoff_expr": "integration_inbound_events.created_at",
        "org_clause": "integration_inbound_events.org_id=?",
        "project_clause": "integration_inbound_events.project_id=?",
        "where_extra": "",
    },
    "integration_replay_claims": {
        "table": "integration_replay_claims", "apply": "delete",
        "cutoff_expr": "integration_replay_claims.created_at",
        "org_clause": "integration_replay_claims.org_id=?",
        "project_clause": "integration_replay_claims.integration_id IN "
                          "(SELECT id FROM external_integrations WHERE "
                          "project_id=? AND org_id="
                          "integration_replay_claims.org_id)",
        "where_extra": "integration_replay_claims.status IN "
                       "('accepted','failed') AND "
                       "(integration_replay_claims.completed_at<>'' OR "
                       "integration_replay_claims.failed_at<>'')",
    },
}


def validate_retention_catalog() -> bool:
    """Fail closed if retention kinds, defaults and executable table specs
    diverge. A missing or malformed rule never inherits an unlimited/default
    retention policy. Credential-bearing connection/secret tables are not
    eligible for this ordinary event/history retention engine."""
    kinds = set(models.RETENTION_KINDS)
    if kinds != set(models.RETENTION_DEFAULTS) or \
            kinds != set(RETENTION_SPEC):
        raise errors.ConfigurationError(
            "retention_catalog_inconsistent: kinds, defaults and specs "
            "must have identical keys")
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    fragment_chars = re.compile(r"^[A-Za-z0-9_().,' =<>?-]*$")
    for kind in models.RETENTION_KINDS:
        spec = RETENTION_SPEC.get(kind)
        required = {"table", "apply", "cutoff_expr", "org_clause",
                    "project_clause", "where_extra"}
        if not isinstance(spec, dict) or not required.issubset(spec):
            raise errors.ConfigurationError(f"retention_spec_invalid: {kind}")
        if spec.get("apply") not in ("delete", "tombstone", "advisory"):
            raise errors.ConfigurationError(f"retention_spec_invalid: {kind}")
        table = spec.get("table")
        cutoff = spec.get("cutoff_expr")
        org_clause = spec.get("org_clause")
        project_clause = spec.get("project_clause")
        where_extra = spec.get("where_extra")
        if not isinstance(table, str) or not identifier.fullmatch(table) or \
                table in {"external_integrations", "secrets_registry"}:
            raise errors.ConfigurationError(f"retention_table_forbidden: {kind}")
        if not isinstance(cutoff, str) or not fragment_chars.fullmatch(cutoff) \
                or not cutoff or ";" in cutoff:
            raise errors.ConfigurationError(f"retention_cutoff_invalid: {kind}")
        if not isinstance(org_clause, str) or org_clause.count("?") != 1 \
                or not fragment_chars.fullmatch(org_clause) or ";" in org_clause:
            raise errors.ConfigurationError(f"retention_scope_invalid: {kind}")
        if project_clause is not None and (
                not isinstance(project_clause, str) or
                project_clause.count("?") != 1 or
                not fragment_chars.fullmatch(project_clause) or
                ";" in project_clause):
            raise errors.ConfigurationError(f"retention_scope_invalid: {kind}")
        if not isinstance(where_extra, str) or "?" in where_extra or \
                not fragment_chars.fullmatch(where_extra) or ";" in where_extra:
            raise errors.ConfigurationError(f"retention_filter_invalid: {kind}")
        if spec["apply"] == "tombstone":
            columns = spec.get("tombstone_cols")
            if not isinstance(columns, (tuple, list)) or not columns or \
                    any(not isinstance(column, str) or
                        not identifier.fullmatch(column) for column in columns):
                raise errors.ConfigurationError(f"retention_tombstone_invalid: {kind}")
        children = spec.get("children", ())
        if not isinstance(children, (tuple, list)) or any(
                not isinstance(pair, (tuple, list)) or len(pair) != 2 or
                any(not isinstance(part, str) or not identifier.fullmatch(part)
                    for part in pair) for pair in children):
            raise errors.ConfigurationError(f"retention_children_invalid: {kind}")
        minimum_days = spec.get("minimum_days", RETENTION_MIN_DAYS)
        if isinstance(minimum_days, bool) or not isinstance(minimum_days, int) or \
                not RETENTION_MIN_DAYS <= minimum_days <= RETENTION_MAX_DAYS:
            raise errors.ConfigurationError(
                f"retention_minimum_invalid: {kind}")
        days = models.RETENTION_DEFAULTS.get(kind)
        if isinstance(days, bool) or not isinstance(days, int) or not (
                minimum_days <= days <= RETENTION_MAX_DAYS):
            raise errors.ConfigurationError(
                f"retention_default_invalid: {kind}")
    return True


def _retention_minimum(kind: str) -> int:
    return int(_retention_spec(kind).get("minimum_days", RETENTION_MIN_DAYS))


def _retention_spec(kind: str) -> dict:
    k = str(kind or "").strip().lower()
    if k not in models.RETENTION_KINDS:
        raise errors.ValidationError(f"unknown retention kind: {k!r}")
    validate_retention_catalog()
    return RETENTION_SPEC[k]


def _retention_default(kind: str) -> int:
    k = str(kind or "").strip().lower()
    if k not in models.RETENTION_KINDS:
        raise errors.ValidationError(f"unknown retention kind: {k!r}")
    validate_retention_catalog()
    return models.RETENTION_DEFAULTS[k]


validate_retention_catalog()

# Controlled-deletion registry: object_type -> (table, cutoff_col, id_col,
# tenant-scoped SELECT). Some tables carry org_id directly; phase-1/4 tables
# (findings, scans) reach the org via projects — isolation is enforced by the
# scoped statement itself (fail closed: a foreign or unknown row is
# NotFoundError).
DELETE_TYPES = {
    "finding": {
        "table": "findings", "cutoff": "resolved_at", "id": "id",
        "scoped": "SELECT f.* FROM findings f JOIN projects p ON "
                  "f.project_id=p.id WHERE f.id=? AND p.org_id=?",
        "fallback": "last_detected"},
    "case": {
        "table": "investigation_cases", "cutoff": "closed_at", "id": "id",
        "scoped": "SELECT * FROM investigation_cases WHERE id=? AND "
                  "org_id=?", "fallback": "updated_at"},
    "secret": {
        "table": "secrets_registry", "cutoff": "created_at", "id": "id",
        "scoped": "SELECT * FROM secrets_registry WHERE id=? AND org_id=?",
        "fallback": None},
    "ioc": {
        "table": "threat_indicators", "cutoff": "last_seen", "id": "id",
        "scoped": "SELECT * FROM threat_indicators WHERE id=? AND org_id=?",
        "fallback": "created_at"},
    "scan": {
        "table": "scans", "cutoff": "created_at", "id": "id",
        "scoped": "SELECT s.* FROM scans s JOIN projects p ON "
                  "s.project_id=p.id WHERE s.id=? AND p.org_id=?",
        "fallback": None},
    "export_record": {
        "table": "data_exports", "cutoff": "created_at", "id": "id",
        "scoped": "SELECT * FROM data_exports WHERE id=? AND org_id=?",
        "fallback": None},
}
# object types that are tombstone-only by design (refuse hard delete)
TOMBSTONE_ONLY = ("evidence", "audit_event")
# dependency-ordered child clears BEFORE the parent row where the schema has
# no cascade; empty everywhere today (all children are ON DELETE CASCADE) —
# kept as an explicit, guarded declaration of deletion order.
PRE_DELETE = {
    "finding": (), "case": (), "secret": (), "ioc": (), "scan": (),
    "export_record": (),
}

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _now() -> str:
    return models.utcnow()


def _utc_epoch(ts: str) -> float | None:
    """Parse an explicitly timezone-aware ISO timestamp without consulting
    the host's local timezone. Naive, malformed or empty values are
    unavailable (None), never silently interpreted as local time."""
    value = str(ts or "").strip()
    if not value or len(value) > 64:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc).timestamp()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _epoch(ts: str) -> float:
    """Compatibility wrapper: invalid timestamps sort before valid history.
    Retention callers validate `now` separately; malformed stored timestamps
    therefore fail closed rather than becoming local-time dependent."""
    value = _utc_epoch(ts)
    return 0.0 if value is None else value


def _iso(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


def _retention_utc_timestamp(value, label: str = "now") -> str:
    """Require an explicit timezone and normalize to canonical UTC text.

    Retention SQL compares timestamps lexicographically, so accepting an
    offset-bearing value without normalizing it can change eligibility.
    Naive, empty and malformed values fail closed instead of using local time.
    """
    epoch = _utc_epoch(value)
    if epoch is None:
        raise errors.ValidationError(
            f"{label} must be an explicit timezone-aware timestamp")
    return _iso(epoch)


def _valid_ts(value, label: str) -> str:
    v = str(value or "").strip()
    if v and (len(v) > 32 or not _TS_RE.match(v)):
        raise errors.ValidationError(f"invalid {label}: {v!r}")
    return v


def _bound_int(value, *, lo: int, hi: int, default: int, label: str) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise errors.ValidationError(f"{label} must be an integer")
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise errors.ValidationError(f"{label} must be an integer") from None
    if n < lo or n > hi:
        raise errors.ValidationError(
            f"{label} out of bounds [{lo}, {hi}]: {n}")
    return n


def _retention_days_value(value, *, label: str = "days",
                         minimum: int = RETENTION_MIN_DAYS) -> int:
    """Retention settings accept integers or digit strings only.

    In particular, floats such as 30.9 must not be silently truncated to a
    more destructive policy by the generic integer-bound helper.
    """
    if isinstance(value, bool):
        raise errors.ValidationError(f"{label} must be an integer")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        number = int(value.strip())
    else:
        raise errors.ValidationError(f"{label} must be an integer")
    if number < minimum or number > RETENTION_MAX_DAYS:
        raise errors.ValidationError(
            f"{label} out of bounds [{minimum}, {RETENTION_MAX_DAYS}]")
    return number


def _bounded(text, n: int) -> str:
    return str(text or "")[:n]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def secret_search_hash(material: str, *, kind: str, name: str,
                       reference: str) -> str:
    """Deterministic search hash for the secrets registry. This is a
    one-way fingerprint used ONLY for duplicate detection — it is NOT a
    decryptable representation and the registry never holds the material."""
    return _sha256(f"{kind}|{name}|{reference}|{redact.redact_text(str(material))}")


# ---------------------------------------------------------------------------
# Secret-shaped-value detection (conservative; NEVER prints the value).
# Pattern classes mirror redact.py's documented formats so the platform has
# exactly one secret vocabulary — this only COUNTS hits.
# ---------------------------------------------------------------------------
_DETECT_PATTERNS = (
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    ("private_key_block", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-\._~+/]{8,}=*")),
)


def detect_secret_shapes(text, *, sample: int = 200) -> dict:
    """Count likely secret-shaped values per class. Returns counts + a
    REDACTED sample only — the detected values are never returned."""
    body = str(text or "")
    classes = {}
    for name, pat in _DETECT_PATTERNS:
        n = len(pat.findall(body))
        if n:
            classes[name] = n
    safe = redact.redact_text(body)[:sample]
    # defense in depth: mask any residual shape that the sample pass could
    # still contain (redaction + our own allowlisted pattern vocabulary)
    for _name, pat in _DETECT_PATTERNS:
        safe = pat.sub("[REDACTED]", safe)
    return {"hits": sum(classes.values()),
            "classes": classes,
            "redacted_sample": safe,
            "note": "values are never returned; counts only"}


# ---------------------------------------------------------------------------
class _Base:
    """Shared governance base: platform handle, bounded queries, audit +
    security-event emission (exactly like the Phase-10 services)."""

    def __init__(self, platform, *, limiter=None):
        self.svc = platform
        self.db = platform.db
        self.limiter = limiter or _id_mod.RateLimiter(max_keys=4096)

    # ------------------------------------------------------------- helpers
    def _acquire(self, key: str, op: str) -> None:
        limit, window = RATE[op]
        ok, retry = self.limiter.allowed(key, limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"{op} rate limit exceeded", retry_after=retry)

    def _org(self, org_id: str) -> None:
        self.svc.org_require(org_id)

    def _project(self, project_id: str) -> models.Project:
        return self.svc.project_require(project_id)

    def _project_owned(self, org_id: str, project_id: str) -> None:
        if project_id:
            proj = self._project(project_id)
            if proj.org_id != org_id:
                raise errors.NotFoundError("project not found")

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
            # platform.audit); the failure is still recorded in metrics
            metrics.inc("governance_audit_failures")

    def _emit(self, project_id: str, event_type: str, *, asset_id: str = "",
              key: str = "", source: str = "data_governance",
              confidence: float = 0.5, previous_state=None, new_state=None,
              actor: str = "system", org_id: str = "") -> dict | None:
        if not project_id:
            return None
        try:
            return _events_mod.SecurityEventService(self.svc).emit(
                project_id, event_type, asset_id=_bounded(asset_id, 64),
                key=_bounded(key, 160), scan_id="", source=source,
                confidence=confidence, previous_state=previous_state,
                new_state=new_state, actor=actor, org_id=org_id)
        except (errors.ValidationError, errors.NotFoundError):
            return None

    def _q(self, sql, params=()):
        return [dict(r) for r in self.db.query(sql, tuple(params))]

    def _one(self, sql, params=()):
        rows = self._q(sql, params)
        return rows[0] if rows else None

    def _page_limit(self, value, *, default: int = 100) -> int:
        return _bound_int(value, lo=1, hi=MAX_LIST_LIMIT, default=default,
                          label="limit")

    def _offset(self, value) -> int:
        return _bound_int(value, lo=0, hi=1_000_000, default=0, label="offset")

    def _row_owned(self, table: str, record_id: str, org_id: str,
                   label: str) -> dict | None:
        """Tenant-scoped lookup: record OR org mismatch -> NotFoundError
        (never reveals whether a foreign object exists)."""
        row = self._one(f"SELECT * FROM {table} WHERE id=?", (record_id,))
        if not row or str(row.get("org_id") or "") != org_id:
            raise errors.NotFoundError(f"{label} not found")
        return row

    def _row_locked(self, conn, table: str, record_id: str, org_id: str,
                    label: str) -> dict:
        row = conn.execute("SELECT * FROM " + table + " WHERE id=?",
                           (record_id,)).fetchone()
        if not row:
            raise errors.NotFoundError(f"{label} not found")
        row = dict(row)
        if str(row.get("org_id") or "") != org_id:
            raise errors.NotFoundError(f"{label} not found")
        return row

    def _upsert(self, table: str, record: dict) -> None:
        cols = ", ".join(record.keys())
        marks = ", ".join("?" for _ in record)
        self.db.execute(
            f"INSERT INTO {table} ({cols}) VALUES ({marks}) "
            f"ON CONFLICT(id) DO UPDATE SET " +
            ", ".join(f"{k}=excluded.{k}" for k in record if k != "id"),
            tuple(record.values()))


# ===========================================================================
# §7 — DATA CLASSIFICATION (allowlist, ranked, downgrade-protected)
# ===========================================================================
class ClassificationService(_Base):
    """Deterministic classification with provenance. The vocabulary is the
    models.DATA_CLASSIFICATIONS allowlist (ranked). A transition to a
    strictly lower rank raises AuthorizationError unless `authorized=True`
    (caller must hold data.downgrade — enforced by CLI/API; the attempt is
    always audited)."""

    def classify(self, org_id: str, object_type: str, *, object_id: str = "",
                 classification: str | None = None, field_name: str = "",
                 provenance: str = "manual", project_id: str = "",
                 authorized: bool = False, actor: str = "api") -> dict:
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"classify:{org_id}", "classify")
        cls = str(classification or "internal").strip().lower()
        if cls not in models.DATA_CLASSIFICATIONS:
            raise errors.ValidationError(
                f"unknown classification: {cls!r} "
                f"(allowlist: {', '.join(models.DATA_CLASSIFICATIONS)})")
        ot = _bounded(str(object_type or "").strip(), 64)
        if not ot:
            raise errors.ValidationError("object_type is required")
        oid = _bounded(str(object_id or "").strip(), 128)
        fn = _bounded(str(field_name or "").strip(), 64)
        prov = _bounded(str(provenance or "manual").strip(), 40)
        if not oid and ot != "default":
            raise errors.ValidationError("object_id is required")
        now = _now()
        cid = models.stable_id(
            models.NS_CLASSIFICATION,
            f"{org_id}|{project_id}|{ot}|{oid}|{fn}")
        existing = self._row_owned("data_classifications", cid, org_id,
                                   "classification") if self._one(
            "SELECT 1 x FROM data_classifications WHERE id=?",
            (cid,)) else None
        if existing is not None:
            existing["classification"] = str(existing.get(
                "classification") or "internal")
            old_rank = models.CLASSIFICATION_RANK.get(
                existing["classification"], 0)
            new_rank = models.CLASSIFICATION_RANK[cls]
            if new_rank < old_rank and not authorized:
                self._audit("classification.downgrade_denied",
                            object_type=ot, object_id=oid or ot, org_id=org_id,
                            project_id=project_id, actor=actor,
                            metadata={"field": fn, "from": existing[
                                "classification"], "to": cls})
                raise errors.AuthorizationError(
                    "classification downgrade requires explicit "
                    "authorization")
        self.db.execute(
            "INSERT INTO data_classifications (id, org_id, project_id, "
            "object_type, object_id, field_name, classification, provenance, "
            "created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET classification=excluded."
            "classification, provenance=excluded.provenance, "
            "updated_at=excluded.updated_at",
            (cid, org_id, project_id, ot, oid, fn, cls, prov,
             _bounded(actor, 128), now, now))
        self._audit("classification.changed", object_type=ot,
                    object_id=oid or ot, org_id=org_id, project_id=project_id,
                    actor=actor, metadata={"field": fn, "to": cls,
                                           "provenance": prov,
                                           "previous": existing[
                                               "classification"] if existing
                                           else None})
        self._emit(project_id, "classification.changed", key=cid,
                   new_state={"object_type": ot, "object_id": oid,
                              "classification": cls}, actor=actor)
        metrics.inc("governance_classifications")
        return self.get(org_id, ot, oid, field_name=fn)

    def default(self, org_id: str, *, classification: str,
                project_id: str = "", actor: str = "api") -> dict:
        if classification not in models.DATA_CLASSIFICATIONS:
            raise errors.ValidationError("unknown classification")
        if project_id:
            self._project(project_id)
        return self.classify(org_id, "default", object_id="",
                             classification=classification,
                             provenance="policy", project_id=project_id,
                             actor=actor)

    def get(self, org_id: str, object_type: str, object_id: str = "",
            *, field_name: str = "", project_id: str = "") -> dict:
        self._org(org_id)
        row = self._one(
            "SELECT * FROM data_classifications WHERE org_id=? AND "
            "object_type=? AND object_id=? AND field_name=?",
            (org_id, str(object_type or ""), str(object_id or ""),
             str(field_name or "")))
        if row:
            return {"effective": row["classification"],
                    "rank": models.CLASSIFICATION_RANK.get(
                        row["classification"], 0),
                    "provenance": row["provenance"], "source": row}
        return self.effective(org_id, object_type, object_id, field_name="",
                              project_id=project_id)

    def effective(self, org_id: str, object_type: str, object_id: str = "",
                  *, field_name: str = "", project_id: str = "") -> dict:
        """Resolution order: exact row -> org default ('default' +
        project scoping first, then org-wide) -> built-in 'internal'.
        Never silently downgrades: any explicit row wins."""
        self._org(org_id)
        row = self._one(
            "SELECT * FROM data_classifications WHERE org_id=? AND "
            "object_type=? AND object_id=? AND field_name=?",
            (org_id, str(object_type or ""), str(object_id or ""),
             str(field_name or "")))
        if not row:
            dflt = self._one(
                "SELECT * FROM data_classifications WHERE org_id=? AND "
                "object_type='default' AND project_id=?",
                (org_id, str(project_id or "")))
            if not dflt:
                dflt = self._one(
                    "SELECT * FROM data_classifications WHERE org_id=? AND "
                    "object_type='default' AND project_id=''",
                    (org_id,))
            cls = dflt["classification"] if dflt else "internal"
            return {"effective": cls,
                    "rank": models.CLASSIFICATION_RANK.get(cls, 0),
                    "provenance": dflt["provenance"] if dflt else "default",
                    "source": dflt}
        return {"effective": row["classification"],
                "rank": models.CLASSIFICATION_RANK.get(
                    row["classification"], 0),
                "provenance": row["provenance"], "source": row}

    def list(self, org_id: str, *, object_type: str = "", project_id: str = "",
             limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = self._offset(offset)
        where, args = ["org_id=?"], [org_id]
        if object_type:
            where.append("object_type=?")
            args.append(str(object_type))
        if project_id:
            where.append("project_id=?")
            args.append(project_id)
        clause = " AND ".join(where)
        total = int(self._one(
            "SELECT COUNT(*) n FROM data_classifications WHERE " + clause,
            args)["n"])
        rows = self._q(
            "SELECT * FROM data_classifications WHERE " + clause +
            " ORDER BY object_type, object_id, field_name, id "
            "LIMIT ? OFFSET ?", args + [limit, offset])
        return {"total": total, "count": len(rows), "items": rows}

    def changes(self, org_id: str, object_type: str, object_id: str = "",
                *, limit: int = 50) -> dict:
        """Provenance history: classification writes from the immutable
        audit chain (never a soft second history table)."""
        self._org(org_id)
        limit = self._page_limit(max(1, min(int(limit or 50), 100)))
        rows = self._q(
            "SELECT ts, action, actor, metadata FROM audit_events WHERE "
            "org_id=? AND action IN ('classification.changed', "
            "'classification.downgrade_denied') AND object_type=? "
            "ORDER BY ts DESC LIMIT ?",
            (org_id, str(object_type), limit))
        rows = [dict(r) for r in rows]
        for r in rows:
            try:
                r["metadata"] = store.loads(r.get("metadata") or "{}")
            except Exception:
                r["metadata"] = {}
        return {"count": len(rows), "items": rows}


# ===========================================================================
# §9/§10 — SECRET + CREDENTIAL GOVERNANCE (metadata-only registry)
# ===========================================================================
class SecretGovernanceService(_Base):
    """Governance METADATA for secrets the platform already handles:
    lifecycle, expiry, rotation due, revocation. The registry stores NEVER
    the material; `search_hash` is a one-way dedup fingerprint, explicitly
    NOT a decryptable representation."""

    def register(self, org_id: str, *, kind: str, name: str = "",
                 reference: str = "", material: str = "", project_id: str = "",
                 expires_at: str = "", rotation_due_at: str = "",
                 actor: str = "api") -> dict:
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"secret:{org_id}", "secret")
        k = str(kind or "").strip().lower()
        if k not in models.SECRET_KINDS:
            raise errors.ValidationError(
                f"unknown secret kind: {k!r} "
                f"(allowlist: {', '.join(models.SECRET_KINDS)})")
        nm = _bounded(redact.redact_text(str(name or "").strip()), 80)
        ref = _bounded(redact.redact_text(str(reference or "").strip()), 200)
        exp = _valid_ts(expires_at, "expires_at")
        rot = _valid_ts(rotation_due_at, "rotation_due_at")
        now = _now()
        shash = secret_search_hash(material, kind=k, name=nm, reference=ref)
        sid = models.stable_id(
            models.NS_SECRET, f"{org_id}|{k}|{shash}")
        self.db.execute(
            "INSERT INTO secrets_registry (id, org_id, project_id, kind, "
            "name, reference, search_hash, status, created_by, created_at, "
            "last_used_at, expires_at, rotation_due_at, revoked_at, "
            "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET last_used_at=excluded."
            "last_used_at, expires_at=excluded.expires_at, "
            "rotation_due_at=excluded.rotation_due_at, updated_at=excluded."
            "updated_at",
            (sid, org_id, project_id, k, nm, ref, shash, "active",
             _bounded(actor, 128), now, "", exp, rot, "", now))
        self._audit("secret.registered", object_type="secret",
                    object_id=sid, org_id=org_id, project_id=project_id,
                    actor=actor, metadata={"kind": k, "name": nm,
                                           "reference": ref,
                                           "search_hash": shash[:16]})
        self._emit(project_id, "secret.rotation_required" if rot and
                   _epoch(rot) <= _epoch(now) else "secret.expiring" if exp
                   and _epoch(exp) <= _epoch(now) + 30 * 86400 else "",
                   key=sid, actor=actor) if project_id else None
        metrics.inc("governance_secrets_registered")
        return self.get(org_id, sid)

    def get(self, org_id: str, secret_id: str) -> dict:
        self._org(org_id)
        return self._row_owned("secrets_registry", secret_id, org_id,
                               "secret")

    def list(self, org_id: str, *, kind: str = "", status: str = "",
             project_id: str = "", limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = self._offset(offset)
        where, args = ["org_id=?"], [org_id]
        if kind:
            where.append("kind=?")
            args.append(str(kind))
        if status:
            where.append("status=?")
            args.append(str(status))
        if project_id:
            where.append("project_id=?")
            args.append(project_id)
        clause = " AND ".join(where)
        total = int(self._one(
            "SELECT COUNT(*) n FROM secrets_registry WHERE " + clause,
            args)["n"])
        rows = self._q(
            "SELECT id, org_id, project_id, kind, name, reference, "
            "search_hash, status, created_by, created_at, last_used_at, "
            "expires_at, rotation_due_at, revoked_at, updated_at FROM "
            "secrets_registry WHERE " + clause +
            " ORDER BY kind, name, id LIMIT ? OFFSET ?", args + [limit, offset])
        return {"total": total, "count": len(rows), "items": rows}

    def touch(self, org_id: str, secret_id: str, *, actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"secret:{org_id}", "secret")
        row = self._row_owned("secrets_registry", secret_id, org_id, "secret")
        now = _now()
        self.db.execute(
            "UPDATE secrets_registry SET last_used_at=?, updated_at=? "
            "WHERE id=? AND org_id=?", (now, now, secret_id, org_id))
        self._audit("secret.accessed", object_type="secret",
                    object_id=secret_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"kind": row.get("kind")})
        self._emit(row.get("project_id") or "", "sensitive.data_accessed",
                   key=secret_id, actor=actor)
        return self.get(org_id, secret_id)

    def set_status(self, org_id: str, secret_id: str, status: str, *,
                   actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"secret:{org_id}", "secret")
        row = self._row_owned("secrets_registry", secret_id, org_id, "secret")
        st = str(status or "").strip().lower()
        if st not in models.SECRET_STATUSES:
            raise errors.ValidationError(f"unknown secret status: {st!r}")
        cur = row.get("status") or "active"
        if st not in models.SECRET_TRANSITIONS.get(cur, ()) and st != cur:
            raise errors.LifecycleError(
                f"invalid secret transition: {cur} -> {st}")
        now = _now()
        revoked = now if st == "revoked" else row.get("revoked_at") or ""
        self.db.execute(
            "UPDATE secrets_registry SET status=?, revoked_at=?, "
            "updated_at=? WHERE id=? AND org_id=?",
            (st, revoked, now, secret_id, org_id))
        action = "secret.revoked" if st == "revoked" else \
            "secret.rotation_required" if st == "rotation_required" else \
            "secret.updated"
        self._audit(action, object_type="secret", object_id=secret_id,
                    org_id=org_id, project_id=row.get("project_id") or "",
                    actor=actor, metadata={"kind": row.get("kind"),
                                           "status": st})
        ev = "secret.revoked" if st == "revoked" else \
            "secret.rotation_required" if st == "rotation_required" else ""
        if ev:
            self._emit(row.get("project_id") or "", ev, key=secret_id,
                       actor=actor)
        return self.get(org_id, secret_id)

    def sweep_expiry(self, org_id: str, *, now: str | None = None,
                     actor: str = "scheduler") -> dict:
        """Deterministic lifecycle sweep: active + expires_at<=now ->
        expired; active + rotation_due_at<=now -> rotation_required."""
        self._org(org_id)
        self._acquire(f"secret:{org_id}", "secret")
        now = now or _now()
        expired, rotated = [], []
        for r in self._q(
                "SELECT * FROM secrets_registry WHERE org_id=? AND "
                "status='active' AND expires_at<>'' AND expires_at<=?",
                (org_id, now)):
            self.db.execute(
                "UPDATE secrets_registry SET status='expired', updated_at=? "
                "WHERE id=? AND status='active'",
                (now, r["id"]))
            expired.append(r["id"])
            self._emit(r.get("project_id") or "", "secret.expired",
                       key=r["id"], actor=actor)
        for r in self._q(
                "SELECT * FROM secrets_registry WHERE org_id=? AND "
                "status='active' AND rotation_due_at<>'' AND "
                "rotation_due_at<=?", (org_id, now)):
            self.db.execute(
                "UPDATE secrets_registry SET status='rotation_required', "
                "updated_at=? WHERE id=? AND status='active'",
                (now, r["id"]))
            rotated.append(r["id"])
            self._emit(r.get("project_id") or "",
                       "secret.rotation_required", key=r["id"], actor=actor)
        for r in self._q(
                "SELECT * FROM secrets_registry WHERE org_id=? AND "
                "status='active' AND expires_at<>'' AND expires_at>? AND "
                "expires_at<=?", (org_id, now, _iso(_epoch(now) + 30 * 86400))):
            self._emit(r.get("project_id") or "", "secret.expiring",
                       key=r["id"], actor=actor)
        if expired or rotated:
            self._audit("secret.expired", object_type="secret",
                        object_id=org_id + ":batch", org_id=org_id,
                        actor=actor,
                        metadata={"expired": len(expired),
                                  "rotation_required": len(rotated)})
        return {"expired": len(expired), "rotation_required": len(rotated)}

    def status_summary(self, org_id: str, *, now: str | None = None) -> dict:
        self._org(org_id)
        now = now or _now()
        rows = self._q(
            "SELECT status, COUNT(*) n FROM secrets_registry WHERE org_id=? "
            "GROUP BY status", (org_id,))
        by_status = {r["status"]: int(r["n"]) for r in rows}
        expiring = int(self._one(
            "SELECT COUNT(*) n FROM secrets_registry WHERE org_id=? AND "
            "status='active' AND expires_at<>'' AND expires_at>? AND "
            "expires_at<=?", (org_id, now, _iso(_epoch(now) + 30 * 86400)))
            ["n"])
        due = int(self._one(
            "SELECT COUNT(*) n FROM secrets_registry WHERE org_id=? AND "
            "status='active' AND rotation_due_at<>'' AND rotation_due_at>? "
            "AND rotation_due_at<=?",
            (org_id, now, _iso(_epoch(now) + 7 * 86400)))["n"])
        return {"total": sum(by_status.values()), "by_status": by_status,
                "expiring_within_30d": expiring,
                "rotation_due_within_7d": due}

    def detect(self, org_id: str, text, *, sample: int = 200) -> dict:
        """Conservative secret-shape detection for imported evidence.
        Returns counts + redacted sample only — never the values."""
        self._org(org_id)
        self._acquire(f"secret:{org_id}", "secret")
        if isinstance(text, (dict, list)):
            text = json.dumps(text, sort_keys=True, default=str)
        res = detect_secret_shapes(text, sample=sample)
        self._audit("secret.detection", object_type="secret",
                    object_id=org_id, org_id=org_id, actor="api",
                    metadata={"hits": res["hits"],
                              "classes": res["classes"]})
        return res


# ===========================================================================
# §12/§13 — RETENTION POLICIES + LEGAL/RETENTION HOLDS
# ===========================================================================
class RetentionService(_Base):
    """Tenant-scoped retention policies with deterministic bounds, preview
    (dry-run) mode, explicit hold protection (fail closed) and a recorded
    audit of every run. audit_events are NEVER deleted (immutable chain);
    evidence rows are tombstoned (not dropped)."""

    # ------------------------------------------------------------- policies
    def policy_set(self, org_id: str, *, kind: str, days: int,
                   project_id: str = "", actor: str = "api") -> dict:
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"retention:{org_id}", "retention")
        k = str(kind or "").strip().lower()
        if k not in models.RETENTION_KINDS:
            raise errors.ValidationError(
                f"unknown retention kind: {k!r} "
                f"(allowlist: {', '.join(models.RETENTION_KINDS)})")
        validate_retention_catalog()
        d = _retention_days_value(
            days, label="days", minimum=_retention_minimum(k))
        now = _now()
        rid = models.stable_id(
            models.NS_RETENTION_POLICY, f"{org_id}|{project_id}|{k}")
        self.db.execute(
            "INSERT INTO retention_policies (id, org_id, project_id, kind, "
            "days, enabled, created_by, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "days=excluded.days, enabled=excluded.enabled, "
            "updated_at=excluded.updated_at",
            (rid, org_id, project_id, k, d, 1, _bounded(actor, 128),
             now, now))
        self._audit("retention.policy_set", object_type="retention_policy",
                    object_id=rid, org_id=org_id, project_id=project_id,
                    actor=actor, metadata={"kind": k, "days": d})
        return self.policy_get(org_id, rid)

    def policy_get(self, org_id: str, policy_id: str) -> dict:
        self._org(org_id)
        return self._row_owned("retention_policies", policy_id, org_id,
                               "retention policy")

    def policies(self, org_id: str, *, project_id: str = "",
                 limit: int = 100) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        where, args = ["org_id=?"], [org_id]
        if project_id:
            where.append("project_id=?")
            args.append(project_id)
        clause = " AND ".join(where)
        rows = self._q(
            "SELECT * FROM retention_policies WHERE " + clause +
            " ORDER BY kind, project_id, id LIMIT ?", args + [limit])
        return {"total": len(rows), "items": rows}

    def effective_days(self, org_id: str, kind: str, *,
                       project_id: str = "") -> int:
        """Project policy -> org default -> documented built-in default."""
        k = str(kind or "").strip().lower()
        if k not in models.RETENTION_KINDS:
            raise errors.ValidationError(f"unknown retention kind: {k!r}")
        validate_retention_catalog()
        minimum = _retention_minimum(k)
        row = self._one(
            "SELECT days FROM retention_policies WHERE org_id=? AND "
            "project_id=? AND kind=? AND enabled=1",
            (org_id, project_id or "", k))
        if not row:
            row = self._one(
                "SELECT days FROM retention_policies WHERE org_id=? AND "
                "project_id='' AND kind=? AND enabled=1", (org_id, k))
        if row:
            return _retention_days_value(row["days"], minimum=minimum)
        return _retention_default(k)

    # ------------------------------------------------------------ holds
    def hold_create(self, org_id: str, *, object_type: str, object_id: str,
                    reason: str, kind: str = "other", project_id: str = "",
                    expires_at: str = "", actor: str = "api") -> dict:
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"hold:{org_id}", "hold")
        ot = _bounded(str(object_type or "").strip(), 64)
        oid = _bounded(str(object_id or "").strip(), 128)
        if not ot or not oid:
            raise errors.ValidationError("object_type and object_id required")
        rs = _bounded(redact.redact_text(str(reason or "").strip()), 500)
        if not rs:
            raise errors.ValidationError("hold reason is required")
        k = str(kind or "other").strip().lower()
        if k not in models.HOLD_KINDS:
            raise errors.ValidationError(f"unknown hold kind: {k!r}")
        exp = _valid_ts(expires_at, "expires_at")
        now = _now()
        hid = models.stable_id(
            models.NS_RETENTION_HOLD, f"{org_id}|{ot}|{oid}|{k}")
        self.db.execute(
            "INSERT INTO retention_holds (id, org_id, project_id, "
            "object_type, object_id, kind, reason, created_by, created_at, "
            "expires_at, released_at, released_by, release_reason, "
            "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET reason=excluded.reason, "
            "expires_at=excluded.expires_at, updated_at=excluded.updated_at",
            (hid, org_id, project_id, ot, oid, k, rs, _bounded(actor, 128),
             now, exp, "", "", "", now))
        self._audit("hold.created", object_type="retention_hold",
                    object_id=hid, org_id=org_id, project_id=project_id,
                    actor=actor, metadata={"object_type": ot,
                                           "object_id": oid[:40],
                                           "kind": k})
        self._emit(project_id, "hold.created", key=hid, actor=actor)
        metrics.inc("governance_holds_created")
        return self._row_owned("retention_holds", hid, org_id, "hold")

    def hold_release(self, org_id: str, hold_id: str, *, reason: str,
                     actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"hold:{org_id}", "hold")
        row = self._row_owned("retention_holds", hold_id, org_id, "hold")
        if row.get("released_at"):
            raise errors.LifecycleError("hold already released")
        rs = _bounded(redact.redact_text(str(reason or "").strip()), 500)
        if not rs:
            raise errors.ValidationError("release reason is required")
        now = _now()
        self.db.execute(
            "UPDATE retention_holds SET released_at=?, released_by=?, "
            "release_reason=?, updated_at=? WHERE id=? AND org_id=?",
            (now, _bounded(actor, 128), rs, now, hold_id, org_id))
        self._audit("hold.released", object_type="retention_hold",
                    object_id=hold_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"object_type": row.get("object_type"),
                              "object_id": str(row.get("object_id"))[:40]})
        self._emit(row.get("project_id") or "", "hold.released",
                   key=hold_id, actor=actor)
        metrics.inc("governance_holds_released")
        return self._row_owned("retention_holds", hold_id, org_id, "hold")

    def hold_list(self, org_id: str, *, active_only: bool = True,
                  object_type: str = "", limit: int = 100,
                  offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = self._offset(offset)
        where, args = ["org_id=?"], [org_id]
        if active_only:
            where.append("released_at=''")
        if object_type:
            where.append("object_type=?")
            args.append(str(object_type))
        clause = " AND ".join(where)
        total = int(self._one(
            "SELECT COUNT(*) n FROM retention_holds WHERE " + clause,
            args)["n"])
        rows = self._q(
            "SELECT * FROM retention_holds WHERE " + clause +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        return {"total": total, "count": len(rows), "items": rows}

    def _active_hold_ids(self, conn, org_id: str, object_type: str,
                         ids: list[str], now: str) -> set[str]:
        if not ids:
            return set()
        marks = ",".join("?" for _ in ids)
        sql = ("SELECT object_id FROM retention_holds WHERE org_id=? AND "
               "object_type=? AND released_at='' AND (expires_at='' OR "
               "expires_at>?) AND object_id IN (" + marks + ")")
        params = (org_id, object_type, now) + tuple(ids)
        if hasattr(conn, "query"):          # Database wrapper (self.db)
            rows = conn.query(sql, params)
        else:                               # raw sqlite3 connection
            rows = conn.execute(sql, params).fetchall()
        return {str(r["object_id"]) for r in rows}

    # ------------------------------------------------------- preview/run
    def preview(self, org_id: str, *, kind: str, project_id: str = "",
                now: str | None = None, batch: int = MAX_RETENTION_BATCH,
                dry_run: bool = True, actor: str = "api") -> dict:
        """Deterministic retention preview: eligible / held / protected
        counts — NOTHING is deleted."""
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"retention:{org_id}", "retention")
        k = str(kind or "").strip().lower()
        if k not in models.RETENTION_KINDS:
            raise errors.ValidationError(f"unknown retention kind: {k!r}")
        spec = _retention_spec(k)
        now = _retention_utc_timestamp(_now() if now is None else now)
        days = self.effective_days(org_id, k, project_id=project_id)
        cutoff = _iso(_utc_epoch(now) - days * 86400)
        with self.db.transaction() as conn:
            res = self._preview_locked(conn, org_id, k, spec, project_id,
                                       cutoff, now,
                                       _bound_int(batch, lo=1,
                                                  hi=MAX_RETENTION_BATCH,
                                                  default=MAX_RETENTION_BATCH,
                                                  label="batch"))
        if dry_run:
            run_id = self._record_run(org_id, k, "preview", "completed",
                                      actor, res["before"], 0,
                                      res["held"], 0,
                                      {"cutoff": cutoff, "days": days,
                                       "protected": res["protected"]})
            self._audit("retention.preview", object_type="retention_run",
                        object_id=run_id, org_id=org_id,
                        project_id=project_id, actor=actor,
                        metadata={"kind": k, "days": days,
                                  "eligible": res["before"],
                                  "held": res["held"]})
        return {"kind": k, "mode": "preview" if dry_run else "execution",
                "days": days, "cutoff": cutoff, "eligible": res["before"],
                "held": res["held"], "protected": res["protected"],
                "protected_detail": res["protected_detail"]}

    def _preview_locked(self, conn, org_id: str, kind: str, spec: dict,
                        project_id: str, cutoff: str, now: str,
                        batch: int) -> dict:
        """Tenant-scoped eligibility preview inside an existing
        transaction. Returns eligible count + ids protected by an active
        hold (fail closed)."""
        table = spec["table"]
        where, args = [spec["org_clause"]], [org_id]
        if project_id and spec["project_clause"]:
            where.append(spec["project_clause"])
            args.append(project_id)
        where.append(spec["cutoff_expr"] + "<=?")
        args.append(cutoff)
        if spec["where_extra"]:
            where.append("(" + spec["where_extra"] + ")")
        clause = " AND ".join(where)
        if spec["apply"] == "advisory":
            rows = conn.execute(
                f"SELECT COUNT(*) n FROM {table} WHERE {clause}",
                args).fetchone()
            return {"before": int(rows["n"]), "held": 0,
                    "protected": int(rows["n"]),
                    "protected_detail": {"reason": "immutable audit chain "
                                                   "never deleted"}}
        rows = conn.execute(
            f"SELECT {table}.id FROM {table} WHERE {clause} ORDER BY "
            f"{table}.id LIMIT ?", args + [batch]).fetchall()
        ids = [str(r["id"]) for r in rows]
        held_ids = self._active_hold_ids(conn, org_id, kind, ids, now)
        eligible = [i for i in ids if i not in held_ids]
        return {"before": len(ids), "held": len(held_ids),
                "protected": len(ids) - len(held_ids),
                "protected_detail": {"sample_held": sorted(held_ids)[:5]}}

    def execute(self, org_id: str, *, kind: str, project_id: str = "",
                now: str | None = None, batch: int = MAX_RETENTION_BATCH,
                dry_run: bool = True, actor: str = "api") -> dict:
        """Dry-run (preview record) or real execution. Rows under an active
        hold are skipped; audit_events are never deleted; evidence rows are
        tombstoned in place. Deletes run in bounded windows; each row is a
        short transaction so a crash never leaves a half-committed batch."""
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"retention:{org_id}", "retention")
        k = str(kind or "").strip().lower()
        if k not in models.RETENTION_KINDS:
            raise errors.ValidationError(f"unknown retention kind: {k!r}")
        spec = _retention_spec(k)
        now = _retention_utc_timestamp(_now() if now is None else now)
        days = self.effective_days(org_id, k, project_id=project_id)
        cutoff = _iso(_utc_epoch(now) - days * 86400)
        b = _bound_int(batch, lo=1, hi=MAX_RETENTION_BATCH,
                       default=MAX_RETENTION_BATCH, label="batch")
        deleted = held = errors_n = 0
        eligible_count = 0
        with self.db.transaction() as conn:
            res = self._preview_locked(conn, org_id, k, spec, project_id,
                                       cutoff, now, b)
            if dry_run:
                held = res["held"]
                eligible_count = res["before"]
            elif spec["apply"] == "advisory":
                eligible_count = res["before"]
        # execution: keyset paging in bounded windows (deterministic order)
        if not dry_run and spec["apply"] != "advisory":
            table = spec["table"]
            col = spec["cutoff_expr"]
            last_id = ""
            while True:
                where, args = [spec["org_clause"]], [org_id]
                if project_id and spec["project_clause"]:
                    where.append(spec["project_clause"])
                    args.append(project_id)
                where.append(col + "<=?")
                args.append(cutoff)
                where.append(f"{table}.id>?")
                args.append(last_id)
                if spec["where_extra"]:
                    where.append("(" + spec["where_extra"] + ")")
                rows = self._q(
                    f"SELECT {table}.id FROM {table} WHERE " +
                    " AND ".join(where) + f" ORDER BY {table}.id LIMIT ?",
                    args + [b])
                if not rows:
                    break
                ids = [r["id"] for r in rows]
                last_id = ids[-1]
                hids = self._active_hold_ids(self.db, org_id, k, ids, now)
                for rid in ids:
                    if rid in hids:
                        held += 1
                        continue
                    try:
                        if spec["apply"] == "tombstone":
                            sets = ", ".join(
                                f"{c}='[RETENTION-PURGED]'"
                                for c in spec["tombstone_cols"])
                            with self.db.transaction() as conn:
                                conn.execute(
                                    f"UPDATE {table} SET {sets} WHERE id=?",
                                    (rid,))
                            deleted += 1
                        else:
                            for child, ckey in spec.get("children", ()):
                                with self.db.transaction() as conn:
                                    conn.execute(
                                        f"DELETE FROM {child} WHERE {ckey}=?",
                                        (rid,))
                            with self.db.transaction() as conn:
                                conn.execute(
                                    f"DELETE FROM {table} WHERE id=?", (rid,))
                            deleted += 1
                    except Exception:
                        errors_n += 1
                eligible_count += len(ids) - len(hids)
                if len(rows) < b:
                    break
        mode = "preview" if dry_run else "execution"
        run_id = self._record_run(org_id, k, mode,
                                  "completed" if not errors_n else "partial",
                                  actor, eligible_count + deleted, deleted,
                                  held, errors_n,
                                  {"cutoff": cutoff, "days": days})
        self._audit(f"retention.{mode}", object_type="retention_run",
                    object_id=run_id, org_id=org_id, project_id=project_id,
                    actor=actor, metadata={"kind": k, "days": days,
                                           "eligible": eligible_count,
                                           "deleted": deleted,
                                           "held": held, "errors": errors_n})
        if errors_n:
            metrics.inc("governance_retention_errors", errors_n)
        self._emit(project_id, "retention.executed", key=run_id,
                   new_state={"kind": k, "mode": mode, "deleted": deleted,
                              "held": held}, actor=actor)
        if held and not dry_run:
            self._emit(project_id, "retention.violation", key=k,
                       new_state={"held": held}, actor=actor)
        return {"run_id": run_id, "kind": k, "mode": mode, "days": days,
                "cutoff": cutoff, "eligible": eligible_count + deleted,
                "deleted": deleted, "held": held, "errors": errors_n}

    def _record_run(self, org_id: str, kind: str, mode: str, status: str,
                    actor: str, before: int, deleted: int, held: int,
                    errs: int, metadata: dict) -> str:
        now = _now()
        import time as _t3
        rid = models.stable_id(
            models.NS_RETENTION_RUN,
            f"{org_id}|{kind}|{mode}|{now}|{before}|{deleted}|"
            f"{_t3.monotonic_ns()}")
        self.db.execute(
            "INSERT INTO retention_runs (id, org_id, project_id, kind, mode, "
            "status, actor, before_count, deleted_count, held_count, "
            "error_count, metadata, started_at, finished_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, org_id, "", kind, mode, status, _bounded(actor, 128),
             before, deleted, held, errs, store.dumps(metadata), now, now))
        return rid

    def runs(self, org_id: str, *, kind: str = "", limit: int = 50) -> dict:
        self._org(org_id)
        limit = self._page_limit(max(1, min(int(limit or 50), 200)))
        where, args = ["org_id=?"], [org_id]
        if kind:
            where.append("kind=?")
            args.append(str(kind))
        rows = self._q(
            "SELECT * FROM retention_runs WHERE " + " AND ".join(where) +
            " ORDER BY started_at DESC, id LIMIT ?", args + [limit])
        for r in rows:
            try:
                r["metadata"] = store.loads(r.get("metadata") or "{}")
            except Exception:
                r["metadata"] = {}
        return {"total": len(rows), "items": rows}


# ===========================================================================
# §14 — CONTROLLED DELETION (preview -> authorize -> execute -> verify)
# ===========================================================================
class DeletionService(_Base):
    """Controlled deletion. Every call: tenant scope -> hold check (fail
    closed) -> retention eligibility (or explicit authorization) -> audit.
    Hard-delete is refused for tombstone-only types."""

    def preview(self, org_id: str, *, object_type: str, object_id: str,
                project_id: str = "", actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"delete:{org_id}", "delete")
        ot, oid = self._type_id(object_type, object_id)
        if ot in TOMBSTONE_ONLY:
            return {"object_type": ot, "object_id": oid,
                    "mode": "tombstone",
                    "eligible": True, "held": False,
                    "retention_eligible": None,
                    "note": "hard delete refused: tombstone-only type"}
        spec = DELETE_TYPES[ot]
        self._scoped_row(spec, oid, org_id, ot)
        kind = self._kind_for(ot)
        days = self._retention_days(org_id, kind, project_id)
        age_ok, age = self._age_eligible(spec, oid, days)
        held = self._held(org_id, ot, oid) or \
            self._held(org_id, kind, oid)
        self._audit("data.delete.preview", object_type=ot, object_id=oid,
                    org_id=org_id, project_id=project_id, actor=actor,
                    metadata={"retention_eligible": age_ok,
                              "held": held, "age_days": age})
        return {"object_type": ot, "object_id": oid, "mode": "delete",
                "eligible": not held, "held": held,
                "retention_eligible": age_ok,
                "retention_days": days, "age_days": age, "kind": kind}

    def delete(self, org_id: str, *, object_type: str, object_id: str,
               project_id: str = "", authorized: bool = False,
               actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"delete:{org_id}", "delete")
        ot, oid = self._type_id(object_type, object_id)
        if ot in TOMBSTONE_ONLY:
            raise errors.ValidationError(
                f"{ot} is tombstone-only: use the retention evidence/audit "
                "handling or privacy redaction instead")
        spec = DELETE_TYPES[ot]
        self._scoped_row(spec, oid, org_id, ot)
        kind = self._kind_for(ot)
        days = self._retention_days(org_id, kind, project_id)
        age_ok, age = self._age_eligible(spec, oid, days)
        held = self._held(org_id, ot, oid) or \
            self._held(org_id, kind, oid)
        if held:
            self._audit("data.delete_blocked", object_type=ot,
                        object_id=oid, org_id=org_id, project_id=project_id,
                        actor=actor, metadata={"reason": "active hold"})
            raise errors.LifecycleError("deletion blocked by active hold")
        if not age_ok and not authorized:
            self._audit("data.delete_blocked", object_type=ot,
                        object_id=oid, org_id=org_id, project_id=project_id,
                        actor=actor,
                        metadata={"reason": "not retention-eligible"})
            raise errors.AuthorizationError(
                "object is not retention-eligible; explicit authorization "
                "required")
        table = spec["table"]
        affected = 0
        with self.db.transaction() as conn:
            for child, ckey in PRE_DELETE.get(ot, ()):
                conn.execute(f"DELETE FROM {child} WHERE {ckey}=?", (oid,))
            cur = conn.execute(f"DELETE FROM {table} WHERE id=?", (oid,))
            affected = cur.rowcount
        remaining = int((self._one(
            f"SELECT COUNT(*) n FROM {table} WHERE id=?", (oid,)) or
            {"n": 0})["n"])
        self._audit("data.deleted", object_type=ot, object_id=oid,
                    org_id=org_id, project_id=project_id, actor=actor,
                    metadata={"retention_eligible": age_ok,
                              "authorized": bool(authorized),
                              "affected": affected})
        self._emit(project_id, "data.deleted", key=oid,
                   new_state={"object_type": ot}, actor=actor)
        metrics.inc("governance_deletions")
        return {"object_type": ot, "object_id": oid, "deleted": affected > 0,
                "remaining": remaining, "hold_checked": True,
                "retention_eligible": age_ok}

    # ------------------------------------------------------------ helpers
    def _type_id(self, object_type: str, object_id: str):
        ot = _bounded(str(object_type or "").strip().lower(), 64)
        oid = _bounded(str(object_id or "").strip(), 128)
        if not ot or not oid:
            raise errors.ValidationError("object_type and object_id required")
        if ot in DELETE_TYPES or ot in TOMBSTONE_ONLY:
            return ot, oid
        raise errors.ValidationError(f"unknown deletable type: {ot!r}")

    def _scoped_row(self, spec: dict, oid: str, org_id: str,
                    label: str) -> dict:
        """Tenant-scoped existence check: foreign/unknown -> NotFoundError
        (fail closed; indistinguishable on purpose)."""
        row = self._one(spec["scoped"], (oid, org_id))
        if not row:
            raise errors.NotFoundError(f"{label} not found")
        return row

    def _held(self, org_id: str, ot: str, oid: str) -> bool:
        return bool(self._one(
            "SELECT 1 x FROM retention_holds WHERE org_id=? AND "
            "object_type=? AND object_id=? AND released_at='' AND "
            "(expires_at='' OR expires_at>?)", (org_id, ot, oid, _now())))

    def _kind_for(self, ot: str) -> str:
        return {"finding": "findings", "case": "case_history",
                "secret": "asset_observations", "ioc": "threat_intel_data",
                "scan": "scan_history",
                "export_record": "reports"}.get(ot, "findings")

    def _retention_days(self, org_id: str, kind: str,
                        project_id: str) -> int:
        k = str(kind or "").strip().lower()
        if k not in models.RETENTION_KINDS:
            raise errors.ValidationError(f"unknown retention kind: {k!r}")
        validate_retention_catalog()
        minimum = _retention_minimum(k)
        row = self._one(
            "SELECT days FROM retention_policies WHERE org_id=? AND "
            "project_id=? AND kind=? AND enabled=1",
            (org_id, project_id or "", k))
        if not row:
            row = self._one(
                "SELECT days FROM retention_policies WHERE org_id=? AND "
                "project_id='' AND kind=? AND enabled=1", (org_id, k))
        if row:
            return _retention_days_value(row["days"], minimum=minimum)
        return _retention_default(k)

    def _age_eligible(self, spec: dict, obj_id: str, days: int):
        """Retention-eligibility check on the documented cutoff column
        (fallback column where the object has no lifecycle timestamp)."""
        col = spec["cutoff"]
        row = self._one(
            f"SELECT {col} AS c FROM {spec['table']} WHERE id=?", (obj_id,))
        ts = str(row["c"]) if row else ""
        if not ts and spec.get("fallback"):
            row = self._one(
                f"SELECT {spec['fallback']} AS c FROM {spec['table']} "
                "WHERE id=?", (obj_id,))
            ts = str(row["c"]) if row else ""
        if not ts:
            return False, None
        record_epoch = _utc_epoch(ts)
        current_epoch = _utc_epoch(_now())
        if record_epoch is None or current_epoch is None:
            return False, None
        age = (current_epoch - record_epoch) / 86400.0
        return age >= days, round(max(0.0, age), 1)


class PrivacyRequestService(_Base):
    """Models request lifecycle only. Legal interpretation of what a
    request means remains the customer/operator responsibility — this
    module explicitly makes no compliance claim."""

    def create(self, org_id: str, *, request_type: str, subject_ref: str,
               project_id: str = "", scope: dict | None = None,
               requester: str = "", actor: str = "api") -> dict:
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"privacy:{org_id}", "privacy")
        rt = str(request_type or "").strip().lower()
        if rt not in models.PRIVACY_REQUEST_TYPES:
            raise errors.ValidationError(
                f"unknown privacy request type: {rt!r} (allowlist: "
                f"{', '.join(models.PRIVACY_REQUEST_TYPES)})")
        sr = _bounded(str(subject_ref or "").strip(), 254)
        if not sr:
            raise errors.ValidationError("subject_ref is required")
        req = _bounded(str(requester or "").strip(), 128)
        sc = redact.redact(dict(scope or {}))
        if len(store.dumps(sc)) > 65536:
            raise errors.ValidationError("privacy scope too large")
        now = _now()
        pid = models.stable_id(
            models.NS_PRIVACY_REQUEST,
            f"{org_id}|{rt}|{sr}|{req}|{now}")
        try:
            self.db.execute(
                "INSERT INTO privacy_requests (id, org_id, project_id, "
                "request_type, subject_ref, scope, status, requester, "
                "reviewer, failure_reason, completion_evidence, created_at, "
                "updated_at, completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, org_id, project_id, rt, sr, store.dumps(sc),
                 "submitted", req, "", "", "{}", now, now, ""))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise errors.DuplicateError(
                    "an identical open privacy request already exists") from e
            raise
        self._audit("privacy.created", object_type="privacy_request",
                    object_id=pid, org_id=org_id, project_id=project_id,
                    actor=actor, metadata={"request_type": rt,
                                           "subject_ref": sr[:60]})
        self._emit(project_id, "privacy.requested", key=pid,
                   new_state={"request_type": rt}, actor=actor)
        metrics.inc("governance_privacy_requests")
        return self._row_owned("privacy_requests", pid, org_id,
                               "privacy request")

    def get(self, org_id: str, request_id: str) -> dict:
        self._org(org_id)
        row = self._row_owned("privacy_requests", request_id, org_id,
                              "privacy request")
        row["scope"] = self._loads(row.get("scope"))
        row["completion_evidence"] = self._loads(row.get(
            "completion_evidence"))
        return row

    def list(self, org_id: str, *, status: str = "", project_id: str = "",
             limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = self._offset(offset)
        where, args = ["org_id=?"], [org_id]
        if status:
            where.append("status=?")
            args.append(str(status))
        if project_id:
            where.append("project_id=?")
            args.append(project_id)
        clause = " AND ".join(where)
        total = int(self._one(
            "SELECT COUNT(*) n FROM privacy_requests WHERE " + clause,
            args)["n"])
        rows = self._q(
            "SELECT id, org_id, project_id, request_type, subject_ref, "
            "status, requester, reviewer, failure_reason, created_at, "
            "updated_at, completed_at FROM privacy_requests WHERE " + clause +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        return {"total": total, "count": len(rows), "items": rows}

    def update(self, org_id: str, request_id: str, *, status: str,
               reviewer: str = "", failure_reason: str = "",
               actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"privacy:{org_id}", "privacy")
        row = self._row_owned("privacy_requests", request_id, org_id,
                              "privacy request")
        st = str(status or "").strip().lower()
        if st not in models.PRIVACY_REQUEST_STATUSES:
            raise errors.ValidationError(f"unknown privacy status: {st!r}")
        cur = row.get("status") or "submitted"
        if st not in models.PRIVACY_TRANSITIONS.get(cur, ()) and st != cur:
            raise errors.LifecycleError(
                f"invalid privacy transition: {cur} -> {st}")
        fr = _bounded(redact.redact_text(str(failure_reason or "").strip()),
                      500)
        rv = _bounded(str(reviewer or "").strip(), 128)
        now = _now()
        self.db.execute(
            "UPDATE privacy_requests SET status=?, reviewer=?, "
            "failure_reason=?, updated_at=? WHERE id=? AND org_id=?",
            (st, rv, fr, now, request_id, org_id))
        self._audit("privacy.updated", object_type="privacy_request",
                    object_id=request_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"status": st, "reviewer": rv,
                              "failure_reason": fr[:120]})
        return self.get(org_id, request_id)

    def complete(self, org_id: str, request_id: str, *, reviewer: str,
                 evidence: dict | None = None, actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"privacy:{org_id}", "privacy")
        row = self._row_owned("privacy_requests", request_id, org_id,
                              "privacy request")
        cur = row.get("status") or "submitted"
        if cur not in ("in_progress", "approved"):
            raise errors.LifecycleError(
                f"cannot complete from {cur}")
        rv = _bounded(str(reviewer or "").strip(), 128)
        if not rv:
            raise errors.ValidationError("reviewer is required")
        ev = redact.redact(dict(evidence or {}))
        if len(store.dumps(ev)) > 65536:
            raise errors.ValidationError("completion evidence too large")
        now = _now()
        self.db.execute(
            "UPDATE privacy_requests SET status='completed', reviewer=?, "
            "completion_evidence=?, updated_at=?, completed_at=? "
            "WHERE id=? AND org_id=?",
            (rv, store.dumps(ev), now, now, request_id, org_id))
        self._audit("privacy.completed", object_type="privacy_request",
                    object_id=request_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"reviewer": rv})
        self._emit(row.get("project_id") or "", "privacy.completed",
                   key=request_id, actor=actor)
        metrics.inc("governance_privacy_completed")
        return self.get(org_id, request_id)

    def fail(self, org_id: str, request_id: str, *, reason: str,
             actor: str = "api") -> dict:
        return self.update(org_id, request_id, status="failed",
                           failure_reason=reason, actor=actor)

    @staticmethod
    def _loads(v):
        try:
            return store.loads(v or "{}")
        except Exception:
            return {}


# ===========================================================================
# §21 — POLICY EXCEPTIONS (bounded lifetime; expired never effective)
# ===========================================================================
class PolicyExceptionService(_Base):
    def create(self, org_id: str, *, policy: str, scope: str = "",
               reason: str, approved_by: str = "", project_id: str = "",
               expires_at: str = "", actor: str = "api") -> dict:
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"exception:{org_id}", "exception")
        pol = _bounded(str(policy or "").strip(), 128)
        if not pol:
            raise errors.ValidationError("policy is required")
        sc = _bounded(str(scope or "").strip(), 200)
        rs = _bounded(redact.redact_text(str(reason or "").strip()), 500)
        if not rs:
            raise errors.ValidationError("reason is required")
        ap = _bounded(str(approved_by or "").strip(), 128)
        exp = _valid_ts(expires_at, "expires_at")
        now = _now()
        eid = models.stable_id(
            models.NS_POLICY_EXCEPTION,
            f"{org_id}|{project_id}|{pol}|{sc}|{now}")
        self.db.execute(
            "INSERT INTO policy_exceptions (id, org_id, project_id, policy, "
            "scope, reason, created_by, approved_by, created_at, expires_at, "
            "status, revoked_at, revoked_by, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, org_id, project_id, pol, sc, rs, _bounded(actor, 128),
             ap, now, exp, "active", "", "", now))
        self._audit("exception.created", object_type="policy_exception",
                    object_id=eid, org_id=org_id, project_id=project_id,
                    actor=actor, metadata={"policy": pol, "scope": sc,
                                           "expires_at": exp})
        metrics.inc("governance_exceptions")
        return self._row_owned("policy_exceptions", eid, org_id,
                               "policy exception")

    def get(self, org_id: str, exception_id: str) -> dict:
        self._org(org_id)
        row = self._row_owned("policy_exceptions", exception_id, org_id,
                              "policy exception")
        row["effective"] = self._effective(row, _now())
        return row

    def list(self, org_id: str, *, status: str = "", project_id: str = "",
             limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = self._offset(offset)
        where, args = ["org_id=?"], [org_id]
        if status:
            where.append("status=?")
            args.append(str(status))
        if project_id:
            where.append("project_id=?")
            args.append(project_id)
        clause = " AND ".join(where)
        total = int(self._one(
            "SELECT COUNT(*) n FROM policy_exceptions WHERE " + clause,
            args)["n"])
        rows = self._q(
            "SELECT id, org_id, project_id, policy, scope, reason, "
            "created_by, approved_by, created_at, expires_at, status, "
            "revoked_at, revoked_by, updated_at FROM policy_exceptions "
            "WHERE " + clause + " ORDER BY created_at DESC, id LIMIT ? "
            "OFFSET ?", args + [limit, offset])
        now = _now()
        for r in rows:
            r["effective"] = self._effective(r, now)
        return {"total": total, "count": len(rows), "items": rows}

    def revoke(self, org_id: str, exception_id: str, *, reason: str,
               actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"exception:{org_id}", "exception")
        row = self._row_owned("policy_exceptions", exception_id, org_id,
                              "policy exception")
        if row.get("status") != "active":
            raise errors.LifecycleError("exception is not active")
        rs = _bounded(redact.redact_text(str(reason or "").strip()), 500)
        now = _now()
        self.db.execute(
            "UPDATE policy_exceptions SET status='revoked', revoked_at=?, "
            "revoked_by=?, updated_at=? WHERE id=? AND org_id=?",
            (now, _bounded(actor, 128), now, exception_id, org_id))
        self._audit("exception.revoked", object_type="policy_exception",
                    object_id=exception_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"reason": rs})
        return self.get(org_id, exception_id)

    def sweep_expiry(self, org_id: str, *, now: str | None = None,
                     actor: str = "scheduler") -> dict:
        self._org(org_id)
        self._acquire(f"exception:{org_id}", "exception")
        now = now or _now()
        expired = 0
        for r in self._q(
                "SELECT * FROM policy_exceptions WHERE org_id=? AND "
                "status='active' AND expires_at<>'' AND expires_at<=?",
                (org_id, now)):
            self.db.execute(
                "UPDATE policy_exceptions SET status='expired', updated_at=? "
                "WHERE id=? AND status='active'", (now, r["id"]))
            expired += 1
            self._emit(r.get("project_id") or "",
                       "policy_exception.expired", key=r["id"], actor=actor)
        if expired:
            self._audit("exception.expired", object_type="policy_exception",
                        object_id=org_id + ":batch", org_id=org_id,
                        actor=actor, metadata={"expired": expired})
        return {"expired": expired}

    def effective(self, org_id: str, policy: str, *,
                  project_id: str = "") -> dict | None:
        """Fail closed: ONLY an active, non-expired, non-revoked exception
        is effective. Returns the exception row or None."""
        self._org(org_id)
        now = _now()
        rows = self._q(
            "SELECT * FROM policy_exceptions WHERE org_id=? AND policy=? "
            "AND (project_id=? OR project_id='') AND status='active' "
            "AND (expires_at='' OR expires_at>?)",
            (org_id, policy, project_id or "", now))
        return rows[0] if rows else None

    @staticmethod
    def _effective(row: dict, now: str) -> bool:
        if str(row.get("status") or "") != "active":
            return False
        exp = str(row.get("expires_at") or "")
        return not exp or exp > now


# ===========================================================================
# §16 — SECURE DATA EXPORT (bounded, redacted, deterministic, hash-verified)
# ===========================================================================
EXPORT_SCOPES = ("summary", "classifications", "secrets", "retention",
                 "holds", "privacy", "exceptions", "compliance", "all")


class DataExportService(_Base):
    """Tenant-isolated, RBAC-gated (caller layer), bounded exports with
    deterministic ordering, redaction, manifest + integrity hash. No scope
    loads unbounded rows: keyset paging inside fixed-size pages."""

    def build(self, org_id: str, *, scope: str = "summary",
              fmt: str = "json", project_id: str = "", limit: int = 1000,
              actor: str = "api") -> dict:
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"export:{org_id}", "export")
        sc = str(scope or "summary").strip().lower()
        if sc not in EXPORT_SCOPES:
            raise errors.ValidationError(
                f"unknown export scope: {sc!r} "
                f"(allowlist: {', '.join(EXPORT_SCOPES)})")
        fm = str(fmt or "json").strip().lower()
        if fm not in ("json", "csv"):
            raise errors.ValidationError("export format must be json or csv")
        lim = _bound_int(limit, lo=1, hi=MAX_EXPORT_ITEMS, default=1000,
                         label="limit")
        snapped = {}
        if sc in ("summary", "all"):
            snapped["summary"] = self._summary_payload(org_id, project_id)
        # scope name -> payload key (payload keys stay neutral; the central
        # redactor treats secret*-named keys as opaque by design)
        for scope_name, key, fn in (
                ("classifications", "classifications",
                 self._page_classifications),
                ("secrets", "registry", self._page_secrets),
                ("retention", "retention", self._page_retention),
                ("holds", "holds", self._page_holds),
                ("privacy", "privacy", self._page_privacy),
                ("exceptions", "exceptions", self._page_exceptions),
                ("compliance", "compliance", self._page_compliance)):
            if sc in (scope_name, "all"):
                snapped[key] = fn(org_id, project_id=project_id, limit=lim)
        payload = {
            "schema_version": "data-export-v1",
            "generated_at": _now(),
            "created_by": _bounded(actor, 128),
            "org_id": org_id,
            "project_id": project_id or "",
            "scope": sc,
            "format": fm,
            "truncated": any(v.get("truncated") for v in snapped.values()
                             if isinstance(v, dict)),
            **snapped,
        }
        payload = redact.redact(payload)
        if fm == "json":
            text = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False)
        else:
            text = self._to_csv(snapped)
        data = text.encode("utf-8")
        if len(data) > MAX_EXPORT_BYTES:
            raise errors.ValidationError(
                "export too large (exceeds " + str(MAX_EXPORT_BYTES // 1024
                                                   // 1024) + " MiB); "
                "narrow the scope or reduce limit")
        integrity = _sha256(text)
        import time as _t2
        eid = models.stable_id(
            models.NS_DATA_EXPORT,
            f"{org_id}|{sc}|{fmt}|{_now()}|{integrity[:16]}|{_t2.monotonic_ns()}")
        self.db.execute(
            "INSERT INTO data_exports (id, org_id, project_id, scope, "
            "format, item_count, byte_size, sha256, created_by, created_at, "
            "expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (eid, org_id, project_id, sc, fm, self._count_items(snapped),
             len(data), integrity, _bounded(actor, 128), _now(),
             _iso(_epoch(_now()) + EXPORT_TTL_DAYS * 86400)))
        self._audit("sensitive.exported", object_type="data_export",
                    object_id=eid, org_id=org_id, project_id=project_id,
                    actor=actor,
                    metadata={"scope": sc, "format": fm,
                              "bytes": len(data),
                              "items": self._count_items(snapped),
                              "sha256": integrity[:16]})
        self._emit(project_id, "sensitive.exported", key=eid,
                   new_state={"scope": sc, "format": fm, "items":
                              self._count_items(snapped)}, actor=actor)
        metrics.inc("governance_exports")
        return {"export_id": eid, "integrity": integrity, "byte_size":
                len(data), "scope": sc, "format": fm,
                "item_count": self._count_items(snapped),
                "data": text, "manifest": {
                    "org_id": org_id, "project_id": project_id or "",
                    "generated_at": payload["generated_at"],
                    "created_by": payload["created_by"],
                    "truncated": payload["truncated"]}}

    def record(self, org_id: str, export_id: str) -> dict:
        self._org(org_id)
        return self._row_owned("data_exports", export_id, org_id,
                               "export record")

    def list(self, org_id: str, *, limit: int = 50) -> dict:
        self._org(org_id)
        limit = self._page_limit(max(1, min(int(limit or 50), 200)))
        rows = self._q(
            "SELECT id, org_id, project_id, scope, format, item_count, "
            "byte_size, sha256, created_by, created_at, expires_at FROM "
            "data_exports WHERE org_id=? ORDER BY created_at DESC, id "
            "LIMIT ?", (org_id, limit))
        return {"total": len(rows), "items": rows}

    # ---------------------------------------------------------- pagers
    def _page(self, org_id: str, table: str, cols: str, limit: int,
              *, project_id: str = "", extra: str = "") -> dict:
        out, last, trunc = [], "", limit
        while True:
            where = ["org_id=?"]
            args: list = [org_id]
            if project_id and "project_id" in {r["name"] for r in
                                               self._q(
                                                   f"PRAGMA table_info({table})")}:
                where.append("project_id=?")
                args.append(project_id)
            where.append("id>?")
            args.append(last)
            if extra:
                where.append(extra)
            rows = self._q(
                f"SELECT id, {cols} FROM {table} WHERE " +
                " AND ".join(where) + " ORDER BY id LIMIT ?", args + [500])
            if not rows:
                break
            out.extend(rows)
            last = rows[-1]["id"]
            if len(rows) < 500:
                break
            if len(out) >= limit:
                trunc = True
                out = out[:limit]
                break
        return {"items": out, "count": len(out),
                "truncated": bool(trunc and len(out) >= limit)}

    def _page_classifications(self, org_id, *, project_id="", limit=1000):
        return self._page(org_id, "data_classifications",
                          "object_type, object_id, field_name, "
                          "classification, provenance, project_id, "
                          "created_at, updated_at", limit,
                          project_id=project_id)

    def _page_secrets(self, org_id, *, project_id="", limit=1000):
        return self._page(org_id, "secrets_registry",
                          "kind, name, reference, search_hash, status, "
                          "project_id, created_at, last_used_at, "
                          "expires_at, rotation_due_at, revoked_at", limit,
                          project_id=project_id)

    def _page_retention(self, org_id, *, project_id="", limit=1000):
        return self._page(org_id, "retention_policies",
                          "kind, days, enabled, project_id, created_at, "
                          "updated_at", limit, project_id=project_id)

    def _page_holds(self, org_id, *, project_id="", limit=1000):
        return self._page(org_id, "retention_holds",
                          "object_type, object_id, kind, reason, created_by, "
                          "created_at, expires_at, released_at, "
                          "released_by, release_reason, project_id", limit,
                          project_id=project_id)

    def _page_privacy(self, org_id, *, project_id="", limit=1000):
        return self._page(org_id, "privacy_requests",
                          "request_type, subject_ref, status, requester, "
                          "reviewer, project_id, created_at, updated_at, "
                          "completed_at, failure_reason", limit,
                          project_id=project_id)

    def _page_exceptions(self, org_id, *, project_id="", limit=1000):
        return self._page(org_id, "policy_exceptions",
                          "policy, scope, reason, created_by, approved_by, "
                          "project_id, created_at, expires_at, status, "
                          "revoked_at, revoked_by", limit,
                          project_id=project_id)

    def _page_compliance(self, org_id, *, project_id="", limit=1000):
        rows = self._page(org_id, "compliance_evidence",
                          "control_category, source_type, source_id, "
                          "status, evidence_ts, data_cutoff, description, "
                          "evidence_hash, project_id", limit,
                          project_id=project_id)
        return rows

    def _summary_payload(self, org_id: str, project_id: str) -> dict:
        svc = SecurityGovernance(self.svc)
        summ = svc.summary(org_id, budget_items=20)
        if project_id:
            summ = {k: v for k, v in summ.items()
                    if k in ("generated_at", "classifications",
                             "secrets", "retention", "holds", "privacy",
                             "exceptions", "compliance")}
        return {"kind": "governance_summary", "data": summ}

    @staticmethod
    def _count_items(snapped: dict) -> int:
        n = 0
        for v in snapped.values():
            if isinstance(v, dict) and isinstance(v.get("items"), list):
                n += len(v["items"])
            elif isinstance(v, dict) and isinstance(v.get("data"), dict):
                n += 1
        return n

    @staticmethod
    def _to_csv(snapped: dict) -> str:
        buf = io.StringIO()
        keys = [k for k in ("classifications", "registry", "holds",
                            "exceptions", "privacy", "retention",
                            "compliance") if isinstance(snapped.get(k), dict)]
        for k in keys:
            items = snapped[k].get("items", [])
            buf.write(f"# {k}\n")
            if items:
                cols = sorted({c for it in items for c in it})
                buf.write(",".join(cols) + "\n")
                for it in items:
                    buf.write(",".join(
                        '"' + str(it.get(c, "")).replace('"', '""') + '"'
                        for c in cols) + "\n")
        if "summary" in snapped:
            buf.write("# summary\n")
            buf.write(json.dumps(snapped["summary"], sort_keys=True,
                                 default=str) + "\n")
        return buf.getvalue()


# ===========================================================================
# §19/§20 — COMPLIANCE EVIDENCE GOVERNANCE (coverage/gaps; no claims)
# ===========================================================================
class ComplianceGovernanceService(_Base):
    """Maps the EXISTING Phase-6 evidence derivation into a control-state
    view: per control family status distribution, coverage ratio, explicit
    gaps and effective exceptions. `status` describes EVIDENCE STATE only;
    `requirement_satisfied` is intentionally NOT produced — the platform
    makes no compliance claim."""

    def controls(self, org_id: str, *, project_id: str = "",
                 limit: int = MAX_COMPLIANCE_PAGE_SIZE) -> dict:
        self._org(org_id)
        limit = self._page_limit(max(1, min(int(limit or 200),
                                            MAX_COMPLIANCE_PAGE_SIZE)))
        out = []
        for cat in models.CONTROL_CATEGORIES:
            stats = self._stats(org_id, cat, project_id=project_id)
            eff = False
            ex = self._one(
                "SELECT 1 x FROM policy_exceptions WHERE org_id=? AND "
                "policy=? AND (project_id=? OR project_id='') AND "
                "status='active' AND (expires_at='' OR expires_at>?)",
                (org_id, cat, project_id or "", _now()))
            eff = ex is not None
            out.append({
                "control": cat,
                "status": stats.get("status", "not_evaluated"),
                "distribution": stats.get("distribution", {}),
                "coverage": stats.get("coverage", 0.0),
                "evidence_exists": stats.get("total", 0) > 0,
                "gap": stats.get("gap", False),
                "source": stats.get("source", ""),
                "timestamp": stats.get("evidence_ts", ""),
                "provenance": stats.get("provenance", ""),
                "exception_effective": eff,
            })
        return {"org_id": org_id, "project_id": project_id or "",
                "status_vocabulary": list(models.CONTROL_STATUSES),
                "note": "status describes evidence state only; nothing here "
                        "asserts compliance or certification",
                "controls": out[:limit]}

    def gaps(self, org_id: str, *, project_id: str = "") -> list[dict]:
        ctrl = self.controls(org_id, project_id=project_id)
        return [c for c in ctrl["controls"] if c["gap"] or
                not c["evidence_exists"]]

    def exceptions(self, org_id: str, *, project_id: str = "") -> dict:
        return PolicyExceptionService(self.svc).list(
            org_id, project_id=project_id, limit=200)

    def evidence_audit(self, org_id: str, *, project_id: str = "",
                       limit: int = MAX_EVIDENCE_PAGE_SIZE) -> dict:
        rows = self._page_evidence(org_id, project_id=project_id,
                                   limit=limit)
        return {"total": rows[0], "items": rows[1], "truncated": rows[2]}

    def _page_evidence(self, org_id, *, project_id="", limit=500):
        where, args = ["org_id=?"], [org_id]
        if project_id:
            where.append("project_id=?")
            args.append(project_id)
        clause = " AND ".join(where)
        total = int(self._one(
            "SELECT COUNT(*) n FROM compliance_evidence WHERE " + clause,
            args)["n"])
        rows = self._q(
            "SELECT id, control_category, source_type, source_id, status, "
            "evidence_ts, data_cutoff, description, evidence_hash, "
            "project_id FROM compliance_evidence WHERE " + clause +
            " ORDER BY control_category, id LIMIT ?",
            args + [min(limit, MAX_EVIDENCE_PAGE_SIZE)])
        return total, rows, total > len(rows)

    def _stats(self, org_id: str, category: str, *, project_id: str) -> dict:
        where, args = ["org_id=?", "control_category=?"], [org_id, category]
        if project_id:
            where.append("project_id=?")
            args.append(project_id)
        clause = " AND ".join(where)
        rows = self._q(
            "SELECT status, COUNT(*) n, MAX(evidence_ts) ts FROM "
            "compliance_evidence WHERE " + clause + " GROUP BY status",
            args)
        if not rows:
            return {"status": "not_evaluated", "distribution": {},
                    "coverage": 0.0, "total": 0, "gap": True, "source": "",
                    "evidence_ts": "", "provenance": ""}
        total = sum(int(r["n"]) for r in rows)
        status = rows[0]["status"] if len(rows) == 1 else \
            "partially_supported"
        if status in ("not_supported", "insufficient_evidence"):
            status = "insufficient_evidence" if total else "not_supported"
        supported = sum(int(r["n"]) for r in rows if
                        r["status"] in ("supported", "partially_supported"))
        return {"status": status,
                "distribution": {str(r["status"]): int(r["n"])
                                 for r in rows},
                "coverage": round(supported / max(1, total), 3),
                "total": total,
                "gap": status in ("not_evaluated", "not_supported",
                                  "insufficient_evidence"),
                "source": "reporting.EvidenceService",
                "evidence_ts": max((str(r["ts"]) or "") for r in rows),
                "provenance": "derived:" + category}


# ===========================================================================
# Facade — one handle for the whole governance surface (+ dashboard summary)
# ===========================================================================
class SecurityGovernance:
    """Composition facade. Every subsystem is a thin wrapper over the
    existing platform services (no duplicate infrastructure)."""

    def __init__(self, platform, *, limiter=None):
        self.platform = platform
        lim = limiter or _id_mod.RateLimiter(max_keys=4096)
        self.classification = ClassificationService(platform, limiter=lim)
        self.secrets = SecretGovernanceService(platform, limiter=lim)
        self.retention = RetentionService(platform, limiter=lim)
        self.deletion = DeletionService(platform, limiter=lim)
        self.privacy = PrivacyRequestService(platform, limiter=lim)
        self.exceptions = PolicyExceptionService(platform, limiter=lim)
        self.exports = DataExportService(platform, limiter=lim)
        self.compliance = ComplianceGovernanceService(platform, limiter=lim)

    def summary(self, org_id: str, *, budget_items: int = 20) -> dict:
        """Read-only dashboard snapshot (counts + titles only — never
        secret values, never PII beyond subject references already stored
        for the workflow, never audit metadata details)."""
        self.platform.org_require(org_id)
        budget = max(1, min(int(budget_items or 20), 100))
        sec = self.secrets.status_summary(org_id)
        clss = self.classification.list(org_id, limit=budget)
        pol = self.retention.policies(org_id, limit=budget)
        holds = self.retention.hold_list(org_id, active_only=True,
                                         limit=budget)
        priv = self.privacy.list(org_id, limit=budget)
        exc = self.exceptions.list(org_id, limit=budget)
        ctrl = self.compliance.controls(org_id, limit=200)
        recent = [a.to_dict() for a in
                  self.platform.audit_list_org(org_id, limit=budget)]
        sensitive_actions = [a for a in recent if (
            "secret." in str(a.get("action")) or
            "sensitive." in str(a.get("action")) or
            "data.delete" in str(a.get("action")) or
            "hold." in str(a.get("action")) or
            "privacy." in str(a.get("action")) or
            "exception." in str(a.get("action")) or
            "classification." in str(a.get("action")))]
        return {
            "generated_at": _now(),
            "classifications": {"total": clss["total"],
                                "count": clss["count"]},
            "secrets": sec,
            "retention": {"policies": pol["total"],
                          "defaults": dict(models.RETENTION_DEFAULTS),
                          "recent_runs": self.retention.runs(
                              org_id, limit=5)["items"]},
            "holds": {"active": holds["total"], "items": [
                {"object_type": h["object_type"],
                 "object_id": str(h["object_id"])[:40],
                 "kind": h["kind"], "created_at": h["created_at"],
                 "expires_at": h["expires_at"]} for h in holds["items"]]},
            "privacy": {"total": priv["total"], "by_status": self._counts(
                priv["items"], "status")},
            "exceptions": {"total": exc["total"], "items": [
                {"policy": e["policy"], "status": e["status"],
                 "expires_at": e["expires_at"],
                 "effective": e.get("effective")} for e in exc["items"]]},
            "compliance": {"controls": len(ctrl["controls"]),
                           "gaps": [c["control"] for c in
                                    self.compliance.gaps(org_id)],
                           "coverage_by_control": {
                               c["control"]: c["coverage"]
                               for c in ctrl["controls"]}},
            "sensitive_events": [{
                "ts": a.get("ts"), "action": a.get("action"),
                "actor": a.get("actor"),
                "object_type": a.get("object_type")}
                for a in sensitive_actions[:budget]],
        }

    @staticmethod
    def _counts(items, key) -> dict:
        out = {}
        for it in items:
            k = str(it.get(key) or "unknown")
            out[k] = out.get(k, 0) + 1
        return out
