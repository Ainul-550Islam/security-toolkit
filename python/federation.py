#!/usr/bin/env python3
# ============================================================================
#  federation.py — Phase 12: enterprise data federation, evidence exchange,
#  bulk operations and the external-integration boundary.
#  ---------------------------------------------------------------------------
#  Design invariants (all enforced in code, all covered by tests):
#    - EXTENSION, never replacement: peers/policies/packages/imports are new
#      tenant-scoped tables (store v14); findings, evidence, assets, cases,
#      IOC catalog, jobs, audit chain, rate limiter, retention, redaction,
#      classification and webhook SSRF guards are the EXISTING systems.
#    - explicit trust only: a peer is created `pending`; only an approval
#      (admin-level permission + creator != approver) makes it `active`;
#      expired/revoked/suspended fail closed on EVERY export/import path.
#    - packages are deterministic: canonical JSON (sorted keys, compact
#      separators, volatile keys removed) hashed with sha256; identical
#      content always yields the identical package id + hash, which makes
#      duplicate imports idempotent (UNIQUE(org_id, package_hash)).
#    - data leaves an organization ONLY through a policy: object types,
#      classifications, field allowlists and object limits are enforced at
#      build time AND re-verified at import time (never trust the sender).
#    - `secret` / `authentication_material` classifications require an
#      explicit policy acknowledgment; raw secret material is never
#      exportable regardless (single redaction engine + shape scrub).
#      Envelope keys must never match redact.SECRET_KEY_RE: the envelope is
#      staged on the job scan record (scan_save_raw redacts it) and its hash
#      is recomputed on import, so a redacted key would break integrity.
#    - privacy wins: an object carrying a Phase-11 subject-restriction
#      marker is excluded from federation even when the policy allows its
#      classification.
#    - imports never masquerade: every imported object carries provenance
#      (source org/project/object id, package id/hash, import id, policy,
#      timestamp); findings reuse the Phase-4 fingerprint/dedup pipeline.
#    - bulk operations run through the EXISTING Phase-3 job engine
#      (in-process profile `federation-bulk`): leases, pause/cancel at
#      checkpoints, retries, stale recovery, bounded concurrency, audit.
#    - external integrations are a delivery BOUNDARY only: https-only
#      endpoints validated by the EXISTING notify SSRF guard, HMAC signing
#      via the EXISTING notify signer, bounded + redacted payloads, every
#      delivery attempt logged. No vendor platform is implemented.
#    - no eval/exec/shell, no pickle, no unsafe YAML, no unbounded queries,
#      no silent exception swallowing, no secret material in audit events,
#      security events, errors, logs, packages or webhook payloads.
# ============================================================================

from __future__ import annotations

import hmac
import json
import re
import sqlite3
import time

import errors
import metrics
import models
import redact
import store

import identity as _id_mod
import events as _events_mod
import notify as _notify
import data_governance as _gov
from data_governance import (_now, _epoch, _iso, _bounded, _bound_int,
                             _valid_ts, _sha256)

# ---------------------------------------------------------------------------
# Central bounded limits — no caller may override upward.
# ---------------------------------------------------------------------------
FED_SCHEMA = models.FEDERATION_SCHEMA_VERSION          # "fed-package-v1"
CANONICALIZATION = "json-sortkeys-sep-v1"
MAX_PACKAGE_OBJECTS = 5_000            # per package (policy may lower it)
MAX_PACKAGE_BYTES = 32 * 1024 * 1024   # 32 MiB serialized envelope ceiling
MAX_IMPORT_BYTES = 32 * 1024 * 1024    # inbound serialized ceiling
MAX_OBJECT_DEPTH = 8                   # malformed-nesting guard
MAX_STRUCTURE_NODES = 200_000          # inbound structure node budget
MAX_STRING_FIELD = 65_536              # inbound per-string ceiling
MAX_LIST_LIMIT = 200
MAX_TYPE_LIMIT = 1_000                 # per-type default page cap
MAX_FIELD_VALUE = 4_096                # exported per-field truncation
MAX_WEBHOOK_PAYLOAD_BYTES = 16 * 1024  # integration payload ceiling
MAX_INTEGRATIONS_PER_EVENT = 10
MAX_REJECTED_FOR_FINDING = 3           # repeated-rejection finding trigger
BULK_PAGE_SIZE = 200                   # checkpoint cadence inside bulk ops

# ops -> (limit, window) rate buckets (identity.RateLimiter reuse; tenant +
# actor aware because the key carries the org and the operation)
RATE = {
    "peer": (60, 60),
    "policy": (60, 60),
    "package": (20, 60),
    "import": (20, 60),
    "bulk": (20, 60),
    "integration": (60, 60),
    "emit": (120, 60),
}

# Webhook vocabulary for the integration boundary (§24). Deliberately small
# and explicit; anything else is rejected (never free-form event names).
WEBHOOK_EVENTS = (
    "package.created", "package.imported", "package.rejected",
    "peer.revoked", "policy.expired", "bulk.completed", "bulk.failed",
)

# Privacy restriction marker written by the Phase-11 privacy engine — an
# object carrying it anywhere is EXCLUDED from federation (privacy
# restriction overrides an ordinary federation export permission).
_PRIVACY_MARKER = "[REDACTED-SUBJECT"

# ---------------------------------------------------------------------------
# Field universe (§8): the ONLY fields that may ever appear in a package
# object, per type. Everything else (internal ids like scan_id, raw blobs,
# Phase-4 intelligence columns, hashes, subject references) never leaves.
# A federation policy may NARROW this set per type; it can never widen it.
# `_provenance` and `_classification` are structural keys added by the
# builder and validated separately at import.
# ---------------------------------------------------------------------------
FIELD_UNIVERSE = {
    "organization": ("id", "name", "status", "created_at"),
    "project": ("id", "name", "description", "status", "created_at",
                "updated_at"),
    "asset": ("id", "asset_type", "value", "display", "status",
              "first_seen", "last_seen", "criticality", "exposure"),
    "finding": ("id", "title", "description", "severity", "confidence",
                "category", "source", "rule_id", "template_id", "cwe",
                "cve", "remediation", "lifecycle", "first_detected",
                "last_detected", "parameter", "endpoint", "asset_type",
                "asset_value"),
    "evidence": ("id", "evidence_type", "url", "method", "status_code",
                 "request_snippet", "response_snippet", "detection_reason",
                 "scanner", "rule_id", "captured_at"),
    "report": ("id", "report_type", "title", "status", "report_hash",
               "data_cutoff", "generated_at", "generated_by", "truncated",
               "byte_size"),
    "case": ("id", "title", "description", "status", "priority", "owner",
             "created_at", "updated_at", "closed_at", "refs"),
    "threat_intel_match": ("id", "ioc_type", "indicator", "matched_on",
                           "first_seen", "last_seen", "match_count",
                           "status", "confidence"),
    "security_event": ("id", "event_type", "source", "ts", "confidence",
                       "state_key"),
}
# keys added by the builder to every object (not policy-narrowable)
_STRUCTURAL_KEYS = ("_provenance", "_classification")

# Export specs: type -> (SQL with keyset paging placeholders, row->object
# mapper). All queries are tenant-scoped BY THE SQL ITSELF (fail closed) and
# ordered by id for deterministic keyset paging. `{proj}` marks the optional
# project filter. Page size is bounded; the builder loops page -> minimize
# -> append -> hash at the end (bounded memory: <= MAX_PACKAGE_OBJECTS).
_EXPORT_SQL = {
    "organization": (
        "SELECT id, name, status, created_at FROM organizations "
        "WHERE id=? AND id>? ORDER BY id LIMIT ?", None),
    "project": (
        "SELECT id, name, description, status, created_at, updated_at, "
        "id AS project_id FROM projects WHERE org_id=?{proj} AND id>? "
        "ORDER BY id LIMIT ?", "id"),
    "asset": (
        "SELECT a.id, a.asset_type, a.value, a.display, a.status, "
        "a.first_seen, a.last_seen, a.criticality, a.exposure, "
        "a.project_id FROM assets a JOIN projects p ON p.id=a.project_id "
        "WHERE p.org_id=?{proj} AND a.id>? ORDER BY a.id LIMIT ?",
        "a.project_id"),
    "finding": (
        "SELECT f.id, f.title, f.description, f.severity, f.confidence, "
        "f.category, f.source, f.rule_id, f.template_id, f.cwe, f.cve, "
        "f.remediation, f.lifecycle, f.first_detected, f.last_detected, "
        "f.raw, f.project_id, a2.asset_type AS asset_type, "
        "a2.value AS asset_value FROM findings f JOIN projects p ON "
        "p.id=f.project_id LEFT JOIN assets a2 ON a2.id=f.asset_id "
        "WHERE p.org_id=?{proj} AND f.id>? ORDER BY f.id LIMIT ?",
        "f.project_id"),
    "evidence": (
        "SELECT e.id, e.evidence_type, e.url, e.method, e.status_code, "
        "e.request_snippet, e.response_snippet, e.detection_reason, "
        "e.scanner, e.rule_id, e.captured_at, e.finding_id, f.project_id "
        "FROM evidence e JOIN findings f ON f.id=e.finding_id "
        "JOIN projects p ON p.id=f.project_id WHERE p.org_id=?{proj} "
        "AND e.id>? ORDER BY e.id LIMIT ?", "f.project_id"),
    "report": (
        "SELECT id, report_type, title, status, report_hash, data_cutoff, "
        "generated_at, generated_by, truncated, byte_size, project_id "
        "FROM report_runs WHERE org_id=?{proj} AND id>? ORDER BY id LIMIT ?",
        "project_id"),
    "case": (
        "SELECT id, title, description, status, priority, owner, "
        "created_at, updated_at, closed_at, project_id FROM "
        "investigation_cases WHERE org_id=?{proj} AND id>? ORDER BY id "
        "LIMIT ?", "project_id"),
    "threat_intel_match": (
        "SELECT m.id, m.ioc_type, m.matched_on, m.first_seen, m.last_seen, "
        "m.match_count, m.status, i.indicator, i.confidence_level AS "
        "confidence, m.project_id FROM threat_matches m JOIN "
        "threat_indicators i ON i.id=m.indicator_id WHERE m.org_id=?{proj} "
        "AND m.id>? ORDER BY m.id LIMIT ?", "m.project_id"),
    "security_event": (
        "SELECT id, event_type, source, ts, confidence, state_key, "
        "project_id FROM security_events WHERE org_id=?{proj} AND id>? "
        "ORDER BY id LIMIT ?", "project_id"),
}

# keys removed before canonicalization (nondeterministic / added after the
# hash is computed) — mirrors reporting.canonical()'s documented approach
_VOLATILE_KEYS = ("package_id", "created_at", "integrity", "trust_mode",
                  "external_signature")

_REQUIRED_ENVELOPE_KEYS = (
    "schema_version", "source_organization", "destination",
    "policy_reference", "classification", "provenance", "objects", "counts",
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def canonical_payload(envelope: dict) -> str:
    """Deterministic canonical form of a package envelope: volatile keys
    removed, sorted keys, compact separators, UTF-8. Identical content
    always yields an identical string (and therefore an identical hash)."""
    core = {k: v for k, v in dict(envelope).items() if k not in _VOLATILE_KEYS}
    return json.dumps(core, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def package_hash(envelope: dict) -> str:
    return _sha256(canonical_payload(envelope))


def verify_envelope(envelope) -> dict:
    """Pure integrity verification (no writes). Recomputes the sha256 over
    the canonical payload and compares in constant time. An
    `externally_signed` package is integrity-checked like any other; its
    external signature is NEVER reported as verified by local code (no
    fabricated cryptographic trust)."""
    out = {"valid": False, "algorithm": "sha256", "expected": "",
           "actual": "", "schema_version": "", "error": ""}
    if isinstance(envelope, (str, bytes)):
        text = envelope if isinstance(envelope, str) else \
            envelope.decode("utf-8", "strict")
        if len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
            out["error"] = "package_too_large"
            return out
        try:
            envelope = json.loads(text)
        except (ValueError, UnicodeDecodeError):
            out["error"] = "package_unparsable"
            return out
    if not isinstance(envelope, dict):
        out["error"] = "package_not_object"
        return out
    integ = envelope.get("integrity")
    if not isinstance(integ, dict):
        out["error"] = "integrity_missing"
        return out
    algo = str(integ.get("algorithm") or "")
    expected = str(integ.get("hash") or "")
    out["algorithm"] = algo
    out["expected"] = expected[:64]
    out["schema_version"] = str(envelope.get("schema_version") or "")
    if algo != "sha256":
        out["error"] = "integrity_algorithm_unsupported"
        return out
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        out["error"] = "integrity_hash_malformed"
        return out
    try:
        _check_structure(envelope)
    except errors.ValidationError as e:
        out["error"] = f"structure_invalid: {e}"[:200]
        return out
    actual = package_hash(envelope)
    out["actual"] = actual
    out["valid"] = hmac.compare_digest(expected, actual)
    if not out["valid"]:
        out["error"] = "integrity_mismatch"
    return out


def _check_structure(obj, *, _depth: int = 0, _nodes: list | None = None) \
        -> int:
    """Inbound structure guard: JSON-like types only, bounded depth/node
    count/string length. Raises ValidationError on anything malformed.
    Returns the node count. Never calls eval/pickle/yaml."""
    if _nodes is None:
        _nodes = [0]
    _nodes[0] += 1
    if _nodes[0] > MAX_STRUCTURE_NODES:
        raise errors.ValidationError("package_structure_exceeded: too many "
                                     "nodes")
    if _depth > MAX_OBJECT_DEPTH:
        raise errors.ValidationError("package_structure_exceeded: nesting "
                                     "too deep")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str) or len(k) > 128:
                raise errors.ValidationError("package_structure_exceeded: "
                                             "invalid key")
            _check_structure(v, _depth=_depth + 1, _nodes=_nodes)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_structure(v, _depth=_depth + 1, _nodes=_nodes)
    elif isinstance(obj, str):
        if len(obj) > MAX_STRING_FIELD:
            raise errors.ValidationError("package_structure_exceeded: "
                                         "string too long")
    elif obj is None or isinstance(obj, bool) or isinstance(obj, (int, float)):
        pass
    else:
        raise errors.ValidationError(
            f"package_structure_exceeded: type {type(obj).__name__}")
    return _nodes[0]



class _Base:
    """Shared federation base — the same shape as the Phase-10/11 services:
    platform handle, bounded queries, tenant guards, rate limiting, audit +
    security-event emission through the EXISTING systems."""

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

    def _org(self, org_id: str):
        return self.svc.org_require(org_id) or \
            self.svc.org_get(org_id)

    def _project_owned(self, org_id: str, project_id: str) -> None:
        if project_id:
            proj = self.svc.project_require(project_id)
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
            # platform.audit / Phase-11 services); the failure stays
            # observable through metrics
            metrics.inc("federation_audit_failures")

    def _emit(self, project_id: str, event_type: str, *, key: str = "",
              source: str = "federation", confidence: float = 0.6,
              new_state=None, actor: str = "system", org_id: str = "") \
            -> dict | None:
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

    def _q(self, sql, params=()):
        return self.db.query(sql, tuple(params))

    def _one(self, sql, params=()):
        row = self.db.query_one(sql, tuple(params))
        return row

    def _maybe(self, sql, params=()):
        try:
            return self.db.query_one(sql, tuple(params))
        except errors.NotFoundError:
            return None

    def _page_limit(self, value, *, default: int = 100) -> int:
        return _bound_int(value, lo=1, hi=MAX_LIST_LIMIT, default=default,
                          label="limit")

    # ------------------------------------------------- security findings
    def _fed_scan(self, project_id: str) -> str:
        """Deterministic per-project 'federation' scan — security findings
        raised by federation anomalies reference it (findings REQUIRE a
        scan_id; same pattern as the Phase-10 threat-intel scan)."""
        sid = models.stable_id(models.NS_SCAN, f"{project_id}|federation")
        try:
            return self.svc.scan_get(sid).id
        except errors.NotFoundError:
            return self.svc.scan_create(project_id, "federation",
                                        scope_ref="", scan_id=sid).id

    def _security_finding(self, project_id: str, *, rule_id: str, title: str,
                          description: str, severity: str,
                          raw: dict | None = None) -> models.Finding:
        """Raise a REAL platform finding (existing normalization, existing
        fingerprint, existing dedup — repeated anomalies never duplicate).
        Values are redacted before they ever reach the finding."""
        f = models.Finding(
            scan_id=self._fed_scan(project_id),
            project_id=project_id,
            asset_id="",
            title=_bounded(redact.redact_text(title), 200),
            description=_bounded(redact.redact_text(description), 2000),
            severity=severity if severity in models.SEVERITIES else "Medium",
            confidence="medium",
            category="federation",
            source="federation",
            rule_id=_bounded(rule_id, 64),
            remediation="Review the federation agreement, package integrity "
                        "and import validation results; revoke the peer if "
                        "the anomaly persists.",
            evidence=[], raw=redact.redact(dict(raw or {})))
        return self.svc.finding_ingest(f)


# ===========================================================================
# Peers — the explicit trust relationships (§5/§6/§29/§30/§31)
# ===========================================================================
class FederationPeerService(_Base):

    def create(self, org_id: str, *, peer_org_id: str, name: str,
               purpose: str = "", direction: str = "outbound",
               expires_at: str = "", actor: str = "api") -> dict:
        """Create a PENDING peer. Never active on creation — trust always
        requires an explicit approval by a different actor (SoD)."""
        self._org(org_id)
        self._acquire(f"peer:{org_id}", "peer")
        if peer_org_id == org_id:
            raise errors.ValidationError("peer_org must differ from org")
        self.svc.org_require(peer_org_id)
        nm = _bounded(redact.redact_text(str(name or "").strip()), 120)
        if len(nm) < 3:
            raise errors.ValidationError("peer name too short")
        d = str(direction or "outbound").strip().lower()
        if d not in models.FEDERATION_DIRECTIONS:
            raise errors.ValidationError(f"unknown direction: {d!r}")
        purpose_b = _bounded(redact.redact_text(str(purpose or "")), 300)
        exp = _valid_ts(expires_at, "expires_at")
        now = _now()
        pid = models.stable_id(models.NS_FED_PEER,
                               f"{org_id}|{peer_org_id}|{nm}")
        try:
            self.db.execute(
                "INSERT INTO federation_peers (id, org_id, peer_org_id, "
                "name, purpose, direction, status, created_by, approved_by, "
                "created_at, updated_at, expires_at) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, org_id, peer_org_id, nm, purpose_b, d, "pending",
                 _bounded(actor, 128), "", now, now, exp))
        except sqlite3.IntegrityError:
            raise errors.DuplicateError(
                f"federation peer already exists: {nm}") from None
        metrics.inc("federation_peers_created")
        self._audit("federation.peer.created", object_type="federation_peer",
                    object_id=pid, org_id=org_id, actor=actor,
                    metadata={"peer_org_id": peer_org_id, "direction": d,
                              "status": "pending"})
        self._emit("", "federation.peer_created", key=pid, org_id=org_id,
                   actor=actor)
        return self.get(org_id, pid)

    def get(self, org_id: str, peer_id: str) -> dict:
        self._org(org_id)
        row = self._maybe(
            "SELECT * FROM federation_peers WHERE id=? AND org_id=?",
            (peer_id, org_id))
        if not row:
            raise errors.NotFoundError("federation peer not found")
        return dict(row)

    def list(self, org_id: str, *, status: str = "", peer_org_id: str = "",
             limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if status:
            s = str(status).strip().lower()
            if s not in models.FEDERATION_PEER_STATUSES:
                raise errors.ValidationError(f"unknown status: {s!r}")
            where.append("status=?"); args.append(s)
        if peer_org_id:
            where.append("peer_org_id=?"); args.append(peer_org_id)
        total = int(self._one(
            "SELECT COUNT(*) n FROM federation_peers WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            "SELECT id, peer_org_id, name, purpose, direction, status, "
            "created_by, approved_by, created_at, expires_at, revoked_at "
            "FROM federation_peers WHERE " + " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        return {"total": total, "count": len(rows), "items": rows}

    def _transition(self, org_id: str, peer_id: str, target: str, *,
                    action: str, actor: str, reason: str = "",
                    approved_by: str = "", extra_sets: dict | None = None,
                    require_different_actor: bool = False) -> dict:
        row = self.get(org_id, peer_id)
        cur = str(row["status"])
        allowed = models.FEDERATION_PEER_TRANSITIONS.get(cur, set())
        if target not in allowed:
            raise errors.LifecycleError(
                f"peer transition denied: {cur} -> {target}")
        if row.get("expires_at") and (
                (cur in ("active", "suspended") and
                 target not in ("expired", "revoked")) or
                (cur == "pending" and target == "active")) and \
                str(row["expires_at"]) <= _now():
            # an expired grant can never transition to/back to active
            # without an explicit re-request (fail closed on expiry, §30) —
            # including approval of a pending peer whose window already
            # elapsed
            raise errors.LifecycleError(
                "peer grant expired; re-request approval (expired -> "
                "pending) before reactivation")
        if require_different_actor:
            creator = str(row.get("created_by") or "")
            approver = _bounded(str(approved_by or actor or ""), 128)
            if not approver:
                raise errors.ValidationError("approver identity required")
            if creator and approver == creator:
                raise errors.AuthorizationError(
                    "Forbidden: separation of duties — the peer creator "
                    "cannot approve their own federation grant")
        now = _now()
        sets = {"status": target, "updated_at": now}
        if approved_by:
            sets["approved_by"] = _bounded(approved_by, 128)
        if target == "revoked":
            sets["revoked_at"] = now
            sets["revoked_by"] = _bounded(actor, 128)
            sets["revoke_reason"] = _bounded(
                redact.redact_text(reason), 300) or "revoked"
        if target == "suspended":
            sets["suspended_at"] = now
        for k, v in (extra_sets or {}).items():
            sets[k] = v
        cols = ", ".join(f"{k}=?" for k in sorted(sets))
        self.db.execute(
            f"UPDATE federation_peers SET {cols} WHERE id=? AND org_id=?",
            tuple(sets[k] for k in sorted(sets)) + (peer_id, org_id))
        self._audit(action, object_type="federation_peer", object_id=peer_id,
                    org_id=org_id, actor=actor,
                    metadata={"from": cur, "to": target,
                              **({"reason": _bounded(reason, 120)}
                                 if reason else {})})
        return self.get(org_id, peer_id)

    def approve(self, org_id: str, peer_id: str, *, approved_by: str,
                actor: str = "api") -> dict:
        """pending -> active. Requires an approver identity DIFFERENT from
        the creator (separation of duties, §29). The federation.approve
        permission itself is enforced at the API/CLI boundary (admin+)."""
        self._acquire(f"peer:{org_id}", "peer")
        # the effective approver is always recorded: an explicit
        # approved_by, else the authenticated actor (never empty — the
        # trust record must identify WHO approved, §6)
        approver = _bounded(str(approved_by or actor or ""), 128)
        if not approver:
            raise errors.ValidationError("approver identity required")
        row = self._transition(org_id, peer_id, "active",
                               action="federation.peer.approved",
                               actor=actor, approved_by=approver,
                               require_different_actor=True)
        self._emit("", "federation.peer_approved", key=peer_id,
                   org_id=org_id, actor=actor)
        return row

    def suspend(self, org_id: str, peer_id: str, *, reason: str,
                actor: str = "api") -> dict:
        self._acquire(f"peer:{org_id}", "peer")
        if not str(reason or "").strip():
            raise errors.ValidationError("suspension reason required")
        return self._transition(org_id, peer_id, "suspended",
                                action="federation.peer.suspended",
                                actor=actor, reason=reason)

    def resume(self, org_id: str, peer_id: str, *, actor: str = "api") -> dict:
        self._acquire(f"peer:{org_id}", "peer")
        return self._transition(org_id, peer_id, "active",
                                action="federation.peer.resumed", actor=actor)

    def revoke(self, org_id: str, peer_id: str, *, reason: str,
               actor: str = "api") -> dict:
        """Terminal. Immediately blocks new exports/imports/bulk transfers
        (every path re-checks peer status). Previously imported local data
        is NOT erased — it stays governed by local retention/privacy rules
        (§31); deletion requires the explicit Phase-11 workflow."""
        self._acquire(f"peer:{org_id}", "peer")
        if not str(reason or "").strip():
            raise errors.ValidationError("revocation reason required")
        row = self._transition(org_id, peer_id, "revoked",
                               action="federation.peer.revoked",
                               actor=actor, reason=reason)
        self._emit("", "federation.peer_revoked", key=peer_id, org_id=org_id,
                   new_state={"reason": _bounded(reason, 80)}, actor=actor)
        return row

    def re_request(self, org_id: str, peer_id: str, *, expires_at: str = "",
                   actor: str = "api") -> dict:
        """expired -> pending: the ONLY renewal path. Requires a fresh
        approval; never expired -> active directly (§30)."""
        self._acquire(f"peer:{org_id}", "peer")
        exp = _valid_ts(expires_at, "expires_at")
        return self._transition(
            org_id, peer_id, "pending",
            action="federation.peer.re_requested", actor=actor,
            extra_sets={"expires_at": exp, "approved_by": ""})

    def sweep_expiry(self, org_id: str, *, now: str | None = None,
                     actor: str = "system") -> dict:
        """Deterministic expiry sweep: active/suspended peers past
        expires_at become `expired` (fail closed; no silent renewal)."""
        self._org(org_id)
        self._acquire(f"peer:{org_id}", "peer")
        now = now or _now()
        rows = self._q(
            "SELECT id FROM federation_peers WHERE org_id=? AND status IN "
            "('active','suspended') AND expires_at<>'' AND expires_at<=? "
            "ORDER BY id LIMIT ?", (org_id, now, MAX_LIST_LIMIT))
        expired = 0
        for r in rows:
            self._transition(org_id, r["id"], "expired",
                             action="federation.peer.expired", actor=actor,
                             reason="grant expired")
            self._emit("", "federation.peer_expired", key=r["id"],
                       org_id=org_id, actor=actor)
            expired += 1
        return {"expired": expired, "now": now}


# ===========================================================================
# Policies — the data-sharing contract (§7/§8/§30/§32)
# ===========================================================================
class FederationPolicyService(_Base):

    def _validate_rules(self, *, object_types, classifications, fields,
                        max_objects, explicit_sensitive) -> dict:
        otypes = tuple(dict.fromkeys(
            str(t).strip().lower() for t in (object_types or ())))
        if not otypes:
            raise errors.ValidationError(
                "policy requires at least one object type (no implicit "
                "'everything' policies)")
        for t in otypes:
            if t not in models.FEDERATION_OBJECT_TYPES:
                raise errors.ValidationError(f"unknown object type: {t!r}")
        classes = tuple(dict.fromkeys(
            str(c).strip().lower() for c in (classifications or ())))
        if not classes:
            raise errors.ValidationError(
                "policy requires an explicit classification allowlist")
        for c in classes:
            if c not in models.DATA_CLASSIFICATIONS:
                raise errors.ValidationError(f"unknown classification: {c!r}")
        sensitive = set(classes) & set(
            models.FEDERATION_SENSITIVE_BY_DEFAULT)
        if sensitive and not explicit_sensitive:
            raise errors.ValidationError(
                "policy_denied: classifications "
                f"{sorted(sensitive)} are never federated by default — an "
                "explicit acknowledgment (explicit_sensitive=True) is "
                "required, and even then raw secret material is never "
                "exportable")
        fmap: dict = {}
        for t, flist in dict(fields or {}).items():
            tl = str(t).strip().lower()
            if tl not in models.FEDERATION_OBJECT_TYPES:
                raise errors.ValidationError(f"unknown object type: {tl!r}")
            universe = set(FIELD_UNIVERSE.get(tl, ()))
            allowed = []
            for f in (flist or ()):
                fs = str(f).strip()
                if fs in universe and fs not in allowed:
                    allowed.append(fs)
            fmap[tl] = allowed          # unknown fields are dropped, never
            # widened: a policy can only NARROW the universe
        mo = _bound_int(max_objects, lo=1, hi=MAX_PACKAGE_OBJECTS,
                        default=1_000, label="max_objects")
        return {"object_types": list(otypes), "classifications":
                list(classes), "fields": fmap, "max_objects": mo,
                "explicit_sensitive": bool(explicit_sensitive)}

    def create(self, org_id: str, *, peer_id: str, name: str,
               project_id: str = "", object_types, classifications,
               fields: dict | None = None, max_objects: int = 1_000,
               expires_at: str = "", explicit_sensitive: bool = False,
               actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"policy:{org_id}", "policy")
        peer = self._one(
            "SELECT * FROM federation_peers WHERE id=? AND org_id=?",
            (peer_id, org_id))
        if not peer:
            raise errors.NotFoundError("federation peer not found")
        self._project_owned(org_id, project_id)
        nm = _bounded(redact.redact_text(str(name or "").strip()), 120)
        if len(nm) < 3:
            raise errors.ValidationError("policy name too short")
        rules = self._validate_rules(object_types=object_types,
                                     classifications=classifications,
                                     fields=fields, max_objects=max_objects,
                                     explicit_sensitive=explicit_sensitive)
        exp = _valid_ts(expires_at, "expires_at")
        now = _now()
        pol_id = models.stable_id(models.NS_FED_POLICY,
                                  f"{org_id}|{peer_id}|{nm}")
        try:
            self.db.execute(
                "INSERT INTO federation_policies (id, org_id, peer_id, "
                "project_id, name, allowed_object_types, "
                "allowed_classifications, allowed_fields, max_objects, "
                "explicit_sensitive, status, created_by, created_at, "
                "updated_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pol_id, org_id, peer_id, project_id or "", nm,
                 store.dumps(rules["object_types"]),
                 store.dumps(rules["classifications"]),
                 store.dumps(rules["fields"]), rules["max_objects"],
                 1 if rules["explicit_sensitive"] else 0, "active",
                 _bounded(actor, 128), now, now, exp))
        except sqlite3.IntegrityError:
            raise errors.DuplicateError(
                f"federation policy already exists: {nm}") from None
        metrics.inc("federation_policies_created")
        self._audit("federation.policy.created",
                    object_type="federation_policy", object_id=pol_id,
                    org_id=org_id, project_id=project_id, actor=actor,
                    metadata={"peer_id": peer_id,
                              "object_types": rules["object_types"],
                              "classifications": rules["classifications"],
                              "max_objects": rules["max_objects"]})
        self._emit(project_id, "federation.policy_created", key=pol_id,
                   org_id=org_id, actor=actor)
        return self.get(org_id, pol_id)

    def get(self, org_id: str, policy_id: str) -> dict:
        self._org(org_id)
        row = self._maybe(
            "SELECT * FROM federation_policies WHERE id=? AND org_id=?",
            (policy_id, org_id))
        if not row:
            raise errors.NotFoundError("federation policy not found")
        out = dict(row)
        out["allowed_object_types"] = store.loads(
            out.get("allowed_object_types", "[]"), default=[])
        out["allowed_classifications"] = store.loads(
            out.get("allowed_classifications", "[]"), default=[])
        out["allowed_fields"] = store.loads(
            out.get("allowed_fields", "{}"), default={})
        out["explicit_sensitive"] = bool(out.get("explicit_sensitive"))
        return out

    def list(self, org_id: str, *, peer_id: str = "", status: str = "",
             limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if peer_id:
            where.append("peer_id=?"); args.append(peer_id)
        if status:
            s = str(status).strip().lower()
            if s not in models.FEDERATION_POLICY_STATUSES:
                raise errors.ValidationError(f"unknown status: {s!r}")
            where.append("status=?"); args.append(s)
        total = int(self._one(
            "SELECT COUNT(*) n FROM federation_policies WHERE " +
            " AND ".join(where), args)["n"])
        rows = [self.get(org_id, r["id"]) for r in self._q(
            "SELECT id FROM federation_policies WHERE " +
            " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])]
        return {"total": total, "count": len(rows), "items": rows}

    def update(self, org_id: str, policy_id: str, *, name: str | None = None,
               object_types=None, classifications=None, fields=None,
               max_objects: int | None = None, expires_at: str | None = None,
               explicit_sensitive: bool = False, actor: str = "api") -> dict:
        """Update revalidates the FULL ruleset (existing values are the
        base for anything not supplied) — a policy can never drift into an
        invalid or implicitly widened state."""
        self._org(org_id)
        self._acquire(f"policy:{org_id}", "policy")
        cur = self.get(org_id, policy_id)
        if cur["status"] == "expired":
            raise errors.LifecycleError("expired policy is immutable; "
                                        "create a new one")
        otypes = list(object_types) if object_types is not None else \
            cur["allowed_object_types"]
        classes = list(classifications) if classifications is not None \
            else cur["allowed_classifications"]
        fmap = dict(fields) if fields is not None else cur["allowed_fields"]
        mo = max_objects if max_objects is not None else cur["max_objects"]
        ack = bool(explicit_sensitive) or (
            bool(cur["explicit_sensitive"]) and classifications is None)
        rules = self._validate_rules(object_types=otypes,
                                     classifications=classes, fields=fmap,
                                     max_objects=mo,
                                     explicit_sensitive=ack)
        nm = _bounded(redact.redact_text(str(name).strip()), 120) \
            if name is not None else cur["name"]
        if len(nm) < 3:
            raise errors.ValidationError("policy name too short")
        exp = _valid_ts(expires_at, "expires_at") \
            if expires_at is not None else str(cur.get("expires_at") or "")
        now = _now()
        self.db.execute(
            "UPDATE federation_policies SET name=?, allowed_object_types=?, "
            "allowed_classifications=?, allowed_fields=?, max_objects=?, "
            "explicit_sensitive=?, expires_at=?, updated_at=? WHERE id=? "
            "AND org_id=?",
            (nm, store.dumps(rules["object_types"]),
             store.dumps(rules["classifications"]),
             store.dumps(rules["fields"]), rules["max_objects"],
             1 if rules["explicit_sensitive"] else 0, exp, now, policy_id,
             org_id))
        self._audit("federation.policy.updated",
                    object_type="federation_policy", object_id=policy_id,
                    org_id=org_id, project_id=cur.get("project_id") or "",
                    actor=actor,
                    metadata={"object_types": rules["object_types"],
                              "classifications": rules["classifications"],
                              "max_objects": rules["max_objects"]})
        self._emit(cur.get("project_id") or "", "federation.policy_updated",
                   key=policy_id, org_id=org_id, actor=actor)
        return self.get(org_id, policy_id)

    def disable(self, org_id: str, policy_id: str, *, actor: str = "api") \
            -> dict:
        self._org(org_id)
        self._acquire(f"policy:{org_id}", "policy")
        cur = self.get(org_id, policy_id)
        if cur["status"] != "active":
            raise errors.LifecycleError(
                f"policy status {cur['status']} cannot be disabled")
        now = _now()
        self.db.execute(
            "UPDATE federation_policies SET status='disabled', "
            "disabled_at=?, updated_at=? WHERE id=? AND org_id=?",
            (now, now, policy_id, org_id))
        self._audit("federation.policy.disabled",
                    object_type="federation_policy", object_id=policy_id,
                    org_id=org_id, actor=actor, metadata={})
        return self.get(org_id, policy_id)

    def sweep_expiry(self, org_id: str, *, now: str | None = None,
                     actor: str = "system") -> dict:
        self._org(org_id)
        self._acquire(f"policy:{org_id}", "policy")
        now = now or _now()
        rows = self._q(
            "SELECT id, project_id FROM federation_policies WHERE org_id=? "
            "AND status='active' AND expires_at<>'' AND expires_at<=? "
            "ORDER BY id LIMIT ?", (org_id, now, MAX_LIST_LIMIT))
        expired = 0
        for r in rows:
            self.db.execute(
                "UPDATE federation_policies SET status='expired', "
                "updated_at=? WHERE id=? AND org_id=?",
                (now, r["id"], org_id))
            self._audit("federation.policy.expired",
                        object_type="federation_policy", object_id=r["id"],
                        org_id=org_id, project_id=r.get("project_id") or "",
                        actor=actor, metadata={})
            self._emit(r.get("project_id") or "", "federation.policy_expired",
                       key=r["id"], org_id=org_id, actor=actor)
            expired += 1
        return {"expired": expired, "now": now}


# ===========================================================================
# Packages — deterministic, minimized, integrity-protected (§9/§10/§11/§21)
# ===========================================================================
class FederationPackageService(_Base):

    def __init__(self, platform, *, limiter=None, gov=None):
        super().__init__(platform, limiter=limiter)
        self.gov = gov or _gov.SecurityGovernance(platform,
                                                  limiter=self.limiter)

    # ------------------------------------------------------------ policy
    def _active_peer(self, org_id: str, peer_id: str, *,
                     want_direction: str) -> dict:
        peer = self._maybe(
            "SELECT * FROM federation_peers WHERE id=? AND org_id=?",
            (peer_id, org_id))
        if not peer:
            raise errors.NotFoundError("federation peer not found")
        status = str(peer["status"])
        if status == "revoked":
            raise errors.AuthorizationError(
                "Forbidden: federation peer revoked — transfers blocked")
        if status == "expired":
            raise errors.AuthorizationError(
                "Forbidden: federation grant expired — re-request approval")
        if status != "active":
            raise errors.LifecycleError(
                f"peer is {status}; only an approved active peer may "
                "exchange packages")
        exp = str(peer.get("expires_at") or "")
        if exp and exp <= _now():
            raise errors.AuthorizationError(
                "Forbidden: federation grant expired — re-request approval")
        d = str(peer["direction"])
        if d != "bidirectional" and d != want_direction:
            raise errors.AuthorizationError(
                f"Forbidden: peer direction {d!r} does not allow "
                f"{want_direction} transfer")
        return dict(peer)

    def _active_policy(self, org_id: str, peer_id: str, project_id: str,
                       policy_id: str = "") -> dict:
        if policy_id:
            row = self._maybe(
                "SELECT * FROM federation_policies WHERE id=? AND org_id=? "
                "AND peer_id=?", (policy_id, org_id, peer_id))
            if not row:
                raise errors.NotFoundError("federation policy not found")
        else:
            rows = self._q(
                "SELECT * FROM federation_policies WHERE org_id=? AND "
                "peer_id=? AND status='active' ORDER BY created_at DESC, "
                "rowid DESC",
                (org_id, peer_id))
            row = dict(rows[0]) if rows else None
            if row is None:
                raise errors.NotFoundError(
                    "no active federation policy for this peer")
        pol = dict(row)
        if str(pol["status"]) == "expired" or (
                str(pol.get("expires_at") or "") and
                str(pol["expires_at"]) <= _now()):
            raise errors.AuthorizationError(
                "Forbidden: federation policy expired")
        if str(pol["status"]) != "active":
            raise errors.LifecycleError(
                f"policy is {pol['status']}; only active policies apply")
        scope = str(pol.get("project_id") or "")
        if scope and project_id and scope != project_id:
            raise errors.NotFoundError("policy not found for this project")
        if scope and not project_id:
            project_id = scope
        pol["allowed_object_types"] = store.loads(
            pol.get("allowed_object_types", "[]"), default=[])
        pol["allowed_classifications"] = store.loads(
            pol.get("allowed_classifications", "[]"), default=[])
        pol["allowed_fields"] = store.loads(pol.get("allowed_fields", "{}"),
                                            default={})
        pol["_scope_project"] = project_id
        return pol

    def _fields_for(self, pol: dict, otype: str) -> tuple:
        universe = tuple(FIELD_UNIVERSE.get(otype, ()))
        narrowed = (pol.get("allowed_fields") or {}).get(otype)
        if narrowed:
            return tuple(f for f in universe if f in set(narrowed))
        return universe

    # ------------------------------------------------------------ build
    def build(self, org_id: str, *, peer_id: str, policy_id: str = "",
              project_id: str = "", object_types=(), limit: int = 0,
              trust_mode: str = "integrity_verified",
              external_signature_ref: str = "",
              progress_cb=None, cancel_check=None,
              actor: str = "api") -> dict:
        """Build a federation evidence package: page query -> classify ->
        policy gate -> minimize -> redact -> append (bounded memory) ->
        canonicalize -> hash -> persist -> audit. Chunked with keyset
        paging; `progress_cb(frac)`/`cancel_check()` are optional bulk-job
        hooks (checkpoint + cooperative cancellation)."""
        org = self.svc.org_get(org_id)
        self._acquire(f"package:{org_id}", "package")
        peer = self._active_peer(org_id, peer_id, want_direction="outbound")
        pol = self._active_policy(org_id, peer_id, project_id, policy_id)
        eff_project = project_id or pol.get("_scope_project") or ""
        self._project_owned(org_id, eff_project)
        tm = str(trust_mode or "integrity_verified").strip().lower()
        if tm not in models.FEDERATION_TRUST_MODES:
            raise errors.ValidationError(f"unknown trust mode: {tm!r}")
        if tm == "unsigned":
            raise errors.ValidationError(
                "packages built by this platform always carry an integrity "
                "hash; 'unsigned' is only valid on inbound foreign "
                "envelopes (and is reported honestly)")
        ext_ref = _bounded(str(external_signature_ref or ""), 300)
        if ext_ref and tm != "externally_signed":
            tm = "externally_signed"
        requested = tuple(dict.fromkeys(
            str(t).strip().lower() for t in (object_types or ()))) or \
            tuple(pol["allowed_object_types"])
        for t in requested:
            if t not in pol["allowed_object_types"]:
                raise errors.ValidationError(
                    f"policy_denied: object type {t!r} is not allowed by "
                    "the federation policy")
        cap = _bound_int(limit or pol["max_objects"], lo=1,
                         hi=min(int(pol["max_objects"]), MAX_PACKAGE_OBJECTS),
                         default=min(int(pol["max_objects"]),
                                     MAX_PACKAGE_OBJECTS), label="limit")
        allowed_classes = set(pol["allowed_classifications"])
        objects: dict = {}
        counts: dict = {}
        denied = {"classification": 0, "privacy": 0, "shape_hits": 0}
        truncated = False
        total = 0
        for otype in requested:
            bucket, n, trunc = self._collect_type(
                org_id, otype, eff_project, allowed_classes, pol, cap - total,
                denied)
            if n:
                objects[otype] = bucket
                counts[otype] = n
                total += n
            truncated = truncated or trunc
            if progress_cb:
                progress_cb(min(0.95, (requested.index(otype) + 1) /
                                max(1, len(requested))))
            if cancel_check:
                cancel_check()
        top_cls = "public"
        top_rank = -1
        for bucket in objects.values():
            for o in bucket:
                r = models.CLASSIFICATION_RANK.get(
                    str(o.get("_classification") or "internal"), 1)
                if r > top_rank:
                    top_rank, top_cls = r, str(o.get("_classification"))
        if total == 0:
            top_cls = "public"
        core = {
            "schema_version": FED_SCHEMA,
            "source_organization": {"id": org.id, "name": org.name},
            "destination": {"org_id": str(peer["peer_org_id"]),
                            "peer_id": str(peer["id"])},
            "policy_reference": {"policy_id": str(pol["id"]),
                                 "peer_id": peer_id,
                                 "name": str(pol["name"])},
            "classification": top_cls,
            "provenance": {"platform": "SecuToolkit",
                           "canonicalization": CANONICALIZATION,
                           "created_by": _bounded(actor, 128)},
            "objects": objects,
            "counts": counts,
            "denied": denied,
            "truncated": bool(truncated),
        }
        canon = canonical_payload(core)
        data = canon.encode("utf-8")
        if len(data) > MAX_PACKAGE_BYTES:
            raise errors.ValidationError(
                "package too large (exceeds "
                f"{MAX_PACKAGE_BYTES // 1024 // 1024} MiB); narrow the "
                "policy scope or limit")
        digest = _sha256(canon)
        package_id = models.stable_id(
            models.NS_FED_PACKAGE,
            f"{org_id}|{peer_id}|{pol['id']}|{digest}")
        now = _now()
        ext_sig = {"mode": tm, "reference": ext_ref, "verified": False,
                   "note": "external signature recorded as a reference; "
                           "local code never fabricates verification "
                           "success"} if tm == "externally_signed" else None
        self.db.execute(
            "INSERT INTO federation_packages (id, org_id, project_id, "
            "peer_id, policy_id, destination_org_id, schema_version, "
            "classification, object_count, byte_size, integrity_algorithm, "
            "integrity_hash, trust_mode, external_signature_ref, payload, "
            "status, created_by, created_at, expires_at) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE "
            "SET byte_size=excluded.byte_size, object_count=excluded."
            "object_count, payload=excluded.payload",
            (package_id, org_id, eff_project, peer_id, str(pol["id"]),
             str(peer["peer_org_id"]), FED_SCHEMA, top_cls, total, len(data),
             "sha256", digest, tm, ext_ref, canon, "created",
             _bounded(actor, 128), now,
             _iso(_epoch(now) + _gov.EXPORT_TTL_DAYS * 86400)))
        self._audit("federation.package.created",
                    object_type="federation_package", object_id=package_id,
                    org_id=org_id, project_id=eff_project, actor=actor,
                    metadata={"peer_id": peer_id, "policy_id": pol["id"],
                              "objects": total, "bytes": len(data),
                              "classification": top_cls,
                              "denied": sum(denied.values()),
                              "sha256": digest[:16]})
        self._emit(eff_project, "federation.package_created",
                   key=package_id, org_id=org_id,
                   new_state={"objects": total, "types": sorted(counts)},
                   actor=actor)
        metrics.inc("federation_packages_created")
        envelope = self._envelope(package_id, core, digest, tm, ext_sig, now)
        if progress_cb:
            progress_cb(1.0)
        return {"package_id": package_id, "integrity": digest,
                "object_count": total, "byte_size": len(data),
                "counts": counts, "denied": denied,
                "truncated": bool(truncated), "classification": top_cls,
                "trust_mode": tm, "envelope": envelope}

    def _envelope(self, package_id: str, core: dict, digest: str,
                  trust_mode: str, ext_sig, created_at: str) -> dict:
        env = json.loads(json.dumps(core, sort_keys=True,
                                    ensure_ascii=False, default=str))
        env["package_id"] = package_id
        env["created_at"] = created_at
        env["integrity"] = {"algorithm": "sha256", "hash": digest,
                            "canonicalization": CANONICALIZATION,
                            "schema_version": FED_SCHEMA}
        env["trust_mode"] = trust_mode
        if ext_sig is not None:
            env["external_signature"] = ext_sig
        return env

    def _collect_type(self, org_id: str, otype: str, project_id: str,
                      allowed_classes: set, pol: dict, budget: int,
                      denied: dict) -> tuple:
        """Keyset-paged collection for ONE object type: query page ->
        classification gate -> privacy gate -> field minimization ->
        redaction -> shape scrub -> append. Bounded by `budget`."""
        sql_t, proj_col = _EXPORT_SQL[otype]
        proj_filter = ""
        args_head = [org_id]
        if proj_col and project_id and otype != "organization":
            # proj_col is the table-qualified project column declared by the
            # export spec (WHERE clauses reference real columns, never
            # SELECT aliases)
            proj_filter = f" AND {proj_col}=?"
            args_head.append(project_id)
        sql = sql_t.replace("{proj}", proj_filter)
        if otype == "organization":
            args_head = [org_id]
        fields = self._fields_for(pol, otype)
        page = min(BULK_PAGE_SIZE, max(1, budget))
        out, last, n = [], "", 0
        truncated = False
        while n < budget:
            rows = self._q(sql, args_head + [last, page])
            if not rows:
                break
            for row in rows:
                last = str(row["id"])
                if n >= budget:
                    truncated = True
                    break
                obj = self._minimize_row(org_id, otype, dict(row), fields,
                                         allowed_classes, denied)
                if obj is not None:
                    out.append(obj)
                    n += 1
            if len(rows) < page:
                break
        if not truncated and otype != "organization":
            extra = self._q(sql, args_head + [last, 1])
            if extra and n >= budget:
                truncated = True
        return out, n, truncated

    def _minimize_row(self, org_id: str, otype: str, row: dict,
                      fields: tuple, allowed_classes: set,
                      denied: dict) -> dict | None:
        """One row -> one package object (or None when denied). Pipeline:
        classification -> policy gate -> privacy gate -> minimization ->
        redaction -> secret-shape scrub. Never returns raw secrets."""
        oid = str(row.get("id") or "")
        proj = str(row.get("project_id") or "")
        eff = self.gov.classification.effective(org_id, otype, oid,
                                                project_id=proj)
        cls = str(eff.get("effective") or "internal")
        if cls not in allowed_classes:
            denied["classification"] += 1
            return None
        obj = {}
        for f in fields:
            if f == "id":
                obj["id"] = _bounded(oid, 64)
                continue
            v = row.get(f)
            if otype == "finding" and f in ("parameter", "endpoint"):
                raw = store.loads(row.get("raw", "{}"), default={}) \
                    if isinstance(row.get("raw"), str) else \
                    (row.get("raw") or {})
                v = raw.get(f, "")
            if v is None:
                v = ""
            if isinstance(v, (dict, list)):
                v = json.dumps(v, sort_keys=True, ensure_ascii=False,
                               default=str)
            s = str(v)
            if len(s) > MAX_FIELD_VALUE:
                s = s[:MAX_FIELD_VALUE]
            obj[f] = s
        # evidence rows carry their source finding for import-side mapping
        extra_prov = {}
        if otype == "evidence":
            extra_prov["source_finding_id"] = _bounded(
                str(row.get("finding_id") or ""), 64)
        prov_text = json.dumps(obj, sort_keys=True, ensure_ascii=False,
                               default=str)
        if _PRIVACY_MARKER in prov_text:
            denied["privacy"] += 1          # privacy restriction wins (§32)
            return None
        obj = redact.redact(obj)
        scrubbed = json.dumps(obj, sort_keys=True, ensure_ascii=False,
                              default=str)
        if _PRIVACY_MARKER in scrubbed:
            denied["privacy"] += 1
            return None
        if _gov.detect_secret_shapes(scrubbed, sample=0).get("hits"):
            # the redactor already replaced known shapes; a residual hit
            # means the object cannot be shared safely — exclude it (never
            # export raw secret material, §7)
            denied["shape_hits"] += 1
            return None
        obj["_classification"] = cls
        obj["_provenance"] = {
            "source_org_id": org_id,
            "source_project_id": _bounded(proj, 64),
            "source_object_id": _bounded(oid, 64),
            "object_type": otype,
            **extra_prov,
        }
        return obj

    # ------------------------------------------------------------ reads
    def serialize(self, org_id: str, package_id: str, *,
                  actor: str = "api") -> dict:
        """Return the transferable envelope for a stored package (the
        'export' action). Payload never contains secret material — it was
        minimized + redacted + scrubbed at build time."""
        self._org(org_id)
        self._acquire(f"package:{org_id}", "package")
        row = self._maybe(
            "SELECT * FROM federation_packages WHERE id=? AND org_id=?",
            (package_id, org_id))
        if not row:
            raise errors.NotFoundError("federation package not found")
        core = store.loads(row["payload"], default={})
        ext_sig = None
        if str(row["trust_mode"]) == "externally_signed":
            ext_sig = {"mode": "externally_signed",
                       "reference": str(row["external_signature_ref"] or ""),
                       "verified": False,
                       "note": "external signature recorded as a reference; "
                               "local code never fabricates verification "
                               "success"}
        env = self._envelope(str(row["id"]), core,
                             str(row["integrity_hash"]),
                             str(row["trust_mode"]), ext_sig,
                             str(row["created_at"]))
        self._audit("federation.package.exported",
                    object_type="federation_package", object_id=package_id,
                    org_id=org_id, project_id=row.get("project_id") or "",
                    actor=actor,
                    metadata={"bytes": int(row["byte_size"] or 0),
                              "objects": int(row["object_count"] or 0),
                              "sha256": str(row["integrity_hash"])[:16]})
        self._emit(row.get("project_id") or "", "federation.package_exported",
                   key=package_id, org_id=org_id, actor=actor)
        return env

    def verify(self, org_id: str, package_id: str) -> dict:
        """DB-backed verification: recompute the hash from the STORED
        payload and compare with the stored integrity value (detects
        storage tampering)."""
        self._org(org_id)
        row = self._maybe(
            "SELECT * FROM federation_packages WHERE id=? AND org_id=?",
            (package_id, org_id))
        if not row:
            raise errors.NotFoundError("federation package not found")
        core = store.loads(row["payload"], default={})
        actual = _sha256(canonical_payload(core))
        valid = hmac.compare_digest(actual, str(row["integrity_hash"]))
        if not valid:
            metrics.inc("federation_integrity_failures")
            self._audit("federation.integrity_failure",
                        object_type="federation_package",
                        object_id=package_id, org_id=org_id,
                        project_id=row.get("project_id") or "",
                        actor="system",
                        metadata={"stage": "stored-verification"})
        return {"valid": valid, "algorithm": "sha256",
                "expected": str(row["integrity_hash"]), "actual": actual,
                "schema_version": str(row["schema_version"]),
                "trust_mode": str(row["trust_mode"])}

    def get(self, org_id: str, package_id: str) -> dict:
        """Metadata only — the payload is never returned by get/list."""
        self._org(org_id)
        row = self._maybe(
            "SELECT id, org_id, project_id, peer_id, policy_id, "
            "destination_org_id, schema_version, classification, "
            "object_count, byte_size, integrity_algorithm, integrity_hash, "
            "trust_mode, external_signature_ref, status, created_by, "
            "created_at, expires_at FROM federation_packages WHERE id=? "
            "AND org_id=?", (package_id, org_id))
        if not row:
            raise errors.NotFoundError("federation package not found")
        return dict(row)

    def list(self, org_id: str, *, peer_id: str = "", limit: int = 50,
             offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit, default=50)
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if peer_id:
            where.append("peer_id=?"); args.append(peer_id)
        total = int(self._one(
            "SELECT COUNT(*) n FROM federation_packages WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            "SELECT id, project_id, peer_id, destination_org_id, "
            "classification, object_count, byte_size, trust_mode, status, "
            "integrity_hash, created_by, created_at FROM federation_packages "
            "WHERE " + " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        for r in rows:
            r["integrity_hash"] = str(r["integrity_hash"])[:16]
        return {"total": total, "count": len(rows), "items": rows}


# ===========================================================================
# Imports — validate everything, trust nothing (§12/§13/§14/§15/§16/§17)
# ===========================================================================
class FederationImportService(_Base):

    IMPORT_ERROR_FINDING_RULES = {
        "integrity_mismatch": ("fed-integrity-mismatch", "High"),
        "policy_field_violation": ("fed-field-policy-violation", "Medium"),
    }

    def import_envelope(self, org_id: str, *, envelope,
                        target_project_id: str, peer_id: str = "",
                        collision: str = "skip", actor: str = "api",
                        progress_cb=None, cancel_check=None) -> dict:
        """Full inbound validation chain (§12) then provenance-preserving
        merge through the EXISTING finding/asset/evidence/case/IOC systems.
        Any failed validation stops the import safely (fail closed) and is
        recorded as a rejection."""
        self._org(org_id)
        self._acquire(f"import:{org_id}", "import")
        proj = self.svc.project_require(target_project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        strategy = str(collision or "skip").strip().lower()
        if strategy not in models.FEDERATION_COLLISION_STRATEGIES:
            raise errors.ValidationError(
                f"unknown collision strategy: {collision!r}")
        # 1. syntax + bounds (JSON only — never pickle/yaml/eval, §26)
        if isinstance(envelope, (bytes, bytearray)):
            envelope = bytes(envelope).decode("utf-8", "strict") \
                if len(bytes(envelope)) <= MAX_IMPORT_BYTES else None
            if envelope is None:
                raise errors.ValidationError("package_too_large")
        if isinstance(envelope, str):
            if len(envelope.encode("utf-8")) > MAX_IMPORT_BYTES:
                raise errors.ValidationError("package_too_large")
            try:
                env = json.loads(envelope)
            except (ValueError, UnicodeDecodeError) as e:
                raise errors.ValidationError(
                    f"package_unparsable: {e}") from e
        else:
            env = json.loads(json.dumps(envelope, sort_keys=True,
                                        ensure_ascii=False, default=str))
        _check_structure(env)
        if not isinstance(env, dict):
            raise errors.ValidationError("package_not_object")
        missing = [k for k in _REQUIRED_ENVELOPE_KEYS if k not in env]
        if missing:
            raise errors.ValidationError(
                f"package_keys_missing: {sorted(missing)}")
        # 2. schema version
        if str(env.get("schema_version")) != FED_SCHEMA:
            raise self._reject(
                org_id, env, "", peer_id, target_project_id, strategy,
                actor, "schema_mismatch: expected "
                f"{FED_SCHEMA!r}, got {str(env.get('schema_version'))[:40]!r}")
        # 3. integrity (recompute + constant-time compare)
        ver = verify_envelope(env)
        digest = str((env.get("integrity") or {}).get("hash") or "")
        if not ver["valid"]:
            # error stays a bare, stable reason code: reporting counts
            # integrity failures with `error LIKE 'integrity_%'` and the
            # finding rule lookup keys on the code before the first ':'
            err = str(ver["error"] or "integrity_mismatch")
            if not err.startswith("integrity_"):
                err = f"integrity_{err}"
            raise self._reject(org_id, env, digest, peer_id,
                               target_project_id, strategy, actor, err,
                               integrity_failure=True)
        # 4-7. grant / sender / destination / expiration
        src = env.get("source_organization") or {}
        dest = env.get("destination") or {}
        src_org = _bounded(str(src.get("id") or ""), 64)
        if not src_org:
            raise self._reject(org_id, env, digest, peer_id,
                               target_project_id, strategy, actor,
                               "sender_missing")
        if _bounded(str(dest.get("org_id") or ""), 64) != org_id:
            raise self._reject(org_id, env, digest, peer_id,
                               target_project_id, strategy, actor,
                               "destination_mismatch", src_org=src_org)
        peer = self._resolve_peer(org_id, peer_id, src_org)
        if peer is None:
            raise self._reject(org_id, env, digest, "", target_project_id,
                               strategy, actor, "grant_missing",
                               src_org=src_org)
        pid = str(peer["id"])
        status = str(peer["status"])
        if status == "revoked":
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor, "peer_revoked",
                               src_org=src_org)
        exp = str(peer.get("expires_at") or "")
        if status == "expired" or (exp and exp <= _now()):
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor, "grant_expired",
                               src_org=src_org)
        if status != "active":
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor, f"grant_inactive:{status}",
                               src_org=src_org)
        d = str(peer["direction"])
        if d not in ("inbound", "bidirectional"):
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor, "direction_denied",
                               src_org=src_org)
        pol = self._inbound_policy(org_id, pid)
        if pol is None:
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor, "policy_missing",
                               src_org=src_org)
        if str(pol["status"]) != "active" or (
                str(pol.get("expires_at") or "") and
                str(pol["expires_at"]) <= _now()):
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor, "policy_expired",
                               src_org=src_org)
        # 8. classification policy (package level AND per object)
        allowed_classes = set(pol["allowed_classifications"])
        if str(env.get("classification")) not in allowed_classes:
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor,
                               "policy_denied:classification:" +
                               _bounded(str(env.get("classification")), 40),
                               src_org=src_org)
        objects = env.get("objects") or {}
        if not isinstance(objects, dict):
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor, "objects_invalid",
                               src_org=src_org)
        # 9. object limits
        total = sum(len(v) for v in objects.values()
                    if isinstance(v, list))
        if total > min(int(pol["max_objects"]), MAX_PACKAGE_OBJECTS):
            raise self._reject(org_id, env, digest, pid, target_project_id,
                               strategy, actor, "limit_exceeded",
                               src_org=src_org)
        # 10. field policy + per-object classification (defense in depth —
        # a tampered package with extra fields or smuggled classifications
        # is rejected even though its hash still matches)
        for otype, bucket in objects.items():
            if not isinstance(bucket, list):
                raise self._reject(org_id, env, digest, pid,
                                   target_project_id, strategy, actor,
                                   "objects_invalid", src_org=src_org)
            if otype not in models.FEDERATION_OBJECT_TYPES:
                raise self._reject(org_id, env, digest, pid,
                                   target_project_id, strategy, actor,
                                   f"policy_denied:type:{otype}"[:120],
                                   src_org=src_org)
            if otype not in pol["allowed_object_types"]:
                raise self._reject(org_id, env, digest, pid,
                                   target_project_id, strategy, actor,
                                   f"policy_denied:type:{otype}"[:120],
                                   src_org=src_org)
            allowed_fields = set(self._fields_for(pol, otype)) | \
                set(FIELD_UNIVERSE[otype])
            for obj in bucket:
                if not isinstance(obj, dict):
                    raise self._reject(org_id, env, digest, pid,
                                       target_project_id, strategy, actor,
                                       "object_malformed", src_org=src_org)
                # 12. provenance gate: every object must identify its
                # source org + source object (fail closed, §12/§13)
                prov = obj.get("_provenance")
                if not isinstance(prov, dict) or \
                        not str(prov.get("source_org_id") or "").strip() or \
                        not str(prov.get("source_object_id") or "").strip():
                    raise self._reject(
                        org_id, env, digest, pid, target_project_id,
                        strategy, actor, f"provenance_invalid:{otype}"[:120],
                        src_org=src_org)
                extra = set(obj) - allowed_fields - set(_STRUCTURAL_KEYS)
                if extra:
                    raise self._reject(
                        org_id, env, digest, pid, target_project_id,
                        strategy, actor,
                        "policy_field_violation:" +
                        ",".join(sorted(extra)[:5])[:120],
                        src_org=src_org, project_id=target_project_id)
                if str(obj.get("_classification") or
                       "internal") not in allowed_classes:
                    raise self._reject(org_id, env, digest, pid,
                                       target_project_id, strategy, actor,
                                       "policy_denied:object_classification",
                                       src_org=src_org)
        # importable-type gate (export-only types are an explicit
        # rejection, never a silent drop)
        for otype in objects:
            if objects[otype] and otype not in \
                    models.FEDERATION_IMPORTABLE_TYPES:
                raise self._reject(org_id, env, digest, pid,
                                   target_project_id, strategy, actor,
                                   f"import_unsupported:{otype}"[:120],
                                   src_org=src_org)
        # 11/12. idempotency claim + tenant mapping + provenance, then apply
        import_id = models.stable_id(
            models.NS_FED_IMPORT, f"{org_id}|{digest}")
        existing = self._maybe(
            "SELECT * FROM federation_imports WHERE org_id=? AND "
            "package_hash=?", (org_id, digest))
        if existing:
            # UNIQUE(org_id, package_hash) is the idempotency claim: a
            # terminal row is reported as-is and the objects are NEVER
            # re-applied (a rejected/failed row is re-reported so the caller
            # sees the real outcome, not a silent success)
            st = str(existing["status"])
            detail = store.loads(existing["detail_json"], default={})
            if st == "in_progress":
                raise errors.DuplicateError(
                    "another import of this package is in progress for this "
                    "organization; retry after it completes")
            err = str(existing["error"] or "")
            if st != "completed":
                raise errors.ValidationError(
                    f"import_rejected: {err or st or 'previous attempt'}")
            return {"duplicate": True, "import_id": str(existing["id"]),
                    "status": st, "package_hash": digest,
                    "object_count": int(existing["object_count"] or 0),
                    "imported": int(existing["imported_count"] or 0),
                    "skipped": int(existing["skipped_count"] or 0),
                    "linked": int(existing["linked_count"] or 0),
                    "detail": detail, "error": err}
        now = _now()
        try:
            self.db.execute(
                "INSERT INTO federation_imports (id, org_id, package_id, "
                "package_hash, source_org_id, peer_id, policy_id, "
                "target_project_id, status, collision_strategy, "
                "object_count, imported_count, skipped_count, linked_count, "
                "detail_json, error, created_by, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,'in_progress',?,?,0,0,0,'{}','',?,"
                "?,?)",
                (import_id, org_id, _bounded(str(env.get("package_id") or
                                              ""), 64), digest, src_org, pid,
                 str(pol["id"]), target_project_id, strategy, total,
                 _bounded(actor, 128), now, now))
        except sqlite3.IntegrityError as e:
            # lost the claim race: report the winner's terminal outcome
            # instead of re-applying the package (§14 idempotency)
            winner = self._maybe(
                "SELECT * FROM federation_imports WHERE org_id=? AND "
                "package_hash=?", (org_id, digest))
            if winner is None:
                # a different constraint failed (not the idempotency claim)
                # — surface it instead of masking it as a duplicate
                raise errors.PersistenceError(
                    f"import claim could not be recorded: {e}") from e
            st = str(winner.get("status") or "")
            if st in ("in_progress", ""):
                raise errors.DuplicateError(
                    "another import of this package is in progress for this "
                    "organization; retry after it completes") from e
            err = str(winner.get("error") or "")
            if st != "completed":
                raise errors.ValidationError(
                    f"import_rejected: {err or st or 'previous attempt'}")
            return {"duplicate": True,
                    "import_id": str(winner.get("id") or ""), "status": st,
                    "package_hash": digest,
                    "object_count": int(winner.get("object_count") or 0),
                    "imported": int(winner.get("imported_count") or 0),
                    "skipped": int(winner.get("skipped_count") or 0),
                    "linked": int(winner.get("linked_count") or 0),
                    "detail": store.loads(
                        str(winner.get("detail_json") or "{}"), default={})}
        try:
            res = self._apply(org_id, env, objects, digest, import_id, pid,
                              str(pol["id"]), src_org, target_project_id,
                              strategy, actor, progress_cb, cancel_check)
        except errors.WorkerStopped:
            self._finalize_import(import_id, org_id, "failed",
                                  counts=None, detail={}, error="cancelled",
                                  actor=actor)
            raise
        except errors.DuplicateError as e:
            # a collision under strategy=reject is a POLICY outcome, not an
            # engine failure: the import is recorded as rejected (fail
            # closed, nothing silently overwritten) and re-raised as a
            # ValidationError so callers see `import_rejected:`
            self._finalize_import(import_id, org_id, "rejected", counts=None,
                                  detail={}, error=_bounded(str(e), 200),
                                  actor=actor)
            raise errors.ValidationError(
                f"import_rejected: {e}") from e
        except errors.SecurityToolkitError as e:
            self._finalize_import(import_id, org_id, "failed", counts=None,
                                  detail={}, error=_bounded(str(e), 200),
                                  actor=actor)
            raise
        self._audit("federation.package.imported",
                    object_type="federation_import", object_id=import_id,
                    org_id=org_id, project_id=target_project_id, actor=actor,
                    metadata={"package_hash": digest[:16],
                              "source_org_id": src_org, "peer_id": pid,
                              "objects": total,
                              "imported": res["imported"],
                              "skipped": res["skipped"],
                              "strategy": strategy})
        self._emit(target_project_id, "federation.package_imported",
                   key=import_id, org_id=org_id,
                   new_state={"imported": res["imported"],
                              "skipped": res["skipped"]}, actor=actor)
        metrics.inc("federation_packages_imported")
        return {"duplicate": False, "import_id": import_id,
                "status": "completed", "package_hash": digest,
                "object_count": total, **res}

    # ------------------------------------------------------------ helpers
    def _fields_for(self, pol: dict, otype: str) -> tuple:
        universe = tuple(FIELD_UNIVERSE.get(otype, ()))
        narrowed = (pol.get("allowed_fields") or {}).get(otype)
        if narrowed:
            return tuple(f for f in universe if f in set(narrowed))
        return universe

    def _resolve_peer(self, org_id: str, peer_id: str, src_org: str):
        if peer_id:
            return self._maybe(
                "SELECT * FROM federation_peers WHERE id=? AND org_id=?",
                (peer_id, org_id))
        return self._maybe(
            "SELECT * FROM federation_peers WHERE org_id=? AND "
            "peer_org_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (org_id, src_org))

    def _inbound_policy(self, org_id: str, peer_id: str):
        rows = self._q(
            "SELECT * FROM federation_policies WHERE org_id=? AND peer_id=? "
            "ORDER BY created_at DESC, rowid DESC", (org_id, peer_id))
        if not rows:
            return None
        pol = dict(rows[0])
        pol["allowed_object_types"] = store.loads(
            pol.get("allowed_object_types", "[]"), default=[])
        pol["allowed_classifications"] = store.loads(
            pol.get("allowed_classifications", "[]"), default=[])
        pol["allowed_fields"] = store.loads(pol.get("allowed_fields", "{}"),
                                            default={})
        return pol

    def _reject(self, org_id: str, env: dict, digest: str, peer_id: str,
                target_project_id: str, strategy: str, actor: str,
                error: str, *, src_org: str = "",
                integrity_failure: bool = False,
                project_id: str = "") -> errors.ValidationError:
        """Record a rejection (bounded, audited, event-emitted) and return
        the error to raise — the caller does `raise self._reject(...)` so
        the import ALWAYS stops. Repeated rejections and integrity failures
        become real platform findings (existing dedup — never duplicated)."""
        now = _now()
        err_b = _bounded(redact.redact_text(error), 200)
        hash_b = _bounded(digest, 64)
        import_id = models.stable_id(
            models.NS_FED_IMPORT, f"{org_id}|{hash_b or err_b}|{now[:10]}")
        try:
            self.db.execute(
                "INSERT INTO federation_imports (id, org_id, package_id, "
                "package_hash, source_org_id, peer_id, policy_id, "
                "target_project_id, status, collision_strategy, "
                "object_count, imported_count, skipped_count, linked_count, "
                "detail_json, error, created_by, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?, 'rejected',?,0,0,0,0,'{}',?,?,?,?) "
                "ON CONFLICT(org_id, package_hash) DO NOTHING",
                (import_id, org_id,
                 _bounded(str((env or {}).get("package_id") or ""), 64),
                 hash_b, src_org, peer_id, "", target_project_id, strategy,
                 err_b, _bounded(actor, 128), now, now))
        except sqlite3.IntegrityError:
            pass  # UNIQUE(org_id, package_hash): first rejection is the
            # record of reference; this path is only reached without a
            # hash (pre-integrity rejections are keyed by error+date)
        self._audit("federation.package.rejected",
                    object_type="federation_import", object_id=import_id,
                    org_id=org_id, project_id=target_project_id, actor=actor,
                    metadata={"error": err_b[:120], "peer_id": peer_id,
                              "package_hash": hash_b[:16]})
        if integrity_failure:
            self._audit("federation.integrity_failure",
                        object_type="federation_import",
                        object_id=import_id, org_id=org_id,
                        project_id=target_project_id, actor="system",
                        metadata={"package_hash": hash_b[:16]})
        self._emit(target_project_id or project_id,
                   "federation.package_rejected", key=import_id,
                   org_id=org_id, new_state={"error": err_b[:80]},
                   actor=actor)
        if integrity_failure:
            self._emit(target_project_id or project_id,
                       "federation.integrity_failure", key=import_id,
                       org_id=org_id, actor=actor)
        metrics.inc("federation_imports_rejected")
        # security-operations integration (§36): anomalies become findings
        proj_for_finding = target_project_id or project_id
        if proj_for_finding:
            rule = self.IMPORT_ERROR_FINDING_RULES.get(
                err_b.split(":", 1)[0])
            if rule:
                self._security_finding(
                    proj_for_finding, rule_id=rule[0],
                    title=f"Federation import anomaly: {err_b.split(':', 1)[0]}",
                    description=f"A federation package import was rejected "
                                f"({err_b[:160]}). Source org: "
                                f"{src_org or 'unknown'}.",
                    severity=rule[1],
                    raw={"package_hash": hash_b[:16], "error": err_b[:80]})
            if integrity_failure:
                metrics.inc("federation_integrity_failures")
            elif peer_id:
                recent = self._one(
                    "SELECT COUNT(*) n FROM federation_imports WHERE "
                    "org_id=? AND peer_id=? AND status='rejected' AND "
                    "created_at>=?",
                    (org_id, peer_id, _iso(_epoch(now) - 86400)))
                if int(recent["n"]) >= MAX_REJECTED_FOR_FINDING:
                    self._security_finding(
                        proj_for_finding,
                        rule_id="fed-repeated-rejection",
                        title="Repeated federation import rejections",
                        description=f"{int(recent['n'])} federation imports "
                                    "were rejected for this peer within 24h.",
                        severity="Medium",
                        raw={"peer_id": peer_id,
                             "rejections_24h": int(recent["n"])})
        return errors.ValidationError(f"import_rejected: {err_b}")

    def _finalize_import(self, import_id: str, org_id: str, status: str, *,
                         counts, detail: dict, error: str,
                         actor: str) -> None:
        now = _now()
        if counts:
            self.db.execute(
                "UPDATE federation_imports SET status=?, imported_count=?, "
                "skipped_count=?, linked_count=?, detail_json=?, error=?, "
                "updated_at=? WHERE id=? AND org_id=?",
                (status, counts[0], counts[1], counts[2],
                 store.dumps(detail), _bounded(error, 200), now, import_id,
                 org_id))
        else:
            self.db.execute(
                "UPDATE federation_imports SET status=?, detail_json=?, "
                "error=?, updated_at=? WHERE id=? AND org_id=?",
                (status, store.dumps(detail), _bounded(error, 200), now,
                 import_id, org_id))

    # ------------------------------------------------------------ apply
    def _apply(self, org_id: str, env: dict, objects: dict, digest: str,
               import_id: str, peer_id: str, policy_id: str, src_org: str,
               target_project_id: str, strategy: str, actor: str,
               progress_cb, cancel_check) -> dict:
        """Two-phase merge: assets first (findings fingerprint against the
        LOCAL asset identity), then findings (+their evidence), then cases,
        then threat-intel matches. Every imported object carries full
        provenance (§13). Repeated imports are idempotent through the
        EXISTING Phase-4 fingerprint/dedup pipeline (§15)."""
        imported = skipped = linked = 0
        invalid = 0
        detail: dict = {"by_type": {}, "collisions": {}}
        pkg_id = _bounded(str(env.get("package_id") or ""), 64)
        now = _now()
        base_prov = {
            "source_org_id": src_org,
            "package_id": pkg_id,
            "package_hash": digest,
            "import_id": import_id,
            "imported_at": now,
            "policy_id": policy_id,
            "peer_id": peer_id,
        }
        total = sum(len(v) for v in objects.values() if isinstance(v, list))
        done = 0
        asset_map: dict = {}
        finding_map: dict = {}

        def _bump(kind: str) -> None:
            d = detail["collisions"]
            d[kind] = int(d.get(kind, 0)) + 1

        def _checkpoint() -> None:
            if cancel_check:
                cancel_check()
            if progress_cb and total:
                progress_cb(min(0.99, done / total))

        # ---------------------------------------------------------- assets
        for obj in objects.get("asset", []):
            done += 1
            prov = dict(base_prov)
            prov["source_object_id"] = str((obj.get("_provenance") or {})
                                           .get("source_object_id") or "")
            prov["source_project_id"] = str(
                (obj.get("_provenance") or {}).get("source_project_id") or "")
            atype = _bounded(str(obj.get("asset_type") or ""), 40)
            value = _bounded(str(obj.get("value") or ""), 300)
            if not atype or not value:
                invalid += 1
                continue
            existing = self._maybe(
                "SELECT id FROM assets WHERE project_id=? AND asset_type=? "
                "AND value=?", (target_project_id, atype, value))
            if existing:
                if strategy == "skip":
                    skipped += 1; _bump("asset_skip")
                elif strategy == "link":
                    linked += 1; _bump("asset_link")
                elif strategy == "merge_metadata":
                    meta = store.loads(self._one(
                        "SELECT metadata FROM assets WHERE id=?",
                        (existing["id"],))["metadata"], default={})
                    meta["federation"] = prov
                    self.db.execute(
                        "UPDATE assets SET metadata=?, display=COALESCE("
                        "NULLIF(display,''), ?) WHERE id=?",
                        (store.dumps(meta),
                         _bounded(str(obj.get("display") or ""), 200),
                         existing["id"]))
                    imported += 1; _bump("asset_merge")
                else:  # reject
                    raise errors.DuplicateError(
                        f"collision_reject: asset {value[:80]!r} already "
                        "exists locally")
                asset_map[prov["source_object_id"]] = str(existing["id"])
            else:
                a = self.svc.asset_add(target_project_id, atype, value,
                                       {"federation": prov},
                                       _bounded(str(obj.get("display") or
                                                    ""), 200))
                asset_map[prov["source_object_id"]] = a.id
                imported += 1
            _checkpoint()
        detail["by_type"]["asset"] = len(objects.get("asset", []))

        # -------------------------------------------------------- findings
        findings_objs = objects.get("finding", [])
        evidence_by_source: dict = {}
        for ev in objects.get("evidence", []):
            src_fid = str((ev.get("_provenance") or {})
                          .get("source_finding_id") or "")
            evidence_by_source.setdefault(src_fid, []).append(ev)
        for obj in findings_objs:
            done += 1
            prov = dict(base_prov)
            prov["source_object_id"] = str((obj.get("_provenance") or {})
                                           .get("source_object_id") or "")
            prov["source_project_id"] = str(
                (obj.get("_provenance") or {}).get("source_project_id") or "")
            sev = str(obj.get("severity") or "Info")
            conf = str(obj.get("confidence") or "medium")
            if sev not in models.SEVERITIES or conf not in models.CONFIDENCE:
                invalid += 1
                continue
            asset_local = ""
            a_type = str(obj.get("asset_type") or "")
            a_value = str(obj.get("asset_value") or "")
            if a_type and a_value:
                row = self._maybe(
                    "SELECT id FROM assets WHERE project_id=? AND "
                    "asset_type=? AND value=?",
                    (target_project_id, _bounded(a_type, 40),
                     _bounded(a_value, 300)))
                if row:
                    asset_local = str(row["id"])
            raw = {"parameter": _bounded(str(obj.get("parameter") or ""),
                                         200),
                   "endpoint": _bounded(str(obj.get("endpoint") or ""), 300),
                   "_federation": prov}
            f = models.Finding(
                scan_id=self._fed_scan(target_project_id),
                project_id=target_project_id,
                asset_id=asset_local,
                title=_bounded(str(obj.get("title") or
                                   "Federated finding"), 200),
                description=_bounded(str(obj.get("description") or ""), 2000),
                severity=sev, confidence=conf,
                category=_bounded(str(obj.get("category") or "other"), 60),
                source="federation",
                rule_id=_bounded(str(obj.get("rule_id") or ""), 64),
                template_id=_bounded(str(obj.get("template_id") or ""), 64),
                cwe=_bounded(str(obj.get("cwe") or ""), 32),
                cve=_bounded(str(obj.get("cve") or ""), 32),
                remediation=_bounded(str(obj.get("remediation") or ""), 2000),
                evidence=[], raw=redact.redact(raw))
            f.finalize()      # Phase-4 fingerprint + deterministic id
            existing = None
            try:
                existing = self.svc.finding_get(f.id)
            except errors.NotFoundError:
                existing = None
            evs = self._evidence_models(evidence_by_source.get(
                prov["source_object_id"], []), f.id, prov, import_id)
            if existing:
                if strategy == "skip":
                    skipped += 1; _bump("finding_skip")
                elif strategy == "link":
                    # record the association only: the local object is
                    # untouched (never silently overwritten, §14) and no
                    # finding.created event is fabricated
                    linked += 1; _bump("finding_link")
                    detail.setdefault("linked_findings", []).append(
                        _bounded(f.id, 64))
                elif strategy == "merge_metadata":
                    self.svc.finding_ingest(f, evidence=[])
                    imported += 1; _bump("finding_merge")
                else:
                    raise errors.DuplicateError(
                        "collision_reject: finding fingerprint already "
                        f"exists locally ({f.fingerprint[:16]})")
            else:
                self.svc.finding_ingest(f, evidence=evs)
                imported += 1
            finding_map[prov["source_object_id"]] = f.id
            _checkpoint()
        detail["by_type"]["finding"] = len(findings_objs)
        # evidence for findings that already existed and were skipped/linked
        detail["by_type"]["evidence"] = len(objects.get("evidence", []))

        # ------------------------------------------------------------ cases
        for obj in objects.get("case", []):
            done += 1
            prov = dict(base_prov)
            prov["source_object_id"] = str((obj.get("_provenance") or {})
                                           .get("source_object_id") or "")
            title = _bounded(str(obj.get("title") or "").strip(), 200)
            if len(title) < 3:
                invalid += 1
                continue
            marker = f"[federated:{src_org[:8]}:{pkg_id[:8]}]"
            desc = _bounded(
                f"{str(obj.get('description') or '')[:1500]} {marker}", 2000)
            pri = str(obj.get("priority") or "medium").lower()
            if pri not in models.CASE_PRIORITIES:
                pri = "medium"
            import security_operations as _so
            cases = _so.InvestigationCaseService(self.svc)
            try:
                # dedup identity = source package + the foreign case id.
                # Re-importing the SAME package resolves to the SAME local
                # case (idempotent import); two distinct foreign cases that
                # share a title on the same day stay distinct.
                c = cases.create(org_id, target_project_id, title=title,
                                 description=desc, priority=pri,
                                 owner=_bounded(str(obj.get("owner") or ""),
                                                128),
                                 dedup_key=f"federation:{pkg_id}:"
                                           f"{str(obj.get('id') or title)}",
                                 actor=f"federation:{actor}"[:128])
                imported += 1
                # cross-org refs: ONLY refs that resolve locally (the case
                # service re-verifies existence + tenant — a foreign id can
                # never be linked, §17)
                for ref in (obj.get("refs") or [])[:20]:
                    if not isinstance(ref, dict):
                        continue
                    try:
                        cases.link(org_id, c["id"],
                                   str(ref.get("ref_type") or ""),
                                   str(ref.get("ref_id") or ""),
                                   note="federated reference",
                                   actor=f"federation:{actor}"[:128])
                        linked += 1
                    except (errors.NotFoundError, errors.ValidationError):
                        skipped += 1     # foreign/dangling ref: never linked
            except (sqlite3.IntegrityError, errors.DuplicateError):
                if strategy == "reject":
                    raise errors.DuplicateError(
                        f"collision_reject: case {title[:60]!r} already "
                        "exists locally") from None
                skipped += 1; _bump("case_skip")
            _checkpoint()
        detail["by_type"]["case"] = len(objects.get("case", []))

        # ------------------------------------------------ threat-intel IOCs
        for obj in objects.get("threat_intel_match", []):
            done += 1
            indicator = _bounded(str(obj.get("indicator") or ""), 300)
            if not indicator:
                invalid += 1
                continue
            import security_operations as _so
            iocs = _so.IocCatalogService(self.svc)
            existed = self._maybe(
                "SELECT id FROM threat_indicators WHERE org_id=? AND "
                "indicator=?", (org_id, indicator.lower()))
            try:
                iocs.add(org_id, indicator,
                         ioc_type=str(obj.get("ioc_type") or "") or None,
                         source=f"federation:{peer_id[:8]}",
                         confidence_level=str(obj.get("confidence") or
                                              "medium"),
                         reference=f"package:{digest[:16]}",
                         actor=f"federation:{actor}"[:128])
                if existed:
                    skipped += 1; _bump("ioc_exists")
                else:
                    imported += 1
            except (errors.ValidationError, errors.DuplicateError):
                invalid += 1
            _checkpoint()
        detail["by_type"]["threat_intel_match"] = \
            len(objects.get("threat_intel_match", []))
        if invalid:
            detail["invalid_objects"] = invalid
        self._finalize_import(import_id, org_id, "completed",
                              counts=(imported, skipped, linked),
                              detail=detail, error="", actor=actor)
        if progress_cb:
            progress_cb(1.0)
        return {"imported": imported, "skipped": skipped, "linked": linked,
                "invalid": invalid, "detail": detail, "error": ""}

    def _evidence_models(self, ev_objs: list, finding_id: str, prov: dict,
                         import_id: str) -> list:
        out = []
        for ev in ev_objs[:50]:               # bounded per finding
            try:
                e = models.Evidence(
                    finding_id=finding_id,
                    evidence_type=(
                        str(ev.get("evidence_type") or "other")
                        if str(ev.get("evidence_type") or "other")
                        in models.EVIDENCE_TYPES else "other"),
                    url=_bounded(str(ev.get("url") or ""), 2000),
                    method=_bounded(str(ev.get("method") or ""), 10),
                    status_code=_bounded(str(ev.get("status_code") or ""), 8),
                    request_snippet=_bounded(
                        str(ev.get("request_snippet") or ""), 4000),
                    response_snippet=_bounded(
                        str(ev.get("response_snippet") or ""), 4000),
                    detection_reason=_bounded(
                        f"{str(ev.get('detection_reason') or '')[:400]} "
                        f"[federated:{import_id[:8]}]", 500),
                    scanner="federation",
                    rule_id=_bounded(str(ev.get("rule_id") or ""), 64))
                e.finalize()      # centralized sanitization (Phase-1)
                out.append(e)
            except errors.ValidationError:
                continue          # structurally invalid evidence is never
                # stored; the count is surfaced via detail.invalid_objects
        return out

    # ------------------------------------------------------------ reads
    def get(self, org_id: str, import_id: str) -> dict:
        self._org(org_id)
        row = self._maybe(
            "SELECT * FROM federation_imports WHERE id=? AND org_id=?",
            (import_id, org_id))
        if not row:
            raise errors.NotFoundError("federation import not found")
        out = dict(row)
        out["detail"] = store.loads(out.pop("detail_json", "{}"), default={})
        return out

    def list(self, org_id: str, *, status: str = "", limit: int = 50,
             offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit, default=50)
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if status:
            s = str(status).strip().lower()
            if s not in models.FEDERATION_IMPORT_STATUSES:
                raise errors.ValidationError(f"unknown status: {s!r}")
            where.append("status=?"); args.append(s)
        total = int(self._one(
            "SELECT COUNT(*) n FROM federation_imports WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            "SELECT id, package_id, package_hash, source_org_id, peer_id, "
            "target_project_id, status, collision_strategy, object_count, "
            "imported_count, skipped_count, linked_count, error, created_by, "
            "created_at FROM federation_imports WHERE " +
            " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        for r in rows:
            r["package_hash"] = str(r["package_hash"])[:16]
        return {"total": total, "count": len(rows), "items": rows}


# ===========================================================================
# External integrations — the governed delivery boundary (§23/§24/§25)
# ===========================================================================
class IntegrationService(_Base):

    def __init__(self, platform, *, limiter=None, provider=None):
        super().__init__(platform, limiter=limiter)
        # injectable for tests (notify.RecordingProvider); production
        # default is the EXISTING SSRF-guarded, HMAC-signing webhook
        # provider — no second HTTP stack
        self.provider = provider or _notify.WebhookProvider()

    def create(self, org_id: str, *, project_id: str = "", name: str,
               kind: str, endpoint_url: str = "", actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"integration:{org_id}", "integration")
        self._project_owned(org_id, project_id)
        nm = _bounded(redact.redact_text(str(name or "").strip()), 120)
        if len(nm) < 3:
            raise errors.ValidationError("integration name too short")
        k = str(kind or "").strip().lower()
        if k not in models.INTEGRATION_KINDS:
            raise errors.ValidationError(f"unknown integration kind: {k!r}")
        url = _bounded(str(endpoint_url or "").strip(), 512)
        if url:
            # storage-time format check (offline-safe); the FULL SSRF guard
            # (DNS resolution + private-range blocking) runs at send time
            # inside the existing webhook provider
            _notify.validate_webhook_url(url, resolve=False)
        iid = models.stable_id(models.NS_INTEGRATION,
                               f"{org_id}|{project_id}|{nm}")
        now = _now()
        try:
            self.db.execute(
                "INSERT INTO external_integrations (id, org_id, project_id, "
                "name, kind, endpoint_url, status, created_by, created_at, "
                "updated_at) VALUES (?,?,?,?,?,?, 'enabled',?,?,?)",
                (iid, org_id, project_id or "", nm, k, url,
                 _bounded(actor, 128), now, now))
        except sqlite3.IntegrityError:
            raise errors.DuplicateError(
                f"integration already exists: {nm}") from None
        metrics.inc("federation_integrations_created")
        self._audit("integration.created", object_type="integration",
                    object_id=iid, org_id=org_id, project_id=project_id,
                    actor=actor,
                    metadata={"kind": k, "has_endpoint": bool(url)})
        self._emit(project_id, "integration.created", key=iid,
                   org_id=org_id, actor=actor)
        return self.get(org_id, iid)

    def get(self, org_id: str, integration_id: str) -> dict:
        self._org(org_id)
        row = self._maybe(
            "SELECT id, org_id, project_id, name, kind, endpoint_url, "
            "status, created_by, created_at, updated_at, disabled_at, "
            "last_delivery_at FROM external_integrations WHERE id=? AND "
            "org_id=?", (integration_id, org_id))
        if not row:
            raise errors.NotFoundError("integration not found")
        return dict(row)

    def list(self, org_id: str, *, project_id: str = "", status: str = "",
             limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if project_id:
            where.append("project_id=?"); args.append(project_id)
        if status:
            s = str(status).strip().lower()
            if s not in models.INTEGRATION_STATUSES:
                raise errors.ValidationError(f"unknown status: {s!r}")
            where.append("status=?"); args.append(s)
        total = int(self._one(
            "SELECT COUNT(*) n FROM external_integrations WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            "SELECT id, project_id, name, kind, status, created_at, "
            "disabled_at, last_delivery_at FROM external_integrations "
            "WHERE " + " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        return {"total": total, "count": len(rows), "items": rows}

    def update(self, org_id: str, integration_id: str, *,
               endpoint_url: str | None = None, name: str | None = None,
               actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"integration:{org_id}", "integration")
        row = self.get(org_id, integration_id)
        url = row["endpoint_url"]
        nm = row["name"]
        if endpoint_url is not None:
            url = _bounded(str(endpoint_url or "").strip(), 512)
            if url:
                _notify.validate_webhook_url(url, resolve=False)
        if name is not None:
            nm = _bounded(redact.redact_text(str(name).strip()), 120)
            if len(nm) < 3:
                raise errors.ValidationError("integration name too short")
        now = _now()
        self.db.execute(
            "UPDATE external_integrations SET endpoint_url=?, name=?, "
            "updated_at=? WHERE id=? AND org_id=?",
            (url, nm, now, integration_id, org_id))
        self._audit("integration.updated", object_type="integration",
                    object_id=integration_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={"has_endpoint": bool(url)})
        return self.get(org_id, integration_id)

    def disable(self, org_id: str, integration_id: str, *,
                actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"integration:{org_id}", "integration")
        row = self.get(org_id, integration_id)
        if row["status"] == "disabled":
            raise errors.LifecycleError("integration already disabled")
        now = _now()
        self.db.execute(
            "UPDATE external_integrations SET status='disabled', "
            "disabled_at=?, updated_at=? WHERE id=? AND org_id=?",
            (now, now, integration_id, org_id))
        self._audit("integration.disabled", object_type="integration",
                    object_id=integration_id, org_id=org_id,
                    project_id=row.get("project_id") or "", actor=actor,
                    metadata={})
        self._emit(row.get("project_id") or "", "integration.disabled",
                   key=integration_id, org_id=org_id, actor=actor)
        return self.get(org_id, integration_id)

    def emit(self, org_id: str, integration_id: str, event_type: str,
             payload: dict, *, actor: str = "api") -> dict:
        """Deliver ONE bounded, redacted, deterministic event through the
        integration boundary. Signed with the project's EXISTING webhook
        secret when present (notify.sign_payload inside the provider).
        Delivery outcomes are always logged — failures are observable,
        never swallowed."""
        self._org(org_id)
        self._acquire(f"emit:{org_id}", "emit")
        ev = str(event_type or "").strip().lower()
        if ev not in WEBHOOK_EVENTS:
            raise errors.ValidationError(
                f"unknown webhook event: {event_type!r} "
                f"(allowlist: {', '.join(WEBHOOK_EVENTS)})")
        row = self.get(org_id, integration_id)
        body = self._bounded_payload(ev, payload, integration_id)
        text = json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
        digest = _sha256(text)
        now = _now()
        event_id = models.stable_id(
            models.NS_INTEGRATION_EVENT,
            f"{integration_id}|{ev}|{digest[:16]}|{time.monotonic_ns()}")
        project_id = str(row.get("project_id") or "")
        if row["status"] != "enabled":
            status, outcome, err = "skipped", "disabled", "integration is disabled"
        elif not str(row["endpoint_url"] or ""):
            status, outcome, err = "skipped", "no_endpoint", \
                "integration has no endpoint configured"
        else:
            secret = ""
            if project_id:
                try:
                    settings = _notify.NotificationService(self.svc) \
                        .settings_get(project_id)
                    secret = str(settings.get("webhook_secret") or "")
                except errors.NotFoundError:
                    secret = ""
            send_settings = {"webhook_url": str(row["endpoint_url"]),
                             "webhook_secret": secret}
            try:
                res = self.provider.send(send_settings, body)
            except errors.SecurityToolkitError as e:
                res = {"ok": False, "outcome": "invalid",
                       "error": str(e)[:200]}
            status = "sent" if res.get("ok") else \
                ("invalid" if res.get("outcome") == "invalid" else "failed")
            outcome = str(res.get("outcome") or "")
            err = _bounded(str(res.get("error") or ""), 200)
        self.db.execute(
            "INSERT INTO integration_events (id, org_id, project_id, "
            "integration_id, event_type, status, payload_sha256, byte_size, "
            "provider_outcome, error, created_at) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, org_id, project_id, integration_id, ev, status,
             digest, len(text.encode("utf-8")), _bounded(outcome, 40), err,
             now))
        self.db.execute(
            "UPDATE external_integrations SET last_delivery_at=?, "
            "updated_at=? WHERE id=? AND org_id=?",
            (now, now, integration_id, org_id))
        self._audit("integration.emitted", object_type="integration_event",
                    object_id=event_id, org_id=org_id, project_id=project_id,
                    actor=actor,
                    metadata={"integration_id": integration_id,
                              "event_type": ev, "status": status,
                              "bytes": len(text.encode("utf-8")),
                              "sha256": digest[:16]})
        if project_id:
            self._emit(project_id,
                       "integration.delivered" if status == "sent" else
                       "integration.failed",
                       key=event_id, org_id=org_id,
                       new_state={"event": ev, "status": status},
                       actor=actor)
        metrics.inc("federation_integration_events")
        if status == "failed":
            metrics.inc("federation_integration_failures")
        return {"event_id": event_id, "status": status, "outcome": outcome,
                "error": err, "payload_sha256": digest,
                "byte_size": len(text.encode("utf-8"))}

    def _bounded_payload(self, event_type: str, payload: dict,
                         integration_id: str) -> dict:
        """Deterministic, redacted, bounded webhook payload. Oversized
        payloads degrade to a count-only summary — never truncated
        mid-structure, never unbounded."""
        body = redact.redact({
            "schema_version": FED_SCHEMA,
            "event_type": event_type,
            "integration_id": integration_id,
            "emitted_at": _now(),
            "data": payload if isinstance(payload, dict) else {},
        })
        text = json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, default=str)
        if len(text.encode("utf-8")) > MAX_WEBHOOK_PAYLOAD_BYTES:
            data = body.get("data") or {}
            summary = {}
            for k, v in sorted(data.items()):
                if isinstance(v, (int, float, bool)):
                    summary[k] = v
                elif isinstance(v, str):
                    summary[k] = v[:64]
                elif isinstance(v, list):
                    summary[f"{k}_count"] = len(v)
                elif isinstance(v, dict):
                    summary[f"{k}_keys"] = sorted(v)[:20]
            body["data"] = {"truncated": True, "summary": summary}
        return body

    def events_list(self, org_id: str, *, integration_id: str = "",
                    limit: int = 100, offset: int = 0) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit)
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if integration_id:
            where.append("integration_id=?"); args.append(integration_id)
        total = int(self._one(
            "SELECT COUNT(*) n FROM integration_events WHERE " +
            " AND ".join(where), args)["n"])
        rows = self._q(
            "SELECT id, integration_id, event_type, status, payload_sha256, "
            "byte_size, provider_outcome, error, created_at FROM "
            "integration_events WHERE " + " AND ".join(where) +
            " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            args + [limit, offset])
        for r in rows:
            r["payload_sha256"] = str(r["payload_sha256"])[:16]
        return {"total": total, "count": len(rows), "items": rows}


# ===========================================================================
# Bulk operations — the EXISTING Phase-3 job engine, federated (§18-§21)
# ===========================================================================
BULK_PROFILE = "federation-bulk"


class BulkOperationService(_Base):
    """Enqueue + inspect bulk federation jobs. Execution happens in the
    existing worker through the in-process `federation-bulk` profile; the
    runner (BulkRunner) is shared with the synchronous CLI path so bounds,
    checkpoints and audit are identical."""

    def __init__(self, platform, *, limiter=None, federation=None):
        super().__init__(platform, limiter=limiter)
        self.fed = federation

    def _jobs(self):
        import jobs as _jobs
        import scanners as _scanners
        return _jobs.JobService(self.svc, _scanners.ScannerRegistry())

    def enqueue(self, org_id: str, project_id: str, *, op: str,
                peer_id: str = "", policy_id: str = "", package_id: str = "",
                strategy: str = "skip", object_types=(), params=None,
                envelope=None, priority: str = "normal",
                actor: str = "cli") -> dict:
        """Create a bounded bulk job. Scope is ALWAYS explicit (org +
        project + op + peer/policy); 'everything' jobs do not exist. Bulk
        material (a foreign package envelope, operation params) is staged
        on the job's scan record — job payloads stay scalar-only."""
        self._org(org_id)
        proj = self.svc.project_require(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        self._acquire(f"bulk:{org_id}", "bulk")
        o = str(op or "").strip().lower()
        if o not in models.BULK_OPERATIONS:
            raise errors.ValidationError(
                f"unknown bulk operation: {op!r} "
                f"(allowlist: {', '.join(models.BULK_OPERATIONS)})")
        strat = str(strategy or "skip").strip().lower()
        if strat not in models.FEDERATION_COLLISION_STRATEGIES:
            raise errors.ValidationError(
                f"unknown collision strategy: {strategy!r}")
        otypes = tuple(dict.fromkeys(
            str(t).strip().lower() for t in (object_types or ())))
        for t in otypes:
            if t not in models.FEDERATION_OBJECT_TYPES:
                raise errors.ValidationError(f"unknown object type: {t!r}")
        material_key = o
        if o == "bulk_import":
            if not envelope:
                raise errors.ValidationError(
                    "bulk_import requires a package envelope staged with "
                    "the job")
            material_key = f"{o}|{_sha256(json.dumps(envelope, sort_keys=True, default=str))[:16]}"
        scan_id = models.stable_id(models.NS_SCAN,
                                   f"{project_id}|{BULK_PROFILE}|{material_key}")
        try:
            scan = self.svc.scan_get(scan_id)
        except errors.NotFoundError:
            scan = self.svc.scan_create(project_id, BULK_PROFILE,
                                        scope_ref=_bounded(o, 60),
                                        scan_id=scan_id)
        staged = {}
        if envelope is not None:
            text = json.dumps(envelope, sort_keys=True, ensure_ascii=False,
                              default=str)
            if len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
                raise errors.ValidationError("package_too_large")
            staged["package"] = envelope
        if params:
            if not isinstance(params, dict):
                raise errors.ValidationError("params must be an object")
            staged["params"] = redact.redact(params)
        if staged:
            self.svc.scan_save_raw(scan_id, staged)
        # `target` names the operation itself (vocabulary-controlled, no
        # unsafe chars): validate_execution requires an explicit target for
        # every in-process profile — bulk scope is the org+project+op, there
        # is no network target and scope_check never applies. Optional ids
        # are omitted when empty (payload fields must be non-empty safe
        # scalars — validate_payload rejects "").
        payload = {"op": o, "target": f"bulk:{o}", "strategy": strat}
        for key, val in (("peer_id", peer_id), ("policy_id", policy_id),
                         ("package_id", package_id),
                         ("object_types", ",".join(otypes))):
            v = _bounded(str(val or ""), 300 if key == "object_types" else 64)
            if v:
                payload[key] = v
        # Job ids derive from scan_id|job_type|created_at|payload_hash; the
        # bulk scan id is deterministic by design (staged material lives on
        # it), so an explicit per-scan sequence keeps repeated enqueues of
        # the same operation distinct jobs instead of an id collision.
        # Operation-level idempotency is enforced where it matters: import
        # claims (org, package_hash) and deterministic package rebuilds.
        prev = self._one("SELECT COUNT(*) n FROM jobs WHERE scan_id=?",
                         (scan_id,))
        payload["note"] = f"seq:{int(prev['n']) + 1}"
        job = self._jobs().create_job(
            scan.id, BULK_PROFILE, payload, job_type="federation_bulk",
            priority=priority, timeout_seconds=1800, actor=actor,
            queue_now=True)
        self._audit("federation.bulk.started", object_type="job",
                    object_id=job.id, org_id=org_id, project_id=project_id,
                    actor=actor,
                    metadata={"op": o, "peer_id": peer_id[:16],
                              "strategy": strat})
        self._emit(project_id, "bulk.started", key=job.id, org_id=org_id,
                   new_state={"op": o}, actor=actor)
        metrics.inc("federation_bulk_jobs")
        return {"job_id": job.id, "scan_id": scan.id, "op": o,
                "status": job.status, "payload": payload}

    def jobs_list(self, org_id: str, *, project_id: str = "",
                  status: str = "", limit: int = 50) -> dict:
        self._org(org_id)
        limit = self._page_limit(limit, default=50)
        where, args = ["org_id=?", "profile=?"], [org_id, BULK_PROFILE]
        if project_id:
            where.append("project_id=?"); args.append(project_id)
        if status:
            where.append("status=?"); args.append(str(status))
        rows = self._q(
            "SELECT id, project_id, scan_id, job_type, status, attempt, "
            "max_attempts, created_at, queued_at, started_at, finished_at, "
            "error_code, error_message, payload FROM jobs WHERE " +
            " AND ".join(where) + " ORDER BY created_at DESC, id LIMIT ?",
            args + [limit])
        return {"total": len(rows), "items": rows}


class BulkRunner:
    """Executes bulk operations. Shared by the worker (job path — with
    checkpoint/pause/cancel/retry semantics from the existing engine) and
    the synchronous CLI/test path (identical bounds + audit). Never builds
    an unbounded in-memory list: everything is paged, and every page is a
    safe checkpoint."""

    def __init__(self, platform, *, federation=None):
        self.svc = platform
        self.db = platform.db
        self.fed = federation

    # ------------------------------------------------------------ entry
    def run_for_job(self, job) -> dict:
        import jobs as _jobs
        import scanners as _scanners
        js = _jobs.JobService(self.svc, _scanners.ScannerRegistry())

        def cancel_check():
            ctl = js.control_state(job.id)
            # `cancelling` is the only mid-run control signal: WorkerStopped
            # is the engine's cancellation path. A `paused` row means the
            # lease was taken over/paused by an operator, so the runner
            # stops the same way (never keeps writing after a pause).
            if ctl in ("cancelling", "paused"):
                raise errors.WorkerStopped(
                    f"bulk {ctl} at checkpoint")
            js.heartbeat(job.id, job.worker_id)

        def progress(frac):
            try:
                self.svc.scan_set_progress(job.scan_id, float(frac))
            except errors.SecurityToolkitError:
                metrics.inc("federation_bulk_progress_errors")

        payload = dict(job.payload or {})
        return self.run(org_id=job.org_id, project_id=job.project_id,
                        op=str(payload.get("op") or ""),
                        peer_id=str(payload.get("peer_id") or ""),
                        policy_id=str(payload.get("policy_id") or ""),
                        package_id=str(payload.get("package_id") or ""),
                        strategy=str(payload.get("strategy") or "skip"),
                        object_types=[t for t in str(
                            payload.get("object_types") or "").split(",")
                            if t],
                        scan_id=job.scan_id, job_id=job.id,
                        actor=f"job:{job.id[:8]}",
                        progress_cb=progress, cancel_check=cancel_check)

    def run(self, *, org_id: str, project_id: str, op: str,
            peer_id: str = "", policy_id: str = "", package_id: str = "",
            strategy: str = "skip", object_types=(), scan_id: str = "",
            job_id: str = "", actor: str = "cli", progress_cb=None,
            cancel_check=None, envelope=None, params=None) -> dict:
        o = str(op or "").strip().lower()
        if o not in models.BULK_OPERATIONS:
            raise errors.ValidationError(f"unknown bulk operation: {op!r}")
        staged = {}
        if scan_id:
            # the worker path stages material on the job's scan record
            try:
                staged = dict(self.svc.scan_get(scan_id).raw or {})
            except errors.NotFoundError:
                staged = {}
        if envelope is not None:
            text = json.dumps(envelope, sort_keys=True, ensure_ascii=False,
                              default=str)
            if len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
                raise errors.ValidationError("package_too_large")
            staged["package"] = envelope
        if params is not None:
            if not isinstance(params, dict):
                raise errors.ValidationError("params must be an object")
            staged["params"] = redact.redact(dict(params))
        try:
            if o == "bulk_export":
                res = self._bulk_export(org_id, project_id, peer_id,
                                        policy_id, object_types, actor,
                                        progress_cb, cancel_check)
            elif o == "bulk_import":
                res = self._bulk_import(org_id, project_id, peer_id,
                                        strategy, staged, actor,
                                        progress_cb, cancel_check)
            elif o == "bulk_classify":
                res = self._bulk_classify(org_id, project_id, staged, actor)
            else:  # bulk_retention_preview
                res = self._bulk_retention_preview(org_id, project_id,
                                                   staged, actor)
        except errors.WorkerStopped:
            self._bulk_event(org_id, project_id, job_id, "bulk.failed",
                             actor, {"op": o, "outcome": "cancelled"})
            raise
        except errors.SecurityToolkitError as e:
            self._bulk_event(org_id, project_id, job_id, "bulk.failed",
                             actor, {"op": o, "error": str(e)[:120]})
            raise
        res = {"op": o, "job_id": job_id, **res}
        self._bulk_event(org_id, project_id, job_id, "bulk.completed", actor,
                         {"op": o,
                          **{k: v for k, v in res.items()
                             if isinstance(v, (int, bool))}})
        return res

    def _bulk_event(self, org_id: str, project_id: str, job_id: str,
                    event_type: str, actor: str, state: dict) -> None:
        try:
            _events_mod.SecurityEventService(self.svc).emit(
                project_id, event_type, key=_bounded(job_id or org_id, 160),
                source="federation", new_state=state, actor=actor,
                org_id=org_id)
        except (errors.ValidationError, errors.NotFoundError):
            metrics.inc("federation_bulk_event_dropped")
        try:
            self.svc.audit(
                "federation.bulk.completed" if event_type ==
                "bulk.completed" else "federation.bulk.failed",
                object_type="job", object_id=_bounded(job_id, 64),
                org_id=org_id, project_id=project_id,
                actor=str(actor)[:128],
                metadata=redact.redact(state))
        except Exception:
            metrics.inc("federation_audit_failures")

    # ------------------------------------------------------------ ops
    def _fed(self):
        if self.fed is None:
            self.fed = FederationService(self.svc)
        return self.fed

    def _bulk_export(self, org_id, project_id, peer_id, policy_id,
                     object_types, actor, progress_cb, cancel_check) -> dict:
        if not peer_id:
            raise errors.ValidationError(
                "bulk_export requires an explicit peer (no unbounded "
                "'share everything' exports)")
        r = self._fed().packages.build(
            org_id, peer_id=peer_id, policy_id=policy_id,
            project_id=project_id, object_types=tuple(object_types or ()),
            limit=0,  # 0 = "the policy's own max_objects cap governs"
            progress_cb=progress_cb,
            cancel_check=cancel_check, actor=actor)
        return {"packages": 1, "objects": r["object_count"],
                "package_id": r["package_id"], "denied":
                sum(int(v) for v in r["denied"].values()),
                "truncated": r["truncated"]}

    def _bulk_import(self, org_id, project_id, peer_id, strategy, staged,
                     actor, progress_cb, cancel_check) -> dict:
        env = staged.get("package")
        if not env:
            raise errors.ValidationError(
                "bulk_import requires a staged package envelope "
                "(scan_save_raw {'package': ...})")
        r = self._fed().imports.import_envelope(
            org_id, envelope=env, target_project_id=project_id,
            peer_id=peer_id, collision=strategy, actor=actor,
            progress_cb=progress_cb, cancel_check=cancel_check)
        return {"imports": 0 if r.get("duplicate") else 1,
                "objects": int(r.get("object_count") or 0),
                "imported": int(r.get("imported") or 0),
                "skipped": int(r.get("skipped") or 0),
                "linked": int(r.get("linked") or 0),
                "duplicate": bool(r.get("duplicate")),
                "import_id": r.get("import_id", "")}

    def _bulk_classify(self, org_id, project_id, staged, actor) -> dict:
        """Bulk classification = set the project-scope DEFAULT through the
        EXISTING Phase-11 classification engine; inheritance then covers
        every unclassified object deterministically (explicit rows always
        win — never a silent downgrade of existing classifications)."""
        params = staged.get("params") or {}
        cls = str(params.get("classification") or "").strip().lower()
        if cls not in models.DATA_CLASSIFICATIONS:
            raise errors.ValidationError(
                f"bulk_classify requires a valid classification in params "
                f"(got {cls!r})")
        gov = self._fed().gov
        gov.classification.default(org_id, classification=cls,
                                   project_id=project_id, actor=actor)
        covered = int(self._one_count(
            "SELECT COUNT(*) n FROM findings f WHERE f.project_id=? AND "
            "NOT EXISTS (SELECT 1 FROM data_classifications c WHERE "
            "c.org_id=? AND c.object_type='finding' AND c.object_id=f.id)",
            (project_id, org_id)))
        return {"classified": covered, "classification": cls}

    def _bulk_retention_preview(self, org_id, project_id, staged,
                                actor) -> dict:
        params = staged.get("params") or {}
        kinds = params.get("kinds") or list(models.RETENTION_KINDS)
        if not isinstance(kinds, list):
            raise errors.ValidationError("params.kinds must be a list")
        gov = self._fed().gov
        out = {}
        eligible = held = 0
        for k in [str(x) for x in kinds][:len(models.RETENTION_KINDS)]:
            if k not in models.RETENTION_KINDS:
                raise errors.ValidationError(f"unknown retention kind: {k!r}")
            r = gov.retention.preview(org_id, kind=k,
                                      project_id=project_id, actor=actor)
            out[k] = {"eligible": r["eligible"], "held": r["held"],
                      "days": r["days"]}
            eligible += int(r["eligible"])
            held += int(r["held"])
        return {"kinds": len(out), "eligible": eligible, "held": held,
                "preview": out}

    def _one_count(self, sql, params) -> int:
        row = self.db.query_one(sql, tuple(params))
        return int(row["n"]) if row else 0


# ===========================================================================
# Facade
# ===========================================================================
class FederationService:
    """Composition facade (same shape as Phase-10/11 facades): thin
    wrappers over the existing platform — no duplicate infrastructure."""

    def __init__(self, platform, *, limiter=None, provider=None):
        self.platform = platform
        lim = limiter or _id_mod.RateLimiter(max_keys=4096)
        self.gov = _gov.SecurityGovernance(platform, limiter=lim)
        self.peers = FederationPeerService(platform, limiter=lim)
        self.policies = FederationPolicyService(platform, limiter=lim)
        self.packages = FederationPackageService(platform, limiter=lim,
                                                 gov=self.gov)
        self.imports = FederationImportService(platform, limiter=lim)
        self.integrations = IntegrationService(platform, limiter=lim,
                                               provider=provider)
        self.bulk = BulkOperationService(platform, limiter=lim,
                                         federation=self)
        # execution engine shared by the worker (job path) and the
        # synchronous CLI/test path — identical bounds, checkpoints, audit
        self.bulk_runner = BulkRunner(platform, federation=self)

    # ------------------------------------------------------------ webhook
    def notify_integrations(self, org_id: str, event_type: str,
                            payload: dict, *, project_id: str = "",
                            actor: str = "system") -> list:
        """Fan a federation webhook event out to enabled integrations
        (bounded). Delivery failures are recorded per event — they never
        break (or silently vanish from) the primary operation."""
        if event_type not in WEBHOOK_EVENTS:
            raise errors.ValidationError(
                f"unknown webhook event: {event_type!r}")
        rows = self.integrations._q(
            "SELECT id FROM external_integrations WHERE org_id=? AND "
            "status='enabled' AND (project_id=? OR project_id='') ORDER BY "
            "created_at, id LIMIT ?",
            (org_id, project_id or "", MAX_INTEGRATIONS_PER_EVENT))
        out = []
        for r in rows:
            try:
                out.append(self.integrations.emit(
                    org_id, r["id"], event_type, payload, actor=actor))
            except errors.SecurityToolkitError as e:
                out.append({"integration_id": r["id"], "status": "invalid",
                            "error": str(e)[:160]})
                metrics.inc("federation_integration_failures")
        return out

    # ------------------------------------------------------------ summary
    def summary(self, org_id: str, *, budget_items: int = 20) -> dict:
        """Read-only dashboard snapshot: peers, grants, packages, imports,
        bulk jobs, integrations, violations. Tenant-scoped; identifiers +
        counts only — never payloads, never secrets."""
        self.platform.org_require(org_id)
        budget = max(1, min(int(budget_items or 20), 100))
        now = _now()
        horizon = _iso(_epoch(now) + 30 * 86400)

        def counts(sql, args, key):
            out = {}
            for r in self.packages._q(sql, args):
                out[str(r[key])] = int(r["n"])
            return out

        peers = counts("SELECT status, COUNT(*) n FROM federation_peers "
                       "WHERE org_id=? GROUP BY status", (org_id,), "status")
        expiring = self.packages._one(
            "SELECT COUNT(*) n FROM federation_peers WHERE org_id=? AND "
            "status IN ('active','suspended') AND expires_at<>'' AND "
            "expires_at>? AND expires_at<=?", (org_id, now, horizon))
        policies = counts("SELECT status, COUNT(*) n FROM "
                          "federation_policies WHERE org_id=? GROUP BY "
                          "status", (org_id,), "status")
        packages_total = self.packages._one(
            "SELECT COUNT(*) n FROM federation_packages WHERE org_id=?",
            (org_id,))
        imports = counts("SELECT status, COUNT(*) n FROM federation_imports "
                         "WHERE org_id=? GROUP BY status", (org_id,),
                         "status")
        integrity = self.packages._one(
            "SELECT COUNT(*) n FROM federation_imports WHERE org_id=? AND "
            "error LIKE 'integrity_%'", (org_id,))
        bulk = counts("SELECT status, COUNT(*) n FROM jobs WHERE org_id=? "
                      "AND profile=? GROUP BY status",
                      (org_id, BULK_PROFILE), "status")
        integ = counts("SELECT status, COUNT(*) n FROM "
                       "external_integrations WHERE org_id=? GROUP BY "
                       "status", (org_id,), "status")
        recent_packages = self.packages.list(org_id, limit=budget)["items"]
        rejected = self.imports.list(org_id, status="rejected",
                                     limit=budget)["items"]
        fed_actions = (
            "action LIKE 'federation.%' OR action LIKE 'integration.%'")
        recent_audit = []
        for a in self.platform.audit_list_org(org_id, limit=budget * 5):
            d = a.to_dict()
            act = str(d.get("action") or "")
            if act.startswith("federation.") or act.startswith(
                    "integration.") or act.startswith("bulk."):
                recent_audit.append({
                    "ts": d.get("ts"), "action": act,
                    "actor": str(d.get("actor") or "")[:40],
                    "object_type": str(d.get("object_type") or "")[:40]})
            if len(recent_audit) >= budget:
                break
        return {
            "generated_at": now,
            "peers": {"by_status": peers,
                      "active": int(peers.get("active", 0)),
                      "expiring_30d": int(expiring["n"]) if expiring else 0},
            "policies": {"by_status": policies},
            "packages": {"total": int(packages_total["n"])
                         if packages_total else 0,
                         "recent": recent_packages},
            "imports": {"by_status": imports,
                        "integrity_failures": int(integrity["n"])
                        if integrity else 0,
                        "recent_rejected": rejected},
            "bulk_jobs": {"by_status": bulk},
            "integrations": {"by_status": integ},
            "recent_audit": recent_audit,
        }
