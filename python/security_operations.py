#!/usr/bin/env python3
# ============================================================================
#  security_operations.py — Phase 10: Security Operations, Threat
#  Intelligence & External Attack Surface Management.
#
#  ── DESIGN RULES (deterministic, provider-neutral, passive) ───────────────
#  * NO network I/O at all: correlation is passive (matches against the
#    EXISTING asset/observation/finding/event data already in the platform).
#    An IOC URL is data, never permission to browse (§39). Active discovery
#    only ever happens through the existing authorized scanner/job framework
#    (subdomain_enum, cloudsec) — this module only INGESTS their results (§40).
#  * NO eval/exec/pickle/subprocess; feeds parsed only with json + csv (§17).
#  * Findings from IOC matches use the EXISTING finding pipeline
#    (CorrelationService.ingest_finding → platform.finding_ingest) — the
#    threat_matches table is a correlation LEDGER, not a finding store (§19).
#  * Risk reuses the EXISTING RiskEngine/ConfidenceEngine/RiskSnapshotService
#    (§23). Threat-intel confidence is a SEPARATE axis from severity/risk.
#  * Cases reference EXISTING findings/assets/observations/IOCs/evidence/
#    alerts/remediation (§25) — IDs verified, tenant-scoped, never duplicated.
#  * Neutral cluster labels only; no attribution, no actor names (§21/§47).
#  * No credentials/payloads/private keys ever accepted or stored (§11/§38).
# ============================================================================

from __future__ import annotations

import csv
import io
import json
import ipaddress
import urllib.parse

import errors
import events as events_mod
import correlate
import identity as identity_mod
import intel
import metrics
import models
import redact
import risk as risk_mod
import scope as scope_mod
import seclog
import store

from typing import Any

_LOG = seclog.get_logger("phase10")

# ---------------------------------------------------------------------------
# Limits (documented, bounded; §17/§30/§41/§42)
# ---------------------------------------------------------------------------
MAX_IOC_LEN = 512
MAX_FEED_BYTES = 2 * 1024 * 1024          # 2 MiB per import
MAX_FEED_RECORDS = 5000                   # records per import call
MAX_FEED_FIELDS = 20                      # fields per record
MAX_FEED_FIELD_LEN = 300
MAX_FEED_NESTING = 3                      # JSON nesting depth
MAX_INDICATORS_PER_ORG = 100_000          # hard catalog cap (§41 retention cap)
MAX_MATCH_IOCS_PER_RUN = 20_000           # correlation batch (§42)
MAX_MATCH_TARGETS_PER_RUN = 100_000
MAX_CASE_TITLE = 200
MAX_CASE_DESC = 4000
MAX_SURFACE_ENTRIES = 2000                # per ingest call
MAX_OBS_VALUE = 300                       # must agree with intel.MAX_VALUE_LEN
MAX_SCALE_RECORDS = 100_000               # scale-test ceiling (documented)

# Feed safety: single-quoted STIX-like patterns only; never evaluated.
STIX_PATTERN_RE = None                    # set below (regex compiled lazily)

# ---------------------------------------------------------------------------
# Deterministic severity mapping: TI confidence level -> finding severity.
# This is SEPARATE from risk; documented in README (§15/§23).
# ---------------------------------------------------------------------------
TI_CONFIDENCE_TO_SEVERITY = {
    "unknown": "Info", "low": "Low", "medium": "Medium",
    "high": "Medium", "confirmed": "High",
}
MIN_MATCH_CONFIDENCE = "low"              # below this → no finding (config)

# Rate limits per service instance/tenant (sliding window, seconds).
RATE = {
    "import": (10, 60),
    "match": (30, 60),
    "export": (20, 60),
    "case": (120, 60),
    "surface": (120, 60),
    "cluster": (30, 60),
}


def _now() -> str:
    return models.utcnow()


def _bounded(text, n: int) -> str:
    return str(text or "")[:n]


# ===========================================================================
# §8/§14 — deterministic normalization (domains, IPs, URLs, hashes, emails,
# certificate fingerprints). Pure functions: same input ⇒ same output.
# ===========================================================================
def normalize_domain(value: str) -> str:
    """Canonical domain/hostname: lowercase, IDNA, strip trailing dot(s),
    reject malformed names (§8 rules: no scheme, no path, no port, no
    whitespace/control chars, bounded length, sane labels)."""
    v = str(value or "").strip().lower()
    v = v.rstrip(".")
    if not v or len(v) > 253 or any(ord(c) < 33 for c in v):
        raise errors.ValidationError("malformed domain")
    try:
        v = v.encode("idna").decode("ascii").lower()
    except Exception as e:
        raise errors.ValidationError("malformed domain (idna)") from e
    if "/" in v or "\\" in v or ":" in v or "@" in v:
        raise errors.ValidationError("malformed domain")
    labels = v.split(".")
    if len(labels) < 2:
        raise errors.ValidationError("domain needs a TLD")
    for lab in labels:
        if not lab or len(lab) > 63:
            raise errors.ValidationError("malformed domain label")
        if not (lab[0].isalnum() and lab[-1].isalnum()):
            raise errors.ValidationError("malformed domain label")
    if len(labels[-1]) < 2 or not labels[-1].isalpha():
        raise errors.ValidationError("malformed TLD")
    return v


def normalize_hostname(value: str) -> str:
    """Canonical hostname (a domain with 3+ labels or a 'www.' prefix —
    the distinction is deterministic and documented in README §8)."""
    v = normalize_domain(value)
    labels = v.split(".")
    if len(labels) == 2 and not v.startswith("www."):
        # apex domain stored as domain; classify as hostname only when the
        # caller explicitly wants a hostname asset.
        return v
    return v


def normalize_ipv4(value: str) -> str:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError as e:
        raise errors.ValidationError("malformed ip") from e
    if ip.version != 4:
        raise errors.ValidationError("not an ipv4")
    return str(ip)


def normalize_ipv6(value: str) -> str:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError as e:
        raise errors.ValidationError("malformed ip") from e
    if ip.version != 6:
        raise errors.ValidationError("not an ipv6")
    return str(ip).lower()


def normalize_url(value: str, *, allow_netloc: bool = True) -> str:
    """Canonical URL: http/https only (IOC URLs are data, never fetch
    targets here); host lowercased + IDNA; userinfo REJECTED (credential
    smuggling); fragment kept (semantics preserved); bounded length."""
    v = str(value or "").strip()
    if len(v) > 1024:
        raise errors.ValidationError("url too long")
    parsed = urllib.parse.urlsplit(v)
    if parsed.scheme not in ("http", "https"):
        raise errors.ValidationError("unsupported url scheme")
    if parsed.username or parsed.password:
        raise errors.ValidationError("url userinfo rejected")
    host = normalize_domain(parsed.hostname or "") if parsed.hostname else ""
    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise errors.ValidationError("bad url port")
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    out = f"{parsed.scheme}://{netloc}{path}{query}{fragment}"
    if len(out) > MAX_IOC_LEN:
        raise errors.ValidationError("url too long after normalization")
    return out


def normalize_hash(value: str) -> tuple[str, str]:
    """(value, ioc_type) — md5 (32) / sha1 (40) / sha256 (64), lowercase.
    Rejects non-hex and unsupported lengths."""
    v = str(value or "").strip().lower()
    if not v or not all(c in "0123456789abcdef" for c in v):
        raise errors.ValidationError("malformed hash")
    if len(v) == 32:
        return v, "hash_md5"
    if len(v) == 40:
        return v, "hash_sha1"
    if len(v) == 64:
        return v, "hash_sha256"
    raise errors.ValidationError("unsupported hash length")


def normalize_email(value: str) -> str:
    v = str(value or "").strip().lower()
    if len(v) > 254 or " " in v:
        raise errors.ValidationError("malformed email")
    if v.count("@") != 1:
        raise errors.ValidationError("malformed email")
    local, _, dom = v.partition("@")
    if not local or not dom or "." not in dom:
        raise errors.ValidationError("malformed email")
    return v


def normalize_fingerprint(value: str) -> str:
    """Certificate fingerprint: hex with optional ':'/space separators;
    accepts SHA-1 (40) or SHA-256 (64) hex; lowercase, no separators."""
    v = str(value or "").strip().lower()
    v = "".join(ch for ch in v if ch in "0123456789abcdef")
    if len(v) not in (40, 64):
        raise errors.ValidationError("malformed fingerprint")
    return v


def normalize_indicator(value, ioc_type: str | None = None):
    """Normalize + validate an indicator. Returns (value, ioc_type).
    When ioc_type is None, the type is auto-classified (§14)."""
    v = str(value or "").strip()
    if not v or len(v) > MAX_IOC_LEN:
        raise errors.ValidationError("indicator empty or too long")
    if any(ord(c) < 32 for c in v):
        raise errors.ValidationError("indicator contains control characters")
    if ioc_type is None:
        ioc_type = classify_indicator(v)
        if ioc_type is None:
            raise errors.ValidationError("unrecognized indicator format")
    t = str(ioc_type).lower()
    if t not in models.IOC_TYPES:
        raise errors.ValidationError(f"unknown ioc type: {t!r}")
    if t == "domain":
        return normalize_domain(v), t
    if t == "hostname":
        return normalize_hostname(v), t
    if t == "ipv4":
        return normalize_ipv4(v), t
    if t == "ipv6":
        return normalize_ipv6(v), t
    if t == "url":
        return normalize_url(v), t
    if t in ("hash_md5", "hash_sha1", "hash_sha256"):
        hv, ht = normalize_hash(v)
        if ht != t:
            raise errors.ValidationError(f"hash length does not match {t}")
        return hv, t
    if t == "email":
        return normalize_email(v), t
    if t == "cert_fingerprint":
        return normalize_fingerprint(v), t
    raise errors.ValidationError(f"unsupported ioc type: {t!r}")


def classify_indicator(value: str) -> str | None:
    """Deterministic type auto-detection (pure, no ambiguity resolution
    needed for well-formed inputs; a URL wins over a domain, a hash wins
    over hex strings, an email over a hostname)."""
    v = str(value or "").strip()
    if not v or len(v) > MAX_IOC_LEN:
        return None
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if "://" in v:
        try:
            normalize_url(v)
            return "url"
        except errors.ValidationError:
            return None
    if v.count("@") == 1 and "." in v.partition("@")[2]:
        try:
            normalize_email(v)
            return "email"
        except errors.ValidationError:
            pass
    if all(c in "0123456789abcdefABCDEF" for c in v) and len(v) in (32, 40, 64):
        return "hash_sha256" if len(v) == 64 else (
            "hash_sha1" if len(v) == 40 else "hash_md5")
    if ":" in v and all(c in "0123456789abcdefABCDEF:" for c in v):
        try:
            normalize_fingerprint(v)
            return "cert_fingerprint"
        except errors.ValidationError:
            pass
    try:
        d = normalize_domain(v)
        labels = d.split(".")
        if len(labels) >= 3 or d.startswith("www.") or len(labels) == 2:
            return "hostname" if len(labels) >= 3 else "domain"
    except errors.ValidationError:
        pass
    return None


# ===========================================================================
# Service base — auditing (immutable, never swallowed), rate limiting
# ===========================================================================
class _Base:
    def __init__(self, platform, *, limiter: identity_mod.RateLimiter | None = None):
        self.svc = platform
        self.db = platform.db
        self.limiter = limiter or identity_mod.RateLimiter(max_keys=4096)

    # ------------------------------------------------------------- helpers
    def _acquire(self, key: str, op: str) -> None:
        limit, window = RATE[op]
        ok, retry = self.limiter.allowed(key, limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"{op} rate limit exceeded", retry_after=retry)

    def _audit(self, action: str, *, object_type: str, object_id: str,
               org_id: str, project_id: str = "", actor: str = "api",
               metadata: dict | None = None) -> None:
        try:
            self.svc.audit(
                action, object_type=object_type, object_id=object_id,
                org_id=org_id, project_id=project_id or "",
                actor=str(actor)[:128],
                metadata=redact.redact(dict(metadata or {})))
        except Exception as e:                       # §29: never swallowed
            _LOG.warn("audit write failed", action=action, error=str(e)[:200])
            metrics.inc("audit_failures")

    def _org(self, org_id: str) -> None:
        self.svc.org_require(org_id)

    def _project(self, project_id: str) -> models.Project:
        return self.svc.project_require(project_id)

    def _ti_scan(self, project_id: str) -> str:
        """Deterministic per-project 'threat-intel' scan — findings created
        by IOC correlation reference it (findings REQUIRE a scan_id)."""
        sid = models.stable_id(models.NS_SCAN, f"{project_id}|threat-intel")
        try:
            return self.svc.scan_get(sid).id
        except errors.NotFoundError:
            return self.svc.scan_create(project_id, "threat-intel",
                                        scope_ref="",
                                        scan_id=sid).id

    def _finding(self, project_id: str, *, rule_id: str, title: str,
                 description: str, severity: str, category: str,
                 asset_id: str, confidence_score: float, source: str,
                 remediation: str, raw: dict | None = None) -> models.Finding:
        f = models.Finding(
            scan_id=self._ti_scan(project_id),
            project_id=project_id,
            asset_id=str(asset_id or ""),
            title=_bounded(redact.redact_text(title), 200),
            description=_bounded(redact.redact_text(description), 2000),
            severity=severity,
            confidence="medium" if confidence_score >= 0.5 else "low",
            category=category,
            source=_bounded(source or "ti", 80),
            rule_id=_bounded(rule_id, 64),
            remediation=_bounded(remediation, 500),
            evidence=[], raw=dict(raw or {}),
        )
        return f

    def _emit(self, project_id: str, event_type: str, *, asset_id: str = "",
              key: str = "", source: str = "phase10", confidence: float = 0.5,
              previous_state=None, new_state=None, actor: str = "system",
              org_id: str = "") -> dict | None:
        try:
            return events_mod.SecurityEventService(self.svc).emit(
                project_id, event_type, asset_id=_bounded(asset_id, 64),
                key=_bounded(key, 160), scan_id="", source=source,
                confidence=confidence, previous_state=previous_state,
                new_state=new_state, actor=actor, org_id=org_id)
        except (errors.ValidationError, errors.NotFoundError):
            # unknown event type or missing project → no event (safe);
            # org-scoped operations are still covered by the audit trail
            return None

    def _row(self, conn, sql, params=()):
        cur = conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row is not None else None

    def _maybe(self, sql: str, params=()) -> dict | None:
        """Query-one that returns None instead of raising NotFoundError
        (existence checks)."""
        try:
            return self.db.query_one(sql, params)
        except errors.NotFoundError:
            return None


# ===========================================================================
# §13/§14/§16/§17 — IOC catalog + feeds
# ===========================================================================
class IocCatalogService(_Base):
    """Normalized threat indicators (per-org), source metadata, safe feed
    import (json/csv/STIX-like), lifecycle (active/expired/revoked)."""

    # ------------------------------------------------------------- add/put
    def add(self, org_id: str, indicator: str, *, ioc_type: str | None = None,
            source: str = "manual", confidence_level: str = "medium",
            valid_from: str = "", valid_until: str = "",
            reference: str = "", actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"ti:add:{org_id}", "import")
        nval, t = normalize_indicator(indicator, ioc_type)
        level = self._confidence_level(confidence_level)
        score = models.TI_CONFIDENCE_SCORES[level]
        src = _bounded(redact.redact_text(str(source or "manual")), 80)
        ref = _bounded(redact.redact_text(str(reference or "")), 300)
        valid_until = _bounded(valid_until or "", 32)
        if valid_until:
            try:
                _parse_ts(valid_until)
            except errors.ValidationError:
                raise
        now = _now()
        iid = models.stable_id(models.NS_TI_IOC,
                               f"{org_id}|{t}|{nval}|{src}")
        existing = self._maybe(
            "SELECT * FROM threat_indicators WHERE id=?", (iid,))
        with self.db.transaction() as conn:
            if existing:
                conn.execute(
                    "UPDATE threat_indicators SET confidence=?, "
                    "confidence_level=?, last_seen=?, status=?, "
                    "valid_from=?, valid_until=?, reference=?, updated_at=? "
                    "WHERE id=?",
                    (score, level, now, "active", _bounded(valid_from, 32),
                     valid_until, ref, now, iid))
            else:
                conn.execute(
                    "INSERT INTO threat_indicators (id, org_id, indicator, "
                    "ioc_type, source, confidence, confidence_level, status, "
                    "first_seen, last_seen, valid_from, valid_until, "
                    "reference, created_at, updated_at) VALUES (?,?,?,?,?,"
                    "?,?,?,?,?,?,?,?,?,?)",
                    (iid, org_id, nval, t, src, score, level, "active",
                     now, now, _bounded(valid_from, 32), valid_until, ref,
                     now, now))
        # audit + events AFTER commit: platform.audit/open transactions must
        # never run inside another connection's write txn (WAL: busy → lost)
        if existing:
            self._audit("ioc.updated", object_type="ioc", object_id=iid,
                        org_id=org_id, actor=actor, metadata={"type": t})
        else:
            metrics.inc("phase10_indicators")
            self._audit("ioc.created", object_type="ioc", object_id=iid,
                        org_id=org_id, actor=actor,
                        metadata={"type": t, "source": src})
        return self.get(org_id, iid)

    def _confidence_level(self, level) -> str:
        lv = str(level or "medium").strip().lower()
        if lv not in models.TI_CONFIDENCE_LEVELS:
            raise errors.ValidationError(f"unknown confidence level: {lv!r}")
        return lv

    def get(self, org_id: str, indicator_id: str) -> dict:
        self._org(org_id)
        row = self.db.query_one(
            "SELECT * FROM threat_indicators WHERE id=? AND org_id=?",
            (indicator_id, org_id))
        if not row:
            raise errors.NotFoundError("indicator not found")
        return self._clean(row)

    def _clean(self, row: dict) -> dict:
        out = dict(row)
        return {k: (v if not isinstance(v, (bytes, bytearray)) else "")
                for k, v in out.items()}

    def list(self, org_id: str, *, ioc_type: str = "", status: str = "",
             source: str = "", search: str = "", limit: int = 100,
             offset: int = 0) -> list[dict]:
        self._org(org_id)
        limit = max(1, min(int(limit or 100), 500))
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if ioc_type:
            where.append("ioc_type=?"); args.append(ioc_type)
        if status:
            where.append("status=?"); args.append(status)
        if source:
            where.append("source=?"); args.append(source)
        if search:
            where.append("indicator LIKE ?")
            args.append("%" + str(search)[:80] + "%")
        rows = self.db.query(
            "SELECT * FROM threat_indicators WHERE " + " AND ".join(where) +
            " ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            args + [limit, offset])
        return [self._clean(r) for r in rows]

    def count(self, org_id: str, *, ioc_type: str = "") -> int:
        self._org(org_id)
        where, args = ["org_id=?"], [org_id]
        if ioc_type:
            where.append("ioc_type=?"); args.append(ioc_type)
        row = self.db.query_one(
            "SELECT COUNT(*) n FROM threat_indicators WHERE "
            + " AND ".join(where), args)
        return int(row["n"])

    # ------------------------------------------------------ lifecycle/state
    def update(self, org_id: str, indicator_id: str, *,
               confidence_level: str | None = None, status: str | None = None,
               valid_until: str | None = None, reference: str | None = None,
               actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"ti:update:{org_id}", "import")
        row = self.db.query_one(
            "SELECT * FROM threat_indicators WHERE id=? AND org_id=?",
            (indicator_id, org_id))
        if not row:
            raise errors.NotFoundError("indicator not found")
        sets, args = [], []
        if confidence_level is not None:
            lv = self._confidence_level(confidence_level)
            sets.append("confidence_level=?")
            args.append(lv)
            sets.append("confidence=?")
            args.append(models.TI_CONFIDENCE_SCORES[lv])
        if status is not None:
            st = str(status).strip().lower()
            if st not in models.IOC_STATUSES:
                raise errors.ValidationError(f"unknown ioc status: {st!r}")
            sets.append("status=?"); args.append(st)
        if valid_until is not None:
            sets.append("valid_until=?"); args.append(_bounded(valid_until, 32))
        if reference is not None:
            sets.append("reference=?")
            args.append(_bounded(redact.redact_text(str(reference)), 300))
        if not sets:
            return self.get(org_id, indicator_id)
        sets.append("updated_at=?"); args.append(_now())
        args.append(indicator_id)
        self.db.execute("UPDATE threat_indicators SET " + ", ".join(sets) +
                        " WHERE id=? AND org_id=?", args + [org_id])
        self._audit("ioc.updated", object_type="ioc", object_id=indicator_id,
                    org_id=org_id, actor=actor, metadata={})
        self._emit(org_id, "ioc.updated", key=indicator_id, actor=actor)
        return self.get(org_id, indicator_id)

    def revoke(self, org_id: str, indicator_id: str, *, reason: str,
               actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"ti:revoke:{org_id}", "import")
        if not str(reason or "").strip():
            raise errors.ValidationError("revocation reason is required")
        row = self.db.query_one(
            "SELECT * FROM threat_indicators WHERE id=? AND org_id=?",
            (indicator_id, org_id))
        if not row:
            raise errors.NotFoundError("indicator not found")
        self.db.execute(
            "UPDATE threat_indicators SET status='revoked', updated_at=? "
            "WHERE id=? AND org_id=?", (_now(), indicator_id, org_id))
        self._audit("ioc.revoked", object_type="ioc", object_id=indicator_id,
                    org_id=org_id, actor=actor,
                    metadata={"reason": redact.redact_text(str(reason)[:200])})
        self._emit(org_id, "ioc.revoked", key=indicator_id, actor=actor)
        return self.get(org_id, indicator_id)

    def sweep_expiry(self, org_id: str, *, now: str | None = None,
                     actor: str = "scheduler") -> dict:
        """Deterministic expiry sweep: active + valid_until <= now → expired."""
        self._org(org_id)
        now = now or _now()
        rows = self.db.query(
            "SELECT id, valid_until FROM threat_indicators WHERE org_id=? "
            "AND status='active' AND valid_until<>'' AND valid_until<=?",
            (org_id, now), limit=MAX_FEED_RECORDS)
        for r in rows:
            self.db.execute(
                "UPDATE threat_indicators SET status='expired', updated_at=? "
                "WHERE id=? AND org_id=? AND status='active'",
                (now, r["id"], org_id))
        if rows:
            self._audit("ioc.expired", object_type="ioc",
                        object_id=org_id + ":batch", org_id=org_id,
                        actor=actor,
                        metadata={"count": len(rows)})
        return {"expired": len(rows)}

    # ------------------------------------------------------------- sources
    def sources(self, org_id: str, *, limit: int = 100) -> list[dict]:
        self._org(org_id)
        limit = max(1, min(int(limit or 100), 500))
        return self.db.query(
            "SELECT source, COUNT(*) n, MAX(first_seen) first_seen, "
            "MAX(last_seen) last_seen FROM threat_indicators WHERE org_id=? "
            "GROUP BY source ORDER BY n DESC LIMIT ?", (org_id, limit))

    # ------------------------------------------------------------- export
    def export(self, org_id: str, *, ioc_type: str = "", status: str = "",
               limit: int = 500) -> dict:
        """Deterministic, redacted export of indicator metadata. NEVER
        contains payloads, credentials, private keys or PII beyond the
        indicator value itself (correlation-required, §38)."""
        self._org(org_id)
        self._acquire(f"ti:export:{org_id}", "export")
        limit = max(1, min(int(limit or 500), 5000))
        rows = self.list(org_id, ioc_type=ioc_type, status=status,
                         limit=limit)
        return {
            "generated_at": _now(),
            "count": len(rows),
            "truncated": len(rows) >= limit,
            "indicators": [
                {"indicator": r["indicator"], "type": r["ioc_type"],
                 "source": r["source"], "confidence_level":
                     r["confidence_level"], "status": r["status"],
                 "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                 "valid_from": r["valid_from"], "valid_until":
                     r["valid_until"]}
                for r in rows],
        }

    # ----------------------------------------------------------- feed import
    def _fail(self, msg: str):
        metrics.inc("phase10_feed_import_failures")
        raise errors.ValidationError(msg)

    def import_feed(self, org_id: str, *, name: str, data: str | bytes,
                    fmt: str = "auto", source_type: str = "feed",
                    confidence_level: str = "medium", actor: str = "api") -> dict:
        """Safe feed import (§17): json / csv / STIX-like. Bounded bytes,
        records, fields, field length, nesting, total per-org count. Only
        stdlib json/csv parsing — no pickle, no eval, no YAML. Malformed
        structure → error (no false success); malformed RECORDS are skipped
        with explicit reasons (partial import is reported, not hidden)."""
        self._org(org_id)
        self._acquire(f"ti:import:{org_id}", "import")
        if not str(name or "").strip():
            raise errors.ValidationError("feed name is required")
        if isinstance(data, bytes):
            if len(data) > MAX_FEED_BYTES:
                self._fail("feed_oversized")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as e:
                self._fail("feed_not_utf8")
        else:
            text = str(data or "")
            if len(text.encode("utf-8", "ignore")) > MAX_FEED_BYTES:
                self._fail("feed_oversized")
        if "pickle" in text[:200] or "P" + "ickle" in text[:200]:
            self._fail("feed_unsafe_serialization")
        fmt = str(fmt or "auto").strip().lower()
        if fmt not in ("auto", "json", "csv", "stix"):
            raise errors.ValidationError(f"unknown feed format: {fmt!r}")
        if fmt != "csv":
            records = self._parse_json(text)
        else:
            records, err = self._parse_csv(text)
            if err:
                raise errors.ValidationError(err)
        records = records[:MAX_FEED_RECORDS]
        total = self.count(org_id)
        imported, skipped, errors_list = 0, 0, []
        level = self._confidence_level(confidence_level)
        with self.db.transaction() as conn:
            for idx, rec in enumerate(records):
                if total + imported >= MAX_INDICATORS_PER_ORG:
                    skipped += 1
                    if len(errors_list) < 50:
                        errors_list.append({
                            "line": idx + 2, "reason": "org indicator cap"})
                    continue
                try:
                    indicator = rec.get("indicator") or rec.get("value")
                    if not indicator:
                        raise errors.ValidationError("missing indicator")
                    rtype = rec.get("type") or rec.get("ioc_type")
                    nval, t = normalize_indicator(indicator, rtype)
                    # textual level only; numeric STIX-style confidence
                    # (e.g. 85/100) is mapped through the DETERMINISTIC
                    # buckets below, never trusted as a level name
                    rlevel = rec.get("confidence_level") or level
                    if rlevel in ("", None):
                        rlevel = level
                    if isinstance(rlevel, str) and rlevel.isdigit():
                        num = int(rlevel)
                        rlevel = ("low" if num < 25 else
                                  "medium" if num < 50 else
                                  "high" if num < 75 else "confirmed")
                    rlevel = self._confidence_level(rlevel)
                    rsrc = _bounded(redact.redact_text(str(
                        rec.get("source") or "feed")), 80)
                    iid = models.stable_id(
                        models.NS_TI_IOC, f"{org_id}|{t}|{nval}|{rsrc}")
                    if self._row(conn, "SELECT id FROM threat_indicators "
                                  "WHERE id=?", (iid,)):
                        imported += 1      # deterministic dedup: no second row
                        continue
                    conn.execute(
                        "INSERT INTO threat_indicators (id, org_id, "
                        "indicator, ioc_type, source, confidence, "
                        "confidence_level, status, first_seen, last_seen, "
                        "valid_from, valid_until, reference, created_at, "
                        "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (iid, org_id, nval, t, rsrc,
                         models.TI_CONFIDENCE_SCORES[rlevel], rlevel,
                         "active", _now(), _now(),
                         _bounded(str(rec.get("valid_from") or ""), 32),
                         _bounded(str(rec.get("valid_until") or ""), 32),
                         _bounded(redact.redact_text(str(
                             rec.get("reference") or "")), 300),
                         _now(), _now()))
                    imported += 1
                except errors.ValidationError as e:
                    skipped += 1
                    if len(errors_list) < 50:
                        errors_list.append({"line": idx + 2,
                                            "reason": str(e)[:200]})
        metrics.inc("phase10_indicators", imported)
        metrics.inc("phase10_feed_imports")
        # audit + event AFTER commit (see add() note)
        self._audit("feed.imported", object_type="feed",
                    object_id=_bounded(name, 80), org_id=org_id, actor=actor,
                    metadata={"imported": imported, "skipped": skipped,
                              "fmt": fmt, "source_type":
                                  str(source_type)[:40]})
        self._emit(org_id, "feed.imported",
                   key=f"{name}|{imported}|{skipped}", source=name,
                   actor=actor)
        return {"feed": _bounded(name, 80), "format": fmt,
                "imported": imported, "skipped": skipped,
                "errors": errors_list,
                "records_seen": len(records)}

    def _parse_json(self, text: str) -> list[dict]:
        try:
            obj = json.loads(text)
        except Exception as e:
            raise errors.ValidationError(
                f"feed_malformed: {str(e)[:160]}") from e
        if isinstance(obj, dict):
            if "objects" in obj and isinstance(obj["objects"], list):
                obj = obj["objects"]        # STIX bundle shape
            elif "indicators" in obj and isinstance(obj["indicators"], list):
                obj = obj["indicators"]
            else:
                raise errors.ValidationError(
                    "feed_malformed: expected a list of indicator records")
        if not isinstance(obj, list):
            raise errors.ValidationError("feed_malformed: not a list")
        depth = self._depth(obj)
        if depth > MAX_FEED_NESTING:
            raise errors.ValidationError("feed_too_deep")
        out = []
        for rec in obj[:MAX_FEED_RECORDS]:
            if not isinstance(rec, dict):
                continue
            if len(rec) > MAX_FEED_FIELDS:
                raise errors.ValidationError("feed_record_too_wide")
            clean = {}
            for k, v in rec.items():
                if len(str(k)) > 60:
                    continue
                if isinstance(v, str):
                    if len(v) > MAX_FEED_FIELD_LEN:
                        raise errors.ValidationError("feed_value_too_long")
                    clean[k] = v
                elif isinstance(v, (int, float)):
                    clean[k] = str(v)
                elif v is None:
                    continue
                else:
                    raise errors.ValidationError(
                        "feed_field_not_scalar")
            if "pattern" in clean and not any(
                    k in clean for k in ("indicator", "value")):
                parsed = self._parse_stix_pattern(str(clean["pattern"]))
                if parsed is None:
                    continue                 # unsupported pattern → skip
                iv, it = parsed
                clean["indicator"] = iv
                clean["type"] = it           # derived IOC type wins over the
                clean.pop("pattern", None)   # STIX object type ("indicator")
            out.append(clean)
        return out

    def _parse_stix_pattern(self, pattern: str):
        """Conservative STIX-like extraction: ONLY simple equality patterns
        '[a:b = 'value']'. Never evaluated — regex extraction only."""
        p = str(pattern).strip()
        if not (p.startswith("[") and p.endswith("]")):
            return None
        import re
        m = re.match(r"^\[\s*[\w.:-]+\s*=\s*'([^']+)'\s*\]$", p)
        if not m:
            return None
        value = m.group(1)
        if "://" in value:
            t = "url"
        elif re.match(r"^[0-9.]+$", value) and value.count(".") == 3:
            t = "ipv4"
        elif ":" in value and all(
                c in "0123456789abcdefABCDEF:" for c in value):
            t = "ipv6"
        elif "@" in value:
            t = "email"
        elif all(c in "0123456789abcdefABCDEF" for c in value) and \
                len(value) in (32, 40, 64):
            t = ("hash_sha256" if len(value) == 64 else
                 "hash_sha1" if len(value) == 40 else "hash_md5")
        else:
            t = "hostname" if value.count(".") >= 2 else "domain"
        try:
            return normalize_indicator(value, t)
        except errors.ValidationError:
            return None

    def _parse_csv(self, text: str):
        rows = []
        try:
            reader = csv.DictReader(io.StringIO(text))
            headers = [h.strip().lower() for h in (reader.fieldnames or [])]
            allowed = {"indicator", "value", "type", "ioc_type", "source",
                       "confidence", "confidence_level", "valid_from",
                       "valid_until", "reference"}
            for idx, row in enumerate(reader):
                if idx >= MAX_FEED_RECORDS:
                    break
                if row is None:
                    continue
                rec = {}
                for k, v in (row.items() or []):
                    kk = str(k or "").strip().lower()
                    if kk in allowed and v is not None:
                        rec[kk] = str(v)[:MAX_FEED_FIELD_LEN]
                rows.append(rec)
        except csv.Error as e:
            return [], f"feed_malformed: {str(e)[:160]}"
        return rows, None

    @staticmethod
    def _depth(obj) -> int:
        stack = [(obj, 1)]
        best = 1
        while stack:
            o, d = stack.pop()
            best = max(best, d)
            if best > MAX_FEED_NESTING:
                return best
            if isinstance(o, dict):
                for v in o.values():
                    if isinstance(v, (dict, list)):
                        stack.append((v, d + 1))
            elif isinstance(o, list):
                for v in o:
                    if isinstance(v, (dict, list)):
                        stack.append((v, d + 1))
        return best


def _parse_ts(value: str):
    """ISO-8601 sanity parse (used for IOC validity windows)."""
    v = str(value or "").strip()
    if len(v) < 10 or len(v) > 32:
        raise errors.ValidationError("invalid timestamp")
    from datetime import datetime, timezone
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as e:
        raise errors.ValidationError("invalid timestamp") from e
    return v


# ===========================================================================
# §18/§19 — IOC correlation → existing findings
# ===========================================================================
class ThreatCorrelationService(_Base):
    """Deterministic passive matching of active indicators against the
    EXISTING asset/observation/finding/event data. Matches become normal
    findings via CorrelationService.ingest_finding (dedup/canonical key/
    confidence/risk all reused). threat_matches is a ledger only."""

    def __init__(self, platform, *, limiter=None):
        super().__init__(platform, limiter=limiter)
        self.corr = correlate.CorrelationService(platform)

    def match(self, org_id: str, project_id: str, *,
              ioc_type: str = "", min_confidence: str = MIN_MATCH_CONFIDENCE,
              limit: int = 200) -> dict:
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        self._acquire(f"ti:match:{org_id}", "match")
        mcl = self._confidence_level(min_confidence)
        min_score = models.TI_CONFIDENCE_SCORES[mcl]
        ioc_rows = self.db.query(
            "SELECT * FROM threat_indicators WHERE org_id=? AND "
            "status='active' AND confidence>=? AND "
            "(valid_until='' OR valid_until>=?) "
            "ORDER BY last_seen DESC LIMIT ?",
            (org_id, min_score, _now(), MAX_MATCH_IOCS_PER_RUN))
        # ---- targets (asset values + observations + findings + events) ----
        assets = self.db.query(
            "SELECT a.id, a.asset_type, a.value FROM assets a "
            "JOIN projects p ON p.id=a.project_id WHERE p.org_id=? "
            "LIMIT ?", (org_id, MAX_MATCH_TARGETS_PER_RUN))
        obs = self.db.query(
            "SELECT o.asset_id, o.obs_type, o.obs_value FROM "
            "asset_observations o JOIN projects p ON p.id=o.project_id "
            "WHERE p.org_id=? LIMIT ?", (org_id, MAX_MATCH_TARGETS_PER_RUN))
        findings = self.db.query(
            "SELECT f.id, f.asset_id, f.title, f.description, f.evidence "
            "FROM findings f JOIN projects p ON p.id=f.project_id "
            "WHERE p.org_id=? AND f.lifecycle IN ('open','under_investigation')"
            " AND f.category<>'threat_intel'"
            " LIMIT ?", (org_id, MAX_MATCH_TARGETS_PER_RUN))
        events_rows = self.db.query(
            "SELECT e.id, e.asset_id, e.state_key FROM security_events e "
            "WHERE e.org_id=? LIMIT ?", (org_id, MAX_MATCH_TARGETS_PER_RUN))
        # ---- deterministic matching -------------------------------------
        new_matches, existing = 0, 0
        created_findings = 0
        scanned = 0
        # NOTE: no outer transaction here — finding ingestion, ledger writes
        # and event emits each use their OWN connections/transactions (WAL
        # only supports one writer; nested open transactions would lose
        # audit/event rows). Dedup is guaranteed by the UNIQUE ledger
        # constraint + the canonical finding key.
        for ioc in ioc_rows:
            hits = self._candidates(ioc, assets, obs, findings, events_rows)
            for (kind, ref_id, asset_id, needle) in hits:
                scanned += 1
                if scanned > limit * 100:
                    break
                finding_id, _is_new = self._match_one(
                    project_id, ioc, kind, ref_id, asset_id)
                if finding_id is None:
                    continue
                affected = self.db.execute_affected(
                    "INSERT OR IGNORE INTO threat_matches (id, org_id, "
                    "project_id, indicator_id, finding_id, asset_id, "
                    "ioc_type, matched_on, fingerprint, first_seen, "
                    "last_seen, match_count, status) VALUES (?,?,?,?,?,?,?,"
                    "?,?,?,?,?,?)",
                    (models.stable_id(models.NS_TI_MATCH,
                                      f"{org_id}|{ioc['id']}|{finding_id}"),
                     org_id, project_id, ioc["id"], finding_id,
                     _bounded(asset_id, 64), ioc["ioc_type"],
                     _bounded(kind, 32),
                     models.stable_id(models.NS_FINDING,
                                      f"{project_id}|{ioc['id']}|{ref_id}"),
                     _now(), _now(), 1, "active"))
                if affected == 1:
                    new_matches += 1
                    # a NEW ledger row implies a newly linked finding
                    # (the ledger insert follows finding ingest in the same
                    # flow), so findings_created counts real creations only:
                    created_findings += 1
                    self._emit(project_id, "ioc.matched",
                               key=f"{ioc['id']}|{finding_id}",
                               source=ioc["source"],
                               confidence=ioc["confidence"],
                               actor="correlation")
                else:
                    self.db.execute(
                        "UPDATE threat_matches SET last_seen=?, "
                        "match_count=match_count+1 WHERE indicator_id=? AND "
                        "finding_id=?", (_now(), ioc["id"], finding_id))
                    existing += 1
            if scanned > limit * 100:
                break
        self._audit("ioc.matched", object_type="match",
                    object_id=f"{org_id}:{project_id}:new={new_matches}",
                    org_id=org_id, project_id=project_id, actor="correlation",
                    metadata={"new": new_matches, "existing": existing,
                              "scanned": scanned})
        return {"project_id": project_id, "iocs_evaluated": len(ioc_rows),
                "candidates_scanned": scanned, "new_matches": new_matches,
                "existing_matches": existing,
                "findings_created": created_findings}

    def _candidates(self, ioc: dict, assets, obs, findings, events_rows):
        """Deterministic candidate enumeration for one IOC. Yields
        (kind, ref_id, asset_id, needle) tuples with bounded output."""
        out = []
        val = ioc["indicator"]
        t = ioc["ioc_type"]
        vlow = val.lower()
        for a in assets:
            if self._value_matches(t, vlow, a["value"]):
                out.append(("asset", a["id"], a["id"], a["value"]))
                if len(out) >= 2000:
                    return out
        for o in obs:
            if self._value_matches(t, vlow, o["obs_value"]):
                out.append(("observation", o["asset_id"], o["asset_id"],
                            o["obs_value"]))
                if len(out) >= 2000:
                    return out
        for f in findings:
            hay = " ".join([str(f.get("title") or ""),
                            str(f.get("description") or "")])
            if self._value_matches(t, vlow, hay):
                out.append(("finding", f["id"], str(f.get("asset_id") or ""),
                            hay))
                if len(out) >= 2000:
                    return out
        for e in events_rows:
            if self._value_matches(t, vlow, str(e.get("state_key") or "")):
                out.append(("event", e["id"], str(e.get("asset_id") or ""),
                            str(e.get("state_key") or "")))
                if len(out) >= 2000:
                    return out
        return out

    @staticmethod
    def _value_matches(t: str, vlow: str, haystack: str) -> bool:
        """Deterministic matching discipline (never regex — exact/bounded):
        hashes + emails + fingerprints: exact substring (case-insensitive,
        after normalization happens at ingest); IPs: exact token match;
        domains/hostnames/URLs: substring with boundary discipline."""
        hay = str(haystack or "")
        if not hay or len(hay) > 100_000:
            return False
        hl = hay.lower()
        if t in ("hash_md5", "hash_sha1", "hash_sha256",
                 "cert_fingerprint", "email"):
            return vlow in hl
        if t in ("ipv4", "ipv6"):
            import re
            esc = re.escape(vlow)
            return re.search(r"(?<![0-9a-f.:])" + esc + r"(?![0-9a-f.:])", hl) \
                is not None
        # domain / hostname / url: match the value or its host form
        return vlow in hl

    def _match_one(self, project_id, ioc, kind, ref_id,
                   asset_id) -> tuple[str | None, bool]:
        """Create-or-refresh ONE finding for an IOC match. Existing finding
        (canonical fingerprint) → no new row (dedup); missing → ingest.
        Returns (finding_id, is_new)."""
        if not project_id:
            return None, False
        t = ioc["ioc_type"]
        severity = TI_CONFIDENCE_TO_SEVERITY[ioc["confidence_level"]]
        title = f"IOC match: {ioc['indicator'][:80]}"
        rule_id = "TI-IOC-" + t.upper().replace("_", "-")
        desc = (f"Indicator {ioc['indicator']} (type={t}, "
                f"source={ioc['source']}, confidence="
                f"{ioc['confidence_level']}) matched a {kind} record. "
                f"IOC validity: {ioc.get('valid_from') or 'n/a'} → "
                f"{ioc.get('valid_until') or 'n/a'}. Review and remediate "
                "through the existing workflow.")
        f = self._finding(
            project_id, rule_id=rule_id, title=title, description=desc,
            severity=severity, category="threat_intel", asset_id=asset_id,
            confidence_score=ioc["confidence"], source="ti:" +
            str(ioc["source"]),
            remediation="Review the matched record; block/quarantine only "
            "through an explicit manual workflow.",
            raw={"indicator": ioc["indicator"], "ioc_type": t,
                 "ioc_source": ioc["source"],
                 "matched_on": {"kind": kind, "ref": ref_id}})
        f.evidence = [
            models.Evidence(finding_id="", evidence_type="other",
                            detection_reason=f"ioc:{ioc['indicator'][:200]}",
                            scanner="ti", rule_id=rule_id,
                            captured_at=_now())]
        try:
            res = self.corr.ingest_finding(f, f.evidence, scan_id=f.scan_id,
                                           raw=f.raw)
            out_id = res.get("finding_id") or res.get("id") or f.id
            if res.get("deduped"):
                metrics.inc("phase10_match_deduped")
                return out_id, False
            metrics.inc("phase10_matches")
            return out_id, True
        except errors.NotFoundError:
            # missing asset → still link to asset-less finding (asset_id="")
            f.asset_id = ""
            res = self.corr.ingest_finding(f, f.evidence, scan_id=f.scan_id,
                                           raw=f.raw)
            return (res.get("finding_id") or f.id), bool(
                not res.get("deduped"))

    def matches_list(self, org_id: str, *, project_id: str = "",
                     finding_id: str = "", indicator_id: str = "",
                     limit: int = 100, offset: int = 0) -> list[dict]:
        self._org(org_id)
        limit = max(1, min(int(limit or 100), 500))
        offset = max(0, int(offset or 0))
        where, args = ["m.org_id=?"], [org_id]
        if project_id:
            where.append("m.project_id=?"); args.append(project_id)
        if finding_id:
            where.append("m.finding_id=?"); args.append(finding_id)
        if indicator_id:
            where.append("m.indicator_id=?"); args.append(indicator_id)
        return self.db.query(
            "SELECT m.*, i.indicator, i.ioc_type FROM threat_matches m "
            "JOIN threat_indicators i ON i.id=m.indicator_id WHERE "
            + " AND ".join(where) +
            " ORDER BY m.last_seen DESC LIMIT ? OFFSET ?",
            args + [limit, offset])

    def matches_count(self, org_id: str) -> int:
        self._org(org_id)
        return int(self.db.query_one(
            "SELECT COUNT(*) n FROM threat_matches WHERE org_id=?",
            (org_id,))["n"])

    def _confidence_level(self, level) -> str:
        lv = str(level or "medium").strip().lower()
        if lv not in models.TI_CONFIDENCE_LEVELS:
            raise errors.ValidationError(f"unknown confidence level: {lv!r}")
        return lv


# ===========================================================================
# §23 — prioritization (reuses RiskEngine; documented formula)
# ===========================================================================
class ThreatPrioritizationService(_Base):
    """Rank open threat-intel findings using the EXISTING RiskEngine —
    threat context (IOC confidence, asset criticality, exposure) enters ONLY
    through the engine's documented inputs. No second risk engine."""

    def __init__(self, platform, *, limiter=None):
        super().__init__(platform, limiter=limiter)
        self.risk = risk_mod.RiskEngine()

    def prioritize(self, org_id: str, project_id: str, *,
                   limit: int = 100) -> list[dict]:
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        self._acquire(f"ti:prio:{org_id}", "cluster")
        limit = max(1, min(int(limit or 100), 500))
        rows = self.db.query(
            "SELECT f.*, m.indicator_id, i.confidence_level ioc_conf, "
            "i.indicator FROM findings f "
            "JOIN threat_matches m ON m.finding_id=f.id "
            "JOIN threat_indicators i ON i.id=m.indicator_id "
            "WHERE f.project_id=? AND f.category='threat_intel' AND "
            "f.lifecycle IN ('open','under_investigation') "
            "ORDER BY f.last_detected DESC LIMIT ?", (project_id, limit * 4))
        out = []
        for r in rows:
            crit = self._criticality(r.get("asset_id") or "")
            exposure = self._exposure(r.get("asset_id") or "")
            conf_score = models.TI_CONFIDENCE_SCORES.get(
                r.get("ioc_conf") or "unknown", 0.3)
            base = self.risk.compute(
                severity=r.get("severity") or "Info",
                confidence_score=conf_score,
                exposure=exposure or "unknown",
                criticality=crit or "unknown",
                category=r.get("category") or "threat_intel",
                rule_id=r.get("rule_id") or "")
            score = base.get("risk_score", 0.0)
            out.append({
                "finding_id": r["id"], "rule_id": r.get("rule_id"),
                "indicator": r.get("indicator"), "severity":
                    r.get("severity"),
                "ioc_confidence": r.get("ioc_conf"),
                "asset_criticality": crit, "asset_exposure": exposure,
                "risk_score": score, "risk_level": base.get("risk_level"),
                "priority": self.risk.priority_for(
                    score, conf_score, exposure or "unknown",
                    crit or "unknown")[0],
            })
        out.sort(key=lambda x: (-x["risk_score"], x["finding_id"]))
        return out[:limit]

    def _criticality(self, asset_id: str) -> str:
        if not asset_id:
            return "unknown"
        row = self._maybe(
            "SELECT criticality FROM assets WHERE id=?", (asset_id,))
        val = str(row["criticality"]) if row else ""
        return val if val in ("unknown", "low", "medium", "high",
                              "critical") else "unknown"

    def _exposure(self, asset_id: str) -> str:
        if not asset_id:
            return "unknown"
        row = self._maybe(
            "SELECT exposure FROM assets WHERE id=?", (asset_id,))
        val = str(row["exposure"]) if row else ""
        return val if val in ("internet_facing", "internal", "restricted",
                              "unknown") else "unknown"


# ===========================================================================
# §21/§47 — deterministic, non-attributing threat clusters
# ===========================================================================
class ThreatClusterService(_Base):
    """Group related matches/findings via deterministic signals (same
    indicator, same asset, same IP/domain/fingerprint, same time window).
    Neutral labels only — NEVER actor or group names (§21/§47)."""

    def __init__(self, platform, *, limiter=None):
        super().__init__(platform, limiter=limiter)
        self.corr = correlate.CorrelationService(platform)

    def build(self, org_id: str, project_id: str, *,
              window_hours: int = 168) -> dict:
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        self._acquire(f"ti:cluster:{org_id}", "cluster")
        wh = max(1, min(int(window_hours or 168), 24 * 90))
        rows = self.db.query(
            "SELECT m.finding_id, m.indicator_id, m.asset_id, "
            "m.first_seen, i.indicator, i.ioc_type FROM threat_matches m "
            "JOIN threat_indicators i ON i.id=m.indicator_id "
            "WHERE m.org_id=? AND m.project_id=? ORDER BY m.first_seen DESC "
            "LIMIT 20000", (org_id, project_id))
        if not rows:
            return {"clusters_updated": 0}
        # ---- deterministic signal extraction ------------------------------
        from collections import defaultdict
        groups: dict[str, set] = defaultdict(set)      # signal -> ref ids
        for r in rows:
            h = {"ioc:" + r["indicator_id"]}
            if r["asset_id"]:
                h.add("asset:" + r["asset_id"])
            for dom in self._domains_from_value(r.get("indicator") or ""):
                h.add("domain:" + dom)
            for ip in self._ips_from_value(r.get("indicator") or ""):
                h.add("ip:" + ip)
            for sig in h:
                groups[sig].add(r["finding_id"])
        updated = 0
        new_cluster_ids: list[str] = []
        with self.db.transaction() as conn:
            for sig, finding_ids in sorted(groups.items()):
                if len(finding_ids) < 2:
                    continue
                ckey = models.stable_id(models.NS_THREAT_CLUSTER,
                                        f"{project_id}|{sig}")
                kind = self._kind(sig, finding_ids)
                label = models.THREAT_CLUSTER_LABELS[kind]
                now = _now()
                row = self._row(conn,
                                "SELECT * FROM threat_clusters WHERE "
                                "cluster_key=? AND project_id=?",
                                (ckey, project_id))
                if row:
                    conn.execute(
                        "UPDATE threat_clusters SET member_count=?, "
                        "last_seen=?, updated_at=? WHERE id=?",
                        (len(finding_ids), now, now, row["id"]))
                    cid = row["id"]
                else:
                    cid = models.stable_id(models.NS_THREAT_CLUSTER,
                                           f"{project_id}|{sig}") + "" \
                        if False else None
                    cid = models.stable_id(
                        models.NS_THREAT_CLUSTER,
                        f"{project_id}|cluster|{sig}")
                    conn.execute(
                        "INSERT OR IGNORE INTO threat_clusters (id, org_id, "
                        "project_id, cluster_key, label, kind, member_count, "
                        "first_seen, last_seen, created_at, updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (cid, org_id, project_id, ckey, label, kind,
                         len(finding_ids), now, now, now, now))
                    updated += 1
                for fid in finding_ids:
                    mid = models.stable_id(
                        models.NS_THREAT_MEMBER, f"{cid}|finding|{fid}")
                    conn.execute(
                        "INSERT OR IGNORE INTO threat_cluster_members (id, "
                        "cluster_id, org_id, ref_type, ref_id, added_at) "
                        "VALUES (?,?,?,?,?,?)",
                        (mid, cid, org_id, "finding", fid, now))
                if row is None:
                    new_cluster_ids.append(cid)
        # events AFTER commit (WAL: one writer; never emit inside a txn)
        for cid in new_cluster_ids:
            self._emit(project_id, "threat_cluster.updated", key=cid,
                       source="phase10", actor="cluster")
        self._audit("threat.cluster_built", object_type="cluster",
                    object_id=project_id, org_id=org_id, project_id=project_id,
                    actor="cluster", metadata={"clusters": updated})
        metrics.inc("phase10_clusters", updated)
        return {"clusters_updated": updated, "signals": len(groups)}

    @staticmethod
    def _domains_from_value(v: str) -> list[str]:
        v = str(v or "").lower()
        out = []
        for tok in v.split():
            try:
                d = normalize_domain(tok)
                out.append(d)
            except errors.ValidationError:
                continue
        return out[:4]

    @staticmethod
    def _ips_from_value(v: str) -> list[str]:
        import re
        out = []
        for tok in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", str(v or "")):
            try:
                out.append(normalize_ipv4(tok))
            except errors.ValidationError:
                continue
        return out[:4]

    @staticmethod
    def _kind(sig: str, finding_ids: set) -> str:
        """Deterministic neutral kind: indicator-only groups stay
        'indicator_cluster'; groups spanning multiple assets or a domain
        signal become 'related_activity'; a 3+-signal overlap becomes
        'campaign_like'. No attribution semantics."""
        if "domain:" in sig or "ip:" in sig:
            return "campaign_like"
        if len(finding_ids) >= 3:
            return "related_activity"
        return "indicator_cluster"

    def list(self, org_id: str, *, project_id: str = "", limit: int = 100,
             offset: int = 0) -> list[dict]:
        self._org(org_id)
        limit = max(1, min(int(limit or 100), 500))
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if project_id:
            where.append("project_id=?"); args.append(project_id)
        return self.db.query(
            "SELECT * FROM threat_clusters WHERE " + " AND ".join(where) +
            " ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            args + [limit, offset])

    def members(self, org_id: str, cluster_id: str, *,
                limit: int = 100) -> list[dict]:
        self._org(org_id)
        limit = max(1, min(int(limit or 100), 500))
        row = self.db.query_one(
            "SELECT * FROM threat_clusters WHERE id=? AND org_id=?",
            (cluster_id, org_id))
        if not row:
            raise errors.NotFoundError("cluster not found")
        return self.db.query(
            "SELECT * FROM threat_cluster_members WHERE cluster_id=? "
            "ORDER BY added_at DESC LIMIT ?", (cluster_id, limit))


# ===========================================================================
# §7–§12 — external attack surface (extensions of Asset Intelligence)
# ===========================================================================
class AttackSurfaceService(_Base):
    """Ingest authorized external-asset observations into the EXISTING
    Asset/AssetObservation/AssetRelation model, generate deterministic
    discovery events + exposure/change findings, and validate cert
    metadata. Passive: no fetch, no DNS, no crawls (§39/§40)."""

    def __init__(self, platform, *, limiter=None):
        super().__init__(platform, limiter=limiter)
        self.intel_svc = intel.IntelService(platform)
        self.corr = correlate.CorrelationService(platform)

    # ------------------------------------------------------------- ingestion
    def ingest(self, org_id: str, project_id: str, *, entries: list[dict],
               source: str = "passive", actor: str = "api") -> dict:
        """entries: [{type, value, confidence?, extra?, parent?}]
        asset types: domain|subdomain|hostname|ip|ipv6|url|service|port|
        technology|cloud_resource|certificate."""
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        self._acquire(f"as:ingest:{org_id}", "surface")
        entries = list(entries or [])[:MAX_SURFACE_ENTRIES]
        created, observed, rejected = [], 0, 0
        errors_list = []
        for idx, e in enumerate(entries):
            if not isinstance(e, dict):
                rejected += 1
                continue
            try:
                atype = str(e.get("type") or "").strip().lower()
                if atype not in models.ASSET_TYPES:
                    raise errors.ValidationError(
                        f"unknown asset type {atype!r}")
                value = str(e.get("value") or "").strip()
                if not value:
                    raise errors.ValidationError("missing value")
                # scope enforcement (§40): ingest only authorized targets
                if atype in ("domain", "subdomain", "hostname", "url", "ip",
                             "ipv6"):
                    guard_value = value if atype != "url" else str(
                        urllib.parse.urlsplit(value).hostname or value)
                    try:
                        scope_mod.guard_target(guard_value)
                    except errors.ScopeViolationError:
                        raise errors.ScopeViolationError(
                            "target outside authorized scope")
                if atype in ("domain", "subdomain", "hostname"):
                    value = normalize_hostname(value) if atype == "hostname" \
                        else normalize_domain(value)
                elif atype == "ip":
                    value = normalize_ipv4(value)
                elif atype == "ipv6":
                    value = normalize_ipv6(value)
                elif atype == "url":
                    value = normalize_url(value)
                asset = self.svc.asset_add(
                    project_id, atype, value,
                    metadata={"source": _bounded(source, 80),
                              "confidence": min(1.0, max(0.0, float(
                                  e.get("confidence", 0.5))))})
                asset_id = asset.id
                obs_meta = dict(e.get("extra") or {})
                if not self._observed_before(project_id, asset_id,
                                             atype, value):
                    self._emit(project_id, self._discovery_event(atype),
                               asset_id=asset_id,
                               key=_bounded(f"{atype}:{value}", 160),
                               source=_bounded(source, 80),
                               confidence=float(
                                   e.get("confidence", 0.5)), actor=actor)
                observed += 1
                created.append(asset_id)
                # parent/topology relations
                parent = e.get("parent")
                if parent:
                    self._relate(org_id, project_id, asset_id, atype, parent,
                                 actor)
            except errors.ValidationError as ex:
                rejected += 1
                if len(errors_list) < 50:
                    errors_list.append({"line": idx + 1,
                                        "reason": str(ex)[:200]})
            except errors.ScopeViolationError as ex:
                rejected += 1
                if len(errors_list) < 50:
                    errors_list.append({"line": idx + 1,
                                        "reason": str(ex)[:160]})
        metrics.inc("phase10_surface_observations", observed)
        self._audit("attack_surface.scan", object_type="attack_surface",
                    object_id=project_id, org_id=org_id, project_id=project_id,
                    actor=actor,
                    metadata={"accepted": len(created), "rejected": rejected,
                              "source": _bounded(source, 80)})
        self._emit(project_id, "attack_surface.scanned", key=project_id,
                   source=_bounded(source, 80), actor=actor,
                   new_state={"accepted": len(created),
                              "rejected": rejected})
        return {"accepted": len(created), "observed": observed,
                "rejected": rejected, "errors": errors_list}

    def _observed_before(self, project_id, asset_id, obs_type, value) -> bool:
        row = self._maybe(
            "SELECT 1 x FROM asset_observations WHERE asset_id=? AND "
            "obs_type=? AND obs_value=?", (asset_id, obs_type, value[:300]))
        return row is not None

    def _discovery_event(self, atype: str) -> str:
        return {
            "domain": "domain.discovered",
            "subdomain": "subdomain.discovered",
            "hostname": "hostname.discovered",
            "ip": "ip.discovered",
            "ipv6": "ip.discovered",
            "url": "hostname.discovered",
            "service": "service.discovered",
            "cloud_resource": "cloud_resource.discovered",
        }.get(atype, "attack_surface.changed")

    def _relate(self, org_id, project_id, asset_id, atype, parent, actor):
        pv = str(parent or "").strip()[:255]
        if not pv:
            return
        try:
            if atype in ("subdomain", "hostname"):
                ptype, rel = "domain", "subdomain_of"
            elif atype == "ip":
                ptype, rel = "domain", "resolves_to"
            elif atype == "url":
                ptype, rel = "hostname", "serves"
            else:
                return
            pnorm = normalize_domain(pv) if ptype != "hostname" else \
                normalize_hostname(pv)
            par = self.svc.asset_add(project_id, ptype, pnorm)
            self.intel_svc.relate(project_id, from_asset_id=asset_id,
                                  to_asset_id=par.id, rel_type=rel,
                                  source="phase10")
        except (errors.ValidationError, Exception):
            # relation failures must not fail the ingest batch; they are
            # data-level, logged, not swallowed silently
            _LOG.warn("attack-surface relation failed", asset=asset_id,
                      parent=_bounded(pv, 80))

    # ------------------------------------------------------ certificates §11
    def certificate_register(self, org_id: str, project_id: str, *,
                             asset_id: str, subject: str, issuer: str,
                             sans: list[str], valid_from: str, valid_to: str,
                             fingerprint: str, key_algorithm: str = "",
                             signature_algorithm: str = "",
                             source: str = "passive",
                             actor: str = "api") -> dict:
        """Certificate metadata intelligence. NEVER accepts/stores private
        keys — any key material passed here is REJECTED. Findings from
        expiry/mismatch/weak-algo/SAN checks only (§11: age is never a
        vulnerability on its own)."""
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        self._acquire(f"as:cert:{org_id}", "surface")
        if "private" in " ".join(sans).lower() or "private_key" in str(
                sans).lower():
            raise errors.ValidationError("private key material rejected")
        fp = normalize_fingerprint(fingerprint)
        sfp = _bounded(redact.redact_text(str(subject)), 300)
        isr = _bounded(redact.redact_text(str(issuer)), 300)
        san_list = [normalize_domain(str(s).strip().lower())
                    for s in (sans or []) if str(s).strip()][:30]
        ka = _bounded(str(key_algorithm or ""), 60).lower()
        sa = _bounded(str(signature_algorithm or ""), 60).lower()
        try:
            vf = _parse_ts(valid_from)
            vt = _parse_ts(valid_to)
        except errors.ValidationError:
            raise
        # association: asset (hostname/domain/url — or a certificate asset
        # keyed by fingerprint) ← certificate metadata. Tenant verified.
        if asset_id:
            own = self.db.query_one(
                "SELECT 1 x FROM assets WHERE id=? AND project_id=?",
                (asset_id, project_id))
            if not own:
                raise errors.NotFoundError("asset not found")
        else:
            asset_id = self.svc.asset_add(
                project_id, "certificate", fp,
                metadata={"source": _bounded(source, 80),
                          "subject": sfp}).id
        self.intel_svc.observe(
            asset_id, "certificate", obs_key="fingerprint",
            obs_value=fp, source=source, confidence=0.9,
            extra={"subject": sfp, "issuer": isr,
                   "valid_from": vf, "valid_to": vt})
        for k, v in (("cert_subject", sfp), ("cert_issuer", isr),
                     ("key_algorithm", ka), ("signature_algorithm", sa),
                     ("expiry", vt)):
            if v:
                self.intel_svc.observe(asset_id, k, obs_value=v[:300],
                                       source=source, confidence=0.8)
        for san in san_list:
            self.intel_svc.observe(asset_id, "cert_san", obs_value=san,
                                   source=source, confidence=0.8)
        if not self._observed_before(project_id, asset_id, "certificate", fp):
            self._emit(project_id, "certificate.discovered", asset_id=asset_id,
                       key=fp, source=_bounded(source, 80), actor=actor)
        findings = []
        asset = self.db.query_one(
            "SELECT value, asset_type FROM assets WHERE id=? AND "
            "project_id=?", (asset_id, project_id))
        asset_value = str(asset["value"]) if asset else ""
        now = _now()
        from datetime import datetime, timezone
        try:
            vto = datetime.fromisoformat(vt.replace("Z", "+00:00"))
            days_left = (vto - datetime.now(timezone.utc)).days
        except Exception:
            days_left = 9999
        if days_left < 0:
            findings.append(self._finding(
                project_id, rule_id="AS-CERT-EXPIRED-001",
                title=f"Certificate expired: {asset_value or fp}",
                description=f"Certificate for {asset_value or fp} expired on "
                            f"{vt} (fingerprint {fp[:16]}…).",
                severity="High", category="exposure",
                asset_id=asset_id, confidence_score=0.95,
                source="as:certificate",
                remediation="Replace the certificate before exposure",
                raw={"fingerprint": fp, "valid_to": vt}))
            self._emit(project_id, "certificate.expired", asset_id=asset_id,
                       key=fp, actor=actor)
        elif days_left <= 30:
            findings.append(self._finding(
                project_id, rule_id="AS-CERT-EXPIRING-002",
                title=f"Certificate expiring soon: {asset_value or fp}",
                description=f"Certificate expires {vt} "
                            f"({days_left} days remaining).",
                severity="Medium", category="exposure",
                asset_id=asset_id, confidence_score=0.9,
                source="as:certificate",
                remediation="Renew before expiry; automate renewal",
                raw={"fingerprint": fp, "valid_to": vt}))
            self._emit(project_id, "certificate.expiring", asset_id=asset_id,
                       key=fp, actor=actor)
        weak = sa in ("sha1", "md5", "sha1withrsa", "md5withrsa",
                      "sha1withecdsa") or \
            ("rsa" in ka and "2048" not in ka and "4096" not in ka) or \
            ka in ("dsa",)
        if weak:
            findings.append(self._finding(
                project_id, rule_id="AS-CERT-WEAK-004",
                title=f"Weak certificate algorithm: {asset_value or fp}",
                description=f"key_algo={ka or '?'}, "
                            f"sig_algo={sa or '?'}.",
                severity="Medium", category="misconfiguration",
                asset_id=asset_id, confidence_score=0.85,
                source="as:certificate",
                remediation="Use SHA-256+ signatures and ≥2048-bit RSA",
                raw={"fingerprint": fp, "key_algorithm": ka,
                     "signature_algorithm": sa}))
        host_like = str(asset["asset_type"]) in (
            "hostname", "domain", "subdomain", "url") if asset else False
        if host_like and asset_value and san_list:
            host_labels = asset_value.lower().split(".")
            mismatch = True
            for san in san_list:
                # wildcard SAN matches one label depth
                if san == asset_value.lower():
                    mismatch = False
                    break
                if san.startswith("*."):
                    base = asset_value.lower()
                    if base.endswith(san[1:]) and \
                            base.count(".") == san.count("."):
                        mismatch = False
                        break
            if mismatch:
                findings.append(self._finding(
                    project_id, rule_id="AS-CERT-MISMATCH-003",
                    title=f"Certificate hostname mismatch: {asset_value}",
                    description=f"Asset {asset_value} not covered by SANs "
                                f"{', '.join(san_list[:5])}.",
                    severity="Medium", category="misconfiguration",
                    asset_id=asset_id, confidence_score=0.8,
                    source="as:certificate",
                    remediation="Issue a certificate covering all hostnames",
                    raw={"fingerprint": fp, "sans": san_list[:10]}))
        bad_san = [s for s in san_list if _registrable(s) !=
                   _registrable(asset_value)] if (host_like and
                                                  asset_value) else []
        if bad_san:
            findings.append(self._finding(
                project_id, rule_id="AS-CERT-UNEXPECTED-SAN-005",
                title=f"Unexpected SAN on certificate: {asset_value}",
                description=f"SANs outside the asset's registrable domain: "
                            f"{', '.join(bad_san[:5])}.",
                severity="Low", category="misconfiguration",
                asset_id=asset_id, confidence_score=0.7,
                source="as:certificate",
                remediation="Review SAN inclusion; verify certificate "
                            "ownership",
                raw={"fingerprint": fp, "bad_sans": bad_san[:10]}))
        ingest_results = []
        for f in findings:
            try:
                res = self.corr.ingest_finding(f, f.evidence or [],
                                               scan_id=f.scan_id, raw=f.raw)
                ingest_results.append(
                    res.get("finding_id") or res.get("id") or f.id)
            except Exception as ex:
                _LOG.warn("certificate finding ingest failed",
                          error=str(ex)[:160])
        self._audit("certificate.registered", object_type="certificate",
                    object_id=fp[:40], org_id=org_id,
                    project_id=project_id, actor=actor,
                    metadata={"subject": sfp[:80], "findings":
                              len(findings)})
        return {"fingerprint": fp, "sans": san_list, "checks_run": 5,
                "findings": ingest_results}

    # ------------------------------------------------------- exposure deltas
    def exposure_changes(self, org_id: str, project_id: str, *,
                         limit: int = 100) -> list[dict]:
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        limit = max(1, min(int(limit or 100), 500))
        return self.db.query(
            "SELECT e.* FROM security_events e WHERE e.org_id=? AND "
            "e.project_id=? AND (e.event_type='exposure.changed' OR "
            "e.event_type='service.opened' OR e.event_type='service.closed' "
            "OR e.event_type='attack_surface.changed') "
            "ORDER BY e.ts DESC LIMIT ?", (org_id, project_id, limit))

    # ------------------------------------------------------------- inventory
    def inventory(self, org_id: str, project_id: str, *,
                  asset_type: str = "", limit: int = 100,
                  offset: int = 0) -> dict:
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        limit = max(1, min(int(limit or 100), 500))
        offset = max(0, int(offset or 0))
        where, args = ["a.project_id=?"], [project_id]
        if asset_type:
            where.append("a.asset_type=?"); args.append(asset_type)
        rows = self.db.query(
            "SELECT a.id, a.asset_type, a.value, a.first_seen, a.last_seen, "
            "a.status FROM assets a WHERE " + " AND ".join(where) +
            " ORDER BY a.last_seen DESC LIMIT ? OFFSET ?",
            args + [limit, offset])
        return {"count": len(rows), "assets": rows}


def _registrable(host: str) -> str:
    """Deterministic 'registrable-ish' suffix for the unexpected-SAN check:
    last two labels (documented simplification — no PSL dependency)."""
    labels = (host or "").split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


# ===========================================================================
# §25/§26/§27 — investigation cases (references EXISTING records)
# ===========================================================================
class InvestigationCaseService(_Base):
    """Analyst case abstraction. Cases REFERENCE existing findings/assets/
    observations/IOCs/evidence/alerts/remediation (verified, tenant-scoped).
    Deterministic timeline; full audit; no duplicated evidence."""

    _TRANSITIONS = {
        "open": ("investigating", "contained", "resolved", "closed"),
        "investigating": ("contained", "resolved", "closed", "open"),
        "contained": ("investigating", "resolved", "closed"),
        "resolved": ("closed",),
        "closed": ("open",),                    # explicit reopen only
    }

    def create(self, org_id: str, project_id: str, *, title: str,
               description: str = "", priority: str = "medium",
               owner: str = "", dedup_key: str = "",
               actor: str = "api") -> dict:
        """Open an investigation case.

        Case identity is deterministic so that re-processing the SAME
        input never creates a second case. By default the identity is
        (org, project, title, day) — correct for operator-driven cases,
        where "the same case title re-opened on the same day" is the same
        case.

        Automated producers (integration inbound callbacks, federated
        package imports) MUST pass `dedup_key`: a caller-owned identity
        such as an external event id. Two genuinely distinct external
        events that happen to share a title on the same day are then
        distinct cases, while a replay of the SAME external event
        re-resolves to the SAME case. Without it those events would
        collide on the day-bucket identity.
        """
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        self._acquire(f"case:{org_id}", "case")
        title = _bounded(redact.redact_text(str(title or "").strip()),
                         MAX_CASE_TITLE)
        if len(title) < 3:
            raise errors.ValidationError("case title too short")
        desc = _bounded(redact.redact_text(str(description or "")),
                        MAX_CASE_DESC)
        pri = self._priority(priority)
        ow = _bounded(str(owner or "").strip(), 128)
        now = _now()
        key = _bounded(str(dedup_key or "").strip(), 200)
        cid = models.stable_id(
            models.NS_CASE,
            f"{org_id}|{project_id}|{key}" if key else
            f"{org_id}|{project_id}|{title}|{now[:10]}")
        existing = self._maybe(
            "SELECT id FROM investigation_cases WHERE id=?", (cid,))
        if existing is not None:
            # idempotent re-processing: the identical input resolves to the
            # case that already exists (never a second case, never a raw
            # database integrity error surfacing to the caller)
            return self.get(org_id, cid)
        try:
            self.db.execute(
                "INSERT INTO investigation_cases (id, org_id, project_id, "
                "title, description, status, priority, owner, created_by, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (cid, org_id, project_id, title, desc, "open", pri, ow,
                 _bounded(actor, 128), now, now))
        except Exception as e:
            if "UNIQUE" in str(e):
                # lost a concurrent race for the same identity — the winner's
                # case is the answer (idempotent, never a duplicate)
                return self.get(org_id, cid)
            raise errors.PersistenceError(f"case create failed: {e}") from e
        metrics.inc("phase10_cases_created")
        self._audit("case.created", object_type="case", object_id=cid,
                    org_id=org_id, project_id=project_id, actor=actor,
                    metadata={"title": title})
        self._entry(org_id, cid, project_id, "case.created",
                    "Case created", actor=actor)
        self._emit(project_id, "case.created", key=cid, actor=actor)
        return self.get(org_id, cid)

    def _priority(self, value) -> str:
        p = str(value or "medium").strip().lower()
        if p not in models.CASE_PRIORITIES:
            raise errors.ValidationError(f"unknown priority: {p!r}")
        return p

    def _status(self, value) -> str:
        s = str(value or "").strip().lower()
        if s not in models.CASE_STATUSES:
            raise errors.ValidationError(f"unknown status: {s!r}")
        return s

    def _row(self, case_id: str, org_id: str) -> dict | None:
        r = self.db.query_one(
            "SELECT * FROM investigation_cases WHERE id=? AND org_id=?",
            (case_id, org_id))
        return r

    def get(self, org_id: str, case_id: str) -> dict:
        self._org(org_id)
        row = self._row(case_id, org_id)
        if not row:
            raise errors.NotFoundError("case not found")   # no leakage
        out = dict(row)
        out["refs"] = self.db.query(
            "SELECT ref_type, ref_id, note, created_at FROM case_refs "
            "WHERE case_id=? ORDER BY created_at", (case_id,))
        return out

    def list(self, org_id: str, *, project_id: str = "", status: str = "",
             owner: str = "", priority: str = "", limit: int = 100,
             offset: int = 0) -> list[dict]:
        self._org(org_id)
        limit = max(1, min(int(limit or 100), 500))
        offset = max(0, int(offset or 0))
        where, args = ["org_id=?"], [org_id]
        if project_id:
            where.append("project_id=?"); args.append(project_id)
        if status:
            where.append("status=?"); args.append(self._status(status))
        if owner:
            where.append("owner=?"); args.append(owner)
        if priority:
            where.append("priority=?"); args.append(self._priority(priority))
        return self.db.query(
            "SELECT id, project_id, title, status, priority, owner, "
            "created_at, updated_at, closed_at FROM investigation_cases "
            "WHERE " + " AND ".join(where) +
            " ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            args + [limit, offset])

    def update(self, org_id: str, case_id: str, *, title: str | None = None,
               description: str | None = None,
               priority: str | None = None, actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"case:{org_id}", "case")
        row = self._row(case_id, org_id)
        if not row:
            raise errors.NotFoundError("case not found")
        sets, args = [], []
        if title is not None:
            t = _bounded(redact.redact_text(str(title).strip()),
                         MAX_CASE_TITLE)
            if len(t) < 3:
                raise errors.ValidationError("case title too short")
            sets.append("title=?"); args.append(t)
        if description is not None:
            sets.append("description=?")
            args.append(_bounded(redact.redact_text(str(description)),
                                 MAX_CASE_DESC))
        if priority is not None:
            sets.append("priority=?"); args.append(self._priority(priority))
        if not sets:
            return self.get(org_id, case_id)
        sets.append("updated_at=?"); args.append(_now())
        args.append(case_id)
        self.db.execute(
            "UPDATE investigation_cases SET " + ", ".join(sets) +
            " WHERE id=? AND org_id=?", args + [org_id])
        self._audit("case.updated", object_type="case", object_id=case_id,
                    org_id=org_id, project_id=row["project_id"], actor=actor,
                    metadata={"fields": [s.split("=")[0] for s in sets]})
        self._entry(org_id, case_id, row["project_id"], "case.updated",
                    "Case updated", actor=actor)
        self._emit(row["project_id"], "case.updated", key=case_id,
                   actor=actor)
        return self.get(org_id, case_id)

    def assign(self, org_id: str, case_id: str, owner: str,
               actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"case:{org_id}", "case")
        row = self._row(case_id, org_id)
        if not row:
            raise errors.NotFoundError("case not found")
        ow = _bounded(str(owner or "").strip(), 128)
        if not ow:
            raise errors.ValidationError("owner required")
        self.db.execute(
            "UPDATE investigation_cases SET owner=?, updated_at=? "
            "WHERE id=? AND org_id=?", (ow, _now(), case_id, org_id))
        self._audit("case.assigned", object_type="case", object_id=case_id,
                    org_id=org_id, project_id=row["project_id"], actor=actor,
                    metadata={"owner": ow})
        self._entry(org_id, case_id, row["project_id"], "case.assigned",
                    f"Assigned to {ow}", actor=actor)
        self._emit(row["project_id"], "case.assigned", key=case_id,
                   actor=actor)
        return self.get(org_id, case_id)

    def set_status(self, org_id: str, case_id: str, status: str, *,
                   reason: str = "", actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"case:{org_id}", "case")
        row = self._row(case_id, org_id)
        if not row:
            raise errors.NotFoundError("case not found")
        target = self._status(status)
        allowed = self._TRANSITIONS.get(row["status"], ())
        if target not in allowed and target != row["status"]:
            raise errors.LifecycleError(
                f"invalid case transition: {row['status']} → {target}")
        sets = ["status=?", "updated_at=?", "closed_at=?", "closed_reason=?"]
        closed_at = _now() if target == "closed" else row.get("closed_at", "")
        closed_reason = _bounded(redact.redact_text(str(reason or "")), 500) \
            if target == "closed" else row.get("closed_reason", "")
        self.db.execute(
            "UPDATE investigation_cases SET status=?, updated_at=?, "
            "closed_at=?, closed_reason=? WHERE id=? AND org_id=?",
            (target, _now(), closed_at, closed_reason, case_id, org_id))
        if target == "closed":
            metrics.inc("phase10_cases_closed")
        self._audit(f"case.{target}", object_type="case", object_id=case_id,
                    org_id=org_id, project_id=row["project_id"], actor=actor,
                    metadata={"from": row["status"], "reason":
                              str(reason or "")[:200]})
        self._entry(org_id, case_id, row["project_id"],
                    "case.status_changed",
                    f"Status {row['status']} → {target}", actor=actor,
                    entry_detail=str(reason or "")[:200])
        self._emit(row["project_id"],
                   "case.closed" if target == "closed" else "case.updated",
                   key=case_id, actor=actor)
        return self.get(org_id, case_id)

    def close(self, org_id: str, case_id: str, *, reason: str,
              actor: str = "api") -> dict:
        return self.set_status(org_id, case_id, "closed", reason=reason,
                               actor=actor)

    def link(self, org_id: str, case_id: str, ref_type: str, ref_id: str, *,
             note: str = "", actor: str = "api") -> dict:
        """Reference an EXISTING finding/asset/observation/ioc/evidence/
        alert/remediation. Existence + tenant verified; no duplication."""
        self._org(org_id)
        self._acquire(f"case:{org_id}", "case")
        row = self._row(case_id, org_id)
        if not row:
            raise errors.NotFoundError("case not found")
        rt = str(ref_type or "").strip().lower()
        if rt not in models.CASE_REF_TYPES:
            raise errors.ValidationError(f"unknown ref type: {rt!r}")
        rid = _bounded(str(ref_id or "").strip(), 128)
        if not rid:
            raise errors.ValidationError("ref id required")
        self._verify_ref(org_id, row["project_id"], rt, rid)
        crid = models.stable_id(models.NS_CASE_REF,
                                f"{case_id}|{rt}|{rid}")
        self.db.execute(
            "INSERT OR IGNORE INTO case_refs (id, case_id, org_id, ref_type, "
            "ref_id, note, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (crid, case_id, org_id, rt, rid,
             _bounded(redact.redact_text(str(note or "")), 500),
             _bounded(actor, 128), _now()))
        self._audit("case.reference_added", object_type="case",
                    object_id=case_id, org_id=org_id,
                    project_id=row["project_id"], actor=actor,
                    metadata={"ref_type": rt, "ref_id": rid})
        self._entry(org_id, case_id, row["project_id"], "case.referenced",
                    f"Linked {rt}", actor=actor,
                    ref_type=rt, ref_id=rid)
        return self.get(org_id, case_id)

    def unlink(self, org_id: str, case_id: str, ref_type: str, ref_id: str,
               *, actor: str = "api") -> dict:
        self._org(org_id)
        self._acquire(f"case:{org_id}", "case")
        row = self._row(case_id, org_id)
        if not row:
            raise errors.NotFoundError("case not found")
        rt = str(ref_type or "").strip().lower()
        self.db.execute(
            "DELETE FROM case_refs WHERE case_id=? AND ref_type=? AND "
            "ref_id=? AND org_id=?", (case_id, rt, str(ref_id), org_id))
        self._audit("case.reference_removed", object_type="case",
                    object_id=case_id, org_id=org_id,
                    project_id=row["project_id"], actor=actor,
                    metadata={"ref_type": rt, "ref_id": str(ref_id)})
        self._entry(org_id, case_id, row["project_id"], "case.referenced",
                    f"Unlinked {rt}", actor=actor,
                    ref_type=rt, ref_id=str(ref_id))
        return self.get(org_id, case_id)

    def _verify_ref(self, org_id: str, project_id: str, rt: str,
                    rid: str) -> None:
        """Existence + tenant check. Missing/mismatched → NotFoundError
        (never a dangling reference, never existence leakage)."""
        if rt == "finding":
            row = self.db.query_one(
                "SELECT 1 x FROM findings f JOIN projects p ON p.id="
                "f.project_id WHERE f.id=? AND p.org_id=?", (rid, org_id))
        elif rt == "asset":
            row = self.db.query_one(
                "SELECT 1 x FROM assets a JOIN projects p ON p.id="
                "a.project_id WHERE a.id=? AND p.org_id=?", (rid, org_id))
        elif rt == "ioc":
            row = self.db.query_one(
                "SELECT 1 x FROM threat_indicators WHERE id=? AND org_id=?",
                (rid, org_id))
        elif rt == "observation":
            row = self.db.query_one(
                "SELECT 1 x FROM asset_observations o JOIN projects p ON "
                "p.id=o.project_id WHERE o.id=? AND p.org_id=?",
                (rid, org_id))
        elif rt == "evidence":
            row = self.db.query_one(
                "SELECT 1 x FROM evidence e JOIN findings f ON f.id="
                "e.finding_id JOIN projects p ON p.id=f.project_id WHERE "
                "e.id=? AND p.org_id=?", (rid, org_id))
        elif rt == "alert":
            row = self.db.query_one(
                "SELECT 1 x FROM alerts a WHERE a.id=? AND a.org_id=?",
                (rid, org_id))
        elif rt == "remediation":
            row = self.db.query_one(
                "SELECT 1 x FROM remediation_tickets t JOIN projects p ON "
                "p.id=t.project_id WHERE t.id=? AND p.org_id=?",
                (rid, org_id))
        elif rt == "federation_package":
            # Phase 12: a LOCALLY stored evidence package (source-side row
            # or an import record — both tenant-scoped). A foreign package
            # id is NotFound, never a cross-tenant window (BOLA guard).
            row = self.db.query_one(
                "SELECT 1 x FROM federation_packages WHERE id=? AND org_id=?",
                (rid, org_id))
            if not row:
                row = self.db.query_one(
                    "SELECT 1 x FROM federation_imports WHERE id=? AND "
                    "org_id=?", (rid, org_id))
        else:
            row = None
        if not row:
            raise errors.NotFoundError(f"{rt} reference not found")

    def timeline(self, org_id: str, case_id: str, *, limit: int = 100,
                 offset: int = 0) -> list[dict]:
        self._org(org_id)
        row = self._row(case_id, org_id)
        if not row:
            raise errors.NotFoundError("case not found")
        limit = max(1, min(int(limit or 100), 500))
        offset = max(0, int(offset or 0))
        return self.db.query(
            "SELECT * FROM case_timeline WHERE case_id=? AND org_id=? "
            "ORDER BY ts DESC LIMIT ? OFFSET ?",
            (case_id, org_id, limit, offset))

    def _entry(self, org_id, case_id, project_id, entry_type, entry, *,
               actor: str = "system", ref_type: str = "", ref_id: str = "",
               entry_detail: str = "") -> None:
        eid = models.stable_id(
            models.NS_CASE_ENTRY,
            f"{case_id}|{entry_type}|{entry}|{actor}")
        self.db.execute(
            "INSERT OR IGNORE INTO case_timeline (id, case_id, org_id, "
            "project_id, entry_type, entry, ref_type, ref_id, actor, ts) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (eid, case_id, org_id, project_id, entry_type,
             _bounded(redact.redact_text(entry), 500), ref_type, ref_id,
             _bounded(actor, 128), _now()))


# ===========================================================================
# §24 — security-event enrichment (read side; no duplicate event bus)
# ===========================================================================
def enrich_security_event(platform, project_id: str, event: dict) -> dict:
    """Augment an existing security event with IOC/finding/risk context.
    Read-only, deterministic, bounded — the event bus itself is unchanged."""
    out = dict(event)
    out["threat_context"] = {"iocs": [], "findings": [], "risk": None}
    asset_id = str(event.get("asset_id") or "")
    if asset_id:
        rows = platform.db.query(
            "SELECT m.*, i.indicator, i.confidence_level FROM "
            "threat_matches m JOIN threat_indicators i ON i.id="
            "m.indicator_id WHERE m.asset_id=? LIMIT 20", (asset_id,))
        out["threat_context"]["iocs"] = [
            {"match_id": r["id"], "indicator": r["indicator"],
             "type": r["ioc_type"], "confidence": r["confidence_level"],
             "finding_id": r["finding_id"]} for r in rows]
        fids = list({r["finding_id"] for r in rows})[:5]
        if fids:
            rs = risk_mod.RiskSnapshotService(platform)
            for fid in fids:
                snap = rs.latest(fid)
                if snap:
                    out["threat_context"]["risk"] = {
                        "finding_id": fid, "score": snap.get("risk_score"),
                        "level": snap.get("risk_level")}
                    break
    return out


# ===========================================================================
# Module-level convenience: one-stop service bundle used by CLI/API/tests
# ===========================================================================
class SecurityOperations:
    """Composition facade — every subsystem below is a thin wrapper over
    EXISTING platform services (no duplicate infrastructure)."""

    def __init__(self, platform, *, limiter=None):
        self.platform = platform
        lim = limiter or identity_mod.RateLimiter(max_keys=4096)
        self.iocs = IocCatalogService(platform, limiter=lim)
        self.correlation = ThreatCorrelationService(platform, limiter=lim)
        self.prioritization = ThreatPrioritizationService(platform,
                                                          limiter=lim)
        self.clusters = ThreatClusterService(platform, limiter=lim)
        self.surface = AttackSurfaceService(platform, limiter=lim)
        self.cases = InvestigationCaseService(platform, limiter=lim)

    @staticmethod
    def normalize(indicator, ioc_type: str | None = None):
        return normalize_indicator(indicator, ioc_type)

    @staticmethod
    def classify(indicator):
        return classify_indicator(indicator)
