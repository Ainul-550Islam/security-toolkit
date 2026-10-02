#!/usr/bin/env python3
# ============================================================================
#  events.py — Phase 5 security change events + change detection.
#  ---------------------------------------------------------------------------
#  - SecurityEventService.emit(): normalized change events with a DETERMINISTIC
#    identity (project|type|asset|key|scan) — reprocessing the same scan can
#    never duplicate an event (INSERT OR IGNORE).
#  - ChangeDetector.detect(): derives events from a Phase-4 baseline diff
#    (frozen payloads) — asset/service/technology/version/exposure/finding/
#    risk changes. It REUSES Phase-4 observation history and diff payloads;
#    nothing is re-invented or re-stored.
#  - Secrets never appear: previous_state/new_state are bounded + redacted.
#  - Events are the single alert source for the Phase-5 pipeline.
# ============================================================================

from __future__ import annotations

import re

import errors
import metrics
import models
import redact
import store

MAX_STATE_LEN = 600          # bounded previous/new state payload
MAX_EVENTS_PER_SCAN = 200    # bounded change-detection pass
_VERSION_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._+-]*)\s+(\d[\w.+-]*)$")


def _bounded_state(state) -> str:
    """Serialize a state fragment: redacted, bounded, JSON-only."""
    data = dict(state or {})
    out = {}
    for k, v in list(data.items())[:12]:
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[str(k)[:64]] = v if isinstance(v, (int, float, bool)) \
                else str(v)[:MAX_STATE_LEN]
        elif isinstance(v, (list, tuple)):
            out[str(k)[:64]] = [str(x)[:120] for x in list(v)[:20]]
        else:
            out[str(k)[:64]] = str(v)[:120]
    return store.dumps(redact.redact(out))


class SecurityEventService:
    """Append-only, idempotent security change events (tenant-scoped)."""

    def __init__(self, platform):
        self.svc = platform
        self.db = platform.db

    # ------------------------------------------------------------ emit
    def emit(self, project_id: str, event_type: str, *,
             asset_id: str = "", key: str = "", scan_id: str = "",
             previous_state=None, new_state=None, source: str = "",
             confidence: float = 0.5, actor: str = "scheduler",
             org_id: str = "") -> dict | None:
        """Create one event. Returns the event row, or None when the event
        identity already exists (idempotent re-processing)."""
        if event_type not in models.EVENT_TYPES:
            raise errors.ValidationError(
                f"event_unknown: {event_type!r} is not a change event")
        project = self.svc.project_require(project_id)
        if not org_id:
            org_id = project.org_id
        key = str(key or "")[:160]
        event_id = models.stable_id(
            models.NS_SECEVENT,
            f"{project_id}|{event_type}|{asset_id}|{key}|{scan_id}")
        ts = models.utcnow()
        try:
            with self.db.transaction() as conn:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO security_events (id, project_id, "
                    "org_id, asset_id, event_type, source, ts, "
                    "previous_state, new_state, confidence, scan_id, "
                    "state_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (event_id, project_id, org_id, str(asset_id)[:64],
                     event_type, str(source)[:80], ts,
                     _bounded_state(previous_state),
                     _bounded_state(new_state),
                     min(1.0, max(0.0, float(confidence))),
                     str(scan_id)[:80], key))
                if cur.rowcount != 1:
                    return None
        except Exception as e:
            raise errors.PersistenceError(f"event emit failed: {e}") from e
        metrics.inc("security_change_events")
        return {
            "id": event_id, "project_id": project_id, "org_id": org_id,
            "asset_id": str(asset_id)[:64], "event_type": event_type,
            "source": str(source)[:80], "ts": ts,
            "previous_state": store.loads(_bounded_state(previous_state)),
            "new_state": store.loads(_bounded_state(new_state)),
            "confidence": min(1.0, max(0.0, float(confidence))),
            "scan_id": str(scan_id)[:80], "state_key": key,
        }

    # ------------------------------------------------------------- reads
    def list_events(self, project_id: str, *, event_type: str = "",
                    limit: int = 100) -> list[dict]:
        """Bounded, tenant-scoped event listing (newest first)."""
        self.svc.project_require(project_id)
        limit = min(max(int(limit), 1), 500)
        if event_type:
            if event_type not in models.EVENT_TYPES:
                raise errors.ValidationError(
                    f"event_unknown: {event_type!r} is not a change event")
            rows = self.db.query(
                "SELECT * FROM security_events WHERE project_id=? AND "
                "event_type=? ORDER BY ts DESC, id DESC LIMIT ?",
                (project_id, event_type, limit))
        else:
            rows = self.db.query(
                "SELECT * FROM security_events WHERE project_id=? "
                "ORDER BY ts DESC, id DESC LIMIT ?", (project_id, limit))
        out = []
        for r in rows:
            r["previous_state"] = store.loads(r.get("previous_state", "{}"))
            r["new_state"] = store.loads(r.get("new_state", "{}"))
            out.append(redact.redact(dict(r)))
        return out

    def count_events(self, project_id: str) -> dict:
        self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT event_type, COUNT(*) AS n FROM security_events WHERE "
            "project_id=? GROUP BY event_type ORDER BY event_type",
            (project_id,))
        return {r["event_type"]: r["n"] for r in rows}


# ---------------------------------------------------------------------------
# Change detection (Phase-4 payload diff → normalized events)
# ---------------------------------------------------------------------------
def _split_version(value: str) -> tuple:
    m = _VERSION_RE.match(str(value).strip())
    if not m:
        return ("", "")
    return (m.group(1).strip().lower(), m.group(2))


class ChangeDetector:
    """Derive security change events from a Phase-4 baseline comparison.
    Inputs are the FROZEN `from`/`to` payloads produced by diffs.capture, so
    the same scan always yields the same event set (idempotent)."""

    def __init__(self, platform):
        self.svc = platform
        self.db = platform.db
        self.events = SecurityEventService(platform)

    def detect(self, project_id: str, from_payload: dict, to_payload: dict,
               *, scan_id: str = "", source: str = "change-detector",
               actor: str = "scanner") -> list[dict]:
        """Emit events for payload changes. Returns the created events."""
        ff = (from_payload or {}).get("findings", {}) or {}
        fa = (from_payload or {}).get("assets", {}) or {}
        tf = (to_payload or {}).get("findings", {}) or {}
        ta = (to_payload or {}).get("assets", {}) or {}
        created: list[dict] = []
        first = not ff

        def _emit(event_type, *, asset_id="", key="", prev=None, new=None,
                  confidence=0.5):
            if len(created) >= MAX_EVENTS_PER_SCAN:
                return
            ev = self.events.emit(
                project_id, event_type, asset_id=asset_id, key=key,
                scan_id=scan_id, previous_state=prev, new_state=new,
                source=source, confidence=confidence, actor=actor)
            if ev is not None:
                created.append(ev)

        # --- findings ----------------------------------------------------
        if first:
            for fp in sorted(tf)[:MAX_EVENTS_PER_SCAN]:
                v = tf[fp]
                _emit("finding.created", asset_id=v.get("asset_id", ""),
                      key=fp, prev={}, new={
                          "title": str(v.get("title", ""))[:200],
                          "severity": v.get("severity", ""),
                          "risk_score": v.get("risk_score", 0),
                          "risk_level": v.get("risk_level", "info")})
        else:
            fk, tk = set(ff), set(tf)
            for fp in sorted(tk - fk)[:MAX_EVENTS_PER_SCAN]:
                v = tf[fp]
                _emit("finding.created", asset_id=v.get("asset_id", ""),
                      key=fp, prev={}, new={
                          "title": str(v.get("title", ""))[:200],
                          "severity": v.get("severity", ""),
                          "risk_score": v.get("risk_score", 0),
                          "risk_level": v.get("risk_level", "info")})
            for fp in sorted(fk - tk)[:MAX_EVENTS_PER_SCAN]:
                v = ff[fp]
                _emit("finding.resolved", asset_id=v.get("asset_id", ""),
                      key=fp, prev={
                          "title": str(v.get("title", ""))[:200],
                          "severity": v.get("severity", ""),
                          "risk_score": v.get("risk_score", 0)},
                      new={"lifecycle": "resolved"})
            for fp in sorted(fk & tk)[:MAX_EVENTS_PER_SCAN]:
                a, b = ff[fp], tf[fp]
                if b.get("lifecycle") == "reopened" and \
                        a.get("lifecycle") != "reopened":
                    _emit("finding.reopened", asset_id=b.get("asset_id", ""),
                          key=fp, prev={"lifecycle": a.get("lifecycle", "")},
                          new={"lifecycle": "reopened"})
                ra = float(a.get("risk_score") or 0)
                rb = float(b.get("risk_score") or 0)
                if ra != rb:
                    _emit("risk.increased" if rb > ra else "risk.decreased",
                          asset_id=b.get("asset_id", ""),
                          key=f"{fp}|risk", prev={
                              "risk_score": ra, "risk_level":
                              a.get("risk_level", "info"),
                              "severity": a.get("severity", "")},
                          new={"risk_score": rb, "risk_level":
                               b.get("risk_level", "info"),
                               "severity": b.get("severity", "")})

        # --- assets ------------------------------------------------------
        ak, bkt = set(fa), set(ta)
        for aid in sorted(bkt - ak)[:MAX_EVENTS_PER_SCAN]:
            v = ta[aid]
            _emit("asset.created", asset_id=aid, key=aid, prev={}, new={
                "asset_type": v.get("asset_type", ""),
                "value": str(v.get("value", ""))[:200],
                "exposure": v.get("exposure", "unknown"),
                "criticality": v.get("criticality", "unknown")})
        for aid in sorted(ak - bkt)[:MAX_EVENTS_PER_SCAN]:
            v = fa[aid]
            _emit("asset.removed", asset_id=aid, key=aid, prev={
                "asset_type": v.get("asset_type", ""),
                "value": str(v.get("value", ""))[:200],
                "exposure": v.get("exposure", "unknown")},
                new={"status": "removed"})
        for aid in sorted(ak & bkt)[:MAX_EVENTS_PER_SCAN]:
            a, b = fa[aid], ta[aid]
            a_svc, b_svc = set(a.get("services", [])), \
                set(b.get("services", []))
            a_tech, b_tech = set(a.get("technologies", [])), \
                set(b.get("technologies", []))
            for svc_name in sorted(b_svc - a_svc)[:20]:
                _emit("service.opened", asset_id=aid,
                      key=f"svc|{svc_name}", prev={"service": svc_name},
                      new={"service": svc_name, "status": "open"},
                      confidence=0.6)
            for svc_name in sorted(a_svc - b_svc)[:20]:
                _emit("service.closed", asset_id=aid,
                      key=f"svc|{svc_name}", prev={"service": svc_name},
                      new={"service": svc_name, "status": "closed"},
                      confidence=0.6)
            # technology / version changes (version detected via token parse)
            a_ver: dict = {}
            b_ver: dict = {}
            for t in a_tech:
                name, ver = _split_version(t)
                if name and ver:
                    a_ver[name] = ver
            for t in b_tech:
                name, ver = _split_version(t)
                if name and ver:
                    b_ver[name] = ver
            for name in sorted(set(a_ver) & set(b_ver))[:20]:
                if a_ver[name] != b_ver[name]:
                    _emit("version.changed", asset_id=aid,
                          key=f"ver|{name}",
                          prev={"technology": name, "version": a_ver[name]},
                          new={"technology": name, "version": b_ver[name]},
                          confidence=0.6)
            if a_tech != b_tech:
                _emit("technology.changed", asset_id=aid, key="tech",
                      prev={"technologies": sorted(a_tech)[:20]},
                      new={"technologies": sorted(b_tech)[:20]},
                      confidence=0.6)
            if (a.get("exposure") or "unknown") != \
                    (b.get("exposure") or "unknown"):
                _emit("exposure.changed", asset_id=aid, key="exposure",
                      prev={"exposure": a.get("exposure", "unknown")},
                      new={"exposure": b.get("exposure", "unknown")},
                      confidence=0.7)
        return created
