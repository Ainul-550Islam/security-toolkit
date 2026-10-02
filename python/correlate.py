#!/usr/bin/env python3
# ============================================================================
#  correlate.py — Phase 4 finding intelligence:
#  canonical identity, deterministic cross-scanner deduplication, finding
#  lifecycle helpers (false positive / accepted risk / suppression expiry),
#  deterministic correlation, root-cause grouping, security clusters and
#  remediation grouping.
#
#  GUARANTEES
#    - canonical_key is deterministic, tenant-safe (project+asset scoped),
#      timestamp/evidence independent, secret-free
#    - deduplication NEVER deletes evidence: the canonical finding keeps the
#      merged evidence list; duplicate observations are recorded in
#      finding_observations (provenance) — unbounded history is bounded by
#      caps, not destruction
#    - correlation ≠ deduplication: linked findings stay separate findings
#    - correlation is rule-based and deterministic; no AI/LLM dependency
#    - user-driven state changes (false positive / accepted risk / review
#      expiry) are audited and RBAC-gated by the caller
#    - every function is idempotent (UNIQUE constraints + update-in-place)
# ============================================================================

from __future__ import annotations

import hashlib
import json
import re

import errors
import metrics
import models
import redact
import risk as risk_mod
import store

MAX_EVIDENCE_PER_FINDING = 100
MAX_LINK_PARTNERS = 120
MAX_PROJECT_SCAN = 500
MAX_TOPIC_RULES = "N/A"          # documented; topics are a fixed vocabulary

COMPONENT_KEYS = ("component", "technology", "server", "framework",
                  "library", "software")

# Deterministic topic vocabulary (category → topics), keywords enrich it.
CATEGORY_TOPICS = {
    "injection": {"injection", "input_handling"},
    "xss": {"injection", "input_handling", "client_side"},
    "csrf": {"state_handling", "client_side"},
    "auth": {"authentication", "access_control"},
    "access_control": {"access_control", "authorization"},
    "tls": {"transport_security", "crypto"},
    "crypto": {"crypto", "transport_security"},
    "misconfiguration": {"configuration", "hardening"},
    "exposure": {"configuration", "exposure", "data_leak"},
    "information_disclosure": {"exposure", "data_leak", "information"},
    "deserialization": {"injection", "input_handling", "code_execution"},
    "ssrf": {"injection", "input_handling", "network_reach"},
    "rce": {"code_execution", "input_handling"},
    "dos": {"availability"},
    "other": set(),
}
KEYWORD_TOPICS = {
    "header": {"hardening"}, "missing security header": {"hardening"},
    "server": {"fingerprint", "exposure"},
    "directory": {"exposure", "configuration"},
    "debug": {"exposure", "development"},
    "backup": {"exposure", "data_leak"},
    "outdated": {"version"},
    "version": {"version"},
    "weak": {"crypto", "hardening"},
    "redirect": {"state_handling"},
    "cookie": {"session", "state_handling"},
    "error": {"information"},
    "endpoint": {"api_surface"},
    "api": {"api_surface"},
}

FAMILY_CATEGORIES = frozenset({"misconfiguration", "exposure",
                               "information_disclosure", "access_control"})


def _norm(text) -> str:
    """Deterministic text canonicalization for identity inputs."""
    s = re.sub(r"[\s_\-]+", " ", str(text or "")).strip().lower()
    return re.sub(r"[^a-z0-9 /.:?=&%-]", "", s)[:200]


def topics_for(title: str, category: str) -> frozenset:
    out = set(CATEGORY_TOPICS.get(str(category or "other"), set()))
    low = str(title or "").lower()
    for kw, tops in KEYWORD_TOPICS.items():
        if kw in low:
            out |= set(tops)
    return frozenset(out)


class CorrelationService:
    def __init__(self, platform):
        self.svc = platform
        self.db = platform.db
        self.confidence = risk_mod.ConfidenceEngine()
        self.risk = risk_mod.RiskEngine()
        self.snapshots = risk_mod.RiskSnapshotService(platform)
        self.calc_version = risk_mod.CALC_VERSION

    # ------------------------------------------------------------ helpers
    def _audit(self, action, *, object_type, object_id, project_id,
               actor, metadata):
        try:
            self.svc.audit(action, object_type=object_type,
                           object_id=object_id, project_id=project_id,
                           actor=actor, metadata=metadata)
        except Exception:
            pass

    def _finding_row(self, finding_id: str) -> dict:
        rows = self.db.query("SELECT * FROM findings WHERE id=? LIMIT 1",
                             (finding_id,))
        row = dict(rows[0]) if rows else {}
        for k in ("cvss", "raw", "evidence", "confidence_reasons",
                  "risk_factors", "business_impact"):
            row[k] = store.loads(row.get(k, "{}") if k in (
                "cvss", "raw", "confidence_reasons", "risk_factors",
                "business_impact") else row.get(k, "[]"))
        return row

    def _asset_ctx(self, asset_id: str) -> dict:
        if not asset_id:
            return {"criticality": "unknown", "exposure": "unknown",
                    "business_impact": {}}
        rows = self.db.query("SELECT * FROM assets WHERE id=? LIMIT 1",
                             (asset_id,))
        if not rows:
            return {"criticality": "unknown", "exposure": "unknown",
                    "business_impact": {}}
        row = dict(rows[0])
        return {"criticality": row.get("criticality", "unknown"),
                "exposure": row.get("exposure", "unknown"),
                "business_impact": store.loads(
                    row.get("business_impact", "{}") or "{}")}

    # ------------------------------------------------- canonical identity
    def canonical_key(self, *, project_id: str, asset_id: str,
                      category: str, rule_id: str, template_id: str,
                      title: str, raw: dict) -> str:
        """Deterministic, tenant-safe canonical identity. Includes:
        project, asset, category, normalized rule (id/template/title),
        normalized location, parameter and component. Excludes: source,
        timestamps, evidence, descriptions, severity, random ids."""
        raw = raw or {}
        rule = _norm(rule_id or template_id or "")
        if not rule:
            rule = _norm(title)
        location = _norm(raw.get("endpoint") or raw.get("url") or
                         raw.get("target") or "")
        parameter = _norm(raw.get("parameter") or "")
        component = ""
        for k in COMPONENT_KEYS:
            v = raw.get(k)
            if isinstance(v, str) and v:
                component = _norm(v)
                break
            if isinstance(v, dict):
                component = _norm(v.get("name") or v.get("product") or "")
                if component:
                    break
        if not component:
            tech = raw.get("technologies")
            if isinstance(tech, list) and tech:
                t0 = tech[0]
                if isinstance(t0, dict):
                    component = _norm(t0.get("name") or t0.get("technology"))
                else:
                    component = _norm(t0)
        key = "|".join([str(project_id), str(asset_id or ""),
                        str(category or "other").lower(), rule, location,
                        parameter, component])
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]

    # ------------------------------------------------------- confidence+risk
    def evaluate(self, row: dict) -> dict:
        """Deterministic confidence + risk evaluation for ONE finding row.
        Never raises: on unexpected input it returns an unverified default
        and increments risk_calculation_failures."""
        try:
            finding = models.Finding.from_dict(row)
        except Exception:
            metrics.inc("risk_calculation_failures")
            return {"confidence_score": 0.0, "confidence_level": "unverified",
                    "confidence_reasons": ["unreadable finding"],
                    "risk_score": 0, "risk_level": "info",
                    "risk_factors": [{"name": "error", "delta": 0,
                                      "reason": "evaluation failed"}],
                    "priority": "P4", "priority_order": 4,
                    "exploitability": "unknown", "calc_version": ""}
        try:
            evidence = row.get("evidence") or []
            sources = self.db.query(
                "SELECT DISTINCT source FROM finding_observations "
                "WHERE finding_id=? LIMIT 20", (row.get("id"),))
            distinct = {s["source"] for s in sources if s["source"]}
            distinct.add(str(row.get("source") or ""))
            occ = int(row.get("occurrence_count") or 1)
            asset = self._asset_ctx(row.get("asset_id") or "")
            conf = self.confidence.compute(
                severity=str(row.get("severity", "Info")),
                source=str(row.get("source", "")),
                evidence_count=len(evidence),
                distinct_sources=distinct,
                asset_certainty="exact" if row.get("asset_id") else "none",
                occurrence_count=max(1, occ),
                declared_confidence=str(row.get("confidence", "medium")))
            rl = self.risk.compute(
                severity=str(row.get("severity", "Info")),
                confidence_score=conf["confidence_score"],
                exposure=str(asset["exposure"]),
                criticality=str(asset["criticality"]),
                business_impact=asset["business_impact"],
                category=str(row.get("category", "other")),
                rule_id=str(row.get("rule_id", "")),
                title=str(row.get("title", "")),
                occurrence_count=max(1, occ))
            return {"confidence_score": conf["confidence_score"],
                    "confidence_level": conf["confidence_level"],
                    "confidence_reasons": conf["confidence_reasons"],
                    "risk_score": rl["risk_score"],
                    "risk_level": rl["risk_level"],
                    "risk_factors": rl["risk_factors"],
                    "priority": rl["priority"],
                    "priority_order": rl["priority_order"],
                    "exploitability": rl["exploitability"],
                    "calc_version": rl["calc_version"]}
        except Exception:
            metrics.inc("risk_calculation_failures")
            return {"confidence_score": 0.0,
                    "confidence_level": "unverified",
                    "confidence_reasons": ["evaluation error"],
                    "risk_score": 0, "risk_level": "info",
                    "risk_factors": [{"name": "error", "delta": 0,
                                      "reason": "evaluation failed"}],
                    "priority": "P4", "priority_order": 4,
                    "exploitability": "unknown", "calc_version": ""}

    def _store_evaluation(self, finding_id: str, ev: dict) -> None:
        self.db.execute(
            "UPDATE findings SET confidence_score=?, confidence_level=?, "
            "confidence_reasons=?, risk_score=?, risk_level=?, "
            "risk_factors=?, priority=?, priority_order=?, "
            "exploitability=?, calc_version=? WHERE id=?",
            (ev["confidence_score"], ev["confidence_level"],
             store.dumps(ev["confidence_reasons"]), ev["risk_score"],
             ev["risk_level"], store.dumps(ev["risk_factors"]),
             ev["priority"], ev["priority_order"], ev["exploitability"],
             ev["calc_version"], finding_id))

    # ------------------------------------------------------------- ingest
    def ingest_finding(self, f: models.Finding, evidence: list, *,
                       scan_id: str = "", raw: dict | None = None,
                       job_id: str = "") -> dict:
        """Phase-4 ingestion entry point. Callers (worker) pass a normalized
        Finding + Evidence; this method:
          1. computes the canonical identity FIRST
          2. if a canonical finding already exists → deduplicates into it
             (merges bounded evidence, records provenance, never deletes)
          3. otherwise ingests via the existing platform.finding_ingest and
             attaches canonical key + deterministic confidence/risk.
        Idempotent: the exact same input twice ⇒ zero state change."""
        f.finalize()          # deterministic id + fingerprint, fail-closed
        try:
            ck = self.canonical_key(
                project_id=f.project_id, asset_id=f.asset_id,
                category=f.category, rule_id=f.rule_id,
                template_id=f.template_id, title=f.title,
                raw=raw or f.raw)
        except Exception:
            ck = ""
        existing = None
        if ck:
            rows = self.db.query(
                "SELECT id, lifecycle FROM findings WHERE project_id=? AND "
                "canonical_key=? AND id<>? LIMIT 1",
                (f.project_id, ck, f.id))
            existing = rows[0] if rows else None
        if existing:
            # pure re-ingest (same scan + source + origin finding) → no-op
            if not self._observation_new(existing["id"], scan_id,
                                         f.source, f.id):
                row = self._finding_row(existing["id"])
                return {"finding_id": existing["id"], "deduped": True,
                        "occurrence_count": row.get("occurrence_count", 1),
                        "risk_score": row.get("risk_score", 0),
                        "risk_level": row.get("risk_level", "info"),
                        "priority": row.get("priority", "P4"),
                        "confidence_score": row.get("confidence_score", 0.0)}
            return self._dedupe_into(existing["id"], f, evidence,
                                     scan_id=scan_id, raw=raw or f.raw,
                                     job_id=job_id)
        # probe the Phase-1 identity (re-detection of an existing row id)
        probe = self.db.query(
            "SELECT id, lifecycle FROM findings WHERE id=? LIMIT 1",
            (f.id,))
        if probe and not self._observation_new(f.id, scan_id, f.source, f.id):
            row = self._finding_row(f.id)
            return {"finding_id": f.id, "deduped": False,
                    "occurrence_count": row.get("occurrence_count", 1),
                    "risk_score": row.get("risk_score", 0),
                    "risk_level": row.get("risk_level", "info"),
                    "priority": row.get("priority", "P4"),
                    "confidence_score": row.get("confidence_score", 0.0)}
        # normal ingest path (Phase-1 finding_ingest — insert or re-detect)
        try:
            self.svc.finding_ingest(f, evidence=evidence)
        except errors.DuplicateError:
            pass
        except Exception as e:
            if "UNIQUE" not in str(e):
                raise
        new_obs = self._record_observation(f.id, f.project_id, scan_id,
                                           f.source, f.id)
        row = self._finding_row(f.id)
        if probe and new_obs and probe[0]["lifecycle"] in (
                "resolved", "remediated"):
            self._reappear(f.id, row)
            row = self._finding_row(f.id)
        ev = self.evaluate(row)
        if ck:
            claimed = self.db.execute_affected(
                "UPDATE findings SET canonical_key=? WHERE id=? "
                "AND canonical_key=''", (ck, f.id))
            if claimed != 1:
                # lost a claim race: another row already owns this canonical.
                # remove the just-inserted duplicate row (evidence cascades,
                # provenance merges into the canonical) and dedupe there.
                self.db.execute("DELETE FROM findings WHERE id=? AND "
                                "canonical_key=''", (f.id,))
                others = self.db.query(
                    "SELECT id FROM findings WHERE project_id=? AND "
                    "canonical_key=? AND id<>? LIMIT 1",
                    (f.project_id, ck, f.id))
                if others:
                    return self._dedupe_into(others[0]["id"], f, evidence,
                                             scan_id=scan_id,
                                             raw=raw or f.raw,
                                             job_id=job_id)
        if probe and new_obs:
            # re-detection of the same Phase-1 finding id → occurrence += 1,
            # evidence merged (never dropped), lifecycle may reappear
            self.db.execute(
                "UPDATE findings SET occurrence_count=occurrence_count+1 "
                "WHERE id=?", (f.id,))
            merged = self._merge_evidence(f.id, row, evidence)
            self.db.execute(
                "UPDATE findings SET evidence=? WHERE id=?",
                (store.dumps(redact.redact(merged)), f.id))
            row = self._finding_row(f.id)
            ev = self.evaluate(row)
        self._store_evaluation(f.id, ev)
        self.snapshots.record(
            f.id, project_id=f.project_id, risk_score=ev["risk_score"],
            risk_level=ev["risk_level"], severity=str(f.severity),
            confidence=ev["confidence_score"],
            asset_criticality=self._asset_ctx(f.asset_id)["criticality"],
            exposure=self._asset_ctx(f.asset_id)["exposure"],
            calc_version=ev["calc_version"], factors=ev["risk_factors"])
        metrics.inc("findings_ingested")
        self.link_for(f.id)
        return {"finding_id": f.id, "deduped": False, "canonical_key": ck,
                "occurrence_count": row.get("occurrence_count", 1),
                "risk_score": ev["risk_score"],
                "risk_level": ev["risk_level"],
                "priority": ev["priority"],
                "confidence_score": ev["confidence_score"]}

    def _observation_new(self, finding_id: str, scan_id: str,
                         source: str, origin: str) -> bool:
        try:
            rows = self.db.query(
                "SELECT 1 FROM finding_observations WHERE finding_id=? AND "
                "scan_id=? AND source=? AND source_finding_id=? LIMIT 1",
                (finding_id, str(scan_id)[:80], str(source)[:80],
                 str(origin)[:80]))
            return not rows
        except Exception:
            return True

    def _reappear(self, finding_id: str, row: dict) -> dict:
        """A formerly remediated/resolved finding is detected again →
        reopened (NOT a new duplicate). Audited, sets reopened_at."""
        ago = str(row.get("reopened_at") or "")
        try:
            f = self.svc.finding_get(finding_id)
            f.transition("reopened")
            reopened_at = f.reopened_at or models.utcnow()
        except Exception:
            reopened_at = ago or models.utcnow()
        self.db.execute(
            "UPDATE findings SET lifecycle='reopened', reopened_at=?, "
            "resolved_at='' WHERE id=?", (reopened_at, finding_id))
        metrics.inc("findings_reopened")
        self._audit("finding.reopened", object_type="finding",
                    object_id=finding_id, project_id=row.get("project_id"),
                    actor="scanner",
                    metadata={"reason": "reappeared after remediation",
                              "from": str(row.get("lifecycle", ""))})
        return {"finding_id": finding_id, "reopened": True,
                "reopened_at": reopened_at}

    def _merge_evidence(self, canonical_id: str, row: dict,
                        evidence: list) -> list:
        """Merge evidence (bounded, deduplicated by evidence id) — evidence
        is NEVER deleted by deduplication."""
        merged = list(row.get("evidence") or [])
        existing_ids = {}
        for ev in merged:
            eid = ev.get("id") or ""
            if eid:
                existing_ids[eid] = True
        for ev in evidence:
            try:
                e = ev if isinstance(ev, models.Evidence) else \
                    models.Evidence.from_dict(dict(ev))
                e.finding_id = canonical_id
                e.finalize()
                d = e.to_dict()
            except Exception:
                continue
            # PHASE-1 ids (finding|captured_at|url) collide when two distinct
            # pieces of evidence share the same second+URL — fall back to a
            # content-addressed id so NO evidence is ever dropped.
            if d.get("id") in existing_ids:
                content = (f"{d['evidence_type']}|{d['url']}|{d['method']}|"
                           f"{d['status_code']}|{d['request_snippet']}|"
                           f"{d['response_snippet']}|{d['detection_reason']}")
                h = hashlib.sha256(content.encode("utf-8")).hexdigest()[:20]
                d["id"] = models.stable_id(
                    models.NS_EVIDENCE, f"{canonical_id}|content|{h}")
            if d.get("id") in existing_ids:
                continue
            if len(merged) >= MAX_EVIDENCE_PER_FINDING:
                break
            merged.append(d)
            existing_ids[d["id"]] = True
        return merged

    def _dedupe_into(self, canonical_id: str, f: models.Finding,
                     evidence: list, *, scan_id: str, raw: dict,
                     job_id: str = "") -> dict:
        """Merge an observation into the canonical finding. Evidence lists
        are merged (bounded, deduplicated by evidence id) — never deleted."""
        row = self._finding_row(canonical_id)
        now = models.utcnow()
        merged = self._merge_evidence(canonical_id, row, evidence)
        occ = int(row.get("occurrence_count") or 1)
        new_obs = self._record_observation(canonical_id, f.project_id,
                                           scan_id, f.source, f.id)
        if new_obs:
            occ += 1
        self.db.execute(
            "UPDATE findings SET last_detected=?, occurrence_count=?, "
            "confidence=?, evidence=? WHERE id=?",
            (now if new_obs else str(row.get("last_detected") or now),
             occ, str(f.confidence or row.get("confidence", "medium")),
             store.dumps(redact.redact(merged)), canonical_id))
        if new_obs:
            metrics.inc("findings_deduplicated")
        # refresh confidence/risk on the CANONICAL (merged) finding
        row2 = self._finding_row(canonical_id)
        ev = self.evaluate(row2)
        self._store_evaluation(canonical_id, ev)
        self.snapshots.record(
            canonical_id, project_id=f.project_id,
            risk_score=ev["risk_score"], risk_level=ev["risk_level"],
            severity=str(row2.get("severity", "Info")),
            confidence=ev["confidence_score"],
            asset_criticality=self._asset_ctx(row2.get("asset_id"))[
                "criticality"],
            exposure=self._asset_ctx(row2.get("asset_id"))["exposure"],
            calc_version=ev["calc_version"], factors=ev["risk_factors"])
        self.link_for(canonical_id)
        return {"finding_id": canonical_id, "deduped": True,
                "occurrence_count": occ, "risk_score": ev["risk_score"],
                "risk_level": ev["risk_level"],
                "priority": ev["priority"],
                "confidence_score": ev["confidence_score"]}

    def _record_observation(self, finding_id: str, project_id: str,
                            scan_id: str, source: str,
                            source_finding_id: str, count: int = 1) -> bool:
        """Idempotent provenance record; returns True when a NEW observation
        (scanner occurrence) was inserted, False for a pure re-ingest."""
        try:
            now = models.utcnow()
            obs_id = models.stable_id(
                models.NS_FOBS,
                f"{finding_id}|{scan_id}|{source}|{source_finding_id}")
            affected = self.db.execute_affected(
                "INSERT OR IGNORE INTO finding_observations (id, finding_id, "
                "project_id, scan_id, source, source_finding_id, first_seen, "
                "last_seen, count) VALUES (?,?,?,?,?,?,?,?,?)",
                (obs_id, finding_id, project_id, scan_id,
                 str(source)[:80], str(source_finding_id)[:80], now, now,
                 int(count)))
            return affected == 1
        except Exception:
            return False

    def observations(self, finding_id: str, limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM finding_observations WHERE finding_id=? "
            "ORDER BY first_seen DESC LIMIT ?", (finding_id, limit))
        return [dict(r) for r in rows]

    # ---------------------------------------------- lifecycle: FP / AR etc.
    def false_positive(self, finding_id: str, *, reason: str,
                       actor: str = "cli", until: str = "",
                       suppress: bool = False) -> dict:
        """structured false-positive handling (reason + actor + expiry +
        audit). With suppress=True the finding is hidden from open lists
        until `until` — it never leaves the database."""
        reason = str(redact.redact_text(reason or ""))[:500]
        if not reason.strip():
            raise errors.ValidationError("a reason is required")
        f = self.svc.finding_get(finding_id)
        try:
            changed = f.transition("false_positive")
        except errors.LifecycleError as e:
            raise errors.LifecycleError(
                f"validation_rejected: {e}") from None
        self.db.execute(
            "UPDATE findings SET lifecycle=?, resolved_at=?, "
            "suppressed_until=?, dismissed_reason=?, dismissed_by=?, "
            "last_detected=? WHERE id=?",
            ("false_positive", f.resolved_at or "", str(until or "")[:64],
             reason, str(actor)[:128], models.utcnow(), finding_id))
        metrics.inc("false_positives")
        self._audit("finding.suppressed" if suppress
                    else "finding.false_positive",
                    object_type="finding", object_id=finding_id,
                    project_id=f.project_id, actor=actor,
                    metadata={"reason": reason[:200],
                              "until": str(until or "")})
        return {"finding_id": finding_id, "changed": changed,
                "status": "false_positive", "suppressed_until": until}

    def accept_risk(self, finding_id: str, *, reason: str,
                    actor: str = "cli", until: str = "",
                    review_at: str = "") -> dict:
        reason = str(redact.redact_text(reason or ""))[:500]
        if not reason.strip():
            raise errors.ValidationError("a reason is required")
        f = self.svc.finding_get(finding_id)
        changed = f.transition("accepted_risk")
        self.db.execute(
            "UPDATE findings SET lifecycle=?, resolved_at=?, "
            "suppressed_until=?, dismissed_reason=?, dismissed_by=?, "
            "last_detected=? WHERE id=?",
            ("accepted_risk", f.resolved_at or "", str(until or "")[:64],
             reason, str(actor)[:128], models.utcnow(), finding_id))
        metrics.inc("accepted_risks")
        self._audit("finding.accepted_risk", object_type="finding",
                    object_id=finding_id, project_id=f.project_id,
                    actor=actor,
                    metadata={"reason": reason[:200],
                              "review_at": str(review_at or "")[:64],
                              "until": str(until or "")})
        return {"finding_id": finding_id, "changed": changed,
                "status": "accepted_risk"}

    def reopen_expired(self, now: str | None = None) -> int:
        """Expiry sweep: a false-positive suppression or accepted-risk that
        passed its `until` becomes reviewable again (reopened). Idempotent."""
        now = now or models.utcnow()
        rows = self.db.query(
            "SELECT id, project_id, suppressed_until, lifecycle FROM "
            "findings WHERE lifecycle IN ('false_positive','accepted_risk') "
            "AND suppressed_until<>'' AND suppressed_until<=? LIMIT 200",
            (now,))
        n = 0
        for r in rows:
            f = self.svc.finding_get(r["id"])
            try:
                f.transition("reopened")
            except errors.LifecycleError:
                continue
            self.db.execute(
                "UPDATE findings SET lifecycle=?, reopened_at=?, "
                "resolved_at='', suppressed_until='', last_detected=? "
                "WHERE id=?",
                ("reopened", f.reopened_at, models.utcnow(), r["id"]))
            metrics.inc("findings_reopened")
            self._audit("finding.reopened", object_type="finding",
                        object_id=r["id"], project_id=r["project_id"],
                        actor="system",
                        metadata={"reason": "review expiry",
                                  "from": r["lifecycle"]})
            n += 1
        return n

    # --------------------------------------------------------- correlation
    def link_for(self, finding_id: str, limit: int = MAX_LINK_PARTNERS) -> int:
        """Deterministic rule-based correlation for one finding. Linked
        findings REMAIN separate — this is correlation, not deduplication."""
        row = self._finding_row(finding_id)
        topics = topics_for(str(row.get("title", "")),
                            str(row.get("category", "other")))
        asset_id = str(row.get("asset_id") or "")
        component = ""
        for k in COMPONENT_KEYS:
            v = row.get("raw", {}).get(k)
            if isinstance(v, str) and v:
                component = _norm(v)
                break
        if not component:
            tech = row.get("raw", {}).get("technologies")
            if isinstance(tech, list) and tech:
                t0 = tech[0] if isinstance(tech[0], dict) else {"name": tech[0]}
                component = _norm(t0.get("name") or t0.get("technology"))
        partners = self.db.query(
            "SELECT id, category, title, asset_id, raw FROM findings "
            "WHERE project_id=? AND id<>? AND lifecycle NOT IN "
            "('false_positive','accepted_risk') LIMIT ?",
            (row.get("project_id"), finding_id, limit))
        added = 0
        for p in partners:
            p_raw = store.loads(p.get("raw", "{}"))
            p_topics = topics_for(str(p.get("title", "")),
                                  str(p.get("category", "other")))
            shared = topics & p_topics
            rel = None
            conf = 0.0
            rule = ""
            if asset_id and p["asset_id"] == asset_id:
                for t in sorted(shared):
                    if t in ("hardening", "exposure", "configuration",
                             "data_leak", "information", "version"):
                        rel = "related_to"
                        conf = 0.60
                        rule = f"topic:{t}"
                        break
                if rel is None and shared and \
                        str(p.get("category")) == str(row.get("category")):
                    rel = "related_to"
                    conf = 0.55
                    rule = "same_category:" + _norm(p.get("category"))
                if rel is None and component:
                    p_comp = ""
                    for k in COMPONENT_KEYS:
                        v = p_raw.get(k)
                        if isinstance(v, str) and v:
                            p_comp = _norm(v)
                            break
                    if p_comp == component:
                        rel = "shares_component"
                        conf = 0.70
                        rule = "component:" + component[:40]
            if rel is None and component:
                p_comp = ""
                for k in COMPONENT_KEYS:
                    v = p_raw.get(k)
                    if isinstance(v, str) and v:
                        p_comp = _norm(v)
                        break
                if p_comp == component and p["asset_id"] != asset_id:
                    rel = "shared_component"
                    conf = 0.50
                    rule = "component:" + component[:40]
            if rel is None:
                continue
            a, b = sorted((finding_id, p["id"]))
            link_id = models.stable_id(
                models.NS_LINK, f"{a}|{rel}|{b}|{rule}")
            self.db.execute(
                "INSERT OR IGNORE INTO finding_links (id, project_id, "
                "finding_a_id, finding_b_id, relation_type, rule_id, "
                "confidence, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (link_id, row.get("project_id"), a, b, rel, rule,
                 conf, models.utcnow()))
            cur = self.db.execute_affected(
                "UPDATE finding_links SET confidence=MAX(confidence, ?) "
                "WHERE id=?", (max(conf, 0.55), link_id))
            if cur:
                added += 1
        if added:
            metrics.inc("correlation_matches", added)
        return added

    def links(self, finding_id: str, limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM finding_links WHERE finding_a_id=? OR "
            "finding_b_id=? LIMIT ?", (finding_id, finding_id, limit))
        return [dict(r) for r in rows]

    # ------------------------------------------------------- root causes
    def root_causes_for(self, finding_id: str) -> list[dict]:
        """Deterministic root-cause groups for one finding. Groups are
        created ONLY when ≥2 findings share the cause key; findings are
        never merged (correlation ≠ deduplication)."""
        row = self._finding_row(finding_id)
        project_id = row.get("project_id")
        asset_id = str(row.get("asset_id") or "")
        component = ""
        for k in COMPONENT_KEYS:
            v = row.get("raw", {}).get(k)
            if isinstance(v, str) and v:
                component = _norm(v)
                break
        created = []
        # (a) component-based: same asset + same component, ≥2 findings
        if component and asset_id:
            created.append(self._root_cause(
                project_id, root_type="component_misconfiguration",
                key_value=component, asset_id=asset_id,
                title=f"Component '{component}' on asset {asset_id[:12]}",
                seed_ids=[finding_id], min_members=2))
        # (b) hardening-family: same asset, ≥2 findings in the family
        if asset_id and str(row.get("category", "")) in FAMILY_CATEGORIES:
            created.append(self._root_cause(
                project_id, root_type="misconfiguration_family",
                key_value="hardening", asset_id=asset_id,
                title=f"Hardening cluster on asset {asset_id[:12]}",
                seed_ids=[finding_id],
                category_filter=FAMILY_CATEGORIES, min_members=2))
        return [c for c in created if c is not None]

    def _root_cause(self, project_id: str, *, root_type: str,
                    key_value: str, asset_id: str, title: str,
                    seed_ids: list, min_members: int = 2,
                    category_filter=None) -> dict | None:
        root_id = models.stable_id(
            models.NS_ROOT,
            f"{project_id}|{root_type}|{key_value}|{asset_id}")
        now = models.utcnow()
        members = self.db.query(
            "SELECT id FROM findings WHERE project_id=? AND asset_id=? "
            "AND lifecycle NOT IN ('false_positive','accepted_risk') "
            "LIMIT 50", (project_id, asset_id))
        ids = {m["id"] for m in members} | set(seed_ids)
        if len(ids) < min_members:
            return None
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT id FROM root_causes WHERE id=? LIMIT 1",
                (root_id,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO root_causes (id, project_id, root_type, "
                    "key_value, asset_id, confidence, title, first_seen, "
                    "updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (root_id, project_id, root_type, str(key_value)[:200],
                     asset_id, 0.55, str(title)[:200], now, now))
            else:
                conn.execute(
                    "UPDATE root_causes SET updated_at=?, confidence=MAX("
                    "confidence, 0.55) WHERE id=?", (now, root_id))
            for fid in sorted(ids):
                conn.execute(
                    "INSERT OR IGNORE INTO root_cause_findings "
                    "(root_cause_id, finding_id) VALUES (?,?)",
                    (root_id, fid))
        return {"root_cause_id": root_id, "root_type": root_type,
                "key_value": key_value, "findings": len(ids)}

    def project_root_causes(self, project_id: str,
                            limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT rc.*, COUNT(rcf.finding_id) AS member_count FROM "
            "root_causes rc LEFT JOIN root_cause_findings rcf ON "
            "rcf.root_cause_id=rc.id WHERE rc.project_id=? GROUP BY rc.id "
            "ORDER BY member_count DESC LIMIT ?", (project_id, limit))
        return [dict(r) for r in rows]

    # ------------------------------------------------------------ clusters
    def _discover_root_causes(self, project_id: str) -> None:
        """Deterministic root-cause discovery: for every asset with ≥2
        active findings sharing a component (or in the hardening family)
        a root-cause group is created. Idempotent; bounded."""
        rows = self.db.query(
            "SELECT DISTINCT asset_id FROM findings WHERE project_id=? AND "
            "asset_id<>'' AND lifecycle NOT IN "
            "('false_positive','accepted_risk') LIMIT 50", (project_id,))
        for r in rows:
            aid = r["asset_id"]
            fids = [m["id"] for m in self.db.query(
                "SELECT id FROM findings WHERE project_id=? AND asset_id=? "
                "AND lifecycle NOT IN ('false_positive','accepted_risk') "
                "LIMIT 50", (project_id, aid))]
            if len(fids) < 2:
                continue
            member = self._finding_row(fids[0])
            component = ""
            raw = member.get("raw") or {}
            for k in COMPONENT_KEYS:
                v = raw.get(k)
                if isinstance(v, str) and v:
                    component = _norm(v)
                    break
            if not component:
                tech = raw.get("technologies")
                if isinstance(tech, list) and tech:
                    t0 = tech[0] if isinstance(tech[0], dict) else {
                        "name": tech[0]}
                    component = _norm(t0.get("name") or
                                      t0.get("technology"))
            if component:
                self._root_cause(
                    project_id, root_type="component_misconfiguration",
                    key_value=component, asset_id=aid,
                    title=f"Component '{component}' on asset {aid[:12]}",
                    seed_ids=fids, min_members=2)
            if str(member.get("category", "")) in FAMILY_CATEGORIES:
                self._root_cause(
                    project_id, root_type="misconfiguration_family",
                    key_value="hardening", asset_id=aid,
                    title=f"Hardening cluster on asset {aid[:12]}",
                    seed_ids=fids, min_members=2)

    def clusters_build(self, project_id: str) -> int:
        """Deterministic cluster pass: root-cause clusters + technology
        clusters (same component+version across ≥2 assets). Idempotent."""
        created = 0
        self._discover_root_causes(project_id)
        for rc in self.project_root_causes(project_id, limit=100):
            cid = models.stable_id(
                models.NS_CLUSTER, f"{project_id}|root_cause|{rc['id']}")
            now = models.utcnow()
            members = self.db.query(
                "SELECT finding_id FROM root_cause_findings WHERE "
                "root_cause_id=? LIMIT 100", (rc["id"],))
            risk = self._cluster_risk([m["finding_id"] for m in members])
            with self.db.transaction() as conn:
                row = conn.execute(
                    "SELECT id FROM clusters WHERE id=? LIMIT 1",
                    (cid,)).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO clusters (id, project_id, cluster_type, "
                        "key_value, title, confidence, risk_score, "
                        "risk_level, first_seen, updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (cid, project_id, "root_cause", rc["id"],
                         f"Root cause: {rc.get('title', '')[:120]}",
                         0.55, risk["score"], risk["level"], now, now))
                    metrics.inc("clusters_created")
                    created += 1
                else:
                    conn.execute(
                        "UPDATE clusters SET risk_score=?, risk_level=?, "
                        "confidence=MAX(confidence, 0.55), updated_at=? "
                        "WHERE id=?", (risk["score"], risk["level"], now, cid))
                for m in members:
                    conn.execute(
                        "INSERT OR IGNORE INTO cluster_members "
                        "(cluster_id, finding_id, asset_id) VALUES (?,?,'')",
                        (cid, m["finding_id"]))
        # technology clusters: component+version across ≥2 assets
        tech_rows = self.db.query(
            "SELECT id FROM findings WHERE project_id=? AND "
            "lifecycle NOT IN ('false_positive','accepted_risk') "
            "LIMIT ?", (project_id, MAX_PROJECT_SCAN))
        buckets: dict[str, list] = {}
        for r in tech_rows:
            row = self._finding_row(r["id"])
            comp, ver = "", ""
            raw = row.get("raw") or {}
            for k in COMPONENT_KEYS:
                v = raw.get(k)
                if isinstance(v, str) and v:
                    comp = _norm(v)
                    break
            if not comp:
                tech = raw.get("technologies")
                if isinstance(tech, list) and tech:
                    t0 = tech[0] if isinstance(tech[0], dict) else {
                        "name": tech[0]}
                    comp = _norm(t0.get("name") or t0.get("technology"))
            if comp:
                ver = _norm(raw.get("version") or "")
                buckets.setdefault(f"{comp}|{ver}", []).append(r["id"])
        for bucket, fids in sorted(buckets.items()):
            comp, _, ver = bucket.partition("|")
            assets = self.db.query(
                "SELECT DISTINCT asset_id FROM findings WHERE id IN "
                "(%s) AND asset_id<>'' LIMIT 20" %
                ",".join("?" for _ in fids), tuple(fids))
            if len(assets) < 2:
                continue
            key = f"{comp} {ver}".strip()
            cid = models.stable_id(models.NS_CLUSTER,
                                   f"{project_id}|technology|{key}")
            now = models.utcnow()
            risk = self._cluster_risk(fids)
            with self.db.transaction() as conn:
                row = conn.execute(
                    "SELECT id FROM clusters WHERE id=? LIMIT 1",
                    (cid,)).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO clusters (id, project_id, cluster_type, "
                        "key_value, title, confidence, risk_score, "
                        "risk_level, first_seen, updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (cid, project_id, "technology", key,
                         f"Technology group: {key}", 0.60,
                         risk["score"], risk["level"], now, now))
                    metrics.inc("clusters_created")
                    created += 1
                else:
                    conn.execute(
                        "UPDATE clusters SET risk_score=?, risk_level=?, "
                        "updated_at=? WHERE id=?",
                        (risk["score"], risk["level"], now, cid))
                for fid in fids:
                    conn.execute(
                        "INSERT OR IGNORE INTO cluster_members "
                        "(cluster_id, finding_id, asset_id) VALUES (?,?,'')",
                        (cid, fid))
        return created

    def _cluster_risk(self, finding_ids: list) -> dict:
        if not finding_ids:
            return {"score": 0, "level": "info"}
        rows = self.db.query(
            "SELECT risk_score, confidence_score FROM findings WHERE id IN "
            "(%s) LIMIT 100" % ",".join("?" for _ in finding_ids),
            tuple(finding_ids))
        if not rows:
            return {"score": 0, "level": "info"}
        top = max(float(r["risk_score"] or 0) for r in rows)
        return {"score": int(top), "level": risk_mod.RiskEngine.level_for(top)}

    def clusters(self, project_id: str, limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT c.*, COUNT(cm.finding_id) AS member_count FROM "
            "clusters c LEFT JOIN cluster_members cm ON cm.cluster_id=c.id "
            "WHERE c.project_id=? GROUP BY c.id ORDER BY c.risk_score DESC, "
            "c.updated_at DESC LIMIT ?", (project_id, limit))
        return [dict(r) for r in rows]

    def cluster_view(self, cluster_id: str) -> dict | None:
        rows = self.db.query(
            "SELECT * FROM clusters WHERE id=? LIMIT 1", (cluster_id,))
        if not rows:
            return None
        members = self.db.query(
            "SELECT f.id, f.title, f.severity, f.risk_score, f.risk_level, "
            "f.priority, f.asset_id, f.lifecycle FROM cluster_members cm "
            "JOIN findings f ON f.id=cm.finding_id WHERE cm.cluster_id=? "
            "ORDER BY f.risk_score DESC LIMIT 200", (cluster_id,))
        return {**dict(rows[0]), "members": [dict(m) for m in members]}

    # -------------------------------------------------- remediation groups
    def remediation_groups_build(self, project_id: str) -> int:
        """Group findings fixable by the same remediation (same canonical
        component, ≥2 findings). Unrelated findings are never merged."""
        rows = self.db.query(
            "SELECT id FROM findings WHERE project_id=? AND lifecycle NOT IN "
            "('false_positive','accepted_risk') LIMIT ?",
            (project_id, MAX_PROJECT_SCAN))
        buckets: dict[str, list] = {}
        for r in rows:
            row = self._finding_row(r["id"])
            comp = ""
            raw = row.get("raw") or {}
            for k in COMPONENT_KEYS:
                v = raw.get(k)
                if isinstance(v, str) and v:
                    comp = _norm(v)
                    break
            if not comp:
                tech = raw.get("technologies")
                if isinstance(tech, list) and tech:
                    t0 = tech[0] if isinstance(tech[0], dict) else {
                        "name": tech[0]}
                    comp = _norm(t0.get("name") or t0.get("technology"))
            if comp:
                buckets.setdefault(comp, []).append(r["id"])
        created = 0
        for comp, fids in sorted(buckets.items()):
            if len(fids) < 2:
                continue
            gid = models.stable_id(models.NS_REGROUP,
                                   f"{project_id}|{comp}")
            now = models.utcnow()
            with self.db.transaction() as conn:
                row = conn.execute(
                    "SELECT id FROM remediation_groups WHERE id=? LIMIT 1",
                    (gid,)).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO remediation_groups (id, project_id, "
                        "component, title, first_seen, updated_at) "
                        "VALUES (?,?,?,?,?,?)",
                        (gid, project_id, comp,
                         f"Upgrade/fix component: {comp}", now, now))
                    created += 1
                else:
                    conn.execute(
                        "UPDATE remediation_groups SET updated_at=? "
                        "WHERE id=?", (now, gid))
                for fid in fids:
                    conn.execute(
                        "INSERT OR IGNORE INTO remediation_group_findings "
                        "(group_id, finding_id) VALUES (?,?)", (gid, fid))
        return created

    def remediation_groups(self, project_id: str,
                           limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT g.*, COUNT(gf.finding_id) AS member_count FROM "
            "remediation_groups g LEFT JOIN remediation_group_findings gf "
            "ON gf.group_id=g.id WHERE g.project_id=? GROUP BY g.id "
            "ORDER BY member_count DESC LIMIT ?", (project_id, limit))
        return [dict(r) for r in rows]

    # ------------------------------------------------- project intel pass
    def build_project_intel(self, project_id: str) -> dict:
        """Idempotent full pass for one project (CLI/dashboard refresh)."""
        rows = self.db.query(
            "SELECT id FROM findings WHERE project_id=? LIMIT ?",
            (project_id, MAX_PROJECT_SCAN))
        evaluated = 0
        links = 0
        for r in rows:
            row = self._finding_row(r["id"])
            if not row.get("calc_version"):
                ev = self.evaluate(row)
                self._store_evaluation(r["id"], ev)
                evaluated += 1
            links += self.link_for(r["id"])
        roots = sum(1 for _ in self.project_root_causes(project_id))
        clusters = self.clusters_build(project_id)
        groups = self.remediation_groups_build(project_id)
        return {"findings_scanned": len(rows), "evaluated": evaluated,
                "links": links, "root_cause_groups": roots,
                "clusters": clusters, "remediation_groups": groups}

    # ------------------------------------------------------ evidence graph
    GRAPH_REL_TYPES = ("supports", "contradicts", "derived_from",
                       "observed_on", "caused_by", "related_to")
    GRAPH_TYPES = ("evidence", "finding", "asset")

    def graph_add(self, project_id: str, *, from_type: str, from_id: str,
                  rel_type: str, to_type: str, to_id: str,
                  confidence: float = 0.5, source: str = "",
                  reason: str = "", actor: str = "cli") -> dict:
        """Evidence-graph edge (supports/contradicts/derived_from/
        observed_on/caused_by/related_to). Both ends must exist in the
        same project (tenant-safe, fail-closed); idempotent by design."""
        if rel_type not in self.GRAPH_REL_TYPES:
            raise errors.ValidationError(f"unknown relation: {rel_type}")
        if from_type not in self.GRAPH_TYPES or \
                to_type not in self.GRAPH_TYPES:
            raise errors.ValidationError("unknown graph node type")
        for t, i in ((from_type, from_id), (to_type, to_id)):
            if not str(i).strip():
                raise errors.ValidationError("empty graph node id")
            table = {"asset": "assets", "finding": "findings",
                     "evidence": "evidence"}[t]
            rows = self.db.query(
                f"SELECT project_id FROM {table} WHERE id=? LIMIT 1",
                (str(i),))
            if not rows:
                raise errors.NotFoundError(f"{t} not found: {i}")
            if rows[0]["project_id"] != project_id:
                raise errors.AuthorizationError("Forbidden")
        eid = models.stable_id(
            models.NS_LINK,
            f"{project_id}|{from_type}:{from_id}|{rel_type}|{to_type}:"
            f"{to_id}|{source}")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO evidence_relations (id, project_id, "
                "from_type, from_id, rel_type, to_type, to_id, confidence, "
                "source, reason, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (eid, project_id, from_type, str(from_id)[:100], rel_type,
                 to_type, str(to_id)[:100], float(confidence),
                 str(source)[:60], str(redact.redact_text(reason))[:300],
                 models.utcnow()))
        self._audit("finding.graph_linked", object_type="finding",
                    object_id=(from_id if from_type == "finding" else to_id),
                    project_id=project_id, actor=actor,
                    metadata={"rel_type": rel_type,
                              "from": f"{from_type}:{from_id}",
                              "to": f"{to_type}:{to_id}"})
        return {"relation_id": eid, "rel_type": rel_type,
                "from": f"{from_type}:{from_id}",
                "to": f"{to_type}:{to_id}"}

    def graph_list(self, project_id: str, limit: int = 200) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM evidence_relations WHERE project_id=? "
            "ORDER BY ts DESC LIMIT ?", (project_id, limit))
        return [dict(r) for r in rows]

    def graph_for(self, node_type: str, node_id: str,
                  limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM evidence_relations WHERE (from_type=? AND "
            "from_id=?) OR (to_type=? AND to_id=?) ORDER BY ts DESC "
            "LIMIT ?", (node_type, str(node_id), node_type, str(node_id),
                        limit))
        return [dict(r) for r in rows]

    # -------------------------------------------------------- aggregate view
    def finding_view(self, finding_id: str, *,
                     include_evidence: bool = True) -> dict | None:
        row = self._finding_row(finding_id)
        if not row.get("id"):
            return None
        view = {k: row.get(k, "") for k in (
            "id", "scan_id", "project_id", "asset_id", "title", "description",
            "severity", "confidence", "category", "source", "rule_id",
            "template_id", "cwe", "cve", "remediation", "lifecycle",
            "fingerprint", "first_detected", "last_detected", "resolved_at",
            "reopened_at", "confidence_score", "confidence_level",
            "risk_score", "risk_level", "priority", "exploitability",
            "occurrence_count", "suppressed_until", "dismissed_reason",
            "dismissed_by", "business_impact", "calc_version")}
        view["confidence_reasons"] = row.get("confidence_reasons", [])
        view["risk_factors"] = row.get("risk_factors", [])
        view["evidence"] = row.get("evidence", []) if include_evidence else []
        view["observations"] = self.observations(finding_id)
        view["links"] = self.links(finding_id)
        view["graph"] = self.graph_for("finding", finding_id)
        view["root_causes"] = [
            {**dict(r), "findings": [m["finding_id"] for m in self.db.query(
                "SELECT finding_id FROM root_cause_findings WHERE "
                "root_cause_id=? LIMIT 100", (r["id"],))]}
            for r in self.db.query(
                "SELECT * FROM root_causes WHERE id IN (SELECT "
                "root_cause_id FROM root_cause_findings WHERE finding_id=?) "
                "LIMIT 20", (finding_id,))]
        view["risk_history"] = self.snapshots.history(finding_id, limit=50)
        return view

    def prioritized(self, project_id: str, *, limit: int = 100,
                    statuses: tuple = ("open", "confirmed", "in_review",
                                       "acknowledged", "reopened")) -> list:
        """Deterministic P0→P4 prioritization (never severity alone)."""
        placeholders = ",".join("?" for _ in statuses)
        rows = self.db.query(
            f"SELECT id, title, severity, confidence_score, risk_score, "
            f"risk_level, priority, priority_order, asset_id, category, "
            f"lifecycle, last_detected FROM findings WHERE project_id=? AND "
            f"lifecycle IN ({placeholders}) ORDER BY priority_order, "
            f"risk_score DESC, last_detected DESC LIMIT ?",
            (project_id, *statuses, limit))
        return [dict(r) for r in rows]
