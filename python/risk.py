#!/usr/bin/env python3
# ============================================================================
#  risk.py — Phase 4 deterministic Confidence + Risk engines.
#  ---------------------------------------------------------------------------
#  Design rules:
#    - DETERMINISTIC: identical inputs ⇒ identical scores (no randomness, no
#      timestamps inside the score, no user-supplied multipliers)
#    - EXPLAINABLE: every score carries bounded, structured factors
#    - BOUNDED: confidence 0.00–1.00, risk 0–100, priority P0–P4
#    - SEVERITY ≠ RISK: raw severity is preserved untouched; risk is computed
#      from severity + confidence + exposure + criticality + business impact
#      + exploitability + recurrence
#    - NO invented compromise claims: exploitability is derived ONLY from
#      deterministic category/rule hints, never from "suspicion"
#    - VERSIONED: calc_version="risk-v1" accompanies every snapshot so old
#      scores stay interpretable when the algorithm later changes
#    - SECRET-SAFE: factors contain categories only; all inputs pass through
#      redact.redact_text(); snapshots never carry raw evidence text
# ============================================================================

from __future__ import annotations

import models
import metrics
import redact
import store

CALC_VERSION = "risk-v1"

# --- severity base weight (0..1) -------------------------------------------
_SEVERITY_BASE = {"Critical": 0.90, "High": 0.70, "Medium": 0.50,
                  "Low": 0.30, "Info": 0.10}
_SEVERITY_POINTS = {"Critical": 25, "High": 20, "Medium": 14,
                    "Low": 8, "Info": 3}

# --- stage-2 weights (all bounded, no randomness) ---------------------------
_CONF_WEIGHT = 0.20          # multiplied by confidence score (0..1)
_EXPOSURE_WEIGHT = {"internet_facing": 15, "internal": 5, "restricted": 0,
                    "unknown": 3}
_CRITICALITY_WEIGHT = {"critical": 15, "high": 11, "medium": 7, "low": 3,
                       "unknown": 4}
_EXPLOITABILITY_WEIGHT = {"high": 12, "medium": 7, "low": 3, "unknown": 2}
_BUSINESS_WEIGHT = {"payment_related": 10, "authentication_system": 10,
                    "sensitive_data": 7, "customer_facing": 6,
                    "administrative_system": 6, "production_system": 5,
                    "internet_exposed": 4, "internal_only": 0}
_RECURRENCE_WEIGHT = 4        # capped at +8 for occurrence_count >= 2

# --- confidence dimensions --------------------------------------------------
_SOURCE_RELIABILITY = {          # who reported it (bounded, static table)
    "web_security_audit": 0.92, "secuaudit": 0.92, "api_security_audit": 0.88,
    "secuaudit_api": 0.88, "template_engine": 0.86, "nucleus": 0.86,
    "active_fuzzer": 0.80, "injector": 0.80, "spider": 0.55, "secuspider": 0.55,
    "waf_detect": 0.65, "wallfinder": 0.65, "cloud_check": 0.82,
    "subdomain_enum": 0.72, "subkraken": 0.72, "port_scanner": 0.78,
    "dir_fuzzer": 0.70, "workflow": 0.80, "recon": 0.72, "scanner": 0.50,
}
_DEFAULT_SOURCE = 0.50
_EVIDENCE_POINTS = (0.05, 0.11, 0.18, 0.25)    # 1..4 + evidence records
_AGREEMENT_BONUS = 0.08                        # ≥2 distinct sources
_ASSET_CERTAINTY = {"exact": 0.10, "derived": 0.05, "none": 0.0}
_REPRO_BONUS = 0.05                            # occurrence_count ≥ 2

CONFIDENCE_LEVELS = {"high": 0.85, "medium": 0.62, "low": 0.40}
CONFIDENCE_LABELS = ("high", "medium", "low", "unverified")


def _round2(x: float) -> float:
    return round(float(x) + 1e-9, 2)


def _clamp01(x: float) -> float:
    return min(1.0, max(0.0, float(x)))


class ConfidenceEngine:
    """Deterministic confidence scoring (bounded 0.00–1.00)."""

    @staticmethod
    def level_for(score: float) -> str:
        score = _clamp01(score)
        for label, threshold in (("high", CONFIDENCE_LEVELS["high"]),
                                 ("medium", CONFIDENCE_LEVELS["medium"]),
                                 ("low", CONFIDENCE_LEVELS["low"])):
            if score >= threshold:
                return label
        return "unverified"

    def compute(self, *, severity: str, source: str,
                evidence_count: int, distinct_sources: set,
                asset_certainty: str = "exact",
                occurrence_count: int = 1,
                declared_confidence: str = "medium") -> dict:
        """Deterministic confidence dimensions → (score, level, reasons).
        `declared_confidence` is the scanner's own label (low/medium/high/
        confirmed) — an INPUT, never a way to force the score to 100%."""
        score = 0.0
        reasons = []
        # 1. source reliability (bounded static map)
        rel = _SOURCE_RELIABILITY.get(
            str(source or "").strip().lower(), _DEFAULT_SOURCE)
        score += rel * 0.40
        reasons.append(f"source reliability {rel:.2f}")
        # 2. evidence completeness (capped at 4+ records)
        ev = min(int(evidence_count), 4)
        score += _EVIDENCE_POINTS[ev - 1] if ev >= 1 else 0.0
        reasons.append(f"evidence records {ev}")
        # 3. scanner agreement (deduplicated observations from other tools)
        agree = max(0, len({str(s).lower() for s in distinct_sources} - {
            str(source or "").lower()}) )
        if agree >= 1:
            score += _AGREEMENT_BONUS * min(agree, 2)
            reasons.append(f"{agree} agreeing source(s)")
        # 4. asset certainty (exact asset match vs derived)
        score += _ASSET_CERTAINTY.get(str(asset_certainty or "none"), 0.0)
        if asset_certainty:
            reasons.append(f"asset certainty {asset_certainty}")
        # 5. reproducibility (seen before)
        if int(occurrence_count or 1) >= 2:
            score += _REPRO_BONUS
            reasons.append(f"{occurrence_count} occurrences")
        # 6. declared confidence as a weak prior — never a shortcut to 1.0
        prior = {"low": 0.0, "medium": 0.02, "high": 0.05,
                 "confirmed": 0.06}.get(str(declared_confidence).lower(), 0.0)
        score += prior
        if prior:
            reasons.append(f"scanner prior {declared_confidence}")
        score = _round2(_clamp01(score))
        return {"confidence_score": score,
                "confidence_level": self.level_for(score),
                "confidence_reasons": redact.redact(reasons)}


class RiskEngine:
    """Deterministic, explainable, bounded risk scoring (0–100)."""

    @staticmethod
    def level_for(score: float) -> str:
        score = min(100.0, max(0.0, float(score)))
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "info"

    @staticmethod
    def priority_for(risk_score: float, confidence: float,
                     exposure: str, criticality: str) -> tuple:
        """P0..P4 from risk + context — severity alone never decides it."""
        score = float(risk_score)
        conf = float(confidence)
        bump = 0
        if exposure == "internet_facing" and criticality in ("high", "critical"):
            bump = 1
        eff = score + (5 * bump)
        if eff >= 85 and conf >= 0.55:
            return "P0", 0
        if eff >= 70 or (eff >= 60 and conf >= 0.62):
            return "P1", 1
        if eff >= 50:
            return "P2", 2
        if eff >= 30:
            return "P3", 3
        return "P4", 4

    @staticmethod
    def exploitability_for(category: str, rule_id: str, title: str) -> str:
        """Deterministic exploitability hint from category/rule/title ONLY.
        This is a code-level classification, never an exploitation claim."""
        blob = " ".join([str(category or ""), str(rule_id or ""),
                         str(title or "")]).lower()
        if any(k in blob for k in ("sqli", "injection", "rce", "deserial",
                                   "ssrf", "xss", "traversal", "command")):
            return "high"
        if any(k in blob for k in ("csrf", "auth", "open_redirect", "xxe",
                                   "header", "misconfig", "weak")):
            return "medium"
        if any(k in blob for k in ("disclosure", "info", "fingerprint",
                                   "tls", "version", "cve")):
            return "low"
        return "unknown"

    def compute(self, *, severity: str, confidence_score: float,
                exposure: str, criticality: str,
                business_impact: dict | None = None,
                category: str = "other", rule_id: str = "",
                title: str = "", occurrence_count: int = 1,
                internet_exposed: bool = False,
                declared_exploitability: str = "unknown") -> dict:
        """All inputs are bounded/mapped; output score is deterministic."""
        bi = business_impact or {}
        factors = []
        total = 0.0

        sev_pts = _SEVERITY_POINTS.get(str(severity), 3)
        total += sev_pts
        factors.append({"name": "severity",
                        "delta": sev_pts,
                        "reason": f"{severity} severity"})

        conf = _clamp01(float(confidence_score or 0.0))
        total += round(_CONF_WEIGHT * conf * 100, 1)
        factors.append({"name": "confidence",
                        "delta": round(_CONF_WEIGHT * conf * 100, 1),
                        "reason": f"confidence {conf:.2f}"})

        exp = str(exposure or "unknown")
        exp_pts = _EXPOSURE_WEIGHT.get(exp, 3) + \
            (4 if (internet_exposed or exp == "internet_facing") else 0)
        total += exp_pts
        factors.append({"name": "exposure", "delta": exp_pts,
                        "reason": f"{exp} exposure"})

        crit = str(criticality or "unknown")
        crit_pts = _CRITICALITY_WEIGHT.get(crit, 4)
        total += crit_pts
        factors.append({"name": "asset_criticality", "delta": crit_pts,
                        "reason": f"{crit} asset"})

        expl = str(declared_exploitability or "unknown")
        if expl == "unknown":
            expl = self.exploitability_for(category, rule_id, title)
        expl_pts = _EXPLOITABILITY_WEIGHT.get(expl, 2)
        total += expl_pts
        factors.append({"name": "exploitability", "delta": expl_pts,
                        "reason": f"{expl} exploitability hint"})

        biz = 0.0
        for dim, weight in sorted(_BUSINESS_WEIGHT.items()):
            if bi.get(dim):
                biz += weight
                factors.append({"name": "business_impact",
                                "delta": weight,
                                "reason": f"{dim} impact tag"})
        total += biz

        rec = min(8, _RECURRENCE_WEIGHT *
                  max(0, int(occurrence_count or 1) - 1))
        if rec:
            total += rec
            factors.append({"name": "recurrence", "delta": rec,
                            "reason": f"{occurrence_count} occurrences"})

        score = int(round(min(100.0, max(0.0, total))))
        level = self.level_for(score)
        priority, order = self.priority_for(score, conf, exp, crit)
        return {"risk_score": score, "risk_level": level,
                "risk_factors": factors,
                "priority": priority, "priority_order": order,
                "exploitability": expl,
                "calc_version": CALC_VERSION}


class RiskSnapshotService:
    """Historical risk snapshots — recorded when the value CHANGES, so the
    table grows with real change points, not with every scan tick."""

    def __init__(self, platform):
        self.svc = platform
        self.db = platform.db

    def record(self, finding_id: str, *, project_id: str = "",
               risk_score: int, risk_level: str, severity: str,
               confidence: float, asset_criticality: str, exposure: str,
               calc_version: str, factors: list,
               force: bool = False) -> dict:
        """Deterministic idempotent snapshot; identical input at the same
        second maps to the same row (INSERT OR IGNORE)."""
        ts = models.utcnow()
        last_rows = self.db.query(
            "SELECT risk_score, risk_level FROM risk_snapshots "
            "WHERE finding_id=? ORDER BY ts DESC LIMIT 1", (finding_id,))
        last = last_rows[0] if last_rows else None
        if last and not force:
            if abs(float(last["risk_score"]) - float(risk_score)) < 0.5 and \
                    last["risk_level"] == risk_level:
                return {"snapshot_id": "", "recorded": False,
                        "reason": "unchanged"}
        snap_id = models.stable_id(
            models.NS_RISK,
            f"{finding_id}|{calc_version}|{ts}|{risk_score}|{risk_level}")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO risk_snapshots (id, finding_id, "
                "project_id, ts, risk_score, risk_level, severity, "
                "confidence, asset_criticality, exposure, calc_version, "
                "factors) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (snap_id, finding_id, project_id, ts, risk_score, risk_level,
                 severity, confidence, asset_criticality, exposure,
                 calc_version, store.dumps(redact.redact(factors))))
        metrics.inc("risk_calculations")
        return {"snapshot_id": snap_id, "recorded": True,
                "ts": ts, "calc_version": calc_version}

    def history(self, finding_id: str, limit: int = 200) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM risk_snapshots WHERE finding_id=? "
            "ORDER BY ts DESC LIMIT ?", (finding_id, limit))
        out = []
        for r in rows:
            r["factors"] = store.loads(r.get("factors", "{}"))
            out.append(dict(r))
        return out

    def latest(self, finding_id: str) -> dict | None:
        rows = self.db.query(
            "SELECT * FROM risk_snapshots WHERE finding_id=? "
            "ORDER BY ts DESC LIMIT 1", (finding_id,))
        if not rows:
            return None
        r = rows[0]
        r["factors"] = store.loads(r.get("factors", "{}"))
        return dict(r)
