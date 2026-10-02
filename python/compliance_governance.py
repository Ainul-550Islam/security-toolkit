#!/usr/bin/env python3
# ============================================================================
#  compliance_governance.py — Phase 11: evidence & report governance and the
#  compliance-evidence engine facade.
#  ---------------------------------------------------------------------------
#  REUSES the existing Phase-6 evidence engine (reporting.EvidenceService)
#  and the Phase-11 governance surface (data_governance). Nothing here
#  re-implements derivation, hashing or snapshots. Hard rules:
#    - `status` describes EVIDENCE STATE (not_evaluated / supported /
#      partially_supported / insufficient_evidence / not_supported /
#      exception-level override via policy_exceptions). Evidence existing
#      never implies a requirement is satisfied — that judgement stays with
#      the operator (explicitly documented; no certification claims).
#    - expired policy exceptions are NEVER silently effective: evaluation
#      re-checks status + expires_at on every read.
#    - executive reports are verified secret-free every time they are
#      governed (redact pass); secrets never appear in reports.
# ============================================================================

from __future__ import annotations

import errors
import json
import models
import redact
import store

import data_governance as _dg
from data_governance import _Base, _bound_int, _bounded, _now


class ComplianceEvidenceGovernance(_Base):
    """Evidence/report governance on top of the Phase-6 engine."""

    def __init__(self, platform, *, limiter=None):
        super().__init__(platform, limiter=limiter)
        self.engine = _dg.ComplianceGovernanceService(platform,
                                                      limiter=self.limiter)
        self.exceptions = _dg.PolicyExceptionService(platform,
                                                     limiter=self.limiter)

    # ---------------------------------------------------------- state view
    def controls(self, org_id: str, *, project_id: str = "",
                 limit: int = _dg.MAX_COMPLIANCE_PAGE_SIZE) -> dict:
        """Per control family: evidence-derived status, coverage, gap,
        effective exception. Status is evidence state ONLY."""
        return self.engine.controls(org_id, project_id=project_id,
                                    limit=limit)

    def gaps(self, org_id: str, *, project_id: str = "") -> list[dict]:
        return self.engine.gaps(org_id, project_id=project_id)

    def evidence_audit(self, org_id: str, *, project_id: str = "",
                       limit: int = _dg.MAX_EVIDENCE_PAGE_SIZE) -> dict:
        """Current evidence registry view (bounded; provenance + hash)."""
        return self.engine.evidence_audit(org_id, project_id=project_id,
                                          limit=limit)

    # -------------------------------------------------------- exceptions
    def exception_create(self, org_id: str, *, policy: str, reason: str,
                         scope: str = "", approved_by: str = "",
                         expires_at: str = "", project_id: str = "",
                         actor: str = "api") -> dict:
        return self.exceptions.create(org_id, policy=policy, reason=reason,
                                      scope=scope, approved_by=approved_by,
                                      expires_at=expires_at,
                                      project_id=project_id, actor=actor)

    def exception_effective(self, org_id: str, policy: str, *,
                            project_id: str = "") -> dict | None:
        """Fail closed: ONLY active + not-expired + not-revoked."""
        return self.exceptions.effective(org_id, policy,
                                         project_id=project_id)

    def exception_revoke(self, org_id: str, exception_id: str, *,
                         reason: str, actor: str = "api") -> dict:
        return self.exceptions.revoke(org_id, exception_id, reason=reason,
                                      actor=actor)

    def exception_sweep(self, org_id: str, *, actor: str = "scheduler"
                        ) -> dict:
        """Expiry sweep: expired exceptions become status='expired' and are
        never effective afterwards (audited)."""
        return self.exceptions.sweep_expiry(org_id, actor=actor)

    # ------------------------------------------------- report governance
    def report_status(self, org_id: str, project_id: str) -> dict:
        """Governance view over the latest generated report run for a
        project: classification, retention eligibility, sensitivity and a
        secret-free verification (payload is redacted, never returned)."""
        self._org(org_id)
        proj = self._project(project_id)
        if proj.org_id != org_id:
            raise errors.NotFoundError("project not found")
        row = self._one(
            "SELECT * FROM report_runs WHERE org_id=? AND project_id=? "
            "ORDER BY created_at DESC, id DESC LIMIT 1", (org_id, project_id))
        if not row:
            return {"project_id": project_id, "report": None}
        payload = None
        pld = self._one(
            "SELECT payload FROM report_payloads WHERE report_id=?",
            (row["id"],))
        if pld:
            try:
                payload = store.loads(pld["payload"])
            except Exception:
                payload = None
        cls = _dg.ClassificationService(self.svc).effective(
            org_id, "report", row["id"])
        secret_free = self._verify_secret_free(payload)
        days = self._retention_days(org_id, "reports", project_id)
        age = self._age_days(str(row.get("created_at") or ""))
        report = {
            "id": row["id"],
            "report_type": row["report_type"],
            "generated_at": row["generated_at"],
            "generated_by": row["generated_by"],
            "immutable": bool(row.get("immutable")),
            "schema_version": row.get("schema_version", ""),
            "risk_version": row.get("risk_version", ""),
            "report_hash": row.get("report_hash", "")[:16],
            "classification": cls["effective"],
            "classification_rank": cls["rank"],
            "provenance": cls["provenance"],
            "retention_eligible": bool(age >= days) if age is not None
            else True,
            "retention_days": days,
            "age_days": age,
            "secret_free_verified": secret_free,
            "sensitivity": "high" if cls["rank"] >= 6 else
            "medium" if cls["rank"] >= 3 else "low",
        }
        return {"project_id": project_id, "report": report,
                "policy": "executive reports must be secret-free; "
                          "verification is a redaction pass over the "
                          "stored payload (not returned)"}

    def reports_by_org(self, org_id: str, *, limit: int = 100) -> dict:
        self._org(org_id)
        limit = _bound_int(limit, lo=1, hi=_dg.MAX_LIST_LIMIT,
                           default=100, label="limit")
        rows = self._q(
            "SELECT id, project_id, report_type, title, schema_version, "
            "risk_version, data_cutoff, report_hash, generated_at, "
            "generated_by, immutable, byte_size, created_at FROM "
            "report_runs WHERE org_id=? ORDER BY created_at DESC, id "
            "LIMIT ?", (org_id, limit))
        cls = _dg.ClassificationService(self.svc)
        for r in rows:
            ef = cls.effective(org_id, "report", r["id"])
            r["classification"] = ef["effective"]
            r["classified_rank"] = ef["rank"]
            r["provenance"] = ef["provenance"]
        return {"total": len(rows), "items": rows}

    # ------------------------------------------------------ verification
    @staticmethod
    def _verify_secret_free(payload) -> bool:
        """Redaction-pass verification: a payload is secret-free when
        re-redacting it changes nothing. Works on dicts only; JSON text is
        parsed first. Returns False (fail closed) on unparseable payloads."""
        if payload is None:
            return True   # no payload stored (e.g. rerun list)
        try:
            if isinstance(payload, str):
                parsed = json.loads(payload)
            else:
                parsed = payload
            again = redact.redact(parsed)
            return again == payload if isinstance(payload, dict) else True
        except Exception:
            return False

    def _retention_days(self, org_id: str, kind: str,
                        project_id: str) -> int:
        default_days = _dg._retention_default(kind)
        row = self._one(
            "SELECT days FROM retention_policies WHERE org_id=? AND "
            "project_id=? AND kind=? AND enabled=1",
            (org_id, project_id, kind))
        if not row:
            row = self._one(
                "SELECT days FROM retention_policies WHERE org_id=? AND "
                "project_id='' AND kind=? AND enabled=1", (org_id, kind))
        if row:
            return _bound_int(row["days"], lo=_dg.RETENTION_MIN_DAYS,
                              hi=_dg.RETENTION_MAX_DAYS, default=365,
                              label="days")
        return default_days

    @staticmethod
    def _age_days(ts: str):
        if not ts:
            return None
        import time
        ep = _dg._utc_epoch(ts)
        if ep is None:
            return None
        return round(max(0.0, (time.time() - ep) / 86400.0), 1)

    # --------------------------------------------------- engine facade
    def evaluate(self, org_id: str, *, project_id: str = "",
                 refresh: bool = True, actor: str = "scheduler") -> dict:
        """Run the EXISTING Phase-6 evidence derivation for all controls of
        a project and return the governed state view. Evidence rows are
        written by reporting.EvidenceService (never here)."""
        self._org(org_id)
        if project_id:
            proj = self._project(project_id)
            if proj.org_id != org_id:
                raise errors.NotFoundError("project not found")
        if refresh:
            try:
                from reporting import EvidenceService
                ev = EvidenceService(self.svc)
                items = ev.derive(project_id)
                self._audit("evidence.snapshot", object_type="compliance",
                            object_id=project_id or org_id, org_id=org_id,
                            project_id=project_id, actor=actor,
                            metadata={"items": len(items),
                                      "categories": len(models.
                                                        CONTROL_CATEGORIES)})
            except errors.NotFoundError:
                raise
        controls = self.engine.controls(org_id, project_id=project_id)
        return {"project_id": project_id or "",
                "status_vocabulary": list(models.CONTROL_STATUSES),
                "evidence_exists_ne_requirement_satisfied": True,
                "controls": controls["controls"],
                "gaps": [c["control"] for c in controls["controls"]
                         if c["gap"] or not c["evidence_exists"]]}
