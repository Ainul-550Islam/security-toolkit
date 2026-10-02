#!/usr/bin/env python3
"""privacy.py — subject-level data minimization (Phase 11).

Restriction: detection is conservative and never claims completeness; the
legal interpretation of privacy requests remains the customer/operator
responsibility (this module makes no legal or compliance claim).
"""
# ============================================================================
#  privacy.py — Phase 11: subject-level data minimization for the platform's
#  own stored content (no external DLP; no second redaction engine).
#  ---------------------------------------------------------------------------
#  Everything here REUSES the Phase-11 foundation:
#    - data_governance._Base      (rate limiting + immutable audit emission)
#    - data_governance.RetentionService holds   (fail closed on active holds)
#    - data_governance.PrivacyRequestService    (the request workflow — this
#      module only performs the DATA actions a request triggers)
#    - redact.py                  (the one and only redaction implementation)
#  Detection & correction are CONSERVATIVE: the module explicitly never
#  claims to find every instance of personal data ("no perfect-PII" rule),
#  and legal interpretation of privacy requests remains the operator's
#  responsibility (documented, non-goal).
# ============================================================================

from __future__ import annotations

import json

import errors
import metrics
import models
import redact
import store

import data_governance as _dg
from data_governance import _Base, _bound_int, _bounded, _now

MAX_SCAN_ROWS = 500
MAX_COVER_BATCH = 500
JSON_FIELDS = ("evidence", "raw", "extra", "metadata")

# ---------------------------------------------------------------------------
# Object map (allowlist): object_type -> table + org-scoped lookup +
# text fields (JSON fields handled JSON-safely) + retention hold bucket.
# Tables without org_id reach it via projects — the scoped SELECT enforces
# tenant isolation before any write.
# ---------------------------------------------------------------------------
OBJECT_MAP = {
    # every entry carries:
    #   scoped    tenant-scoped row read (id + org -> the row or NotFound)
    #   scope_sql org-filter for bulk scans (tables use their own prefix;
    #            `evidence` reaches org via findings)
    #   project_sql optional project filter (None = org-scoped only)
    "finding": {
        "table": "findings",
        "scoped": "SELECT * FROM findings f JOIN projects p ON "
                  "f.project_id=p.id WHERE f.id=? AND p.org_id=?",
        "scope_sql": "findings.project_id IN (SELECT id FROM projects "
                     "WHERE org_id=?)",
        "project_sql": "findings.project_id=?",
        "fields": {"title": False, "description": False,
                   "remediation": False, "evidence": True, "raw": True},
        "hold_kind": "findings",
    },
    "case": {
        "table": "investigation_cases",
        "scoped": "SELECT * FROM investigation_cases WHERE id=? AND org_id=?",
        "scope_sql": "investigation_cases.org_id=?",
        "project_sql": "investigation_cases.project_id=?",
        "fields": {"title": False, "description": False},
        "hold_kind": "case_history",
    },
    "evidence": {
        "table": "evidence",
        "scoped": "SELECT e.* FROM evidence e JOIN findings f ON "
                  "e.finding_id=f.id JOIN projects p ON f.project_id=p.id "
                  "WHERE e.id=? AND p.org_id=?",
        "scope_sql": "evidence.finding_id IN (SELECT f.id FROM findings f "
                     "JOIN projects p ON f.project_id=p.id WHERE p.org_id=?)",
        "project_sql": "evidence.finding_id IN (SELECT id FROM findings "
                       "WHERE project_id=?)",
        "fields": {"url": False, "request_snippet": False,
                   "response_snippet": False, "detection_reason": False},
        "hold_kind": "evidence",
    },
    "asset_observation": {
        "table": "asset_observations",
        "scoped": "SELECT * FROM asset_observations o JOIN projects p ON "
                  "o.project_id=p.id WHERE o.id=? AND p.org_id=?",
        "scope_sql": "asset_observations.project_id IN (SELECT id FROM "
                     "projects WHERE org_id=?)",
        "project_sql": "asset_observations.project_id=?",
        "fields": {"obs_value": False, "extra": True, "obs_key": False},
        "hold_kind": "asset_observations",
    },
    "ioc": {
        "table": "threat_indicators",
        "scoped": "SELECT * FROM threat_indicators WHERE id=? AND org_id=?",
        "scope_sql": "threat_indicators.org_id=?",
        "project_sql": None,
        "fields": {"indicator": False, "reference": False},
        "hold_kind": "threat_intel_data",
    },
}

# fields whose value is legal to CORRECT (never identity/audit columns)
CORRECTABLE = {
    "finding": ("title", "description", "remediation"),
    "case": ("title", "description"),
    "ioc": ("reference",),
}
# fields whose value is legal to RESTRICT (tombstone in place)
RESTRICTABLE = {
    "finding": ("description", "remediation", "evidence", "raw"),
    "case": ("description",),
    "evidence": ("url", "request_snippet", "response_snippet",
                 "detection_reason"),
    "asset_observation": ("obs_value", "extra"),
    "ioc": ("reference",),
}


def _like_escape(subject: str) -> str:
    return (str(subject).replace("\\", "\\\\").replace("%", "\\%")
            .replace("_", "\\_"))


def _contains_subject(value, subject: str) -> bool:
    return subject.lower() in str(value or "").lower()


class PrivacyService(_Base):
    """Subject-level minimization over the platform's own stored content.
    Request lifecycle LIVES in data_governance.PrivacyRequestService (this
    class exposes it as `workflow` — one implementation, no fork)."""

    def __init__(self, platform, *, limiter=None):
        super().__init__(platform, limiter=limiter)
        self.workflow = _dg.PrivacyRequestService(platform,
                                                  limiter=self.limiter)

    # ----------------------------------------------------------------- scan
    def scan(self, org_id: str, subject_ref: str, *, project_id: str = "",
             object_type: str = "", limit: int = 100) -> dict:
        """Conservative occurrence scan: counts per object type where the
        subject reference appears in stored text. Bounded, parameterized,
        and returns NO stored content (redacted hit counts only)."""
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"privacy:{org_id}", "privacy")
        subj = _bounded(str(subject_ref or "").strip(), 254)
        if len(subj) < 3:
            raise errors.ValidationError(
                "subject_ref must be at least 3 characters")
        lim = _bound_int(limit, lo=1, hi=MAX_SCAN_ROWS, default=100,
                         label="limit")
        like = "%" + _like_escape(subj) + "%"
        out = []
        for ot, spec in OBJECT_MAP.items():
            if object_type and ot != object_type:
                continue
            cols = list(spec["fields"])
            if not cols:
                continue
            where = [spec["scope_sql"]]
            args: list = [org_id]
            if project_id and spec.get("project_sql"):
                where.append(spec["project_sql"])
                args.append(project_id)
            ors = []
            for c in cols:
                ors.append(f"LOWER(CAST({spec['table']}." + c +
                           " AS TEXT)) LIKE LOWER(?) ESCAPE '\\'")
                args.append(like)
            where.append("(" + " OR ".join(ors) + ")")
            row = self._one(
                "SELECT COUNT(*) n FROM " + spec["table"] + " WHERE " +
                " AND ".join(where), args)
            n = int(row["n"]) if row else 0
            if n:
                out.append({"object_type": ot, "count": n})
        self._audit("privacy.updated", object_type="privacy_scan",
                    object_id=org_id, org_id=org_id, project_id=project_id,
                    actor="api",
                    metadata={"subject_ref": subj[:40],
                              "object_types": len(out)})
        return {"subject_ref": subj[:40],
                "note": "conservative detection; never a claim of "
                        "completeness; stored contents not returned",
                "object_types": out, "total": sum(o["count"] for o in out),
                "truncated": any(o["count"] > lim for o in out)}

    # ------------------------------------------------------- workflows
    def create_request(self, org_id: str, *, request_type: str,
                       subject_ref: str, project_id: str = "",
                       scope: dict | None = None, requester: str = "",
                       actor: str = "api") -> dict:
        return self.workflow.create(org_id, request_type=request_type,
                                    subject_ref=subject_ref,
                                    project_id=project_id, scope=scope,
                                    requester=requester, actor=actor)

    def request(self, org_id: str, request_id: str) -> dict:
        return self.workflow.get(org_id, request_id)

    def requests(self, org_id: str, *, status: str = "",
                 project_id: str = "", limit: int = 100,
                 offset: int = 0) -> dict:
        return self.workflow.list(org_id, status=status,
                                  project_id=project_id, limit=limit,
                                  offset=offset)

    # -------------------------------------------------------------- correct
    def correct(self, org_id: str, *, object_type: str, object_id: str,
                field: str, value, authorized: bool = False,
                actor: str = "api") -> dict:
        """Field-level correction for a documented allowlist of fields.
        Refused when an active hold covers the object (fail closed) or when
        the object's effective classification is restricted/secret/
        authentication_material and the caller is not authorized."""
        self._org(org_id)
        self._project_owned(org_id, "")
        self._acquire(f"privacy:{org_id}", "privacy")
        import data_governance as _mod
        ot = _bounded(str(object_type or "").strip().lower(), 64)
        oid = _bounded(str(object_id or "").strip(), 128)
        if ot not in OBJECT_MAP:
            raise errors.ValidationError(f"unknown object type: {ot!r}")
        spec = OBJECT_MAP[ot]
        row = self._one(spec["scoped"], (oid, org_id))
        if not row:
            raise errors.NotFoundError(f"{ot} not found")
        if field not in CORRECTABLE.get(ot, ()):
            raise errors.ValidationError(
                f"field {field!r} is not correctable for {ot} "
                f"(allowlist: {', '.join(CORRECTABLE.get(ot, ()))})")
        cls = _mod.ClassificationService(self.svc).effective(
            org_id, ot, oid)["effective"]
        if (cls in models.SENSITIVE_CLASSIFICATIONS and
                cls in ("restricted", "secret", "authentication_material")
                and not authorized):
            raise errors.AuthorizationError(
                "correcting a restricted/secret/authentication_material "
                "object requires explicit authorization")
        proj = self._project_id_of(spec, row)
        kind = spec["hold_kind"]
        if self._held(org_id, ot, oid) or self._held(org_id, kind, oid):
            raise errors.LifecycleError(
                "correction blocked by active hold")
        new_val = redact.redact_text(_bounded(str(value or ""), 4000))
        if new_val.strip() == "":
            raise errors.ValidationError("correction value is empty")
        with self.db.transaction() as conn:
            conn.execute(
                f"UPDATE {spec['table']} SET {field}=? WHERE id=?",
                (new_val, oid))
        self._audit("privacy.updated", object_type=ot, object_id=oid,
                    org_id=org_id, project_id=proj, actor=actor,
                    metadata={"field": field,
                              "classified": cls,
                              "corrected": True})
        self._emit(proj, "privacy.completed", key=oid,
                   new_state={"action": "correction"}, actor=actor)
        metrics.inc("governance_privacy_completed")
        return {"object_type": ot, "object_id": oid, "field": field,
                "corrected": True, "classification": cls,
                "value": new_val[:80]}

    # -------------------------------------------------------------- restrict
    def restrict(self, org_id: str, *, object_type: str, object_id: str,
                 fields, reason: str, actor: str = "api") -> dict:
        """Tombstone selected fields of a stored object IN PLACE (audit
        integrity: rows are never dropped; content is replaced by the
        platform's redaction marker). Refused under an active hold."""
        self._org(org_id)
        self._project_owned(org_id, "")
        self._acquire(f"privacy:{org_id}", "privacy")
        ot = _bounded(str(object_type or "").strip().lower(), 64)
        oid = _bounded(str(object_id or "").strip(), 128)
        if ot not in OBJECT_MAP:
            raise errors.ValidationError(f"unknown object type: {ot!r}")
        spec = OBJECT_MAP[ot]
        row = self._one(spec["scoped"], (oid, org_id))
        if not row:
            raise errors.NotFoundError(f"{ot} not found")
        rs = _bounded(redact.redact_text(str(reason or "").strip()), 300)
        if not rs:
            raise errors.ValidationError("reason is required")
        if isinstance(fields, str):
            flds = [fields]
        else:
            flds = list(fields or [])
        flds = [f for f in flds if f in RESTRICTABLE.get(ot, ())]
        if not flds:
            raise errors.ValidationError(
                f"no restrictable fields given (allowlist for {ot}: "
                f"{', '.join(RESTRICTABLE.get(ot, ()))})")
        proj = self._project_id_of(spec, row)
        kind = spec["hold_kind"]
        if self._held(org_id, ot, oid) or self._held(org_id, kind, oid):
            raise errors.LifecycleError("restriction blocked by active hold")
        marker = f"[REDACTED-SUBJECT: {rs}]"
        with self.db.transaction() as conn:
            for f in flds:
                conn.execute(
                    f"UPDATE {spec['table']} SET {f}=? WHERE id=?",
                    (marker if f not in JSON_FIELDS else
                     json.dumps([marker]), oid))
        self._audit("privacy.updated", object_type=ot, object_id=oid,
                    org_id=org_id, project_id=proj, actor=actor,
                    metadata={"fields": flds, "restricted": True,
                              "reason": rs})
        self._emit(proj, "privacy.completed", key=oid,
                   new_state={"action": "restriction"}, actor=actor)
        metrics.inc("governance_privacy_completed")
        return {"object_type": ot, "object_id": oid, "fields": flds,
                "restricted": True}

    # ---------------------------------------------------------------- cover
    def cover(self, org_id: str, *, subject_ref: str, object_type: str = "",
              project_id: str = "", batch: int = MAX_COVER_BATCH,
              actor: str = "api") -> dict:
        """Redact every occurrence of a subject reference in the mapped text
        fields of the platform's stored content. JSON fields are handled
        JSON-safely (parse -> replace -> re-serialize; on any failure the
        field is replaced by the marker rather than left partially leaked).
        Objects under an active hold are skipped (counted), never touched."""
        self._org(org_id)
        self._project_owned(org_id, project_id)
        self._acquire(f"privacy:{org_id}", "privacy")
        subj = _bounded(str(subject_ref or "").strip(), 254)
        if len(subj) < 3:
            raise errors.ValidationError(
                "subject_ref must be at least 3 characters")
        b = _bound_int(batch, lo=1, hi=MAX_COVER_BATCH,
                       default=MAX_COVER_BATCH, label="batch")
        totals = {"scanned": 0, "updated": 0, "skipped_held": 0}
        for ot, spec in OBJECT_MAP.items():
            if object_type and ot != object_type:
                continue
            totals = self._cover_table(org_id, ot, spec, subj, b, totals,
                                       project_id=project_id, actor=actor)
        self._audit("privacy.updated", object_type="privacy_cover",
                    object_id=org_id, org_id=org_id, project_id=project_id,
                    actor=actor, metadata={"subject_ref": subj[:40],
                                           **{k: totals[k]
                                              for k in ("updated",
                                                        "skipped_held")}})
        self._emit(project_id, "privacy.completed", key=org_id,
                   new_state={"action": "cover", "updated": totals["updated"]},
                   actor=actor)
        return {"subject_ref": subj[:40], **totals,
                "note": "conservative; no completeness claim; JSON fields "
                        "fail closed to the redaction marker"}

    def _cover_table(self, org_id: str, ot: str, spec: dict, subj: str,
                     batch: int, totals: dict, *, project_id: str,
                     actor: str) -> dict:
        table = spec["table"]
        cols = list(spec["fields"])
        where = [spec["scope_sql"]]
        args: list = [org_id]
        if project_id and spec.get("project_sql"):
            where.append(spec["project_sql"])
            args.append(project_id)
        like = "%" + _like_escape(subj) + "%"
        ors = []
        for c in cols:
            ors.append(f"LOWER(CAST({table}." + c +
                       " AS TEXT)) LIKE LOWER(?) ESCAPE '\\'")
            args.append(like)
        where.append("(" + " OR ".join(ors) + ")")
        rows = self._q(
            "SELECT " + table + ".id FROM " + table + " WHERE " +
            " AND ".join(where) + " ORDER BY " + table + ".id LIMIT ?",
            args + [batch])
        totals["scanned"] += len(rows)
        ids = [str(r["id"]) for r in rows]
        if not ids:
            return totals
        held = self._active_hold_ids(self.db, org_id, spec["hold_kind"],
                                     ids, _now())
        for r in rows:
            rid = str(r["id"])
            if rid in held:
                totals["skipped_held"] += 1
                continue
            full = self._one(spec["scoped"], (rid, org_id))
            if not full:
                continue
            self._privacy_safe = True
            with self.db.transaction() as conn:
                for c in cols:
                    val = str(full.get(c) or "")
                    if subj.lower() not in val.lower():
                        continue
                    if c in JSON_FIELDS:
                        try:
                            parsed = json.loads(val)
                            text = json.dumps(parsed, sort_keys=True,
                                              ensure_ascii=False)
                            if subj.lower() in text.lower():
                                newtext = text.replace(subj, "[REDACTED-SUBJECT]")
                                json.loads(newtext)   # validate
                                newval = newtext
                            else:
                                continue
                        except Exception:
                            newval = json.dumps(["[REDACTED-SUBJECT]"])
                        conn.execute(
                            f"UPDATE {table} SET {c}=? WHERE id=?",
                            (newval, rid))
                        totals["updated"] += 1
                    else:
                        newval = val.replace(subj, "[REDACTED-SUBJECT]")
                        conn.execute(
                            f"UPDATE {table} SET {c}=? WHERE id=?",
                            (newval, rid))
                        totals["updated"] += 1
        return totals

    # ------------------------------------------------------------ helpers
    def _project_id_of(self, spec: dict, row: dict) -> str:
        return str(row.get("project_id") or "")

    def _held(self, org_id: str, object_type: str, object_id: str) -> bool:
        return bool(self._one(
            "SELECT 1 x FROM retention_holds WHERE org_id=? AND "
            "object_type=? AND object_id=? AND released_at='' AND "
            "(expires_at='' OR expires_at>?)", (org_id, object_type,
                                                 object_id, _now())))

    def _active_hold_ids(self, db, org_id: str, object_type: str,
                         ids: list[str], now: str) -> set[str]:
        marks = ",".join("?" for _ in ids)
        rows = db.query(
            "SELECT object_id FROM retention_holds WHERE org_id=? AND "
            "object_type=? AND released_at='' AND (expires_at='' OR "
            "expires_at>?) AND object_id IN (" + marks + ")",
            (org_id, object_type, now) + tuple(ids))
        return {str(r["object_id"]) for r in rows}
