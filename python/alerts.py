#!/usr/bin/env python3
# ============================================================================
#  alerts.py — Phase 5 deterministic alert rule engine + alert lifecycle.
#  ---------------------------------------------------------------------------
#  - Rules are project-scoped, allowlist-validated conditions (NO eval, NO
#    user code): explicit operators + explicit context field names + typed
#    values only. Malformed rules evaluate to False (fail closed).
#  - Alert identity is DETERMINISTIC and separate from occurrences:
#      identity_key = project | rule | event_type | asset | fingerprint | group
#    → one Alert row per underlying issue; every firing is one occurrence.
#  - Cooldown + suppression + grouping are the anti-fatigue guards; nothing
#    is ever silently dropped — suppressed/deduplicated items stay queryable.
#  - Transitions are centralized (models.ALERT_TRANSITIONS); invalid
#    transitions fail closed; user-driven transitions are audited.
#  - Alert severity is independent of finding severity (rule-declared).
#  - Secrets never enter rule conditions, alerts or occurrences.
# ============================================================================

from __future__ import annotations

import re
import time

import errors
import metrics
import models
import redact
import store

# --- condition vocabulary (explicit allowlists — no eval anywhere) ----------
OPERATORS = ("==", "!=", ">", ">=", "<", "<=", "in", "not_in")
CONTEXT_FIELDS = frozenset({
    "event_type", "asset_id", "title", "severity", "risk_score", "risk_level",
    "priority", "confidence_score", "exposure", "asset_criticality",
    "occurrence_count", "fingerprint", "source", "lifecycle",
})
_FIELD_TYPES = {
    "risk_score": float, "confidence_score": float, "occurrence_count": int,
    "severity": str, "risk_level": str, "priority": str, "exposure": str,
    "asset_criticality": str, "event_type": str, "asset_id": str,
    "title": str, "fingerprint": str, "source": str, "lifecycle": str,
}
_MAX_RULE_CONDITIONS = 8
_MAX_COND_DEPTH = 2
_LIMIT_RULES = 200
ALERT_OP_LIMIT = 60            # user-driven alert ops per actor per window
ALERT_OP_WINDOW = 300          # seconds
_LIMIT_ALERTS = 500
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _epoch(ts: str) -> float:
    try:
        return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def _iso(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


def _coerce(field: str, value):
    """Coerce a context value to the field's declared type (fail closed)."""
    typ = _FIELD_TYPES.get(field)
    if typ is None:
        return None
    try:
        if typ is int:
            return int(value)
        if typ is float:
            return float(value)
        return str(value)
    except (TypeError, ValueError):
        return None


def validate_condition(cond) -> None:
    """Recursive allowlist validation. Raises ValidationError on anything
    outside the vocabulary (never evaluated — fail closed). An empty dict
    is a valid no-op condition (rule is purely event-type-scoped)."""
    if isinstance(cond, dict) and not cond:
        return
    if isinstance(cond, dict):
        op = cond.get("op")
        if op in ("and", "or"):
            subs = cond.get("conditions")
            if not isinstance(subs, list) or not subs or \
                    len(subs) > _MAX_RULE_CONDITIONS:
                raise errors.ValidationError(
                    "condition_rejected: and/or requires 1..8 conditions")
            depth = [0]
            _depth(cond, 0, depth)
            if depth[0] > _MAX_COND_DEPTH:
                raise errors.ValidationError(
                    "condition_rejected: condition nesting too deep")
            for s in subs:
                validate_condition(s)
            return
        field = cond.get("field")
        cop = cond.get("op")
        value = cond.get("value")
        if field not in CONTEXT_FIELDS:
            raise errors.ValidationError(
                f"condition_rejected: unknown field {field!r}")
        if cop not in OPERATORS:
            raise errors.ValidationError(
                f"condition_rejected: unknown operator {cop!r}")
        if cop in ("in", "not_in"):
            if not isinstance(value, list) or not value or \
                    len(value) > 10:
                raise errors.ValidationError(
                    f"condition_rejected: {cop} needs a 1..10 item list")
            for v in value:
                if not isinstance(v, (str, int, float)):
                    raise errors.ValidationError(
                        f"condition_rejected: bad list value {v!r}")
            return
        if isinstance(value, bool) or (isinstance(value, (int, float)) and
                                       not isinstance(value, bool)):
            return
        if isinstance(value, str):
            if len(value) > 200:
                raise errors.ValidationError(
                    "condition_rejected: string value too long")
            return
        raise errors.ValidationError(
            f"condition_rejected: unsupported value {value!r}")
    raise errors.ValidationError("condition_rejected: must be a dict")


def _depth(cond, d, out):
    if not isinstance(cond, dict):
        return
    out[0] = max(out[0], d)
    for s in (cond.get("conditions") or []):
        _depth(s, d + 1, out)


def evaluate_condition(cond, context: dict) -> bool:
    """Deterministic condition evaluation. Malformed conditions → False."""
    if isinstance(cond, dict) and not cond:
        return True  # empty dict is a valid no-op condition (matches all)
    if not isinstance(cond, dict):
        return False
    op = cond.get("op")
    try:
        if op == "and":
            return all(evaluate_condition(s, context) for s in
                       (cond.get("conditions") or []))
        if op == "or":
            return any(evaluate_condition(s, context) for s in
                       (cond.get("conditions") or []))
        field = cond.get("field")
        cop = cond.get("op")
        value = cond.get("value")
        if field not in CONTEXT_FIELDS or cop not in OPERATORS:
            return False
        actual = _coerce(field, context.get(field))
        if actual is None:
            return False  # missing/typed context never matches
        if cop in ("in", "not_in"):
            hit = any(str(actual) == str(v) for v in (value or []))
            return hit if cop == "in" else not hit
        try:
            expected = value
            if isinstance(actual, float) and not isinstance(expected, bool):
                expected = float(expected)
            elif isinstance(actual, int) and not isinstance(expected, bool):
                expected = int(expected)
            if cop == "==":
                return actual == expected
            if cop == "!=":
                return actual != expected
            if cop == ">":
                return actual > expected
            if cop == ">=":
                return actual >= expected
            if cop == "<":
                return actual < expected
            if cop == "<=":
                return actual <= expected
        except (TypeError, ValueError):
            return False
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# Default rule templates (deterministic ids; enable per project)
# ---------------------------------------------------------------------------
DEFAULT_RULE_TEMPLATES = (
    {"name": "new-finding", "event_type": "finding.created",
     "condition": {"field": "event_type", "op": "==",
                   "value": "finding.created"},
     "severity": "medium", "cooldown_minutes": 120, "group_by": "asset"},
    {"name": "critical-finding", "event_type": "finding.created",
     "condition": {"op": "and", "conditions": [
         {"field": "severity", "op": "==", "value": "Critical"},
         {"field": "lifecycle", "op": "!=", "value": "false_positive"}]},
     "severity": "critical", "cooldown_minutes": 60, "group_by": "none"},
    {"name": "high-risk", "event_type": "",
     "condition": {"field": "risk_score", "op": ">=", "value": 80},
     "severity": "critical", "cooldown_minutes": 60, "group_by": "none"},
    {"name": "risk-increase", "event_type": "risk.increased",
     "condition": {"field": "risk_score", "op": ">=", "value": 50},
     "severity": "high", "cooldown_minutes": 240, "group_by": "none"},
    {"name": "finding-reopened", "event_type": "finding.reopened",
     "condition": {"field": "event_type", "op": "==",
                   "value": "finding.reopened"},
     "severity": "high", "cooldown_minutes": 240, "group_by": "none"},
    {"name": "new-internet-asset", "event_type": "asset.created",
     "condition": {"field": "exposure", "op": "==",
                   "value": "internet_facing"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "new-exposed-service", "event_type": "service.opened",
     "condition": {"field": "exposure", "op": "==",
                   "value": "internet_facing"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "asset"},
    {"name": "technology-change", "event_type": "technology.changed",
     "condition": {"field": "event_type", "op": "==",
                   "value": "technology.changed"},
     "severity": "low", "cooldown_minutes": 1440, "group_by": "asset"},
    {"name": "vulnerable-version", "event_type": "version.changed",
     "condition": {"field": "event_type", "op": "==",
                   "value": "version.changed"},
     "severity": "low", "cooldown_minutes": 1440, "group_by": "asset"},
    {"name": "asset-disappeared", "event_type": "asset.removed",
     "condition": {"field": "event_type", "op": "==",
                   "value": "asset.removed"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "monitoring-failure", "event_type": "monitoring.scan_failure",
     "condition": {"field": "event_type", "op": "in",
                   "value": ["monitoring.missed_scan", "monitoring.scan_failure",
                             "monitoring.stale", "monitoring.worker_unavailable",
                             "monitoring.notification_failure",
                             "monitoring.verification_failure"]},
     "severity": "high", "cooldown_minutes": 60, "group_by": "none"},
    # --- Phase 11: data protection / privacy / secrets governance events
    # (same rule engine, same condition vocabulary — no second alerting
    # system; event metadata never contains secret values)
    {"name": "secret-expiring", "event_type": "secret.expiring",
     "condition": {"field": "event_type", "op": "==",
                   "value": "secret.expiring"},
     "severity": "high", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "secret-expired", "event_type": "secret.expired",
     "condition": {"field": "event_type", "op": "==",
                   "value": "secret.expired"},
     "severity": "critical", "cooldown_minutes": 60, "group_by": "none"},
    {"name": "secret-rotation-required", "event_type":
     "secret.rotation_required",
     "condition": {"field": "event_type", "op": "==",
                   "value": "secret.rotation_required"},
     "severity": "high", "cooldown_minutes": 240, "group_by": "none"},
    {"name": "secret-revoked", "event_type": "secret.revoked",
     "condition": {"field": "event_type", "op": "==",
                   "value": "secret.revoked"},
     "severity": "high", "cooldown_minutes": 240, "group_by": "none"},
    {"name": "retention-violation", "event_type": "retention.violation",
     "condition": {"field": "event_type", "op": "==",
                   "value": "retention.violation"},
     "severity": "critical", "cooldown_minutes": 60, "group_by": "none"},
    {"name": "hold-created", "event_type": "hold.created",
     "condition": {"field": "event_type", "op": "==",
                   "value": "hold.created"},
     "severity": "high", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "sensitive-data-exported", "event_type": "sensitive.exported",
     "condition": {"field": "event_type", "op": "==",
                   "value": "sensitive.exported"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "privacy-request-filed", "event_type": "privacy.requested",
     "condition": {"field": "event_type", "op": "==",
                   "value": "privacy.requested"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "policy-exception-expired", "event_type":
     "policy_exception.expired",
     "condition": {"field": "event_type", "op": "==",
                   "value": "policy_exception.expired"},
     "severity": "medium", "cooldown_minutes": 1440, "group_by": "none"},
    # --- Phase 12: federation / evidence exchange / bulk / integrations
    # (same rule engine + condition vocabulary; event metadata carries
    # identifiers and counts only — never package payloads or secrets)
    {"name": "federation-integrity-failure", "event_type":
     "federation.integrity_failure",
     "condition": {"field": "event_type", "op": "==",
                   "value": "federation.integrity_failure"},
     "severity": "critical", "cooldown_minutes": 60, "group_by": "none"},
    {"name": "federation-import-rejected", "event_type":
     "federation.package_rejected",
     "condition": {"field": "event_type", "op": "==",
                   "value": "federation.package_rejected"},
     "severity": "high", "cooldown_minutes": 240, "group_by": "none"},
    {"name": "federation-peer-revoked", "event_type":
     "federation.peer_revoked",
     "condition": {"field": "event_type", "op": "==",
                   "value": "federation.peer_revoked"},
     "severity": "high", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "federation-peer-expired", "event_type":
     "federation.peer_expired",
     "condition": {"field": "event_type", "op": "==",
                   "value": "federation.peer_expired"},
     "severity": "high", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "federation-policy-expired", "event_type":
     "federation.policy_expired",
     "condition": {"field": "event_type", "op": "==",
                   "value": "federation.policy_expired"},
     "severity": "medium", "cooldown_minutes": 1440, "group_by": "none"},
    {"name": "bulk-operation-failed", "event_type": "bulk.failed",
     "condition": {"field": "event_type", "op": "==", "value": "bulk.failed"},
     "severity": "high", "cooldown_minutes": 240, "group_by": "none"},
    {"name": "integration-delivery-failed", "event_type": "integration.failed",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.failed"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "none"},
    # --- Phase 13: enterprise integration pipeline (§32/§33)
    # The SAME rule engine, condition vocabulary and cooldown/grouping
    # semantics as every rule above — no second alerting path exists.
    # `integration-delivery-failed` (declared above, Phase 12) already
    # covers delivery failures and is deliberately NOT duplicated here.
    # Event metadata carries identifiers, counts, statuses and hashes
    # only: never credentials, never authorization headers, never inbound
    # payload bodies.
    #
    # Inbound authentication failures are the highest-signal integration
    # event (a wrong/forged signature on a tenant-scoped endpoint), so it
    # fires at high severity with a short cooldown; the rest are grouped
    # to keep a noisy provider from flooding the operator.
    {"name": "integration-auth-failure", "event_type":
     "integration.auth_failure",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.auth_failure"},
     "severity": "high", "cooldown_minutes": 60, "group_by": "none"},
    {"name": "integration-replay-detected", "event_type":
     "integration.replay_detected",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.replay_detected"},
     "severity": "high", "cooldown_minutes": 240, "group_by": "none"},
    {"name": "integration-integrity-failure", "event_type":
     "integration.integrity_failure",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.integrity_failure"},
     "severity": "critical", "cooldown_minutes": 60, "group_by": "none"},
    {"name": "integration-policy-violation", "event_type":
     "integration.policy_violation",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.policy_violation"},
     "severity": "high", "cooldown_minutes": 240, "group_by": "none"},
    {"name": "integration-abnormal-volume", "event_type":
     "integration.abnormal_volume",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.abnormal_volume"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "integration-health-degraded", "event_type":
     "integration.health_degraded",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.health_degraded"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "none"},
    {"name": "integration-rate-limited", "event_type":
     "integration.rate_limited",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.rate_limited"},
     "severity": "medium", "cooldown_minutes": 720, "group_by": "none"},
    # credential governance: the connection references a secrets_registry
    # entry that is revoked/expired — the connection keeps failing closed
    # until an operator rotates it (long cooldown: it is a standing
    # condition, not a burst)
    {"name": "integration-config-expired", "event_type":
     "integration.config_expired",
     "condition": {"field": "event_type", "op": "==",
                   "value": "integration.config_expired"},
     "severity": "high", "cooldown_minutes": 1440, "group_by": "none"},
)


class AlertService:
    """Alert rules + alert identity/lifecycle (deterministic, scoped)."""

    def __init__(self, platform, *,
                 limiter=None, notifier=None, limit_rules: int = _LIMIT_RULES):
        self.svc = platform
        self.db = platform.db
        self.limiter = limiter
        self._notifier = notifier  # injectable NotificationService (tests)
        self.limit_rules = int(limit_rules)
        self._min_epoch = _epoch("1970-01-01T00:00:00Z")

    def _acquire(self, key: str, limit: int, window: int) -> None:
        """Rate-limit gate for user-driven alert operations (bounded)."""
        if self.limiter is None:
            import identity as _id
            self.limiter = _id.RateLimiter()
        ok, retry = self.limiter.allowed(key, limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"rate_limited: retry after {retry}s ({limit}/{window}s)")

    # ------------------------------------------------------------ rules
    def install_default_rules(self, project_id: str, *,
                              actor: str = "cli") -> int:
        """Create (idempotent) the default rule set for a project."""
        self.svc.project_require(project_id)
        project = self.svc.project_get(project_id)
        n = 0
        for tmpl in DEFAULT_RULE_TEMPLATES:
            rule_id = models.stable_id(
                models.NS_ALERTRULE,
                f"{project_id}|{tmpl['name']}|alert-rule-v1")
            try:
                with self.db.transaction() as conn:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO alert_rules (id, project_id, "
                        "org_id, name, enabled, event_type, condition, "
                        "severity, cooldown_minutes, group_by, notify, "
                        "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (rule_id, project_id, project.org_id, tmpl["name"],
                         1, tmpl["event_type"],
                         store.dumps(tmpl["condition"]), tmpl["severity"],
                         tmpl["cooldown_minutes"], tmpl["group_by"], 1,
                         models.utcnow(), models.utcnow()))
                    if cur.rowcount == 1:
                        n += 1
            except Exception as e:
                raise errors.PersistenceError(
                    f"alert rule default failed: {e}") from e
        if n:
            self.svc.audit("alert.rule.created", object_type="project",
                           object_id=project_id, org_id=project.org_id,
                           project_id=project_id, actor=actor,
                           metadata={"rules": n, "template": "defaults"})
        return n

    def rule_create(self, project_id: str, name: str, *,
                    event_type: str = "", condition=None, severity: str = "medium",
                    cooldown_minutes: int = 60, group_by: str = "none",
                    notify: bool = True, actor: str = "cli") -> dict:
        self.svc.project_require(project_id)
        project = self.svc.project_get(project_id)
        if event_type and event_type not in models.EVENT_TYPES:
            raise errors.ValidationError(
                f"event_unknown: {event_type!r} is not a change event")
        if severity not in models.ALERT_SEVERITIES:
            raise errors.ValidationError(
                f"alert_severity_unknown: {severity!r}")
        if group_by not in models.ALERT_GROUP_KEYS:
            raise errors.ValidationError(f"group_by_unknown: {group_by!r}")
        if cooldown_minutes < 0 or cooldown_minutes > 10080:
            raise errors.ValidationError(
                "cooldown_rejected: 0..10080 minutes")
        validate_condition(condition or {})
        name = str(name or "").strip()[:120]
        if not name:
            raise errors.ValidationError("name_required")
        rule_id = models.stable_id(models.NS_ALERTRULE,
                                   f"{project_id}|{name}|alert-rule-v1")
        now = models.utcnow()
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO alert_rules (id, project_id, "
                    "org_id, name, enabled, event_type, condition, severity, "
                    "cooldown_minutes, group_by, notify, created_at, "
                    "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rule_id, project_id, project.org_id, name, 1,
                     event_type, store.dumps(condition), severity,
                     int(cooldown_minutes), group_by, 1 if notify else 0,
                     now, now))
        except Exception as e:
            raise errors.PersistenceError(f"alert rule failed: {e}") from e
        self.svc.audit("alert.rule.created", object_type="alert_rule",
                       object_id=rule_id, org_id=project.org_id,
                       project_id=project_id, actor=actor,
                       metadata={"name": name, "event_type": event_type,
                                 "severity": severity})
        return self.rule_view(rule_id)

    def rule_view(self, rule_id: str) -> dict:
        rows = self.db.query("SELECT * FROM alert_rules WHERE id=? LIMIT 1",
                             (rule_id,))
        if not rows:
            raise errors.NotFoundError("alert rule not found")
        r = dict(rows[0])
        r["condition"] = store.loads(r.get("condition", "{}"))
        return r

    def rule_list(self, project_id: str, *, include_disabled: bool = True,
                  limit: int = 100) -> list[dict]:
        self.svc.project_require(project_id)
        limit = min(max(int(limit), 1), 500)
        sql = ("SELECT * FROM alert_rules WHERE project_id=? " +
               ("" if include_disabled else "AND enabled=1 ")) + \
              "ORDER BY name LIMIT ?"
        out = []
        for r in self.db.query(sql, (project_id, limit)):
            r["condition"] = store.loads(r.get("condition", "{}"))
            out.append(dict(r))
        return out

    def rule_enable(self, rule_id: str, enabled: bool, *,
                    actor: str = "cli") -> dict:
        rows = self.db.query(
            "SELECT * FROM alert_rules WHERE id=? LIMIT 1", (rule_id,))
        if not rows:
            raise errors.NotFoundError("alert rule not found")
        self.db.execute("UPDATE alert_rules SET enabled=?, updated_at=? "
                        "WHERE id=?", (1 if enabled else 0, models.utcnow(),
                                       rule_id))
        self.svc.audit("alert.rule.updated", object_type="alert_rule",
                       object_id=rule_id, project_id=rows[0]["project_id"],
                       org_id=rows[0]["org_id"], actor=actor,
                       metadata={"enabled": bool(enabled)})
        return self.rule_view(rule_id)

    # ------------------------------------------------------- evaluation
    def _context_for_event(self, ev: dict) -> dict:
        ctx = {
            "event_type": ev.get("event_type", ""),
            "asset_id": ev.get("asset_id", ""),
            "source": ev.get("source", ""),
            "title": "",
            "severity": "", "risk_score": 0.0, "risk_level": "",
            "priority": "", "confidence_score": 0.0, "exposure": "",
            "asset_criticality": "", "occurrence_count": 0,
            "fingerprint": ev.get("state_key", ""), "lifecycle": "",
        }
        # enrich from Phase-4 state (never invented — read-only lookup)
        fp = ev.get("state_key", "")
        if fp:
            rows = self.db.query(
                "SELECT id, title, severity, risk_score, risk_level, "
                "priority, confidence_score, occurrence_count, lifecycle "
                "FROM findings WHERE project_id=? AND fingerprint=? "
                "ORDER BY last_detected DESC LIMIT 1",
                (ev.get("project_id", ""), fp))
            if rows:
                f = rows[0]
                ctx.update({
                    "title": str(f.get("title", ""))[:200],
                    "severity": f.get("severity", ""),
                    "risk_score": float(f.get("risk_score") or 0),
                    "risk_level": f.get("risk_level", ""),
                    "priority": f.get("priority", ""),
                    "confidence_score": float(f.get("confidence_score") or 0),
                    "occurrence_count": int(f.get("occurrence_count") or 0),
                    "lifecycle": f.get("lifecycle", ""),
                    "fingerprint": fp,
                })
        aid = ev.get("asset_id", "")
        if aid:
            rows = self.db.query(
                "SELECT criticality, exposure FROM assets WHERE id=? LIMIT 1",
                (aid,))
            if rows:
                ctx["asset_criticality"] = rows[0].get("criticality", "")
                ctx["exposure"] = rows[0].get("exposure", "")
        return ctx

    def _group_key(self, rule: dict, ev: dict) -> str:
        gb = rule.get("group_by", "none")
        if gb == "asset":
            return ev.get("asset_id", "")
        if gb in ("root_cause", "remediation_group"):
            fp = ev.get("state_key", "")
            if fp:
                rows = self.db.query(
                    "SELECT f.id FROM findings f WHERE f.project_id=? AND "
                    "f.fingerprint=? LIMIT 1", (ev.get("project_id", ""), fp))
                if rows:
                    fid = rows[0]["id"]
                    tbl = "root_cause_findings" if gb == "root_cause" \
                        else "remediation_group_findings"
                    col = "root_cause_id" if gb == "root_cause" else "group_id"
                    try:
                        g = self.db.query(
                            f"SELECT {col} AS gid FROM {tbl} WHERE "
                            "finding_id=? LIMIT 1", (fid,))
                        if g:
                            return str(g[0]["gid"])
                    except Exception:
                        return ""
        return ""

    def process_event(self, ev: dict, *, actor: str = "scheduler") -> list[dict]:
        """Evaluate an event against all enabled rules for its project.
        Returns alert views for each matched rule (created or re-fired)."""
        import notify as _notify
        project_id = ev.get("project_id", "")
        if not project_id:
            return []
        out: list[dict] = []
        rows = self.db.query(
            "SELECT * FROM alert_rules WHERE project_id=? AND enabled=1 "
            "ORDER BY name LIMIT ?", (project_id, self.limit_rules))
        context = self._context_for_event(ev)
        for r in rows:
            r["condition"] = store.loads(r.get("condition", "{}"))
            if r.get("event_type") and r["event_type"] != ev.get("event_type"):
                continue
            try:
                matched = evaluate_condition(r["condition"], context)
            except Exception:
                matched = False
            if not matched:
                continue
            alert = self._fire(project_id, r, ev, context, actor=actor)
            if alert:
                out.append(alert)
        return out

    # ------------------------------------------------- alert identity
    def _fire(self, project_id: str, rule: dict, ev: dict,
              context: dict, *, actor: str) -> dict | None:
        group_key = self._group_key(rule, ev)
        asset_id = ev.get("asset_id", "")
        # Identity semantics: with group_by != none the group key replaces
        # the fingerprint component so events of the SAME group collapse
        # into one alert (occurrences counted separately). With group_by
        # 'none' the raw fingerprint keeps distinct findings distinct.
        fingerprint = (group_key
                       if rule.get("group_by", "none") != "none" and group_key
                       else ev.get("state_key", ""))
        identity_key = f"{project_id}|{rule['id']}|{ev.get('event_type', '')}" \
            f"|{asset_id}|{fingerprint}|{group_key}"
        alert_id = models.stable_id(models.NS_ALERT, identity_key)
        event_id = ev.get("id", "")
        now = models.utcnow()
        row = self.db.query("SELECT * FROM alerts WHERE id=? LIMIT 1",
                            (alert_id,))
        title = context.get("title") or f"{rule['name']} — " \
            f"{ev.get('event_type', '')}"
        if not row:
            try:
                with self.db.transaction() as conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO alerts (id, project_id, "
                        "org_id, rule_id, identity_key, event_type, asset_id, "
                        "finding_id, fingerprint, group_key, title, severity, "
                        "state, occurrence_count, first_seen, last_seen, "
                        "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (alert_id, project_id, ev.get("org_id", ""),
                         rule["id"], identity_key,
                         ev.get("event_type", ""), asset_id, "", fingerprint,
                         group_key, str(title)[:200], rule["severity"],
                         "open", 1, now, now, now, now))
                    conn.execute(
                        "INSERT OR IGNORE INTO alert_occurrences (id, "
                        "alert_id, event_id, occurrence_number, ts, "
                        "state_snapshot) VALUES (?,?,?,?,?,?)",
                        (models.stable_id(models.NS_ALOCC,
                                          f"{alert_id}|{event_id or identity_key}"),
                         alert_id, event_id or identity_key, 1, now,
                         store.dumps({"event_type": ev.get("event_type", "")})))
                    conn.execute(
                        "INSERT INTO alert_events (id, alert_id, actor, "
                        "action, ts, reason, metadata) VALUES (?,?,?,?,?,?,?)",
                        (models.stable_id(
                            models.NS_ALEVENT, f"{alert_id}|created|{now}"),
                         alert_id, actor, "created", now, "", "{}"))
            except Exception as e:
                raise errors.PersistenceError(f"alert create failed: {e}") \
                    from e
            metrics.inc("alerts_created")
            self._maybe_notify(alert_id, event_id, rule)
            return self.alert_view(alert_id)
        alert = dict(row[0])
        just_occurred = False
        with self.db.transaction() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO alert_occurrences (id, alert_id, "
                "event_id, occurrence_number, ts, state_snapshot) "
                "VALUES (?,?,?,?,?,?)",
                (models.stable_id(models.NS_ALOCC,
                                  f"{alert_id}|{event_id or identity_key}"),
                 alert_id, event_id or identity_key,
                 int(alert.get("occurrence_count") or 1) + 1, now,
                 store.dumps({"event_type": ev.get("event_type", "")})))
            if cur.rowcount == 1:
                just_occurred = True
                conn.execute(
                    "UPDATE alerts SET occurrence_count=occurrence_count+1, "
                    "last_seen=? WHERE id=?", (now, alert_id))
        if not just_occurred:
            metrics.inc("alerts_deduplicated")
            return self.alert_view(alert_id)
        # re-fire semantics: resolved → open again (same identity, no dup;
        # expired suppression → open; suppression expiry stops suppressing)
        if alert.get("state") in ("resolved", "suppressed"):
            if alert.get("state") == "suppressed" and \
                    alert.get("suppressed_until", "") and \
                    alert["suppressed_until"] <= now:
                self._transition(alert_id, "open", actor, "suppression expired",
                                 "suppression_expired")
            elif alert.get("state") == "resolved":
                self._transition(alert_id, "open", actor,
                                 "condition re-fired", "reopened")
        self._maybe_notify(alert_id, event_id, rule)
        return self.alert_view(alert_id)

    def _maybe_notify(self, alert_id: str, event_id: str, rule: dict) -> None:
        """Cooldown + suppression gate. Occurrences are ALWAYS tracked; the
        gate only decides whether a NEW delivery is dispatched."""
        if not rule.get("notify", 1):
            return
        rows = self.db.query(
            "SELECT state, suppressed_until, cooldown_until, org_id "
            "FROM alerts WHERE id=? LIMIT 1", (alert_id,))
        if not rows:
            return
        r = rows[0]
        now = models.utcnow()
        if r.get("state") == "suppressed" and (
                not r.get("suppressed_until") or
                r["suppressed_until"] > now):
            return  # suppressed: occurrence noted, no notification
        cu = r.get("cooldown_until", "") or ""
        if cu and cu > now:
            return  # cooldown active (anti-fatigue; tracked, not silent-lost)
        try:
            dispatcher = self._notifier
            if dispatcher is None:
                from services.notifications import NotificationService
                dispatcher = NotificationService(self.svc)
            dispatcher.dispatch_alert(
                alert_id,
                event_id,
                rule,
                org_id=str(r.get("org_id", "") or ""),
            )
        except Exception:
            metrics.inc("notifications_failed")
        cooldown_min = max(0, int(rule.get("cooldown_minutes") or 0))
        self.db.execute(
            "UPDATE alerts SET last_notified_at=?, cooldown_until=? WHERE id=?",
            (now, _iso(_epoch(now) + cooldown_min * 60), alert_id))

    def _suppressed(self, alert: dict) -> bool:
        return alert.get("state") == "suppressed" and \
            (not alert.get("suppressed_until") or
             alert["suppressed_until"] > models.utcnow())

    # -------------------------------------------------------- lifecycle
    def _transition(self, alert_id: str, new_state: str, actor: str,
                    reason: str = "", action: str = "") -> dict:
        rows = self.db.query("SELECT * FROM alerts WHERE id=? LIMIT 1",
                             (alert_id,))
        if not rows:
            raise errors.NotFoundError("alert not found")
        row = rows[0]
        old = row["state"]
        if old == new_state:
            return self.alert_view(alert_id)  # idempotent same-state op
        if new_state not in models.ALERT_TRANSITIONS.get(old, set()):
            raise errors.LifecycleError(
                f"validation_rejected: alert {old} → {new_state} is not "
                f"a legal transition")
        now = models.utcnow()
        with self.db.transaction() as conn:
            conn.execute("UPDATE alerts SET state=?, updated_at=?, "
                         "resolved_at=CASE WHEN ?='resolved' THEN ? ELSE "
                         "resolved_at END, suppressed_until=CASE WHEN "
                         "?='suppressed' THEN suppressed_until ELSE "
                         "suppressed_until END WHERE id=?",
                         (new_state, now, new_state, now, new_state,
                          alert_id))
            conn.execute(
                "INSERT INTO alert_events (id, alert_id, actor, action, "
                "ts, reason, metadata) VALUES (?,?,?,?,?,?,?)",
                (models.stable_id(models.NS_ALEVENT,
                                  f"{alert_id}|{action or new_state}|{now}|"
                                  f"{time.monotonic_ns()}"),
                 alert_id, str(actor)[:80], action or new_state, now,
                 str(redact.redact_text(reason))[:300], "{}"))
        if new_state == "suppressed":
            metrics.inc("alerts_suppressed")
        self.svc.audit("alert." + (action or new_state),
                       object_type="alert", object_id=alert_id,
                       org_id=row["org_id"], project_id=row["project_id"],
                       actor=actor,
                       metadata={"from": old, "to": new_state,
                                 "reason": redact.redact_text(reason)[:200]})
        return self.alert_view(alert_id)

    def ack(self, alert_id: str, *, actor: str = "cli",
            reason: str = "") -> dict:
        self._acquire(f"alert:op:{actor}", ALERT_OP_LIMIT, ALERT_OP_WINDOW)
        return self._transition(alert_id, "acknowledged", actor, reason, "ack")

    def investigate(self, alert_id: str, *, actor: str = "cli",
                    reason: str = "") -> dict:
        self._acquire(f"alert:op:{actor}", ALERT_OP_LIMIT, ALERT_OP_WINDOW)
        return self._transition(alert_id, "investigating", actor, reason,
                                "investigate")

    def resolve(self, alert_id: str, *, actor: str = "cli",
                reason: str = "") -> dict:
        self._acquire(f"alert:op:{actor}", ALERT_OP_LIMIT, ALERT_OP_WINDOW)
        return self._transition(alert_id, "resolved", actor, reason, "resolve")

    def suppress(self, alert_id: str, *, actor: str = "cli",
                 reason: str = "", until: str = "") -> dict:
        reason = str(reason or "").strip()
        if not reason:
            raise errors.ValidationError(
                "validation_rejected: suppression requires a reason")
        self._acquire(f"alert:op:{actor}", ALERT_OP_LIMIT, ALERT_OP_WINDOW)
        if not _ISO_RE.match(str(until or "")) or \
                str(until or "") <= models.utcnow():
            raise errors.ValidationError(
                "validation_rejected: until must be a future ISO timestamp")
        rows = self.db.query("SELECT * FROM alerts WHERE id=? LIMIT 1",
                             (alert_id,))
        if not rows:
            raise errors.NotFoundError("alert not found")
        self.db.execute("UPDATE alerts SET suppressed_until=? WHERE id=?",
                        (str(until), alert_id))
        out = self._transition(alert_id, "suppressed", actor, reason,
                               "suppress")
        return out

    def expire_orphaned(self, *, actor: str = "scheduler",
                        limit: int = 200) -> int:
        """Alerts whose rule was soft-disabled → expired (history kept)."""
        n = 0
        rows = self.db.query(
            "SELECT a.id, a.state FROM alerts a LEFT JOIN alert_rules r "
            "ON r.id=a.rule_id WHERE a.state IN ('open','acknowledged',"
            "'investigating','resolved') AND (r.id IS NULL OR r.enabled=0) "
            "LIMIT ?", (int(limit),))
        for r in rows:
            try:
                self._transition(r["id"], "expired", actor,
                                 "rule disabled or removed", "expire")
                n += 1
            except errors.LifecycleError:
                continue
        return n

    # ------------------------------------------------------------- reads
    def alert_view(self, alert_id: str, *,
                   include_occurrences: bool = True) -> dict:
        rows = self.db.query("SELECT * FROM alerts WHERE id=? LIMIT 1",
                             (alert_id,))
        if not rows:
            raise errors.NotFoundError("alert not found")
        v = dict(rows[0])
        if include_occurrences:
            v["occurrences"] = self.occurrences(alert_id, limit=50)
        v["events"] = self.history(alert_id, limit=50)
        return v

    def alert_by_identity(self, project_id: str, rule_id: str,
                          event_type: str, asset_id: str,
                          fingerprint: str, group_key: str) -> dict | None:
        identity_key = f"{project_id}|{rule_id}|{event_type}|{asset_id}" \
            f"|{fingerprint}|{group_key}"
        rows = self.db.query("SELECT * FROM alerts WHERE identity_key=? "
                             "LIMIT 1", (identity_key,))
        return dict(rows[0]) if rows else None

    def occurrences(self, alert_id: str, *, limit: int = 50) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM alert_occurrences WHERE alert_id=? ORDER BY ts "
            "DESC, occurrence_number DESC LIMIT ?", (alert_id, limit))
        out = []
        for r in rows:
            r["state_snapshot"] = store.loads(r.get("state_snapshot", "{}"))
            out.append(dict(r))
        return out

    def history(self, alert_id: str, *, limit: int = 50) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM alert_events WHERE alert_id=? ORDER BY ts DESC "
            "LIMIT ?", (alert_id, limit))
        out = []
        for r in rows:
            r["metadata"] = store.loads(r.get("metadata", "{}"))
            out.append(redact.redact(dict(r)))
        return out

    def list_alerts(self, project_id: str, *, state: str = "",
                    limit: int = 100) -> list[dict]:
        self.svc.project_require(project_id)
        limit = min(max(int(limit), 1), 500)
        if state:
            if state not in models.ALERT_STATES:
                raise errors.ValidationError(
                    f"alert_state_unknown: {state!r}")
            rows = self.db.query(
                "SELECT * FROM alerts WHERE project_id=? AND state=? "
                "ORDER BY last_seen DESC, id DESC LIMIT ?",
                (project_id, state, limit))
        else:
            rows = self.db.query(
                "SELECT * FROM alerts WHERE project_id=? ORDER BY "
                "last_seen DESC, id DESC LIMIT ?", (project_id, limit))
        return [dict(r) for r in rows]

    def alert_count(self, project_id: str) -> dict:
        self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT state, COUNT(*) AS n FROM alerts WHERE project_id=? "
            "GROUP BY state", (project_id,))
        out = {r["state"]: r["n"] for r in rows}
        out.setdefault("open", 0)
        out["total"] = sum(out.values())
        return out


# ---------------------------------------------------------------------------
# Pipeline glue: event → alert → notification (single entry point used by
# the worker/change detector, the scheduler and the remedy service.)
# ---------------------------------------------------------------------------
def pipeline_event(svc, *, project_id: str, event_type: str,
                   asset_id: str = "", key: str = "", scan_id: str = "",
                   previous_state=None, new_state=None, source: str = "",
                   confidence: float = 0.5, actor: str = "scheduler",
                   org_id: str = "") -> dict | None:
    """Emit one security event, evaluate it against alert rules and dispatch
    notifications for fired alerts. Returns {"event":…, "alerts":[…]}, or
    None when the event already existed (idempotent reprocessing)."""
    from events import SecurityEventService
    ev = SecurityEventService(svc).emit(
        project_id, event_type, asset_id=asset_id, key=key, scan_id=scan_id,
        previous_state=previous_state, new_state=new_state, source=source,
        confidence=confidence, actor=actor, org_id=org_id)
    if ev is None:
        return None
    try:
        fired = AlertService(svc).process_event(ev, actor=actor)
    except Exception:
        metrics.inc("alert_evaluation_failures")
        fired = []
    return {"event": ev, "alerts": fired}
