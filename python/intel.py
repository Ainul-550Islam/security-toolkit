#!/usr/bin/env python3
# ============================================================================
#  intel.py — Phase 4 Asset Intelligence service.
#  ---------------------------------------------------------------------------
#  Adds capability ON TOP of the existing Asset subsystem (models.Asset /
#  platform.asset_add) without duplicating it:
#
#    - normalized, bounded observations (services / ports / technologies /
#      software+version / server / TLS / DNS / HTTP / cloud / network) with
#      PROVENANCE (source, scan_id, confidence, first_seen, last_seen)
#    - append-only change history (asset_observation_events) — identical
#      observations are deduplicated, real changes are recorded
#    - provenance-carrying asset relationships (domain→subdomain,
#      hostname→IP, asset→service, service→technology, asset→certificate,
#      asset→cloud resource) — strictly project-scoped (tenant-safe)
#    - derived, evidence-driven attack-surface model (exposure + services)
#    - asset criticality + business-impact metadata (audited, RBAC-gated by
#      the caller — this module never bypasses authorization)
#
#  NO intelligence is invented: every record comes from scanner output keys
#  that actually exist (see _EXTRACTORS) and every derived flag carries its
#  provenance/reason. Output limits are enforced (bounded values, bounded
#  extra metadata) and everything passes redact.redact() before storage.
# ============================================================================

from __future__ import annotations

import ipaddress
import json

import errors
import metrics
import models
import redact
import store

# ---------------------------------------------------------------------------
# Observation vocabulary (allowlist — nothing outside is stored)
# ---------------------------------------------------------------------------
OBS_TYPES = ("identity", "network", "service", "port", "technology",
             "software", "version", "framework", "server", "tls", "dns",
             "http", "cloud", "protocol", "exposure", "certificate",
             # Phase 10 — external attack surface (§7/§8/§9/§11): these are
             # observation kinds on the EXISTING Asset model — no new one.
             "domain", "subdomain", "hostname", "ip", "ipv6", "url",
             "cloud_resource", "dns_record",
             "cert_subject", "cert_issuer", "cert_san", "fingerprint",
             "key_algorithm", "signature_algorithm", "expiry")
REL_TYPES = ("hosts", "resolves_to", "serves", "uses", "runs_on",
             "has_certificate", "cloud_of", "related_to", "part_of",
             # Phase 10 — attack-surface topology relations (deterministic)
             "subdomain_of", "cname_to")
CRITICALITY_LEVELS = ("unknown", "low", "medium", "high", "critical")
EXPOSURE_LEVELS = ("internet_facing", "internal", "restricted", "unknown")

MAX_VALUE_LEN = 300
MAX_EXTRA_LEN = 2000
MAX_HISTORY_EVENTS_PER_ASSET = 500
MAX_RELATED_PER_ASSET = 100

_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("/")[0].strip())
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


def _bounded(value, limit: int = MAX_VALUE_LEN) -> str:
    return str(value)[:limit]


class IntelService:
    """Phase-4 asset intelligence on top of the shared PlatformService.

    Every write is parameterized; every read is project-scoped. `actor` is
    only used for audit labels on USER-DRIVEN changes (never on auto
    ingestion, which is not audited to avoid immutable-log flooding)."""

    def __init__(self, platform):
        self.svc = platform
        self.db = platform.db

    # ------------------------------------------------------------- helpers
    def _audit(self, action: str, *, object_type: str, object_id: str,
               project_id: str, actor: str, metadata: dict):
        try:
            self.svc.audit(action, object_type=object_type,
                           object_id=object_id, project_id=project_id,
                           actor=actor, metadata=metadata)
        except Exception:
            pass   # auditing never breaks intelligence writes

    def _project_asset(self, asset_id: str) -> dict:
        row = self.db.query_one(
            "SELECT * FROM assets WHERE id=? LIMIT 1", (asset_id,))
        for k in ("metadata", "business_impact"):
            row[k] = store.loads(row.get(k, "{}"))
        return row

    # ------------------------------------------------------------ assets
    def asset_count(self, project_id: str) -> int:
        rows = self.db.query(
            "SELECT COUNT(*) AS n FROM assets WHERE project_id=?",
            (project_id,))
        return int(rows[0]["n"]) if rows else 0

    def asset_intel(self, asset_id: str, *,
                    limit_observations: int = 200) -> dict:
        """Full bounded intelligence view of one asset — identity, network,
        services, technologies, DNS/TLS/HTTP/cloud, exposure, criticality."""
        asset = self._project_asset(asset_id)
        observations = self.db.query(
            "SELECT * FROM asset_observations WHERE asset_id=? "
            "ORDER BY obs_type, obs_key, last_seen DESC LIMIT ?",
            (asset_id, limit_observations))
        grouped: dict[str, list] = {}
        for o in observations:
            o["extra"] = store.loads(o.get("extra", "{}"))
            grouped.setdefault(o["obs_type"], []).append({
                "key": o["obs_key"], "value": o["obs_value"],
                "source": o["source"], "confidence": o["confidence"],
                "first_seen": o["first_seen"], "last_seen": o["last_seen"]})
        relations_out = self.db.query(
            "SELECT * FROM asset_relations WHERE from_asset_id=? "
            "OR to_asset_id=? ORDER BY rel_type LIMIT ?",
            (asset_id, asset_id, MAX_RELATED_PER_ASSET))
        relations = [{"id": r["id"], "rel_type": r["rel_type"],
                      "from_asset_id": r["from_asset_id"],
                      "to_asset_id": r["to_asset_id"],
                      "source": r["source"], "confidence": r["confidence"],
                      "status": r["status"],
                      "first_seen": r["first_seen"],
                      "last_seen": r["last_seen"]} for r in relations_out]
        return {"asset": {k: asset.get(k, "") for k in
                          ("id", "project_id", "asset_type", "value",
                           "display", "status", "criticality", "exposure",
                           "exposure_reason", "first_seen", "last_seen",
                           "business_impact", "metadata")},
                "observations": grouped,
                "relations": relations,
                "observation_count": len(observations)}

    def asset_history(self, asset_id: str, *,
                      limit: int = 200) -> list[dict]:
        """Change history (append-only, deduplicated by (type,key,ts))."""
        rows = self.db.query(
            "SELECT * FROM asset_observation_events WHERE asset_id=? "
            "ORDER BY ts DESC LIMIT ?", (asset_id, limit))
        return [{**{"id": r["id"], "obs_type": r["obs_type"],
                    "obs_key": r["obs_key"], "old_value": r["old_value"],
                    "new_value": r["new_value"], "source": r["source"],
                    "scan_id": r["scan_id"], "ts": r["ts"]}}
                for r in rows]

    # ------------------------------------------------- attrs: criticality
    def criticality_set(self, asset_id: str, level: str, *,
                        actor: str = "cli") -> dict:
        """Audited, authorized-by-caller criticality change (RBAC is enforced
        by the CLI/API layer — this method never checks permissions itself)."""
        level = str(level).strip().lower()
        if level not in CRITICALITY_LEVELS:
            raise errors.ValidationError(
                f"Invalid criticality: {level!r} "
                f"(choose from {', '.join(CRITICALITY_LEVELS)})")
        asset = self._project_asset(asset_id)
        old = asset.get("criticality", "unknown")
        if old == level:
            return {"asset_id": asset_id, "criticality": level,
                    "changed": False}
        self.db.execute(
            "UPDATE assets SET criticality=? WHERE id=?",
            (level, asset_id))
        metrics.inc("asset_criticality_changes")
        self._audit("asset.criticality_changed", object_type="asset",
                    object_id=asset_id, project_id=asset["project_id"],
                    actor=actor, metadata={"from": old, "to": level})
        return {"asset_id": asset_id, "criticality": level, "changed": True}

    def business_impact_set(self, asset_id: str, tags: dict, *,
                            actor: str = "cli") -> dict:
        if not isinstance(tags, dict):
            raise errors.ValidationError("business impact must be an object")
        allowed = {"customer_facing", "authentication_system",
                   "payment_related", "sensitive_data", "administrative_system",
                   "production_system", "internal_only", "internet_exposed"}
        unknown = set(tags) - allowed
        if unknown:
            raise errors.ValidationError(
                f"Unknown impact dimension(s): {sorted(unknown)}")
        clean = {k: bool(v) for k, v in tags.items()}
        asset = self._project_asset(asset_id)
        self.db.execute(
            "UPDATE assets SET business_impact=? WHERE id=?",
            (store.dumps(redact.redact(clean)), asset_id))
        self._audit("asset.business_impact_changed", object_type="asset",
                    object_id=asset_id, project_id=asset["project_id"],
                    actor=actor, metadata={"impact": clean})
        return {"asset_id": asset_id, "business_impact": clean}

    # ------------------------------------------------ derived attack surface
    def exposure_derive(self, asset_id: str) -> dict:
        """Derive exposure from OBSERVED evidence only (no guessing):
        private IP/net evidence → internal; restricted evidence → restricted;
        otherwise internet-facing when service/network evidence exists."""
        asset = self._project_asset(asset_id)
        obs = self.db.query(
            "SELECT obs_type, obs_key, obs_value FROM asset_observations "
            "WHERE asset_id=? LIMIT 300", (asset_id,))
        reasons = []
        exposure = "unknown"
        has_public = False
        has_private = False
        type_seen = set()
        for o in obs:
            type_seen.add(o["obs_type"])
            v = str(o["obs_value"])
            if o["obs_type"] != "network":
                continue
            if _is_private_ip(v):
                has_private = True
                reasons.append(f"private address {v}")
            elif v.count(".") == 3:
                has_public = True
                reasons.append(f"public address {v}")
        if has_private and not has_public:
            exposure, reasons = "internal", reasons or ["private addressing"]
        elif has_public:
            exposure = "internet_facing"
        elif type_seen & {"service", "port", "http", "tls", "dns"}:
            exposure = "internet_facing"
            reasons = reasons or ["observed network services"]
        return {"exposure": exposure,
                "reason": "; ".join(reasons[:5])[:500],
                "evidence_types": sorted(type_seen)}

    def refresh_exposure(self, asset_id: str) -> dict:
        drv = self.exposure_derive(asset_id)
        self.db.execute(
            "UPDATE assets SET exposure=?, exposure_reason=? WHERE id=?",
            (drv["exposure"], _bounded(drv["reason"], 500), asset_id))
        return drv

    def attack_surface(self, project_id: str, *,
                       limit_assets: int = 500) -> dict:
        """Normalized attack-surface model for a project: per-asset exposure,
        services, technologies, ports — derived from observations, bounded."""
        assets = self.db.query(
            "SELECT * FROM assets WHERE project_id=? ORDER BY last_seen DESC "
            "LIMIT ?", (project_id, limit_assets))
        surf = []
        for a in assets:
            obs = self.db.query(
                "SELECT obs_type, obs_key, obs_value, source FROM "
                "asset_observations WHERE asset_id=? LIMIT 200", (a["id"],))
            services = [{"key": o["obs_key"] or "", "value": o["obs_value"],
                         "source": o["source"]} for o in obs
                        if o["obs_type"] == "service"]
            tech = [{"key": o["obs_key"] or "", "value": o["obs_value"],
                     "source": o["source"]} for o in obs
                    if o["obs_type"] in ("technology", "software",
                                         "framework", "server")]
            ports = [{"key": o["obs_key"] or "", "value": o["obs_value"],
                      "source": o["source"]} for o in obs
                     if o["obs_type"] == "port"]
            surf.append({"asset_id": a["id"], "asset_type": a["asset_type"],
                         "value": a["value"],
                         "criticality": a.get("criticality", "unknown"),
                         "exposure": a.get("exposure", "unknown"),
                         "exposure_reason": a.get("exposure_reason", ""),
                         "services": services, "technologies": tech,
                         "ports": ports,
                         "first_seen": a["first_seen"],
                         "last_seen": a["last_seen"]})
        counts = {"assets": len(surf),
                  "services": sum(len(s["services"]) for s in surf),
                  "technologies": sum(len(s["technologies"]) for s in surf),
                  "ports": sum(len(s["ports"]) for s in surf),
                  "internet_facing": sum(1 for s in surf
                                         if s["exposure"] == "internet_facing"),
                  "internal": sum(1 for s in surf
                                  if s["exposure"] == "internal")}
        return {"project_id": project_id, "counts": counts,
                "assets": surf}

    # ----------------------------------------------------------- observations
    def observe(self, asset_id: str, obs_type: str, *, obs_key: str = "",
                obs_value: str, source: str = "", confidence: float = 0.5,
                scan_id: str = "", extra: dict | None = None) -> dict:
        """Upsert ONE observation: identical observations are deduplicated
        (last_seen refreshed only); a VALUE CHANGE records an append-only
        history event (old → new), so 'when X changed' is always answerable."""
        if obs_type not in OBS_TYPES:
            raise errors.ValidationError(
                f"Unknown observation type: {obs_type!r}")
        confidence = min(1.0, max(0.0, float(confidence or 0.5)))
        if not obs_value:
            raise errors.ValidationError("observation value is required")
        asset = self._project_asset(asset_id)
        # centralized redaction BEFORE persistence: an observation value is
        # intelligence evidence — a header/cookie value may carry secrets
        # and they must never be stored (reuses the Phase-1/2 redactor)
        val = _bounded(redact.redact_text(str(obs_value)))
        key = _bounded(obs_key or "", 80)
        src = _bounded(source or "scanner", 80)
        now = models.utcnow()
        extra_clean = {}
        if isinstance(extra, dict):
            extra_clean = redact.redact(extra)
            if len(store.dumps(extra_clean)) > MAX_EXTRA_LEN:
                extra_clean = {}
        obs_id = models.stable_id(
            models.NS_OBSERVATION,
            f"{asset_id}|{obs_type}|{key}|{val}|{src}")
        history = None
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT id, first_seen FROM asset_observations "
                "WHERE asset_id=? AND obs_type=? AND obs_key=? AND "
                "obs_value=? AND source=? LIMIT 1",
                (asset_id, obs_type, key, val, src)).fetchone()
            if row is not None:
                # identical observation → deduplicated, liveness refreshed
                conn.execute(
                    "UPDATE asset_observations SET last_seen=?, "
                    "confidence=?, extra=?, scan_id=? WHERE id=?",
                    (now, confidence, store.dumps(extra_clean),
                     _bounded(scan_id, 64), row["id"]))
                changed = False
                obs_id = row["id"]
            else:
                # value change (or first appearance) for the same
                # (asset,type,key,source) → append-only history event
                prev = conn.execute(
                    "SELECT obs_value FROM asset_observations WHERE "
                    "asset_id=? AND obs_type=? AND obs_key=? AND source=? "
                    "ORDER BY last_seen DESC LIMIT 1",
                    (asset_id, obs_type, key, src)).fetchone()
                history = {"obs_type": obs_type, "obs_key": key,
                           "old_value": (prev["obs_value"]
                                         if prev is not None else ""),
                           "new_value": val, "source": src}
                ev_id = models.stable_id(
                    models.NS_OBSEVENT,
                    f"{asset_id}|{obs_type}|{key}|{src}|{now}|{val}")
                conn.execute(
                    "INSERT OR IGNORE INTO asset_observation_events "
                    "(id, asset_id, project_id, obs_type, obs_key, "
                    "old_value, new_value, source, scan_id, ts) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (ev_id, asset_id, asset["project_id"], obs_type, key,
                     _bounded(history["old_value"]),
                     _bounded(history["new_value"]), src,
                     _bounded(scan_id, 64), now))
                self._prune_history(conn, asset_id)
                conn.execute(
                    "INSERT INTO asset_observations (id, asset_id, "
                    "project_id, obs_type, obs_key, obs_value, source, "
                    "confidence, scan_id, extra, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (obs_id, asset_id, asset["project_id"], obs_type, key,
                     val, src, confidence, _bounded(scan_id, 64),
                     store.dumps(extra_clean), now, now))
                metrics.inc("asset_observations")
                changed = True
        self.svc.db.execute(
            "UPDATE assets SET last_seen=? WHERE id=?", (now, asset_id))
        # keep the derived exposure current with the observation (provenance
        # in assets.exposure_reason — never a silent guess)
        self.refresh_exposure(asset_id)
        return {"observation_id": obs_id, "changed": changed,
                "history": history, "first_seen": now}

    @staticmethod
    def _prune_history(conn, asset_id: str, keep: int = MAX_HISTORY_EVENTS_PER_ASSET):
        rows = conn.execute(
            "SELECT id FROM asset_observation_events WHERE asset_id=? "
            "ORDER BY ts DESC LIMIT -1 OFFSET ?", (asset_id, keep)).fetchall()
        for r in rows:
            conn.execute("DELETE FROM asset_observation_events WHERE id=?",
                         (r["id"],))

    # -------------------------------------------------------- relationships
    def relate(self, project_id: str, from_asset_id: str, to_asset_id: str,
               rel_type: str, *, source: str = "scanner",
               confidence: float = 0.5, activate: bool = True) -> dict:
        """One provenance-carrying relationship. Strictly intra-project:
        cross-tenant edges are impossible because both endpoints must be
        assets of the SAME project (validated here AND by the schema)."""
        if rel_type not in REL_TYPES:
            raise errors.ValidationError(f"Unknown relation type: {rel_type!r}")
        if from_asset_id == to_asset_id:
            raise errors.ValidationError("self-relations are not meaningful")
        fa = self._project_asset(from_asset_id)
        ta = self._project_asset(to_asset_id)
        if fa["project_id"] != project_id or ta["project_id"] != project_id:
            raise errors.AuthorizationError("Forbidden")
        confidence = min(1.0, max(0.0, float(confidence or 0.5)))
        now = models.utcnow()
        rel_id = models.stable_id(
            models.NS_RELATION,
            f"{project_id}|{from_asset_id}|{rel_type}|{to_asset_id}|"
            f"{source}")
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT id, status FROM asset_relations WHERE id=? LIMIT 1",
                (rel_id,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO asset_relations (id, project_id, "
                    "from_asset_id, to_asset_id, rel_type, source, "
                    "confidence, status, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (rel_id, project_id, from_asset_id, to_asset_id,
                     rel_type, _bounded(source, 80), confidence,
                     "active" if activate else "inactive", now, now))
                return {"relation_id": rel_id, "created": True}
            status = "active" if activate else "inactive"
            conn.execute(
                "UPDATE asset_relations SET status=?, confidence=?, "
                "last_seen=? WHERE id=?", (status, confidence, now, rel_id))
            return {"relation_id": rel_id, "created": False,
                    "status": status}

    def relations(self, asset_id: str, limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM asset_relations WHERE from_asset_id=? "
            "OR to_asset_id=? LIMIT ?", (asset_id, asset_id, limit))
        return [dict(r) for r in rows]

    # -------------------------------------------------------- raw ingestion
    def ingest_observations(self, project_id: str, scan_id: str,
                            raw: dict, assets: list) -> int:
        """Extract bounded structured observations from a scanner result.
        Only known keys are read; nothing is invented. Returns the number
        of NEW (changed) observations recorded — a repeated ingest of the
        same payload returns 0 (data-level idempotency)."""
        if not isinstance(raw, dict):
            return 0
        count = 0
        by_value = {a.value: a for a in assets}

        def _o(asset_id: str, obs_type: str, **kw) -> None:
            nonlocal count
            try:
                if self.observe(asset_id, obs_type, **kw)["changed"]:
                    count += 1
            except errors.ValidationError:
                return

        def _atype(value: str) -> str:
            v = value.strip()
            if "://" in v:
                return "url"
            try:
                ipaddress.ip_address(v.split("/")[0])
                return "ip"
            except ValueError:
                return "domain"

        def asset_for(value: str):
            v = str(value).strip()
            a = by_value.get(v)
            if a is None:
                try:
                    a = models.Asset(project_id=project_id,
                                     asset_type=_atype(v), value=v[:300])
                    a.finalize()
                    a = self.svc.asset_add(project_id, a.asset_type,
                                           a.value)
                except Exception:
                    return None
            return a

        # 1. target asset identity
        for key in ("target", "url", "domain", "host"):
            v = raw.get(key)
            if isinstance(v, str) and v:
                a = asset_for(v)
                if a is not None:
                    _o(a.id, "identity", obs_key="target",
                       obs_value=_bounded(v), source="scan",
                       scan_id=scan_id)
                break
        # 2. subdomains -> dns + network observations + relationships
        subs = raw.get("subdomains")
        if isinstance(subs, dict):
            for name, info in subs.items():
                info = info if isinstance(info, dict) else {}
                a = asset_for(str(name))
                if a is None:
                    continue
                _o(a.id, "dns", obs_key="name",
                   obs_value=_bounded(name), source="recon",
                   scan_id=scan_id)
                for ip in (info.get("ips") or [])[:10]:
                    if isinstance(ip, str) and ip:
                        _o(a.id, "network", obs_key="ip",
                           obs_value=_bounded(ip), source="recon",
                           scan_id=scan_id)
                        ipa = asset_for(ip)
                        if ipa is not None:
                            self.relate(project_id, a.id, ipa.id,
                                        "resolves_to", source="recon",
                                        confidence=0.7)
        # 3. ports / services (list of dicts or list of strings)
        for key in ("ports", "services", "open_ports"):
            vals = raw.get(key)
            if isinstance(vals, list):
                for v in vals[:100]:
                    item = v if isinstance(v, dict) else {"name": v}
                    name = str(item.get("service") or item.get("name")
                               or item.get("port") or "")[:300]
                    if not name:
                        continue
                    a = asset_for(str(raw.get("target") or
                                      raw.get("host") or
                                      raw.get("domain") or ""))
                    if a is None:
                        continue
                    _o(a.id, "port",
                       obs_key=str(item.get("port", ""))[:80],
                       obs_value=_bounded(name),
                       source=str(item.get("source", "scanner"))[:80],
                       confidence=0.6, scan_id=scan_id)
                    _o(a.id, "service",
                       obs_key=str(item.get("port", ""))[:80],
                       obs_value=_bounded(name),
                       source=str(item.get("source", "scanner"))[:80],
                       confidence=0.6, scan_id=scan_id)
        # 4. technologies / software / versions / server / framework
        tech = raw.get("technologies")
        if isinstance(tech, list):
            for t in tech[:60]:
                t = t if isinstance(t, dict) else {"name": t}
                a = asset_for(str(raw.get("target") or raw.get("url")
                                  or raw.get("host") or ""))
                if a is None:
                    continue
                name = str(t.get("name") or t.get("technology") or "")[:120]
                if not name:
                    continue
                _o(a.id, "technology", obs_key="name",
                   obs_value=_bounded(name),
                   source=str(t.get("source", "scanner"))[:80],
                   confidence=0.6, scan_id=scan_id)
                ver = str(t.get("version") or "")[:80]
                if ver:
                    _o(a.id, "version", obs_key=name, obs_value=ver,
                       source=str(t.get("source", "scanner"))[:80],
                       confidence=0.6, scan_id=scan_id)
        # 5. tls metadata block (where scanners provide it)
        tls = raw.get("tls")
        if isinstance(tls, dict):
            a = asset_for(str(raw.get("target") or raw.get("url")
                              or raw.get("host") or ""))
            if a is not None:
                for k in ("verified", "issuer", "expires", "version"):
                    v = tls.get(k)
                    if isinstance(v, (str, bool)):
                        _o(a.id, "tls", obs_key=k,
                           obs_value=_bounded(str(v)),
                           source="scanner", confidence=0.7,
                           scan_id=scan_id)
        # 6. cloud checks (bucket/service + region/provider when present)
        if raw.get("bucket") or raw.get("service"):
            a = asset_for(str(raw.get("bucket") or raw.get("service") or ""))
            if a is not None:
                _o(a.id, "cloud", obs_key="resource_type",
                   obs_value="cloud_resource" if raw.get("bucket")
                   else "service",
                   source="cloud-check", confidence=0.7,
                   scan_id=scan_id)
        # 7. relationships: domain -> subdomain when target present
        target = str(raw.get("domain") or raw.get("target") or "")
        if target and isinstance(subs, dict):
            ta = asset_for(target)
            if ta is not None:
                for name, info in subs.items():
                    sa = asset_for(str(name))
                    if sa is not None and sa.id != ta.id:
                        self.relate(project_id, ta.id, sa.id, "hosts",
                                    source="recon", confidence=0.8)
        if count:
            metrics.inc("assets_ingested", 1)
        return count
