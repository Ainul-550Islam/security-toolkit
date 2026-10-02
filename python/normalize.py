#!/usr/bin/env python3
# ============================================================================
#  normalize.py — scanner result normalization (adapter layer).
#  ---------------------------------------------------------------------------
#  Existing scanners emit heterogeneous JSON (findings[], checks[],
#  subdomains{}, waf[], endpoints[]). This module converts ANY existing
#  scanner result into normalized Asset/Scan/Finding/Evidence objects while
#  PRESERVING the original/raw payload untouched for backward compatibility.
#
#  Known scanner "tool strings" map to profiles. Unknown JSON with a
#  `findings` list is handled generically — existing output stays usable.
# ============================================================================

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

import errors
import models

TOOL_PROFILES = {
    "secuaudit": "web-audit",
    "secuaudit-api": "api-audit",
    "injector": "active-fuzz",
    "wallfinder": "waf-detect",
    "cloudscope": "cloud-check",
    "subkraken": "subdomain-enum",
    "nucleus": "template-scan",
    "secuspider": "crawler",
    "hunter": "workflow",
    "hunter (workflow automation)": "workflow",
}

SEV_MAP = {"critical": "Critical", "high": "High", "medium": "Medium",
           "low": "Low", "info": "Info"}


def normalize_severity(value) -> str:
    s = SEV_MAP.get(str(value or "info").strip().lower(), "Info")
    return s


def rule_id_for(raw_finding: dict, fallback: str) -> str:
    for k in ("rule_id", "template_id", "id", "check", "type", "name"):
        v = raw_finding.get(k)
        if v and isinstance(v, str):
            return str(v)[:128]
    return fallback


def category_for(raw_finding: dict, title: str) -> str:
    t = f"{raw_finding.get('type', '')} {raw_finding.get('category', '')} {title}".lower()
    if any(x in t for x in ("sql", "injection", "sqli", "xss", "cmdi", "command")):
        return "injection" if "xss" not in t else "xss"
    if "xss" in t:
        return "xss"
    if any(x in t for x in ("traversal", "lfi", "rfi", "path")):
        return "access_control"
    if any(x in t for x in ("tls", "certificate", "ssl", "http")):
        return "tls"
    if any(x in t for x in ("exposure", "listing", "open", "missing", "information")):
        return "misconfiguration"
    if any(x in t for x in ("waf", "cloud")):
        return "exposure"
    if any(x in t for x in ("x-frame", "clickjack", "hsts", "csp", "header")):
        return "misconfiguration"
    return "other"


def _url_detail(value: str) -> tuple:
    """Return (host, endpoint, parameter) from a URL-ish value."""
    try:
        p = urlparse(value)
        if p.scheme in ("http", "https") and p.netloc:
            qs = re.split(r"[&;]", p.query)
            param = ""
            for q in qs:
                if "=" in q:
                    param = q.split("=", 1)[0]
                    break
            return p.hostname or "", p.path or "", param
    except Exception:
        pass
    return "", "", ""


def scan_from_raw(raw: dict, *, project_id: str, scan_id: str = "",
                  status: str = "completed") -> models.Scan:
    """Normalize a raw scanner result into a Scan (raw preserved)."""
    tool = str(raw.get("tool") or raw.get("name") or "scanner")
    profile = tool
    low = tool.lower()
    for key, prof in TOOL_PROFILES.items():
        if key in low:
            profile = prof
            break
    target = (raw.get("target") or raw.get("url") or raw.get("domain")
              or raw.get("host") or "")
    scan = models.Scan(project_id=project_id, profile=profile,
                       status=status, id=scan_id,
                       created_at=raw.get("scan_date", ""),
                       scope_ref=str(raw.get("scope_ref", "")),
                       summary=raw.get("summary") or {},
                       initiator={"tool": tool,
                                  "raw_target": str(target)[:300]},
                       stages=[{"name": "scanner", "tool": tool}])
    if not scan.id:
        scan.id = models.stable_id(
            models.NS_SCAN,
            f"{scan.project_id}|{scan.profile}|{scan.created_at or 'none'}")
    if raw.get("score") is not None:
        scan.summary["score"] = raw["score"]
        scan.summary["grade"] = raw.get("grade", "")
    return scan


def assets_from_raw(raw: dict, *, project_id: str) -> list[models.Asset]:
    """Derive normalized assets from a scanner result (deduped)."""
    out: dict[str, models.Asset] = {}
    def add(atype: str, value: str, metadata=None):
        if not value:
            return
        try:
            a = models.Asset(project_id=project_id, asset_type=atype,
                             value=value, metadata=metadata or {})
            a.finalize()
            out[a.id] = a
        except errors.ValidationError:
            return

    for key in ("target", "url", "domain", "host"):
        v = raw.get(key)
        if isinstance(v, str) and v:
            if key == "domain" or (v and "." in v and "://" not in v
                                   and not re.match(r"^\d+\.\d+", v)):
                add("domain", v, {"source": "scan-target"})
            elif v.startswith("http"):
                add("url", v, {"source": "scan-target"})
            else:
                add("domain", v, {"source": "scan-target"})
    if isinstance(raw.get("subdomains"), dict):
        for name, info in raw["subdomains"].items():
            meta = {"source": ", ".join((info or {}).get("sources", ["ct"])),
                    "ips": (info or {}).get("ips", [])}
            try:
                add("subdomain", name, meta)
            except errors.ValidationError:
                continue
    if isinstance(raw.get("hosts"), list):
        for h in raw["hosts"]:
            if isinstance(h, dict):
                u = h.get("url") or ""
                if u.startswith("http"):
                    add("url", u, {"source": "workflow"})
                elif h.get("host"):
                    add("subdomain", h["host"], {"source": "workflow"})
    if isinstance(raw.get("endpoints"), list):
        for e in raw["endpoints"][:200]:
            u = e.get("url") if isinstance(e, dict) else e
            if isinstance(u, str) and u.startswith("http"):
                add("url", u, {"source": "crawler"})
    if isinstance(raw.get("param_urls"), list):
        for e in raw["param_urls"][:200]:
            u = e.get("url") if isinstance(e, dict) else e
            if isinstance(u, str) and u.startswith("http"):
                add("api", u, {"source": "crawler-params"})
    raw_checks = raw.get("checks")
    if isinstance(raw_checks, list):
        for c in raw_checks[:200]:
            if isinstance(c, dict) and c.get("service"):
                add("cloud_resource", str(c.get("service", "")), {"status": c.get("status", "")})
    return list(out.values())


def findings_from_raw(raw: dict, *, project_id: str, scan_id: str,
                      asset_index: dict[str, str] | None = None) \
        -> list[models.Finding]:
    """Convert a raw scanner result's findings into normalized Findings.
    `asset_index` maps canonical asset values → asset ids (from
    assets_from_raw) for fingerprint stability."""
    asset_index = asset_index or {}
    raw_findings = raw.get("findings")
    if not isinstance(raw_findings, list):
        return []
    out = []
    for i, rf in enumerate(raw_findings):
        if not isinstance(rf, dict):
            continue
        title = (rf.get("title") or rf.get("type") or rf.get("name")
                 or rf.get("check") or f"Finding {i + 1}")
        asset_value = (rf.get("target") or rf.get("url") or rf.get("asset")
                       or raw.get("target") or raw.get("url") or "")
        asset_id = asset_index.get(str(asset_value).strip(), "")
        source = str(raw.get("tool") or "scanner")
        evidence_list = evidence_from_finding(rf, source=source)
        f = models.Finding(
            scan_id=scan_id, project_id=project_id, asset_id=asset_id,
            title=str(title)[:280],
            description=str(rf.get("description", ""))[:2000],
            severity=normalize_severity(rf.get("severity") or rf.get("risk")),
            confidence=str(rf.get("confidence", "medium")),
            category=category_for(rf, str(title)),
            source=source,
            rule_id=rule_id_for(rf, f"scanner-{i + 1}"),
            template_id=str(rf.get("template_id", rf.get("id", "")))[:128],
            cwe=str(rf.get("cwe", "")),
            cve=str(rf.get("cve", "")),
            cvss=dict(rf.get("cvss") or {}),
            remediation=str(rf.get("remediation") or rf.get("fix") or "")[:3000],
            evidence=evidence_list,
            raw=dict(rf))
        host, endpoint, param = _url_detail(str(asset_value))
        if host:
            f.raw.setdefault("endpoint", endpoint)
            f.raw.setdefault("parameter", param or rf.get("parameter", ""))
        f.finalize()
        f.title = str(title)[:280]
        out.append(f)
    return out


def evidence_from_finding(rf: dict, *, source: str = "") -> list[dict]:
    """Build SANITIZED evidence dicts from a finding's evidence string.
    Redaction happens in models.Evidence.sanitize() — here we only slice."""
    ev = rf.get("evidence") or rf.get("description") or ""
    payload = rf.get("payload") or ""
    items = []
    if ev:
        items.append({"evidence_type": "response", "url": "",
                      "detection_reason": str(ev)[:500], "scanner": source,
                      "rule_id": rule_id_for(rf, "")})
    if payload:
        items.append({"evidence_type": "request", "url": "",
                      "detection_reason": f"payload: {str(payload)[:200]}",
                      "scanner": source, "rule_id": rule_id_for(rf, "")})
    return items


def waf_findings_from_raw(raw: dict, *, project_id: str, scan_id: str) \
        -> list[models.Finding]:
    """WallFinder output → Findings (WAF in front)."""
    wafs = raw.get("waf") or []
    if not wafs and raw.get("reachable") is not False:
        return []
    out = []
    for w in wafs:
        if not isinstance(w, dict):
            continue
        f = models.Finding(
            scan_id=scan_id, project_id=project_id,
            title=f"WAF in front: {w.get('vendor', 'unknown')}",
            severity="Low", category="exposure", source="WallFinder",
            rule_id=str(w.get("vendor", "waf"))[:128],
            remediation="Tailor payloads & expect rate limits; confirm scope.",
            evidence=[{"evidence_type": "behavioral",
                       "detection_reason": ", ".join(w.get("evidence", []))[:500],
                       "scanner": "WallFinder",
                       "rule_id": str(w.get("vendor", "waf"))[:128]}],
            raw=dict(w))
        f.finalize()
        out.append(f)
    return out


def subdomain_findings_from_raw(raw: dict, *, project_id: str, scan_id: str) \
        -> list[models.Finding]:
    """SubKraken output → Info findings about live subdomains."""
    subs = raw.get("subdomains")
    if not isinstance(subs, dict):
        return []
    out = []
    for i, (name, info) in enumerate(sorted(subs.items())):
        info = info or {}
        ips = info.get("ips", [])
        f = models.Finding(
            scan_id=scan_id, project_id=project_id,
            title=f"Live subdomain: {name}" if ips else f"Discovered subdomain: {name}",
            severity="Info" if not ips else "Low",
            category="exposure", source="SubKraken",
            rule_id=f"subkraken-{i + 1:03d}",
            remediation="Enumerate all live hosts for exposed services.",
            evidence=[{"evidence_type": "dns",
                       "detection_reason": f"ips={','.join(ips[:3])} "
                                           f"src={','.join(info.get('sources', ['ct']))}",
                       "scanner": "SubKraken"}],
            raw={"name": name, "ips": ips})
        f.finalize()
        out.append(f)
    return out


def cloud_findings_from_raw(raw: dict, *, project_id: str, scan_id: str) \
        -> list[models.Finding]:
    """CloudScope output → Findings."""
    checks = raw.get("checks")
    if not isinstance(checks, list):
        return []
    out = []
    for c in checks:
        if not isinstance(c, dict):
            continue
        f = models.Finding(
            scan_id=scan_id, project_id=project_id,
            title=f"{c.get('service', 'service')} — {c.get('status', '')}",
            severity=normalize_severity(c.get("severity")),
            category="misconfiguration", source="CloudScope",
            rule_id=str(c.get("service", "cloud"))[:128],
            remediation=str(c.get("remediation", ""))[:3000],
            evidence=[{"evidence_type": "configuration",
                       "detection_reason": str(c.get("evidence", ""))[:500],
                       "scanner": "CloudScope",
                       "rule_id": str(c.get("service", "cloud"))[:128]}],
            raw=dict(c))
        f.finalize()
        out.append(f)
    return out


def normalize_result(raw: dict, *, project_id: str, target_urls: list[str] | None = None) \
        -> dict:
    """One-stop adapter: raw scanner JSON → {scan, assets, findings}.
    The raw payload is returned untouched (caller persists it)."""
    if not isinstance(raw, dict):
        raise errors.ValidationError("Scanner result must be a JSON object")
    scan = scan_from_raw(raw, project_id=project_id)
    assets = assets_from_raw(raw, project_id=project_id)
    asset_index = {}
    for a in assets:
        asset_index[a.value] = a.id
    if isinstance(raw.get("subdomains"), dict):
        findings = subdomain_findings_from_raw(raw, project_id=project_id,
                                               scan_id=scan.id)
    elif isinstance(raw.get("checks"), list):
        findings = cloud_findings_from_raw(raw, project_id=project_id,
                                           scan_id=scan.id)
    elif isinstance(raw.get("waf"), list):
        findings = waf_findings_from_raw(raw, project_id=project_id,
                                         scan_id=scan.id)
    else:
        findings = findings_from_raw(raw, project_id=project_id, scan_id=scan.id,
                                     asset_index=asset_index)
    return {"scan": scan, "assets": assets, "findings": findings}
