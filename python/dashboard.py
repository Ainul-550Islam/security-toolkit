#!/usr/bin/env python3
# ============================================================================
#  SecuPulse — Security Findings Dashboard (zero-dependency web portal)
#  ---------------------------------------------------------------------------
#  Starts a local/self-hosted web portal that visualises every JSON report
#  produced by the toolkit (web audit, API audit, Nucleus template scan,
#  Injector fuzzing, WallFinder WAF, CloudScope, SubKraken, SecuSpider, ...).
#
#  Multi-client (SaaS-style) mode:
#      results/
#        acme-corp/   -> scan_2026-09-04.json   (tenant: acme-corp)
#        globex/      -> ...
#        report.json  -> tenant: "default"
#
#  Features:
#    • Overview dashboard (score gauges, severity donut, recent scans)
#    • Per-client (tenant) workspace
#    • Findings explorer: search / severity filter / expandable evidence+fix
#    • Remediation tracking: open → in-progress → mitigated → verified
#    • REST API + per-tenant isolation
#    • Optional Bearer-token auth (--token) for client-facing portals
#    • Everything inline (no CDN, no pip package) — runs fully offline
#
#  Usage:
#    python3 dashboard.py --root results --port 8080
#    python3 dashboard.py --root results --port 8443 --token SECRET   # client portal
#    curl http://127.0.0.1:8080/api/tenant/acme/scans
#
#  LEGAL: a reporting portal for authorised engagements only.
# ============================================================================

import argparse
import hmac
import ipaddress
import json
import logging
import os
import re
import sys
import uuid
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
SEV_WEIGHTS = {"Critical": 25, "High": 14, "Medium": 8, "Low": 4, "Info": 0}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEV_COLORS = {"Critical": "#ff3b5c", "High": "#ff8a3d", "Medium": "#ffd23d",
              "Low": "#4da3ff", "Info": "#7d8590"}
STATUSES = ["open", "in-progress", "mitigated", "verified"]
SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$")
MAX_DASHBOARD_TOKEN_LENGTH = 4096
MAX_STATUS_NOTE_LENGTH = 1024
MAX_EXPORT_BYTES = 4_000_000
DASHBOARD_TOKEN_ENV = "SECURITY_TOOLKIT_DASHBOARD_TOKEN"

HTML_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecuPulse — Security Findings Portal</title>
<style>
:root{--bg:#0b0f17;--panel:#121826;--panel2:#0f1522;--line:#1e2838;--txt:#e6ebf4;
--mut:#8a94a6;--acc:#3ddc97;--acc2:#9d6bff;--mono:'SF Mono',Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.55 -apple-system,'Segoe UI',Roboto,Arial,sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:20px}header{display:flex;align-items:center;
gap:14px;padding:14px 0;border-bottom:1px solid var(--line);margin-bottom:22px;
flex-wrap:wrap}header .logo{font-weight:800;font-size:19px;letter-spacing:.3px}
header .logo span{color:var(--acc)}header .sub{color:var(--mut);font-size:12px}
header .sp{flex:1}.pill{border:1px solid var(--line);border-radius:999px;padding:3px 12px;
color:var(--mut);font-size:12px}
.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(auto-fit,minmax(210px,1fr))}
.g3{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:16px}.card h3{margin:0 0 12px;font-size:14px;color:var(--mut);
font-weight:600;text-transform:uppercase;letter-spacing:.8px}
.big{font-size:34px;font-weight:800}.small{color:var(--mut);font-size:12px}
table{width:100%;border-collapse:collapse}th{text-align:left;color:var(--mut);
font-size:11px;text-transform:uppercase;letter-spacing:.7px;padding:8px 10px;
border-bottom:1px solid var(--line)}td{padding:9px 10px;border-bottom:1px solid var(--line2,#161e2e);
vertical-align:top}tr:hover td{background:#151d2e}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;
font-weight:700;letter-spacing:.4px;color:#0b0f17}
.badge{display:inline-block;padding:2px 9px;border-radius:6px;font-size:11px;
border:1px solid var(--line);color:var(--mut);cursor:pointer}
.badge.open{color:#ffb0bd;border-color:#ff3b5c55}.badge.in-progress{color:#ffd9a8;
border-color:#ff8a3d55}.badge.mitigated{color:#b9d8ff;border-color:#4da3ff55}
.badge.verified{color:#b7f4d8;border-color:#3ddc9755}
input,select{background:var(--panel2);border:1px solid var(--line);color:var(--txt);
border-radius:8px;padding:8px 12px;font-size:13px;outline:none}
input:focus,select:focus{border-color:var(--acc2)}
.btn{background:var(--acc);color:#06281c;border:0;border-radius:8px;padding:9px 16px;
font-weight:700;cursor:pointer;font-size:13px}.btn.ghost{background:transparent;
border:1px solid var(--line);color:var(--txt)}
.find{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
margin-bottom:10px;overflow:hidden}.find summary{padding:12px 14px;cursor:pointer;
display:flex;gap:10px;align-items:center;list-style:none}.find summary::-webkit-details-marker{display:none}
.find summary .t{flex:1;font-weight:600}.find .body{padding:0 14px 12px}
.ev{background:#0a0e16;border:1px solid var(--line);border-radius:8px;padding:10px;
font-family:var(--mono);font-size:12px;white-space:pre-wrap;color:#c8d3e5;
margin:8px 0;word-break:break-word}
.mut{color:var(--mut)}.mono{font-family:var(--mono);font-size:12px}
.gauge{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}
footer{margin-top:30px;color:#5c6675;font-size:11px;text-align:center;
border-top:1px solid var(--line);padding-top:14px}
.nav{display:flex;gap:8px;flex-wrap:wrap}.nav a{padding:6px 14px;border:1px solid var(--line);
border-radius:8px;color:var(--txt);font-size:13px}.nav a.on{background:#1d2b46;border-color:var(--acc2)}
.login{max-width:380px;margin:12vh auto;text-align:center}
@media print{header .nav,header .sp,.toolbar,.badge{cursor:default}
.find{page-break-inside:avoid}body{background:#fff;color:#111}
.card,input,.find{background:#fff;border-color:#ccc}}
</style></head><body><div class="wrap">"""

HTML_FOOT = """<footer>SecuPulse v1.0 — reporting portal for authorised security engagements only.
Findings require written permission before testing. · Generated %s</footer>
</div></body></html>"""

JS_HELPERS = """
<script>
const COLORS={"Critical":"#ff3b5c","High":"#ff8a3d","Medium":"#ffd23d",
"Low":"#4da3ff","Info":"#7d8590"};
function donut(segs,size){ // segs: [{k,v}]
  const total=segs.reduce((a,s)=>a+s.v,0)||1; const r=size/2-10, cx=size/2, cy=size/2;
  let a0=-Math.PI/2, out='';
  segs.forEach(s=>{ if(!s.v) return; const a1=a0+2*Math.PI*s.v/total;
    const large=(a1-a0)>Math.PI?1:0;
    const x0=cx+r*Math.cos(a0),y0=cy+r*Math.sin(a0),x1=cx+r*Math.cos(a1),y1=cy+r*Math.sin(a1);
    out+=`<path d="M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}"
      stroke="${COLORS[s.k]||'#888'}" stroke-width="14" fill="none"
      stroke-linecap="butt" transform="rotate(0 ${cx} ${cy})"/>`;
    a0=a1;});
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${out}
    <text x="${cx}" y="${cy-2}" text-anchor="middle" fill="#e6ebf4" font-size="18"
      font-weight="800">${total}</text>
    <text x="${cx}" y="${cy+16}" text-anchor="middle" fill="#8a94a6"
      font-size="10">findings</text></svg>`;
}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;',
  '>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function sevChip(sev){return `<span class="chip" style="background:${COLORS[sev]||'#888'}">${esc(sev)}</span>`;}
async function api(u){const r=await fetch(u,{credentials:'same-origin',cache:'no-store',
  headers:{'Accept':'application/json'}});
  if(r.status===401){showLogin();throw new Error('unauthorized');}
  if(!r.ok) throw new Error('request failed'); return r.json();}
function showLogin(){document.body.innerHTML='<div class="login"><h2>Token required</h2>'+
  '<input id="tk" placeholder="access token"><br><br><button class="btn" onclick="setTok()">Unlock</button></div>';}
function setTok(){const t=document.getElementById('tk').value;
  if(!t||t.length>4096)return;
  const secure=location.protocol==='https:'?';Secure':'';
  document.cookie='sess='+encodeURIComponent(t)+';Path=/;SameSite=Strict'+secure;
  location.assign(location.pathname);}
</script>
"""


# ---------------------------------------------------------------------------
# Data layer — scan discovery & normalisation
# ---------------------------------------------------------------------------
def ensure_finding(f, idx):
    f = dict(f)
    f.setdefault("id", f"F-{idx + 1:03d}")
    f.setdefault("title", f.get("name") or f.get("check") or f.get("type") or "Finding")
    f.setdefault("severity", f.get("risk") or "Info")
    if f["severity"] not in SEV_ORDER:
        f["severity"] = "Info"
    f.setdefault("evidence", f.get("description") or f.get("detail") or "")
    f.setdefault("remediation", f.get("recommendation") or f.get("fix") or "")
    return f


def normalize(path: str, rel: str) -> dict | None:
    """Turn one result-JSON into a uniform scan record (or None to skip)."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None

    rec = {"file": rel, "raw": raw}
    stem = os.path.basename(path)
    if stem.endswith(".json"):
        stem = stem[:-5]
    rec["tool"] = str(raw.get("tool") or raw.get("name") or stem)
    rec["target"] = str(raw.get("target") or raw.get("url") or raw.get("domain")
                        or raw.get("host") or "-")
    rec["date"] = str(raw.get("scan_date") or raw.get("date") or time.strftime("%Y-%m-%d"))
    rec["score"] = raw.get("score")
    rec["grade"] = raw.get("grade")

    findings = []
    kind = "findings"
    if isinstance(raw.get("findings"), list):
        findings = [ensure_finding(f, i) for i, f in enumerate(raw["findings"])
                    if isinstance(f, dict)]
    elif isinstance(raw.get("checks"), list):                     # CloudScope
        kind = "cloud"
        findings = [ensure_finding({
            "id": c.get("service", "SVC"),
            "title": f"{c.get('service','')} — {c.get('status','')}",
            "severity": c.get("severity", "Info"),
            "evidence": c.get("evidence", ""),
            "remediation": c.get("remediation", "")}, i)
            for i, c in enumerate(raw["checks"]) if isinstance(c, dict)]
    elif isinstance(raw.get("subdomains"), dict):                 # SubKraken
        kind = "subdomain"
        live = sorted(n for n, v in raw["subdomains"].items() if (v or {}).get("ips"))
        findings = [
            {"id": f"S-{i+1:03d}",
             "title": f"{n}  ({', '.join(raw['subdomains'][n].get('ips', [])[:2])})",
             "severity": "Info" if not raw['subdomains'][n].get('ips') else "Low",
             "evidence": f"source: {', '.join(raw['subdomains'][n].get('sources', ['ct']))}",
             "remediation": "Enumerate all live hosts for exposed services."}
            for i, n in enumerate(sorted(raw["subdomains"]))]
    elif isinstance(raw.get("waf"), list):                        # WallFinder
        kind = "waf"
        detected = raw.get("waf") or []
        findings = [ensure_finding({
            "id": w.get("vendor", "WAF"),
            "title": f"WAF: {w.get('vendor','')}",
            "severity": "High",
            "evidence": ", ".join(w.get("evidence", [])) or "behavioral match",
            "remediation": "Know your protective layer; tailor payloads and expect "
                           "rate limits when testing (authorized only)."}, i)
            for i, w in enumerate(detected)] if detected else []
        if not findings:
            findings = [{"id": "WAF-NONE", "title": "No WAF fingerprint detected",
                         "severity": "Info", "evidence": "Direct hosting or custom layout",
                         "remediation": "Confirm protection layers manually."}]
    elif isinstance(raw.get("endpoints"), list):                  # SecuSpider
        kind = "spider"
        findings = [{"id": f"E-{i+1:03d}", "title": f"endpoint {e}",
                     "severity": "Info", "evidence": "discovered by crawler",
                     "remediation": "Validate auth on every discovered endpoint."}
                    for i, e in enumerate(raw.get("endpoints", [])[:200])]
    else:
        kind = "raw"
        findings = [{"id": "RAW", "title": f"{stem} (raw result)",
                     "severity": "Info",
                     "evidence": json.dumps(raw, ensure_ascii=False)[:300],
                     "remediation": "Open the JSON file for the source detail."}]

    if rec["score"] is None:
        rec["score"] = max(0.0, 100.0 - sum(SEV_WEIGHTS.get(f["severity"], 0)
                                            for f in findings))
        rec["score"] = round(rec["score"], 1)
    if rec["grade"] is None:
        s = rec["score"]
        rec["grade"] = ("A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else
                        "D" if s >= 45 else "E" if s >= 30 else "F")
    rec["kind"] = kind
    rec["findings"] = findings
    rec["summary"] = {}
    for f in findings:
        rec["summary"][f["severity"]] = rec["summary"].get(f["severity"], 0) + 1
    return rec


def discover(root: str) -> tuple:
    """Return (scans list, tenants list) sorted."""
    scans, tenants = [], {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith(".json") or fn.startswith("."):
                continue
            if fn in ("status.json",) or ".status" in fn:
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            parts = rel.split(os.sep)
            tenant = parts[0] if len(parts) > 1 else "default"
            tenant_id = re.sub(r"[^A-Za-z0-9._-]", "-", tenant)
            rec = normalize(path, rel)
            if not rec:
                continue
            scan_id = fn[:-5]
            if not SAFE_ID.match(scan_id):
                scan_id = "scan"
            scans.append({"tenant": tenant_id, "id": scan_id, **rec})
            tenants.setdefault(tenant_id, []).append(scan_id)
    scans.sort(key=lambda s: s["date"], reverse=True)
    return scans, tenants


def status_path(root: str):
    return os.path.join(root, ".status.json")


def load_status(root: str) -> dict:
    p = status_path(root)
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_status(root: str, data: dict):
    with open(status_path(root), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# HTML fragments
# ---------------------------------------------------------------------------
def load_jobs_snapshot(db_path, org_filter="", limit=200):
    """Phase 3 ops snapshot from the platform SQLite (read/redacted).
    Never exposes payloads or actor ids; org-filtered so a multi-tenant
    deployment can run one dashboard per org without leaking job ids."""
    out, stages_index = [], {}
    if not db_path:
        return out, stages_index
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import jobs as _jobs
        import platform_service as _pf
        import scanners as _sc
        svc = _pf.PlatformService(db_path)
        jsvc = _jobs.JobService(svc, _sc.REGISTRY)
        for j in jsvc.job_list(org_id=org_filter or None, limit=int(limit)):
            out.append({"id": j.id, "scan_id": j.scan_id,
                        "profile": j.profile, "status": j.status,
                        "priority": j.priority, "attempt": j.attempt,
                        "max_attempts": j.max_attempts,
                        "worker": j.worker_id,
                        "error_code": j.error_code,
                        "created_at": j.created_at,
                        "started_at": j.started_at,
                        "finished_at": j.finished_at})
            stages_index[j.scan_id] = [
                {"stage": s.stage, "status": s.status,
                 "error_code": s.error_code}
                for s in svc.scan_stage_list(j.scan_id)]
    except Exception:
        out, stages_index = [], {}
    return out, stages_index


def load_intel_snapshot(db_path, org_filter="", *, max_findings=400):
    """Phase-4 intelligence snapshot — READ ONLY, org-filtered, redacted.
    Returns counts + bounded metadata (never evidence snippets, never
    payloads). `db_path` empty → None (panel simply hidden)."""
    if not db_path:
        return None
    try:
        import platform_service as _pf
        svc = _pf.PlatformService(db_path)
        proj_ids, proj_names = [], {}
        if org_filter:
            for p in svc.project_list(org_filter):
                proj_ids.append(p.id)
                proj_names[p.id] = p.name
        else:
            for o in svc.org_list():
                for p in svc.project_list(o.id):
                    proj_ids.append(p.id)
                    proj_names[p.id] = p.name
        proj_ids = proj_ids[:100]
        if not proj_ids:
            return {"org": org_filter or "", "projects": [], "assets": [],
                    "findings": [], "clusters": [], "diffs": [],
                    "counts": {}, "empty": True}
        ph = ",".join("?" for _ in proj_ids)
        rows = svc.db.query(
            f"SELECT id, value, asset_type, criticality, exposure, status, "
            f"project_id FROM assets WHERE project_id IN ({ph}) ORDER BY "
            f"criticality DESC, id LIMIT 1000", tuple(proj_ids))
        assets = [{"id": r["id"], "value": r["value"][:160],
                   "asset_type": r["asset_type"],
                   "criticality": r["criticality"],
                   "exposure": r["exposure"], "status": r["status"],
                   "project_id": r["project_id"]} for r in rows]
        findings = svc.db.query(
            f"SELECT id, title, severity, confidence_score, risk_score, "
            f"risk_level, priority, priority_order, lifecycle, category, "
            f"asset_id, project_id FROM findings WHERE project_id IN ({ph}) "
            f"ORDER BY priority_order, risk_score DESC LIMIT ?",
            tuple(proj_ids) + (int(max_findings),))
        flist = [{"id": r["id"], "title": str(r["title"])[:120],
                  "severity": r["severity"],
                  "confidence_score": r["confidence_score"],
                  "risk_score": r["risk_score"],
                  "risk_level": r["risk_level"],
                  "priority": r["priority"],
                  "lifecycle": r["lifecycle"],
                  "category": r["category"],
                  "project_id": r["project_id"]} for r in findings]
        clusters = svc.db.query(
            f"SELECT id, cluster_type, title, risk_score, risk_level, "
            f"project_id FROM clusters WHERE project_id IN ({ph}) ORDER BY "
            f"risk_score DESC LIMIT 100", tuple(proj_ids))
        diffs = svc.db.query(
            f"SELECT id, baseline_scan_id, current_scan_id, calc_version, "
            f"created_at, summary FROM scan_diffs WHERE project_id IN "
            f"({ph}) ORDER BY created_at DESC LIMIT 10", tuple(proj_ids))
        counts = {"assets": len(assets), "findings": len(flist),
                  "open": sum(1 for f in flist if f["lifecycle"] in (
                      "open", "reopened", "in_review", "confirmed")),
                  "internet_facing": sum(1 for a in assets if
                                         a["exposure"] == "internet_facing"),
                  "critical_assets": sum(1 for a in assets if
                                         a["criticality"] == "critical"),
                  "P0": sum(1 for f in flist if f["priority"] == "P0"),
                  "P1": sum(1 for f in flist if f["priority"] == "P1"),
                  "high_risk": sum(1 for f in flist if f["risk_level"] in (
                      "critical", "high"))}
        import json as _json
        return {"org": org_filter or "", "projects": [
            {"id": pid, "name": proj_names.get(pid, "")}
            for pid in proj_ids],
            "assets": assets, "findings": flist,
            "clusters": [{k: (v if k != "title" else str(v)[:100])
                          for k, v in dict(c).items() if k != "summary"}
                         for c in clusters],
            "diffs": [{"id": r["id"],
                       "from_scan": r["baseline_scan_id"][:24],
                       "to_scan": r["current_scan_id"][:24],
                       "calc_version": r["calc_version"],
                       "created_at": r["created_at"],
                       "summary": _json.loads(r["summary"] or "{}")
                       .get("summary", {})} for r in diffs],
            "counts": counts}
    except Exception:
        return None


def load_monitor_snapshot(db_path, org_filter="", *, max_rows=200):
    """Phase-5 monitoring snapshot — READ ONLY, org-filtered, redacted.
    Never exposes webhook secrets, notification payloads, or raw state
    blobs. `db_path` empty → None (panel hidden)."""
    if not db_path:
        return None
    try:
        import store as _store
        svc = _pf_service(db_path)
        proj_ids, proj_names = [], {}
        if org_filter:
            for p in svc.project_list(org_filter):
                proj_ids.append(p.id)
                proj_names[p.id] = p.name
        else:
            for o in svc.org_list():
                for p in svc.project_list(o.id):
                    proj_ids.append(p.id)
                    proj_names[p.id] = p.name
        proj_ids = proj_ids[:100]
        if not proj_ids:
            return {"org": org_filter or "", "empty": True, "projects": [],
                    "policies": [], "executions": [], "events": [],
                    "alerts": [], "tickets": [], "health": []}
        ph = ",".join("?" for _ in proj_ids)

        def q(sql, extra=(), limit=max_rows):
            # expand the `IN ({})` project-id placeholder — never string-
            # interpolate values, only the positional markers
            sql = sql.replace("{}", ph)
            return [dict(r) for r in svc.db.query(
                sql + f" LIMIT {int(limit)}", tuple(proj_ids) + tuple(extra))]

        policies = []
        for r in q("SELECT id, project_id, org_id, name, enabled, "
                   "scan_profile, schedule_type, interval_minutes, "
                   "daily_time, weekly_day, weekly_time, priority, "
                   "timeout_minutes, missed_policy, max_concurrent, "
                   "last_run, last_success, last_failure, "
                   "consecutive_failures, next_run, created_at, targets "
                   "FROM monitoring_policies WHERE project_id IN ({}) "
                   "ORDER BY name"):
            d = dict(r)
            d["targets"] = [str(t)[:120]
                            for t in (_store.loads(d.get("targets") or "[]")
                                      or [])]
            d["project_name"] = proj_names.get(r["project_id"], "")
            policies.append(d)
        executions = q("SELECT id, project_id, policy_id, scheduled_window, "
                       "scan_id, status, reason, created_at, finished_at FROM "
                       "scheduler_executions WHERE project_id IN ({}) "
                       "ORDER BY created_at DESC")
        events = q("SELECT id, project_id, asset_id, event_type, source, ts, "
                   "confidence, state_key FROM security_events WHERE "
                   "project_id IN ({}) ORDER BY ts DESC, id DESC")
        alerts = q("SELECT id, project_id, rule_id, event_type, asset_id, "
                   "title, severity, state, occurrence_count, first_seen, "
                   "last_seen, suppressed_until FROM alerts WHERE "
                   "project_id IN ({}) ORDER BY last_seen DESC")
        tickets = q("SELECT t.id, t.project_id, t.finding_id, t.priority, "
                    "t.status, t.verification_status, "
                    "t.verification_attempts, t.due_at, t.resolved_at, "
                    "t.created_at, t.updated_at FROM remediation_tickets t "
                    "WHERE t.project_id IN ({}) ORDER BY t.due_at, "
                    "t.created_at")
        try:
            health = []
            import monitor as _mon
            for pid in proj_ids[:50]:
                h = _mon.MonitoringHealthService(svc).compute(pid)
                health.append({k: h.get(k) for k in
                               ("project_id", "health", "score",
                                "last_success", "consecutive_failures",
                                "next_expected_run", "stale_after")})
            health = [h for h in health if h]
        except Exception:
            health = []
        return {"org": org_filter or "", "empty": False,
                "projects": [{"id": p, "name": proj_names.get(p, "")}
                             for p in proj_ids],
                "policies": policies, "executions": executions,
                "events": events, "alerts": alerts, "tickets": tickets,
                "health": health}
    except Exception:
        return None


_PF_CACHE = {}


def load_reporting_snapshot(db_path, org_filter="", *,
                            max_projects=20, max_reports=50,
                            max_evidence=100):
    """Phase-6 read-only snapshot: analytics bundles (posture/KPIs/trends/
    exposure/remediation/monitoring) + recent report runs + compliance
    evidence items. `db_path` empty → None (panels hidden). Bounded +
    redacted; never crosses tenants (org filter required in multi-tenant
    mode)."""
    if not db_path:
        return None
    try:
        import analytics as _an
        data = _an.analytics_snapshot(db_path, org_filter,
                                      max_projects=max_projects)
        if data is None:
            return None
        import platform_service as _pf
        svc = _pf.PlatformService(db_path)
        reports, evidence = [], []
        if org_filter:
            proj_ids = [p.id for p in svc.project_list(org_filter)]
        else:
            proj_ids = [p.id for o in svc.org_list()
                        for p in svc.project_list(o.id)]
        for pid in proj_ids:
            for r in svc.db.query(
                    "SELECT id, report_type, title, generated_at, "
                    "generated_by, report_hash, data_cutoff, truncated, "
                    "truncation_reason, original_count, included_count, "
                    "immutable FROM report_runs WHERE project_id=? ORDER BY "
                    "created_at DESC LIMIT ?", (pid, max_reports)):
                reports.append(dict(r))
            for e in svc.db.query(
                    "SELECT id, control_category, source_type, source_id, "
                    "status, evidence_hash, evidence_ts, data_cutoff, "
                    "description FROM compliance_evidence WHERE "
                    "project_id=? ORDER BY control_category, id LIMIT ?",
                    (pid, max_evidence)):
                evidence.append(dict(e))
        reports = reports[:max_reports]
        evidence = evidence[:max_evidence]
        import redact as _rd
        return _rd.redact({
            "org": org_filter or "", "empty": False,
            "analytics": data.get("bundles") or [],
            "reports": reports,
            "evidence": evidence,
            "counts": {"reports": len(reports),
                       "evidence": len(evidence)}})
    except Exception:
        return None


def load_phase9_snapshot(db_path, org_filter="", *, limit=300):
    """Read-only Phase-9 snapshot: registered cloud accounts / container
    images / kubernetes clusters / IaC scan records + finding counts by
    rule family. Counts only — never secret material."""
    import sqlite3 as _sql
    snap = {"generated_at": "", "org": org_filter or "",
            "totals": {},
            "findings": {"CLOUD": {}, "CONT": {}, "K8S": {}, "IAC": {}}}
    try:
        conn = _sql.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = _sql.Row
        try:
            org_clause, args = ("WHERE org_id=?", [org_filter]) \
                if org_filter else ("", [])
            for r in conn.execute(
                    f"SELECT provider, status, COUNT(*) AS n FROM "
                    f"cloud_accounts {org_clause} GROUP BY provider, status",
                    args):
                d = snap["totals"].setdefault("accounts", {})
                d[f"{r['provider']}|{r['status']}"] = int(r["n"])
            rows = conn.execute(
                    f"SELECT COUNT(*) AS total, SUM(CASE WHEN scanned_at!='' "
                    f"THEN 1 ELSE 0 END) AS scanned FROM container_images "
                    f"{org_clause}", args).fetchone()
            snap["totals"]["images"] = {"total": int(rows["total"] or 0),
                                        "scanned": int(rows["scanned"] or 0)}
            snap["totals"]["clusters"] = int(conn.execute(
                "SELECT COUNT(*) AS n FROM kubernetes_clusters "
                + org_clause, args).fetchone()["n"])
            for r in conn.execute(
                    "SELECT status, COUNT(*) AS n FROM iac_scans "
                    + org_clause + " GROUP BY status", args):
                snap["totals"].setdefault("iac_status",
                                          {})[r["status"]] = int(r["n"])
            fam_q = ("SELECT substr(rule_id, 1, instr(rule_id, '-')-1) "
                     "AS fam, severity, "
                     "lifecycle, COUNT(*) AS n FROM findings WHERE "
                     "(rule_id LIKE 'CLOUD-%' OR rule_id LIKE 'CONT-%' "
                     "OR rule_id LIKE 'K8S-%' OR rule_id LIKE 'IAC-%') "
                     + ("AND project_id IN (SELECT id FROM projects "
                        "WHERE org_id=?)" if org_filter else ""))
            params = args if org_filter else []
            for r in conn.execute(fam_q + " GROUP BY fam, severity, "
                                 "lifecycle", params):
                fam = str(r["fam"]) or "OTHER"
                f = snap["findings"].setdefault(fam, {})
                sev = f.setdefault(str(r["severity"]), {})
                sev["total"] = int(sev.get("total", 0)) + int(r["n"])
                if str(r["lifecycle"]) not in ("resolved", "false_positive",
                                               "accepted_risk",
                                               "remediated"):
                    sev["open"] = int(sev.get("open", 0)) + int(r["n"])
        finally:
            conn.close()
    except Exception:
        snap["error"] = "phase9 snapshot unavailable"
    snap["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return snap


def load_phase9_api(db_path, org_filter="", *, limit=200):
    """Read-only Phase-9 API payload (spec §35): accounts / images /
    clusters / IaC records / recent findings — org-filtered, redacted,
    bounded. No credentials, no secret values, no raw evidence."""
    import sqlite3 as _sql
    limit = max(1, min(int(limit or 200), 500))
    out = {"org": org_filter or "", "accounts": [], "images": [],
           "clusters": [], "iac": [], "findings": []}
    try:
        conn = _sql.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = _sql.Row
        try:
            clause, args = ("WHERE org_id=?", [org_filter]) \
                if org_filter else ("", [])
            for r in conn.execute(
                    f"SELECT provider, account_identifier, display_name, "
                    f"status, credential_hint, last_inventory_at, "
                    f"last_scan_at, created_at FROM cloud_accounts "
                    f"{clause} ORDER BY created_at DESC LIMIT ?",
                    args + [limit]):
                d = dict(r)
                # hint is an 'enc:<sha8>' fingerprint — allow-list its prefix
                d["credential_hint"] = str(d.get("credential_hint") or "")[:16]
                out["accounts"].append(d)
            for r in conn.execute(
                    f"SELECT registry, repository, digest, package_count, "
                    f"vuln_count, created_at, scanned_at FROM "
                    f"container_images {clause} ORDER BY created_at DESC "
                    f"LIMIT ?", args + [limit]):
                d = dict(r)
                d["digest"] = str(d.get("digest") or "")[:24]  # prefix only
                out["images"].append(d)
            for r in conn.execute(
                    f"SELECT name, context, created_at FROM "
                    f"kubernetes_clusters {clause} ORDER BY created_at DESC "
                    f"LIMIT ?", args + [limit]):
                ctx = {}
                try:
                    ctx = _json_loads(r["context"]) if isinstance(
                        r["context"], str) else (r["context"] or {})
                except Exception:
                    ctx = {}
                out["clusters"].append({
                    "name": r["name"],
                    "status": str(ctx.get("status") or "registered")[:32],
                    "endpoint": str(ctx.get("endpoint") or "in-cluster")[:80],
                    "api_version": str(ctx.get("api_version") or "")[:32],
                    "created_at": r["created_at"]})
            for r in conn.execute(
                    f"SELECT source_name, file_name, format, files_parsed, "
                    f"resource_count, secret_count, finding_count, status, "
                    f"error_code, created_at FROM iac_scans {clause} "
                    f"ORDER BY created_at DESC LIMIT ?", args + [limit]):
                out["iac"].append(
                    {k: (v if not isinstance(v, (bytes, bytearray)) else "")
                     for k, v in dict(r).items()})
            # recent Phase-9 findings (counts/identifiers only — no raw)
            fam_clause = (" AND f.project_id IN (SELECT id FROM projects "
                          "WHERE org_id=?)") if org_filter else ""
            for r in conn.execute(
                    "SELECT f.rule_id, f.severity, f.lifecycle, f.title, "
                    "f.asset_id, f.last_detected FROM findings f WHERE "
                    "(f.rule_id LIKE 'CLOUD-%' OR f.rule_id LIKE 'CONT-%' "
                    "OR f.rule_id LIKE 'K8S-%' OR f.rule_id LIKE 'IAC-%') "
                    + fam_clause + " ORDER BY f.last_detected DESC LIMIT ?",
                    (([org_filter] if org_filter else []) + [limit])):
                d = dict(r)
                d["title"] = str(d.get("title") or "")[:160]
                out["findings"].append(d)
        finally:
            conn.close()
    except Exception:
        out["error"] = "phase9 api payload unavailable"
    return out


def _json_loads(text):
    import json as _j
    return _j.loads(text)


def phase9_page(snap) -> str:
    """Phase-9 panel: sources + finding counts by rule family (read-only)."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a href='/monitoring'>Monitoring</a>"
           "<a href='/reports'>Reports</a>"
           "<a href='/devsecops'>DevSecOps</a>"
           "<a class='on' href='/phase9'>Phase 9</a>"
           "<a href='/identity'>Identity</a><a href='/api/scans'>API</a>")
    if not snap or snap.get("error"):
        return page("Phase 9", "<p class='muted'>Phase-9 snapshot "
                               "unavailable.</p>", nav)
    acc = snap["totals"].get("accounts", {})
    imgs = snap["totals"].get("images", {})
    iac_status = snap["totals"].get("iac_status", {})
    cards = []
    for k, n in sorted(acc.items()):
        prov, status = k.split("|", 1)
        cards.append(f"<div class='card'><div class='big'>{n}</div>"
                     f"<div class='small'>{esc(prov)} accounts "
                     f"({esc(status)})</div></div>")
    cards.append(f"<div class='card'><div class='big'>"
                 f"{imgs.get('scanned', 0)}/{imgs.get('total', 0)}"
                 f"</div><div class='small'>images scanned</div></div>")
    cards.append(f"<div class='card'><div class='big'>"
                 f"{snap['totals'].get('clusters', 0)}</div>"
                 f"<div class='small'>k8s clusters</div></div>")
    cards.append(f"<div class='card'><div class='big'>"
                 f"{sum(iac_status.values())}</div>"
                 f"<div class='small'>IaC scans</div></div>")
    fam_rows = []
    for fam in ("CLOUD", "CONT", "K8S", "IAC"):
        dist = snap["findings"].get(fam, {})
        total = sum(v.get("total", 0) for v in dist.values())
        open_n = sum(v.get("open", 0) for v in dist.values())
        chips = "".join(
            f"<span class='chip' style='background:{SEV_COLORS.get(s, '#888')}'>"
            f"{esc(s)}: {v.get('open', 0)}</span> "
            for s, v in sorted(dist.items()))
        fam_rows.append(
            f"<tr><td><b>{fam}</b></td><td>{total}</td><td>{open_n}</td>"
            f"<td>{chips}</td></tr>")
    body = f"""
    <h2>Enterprise cloud / container / Kubernetes / IaC security</h2>
    <div class='cards'>{''.join(cards)}</div>
    <h3>Findings by rule family</h3>
    <table class='tbl'><tr><th>Family</th><th>Total</th><th>Open</th>
    <th>Open by severity</th></tr>{''.join(fam_rows)}</table>
    <p class='muted'>Registered cloud accounts / cluster credentials are
    stored encrypted at rest; Kubernetes Secret values are never stored.
    Generated {esc(snap['generated_at'])}.</p>
    """
    return page("Phase 9", body, nav)



def load_phase10_snapshot(db_path, org_filter="", *, limit=300):
    """Read-only Phase-10 snapshot: threat indicators / attack-surface
    assets / correlations / clusters / cases + TI finding counts.
    Counts and metadata only — never indicator payloads beyond the
    indicator value itself (correlation-required), never case notes."""
    import sqlite3 as _sql
    snap = {"generated_at": "", "org": org_filter or "",
            "indicators": {}, "assets": {}, "cases": {}, "clusters": 0,
            "matches": 0, "findings": {}}
    try:
        conn = _sql.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = _sql.Row
        try:
            clause, args = ("WHERE org_id=?", [org_filter]) \
                if org_filter else ("", [])
            for r in conn.execute(
                    f"SELECT ioc_type, status, COUNT(*) AS n FROM "
                    f"threat_indicators {clause} "
                    f"GROUP BY ioc_type, status", args):
                d = snap["indicators"].setdefault(str(r["ioc_type"]), {})
                d[str(r["status"])] = int(r["n"])
            aclause, aargs = ("WHERE p.org_id=?", [org_filter]) \
                if org_filter else ("WHERE 1=1", [])
            for r in conn.execute(
                    f"SELECT a.asset_type, COUNT(*) AS n FROM assets a "
                    f"JOIN projects p ON p.id=a.project_id {aclause} "
                    f"GROUP BY a.asset_type", aargs):
                snap["assets"][str(r["asset_type"])] = int(r["n"])
            snap["matches"] = int(conn.execute(
                "SELECT COUNT(*) AS n FROM threat_matches " + clause,
                args).fetchone()["n"])
            snap["clusters"] = int(conn.execute(
                "SELECT COUNT(*) AS n FROM threat_clusters " + clause,
                args).fetchone()["n"])
            for r in conn.execute(
                    f"SELECT status, priority, COUNT(*) AS n FROM "
                    f"investigation_cases {clause} GROUP BY status, priority",
                    args):
                d = snap["cases"].setdefault(str(r["status"]), {})
                d[str(r["priority"])] = int(r["n"])
            fam_q = ("SELECT CASE WHEN rule_id LIKE 'TI-%' THEN 'TI' "
                     "WHEN rule_id LIKE 'AS-CERT-%' THEN 'AS-CERT' "
                     "WHEN rule_id LIKE 'AS-%' THEN 'AS' ELSE 'OTHER' END "
                     "AS fam, severity, lifecycle, COUNT(*) AS n FROM "
                     "findings WHERE (rule_id LIKE 'TI-%' OR "
                     "rule_id LIKE 'AS-%') "
                     + ("AND project_id IN (SELECT id FROM projects "
                        "WHERE org_id=?)" if org_filter else ""))
            params = args if org_filter else []
            for r in conn.execute(fam_q + " GROUP BY fam, severity, "
                                  "lifecycle", params):
                fam = str(r["fam"]) or "OTHER"
                f = snap["findings"].setdefault(fam, {})
                sev = f.setdefault(str(r["severity"]), {})
                sev["total"] = int(sev.get("total", 0)) + int(r["n"])
                if str(r["lifecycle"]) not in ("resolved", "false_positive",
                                               "accepted_risk",
                                               "remediated"):
                    sev["open"] = int(sev.get("open", 0)) + int(r["n"])
        finally:
            conn.close()
    except Exception:
        snap["error"] = "phase10 snapshot unavailable"
    snap["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return snap


def load_phase10_api(db_path, org_filter="", *, limit=200):
    """Read-only Phase-10 API payload: recent indicators / cases /
    clusters / TI findings — org-filtered, redacted, bounded. Never case
    notes, never evidence, never feed secrets."""
    import sqlite3 as _sql
    limit = max(1, min(int(limit or 200), 500))
    out = {"org": org_filter or "", "iocs": [], "cases": [], "clusters": [],
           "findings": []}
    try:
        conn = _sql.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = _sql.Row
        try:
            clause, args = ("WHERE org_id=?", [org_filter]) \
                if org_filter else ("", [])
            for r in conn.execute(
                    f"SELECT indicator, ioc_type, confidence_level, status, "
                    f"last_seen FROM threat_indicators {clause} "
                    f"ORDER BY last_seen DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["indicator"] = str(d.get("indicator") or "")[:60]
                out["iocs"].append(d)
            for r in conn.execute(
                    f"SELECT id, title, status, priority, owner, created_at "
                    f"FROM investigation_cases {clause} "
                    f"ORDER BY updated_at DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["id"] = str(d.get("id") or "")[:8]
                d["title"] = str(d.get("title") or "")[:80]
                out["cases"].append(d)
            for r in conn.execute(
                    f"SELECT label, kind, member_count, last_seen FROM "
                    f"threat_clusters {clause} ORDER BY last_seen DESC "
                    f"LIMIT ?", args + [limit]):
                out["clusters"].append(dict(r))
            act = (" AND project_id IN (SELECT id FROM projects "
                   "WHERE org_id=?)" if org_filter else "")
            for r in conn.execute(
                    "SELECT rule_id, severity, lifecycle, COUNT(*) AS n "
                    "FROM findings WHERE (rule_id LIKE 'TI-%' OR "
                    "rule_id LIKE 'AS-%')" + act +
                    " GROUP BY rule_id, severity, lifecycle ORDER BY n DESC "
                    "LIMIT ?", (args if org_filter else []) + [limit]):
                d = dict(r)
                d["rule_id"] = str(d.get("rule_id") or "")[:64]
                out["findings"].append(d)
        finally:
            conn.close()
    except Exception:
        out["error"] = "phase10 api payload unavailable"
    return out


# ============================================================================
#  Phase 11 — data protection / privacy / secrets / compliance governance
#  panel. Read-only. Counts and metadata only — never secret values, never
#  search hashes, never subject references beyond truncation for own-tenant
#  rows, never audit metadata payloads.
# ============================================================================
def load_phase11_snapshot(db_path, org_filter="", *, limit=300):
    """Read-only Phase-11 snapshot: classification / secrets / retention /
    holds / privacy / exceptions / compliance-evidence state for one org."""
    import sqlite3 as _sql
    snap = {"generated_at": "", "org": org_filter or "",
            "classifications": {}, "secrets": {}, "retention_policies": 0,
            "holds": {}, "privacy": {}, "exceptions": {}, "compliance": {},
            "exports": 0, "recent": []}
    try:
        conn = _sql.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = _sql.Row
        try:
            clause, args = ("WHERE org_id=?", [org_filter]) \
                if org_filter else ("", [])
            for r in conn.execute(
                    f"SELECT classification, COUNT(*) AS n FROM "
                    f"data_classifications {clause} GROUP BY "
                    f"classification", args):
                snap["classifications"][str(r["classification"])] = int(r["n"])
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM secrets_registry "
                    f"{clause} GROUP BY status", args):
                snap["secrets"][str(r["status"])] = int(r["n"])
            snap["retention_policies"] = int(conn.execute(
                f"SELECT COUNT(*) AS n FROM retention_policies {clause}",
                args).fetchone()["n"])
            for r in conn.execute(
                    f"SELECT kind, COUNT(*) AS n FROM retention_holds "
                    f"{clause} AND released_at='' GROUP BY kind", args):
                snap["holds"][str(r["kind"])] = int(r["n"])
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM privacy_requests "
                    f"{clause} GROUP BY status", args):
                snap["privacy"][str(r["status"])] = int(r["n"])
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM policy_exceptions "
                    f"{clause} GROUP BY status", args):
                snap["exceptions"][str(r["status"])] = int(r["n"])
            # compliance evidence state (status vocabulary from models — the
            # panel only ever shows evidence state, never a compliance claim)
            for r in conn.execute(
                    f"SELECT control_category, status, COUNT(*) AS n FROM "
                    f"compliance_evidence {clause} GROUP BY "
                    f"control_category, status", args):
                d = snap["compliance"].setdefault(
                    str(r["control_category"]), {})
                d[str(r["status"])] = int(r["n"])
            snap["exports"] = int(conn.execute(
                f"SELECT COUNT(*) AS n FROM data_exports {clause}",
                args).fetchone()["n"])
            gov_actions = (
                "action IN ('secret.registered','secret.revoked',"
                "'secret.expired','secret.rotation_required',"
                "'hold.created','hold.released','data.deleted',"
                "'data.delete_blocked','retention.preview',"
                "'retention.execution','classification.changed',"
                "'classification.downgrade_denied','privacy.created',"
                "'privacy.updated','privacy.completed',"
                "'exception.created','exception.revoked',"
                "'sensitive.exported')")
            if org_filter:
                for r in conn.execute(
                        "SELECT ts, action, actor, object_type FROM "
                        "audit_events WHERE org_id=? AND " + gov_actions +
                        " ORDER BY ts DESC LIMIT ?",
                        (org_filter, limit)):
                    snap["recent"].append({
                        "ts": str(r["ts"]), "action": str(r["action"]),
                        "actor": str(r["actor"])[:40],
                        "object_type": str(r["object_type"])[:40]})
            else:
                for r in conn.execute(
                        "SELECT ts, action, actor, object_type FROM "
                        "audit_events WHERE " + gov_actions +
                        " ORDER BY ts DESC LIMIT ?", (limit,)):
                    snap["recent"].append({
                        "ts": str(r["ts"]), "action": str(r["action"]),
                        "actor": str(r["actor"])[:40],
                        "object_type": str(r["object_type"])[:40]})
        finally:
            conn.close()
    except Exception:
        snap["error"] = "phase11 snapshot unavailable"
    snap["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return snap


def load_phase11_api(db_path, org_filter="", *, limit=200):
    """Read-only Phase-11 API payload. Bounded, org-filtered, NEVER secret
    values or search hashes; subject references are truncated to a
    non-linkable prefix."""
    import sqlite3 as _sql
    limit = max(1, min(int(limit or 200), 500))
    out = {"org": org_filter or "", "classifications": [], "registry": [],
           "holds": [], "privacy": [], "exceptions": [], "compliance": []}
    try:
        conn = _sql.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = _sql.Row
        try:
            clause, args = ("WHERE org_id=?", [org_filter]) \
                if org_filter else ("", [])
            for r in conn.execute(
                    f"SELECT object_type, classification, provenance, "
                    f"project_id FROM data_classifications {clause} "
                    f"ORDER BY updated_at DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["object_type"] = str(d.get("object_type") or "")[:40]
                out["classifications"].append(d)
            for r in conn.execute(
                    f"SELECT kind, name, status, expires_at, "
                    f"rotation_due_at, revoked_at FROM secrets_registry "
                    f"{clause} ORDER BY updated_at DESC LIMIT ?",
                    args + [limit]):
                d = dict(r)
                d["name"] = str(d.get("name") or "")[:40]
                out["registry"].append(d)
            for r in conn.execute(
                    f"SELECT object_type, object_id, kind, created_at, "
                    f"expires_at FROM retention_holds {clause} AND "
                    f"released_at='' ORDER BY created_at DESC LIMIT ?",
                    args + [limit]):
                d = dict(r)
                d["object_id"] = str(d.get("object_id") or "")[:24]
                out["holds"].append(d)
            for r in conn.execute(
                    f"SELECT id, request_type, status, requester, "
                    f"created_at, updated_at FROM privacy_requests {clause} "
                    f"ORDER BY created_at DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["id"] = str(d.get("id") or "")[:8]
                d["request_type"] = str(d.get("request_type") or "")[:32]
                # subject_ref deliberately excluded (personal data)
                out["privacy"].append(d)
            for r in conn.execute(
                    f"SELECT policy, scope, status, created_by, approved_by, "
                    f"created_at, expires_at FROM policy_exceptions {clause} "
                    f"ORDER BY created_at DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["policy"] = str(d.get("policy") or "")[:64]
                d["scope"] = str(d.get("scope") or "")[:40]
                out["exceptions"].append(d)
            for r in conn.execute(
                    f"SELECT control_category, status, source_type, "
                    f"evidence_ts FROM compliance_evidence {clause} ORDER BY "
                    f"evidence_ts DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["control_category"] = str(
                    d.get("control_category") or "")[:40]
                d["source_type"] = str(d.get("source_type") or "")[:40]
                out["compliance"].append(d)
        finally:
            conn.close()
    except Exception:
        out["error"] = "phase11 api payload unavailable"
    return out


def phase10_page(snap) -> str:
    """Phase-10 panel: IOC / attack-surface / cases / clusters (read-only)."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a href='/monitoring'>Monitoring</a>"
           "<a href='/reports'>Reports</a>"
           "<a href='/devsecops'>DevSecOps</a>"
           "<a href='/phase9'>Phase 9</a>"
           "<a class='on' href='/phase10'>Phase 10</a>"
           "<a href='/phase11'>Phase 11</a>"
           "<a href='/phase12'>Phase 12</a>"
           "<a href='/identity'>Identity</a><a href='/api/scans'>API</a>")
    if not snap or snap.get("error"):
        return page("Phase 10", "<p class='muted'>Phase-10 snapshot "
                                "unavailable.</p>", nav)
    ind_total = sum(int(n) for d in snap["indicators"].values()
                    for n in d.values())
    open_iols = sum(int(n) for d in snap["indicators"].values()
                    for k, n in d.items() if k in ("active",))
    as_total = sum(snap["assets"].values())
    case_total = sum(int(n) for d in snap["cases"].values() for n in d.values())
    cards = [f"<div class='card'><div class='big'>{ind_total}</div>"
             f"<div class='small'>threat indicators</div></div>",
             f"<div class='card'><div class='big'>{as_total}</div>"
             f"<div class='small'>attack-surface assets</div></div>",
             f"<div class='card'><div class='big'>{snap['matches']}</div>"
             f"<div class='small'>IOC correlations</div></div>",
             f"<div class='card'><div class='big'>{snap['clusters']}</div>"
             f"<div class='small'>threat clusters</div></div>",
             f"<div class='card'><div class='big'>{case_total}</div>"
             f"<div class='small'>investigation cases</div></div>"]
    ioc_rows = []
    for t, dist in sorted(snap["indicators"].items()):
        parts = " / ".join(str(k) + ":" + str(int(n))
                           for k, n in sorted(dist.items()))
        ioc_rows.append(f"<tr><td><b>{esc(t)}</b></td>"
                        f"<td>{sum(int(n) for n in dist.values())}</td>"
                        f"<td>{esc(parts)}</td></tr>")
    case_rows = []
    for st, dist in sorted(snap["cases"].items()):
        parts = " / ".join(str(k) + ":" + str(int(n))
                           for k, n in sorted(dist.items()))
        case_rows.append(f"<tr><td><b>{esc(st)}</b></td>"
                         f"<td>{sum(int(n) for n in dist.values())}</td>"
                         f"<td>{esc(parts)}</td></tr>")
    fam_rows = []
    for fam in ("TI", "AS", "AS-CERT"):
        dist = snap["findings"].get(fam, {})
        total = sum(v.get("total", 0) for v in dist.values())
        open_n = sum(v.get("open", 0) for v in dist.values())
        chips = "".join(
            f"<span class='chip' style='background:{SEV_COLORS.get(s, '#888')}'>"
            f"{esc(s)}: {v.get('open', 0)}</span> "
            for s, v in sorted(dist.items()))
        fam_rows.append(
            f"<tr><td><b>{fam}</b></td><td>{total}</td><td>{open_n}</td>"
            f"<td>{chips}</td></tr>")
    body = f"""
    <h2>Security operations · threat intelligence · attack surface</h2>
    <div class='cards'>{''.join(cards)}</div>
    <h3>Indicators by type</h3>
    <table class='tbl'><tr><th>Type</th><th>Total</th><th>By status</th>
    </tr>{''.join(ioc_rows)}</table>
    <h3>Cases by status</h3>
    <table class='tbl'><tr><th>Status</th><th>Total</th><th>By priority</th>
    </tr>{''.join(case_rows)}</table>
    <h3>Threat-intelligence findings</h3>
    <table class='tbl'><tr><th>Family</th><th>Total</th><th>Open</th>
    <th>Open by severity</th></tr>{''.join(fam_rows)}</table>
    <p class='muted'>Provider-neutral: indicators, attack-surface
    observations and cases are per-tenant; feed secrets and case notes are
    never exposed. Generated {esc(snap['generated_at'])}.</p>
    """
    return page("Phase 10", body, nav)


def phase11_page(snap) -> str:
    """Phase-11 panel: data protection / privacy / secrets / compliance
    governance (read-only; counts and metadata only)."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a href='/monitoring'>Monitoring</a>"
           "<a href='/reports'>Reports</a>"
           "<a href='/devsecops'>DevSecOps</a>"
           "<a href='/phase9'>Phase 9</a>"
           "<a href='/phase10'>Phase 10</a>"
           "<a class='on' href='/phase11'>Phase 11</a>"
           "<a href='/phase12'>Phase 12</a>"
           "<a href='/identity'>Identity</a><a href='/api/scans'>API</a>")
    if not snap or snap.get("error"):
        return page("Phase 11", "<p class='muted'>Phase-11 snapshot "
                                "unavailable.</p>", nav)
    cls_total = sum(int(n) for n in snap["classifications"].values())
    sec_total = sum(int(n) for n in snap["secrets"].values())
    sec_bad = (int(snap["secrets"].get("expired", 0)) +
               int(snap["secrets"].get("rotation_required", 0)))
    hold_total = sum(int(n) for n in snap["holds"].values())
    priv_total = sum(int(n) for n in snap["privacy"].values())
    exc_total = sum(int(n) for n in snap["exceptions"].values())
    cards = [f"<div class='card'><div class='big'>{cls_total}</div>"
             f"<div class='small'>classified objects</div></div>",
             f"<div class='card'><div class='big'>{sec_total}</div>"
             f"<div class='small'>secrets registered</div></div>",
             f"<div class='card'><div class='big'"
             f" style='color:{'#c62828' if sec_bad else '#2e7d32'}'>"
             f"{sec_bad}</div><div class='small'>secrets expired or due "
             f"for rotation</div></div>",
             f"<div class='card'><div class='big'>{hold_total}</div>"
             f"<div class='small'>active retention holds</div></div>",
             f"<div class='card'><div class='big'>{priv_total}</div>"
             f"<div class='small'>privacy requests</div></div>",
             f"<div class='card'><div class='big'>{exc_total}</div>"
             f"<div class='small'>policy exceptions</div></div>"]
    rows = []
    for k, dist in sorted(snap["classifications"].items()):
        rows.append(f"<tr><td><b>{esc(k)}</b></td>"
                    f"<td>{int(dist)}</td></tr>")
    sec_rows = "".join(
        f"<tr><td><b>{esc(k)}</b></td><td>{int(v)}</td></tr>"
        for k, v in sorted(snap["secrets"].items()))
    hold_rows = "".join(
        f"<tr><td><b>{esc(k)}</b></td><td>{int(v)}</td></tr>"
        for k, v in sorted(snap["holds"].items()))
    priv_rows = "".join(
        f"<tr><td><b>{esc(k)}</b></td><td>{int(v)}</td></tr>"
        for k, v in sorted(snap["privacy"].items()))
    exc_rows = "".join(
        f"<tr><td><b>{esc(k)}</b></td><td>{int(v)}</td></tr>"
        for k, v in sorted(snap["exceptions"].items()))
    comp_rows = []
    for cat, dist in sorted(snap["compliance"].items()):
        tot = sum(int(v) for v in dist.values())
        chips = "".join(
            f"<span class='chip'>{esc(k)}: {int(v)}</span> "
            for k, v in sorted(dist.items()))
        comp_rows.append(f"<tr><td><b>{esc(cat)}</b></td><td>{tot}</td>"
                         f"<td>{chips}</td></tr>")
    recent_rows = "".join(
        f"<tr><td>{esc(r['ts'])}</td><td>{esc(r['action'])}</td>"
        f"<td>{esc(r['actor'])}</td></tr>" for r in snap["recent"][:20])
    body = f"""
    <h2>Data protection · privacy · secrets · compliance governance</h2>
    <div class='cards'>{''.join(cards)}</div>
    <div class='cards'>
      <div class='card'><div class='big'>{snap['retention_policies']}</div>
      <div class='small'>retention policies</div></div>
      <div class='card'><div class='big'>{snap['exports']}</div>
      <div class='small'>data exports</div></div>
    </div>
    <h3>Classifications</h3>
    <table class='tbl'><tr><th>Classification</th><th>Objects</th>
    </tr>{''.join(rows)}</table>
    <h3>Secrets registry</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>
    {sec_rows}</table>
    <h3>Active retention holds</h3>
    <table class='tbl'><tr><th>Kind</th><th>Count</th></tr>
    {hold_rows}</table>
    <h3>Privacy requests</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>
    {priv_rows}</table>
    <h3>Policy exceptions</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>
    {exc_rows}</table>
    <h3>Compliance evidence state</h3>
    <p class='muted'>Evidence state only — never a compliance or
    certification claim.</p>
    <table class='tbl'><tr><th>Control family</th><th>Items</th>
    <th>By status</th></tr>{''.join(comp_rows)}</table>
    <h3>Recent governance activity</h3>
    <table class='tbl'><tr><th>Timestamp</th><th>Action</th><th>Actor</th>
    </tr>{recent_rows}</table>
    <p class='muted'>Read-only panel. Secret values, search hashes,
    subject references and audit metadata are never rendered. Generated
    {esc(snap['generated_at'])}.</p>
    """
    return page("Phase 11", body, nav)


# ===========================================================================
#  Phase 12 — federation / evidence exchange / bulk ops / integrations
# ===========================================================================
def load_phase12_snapshot(db_path, org_filter="", *, limit=300):
    """Read-only Phase-12 snapshot: peers / policies / packages / imports /
    bulk jobs / integrations for one org. Counts + metadata only — package
    payloads, envelope contents and webhook payloads are NEVER read."""
    import sqlite3 as _sql
    snap = {"generated_at": "", "org": org_filter or "",
            "peers": {}, "policies": {}, "packages": 0, "package_objects": 0,
            "imports": {}, "imported_objects": 0, "rejected_recent": [],
            "bulk_jobs": {}, "integrations": {}, "integration_events": {},
            "recent": []}
    try:
        conn = _sql.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = _sql.Row
        try:
            clause, args = ("WHERE org_id=?", [org_filter]) \
                if org_filter else ("", [])
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM federation_peers "
                    f"{clause} GROUP BY status", args):
                snap["peers"][str(r["status"])] = int(r["n"])
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM federation_policies "
                    f"{clause} GROUP BY status", args):
                snap["policies"][str(r["status"])] = int(r["n"])
            row = conn.execute(
                f"SELECT COUNT(*) AS n, COALESCE(SUM(object_count),0) AS o "
                f"FROM federation_packages {clause}", args).fetchone()
            snap["packages"] = int(row["n"])
            snap["package_objects"] = int(row["o"])
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM federation_imports "
                    f"{clause} GROUP BY status", args):
                snap["imports"][str(r["status"])] = int(r["n"])
            row = conn.execute(
                f"SELECT COALESCE(SUM(imported_count),0) AS n FROM "
                f"federation_imports {clause}", args).fetchone()
            snap["imported_objects"] = int(row["n"])
            rej_clause = ("WHERE org_id=? AND status='rejected'"
                          if org_filter else "WHERE status='rejected'")
            for r in conn.execute(
                    f"SELECT error, created_at FROM federation_imports "
                    f"{rej_clause} ORDER BY created_at DESC LIMIT 20", args):
                snap["rejected_recent"].append(
                    {"error": safe_stored_error(r["error"]),
                     "created_at": str(r["created_at"])})
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM jobs {clause}"
                    f"{' AND' if clause else ' WHERE'} profile="
                    f"'federation-bulk' GROUP BY status", args):
                snap["bulk_jobs"][str(r["status"])] = int(r["n"])
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM external_integrations "
                    f"{clause} GROUP BY status", args):
                snap["integrations"][str(r["status"])] = int(r["n"])
            for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM integration_events "
                    f"{clause} GROUP BY status", args):
                snap["integration_events"][str(r["status"])] = int(r["n"])
            fed_actions = (
                "action LIKE 'federation.%' OR action LIKE 'integration.%'")
            if org_filter:
                rows = conn.execute(
                    "SELECT ts, action, actor, object_type FROM audit_events "
                    "WHERE org_id=? AND (" + fed_actions + ") ORDER BY ts "
                    "DESC LIMIT ?", (org_filter, limit))
            else:
                rows = conn.execute(
                    "SELECT ts, action, actor, object_type FROM audit_events "
                    "WHERE " + fed_actions + " ORDER BY ts DESC LIMIT ?",
                    (limit,))
            for r in rows:
                snap["recent"].append({
                    "ts": str(r["ts"]), "action": str(r["action"]),
                    "actor": str(r["actor"])[:40],
                    "object_type": str(r["object_type"])[:40]})
        finally:
            conn.close()
    except Exception:
        snap["error"] = "phase12 snapshot unavailable"
    snap["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return snap


def load_phase12_api(db_path, org_filter="", *, limit=200):
    """Read-only Phase-12 API payload. Bounded, org-filtered, metadata
    only: never package payloads, never envelope objects, never webhook
    payload bodies (hashes + byte sizes instead)."""
    import sqlite3 as _sql
    limit = max(1, min(int(limit or 200), 500))
    out = {"org": org_filter or "", "peers": [], "policies": [],
           "packages": [], "imports": [], "integrations": [], "events": []}
    try:
        conn = _sql.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = _sql.Row
        try:
            clause, args = ("WHERE org_id=?", [org_filter]) \
                if org_filter else ("", [])
            for r in conn.execute(
                    f"SELECT id, peer_org_id, name, status, direction, "
                    f"created_by, approved_by, created_at, expires_at, "
                    f"revoked_at FROM federation_peers {clause} ORDER BY "
                    f"created_at DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["name"] = str(d.get("name") or "")[:60]
                out["peers"].append(d)
            for r in conn.execute(
                    f"SELECT id, peer_id, name, status, project_id, "
                    f"max_objects, explicit_sensitive, created_at, "
                    f"expires_at FROM federation_policies {clause} ORDER BY "
                    f"created_at DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["name"] = str(d.get("name") or "")[:60]
                out["policies"].append(d)
            # payload column deliberately excluded (never leaves the store)
            for r in conn.execute(
                    f"SELECT id, peer_id, policy_id, project_id, "
                    f"destination_org_id, classification, object_count, "
                    f"byte_size, integrity_algorithm, integrity_hash, "
                    f"trust_mode, status, created_by, created_at FROM "
                    f"federation_packages {clause} ORDER BY created_at DESC "
                    f"LIMIT ?", args + [limit]):
                out["packages"].append(dict(r))
            for r in conn.execute(
                    f"SELECT id, package_id, package_hash, source_org_id, "
                    f"peer_id, status, collision_strategy, object_count, "
                    f"imported_count, skipped_count, linked_count, error, "
                    f"created_by, created_at FROM federation_imports "
                    f"{clause} ORDER BY created_at DESC LIMIT ?",
                    args + [limit]):
                d = dict(r)
                d["error"] = safe_stored_error(d.get("error"))
                out["imports"].append(d)
            for r in conn.execute(
                    f"SELECT id, project_id, name, kind, endpoint_url, "
                    f"status, created_by, created_at, disabled_at, "
                    f"last_delivery_at FROM external_integrations {clause} "
                    f"ORDER BY created_at DESC LIMIT ?", args + [limit]):
                d = dict(r)
                d["name"] = str(d.get("name") or "")[:60]
                out["integrations"].append(d)
            # payload_sha256 + byte_size only — event bodies are never
            # rendered or re-served
            for r in conn.execute(
                    f"SELECT id, integration_id, event_type, status, "
                    f"provider_outcome, payload_sha256, byte_size, "
                    f"created_at FROM integration_events {clause} ORDER BY "
                    f"created_at DESC LIMIT ?", args + [limit]):
                out["events"].append(dict(r))
        finally:
            conn.close()
    except Exception:
        out["error"] = "phase12 api payload unavailable"
    return out


def phase12_page(snap) -> str:
    """Phase-12 panel: federation / evidence exchange / bulk operations /
    external integrations (read-only; counts and metadata only)."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a href='/monitoring'>Monitoring</a>"
           "<a href='/reports'>Reports</a>"
           "<a href='/devsecops'>DevSecOps</a>"
           "<a href='/phase9'>Phase 9</a>"
           "<a href='/phase10'>Phase 10</a>"
           "<a href='/phase11'>Phase 11</a>"
           "<a class='on' href='/phase12'>Phase 12</a>"
           "<a href='/identity'>Identity</a><a href='/api/scans'>API</a>")
    if not snap or snap.get("error"):
        return page("Phase 12", "<p class='muted'>Phase-12 snapshot "
                                "unavailable.</p>", nav)
    peer_total = sum(int(n) for n in snap["peers"].values())
    peer_active = int(snap["peers"].get("active", 0))
    peer_bad = (int(snap["peers"].get("expired", 0)) +
                int(snap["peers"].get("suspended", 0)))
    pol_total = sum(int(n) for n in snap["policies"].values())
    imp_rejected = int(snap["imports"].get("rejected", 0)) + \
        int(snap["imports"].get("failed", 0))
    bulk_total = sum(int(n) for n in snap["bulk_jobs"].values())
    bulk_bad = int(snap["bulk_jobs"].get("failed", 0)) + \
        int(snap["bulk_jobs"].get("dead_letter", 0))
    integ_total = sum(int(n) for n in snap["integrations"].values())
    cards = [
        f"<div class='card'><div class='big'>{peer_total}</div>"
        f"<div class='small'>federation peers ({peer_active} active)</div>"
        f"</div>",
        f"<div class='card'><div class='big'"
        f" style='color:{'#c62828' if peer_bad else '#2e7d32'}'>"
        f"{peer_bad}</div><div class='small'>peers expired or suspended"
        f"</div></div>",
        f"<div class='card'><div class='big'>{pol_total}</div>"
        f"<div class='small'>exchange policies</div></div>",
        f"<div class='card'><div class='big'>{snap['packages']}</div>"
        f"<div class='small'>packages built ({snap['package_objects']} "
        f"objects)</div></div>",
        f"<div class='card'><div class='big'"
        f" style='color:{'#c62828' if imp_rejected else '#2e7d32'}'>"
        f"{imp_rejected}</div><div class='small'>imports rejected or "
        f"failed (fail closed)</div></div>",
        f"<div class='card'><div class='big'>{snap['imported_objects']}</div>"
        f"<div class='small'>objects imported</div></div>",
        f"<div class='card'><div class='big'"
        f" style='color:{'#c62828' if bulk_bad else '#2e7d32'}'>"
        f"{bulk_total}</div><div class='small'>bulk jobs ({bulk_bad} "
        f"failed/dead-letter)</div></div>",
        f"<div class='card'><div class='big'>{integ_total}</div>"
        f"<div class='small'>external integrations</div></div>"]

    def _dist_rows(dist):
        return "".join(
            f"<tr><td><b>{esc(k)}</b></td><td>{int(v)}</td></tr>"
            for k, v in sorted(dist.items())) or \
            "<tr><td class='muted'>none</td><td>0</td></tr>"

    rej_rows = "".join(
        f"<tr><td>{esc(r['created_at'])}</td><td>{esc(r['error'])}</td></tr>"
        for r in snap["rejected_recent"][:20]) or \
        "<tr><td class='muted' colspan='2'>no rejected imports</td></tr>"
    ev_dist = _dist_rows(snap["integration_events"])
    recent_rows = "".join(
        f"<tr><td>{esc(r['ts'])}</td><td>{esc(r['action'])}</td>"
        f"<td>{esc(r['actor'])}</td></tr>" for r in snap["recent"][:20])
    body = f"""
    <h2>Data federation · evidence exchange · bulk operations ·
    external integrations</h2>
    <div class='cards'>{''.join(cards)}</div>
    <h3>Peers by status</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>
    {_dist_rows(snap['peers'])}</table>
    <h3>Policies by status</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>
    {_dist_rows(snap['policies'])}</table>
    <h3>Imports by status</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>
    {_dist_rows(snap['imports'])}</table>
    <h3>Recent rejected imports</h3>
    <table class='tbl'><tr><th>When</th><th>Reason</th></tr>{rej_rows}</table>
    <h3>Bulk jobs by status</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>
    {_dist_rows(snap['bulk_jobs'])}</table>
    <h3>Integrations by status</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>
    {_dist_rows(snap['integrations'])}</table>
    <h3>Integration events by status</h3>
    <table class='tbl'><tr><th>Status</th><th>Count</th></tr>{ev_dist}</table>
    <h3>Recent federation activity</h3>
    <table class='tbl'><tr><th>Timestamp</th><th>Action</th><th>Actor</th>
    </tr>{recent_rows}</table>
    <p class='muted'>Read-only panel. Package payloads, envelope contents,
    webhook bodies and secret material are never rendered (hashes and byte
    sizes only). Trust is explicit per grant — this panel is not a claim of
    external certification. Generated {esc(snap['generated_at'])}.</p>
    """
    return page("Phase 12", body, nav)



def _pf_service(db_path):
    """Cached PlatformService handle for live detail lookups (read-only)."""
    key = str(db_path)
    if key not in _PF_CACHE:
        import platform_service as _pf
        _PF_CACHE[key] = _pf.PlatformService(db_path)
    return _PF_CACHE[key]


def esc(s) -> str:
    """HTML-escape a string for safe embedding in page markup."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def sev_chip(sev: str) -> str:
    color = SEV_COLORS.get(sev, "#888")
    return f"<span class='chip' style='background:{color}'>{esc(sev)}</span>"


def page(title: str, body: str, nav: str = "") -> str:
    d = time.strftime("%Y-%m-%d %H:%M")
    return HTML_HEAD + f"<header><div class='logo'>Secu<span>Pulse</span></div>" \
        f"<div class='sub'>security findings portal · v{VERSION}</div>" \
        f"<div class='sp'></div><div class='nav'>{nav}</div></header>" \
        + body + HTML_FOOT % d + JS_HELPERS


def jobs_page(jobs, stages_index):
    """Phase 3 ops panel: persistent job queue + stage checkpoints.
    `jobs` are pre-redacted, org-filtered dicts (no cross-tenant leak:
    run one dashboard per org via --jobs-org in multi-tenant mode)."""
    if not jobs:
        body = ("<div class='card'><h3>Scan jobs</h3>"
                "<p class='mut'>No jobs — start a worker with "
                "<code>scan-worker run</code> and queue work with "
                "<code>scan-job create</code> (or "
                "<code>platform scan-create --target …</code>).</p></div>")
        return page("Scan jobs", body,
                    "<a href='/'>← Overview</a><a class='on' href='#'>Jobs</a>")
    colors = {"completed": "#3ddc97", "failed": "#ff3b5c",
              "cancelled": "#ffd23d", "dead_letter": "#ff3b5c",
              "running": "#4da3ff", "queued": "#8a93a6",
              "paused": "#ffd23d", "retry_wait": "#ff8a3d",
              "cancelling": "#ffd23d", "created": "#8a93a6"}
    rows = []
    for j in jobs:
        status = j["status"]
        color = colors.get(status, "#8a93a6")
        stages = stages_index.get(j["scan_id"], [])
        st_parts = []
        for s in stages:
            scolor = colors.get(s["status"], "#8a93a6") if \
                s["status"] != "completed" else "#3ddc97"
            err = (" (" + esc(s["error_code"]) + ")") if s["error_code"] else ""
            st_parts.append(
                "<span class='chip' style='background:" + scolor + "'>" +
                esc(s["stage"]) + " " + esc(s["status"]) + err + "</span>")
        stages_html = " ".join(st_parts) or "<span class='mut'>no stages yet</span>"
        rows.append(f"""<tr>
<td class="mono">{esc(j['id'][:18])}…</td>
<td>{esc(j['profile'])}</td>
<td><span class="chip" style="background:{color}">{esc(status)}</span><br>
 <span class="small mut">attempt {j['attempt']}/{j['max_attempts']} ·
 prio {j['priority']}</span></td>
<td class="mono">{j.get('worker') or '—'}</td>
<td>{stages_html}</td>
<td class="mono">{esc(j.get('error_code') or '')}</td>
<td class="mono small">{esc((j.get('started_at') or j.get('created_at') or '')[:19])}</td>
</tr>""")
    body = f"""<h2 style='margin-top:0'>Scan jobs <span class='small mut'>— phase 3 queue</span></h2>
<div class='card'>
<table><tr><th>Job</th><th>Profile</th><th>Status</th><th>Worker</th>
<th>Stages</th><th>Error</th><th>Started</th></tr>{''.join(rows)}</table>
</div>"""
    return page("Scan jobs", body,
                "<a href='/'>← Overview</a><a class='on' href='#'>Jobs</a>")


def scan_row(sc, tenant_url=""):
    t = sc["target"]
    sev = sc["summary"] or {}
    return f"""<tr>
<td class="mono">{esc(sc['date'][:10])}</td>
<td><a href="{tenant_url}/s/{esc(sc['id'])}"><b>{esc(sc['tool'])}</b></a><br>
<span class="small mut">{esc(t[:60])}</span></td>
<td>{' '.join(f"<span class='chip' style='background:{SEV_COLORS.get(k)}'>{v} {esc(k)}</span>"
             for k, v in sev.items()) or '<span class="small mut">—</span>'}</td>
<td class="mono">{sc['score']}/100 <b>{esc(sc['grade'])}</b></td></tr>"""


# ---------------------------------------------------------------------------
# Phase-5 monitoring panel (server-rendered, read-only, redacted snapshot)
# ---------------------------------------------------------------------------
def _sched_desc(p: dict) -> str:
    if p.get("schedule_type") == "interval":
        return f"interval {int(p.get('interval_minutes') or 0)}m"
    return str(p.get("schedule_type") or "manual")


def _rows(items, rowfn, fallback, limit=100):
    """Join rendered rows, or the fallback row when empty (no lost tags)."""
    out = "".join(rowfn(i) for i in items[:int(limit)])
    return out if out else fallback


def monitoring_page(snap) -> str:
    """Render the Phase-5 Monitoring section from the read-only snapshot.
    `snap` is the redacted dict produced by load_monitor_snapshot (or None
    when no platform DB is configured)."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a class='on' href='/monitoring'>Monitoring</a>"
           "<a href='/reports'>Reports</a><a href='/phase9'>Phase 9</a><a href='/api/scans'>API</a>")
    if not snap:
        return page("Monitoring",
                    "<div class='card'>No monitoring database configured — "
                    "start the dashboard with <code>--intel-db &lt;platform.db&gt;"
                    "</code> (and <code>--intel-org</code> for tenant "
                    "filtering).</div>", nav)
    policies = snap.get("policies") or []
    executions = snap.get("executions") or []
    events = snap.get("events") or []
    alerts = snap.get("alerts") or []
    tickets = snap.get("tickets") or []
    health = snap.get("health") or []
    projects = snap.get("projects") or []

    def card(small, big, extra=""):
        return (f"<div class='card'><div class='small mut'>{esc(small)}</div>"
                f"<div class='big'>{int(big)}</div>{extra}</div>")
    nhealth = sum(1 for h in health if h.get("health") not in
                  ("healthy", "disabled"))
    cards = (card("Projects", len(projects)) +
             card("Policies", len(policies)) +
             card("Scheduled runs", len(executions)) +
             card("Security changes", len(events)) +
             card("Alerts", len(alerts)) +
             card("Open tickets", len(tickets)) +
             card("Projects not healthy", nhealth,
                  "<div class='small'><a href='#health'>details ↓</a></div>"))
    health_rows = _rows(health, lambda h: (
        f"<tr><td class='mono'>{esc(h.get('project_id', '')[:8])}</td>"
        f"<td><span class='badge {esc(h.get('health', ''))}'>"
        f"{esc(h.get('health', ''))}</span></td>"
        f"<td>{round(float(h.get('score') or 0), 1)}</td>"
        f"<td class='mono mut'>{esc(h.get('last_success') or '—')}</td>"
        f"<td>{int(h.get('consecutive_failures') or 0)}</td>"
        f"<td class='mono mut'>{esc(h.get('next_expected_run') or '—')}"
        f"</td></tr>"), "<tr><td colspan=6 class='mut'>No health data "
                        "yet.</td></tr>", 50)
    policy_rows = _rows(policies, lambda p: (
        f"<tr><td>{esc(p.get('name', ''))}</td>"
        f"<td>{esc(p.get('scan_profile', ''))}</td>"
        f"<td>{esc(_sched_desc(p))}</td>"
        f"<td><span class='badge {'ok' if p.get('enabled') else 'muted'}'>"
        f"{'ON' if p.get('enabled') else 'OFF'}</span></td>"
        f"<td class='mono mut'>{esc(p.get('next_run') or '—')}</td></tr>"),
        "<tr><td colspan=5 class='mut'>No policies yet.</td></tr>")
    exec_rows = _rows(executions, lambda e: (
        f"<tr><td class='mono mut'>{esc(e.get('scheduled_window', ''))}</td>"
        f"<td>{esc(e.get('status', ''))}</td>"
        f"<td class='mono mut'>{esc(e.get('scan_id', '')[:12]) or '—'}"
        f"</td></tr>"), "<tr><td colspan=3 class='mut'>No scheduled runs "
                        "yet.</td></tr>")
    event_rows = _rows(events, lambda e: (
        f"<tr><td class='mono mut'>{esc(e.get('ts', '')[:16])}</td>"
        f"<td>{esc(e.get('event_type', ''))}</td>"
        f"<td class='mono mut'>{esc(e.get('asset_id', '')[:14]) or '—'}</td>"
        f"<td>{round(float(e.get('confidence') or 0), 2)}</td></tr>"),
        "<tr><td colspan=4 class='mut'>No security changes yet.</td></tr>")
    alert_rows = _rows(alerts, lambda a: (
        f"<tr><td><span class='badge {esc(a.get('state', ''))}'>"
        f"{esc(a.get('state', ''))}</span></td>"
        f"<td>{sev_chip(a.get('severity', ''))}</td>"
        f"<td>{esc(a.get('title', '')[:80])}</td>"
        f"<td>{int(a.get('occurrence_count') or 0)}</td>"
        f"<td class='mono mut'>{esc(a.get('last_seen', '')[:16])}</td></tr>"),
        "<tr><td colspan=5 class='mut'>No alerts yet.</td></tr>")
    ticket_rows = _rows(tickets, lambda t: (
        f"<tr><td>{esc(t.get('priority', ''))}</td>"
        f"<td>{esc(t.get('status', ''))}</td>"
        f"<td>{esc(t.get('verification_status') or '—')}</td>"
        f"<td class='mono mut'>{esc(t.get('due_at') or '—')}</td>"
        f"<td>{int(t.get('verification_attempts') or 0)}</td></tr>"),
        "<tr><td colspan=5 class='mut'>No tickets yet.</td></tr>")
    body = (
        f"<div class='grid g4'>{cards}</div>"
        f"<div class='grid g2' style='margin-top:14px'>"
        f"<div class='card'><h3>Policies</h3><table>"
        f"<tr><th>Name</th><th>Profile</th><th>Schedule</th><th>State</th>"
        f"<th>Next run</th></tr>{policy_rows}</table></div>"
        f"<div class='card'><h3>Scheduled scans</h3><table>"
        f"<tr><th>Window</th><th>Status</th><th>Scan</th></tr>{exec_rows}"
        f"</table></div></div>"
        f"<div class='grid g2' style='margin-top:14px'>"
        f"<div class='card'><h3>Security changes</h3><table>"
        f"<tr><th>Ts</th><th>Event</th><th>Asset</th><th>Conf.</th></tr>"
        f"{event_rows}</table></div>"
        f"<div class='card'><h3 id='health'>Health</h3><table>"
        f"<tr><th>Project</th><th>State</th><th>Score</th><th>Last success</th>"
        f"<th>Consec. fails</th><th>Next expected</th></tr>{health_rows}"
        f"</table></div></div>"
        f"<div class='grid g2' style='margin-top:14px'>"
        f"<div class='card'><h3>Alerts</h3><table>"
        f"<tr><th>State</th><th>Sev.</th><th>Title</th><th>Occ.</th>"
        f"<th>Last seen</th></tr>{alert_rows}</table></div>"
        f"<div class='card'><h3>Remediation queue</h3><table>"
        f"<tr><th>Priority</th><th>Status</th><th>Verif.</th><th>Due</th>"
        f"<th>Attempts</th></tr>{ticket_rows}</table></div></div>"
        f"<div class='small mut' style='margin-top:12px'>Read-only "
        f"monitoring snapshot — capped at 200 rows per table, redacted."
        f"</div>")
    return page("Monitoring", body, nav)


# ---------------------------------------------------------------------------
# Phase-6 reporting / analytics panel (server-rendered, read-only, redacted)
# ---------------------------------------------------------------------------
def _sev_badge(sev: str) -> str:
    color = SEV_COLORS.get(sev, "#888888")
    return f"<span class='chip' style='background:{color}'>{esc(sev)}</span>"


def reporting_page(snap) -> str:
    """Phase-6 panel: Executive Overview, Posture, Risk Trends, Asset
    Exposure, Remediation, Monitoring, Reports, Evidence."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a href='/monitoring'>Monitoring</a>"
           "<a class='on' href='/reports'>Reports</a>"
           "<a href='/evidence'>Evidence</a><a href='/devsecops'>DevSecOps</a>"
           "<a href='/phase9'>Phase 9</a><a href='/api/scans'>API</a>")
    if not snap:
        return page("Reports",
                    "<div class='card'>No reporting database configured — "
                    "start the dashboard with <code>--intel-db "
                    "&lt;platform.db&gt;</code> (and <code>--intel-org</code> "
                    "for tenant filtering).</div>", nav)
    bundles = snap.get("analytics") or []
    reports = snap.get("reports") or []
    evidence = snap.get("evidence") or []
    body = ["<h2 style='margin-top:0'>Executive reporting "
            "<span class='small mut'>— phase 6 snapshots</span></h2>"]
    for b in bundles:
        name = esc(b.get("project_name") or b.get("project_id", "")[:12])
        posture = b.get("posture") or {}
        risk = b.get("risk") or {}
        kpi = b.get("kpis") or {}
        trends = (b.get("trends") or {}).get("findings") or {}
        rem = b.get("remediation") or {}
        mon = b.get("monitoring") or {}
        assets = b.get("assets") or {}
        # 1) executive overview
        body.append(
            "<div class='card'><h3>Executive overview — " + name + "</h3>"
            "<div class='grid g4'>"
            f"<div class='card'><div class='small mut'>POSTURE (posture-v1)"
            "</div><div class='big'>" + esc(str(posture.get("score", "-")))
            + "</div><div class='small'>" + esc(str(posture.get("level", "")))
            + "</div></div>"
            f"<div class='card'><div class='small mut'>OPEN FINDINGS</div>"
            f"<div class='big'>{int(risk.get('count', 0))}</div>"
            f"<div class='small'>crit {int((risk.get('by_severity') or {}).get('Critical', 0))}"
            f" · high {int((risk.get('by_severity') or {}).get('High', 0))}"
            "</div></div>"
            f"<div class='card'><div class='small mut'>RESOLUTION RATE</div>"
            f"<div class='big'>{round(float(kpi.get('resolution_rate', 0) or 0) * 100, 1)}%"
            "</div><div class='small'>reopen "
            f"{round(float(kpi.get('reopen_rate', 0) or 0) * 100, 1)}%</div></div>"
            f"<div class='card'><div class='small mut'>MTTR (HOURS)</div>"
            f"<div class='big'>{esc(str(kpi.get('mttr_hours', 0)))}</div>"
            f"<div class='small'>MTTD {esc(str(kpi.get('mttd_hours', 0)))}</div>"
            "</div></div></div>")
        # 2) posture factors (always documented — no hidden formula)
        factors = posture.get("factors") or []
        frows = _rows(factors,
                      lambda f: "<tr><td>" + esc(str(f.get("factor", "")))
                      + "</td><td class='mono'>" + esc(str(f.get("value", 0)))
                      + "</td><td class='mono'>"
                      + esc(str(f.get("points", 0))) + "</td><td class='mut'>"
                      + esc(str(f.get("definition", ""))[:110]) + "</td></tr>",
                      "<tr><td colspan=4 class='mut'>no posture factors</td>"
                      "</tr>")
        body.append("<div class='card'><h3>Security posture — factors "
                    "(posture-v1, deterministic)</h3><table><tr><th>Factor</th>"
                    "<th>Value</th><th>Points</th><th>Definition</th></tr>"
                    + frows + "</table></div>")
        # 3) risk trends (findings created per bucket)
        pts = (trends.get("created") or [])[-30:]
        trows = _rows(pts,
                      lambda p: "<tr><td class='mono'>" + esc(str(
                          next(iter(p)))) + "</td><td>"
                      + esc(str(next(iter(p.values())))) + "</td></tr>",
                      "<tr><td colspan=2 class='mut'>no trend window — "
                      "run analytics with a bounded range</td></tr>")
        body.append("<div class='card'><h3>Risk trend — findings created "
                    f"(bucket {esc(str(trends.get('bucket_days', '-')))}d, "
                    "bounded)</h3><table><tr><th>Bucket</th><th>Created</th>"
                    "</tr>" + trows + "</table>"
                    f"<div class='small mut'>window {esc(str(trends.get('start','')))[:10]}"
                    f" → {esc(str(trends.get('end','')))[:10]}</div></div>")
        # 4) asset exposure
        by_exp = assets.get("by_exposure") or {}
        chips = " ".join(
            f"<span class='chip' style='background:{_exp_color(k)}'>"
            f"{v} {esc(k)}</span>" for k, v in sorted(by_exp.items()))
        body.append("<div class='card'><h3>Asset exposure</h3>"
                    + (chips or "<span class='mut'>no assets</span>")
                    + f"<div class='small mut'>{int(assets.get('total', 0))} "
                    f"asset(s); {int(assets.get('internet_facing', 0))} "
                    f"internet-facing; criticality "
                    f"{esc(str((assets.get('by_criticality') or {})))[:120]}"
                    "</div></div>")
        # 5) remediation
        rows = _rows(sorted((rem.get("by_status") or {}).items()),
                     lambda kv: "<tr><td>" + esc(str(kv[0])) + "</td><td>"
                     + esc(str(kv[1])) + "</td></tr>",
                     "<tr><td colspan=2 class='mut'>no tickets</td></tr>")
        body.append("<div class='card'><h3>Remediation</h3>"
                    f"<div class='small mut'>tickets "
                    f"{int(rem.get('total', 0))} · overdue "
                    f"{int(rem.get('overdue_count', 0))} · avg age "
                    f"{esc(str(rem.get('avg_remediation_age_days', 0)))}d"
                    "</div><table><tr><th>Status</th><th>Count</th></tr>"
                    + rows + "</table></div>")
        # 6) monitoring
        health = mon.get("health") or {}
        hrows = _rows(sorted((mon.get("executions_by_status") or {}).items()),
                      lambda kv: "<tr><td>" + esc(str(kv[0])) + "</td><td>"
                      + esc(str(kv[1])) + "</td></tr>",
                      "<tr><td colspan=2 class='mut'>no executions</td></tr>")
        body.append("<div class='card'><h3>Monitoring</h3>"
                    f"<div class='small mut'>health "
                    f"{esc(str(health.get('health', '-')))} · score "
                    f"{esc(str(health.get('score', '-')))} · policies "
                    f"{int(mon.get('enabled_policies', 0))} · open alerts "
                    f"{int(mon.get('open_alerts', 0))}</div><table><tr>"
                    "<th>Status</th><th>Executions</th></tr>" + hrows +
                    "</table></div>")
    # 7) reports (recent runs)
    rrows = _rows(reports,
                  lambda r: "<tr><td class='mono'>"
                  + esc(str(r.get("id", ""))[:12]) + "…</td><td>"
                  + _sev_badge(str(r.get("report_type", "report")),
                               ) + "</td><td>" + esc(str(r.get("title", ""))[:60])
                  + "</td><td class='mono small'>"
                  + esc(str(r.get("generated_at", ""))[:19]) + "</td><td>"
                  + esc(str(r.get("generated_by", ""))[:16])
                  + "</td><td class='mono'>"
                  + esc(str(r.get("report_hash", ""))[:16]) + "</td>"
                  + ("<td class='small'>truncated</td>" if r.get("truncated")
                     else "<td class='mut small'>—</td>") + "</tr>",
                  "<tr><td colspan=7 class='mut'>no reports generated yet — "
                  "use <code>reporting generate</code></td></tr>")
    body.append("<div class='card'><h3>Reports — recent runs (bounded, "
                "redacted metadata)</h3><table><tr><th>Id</th><th>Type</th>"
                "<th>Title</th><th>Generated</th><th>By</th><th>Hash</th>"
                "<th>Limits</th></tr>" + rrows + "</table></div>")
    # 8) compliance evidence
    erows = _rows(evidence,
                  lambda e: "<tr><td>" + esc(str(e.get("control_category", "")))
                  + "</td><td>" + esc(str(e.get("status", "")))
                  + "</td><td>" + esc(str(e.get("source_type", "")))
                  + "</td><td class='mono mut'>"
                  + esc(str(e.get("source_id", ""))[:24]) + "</td><td class='mono'>"
                  + esc(str(e.get("evidence_hash", ""))[:16]) + "</td></tr>",
                  "<tr><td colspan=5 class='mut'>no evidence items — run "
                  "<code>evidence refresh</code></td></tr>")
    body.append("<div class='card'><h3>Compliance evidence — generic "
                "categories (no compliance claim)</h3><table><tr><th>Category"
                "</th><th>Status</th><th>Source</th><th>Source id</th>"
                "<th>Hash</th></tr>" + erows + "</table></div>")
    return page("Reports", "".join(body), nav)


def evidence_page(snap) -> str:
    """Focused evidence registry panel (provenance + hashes visible)."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a href='/monitoring'>Monitoring</a>"
           "<a href='/reports'>Reports</a>"
           "<a class='on' href='/evidence'>Evidence</a>"
           "<a href='/phase9'>Phase 9</a><a href='/api/scans'>API</a>")
    if not snap:
        return page("Evidence",
                    "<div class='card'>No reporting database configured — "
                    "start the dashboard with <code>--intel-db</code>.</div>",
                    nav)
    evidence = snap.get("evidence") or []
    erows = _rows(evidence,
                  lambda e: "<tr><td>" + esc(str(e.get("control_category", "")))
                  + "</td><td>" + esc(str(e.get("status", "")))
                  + "</td><td>" + esc(str(e.get("source_type", "")))
                  + "</td><td class='mono'>"
                  + esc(str(e.get("source_id", ""))[:32]) + "</td><td class='mono'>"
                  + esc(str(e.get("evidence_hash", ""))[:24]) + "</td><td class='mut'>"
                  + esc(str(e.get("description", ""))[:110]) + "</td></tr>",
                  "<tr><td colspan=6 class='mut'>no evidence items — run "
                  "<code>evidence refresh</code></td></tr>")
    return page("Evidence", "<h2 style='margin-top:0'>Compliance evidence "
                "<span class='small mut'>— generic controls, provenance kept, "
                "no compliance claim</span></h2><div class='card'><table>"
                "<tr><th>Category</th><th>Status</th><th>Source</th>"
                "<th>Source id</th><th>Evidence hash</th><th>Description</th>"
                "</tr>" + erows + "</table>"
                "<div class='small mut'>Snapshots are immutable; the "
                "registry only reflects the current derivation.</div>"
                "</div>", nav)


def _exp_color(k: str) -> str:
    return {"internet_facing": "#ff3b5c", "internal": "#4da3ff",
            "restricted": "#3ddc97", "unknown": "#7d8590"}.get(k, "#888888")


def render_overview(scans, tenants, root):
    tot = {}
    for sc in scans:
        for k, v in sc["summary"].items():
            tot[k] = tot.get(k, 0) + v
    cards = "".join(
        f"<div class='card'><div class='small mut'>{esc(t)}</div>"
        f"<div class='big'>{len(tenants[t])}</div><div class='small'>scans</div>"
        f"<div style='margin-top:10px'><a class='btn ghost' href='/t/{esc(t)}'>Open →</a></div></div>"
        for t in sorted(tenants))
    recent = "".join(scan_row(sc, f"/t/{esc(sc['tenant'])}") for sc in scans[:12]) or \
        "<tr><td colspan=4 class='mut'>No results yet — run any scanner with `--out results/&lt;client&gt;/scan.json`</td></tr>"
    segs = ','.join(f"{{k:'{esc(k)}',v:{v}}}" for k, v in tot.items())
    body = f"""
<div class='grid g4'>{cards}</div>
<div class='grid g3' style='margin-top:14px'>
  <div class='card'><h3>Severity — all clients</h3>
    <div class='gauge'><div id='pit'></div><div>
      {'<br>'.join(f"<span class='chip' style='background:{SEV_COLORS.get(k)}'>{v} {esc(k)}</span>"
                   for k, v in tot.items()) or '<span class="mut">no findings</span>'}
    </div></div></div>
  <div class='card' style='grid-column:span 2'><h3>Recent scans</h3>
    <table><tr><th>Date</th><th>Scan</th><th>Findings</th><th>Score</th></tr>{recent}</table></div>
</div>
<script>const segs=[{segs}];document.getElementById('pit').innerHTML=donut(segs,190);</script>"""
    return page("Overview", body,
                "<a class='on' href='/'>Overview</a><a href='/jobs'>Jobs</a>"
                "<a href='/monitoring'>Monitoring</a>"
                "<a href='/reports'>Reports</a><a href='/phase9'>Phase 9</a><a href='/api/scans'>API</a>")


def render_tenant(t, scans, tenants, root):
    tscans = [s for s in scans if s["tenant"] == t]
    tot = {}
    for sc in tscans:
        for k, v in sc["summary"].items():
            tot[k] = tot.get(k, 0) + v
    rows = "".join(scan_row(sc, f"/t/{esc(t)}") for sc in tscans) or \
        "<tr><td colspan=4 class='mut'>No scans for this client yet.</td></tr>"
    segs = ','.join(f"{{k:'{esc(k)}',v:{v}}}" for k, v in tot.items())
    body = f"""
<h2 style='margin-top:0'>Client workspace: <span style='color:var(--acc2)'>{esc(t)}</span></h2>
<div class='grid g4'>
  <div class='card'><div class='small'>Scans</div><div class='big'>{len(tscans)}</div></div>
  <div class='card'><div class='small'>Total findings</div><div class='big'>{sum(tot.values())}</div></div>
  <div class='card'><div class='small'>Critical</div><div class='big' style='color:{SEV_COLORS['Critical']}'>{tot.get('Critical',0)}</div></div>
  <div class='card'><div class='small'>High</div><div class='big' style='color:{SEV_COLORS['High']}'>{tot.get('High',0)}</div></div>
</div>
<div class='grid g3' style='margin-top:14px'>
  <div class='card'><h3>Severity</h3><div id='pit'></div></div>
  <div class='card' style='grid-column:span 2'><h3>Scans</h3>
    <table><tr><th>Date</th><th>Scan</th><th>Findings</th><th>Score</th></tr>{rows}</table></div>
</div>
<script>const segs=[{segs}];document.getElementById('pit').innerHTML=donut(segs,180);</script>"""
    return page(f"Client {t}", body, f"<a href='/'>← Overview</a><a class='on' href='#'>{esc(t)}</a>")


def render_scan(t, sc, root):
    statuses = load_status(root)
    score_color = "#3ddc97" if sc["score"] >= 80 else \
        "#ffd23d" if sc["score"] >= 60 else "#ff3b5c"
    rows = []
    for i, f in enumerate(sc["findings"]):
        key = f"{t}/{sc['id']}/{f['id']}"
        st = statuses.get(key, {}).get("status", "open")
        note = statuses.get(key, {}).get("note", "")
        opts = "".join(f"<option value='{s}' {'selected' if s == st else ''}>{s}</option>"
                       for s in STATUSES)
        rows.append(f"""
<details class='find'><summary>
  {sev_chip(f['severity'])}<span class='t'>{esc(f['title'])}</span>
  <span class='mono mut'>{esc(f['id'])}</span>
  <span class='badge {esc(st)}' id='b-{i}'>{esc(st)}</span></summary>
 <div class='body'>
  <div class='small mut'>EVIDENCE</div><div class='ev'>{esc(f['evidence'])}</div>
  <div class='small mut'>REMEDIATION</div><div class='ev'>{esc(f['remediation'])}</div>
  <div class='toolbar'>
    <select id='st-{i}' onchange="setSt({i})">{opts}</select>
    <input id='nt-{i}' placeholder='note (optional)' value='{esc(note)}'>
    <button class='btn ghost' onclick="setSt({i})">Save status</button>
    <button class='btn ghost' onclick="window.print()">🖨 Print</button>
  </div></div></details>""")
    if not rows:
        rows = ["<div class='card'>No findings recorded for this scan.</div>"]
    sev = sc["summary"] or {}
    sevsel = "".join(f"<option value='{esc(k)}'>{esc(k)} ({v})</option>"
                     for k, v in sev.items())
    body = f"""
<a href="/t/{esc(t)}">← {esc(t)}</a>
<div class='card' style='margin-top:10px;display:flex;gap:22px;flex-wrap:wrap;align-items:center'>
  <div><div class='small mut'>SCAN</div><div class='big'>{esc(sc['tool'])}</div></div>
  <div><div class='small mut'>TARGET</div><div class='mono'>{esc(sc['target'])}</div></div>
  <div><div class='small mut'>DATE</div><div>{esc(sc['date'])}</div></div>
  <div><div class='small mut'>SCORE</div><div class='big' style='color:{score_color}'>{sc['score']}/100 <span style='font-size:16px'>({esc(sc['grade'])})</span></div></div>
  <div style='margin-left:auto'><a class='btn ghost' href="/export/{esc(t)}/{esc(sc['id'])}">⬇ JSON</a></div>
</div>
<div class='toolbar'>
  <input id='q' placeholder='🔍 search title / evidence…' style='min-width:260px'>
  <select id='fs'><option value=''>all severities</option>{sevsel}</select>
  <span class='small mut' id='cnt'></span></div>
{''.join(rows)}
<script>
const raw={json.dumps([{"id":f["id"],"sev":f["severity"],"title":f["title"],"ev":f["evidence"],"key":f"{t}/{sc['id']}/{f['id']}"} for f in sc["findings"]], ensure_ascii=False).replace("<", "\\u003c")};
const els=[...document.querySelectorAll('details.find')];
function apply(){{const q=document.getElementById('q').value.toLowerCase();
 const fs=document.getElementById('fs').value;let n=0;
 els.forEach(el=>{{const i=els.indexOf(el);const d=raw[i];
  const ok=(!q||d.title.toLowerCase().includes(q)||d.ev.toLowerCase().includes(q))
   &&(!fs||d.sev===fs);el.style.display=ok?'':'none';if(ok)n++;}});
 document.getElementById('cnt').textContent=n+' / '+raw.length+' findings';}}
document.getElementById('q').addEventListener('input',apply);
document.getElementById('fs').addEventListener('input',apply);apply();
function setSt(i){{const sel=document.getElementById('st-'+i);
 const nt=document.getElementById('nt-'+i);
 fetch('/api/status?t={esc(t)}&s={esc(sc['id'])}&f='+encodeURIComponent(raw[i].id)
  +'&status='+encodeURIComponent(sel.value)+'&note='+encodeURIComponent(nt.value)
  ,{{method:'POST'}}).then(r=>{{if(!r.ok)alert('save failed');return r.json();}})
  .then(d=>{{const b=document.getElementById('b-'+i);
   b.textContent=d.status;b.className='badge '+d.status;}});}}
</script>"""
    return page(f"{sc['tool']} — {sc['target'][:40]}", body,
                f"<a href='/'>Overview</a><a href='/t/{esc(t)}'>{esc(t)}</a><a class='on' href='#'>Scan</a>")


# ---------------------------------------------------------------------------
# Phase-7 DevSecOps panel (server-rendered, read-only, redacted snapshot)
# ---------------------------------------------------------------------------
def load_devsecops_snapshot(db_path, org_filter="", *,
                            max_gates=100, max_runs=60, max_results=60):
    """Read-only DevSecOps snapshot: gates, latest CI runs, gate results,
    pass/fail/inconclusive counts, regressions, top failing projects.
    Bounded + redacted; never crosses tenants. `db_path` empty -> None."""
    if not db_path:
        return None
    try:
        import devsecops as _ds
        import platform_service as _pf
        svc = _ds.DevSecOpsService(_pf.PlatformService(db_path))
        return svc.snapshot(org_filter, max_gates=max_gates,
                            max_runs=max_runs, max_results=max_results)
    except Exception:
        return None


def load_identity_snapshot(db_path, org_filter="", *, max_rows=100):
    """Phase-8 identity snapshot — READ ONLY, org-filtered, redacted.
    Never exposes TOTP seeds, recovery codes, session secrets, SCIM
    verifiers/secrets, or provider client secrets (the SCIM credential
    key_prefix is the same redacted metadata the CLI's read-only view
    already shows). `db_path` empty -> None (panel hidden)."""
    if not db_path:
        return None
    try:
        import store as _store
        import mfa_service as _mfs
        svc = _pf_service(db_path)
        orgs = []
        if org_filter:
            rows = svc.db.query(
                "SELECT id, name FROM organizations WHERE id=? LIMIT 1",
                (org_filter,))
            if rows:
                orgs = [{"id": rows[0]["id"], "name": rows[0]["name"]}]
        else:
            orgs = [dict(r) for r in svc.db.query(
                "SELECT id, name FROM organizations ORDER BY name LIMIT 50")]
        if not orgs:
            return {"configured": True, "empty": True, "org": org_filter,
                    "orgs": []}
        org_ids = [o["id"] for o in orgs]
        ph = ",".join("?" for _ in org_ids)

        def q(sql, extra=(), limit=max_rows):
            sql = sql.replace("{}", ph)
            if "LIMIT" not in sql.upper():
                sql = sql + " LIMIT %d" % int(limit)
            return [dict(r) for r in svc.db.query(
                sql, tuple(org_ids) + tuple(extra))]

        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        policy = {}
        for r in q("SELECT org_id, mode, roles, step_up_ttl, "
                   "require_recent, version, updated_at FROM mfa_policy "
                   "WHERE org_id IN ({})"):
            try:
                roles = _store.loads(r["roles"] or "[]")
            except Exception:
                roles = []
            policy[r["org_id"]] = {"mode": r["mode"],
                                   "roles": list(roles or []),
                                   "step_up_ttl": int(r["step_up_ttl"]),
                                   "require_recent": bool(r["require_recent"]),
                                   "version": int(r["version"]),
                                   "updated_at": r["updated_at"]}
        users = [dict(r) for r in q(
            "SELECT org_id, status, COUNT(*) n FROM users WHERE org_id IN "
            "({}) GROUP BY org_id, status ORDER BY status")]
        mfa_enrolled = {}
        for r in q("SELECT u.org_id org_id, COUNT(*) n FROM mfa_secrets s "
                   "JOIN users u ON u.id=s.user_id WHERE s.enabled=1 AND "
                   "u.org_id IN ({}) GROUP BY u.org_id"):
            mfa_enrolled[r["org_id"]] = int(r["n"])
        recovery = {}
        for r in q("SELECT u.org_id org_id, "
                   "SUM(CASE WHEN c.used_at='' THEN 1 ELSE 0 END) unused, "
                   "SUM(CASE WHEN c.used_at<>'' THEN 1 ELSE 0 END) used "
                   "FROM mfa_recovery_codes c JOIN users u ON u.id=c.user_id "
                   "WHERE u.org_id IN ({}) GROUP BY u.org_id"):
            recovery[r["org_id"]] = {"unused": int(r["unused"] or 0),
                                     "used": int(r["used"] or 0)}
        sessions = [dict(r) for r in q(
            "SELECT u.org_id org_id, s.mfa_status mfa_status, "
            "CASE WHEN s.revoked_at<>'' THEN 'revoked' ELSE 'active' END "
            "state, COUNT(*) n FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE u.org_id IN ({}) GROUP BY u.org_id, s.mfa_status, state "
            "ORDER BY s.mfa_status")]
        step_up_active = {}
        for r in q("SELECT u.org_id org_id, COUNT(*) n FROM sessions s "
                   "JOIN users u ON u.id=s.user_id WHERE u.org_id IN ({}) "
                   "AND s.step_up_until<>'' AND s.step_up_until>? "
                   "GROUP BY u.org_id", (now_iso,)):
            step_up_active[r["org_id"]] = int(r["n"])
        providers = []
        for r in q("SELECT id, org_id, provider_type, display_name, enabled, "
                   "jit, version, created_at, config FROM sso_providers "
                   "WHERE org_id IN ({}) ORDER BY display_name LIMIT 200",
                   limit=200):
            d = dict(r)
            try:
                cfg = _store.loads(d.pop("config") or "{}")
            except Exception:
                cfg = {}
            d["pkce"] = bool(cfg.get("pkce"))
            d["has_secret"] = bool(cfg.get("client_secret_enc"))
            d["issuer_configured"] = bool(str(cfg.get("issuer") or ""))
            providers.append(d)
        domains = [dict(r) for r in q(
            "SELECT org_id, provider_id, domain, created_at FROM "
            "sso_domains WHERE org_id IN ({}) ORDER BY domain LIMIT 500",
            limit=500)]
        mappings = [dict(r) for r in q(
            "SELECT org_id, provider_id, idp_group, role, updated_at FROM "
            "group_role_mappings WHERE org_id IN ({}) ORDER BY idp_group "
            "LIMIT 500", limit=500)]
        scim = [dict(r) for r in q(
            "SELECT id, org_id, name, key_prefix, max_role, status, "
            "created_at, last_used_at FROM scim_credentials WHERE org_id IN "
            "({}) ORDER BY name LIMIT 200", limit=200)]
        events = []
        for r in q("SELECT org_id, event_type, actor, ts, detail FROM "
                   "identity_events WHERE org_id IN ({}) ORDER BY ts DESC, "
                   "rowid DESC LIMIT 40", limit=40):
            d = dict(r)
            try:
                d["detail"] = _store.loads(d.get("detail") or "{}")
            except Exception:
                d["detail"] = {}
            events.append(d)
        return {"configured": True, "empty": False, "org": org_filter,
                "orgs": [{"id": o["id"], "name": o["name"]} for o in orgs],
                "policy": policy, "users": users, "mfa_enrolled":
                    mfa_enrolled, "recovery": recovery, "sessions": sessions,
                "step_up_active": step_up_active, "providers": providers,
                "domains": domains, "mappings": mappings, "scim": scim,
                "events": events}
    except Exception:
        return None


def identity_page(snap) -> str:
    """Phase-8 identity & access panel (read-only; never credentials)."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a href='/identity' class='on'>Identity</a>"
           "<a href='/monitoring'>Monitoring</a>"
           "<a href='/reports'>Reports</a>"
           "<a href='/devsecops'>DevSecOps</a>"
           "<a href='/phase9'>Phase 9</a><a href='/api/scans'>API</a>")
    if snap is None:
        return page("Identity", "<div class='empty'>Identity panel not "
                    "configured — start the dashboard with --identity-db "
                    "(and --identity-org for tenant filtering).</div>", nav)
    if snap.get("empty"):
        return page("Identity", "<div class='empty'>No organizations match "
                    "the identity filter.</div>", nav)
    orgs = {o["id"]: o["name"] for o in snap.get("orgs", [])}
    body = []

    def org_name(oid):
        return esc(orgs.get(oid, oid[:8]))

    for oid in orgs:
        pol = snap["policy"].get(oid)
        pol_txt = ("mode=<b>%s</b> roles=%s step-up ttl=%ss version=%s" %
                   (pol["mode"], ", ".join(pol["roles"]) or "all",
                    pol["step_up_ttl"], pol["version"])) if pol else \
            "<i>default (optional; no explicit policy row)</i>"
        body.append(
            "<div class='card'><h3>%s — MFA policy</h3>"
            "<p class='mut'>%s</p>"
            "<div class='g4 grid' style='gap:10px;margin-top:8px'>" % (
                org_name(oid), pol_txt))
        counts = {"active": 0, "suspended": 0, "deactivated": 0}
        for u in snap["users"]:
            if u["org_id"] == oid:
                counts[u["status"]] = int(u["n"])
        body.append(
            "<div class='card'><div class='big'>%d</div>"
            "<div class='small'>users</div></div>"
            "<div class='card'><div class='big'>%d</div>"
            "<div class='small'>active</div></div>"
            "<div class='card'><div class='big'>%d</div>"
            "<div class='small'>suspended</div></div>"
            "<div class='card'><div class='big'>%d</div>"
            "<div class='small'>deactivated</div></div>"
            "<div class='card'><div class='big'>%d</div>"
            "<div class='small'>MFA enabled</div></div>"
            "<div class='card'><div class='big'>%d</div>"
            "<div class='small'>recovery unused</div></div>"
            "<div class='card'><div class='big'>%d</div>"
            "<div class='small'>recovery used</div></div>"
            "<div class='card'><div class='big'>%d</div>"
            "<div class='small'>step-up active</div></div>"
            "</div></div>" % (
                sum(counts.values()), counts["active"], counts["suspended"],
                counts["deactivated"],
                int(snap["mfa_enrolled"].get(oid, 0)),
                int(snap["recovery"].get(oid, {}).get("unused", 0)),
                int(snap["recovery"].get(oid, {}).get("used", 0)),
                int(snap["step_up_active"].get(oid, 0))))
        sess = [s for s in snap["sessions"] if s["org_id"] == oid]
        s_txt = " · ".join("%s/%s=%d" % (s["state"], s["mfa_status"],
                                         int(s["n"])) for s in sess) or "none"
        body.append("<div class='card'><h3>%s — sessions</h3>"
                    "<p class='mut'>%s</p></div>" % (org_name(oid),
                                                       esc(s_txt)))
    # SSO providers / domains / mappings
    prov_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
        "<td>%s</td></tr>" % (
            esc(p["display_name"] or p["provider_type"]),
            esc(p["provider_type"]), "on" if p["enabled"] else "off",
            "on" if p["jit"] else "off", esc(str(p["version"])),
            "pkce" if p["pkce"] else ("secret" if p["has_secret"] else ""))
        for p in snap["providers"])
    dom_rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
        org_name(d["org_id"]), esc(d["domain"]), esc(str(d["provider_id"])[:12]))
        for d in snap["domains"])
    map_rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                       "</tr>" % (
                           org_name(m["org_id"]), esc(m["idp_group"]),
                           esc(m["role"]), esc(str(m["provider_id"])[:12]))
                       for m in snap["mappings"])
    scim_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
        "<td>%s</td></tr>" % (
            org_name(c["org_id"]), esc(c["name"]), esc(c["key_prefix"] + "…"),
            esc(c["max_role"]), esc(c["status"]), esc(c["last_used_at"] or "-"))
        for c in snap["scim"])
    body.append(
        "<div class='card'><h3>SSO providers</h3>"
        "<table class=''><tr><th>name</th><th>type</th><th>enabled</th>"
        "<th>jit</th><th>version</th><th>features</th></tr>%s</table>"
        "</div><div class='card'><h3>Claimed domains</h3>"
        "<table class=''><tr><th>org</th><th>domain</th><th>provider</th>"
        "</tr>%s</table></div>"
        "<div class='card'><h3>Group → role mappings</h3>"
        "<table class=''><tr><th>org</th><th>idp group</th><th>role</th>"
        "<th>provider</th></tr>%s</table></div>"
        "<div class='card'><h3>SCIM credentials (redacted)</h3>"
        "<table class=''><tr><th>org</th><th>name</th><th>prefix</th>"
        "<th>max role</th><th>status</th><th>last used</th></tr>%s</table>"
        "</div>" % (prov_rows or "<tr><td colspan='6' class='mut'>none"
                                  "</td></tr>",
                    dom_rows or "<tr><td colspan='3' class='mut'>none"
                                "</td></tr>",
                    map_rows or "<tr><td colspan='4' class='mut'>none"
                                "</td></tr>",
                    scim_rows or "<tr><td colspan='6' class='mut'>none"
                                 "</td></tr>"))
    ev_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(e["ts"]), esc(e["event_type"]), esc(e["actor"] or "-"),
            esc(str(e["detail"]))[:180]) for e in snap["events"])
    body.append(
        "<div class='card'><h3>Identity events (read-only)</h3>"
        "<table class=''><tr><th>time</th><th>event</th><th>actor</th>"
        "<th>detail</th></tr>%s</table></div>" %
        (ev_rows or "<tr><td colspan='4' class='mut'>no events</td></tr>"))
    return page("Identity", "".join(body), nav)


def devsecops_page(snap) -> str:
    """Phase-7 panel: gate status, latest CI runs, pass/fail/inconclusive
    counts, new/reopened findings, risk regressions, top failing projects,
    recent gate failures, policy summary."""
    nav = ("<a href='/'>Overview</a><a href='/jobs'>Jobs</a>"
           "<a href='/monitoring'>Monitoring</a><a href='/reports'>Reports</a>"
           "<a class='on' href='/devsecops'>DevSecOps</a>"
           "<a href='/phase9'>Phase 9</a><a href='/api/scans'>API</a>")
    if not snap:
        return page("DevSecOps",
                    "<div class='card'>No platform database configured — "
                    "start the dashboard with <code>--intel-db "
                    "&lt;platform.db&gt;</code> (and <code>--intel-org</code> "
                    "for tenant filtering).</div>", nav)
    by_status = snap.get("by_status") or {}
    cols = {"pass": "#3ddc97", "fail": "#ff3b5c", "warn": "#ffd23d",
            "inconclusive": "#8a93a6"}

    def stat(label, value, color="#"):
        return (f"<div class='card'><div class='small mut'>{esc(label)}</div>"
                f"<div class='big' style='color:{color}'>{esc(str(value))}"
                f"</div></div>")
    cards = (stat("GATES", int(snap.get("counts", {}).get("gates", 0))) +
             stat("CI RUNS", int(snap.get("counts", {}).get("runs", 0))) +
             stat("RESULTS", int(snap.get("counts", {}).get("results", 0))) +
             stat("PASS", int(by_status.get("pass", 0)), "#3ddc97") +
             stat("FAIL", int(by_status.get("fail", 0)), "#ff3b5c") +
             stat("WARN", int(by_status.get("warn", 0)), "#ffd23d") +
             stat("INCONCLUSIVE", int(by_status.get("inconclusive", 0)),
                  "#8a93a6") +
             stat("NEW FINDINGS", int(snap.get("new_findings_total", 0))) +
             stat("REOPENED", int(snap.get("reopened_findings_total", 0))) +
             stat("RISK REGRESSIONS", int(snap.get("risk_regressions", 0))))
    gates = snap.get("gates") or []
    g_rows = _rows(
        gates,
        lambda g: "<tr><td class='mono'>" + esc(str(g.get("id"))[:18])
        + "…</td><td>" + esc(str(g.get("name"))[:40]) + "</td><td><span "
        "class='chip' style='background:" + ("#3ddc97" if g.get("enabled")
        else "#8a93a6") + "'>" + ("enabled" if g.get("enabled") else
        "disabled") + "</span></td><td class='mono'>v"
        + esc(str(g.get("policy_version"))) + "</td><td class='mono'>"
        + esc(str(g.get("policy_hash"))[:16]) + "</td><td class='mono small'>"
        + esc(str(g.get("created_at") or "")[:19]) + "</td></tr>",
        "<tr><td colspan=6 class='mut'>no security gates</td></tr>")
    runs = snap.get("runs") or []
    r_rows = _rows(
        runs,
        lambda r: "<tr><td class='mono'>" + esc(str(r.get("id"))[:18])
        + "…</td><td>" + esc(str(r.get("provider"))) + "</td><td>"
        + esc(str(r.get("branch") or r.get("commit_sha") or "—"))[:28]
        + "</td><td>" + esc(str(r.get("profile"))) + "</td><td><span class='chip' "
        "style='background:#4da3ff'>" + esc(str(r.get("status")))
        + "</span></td><td class='mono small'>"
        + esc(str(r.get("created_at") or "")[:19]) + "</td></tr>",
        "<tr><td colspan=6 class='mut'>no CI runs yet</td></tr>")
    results = snap.get("results") or []
    x_rows = _rows(
        list(results)[:20],
        lambda x: "<tr><td class='mono'>" + esc(str(x.get("id"))[:18])
        + "…</td><td><span class='chip' style='background:"
        + cols.get(x.get("status"), "#8a93a6") + "'>"
        + esc(str(x.get("status"))) + "</span></td><td class='mut'>"
        + esc(str(x.get("reason"))[:40]) + "</td><td class='mono'>v"
        + esc(str(x.get("policy_version"))) + "</td><td class='mono'>"
        + esc(str(x.get("result_hash"))[:16]) + "</td><td class='mono small'>"
        + esc(str(x.get("created_at") or "")[:19]) + "</td></tr>",
        "<tr><td colspan=6 class='mut'>no gate results yet</td></tr>")
    fails = snap.get("recent_failures") or []
    f_rows = _rows(
        list(fails)[:10],
        lambda x: "<tr><td class='mono'>" + esc(str(x.get("project_id"))[:16])
        + "…</td><td class='mono'>" + esc(str(x.get("run_id"))[:16])
        + "…</td><td class='mut'>" + esc(str(x.get("reason"))[:60])
        + "</td><td class='mono small'>"
        + esc(str(x.get("created_at") or "")[:19]) + "</td></tr>",
        "<tr><td colspan=4 class='mut'>no recent gate failures</td></tr>")
    top = snap.get("top_failing") or []
    t_rows = _rows(
        top,
        lambda t: "<tr><td class='mono'>" + esc(str(t.get("project_id"))[:20])
        + "…</td><td class='mono'>" + esc(str(t.get("fails"))) + "</td></tr>",
        "<tr><td colspan=2 class='mut'>no failing projects</td></tr>")
    ps = snap.get("policy_summary") or []
    p_rows = _rows(
        ps,
        lambda p: "<tr><td class='mono'>" + esc(str(p.get("policy_hash")))
        + "</td><td class='mono'>v" + esc(str(p.get("version")))
        + "</td><td class='mono'>" + esc(str(p.get("count"))) + "</td></tr>",
        "<tr><td colspan=3 class='mut'>no policies</td></tr>")
    body = (
        "<h2 style='margin-top:0'>DevSecOps <span class='small mut'>— "
        "phase 7 security gates &amp; CI runs</span></h2>"
        "<div class='grid g5'>" + cards + "</div>"
        "<div class='card'><h3>Security gates</h3><table><tr><th>Gate</th>"
        "<th>Name</th><th>State</th><th>Policy</th><th>Hash</th>"
        "<th>Created</th></tr>" + g_rows + "</table></div>"
        "<div class='card'><h3>Latest CI runs (bounded)</h3><table>"
        "<tr><th>Run</th><th>Provider</th><th>Ref</th><th>Profile</th>"
        "<th>Status</th><th>Created</th></tr>" + r_rows + "</table></div>"
        "<div class='card'><h3>Gate results (recent, bounded)</h3><table>"
        "<tr><th>Result</th><th>Status</th><th>Reason</th><th>Policy</th>"
        "<th>Hash</th><th>Created</th></tr>" + x_rows + "</table></div>"
        "<div class='card'><h3>Recent gate failures</h3><table>"
        "<tr><th>Project</th><th>Run</th><th>Reason</th><th>When</th></tr>"
        + f_rows + "</table></div>"
        "<div class='card'><h3>Top failing projects</h3><table>"
        "<tr><th>Project</th><th>Fails</th></tr>" + t_rows + "</table></div>"
        "<div class='card'><h3>Policy summary</h3><table><tr><th>Hash</th>"
        "<th>Version</th><th>Gates</th></tr>" + p_rows + "</table></div>")
    return page("DevSecOps", body, nav)


# ---------------------------------------------------------------------------
# HTTP server
def check_access(
    token: str,
    header_t: str,
    cookie_t: str,
    query_t: str = "",
    *,
    allow_legacy_query: bool = False,
) -> bool:
    """Constant-time token comparison across accepted transports.

    Preferred transport: ``Authorization: Bearer <token>``. The historical
    ``sess=`` cookie remains available to the local HTML frontend. Query-string
    credentials are rejected unless the explicit, temporary compatibility
    switch is enabled because URLs can leak through logs, history, and referrers.
    """
    expect = str(token or "")
    if not expect:
        return True
    transports = (str(header_t or ""), str(cookie_t or ""))
    if allow_legacy_query:
        transports += (str(query_t or ""),)
    for got in transports:
        if got and len(got) <= MAX_DASHBOARD_TOKEN_LENGTH and hmac.compare_digest(got, expect):
            return True
    return False


def safe_request_id(value: str = "") -> str:
    """Return a bounded correlation ID, replacing untrusted values."""
    candidate = str(value or "")[:96]
    return candidate if REQUEST_ID_RE.fullmatch(candidate) else uuid.uuid4().hex


def safe_stored_error(value) -> str:
    """Expose only whether a persisted operation failed, never its raw detail."""
    return "operation_failed" if value else ""


def safe_request_line(path: str) -> str:
    """Request path for logs with the query string stripped — a legacy
    `?t=SECRET` token must never reach the log stream."""
    return str(path or "").split("?", 1)[0]


# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    root = "."
    scans = []
    tenants = {}
    token = None
    allow_legacy_query_token = False
    jobs = []                 # phase-3 ops snapshot (redacted, org-filtered)
    job_stages = {}           # scan_id -> [stage dicts]
    jobs_org = ""             # org filter (multi-tenant deployments)
    intel_db = None           # phase-4 platform db (read-only panel)
    intel_org = ""            # org filter for the intelligence panel
    intel = None              # snapshot cache
    _intel_key = None
    monitor = None            # phase-5 monitoring snapshot cache
    monitor_org = ""          # org filter for the monitoring panel
    _monitor_key = None
    reporting = None          # phase-6 reporting/analytics snapshot cache
    _reporting_key = None
    devsecops = None          # phase-7 devsecops snapshot cache
    _devsecops_key = None
    identity = None           # phase-8 identity snapshot cache (read-only)
    identity_db = None        # platform db for the identity panel
    identity_org = ""         # org filter (one dashboard per org)
    _identity_key = None
    phase9 = None             # phase-9 cloud/container/k8s/iac snapshot
    _phase9_key = None
    phase10 = None            # phase-10 security-ops snapshot
    _phase10_key = None
    phase11 = None            # phase-11 governance snapshot
    _phase11_key = None
    phase12 = None            # phase-12 federation snapshot
    _phase12_key = None
    _lock = threading.Lock()
    _disc_cache = {"key": None, "scans": [], "tenants": {}}

    @classmethod
    def refresh_monitor(cls):
        """Reload the Phase-5 monitoring snapshot when the db changes."""
        try:
            key = (os.path.getmtime(cls.intel_db), os.path.getsize(
                cls.intel_db)) if cls.intel_db else None
            if key != cls._monitor_key or cls.monitor is None:
                cls.monitor = load_monitor_snapshot(cls.intel_db,
                                                    cls.monitor_org)
                cls._monitor_key = key
        except Exception:
            cls.monitor = None

    @classmethod
    def refresh_reporting(cls):
        """Reload the Phase-6 reporting snapshot when the db changes."""
        try:
            key = (os.path.getmtime(cls.intel_db), os.path.getsize(
                cls.intel_db)) if cls.intel_db else None
            if key != cls._reporting_key or cls.reporting is None:
                cls.reporting = load_reporting_snapshot(cls.intel_db,
                                                        cls.intel_org)
                cls._reporting_key = key
        except Exception:
            cls.reporting = None

    @classmethod
    def refresh_devsecops(cls):
        """Reload the Phase-7 DevSecOps snapshot when the db changes."""
        try:
            key = (os.path.getmtime(cls.intel_db), os.path.getsize(
                cls.intel_db)) if cls.intel_db else None
            if key != cls._devsecops_key or cls.devsecops is None:
                cls.devsecops = load_devsecops_snapshot(cls.intel_db,
                                                        cls.intel_org)
                cls._devsecops_key = key
        except Exception:
            cls.devsecops = None

    @classmethod
    def refresh_identity(cls):
        """Reload the Phase-8 identity snapshot when the db changes."""
        try:
            key = (os.path.getmtime(cls.identity_db), os.path.getsize(
                cls.identity_db)) if cls.identity_db else None
            if key != cls._identity_key or cls.identity is None:
                cls.identity = load_identity_snapshot(cls.identity_db,
                                                      cls.identity_org)
                cls._identity_key = key
        except Exception:
            cls.identity = None

    @classmethod
    def refresh_phase9(cls):
        """Reload the Phase-9 snapshot when the db changes."""
        try:
            key = (os.path.getmtime(cls.intel_db), os.path.getsize(
                cls.intel_db)) if cls.intel_db else None
            if key != cls._phase9_key or cls.phase9 is None:
                cls.phase9 = load_phase9_snapshot(cls.intel_db,
                                                  cls.intel_org)
                cls._phase9_key = key
        except Exception:
            cls.phase9 = None

    @classmethod
    def refresh_phase10(cls):
        """Reload the Phase-10 snapshot when the db changes."""
        try:
            key = (os.path.getmtime(cls.intel_db), os.path.getsize(
                cls.intel_db)) if cls.intel_db else None
            if key != cls._phase10_key or cls.phase10 is None:
                cls.phase10 = load_phase10_snapshot(cls.intel_db,
                                                    cls.intel_org)
                cls._phase10_key = key
        except Exception:
            cls.phase10 = None

    @classmethod
    def refresh_phase11(cls):
        """Reload the Phase-11 snapshot when the db changes."""
        try:
            key = (os.path.getmtime(cls.intel_db), os.path.getsize(
                cls.intel_db)) if cls.intel_db else None
            if key != cls._phase11_key or cls.phase11 is None:
                cls.phase11 = load_phase11_snapshot(cls.intel_db,
                                                    cls.intel_org)
                cls._phase11_key = key
        except Exception:
            cls.phase11 = None

    @classmethod
    def refresh_phase12(cls):
        """Reload the Phase-12 snapshot when the db changes."""
        try:
            key = (os.path.getmtime(cls.intel_db), os.path.getsize(
                cls.intel_db)) if cls.intel_db else None
            if key != cls._phase12_key or cls.phase12 is None:
                cls.phase12 = load_phase12_snapshot(cls.intel_db,
                                                    cls.intel_org)
                cls._phase12_key = key
        except Exception:
            cls.phase12 = None

    @classmethod
    def refresh_intel(cls):
        """Reload the intelligence snapshot when the db file changes."""
        try:
            key = (os.path.getmtime(cls.intel_db), os.path.getsize(
                cls.intel_db)) if cls.intel_db else None
            if key != cls._intel_key or cls.intel is None:
                cls.intel = load_intel_snapshot(cls.intel_db, cls.intel_org)
                cls._intel_key = key
        except Exception:
            cls.intel = None

    @classmethod
    def refresh(cls):
        """Re-discover result files when they change (live-updating portal)."""
        try:
            key = []
            for dirpath, _dirs, files in os.walk(cls.root):
                for fn in files:
                    if fn.endswith(".json") and not fn.startswith("."):
                        p = os.path.join(dirpath, fn)
                        try:
                            st = os.stat(p)
                            key.append((p, st.st_mtime_ns, st.st_size))
                        except OSError:
                            pass
            key = tuple(sorted(key))
            if key != cls._disc_cache["key"]:
                cls.scans, cls.tenants = discover(cls.root)
                cls._disc_cache["key"] = key
        except Exception:
            pass

    # --- auth -------------------------------------------------------------
    def _get_token_transports(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        query_t = (q["t"][0] if q.get("t") else "")
        header_t = ""
        ah = self.headers.get("Authorization", "")
        if ah.startswith("Bearer "):
            header_t = ah[len("Bearer "):].strip()
        cookie_t = ""
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("sess="):
                cookie_t = part[len("sess="):]
        try:
            cookie_t = urllib.parse.unquote(cookie_t, errors="strict")
        except (UnicodeDecodeError, ValueError):
            cookie_t = ""
        return tuple(
            value if len(value) <= MAX_DASHBOARD_TOKEN_LENGTH else ""
            for value in (header_t, cookie_t, query_t)
        )

    def authorized(self):
        if not self.token:
            return True
        header_t, cookie_t, query_t = self._get_token_transports()
        return check_access(
            self.token,
            header_t,
            cookie_t,
            query_t,
            allow_legacy_query=self.allow_legacy_query_token,
        )

    def _same_origin_request(self) -> bool:
        """CSRF guard for cookie/query-transport POSTs: when the request is
        not authenticated via a Bearer header (which browsers cannot attach
        cross-site without script access to the secret), a state-changing
        POST must carry a matching Origin/Referer."""
        origin = self.headers.get("Origin", "")
        referer = self.headers.get("Referer", "")
        base = origin or referer
        if not base:
            return False
        try:
            parsed = urllib.parse.urlparse(base)
        except Exception:
            return False
        return parsed.netloc == self.headers.get("Host", "")

    def version_string(self):
        """Avoid exposing the Python/http.server version to clients."""
        return "SecurityToolkit"

    def send_error(self, code, message=None, explain=None):
        """Emit a fixed, correlated error rather than the stdlib HTML page."""
        headers = getattr(self, "headers", {})
        try:
            supplied = headers.get("X-Request-ID", "")
        except (AttributeError, TypeError):
            supplied = ""
        self.request_id = safe_request_id(supplied)
        body = json.dumps({
            "error": "http_error",
            "request_id": self.request_id,
        }, separators=(",", ":")).encode("utf-8")
        self.send(code, body, "application/json; charset=utf-8")

    def _request_id(self):
        request_id = str(getattr(self, "request_id", "") or "")
        if not REQUEST_ID_RE.fullmatch(request_id):
            headers = getattr(self, "headers", {})
            try:
                supplied = headers.get("X-Request-ID", "")
            except (AttributeError, TypeError):
                supplied = ""
            request_id = safe_request_id(supplied)
            self.request_id = request_id
        return request_id

    def send(self, code, body: bytes, ctype="text/html; charset=utf-8", extra=None):
        request_id = self._request_id()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Request-ID", request_id)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; base-uri 'none'; object-src 'none'; "
                         "frame-ancestors 'none'; form-action 'self'; "
                         "style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                         "img-src 'data:'; connect-src 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy",
                         "camera=(), microphone=(), geolocation=(), "
                         "payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            if (
                isinstance(key, str)
                and isinstance(value, str)
                and key.lower() != "x-request-id"
                and not re.search(r"[\r\n:]", key)
                and not re.search(r"[\r\n]", value)
            ):
                self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            return

    def json_out(self, code, obj):
        payload = obj
        if isinstance(obj, dict) and "error" in obj:
            payload = dict(obj)
            payload.setdefault("request_id", self._request_id())
        self.send(code, json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        self.request_id = safe_request_id(
            self.headers.get("X-Request-ID", ""))
        Handler.refresh()
        if not self.authorized():
            if "api/" in self.path or "export/" in self.path:
                return self.json_out(401, {"error": "token required"})
            return self.send(401, ("<div class='login'><h2>SecuPulse &mdash; token required</h2>"
                                   "<input id='tk' placeholder='access token'><br><br>"
                                   "<button class='btn' onclick='setTok()'>Unlock</button>"
                                   "<script>function setTok(){const t=document.getElementById('tk').value;"
                                   "if(!t||t.length>4096)return;"
                                   "const secure=location.protocol==='https:'?';Secure':'';"
                                   "document.cookie='sess='+encodeURIComponent(t)+';Path=/;SameSite=Strict'+secure;"
                                   "location.assign(location.pathname);}</script>").encode())
        # CSRF: cookie/query-transport browser POSTs must be same-origin.
        # Bearer-header calls are exempt (a cross-site page cannot read the
        # secret to attach; it is not a cookie). Local mode (no token) is
        # unchanged — the portal is a read/report view by design.
        if (method == "POST" and self.token and not self.headers.get(
                "Authorization", "").startswith("Bearer ")):
            if not self._same_origin_request():
                return self.json_out(403, {"error": "forbidden"})
        path = urllib.parse.urlparse(self.path).path
        if path == "/favicon.ico":
            return self.send(204, b"", "image/x-icon")
        try:
            if path.startswith("/api/"):
                return self.route_api(method, path)
            if path.startswith("/export/"):
                return self.route_export(path)
            if method != "GET":
                return self.send(405, b"method not allowed")
            if path == "/":
                return self.send(200, render_overview(self.scans, self.tenants,
                                                      self.root).encode())
            if path == "/jobs":
                return self.send(200, jobs_page(self.jobs,
                                                self.job_stages).encode())
            if path == "/monitoring":
                Handler.refresh_monitor()
                return self.send(200, monitoring_page(
                    Handler.monitor).encode())
            if path == "/reports":
                Handler.refresh_reporting()
                return self.send(200, reporting_page(
                    Handler.reporting).encode())
            if path == "/evidence":
                Handler.refresh_reporting()
                return self.send(200, evidence_page(
                    Handler.reporting).encode())
            if path == "/devsecops":
                Handler.refresh_devsecops()
                return self.send(200, devsecops_page(
                    Handler.devsecops).encode())
            if path == "/identity":
                Handler.refresh_identity()
                return self.send(200, identity_page(
                    Handler.identity).encode())
            if path == "/phase9":
                Handler.refresh_phase9()
                return self.send(200, phase9_page(
                    Handler.phase9).encode())
            if path == "/phase10":
                Handler.refresh_phase10()
                return self.send(200, phase10_page(
                    Handler.phase10).encode())
            if path == "/phase11":
                Handler.refresh_phase11()
                return self.send(200, phase11_page(
                    Handler.phase11).encode())
            if path == "/phase12":
                Handler.refresh_phase12()
                return self.send(200, phase12_page(
                    Handler.phase12).encode())
            m = re.match(r"^/t/([A-Za-z0-9._-]+)$", path)
            if m:
                return self.send(200, render_tenant(m.group(1), self.scans,
                                                    self.tenants, self.root).encode())
            m = re.match(r"^/t/([A-Za-z0-9._-]+)/s/([A-Za-z0-9._-]+)$", path)
            if m:
                for sc in self.scans:
                    if sc["tenant"] == m.group(1) and sc["id"] == m.group(2):
                        return self.send(200, render_scan(m.group(1), sc,
                                                          self.root).encode())
                return self.send(404, b"scan not found")
            m = re.match(r"^/([A-Za-z0-9._-]+)/?$", path)
            if m and m.group(1) in self.tenants:
                return self.send(200, render_tenant(m.group(1), self.scans,
                                                    self.tenants, self.root).encode())
            return self.send(404, b"not found")
        except Exception as exc:
            logging.getLogger("security_toolkit.dashboard").error(
                "dashboard_request_failed",
                extra={
                    "event": "dashboard_request_failed",
                    "request_id": self.request_id,
                    "exception_type": type(exc).__name__[:80],
                },
            )
            if path.startswith("/api/") or path.startswith("/export/"):
                return self.json_out(500, {"error": "internal_error"})
            return self.send(500, b"internal error")

    # --- API --------------------------------------------------------------
    def _find(self, t, s):
        for sc in self.scans:
            if sc["tenant"] == t and sc["id"] == s:
                return sc
        return None

    def route_api(self, method, path):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if path.startswith("/api/intel") and method == "GET":
            return self.route_intel(path, q)
        if path == "/api/scans" and method == "GET":
            return self.json_out(200, {"count": len(self.scans),
                                       "scans": [{k: v for k, v in sc.items()
                                                  if k != "raw"} for sc in self.scans]})
        if path == "/api/phase9/checks" and method == "GET":
            # bounded allowlisted rule metadata (no evidence/raw/secrets)
            fams = {}
            try:
                import cloud_security as _cs
                import container_security as _ct
                import kubernetes_security as _k8
                import iac_security as _ia
                fams = {"cloud": _cs.cloud_rules_meta(),
                        "container": _ct.container_checks_meta(),
                        "kubernetes": _k8.k8s_rules_meta(),
                        "iac": _ia.iac_rules_meta()}
            except Exception:
                pass
            return self.json_out(200, {
                "families": {k: [{"rule_id": r["rule_id"],
                                  "title": r["title"],
                                  "severity": r["severity"],
                                  "category": r["category"],
                                  "version": r["version"]}
                                 for r in v] for k, v in fams.items()}})
        if path.startswith("/api/phase9/") and method == "GET":
            # §35 read-only Phase-9 API: org-filtered, redacted, bounded
            # (accounts / images / clusters / iac / findings)
            payload = load_phase9_api(Handler.intel_db, Handler.intel_org)
            sub = path.rsplit("/", 1)[-1]
            if sub == "accounts":
                return self.json_out(200, {"accounts": payload["accounts"]})
            if sub == "images":
                return self.json_out(200, {"images": payload["images"]})
            if sub == "clusters":
                return self.json_out(200, {"clusters": payload["clusters"]})
            if sub == "iac":
                return self.json_out(200, {"iac": payload["iac"]})
            if sub == "findings":
                return self.json_out(200, {"findings": payload["findings"]})
            return self.json_out(404, {"error": "unknown phase9 endpoint"})
        if path.startswith("/api/phase10") and method == "GET":
            # read-only Phase-10 API: org-filtered, redacted, bounded
            payload = load_phase10_api(Handler.intel_db, Handler.intel_org)
            sub = path[len("/api/phase10"):].lstrip("/")
            if sub == "":
                return self.json_out(200, payload)
            if sub == "iocs":
                return self.json_out(200, {"iocs": payload["iocs"]})
            if sub == "cases":
                return self.json_out(200, {"cases": payload["cases"]})
            if sub == "clusters":
                return self.json_out(200, {"clusters": payload["clusters"]})
            if sub == "findings":
                return self.json_out(200, {"findings": payload["findings"]})
            return self.json_out(404, {"error": "unknown phase10 endpoint"})
        if path.startswith("/api/phase11") and method == "GET":
            # read-only Phase-11 API: org-filtered, redacted, bounded;
            # no secret values, no search hashes, no subject references
            payload = load_phase11_api(Handler.intel_db, Handler.intel_org)
            sub = path[len("/api/phase11"):].lstrip("/")
            if sub == "":
                return self.json_out(200, payload)
            if sub == "classifications":
                return self.json_out(200, {"classifications":
                                           payload["classifications"]})
            if sub == "secrets":
                return self.json_out(200, {"registry": payload["registry"]})
            if sub == "holds":
                return self.json_out(200, {"holds": payload["holds"]})
            if sub == "privacy":
                return self.json_out(200, {"privacy": payload["privacy"]})
            if sub == "exceptions":
                return self.json_out(200, {"exceptions":
                                           payload["exceptions"]})
            if sub == "compliance":
                return self.json_out(200, {"compliance":
                                           payload["compliance"]})
            return self.json_out(404, {"error": "unknown phase11 endpoint"})
        if path.startswith("/api/phase12") and method == "GET":
            # read-only Phase-12 API: org-filtered, bounded, metadata only
            # (never package payloads, never webhook bodies)
            payload = load_phase12_api(Handler.intel_db, Handler.intel_org)
            sub = path[len("/api/phase12"):].lstrip("/")
            if sub == "":
                return self.json_out(200, payload)
            if sub in ("peers", "policies", "packages", "imports",
                       "integrations", "events"):
                return self.json_out(200, {sub: payload[sub]})
            return self.json_out(404, {"error": "unknown phase12 endpoint"})
        if path == "/api/jobs" and method == "GET":
            return self.json_out(200, {"count": len(self.jobs),
                                       "org": self.jobs_org,
                                       "jobs": self.jobs})
        if path == "/api/identity" and method == "GET":
            Handler.refresh_identity()
            return self.json_out(
                200, Handler.identity
                if Handler.identity is not None
                else {"configured": False,
                      "org": Handler.identity_org})
        m = re.match(r"^/api/tenant/([A-Za-z0-9._-]+)/scans$", path)
        if m and method == "GET":
            lst = [sc for sc in self.scans if sc["tenant"] == m.group(1)]
            return self.json_out(200, {"tenant": m.group(1), "count": len(lst),
                                       "scans": [{k: v for k, v in sc.items()
                                                  if k != "raw"} for sc in lst]})
        m = re.match(r"^/api/tenant/([A-Za-z0-9._-]+)/scan/([A-Za-z0-9._-]+)$", path)
        if m and method == "GET":
            sc = self._find(m.group(1), m.group(2))
            if not sc:
                return self.json_out(404, {"error": "not found"})
            return self.json_out(200, {k: v for k, v in sc.items() if k != "raw"})
        if path == "/api/status" and method == "POST":
            t, s = q.get("t", [""])[0], q.get("s", [""])[0]
            f = q.get("f", [""])[0]
            status = q.get("status", ["open"])[0]
            note = q.get("note", [""])[0]
            if (
                status not in STATUSES
                or not SAFE_ID.fullmatch(f)
                or not SAFE_ID.fullmatch(t)
                or not SAFE_ID.fullmatch(s)
                or len(note) > MAX_STATUS_NOTE_LENGTH
            ):
                return self.json_out(400, {"error": "bad request"})
            if not self._find(t, s):
                return self.json_out(404, {"error": "scan not found"})
            with self._lock:
                st = load_status(self.root)
                key = f"{t}/{s}/{f}"
                st[key] = {"status": status, "note": note,
                           "updated": time.strftime("%Y-%m-%dT%H:%M:%S")}
                save_status(self.root, st)
            return self.json_out(200, {"ok": True, "status": status})
        if path == "/api/summary" and method == "GET":
            tot = {}
            for sc in self.scans:
                for k, v in sc["summary"].items():
                    tot[k] = tot.get(k, 0) + v
            return self.json_out(200, {"total": sum(tot.values()),
                                       "by_severity": tot})
        if path.startswith("/api/monitor") and method == "GET":
            return self.route_monitor(path, q)
        if path.startswith("/api/reports") and method == "GET":
            return self.route_reports(path, q)
        if path == "/api/evidence" and method == "GET":
            Handler.refresh_reporting()
            snap = Handler.reporting
            if snap is None:
                return self.json_out(200, {"empty": True, "items": []})
            return self.json_out(200, {"empty": False,
                                       "count": snap.get("counts", {}).get(
                                           "evidence", 0),
                                       "items": (snap.get("evidence")
                                                 or [])[:100]})
        if path == "/api/analytics" and method == "GET":
            Handler.refresh_reporting()
            snap = Handler.reporting
            if snap is None:
                return self.json_out(200, {"empty": True, "bundles": []})
            return self.json_out(200, {"empty": False,
                                       "bundles": (snap.get("analytics")
                                                   or [])[:20]})
        if path.startswith("/api/devsecops/") and method == "GET":
            return self.route_devsecops(path, q)
        return self.json_out(404, {"error": "no such endpoint"})

    # --- Phase-6 reporting API (read-only, org-filtered, redacted) ----
    def route_reports(self, path, q):
        Handler.refresh_reporting()
        snap = Handler.reporting
        if snap is None:
            return self.json_out(200, {"empty": True, "reports": []})
        m = re.match(r"^/api/reports/([A-Za-z0-9-]+)$", path)
        if m:
            for r in snap.get("reports") or []:
                if r.get("id") == m.group(1):
                    return self.json_out(200, r)
            return self.json_out(404, {"error": "not found"})
        return self.json_out(200, {"empty": False,
                                   "count": snap.get("counts", {}).get(
                                       "reports", 0),
                                   "reports": (snap.get("reports")
                                               or [])[:100]})

    # --- Phase-7 DevSecOps API (read-only, org-filtered, redacted) ----
    def route_devsecops(self, path, q):
        Handler.refresh_devsecops()
        snap = Handler.devsecops
        if snap is None:
            return self.json_out(200, {"empty": True, "gates": [], "runs": [],
                                       "results": []})
        def cap(v, default, hi):
            try:
                return min(max(1, int(v)), hi)
            except (TypeError, ValueError):
                return default
        offset = cap((q.get("offset") or ["0"])[0], 0, 10000)
        base = {"empty": False, "org": snap.get("org") or "",
                "counts": snap.get("counts") or {}}
        if path == "/api/devsecops/gates":
            out = dict(base)
            out["gates"] = (snap.get("gates") or [])[offset: offset + cap(
                (q.get("limit") or ["20"])[0], 20, 100)]
            return self.json_out(200, out)
        if path == "/api/devsecops/runs":
            out = dict(base)
            out["runs"] = (snap.get("runs") or [])[offset: offset + cap(
                (q.get("limit") or ["20"])[0], 20, 100)]
            return self.json_out(200, out)
        if path == "/api/devsecops/results":
            out = dict(base)
            out["by_status"] = snap.get("by_status") or {}
            out["results"] = (snap.get("results") or [])[offset: offset + cap(
                (q.get("limit") or ["20"])[0], 20, 100)]
            return self.json_out(200, out)
        m = re.match(r"^/api/devsecops/(gates|runs|results)/([A-Za-z0-9-]+)$",
                     path)
        if m:
            kind, rid = m.group(1), m.group(2)
            for r in snap.get(kind) or []:
                if r.get("id") == rid:
                    return self.json_out(200, r)
            return self.json_out(404, {"error": "not found"})
        return self.json_out(404, {"error": "no such endpoint"})

    # --- Phase-5 monitoring panel (read-only, org-filtered, redacted) ---
    def route_monitor(self, path, q):
        Handler.refresh_monitor()
        snap = Handler.monitor
        if snap is None or snap.get("empty"):
            return self.json_out(200, {"enabled": False,
                                       "org": Handler.monitor_org or "",
                                       "note": "no monitoring data"})
        limit = 200
        try:
            limit = min(int(q.get("limit", ["200"])[0]), 200)
        except ValueError:
            limit = 200
        if path == "/api/monitor":
            return self.json_out(200, {"enabled": True, "org": snap["org"],
                                       "projects": snap["projects"],
                                       "counts": {
                                           "policies": len(snap["policies"]),
                                           "executions":
                                               len(snap["executions"]),
                                           "events": len(snap["events"]),
                                           "alerts": len(snap["alerts"]),
                                           "tickets": len(snap["tickets"]),
                                           "health": len(snap["health"])}})
        if path == "/api/monitor/policies":
            return self.json_out(200, {"count": len(snap["policies"]),
                                       "policies": snap["policies"][:limit]})
        if path == "/api/monitor/executions":
            return self.json_out(200, {"count": len(snap["executions"]),
                                       "executions":
                                           snap["executions"][:limit]})
        if path == "/api/monitor/events":
            return self.json_out(200, {"count": len(snap["events"]),
                                       "events": snap["events"][:limit]})
        if path == "/api/monitor/alerts":
            st = q.get("state", [""])[0]
            lst = snap["alerts"]
            if st:
                lst = [a for a in lst if a["state"] == st]
            return self.json_out(200, {"count": len(lst),
                                       "alerts": lst[:limit]})
        m = re.match(r"^/api/monitor/alerts/([A-Za-z0-9._-]+)$", path)
        if m:
            for a in snap["alerts"]:
                if a["id"] == m.group(1):
                    try:
                        import alerts as _al
                        svc = _pf_service(Handler.intel_db)
                        view = _al.AlertService(svc).alert_view(a["id"])
                        redacted = {k: view.get(k) for k in (
                            "id", "project_id", "rule_id", "event_type",
                            "asset_id", "title", "severity", "state",
                            "occurrence_count", "first_seen", "last_seen",
                            "suppressed_until", "group_key",
                            "fingerprint")}
                        redacted["occurrences"] = [
                            {"occurrence_number": o.get("occurrence_number"),
                             "ts": o.get("ts")}
                            for o in _al.AlertService(svc).occurrences(
                                a["id"])[:100]]
                        redacted["history"] = [
                            {"action": h.get("action"), "ts": h.get("ts"),
                             "actor": h.get("actor"),
                             "reason": h.get("reason", "")[:160]}
                            for h in _al.AlertService(svc).history(
                                a["id"])[:100]]
                        return self.json_out(200, redacted)
                    except Exception:
                        return self.json_out(500, {"error": "lookup failed"})
            return self.json_out(404, {"error": "alert not found"})
        if path == "/api/monitor/remediation":
            st = q.get("status", [""])[0]
            lst = snap["tickets"]
            if st:
                lst = [t for t in lst if t["status"] == st]
            return self.json_out(200, {"count": len(lst),
                                       "tickets": lst[:limit]})
        if path == "/api/monitor/health":
            return self.json_out(200, {"count": len(snap["health"]),
                                       "health": snap["health"][:limit]})
        return self.json_out(404, {"error": "no such endpoint"})

    # --- Phase-4 intelligence API (read-only, org-filtered, redacted) ----
    def route_intel(self, path, q):
        Handler.refresh_intel()
        snap = Handler.intel
        if snap is None or snap.get("empty"):
            return self.json_out(200, {"enabled": False,
                                       "org": Handler.intel_org or "",
                                       "note": "no intelligence data"})
        limit = 200
        try:
            limit = min(int(q.get("limit", ["200"])[0]), 200)
        except ValueError:
            limit = 200
        if path == "/api/intel":
            return self.json_out(200, {"enabled": True,
                                       "org": snap["org"],
                                       "counts": snap["counts"],
                                       "projects": snap["projects"]})
        if path == "/api/intel/assets":
            return self.json_out(200, {"count": len(snap["assets"]),
                                       "assets": snap["assets"][:limit]})
        m = re.match(r"^/api/intel/assets/([A-Za-z0-9._-]+)$", path)
        if m:
            for a in snap["assets"]:
                if a["id"] == m.group(1):
                    fid = [f for f in snap["findings"]
                           if f.get("asset_id") == a["id"]]
                    detail = {k: v for k, v in a.items()
                              if k != "project_id"}
                    detail["findings"] = [
                        {"id": f["id"], "title": f["title"],
                         "severity": f["severity"],
                         "risk_score": f["risk_score"],
                         "priority": f["priority"]} for f in fid[:100]]
                    return self.json_out(200, detail)
            return self.json_out(404, {"error": "asset not found"})
        if path == "/api/intel/findings":
            prio = q.get("priority", [""])[0]
            flist = snap["findings"]
            if prio:
                if prio not in ("P0", "P1", "P2", "P3", "P4"):
                    return self.json_out(400, {"error": "bad priority"})
                flist = [f for f in flist if f["priority"] == prio]
            return self.json_out(200, {"count": len(flist),
                                       "findings": flist[:limit]})
        m = re.match(r"^/api/intel/findings/([A-Za-z0-9._-]+)$", path)
        if m:
            for f in snap["findings"]:
                if f["id"] == m.group(1):
                    try:
                        sys.path.insert(0, os.path.dirname(
                            os.path.abspath(__file__)))
                        import correlate as _cor
                        svc = _pf_service(Handler.intel_db)
                        view = _cor.CorrelationService(svc).finding_view(
                            f["id"])
                        if view is None:
                            return self.json_out(404,
                                                 {"error": "not found"})
                        redacted = {k: view.get(k) for k in (
                            "id", "project_id", "asset_id", "title",
                            "severity", "confidence", "category", "source",
                            "rule_id", "template_id", "cwe", "cve",
                            "lifecycle", "first_detected", "last_detected",
                            "resolved_at", "reopened_at", "occurrence_count",
                            "confidence_score", "confidence_level",
                            "risk_score", "risk_level", "priority",
                            "exploitability", "calc_version",
                            "suppressed_until")}
                        redacted["confidence_reasons"] = view.get(
                            "confidence_reasons", [])
                        redacted["risk_factors"] = view.get("risk_factors",
                                                            [])
                        redacted["evidence_meta"] = [
                            {"evidence_type": e.get("evidence_type"),
                             "url": e.get("url", "")[:200],
                             "scanner": e.get("scanner"),
                             "detection_reason": e.get("detection_reason",
                                                       "")[:160]}
                            for e in (view.get("evidence") or [])[:50]]
                        redacted["observations"] = [
                            {"source": o.get("source"),
                             "scan_id": o.get("scan_id", "")[:24],
                             "count": o.get("count"),
                             "first_seen": o.get("first_seen")}
                            for o in view.get("observations", [])[:100]]
                        redacted["links"] = view.get("links", [])[:50]
                        redacted["risk_history"] = [
                            {"ts": h.get("ts"), "score": h.get("risk_score"),
                             "level": h.get("risk_level"),
                             "version": h.get("calc_version")}
                            for h in view.get("risk_history", [])[:50]]
                        return self.json_out(200, redacted)
                    except Exception as e:
                        return self.json_out(500, {"error": "lookup failed"})
            return self.json_out(404, {"error": "finding not found"})
        if path == "/api/intel/clusters":
            return self.json_out(200, {"count": len(snap["clusters"]),
                                       "clusters": snap["clusters"][:limit]})
        if path == "/api/intel/diffs":
            return self.json_out(200, {"count": len(snap["diffs"]),
                                       "diffs": snap["diffs"][:limit]})
        return self.json_out(404, {"error": "no such endpoint"})

    def route_export(self, path):
        m = re.match(r"^/export/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)$", path)
        if not m:
            return self.send(404, b"not found")
        sc = self._find(m.group(1), m.group(2))
        if not sc:
            return self.send(404, b"not found")
        root_path = os.path.realpath(self.root)
        source_path = os.path.realpath(os.path.join(root_path, sc["file"]))
        try:
            if os.path.commonpath((root_path, source_path)) != root_path:
                return self.json_out(404, {"error": "not found"})
            with open(source_path, "rb") as fh:
                body = fh.read(MAX_EXPORT_BYTES + 1)
        except OSError:
            return self.json_out(404, {"error": "not found"})
        if len(body) > MAX_EXPORT_BYTES:
            return self.json_out(413, {"error": "export_too_large"})
        raw_filename = os.path.basename(sc["file"])
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", raw_filename)[:128] or "report.json"
        return self.send(
            200,
            body,
            "application/json; charset=utf-8",
            {"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    def log_message(self, fmt, *args):
        """Log only a query-free, bounded request target and safe method."""
        client = self.client_address[0] if self.client_address else "-"
        method = str(getattr(self, "command", ""))[:16]
        if not re.fullmatch(r"[A-Z]{1,16}", method):
            method = "-"
        target = safe_request_line(getattr(self, "path", ""))[:2048]
        version = str(getattr(self, "request_version", ""))[:16]
        if not re.fullmatch(r"HTTP/[0-9.]{1,8}", version):
            version = "HTTP/?"
        request_id = str(getattr(self, "request_id", "") or "")
        if not REQUEST_ID_RE.fullmatch(request_id):
            request_id = "-"
        sys.stderr.write("[http] %s %s %s %s %s\n" % (
            request_id, str(client)[:128], method, target, version))



def is_loopback_bind_host(host: str) -> bool:
    """Return True only for an explicit loopback address/name.

    Non-loopback hostnames are treated as remote rather than DNS-resolved:
    the dashboard refuses unauthenticated exposure before opening a socket.
    """
    value = str(host or "").strip()
    if value.lower().rstrip(".") == "localhost":
        return True
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    return bool(mapped and mapped.is_loopback)


def configured_dashboard_token(cli_token, environ=None):
    """Read the explicit CLI token or preferred environment-backed token."""
    source = os.environ if environ is None else environ
    value = cli_token if cli_token is not None else source.get(DASHBOARD_TOKEN_ENV, "")
    return str(value or "").strip()


def main():
    ap = argparse.ArgumentParser(description="SecuPulse — findings dashboard")
    ap.add_argument("--root", default="results", help="Directory of result JSONs "
                    "(subdirectories = clients/tenants)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default 127.0.0.1; non-loopback requires --token)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument(
        "--token",
        default=None,
        help="Require a bearer token (prefer SECURITY_TOOLKIT_DASHBOARD_TOKEN env var)",
    )
    ap.add_argument(
        "--allow-legacy-query-token",
        action="store_true",
        help="Temporarily accept ?t=<token>; URL credentials can leak through logs/history/referrers",
    )
    ap.add_argument("--jobs-db", default=None,
                    help="Platform SQLite — adds the Phase-3 scan-jobs ops "
                         "panel (/jobs, /api/jobs) gated by the same token")
    ap.add_argument("--jobs-org", default="",
                    help="Job panel org filter (multi-tenant: run one "
                         "dashboard per org so no job id crosses tenants)")
    ap.add_argument("--intel-db", default=None,
                    help="Platform SQLite — adds the Phase-4 intelligence "
                         "panel (/api/intel*) gated by the same token")
    ap.add_argument("--intel-org", default="",
                    help="Intelligence org filter (one dashboard per org)")
    ap.add_argument("--identity-db", default=None,
                    help="Platform SQLite — adds the Phase-8 identity "
                         "panel (/identity, /api/identity) gated by the "
                         "same token")
    ap.add_argument("--identity-org", default="",
                    help="Identity org filter (one dashboard per org)")
    args = ap.parse_args()

    token = configured_dashboard_token(args.token)
    if args.token is not None and not token:
        ap.error("--token must not be empty")
    if args.token is not None:
        print(
            "[!] A command-line token may be visible to process inspection; "
            f"prefer {DASHBOARD_TOKEN_ENV}.",
            file=sys.stderr,
        )
    if token and len(token) > MAX_DASHBOARD_TOKEN_LENGTH:
        ap.error("dashboard token exceeds the maximum allowed length")
    if not is_loopback_bind_host(args.host) and not token:
        ap.error("non-loopback bind refused: --token is required for remote access")
    if args.allow_legacy_query_token and not token:
        ap.error("--allow-legacy-query-token requires --token")
    if args.allow_legacy_query_token:
        print(
            "[!] Legacy query-string authentication is enabled; credentials in URLs can leak.",
            file=sys.stderr,
        )
    token = token or None

    os.makedirs(args.root, exist_ok=True)
    scans, tenants = discover(args.root)
    Handler.root = os.path.abspath(args.root)
    Handler.scans = scans
    Handler.tenants = tenants
    Handler.token = token
    Handler.allow_legacy_query_token = args.allow_legacy_query_token
    Handler.jobs_org = args.jobs_org or ""
    Handler.jobs, Handler.job_stages = load_jobs_snapshot(
        args.jobs_db, Handler.jobs_org)
    Handler.intel_db = args.intel_db
    Handler.intel_org = args.intel_org or ""
    Handler.monitor_org = Handler.intel_org  # same platform DB, same filter
    Handler.identity_db = args.identity_db or args.intel_db
    Handler.identity_org = args.identity_org or Handler.intel_org or ""
    Handler.refresh_intel()
    Handler.refresh_identity()
    Handler.refresh_monitor()
    Handler.refresh_reporting()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    port = httpd.server_address[1]
    print("═" * 58)
    print("  SECUPULSE — Security Findings Portal")
    print("═" * 58)
    print(f"  Root      : {args.root}")
    print(f"  Tenants   : {len(tenants)}  ({', '.join(sorted(tenants)) or 'none'})")
    print(f"  Scans     : {len(scans)}")
    print(f"  URL       : http://127.0.0.1:{port}/")
    print(f"  API       : http://127.0.0.1:{port}/api/scans")
    print(f"  Auth      : {'Bearer token required' if token else 'none (local)'}")
    print("  Ctrl+C to stop.")
    print("═" * 58)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[✓] stopped.")


if __name__ == "__main__":
    main()
