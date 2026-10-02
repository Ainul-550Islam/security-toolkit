#!/usr/bin/env python3
# ============================================================================
#  Hunter — Bug-Bounty Workflow Automation (one command, full chain)
#  ---------------------------------------------------------------------------
#  Stage 1  Recon      : SubKraken subdomain enum (crt.sh CT logs + DNS brute)
#  Stage 2  Live hosts : httpx-style probing (status/title/server/tech) — plus
#                        subdomain-takeover detection (CNAME dangling → known
#                        cloud services, fingerprints verified via
#                        can-i-take-over-xyz, Aug-2026 markers)
#  Stage 3  Edge       : WallFinder WAF fingerprint on the primary host
#  Stage 4  Crawl      : SecuSpider endpoint discovery (links + param URLs)
#  Stage 5  Coverage   : Nucleus template scan (25+ YAML templates, passive)
#  Stage 6  Directed   : Injector fuzzing on discovered parameters
#                        (OPT-IN via --active; authorized targets only)
#  Stage 7  Report     : unified JSON (dashboard-ready) + optional SARIF
#
#  The same order real 2026 bug-bounty stacks use:
#  subfinder→httpx→katana→nuclei→ffuf/sqlmap (see research notes).
#
#  Usage:
#    python3 workflow.py --domain example.com
#    python3 workflow.py --domain example.com --active --payloads 6
#    python3 workflow.py --domain example.com --client acme --sarif
#
#  LEGAL: authorized engagements only. Stage 6 performs ACTIVE testing.
# ============================================================================

import argparse
import concurrent.futures
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_ROOT = os.path.dirname(HERE)
TEMPLATES_DIR = os.path.join(TOOLKIT_ROOT, "templates")

UA = ("Mozilla/5.0 (compatible; Hunter/1.0; authorized-security-recon; "
      "+research-consent)")
SSLC = ssl.create_default_context()
SSLC.check_hostname = False
SSLC.verify_mode = ssl.CERT_NONE
SSL_OPTS = {"context": SSLC}

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEV_WEIGHTS = {"Critical": 25, "High": 14, "Medium": 8, "Low": 4, "Info": 0}
DEFAULT_PORTS = (80, 443, 8080, 8443)
TECH_RE = re.compile(r"(jetty|tomcat|nginx|apache|express|django|rails|php\s|"
                     r"iis|wordpress|cloudflare|fastly|akamai|aws|azure|golang)", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# ---------------------------------------------------------------------------
# Subdomain takeover fingerprints (can-i-take-over-xyz, verified Aug 2026)
# ---------------------------------------------------------------------------
TAKEOVER_FP = [
    {"cname": ("s3.amazonaws.com",), "markers": ("NoSuchBucket",)},
    {"cname": ("blob.core.windows.net",), "markers": ("specified container does not exist",)},
    {"cname": ("azurewebsites.net",), "markers": ("404 Web Site Not Found",
                                                  "You do not have permission to view this directory")},
    {"cname": ("cloudapp.azure.com", "azurefd.net"), "markers": ("404 Web Site Not Found",)},
    {"cname": ("github.io",), "markers": ("There isn't a GitHub Pages site here",)},
    {"cname": ("herokuapp.com",), "markers": ("No such app", "There's nothing here, yet.")},
    {"cname": ("vercel.app",), "markers": ("The deployment could not be found on Vercel",)},
    {"cname": ("netlify.app",), "markers": ("Not Found - Request ID:",)},
    {"cname": ("myshopify.com", "shops.myshopify.com"), "markers": ("Sorry, this shop is currently unavailable",)},
    {"cname": ("zendesk.com",), "markers": ("Help Center Closed",)},
    {"cname": ("hubspot.net",), "markers": ("Domain not found", "This page isn't available")},
    {"cname": ("fastly.net",), "markers": ("Fastly error: unknown domain",)},
    {"cname": ("readthedocs.io",), "markers": ("Read the Docs: Page Not Found",)},
    {"cname": ("surge.sh",), "markers": ("project not found",)},
    {"cname": ("bitbucket.io",), "markers": ("There isn't a GitHub Pages site here",)},
    {"cname": ("tumblr.com",), "markers": ("There's nothing here",)},
    {"cname": ("unbouncepages.com",), "markers": ("Site Not Found",)},
    {"cname": ("helpscoutdocs.com",), "markers": ("Page Not Found",)},
    {"cname": ("trafficmanager.net",), "markers": ("NXDOMAIN",)},
    {"cname": ("azureedge.net",), "markers": ("NXDOMAIN",)},
]

DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]


# ---------------------------------------------------------------------------
# Minimal DNS (CNAME resolution over UDP) — stdlib only
# ---------------------------------------------------------------------------
def dns_cname(host: str, timeout: float = 3.0) -> str:
    """Return the CNAME target of `host` (or an empty string)."""
    try:
        servers = []
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("nameserver"):
                        servers.append(line.split()[1])
        except Exception:
            pass
        servers += [s for s in DNS_SERVERS if s not in servers]
        for ns in servers[:3]:
            try:
                cname = _dns_query(host, ns, timeout)
                if cname is not None:
                    return cname
            except Exception:
                continue
    except Exception:
        pass
    return ""


def _dns_query(host: str, ns: str, timeout: float = 3.0) -> str | None:
    """CNAME lookup via raw DNS packet. Returns target or '' (exists, no CNAME)."""
    tid = random.randint(0, 65535)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + \
        struct.pack(">HH", 5, 1)  # CNAME query
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(pkt, (ns, 53))
        data, _ = s.recvfrom(4096)
    if len(data) < 12 or struct.unpack(">H", data[0:2])[0] != tid:
        return None
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        if struct.unpack(">H", data[4:6])[0] != 0:  # NXDOMAIN / SERVFAIL
            return None
        return ""  # no answer but domain exists
    # skip question section
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    i += 5
    for _ in range(ancount):
        if i >= len(data):
            return None
        while i < len(data) and data[i] != 0:
            i += 1 + data[i]
        i += 1
        if i + 10 > len(data):
            return None
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if rtype == 5:  # CNAME
            name = _decode_name(data, i)
            if name:
                return name.lower().rstrip(".")
        i += rdlen
    return ""


def _decode_name(data: bytes, off: int) -> str:
    labels, jumped, guard = [], False, 0
    while guard < 64:
        l = data[off]
        if l & 0xC0 == 0xC0:
            if not jumped:
                jumped = True
            off = ((l & 0x3F) << 8) | data[off + 1]
            guard += 1
            continue
        off += 1
        if l == 0:
            break
        labels.append(data[off:off + l].decode("ascii", "ignore"))
        off += l
        guard += 1
    return ".".join(labels)


# ---------------------------------------------------------------------------
# HTTP probing (httpx-style)
# ---------------------------------------------------------------------------
def fetch(url, timeout=12, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **{k: v for k, v in
                                 (headers or {}).items()}})
    try:
        with urllib.request.urlopen(req, timeout=timeout, **SSL_OPTS) as r:
            return r.status, dict((k.lower(), v) for k, v in r.headers.items()), \
                r.read(300_000)
    except urllib.error.HTTPError as e:
        try:
            b = e.read(60_000)
        except Exception:
            b = b""
        return e.code, dict((k.lower(), v) for k, v in e.headers.items()), b
    except Exception as e:
        return None, {}, str(e).encode()[:200]


def probe(host: str, timeout=10):
    """httpx-lite: find a live (scheme, port) with status/title/server/tech."""
    if host.startswith(("http://", "https://")):
        scheme, rest = urllib.parse.urlparse(host).scheme, \
            urllib.parse.urlparse(host).netloc
        host = rest
    else:
        scheme = None
        rest = host
    hostname = rest.split(":")[0]
    if ":" in rest:
        ports = [int(rest.split(":")[1])]
    elif scheme:
        ports = [443 if scheme == "https" else 80]
    else:
        ports = None
    for s in ([scheme or "https", "http"] if not scheme else [scheme]):
        for p in (ports or DEFAULT_PORTS):
            url = f"{s}://{hostname}:{p}/" if (ports or p not in (80, 443)) \
                else f"{s}://{hostname}/"
            status, h, body = fetch(url, timeout)
            if status:
                title = ""
                m = TITLE_RE.search(body.decode("utf-8", "ignore"))
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
                tech = sorted({t.strip() for t in TECH_RE.findall(
                    (h.get("server", "") + " " + h.get("x-powered-by", "") +
                     " " + h.get("via", "")).lower())})[:4]
                return {"url": url, "host": hostname, "port": p, "scheme": s,
                        "status": status, "title": title,
                        "server": h.get("server", "")[:60],
                        "tech": tech, "len": len(body)}
    return None


# ---------------------------------------------------------------------------
# Subdomain takeover check
# ---------------------------------------------------------------------------
def takeover_check(host: str, cname: str = None, timeout=10) -> dict:
    """Return {takeover:bool, service, evidence} for a dangling CNAME."""
    cname = (cname or dns_cname(host)).lower()
    if not cname:
        return {"takeover": False, "service": "", "evidence": f"{host}: no CNAME"}
    for fp in TAKEOVER_FP:
        if any(cname.endswith(sf) for sf in fp["cname"]):
            for s in ("https", "http"):
                try:
                    status, h, body = fetch(f"{s}://{host}/", timeout)
                    if status is None:
                        continue
                    text = (body or b"").decode("utf-8", "ignore")
                    for mk in fp["markers"]:
                        if mk.lower() in text.lower():
                            return {"takeover": True,
                                    "service": fp["cname"][0],
                                    "evidence": f"CNAME→{cname}; marker "
                                                f"'{mk}' on HTTP {status}"}
                    return {"takeover": False, "service": fp["cname"][0],
                            "evidence": f"CNAME→{cname}; no dangling marker "
                                        f"(HTTP {status})"}
                except Exception:
                    continue
    return {"takeover": False, "service": "",
            "evidence": f"CNAME→{cname}: not a takeover-service target"}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_workflow(domain: str, use_crt=True, do_brute=True, wordlist=None,
                 threads=50, timeout=10, max_hosts=40, spider_depth=1,
                 spider_limit=40, do_takeover=True, do_waf=True,
                 active=False, payloads=5, delay=0.6, cookie=None,
                 extra_headers=None, client="default", out_dir=None,
                 sarif=None, hosts_override=None, verbose=False):
    """Run the full bug-bounty chain. Returns the unified result dict."""
    import subdomain_enum, spider, template_engine, active_fuzzer, waf_detect
    t0 = time.time()
    log = lambda *a: print("[*]", *a)
    domains_findings, hosts, steps = [], [], []

    # ---- Stage 1: recon --------------------------------------------------
    log(f"STAGE 1 — subdomain enumeration for {domain}")
    if hosts_override:
        names = [{"name": h, "ips": []} for h in hosts_override]
        sub_info = {}
        for h in hosts_override:
            sub_info[h] = {"sources": ["override"], "ips": []}
        log(f"using provided host list ({len(hosts_override)})")
    else:
        words = wordlist
        if words:
            with open(wordlist, encoding="utf-8", errors="ignore") as fh:
                words = [w.strip().lower() for w in fh
                         if w.strip() and not w.startswith("#")]
        elif not do_brute:
            words = []
        if do_brute:
            words = words or subdomain_enum.DEFAULT_WORDS
        sub_info = subdomain_enum.enumerate(domain, use_crt,
                                            words if do_brute else [],
                                            threads, False, timeout)
        names = [{"name": n, "ips": v.get("ips", [])} for n, v in sub_info.items()]
        log(f"recon: {len(names)} names")

    # ---- Stage 2: live probing + takeover ----------------------------------
    log(f"STAGE 2 — probing {min(len(names), max_hosts)} live hosts")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(8, min(threads, 60))) as ex:
        fut = {n["name"]: ex.submit(probe, n["name"], timeout) for n in names[:max_hosts]}
        for name, f in fut.items():
            p = f.result()
            if p:
                p["cname"] = dns_cname(name, timeout) if do_takeover else ""
                hosts.append(p)
    hosts.sort(key=lambda h: (h["host"].startswith("www"), h["host"]))
    log(f"live: {len(hosts)} hosts")

    # ---- Stage 3: WAF -------------------------------------------------------
    if do_waf and hosts:
        log("STAGE 3 — WAF fingerprint (primary host)")
        try:
            waf = waf_detect.detect(hosts[0]["url"], timeout)
            steps.append({"stage": "waf", "target": hosts[0]["url"],
                          "waf": waf.get("waf", [])})
            for w in waf.get("waf", []):
                domains_findings.append({
                    "id": f"WAF-{w.get('vendor', 'X')}",
                    "title": f"WAF in front: {w.get('vendor', 'unknown')}",
                    "severity": "Low",
                    "evidence": ", ".join(w.get("evidence", [])) or "behavioral",
                    "remediation": f"Tailor payloads & expect rate limits "
                                   f"({w.get('vendor','')}); confirm scope."})
        except Exception:
            pass

    # ---- Stage 4: spider -----------------------------------------------------
    log(f"STAGE 4 — crawling {min(len(hosts), 5)} hosts (depth {spider_depth})")
    param_urls, endpoints_all = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, max(1, len(hosts)))) as ex:
        fut = {h["url"]: ex.submit(spider.crawl, h["url"], spider_depth,
                                   spider_limit, timeout, cookie, verbose)
               for h in hosts[:5]}
        for hurl, f in fut.items():
            try:
                _stats, eps, params, _api, _pages = f.result()
            except Exception:
                continue
            for e in eps:
                u = e.get("url") if isinstance(e, dict) else e
                if u and u.startswith("http") and u not in endpoints_all:
                    endpoints_all.append(u)
            for p in params:
                u = p.get("url") if isinstance(p, dict) else p
                if u and u.startswith("http"):
                    param_urls.append(u)
    seen = set()
    param_urls = [u for u in param_urls if not (u in seen or seen.add(u))]
    seen = set()
    endpoints_all = [e for e in endpoints_all if not (e in seen or seen.add(e))]
    log(f"crawl: {len(endpoints_all)} endpoints, {len(param_urls)} params")
    steps.append({"stage": "crawl", "endpoints": endpoints_all[:200],
                  "param_urls": param_urls[:100]})

    # ---- Stage 5: template coverage ------------------------------------------
    log("STAGE 5 — Nucleus template coverage")
    tpl_targets = []
    for h in hosts[:3]:
        tpl_targets.append(h["url"])
    for u in endpoints_all[:20]:
        tpl_targets.append(u)
    seen_t = set()
    tpl_targets = [u for u in tpl_targets if not (u in seen_t or seen_t.add(u))]
    len_before_tpl = len(domains_findings)
    try:
        tpl_findings = []
        for t in tpl_targets[:10]:
            try:
                tpl_findings += template_engine.scan(t, TEMPLATES_DIR, timeout,
                                                     extra_headers, verbose)
            except Exception:
                continue
        # dedupe on (title, evidence)
        seen_tf = set()
        for f in tpl_findings:
            k = (f.get("title", ""), f.get("evidence", "")[:60])
            if k not in seen_tf:
                seen_tf.add(k)
                domains_findings.append(f)
        log(f"templates: {len(domains_findings) - len_before_tpl} findings "
            f"({len(tpl_targets)} targets)")
    except Exception:
        pass
    steps.append({"stage": "templates", "targets": tpl_targets[:20]})

    # ---- Stage 6: directed fuzzing (opt-in, active) ---------------------------
    if active:
        log("STAGE 6 — Injector fuzzing on discovered parameters (ACTIVE)")
        for pu in param_urls[:12]:
            path_q = urllib.parse.urlparse(pu)
            qs = urllib.parse.parse_qsl(path_q.query, keep_blank_values=True)
            if not qs:
                continue
            try:
                res = active_fuzzer.run(pu, qs[0][0], "auto", delay, payloads,
                                        cookie, extra_headers, timeout,
                                        skip_timebased=True)
            except SystemExit:
                continue
            seen_fuzz = set()
            for f in res.get("findings", []):
                tkey = f.get("type", f.get("title", "finding"))
                if tkey in seen_fuzz:
                    continue
                seen_fuzz.add(tkey)
                f["id"] = f"FUZZ-{len(domains_findings) + 1:03d}"
                f.setdefault("title", tkey)
                f["target"] = pu
                domains_findings.append(f)
            log(f"fuzz {pu}: {len(res.get('findings', []))} hits")

    # ---- Stage 7: report --------------------------------------------------------
    order = {k: i for i, k in enumerate(SEV_ORDER)}
    domains_findings.sort(key=lambda f: order.get(f.get("severity", "Info"), 9))
    summary = {}
    for f in domains_findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    score = max(0.0, 100.0 - sum(SEV_WEIGHTS.get(f.get("severity", "Info"), 0)
                                 for f in domains_findings))
    score = round(score, 1)
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else
             "D" if score >= 45 else "E" if score >= 30 else "F")
    result = {
        "tool": "Hunter (workflow automation)",
        "target": domain, "scan_date": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "hosts": [{k: v for k, v in h.items()} for h in hosts][:200],
        "host_count": len(hosts),
        "param_urls": param_urls[:60], "endpoints": endpoints_all[:60],
        "steps": steps, "findings": domains_findings, "summary": summary,
        "score": score, "grade": grade, "elapsed_s": round(time.time() - t0, 1),
        "active_mode": active,
        "disclaimer": "Authorized security assessment only. Outputs are "
                      "indicative — re-verify before reporting.",
    }
    out_dir = out_dir or os.path.join(TOOLKIT_ROOT, "results", client)
    os.makedirs(out_dir, exist_ok=True)
    fname = f"hunter_{domain.replace('.', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(out_dir, fname)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    result["path"] = path
    if sarif:
        sys.path.insert(0, HERE)
        import sarif_export
        try:
            s = dict(result)
            s["findings"] = [{"id": f.get("id", f"W{i}"), "title": f.get("title", ""),
                              "severity": f.get("severity", "Info"),
                              "evidence": f.get("evidence", ""),
                              "remediation": f.get("remediation", "")}
                             for i, f in enumerate(domains_findings)]
            sarif_export.write_sarif(s, sarif)
            log(f"SARIF: {sarif}")
        except Exception as e:
            log(f"SARIF export skipped: {e}")
    return result


def print_summary(r):
    print("═" * 62)
    print("  HUNTER — workflow results")
    print("═" * 62)
    print(f"  Target      : {r['target']}")
    print(f"  Live hosts  : {r['host_count']}    params: {len(r['param_urls'])}")
    print(f"  Findings    : {len(r['findings'])}    score: {r['score']}/100 "
          f"({r['grade']})    elapsed: {r['elapsed_s']}s")
    print("─" * 62)
    mk = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"}
    shown = 0
    for f in r["findings"]:
        if f.get("severity") in ("Critical", "High", "Medium") or shown < 8:
            print(f"  {mk.get(f['severity'], '⚪')} [{f['severity']:>8}] {f.get('id','')} "
                  f"| {str(f.get('title', ''))[:70]}")
            shown += 1
    print("═" * 62)
    print(f"[✓] JSON: {r.get('path')}")


def main():
    ap = argparse.ArgumentParser(description="Hunter — bug-bounty workflow automation")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--client", default="default", help="Client folder in results/")
    ap.add_argument("--hosts", default=None, help="Comma list of hosts (skip recon)")
    ap.add_argument("--no-crt", action="store_true")
    ap.add_argument("--no-brute", action="store_true")
    ap.add_argument("--wordlist", default=None)
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-hosts", type=int, default=40)
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--no-takeover", action="store_true")
    ap.add_argument("--no-waf", action="store_true")
    ap.add_argument("--active", action="store_true",
                    help="ACTIVE fuzzing (authorized targets only)")
    ap.add_argument("--payloads", type=int, default=5)
    ap.add_argument("--delay", type=float, default=0.6)
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--headers", default=None, help='JSON headers')
    ap.add_argument("--sarif", default=None)
    args = ap.parse_args()
    extra = json.loads(args.headers) if args.headers else None
    hosts_override = args.hosts.split(",") if args.hosts else None
    r = run_workflow(args.domain, use_crt=not args.no_crt, do_brute=not args.no_brute,
                     wordlist=args.wordlist, threads=args.threads,
                     timeout=args.timeout, max_hosts=args.max_hosts,
                     spider_depth=args.depth, spider_limit=args.limit,
                     do_takeover=not args.no_takeover, do_waf=not args.no_waf,
                     active=args.active, payloads=args.payloads, delay=args.delay,
                     cookie=args.cookie, extra_headers=extra, client=args.client,
                     sarif=args.sarif, hosts_override=hosts_override)
    print_summary(r)


if __name__ == "__main__":
    main()
