#!/usr/bin/env python3
# ============================================================================
#  Sentinel Log — Web Access Log Analyzer / Lightweight IDS (stdlib only)
#  ---------------------------------------------------------------------------
#  Parses common/combined nginx & Apache log formats and flags attack
#  patterns: SQLi, XSS, path traversal, command injection, scanner bots,
#  credential stuffing (401/403 storms), and 404 recon bursts.
#
#  Usage:
#    python3 log_analyzer.py --log access.log
#    python3 log_analyzer.py --log access.log --top 10 --json report.json
#    tail -f access.log | python3 log_analyzer.py --stdin
# ============================================================================

import argparse
import collections
import json
import re
import sys

# --- Common access-log line patterns -----------------------------------------
COMMON_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_line(line: str):
    m = COMMON_RE.match(line.strip())
    if not m:
        return None
    g = m.groupdict()
    req = g["req"].split()
    method = req[0].upper() if req else "-"
    path = req[1] if len(req) > 1 else "-"
    return {
        "ip": g["ip"], "ts": g["ts"], "method": method,
        "path": path, "status": int(g["status"]), "size": int(g["size"] or 0),
        "referer": g.get("referer", ""), "ua": g.get("ua", ""),
        "raw": line.strip(),
    }

SQLI_PATTERNS = [
    (r"(\%27)|(\')|(\%22)|(\")", "SQL injection (quote/encode)"),
    (r"union\s+(all\s+)?select", "SQL injection (UNION SELECT)"),
    (r"(or|and)\s+1\s*=\s*1", "SQL injection (boolean)"),
    (r"sleep\s*\(|benchmark\s*\(|pg_sleep", "SQL injection (time-based)"),
    (r"information_schema|sys\.tables|user_tables", "SQL injection (schema dump)"),
    (r"\b(xp_cmdshell|exec\s*\(\s*sp_)\b", "MSSQL command exec attempt"),
]
XSS_PATTERNS = [
    (r"<script", "XSS attempt"),
    (r"javascript:", "XSS (javascript: URI)"),
    (r"onerror\s*=|onload\s*=|onclick\s*=", "XSS (event handler)"),
    (r"<img\s+[^>]*src\s*=", "XSS (img tag)"),
    (r"<iframe", "XSS (iframe)"),
    (r"document\.cookie", "XSS (cookie theft)"),
]
TRAVERSAL_PATTERNS = [
    (r"\.\./|\.\.%2f|%2e%2e", "Path traversal"),
    (r"etc/passwd|boot\.ini|win\.ini|\.env", "Sensitive file read attempt"),
]
EXEC_PATTERNS = [
    (r"\%3b|;cat\s|;ls\s|;wget\s|;curl\s|;nc\s|;bash|;sh\s", "Command injection"),
    (r"nslookup\s|ping\s-c\s", "Command execution attempt"),
]
SCANNER_UAS = [
    (r"sqlmap", "SQLMap scanner"), (r"nikto", "Nikto scanner"),
    (r"nuclei", "Nuclei scanner"), (r"acunetix", "Acunetix scanner"),
    (r"nessus", "Nessus scanner"), (r"masscan", "Masscan scanner"),
    (r"zgrab", "Zgrab scanner"), (r"nmap", "Nmap scan"),
    (r"arachni", "Arachni scanner"), (r"openvas", "OpenVAS scanner"),
    (r"wpscan", "WPScan"), (r"dirbuster", "Dirbuster"), (r"gobuster", "Gobuster"),
    (r"ffuf", "FFUF fuzzer"), (r"feroxbuster", "Feroxbuster fuzzer"),
    (r"python-requests", "Scripted client (requests)"),
]
ADMIN_PATHS = [r"/wp-admin", r"/phpmyadmin", r"/admin", r"/.git", r"/actuator",
               r"/panel", r"/manager/html", r"/cgi-bin", r"/api/v1/"]

ATTACK_GROUPS = [
    ("SQLi", SQLI_PATTERNS), ("XSS", XSS_PATTERNS), ("Traversal", TRAVERSAL_PATTERNS),
    ("Command-Injection", EXEC_PATTERNS), ("Scanner-Bot", SCANNER_UAS),
]


def classify(entry: dict) -> list:
    hits = []
    blob = urllib_decode(entry["path"] + " " + entry["ua"])
    for group, patterns in ATTACK_GROUPS:
        for pat, label in patterns:
            if re.search(pat, blob, re.I):
                hits.append(label)
                break
    if any(re.search(p, entry["path"], re.I) for p in ADMIN_PATHS):
        hits.append("Admin-path probing")
    return hits


def urllib_decode(s: str) -> str:
    try:
        import urllib.parse
        return urllib.parse.unquote(s)
    except Exception:
        return s


def analyze(lines, top_n=10):
    parsed = [p for p in (parse_line(l) for l in lines) if p]
    if not parsed:
        return None

    attacks = collections.Counter()
    attack_ips = collections.Counter()
    ip_status = collections.Counter()
    unique_ips = set()
    methods = collections.Counter()
    admin_paths = collections.Counter()
    total = len(parsed)
    bad = 0

    for e in parsed:
        unique_ips.add(e["ip"])
        methods[e["method"]] += 1
        ip_status[(e["ip"], e["status"])] += 1
        tags = classify(e)
        if tags:
            bad += 1
            for t in tags:
                attacks[t] += 1
            attack_ips[e["ip"]] += 1
            if "Admin-path probing" in tags:
                admin_paths[e["path"]] += 1

    # Credential stuffing: many 401/403 from one IP
    stuffing = []
    for (ip, st), cnt in ip_status.items():
        if st in (401, 403) and cnt >= 5:
            stuffing.append((ip, st, cnt))
    stuffing.sort(key=lambda x: -x[2])

    # 404 recon bursts
    recon = []
    for (ip, st), cnt in ip_status.items():
        if st == 404 and cnt >= 10:
            recon.append((ip, cnt))
    recon.sort(key=lambda x: -x[1])

    # Top attacker IPs
    top_attackers = attack_ips.most_common(top_n)

    report = {
        "total_requests": total,
        "unique_ips": len(unique_ips),
        "flagged_requests": bad,
        "methods": dict(methods.most_common()),
        "attack_classes": dict(attacks.most_common()),
        "top_attackers": top_attackers,
        "credential_stuffing_candidates": stuffing[:10],
        "recon_burst_candidates": recon[:10],
        "admin_path_probes": dict(admin_paths.most_common(10)),
    }
    return report


def print_report(r):
    print("═" * 60)
    print("  SENTINEL LOG — Web Access Log IDS Report")
    print("═" * 60)
    print(f"  Requests        : {r['total_requests']}")
    print(f"  Unique IPs      : {r['unique_ips']}")
    print(f"  Flagged         : {r['flagged_requests']}")
    print("─" * 60)
    print("  Attack classes:")
    for k, v in r["attack_classes"].items():
        print(f"   • {k:<24} {v}")
    print("─" * 60)
    print("  Top attacker IPs:")
    for ip, n in r["top_attackers"]:
        print(f"   • {ip:<18} {n} flagged")
    print("─" * 60)
    if r["credential_stuffing_candidates"]:
        print("  Credential-stuffing candidates (many 401/403):")
        for ip, st, n in r["credential_stuffing_candidates"]:
            print(f"   • {ip:<18} {st} x{n}")
    if r["recon_burst_candidates"]:
        print("  Recon bursts (many 404):")
        for ip, n in r["recon_burst_candidates"]:
            print(f"   • {ip:<18} 404 x{n}")
    if r["admin_path_probes"]:
        print("  Admin/system paths probed:")
        for p, n in r["admin_path_probes"].items():
            print(f"   • {p[:50]:<52} x{n}")
    print("═" * 60)


def main():
    ap = argparse.ArgumentParser(description="Sentinel Log — access log IDS")
    ap.add_argument("--log", help="Path to access log file")
    ap.add_argument("--stdin", action="store_true", help="Read from stdin")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    lines = []
    if args.log:
        with open(args.log, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    elif args.stdin:
        lines = sys.stdin.readlines()
    else:
        print("Usage: python3 log_analyzer.py --log access.log | --stdin")
        sys.exit(1)

    r = analyze(lines, args.top)
    if not r:
        print("[!] No parsable log lines (expect common/combined Apache or nginx format)")
        sys.exit(1)
    print_report(r)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)
        print(f"[✓] JSON: {args.json}")


if __name__ == "__main__":
    main()
