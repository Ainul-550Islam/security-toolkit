#!/usr/bin/env python3
# ============================================================================
#  SubKraken — Subdomain Enumeration (crt.sh passive + wordlist brute + DNS)
#  ---------------------------------------------------------------------------
#  Sources:
#    1. crt.sh — Certificate Transparency logs (passive, no target interaction)
#    2. Built-in mini wordlist / --wordlist file (active DNS resolution)
#  Zero dependencies. Threaded DNS resolution. Optional IP capture.
#
#  Usage:
#    python3 subdomain_enum.py --domain example.com
#    python3 subdomain_enum.py --domain example.com --threads 200 --resolve
#    python3 subdomain_enum.py --domain example.com --wordlist words.txt
#
#  LEGAL: passive CT lookup + standard DNS queries only (OSINT).
# ============================================================================

import argparse
import concurrent.futures
import json
import re
import socket
import sys
import time
import urllib.request

UA = "Mozilla/5.0 (compatible; SubKraken/1.0; osint-recon)"

DEFAULT_WORDS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ns1", "ns2",
    "api", "api2", "api3", "v1", "v2", "app", "apps", "mobile", "m", "my",
    "admin", "administrator", "portal", "panel", "cpanel", "login", "auth", "sso",
    "secure", "login", "id", "account", "accounts", "users", "customer",
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "demo", "beta", "preview", "sandbox", "old", "new", "backup", "tmp", "temp",
    "docs", "doc", "wiki", "kb", "help", "support", "ticket", "tickets", "status",
    "monitor", "monitoring", "grafana", "kibana", "jenkins", "git", "gitlab",
    "gitea", "bitbucket", "ci", "cd", "build", "deploy", "worker",
    "db", "mysql", "postgres", "redis", "mongo", "mongodb", "elastic", "es",
    "cache", "cdn", "static", "assets", "img", "images", "media", "video",
    "files", "file", "upload", "uploads", "download", "downloads", "storage",
    "s3", "cloud", "drive", "backup", "archive", "logs", "log",
    "shop", "store", "sales", "billing", "pay", "payment", "checkout", "cart",
    "blog", "news", "forum", "community", "web", "www2", "www3", "host",
    "remote", "vpn", "gateway", "gw", "proxy", "extranet", "intranet", "internal",
]

IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def crt_sh(domain: str, timeout: float = 25.0) -> list:
    """Pull subdomain names from Certificate Transparency (crt.sh). Passive."""
    names = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
            for entry in data:
                nv = entry.get("name_value", "")
                for line in str(nv).splitlines():
                    line = line.strip().lower()
                    if not line or "*" in line or " " in line:
                        continue
                    if line.endswith("." + domain) or line == domain:
                        names.add(line)
            break
        except Exception as e:
            if attempt == 0:
                time.sleep(2)
                continue
            print(f"[!] crt.sh lookup failed: {e}")
    return sorted(names)


def resolve(name: str, timeout: float = 4.0):
    """Return list of IPv4 addresses for `name` (or [] if not resolvable)."""
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except Exception:
        return []


def brute(domain: str, words, threads: int, timeout: float = 4.0) -> dict:
    """Resolve candidates concurrently; return {candidate: [ips]}."""
    found = {}
    arg_list = [(w, domain) for w in words]

    def worker(item):
        w, d = item
        cand = f"{w}.{d}"
        ips = resolve(cand, timeout)
        return (cand, ips) if ips else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        for res in ex.map(worker, arg_list):
            if res:
                found[res[0]] = res[1]
    return found


def enumerate(domain: str, use_crt: bool, wordlist, threads: int, resolve_all: bool,
              timeout: float = 4.0):
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain.lower()):
        print(f"[!] Invalid domain: {domain}")
        sys.exit(2)
    domain = domain.lower()

    results = {}

    if use_crt:
        print(f"[*] Querying crt.sh (Certificate Transparency) for {domain} …")
        t0 = time.time()
        ct = crt_sh(domain)
        print(f"    {'+' if ct else '!'} {len(ct)} names from CT logs ({time.time()-t0:.1f}s)")
        for n in ct:
            results.setdefault(n, {"sources": ["crt.sh"], "ips": []})

    if wordlist:
        print(f"[*] Brute-forcing {len(wordlist)} candidate names (concurrent)…")
        t0 = time.time()
        found = brute(domain, wordlist, threads, timeout)
        print(f"    {'+' if found else '!'} {len(found)} resolved ({time.time()-t0:.1f}s)")
        for cand, ips in found.items():
            results.setdefault(cand, {"sources": [], "ips": []})
            results[cand]["sources"].append("wordlist")
            results[cand]["ips"] = ips

    if resolve_all:
        print("[*] Resolving all discovered names…")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            fut = {n: ex.submit(resolve, n, timeout) for n in results}
            for n, f in fut.items():
                results[n]["ips"] = f.result()

    return results


def main():
    ap = argparse.ArgumentParser(description="SubKraken — subdomain enumeration")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--no-crt", action="store_true", help="Skip crt.sh (offline mode)")
    ap.add_argument("--no-brute", action="store_true", help="Skip wordlist brute")
    ap.add_argument("--wordlist", default=None, help="Custom wordlist file")
    ap.add_argument("--threads", type=int, default=100)
    ap.add_argument("--resolve", action="store_true",
                    help="Resolve IPs for ALL discovered names")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    words = []
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
            words = [w.strip().lower() for w in f if w.strip() and not w.startswith("#")]
    elif not args.no_brute:
        words = DEFAULT_WORDS

    results = enumerate(args.domain, not args.no_crt, words if not args.no_brute else [],
                        args.threads, args.resolve, args.timeout)

    total = len(results)
    with_ips = sum(1 for v in results.values() if v.get("ips"))
    live = [n for n, v in results.items() if v.get("ips")]

    print("═" * 58)
    print(f"  SUBKRAKEN — results for {args.domain}")
    print("═" * 58)
    print(f"  Total names found : {total}")
    print(f"  Live (resolvable) : {len(live)}")
    print("─" * 58)
    for n in sorted(results):
        v = results[n]
        ips = v.get("ips") or []
        src = ",".join(v.get("sources") or ["ct"])[:12]
        ip_txt = ", ".join(ips[:3]) + ("…" if len(ips) > 3 else "")
        marker = "●" if ips else "○"
        print(f"  {marker} {n:<42} [{src}] {ip_txt}")
    print("═" * 58)

    out = args.out or f"subdomains_{args.domain.replace('.', '_')}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"domain": args.domain, "count": total, "subdomains": results},
                  f, indent=2, ensure_ascii=False)
    print(f"[✓] JSON: {out}")


if __name__ == "__main__":
    main()
