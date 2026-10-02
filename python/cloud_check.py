#!/usr/bin/env python3
# ============================================================================
#  CloudScope — Cloud & Database Exposure Checker (stdlib only)
#  ---------------------------------------------------------------------------
#  Checks (read-only, non-intrusive):
#    AWS S3            bucket public listing (ListBucketResult), exists/private
#    Google Cloud      GCS bucket public listing
#    Azure             blob container public listing
#    Redis             unauthenticated PING (data exposure -> RCE risk)
#    Memcached         unauthenticated STATS (info leak)
#    Elasticsearch     open cluster (data access)
#    MongoDB           internet-open port (confirm auth manually)
#
#  Safety: only ONE light probe per resource. Never writes, never exploits.
#  LEGAL: authorized targets only.
#
#  Usage:
#    python3 cloud_check.py --bucket mycompany-assets
#    python3 cloud_check.py --bucket mybucket --azure myaccount --container files
#    python3 cloud_check.py --service 203.0.113.5
#    python3 cloud_check.py --service 203.0.113.5:9200
# ============================================================================

import argparse
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request

UA = "Mozilla/5.0 (compatible; CloudScope/1.0; authorized-security-audit)"

S3_LIST = re.compile(r"<ListBucketResult", re.I)
S3_NO_SUCH = re.compile(r"NoSuchBucket", re.I)
GCS_LIST = re.compile(r"<Contents>|<ListBucketResult", re.I)
AZURE_LIST = re.compile(r"<EnumerationResults|<Blob", re.I)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def fetch(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(120_000)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(60_000)
        except Exception:
            return e.code, b""
    except Exception as e:
        return None, str(e).encode()[:200]


# ---------------------------------------------------------------------------
# S3 / GCS / Azure
# ---------------------------------------------------------------------------
def probe_s3_url(url: str, timeout=12) -> dict:
    status, body = fetch(url, timeout)
    text = body.decode("utf-8", "ignore")
    if status is None:
        return {"service": "S3", "status": "unreachable", "severity": "Info",
                "evidence": str(body)[:120],
                "remediation": "Check network / bucket region."}
    if S3_LIST.search(text) and status == 200:
        return {"service": "S3", "status": "PUBLIC LISTING ENABLED", "severity": "High",
                "evidence": f"GET {url} -> HTTP {status}; XML ListBucketResult returned",
                "remediation": "Block public access: Bucket policy deny s3:* on "
                               "Principal '*', uncheck 'Block public access' off — "
                               "enable 'Block all public access'."}
    if status == 403:
        return {"service": "S3", "status": "exists — private (good)", "severity": "Info",
                "evidence": f"GET {url} -> HTTP 403 AccessDenied",
                "remediation": "No action needed; verify IAM policies quarterly."}
    if S3_NO_SUCH.search(text) or status == 404:
        return {"service": "S3", "status": "not found", "severity": "Info",
                "evidence": f"GET {url} -> HTTP {status}",
                "remediation": "No action needed."}
    return {"service": "S3", "status": "unknown", "severity": "Info",
            "evidence": f"GET {url} -> HTTP {status}",
            "remediation": "Review response manually."}


def check_s3(bucket: str, timeout=12) -> dict:
    url = f"https://{bucket}.s3.amazonaws.com/"
    return probe_s3_url(url, timeout)


def probe_gcs_url(url: str, timeout=12) -> dict:
    status, body = fetch(url, timeout)
    text = body.decode("utf-8", "ignore")
    if status is None:
        return {"service": "GCS", "status": "unreachable", "severity": "Info",
                "evidence": str(body)[:120], "remediation": "Check network."}
    if GCS_LIST.search(text) and status == 200:
        return {"service": "GCS", "status": "PUBLIC LISTING ENABLED", "severity": "High",
                "evidence": f"GET {url} -> HTTP {status}; bucket XML contents returned",
                "remediation": "Set 'Uniform bucket-level access' and remove "
                               "allUsers/allAuthenticatedUsers permissions."}
    if status in (403, 404) and "NoSuchBucket" not in text and status == 403:
        return {"service": "GCS", "status": "exists — private (good)", "severity": "Info",
                "evidence": f"GET {url} -> HTTP 403",
                "remediation": "No action needed."}
    return {"service": "GCS", "status": "not found / private", "severity": "Info",
            "evidence": f"GET {url} -> HTTP {status}",
            "remediation": "No action needed."}


def check_gcs(bucket: str, timeout=12) -> dict:
    return probe_gcs_url(f"https://storage.googleapis.com/{bucket}/", timeout)


def check_azure(account: str, container: str | None, timeout=12) -> dict:
    if container:
        url = (f"https://{account}.blob.core.windows.net/{container}"
               "?restype=container&comp=list")
        status, body = fetch(url, timeout)
        text = body.decode("utf-8", "ignore")
        if status is None:
            return {"service": "Azure Blob", "status": "unreachable", "severity": "Info",
                    "evidence": str(body)[:120], "remediation": "Check network."}
        if AZURE_LIST.search(text) and status == 200:
            return {"service": "Azure Blob", "status": "PUBLIC CONTAINER LISTING",
                    "severity": "High",
                    "evidence": f"GET container list -> HTTP {status}; blobs enumerated",
                    "remediation": "Set container access to 'Private' in Azure portal "
                                   "(Access policy: no anonymous read)."}
        if status == 403:
            return {"service": "Azure Blob", "status": "container private (good)",
                    "severity": "Info",
                    "evidence": f"GET {url} -> HTTP 403",
                    "remediation": "No action needed."}
        return {"service": "Azure Blob", "status": "container not found / private",
                "severity": "Info", "evidence": f"GET {url} -> HTTP {status}",
                "remediation": "No action needed."}
    # account-level probe
    status, body = fetch(f"https://{account}.blob.core.windows.net/", timeout)
    if status == 403:
        return {"service": "Azure Blob", "status": "account exists — access denied (good)",
                "severity": "Info", "evidence": f"HEAD account -> HTTP {status}",
                "remediation": "No action needed."}
    if status == 404:
        return {"service": "Azure Blob", "status": "account not found", "severity": "Info",
                "evidence": f"GET account -> HTTP 404", "remediation": "No action needed."}
    return {"service": "Azure Blob", "status": "unknown", "severity": "Info",
            "evidence": f"GET account -> HTTP {status}",
            "remediation": "Review manually."}


# ---------------------------------------------------------------------------
# Database / cache services
# ---------------------------------------------------------------------------
def tcp_banner(host, port, send: bytes | None = None, timeout=4.0, read_first=False):
    """Return (ok, data) — ok=True if TCP connect succeeded."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = b""
            if read_first:
                try:
                    data = s.recv(512)
                except socket.timeout:
                    data = b""
            if send:
                s.sendall(send)
                try:
                    data = s.recv(512)
                except socket.timeout:
                    data = b""
            return True, data
    except Exception as e:
        return False, str(e).encode()[:120]


def check_redis(host, port=6379, timeout=4.0) -> dict:
    ok, data = tcp_banner(host, port, b"PING\r\n", timeout)
    if not ok:
        return {"service": "Redis", "host": host, "port": port, "status": "closed/filtered",
                "severity": "Info", "evidence": data.decode(errors="ignore"),
                "remediation": "No action needed."}
    text = data.decode("utf-8", "ignore")
    if "+PONG" in text:
        return {"service": "Redis", "host": host, "port": port,
                "status": "OPEN — NO AUTH (CRITICAL)", "severity": "Critical",
                "evidence": "PING -> +PONG (unauthenticated access — data read/write, "
                            "possible RCE via CONFIG/EVAL)",
                "remediation": "Set requirepass, bind 127.0.0.1 or firewall 6379, "
                               "disable CONFIG/EVAL, use ACLs (Redis 6+)."}
    if "-NOAUTH" in text or "NOAUTH" in text:
        return {"service": "Redis", "host": host, "port": port,
                "status": "auth required (good)", "severity": "Info",
                "evidence": "PING -> NOAUTH", "remediation": "No action needed."}
    return {"service": "Redis", "host": host, "port": port, "status": "reachable — verify",
            "severity": "Low", "evidence": f"TCP banner: {text[:80]}",
            "remediation": "Confirm auth + network restrictions."}


def check_memcached(host, port=11211, timeout=4.0) -> dict:
    ok, data = tcp_banner(host, port, b"stats\r\n", timeout)
    if not ok:
        return {"service": "Memcached", "host": host, "port": port,
                "status": "closed/filtered", "severity": "Info",
                "evidence": data.decode(errors="ignore"), "remediation": "No action needed."}
    text = data.decode("utf-8", "ignore")
    if "STAT " in text:
        return {"service": "Memcached", "host": host, "port": port,
                "status": "OPEN — INFO LEAK", "severity": "High",
                "evidence": "stats -> STAT lines (memory, keys, items exposed; "
                            "UDP amplification vector)",
                "remediation": "Firewall 11211 (esp. UDP), disable UDP, restrict to "
                               "trusted networks."}
    return {"service": "Memcached", "host": host, "port": port, "status": "reachable — verify",
            "severity": "Low", "evidence": f"banner: {text[:80]}",
            "remediation": "Confirm network restriction."}


def check_elasticsearch(host, port=9200, timeout=6.0) -> dict:
    status, body = fetch(f"http://{host}:{port}/", timeout)
    if status is None:
        return {"service": "Elasticsearch", "host": host, "port": port,
                "status": "closed/filtered", "severity": "Info",
                "evidence": str(body)[:100], "remediation": "No action needed."}
    text = body.decode("utf-8", "ignore")
    if status == 200 and ("You Know, for Search" in text or "cluster_name" in text):
        return {"service": "Elasticsearch", "host": host, "port": port,
                "status": "OPEN CLUSTER", "severity": "High",
                "evidence": "Cluster info returned without auth (version: "
                            + re.search(r'"number"\s*:\s*"([^"]+)"', text).group(1)
                            if re.search(r'"number"\s*:\s*"([^"]+)"', text) else "unknown",
                "remediation": "Enable Elasticsearch security (xpack.security), "
                               "bind private network, review data exposure (indices/"
                               "_cat/indices)."}
    if status in (401, 403):
        return {"service": "Elasticsearch", "host": host, "port": port,
                "status": "auth required (good)", "severity": "Info",
                "evidence": f"HTTP {status}", "remediation": "No action needed."}
    return {"service": "Elasticsearch", "host": host, "port": port,
            "status": "reachable — verify", "severity": "Low",
            "evidence": f"HTTP {status}", "remediation": "Confirm security settings."}


def check_mongodb(host, port=27017, timeout=4.0) -> dict:
    ok, data = tcp_banner(host, port, None, timeout, read_first=True)
    if not ok:
        return {"service": "MongoDB", "host": host, "port": port,
                "status": "closed/filtered", "severity": "Info",
                "evidence": data.decode(errors="ignore"), "remediation": "No action needed."}
    text = data.decode("utf-8", "ignore")
    if text.strip():
        return {"service": "MongoDB", "host": host, "port": port,
                "status": "open — banner received (verify auth)", "severity": "High",
                "evidence": f"TCP banner: {text[:80]}",
                "remediation": "Enable auth, bind 127.0.0.1 or firewall 27017, "
                               "deploy MongoDB 6+ (no default user creation)."}
    return {"service": "MongoDB", "host": host, "port": port,
            "status": "open — no banner (verify auth)", "severity": "Medium",
            "evidence": "TCP 27017 accepts connections",
            "remediation": "Verify auth is enabled; thousands of MongoDB instances "
                           "are ransomwared weekly when left unauthenticated."}


SERVICE_CHECKS = {"6379": check_redis, "11211": check_memcached,
                  "9200": check_elasticsearch, "27017": check_mongodb}
DEFAULT_PORTS = ["6379", "11211", "9200", "27017"]


def check_service(host, port, timeout=4.0) -> dict:
    fn = SERVICE_CHECKS.get(str(port))
    if not fn:
        ok, data = tcp_banner(host, port, b"", timeout)
        return {"service": f"TCP:{port}", "host": host, "port": port,
                "status": "open — unknown service" if ok else "closed/filtered",
                "severity": "Info" if not ok else "Low",
                "evidence": data.decode(errors="ignore") or "port open",
                "remediation": "Identify the service; restrict if not required."}
    return fn(host, int(port), timeout)


def main():
    ap = argparse.ArgumentParser(description="CloudScope — cloud & DB exposure checker")
    ap.add_argument("--bucket", default=None, help="S3/GCS bucket name to probe")
    ap.add_argument("--azure", default=None, help="Azure storage account name")
    ap.add_argument("--container", default=None, help="Azure container (with --azure)")
    ap.add_argument("--service", default=None, help="Host[:port] to check DB/cache services")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if not (args.bucket or args.azure or args.service):
        print("Usage: cloud_check.py --bucket NAME | --azure ACCT [--container C] | "
              "--service HOST[:PORT]")
        sys.exit(2)

    findings = []
    if args.bucket:
        print(f"[*] Probing S3: {args.bucket}")
        findings.append(check_s3(args.bucket, args.timeout))
        print(f"[*] Probing GCS: {args.bucket}")
        findings.append(check_gcs(args.bucket, args.timeout))

    if args.azure:
        print(f"[*] Probing Azure Blob: {args.azure}" +
              (f"/{args.container}" if args.container else ""))
        findings.append(check_azure(args.azure, args.container, args.timeout))

    if args.service:
        svc = args.service.strip()
        if ":" in svc:
            host, port = svc.rsplit(":", 1)
            ports = [port]
        else:
            host, ports = svc, DEFAULT_PORTS
        for port in ports:
            findings.append(check_service(host, port, args.timeout))

    print("═" * 58)
    print("  CLOUDSCOPE — Exposure Check Results")
    print("═" * 58)
    for f in findings:
        mark = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵",
                "Info": "⚪"}.get(f["severity"], "⚪")
        host_port = f" {f['host']}:{f['port']} " if f.get("host") else " "
        print(f"  {mark} [{f['severity']:>8}] {f['service']}{host_port}-> {f['status']}")
        print(f"     evidence: {f['evidence'][:110]}")
    print("═" * 58)

    out = args.out or "cloud_checks.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"tool": "CloudScope", "scan_date": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "checks": findings}, f, indent=2, ensure_ascii=False)
    print(f"[✓] JSON: {out}")


if __name__ == "__main__":
    main()
