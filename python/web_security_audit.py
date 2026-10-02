#!/usr/bin/env python3
# ============================================================================
#  SecuAudit — Web Security Audit Tool (Python 3 stdlib only, zero deps)
#  ---------------------------------------------------------------------------
#  What it checks:
#    1. Security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options,
#       Referrer-Policy, Permissions-Policy, COOP)
#    2. Information disclosure (Server / X-Powered-By headers)
#    3. TLS certificate (issuer, expiry, self-signed, hostname match)
#    4. Cookie security flags (Secure / HttpOnly / SameSite)
#    5. Exposed sensitive files (.env, .git, backups, dumps, configs)
#    6. Directory listing exposure
#    7. CORS misconfigurations
#    8. HTTP->HTTPS redirect enforcement
#
#  Output : HTML report (self-contained, client-ready) + JSON results
#  Usage  : python3 web_security_audit.py --url https://example.com
#           python3 web_security_audit.py --url https://example.com --out report.html
#
#  LEGAL: Authorized penetration/assessment testing only. Never point this at
#         a host you do not own or have written permission to test.
# ============================================================================

import argparse
import concurrent.futures
import datetime
import json
import re
import socket
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from html import escape
from urllib.parse import urlparse

VERSION = "1.0"
UA = "Mozilla/5.0 (compatible; SecuAudit/1.0; authorized-security-audit)"

# ---------------------------------------------------------------------------
# Finding definitions
# ---------------------------------------------------------------------------
SEVERITY_WEIGHT = {"Critical": -25.0, "High": -14.0, "Medium": -8.0, "Low": -4.0, "Info": -0.5}

SECURITY_HEADERS = [
    ("Content-Security-Policy",
     "CSP is missing. Without a Content-Security-Policy, the page can load/execute "
     "arbitrary scripts, greatly amplifying XSS and data-injection attacks. Add a "
     "policy (start with: default-src 'self'; then tighten it)."),
    ("Strict-Transport-Security",
     "HSTS is missing. Browsers may still contact the site over plain HTTP, allowing "
     "downgrade/SSL-stripping attacks. Add: Strict-Transport-Security: "
     "max-age=31536000; includeSubDomains; preload"),
    ("X-Content-Type-Options",
     "X-Content-Type-Options is missing. Set: X-Content-Type-Options: nosniff to "
     "prevent MIME-sniffing attacks."),
    ("X-Frame-Options",
     "X-Frame-Options (or CSP frame-ancestors) is missing, exposing the site to "
     "clickjacking. Set: X-Frame-Options: DENY (or SAMEORIGIN)."),
    ("Referrer-Policy",
     "Referrer-Policy is missing. Full or partial URLs may leak to third parties. "
     "Set: strict-origin-when-cross-origin."),
    ("Permissions-Policy",
     "Permissions-Policy is missing. Browser features (camera, mic, geolocation) "
     "stay enabled by default. Explicitly deny what you do not use."),
    ("Cross-Origin-Opener-Policy",
     "COOP is missing. Cross-origin windows can retain a reference to your page "
     "window (Spectre-class risk). Set: Cross-Origin-Opener-Policy: same-origin."),
]

SENSITIVE_PATHS = [
    (".env", "Critical", "Environment file exposed — may contain DB passwords, API "
                          "keys and the Django SECRET_KEY. Remove from web root and "
                          "block via server config (location ~ /\\.env { deny all; })."),
    (".git/config", "Critical", "Git repository exposed — the full source code can be "
                                "downloaded (/.git/HEAD etc.). Block dot-directories."),
    (".git/HEAD", "Critical", "Git repository exposed — source code disclosure risk."),
    ("backup.zip", "High", "Backup archive publicly downloadable."),
    ("db.sql", "High", "Database dump publicly downloadable — entire DB at risk."),
    ("database.sql", "High", "Database dump publicly downloadable."),
    ("dump.sql", "High", "Database dump publicly downloadable."),
    ("config.php.bak", "High", "Backup of a config file may contain credentials."),
    ("wp-config.php.bak", "High", "Backup of WordPress config may contain DB credentials."),
    ("phpinfo.php", "High", "phpinfo() exposed — leaks full PHP/server configuration."),
    ("server-status", "High", "Apache server-status exposed — request/activity data leak."),
    (".htaccess", "Medium", "Apache .htaccess exposed — may reveal rewrite/security rules."),
    (".svn/entries", "High", "SVN repository exposed — source code disclosure risk."),
    (".DS_Store", "Low", "macOS metadata file exposed — may leak file/folder names."),
    (".idea/workspace.xml", "Low", "IDE workspace file exposed — may leak developer paths."),
    ("secrets.yml", "High", "Secrets file exposed — credentials disclosure risk."),
    ("config.json", "Low", "Config file exposed — review contents for sensitive data."),
    ("package.json", "Info", "Frontend package manifest exposed — enumerates versions."),
    (".gitignore", "Info", ".gitignore exposed — reveals project structure."),
    ("web.config", "Low", "IIS config file exposed — may reveal rules and paths."),
    ("admin/", "Info", "Admin panel directory detected (verify this is intended)."),
]

DISCLAIMER = (
    "This assessment was performed against the target provided by the client/publisher "
    "with authorization. Findings reflect the state of the target at scan time only."
)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def fetch(url, timeout, extra_headers=None, allow_redirects=True):
    """Returns (status, headers, body, final_url, error)"""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    opener = urllib.request.build_opener()
    if not allow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(512_000)
            return resp.status, resp.headers, body, resp.geturl(), None
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(64_000)
        except Exception:
            pass
        return e.code, e.headers, body, url, None
    except Exception as e:  # connection errors, TLS errors, timeouts
        return None, None, b"", url, str(e)


def get_cert_info(host, port, timeout):
    """Return dict with cert details or None. Uses only stdlib."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return None
                pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as f:
            f.write(pem)
            tmp = f.name
        try:
            return ssl._ssl._test_decode_cert(tmp)
        finally:
            import os
            os.unlink(tmp)
    except Exception:
        return None


def cert_findings(cert, host):
    """Analyze a decoded certificate dict -> list of findings.
    Handles the ssl._ssl._test_decode_cert structure (nested RDN tuples).
    """
    findings = []
    if not cert:
        return findings

    # ---- normalization helpers -------------------------------------------
    def collect(field, attr):
        """Return values of `attr` from a nested cert field (list of str)."""
        vals = []

        def walk(x):
            if isinstance(x, dict):
                for k, v in x.items():
                    if k == attr:
                        vals.append(str(v))
                    else:
                        walk(v)
            elif isinstance(x, (list, tuple)):
                if len(x) == 2 and isinstance(x[0], str) and isinstance(x[1], str):
                    if x[0] == attr:
                        vals.append(x[1])
                else:
                    for item in x:
                        walk(item)

        walk(field)
        return vals

    def fmt(field):
        parts = []

        def walk(x):
            if isinstance(x, dict):
                for k, v in x.items():
                    parts.append(f"{k}={v}")
            elif isinstance(x, (list, tuple)):
                if len(x) == 2 and isinstance(x[0], str) and isinstance(x[1], str):
                    parts.append(f"{x[0]}={x[1]}")
                else:
                    for item in x:
                        walk(item)

        walk(field)
        return ", ".join(parts)

    not_after = cert.get("notAfter", "")
    not_before = cert.get("notBefore", "")

    def parse_utc(s):
        try:
            return datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=datetime.timezone.utc
            )
        except Exception:
            return None

    # ---- validity ----------------------------------------------------------
    na = parse_utc(not_after)
    nb = parse_utc(not_before)
    if na:
        days = (na - datetime.datetime.now(datetime.timezone.utc)).days
        if days < 0:
            findings.append({
                "id": "TLS-EXPIRED", "title": "TLS certificate is EXPIRED",
                "severity": "Critical",
                "evidence": f"Expired {abs(days)} day(s) ago ({not_after})",
                "remediation": "Renew the certificate immediately. Expired certs break "
                               "trust and are treated as hostile by modern browsers.",
            })
        elif days <= 14:
            findings.append({
                "id": "TLS-EXPIRES-SOON", "title": "TLS certificate expires very soon",
                "severity": "High",
                "evidence": f"Expires in {days} day(s) ({not_after})",
                "remediation": "Renew within 1-2 weeks. Use auto-renewal (Let's Encrypt "
                               "certbot, or your provider's managed renewal).",
            })
        elif days <= 45:
            findings.append({
                "id": "TLS-EXPIRY", "title": "TLS certificate expires soon",
                "severity": "Medium",
                "evidence": f"Expires in {days} day(s) ({not_after})",
                "remediation": f"Renew within {days} day(s).",
            })
        else:
            findings.append({
                "id": "TLS-OK", "title": "TLS certificate valid", "severity": "Info",
                "evidence": f"Valid until {not_after} ({days} days)",
                "remediation": "Keep automatic renewal enabled.",
            })

    # ---- self-signed -------------------------------------------------------
    issuer_txt = fmt(cert.get("issuer", ""))
    subject_txt = fmt(cert.get("subject", ""))
    if issuer_txt and subject_txt and issuer_txt == subject_txt:
        findings.append({
            "id": "TLS-SELF-SIGNED", "title": "Self-signed TLS certificate",
            "severity": "High",
            "evidence": f"Subject == Issuer: {subject_txt[:120]}",
            "remediation": "Replace with a certificate from a trusted CA "
                           "(Let's Encrypt is free) - self-signed certs cause "
                           "MITM exposure and break user trust.",
        })

    # ---- hostname match -----------------------------------------------------
    dns_names = [v for v in collect(cert.get("subjectAltName", ""), "DNS")]
    cn_vals = collect(cert.get("subject", ""), "commonName")
    names = set(dns_names) | set(cn_vals)
    match = False
    for n in names:
        n_low = n.lower()
        if n_low == host.lower():
            match = True
            break
        if n_low.startswith("*."):
            base_domain = n_low[2:]
            if host.lower().endswith("." + base_domain):
                match = True
                break
    if names and not match:
        findings.append({
            "id": "TLS-HOSTNAME-MISMATCH", "title": "Hostname mismatch in TLS certificate",
            "severity": "High",
            "evidence": f"Certificate names ({', '.join(sorted(names))[:120]}) do not "
                        f"cover host {host}",
            "remediation": "Re-issue the certificate including this hostname in SAN.",
        })

    # ---- issuer info --------------------------------------------------------
    issuers = collect(cert.get("issuer", ""), "organizationName")
    if issuers or issuer_txt:
        findings.append({
            "id": "TLS-INFO", "title": "TLS certificate details", "severity": "Info",
            "evidence": f"Issuer: {(issuers[0] if issuers else issuer_txt)[:140]}",
            "remediation": "Verify you recognize the issuer / CA.",
        })
    return findings


# ---------------------------------------------------------------------------
# Main checks
# ---------------------------------------------------------------------------
def run_checks(target, timeout):
    findings = []
    parsed = urlparse(target)
    scheme = (parsed.scheme or "https").lower()
    host = parsed.hostname
    if not host:
        print(f"[!] Invalid URL: {target}")
        sys.exit(2)
    port = parsed.port or (443 if scheme == "https" else 80)
    base = f"{scheme}://{host}" + (f":{port}" if parsed.port else "")
    print(f"[*] Target: {base}")

    # --- 1. Main page fetch -------------------------------------------------
    status, headers, body, final_url, err = fetch(base, timeout)
    reached_https = scheme == "https" and err is None
    if err:
        findings.append({
            "id": "UNREACHABLE", "title": f"Could not reach target over {scheme.upper()}",
            "severity": "High", "evidence": str(err)[:160],
            "remediation": "Check DNS, firewall rules, and that the service is running "
                           "on the expected port.",
        })
        return findings, base

    print(f"[*] HTTP {status} — {len(body)} bytes")

    # --- 2. Security headers ------------------------------------------------
    hdr = {k.lower(): v for k, v in headers.items()} if headers else {}
    for name, advice in SECURITY_HEADERS:
        present = name.lower() in hdr
        if not present:
            findings.append({
                "id": f"HDR-{name[:12].upper()}",
                "title": f"Missing security header: {name}",
                "severity": "High" if name in ("Strict-Transport-Security",) else
                            ("Medium" if name in ("Content-Security-Policy",
                                                  "X-Content-Type-Options",
                                                  "X-Frame-Options") else "Low"),
                "evidence": f"Header '{name}' not present in response",
                "remediation": advice,
            })
        else:
            val = hdr[name.lower()][:120]
            findings.append({
                "id": f"HDR-OK-{name[:10].upper()}",
                "title": f"Security header present: {name}", "severity": "Info",
                "evidence": f"{name}: {val}",
                "remediation": "No action needed.",
            })

    # Force-https special case: HSTS must be present on https responses.
    if scheme == "http" and not err:
        findings.append({
            "id": "HTTP-NOT-TLS", "title": "Target served over plain HTTP",
            "severity": "High",
            "evidence": "The primary URL uses http:// — all traffic is unencrypted.",
            "remediation": "Redirect all HTTP traffic to HTTPS (301) and set HSTS.",
        })

    # --- 3. Info disclosure -------------------------------------------------
    for h in ("server", "x-powered-by"):
        if h in hdr and hdr[h].strip():
            findings.append({
                "id": f"INFO-{h.upper()}",
                "title": f"Technology disclosure via {h} header",
                "severity": "Low",
                "evidence": f"{h}: {hdr[h][:120]}",
                "remediation": "Remove or obfuscate the header, or upgrade outdated "
                               "versions it advertises.",
            })

    # --- 4. CORS ------------------------------------------------------------
    try:
        origin = "https://evil.example"
        s2, h2, _, _, e2 = fetch(base, timeout, extra_headers={"Origin": origin})
        if s2 and h2:
            acao = h2.get("Access-Control-Allow-Origin")
            acac = h2.get("Access-Control-Allow-Credentials")
            if acao:
                bad = acao == "*" or acao == origin
                if bad:
                    findings.append({
                        "id": "CORS-PERMISSIVE",
                        "title": "Permissive CORS policy",
                        "severity": "High" if (acao == "*" and acac == "true") else "Medium",
                        "evidence": f"Access-Control-Allow-Origin: {acao}"
                                    + (f"; Allow-Credentials: {acac}" if acac else ""),
                        "remediation": "Restrict Access-Control-Allow-Origin to a "
                                       "global allowlist of trusted origins; never use "
                                       "'*' together with Allow-Credentials, and do not "
                                       "reflect arbitrary origins.",
                    })
                else:
                    findings.append({
                        "id": "CORS-OK", "title": "CORS policy appears restricted",
                        "severity": "Info",
                        "evidence": f"Access-Control-Allow-Origin: {acao}",
                        "remediation": "No action needed.",
                    })
    except Exception:
        pass

    # --- 5. Cookies ---------------------------------------------------------
    set_cookies = (headers.get_all("Set-Cookie") or []) if headers is not None else []
    for c in set_cookies:
        first = c.split(";")[0]
        flags = [f.strip().lower() for f in c.split(";")[1:]]
        name = first.split("=")[0][:60]
        if "secure" not in flags and scheme == "https":
            findings.append({
                "id": "COOKIE-NO-SECURE",
                "title": f"Cookie '{name}' missing Secure flag",
                "severity": "Medium",
                "evidence": f"Set-Cookie: {first}",
                "remediation": "Add 'Secure' so the cookie is only sent over HTTPS.",
            })
        if "httponly" not in flags:
            findings.append({
                "id": "COOKIE-NO-HTTPONLY",
                "title": f"Cookie '{name}' missing HttpOnly flag",
                "severity": "Medium",
                "evidence": f"Set-Cookie: {first}",
                "remediation": "Add 'HttpOnly' so JavaScript cannot read it (XSS "
                               "protection).",
            })
        same_site = next((f.split("=")[1] for f in flags if f.startswith("samesite")), None)
        if not same_site:
            findings.append({
                "id": "COOKIE-NO-SAMESITE",
                "title": f"Cookie '{name}' missing SameSite attribute",
                "severity": "Medium",
                "evidence": f"Set-Cookie: {first}",
                "remediation": "Add 'SameSite=Lax' (or 'Strict' for sensitive "
                               "cookies) to mitigate CSRF.",
            })

    # --- 6. TLS certificate (https only) ------------------------------------
    if scheme == "https" and err is None:
        cert = get_cert_info(host, port, timeout)
        findings.extend(cert_findings(cert, host) if cert else [{
            "id": "TLS-NO-CERT", "title": "Could not retrieve TLS certificate",
            "severity": "Info",
            "evidence": "Certificate retrieval failed (timeout or protocol issue).",
            "remediation": "Verify TLS is configured correctly.",
        }])
    elif scheme == "https":
        findings.append({
            "id": "TLS-CONNECT-FAIL", "title": "TLS handshake failed",
            "severity": "High", "evidence": str(err)[:160],
            "remediation": "Check certificate validity and server TLS configuration.",
        })

    # --- 7. HTTP -> HTTPS redirect (only if https target & port 80 reachable) -
    if scheme == "https":
        try:
            s_http, h_http, _, _, e_http = fetch(f"http://{host}/", timeout, allow_redirects=False)
            if s_http and s_http in (301, 302, 307, 308):
                loc = (h_http.get("Location") or "").lower() if h_http else ""
                if "https" in loc:
                    findings.append({
                        "id": "REDIRECT-OK", "title": "HTTP redirects to HTTPS",
                        "severity": "Info",
                        "evidence": f"HTTP {s_http} -> {loc[:90]}",
                        "remediation": "No action needed.",
                    })
                else:
                    findings.append({
                        "id": "REDIRECT-UNSAFE",
                        "title": "HTTP redirect does not go to HTTPS",
                        "severity": "Medium",
                        "evidence": f"HTTP {s_http} -> {loc[:90]}",
                        "remediation": "Redirect all HTTP requests to the HTTPS version.",
                    })
            elif s_http == 200:
                findings.append({
                    "id": "NO-HTTPS-REDIRECT",
                    "title": "Site is also served on plain HTTP (no redirect)",
                    "severity": "Medium",
                    "evidence": "http:// {host}/ returns 200 instead of a redirect to https",
                    "remediation": "Return a 301 to https:// for all http requests.",
                })
        except Exception:
            pass

    # --- 8. Sensitive files (concurrent) -------------------------------------
    print("[*] Checking sensitive files & paths…")
    path_results = {}

    def probe(item):
        path, sev, advice = item
        u = base.rstrip("/") + "/" + path
        s, h, b, _, e = fetch(u, timeout)
        return path, s, len(b), e

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for path, s, blen, e in ex.map(probe, SENSITIVE_PATHS):
            path_results[path] = (s, blen, e)

    for path, sev, advice in SENSITIVE_PATHS:
        s, blen, e = path_results.get(path, (None, 0, None))
        if s is None:
            continue
        if s == 200 and blen > 0:
            findings.append({
                "id": f"FILE-{path.replace('.', '-').replace('/', '-')[:18].upper()}",
                "title": f"Sensitive file exposed: {path}",
                "severity": sev,
                "evidence": f"GET {path} -> HTTP {s} ({blen} bytes)",
                "remediation": advice,
            })
        elif s in (403, 401):
            findings.append({
                "id": f"FILE-OK-{path.replace('.', '-').replace('/', '-')[:14].upper()}",
                "title": f"Access to {path} is restricted", "severity": "Info",
                "evidence": f"GET {path} -> HTTP {s}",
                "remediation": "No action needed (verify a WAF is not masking the file).",
            })
        elif s == 301 or s == 302:
            pass  # handled by main request logic; ignore

    # --- 9. Directory listing ------------------------------------------------
    try:
        text = body.decode("utf-8", "ignore").lower()
        if "index of /" in text or "directory listing for" in text:
            findings.append({
                "id": "DIR-LISTING", "title": "Directory listing enabled",
                "severity": "Medium",
                "evidence": f"GET / -> HTTP {status}: page shows 'Index of /'",
                "remediation": "Disable directory listing (Apache: Options -Indexes; "
                               "Nginx: autoindex off; IIS: remove Directory Browsing).",
            })
    except Exception:
        pass

    return findings, base


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def score(findings):
    real = [f for f in findings if f["severity"] not in ("Info",)]
    s = 100.0
    for f in real:
        s += SEVERITY_WEIGHT[f["severity"]]
    s = max(0.0, min(100.0, s))
    grade = ("A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else
             "D" if s >= 45 else "E" if s >= 30 else "F")
    return round(s, 1), grade, len(real)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
def build_html(target, base, findings, score_val, grade, counts, elapsed):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        color = {"Critical": "#b91c1c", "High": "#dc2626", "Medium": "#d97706",
                 "Low": "#2563eb", "Info": "#6b7280"}[sev]
        rows += f"""
        <tr>
          <td>{i}</td>
          <td class="sev" style="color:{color};font-weight:700">{sev}</td>
          <td><strong>{escape(f['title'])}</strong><br>
              <span class="ev">{escape(f['evidence'][:240])}</span></td>
          <td class="rem">{escape(f['remediation'])}</td>
        </tr>"""
    sum_cards = ""
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        n = counts.get(sev, 0)
        color = {"Critical": "#b91c1c", "High": "#dc2626", "Medium": "#d97706",
                 "Low": "#2563eb", "Info": "#6b7280"}[sev]
        sum_cards += f'<div class="card"><div class="num" style="color:{color}">{n}</div><div class="lbl">{sev}</div></div>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Audit Report — {escape(host_or(base))}</title>
<style>
  * {{ box-sizing: border-box; margin:0; padding:0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#f1f5f9; color:#0f172a; padding:24px; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; }}
  header {{ background: linear-gradient(135deg,#0f172a,#1e293b); color:#fff; border-radius:14px; padding:28px 32px; margin-bottom:22px; }}
  header h1 {{ font-size:22px; letter-spacing:.5px; }}
  header .sub {{ color:#94a3b8; margin-top:6px; font-size:13px; }}
  .score-row {{ display:flex; gap:12px; align-items:center; margin-top:18px; flex-wrap:wrap; }}
  .badge {{ background:#38bdf8; color:#0f172a; font-weight:800; border-radius:10px; padding:8px 18px; font-size:26px; }}
  .badge small {{ font-size:12px; font-weight:600; display:block; color:#0c4a6e; }}
  .meta {{ font-size:12px; color:#cbd5e1; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:12px; margin-bottom:22px; }}
  .card {{ background:#fff; border-radius:12px; padding:14px; text-align:center; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  .card .num {{ font-size:30px; font-weight:800; }}
  .card .lbl {{ font-size:12px; color:#475569; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:12px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  th {{ background:#0f172a; color:#fff; text-align:left; padding:10px 12px; font-size:12px; letter-spacing:.4px; }}
  td {{ padding:10px 12px; border-bottom:1px solid #e2e8f0; font-size:13px; vertical-align:top; }}
  .sev {{ white-space:nowrap; }}
  .ev {{ color:#64748b; font-size:12px; }}
  .rem {{ color:#334155; font-size:12px; max-width:320px; }}
  footer {{ margin-top:20px; font-size:11px; color:#64748b; text-align:center; }}
  .note {{ background:#fef3c7; border-left:4px solid #f59e0b; padding:10px 14px; border-radius:6px; font-size:12px; margin-bottom:18px; }}
</style></head><body><div class="wrap">
  <header>
    <h1>🛡️ SECURITY AUDIT REPORT</h1>
    <div class="sub">Target: <strong>{escape(base)}</strong> &nbsp;|&nbsp; Scan date: {now} &nbsp;|&nbsp; Tool: SecuAudit v{VERSION} (Python + Rust)</div>
    <div class="score-row">
      <div class="badge">{grade}<small>GRADE</small></div>
      <div class="meta">Security score: <strong>{score_val}/100</strong><br>
        Findings: {len(findings)} ({counts.get('Critical',0)} critical) &nbsp;|&nbsp; Duration: {elapsed:.1f}s</div>
    </div>
  </header>
  <div class="note">⚠️ {escape(DISCLAIMER)}</div>
  <div class="cards">{sum_cards}</div>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Finding / Evidence</th><th>Recommended Fix</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <footer>Generated by SecuAudit — authorized security assessment tool.<br>
  Contact: your-email@example.com</footer>
</div></body></html>"""


def host_or(base):
    try:
        return urlparse(base).hostname or base
    except Exception:
        return base


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="SecuAudit — web security audit (stdlib only)")
    ap.add_argument("--url", required=True, help="Target URL, e.g. https://example.com")
    ap.add_argument("--out", default="report.html", help="Output HTML report path")
    ap.add_argument("--json", default="results.json", help="Output JSON results path")
    ap.add_argument("--timeout", type=float, default=12.0, help="Request timeout (seconds)")
    args = ap.parse_args()

    t0 = datetime.datetime.now()
    findings, base = run_checks(args.url, args.timeout)
    score_val, grade, real_count = score(findings)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    elapsed = (datetime.datetime.now() - t0).total_seconds()

    # Sort: Critical > High > Medium > Low > Info
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    data = {
        "tool": "SecuAudit", "version": VERSION, "target": base,
        "scan_date": t0.isoformat(), "score": score_val, "grade": grade,
        "active_findings": real_count, "findings": findings,
        "summary": counts, "disclaimer": DISCLAIMER,
    }
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    html = build_html(args.url, base, findings, score_val, grade, counts, elapsed)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)

    print()
    print(f"[✓] Scan complete in {elapsed:.1f}s")
    print(f"[✓] Security score: {score_val}/100  (Grade {grade})")
    print(f"[✓] Findings: {real_count} active")
    for f in findings:
        if f["severity"] not in ("Info",):
            print(f"    [{f['severity']:>8}] {f['title']}")
    print(f"[✓] Report : {args.out}")
    print(f"[✓] JSON   : {args.json}")


if __name__ == "__main__":
    main()
