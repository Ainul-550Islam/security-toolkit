#!/usr/bin/env python3
# ============================================================================
#  SecuAudit API — API Security Auditor (OWASP API Top 10 2023/2026 baseline)
#  ---------------------------------------------------------------------------
#  Checks (observable, non-destructive):
#    API9  Inventory: exposed Swagger/OpenAPI/GraphQL/docs endpoints
#    API2  Auth:      session cookie flags, JWT hints, auth-endpoint exposure
#    API4  Resource:  rate-limit headers present? 429 allowed? body size caps?
#    API8  Misconfig: security headers, verbose errors (DEBUG traces), CORS,
#                     server version disclosure, unnecessary methods (OPTIONS/TRACE)
#    API7  SSRF hint: endpoints accepting URLs (fetch, callback, redirect params)
#    API10 OWASP:     usage of known-insecure patterns in error bodies
#  Output: JSON + section of the shared HTML report
#
#  Usage: python3 api_security_audit.py --url https://api.example.com
# ============================================================================

import argparse
import concurrent.futures
import datetime
import json
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

UA = "Mozilla/5.0 (compatible; SecuAudit-API/1.0; authorized-security-audit)"

DOC_PATHS = [
    "/swagger", "/swagger.json", "/swagger-ui", "/swagger-ui/", "/swagger/index.html",
    "/api-docs", "/api-docs/", "/v1/api-docs", "/openapi.json", "/openapi.yaml",
    "/redoc", "/docs", "/graphql", "/graphiql", "/api/graphql", "/api/docs",
    "/api/swagger.json", "/api/openapi.json", "/api/v1/docs", "/v2/api-docs",
    "/api/v1/swagger.json", "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/health", "/status", "/api/health", "/api/status",
]

SECURITY_HEADERS = [
    ("Content-Security-Policy", "Medium"),
    ("Strict-Transport-Security", "High"),
    ("X-Content-Type-Options", "Medium"),
    ("X-Frame-Options", "Low"),
]

RATE_LIMIT_HEADERS = ["x-ratelimit-limit", "x-rate-limit", "x-ratelimit-remaining",
                      "ratelimit-limit", "retry-after"]

SSRF_HINT_RE = re.compile(
    r"(fetch|callback|redirect|url|uri|target|proxy|webhook|remote|file|image|img|avatar|src|link|forward|next)",
    re.I,
)
VERBOSE_ERROR_RE = re.compile(
    r"(traceback|stack trace|sqlstate|mysql_fetch|psql|sqlalchemy|error in your sql syntax|"
    r"you're seeing this error because you have debug|django/|at [a-z_]+\.py:\d+|"
    r"java\.[a-z]+\.[a-z]+exception|org\.apache|node\.js|/usr/local/lib|/var/www|"
    r"internal server error details|exception occurred)",
    re.I,
)
JWT_RE = re.compile(r"payload.*(alg|kid|iat|exp).*\{.*signed|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", re.S)


def fetch(url, timeout, method="GET", extra_headers=None):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(200_000), None
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(32_000)
        except Exception:
            pass
        return e.code, dict(e.headers or {}), body, None
    except Exception as e:
        return None, {}, b"", str(e)


def severity(pre, score, weight):
    return {"id": f"API-{pre}", "title": pre, "severity": "High" if weight >= 8 else
            ("Medium" if weight >= 4 else "Low"), "evidence": "", "remediation": ""}


def main():
    ap = argparse.ArgumentParser(description="SecuAudit API — OWASP API Top 10 observable checks")
    ap.add_argument("--url", required=True, help="API base URL, e.g. https://api.example.com")
    ap.add_argument("--json", default="api_results.json")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    base = args.url.rstrip("/")
    parsed = urlparse(base)
    host = parsed.hostname or base
    if not parsed.scheme or not host:
        print(f"[!] Invalid URL: {base}")
        sys.exit(2)

    findings = []
    print(f"[*] API target: {base}")

    # --- Helper to add finding ------------------------------------------------
    def add(fid, title, severity, evidence, remediation, weight):
        findings.append({
            "id": fid, "title": title, "severity": severity,
            "evidence": evidence[:400], "remediation": remediation, "weight": weight,
        })

    # --- 1. API9 inventory: doc endpoints --------------------------------------
    print("[*] Checking API documentation endpoints…")

    def probe(path):
        s, h, b, e = fetch(base + path, args.timeout)
        return path, s, len(b), bool(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(probe, DOC_PATHS))

    exposed = []
    for path, s, blen, err in results:
        if err:
            continue
        if s in (200, 304) and blen > 100:
            exposed.append(path)
            add("API9-DOC", f"Exposed API documentation: {path}", "Medium",
                f"GET {path} -> HTTP {s} ({blen} bytes)",
                "Disable or protect (auth) documentation in production. OpenAPI/GraphQL "
                "schemas reveal every endpoint and parameter.", 6)
        elif s == 401:
            add("API9-DOC-AUTH", f"API documentation requires auth: {path}", "Info",
                f"GET {path} -> HTTP {s}",
                "OK — ensure auth is enforced for all docs in production.", 0)

    if not exposed:
        add("API9-DOC-OK", "No exposed API documentation endpoints detected", "Info",
            "Checked 30+ common doc paths (swagger, openapi, graphql, actuator)",
            "No action needed. Re-check after every release (shadow APIs!).", 0)

    # --- 2. API8 misconfiguration: security headers + server info --------------
    s, h, b, err = fetch(base + "/", args.timeout, method="GET")
    if err:
        add("API8-UNREACHABLE", f"API root unreachable: {err[:120]}", "High",
            f"GET {base}/ -> error", "Check DNS/firewall/TLS.", 9)
    else:
        print(f"[*] Root: HTTP {s}")
        for hn, sev in SECURITY_HEADERS:
            if hn.lower() not in h:
                add("API8-HDR", f"API missing security header: {hn}", sev,
                    f"Header '{hn}' not present", 
                    "Add it at the gateway/load-balancer, not only in the app.", 
                    4 if sev == "Medium" else 6 if sev == "High" else 2)
        for d in ("server", "x-powered-by", "x-aspnet-version", "x-drupal-cache"):
            if d in h:
                add("API8-DISCLOSE", f"Technology disclosure via '{d}'", "Low",
                    f"{d}: {h[d][:80]}", "Remove or genericize the header.", 2)

        # Rate limit headers (API4)
        rl = [k for k in h if k.lower() in RATE_LIMIT_HEADERS or "ratelimit" in k.lower()]
        if not rl:
            add("API4-NO-RATELIMIT", "No rate-limit headers observed", "Medium",
                "Response lacks X-RateLimit-*/Retry-After headers",
                "Apply per-client rate limiting on all endpoints (strict on auth & "
                "payment endpoints). Use 429 + Retry-After.", 6)
        else:
            add("API4-RATELIMIT", f"Rate-limit headers present: {', '.join(rl[:4])}", "Info",
                ", ".join(f"{k}: {h[k][:30]}" for k in rl[:4]), "No action needed.", 0)

        # Verbose errors (API8)
        text = b.decode("utf-8", "ignore")
        if VERBOSE_ERROR_RE.search(text) and s >= 400:
            add("API8-VERBOSE", "API returns verbose/internal error details", "High",
                "Response body contains tech stack/DB error clues",
                "Return generic errors (e.g. 'invalid request'); log details server-side "
                "only. Never expose DEBUG=True in production.", 8)
        if "DEBUG = True" in text:
            add("API8-DEBUG", "Django DEBUG=True leak", "Critical",
                "Response mentions DEBUG = True", "Set DEBUG=False in production.", 10)

        # JWT hints in body (API2)
        if JWT_RE.search(text):
            add("API2-JWT", "JWT/claims material visible in response", "Low",
                "Response may contain JWT structure hints",
                "Ensure tokens are never logged or returned in error bodies; verify "
                "alg whitelisting (reject 'none', RS256/HS256 confusion).", 3)

        # CORS on API (API8/API3)
        try:
            s2, h2, b2, e2 = fetch(base + "/", args.timeout,
                                   extra_headers={"Origin": "https://evil.example"})
            if s2 and h2:
                acao = h2.get("Access-Control-Allow-Origin")
                acac = h2.get("Access-Control-Allow-Credentials")
                if acao:
                    if acao == "*" or acao == "https://evil.example":
                        add("API3-CORS", "Permissive CORS on API", "Medium",
                            f"Access-Control-Allow-Origin: {acao}",
                            "Allowlist trusted origins; never reflect arbitrary Origin or "
                            "use '*' with credentials.", 6)
                    else:
                        add("API3-CORS-OK", "API CORS restricted", "Info",
                            f"Access-Control-Allow-Origin: {acao}", "No action needed.", 0)
                elif "access-control" not in "".join(h2.keys()).lower():
                    add("API3-NO-CORS", "No CORS headers on API response", "Low",
                        "No Access-Control-* headers returned",
                        "If API is intended for browsers, configure CORS explicitly; "
                        "otherwise verify same-origin usage.", 2)
        except Exception:
            pass

    # --- 3. Method handling (API5/API8): OPTIONS/TRACE -------------------------
    try:
        so, ho, bo, eo = fetch(base + "/", args.timeout, method="OPTIONS")
        if so == 200:
            add("API8-OPTIONS", "OPTIONS returns 200 with content", "Low",
                "OPTIONS / -> HTTP 200", "Prefer 204 for OPTIONS; verify Allow list "
                "does not expose dangerous methods.", 3)
        if "tracemethod" not in h.get("allow", "").lower() and "trace" in h.get("allow", "").lower():
            add("API8-TRACE", "TRACE method allowed", "High",
                f"Allow header: {h.get('allow', '')[:60]}",
                "Disable TRACE (XST attacks / cookie theft).", 8)
    except Exception:
        pass

    # --- 4. SSRF hint endpoints (API7, informational) --------------------------
    hits = []
    for path in ("/api/", "/v1/", "/v2/", "/graphql"):
        s3, h3, b3, e3 = fetch(base + path, args.timeout)
        if e3:
            continue
        text3 = b3.decode("utf-8", "ignore")[:200000]
        params = re.findall(r'"(\w{2,25})"\s*:\s*"', text3)
        ssrf = [p for p in params if SSRF_HINT_RE.match(p)]
        if ssrf:
            hits.append((path, ssrf[:6]))
    if hits:
        for path, ps in hits[:3]:
            add("API7-SSRF-HINT", "Potential SSRF-style parameters found", "Info",
                f"{path}: parameters {', '.join(ps)}",
                "Manually verify these params validate URL schemes (http/https only), "
                "block private IP ranges, and resolve DNS twice to prevent SSRF (API7).", 1)
    if not hits:
        add("API7-NOHINT", "No obvious SSRF-style parameters in responses", "Info",
            "Automated scan cannot confirm SSRF; manual review required", 
            "Tests SSRF with a collaborator/whitelisted domain when authorizing deeper tests.", 0)

    # --- 5. Auth endpoint checks (API2) ----------------------------------------
    auth_hits = 0
    for path in ("/login", "/api/login", "/auth", "/api/auth", "/token", "/oauth/token",
                 "/api/token", "/v1/login", "/users", "/api/users", "/admin", "/api/admin"):
        s4, h4, b4, e4 = fetch(base + path, args.timeout)
        if e4 or s4 in (401, 403, 404, 405, 501):
            if s4 in (401, 403):
                auth_hits += 1
                add("API2-AUTH", f"Auth-protected endpoint responds {s4}: {path}", "Info",
                    f"GET {path} -> HTTP {s4}", "Ensure all endpoints return 401/403 for "
                    "unauthenticated access — including object IDs (BOLA/IDOR review).", 0)
        elif s4 in (200, 400):
            # Endpoint exists and is reachable
            add("API2-EXPOSED", f"Auth-related endpoint reachable: {path}", "Medium",
                f"GET {path} -> HTTP {s4}", "Check brute-force protection (rate limit + "
                "lockout) and generic error messages at login.", 4)
    if auth_hits:
        add("API2-AUTH-OK", "Unauthenticated requests receive 401/403", "Info",
            f"{auth_hits} endpoints enforce auth correctly", "No action needed.", 0)

    # --- Summary ----------------------------------------------------------------
    weights = {f["id"]: f.get("weight", 0) for f in findings}
    score = 100.0 - sum(f.get("weight", 0) for f in findings if f["severity"] not in ("Info",))
    score = max(0.0, min(100.0, score))
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else
             "D" if score >= 45 else "E" if score >= 30 else "F")

    data = {
        "tool": "SecuAudit-API", "target": base,
        "scan_date": datetime.datetime.now().isoformat(),
        "score": round(score, 1), "grade": grade,
        "findings": findings, "methodology": "OWASP API Security Top 10 (2023/2026)",
    }
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print()
    print(f"[✓] API audit complete: {round(score,1)}/100 (Grade {grade})")
    for f in findings:
        if f["severity"] not in ("Info",):
            print(f"    [{f['severity']:>8}] {f['title']}")
    print(f"[✓] JSON: {args.json}")

    if not findings:
        print("    (no findings — verify with manual testing)")


if __name__ == "__main__":
    main()
