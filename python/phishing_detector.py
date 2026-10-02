#!/usr/bin/env python3
# ============================================================================
#  PhishScan — Phishing URL Detector (Python 3, stdlib, heuristic engine)
#  ---------------------------------------------------------------------------
#  Engine: weighted heuristic scoring (length, obfuscation, brand
#  impersonation via Levenshtein, TLD trust, keywords, shorteners, IP hosts,
#  punycode, port obfuscation, URL-encoding tricks).
#  Output: verdict + score + reasons (console + JSON)
#
#  Usage: python3 phishing_detector.py --url https://paypa1-secure-login.tk/verify
#         python3 phishing_detector.py --file urls.txt --json out.json
# ============================================================================

import argparse
import json
import re
import sys
import urllib.parse

# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "click", "link", "work",
    "zip", "mov", "country", "stream", "download", "racing", "win", "bid",
    "vip", "icu", "live", "site", "online", "store", "tech", "fun", "gdn",
    "loan", "win", "mom", "cricket", "science", "party",
}

TRUSTED_TLDS = {"com", "org", "net", "edu", "gov", "io", "co", "biz", "info",
                "app", "dev", "ai", "in", "bd", "uk", "de", "fr", "ca", "au",
                "jp", "sg", "us", "mil", "int", "me", "tv", "cc", "name", "pro"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "tiny.cc", "cut.ly", "rebrand.ly", "rb.gy", "cutt.ly", "shorturl.at",
    "s.id", "t.ly", "soo.gd", "lnkd.in", "shorte.st", "adf.ly", "bc.vc",
}

BRANDS = {
    "paypal": ["paypal", "pay-pal", "paypal-secure"], "apple": ["apple", "icloud"],
    "microsoft": ["microsoft", "msn", "outlook", "office365", "live.com"],
    "google": ["google", "gmail", "chrome", "youtube"], "amazon": ["amazon"],
    "netflix": ["netflix"], "facebook": ["facebook", "fb"], "instagram": ["instagram"],
    "whatsapp": ["whatsapp"], "bKash": ["bkash", "bikash"], "nagad": ["nagad"],
    "rocket": ["rocket", "dbbl"], "sslcommerz": ["sslcommerz"], "daraz": ["daraz"],
    "steam": ["steam"], "ebay": ["ebay"], "linkedin": ["linkedin"],
    "binance": ["binance"], "coinbase": ["coinbase"], "wise": ["wise"],
    "revolut": ["revolut"], "chase": ["chase"], "hsbc": ["hsbc"],
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "confirm", "banking", "password", "credential", "support", "alert", "security",
    "unlock", "suspend", "recover", "validate", "wallet", "bonus", "free",
    "reward", "prize", "lottery", "gift", "invoice", "payment", "checkout",
    "webscr", "id", "session", "auth", "otp", "promo",
]

SUSPICIOUS_PREFIXES = ["login-", "verify-", "secure-", "account-", "update-", "bank-"]


def edit_distance(a: str, b: str) -> int:
    """Classic Levenshtein distance (small strings only — fast enough)."""
    if abs(len(a) - len(b)) > 3:
        return abs(len(a) - len(b))
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev = dp[0]
        dp[0] = i
        for j, cb in enumerate(b, 1):
            tmp = dp[j]
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
            prev = tmp
    return dp[-1]


def analyze_url(raw_url: str) -> dict:
    reasons = []
    score = 0.0  # 0 = safe, 100 = phishing

    url = raw_url.strip()
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port
    netloc = parsed.netloc or ""
    path = parsed.path or "/"
    try:
        query = urllib.parse.unquote(parsed.query).lower()
    except Exception:
        query = parsed.query.lower()
    full_lower = urllib.parse.unquote(url).lower()

    # --- scheme checks -------------------------------------------------------
    if scheme not in ("http", "https"):
        reasons.append(f"Unusual scheme '{scheme}' (javascript:, data: are attack vectors)")
        score += 60
    elif scheme == "http" and host and host not in ("localhost", "127.0.0.1"):
        if ".tk" not in host:
            reasons.append("Uses plain http:// instead of https://")
            score += 8

    # --- host-based checks ----------------------------------------------------
    host_parts = host.split(".")
    if not host or len(host) < 4:
        reasons.append("Host is empty or too short")
        score += 40

    # IP as host
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        reasons.append(f"Raw IP address as host ({host}) — legitimate brands rarely use IPs")
        score += 40

    # punycode / unicode
    if "xn--" in host:
        reasons.append("Punycode/IDN domain (homograph attack risk)")
        score += 35
    if any(ord(c) > 127 for c in host):
        reasons.append("Non-ASCII characters in host (homoglyph risk)")
        score += 25

    # @ trick
    if "@" in netloc:
        reasons.append(f"'@' in URL — real host is {host}")
        score += 50

    # many dots / subdomains
    if len(host_parts) > 4:
        reasons.append(f"Too many subdomain levels ({len(host_parts)})")
        score += 12
    if host.count("-") >= 3:
        reasons.append("Many hyphens in domain — common in lookalike domains")
        score += 10

    # long URL
    if len(url) > 120:
        reasons.append(f"Very long URL ({len(url)} chars)")
        score += 8
    if len(url) > 250:
        score += 10

    # port obfuscation
    if port and port not in (80, 443, 8080, 8443):
        reasons.append(f"Non-standard port {port}")
        score += 15

    # TLD
    tld = host_parts[-1].lower() if len(host_parts) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"High-risk TLD: .{tld} (free/abused TLDs)")
        score += 25
    elif tld and tld not in TRUSTED_TLDS:
        reasons.append(f"Uncommon TLD: .{tld}")
        score += 8

    # URL shortener
    domain2 = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    if domain2 in SHORTENERS or host in SHORTENERS:
        reasons.append(f"URL shortener ({domain2}) hides the real destination")
        score += 30

    # brand impersonation (host or path)
    host_clean = host.replace("-", "").replace(".", "")
    found_brand = None
    for brand, aliases in BRANDS.items():
        for alias in aliases:
            alias_clean = alias.replace("-", "").replace(".", "")
            if alias_clean == host_clean:
                found_brand = None
                break
            if alias_clean in host_clean or alias_clean in path.lower():
                # ensure not exact legit (e.g., paypal.com exact match)
                if alias_clean in host_clean and host_clean.endswith(alias_clean) and \
                   len(host_clean) == len(alias_clean):
                    continue
                reasons.append(f"Brand '{brand}' appears in suspicious context")
                score += 18
                found_brand = brand
                break
        if found_brand:
            break

    # lookalike domains (levenshtein) — whole host AND hyphenized tokens
    tokens = [t for t in re.split(r"[.-]", host) if len(t) >= 4]
    for brand, aliases in BRANDS.items():
        for alias in aliases:
            if len(alias) >= 5:
                # whole-host check
                if abs(len(host_clean) - len(alias)) <= 2:
                    d = edit_distance(host_clean, alias)
                    if 1 <= d <= 2 and host_clean != alias:
                        reasons.append(f"Lookalike domain: '{host}' ~ '{alias}' "
                                       f"(distance {d})")
                        score += 28
                        break
                # token check (paypa1 vs paypal)
                for tok in tokens:
                    if abs(len(tok) - len(alias)) <= 1:
                        d = edit_distance(tok, alias)
                        if 1 <= d <= 1 and tok != alias:
                            reasons.append(f"Brand lookalike token: '{tok}' ~ '{alias}' "
                                           f"(distance {d})")
                            score += 30
                            break
                if any("lookalike" in r for r in reasons):
                    break
        if any("lookalike" in r for r in reasons):
            break

    # keywords in host/path
    kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in path.lower()]
    if kw_hits:
        reasons.append(f"Suspicious keywords in path: {', '.join(kw_hits[:5])}")
        score += min(20, 6 * len(kw_hits))
    for pref in SUSPICIOUS_PREFIXES:
        if host_clean.startswith(pref.replace("-", "")) or path.lower().startswith(pref):
            reasons.append(f"Suspicious prefix pattern: {pref}")
            score += 10
            break

    # encoding tricks
    if "%" in url and re.search(r"%[0-9a-f]{2}", url, re.I):
        if "%2e" in url.lower() or "%2f" in url.lower() or "%00" in url.lower():
            reasons.append("Percent-encoding obfuscation detected")
            score += 15

    # double slash / multi domain
    if url.count("://") > 1:
        reasons.append("Multiple protocol markers — possible redirect confusion")
        score += 20

    # suspicious extension
    if re.search(r"\.(exe|scr|bat|cmd|js|apk|jar|hta)$", path.lower()):
        reasons.append("Suspicious file extension in URL")
        score += 20

    # at least one redirect parameter
    if "redirect" in query and "http" in query:
        reasons.append("Redirect parameter in URL — open-redirect pattern")
        score += 12

    score = max(0.0, min(100.0, score))
    verdict = (
        "PHISHING (very likely)" if score >= 60 else
        "SUSPICIOUS (manual review)" if score >= 35 else
        "LOW-RISK" if score >= 15 else
        "SAFE (no strong indicators)"
    )

    return {
        "url": url,
        "parsed_host": host,
        "scheme": scheme,
        "phishing_score": round(score),
        "verdict": verdict,
        "indicators": reasons,
        "suggestions": [
            "Never enter passwords/OTP on HTTP or lookalike domains",
            "Verify the domain in the address bar, not the link text",
            "Contact the official brand directly if in doubt",
            "Report to: https://reportphishing.net / your bank's official channel",
        ] if score >= 35 else ["No urgent action needed — stay alert."],
    }


def main():
    ap = argparse.ArgumentParser(description="PhishScan — phishing URL detector")
    ap.add_argument("--url", help="Single URL to analyze")
    ap.add_argument("--file", help="File with one URL per line")
    ap.add_argument("--json", default=None, help="Output JSON path")
    args = ap.parse_args()

    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as f:
            urls = [l.strip() for l in f if l.strip()][:1000]
    if not urls:
        print("Usage: python3 phishing_detector.py --url 'https://example.com' "
              "| --file urls.txt")
        sys.exit(1)

    results = []
    for u in urls:
        r = analyze_url(u)
        results.append(r)
        if len(urls) == 1:
            print("=" * 56)
            print("  PHISHSCAN — URL Threat Analysis")
            print("=" * 56)
            print(f"  URL      : {u}")
            print(f"  Host     : {r['parsed_host']}")
            print(f"  Verdict  : {r['verdict']}")
            print(f"  Score    : {r['phishing_score']}/100")
            print("-" * 56)
            print("  Indicators:")
            for ind in r["indicators"] or ["(none)"]:
                print(f"   • {ind}")
            print("  Advice:")
            for s in r["suggestions"]:
                print(f"   • {s}")
            print("=" * 56)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[✓] JSON saved to {args.json}")


if __name__ == "__main__":
    main()
