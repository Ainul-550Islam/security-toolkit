#!/usr/bin/env python3
# ============================================================================
#  WallBreaker? No — WallFinder — WAF detection & fingerprinting (passive-probe)
#  ---------------------------------------------------------------------------
#  Detects the WAF/product in front of a target by combining:
#    - response header fingerprints (cf-ray, x-amzn-, akamai, big-ip, ...)
#    - cookie fingerprints (cf_clearance, incap_ses, TS..., __cfduid, ...)
#    - error/challenge page body markers (Cloudflare challenge, AWS WAF page,
#      ModSecurity block page, Imperva, Sucuri, ...)
#    - behavior: 403/406/429 to a benign probe vs an attack probe
#
#  Usage: python3 waf_detect.py --url https://example.com [--json out.json]
#  LEGAL: authorized testing only (probes are a single benign GET + one
#         harmless-looking parameter value).
# ============================================================================

import argparse
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; WallFinder/1.0; authorized-security-audit)"

FINGERPRINTS = [
    # (name, kind, pattern)  kind: header|cookie|body
    ("Cloudflare", "header", r"cf-ray|cf-cache-status|cf-mitigated|x-cache-hits"),
    ("Cloudflare", "cookie", r"__cfduid|cf_clearance|cf_chl"),
    ("Cloudflare", "body", r"Attention Required! \| Cloudflare|cf-error-details"),
    ("AWS WAF (ALB/CloudFront)", "header", r"x-amzn-requestid|x-amz-cf-id|x-amz-cf-pop"),
    ("AWS WAF", "body", r"Request ID: [0-9a-f-]{36}|blocked by AWS WAF|aws waf"),
    ("CloudFront", "cookie", r"cloudfront"),
    ("Akamai", "header", r"akamai|akamai-|x-akamai"),
    ("Akamai", "cookie", r"ak_|akamai"),
    ("Akamai Ghost", "body", r"Access Denied.*akamai|Reference #\d+\.\d+\.\d+"),
    ("Imperva / Incapsula", "header", r"x-iinfo"),
    ("Imperva / Incapsula", "cookie", r"incap_ses|visid_incap"),
    ("ModSecurity / CRS", "header", r"x-mod-security|mod_security"),
    ("ModSecurity / CRS", "body", r"This request has been blocked|Invalid URL|"
                                  r"ModSecurity|Access Denied"),
    ("Fastly", "header", r"x-served-by|fastly|surrogate-key"),
    ("Varnish", "header", r"via: 1\.1 varnish|x-varnish"),
    ("Sucuri / CloudProxy", "header", r"x-sucuri-id|x-sucuri-cache"),
    ("Sucuri / CloudProxy", "cookie", r"sucuri_cloudproxy"),
    ("Barracuda", "header", r"barracuda|x-bw-|x-caucho"),
    ("F5 BIG-IP / ASM", "cookie", r"BIGipServer|TS\w{8}|F5_"),
    ("F5 BIG-IP / ASM", "header", r"x-wa-info|x-forwarded-server"),
    ("F5 BIG-IP / ASM", "body", r"The requested URL was rejected. Please consult with "
                                r"your administrator|ASM\s*\(\d+\)"),
    ("Radware", "cookie", r"radware|al_?lb_?config"),
    ("Citrix NetScaler", "cookie", r"NSC_[a-z0-9]+="),
    ("Citrix NetScaler", "header", r"via: 1\.1 ns|citeva"),
    ("Google Cloud Armor", "body", r"An error occurred while connecting to the server|"
                                   r"blocked by Google Cloud Armor"),
    ("Microsoft Azure WAF", "header", r"x-azure-ref|x-waf"),
    ("Microsoft Azure WAF", "body", r"The request has been blocked|azure websit"),
    ("Fortinet FortiWeb", "cookie", r"FORTIWAFSID|fortiweb"),
    ("Wordfence (WordPress)", "header", r"x-powered-by: wordfence|"
                                        r"x-wordfence-proxy"),
    ("Palo Alto Prisma/Cloud NGFW", "body", r"blocked by palo alto|"
                                            r"prisma cloud security"),
    ("Reblaze", "header", r"x-reblaze|reb-reqid"),
    ("SiteGround", "header", r"x-ssg|x-ssg-id|sg-"),
    ("Verizon/Oath EdgeCast", "header", r"x-edg|ecd_"),
]

BLOCK_COOKIE_PAT = re.compile(r"(cf_clearance|incap_ses|FORTIWAFSID|BIGipServer|TS\w{8})", re.I)


def fetch(url, timeout=12, method="GET"):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(200_000)
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), e.read(32_000)
        except Exception:
            return e.code, dict(e.headers or {}), b""
    except Exception as e:
        return None, {}, str(e).encode()[:200]


def fingerprint(status, headers, body):
    header_lc = {k.lower(): v for k, v in headers.items()}
    joined_headers = " ".join(f"{k}: {v}" for k, v in header_lc.items())
    cookie = header_lc.get("set-cookie", "") + header_lc.get("cookie", "")
    body_text = body[:4000].decode("utf-8", "ignore")
    combined = {
        "header": joined_headers.lower(),
        "cookie": cookie.lower(),
        "body": body_text.lower(),
    }
    hits = {}
    for name, kind, pat in FINGERPRINTS:
        if re.search(pat, combined.get(kind, ""), re.I):
            hits.setdefault(name, []).append(kind)
    return hits


def detect(target, timeout=12):
    print(f"[*] Probing {target}")
    status, headers, body = fetch(target, timeout)
    if status is None:
        print(f"[!] Unreachable: {body[:120]}")
        return {"target": target, "reachable": False, "waf": []}

    hits = fingerprint(status, headers, body)

    # behavior check: benign probe vs attack-ish value
    behavior = []
    probe_url = target + ("&" if "?" in target else "?") + "id=1"
    s1, h1, b1 = fetch(probe_url, timeout)
    attack_url = target + ("&" if "?" in target else "?") + \
        "id=" + urllib.parse.quote("1' OR '1'='1")
    s2, h2, b2 = fetch(attack_url, timeout)

    # fingerprint blocked responses too (WAF error pages carry markers)
    if s1:
        for name, evs in fingerprint(s1, h1, b1).items():
            hits.setdefault(name, [])
            evs2 = list(evs)
            for e in evs2:
                if e not in hits[name]:
                    hits[name].append(e)
    if s2:
        for name, evs in fingerprint(s2, h2, b2).items():
            hits.setdefault(name, [])
            for e in evs:
                if e not in hits[name]:
                    hits[name].append(e)

    if s1 and s2:
        if s2 in (403, 406, 429, 999) and s1 not in (403, 406, 429, 999):
            behavior.append("Blocks obvious SQLi probe (403/406/429)")
            hits.setdefault("Behavioral", []).append("blocking")
        elif s1 == s2 and s2 in (403, 406):
            behavior.append("Denies requests broadly (possibly WAF or security plugin)")
            hits.setdefault("Behavioral", []).append("deny-all")
    if hits:
        hits["Behavioral"] = hits.get("Behavioral", []) + behavior
    else:
        hits = {"Behavioral": behavior} if behavior else {}

    return {"target": target, "reachable": True,
            "waf": [{"vendor": v, "evidence": ev} for v, ev in hits.items()],
            "detected": bool(hits)}


def main():
    ap = argparse.ArgumentParser(description="WallFinder — WAF detection")
    ap.add_argument("--url", required=True)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    result = detect(args.url, args.timeout)
    print("═" * 58)
    print("  WALLFINDER — WAF Detection")
    print("═" * 58)
    if not result.get("reachable"):
        print("  Target unreachable — no WAF data.")
    elif not result["waf"]:
        print("  No WAF detected (direct hosting or custom setup).")
    else:
        for w in result["waf"]:
            print(f"  • {w['vendor']:28} via {', '.join(w['evidence'])}")
    print("═" * 58)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"[✓] JSON: {args.json}")


if __name__ == "__main__":
    main()
