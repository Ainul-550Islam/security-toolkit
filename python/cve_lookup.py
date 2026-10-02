#!/usr/bin/env python3
# ============================================================================
#  CVE Radar — Real internet CVE lookup (free CIRCL API, stdlib only)
#  ---------------------------------------------------------------------------
#  Sources:
#    - vendor/product search : https://cve.circl.lu/api/search/{vendor}/{product}
#    - single CVE            : https://cve.circl.lu/api/cve/{CVE-YYYY-NNNNN}
#  Features: offline cache, CVSS sorting, retry/backoff, JSON + text output.
#  Usage:
#    python3 cve_lookup.py --product nginx            (vendor 'nginx')
#    python3 cve_lookup.py --vendor microsoft --product windows
#    python3 cve_lookup.py --cve CVE-2024-3094
#    python3 cve_lookup.py --offline                   (use cache only)
# ============================================================================

import argparse
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cve_cache")
UA = {"User-Agent": "CVECache/1.0 (authorized-audit; educational)"}
TIMEOUT = 20


def cache_path(key: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, key + ".json")


def load_cache(key: str):
    p = cache_path(key)
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def save_cache(key: str, data) -> None:
    try:
        with open(cache_path(key), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception:
        pass


def api_get(url: str, retries: int = 2) -> dict | None:
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # Rate-limited: wait longer, then retry
                if attempt < retries:
                    wait = 5.0 * (attempt + 1)
                    print(f"[!] Rate limited (429) — waiting {wait:.0f}s…")
                    time.sleep(wait)
                    continue
            elif attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            print(f"[!] API error: {e}")
            return None
        except Exception as e:
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
            else:
                print(f"[!] API error: {e}")
                return None
    return None


def cvss_score(entry: dict) -> float:
    cvss = entry.get("cvss")
    if isinstance(cvss, dict):
        try:
            return float(cvss.get("score", 0) or 0)
        except (TypeError, ValueError):
            return 0.0
    # Some CIRCL entries return cvss as a raw string like "9.8"
    if isinstance(cvss, (str, int, float)):
        try:
            return float(cvss)
        except (TypeError, ValueError):
            return 0.0
    # CVE List v5: metrics.cvssV3_1 / cvssV2 etc. (score lives under baseScore)
    metrics = entry.get("metrics") or {}
    if isinstance(metrics, list):
        for m in metrics:
            if isinstance(m, dict):
                for k, v in m.items():
                    if isinstance(v, dict) and "baseScore" in v:
                        try:
                            return float(v["baseScore"])
                        except (TypeError, ValueError):
                            continue
    elif isinstance(metrics, dict):
        for k, v in metrics.items():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and "baseScore" in item:
                        try:
                            return float(item["baseScore"])
                        except (TypeError, ValueError):
                            continue
    # Fallback: parse from related fields
    for key in ("cvss_score", "vuln_status"):
        try:
            return float(entry.get(key, 0) or 0)
        except (TypeError, ValueError):
            continue
    return 0.0


def normalize_v5(cve_id: str, container: dict) -> dict:
    """Convert a CVE List v5 entry [id, {containers: {cna: {...}}}] to flat dict."""
    cna = (container.get("containers") or {}).get("cna") or {}
    descs = cna.get("descriptions") or []
    desc = ""
    for d in descs:
        if isinstance(d, dict) and d.get("lang") == "en":
            desc = d.get("value", "")
            break
    affected = cna.get("affected") or []
    products = []
    for a in affected:
        if isinstance(a, dict):
            products.append(str(a.get("product", "")))
    meta = container.get("cveMetadata") or {}
    published = meta.get("datePublished", "")
    # severity from metrics
    sev = ""
    metrics = cna.get("metrics") or []
    if isinstance(metrics, list):
        for m in metrics:
            if isinstance(m, dict):
                for k, v in m.items():
                    if isinstance(v, dict):
                        sev = str(v.get("baseSeverity", "") or sev)
    refs = []
    for r in cna.get("references") or []:
        if isinstance(r, dict):
            refs.append(str(r.get("url", "")))
    return {
        "id": cve_id.upper(),
        "cve": cve_id.upper(),
        "severity": sev,
        "Published": published or "",
        "published": published or "",
        "summary": desc,
        "description": desc,
        "references": refs,
        "cvss": {"score": cvss_score({
            "metrics": cna.get("metrics") or [],
            "cvss": cna.get("cvss"),
        })},
        "products": ", ".join(products),
    }


def extract_entries(data: dict) -> list:
    """Handle BOTH old CIRCL flat format and the new v5-format response."""
    results = data.get("results", [])
    entries = []
    if isinstance(results, dict):
        # New v5 structure: {"cvelistv5": [[id, container]...], "nvd": [...]}
        for bucket in results.values():
            if not isinstance(bucket, list):
                continue
            for item in bucket:
                if isinstance(item, list) and len(item) == 2 and isinstance(item[1], dict):
                    entries.append(normalize_v5(str(item[0]), item[1]))
                elif isinstance(item, dict):
                    entries.append(item)
    elif isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                entries.append(item)
    return entries


def is_recent(entry: dict, days: int = 365) -> bool:
    published = entry.get("Published") or entry.get("published") or ""
    try:
        d = datetime.datetime.fromisoformat(published.replace("Z", "+00:00"))
        return (datetime.datetime.now(datetime.timezone.utc) - d).days <= days
    except Exception:
        return False


def format_entry(e: dict) -> str:
    sev = e.get("severity", "")
    score = cvss_score(e)
    cve = e.get("id", e.get("cve", "?"))
    published = str(e.get("Published", e.get("published", "")))[:10]
    desc = str(e.get("summary") or e.get("description") or "")[:130]
    line = f"  [{score:>4.1f} | {str(sev)[:7]:<7}] {cve}  ({published})"
    line += f"\n      {desc}"
    refs = e.get("references") or []
    if isinstance(refs, list):
        refs = [str(r) for r in refs if isinstance(r, str)]
        if refs:
            line += f"\n      {' '.join(refs[:2])}"
    return line


def mini_db_lookup(vendor: str, product: str) -> list:
    """Fallback: local mini CVE database (works offline, real CVEs)."""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_mini_db.json")
    try:
        with open(db_path, encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        return []
    needle = (product or vendor or "").lower()
    out = []
    for e in db.get("cves", []):
        if needle and (needle in str(e.get("product", "")).lower() or
                       needle in e.get("id", "").lower()):
            out.append({
                "id": e["id"], "severity": e.get("severity", ""),
                "Published": e.get("published", ""), "summary": e.get("summary", ""),
                "references": e.get("references", []), "cvss": {"score": e.get("cvss", 0)},
            })
    return out


def print_local(results: list, top: int, vendor: str, product: str, report_total: int):
    results = sorted(results, key=cvss_score, reverse=True)[:top]
    print("═" * 60)
    print(f"  CVE RADAR — {vendor}/{product}  (offline mini-DB)")
    print(f"  Total CVEs: {report_total}   (top {len(results)} shown)")
    print("═" * 60)
    for e in results:
        print(format_entry(e))


def search_vendor_product(vendor: str, product: str, top: int, recent_days: int, offline: bool):
    key = f"search_{vendor}_{product}"
    data = None
    if offline:
        data = load_cache(key)
        if data is None:
            print(f"[!] No cache for {vendor}/{product}. Trying offline mini-DB…")
            results = mini_db_lookup(vendor, product)
            if not results:
                print("[!] Mini-DB has no entries for this product.")
                return
            print_local(results, top, vendor, product, report_total=len(results))
            return
    else:
        url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(vendor)}/{urllib.parse.quote(product)}"
        data = api_get(url)
        if data:
            save_cache(key, data)
    if not data:
        # API failed (offline / rate-limited): fall back to mini-DB
        print("[!] API unavailable — falling back to offline mini-DB.")
        results = mini_db_lookup(vendor, product)
        if not results:
            print("[!] Mini-DB has no entries for this product. Try again later.")
            return
        print_local(results, top, vendor, product, report_total=len(results))
        return

    results = extract_entries(data)
    results = [e for e in results if isinstance(e, dict)]

    # Enrich top candidates with per-CVE detail (which includes CVSS metrics).
    def enrich(e: dict) -> dict:
        if cvss_score(e) > 0:
            return e
        if offline:
            return e
        detail = api_get(f"https://cve.circl.lu/api/cve/{e['id']}", retries=1)
        time.sleep(2.0)  # be polite: avoid 429 storms
        if isinstance(detail, dict):
            e = dict(e)
            e.update(detail)
        return e

    results = [enrich(e) for e in results[:max(top, 4)]]

    # If enrichment failed (API rate-limited), merge offline mini-DB entries
    # so that CVSS-scored CVEs are still shown.
    if results and all(cvss_score(e) == 0 for e in results):
        extra = mini_db_lookup(vendor, product)
        ids = {e.get("id") for e in results}
        for e in extra:
            if e.get("id") not in ids:
                results.append(e)

    results.sort(key=cvss_score, reverse=True)
    recent = [e for e in results if is_recent(e, recent_days)]
    top_entries = results[:top] if not recent else (recent[:max(top, 8)] if len(recent) >= 3
                                                    else results[:top])

    total = data.get("total_count", len(results)) if isinstance(data, dict) else len(results)
    print("═" * 60)
    print(f"  CVE RADAR — {vendor}/{product}")
    print(f"  Total CVEs: {total}   (top {len(top_entries)} shown, enriched with CVSS)")
    print("═" * 60)
    for e in top_entries:
        print(format_entry(e))


def lookup_cve(cve_id: str, offline: bool):
    key = f"cve_{cve_id}"
    data = None
    if offline:
        data = load_cache(key)
        if data is None:
            print(f"[!] No cache for {cve_id}. Need internet on first run.")
            return
    else:
        data = api_get(f"https://cve.circl.lu/api/cve/{cve_id}")
        if data:
            save_cache(key, data)
    if not data:
        return
    print("═" * 60)
    print("  CVE DETAIL")
    print("═" * 60)
    print(format_entry(data))
    if data.get("vulnerable_configuration"):
        print("  Affected configs:")
        for c in data["vulnerable_configuration"][:8]:
            if isinstance(c, dict):
                c = c.get("id", c)
            print(f"   • {c}")


def main():
    ap = argparse.ArgumentParser(description="CVE Radar — CIRCL API CVE lookup")
    ap.add_argument("--vendor", default=None)
    ap.add_argument("--product", default=None)
    ap.add_argument("--cve", default=None, help="Single CVE id (CVE-YYYY-NNNNN)")
    ap.add_argument("--top", type=int, default=10, help="How many CVE entries to show")
    ap.add_argument("--recent-days", type=int, default=365)
    ap.add_argument("--offline", action="store_true", help="Use local cache only")
    args = ap.parse_args()

    if args.cve:
        lookup_cve(args.cve, args.offline)
    elif args.product:
        search_vendor_product(args.vendor or args.product, args.product,
                              args.top, args.recent_days, args.offline)
    else:
        print("Usage: python3 cve_lookup.py --product nginx | "
              "--vendor X --product Y | --cve CVE-2024-3094")
        sys.exit(1)


if __name__ == "__main__":
    main()
