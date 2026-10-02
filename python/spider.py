#!/usr/bin/env python3
# ============================================================================
#  Spider — Website Crawler / Endpoint Discovery (stdlib html.parser only)
#  ---------------------------------------------------------------------------
#  Discovers: pages, links, forms, JS files, API-ish paths, parameters.
#  Output: spider_results.json (endpoints for template engine / API audit)
#
#  Usage:
#    python3 spider.py --url https://example.com --depth 2 --limit 50
#    python3 spider.py --url https://example.com --cookie "session=abc"
# ============================================================================

import argparse
import json
import re
import urllib.request
import urllib.error
import urllib.parse
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qsl

UA = "Mozilla/5.0 (compatible; SecuSpider/1.0; authorized-security-audit)"

API_HINT = re.compile(r"(/api/|/v\d+/|\.json$|/graphql|/rest/|/ajax/|/wp-json|/actuator)", re.I)


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []      # (href, tag)
        self.forms = []      # (action, method, inputs)
        self.scripts = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link", "area"):
            href = a.get("href")
            if href:
                self.links.append((href, tag))
        elif tag == "script":
            src = a.get("src")
            if src:
                self.scripts.append(src)
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                          "inputs": []}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append((name, a.get("type", "text")))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def fetch(url, timeout, cookie=None):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(600_000), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, b"", url
    except Exception as e:
        return None, {}, b"", str(e)


def normalize(base, href, origin):
    """Return absolute URL if same-origin (or protocol-relative), else None."""
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    full = urljoin(base, href)
    p = urlparse(full)
    if p.scheme not in ("http", "https"):
        return None
    if p.netloc != origin:
        return None
    # strip fragments, keep query (params matter for API discovery)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))


def crawl(start_url, depth=2, limit=60, timeout=12, cookie=None, verbose=False):
    parsed = urlparse(start_url)
    origin = parsed.netloc
    scheme = parsed.scheme or "https"
    visited = {}   # url -> status
    queue = [(start_url, 0)]
    pages = {}     # url -> {links, forms, scripts}

    while queue and len(visited) < limit:
        url, d = queue.pop(0)
        if url in visited or d > depth:
            continue
        status, headers, body, final = fetch(url, timeout, cookie)
        if status is None:
            continue
        visited[url] = status
        if verbose:
            print(f"    [{status}] {url}")
        content_type = (headers.get("content-type") or "").lower()
        if "html" not in content_type:
            pages[url] = {"status": status, "type": content_type[:40]}
            continue
        parser = LinkCollector()
        try:
            parser.feed(body.decode("utf-8", "ignore"))
        except Exception:
            pass
        pages[url] = {
            "status": status,
            "type": "html",
            "links": [l[0] for l in parser.links][:100],
            "scripts": parser.scripts[:50],
            "forms": parser.forms[:30],
        }
        for href, _ in parser.links:
            nxt = normalize(url, href, origin)
            if nxt and nxt not in visited:
                queue.append((nxt, d + 1))
        for src in parser.scripts:
            nxt = normalize(url, src, origin)
            if nxt and nxt not in visited:
                queue.append((nxt, d + 1))

    # Build endpoint list
    endpoints = []
    param_urls = []
    api_candidates = []
    for url in sorted(visited):
        p = urlparse(url)
        path = p.path
        query = dict(parse_qsl(p.query))
        endpoints.append({"method": "GET", "url": url, "path": path,
                          "params": sorted(query.keys()),
                          "status": visited[url]})
        if query:
            param_urls.append({"url": url, "params": sorted(query.keys())})
        if API_HINT.search(url):
            api_candidates.append({"method": "GET", "url": url, "path": path,
                                   "params": sorted(query.keys()),
                                   "status": visited[url]})
        # POST candidates (forms / api paths)
    for url, page in pages.items():
        for form in page.get("forms", []):
            action = form.get("action") or url
            endpoints.append({
                "method": form.get("method", "GET"),
                "url": urljoin(url, action),
                "path": urlparse(urljoin(url, action)).path,
                "params": [n for n, _ in form.get("inputs", [])],
                "form": True,
            })

    stats = {
        "target": start_url,
        "origin": origin,
        "pages_crawled": len(pages),
        "urls_discovered": len(visited),
        "endpoints": len(endpoints),
        "api_candidates": len(api_candidates),
        "forms": sum(1 for e in endpoints if e.get("form")),
        "params_urls": len(param_urls),
        "depth": depth,
        "limit": limit,
    }
    return stats, endpoints, param_urls, api_candidates, pages


def main():
    ap = argparse.ArgumentParser(description="SecuSpider — crawler/endpoint discovery")
    ap.add_argument("--url", required=True)
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--out", default="spider_results.json")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    stats, endpoints, param_urls, api_candidates, pages = crawl(
        args.url, args.depth, args.limit, args.timeout, args.cookie, args.verbose)

    data = {"stats": stats, "endpoints": endpoints[:args.limit * 10],
            "api_candidates": api_candidates[:200],
            "param_urls": param_urls[:200]}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print("═" * 58)
    print("  SECUSPIDER — Crawler Results")
    print("═" * 58)
    print(f"  Pages crawled : {stats['pages_crawled']}")
    print(f"  URLs found    : {stats['urls_discovered']}")
    print(f"  Endpoints     : {stats['endpoints']}")
    print(f"  API candidates: {stats['api_candidates']}")
    print(f"  Forms         : {stats['forms']}")
    print("─" * 58)
    if api_candidates:
        print("  API-like URLs:")
        for a in api_candidates[:15]:
            print(f"   • {a['method']:5} {a['url'][:80]}")
    if param_urls:
        print("  URLs with parameters (fuzz candidates):")
        for u in param_urls[:10]:
            print(f"   • {u['url'][:80]}  params={u['params'][:5]}")
    print("═" * 58)
    print(f"[✓] JSON: {args.out}")


if __name__ == "__main__":
    main()
