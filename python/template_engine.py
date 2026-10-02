#!/usr/bin/env python3
# ============================================================================
#  Nucleus — YAML Template Scanning Engine (Nuclei-style, zero dependencies)
#  ---------------------------------------------------------------------------
#  Own mini-YAML parser (indentation based, no PyYAML needed) + template
#  runner supporting:
#    - info (id, name, severity, description, solution, tags, reference)
#    - requests: method, path(s), headers, data, extractors, matchers
#    - matchers: status, regex, contains, version (with comparison)
#    - extractors: regex with named capture -> {{var}} in matchers
#    - condition: and / or
#    - parts: status | header | body | all
#    - auth: cookie / custom headers (session support)
#
#  Usage:
#    python3 template_engine.py --target https://example.com
#              --templates templates --cookie "session=abc" --heads '{"X-Test":"1"}'
#  Output: scan_results.json (same schema as other SecuAudit modules)
#
#  LEGAL: passive detection templates only — authorized testing only.
# ============================================================================

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin

UA = "Mozilla/5.0 (compatible; Nucleus/1.0; authorized-security-audit)"


# ---------------------------------------------------------------------------
# Mini YAML parser (subset sufficient for our template schema)
# ---------------------------------------------------------------------------
def _strip_comment(line):
    # remove trailing # comment (not inside quotes)
    out = []
    in_s = None
    for ch in line:
        if in_s:
            out.append(ch)
            if ch == in_s:
                in_s = None
        elif ch in ("'", '"'):
            in_s = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


def _parse_scalar(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]  # quoted -> always string
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(x) for x in inner.split(",")]
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", ""):
        return None
    # unquoted numeric -> int/float (needed for status matchers)
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    return s


def _parse_block(lines, i, indent):
    """Parse a block starting at lines[i] with given indent. Returns (value, next_i)."""
    if lines[i][1].startswith("- "):
        # list block
        items = []
        while i < len(lines) and lines[i][0] == indent and \
                lines[i][1].startswith("- "):
            rest = lines[i][1][2:].strip()
            if ":" in rest:
                key, _, val = rest.partition(":")
                val = val.strip()
                item = {}
                if val == "" and i + 1 < len(lines) and lines[i + 1][0] > indent:
                    child, i = _parse_block(lines, i + 1, lines[i + 1][0])
                    item[key.strip()] = child
                else:
                    item[key.strip()] = _parse_scalar(val)
                    i += 1
                # consume deeper sibling keys belonging to same item
                j = i
                while j < len(lines) and lines[j][0] > indent:
                    content = lines[j][1]
                    if ":" not in content:
                        j += 1
                        continue
                    k2, _, v2 = content.partition(":")
                    v2 = v2.strip()
                    if v2 == "" and j + 1 < len(lines) and lines[j + 1][0] > lines[j][0]:
                        child, j = _parse_block(lines, j + 1, lines[j + 1][0])
                        item[k2.strip()] = child
                    else:
                        item[k2.strip()] = _parse_scalar(v2)
                        j += 1
                items.append(item)
                i = j
            else:
                items.append(_parse_scalar(rest))
                i += 1
        return items, i

    # dict block
    d = {}
    while i < len(lines) and lines[i][0] == indent:
        content = lines[i][1]
        if ":" not in content:
            i += 1
            continue
        key, _, val = content.partition(":")
        key = key.strip()
        val = val.strip()
        if val == "":
            # nested block
            child, i = _parse_block(lines, i + 1, lines[i + 1][0] if i + 1 < len(lines) else indent)
            d[key] = child
        else:
            d[key] = _parse_scalar(val)
            i += 1
    return d, i


def parse_yaml(text):
    raw = []
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        stripped = _strip_comment(line)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        raw.append((indent, stripped.lstrip(" ")))
    if not raw:
        return {}
    value, _ = _parse_block(raw, 0, raw[0][0])
    return value


# ---------------------------------------------------------------------------
# Version comparison (no external deps)
# ---------------------------------------------------------------------------
def _parts(v):
    v = re.sub(r"[^0-9.]", ".", str(v))
    return [int(x) for x in v.split(".") if x.isdigit()]


def ver_compare(a, b):
    pa, pb = _parts(a), _parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)


# ---------------------------------------------------------------------------
# HTTP fetch with auth support
# ---------------------------------------------------------------------------
def fetch(url, method="GET", timeout=12, extra_headers=None, data=None):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    hdrs = dict(extra_headers or {})
    for k, v in hdrs.items():
        req.add_header(k, v)
    if data is not None:
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else str(data).encode()
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    else:
        body = None
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(400_000)
    except urllib.error.HTTPError as e:
        try:
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(64_000)
        except Exception:
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, b""
    except Exception as e:
        return None, {}, b""


# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------
def load_templates(directory):
    templates = []
    for root, _, files in os.walk(directory):
        for fn in sorted(files):
            if fn.endswith((".yaml", ".yml")):
                with open(os.path.join(root, fn), encoding="utf-8") as f:
                    try:
                        tpl = parse_yaml(f.read())
                        if isinstance(tpl, dict) and tpl.get("id"):
                            templates.append(tpl)
                    except Exception as e:
                        print(f"[!] Skipping bad template {fn}: {e}")
    return templates


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------
def extract(tpl_extractors, parts):
    """parts = dict(status, header_text, body_text). Returns dict name->value."""
    out = {}
    for ex in (tpl_extractors or []):
        name = ex.get("name")
        regex = ex.get("regex") or ex.get("regexp")
        if not name or not regex:
            continue
        part = (ex.get("part") or "body").lower()
        text = {"status": str(parts["status"]), "header": parts["header"],
                "body": parts["body"], "all": parts["header"] + "\n" + parts["body"]}.get(part, parts["body"])
        m = re.search(regex, text, re.S | re.I)
        if m:
            out[name] = m.group(1) if m.groups() else m.group(0)
    if tpl_extractors:
        # also allow extractor of the matched part directly
        pass
    return out


# ---------------------------------------------------------------------------
# Matchers
# ---------------------------------------------------------------------------
def _match_status(m, parts):
    want = m.get("value")
    if isinstance(want, list):
        return parts["status"] in want
    return parts["status"] == want


def _match_regex(m, parts, vars_):
    pattern = m.get("pattern") or m.get("regex")
    text = _part_text(m, parts, vars_)
    try:
        return bool(re.search(pattern, text, re.S | re.I))
    except re.error:
        return False


def _match_contains(m, parts, vars_):
    val = m.get("value") or m.get("contains") or ""
    text = _part_text(m, parts, vars_).lower()
    vals = val if isinstance(val, list) else [val]
    vals = [str(v).lower() for v in vals]
    return all(v in text for v in vals) if m.get("condition") == "and" else any(v in text for v in vals)


def _match_version(m, parts, vars_):
    src = m.get("regex") or m.get("value") or ""
    var = src.strip("{}") if src.startswith("{{") else None
    actual = vars_.get(var, "") if var else src
    if not actual:
        return False
    comp = m.get("comparison", "eq")
    target = m.get("version", "")
    c = ver_compare(actual, target)
    return {"eq": c == 0, "gt": c > 0, "gte": c >= 0, "lt": c < 0, "lte": c <= 0}.get(comp, False)


def _part_text(m, parts, vars_):
    part = (m.get("part") or "body").lower()
    if part == "status":
        return str(parts["status"])
    if part == "header":
        return parts["header"]
    if part == "all":
        return parts["header"] + "\n" + parts["body"]
    body = parts["body"]
    for k, v in vars_.items():
        body = body.replace("{{" + k + "}}", v)
    return body


MATCHERS = {
    "status": _match_status,
    "regex": _match_regex,
    "regexp": _match_regex,
    "contains": _match_contains,
    "word": _match_contains,
    "version": _match_version,
}


def evaluate_matchers(matchers, parts, vars_):
    if not matchers:
        return True
    results = []
    for m in matchers:
        mtype = (m.get("type") or "contains").lower()
        fn = MATCHERS.get(mtype)
        if fn:
            try:
                res = bool(fn(m, parts, vars_))
                if m.get("not"):
                    res = not res
                results.append(res)
            except Exception:
                results.append(False)
    cond = "or"
    for m in matchers:
        if m.get("condition") == "and":
            cond = "and"
    return all(results) if cond == "and" else any(results)


# ---------------------------------------------------------------------------
# Templating lookup
# ---------------------------------------------------------------------------
def _subst(s, vars_):
    s = str(s)
    for k, v in vars_.items():
        s = s.replace("{{" + k + "}}", str(v))
    return s


# ---------------------------------------------------------------------------
# Run single template against target
# ---------------------------------------------------------------------------
def run_template(tpl, base, timeout, extra_headers):
    info = tpl.get("info") or {}
    requests = tpl.get("requests") or tpl.get("request") or []
    findings = []
    for req in requests:
        method = (req.get("method") or "GET").upper()
        paths = req.get("path") or ["/"]
        if isinstance(paths, str):
            paths = [paths]
        hdrs = dict(extra_headers)
        for k, v in (req.get("headers") or {}).items():
            hdrs[k] = str(v)
        data = req.get("data")
        for path in paths:
            url = urljoin(base + "/", _subst(path, {}))
            status, headers, body = fetch(url, method, timeout, hdrs, data)
            if status is None:
                continue
            header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            parts = {"status": status, "header": header_text,
                     "body": body.decode("utf-8", "ignore")}
            vars_ = extract(req.get("extractors"), parts)
            if not evaluate_matchers(req.get("matchers"), parts, vars_):
                continue
            findings.append({
                "id": tpl["id"],
                "title": info.get("name") or tpl["id"],
                "severity": (info.get("severity") or "medium").capitalize(),
                "evidence": (f"{method} {path} -> HTTP {status}"
                             + (f" | {list(vars_.items())[0][0]}={list(vars_.items())[0][1]}"
                                if vars_ else "")),
                "remediation": info.get("solution")
                                or "Review the finding and apply the recommended fix.",
                "description": info.get("description", ""),
                "tags": info.get("tags", ""),
                "reference": info.get("reference", ""),
                "template_name": os.path.basename(tpl.get("_file", "")),
            })
            break  # one match per request block is enough
    return findings


# ---------------------------------------------------------------------------
# Scan orchestrator
# ---------------------------------------------------------------------------
def scan(target, templates_dir, timeout=12, extra_headers=None, verbose=False):
    base = target.rstrip("/")
    templates = load_templates(templates_dir)
    if not templates:
        print(f"[!] No templates found in {templates_dir}")
        return []
    print(f"[*] {len(templates)} templates loaded from {templates_dir}")
    findings = []
    for tpl in templates:
        tpl["_file"] = ""
        try:
            res = run_template(tpl, base, timeout, extra_headers or {})
            if res:
                findings.extend(res)
                if verbose:
                    for r in res:
                        print(f"    [MATCH] {r['severity']:>8}  {r['title']}")
        except Exception as e:
            if verbose:
                print(f"    [!] {tpl.get('id')}: {e}")
    return findings


def main():
    ap = argparse.ArgumentParser(description="Nucleus — YAML template scanning engine")
    ap.add_argument("--target", required=True)
    ap.add_argument("--templates", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                        "..", "templates"))
    ap.add_argument("--cookie", default=None, help="Cookie header value (auth session)")
    ap.add_argument("--headers", default=None, help='JSON dict of extra headers, e.g. \'{"X-API-Key":"..."}\'')
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--out", default="scan_results.json")
    ap.add_argument("--sarif", default=None, help="Also write SARIF output")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    extra = {}
    if args.cookie:
        extra["Cookie"] = args.cookie
    if args.headers:
        try:
            extra.update(json.loads(args.headers))
        except Exception:
            print("[!] --headers must be valid JSON")
            sys.exit(2)

    t0 = time.time()
    findings = scan(args.target, args.templates, args.timeout, extra, args.verbose)
    elapsed = time.time() - t0

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    data = {"tool": "Nucleus (template engine)", "target": args.target,
            "scan_date": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "templates_run": None, "findings": findings, "summary": summary,
            "disclaimer": "Passive detection templates. Authorized testing only.",
            "score": max(0.0, 100.0 - sum({"Critical": 25, "High": 14,
                                           "Medium": 8, "Low": 4}.get(f["severity"], 0)
                                          for f in findings)),
            "grade": "F"}
    score = data["score"]
    data["grade"] = ("A" if score >= 90 else "B" if score >= 75 else
                     "C" if score >= 60 else "D" if score >= 45 else
                     "E" if score >= 30 else "F")

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print()
    print(f"[✓] Template scan complete in {elapsed:.1f}s")
    print(f"[✓] Score: {score}/100 (Grade {data['grade']})")
    for f in findings:
        if f["severity"] not in ("Info",):
            print(f"    [{f['severity']:>8}] {f['title']}")
    print(f"[✓] JSON: {args.out}")

    if args.sarif:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from sarif_export import write_sarif
        write_sarif(data, args.sarif)
        print(f"[✓] SARIF: {args.sarif}")


if __name__ == "__main__":
    main()
