#!/usr/bin/env python3
# ============================================================================
#  SecuToolkit Test Suite — runs every module end-to-end (stdlib unittest)
#  Usage: python3 tests/run_tests.py
# ============================================================================

import json
import os
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "python")
sys.path.insert(0, PY)
sys.path.insert(0, HERE)

# Phase-1 foundation test suite (org/project/asset/scan/finding/evidence/
# scope/audit/persistence/normalization + security regressions) — runs as
# part of the SAME suite so total = existing + foundation.
from test_foundation import *  # noqa: F401,F403,E402

# Phase-2 security-control test suite (identity, RBAC, tenant isolation,
# API credentials, audit integrity, rate limiting, password reset, dashboard
# hardening, secret-leak regressions) — same-suite integration.
from test_security import *  # noqa: F401,F403,E402

# Phase-3 orchestration suite (job queue, atomic claiming, retry/stale,
# pause/resume/cancel, checkpoints, execution-time revalidation, subprocess
# safety, payload security, tenant isolation, CLI smoke) — same suite.
from test_orchestration import *  # noqa: F401,F403,E402

# Phase-4 intelligence suite (asset intelligence, canonical identity +
# fingerprint + cross-scanner dedup, lifecycle, confidence, risk + snapshots,
# correlation/root-cause/clusters/remediation, evidence graph, temporal
# scan diffs, security + idempotency regressions) — same suite.
from test_intelligence import *  # noqa: F401,F403,E402

# Phase-5/6/7 suites (monitoring, reporting, devsecops) + Phase-8 identity
# (MFA, step-up, OIDC/SAML SSO, SCIM, session hardening) — same suite.
from test_monitoring import *  # noqa: F401,F403,E402
from test_reporting import *  # noqa: F401,F403,E402
from test_devsecops import *  # noqa: F401,F403,E402
from test_identity import *  # noqa: F401,F403,E402

# Phase-9 enterprise-security suite (cloud / container / Kubernetes / IaC:
# provider + fixture determinism, exposure invariant, credential
# encryption-at-rest, CLOUD/CONT/K8S/IAC rules, digest identity, Secret
# metadata-only, secret redaction, explicit failure taxonomy, tenant
# isolation (BOLA), RBAC matrix, in-process job profiles, DevSecOps gate +
# SARIF interop, dashboard isolation, §44 concurrency, §49 failure
# injection, §50 deterministic scale) — same suite.
from test_cloud_security import *  # noqa: F401,F403,E402

# Phase-10 security-operations suite (IOC catalog + safe feed import,
# external attack surface + certificate intelligence, TI correlation
# -> findings, prioritization, threat clusters, investigation cases,
# event enrichment, tenant isolation + rate limits) — same suite.
from test_security_operations import *  # noqa: F401,F403,E402

# Phase-11 data-protection / privacy / secrets / compliance-governance
# suite (classification allowlist + downgrade guard, minimization +
# redaction, secret metadata registry, retention + holds, controlled
# deletion, privacy request workflow, secure exports, compliance evidence
# governance + policy exceptions, audit + tenant isolation, CLI/RBAC,
# dashboard panel, concurrency, deterministic scale) — same suite.
from test_data_governance import *  # noqa: F401,F403,E402

# Phase-12 enterprise data-federation / evidence-exchange / bulk-operations
# / external-integration-governance suite (peer trust lifecycle + SoD
# approval, exchange policies with the never-exportable sensitive classes,
# deterministic provider-neutral packages with canonical sha256 integrity,
# the 12-gate inbound validation chain, provenance-preserving imports
# through the existing finding/asset/evidence/case/IOC pipelines, idempotent
# re-import + collision strategies, bulk ops on the existing job engine,
# the redacted/bounded/audited integration boundary, RBAC where viewers and
# analysts get nothing, tenant isolation, audit-chain verification,
# dashboard/API panels, CLI smoke, failure injection, concurrency and
# bounded scale) — same suite.
from test_federation import *  # noqa: F401,F403,E402

# PART-01 enterprise-foundation suite. Every module below exercises the new
# root-level foundation packages (core/, config/, interfaces/, services/,
# api/, schemas/) that ship OUTSIDE python/ — they are import-only-sibling
# checks, fail-closed configuration checks, engine-registry/health checks,
# JSON-schema contract checks and the repo-wide security baseline. Each
# module inserts the repository ROOT on sys.path itself, so importing them
# here is enough to bring the foundation into this single suite:
#   test_foundation_runtime — injectable UTC clock, Result/Err, ids,
#                             path-safety (traversal/absolute/control-char/
#                             workspace escape), version_info, stdlib
#                             `platform` coexistence after the rename.
#   test_configuration      — fail-closed defaults, unset/empty/invalid
#                             distinction, production refusals, secret
#                             redaction in logs, feature-flag gating.
#   test_engine_registry    — Python/Rust/C++/unavailable/degraded modelling,
#                             capability reporting, health service liveness/
#                             readiness/dependency semantics, api.v1 handlers.
#   test_schemas            — event/finding/health JSON schemas: stability,
#                             required fields, UTC timestamps, trace ids,
#                             enum agreement with core.constants.
#   test_security_baseline  — repo-wide hygiene: no hard-coded secrets, no
#                             dangerous dynamic imports, no insecure default
#                             bindings, redaction coverage, dependency
#                             hygiene, and no offensive automation in the
#                             foundation layer.
from test_foundation_runtime import *  # noqa: F401,F403,E402
from test_configuration import *  # noqa: F401,F403,E402
from test_engine_registry import *  # noqa: F401,F403,E402
from test_schemas import *  # noqa: F401,F403,E402
from test_security_baseline import *  # noqa: F401,F403,E402

import password_audit
import phishing_detector
import log_analyzer
import template_engine
import spider
import sarif_export
import active_fuzzer
import waf_detect
import subdomain_enum
import cloud_check
import dashboard
import workflow


class TestPasswordAudit(unittest.TestCase):
    def test_weak_common(self):
        r = password_audit.analyze("password123")
        self.assertLess(r["score"], 40)
        self.assertIn("Very Weak", r["strength"])

    def test_strong_random(self):
        r = password_audit.analyze("Xk9#mQz!vR2$tLp7@Wq")
        self.assertGreaterEqual(r["score"], 90)
        self.assertIn("Excellent", r["strength"])

    def test_name_year_style(self):
        r = password_audit.analyze("Rahim2019")
        self.assertTrue(any("year" in f.lower() for f in r["findings"]))

    def test_breached_list_hit(self):
        r = password_audit.analyze("qwerty")
        self.assertTrue(any("breached" in f.lower() for f in r["findings"]))


class TestPhishing(unittest.TestCase):
    def test_obvious_phish(self):
        r = phishing_detector.analyze_url("https://paypa1-secure-verify.tk/login/update-account")
        self.assertGreaterEqual(r["phishing_score"], 55)

    def test_bkash_lookalike(self):
        r = phishing_detector.analyze_url("https://bkash-verify-account.xyz/otp")
        self.assertGreaterEqual(r["phishing_score"], 60)

    def test_safe_url(self):
        r = phishing_detector.analyze_url("https://www.google.com/search?q=django")
        self.assertLess(r["phishing_score"], 35)

    def test_at_trick(self):
        r = phishing_detector.analyze_url("https://www.google.com@evil-site.tk/login")
        self.assertGreaterEqual(r["phishing_score"], 50)
        self.assertTrue(any("@" in x for x in r["indicators"]))


class TestLogAnalyzer(unittest.TestCase):
    SAMPLE = [
        '103.94.153.21 - - [03/Sep/2026:10:15:22 +0000] "GET /index.php?id=1 UNION SELECT '
        'username,password FROM users HTTP/1.1" 200 1532 "-" "sqlmap/1.7"',
        '203.0.113.77 - - [03/Sep/2026:10:15:24 +0000] "POST /login HTTP/1.1" 401 512 "-" '
        '"Mozilla/5.0"',
        '198.51.100.9 - - [03/Sep/2026:10:17:01 +0000] "GET / HTTP/1.1" 200 9021 "-" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    ]

    def test_detects_sqlmap(self):
        r = log_analyzer.analyze(self.SAMPLE)
        self.assertIsNotNone(r)
        self.assertIn("SQLMap scanner", r["attack_classes"])

    def test_counts(self):
        r = log_analyzer.analyze(self.SAMPLE)
        self.assertEqual(r["total_requests"], 3)
        self.assertEqual(r["unique_ips"], 3)


class TestWebAudit(unittest.TestCase):
    """Runs the full web auditor against a local temp server."""

    def test_local_http_server(self):
        import http.server
        import socketserver
        import threading
        import io

        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<h1>test</h1>")
        with open(os.path.join(root, ".env"), "w") as f:
            f.write("SECRET=x")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            import subprocess
            out = tempfile.mktemp(suffix=".html")
            r = subprocess.run(
                [sys.executable, os.path.join(PY, "web_security_audit.py"),
                 "--url", f"http://127.0.0.1:{port}", "--out", out,
                 "--json", tempfile.mktemp(suffix=".json"), "--timeout", "3"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, encoding="utf-8") as fh:
                html = fh.read()
            self.assertIn("SECURITY AUDIT REPORT", html)
            self.assertIn("GRADE", html)
            httpd.shutdown()


class TestApiAudit(unittest.TestCase):
    def test_api_auditor_local(self):
        import http.server
        import socketserver
        import threading
        import subprocess
        import tempfile as tf

        root = tf.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write('{"status":"ok"}')

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            out = tf.mktemp(suffix=".json")
            r = subprocess.run(
                [sys.executable, os.path.join(PY, "api_security_audit.py"),
                 "--url", f"http://127.0.0.1:{port}", "--json", out,
                 "--timeout", "3"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("findings", data)
            self.assertIn("score", data)
            httpd.shutdown()


class TestPdfReport(unittest.TestCase):
    def test_pdf_generation(self):
        import subprocess
        data = {"tool": "SecuAudit", "target": "https://example.com",
                "scan_date": "2026-09-04T00:00:00", "score": 38.0, "grade": "E",
                "summary": {"High": 1, "Medium": 2},
                "findings": [
                    {"severity": "High", "title": "Test finding",
                     "evidence": "evidence line here", "remediation": "fix it"},
                ],
                "disclaimer": "authorized only"}
        jf = tempfile.mktemp(suffix=".json")
        pf = tempfile.mktemp(suffix=".pdf")
        with open(jf, "w") as f:
            json.dump(data, f)
        r = subprocess.run(
            [sys.executable, os.path.join(PY, "pdf_report.py"), "--json", jf,
             "--out", pf, "--title", "Test"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        data_bytes = open(pf, "rb").read()
        self.assertTrue(data_bytes.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", data_bytes)
        self.assertGreater(len(data_bytes), 1000)


class TestCveMiniDb(unittest.TestCase):
    def test_mini_db_lookup(self):
        import cve_lookup
        entries = cve_lookup.mini_db_lookup("nginx", "nginx")
        self.assertGreater(len(entries), 0)
        self.assertTrue(any(e["id"].startswith("CVE") for e in entries))
        entries2 = cve_lookup.mini_db_lookup("", "log4j")
        self.assertGreater(len(entries2), 0)
        self.assertGreater(entries2[0]["cvss"]["score"], 0)


class TestMainCli(unittest.TestCase):
    def test_main_help(self):
        import subprocess
        r = subprocess.run([sys.executable, os.path.join(ROOT, "main.py"), "--help"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        for sub in ("web", "api", "ports", "fuzz", "phishing", "cve", "logs",
                    "passwd", "report", "audit", "demo", "scan", "spider", "sarif",
                    "active", "waf", "subdomain", "cloud", "dashboard", "hunt",
                    "platform"):
            self.assertIn(sub, r.stdout)


class TestActiveFuzzer(unittest.TestCase):
    """Active fuzzing against a local 'vulnerable' app (fully controlled)."""

    def _serve(self, handler_cls):
        import http.server, socketserver, threading
        httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, port

    def test_sqli_error_detection(self):
        import http.server
        import urllib.parse

        class Vuln(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                val = q.get("id", [""])[0]
                if "'" in val or "OR" in val.upper() or "UNION" in val.upper():
                    body = b"You have an error in your SQL syntax; check the manual"
                    self.send_response(500)
                else:
                    body = b"OK"
                    self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._serve(Vuln)
        try:
            result = active_fuzzer.run(
                f"http://127.0.0.1:{port}/?id=1", "id", "sqli", 0.0, 10,
                None, {}, 5, True)
            types = [f["type"] for f in result["findings"]]
            self.assertTrue(any("SQL Injection" in t for t in types), types)
        finally:
            httpd.shutdown()

    def test_xss_reflection(self):
        import http.server, urllib.parse

        class Vuln(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                val = q.get("q", [""])[0]
                body = ("<html>" + val + "</html>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._serve(Vuln)
        try:
            result = active_fuzzer.run(
                f"http://127.0.0.1:{port}/?q=hello", "q", "xss", 0.0, 10,
                None, {}, 5, True)
            types = [f["type"] for f in result["findings"]]
            self.assertTrue(any("XSS" in t for t in types), types)
        finally:
            httpd.shutdown()

    def test_waf_block_flagged(self):
        import http.server

        class BlockSrv(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if "OR" in self.path or "'" in self.path:
                    self.send_response(403)
                    body = b"Request blocked by ModSecurity"
                else:
                    self.send_response(200)
                    body = b"OK"
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._serve(BlockSrv)
        try:
            result = waf_detect.detect(f"http://127.0.0.1:{port}/", 3)
            vendors = [w["vendor"] for w in result["waf"]]
            self.assertTrue(any("ModSecurity" in v for v in vendors), vendors)
        finally:
            httpd.shutdown()


class TestWafDetect(unittest.TestCase):
    def test_cloudflare_headers(self):
        import http.server

        class CF(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"OK"
                self.send_response(200)
                self.send_header("cf-ray", "7a1f2b3c4d5e6f78-SIN")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with socketserver.TCPServer(("127.0.0.1", 0), CF) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            result = waf_detect.detect(f"http://127.0.0.1:{port}/", 3)
            vendors = [w["vendor"] for w in result["waf"]]
            self.assertIn("Cloudflare", vendors)
            httpd.shutdown()


class TestCveTemplates(unittest.TestCase):
    def test_template_count(self):
        templates = template_engine.load_templates(os.path.join(ROOT, "templates"))
        self.assertGreaterEqual(len(templates), 25)

    def test_mini_db_kev(self):
        import cve_lookup
        for product, cve in (("react", "CVE-2025-55182"), ("citrix", "CVE-2025-5777")):
            entries = cve_lookup.mini_db_lookup("", product)
            self.assertTrue(any(e["id"] == cve for e in entries), f"{cve} missing")


class TestTemplateEngine(unittest.TestCase):
    def test_all_templates_parse(self):
        templates = template_engine.load_templates(os.path.join(ROOT, "templates"))
        self.assertGreaterEqual(len(templates), 14)
        for t in templates:
            self.assertIn("id", t)
            self.assertIn("requests", t)

    def test_version_compare(self):
        self.assertEqual(template_engine.ver_compare("1.13.2", "1.13.2"), 0)
        self.assertEqual(template_engine.ver_compare("1.13.3", "1.13.2"), 1)
        self.assertEqual(template_engine.ver_compare("1.12.1", "1.13.0"), -1)

    def test_mini_yaml(self):
        data = template_engine.parse_yaml(
            'id: test\ninfo:\n  name: "T: x"\n  severity: high\n'
            'requests:\n  - method: GET\n    path: "/x"\n'
            '    matchers:\n      - type: status\n        value: 200\n')
        self.assertEqual(data["id"], "test")
        self.assertEqual(data["info"]["name"], "T: x")
        self.assertEqual(data["requests"][0]["path"], "/x")
        self.assertEqual(data["requests"][0]["matchers"][0]["value"], 200)

    def test_git_template_matches_local_server(self):
        import http.server, socketserver, threading, tempfile
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        os.makedirs(os.path.join(root, ".git"), exist_ok=True)
        with open(os.path.join(root, ".git", "HEAD"), "w") as f:
            f.write("ref: refs/heads/main\n")
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<h1>x</h1>")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            tpl = template_engine.load_templates(os.path.join(ROOT, "templates", "misconfig"))
            findings = []
            for t in tpl:
                if t["id"] != "misconfig-git-exposure":
                    continue
                findings.extend(template_engine.run_template(
                    t, f"http://127.0.0.1:{port}", 5, {}))
            self.assertTrue(any(f["id"] == "misconfig-git-exposure" for f in findings))
            httpd.shutdown()

    def test_hsts_missing_template(self):
        import http.server, socketserver, threading, tempfile
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<h1>no headers here</h1>")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            tpls = template_engine.load_templates(os.path.join(ROOT, "templates", "headers"))
            hits = []
            for t in tpls:
                if t["id"] != "header-hsts-missing":
                    continue
                hits.extend(template_engine.run_template(t, f"http://127.0.0.1:{port}", 5, {}))
            self.assertTrue(any(f["id"] == "header-hsts-missing" for f in hits))
            httpd.shutdown()


class TestSpider(unittest.TestCase):
    def test_spider_discovers_links(self):
        import http.server, socketserver, threading, tempfile
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write('<a href="/about">About</a><a href="/api/users">Users</a>'
                    '<form action="/login" method="post"><input name="user"></form>')
        with open(os.path.join(root, "about.html"), "w") as f:
            f.write('<a href="/">home</a>')
        os.makedirs(os.path.join(root, "api"), exist_ok=True)
        with open(os.path.join(root, "api", "users"), "w") as f:
            f.write("[]")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            stats, endpoints, param_urls, api_candidates, pages = spider.crawl(
                f"http://127.0.0.1:{port}/", depth=2, limit=20, timeout=5)
            self.assertGreaterEqual(stats["pages_crawled"], 2)
            apis = [e["url"] for e in api_candidates]
            self.assertTrue(any("api" in u for u in apis))
            self.assertTrue(any(e.get("form") for e in endpoints))
            httpd.shutdown()


class TestSubdomainEnum(unittest.TestCase):
    def test_crt_parser(self):
        """Verify name extraction from the crt.sh JSON structure."""
        sample = [
            {"name_value": "*.example.com\nwww.example.com"},
            {"name_value": "api.example.com"},
        ]
        names = sorted({n for e in sample
                        for n in str(e["name_value"]).splitlines()
                        if n.strip() and "*" not in n and " " not in n})
        self.assertIn("www.example.com", names)
        self.assertIn("api.example.com", names)
        self.assertNotIn("*.example.com", names)

    def test_default_wordlist_has_core_entries(self):
        self.assertIn("www", subdomain_enum.DEFAULT_WORDS)
        self.assertIn("api", subdomain_enum.DEFAULT_WORDS)
        self.assertIn("admin", subdomain_enum.DEFAULT_WORDS)

    def test_domain_validation(self):
        bad = "not_a_domain"
        with self.assertRaises(SystemExit):
            subdomain_enum.enumerate(bad, False, [], 10, False)


class TestCloudScope(unittest.TestCase):
    def _http_server(self, handler_cls):
        import http.server
        httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, port

    def test_s3_public_listing(self):
        import http.server

        class S3(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = (b'<?xml version="1.0"?><ListBucketResult>'
                        b'<Name>demo</Name><Contents><Key>secret.zip</Key></Contents>'
                        b'</ListBucketResult>')
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._http_server(S3)
        try:
            r = cloud_check.probe_s3_url(f"http://127.0.0.1:{port}/")
            self.assertIn("PUBLIC LISTING", r["status"])
            self.assertEqual(r["severity"], "High")
        finally:
            httpd.shutdown()

    def test_s3_private_via_403(self):
        import http.server

        class S3(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"<Error><Code>AccessDenied</Code></Error>"
                self.send_response(403)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd, port = self._http_server(S3)
        try:
            r = cloud_check.probe_s3_url(f"http://127.0.0.1:{port}/")
            self.assertIn("private", r["status"])
            self.assertEqual(r["severity"], "Info")
        finally:
            httpd.shutdown()

    def test_redis_noauth(self):
        import socketserver as ss

        class Redis(ss.StreamRequestHandler):
            def handle(self):
                data = self.rfile.readline()
                if data.strip().upper() == b"PING":
                    self.wfile.write(b"+PONG\r\n")
                else:
                    self.wfile.write(b"-ERR unknown\r\n")

        httpd = ss.TCPServer(("127.0.0.1", 0), Redis)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            r = cloud_check.check_redis("127.0.0.1", port)
            self.assertEqual(r["severity"], "Critical")
            self.assertIn("NO AUTH", r["status"])
        finally:
            httpd.shutdown()

    def test_redis_authrequired(self):
        import socketserver as ss

        class Redis(ss.StreamRequestHandler):
            def handle(self):
                data = self.rfile.readline()
                self.wfile.write(b"-NOAUTH Authentication required.\r\n")

        httpd = ss.TCPServer(("127.0.0.1", 0), Redis)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            r = cloud_check.check_redis("127.0.0.1", port)
            self.assertEqual(r["severity"], "Info")
            self.assertIn("auth required", r["status"].lower())
        finally:
            httpd.shutdown()


class TestDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="secupulse_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        cls.port = _free_port()
        # two "clients" (tenants) with one scan each
        os.makedirs(os.path.join(cls.tmp, "acme-corp"), exist_ok=True)
        os.makedirs(os.path.join(cls.tmp, "globex"), exist_ok=True)
        with open(os.path.join(cls.tmp, "acme-corp", "audit.json"), "w") as fh:
            json.dump({"tool": "SecuAudit", "target": "https://shop.acme.test",
                       "scan_date": "2026-09-04T10:00:00", "score": 63, "grade": "C",
                       "findings": [
                           {"id": "SQLI-1", "title": "Boolean-based SQL injection",
                            "severity": "Critical", "evidence": "?id=1 AND 1=1→200",
                            "remediation": "Parameterised queries."},
                           {"id": "XSS-1", "title": "Reflected XSS", "severity": "High",
                            "evidence": "<script>alert(1)</script> reflected",
                            "remediation": "Output-encode."}],
                       "summary": {"Critical": 1, "High": 1}}, fh)
        with open(os.path.join(cls.tmp, "globex", "cloud.json"), "w") as fh:
            json.dump({"tool": "CloudScope", "target": "s3://globex-assets",
                       "scan_date": "2026-09-03T09:00:00",
                       "checks": [{"service": "S3", "status": "PUBLIC LISTING ENABLED",
                                   "severity": "High", "evidence": "ListBucketResult",
                                   "remediation": "Block public access"},
                                  {"service": "Redis", "status": "OPEN — NO AUTH (CRITICAL)",
                                   "severity": "Critical", "evidence": "+PONG",
                                   "remediation": "requirepass"}]}, fh)
        cls.scans, cls.tenants = dashboard.discover(cls.tmp)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", cls.port), dashboard.Handler)
        dashboard.Handler.root = cls.tmp
        dashboard.Handler.scans = cls.scans
        dashboard.Handler.tenants = cls.tenants
        dashboard.Handler.token = None
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _get(self, path, token=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "ignore")

    def test_discover_tenants(self):
        self.assertIn("acme-corp", self.tenants)
        self.assertIn("globex", self.tenants)
        self.assertEqual(len(self.scans), 2)

    def test_normalize_web_findings(self):
        sc = next(s for s in self.scans if s["tool"] == "SecuAudit")
        self.assertEqual(len(sc["findings"]), 2)
        self.assertEqual(sc["summary"]["Critical"], 1)
        self.assertEqual(sc["score"], 63)

    def test_normalize_cloud_checks(self):
        sc = next(s for s in self.scans if s["tool"] == "CloudScope")
        self.assertEqual(sc["kind"], "cloud")
        crit = [f for f in sc["findings"] if f["severity"] == "Critical"]
        self.assertEqual(len(crit), 1)
        self.assertIn("NO AUTH", crit[0]["title"])

    def test_api_scans(self):
        code, body = self._get("/api/scans")
        self.assertEqual(code, 200)
        data = json.loads(body)
        self.assertEqual(data["count"], 2)

    def test_api_tenant_scan(self):
        code, body = self._get("/api/tenant/acme-corp/scan/audit")
        self.assertEqual(code, 200)
        data = json.loads(body)
        self.assertEqual(data["findings"][0]["id"], "SQLI-1")
        code, _ = self._get("/api/tenant/acme-corp/scan/does-not-exist")
        self.assertEqual(code, 404)

    def test_status_roundtrip(self):
        body = ("/api/status?t=acme-corp&s=audit&f=SQLI-1&status=mitigated&note=fix+deployed")
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{body}", method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            self.assertEqual(r.status, 200)
        st = dashboard.load_status(self.tmp)
        self.assertEqual(st["acme-corp/audit/SQLI-1"]["status"], "mitigated")

    def test_html_pages_render(self):
        code, body = self._get("/")
        self.assertEqual(code, 200)
        self.assertIn("SecuPulse", body)
        self.assertIn("acme-corp", body)
        code, body = self._get("/t/acme-corp/s/audit")
        self.assertEqual(code, 200)
        self.assertIn("Boolean-based SQL injection", body)
        self.assertIn("Parameterised queries", body)

    def test_path_traversal_denied(self):
        code, _ = self._get("/export/acme-corp/..%2f..%2fetc%2fpasswd")
        self.assertIn(code, (400, 404))


class TestDiscoverMisc(unittest.TestCase):
    def test_tool_less_json_and_subdomain_normalisation(self):
        tmp = tempfile.mkdtemp(prefix="secupulse2_")
        try:
            with open(os.path.join(tmp, "subs.json"), "w") as fh:
                json.dump({"domain": "example.com", "count": 3,
                           "subdomains": {
                               "www.example.com": {"sources": ["crt.sh"],
                                                   "ips": ["93.184.216.34"]},
                               "mail.example.com": {"sources": ["crt.sh"], "ips": []}}}, fh)
            scans, tenants = dashboard.discover(tmp)
            self.assertEqual(len(scans), 1)
            sc = scans[0]
            self.assertEqual(sc["kind"], "subdomain")
            self.assertEqual(sc["tool"], "subs")          # falls back to filename
            self.assertEqual(sum(sc["summary"].values()), 2)
            by_title = {f["title"]: f["severity"] for f in sc["findings"]}
            self.assertTrue(any("www.example.com" in t and s == "Low"
                                for t, s in by_title.items()))      # live host
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestWorkflow(unittest.TestCase):
    """End-to-end workflow chain against local servers (no internet needed)."""

    def _vuln_site(self):
        """Site with: homepage links, a param URL (SQLi-vulnerable), /admin."""
        import http.server

        class V(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                path = urllib.parse.urlparse(self.path).path
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                v = q.get("id", [""])[0]
                if path == "/":
                    body = (b"<html><head><title>Acme Shop</title></head><body>"
                            b"<a href='/item?id=1'>item</a>"
                            b"<a href='/admin'>admin</a></body></html>")
                elif path == "/item":
                    if "'" in v or " AND " in v.upper():
                        body = (b"You have an error in your SQL syntax; "
                                b"check the manual for MySQL")
                    else:
                        body = b"product page"
                elif path == "/admin":
                    body = b"<html><title>Admin</title><body>login</body></html>"
                else:
                    body = b"404"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd = socketserver.TCPServer(("127.0.0.1", 0), V)
        httpd.timeout = 1
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd

    def test_dns_cname_parser(self):
        # encoding/decoding round-trip through the raw DNS helpers
        self.assertEqual(
            workflow._decode_name(b"\x03www\x07example\x03com\x00", 0),
            "www.example.com")

    def test_full_chain_local(self):
        httpd = self._vuln_site()
        port = httpd.server_address[1]
        try:
            out_dir = tempfile.mkdtemp(prefix="hunter_")
            self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
            r = workflow.run_workflow(
                "acme.test",
                use_crt=False, do_brute=False, do_takeover=False, do_waf=False,
                active=True, payloads=4, delay=0.05, timeout=5,
                hosts_override=[f"127.0.0.1:{port}"],
                out_dir=out_dir)
            self.assertEqual(r["host_count"], 1)
            self.assertEqual(r["hosts"][0]["title"], "Acme Shop")
            self.assertEqual(r["hosts"][0]["status"], 200)
            # spider found param + template scan + active fuzz all produced findings
            sevs = [f.get("severity") for f in r["findings"]]
            self.assertIn("Critical", sevs)
            titles = " ".join(f.get("title", "") for f in r["findings"])
            self.assertIn("SQL", titles)
            self.assertIn("param_urls", r)
            self.assertTrue(any("item" in u for u in r["param_urls"]))
            self.assertGreaterEqual(len(r["findings"]), 1)
            # Critical SQLi (weight 25 each) + template findings deducted → ≤ 75
            self.assertGreaterEqual(r["score"], 0.0)
            self.assertLessEqual(r["score"], 75.0)
            self.assertIn(r["grade"], "ABCDEF")
            self.assertTrue(r["active_mode"])
        finally:
            httpd.shutdown()

    def test_takeover_detection_local(self):
        """Dangling CNAME → known service marker on the HTTP response."""
        import http.server

        class G(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"<html><body>There isn't a GitHub Pages site here.</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd = socketserver.TCPServer(("127.0.0.1", 0), G)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        try:
            # fake a dangling CNAME: sub.foo.github.io
            res = workflow.takeover_check(f"127.0.0.1:{port}",
                                          cname="evil.foo.github.io", timeout=4)
            self.assertTrue(res["takeover"])
            self.assertIn("github.io", res["service"])
            self.assertIn("GitHub Pages", res["evidence"])
        finally:
            httpd.shutdown()

    def test_probe_local(self):
        httpd = self._vuln_site()
        port = httpd.server_address[1]
        try:
            p = workflow.probe(f"127.0.0.1:{port}", timeout=5)
            self.assertIsNotNone(p)
            self.assertEqual(p["status"], 200)
            self.assertEqual(p["title"], "Acme Shop")
        finally:
            httpd.shutdown()


class TestSarif(unittest.TestCase):
    def test_sarif_structure(self):
        data = {"tool": "Nucleus", "target": "https://example.com",
                "scan_date": "2026-09-04T00:00:00",
                "findings": [
                    {"id": "header-hsts-missing", "title": "Missing HSTS",
                     "severity": "High", "evidence": "no header",
                     "remediation": "add HSTS", "description": "desc",
                     "tags": "header,hardening"},
                    {"id": "misconfig-git-exposure", "title": "Git exposed",
                     "severity": "Critical", "evidence": "200", "remediation": "block"},
                ]}
        sarif = sarif_export.to_sarif(data)
        self.assertEqual(sarif["version"], "2.1.0")
        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(len(driver["rules"]), 2)
        self.assertEqual(len(sarif["runs"][0]["results"]), 2)
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")


def load_tests(loader, standard_tests, pattern):
    """Load every test module without star-import name collisions.

    The legacy runner imports modules with ``from test_x import *`` because
    its local integration tests reuse helpers from those modules. That keeps
    those helpers available, but repeated TestCase names in separate modules
    overwrite one another in this module's global namespace. Load each module
    independently here, then add only the TestCase classes defined locally.
    """
    module_names = (
        "test_foundation",
        "test_security",
        "test_orchestration",
        "test_intelligence",
        "test_monitoring",
        "test_reporting",
        "test_devsecops",
        "test_identity",
        "test_cloud_security",
        "test_security_operations",
        "test_data_governance",
        "test_federation",
        "test_foundation_runtime",
        "test_configuration",
        "test_engine_registry",
        "test_schemas",
        "test_security_baseline",
    )
    missing_modules = [name for name in module_names if name not in sys.modules]
    if missing_modules:
        raise RuntimeError(
            "custom test runner did not import required modules: "
            + ", ".join(missing_modules)
        )

    suite = unittest.TestSuite()
    for module_name in module_names:
        suite.addTests(loader.loadTestsFromModule(sys.modules[module_name]))

    local_test_cases = {}
    for candidate in globals().values():
        if (
            isinstance(candidate, type)
            and issubclass(candidate, unittest.TestCase)
            and candidate is not unittest.TestCase
            and candidate.__module__ == __name__
        ):
            local_test_cases.setdefault(candidate, None)
    for test_case in local_test_cases:
        suite.addTests(loader.loadTestsFromTestCase(test_case))
    return suite


if __name__ == "__main__":
    print("SecuToolkit test suite — web, api, phishing, logs, cve, pdf, cli\n")
    unittest.main(verbosity=2)
