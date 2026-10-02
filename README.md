# 🛡️ SecuToolkit — World-Class Cybersecurity Suite (Python + Rust)

**Ainul-এর Selling Toolkit** — Zero-dependency, 100% tested security tool suite
for Fiverr/Upwork. **Phases 1–12 complete**, plus **PART 01 — Enterprise
Foundation** (§PART 01 below). Covered: platform foundation, identity/RBAC/audit,
managed scan execution, asset intelligence + finding correlation/dedup/risk/
evidence graph, continuous monitoring/alerts/remediation, enterprise reporting
+ security analytics + compliance evidence, DevSecOps security gates +
provider-neutral CI/CD integration, enterprise identity & access (TOTP MFA,
OIDC/SAML SSO, SCIM 2.0, break-glass, session revocation), cloud/container/
Kubernetes/IaC security, security operations + threat intelligence + EASM,
data protection + privacy + secrets + compliance governance, and enterprise
data federation + evidence exchange + external-integration governance.

**1181 passing tests in the final custom run.** Exact results: `unittest`
discovery ran 1133 module tests (OK), and `python3 tests/run_tests.py` ran 1181
(1133 module tests + 48 runner-local integration tests, OK). The earlier 1147
count hid 34 old tests because star imports overwrote duplicate TestCase names;
the runner now loads modules independently. PART 01 adds 192 foundation tests.
See §PART 01 for the breakdown and validation log details.

```
security-toolkit/
├── README.md                    ← এই ফাইল
├── main.py                      ← ⭐ এক কমান্ডে সব (unified CLI, 29 subcommands)
├── run_audit.sh                 ← এক-ক্লিক ফুল অডিট (Rust + Python)
├── python/
│   ├── web_security_audit.py    ← ওয়েব অডিট → HTML রিপোর্ট + JSON
│   ├── api_security_audit.py    ← API অডিট (OWASP API Top 10)
│   ├── template_engine.py       ← Nucleus — Nuclei-style YAML template engine
│   ├── spider.py                ← crawler / endpoint discovery
│   ├── active_fuzzer.py         ← Injector — SQLi/XSS/CMDi/traversal fuzzer
│   ├── waf_detect.py            ← WallFinder — WAF fingerprinting (30+ vendors)
│   ├── subdomain_enum.py        ← ⭐ Part 5: SubKraken — crt.sh + DNS brute subdomain enum
│   ├── cloud_check.py           ← ⭐ Part 5: CloudScope — S3/GCS/Azure/Redis/Mongo/ES exposure
│   ├── dashboard.py             ← ⭐ Part 6: SecuPulse — findings web portal (multi-client)
│   ├── workflow.py              ← ⭐ NEW Part 7: Hunter — one-command bug-bounty chain
│                                   (subdomain→probe→takeover→crawl→templates→fuzz→report)
│   ├── sarif_export.py          ← findings → SARIF 2.1.0 (CI/CD)
│   ├── phishing_detector.py     ← Phishing URL detector (Levenshtein engine)
│   ├── log_analyzer.py          ← Access-log IDS (SQLi/XSS/scanner detection)
│   ├── cve_lookup.py            ← Real CVE lookup (CIRCL API + offline fallback)
│   ├── cve_mini_db.json         ← Mini CVE knowledge base (20 real CVEs)
│   ├── password_audit.py        ← Password strength auditor
│   └── pdf_report.py            ← Pure-stdlib PDF report generator
├── templates/                   ← 25 YAML templates (Nucleus engine)
│   ├── misconfig/               ← git, .env, actuator, phpmyadmin, backups, server-status, swagger, graphql, dir-listing, elasticsearch
│   ├── headers/                 ← hsts, csp, x-frame, x-content-type, referrer-policy
│   └── cve/                     ← nginx, Apache, PHP + TeamCity CVE-2023-42793, Confluence CVE-2023-22515,
│                                   WordPress/GitLab/Tomcat/Jenkins version ranges, Log4Shell stack-check
│                                   (version-range matching; KEV-aware)
├── rust/
│   ├── port_scanner.rs          ← RapidScan: 1000 ports in 0.03s!
│   └── dir_fuzzer.rs            ← RapidDir: concurrent directory fuzzer
├── tests/run_tests.py           ← full regression: 757 tests (all phases)
├── tests/test_monitoring.py     ← Phase-5 suite (110 tests)
├── tests/test_reporting.py      ← Phase-6 suite (76 tests)
├── tests/test_identity.py       ← Phase-8 suite (100 tests: MFA/SSO/SCIM/break-glass)
├── tests/test_cloud_security.py ← Phase-9 suite (63 tests: cloud/container/K8s/IaC)
├── python/cloud_security.py     ← Phase-9 core: providers, CLOUD rules, persistence
├── python/container_security.py ← Phase-9: digest identity, CONT rules, CVE normalize
├── python/kubernetes_security.py← Phase-9: manifest parser, K8S rules, Secret metadata-only
├── python/iac_security.py       ← Phase-9: TF/CFN/YAML parser, IAC rules, redaction
├── cloudsec_cmd.py              ← Phase-9 CLI surface (main.py cloudsec ...)
├── sample_audit.html            ← ক্লায়েন্ট-রেডি ডেমো রিপোর্ট (HTML)
└── sample_audit.pdf             ← ক্লায়েন্ট-রেডি ডেমো রিপোর্ট (PDF)
```

---

## 🏗️ PART 01 — Enterprise Foundation

The foundation is a **new layer that sits beside the working system**, not a
rewrite of it. `core/`, `config/`, `interfaces/`, `services/`, `api/` and
`schemas/` import nothing from `python/`, so they are testable in isolation;
the existing domain code keeps working untouched.

```
security-toolkit/
├── core/           clock (UTC, injectable), paths (escape-safe), ids,
│                errors, result (Ok/Err), constants, version, runtime
├── config/         settings (validating, fail-closed), logging (redacting
│                filter), feature_flags
├── interfaces/     telemetry, engine, secrets, scanner, storage, policy
│                — Protocol contracts only
├── services/       engine_registry (Python/Rust/C++/unavailable/degraded),
│                health_service (liveness/readiness), capability_service
├── api/v1/         /livez /readyz /healthz /metadata /version
│                /capabilities /features
├── schemas/        event / finding / health JSON Schemas (draft 2020-12)
├── native/rust/    engine_core — zero deps, #![forbid(unsafe_code)]
├── native/cpp/     security_engine — C++17, RAII, hardened flags
└── web/ infra/     documented placeholders — **nothing implemented**
```

### Properties the foundation guarantees

| Guarantee | Where | How it is enforced |
|---|---|---|
| Clock is UTC-aware and injectable | `core/clock.py` | naive datetimes are rejected; expiry uses UTC epoch — never `time.mktime()`, which is local-time and would shift every expiry by the host offset |
| Config fails closed | `config/settings.py` | defaults bind `127.0.0.1`, require auth + TLS, `debug=False`; production **refuses** `debug`, disabled auth, disabled TLS or a `0.0.0.0` bind |
| Unset ≠ empty ≠ invalid | `config/settings.py` | three distinct error codes instead of one falsy check |
| Secrets never reach a log | `config/logging.py` | redaction is a `logging.Filter` on the handler, so it scrubs every record regardless of call site; by key name *and* by value shape (Authorization, bearer, cookies, passwords, API keys, private keys, webhook secrets) |
| No custom cryptography | `interfaces/secrets.py` | secrets are an **interface only** — a `SecretValue` refuses to hash/print its material, and the module is AST-checked to contain no crypto primitives |
| Path safety | `core/paths.py` | rejects `..`, absolute components, drive-qualified paths and control characters; resolves symlinks *before* the containment check |
| Engines are never faked | `services/engine_registry.py` | Rust/C++ engines are declared but register as `unavailable` **with a reason**; `execute()` raises instead of returning an empty result; the registry empty state is `unknown`, not `healthy` |
| Health never leaks | `services/health_service.py` | liveness ignores dependencies, readiness consults them and fails closed; probes report the exception **type** only |
| Policy is deny-by-default | `interfaces/policy.py` | absence of a rule is a denial, and an `allow` requires a recorded reason |
| Schemas are versioned | `schemas/` | closed enums, UTC-only timestamps, `schema_version` pinned to `1` and checked against the Rust **and** C++ declarations |
| Dependencies are justified | `requirements.txt` | **empty on purpose** — PART 01 adds zero runtime dependencies; `requirements-dev.txt` holds only mypy + ruff |

### The `platform` collision (PART 01's mandatory first fix)

`python/platform.py` shadowed the standard-library `platform` module for every
process that put `python/` on `sys.path` — which every CLI entrypoint does — so
`platform.system()` raised `AttributeError`. It is renamed to
`python/platform_service.py`, all 26 import sites across 17 files were
rewritten, and the old path was **deleted rather than left as a shim**,
because a module at that path recreates the exact bug. Regression tests assert
that `import platform` now resolves to the standard library, that no project
symbol leaks into it, and that both modules are usable in one process.

### Validation — actually executed

```bash
python3 -m compileall .                                   # exit 0
python3 -m unittest discover -s tests -p 'test_*.py' -v  # 1133 tests · OK, exit 0
python3 tests/run_tests.py                                # 1181 tests · OK, exit 0
python3 -m mypy --config-file pyproject.toml core config interfaces services api
                                                          # Success: no issues found in 28 source files
python3 -m ruff check core config interfaces services api schemas native
                                                          # All checks passed!
cargo check  --manifest-path native/rust/Cargo.toml       # clean
cargo test   --manifest-path native/rust/Cargo.toml       # 20 passed; 0 failed
cmake -S native/cpp -B native/cpp/build && cmake --build native/cpp/build
./native/cpp/build/security_engine_tests                  # 42/42 checks passed, exit 0
```

The foundation packages are lint- and type-clean under the strict settings in
`pyproject.toml`. Two rules are suppressed **in place, with a reason**: `S105`
on `secret_provider = "env"` (a provider *name*, not a credential) and `S104`
on the all-interface literal inside the guard that *rejects* all-interface
binding. Suppressing the guard's own literal is correct; weakening the guard
would not be.

Legacy code is **not** yet lint-clean: `python3 -m ruff check .` reports 880
findings across `python/`, `main.py` and the older test modules (mostly
`typing`→`collections.abc` migrations and unused imports). The final custom test
run also emitted 46 `ResourceWarning` instances for unclosed resources in
legacy/test paths; none failed the suite. These are tracked as known debt, not
hidden or silently fixed in PART 01.

New foundation test modules (192 tests, all passing):
`test_foundation_runtime.py` (33), `test_configuration.py` (36),
`test_engine_registry.py` (38), `test_schemas.py` (46),
`test_security_baseline.py` (39).

The custom test runner loads each module independently so repeated `TestCase`
names cannot hide tests. `unittest discover` reports 1133 module tests; the
custom runner adds 48 integration cases defined in `tests/run_tests.py` for a
final 1181.

**Legacy dashboard warning (not changed in PART 01):** `main.py dashboard` and
direct `python/dashboard.py` still default to binding `0.0.0.0` with no token
unless one is supplied. Do not expose that legacy dashboard to an untrusted
network. A later compatibility-reviewed change should default it to loopback
and require authentication for non-loopback binds.

### What PART 01 does **not** do

* `web/` and `infra/` contain **documentation only** — no TypeScript, no
  Dockerfile, no manifests. The files say so explicitly rather than implying
  otherwise.
* No Rust or C++ code is reachable from Python. PART 01 ships an `rlib` only —
  no `cdylib`, no FFI, no autoloading. The engines are *declared*, and report
  themselves `unavailable`.
* No certifications, no compliance claims, no pentest results. `SECURITY.md`
  says this explicitly.
* Phase 13 (enterprise integrations) is **partially** complete: files 1–8 of
  the plan are implemented and green; files 9–12 remain. Nothing in the
  README claims otherwise.

---

## 🚀 কুইক স্টার্ট

```bash
# এক কমান্ডে সব (demo server বানিয়ে ফুল অডিট):
python3 main.py demo

# আসল টার্গেটে ফুল পাইপলাইন (ports + web + api + PDF + SARIF):
python3 main.py audit https://example.com

# আলাদা আলাদা টুল:
python3 main.py web https://example.com          # web audit → HTML+JSON
python3 main.py api https://api.example.com      # API audit (OWASP API Top 10)
python3 main.py scan https://example.com --sarif out.sarif   # Nuclei-style template scan
python3 main.py spider https://example.com --depth 2        # crawl + endpoint discovery
python3 main.py active https://example.com/item?id=1 --type sqli --skip-timebased  # active SQLi/XSS fuzz (AUTHORIZED ONLY)
python3 main.py waf https://example.com          # WAF fingerprinting
python3 main.py subdomain example.com --resolve  # ⭐ Part 5: crt.sh + DNS brute (OSINT, passive!)
python3 main.py cloud --bucket mycompany-assets  # ⭐ Part 5: S3/GCS bucket exposure check
python3 main.py cloud --service 203.0.113.5      # ⭐ Part 5: Redis/Mongo/ES/Memcached port check
python3 main.py dashboard --root results --host 127.0.0.1  # local-only; override the insecure legacy default explicitly
export DASHBOARD_TOKEN='replace-with-a-long-random-token'
python3 main.py dashboard --root results --host 0.0.0.0 --token "$DASHBOARD_TOKEN"  # external bind requires a strong token + trusted TLS proxy
python3 main.py hunt example.com --client acme   # ⭐ Part 7: FULL chain — subdomain→probe→takeover→crawl→templates (passive)
python3 main.py hunt example.com --active --client acme   # ⭐ Part 7: + directed fuzzing on found params (AUTHORIZED ONLY)
python3 main.py hunt example.com --hosts www.example.com,api.example.com   # ⭐ Part 7: skip recon, target specific hosts
python3 main.py sarif --json scan_results.json   # findings JSON → SARIF (GitHub Code Scanning)
python3 main.py ports example.com --top 100      # Rust port scan
python3 main.py fuzz https://example.com         # Rust dir fuzzer
python3 main.py phishing --url "https://paypa1-verify.tk/login"
python3 main.py cve --product nginx              # real internet CVE lookup
python3 main.py logs --log access.log            # IDS on web logs
python3 main.py passwd --password "P@ssw0rd123"
python3 main.py report --json results.json       # JSON → PDF

# টেস্ট:
python3 tests/run_tests.py
```

**Rust binary কম্পাইল (একবার):**
```bash
rustc -O rust/port_scanner.rs -o rust/port_scanner
rustc -O rust/dir_fuzzer.rs -o rust/dir_fuzzer
```
(প্রথমবার `main.py` চালালে অটো-কম্পাইলও হয়ে যায়)

---

## 🧪 Part 2 — নতুন মডিউল (সব লাইভ টেস্টেড)

| মডিউল | কী করে | ব্রেঞ্চমার্ক |
|---|---|---|
| **port_scanner.rs** | Concurrent TCP scan + 200+ service fingerprints | 1000 ports = ০.০৩s |
| **dir_fuzzer.rs** | Concurrent directory fuzzing (122 words default, custom wordlist, `--ext`, `--status` filter) | 122 paths = ২.০s |
| **api_security_audit.py** | OWASP API Top 10 observable checks: docs exposure (API9), auth (API2), rate-limit (API4), misconfig/headers/CORS/verbose errors (API8), SSRF params (API7), method handling (API5) | ৩০+ doc paths checked |
| **phishing_detector.py** | ২৫+ heuristics: TLD trust, brand impersonation via **Levenshtein** (paypa1→paypal d=1), punycode, IP hosts, shorteners, @-trick, port obfuscation, keyword scoring | phish=79/100, google=18/100 |
| **log_analyzer.py** | Web-log IDS: SQLi/XSS/traversal/cmd-injection patterns, scanner UAs (sqlmap/nikto/nuclei/ffuf…), credential-stuffing (401 storms), 404 recon bursts, admin-path probing | 9-line sample → 4 attack classes |
| **cve_lookup.py** | Real internet lookup (CIRCL API, free, no key) + offline `cve_mini_db.json` fallback + cache + 429 backoff | nginx: 8 CVEs + CVSS |
| **pdf_report.py** | Pure-stdlib PDF writer (no pip deps!): title page, severity summary, findings with evidence + remediation, page breaks | valid 2-page PDF |
| **main.py** | Unified CLI + full pipeline (`audit` merges web+api into one PDF) | `airflow`-style orchestration |

---

## 🏗️ Phase 1 — Security Platform Foundation (platform/ সাবসিস্টেম)

সব `token`-ভিত্তিক অ্যাসেসমেন্ট টুলের **পেছনের ডেটা লেয়ার** — Organization → Project →
Assets → Scan (state machine) → Scanner Stages → Findings (deterministic dedupe) →
Evidence (কেন্দ্রীয় secret redaction) → Risk Metadata → Reports → Audit Trail।
কোনো scanner rewrite হয়নি — সবার জন্য **normalization adapter** আছে (`normalize.py`)।

**নতুন কমান্ড:**
```bash
python3 main.py platform init                                    # SQLite + migrations
python3 main.py platform org-create Acme
python3 main.py platform project-create --org <org_id> Web
python3 main.py platform asset-add --project <proj_id> --type domain example.com
python3 main.py platform scope-set --project <proj_id> --allow "*.example.com,10.0.0.0/8"
python3 main.py platform scope-check --project <proj_id> --target api.example.com
python3 main.py platform scan-create --project <proj_id> --profile web-audit
python3 main.py platform scan-status <scan_id> --status running
python3 main.py platform ingest --project <proj_id> --json results.json
python3 main.py platform finding-list --project <proj_id>
python3 main.py platform audit                                    # সব অ্যাকশনের ট্রেইল (sanitized)
```

**কী আছে:**
| অংশ | বিবরণ |
|---|---|
| `models.py` | Scan lifecycle (`pending→queued→running→paused→completed/failed/cancelled`, `cancelling`), Finding lifecycle (`open→acknowledged→resolved/false_positive/accepted_risk`), valid-transition ম্যাপ, same-status = no-op |
| `store.py` | Parameterized SQLite, transactions, FK, indexes, versioned migrations, bounded queries, no plaintext secrets |
| `scope.py` | Reusable scope engine: allow/deny, wildcard `*.example.com`, IP/CIDR/URL validation, out-of-scope rejection; প্রতিটি CLI network entry point-এ `guard()` |
| `redact.py` | একমাত্র redaction source of truth: Authorization/Bearer/cookies/API keys (AWS/GitHub/OpenAI/Slack/Stripe/Google)/passwords/private keys/URL userinfo |
| `normalize.py` | যেকোনো scanner JSON → normalized Asset/Scan/Finding/Evidence; **raw payload verbatim preserved** |
| `platform_service.py` | Persistence service + `maybe_register_scan_result()` — workflow ইন্টিগ্রেশন (opt-in, config-এ `platform.enabled`). **Renamed from `platform.py` in PART 01**: a module at that path shadowed the standard-library `platform` module for every process with `python/` on `sys.path`, so `platform.system()` raised `AttributeError`. |
| `seclog.py` / `sec_config.py` | Structured JSON logging (no secrets) + env-ভিত্তিক config |

**টেস্ট:**
```bash
python3 tests/run_tests.py        # 210 tests — সব GREEN
python3 tests/test_foundation.py  # Phase-1 suite: 64 tests
python3 tests/test_security.py    # Phase-2 suite: 98 tests
```
Security regressions covered: path traversal, SQL injection, malformed input, secret
leakage (এভিডেন্স + audit + logs), lifecycle violations, scope bypass, FK/transaction
atomicity, migration idempotency।

---

## 🔐 Phase 2 — Identity, RBAC, API Auth, Tenant Isolation & Immutable Audit

**কী যোগ হলো (সবকিছু Phase-1 এর উপর EXTENSION, কোনো rewrite নয়):**

| অংশ | বিবরণ |
|---|---|
| **Users** | `org_id`-bound user, normalized email, active/disabled status, last-auth, scrypt password hash (`scrypt$N$r$p$salt$hash`, stdlib `hashlib.scrypt`) — **plaintext কখনো না, hash API-এ কখনো serialize হয় না** |
| **RBAC** | `rbac.py` — deterministic role→permission matrix (owner/admin/security_manager/analyst/viewer), 34 explicit permissions, escalation guard (`can_assign_role`) |
| **Tenant isolation** | `authz.py` — object-level ownership walk (project→org, asset→project, scan/finding/evidence→project, credential→org); **fail-closed**; IDOR/BOLA/forged-id সব DENY; denial → `authorization.denied` audit |
| **API keys** | `stk_` credential: secret **একবারই দেখানো হয়**, শুধু SHA-256 verifier + prefix store হয়; active/revoked/expired, last-used, project-bound optional, scope-gated (creator-এর scope-এর বেশি নয়), rotate (scope unchanged) |
| **Sessions** | `ses_` bearer tokens, 12h TTL, logout/disable/পাসওয়ার্ড-change-এ revoke; DB-তে শুধু hash |
| **Password reset** | one-time `rst_` token (30 min, single-use, hashed storage); generic response (no enumeration); email delivery নেই — service boundary, token one-time print |
| **Brute force** | in-memory bounded sliding-window limiter (auth/api/credential-create/scan-create) + temporary lockout (5 fails → 15 min) — **কখনো permanent lock** |
| **Immutable audit** | audit chain: `event_hash = SHA256(canonical_json ‖ prev_hash)`; `platform audit-verify` detects modified/deleted/reordered/broken; legacy Phase-1 rows counted separately |
| **Dashboard** | constant-time auth (`hmac.compare_digest`), `?t=` LEGACY (preserved, never logged — `safe_request_line`), Referrer-Policy/Permissions-Policy headers, POST same-origin guard (cookie/query transport), CORS কোনো allow-* নেই |
| **CLI** | নতুন `auth` group: `bootstrap-owner, user-create/list, user-disable/enable, role-set, set-password, login, logout, key-create/list/revoke/rotate, password-reset, reset-consume`; `platform ... --as TOKEN` — সব platform action-এ RBAC+tenant enforcement |

**ডিপ্লয়মেন্ট মোড (সৎভাবে আলাদা):**
- **local dev / single-user**: `platform` + `auth bootstrap-owner` — কোনো auth বাধ্যতামূলক নয় (Phase-1 behavior intact)।
- **multi-user deployment**: `auth bootstrap-owner` → `auth user-create` → প্রত্যেকে `auth login`-এর session token দিয়ে `platform --as TOKEN`; API integration-এর জন্য `auth key-create` (scoped)।
- **production**: সম্পূর্ণ hardened claim নয় — secrets env-ভিত্তিক (`SECTOOLKIT_*`), rate limiter single-process (distributed proxy যেমন nginx `limit_req`-এর পেছনে বসাতে হবে), TLS deployment-এ HSTS নিজে যোগ করবেন (dashboard HTTPS-এ চালালে)।

**টেস্ট:**
```bash
python3 tests/run_tests.py        # 282 tests (48 original + 64 Phase-1 + 98 Phase-2 + 72 Phase-3) — সব GREEN
```

---

## ⚙️ Phase 3 — Managed Scan Execution Platform (job queue + workers)

Phase 3 orchestration চালায় **already-built** Phase-1 + Phase-2 components — কোনো
rewrite নেই, কোনো duplicate authz/scanner logic নেই:

```
User → Auth → RBAC → Tenant Authz → Project → Scope → Scan
     → Job → Queue → Worker → Scanner Adapter → Scanner
     → Normalized Results → Findings/Evidence → Risk → Report → Audit
```

### Scan + job lifecycle

| Scan state | অর্থ | Job state | অর্থ |
|---|---|---|---|
| `pending` → `queued` → `running` | scan-এর Phase-1 lifecycle unchanged (extend only) | `created` → `queued` −→ `running` | নির্ভরযোগ্য queue |
| `paused` | checkpoint-এ থামে | `paused` | operator-এর pause request |
| `cancelling` → `cancelled` | safe checkpoint-এ stop | `cancelling` → `cancelled` | subprocess controlled terminate |
| `completed` / `failed` | terminal | `completed` / `failed` / `dead_letter` | attempts exhausted ⇒ admin-visible |
| | | `retry_wait` | bounded exponential backoff + jitter |

ট্রানজিশন **centralized** (`models.JOB_TRANSITIONS`, `jobs.py`) — worker-কোডে scattered
নয়; invalid transition fail-closed, same-state operation no-op (idempotent)।

### Persistent queue (zero external dependency)

- SQLite-তেই queue: jobs/workers/stages টেবিল (schema v3); Redis/Celery/Kafka **নেই**
- Worker crash ⇒ জব হারায় না; `lease_until` expiry ⇒ `sweep_stale()` reclaims
- **Atomic claim**: guarded `UPDATE ... WHERE status='queued'` + affected-row check ⇒
  দুটো worker একই জব claim করতে পারে না (concurrency test-এ proven)
- **Lease + heartbeat**: `lease_owner/lease_until/heartbeat_at`; মৃত worker-এর জব
  retry (attempts থাকলে) বা dead-letter

### Execution-time revalidation (FAIL CLOSED)

queue-তে জব ঘণ্টা অপেক্ষা করতে পারে — execution-এর আগে আবার চেক হয়:
`org active` → `project active` → `scan valid` → **`target in scope`** (প্রতিটি
network-producing stage-এর আগেও) → `profile permitted` → `active_enabled`
(ACTIVE profile-এর জন্য বাধ্যতামূলক, **default নয়**) → `job ∈ scan`।

### Retry policy

- **Retryable**: `timeout`, `network_error`, `malformed_output`, `subprocess_failed`, `worker_error`, `stale_worker`
- **NEVER retried**: `scope_denied`, `auth_failed`, `config_invalid`, `validation_rejected`,
  `payload_rejected`, `profile_unknown`, `not_authorized_active`, `project_inactive`,
  `org_disabled`, `scan_invalid`
- Bounded backoff (`min(300s, 2s·2^attempt)` + jitter ≤ 5s), bounded `max_attempts`
  (1–20, default 3), exhaustion ⇒ `dead_letter` (administrator-visible)

### Pause / resume — honest semantics

- Pause request ⇒ বর্তমান **stage শেষ হয়**; পরবর্তী stage শুরু হয় না; scan `paused`
  (নেটওয়ার্ক রিকোয়েস্ট mid-flight interrupt করা হয় না — এটাই সত্য)
- Resume ⇒ checkpoint থেকে continues: **completed stages re-run হয় না**
  (`scan_stages` টেবিলে stage_id/status/attempt/started/finished/result_reference)

### Cancellation

`cancel` → `cancelling` → worker-এর next safe checkpoint-এ subprocess-কে
**controlled terminate → grace → escalate** দিয়ে থামানো হয় (কখনো blind SIGKILL first নয়,
zombie নেই)। Stage `cancelled` চিহ্নিত হয়, scan `cancelled`।

### Concurrency, priority, fairness

- Global/per-org/per-project/per-scan caps: `org_concurrency=3`,
  `project_concurrency=2`, `scan_concurrency=1` (configurable)
- Priority server-side normalized: `critical=1 / high=2 / normal=3 / low=4`
  (user-defined arbitrary priority নেই — starvation impossible)
- **Round-robin** eligible orgs + priority within org; per-org cap ⇒ কোনো tenant
  অন্য tenant-কে starve করতে পারে না

### Scanner adapter + profile registry

- **Static allowlist** (`python/scanners.py`): `web-audit`, `api-audit`,
  `template-scan`, `crawler`, `waf-detect`, `recon`, `cloud-check`,
  `active-fuzz` (ACTIVE, opt-in), `port-scan` (Rust), `dir-fuzz` (Rust),
  `full-assessment` (workflow chain) — প্রতিটা profile-এ stages/timeout/
  permissions declared; user-supplied profile name **কখনো** dynamic module load করে না
- `shell=False` সবসময়; argv arrays; user input কখনো shell string-এ concatenate হয় না
  (+ command-injection regression tests)
- Output bounded (stdout 1 MiB / stderr 200 KiB / JSON 4 MiB), truncation flagged,
  JSON কখনো silent-corrupt হয় না; timeout-এ controlled terminate
- **Rust scanners** preserved: `rust/port_scanner` + `rust/dir_fuzzer` safe adapter
  দিয়ে চলে (validate scope → argv → bounded capture → normalize → persist)
- **Idempotency**: deterministic finding fingerprints + `INSERT OR IGNORE` assets ⇒
  stage retry/crash-recovery-তে findings duplicate হয় না

### Payload security

JSON-only (কখনো pickle নয়); allowlist keys; unknown field / control chars /
oversized (4 KiB) / shell fragments rejected; centralized `redact.redact()`
সব payload-এ (secrets at rest নেই — verified); scalar-only values।

### Result capture + partial results

Normalizer (Phase 1) intact; raw → redaction → bounded evidence storage।
প্রতি stage-তে findings cap (500); cap প্রয়োগ হলে stage record
(`findings:N|capped`) + audit event (`findings_capped: true`) দুটোতেই
**চিহ্নিত হয় — কখনো silent truncation নয়**।
**Partial results preserved**: recon+crawl সম্পন্ন, template fail ⇒ সম্পন্ন কাজ
দেখা যাবে; scan `failed` + error_code; প্রতিটি stage-র নিজস্ব checkpoint।

### Observability / audit / metrics / dashboard

- Audit events: `job.created/queued/claimed/started/paused/resumed/retry_scheduled/
  failed/dead_lettered/cancelled/completed`, `stage.completed/failed`,
  `worker.started/stopped`, `authorization.denied`, `scope.denied` — immutable chain
- **Heartbeat NEVER audited** (audit flooding নেই); heartbeat telemetry jobs/workers
  টেবিল + structured logs-এ
- Lightweight in-process metrics (`python/metrics.py`): jobs_created/completed/
  failed/retried/cancelled/stale/dead_lettered, scan_duration/stage_duration
- Dashboard: `--jobs-db <sqlite> --jobs-org <org_id>` দিলে `/jobs` ops panel
  (status/priority/attempt/worker/stages/error) — same token gate, org-filtered
  (multi-tenant-এ প্রতি org-এ একটা dashboard চালান — job id cross-tenant leak নেই)

### Worker model

`python3 main.py scan-worker run [--once N] [--heartbeat 15]` — local-process
worker; `worker_id/hostname/pid/started_at/last_heartbeat/status` registry-তে,
**client-facing data-তে hostname কখনো যায় না**। Trust model: local-process worker =
safe internal boundary (worker-side identities client-supplied নয়)।

**Worker health** (`scan-worker status`): `healthy` / `degraded` / `stopped` —
**expired heartbeat কখনোই healthy নয়** (heartbeat `3× interval`-এর বেশি পুরোনো
হলে `degraded`); `stopped` শুধু clean unregister-এ।

### Phase 3 CLI

```bash
python3 main.py platform scan-create --project P --profile waf-detect \
    --target https://example.com --db app.db        # scan + initial job একসাথে
python3 main.py scan-job create --scan SCAN_ID --project P --profile recon \
    --target example.com [--priority high] [--active] [--attempts 3] \
    [--timeout 300] --db app.db
python3 main.py scan-job list|status|pause|resume|cancel|retry ... --db app.db
python3 main.py scan-worker run --once 1 --db app.db    # queue প্রসেস করুন
python3 main.py scan-worker status --db app.db          # workers + metrics
python3 main.py dashboard --jobs-db app.db --jobs-org ORG_ID --token SECRET
```
প্রতিটা protected action Phase-2 RBAC-এর মধ্য দিয়ে যায় (`--as TOKEN`):
`scan-job pause` ⇒ `scan.pause`; `cancel` ⇒ `scan.cancel`; `retry`/`resume` ⇒
`scan.start`; cross-tenant job id ⇒ generic `[!] Forbidden` (existence leak নেই);
local mode (no `--as`) = Phase-1 single-user behavior intact।

### Honest deployment limits

- Phase 3 queue = **zero-dependency SQLite foundation** — ক্লিন shutdown-এ survived,
  single-process worker-দের জন্য সঠিক
- **এটি distributed production queue নয়**: multiple hosts/multiple processes-
  এ worker চালালে atomic claim ঠিক থাকবে, কিন্তু SQLite lock contention,
  single-writer bottleneck আর heartbeat-বিলম্ব বাড়বে — production-এ Redis/Celery
  (ভবিষ্যৎ) দরকার হবে
- Dynamic autoscaling, ML scheduling, AI autonomous scanning, billing/SIEM/
  MFA/SSO ইত্যাদি **পurpose-built নয়** (রোডম্যাপ-এ থাকলেও এই phase-এ নয়)

---

## 🧠 Phase 4 — Asset Intelligence, Finding Correlation, Dedup, Risk & Evidence Graph

**Goal:** turn raw scanner output into a *managed, explainable, tenant-safe
intelligence layer* — the same platform (no second org/project/finding
system), extended with Phase-1/2 persistence, RBAC, audit and redaction.

### Architecture

```
scanner JSON ──▶ normalize.normalize_result          (stable scan/asset/finding ids)
                 │
                 ├─▶ intel.ingest_observations ──▶ asset_observations + *_events
                 │        (provenance: source, scan_id, confidence, first/last_seen)
                 │
                 ├─▶ correlate.ingest_finding ──▶ canonical identity + fingerprint
                 │        ├─▶ dedup into canonical finding (evidence merged, never deleted)
                 │        ├─▶ confidence + risk (deterministic, calc_version=risk-v1)
                 │        ├─▶ risk snapshots (change-points only)
                 │        ├─▶ correlation / root-cause / remediation groups / clusters
                 │        └─▶ evidence graph (supports/contradicts/derived_from/…)
                 │
                 └─▶ diffs.capture ──▶ frozen baseline payload ──▶ scan_diffs (diff-v1)
                                                             (auto after every ingest;
                                                              worker calls it on completion)
```

Everything extends Phase-1–3 tables: `assets`, `findings`, `evidence`, `audit`,
`scans` are untouched in shape; Phase 4 adds `asset_observations`,
`asset_observation_events`, `asset_relations`, `finding_observations`,
`finding_links`, `root_causes`, `finding_clusters`, `remediation_groups`,
`risk_snapshots`, `scan_diffs`, `project_baselines` — all SQLite, all
parameterized, all tenant-scoped.

### Asset intelligence

- **Observation vocabulary (allowlist):** `identity, network, service, port,
  technology, software, version, framework, server, tls, dns, http, cloud,
  protocol, exposure, certificate`. Unknown types are rejected, never stored.
- **Provenance on every record:** source, scan_id, confidence, first_seen,
  last_seen; identical observations are deduplicated (insert-on-conflict),
  so first/last_seen stay truthful.
- **History:** `asset_observation_events` is append-only — a bounded ring
  (500 events/asset, oldest pruned) so first/last appearance and
  service/technology changes are reconstructable without unbounded growth.
- **Relationships** (`asset_relations`): `hosts, resolves_to, serves, uses,
  runs_on, has_certificate, cloud_of, related_to, part_of` — strict
  tenant/project checks on every write, idempotent by stable id.
- **Attack surface** (`asset_exposure`): derived from evidence only
  (`internet_facing / internal / restricted / unknown` + reason); a service
  is only claimed when an observation evidences it; provenance is always
  attached; `internal_only` assets cannot flip to internet-facing by
  inference.
- **Business impact** = metadata flags only
  (`customer_facing, authentication_system, payment_related, sensitive_data,
  administrative_system, production_system, internal_only, internet_exposed`)
  — never an inference of compromise.
- **Asset criticality:** normalized (`unknown/low/medium/high/critical`),
  project-scoped, **manager-only** via RBAC (`asset.criticality`), audited,
  allowlisted values.

### Canonical identity + fingerprint

Canonical key = `org|project|asset|type|normalized rule|normalized title|
parameter|endpoint|technology` — deliberately **excludes** evidence text,
timestamps, random ids and source names. The SHA-256 fingerprint is
deterministic, tenant-safe and reproducible; the same issue reported by
`web-audit` + `template-scan` + a workflow ingest lands on **one** canonical
finding. All evidence and scanner provenance is preserved on
`finding_observations` (bounded, id-deduplicated); nothing is ever deleted
because of dedup. Ingestion is idempotent: the identical payload twice ⇒ zero
state change.

### Lifecycle

`open → confirmed → in_review → accepted_risk | false_positive →
remediated → resolved`, plus `reopened`. Transitions live in one centralized
table; invalid transitions **fail closed**; every transition is audited and
requires `finding.update`. A resolved/remediated finding that reappears (same
fingerprint) becomes `reopened` — never an endless duplicate.
`accepted_risk` and `false_positive` may carry an expiry (`--until`), after
which the finding is reactivated/reviewable — it never silently disappears
from reports. `occurrence_count`, `first_seen`, `last_seen`, `resolved_at`,
`reopened_at` are tracked.

### Correlation ≠ dedup

Deterministic rule-based rules only (no LLM/AI): same-topic + same-asset →
`related_to`; matching stack (same CVE/template family) → root-cause group
(`root_cause_id`, `related_finding_ids`, `relation_type`, `confidence`,
`evidence`); root causes materialize only with ≥2 members. Correlated
findings are **never merged** when materially different; correlation never
invents exploitability — `exploitability` is derived only from deterministic
category/rule hints (`high/medium/low/unknown`).

### Confidence & risk

- **Confidence** (0.00–1.00, deterministic): source reliability + evidence
  completeness + scanner agreement + asset certainty + reproducibility
  (occurrence). Declared scanner confidence is only an input — it can never
  force a score up. Levels: high ≥ 0.85, medium ≥ 0.62, low ≥ 0.40, else
  `unverified`.
- **Risk** (0–100, deterministic, `calc_version=risk-v1`): severity base +
  confidence + exposure + asset criticality + business impact +
  exploitability + recurrence (bounded weights, no randomness). Every score
  carries a `factors` list; risk snapshots record change-points only (same
  inputs ⇒ same score ⇒ no snapshot spam). **Raw severity is preserved
  separately — severity ≠ risk.**
- **Priorities P0–P4** derive from risk + context, never severity alone (a
  Critical+low-confidence+internal finding can rank below a
  High+high-confidence+internet-facing one).

### Baseline diff

`diffs.capture(project, scan)` freezes the previous payload
(`project_baselines.payload`), snapshots the new scan via **stable
fingerprints** (not random ids), and materializes
new/resolved/persistent/reopened/changed findings + new/removed assets +
service/technology changes into `scan_diffs` (`diff-v1`, idempotent
`INSERT OR IGNORE`, deterministic diff id). It runs automatically after every
`register_scanner_result`, and the worker also captures on job completion.
First baseline ⇒ all `findings_new`; re-capture of the same scan returns the
existing diff (`created=False`).

### CLI (Phase 4)

```
python3 main.py platform asset-intel --asset AID [--db DB]
python3 main.py platform asset-history --asset AID
python3 main.py platform asset-relations --asset AID
python3 main.py platform asset-exposure --asset AID
python3 main.py platform asset-impact AID --tag customer_facing
python3 main.py platform asset-criticality AID --level critical --as TOKEN
python3 main.py platform finding-show FID / finding-history FID / finding-correlate FID
python3 main.py platform finding-false-positive FID --reason R --until DATE --suppress
python3 main.py platform finding-accept-risk FID --reason R --until DATE --review-at DATE
python3 main.py platform risk-show FID / risk-history FID
python3 main.py platform cluster-list --project P / cluster-show CID
python3 main.py platform remediation-list --project P
python3 main.py platform graph-list --project P
python3 main.py platform priority-list --project P
python3 main.py platform scan-diff --project P [--scan S|--from-scan A --to-scan B]
python3 main.py platform scan-diff-get DIFFID / baseline-status --project P
```

All actions honor RBAC + tenant scope (`--as TOKEN`); identifiers are
allowlisted, everything parameterized.

### Dashboard API (Phase 4)

Read-only, org-filtered, redacted, token-gated: `GET /api/intel`,
`/api/intel/assets`, `/api/intel/assets/{id}`, `/api/intel/findings`,
`/api/intel/findings/{id}`, `/api/intel/clusters`, `/api/intel/diffs`
(served from the platform DB via `--jobs-db`/`--jobs-org`).

### Tests & security boundaries

- `tests/test_intelligence.py` — **65 tests**: asset intel, canonical/
  fingerprint, cross-scanner dedup + evidence merge, idempotency,
  lifecycle (incl. reopened-not-duplicates), confidence determinism & bounds
  (declared-confidence can't force high), risk determinism/versions/
  snapshots/priorities, correlation/clusters/remediation, evidence graph,
  baseline diffs (first baseline, second-scan states, changed-risk,
  readback, stable fingerprints), security (secrets never in
  evidence/observations, BOLA, manager-only criticality, bounded queries),
  integration (register-scanner-result intelifies, garbage fail-soft).
- **Full suite (Phases 0–4): 349 tests OK** (`python3 tests/run_tests.py`) —
  zero removals/weakening; the only warnings are 27 pre-existing
  `ResourceWarning`s from Phase-2 HTTP fuzz sockets (unclosed test socket,
  benign, unchanged). Phase-5 adds `tests/test_monitoring.py` (110 tests),
  Phase-6 adds `tests/test_reporting.py` (76 tests) → **535 total** (see
  Phase-6 §Tests).
- Security: tenant isolation on every phase-4 query, fail-closed RBAC,
  centralized redaction (now also covering bare `session`/`cookie`/
  `set-cookie` assignment keys), secrets never land in findings/evidence/
  observations/correlation/risk explanations/serialized API; bounded queries,
  indexes on all phase-4 lookups, no unbounded graphs, SQLite-only (no
  Redis/Kafka/ES — deliberately).
- Excluded (honest): LLM/AI correlation, autonomous exploitation,
  unrestricted active scanning, distributed infra — none are claimed.
## 📡 Phase 5 — Continuous Monitoring, Alerting & Remediation Lifecycle

Phase 5 turns SecuToolkit from a "scan it once" platform into a **continuous
monitoring program**. It deliberately **extends** the Phase 1–4 platform: the
scheduler creates **ordinary Phase-3 Scan/Job records through JobService**, the
risk engine is **never re-run** (only re-read), findings keep their Phase-4
stable fingerprints, and every read/write goes through the existing tenant
isolation, RBAC, audit and redaction layers. No second execution engine, no
new org/project/asset/finding/worker model.

### Architecture

```
monitor.py     MonitoringService (policy config) + SchedulerService (tick)
               + MonitoringHealthService + retention_sweep
events.py      SecurityEventService (event store) + ChangeDetector (Phase-4
               observation deltas → security change events)
alerts.py      AlertService: allowlist conditions, identities, grouping,
               cooldown, lifecycle, suppression, default rules
notify.py      NotificationService: provider-neutral email + webhook,
               SSRF-hardened HTTPS delivery, HMAC, backoff/dead-letter
remedy.py      RemediationService: tickets, SLA, assignment, verification
authz.py       Object-level Phase-5 authorization helpers (ownership chain)
store.py       Phase-5 schema (all tables + indexes, SQLite, deterministic)
main.py        `monitor` CLI subtree + `audit`/`sweep` extraction hooks
dashboard.py   Monitoring snapshot API + read-only panels (redacted)
worker.py      Scheduled-run bookkeeping + verification scan hooks
```

Scheduling, dispatching and verification all flow through the **existing**
queue: `monitor tick` → `JobService` → worker → `on_scan_completed/on_scan_failed`
hooks → health + verification state.

### Scheduling (deterministic, no Celery/Redis/Kafka)

- Policies per project: name, scan profile, `interval` (5–10080 min) /
  `daily` / `weekly` / `manual`, targets, scope, active-scan permission,
  priority, timeout, missed-policy mode, `max_concurrent`.
- The schedule is an **anchor-at-creation grid** (`created_at + k·interval`,
  or configured UTC clock time for daily/weekly): reproducible, idempotent,
  timezone-free. One tick processes all due policies globally (bounded
  `limit`); each run is keyed by `UNIQUE(policy_id, scheduled_window)` so a
  tick can never double-create a window.
- **Missed-run policy** (bounded): `skip` (latest window only),
  `run_once` (latest + newest missed), `catch_up` (≤3 total, `catch_up_max`).
  Missed windows emit `monitoring.missed_scan` events (bounded per tick).
- **Execution-time fail-closed revalidation** with recorded reasons:
  org inactive / project inactive / policy disabled / profile unknown /
  target out of scope / active scan not authorized — the exact same Phase-3
  runtime checks; the scheduler never bypasses them.
- Concurrency = Phase-3 limits + per-project gate (jobs in flight ≥ project
  cap) + per-policy `max_concurrent` (executions in `scheduled`/`created`).

### Health (separate from risk)

Per project: `healthy` / `degraded` / `stale` / `disabled` / `error`, with
last success/failure, consecutive failures, last change/alert,
`next_expected_run`, `stale_after` and a 0–100 score over five dimensions
(scan freshness, asset freshness, success ratio, notification health, worker
availability). The score is **operational**, never conflated with finding
risk.

### Change detection → security change events

`ChangeDetector.detect()` diffs Phase-4 observation history (assets,
services, tech, versions, TLS, DNS, HTTP, exposure, findings, risk) into
typed security-change events (`asset.created`, `finding.created`,
`version.changed`, `risk.increased`, `exposure.changed`, …) with an
**allowlisted event vocabulary**, state bounds, redaction and a
deterministic identity (`project|type|asset|key|scan_id`) — re-emitting the
same change is a no-op. Secrets never appear in event state.

### Alert rules

- Deterministic, project-scoped, composable via explicit
  **allowlist** operators (`== != > >= < <= in not_in`) over a fixed context
  field list plus `and`/`or` combinators, depth- and count-bounded.
  **No `eval`, no user code, no regex engines** — enforced by validation and
  regression-tested (`test_no_eval_anywhere_in_rule_path`).
- Rule severity is independent of finding severity. Alert identity =
  `rule + event + asset + fingerprint + group` (stable, collision-free
  across rules); `UNIQUE(identity_key)` makes duplicate firing idempotent.
- Occurrences are counted separately; **cooldown gates delivery only**
  (never loses history); grouping (`none`/`asset`/`root_cause`/
  `remediation_group`) never merges unrelated criticals.
- Lifecycle `open → acknowledged → investigating → resolved → suppressed →
  expired` is fail-closed (no illegal edges), audited, and re-fires on new
  occurrences. Suppression requires a reason + future `until`; expiry
  reopens with history kept.

### Notifications (provider-neutral)

- `email` (interface — real transport is an optional SMTP adapter; until
  then it reports an explicit "transport not configured" error — never a
  fake send) and `webhook` (real HTTPS POST).
- **Webhook security**: HTTPS-only, no redirects, bounded timeout + response
  size, and SSRF hardening — localhost/127.0.0.0/8/::1/private/link-local/
  metadata hosts are rejected; non-public resolutions fail closed. URL is
  validated at save (format + denylist) and **re-resolved at delivery**.
- **HMAC**: `X-Security-Toolkit-Timestamp` + `X-Security-Toolkit-Signature`
  over `timestamp || raw_body`, constant-time compare; the signing secret is
  stored **encrypted at rest** (32-byte key file `0600` beside the DB, env
  fallback `SECTOOLKIT_WEBHOOK_KEY`), decrypted internally only — views,
  payloads, attempts and logs never carry it.
- Retry with exponential backoff (bounded `max_attempts=3`) → dead-letter;
  manual retry resets; delivery idempotency via
  `UNIQUE(project_id, occurrence_event_id, channel)`.
- All events are redacted; `monitoring.notification_failure` events fire once
  per dead-letter without recursive storming.

### Remediation tickets + verification

- Auto-opened per finding (Phase-4 identity), statuses open/assigned/
  in_progress/blocked/ready_for_verification/verified/closed/reopened,
  priority P0–P4, due date from SLA, assignment **only to existing users**
  (no team model), every user change audited.
- **Verification is evidence-based, never click-to-resolve**:
  `ready_for_verification` → ordinary scan/job → re-observation of the
  stable fingerprint: re-appearance ⇒ verification failed, finding + ticket
  reopened (optional alert); absence ⇒ passed. Attempts bounded
  (`max_attempts=3`), a failed verification scan returns the ticket to
  `ready_for_verification` automatically.

### Fatigue control, RBAC, audit, retention

- Cooldown / dedup / grouping / suppression / severity thresholds;
  suppressed and deduped events stay queryable. Monitoring-failure alerts
  (missed scan, repeated failure, worker unavailable, stale, notification
  failure, verification failure) are their own event types — bounded.
- Permissions: `monitoring.{read,create,update,run,delete}`,
  `alert.{read,update,suppress}`, `remediation.{read,update,assign,verify}`,
  `notification.{read,retry}`; ownership-chain isolation
  (notification→alert→project→org; ticket→finding→project→org), forged IDs
  denied with generic errors.
- Rate limits (existing limiter): manual runs 5/300 per policy+actor,
  alert ops 60/300 per actor, notification retries 20/300 per actor,
  verification requests 10/300 per ticket+actor.
- Every policy/rule/alert/remediation/notification change is audited
  (never secrets); the **retention sweep** prunes only Phase-5 high-volume
  history (`security_events` 180 d, `notification_attempts` 90 d,
  `scheduler_executions` 365 d; configurable per call, tenant-scoped,
  single audited `retention.sweep` row); immutable audit + finding history
  are never touched.

### Dashboard & CLI

- Dashboard (SecuPulse) adds a **Monitoring** section — `/monitoring` page
  and `/api/monitor*` endpoints: overview cards, policies, scheduled
  executions, security changes, alerts, remediation queue with SLA/
  verification status and project health — read-only, org-filtered, capped
  (≤200 rows), redacted.
- CLI `monitor`:
  `policy-create|policy-list|policy-show|policy-enable|policy-disable|
  policy-delete|run|tick|health|rules-install|alert-list|alert-show|
  alert-ack|alert-resolve|alert-suppress|remediation-list|remediation-show|
  remediation-assign|remediation-status|remediation-verify|sla-set|
  notification-list|notification-retry|settings-show|settings-set
  (--keep-secret)|sweep`; every action accepts `--as`/`--db`, is
  RBAC-gated, tenant-isolated and paginated.

### Phase-5 tests

- `tests/test_monitoring.py` — **110 tests** (change events, condition
  allowlist/evaluation, alert identity/grouping/cooldown/lifecycle/
  suppression/expiry/secrets, notification abstraction/SSRF/HMAC/backoff/
  dead-letter/idempotency/redaction, remediation lifecycle/SLA/verification
  success+failure/reopen/audit, scheduler grid/idempotency/concurrency/
  fail-closed revalidation, health, retention, RBAC/tenant/forged IDs,
  dashboard snapshot, no-eval, malformed-input regressions).
- **Full suite: `python3 -W default tests/run_tests.py` → 349 tests OK**
  (unchanged, no removals/weakening) **+ Phase-5 suite → 110 tests OK
  + Phase-6 suite (`tests/test_reporting.py`) → 76 tests OK = 535 total**
  (`python3 tests/test_reporting.py` runs the Phase-6 suite alone, and
  `python3 -m unittest tests.test_monitoring` the Phase-5 suite).
- Security regression coverage: SQLi-shaped inputs, secret leakage,
  SSRF denylist, malformed conditions, cross-tenant/forged IDs, duplicate
  dispatch, race/idempotency, failure injection — all fail-closed.

### Safe boundary & honest limits

- Scheduled **active** scans need the same explicit authorization as manual
  active scans (`active_scan_permitted` + scope revalidation at run time).
- SQLite-only storage (no Redis/Kafka/Celery/ES); single-host worker;
  alerting is deterministic rules (no LLM/AI triage, no autonomous
  remediation, no SIEM/SOAR integration); "SLA" hours are configuration,
  not regulatory commitments; email delivery requires a deployment-provided
  SMTP adapter — the toolkit reports honestly when it cannot send.

## 📊 Phase 6 — Enterprise Reporting, Security Analytics & Compliance Evidence

**Extends only.** No new DB, no new finding model, no new risk engine, no new
audit system: every report/analytics/evidence value is derived from the
existing scanner → finding → asset-intel → risk → monitoring → remediation →
evidence pipeline, tenant-isolated and centrally redacted. The only new
tables are `report_runs`, `report_payloads` (stored snapshot payloads) and
`compliance_evidence` (the evidence *registry* — always re-derivable, never
the source of truth).

### Architecture

- `python/reporting.py` — `ReportService` (snapshot + store/retrieve/export/
  delete/share + retention) and `EvidenceService` (derive/refresh/list/
  snapshot). `python/analytics.py` — `AnalyticsService` (read-only KPIs,
  posture, trends, buckets, asset/remediation/monitoring analytics).
  `python/pdf_report.py` renders the same redacted snapshot to PDF; the
  dashboard renders HTML panels and JSON APIs from the same snapshot.
- A report snapshot carries: org/project, type, `generated_at`, `generated_by`,
  `data_cutoff`, `risk_version`, `report_version`, filter, assets, findings,
  monitoring, analytics, truncation metadata and the canonical hash.
- Snapshot payloads are stored once (`report_payloads`) and never mutated;
  re-generation is a new snapshot (immutability is structural, not a claim).

### Report types & filters

- Types: `executive`, `technical`, `asset_inventory`, `vulnerability`,
  `remediation`, `monitoring`, `trend`, `compliance_evidence`.
- Filters are **allowlisted** (severity, status, category, risk_min/max,
  exposure, criticality, technology, asset_id, date range) — arbitrary
  columns/SQL are rejected. Date ranges are validated with a calendar check
  and **bounded** (never unbounded historical queries); pagination is capped
  (rejecting e.g. `limit=1000000000`, `0`, negatives), and every bounded
  result carries `truncated: true/false` + `reason` + `original_count` +
  `included_count` — truncation is never silent.

### Posture score (separate from finding risk)

`posture-v1` — deterministic weighted score (0–100) with **documented factor
formulas**, every factor carrying its `definition` and `weight`:

| factor | weight | formula |
|---|---|---|
| open_risk_pressure | 0.30 | 1 − min(1, (3·open_critical + open_high)/30) |
| remediation_progress | 0.20 | 0.6·closed_or_verified_ratio + 0.4·(1 − overdue_ratio) |
| asset_exposure | 0.15 | 1 − internet_facing_ratio |
| risk_trend | 0.15 | 1 when no net risk increase; decays over 20 net events |
| monitoring_freshness | 0.10 | Phase-5 monitoring health score / 100 (reused) |
| verification_status | 0.10 | verification pass rate (none ⇒ neutral 0.5) |

Levels: excellent ≥85 / good ≥70 / fair ≥50 / weak <50. Trend range:
7/30/90 days or any bounded custom window; bucket widths are deterministic
(≤180 points per series).

### Compliance evidence — categories only, no certification claims

Evidence items map strictly to **stored platform data** with provenance
(`source_type`, `source_id`, `evidence_ts`, `data_cutoff`, `evidence_hash`)
across 8 generic control categories: access_control, asset_management,
vulnerability_management, logging_monitoring, change_management,
incident_response, data_protection, security_testing. Statuses:
`supported` / `partially_supported` / `not_supported` /
`insufficient_evidence`. **No "compliant / certified / SOC 2 / ISO / PCI"
labels are ever produced** — the platform reports what it can observe, not
certification outcomes.

### Determinism, hashing, redaction

- Same cutoff ⇒ byte-identical snapshot: UTC-exact timestamps throughout,
  stable sort orders, no host-TZ dependence, `SHA-256` canonical hash over
  the exact serialized payload (`report_hash`). **No PKI/signing claim** —
  it is tamper-evidence for the stored payload, not a signature.
- Central redaction (`python/redact.py`) applies on **every** path: JSON,
  HTML, PDF, dashboard pages and API payloads. Secrets (headers, tokens,
  cookies) are redacted before storage and rendering.

### RBAC, audit, retention

- Permissions: `report.read` / `report.generate` / `report.export`,
  `analytics.read`, `compliance_evidence.read`; tenant isolation on every
  query; unknown asset/project filters fail closed.
- Audit (metadata only, no payloads): `report.generated`, `report.exported`,
  `report.deleted`, `report.shared` — appended to the same immutable audit
  hash chain.
- `retention-sweep` removes only expired **non-immutable** report runs
  (days bounded 1–3650, audited); it **never** deletes immutable evidence
  snapshots, audit history, finding history or evidence provenance.

### Dashboard, API, CLI

- Dashboard panels (read-only snapshot): Executive Overview, Posture,
  Risk Trends, Asset Exposure, Remediation, Monitoring, Reports, Evidence
  (`/reports`, `/evidence`; JSON: `/api/reports`, `/api/reports/{id}`,
  `/api/analytics`, `/api/evidence` — bounded defaults 20/50/100).
- CLI (Phase-1 `report` command preserved untouched; the new family is
  `reporting`): `reporting generate|list|get|export|delete|share|
  retention-sweep`, `analytics posture|kpis|risk|risk-buckets|risk-assets|
  risk-projects|trends|attack-surface|remediation|assets|monitoring|bundle`,
  `evidence refresh|list|show|snapshot|export`; `--as` token enables
  RBAC-tenancy enforcement, `--db` selects the platform DB, `--out` paths
  are sanitized (traversal rejected).

### Tests (Phase 6)

`tests/test_reporting.py` — **76 tests**: tenant isolation, RBAC & unknown
permissions, redaction on JSON/HTML/PDF/dashboard/API, filter allowlist +
bounds (SQLi-shaped values never execute), snapshot determinism + canonical
hash, evidence mapping/provenance/immutability + hash-chain survival,
retention (audit never touched), export-path security, CLI behaviors, and
performance (100 assets / 500 findings / 1000 events, single-digit seconds
on SQLite). **Full regression: 349 (Phases 0–4) + 110 (Phase 5) + 76
(Phase 6) = 535 tests OK**; Phase-7 adds `tests/test_devsecops.py`
  (93 tests) → **628 total**; Phase-8 adds `tests/test_identity.py`
  (100 tests) → **694 total**; Phase-9 adds `tests/test_cloud_security.py`
  (63 tests) — combined `tests/run_tests.py` now reports **757 tests OK**.

### Honest limits (Phase 6)

- Single-host **SQLite** storage: reporting/analytics scale to the same
  bounds as the platform (thousands of findings, tens of thousands of
  events) — no enterprise-scale/concurrent-service claims.
- Posture/KPIs use **local documented definitions**, not external
  benchmarks; evidence statuses are observational, never a certification
  (no SOC 2/ISO/PCI claims).
- Report hashes are integrity checks, not signatures; retention is
  config-driven and auditable, not policy automation.
- No SIEM/EDR/SOAR/LLM/Redis/Kafka/ES/SSO/MFA/billing — deliberately.

## 🚦 Phase 7 — DevSecOps Security Gates & Provider-Neutral CI/CD Integration

CI/CD-তে নিরাপত্তা **গেট** চালানোর extend-only লেয়ার: *কোনো* নতুন scanner, job
queue, baseline, risk engine, SARIF engine, report engine, auth/RBAC, audit বা
dashboard বানানো হয়নি — Phase 1–6-এর প্রতিটি সাবসিস্টেম **reuse** করা হয়েছে।
কোনো Redis/Kafka/Celery/ES/SIEM/EDR/SOAR নেই; সব SQLite + stdlib।

### Architecture

```
CI provider (github|gitlab|jenkins|generic|local — ALLOWLIST, unknown → FAIL CLOSED)
        │  metadata only: repository/branch/commit_sha/commit_ref/pipeline_id/url/actor
        ▼
devsecops ci-create ──▶ idempotency key (project|provider|gate|pipeline|sha|ref|run_key)
        │                    └─ one ci_runs row + ONE existing Scan + ONE existing Job
        ▼
devsecops evaluate ──▶ atomic claim (status→evaluating; concurrent callers wait & reuse)
        │                    └─ _evidence(): completed scan + findings (fingerprint-only
        │                       join) + Phase-4 risk columns + Phase-4 scan-diff baseline
        ▼
allowlisted policy evaluation ──▶ immutable gate_results row (policy frozen at
        │                          evaluation time; duplicate INSERT OR IGNORE)
        ▼
JSON / SARIF 2.1.0 (existing exporter) / Phase-6 report snapshot (ci provenance)
```

### Policy language (deterministic, allowlisted, no eval/exec)

- **কী:** `max_risk`, `max_open_critical/high`, `max_new_findings`,
  `max_reopened_findings`, `max_increased_risk` (numeric); `max_severity`
  (Info/Critical), `require_minimum_confidence` (low/medium/high/confirmed);
  `block_active_findings`, `block_internet_facing_critical`,
  `require_no_regression`, `require_scan_success` (bool).
- **Operator:** শুধু `== != > >= < <=` (bool → শুধু `==`/`!=`)। কোনো ফিল্ড-নেম,
  এক্সপ্রেশন, `eval`/`exec`, arbitrary SQL নেই।
- **Caps:** 4096 bytes, 20 conditions, flat (depth 1), version 1–999,
  description 200 chars (reject, কখনো silent-truncate নয়), control chars
  rejected, secrets → redact।
- **Semantics:** `max_*` = threshold; derived bools = "require/block" assertion;
  missing metric → numeric 0 (`max_severity` → Info-order, confidence →
  confirmed), কিন্তু **evidence-ই untrusted হলে আগেই INCONCLUSIVE** —
  `evaluate_conditions()` এ কখনো INCONCLUSIVE আসে না।

### Fail-closed (কখনোই PASS না)

`scan_failed` / `scan_not_found` / `baseline_unavailable` / `risk_unavailable` /
`gate_disabled` → **INCONCLUSIVE** (reason সহ)। Authorization failure, missing
evidence, malformed policy, DB conflict — সবই gate fail-closed। commit SHA
শুধু **metadata** (validated: 7–64 hex, bounded fields, control chars rejected);
authorization নয়। Provider unknown → fail closed. `active-fuzz` শুধু opt-in।

### Determinism & integrity

- Policy hash = SHA-256 of canonical JSON (sorted keys, `,`/`:` separators)।
- `result_hash` = SHA-256 of gate-result canonical body (timestamps/
  annotations/ci_context excluded) — **integrity, signature নয়** (documented)।
- একই run+gate+policy → একই immutable result; duplicate insert `OR IGNORE`;
  concurrent evaluations → একটাই evaluation (atomic claim + short wait)।
- `policy_version`/`policy_hash`/`result_version` ("gate-v1") frozen; historical
  results কখনো mutate হয় না।

### Reuse map

| প্রয়োজন | ব্যবহৃত সিস্টেম |
|---|---|
| scan dispatch | `platform.scan_create` + `jobs.JobService.create_job(queue_now=True)` (Phase 3) |
| finding identity | Phase-4 fingerprint (32-hex), observations provenance |
| severity ≠ risk | Phase-4 `risk_score/risk_level/priority` + `analytics.risk_summary` |
| regression | Phase-4 `BaselineService` scan-diff (fingerprint-only) |
| SARIF | existing `sarif_export.to_sarif` (2.1.0, no secrets) — only gate metadata attached |
| audit | existing immutable hash-chain (`devsecops.*` actions added to allowlist) |
| redaction | central `redact.redact` on EVERY output (no API keys/cookies/auth headers/ passwords/webhook secrets/private keys) |
| rate limit | existing `identity.RateLimiter` (no second implementation) |
| report input | Phase-6 `reporting.snapshot(..., ci=...)` — allowlisted `_CI_KEYS`, bounded 128, redacted |
| RBAC | `devsecops.*` permissions (viewer/analyst/admin/owner matrix) + org-scoped ownership chains (`require_gate/ci_run/result`) — forged IDs fail closed without existence leak |

### CLI (`devsecops` family — 15 subcommands)

`gate-create|list|show|update|delete`, `ci-create` (alias `run`),
`ci-list`, `ci-show` (alias `status`), `evaluate`, `result`, `export`,
`report`, `retention-sweep` — সবার `--as`/`--db`। Output JSON-only (show/status/
result); gate/CI list bounded (limit cap 500, offset cap 100000)।

**Exit codes (documented):** `evaluate` → **0** pass/warn, **1** fail,
**2** inconclusive, **3** evaluation system error (result store failure);
অন্যান্য platform errors তাদের নিজস্ব কোড (validation 2, not found 4,
authorization 11, rate-limited 12…)।

### Dashboard & API

`/devsecops` panel + read-only `/api/devsecops/gates|runs|results` (and
`/api/devsecops/(gates|runs|results)/{id}`) — tenant-filtered (`--intel-org`),
bounded (`limit` ≤ 100, `offset` ≤ 10000), redacted; snapshot cache keyed on
DB `(mtime, size)`। Read-only APIs follow the Phase-5/6 dashboard model
(server token + org filter); **full per-role RBAC enforcement lives at the
CLI/service edge** (`authz.require_*` + `devsecops.*` permission matrix)।

### Idempotency & retention

- CI submission idempotent by `(project|provider|gate|pipeline_id|commit_sha|
  commit_ref|run_key)` — duplicate `ci-create` reuses একই run + scan (কোনো
  duplicate job নয়)। Providers: allowlist `github|gitlab|jenkins|generic|
  local`; triggers: `pull_request|merge_request|branch_push|manual|scheduled`।
- `retention-sweep` (days 1–3650, project-scoped optional) শুধু terminal-status
  `ci_runs` মুছে — **gate_results/audit/finding history/report snapshots
  কখনো না**; audited + `devsecops_runs_retained` metric।

### Tests (Phase 7)

`tests/test_devsecops.py` — **93 tests OK**: policy validation (fields/ops/
types/depth/size/no-eval), deterministic evaluation (pass/fail/warn + all ops),
gate CRUD + versioning + frozen results, CI run creation/reuse/idempotency,
metadata bounds + allowlists + control chars, fail-closed matrix (scan failed/
orphan scan/baseline missing/risk unavailable/gate disabled), risk vs severity,
reopened-regression (Phase-4 fingerprint diff), active/IFC blocking, secrets
never in JSON/SARIF/audit, SARIF 2.1.0 validation, deterministic hash
recomputation, Phase-6 report integration (`ci` provenance allowlist +
rejection), retirement (immutable evidence survives), tenant isolation (Org A
cannot read/run/export Org B gate/run/result; forged IDs no existence leak),
RBAC matrix + audited denials, concurrency (duplicate CI submissions + parallel
evaluations → single row, single audit), failure injection, and scale:
**100 assets / 500 findings / 1000 events + 100 CI runs + 50 evaluations in
~3s** on SQLite (no N+1)। **Full regression: 349 + 110 + 76 + 93 = 628 tests OK**;
Phase-8 adds `tests/test_identity.py` (100 tests) → **694 tests**; Phase-9
adds `tests/test_cloud_security.py` (63 tests) → combined `tests/run_tests.py`
**757 tests OK** (Phase-8/9 §Tests)।

### Honest limits (Phase 7)

- Provider adapters are **metadata-only** — no outbound CI API calls, no
  credential storage (credentials কখনো plaintext/logged/serialized হয় না)।
- `result_hash` is integrity, not a cryptographic signature; no autonomous
  exploitation/remediation/source modification, no LLM decisions, no arbitrary
  shell/CI commands।
- Single-host SQLite: gate evaluation throughput bounded by the platform's
  own bounds (hundreds of CI runs, tens of evaluations/minute with rate
  limits) — no enterprise-scale/concurrent-service claim।
- No webhook listener is implemented; CI integration is pull/CLI-driven by
  design (provider tokens never enter this system).

## 🔑 Phase 8 — Enterprise Identity & Access Layer (MFA · SSO · SCIM)

Phases 1–7-এর identity/RBAC/audit/tenant/session foundation-এর **উপর** তৈরি —
কোনো কিছু replace বা duplicate করে না: একই `users`, একই RBAC রোল, একই
immutable audit, একই multi-tenant isolation, একই session store। Phase 8 যা
যোগ করে: **deterministic, fail-closed enterprise access control**।

### MFA (TOTP + recovery codes)

- **TOTP per RFC 6238 semantics** — stdlib `hmac`/`hashlib`/`base64` (SHA-1,
  6 digits, 30s window, no third-party crypto)। Seed = `secrets`-random,
  **encrypted at rest** (webhook encryption key), কখনও audit/dashboard/
  exception/log-এ যায় না (`test_seed_encrypted_at_rest`,
  `test_seed_never_in_audit`)।
- **Enrollment lifecycle**: `mfa-enroll` → seed প্রিন্ট হয় **ONCE** (activates
  নয়) → `mfa-verify <TOTP>` → active। Verify-এর আগে seed দিয়ে কোনো
  authentication হয় না (`test_seed_not_active_until_verified`,
  `test_verify_activates_mfa`); corrupt/empty seed fail-closed।
- **Recovery codes**: 128-bit crypto-random, **shown once**, at-rest শুধু
  salted-HMAC-SHA256 verifier, **single-use** (replay rejected), rotation
  পুরনো সব void করে, admin `mfa-reset` সব void + সব session revoke +
  re-enroll force (`test_recovery_codes_random_and_only_hmac_stored`,
  `test_recovery_codes_single_use_and_rotation`,
  `test_reset_voids_everything_and_revokes_sessions`)।
- **TOTP replay** rejected (থেকে `last_used_step` tracking) — যেকোনো reuse
  invalid code → generic error।

### Policy + step-up (deterministic, fail-closed)

- `policy-set --org <org> --mode {optional,roles,required} --roles ...`
  — versioned, audited, history-লগ। Corrupt/unknown policy কখনো MFA off করে না
  (`test_corrupt_policy_never_disables_mfa`,
  `test_policy_deterministic_and_fail_closed`)।
- `login`-এ centralized policy hook: MFA needed হলে session `mfa=pending`
  হয় — pending session **কোনো privileged action দেয় না**
  (`test_pending_session_cannot_act`, `test_login_under_required_policy_
  creates_pending_session`)। `mfa-challenge --code <TOTP|rec_...>` →
  `verified`। MFA না থাকা user require-র নিচে challenge করতে পারে না
  (`test_user_without_mfa_cannot_challenge`)।
- **Step-up**: verified session-এর `step_up_expires_at` + `require_recent` —
  মেয়াদ শেষে আবার MFA চাই (`test_step_up_expires_and_requires_refresh`,
  `test_mfa_complete_upgrades_and_step_up_ok`); `--as` token শুধু verified
  session।

### Session hardening + revocation

`auth_method`, `mfa_status` (none/pending/verified), `step_up_expires_at`,
**absolute lifetime** (`test_absolute_session_ttl_enforced`), idle timeout
revoke (`test_idle_timeout_revokes`), session secret শুধুই hash-এ at rest ও
ONCE print (`test_session_secret_never_in_db`); `session-revoke` /
`sessions-revoke-user` / `sessions-revoke-org` (bounded) — সব **revocation
reason** সহ audited (`test_revocation_reasons_and_org_scope`); suspended/
deactivated user authenticate করতে পারে না + সব session revoke হয়
(`test_suspended_user_cannot_authenticate`,
`test_deactivated_user_and_api_key_owner`,
`test_user_delete_deactivates_and_revokes`); sessions-list org-scoped,
token-free (`test_sessions_list_org_scoped_and_token_free`), scale:
**4 concurrent users × 10 sessions** (`test_session_list_scale`), 50+ scale
sessions… সব বাউন্ডেড।

### OIDC SSO (full cryptographic validation)

- ID token **কখনোই unsigned claim-এ বিশ্বাস নয়**: alg allowlist (RSA
  family + HS256 শুধু configured symmetric secret-সহ), kid → JWKS fetch,
  signature verify, **issuer + audience + expiry/nbf + nonce** সব বাধ্যতামূলক
  (`test_validation_matrix`, `test_tampered_payload_rejected`,
  `test_garbage_jwks_rejected`, `test_unsigned_rejected`)।
- **State + nonce single-use, 5 min expiry**, PKCE S256 support
  (`test_state_single_use_and_expiry`, `test_pkce_verifier_binding`)।
- **redirect_uri fail-closed binding** (এই সেশনে যোগ): authorization URL
  শুধু provider-config-এ registered redirect বহন করতে পারে; callback-এ
  unregistered redirect আসলে state consume-এর **আগেই** rejected — probe
  legitimate session-ও burn করে না (`test_oidc_start_rejects_redirect_
  mismatch`, `test_oidc_callback_rejects_redirect_mismatch`)।
- Discovery/network fetch **SSRF-safe** (HTTPS only, private/loopback/
  link-local refused, bounded timeout/size, no redirects) — একই validator
  যা webhook-এ ব্যবহৃত।

### SAML SSO (secure XML + signature validation)

- Signed assertion: canonical XML, **XXE/DTD/external entity/oversized/deep
  XML সব rejected** (`test_xxe_and_dtd_rejected`,
  `test_oversized_and_deep_xml_rejected`), একাধিক assertion rejected
  (`test_multiple_assertions_rejected`) — XML-wrapping attack surface বন্ধ।
- **Audience + recipient + destination + issuer + temporal (NotBefore/
  NotOnOrAfter) + replay (assertion ID single-use)** সব checked
  (`test_audience_recipient_destination_issuer_checks`,
  `test_temporal_validity`, `test_replay_rejected`,
  `test_in_response_to_and_request_binding`, `test_nameid_validation`,
  `test_password_attribute_rejected`)।
- Signing cert শুধু **provider config-এ থাকা fixed cert** থেকে — কোনো dynamic
  trust নেই; wrong key/unsigned/tampered → rejected
  (`test_wrong_signing_key_rejected`, `test_signature_tamper_detected`)।

### Provider-neutral config + domain discovery + JIT + group mapping

- `sso_providers` + versioned `sso_provider_history`: যেকোনো change audited,
  optimistic-lock (stale version → conflict), secrets encrypted at rest,
  সব view redacted (`test_provider_config_redaction`,
  `test_provider_version_conflict_and_history`)।
- Domain claim: normalized, **org-unique**, no existence leak
  (`test_domain_normalization_and_uniqueness`,
  `test_domain_discovery_no_existence_leak`)।
- **JIT**: deterministic external-identity key (`provider|subject`), org-safe
  duplicate handling, username email local-part থেকে, **bulk scale 150**
  (`test_jit_tenant_safety`, `test_jit_username_derived_and_deduplicated`,
  `test_provisioning_idempotent_by_external_id`,
  `test_bulk_jit_provisioning_150`)।
- **Group → existing RBAC role mapping** শুধু: unknown mapping fail-closed,
  union semantics (কখনো role strip করে না), reconcile + concurrent group
  patch-এ double-grant হয় না (`test_group_mapping_only_existing_roles`,
  `test_group_membership_reconciles_roles`,
  `test_concurrent_group_patch_no_double_grant`)।
- SSO login-এও MFA policy binding + inactive user rejected
  (`test_sso_login_mfa_binding`, `test_sso_login_rejects_inactive_user`)।
- Provider secrets কখনো CLI/dashboard/audit/exception-এ নয়
  (`test_secrets_absent_from_all_views`,
  `test_identity_events_never_contain_secrets`) — সব Phase-2 redaction
  layer দিয়ে যায়।

### SCIM 2.0 (Users/Groups)

- একই `users`/RBAC-এর উপরে; `/Users` + `/Groups` (create/read/patch/replace/
  delete/list with **bounded pagination + filter allowlist**, malformed/cap
  rejected — `test_filter_allowlist_and_bounds`,
  `test_pagination_bounds`, `test_malformed_json_and_capabilities`)।
- **Dedicated tenant-scoped credential**: prefix + salted verifier, secret
  ONCE; `max_role` cap (SCIM যত role-ই পাঠাক, cap-এর বেশি দিতে পারে না —
  `test_max_role_cap_enforced`); client-supplied org trust নেই — credential
  থেকে org আসে; expire/revoke + ওনার deactivate সব কাজ করে
  (`test_expired_credential_rejected`,
  `test_deactivated_user_and_api_key_owner`)।
- Idempotent `externalId` key-এ (`test_provisioning_idempotent_by_
  external_id`), group replace version-contract (`test_group_replace_
  semantics_and_version`), একই concurrent-race guard।

### Integration

- **Audit + events + metrics** সব **existing** audit system-এ (দ্বিতীয় audit
  DB নেই); সব identity event metadata redacted।
- **Dashboard**: `/identity` page + `/api/identity` JSON;
  `dashboard.py --identity-db <path> --identity-org <org>`; সেশন/পলিসি/
  MFA/recovery/SCIM snapshot — TOTP seed, recovery code, session secret,
  SCIM secret **কখনোই render হয় না** (`test_page_renders_without_secrets`,
  `test_snapshot_redacted_and_counts`, `test_snapshot_empty_and_
  unconfigured`)।
- **CLI** (`main.py auth …`): `bootstrap-owner`, `user-create/list/disable/
  enable`, `role-set`, `set-password`, `login/logout`, `key-*`, `password-
  reset/reset-consume`, `mfa-status/enroll/verify/challenge/disable/
  recovery-generate/recovery-list/reset`, `policy-get/policy-set`, `sso-
  provider-*/sso-domain-*/sso-mapping-*/sso-oidc-start/sso-saml-start`,
  `sessions-list/session-revoke/sessions-revoke-user/sessions-revoke-org`,
  `scim-cred-create/list/revoke`। User lifecycle commands **platform user
  ID অথবা username/email — দুটোই** accept করে; `--as <session>` হল
  verified step-up token।

### Tests (Phase 8)

`tests/test_identity.py` — **100 tests OK** (OIDC 16, SAML 12, SCIM 14, MFA
lifecycle 13, session hardening 10, lifecycle/failure-injection 7,
**break-glass 9**, **SCIM-over-HTTP 7**, scale 6 (incl. **250-user SCIM HTTP
bulk provisioning + 100 break-glass grants**), dashboard-identity 3,
**CLI regression 3** — bootstrap-owner → login →
user-create/role-set/set-password/disable/enable by **username** on a
throwaway DB with `SECTOOLKIT_PLATFORM_DB`, password never echoed; the
no-password prompt crash regression; break-glass CLI step-up gates)।
Adversarial + concurrency + failure-injection + scale সবই ভেতরে:
corrupt seed/corrupt policy, wrong-code lockout (8/300s window), TOTP replay,
recovery churn, state replay/expiry, XML wrapping/XXE/deep XML, tampered/
unsigned/wrong-key tokens, forged tenant IDs (no existence leak), concurrent
group patch, duplicate CI-না — duplicate SCIM submissions, bulk JIT 150,
session scale 4×10, SAML attribute scale, 200/60 SCIM + 30/300 SSO callback
rate limits, break-glass token/expiry/revocation/secrets-in-views.
**Full regression: `python3 tests/run_tests.py` → 757 tests OK**
(Phase-9 adds `tests/test_cloud_security.py`: 63 tests → 694 + 63 = **757**).
(foundation 64 + security 86 + orchestration 74 + intelligence 65 +
monitoring 107 + reporting 57 + devsecops 93 + **identity 100** + 48
original-Part suites = 694) — Phase-7-এর 628 থেকে +66।

### Phase-8 additions in this pass

- **§15 break-glass emergency access**: `python/breakglass_service.py`
  (`auth break-glass-start/status/end`) — explicit, reason-required
  (8–200 chars), short-lived (default 600s, cap 3600s) grants minted ONLY
  from a verified step-up context by holders of the new
  `identity.break_glass` permission (security_manager+); one active grant
  per actor+org (supersede), hashed at rest, throttled 5/300, audited
  (start/end), never in views/logs; a `bg_` token acts as a verified
  step-up context that NEVER adds permissions.
- **§36 SCIM 2.0 HTTP surface**: `main.py scim-server` (stdlib-only) —
  `/scim/v2/ServiceProviderConfig|ResourceTypes|Schemas` (public discovery),
  `/scim/v2/Users|Groups` CRUD + filters + pagination, HTTP Basic against
  SCIM credentials, tenant ALWAYS from the credential, `application/scim+json`,
  SCIM error envelopes, bounded bodies (1 MiB), per-credential + global
  throttles sized for §47-scale bursts.
- **Genuine defects found by live CLI/HTTP smoke and fixed**:
  (1) `_read_secret` used `os.stdin` → `AttributeError` crash on any
  password-less invocation (now `sys.stdin`; clean non-tty message + exit 2);
  (2) `enroll_start` silently rotated an **already-verified** MFA enrollment
  with no verified context — MFA-rebinding vector (now
  `mfa_rebind_blocked` unless the caller holds a verified step-up context);
  (3) SCIM `groups_list` filter mapped SCIM attribute names to JSON keys
  instead of DB columns (`displayName` filters crashed with 500 — now
  filtered correctly).

### Honest limits (Phase 8)

- **No WebAuthn/passkeys, hardware keys, SMS, email OTP** — TOTP
  authenticator app + recovery codes যথেষ্ট; কোনো মাল্টি-ফ্যাক্টর beyond
  TOTP নেই।
- **SCIM over HTTP is a stdlib server** (`main.py scim-server`, bind
  127.0.0.1 by default): no TLS, no OAuth2 client-credentials grant, no
  `/Bulk` or `/Me` endpoints (RFC 7644 §3.8), Basic auth only — terminate
  TLS at a reverse proxy and protect the port; per-credential throttles
  (scim_auth/scim_write 600/60) still bound bursts.
- **Break-glass is session-anchored**, not a master bypass: minting needs a
  verified step-up context AND the `identity.break_glass` permission; a
  grant is useless against a `required`-policy org unless the actor's own
  session was MFA-verified, and it never adds roles/permissions (an
  operator who cannot do it normally cannot do it through the grant).
- SSO callback service-level (HTTP callback listener নেই): IdP-এর সাথে
  integration সম্পূর্ণ CLI/API + library path দিয়ে — browser redirect
  উইন্ডো প্রোডাকশন ডিপ্লয়মেন্টে নিজের reverse proxy দিতে হবে।
- `policy` login/step-up boundary-তে evaluate হয় — **ইতিমধ্যে active old
  session কে retroactively void করে না** (revoke explicit)।
- Discovery ও metadata শুধু OIDC discovery (reuse safe_https_fetch);
  SAML metadata ম্যানুয়াল config; কোনো automatic IdP cert rotation নেই।
- JIT শুধু SSO login path-এ; domain discovery OSINT-level (public source),
  verify ownership-এর কোনো DNS challenge নেই।
- Single-host SQLite: session/SCIM/SSO scale বাউন্ডেড (rate limits +
  pagination caps); কোনো HA/scale-out claim নেই; `mfa-reset`-সহ সব admin
  action RBAC-gated — local-mode CLI (no `--as`) শুধু single-owner bootstrap
  path।


## 🏆 ইন্টারনেট রিসার্চে পাওয়া "World #1" ফিচার ম্যাপ

(উৎস: [Nuclei/RustScan/feroxbuster comparisons](https://www.pistack.xyz/posts/owasp-zap-vs-nuclei-vs-nikto-self-hosted-dast-scanning-guide-2026/),
[Free DAST tools 2026](https://appsecsanta.com/dast-tools/free-dast-tools),
[OWASP API Top 10 (2023/2026)](https://totalshiftleft.ai/blog/owasp-api-security-top-10-explained))

| Feature (World-class টুল থেকে) | আমাদের স্ট্যাটাস |
|---|---|
| Template-based scanning (Nuclei: 11,000+ templates) | ✅ **Part 3 — Nucleus engine + 25 templates** |
| Directory fuzzing (feroxbuster/ffuf) | ✅ RapidDir |
| API security (OWASP API Top 10) | ✅ Part 2 |
| CVE detection + lookup | ✅ Part 2 + CVE version-range templates + KEV-aware mini-DB (27 CVEs) |
| **Active injection testing (SQLi/XSS/CMDi/traversal)** | ✅ **Part 4 — Injector (error/boolean/time-based/reflection detection)** |
| **WAF detection & bypass-awareness** | ✅ **Part 4 — WallFinder (30+ vendors)** |
| **Subdomain enumeration (OSINT)** | ✅ **Part 5 — SubKraken (crt.sh CT logs + threaded DNS brute)** |
| **Cloud misconfig (S3/GCS/Azure/Redis/Mongo/ES)** | ✅ **Part 5 — CloudScope** |
| **Findings dashboard + client portal (multi-tenant)** | ✅ **Part 6 — SecuPulse** |
| **Remediation status tracking (open→in-progress→mitigated→verified)** | ✅ **Part 6 — SecuPulse** |
| **Bug-bounty full-chain automation (1 command)** | ✅ **Part 7 — Hunter** |
| **Subdomain takeover detection (dangling CNAME)** | ✅ **Part 7 — Hunter (20 service fingerprints)** |
| Concurrent fast scanning (Rust/Go) | ✅ Rust engine |
| CI/CD output (JSON/SARIF) | ✅ Part 3 — SARIF 2.1.0 |
| Crawling + endpoint discovery | ✅ Part 3 — SecuSpider |
| HTML + PDF reporting | ✅ Part 2 |
| Auth/session support | ✅ Part 3 — `--cookie` / `--headers` (session-aware scan) |

> 📌 **Nucleus engine = Nuclei-র কাঠামোর mini replica**: নিজস্ব YAML parser
> (zero-dependency!), extractors (`{{var}}`), matchers (status/regex/contains/version),
> `and/or` condition, `not` inversion, part selection (status/header/body/all)।
> ক্রেতাকে এখন বলতে পারবে: *"I built my own Nuclei-style template engine + CVE
> templates"* — এটাই প্রিমিয়াম gig।

---

## ⚖️ আইনি নোট
1. শুধু অনুমোদিত টার্গেট (নিজের সাইট/ল্যাব/লিখিত পারমিশন)।
2. Gig-এ "hacking" লিখো না — "Security Audit / Vulnerability Assessment / Hardening"।
3. টুলগুলো defensive/audit — Fiverr ToS-সম্মত।
4. `cve_lookup.py` তৃতীয় পক্ষের ফ্রি API (CIRCL) ব্যবহার করে — rate limits মেনে চলা হয়।

---

## ☁️ Phase 9 — Enterprise Cloud, Container, Kubernetes & IaC Security

Provider-neutral security layer on TOP of the existing Phase 1–8 platform.
**No second system**: every Phase-9 finding flows through the existing
`Finding` → fingerprint → dedup → confidence → risk → evidence →
correlation pipeline, and cloud assets through the existing `Asset` model.
Jobs/worker, monitoring, DevSecOps gates, SARIF, reporting, RBAC, audit
and rate limiting are all reused (not duplicated).

### Modules

| File | Responsibility |
|---|---|
| `python/cloud_security.py` | Provider registry (`fixture`/`aws`/`azure`/`gcp` in-place stubs), account CRUD + credential encryption-at-rest, exposure classifier, 10 CLOUD rules (v1), `persist_result` (shared persistence for all four domains) |
| `python/container_security.py` | Digest-identity image registry, 9 CONT rules, package + CVE normalization |
| `python/kubernetes_security.py` | Bounded multi-doc YAML parser (PyYAML safe_load; no eval/exec), 16 K8S rules, **Secret metadata only** (values dropped before storage) |
| `python/iac_security.py` | Static Terraform/CloudFormation/YAML analysis (regex-attribute extractor, no Terraform/kubectl execution), 9 IAC rules, hardcoded-secret detection (values always redacted) |
| `cloudsec_cmd.py` | `main.py cloudsec …` CLI surface |

### Deterministic identity
- Cloud resource: `provider|account|region|resource_type|resource_id`
  (canonical form; names are never identity).
- Container image: `registry/repository@sha256:<digest>` — tags are
  metadata, never identity.
- Kubernetes workload/RBAC asset: `kubernetes|org|namespace|
  cluster_resource|namespace|kind|name`.

### Credentials & secrets (never stored in clear)
- Cloud account / cluster credentials: `credential_ref` (pointer) +
  `credential_enc` (encrypted at rest via the existing `notify` key-wrap)
  + a non-reversible `enc:<sha256[:8]>` hint. Serialized views redact to
  `[REDACTED]`.
- Kubernetes `Secret` documents: only `name/namespace/type/key_names/
  managed_by/created_at` are persisted (in the scan summary) — values are
  dropped before any storage/logging.
- IaC hardcoded-secret literals: reported as
  `IAC-SECRET-HARDCODED-001` with the attribute NAME only; the value is
  replaced by a redaction marker and never persisted (verified by test).

### Rules (all deterministic, all versioned `v1`)
- **CLOUD (10):** CLOUD-STORAGE-PUBLIC-001, CLOUD-DB-PUBLIC-002,
  CLOUD-NET-MGMT-OPEN-003, CLOUD-NET-ANY-OPEN-004,
  CLOUD-ENCRYPTION-MISSING-005, CLOUD-LOGGING-DISABLED-006,
  CLOUD-MONITORING-DISABLED-007, CLOUD-IAM-WILDCARD-008,
  CLOUD-KEY-UNUSED-009, CLOUD-LB-PUBLIC-010.
- **CONT (9):** privileged, host-network, host-PID, hostPath, dangerous
  capabilities, root user, missing resource limits, sensitive env keys,
  unpinned tag (CONT-…-001…009) + `CONT-CVE-<id>` for supplied vulns.
- **K8S (16):** K8S-PRIVILEGED-001 … K8S-RBAC-WILDCARD-012,
  K8S-CLUSTER-ADMIN-013, K8S-ANON-ACCESS-014 (anonymous bindings),
  K8S-NO-NETWORKPOLICY-015 (per namespace), K8S-NO-PROBES-016.
- **IAC (9):** IAC-SECRET-HARDCODED-001 … IAC-UNPINNED-PROVIDER-009.

### Failure taxonomy (§47) — an unavailable assessment is NEVER “0 / PASS”
- Cloud: `cloud_provider_unavailable`, `invalid_cloud_credentials`,
  `cloud_permission_denied`, `inventory_failed`,
  `resource_limit_exceeded` (tested via injectable failing providers).
- Container: `container_registry_unavailable`, `parser_failure` (ceiling),
  `secret_redaction_failure`.
- Kubernetes: `k8s_api_unavailable`, `k8s_manifest_invalid`,
  `parser_failure` (manifest bytes/docs ceilings), plus YAML
  alias-bomb defence (anchor/alias budget).
- IaC: `iac_source_unavailable`, `iac_file_limit_exceeded`,
  `parser_failure` (file bytes / resource ceilings), `iac_source_forbidden`.

### Integration
- **DevSecOps:** Phase-9 findings carry risk/observations (via the
  existing CorrelationService), so gates evaluate them
  (`max_open_critical`, …) and produce immutable results; verified end-to-end
  with `cloud-scan` profile + `extra_payload`.
- **SARIF:** existing `sarif_export.to_sarif` emits valid SARIF 2.1.0 for
  Phase-9 findings (no second serializer).
- **Jobs:** six in-process profiles
  (`cloud-scan`, `cloud-inventory`, `container-scan`, `kubernetes-scan`,
  `iac-scan`, `posture-snapshot`) run inside the worker — **no subprocess,
  no shell** (`Profile.in_process`); bulk material (manifests/files/
  inventories) is staged in the scan record, job payloads stay scalar +
  allowlisted. Phase-9 counters surface on the stage record
  (`phase9.findings:N` etc.).
- **Monitoring:** existing `MonitoringService.create(scan_profile=
  “cloud-scan”)` accepts Phase-9 profiles (tested).
- **RBAC (Phase-9 permissions, only what is required):** read (viewer+),
  scan/inventory run (analyst+), source registration + credential
  management (security_manager+), destructive deletion (admin/owner).
- **Audit:** `cloud.account.created/deleted`, `cloud.inventory.refreshed`,
  `cloud.scan.started/completed`, `container.image_registered/deleted`,
  `container.scan.started/completed`, `kubernetes.cluster_registered/
  probed/deleted`, `kubernetes.scan.started/completed`, `iac.scan.started/
  completed`, `iac.record_deleted` — plus the Phase-8 audit allowlist gap
  fixed (`identity.break_glass.started/ended` were being swallowed).
- **Dashboard:** `/phase9` panel + read-only API `/api/phase9/checks`,
  `/api/phase9/accounts|images|clusters|iac|findings` (rule metadata /
  source summaries / recent findings — org-filtered, redacted, bounded;
  zero secret material).

### CLI

```bash
python3 main.py cloudsec profiles                     # in-process profiles
python3 main.py cloudsec account-add --org X --provider fixture --account-id 111122223333 ...
python3 main.py cloudsec account-scan --org X --project P --account <id>
python3 main.py cloudsec image-add --repository ghcr.io/acme/web --digest sha256:...
python3 main.py cloudsec cluster-add --name prod --endpoint k8s.example:6443
python3 main.py cloudsec cluster-scan --cluster <id> --manifest deploy.yaml
python3 main.py cloudsec iac-scan --file main.tf --source my-repo
python3 main.py cloudsec findings --limit 20
```

Every command honors `--db` and `--as TOKEN` (RBAC + tenant isolation).

### Tests (Phase 9) — honest numbers
- `tests/test_cloud_security.py`: **63 tests** — provider validation &
  fixture determinism, exposure invariant (`internal_only` can never be
  internet-facing), account CRUD + duplicate rejection + credential
  redaction, CLOUD CONT K8S IAC rule coverage, digest identity, Secret
  values never stored, IaC secret redaction, explicit failure taxonomy,
  BOLA/cross-tenant isolation on every service, RBAC matrix consistency,
  in-process job profiles (success + explicit payload failure), DevSecOps
  gate verdict + SARIF 2.1.0, dashboard org isolation, **§44 concurrency**
  (4 parallel scans → deterministic 11 findings/10 assets; 4 duplicate
  ingests → still 11/10), **§49 failure injection** (provider 500-like /
  permission-denied / missing project / missing account), **§50 scale**
  (60 files → 420 resources; 5,000 packages bounded; deterministic
  fingerprints across reruns).
- **Full regression:** `python3 tests/run_tests.py` → **757 tests OK**
  (694 Phase-1–8 + 63 Phase-9), 0 failures/errors, 258.5s.
- Solo suites (this run): monitoring 110, reporting 76, devsecops 93,
  identity 100, cloud-security 60 — all OK.

### Honest limits (Phase 9)
- `aws`/`azure`/`gcp` are **in-place adapter stubs**: they validate
  provider identity + environment-credential references and then fail
  explicitly (`cloud_provider_unavailable`) — live cloud SDK adapters are
  NOT bundled; the `fixture` provider is the deterministic test source.
- Kubernetes assessment is **declarative/manifest-only** (bounded YAML);
  no live API mutation, no `kubectl`, no operator.
- Terraform analysis is **static regex-attribute extraction**: it covers
  the documented deterministic checks; it is not a full HCL parser and
  will not evaluate expressions, modules, or functions.
- No archive/directory extraction (out of scope by design — no archive
  surface to protect).
- No automatic remediation, no infrastructure mutation, no
  `terraform apply/destroy`, no `kubectl apply/delete`, no IAM changes.
- No certification claims (not CIS/SOC 2/PCI/ISO certified).

---

## 🛡️ Phase 10 — Security Operations · Threat Intelligence · EASM

Provider-neutral security operations CLI (`python3 main.py security …`) that
**reuses** the existing platform (Phase 1–9) — no duplicate infrastructure:

- **Threat-intel catalog** (`ti add|list|update|revoke|import|export|source-list|match`):
  deterministic IOC normalization (domain/hostname/ipv4/ipv6/url/hash/email/
  cert-fingerprint), lifecycle (active → expired/revoked), confidence axis
  (`unknown|low|medium|high|confirmed`), per-org isolation.
- **Safe feed import** (json / csv / STIX-like bundles): bounded bytes,
  records, fields, nesting; stdlib-only parsing (no pickle/eval/YAML);
  malformed records skipped with explicit reasons; deterministic dedup.
- **External Attack Surface** (`attack-surface scan|list`, `observations`,
  `domains`, `certificates`): scope-guarded asset ingest, discovery events,
  topology relations, exposure deltas, certificate intelligence with the
  deterministic rule set (`AS-CERT-EXPIRED-001`, `-EXPIRING-002`,
  `-MISMATCH-003`, `-WEAK-004`, `-UNEXPECTED-SAN-005`) — private key
  material is always rejected.
- **Correlation → findings**: IOC matches against assets/observations/
  findings/events create `TI-IOC-*` findings (dedup, no self-matching),
  with `ioc.matched` events and a threat-match ledger.
- **Prioritization**: reuses `risk.RiskEngine` with asset criticality /
  exposure context → risk score + P0–P4 priority.
- **Threat clusters**: deterministic, non-attributing signal clusters
  (findings sharing IOC/domain/IP signals) with members.
- **Investigation cases**: create/list/show/update/assign/close + status
  machine, linked references (finding/asset/ioc/observation/evidence/
  alert/remediation — existence + tenant verified), timeline, events.
- **RBAC**: `attack_surface.*`, `threat_intel.*`, `cases.*` permissions in
  the existing role matrix (viewer ⊆ analyst ⊆ security_manager);
  `--as TOKEN` enforces fail-closed with tenant scoping.
- **Dashboard**: `/phase10` panel + read-only API `/api/phase10`,
  `/api/phase10/iocs|cases|clusters|findings` (org-filtered, redacted).
- **Reporting**: `threat_intel` section in report snapshots
  (IOC counts, matches, clusters, cases, open TI findings).

### CLI
```bash
python3 main.py security --db platform.db attack-surface scan --org O --project P --entries '[...]'
python3 main.py security ti add --org O --value 203.0.113.99 --type ipv4 --confidence confirmed
python3 main.py security ti import --org O --name feed --file iocs.json
python3 main.py security ti match --org O --project P
python3 main.py security threat clusters --org O --project P
python3 main.py security threat prioritize --org O --project P
python3 main.py security case create --org O --project P --title "Review IOC hit"
python3 main.py security --as TOKEN ti add --org O --value a.b --type domain   # RBAC enforced
```

### Tests (Phase 10) — honest numbers
- `tests/test_security_operations.py`: **41 tests** — normalization/
  classification, IOC lifecycle + tenant isolation, feed import (json/csv/
  stix + rate limit), attack-surface ingest + cert rules + idempotence,
  correlation/dedup/confidence gate, prioritization (risk reuse), clusters
  (build/list/members/determinism), cases (lifecycle/links/events), event
  enrichment, dashboard panel (snapshot/api/escaping), reporting
  integration, RBAC matrix.
- **Full regression:** `python3 tests/run_tests.py` → **955 tests OK**
  (848 Phase-1–11 + 107 Phase-12), 0 failures/errors, 400.3s.
- Phase-11 solo suite: `python3 tests/test_data_governance.py` → **50 tests OK**.
- Phase-12 solo suite: `python3 -m unittest test_federation` → **107 tests OK**.
- Solo suites (this run): intelligence 65, monitoring 110, reporting 76,
  security-operations 41 — all OK.

### Honest limits (Phase 10)
- Correlation is deterministic exact/substring matching (no fuzzy IP CIDR
  or typosquat analysis); domain signals use the documented two-label
  registrable-`ish` simplification (no PSL dependency).
- Feed import accepts only the documented record shapes (json list / csv /
  simple STIX equality patterns); complex STIX (AND/OR nesting, ranges) is
  skipped at parse time, never evaluated.
- EASM is ingest/analysis of authorized observations — no active scanning
  or crawling is performed by Phase 10 (`scope.py` guards rejects
  out-of-scope targets).

---

## 🛡️ Phase 11 — Data Protection · Privacy · Secrets & Compliance Governance

একই আর্কিটেকচারের **এক্সটেনশন** (কোনো প্রতিদ্বন্দ্বী সিস্টেম নেই, রিরাইট নেই):
Phase-1–10-এর IDENTITY + AUTHORIZATION + TENANT + ASSET/FINDING/RISK +
MONITORING/REPORTING/DEVSECOPS/CLOUD/SECOPS সব পুনঃব্যবহার হয়।

### যা যোগ হলো (`python/data_governance.py`, `python/privacy.py`,
### `python/compliance_governance.py`, `store.py` migration v13)

- **Data classification** — documented allowlist (public / internal /
  confidential / restricted / secret / personal_data / security_sensitive /
  authentication_material / financial_data), rank + effective resolution
  (explicit row → org default → built-in `internal`), provenance, এবং
  **no-silent-downgrade**: sensitive→less-sensitive পরিবর্তনে `authorized`
  লাগবে (data.downgrade permission; প্রতিটি অস্বীকৃতি audited)।
- **Central minimization/redaction engine** — `redact.py`-ই একমাত্র engine;
  detect শুধু *count* + redacted sample রিটার্ন করে (value কখনোই নয়)।
- **Secret & credential governance** — metadata-only registry:
  search hash (sha256, one-way) ≠ decryptable storage (notify encryption,
  scim creds, cloud credential_enc আলাদা করে documented); never plaintext;
  lifecycle active→expired/revoked/rotation_required; কোনো auto-rotation নেই।
- **Personal-data governance** — conservative detection + auditable
  correction/restriction/cover; কোনো "perfect-PII" দাবি নেই।
- **Retention** — tenant/project-scoped policies, deterministic bounds
  (1–3650 days), documented defaults, dry-run (preview counts) → audit
  per run; `audit_events` কখনো deleted হয় না; evidence tombstoned in place।
- **Legal/retention holds** — fail closed: held object delete/correct/
  cover সম্ভব নয়; viewer কখনো hold create/release করতে পারে না।
- **Controlled deletion** — preview → hold check → retention-eligibility
  (বা explicit authorization) → delete → audit; tombstone-only types
  (evidence/audit) hard-delete refused।
- **Privacy request workflow** — access/export/deletion/correction/
  restriction; strict state machine; legal interpretation **operator/
  customer responsibility** (module-এ স্পষ্ট documented)।
- **Secure export** — bounded (MAX_EXPORT_ITEMS 50k / 64 MiB), deterministic,
  redacted, sha256 integrity + manifest, `data_exports` record; no unbounded
  memory (keyset paging)।
- **Compliance evidence engine + policy exceptions** — 12 control families,
  6 evidence-state statuses (not_evaluated/supported/partially_supported/
  insufficient_evidence/not_supported/exception); **evidence 존재 ≠
  requirement satisfied**; expired exception কখনোই silently effective নয়।
- **Audit + tenant isolation** — সব sensitive অপারেশন existing immutable
  chain-এ; cross-tenant সবসময় NotFoundError (fail closed); audit metadata
  কখনো secret content ধারণ করে না।
- **RBAC** — 18টি নতুন permission (`data.*` `secrets.*` `privacy.*`
  `compliance.*`), monotonic tiers; holds/delete/export/secrets-privacy
  কখনো viewer-level নয়। এখন মোট **122 permissions**।
- **API/CLI/Dashboard** — `security data|privacy|compliance|secrets`
  subcommands (`--as TOKEN` RBAC-enforced), dashboard `/phase11` +
  `/api/phase11/*` (read-only, redacted), `/secrets/status`।
- **Integrations** — security events + Phase-5 alert rules (9টি new
  default rule), reporting (evidence builders: authentication/retention/
  secrets_management/monitoring), DevSecOps gate signals
  (secret_like_evidence, sensitive_findings, registry_clean,
  private_data_classified — same evaluator), monitoring counters।

### Safety & limits (স্বচ্ছতা)
- কোনো eval/exec/shell নেই, কোনো unsafe deserialization নেই, কোনো
  unbounded SQL নেই; সব বাউন্ড central constants-এ
  (MAX_EXPORT_ITEMS/MAX_RETENTION_BATCH/MAX_AUDIT_PAGE_SIZE/
  MAX_EVIDENCE_PAGE_SIZE/MAX_COMPLIANCE_PAGE_SIZE)।
- কোনো plaintext secret logging নেই; `detect()` শুধু redacted sample।
- **Non-goals (ইচ্ছাকৃতভাবে নেই):** WebAuthn, SIEM/EDR/SOAR, LLM-ভিত্তিক
  privacy/compliance সিদ্ধান্ত, blockchain, Kafka/Redis/ES, external
  KMS/DLP, billing, কোনো certification/compliance দাবি।
- Scale test: 100 tenants / 1000 projects / 10k findings / 20k evidence /
  5k audit / 1k privacy requests — deterministic + bounded (one pass)।

---

## 🛡️ Phase 12 — Enterprise Data Federation · Evidence Exchange · Bulk Operations · External Integration Governance

একই আর্কিটেকচারের **এক্সটেনশন** (কোনো প্রতিদ্বন্দ্বী সিস্টেম নেই, রিরাইট নেই):
Phase-1–11-এর IDENTITY + RBAC + TENANT + ASSET/FINDING/RISK + EVIDENCE +
JOBS + MONITORING/REPORTING/DEVSECOPS/CLOUD/SECOPS + DATA GOVERNANCE/
PRIVACY/RETENTION সব পুনঃব্যবহার হয়। কোনো Redis/Kafka/Celery/ES নেই,
দ্বিতীয় scheduler নেই, দ্বিতীয় retention/redaction engine নেই।

### যা যোগ হলো (`python/federation.py` — ২,৮৪২ লাইন, `store.py` migration v14)

- **Peer trust lifecycle** — `pending → active → suspended/expired/revoked`
  (closed transition table); creation-এ কখনো implicit trust নেই;
  approval-এ **separation of duties** (creator ≠ approver, নাহলে
  Forbidden); revoke TERMINAL — নতুন operation বন্ধ, কিন্তু আগে import হওয়া
  local data কখনো মুছে যায় না; expiry **fail closed** (sweep-এর আগেই
  usage বন্ধ); renewal একমাত্র `re-request → fresh approval` পথে।
- **Exchange policies** — classification allowlist; `secret` +
  `authentication_material` ডিফল্টে **কখনোই exportable নয়**
  (`explicit_sensitive` লাগে, তাতেও raw secret value কখনো যায় না);
  field allowlist শুধু NARROW করতে পারে (Phase-11 minimization engine
  reuse); max_objects bounded (≤ 5000); expired policy immutable।
- **Provider-neutral package** — deterministic envelope
  (`fed-package-v1`), canonical sha256 integrity (volatile keys বাদে
  sort-keys JSON); একই content → একই hash → একই package_id;
  `unsigned|integrity_verified|externally_signed` — external signature
  শুধু REFERENCE (`verified: false`), কোনো fake PKI trust নেই।
- **Import — ১২টি validation gate** (syntax, schema, integrity, grant,
  sender, destination, expiration, classification, object limits, field
  policy, idempotency claim, tenant mapping + provenance) — প্রতিটি gate
  fail closed; tampered package → `integrity_mismatch` + audit + Phase-10
  finding; rejections recorded/replayed (কখনো silent success নয়)।
- **Idempotent import** — `UNIQUE(org_id, package_hash)` claim; একই
  envelope আবার → duplicate shortcut (কিছুই re-apply হয় না); নতুন
  envelope-এ একই content → Phase-4 fingerprint dedup (কোনো duplicate
  finding নয়); collision strategies `skip|link|merge_metadata|reject` —
  কখনো silent overwrite নয়; 2-thread race-এও ঠিক একবার apply (asserted)।
- **Provenance** — প্রতিটি imported object-এ source org/project/object,
  package id/hash, import id/time, policy id; evidence-এ
  `[federated:…]` marker + `scanner="federation"`; case-এ marker;
  IOC-তে `source="federation:<peer8>"`।
- **Cross-org BOLA safety** — case refs শুধু লোকালি resolve হলেই link হয়
  (existence + tenant re-verified); foreign/dangling ref → skipped।
- **Bulk operations — EXISTING Phase-3 job engine-এ** (নতুন scheduler
  নেই): scalar-only job payload (≤ 4 KiB), staged material scan record-এ,
  deterministic scan/job ids, progress checkpoint, cooperative cancel,
  bounded concurrency, non-retryable deterministic refusals
  (`validation_rejected`), stage counters (`phase12.packages:1|…`);
  4 op: `bulk_export|bulk_import|bulk_classify|bulk_retention_preview` —
  "share everything" job-এর অস্তিত্ব নেই (explicit peer/policy বাধ্যতামূলক)।
- **External integration boundary** — SIEM/ticketing/data-lake/GRC/webhook
  ABSTRACTION (কোনো real SIEM/EDR/SOAR connector নেই); 7টি closed webhook
  event; payload redacted + bounded (16 KiB, honest summary degradation) +
  sha256-fingerprinted + audited; endpoint SSRF guard existing
  `validate_webhook_url` reuse (HTTPS, private-net block); delivery
  failure কখনো swallowed নয় (recorded + observable)।
- **RBAC** — 15টি নতুন permission (`federation.*` ×10, `integration.*`
  ×5); **viewer ও analyst শূন্য পায়**; security_manager operate করে কিন্তু
  approve/revoke করতে পারে না (admin+); মোট **137 permissions**
  (viewer 35 / analyst 63 / security_manager 113 / admin=owner 137)।
- **Retention reuse** — `federation_packages` (365d, tombstone) /
  `federation_imports` (1095d) / `integration_events` (180d) — same
  Phase-11 engine, holds কাজ করে (object_type = retention kind)।
- **Reporting/Monitoring/DevSecOps/SecOps** — `federation` report section;
  7টি নতুন default alert rule (peer/policy expiry, repeated import
  failures, integrity failures, bulk failures, delivery failures); 5টি
  gate signal (same evaluator); import anomalies → real findings
  (`fed-integrity-mismatch` High, `fed-field-policy-violation` Medium,
  `fed-repeated-rejection` Medium)।
- **Dashboard/API/CLI** — `/phase12` panel + `/api/phase12`
  (tenant-scoped, metadata-only — payload কখনো পড়া হয় না,
  HTML-escaped); `security federation` CLI family (15 subcommands,
  `--as TOKEN`, fail closed)।

### Tests (Phase 12) — honest numbers
- `tests/test_federation.py`: **107 tests OK** (~66s solo) — lifecycle,
  policy, package determinism/integrity, 12 gates, apply/dedup/collision,
  idempotency + concurrency race, bulk ops (worker + sync), RBAC (5 roles),
  tenant isolation, integration boundary, audit chain verify, dashboard/API,
  Phase 4–11 reuse, failure injection, CLI subprocess smoke (RBAC gates সহ)।
- **Full regression:** `python3 tests/run_tests.py` → **955 tests OK**
  (848 Phase-1–11 + 107 Phase-12), 0 failures/errors, 400.3s।

### Honest limits (Phase 12)
- কোনো PKI/trust-anchor infra নেই — `externally_signed` শুধু reference,
  local code কখনো signature-verified দাবি করে না।
- কোনো peer discovery/federation network নেই — trust সর্বদা explicit,
  mutually-configured; transitive trust নেই।
- কোনো real SIEM/EDR/SOAR/ticketing connector নেই — bounded redacted
  webhook events only (existing provider abstraction)।
- Scale test offline suite budget-এ bounded (120 findings + 120 evidence →
  241-object package end-to-end, 30 concurrent bulk jobs) — spec-এর
  literal 10k/500k/100 figures-এর জন্য একই hard caps (5000 objects,
  32 MiB, 200/page keyset paging) boundary-তে directly asserted।
- কোনো legal/compliance certification দাবি নেই।

---

## 💰 বিক্রির গিগ প্ল্যান (আপডেটেড)

**Gig 1 — "I will audit your website & API security (OWASP Top 10 + report)"**
$75 (1 URL+HTML) / $150 (HTML+PDF+fix guide) / $300 (web+API+30-day support)

**Gig 2 — "I will build a custom security scanner / cybersecurity project"** $199–$499
(তোমার full suite-এর sub-set — Django/React/CLI, source code সহ)

**Gig 3 — "I will detect & fix website hacking attempts (log IDS + hardening)"** $100–$300

**Gig 4 — "I will find CVEs for your server software"** (cve_lookup + manual) $50–$150

> মাঝারি টার্গেট মাস ১–২ এর মধ্যে **$200–$600**; টেমপ্লেট ইঞ্জিন সহ Part 3 শেষে **$500+ /প্রজেক্ট**।

---

## 🛣️ রোডম্যাপ (Part 3+ — "World #1" দিকে)

- [x] **Part 3 (কমপ্লিট ✅):** Nucleus YAML template engine + 17 templates + SARIF 2.1.0 + SecuSpider crawler + auth/session (`--cookie`, `--headers`)
- [x] **Part 4 (কমপ্লিট ✅):** Injector active fuzzer (SQLi error/boolean/time-based, XSS reflection, CMDi, traversal) + WallFinder WAF fingerprinting (30+ vendors) + ৮টা নতুন CVE টেমপ্লেট + KEV mini-DB আপডেট (27 CVEs)
- [x] **Part 5 (কমপ্লিট ✅):** SubKraken subdomain enum (crt.sh CT-logs + threaded DNS, লাইভ টেস্টেড: example.com → ৬ নাম + IP রেজলভ ৩.৫s) + CloudScope cloud/DB exposure checker (S3, GCS, Azure, Redis, MongoDB, Elasticsearch, Memcached)
- [x] **Part 6 (কমপ্লিট ✅):** SecuPulse findings portal — zero-dependency stdlib web UI (no Django/pip needed): overview dashboard + SVG severity donut, per-client (multi-tenant) workspaces, findings explorer (search/filter/expandable evidence+fix), **remediation status tracking** (open → in-progress → mitigated → verified, persisted), REST API, token auth for client-facing mode, JSON export. লাইভ টেস্টেড: 4 real scans (8 Critical SQLi + cloud + subdomain + WAF) → portal renders, API 200, auth 401/200।
- [x] **Part 7 (কমপ্লিট ✅):** Hunter — ৭-স্টেজ এক-কমান্ড bug-bounty chain: **Stage 1** SubKraken recon (crt.sh) → **Stage 2** live-host probing (status/title/server/tech) + **subdomain takeover detection** (নিজস্ব stdlib DNS-CNAME resolver; 20টি service fingerprint — can-i-take-over-xyz Aug-2026 markers) → **Stage 3** WallFinder WAF → **Stage 4** SecuSpider crawl (endpoints + param URLs) → **Stage 5** 25টি Nucleus template → **Stage 6** Injector fuzzing (opt-in `--active`) → **Stage 7** unified dashboard-ready JSON (+SARIF)। লাইভ টেস্টেড: `hunt example.com` → 2 live hosts + Cloudflare WAF + 5 template findings (35.8s)। SecuPulse এখন **live-updating** — নতুন scan পোর্টালে auto-appear।

সব Part শেষ — **মোট ১৯টি সাবকমান্ড, ২১টি মডিউল** (স্ট্যান্ডঅ্যালোন টুলস; এই
part-গুলোতে ৪৮/৪৮ টেস্ট)। এর উপরে এসেছে প্ল্যাটফর্ম ফেজ 1–12 (নিচের Phase 1–12
সেকশন) — সম্পূর্ণ স্যুট এখন **955/955 টেস্ট OK** (`tests/run_tests.py`: ৪৮ Part
suite + foundation 64 + security 86 + orchestration 74 + intelligence 65 +
monitoring 110 + reporting 76 + devsecops 93 + `test_identity.py` 100 +
`test_cloud_security.py` 63 + `test_security_operations.py` 41 +
`test_data_governance.py` 50 + `test_federation.py` 107)।

> ⚠️ সৎ কথা: "40MB source code" নিজে লক্ষ্য না — `nuclei` মাত্র ~10MB binary,
> কিন্তু 11,000+ টেমপ্লেট। **কোডের পরিমাণ নয়, কভারেজ + পারফরম্যান্সই "World #1"**
> বানায়। আমরা কোয়ালিটি-ফার্স্ট বাড়াচ্ছি।

---

## 📚 লার্নিং (ফ্রি)
1. PortSwigger Web Security Academy — https://portswigger.net/web-security
2. OWASP API Security Top 10 — https://owasp.org/API-Security/
3. Rust book — https://doc.rust-lang.org/book/
4. ল্যাব: OWASP Juice Shop, DVWA, HackTheBox (free tier)

