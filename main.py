#!/usr/bin/env python3
# ============================================================================
#  SecuToolkit — Unified CLI (world-class security suite, zero external deps)
#  ---------------------------------------------------------------------------
#  Subcommands:
#    web      <url>                 Web security audit -> HTML + JSON
#    api      <url>                 API security audit (OWASP API Top 10)
#    scan     <url>                 Nuclei-style YAML template scan (+ SARIF)
#    spider   <url>                 Crawler / endpoint discovery
#    active   <url>                 Active fuzzing: SQLi/XSS/CMDi/traversal (AUTHORIZED ONLY)
#    waf      <url>                 WAF fingerprinting
#    subdomain <dom>                Subdomain enumeration (crt.sh + DNS brute)
#    cloud    --bucket/--service    Cloud & DB exposure checker (S3/GCS/Azure/Redis/…)
#    dashboard --root results       SecuPulse findings portal (multi-client web UI)
#    hunt     <domain>              ⭐ Part 7: one-command bug-bounty chain
#                                   (subdomain→live probe→takeover→crawl→templates→[active fuzz])
#    ports    <host> [ports]        Fast port scan (Rust back-end)
#    fuzz     <url>                 Directory fuzzer (Rust back-end)
#    phishing <url>|--file f        Phishing URL analysis
#    cve      --product X           CVE lookup (internet, CIRCL API)
#    logs     --log access.log      Access-log IDS analysis
#    passwd   --password "..."      Password strength audit
#    report   --json f.json         Generate PDF from findings JSON
#    sarif    --json f.json         Findings JSON -> SARIF 2.1.0
#    audit    <url>                 FULL pipeline: ports + web + api + PDF + SARIF
#    demo     --host H              Run demo against a local test server
#    platform <action>              Phase 1 foundation: org/project/asset/scope/
#                                   scan/finding/ingest/audit (SQLite, opt-in)
#                                   --as TOKEN enforces RBAC+tenancy (Phase 2)
#    auth     <action>              Phase 2: users, roles, sessions, API keys,
#                                   password reset, lockout, rate limiting
#    scan-job <action>              Phase 3: persistent job queue (create/list/
#                                   status/pause/resume/cancel/retry) — same
#                                   RBAC/tenancy rules as platform
#    scan-worker <action>           Phase 3: local worker runtime (run/status)
#
#  LEGAL: authorized testing only.
# ============================================================================

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

from cloudsec_cmd import cmd_cloudsec   # Phase 9 CLI surface

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(HERE, "python")
RUST_BIN = os.path.join(HERE, "rust")


def run_py(script, *args, capture=False):
    cmd = [sys.executable, os.path.join(PY, script), *args]
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True)
    return subprocess.run(cmd)


def run_rust(src, *args):
    binary = os.path.join(RUST_BIN, src.replace(".rs", ""))
    if not os.path.exists(binary):
        print(f"[*] Compiling {src}…")
        subprocess.run(["rustc", "-O", os.path.join(RUST_BIN, src), "-o", binary], check=True)
    subprocess.run([binary, *args])


def guard(target):
    """Scope enforcement integration point (Phase 1).
    NO-OP unless scope is enabled in secconfig — existing CLI semantics
    unchanged by default. When enabled, raises ScopeViolationError for
    targets outside the allow/deny policy (exit code 3)."""
    sys.path.insert(0, PY)
    import scope
    try:
        scope.guard_target(target)
    except SystemExit:
        raise
    except Exception as e:
        print(f"[!] Scope refused: {getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 3))


def errors_mod():
    sys.path.insert(0, PY)
    import errors
    return errors


def cmd_web(args):
    guard(args.url)
    run_py("web_security_audit.py", "--url", args.url,
           "--out", args.out or f"report_{host_of(args.url)}.html",
           "--json", args.json or f"results_{host_of(args.url)}.json")


def cmd_api(args):
    guard(args.url)
    run_py("api_security_audit.py", "--url", args.url, "--json",
           args.json or f"api_{host_of(args.url)}.json")


def cmd_ports(args):
    guard(args.host)
    run_rust("port_scanner.rs", args.host, *( [args.ports] if args.ports else ["--top", "100"]))


def cmd_fuzz(args):
    guard(args.url)
    run_rust("dir_fuzzer.rs", args.url)


def cmd_phishing(args):
    if args.file:
        run_py("phishing_detector.py", "--file", args.file, "--json",
               args.json or "phishing_results.json")
    else:
        run_py("phishing_detector.py", "--url", args.url)


def cmd_cve(args):
    if args.cve:
        run_py("cve_lookup.py", "--cve", args.cve)
    else:
        run_py("cve_lookup.py", "--vendor", args.vendor or args.product,
               "--product", args.product, "--top", str(args.top or 10))


def cmd_logs(args):
    run_py("log_analyzer.py", "--log", args.log, "--json", args.json or "log_report.json")


def cmd_passwd(args):
    run_py("password_audit.py", "--password", args.password)


def cmd_report_pdf(args):
    # PART 01: renamed from the shadowed ``cmd_report`` duplicate.
    # A later Phase-6 ``cmd_report`` (snapshot reports) silently
    # overrode this one, so ``main.py report --json ...`` -- a
    # documented command -- crashed with AttributeError on
    # ``args.action``. The legacy ``report`` subparser keeps its
    # original behaviour under this explicit name.
    run_py("pdf_report.py", "--json", args.json,
           "--out", args.out or "report.pdf", "--title", args.title or "Security Assessment")


def cmd_scan(args):
    """Nucleus template engine (Nuclei-style YAML templates)."""
    guard(args.url)
    scan_args = ["--target", args.url,
                 "--templates", args.templates or os.path.join(HERE, "templates"),
                 "--out", args.out or f"scan_{host_of(args.url)}.json",
                 "--timeout", str(args.timeout or 12)]
    if args.sarif:
        scan_args += ["--sarif", args.sarif]
    if args.cookie:
        scan_args += ["--cookie", args.cookie]
    if args.verbose:
        scan_args.append("-v")
    run_py("template_engine.py", *scan_args)


def cmd_spider(args):
    guard(args.url)
    sp_args = ["--url", args.url, "--depth", str(args.depth or 2),
               "--limit", str(args.limit or 60),
               "--out", args.out or f"spider_{host_of(args.url)}.json"]
    if args.cookie:
        sp_args += ["--cookie", args.cookie]
    if args.verbose:
        sp_args.append("-v")
    run_py("spider.py", *sp_args)


def cmd_sarif(args):
    run_py("sarif_export.py", "--json", args.json, "--out", args.out or "results.sarif")


def cmd_active(args):
    """Injector — active payload fuzzing (SQLi/XSS/CMDi/traversal)."""
    guard(args.url)
    act_args = ["--url", args.url, "--type", args.type or "auto",
                "--delay", str(args.delay or 0.4), "--max", str(args.max or 40),
                "--out", args.out or f"active_{host_of(args.url)}.json"]
    if args.param:
        act_args += ["--param", args.param]
    if args.cookie:
        act_args += ["--cookie", args.cookie]
    if args.skip_timebased:
        act_args.append("--skip-timebased")
    if args.sarif:
        act_args += ["--sarif", args.sarif]
    run_py("active_fuzzer.py", *act_args)


def cmd_waf(args):
    guard(args.url)
    run_py("waf_detect.py", "--url", args.url,
           "--json", args.out or f"waf_{host_of(args.url)}.json")


def cmd_subdomain(args):
    guard(args.domain)
    en_args = ["--domain", args.domain, "--threads", str(args.threads or 100),
               "--timeout", str(args.timeout or 4.0),
               "--out", args.out or f"subdomains_{args.domain.replace('.', '_')}.json"]
    if args.no_crt:
        en_args.append("--no-crt")
    if args.no_brute:
        en_args.append("--no-brute")
    if args.resolve:
        en_args.append("--resolve")
    if args.wordlist:
        en_args += ["--wordlist", args.wordlist]
    run_py("subdomain_enum.py", *en_args)


def cmd_cloud(args):
    if args.service:
        # host[:port] service probe is a live network target — enforce scope
        guard(args.service.split(":", 1)[0] or args.service)
    # bucket/container names that embed a domain (e.g. "data.acme.com") are
    # scope-relevant too; plain resource names are identifiers, not targets.
    for name in (args.bucket, args.azure):
        if name and "." in name:
            guard(name)
    cl_args = ["--out", args.out or "cloud_checks.json", "--timeout", str(args.timeout or 6.0)]
    if args.bucket:
        cl_args += ["--bucket", args.bucket]
    if args.azure:
        cl_args += ["--azure", args.azure]
    if args.container:
        cl_args += ["--container", args.container]
    if args.service:
        cl_args += ["--service", args.service]
    run_py("cloud_check.py", *cl_args)


def cmd_hunt(args):
    guard(args.domain)
    hp = ["--domain", args.domain, "--client", args.client or "default",
          "--threads", str(args.threads or 50), "--timeout", str(args.timeout or 10.0),
          "--max-hosts", str(args.max_hosts or 40), "--depth", str(args.depth or 1),
          "--limit", str(args.limit or 40), "--payloads", str(args.payloads or 5),
          "--delay", str(args.delay or 0.6)]
    if args.hosts:
        hp += ["--hosts", args.hosts]
    if args.no_crt:
        hp.append("--no-crt")
    if args.no_brute:
        hp.append("--no-brute")
    if args.no_takeover:
        hp.append("--no-takeover")
    if args.no_waf:
        hp.append("--no-waf")
    if args.active:
        hp.append("--active")
    if args.cookie:
        hp += ["--cookie", args.cookie]
    if args.headers:
        hp += ["--headers", args.headers]
    if args.sarif:
        hp += ["--sarif", args.sarif]
    if args.wordlist:
        hp += ["--wordlist", args.wordlist]
    run_py("workflow.py", *hp)


def cmd_dashboard(args):
    da = ["--root", args.root or "results", "--host", args.host or "127.0.0.1",
          "--port", str(args.port or 8080)]
    if args.token is not None:
        token = str(args.token or "").strip()
        if not token:
            print("[!] Dashboard token must not be empty.", file=sys.stderr)
            sys.exit(2)
        if len(token) > 4096:
            print("[!] Dashboard token exceeds the maximum allowed length.", file=sys.stderr)
            sys.exit(2)
        os.environ["SECURITY_TOOLKIT_DASHBOARD_TOKEN"] = token
        print(
            "[!] A command-line token may be visible to process inspection; "
            "prefer SECURITY_TOOLKIT_DASHBOARD_TOKEN.",
            file=sys.stderr,
        )
    if getattr(args, "jobs_db", None):
        da += ["--jobs-db", args.jobs_db]
        if getattr(args, "jobs_org", ""):
            da += ["--jobs-org", args.jobs_org]
    if getattr(args, "intel_db", None):
        da += ["--intel-db", args.intel_db]
        if getattr(args, "intel_org", ""):
            da += ["--intel-org", args.intel_org]
    run_py("dashboard.py", *da)


def cmd_platform(args):
    """Phase 1 platform: orgs/projects/assets/scans/findings/scope/audit.
    Without --as: local/single-user mode (Phase-1 behaviour, unchanged).
    With --as TOKEN: every operation is enforced through the Phase-2
    RBAC + tenant-isolation layer (fail closed, generic errors)."""
    sys.path.insert(0, PY)
    import platform_service as pf
    import sec_config
    try:
        svc = pf.PlatformService(getattr(args, "db", None) or None)
    except Exception as e:
        print(f"[!] Platform init failed: {getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 5))
    ctx, authz = None, None
    as_tok = getattr(args, "as_token", "") or ""
    if as_tok:
        import authz as _az
        import identity as _id
        id_svc = _id.IdentityService(svc)
        authz = _az.AuthorizationService(svc, id_svc)
        try:
            ctx = authz.context_from_secret(as_tok)
        except Exception as e:
            print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
            sys.exit(getattr(e, "exit_code", 10))

    def need(perm):
        """RBAC gate — no-op in local mode, enforced with --as."""
        if ctx is not None:
            authz.require(ctx, perm)

    def need_org(org_id):
        if ctx is not None:
            authz.require_org(ctx, org_id)

    def need_project(project_id):
        if ctx is not None:
            authz.require_project(ctx, project_id)

    act = args.action
    try:
        if act == "init":
            cfg = sec_config.ensure_layout()
            print(f"[✓] Platform initialized (db: {svc.db_path})")
            print(f"    config : {sec_config.config_path()}")
            print(f"    data   : {cfg['data_dir']}")
            return
        if act in ("org-create",):
            if ctx is not None:
                # tenant creation is a bootstrap/local operation — an
                # authenticated caller cannot fabricate other tenants
                print("[!] Forbidden")
                sys.exit(errors_mod().AuthorizationError.exit_code)
            org = svc.org_create(args.name)
            print(f"[✓] Organization created: {org.id}  {org.name}")
            return
        if act in ("org-list",):
            if ctx is not None:
                need("organization.read")
                rows = [svc.org_get(ctx.org_id)]
            else:
                rows = svc.org_list()
            print(f"  {len(rows)} organization(s)")
            for o in rows:
                print(f"   {o.id}  {o.name:<28} {o.status}")
            return
        if act in ("project-create",):
            need("project.create")
            need_org(args.org)
            p = svc.project_create(args.org, args.name, args.description or "")
            print(f"[✓] Project created: {p.id}  {p.name} (org {p.org_id})")
            return
        if act in ("project-list",):
            if ctx is not None:
                org_arg = getattr(args, "org", None) or ctx.org_id
                if org_arg != ctx.org_id:
                    raise errors_mod().AuthorizationError("Forbidden")
                need("project.read")
                rows = authz.visible_projects(ctx)
            else:
                rows = svc.project_list(getattr(args, "org", None))
            print(f"  {len(rows)} project(s)")
            for p in rows:
                print(f"   {p.id}  {p.name:<28} org={p.org_id} {p.status}")
            return
        if act in ("asset-add",):
            need("asset.create")
            need_project(args.project)
            a = svc.asset_add(args.project, args.asset_type, args.value)
            print(f"[✓] Asset: {a.id}  [{a.asset_type}] {a.value}")
            return
        if act in ("asset-list",):
            need("asset.read")
            need_project(args.project)
            rows = svc.asset_list(args.project, getattr(args, "type", None))
            print(f"  {len(rows)} asset(s)")
            for a in rows:
                print(f"   {a.id}  [{a.asset_type:<14}] {a.value}")
            return
        if act in ("scope-set",):
            need("scope.update")
            need_project(args.project)
            data = svc.scope_set(args.project, args.allow.split(",") if args.allow else [],
                                 args.deny.split(",") if args.deny else [])
            print(f"[✓] Scope updated for {args.project}: {data}")
            return
        if act in ("scope-check",):
            need("scope.read")
            need_project(args.project)
            r = svc.scope_check(args.project, args.target)
            print(f"  {'✓ IN SCOPE' if r['in_scope'] else '✗ OUT OF SCOPE'}  {args.target}")
            return
        if act in ("scan-create",):
            import models
            need("scan.create")
            need_project(args.project)
            s = svc.scan_create(args.project, args.profile,
                                getattr(args, "scope", "") or "",
                                initiator={"actor": ctx.label() if ctx else "cli"})
            print(f"[✓] Scan created: {s.id}  profile={s.profile}  status={s.status}")
            # Phase 3: scan-create also creates the initial execution job
            # when the profile is a registered scanner profile and a target
            # is supplied (--target, else --scope). Existing single-command
            # behaviour is preserved: if either is missing we only warn.
            if not getattr(args, "no_job", False):
                import scanners as _sc
                import jobs as _jb
                registry = _sc.REGISTRY
                target = str(getattr(args, "target", "") or "") or \
                    str(getattr(args, "scope", "") or "")
                name = str(args.profile).strip().lower()
                if name in registry.PROFILES and target:
                    try:
                        jsvc = _jb.JobService(svc, registry)
                        job = jsvc.create_job(
                            s.id, name, {"target": target},
                            priority=getattr(args, "priority", "normal"),
                            active_enabled=bool(getattr(args, "active", False)),
                            max_attempts=int(getattr(args, "attempts", 3)),
                            timeout_seconds=int(
                                getattr(args, "timeout", 0)
                                or registry.get(name).timeout),
                            actor_id=(ctx.user_id if ctx else "cli"),
                            actor=(ctx.label() if ctx else "cli"))
                        print(f"[✓] Execution job queued: {job.id}  "
                              f"profile={job.profile}  status={job.status}")
                    except Exception as e:
                        print(f"[!] Job not created: "
                              f"{getattr(e, 'user_message', lambda: str(e))()}")
                elif target:
                    print(f"[!] No execution job: {name!r} is not a "
                          "registered scanner profile "
                          "(use `scan-job create`)")
                else:
                    print("[!] No execution job: give --target (or --scope) "
                          "and a registered profile, or use `scan-job create`")
            return
        if act in ("scan-status",):
            status = getattr(args, "status", "running")
            need("scan.start" if status in ("queued", "running", "completed",
                                            "failed")
                 else "scan.pause" if status == "paused" else "scan.cancel")
            if ctx is not None:
                authz.require_scan(ctx, args.scan_id)
            s = svc.scan_transition(args.scan_id, status)
            print(f"[✓] Scan {s.id}: {s.status}")
            return
        if act in ("scan-list",):
            need("scan.read")
            need_project(args.project)
            rows = svc.scan_list(args.project)
            print(f"  {len(rows)} scan(s)")
            for s in rows:
                print(f"   {s.id}  {s.profile:<16} {s.status:<10} {s.created_at}")
            return
        if act in ("finding-list",):
            need("finding.read")
            need_project(args.project)
            rows = svc.finding_list(args.project, getattr(args, "severity", None))
            print(f"  {len(rows)} finding(s)")
            for f in rows:
                print(f"   {f.id}  [{f.severity:>8}] {f.source:<12} "
                      f"{f.lifecycle:<14} {f.title[:60]}")
            return
        if act in ("finding-status",):
            need("finding.accept_risk" if args.status == "accepted_risk"
                 else "finding.resolve" if args.status in (
                     "resolved", "remediated", "false_positive")
                 else "finding.update")
            if ctx is not None:
                authz.require_finding(ctx, args.finding)
            f = svc.finding_set_status(args.finding, args.status)
            print(f"[✓] Finding {f.id}: {f.lifecycle}")
            return
        # ---- Phase 4: asset intelligence / finding intelligence --------
        _actor = ctx.label() if ctx is not None else "cli"
        if act in ("asset-intel", "asset-history", "asset-relations",
                   "asset-exposure"):
            need("asset.read")
            if ctx is not None:
                authz.require_asset(ctx, args.asset)
            import intel as _intel
            intel_svc = _intel.IntelService(svc)
            if act == "asset-intel":
                out = intel_svc.asset_intel(args.asset)
                print(json.dumps(out, indent=2, default=str,
                                 ensure_ascii=False))
            elif act == "asset-history":
                out = intel_svc.asset_history(
                    args.asset, limit=getattr(args, "limit", 50) or 50)
                print(f"  {len(out)} event(s)")
                for e in out:
                    print(f"   {e['ts']}  {e['obs_type']}"
                          f"({e['obs_key']}) {e['old_value']!r} -> "
                          f"{e['new_value']!r}  src={e['source']}")
            elif act == "asset-relations":
                out = intel_svc.relations(args.asset,
                                          limit=getattr(args, "limit", 50)
                                          or 50)
                print(f"  {len(out)} relation(s)")
                for e in out:
                    print(f"   {e['direction']} {e['rel_type']} "
                          f"{e['target_value']}  conf={e['confidence']}")
            else:
                out = intel_svc.exposure_derive(args.asset)
                print(json.dumps(out, indent=2, default=str,
                                 ensure_ascii=False))
            return
        if act in ("asset-criticality",):
            need("asset.criticality")
            if ctx is not None:
                authz.require_asset(ctx, args.asset)
            import intel as _intel
            intel_svc = _intel.IntelService(svc)
            out = intel_svc.criticality_set(args.asset, args.level,
                                            actor=_actor)
            print(f"[✓] {out}")
            return
        if act in ("asset-impact",):
            need("asset.criticality")
            if ctx is not None:
                authz.require_asset(ctx, args.asset)
            import intel as _intel
            intel_svc = _intel.IntelService(svc)
            tags = list(getattr(args, "tag", []) or [])
            out = intel_svc.business_impact_set(
                args.asset, {t: True for t in tags}, actor=_actor)
            print(f"[✓] {out}")
            return
        if act in ("finding-show", "finding-history", "finding-correlate",
                   "risk-show", "risk-history"):
            need("finding.read")
            if ctx is not None:
                authz.require_finding(ctx, args.finding)
            import correlate as _cor
            cs_svc = _cor.CorrelationService(svc)
            if act == "finding-show":
                v = cs_svc.finding_view(args.finding)
                if v is None:
                    print("[!] not found")
                    sys.exit(5)
                if getattr(args, "no_evidence", False):
                    v["evidence"] = []
                print(json.dumps(v, indent=2, default=str,
                                 ensure_ascii=False))
            elif act == "finding-history":
                v = cs_svc.finding_view(args.finding)
                if v is None:
                    print("[!] not found")
                    sys.exit(5)
                print(json.dumps(
                    {"observations": v["observations"],
                     "risk_history": v["risk_history"],
                     "reopened_at": v.get("reopened_at", "")},
                    indent=2, default=str, ensure_ascii=False))
            elif act == "finding-correlate":
                if ctx is not None:
                    authz.require_finding(ctx, args.finding)
                n = cs_svc.link_for(args.finding)
                print(f"[✓] {n} correlation link(s) current")
            else:
                snaps = svc.db.query(
                    "SELECT * FROM risk_snapshots WHERE finding_id=? "
                    "ORDER BY ts DESC LIMIT ?",
                    (args.finding, getattr(args, "limit", 100) or 100))
                if not snaps:
                    print("[!] no risk snapshots for this finding")
                    return
                for s in snaps:
                    print(f"   {s['ts']}  score={s['risk_score']} "
                          f"level={s['risk_level']} v={s['calc_version']} "
                          f"priority-linked conf={s['confidence']}")
            return
        if act in ("finding-false-positive", "finding-accept-risk"):
            need("finding.resolve" if act == "finding-false-positive"
                 else "finding.accept_risk")
            if ctx is not None:
                authz.require_finding(ctx, args.finding)
            import correlate as _cor
            cs_svc = _cor.CorrelationService(svc)
            until = getattr(args, "until", "") or ""
            if act == "finding-false-positive":
                out = cs_svc.false_positive(
                    args.finding, reason=args.reason, actor=_actor,
                    until=until, suppress=getattr(args, "suppress", False))
            else:
                out = cs_svc.accept_risk(
                    args.finding, reason=args.reason, actor=_actor,
                    until=until,
                    review_at=getattr(args, "review_at", "") or "")
            print(f"[✓] {json.dumps(out, default=str)}")
            return
        if act in ("cluster-list", "remediation-list", "graph-list",
                   "scan-diff", "priority-list"):
            need("finding.read" if act in ("cluster-list", "remediation-list",
                                           "graph-list", "priority-list")
                 else "scan.read")
            need_project(args.project)
            import correlate as _cor
            import diffs as _df
            cs_svc = _cor.CorrelationService(svc)
            if act == "cluster-list":
                rows = cs_svc.clusters(args.project,
                                       limit=getattr(args, "limit", 50) or 50)
                print(f"  {len(rows)} cluster(s)")
                for c in rows:
                    print(f"   {c['id'][:16]}  {c['cluster_type']:<10} "
                          f"risk={c['risk_score']} "
                          f"{c['risk_level']:<8} members={c['member_count']} "
                          f"{c['title'][:40]}")
            elif act == "remediation-list":
                rows = cs_svc.remediation_groups(
                    args.project, limit=getattr(args, "limit", 50) or 50)
                print(f"  {len(rows)} remediation group(s)")
                for g in rows:
                    print(f"   {g['id'][:16]}  {g['component']} "
                          f"findings={g['member_count']}")
            elif act == "graph-list":
                rows = cs_svc.graph_list(
                    args.project, limit=getattr(args, "limit", 100) or 100)
                print(f"  {len(rows)} edge(s)")
                for g in rows:
                    print(f"   {g['from_type']}:{g['from_id'][:12]} "
                          f"--{g['rel_type']}--> "
                          f"{g['to_type']}:{g['to_id'][:12]} "
                          f"conf={round(g['confidence'], 2)}")
            elif act == "priority-list":
                rows = cs_svc.prioritized(
                    args.project, limit=getattr(args, "limit", 50) or 50)
                for r in rows:
                    print(f"   {r['priority']}  risk={r['risk_score']:>3} "
                          f"{r['risk_level']:<8} {r['severity']:<8} "
                          f"{r['title'][:50]}")
            else:
                bs_svc = _df.BaselineService(svc)
                if getattr(args, "from_scan", "") or \
                        getattr(args, "to_scan", ""):
                    out = bs_svc.diff_between(
                        args.project,
                        getattr(args, "from_scan", "") or "",
                        getattr(args, "to_scan", "") or "",
                        actor=_actor)
                elif getattr(args, "scan", ""):
                    out = bs_svc.capture(args.project, args.scan,
                                         actor=_actor)
                else:
                    rows = bs_svc.diffs(args.project, limit=1)
                    out = (bs_svc.diff_get(rows[0]["id"]) if rows
                           else {"note": "no diffs yet"})
                print(json.dumps(out, indent=2, default=str,
                                 ensure_ascii=False))
            return
        if act in ("cluster-show", "scan-diff-get", "baseline-status"):
            need("finding.read" if act == "cluster-show" else "scan.read")
            import correlate as _cor
            import diffs as _df
            bs_svc = _df.BaselineService(svc)
            if act == "cluster-show":
                v = _cor.CorrelationService(svc).cluster_view(args.cluster)
                if v is None:
                    print("[!] not found")
                    sys.exit(5)
                print(json.dumps(v, indent=2, default=str,
                                 ensure_ascii=False))
            else:
                if act == "scan-diff-get":
                    out = bs_svc.diff_get(args.diff)
                else:
                    out = bs_svc.baseline_status(args.project)
                if out is None:
                    print("[!] not found")
                    sys.exit(5)
                print(json.dumps(out, indent=2, default=str,
                                 ensure_ascii=False))
            return
        if act in ("rebuild-intel",):
            need("finding.update")
            need_project(args.project)
            import correlate as _cor
            out = _cor.CorrelationService(svc).build_project_intel(
                args.project)
            print(f"[✓] {json.dumps(out, default=str)}")
            return
        if act in ("ingest",):
            need("scan.create")
            need_project(args.project)
            with open(args.json, encoding="utf-8") as fh:
                import json as _json
                raw = _json.load(fh)
            out = svc.register_scanner_result(args.project, raw)
            print(f"[✓] Ingested: scan={out['scan_id']} assets={out['assets']} "
                  f"findings={out['findings']}")
            return
        if act in ("audit",):
            need("audit.read")
            if ctx is not None:
                rows = authz.audit_visible_rows(ctx, ctx.org_id,
                                                getattr(args, "limit", 50) or 50)
            else:
                rows = svc.audit_list(getattr(args, "project", None),
                                      getattr(args, "limit", 50) or 50)
            print(f"  {len(rows)} audit event(s)")
            for e in rows:
                print(f"   {e.ts}  {e.action:<28} obj={e.object_type}/{e.object_id}")
            return
        if act in ("audit-verify",):
            need("audit.read")
            report = svc.audit_verify()
            if ctx is not None:
                # org-scoped caller: counts only (issue ids belong to the
                # global chain and are not disclosed across tenants)
                print(f"  chain ok       : {report['ok']}")
                print(f"  verified events: {report['verified']}")
                print(f"  legacy events  : {report['legacy']}")
                print(f"  total events   : {report['total']}")
                print(f"  issues         : {len(report['issues'])}")
            else:
                print(f"  chain ok       : {report['ok']}")
                print(f"  verified events: {report['verified']}")
                print(f"  legacy events  : {report['legacy']}")
                print(f"  total events   : {report['total']}")
                for issue in report["issues"]:
                    print(f"   ! {issue}")
            return
    except Exception as e:
        msg = getattr(e, "user_message", lambda: str(e))()
        print(f"[!] {msg}")
        sys.exit(getattr(e, "exit_code", 1))
    print("[!] Unknown platform action")
    sys.exit(2)


def _monitor_stack(args):
    """Shared Phase-5 stack: PlatformService + monitoring/alerts/notify/
    remediation services (+ RBAC context). Without --as: local mode."""
    sys.path.insert(0, PY)
    import platform_service as pf
    import scanners as _sc
    try:
        svc = pf.PlatformService(getattr(args, "db", None) or None)
    except Exception as e:
        print(f"[!] Platform init failed: "
              f"{getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 5))
    import monitor as _mon
    import alerts as _al
    import notify as _nt
    import remedy as _rm
    mon = _mon.MonitoringService(svc, registry=_sc.REGISTRY)
    sched = _mon.SchedulerService(svc, registry=_sc.REGISTRY)
    alerts = _al.AlertService(svc)
    notify = _nt.NotificationService(svc)
    remedy = _rm.RemediationService(svc, registry=_sc.REGISTRY)
    ctx, authz = None, None
    as_tok = getattr(args, "as_token", "") or ""
    if as_tok:
        import authz as _az
        import identity as _id
        authz = _az.AuthorizationService(svc, _id.IdentityService(svc))
        try:
            ctx = authz.context_from_secret(as_tok)
        except Exception as e:
            print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
            sys.exit(getattr(e, "exit_code", 10))
    return svc, mon, sched, alerts, notify, remedy, ctx, authz


def _visible_project_ids(svc, authz, ctx, project_id=""):
    """Tenant-safe project resolution: --project must be inside the
    caller's visible set (local mode: any)."""
    if ctx is None:
        return [project_id] if project_id else \
            [p.id for o in svc.org_list() for p in svc.project_list(o.id)]
    if project_id:
        authz.require_project(ctx, project_id)
        return [project_id]
    return [p.id for p in authz.visible_projects(ctx)]


# ---------------------------------------------------------------------------
# Phase 6 — reporting / analytics / compliance evidence CLI
# ---------------------------------------------------------------------------

def _report_stack(args):
    """Shared Phase-6 stack: PlatformService + RBAC context (local mode
    without --as; fail-closed with --as)."""
    sys.path.insert(0, PY)
    import platform_service as pf
    try:
        svc = pf.PlatformService(getattr(args, "db", None) or None)
    except Exception as e:
        print(f"[!] Platform init failed: "
              f"{getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 5))
    ctx, authz = None, None
    as_tok = getattr(args, "as_token", "") or ""
    if as_tok:
        import authz as _az
        import identity as _id
        authz = _az.AuthorizationService(svc, _id.IdentityService(svc))
        try:
            ctx = authz.context_from_secret(as_tok)
        except Exception as e:
            print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
            sys.exit(getattr(e, "exit_code", 10))
    return svc, ctx, authz


def _need_closures(ctx, authz):
    def need(perm):
        if ctx is not None:
            authz.require(ctx, perm)

    def need_org(org_id):
        if ctx is not None:
            authz.require_org(ctx, org_id)

    def need_project(project_id):
        if ctx is not None:
            authz.require_project(ctx, project_id)

    return need, need_org, need_project


def _report_open(svc):
    """Open the reporting + analytics + evidence services on one platform."""
    import reporting as _rp
    return _rp.ReportService(svc), _rp.EvidenceService(svc)


def _print_json(obj, limit=40):
    import json as _j
    txt = _j.dumps(obj, indent=2, default=str, ensure_ascii=False)
    lines = txt.splitlines()
    if len(lines) > limit:
        lines = lines[:limit] + [f"... ({len(lines) - limit} more line(s))"]
    print("\n".join(lines))


def cmd_report(args):
    """Phase 6: snapshot reports (generate/list/get/export/delete/share)."""
    svc, ctx, authz = _report_stack(args)
    need, need_org, need_project = _need_closures(ctx, authz)
    rsvc, _evs = _report_open(svc)
    act = args.action
    try:
        if act == "generate":
            need("report.generate")
            need_project(args.project)
            filters = {}
            for fld in ("asset_id", "severity", "status", "risk_min",
                        "risk_max", "exposure", "criticality", "technology",
                        "category", "start", "end"):
                v = getattr(args, fld, None)
                if v not in (None, "", []):
                    filters[fld] = v
            snap = rsvc.snapshot(args.project, args.type,
                                 title=args.title or "",
                                 generated_by=(ctx.label() if ctx
                                               else _actor()),
                                 data_cutoff=args.cutoff or "",
                                 filters=filters,
                                 store_payload=True)
            run = rsvc.store_run(snap, store_payload=True)
            print(f"[✓] Report generated: {run['id']}")
            print(f"    type       : {run['report_type']}")
            print(f"    hash       : {run['report_hash'][:32]}...")
            print(f"    cutoff     : {run['data_cutoff']}")
            print(f"    findings   : {run['included_count']} "
                  f"of {run['original_count']}"
                  + (" (truncated: " + run["truncation_reason"] + ")"
                     if run["truncated"] else ""))
            out = getattr(args, "out", "") or ""
            fmt = getattr(args, "format", "") or ""
            if out or fmt:
                fmt = (fmt or "json").lower()
                from reporting import file_name_for, secure_export_path
                target = secure_export_path(out or file_name_for(
                    run["id"], fmt))
                raw = rsvc.export(run["id"], fmt, out_path=target)
                print(f"    exported   : {target} ({len(raw)} bytes)")
            return
        if act == "list":
            need("report.read")
            pids = _visible_project_ids(svc, authz, ctx, args.project)
            for pid in pids:
                data = rsvc.list_runs(pid, limit=args.limit,
                                      offset=args.offset,
                                      report_type=args.type or "")
                print(f"  {data['count']} report(s) in {pid} "
                      f"({data['total']} total)")
                for r in data["reports"]:
                    print(f"   {r['id'][:12]}  {r['report_type']:<20} "
                          f"{str(r['title'])[:44]:<44} "
                          f"{r['generated_at'][:19]}  "
                          f"hash {r['report_hash'][:16]}")
            return
        if act == "get":
            need("report.read")
            run = rsvc.get_run(args.report, with_payload=True)
            meta = {k: run[k] for k in
                    ("id", "org_id", "project_id", "report_type", "title",
                     "status", "schema_version", "risk_version",
                     "data_cutoff", "report_hash", "generated_at",
                     "generated_by", "truncated", "truncation_reason",
                     "original_count", "included_count", "byte_size",
                     "immutable")}
            _print_json(meta)
            if args.payload and run.get("payload"):
                _print_json(run["payload"], limit=120)
            return
        if act == "export":
            need("report.export")
            run = rsvc.get_run(args.report)
            need_project(run["project_id"])
            from reporting import file_name_for, secure_export_path
            out = getattr(args, "out", "") or ""
            target = secure_export_path(out or file_name_for(
                args.report, args.format))
            raw = rsvc.export(args.report, args.format, out_path=target)
            print(f"[✓] Exported {len(raw)} bytes to {target}")
            return
        if act == "delete":
            need("report.generate")
            run = rsvc.get_run(args.report)
            need_project(run["project_id"])
            if run["immutable"]:
                print("[!] Immutable (evidence snapshot) reports are never "
                      "deleted by retention or users")
                sys.exit(errors_mod().ValidationError.exit_code)
            svc.audit("report.deleted", object_type="report",
                      object_id=run["id"], org_id=run["org_id"],
                      project_id=run["project_id"],
                      actor=(ctx.label() if ctx else _actor()),
                      metadata={"report_type": run["report_type"],
                                "report_hash": str(run["report_hash"])[:32]})
            with svc.db.transaction() as conn:
                conn.execute("DELETE FROM report_payloads WHERE report_id=?",
                             (run["id"],))
                conn.execute(
                    "DELETE FROM report_runs WHERE id=? AND immutable=0",
                    (run["id"],))
            print(f"[✓] Report deleted (audited): {run['id']}")
            return
        if act == "share":
            need("report.generate")
            run = rsvc.get_run(args.report)
            need_project(run["project_id"])
            # metadata-only share event: this platform has no external
            # sharing/storage — the event makes the intent auditable.
            svc.audit("report.shared", object_type="report",
                      object_id=run["id"], org_id=run["org_id"],
                      project_id=run["project_id"],
                      actor=(ctx.label() if ctx else _actor()),
                      metadata={"report_type": run["report_type"],
                                "note": str(getattr(args, "note", "")
                                            or "")[:200]})
            print("[✓] Share intent recorded (audit only — no external "
                  "sharing subsystem exists)")
            return
        if act == "retention-sweep":
            need("report.generate")
            res = rsvc.retention_sweep(days=args.days,
                                       project_id=args.project or "")
            print(f"[✓] Retention sweep: removed {res['removed']} "
                  f"non-immutable report(s) older than {res['days']}d "
                  f"(cutoff {res['cutoff'][:19]})")
            return
    except errors_mod().SecurityToolkitError as e:
        print(f"[!] {e.user_message()}")
        sys.exit(e.exit_code)
    print(f"[!] Unknown report action: {act}")
    sys.exit(2)


def cmd_analytics(args):
    """Phase 6: read-only security analytics (posture/KPIs/trends)."""
    svc, ctx, authz = _report_stack(args)
    need, need_org, need_project = _need_closures(ctx, authz)
    import analytics as _an
    an = _an.AnalyticsService(svc)
    act = args.action
    try:
        scope = {"project_id": args.project} if getattr(
            args, "project", None) else {}
        if act in ("posture", "kpis", "risk", "risk-assets", "risk-buckets",
                   "trends", "attack-surface", "remediation", "assets",
                   "monitoring", "bundle"):
            need("analytics.read")
            need_project(args.project)
        elif act == "risk-projects":
            need("analytics.read")
            org = getattr(args, "org", None) or (ctx.org_id if ctx else "")
            if not org:
                raise errors_mod().ValidationError("org_required")
            need_org(org)
        else:
            print(f"[!] Unknown analytics action: {act}")
            sys.exit(2)
        if act == "posture":
            _print_json(an.posture(args.project, cutoff=args.cutoff or ""))
        elif act == "kpis":
            _print_json(an.kpis(args.project, cutoff=args.cutoff or "",
                                start=args.start or "", end=args.end or ""))
        elif act == "risk":
            _print_json(an.risk_summary(args.project, cutoff=args.cutoff or
                                        ""))
        elif act == "risk-buckets":
            _print_json(an.risk_buckets(args.project, cutoff=args.cutoff or "",
                                        bucket_width=args.width))
        elif act == "risk-assets":
            _print_json(an.risk_by_asset(args.project,
                                         cutoff=args.cutoff or "",
                                         limit=args.limit))
        elif act == "risk-projects":
            _print_json(an.risk_by_project(org, cutoff=args.cutoff or "",
                                           limit=args.limit))
        elif act == "trends":
            out = {"findings": an.finding_trend(args.project,
                                                start=args.start or "",
                                                end=args.end or ""),
                   "assets": an.asset_trend(args.project,
                                            start=args.start or "",
                                            end=args.end or "")}
            _print_json(out)
        elif act == "attack-surface":
            _print_json(an.attack_surface_trend(args.project,
                                                start=args.start or "",
                                                end=args.end or ""))
        elif act == "remediation":
            _print_json(an.remediation_summary(args.project,
                                               cutoff=args.cutoff or ""))
        elif act == "assets":
            _print_json(an.asset_summary(args.project, cutoff=args.cutoff
                                         or ""))
        elif act == "monitoring":
            _print_json(an.monitoring_summary(args.project,
                                              cutoff=args.cutoff or ""))
        elif act == "bundle":
            _print_json(an.bundle(args.project, cutoff=args.cutoff or "",
                                  start=args.start or "", end=args.end or ""),
                        limit=200)
    except errors_mod().SecurityToolkitError as e:
        print(f"[!] {e.user_message()}")
        sys.exit(e.exit_code)


def cmd_evidence(args):
    """Phase 6: compliance evidence (generic categories; provenance kept)."""
    svc, ctx, authz = _report_stack(args)
    need, need_org, need_project = _need_closures(ctx, authz)
    _rsvc, evs = _report_open(svc)
    act = args.action
    try:
        if act == "refresh":
            need("compliance_evidence.read")
            need("report.generate")
            need_project(args.project)
            items = evs.refresh(args.project, cutoff=args.cutoff or "")
            print(f"[✓] Evidence registry refreshed: {len(items)} item(s)")
            for it in items:
                print(f"   [{it['status']}] {it['control_category']:<24}"
                      f" {it['source_type']:<24} {it['id'][:12]}  "
                      f"hash {it['evidence_hash'][:16]}")
            return
        if act == "list":
            need("compliance_evidence.read")
            need_project(args.project)
            data = evs.list_items(args.project, category=args.category or "",
                                  limit=args.limit, offset=args.offset)
            print(f"  {data['count']} item(s) ({data['total']} total)")
            for it in data["items"]:
                print(f"   [{it['status']}] {it['control_category']:<24}"
                      f" {it['source_type']:<24} {it['source_id'][:32]:<32}"
                      f" {str(it['data_cutoff'])[:19]}")
            return
        if act == "show":
            need("compliance_evidence.read")
            it = evs.get_item(args.evidence)
            _print_json(it)
            return
        if act == "snapshot":
            need("compliance_evidence.read")
            need("report.generate")
            need_project(args.project)
            import reporting as _rp
            run = evs.snapshot(args.project, generated_by=(
                ctx.label() if ctx else _actor()),
                cutoff=args.cutoff or "")
            print(f"[✓] Immutable evidence snapshot: {run['id']}")
            print(f"    hash       : {run['report_hash'][:32]}...")
            print(f"    evidence   : {run.get('evidence_count', 0)} item(s)")
            return
        if act == "export":
            need("compliance_evidence.read")
            need_project(args.project)
            from reporting import secure_export_path
            out = getattr(args, "out", "") or ""
            target = secure_export_path(out or f"evidence-{args.project[:12]}-"
                                        + (args.category or "all") + "." +
                                        (args.format or "json"))
            raw = evs.export_items(args.project, fmt=args.format or "json",
                                   category=args.category or "",
                                   out_path=target)
            print(f"[✓] Exported {len(raw)} bytes to {target}")
            return
    except errors_mod().SecurityToolkitError as e:
        print(f"[!] {e.user_message()}")
        sys.exit(e.exit_code)
    print(f"[!] Unknown evidence action: {act}")
    sys.exit(2)


def cmd_devsecops(args):
    """Phase 7: DevSecOps security gates & CI runs (extends platform)."""
    svc, ctx, authz = _report_stack(args)
    need, need_org, need_project = _need_closures(ctx, authz)
    import devsecops as _ds
    dso = _ds.DevSecOpsService(svc)
    act = args.action
    try:
        if act == "gate-create":
            need("devsecops.create")
            need_project(args.project)
            policy = json.loads(args.policy) if args.policy else {}
            g = dso.gate_create(args.project, args.name, policy,
                                created_by=(ctx.label() if ctx else _actor()),
                                actor=(ctx.label() if ctx else _actor()))
            print(f"[✓] Gate created: {g['id']}")
            print(f"    policy v{g['policy_version']} "
                  f"hash {g['policy_hash'][:16]}...")
            print(f"    conditions: {len(g['policy']['conditions'])}")
            return
        if act == "gate-list":
            need("devsecops.read")
            need_project(args.project)
            out = dso.gate_list(args.project, limit=args.limit,
                                offset=args.offset)
            print(f"  {out['count']} gate(s) ({out['total']} total)")
            for g in out["gates"]:
                print(f"   [{('on' if g['enabled'] else 'off')}] "
                      f"{g['name']:<32} v{g['policy_version']} "
                      f"{g['policy_hash'][:16]}")
            return
        if act == "gate-show":
            need("devsecops.read")
            authz.require_gate(ctx, args.gate) if ctx else None
            _print_json(dso.gate_get(args.gate), limit=60)
            return
        if act == "gate-update":
            need("devsecops.update")
            authz.require_gate(ctx, args.gate) if ctx else None
            policy = json.loads(args.policy) if getattr(args, "policy", "") \
                else None
            enabled = None
            if getattr(args, "enabled", "") in ("true", "false"):
                enabled = args.enabled == "true"
            g = dso.gate_update(
                args.gate, name=getattr(args, "name", "") or None,
                enabled=enabled, policy=policy,
                actor=(ctx.label() if ctx else _actor()))
            print(f"[✓] Gate updated: {g['id']} (v{g['policy_version']}, "
                  f"hash {g['policy_hash'][:16]}...)")
            return
        if act == "gate-delete":
            need("devsecops.delete")
            authz.require_gate(ctx, args.gate) if ctx else None
            out = dso.gate_delete(args.gate,
                                  actor=(ctx.label() if ctx else _actor()))
            print(f"[✓] Gate deleted (results kept): {out['deleted']}")
            return
        if act in ("ci-create", "run"):
            need("devsecops.run")
            need_project(args.project)
            out = dso.run_create(
                args.project, args.gate, args.profile,
                provider=args.provider or "generic",
                repository=args.repository or "",
                branch=args.branch or "",
                commit_sha=args.commit_sha or "",
                commit_ref=args.commit_ref or "",
                pipeline_id=args.pipeline_id or "",
                pipeline_url=args.pipeline_url or "",
                actor=args.actor or (ctx.label() if ctx else ""),
                trigger=args.trigger or "manual",
                target=args.target or "",
                run_key=args.run_key or "",
                active=bool(getattr(args, "active", False)),
                run_actor=(ctx.label() if ctx else _actor()))
            r = out["run"]
            print(f"[{'reused' if out['reused'] else 'created'}] CI run: "
                  f"{r['id']}")
            print(f"    scan: {out['scan_id']}"
                  + (f"  job: {out['job_id']}" if out["job_id"] else ""))
            print(f"    status: {r['status']}  gate: {r['gate_id'][:12]}...")
            return
        if act == "ci-list":
            need("devsecops.read")
            need_project(args.project)
            out = dso.ci_list(args.project, limit=args.limit,
                              offset=args.offset, status=args.status or "")
            print(f"  {out['count']} run(s) ({out['total']} total)")
            for r in out["runs"]:
                print(f"   [{r['status']:<10}] {r['provider']:<8} "
                      f"{r['id'][:18]}... {str(r.get('branch') or '')[:24]}")
            return
        if act in ("ci-show", "status"):
            need("devsecops.read")
            authz.require_ci_run(ctx, args.run) if ctx else None
            _print_json(dso.run_status(args.run), limit=80)
            return
        if act == "evaluate":
            need("devsecops.run")
            authz.require_ci_run(ctx, args.run) if ctx else None
            try:
                res = dso.evaluate(args.run,
                                   actor=(ctx.label() if ctx else _actor()))
            except errors_mod().PersistenceError as e:
                print(f"[!] {e.user_message()}")
                sys.exit(3)              # gate could not be evaluated
            _print_json(res, limit=80)
            # documented exit contract: 0 = pass/warn, 1 = fail,
            # 2 = inconclusive, 3 = evaluation system error
            sys.exit({"pass": 0, "warn": 0, "fail": 1,
                      "inconclusive": 2}[res["status"]])
            return
        if act == "result":
            need("devsecops.read")
            authz.require_gate_result(ctx, args.result) if ctx else None
            _print_json(dso.result_get(args.result), limit=80)
            return
        if act == "export":
            need("devsecops.export")
            authz.require_gate_result(ctx, args.result) if ctx else None
            from reporting import secure_export_path
            out = getattr(args, "out", "") or ""
            target = secure_export_path(
                out or f"gate-result-{args.result[:12]}.{args.format}")
            raw = dso.export_result(args.result, args.format, out_path=target,
                                    actor=(ctx.label() if ctx else _actor()))
            print(f"[✓] Exported {len(raw)} bytes to {target} "
                  f"({args.format})")
            return
        if act == "report":
            need("devsecops.read")
            need("report.generate")
            authz.require_gate_result(ctx, args.result) if ctx else None
            run = dso.ci_report(
                args.result, report_type=args.type or "technical",
                generated_by=(ctx.label() if ctx else _actor()))
            print(f"[✓] Report stored (Phase-6 engine): {run['id']}")
            print(f"    hash {run['report_hash'][:32]}...")
            return
        if act == "retention-sweep":
            need("devsecops.delete")
            out = dso.retention_sweep(
                args.days, project_id=getattr(args, "project", "") or "",
                actor=(ctx.label() if ctx else _actor()))
            print(f"[✓] Retention sweep: removed {out['removed']} CI "
                  f"run(s) older than {out['days']}d (cutoff "
                  f"{out['cutoff'][:19]}); gate results & audit untouched")
            return
    except errors_mod().SecurityToolkitError as e:
        print(f"[!] {e.user_message()}")
        sys.exit(e.exit_code)
    print(f"[!] Unknown devsecops action: {act}")
    sys.exit(2)


def cmd_monitor(args):
    """Phase 5: continuous monitoring, alerting, remediation, notifications.
    Every protected action goes through Phase-2 RBAC + tenant isolation
    (fail closed, generic errors, no secrets in output)."""
    svc, mon, sched, alerts, notify, remedy, ctx, authz = _monitor_stack(args)

    def need(perm):
        if ctx is not None:
            authz.require(ctx, perm)

    def need_project(project_id):
        if ctx is not None:
            authz.require_project(ctx, project_id)

    def need_policy(policy_id):
        if ctx is not None:
            authz.require_monitoring_policy(ctx, policy_id)

    def need_alert(alert_id):
        if ctx is not None:
            authz.require_alert(ctx, alert_id)

    def need_ticket(ticket_id):
        if ctx is not None:
            authz.require_remediation(ctx, ticket_id)

    def need_notification(notification_id):
        if ctx is not None:
            authz.require_notification(ctx, notification_id)

    act = args.action
    try:
        # ------------------------------------------------------ monitoring
        if act == "rules-install":
            need("monitoring.create")
            need_project(args.project)
            n = alerts.install_default_rules(args.project, actor=_actor())
            print(f"[✓] {n} default alert rule(s) installed for "
                  f"{args.project}")
            return
        if act == "policy-create":
            need("monitoring.create")
            need_project(args.project)
            pol = mon.create(
                args.project, args.name, scan_profile=args.profile,
                schedule_type=args.schedule, interval_minutes=args.interval,
                daily_time=args.daily_time or "08:00",
                weekly_day=args.weekly_day, weekly_time=args.weekly_time or
                "09:00", targets=args.target or [],
                active_scan_permitted=args.active,
                priority=args.priority, timeout_minutes=args.timeout,
                missed_policy=args.missed, max_concurrent=args.concurrent,
                actor=_actor())
            print(f"[✓] Monitoring policy: {pol['id']}")
            print(f"    profile : {pol['scan_profile']}  "
                  f"enabled: {bool(pol['enabled'])}")
            print(f"    schedule: {pol['schedule_type']}  "
                  f"next_run: {pol['next_run'] or '-'}")
            return
        if act == "policy-list":
            need("monitoring.read")
            pids = _visible_project_ids(svc, authz, ctx, args.project)
            limit = min(max(int(getattr(args, "limit", 50) or 50), 1), 200)
            rows = []
            for pid in pids:
                rows.extend(mon.list(pid))
            print(f"  {len(rows)} monitoring policy(ies)")
            for p in rows[:limit]:
                print(f"   {p['id'][:8]}  {'ON ' if p['enabled'] else 'OFF'} "
                      f"{p['name']:<24} {p['scan_profile']:<16} "
                      f"{p['schedule_type']:<9} "
                      f"next={p['next_run'] or '-'}")
            return
        if act == "policy-show":
            need("monitoring.read")
            need_policy(args.policy)
            p = mon.get(args.policy)
            print(f"  policy : {p['id']}  {p['name']}")
            print(f"  project: {p['project_id']}")
            print(f"  enabled: {bool(p['enabled'])}  profile: "
                  f"{p['scan_profile']}  priority: {p['priority']}")
            print(f"  schedule: {p['schedule_type']}  next_run: "
                  f"{p['next_run'] or '-'}  last_run: "
                  f"{p['last_run'] or '-'}")
            print(f"  targets: {', '.join(str(t)[:80] for t in p['targets'])}")
            print(f"  active_scan_permitted: {bool(p['active_scan_permitted'])}"
                  f"  missed: {p['missed_policy']}")
            return
        if act == "policy-enable":
            need("monitoring.update")
            need_policy(args.policy)
            mon.set_enabled(args.policy, True, actor=_actor())
            print(f"[✓] Enabling policy {args.policy[:8]}")
            return
        if act == "policy-disable":
            need("monitoring.update")
            need_policy(args.policy)
            mon.set_enabled(args.policy, False, actor=_actor())
            print(f"[✓] Disabling policy {args.policy[:8]}")
            return
        if act == "policy-delete":
            need("monitoring.delete")
            need_policy(args.policy)
            mon.delete(args.policy, actor=_actor())
            print(f"[✓] Deleted policy {args.policy[:8]}")
            return
        if act == "run":
            need("monitoring.run")
            need_policy(args.policy)
            res = sched.run_now(args.policy, actor=_actor())
            print(f"  run status: {res['status']}"
                  + (f"  reason: {res['reason']}" if res.get("reason") else ""))
            return
        if act == "tick":
            need("monitoring.run")
            res = sched.run_due()
            print(f"  scans created: {res['scans_created']}  "
                  f"skipped: {res['skipped']}  missed: "
                  f"{res['missed_events']}")
            return
        if act == "health":
            need("monitoring.read")
            pids = _visible_project_ids(svc, authz, ctx,
                                        getattr(args, "project", "") or "")
            for pid in pids:
                h = mon_health(svc).compute(pid)
                print(f"  {pid[:8]}  {h['health']:<10} score={h['score']:.1f}")
            return
        # ---------------------------------------------------------- alerts
        if act == "alert-list":
            need("alert.read")
            pids = _visible_project_ids(svc, authz, ctx,
                                        getattr(args, "project", "") or "")
            limit = min(max(int(getattr(args, "limit", 50) or 50), 1), 200)
            rows = []
            for pid in pids:
                rows.extend(alerts.list_alerts(
                    pid, state=getattr(args, "state", "") or "",
                    limit=limit))
            print(f"  {len(rows)} alert(s)")
            for a in rows[:limit]:
                print(f"   {a['id'][:8]}  {a['state']:<14} "
                      f"{a['severity']:<8} {a['event_type']:<24} "
                      f"x{a['occurrence_count']}  {str(a['title'])[:50]}")
            return
        if act == "alert-show":
            need("alert.read")
            need_alert(args.alert)
            a = alerts.alert_view(args.alert)
            print(f"  alert : {a['id']}  {a['title']}")
            print(f"  state : {a['state']}  severity: {a['severity']}  "
                  f"occ: {a['occurrence_count']}")
            print(f"  rule  : {a['rule_id']}  event: {a['event_type']}")
            print(f"  first : {a['first_seen']}  last: {a['last_seen']}")
            for h in alerts.history(args.alert, limit=10):
                print(f"   {h['ts']}  {h['action']:<22} "
                      f"{str(h.get('reason', ''))[:60]}")
            return
        if act == "alert-ack":
            need("alert.update")
            need_alert(args.alert)
            alerts.ack(args.alert, actor=_actor(), reason=args.reason)
            print(f"[✓] Alert {args.alert[:8]} acknowledged")
            return
        if act == "alert-resolve":
            need("alert.update")
            need_alert(args.alert)
            alerts.resolve(args.alert, actor=_actor(), reason=args.reason)
            print(f"[✓] Alert {args.alert[:8]} resolved")
            return
        if act == "alert-suppress":
            need("alert.suppress")
            need_alert(args.alert)
            alerts.suppress(args.alert, actor=_actor(), reason=args.reason,
                            until=args.until)
            print(f"[✓] Alert {args.alert[:8]} suppressed until {args.until}")
            return
        # ---------------------------------------------------- remediation
        if act == "remediation-list":
            need("remediation.read")
            pids = _visible_project_ids(svc, authz, ctx,
                                        getattr(args, "project", "") or "")
            limit = min(max(int(getattr(args, "limit", 50) or 50), 1), 200)
            rows = []
            for pid in pids:
                rows.extend(remedy.list_tickets(
                    pid, status=getattr(args, "status", "") or "",
                    limit=limit))
            print(f"  {len(rows)} remediation ticket(s)")
            for t in rows[:limit]:
                print(f"   {t['id'][:8]}  {t['status']:<24} "
                      f"{t['priority']:<3} due={t['due_at'] or '-'}  "
                      f"v={t.get('verification_status', '')}")
            return
        if act == "remediation-show":
            need("remediation.read")
            need_ticket(args.ticket)
            t = remedy.view(args.ticket)
            print(f"  ticket: {t['id']}  {t['status']}  "
                  f"priority {t['priority']}  due {t['due_at'] or '-'}")
            print(f"  finding: {t['finding_id']}  owner: "
                  f"{t.get('owner_name', '') or '-'}")
            print(f"  verification: {t.get('verification_status', '')} "
                  f"attempts {t.get('verification_attempts', 0)}  "
                  f"scan {t.get('verification_scan_id', '')[:8]}")
            for h in t.get("history", [])[:10]:
                print(f"   {h['ts']}  {h['action']:<24} "
                      f"{str(h.get('detail', {}))[:60]}")
            return
        if act == "remediation-assign":
            need("remediation.assign")
            need_ticket(args.ticket)
            remedy.assign(args.ticket, args.type, args.user, actor=_actor())
            print(f"[✓] Ticket {args.ticket[:8]} assigned")
            return
        if act == "remediation-status":
            need("remediation.update")
            need_ticket(args.ticket)
            remedy.status(args.ticket, args.status, actor=_actor(),
                          reason=args.reason)
            print(f"[✓] Ticket {args.ticket[:8]} → {args.status}")
            return
        if act == "remediation-verify":
            need("remediation.verify")
            need_ticket(args.ticket)
            v = remedy.request_verification(args.ticket, actor=_actor())
            print(f"[✓] Verification queued: scan {v['verification_scan_id']}")
            return
        if act == "sla-set":
            need("remediation.update")
            need_project(args.project)
            sla = remedy.sla_set(args.project, priority=args.priority,
                                 hours=args.hours, actor=_actor())
            print(f"[✓] SLA updated: {args.priority} = {args.hours}h")
            return
        # ---------------------------------------------------- notifications
        if act == "notification-list":
            need("notification.read")
            pids = _visible_project_ids(svc, authz, ctx,
                                        getattr(args, "project", "") or "")
            limit = min(max(int(getattr(args, "limit", 50) or 50), 1), 200)
            rows = []
            for pid in pids:
                rows.extend(notify.list_notifications(
                    pid, status=getattr(args, "status", "") or "",
                    limit=limit))
            print(f"  {len(rows)} notification(s)")
            for n in rows[:limit]:
                print(f"   {n['id'][:8]}  {n['channel']:<10} "
                      f"{n['status']:<12} attempts={n['attempts']}  "
                      f"{n.get('error', '')[:50]}")
            return
        if act == "notification-retry":
            need("notification.retry")
            need_notification(args.notification)
            n = notify.retry_manual(args.notification, actor=_actor())
            print(f"[✓] Notification {args.notification[:8]} → {n['status']}")
            return
        if act == "settings-show":
            need("notification.read")
            need_project(args.project)
            s = notify.settings_view(args.project)
            print(f"  email enabled: {s['email_enabled']}  to: "
                  f"{s['email_to'] or '-'}")
            print(f"  webhook enabled: {s['webhook_enabled']}  url: "
                  f"{s['webhook_url'][:60] or '-'}  has_secret: "
                  f"{s['has_secret']}")
            return
        if act == "settings-set":
            need("notification.update")
            need_project(args.project)
            notify.settings_set(
                args.project, email_enabled=args.email_enabled,
                email_to=args.email_to or "",
                webhook_enabled=args.webhook_enabled,
                webhook_url=args.webhook_url or "",
                webhook_secret=args.webhook_secret or "",
                keep_secret=bool(getattr(args, "keep_secret", False)),
                actor=_actor())
            print(f"[✓] Notification settings updated for {args.project}")
            return
        if act == "sweep":
            need("monitoring.delete")
            n = retention_sweep_cmd(svc, args)
            print(f"[✓] Retention sweep removed {n} row(s)")
            return
    except Exception as e:
        msg = getattr(e, "user_message", lambda: str(e))()
        print(f"[!] {msg}")
        sys.exit(getattr(e, "exit_code", 1))
    print("[!] Unknown monitoring action")
    sys.exit(2)


def mon_health(svc):
    import monitor as _mon
    return _mon.MonitoringHealthService(svc)


def retention_sweep_cmd(svc, args):
    import monitor as _mon
    counts = _mon.retention_sweep(
        svc, project_id=getattr(args, "project", "") or "",
        event_days=getattr(args, "event_days", 180),
        attempt_days=getattr(args, "attempt_days", 90),
        exec_days=getattr(args, "exec_days", 365),
        actor=_actor())
    return sum(counts.values())


def _actor():
    import os as _os
    return _os.environ.get("SECTOOLKIT_ACTOR", "cli")


def _job_stack(args):
    """Shared PlatformService + JobService (+ RBAC context) for Phase 3 CLI."""
    sys.path.insert(0, PY)
    import jobs as _jobs
    import platform_service as pf
    import scanners as _sc
    try:
        svc = pf.PlatformService(getattr(args, "db", None) or None)
    except Exception as e:
        print(f"[!] Platform init failed: "
              f"{getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 5))
    jsvc = _jobs.JobService(svc, _sc.REGISTRY)
    ctx, authz = None, None
    as_tok = getattr(args, "as_token", "") or ""
    if as_tok:
        import authz as _az
        import identity as _id
        authz = _az.AuthorizationService(svc, _id.IdentityService(svc))
        try:
            ctx = authz.context_from_secret(as_tok)
        except Exception as e:
            print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
            sys.exit(getattr(e, "exit_code", 10))
    return svc, jsvc, ctx, authz


def cmd_scan_job(args):
    """Phase 3: persistent job queue (create/list/status/pause/resume/
    cancel/retry) — every protected action goes through the Phase-2 RBAC +
    tenant-isolation layer (fail closed, generic errors)."""
    svc, jsvc, ctx, authz = _job_stack(args)

    def need(perm):
        if ctx is not None:
            authz.require(ctx, perm)

    def need_project(project_id):
        if ctx is not None:
            authz.require_project(ctx, project_id)

    def need_scan(scan_id):
        if ctx is not None:
            authz.require_scan(ctx, scan_id)

    act = args.action
    try:
        if act == "create":
            need("scan.create")
            need_project(args.project)
            payload = {}
            if args.target:
                payload["target"] = args.target
            if args.param:
                payload["param"] = args.param
            if args.limit:
                payload["limit"] = int(args.limit)
            if args.depth:
                payload["depth"] = int(args.depth)
            if args.bucket:
                payload["bucket"] = args.bucket
            if args.service:
                payload["service"] = args.service
            if args.threads:
                payload["threads"] = int(args.threads)
            if args.max:
                payload["max"] = int(args.max)
            job = jsvc.create_job(
                args.scan, args.profile, payload,
                priority=args.priority,
                active_enabled=bool(args.active),
                max_attempts=int(args.attempts),
                timeout_seconds=int(args.timeout),
                actor_id=(ctx.user_id if ctx else "cli"),
                actor=(ctx.label() if ctx else "cli"))
            print(f"[✓] Job created+queued: {job.id}")
            print(f"    scan={job.scan_id}  profile={job.profile}  "
                  f"priority={args.priority}  active={job.active_enabled}  "
                  f"max_attempts={job.max_attempts}")
            return
        if act == "list":
            need("scan.read")
            if ctx is not None and args.project:
                need_project(args.project)
            jobs = jsvc.job_list(project_id=args.project or None,
                                 org_id=(ctx.org_id if ctx else None),
                                 status=args.status or None,
                                 limit=args.limit)
            print(f"  {len(jobs)} job(s)")
            for j in jobs:
                print(f"   {j.id}  {j.profile:<14} {j.status:<10} "
                      f"att={j.attempt}/{j.max_attempts}  "
                      f"prio={j.priority}  {j.created_at}"
                      + (f"  err={j.error_code}" if j.error_code else ""))
            return
        if act == "status":
            need("scan.read")
            job = jsvc.job_get(args.job)
            need_scan(job.scan_id)
            print(f"Job {job.id}")
            print(f"  scan       : {job.scan_id}")
            print(f"  profile    : {job.profile}")
            print(f"  status     : {job.status}  "
                  f"(attempt {job.attempt}/{job.max_attempts})")
            print(f"  priority   : {job.priority}  active={job.active_enabled}"
                  + (f"  worker={job.worker_id}" if job.worker_id else ""))
            print(f"  created    : {job.created_at}")
            if job.started_at:
                print(f"  started    : {job.started_at}")
            if job.finished_at:
                print(f"  finished   : {job.finished_at}")
            if job.error_code:
                print(f"  error      : {job.error_code} — {job.error_message}")
            stages = svc.scan_stage_list(job.scan_id)
            if stages:
                print("  stages:")
                for s in stages:
                    print(f"   - {s.stage:<16} {s.status:<10} "
                          f"att={s.attempt}"
                          + (f"  err={s.error_code}" if s.error_code else ""))
            return
        if act == "pause":
            need("scan.pause")
            job = jsvc.job_get(args.job)
            need_scan(job.scan_id)
            j = jsvc.pause(args.job, actor=f"cli:{ctx.label() if ctx else 'local'}")
            print(f"[✓] Job pause requested: {j.id} → {j.status}")
            print("    (honest semantics: the running stage completes; the "
                  "next stage will not start)")
            return
        if act == "resume":
            need("scan.start")
            job = jsvc.job_get(args.job)
            need_scan(job.scan_id)
            j = jsvc.resume(args.job, actor=f"cli:{ctx.label() if ctx else 'local'}")
            print(f"[✓] Job resumed: {j.id} → {j.status} (queued again)")
            return
        if act == "cancel":
            need("scan.cancel")
            job = jsvc.job_get(args.job)
            need_scan(job.scan_id)
            j = jsvc.cancel(args.job, actor=f"cli:{ctx.label() if ctx else 'local'}")
            if j.status == "cancelled":
                print(f"[✓] Job already cancelled: {j.id}")
            else:
                print(f"[✓] Cancel requested: {j.id} → {j.status} "
                      "(worker stops at the next safe checkpoint)")
            return
        if act == "retry":
            need("scan.start")
            job = jsvc.job_get(args.job)
            need_scan(job.scan_id)
            j = jsvc.retry_manual(args.job,
                                  actor=f"cli:{ctx.label() if ctx else 'local'}")
            print(f"[✓] Job retried: {j.id} → {j.status} (attempts reset)")
            return
    except Exception as e:
        msg = getattr(e, "user_message", lambda: str(e))()
        print(f"[!] {msg}")
        sys.exit(getattr(e, "exit_code", 1))
    print("[!] Unknown scan-job action")
    sys.exit(2)


def cmd_scan_worker(args):
    """Phase 3 worker runtime: `run` executes queued jobs (local-process
    boundary), `status` reports workers/jobs/metrics without host secrets."""
    svc, jsvc, ctx, authz = _job_stack(args)

    def need(perm):
        if ctx is not None:
            authz.require(ctx, perm)

    try:
        if args.action == "run":
            need("scan.start")
            import identity as _id
            import models as _m
            import worker as _wk
            id_svc = _id.IdentityService(svc)
            # execution-time actor reauthorization only applies in RBAC mode
            # (--as): local single-user mode has no named actor to validate
            worker = _wk.WorkerRuntime(
                svc, id_svc, jsvc, _sc_registry(),
                worker_id=args.worker_id or "",
                heartbeat_interval=float(args.heartbeat or 15.0),
                actor_check=(_actor_checker(id_svc) if ctx else None))
            mode = "one job" if args.once else "continuous"
            print(f"[*] Worker {worker.worker_id} starting ({mode}) — "
                  "Ctrl+C to stop")
            try:
                worker.run_forever(max_jobs=int(args.once or 0))
            except KeyboardInterrupt:
                worker.stop()
                svc.db.execute(
                    "UPDATE workers SET status='stopped', stopped_at=? "
                    "WHERE id=?", (_m.utcnow(), worker.worker_id))
                print("[✓] Worker stopped (Ctrl+C)")
            else:
                if args.once:
                    print("[✓] Worker stopped (finished)")
            return
        if args.action == "status":
            need("scan.read")
            import worker as _wkm
            rows = svc.db.query(
                "SELECT * FROM workers ORDER BY last_heartbeat DESC "
                "LIMIT 20")
            print(f"  {len(rows)} worker(s) (local process registry)")
            for w in rows:
                # expired heartbeat is NEVER reported as healthy
                health = _wkm.worker_health(w["last_heartbeat"], w["status"])
                print(f"   {w['id']}  health={health:<9}"
                      f" started={w['started_at']}"
                      f"  last_hb={w['last_heartbeat']}"
                      + (f"  stopped={w['stopped_at']}"
                         if w["stopped_at"] else ""))
            counts = svc.db.query(
                "SELECT status, COUNT(*) AS n FROM jobs GROUP BY status")
            print("  jobs by status:")
            for c in counts:
                print(f"   {c['status']:<12} {c['n']}")
            import metrics as _m
            snap = _m.snapshot()
            print("  counters:", {k: v for k, v in
                                  snap["counters"].items() if v})
            print("  durations:", {k: round(v, 2) for k, v in
                                   snap["durations"].items() if v})
            return
    except Exception as e:
        msg = getattr(e, "user_message", lambda: str(e))()
        print(f"[!] {msg}")
        sys.exit(getattr(e, "exit_code", 1))
    print("[!] Unknown scan-worker action")
    sys.exit(2)


def _sc_registry():
    import scanners as _sc
    return _sc.REGISTRY


def _SCANNER_PROFILES():
    """Static allowlist used at argparse time (scanner registry is dynamic
    only in the sense of the loaded module — never user-defined)."""
    return sorted(_sc_registry().PROFILES.keys())


def _actor_checker(id_svc):
    """Execution-time actor reauthorization: the user who created the job
    must still exist and be active. Returns (ok, reason). Sentinels used in
    local mode ('cli', '') are not user ids and pass by definition."""
    if id_svc is None:
        return None

    def check(user_id: str):
        if user_id in ("", "cli", "system", "anonymous"):
            return True, "local sentinel actor"
        try:
            u = id_svc.user_get(user_id)
        except Exception:
            return False, "user deleted"
        if getattr(u, "status", "") != "active":
            return False, f"user not active ({getattr(u, 'status', '?')})"
        return True, ""
    return check


def _auth_stack(args):
    """Shared IdentityService (+ optional AuthorizationService) per command."""
    sys.path.insert(0, PY)
    import identity as _id
    import platform_service as pf
    try:
        svc = pf.PlatformService(getattr(args, "db", None) or None)
    except Exception as e:
        print(f"[!] Platform init failed: {getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 5))
    return svc, _id.IdentityService(svc)


def _read_secret(flag_value, *, env_name="SECTOOLKIT_PASSWORD"):
    """Password entry: --password flag, else env var, else interactive prompt.
    Never echoes; never logs."""
    import os as _os
    if flag_value:
        return flag_value
    val = _os.environ.get(env_name)
    if val:
        return val
    if sys.stdin is not None and _os.isatty(sys.stdin.fileno()):
        import getpass
        return getpass.getpass("Password: ")
    print(f"[!] No password supplied (use --password or {env_name})")
    sys.exit(2)


def cmd_security(args):
    """Phase 10 security operations: attack surface, threat intel, cases.

    Sub-actions: attack-surface scan|list, observations, domains,
    certificates, ti add|list|update|revoke|import|match|export|source-list,
    case create|list|show|update|assign|close|timeline, threat clusters|
    prioritize. Local mode (no --as) = platform-local; --as TOKEN enforces
    the Phase-10 RBAC permissions (fail closed)."""
    sys.path.insert(0, PY)
    import json as _json
    import platform_service as pf
    import security_operations as so
    import errors as _err
    try:
        svc = pf.PlatformService(getattr(args, "db", None) or None)
    except Exception as e:
        print(f"[!] Platform init failed: "
              f"{getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 5))
    ctx, authz = None, None
    as_tok = getattr(args, "as_token", "") or ""
    if as_tok:
        import authz as _az
        import identity as _id
        id_svc = _id.IdentityService(svc)
        authz = _az.AuthorizationService(svc, id_svc)
        try:
            ctx = authz.context_from_secret(as_tok)
        except Exception as e:
            print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
            sys.exit(getattr(e, "exit_code", 10))

    def need(perm):
        if ctx is not None:
            authz.require(ctx, perm)

    def need_org(org_id):
        if ctx is not None:
            authz.require_org(ctx, org_id)

    def need_project(project_id):
        if ctx is not None:
            authz.require_project(ctx, project_id)

    ops = so.SecurityOperations(svc)
    act = getattr(args, "action", "")
    sub = getattr(args, "sub", "")
    # Phase 11 governance families (data / secrets / privacy / compliance)
    if act in ("data", "secrets", "privacy", "compliance"):
        sys.path.insert(0, PY)
        return _cmd_gov(args, svc, ctx, authz, act)
    # Phase 12 federation / evidence exchange / bulk / integrations
    if act == "federation":
        sys.path.insert(0, PY)
        return _cmd_fed(args, svc, ctx, authz)
    try:
        # --------------------------------------------------- attack surface
        if act == "attack-surface" and sub == "scan":
            need("attack_surface.scan"); need_project(args.project)
            entries = []
            if getattr(args, "file", ""):
                with open(args.file, "r", encoding="utf-8") as fh:
                    data = _json.load(fh)
                entries = data if isinstance(data, list) else \
                    data.get("entries", [])
            elif getattr(args, "entries", ""):
                entries = _json.loads(args.entries)
            if not entries:
                print("[!] Provide --file (JSON list) or --entries JSON")
                sys.exit(2)
            r = ops.surface.ingest(args.org, args.project, entries=entries,
                                   source=getattr(args, "source", "cli"),
                                   actor=str(ctx.label() if ctx else "cli"))
            print(f"[✓] Attack-surface scan: accepted={r['accepted']} "
                  f"rejected={r['rejected']} observed={r['observed']}")
            for e in r["errors"][:10]:
                print(f"    ! {e}")
            return
        if act == "attack-surface" and sub == "list":
            need("attack_surface.read"); need_project(args.project)
            inv = ops.surface.inventory(args.org, args.project,
                                        asset_type=getattr(args, "type", ""))
            for a in inv["assets"]:
                print(f"  {a['asset_type']:12s} {a['value']}")
            print(f"[✓] {inv['count']} assets")
            return
        if act == "observations":
            need("attack_surface.read"); need_project(args.project)
            for r in ops.surface.exposure_changes(args.org, args.project,
                                                  limit=50):
                print(f"  {r['ts']}  {r['event_type']}  asset={r['asset_id'][:12]}")
            return
        if act == "domains":
            need("attack_surface.read"); need_project(args.project)
            inv = ops.surface.inventory(args.org, args.project)
            for a in inv["assets"]:
                if a["asset_type"] in ("domain", "subdomain", "hostname"):
                    print(f"  {a['asset_type']:10s} {a['value']}")
            return
        if act == "certificates":
            need("attack_surface.read"); need_project(args.project)
            inv = ops.surface.inventory(args.org, args.project,
                                        asset_type="certificate")
            for a in inv["assets"]:
                print(f"  cert {a['value'][:40]}  seen={a['last_seen']}")
            return
        # --------------------------------------------------- threat intel
        if act == "ti" and sub == "add":
            need("threat_intel.create"); need_org(args.org)
            i = ops.iocs.add(args.org, args.value,
                             ioc_type=getattr(args, "type", None),
                             source=getattr(args, "source", "manual"),
                             confidence_level=getattr(args, "confidence",
                                                      "medium"),
                             valid_until=getattr(args, "valid_until", ""))
            print(f"[✓] IOC: {i['indicator']} ({i['ioc_type']}) "
                  f"{i['confidence_level']} source={i['source']}")
            return
        if act == "ti" and sub in ("list", "indicators"):
            need("threat_intel.read"); need_org(args.org)
            for i in ops.iocs.list(
                    args.org, ioc_type=getattr(args, "type", ""),
                    status=getattr(args, "status", ""),
                    limit=getattr(args, "limit", 100)):
                print(f"  {i['indicator']:48s} {i['ioc_type']:14s} "
                      f"{i['confidence_level']:8s} {i['status']}")
            return
        if act == "ti" and sub == "update":
            need("threat_intel.create"); need_org(args.org)
            i = ops.iocs.update(args.org, args.id,
                                confidence_level=getattr(args, "confidence",
                                                         None),
                                status=getattr(args, "status", None),
                                valid_until=getattr(args, "valid_until",
                                                    None),
                                reference=getattr(args, "reference", None))
            print(f"[✓] IOC updated: {i['indicator']} status={i['status']}")
            return
        if act == "ti" and sub == "revoke":
            need("threat_intel.create"); need_org(args.org)
            i = ops.iocs.revoke(args.org, args.id, reason=args.reason)
            print(f"[✓] IOC revoked: {i['indicator']}")
            return
        if act == "ti" and sub == "import":
            need("threat_intel.import"); need_org(args.org)
            with open(args.file, "r", encoding="utf-8") as fh:
                data = fh.read()
            r = ops.iocs.import_feed(args.org, name=args.name, data=data,
                                     fmt=getattr(args, "fmt", "auto"),
                                     source_type=getattr(args, "source_type",
                                                         "feed"),
                                     confidence_level=getattr(
                                         args, "confidence", "medium"),
                                     actor=str(ctx.label() if ctx else "cli"))
            print(f"[✓] Feed '{r['feed']}' ({r['format']}): "
                  f"imported={r['imported']} skipped={r['skipped']}")
            for e in r["errors"][:10]:
                print(f"    ! {e}")
            return
        if act == "ti" and sub == "match":
            need("threat_intel.create"); need_org(args.org)
            need_project(args.project)
            m = ops.correlation.match(args.org, args.project,
                                      min_confidence=getattr(
                                          args, "min_confidence", "low"))
            print(f"[✓] IOC match: iocs={m['iocs_evaluated']} "
                  f"new={m['new_matches']} existing={m['existing_matches']} "
                  f"findings={m['findings_created']}")
            return
        if act == "ti" and sub == "export":
            need("threat_intel.export"); need_org(args.org)
            ex = ops.iocs.export(args.org, ioc_type=getattr(args, "type", ""),
                                 status=getattr(args, "status", ""),
                                 limit=getattr(args, "limit", 500))
            out = getattr(args, "out", "") or "-"
            blob = _json.dumps(ex, indent=2)
            if out == "-":
                print(blob)
            else:
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(blob)
                print(f"[✓] Export written: {out} "
                      f"({ex['count']} indicators)")
            return
        if act == "ti" and sub == "source-list":
            need("threat_intel.read"); need_org(args.org)
            for s in ops.iocs.sources(args.org):
                print(f"  {s['source']:24s} count={s['n']} "
                      f"last={s['last_seen']}")
            return
        # ----------------------------------------------------------- cases
        if act == "case" and sub == "create":
            need("cases.create"); need_project(args.project)
            c = ops.cases.create(args.org, args.project, title=args.title,
                                 description=getattr(args, "description", ""),
                                 priority=getattr(args, "priority", "medium"),
                                 owner=getattr(args, "owner", ""),
                                 actor=str(ctx.label() if ctx else "cli"))
            print(f"[✓] Case: {c['id']}  {c['title']}  "
                  f"priority={c['priority']}")
            return
        if act == "case" and sub == "list":
            need("cases.read"); need_org(args.org)
            for c in ops.cases.list(args.org,
                                    project_id=getattr(args, "project", ""),
                                    status=getattr(args, "status", ""),
                                    limit=getattr(args, "limit", 100)):
                print(f"  {c['id'][:12]} {c['status']:12s} "
                      f"{c['priority']:8s} {c['title'][:44]}")
            return
        if act == "case" and sub == "show":
            need("cases.read"); need_org(args.org)
            c = ops.cases.get(args.org, args.id)
            print(f"  {c['title']}  [{c['status']}] prio={c['priority']} "
                  f"owner={c['owner'] or '-'}")
            print(f"  created={c['created_at']} updated={c['updated_at']} "
                  f"closed={c['closed_at'] or '-'}")
            for r in c["refs"]:
                print(f"    ref {r['ref_type']}:{r['ref_id']}")
            return
        if act == "case" and sub == "update":
            need("cases.update"); need_org(args.org)
            c = ops.cases.update(
                args.org, args.id, title=getattr(args, "title", None),
                description=getattr(args, "description", None),
                priority=getattr(args, "priority", None),
                actor=str(ctx.label() if ctx else "cli"))
            print(f"[✓] Case updated: {c['id']} status={c['status']}")
            return
        if act == "case" and sub == "assign":
            need("cases.assign"); need_org(args.org)
            c = ops.cases.assign(args.org, args.id, owner=args.owner,
                                 actor=str(ctx.label() if ctx else "cli"))
            print(f"[✓] Case assigned: {c['id']} → {c['owner']}")
            return
        if act == "case" and sub == "close":
            need("cases.close"); need_org(args.org)
            c = ops.cases.close(args.org, args.id, reason=args.reason,
                                actor=str(ctx.label() if ctx else "cli"))
            print(f"[✓] Case closed: {c['id']}")
            return
        if act == "case" and sub == "timeline":
            need("cases.read"); need_org(args.org)
            for t in ops.cases.timeline(args.org, args.id,
                                        limit=getattr(args, "limit", 100)):
                print(f"  {t['ts']}  {t['entry_type']:22s} {t['entry']}")
            return
        # ---------------------------------------------------------- threat
        if act == "threat" and sub == "clusters":
            need("threat_intel.read"); need_org(args.org)
            for c in ops.clusters.list(args.org,
                                       project_id=getattr(args, "project",
                                                          "")):
                print(f"  {c['label']:28s} members={c['member_count']} "
                      f"last={c['last_seen']}")
            return
        if act == "threat" and sub == "prioritize":
            need("threat_intel.read"); need_org(args.org)
            need_project(args.project)
            for p in ops.prioritization.prioritize(args.org, args.project):
                print(f"  P{p['priority']} risk={p['risk_score']:6.2f} "
                      f"{p['rule_id']:18s} {p['indicator'][:36]}")
            return
        print(f"[!] Unknown security action: {act} {sub}")
        sys.exit(2)
    except Exception as e:
        print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 5))


def _cmd_gov(args, svc, ctx, authz, act):
    """Phase-11 governance CLI: `security data|secrets|privacy|compliance`.
    Local mode = platform-local; --as TOKEN enforces the Phase-11 RBAC
    permissions (fail closed, monotonic tiers). Secret values, search
    hashes and subject references are never printed."""
    import errors as _err

    def need(perm):
        if ctx is not None:
            authz.require(ctx, perm)

    def need_org(org_id):
        if ctx is not None:
            authz.require_org(ctx, org_id)

    def need_project(project_id):
        if ctx is not None:
            authz.require_project(ctx, project_id)

    def actor():
        return str(ctx.label() if ctx else "cli")

    def fail(e):
        print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, 'exit_code', 10))

    import data_governance as _gov
    import privacy as _priv
    import compliance_governance as _cg
    g = _gov.SecurityGovernance(svc)
    sub = getattr(args, "sub", "")
    try:
        # ----------------------------------------------------------------- data
        if act == "data" and sub == "classify":
            need("data.classify")
            if getattr(args, "authorized", False):
                need("data.downgrade")
            r = g.classification.classify(
                args.org, args.object_type, object_id=args.object_id,
                classification=args.classification, field_name=args.field,
                project_id=args.project, authorized=bool(
                    getattr(args, "authorized", False)), actor=actor())
            print(f"[✓] {r['effective']} (rank {r['rank']}, "
                  f"{r['provenance']})")
            return
        if act == "data" and sub == "classifications":
            need("data.classifications.view"); need_org(args.org)
            r = g.classification.list(args.org, object_type=args.object_type,
                                      limit=args.limit)
            for it in r["items"]:
                print(f"  {it['object_type']:16s} "
                      f"{str(it['object_id'])[:32]:32s} "
                      f"{it['classification']}")
            print(f"[✓] {r['total']} classifications")
            return
        if act == "data" and sub == "effective":
            need("data.classifications.view"); need_org(args.org)
            r = g.classification.effective(
                args.org, args.object_type, args.object_id)
            print(f"[✓] {r['effective']} (rank {r['rank']}, "
                  f"{r['provenance']})")
            return
        if act == "data" and sub == "export":
            need("data.export")
            r = g.exports.build(args.org, scope=args.scope,
                                fmt=args.format, project_id=args.project,
                                limit=args.limit, actor=actor())
            print(f"[✓] export {r['export_id'][:12]} "
                  f"items={r['item_count']} bytes={r['byte_size']}")
            print(f"    integrity sha256={r['integrity']}")
            if args.format == "json":
                print(r["data"][:2000] + ("…" if len(r["data"]) > 2000
                                          else ""))
            return
        if act == "data" and sub == "delete-preview":
            need("data.delete")
            r = g.deletion.preview(args.org, object_type=args.object_type,
                                   object_id=args.object_id,
                                   project_id=args.project, actor=actor())
            print(f"[✓] eligible={r['eligible']} held={r['held']} "
                  f"retention_eligible={r['retention_eligible']} "
                  f"age_days={r['age_days']}")
            return
        if act == "data" and sub == "delete":
            need("data.delete")
            r = g.deletion.delete(args.org, object_type=args.object_type,
                                  object_id=args.object_id,
                                  project_id=args.project,
                                  authorized=bool(getattr(args,
                                                          "authorized",
                                                          False)),
                                  actor=actor())
            print(f"[✓] deleted={r['deleted']} remaining={r['remaining']} "
                  f"hold_checked={r['hold_checked']}")
            return
        if act == "data" and sub == "retention":
            need("data.retention.view" if getattr(args, "action", "preview")
                 in ("preview", "policies", "runs") else
                 "data.retention.manage")
            act2 = getattr(args, "retention_action", "preview")
            if act2 == "set":
                need("data.retention.manage")
                r = g.retention.policy_set(args.org, kind=args.kind,
                                           days=args.days,
                                           project_id=args.project,
                                           actor=actor())
                print(f"[✓] {r['kind']} = {r['days']} days")
                return
            if act2 == "policies":
                r = g.retention.policies(args.org, project_id=args.project,
                                         limit=100)
                for p in r["items"]:
                    print(f"  {p['kind']:22s} {p['days']:>5d}d "
                          f"enabled={p['enabled']}")
                print(f"[✓] {r['total']} policies")
                return
            if act2 == "runs":
                r = g.retention.runs(args.org, kind=args.kind,
                                     limit=args.limit)
                for rn in r["items"]:
                    print(f"  {rn['started_at']} {rn['kind']:20s} "
                          f"{rn['mode']:9s} deleted={rn['deleted_count']} "
                          f"held={rn['held_count']} errors={rn['error_count']}")
                print(f"[✓] {r['total']} runs")
                return
            dry = not bool(getattr(args, "execute", False))
            if act2 == "preview" or act2 == "run":
                r = g.retention.execute(args.org, kind=args.kind,
                                        project_id=args.project,
                                        batch=args.batch, dry_run=dry,
                                        actor=actor())
                print(f"[✓] {r['mode']} {r['kind']}: eligible="
                      f"{r['eligible']} deleted={r['deleted']} "
                      f"held={r['held']} errors={r['errors']} "
                      f"run={r['run_id'][:12]}")
                return
            print("[!] unknown retention action")
            sys.exit(2)
        if act == "data" and sub == "hold-create":
            need("data.holds.manage")
            r = g.retention.hold_create(
                args.org, object_type=args.object_type,
                object_id=args.object_id, reason=args.reason,
                kind=args.kind, project_id=args.project,
                expires_at=args.expires, actor=actor())
            print(f"[✓] hold {r['id'][:12]} on {args.object_type}/"
                  f"{str(args.object_id)[:40]} ({r['kind']})")
            return
        if act == "data" and sub == "hold-release":
            need("data.holds.manage")
            r = g.retention.hold_release(args.org, args.hold_id,
                                         reason=args.reason, actor=actor())
            print(f"[✓] released {r['id'][:12]} at {r['released_at']}")
            return
        if act == "data" and sub == "holds":
            need("data.holds.view"); need_org(args.org)
            r = g.retention.hold_list(args.org, active_only=True,
                                      object_type=args.object_type,
                                      limit=args.limit)
            for h in r["items"]:
                print(f"  {h['object_type']:14s} "
                      f"{str(h['object_id'])[:36]:36s} {h['kind']:12s} "
                      f"since={h['created_at']}")
            print(f"[✓] {r['total']} active holds")
            return
        # ---------------------------------------------------------------- secrets
        if act == "secrets" and sub == "register":
            need("secrets.registry.manage")
            r = g.secrets.register(
                args.org, kind=args.kind, name=args.name,
                reference=args.reference, material=args.material,
                project_id=args.project, expires_at=args.expires,
                rotation_due_at=args.rotation_due, actor=actor())
            print(f"[✓] registered {r['kind']} '{r['name']}' status="
                  f"{r['status']} (metadata only — material never stored)")
            return
        if act == "secrets" and sub == "list":
            need("secrets.registry.view"); need_org(args.org)
            r = g.secrets.list(args.org, kind=args.kind, status=args.status,
                               limit=args.limit)
            for it in r["items"]:
                print(f"  {it['kind']:16s} {str(it['name'])[:24]:24s} "
                      f"{it['status']:18s} exp={it['expires_at'] or '-'} "
                      f"rot={it['rotation_due_at'] or '-'}")
            print(f"[✓] {r['total']} secrets")
            return
        if act == "secrets" and sub == "status":
            need("secrets.registry.view"); need_org(args.org)
            r = g.secrets.status_summary(args.org)
            print(f"[✓] total={r['total']} by_status={r['by_status']}")
            print(f"    expiring_within_30d={r['expiring_within_30d']} "
                  f"rotation_due_within_7d={r['rotation_due_within_7d']}")
            return
        if act == "secrets" and sub == "set-status":
            need("secrets.registry.manage")
            r = g.secrets.set_status(args.org, args.secret_id, args.status,
                                     actor=actor())
            print(f"[✓] {r['id'][:12]} -> {r['status']} "
                  f"revoked_at={r['revoked_at'] or '-'}")
            return
        if act == "secrets" and sub == "touch":
            need("secrets.registry.manage")
            r = g.secrets.touch(args.org, args.secret_id, actor=actor())
            print(f"[✓] last_used_at={r['last_used_at']}")
            return
        if act == "secrets" and sub == "detect":
            need("secrets.detect")
            text = args.text
            if args.file:
                with open(args.file, "r", encoding="utf-8") as fh:
                    text = fh.read()
            if not text:
                print("[!] Provide --text or --file")
                sys.exit(2)
            r = g.secrets.detect(args.org, text)
            print(f"[✓] likely secret-shaped values: {r['hits']} "
                  f"{r['classes']}")
            print(f"    redacted sample: {r['redacted_sample'][:120]}")
            return
        if act == "secrets" and sub == "sweep":
            need("secrets.registry.manage")
            r = g.secrets.sweep_expiry(args.org, actor=actor())
            print(f"[✓] expired={r['expired']} "
                  f"rotation_required={r['rotation_required']}")
            return
        # ---------------------------------------------------------------- privacy
        if act == "privacy" and sub == "request-create":
            need("privacy.requests.manage")
            r = g.privacy.create(args.org, request_type=args.type,
                                 subject_ref=args.subject_ref,
                                 project_id=args.project,
                                 requester=args.requester, actor=actor())
            print(f"[✓] {r['id'][:12]} {r['request_type']} "
                  f"status={r['status']}")
            return
        if act == "privacy" and sub == "request":
            need("privacy.requests.view"); need_org(args.org)
            r = g.privacy.get(args.org, args.rid)
            print(f"[✓] {r['id'][:12]} {r['request_type']} "
                  f"status={r['status']} requester={r['requester']}")
            return
        if act == "privacy" and sub == "requests":
            need("privacy.requests.view"); need_org(args.org)
            r = g.privacy.list(args.org, status=args.status,
                               limit=args.limit)
            for it in r["items"]:
                print(f"  {it['id'][:12]} {it['request_type']:14s} "
                      f"{it['status']:14s} {it['created_at']}")
            print(f"[✓] {r['total']} requests")
            return
        if act == "privacy" and sub == "request-update":
            need("privacy.requests.manage")
            r = g.privacy.update(args.org, args.request_id,
                                 status=args.status, reviewer=args.reviewer,
                                 actor=actor())
            print(f"[✓] {r['id'][:12]} -> {r['status']}")
            return
        if act == "privacy" and sub == "request-complete":
            need("privacy.requests.manage")
            r = g.privacy.complete(args.org, args.request_id,
                                   reviewer=args.reviewer, actor=actor())
            print(f"[✓] {r['id'][:12]} completed at {r['completed_at']}")
            return
        if act == "privacy" and sub == "request-fail":
            need("privacy.requests.manage")
            r = g.privacy.fail(args.org, args.request_id, reason=args.reason,
                               actor=actor())
            print(f"[✓] {r['id'][:12]} failed")
            return
        if act == "privacy" and sub == "scan":
            need("privacy.requests.view"); need_org(args.org)
            r = g.scan(args.org, args.subject_ref,
                       object_type=args.object_type)
            print(f"[✓] {r['total']} occurrences {r['object_types']}")
            return
        if act == "privacy" and sub == "cover":
            need("privacy.subject.manage")
            r = g.cover(args.org, subject_ref=args.subject_ref,
                        object_type=args.object_type, project_id=args.project,
                        batch=args.batch, actor=actor())
            print(f"[✓] updated={r['updated']} skipped_held="
                  f"{r['skipped_held']} scanned={r['scanned']}")
            return
        if act == "privacy" and sub == "correct":
            need("privacy.subject.manage")
            r = g.correct(args.org, object_type=args.object_type,
                          object_id=args.object_id, field=args.field,
                          value=args.value,
                          authorized=bool(getattr(args, "authorized",
                                                  False)), actor=actor())
            print(f"[✓] corrected {args.object_type}/{args.object_id} "
                  f"field={args.field}")
            return
        if act == "privacy" and sub == "restrict":
            need("privacy.subject.manage")
            fields = [f.strip() for f in args.fields.split(",") if f.strip()]
            r = g.restrict(args.org, object_type=args.object_type,
                           object_id=args.object_id, fields=fields,
                           reason=args.reason, actor=actor())
            print(f"[✓] restricted fields={r['fields']}")
            return
        # ---------------------------------------------------------------- compliance
        if act == "compliance" and sub == "controls":
            need("compliance.controls.read")
            r = g.compliance.controls(args.org, project_id=args.project)
            for c in r["controls"]:
                print(f"  {c['control']:24s} {c['status']:24s} "
                      f"coverage={c['coverage']} gap={c['gap']} "
                      f"exception={c['exception_effective']}")
            print(f"[✓] {len(r['controls'])} control families "
                  f"(evidence state only)")
            return
        if act == "compliance" and sub == "gaps":
            need("compliance.controls.read")
            r = g.compliance.gaps(args.org, project_id=args.project)
            for c in r:
                print(f"  {c['control']} — evidence_exists="
                      f"{c['evidence_exists']}")
            print(f"[✓] {len(r)} gaps")
            return
        if act == "compliance" and sub == "evidence":
            need("compliance.controls.read")
            r = g.compliance.evidence_audit(args.org,
                                            project_id=args.project,
                                            limit=200)
            print(f"[✓] {r['total']} evidence rows "
                  f"truncated={r['truncated']}")
            for it in r["items"][:20]:
                print(f"  {it['control_category']:24s} {it['status']:24s} "
                      f"{it['source_type']} {str(it['evidence_hash'])[:12]}")
            return
        if act == "compliance" and sub == "evaluate":
            need("compliance.controls.read")
            r = g.compliance.evaluate(args.org, project_id=args.project,
                                      actor=actor())
            print(f"[✓] {len(r['controls'])} families, "
                  f"gaps={len(r['gaps'])} "
                  f"(evidence state only — no compliance claim)")
            return
        if act == "compliance" and sub == "report":
            need("compliance.controls.read")
            r = g.compliance.report_status(args.org, args.project)
            rep = r.get("report")
            if not rep:
                print("[!] no report stored for this project")
                return
            print(f"[✓] {rep['report_type']} {rep['generated_at']} "
                  f"class={rep['classification']} "
                  f"secret_free={rep['secret_free_verified']} "
                  f"retention_eligible={rep['retention_eligible']}")
            return
        if act == "compliance" and sub == "exception":
            act2 = getattr(args, "exception_action", "create")
            if act2 == "create":
                need("compliance.exceptions.manage")
                r = g.exceptions.create(
                    args.org, policy=args.policy, reason=args.reason,
                    scope=args.scope, approved_by=args.approved_by,
                    expires_at=args.expires, project_id=args.project,
                    actor=actor())
                print(f"[✓] exception {r['id'][:12]} policy={r['policy']} "
                      f"status={r['status']}")
                return
            if act2 == "list":
                need("compliance.exceptions.view"); need_org(args.org)
                r = g.exceptions.list(args.org, status=args.status,
                                      limit=args.limit)
                for it in r["items"]:
                    print(f"  {it['id'][:12]} {it['policy']:24s} "
                          f"{it['status']:12s} expires={it['expires_at']}"
                          f" effective={it['effective']}")
                print(f"[✓] {r['total']} exceptions")
                return
            if act2 == "revoke":
                need("compliance.exceptions.manage")
                r = g.exceptions.revoke(args.org, args.exception_id,
                                        reason=args.reason, actor=actor())
                print(f"[✓] revoked {r['id'][:12]}")
                return
            if act2 == "effective":
                need("compliance.exceptions.view"); need_org(args.org)
                r = g.exceptions.effective(args.org, args.policy,
                                           project_id=args.project)
                print(f"[✓] effective={bool(r)}"
                      + (f" ({r['id'][:12]}, expires {r['expires_at']})"
                         if r else ""))
                return
            if act2 == "sweep":
                need("compliance.exceptions.manage")
                r = g.exceptions.sweep_expiry(args.org, actor=actor())
                print(f"[✓] expired={r['expired']}")
                return
            print("[!] unknown exception action")
            sys.exit(2)
        print(f"[!] unknown governance action: {act} {sub}")
        sys.exit(2)
    except _err.SecurityToolkitError as e:
        fail(e)


def _cmd_fed(args, svc, ctx, authz):
    """Phase-12 federation CLI: `security federation <sub>`.
    Local mode = platform-local; --as TOKEN enforces the Phase-12 RBAC
    permissions (fail closed, monotonic tiers). Package payloads are only
    ever read from an explicit --file (size-bounded, JSON-only — never
    pickle/yaml/eval) or written to an explicit --out; the panel and list
    commands print metadata (ids, counts, hashes) only."""
    import errors as _err

    def need(perm):
        if ctx is not None:
            authz.require(ctx, perm)

    def need_org(org_id):
        if ctx is not None:
            authz.require_org(ctx, org_id)

    def need_project(project_id):
        if ctx is not None:
            authz.require_project(ctx, project_id)

    def actor():
        return str(ctx.label() if ctx else "cli")

    def fail(e):
        print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, 'exit_code', 10))

    def read_envelope(path):
        """Bounded, JSON-only envelope read (reject oversized inputs before
        parsing; never any dynamic deserialization)."""
        import federation as _fed
        try:
            sz = os.path.getsize(path)
        except OSError as e:
            print(f"[!] cannot read package file: {e}")
            sys.exit(2)
        if sz > _fed.MAX_IMPORT_BYTES:
            print(f"[!] package file too large ({sz} bytes > "
                  f"{_fed.MAX_IMPORT_BYTES}); refusing to parse")
            sys.exit(2)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                env = json.load(fh)
        except (OSError, ValueError) as e:
            print(f"[!] package file is not valid JSON: {e}")
            sys.exit(2)
        if not isinstance(env, dict):
            print("[!] package envelope must be a JSON object")
            sys.exit(2)
        return env

    def csv_list(value):
        return tuple(t.strip() for t in str(value or "").split(",")
                     if t.strip())

    import federation as _fed
    fed = _fed.FederationService(svc)
    sub = getattr(args, "sub", "")
    try:
        # ------------------------------------------------------------- peers
        if sub == "peer-list":
            need("federation.read"); need_org(args.org)
            r = fed.peers.list(args.org, status=getattr(args, "status", ""),
                               limit=getattr(args, "limit", 100))
            for p in r["items"]:
                print(f"  {p['id'][:12]}  {p['status']:10s} "
                      f"{p['direction']:12s} peer_org={p['peer_org_id'][:12]} "
                      f"name={str(p['name'])[:40]}")
            print(f"[✓] {r['count']} of {r['total']} peers")
            return
        if sub == "peer-create":
            need("federation.create"); need_org(args.org)
            r = fed.peers.create(args.org, peer_org_id=args.peer_org,
                                 name=args.name,
                                 purpose=getattr(args, "purpose", ""),
                                 direction=getattr(args, "direction",
                                                   "outbound"),
                                 expires_at=getattr(args, "expires_at", ""),
                                 actor=actor())
            print(f"[✓] peer {r['id']} status={r['status']} (approval by a "
                  f"DIFFERENT identity is required before any transfer)")
            return
        if sub == "peer-approve":
            need("federation.approve"); need_org(args.org)
            r = fed.peers.approve(args.org, args.peer_id,
                                  approved_by=getattr(args, "approved_by",
                                                      "") or actor(),
                                  actor=actor())
            print(f"[✓] peer {r['id']} status={r['status']} "
                  f"approved_by={r['approved_by']}")
            return
        if sub == "peer-revoke":
            need("federation.revoke"); need_org(args.org)
            r = fed.peers.revoke(args.org, args.peer_id, reason=args.reason,
                                 actor=actor())
            print(f"[✓] peer {r['id']} revoked (terminal; new operations "
                  f"are blocked, local data is retained under local "
                  f"retention/privacy rules)")
            return
        # ---------------------------------------------------------- policies
        if sub == "policy-list":
            need("federation.read"); need_org(args.org)
            r = fed.policies.list(args.org,
                                  peer_id=getattr(args, "peer_id", ""),
                                  status=getattr(args, "status", ""),
                                  limit=getattr(args, "limit", 100))
            for p in r["items"]:
                print(f"  {p['id'][:12]}  {p['status']:9s} "
                      f"peer={p['peer_id'][:12]} name={str(p['name'])[:36]} "
                      f"max_objects={p['max_objects']}")
            print(f"[✓] {r['count']} of {r['total']} policies")
            return
        if sub == "policy-create":
            need("federation.manage_policy"); need_org(args.org)
            need_project(getattr(args, "project", ""))
            fields = {}
            if getattr(args, "fields", ""):
                fields = json.loads(args.fields)
                if not isinstance(fields, dict):
                    print("[!] --fields must be a JSON object "
                          "{object_type: [field,...]}")
                    sys.exit(2)
            r = fed.policies.create(args.org, peer_id=args.peer_id,
                                    name=args.name,
                                    project_id=getattr(args, "project", ""),
                                    object_types=csv_list(args.object_types),
                                    classifications=csv_list(
                                        getattr(args, "classifications", ""))
                                    or ["internal"],
                                    fields=fields,
                                    max_objects=getattr(args, "max_objects",
                                                        0) or 1000,
                                    expires_at=getattr(args, "expires_at",
                                                       ""),
                                    explicit_sensitive=getattr(
                                        args, "explicit_sensitive", False),
                                    actor=actor())
            print(f"[✓] policy {r['id']} status={r['status']} "
                  f"object_types={','.join(r['allowed_object_types'])} "
                  f"classifications={','.join(r['allowed_classifications'])}")
            return
        if sub == "policy-update":
            need("federation.manage_policy"); need_org(args.org)
            kw = {}
            if getattr(args, "name", ""):
                kw["name"] = args.name
            if getattr(args, "object_types", ""):
                kw["object_types"] = csv_list(args.object_types)
            if getattr(args, "classifications", ""):
                kw["classifications"] = csv_list(args.classifications)
            if getattr(args, "max_objects", 0):
                kw["max_objects"] = int(args.max_objects)
            if getattr(args, "expires_at", ""):
                kw["expires_at"] = args.expires_at
            if getattr(args, "fields", ""):
                kw["fields"] = json.loads(args.fields)
            kw["explicit_sensitive"] = getattr(args, "explicit_sensitive",
                                               False)
            if getattr(args, "disable", False):
                r = fed.policies.disable(args.org, args.policy_id,
                                         actor=actor())
            else:
                r = fed.policies.update(args.org, args.policy_id,
                                        actor=actor(), **kw)
            print(f"[✓] policy {r['id']} status={r['status']} "
                  f"max_objects={r['max_objects']}")
            return
        # ---------------------------------------------------------- packages
        if sub == "package-create":
            need("federation.export"); need_org(args.org)
            need_project(getattr(args, "project", ""))
            r = fed.packages.build(args.org, peer_id=args.peer_id,
                                   policy_id=getattr(args, "policy_id", ""),
                                   project_id=getattr(args, "project", ""),
                                   object_types=csv_list(
                                       getattr(args, "object_types", "")),
                                   limit=getattr(args, "limit", 0),
                                   trust_mode=getattr(args, "trust_mode",
                                                      "integrity_verified"),
                                   external_signature_ref=getattr(
                                       args, "signature_ref", ""),
                                   actor=actor())
            print(f"[✓] package {r['package_id']} objects="
                  f"{r['object_count']} bytes={r['byte_size']} "
                  f"classification={r['classification']} "
                  f"integrity=sha256:{r['integrity'][:16]}…")
            print(f"    counts={r['counts']} denied={r['denied']} "
                  f"truncated={r['truncated']}")
            out = getattr(args, "out", "")
            if out:
                env = fed.packages.serialize(args.org, r["package_id"],
                                             actor=actor())
                with open(out, "w", encoding="utf-8") as fh:
                    json.dump(env, fh, sort_keys=True, ensure_ascii=False)
                print(f"[✓] envelope written to {out} "
                      f"(sha256:{r['integrity'][:16]}…)")
            return
        if sub == "package-show":
            need("federation.read"); need_org(args.org)
            r = fed.packages.get(args.org, args.package_id)
            for k in ("id", "peer_id", "policy_id", "project_id",
                      "destination_org_id", "schema_version",
                      "classification", "object_count", "byte_size",
                      "integrity_algorithm", "integrity_hash", "trust_mode",
                      "status", "created_by", "created_at", "expires_at"):
                print(f"  {k:22s} {r.get(k, '')}")
            print("[✓] metadata only — payloads are never printed")
            return
        if sub == "package-verify":
            need("federation.read"); need_org(args.org)
            if getattr(args, "file", ""):
                env = read_envelope(args.file)
                v = _fed.verify_envelope(env)
            else:
                if not getattr(args, "package_id", ""):
                    print("[!] provide --package-id or --file")
                    sys.exit(2)
                v = fed.packages.verify(args.org, args.package_id)
            ok = bool(v.get("valid"))
            print(f"[{'✓' if ok else '!'}] valid={ok} "
                  f"algorithm={v.get('algorithm', '')} "
                  f"expected={str(v.get('expected', ''))[:16]}… "
                  f"actual={str(v.get('actual', ''))[:16]}… "
                  f"error={v.get('error') or '-'}")
            if not ok:
                sys.exit(1)
            return
        if sub == "package-import":
            need("federation.import"); need_org(args.org)
            need_project(args.project)
            env = read_envelope(args.file)
            r = fed.imports.import_envelope(
                args.org, envelope=env, target_project_id=args.project,
                peer_id=getattr(args, "peer_id", ""),
                collision=getattr(args, "collision", "skip"),
                actor=actor())
            if r.get("duplicate"):
                print(f"[✓] duplicate: package already imported "
                      f"(import {r['import_id']}, status={r['status']}) — "
                      f"nothing was re-applied")
                return
            print(f"[✓] import {r['import_id']} status={r['status']} "
                  f"objects={r['object_count']} imported={r['imported']} "
                  f"skipped={r['skipped']} linked={r.get('linked', 0)}")
            return
        # -------------------------------------------------------------- bulk
        if sub == "bulk-export":
            need("federation.bulk"); need_org(args.org)
            need_project(args.project)
            if getattr(args, "now", False):
                r = fed.bulk_runner.run(
                    org_id=args.org, project_id=args.project,
                    op="bulk_export", peer_id=args.peer_id,
                    policy_id=getattr(args, "policy_id", ""),
                    object_types=csv_list(getattr(args, "object_types", "")),
                    actor=actor())
                print(f"[✓] bulk_export (sync) packages={r['packages']} "
                      f"objects={r['objects']} denied={r['denied']} "
                      f"truncated={r['truncated']} package="
                      f"{r['package_id']}")
            else:
                r = fed.bulk.enqueue(args.org, args.project,
                                     op="bulk_export", peer_id=args.peer_id,
                                     policy_id=getattr(args, "policy_id",
                                                       ""),
                                     object_types=csv_list(
                                         getattr(args, "object_types", "")),
                                     actor=actor())
                print(f"[✓] bulk_export job {r['job_id']} status="
                      f"{r['status']} scan={r['scan_id']}")
            return
        if sub == "bulk-import":
            need("federation.bulk"); need_org(args.org)
            need_project(args.project)
            env = read_envelope(args.file)
            if getattr(args, "now", False):
                r = fed.bulk_runner.run(
                    org_id=args.org, project_id=args.project,
                    op="bulk_import", peer_id=getattr(args, "peer_id", ""),
                    strategy=getattr(args, "collision", "skip"),
                    envelope=env, actor=actor())
                print(f"[✓] bulk_import (sync) imports={r['imports']} "
                      f"imported={r['imported']} skipped={r['skipped']} "
                      f"duplicate={r['duplicate']}")
            else:
                r = fed.bulk.enqueue(args.org, args.project, op="bulk_import",
                                     peer_id=getattr(args, "peer_id", ""),
                                     strategy=getattr(args, "collision",
                                                      "skip"),
                                     envelope=env, actor=actor())
                print(f"[✓] bulk_import job {r['job_id']} status="
                      f"{r['status']} scan={r['scan_id']}")
            return
        if sub == "bulk-jobs":
            need("federation.read"); need_org(args.org)
            r = fed.bulk.jobs_list(args.org,
                                   project_id=getattr(args, "project", ""),
                                   status=getattr(args, "status", ""),
                                   limit=getattr(args, "limit", 50))
            for j in r["items"]:
                print(f"  {j['id'][:12]}  {j['status']:11s} "
                      f"attempt={j['attempt']}/{j['max_attempts']} "
                      f"created={j['created_at']}")
            print(f"[✓] {r['total']} bulk jobs")
            return
        # ------------------------------------------------------------- audit
        if sub == "audit":
            need("federation.audit"); need_org(args.org)
            limit = max(1, min(int(getattr(args, "limit", 50) or 50), 500))
            rows = [e for e in svc.audit_list_org(args.org, limit=limit)
                    if e.action.startswith(("federation.", "integration."))]
            for e in rows[:limit]:
                print(f"  {e.ts}  {e.action:34s} actor={str(e.actor)[:24]:24s}"
                      f" {e.object_type}:{str(e.object_id)[:12]}")
            print(f"[✓] {len(rows[:limit])} federation/integration audit "
                  f"events (hash-chained; verify with `platform "
                  f"audit-verify`)")
            return
        print(f"[!] unknown federation action: {sub}")
        sys.exit(2)
    except _err.SecurityToolkitError as e:
        fail(e)


def cmd_auth(args):
    """Phase 2 identity: users, roles, sessions, API keys, resets."""
    act = args.action
    try:
        svc, id_svc = _auth_stack(args)
        import mfa_service as _mfa_mod
        import sso_service as _sso_mod
        import scim_service as _scim_mod
        _mfs = _mfa_mod.MfaService(svc, identity_svc=id_svc)
        _sso = _sso_mod.SsoService(svc, identity_svc=id_svc)
        _scim = _scim_mod.ScimService(svc, identity_svc=id_svc)
        ctx = None
        authz = None
        as_tok = getattr(args, "as_token", "") or ""
        if as_tok:
            import authz as _az
            authz = _az.AuthorizationService(svc, id_svc)
            ctx = authz.context_from_secret(as_tok)

        def need(perm):
            if ctx is not None:
                authz.require(ctx, perm)

        def need_org(org_id):
            if ctx is not None:
                authz.require_org(ctx, org_id)

        if act == "bootstrap-owner":
            # FIRST user of an organization — local setup path only. Refuses
            # when the org already has users (no silent privilege grant).
            if id_svc.user_list(args.org):
                print(f"[!] Organization already has users; use auth login / "
                      f"user-create with an existing owner session.")
                sys.exit(11)
            pw = _read_secret(getattr(args, "password", ""))
            u = id_svc.user_create(args.org, args.username, args.email, pw,
                                   roles=("owner",), allow_any_role=True,
                                   actor="bootstrap")
            print(f"[✓] Owner created: {u.id}  {u.username} ({u.email})")
            return
        if act == "user-create":
            need("user.create")
            need_org(args.org)
            pw = _read_secret(getattr(args, "password", ""))
            roles = tuple(r.strip() for r in (getattr(args, "roles", "") or "")
                          .split(",") if r.strip()) or ("viewer",)
            u = id_svc.user_create(args.org, args.username, args.email, pw,
                                   roles=roles,
                                   display_name=getattr(args, "display", "") or "",
                                   as_roles=ctx.roles if ctx else None,
                                   as_permissions=ctx.permissions if ctx else None,
                                   actor=ctx.label() if ctx else "cli")
            print(f"[✓] User created: {u.id}  {u.username} roles={roles}")
            return
        if act == "user-list":
            need("user.read")
            need_org(args.org)
            for u in id_svc.user_list(args.org):
                print(f"   {u.id}  {u.username:<20} {u.email:<32} "
                      f"{u.status:<9} roles={','.join(id_svc.user_roles(u.id))}")
            return
        if act == "user-disable":
            need("user.disable")
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            u = id_svc.user_set_status(u.id, "disabled",
                                       actor=ctx.label() if ctx else "cli")
            print(f"[✓] User disabled: {u.username} (sessions revoked)")
            return
        if act == "user-enable":
            need("user.update")
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            u = id_svc.user_set_status(u.id, "active",
                                       actor=ctx.label() if ctx else "cli")
            print(f"[✓] User enabled: {u.username}")
            return
        if act == "role-set":
            need("role.assign")
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            roles = tuple(r.strip() for r in (args.roles or "").split(",")
                          if r.strip())
            if not roles:
                print("[!] At least one role required")
                sys.exit(2)
            id_svc.user_set_roles(u.id, roles,
                                  as_roles=ctx.roles if ctx else None,
                                  as_permissions=ctx.permissions if ctx else None,
                                  actor=ctx.label() if ctx else "cli")
            print(f"[✓] Roles for {u.username}: {','.join(roles)}")
            return
        if act == "set-password":
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            need("user.update")
            pw = _read_secret(getattr(args, "password", ""))
            id_svc.user_set_password(u.id, pw,
                                     actor=ctx.label() if ctx else "cli")
            print(f"[✓] Password updated (sessions revoked)")
            return
        if act == "login":
            def _mfa_need(user, roles):
                """Deterministic MFA-policy hook — any evaluation problem
                fails closed (MFA required)."""
                try:
                    return bool(_mfs.policy_requires(user.org_id
                                                     if hasattr(user, "org_id")
                                                     else "", roles))
                except Exception:
                    return True

            out = id_svc.login(args.identifier,
                               _read_secret(getattr(args, "password", ""),
                                            env_name="SECTOOLKIT_PASSWORD"),
                               ip=getattr(args, "ip", "") or "cli",
                               actor="cli", mfa_required=_mfa_need)
            print(f"[✓] Logged in as {out['user'].username} "
                  f"({out['user'].id})")
            if out["mfa_required"]:
                print(f"    MFA REQUIRED — complete it with: auth mfa-challenge "
                      f"--session {out['session'].id} --code <TOTP>")
            print(f"    session: {out['secret']}   # shown ONCE — keep secret")
            return
        if act == "logout":
            id_svc.logout(args.token or "", actor="cli")
            print("[✓] Session revoked")
            return
        if act == "key-create":
            need("credentials.create")
            need_org(args.org)
            scopes = tuple(s.strip() for s in (args.scopes or "").split(",")
                           if s.strip())
            out = id_svc.credential_create(
                args.org, args.name, scopes,
                created_by=ctx.user_id if ctx else "cli",
                project_id=getattr(args, "project", "") or "",
                ttl_seconds=int(getattr(args, "ttl", 0) or 0),
                as_permissions=ctx.permissions if ctx else None,
                actor=ctx.label() if ctx else "cli")
            print(f"[✓] API key created: {out['credential'].id}")
            print(f"    prefix : {out['credential'].key_prefix}")
            print(f"    scopes : {','.join(scopes) or '(none)'}")
            print(f"    secret : {out['secret']}   # shown ONCE — keep secret")
            return
        if act == "key-list":
            need("credentials.create")
            need_org(args.org)
            for c in id_svc.credential_list(args.org):
                print(f"   {c.id}  {c.name:<24} {c.key_prefix}  "
                      f"{c.status:<8} last={c.last_used_at or '-'} "
                      f"exp={c.expires_at or '-'}")
            return
        if act == "key-revoke":
            need("credentials.revoke")
            c = id_svc.credential_get(args.key)
            if ctx is not None and c.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            c = id_svc.credential_revoke(args.key,
                                         actor=ctx.label() if ctx else "cli")
            print(f"[✓] Key revoked: {c.name} ({c.key_prefix})")
            return
        if act == "key-rotate":
            need("credentials.revoke")
            c = id_svc.credential_get(args.key)
            if ctx is not None and c.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            out = id_svc.credential_rotate(
                args.key, as_permissions=ctx.permissions if ctx else None,
                actor=ctx.label() if ctx else "cli")
            print(f"[✓] Key rotated: {out['credential'].name} "
                  f"(scopes unchanged)")
            print(f"    secret : {out['secret']}   # shown ONCE — keep secret")
            return
        if act == "password-reset":
            out = id_svc.password_reset_request(args.identifier, actor="cli")
            if out["token"]:
                print(f"[✓] Reset token (one-time, 30 min): {out['token']}")
            else:
                print("[✓] If that account exists, a reset token was issued.")
            return
        if act == "reset-consume":
            pw = _read_secret(getattr(args, "password", ""))
            id_svc.password_reset_consume(args.token, pw, actor="cli")
            print("[✓] Password reset (token consumed, sessions revoked)")
            return
        # ------------------------------------------------------ Phase 8
        # MFA enforcement / enrollment / recovery (self-service + admin)
        if act in ("mfa-status",):
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            need("identity.mfa.read")
            st = _mfs.mfa_status(u.id)
            print(f"  {args.user}  method={st['method']}  "
                  f"enabled={st['enabled']}  enrolled={st['enrolled']}  "
                  f"recovery_unused={st['recovery_codes']}  "
                  f"verified_at={st.get('verified_at') or '-'}")
            return
        if act == "mfa-enroll":
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None:
                if u.org_id != ctx.org_id:
                    print("[!] Forbidden")
                    sys.exit(11)
                if ctx.user_id != args.user:
                    need("identity.mfa.manage")
            # Re-enrolling a user whose MFA is ALREADY verified is an
            # MFA-rebinding vector: require a verified step-up context.
            out = _mfs.enroll_start(
                u.id, actor=ctx.label() if ctx else "cli",
                verified=bool(ctx is not None and authz.step_up_ok(ctx)))
            print(f"[✓] TOTP enrollment prepared (NOT active yet) "
                  f"user={args.user}")
            print(f"    seed   : {out['seed']}   # shown ONCE")
            print(f"    otpauth: {out['otpauth']}")
            print(f"    Activate with: auth mfa-verify --user {args.user} "
                  f"--code <TOTP>")
            return
        if act == "mfa-verify":
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            out = _mfs.enroll_verify(u.id, args.code,
                                     actor=ctx.label() if ctx else "cli")
            print(f"[✓] MFA enabled for {args.user}")
            return
        if act == "mfa-challenge":
            u = _user_by_ident(id_svc, args.user)
            out = _mfs.challenge(u.id, args.code,
                                 session_id=getattr(args, "session", "") or "",
                                 actor=ctx.label() if ctx else "cli")
            print(f"[✓] MFA verified (method={out['method']}) "
                  f"session={out['session_id'] or '-'}")
            return
        if act == "mfa-disable":
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None:
                if u.org_id != ctx.org_id:
                    print("[!] Forbidden")
                    sys.exit(11)
                if ctx.user_id != args.user:
                    need("identity.mfa.manage")
            _mfs.disable(u.id, actor=ctx.label() if ctx else "cli")
            print(f"[✓] MFA disabled for {args.user} (codes voided)")
            return
        if act == "mfa-recovery-generate":
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            need("identity.mfa.manage")
            out = _mfs.recovery_codes_generate(
                u.id,
                count=int(getattr(args, "count", 10) or 10),
                actor=ctx.label() if ctx else "cli")
            print(f"[✓] {out['count']} recovery codes (shown ONCE; previous "
                  f"codes invalidated)")
            for c in out["codes"]:
                print(f"    {c}")
            return
        if act == "mfa-recovery-list":
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            need("identity.mfa.read")
            st = _mfs.recovery_codes_list(u.id)
            print(f"  {args.user}  issued={st['issued']}  "
                  f"unused={st['unused']}  used={st['used']} (plaintext "
                  f"codes are never stored or listed)")
            return
        if act == "mfa-reset":
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            need("identity.mfa.manage")
            out = _mfs.reset(u.id,
                             reenroll=not bool(getattr(args, "no_reenroll",
                                                       False)),
                             actor=ctx.label() if ctx else "cli")
            print(f"[✓] MFA reset for {args.user}: sessions revoked, "
                  f"codes voided, re-enroll_required={out['reenroll_required']}")
            return
        if act == "policy-get":
            need("identity.policy.read")
            need_org(args.org)
            pol = _mfs.policy_get(args.org)
            print(f"  org={args.org}  mode={pol['mode']}  "
                  f"roles={','.join(pol['roles']) or '-'}  "
                  f"step_up_ttl={pol['step_up_ttl']}s  "
                  f"require_recent={pol['require_recent']}s  "
                  f"version={pol['version']}")
            return
        if act == "policy-set":
            need("identity.policy.update")
            need_org(args.org)
            mode = getattr(args, "mode", "") or "optional"
            if mode not in ("optional", "roles", "required"):
                print("[!] mode must be optional|roles|required")
                sys.exit(2)
            roles = [r.strip() for r in
                     (getattr(args, "roles", "") or "").split(",")
                     if r.strip()]
            pol = _mfs.policy_set(
                args.org, {"mode": mode, "roles": roles,
                           "step_up_ttl": int(getattr(args, "step_up_ttl",
                                                      600) or 600),
                           "require_recent": int(getattr(args,
                                                         "require_recent",
                                                         900) or 900)},
                version=int(getattr(args, "version", 0) or 0),
                actor=ctx.label() if ctx else "cli")
            print(f"[✓] MFA policy v{pol['version']}: mode={pol['mode']} "
                  f"roles={','.join(pol['roles']) or '-'}")
            return
        if act == "sso-provider-create":
            need("identity.sso.create")
            need_org(args.org)
            import json as _json
            cfg = _json.loads(getattr(args, "config", "") or "{}")
            roles = [r.strip() for r in
                     (getattr(args, "default_roles", "") or "").split(",")
                     if r.strip()]
            out = _sso.provider_create(
                args.org, args.type, display_name=args.name,
                enabled=bool(getattr(args, "enabled", False)),
                config=cfg, jit=bool(getattr(args, "jit", False)),
                default_roles=roles, actor=ctx.label() if ctx else "cli")
            print(f"[✓] SSO provider created: {out['id']} "
                  f"({out['provider_type']}, enabled={out['enabled']})")
            return
        if act == "sso-provider-list":
            need("identity.sso.read")
            need_org(args.org)
            for p in _sso.provider_list(args.org)["providers"]:
                print(f"   {p['id']}  {p['display_name']:<24} "
                      f"{p['provider_type']:<5} enabled={p['enabled']} "
                      f"jit={p['jit']} v{p['version']}")
            return
        if act == "sso-provider-get":
            need("identity.sso.read")
            p = _sso.provider_get(args.provider)
            if ctx is not None and p["org_id"] != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            print(f"  {p['id']}  {p['display_name']} ({p['provider_type']})")
            print(f"    enabled={p['enabled']}  jit={p['jit']}  "
                  f"version={p['version']}")
            for k, v in sorted(p["config"].items()):
                print(f"    {k}: {v}")
            return
        if act == "sso-provider-update":
            need("identity.sso.update")
            p = _sso.provider_get(args.provider)
            if ctx is not None and p["org_id"] != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            out = _sso.provider_update(
                args.provider,
                display_name=getattr(args, "name", "") or "",
                enabled=bool(getattr(args, "enabled", False))
                if getattr(args, "enabled", None) is not None else None,
                version=int(getattr(args, "version", 0) or 0),
                actor=ctx.label() if ctx else "cli")
            print(f"[✓] SSO provider updated: v{out['version']}")
            return
        if act == "sso-provider-delete":
            need("identity.sso.delete")
            p = _sso.provider_get(args.provider)
            if ctx is not None and p["org_id"] != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            _sso.provider_delete(args.provider,
                                 actor=ctx.label() if ctx else "cli")
            print(f"[✓] SSO provider deleted: {args.provider}")
            return
        if act == "sso-domain-add":
            need("identity.sso.update")
            need_org(args.org)
            d = _sso.domain_add(args.org, args.provider, args.domain,
                                actor=ctx.label() if ctx else "cli")
            print(f"[✓] Domain claimed: {d['domain']} -> {args.provider}")
            return
        if act == "sso-domain-list":
            need("identity.sso.read")
            need_org(args.org)
            for d in _sso.domain_list(args.org):
                print(f"   {d['domain']:<30} provider={d['provider_id'] or '-'}")
            return
        if act == "sso-domain-remove":
            need("identity.sso.update")
            need_org(args.org)
            _sso.domain_remove(args.org, args.domain,
                               actor=ctx.label() if ctx else "cli")
            print(f"[✓] Domain released: {args.domain}")
            return
        if act == "sso-mapping-set":
            need("identity.sso.update")
            need_org(args.org)
            m = _sso.mapping_set(args.org, args.group, args.role,
                                 provider_id=getattr(args, "provider", "")
                                 or "", actor=ctx.label() if ctx else "cli")
            print(f"[✓] Group mapping: {args.group} -> {args.role} "
                  f"(provider={args.provider or 'all'})")
            return
        if act == "sso-mapping-remove":
            need("identity.sso.update")
            need_org(args.org)
            _sso.mapping_remove(args.org, args.group,
                                provider_id=getattr(args, "provider", "")
                                or "", actor=ctx.label() if ctx else "cli")
            print(f"[✓] Mapping removed: {args.group}")
            return
        if act == "sso-mapping-list":
            need("identity.sso.read")
            need_org(args.org)
            for m in _sso.mapping_list(args.org):
                print(f"   {m['idp_group']:<28} -> {m['role']:<16} "
                      f"provider={m['provider_id'] or 'all'}")
            return
        if act == "sso-oidc-start":
            need("identity.sso.read")
            out = _sso.oidc_start(args.provider,
                                  redirect_uri=getattr(args, "redirect", "")
                                  or "")
            print(f"[✓] Open this URL in a browser (state+nonce are "
                  f"single-use, 5 min):")
            print(f"    {out['authorization_url']}")
            return
        if act == "sso-saml-start":
            need("identity.sso.read")
            out = _sso.saml_start(args.provider)
            print(f"[✓] AuthnRequest URL (single-use, 5 min):")
            print(f"    {out['authorization_url']}")
            return
        if act == "sessions-list":
            need("identity.sessions.read")
            need_org(args.org)
            rows = id_svc.sessions_list_org(
                args.org, status=getattr(args, "status", "active") or "active",
                limit=int(getattr(args, "limit", 100) or 100))
            print(f"  {rows['total']} session(s)")
            for s in rows["sessions"]:
                print(f"   {s['id']}  user={s.get('username') or s['user_id']}  "
                      f"auth={s.get('auth_method') or '-'}  "
                      f"mfa={s.get('mfa_status') or '-'}  "
                      f"expires={s.get('expires_at') or '-'}")
            return
        if act == "session-revoke":
            need("identity.sessions.revoke")
            if ctx is not None:
                if ctx.session_id != args.session:
                    # admin path: the target session must belong to the
                    # caller's own tenant (no cross-org revocation)
                    srows = svc.db.query(
                        "SELECT s.user_id, u.org_id FROM sessions s JOIN "
                        "users u ON u.id=s.user_id WHERE s.id=? LIMIT 1",
                        (args.session,))
                    if not srows or srows[0]["org_id"] != ctx.org_id:
                        print("[!] Forbidden")
                        sys.exit(11)
                else:
                    authz.require_own_session(ctx, args.session)
            id_svc.session_revoke_id(args.session,
                                     reason=getattr(args, "reason",
                                                    "cli_revoke") or "cli_revoke")
            print(f"[✓] Session revoked: {args.session}")
            return
        if act == "sessions-revoke-user":
            need("identity.sessions.revoke")
            u = _user_by_ident(id_svc, args.user)
            if ctx is not None and u.org_id != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            n = id_svc.sessions_revoke_all(args.user,
                                           reason=getattr(args, "reason",
                                                          "admin_revoke")
                                           or "admin_revoke",
                                           actor=ctx.label() if ctx else "cli")
            print(f"[✓] {n} session(s) revoked for {args.user}")
            return
        if act == "sessions-revoke-org":
            need("identity.sessions.revoke")
            need_org(args.org)
            n = id_svc.sessions_revoke_org(args.org,
                                           reason=getattr(args, "reason",
                                                          "org_revoke")
                                           or "org_revoke",
                                           actor=ctx.label() if ctx else "cli")
            print(f"[✓] {n} session(s) revoked org-wide ({args.org})")
            return
        if act == "scim-cred-create":
            need("identity.scim.manage")
            need_org(args.org)
            out = _scim.credential_create(
                args.org, args.name,
                max_role=getattr(args, "max_role", "analyst") or "analyst",
                ttl_seconds=int(getattr(args, "ttl", 0) or 0),
                actor=ctx.label() if ctx else "cli")
            print(f"[✓] SCIM credential created: {out['id']}")
            print(f"    basic : {out['basic']}   # shown ONCE — keep secret")
            print(f"    max_role: {out['max_role']}")
            return
        if act == "scim-cred-list":
            need("identity.scim.read")
            need_org(args.org)
            rows = _scim_rows(svc, args.org)
            for c in rows:
                print(f"   {c['id']}  {c['name']:<24} max_role="
                      f"{c['max_role']:<16} {c['status']:<8} "
                      f"last={c['last_used_at'] or '-'}")
            return
        if act == "scim-cred-revoke":
            need("identity.scim.manage")
            row = _scim_row(svc, args.cred)
            if ctx is not None and row["org_id"] != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            _scim.credential_revoke(args.cred,
                                    actor=ctx.label() if ctx else "cli")
            print(f"[✓] SCIM credential revoked: {args.cred}")
            return
        # -------- Phase 8: break-glass emergency access (§15) ---------------
        if act == "break-glass-start":
            need("identity.break_glass")
            need_org(args.org)
            u = _user_by_ident(id_svc, args.user)
            if u.org_id != args.org:
                print("[!] Forbidden")
                sys.exit(11)
            import breakglass_service as _bg_mod
            _bg = _bg_mod.BreakGlassService(svc, id_svc)
            # A grant is minted ONLY from a verified step-up context: a
            # session that completed MFA, an API credential, or an existing
            # grant. Local-mode (no --as) is refused — no silent bypass.
            verified = bool(ctx is not None and authz.step_up_ok(ctx))
            out = _bg.start(
                u.id, args.org, reason=args.reason,
                ttl_seconds=int(getattr(args, "ttl", 0) or 0),
                verified=verified,
                created_by_session=ctx.session_id if ctx else "",
                actor=ctx.label() if ctx else "cli")
            print(f"[✓] Break-glass active: {out['grant_id']}  "
                  f"expires={out['expires_at']}  ttl={out['ttl_seconds']}s")
            print(f"    bg token: {out['secret']}   "
                  f"# shown ONCE — keep secret")
            return
        if act == "break-glass-status":
            need("identity.break_glass")
            need_org(args.org)
            import breakglass_service as _bg_mod
            _bg = _bg_mod.BreakGlassService(svc, id_svc)
            grants = _bg.list_org(args.org,
                                  limit=int(getattr(args, "limit", 20) or 20),
                                  status=getattr(args, "status", "all")
                                  or "all")
            print(f"  {len(grants)} break-glass grant(s) "
                  f"(org {args.org[:12]}…)")
            for g in grants:
                print(f"   {g['id']}  user={g['user_id'][:12]}…  "
                      f"state={g['state']:<8} reason={g['reason'][:40]:<40}"
                      f" expires={g['expires_at']}"
                      + (f" ended={g['ended_at']}"
                         if g.get("ended_at") else ""))
            snap = _bg.org_status(args.org)
            print(f"   totals: active={snap['active']} "
                  f"expired={snap['expired']} ended={snap['ended']}")
            return
        if act == "break-glass-end":
            need("identity.break_glass")
            rows = svc.db.query(
                "SELECT org_id FROM break_glass_grants WHERE id=? LIMIT 1",
                (args.grant,))
            if not rows:
                errors_mod().NotFoundError("no such break-glass grant")
            if ctx is not None and rows[0]["org_id"] != ctx.org_id:
                print("[!] Forbidden")
                sys.exit(11)
            import breakglass_service as _bg_mod
            _bg = _bg_mod.BreakGlassService(svc, id_svc)
            out = _bg.end(args.grant,
                          actor=ctx.label() if ctx else "cli",
                          reason=getattr(args, "reason", "") or "")
            print(f"[✓] Break-glass {out['id']} ended: {out['ended']}")
            return
    except Exception as e:
        msg = getattr(e, "user_message", lambda: str(e))()
        print(f"[!] {msg}")
        sys.exit(getattr(e, "exit_code", 1))
    print("[!] Unknown auth action")
    sys.exit(2)


def _user_by_ident(id_svc, ident: str):
    """Phase-8 CLI accepts a platform user ID OR a username/email."""
    try:
        return id_svc.user_get(str(ident))
    except Exception:
        rows = id_svc.db.query(
            "SELECT id FROM users WHERE username=? OR email=? LIMIT 1",
            (str(ident), str(ident)))
        if rows:
            return id_svc.user_get(rows[0]["id"])
        raise errors_mod().NotFoundError("no such user")


def _scim_rows(svc, org_id: str) -> list:
    """SCIM credentials of an org (read-only CLI view; never secrets)."""
    return svc.db.query(
        "SELECT id, org_id, name, key_prefix, max_role, status, "
        "last_used_at, expires_at FROM scim_credentials WHERE org_id=? "
        "ORDER BY created_at LIMIT 200", (org_id,))


def _scim_row(svc, cred_id: str):
    rows = svc.db.query(
        "SELECT id, org_id, name FROM scim_credentials WHERE id=? LIMIT 1",
        (cred_id,))
    if not rows:
        sys.exit(11)
    return rows[0]


def host_of(url):
    return url.replace("https://", "").replace("http://", "").split("/")[0].replace(":", "_").replace(".", "_")


def cmd_scim_server(args):
    """SCIM 2.0 HTTP surface (Phase 8 §36): Users/Groups provisioning."""
    svc, id_svc = _auth_stack(args)
    import scim_service as _ss
    import scim_server as _srv
    service = _ss.ScimService(svc, identity_svc=id_svc)
    rc = _srv.serve(service,
                    host=getattr(args, "host", "127.0.0.1") or "127.0.0.1",
                    port=int(getattr(args, "port", 8801) or 8801),
                    threads=int(getattr(args, "threads", 8) or 8),
                    quiet=bool(getattr(args, "quiet", False)))
    sys.exit(rc or 0)


def cmd_audit(args):
    """FULL pipeline: ports (Rust) + web audit + API audit + PDF + HTML."""
    guard(args.url)
    host = host_of(args.url)
    print("=" * 62)
    print("  SECUTOOLKIT — FULL SECURITY ASSESSMENT")
    print(f"  Target: {args.url}")
    print("=" * 62)

    # 1. Rust port scan
    print("\n[1/4] Port scan (Rust, concurrent)…")
    from urllib.parse import urlparse
    scan_host = urlparse(args.url if "://" in args.url else "http://" + args.url).hostname or ""
    run_rust("port_scanner.rs", scan_host, "--top", "100")

    # 2. Web audit
    print("\n[2/4] Web security audit…")
    web_json = f"results_{host}.json"
    run_py("web_security_audit.py", "--url", args.url, "--out", f"report_{host}.html",
           "--json", web_json)

    # 3. API audit
    print("\n[3/4] API security audit…")
    api_json = f"api_{host}.json"
    run_py("api_security_audit.py", "--url", args.url, "--json", api_json)

    # 4. Merge + PDF
    print("\n[4/4] Generating PDF report…")
    try:
        with open(web_json, encoding="utf-8") as f:
            web = json.load(f)
        with open(api_json, encoding="utf-8") as f:
            api = json.load(f)
        merged = dict(web)
        merged["tool"] = "SecuToolkit (Web + API)"
        for fnd in api.get("findings", []):
            if fnd not in merged["findings"]:
                merged["findings"].append(fnd)
        merged["summary"] = {}
        for fnd in merged["findings"]:
            sev = fnd["severity"]
            merged["summary"][sev] = merged["summary"].get(sev, 0) + 1
        # re-score roughly
        weights = {"Critical": 25, "High": 14, "Medium": 8, "Low": 4}
        score = 100.0
        for fnd in merged["findings"]:
            score -= weights.get(fnd["severity"], 0)
        merged["score"] = round(max(0.0, score), 1)
        merged["grade"] = ("A" if merged["score"] >= 90 else "B" if merged["score"] >= 75 else
                           "C" if merged["score"] >= 60 else "D" if merged["score"] >= 45 else
                           "E" if merged["score"] >= 30 else "F")
        combined = f"combined_{host}.json"
        with open(combined, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)
        run_py("pdf_report.py", "--json", combined, "--out", f"report_{host}.pdf",
               "--title", f"Security Assessment — {args.url}")
        run_py("sarif_export.py", "--json", combined, "--out", f"report_{host}.sarif")
        print(f"\n✅ DONE. Files: report_{host}.html | report_{host}.pdf | "
              f"report_{host}.sarif | {combined}")
    except Exception as e:
        print(f"[!] PDF merge failed: {e}")


def cmd_demo(args):
    """Spin up a local vulnerable-ish demo server and audit it."""
    import http.server
    import socketserver
    import threading

    port = args.port or 8899
    root = tempfile.mkdtemp(prefix="secutoolkit_demo_")
    with open(os.path.join(root, "index.html"), "w") as f:
        f.write("<html><body><h1>Demo Bank Portal</h1></body></html>")
    with open(os.path.join(root, ".env"), "w") as f:
        f.write("DB_PASSWORD=supersecret\nSECRET_KEY=demo-secret\n")
    with open(os.path.join(root, "admin"), "w") as f:
        f.write("admin panel placeholder")
    os.makedirs(os.path.join(root, "backup"), exist_ok=True)
    with open(os.path.join(root, "backup", "db.sql"), "w") as f:
        f.write("CREATE TABLE users...;")

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass

    handler = lambda *a, **kw: Quiet(*a, directory=root, **kw)
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        print(f"[*] Demo server on http://127.0.0.1:{port} (has .env, backup/db.sql, admin/)")
        time.sleep(1)
        cmd_audit(argparse.Namespace(url=f"http://127.0.0.1:{port}"))


def main():
    # ensure the python/ package modules are importable while the parser
    # tree is built (Phase 3 profile registry is validated at parse time)
    sys.path.insert(0, PY)
    ap = argparse.ArgumentParser(description="SecuToolkit — unified CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("web", help="Web security audit")
    p.add_argument("url"); p.add_argument("--out"); p.add_argument("--json")
    p.set_defaults(fn=cmd_web)

    p = sub.add_parser("api", help="API security audit")
    p.add_argument("url"); p.add_argument("--json")
    p.set_defaults(fn=cmd_api)

    p = sub.add_parser("ports", help="Port scan (Rust)")
    p.add_argument("host"); p.add_argument("ports", nargs="?")
    p.set_defaults(fn=cmd_ports)

    p = sub.add_parser("fuzz", help="Directory fuzzer (Rust)")
    p.add_argument("url")
    p.set_defaults(fn=cmd_fuzz)

    p = sub.add_parser("phishing", help="Phishing URL analysis")
    p.add_argument("url", nargs="?")
    p.add_argument("--file"); p.add_argument("--json")
    p.set_defaults(fn=cmd_phishing)

    p = sub.add_parser("cve", help="CVE lookup (internet)")
    p.add_argument("--vendor"); p.add_argument("--product"); p.add_argument("--cve")
    p.add_argument("--top", type=int, default=10)
    p.set_defaults(fn=cmd_cve)

    p = sub.add_parser("logs", help="Access log IDS")
    p.add_argument("--log", required=True); p.add_argument("--json")
    p.set_defaults(fn=cmd_logs)

    p = sub.add_parser("passwd", help="Password audit")
    p.add_argument("--password", required=True)
    p.set_defaults(fn=cmd_passwd)

    p = sub.add_parser("report", help="PDF from findings JSON")
    p.add_argument("--json", required=True); p.add_argument("--out"); p.add_argument("--title")
    p.set_defaults(fn=cmd_report_pdf)

    p = sub.add_parser("scan", help="Template scan (Nuclei-style YAML engine)")
    p.add_argument("url")
    p.add_argument("--templates")
    p.add_argument("--out")
    p.add_argument("--sarif", help="Also write SARIF (CI/CD)")
    p.add_argument("--cookie")
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("spider", help="Crawler / endpoint discovery")
    p.add_argument("url")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--limit", type=int, default=60)
    p.add_argument("--cookie")
    p.add_argument("--out")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(fn=cmd_spider)

    p = sub.add_parser("sarif", help="Findings JSON -> SARIF 2.1.0")
    p.add_argument("--json", required=True)
    p.add_argument("--out", default="results.sarif")
    p.set_defaults(fn=cmd_sarif)

    p = sub.add_parser("active", help="Active fuzzing: SQLi/XSS/CMDi/traversal (AUTHORIZED ONLY)")
    p.add_argument("url")
    p.add_argument("--param", help="Parameter to fuzz (default: first query param)")
    p.add_argument("--type", default="auto", choices=["auto", "sqli", "xss", "cmdi", "traversal"])
    p.add_argument("--delay", type=float, default=0.4)
    p.add_argument("--max", type=int, default=40)
    p.add_argument("--cookie")
    p.add_argument("--skip-timebased", action="store_true")
    p.add_argument("--out")
    p.add_argument("--sarif")
    p.set_defaults(fn=cmd_active)

    p = sub.add_parser("waf", help="WAF fingerprinting (Cloudflare/AWS/ModSecurity/etc.)")
    p.add_argument("url")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_waf)

    p = sub.add_parser("subdomain", help="Subdomain enumeration (crt.sh + DNS brute)")
    p.add_argument("domain")
    p.add_argument("--wordlist", help="Custom wordlist file")
    p.add_argument("--threads", type=int, default=100)
    p.add_argument("--timeout", type=float, default=4.0)
    p.add_argument("--no-crt", action="store_true")
    p.add_argument("--no-brute", action="store_true")
    p.add_argument("--resolve", action="store_true", help="Resolve IPs for all names")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_subdomain)

    p = sub.add_parser("cloud", help="Cloud/DB exposure checker (S3/GCS/Azure/Redis/Mongo/ES)")
    p.add_argument("--bucket", help="S3+GCS bucket name")
    p.add_argument("--azure", help="Azure storage account")
    p.add_argument("--container", help="Azure container (with --azure)")
    p.add_argument("--service", help="Host[:port] for Redis/Mongo/ES/Memcached")
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--out")
    p.set_defaults(fn=cmd_cloud)

    p = sub.add_parser("dashboard", help="SecuPulse — findings web portal (local/SaaS-style)")
    p.add_argument("--root", default="results", help="Results dir (subdirs = clients)")
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind address (default 127.0.0.1; non-loopback requires --token)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument(
        "--token",
        default=None,
        help="Bearer token for compatibility (prefer SECURITY_TOOLKIT_DASHBOARD_TOKEN env var)",
    )
    p.add_argument("--jobs-db", default=None,
                   help="Platform SQLite — adds the Phase-3 scan-jobs ops "
                        "panel (/jobs, /api/jobs), same token gate")
    p.add_argument("--jobs-org", default="",
                   help="Job panel org filter (multi-tenant: one dashboard "
                        "per org — no job id crosses tenants)")
    p.add_argument("--intel-db", default=None,
                   help="Platform SQLite — adds the Phase-4 intelligence "
                        "panel (/api/intel*), same token gate")
    p.add_argument("--intel-org", default="",
                   help="Intelligence org filter (one dashboard per org)")
    p.add_argument("--identity-db", default=None,
                   help="Platform SQLite — adds the Phase-8 identity panel "
                        "(/identity, /api/identity), same token gate")
    p.add_argument("--identity-org", default="",
                   help="Identity org filter (one dashboard per org)")
    p.set_defaults(fn=cmd_dashboard)

    p = sub.add_parser("hunt", help="⭐ Part 7: full bug-bounty chain (subdomain→probe→"
                                    "crawl→templates→[fuzz]) in ONE command")
    p.add_argument("domain")
    p.add_argument("--client", default="default", help="results/<client>/ folder")
    p.add_argument("--hosts", default=None, help="Comma-separated hosts (skip recon)")
    p.add_argument("--no-crt", action="store_true")
    p.add_argument("--no-brute", action="store_true")
    p.add_argument("--no-takeover", action="store_true")
    p.add_argument("--no-waf", action="store_true")
    p.add_argument("--wordlist", default=None)
    p.add_argument("--threads", type=int, default=50)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--max-hosts", type=int, default=40)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--active", action="store_true",
                   help="📛 ACTIVE fuzzing — authorized targets ONLY")
    p.add_argument("--payloads", type=int, default=5)
    p.add_argument("--delay", type=float, default=0.6)
    p.add_argument("--cookie", default=None)
    p.add_argument("--headers", default=None, help='JSON extra headers')
    p.add_argument("--sarif", default=None)
    p.set_defaults(fn=cmd_hunt)

    p = sub.add_parser("platform", help="Phase 1: orgs/projects/assets/scans/"
                                        "findings/scope/audit (SQLite)")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("init", help="Initialize platform config + schema")
    q = pp.add_parser("org-create")
    q.add_argument("name")
    q = pp.add_parser("org-list")
    q = pp.add_parser("project-create")
    q.add_argument("--org", required=True)
    q.add_argument("name")
    q.add_argument("--description", default="")
    q = pp.add_parser("project-list")
    q.add_argument("--org", default=None)
    q = pp.add_parser("asset-add")
    q.add_argument("--project", required=True)
    q.add_argument("--type", required=True,
                   choices=["domain", "subdomain", "ip", "url", "api",
                            "service", "certificate", "cloud_resource"],
                   dest="asset_type")
    q.add_argument("value")
    q = pp.add_parser("asset-list")
    q.add_argument("--project", required=True)
    q.add_argument("--type", default=None)
    q = pp.add_parser("scope-set")
    q.add_argument("--project", required=True)
    q.add_argument("--allow", default="", help="Comma-separated allow entries")
    q.add_argument("--deny", default="", help="Comma-separated deny entries")
    q = pp.add_parser("scope-check")
    q.add_argument("--project", required=True)
    q.add_argument("--target", required=True)
    q = pp.add_parser("scan-create")
    q.add_argument("--project", required=True)
    q.add_argument("--profile", required=True)
    q.add_argument("--scope", default="")
    # Phase 3: scan-create also queues the initial execution job when a
    # registered profile + target are given (compatible otherwise)
    q.add_argument("--target", default="",
                   help="Execution target (job payload; must be in scope)")
    q.add_argument("--priority", default="normal",
                   choices=["critical", "high", "normal", "low"])
    q.add_argument("--active", action="store_true",
                   help="Enable ACTIVE scanning for this job (AUTHORIZED "
                        "targets only; never default)")
    q.add_argument("--attempts", type=int, default=3)
    q.add_argument("--timeout", type=int, default=0,
                   help="Job timeout seconds (default: profile timeout)")
    q.add_argument("--no-job", action="store_true",
                   help="Do NOT create the initial execution job")
    q = pp.add_parser("scan-status")
    q.add_argument("scan_id")
    q.add_argument("--status", default="running",
                   choices=["queued", "running", "paused", "cancelling",
                            "completed", "failed", "cancelled"])
    q = pp.add_parser("scan-list")
    q.add_argument("--project", required=True)
    q = pp.add_parser("finding-list")
    q.add_argument("--project", required=True)
    q.add_argument("--severity", default=None,
                   choices=["Critical", "High", "Medium", "Low", "Info"])
    q = pp.add_parser("finding-status")
    q.add_argument("finding")
    q.add_argument("--status", required=True,
                   choices=["open", "acknowledged", "confirmed",
                            "in_review", "resolved", "remediated",
                            "false_positive", "accepted_risk", "reopened"])
    # ---- Phase 4: asset + finding intelligence -------------------------
    q = pp.add_parser("asset-intel")
    q.add_argument("asset", help="Asset id")
    q = pp.add_parser("asset-history")
    q.add_argument("asset")
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("asset-relations")
    q.add_argument("asset")
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("asset-exposure")
    q.add_argument("asset")
    q = pp.add_parser("asset-criticality")
    q.add_argument("asset")
    q.add_argument("--level", required=True,
                   choices=["critical", "high", "medium", "low", "unknown"],
                   help="Manager-only control (RBAC asset.criticality)")
    q = pp.add_parser("asset-impact")
    q.add_argument("asset")
    q.add_argument("--tag", action="append", default=[],
                   choices=["customer_facing", "authentication_system",
                            "payment_related", "sensitive_data",
                            "administrative_system", "production_system",
                            "internal_only", "internet_exposed"])
    q = pp.add_parser("finding-show")
    q.add_argument("finding")
    q.add_argument("--no-evidence", action="store_true")
    q = pp.add_parser("finding-history")
    q.add_argument("finding")
    q = pp.add_parser("finding-correlate")
    q.add_argument("finding")
    q = pp.add_parser("finding-false-positive")
    q.add_argument("finding")
    q.add_argument("--reason", required=True)
    q.add_argument("--until", default="", help="ISO time (suppression only)")
    q.add_argument("--suppress", action="store_true",
                   help="Hide from open lists until --until (never deleted)")
    q = pp.add_parser("finding-accept-risk")
    q.add_argument("finding")
    q.add_argument("--reason", required=True)
    q.add_argument("--until", default="", help="ISO time (optional expiry)")
    q.add_argument("--review-at", default="", help="ISO review date")
    q = pp.add_parser("risk-show")
    q.add_argument("finding")
    q = pp.add_parser("risk-history")
    q.add_argument("finding")
    q.add_argument("--limit", type=int, default=100)
    q = pp.add_parser("cluster-list")
    q.add_argument("--project", required=True)
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("cluster-show")
    q.add_argument("cluster")
    q = pp.add_parser("remediation-list")
    q.add_argument("--project", required=True)
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("graph-list")
    q.add_argument("--project", required=True)
    q.add_argument("--limit", type=int, default=100)
    q = pp.add_parser("priority-list")
    q.add_argument("--project", required=True)
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("scan-diff")
    q.add_argument("--project", required=True)
    q.add_argument("--scan", default="", help="Capture scan N as current")
    q.add_argument("--from-scan", default="")
    q.add_argument("--to-scan", default="")
    q = pp.add_parser("scan-diff-get")
    q.add_argument("diff")
    q = pp.add_parser("baseline-status")
    q.add_argument("--project", required=True)
    q = pp.add_parser("rebuild-intel")
    q.add_argument("--project", required=True)
    q = pp.add_parser("ingest")
    q.add_argument("--project", required=True)
    q.add_argument("--json", required=True, help="Scanner result JSON file")
    q = pp.add_parser("audit")
    q.add_argument("--project", default=None)
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("audit-verify", help="Tamper-evidence check of the "
                                           "audit chain")
    p.set_defaults(fn=cmd_platform)
    # --as TOKEN: enforce RBAC + tenant isolation on every platform action
    # (each subparser gets its own flag so the option may come after action)
    for _q in pp.choices.values():
        _q.add_argument("--as", dest="as_token", default=None,
                        help="Session/API token enabling RBAC enforcement "
                             "(session may need platform.enabled)")
        _q.add_argument("--db", default=None,
                        help="Platform SQLite path (default: config layout)")

    # ---- Phase 9: cloud / container / Kubernetes / IaC security --------
    p = sub.add_parser("cloudsec", help="Phase 9: cloud/container/K8s/IaC "
                                        "security (single finding pipeline)")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("profiles", help="List in-process Phase-9 profiles")
    q = pp.add_parser("account-add")
    q.add_argument("--org", default=None)
    q.add_argument("--provider", required=True,
                   choices=["aws", "azure", "gcp", "fixture"])
    q.add_argument("--account-id", dest="account_id", required=True)
    q.add_argument("--name", default="")
    q.add_argument("--credential-ref", dest="credential_ref", default="")
    q.add_argument("--credential-secret", dest="credential_secret",
                   default="")
    q = pp.add_parser("account-list")
    q.add_argument("--org", default=None)
    q = pp.add_parser("account-scan")
    q.add_argument("--org", default=None)
    q.add_argument("--project", required=True)
    q.add_argument("--account", required=True,
                   help="Internal cloud account id (from account-list)")
    q = pp.add_parser("image-add")
    q.add_argument("--org", default=None)
    q.add_argument("--registry", default="")
    q.add_argument("--repository", required=True)
    q.add_argument("--digest", required=True,
                   help="sha256:<64 hex> — immutable identity")
    q = pp.add_parser("image-list")
    q.add_argument("--org", default=None)
    q = pp.add_parser("image-scan")
    q.add_argument("--org", default=None)
    q.add_argument("--project", required=True)
    q.add_argument("--image", required=True)
    q.add_argument("--meta", default="",
                   help="comma-separated k=v observation metadata")
    q = pp.add_parser("cluster-add")
    q.add_argument("--org", default=None)
    q.add_argument("--name", required=True)
    q.add_argument("--endpoint", default="")
    q.add_argument("--credential-ref", dest="credential_ref", default="")
    q.add_argument("--credential-secret", dest="credential_secret",
                   default="")
    q = pp.add_parser("cluster-list")
    q.add_argument("--org", default=None)
    q = pp.add_parser("cluster-scan")
    q.add_argument("--org", default=None)
    q.add_argument("--project", required=True)
    q.add_argument("--cluster", required=True)
    q.add_argument("--manifest", default="",
                   help="YAML manifest path (bounded)")
    q.add_argument("--namespace", default="")
    q = pp.add_parser("iac-scan")
    q.add_argument("--org", default=None)
    q.add_argument("--project", required=True)
    q.add_argument("--file", action="append", default=[],
                   help="IaC file path (repeatable)")
    q.add_argument("--source", default="repository")
    q.add_argument("--fmt", default="auto",
                   choices=["auto", "terraform", "cloudformation",
                            "yaml", "json"])
    q = pp.add_parser("findings")
    q.add_argument("--org", default=None)
    q.add_argument("--limit", type=int, default=20)
    for _q in pp.choices.values():
        _q.add_argument("--as", dest="as_token", default=None,
                        help="Session/API token enabling RBAC enforcement")
        _q.add_argument("--db", default=None,
                        help="Platform SQLite path (default: config layout)")
    p.set_defaults(fn=cmd_cloudsec)

    # ---- Phase 3: job queue + worker runtime ---------------------------
    p = sub.add_parser("scan-job", help="Phase 3: persistent scan job queue "
                                        "(create/list/status/pause/resume/"
                                        "cancel/retry)")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("create")
    q.add_argument("--scan", required=True, help="Scan id (scan-create's id)")
    q.add_argument("--project", required=True)
    q.add_argument("--profile", required=True,
                   choices=sorted(_SCANNER_PROFILES()),
                   help="Registered scanner profile (allowlist only)")
    q.add_argument("--target", default="",
                   help="Target passed to the scanner (must be in scope)")
    q.add_argument("--priority", default="normal",
                   choices=["critical", "high", "normal", "low"])
    q.add_argument("--active", action="store_true",
                   help="Enable ACTIVE scanning (AUTHORIZED only, opt-in)")
    q.add_argument("--attempts", type=int, default=3)
    q.add_argument("--timeout", type=int, default=300)
    q.add_argument("--param", default="", help="Payload extra (active/fuzz)")
    q.add_argument("--bucket", default="", help="Payload extra (cloud-check)")
    q.add_argument("--service", default="", help="Payload extra (cloud-check)")
    q.add_argument("--limit", type=int, default=0, help="Payload extra")
    q.add_argument("--depth", type=int, default=0, help="Payload extra")
    q.add_argument("--threads", type=int, default=0, help="Payload extra")
    q.add_argument("--max", type=int, default=0, help="Payload extra "
                                                      "(active fuzz)")
    q = pp.add_parser("list")
    q.add_argument("--project", default=None)
    q.add_argument("--status", default=None,
                   choices=["created", "queued", "running", "paused",
                            "retry_wait", "cancelling", "completed",
                            "failed", "cancelled", "dead_letter"])
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("status")
    q.add_argument("job", help="Job id (also shows stage checkpoints)")
    q = pp.add_parser("pause")
    q.add_argument("job")
    q = pp.add_parser("resume")
    q.add_argument("job")
    q = pp.add_parser("cancel")
    q.add_argument("job")
    q = pp.add_parser("retry")
    q.add_argument("job", help="Re-queue a failed/dead-letter job "
                               "(attempts reset)")
    for _q in pp.choices.values():
        _q.add_argument("--as", dest="as_token", default=None,
                        help="Token enabling RBAC+tenancy enforcement")
        _q.add_argument("--db", default=None)
    p.set_defaults(fn=cmd_scan_job)

    p = sub.add_parser("scan-worker", help="Phase 3: local worker runtime")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("run", help="Execute queued jobs (local process)")
    q.add_argument("--once", type=int, default=0,
                   help="Stop after N jobs (default: run until stopped)")
    q.add_argument("--heartbeat", type=float, default=15.0)
    q.add_argument("--worker-id", default="")
    q = pp.add_parser("status", help="Workers, job counts, metrics")
    for _q in pp.choices.values():
        _q.add_argument("--as", dest="as_token", default=None)
        _q.add_argument("--db", default=None)
    p.set_defaults(fn=cmd_scan_worker)

    # ---- Phase 2: identity / auth --------------------------------------
    p = sub.add_parser("scim-server",
                       help="Phase 8: SCIM 2.0 provisioning HTTP surface (§36)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=8801, type=int)
    p.add_argument("--threads", default=8, type=int)
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(fn=cmd_scim_server)
    p = sub.add_parser("auth", help="Phase 2: users, roles, sessions, "
                                    "API keys, resets (RBAC + tenants)")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("bootstrap-owner",
                      help="WORKS ONLY with no users yet: create the first "
                           "owner of an org (local setup)")
    q.add_argument("--org", required=True)
    q.add_argument("--username", required=True)
    q.add_argument("--email", required=True)
    q.add_argument("--password", default=None,
                   help="or set env SECTOOLKIT_PASSWORD / prompt")
    q = pp.add_parser("user-create")
    q.add_argument("--org", required=True)
    q.add_argument("--username", required=True)
    q.add_argument("--email", required=True)
    q.add_argument("--display", default="")
    q.add_argument("--roles", default="viewer", help="comma-separated")
    q.add_argument("--password", default=None)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("user-list")
    q.add_argument("--org", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("user-disable")
    q.add_argument("user")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("user-enable")
    q.add_argument("user")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("role-set")
    q.add_argument("user")
    q.add_argument("--roles", required=True, help="comma-separated roles")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("set-password")
    q.add_argument("user")
    q.add_argument("--password", default=None)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("login", help="Password login -> session token "
                                    "(printed once)")
    q.add_argument("identifier", help="email or username")
    q.add_argument("--password", default=None,
                   help="or env SECTOOLKIT_PASSWORD / prompt")
    q.add_argument("--ip", default="cli")
    q = pp.add_parser("logout")
    q.add_argument("--token", required=True)
    q = pp.add_parser("key-create", help="API key (secret printed once)")
    q.add_argument("--org", required=True)
    q.add_argument("--name", required=True)
    q.add_argument("--scopes", default="",
                   help="comma-separated permissions (default: none)")
    q.add_argument("--project", default="", help="bind key to one project")
    q.add_argument("--ttl", type=int, default=0, help="expiry in seconds")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("key-list")
    q.add_argument("--org", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("key-revoke")
    q.add_argument("key")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("key-rotate")
    q.add_argument("key")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("password-reset", help="Request one-time reset token "
                                             "(no email delivery — printed "
                                             "once, service boundary)")
    q.add_argument("identifier")
    q = pp.add_parser("reset-consume")
    q.add_argument("--token", required=True)
    q.add_argument("--password", default=None)
    # -------- Phase 8: enterprise identity (MFA / SSO / SCIM / sessions) ----
    q = pp.add_parser("mfa-status")
    q.add_argument("user")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("mfa-enroll", help="Prepare TOTP enrollment (activation "
                                        "requires mfa-verify)")
    q.add_argument("user")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("mfa-verify", help="Verify the enrollment code -> MFA "
                                         "becomes active")
    q.add_argument("user")
    q.add_argument("--code", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("mfa-challenge", help="Complete an MFA challenge for a "
                                            "pending session")
    q.add_argument("user")
    q.add_argument("--code", required=True)
    q.add_argument("--session", default="")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("mfa-disable")
    q.add_argument("user")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("mfa-recovery-generate",
                      help="Rotate recovery codes (printed once)")
    q.add_argument("user")
    q.add_argument("--count", type=int, default=10)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("mfa-recovery-list")
    q.add_argument("user")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("mfa-reset", help="Admin reset: void codes, revoke "
                                        "sessions, force re-enroll")
    q.add_argument("user")
    q.add_argument("--no-reenroll", action="store_true")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("policy-get")
    q.add_argument("--org", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("policy-set")
    q.add_argument("--org", required=True)
    q.add_argument("--mode", default="optional",
                   choices=["optional", "roles", "required"])
    q.add_argument("--roles", default="", help="comma-separated roles")
    q.add_argument("--step-up-ttl", type=int, default=600)
    q.add_argument("--require-recent", type=int, default=900)
    q.add_argument("--version", type=int, default=0,
                   help="optimistic concurrency (0 = last-write-wins)")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-provider-create")
    q.add_argument("--org", required=True)
    q.add_argument("--type", required=True, choices=["oidc", "saml"])
    q.add_argument("--name", required=True)
    q.add_argument("--config", default="{}",
                   help="provider configuration JSON (secrets are encrypted "
                        "at rest and never shown again)")
    q.add_argument("--enabled", action="store_true")
    q.add_argument("--jit", action="store_true")
    q.add_argument("--default-roles", default="")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-provider-list")
    q.add_argument("--org", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-provider-get")
    q.add_argument("provider")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-provider-update")
    q.add_argument("provider")
    q.add_argument("--name", default="")
    q.add_argument("--enabled", action="store_true", default=None)
    q.add_argument("--version", type=int, default=0)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-provider-delete")
    q.add_argument("provider")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-domain-add")
    q.add_argument("--org", required=True)
    q.add_argument("--provider", required=True)
    q.add_argument("--domain", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-domain-list")
    q.add_argument("--org", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-domain-remove")
    q.add_argument("--org", required=True)
    q.add_argument("--domain", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-mapping-set",
                      help="Map an IdP group to an EXISTING RBAC role")
    q.add_argument("--org", required=True)
    q.add_argument("--group", required=True)
    q.add_argument("--role", required=True)
    q.add_argument("--provider", default="", help="'' = all providers")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-mapping-remove")
    q.add_argument("--org", required=True)
    q.add_argument("--group", required=True)
    q.add_argument("--provider", default="")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-mapping-list")
    q.add_argument("--org", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-oidc-start",
                      help="Print the authorization URL (state+nonce "
                           "single-use)")
    q.add_argument("--provider", required=True)
    q.add_argument("--redirect", default="")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sso-saml-start",
                      help="Print the AuthnRequest URL (single-use)")
    q.add_argument("--provider", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sessions-list")
    q.add_argument("--org", required=True)
    q.add_argument("--status", default="active",
                   choices=["active", "revoked", "all"])
    q.add_argument("--limit", type=int, default=100)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("session-revoke", help="Revoke one session (own or "
                                             "same-tenant)")
    q.add_argument("session")
    q.add_argument("--reason", default="cli_revoke")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sessions-revoke-user")
    q.add_argument("user")
    q.add_argument("--reason", default="admin_revoke")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("sessions-revoke-org",
                      help="Emergency org-wide revocation (bounded)")
    q.add_argument("--org", required=True)
    q.add_argument("--reason", default="org_revoke")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("scim-cred-create",
                      help="SCIM provisioning credential (secret printed once)")
    q.add_argument("--org", required=True)
    q.add_argument("--name", required=True)
    q.add_argument("--max-role", default="analyst",
                   help="cap on any role SCIM may grant")
    q.add_argument("--ttl", type=int, default=0, help="expiry seconds (0=none)")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("scim-cred-list")
    q.add_argument("--org", required=True)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("scim-cred-revoke")
    q.add_argument("cred")
    q.add_argument("--as", dest="as_token", default=None)
    # -------- Phase 8: break-glass emergency access (§15) -------------------
    q = pp.add_parser("break-glass-start",
                      help="Mint a short-lived audited emergency grant "
                           "(requires --as with a verified step-up context)")
    q.add_argument("user", help="platform user id or username/email")
    q.add_argument("--org", required=True)
    q.add_argument("--reason", required=True,
                   help="mandatory incident reason (8-200 chars)")
    q.add_argument("--ttl", default=0, type=int,
                   help="seconds (60-3600; default 600)")
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("break-glass-status",
                      help="List grants of an org (never secrets)")
    q.add_argument("--org", required=True)
    q.add_argument("--status", default="all",
                   choices=("all", "active", "ended"))
    q.add_argument("--limit", default=20, type=int)
    q.add_argument("--as", dest="as_token", default=None)
    q = pp.add_parser("break-glass-end",
                      help="Explicitly end a grant (idempotent)")
    q.add_argument("grant")
    q.add_argument("--reason", default="")
    q.add_argument("--as", dest="as_token", default=None)
    p.set_defaults(fn=cmd_auth)

    # ---- Phase 5: monitoring / alerts / remediation / notifications ----
    p = sub.add_parser("monitor", help="Phase 5: continuous monitoring, "
                                       "alert rules, remediation tickets, "
                                       "notifications (RBAC + tenants)")
    pp = p.add_subparsers(dest="action", required=True)
    _M_SCHEMES = ("interval", "daily", "weekly", "manual")
    _M_MISSED = ("skip", "run_once", "catch_up")
    q = pp.add_parser("policy-create")
    q.add_argument("--project", required=True)
    q.add_argument("--name", required=True)
    q.add_argument("--profile", required=True,
                   choices=sorted(_SCANNER_PROFILES()))
    q.add_argument("--schedule", default="interval", choices=_M_SCHEMES)
    q.add_argument("--interval", type=int, default=1440)
    q.add_argument("--daily-time", dest="daily_time", default="08:00")
    q.add_argument("--weekly-day", type=int, default=1)
    q.add_argument("--weekly-time", dest="weekly_time", default="08:00")
    q.add_argument("--target", action="append", default=[],
                   help="In-scope target (repeatable; allowlist only)")
    q.add_argument("--active", action="store_true",
                   help="Permit ACTIVE scan profiles (same authorization "
                        "as manual active scans)")
    q.add_argument("--priority", default="normal",
                   choices=["critical", "high", "normal", "low"])
    q.add_argument("--timeout", type=int, default=0)
    q.add_argument("--missed", default="skip", choices=_M_MISSED)
    q.add_argument("--concurrent", type=int, default=1)
    q = pp.add_parser("policy-list")
    q.add_argument("--project", default=None)
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("policy-show")
    q.add_argument("policy")
    q = pp.add_parser("policy-enable")
    q.add_argument("policy")
    q = pp.add_parser("policy-disable")
    q.add_argument("policy")
    q = pp.add_parser("policy-delete")
    q.add_argument("policy")
    q = pp.add_parser("run")
    q.add_argument("policy", help="Manual run of a policy (rate-limited)")
    q = pp.add_parser("tick", help="Run the scheduler once (due windows)")
    q = pp.add_parser("health")
    q.add_argument("--project", default=None)
    q = pp.add_parser("rules-install")
    q.add_argument("--project", required=True)
    q = pp.add_parser("alert-list")
    q.add_argument("--project", default=None)
    q.add_argument("--state", default="",
                   choices=["", "open", "acknowledged", "investigating",
                            "resolved", "suppressed", "expired"])
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("alert-show")
    q.add_argument("alert")
    q = pp.add_parser("alert-ack")
    q.add_argument("alert")
    q.add_argument("--reason", default="")
    q = pp.add_parser("alert-resolve")
    q.add_argument("alert")
    q.add_argument("--reason", default="")
    q = pp.add_parser("alert-suppress")
    q.add_argument("alert")
    q.add_argument("--reason", required=True)
    q.add_argument("--until", required=True,
                   help="ISO timestamp (future) when suppression expires")
    q = pp.add_parser("remediation-list")
    q.add_argument("--project", default=None)
    q.add_argument("--status", default="")
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("remediation-show")
    q.add_argument("ticket")
    q = pp.add_parser("remediation-assign")
    q.add_argument("ticket")
    q.add_argument("--type", default="user", choices=["user"])
    q.add_argument("--user", required=True)
    q = pp.add_parser("remediation-status")
    q.add_argument("ticket")
    q.add_argument("--status", required=True,
                   choices=["open", "assigned", "in_progress", "blocked",
                            "ready_for_verification", "verified", "closed",
                            "reopened"])
    q.add_argument("--reason", default="")
    q = pp.add_parser("remediation-verify")
    q.add_argument("ticket", help="Queue a verification scan (bounded)")
    q = pp.add_parser("sla-set")
    q.add_argument("--project", required=True)
    q.add_argument("--priority", required=True,
                   choices=["P0", "P1", "P2", "P3", "P4"])
    q.add_argument("--hours", type=int, required=True)
    q = pp.add_parser("notification-list")
    q.add_argument("--project", default=None)
    q.add_argument("--status", default="")
    q.add_argument("--limit", type=int, default=50)
    q = pp.add_parser("notification-retry")
    q.add_argument("notification")
    q = pp.add_parser("settings-show")
    q.add_argument("--project", required=True)
    q = pp.add_parser("settings-set")
    q.add_argument("--project", required=True)
    q.add_argument("--email-enabled", action="store_true")
    q.add_argument("--email-to", dest="email_to", default="")
    q.add_argument("--webhook-enabled", action="store_true")
    q.add_argument("--webhook-url", dest="webhook_url", default="")
    q.add_argument("--webhook-secret", dest="webhook_secret", default="",
                   help="HMAC signing secret (never printed)")
    q.add_argument("--keep-secret", action="store_true",
                   help="Keep the existing secret when unset")
    q = pp.add_parser("sweep", help="Retention sweep (bounded, audited)")
    q.add_argument("--project", default="")
    q.add_argument("--event-days", type=int, default=180)
    q.add_argument("--attempt-days", type=int, default=90)
    q.add_argument("--exec-days", type=int, default=365)
    for _q in pp.choices.values():
        _q.add_argument("--as", dest="as_token", default=None,
                        help="Token enabling RBAC+tenancy enforcement")
        _q.add_argument("--db", default=None)
    p.set_defaults(fn=cmd_monitor)

    # ---- Phase 6: reporting / analytics / compliance evidence ----------
    # "report" already exists (Phase-1 PDF builder) — the Phase-6 family is
    # "reporting" so nothing pre-existing is removed or renamed.
    p = sub.add_parser("reporting", help="Phase 6: snapshot reporting "
                                         "(generate/list/get/export/delete/"
                                         "share/retention)")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("generate", help="Generate + store a report snapshot")
    q.add_argument("--project", required=True)
    q.add_argument("--type", required=True,
                   choices=["executive", "technical", "asset_inventory",
                            "vulnerability", "remediation", "monitoring",
                            "trend", "compliance_evidence"])
    q.add_argument("--title", default="")
    q.add_argument("--cutoff", default="",
                   help="Data cutoff (ISO datetime; default now)")
    q.add_argument("--format", default="",
                   choices=["", "json", "html", "pdf"])
    q.add_argument("--out", default="")
    q.add_argument("--asset-id", dest="asset_id", default="")
    q.add_argument("--severity", action="append", default=[],
                   choices=["Critical", "High", "Medium", "Low", "Info"])
    q.add_argument("--status", action="append", default=[],
                   choices=["open", "acknowledged", "confirmed",
                            "in_review", "resolved", "remediated",
                            "false_positive", "accepted_risk", "reopened"])
    q.add_argument("--risk-min", dest="risk_min", type=float, default=None)
    q.add_argument("--risk-max", dest="risk_max", type=float, default=None)
    q.add_argument("--exposure", default="",
                   choices=["internet_facing", "internal", "restricted",
                            "unknown"])
    q.add_argument("--criticality", default="",
                   choices=["unknown", "low", "medium", "high", "critical"])
    q.add_argument("--technology", default="")
    q.add_argument("--category", default="",
                   choices=["injection", "xss", "csrf", "auth",
                            "access_control", "tls", "misconfiguration",
                            "exposure", "information_disclosure", "crypto",
                            "deserialization", "ssrf", "rce", "dos",
                            "other"])
    q.add_argument("--start", default="")
    q.add_argument("--end", default="")
    q = pp.add_parser("list", help="List report runs (bounded)")
    q.add_argument("--project", default="")
    q.add_argument("--type", default="")
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--offset", type=int, default=0)
    q = pp.add_parser("get", help="Show report metadata (+payload)")
    q.add_argument("report")
    q.add_argument("--payload", action="store_true")
    q = pp.add_parser("export", help="Export a stored report (json/html/pdf)")
    q.add_argument("report")
    q.add_argument("--format", default="json",
                   choices=["json", "html", "pdf"])
    q.add_argument("--out", default="")
    q = pp.add_parser("delete", help="Delete a non-immutable report (audited)")
    q.add_argument("report")
    q = pp.add_parser("share", help="Record share intent (audit metadata only)")
    q.add_argument("report")
    q.add_argument("--note", default="")
    q = pp.add_parser("retention-sweep",
                      help="Sweep expired non-immutable reports (audited)")
    q.add_argument("--days", type=int, default=90)
    q.add_argument("--project", default="")
    for _q in pp.choices.values():
        _q.add_argument("--as", dest="as_token", default=None,
                        help="Token enabling RBAC+tenancy enforcement")
        _q.add_argument("--db", default=None)
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("analytics", help="Phase 6: read-only security "
                                         "analytics (posture/KPIs/trends)")
    pp = p.add_subparsers(dest="action", required=True)
    for name in ("posture", "kpis", "risk", "risk-buckets", "risk-assets",
                 "trends", "attack-surface", "remediation", "assets",
                 "monitoring", "bundle"):
        q = pp.add_parser(name)
        q.add_argument("--project", required=True)
        q.add_argument("--cutoff", default="")
        q.add_argument("--start", default="")
        q.add_argument("--end", default="")
        if name == "risk-buckets":
            q.add_argument("--width", type=int, default=10,
                           choices=[5, 10, 20])
        if name == "risk-assets":
            q.add_argument("--limit", type=int, default=20)
        q.add_argument("--as", dest="as_token", default=None)
        q.add_argument("--db", default=None)
    q = pp.add_parser("risk-projects",
                      help="Org risk rollup (visible projects only)")
    q.add_argument("--org", default="")
    q.add_argument("--cutoff", default="")
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--as", dest="as_token", default=None)
    q.add_argument("--db", default=None)
    p.set_defaults(fn=cmd_analytics)

    p = sub.add_parser("evidence", help="Phase 6: compliance evidence "
                                        "(generic controls, provenance)")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("refresh", help="Re-derive + upsert evidence registry")
    q.add_argument("--project", required=True)
    q.add_argument("--cutoff", default="")
    q = pp.add_parser("list", help="List evidence items (bounded)")
    q.add_argument("--project", required=True)
    q.add_argument("--category", default="")
    q.add_argument("--limit", type=int, default=100)
    q.add_argument("--offset", type=int, default=0)
    q = pp.add_parser("show")
    q.add_argument("evidence")
    q = pp.add_parser("snapshot",
                      help="Store an immutable evidence snapshot")
    q.add_argument("--project", required=True)
    q.add_argument("--cutoff", default="")
    q = pp.add_parser("export", help="Export evidence registry (json/html/pdf)")
    q.add_argument("--project", required=True)
    q.add_argument("--category", default="")
    q.add_argument("--format", default="json",
                   choices=["json", "html", "pdf"])
    q.add_argument("--out", default="")
    for _q in pp.choices.values():
        _q.add_argument("--as", dest="as_token", default=None)
        _q.add_argument("--db", default=None)
    p.set_defaults(fn=cmd_evidence)

    # ---- Phase 7: DevSecOps security gates + CI runs -------------------
    p = sub.add_parser("devsecops", help="Phase 7: CI/CD security gates "
                                         "(gate/ci/result/export)")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("gate-create", help="Create a security gate")
    q.add_argument("--project", required=True)
    q.add_argument("--name", required=True)
    q.add_argument("--policy", required=True,
                   help="Gate policy JSON (allowlisted conditions)")
    q = pp.add_parser("gate-list", help="List gates (bounded)")
    q.add_argument("--project", required=True)
    q.add_argument("--limit", type=int, default=100)
    q.add_argument("--offset", type=int, default=0)
    q = pp.add_parser("gate-show")
    q.add_argument("gate")
    q = pp.add_parser("gate-update")
    q.add_argument("gate")
    q.add_argument("--name", default="")
    q.add_argument("--enabled", default="", choices=["true", "false"])
    q.add_argument("--policy", default="")
    q = pp.add_parser("gate-delete")
    q.add_argument("gate")
    q = pp.add_parser("ci-create", aliases=["run"],
                      help="Create a CI run (existing Scan + JobService)")
    q.add_argument("--project", required=True)
    q.add_argument("--gate", required=True)
    q.add_argument("--profile", required=True,
                   help="Existing scanner profile allowlist name")
    q.add_argument("--provider", default="",
                   choices=["github", "gitlab", "jenkins", "generic", "local"])
    q.add_argument("--repository", default="")
    q.add_argument("--branch", default="")
    q.add_argument("--commit-sha", dest="commit_sha", default="")
    q.add_argument("--commit-ref", dest="commit_ref", default="")
    q.add_argument("--pipeline-id", dest="pipeline_id", default="")
    q.add_argument("--pipeline-url", dest="pipeline_url", default="")
    q.add_argument("--actor", default="")
    q.add_argument("--trigger", default="",
                   choices=["pull_request", "merge_request", "branch_push",
                            "manual", "scheduled"])
    q.add_argument("--target", default="")
    q.add_argument("--run-key", dest="run_key", default="")
    q.add_argument("--active", action="store_true",
                   help="ACTIVE fuzzing allowed (requires existing explicit "
                        "authorization semantics)")
    q = pp.add_parser("ci-list", help="List CI runs (bounded)")
    q.add_argument("--project", required=True)
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--offset", type=int, default=0)
    q.add_argument("--status", default="")
    q = pp.add_parser("ci-show", help="CI run + scan + job + result status")
    q.add_argument("run")
    q = pp.add_parser("status", help="Alias of ci-show")
    q.add_argument("run")
    q = pp.add_parser("evaluate",
                      help="Run the security gate (exit 0 pass/warn, 1 fail, "
                           "2 inconclusive)")
    q.add_argument("run")
    q = pp.add_parser("result", help="Show a stored gate result")
    q.add_argument("result")
    q = pp.add_parser("export", help="Export result as deterministic JSON or "
                                     "SARIF 2.1.0")
    q.add_argument("result")
    q.add_argument("--format", default="json", choices=["json", "sarif"])
    q.add_argument("--out", default="")
    q = pp.add_parser("report",
                      help="Store the result as a Phase-6 report snapshot "
                           "(CI provenance embedded)")
    q.add_argument("result")
    q.add_argument("--type", default="technical")
    q = pp.add_parser("retention-sweep",
                      help="Bounded retention for non-immutable CI runs")
    q.add_argument("--days", type=int, default=180)
    q.add_argument("--project", default="")
    for _q in {id(x): x for x in pp.choices.values()}.values():
        _q.add_argument("--as", dest="as_token", default=None,
                        help="Token enabling RBAC+tenancy enforcement")
        _q.add_argument("--db", default=None)
    p.set_defaults(fn=cmd_devsecops)

    # ---------------- Phase 10: security operations CLI -------------------
    p = sub.add_parser("security",
                       help="Phase 10: attack surface / threat intel / cases")
    pp = p.add_subparsers(dest="action", required=True)
    q = pp.add_parser("attack-surface",
                      help="External attack-surface operations")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("scan", help="Ingest authorized observations")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", required=True)
    _q.add_argument("--file", default="",
                    help="JSON file: a list of {type,value,confidence,...}")
    _q.add_argument("--entries", default="", help="Inline JSON entries")
    _q.add_argument("--source", default="cli")
    _q = qq.add_parser("list", help="Inventory")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", required=True)
    _q.add_argument("--type", default="")
    q = pp.add_parser("observations", help="Exposure/change events")
    q.add_argument("--org", required=True)
    q.add_argument("--project", required=True)
    q = pp.add_parser("domains", help="Domain/subdomain/hostname inventory")
    q.add_argument("--org", required=True)
    q.add_argument("--project", required=True)
    q = pp.add_parser("certificates", help="Certificate inventory")
    q.add_argument("--org", required=True)
    q.add_argument("--project", required=True)

    q = pp.add_parser("ti", help="Threat-intelligence indicators")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("add")
    _q.add_argument("--org", required=True)
    _q.add_argument("--value", required=True)
    _q.add_argument("--type", default=None)
    _q.add_argument("--source", default="manual")
    _q.add_argument("--confidence", default="medium")
    _q.add_argument("--valid-until", default="")
    _q = qq.add_parser("list", aliases=["indicators"])
    _q.add_argument("--org", required=True)
    _q.add_argument("--type", default="")
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=100)
    _q = qq.add_parser("update")
    _q.add_argument("--org", required=True)
    _q.add_argument("--id", required=True)
    _q.add_argument("--confidence", default=None)
    _q.add_argument("--status", default=None)
    _q.add_argument("--valid-until", default=None)
    _q.add_argument("--reference", default=None)
    _q = qq.add_parser("revoke")
    _q.add_argument("--org", required=True)
    _q.add_argument("--id", required=True)
    _q.add_argument("--reason", required=True)
    _q = qq.add_parser("import")
    _q.add_argument("--org", required=True)
    _q.add_argument("--name", required=True)
    _q.add_argument("--file", required=True)
    _q.add_argument("--fmt", default="auto")
    _q.add_argument("--source-type", default="feed")
    _q.add_argument("--confidence", default="medium")
    _q = qq.add_parser("match")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", required=True)
    _q.add_argument("--min-confidence", default="low")
    _q = qq.add_parser("export")
    _q.add_argument("--org", required=True)
    _q.add_argument("--type", default="")
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=500)
    _q.add_argument("--out", default="-")
    _q = qq.add_parser("source-list")
    _q.add_argument("--org", required=True)

    q = pp.add_parser("case", help="Investigation cases")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("create")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", required=True)
    _q.add_argument("--title", required=True)
    _q.add_argument("--description", default="")
    _q.add_argument("--priority", default="medium")
    _q.add_argument("--owner", default="")
    _q = qq.add_parser("list")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", default="")
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=100)
    _q = qq.add_parser("show")
    _q.add_argument("--org", required=True)
    _q.add_argument("--id", required=True)
    _q = qq.add_parser("update")
    _q.add_argument("--org", required=True)
    _q.add_argument("--id", required=True)
    _q.add_argument("--title", default=None)
    _q.add_argument("--description", default=None)
    _q.add_argument("--priority", default=None)
    _q = qq.add_parser("assign")
    _q.add_argument("--org", required=True)
    _q.add_argument("--id", required=True)
    _q.add_argument("--owner", required=True)
    _q = qq.add_parser("close")
    _q.add_argument("--org", required=True)
    _q.add_argument("--id", required=True)
    _q.add_argument("--reason", required=True)
    _q = qq.add_parser("timeline")
    _q.add_argument("--org", required=True)
    _q.add_argument("--id", required=True)
    _q.add_argument("--limit", type=int, default=100)

    q = pp.add_parser("threat", help="Threat clusters + prioritization")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("clusters")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", default="")
    _q = qq.add_parser("prioritize")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", required=True)

    # ------------------------------------------------ Phase 11 governance
    q = pp.add_parser("data", help="Phase 11: data protection governance")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("classify")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", required=True)
    _q.add_argument("--object-id", default="")
    _q.add_argument("--classification", required=True)
    _q.add_argument("--field", default="")
    _q.add_argument("--project", default="")
    _q.add_argument("--authorized", action="store_true",
                    help="explicit authorization for a downgrade")
    _q = qq.add_parser("classifications")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", default="")
    _q.add_argument("--limit", type=int, default=100)
    _q = qq.add_parser("effective")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", required=True)
    _q.add_argument("--object-id", default="")
    _q = qq.add_parser("export")
    _q.add_argument("--org", required=True)
    _q.add_argument("--scope", default="summary")
    _q.add_argument("--project", default="")
    _q.add_argument("--format", default="json")
    _q.add_argument("--limit", type=int, default=1000)
    _q = qq.add_parser("delete", help="Controlled deletion (blocks on holds)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", required=True)
    _q.add_argument("--object-id", required=True)
    _q.add_argument("--project", default="")
    _q.add_argument("--authorized", action="store_true",
                    help="skip the retention-eligibility guard")
    _q = qq.add_parser("delete-preview")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", required=True)
    _q.add_argument("--object-id", required=True)
    _q.add_argument("--project", default="")
    _q = qq.add_parser("retention")
    _q.add_argument("--org", required=True)
    _q.add_argument("--kind", default="")
    _q.add_argument("--days", type=int, default=0)
    _q.add_argument("--project", default="")
    _q.add_argument("--limit", type=int, default=50)
    _q.add_argument("--batch", type=int, default=5000)
    _q.add_argument("--execute", action="store_true",
                    help="actually delete (default: dry run)")
    _q.add_argument("--action", dest="retention_action", default="preview",
                    help="set|policies|preview|run|runs")
    _q = qq.add_parser("holds")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", default="")
    _q.add_argument("--limit", type=int, default=100)
    _q = qq.add_parser("hold-create")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", required=True)
    _q.add_argument("--object-id", required=True)
    _q.add_argument("--reason", required=True)
    _q.add_argument("--kind", default="other")
    _q.add_argument("--project", default="")
    _q.add_argument("--expires", default="")
    _q = qq.add_parser("hold-release")
    _q.add_argument("--org", required=True)
    _q.add_argument("--hold-id", required=True)
    _q.add_argument("--reason", required=True)

    q = pp.add_parser("secrets", help="Phase 11: secret governance metadata")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("register")
    _q.add_argument("--org", required=True)
    _q.add_argument("--kind", required=True)
    _q.add_argument("--name", default="")
    _q.add_argument("--reference", default="")
    _q.add_argument("--material", default="",
                    help="used ONLY to compute the search hash; never stored")
    _q.add_argument("--project", default="")
    _q.add_argument("--expires", default="")
    _q.add_argument("--rotation-due", default="")
    _q = qq.add_parser("list")
    _q.add_argument("--org", required=True)
    _q.add_argument("--kind", default="")
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=100)
    _q = qq.add_parser("status")
    _q.add_argument("--org", required=True)
    _q = qq.add_parser("set-status")
    _q.add_argument("--org", required=True)
    _q.add_argument("--secret-id", required=True)
    _q.add_argument("--status", required=True)
    _q = qq.add_parser("touch")
    _q.add_argument("--org", required=True)
    _q.add_argument("--secret-id", required=True)
    _q = qq.add_parser("detect")
    _q.add_argument("--org", required=True)
    _q.add_argument("--text", default="")
    _q.add_argument("--file", default="")
    _q = qq.add_parser("sweep")
    _q.add_argument("--org", required=True)

    q = pp.add_parser("privacy", help="Phase 11: privacy request workflow")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("request")
    _q.add_argument("--org", required=True)
    _q.add_argument("--rid", required=True)
    _q = qq.add_parser("requests")
    _q.add_argument("--org", required=True)
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=100)
    _q = qq.add_parser("request-create")
    _q.add_argument("--org", required=True)
    _q.add_argument("--type", required=True)
    _q.add_argument("--subject-ref", required=True)
    _q.add_argument("--project", default="")
    _q.add_argument("--requester", default="")
    _q = qq.add_parser("request-update")
    _q.add_argument("--org", required=True)
    _q.add_argument("--request-id", required=True)
    _q.add_argument("--status", required=True)
    _q.add_argument("--reviewer", default="")
    _q = qq.add_parser("request-complete")
    _q.add_argument("--org", required=True)
    _q.add_argument("--request-id", required=True)
    _q.add_argument("--reviewer", required=True)
    _q = qq.add_parser("request-fail")
    _q.add_argument("--org", required=True)
    _q.add_argument("--request-id", required=True)
    _q.add_argument("--reason", required=True)
    _q = qq.add_parser("scan")
    _q.add_argument("--org", required=True)
    _q.add_argument("--subject-ref", required=True)
    _q.add_argument("--object-type", default="")
    _q = qq.add_parser("cover")
    _q.add_argument("--org", required=True)
    _q.add_argument("--subject-ref", required=True)
    _q.add_argument("--object-type", default="")
    _q.add_argument("--batch", type=int, default=500)
    _q.add_argument("--project", default="")
    _q = qq.add_parser("correct")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", required=True)
    _q.add_argument("--object-id", required=True)
    _q.add_argument("--field", required=True)
    _q.add_argument("--value", required=True)
    _q.add_argument("--authorized", action="store_true")
    _q = qq.add_parser("restrict")
    _q.add_argument("--org", required=True)
    _q.add_argument("--object-type", required=True)
    _q.add_argument("--object-id", required=True)
    _q.add_argument("--fields", required=True, help="comma-separated")
    _q.add_argument("--reason", required=True)

    q = pp.add_parser("compliance", help="Phase 11: compliance evidence")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("controls")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", default="")
    _q = qq.add_parser("gaps")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", default="")
    _q = qq.add_parser("evidence")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", default="")
    _q = qq.add_parser("evaluate")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", default="")
    _q = qq.add_parser("report")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", required=True)
    _q = qq.add_parser("exception")
    _q.add_argument("--org", required=True)
    _q.add_argument("--policy", required=True)
    _q.add_argument("--reason", default="")
    _q.add_argument("--scope", default="")
    _q.add_argument("--approved-by", default="")
    _q.add_argument("--expires", default="")
    _q.add_argument("--project", default="")
    _q.add_argument("--action", dest="exception_action", default="create",
                    help="create|list|revoke|effective|sweep")
    _q.add_argument("--exception-id", default="")
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=100)

    # ------------------------------------------- Phase 12 federation family
    q = pp.add_parser("federation",
                      help="Phase 12: data federation / evidence exchange / "
                           "bulk operations / external integrations")
    qq = q.add_subparsers(dest="sub", required=True)
    _q = qq.add_parser("peer-list")
    _q.add_argument("--org", required=True)
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=100)
    _q = qq.add_parser("peer-create",
                       help="Register a peer (always starts pending)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--peer-org", required=True,
                    help="organization id of the counterparty")
    _q.add_argument("--name", required=True)
    _q.add_argument("--purpose", default="")
    _q.add_argument("--direction", default="outbound",
                    help="outbound|inbound|bidirectional")
    _q.add_argument("--expires-at", default="")
    _q = qq.add_parser("peer-approve",
                       help="Approve a pending peer (approver must differ "
                            "from the creator)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--peer-id", required=True)
    _q.add_argument("--approved-by", default="")
    _q = qq.add_parser("peer-revoke", help="Terminal revocation")
    _q.add_argument("--org", required=True)
    _q.add_argument("--peer-id", required=True)
    _q.add_argument("--reason", required=True)
    _q = qq.add_parser("policy-list")
    _q.add_argument("--org", required=True)
    _q.add_argument("--peer-id", default="")
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=100)
    _q = qq.add_parser("policy-create",
                       help="Exchange policy (secret/authentication "
                            "material require --explicit-sensitive)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--peer-id", required=True)
    _q.add_argument("--name", required=True)
    _q.add_argument("--project", default="")
    _q.add_argument("--object-types", required=True,
                    help="comma-separated (asset,finding,evidence,...)")
    _q.add_argument("--classifications", default="internal",
                    help="comma-separated (public,internal,confidential,...)")
    _q.add_argument("--fields", default="",
                    help='optional JSON {"finding": ["id","title",...]} '
                         "field narrowing")
    _q.add_argument("--max-objects", type=int, default=1000)
    _q.add_argument("--expires-at", default="")
    _q.add_argument("--explicit-sensitive", action="store_true",
                    help="explicit decision required to allow "
                         "secret/authentication_material classes")
    _q = qq.add_parser("policy-update",
                       help="Revalidates the full ruleset; --disable to "
                            "deactivate")
    _q.add_argument("--org", required=True)
    _q.add_argument("--policy-id", required=True)
    _q.add_argument("--name", default="")
    _q.add_argument("--object-types", default="")
    _q.add_argument("--classifications", default="")
    _q.add_argument("--fields", default="")
    _q.add_argument("--max-objects", type=int, default=0)
    _q.add_argument("--expires-at", default="")
    _q.add_argument("--explicit-sensitive", action="store_true")
    _q.add_argument("--disable", action="store_true")
    _q = qq.add_parser("package-create",
                       help="Build a deterministic, minimized evidence "
                            "package (--out writes the transfer envelope)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--peer-id", required=True)
    _q.add_argument("--policy-id", default="")
    _q.add_argument("--project", default="")
    _q.add_argument("--object-types", default="")
    _q.add_argument("--limit", type=int, default=0)
    _q.add_argument("--trust-mode", default="integrity_verified",
                    help="integrity_verified|externally_signed")
    _q.add_argument("--signature-ref", default="",
                    help="external signature REFERENCE (no local PKI is "
                         "claimed)")
    _q.add_argument("--out", default="", help="write envelope JSON here")
    _q = qq.add_parser("package-show", help="Metadata only (never payload)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--package-id", required=True)
    _q = qq.add_parser("package-verify",
                       help="Recompute + compare the integrity hash")
    _q.add_argument("--org", required=True)
    _q.add_argument("--package-id", default="")
    _q.add_argument("--file", default="", help="foreign envelope JSON")
    _q = qq.add_parser("package-import",
                       help="Import a foreign envelope (12 validation "
                            "gates, fail closed)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--file", required=True)
    _q.add_argument("--project", required=True,
                    help="target project in the importing org")
    _q.add_argument("--peer-id", default="")
    _q.add_argument("--collision", default="skip",
                    help="skip|link|merge_metadata|reject")
    _q = qq.add_parser("bulk-export",
                       help="Chunked bulk export via the Phase-3 job engine "
                            "(--now runs synchronously)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", required=True)
    _q.add_argument("--peer-id", required=True)
    _q.add_argument("--policy-id", default="")
    _q.add_argument("--object-types", default="")
    _q.add_argument("--now", action="store_true")
    _q = qq.add_parser("bulk-import",
                       help="Bulk import via the job engine (--now runs "
                            "synchronously)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", required=True)
    _q.add_argument("--file", required=True)
    _q.add_argument("--peer-id", default="")
    _q.add_argument("--collision", default="skip")
    _q.add_argument("--now", action="store_true")
    _q = qq.add_parser("bulk-jobs", help="List federation bulk jobs")
    _q.add_argument("--org", required=True)
    _q.add_argument("--project", default="")
    _q.add_argument("--status", default="")
    _q.add_argument("--limit", type=int, default=50)
    _q = qq.add_parser("audit",
                       help="Federation/integration audit trail (hash-"
                            "chained; metadata only)")
    _q.add_argument("--org", required=True)
    _q.add_argument("--limit", type=int, default=50)

    # common auth switch
    p.add_argument("--db", default=None)
    p.add_argument("--as", dest="as_token", default=None,
                   help="Enforce RBAC with this API token")
    p.set_defaults(fn=cmd_security)

    p = sub.add_parser("audit", help="FULL pipeline (ports+web+api+PDF)")
    p.add_argument("url")
    p.set_defaults(fn=cmd_audit)

    p = sub.add_parser("demo", help="Local demo server + full audit")
    p.add_argument("--port", type=int, default=8899)
    p.set_defaults(fn=cmd_demo)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
