import sys


def cmd_cloudsec(args):
    """Phase 9: enterprise cloud / container / Kubernetes / IaC security
    through the existing platform store (single asset/finding pipeline).
    Without --as: local/single-user mode. With --as TOKEN: RBAC + tenancy
    enforcement identical to the platform command (Phase-9 permission set)."""
    import os as _os
    _HERE = _os.path.dirname(_os.path.abspath(__file__))
    PY = _os.path.join(_HERE, "python")
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

    def need(perm):
        if ctx is not None:
            authz.require(ctx, perm)

    def need_org(org_id):
        if ctx is not None:
            authz.require_org(ctx, org_id)

    def org_of(arg_org):
        if ctx is not None:
            need_org(arg_org or ctx.org_id)
            return arg_org or ctx.org_id
        if not arg_org:
            print("[!] --org is required (local mode)")
            sys.exit(21)
        return arg_org

    act = args.action
    try:
        if act == "profiles":
            from scanners import ScannerRegistry
            reg = ScannerRegistry()
            print("Phase-9 in-process scan profiles:")
            for p in reg.list_profiles():
                if p["in_process"]:
                    print(f"  {p['name']:20s} {p['description']}")
            print(f"  (total profiles: {len(reg.list_profiles())})")
            return
        # ------------------------------------------------------ accounts
        if act == "account-add":
            need("cloud.account.create")
            oid = org_of(args.org)
            import cloud_security as cs
            s = cs.CloudSecurityService(svc)
            a = s.account_create(oid, provider=args.provider,
                                 account_identifier=args.account_id,
                                 display_name=args.name or "",
                                 credential_ref=args.credential_ref or "",
                                 credential_secret=(args.credential_secret
                                                    or ""))
            print(f"[✓] Cloud account: {a.id}  provider={a.provider} "
                  f"account={a.account_identifier}")
            return
        if act == "account-list":
            need("cloud.read")
            oid = org_of(args.org)
            import cloud_security as cs
            s = cs.CloudSecurityService(svc)
            for a in s.account_list(oid):
                print(f"  {a['id']}  {a['provider']:8s} "
                      f"{a['account_identifier']}  "
                      f"status={a['status']}  "
                      f"hint={a.get('credential_hint', '')[:24]}")
            return
        if act == "account-scan":
            need("cloud.scan.run")
            oid = org_of(args.org)
            pid = args.project
            if not pid:
                print("[!] --project is required")
                sys.exit(21)
            import cloud_security as cs
            s = cs.CloudSecurityService(svc)
            out = s.scan(oid, pid, args.account)
            print(f"[✓] Cloud scan: resources={out['resource_count']} "
                  f"findings={out['findings']} assets={out['assets']} "
                  f"capped={out['capped']}")
            print(f"    scan_id={out['scan_id']}")
            return
        # ------------------------------------------------------------ images
        if act == "image-add":
            need("container.image.register")
            oid = org_of(args.org)
            import container_security as cs
            s = cs.ContainerSecurityService(svc)
            img = s.image_register(oid, repository=args.repository,
                                   digest=args.digest,
                                   registry=args.registry or "")
            print(f"[✓] Image: {img.id}  {img.registry}/{img.repository}"
                  f"@{img.digest[:24]}…")
            return
        if act == "image-list":
            need("container.read")
            oid = org_of(args.org)
            import container_security as cs
            s = cs.ContainerSecurityService(svc)
            for i in s.image_list(oid):
                print(f"  {i['id']}  {i['registry']}/{i['repository']} "
                      f"@{i['digest'][:20]}… pkgs={i['package_count']} "
                      f"vulns={i['vuln_count']}")
            return
        if act == "image-scan":
            need("container.scan.run")
            oid = org_of(args.org)
            pid = args.project
            if not pid:
                print("[!] --project is required")
                sys.exit(21)
            import container_security as cs
            s = cs.ContainerSecurityService(svc)
            out = s.scan(oid, pid, args.image,
                         image_metadata=getattr(args, "meta", "") and
                         _parse_kv(getattr(args, "meta", "")))
            print(f"[✓] Image scan: findings={out['findings']} "
                  f"assets={out['assets']} packages={out['packages']}")
            return
        # ---------------------------------------------------------- clusters
        if act == "cluster-add":
            need("kubernetes.cluster.create")
            oid = org_of(args.org)
            import kubernetes_security as cs
            s = cs.KubernetesSecurityService(svc)
            cl = s.cluster_register(oid, name=args.name,
                                    endpoint=args.endpoint or "",
                                    credential_ref=args.credential_ref or "",
                                    credential_secret=(args.credential_secret
                                                       or ""))
            print(f"[✓] Cluster: {cl.id}  name={cl.name}")
            return
        if act == "cluster-list":
            need("kubernetes.read")
            oid = org_of(args.org)
            import kubernetes_security as cs
            s = cs.KubernetesSecurityService(svc)
            for c in s.cluster_list(oid):
                cid = c.get("context", {}).get("endpoint", "")[:48]
                print(f"  {c['id']}  {c['name']:24s} "
                      f"status={c['context'].get('status', 'registered'):11s}"
                      f"  {cid or 'in-cluster'}")
            return
        if act == "cluster-scan":
            need("kubernetes.scan.run")
            oid = org_of(args.org)
            pid = args.project
            if not pid:
                print("[!] --project is required")
                sys.exit(21)
            manifests = []
            for mf in (getattr(args, "manifest", None) and
                       [args.manifest] or []):
                with open(mf, "r", encoding="utf-8",
                          errors="replace") as fh:
                    manifests.append(fh.read())
            import kubernetes_security as cs
            s = cs.KubernetesSecurityService(svc)
            out = s.scan(oid, pid, args.cluster, manifests=manifests,
                         namespace=getattr(args, "namespace", "") or "")
            print(f"[✓] K8s scan: docs={out['documents']} "
                  f"findings={out['findings']} assets={out['assets']} "
                  f"secrets_observed={out.get('secrets_observed', 0)}")
            return
        # -------------------------------------------------------------- iac
        if act == "iac-scan":
            need("iac.scan.run")
            oid = org_of(args.org)
            pid = args.project
            if not pid:
                print("[!] --project is required")
                sys.exit(21)
            files = []
            for path in (getattr(args, "file", None) or []) + \
                    (getattr(args, "files", None) or []):
                with open(path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    files.append({"name": path, "content": fh.read()})
            import iac_security as cs
            s = cs.IacSecurityService(svc)
            out = s.scan(oid, pid, files=files,
                         source_name=args.source or "repository",
                         fmt=getattr(args, "fmt", None) or "auto")
            print(f"[✓] IaC scan: files={out['files']} "
                  f"resources={out['resources']} findings={out['findings']} "
                  f"secrets={out.get('secrets_detected', 0)}")
            return
        # ---------------------------------------------------------- findings
        if act == "findings":
            need("finding.read")
            oid = org_of(args.org)
            import cloud_security as cs
            s = cs.CloudSecurityService(svc)
            fl = s.findings(oid, limit=getattr(args, "limit", 20) or 20)
            print(f"Phase-9 findings for org {oid}: {len(fl)}")
            for f in fl:
                print(f"  [{f['severity']:8s}] {f['rule_id']:28s} "
                      f"{f['title'][:60]}")
            return
        print(f"[!] unknown cloudsec action: {act}")
        sys.exit(21)
    except Exception as e:
        print(f"[!] {getattr(e, 'user_message', lambda: str(e))()}")
        sys.exit(getattr(e, "exit_code", 50))


def _parse_kv(spec: str) -> dict:
    out = {}
    for part in str(spec or "").split(","):
        if not part.strip():
            continue
        k, _, v = part.partition("=")
        if k.strip():
            out[k.strip()] = v.strip()
    return out
