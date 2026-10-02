#!/usr/bin/env python3
# ============================================================================
#  kubernetes_security.py — Phase 9 Kubernetes security assessment (declarative)
#  ---------------------------------------------------------------------------
#  - Cluster registration stores connection METADATA only. Kubeconfig /
#    bearer tokens are never persisted: credential_ref (pointer) +
#    credential_enc (encrypted at rest, same scheme as cloud accounts) +
#    a non-reversible credential_hint fingerprint.
#  - Assessment is declarative: bounded YAML manifest parsing (safe_load,
#    never eval/exec/shell) and deterministic rule checks on the pod
#    template + RBAC workload, plus optional explicit connectivity probe.
#  - Namespace/kind filters are validated allowlists; a broken manifest or
#    an unreachable API server is an EXPLICIT failure (§47) — never a silent
#    "0 findings / PASS".
# ============================================================================

from __future__ import annotations

import re

import errors
import models
import store as store_mod

MAX_MANIFEST_BYTES = 512 * 1024
MAX_DOCS_PER_MANIFEST = 64
MAX_FINDINGS_PER_SCAN = 5_000
NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,62}[a-z0-9])?$")
POD_SCOPED_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet",
                    "Job", "CronJob", "ReplicaSet"}
ALLOWED_KINDS = POD_SCOPED_KINDS | {"Service", "Namespace",
                                    "Role", "RoleBinding",
                                    "ClusterRole", "ClusterRoleBinding",
                                    "NetworkPolicy", "Secret", "ConfigMap",
                                    "ServiceAccount"}
DANGEROUS_CAPS = {"sys_admin", "net_admin", "sys_ptrace", "sys_module",
                  "cap_sys_admin", "cap_net_admin", "cap_sys_ptrace",
                  "cap_sys_module", "all"}
_EMPTY_TEMPLATE = {"kind": "Pod", "metadata": {"name": ""},
                   "spec": {"containers": []}}

FAIL_API_UNAVAILABLE = "k8s_api_unavailable"
FAIL_PARSER = "parser_failure"
FAIL_INVALID_MANIFEST = "k8s_manifest_invalid"
FAIL_FORBIDDEN = "k8s_api_forbidden"
FAIL_BAD_CREDENTIALS = "invalid_kubeconfig_credentials"


class KubernetesAssessmentError(errors.SecurityToolkitError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def user_message(self) -> str:
        return f"{self.code}: {self!s}"


# ============================================================================
# Bounded manifest parsing (safe_load; no eval/exec/shell)
# ============================================================================
def parse_manifest(text: str) -> list[dict]:
    """Parse a multi-document YAML manifest into validated document dicts.

    Raises KubernetesAssessmentError(k8s_manifest_invalid|parser_failure)
    for malformed, oversized or out-of-allowlist content — never returns
    a partial result silently."""
    if not isinstance(text, str) or not text.strip():
        raise KubernetesAssessmentError(
            FAIL_INVALID_MANIFEST, "manifest text is empty")
    if len(text.encode("utf-8", "replace")) > MAX_MANIFEST_BYTES:
        raise KubernetesAssessmentError(
            FAIL_PARSER,
            f"manifest exceeded {MAX_MANIFEST_BYTES} bytes")
    # §23 alias-bomb defence: bounded anchor/alias fan-out (PyYAML expands
    # aliases in memory — an unbounded anchor web is a DoS vector)
    if text.count("&") + text.count("*") > 2_000:
        raise KubernetesAssessmentError(
            FAIL_PARSER,
            "manifest exceeds alias/anchor budget (YAML bomb defence)")
    try:
        import yaml
        docs = list(yaml.safe_load_all(text))   # PyYAML (no eval/exec)
    except ImportError:
        docs = _parse_yaml_fallback(text)
    except Exception as e:
        raise KubernetesAssessmentError(
            FAIL_PARSER, f"manifest parse failure: {e}") from e
    if not isinstance(docs, list):
        docs = [docs]
    out = []
    for doc in docs:
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise KubernetesAssessmentError(
                FAIL_PARSER, "manifest document is not a mapping")
        kind = str((doc.get("kind") or "") or "")
        if kind not in ALLOWED_KINDS:
            raise KubernetesAssessmentError(
                FAIL_INVALID_MANIFEST,
                f"unsupported kind: {kind or '<missing>'}")
        meta = doc.get("metadata") or {}
        if meta.get("name") and not NAME_RE.match(str(meta["name"])[:64]):
            raise KubernetesAssessmentError(
                FAIL_INVALID_MANIFEST,
                f"invalid resource name: {meta['name']!r}")
        out.append(doc)
        if len(out) > MAX_DOCS_PER_MANIFEST:
            raise KubernetesAssessmentError(
                FAIL_PARSER, f"manifest exceeded {MAX_DOCS_PER_MANIFEST} docs")
    return out


def _parse_yaml_fallback(text: str) -> list:
    """No-PyYAML fallback: split on document separators and parse each
    chunk with the toolkit's bounded template parser. Never eval/exec."""
    parts = re.split(r"(?m)^---[ \t]*$", text)
    docs = []
    from template_engine import parse_yaml
    for part in parts:
        if not part.strip():
            continue
        try:
            docs.append(parse_yaml(part))
        except Exception as e:
            raise KubernetesAssessmentError(
                FAIL_PARSER, f"manifest parse failure: {e}") from e
    return docs


def pod_template(doc: dict) -> dict:
    """Extract the pod template mapping from a workload document
    (for a bare Pod, the document itself)."""
    kind = str(doc.get("kind") or "")
    if kind == "Pod":
        return doc
    spec = doc.get("spec") or {}
    for k in ("template", "jobTemplate"):
        tpl = spec.get(k) or {}
        if isinstance(tpl, dict) and "spec" in tpl:
            return tpl
    if isinstance(spec.get("selector"), dict):
        return _EMPTY_TEMPLATE
    return _EMPTY_TEMPLATE


def container_list(doc: dict) -> list[dict]:
    spec = (pod_template(doc).get("spec") or {})
    out = []
    for c in (spec.get("containers") or []) + \
             (spec.get("initContainers") or []):
        if isinstance(c, dict):
            out.append(c)
            if len(out) > 2_000:
                break
    return out


# ============================================================================
# Deterministic rules (v1)
# ============================================================================
class KubernetesRule:
    __slots__ = ("rule_id", "title", "description", "severity", "category",
                 "check", "remediation", "version")

    def __init__(self, rule_id, title, description, severity, category,
                 check, remediation, version="v1"):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.category = category
        self.check = check
        self.remediation = remediation
        self.version = version

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "title": self.title,
                "description": self.description, "severity": self.severity,
                "category": self.category, "remediation": self.remediation,
                "version": self.version}


K8S_RULES: tuple[KubernetesRule, ...] = (
    KubernetesRule("K8S-PRIVILEGED-001", "Privileged container",
                   "A workload container runs with privileged: true.",
                   "High", "misconfiguration",
                   lambda c: bool(c.get("securityContext", {}).get(
                       "privileged", False))
                   if isinstance(c.get("securityContext"), dict) else False,
                   "Remove privileged: true; scope capabilities."),
    KubernetesRule("K8S-HOST-NET-002", "Host network namespace",
                   "The pod shares the host network namespace.",
                   "High", "exposure",
                   lambda c: bool((c.get("spec") or c.get("_podspec") or {})
                                  .get("hostNetwork", False)),
                   "Remove hostNetwork: true; use an isolated network."),
    KubernetesRule("K8S-HOST-PID-003", "Host PID namespace",
                   "The pod shares the host PID namespace.",
                   "High", "misconfiguration",
                   lambda c: bool((c.get("spec") or c.get("_podspec") or {})
                                  .get("hostPID", False)),
                   "Remove hostPID: true."),
    KubernetesRule("K8S-HOST-PATH-004", "HostPath volume mounted",
                   "A hostPath volume exposes host filesystem paths.",
                   "High", "misconfiguration",
                   lambda c: [v for v in (c.get("_volumes") or [])
                              if isinstance(v, dict)
                              and "hostPath" in v],
                   "Remove hostPath volumes; use bounded volumes."),
    KubernetesRule("K8S-DANGEROUS-CAPS-005", "Dangerous capabilities",
                   "CAP_SYS_ADMIN / CAP_NET_ADMIN / wildcard capabilities "
                   "are added.",
                   "High", "misconfiguration",
                   lambda c: set(str(x).lower() for x in
                                 (((c.get("securityContext") or {}).get(
                                     "capabilities") or {}).get("add") or [])
                                 ) & DANGEROUS_CAPS
                   if isinstance(c.get("securityContext"), dict) else set(),
                   "Drop all capabilities; add only required ones."),
    KubernetesRule("K8S-ROOT-006", "Runs as root / no runAsNonRoot",
                   "The container runs as UID 0 or runAsNonRoot is not set.",
                   "Medium", "misconfiguration",
                   lambda c: ((c.get("securityContext") or {}).get(
                       "runAsUser", 0) == 0
                       and not (c.get("securityContext") or {}).get(
                           "runAsNonRoot", False))
                   if isinstance(c.get("securityContext"), dict) else True,
                   "Set runAsNonRoot: true and a non-root runAsUser."),
    KubernetesRule("K8S-NO-RESOURCE-LIMITS-007",
                   "No resource limits or requests",
                   "CPU/memory limits are absent on a workload container.",
                   "Medium", "misconfiguration",
                   lambda c: not c.get("resources")
                   or not (c.get("resources") or {}).get("limits"),
                   "Set requests and limits for cpu and memory."),
    KubernetesRule("K8S-SECRET-ENV-008",
                   "Secret values injected via environment variables",
                   "A workload consumes a Secret through env var injection "
                   "(values are never stored by this scanner, but this is "
                   "a leak-risk pattern).",
                   "Medium", "information_disclosure",
                   lambda c: bool(_env_secret_refs(c)),
                   "Use mounted Secret volumes or a secret store "
                   "integration."),
    KubernetesRule("K8S-UNPINNED-IMAGE-009",
                   "Workload image uses a mutable tag",
                   "Container image references lack a digest pin.",
                   "Low", "supply_chain",
                   lambda c: bool(c.get("image")) and "@sha256:" not in (
                       c.get("image") or ""),
                   "Pin images by digest "
                   "(registry/repo@sha256:…)."),
    KubernetesRule("K8S-IMAGE-PULL-ALWAYS-010",
                   "imagePullPolicy: Always with a mutable tag",
                   "Repulls on every restart — non-deterministic builds.",
                   "Low", "supply_chain",
                   lambda c: (c.get("imagePullPolicy") == "Always"
                              and "@sha256:" not in (c.get("image") or "")),
                   "Pin by digest; use IfNotPresent."),
    KubernetesRule("K8S-SVC-PUBLIC-011",
                   "Service exposes workload publicly",
                   "Service type LoadBalancer or NodePort exposes the "
                   "workload beyond the cluster.",
                   "High", "exposure",
                   lambda doc: _service_exposure(doc),
                   "Prefer ClusterIP + ingress with TLS."),
    KubernetesRule("K8S-RBAC-WILDCARD-012",
                   "RBAC role grants wildcard access",
                   "A Role/ClusterRole grants * verbs or * resources.",
                   "High", "access_control",
                   lambda doc: _rbac_wildcard(doc),
                   "Restrict RBAC to concrete verbs and resources."),
    KubernetesRule("K8S-CLUSTER-ADMIN-013",
                   "Binding grants cluster-admin",
                   "A RoleBinding/ClusterRoleBinding references the "
                   "cluster-admin ClusterRole (cluster-wide super-user).",
                   "Critical", "access_control",
                   lambda doc: _binding_to_role(doc, "cluster-admin"),
                   "Remove cluster-admin bindings; grant scoped roles "
                   "per namespace."),
    KubernetesRule("K8S-ANON-ACCESS-014",
                   "RBAC grants anonymous/unauthenticated access",
                   "A RoleBinding/ClusterRoleBinding grants "
                   "system:anonymous / system:unauthenticated subjects "
                   "cluster or namespace permissions.",
                   "High", "access_control",
                   lambda doc: _anon_binding(doc),
                   "Remove anonymous/unauthenticated bindings; require "
                   "authenticated identities."),
    KubernetesRule("K8S-NO-NETWORKPOLICY-015",
                   "Namespace has no NetworkPolicy",
                   "Workloads run in a namespace without any "
                   "NetworkPolicy (default-allow east-west traffic).",
                   "Medium", "misconfiguration",
                   lambda doc: [],      # namespace pass (see assess_workloads)
                   "Define a NetworkPolicy per namespace (default-deny "
                   "ingress)."),
    KubernetesRule("K8S-NO-PROBES-016",
                   "Container lacks readiness/liveness probes",
                   "No readinessProbe / livenessProbe on a workload "
                   "container — delayed failure detection.",
                   "Low", "misconfiguration",
                   lambda c: not (c.get("readinessProbe")
                                  or c.get("livenessProbe")),
                   "Define readiness and liveness probes."),
)

# classification used by assess_workloads:
#   container-level : evaluated once per container
#   doc-level       : evaluated once per document (Service/RBAC docs)
#   namespace-level : aggregated over the whole manifest set
_DOC_LEVEL_RULE_IDS = frozenset({
    "K8S-SVC-PUBLIC-011", "K8S-RBAC-WILDCARD-012",
    "K8S-CLUSTER-ADMIN-013", "K8S-ANON-ACCESS-014"})
_NS_LEVEL_RULE_IDS = frozenset({"K8S-NO-NETWORKPOLICY-015"})


def _binding_to_role(doc: dict, role_name: str) -> list[str]:
    """RoleBinding/ClusterRoleBinding whose roleRef targets `role_name`."""
    if str(doc.get("kind") or "") not in ("RoleBinding", "ClusterRoleBinding"):
        return []
    ref = (doc.get("roleRef") or {}).get("name") if \
        isinstance(doc.get("roleRef"), dict) else ""
    if str(ref or "") == role_name:
        return [f"{doc.get('kind')}/{doc.get('metadata', {}).get('name', '')}"]
    return []


def _anon_binding(doc: dict) -> list[str]:
    if str(doc.get("kind") or "") not in ("RoleBinding", "ClusterRoleBinding"):
        return []
    subjects = doc.get("subjects") or []
    if not isinstance(subjects, list):
        return []
    anon = ("system:anonymous", "system:unauthenticated", "anonymous")
    hits = [str(s.get("name")) for s in subjects
            if isinstance(s, dict)
            and str(s.get("name") or "") in anon]
    if hits:
        return [f"{doc.get('kind')}/{doc.get('metadata', {}).get('name', '')}"
                f" -> {', '.join(sorted(set(hits)))}"]
    return []


def _env_secret_refs(container: dict) -> list[dict]:
    refs = []
    for e in container.get("env") or []:
        if isinstance(e, dict) and isinstance(e.get("valueFrom"), dict):
            sf = e["valueFrom"].get("secretKeyRef")
            if isinstance(sf, dict):
                refs.append({"name": str(e.get("name", ""))[:128],
                             "secret": str(sf.get("name", ""))[:128]})
    return refs[:64]


def _service_exposure(doc: dict) -> list[str]:
    if str(doc.get("kind") or "") != "Service":
        return []
    if not doc.get("metadata"):
        return []
    t = (doc.get("spec") or {}).get("type") or "ClusterIP"
    if t in ("LoadBalancer", "NodePort"):
        return [t]
    return []


def _rbac_wildcard(doc: dict) -> list[str]:
    kind = str(doc.get("kind") or "")
    if kind not in ("Role", "ClusterRole"):
        return []
    for rule in (doc.get("rules") or []):
        if not isinstance(rule, dict):
            continue
        verbs = {str(v) for v in (rule.get("verbs") or [])}
        resources = {str(v) for v in (rule.get("resources") or [])}
        if "*" in verbs or "*" in resources:
            return [f"verbs={sorted(verbs)} resources={sorted(resources)}"]
    return []


def k8s_rules_meta() -> list[dict]:
    return [r.to_dict() for r in K8S_RULES]


# ============================================================================
# Workload assessment
# ============================================================================
def _pod_ctx(doc: dict) -> dict:
    """Flatten a document into a container-check context dict."""
    tpl = pod_template(doc)
    spec = tpl.get("spec") or {}
    volumes = [v for v in (spec.get("volumes") or []) if isinstance(v, dict)]
    return {"spec": spec, "_volumes": volumes, "_podspec": spec}


def workload_asset_id(org_id: str, ns: str, kind: str, name: str) -> str:
    """Asset value that matches the persisted cloud_resource asset."""
    return (f"kubernetes|{org_id}|{ns}|cluster_resource|{ns}|{kind}|{name}")


def assess_workloads(docs: list[dict], *, namespace: str = "",
                     org_id: str = "") -> list[dict]:
    """Run deterministic rules over parsed docs. Returns finding-shaped
    dicts; a malformed doc raises instead of being skipped."""
    findings = []
    ns_filter = namespace or ""
    # namespace-level aggregation (NetworkPolicy coverage)
    ns_workload_first: dict[str, dict] = {}      # ns -> first workload info
    ns_with_netpol: set[str] = set()
    for doc in docs:
        kind = str(doc.get("kind") or "Pod")
        meta = doc.get("metadata") or {}
        ns = str(meta.get("namespace") or "default")
        if kind == "NetworkPolicy":
            ns_with_netpol.add(ns)
        elif kind in POD_SCOPED_KINDS:
            ns_workload_first.setdefault(ns, {"doc": doc, "name": str(
                meta.get("name") or "<unnamed>")[:128], "kind": kind,
                "ns": ns})
    for doc in docs:
        meta = doc.get("metadata") or {}
        ns = str(meta.get("namespace") or "default")
        if ns_filter and ns != ns_filter:
            continue
        name = str(meta.get("name") or "<unnamed>")[:128]
        kind = str(doc.get("kind") or "Pod")
        asset_cid = workload_asset_id(org_id, ns, kind, name)
        ctx = _pod_ctx(doc)
        for container in container_list(doc):
            ctx_c = dict(ctx)
            ctx_c["image"] = container.get("image", "")
            ctx_c["resources"] = container.get("resources")
            ctx_c["imagePullPolicy"] = container.get("imagePullPolicy")
            ctx_c["securityContext"] = container.get("securityContext")
            ctx_c["env"] = container.get("env", [])
            ctx_c["readinessProbe"] = container.get("readinessProbe")
            ctx_c["livenessProbe"] = container.get("livenessProbe")
            for rule in K8S_RULES:
                if rule.rule_id in _DOC_LEVEL_RULE_IDS | _NS_LEVEL_RULE_IDS:
                    continue            # doc/namespace checks below
                try:
                    if not rule.check(ctx_c):
                        continue
                except Exception:
                    continue            # never fail open
                findings.append(_finding(rule, doc, container, name, kind,
                                         asset_cid))
                if len(findings) >= MAX_FINDINGS_PER_SCAN:
                    return findings
        # doc-level rules (Service/RBAC)
        for rule in K8S_RULES:
            if rule.rule_id not in _DOC_LEVEL_RULE_IDS:
                continue
            try:
                if not rule.check(doc):
                    continue
            except Exception:
                continue
            findings.append(_finding(rule, doc, None, name, kind, asset_cid))
            if len(findings) >= MAX_FINDINGS_PER_SCAN:
                break
    # namespace-level: workloads without any NetworkPolicy in their ns
    if not ns_filter or ns_filter in ns_workload_first:
        for ns in sorted(ns_workload_first):
            if ns_filter and ns != ns_filter:
                continue
            if ns in ns_with_netpol:
                continue
            info = ns_workload_first[ns]
            rule = _rule_by_id("K8S-NO-NETWORKPOLICY-015")
            findings.append(_finding(
                rule, info["doc"], None, info["name"], info["kind"],
                workload_asset_id(org_id, ns, info["kind"], info["name"])))
            if len(findings) >= MAX_FINDINGS_PER_SCAN:
                break
    return findings


def _rule_by_id(rule_id: str) -> KubernetesRule:
    for r in K8S_RULES:
        if r.rule_id == rule_id:
            return r
    return K8S_RULES[0]


def _finding(rule: KubernetesRule, doc: dict, container: dict | None,
             name: str, kind: str, asset_cid: str) -> dict:
    ns = str((doc.get("metadata") or {}).get("namespace") or "default")
    cid = f"{ns}|{kind}|{name}"
    detail = ""
    if container is not None:
        cname = str(container.get("name") or "<container>")[:128]
        detail = f"/{cname}"
    return {
        "title": f"{name}{detail}: {rule.title}",
        "description": rule.description,
        "severity": rule.severity,
        "confidence": "high" if rule.severity in ("Critical", "High")
        else "medium",
        "category": rule.category,
        "rule_id": rule.rule_id,
        "remediation": rule.remediation,
        "rule_version": rule.version,
        "asset": asset_cid,
        "resource_type": "cluster_resource",
        "resource_id": cid,
        "resource_name": name,
        "provider": "kubernetes",
        "metadata": {"namespace": ns, "kind": kind, "workload": name,
                     "container": (container or {}).get("name", "") if
                     container else "",
                     "rule": rule.rule_id},
        "evidence": [{"evidence_type": "configuration",
                      "url": "",
                      "detection_reason":
                          f"{rule.rule_id}: declarative manifest check "
                          f"matched {kind}/{name}"}]}


# ============================================================================
# Secret metadata handling — values are NEVER stored
# ============================================================================
SECRET_META_KEYS = ("name", "namespace", "type", "key_names", "managed_by",
                    "created_at")
KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _secret_metadata_only(secret: dict) -> dict:
    """Extract metadata-only rendering of a Secret document; any
    stringData/data values are dropped (never logged, never stored)."""
    meta = secret.get("metadata") or {}
    data = secret.get("data") or {}
    string_data = secret.get("stringData") or {}
    keys = []
    for k in (list(data.keys()) + list(string_data.keys())):
        k = str(k)
        if KEY_RE.match(k):
            keys.append(k)
    keys = sorted(set(keys))[:64]
    return {"name": str(meta.get("name") or "")[:128],
            "namespace": str(meta.get("namespace") or "default")[:128],
            "type": str(secret.get("type") or "Opaque")[:64],
            "key_names": keys,
            "managed_by": str((meta.get("labels") or {}).get(
                "app.kubernetes.io/managed-by", "") or "")[:64],
            "created_at": str(meta.get("creationTimestamp") or "")[:64]}


# ============================================================================
# Service — cluster registration + assessment
# ============================================================================
class KubernetesSecurityService:
    def __init__(self, platform, *, limiter=None,
                 limits: dict | None = None):
        self.svc = platform
        self.db = platform.db
        import identity as identity_mod
        self.limiter = limiter or identity_mod.RateLimiter(max_keys=8192)
        self.limits = {"register": (12, 300), "scan": (12, 300)}
        if isinstance(limits, dict):
            self.limits.update(limits)

    def _audit(self, action, *, object_type, object_id, org_id,
               actor="identity", metadata=None):
        try:
            self.svc.audit(action, object_type=object_type,
                           object_id=object_id, org_id=org_id,
                           actor=str(actor)[:128],
                           metadata=redact_meta(dict(metadata or {})))
        except Exception as e:
            # §34: audit failures are NEVER silently swallowed — log and
            # count them (the platform audit is append-only by design)
            import seclog as _seclog
            _seclog.get_logger("phase9").warn(
                "audit write failed", action=action,
                error=str(e)[:200])
            import metrics as _metrics
            _metrics.inc("audit_failures")

    def _throttle(self, kind: str, key: str) -> None:
        limit, window = self.limits.get(kind, (12, 300))
        ok, retry = self.limiter.allowed(f"k8s:{kind}:{key}",
                                         limit, window)
        if not ok:
            raise errors.RateLimitedError("Too many attempts",
                                          retry_after=retry)

    # ------------------------------------------------------------ clusters
    def cluster_register(self, org_id: str, *, name: str, endpoint: str = "",
                         api_version: str = "v1",
                         credential_ref: str = "",
                         credential_secret: str = "",
                         in_cluster: bool = False,
                         created_by: str = "cli") -> models.KubernetesCluster:
        self._throttle("register", org_id)
        name = str(name or "").strip()[:128]
        if not NAME_RE.match(name):
            raise errors.ValidationError(
                "k8s_cluster_invalid: name must be a lower-case RFC1123 label")
        endpoint = str(endpoint or "").strip()[:512]
        if endpoint and not (endpoint.startswith("https://")
                             or endpoint.startswith("http://")):
            endpoint = "https://" + endpoint
        if in_cluster and endpoint:
            raise errors.ValidationError(
                "k8s_cluster_invalid: in_cluster implies no endpoint")
        ctx = {"endpoint": endpoint, "api_version": str(api_version or "v1")
               [:64], "status": "registered", "last_probed_at": "",
               "server_version": "", "namespaces": [],
               "in_cluster": bool(in_cluster),
               "credential_ref": str(credential_ref or "")[:256]}
        if credential_secret:
            import notify
            ctx["credential_enc"] = notify._encrypt_secret(
                credential_secret, self.svc.db_path)
            ctx["credential_hint"] = credential_hint(credential_secret)
        cluster = models.KubernetesCluster(
            org_id=org_id, name=name, provider="k8s",
            api_ref=str(credential_ref or "")[:256],
            # enc/hint are non-plaintext by construction (encrypted blob /
            # non-reversible digest); redact applies on to_dict views
            context=ctx)
        cluster.finalize()
        try:
            self.db.execute(
                "INSERT INTO kubernetes_clusters (id, org_id, name, provider"
                ", api_ref, context, created_at, scanned_at) VALUES "
                "(?,?,?,?,?,?,?,?)",
                (cluster.id, org_id, name, cluster.provider,
                 cluster.api_ref, store_mod.dumps(cluster.context),
                 cluster.created_at, ""))
        except Exception as e:
            rows = self.db.query(
                "SELECT * FROM kubernetes_clusters WHERE org_id=? AND name=?"
                " LIMIT 1", (org_id, name))
            if rows:
                return models.KubernetesCluster.from_row(rows[0])
            raise errors.PersistenceError(
                "kubernetes cluster registration failed") from e
        import metrics as _metrics
        _metrics.inc("kubernetes_clusters_registered")
        self._audit("kubernetes.cluster_registered",
                    object_type="kubernetes_cluster",
                    object_id=cluster.id, org_id=org_id, actor=created_by,
                    metadata={"name": name,
                              "endpoint": endpoint[:80] or "in-cluster"})
        return cluster

    def cluster_get(self, org_id: str, cluster_id: str
                    ) -> models.KubernetesCluster:
        rows = self.db.query(
            "SELECT * FROM kubernetes_clusters WHERE id=? AND org_id=? "
            "LIMIT 1", (cluster_id, org_id))
        if not rows:
            raise errors.NotFoundError("no such kubernetes cluster")
        return models.KubernetesCluster.from_row(rows[0])

    def cluster_list(self, org_id: str, *, limit: int = 200) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM kubernetes_clusters WHERE org_id=? "
            "ORDER BY created_at DESC",
            (org_id,), limit=max(1, min(int(limit or 200), 500)))
        return [models.KubernetesCluster.from_row(r).to_dict() for r in rows]

    def cluster_delete(self, org_id: str, cluster_id: str, *,
                       actor: str = "cli") -> dict:
        """Unregister the cluster (org-scoped). Existing findings/evidence
        stay — they are immutable scan history."""
        cluster = self.cluster_get(org_id, cluster_id)
        self.db.execute(
            "DELETE FROM kubernetes_clusters WHERE id=? AND org_id=?",
            (cluster_id, org_id))
        self._audit("kubernetes.cluster_deleted",
                    object_type="kubernetes_cluster", object_id=cluster_id,
                    org_id=org_id, actor=actor,
                    metadata={"name": cluster.name})
        return {"deleted": cluster_id}

    # ----------------------------------------------------------------- probe
    def probe(self, org_id: str, cluster_id: str, *, actor: str = "cli",
              timeout_s: float = 5.0) -> dict:
        """Explicit connectivity probe. Never silently degrades: an
        unreachable endpoint raises KubernetesAssessmentError."""
        self._throttle("scan", f"{org_id}|{cluster_id}")
        cluster = self.cluster_get(org_id, cluster_id)
        endpoint = str(cluster.context.get("endpoint") or "")
        if not endpoint:
            # in-cluster / declarative mode: mark reachable by definition
            # but the scan itself must still supply manifests.
            status, ver = "reachable", ""
        else:
            import socket
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            try:
                with socket.create_connection((host, port),
                                              timeout=min(
                                                  max(float(timeout_s), 0.5),
                                                  15.0)):
                    status, ver = "reachable", "k8s-probe-ok"
            except OSError as e:
                ctx = dict(cluster.context)
                ctx.update({"status": "unreachable",
                            "last_probed_at": models.utcnow()})
                self.db.execute(
                    "UPDATE kubernetes_clusters SET context=? WHERE id=?",
                    (store_mod.dumps(ctx), cluster_id))
                raise KubernetesAssessmentError(
                    FAIL_API_UNAVAILABLE,
                    f"cluster endpoint unreachable: {host}:{port} ({e})")
        ctx = dict(cluster.context)
        ctx.update({"status": status, "last_probed_at": models.utcnow(),
                    "server_version": ver})
        self.db.execute(
            "UPDATE kubernetes_clusters SET context=? WHERE id=?",
            (store_mod.dumps(ctx), cluster_id))
        self._audit("kubernetes.cluster_probed",
                    object_type="kubernetes_cluster", object_id=cluster_id,
                    org_id=org_id, actor=actor,
                    metadata={"status": status})
        return {"cluster_id": cluster_id, "status": status,
                "server_version": ver,
                "endpoint": endpoint[:80] if endpoint else "in-cluster"}

    # ----------------------------------------------------------------- scan
    def scan(self, org_id: str, project_id: str, cluster_id: str, *,
                 scan_id: str = "",
             manifests: list[str] | None = None,
             namespace: str = "", actor: str = "cli") -> dict:
        """Assess declarative manifests against deterministic rules.
        `manifests` may also be a single manifest text."""
        self._throttle("scan", f"{org_id}|{project_id}|{cluster_id}")
        self.svc.project_require(project_id)
        cluster = self.cluster_get(org_id, cluster_id)
        if namespace and not NAME_RE.match(str(namespace)[:64]):
            raise errors.ValidationError(
                "k8s_manifest_invalid: invalid namespace filter")
        texts = manifests or []
        if isinstance(texts, (str, bytes)):
            texts = [texts]
        docs = []
        for t in texts:
            docs.extend(parse_manifest(t))
        if not docs:
            raise KubernetesAssessmentError(
                FAIL_INVALID_MANIFEST,
                "declarative scan requires at least one manifest")
        # workload assessment
        findings = assess_workloads(docs, namespace=namespace, org_id=org_id)
        # secret metadata-only: record existence, never values
        secret_meta = []
        for doc in docs:
            if str(doc.get("kind") or "") == "Secret":
                secret_meta.append(_secret_metadata_only(doc))
        if scan_id:
            # job-dispatched assessment: reuse the umbrella scan (the
            # worker owns its lifecycle — do NOT transition it here)
            scan = self.svc.scan_get(scan_id)
        else:
            import secrets as _secrets
            scan = self.svc.scan_create(
                project_id, "kubernetes", scope_ref=cluster_id,
                scan_id=scan_id or models.stable_id(
                    models.NS_SCAN,
                    f"{project_id}|kubernetes|{models.utcnow()}|"
                    f"{_secrets.token_hex(4)}"),
                initiator={"org_id": org_id, "cluster_id": cluster_id,
                           "name": cluster.name})
        self._audit("kubernetes.scan.started",
                    object_type="kubernetes_cluster", object_id=cluster_id,
                    org_id=org_id, actor=actor,
                    metadata={"scan_id": scan.id,
                              "docs": len(docs),
                              "secrets_observed": len(secret_meta)})
        # asset for each finding-producing resource
        assets = []
        for doc in docs:
            kind = str(doc.get("kind") or "Pod")
            if kind not in (POD_SCOPED_KINDS | {"Service", "Role",
                                                "RoleBinding",
                                                "ClusterRole",
                                                "ClusterRoleBinding"}):
                continue
            meta = doc.get("metadata") or {}
            ns = str(meta.get("namespace") or "default")
            wn = str(meta.get("name") or "<unnamed>")[:128]
            cid = f"{ns}|{kind}|{wn}"
            assets.append({
                "provider": "kubernetes", "account": org_id,
                "region": ns, "resource_type": "cluster_resource",
                "resource_id": cid, "name": wn,
                "attributes": {"cluster": cluster.name,
                               "namespace": ns, "kind": kind,
                               "workload": wn,
                               "internal_only": True}})
        raw = {"tool": "kubernetes-security",
               "target": cluster.name,
               "cluster_id": cluster_id,
               "docs": len(docs),
               "secrets_observed": secret_meta,
               "assets": assets,
               "findings": findings}
        import cloud_security as _cs
        persisted = _cs.persist_result(self.svc, org_id=org_id,
                                       project_id=project_id, scan_id=scan.id,
                                       raw=raw, actor=actor)
        # Secret METADATA ONLY — key names, type, owner. Values are never
        # stored or logged (they were dropped before this point).
        try:
            self.svc.scan_update_summary(
                scan.id, {"kubernetes": {
                    "docs": len(docs), "secrets_observed": secret_meta,
                    **persisted}})
        except Exception:
            pass
        if not scan_id:      # reused scans are finalized by the worker
            try:
                self.svc.scan_transition(scan.id, "completed")
            except Exception:
                pass
        self._audit("kubernetes.scan.completed",
                    object_type="kubernetes_cluster", object_id=cluster_id,
                    org_id=org_id, actor=actor,
                    metadata={"scan_id": scan.id, **persisted})
        return {"scan_id": scan.id, "cluster_id": cluster_id,
                "documents": len(docs), "secrets_observed": len(secret_meta),
                **persisted}

    def findings(self, org_id: str, *, namespace: str = "",
                 limit: int = 200) -> list[dict]:
        where = "f.project_id IN (SELECT id FROM projects WHERE org_id=?)"
        params = [org_id]
        if namespace:
            where += (" AND f.asset_id IN (SELECT id FROM assets "
                      "WHERE metadata LIKE ?)")
            params.append(f"%{namespace}%")
        rows = self.db.query(
            "SELECT f.id, f.title, f.severity, f.category, f.rule_id, "
            "f.asset_id, f.first_detected, f.last_detected, f.lifecycle "
            "FROM findings f WHERE " + where +
            " ORDER BY f.last_detected DESC LIMIT ?",
            tuple(params + [max(1, min(int(limit or 200), 500))]))
        return [dict(r) for r in rows]

    def secrets_observed(self, org_id: str, project_id: str,
                         cluster_id: str) -> list[dict]:
        """Metadata-only summary of Secrets observed during scans of this
        cluster (persisted in the scan summary). Values are NEVER stored
        or returned — only names, namespaces, types and key names."""
        self.svc.project_require(project_id)
        self.cluster_get(org_id, cluster_id)
        import store as store_mod
        rows = self.db.query(
            "SELECT summary, created_at FROM scans WHERE project_id=? AND "
            "scope_ref=? ORDER BY created_at DESC LIMIT 20",
            (project_id, cluster_id))
        out = []
        for row in rows:
            try:
                summary = store_mod.loads(row["summary"] or "")
            except Exception:
                continue
            k8s = summary.get("kubernetes") or {}
            for s in k8s.get("secrets_observed") or []:
                meta = {k: s.get(k) for k in SECRET_META_KEYS if k in s}
                if meta.get("name") and meta not in out:
                    out.append(meta)
        return out[:200]


def credential_hint(secret: str) -> str:
    import hashlib
    try:
        h = hashlib.sha256((secret or "").encode("utf-8",
                                                 "replace")).hexdigest()[:8]
    except Exception:
        h = ""
    return f"enc:{h}"


def redact_meta(d: dict) -> dict:
    import redact
    return redact.redact(d)
