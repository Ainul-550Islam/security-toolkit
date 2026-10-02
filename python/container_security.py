#!/usr/bin/env python3
# ============================================================================
#  container_security.py — Phase 9 provider-neutral container image analysis
#  ---------------------------------------------------------------------------
#  - Immutable image identity: registry/repository@sha256:<digest> (§19).
#    Tags are metadata; a tag change NEVER changes the asset identity.
#  - Package inventory + vulnerability normalization through the EXISTING
#    finding store; CVE metadata reuses cve_lookup conventions (no second
#    CVE database).
#  - Deterministic misconfiguration checks on OBSERVABLE metadata only
#    (privileged, hostNetwork, hostPID, hostPath, capabilities, root user,
#    missing resource limits, unsafe env). Never requires privileged host
#    access (§17); never executes Dockerfiles / layers (§45).
#  - Secret redaction on all serialized views; evidence is configuration
#    observations — never layer contents, never registry credentials.
# ============================================================================

from __future__ import annotations

import re
import threading

import errors
import models
import store as store_mod

MAX_PACKAGES_PER_IMAGE = 50_000
MAX_FINDINGS_PER_SCAN = 5_000
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# §47 explicit failure codes
FAIL_REGISTRY_UNAVAILABLE = "container_registry_unavailable"
FAIL_PARSER = "parser_failure"
FAIL_SECRET_REDACTION = "secret_redaction_failure"


class ContainerAssessmentError(errors.SecurityToolkitError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def user_message(self) -> str:
        return f"{self.code}: {self!s}"


# ============================================================================
# Identity helpers (§19)
# ============================================================================
def parse_image_ref(ref: str) -> dict:
    """Parse `registry/repository:tag@sha256:digest` defensively.

    Returns {registry, repository, tag, digest, canonical} where canonical
    is always `registry/repository@sha256:<digest>` (immutable identity;
    tag omitted when a digest is present)."""
    raw = str(ref or "").strip()
    if not raw or len(raw) > 512:
        raise errors.ValidationError("container_ref_invalid: malformed ref")
    digest = ""
    if "@" in raw:
        head, _, dg = raw.rpartition("@")
        if not DIGEST_RE.match(dg):
            raise errors.ValidationError(
                "container_ref_invalid: digest must be sha256:<64 hex>")
        digest = dg
    else:
        head = raw
    registry, _, rest = head.partition("/")
    if "." not in registry and ":" not in registry and "localhost" != registry:
        rest = f"{registry}/{rest}"
        registry = "docker.io"
    repo, _, tag = rest.partition(":")
    if tag and not TAG_RE.match(tag):
        raise errors.ValidationError(
            "container_ref_invalid: malformed tag")
    if not repo or len(repo) > 256:
        raise errors.ValidationError(
            "container_ref_invalid: malformed repository")
    canonical = (f"{registry}/{repo}@{digest}" if digest
                 else f"{registry}/{repo}:{tag or 'latest'}")
    return {"registry": registry, "repository": repo, "tag": tag,
            "digest": digest, "canonical": canonical}


def canonical_image_id(org_id: str, registry: str, repository: str,
                       digest: str) -> str:
    """Deterministic, mutable-name-free image identity."""
    return f"{org_id}|{registry}|{repository}|{digest}"


# ============================================================================
# Misconfiguration checks (observable metadata only; deterministic allowlist)
# ============================================================================
class ContainerRule:
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


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


CONTAINER_RULES: tuple[ContainerRule, ...] = (
    ContainerRule("CONT-PRIVILEGED-001", "Container runs privileged",
                  "The container is configured with full privileged access "
                  "to the host (capabilities are not dropped).",
                  "High", "misconfiguration",
                  lambda m: _truthy(m.get("privileged")),
                  "Remove privileged: true and run with a minimal "
                  "capability set."),
    ContainerRule("CONT-HOST-NET-002", "Container uses host networking",
                  "The container shares the host network namespace.",
                  "High", "exposure",
                  lambda m: _truthy(m.get("host_network")),
                  "Use the default bridge network; isolate network "
                  "namespaces."),
    ContainerRule("CONT-HOST-PID-003", "Container shares host PID namespace",
                  "The container can see host processes.",
                  "High", "misconfiguration",
                  lambda m: _truthy(m.get("host_pid")),
                  "Do not share the host PID namespace."),
    ContainerRule("CONT-HOST-PATH-004", "Container mounts a host filesystem",
                  "A hostPath-style mount exposes the host filesystem to "
                  "the container.",
                  "High", "misconfiguration",
                  lambda m: bool(m.get("host_path_mounts")),
                  "Remove hostPath mounts; use volumes with the minimum "
                  "required scope."),
    ContainerRule("CONT-DANGEROUS-CAPS-005",
                  "Container adds dangerous capabilities",
                  "CAP_SYS_ADMIN / CAP_NET_ADMIN or a wildcard capability "
                  "list is present.",
                  "High", "misconfiguration",
                  lambda m: bool(set(str(x).lower() for x in
                                     (m.get("capabilities") or [])) &
                                 {"cap_sys_admin", "cap_net_admin",
                                  "cap_sys_ptrace", "all"}),
                  "Drop all capabilities and add back only what is "
                  "required."),
    ContainerRule("CONT-ROOT-USER-006", "Container runs as root",
                  "The image/container runs as uid 0.",
                  "Medium", "misconfiguration",
                  lambda m: int(m.get("run_as_uid", 0) or 0) == 0,
                  "Run as a non-root user and set runAsNonRoot."),
    ContainerRule("CONT-NO-RESOURCE-LIMITS-007",
                  "Container has no resource limits",
                  "CPU/memory limits are absent — a runaway container can "
                  "exhaust the host.",
                  "Medium", "misconfiguration",
                  lambda m: not m.get("limits") or not (
                      m.get("limits") or {}).get("memory"),
                  "Set explicit memory/CPU requests and limits."),
    ContainerRule("CONT-SENSITIVE-ENV-008",
                  "Sensitive-looking environment variable present",
                  "An environment key matches a secret-like pattern "
                  "(value is never stored).",
                  "Medium", "information_disclosure",
                  lambda m: bool(m.get("sensitive_env_keys")
                                 or []) is True,
                  "Inject secrets via a secret store, not environment "
                  "variables."),
    ContainerRule("CONT-UNPINNED-TAG-009",
                  "Image referenced by a mutable tag only",
                  "A digest should be used for deployment identity and "
                  "reproducibility.",
                  "Low", "supply_chain",
                  lambda m: not m.get("digest"),
                  "Reference images by digest "
                  "(registry/repo@sha256:…)."),
)


def container_checks_meta() -> list[dict]:
    return [r.to_dict() for r in CONTAINER_RULES]


def assess_image_metadata(meta: dict) -> list[dict]:
    """Deterministic misconfiguration findings from OBSERVABLE metadata."""
    out = []
    for rule in CONTAINER_RULES:
        try:
            if not rule.check(meta):
                continue
        except Exception:
            continue                      # never fail open
        out.append({
            "title": rule.title,
            "description": rule.description,
            "severity": rule.severity,
            "confidence": "high" if rule.severity in ("Critical", "High")
            else "medium",
            "category": rule.category,
            "rule_id": rule.rule_id,
            "remediation": rule.remediation,
            "rule_version": rule.version,
            "asset": meta.get("asset_cid",
                              meta.get("canonical",
                                       meta.get("repository", ""))),
            "resource_type": "container_image",
            "resource_id": meta.get("digest", ""),
            "resource_name": meta.get("repository", ""),
            "provider": "container",
            "metadata": {"digest": meta.get("digest", ""),
                         "repository": meta.get("repository", "")},
            "evidence": [{"evidence_type": "configuration",
                          "url": "",
                          "detection_reason":
                              f"{rule.rule_id}: observed metadata "
                              f"indicates the rule condition"}]})
        if len(out) >= MAX_FINDINGS_PER_SCAN:
            break
    return out


# ============================================================================
# Package inventory + vulnerability normalization (existing CVE surface)
# ============================================================================
def normalize_packages(raw_packages) -> list[dict]:
    """Bounded, deterministic package list normalization."""
    if not isinstance(raw_packages, list):
        raise ContainerAssessmentError(
            FAIL_PARSER, "package inventory must be a list")
    if len(raw_packages) > MAX_PACKAGES_PER_IMAGE:
        raise ContainerAssessmentError(
            FAIL_PARSER,
            f"package inventory exceeded ceiling "
            f"({len(raw_packages)} > {MAX_PACKAGES_PER_IMAGE})")
    out = []
    seen = set()
    for p in raw_packages:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").strip()[:256]
        version = str(p.get("version") or "").strip()[:64]
        if not name or not version:
            continue
        key = f"{name}@{version}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "version": version,
                    "epoch": str(p.get("epoch") or "")[:16],
                    "release": str(p.get("release") or "")[:64],
                    "arch": str(p.get("arch") or "")[:32],
                    "source": str(p.get("source") or "container")[:64]})
    return out


def normalize_vulnerabilities(raw_vulns, *, packages: list[dict],
                              image: dict) -> list[dict]:
    """Normalize CVE observations into finding-shaped dicts.

    `image` = {"registry","repository","digest","canonical"}."""
    if not isinstance(raw_vulns, list):
        raise ContainerAssessmentError(
            FAIL_PARSER, "vulnerability list must be a list")
    if len(raw_vulns) > MAX_FINDINGS_PER_SCAN:
        raise ContainerAssessmentError(
            FAIL_PARSER,
            f"vulnerability list exceeded ceiling "
            f"({len(raw_vulns)} > {MAX_FINDINGS_PER_SCAN})")
    pkg_index = {f"{p['name']}@{p['version']}": p for p in packages}
    out = []
    for v in raw_vulns:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cve") or v.get("id") or "").strip()[:128]
        if not cve:
            continue
        pkg_name = str(v.get("package") or v.get("name") or "")[:256]
        installed = str(v.get("installed_version")
                        or v.get("version") or "")[:64]
        fixed = str(v.get("fixed_version") or "")[:64]
        severity = str(v.get("severity") or "Medium").capitalize()
        if severity not in SEV_ORDER:
            severity = "Medium"
        cvss = dict(v.get("cvss") or {})
        out.append({
            "title": f"{pkg_name}: {cve}" if pkg_name else cve,
            "description": str(v.get("description")
                                or f"{cve} in {pkg_name or 'image'}")[:2000],
            "severity": severity,
            "confidence": "high" if v.get("source") else "medium",
            "category": "vulnerability",
            "rule_id": f"CONT-CVE-{cve}",
            "cve": cve,
            "cvss": cvss,
            "remediation": (f"Upgrade {pkg_name} to {fixed}"
                            if pkg_name and fixed
                            else ("Upgrade the affected package to a "
                                  "patched version" if pkg_name
                                  else "Rebuild the image from a patched "
                                       "base")),
            "asset": image.get("asset_cid",
                               image.get("canonical", "")),
            "resource_type": "container_package",
            "resource_id": cve,
            "resource_name": pkg_name,
            "provider": "container",
            "metadata": {"digest": image.get("digest", ""),
                         "repository": image.get("repository", ""),
                         "package": pkg_name,
                         "installed_version": installed,
                         "fixed_version": fixed,
                         "source": str(v.get("source") or "container")[:64]},
            "evidence": [{"evidence_type": "other",
                          "url": "",
                          "detection_reason":
                              f"{cve}: declared by package scanner "
                              f"({str(v.get('source') or 'container')[:64]})"}]},
        )
        if len(out) >= MAX_FINDINGS_PER_SCAN:
            break
    return out


# ============================================================================
# Service — tenant-bound image registration + assessment
# ============================================================================
class ContainerSecurityService:
    """Container image registration (digest identity) + assessment through
    the existing finding pipeline (§17–§20, §32)."""

    def __init__(self, platform, *, limiter=None,
                 limits: dict | None = None):
        self.svc = platform
        self.db = platform.db
        import identity as identity_mod
        self.limiter = limiter or identity_mod.RateLimiter(max_keys=8192)
        self.limits = {"scan": (12, 300)}
        if isinstance(limits, dict):
            self.limits.update(limits)

    def _audit(self, action: str, *, object_type: str, object_id: str,
               org_id: str, actor: str = "identity",
               metadata: dict | None = None):
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
        ok, retry = self.limiter.allowed(f"container:{kind}:{key}",
                                         limit, window)
        if not ok:
            raise errors.RateLimitedError("Too many attempts",
                                          retry_after=retry)

    # ------------------------------------------------------------ registration
    def image_register(self, org_id: str, *, repository: str, digest: str,
                       registry: str = "", tags: list | None = None,
                       metadata: dict | None = None,
                       created_by: str = "cli") -> models.ContainerImage:
        self._throttle("register", org_id)
        ref = f"{registry}/{repository}@{digest}" if registry else \
            f"{repository}@{digest}"
        parsed = parse_image_ref(ref)
        img = models.ContainerImage(
            org_id=org_id, repository=parsed["repository"],
            digest=parsed["digest"] or digest,
            registry=parsed["registry"],
            tags=[t for t in (tags or []) if TAG_RE.match(str(t))][:32],
            metadata=redact_meta(metadata or {}))
        img.finalize()
        try:
            self.db.execute(
                "INSERT INTO container_images (id, org_id, registry, "
                "repository, digest, tags, metadata, package_count, "
                "vuln_count, created_at, scanned_at) VALUES (?,?,?,?,?,?,?,"
                "?,?,?,?)",
                (img.id, org_id, img.registry, img.repository, img.digest,
                 store_mod.dumps(list(img.tags)),
                 store_mod.dumps(img.metadata), 0, 0, img.created_at, ""))
        except Exception as e:
            # idempotent: same org+repo+digest already present
            rows = self.db.query(
                "SELECT * FROM container_images WHERE org_id=? AND "
                "repository=? AND digest=? LIMIT 1",
                (org_id, img.repository, img.digest))
            if rows:
                return models.ContainerImage.from_row(rows[0])
            raise errors.PersistenceError(
                "container image registration failed") from e
        import metrics as _metrics
        _metrics.inc("container_images_registered")
        self._audit("container.image_registered",
                    object_type="container_image", object_id=img.id,
                    org_id=org_id, actor=created_by,
                    metadata={"repository": img.repository,
                              "digest": img.digest[:16] + "…"})
        return img

    def image_get(self, org_id: str, image_id: str) -> models.ContainerImage:
        rows = self.db.query(
            "SELECT * FROM container_images WHERE id=? AND org_id=? "
            "LIMIT 1", (image_id, org_id))
        if not rows:
            raise errors.NotFoundError("no such container image")
        return models.ContainerImage.from_row(rows[0])

    def image_list(self, org_id: str, *, repository: str = "",
                   limit: int = 200) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM container_images WHERE org_id=?"
            + (" AND repository=?" if repository else "")
            + " ORDER BY created_at DESC",
            tuple([org_id] + ([repository] if repository else [])),
            limit=max(1, min(int(limit or 200), 500)))
        return [models.ContainerImage.from_row(r).to_dict() for r in rows]

    def image_delete(self, org_id: str, image_id: str, *,
                     actor: str = "cli") -> dict:
        """Unregister the image (org-scoped). Existing findings/evidence
        stay — they are immutable scan history."""
        img = self.image_get(org_id, image_id)
        self.db.execute(
            "DELETE FROM container_images WHERE id=? AND org_id=?",
            (image_id, org_id))
        self._audit("container.image_deleted",
                    object_type="container_image", object_id=image_id,
                    org_id=org_id, actor=actor,
                    metadata={"repository": img.repository})
        return {"deleted": image_id}

    # ---------------------------------------------------------------- scanning
    def scan(self, org_id: str, project_id: str, image_id: str, *,
                 scan_id: str = "",
             packages: list | None = None,
             vulnerabilities: list | None = None,
             image_metadata: dict | None = None,
             actor: str = "cli") -> dict:
        """Assess a registered image with the PROVIDED (bounded) package
        inventory and CVE observations. The registry is never pulled here —
        callers supply metadata; an unavailable registry is an explicit
        failure (§45, §47)."""
        self._throttle("scan", f"{org_id}|{image_id}")
        self.svc.project_require(project_id)
        img = self.image_get(org_id, image_id)
        meta = dict(img.metadata)
        # merge observable assessment metadata (bounded)
        observable = redact_meta(dict(image_metadata or {}))
        for k in ("privileged", "host_network", "host_pid",
                  "host_path_mounts", "capabilities", "run_as_uid",
                  "limits", "sensitive_env_keys", "digest", "repository"):
            if k in observable:
                meta[k] = observable[k]
        meta.setdefault("digest", img.digest)
        meta.setdefault("repository", img.repository)
        meta.setdefault("registry", img.registry)
        meta.setdefault("canonical",
                        f"{img.registry}/{img.repository}@{img.digest}")
        import cloud_security as _cs
        meta.setdefault(
            "asset_cid",
            _cs.canonical_resource_id("container", org_id, "global",
                                      "container_image", img.digest))
        pkgs = normalize_packages(packages or [])
        vulns = normalize_vulnerabilities(vulnerabilities or [],
                                          packages=pkgs, image=meta)
        findings = assess_image_metadata(meta) + vulns
        if scan_id:
            # job-dispatched assessment: reuse the umbrella scan (the
            # worker owns its lifecycle — do NOT transition it here)
            scan = self.svc.scan_get(scan_id)
        else:
            import secrets as _secrets
            scan = self.svc.scan_create(
                project_id, "container-image", scope_ref=image_id,
                scan_id=scan_id or models.stable_id(
                    models.NS_SCAN,
                    f"{project_id}|container-image|{models.utcnow()}|"
                    f"{_secrets.token_hex(4)}"),
                initiator={"org_id": org_id, "image_id": image_id,
                           "digest": img.digest})
        self._audit("container.scan.started", object_type="container_image",
                    object_id=image_id, org_id=org_id, actor=actor,
                    metadata={"scan_id": scan.id})
        raw = {"tool": "container-security",
               "target": f"{img.registry}/{img.repository}@{img.digest}",
               "image_id": image_id, "digest": img.digest,
               "repository": img.repository,
               "assets": [{"provider": "container", "account": org_id,
                           "region": "global", "resource_type":
                               "container_image",
                           "resource_id": img.digest,
                           "name": img.repository,
                           "attributes": {"registry": img.registry,
                                          "repository": img.repository,
                                          "digest": img.digest,
                                          "internal_only": False}}],
               "findings": findings}
        import cloud_security as _cs
        persisted = _cs.persist_result(self.svc, org_id=org_id,
                                       project_id=project_id, scan_id=scan.id,
                                       raw=raw, actor=actor)
        self.db.execute(
            "UPDATE container_images SET package_count=?, vuln_count=?, "
            "scanned_at=? WHERE id=?",
            (len(pkgs), len(findings), models.utcnow(), image_id))
        if not scan_id:      # reused scans are finalized by the worker
            try:
                self.svc.scan_transition(scan.id, "completed")
            except Exception:
                pass
        self._audit("container.scan.completed",
                    object_type="container_image", object_id=image_id,
                    org_id=org_id, actor=actor,
                    metadata={"scan_id": scan.id, "packages": len(pkgs),
                              **persisted})
        return {"scan_id": scan.id, "image_id": image_id,
                "packages": len(pkgs), "vulnerabilities": len(vulns),
                "misconfigurations": len(findings) - len(vulns),
                **persisted}

    def findings(self, org_id: str, *, digest: str = "",
                 limit: int = 200) -> list[dict]:
        where = "f.project_id IN (SELECT id FROM projects WHERE org_id=?)"
        params = [org_id]
        if digest:
            where += " AND f.asset_id IN (SELECT id FROM assets WHERE value LIKE ?)"
            params.append(f"%{digest}%")
        rows = self.db.query(
            "SELECT f.id, f.title, f.severity, f.category, f.rule_id, "
            "f.cve, f.asset_id, f.first_detected, f.last_detected, "
            "f.lifecycle FROM findings f WHERE " + where +
            " ORDER BY f.last_detected DESC LIMIT ?",
            tuple(params + [max(1, min(int(limit or 200), 500))]))
        return [dict(r) for r in rows]


def redact_meta(d: dict) -> dict:
    import redact
    return redact.redact(d)
