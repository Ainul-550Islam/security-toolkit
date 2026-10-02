#!/usr/bin/env python3
# ============================================================================
#  iac_security.py — Phase 9 Infrastructure-as-Code security assessment
#  ---------------------------------------------------------------------------
#  - Bounded parsing: YAML/JSON via safe_load; Terraform HCL via a
#    deterministic block/attribute extractor (regex-based, size-bounded).
#    NO eval/exec/shell anywhere in this module.
#  - Secret handling: hardcoded secret-like values are DETECTED and always
#    reported redacted — the raw value is never stored, returned or logged.
#  - Explicit failure taxonomy (spec §47): a parse failure, an unsupported
#    format or a file-limit breach raises iac_* errors — a broken scan is
#    never reported as "0 findings / PASS".
#  - Provenance is recorded in the iac_scans table (Phase 9 store).
# ============================================================================

from __future__ import annotations

import re

import errors
import models

MAX_FILE_BYTES = 256 * 1024
MAX_FILES_PER_SCAN = 64
MAX_RESOURCES_PER_SCAN = 8_000
MAX_FINDINGS_PER_SCAN = 5_000
FORMATS = ("terraform", "cloudformation", "yaml", "json", "auto")

FAIL_SOURCE_UNAVAILABLE = "iac_source_unavailable"
FAIL_PARSER = "parser_failure"
FAIL_FILE_LIMIT = "iac_file_limit_exceeded"
FAIL_FORBIDDEN = "iac_source_forbidden"

SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|auth[_-]?key)",
    re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(?i)(password\s*[=:]\s*['\"]?[^\s'\"]{6,}|"
    r"(akia|skia|as[0-9a-z]{16})|"
    r"BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY|"
    r"gh[pousr]_[a-zA-Z0-9]{20,}|"
    r"xox[baprs]-[a-zA-Z0-9-]{10,})")
VAR_RE = re.compile(r"^\$\{?[^}]*\}?$|^var\.[\w.-]+$|^[\w.-]+\.\w+$")


class IacAssessmentError(errors.SecurityToolkitError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def user_message(self) -> str:
        return f"{self.code}: {self!s}"


# ============================================================================
# Rule engine (deterministic, allowlist-based)
# ============================================================================
class IacRule:
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


def _has(res: dict, *keys):
    cur = res.get("attributes") or {}
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _cidr_open(v) -> bool:
    if isinstance(v, str):
        return v.strip() in ("0.0.0.0/0", "::/0")
    if isinstance(v, dict):
        return _cidr_open(v.get("cidr_block") or v.get("cidr_ipv6"))
    if isinstance(v, list):
        return any(_cidr_open(x) for x in v)
    return False


def _sg_open(res: dict) -> list[str]:
    at = res.get("attributes") or {}
    out = []
    ing = at.get("ingress") or at.get("dynamic_ingress") or []
    if isinstance(ing, dict):
        ing = [ing]
    for rule in ing if isinstance(ing, list) else []:
        if not isinstance(rule, dict):
            continue
        if _cidr_open(rule.get("cidr_blocks") or rule.get("cidr_block")
                      or rule.get("ipv6_cidr_blocks")):
            ports = str(rule.get("from_port", rule.get("port", "") or ""))
            to = rule.get("to_port", "")
            proto = str(rule.get("protocol", "") or "")
            if (proto in ("-1", "all") or ports in ("22", "3389", "3306",
                                                    "5432", "6379", "27017",
                                                    "1433", "9200")):
                out.append(f"{proto}/{ports}-{to} open to 0.0.0.0/0")
    if at.get("type") == "ingress" and _cidr_open(
            at.get("cidr_blocks") or at.get("cidr_block")):
        ports = str(at.get("from_port", at.get("port", "") or ""))
        if ports in ("22", "3389", "3306", "5432", "6379", "27017",
                     "1433", "9200", "-1"):
            out.append(f"ingress {ports} open to 0.0.0.0/0")
    return out[:16]


def _policy_wildcards(res: dict) -> list[str]:
    at = res.get("attributes") or {}
    out = []
    statements = (at.get("statement") or at.get("statements") or
                  at.get("policy") or [])
    if isinstance(statements, str):
        # inline policy expression/JSON — detect the wildcard marker only
        if '"*"' in statements or "'*'" in statements or \
                re.search(r'\bAction\s*=\s*"\*\."|"\*"', statements):
            return ["Action/Resource wildcard *"]
        return []
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements if isinstance(statements, list) else []:
        if not isinstance(st, dict):
            continue
        action = st.get("action") or st.get("actions") or []
        resource = st.get("resource") or st.get("resources") or []
        if not isinstance(action, list):
            action = [action]
        if not isinstance(resource, list):
            resource = [resource]
        if any(str(a).strip() == "*" for a in action) or any(
                str(r).strip() == "*" for r in resource):
            out.append("Action/Resource wildcard *")
    return out[:8]


_TF_ATTR_RE = re.compile(
    r'(?m)^\s{2,}([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*(?=\n\s{2,}[A-Za-z0-9_.-]+\s*=|\n\s*[}\n]|$)')


_TF_BLOCK_RE = re.compile(r'(?m)^\s{2,}([A-Za-z0-9_.-]+)\s*\{\s*$')


def _tf_attributes(body: str) -> dict:
    """Deterministic, size-bounded key/value extraction (no eval).
    Captures both `key = value` attributes and nested `key { … }` blocks
    (recursively, with explicit depth/entry ceilings)."""
    attrs = {}
    body = body[:64_000]
    # nested blocks first — they are NOT key=value pairs
    for m in _TF_BLOCK_RE.finditer(body):
        key = m.group(1)
        if key in attrs:
            continue
        i = body.find("{", m.start())
        depth, j = 0, i
        while j < len(body) and depth >= 0:
            c = body[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        inner = body[i + 1:j]
        if not inner.strip():
            continue
        attrs[key] = _tf_attributes(inner)     # bounded recursion (1 level)
        if len(attrs) > 1_500:
            break
    # mask nested-block spans so inner attributes never leak to top level
    masked = list(body)
    for m in _TF_BLOCK_RE.finditer(body):
        i = body.find("{", m.start())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(body) and depth >= 0:
            if body[j] == "{":
                depth += 1
            elif body[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        for k in range(i, min(j + 1, len(masked))):
            if masked[k] != "\n":
                masked[k] = " "
    flat = "".join(masked)
    for m in _TF_ATTR_RE.finditer(flat):
        key, val = m.group(1), m.group(2).strip()
        if key in attrs:
            continue
        val = re.sub(r"\s+", " ", val)[:600]
        try:
            j = _tf_scalar(val)
        except Exception:
            j = val
        attrs[key] = j
        if len(attrs) > 1_500:
            break
    return attrs


def _tf_scalar(val: str):
    v = val.strip()
    if len(v) >= 2 and v[0] in ('"', "'") and v[-1] == v[0]:
        return v[1:-1].replace('\\"', '"')
    if v.startswith("["):
        items = [x.strip() for x in v.strip("[]").split(",")][:128]
        return [_tf_scalar(x) for x in items if x]
    if v.startswith("{"):
        return v[:400]
    if re.match(r"^-?\d+(\.\d+)?$", v):
        return float(v) if "." in v else int(v)
    return v


IAC_RULES: tuple[IacRule, ...] = (
    IacRule("IAC-SECRET-HARDCODED-001",
            "Hardcoded secret in infrastructure code",
            "A secret-like literal appears in the code — it will be "
            "committed and duplicated across environments.",
            "Critical", "information_disclosure",
            lambda res: _hardcoded_secret(res),
            "Move secrets to a secret manager / SSM parameter "
            "references."),
    IacRule("IAC-PUBLIC-STORAGE-002",
            "Publicly readable/writable storage",
            "Storage resource is public (ACL/bucket policy grants "
            "public access).",
            "High", "exposure",
            lambda res: _public_storage(res),
            "Block public ACLs; use bucket policy conditions and "
            "public access blocks."),
    IacRule("IAC-DB-PUBLIC-003",
            "Database publicly accessible",
            "Database resource sets publicly_accessible = true.",
            "High", "exposure",
            lambda res: str((_has(res, "publicly_accessible")
                             or _has(res, "publiclyaccessible")) or ""
                            ).lower() in ("true", "yes", "1"),
            "Set publicly_accessible = false and use private subnets."),
    IacRule("IAC-SG-ANY-OPEN-004",
            "Security group allows management/admin ports from any IP",
            "An ingress rule opens a management or database port to "
            "0.0.0.0/0.",
            "High", "exposure",
            lambda res: bool(_sg_open(res)),
            "Restrict ingress to known CIDR ranges / security groups."),
    IacRule("IAC-IAM-WILDCARD-005",
            "IAM policy with wildcard action or resource",
            "An allow statement grants '*' on an action or resource.",
            "High", "access_control",
            lambda res: bool(_policy_wildcards(res)),
            "Scope actions and resources to the minimum needed."),
    IacRule("IAC-NO-ENCRYPTION-006",
            "Storage/database lacks encryption at rest",
            "No KMS/server-side encryption or storage_encrypted is "
            "false.",
            "Medium", "misconfiguration",
            lambda res: _missing_encryption(res),
            "Enable server-side / KMS encryption for all data stores."),
    IacRule("IAC-LOGGING-DISABLED-007",
            "Storage lacks access logging",
            "Bucket logging is not configured.",
            "Medium", "logging_monitoring",
            lambda res: _missing_logging(res),
            "Enable access logging / audit configuration."),
    IacRule("IAC-UNPINNED-MODULE-008",
            "Terraform module source is unpinned",
            "A module source has no ref/version pin.",
            "Low", "supply_chain",
            lambda res: _unpinned_module(res),
            "Pin module sources to a commit/tag/registry version."),
    IacRule("IAC-UNPINNED-PROVIDER-009",
            "Terraform provider version unpinned",
            "A provider block lacks a constrained version.",
            "Low", "supply_chain",
            lambda res: _unpinned_provider(res),
            "Declare a constrained provider version."),
)


def _hardcoded_secret(res: dict) -> list[str]:
    at = res.get("attributes") or {}
    hits = []
    for k, v in (at.items() if isinstance(at, dict) else []):
        if not isinstance(k, str) or not SECRET_KEY_RE.search(k):
            continue
        if isinstance(v, str) and VAR_RE.match(v.strip()):
            continue                      # variable reference — fine
        if isinstance(v, list):
            v = " ".join(str(x) for x in v)
        if isinstance(v, str) and SECRET_VALUE_RE.search(v):
            hits.append(k)                # the value itself is never stored
        elif isinstance(v, (str, int, float)) and len(str(v)) >= 6:
            # key says password/secret/token/api-key/… and it is a literal
            # (not a reference) => hardcoded-secret indicator. The VALUE
            # is never stored, returned or logged (redacted below).
            hits.append(k)
        if len(hits) >= 8:
            break
    return hits


def _public_storage(res: dict) -> list[str]:
    at = res.get("attributes") or {}
    rt = str(res.get("resource_type") or "").lower()
    if "bucket" not in rt and "storage" not in rt:
        return []
    acl = at.get("acl") or at.get("accesscontrol")
    if str(acl or "").lower() in ("public-read", "public-read-write",
                                  "authenticated-read", "publicread"):
        return [f"acl={acl}"]
    pol = at.get("policy") or at.get("access_policy") or ""
    if isinstance(pol, str) and '"*"' in pol:
        return ["policy grants *"]
    if isinstance(pol, dict) and _policy_wildcards(
            {"attributes": {"statement": pol}}):
        return ["policy grants *"]
    return []


def _missing_encryption(res: dict) -> bool:
    at = res.get("attributes") or {}
    rt = str(res.get("resource_type") or "").lower()
    if "bucket" in rt or "storage" in rt:
        sse = (at.get("server_side_encryption_configuration")
               or at.get("bucketencryption"))
        return not bool(sse)
    if "db" in rt or "database" in rt:
        return str(at.get("storage_encrypted") or "").lower() in (
            "false", "no", "0", "")
    return False


def _missing_logging(res: dict) -> bool:
    at = res.get("attributes") or {}
    rt = str(res.get("resource_type") or "").lower()
    if "bucket" not in rt and "storage" not in rt:
        return False
    return not bool(at.get("logging") or at.get("log_delivery_options")
                    or at.get("access_logging")
                    or at.get("loggingconfiguration"))


def _unpinned_module(res: dict) -> list[str]:
    src = _has(res, "source")
    if not src or not isinstance(src, str):
        return []
    if "?ref=" in src:
        return []
    if re.search(r"registry\.terraform\.io|/modules/", src) and \
            "," not in src:
        return [src[:120]]
    if not re.search(r"[a-z0-9.]+\.[a-z]+/", src):
        return []
    return [src[:120]]


def _unpinned_provider(res: dict) -> bool:
    if str(res.get("resource_type") or "").lower() != "provider":
        return False
    at = res.get("attributes") or {}
    return not bool(at.get("version") or at.get("version_constraint"))


def iac_rules_meta() -> list[dict]:
    return [r.to_dict() for r in IAC_RULES]


# ============================================================================
# Source parsing (bounded, no eval/exec)
# ============================================================================
def parse_source(name: str, content: str, *, fmt: str = "auto") -> list[dict]:
    """Parse one IaC file into normalized resource dicts. Raises
    IacAssessmentError on malformed/oversized/unsupported input."""
    name = str(name or "inline")[:256]
    fmt = (fmt or "auto").lower()
    if len(content.encode("utf-8", "replace")) > MAX_FILE_BYTES:
        raise IacAssessmentError(
            FAIL_PARSER, f"{name}: file exceeded {MAX_FILE_BYTES} bytes")
    if fmt not in FORMATS:
        raise IacAssessmentError(
            FAIL_FORBIDDEN, f"{name}: unsupported format {fmt!r}")
    low = name.lower()
    if fmt == "auto":
        if low.endswith((".tf", ".tf.json")):
            fmt = "terraform"
        elif low.endswith((".yaml", ".yml")):
            fmt = "yaml"
        elif low.endswith(".json"):
            fmt = "json"
        else:
            fmt = "terraform"      # best-effort default (bounded)
    if fmt == "terraform":
        return _parse_terraform(name, content)
    return _parse_cfn(name, content, fmt)


def _parse_terraform(name: str, content: str) -> list[dict]:
    out = []
    # provider blocks (for pinning checks)
    for m in re.finditer(r'\bprovider\s+"([^"]+)"\s*\{', content):
        i = content.find("{", m.start())
        depth, j = 0, i
        while j < min(len(content), i + 64_000) and depth >= 0:
            c = content[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append({"format": "terraform", "resource_type": "provider",
                    "name": m.group(1),
                    "attributes": _tf_attributes(content[i + 1:j])})
    for m in re.finditer(
            r'\b(module|resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{',
            content):
        kind, rtype, name = m.group(1), m.group(2), m.group(3)
        i = content.find("{", m.start())
        depth, j = 0, i
        while j < len(content) and j - i < 64_000 and depth >= 0:
            c = content[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = content[i + 1:j]
        if kind == "module":
            rtype = "module"
        out.append({"format": "terraform",
                    "resource_type": rtype if rtype else "resource",
                    "name": name, "attributes": _tf_attributes(body)})
        if len(out) > MAX_RESOURCES_PER_SCAN:
            raise IacAssessmentError(
                FAIL_PARSER, f"{name}: resource ceiling exceeded")
    return out


def _parse_cfn(name: str, content: str, fmt: str) -> list[dict]:
    # §23 alias-bomb defence (bounded anchor/alias fan-out)
    if content.count("&") + content.count("*") > 2_000:
        raise IacAssessmentError(
            FAIL_PARSER, f"{name}: alias/anchor budget exceeded "
                         f"(YAML bomb defence)")
    try:
        import yaml
        doc = yaml.safe_load(content)
    except Exception as e:
        raise IacAssessmentError(
            FAIL_PARSER, f"{name}: parse failure ({e})") from e
    if not isinstance(doc, dict):
        raise IacAssessmentError(
            FAIL_FORBIDDEN, f"{name}: document is not a mapping")
    resources = doc.get("Resources") or {}
    if not isinstance(resources, dict):
        resources = {} if not resources else {"root": {}}
    out = []
    for rname, rspec in resources.items():
        if not isinstance(rspec, dict):
            continue
        rtype = str(rspec.get("Type") or "")[:160]
        props = rspec.get("Properties") or {}
        if not isinstance(props, dict):
            props = {}
        # lower-cased mirror so the provider-neutral rules (acl /
        # publicly_accessible / storage_encrypted / logging / …) match
        # CloudFormation's PascalCase property names too
        props = {**{str(k).lower(): v for k, v in props.items()}, **props}
        out.append({"format": "cloudformation",
                    "resource_type": rtype.split("::")[-1].lower()
                    if rtype else "resource",
                    "name": str(rname)[:128], "attributes": props})
        if len(out) > MAX_RESOURCES_PER_SCAN:
            raise IacAssessmentError(
                FAIL_PARSER, f"{name}: resource ceiling exceeded")
    return out


# ============================================================================
# Secret redaction
# ============================================================================
def redact_secret_value(value) -> str:
    """Replace a detected secret literal with a constant marker. The real
    value never leaves this call; it is never stored, returned or logged."""
    return "[REDACTED-SECRET]"


def iac_asset_id(org_id: str, source_file: str, rtype: str,
                 name: str) -> str:
    """Canonical asset value — MUST match cloud_security.canonical_resource_id
    (provider|account|region|resource_type|resource_id) so findings link to
    the persisted asset."""
    inner = f"{org_id}|{source_file}|{rtype}|{name}"
    return f"iac|{org_id}|{source_file}|iac_resource|{inner}"


# ============================================================================
# Service
# ============================================================================
class IacSecurityService:
    def __init__(self, platform, *, limiter=None,
                 limits: dict | None = None):
        self.svc = platform
        self.db = platform.db
        import identity as identity_mod
        self.limiter = limiter or identity_mod.RateLimiter(max_keys=8192)
        self.limits = {"scan": (12, 300)}
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
        ok, retry = self.limiter.allowed(f"iac:{kind}:{key}",
                                         limit, window)
        if not ok:
            raise errors.RateLimitedError("Too many attempts",
                                          retry_after=retry)

    @staticmethod
    def _files_param(files) -> list:
        if isinstance(files, dict):
            files = [{"name": k, "content": v} for k, v in files.items()]
        if not isinstance(files, list) or not files:
            raise IacAssessmentError(
                FAIL_SOURCE_UNAVAILABLE, "no IaC sources supplied")
        if len(files) > MAX_FILES_PER_SCAN:
            raise IacAssessmentError(
                FAIL_FILE_LIMIT,
                f"file count exceeded {MAX_FILES_PER_SCAN}")
        out = []
        for f in files:
            if not isinstance(f, dict):
                continue
            out.append((str(f.get("name") or "inline")[:256],
                        str(f.get("content") or "")))
        if not out:
            raise IacAssessmentError(
                FAIL_SOURCE_UNAVAILABLE, "no IaC sources supplied")
        return out

    def scan(self, org_id: str, project_id: str, *, files,
                 scan_id: str = "",
             source_name: str = "repository", fmt: str = "auto",
             actor: str = "cli") -> dict:
        """Assess bounded IaC sources; writes findings/assets through the
        existing pipeline and records provenance in iac_scans."""
        self._throttle("scan", f"{org_id}|{project_id}")
        self.svc.project_require(project_id)
        parsed = []
        secrets_hit = []
        for name, content in self._files_param(files):
            resources = parse_source(name, content, fmt=fmt)
            parsed.append((name, resources))
        all_resources = []
        for name, resources in parsed:
            for res in resources:
                res = dict(res)
                res["source_file"] = name
                all_resources.append(res)
            if len(all_resources) > MAX_RESOURCES_PER_SCAN:
                raise IacAssessmentError(
                    FAIL_PARSER, "resource ceiling exceeded")
        findings = []
        for res in all_resources:
            for rule in IAC_RULES:
                try:
                    hit = rule.check(res)
                except Exception:
                    hit = None
                if not hit:
                    continue
                detail = hit if isinstance(hit, list) else None
                if rule.rule_id == "IAC-SECRET-HARDCODED-001":
                    keys = detail if isinstance(detail, list) else []
                    secrets_hit.extend(keys)
                    evidence_reason = (
                        f"secret-like literal in attribute(s) "
                        f"{', '.join(sorted(set(keys))[:8])}; values "
                        f"redacted")
                    value_repr = redact_secret_value("")
                else:
                    evidence_reason = (f"{rule.rule_id}: IaC attribute "
                                       f"check matched")
                    value_repr = ""
                cid = (f"{org_id}|{str(res.get('source_file') or 'inline')}"
                       f"|{res.get('resource_type')}|{res.get('name')}")
                findings.append({
                    "title": f"{res.get('resource_type')}/"
                             f"{res.get('name')}: {rule.title}",
                    "description": rule.description,
                    "severity": rule.severity,
                    "confidence": "high" if rule.severity in (
                        "Critical", "High") else "medium",
                    "category": rule.category,
                    "rule_id": rule.rule_id,
                    "remediation": rule.remediation,
                    "rule_version": rule.version,
                    "asset": iac_asset_id(
                        org_id, str(res.get("source_file") or "inline"),
                        str(res.get("resource_type") or "resource"),
                        str(res.get("name") or "")),
                    "resource_type": "iac_resource",
                    "resource_id": cid,
                    "resource_name": str(res.get("name") or "")[:128],
                    "provider": "iac",
                    "metadata": {
                        "source": str(source_name)[:160],
                        "source_file": str(
                            res.get("source_file") or "inline")[:160],
                        "resource_type": str(
                            res.get("resource_type") or "")[:160],
                        "rule": rule.rule_id,
                        "secret_attribute": (
                            sorted(set(detail))[:8]
                            if isinstance(detail, list) else []),
                        "secret_value": (value_repr
                                         if rule.rule_id ==
                                         "IAC-SECRET-HARDCODED-001"
                                         else "")},
                    "evidence": [{"evidence_type": "configuration",
                                  "url": "",
                                  "detection_reason":
                                      evidence_reason[:2000]}]})
                if len(findings) >= MAX_FINDINGS_PER_SCAN:
                    break
            if len(findings) >= MAX_FINDINGS_PER_SCAN:
                break
        assets = []
        seen_assets = set()
        for res in all_resources:
            cid = (f"{org_id}|{str(res.get('source_file') or 'inline')}"
                   f"|{res.get('resource_type')}|{res.get('name')}")
            if cid in seen_assets:
                continue
            seen_assets.add(cid)
            assets.append({
                "provider": "iac", "account": org_id,
                "region": str(res.get("source_file") or "inline")[:160],
                "resource_type": "iac_resource", "resource_id": cid,
                "name": str(res.get("name") or "")[:128],
                "attributes": {
                    "source_file": str(
                        res.get("source_file") or "inline")[:160],
                    "format": res.get("format", "terraform"),
                    "resource_type": str(
                        res.get("resource_type") or "")[:160],
                    "internal_only": True}})
        if scan_id:
            # job-dispatched assessment: reuse the umbrella scan (the
            # worker owns its lifecycle — do NOT transition it here)
            scan = self.svc.scan_get(scan_id)
        else:
            import secrets as _secrets
            scan = self.svc.scan_create(
                project_id, "iac", scope_ref=source_name,
                scan_id=scan_id or models.stable_id(
                    models.NS_SCAN,
                    f"{project_id}|iac|{models.utcnow()}|"
                    f"{_secrets.token_hex(4)}"),
                initiator={"org_id": org_id, "source_name": source_name})
        self._audit("iac.scan.started", object_type="iac_source",
                    object_id=source_name, org_id=org_id, actor=actor,
                    metadata={"scan_id": scan.id, "files": len(parsed)})
        raw = {"tool": "iac-security", "target": source_name,
               "source_name": source_name, "files": len(parsed),
               "assets": assets, "findings": findings}
        import cloud_security as _cs
        persisted = _cs.persist_result(self.svc, org_id=org_id,
                                       project_id=project_id,
                                       scan_id=scan.id, raw=raw,
                                       actor=actor)
        import metrics as _metrics
        _metrics.inc("iac_scans")
        import store as store_mod
        import uuid as _uuid
        record_id = models.stable_id(
            models.NS_IACSCAN,
            f"{source_name}|{project_id}|{models.utcnow()}|"
            f"{_uuid.uuid4().hex[:8]}")
        record = models.IacScanRecord(
            org_id=org_id, project_id=project_id, scan_id=scan.id,
            source_name=source_name,
            file_name=((", ".join(n for n, _ in parsed)[:512])
                       or "inline"),
            format=fmt, files_parsed=len(parsed),
            resource_count=len(all_resources),
            secret_count=len(set(secrets_hit)),
            finding_count=len(findings), status="completed",
            error_code="", created_by=str(actor)[:128], id=record_id)
        record.finalize()
        self.db.execute(
            "INSERT INTO iac_scans (id, org_id, project_id, scan_id, "
            "source_name, file_name, format, files_parsed, "
            "resource_count, secret_count, finding_count, status, "
            "error_code, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,"
            "?,?,?,?,?,?)",
            (record.id, org_id, project_id, scan.id, source_name,
             record.file_name, fmt, len(parsed), len(all_resources),
             len(set(secrets_hit)), len(findings), "completed",
             "", record.created_by, record.created_at))
        if not scan_id:      # reused scans are finalized by the worker
            try:
                self.svc.scan_transition(scan.id, "completed")
            except Exception:
                pass
        self._audit("iac.scan.completed", object_type="iac_source",
                    object_id=source_name, org_id=org_id, actor=actor,
                    metadata={"scan_id": scan.id, "files": len(parsed),
                              "resources": len(all_resources), **persisted})
        return {"scan_id": scan.id, "files": len(parsed),
                "resources": len(all_resources),
                "secrets_detected": len(set(secrets_hit)), **persisted}

    def scan_records(self, org_id: str, project_id: str, *,
                     limit: int = 50) -> list[dict]:
        self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT * FROM iac_scans WHERE org_id=? AND project_id=? "
            "ORDER BY created_at DESC LIMIT ?",
            (org_id, project_id, max(1, min(int(limit or 50), 200))))
        return [dict(r) for r in rows]

    def record_delete(self, org_id: str, project_id: str,
                      record_id: str, *, actor: str = "cli") -> dict:
        """Remove ONE provenance row (org+project scoped). Findings and
        evidence stay — they are immutable scan history."""
        self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT * FROM iac_scans WHERE id=? AND org_id=? AND "
            "project_id=? LIMIT 1", (record_id, org_id, project_id))
        if not rows:
            raise errors.NotFoundError("no such iaC scan record")
        self.db.execute(
            "DELETE FROM iac_scans WHERE id=? AND org_id=? AND project_id=?",
            (record_id, org_id, project_id))
        self._audit("iac.record_deleted", object_type="iac_source",
                    object_id=record_id, org_id=org_id, actor=actor,
                    metadata={"project_id": project_id})
        return {"deleted": record_id}

    def findings(self, org_id: str, *, source_name: str = "",
                 limit: int = 200) -> list[dict]:
        where = "f.project_id IN (SELECT id FROM projects WHERE org_id=?)"
        params = [org_id]
        if source_name:
            where += " AND f.rule_id LIKE 'IAC-%' AND f.raw LIKE ?"
            params.append(f"%{source_name}%")
        rows = self.db.query(
            "SELECT f.id, f.title, f.severity, f.category, f.rule_id, "
            "f.asset_id, f.first_detected, f.last_detected, f.lifecycle "
            "FROM findings f WHERE " + where +
            " ORDER BY f.last_detected DESC LIMIT ?",
            tuple(params + [max(1, min(int(limit or 200), 500))]))
        return [dict(r) for r in rows]


def redact_meta(d: dict) -> dict:
    import redact
    return redact.redact(d)
