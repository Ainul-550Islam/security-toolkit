#!/usr/bin/env python3
# ============================================================================
#  cloud_security.py — Phase 9 provider-neutral cloud security core
#  ---------------------------------------------------------------------------
#  - CloudProvider adapter interface + registry (provider-neutral; no
#    provider-specific logic in the core).
#  - In-place providers: aws / azure / gcp adapters that NEVER touch the
#    network and never read real credentials beyond env-detect; they return
#    explicit §47 failure codes when live inventory is unavailable. A
#    deterministic `fixture` provider (synthetic, seeded by the account
#    identifier) powers tests and offline demos.
#  - Deterministic resource identity:
#        provider|account_identifier|region|resource_type|resource_id
#    (mutable names are NEVER identity; §9)
#  - Deterministic, versioned, allowlisted checks (CLOUD-*-NNN, v1). Checks
#    are plain functions in an allowlist — no eval/exec, no policy code.
#  - Exposure classifier enforces the invariant:
#        internal_only  ->  NEVER internet_facing   (§15, tested)
#  - Credentials: reference-only (`credential_ref`), encrypted at rest with
#    the existing notify secret-wrap convention, hint-only views; never
#    logged, never returned, never in dashboard/API.
#  - Findings/evidence/assets persist through the EXISTING Phase-1/4 tables
#    (platform.asset_add / finding_ingest / evidence_add) — no second model.
# ============================================================================

from __future__ import annotations

import os
import re
import sys
import threading

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from services.crypto import CryptoNotConfigured, CryptoService, EncryptedValueError

import errors
import models
import store as store_mod

# ---------------------------------------------------------------- constants
PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,23}$")
MAX_INVENTORY_RESOURCES = 50_000      # hard ceiling per refresh (§44/§47)
MAX_FINDINGS_PER_SCAN = 5_000
RESOURCE_FIELDS = 64                  # metadata keys kept per resource
RULE_VERSION = "v1"
DEFAULT_PROVIDERS = ("aws", "azure", "gcp", "fixture")

# §47 — explicit, stable failure taxonomy (never '0 findings' on failure)
FAIL_CLOUD_UNAVAILABLE = "cloud_provider_unavailable"
FAIL_INVALID_CREDS = "invalid_cloud_credentials"
FAIL_PERMISSION_DENIED = "cloud_permission_denied"
FAIL_INVENTORY = "inventory_failed"
FAIL_RESOURCE_LIMIT = "resource_limit_exceeded"


class AssessmentError(errors.SecurityToolkitError):
    """Explicit Phase-9 assessment failure (never a silent 0-findings)."""

    def __init__(self, code: str, message: str, *, exit_code: int = 1):
        super().__init__(message)
        self.code = str(code)
        self.exit_code = int(exit_code)

    def user_message(self) -> str:
        return f"{self.code}: {self!s}"


# ============================================================================
# Provider adapter interface
# ============================================================================
class CloudProvider:
    """Provider-neutral adapter contract (spec §5).

    Subclasses implement inventory(); the base never talks to a cloud.
    Registration happens through register_provider()."""

    provider_id = "base"
    display_name = "Base"

    def __init__(self, account: models.CloudAccount, credentials: dict):
        self.account = account
        self.credentials = dict(credentials or {})   # refs only, no secrets

    # -- lifecycle ----------------------------------------------------------
    def resolve_credentials(self) -> dict:
        """Resolve the credential REFERENCE into an in-memory context.
        Default: explicit failure (must be overridden). Never logs values."""
        return {"ref": self.account.credential_ref}

    def inventory(self) -> list[dict]:
        """Return normalized resources (dicts). Never mutates anything."""
        raise AssessmentError(
            FAIL_CLOUD_UNAVAILABLE,
            f"provider '{self.provider_id}': live inventory adapter is not "
            f"configured in this environment (supply short-lived "
            f"credentials / workload identity via a credential reference)")

    def close(self) -> None:
        """Drop transient credential references after the bounded provider call."""
        self.credentials.clear()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(provider_id={self.provider_id!r}, credentials=[REDACTED])"


_PROVIDERS: dict[str, type[CloudProvider]] = {}
_providers_lock = threading.Lock()


def register_provider(cls: type[CloudProvider]) -> type[CloudProvider]:
    with _providers_lock:
        _PROVIDERS[cls.provider_id] = cls
    return cls


def provider_ids() -> tuple[str, ...]:
    with _providers_lock:
        return tuple(sorted(_PROVIDERS))


def registered_providers() -> tuple[str, ...]:
    """Alias used by CLI/tests (uniform Phase-9 naming)."""
    return provider_ids()


def get_provider_class(provider_id: str) -> type[CloudProvider]:
    with _providers_lock:
        cls = _PROVIDERS.get(provider_id)
    if cls is None:
        raise errors.ValidationError(
            f"Unknown cloud provider: {provider_id!r} "
            f"(supported: {', '.join(provider_ids())})")
    return cls


# ============================================================================
# Fixture provider — deterministic synthetic inventory (offline tests/demos)
# ============================================================================
@register_provider
class FixtureProvider(CloudProvider):
    """Deterministic synthetic inventory seeded by the account identifier.
    Clearly labeled; used by tests and offline demos only. Generates a fixed
    spread: compute, storage (incl. one public bucket), database (one
    public), security group (one 0.0.0.0/0:22), IAM (one wildcard policy),
    one encryption-missing disk and one logging-disabled setting."""

    provider_id = "fixture"
    display_name = "Deterministic fixture (offline)"

    def inventory(self) -> list[dict]:
        acct = self.account.account_identifier
        region = (self.account.region_scope or ["global"])[0]
        base = {"provider": "fixture", "account": acct, "region": region,
                "attributes": {"internal_only": False}}
        out = [
            {"resource_type": "compute_instance", "resource_id": "i-0001",
             "name": "app-01", "public_ip": "198.51.100.10",
             "attributes": {"os": "linux"}},
            {"resource_type": "storage_bucket", "resource_id": "bkt-app",
             "name": "app-assets", "attributes": {"public_acl": True,
                                                  "public_endpoint": True,
                                                  "encryption_enabled": False}},
            {"resource_type": "storage_bucket", "resource_id": "bkt-db-backup",
             "name": "db-backup",
             "attributes": {"public_acl": False, "encryption_enabled": True,
                            "internal_only": True}},
            {"resource_type": "database", "resource_id": "db-main",
             "name": "main-db",
             "attributes": {"publicly_accessible": True,
                            "engine": "postgres",
                            "encryption_enabled": True}},
            {"resource_type": "security_group", "resource_id": "sg-web",
             "name": "web-sg",
             "attributes": {"open_ports": [{"port": 22, "cidr":
                                             "0.0.0.0/0"},
                                            {"port": 443,
                                             "cidr": "0.0.0.0/0"}]}},
            {"resource_type": "load_balancer", "resource_id": "lb-public",
             "name": "ingress-lb",
             "attributes": {"scheme": "internet-facing",
                            "public_endpoint": True}},
            {"resource_type": "iam_policy", "resource_id": "pol-wild",
             "name": "legacy-wide",
             "attributes": {"statements": [
                 {"effect": "Allow", "action": ["*"],
                  "resource": ["*"], "principal": ["*"]}]}},
            {"resource_type": "access_key", "resource_id": "ak-0001",
             "name": "ci-key", "attributes": {"age_days": 400,
                                              "last_used": ""}},
            {"resource_type": "disk", "resource_id": "vol-0001",
             "name": "data-vol",
             "attributes": {"encryption_enabled": False}},
            {"resource_type": "account_settings", "resource_id": "global",
             "name": "settings",
             "attributes": {"logging_enabled": False,
                            "monitoring_enabled": False}},
        ]
        out = [{**base, **{k: v for k, v in r.items()
                           if k != "attributes"},
                "attributes": {**base["attributes"],
                               **r.get("attributes", {})},
                "account": acct, "region": region} for r in out]
        if len(out) > MAX_INVENTORY_RESOURCES:
            raise AssessmentError(FAIL_RESOURCE_LIMIT,
                                  "fixture inventory exceeded ceiling")
        return out


# ============================================================================
# Live provider adapters (aws / azure / gcp) — explicit, read-only, bounded
# ============================================================================
class _EnvDetectProvider(CloudProvider):
    """Base for optional SDK adapters with explicit credential references."""

    env_vars: tuple[str, ...] = ()

    def resolve_credentials(self) -> dict:
        if self.credentials.get("credential_secret"):
            return self.credentials
        ref = str(self.account.credential_ref or "")
        if ref in {"workload_identity", "default"}:
            return self.credentials
        if ref.startswith("env:"):
            present = [name for name in self.env_vars
                       if name in os.environ and os.environ.get(name)]
            if present:
                return self.credentials
            raise AssessmentError(
                FAIL_INVALID_CREDS,
                f"provider '{self.provider_id}': referenced environment "
                "credentials are unavailable",
            )
        raise AssessmentError(
            FAIL_CLOUD_UNAVAILABLE,
            f"provider '{self.provider_id}': no supported credential "
            "reference or encrypted credential material is configured",
        )

    def inventory(self) -> list[dict]:
        self.resolve_credentials()
        try:
            if self.provider_id == "aws":
                from services.cloud_aws import AwsInventoryAdapter
                adapter = AwsInventoryAdapter()
            elif self.provider_id == "azure":
                from services.cloud_azure import AzureInventoryAdapter
                adapter = AzureInventoryAdapter()
            elif self.provider_id == "gcp":
                from services.cloud_gcp import GcpInventoryAdapter
                adapter = GcpInventoryAdapter()
            else:
                raise AssessmentError(FAIL_CLOUD_UNAVAILABLE,
                                      "cloud provider adapter is unavailable")
            return adapter.inventory(self.account, self.credentials)
        except AssessmentError:
            raise
        except Exception as exc:
            from services.cloud_common import CloudAdapterError
            if not isinstance(exc, CloudAdapterError):
                raise AssessmentError(
                    FAIL_INVENTORY,
                    f"provider '{self.provider_id}': adapter operation failed",
                ) from None
            failure_codes = {
                "not_configured": (FAIL_CLOUD_UNAVAILABLE,
                                   "provider SDK or credentials are not configured"),
                "invalid_credentials": (FAIL_INVALID_CREDS,
                                        "provider credentials are invalid"),
                "permission_denied": (FAIL_PERMISSION_DENIED,
                                      "provider permissions are insufficient"),
                "scope_mismatch": (FAIL_INVALID_CREDS,
                                   "provider identity does not match the account"),
                "resource_limit_exceeded": (FAIL_RESOURCE_LIMIT,
                                            "provider inventory exceeded its configured limit"),
                "timeout": (FAIL_INVENTORY,
                            "provider inventory exceeded its time limit"),
                "rate_limited": (FAIL_INVENTORY,
                                 "provider rate limit was reached"),
                "unavailable": (FAIL_CLOUD_UNAVAILABLE,
                                "provider service is unavailable"),
                "inventory_failed": (FAIL_INVENTORY,
                                     "provider inventory operation failed"),
            }
            code, message = failure_codes.get(
                exc.code,
                (FAIL_INVENTORY, "provider inventory operation failed"),
            )
            raise AssessmentError(code, message) from None


@register_provider
class AwsProvider(_EnvDetectProvider):
    provider_id = "aws"
    display_name = "AWS inventory adapter"
    env_vars = (
        "AWS_ACCESS_KEY_ID", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_PROFILE",
    )


@register_provider
class AzureProvider(_EnvDetectProvider):
    provider_id = "azure"
    display_name = "Azure subscription inventory adapter"
    env_vars = (
        "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE",
    )


@register_provider
class GcpProvider(_EnvDetectProvider):
    provider_id = "gcp"
    display_name = "Google Cloud project inventory adapter"
    env_vars = (
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN",
    )


# ============================================================================
# Exposure classifier (§15 — invariant enforced and tested)
# ============================================================================
_ANY_CIDR = {"0.0.0.0/0", "::/0"}
_MGMT_PORTS = {22, 3389, 23, 5900}


def classify_exposure(resource: dict) -> str:
    """Deterministic exposure label.

    Invariant: an explicit `internal_only` resource can NEVER be classified
    internet_facing — even when it carries public-looking attributes
    (authoritative metadata wins; fail-closed to internal)."""
    attrs = resource.get("attributes") or {}
    if bool(attrs.get("internal_only")):
        return "internal"
    if _looks_public(resource, attrs):
        return "internet_facing"
    return "internal"


def _looks_public(resource: dict, attrs: dict) -> bool:
    if _truthy(attrs.get("public_ip")) or _truthy(attrs.get("public_ipv6")):
        return True
    if _truthy(attrs.get("public_endpoint")):
        return True
    if _truthy(attrs.get("publicly_accessible")):
        return True
    if _truthy(attrs.get("public_acl")) or _truthy(attrs.get("public_read")):
        return True
    if str(attrs.get("scheme", "")).lower() in ("internet-facing",
                                                "internet_facing"):
        return True
    if str(attrs.get("access", "")).lower() in ("public-read",
                                                "public-read-write"):
        return True
    for rule in attrs.get("open_ports") or []:
        if isinstance(rule, dict) and str(rule.get("cidr", "")) in _ANY_CIDR:
            return True
    for cidr in attrs.get("cidrs") or []:
        if str(cidr) in _ANY_CIDR:
            return True
    return False


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on",
                                     "public", "open", "enabled")
    return bool(v)


# ============================================================================
# Deterministic check allowlist (CLOUD-*-NNN, v1) — plain functions, no eval
# ============================================================================
class CloudRule:
    __slots__ = ("rule_id", "title", "description", "severity", "category",
                 "resource_types", "remediation", "references", "version",
                 "check")

    def __init__(self, rule_id, title, description, severity, category,
                 resource_types, remediation, references, check,
                 version=RULE_VERSION):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.category = category
        self.resource_types = frozenset(resource_types)
        self.remediation = remediation
        self.references = tuple(references)
        self.version = version
        self.check = check          # fn(resource, attrs) -> bool (matches)

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "title": self.title,
                "description": self.description, "severity": self.severity,
                "category": self.category,
                "resource_types": sorted(self.resource_types),
                "remediation": self.remediation,
                "references": list(self.references),
                "version": self.version}

    def matches(self, resource: dict) -> dict | None:
        rtype = str(resource.get("resource_type", ""))
        if self.resource_types and rtype not in self.resource_types:
            return None
        attrs = resource.get("attributes") or {}
        try:
            ok = bool(self.check(resource, attrs))
        except Exception:
            return None                       # never fail open
        if not ok:
            return None
        return {"rule_id": self.rule_id, "title": self.title,
                "description": self.description, "severity": self.severity,
                "category": self.category, "remediation": self.remediation,
                "references": list(self.references), "version": self.version,
                "resource_type": rtype, "resource_id": str(resource.get(
                    "resource_id", "")), "name": str(resource.get("name", ""))}


def _has_cidr(attrs, cidrs, *, any_cidr=True) -> bool:
    seen = set(attrs.get("cidrs") or [])
    for rule in attrs.get("open_ports") or []:
        if isinstance(rule, dict):
            seen.add(str(rule.get("cidr", "")))
    return bool(seen & set(cidrs)) if not any_cidr else bool(
        seen & _ANY_CIDR)


def _open_mgmt(attrs) -> bool:
    for rule in attrs.get("open_ports") or []:
        if isinstance(rule, dict) and \
                str(rule.get("cidr", "")) in _ANY_CIDR and \
                int(rule.get("port", 0) or 0) in _MGMT_PORTS:
            return True
    return False


CLOUD_RULES: tuple[CloudRule, ...] = (
    CloudRule(
        "CLOUD-STORAGE-PUBLIC-001",
        "Storage bucket is publicly readable/endpoint-public",
        "The bucket exposes objects over the public internet "
        "(public ACL, public-read access or a public endpoint).",
        "Critical", "exposure", {"storage_bucket", "storage"},
        "Restrict the bucket ACL/policy to authenticated principals and "
        "disable public endpoints; verify with an authenticated read.",
        ["CIS AWS 2.1.2", "CIS GCP 1.3.2"],
        lambda r, a: bool(a.get("public_acl")
                          or a.get("public_read")
                          or a.get("public_endpoint"))),
    CloudRule(
        "CLOUD-DB-PUBLIC-002",
        "Database is publicly accessible",
        "The database accepts connections from the public internet or "
        "has a public endpoint.",
        "Critical", "exposure", {"database", "db", "rds",
                                 "sql_database", "bigtable", "cosmos"},
        "Disable public accessibility, place the DB in a private subnet "
        "and restrict the security group to app tiers only.",
        ["CIS AWS 2.3.1"],
        lambda r, a: bool(a.get("publicly_accessible")
                          or a.get("public_endpoint"))),
    CloudRule(
        "CLOUD-NET-MGMT-OPEN-003",
        "Management port open to the internet",
        "A security group/firewall allows a management port (22/3389/23/"
        "5900) from 0.0.0.0/0 or ::/0.",
        "High", "misconfiguration",
        {"security_group", "firewall", "network_acl", "security_groups"},
        "Restrict management ports to administratively-controlled CIDRs "
        "or a VPN/bastion.", ["CIS AWS 5.1.1"],
        lambda r, a: _open_mgmt(a)),
    CloudRule(
        "CLOUD-NET-ANY-OPEN-004",
        "Network rule allows all traffic from the internet",
        "The resource accepts traffic from 0.0.0.0/0 or ::/0 without "
        "port restriction.",
        "High", "exposure",
        {"security_group", "firewall", "network_acl", "load_balancer",
         "kubernetes_service"},
        "Replace any-CIDR rules with scoped sources and least-privilege "
        "ports.", ["CIS AWS 5.1.2"],
        lambda r, a: _has_cidr(a, set()) or a.get("allow_all_ingress")
        is True),
    CloudRule(
        "CLOUD-ENCRYPTION-MISSING-005",
        "Encryption is not enabled at rest",
        "Resource is not configured with encryption at rest (or the "
        "configuration cannot be confirmed).",
        "Medium", "misconfiguration",
        {"storage_bucket", "storage", "database", "disk", "kms", "volume"},
        "Enable provider-managed encryption at rest for the resource.",
        ["CIS AWS 2.1.1", "CIS GCP 1.3"],
        lambda r, a: a.get("encryption_enabled") is not True),
    CloudRule(
        "CLOUD-LOGGING-DISABLED-006",
        "Cloud logging is disabled",
        "Account/application logging configuration is disabled or absent.",
        "Medium", "observability", {"account_settings", "logging_config",
                                    "global_settings"},
        "Enable audit/access logging and ship to a protected store.",
        ["CIS AWS 3.1"],
        lambda r, a: a.get("logging_enabled") is not True),
    CloudRule(
        "CLOUD-MONITORING-DISABLED-007",
        "Security monitoring is disabled",
        "Security monitoring (guardrails, threat detection, alerts) is "
        "disabled or absent.",
        "Medium", "observability", {"account_settings", "monitoring_config",
                                    "global_settings"},
        "Enable provider security monitoring and alerting.",
        ["CIS AWS 4.1"],
        lambda r, a: a.get("monitoring_enabled") is not True),
    CloudRule(
        "CLOUD-IAM-WILDCARD-008",
        "IAM policy grants wildcard access",
        "The identity policy allows '*' actions/resources or has an "
        "unrestricted principal.",
        "Critical", "identity",
        {"iam_policy", "iam_role", "policy", "role", "service_account"},
        "Replace wildcard grants with least-privilege scoped statements; "
        "review principals.",
        ["CIS AWS 1.22"],
        lambda r, a: any(
            s.get("action") == ["*"] or s.get("action") == "*" or
            "*" in (s.get("action") or []) or s.get("resource") == ["*"]
            or (str(s.get("principal", "")).strip() == "*")
            for s in a.get("statements") or [])),
    CloudRule(
        "CLOUD-KEY-UNUSED-009",
        "Privileged credential unused for a long period",
        "An access key/service account credential is old and unused — "
        "an unmanaged privileged credential.",
        "Medium", "identity", {"access_key", "service_account_key"},
        "Rotate and/or deactivate the unused credential.",
        ["CIS AWS 1.14"],
        lambda r, a: int(a.get("age_days", 0) or 0) >= 90 and
        not (a.get("last_used") or "")),
    CloudRule(
        "CLOUD-LB-PUBLIC-010",
        "Load balancer is internet-facing",
        "A load balancer exposes an internet-facing endpoint.",
        "High", "exposure", {"load_balancer", "elb", "alb", "nlb"},
        "Confirm the LB needs public exposure; otherwise use an internal "
        "scheme behind a WAF/VPN.",
        ["CIS AWS 5.2"],
        lambda r, a: str(a.get("scheme", "")).lower().startswith(
            "internet")),
)


def rule_index() -> dict[str, CloudRule]:
    return {r.rule_id: r for r in CLOUD_RULES}


def checks_list() -> list[dict]:
    """Bounded, allowlisted check metadata (dashboard '/api/cloud/checks')."""
    return [r.to_dict() for r in CLOUD_RULES]


def cloud_rules_meta() -> list[dict]:
    """Uniform Phase-9 naming (container/k8s/iac modules expose the same)."""
    return checks_list()


# ============================================================================
# Resource normalization (deterministic identity; §9)
# ============================================================================
def canonical_resource_id(provider: str, account: str, region: str,
                          resource_type: str, resource_id: str) -> str:
    """Deterministic canonical identity — the ONLY identity used for
    assets/findings. Names never participate."""
    return ("|".join([
        str(provider).strip().lower()[:32],
        str(account).strip()[:256],
        str(region or "global").strip()[:64],
        str(resource_type).strip().lower()[:64],
        str(resource_id).strip()[:256]]))


def resource_to_asset(project_id: str, resource: dict) -> models.Asset | None:
    p = str(resource.get("provider", "")).strip().lower()
    a = str(resource.get("account", "")).strip()
    rg = str(resource.get("region") or "global").strip()
    rt = str(resource.get("resource_type", "")).strip().lower()[:64]
    rid = str(resource.get("resource_id", "")).strip()[:256]
    if not (p and a and rt and rid):
        return None
    value = canonical_resource_id(p, a, rg, rt, rid)
    # existing Phase-1 generic type (no second asset model); the concrete
    # resource_type stays in metadata + value
    asset_type = "cloud_resource"
    metadata = {k: v for k, v in (resource.get("attributes") or {}).items()
                if isinstance(v, (str, int, float, bool, list, dict,
                                  type(None)))}
    metadata = {"provider": p, "account": a, "region": rg,
                "resource_type": rt, "resource_id": rid,
                "name": str(resource.get("name", ""))[:128],
                "canonical_id": value,
                "exposure": classify_exposure(resource)}
    try:
        import redact
        asset = models.Asset(project_id=project_id,
                             asset_type=asset_type,
                             value=value,
                             display=str(resource.get("name", "")
                                         or value)[:160],
                             metadata=redact.redact(metadata))
        asset.finalize()
        return asset
    except (errors.ValidationError, ValueError):
        return None


def normalize_inventory(raw_resources: list[dict], *,
                        provider: str, account: str,
                        default_region: str = "global") -> list[dict]:
    """Bounded, deterministic normalization of provider output."""
    if not isinstance(raw_resources, list):
        raise AssessmentError(FAIL_INVENTORY,
                              "inventory returned a non-list payload")
    if len(raw_resources) > MAX_INVENTORY_RESOURCES:
        raise AssessmentError(
            FAIL_RESOURCE_LIMIT,
            f"inventory exceeded ceiling ({len(raw_resources)} > "
            f"{MAX_INVENTORY_RESOURCES}); refine region scope")
    out = []
    seen_canonical = set()
    for r in raw_resources:
        if not isinstance(r, dict):
            continue
        rtype = str(r.get("resource_type") or r.get("type") or "")[:64]
        rid = str(r.get("resource_id")
                  or r.get("id") or r.get("name") or "")[:256]
        if not rtype or not rid:
            continue
        region = str(r.get("region") or default_region or "global")[:64]
        canon = canonical_resource_id(provider, account, region, rtype, rid)
        if canon in seen_canonical:            # dedup at normalization time
            continue
        seen_canonical.add(canon)
        attrs = dict(r.get("attributes") or {})
        attrs.setdefault("internal_only", bool(r.get("internal_only")))
        # hoist top-level exposure fields into attributes so the
        # classifier + rules see one uniform shape
        for _k in ("public_ip", "public_ipv6", "public_endpoint",
                   "publicly_accessible", "public_acl", "public_read",
                   "scheme", "access", "allow_all_ingress"):
            if _k in r and _k not in attrs:
                attrs[_k] = r[_k]
        out.append({"provider": provider, "account": account, "region": region,
                    "resource_type": rtype, "resource_id": rid,
                    "name": str(r.get("name") or "")[:128],
                    "attributes": attrs, "canonical_id": canon})
    return out


def assess_resources(resources: list[dict]) -> list[dict]:
    """Run the allowlisted rules over normalized resources (deterministic
    order; capped). Returns flat finding-shaped dicts."""
    findings: list[dict] = []
    for res in resources:
        for rule in CLOUD_RULES:
            hit = rule.matches(res)
            if hit:
                findings.append({
                    "title": hit["title"],
                    "description": hit["description"],
                    "severity": hit["severity"],
                    "confidence": "high" if hit["severity"] in
                                  ("Critical", "High") else "medium",
                    "category": hit["category"],
                    "rule_id": hit["rule_id"],
                    "remediation": hit["remediation"],
                    "references": hit["references"],
                    "rule_version": hit["version"],
                    "asset": res["canonical_id"],
                    "resource_type": hit["resource_type"],
                    "resource_id": hit["resource_id"],
                    "resource_name": hit["name"],
                    "provider": res["provider"], "account": res["account"],
                    "region": res["region"],
                    "evidence": [{"evidence_type": "configuration",
                                  "detection_reason": (
                                      f"{hit['rule_id']}: "
                                      f"{hit['description'][:200]}"),
                                  "url": f"cloud://{res['provider']}/"
                                         f"{res['account']}/{res['region']}/"
                                         f"{hit['resource_type']}/"
                                         f"{hit['resource_id']}"}],
                    "metadata": {"exposure": classify_exposure(res),
                                 "canonical_id": res["canonical_id"]}})
        if len(findings) >= MAX_FINDINGS_PER_SCAN:
            break
    return findings


# ============================================================================
# Persistence into the EXISTING finding/asset/evidence system
# ============================================================================
def persist_result(platform, *, org_id: str, project_id: str, scan_id: str,
                   raw: dict, actor: str = "phase9") -> dict:
    """Normalize a Phase-9 raw result into assets + findings through
    platform.asset_add / finding_ingest / evidence_add (single system).
    Returns {"assets": n, "findings": n, "capped": bool}."""
    assets_index: dict[str, str] = {}
    saved = 0
    for a in raw.get("assets") or []:
        if not isinstance(a, dict):
            continue
        asset = resource_to_asset(project_id, a)
        if asset is None:
            continue
        try:
            existing = platform.asset_add(
                project_id, asset.asset_type, asset.value,
                metadata=asset.metadata, display=asset.display)
            assets_index[asset.value] = existing.id
            saved += 1
        except Exception:
            continue
    fcount = 0
    import correlate as _corr_mod
    corr = _corr_mod.CorrelationService(platform)
    for rf in raw.get("findings") or []:
        if not isinstance(rf, dict):
            continue
        asset_id = assets_index.get(str(rf.get("asset") or ""), "")
        try:
            finding = models.Finding(
                scan_id=scan_id, project_id=project_id, asset_id=asset_id,
                title=str(rf.get("title") or "Phase 9 finding")[:280],
                description=str(rf.get("description") or "")[:2000],
                severity=_sev(rf.get("severity")),
                confidence=str(rf.get("confidence") or "medium"),
                category=str(rf.get("category") or "misconfiguration"),
                source=str(raw.get("tool") or "phase9"),
                rule_id=str(rf.get("rule_id") or "")[:128],
                cve=str(rf.get("cve") or ""),
                cvss=dict(rf.get("cvss") or {}),
                remediation=str(rf.get("remediation") or "")[:3000],
                evidence=_evidence_list(rf, raw),
                raw=_bounded(rf))
            # Phase-4 ingestion path: canonical identity, observations,
            # confidence/risk — keeps gates/diffs/reporting consistent
            # (one finding pipeline; no second store)
            corr.ingest_finding(finding,
                                evidence=_evidence_models(finding.id, rf,
                                                          raw),
                                scan_id=scan_id, raw=finding.raw,
                                job_id="")
            fcount += 1
        except Exception:
            continue
    return {"assets": saved, "findings": fcount,
            "capped": _capped(raw)}


def _sev(v) -> str:
    s = str(v or "Info").strip().lower().capitalize()
    return s if s in ("Critical", "High", "Medium", "Low", "Info") else "Info"


def _bounded(rf: dict, limit: int = 2000) -> dict:
    import redact
    return redact.redact({k: (v[:limit] if isinstance(v, str) else v)
                          for k, v in rf.items()}, )


def _capped(raw: dict) -> bool:
    fl = raw.get("findings")
    return isinstance(fl, list) and len(fl) > MAX_FINDINGS_PER_SCAN


def _evidence_list(rf: dict, raw: dict) -> list:
    evs = rf.get("evidence")
    if isinstance(evs, list):
        return [dict(e) for e in evs if isinstance(e, dict)][:8]
    return []


def _evidence_models(finding_id: str, rf: dict, raw: dict) -> list:
    out = []
    for ev in _evidence_list(rf, raw):
        try:
            out.append(models.Evidence(
                finding_id=finding_id,
                evidence_type=str(ev.get("evidence_type")
                                  or "configuration")[:32],
                url=str(ev.get("url") or "")[:2000],
                detection_reason=str(ev.get("detection_reason")
                                     or "")[:2000],
                scanner=str(raw.get("tool") or "phase9"),
                rule_id=str(rf.get("rule_id") or "")[:128]))
        except Exception:
            continue
    return out


# ============================================================================
# Service — tenant-bound lifecycle + assessment (§7, §32–33, §42)
# ============================================================================
class CloudSecurityService:
    """Cloud account registration + inventory + assessment (spec §7, §8,
    §11, §13, §32). Every method is org-scoped; callers supply org_id from
    an authorized context — never from the request."""

    def __init__(self, platform, *, limiter=None,
                 limits: dict | None = None):
        self.svc = platform
        self.db = platform.db
        self.crypto = CryptoService()
        import identity as identity_mod
        self.limiter = limiter or identity_mod.RateLimiter(max_keys=8192)
        self.limits = {"scan": (10, 300)}            # per org+account
        if isinstance(limits, dict):
            self.limits.update(limits)

    # ----------------------------------------------------------- audit/telemetry
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
        limit, window = self.limits.get(kind, (10, 300))
        ok, retry = self.limiter.allowed(f"cloud:{kind}:{key}", limit, window)
        if not ok:
            raise errors.RateLimitedError("Too many attempts",
                                          retry_after=retry)

    # ------------------------------------------------------------- accounts
    def account_create(self, org_id: str, *, provider: str,
                       account_identifier: str, display_name: str = "",
                       region_scope: list | None = None,
                       credential_ref: str = "",
                       credential_secret: str | None = None,
                       created_by: str = "cli") -> models.CloudAccount:
        if provider not in provider_ids():
            raise errors.ValidationError(
                f"Unknown cloud provider: {provider!r} "
                f"(supported: {', '.join(provider_ids())})")
        account = models.CloudAccount(
            org_id=org_id, provider=provider,
            account_identifier=account_identifier,
            display_name=display_name[:128],
            region_scope=list(region_scope or []),
            credential_ref=credential_ref[:128])
        account.finalize()
        enc, hint = self._store_credential(
            credential_secret, org_id=org_id, account_id=account.id
        )
        account.credential_enc = enc
        account.credential_hint = hint
        try:
            self.db.execute(
                "INSERT INTO cloud_accounts (id, org_id, provider, "
                "account_identifier, display_name, enabled, region_scope, "
                "credential_ref, credential_enc, credential_hint, status, "
                "last_inventory_at, last_scan_at, created_by, created_at, "
                "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (account.id, org_id, account.provider,
                 account.account_identifier, account.display_name,
                 1, store_mod.dumps(list(account.region_scope)),
                 account.credential_ref, account.credential_enc,
                 account.credential_hint, "active", "", "",
                 created_by[:128], account.created_at, account.updated_at))
        except Exception as e:
            raise errors.DuplicateError(
                f"cloud account already registered for this tenant/provider/"
                f"identifier") from e
        import metrics as _metrics
        _metrics.inc("cloud_accounts_registered")
        self._audit("cloud.account.created", object_type="cloud_account",
                    object_id=account.id, org_id=org_id, actor=created_by,
                    metadata={"provider": account.provider,
                              "account_identifier": account.account_identifier})
        return account

    @staticmethod
    def _credential_aad(org_id: str, account_id: str) -> str:
        tenant = str(org_id or "")
        account = str(account_id or "")
        if not tenant or not account or ":" in tenant or ":" in account:
            raise errors.ValidationError("cloud credential context is invalid")
        return f"cloud-account-credential:v1:{tenant}:{account}"

    def _store_credential(
        self,
        secret: str | None,
        *,
        org_id: str,
        account_id: str,
    ) -> tuple[str, str]:
        """Encrypt provider material with tenant/account-bound AES-GCM."""
        if not secret:
            return "", ""
        if not isinstance(secret, str) or len(secret.encode("utf-8")) > 16_384:
            raise errors.ValidationError("cloud credential is invalid or too large")
        context = self._credential_aad(org_id, account_id)
        try:
            blob = self.crypto.encrypt_text(secret, associated_data=context)
        except CryptoNotConfigured:
            raise errors.ConfigurationError(
                "cloud credential encryption is not configured"
            ) from None
        except EncryptedValueError:
            raise errors.ValidationError(
                "cloud credential encryption failed"
            ) from None
        return blob, "configured"

    def _provider_credentials(self, account: models.CloudAccount) -> dict:
        """Resolve encrypted account material only for the provider call."""
        result = {"ref": str(account.credential_ref or "")}
        ciphertext = str(account.credential_enc or "")
        if not ciphertext:
            return result
        context = self._credential_aad(account.org_id, account.id)
        if ciphertext.startswith("st-aesgcm:"):
            try:
                result["credential_secret"] = self.crypto.decrypt_text(
                    ciphertext, associated_data=context
                )
            except CryptoNotConfigured:
                raise errors.ConfigurationError(
                    "cloud credential decryption is not configured"
                ) from None
            except EncryptedValueError:
                raise errors.PersistenceError(
                    "cloud credential authentication failed"
                ) from None
            return result

        # Existing rows use the retired, unauthenticated notification wrapper.
        # Read it only for one-time migration, then replace it with tenant- and
        # account-bound AEAD before giving plaintext to a provider.
        try:
            import notify
            legacy_plaintext = notify._decrypt_secret(
                ciphertext, self.svc.db_path
            )
            migrated = self.crypto.encrypt_text(
                legacy_plaintext, associated_data=context
            )
        except errors.ConfigurationError:
            raise errors.ConfigurationError(
                "legacy cloud credential cannot be migrated"
            ) from None
        except CryptoNotConfigured:
            raise errors.ConfigurationError(
                "cloud credential migration is not configured"
            ) from None
        except EncryptedValueError:
            raise errors.PersistenceError(
                "cloud credential migration failed"
            ) from None
        changed = self.db.execute_affected(
            "UPDATE cloud_accounts SET credential_enc=?, updated_at=? "
            "WHERE id=? AND org_id=? AND credential_enc=?",
            (migrated, models.utcnow(), account.id, account.org_id, ciphertext),
        )
        if changed != 1:
            raise errors.PersistenceError("cloud credential changed during migration")
        self._audit(
            "cloud.credentials.migrated",
            object_type="cloud_account",
            object_id=account.id,
            org_id=account.org_id,
            actor="crypto:migration",
            metadata={"cipher_version": "v1"},
        )
        result["credential_secret"] = legacy_plaintext
        return result

    def account_get(self, org_id: str, account_id: str) -> models.CloudAccount:
        rows = self.db.query(
            "SELECT * FROM cloud_accounts WHERE id=? AND org_id=? LIMIT 1",
            (account_id, org_id))
        if not rows:
            raise errors.NotFoundError("no such cloud account")
        return models.CloudAccount.from_row(rows[0])

    def account_list(self, org_id: str, *, enabled: bool | None = None,
                     limit: int = 200) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM cloud_accounts WHERE org_id=?"
            + (" AND enabled=1" if enabled else "")
            + " ORDER BY created_at DESC", (org_id,), limit=max(1, min(
                int(limit or 200), 500)))
        return [models.CloudAccount.from_row(r).to_dict() for r in rows]

    def account_update(self, org_id: str, account_id: str, *,
                       display_name: str | None = None,
                       enabled: bool | None = None,
                       region_scope: list | None = None,
                       credential_secret: str | None = None,
                       actor: str = "cli") -> models.CloudAccount:
        acct = self.account_get(org_id, account_id)
        if display_name is not None:
            acct.display_name = str(display_name)[:128]
        if enabled is not None:
            acct.enabled = 1 if enabled else 0
        if region_scope is not None:
            acct.region_scope = [str(r)[:64] for r in region_scope][:64]
        if credential_secret:
            enc, hint = self._store_credential(
                credential_secret, org_id=org_id, account_id=acct.id
            )
            if enc:
                acct.credential_enc = enc
                acct.credential_hint = hint
                self._audit("cloud.credentials.updated",
                            object_type="cloud_account", object_id=acct.id,
                            org_id=org_id, actor=actor,
                            metadata={"rotated": True})
        acct.updated_at = models.utcnow()
        self.db.execute(
            "UPDATE cloud_accounts SET display_name=?, enabled=?, "
            "region_scope=?, credential_ref=?, credential_enc=?, "
            "credential_hint=?, updated_at=? WHERE id=?",
            (acct.display_name, acct.enabled,
             store_mod.dumps(list(acct.region_scope)), acct.credential_ref,
             acct.credential_enc, acct.credential_hint, acct.updated_at,
             acct.id))
        self._audit("cloud.account.updated", object_type="cloud_account",
                    object_id=acct.id, org_id=org_id, actor=actor,
                    metadata={"provider": acct.provider})
        return acct

    def account_delete(self, org_id: str, account_id: str, *,
                       actor: str = "cli") -> dict:
        acct = self.account_get(org_id, account_id)
        self.db.execute("DELETE FROM cloud_accounts WHERE id=? AND org_id=?",
                        (account_id, org_id))
        self._audit("cloud.account.deleted", object_type="cloud_account",
                    object_id=account_id, org_id=org_id, actor=actor,
                    metadata={"provider": acct.provider})
        return {"deleted": account_id}

    # ------------------------------------------------------ inventory + scan
    def inventory(self, org_id: str, account_id: str, *,
                  actor: str = "cli") -> list[dict]:
        """Provider inventory → normalized resources (no persistence).
        Every provider failure is explicit (never '0 resources')."""
        self._throttle("scan", f"{org_id}|{account_id}")
        acct = self.account_get(org_id, account_id)
        if not acct.enabled:
            raise errors.ValidationError("cloud account is disabled")
        try:
            cls = get_provider_class(acct.provider)
        except errors.ValidationError as e:
            raise AssessmentError(FAIL_CLOUD_UNAVAILABLE, str(e)) from e
        provider = None
        credentials: dict = {}
        try:
            credentials = self._provider_credentials(acct)
            provider = cls(acct, credentials)
            raw = provider.inventory()
            if not isinstance(raw, list):
                raise AssessmentError(
                    FAIL_INVENTORY, "provider returned an invalid inventory shape"
                )
        except AssessmentError:
            raise
        except errors.ConfigurationError:
            raise AssessmentError(
                FAIL_CLOUD_UNAVAILABLE, "cloud credential service is unavailable"
            ) from None
        except errors.PersistenceError:
            raise AssessmentError(
                FAIL_INVALID_CREDS, "cloud credential could not be authenticated"
            ) from None
        except errors.SecurityToolkitError:
            raise AssessmentError(
                FAIL_INVENTORY, "provider operation failed"
            ) from None
        except Exception as exc:
            raise AssessmentError(
                FAIL_INVENTORY,
                f"provider operation raised {type(exc).__name__[:80]}",
            ) from None
        finally:
            if provider is not None:
                try:
                    provider.close()
                except Exception:
                    pass
            credentials.clear()
        resources = normalize_inventory(raw, provider=acct.provider,
                                        account=acct.account_identifier,
                                        default_region=(acct.region_scope
                                                        or ["global"])[0])
        import metrics as _metrics
        _metrics.inc("cloud_resources_inventoried", len(resources))
        self.db.execute(
            "UPDATE cloud_accounts SET last_inventory_at=? WHERE id=?",
            (models.utcnow(), account_id))
        self._audit("cloud.inventory.refreshed", object_type="cloud_account",
                    object_id=account_id, org_id=org_id, actor=actor,
                    metadata={"provider": acct.provider,
                              "resources": len(resources)})
        return resources

    def scan(self, org_id: str, project_id: str, account_id: str, *,
                 scan_id: str = "",
             profile: str = "cloud-security", actor: str = "cli",
             compute_risk: bool = True) -> dict:
        """Inventory + deterministic assessment → raw result + persisted
        scan/assets/findings through the existing system."""
        if profile not in ("cloud-inventory", "cloud-security"):
            raise errors.ValidationError(
                f"unknown cloud profile: {profile}")
        self.svc.project_require(project_id)
        acct = self.account_get(org_id, account_id)
        # explicit unique scan id: the platform's default id is
        # second-precision (back-to-back scans of the same project+profile
        # would otherwise collide)
        if scan_id:
            # job-dispatched assessment: reuse the umbrella scan (the
            # worker owns its lifecycle — do NOT transition it here)
            scan = self.svc.scan_get(scan_id)
        else:
            import secrets as _secrets
            scan = self.svc.scan_create(
                project_id, profile, scope_ref=account_id,
                scan_id=scan_id or models.stable_id(
                    models.NS_SCAN,
                    f"{project_id}|{profile}|{models.utcnow()}|"
                    f"{_secrets.token_hex(4)}"),
                initiator={"org_id": org_id, "provider": acct.provider,
                           "account_identifier": acct.account_identifier})
        self._audit("cloud.scan.started", object_type="cloud_account",
                    object_id=account_id, org_id=org_id, actor=actor,
                    metadata={"profile": profile, "scan_id": scan.id})
        resources = self.inventory(org_id, account_id, actor=actor)
        if profile == "cloud-inventory":
            findings = []
        else:
            findings = assess_resources(resources)
        raw = {"tool": "cloud-security", "target": (
            f"{acct.provider}:{acct.account_identifier}"),
            "account_id": account_id, "provider": acct.provider,
            "account_identifier": acct.account_identifier,
            "assets": resources, "findings": findings}
        persisted = persist_result(self.svc, org_id=org_id,
                                   project_id=project_id, scan_id=scan.id,
                                   raw=raw, actor=actor)
        if not scan_id:      # reused scans are finalized by the worker
            try:
                self.svc.scan_transition(scan.id, "completed")
            except Exception:
                pass
        self.db.execute(
            "UPDATE cloud_accounts SET last_scan_at=? WHERE id=?",
            (models.utcnow(), account_id))
        self._audit("cloud.scan.completed", object_type="cloud_account",
                    object_id=account_id, org_id=org_id, actor=actor,
                    metadata={"profile": profile, "scan_id": scan.id,
                              **persisted})
        if compute_risk:
            try:
                import risk as risk_mod
                risk_mod.RiskEngine(self.svc).recompute_project(project_id)
            except Exception:
                pass
        return {"scan_id": scan.id, **persisted,
                "findings_count": len(findings),
                "resource_count": len(resources)}

    def findings(self, org_id: str, *, account_identifier: str = "",
                 limit: int = 200, rule_id: str = "") -> list[dict]:
        """Tenant-scoped cloud findings (existing finding store; mapped).
        `account_identifier` is the provider account identifier (e.g. the
        12-digit AWS account) stored in the asset metadata — NOT the
        internal cloud_account row id."""
        where, params = "f.project_id IN (SELECT id FROM projects WHERE org_id=?)", [org_id]
        if account_identifier:
            # match resources whose asset metadata carries this account
            where += (" AND f.asset_id IN (SELECT id FROM assets "
                      "WHERE metadata LIKE ?)")
            params.append(f"%{account_identifier}%")
        if rule_id:
            where += " AND f.rule_id=?"
            params.append(rule_id)
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
