#!/usr/bin/env python3
# ============================================================================
#  scope.py — reusable authorization/scope engine (Phase-1 security boundary)
#  ---------------------------------------------------------------------------
#  A ScopePolicy contains allow/deny entries. Entries may be:
#    - exact hostname            example.com            (apex ONLY)
#    - wildcard hostname         *.example.com          (any subdomain depth)
#    - hostname with port        api.example.com:8443
#    - IP address                192.0.2.10
#    - CIDR range                10.0.0.0/8
#    - URL prefix                https://app.example.com/admin/  (host+path)
#
#  Rules (fail-closed):
#    1. malformed input -> ValidationError (or "not in scope" for malformed
#       hostnames — a hostile target must NEVER be silently allowed)
#    2. deny-list wins over allow-list
#    3. no matching allow rule -> OUT OF SCOPE
#    4. http/https are first-class; other schemes are out of scope
#
#  Integration points: subdomain enum, spider, template engine, active fuzzer,
#  web/API audits, workflow, Rust scanners (guarded at the CLI boundary).
# ============================================================================

from __future__ import annotations

import ipaddress
import json
import os
import re
from urllib.parse import urlparse

import errors
import models
import sec_config

HOST_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
MAX_ENTRIES = 500


# ---------------------------------------------------------------------------
# Entry normalization
# ---------------------------------------------------------------------------
class _Entry:
    __slots__ = ("raw", "kind", "host", "port", "network", "path")

    def __init__(self, raw: str):
        self.raw = raw
        self.kind = ""      # host|wildcard|ip|cidr|url
        self.host = ""
        self.port = None
        self.network = None
        self.path = ""
        self._parse(raw)

    def _parse(self, raw: str):
        raw = raw.strip()
        if not raw:
            raise errors.ValidationError("Empty scope entry")
        low = raw.lower()
        # URL form: scheme://host[:port]/path
        if low.startswith(("http://", "https://")):
            p = urlparse(raw)
            if not p.netloc:
                raise errors.ValidationError(f"Invalid scope URL: {raw!r}")
            self.kind = "url"
            self.path = p.path or "/"
            self.host = models.normalize_hostname(p.hostname or "")
            self.port = p.port
            return
        # CIDR
        if "/" in raw:
            try:
                self.network = ipaddress.ip_network(raw, strict=False)
                self.kind = "cidr"
                return
            except ValueError as e:
                raise errors.ValidationError(f"Invalid CIDR: {raw!r}") from e
        # bare IP
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", raw):
            try:
                self.network = ipaddress.ip_network(raw + "/32")
                self.kind = "ip"
                return
            except ValueError as e:
                raise errors.ValidationError(f"Invalid IP: {raw!r}") from e
        # host[:port]
        host, _, port = raw.rpartition(":")
        if port.isdigit() and host:
            self.port = int(port)
            raw_host = host
        else:
            raw_host = raw
        if self.port is not None and not (1 <= self.port <= 65535):
            raise errors.ValidationError(f"Invalid port in scope entry: {raw!r}")
        # wildcard hostname
        if raw_host.startswith("*."):
            base = raw_host[2:]
            if not HOST_RE.match(base):
                raise errors.ValidationError(
                    f"Invalid wildcard scope entry: {raw!r}")
            self.kind = "wildcard"
            self.host = models.normalize_hostname(base)
            return
        # exact hostname
        hostname = models.normalize_hostname(raw_host)
        if not HOST_RE.match(hostname):
            raise errors.ValidationError(f"Invalid hostname in scope entry: {raw!r}")
        self.kind = "host"
        self.host = hostname

    def matches_host(self, host: str, port: int | None) -> bool:
        """Match a normalized hostname (+optional port)."""
        try:
            h = models.normalize_hostname(host)
        except errors.ValidationError:
            return False
        if self.kind in ("url", "host"):
            if h != self.host:
                return False
        elif self.kind == "wildcard":
            if not (h.endswith("." + self.host) and len(h) > len(self.host) + 1):
                return False
        elif self.kind in ("ip", "cidr"):
            try:
                return ipaddress.ip_address(h) in self.network
            except ValueError:
                return False
        else:
            return False
        if self.port is not None:
            return port == self.port
        return True

    def matches_url(self, url: str) -> bool:
        """For URL entries also require path-prefix match."""
        if self.kind != "url":
            return True
        try:
            p = urlparse(url)
            if not p.netloc:
                return False
            host = models.normalize_hostname(p.hostname or "")
            port = p.port
        except (errors.ValidationError, ValueError):
            return False
        if not self.matches_host(host, port):
            return False
        path = p.path or "/"
        return path.startswith(self.path)

    def text(self) -> str:
        return self.raw


def _parse_entries(items) -> list:
    if items is None:
        return []
    if isinstance(items, str):
        items = items.split(",")
    out = []
    for it in items:
        it = str(it).strip()
        if not it:
            continue
        out.append(_Entry(it))
        if len(out) > MAX_ENTRIES:
            raise errors.ValidationError(
                f"Scope policy too large: > {MAX_ENTRIES} entries")
    return out


# ---------------------------------------------------------------------------
# Policy + engine
# ---------------------------------------------------------------------------
class ScopePolicy:
    """Immutable-after-build allow/deny rule set."""

    def __init__(self, allow=None, deny=None, *, name: str = ""):
        self.name = name
        self.allow = _parse_entries(allow)
        self.deny = _parse_entries(deny)
        if not allow and not deny:
            raise errors.ValidationError("Scope policy needs at least one rule")

    @classmethod
    def from_dict(cls, d: dict, *, name: str = "") -> "ScopePolicy":
        if not isinstance(d, dict):
            raise errors.ValidationError("Scope policy must be a dict")
        return cls(d.get("allow"), d.get("deny"), name=name)

    def to_dict(self) -> dict:
        return {"allow": [e.text() for e in self.allow],
                "deny": [e.text() for e in self.deny]}

    def _evaluate(self, host: str, port: int | None, url: str | None):
        try:
            h = models.normalize_hostname(host)
        except errors.ValidationError:
            return False
        for e in self.deny:
            if e.matches_host(h, port):
                return False
            if url and e.kind == "url" and e.matches_url(url):
                return False
        for e in self.allow:
            if e.matches_host(h, port):
                if url and e.kind == "url":
                    return e.matches_url(url)
                return True
            if url and e.kind == "url" and e.matches_url(url):
                return True
        return False

    def is_in_scope(self, target: str) -> bool:
        """Check hostname, host:port, IP, CIDR or a full URL."""
        if not isinstance(target, str) or not target.strip():
            raise errors.ValidationError("Scope target must be a non-empty string")
        t = target.strip()
        url = None
        if t.lower().startswith(("http://", "https://")):
            url = t
            p = urlparse(t)
            host = p.hostname or ""
            port = p.port
        elif "://" in t:
            return False  # unsupported scheme → out of scope (fail closed)
        else:
            host, _, port = t.rpartition(":")
            if not (port.isdigit() and host):
                host, port = t, None
            else:
                port = int(port)
        return self._evaluate(host, port, url)


class ScopeEngine:
    """Loads policies from config or a policy JSON file and evaluates them.
    Fail-closed: no policy → no network scanning may run via guarded entry
    points (returns False)."""

    def __init__(self, policy: ScopePolicy | None = None):
        self.policy = policy

    @classmethod
    def from_config(cls) -> "ScopeEngine":
        cfg = sec_config.load()
        if not cfg.get("scope", {}).get("enabled"):
            return cls(None)
        policy_file = cfg.get("scope", {}).get("policy_file", "")
        if policy_file:
            try:
                with open(policy_file, encoding="utf-8") as fh:
                    d = json.load(fh)
                policy = ScopePolicy.from_dict(d, name=os.path.basename(policy_file))
            except errors.SecurityToolkitError:
                raise
            except Exception as e:
                raise errors.ConfigurationError(
                    f"Error reading scope policy {policy_file}: {e}") from e
        else:
            raise errors.ConfigurationError(
                "Scope is enabled but no policy file is configured "
                "(set scope.policy_file or SECTOOLKIT_SCOPE_POLICY)")
        return cls(policy)

    def assert_in_scope(self, target: str) -> None:
        """Raise ScopeViolationError when the target must not be scanned."""
        if self.policy is None:
            raise errors.ConfigurationError(
                "No scope policy configured — refused to authorize the target "
                "(enable scope in config with a policy file)")
        if not self.policy.is_in_scope(target):
            raise errors.ScopeViolationError(
                f"Target out of scope (denied or not allowed): {target}")

    def check(self, target: str) -> tuple[bool, str]:
        """Non-raising check: (in_scope: bool, reason)."""
        if self.policy is None:
            return False, "no scope policy configured"
        if self.policy.is_in_scope(target):
            return True, "in scope"
        return False, "denied or not allowed"


def guard_target(target: str) -> None:
    """Convenience guard used by CLI entry points.
    NO-OP when scope is disabled → full backward compatibility.
    Raises ScopeViolationError when scope is enabled and target is OOS."""
    cfg = sec_config.load()
    if not cfg.get("scope", {}).get("enabled"):
        return
    ScopeEngine.from_config().assert_in_scope(target)
