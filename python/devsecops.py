#!/usr/bin/env python3
# ============================================================================
#  devsecops.py — Phase 7 DevSecOps: CI/CD security-gate platform.
#  ---------------------------------------------------------------------------
#  EXTENDS ONLY. This service introduces NO second scanner, queue, worker,
#  project model, risk engine, audit system or report engine:
#
#    CI request → existing Phase-1 Project/Scope
#               → existing Phase-1/3 Scan + Phase-3 JobService + Worker
#               → existing Phase-4 fingerprints/risk/baseline/scan-diff
#               → existing Phase-5 remediation/monitoring
#               → NEW deterministic security gate (allowlisted policy)
#               → existing Phase-6 SARIF/redaction/reporting
#               → existing immutable audit chain
#
#  Gate semantics (documented, fail-closed):
#    pass          every mandatory (blocking) condition holds
#    fail          at least one blocking condition is violated
#    warn          only non-blocking conditions are violated
#    inconclusive  required security evidence is unavailable (scan failed,
#                  baseline/diff missing, risk never calculated, gate
#                  disabled) — NEVER silently converted into PASS.
#
#  Policy language:
#    - deterministic, allowlisted KEYS + allowlisted OPERATORS only
#    - flat structure (max depth 1), bounded size and condition count
#    - NO eval/exec/arbitrary expressions/arbitrary SQL/arbitrary fields
#
#  Idempotency: duplicate CI submissions reuse one run (UNIQUE key); gate
#  evaluation is claimed atomically (one result row per run; repeats return
#  the stored immutable result).
#
#  NO autonomous remediation, NO source-code modification, NO provider
#  credentials (adapters are metadata-only; the core is provider-neutral).
# ============================================================================

from __future__ import annotations

import ast
import fnmatch
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import errors
import metrics
import models
import redact

# ---------------------------------------------------------------------------
# Policy vocabulary: the ONLY fields a gate policy may reference (allowlist).
# ---------------------------------------------------------------------------
# key -> (kind, limits): kind selects the validator + the metric it reads.
POLICY_SPEC = {
    # numeric aggregate thresholds
    "max_risk": ("num", (0.0, 100.0)),               # total open risk
    "max_open_critical": ("int", (0, 1_000_000)),
    "max_open_high": ("int", (0, 1_000_000)),
    "max_new_findings": ("int", (0, 1_000_000)),
    "max_reopened_findings": ("int", (0, 1_000_000)),
    "max_increased_risk": ("int", (0, 1_000_000)),
    # enum thresholds
    "max_severity": ("severity", None),
    "require_minimum_confidence": ("confidence", None),
    # boolean requirements (allowed operators: == / != only)
    "block_active_findings": ("bool", None),
    "block_internet_facing_critical": ("bool", None),
    "require_no_regression": ("bool", None),
    "require_scan_success": ("bool", None),
    # Phase 11 — data-protection gate signals (counts only; never values).
    # These extend the EXISTING gate evaluator — no second engine.
    "max_secret_like_evidence": ("int", (0, 1_000_000)),
    "max_sensitive_findings": ("int", (0, 1_000_000)),
    "require_secrets_registry_clean": ("bool", None),
    "require_private_data_classified": ("bool", None),
    # Phase 12 — federation / evidence-exchange / integration gate signals
    # (counts + booleans only; never payloads, endpoints or secrets). These
    # extend the SAME gate evaluator — no second policy language.
    "max_federation_policy_violations": ("int", (0, 1_000_000)),
    "max_federation_integrity_failures": ("int", (0, 1_000_000)),
    "max_expired_federation_grants": ("int", (0, 1_000_000)),
    "max_unapproved_federation_exports": ("int", (0, 1_000_000)),
    "require_safe_external_integrations": ("bool", None),
}
OPS = ("==", "!=", ">", ">=", "<", "<=")
BOOL_OPS = ("==", "!=")
_SEV_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
# confidence as stored on findings (declared, Phase-1 vocabulary)
CONFIDENCE = models.CONFIDENCE
SEVERITIES = models.SEVERITIES
ACTIVE_STATUSES = models.FINDING_STATUSES[:5] + ("reopened", "in_review",
                                                 "confirmed")
# explicit active set (same semantics as analytics.ACTIVE_FINDING_STATUSES)
ACTIVE_FINDING_STATUSES = frozenset({"open", "acknowledged", "confirmed",
                                     "in_review", "reopened"})

MAX_POLICY_BYTES = 4096
MAX_CONDITIONS = 20
MAX_POLICY_DEPTH = 1            # policies are structurally flat
MAX_DESC_LEN = 200
MAX_ANNOTATIONS = 200
MAX_DIFF_SCANS = 5000

# CI metadata bounds (everything is allowlisted + capped)
_RE = {
    "sha": re.compile(r"^[0-9a-fA-F]{7,64}$"),
    "ref": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@-]{0,255}$"),
    "repo": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$"),
    "pipeline": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@-]{0,127}$"),
    "run_key": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@-]{0,127}$"),
    "actor": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ @-]{0,127}$"),
    "url": re.compile(r"^https?://[^\s\x00-\x1f\x7f]{1,1024}$"),
}
BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")

DEFAULT_RL = {"run": (10, 60), "evaluate": (20, 60), "export": (40, 60),
              "status": (120, 60)}

LATEST_N = 500

# Repository release/deployment gates are separate from project scan-gate
# results: they inspect this codebase and consume real fixed-tool exit codes.
# An unrun or unavailable check is never represented as PASS.
RELEASE_GATE_STATUSES = ("PASS", "WARN", "FAIL", "NOT_RUN", "UNAVAILABLE")
RELEASE_TOOL_TIMEOUT_SECONDS = 1800
_RELEASE_ROOT = Path(__file__).resolve().parents[1]
_RELEASE_EXCLUDED_DIRS = frozenset({
    ".git", ".venv", "venv", "env", "build", "dist", "target",
    "node_modules", "__pycache__", ".cache", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", "coverage", "data", "results",
})
_RELEASE_SOURCE_SUFFIXES = frozenset({
    ".py", ".toml", ".txt", ".json", ".yaml", ".yml", ".sh",
    ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
})
_RELEASE_SECRET_NAME = re.compile(
    r"(?i)(?:^|_)(?:password|passwd|pass|secret|token|api[_-]?key|"
    r"access[_-]?key|client[_-]?secret|private[_-]?key|webhook[_-]?secret|"
    r"signing[_-]?key|credential|cookie|session)(?:$|_)")
_RELEASE_SECRET_NAME_EXEMPT_SUFFIXES = (
    "_name", "_ref", "_id", "_hash", "_kind", "_type", "_status",
    "_count", "_enabled", "_required", "_provider",
)
_RELEASE_PLACEHOLDERS = frozenset({
    "changeme", "change-me", "change_me", "example", "placeholder",
    "redacted", "dummy", "fake", "test", "xxx", "none", "null",
    "your-secret", "your-token", "your-password",
})


def _release_check(name: str, status: str, *, blocking: bool,
                   reason: str, summary: str, evidence: dict | None = None) -> dict:
    if status not in RELEASE_GATE_STATUSES:
        raise errors.ConfigurationError("release_gate_status_invalid")
    return redact.redact({
        "name": name, "status": status, "blocking": bool(blocking),
        "reason": reason, "summary": summary,
        "evidence": dict(evidence or {}),
    })


def _release_rel(root: Path, path: Path) -> str:
    try:
        value = path.relative_to(root).as_posix()
    except ValueError:
        value = "external-path"
    return redact.redact_text(value)[:200]


def _release_source_paths(root: Path, *, include_tests: bool) -> list[Path]:
    """List bounded, regular repository source files; never follow symlinks
    or walk runtime databases, generated output, or package caches."""
    found = []
    for current, dirs, files in os.walk(root, followlinks=False):
        base = Path(current)
        rel_parts = base.relative_to(root).parts
        dirs[:] = [d for d in dirs if d not in _RELEASE_EXCLUDED_DIRS
                   and (include_tests or not (not rel_parts and d == "tests"))]
        for filename in files:
            path = base / filename
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() in _RELEASE_SOURCE_SUFFIXES or \
                    filename in (".env.example", ".gitignore"):
                found.append(path)
    return sorted(found, key=lambda p: p.as_posix())


def _target_names(node) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _target_names(item)]
    return []


def _is_placeholder_secret(value: str) -> bool:
    text = str(value or "").strip().lower()
    return (not text or text in _RELEASE_PLACEHOLDERS or
            text.startswith(("${", "<", "your-", "example-", "placeholder-")))


def _secret_scan(root: Path) -> dict:
    """Scan committed-like source/config with the shared redactor, reporting
    locations and counts only. Test fixtures and runtime directories are
    handled by the separate artifact/key gate, not treated as credentials."""
    hits: set[str] = set()
    read_errors: set[str] = set()
    for path in _release_source_paths(root, include_tests=False):
        rel = _release_rel(root, path)
        if rel.startswith(("docs/", "schemas/README")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            read_errors.add(rel)
            continue
        if redact.contains_secret(text):
            lines = text.splitlines()
            line_no = next((i for i, line in enumerate(lines, 1)
                            if redact.contains_secret(line)), 0)
            hits.add(f"{rel}:{line_no}" if line_no else rel)
        if path.suffix.lower() == ".py":
            try:
                tree = ast.parse(text, filename=rel)
            except SyntaxError:
                continue   # the dedicated syntax gate records this failure
            for node in ast.walk(tree):
                targets = []
                value = None
                if isinstance(node, ast.Assign):
                    targets = [name for target in node.targets
                               for name in _target_names(target)]
                    value = node.value
                elif isinstance(node, ast.AnnAssign):
                    targets = _target_names(node.target)
                    value = node.value
                if not targets or not isinstance(value, ast.Constant) or \
                        not isinstance(value.value, str):
                    continue
                for target in targets:
                    lowered = target.lower()
                    if not _RELEASE_SECRET_NAME.search(lowered) or \
                            lowered.endswith(
                                _RELEASE_SECRET_NAME_EXEMPT_SUFFIXES):
                        continue
                    literal = value.value
                    if _is_placeholder_secret(literal):
                        continue
                    candidate = f"{target}={literal}"
                    if redact.redact_text(candidate) != candidate:
                        hits.add(f"{rel}:{node.lineno}")
        elif path.name == ".env.example":
            for number, raw in enumerate(text.splitlines(), 1):
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, _, value = line.partition("=")
                key = name.strip().upper()
                if key == "SECTOOLKIT_SECRETS_PROVIDER":
                    continue
                if not _RELEASE_SECRET_NAME.search(key.lower()):
                    continue
                if _is_placeholder_secret(value):
                    continue
                if redact.redact_text(f"{key}={value}") != f"{key}={value}":
                    hits.add(f"{rel}:{number}")
    if read_errors:
        return _release_check(
            "secret_scan", "UNAVAILABLE", blocking=True,
            reason="source_read_failed", summary="Secret scan could not read every source file.",
            evidence={"unreadable_files": sorted(read_errors)[:20],
                      "finding_count": len(hits)})
    return _release_check(
        "secret_scan", "FAIL" if hits else "PASS", blocking=True,
        reason="secret_like_literal_found" if hits else "scan_complete",
        summary="Shared-redactor scan found secret-like literals." if hits
        else "No secret-like literal was detected in scanned source/config files.",
        evidence={"findings": sorted(hits)[:20], "finding_count": len(hits),
                  "redactor": "python/redact.py"})


def _syntax_check(root: Path) -> dict:
    failures = []
    unreadable = []
    for path in _release_source_paths(root, include_tests=True):
        if path.suffix.lower() != ".py":
            continue
        rel = _release_rel(root, path)
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        except SyntaxError as exc:
            failures.append(f"{rel}:{int(exc.lineno or 0)}")
        except (OSError, UnicodeError):
            unreadable.append(rel)
    if unreadable:
        status, reason = "UNAVAILABLE", "source_read_failed"
    elif failures:
        status, reason = "FAIL", "syntax_error"
    else:
        status, reason = "PASS", "syntax_valid"
    return _release_check(
        "python_syntax", status, blocking=True, reason=reason,
        summary="Python files parse with the current interpreter." if not failures
        and not unreadable else "Python syntax validation did not complete cleanly.",
        evidence={"invalid_files": failures[:20], "unreadable_files": unreadable[:20],
                  "python_version": sys.version.split()[0]})


def _ast_static_value(node, names: dict | None = None):
    """Read only literal AST nodes; never evaluate source or call constructors."""
    names = names or {}
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return names[node.id]
    if isinstance(node, ast.Tuple):
        return tuple(_ast_static_value(item, names) for item in node.elts)
    if isinstance(node, ast.List):
        return [_ast_static_value(item, names) for item in node.elts]
    if isinstance(node, ast.Set):
        return {_ast_static_value(item, names) for item in node.elts}
    if isinstance(node, ast.Dict):
        return {_ast_static_value(key, names): _ast_static_value(value, names)
                for key, value in zip(node.keys, node.values)}
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _ast_static_value(node.operand, names)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("non-numeric unary literal")
        return value if isinstance(node.op, ast.UAdd) else -value
    raise ValueError("non-literal AST node")


def _settings_defaults(root: Path) -> dict:
    path = root / "config" / "settings.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename="config/settings.py")
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != "Settings":
            continue
        for member in node.body:
            if isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name):
                try:
                    out[member.target.id] = _ast_static_value(member.value)
                except (KeyError, ValueError, TypeError):
                    continue
    return out


def _binding_auth_check(root: Path) -> dict:
    failures = []
    hosts = {}
    main_path = root / "main.py"
    dash_path = root / "python" / "dashboard.py"
    try:
        main_text = main_path.read_text(encoding="utf-8")
        dash_text = dash_path.read_text(encoding="utf-8")
    except OSError:
        return _release_check(
            "bind_auth_defaults", "UNAVAILABLE", blocking=True,
            reason="dashboard_sources_missing",
            summary="Dashboard bind/auth sources are unavailable.", evidence={})
    dash_block = main_text.split('p = sub.add_parser("dashboard"', 1)
    dash_block = dash_block[1].split("p.set_defaults(fn=cmd_dashboard)", 1)[0] \
        if len(dash_block) > 1 and "p.set_defaults(fn=cmd_dashboard)" in dash_block[1] \
        else ""
    main_match = re.search(
        r"add_argument\(\s*['\"]--host['\"]\s*,\s*default\s*=\s*['\"]([^'\"]+)",
        dash_block)
    dash_match = re.search(
        r"add_argument\(\s*['\"]--host['\"]\s*,\s*default\s*=\s*['\"]([^'\"]+)",
        dash_text)
    hosts["main.py"] = main_match.group(1) if main_match else "missing"
    hosts["python/dashboard.py"] = dash_match.group(1) if dash_match else "missing"
    for rel, host in hosts.items():
        if host == "missing" or not _is_loopback_host(host):
            failures.append(rel)
    guard_present = (
        "def is_loopback_bind_host" in dash_text and
        "not is_loopback_bind_host(args.host)" in dash_text and
        "args.token" in dash_text and "token is required" in dash_text.lower())
    if not guard_present:
        failures.append("python/dashboard.py:remote_bind_auth_guard")
    fallback_ok = ('args.host or "127.0.0.1"' in main_text or
                   "args.host or '127.0.0.1'" in main_text)
    if not fallback_ok:
        failures.append("main.py:dashboard_host_fallback")
    status = "FAIL" if failures else "PASS"
    return _release_check(
        "bind_auth_defaults", status, blocking=True,
        reason="unsafe_bind_or_missing_auth_guard" if failures else "loopback_default_and_remote_auth_required",
        summary="Dashboard defaults to loopback and requires authentication for non-loopback binds."
        if not failures else "Dashboard bind/auth defaults are not fail-closed.",
        evidence={"host_defaults": hosts,
                  "remote_bind_guard_present": guard_present,
                  "main_fallback_loopback": fallback_ok})


def _is_loopback_host(host: str) -> bool:
    value = str(host or "").strip()
    if value.lower().rstrip(".") == "localhost":
        return True
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _requirement_names(lines) -> tuple[set[str], list[str]]:
    names = set()
    unsupported = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-", ".", "git+", "http:", "https:")):
            unsupported.append("unsupported_requirement_syntax")
            continue
        name = re.split(r"[<>=!~;\[]", line, maxsplit=1)[0].strip()
        if not name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
            unsupported.append("invalid_requirement_name")
            continue
        names.add(re.sub(r"[-_.]+", "-", name).lower())
    return names, unsupported


def _dependency_config_check(root: Path) -> dict:
    pyproject = root / "pyproject.toml"
    runtime_file = root / "requirements.txt"
    dev_file = root / "requirements-dev.txt"
    missing = [p.relative_to(root).as_posix() for p in
               (pyproject, runtime_file, dev_file) if not p.is_file()]
    if missing:
        return _release_check(
            "dependency_config", "UNAVAILABLE", blocking=True,
            reason="dependency_manifests_missing",
            summary="Dependency manifests needed for consistency checks are unavailable.",
            evidence={"missing": missing})
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("project metadata must be a table")
        project = data.get("project") or {}
        if not isinstance(project, dict):
            raise ValueError("project metadata must be a table")
        optional = project.get("optional-dependencies") or {}
        if not isinstance(optional, dict):
            raise ValueError("optional dependencies must be a table")
        runtime_declared, bad_project = _requirement_names(
            project.get("dependencies") or [])
        dev_declared, bad_dev = _requirement_names(optional.get("dev") or [])
        runtime_file_names, bad_runtime_file = _requirement_names(
            runtime_file.read_text(encoding="utf-8").splitlines())
        dev_file_names, bad_dev_file = _requirement_names(
            dev_file.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, TypeError, ValueError):
        return _release_check(
            "dependency_config", "FAIL", blocking=True,
            reason="dependency_manifest_invalid",
            summary="Dependency manifests are malformed or unreadable.", evidence={})
    problems = []
    if runtime_declared != runtime_file_names:
        problems.append("runtime_manifest_mismatch")
    if dev_declared != dev_file_names:
        problems.append("development_manifest_mismatch")
    if runtime_declared.intersection(dev_declared):
        problems.append("development_dependency_in_runtime")
    if bad_project or bad_dev or bad_runtime_file or bad_dev_file:
        problems.append("unsupported_requirement_syntax")
    return _release_check(
        "dependency_config", "FAIL" if problems else "PASS", blocking=True,
        reason=";".join(problems) if problems else "manifests_consistent",
        summary="Runtime and development dependency manifests are internally consistent."
        if not problems else "Dependency manifest consistency checks failed.",
        evidence={"runtime_dependency_count": len(runtime_declared),
                  "development_dependency_count": len(dev_declared),
                  "problem_count": len(problems)})


def _configuration_check(root: Path) -> dict:
    required = (
        ".env.example", ".gitignore", "SECURITY.md", "pyproject.toml",
        "requirements.txt", "requirements-dev.txt", "config/settings.py",
        "docs/SECURITY_MODEL.md", "schemas/event.schema.json",
        "schemas/finding.schema.json", "schemas/health.schema.json",
    )
    missing = [name for name in required if not (root / name).is_file()]
    problems = []
    if (root / ".env").exists():
        problems.append("dotenv_file_present")
    try:
        defaults = _settings_defaults(root)
    except (OSError, SyntaxError, ValueError, TypeError):
        defaults = {}
        problems.append("settings_unavailable")
    if defaults.get("bind_host") != "127.0.0.1":
        problems.append("bind_default_not_loopback")
    if defaults.get("auth_required") is not True:
        problems.append("auth_not_required_by_default")
    if defaults.get("tls_required") is not True:
        problems.append("tls_not_required_by_default")
    if defaults.get("debug") is not False:
        problems.append("debug_not_disabled_by_default")
    env_values = {}
    example = root / ".env.example"
    if example.is_file():
        try:
            example_lines = example.read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            example_lines = []
            problems.append("example_config_unreadable")
        for raw in example_lines:
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env_values[key.strip()] = value.strip()
        expected = {
            "SECTOOLKIT_BIND_HOST": "127.0.0.1",
            "SECTOOLKIT_AUTH_REQUIRED": "true",
            "SECTOOLKIT_TLS_REQUIRED": "true",
            "SECTOOLKIT_DEBUG": "false",
        }
        if any(env_values.get(key, "").lower() != value
               for key, value in expected.items()):
            problems.append("example_security_defaults_mismatch")
        for key, value in env_values.items():
            if _RELEASE_SECRET_NAME.search(key.lower()) and \
                    key != "SECTOOLKIT_SECRETS_PROVIDER" and \
                    not _is_placeholder_secret(value):
                problems.append("secret_value_in_env_example")
                break
    if missing:
        problems.append("required_security_file_missing")
    status = "FAIL" if problems else "PASS"
    return _release_check(
        "required_security_config", status, blocking=True,
        reason=";".join(dict.fromkeys(problems)) if problems else "secure_config_present",
        summary="Required security configuration and placeholder examples are present."
        if not problems else "Required security configuration is missing or unsafe.",
        evidence={"missing": missing,
                  "settings_fields_present": sorted(defaults),
                  "example_keys_checked": len(env_values)})


def _literal_value(path: Path, name: str):
    """Resolve immutable literal vocabulary assignments without importing code."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if value is None:
            continue
        for target in targets:
            for target_name in _target_names(target):
                try:
                    values[target_name] = _ast_static_value(value, values)
                except (KeyError, TypeError, ValueError):
                    continue
    if name not in values:
        raise ValueError("literal assignment unavailable")
    return values[name]


def _schema_consistency_check(root: Path) -> dict:
    schema_names = ("event.schema.json", "finding.schema.json", "health.schema.json")
    schemas = {}
    problems = []
    for name in schema_names:
        path = root / "schemas" / name
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            problems.append(f"schema_unavailable:{name}")
            continue
        if not isinstance(schema, dict) or "2020-12" not in str(schema.get("$schema", "")):
            problems.append(f"schema_draft_invalid:{name}")
            continue
        if "/v1/" not in str(schema.get("$id", "")) or not schema.get("title"):
            problems.append(f"schema_identity_invalid:{name}")
        props = schema.get("properties")
        required_fields = schema.get("required")
        if not isinstance(props, dict):
            problems.append(f"schema_properties_invalid:{name}")
            continue
        if schema.get("additionalProperties") is not False:
            problems.append(f"schema_not_closed:{name}")
        if not isinstance(required_fields, list) or not all(
                isinstance(field, str) for field in required_fields) or \
                not set(required_fields).issubset(set(props)):
            problems.append(f"schema_required_invalid:{name}")
        for field, definition in props.items():
            if re.search(r"(?i)(password|secret|token|api[_-]?key|credential|private[_-]?key)",
                         str(field)):
                problems.append(f"credential_field:{name}")
            if isinstance(definition, dict) and definition.get("format") == "date-time":
                if not str(definition.get("pattern") or "").endswith("Z$"):
                    problems.append(f"timestamp_not_utc:{name}")
        schemas[name] = schema
    if len(schemas) == len(schema_names):
        try:
            severities = tuple(_literal_value(root / "core/constants.py", "SEVERITIES"))
            health_states = tuple(_literal_value(root / "core/constants.py", "HEALTH_STATES"))
            schema_version = str(_literal_value(root / "core/version.py", "SCHEMA_VERSION"))
            for name in ("event.schema.json", "finding.schema.json"):
                enum = tuple(schemas[name]["properties"]["severity"]["enum"])
                if enum != severities:
                    problems.append(f"severity_enum_mismatch:{name}")
            if tuple(schemas["health.schema.json"]["properties"]["status"]["enum"]) != health_states:
                problems.append("health_enum_mismatch")
            declared_version = schemas["event.schema.json"]["properties"][
                "schema_version"]["enum"]
            if declared_version != [schema_version]:
                problems.append("schema_version_mismatch")
            rust = (root / "native/rust/crates/engine_core/src/version.rs").read_text(
                encoding="utf-8")
            cpp = (root / "native/cpp/include/security_engine/version.hpp").read_text(
                encoding="utf-8")
            if f'SCHEMA_VERSION: &str = "{schema_version}"' not in rust or \
                    f'kSchemaVersion = "{schema_version}"' not in cpp:
                problems.append("native_schema_version_mismatch")
        except (OSError, SyntaxError, ValueError, TypeError, KeyError):
            problems.append("schema_vocabulary_unavailable")
    return _release_check(
        "schema_consistency", "FAIL" if problems else "PASS", blocking=True,
        reason=";".join(dict.fromkeys(problems)) if problems else "schema_contracts_aligned",
        summary="JSON schemas, Python vocabularies and native version markers are aligned."
        if not problems else "Schema consistency checks found a contract mismatch.",
        evidence={"schemas_checked": len(schemas), "problem_count": len(problems),
                  "problems": list(dict.fromkeys(problems))[:20]})


def _ignored_by_required_rules(relative: str, gitignore: str) -> bool:
    lines = {line.strip() for line in gitignore.splitlines() if line.strip()}
    path = relative.replace("\\", "/")
    name = Path(path).name
    for directory_rule in ("data/", "results/", "logs/"):
        if path.startswith(directory_rule):
            return directory_rule in lines
    if path == "tests/fixtures/p8test.key":
        return "!tests/fixtures/*.key" in lines and "*.key" in lines
    if path in ("rust/dir_fuzzer", "rust/port_scanner"):
        return path in lines
    for pattern in ("*.key", "*.pem", "*.p12", "*.pfx", "*.jks", "*.db",
                    "*.sqlite", "*.sqlite3", "*.log", "*.pyc", "*.so",
                    "*.dylib", "*.dll", "*.a", "*.o", "*.exe"):
        if pattern in lines and fnmatch.fnmatch(name, pattern):
            return True
    return any(path.startswith(rule.rstrip("/"))
               for rule in ("build/", "dist/", "target/", "node_modules/",
                            ".venv/", "venv/", "__pycache__/"))


def _artifact_hygiene_check(root: Path) -> dict:
    gitignore_path = root / ".gitignore"
    try:
        gitignore = gitignore_path.read_text(encoding="utf-8")
    except OSError:
        gitignore = ""
    required_rules = (
        ".env", "data/", "results/", "*.key", "*.pem", "*.db",
        "*.sqlite3", "*.log", "build/", "target/", "node_modules/",
        "__pycache__", "!tests/fixtures/*.key",
        "rust/dir_fuzzer", "rust/port_scanner",
    )
    lines = {line.strip() for line in gitignore.splitlines() if line.strip()}
    missing_rules = [rule for rule in required_rules if rule not in lines]
    offenders = []
    runtime_keys = 0
    test_keys = 0
    generated_ignored = 0
    excluded = {".git", ".venv", "venv", "build", "dist", "target",
                "node_modules", "__pycache__", ".cache", ".pytest_cache",
                ".mypy_cache", ".ruff_cache", ".tox"}
    for current, dirs, files in os.walk(root, followlinks=False):
        base = Path(current)
        dirs[:] = [d for d in dirs if d not in excluded]
        for filename in files:
            path = base / filename
            if path.is_symlink() or not path.is_file():
                continue
            rel = _release_rel(root, path)
            lower = filename.lower()
            is_key = Path(lower).suffix in {".key", ".pem", ".p12", ".pfx", ".jks"}
            if is_key:
                if rel.startswith("data/"):
                    runtime_keys += 1
                elif rel == "tests/fixtures/p8test.key":
                    test_keys += 1
                elif not _ignored_by_required_rules(rel, gitignore):
                    offenders.append(rel)
            if lower == ".env" and rel == ".env":
                offenders.append(rel)
            try:
                with path.open("rb") as handle:
                    magic = handle.read(4)
            except OSError:
                continue
            executable_magic = (magic.startswith(b"\x7fELF") or
                                magic in (b"MZ\x90\x00", b"\xfe\xed\xfa\xce",
                                          b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"))
            if executable_magic:
                if _ignored_by_required_rules(rel, gitignore):
                    generated_ignored += 1
                else:
                    offenders.append(rel)
            if lower.endswith((".log", ".db", ".sqlite", ".sqlite3", ".pyc")):
                if _ignored_by_required_rules(rel, gitignore):
                    generated_ignored += 1
                else:
                    offenders.append(rel)
    if not (root / "tests/fixtures/p8test.key").is_file():
        offenders.append("tests/fixtures/p8test.key:allowlisted_test_fixture_missing")
    if missing_rules:
        status, reason = "FAIL", "required_ignore_rules_missing"
    elif offenders:
        status, reason = "FAIL", "unignored_generated_or_key_artifact"
    else:
        status, reason = "PASS", "runtime_and_test_artifacts_covered"
    return _release_check(
        "artifact_runtime_keys", status, blocking=True, reason=reason,
        summary="Runtime keys, test fixtures and generated artifacts are covered by explicit ignore rules."
        if status == "PASS" else "Artifact/key hygiene checks found unignored files or missing ignore rules.",
        evidence={"missing_ignore_rules": missing_rules,
                  "unignored_paths": sorted(set(offenders))[:30],
                  "runtime_key_files": runtime_keys,
                  "allowlisted_test_key_files": test_keys,
                  "ignored_generated_artifacts": generated_ignored})


def _tool_availability(name: str, root: Path) -> bool:
    if name == "test_suite":
        return (root / "tests" / "run_tests.py").is_file()
    if name == "dependency_environment":
        try:
            return importlib.util.find_spec("pip") is not None
        except (ImportError, ValueError):
            return False
    executable = {"static_analysis": "ruff", "type_check": "mypy"}.get(name)
    return bool(executable and shutil.which(executable))


def _fixed_tool_check(name: str, *, root: Path, execute: bool,
                      timeout_seconds: int) -> dict:
    available = _tool_availability(name, root)
    blocking = True
    if not available:
        return _release_check(
            name, "UNAVAILABLE", blocking=blocking,
            reason="tool_not_installed" if name != "test_suite" else "test_runner_missing",
            summary="The allowlisted check cannot run because its tool is unavailable.",
            evidence={"tool_available": False, "command_id": name})
    if not execute:
        return _release_check(
            name, "NOT_RUN", blocking=blocking,
            reason="execution_not_requested",
            summary="The check is available but has not been executed in this report.",
            evidence={"tool_available": True, "command_id": name})
    if name == "test_suite":
        command = [sys.executable, "-B", str(root / "tests" / "run_tests.py")]
    elif name == "static_analysis":
        command = [shutil.which("ruff"), "check", "--output-format", "json", "."]
    elif name == "type_check":
        command = [shutil.which("mypy"), "--config-file", "pyproject.toml"]
    elif name == "dependency_environment":
        command = [sys.executable, "-B", "-m", "pip", "check"]
    else:
        raise errors.ValidationError("release_tool_not_allowlisted")
    clean_env = {"PATH": os.environ.get("PATH", ""),
                 "PYTHONPATH": "", "PYTHONDONTWRITEBYTECODE": "1",
                 "PYTHONUNBUFFERED": "1"}
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command, cwd=str(root), env=clean_env, shell=False,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout_seconds, check=False)
        output = (completed.stdout or "") + (completed.stderr or "")
        digest = hashlib.sha256(output.encode("utf-8", "replace")).hexdigest()
        status = "PASS" if completed.returncode == 0 else "FAIL"
        reason = "command_passed" if status == "PASS" else "command_failed"
        return _release_check(
            name, status, blocking=blocking, reason=reason,
            summary="Allowlisted command exited successfully." if status == "PASS"
            else "Allowlisted command returned a nonzero exit code.",
            evidence={"tool_available": True, "command_id": name,
                      "exit_code": int(completed.returncode),
                      "duration_ms": int((time.monotonic() - started) * 1000),
                      "output_bytes": len(output.encode("utf-8", "replace")),
                      "output_sha256": digest})
    except subprocess.TimeoutExpired as exc:
        output = exc.output or b""
        if isinstance(output, str):
            output = output.encode("utf-8", "replace")
        return _release_check(
            name, "FAIL", blocking=blocking, reason="command_timeout",
            summary="Allowlisted command exceeded its bounded time limit.",
            evidence={"tool_available": True, "command_id": name,
                      "duration_ms": int((time.monotonic() - started) * 1000),
                      "partial_output_sha256": hashlib.sha256(output).hexdigest()})
    except OSError:
        return _release_check(
            name, "UNAVAILABLE", blocking=blocking, reason="command_unavailable",
            summary="Allowlisted command could not be started.",
            evidence={"tool_available": False, "command_id": name})


def evaluate_release_gates(root: str | os.PathLike | None = None, *,
                           run_tools: bool = False,
                           timeout_seconds: int = RELEASE_TOOL_TIMEOUT_SECONDS) -> dict:
    """Run deterministic local release-readiness checks and report structured
    PASS/WARN/FAIL/NOT_RUN/UNAVAILABLE results. No user command/module input
    is accepted. Optional process checks use fixed argument arrays, shell=False,
    bounded timeouts, a scrubbed environment and store only exit codes/hashes.
    Tool execution is restricted to this source repository root."""
    if not isinstance(run_tools, bool):
        raise errors.ValidationError("run_tools must be a boolean")
    if isinstance(timeout_seconds, bool):
        raise errors.ValidationError("timeout_seconds must be an integer")
    try:
        timeout = int(timeout_seconds)
        if isinstance(timeout_seconds, float) and timeout != timeout_seconds:
            raise ValueError
    except (TypeError, ValueError):
        raise errors.ValidationError("timeout_seconds must be an integer") from None
    if timeout < 1 or timeout > RELEASE_TOOL_TIMEOUT_SECONDS:
        raise errors.ValidationError(
            f"timeout_seconds must be between 1 and {RELEASE_TOOL_TIMEOUT_SECONDS}")
    try:
        target = Path(root).resolve() if root is not None else _RELEASE_ROOT
    except (OSError, RuntimeError, TypeError, ValueError):
        raise errors.ValidationError("release_gate_root_unavailable") from None
    if not target.is_dir():
        raise errors.ValidationError("release_gate_root_unavailable")
    if run_tools and target != _RELEASE_ROOT:
        raise errors.ValidationError(
            "tool_execution_is_restricted_to_the_repository_root")
    checks = [
        _syntax_check(target),
        _secret_scan(target),
        _binding_auth_check(target),
        _dependency_config_check(target),
        _configuration_check(target),
        _schema_consistency_check(target),
        _artifact_hygiene_check(target),
        _fixed_tool_check("test_suite", root=target, execute=run_tools,
                           timeout_seconds=timeout),
        _fixed_tool_check("static_analysis", root=target, execute=run_tools,
                          timeout_seconds=timeout),
        _fixed_tool_check("type_check", root=target, execute=run_tools,
                          timeout_seconds=timeout),
        _fixed_tool_check("dependency_environment", root=target,
                          execute=run_tools, timeout_seconds=timeout),
    ]
    counts = {status: sum(1 for check in checks
                         if check["status"] == status)
              for status in RELEASE_GATE_STATUSES}
    if counts["FAIL"]:
        overall = "FAIL"
    elif counts["NOT_RUN"]:
        overall = "NOT_RUN"
    elif counts["UNAVAILABLE"]:
        overall = "UNAVAILABLE"
    elif counts["WARN"]:
        overall = "WARN"
    else:
        overall = "PASS"
    return redact.redact({
        "schema_version": "release-gates-v1",
        "generated_at": models.utcnow(),
        "status": overall,
        "counts": counts,
        "blocking_checks": sum(1 for check in checks if check["blocking"]),
        "checks": checks,
        "tool_execution_requested": run_tools,
        "shell_used": False,
        "user_controlled_commands_accepted": False,
    })


# ---------------------------------------------------------------------------
# Canonicalization (deterministic; timestamps excluded from result hashing)
# ---------------------------------------------------------------------------
def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Policy validation — deterministic allowlisted language (no eval/exec).
# ---------------------------------------------------------------------------
def _cond_sort_key(c: dict) -> tuple:
    return (c["key"], c["op"], json.dumps(c["value"], sort_keys=True),
            bool(c["blocking"]))


def validate_policy(policy) -> dict:
    """Validate + normalize a gate policy. Raises errors.ValidationError on
    ANY deviation (unknown field/op/key/value, bad type, oversize, depth).
    Returns the normalized policy (conditions kept in stable sorted order
    so the policy hash is deterministic regardless of input ordering)."""
    if not isinstance(policy, dict):
        raise errors.ValidationError(
            "policy_invalid: policy must be a JSON object")
    keys = set(policy.keys())
    allowed = {"version", "description", "conditions"}
    if not keys <= allowed:
        raise errors.ValidationError(
            f"policy_invalid: unknown field(s) {sorted(keys - allowed)}")
    version = policy.get("version", 1)
    try:
        version = int(version)
    except (TypeError, ValueError):
        raise errors.ValidationError("policy_invalid: version must be an "
                                     "integer")
    if version < 1 or version > 999:
        raise errors.ValidationError("policy_invalid: version out of range")
    desc = policy.get("description", "")
    if desc is not None and not isinstance(desc, str):
        raise errors.ValidationError("policy_invalid: description must be "
                                     "a string")
    desc = str(desc or "")
    if len(desc) > MAX_DESC_LEN:
        raise errors.ValidationError(
            f"policy_invalid: description exceeds {MAX_DESC_LEN} chars")
    if any(ord(ch) < 32 for ch in desc):
        raise errors.ValidationError(
            "policy_invalid: control characters not allowed")
    desc = redact.redact_text(desc)          # secrets never stored
    conds = policy.get("conditions", [])
    if not isinstance(conds, list):
        raise errors.ValidationError("policy_invalid: conditions must be a "
                                     "list")
    if len(conds) > MAX_CONDITIONS:
        raise errors.ValidationError(
            f"policy_invalid: too many conditions (max {MAX_CONDITIONS})")
    out = []
    for c in conds:
        if not isinstance(c, dict):
            raise errors.ValidationError("policy_invalid: each condition "
                                         "must be an object")
        ckeys = set(c.keys())
        if not ckeys <= {"key", "op", "value", "blocking"}:
            raise errors.ValidationError(
                f"policy_invalid: unknown condition field(s) "
                f"{sorted(ckeys - {'key', 'op', 'value', 'blocking'})}")
        if "key" not in c or "op" not in c or "value" not in c:
            raise errors.ValidationError(
                "policy_invalid: key/op/value required")
        key = str(c["key"])
        if key not in POLICY_SPEC:
            raise errors.ValidationError(
                f"policy_invalid: unknown condition key {key!r}")
        kind, lim = POLICY_SPEC[key]
        op = str(c["op"])
        if op not in OPS:
            raise errors.ValidationError(
                f"policy_invalid: unknown operator {op!r}")
        value = c["value"]
        if kind == "num":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise errors.ValidationError(
                    f"policy_invalid: {key} requires a number")
            value = round(float(value), 2)
            if value < lim[0] or value > lim[1]:
                raise errors.ValidationError(
                    f"policy_invalid: {key} out of range {lim}")
        elif kind == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise errors.ValidationError(
                    f"policy_invalid: {key} requires an integer")
            if not (lim[0] <= value <= lim[1]):
                raise errors.ValidationError(
                    f"policy_invalid: {key} out of range {lim}")
        elif kind == "severity":
            if value not in SEVERITIES:
                raise errors.ValidationError(
                    f"policy_invalid: {key} requires one of {SEVERITIES}")
        elif kind == "confidence":
            if value not in CONFIDENCE:
                raise errors.ValidationError(
                    f"policy_invalid: {key} requires one of {CONFIDENCE}")
        elif kind == "bool":
            if not isinstance(value, bool):
                raise errors.ValidationError(
                    f"policy_invalid: {key} requires a boolean")
            if op not in BOOL_OPS:
                raise errors.ValidationError(
                    f"policy_invalid: {key} supports only {BOOL_OPS}")
        blocking = bool(c.get("blocking", True))
        out.append({"key": key, "op": op, "value": value,
                    "blocking": blocking})
    out.sort(key=_cond_sort_key)
    normalized = {"version": version, "description": desc,
                  "conditions": out}
    raw = json.dumps(normalized, ensure_ascii=False)
    if len(raw.encode("utf-8")) > MAX_POLICY_BYTES:
        metrics.inc("devsecops_policy_rejected")
        raise errors.ValidationError(
            f"policy_invalid: exceeds {MAX_POLICY_BYTES} bytes")
    return normalized


def policy_hash(policy: dict) -> str:
    return sha256_hex(_canon(validate_policy(policy)))


# ---------------------------------------------------------------------------
# Pure condition evaluation (no DB, fully deterministic).
# ---------------------------------------------------------------------------
def _order_value(key: str, actual, policy_value):
    if key == "max_severity":
        return _SEV_RANK[actual], _SEV_RANK[policy_value]
    if key == "require_minimum_confidence":
        return _CONF_RANK[actual], _CONF_RANK[policy_value]
    return float(actual), float(policy_value)


def evaluate_conditions(policy: dict, evidence: dict) -> tuple[str, list]:
    """Evaluate a validated policy against a metric dict. Returns
    (status, violations) with status in pass|fail|warn. This function NEVER
    produces inconclusive — inconclusive is decided by the service when
    evidence itself cannot be trusted (fail-closed)."""
    violations = []
    for c in policy["conditions"]:
        key = c["key"]
        actual = evidence.get(key)
        if actual is None:
            actual = 0 if key not in ("max_severity",
                                      "require_minimum_confidence") else \
                (None if key == "max_severity" else "confirmed")
        if key == "max_severity":
            ok = (actual is not None and _SEV_RANK[actual] <=
                  _SEV_RANK[c["value"]]) if c["op"] in ("<=", "<") else (
                _SEV_RANK[actual] >= _SEV_RANK[c["value"]]
                if c["op"] in (">=", ">") else
                _SEV_RANK[actual] == _SEV_RANK[c["value"]]
                if c["op"] == "==" else
                _SEV_RANK[actual] != _SEV_RANK[c["value"]])
        elif key == "require_minimum_confidence":
            ok = (_CONF_RANK[actual] >= _CONF_RANK[c["value"]]
                  if c["op"] in (">=", ">") else
                  _CONF_RANK[actual] <= _CONF_RANK[c["value"]]
                  if c["op"] in ("<=", "<") else
                  _CONF_RANK[actual] == _CONF_RANK[c["value"]]
                  if c["op"] == "==" else
                  _CONF_RANK[actual] != _CONF_RANK[c["value"]])
        elif POLICY_SPEC[key][0] == "bool":
            ok = (bool(actual) == bool(c["value"])
                  if c["op"] == "==" else bool(actual) != bool(c["value"]))
        else:
            a = float(actual)
            v = float(c["value"])
            ok = {"==": a == v, "!=": a != v, ">": a > v, ">=": a >= v,
                  "<": a < v, "<=": a <= v}[c["op"]]
        if not ok:
            violations.append({"key": key, "op": c["op"],
                               "value": c["value"], "blocking": c["blocking"],
                               "actual": actual})
    violations.sort(key=lambda v: (v["key"], v["op"]))
    if any(v["blocking"] for v in violations):
        return "fail", violations
    if violations:
        return "warn", violations
    return "pass", violations


# ---------------------------------------------------------------------------
# Provider-neutral CI adapters — METADATA ONLY. No external API calls are
# performed by the core; adapters never hold credentials (documented).
# ---------------------------------------------------------------------------
class ProviderAdapter:
    """Generic adapter: validates provider metadata (all providers share the
    same bounded, allowlisted metadata contract)."""

    name = "generic"

    def normalize(self, data: dict) -> dict:
        return dict(data)


_GENERIC = ProviderAdapter()


class GenericCIClient:
    """Provider-neutral CI client surface. Concrete providers (GitHub,
    GitLab, Jenkins) are thin metadata adapters over the SAME contract; the
    platform never talks to external APIs and never stores provider
    credentials."""

    def __init__(self, registry=None):
        self._adapters = {"generic": _GENERIC}

    def adapter(self, provider: str):
        if provider not in self._adapters:
            raise errors.ValidationError(
                f"provider_unknown: {provider!r} (no adapter)")
        return self._adapters[provider]


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------
class DevSecOpsService:
    """Security gates + CI runs on the existing platform (SQLite)."""

    def __init__(self, platform, *, registry=None, limiter=None,
                 services=None):
        self.svc = platform
        self.db = platform.db
        import scanners as _sc
        self.registry = registry or _sc.ScannerRegistry()
        import identity as _id
        self.limiter = limiter or _id.RateLimiter()
        self.rl = dict(DEFAULT_RL)
        self._svc = services or {}

    # ------------------------------------------------------------ helpers
    def _analytics(self):
        if "analytics" not in self._svc:
            import analytics as _an
            self._svc["analytics"] = _an.AnalyticsService(self.svc)
        return self._svc["analytics"]

    def _audit(self, action, *, object_type, object_id, project_id="",
               org_id="", actor="cli", metadata=None):
        # audit failures are never swallowed silently: they propagate
        # (the caller decides; gate results are only stored after audit)
        self.svc.audit(action, object_type=object_type,
                       object_id=object_id, org_id=org_id,
                       project_id=project_id, actor=str(actor)[:128],
                       metadata=redact.redact(dict(metadata or {})))

    def _throttle(self, op: str, actor: str):
        limit, window = self.rl.get(op, (1000, 60))
        ok, retry = self.limiter.allowed(f"devsecops:{op}:{actor or 'cli'}",
                                         limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"rate_limited: retry after {retry}s ({limit}/{window}s)",
                retry_after=retry)

    def _bounded(self, value, lo, hi, label):
        try:
            v = int(value)
        except (TypeError, ValueError):
            raise errors.ValidationError(f"{label}_invalid: not an integer")
        if v < lo or v > hi:
            raise errors.ValidationError(
                f"{label}_invalid: must be {lo}..{hi} (bounded)")
        return v

    def _one(self, table, record_id, label):
        if table not in ("security_gates", "ci_runs", "gate_results"):
            raise errors.ValidationError("unknown table")
        row = self.db.query_one(
            "SELECT * FROM " + table + " WHERE id=? LIMIT 1", (record_id,))
        return row

    # ---------------------------------------------------------- gates
    def gate_create(self, project_id: str, name: str, policy: dict, *,
                    created_by: str = "", actor: str = "cli") -> dict:
        project = self.svc.project_require(project_id)
        name = str(name or "").strip()
        if not models.NAME_RE.match(name):
            raise errors.ValidationError(
                "gate_name_invalid: 1-128 chars, letters/digits/"
                "spaces/._-&() only")
        norm = validate_policy(policy)
        gate_id = models.stable_id(models.NS_GATE,
                                   f"{project_id}|{name.lower()}")
        h = policy_hash(norm)
        now = models.utcnow()
        try:
            self.db.execute(
                "INSERT INTO security_gates (id, project_id, org_id, name, "
                "enabled, policy, policy_version, policy_hash, created_by, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (gate_id, project.id, project.org_id, name, 1,
                 json.dumps(norm, sort_keys=True, ensure_ascii=False),
                 norm["version"], h, str(created_by)[:128], now, now))
        except Exception as e:
            if "UNIQUE" in str(e) or "duplicate" in str(e).lower():
                raise errors.DuplicateError("gate_exists") from e
            raise errors.PersistenceError(f"gate_create failed: {e}") from e
        self._audit("devsecops.gate.created", object_type="security_gate",
                    object_id=gate_id, project_id=project.id,
                    org_id=project.org_id, actor=actor,
                    metadata={"name": name, "policy_version": norm["version"],
                              "policy_hash": h[:16]})
        return self.gate_get(gate_id)

    def gate_get(self, gate_id: str) -> dict:
        row = self._one("security_gates", gate_id, "gate")
        out = dict(row)
        out["policy"] = json.loads(out.get("policy") or "{}")
        out["enabled"] = bool(out.get("enabled"))
        return redact.redact(out)

    def gate_list(self, project_id: str, *, limit: int = 100,
                  offset: int = 0) -> dict:
        self.svc.project_require(project_id)
        limit = self._bounded(limit, 1, 500, "limit")
        offset = self._bounded(offset, 0, 100000, "offset")
        rows = self.db.query(
            "SELECT * FROM security_gates WHERE project_id=? ORDER BY "
            "name LIMIT ? OFFSET ?", (project_id, limit, offset))
        total = int(self.db.query_one(
            "SELECT COUNT(*) n FROM security_gates WHERE project_id=?",
            (project_id,))["n"])
        return {"count": len(rows), "total": total, "limit": limit,
                "offset": offset,
                "gates": [redact.redact(dict(r)) for r in rows]}

    def gate_update(self, gate_id: str, *, name: str | None = None,
                    enabled: bool | None = None, policy: dict | None = None,
                    actor: str = "cli") -> dict:
        row = self._one("security_gates", gate_id, "gate")
        new_policy = json.loads(row["policy"] or "{}")
        version = int(row["policy_version"])
        new_name = str(row["name"])
        new_enabled = bool(row["enabled"])
        changed = False
        if name is not None:
            nm = str(name).strip()
            if not models.NAME_RE.match(nm):
                raise errors.ValidationError("gate_name_invalid")
            if nm != new_name:
                new_name = nm
                changed = True
        if enabled is not None and bool(enabled) != new_enabled:
            new_enabled = bool(enabled)
            changed = True
        if policy is not None:
            norm = validate_policy(policy)
            if norm != new_policy:
                new_policy = norm
                version = int(new_policy["version"])
                changed = True
        if not changed:
            return self.gate_get(gate_id)
        h = policy_hash(new_policy)
        self.db.execute(
            "UPDATE security_gates SET name=?, enabled=?, policy=?, "
            "policy_version=?, policy_hash=?, updated_at=? WHERE id=?",
            (new_name, 1 if new_enabled else 0,
             json.dumps(new_policy, sort_keys=True, ensure_ascii=False),
             version, h, models.utcnow(), gate_id))
        self._audit("devsecops.gate.updated", object_type="security_gate",
                    object_id=gate_id, project_id=row["project_id"],
                    org_id=row["org_id"], actor=actor,
                    metadata={"policy_version": version, "policy_hash": h[:16],
                              "enabled": new_enabled})
        return self.gate_get(gate_id)

    def gate_delete(self, gate_id: str, *, actor: str = "cli") -> dict:
        row = self._one("security_gates", gate_id, "gate")
        self.db.execute("DELETE FROM security_gates WHERE id=?", (gate_id,))
        self._audit("devsecops.gate.deleted", object_type="security_gate",
                    object_id=gate_id, project_id=row["project_id"],
                    org_id=row["org_id"], actor=actor,
                    metadata={"name": row["name"]})
        return {"deleted": gate_id, "name": row["name"]}

    # ------------------------------------------------------------ CI runs
    def _ci_meta(self, *, provider, repository="", branch="", commit_sha="",
                 commit_ref="", pipeline_id="", pipeline_url="", actor="",
                 trigger="manual", run_key=""):
        provider = str(provider or "").strip().lower()
        if provider not in models.CI_PROVIDERS:
            raise errors.ValidationError(
                f"provider_unknown: {provider!r} (allowlist "
                f"{models.CI_PROVIDERS})")
        trigger = str(trigger or "manual").strip().lower()
        if trigger not in models.CI_TRIGGERS:
            raise errors.ValidationError(
                f"trigger_unknown: {trigger!r} (allowlist "
                f"{models.CI_TRIGGERS})")
        sha = str(commit_sha or "").strip()
        if sha and not _RE["sha"].match(sha):
            raise errors.ValidationError(
                "commit_sha_invalid: 7-64 hex characters")
        ref = str(commit_ref or "").strip()
        if ref and not _RE["ref"].match(ref):
            raise errors.ValidationError("commit_ref_invalid")
        repo = str(repository or "").strip()
        if repo and not _RE["repo"].match(repo):
            raise errors.ValidationError("repository_invalid")
        br = str(branch or "").strip()
        if br and not _RE["ref"].match(br):
            raise errors.ValidationError("branch_invalid")
        pid = str(pipeline_id or "").strip()
        if pid and not _RE["pipeline"].match(pid):
            raise errors.ValidationError("pipeline_id_invalid")
        p_url = str(pipeline_url or "").strip()
        if p_url and not _RE["url"].match(p_url):
            raise errors.ValidationError("pipeline_url_invalid")
        act = str(actor or "").strip()
        if act and not _RE["actor"].match(act):
            raise errors.ValidationError("actor_invalid")
        rk = str(run_key or "").strip()
        if rk and not _RE["run_key"].match(rk):
            raise errors.ValidationError("run_key_invalid")
        for label, v in (("repository", repo), ("branch", br),
                         ("commit_sha", sha), ("commit_ref", ref),
                         ("pipeline_id", pid), ("pipeline_url", p_url),
                         ("actor", act), ("run_key", rk)):
            if BAD_CHARS.search(v):
                raise errors.ValidationError(f"{label}_invalid: control "
                                             "characters")
        return {"provider": provider, "repository": repo, "branch": br,
                "commit_sha": sha, "commit_ref": ref, "pipeline_id": pid,
                "pipeline_url": p_url, "actor": act, "trigger": trigger,
                "run_key": rk}

    def _idempotency_key(self, project_id: str, gate_id: str,
                         meta: dict) -> str:
        parts = [project_id, meta["provider"], gate_id, meta["pipeline_id"],
                 meta["commit_sha"], meta["commit_ref"], meta["run_key"]]
        if not parts[3] and not parts[4] and not parts[5] and not parts[6]:
            raise errors.ValidationError(
                "run_key_required: duplicate-safe CI runs need a "
                "pipeline_id, commit_sha, commit_ref or explicit run_key")
        return "|".join(p for p in parts if p)

    def run_create(self, project_id: str, gate_id: str, profile: str, *,
                   provider: str = "generic", repository: str = "",
                   branch: str = "", commit_sha: str = "", commit_ref: str = "",
                   pipeline_id: str = "", pipeline_url: str = "", actor: str = "",
                   trigger: str = "manual", target: str = "", run_key: str = "",
                   active: bool = False, submit: bool = True,
                   run_actor: str = "cli",
                   extra_payload: dict | None = None) -> dict:
        """CI request → existing Scan → existing Job (JobService)."""
        project = self.svc.project_require(project_id)
        self._throttle("run", run_actor)
        profile = self.registry.validate_profile(profile)
        gate = self._one("security_gates", gate_id, "gate")
        if gate["project_id"] != project_id:
            raise errors.NotFoundError("no such gate")     # no existence leak
        if not bool(gate["enabled"]):
            raise errors.ValidationError("gate_disabled")
        tgt = str(target or "").strip()
        if tgt and len(tgt) > 512:
            raise errors.ValidationError("target_invalid: too long")
        if tgt and BAD_CHARS.search(tgt):
            raise errors.ValidationError("target_invalid: control characters")
        meta = self._ci_meta(provider=provider, repository=repository,
                             branch=branch, commit_sha=commit_sha,
                             commit_ref=commit_ref, pipeline_id=pipeline_id,
                             pipeline_url=pipeline_url, actor=actor,
                             trigger=trigger, run_key=run_key)
        key = self._idempotency_key(project_id, gate_id, meta)
        run_id = models.stable_id(models.NS_CIRUN, key)
        scan_id = models.stable_id(models.NS_CIRUN, key + "|scan")
        now = models.utcnow()
        try:
            with self.db.transaction() as conn:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO ci_runs (id, project_id, org_id, "
                    "gate_id, provider, repository, branch, commit_sha, "
                    "commit_ref, pipeline_id, pipeline_url, actor, trigger, "
                    "profile, target, idempotency_key, status, scan_id, "
                    "started_at, created_at) VALUES "
                    "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, project.id, project.org_id, gate_id,
                     meta["provider"], meta["repository"], meta["branch"],
                     meta["commit_sha"], meta["commit_ref"],
                     meta["pipeline_id"], meta["pipeline_url"], meta["actor"],
                     meta["trigger"], profile, tgt, key, "created", scan_id,
                     now, now))
                reused = cur.rowcount != 1
        except Exception as e:
            raise errors.PersistenceError(f"ci_run_create failed: {e}") from e
        if reused:
            return {"run": self.run_get(run_id), "reused": True,
                    "scan_id": scan_id, "job_id": ""}
        self._audit("devsecops.run.created", object_type="ci_run",
                    object_id=run_id, project_id=project.id,
                    org_id=project.org_id, actor=run_actor,
                    metadata=redact.redact({
                        "provider": meta["provider"],
                        "pipeline_id": meta["pipeline_id"],
                        "commit_sha": meta["commit_sha"],
                        "trigger": meta["trigger"], "profile": profile,
                        "gate_id": gate_id}))
        job_id = ""
        try:
            self.svc.scan_create(
                project.id, profile, scope_ref=f"ci:{run_id}"[:120],
                initiator={"actor": "ci", "ci_run_id": run_id,
                           "gate_id": gate_id},
                scan_id=scan_id)
            if submit:
                import jobs as _jb
                jsvc = _jb.JobService(self.svc, self.registry)
                # Phase 9 in-process profiles: entity reference payloads
                # (account_id/image_id/cluster_id/source_name) — validated
                # against the shared job payload allowlist before submit
                payload = ({"target": tgt} if tgt else {}) | \
                    dict(extra_payload or {}) | \
                    {"note": f"ci run {run_id}"}
                _jb.validate_payload(payload)
                job = jsvc.create_job(
                    scan_id, profile, payload,
                    job_type="scan", priority="normal",
                    active_enabled=bool(active), max_attempts=3,
                    timeout_seconds=self.registry.get(profile).timeout,
                    actor_id=run_id, actor="ci", queue_now=True)
                job_id = job.id
                self.db.execute(
                    "UPDATE ci_runs SET status='scanning', job_id=? WHERE "
                    "id=?", (job_id, run_id))
                self._audit("devsecops.run.started", object_type="ci_run",
                            object_id=run_id, project_id=project.id,
                            org_id=project.org_id, actor=run_actor,
                            metadata={"scan_id": scan_id, "job_id": job_id})
        except Exception as e:
            self.db.execute(
                "UPDATE ci_runs SET status='failed', error=? WHERE id=?",
                (str(e)[:200], run_id))
            metrics.inc("devsecops_runs_failed")
            self._audit("devsecops.run.completed", object_type="ci_run",
                        object_id=run_id, project_id=project.id,
                        org_id=project.org_id, actor=run_actor,
                        metadata={"status": "failed"})
            raise
        metrics.inc("devsecops_runs_created")
        return {"run": self.run_get(run_id), "reused": False,
                "scan_id": scan_id, "job_id": job_id}

    def run_get(self, run_id: str) -> dict:
        return redact.redact(dict(self._one("ci_runs", run_id, "ci_run")))

    def run_status(self, run_id: str) -> dict:
        run = self.run_get(run_id)
        out = {"run": run, "scan": None, "job": None, "result": None}
        if run.get("scan_id"):
            try:
                sc = self.svc.scan_get(run["scan_id"])
                out["scan"] = redact.redact(sc.to_dict())
            except errors.NotFoundError:
                out["scan"] = {"status": "missing"}
        if run.get("job_id"):
            try:
                import jobs as _jb
                jrow = self.db.query_one(
                    "SELECT id, status, attempt, max_attempts, profile, "
                    "active_enabled, created_at, started_at, finished_at, "
                    "error_code FROM jobs WHERE id=? LIMIT 1", (run["job_id"],))
                out["job"] = dict(jrow)
            except errors.NotFoundError:
                out["job"] = {"status": "missing"}
        if run.get("result_id"):
            out["result"] = self.result_get(run["result_id"])
        return out

    def ci_list(self, project_id: str, *, limit: int = 50,
                offset: int = 0, status: str = "") -> dict:
        self.svc.project_require(project_id)
        limit = self._bounded(limit, 1, 500, "limit")
        offset = self._bounded(offset, 0, 100000, "offset")
        where = "project_id=?"
        params = [project_id]
        if status:
            if status not in models.CI_RUN_STATUSES:
                raise errors.ValidationError(
                    f"ci_status_unknown: {status!r}")
            where += " AND status=?"
            params.append(status)
        rows = self.db.query(
            "SELECT * FROM ci_runs WHERE " + where +
            " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset))
        total = int(self.db.query_one(
            "SELECT COUNT(*) n FROM ci_runs WHERE " + where,
            tuple(params))["n"])
        return {"count": len(rows), "total": total, "limit": limit,
                "offset": offset,
                "runs": [redact.redact(dict(r)) for r in rows]}

    # ------------------------------------------------------------ results
    def result_get(self, result_id: str) -> dict:
        row = self._one("gate_results", result_id, "gate_result")
        out = dict(row)
        for k in ("summary", "violations", "annotations", "policy",
                  "ci_context"):
            out[k] = json.loads(out.get(k) or ("{}" if k in ("summary",
                                                            "policy",
                                                            "ci_context")
                                               else "[]"))
        out["immutable"] = bool(out.get("immutable"))
        return redact.redact(out)

    def results_list(self, project_id: str, *, limit: int = 50,
                     offset: int = 0, status: str = "") -> dict:
        self.svc.project_require(project_id)
        limit = self._bounded(limit, 1, 500, "limit")
        offset = self._bounded(offset, 0, 100000, "offset")
        where = "project_id=?"
        params = [project_id]
        if status:
            if status not in models.GATE_RESULT_STATUSES:
                raise errors.ValidationError(
                    f"result_status_unknown: {status!r}")
            where += " AND status=?"
            params.append(status)
        rows = self.db.query(
            "SELECT id, run_id, gate_id, scan_id, status, reason, "
            "result_hash, result_version, policy_version, policy_hash, "
            "created_at FROM gate_results WHERE " + where +
            " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset))
        total = int(self.db.query_one(
            "SELECT COUNT(*) n FROM gate_results WHERE " + where,
            tuple(params))["n"])
        return {"count": len(rows), "total": total, "limit": limit,
                "offset": offset,
                "results": [redact.redact(dict(r)) for r in rows]}

    # ------------------------------------------------------------ evaluate
    def _scan_findings(self, scan_id: str) -> list[dict]:
        return self.db.query(
            "SELECT f.id, f.fingerprint, f.title, f.severity, f.confidence, "
            "f.confidence_level, f.calc_version, f.risk_score, f.risk_level, "
            "f.lifecycle, f.asset_id, f.category, f.priority "
            "FROM findings f JOIN finding_observations o ON "
            "o.finding_id=f.id WHERE o.scan_id=? ORDER BY f.fingerprint "
            "LIMIT ?", (scan_id, LATEST_N))

    def _diff_for_scan(self, project_id: str, scan_id: str) -> dict | None:
        rows = self.db.query(
            "SELECT summary FROM scan_diffs WHERE project_id=? AND "
            "current_scan_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (project_id, scan_id))
        if not rows:
            return None
        payload = json.loads(rows[0]["summary"] or "{}")
        # scan_diffs.summary holds {summary, detail, calc_version} (Phase 4)
        summary = payload.get("summary", payload)
        detail = payload.get("detail", {})
        increased = 0
        for c in detail.get("findings_changed", []):
            try:
                if float(c["to"]["risk_score"]) > float(c["from"]["risk_score"]):
                    increased += 1
            except (KeyError, TypeError, ValueError):
                continue
        return {"summary": summary, "detail": detail,
                "increased_risk": increased}

    def _evidence(self, project_id: str, scan_id: str) -> dict:
        """Collect the deterministic gate metrics. Raises errors.ValidationError
        (inconclusive signal) when required evidence is untrusted."""
        try:
            sc = self.svc.scan_get(scan_id)
        except errors.NotFoundError:
            raise errors.ValidationError("scan_not_found") from None
        if sc.status != "completed":
            raise errors.ValidationError("scan_failed")
        findings = self._scan_findings(scan_id)
        if findings and any(not (f.get("calc_version") or "")
                            for f in findings):
            raise errors.ValidationError("risk_unavailable")
        diff = self._diff_for_scan(project_id, scan_id)
        if diff is None:
            raise errors.ValidationError("baseline_unavailable")
        rs = self._analytics().risk_summary(project_id)
        sev_rank = _SEV_RANK
        worst = None
        for f in findings:
            r = sev_rank.get(f["severity"], 0)
            if worst is None or r > sev_rank[worst]:
                worst = f["severity"]
        new_fps = {d["fingerprint"]
                   for d in diff["detail"].get("findings_new", [])}
        new_conf = "confirmed"
        for f in findings:
            if f["fingerprint"] in new_fps:
                if _CONF_RANK.get(f["confidence"], 0) < _CONF_RANK[new_conf]:
                    new_conf = f["confidence"]
        active_scan = sum(1 for f in findings
                          if f["lifecycle"] in ACTIVE_FINDING_STATUSES)
        ifc = int(self.db.query_one(
            "SELECT COUNT(*) n FROM findings f JOIN assets a ON "
            "a.id=f.asset_id WHERE f.project_id=? AND f.severity='Critical' "
            "AND f.lifecycle IN (" + ",".join("?" for _ in
                                              ACTIVE_FINDING_STATUSES) +
            ") AND a.exposure='internet_facing'",
            (project_id,) + tuple(sorted(ACTIVE_FINDING_STATUSES)))["n"])
        s = diff["summary"]
        summary = {
            "total_risk": round(float(rs.get("total_risk", 0.0)), 2),
            "open_critical": int(rs.get("by_severity", {}).get("Critical", 0)),
            "open_high": int(rs.get("by_severity", {}).get("High", 0)),
            "new_findings": int(s.get("findings_new", 0)),
            "reopened_findings": int(s.get("findings_reopened", 0)),
            "increased_risk": int(diff["increased_risk"]),
            "resolved_findings": int(s.get("findings_resolved", 0)),
            "worst_severity": worst or "Info",
            "active_findings": active_scan,
            "internet_facing_critical": ifc,
        }
        # policy-keyed gate metrics (exact allowlisted vocabulary; derived
        # booleans are deterministic; the pure evaluator fails closed on any
        # missing key — evidence itself was already validated above)
        gate = {
            "max_risk": summary["total_risk"],
            "max_severity": worst or "Info",
            "max_open_critical": summary["open_critical"],
            "max_open_high": summary["open_high"],
            "max_new_findings": summary["new_findings"],
            "max_reopened_findings": summary["reopened_findings"],
            "max_increased_risk": summary["increased_risk"],
            "require_minimum_confidence": new_conf,
            "require_scan_success": True,
            "require_no_regression": not (
                summary["new_findings"] or summary["reopened_findings"] or
                summary["increased_risk"]),
            "block_active_findings": active_scan == 0,
            "block_internet_facing_critical": ifc == 0,
            # Phase 11: data-protection signals (values are never included;
            # counts are computed conservatively and bounded)
            **self._gov_signals(project_id, findings),
            # Phase 12: federation/integration signals (counts + booleans
            # only; conservative defaults when nothing is federated yet)
            **self._federation_signals(project_id),
        }
        return {"metrics": summary, "gate": gate, "findings": findings,
                "diff": diff, "scan": sc}

    def _gov_signals(self, project_id: str, findings: list) -> dict:
        """Phase-11 data-protection gate signals for one CI run. Counts
        only: no values, no PII, no secret material. Conservative by
        design (an unclassifiable finding counts toward the sensitive
        bucket; JSON columns are scanned with the platform's single
        secret-shape vocabulary)."""
        try:
            import data_governance as _gov
        except Exception:
            return {"max_secret_like_evidence": 0, "max_sensitive_findings": 0,
                    "require_secrets_registry_clean": True,
                    "require_private_data_classified": True}
        try:
            project = self.svc.project_get(project_id)
        except errors.NotFoundError:
            project = None
        org_id = project.org_id if project else ""
        secret_like = 0
        examined = 0
        for f in findings[:200]:
            payload = {"description": f.get("description", ""),
                       "evidence": f.get("evidence", []),
                       "raw": f.get("raw", {})}
            try:
                res = _gov.detect_secret_shapes(payload, sample=32)
            except Exception:
                res = {"hits": 0}
            if res.get("hits"):
                secret_like += 1
            examined += 1
        # sensitive (rank >= personal_data) findings WITHOUT an explicit
        # classification row — conservative: inherited defaults count as
        # "not private-classified"
        sensitive = 0
        explicit = set()
        if org_id and findings:
            ids = [str(f.get("id")) for f in findings[:200] if f.get("id")]
            if ids:
                marks = ",".join("?" for _ in ids)
                rows = self.db.query(
                    "SELECT DISTINCT object_id FROM data_classifications "
                    "WHERE org_id=? AND object_type='finding' AND "
                    "object_id IN (" + marks + ")",
                    (org_id,) + tuple(ids))
                explicit = {str(r["object_id"]) for r in rows}
        private_classified = True
        try:
            _rank = _gov.models.CLASSIFICATION_RANK
            for f in findings[:200]:
                sev = str(f.get("severity") or "")
                if sev in ("High", "Critical") and f.get("id") not in explicit:
                    sensitive += 1
                if sev in ("High", "Critical") and f.get("id") not in explicit:
                    private_classified = False
        except Exception:
            private_classified = bool(sensitive) is False
        registry_clean = True
        if org_id:
            bad = self.db.query_one(
                "SELECT COUNT(*) n FROM secrets_registry WHERE org_id=? "
                "AND project_id=? AND status IN ('expired',"
                "'rotation_required')", (org_id, project_id))
            if bad:
                registry_clean = int(bad["n"]) == 0
        return {"max_secret_like_evidence": secret_like,
                "max_sensitive_findings": sensitive,
                "require_secrets_registry_clean": registry_clean,
                "require_private_data_classified": private_classified}

    def _federation_signals(self, project_id: str) -> dict:
        """Phase-12 federation / evidence-exchange gate signals for one CI
        run. Counts + booleans only: never package payloads, never
        endpoints, never secret material. Conservative by design — a
        project with no federation state yields zero violations and
        `require_safe_external_integrations=True` (nothing unsafe exists).
        Org-scoped (federation agreements are tenant-level); the project is
        only used to resolve its organization."""
        out = {"max_federation_policy_violations": 0,
               "max_federation_integrity_failures": 0,
               "max_expired_federation_grants": 0,
               "max_unapproved_federation_exports": 0,
               "require_safe_external_integrations": True}
        try:
            project = self.svc.project_get(project_id)
        except errors.NotFoundError:
            return out
        org_id = project.org_id
        now = models.utcnow()
        out["max_federation_policy_violations"] = int(self.db.query_one(
            "SELECT COUNT(*) n FROM federation_imports WHERE org_id=? AND "
            "status='rejected' AND error LIKE 'policy_%'", (org_id,))["n"])
        out["max_federation_integrity_failures"] = int(self.db.query_one(
            "SELECT COUNT(*) n FROM federation_imports WHERE org_id=? AND "
            "status='rejected' AND error LIKE 'integrity_%'", (org_id,))["n"])
        # grants that lapsed or sit past their expiry without an explicit
        # revocation — an expired-but-unresolved peer is a gate signal
        out["max_expired_federation_grants"] = int(self.db.query_one(
            "SELECT COUNT(*) n FROM federation_peers WHERE org_id=? AND "
            "(status='expired' OR (status IN ('active','suspended') AND "
            "expires_at<>'' AND expires_at<=?))", (org_id, now))["n"])
        # packages built for a peer that is not currently active, or with no
        # peer/policy reference at all (unbounded "share everything")
        out["max_unapproved_federation_exports"] = int(self.db.query_one(
            "SELECT COUNT(*) n FROM federation_packages pk WHERE pk.org_id=? "
            "AND pk.status='created' AND (pk.peer_id='' OR pk.policy_id='' "
            "OR NOT EXISTS (SELECT 1 FROM federation_peers pe WHERE "
            "pe.id=pk.peer_id AND pe.org_id=pk.org_id AND "
            "pe.status='active'))", (org_id,))["n"])
        # every enabled integration must still point at a safe endpoint
        # (re-validated at gate time; format/DNS checks reuse the EXISTING
        # notify.validate_webhook_url guard — no second SSRF engine)
        try:
            import notify as _notify
            rows = self.db.query(
                "SELECT endpoint_url FROM external_integrations WHERE "
                "org_id=? AND status='enabled' AND endpoint_url<>''",
                (org_id,), limit=200)
            for r in rows:
                _notify.validate_webhook_url(str(r["endpoint_url"]),
                                             resolve=False)
        except errors.ValidationError:
            out["require_safe_external_integrations"] = False
        return out

    def evaluate(self, run_id: str, *, actor: str = "cli") -> dict:
        """Evaluate the security gate for a CI run. Fail-closed; the result
        is an immutable snapshot (policy frozen at evaluation time)."""
        self._throttle("evaluate", actor)
        run = self.run_get(run_id)
        gate = self._one("security_gates", run["gate_id"], "gate")
        # atomic claim: exactly one evaluation per run (SQLite write lock
        # serializes the claim; concurrent callers wait briefly for the
        # winner to publish the immutable result, then return it)
        claimed = self.db.execute_affected(
            "UPDATE ci_runs SET status='evaluating' WHERE id=? AND "
            "status NOT IN ('evaluating','completed','failed','cancelled') "
            "AND result_id=''", (run_id,))
        if claimed != 1:
            import time as _t
            deadline = _t.monotonic() + 5.0
            while _t.monotonic() < deadline:
                run2 = self.run_get(run_id)
                if run2.get("result_id"):
                    return self.result_get(run2["result_id"])
                if run2.get("status") != "evaluating":
                    break
                _t.sleep(0.02)
            run2 = self.run_get(run_id)
            raise errors.LifecycleError(
                f"validation_rejected: cannot evaluate run in state "
                f"{run2.get('status')}")
        meta = redact.redact({
            "provider": run["provider"], "repository": run["repository"],
            "branch": run["branch"], "commit_sha": run["commit_sha"],
            "pipeline_id": run["pipeline_id"], "trigger": run["trigger"],
            "actor": run["actor"]})
        inconclusive_reason = ""
        status = "inconclusive"
        reason = ""
        summary = {}
        violations = []
        annotations = []
        policy_snap = {}
        policy_version = int(gate["policy_version"])
        policy_hash_v = str(gate["policy_hash"])
        findings = []
        if not bool(gate["enabled"]):
            inconclusive_reason = "gate_disabled"
        try:
            if not inconclusive_reason:
                policy_snap = json.loads(gate["policy"] or "{}")
                ev = self._evidence(run["project_id"], run["scan_id"])
                findings = ev["findings"]
                summary = ev["metrics"]
                status, violations = evaluate_conditions(policy_snap,
                                                         ev["gate"])
                ann = []
                d = ev["diff"]["detail"]
                want = [] if status == "pass" else \
                    (d.get("findings_new", []) + d.get("findings_reopened", [])
                     + d.get("findings_changed", []))
                seen = set()
                for w in want:
                    fp = w.get("fingerprint", "")
                    if not fp or fp in seen:
                        continue
                    seen.add(fp)
                    frow = next((f for f in findings
                                 if f["fingerprint"] == fp), {})
                    annotation = ("changed"
                                  if w in d.get("findings_changed", [])
                                  else "new"
                                  if w in d.get("findings_new", [])
                                  else "reopened")
                    ann.append({
                        "fingerprint": fp,
                        "annotation": annotation,
                        "finding_id": str(w.get("finding_id") or
                                          frow.get("id") or "")[:64],
                        "title": str(frow.get("title") or "")[:200],
                        "severity": frow.get("severity", "Info")})
                annotations = ann[:MAX_ANNOTATIONS]
            else:
                reason = inconclusive_reason
        except errors.ValidationError as e:
            # evidence problem → INCONCLUSIVE (fail-closed, never PASS)
            reason = str(e).split(":", 1)[0] or "evidence_unavailable"
            status = "inconclusive"
        except Exception:
            reason = "internal_unavailable"
            status = "inconclusive"
        # deterministic canonical body (timestamps/annotations excluded)
        body = {"status": status, "reason": reason, "project_id":
                run["project_id"], "gate_id": run["gate_id"], "scan_id":
                run["scan_id"], "run_id": run_id,
                "policy_hash": policy_hash_v,
                "policy_version": policy_version, "summary": summary,
                "violations": violations}
        result_hash = sha256_hex(_canon(body))
        result_id = models.stable_id(
            models.NS_GATERT, f"{run_id}|{run['gate_id']}|{policy_hash_v}")
        now = models.utcnow()
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO gate_results (id, run_id, "
                    "gate_id, project_id, org_id, scan_id, status, reason, "
                    "summary, violations, annotations, policy, "
                    "policy_version, policy_hash, result_hash, "
                    "result_version, ci_context, created_at, immutable) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                    (result_id, run_id, run["gate_id"], run["project_id"],
                     run["org_id"], run["scan_id"], status, reason,
                     json.dumps(summary, sort_keys=True, ensure_ascii=False),
                     json.dumps(violations, sort_keys=True,
                                ensure_ascii=False),
                     json.dumps(annotations, sort_keys=True,
                                ensure_ascii=False),
                     json.dumps(policy_snap, sort_keys=True,
                                ensure_ascii=False),
                     policy_version, policy_hash_v, result_hash,
                     models.GATE_RESULT_VERSION, json.dumps(meta,
                                                            sort_keys=True,
                                                            ensure_ascii=False),
                     now))
                conn.execute(
                    "UPDATE ci_runs SET status=?, result_id=?, finished_at=?"
                    " WHERE id=?", ("completed" if status != "fail" else
                                    "failed", result_id, now, run_id))
        except Exception as e:
            self.db.execute(
                "UPDATE ci_runs SET status='failed', error=? WHERE id=?",
                (str(e)[:200], run_id))
            metrics.inc("devsecops_runs_failed")
            raise errors.PersistenceError(
                f"gate result store failed: {e}") from e
        # audit BEFORE returning (never silently swallowed)
        audit_action = {"pass": "devsecops.gate.passed",
                        "fail": "devsecops.gate.failed",
                        "warn": "devsecops.gate.warned",
                        "inconclusive": "devsecops.gate.inconclusive"}[status]
        self._audit(audit_action, object_type="gate_result",
                    object_id=result_id, project_id=run["project_id"],
                    org_id=run["org_id"], actor=actor,
                    metadata={"run_id": run_id, "scan_id": run["scan_id"],
                              "policy_hash": policy_hash_v[:16],
                              "violations": len(violations),
                              "reason": reason})
        if status == "pass":
            metrics.inc("devsecops_gate_passed")
            metrics.inc("devsecops_runs_completed")
        elif status == "fail":
            metrics.inc("devsecops_gate_failed")
            metrics.inc("devsecops_runs_failed")
        elif status == "warn":
            metrics.inc("devsecops_gate_warned")
            metrics.inc("devsecops_runs_completed")
        else:
            metrics.inc("devsecops_gate_inconclusive")
            metrics.inc("devsecops_runs_completed")
        return self.result_get(result_id)

    # ------------------------------------------------------------ export
    def export_result(self, result_id: str, fmt: str, *,
                      out_path: str = "", actor: str = "cli") -> bytes:
        """Deterministic JSON / valid SARIF 2.1.0 export of a stored result.
        Central redaction applies; no secrets can reach the output."""
        self._throttle("export", actor)
        res = self.result_get(result_id)
        fmt = str(fmt or "json").lower()
        run = None
        if res.get("run_id"):
            try:
                run = self.run_get(res["run_id"])
            except errors.NotFoundError:
                run = None
        if fmt == "json":
            out = {
                "status": res["status"],
                "reason": res["reason"],
                "project_id": res["project_id"],
                "scan_id": res["scan_id"],
                "ci_run_id": res["run_id"],
                "gate_id": res["gate_id"],
                "policy_id": res["gate_id"],
                "provider": run["provider"] if run else "",
                "repository": run["repository"] if run else "",
                "branch": run["branch"] if run else "",
                "commit_sha": run["commit_sha"] if run else "",
                "pipeline_id": run["pipeline_id"] if run else "",
                "trigger": run["trigger"] if run else "",
                "profile": run["profile"] if run else "",
                "summary": res["summary"],
                "violations": res["violations"],
                "policy": {"policy_version": res["policy_version"],
                           "policy_hash": res["policy_hash"]},
                "result_version": res["result_version"],
                "result_hash": res["result_hash"],
                "generated_at": res["created_at"],
            }
            raw = json.dumps(redact.redact(out), sort_keys=True,
                             separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        elif fmt == "sarif":
            raw = json.dumps(self.ci_sarif(res, run), sort_keys=False,
                             indent=2, ensure_ascii=False).encode("utf-8")
        else:
            raise errors.ValidationError(
                f"format_unknown: {fmt!r} (use json or sarif)")
        if out_path:
            from reporting import secure_export_path
            with open(secure_export_path(out_path), "wb") as fh:
                fh.write(raw)
        self._audit("devsecops.exported", object_type="gate_result",
                    object_id=result_id, project_id=res["project_id"],
                    org_id=res["org_id"], actor=actor,
                    metadata={"format": fmt, "size": len(raw)})
        return raw

    def ci_sarif(self, res: dict, run: dict | None) -> dict:
        """Reuse the existing SARIF 2.1.0 exporter; only attach gate
        metadata (valid `properties` on invocations). Never secrets."""
        import sarif_export as _se
        findings = self.db.query(
            "SELECT f.id, f.title, f.description, f.severity, f.remediation "
            "FROM findings f JOIN finding_observations o ON "
            "o.finding_id=f.id WHERE o.scan_id=? ORDER BY f.fingerprint "
            "LIMIT ?", (res.get("scan_id") or "", LATEST_N))
        payload = [{
            "id": str(f["id"]), "title": redact.redact_text(str(f["title"])),
            "description": redact.redact_text(str(f["description"])),
            "severity": f["severity"],
            "remediation": redact.redact_text(str(f["remediation"])),
            "evidence": "", "tags": "",
        } for f in findings]
        target = ((run or {}).get("repository") or
                  res.get("scan_id") or "unknown-target")
        sarif = _se.to_sarif({"tool": "SecuToolkit", "target": target,
                              "scan_date": res.get("created_at", ""),
                              "findings": payload}, target)
        inv = sarif["runs"][0]["invocations"][0]
        inv["executionSuccessful"] = res.get("status") != "inconclusive"
        inv["properties"] = {
            "securityGate": {
                "status": res["status"], "reason": res.get("reason", ""),
                "result_hash": res.get("result_hash", ""),
                "result_version": res.get("result_version", ""),
                "policy_version": res.get("policy_version", 1),
                "policy_hash": res.get("policy_hash", ""),
                "gate_id": res.get("gate_id", ""),
                "ci_run_id": res.get("run_id", ""),
                "scan_id": res.get("scan_id", ""),
                "violations": res.get("violations", []),
            }}
        return sarif

    # ------------------------------------------------------ report input
    def ci_report(self, result_id: str, *, report_type: str = "technical",
                  generated_by: str = "ci") -> dict:
        """CI gate results as Phase-6 report input: the existing snapshot
        engine is reused; the CI context is embedded in report metadata."""
        res = self.result_get(result_id)
        import reporting as _rp
        rsvc = _rp.ReportService(self.svc)
        snap = rsvc.snapshot(
            res["project_id"], report_type, generated_by=generated_by,
            ci={"ci_run_id": res["run_id"], "gate_id": res["gate_id"],
                "result_id": result_id, "status": res["status"],
                "result_hash": res["result_hash"]})
        return rsvc.store_run(snap, store_payload=True)

    # ---------------------------------------------------------- retention
    def retention_sweep(self, days: int, *, project_id: str = "",
                        actor: str = "cli") -> dict:
        """Bounded retention for high-volume NON-immutable CI run records.
        Gate results (immutable), audit history, finding history, evidence
        provenance and report snapshots are NEVER touched."""
        days = self._bounded(days, 1, 3650, "days")
        cutoff = models.utcnow()
        import time as _t
        cutoff = _t.strftime("%Y-%m-%dT%H:%M:%SZ",
                             _t.gmtime(_t.time() - days * 86400))
        params = [cutoff]
        where = "created_at<? AND status IN ('completed','failed','cancelled')"
        audit_org = ""
        if project_id:
            p = self.svc.project_require(project_id)
            audit_org = p.org_id
            where += " AND project_id=?"
            params.append(project_id)
        with self.db.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM ci_runs WHERE " + where, tuple(params))
        removed = cur.rowcount
        self._audit("devsecops.retention", object_type="ci_run",
                    object_id="", project_id=project_id or "",
                    org_id=audit_org, actor=actor,
                    metadata={"days": days, "removed": removed})
        metrics.inc("devsecops_runs_retained", removed)
        return {"removed": removed, "days": days, "cutoff": cutoff}

    # --------------------------------------------------------- dashboard
    def snapshot(self, org_filter: str = "", *, max_gates: int = 100,
                 max_runs: int = 100, max_results: int = 100) -> dict:
        """Read-only tenant-scoped snapshot for the SecuPulse DevSecOps
        panel (bounded, redacted; never crosses orgs)."""
        if org_filter:
            proj_ids = [p.id for p in self.svc.project_list(org_filter)]
        else:
            proj_ids = [p.id for o in self.svc.org_list()
                        for p in self.svc.project_list(o.id)]
        gates, runs, results = [], [], []
        if not proj_ids:
            return redact.redact({"org": org_filter or "", "empty": True,
                                  "counts": {"gates": 0, "runs": 0,
                                             "results": 0},
                                  "by_status": {s: 0 for s in
                                                models.GATE_RESULT_STATUSES},
                                  "new_findings_total": 0,
                                  "reopened_findings_total": 0,
                                  "risk_regressions": 0, "top_failing": [],
                                  "recent_failures": [], "policy_summary": [],
                                  "gates": [], "runs": [], "results": []})
        for pid in proj_ids[:50]:
            gates += self.db.query(
                "SELECT id, name, enabled, policy_version, policy_hash, "
                "created_at, updated_at FROM security_gates WHERE "
                "project_id=? ORDER BY name LIMIT ?", (pid, max_gates))
            runs += self.db.query(
                "SELECT id, project_id, provider, branch, commit_sha, "
                "trigger, profile, status, scan_id, result_id, created_at, "
                "finished_at FROM ci_runs WHERE project_id=? ORDER BY "
                "created_at DESC LIMIT ?", (pid, max_runs))
            results += self.db.query(
                "SELECT id, project_id, gate_id, run_id, scan_id, status, "
                "reason, result_hash, policy_hash, policy_version, "
                "created_at FROM gate_results WHERE project_id=? ORDER BY "
                "created_at DESC LIMIT ?", (pid, max_results))
        gates = gates[:max_gates]
        runs = runs[:max_runs]
        results = results[:max_results]
        by_status = {s: 0 for s in models.GATE_RESULT_STATUSES}
        new_total = reopened_total = regressions = 0
        failing: dict[str, dict] = {}
        for r in results:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
            if r["status"] == "fail":
                p = failing.setdefault(
                    r["project_id"],
                    {"project_id": r["project_id"], "fails": 0})
                p["fails"] += 1
        top_failing = sorted(failing.values(),
                             key=lambda d: -d["fails"])[:10]
        recent_failures = [dict(r) for r in results
                           if r["status"] == "fail"][:10]
        for r in self.db.query(
                "SELECT summary FROM gate_results WHERE project_id IN (" +
                ",".join("?" for _ in proj_ids[:50]) + ") LIMIT ?",
                tuple(proj_ids[:50]) + (max_results * 2,)):
            try:
                s = json.loads(r["summary"] or "{}")
            except (TypeError, ValueError):
                continue
            new_total += int(s.get("new_findings", 0))
            reopened_total += int(s.get("reopened_findings", 0))
            if int(s.get("increased_risk", 0)) > 0:
                regressions += 1
        policy_summary: dict[str, dict] = {}
        for g in gates:
            ph = str(g["policy_hash"])[:16]
            e = policy_summary.setdefault(
                ph, {"policy_hash": ph, "version": g["policy_version"],
                     "count": 0})
            e["count"] += 1
        return redact.redact({
            "org": org_filter or "", "empty": False,
            "counts": {"gates": len(gates), "runs": len(runs),
                       "results": len(results)},
            "by_status": by_status,
            "new_findings_total": new_total,
            "reopened_findings_total": reopened_total,
            "risk_regressions": regressions,
            "top_failing": top_failing,
            "recent_failures": recent_failures,
            "policy_summary": sorted(policy_summary.values(),
                                     key=lambda d: -d["count"]),
            "gates": gates, "runs": runs, "results": results})
