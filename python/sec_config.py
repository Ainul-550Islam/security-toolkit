#!/usr/bin/env python3
# ============================================================================
#  sec_config.py — CENTRAL configuration (single source, no duplicates).
#  ---------------------------------------------------------------------------
#  Precedence (highest first):
#    1. Environment variables  (SECTOOLKIT_*)
#    2. Config file             <data_dir>/config.json
#    3. Built-in defaults
#
#  The config file is created with safe defaults and NEVER stores secrets.
#  Secrets flow exclusively through environment variables / keyring-style
#  external mechanisms and are collected via env_secret().
# ============================================================================

from __future__ import annotations

import json
import os

import errors

TOOLKIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULTS = {
    "data_dir": os.path.join(TOOLKIT_ROOT, "data"),
    "results_dir": os.path.join(TOOLKIT_ROOT, "results"),
    "templates_dir": os.path.join(TOOLKIT_ROOT, "templates"),
    "db_path": os.path.join(TOOLKIT_ROOT, "data", "security_platform.db"),
    "http_timeout": 12.0,
    "threads": 50,
    "max_hosts": 40,
    "max_payloads": 5,
    "log_level": "INFO",
    "log_file": "",                      # empty → stderr
    "scope": {"enabled": False, "policy_file": ""},
    # platform persistence: explicitly enabled (flag) — default is OFF so
    # existing scanner CLIs behave exactly as before (no hidden DB writes).
    "platform": {"enabled": False,
                 "db": os.path.join(TOOLKIT_ROOT, "data", "security_platform.db")},
}

_ENV_MAP = {
    "data_dir": "SECTOOLKIT_DATA_DIR",
    "results_dir": "SECTOOLKIT_RESULTS_DIR",
    "templates_dir": "SECTOOLKIT_TEMPLATES_DIR",
    "db_path": "SECTOOLKIT_DB",
    "http_timeout": "SECTOOLKIT_TIMEOUT",
    "threads": "SECTOOLKIT_THREADS",
    "max_hosts": "SECTOOLKIT_MAX_HOSTS",
    "max_payloads": "SECTOOLKIT_MAX_PAYLOADS",
    "log_level": "SECTOOLKIT_LOG_LEVEL",
}

_config: dict | None = None
_config_path: str | None = None


def _config_dir() -> str:
    return os.environ.get("SECTOOLKIT_DATA_DIR", DEFAULTS["data_dir"])


def config_path() -> str:
    return os.path.join(_config_dir(), "config.json")


def load(force: bool = False) -> dict:
    """Load configuration (env > file > defaults). Cached; `force` re-reads."""
    global _config, _config_path
    if _config is not None and not force:
        return _config
    data = dict(DEFAULTS)
    data["scope"] = dict(DEFAULTS["scope"])
    data["platform"] = dict(DEFAULTS["platform"])
    path = config_path()
    try:
        with open(path, encoding="utf-8") as fh:
            file_cfg = json.load(fh)
        if isinstance(file_cfg, dict):
            for k, v in file_cfg.items():
                if k in ("scope", "platform") and isinstance(v, dict):
                    data[k].update(v)
                elif k in data and not isinstance(v, (dict,)):
                    data[k] = v
    except FileNotFoundError:
        pass
    except Exception as e:
        raise errors.ConfigurationError(
            f"Invalid config file {path}: {e}") from e
    for key, env in _ENV_MAP.items():
        val = os.environ.get(env)
        if val is not None:
            if key in ("http_timeout",):
                data[key] = float(val)
            elif key in ("threads", "max_hosts", "max_payloads"):
                data[key] = int(val)
            else:
                data[key] = val
    data["scope"]["enabled"] = (
        os.environ.get("SECTOOLKIT_SCOPE_ENABLED", "false").lower() in
        ("1", "true", "yes") or bool(data["scope"].get("enabled")))
    if os.environ.get("SECTOOLKIT_SCOPE_POLICY"):
        data["scope"]["policy_file"] = os.environ["SECTOOLKIT_SCOPE_POLICY"]
    if os.environ.get("SECTOOLKIT_PLATFORM_DB"):
        data["platform"]["db"] = os.environ["SECTOOLKIT_PLATFORM_DB"]
        data["platform"]["enabled"] = True
    data["platform"]["enabled"] = (
        os.environ.get("SECTOOLKIT_PLATFORM_ENABLED", "false").lower() in
        ("1", "true", "yes") or bool(data["platform"].get("enabled")))
    _config = data
    _config_path = path
    return data


def save(overrides: dict | None = None) -> dict:
    """Write current config to the config file (never secrets)."""
    cfg = load(force=True)
    if overrides:
        for k, v in overrides.items():
            if k in ("scope", "platform") and isinstance(v, dict):
                cfg[k].update(v)
            elif k in cfg:
                cfg[k] = v
            else:
                raise errors.ConfigurationError(f"Unknown config key: {k}")
    os.makedirs(cfg["data_dir"], exist_ok=True)
    with open(config_path(), "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
    return cfg


def ensure_layout() -> dict:
    """Create data/results dirs; returns the effective config."""
    cfg = load(force=True)
    for key in ("data_dir", "results_dir"):
        os.makedirs(str(cfg[key]), exist_ok=True)
    if not os.path.exists(config_path()):
        save()
    return cfg


def get(key: str, default=None):
    cfg = load()
    return cfg.get(key, default)


def db_path() -> str:
    return str(get("db_path"))


def platform_enabled() -> bool:
    """True only when platform persistence is explicitly enabled (file/env)."""
    cfg = load()
    return bool(cfg.get("platform", {}).get("enabled"))


def platform_db_path() -> str:
    cfg = load()
    return str(cfg.get("platform", {}).get("db") or cfg.get("db_path"))


def env_secret(name: str) -> str | None:
    """Secrets ONLY come from here: never read hard-coded credentials."""
    return os.environ.get(name)


def require_env_secret(name: str) -> str:
    val = env_secret(name)
    if not val:
        raise errors.ConfigurationError(
            f"Required secret environment variable {name} is not set")
    return val
