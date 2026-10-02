"""Feature flags with deny-by-default semantics for security-sensitive gates.

Rules
-----
* Unknown flag -> ``False``. Never a KeyError-driven crash, and never True.
  A typo in a flag name must not silently enable something.
* Security-sensitive flags cannot be enabled in production through the
  environment. They are marked ``production_locked`` and require a
  deliberate code/deployment change, not an env var on a running host.
* Every flag declares its default explicitly; there is no implicit registry.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from core.constants import ENV_PRODUCTION
from core.errors import ConfigurationError

FLAG_PREFIX: Final[str] = "SECTOOLKIT_FEATURE_"

_TRUE = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSE = frozenset({"0", "false", "no", "off", "disabled"})


@dataclass(frozen=True, slots=True)
class FeatureFlag:
    """Declaration of a single flag."""

    name: str
    default: bool
    description: str
    security_sensitive: bool = False
    production_locked: bool = False

    @property
    def env_var(self) -> str:
        return f"{FLAG_PREFIX}{self.name.upper()}"


# Declared flags. Everything security-relevant defaults to False.
FLAGS: Final[dict[str, FeatureFlag]] = {
    f.name: f
    for f in (
        FeatureFlag(
            "rust_engine", False,
            "Load the native Rust engine when it has been built.",
        ),
        FeatureFlag(
            "cpp_engine", False,
            "Load the native C++ engine when it has been built.",
        ),
        FeatureFlag(
            "experimental_api", False,
            "Expose unstable API routes.",
            security_sensitive=True, production_locked=True,
        ),
        FeatureFlag(
            "verbose_errors", False,
            "Return internal error detail to API clients. Leaks internals; "
            "development only.",
            security_sensitive=True, production_locked=True,
        ),
        FeatureFlag(
            "allow_anonymous_health", True,
            "Serve liveness/readiness without authentication. The payload is "
            "non-sensitive by construction.",
        ),
        FeatureFlag(
            "native_engine_autoload", False,
            "Probe for native engines automatically at startup.",
            security_sensitive=True,
        ),
    )
}


def _parse(raw: str, flag: FeatureFlag) -> bool:
    text = raw.strip().lower()
    if text == "":
        return flag.default
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ConfigurationError(
        f"feature flag {flag.env_var} must be a boolean",
        context={"flag": flag.name, "reason": "invalid_bool"},
    )


def is_enabled(
    name: str,
    *,
    environment: str | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Resolve a flag. Unknown flags are disabled."""
    flag = FLAGS.get(str(name))
    if flag is None:
        return False
    source = env if env is not None else os.environ
    mode = environment if environment is not None else source.get(
        "SECTOOLKIT_ENV", "development"
    ).strip().lower()

    raw = source.get(flag.env_var)
    value = flag.default if raw is None else _parse(str(raw), flag)

    # Production lock: refuse the override rather than honouring it.
    if value and flag.production_locked and mode == ENV_PRODUCTION:
        return False
    return value


def all_flags(
    *,
    environment: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, bool]:
    """Resolved state of every declared flag."""
    return {
        name: is_enabled(name, environment=environment, env=env)
        for name in sorted(FLAGS)
    }


def describe_flags() -> list[dict[str, object]]:
    """Non-sensitive flag documentation for the metadata endpoint."""
    return [
        {
            "name": f.name,
            "default": f.default,
            "description": f.description,
            "security_sensitive": f.security_sensitive,
            "production_locked": f.production_locked,
            "env_var": f.env_var,
        }
        for f in sorted(FLAGS.values(), key=lambda x: x.name)
    ]


__all__ = [
    "FeatureFlag",
    "FLAGS",
    "FLAG_PREFIX",
    "is_enabled",
    "all_flags",
    "describe_flags",
]
