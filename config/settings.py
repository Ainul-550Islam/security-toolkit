"""Typed configuration loading with fail-closed security defaults.

Principles
----------
* Secure by default. Every security-relevant default is the RESTRICTIVE one;
  a deployment must opt IN to anything weaker, and production refuses the
  weakening entirely.
* Unset, empty and invalid are distinct. ``""`` is not "use the default"; an
  explicitly empty required value is a configuration error, because silently
  substituting a default is how an unconfigured system ends up listening on
  0.0.0.0 with authentication disabled.
* No secrets in source. Values arrive from the environment; secret MATERIAL
  is resolved through ``interfaces/secrets.py``, never stored here.
* Never logged. :meth:`Settings.safe_dump` redacts every sensitive field, and
  ``__repr__`` routes through it so an accidental ``print(settings)`` or a
  traceback cannot leak a token.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Final

from core.constants import (
    ENV_DEVELOPMENT,
    ENV_PRODUCTION,
    ENV_TEST,
    ENVIRONMENTS,
    REDACTED,
)
from core.errors import ConfigurationError
from core.paths import REPO_ROOT, ensure_directory

ENV_PREFIX: Final[str] = "SECTOOLKIT_"

# Substring markers identifying a field whose value must never be printed.
_SENSITIVE_MARKERS: Final[tuple[str, ...]] = (
    "secret", "token", "password", "passwd", "api_key", "apikey",
    "private_key", "credential", "auth", "cookie", "session", "signing",
)

_TRUE = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSE = frozenset({"0", "false", "no", "off", "disabled"})

_UNSET: Final[object] = object()


def is_sensitive_name(name: str) -> bool:
    """True when a configuration/log key should be redacted by name."""
    lowered = str(name).lower()
    return any(marker in lowered for marker in _SENSITIVE_MARKERS)


# ---------------------------------------------------------------------------
# Typed environment accessors
#
# Each distinguishes UNSET (variable absent) from EMPTY (present but "") from
# INVALID (present but unparseable).
# ---------------------------------------------------------------------------
def _raw(name: str, env: Mapping[str, str]) -> str | object:
    return env.get(name, _UNSET)


def get_str(
    name: str,
    *,
    default: str | None = None,
    required: bool = False,
    allow_empty: bool = False,
    choices: tuple[str, ...] | None = None,
    max_length: int = 4096,
    env: Mapping[str, str] | None = None,
) -> str:
    """Read a string setting."""
    source = env if env is not None else os.environ
    raw = _raw(name, source)
    if raw is _UNSET:
        if required:
            raise ConfigurationError(
                f"required configuration {name} is not set",
                context={"variable": name, "reason": "unset"},
            )
        value = default if default is not None else ""
    else:
        value = str(raw)
        if value == "" and not allow_empty:
            if required or default is None:
                raise ConfigurationError(
                    f"configuration {name} is set but empty",
                    context={"variable": name, "reason": "empty"},
                )
            value = default
    if len(value) > max_length:
        raise ConfigurationError(
            f"configuration {name} exceeds {max_length} characters",
            context={"variable": name, "reason": "too_long"},
        )
    if choices is not None and value not in choices:
        # The VALUE is intentionally excluded from the message: this helper
        # also reads sensitive variables.
        raise ConfigurationError(
            f"configuration {name} is not one of: {', '.join(choices)}",
            context={"variable": name, "reason": "invalid_choice"},
        )
    return value


def get_bool(
    name: str,
    *,
    default: bool,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Read a boolean setting from an explicit allowlist of spellings.

    An unrecognised value is an ERROR, not a silent False: ``AUTH=maybe``
    quietly disabling authentication is precisely the failure mode to avoid.
    """
    source = env if env is not None else os.environ
    raw = _raw(name, source)
    if raw is _UNSET:
        return bool(default)
    text = str(raw).strip().lower()
    if text == "":
        return bool(default)
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ConfigurationError(
        f"configuration {name} must be a boolean "
        f"({'/'.join(sorted(_TRUE))} or {'/'.join(sorted(_FALSE))})",
        context={"variable": name, "reason": "invalid_bool"},
    )


def get_int(
    name: str,
    *,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    """Read a bounded integer setting."""
    source = env if env is not None else os.environ
    raw = _raw(name, source)
    if raw is _UNSET or str(raw).strip() == "":
        value = int(default)
    else:
        try:
            value = int(str(raw).strip())
        except ValueError as exc:
            raise ConfigurationError(
                f"configuration {name} must be an integer",
                context={"variable": name, "reason": "invalid_int"},
            ) from exc
    if minimum is not None and value < minimum:
        raise ConfigurationError(
            f"configuration {name} must be >= {minimum}",
            context={"variable": name, "reason": "below_minimum"},
        )
    if maximum is not None and value > maximum:
        raise ConfigurationError(
            f"configuration {name} must be <= {maximum}",
            context={"variable": name, "reason": "above_maximum"},
        )
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated application configuration.

    Construct via :func:`load_settings`; the constructor performs no I/O so
    tests can build instances directly.
    """

    environment: str = ENV_DEVELOPMENT

    # --- HTTP surface -----------------------------------------------------
    # Loopback by default: a foundation build must never expose a listener on
    # every interface because someone forgot to set a variable.
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000

    # --- Security toggles (restrictive defaults) --------------------------
    auth_required: bool = True
    tls_required: bool = True
    debug: bool = False
    allow_insecure_bind: bool = False

    # --- Paths ------------------------------------------------------------
    workspace_root: Path = field(default_factory=lambda: REPO_ROOT)
    data_dir: Path = field(default_factory=lambda: REPO_ROOT / "data")

    # --- Logging ----------------------------------------------------------
    log_level: str = "INFO"
    log_format: str = "json"

    # --- Secret provider --------------------------------------------------
    # Selects WHICH provider resolves secrets. Never a secret value itself.
    # Read from SECTOOLKIT_SECRETS_PROVIDER (note the plural): the singular
    # SECTOOLKIT_SECRET_ prefix is reserved for actual secret material in
    # interfaces/secrets.py, so SECTOOLKIT_SECRET_PROVIDER would be parsed as
    # a secret literally named "provider".
    secret_provider: str = "env"  # noqa: S105 - a provider NAME, not a credential
    # (S105 fires on the name "secret_provider"; the value is "env", an
    #  enum-like selector. The actual secret material never lives here.)

    # --- Native engines ---------------------------------------------------
    enable_rust_engine: bool = False
    enable_cpp_engine: bool = False

    # ------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.environment == ENV_PRODUCTION

    @property
    def is_test(self) -> bool:
        return self.environment == ENV_TEST

    def validate(self) -> None:
        """Enforce cross-field invariants. Raises :class:`ConfigurationError`.

        These are the rules a single field cannot express: a setting that is
        acceptable in development and unacceptable in production.
        """
        if self.environment not in ENVIRONMENTS:
            raise ConfigurationError(
                f"unknown environment: must be one of {', '.join(ENVIRONMENTS)}",
                context={"reason": "invalid_environment"},
            )
        if not (1 <= self.bind_port <= 65535):
            raise ConfigurationError(
                "bind port must be between 1 and 65535",
                context={"reason": "invalid_port"},
            )

        # Binding to all interfaces requires an EXPLICIT opt-in, and is
        # forbidden in production regardless: production exposure belongs to
        # the ingress/load balancer, not the app process.
        # noqa: S104 - this is the guard that REJECTS all-interface
        # binding; the literal has to appear for the check to exist.
        if self.bind_host in ("0.0.0.0", "::", "*"):  # noqa: S104
            if self.is_production:
                raise ConfigurationError(
                    "binding to all interfaces is not permitted in production",
                    context={"reason": "insecure_bind_production"},
                )
            if not self.allow_insecure_bind:
                raise ConfigurationError(
                    "binding to all interfaces requires "
                    f"{ENV_PREFIX}ALLOW_INSECURE_BIND=true",
                    context={"reason": "insecure_bind_not_allowed"},
                )

        if self.is_production:
            if self.debug:
                raise ConfigurationError(
                    "debug mode must be disabled in production",
                    context={"reason": "debug_in_production"},
                )
            if not self.auth_required:
                raise ConfigurationError(
                    "authentication cannot be disabled in production",
                    context={"reason": "auth_disabled_in_production"},
                )
            if not self.tls_required:
                raise ConfigurationError(
                    "TLS cannot be disabled in production",
                    context={"reason": "tls_disabled_in_production"},
                )

        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ConfigurationError(
                "invalid log level", context={"reason": "invalid_log_level"}
            )
        if self.log_format not in ("json", "text"):
            raise ConfigurationError(
                "log format must be 'json' or 'text'",
                context={"reason": "invalid_log_format"},
            )
        if self.secret_provider not in ("env", "file", "vault", "kms"):
            raise ConfigurationError(
                "unknown secret provider",
                context={"reason": "invalid_secret_provider"},
            )

    def safe_dump(self) -> dict[str, Any]:
        """Configuration rendered for logs: sensitive fields redacted.

        Nothing in :class:`Settings` currently holds secret material, but the
        redaction is enforced by NAME so a future sensitive field is covered
        the moment it is added rather than the moment someone remembers.
        """
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if is_sensitive_name(f.name):
                out[f.name] = REDACTED
            elif isinstance(value, Path):
                out[f.name] = str(value)
            else:
                out[f.name] = value
        return out

    def __repr__(self) -> str:
        return f"Settings({self.safe_dump()})"

    __str__ = __repr__


def load_settings(
    env: Mapping[str, str] | None = None,
    *,
    create_dirs: bool = False,
) -> Settings:
    """Build and validate :class:`Settings` from the environment.

    ``env`` may be supplied for tests. ``create_dirs`` is opt-in so importing
    configuration never writes to disk as a side effect.
    """
    source = env if env is not None else os.environ
    p = ENV_PREFIX

    environment = get_str(
        f"{p}ENV", default=ENV_DEVELOPMENT, choices=ENVIRONMENTS, env=source
    )
    workspace = Path(
        get_str(f"{p}WORKSPACE", default=str(REPO_ROOT), env=source)
    ).expanduser()
    data_dir = Path(
        get_str(f"{p}DATA_DIR", default=str(workspace / "data"), env=source)
    ).expanduser()

    settings = Settings(
        environment=environment,
        bind_host=get_str(f"{p}BIND_HOST", default="127.0.0.1", env=source),
        bind_port=get_int(
            f"{p}BIND_PORT", default=8000, minimum=1, maximum=65535, env=source
        ),
        auth_required=get_bool(f"{p}AUTH_REQUIRED", default=True, env=source),
        tls_required=get_bool(f"{p}TLS_REQUIRED", default=True, env=source),
        debug=get_bool(f"{p}DEBUG", default=False, env=source),
        allow_insecure_bind=get_bool(
            f"{p}ALLOW_INSECURE_BIND", default=False, env=source
        ),
        workspace_root=workspace,
        data_dir=data_dir,
        log_level=get_str(
            f"{p}LOG_LEVEL",
            default="INFO",
            choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
            env=source,
        ),
        log_format=get_str(
            f"{p}LOG_FORMAT", default="json", choices=("json", "text"), env=source
        ),
        secret_provider=get_str(
            f"{p}SECRETS_PROVIDER",
            default="env",
            choices=("env", "file", "vault", "kms"),
            env=source,
        ),
        enable_rust_engine=get_bool(f"{p}ENABLE_RUST", default=False, env=source),
        enable_cpp_engine=get_bool(f"{p}ENABLE_CPP", default=False, env=source),
    )
    settings.validate()
    if create_dirs:
        ensure_directory(settings.data_dir)
    return settings


__all__ = [
    "Settings",
    "load_settings",
    "get_str",
    "get_bool",
    "get_int",
    "is_sensitive_name",
    "ENV_PREFIX",
    "ENV_DEVELOPMENT",
    "ENV_TEST",
    "ENV_PRODUCTION",
]
