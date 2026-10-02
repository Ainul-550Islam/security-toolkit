"""Secret-provider interface.

What this module IS
-------------------
An abstraction for RESOLVING secrets from a provider the deployment already
trusts: process environment today; Vault, AWS/GCP KMS or a Kubernetes secret
store later, behind the same contract.

What this module is NOT
-----------------------
* Not a secret STORE. Nothing here persists secret material.
* Not cryptography. There is no home-grown encryption, obfuscation or
  "encoding" pretending to be protection. Base64 is not encryption, and a
  local XOR routine would be worse than plaintext because it invites false
  confidence. When encryption at rest is required it will be delegated to a
  real KMS/Vault implementation of this same interface.

Handling rules
--------------
* :class:`SecretRef` is a NAME, never a value; refs are safe to log.
* Resolved material is returned as a :class:`SecretValue` whose ``repr`` and
  ``str`` are redacted, so an accidental log/traceback cannot print it.
* A missing secret raises; it never returns ``""``, which a caller could
  mistake for "no auth required".
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from core.constants import REDACTED
from core.errors import SecretError, ValidationError
from core.ids import constant_time_equals

MAX_SECRET_NAME_LEN: Final[int] = 200
_VALID_NAME_CHARS: Final[str] = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-/"
)


@dataclass(frozen=True, slots=True)
class SecretRef:
    """A reference to a secret. Contains no material and is safe to log."""

    name: str
    provider: str = "env"

    def validate(self) -> SecretRef:
        if not self.name or len(self.name) > MAX_SECRET_NAME_LEN:
            raise ValidationError("secret name must be 1..200 characters")
        if any(ch not in _VALID_NAME_CHARS for ch in self.name):
            raise ValidationError(
                "secret name contains invalid characters "
                "(allowed: letters, digits, _ . - /)"
            )
        return self

    def __str__(self) -> str:
        return f"{self.provider}:{self.name}"


class SecretValue:
    """Resolved secret material with redacted representations.

    ``reveal()`` is the single, deliberately conspicuous way to obtain the
    plaintext, which makes misuse easy to spot in review and in grep.
    """

    __slots__ = ("_value", "_ref")

    def __init__(self, value: str, ref: SecretRef) -> None:
        self._value = str(value)
        self._ref = ref

    def reveal(self) -> str:
        """Return the plaintext. Never log or serialize the result."""
        return self._value

    @property
    def ref(self) -> SecretRef:
        return self._ref

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        """Timing-safe comparison (prevents byte-position leakage)."""
        if isinstance(other, SecretValue):
            return constant_time_equals(self._value, other._value)
        if isinstance(other, str):
            return constant_time_equals(self._value, other)
        return NotImplemented

    def __hash__(self) -> int:
        # Hashing secret material would expose it via hash-ordered structures.
        raise TypeError("SecretValue is not hashable")

    def __repr__(self) -> str:
        return f"SecretValue(ref={self._ref}, value={REDACTED})"

    __str__ = __repr__


@runtime_checkable
class SecretProvider(Protocol):
    """Resolves secret references to material."""

    @property
    def name(self) -> str:
        """Provider identifier, e.g. ``env``."""
        ...

    def get(self, ref: SecretRef) -> SecretValue:
        """Resolve a secret. Raises :class:`SecretError` when absent."""
        ...

    def has(self, ref: SecretRef) -> bool:
        """True when the secret can be resolved."""
        ...


class EnvironmentSecretProvider:
    """Reads secrets from environment variables.

    Appropriate for development and for container runtimes that inject
    secrets as env vars. Its limitation is honest and documented: environment
    variables are visible to the process tree and may appear in crash dumps,
    so a KMS/Vault provider is the production path.
    """

    def __init__(
        self,
        env: Mapping[str, str] | None = None,
        *,
        prefix: str = "SECTOOLKIT_SECRET_",
    ) -> None:
        self._env = env if env is not None else os.environ
        self._prefix = str(prefix)

    @property
    def name(self) -> str:
        return "env"

    def _var(self, ref: SecretRef) -> str:
        return f"{self._prefix}{ref.name.upper().replace('-', '_').replace('.', '_')}"

    def get(self, ref: SecretRef) -> SecretValue:
        ref.validate()
        raw = self._env.get(self._var(ref))
        if raw is None:
            raise SecretError(
                f"secret {ref.name!r} is not configured",
                context={"secret": ref.name, "provider": self.name,
                         "reason": "unset"},
            )
        if raw == "":
            # An empty secret is a configuration error, never a valid value:
            # treating "" as usable can disable a signature check.
            raise SecretError(
                f"secret {ref.name!r} is set but empty",
                context={"secret": ref.name, "provider": self.name,
                         "reason": "empty"},
            )
        return SecretValue(raw, ref)

    def has(self, ref: SecretRef) -> bool:
        try:
            ref.validate()
        except ValidationError:
            return False
        return bool(self._env.get(self._var(ref)))


class NullSecretProvider:
    """Resolves nothing. The fail-closed default when none is configured."""

    @property
    def name(self) -> str:
        return "null"

    def get(self, ref: SecretRef) -> SecretValue:
        raise SecretError(
            "no secret provider is configured",
            context={"secret": ref.name, "provider": self.name,
                     "reason": "no_provider"},
        )

    def has(self, ref: SecretRef) -> bool:
        return False


__all__ = [
    "SecretRef",
    "SecretValue",
    "SecretProvider",
    "EnvironmentSecretProvider",
    "NullSecretProvider",
]
