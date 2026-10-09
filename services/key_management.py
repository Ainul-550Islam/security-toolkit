"""Encryption-key resolution with an injectable provider boundary.

Only an environment-backed provider is included here. Deployments may inject
Vault/KMS-backed implementations of ``KeyProvider``; this module never
pretends that an unavailable remote provider is configured.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass, field
from typing import Protocol


_ACTIVE_KEY_ID_ENV = "SECURITY_TOOLKIT_ENCRYPTION_ACTIVE_KEY_ID"
_ACTIVE_KEY_ENV = "SECURITY_TOOLKIT_ENCRYPTION_KEY"
_KEY_PREFIX_ENV = "SECURITY_TOOLKIT_ENCRYPTION_KEY_"
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_KEY_BYTES = 32


class KeyManagementError(Exception):
    """Safe base exception for missing or invalid encryption-key settings."""

    def __init__(self, code: str) -> None:
        self.code = code if re.fullmatch(r"[a-z0-9_]{1,64}", code) else "key_error"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedKey:
    """An identified AES-256 key whose representation never prints material."""

    key_id: str
    material: bytes = field(repr=False)

    def __repr__(self) -> str:
        return f"ResolvedKey(key_id={self.key_id!r}, material=[REDACTED])"


class KeyProvider(Protocol):
    """Minimal contract for environment, KMS, or Vault key providers."""

    def active_key_id(self) -> str:
        """Return the identifier of the key used for new ciphertext."""

    def resolve(self, key_id: str) -> bytes:
        """Resolve key material by identifier or raise ``KeyManagementError``."""

    def available_key_ids(self) -> tuple[str, ...]:
        """Return configured identifiers only; never return key material."""


class EnvironmentKeyProvider:
    """Resolve strict base64-encoded AES-256 keys from process environment."""

    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self._environ = environ

    def _env(self) -> dict[str, str]:
        return os.environ if self._environ is None else self._environ

    def active_key_id(self) -> str:
        env = self._env()
        key_id = str(env.get(_ACTIVE_KEY_ID_ENV, "") or "").strip()
        active_key = str(env.get(_ACTIVE_KEY_ENV, "") or "").strip()
        if not key_id:
            if active_key:
                key_id = "env-v1"
            else:
                raise KeyManagementError("encryption_key_not_configured")
        if not _KEY_ID_RE.fullmatch(key_id):
            raise KeyManagementError("encryption_key_id_invalid")
        if not self._encoded_value(key_id):
            raise KeyManagementError("encryption_active_key_unavailable")
        return key_id

    def resolve(self, key_id: str) -> bytes:
        candidate = str(key_id or "").strip()
        if not _KEY_ID_RE.fullmatch(candidate):
            raise KeyManagementError("encryption_key_id_invalid")
        encoded = self._encoded_value(candidate)
        if not encoded:
            raise KeyManagementError("encryption_key_unavailable")
        try:
            raw = base64.b64decode(
                encoded.encode("ascii"), altchars=b"-_", validate=True
            )
        except (UnicodeEncodeError, binascii.Error, ValueError):
            raise KeyManagementError("encryption_key_encoding_invalid") from None
        if len(raw) != _KEY_BYTES:
            raise KeyManagementError("encryption_key_length_invalid")
        return raw

    def available_key_ids(self) -> tuple[str, ...]:
        ids: set[str] = set()
        env = self._env()
        for name, value in env.items():
            if not name.startswith(_KEY_PREFIX_ENV) or not value:
                continue
            key_id = name[len(_KEY_PREFIX_ENV):]
            if _KEY_ID_RE.fullmatch(key_id):
                ids.add(key_id)
        if env.get(_ACTIVE_KEY_ENV):
            try:
                ids.add(self.active_key_id())
            except KeyManagementError:
                pass
        return tuple(sorted(ids))

    def _encoded_value(self, key_id: str) -> str:
        env = self._env()
        specific = str(env.get(_KEY_PREFIX_ENV + key_id, "") or "").strip()
        if specific:
            return specific
        try:
            active_id = str(env.get(_ACTIVE_KEY_ID_ENV, "") or "").strip()
        except (AttributeError, TypeError):
            active_id = ""
        if key_id == (active_id or "env-v1"):
            return str(env.get(_ACTIVE_KEY_ENV, "") or "").strip()
        return ""


class KeyManagementService:
    """Resolve active and historical encryption keys without caching secrets."""

    def __init__(self, provider: KeyProvider | None = None) -> None:
        self._provider: KeyProvider = provider or EnvironmentKeyProvider()

    def active_key(self) -> ResolvedKey:
        key_id = self._provider.active_key_id()
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise KeyManagementError("encryption_key_id_invalid")
        material = self._provider.resolve(key_id)
        self._validate_material(material)
        return ResolvedKey(key_id=key_id, material=bytes(material))

    def resolve_key(self, key_id: str) -> ResolvedKey:
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise KeyManagementError("encryption_key_id_invalid")
        material = self._provider.resolve(key_id)
        self._validate_material(material)
        return ResolvedKey(key_id=key_id, material=bytes(material))

    def available_key_ids(self) -> tuple[str, ...]:
        return self._provider.available_key_ids()

    def status(self) -> dict[str, object]:
        """Safe operator summary; it includes identifiers, never key bytes."""
        try:
            active_id = self._provider.active_key_id()
            material = self._provider.resolve(active_id)
            self._validate_material(material)
        except KeyManagementError:
            return {
                "state": "NOT_CONFIGURED",
                "active_key_id": "",
                "available_key_ids": list(self.available_key_ids()),
            }
        return {
            "state": "CONFIGURED",
            "active_key_id": active_id,
            "available_key_ids": list(self.available_key_ids()),
        }

    @staticmethod
    def _validate_material(material: bytes) -> None:
        if not isinstance(material, bytes) or len(material) != _KEY_BYTES:
            raise KeyManagementError("encryption_key_length_invalid")


__all__ = [
    "EnvironmentKeyProvider",
    "KeyManagementError",
    "KeyManagementService",
    "KeyProvider",
    "ResolvedKey",
]
