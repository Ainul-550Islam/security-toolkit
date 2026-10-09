"""Versioned authenticated encryption for small platform secrets.

Ciphertext uses AES-256-GCM from ``cryptography``. The package is deliberately
imported here rather than replaced with a local cipher implementation. AAD is
required so callers can bind ciphertext to a tenant/resource/purpose.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.key_management import KeyManagementError, KeyManagementService


_FORMAT = "st-aesgcm"
_VERSION = "v1"
_NONCE_BYTES = 12
_TAG_BYTES = 16
_MAX_PLAINTEXT_BYTES = 1_048_576
_MAX_CIPHERTEXT_CHARS = 1_500_000
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_AAD_PREFIX = b"security-toolkit\x00aes-256-gcm\x00v1\x00"


class CryptoError(Exception):
    """Base crypto failure with a stable, safe code and no embedded input."""

    def __init__(self, code: str) -> None:
        self.code = code if re.fullmatch(r"[a-z0-9_]{1,64}", code) else "crypto_error"
        super().__init__(self.code)


class CryptoNotConfigured(CryptoError):
    """Raised when no usable active encryption key is available."""


class EncryptedValueError(CryptoError):
    """Raised when ciphertext is malformed, unsupported, or unauthentic."""


class CryptoService:
    """Small-value AEAD service with key IDs, unique nonces, and strict bounds."""

    def __init__(self, key_management: KeyManagementService | None = None) -> None:
        self._keys = key_management or KeyManagementService()

    def encrypt_bytes(self, plaintext: bytes, *, associated_data: str | bytes) -> str:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if len(plaintext) > _MAX_PLAINTEXT_BYTES:
            raise EncryptedValueError("plaintext_too_large")
        aad_context = self._context_bytes(associated_data)
        try:
            resolved = self._keys.active_key()
        except KeyManagementError:
            raise CryptoNotConfigured("encryption_key_not_configured") from None
        key_id = resolved.key_id
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise CryptoNotConfigured("encryption_key_id_invalid")
        nonce = secrets.token_bytes(_NONCE_BYTES)
        aad = self._aad(key_id, aad_context)
        try:
            ciphertext = AESGCM(resolved.material).encrypt(nonce, plaintext, aad)
        except (TypeError, ValueError):
            raise CryptoNotConfigured("encryption_key_invalid") from None
        return ":".join((
            _FORMAT,
            _VERSION,
            key_id,
            self._encode(nonce),
            self._encode(ciphertext),
        ))

    def decrypt_bytes(self, value: str, *, associated_data: str | bytes) -> bytes:
        if not isinstance(value, str) or not value or len(value) > _MAX_CIPHERTEXT_CHARS:
            raise EncryptedValueError("ciphertext_invalid")
        parts = value.split(":")
        if len(parts) != 5 or parts[0] != _FORMAT or parts[1] != _VERSION:
            raise EncryptedValueError("ciphertext_version_unsupported")
        key_id = parts[2]
        if not _KEY_ID_RE.fullmatch(key_id):
            raise EncryptedValueError("ciphertext_key_id_invalid")
        nonce = self._decode(parts[3])
        ciphertext = self._decode(parts[4])
        if len(nonce) != _NONCE_BYTES or len(ciphertext) < _TAG_BYTES:
            raise EncryptedValueError("ciphertext_invalid")
        if len(ciphertext) > _MAX_PLAINTEXT_BYTES + _TAG_BYTES:
            raise EncryptedValueError("ciphertext_too_large")
        aad_context = self._context_bytes(associated_data)
        try:
            resolved = self._keys.resolve_key(key_id)
        except KeyManagementError:
            raise CryptoNotConfigured("encryption_key_unavailable") from None
        aad = self._aad(key_id, aad_context)
        try:
            return AESGCM(resolved.material).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError, TypeError):
            raise EncryptedValueError("ciphertext_authentication_failed") from None

    def encrypt_text(self, plaintext: str, *, associated_data: str | bytes) -> str:
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be text")
        try:
            encoded = plaintext.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise EncryptedValueError("plaintext_encoding_invalid") from None
        return self.encrypt_bytes(encoded, associated_data=associated_data)

    def decrypt_text(self, value: str, *, associated_data: str | bytes) -> str:
        plaintext = self.decrypt_bytes(value, associated_data=associated_data)
        try:
            return plaintext.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise EncryptedValueError("ciphertext_encoding_invalid") from None

    @staticmethod
    def _context_bytes(value: str | bytes) -> bytes:
        if isinstance(value, str):
            try:
                raw = value.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raise EncryptedValueError("associated_data_invalid") from None
        elif isinstance(value, bytes):
            raw = value
        else:
            raise EncryptedValueError("associated_data_invalid")
        if not raw or len(raw) > 1024:
            raise EncryptedValueError("associated_data_invalid")
        return raw

    @staticmethod
    def _aad(key_id: str, context: bytes) -> bytes:
        return _AAD_PREFIX + key_id.encode("ascii") + b"\x00" + context

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _decode(value: str) -> bytes:
        if not value or len(value) > _MAX_CIPHERTEXT_CHARS:
            raise EncryptedValueError("ciphertext_invalid")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise EncryptedValueError("ciphertext_encoding_invalid")
        padding = "=" * ((4 - len(value) % 4) % 4)
        try:
            decoded = base64.b64decode(
                (value + padding).encode("ascii"), altchars=b"-_", validate=True
            )
        except (binascii.Error, UnicodeEncodeError, ValueError):
            raise EncryptedValueError("ciphertext_encoding_invalid") from None
        if CryptoService._encode(decoded) != value:
            raise EncryptedValueError("ciphertext_encoding_invalid")
        return decoded


__all__ = [
    "CryptoError",
    "CryptoNotConfigured",
    "CryptoService",
    "EncryptedValueError",
]
