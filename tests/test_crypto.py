"""Authenticated-encryption and environment key-management regressions."""

from __future__ import annotations

import base64
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from services.crypto import CryptoNotConfigured, CryptoService, EncryptedValueError
from services.key_management import (
    EnvironmentKeyProvider,
    KeyManagementError,
    KeyManagementService,
)

_ACTIVE_ID = "SECURITY_TOOLKIT_ENCRYPTION_ACTIVE_KEY_ID"
_ACTIVE_KEY = "SECURITY_TOOLKIT_ENCRYPTION_KEY"
_KEY_PREFIX = "SECURITY_TOOLKIT_ENCRYPTION_KEY_"


def _encoded_key(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class CryptoServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_key = b"O" * 32
        self.new_key = b"N" * 32
        self.env = {
            _ACTIVE_ID: "key-new",
            _ACTIVE_KEY: _encoded_key(self.new_key),
            _KEY_PREFIX + "key-old": _encoded_key(self.old_key),
        }
        self.keys = KeyManagementService(EnvironmentKeyProvider(self.env))
        self.crypto = CryptoService(self.keys)

    def test_encrypt_decrypt_uses_versioned_aead_and_context_binding(self) -> None:
        encrypted = self.crypto.encrypt_text(
            "sensitive webhook value",
            associated_data="notification:webhook-secret:tenant-a:project-a",
        )
        self.assertTrue(encrypted.startswith("st-aesgcm:v1:key-new:"))
        self.assertNotIn("sensitive webhook value", encrypted)
        self.assertEqual(
            self.crypto.decrypt_text(
                encrypted,
                associated_data="notification:webhook-secret:tenant-a:project-a",
            ),
            "sensitive webhook value",
        )
        with self.assertRaises(EncryptedValueError):
            self.crypto.decrypt_text(
                encrypted,
                associated_data="notification:webhook-secret:tenant-b:project-a",
            )

    def test_ciphertexts_use_distinct_random_nonces(self) -> None:
        first = self.crypto.encrypt_text("same", associated_data="purpose:one")
        second = self.crypto.encrypt_text("same", associated_data="purpose:one")
        self.assertNotEqual(first, second)
        self.assertEqual(
            self.crypto.decrypt_text(first, associated_data="purpose:one"), "same"
        )
        self.assertEqual(
            self.crypto.decrypt_text(second, associated_data="purpose:one"), "same"
        )

    def test_tampering_and_unsupported_versions_fail_closed(self) -> None:
        encrypted = self.crypto.encrypt_text("value", associated_data="purpose:one")
        parts = encrypted.split(":")
        final = parts[4]
        replacement = "A" if final[-1] != "A" else "B"
        parts[4] = final[:-1] + replacement
        with self.assertRaises(EncryptedValueError):
            self.crypto.decrypt_text(":".join(parts), associated_data="purpose:one")
        with self.assertRaises(EncryptedValueError):
            self.crypto.decrypt_text(
                encrypted.replace(":v1:", ":v2:", 1),
                associated_data="purpose:one",
            )
        with self.assertRaises(EncryptedValueError):
            self.crypto.decrypt_text("plaintext", associated_data="purpose:one")

    def test_key_rotation_keeps_historical_key_available_for_decryption(self) -> None:
        old_environment = {
            _ACTIVE_ID: "key-old",
            _ACTIVE_KEY: _encoded_key(self.old_key),
        }
        old_crypto = CryptoService(
            KeyManagementService(EnvironmentKeyProvider(old_environment))
        )
        legacy_key_ciphertext = old_crypto.encrypt_text(
            "rotate me", associated_data="notification:webhook-secret:tenant-a:project-a"
        )
        migrated_key_ciphertext = self.crypto.encrypt_text(
            self.crypto.decrypt_text(
                legacy_key_ciphertext,
                associated_data="notification:webhook-secret:tenant-a:project-a",
            ),
            associated_data="notification:webhook-secret:tenant-a:project-a",
        )
        self.assertTrue(migrated_key_ciphertext.startswith("st-aesgcm:v1:key-new:"))
        self.assertEqual(
            self.crypto.decrypt_text(
                migrated_key_ciphertext,
                associated_data="notification:webhook-secret:tenant-a:project-a",
            ),
            "rotate me",
        )

    def test_missing_or_invalid_active_key_is_not_silently_replaced(self) -> None:
        missing = CryptoService(
            KeyManagementService(EnvironmentKeyProvider({}))
        )
        with self.assertRaises(CryptoNotConfigured):
            missing.encrypt_text("value", associated_data="purpose:one")

        malformed = EnvironmentKeyProvider({
            _ACTIVE_ID: "bad-key",
            _ACTIVE_KEY: "not-base64!",
        })
        with self.assertRaises(KeyManagementError):
            malformed.resolve("bad-key")

        wrong_length = EnvironmentKeyProvider({
            _ACTIVE_ID: "short-key",
            _ACTIVE_KEY: _encoded_key(b"short"),
        })
        with self.assertRaises(KeyManagementError):
            wrong_length.resolve("short-key")

    def test_key_status_never_contains_material(self) -> None:
        status = self.keys.status()
        self.assertEqual(status["state"], "CONFIGURED")
        self.assertEqual(status["active_key_id"], "key-new")
        self.assertIn("key-old", status["available_key_ids"])
        self.assertNotIn(_encoded_key(self.new_key), str(status))
        self.assertEqual(
            repr(self.keys.active_key()),
            "ResolvedKey(key_id='key-new', material=[REDACTED])",
        )


if __name__ == "__main__":
    unittest.main()
