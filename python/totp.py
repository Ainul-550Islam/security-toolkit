#!/usr/bin/env python3
# ============================================================================
#  totp.py — RFC 6238 TOTP + recovery-code primitives (Phase 8).
#  ---------------------------------------------------------------------------
#  Zero-dependency implementation of the STANDARD HOTP/TOTP construction
#  (RFC 4226 / RFC 6238) on top of stdlib hmac/hashlib — the same well-known
#  algorithm used by RFC-compliant authenticator apps (Google Authenticator,
#  Authy, 1Password, …). No custom cryptography; no external dependency.
#
#  Security properties:
#    - seeds: 160-bit (20-byte) cryptographically random secrets,
#      Base32-encoded (RFC 4648, no padding) — the standard representation.
#    - codes: 6 digits, 30-second step, SHA-1 (the RFC 6238 default), with a
#      ±1-step clock-skew window (3 codes tried per verification).
#    - verification is constant-time (hmac.compare_digest) and returns the
#      matched time-step so callers can enforce REPLAY RESISTANCE (a step
#      once accepted is never accepted again for the same user).
#    - recovery codes: 128-bit cryptographically random, shown once,
#      stored ONLY as salted HMAC-SHA256 verifiers, single-use by design.
# ============================================================================

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time

import errors

# ---------------------------------------------------------------------------
# constants / validation
# ---------------------------------------------------------------------------
DIGITS = 6
TIME_STEP = 30
WINDOW = 1                  # ±1 step around the current step
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_PREFIX = "rec_"


def _now_epoch() -> float:
    return time.time()


def normalize_seed(seed: str) -> str:
    """Validate + normalize a Base32 TOTP seed (uppercase, no spaces/padding).
    Raises ValidationError for anything that is not clean Base32."""
    s = str(seed or "").strip().upper().replace(" ", "").replace("-", "")
    if not s:
        raise errors.ValidationError("totp_seed_invalid: empty")
    if len(s) < 16 or len(s) > 128:
        raise errors.ValidationError("totp_seed_invalid: length out of range")
    if s.endswith("="):
        s = s.rstrip("=")
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for ch in s):
        raise errors.ValidationError("totp_seed_invalid: not Base32")
    try:
        raw = base64.b32decode(s + ("=" * ((8 - len(s) % 8) % 8)), casefold=False)
    except (binascii.Error, ValueError):
        raise errors.ValidationError("totp_seed_invalid: not decodable") from None
    if len(raw) < 10:
        raise errors.ValidationError("totp_seed_invalid: seed too short")
    return s


def generate_seed() -> str:
    """Fresh 20-byte (160-bit) TOTP seed as unpadded Base32."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def hotp(seed: str, counter: int, *, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP value for a 64-bit counter (constant-time truncation)."""
    raw = base64.b32decode(normalize_seed(seed)
                           + ("=" * ((8 - len(normalize_seed(seed)) % 8) % 8)))
    msg = struct.pack(">Q", int(counter) & 0xFFFFFFFFFFFFFFFF)
    digest = hmac.new(raw, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24 |
              (digest[offset + 1] & 0xFF) << 16 |
              (digest[offset + 2] & 0xFF) << 8 |
              (digest[offset + 3] & 0xFF))
    return str(binary % (10 ** int(digits))).zfill(int(digits))


def current_step(epoch: float | None = None, *, step: int = TIME_STEP) -> int:
    return int((epoch if epoch is not None else _now_epoch()) // int(step))


def code_for(seed: str, epoch: float | None = None, *, step: int = TIME_STEP,
             digits: int = DIGITS) -> str:
    """The TOTP code valid at `epoch` (default: now)."""
    return hotp(seed, current_step(epoch, step=step), digits=digits)


def verify(seed: str, code: str, *, epoch: float | None = None,
           step: int = TIME_STEP, digits: int = DIGITS,
           window: int = WINDOW, last_used_step: int = -1) -> tuple[bool, int]:
    """Verify `code` against `seed` within ±`window` steps.

    Returns (ok, matched_step). `matched_step` is the time-step the code was
    valid for (so the caller can enforce REPLAY RESISTANCE by refusing any
    step at or below the previously accepted step). Constant-time compare
    against every candidate; no early exit on a guessed first candidate.
    """
    code = str(code or "").strip()
    if not code or not code.isdigit() or len(code) != int(digits):
        return False, -1
    now = current_step(epoch, step=step)
    ok_step = -1
    matched = False
    for candidate in (now, now - 1, now + 1):
        want = hotp(seed, candidate, digits=digits)
        if hmac.compare_digest(want, code):
            matched = True
            ok_step = candidate
            break
    if not matched:
        return False, -1
    if ok_step <= int(last_used_step):
        # replay of a previously accepted code (same or past step)
        return False, -1
    return True, ok_step


def otpauth_uri(issuer: str, account: str, seed: str, *,
                digits: int = DIGITS, step: int = TIME_STEP) -> str:
    """Standard otpauth:// URI for enrollment QR codes (secret is url-quoted;
    the only place the seed is meant to leave this system)."""
    import urllib.parse
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    params = urllib.parse.urlencode({
        "secret": normalize_seed(seed), "issuer": issuer,
        "algorithm": "SHA1", "digits": int(digits),
        "period": int(step)})
    return f"otpauth://totp/{label}?{params}"


# ---------------------------------------------------------------------------
# recovery codes — high-entropy, hash-only at rest, single-use
# ---------------------------------------------------------------------------
def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """`count` brand-new 128-bit codes (shown to the user exactly once)."""
    n = max(4, min(50, int(count)))
    return [RECOVERY_CODE_PREFIX + secrets.token_hex(16) for _ in range(n)]


def hash_recovery_code(code: str, salt: str) -> str:
    """Salted HMAC-SHA256 verifier for one recovery code (never reversed:
    the code itself carries 128 bits of entropy)."""
    return hmac.new(
        (str(salt)).encode("utf-8"), str(code).encode("utf-8"),
        hashlib.sha256).hexdigest()


def verify_recovery_code(code: str, salt: str, stored: str) -> bool:
    """Constant-time check of a recovery code against its stored verifier."""
    if not code or not stored or len(stored) != 64:
        return False
    got = hash_recovery_code(str(code).strip(), str(salt))
    return hmac.compare_digest(got, str(stored).lower())
