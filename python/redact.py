#!/usr/bin/env python3
# ============================================================================
#  redact.py — CENTRALIZED sensitive-data redaction (single source of truth).
#  ---------------------------------------------------------------------------
#  Used by: evidence sanitization, audit-event sanitization, structured
#  logging, and platform persistence. Scanners must NOT implement their own
#  ad-hoc redaction — they pass data through these helpers.
#
#  Redacts: Authorization headers, Bearer tokens, cookies & session ids,
#  API keys (AWS/Azure/GitHub/OpenAI/Slack/Stripe/private patterns), common
#  secret JSON/YAML keys, URLs with userinfo, private-key blocks, generic
#  `SECRET=value` / `password=value` assignments.
#
#  Pure functions, deterministic, no I/O, no global state.
# ============================================================================

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# --- key/value patterns ------------------------------------------------------
_BEARER = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{8,}=*)")
_KEY_SPACE_VALUE = re.compile(
    r"(?i)\b((?:x-)?api[-_]?key|auth[-_]?token|access[-_]?token|"
    r"client[-_]?secret)\s+([A-Za-z0-9_\-./+]{6,})")
_AUTH_HEADER = re.compile(
    r"(?im)^(\s*(?:(?:proxy-)?authorization|www-authenticate|x-api-key|"
    r"x-auth-token|api-key)\s*[:=]\s*)([^\r\n]+)")
_COOKIE = re.compile(r"(?i)(\bcookie\s*[:=]\s*)([^\r\n;]+)")
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(password|passwd|pass|secret|token|api[-_]?key|apikey|access[-_]?key|"
    r"client[-_]?secret|private[-_]?key|session|session[-_]?(id|token)|cookie|"
    r"set-cookie|auth[-_]?token|"
    r"refresh[-_]?token|signing[-_]?key|db[-_]?password|pwd|aws[-_]?secret)"
    r"\s*[:=]\s*([^\s,;&\"']+)")
_PRV_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL)
_USERINFO_URL = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s@]+)@([^/\s]+)", re.I)
# secrets smuggled via query strings (?t=, &token=, &session=, …) — the KEY
# itself stays visible (useful for triage), the VALUE is replaced.
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:t|tok|token|apikey|api[-_]?key|key|pass|passwd|password|"
    r"pwd|secret|session|sess|sid|cookie|auth|credential)=)([^&#\"'<>;\s]+)")
# session identifiers in headers/cookies/logs (jsessionid, phpsessid, …)
_SESSION_ID = re.compile(
    r"(?i)\b(jsessionid|phpsessid|asp\.net_sessionid|sessionid|sessid|"
    r"session[-_]?id)\s*[:=]\s*([A-Za-z0-9_-]{6,})")
# AWS SigV4 query parameters (presigned URLs) — never logged/persisted
_AMZ_QUERY = re.compile(
    r"(?i)(x-amz-(?:credential|signature|security-token|algorithm|date|"
    r"expires|signedheaders)=)[^&\s]+")

# --- known key/format fingerprints --------------------------------------------
_AWS_ACCESS = re.compile(r"\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b")
_GH_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")
_GITHUB = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")
_OPENAI = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")
_SLACK = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_STRIPE = re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")
_GOOGLE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")

# --- key-name based rules (recursive dict/list handling) ------------------------
SECRET_KEYS = {
    "password", "passwd", "pwd", "secret", "client_secret", "clientsecret",
    "api_key", "apikey", "api-key", "access_key", "accesskey", "token",
    "access_token", "refresh_token", "auth_token", "authorization",
    "cookie", "session", "session_id", "sessionid", "session_token",
    "private_key", "privatekey", "ssh_key", "db_password", "db_password",
    "aws_secret_access_key", "aws_secret_key", "azure_client_secret",
    "github_token", "stripe_secret_key", "openai_api_key", "webhook_secret",
    "signing_key", "secret_key", "consumer_secret", "app_secret",
    "authtoken", "credentials", "passphrase",
}
SECRET_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|secret|token|passwd|password|pwd|"
    r"auth|session|cookie|credential|private[_-]?key|signing[_-]?key|"
    r"client[_-]?secret)", re.I)


def _apply_patterns(text: str) -> str:
    text = _PRV_KEY_BLOCK.sub(REDACTED, text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _COOKIE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _BEARER.sub(lambda m: "Bearer " + REDACTED, text)
    text = _KEY_SPACE_VALUE.sub(lambda m: m.group(1) + " " + REDACTED, text)
    text = _SECRET_ASSIGN.sub(lambda m: m.group(1) + "=" + REDACTED, text)
    text = _QUERY_SECRET.sub(lambda m: m.group(1) + REDACTED, text)
    text = _SESSION_ID.sub(lambda m: m.group(1) + "=" + REDACTED, text)
    text = _AMZ_QUERY.sub(lambda m: m.group(1) + REDACTED, text)
    text = _USERINFO_URL.sub(lambda m: m.group(1) + REDACTED + "@" + m.group(3), text)
    for pat in (_AWS_ACCESS, _GH_TOKEN, _GITHUB, _OPENAI,
                _SLACK, _STRIPE, _GOOGLE, _JWT):
        text = pat.sub(REDACTED, text)
    return text


def redact_text(text) -> str:
    """Redact secrets inside arbitrary text (headers, bodies, logs)."""
    if text is None:
        return ""
    return _apply_patterns(str(text))


def _redact_key(key: str) -> bool:
    return bool(SECRET_KEY_RE.search(key)) and key.lower() not in (
        "authorized", "authorization_required", "no_auth", "unauthorized")


def redact_value(value, *, key: str = ""):
    """Recursively redact a value; dict keys matching secret patterns are
    replaced entirely. A scalar passed under a secret KEY (e.g. a log field
    named `password`) is replaced entirely as well — never rely on the value
    shape alone."""
    if key and _redact_key(str(key)):
        return REDACTED
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if _redact_key(str(k)):
                out[k] = REDACTED
            else:
                out[k] = redact_value(v, key=str(k))
        return out
    if isinstance(value, (list, tuple)):
        return [redact_value(v, key=key) for v in value]
    if isinstance(value, (str,)):
        return _apply_patterns(value)
    return value


def redact(value):
    """Public entry point: redact any JSON-able structure or text."""
    return redact_value(value)


def contains_secret(value) -> bool:
    """Cheap heuristic used by tests: does a structure still look secretful?"""
    if isinstance(value, dict):
        return any(_redact_key(str(k)) or contains_secret(v)
                   for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(contains_secret(v) for v in value)
    if isinstance(value, str):
        return bool(_BEARER.search(value) or _PRV_KEY_BLOCK.search(value)
                    or _AWS_ACCESS.search(value) or _GH_TOKEN.search(value)
                    or _OPENAI.search(value) or _SLACK.search(value)
                    or _STRIPE.search(value) or _GOOGLE.search(value))
    return False
