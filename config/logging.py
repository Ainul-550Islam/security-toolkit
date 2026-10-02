"""Structured logging with mandatory secret redaction.

Redaction is applied in a :class:`logging.Filter`, not at each call site.
Call-site discipline fails eventually: one forgotten ``log.info(headers)``
writes an Authorization header to disk forever. A filter sits on the handler,
so every record on that handler is scrubbed regardless of who emitted it.

Two complementary strategies:

* by KEY: any field whose name looks sensitive (``token``, ``password``,
  ``api_key``, ...) has its value replaced entirely.
* by PATTERN: values are scanned for well-known secret SHAPES (bearer
  tokens, ``Authorization:`` headers, PEM private keys, ``key=value``
  credential pairs, cookies) and those substrings are replaced. This catches
  secrets embedded in an innocently named field such as ``message``.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Mapping
from typing import Any, Final

from core.clock import utcnow_iso
from core.constants import MAX_LOG_VALUE_LEN, REDACTED
from core.ids import sanitize_correlation_id

# Field names whose values are always replaced.
SENSITIVE_KEYS: Final[frozenset[str]] = frozenset({
    "authorization", "auth", "proxy_authorization", "password", "passwd",
    "pwd", "secret", "token", "access_token", "refresh_token", "id_token",
    "bearer", "api_key", "apikey", "x_api_key", "private_key", "privatekey",
    "client_secret", "webhook_secret", "signing_key", "signature", "cookie",
    "set_cookie", "session", "session_id", "sessionid", "csrf", "credential",
    "credentials", "db_password", "database_url", "dsn", "connection_string",
    "passphrase", "salt", "hash", "otp", "mfa_code", "recovery_code",
})

_SENSITIVE_SUBSTRINGS: Final[tuple[str, ...]] = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "credential", "cookie", "authorization", "signing",
    "passphrase",
)

# Value-shape patterns. Each replaces only the secret portion so the
# surrounding message stays readable and useful for debugging.
_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # Authorization: Bearer <token> / Basic <blob>
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(bearer|basic|digest)\s+\S+"),
     r"\1\2 " + REDACTED),
    # bare "Bearer eyJ..."
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer " + REDACTED),
    # PEM private key blocks
    (re.compile(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
     REDACTED),
    # key=value / key: value credential pairs
    (re.compile(
        r"(?i)\b([a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|"
        r"credential|passphrase)[a-z0-9_.-]*)(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1\2" + REDACTED),
    # Cookie headers
    (re.compile(r"(?i)\b(set-cookie|cookie)(\s*[:=]\s*)(\S.*)"),
     r"\1\2" + REDACTED),
    # AWS access key ids
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    # Common provider token prefixes (GitHub, Slack, Stripe)
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
                r"sk_(?:live|test)_[A-Za-z0-9]{10,})\b"), REDACTED),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),
     REDACTED),
)

# Reserved LogRecord attributes; anything else on a record is user metadata.
_RESERVED: Final[frozenset[str]] = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "getMessage", "message", "asctime",
    "taskName",
})


def is_sensitive_key(key: str) -> bool:
    """True when a field name indicates secret content."""
    lowered = str(key).strip().lower().replace("-", "_")
    if lowered in SENSITIVE_KEYS:
        return True
    return any(marker in lowered for marker in _SENSITIVE_SUBSTRINGS)


def redact_text(value: str) -> str:
    """Replace secret-shaped substrings inside free text."""
    if not isinstance(value, str) or not value:
        return value
    out = value
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    if len(out) > MAX_LOG_VALUE_LEN:
        out = out[:MAX_LOG_VALUE_LEN] + "...[truncated]"
    return out


def redact_value(key: str, value: Any, _depth: int = 0) -> Any:
    """Redact a single value, recursing into containers.

    Depth is bounded so a self-referential or pathologically nested structure
    cannot hang the logger.
    """
    if _depth > 6:
        return "[depth-limit]"
    if is_sensitive_key(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {str(k): redact_value(str(k), v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact_value(key, v, _depth + 1) for v in list(value)[:100]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value))


def redact_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    """Redact every entry of a mapping."""
    return {str(k): redact_value(str(k), v) for k, v in data.items()}


class RedactionFilter(logging.Filter):
    """Scrubs the message and all extra fields of every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_text(record.getMessage())
            record.args = ()
        except Exception:  # pragma: no cover - logging must never crash
            record.msg = "[unrenderable log record]"
            record.args = ()
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED or key.startswith("_"):
                continue
            record.__dict__[key] = redact_value(key, value)
        return True


class JsonFormatter(logging.Formatter):
    """Machine-readable records: UTC timestamp, level, component, metadata."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": utcnow_iso(),
            "level": record.levelname,
            "component": record.name,
            "event": getattr(record, "event", record.funcName or "log"),
            "message": record.getMessage(),
        }
        correlation = getattr(record, "correlation_id", None)
        if correlation:
            payload["correlation_id"] = sanitize_correlation_id(str(correlation))
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            if key in ("event", "correlation_id"):
                continue
            payload[key] = value
        if record.exc_info:
            # Type only: exception text can embed paths, queries or tokens.
            payload["error_type"] = getattr(record.exc_info[0], "__name__", "Exception")
        try:
            return json.dumps(payload, default=str, sort_keys=True)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return json.dumps(
                {"ts": payload["ts"], "level": payload["level"],
                 "component": payload["component"],
                 "message": "[unserializable log record]"}
            )


class TextFormatter(logging.Formatter):
    """Human-readable records for local development."""

    def format(self, record: logging.LogRecord) -> str:
        correlation = getattr(record, "correlation_id", "")
        suffix = f" cid={sanitize_correlation_id(str(correlation))}" if correlation else ""
        return (
            f"{utcnow_iso()} {record.levelname:<8} {record.name}: "
            f"{record.getMessage()}{suffix}"
        )


def configure_logging(
    *,
    level: str = "INFO",
    fmt: str = "json",
    stream: Any = None,
    force: bool = True,
) -> logging.Logger:
    """Install the redacting handler on the application's root logger.

    Scoped to the ``security_toolkit`` logger rather than the global root so
    importing this package does not hijack logging for an embedding
    application. ``propagate`` is disabled to prevent duplicate, UNREDACTED
    output through an inherited root handler.
    """
    logger = logging.getLogger("security_toolkit")
    if force:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    handler.addFilter(RedactionFilter())
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.propagate = False
    return logger


def get_logger(component: str, **context: Any) -> logging.LoggerAdapter:
    """Return a logger bound to a component, with optional static context."""
    base = logging.getLogger(f"security_toolkit.{component}")
    safe_context = redact_mapping(context) if context else {}
    return logging.LoggerAdapter(base, safe_context)


__all__ = [
    "configure_logging",
    "get_logger",
    "RedactionFilter",
    "JsonFormatter",
    "TextFormatter",
    "redact_text",
    "redact_value",
    "redact_mapping",
    "is_sensitive_key",
    "SENSITIVE_KEYS",
]
