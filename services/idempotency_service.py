"""Persistent tenant-scoped idempotency for API work and side effects.

The service owns request fingerprinting, atomic claims, bounded successful
response replay, and expiry cleanup. HTTP adapters translate
``IdempotencyError`` into their stable public error model; this module never
imports the API layer.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

_KEY_RE = re.compile(r"^[!-~]{8,128}$")
_SCOPE_RE = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
_MAX_REQUEST_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 65_536


class IdempotencyError(Exception):
    """Stable, value-free idempotency failure."""

    def __init__(self, code: str, status: int = 409) -> None:
        allowed = {
            "invalid_idempotency_scope": 400,
            "idempotency_key_required": 400,
            "invalid_request": 400,
            "request_too_large": 413,
            "idempotency_conflict": 409,
            "idempotent_request_failed": 409,
            "idempotent_request_in_progress": 409,
            "idempotency_record_invalid": 503,
            "idempotency_store_unavailable": 503,
        }
        self.code = code if code in allowed else "idempotency_store_unavailable"
        self.status = allowed.get(self.code, status)
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class IdempotencyClaim:
    """Result of claiming a tenant-scoped operation key."""

    org_id: str
    scope: str
    key_hash: str
    request_hash: str
    is_replay: bool
    status_code: int = 0
    response: dict[str, Any] | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_request_hash(value: Any) -> str:
    """Hash bounded canonical JSON; never retain the original request body."""
    try:
        canonical = json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, OverflowError, UnicodeError):
        raise IdempotencyError("invalid_request", 400) from None
    if len(canonical) > _MAX_REQUEST_BYTES:
        raise IdempotencyError("request_too_large", 413)
    return hashlib.sha256(canonical).hexdigest()


class IdempotencyService:
    """Atomically reserve, complete, replay, and expire idempotency claims."""

    def __init__(self, database: Any, *, ttl_seconds: int = 86_400) -> None:
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 604_800:
            raise ValueError("idempotency TTL must be between 60 and 604800 seconds")
        self.db = database
        self.ttl_seconds = ttl_seconds

    def claim(self, org_id: str, scope: str, key: str, request: Any) -> IdempotencyClaim:
        """Reserve an operation key or replay its prior successful response."""
        tenant = str(org_id or "")
        operation_scope = str(scope or "")
        client_key = str(key or "")
        if not tenant or len(tenant) > 160 or not _SCOPE_RE.fullmatch(operation_scope):
            raise IdempotencyError("invalid_idempotency_scope", 400)
        if not _KEY_RE.fullmatch(client_key):
            raise IdempotencyError("idempotency_key_required", 400)
        request_hash = canonical_request_hash(request)
        key_hash = hashlib.sha256(client_key.encode("ascii")).hexdigest()
        now = _now()
        now_text = _timestamp(now)
        expires_text = _timestamp(now + timedelta(seconds=self.ttl_seconds))
        record_id = uuid.uuid4().hex
        try:
            with self.db.transaction() as connection:
                existing = connection.execute(
                    "SELECT request_hash, state, status_code, response_json, expires_at "
                    "FROM api_idempotency_records WHERE org_id=? AND scope=? "
                    "AND key_hash=? LIMIT 1",
                    (tenant, operation_scope, key_hash),
                ).fetchone()
                if existing is not None and str(existing["expires_at"]) <= now_text:
                    connection.execute(
                        "DELETE FROM api_idempotency_records WHERE org_id=? "
                        "AND scope=? AND key_hash=?",
                        (tenant, operation_scope, key_hash),
                    )
                    existing = None
                if existing is not None:
                    if str(existing["request_hash"]) != request_hash:
                        raise IdempotencyError("idempotency_conflict")
                    state = str(existing["state"])
                    if state == "completed":
                        try:
                            stored = json.loads(str(existing["response_json"]))
                        except (TypeError, ValueError, json.JSONDecodeError):
                            raise IdempotencyError("idempotency_record_invalid", 503) from None
                        if not isinstance(stored, dict):
                            raise IdempotencyError("idempotency_record_invalid", 503)
                        return IdempotencyClaim(
                            tenant,
                            operation_scope,
                            key_hash,
                            request_hash,
                            True,
                            int(existing["status_code"]),
                            stored,
                        )
                    if state == "failed":
                        raise IdempotencyError("idempotent_request_failed")
                    if state != "in_progress":
                        raise IdempotencyError("idempotency_record_invalid", 503)
                    raise IdempotencyError("idempotent_request_in_progress")
                connection.execute(
                    "INSERT INTO api_idempotency_records "
                    "(id, org_id, scope, key_hash, request_hash, state, status_code, "
                    "response_json, created_at, updated_at, expires_at) "
                    "VALUES (?,?,?,?,?,'in_progress',0,'{}',?,?,?)",
                    (record_id, tenant, operation_scope, key_hash, request_hash,
                     now_text, now_text, expires_text),
                )
        except IdempotencyError:
            raise
        except Exception:
            raise IdempotencyError("idempotency_store_unavailable", 503) from None
        return IdempotencyClaim(
            tenant,
            operation_scope,
            key_hash,
            request_hash,
            False,
        )

    def complete(
        self,
        claim: IdempotencyClaim,
        *,
        status_code: int,
        response: dict[str, Any],
    ) -> None:
        """Persist only a bounded successful, JSON-safe replay result."""
        if not isinstance(claim, IdempotencyClaim) or claim.is_replay:
            raise ValueError("an active idempotency claim is required")
        if type(status_code) is not int or status_code < 200 or status_code > 299:
            raise ValueError("idempotency response status must be successful")
        if not isinstance(response, dict):
            raise ValueError("idempotency response must be an object")
        try:
            payload = json.dumps(
                response,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError, OverflowError, UnicodeError):
            raise ValueError("idempotency response is not JSON serializable") from None
        if len(payload.encode("utf-8")) > _MAX_RESPONSE_BYTES:
            raise ValueError("idempotency response exceeds the storage bound")
        try:
            changed = self.db.execute_affected(
                "UPDATE api_idempotency_records SET state='completed', status_code=?, "
                "response_json=?, updated_at=? WHERE org_id=? AND scope=? "
                "AND key_hash=? AND request_hash=? AND state='in_progress'",
                (status_code, payload, _timestamp(_now()), claim.org_id,
                 claim.scope, claim.key_hash, claim.request_hash),
            )
        except Exception:
            raise IdempotencyError("idempotency_store_unavailable", 503) from None
        if changed != 1:
            raise IdempotencyError("idempotency_record_invalid", 503)

    def fail(self, claim: IdempotencyClaim) -> None:
        """Mark the request failed without retaining exception or response data."""
        if not isinstance(claim, IdempotencyClaim) or claim.is_replay:
            return
        try:
            self.db.execute_affected(
                "UPDATE api_idempotency_records SET state='failed', response_json='{}', "
                "updated_at=? WHERE org_id=? AND scope=? AND key_hash=? "
                "AND request_hash=? AND state='in_progress'",
                (_timestamp(_now()), claim.org_id, claim.scope, claim.key_hash,
                 claim.request_hash),
            )
        except Exception:
            raise IdempotencyError("idempotency_store_unavailable", 503) from None

    def purge_expired(self, *, limit: int = 500) -> int:
        """Delete only expired records in a bounded batch."""
        if type(limit) is not int or not 1 <= limit <= 5000:
            raise ValueError("idempotency purge limit is outside the allowed range")
        now_text = _timestamp(_now())
        try:
            with self.db.transaction() as connection:
                rows = connection.execute(
                    "SELECT id FROM api_idempotency_records WHERE expires_at<=? "
                    "ORDER BY expires_at, id LIMIT ?",
                    (now_text, limit),
                ).fetchall()
                ids = [str(row["id"]) for row in rows]
                if not ids:
                    return 0
                marks = ",".join("?" for _ in ids)
                cursor = connection.execute(
                    f"DELETE FROM api_idempotency_records WHERE id IN ({marks}) "
                    "AND expires_at<=?",
                    (*ids, now_text),
                )
                return max(0, int(cursor.rowcount))
        except Exception:
            raise IdempotencyError("idempotency_store_unavailable", 503) from None


__all__ = [
    "IdempotencyClaim",
    "IdempotencyError",
    "IdempotencyService",
    "canonical_request_hash",
]
