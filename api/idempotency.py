"""HTTP error adapter for the shared idempotency service.

``IdempotencyStore`` remains as the compatibility name used by API resource
modules and existing callers; persistence and request fingerprinting live in
``services.idempotency_service``.
"""

from __future__ import annotations

from typing import Any

from api.errors import ApiException, ApiProblem
from services.idempotency_service import (
    IdempotencyClaim,
    IdempotencyError,
    IdempotencyService,
)

_ERROR_MESSAGES = {
    "invalid_idempotency_scope": "The idempotency scope is invalid",
    "idempotency_key_required": "A valid Idempotency-Key header is required",
    "invalid_request": "The request cannot be processed",
    "request_too_large": "The request body exceeds the configured limit",
    "idempotency_conflict": "The idempotency key was already used for a different request",
    "idempotent_request_failed": "A previous request with this key failed; submit a new key",
    "idempotent_request_in_progress": "A request with this key is already in progress",
    "idempotency_record_invalid": "The previous request result is unavailable",
    "idempotency_store_unavailable": "Idempotency storage is unavailable",
}


class IdempotencyStore:
    """Compatibility adapter translating domain idempotency failures to HTTP."""

    def __init__(self, database: Any, *, ttl_seconds: int = 86_400) -> None:
        self._service = IdempotencyService(database, ttl_seconds=ttl_seconds)
        self.db = database
        self.ttl_seconds = ttl_seconds

    def claim(
        self,
        org_id: str,
        scope: str,
        key: str,
        request: Any,
    ) -> IdempotencyClaim:
        try:
            return self._service.claim(org_id, scope, key, request)
        except IdempotencyError as exc:
            raise ApiException(ApiProblem(
                exc.status,
                exc.code,
                _ERROR_MESSAGES.get(exc.code, "The request could not be processed"),
            )) from None

    def complete(
        self,
        claim: IdempotencyClaim,
        *,
        status_code: int,
        response: dict[str, Any],
    ) -> None:
        try:
            self._service.complete(claim, status_code=status_code, response=response)
        except IdempotencyError as exc:
            raise ApiException(ApiProblem(
                exc.status,
                exc.code,
                _ERROR_MESSAGES.get(exc.code, "The request could not be processed"),
            )) from None

    def fail(self, claim: IdempotencyClaim) -> None:
        try:
            self._service.fail(claim)
        except IdempotencyError as exc:
            raise ApiException(ApiProblem(
                exc.status,
                exc.code,
                _ERROR_MESSAGES.get(exc.code, "The request could not be processed"),
            )) from None

    def purge_expired(self, *, limit: int = 500) -> int:
        try:
            return self._service.purge_expired(limit=limit)
        except IdempotencyError as exc:
            raise ApiException(ApiProblem(
                exc.status,
                exc.code,
                _ERROR_MESSAGES.get(exc.code, "The request could not be processed"),
            )) from None


__all__ = ["IdempotencyClaim", "IdempotencyStore"]
