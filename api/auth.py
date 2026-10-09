"""Adapter over the existing identity and authorization services.

The adapter intentionally does not implement password hashing, token formats,
RBAC, or object ownership itself. Those decisions remain in
``python/identity.py``, ``python/rbac.py`` and ``python/authz.py``. Raw bearer
credentials are consumed at the boundary and never copied into request
contexts or log fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable

from api.request_context import Principal


class AuthenticationAdapterError(Exception):
    """Internal adapter failure with no credential material in its message."""

    def __init__(self) -> None:
        super().__init__("authentication adapter unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class LoginGrant:
    """One-time result of an identity login; the token is never represented."""

    token: str = field(repr=False)
    token_type: str
    principal: Principal
    session_id: str
    expires_at: str
    mfa_required: bool
    mfa_status: str

    def __repr__(self) -> str:
        return (
            "LoginGrant(token=[REDACTED], "
            f"principal_id={self.principal.principal_id!r}, "
            f"session_id={self.session_id!r}, mfa_status={self.mfa_status!r})"
        )


class AuthenticationAdapter:
    """Translate HTTP credentials into the repository's existing auth context."""

    def __init__(self, authorization: Any, identity: Any) -> None:
        self.authorization = authorization
        self.identity = identity

    @staticmethod
    def parse_bearer(header_value: str) -> str:
        """Accept one canonical Bearer credential and reject ambiguous input."""
        raw = str(header_value or "")
        if len(raw) > 8192:
            raise ValueError("authorization header is too large")
        scheme, separator, credential = raw.partition(" ")
        if not separator or scheme.lower() != "bearer":
            raise ValueError("a bearer credential is required")
        token = credential.strip()
        if not token or any(ch.isspace() for ch in token) or len(token) > 4096:
            raise ValueError("a bearer credential is required")
        return token

    def authenticate(self, header_value: str) -> tuple[Principal, Any]:
        """Return safe principal metadata and the existing in-process auth context."""
        token = self.parse_bearer(header_value)
        auth_context = self.authorization.context_from_secret(token)
        principal_id = str(
            getattr(auth_context, "credential_id", "")
            or getattr(auth_context, "user_id", "")
            or ""
        )
        tenant_id = str(getattr(auth_context, "org_id", "") or "")
        if not principal_id or not tenant_id:
            raise AuthenticationAdapterError()
        credential_id = str(getattr(auth_context, "credential_id", "") or "")
        session_id = str(getattr(auth_context, "session_id", "") or "")
        principal = Principal(
            principal_id=principal_id,
            tenant_id=tenant_id,
            subject_type="api_credential" if credential_id else "user",
            roles=frozenset(str(role) for role in getattr(auth_context, "roles", ())),
            permissions=frozenset(
                str(permission)
                for permission in getattr(auth_context, "permissions", ())
            ),
            authentication_method=str(
                getattr(auth_context, "auth_method", "") or
                ("api_credential" if credential_id else "session")
            )[:64],
            session_id=session_id,
            credential_id=credential_id,
        )
        return principal, auth_context

    def require(self, auth_context: Any, permission: str) -> None:
        """Delegate a permission decision to the existing authorization service."""
        self.authorization.require(auth_context, permission)

    def require_org(self, auth_context: Any, org_id: str) -> None:
        """Delegate organization ownership to the existing authorization service."""
        self.authorization.require_org(auth_context, org_id)

    def require_project(self, auth_context: Any, project_id: str) -> Any:
        """Delegate project ownership to the existing authorization service."""
        return self.authorization.require_project(auth_context, project_id)

    def login(
        self,
        identifier: str,
        password: str,
        *,
        source_ip: str = "",
        user_agent: str = "",
    ) -> LoginGrant:
        """Establish an existing password session and return its one-time bearer."""
        def mfa_required(user: Any, roles: tuple[str, ...]) -> bool:
            return bool(
                self.authorization.mfa_required_for(
                    SimpleNamespace(org_id=user.org_id, roles=roles)
                )
            )

        result = self.identity.login(
            identifier,
            password,
            ip=source_ip,
            actor="api.login",
            mfa_required=mfa_required,
        )
        user = result["user"]
        session = result["session"]
        roles = tuple(self.identity.user_roles(user.id))
        rbac_module = self._rbac_module()
        permissions = frozenset(rbac_module.permissions_for(roles))
        principal = Principal(
            principal_id=str(user.id),
            tenant_id=str(user.org_id),
            subject_type="user",
            roles=frozenset(roles),
            permissions=permissions,
            authentication_method=str(getattr(session, "auth_method", "password")),
            session_id=str(session.id),
        )
        return LoginGrant(
            token=str(result["secret"]),
            token_type="Bearer",
            principal=principal,
            session_id=str(session.id),
            expires_at=str(session.expires_at),
            mfa_required=bool(result.get("mfa_required", False)),
            mfa_status=str(getattr(session, "mfa_status", "none")),
        )

    @staticmethod
    def _rbac_module() -> Any:
        """Resolve the already-used RBAC module without creating a second policy."""
        try:
            import rbac
        except ImportError as exc:
            raise AuthenticationAdapterError() from exc
        return rbac

    def refresh(self, bearer_header: str) -> LoginGrant:
        """Rotate a valid user session through IdentityService."""
        token = self.parse_bearer(bearer_header)
        result = self.identity.session_refresh(token)
        session = result["session"]
        user = self.identity.user_get(session.user_id)
        roles = tuple(self.identity.user_roles(user.id))
        permissions = frozenset(self._rbac_module().permissions_for(roles))
        principal = Principal(
            principal_id=str(user.id),
            tenant_id=str(user.org_id),
            subject_type="user",
            roles=frozenset(roles),
            permissions=permissions,
            authentication_method=str(getattr(session, "auth_method", "password")),
            session_id=str(session.id),
        )
        return LoginGrant(
            token=str(result["secret"]),
            token_type="Bearer",
            principal=principal,
            session_id=str(session.id),
            expires_at=str(session.expires_at),
            mfa_required=getattr(session, "mfa_status", "none") == "pending",
            mfa_status=str(getattr(session, "mfa_status", "none")),
        )

    def logout(self, auth_context: Any) -> None:
        """Revoke the authenticated session; API credentials cannot log out users."""
        session_id = str(getattr(auth_context, "session_id", "") or "")
        if not session_id:
            raise AuthenticationAdapterError()
        self.identity.session_revoke_id(session_id, reason="api_logout")

    def principal_for_context(self, auth_context: Any) -> Principal:
        """Build a public-safe principal from a context already authenticated."""
        principal_id = str(
            getattr(auth_context, "credential_id", "")
            or getattr(auth_context, "user_id", "")
            or ""
        )
        tenant_id = str(getattr(auth_context, "org_id", "") or "")
        if not principal_id or not tenant_id:
            raise AuthenticationAdapterError()
        credential_id = str(getattr(auth_context, "credential_id", "") or "")
        return Principal(
            principal_id=principal_id,
            tenant_id=tenant_id,
            subject_type="api_credential" if credential_id else "user",
            roles=frozenset(str(role) for role in getattr(auth_context, "roles", ())),
            permissions=frozenset(
                str(permission)
                for permission in getattr(auth_context, "permissions", ())
            ),
            authentication_method=str(
                getattr(auth_context, "auth_method", "") or
                ("api_credential" if credential_id else "session")
            )[:64],
            session_id=str(getattr(auth_context, "session_id", "") or ""),
            credential_id=credential_id,
        )


__all__ = ["AuthenticationAdapter", "AuthenticationAdapterError", "LoginGrant"]
