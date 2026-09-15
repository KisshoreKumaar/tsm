"""Bearer-token authentication and permission guards.

Tokens are compared as SHA-256 digests with `hmac.compare_digest`; only digests are held in memory.
Every API route depends on exactly one guard (`require(...)` or `public()`), which the RBAC tests enforce.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from fastapi import Request

from app.core.config import IdentityConfig
from app.core.errors import Forbidden, Unauthorized
from app.core.permissions import AUTHENTICATED, PERMISSIONS, PUBLIC, ROLE_PERMISSIONS


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    permissions: frozenset[str]

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    def public(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role, "permissions": sorted(self.permissions)}


SYSTEM_PRINCIPAL = Principal(name="system", role="system", permissions=frozenset())


class Authenticator:
    def __init__(self, identities: Sequence[IdentityConfig]) -> None:
        self._identities = tuple(identities)

    def authenticate(self, header: str | None) -> Principal | None:
        if not header or len(header) > 1024:
            return None
        scheme, _, token = header.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            return None
        candidate = hashlib.sha256(token.encode("utf-8", errors="replace")).digest()
        match: IdentityConfig | None = None
        for identity in self._identities:  # compare against every identity to keep timing uniform
            if hmac.compare_digest(candidate, identity.token_sha256):
                match = identity
        if match is None:
            return None
        return Principal(name=match.name, role=match.role, permissions=ROLE_PERMISSIONS[match.role])


class RequirePermission:
    """FastAPI dependency: authenticates the caller and checks one permission."""

    def __init__(self, permission: str) -> None:
        if permission not in PERMISSIONS and permission != AUTHENTICATED:
            raise ValueError(f"Unknown permission: {permission}")
        self.permission = permission

    def __call__(self, request: Request) -> Principal:
        principal = request.app.state.ctx.authenticator.authenticate(request.headers.get("authorization"))
        if principal is None:
            raise Unauthorized("A valid bearer token is required")
        if self.permission != AUTHENTICATED and self.permission not in principal.permissions:
            raise Forbidden("Your role does not have permission for this action", details={"required": self.permission})
        request.state.principal = principal
        return principal


class PublicRoute:
    """Marks a route as intentionally unauthenticated."""

    permission = PUBLIC

    def __call__(self) -> None:
        return None


def require(permission: str) -> RequirePermission:
    return RequirePermission(permission)


def public() -> PublicRoute:
    return PublicRoute()
