"""RBAC matrix for every API route of the real application (grows automatically with new features)."""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.core.permissions import AUTHENTICATED, PUBLIC, ROLE_PERMISSIONS, ROLES
from tests.support import auth

PLACEHOLDER_ID = "00000000-0000-4000-8000-000000000000"
BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class RouteInfo:
    method: str
    path: str
    guards: tuple[str, ...]
    name: str

    @property
    def permission(self) -> str:
        return self.guards[0] if len(self.guards) == 1 else ""


def _guards(dependencies: Sequence[Any]) -> list[str]:
    found: list[str] = []
    for dependency in dependencies:
        call = getattr(dependency, "call", None) or getattr(dependency, "dependency", None)
        permission = getattr(call, "permission", None)
        if permission:
            found.append(permission)
        found.extend(_guards(getattr(dependency, "dependencies", ())))
    return found


def _walk(routes: Sequence[Any], prefix: str = "", inherited: Sequence[Any] = ()) -> Iterator[RouteInfo]:
    """Yield API routes, descending into lazily included routers (FastAPI >= 0.14x) by duck typing."""
    for route in routes:
        included = getattr(route, "original_router", None)
        context = getattr(route, "include_context", None)
        if included is not None and context is not None:
            yield from _walk(
                included.routes,
                prefix + getattr(context, "prefix", ""),
                [*inherited, *getattr(context, "dependencies", [])],
            )
        elif isinstance(route, APIRoute):
            guards = tuple(_guards(inherited) + _guards(route.dependant.dependencies))
            for method in sorted(route.methods):
                yield RouteInfo(method, prefix + route.path, guards, route.name)


def api_routes(app: FastAPI) -> list[RouteInfo]:
    return [info for info in _walk(app.router.routes) if info.path.startswith("/api/")]


def fill(path: str) -> str:
    return re.sub(r"\{[^}]+\}", PLACEHOLDER_ID, path)


def test_route_discovery_finds_core_routes(app: FastAPI) -> None:
    paths = {info.path for info in api_routes(app)}
    assert {"/api/healthz", "/api/me", "/api/audit/verify", "/api/jobs/{job_id}", "/api/stream"} <= paths


def test_every_api_route_declares_exactly_one_guard(app: FastAPI) -> None:
    offenders = [(info.method, info.path, info.guards) for info in api_routes(app) if len(info.guards) != 1]
    assert offenders == []


def test_only_health_is_public(app: FastAPI) -> None:
    assert [info.path for info in api_routes(app) if info.permission == PUBLIC] == ["/api/healthz"]


def test_missing_token_is_401_on_every_protected_route(app: FastAPI, client: TestClient) -> None:
    checked = 0
    for info in api_routes(app):
        if info.permission == PUBLIC:
            continue
        kwargs = {"json": {}} if info.method in BODY_METHODS else {}
        response = client.request(info.method, fill(info.path), **kwargs)
        assert response.status_code == 401, (info.method, info.path, response.status_code)
        checked += 1
    assert checked > 0


@pytest.mark.parametrize("role", ROLES)
def test_role_matrix(app: FastAPI, client: TestClient, role: str) -> None:
    checked = 0
    for info in api_routes(app):
        if info.permission == PUBLIC:
            continue
        allowed = info.permission == AUTHENTICATED or info.permission in ROLE_PERMISSIONS[role]
        if allowed and info.name.endswith("_stream"):
            continue  # streaming responses never finish; denial is still checked for other roles
        kwargs = {"json": {}} if info.method in BODY_METHODS else {}
        response = client.request(info.method, fill(info.path), headers=auth(role), **kwargs)
        if allowed:
            assert response.status_code not in (401, 403), (role, info.method, info.path, response.status_code)
        else:
            assert response.status_code == 403, (role, info.method, info.path, response.status_code)
        checked += 1
    assert checked > 0
