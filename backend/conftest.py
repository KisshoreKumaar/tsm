"""Shared pytest fixtures. Tests never open network connections (enforced below)."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.context import AppContext
from app.core.timeutil import ManualClock
from app.main import create_app
from tests.support import make_settings


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if self.family == socket.AF_UNIX:
            return real_connect(self, address)
        raise RuntimeError(f"Tests must not open network connections (attempted {address!r})")

    def guarded_create_connection(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Tests must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)


@pytest.fixture
def clock() -> ManualClock:
    return ManualClock()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "aegis.db"


@pytest.fixture
def app(tmp_path: Path, clock: ManualClock) -> FastAPI:
    return create_app(make_settings(tmp_path), clock=clock)


@pytest.fixture
def ctx(app: FastAPI) -> AppContext:
    context: AppContext = app.state.ctx
    return context


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
