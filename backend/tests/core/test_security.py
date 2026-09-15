from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.features.core import FEATURE as CORE
from app.main import create_app
from tests.support import EXAMPLE_FEATURE, auth, make_settings


def build_client(tmp_path: Path, **overrides: object) -> TestClient:
    app = create_app(make_settings(tmp_path, **overrides), features=(CORE, EXAMPLE_FEATURE))
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def api(tmp_path: Path) -> Iterator[TestClient]:
    with build_client(tmp_path) as client:
        yield client


def test_security_headers(api: TestClient) -> None:
    response = api.get("/api/healthz")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("header", [None, "Basic abc", "Bearer ", "Bearer wrong-token-" + "y" * 40])
def test_invalid_credentials_get_401(api: TestClient, header: str | None) -> None:
    headers = {"Authorization": header} if header is not None else {}
    response = api.get("/api/me", headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_missing_permission_gets_403(api: TestClient) -> None:
    response = api.post("/api/example/echo", headers=auth("viewer"), json={"message": "hi"})
    assert response.status_code == 403
    assert response.json()["error"]["details"] == {"required": "investigate"}


def test_valid_request_succeeds(api: TestClient) -> None:
    response = api.post("/api/example/echo", headers=auth("analyst"), json={"message": "hi", "count": 2})
    assert response.status_code == 200
    assert response.json() == {"message": "hi", "count": 2}


def test_duplicate_json_keys_rejected(api: TestClient) -> None:
    response = api.post(
        "/api/example/echo",
        headers={**auth("analyst"), "Content-Type": "application/json"},
        content=b'{"message": "a", "message": "b"}',
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_json"


def test_non_finite_numbers_rejected(api: TestClient) -> None:
    response = api.post(
        "/api/example/echo",
        headers={**auth("analyst"), "Content-Type": "application/json"},
        content=b'{"message": "a", "count": NaN}',
    )
    assert response.status_code == 400


def test_unknown_fields_rejected_without_echoing_values(api: TestClient) -> None:
    response = api.post(
        "/api/example/echo", headers=auth("analyst"), json={"message": "a", "extra": "SENSITIVE-VALUE-123"}
    )
    assert response.status_code == 422
    assert "SENSITIVE-VALUE-123" not in response.text


def test_strict_integer_types(api: TestClient) -> None:
    response = api.post("/api/example/echo", headers=auth("analyst"), json={"message": "a", "count": "2"})
    assert response.status_code == 422


def test_wrong_content_type_rejected(api: TestClient) -> None:
    response = api.post(
        "/api/example/echo", headers={**auth("analyst"), "Content-Type": "text/plain"}, content=b"message=a"
    )
    assert response.status_code == 415


def test_body_limit(tmp_path: Path) -> None:
    with build_client(tmp_path, max_body_bytes=200) as client:
        response = client.post(
            "/api/example/echo", headers=auth("analyst"), json={"message": "x" * 190, "pad": "y" * 50}
        )
        assert response.status_code == 413


def test_rate_limit(tmp_path: Path) -> None:
    with build_client(tmp_path, rate_limit_per_minute=10) as client:
        statuses = [client.get("/api/me", headers=auth("viewer")).status_code for _ in range(11)]
        assert statuses[:10] == [200] * 10
        assert statuses[10] == 429
        assert client.get("/api/healthz").status_code == 200  # health checks are exempt


def test_internal_errors_hide_details(api: TestClient) -> None:
    response = api.get("/api/example/boom", headers=auth("viewer"))
    assert response.status_code == 500
    assert response.json() == {"error": {"code": "internal_error", "message": "Internal server error"}}
    assert "passwd" not in response.text


def test_unknown_route_is_json_404(api: TestClient) -> None:
    response = api.get("/api/does-not-exist", headers=auth("viewer"))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
