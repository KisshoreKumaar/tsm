"""X1: provider settings with a write-only, encrypted API key field."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.timeutil import ManualClock
from app.main import create_app
from tests.core.test_rbac_matrix import api_routes
from tests.support import auth, make_settings

API_KEY = "gsk_TESTKEY_0123456789abcdefXYZ"
SECRET_KEY = "server-secret-key-" + "z" * 30
GROQ = {
    "name": "Groq",
    "preset": "groq",
    "api_type": "openai",
    "base_url": "https://api.groq.com/openai/v1",
    "model": "llama-3.1-8b-instant",
    "context_tokens": 8192,
    "max_output_tokens": 600,
    "timeout_seconds": 30,
}


@pytest.fixture
def secure_app(tmp_path: Path) -> FastAPI:
    return create_app(make_settings(tmp_path, secret_key=SECRET_KEY), clock=ManualClock())


@pytest.fixture
def admin(secure_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(secure_app, raise_server_exceptions=False) as client:
        yield client


def create(client: TestClient, **overrides: Any) -> dict[str, Any]:
    response = client.post("/api/llm/providers", json={**GROQ, **overrides}, headers=auth("admin"))
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def test_key_is_write_only_and_encrypted(admin: TestClient, secure_app: FastAPI) -> None:
    created = create(admin, api_key=API_KEY)
    assert created["key_set"] is True and created["key_hint"] == "…fXYZ"
    assert API_KEY not in json.dumps(created)
    listing = admin.get("/api/llm/providers", headers=auth("admin"))
    assert API_KEY not in listing.text and listing.json()["secret_key_configured"] is True
    ctx = secure_app.state.ctx
    with ctx.db.read() as session:
        stored = session.scalar("SELECT key_ciphertext FROM llm_providers WHERE id = ?", (created["id"],))
        audit_bodies = " ".join(r["body"] for r in session.all("SELECT body FROM audit_log"))
    assert stored and API_KEY not in stored and "…fXYZ" not in stored
    assert API_KEY not in audit_bodies


def test_key_never_appears_in_any_get_response(admin: TestClient, secure_app: FastAPI) -> None:
    created = create(admin, api_key=API_KEY)
    checked = 0
    for info in api_routes(secure_app):
        if info.method != "GET" or info.name.endswith("_stream"):
            continue
        path = re.sub(r"\{provider_id\}", created["id"], info.path)
        path = re.sub(r"\{[^}]+\}", "00000000-0000-4000-8000-000000000000", path)
        response = admin.get(path, headers=auth("admin"))
        assert API_KEY not in response.text, path
        assert API_KEY[:-4] not in response.text, path
        checked += 1
    assert checked > 20


def test_only_admins_manage_providers(admin: TestClient) -> None:
    for role in ("viewer", "analyst", "approver", "detection_engineer"):
        assert admin.get("/api/llm/providers", headers=auth(role)).status_code == 403
        assert admin.post("/api/llm/providers", json=GROQ, headers=auth(role)).status_code == 403


def test_keys_require_a_server_secret(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path), clock=ManualClock())
    with TestClient(app) as client:
        response = client.post("/api/llm/providers", json={**GROQ, "api_key": API_KEY}, headers=auth("admin"))
        assert response.status_code == 409 and response.json()["error"]["code"] == "secret_key_missing"
        assert API_KEY not in response.text
        assert client.get("/api/llm/providers", headers=auth("admin")).json()["secret_key_configured"] is False


@pytest.mark.parametrize(
    "base_url",
    [
        "http://169.254.169.254/latest",
        "file:///etc/passwd",
        "http://user:pw@api.groq.com",
        "http://metadata.google.internal",
    ],
)
def test_unsafe_base_urls_are_rejected(admin: TestClient, base_url: str) -> None:
    response = admin.post("/api/llm/providers", json={**GROQ, "base_url": base_url}, headers=auth("admin"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_base_url"


def test_validation_errors_do_not_echo_the_key(admin: TestClient) -> None:
    response = admin.post("/api/llm/providers", json={**GROQ, "api_key": API_KEY + " spaces"}, headers=auth("admin"))
    assert response.status_code == 422 and API_KEY not in response.text


def test_set_rotate_and_remove_key_are_audited(admin: TestClient, secure_app: FastAPI) -> None:
    provider = create(admin)
    assert provider["key_set"] is False
    for _ in range(2):
        response = admin.put(
            f"/api/llm/providers/{provider['id']}/key", json={"api_key": API_KEY}, headers=auth("admin")
        )
        assert response.status_code == 200 and response.json()["key_set"] is True
    removed = admin.delete(f"/api/llm/providers/{provider['id']}/key", headers=auth("admin"))
    assert removed.json()["key_set"] is False
    ctx = secure_app.state.ctx
    records = [i for i in ctx.audit.page(ctx.db, limit=50)["items"] if i["action"].startswith("llm.provider_key")]
    assert [(r["action"], r["body"].get("rotated")) for r in reversed(records)] == [
        ("llm.provider_key_set", False),
        ("llm.provider_key_set", True),
        ("llm.provider_key_removed", None),
    ]


def test_changed_server_secret_fails_safely(tmp_path: Path) -> None:
    first = create_app(make_settings(tmp_path, secret_key=SECRET_KEY), clock=ManualClock())
    with TestClient(first) as client:
        provider = create(client, api_key=API_KEY, make_active=True)
    second = create_app(make_settings(tmp_path, secret_key="another-secret-" + "q" * 30), clock=ManualClock())
    with TestClient(second) as client:
        assert client.get("/api/ai/status", headers=auth("viewer")).json()["enabled"] is False
        tested = client.post(f"/api/llm/providers/{provider['id']}/test", json={}, headers=auth("admin")).json()
        assert tested["ok"] is False and "could not be decrypted" in tested["error"]
        assert API_KEY not in json.dumps(tested)


def test_connection_test_reports_json_mode_and_records_result(admin: TestClient, secure_app: FastAPI) -> None:
    provider = create(admin, api_key=API_KEY)
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        chunks = [
            'data: {"choices":[{"delta":{"content":"{\\"ok\\": true, \\"word\\": \\"ready\\"}"}}]}',
            "data: [DONE]",
        ]
        return httpx.Response(200, content="\n\n".join(chunks).encode())

    secure_app.state.ctx.service("ai").transport = httpx.MockTransport(handler)
    result = admin.post(f"/api/llm/providers/{provider['id']}/test", json={}, headers=auth("admin")).json()
    assert result["ok"] is True and result["json_ok"] is True
    assert seen["auth"] == f"Bearer {API_KEY}"
    listed = admin.get("/api/llm/providers", headers=auth("admin")).json()["providers"][0]
    assert listed["last_test"]["ok"] is True
    actions = [i["action"] for i in secure_app.state.ctx.audit.page(secure_app.state.ctx.db, limit=20)["items"]]
    assert "llm.provider_tested" in actions


def test_active_provider_and_deterministic_mode(admin: TestClient) -> None:
    first = create(admin, name="First")
    second = create(admin, name="Second")
    body = admin.post("/api/llm/active", json={"provider_id": second["id"]}, headers=auth("admin")).json()
    assert body["active"]["id"] == second["id"]
    assert admin.get("/api/ai/status", headers=auth("viewer")).json()["active_provider"]["name"] == "Second"
    body = admin.post("/api/llm/active", json={"provider_id": None}, headers=auth("admin")).json()
    assert body["deterministic_only"] is True and body["active"] is None
    status = admin.get("/api/ai/status", headers=auth("viewer")).json()
    assert status["enabled"] is False and status["mode"] == "deterministic"
    assert (
        admin.patch(f"/api/llm/providers/{first['id']}", json={"enabled": False}, headers=auth("admin")).status_code
        == 200
    )
    assert admin.post("/api/llm/active", json={"provider_id": first["id"]}, headers=auth("admin")).status_code == 409


def test_ai_status_reports_detector_and_queue(admin: TestClient) -> None:
    status = admin.get("/api/ai/status", headers=auth("viewer")).json()
    for key in ("enabled", "measured_tokens_per_second", "queue", "cache_hit_rate", "grounding_rate", "fallback_count"):
        assert key in status
    assert status["injection_detector_pass_rate"] == 1.0
    presets = admin.get("/api/llm/presets", headers=auth("admin")).json()["presets"]
    assert {p["id"] for p in presets} == {"ollama-ec2", "groq", "gemini", "custom"}
