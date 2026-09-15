from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.core.context import AppContext
from app.main import create_app
from tests.support import auth, failures, make_settings, raw_event


def event_count(ctx: AppContext) -> int:
    with ctx.db.read() as session:
        return int(session.scalar("SELECT count(*) FROM events"))


def test_single_event_and_idempotent_retry(client: TestClient, ctx: AppContext) -> None:
    event = raw_event(event_id="retry-1")
    first = client.post("/api/events", json=event, headers=auth("ingest"))
    assert first.status_code == 201
    body = first.json()
    assert set(body) == {"stored", "duplicates", "results", "incident_ids"}
    assert set(body["results"][0]) == {"id", "duplicate", "source", "event_id"}  # identifiers only
    retry = client.post("/api/events", json=dict(reversed(list(event.items()))), headers=auth("ingest"))
    assert retry.status_code == 200
    assert retry.json()["results"][0] == {**body["results"][0], "duplicate": True}
    assert event_count(ctx) == 1


def test_same_event_id_with_different_content_is_rejected(client: TestClient, ctx: AppContext) -> None:
    assert client.post("/api/events", json=raw_event(event_id="dup"), headers=auth("ingest")).status_code == 201
    changed = raw_event(event_id="dup", user="mallory")
    response = client.post("/api/events", json=changed, headers=auth("ingest"))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "event_conflict"
    assert event_count(ctx) == 1


def test_batch_is_atomic_on_validation_error(client: TestClient, ctx: AppContext) -> None:
    batch = [raw_event(), raw_event(), raw_event(kind="not_a_kind")]
    response = client.post("/api/events/batch", json={"events": batch}, headers=auth("analyst"))
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["index"] == 2
    assert event_count(ctx) == 0


def test_batch_is_atomic_on_duplicate_conflict(client: TestClient, ctx: AppContext) -> None:
    client.post("/api/events", json=raw_event(event_id="exists"), headers=auth("analyst"))
    batch = [raw_event(), raw_event(event_id="exists", details="changed")]
    assert client.post("/api/events/batch", json={"events": batch}, headers=auth("analyst")).status_code == 409
    assert event_count(ctx) == 1


def test_duplicates_within_one_batch(client: TestClient, ctx: AppContext) -> None:
    event = raw_event(event_id="twice")
    response = client.post("/api/events/batch", json={"events": [event, event]}, headers=auth("analyst"))
    assert response.status_code == 201
    assert [r["duplicate"] for r in response.json()["results"]] == [False, True]
    assert event_count(ctx) == 1


def test_future_timestamps_beyond_clock_skew_are_rejected(client: TestClient, ctx: AppContext) -> None:
    # The test clock is 2026-01-15T09:00:00Z with a 120-second tolerance.
    assert (
        client.post("/api/events", json=raw_event(timestamp="2026-01-15T09:01:59Z"), headers=auth("ingest")).status_code
        == 201
    )
    late = client.post("/api/events", json=raw_event(timestamp="2026-01-15T09:02:01Z"), headers=auth("ingest"))
    assert late.status_code == 422
    assert late.json()["error"]["details"][0]["errors"][0]["loc"] == ["timestamp"]


def test_batch_size_limit(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path, batch_max_events=3))
    with TestClient(app) as client:
        response = client.post(
            "/api/events/batch", json={"events": [raw_event() for _ in range(4)]}, headers=auth("analyst")
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "batch_too_large"


def test_raw_json_and_entities_are_stored(client: TestClient) -> None:
    event = raw_event(event_id="raw-1", asset="HOST-RAW", details="Original Casing")
    stored = client.post("/api/events", json=event, headers=auth("analyst")).json()["results"][0]["id"]
    detail = client.get(f"/api/events/{stored}", headers=auth("viewer")).json()
    assert detail["raw"] == event
    assert detail["asset"] == "host-raw"
    assert {"type": "source_ip", "value": "192.0.2.10"} in detail["entities"]


def test_ingestion_creates_incident_and_audit(client: TestClient, ctx: AppContext) -> None:
    response = client.post("/api/events/batch", json={"events": failures()}, headers=auth("analyst"))
    assert response.status_code == 201
    [incident_id] = response.json()["incident_ids"]
    incident = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
    assert incident["rules"] == ["AUTH-001"]
    assert incident["status"] == "OPEN"
    actions = [item["action"] for item in ctx.audit.page(ctx.db, limit=50)["items"]]
    assert "events.ingested" in actions and "incident.created" in actions
    assert ctx.audit.verify(ctx.db)["valid"]


def test_events_explorer_filters(client: TestClient) -> None:
    client.post(
        "/api/events/batch",
        json={"events": [*failures(), raw_event(kind="log_cleared", asset="host-2", details="cleared by admin")]},
        headers=auth("analyst"),
    )
    assert client.get("/api/events", params={"kind": "log_cleared"}, headers=auth("viewer")).json()["total"] == 1
    assert client.get("/api/events", params={"q": "cleared by"}, headers=auth("viewer")).json()["total"] == 1
    assert client.get("/api/events", params={"asset": "HOST-1"}, headers=auth("viewer")).json()["total"] == 5
    listed = client.get("/api/events", params={"asset": "host-1", "limit": 2}, headers=auth("viewer")).json()
    assert len(listed["items"]) == 2 and listed["items"][0]["incident_ids"]
    assert client.get("/api/event-kinds", headers=auth("viewer")).json()["kinds"]
