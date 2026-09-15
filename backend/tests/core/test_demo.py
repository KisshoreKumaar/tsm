from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from app.core.context import AppContext
from app.core.timeutil import ManualClock, parse_iso
from tests.support import auth


def replay(client: TestClient, ctx: AppContext, clock: ManualClock, scenario: str) -> dict:  # type: ignore[type-arg]
    started = client.post("/api/demo/run", json={"scenario": scenario, "mode": "replay"}, headers=auth("analyst"))
    assert started.status_code == 201
    body = started.json()
    steps = len(body["steps"])
    for index in range(steps):
        if index:
            clock.advance(ctx.settings.replay_interval_seconds)
        assert ctx.jobs.run_pending(ctx, ignore_schedule=False) == 1
    return body  # type: ignore[no-any-return]


def test_scenario_catalog(client: TestClient) -> None:
    scenarios = client.get("/api/demo/scenarios", headers=auth("viewer")).json()["scenarios"]
    assert {s["id"] for s in scenarios} == {
        "attack-chain",
        "benign",
        "late-arrival",
        "indicator",
        "lateral-movement",
        "authorized-scanner",
        "ransomware-burst",
        "prompt-injection",
    }


def test_each_run_uses_a_unique_asset_suffix(client: TestClient) -> None:
    first = client.post("/api/demo/run", json={"scenario": "attack-chain"}, headers=auth("ingest")).json()
    second = client.post("/api/demo/run", json={"scenario": "attack-chain"}, headers=auth("ingest")).json()
    assert first["suffix"] != second["suffix"]
    assert first["incident_ids"] != second["incident_ids"]
    assert client.get("/api/incidents", headers=auth("viewer")).json()["total"] == 2


def test_unknown_scenario(client: TestClient) -> None:
    assert client.post("/api/demo/run", json={"scenario": "nope"}, headers=auth("analyst")).status_code == 404


def test_replay_releases_steps_on_a_timer(client: TestClient, ctx: AppContext, clock: ManualClock) -> None:
    started = client.post(
        "/api/demo/run", json={"scenario": "attack-chain", "mode": "replay"}, headers=auth("analyst")
    ).json()
    assert ctx.jobs.run_pending(ctx, ignore_schedule=False) == 1  # the first step is due immediately
    assert client.get("/api/incidents", headers=auth("viewer")).json()["items"][0]["rules"] == ["AUTH-001"]
    assert ctx.jobs.run_pending(ctx, ignore_schedule=False) == 0  # the next step is not due yet
    for _ in range(3):
        clock.advance(ctx.settings.replay_interval_seconds)
        assert ctx.jobs.run_pending(ctx, ignore_schedule=False) == 1
    [incident] = client.get("/api/incidents", headers=auth("viewer")).json()["items"]
    assert incident["rules"] == ["AUTH-001", "AUTH-002", "NET-001", "PROC-001"]
    run = client.get(f"/api/demo/runs/{started['run_id']}", headers=auth("viewer")).json()
    assert run["status"] == "COMPLETED" and run["released"] == 4
    latest = max(parse_iso(e["timestamp"]) for e in client.get("/api/events", headers=auth("viewer")).json()["items"])
    assert latest <= clock.now()


def test_late_arrival_replay_matches_ordered_replay(client: TestClient, ctx: AppContext, clock: ManualClock) -> None:
    replay(client, ctx, clock, "late-arrival")
    [incident] = client.get("/api/incidents", headers=auth("viewer")).json()["items"]
    assert incident["rules"] == ["AUTH-001", "AUTH-002", "NET-001", "PROC-001"]
    assert incident["event_count"] == 19
    events = client.get("/api/events", params={"limit": 200}, headers=auth("viewer")).json()["items"]
    assert all(parse_iso(e["timestamp"]) <= clock.now() + timedelta(seconds=1) for e in events)
