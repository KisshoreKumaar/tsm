"""F4 watchlist: predictions appear and flip to OBSERVED during replay, raise risk, expire, and are audited."""

from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from app.core.context import AppContext
from app.core.timeutil import ManualClock
from tests.support import auth, run_scenario


def release_next_step(ctx: AppContext, clock: ManualClock) -> None:
    clock.advance(10)
    assert ctx.jobs.run_pending(ctx, lanes=("default",), max_jobs=1) == 1


def open_incident(ctx: AppContext) -> str:
    with ctx.db.read() as session:
        [row] = session.all("SELECT id FROM incidents WHERE status != 'MERGED'")
    return str(row["id"])


def predictions(client: TestClient, incident_id: str) -> dict[str, dict[str, Any]]:
    response = client.get(f"/api/incidents/{incident_id}/predictions", headers=auth("viewer"))
    assert response.status_code == 200, response.text
    return {p["technique"]["id"]: p for p in response.json()["predictions"]}


def audit_bodies(ctx: AppContext, action: str) -> list[dict[str, Any]]:
    with ctx.db.read() as session:
        rows = session.all("SELECT body FROM audit_log WHERE action = ? ORDER BY seq", (action,))
    return [json.loads(row["body"]) for row in rows]


def test_attack_chain_replay_predicts_execution_then_observes_it(
    client: TestClient, ctx: AppContext, clock: ManualClock
) -> None:
    run_scenario(ctx, "attack-chain", mode="replay")
    release_next_step(ctx, clock)  # password guessing
    incident_id = open_incident(ctx)
    assert predictions(client, incident_id)["T1078"]["status"] == "WATCHING"

    release_next_step(ctx, clock)  # successful login
    after_login = predictions(client, incident_id)
    assert after_login["T1078"]["status"] == "OBSERVED"
    assert after_login["T1059.001"]["status"] == "WATCHING"
    assert after_login["T1059.001"]["label"] == "HYPOTHESIS"
    detail = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
    assert next(f for f in detail["risk"]["factors"] if f["name"] == "observed_prediction")["points"] > 0

    release_next_step(ctx, clock)  # encoded PowerShell
    execution = predictions(client, incident_id)["T1059.001"]
    detail = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
    powershell = {e["id"] for e in detail["events"] if e["kind"] == "process_start"}
    assert execution["status"] == "OBSERVED" and set(execution["observed_event_ids"]) == powershell
    observed = [body["technique_id"] for body in audit_bodies(ctx, "prediction.observed")]
    assert observed == ["T1078", "T1059.001"]
    assert ctx.audit.verify(ctx.db)["valid"]


def test_unobserved_predictions_expire_after_their_horizon(
    client: TestClient, ctx: AppContext, clock: ManualClock
) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    assert predictions(client, incident_id)["T1087"]["status"] == "WATCHING"
    clock.advance(hours=3)
    ctx.jobs.run_pending(ctx, lanes=("default",))
    after = predictions(client, incident_id)
    assert after["T1087"]["status"] == "EXPIRED"
    assert after["T1059.001"]["status"] == "OBSERVED"
    assert "T1087" in audit_bodies(ctx, "prediction.expired")[-1]["technique_ids"]


def test_late_arrival_yields_the_same_predictions(client: TestClient, ctx: AppContext) -> None:
    [first] = run_scenario(ctx, "attack-chain")["incident_ids"]
    [second] = run_scenario(ctx, "late-arrival")["incident_ids"]

    def summary(incident_id: str) -> list[tuple[str, str, int, int]]:
        return sorted(
            (t, p["status"], p["score"], len(p["observed_event_ids"]))
            for t, p in predictions(client, incident_id).items()
        )

    assert summary(first) == summary(second)


def test_watchlist_hit_rate_and_model_endpoints(client: TestClient, ctx: AppContext) -> None:
    run_scenario(ctx, "attack-chain")
    observed = client.get("/api/predictions", params={"status": "OBSERVED"}, headers=auth("viewer")).json()
    assert {p["technique"]["id"] for p in observed["items"]} == {"T1078", "T1059.001", "T1046"}
    assert all(p["label"] == "HYPOTHESIS" and p["incident_title"] for p in observed["items"])
    rate = client.get("/api/metrics/prediction-hit-rate", headers=auth("viewer")).json()
    assert rate["observed"] == 3 and rate["total"] == 7 and rate["hit_rate"] == round(3 / 7, 4)
    assert "not an accuracy guarantee" in rate["label"]
    model = client.get("/api/attack/transitions", headers=auth("viewer")).json()
    assert model["transitions"] and "MITRE" in model["attribution"]
    assert client.get("/api/predictions", headers=auth("ingest")).status_code == 403
    assert client.get("/api/incidents/nope/predictions", headers=auth("viewer")).status_code == 404


def test_agent_can_read_predictions(ctx: AppContext) -> None:
    registry = ctx.service("ai_tools")
    assert {"get_predictions", "list_watchlist"} <= {spec.name for spec in registry.tools(ctx.features.ids)}
    assert "f4" in registry.features_with_read_tools()
