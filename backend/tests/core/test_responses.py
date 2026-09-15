from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.context import AppContext
from app.core.timeutil import ManualClock
from app.main import create_app
from tests.support import auth, failures, make_settings, raw_event


def create_incident(client: TestClient) -> dict[str, Any]:
    [incident_id] = client.post("/api/events/batch", json={"events": failures()}, headers=auth("analyst")).json()[
        "incident_ids"
    ]
    detail: dict[str, Any] = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
    return detail


def request(
    client: TestClient, incident: dict[str, Any], playbook: str = "isolate_endpoint", role: str = "analyst"
) -> Any:
    return client.post(
        "/api/responses",
        json={
            "incident_id": incident["id"],
            "playbook": playbook,
            "rationale": "Contain the host",
            "revision": incident["revision"],
        },
        headers=auth(role),
    )


def approve(client: TestClient, response_id: str, role: str = "approver", phrase: str = "APPROVE SIMULATION") -> Any:
    return client.post(f"/api/responses/{response_id}/approve", json={"confirmation": phrase}, headers=auth(role))


def execute(client: TestClient, response_id: str, role: str = "approver") -> Any:
    return client.post(f"/api/responses/{response_id}/execute", json={}, headers=auth(role))


def test_full_isolation_flow(client: TestClient, ctx: AppContext) -> None:
    incident = create_incident(client)
    requested = request(client, incident)
    assert requested.status_code == 201
    response_id = requested.json()["id"]
    assert requested.json()["status"] == "PENDING"
    wrong = approve(client, response_id, phrase="yes")
    assert wrong.status_code == 422 and wrong.json()["error"]["code"] == "confirmation_required"
    approved = approve(client, response_id)
    assert approved.status_code == 200 and approved.json()["status"] == "APPROVED"
    executed = execute(client, response_id)
    assert executed.status_code == 200
    result = executed.json()["result"]
    assert result == {
        "simulated": True,
        "note": "Virtual endpoint registry only. No real endpoint was changed or contacted.",
        "before": "CONNECTED",
        "after": "ISOLATED",
        "expected": "ISOLATED",
        "verified": True,
    }
    assert execute(client, response_id).status_code == 409  # cannot repeat
    endpoints = client.get("/api/endpoints", headers=auth("viewer")).json()["items"]
    assert endpoints == [
        {
            "asset": "host-1",
            "state": "ISOLATED",
            "updated_at": endpoints[0]["updated_at"],
            "updated_by": "approver-user",
        }
    ]
    actions = [i["action"] for i in ctx.audit.page(ctx.db, limit=100)["items"]]
    assert {"response.requested", "response.approved", "response.executed"} <= set(actions)


def test_collect_evidence_manifest(client: TestClient) -> None:
    incident = create_incident(client)
    response_id = request(client, incident, playbook="collect_evidence").json()["id"]
    approve(client, response_id)
    result = execute(client, response_id).json()["result"]
    assert result["verified"] is True
    assert len(result["manifest"]) == 5
    assert all(len(item["sha256"]) == 64 for item in result["manifest"])


def test_incident_change_cancels_approved_request(client: TestClient) -> None:
    incident = create_incident(client)
    response_id = request(client, incident).json()["id"]
    approve(client, response_id)
    client.post(f"/api/incidents/{incident['id']}/notes", json={"text": "new info"}, headers=auth("analyst"))
    assert client.get(f"/api/responses/{response_id}", headers=auth("viewer")).json()["status"] == "CANCELLED"
    assert execute(client, response_id).status_code == 409


def test_new_evidence_cancels_pending_request(client: TestClient) -> None:
    incident = create_incident(client)
    response_id = request(client, incident).json()["id"]
    client.post("/api/events", json=raw_event(timestamp="2026-01-15T08:01:00Z"), headers=auth("analyst"))
    assert client.get(f"/api/responses/{response_id}", headers=auth("viewer")).json()["status"] == "CANCELLED"


def test_approval_expires_after_fifteen_minutes(client: TestClient, clock: ManualClock) -> None:
    incident = create_incident(client)
    response_id = request(client, incident).json()["id"]
    approve(client, response_id)
    clock.advance(minutes=16)
    expired = execute(client, response_id)
    assert expired.status_code == 409 and expired.json()["error"]["code"] == "approval_expired"
    assert client.get(f"/api/responses/{response_id}", headers=auth("viewer")).json()["status"] == "EXPIRED"


def test_reject_requires_reason_and_final_states_are_immutable(client: TestClient) -> None:
    incident = create_incident(client)
    response_id = request(client, incident).json()["id"]
    assert (
        client.post(f"/api/responses/{response_id}/reject", json={"reason": ""}, headers=auth("approver")).status_code
        == 422
    )
    rejected = client.post(
        f"/api/responses/{response_id}/reject", json={"reason": "Not needed"}, headers=auth("approver")
    )
    assert rejected.json()["status"] == "REJECTED"
    assert approve(client, response_id).status_code == 409


def test_request_validation(client: TestClient) -> None:
    incident = create_incident(client)
    stale = client.post(
        "/api/responses",
        json={"incident_id": incident["id"], "playbook": "isolate_endpoint", "rationale": "x" * 5, "revision": 99},
        headers=auth("analyst"),
    )
    assert stale.status_code == 409
    assert request(client, incident).status_code == 201
    assert request(client, incident).status_code == 409  # duplicate open request
    bogus = client.post(
        "/api/responses",
        json={
            "incident_id": incident["id"],
            "playbook": "wipe_disk",
            "rationale": "no",
            "revision": incident["revision"],
        },
        headers=auth("analyst"),
    )
    assert bogus.status_code == 422


def test_closed_incident_cannot_get_responses(client: TestClient) -> None:
    incident = create_incident(client)
    closed = client.patch(
        f"/api/incidents/{incident['id']}",
        json={"revision": incident["revision"], "status": "RESOLVED", "note": "done"},
        headers=auth("analyst"),
    ).json()
    assert request(client, closed).status_code == 409


@pytest.fixture
def two_person(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(make_settings(tmp_path, two_person=True), clock=ManualClock())
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def test_two_person_rule_blocks_requester_from_approving_or_executing(two_person: TestClient) -> None:
    incident = create_incident(two_person)
    response_id = request(two_person, incident, role="admin").json()["id"]
    blocked = approve(two_person, response_id, role="admin")
    assert blocked.status_code == 403 and blocked.json()["error"]["code"] == "two_person_rule"
    assert approve(two_person, response_id, role="approver").status_code == 200
    assert execute(two_person, response_id, role="admin").status_code == 403
    assert execute(two_person, response_id, role="approver").status_code == 200
