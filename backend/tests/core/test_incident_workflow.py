from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from tests.support import auth, failures


def create_incident(client: TestClient, **overrides: Any) -> dict[str, Any]:
    response = client.post("/api/events/batch", json={"events": failures(**overrides)}, headers=auth("analyst"))
    [incident_id] = response.json()["incident_ids"]
    detail: dict[str, Any] = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
    return detail


def patch(client: TestClient, incident: dict[str, Any], **body: Any) -> Any:
    return client.patch(
        f"/api/incidents/{incident['id']}", json={"revision": incident["revision"], **body}, headers=auth("analyst")
    )


def test_detail_contains_evidence_and_explanations(client: TestClient) -> None:
    incident = create_incident(client)
    assert len(incident["events"]) == 5
    assert incident["detections"][0]["rule_id"] == "AUTH-001"
    assert incident["risk"]["factors"]
    assert {c["label"] for c in incident["analysis"]["claims"]} >= {"FACT", "INFERENCE", "UNKNOWN"}


def test_status_owner_and_revision(client: TestClient) -> None:
    incident = create_incident(client)
    response = patch(client, incident, status="INVESTIGATING", owner="analyst-user")
    assert response.status_code == 200
    updated = response.json()
    assert updated["status"] == "INVESTIGATING"
    assert updated["owner"] == "analyst-user"
    assert updated["revision"] == incident["revision"] + 1
    stale = patch(client, incident, note="late note")
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "stale_revision"


def test_closing_requires_a_note(client: TestClient) -> None:
    incident = create_incident(client)
    response = patch(client, incident, status="RESOLVED")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "note_required"


def test_false_positive_requires_category_and_known_entities(client: TestClient) -> None:
    incident = create_incident(client)
    missing = patch(client, incident, status="FALSE_POSITIVE", note="scanner")
    assert missing.json()["error"]["code"] == "category_required"
    unknown = patch(
        client,
        incident,
        status="FALSE_POSITIVE",
        note="scanner",
        closure_category="authorized_scanner",
        benign_entities=[{"type": "source_ip", "value": "10.9.9.9"}],
    )
    assert unknown.json()["error"]["code"] == "unknown_entity"
    closed = patch(
        client,
        incident,
        status="FALSE_POSITIVE",
        note="Authorised scanner",
        closure_category="authorized_scanner",
        benign_entities=[{"type": "source_ip", "value": "192.0.2.10"}],
    )
    assert closed.status_code == 200
    body = closed.json()
    assert body["closure_category"] == "authorized_scanner"
    assert body["closure_entities"] == [{"type": "source_ip", "value": "192.0.2.10"}]
    assert body["notes"][-1]["kind"] == "closure"


def test_reopen_clears_closure(client: TestClient) -> None:
    incident = create_incident(client)
    closed = patch(client, incident, status="FALSE_POSITIVE", note="test", closure_category="test_activity").json()
    reopened = patch(client, closed, status="OPEN", note="Not a test after all").json()
    assert reopened["status"] == "OPEN"
    assert reopened["closure_category"] is None and reopened["closed_at"] is None


def test_notes_bump_revision(client: TestClient) -> None:
    incident = create_incident(client)
    response = client.post(
        f"/api/incidents/{incident['id']}/notes", json={"text": "Called the user"}, headers=auth("analyst")
    )
    assert response.status_code == 201
    assert response.json()["revision"] == incident["revision"] + 1


def test_empty_update_is_rejected(client: TestClient) -> None:
    incident = create_incident(client)
    assert patch(client, incident).status_code == 422


def test_list_search_filters_and_pagination(client: TestClient) -> None:
    create_incident(client)
    create_incident(client, asset="db-server")
    listing = client.get("/api/incidents", params={"q": "db-server"}, headers=auth("viewer")).json()
    assert listing["total"] == 1 and listing["items"][0]["asset"] == "db-server"
    assert client.get("/api/incidents", params={"status": "RESOLVED"}, headers=auth("viewer")).json()["total"] == 0
    page = client.get("/api/incidents", params={"limit": 1, "sort": "risk"}, headers=auth("viewer")).json()
    assert page["total"] == 2 and len(page["items"]) == 1
    assert client.get("/api/incidents", params={"status": "BOGUS"}, headers=auth("viewer")).status_code == 422


def test_overview_metrics(client: TestClient) -> None:
    create_incident(client)
    overview = client.get("/api/overview", headers=auth("viewer")).json()
    assert overview["metrics"]["events_total"] == 5
    assert overview["incidents_by_status"] == {"OPEN": 1}
    assert overview["top_incidents"][0]["rules"] == ["AUTH-001"]


def test_rules_and_catalog_endpoints(client: TestClient) -> None:
    rules = client.get("/api/rules", headers=auth("viewer")).json()["rules"]
    assert {r["id"] for r in rules} == {
        "AUTH-001",
        "AUTH-002",
        "PROC-001",
        "NET-001",
        "FILE-001",
        "LOG-001",
        "ACCT-001",
        "INJ-001",
        "SOURCE-001",
        "SOURCE-002",
    }
    catalog = client.get("/api/attack/techniques", headers=auth("viewer")).json()
    assert "MITRE" in catalog["attribution"]
