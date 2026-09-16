"""A5: false-positive verdicts lead to simulated, human-approved, reversible tuning that keeps true positives."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app.core.context import AppContext
from app.core.timeutil import ManualClock
from tests.support import auth, run_scenario

SCANNER_IP = "10.20.0.250"


def close_false_positive(client: TestClient, ctx: AppContext, incident_id: str, **extra: Any) -> None:
    detail = ctx.service("incidents").get(incident_id)
    body = {
        "revision": detail["revision"],
        "status": "FALSE_POSITIVE",
        "note": "Authorised weekly vulnerability scan",
        "closure_category": "authorized_scanner",
        **extra,
    }
    response = client.patch(f"/api/incidents/{incident_id}", json=body, headers=auth("analyst"))
    assert response.status_code == 200, response.text


def scanner_false_positives(client: TestClient, ctx: AppContext, count: int = 3) -> list[str]:
    incident_ids = []
    for _ in range(count):
        [incident_id] = run_scenario(ctx, "authorized-scanner")["incident_ids"]
        close_false_positive(client, ctx, incident_id)
        incident_ids.append(incident_id)
    ctx.jobs.run_pending(ctx)  # the false-positive verdict enqueues deterministic generation
    return incident_ids


def suggestions(client: TestClient, rule_id: str, status: str = "PROPOSED") -> list[dict[str, Any]]:
    items = client.get("/api/tuning/suggestions", params={"status": status}, headers=auth("analyst")).json()["items"]
    return [item for item in items if item["rule_id"] == rule_id]


def suppressed(client: TestClient, rule_id: str = "NET-001") -> list[dict[str, Any]]:
    response = client.get("/api/tuning/suppressed-detections", params={"rule_id": rule_id}, headers=auth("viewer"))
    items: list[dict[str, Any]] = response.json()["items"]
    return items


def incident_rules(client: TestClient, incident_id: str) -> list[str]:
    rules: list[str] = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()["rules"]
    return rules


def test_three_scanner_false_positives_suggest_a_scoped_suppression(client: TestClient, ctx: AppContext) -> None:
    incident_ids = scanner_false_positives(client, ctx)
    [suggestion] = suggestions(client, "NET-001")
    assert suggestion["type"] == "suppression" and suggestion["source"] == "deterministic"
    assert suggestion["scope"]["entities"] == [{"type": "source_ip", "value": SCANNER_IP}]
    impact = suggestion["impact"]
    assert impact["alerts_removed"] == 3 and impact["false_positive_alerts_removed"] == 3
    assert impact["true_positive_alerts_removed"] == 0 and impact["true_positives_lost"] == 0
    assert impact["red_flag"] is False
    assert set(suggestion["evidence"]["false_positive_incidents"]) == set(incident_ids)

    url = f"/api/tuning/suggestions/{suggestion['id']}/approve"
    assert client.post(url, json={}, headers=auth("analyst")).status_code == 403
    approved = client.post(url, json={"expires_in_days": 30}, headers=auth("approver"))
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "APPROVED"
    suppression_id = approved.json()["applied"]["suppression_id"]

    stored = suppressed(client)
    assert len(stored) == 3 and {d["suppression_id"] for d in stored} == {suppression_id}
    assert all(d["incident_id"] in incident_ids for d in stored)
    assert run_scenario(ctx, "authorized-scanner")["incident_ids"] == []  # a new scan raises no incident

    [attack] = run_scenario(ctx, "attack-chain")["incident_ids"]
    assert "NET-001" in incident_rules(client, attack)  # discovery from another source is still detected
    with ctx.db.read() as session:
        actions = {row["action"] for row in session.all("SELECT action FROM audit_log")}
    assert {"tuning.suggestion_created", "tuning.approved", "detections.suppressed"} <= actions
    assert ctx.audit.verify(ctx.db)["valid"]


def test_reverting_a_suppression_restores_detections(client: TestClient, ctx: AppContext) -> None:
    scanner_false_positives(client, ctx)
    [suggestion] = suggestions(client, "NET-001")
    client.post(f"/api/tuning/suggestions/{suggestion['id']}/approve", json={}, headers=auth("approver"))
    suppression = client.get("/api/suppressions", headers=auth("viewer")).json()["items"][0]
    assert suppression["applies"] is True and suppression["seconds_remaining"] > 0

    reverted = client.post(
        f"/api/suppressions/{suppression['id']}/revert",
        json={"reason": "The scanner was decommissioned"},
        headers=auth("approver"),
    )
    assert reverted.status_code == 200 and reverted.json()["status"] == "REVERTED"
    assert suppressed(client) == []
    assert len(run_scenario(ctx, "authorized-scanner")["incident_ids"]) == 1
    assert (
        client.get(f"/api/tuning/suggestions/{suggestion['id']}", headers=auth("viewer")).json()["status"] == "REVERTED"
    )


def test_expired_suppressions_stop_applying(client: TestClient, ctx: AppContext, clock: ManualClock) -> None:
    scanner_false_positives(client, ctx)
    [suggestion] = suggestions(client, "NET-001")
    client.post(
        f"/api/tuning/suggestions/{suggestion['id']}/approve", json={"expires_in_days": 1}, headers=auth("approver")
    )
    assert len(suppressed(client)) == 3

    clock.advance(86_405)
    ctx.jobs.run_pending(ctx, lanes=("default",))
    [suppression] = client.get("/api/suppressions", headers=auth("viewer")).json()["items"]
    assert suppression["status"] == "EXPIRED" and suppression["applies"] is False
    assert suppressed(client) == []
    assert len(run_scenario(ctx, "authorized-scanner")["incident_ids"]) == 1


def test_protected_rules_and_true_positive_loss_need_acknowledgement(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "ransomware-burst")["incident_ids"]
    asset = ctx.service("incidents").get(incident_id)["asset"]
    assert "FILE-001" in ctx.settings.protected_rules
    created = client.post(
        "/api/tuning/suggestions",
        json={
            "type": "suppression",
            "rule_id": "FILE-001",
            "scope": {"entities": [{"type": "asset", "value": asset}], "expires_in_days": 7},
            "rationale": "The backup job rewrites these files every night",
        },
        headers=auth("analyst"),
    )
    assert created.status_code == 201, created.text
    suggestion = created.json()
    assert suggestion["impact"]["red_flag"] is True and suggestion["impact"]["true_positive_alerts_removed"] == 1
    assert suggestion["requires"] == {
        "protected_rule_acknowledgement": True,
        "true_positive_loss_acknowledgement": True,
    }

    url = f"/api/tuning/suggestions/{suggestion['id']}/approve"
    first = client.post(url, json={}, headers=auth("approver"))
    assert first.status_code == 422 and first.json()["error"]["code"] == "protected_rule_acknowledgement_required"
    second = client.post(url, json={"acknowledge_protected_rule": True}, headers=auth("approver"))
    assert second.status_code == 422
    assert second.json()["error"]["code"] == "true_positive_loss_acknowledgement_required"
    third = client.post(
        url,
        json={"acknowledge_protected_rule": True, "acknowledge_true_positive_loss": True},
        headers=auth("approver"),
    )
    assert third.status_code == 200, third.text
    assert "FILE-001" not in incident_rules(client, incident_id)
    assert "LOG-001" in incident_rules(client, incident_id)  # the incident survives on its other detection


def test_threshold_change_applies_as_an_override_and_reverts(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    created = client.post(
        "/api/tuning/suggestions",
        json={
            "type": "threshold",
            "rule_id": "NET-001",
            "scope": {"threshold": 20},
            "rationale": "Discovery bursts below 20 targets are routine on this lab segment",
        },
        headers=auth("analyst"),
    ).json()
    assert created["impact"]["true_positive_alerts_removed"] == 1
    approved = client.post(
        f"/api/tuning/suggestions/{created['id']}/approve",
        json={"acknowledge_true_positive_loss": True},
        headers=auth("approver"),
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["applied"]["kind"] == "parameters"
    rules = client.get("/api/rules", headers=auth("viewer")).json()["rules"]
    assert next(r for r in rules if r["id"] == "NET-001")["parameters"]["threshold"] == 20
    assert "NET-001" not in incident_rules(client, incident_id)

    client.post(
        f"/api/tuning/suggestions/{created['id']}/revert",
        json={"reason": "Too aggressive"},
        headers=auth("approver"),
    )
    rules = client.get("/api/rules", headers=auth("viewer")).json()["rules"]
    assert next(r for r in rules if r["id"] == "NET-001")["parameters"]["threshold"] == 10
    assert "NET-001" in incident_rules(client, incident_id)


def test_custom_rule_false_positives_suggest_an_exclusion(client: TestClient, ctx: AppContext) -> None:
    definition = {
        "name": "Internal service sweep",
        "description": "Five or more distinct internal destinations contacted by one account within five minutes.",
        "severity": "MEDIUM",
        "techniques": ["T1046"],
        "logic": {
            "kinds": ["network_connection"],
            "group_by": ["asset", "user"],
            "window_seconds": 300,
            "threshold": {"type": "distinct_count", "field": "destination_ip", "value": 5},
        },
    }
    rule_id = client.post("/api/rules", json={"definition": definition}, headers=auth("detection_engineer")).json()[
        "id"
    ]
    client.post(f"/api/rules/{rule_id}/backtest", json={}, headers=auth("detection_engineer"))
    client.post(f"/api/rules/{rule_id}/approve", json={}, headers=auth("approver"))
    client.post(f"/api/rules/{rule_id}/activate", json={}, headers=auth("approver"))

    scanner_false_positives(client, ctx)
    [suggestion] = suggestions(client, rule_id)
    assert suggestion["type"] == "dsl_exclusion"
    assert suggestion["scope"]["exclusion"] == {"field": "source_ip", "op": "equals", "value": SCANNER_IP}
    approved = client.post(f"/api/tuning/suggestions/{suggestion['id']}/approve", json={}, headers=auth("approver"))
    assert approved.status_code == 200, approved.text
    assert approved.json()["applied"]["kind"] == "rule_version"
    rule = client.get(f"/api/rules/{rule_id}", headers=auth("viewer")).json()
    assert rule["active_version"] == 2 and rule["status"] == "ACTIVE"
    assert rule["definition"]["logic"]["exclusions"] == [{"field": "source_ip", "op": "equals", "value": SCANNER_IP}]
    # The custom rule now ignores the scanner; NET-001 has no approved suppression here, so it still fires.
    [next_scan] = run_scenario(ctx, "authorized-scanner")["incident_ids"]
    assert incident_rules(client, next_scan) == ["NET-001"]


def test_false_positive_analytics_and_agent_tools(client: TestClient, ctx: AppContext) -> None:
    scanner_false_positives(client, ctx)
    analytics = client.get("/api/tuning/fp-analytics", headers=auth("viewer")).json()
    assert analytics["false_positive_closures"] == 3 and analytics["false_positive_rate"] == 1.0
    assert next(r for r in analytics["per_rule"] if r["rule_id"] == "NET-001")["false_positives"] == 3
    assert analytics["per_category"] == [{"category": "authorized_scanner", "count": 3}]
    assert any(
        e["type"] == "source_ip" and e["value"] == SCANNER_IP and e["incidents"] == 3 for e in analytics["per_entity"]
    )
    assert analytics["trend"] and "not ground truth" in analytics["label"]

    registry = ctx.service("ai_tools")
    names = {spec.name for spec in registry.tools(ctx.features.ids)}
    assert {"get_fp_analytics", "list_tuning_suggestions", "get_rule", "list_custom_rules"} <= names
    assert {"a3", "a5"} <= registry.features_with_read_tools()
    proposals = {spec.name for spec in registry.tools(ctx.features.ids, include_propose=True)}
    assert {"propose_rule_draft", "propose_rule_backtest", "propose_tuning_review"} <= proposals
