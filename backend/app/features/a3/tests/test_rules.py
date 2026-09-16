"""A3: lifecycle gates, two-person approval, firing and disabling, versions, export and drafts from incidents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.ai.providers import FakeProvider
from app.core.context import AppContext
from app.core.timeutil import ManualClock
from app.main import create_app
from tests.ai.helpers import ai_calls
from tests.support import auth, failures, make_settings, run_scenario


def definition(**logic: Any) -> dict[str, Any]:
    return {
        "name": "Password spraying from one source",
        "description": "Five or more failed logins from one source against one account within five minutes.",
        "severity": "MEDIUM",
        "techniques": ["T1110"],
        "known_false_positives": ["A user repeatedly mistyping a password"],
        "logic": {
            "kinds": ["auth_failure"],
            "group_by": ["asset", "user", "source_ip"],
            "window_seconds": 300,
            "threshold": {"type": "count", "value": 5},
            **logic,
        },
    }


def ingest(ctx: AppContext, raws: list[dict[str, Any]]) -> list[str]:
    pipeline = ctx.service("pipeline")
    normalized = pipeline.validate(raws)
    with ctx.db.write() as session:
        outcome = pipeline.ingest(session, normalized, "test")
    return outcome.incident_ids


def activate(
    client: TestClient, rule_id: str, engineer: str = "detection_engineer", approver: str = "approver"
) -> None:
    assert client.post(f"/api/rules/{rule_id}/backtest", json={}, headers=auth(engineer)).status_code == 200
    assert client.post(f"/api/rules/{rule_id}/approve", json={}, headers=auth(approver)).status_code == 200
    assert client.post(f"/api/rules/{rule_id}/activate", json={}, headers=auth(approver)).status_code == 200


def incident_rules(client: TestClient, incident_id: str) -> list[str]:
    rules: list[str] = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()["rules"]
    return rules


def test_lifecycle_gates_activation_and_the_rule_fires_until_disabled(client: TestClient, ctx: AppContext) -> None:
    created = client.post(
        "/api/rules", json={"definition": definition(), "rationale": "Lab spraying"}, headers=auth("detection_engineer")
    )
    assert created.status_code == 201, created.text
    rule = created.json()
    rule_id = rule["id"]
    assert (
        rule_id == "CUS-001" and rule["status"] == "DRAFT" and rule["allowed_actions"] == ["edit", "backtest", "retire"]
    )
    assert client.post(f"/api/rules/{rule_id}/activate", json={}, headers=auth("approver")).status_code == 409
    assert client.post(f"/api/rules/{rule_id}/approve", json={}, headers=auth("approver")).status_code == 409
    assert client.post(f"/api/rules/{rule_id}/approve", json={}, headers=auth("detection_engineer")).status_code == 403

    backtest = client.post(f"/api/rules/{rule_id}/backtest", json={}, headers=auth("detection_engineer")).json()
    assert backtest["status"] == "TESTED" and backtest["result"]["matches_in_benign_scenario"] == 0
    assert client.post(f"/api/rules/{rule_id}/activate", json={}, headers=auth("approver")).status_code == 409
    assert (
        client.post(f"/api/rules/{rule_id}/approve", json={}, headers=auth("approver")).json()["status"] == "APPROVED"
    )
    active = client.post(f"/api/rules/{rule_id}/activate", json={}, headers=auth("approver")).json()
    assert active["status"] == "ACTIVE" and active["active_version"] == 1

    [incident_id] = ingest(ctx, failures(6, source_ip="198.51.100.23", user="dana", asset="lab-web-9"))
    assert {"AUTH-001", "CUS-001"} <= set(incident_rules(client, incident_id))
    assert any(
        r["id"] == "CUS-001" and not r["builtin"]
        for r in client.get("/api/rules", headers=auth("viewer")).json()["rules"]
    )

    disabled = client.post(
        f"/api/rules/{rule_id}/disable", json={"reason": "Noisy in the lab"}, headers=auth("approver")
    )
    assert disabled.json()["status"] == "DISABLED"
    [later] = ingest(ctx, failures(6, minute=30, source_ip="198.51.100.24", user="erin", asset="lab-web-8"))
    assert "CUS-001" not in incident_rules(client, later)
    with ctx.db.read() as session:
        actions = {row["action"] for row in session.all("SELECT action FROM audit_log WHERE action LIKE 'rule.%'")}
    assert {"rule.created", "rule.backtested", "rule.approved", "rule.activated", "rule.disabled"} <= actions


def test_two_person_mode_requires_a_different_approver(tmp_path: Path, clock: ManualClock) -> None:
    app = create_app(make_settings(tmp_path, two_person=True), clock=clock)
    with TestClient(app, raise_server_exceptions=False) as client:
        rule_id = client.post("/api/rules", json={"definition": definition()}, headers=auth("admin")).json()["id"]
        client.post(f"/api/rules/{rule_id}/backtest", json={}, headers=auth("admin"))
        denied = client.post(f"/api/rules/{rule_id}/approve", json={}, headers=auth("admin"))
        assert denied.status_code == 403 and denied.json()["error"]["code"] == "two_person_rule"
        assert client.post(f"/api/rules/{rule_id}/approve", json={}, headers=auth("approver")).status_code == 200


def test_editing_keeps_the_active_version_running_and_supports_diff_and_export(
    client: TestClient, ctx: AppContext
) -> None:
    rule_id = client.post("/api/rules", json={"definition": definition()}, headers=auth("detection_engineer")).json()[
        "id"
    ]
    activate(client, rule_id)
    edited = client.post(
        f"/api/rules/{rule_id}/versions",
        json={"definition": definition(window_seconds=600), "rationale": "Slower spraying"},
        headers=auth("detection_engineer"),
    ).json()
    assert edited["status"] == "DRAFT" and edited["current_version"] == 2 and edited["active_version"] == 1
    assert "disable" in edited["allowed_actions"] and "activate" not in edited["allowed_actions"]
    [incident_id] = ingest(ctx, failures(6, source_ip="198.51.100.30", user="fay", asset="lab-web-7"))
    assert "CUS-001" in incident_rules(client, incident_id)

    diff = client.get(f"/api/rules/{rule_id}/diff", params={"from_version": 1, "to_version": 2}, headers=auth("viewer"))
    assert diff.json()["changes"] == [{"path": "logic.window_seconds", "change": "changed", "old": 300, "new": 600}]
    sigma = client.get(f"/api/rules/{rule_id}/export", params={"format": "sigma"}, headers=auth("viewer"))
    assert sigma.status_code == 200 and sigma.text.startswith("# Best-effort Sigma export")
    assert "attachment" in sigma.headers["content-disposition"]
    exported = json.loads(client.get(f"/api/rules/{rule_id}/export", headers=auth("viewer")).text)
    assert exported["rule"]["definition"]["logic"]["window_seconds"] == 600
    assert client.get("/api/rules/AUTH-001/export", headers=auth("viewer")).status_code == 409

    invalid = client.post(
        "/api/rules/validate",
        json={"definition": definition(conditions=[{"field": "command_line", "op": "regex", "value": "(a+)+"}])},
        headers=auth("detection_engineer"),
    ).json()
    assert invalid["valid"] is False and "Nested quantifiers" in json.dumps(invalid["errors"])
    rejected = client.post(
        "/api/rules",
        json={"definition": {**definition(), "code": "__import__('os')"}},
        headers=auth("detection_engineer"),
    )
    assert rejected.status_code == 422 and "__import__" not in rejected.text


def draft_job(client: TestClient, ctx: AppContext, incident_id: str) -> dict[str, Any]:
    response = client.post(f"/api/rules/draft-from-incident/{incident_id}", json={}, headers=auth("detection_engineer"))
    assert response.status_code == 202, response.text
    ctx.jobs.run_pending(ctx)
    job: dict[str, Any] = client.get(
        f"/api/jobs/{response.json()['job_id']}", headers=auth("detection_engineer")
    ).json()
    assert job["status"] == "SUCCEEDED", job
    return job


def test_rule_drafted_from_lateral_movement_backtests_with_hits_on_that_incident(
    client: TestClient, ctx: AppContext
) -> None:
    incident_id = run_scenario(ctx, "lateral-movement")["incident_ids"][0]
    job = draft_job(client, ctx, incident_id)
    assert job["result"]["source"] == "deterministic_draft"
    rule_id = job["result"]["rule_id"]
    rule = client.get(f"/api/rules/{rule_id}", headers=auth("viewer")).json()
    assert rule["source_incident_id"] == incident_id and rule["status"] == "DRAFT"
    backtest = client.post(f"/api/rules/{rule_id}/backtest", json={}, headers=auth("detection_engineer")).json()
    assert incident_id in backtest["result"]["matched_incident_ids"]
    assert backtest["result"]["overlap_with_existing_rules"]


def test_invalid_ai_rule_is_repaired_once_then_falls_back(client: TestClient, ctx: AppContext) -> None:
    incident_id = run_scenario(ctx, "lateral-movement")["incident_ids"][0]
    ctx.service("ai").override = FakeProvider(default=json.dumps({"n": "Bad", "k": ["not_a_kind"], "t": 5}))
    job = draft_job(client, ctx, incident_id)
    assert job["result"]["source"] == "deterministic_draft" and job["result"]["ai_status"] == "failed_validation"
    assert "failed_validation" in [call["outcome"] for call in ai_calls(ctx)]


def test_valid_ai_rule_is_kept_only_when_it_matches_its_incident(client: TestClient, ctx: AppContext) -> None:
    first, second = run_scenario(ctx, "lateral-movement")["incident_ids"][:2]
    good = {
        "n": "Password guessing on a server",
        "k": ["auth_failure"],
        "c": [],
        "g": ["asset", "user"],
        "w": 600,
        "t": 5,
        "df": None,
        "s": "HIGH",
        "x": ["T1110"],
        "r": "Five failures against one account",
        "fp": ["A user mistyping a password"],
    }
    ctx.service("ai").override = FakeProvider(default=json.dumps(good))
    assert draft_job(client, ctx, first)["result"]["source"] == "ai_draft"
    # A rule that cannot fire on its own incident is rejected (a different incident, so no cached answer).
    ctx.service("ai").override = FakeProvider(default=json.dumps({**good, "k": ["process_start"], "x": ["T1059.001"]}))
    assert draft_job(client, ctx, second)["result"]["source"] == "deterministic_draft"
