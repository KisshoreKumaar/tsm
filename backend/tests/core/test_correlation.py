from __future__ import annotations

import tempfile
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.context import AppContext, build_context
from app.core.timeutil import ManualClock
from app.demo.scenarios import SCENARIOS, materialize, step_start_offsets
from app.features.registry import ALL_FEATURES
from app.main import create_app
from tests.support import auth, failures, make_settings, principal, raw_event, run_scenario


def incidents(ctx: AppContext) -> list[dict[str, Any]]:
    with ctx.db.read() as session:
        rows = session.all("SELECT * FROM incidents WHERE status != 'MERGED'")
    return [ctx.service("incidents").get(row["id"]) for row in rows]


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_scenarios_match_expectations(ctx: AppContext, scenario: str) -> None:
    run_scenario(ctx, scenario)
    found = incidents(ctx)
    expected = SCENARIOS[scenario].expected
    assert len(found) == expected["incidents"]
    assert sorted({rule for incident in found for rule in incident["rules"]}) == sorted(expected["rules"])
    if "techniques" in expected:
        assert [t for incident in found for t in incident["analysis"]["techniques"]] == expected["techniques"]
    assert ctx.audit.verify(ctx.db)["valid"]


def test_attack_chain_incident_details(ctx: AppContext) -> None:
    result = run_scenario(ctx, "attack-chain")
    [incident_id] = result["incident_ids"]
    incident = ctx.service("incidents").get(incident_id)
    assert incident["event_count"] == 19
    assert [s["stage"] for s in incident["analysis"]["stages"]] == [
        "Credential Access",
        "Initial Access",
        "Execution",
        "Discovery",
    ]
    assert incident["risk"]["severity"] in ("HIGH", "CRITICAL")


def test_late_arrival_matches_attack_chain(tmp_path: Path) -> None:
    def outcome(scenario: str, directory: Path) -> tuple[int, list[str], list[str]]:
        app = create_app(make_settings(directory), clock=ManualClock())
        context: AppContext = app.state.ctx
        run_scenario(context, scenario)
        [incident] = incidents(context)
        return incident["event_count"], incident["rules"], [s["stage"] for s in incident["analysis"]["stages"]]

    assert outcome("late-arrival", tmp_path / "late") == outcome("attack-chain", tmp_path / "ordered")


def test_prompt_injection_is_flagged_as_data(ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "prompt-injection")["incident_ids"]
    incident = ctx.service("incidents").get(incident_id)
    assert incident["analysis"]["injection"]["suspected"]
    assert all(event["injection_suspected"] for event in incident["events"])
    assert ctx.service("responses").list()["total"] == 0  # the embedded "approve all" did nothing


def test_merge_keeps_oldest_incident_and_cancels_responses(
    client: TestClient, ctx: AppContext, clock: ManualClock
) -> None:
    first = client.post("/api/events/batch", json={"events": failures(minute=0)}, headers=auth("analyst")).json()
    clock.advance(5)
    second = client.post("/api/events/batch", json={"events": failures(minute=30)}, headers=auth("analyst")).json()
    [older], [newer] = first["incident_ids"], second["incident_ids"]
    assert older != newer
    newer_revision = client.get(f"/api/incidents/{newer}", headers=auth("viewer")).json()["revision"]
    pending = client.post(
        "/api/responses",
        json={"incident_id": newer, "playbook": "isolate_endpoint", "rationale": "contain", "revision": newer_revision},
        headers=auth("analyst"),
    ).json()
    clock.advance(5)
    bridge = [
        raw_event(kind="auth_success", source_ip="198.51.100.1", timestamp="2026-01-15T08:10:00Z"),
        raw_event(kind="auth_success", source_ip="198.51.100.1", timestamp="2026-01-15T08:20:00Z"),
    ]
    merged = client.post("/api/events/batch", json={"events": bridge}, headers=auth("analyst")).json()
    assert merged["incident_ids"] == [older]
    newer_now = client.get(f"/api/incidents/{newer}", headers=auth("viewer")).json()
    assert newer_now["status"] == "MERGED" and newer_now["merged_into"] == older
    assert client.get(f"/api/incidents/{older}", headers=auth("viewer")).json()["event_count"] == 12
    assert client.get(f"/api/responses/{pending['id']}", headers=auth("viewer")).json()["status"] == "CANCELLED"
    actions = [i["action"] for i in ctx.audit.page(ctx.db, limit=100)["items"]]
    assert "incident.merged" in actions
    assert client.get("/api/incidents", headers=auth("viewer")).json()["total"] == 1


def test_new_evidence_reopens_closed_incident(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = client.post("/api/events/batch", json={"events": failures()}, headers=auth("analyst")).json()[
        "incident_ids"
    ]
    incident = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
    closed = client.patch(
        f"/api/incidents/{incident_id}",
        json={"revision": incident["revision"], "status": "RESOLVED", "note": "Password reset done"},
        headers=auth("analyst"),
    )
    assert closed.status_code == 200 and closed.json()["status"] == "RESOLVED"
    client.post("/api/events", json=raw_event(timestamp="2026-01-15T08:05:00Z"), headers=auth("analyst"))
    reopened = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
    assert reopened["status"] == "OPEN"
    assert reopened["notes"][-1]["kind"] == "reopen"
    assert "incident.reopened" in [i["action"] for i in ctx.audit.page(ctx.db, limit=100)["items"]]


def test_uncorrelated_events_do_not_join(client: TestClient) -> None:
    client.post("/api/events/batch", json={"events": failures(minute=0)}, headers=auth("analyst"))
    client.post("/api/events", json=raw_event(timestamp="2026-01-15T08:15:00Z"), headers=auth("analyst"))
    [incident] = client.get("/api/incidents", headers=auth("viewer")).json()["items"]
    assert incident["event_count"] == 5


def test_component_capacity_fails_atomically(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path, max_component_events=10), clock=ManualClock())
    with TestClient(app) as client:
        events = [raw_event(timestamp=f"2026-01-15T08:00:{i:02d}Z") for i in range(11)]
        response = client.post("/api/events/batch", json={"events": events}, headers=auth("analyst"))
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "capacity_exceeded"
        assert client.get("/api/events", headers=auth("viewer")).json()["total"] == 0


# -- arrival-order invariance (property test) ---------------------------------------------------------------

PROPERTY_BASE = datetime(2026, 1, 15, 6, 0, tzinfo=UTC)


def _scenario_events(scenario_id: str, suffix: str, start: datetime) -> list[dict[str, Any]]:
    scenario = SCENARIOS[scenario_id]
    steps = scenario.build(suffix)
    starts = step_start_offsets(steps, scenario.step_gap_seconds)
    return [
        event
        for index in range(len(steps))
        for event in materialize(
            scenario, suffix, index, f"{scenario_id}-{suffix}", start + timedelta(seconds=starts[index])
        )
    ]


PROPERTY_EVENTS = (
    _scenario_events("attack-chain", "aaa111", PROPERTY_BASE)
    + _scenario_events("lateral-movement", "bbb222", PROPERTY_BASE + timedelta(minutes=3))
    + _scenario_events("benign", "ccc333", PROPERTY_BASE + timedelta(minutes=1))
    + failures(minute=0, asset="host-bridge")
    + failures(minute=25, asset="host-bridge")
    # 08:00:20 -> 08:10:00 -> 08:17:30 -> 08:25:00: every gap is within the 600-second window, so both bursts merge.
    + [raw_event(asset="host-bridge", kind="auth_success", timestamp="2026-01-15T08:10:00Z", source_ip="198.51.100.1")]
    + [raw_event(asset="host-bridge", kind="auth_success", timestamp="2026-01-15T08:17:30Z", source_ip="198.51.100.1")]
)


def _partition(events: list[dict[str, Any]], chunk: int) -> frozenset[tuple[frozenset[str], frozenset[str]]]:
    with tempfile.TemporaryDirectory() as tmp:
        ctx = build_context(
            make_settings(Path(tmp)), ALL_FEATURES, clock=ManualClock(datetime(2026, 1, 15, 9, 0, tzinfo=UTC))
        )
        pipeline = ctx.service("pipeline")
        for start in range(0, len(events), chunk):
            normalized = pipeline.validate(events[start : start + chunk])
            with ctx.db.write() as session:
                pipeline.ingest(session, normalized, principal("analyst").name)
        with ctx.db.read() as session:
            members = session.all(
                "SELECT i.id, e.external_id FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id "
                "JOIN events e ON e.id = ie.event_id WHERE i.status != 'MERGED'"
            )
            rules = session.all(
                "SELECT d.incident_id, d.rule_id FROM detections d JOIN incidents i ON i.id = d.incident_id "
                "WHERE i.status != 'MERGED' AND d.status = 'ACTIVE'"
            )
        groups: dict[str, set[str]] = defaultdict(set)
        for row in members:
            groups[row["id"]].add(row["external_id"])
        rule_sets: dict[str, set[str]] = defaultdict(set)
        for row in rules:
            rule_sets[row["incident_id"]].add(row["rule_id"])
        return frozenset((frozenset(ids), frozenset(rule_sets[incident])) for incident, ids in groups.items())


BASELINE = None


@pytest.mark.slow
@settings(max_examples=12, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(order=st.permutations(PROPERTY_EVENTS), chunk=st.integers(min_value=1, max_value=25))
def test_results_do_not_depend_on_arrival_order(order: list[dict[str, Any]], chunk: int) -> None:
    global BASELINE
    if BASELINE is None:
        BASELINE = _partition(sorted(PROPERTY_EVENTS, key=lambda e: e["timestamp"]), len(PROPERTY_EVENTS))
        assert len(BASELINE) == 5  # attack chain + 3 lateral hosts + merged bridge incident
    assert _partition(list(order), chunk) == BASELINE
