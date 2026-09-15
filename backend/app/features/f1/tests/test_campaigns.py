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
from app.features.registry import ALL_FEATURES
from app.main import create_app
from tests.core.test_correlation import PROPERTY_EVENTS
from tests.support import auth, make_settings, principal, raw_event, run_scenario

BASE = datetime(2026, 1, 15, 8, 0, tzinfo=UTC)


def burst(asset: str, user: str, ip: str, start: datetime, success: bool = True) -> list[dict[str, Any]]:
    events = [
        raw_event(asset=asset, user=user, source_ip=ip, timestamp=(start + timedelta(seconds=i * 5)).isoformat())
        for i in range(5)
    ]
    if success:
        events.append(
            raw_event(
                asset=asset,
                user=user,
                source_ip=ip,
                kind="auth_success",
                timestamp=(start + timedelta(seconds=40)).isoformat(),
            )
        )
    return events


def ingest(client: TestClient, events: list[dict[str, Any]]) -> list[str]:
    response = client.post("/api/events/batch", json={"events": events}, headers=auth("analyst"))
    assert response.status_code == 201, response.text
    incident_ids: list[str] = response.json()["incident_ids"]
    return incident_ids


def active_campaigns(client: TestClient) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = client.get("/api/campaigns", headers=auth("viewer")).json()["items"]
    return items


def test_lateral_movement_forms_one_explained_campaign(client: TestClient, ctx: AppContext) -> None:
    result = run_scenario(ctx, "lateral-movement")
    assert len(result["incident_ids"]) == 3
    [summary] = active_campaigns(client)
    campaign = client.get(f"/api/campaigns/{summary['id']}", headers=auth("viewer")).json()
    assert campaign["incident_count"] == 3 and len(campaign["assets"]) == 3
    assert {(link["entity_type"], link["entity_value"]) for link in campaign["links"]} == {
        ("user", "svc-backup"),
        ("source_ip", "203.0.113.77"),
    }
    assert len(campaign["links"]) == 6  # 3 incident pairs x 2 shared entities
    for link in campaign["links"]:
        assert link["supporting_event_ids"]
        assert link["reason"].startswith("Shared ")
        assert 0 < link["strength"] <= 1
    assert "svc-backup" in campaign["title"] and "203.0.113.77" in campaign["title"]
    timestamps = [event["timestamp"] for event in campaign["timeline"]]
    assert timestamps == sorted(timestamps) and len(timestamps) == 18
    assert "heuristic" in campaign["risk"]["label"].lower()
    related = client.get(f"/api/incidents/{result['incident_ids'][0]}/related", headers=auth("viewer")).json()
    assert related["campaign"]["id"] == campaign["id"]
    assert len(related["related_incidents"]) == 2
    assert {link["entity_value"] for link in related["links"]} == {"svc-backup", "203.0.113.77"}
    actions = [item["action"] for item in ctx.audit.page(ctx.db, limit=200)["items"]]
    assert "campaign.created" in actions


@pytest.mark.parametrize("scenario", ["attack-chain", "benign", "indicator", "ransomware-burst", "prompt-injection"])
def test_single_incident_scenarios_create_no_campaign(client: TestClient, ctx: AppContext, scenario: str) -> None:
    run_scenario(ctx, scenario)
    assert active_campaigns(client) == []


def test_allowlisted_entities_do_not_link(tmp_path: Path) -> None:
    app = create_app(
        make_settings(tmp_path, common_entities=frozenset({"user:svc-backup", "ip:203.0.113.77"})), clock=ManualClock()
    )
    with TestClient(app) as client:
        run_scenario(app.state.ctx, "lateral-movement")
        assert active_campaigns(client) == []
        entity = client.get("/api/entities/user/SVC-BACKUP", headers=auth("viewer")).json()
        assert entity["allowlisted"] is True and entity["linkable"] is False


def test_degree_cap_prevents_over_linking(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path, max_link_degree=2), clock=ManualClock())
    with TestClient(app) as client:
        run_scenario(app.state.ctx, "lateral-movement")
        assert active_campaigns(client) == []


def test_internal_ips_and_distant_activity_do_not_link(client: TestClient) -> None:
    ingest(client, burst("host-a", "alice", "10.20.3.3", BASE))
    ingest(client, burst("host-b", "bob", "10.20.3.3", BASE))
    assert active_campaigns(client) == []  # shared internal IP is infrastructure, not a campaign signal
    ingest(client, burst("host-c", "carol", "198.51.100.9", BASE - timedelta(hours=25)))
    ingest(client, burst("host-d", "dave", "198.51.100.9", BASE))
    assert active_campaigns(client) == []  # outside the 24-hour campaign window
    ingest(client, burst("host-e", "erin", "198.51.100.9", BASE - timedelta(hours=2)))
    [campaign] = active_campaigns(client)
    # host-e is ~23 h after host-c and 2 h before host-d, so it links to both; campaigns are transitive components
    # even though host-c and host-d alone are too far apart to link directly.
    assert campaign["incident_count"] == 3
    detail = client.get(f"/api/campaigns/{campaign['id']}", headers=auth("viewer")).json()
    pairs = {frozenset((link["asset_a"], link["asset_b"])) for link in detail["links"]}
    assert pairs == {frozenset(("host-c", "host-e")), frozenset(("host-d", "host-e"))}


def test_false_positive_closure_updates_and_dissolves_campaign(client: TestClient, ctx: AppContext) -> None:
    incident_ids = run_scenario(ctx, "lateral-movement")["incident_ids"]
    [campaign] = active_campaigns(client)
    for count, incident_id in enumerate(incident_ids[:2], start=1):
        detail = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
        response = client.patch(
            f"/api/incidents/{incident_id}",
            json={
                "revision": detail["revision"],
                "status": "FALSE_POSITIVE",
                "note": "backup job",
                "closure_category": "known_admin_activity",
            },
            headers=auth("analyst"),
        )
        assert response.status_code == 200
        if count == 1:
            assert active_campaigns(client)[0]["incident_count"] == 2
    assert active_campaigns(client) == []
    dissolved = client.get("/api/campaigns", params={"status": "DISSOLVED"}, headers=auth("viewer")).json()["items"]
    assert [c["id"] for c in dissolved] == [campaign["id"]]
    actions = [item["action"] for item in ctx.audit.page(ctx.db, limit=300)["items"]]
    assert {"campaign.updated", "campaign.dissolved"} <= set(actions)


def test_campaigns_merge_when_a_new_incident_bridges_them(client: TestClient, ctx: AppContext) -> None:
    ingest(client, burst("host-1", "u1", "198.51.100.1", BASE))
    ingest(client, burst("host-2", "u1", "198.51.100.2", BASE))
    ingest(client, burst("host-3", "u2", "198.51.100.3", BASE))
    ingest(client, burst("host-4", "u2", "198.51.100.4", BASE))
    assert len(active_campaigns(client)) == 2
    ingest(client, burst("host-5", "u1", "198.51.100.3", BASE))  # shares u1 with hosts 1-2 and an IP with host 3
    [merged] = active_campaigns(client)
    assert merged["incident_count"] == 5
    assert client.get("/api/campaigns", params={"status": "MERGED"}, headers=auth("viewer")).json()["total"] == 1
    assert "campaign.merged" in [item["action"] for item in ctx.audit.page(ctx.db, limit=300)["items"]]


def test_entity_pivot_and_graph(client: TestClient, ctx: AppContext) -> None:
    run_scenario(ctx, "lateral-movement")
    [campaign] = active_campaigns(client)
    entity = client.get("/api/entities/source_ip/203.0.113.77", headers=auth("viewer")).json()
    assert entity["events"] == 18 and len(entity["incidents"]) == 3 and entity["linkable"] is True
    assert client.get("/api/entities/source_ip/not-an-ip", headers=auth("viewer")).status_code == 422
    graph = client.get("/api/graph", params={"campaign_id": campaign["id"]}, headers=auth("viewer")).json()
    types = defaultdict(int)
    for node in graph["nodes"]:
        types[node["type"]] += 1
    assert dict(types) == {"incident": 3, "asset": 3, "user": 1, "source_ip": 1}
    correlation_edges = [e for e in graph["edges"] if e["kind"] == "correlation"]
    assert len(correlation_edges) == 3
    assert all("svc-backup" in e["label"] and "203.0.113.77" in e["label"] for e in correlation_edges)
    node_ids = {node["id"] for node in graph["nodes"]}
    assert all(edge["source"] in node_ids and edge["target"] in node_ids for edge in graph["edges"])


def test_disabled_feature_hides_campaign_routes(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path, features=frozenset({"core"})), clock=ManualClock())
    with TestClient(app) as client:
        assert client.get("/api/campaigns", headers=auth("viewer")).status_code == 404
        run_scenario(app.state.ctx, "lateral-movement")  # ingestion still works without F1


# -- arrival-order invariance for campaigns ---------------------------------------------------------------


def _campaign_partition(events: list[dict[str, Any]], chunk: int) -> frozenset[frozenset[frozenset[str]]]:
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
            rows = session.all(
                "SELECT ci.campaign_id, ie.incident_id, e.external_id FROM campaign_incidents ci "
                "JOIN campaigns c ON c.id = ci.campaign_id JOIN incident_events ie ON ie.incident_id = ci.incident_id "
                "JOIN events e ON e.id = ie.event_id WHERE c.status = 'ACTIVE'"
            )
    campaigns: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for row in rows:
        campaigns[row["campaign_id"]][row["incident_id"]].add(row["external_id"])
    return frozenset(frozenset(frozenset(ids) for ids in incidents.values()) for incidents in campaigns.values())


CAMPAIGN_BASELINE = None


@pytest.mark.slow
@settings(max_examples=10, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(order=st.permutations(PROPERTY_EVENTS), chunk=st.integers(min_value=1, max_value=25))
def test_campaigns_do_not_depend_on_arrival_order(order: list[dict[str, Any]], chunk: int) -> None:
    global CAMPAIGN_BASELINE
    if CAMPAIGN_BASELINE is None:
        CAMPAIGN_BASELINE = _campaign_partition(
            sorted(PROPERTY_EVENTS, key=lambda e: e["timestamp"]), len(PROPERTY_EVENTS)
        )
        assert len(CAMPAIGN_BASELINE) == 1  # the lateral-movement campaign
    assert _campaign_partition(list(order), chunk) == CAMPAIGN_BASELINE
