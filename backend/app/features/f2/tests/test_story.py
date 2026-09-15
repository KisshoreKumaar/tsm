from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app.ai.injection import scan_text
from app.core.context import AppContext
from app.story.builder import QUOTED_RE, all_sentences, render_markdown, validate_citations
from tests.support import auth, failures, raw_event, run_scenario

LABELS = {"FACT", "INFERENCE", "HYPOTHESIS", "UNKNOWN"}


def get_story(client: TestClient, incident_id: str) -> dict[str, Any]:
    response = client.get(f"/api/incidents/{incident_id}/story", headers=auth("viewer"))
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def incident_event_ids(client: TestClient, incident_id: str) -> set[str]:
    detail = client.get(f"/api/incidents/{incident_id}", headers=auth("viewer")).json()
    return {event["id"] for event in detail["events"]}


def test_attack_chain_story_is_chronological_concrete_and_cited(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    body = get_story(client, incident_id)
    story = body["story"]
    assert story["badge"] == "Deterministic" and story["citations_valid"] is True
    assert body["stale"] is False and body["saved"] is None
    assert [stage["stage"] for stage in story["stages"]] == [
        "Credential Access",
        "Initial Access",
        "Execution",
        "Discovery",
    ]
    assert [stage["first_ts"] for stage in story["stages"]] == sorted(stage["first_ts"] for stage in story["stages"])
    assert 150 <= story["analyst"]["word_count"] <= 300
    assert [line["key"] for line in story["executive"]["lines"]] == [
        "what_happened",
        "impact",
        "contained",
        "actions",
        "needs",
    ]
    stage_text = " ".join(stage["sentence"]["text"] for stage in story["stages"])
    for concrete in ("5 logins for alex", "203.0.113.45", "-EncodedCommand", "12 distinct destinations", "445"):
        assert concrete in stage_text
    valid = incident_event_ids(client, incident_id)
    for sentence in all_sentences(story):
        assert sentence["label"] in LABELS
        assert set(sentence["evidence_ids"]) <= valid
        if sentence["label"] == "FACT" and sentence["basis"] == "events":
            assert sentence["evidence_ids"], sentence
    refs = [item["ref"] for item in story["evidence_index"]]
    assert refs == [f"E{i}" for i in range(1, len(refs) + 1)]


def test_stages_follow_evidence_time_when_powershell_comes_first(client: TestClient) -> None:
    events = [
        raw_event(
            kind="process_start",
            process_name="powershell.exe",
            command_line="powershell.exe -enc AAAA",
            timestamp="2026-01-15T08:00:00Z",
        ),
        *failures(minute=3),
        raw_event(kind="auth_success", timestamp="2026-01-15T08:04:00Z"),
    ]
    [incident_id] = client.post("/api/events/batch", json={"events": events}, headers=auth("analyst")).json()[
        "incident_ids"
    ]
    story = get_story(client, incident_id)["story"]
    assert [stage["stage"] for stage in story["stages"]] == ["Execution", "Credential Access", "Initial Access"]


def test_injection_text_only_appears_as_quoted_data(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "prompt-injection")["incident_ids"]
    story = get_story(client, incident_id)["story"]
    texts = [sentence["text"] for sentence in all_sentences(story)]
    assert any("“" in text and "Ignore previous instructions" in text for text in texts)
    for text in [*texts, render_markdown(story)]:
        assert scan_text(QUOTED_RE.sub("", text)) == [], text


def test_short_incidents_still_get_a_full_analyst_story(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "indicator")["incident_ids"]
    story = get_story(client, incident_id)["story"]
    assert 150 <= story["analyst"]["word_count"] <= 300
    assert "not verified" in " ".join(s["text"] for s in all_sentences(story))
    assert story["citations_valid"]


def test_citation_validator_rejects_unknown_and_missing_evidence() -> None:
    problems = validate_citations(
        [
            {"id": "s1", "label": "FACT", "text": "x", "evidence_ids": ["made-up"], "basis": "events"},
            {"id": "s2", "label": "FACT", "text": "y", "evidence_ids": [], "basis": "events"},
            {"id": "s3", "label": "FACT", "text": "z", "evidence_ids": [], "basis": "aegis_records"},
            {"id": "s4", "label": "PROBABLY", "text": "w", "evidence_ids": [], "basis": "events"},
        ],
        {"real-event"},
    )
    assert len(problems) == 3
    assert any("s1" in p for p in problems) and any("s2" in p for p in problems) and any("s4" in p for p in problems)


def test_markdown_export(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    full = client.get(f"/api/incidents/{incident_id}/story.md", headers=auth("viewer"))
    assert full.status_code == 200
    assert full.headers["content-type"].startswith("text/markdown")
    assert "attachment" in full.headers["content-disposition"]
    assert "## Executive summary" in full.text and "## Analyst narrative" in full.text and "| E1 |" in full.text
    executive = client.get(
        f"/api/incidents/{incident_id}/story.md", params={"format": "executive"}, headers=auth("viewer")
    )
    assert "## Analyst narrative" not in executive.text


def test_regeneration_versions_and_stale_indicator(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    assert (
        client.post(f"/api/incidents/{incident_id}/story/regenerate", json={}, headers=auth("viewer")).status_code
        == 403
    )
    first = client.post(f"/api/incidents/{incident_id}/story/regenerate", json={}, headers=auth("analyst")).json()
    assert first["saved"]["version"] == 1 and first["stale"] is False
    client.post(f"/api/incidents/{incident_id}/notes", json={"text": "Checked with the user"}, headers=auth("analyst"))
    assert get_story(client, incident_id)["stale"] is True
    second = client.post(f"/api/incidents/{incident_id}/story/regenerate", json={}, headers=auth("analyst")).json()
    assert second["saved"]["version"] == 2 and second["stale"] is False
    actions = [item["action"] for item in ctx.audit.page(ctx.db, limit=200)["items"]]
    assert actions.count("story.generated") == 2


def test_campaign_story_combines_incident_stories(client: TestClient, ctx: AppContext) -> None:
    run_scenario(ctx, "lateral-movement")
    [campaign] = client.get("/api/campaigns", headers=auth("viewer")).json()["items"]
    response = client.get(f"/api/campaigns/{campaign['id']}/story", headers=auth("viewer"))
    assert response.status_code == 200
    story = response.json()["story"]
    text = " ".join(sentence["text"] for sentence in all_sentences(story))
    assert "svc-backup" in text and "203.0.113.77" in text
    assert story["citations_valid"] is True
    assert len(story["analyst"]["paragraphs"]) == 5  # opening + three incidents + hypothesis
    markdown = client.get(f"/api/campaigns/{campaign['id']}/story.md", headers=auth("viewer"))
    assert markdown.status_code == 200 and "Campaign story" in markdown.text
