"""F2 AI polish: accepted only when fully validated; otherwise the deterministic story stays."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

from fastapi.testclient import TestClient

from app.ai.providers import ChatMessage, FakeProvider
from app.core.context import AppContext
from app.story.builder import all_sentences
from tests.ai.helpers import ai_calls
from tests.support import auth, run_scenario


def drafts(messages: Sequence[ChatMessage]) -> list[dict[str, Any]]:
    # On a repair retry the last message is the repair instruction, so find the drafting prompt.
    text = next(m.content for m in reversed(messages) if "Draft sentences:\n" in m.content)
    block = text.split("Draft sentences:\n", 1)[1].split("\n<data>", 1)[0]
    return [json.loads(line) for line in block.splitlines() if line.strip()]


def rewrite(transform: Callable[[dict[str, Any]], dict[str, Any]]) -> Callable[[Sequence[ChatMessage]], str]:
    return lambda messages: json.dumps({"s": [transform(row) for row in drafts(messages)]})


def polish(client: TestClient, ctx: AppContext, fake: FakeProvider) -> tuple[str, dict[str, Any]]:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    ctx.service("ai").override = fake
    response = client.post(f"/api/incidents/{incident_id}/story/regenerate", json={}, headers=auth("analyst"))
    assert response.status_code == 200 and response.json()["polish_job_id"]
    ctx.jobs.run_pending(ctx)
    body: dict[str, Any] = client.get(f"/api/incidents/{incident_id}/story", headers=auth("viewer")).json()
    return incident_id, body


def test_validated_polish_replaces_the_story(client: TestClient, ctx: AppContext) -> None:
    fake = FakeProvider(default=rewrite(lambda row: {**row, "t": "In plain terms: " + row["t"]}))
    incident_id, body = polish(client, ctx, fake)
    story = body["story"]
    assert story["badge"] == "AI-polished (validated)" and story["source"] == "ai_polished"
    assert story["citations_valid"] is True
    assert story["executive"]["lines"][0]["sentence"]["text"].startswith("In plain terms:")
    assert body["saved"]["source"] == "ai_polished"
    event_ids = {e["id"] for e in ctx.service("incidents").get(incident_id)["events"]}
    for sentence in all_sentences(story):
        assert set(sentence["evidence_ids"]) <= event_ids
    assert "story.generated" in [i["action"] for i in ctx.audit.page(ctx.db, limit=100)["items"]]


def test_rewrite_citing_other_evidence_is_rejected(client: TestClient, ctx: AppContext) -> None:
    fake = FakeProvider(default=rewrite(lambda row: {**row, "e": ["E1", "E999"]}))
    _, body = polish(client, ctx, fake)
    assert body["story"]["badge"] == "Deterministic"
    assert "failed_validation" in [c["outcome"] for c in ai_calls(ctx)]


def test_rewrite_that_changes_numbers_is_rejected(client: TestClient, ctx: AppContext) -> None:
    fake = FakeProvider(
        default=rewrite(lambda row: {**row, "t": "".join(ch for ch in row["t"] if not ch.isdigit()) + " soon."})
    )
    _, body = polish(client, ctx, fake)
    assert body["story"]["badge"] == "Deterministic"


def test_no_polish_job_without_an_llm(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    response = client.post(f"/api/incidents/{incident_id}/story/regenerate", json={}, headers=auth("analyst")).json()
    assert response["polish_job_id"] is None and response["story"]["badge"] == "Deterministic"


def test_incident_changes_precompute_polish(client: TestClient, ctx: AppContext) -> None:
    ctx.service("ai").override = FakeProvider(default=rewrite(lambda row: row))
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    with ctx.db.read() as session:
        queued = session.all("SELECT subject_id FROM jobs WHERE kind = 'story.polish' AND status = 'QUEUED'")
    assert {r["subject_id"] for r in queued} == {incident_id}  # superseded jobs were cancelled; one remains
