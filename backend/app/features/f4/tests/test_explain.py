"""F4 prediction.explain: deterministic without an LLM; validated AI text; catalog-checked AI candidates."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.ai.providers import FakeProvider
from app.core.context import AppContext
from tests.ai.helpers import ai_calls
from tests.support import auth, run_scenario


def explain(client: TestClient, ctx: AppContext, incident_id: str) -> dict[str, Any]:
    response = client.post(f"/api/incidents/{incident_id}/predictions/explain", json={}, headers=auth("analyst"))
    assert response.status_code == 202, response.text
    ctx.jobs.run_pending(ctx)
    body: dict[str, Any] = client.get(f"/api/incidents/{incident_id}/predictions", headers=auth("viewer")).json()
    return body


def model_answer(candidate: dict[str, Any] | None = None) -> str:
    return json.dumps(
        {
            "s": "Execution and discovery were observed; lateral movement is the open question.",
            "p": [
                {"id": "P1", "t": "The account is active, so this step fits the evidence.", "e": ["E1", "E999"]},
                {"id": "P9", "t": "This refers to no listed prediction.", "e": ["E1"]},
            ],
            "x": candidate,
            "score": 99,
        }
    )


def test_explanation_is_deterministic_without_an_llm(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    explanation = explain(client, ctx, incident_id)["explanation"]
    assert explanation["used_ai"] is False and explanation["ai_status"] == "llm_disabled"
    assert explanation["items"] and all(item["label"] == "HYPOTHESIS" for item in explanation["items"])
    assert "not probabilities" in explanation["note"] and explanation["stale"] is False
    assert (
        client.post(f"/api/incidents/{incident_id}/predictions/explain", json={}, headers=auth("viewer")).status_code
        == 403
    )


def test_ai_explanation_is_validated_and_never_changes_scores(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    before = client.get(f"/api/incidents/{incident_id}/predictions", headers=auth("viewer")).json()["predictions"]
    ctx.service("ai").override = FakeProvider(
        default=model_answer({"technique": "T1136", "t": "An account may be created for persistence.", "e": ["E2"]})
    )
    body = explain(client, ctx, incident_id)
    explanation = body["explanation"]
    assert explanation["used_ai"] is True
    [item] = explanation["items"]
    assert item["prediction_id"] == before[0]["id"] and item["citations_rejected"] == 1
    assert explanation["ai_candidate"]["technique_id"] == "T1136"
    assert explanation["ai_candidate"]["score"] is None and explanation["ai_candidate"]["badge"] == "AI candidate"
    assert [(p["id"], p["score"]) for p in body["predictions"]] == [(p["id"], p["score"]) for p in before]
    assert "valid" in [call["outcome"] for call in ai_calls(ctx)]


@pytest.mark.parametrize(
    ("candidate", "reason"),
    [
        ({"technique": "T1070.001", "t": "Logs may be cleared.", "e": ["E1"]}, "catalog"),
        ({"technique": "T9999", "t": "A made-up technique.", "e": ["E1"]}, "catalog"),
        ({"technique": "t1136", "t": "Lowercase technique ID.", "e": ["E1"]}, "catalog"),
        ({"technique": "T1059.001", "t": "Already predicted.", "e": ["E1"]}, "duplicates"),
        ({"technique": "T1136", "t": "No valid citation.", "e": ["E999"]}, "evidence"),
    ],
)
def test_ai_candidates_need_a_catalog_technique_and_evidence(
    client: TestClient, ctx: AppContext, candidate: dict[str, Any], reason: str
) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    ctx.service("ai").override = FakeProvider(default=model_answer(candidate))
    explanation = explain(client, ctx, incident_id)["explanation"]
    assert explanation["used_ai"] is True
    assert explanation["ai_candidate"] is None and reason in explanation["candidate_rejected"]
