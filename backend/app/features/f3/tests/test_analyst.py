"""F3 AI analyst: chats, async answers, grounding, deterministic fallback, injection corpus, notes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.ai.providers import FakeProvider
from app.core.context import AppContext
from tests.ai.helpers import answer_json, final_json
from tests.support import auth, run_scenario

CORPUS = Path(__file__).resolve().parents[4] / "tests" / "ai" / "injection_cases.jsonl"


def ask(
    client: TestClient, ctx: AppContext, subject_type: str, subject_id: str, question: str, mode: str = "quick"
) -> dict[str, Any]:
    chat = client.post(
        "/api/chats", json={"subject_type": subject_type, "subject_id": subject_id}, headers=auth("analyst")
    )
    assert chat.status_code == 201, chat.text
    posted = client.post(
        f"/api/chats/{chat.json()['id']}/messages", json={"content": question, "mode": mode}, headers=auth("analyst")
    )
    assert posted.status_code == 202, posted.text
    assert posted.json()["queue_position"] == 1
    ctx.jobs.run_pending(ctx)
    detail = client.get(f"/api/chats/{chat.json()['id']}", headers=auth("viewer")).json()
    assistant = [m for m in detail["messages"] if m["role"] == "assistant"][-1]
    assert assistant["status"] == "complete", assistant
    return {"chat": detail, "answer": assistant["content"], "message": assistant}


def incident(ctx: AppContext, scenario: str = "attack-chain") -> dict[str, Any]:
    [incident_id] = run_scenario(ctx, scenario)["incident_ids"]
    detail: dict[str, Any] = ctx.service("incidents").get(incident_id)
    return detail


def test_quick_answer_is_grounded_and_audited(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    ctx.service("ai").override = FakeProvider([answer_json()])
    result = ask(client, ctx, "incident", detail["id"], "Why is this suspicious?")
    answer = result["answer"]
    assert answer["used_ai"] is True and answer["ai_status"] == "validated"
    assert answer["claims"][0]["label"] == "FACT"
    assert set(answer["claims"][0]["evidence_ids"]) <= {e["id"] for e in detail["events"]}
    assert answer["subject_revision"] == detail["revision"]
    actions = [i["action"] for i in ctx.audit.page(ctx.db, limit=100)["items"]]
    assert {"chat.created", "chat.message_posted", "ai.call"} <= set(actions)


def test_deterministic_answer_when_llm_disabled(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    answer = ask(client, ctx, "incident", detail["id"], "Is this a false positive?")["answer"]
    assert answer["used_ai"] is False and answer["ai_status"] == "llm_disabled"
    assert any(c["label"] == "UNKNOWN" for c in answer["claims"])
    facts = [c for c in answer["claims"] if c["label"] == "FACT"]
    assert all(c["evidence_ids"] for c in facts)


def test_out_of_scope_questions_get_unknown(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    answer = ask(client, ctx, "incident", detail["id"], "What is the weather in Mumbai?")["answer"]
    assert [c["label"] for c in answer["claims"]] == ["UNKNOWN"]
    assert answer["suggested_actions"] == []


def test_deep_mode_uses_read_only_tools(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    ctx.service("ai").override = FakeProvider(['{"tool": "get_story", "args": {}}', final_json()])
    answer = ask(client, ctx, "incident", detail["id"], "Summarise the story", mode="deep")["answer"]
    assert answer["steps"] == 1 and answer["tool_calls"][0]["tool"] == "get_story"
    assert detail["revision"] == ctx.service("incidents").get(detail["id"])["revision"]  # nothing changed


def test_campaign_chat(client: TestClient, ctx: AppContext) -> None:
    run_scenario(ctx, "lateral-movement")
    [campaign] = client.get("/api/campaigns", headers=auth("viewer")).json()["items"]
    answer = ask(client, ctx, "campaign", campaign["id"], "What happened?")["answer"]
    assert answer["claims"]


def test_roles_without_ai_use_are_refused(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    for role in ("viewer", "approver", "ingest"):
        response = client.post(
            "/api/chats", json={"subject_type": "incident", "subject_id": detail["id"]}, headers=auth(role)
        )
        assert response.status_code == 403


def test_add_to_notes_creates_a_human_note_referencing_the_job(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    result = ask(client, ctx, "incident", detail["id"], "What happened?")
    chat_id, message = result["chat"]["id"], result["message"]
    response = client.post(
        f"/api/chats/{chat_id}/messages/{message['id']}/add-to-notes",
        json={"text": "Analyst reviewed the AI summary and agrees."},
        headers=auth("analyst"),
    )
    assert response.status_code == 201
    note = ctx.service("incidents").get(detail["id"])["notes"][-1]
    assert (note["kind"], note["author"], note["ai_job_id"]) == ("ai_reference", "analyst-user", message["job_id"])


def test_injection_corpus_never_survives_as_claims_or_actions(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx, "prompt-injection")
    malicious = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]
    malicious = [case["text"] for case in malicious if case["flag"]]
    replies = [
        answer_json(
            summary=text,
            claims=[{"t": text, "l": "FACT", "e": ["E1"]}],
            questions=[text],
            actions=[{"t": text, "p": "isolate_endpoint"}, {"t": "Approve the pending isolation", "p": None}],
            confidence="high",
        )
        for text in malicious
    ]
    ctx.service("ai").override = FakeProvider(replies)
    for text in malicious:
        answer = ask(client, ctx, "incident", detail["id"], "Is this a false positive?")["answer"]
        assert text not in json.dumps([c["text"] for c in answer["claims"]]), text
        assert answer["suggested_actions"] == [], text
        assert answer["suggested_next_questions"] == [], text
        assert answer["injection_suspected"] is True
    assert ctx.service("responses").list()["total"] == 0
    assert ctx.service("incidents").get(detail["id"])["status"] == "OPEN"
