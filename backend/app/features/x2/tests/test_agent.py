"""X2 agent console: proposals are drafts; only humans with the target permission apply them."""

from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from app.ai.providers import FakeProvider
from app.core.context import AppContext
from app.features.x2.service import HUMAN_ONLY_ACTIONS, PROPOSAL_TYPES
from tests.ai.helpers import final_json
from tests.support import auth, run_scenario


def incident(ctx: AppContext, scenario: str = "attack-chain") -> dict[str, Any]:
    [incident_id] = run_scenario(ctx, scenario)["incident_ids"]
    detail: dict[str, Any] = ctx.service("incidents").get(incident_id)
    return detail


def run_agent(client: TestClient, ctx: AppContext, replies: list[Any], subject: dict[str, Any]) -> dict[str, Any]:
    ctx.service("ai").override = FakeProvider(replies)
    chat = client.post("/api/chats", json=subject, headers=auth("analyst")).json()
    posted = client.post(
        f"/api/chats/{chat['id']}/messages",
        json={"content": "Help me triage", "mode": "agent"},
        headers=auth("analyst"),
    )
    assert posted.status_code == 202, posted.text
    ctx.jobs.run_pending(ctx)
    messages = client.get(f"/api/chats/{chat['id']}", headers=auth("viewer")).json()["messages"]
    content: dict[str, Any] = messages[-1]["content"]
    return content


def propose(tool: str, **args: Any) -> str:
    return json.dumps({"tool": tool, "args": args})


def proposals(client: TestClient) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = client.get("/api/agent/proposals", headers=auth("viewer")).json()["items"]
    return items


def test_agent_proposes_and_a_human_applies(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    answer = run_agent(
        client,
        ctx,
        [
            propose(
                "propose_incident_update",
                status="INVESTIGATING",
                note="Taking ownership",
                rationale="High-risk login",
                evidence=["E1"],
            ),
            final_json(),
        ],
        {"subject_type": "incident", "subject_id": detail["id"]},
    )
    [proposal] = proposals(client)
    assert answer["proposal_ids"] == [proposal["id"]]
    assert proposal["status"] == "PROPOSED" and proposal["target_revision"] == detail["revision"]
    assert proposal["created_by"].startswith("ai:agent")
    assert ctx.service("incidents").get(detail["id"])["status"] == "OPEN"  # the agent changed nothing
    denied = client.post(f"/api/agent/proposals/{proposal['id']}/apply", json={}, headers=auth("viewer"))
    assert denied.status_code == 403 and denied.json()["error"]["details"] == {"required": "investigate"}
    applied = client.post(f"/api/agent/proposals/{proposal['id']}/apply", json={}, headers=auth("analyst"))
    assert applied.status_code == 200, applied.text
    assert applied.json()["status"] == "APPLIED" and applied.json()["decided_by"] == "analyst-user"
    updated = ctx.service("incidents").get(detail["id"])
    assert updated["status"] == "INVESTIGATING" and updated["revision"] == detail["revision"] + 1
    assert applied.json()["result"] == {
        "incident_id": detail["id"],
        "status": "INVESTIGATING",
        "revision": detail["revision"] + 1,
    }
    actions = [i["action"] for i in ctx.audit.page(ctx.db, limit=200)["items"]]
    assert {"agent.proposal_created", "agent.proposal_applied", "incident.reviewed"} <= set(actions)
    assert (
        client.post(f"/api/agent/proposals/{proposal['id']}/apply", json={}, headers=auth("analyst")).status_code == 409
    )


def test_response_proposal_uses_the_normal_workflow(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    run_agent(
        client,
        ctx,
        [
            propose("propose_response", playbook="isolate_endpoint", rationale="Contain the host", evidence=["E2"]),
            final_json(),
        ],
        {"subject_type": "incident", "subject_id": detail["id"]},
    )
    [proposal] = proposals(client)
    assert (
        client.post(f"/api/agent/proposals/{proposal['id']}/apply", json={}, headers=auth("approver")).status_code
        == 403
    )
    applied = client.post(f"/api/agent/proposals/{proposal['id']}/apply", json={}, headers=auth("analyst")).json()
    [response] = ctx.service("responses").list()["items"]
    assert response["status"] == "PENDING" and response["id"] == applied["result"]["response_id"]


def test_stale_proposals_cannot_be_applied(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    run_agent(
        client,
        ctx,
        [propose("propose_incident_note", text="Looks like guessing", evidence=["E1"]), final_json()],
        {"subject_type": "incident", "subject_id": detail["id"]},
    )
    [proposal] = proposals(client)
    client.post(f"/api/incidents/{detail['id']}/notes", json={"text": "Manual note"}, headers=auth("analyst"))
    response = client.post(f"/api/agent/proposals/{proposal['id']}/apply", json={}, headers=auth("analyst"))
    assert response.status_code == 409 and response.json()["error"]["code"] == "stale_proposal"
    assert proposals(client)[0]["status"] == "STALE"


def test_injection_context_requires_acknowledgement(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx, "prompt-injection")
    run_agent(
        client,
        ctx,
        [propose("propose_incident_note", text="Suspicious text in logs", evidence=["E1"]), final_json()],
        {"subject_type": "incident", "subject_id": detail["id"]},
    )
    [proposal] = proposals(client)
    assert proposal["injection_context"] is True
    blocked = client.post(f"/api/agent/proposals/{proposal['id']}/apply", json={}, headers=auth("analyst"))
    assert blocked.status_code == 422 and blocked.json()["error"]["code"] == "injection_acknowledgement_required"
    ok = client.post(
        f"/api/agent/proposals/{proposal['id']}/apply", json={"acknowledge_injection": True}, headers=auth("analyst")
    )
    assert ok.status_code == 200


def test_human_only_actions_are_never_proposable(client: TestClient, ctx: AppContext) -> None:
    assert not set(PROPOSAL_TYPES) & HUMAN_ONLY_ACTIONS
    catalogue = client.get("/api/agent/tools", headers=auth("viewer")).json()
    names = {tool["name"] for tool in catalogue["tools"]}
    for forbidden in ("approve", "execute", "activate", "finalize", "suppress", "submit"):
        assert not any(forbidden in name for name in names), forbidden
    detail = incident(ctx, "prompt-injection")
    answer = run_agent(
        client,
        ctx,
        [
            '{"tool": "approve_response", "args": {"response_id": "*"}}',
            '{"tool": "propose_rule_activation", "args": {}}',
            final_json(),
        ],
        {"subject_type": "incident", "subject_id": detail["id"]},
    )
    assert [c["ok"] for c in answer["tool_calls"]] == [False, False]
    assert proposals(client) == []


def test_dismiss_requires_a_reason(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    run_agent(
        client,
        ctx,
        [propose("propose_incident_note", text="Check VPN logs", evidence=["E1"]), final_json()],
        {"subject_type": "incident", "subject_id": detail["id"]},
    )
    [proposal] = proposals(client)
    assert (
        client.post(
            f"/api/agent/proposals/{proposal['id']}/dismiss", json={"reason": ""}, headers=auth("analyst")
        ).status_code
        == 422
    )
    dismissed = client.post(
        f"/api/agent/proposals/{proposal['id']}/dismiss", json={"reason": "Not needed"}, headers=auth("analyst")
    )
    assert dismissed.json()["status"] == "DISMISSED"


def test_workspace_agent_without_llm_falls_back(client: TestClient, ctx: AppContext) -> None:
    chat = client.post("/api/chats", json={"subject_type": "global"}, headers=auth("analyst")).json()
    client.post(
        f"/api/chats/{chat['id']}/messages",
        json={"content": "What needs attention?", "mode": "agent"},
        headers=auth("analyst"),
    )
    ctx.jobs.run_pending(ctx)
    content = client.get(f"/api/chats/{chat['id']}", headers=auth("viewer")).json()["messages"][-1]["content"]
    assert content["used_ai"] is False and "needs an enabled LLM" in content["summary"]


def test_proposal_limit_per_run(client: TestClient, ctx: AppContext) -> None:
    detail = incident(ctx)
    replies = [propose("propose_incident_note", text=f"Note {i}", evidence=["E1"]) for i in range(4)] + [final_json()]
    ctx.service("ai").override = FakeProvider(replies)
    chat = client.post(
        "/api/chats", json={"subject_type": "incident", "subject_id": detail["id"]}, headers=auth("analyst")
    ).json()
    client.post(
        f"/api/chats/{chat['id']}/messages", json={"content": "Add notes", "mode": "agent"}, headers=auth("analyst")
    )
    ctx.jobs.run_pending(ctx)
    assert len(proposals(client)) <= 3
