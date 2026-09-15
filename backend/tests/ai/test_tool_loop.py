"""Deep analyst / agent tool loop with FakeProvider: termination, step cap, unknown tools, injection handling."""

from __future__ import annotations

from typing import Any

from app.ai.builtin_tools import F3_DEEP_TOOLS
from app.ai.evidence import build_incident_pack
from app.ai.providers import FakeProvider, ProviderUnavailable
from app.ai.tasks.analyst import deterministic_answer
from app.ai.tasks.tool_loop import LoopResult, run_tool_loop
from app.core.context import AppContext
from tests.ai.helpers import final_json, scenario_incident


def loop(
    ctx: AppContext, detail: dict[str, Any], replies: list[Any], max_steps: int | None = None
) -> tuple[LoopResult, FakeProvider]:
    fake = FakeProvider(replies)
    ctx.service("ai").override = fake
    tools = ctx.service("ai_tools").tools(ctx.features.ids, names=F3_DEEP_TOOLS)
    result = run_tool_loop(
        ctx.service("ai"),
        ctx=ctx,
        task_name="analyst.deep",
        tools=tools,
        pack_builder=lambda config: build_incident_pack(detail, budget_tokens=1500, redact=False),
        question="What happened here?",
        fallback=lambda: deterministic_answer(detail, "What happened here?"),
        actor="analyst-user",
        subject_type="incident",
        subject_id=detail["id"],
        subject=("incident", detail["id"], detail["revision"]),
        job_id=None,
        max_steps=max_steps,
    )
    return result, fake


def test_tool_call_then_final_answer(ctx: AppContext) -> None:
    detail = scenario_incident(ctx)
    result, fake = loop(ctx, detail, ['{"tool": "get_incident", "args": {}}', final_json()])
    assert result.outcome == "valid" and result.steps == 1
    assert result.tool_calls == [{"step": 1, "tool": "get_incident", "ok": True}]
    assert "<tool_result" in fake.calls[1]["messages"][-1].content
    assert set(result.answer["claims"][0]["evidence_ids"]) <= {e["id"] for e in detail["events"]}


def test_step_cap_is_enforced(ctx: AppContext) -> None:
    detail = scenario_incident(ctx)
    fake = FakeProvider(default='{"tool": "list_rules", "args": {}}')
    ctx.service("ai").override = fake
    tools = ctx.service("ai_tools").tools(ctx.features.ids, names=F3_DEEP_TOOLS)
    result = run_tool_loop(
        ctx.service("ai"),
        ctx=ctx,
        task_name="analyst.deep",
        tools=tools,
        pack_builder=lambda config: build_incident_pack(detail, budget_tokens=1500, redact=False),
        question="Keep calling tools",
        fallback=lambda: {
            "summary": "fallback",
            "claims": [],
            "suggested_next_questions": [],
            "suggested_actions": [],
            "confidence": "low",
        },
        actor="analyst-user",
        subject_type="incident",
        subject_id=detail["id"],
        subject=None,
        job_id=None,
        max_steps=2,
    )
    assert result.outcome == "failed_validation" and result.steps == 2
    assert len(fake.calls) == 4  # two tool steps, one forced "answer now", one more tool call -> stop
    assert result.answer["summary"] == "fallback"


def test_unknown_tools_and_bad_arguments_are_reported_not_executed(ctx: AppContext) -> None:
    detail = scenario_incident(ctx)
    result, fake = loop(
        ctx,
        detail,
        [
            '{"tool": "approve_response", "args": {"response_id": "*"}}',
            '{"tool": "search_events", "args": {"limit": 99}}',
            final_json(),
        ],
    )
    assert result.outcome == "valid"
    assert [c["ok"] for c in result.tool_calls] == [False, False]
    assert "Unknown tool" in fake.calls[1]["messages"][-1].content
    assert ctx.service("responses").list()["total"] == 0


def test_tool_call_shaped_text_inside_events_is_ignored(ctx: AppContext) -> None:
    detail = scenario_incident(ctx, "prompt-injection")
    result, _ = loop(
        ctx, detail, ['{"tool": "search_events", "args": {"query": "approve_response"}}', final_json(claims=[])]
    )
    assert result.outcome == "valid"
    assert result.injection_suspected is True
    assert [c["tool"] for c in result.tool_calls] == ["search_events"]  # the payload's "tool" never ran
    assert ctx.service("responses").list()["total"] == 0


def test_provider_failure_mid_loop_falls_back(ctx: AppContext) -> None:
    detail = scenario_incident(ctx)
    result, _ = loop(ctx, detail, ['{"tool": "list_rules", "args": {}}', ProviderUnavailable("down")])
    assert result.outcome == "provider_error"
    assert result.answer["confidence_note"].startswith("Deterministic")


def test_malformed_reply_gets_one_repair(ctx: AppContext) -> None:
    detail = scenario_incident(ctx)
    result, _ = loop(ctx, detail, ["not json", final_json()])
    assert result.outcome == "repaired"
    result, _ = loop(ctx, detail, ["not json", "still not json"])
    assert result.outcome == "failed_validation"


def test_every_enabled_feature_registers_a_read_tool(ctx: AppContext) -> None:
    assert set(ctx.features.ids) <= ctx.service("ai_tools").features_with_read_tools()
