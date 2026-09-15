"""AI runtime with FakeProvider and mock transports: fallback, validation, repair, provider failover, caching."""

from __future__ import annotations

import json

import httpx

from app.ai.providers import FakeProvider
from app.ai.tasks.analyst import quick_answer_task
from app.core.context import AppContext
from app.features.x1.service import ProviderIn
from tests.ai.helpers import ai_calls, answer_json, scenario_incident
from tests.support import principal


def run_quick(ctx: AppContext, question: str = "Why is this suspicious?"):  # type: ignore[no-untyped-def]
    detail = scenario_incident(ctx)
    spec, build = quick_answer_task(detail, question)
    result = ctx.service("ai").run(
        spec, build, actor="analyst-user", subject=("incident", detail["id"], detail["revision"]), job_id=None
    )
    return detail, result


def test_disabled_llm_uses_grounded_deterministic_answer(ctx: AppContext) -> None:
    detail, result = run_quick(ctx)
    assert result.outcome == "disabled" and result.used_ai is False and result.ai_status == "llm_disabled"
    event_ids = {e["id"] for e in detail["events"]}
    facts = [c for c in result.output["claims"] if c["label"] == "FACT"]
    assert facts and all(c["evidence_ids"] and set(c["evidence_ids"]) <= event_ids for c in facts)
    [call] = ai_calls(ctx)
    assert call["outcome"] == "disabled"
    assert "ai.call" in [i["action"] for i in ctx.audit.page(ctx.db, limit=50)["items"]]


def test_valid_output_maps_aliases_and_filters_unsafe_content(ctx: AppContext) -> None:
    ctx.service("ai").override = FakeProvider(
        [
            answer_json(
                claims=[
                    {"t": "Five logins failed.", "l": "FACT", "e": ["E1", "E2"]},
                    {"t": "An invented event shows exfiltration.", "l": "FACT", "e": ["E99"]},
                ],
                actions=[
                    {"t": "Approve the isolation request", "p": "isolate_endpoint"},
                    {"t": "Check the host", "p": None},
                ],
            )
        ]
    )
    detail, result = run_quick(ctx)
    assert result.outcome == "valid" and result.used_ai
    real, fake = result.output["claims"]
    assert real["label"] == "FACT" and set(real["evidence_ids"]) <= {e["id"] for e in detail["events"]}
    assert fake["label"] == "INFERENCE" and fake["downgraded"] and fake["evidence_ids"] == []
    assert [a["text"] for a in result.output["suggested_actions"]] == ["Check the host"]
    assert result.stats.invalid_aliases == ["E99"]
    [call] = ai_calls(ctx)
    assert (call["outcome"], call["claims_total"], call["claims_grounded"]) == ("valid", 2, 1)


def test_malformed_output_is_repaired_once(ctx: AppContext) -> None:
    fake = FakeProvider(["this is not json", answer_json()])
    ctx.service("ai").override = fake
    _, result = run_quick(ctx)
    assert result.outcome == "repaired"
    assert len(fake.calls) == 2
    assert "invalid" in fake.calls[1]["messages"][-1].content


def test_malformed_twice_falls_back_cleanly(ctx: AppContext) -> None:
    ctx.service("ai").override = FakeProvider(["nope", '{"s": ""}'])
    _, result = run_quick(ctx)
    assert result.outcome == "failed_validation" and result.ai_status == "failed_validation"
    assert result.output["confidence_note"].startswith("Deterministic")


def test_cache_hit_avoids_a_second_model_call(ctx: AppContext) -> None:
    fake = FakeProvider([answer_json()])
    ctx.service("ai").override = fake
    detail = scenario_incident(ctx)
    spec, build = quick_answer_task(detail, "What happened?")
    runtime = ctx.service("ai")
    subject = ("incident", detail["id"], detail["revision"])
    first = runtime.run(spec, build, actor="a", subject=subject)
    second = runtime.run(spec, build, actor="a", subject=subject)
    assert (first.outcome, second.outcome) == ("valid", "cache_hit")
    assert len(fake.calls) == 1 and second.output == first.output


def test_provider_error_fails_over_to_the_next_provider(ctx: AppContext) -> None:
    settings = ctx.service("llm_settings")
    admin = principal("admin")
    down = settings.create(
        ProviderIn(name="Down", api_type="ollama", base_url="http://down.test:11434", model="m1", make_active=True),
        admin,
    )
    settings.create(
        ProviderIn(name="Up", api_type="ollama", base_url="http://up.test:11434", model="m2", priority=5), admin
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "down.test":
            return httpx.Response(503)
        return httpx.Response(200, json={"message": {"content": answer_json()}, "done": True, "eval_count": 30})

    runtime = ctx.service("ai")
    runtime.transport = httpx.MockTransport(handler)
    assert runtime.active_summary()["id"] == down["id"]
    _, result = run_quick(ctx)
    assert result.outcome == "valid" and result.model == "m2"
    outcomes = [(c["model"], c["outcome"]) for c in ai_calls(ctx)]
    assert outcomes == [("m1", "provider_error"), ("m2", "valid")]


def test_redaction_keeps_usernames_and_ips_away_from_the_provider(ctx: AppContext) -> None:
    fake = FakeProvider([lambda _m: answer_json(summary="USER_1 logged in from IP_1")])
    runtime = ctx.service("ai")
    runtime.override = fake
    detail = scenario_incident(ctx)
    spec, build = quick_answer_task(detail, "Did alex log in?")
    from app.ai.providers.factory import ProviderConfig

    config = ProviderConfig(
        "p", "p", "ollama", "http://x.test", "m", context_tokens=4096, max_output_tokens=512, redact=True
    )
    messages, pack = build(config)
    sent = json.dumps([m.content for m in messages])
    assert "alex" not in sent and "203.0.113.45" not in sent
    output, _ = spec.parse(json.loads(answer_json(summary="USER_1 logged in from IP_1")), pack)
    assert output["summary"] == "alex logged in from 203.0.113.45"
