"""Shared helpers for AI tasks: output limits per provider size, prompt rendering and answer expansion."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.ai.evidence import EvidencePack
from app.ai.guardrails import (
    OutputInvalid,
    ValidationStats,
    filter_actions,
    looks_injected,
    string_list,
    validate_claims,
)
from app.ai.providers.factory import ProviderConfig

CONFIDENCE = ("low", "medium", "high")
WITHHELD_SUMMARY = "The model's summary was withheld because it repeated instruction-like text from the log data."


def output_limits(max_output_tokens: int) -> dict[str, int]:
    """Small models with ~160 output tokens must answer tersely; larger providers may say more."""
    if max_output_tokens <= 200:
        return {"summary_words": 20, "max_claims": 3, "claim_words": 15, "max_questions": 2, "max_actions": 2}
    if max_output_tokens <= 600:
        return {"summary_words": 40, "max_claims": 5, "claim_words": 25, "max_questions": 3, "max_actions": 3}
    return {"summary_words": 60, "max_claims": 6, "claim_words": 30, "max_questions": 3, "max_actions": 4}


def render(template: str, **values: Any) -> str:
    """Replace `{name}` placeholders without touching the JSON braces in templates."""
    for key, value in values.items():
        template = template.replace("{" + key + "}", str(value))
    return template


def pack_budget(config: ProviderConfig, overhead_tokens: int, output_tokens: int | None = None) -> int:
    reserve = min(output_tokens or config.max_output_tokens, config.max_output_tokens)
    return max(300, config.context_tokens - reserve - overhead_tokens - 96)


def expand_answer(obj: Mapping[str, Any], pack: EvidencePack) -> tuple[dict[str, Any], ValidationStats]:
    summary_raw = obj.get("s", obj.get("summary"))
    if not isinstance(summary_raw, str) or not summary_raw.strip():
        raise OutputInvalid('The answer needs a non-empty "s" summary string')
    summary = pack.restore(" ".join(summary_raw.split())[:600])
    if looks_injected(summary):
        summary = WITHHELD_SUMMARY
    claims, stats = validate_claims(obj.get("c", obj.get("claims")), pack)
    questions = [
        pack.restore(q)
        for q in string_list(obj.get("q", obj.get("suggested_next_questions")), limit=3)
        if not looks_injected(q)
    ]
    actions, removed = filter_actions(obj.get("a", obj.get("suggested_actions")), pack)
    confidence = str(obj.get("k", obj.get("confidence", "low"))).lower()
    return (
        {
            "summary": summary,
            "claims": claims,
            "suggested_next_questions": questions,
            "suggested_actions": actions,
            "confidence": confidence if confidence in CONFIDENCE else "low",
            "confidence_note": "Heuristic self-assessment, not a probability.",
            "actions_removed": removed,
        },
        stats,
    )
