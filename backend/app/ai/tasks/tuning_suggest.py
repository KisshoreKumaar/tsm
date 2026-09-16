"""A5 tuning.suggest: AI ranking and rationale for proposed tuning changes. It never alters scope or impact."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.ai.evidence import EvidencePack, Redactor
from app.ai.guardrails import OutputInvalid, ValidationStats, looks_injected
from app.ai.prompts import load_prompt
from app.ai.providers.base import ChatMessage
from app.ai.providers.factory import ProviderConfig
from app.ai.runtime import TaskSpec, build_messages
from app.ai.tasks.common import output_limits, render

DETERMINISTIC_NOTE = (
    "Ranked by simulated impact (LLM not used): no true-positive loss first, then most false positives removed."
)
AI_NOTE = (
    "AI ranking and rationale. Scopes and simulated impact are unchanged and every change still needs human approval."
)


def _clean(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def describe_scope(suggestion: Mapping[str, Any]) -> str:
    scope = suggestion["scope"]
    parts = [f"{e['type']}={e['value']}" for e in scope.get("entities") or []]
    if scope.get("schedule"):
        schedule = scope["schedule"]
        parts.append(f"days {','.join(str(d) for d in schedule['days'])} {schedule['start']}-{schedule['end']} UTC")
    if scope.get("threshold") is not None:
        parts.append(f"threshold {scope['threshold']}")
    if scope.get("window_seconds") is not None:
        parts.append(f"window {scope['window_seconds']}s")
    if scope.get("exclusion"):
        exclusion = scope["exclusion"]
        parts.append(f"exclude {exclusion['field']} {exclusion['op']} {exclusion['value']}")
    return " ".join(parts) or "rule-wide"


def _impact(suggestion: Mapping[str, Any]) -> tuple[int, int, bool]:
    impact = suggestion.get("impact") or {}
    return (
        int(impact.get("false_positive_alerts_removed", 0)),
        int(impact.get("true_positive_alerts_removed", 0)),
        bool(impact.get("red_flag")),
    )


def default_rationale(suggestion: Mapping[str, Any]) -> str:
    false_positive, true_positive, _ = _impact(suggestion)
    return f"Removes {false_positive} false-positive and {true_positive} true-positive alert(s) in the simulated range."


def deterministic_ranking(suggestions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ordered = sorted(
        suggestions, key=lambda s: (_impact(s)[2], -_impact(s)[0], _impact(s)[1], str(s["created_at"]), str(s["id"]))
    )
    return {
        "ranking": [
            {"suggestion_id": s["id"], "rank": rank, "rationale": default_rationale(s)}
            for rank, s in enumerate(ordered, start=1)
        ],
        "note": DETERMINISTIC_NOTE,
    }


def tuning_rank_task(suggestions: Sequence[Mapping[str, Any]]) -> tuple[TaskSpec, Any]:
    system_version, system = load_prompt("system")
    rank_version, template = load_prompt("tuning_suggest")
    items = list(suggestions)
    by_ref = {f"S{index}": suggestion for index, suggestion in enumerate(items, start=1)}
    fallback_order = [entry["suggestion_id"] for entry in deterministic_ranking(items)["ranking"]]

    def build(config: ProviderConfig) -> tuple[list[ChatMessage], EvidencePack]:
        users = [e["value"] for s in items for e in s["scope"].get("entities") or [] if e["type"] == "user"]
        redactor = Redactor(users) if config.redact else None
        lines = []
        for ref, suggestion in by_ref.items():
            false_positive, true_positive, _ = _impact(suggestion)
            line = (
                f"{ref} {suggestion['rule_id']} {suggestion['type']} {describe_scope(suggestion)} | "
                f"FP closures {suggestion['evidence'].get('closures', 0)} | FP alerts removed {false_positive} | "
                f"TP alerts removed {true_positive}"
            )
            lines.append(redactor.redact(line) if redactor is not None else line)
        limits = output_limits(config.max_output_tokens)
        instructions = render(template, suggestions="\n".join(lines), claim_words=limits["claim_words"])
        pack = EvidencePack(data={}, alias_to_event={}, redactor=redactor)
        return build_messages(system, instructions, pack), pack

    def parse(obj: dict[str, Any], pack: EvidencePack) -> tuple[dict[str, Any], ValidationStats]:
        raw = obj.get("r")
        if not isinstance(raw, list) or not raw:
            raise OutputInvalid('"r" must be a non-empty list of ranked suggestion ids')
        stats = ValidationStats()
        ranked: list[str] = []
        reasons: dict[str, str] = {}
        for item in raw[: len(by_ref) + 2]:
            if not isinstance(item, Mapping):
                raise OutputInvalid("Each ranked entry must be an object")
            stats.total += 1
            ref = str(item.get("id", "")).strip().upper()
            text = pack.restore(_clean(item.get("t"), 300))
            if ref not in by_ref or ref in ranked or not text or looks_injected(text):
                stats.dropped += 1
                continue
            ranked.append(ref)
            reasons[ref] = text
            stats.grounded += 1
        if not ranked:
            raise OutputInvalid("No listed suggestion id was ranked (use S1, S2, ...)")
        ids = [by_ref[ref]["id"] for ref in ranked]
        ids += [suggestion_id for suggestion_id in fallback_order if suggestion_id not in ids]
        rationale = {by_ref[ref]["id"]: reasons[ref] for ref in ranked}
        by_id = {s["id"]: s for s in items}
        return (
            {
                "ranking": [
                    {
                        "suggestion_id": suggestion_id,
                        "rank": rank,
                        "rationale": rationale.get(suggestion_id) or default_rationale(by_id[suggestion_id]),
                    }
                    for rank, suggestion_id in enumerate(ids, start=1)
                ],
                "note": AI_NOTE,
            },
            stats,
        )

    spec = TaskSpec(
        name="tuning.suggest",
        prompt_version=f"{system_version}+{rank_version}",
        max_output_tokens=300,
        parse=parse,
        fallback=lambda: deterministic_ranking(items),
    )
    return spec, build
