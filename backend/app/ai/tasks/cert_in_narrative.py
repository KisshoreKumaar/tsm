"""I1 report.cert_in_narrative: the description field of a CERT-In draft, written from the F2 story.

The story is already deterministic and cited, so the AI only rewrites it in plain language. Output is accepted only
when it cites valid evidence and repeats no instruction-like text; otherwise the story's own executive lines are used.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.ai.evidence import EvidencePack, build_incident_pack
from app.ai.guardrails import OutputInvalid, ValidationStats, looks_injected
from app.ai.prompts import load_prompt
from app.ai.providers.base import ChatMessage, estimate_tokens
from app.ai.providers.factory import ProviderConfig
from app.ai.runtime import TaskSpec, build_messages
from app.ai.tasks.common import output_limits, pack_budget, render

DETERMINISTIC_NOTE = "Written from the deterministic incident story (LLM not used). Review and edit before filing."
AI_NOTE = "Drafted by the AI from the incident story and validated against the evidence. Review and edit before filing."
MAX_DESCRIPTION = 4000


def _clean(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def story_lines(story: Mapping[str, Any]) -> list[tuple[str, list[str]]]:
    return [
        (str(line["sentence"]["text"]), list(line["sentence"].get("evidence_ids") or []))
        for line in story["executive"]["lines"]
    ]


def deterministic_narrative(story: Mapping[str, Any]) -> dict[str, Any]:
    lines = story_lines(story)
    return {
        "description": " ".join(text for text, _ in lines)[:MAX_DESCRIPTION],
        "evidence_ids": sorted({event_id for _, ids in lines for event_id in ids})[:20],
        "provenance": "auto",
        "note": DETERMINISTIC_NOTE,
    }


def narrative_task(detail: Mapping[str, Any], story: Mapping[str, Any]) -> tuple[TaskSpec, Any]:
    system_version, system = load_prompt("system")
    narrative_version, template = load_prompt("cert_in_narrative")
    lines = story_lines(story)

    def build(config: ProviderConfig) -> tuple[list[ChatMessage], EvidencePack]:
        limits = output_limits(config.max_output_tokens)
        words = max(80, limits["summary_words"] * 4)
        rendered = "\n".join(f"- {text}" for text, _ in lines) or "- (no story lines)"
        instructions = render(template, story=rendered, summary_words=words)
        overhead = estimate_tokens(system) + estimate_tokens(instructions) + 40
        pack = build_incident_pack(detail, budget_tokens=pack_budget(config, overhead), redact=config.redact)
        return build_messages(system, instructions, pack), pack

    def parse(obj: dict[str, Any], pack: EvidencePack) -> tuple[dict[str, Any], ValidationStats]:
        description = pack.restore(_clean(obj.get("d"), MAX_DESCRIPTION))
        if len(description) < 40:
            raise OutputInvalid('"d" must be a description of at least 40 characters')
        if looks_injected(description):
            raise OutputInvalid("The description repeated instruction-like text from the evidence")
        aliases = obj.get("e")
        valid, invalid = pack.resolve([str(a) for a in aliases]) if isinstance(aliases, list) else ([], [])
        if not valid:
            raise OutputInvalid("The description must cite at least one valid evidence alias")
        stats = ValidationStats()
        stats.total, stats.grounded = 1, 1
        stats.invalid_aliases.extend(invalid)
        return (
            {"description": description, "evidence_ids": valid, "provenance": "ai", "note": AI_NOTE},
            stats,
        )

    spec = TaskSpec(
        name="report.cert_in_narrative",
        prompt_version=f"{system_version}+{narrative_version}",
        max_output_tokens=500,
        parse=parse,
        fallback=lambda: deterministic_narrative(story),
    )
    return spec, build
