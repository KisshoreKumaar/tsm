"""A3 rules.draft: an AI-drafted DSL rule, accepted only if it validates and matches the incident it came from."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, get_args

from app.ai.evidence import EvidencePack, build_incident_pack
from app.ai.guardrails import OutputInvalid, ValidationStats, looks_injected
from app.ai.prompts import load_prompt
from app.ai.providers.base import ChatMessage, estimate_tokens
from app.ai.providers.factory import ProviderConfig
from app.ai.runtime import TaskSpec, build_messages
from app.ai.tasks.common import pack_budget, render
from app.detection.base import Event
from app.detection.catalog import TechniqueCatalog
from app.prediction.signals import NUMERIC_FIELDS, STRING_FIELDS, EventKind
from app.rules.draft import draft_from_incident
from app.rules.dsl import CompiledRule, RuleValidationError, validate_definition


def _clean(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _restore(value: Any, pack: EvidencePack) -> Any:
    if isinstance(value, str):
        return pack.restore(value)
    if isinstance(value, list):
        return [pack.restore(item) if isinstance(item, str) else item for item in value]
    return value


def deterministic_rule_draft(detail: Mapping[str, Any]) -> dict[str, Any]:
    definition, rationale = draft_from_incident(detail)
    return {"definition": definition, "rationale": rationale, "source": "deterministic_draft"}


def rules_draft_task(
    detail: Mapping[str, Any], events: Sequence[Event], catalog: TechniqueCatalog, existing_rules: Sequence[str]
) -> tuple[TaskSpec, Any]:
    system_version, system = load_prompt("system")
    draft_version, template = load_prompt("rules_draft")
    techniques = sorted({t for d in detail["detections"] for t in d["techniques"]}) or [t.id for t in catalog.all()]

    def build(config: ProviderConfig) -> tuple[list[ChatMessage], EvidencePack]:
        instructions = render(
            template,
            rules="; ".join(existing_rules)[:500],
            kinds=", ".join(get_args(EventKind)),
            fields=", ".join(sorted(STRING_FIELDS | NUMERIC_FIELDS)),
            techniques=", ".join(techniques[:15]),
        )
        overhead = estimate_tokens(system) + estimate_tokens(instructions) + 40
        pack = build_incident_pack(detail, budget_tokens=pack_budget(config, overhead), redact=config.redact)
        return build_messages(system, instructions, pack), pack

    def parse(obj: dict[str, Any], pack: EvidencePack) -> tuple[dict[str, Any], ValidationStats]:
        raw_conditions = obj.get("c") or []
        if not isinstance(raw_conditions, list):
            raise OutputInvalid('"c" must be a list of [field, op, value] conditions')
        conditions = []
        for item in raw_conditions[:10]:
            if isinstance(item, list) and len(item) == 3:
                field, op, value = item
            elif isinstance(item, Mapping):
                field, op, value = item.get("field"), item.get("op"), item.get("value")
            else:
                raise OutputInvalid("Each condition must be [field, op, value]")
            conditions.append({"field": field, "op": op, "value": _restore(value, pack)})
        name = pack.restore(_clean(obj.get("n"), 120))
        rationale = pack.restore(_clean(obj.get("r"), 600))
        if looks_injected(name) or looks_injected(rationale):
            raise OutputInvalid("The draft repeated instruction-like text from the evidence")
        distinct = obj.get("df")
        threshold = {"type": "distinct_count", "field": distinct, "value": obj.get("t", 1)} if distinct else None
        definition = {
            "name": name or "AI-drafted rule",
            "description": f"AI draft from incident {str(detail['id'])[:8]}: {rationale or 'see rationale'}"[:1000],
            "severity": str(obj.get("s", "MEDIUM")).upper(),
            "confidence": 50,
            "techniques": obj.get("x") or [],
            "known_false_positives": [
                text
                for text in (_clean(v, 200) for v in (obj.get("fp") or [])[:5])
                if text and not looks_injected(text)
            ],
            "logic": {
                "kinds": obj.get("k"),
                "conditions": conditions,
                "group_by": obj.get("g") or ["asset", "user"],
                "window_seconds": obj.get("w", 300),
                "threshold": threshold or {"type": "count", "value": obj.get("t", 1)},
            },
        }
        try:
            validated = validate_definition(definition, catalog)
        except RuleValidationError as exc:
            location = ".".join(exc.errors[0]["loc"]) if exc.errors else "rule"
            raise OutputInvalid(f"The drafted rule is invalid at {location}: {exc}") from None
        if not CompiledRule.build("DRAFT-000", 1, validated, catalog).evaluate(events):
            raise OutputInvalid("The drafted rule does not match the incident it was drafted from")
        stats = ValidationStats()
        stats.total, stats.grounded = 1, 1
        return (
            {"definition": validated.model_dump(mode="json"), "rationale": rationale, "source": "ai_draft"},
            stats,
        )

    spec = TaskSpec(
        name="rules.draft",
        prompt_version=f"{system_version}+{draft_version}",
        max_output_tokens=500,
        parse=parse,
        fallback=lambda: deterministic_rule_draft(detail),
    )
    return spec, build
