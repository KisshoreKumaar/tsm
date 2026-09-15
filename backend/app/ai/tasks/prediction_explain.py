"""F4 prediction.explain: plain-language explanation of the top predictions. It never changes scores.

The model may add one "AI candidate" technique, accepted only if its ID is in the local ATT&CK catalog, it is not
already predicted, and its rationale cites valid evidence aliases. Candidates are unscored hypotheses.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.ai.evidence import EvidencePack, build_incident_pack
from app.ai.guardrails import OutputInvalid, ValidationStats, looks_injected
from app.ai.prompts import load_prompt
from app.ai.providers.base import ChatMessage, estimate_tokens
from app.ai.providers.factory import ProviderConfig
from app.ai.runtime import TaskSpec, build_messages
from app.ai.tasks.common import WITHHELD_SUMMARY, output_limits, pack_budget, render
from app.detection.catalog import TECHNIQUE_ID_RE, TechniqueCatalog

MAX_EXPLAINED = 5
DETERMINISTIC_NOTE = (
    "Deterministic explanation from the curated model (LLM not used). Scores are heuristics, not probabilities."
)
AI_NOTE = "AI explanation validated against evidence aliases. It cannot change scores; an AI candidate is unscored."


def _clean(value: Any, limit: int = 400) -> str:
    return " ".join(str(value or "").split())[:limit]


def deterministic_explanation(predictions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    top = list(predictions[:MAX_EXPLAINED])
    items = []
    for prediction in top:
        technique = prediction["technique"]
        watch = "; ".join(signal["text"] for signal in prediction["watch_signals"][:2])
        items.append(
            {
                "prediction_id": prediction["id"],
                "technique_id": technique["id"],
                "text": f"{technique['name']} ({technique['tactic']}) ranks {prediction['score']}/100 "
                f"({prediction['band']}) and is {prediction['status'].lower()}. {prediction['rationale']} "
                f"Watch for: {watch}.",
                "label": "HYPOTHESIS",
                "evidence_ids": list(prediction["evidence_ids"][:5]),
                "citations_rejected": 0,
            }
        )
    if top:
        watching = [p for p in top if p["status"] == "WATCHING"]
        observed = sum(1 for p in top if p["status"] == "OBSERVED")
        summary = f"{len(top)} ranked hypotheses: {observed} already observed, {len(watching)} still watched."
        if watching:
            summary += f" Highest-ranked open step: {watching[0]['technique']['name']} ({watching[0]['score']}/100, heuristic)."
    else:
        summary = "No next-step predictions exist for this incident's observed techniques."
    return {
        "summary": summary,
        "items": items,
        "ai_candidate": None,
        "candidate_rejected": None,
        "note": DETERMINISTIC_NOTE,
    }


def _candidate(
    raw: Any, pack: EvidencePack, catalog: TechniqueCatalog, predicted: set[str]
) -> tuple[dict[str, Any] | None, str | None]:
    if raw is None:
        return None, None
    if not isinstance(raw, Mapping):
        return None, "The AI candidate was not an object"
    technique_id = str(raw.get("technique", "")).strip()
    if not TECHNIQUE_ID_RE.fullmatch(technique_id) or technique_id not in catalog:
        return None, "The AI candidate's technique ID is not in the local ATT&CK catalog"
    if technique_id in predicted:
        return None, "The AI candidate duplicates an existing prediction"
    text = pack.restore(_clean(raw.get("t")))
    if not text or looks_injected(text):
        return None, "The AI candidate's rationale was empty or instruction-like"
    aliases = raw.get("e")
    valid, _ = pack.resolve([str(a) for a in aliases]) if isinstance(aliases, list) else ([], [])
    if not valid:
        return None, "The AI candidate did not cite valid evidence"
    technique = catalog.require(technique_id)
    return (
        {
            "technique_id": technique.id,
            "technique_name": technique.name,
            "tactics": list(technique.tactics),
            "url": technique.url,
            "text": text,
            "label": "HYPOTHESIS",
            "badge": "AI candidate",
            "evidence_ids": valid,
            "score": None,
            "note": "AI candidate: not scored and not watched. Verify it against the evidence before acting.",
        },
        None,
    )


def explain_task(
    detail: Mapping[str, Any], predictions: Sequence[Mapping[str, Any]], catalog: TechniqueCatalog
) -> tuple[TaskSpec, Any]:
    system_version, system = load_prompt("system")
    explain_version, template = load_prompt("prediction_explain")
    top = list(predictions[:MAX_EXPLAINED])
    by_ref = {f"P{index}": prediction for index, prediction in enumerate(top, start=1)}
    predicted = {prediction["technique"]["id"] for prediction in predictions}

    def build(config: ProviderConfig) -> tuple[list[ChatMessage], EvidencePack]:
        limits = output_limits(config.max_output_tokens)
        shown = list(by_ref.items())[: max(1, limits["max_claims"])]
        overhead = estimate_tokens(system) + estimate_tokens(template) + 30 * len(shown) + 40
        pack = build_incident_pack(detail, budget_tokens=pack_budget(config, overhead), redact=config.redact)
        alias_for = {event_id: alias for alias, event_id in pack.alias_to_event.items()}
        lines = []
        for ref, prediction in shown:
            technique = prediction["technique"]
            basis = [alias_for[e] for e in prediction["evidence_ids"] if e in alias_for][:3]
            lines.append(
                f"{ref} {technique['id']} {technique['name']} | {technique['tactic']} | score {prediction['score']} "
                f"{prediction['band']} | {prediction['status']} | basis {','.join(basis) or 'none'}"
            )
        instructions = render(
            template,
            predictions="\n".join(lines) or "(none)",
            summary_words=limits["summary_words"],
            max_items=len(shown),
            claim_words=limits["claim_words"],
        )
        return build_messages(system, instructions, pack), pack

    def parse(obj: dict[str, Any], pack: EvidencePack) -> tuple[dict[str, Any], ValidationStats]:
        summary_raw = obj.get("s")
        if not isinstance(summary_raw, str) or not summary_raw.strip():
            raise OutputInvalid('The explanation needs a non-empty "s" summary string')
        summary = pack.restore(_clean(summary_raw, 600))
        if looks_injected(summary):
            summary = WITHHELD_SUMMARY
        raw_items = obj.get("p", [])
        if not isinstance(raw_items, list):
            raise OutputInvalid('"p" must be a list of prediction explanations')
        stats = ValidationStats()
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw_items[:MAX_EXPLAINED]:
            if not isinstance(item, Mapping):
                raise OutputInvalid("Each prediction explanation must be an object")
            stats.total += 1
            ref = str(item.get("id", "")).strip().upper()
            prediction = by_ref.get(ref)
            text = pack.restore(_clean(item.get("t")))
            aliases = item.get("e") or []
            if prediction is None or ref in seen or not text or looks_injected(text) or not isinstance(aliases, list):
                stats.dropped += 1
                continue
            valid, invalid = pack.resolve([str(a) for a in aliases])
            stats.invalid_aliases.extend(invalid)
            if valid:
                stats.grounded += 1
            seen.add(ref)
            items.append(
                {
                    "prediction_id": prediction["id"],
                    "technique_id": prediction["technique"]["id"],
                    "text": text,
                    "label": "HYPOTHESIS",
                    "evidence_ids": valid,
                    "citations_rejected": len(invalid),
                }
            )
        if raw_items and not items:
            raise OutputInvalid("No explanation referred to a listed prediction id (use P1, P2, ...)")
        candidate, rejected = _candidate(obj.get("x"), pack, catalog, predicted)
        return (
            {
                "summary": summary,
                "items": items,
                "ai_candidate": candidate,
                "candidate_rejected": rejected,
                "note": AI_NOTE,
            },
            stats,
        )

    spec = TaskSpec(
        name="prediction.explain",
        prompt_version=f"{system_version}+{explain_version}",
        max_output_tokens=400,
        parse=parse,
        fallback=lambda: deterministic_explanation(predictions),
    )
    return spec, build
