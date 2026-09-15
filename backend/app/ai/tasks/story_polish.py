"""F2 AI polish (`story.narrate`): rewrite deterministic story sentences in plainer language, strictly validated.

A rewrite is accepted only if it keeps the same sentence IDs and labels, cites only aliases the draft sentence cited
(and at least one for FACTs), keeps every number from the draft, and does not echo instruction-like text. Any chunk
that fails validation (after one repair) keeps the whole story deterministic.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from app.ai.evidence import EvidencePack, build_incident_pack
from app.ai.guardrails import OutputInvalid, ValidationStats, looks_injected
from app.ai.prompts import load_prompt
from app.ai.providers.base import ChatMessage, estimate_tokens
from app.ai.providers.factory import ProviderConfig
from app.ai.runtime import AIRuntime, TaskResult, TaskSpec
from app.story.builder import all_sentences, validate_citations

NUMBER_RE = re.compile(r"\d+(?:[.:]\d+)*")


def polish_targets(story: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Executive lines and stage sentences whose basis is event evidence."""
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in story["executive"]["lines"]:
        sentence = line["sentence"]
        if sentence["basis"] == "events" and sentence["id"] not in seen:
            targets.append(sentence)
            seen.add(sentence["id"])
    for stage in story["stages"]:
        sentence = stage["sentence"]
        if sentence["basis"] == "events" and sentence["id"] not in seen:
            targets.append(sentence)
            seen.add(sentence["id"])
    return targets


def chunk(items: Sequence[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    return [list(items[i : i + size]) for i in range(0, len(items), size)]


def _task(detail: Mapping[str, Any], sentences: list[dict[str, Any]]) -> tuple[TaskSpec, Any]:
    system_version, system = load_prompt("system")
    narrate_version, template = load_prompt("story_narrate")
    allowed: dict[str, set[str]] = {}

    def build(config: ProviderConfig) -> tuple[list[ChatMessage], EvidencePack]:
        pack = build_incident_pack(detail, budget_tokens=max(300, config.context_tokens // 2), redact=config.redact)
        events_by_id = {e["id"]: e for e in detail["events"]}
        needed = [events_by_id[eid] for s in sentences for eid in s["evidence_ids"] if eid in events_by_id]
        pack.add_events([e for e in needed if e["id"] not in pack.event_to_alias])
        draft_rows = []
        for sentence in sentences:
            aliases = [pack.event_to_alias[eid] for eid in sentence["evidence_ids"] if eid in pack.event_to_alias]
            allowed[sentence["id"]] = set(aliases)
            text = pack.redactor.redact(sentence["text"]) if pack.redactor is not None else sentence["text"]
            draft_rows.append({"id": sentence["id"], "t": text, "l": sentence["label"], "e": aliases})
        draft = "\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in draft_rows)
        instructions = template.replace("{sentence_words}", "45").replace("{draft}", draft)
        messages = [ChatMessage("system", system), ChatMessage("user", f"{instructions}\n{pack.data_block()}")]
        return messages, pack

    def parse(obj: dict[str, Any], pack: EvidencePack) -> tuple[dict[str, Any], ValidationStats]:
        items = obj.get("s")
        if not isinstance(items, list):
            raise OutputInvalid('Expected {"s": [...]}')
        by_id = {s["id"]: s for s in sentences}
        rewritten: dict[str, dict[str, Any]] = {}
        stats = ValidationStats()
        for item in items:
            if not isinstance(item, Mapping) or item.get("id") not in by_id:
                raise OutputInvalid("Each item must use one of the draft sentence ids")
            original = by_id[str(item["id"])]
            text = item.get("t")
            if not isinstance(text, str) or not text.strip():
                raise OutputInvalid(f"Sentence {item['id']} has no text")
            text = pack.restore(" ".join(text.split())[:500])
            label = str(item.get("l", "")).upper()
            if label != original["label"]:
                raise OutputInvalid(f"Sentence {item['id']} changed its label")
            aliases = [str(a).upper() for a in (item.get("e") or [])]
            if any(alias not in allowed.get(original["id"], set()) for alias in aliases):
                raise OutputInvalid(f"Sentence {item['id']} cites evidence the draft did not cite")
            if label == "FACT" and not aliases:
                raise OutputInvalid(f"FACT sentence {item['id']} lost its citations")
            missing = sorted(set(NUMBER_RE.findall(original["text"])) - set(NUMBER_RE.findall(text)))
            if missing:
                raise OutputInvalid(f"Sentence {item['id']} dropped or changed numbers {missing[:3]}")
            if looks_injected(text):
                raise OutputInvalid(f"Sentence {item['id']} contains instruction-like text")
            valid, _ = pack.resolve(aliases)
            stats.total += 1
            stats.grounded += 1 if valid else 0
            rewritten[original["id"]] = {"text": text, "evidence_ids": valid}
        if set(rewritten) != set(by_id):
            raise OutputInvalid("Every draft sentence must be returned exactly once")
        return {"s": rewritten}, stats

    spec = TaskSpec(
        name="story.narrate",
        prompt_version=f"{system_version}+{narrate_version}",
        max_output_tokens=80 * len(sentences) + 40,
        parse=parse,
        fallback=lambda: {"s": {}},
    )
    return spec, build


def polish_story(
    runtime: AIRuntime,
    detail: Mapping[str, Any],
    story: Mapping[str, Any],
    *,
    actor: str,
    job_id: str | None = None,
) -> tuple[dict[str, Any], list[TaskResult]]:
    """Returns (story, results). The story is AI-polished only if every chunk validated; otherwise it is unchanged."""
    chain = runtime.provider_chain()
    if not chain:
        return dict(story), []
    small = chain[0][0].max_output_tokens <= 200
    targets = polish_targets(story)
    results: list[TaskResult] = []
    replacements: dict[str, dict[str, Any]] = {}
    subject = ("incident", str(detail["id"]), int(detail["revision"]))
    for group in chunk(targets, 2 if small else len(targets) or 1):
        spec, build = _task(detail, group)
        result = runtime.run(spec, build, actor=actor, subject=subject, job_id=job_id)
        results.append(result)
        if not result.used_ai:
            return dict(story), results
        replacements.update(result.output["s"])
    polished = copy.deepcopy(dict(story))
    for sentence in all_sentences(polished):
        if sentence["id"] in replacements:
            sentence["text"] = replacements[sentence["id"]]["text"]
            sentence["evidence_ids"] = replacements[sentence["id"]]["evidence_ids"]
    for stage in polished["stages"]:
        if stage["sentence"]["id"] in replacements:
            stage["sentence"]["text"] = replacements[stage["sentence"]["id"]]["text"]
            stage["sentence"]["evidence_ids"] = replacements[stage["sentence"]["id"]]["evidence_ids"]
    problems = validate_citations(all_sentences(polished), {e["id"] for e in detail["events"]})
    if problems:
        return dict(story), results
    polished.update(
        source="ai_polished",
        badge="AI-polished (validated)",
        ai_status="validated",
        ai_provider=results[-1].provider_id if results else None,
        ai_model=results[-1].model if results else None,
        citations_valid=True,
    )
    polished["analyst"]["word_count"] = sum(
        len(s["text"].split()) for paragraph in polished["analyst"]["paragraphs"] for s in paragraph
    )
    return polished, results


def estimate_polish_calls(story: Mapping[str, Any], max_output_tokens: int) -> int:
    targets = len(polish_targets(story))
    return (targets + 1) // 2 if max_output_tokens <= 200 else 1


__all__ = ["estimate_polish_calls", "estimate_tokens", "polish_story", "polish_targets"]
