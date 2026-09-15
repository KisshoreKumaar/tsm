"""F3 quick analyst answers: one model call over a compact evidence pack, with deterministic template answers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.ai.evidence import EvidencePack, build_incident_pack
from app.ai.guardrails import ValidationStats
from app.ai.prompts import load_prompt
from app.ai.providers.base import ChatMessage, estimate_tokens
from app.ai.providers.factory import ProviderConfig
from app.ai.runtime import TaskSpec, build_messages
from app.ai.tasks.common import expand_answer, output_limits, pack_budget, render

QUICK_PROMPTS = {
    "why_suspicious": "Why is this suspicious?",
    "explain_risk": "Explain the risk.",
    "what_happened": "What happened?",
    "false_positive": "Is this a false positive?",
    "likely_next": "What is likely next?",
    "what_now": "What should I do now?",
}
SCOPE_NOTE = (
    "AEGIS answers only from this incident's evidence and rule analysis. It cannot look anything up externally or "
    "verify intent, so it can explain what happened, why it is suspicious, the risk, false-positive considerations "
    "and sensible next investigation steps."
)


def _claim(text: str, label: str, evidence: list[str] | None = None) -> dict[str, Any]:
    return {
        "text": text,
        "label": label,
        "evidence_ids": list(evidence or []),
        "citations_rejected": 0,
        "downgraded": False,
    }


def deterministic_answer(detail: Mapping[str, Any], question: str) -> dict[str, Any]:
    """Template answers built only from stored analysis, so they stay grounded when the LLM is unavailable."""
    q = question.lower()
    analysis = detail["analysis"]
    claims = analysis.get("claims", [])
    facts = [_claim(c["text"], "FACT", c["evidence_ids"]) for c in claims if c["label"] == "FACT"]
    inferences = [_claim(c["text"], "INFERENCE", c["evidence_ids"]) for c in claims if c["label"] == "INFERENCE"]
    hypotheses = [_claim(c["text"], "HYPOTHESIS", c["evidence_ids"]) for c in claims if c["label"] == "HYPOTHESIS"]
    unknowns = [_claim(c["text"], "UNKNOWN") for c in claims if c["label"] == "UNKNOWN"]
    risk = {"score": detail["risk_score"], "severity": detail["severity"]}
    asset = detail["asset"]
    actions: list[dict[str, Any]] = [
        {"text": f"Confirm with the owner of {asset} whether this activity was authorised", "playbook": None}
    ]
    questions = [
        "Was this activity authorised by the asset owner?",
        "Which other assets did this user or source address touch?",
    ]

    if "false positive" in q or "benign" in q or "legit" in q:
        summary = (
            "AEGIS cannot confirm or rule out a false positive from rule evidence alone; the caveats below describe "
            "legitimate activity that matches the same rules."
        )
        answer_claims = [*facts[:2], *inferences, *unknowns]
    elif "risk" in q or "severe" in q or "score" in q:
        factors = [f for f in (detail.get("risk", {}).get("factors") or []) if f.get("points")]
        summary = f"Risk is {risk['severity']} ({risk['score']}/100). This heuristic ranks attention; it is not a probability."
        answer_claims = [
            _claim(f"{f['label']}: {f['points']}/{f['max_points']} — {f['explanation']}", "INFERENCE")
            for f in factors[:6]
        ]
        answer_claims += facts[:2]
    elif "happen" in q or "summar" in q or "timeline" in q:
        stages = [s["stage"] for s in analysis.get("stages", [])]
        summary = f"Correlated activity on {asset} progressed through: {', '.join(stages) or 'no tactic stages'}."
        answer_claims = facts
    elif "next" in q or "likely" in q or "predict" in q:
        summary = "Possible next steps are hypotheses drawn from the observed stages; watch for the related activity."
        answer_claims = hypotheses or [_claim("No hypothesis is available for the observed stages.", "UNKNOWN")]
        questions = [
            "Has the account authenticated anywhere else since?",
            "Did the host start new outbound connections?",
        ]
    elif "do" in q or "should" in q or "action" in q or "respond" in q:
        summary = "Recommended investigation steps; containment requests are simulated and need human approval."
        answer_claims = [*facts[:2], *hypotheses[:1]]
        if risk["severity"] in ("HIGH", "CRITICAL"):
            actions.append(
                {"text": "Collect an evidence manifest before changing anything", "playbook": "collect_evidence"}
            )
            actions.append(
                {
                    "text": f"Consider requesting simulated isolation of {asset} if compromise is confirmed",
                    "playbook": "isolate_endpoint",
                }
            )
    elif "suspicious" in q or "why" in q or "alert" in q:
        summary = "The detections below met their rule thresholds; each fact cites the events that triggered it."
        answer_claims = [*facts, *inferences[:2]]
    else:
        summary = "This question cannot be answered from the incident's evidence. " + SCOPE_NOTE
        answer_claims = [_claim("The evidence available to AEGIS does not address this question.", "UNKNOWN")]
        actions = []
    return {
        "summary": summary,
        "claims": answer_claims[:8],
        "suggested_next_questions": questions[:3],
        "suggested_actions": actions[:4],
        "confidence": "low",
        "confidence_note": "Deterministic template answer (LLM not used).",
        "actions_removed": 0,
    }


def quick_answer_task(detail: Mapping[str, Any], question: str) -> tuple[TaskSpec, Any]:
    system_version, system = load_prompt("system")
    quick_version, template = load_prompt("analyst_quick")

    def build(config: ProviderConfig) -> tuple[list[ChatMessage], EvidencePack]:
        instructions = render(template, **output_limits(config.max_output_tokens))
        overhead = estimate_tokens(system) + estimate_tokens(instructions) + estimate_tokens(question) + 40
        pack = build_incident_pack(detail, budget_tokens=pack_budget(config, overhead), redact=config.redact)
        asked = pack.redactor.redact(question) if pack.redactor is not None else question
        return build_messages(system, instructions, pack, question=asked), pack

    def parse(obj: dict[str, Any], pack: EvidencePack) -> tuple[dict[str, Any], ValidationStats]:
        return expand_answer(obj, pack)

    spec = TaskSpec(
        name="analyst.answer",
        prompt_version=f"{system_version}+{quick_version}",
        max_output_tokens=600,
        parse=parse,
        fallback=lambda: deterministic_answer(detail, question),
    )
    return spec, build
