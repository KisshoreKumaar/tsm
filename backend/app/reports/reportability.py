"""Reportability suggestion (I1). A starting point for a human, never a legal determination.

Categories are scored from the rules and techniques that fired and from keywords found in AEGIS's own detection
summaries. Raw event text is not scored: it is attacker-controlled and must not steer a compliance decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.reports.template import CertInTemplate, IncidentTypeOption

SUGGESTION_LABEL = "Suggestion — confirm with compliance or legal before relying on it."
RULE_POINTS = 3
TECHNIQUE_POINTS = 2
KEYWORD_POINTS = 1
# On a tie, prefer the category that is clearly reportable: under-reporting is the costlier mistake.
REPORTABLE_RANK = {"yes": 0, "likely": 1, "unlikely": 2}


def _score(option: IncidentTypeOption, rules: set[str], techniques: set[str], text: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    for rule_id in sorted(rules & set(option.rules)):
        score += RULE_POINTS
        reasons.append(f"rule {rule_id} fired")
    for technique in sorted(techniques & set(option.techniques)):
        score += TECHNIQUE_POINTS
        reasons.append(f"technique {technique} is mapped to this category")
    for keyword in sorted(option.keywords):
        if keyword.casefold() in text:
            score += KEYWORD_POINTS
            reasons.append(f"detection summaries mention {keyword!r}")
    return score, reasons


def suggest(detail: Mapping[str, Any], template: CertInTemplate) -> dict[str, Any]:
    active = [d for d in detail["detections"] if d["status"] == "ACTIVE"]
    rules = {d["rule_id"] for d in active}
    techniques = {t for d in active for t in d["techniques"]}
    text = " ".join(d["summary"] for d in active).casefold()

    scored = []
    for option in template.incident_types:
        score, reasons = _score(option, rules, techniques, text)
        if score > 0:
            scored.append((score, option, reasons))
    scored.sort(key=lambda item: (-item[0], REPORTABLE_RANK.get(item[1].reportable, 3), item[1].id))

    if scored:
        score, option, reasons = scored[0]
        confidence = "medium" if score >= RULE_POINTS + TECHNIQUE_POINTS else "low"
    else:
        option = template.incident_type("other") or template.incident_types[-1]
        score, reasons, confidence = 0, ["No mapped category matched the rules that fired"], "low"

    return {
        "incident_type": option.id,
        "incident_type_label": option.label,
        "reportable": option.reportable,
        "confidence": confidence,
        "score": score,
        "reasons": reasons[:8],
        "category_note": option.note,
        "alternatives": [
            {"incident_type": other.id, "label": other.label, "score": other_score}
            for other_score, other, _ in scored[1:4]
        ],
        "notes": list(template.data.reportability_notes),
        "label": SUGGESTION_LABEL,
        "template_status": template.data.status,
    }
