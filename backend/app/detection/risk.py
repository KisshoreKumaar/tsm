"""Explainable risk scoring: a capped sum of named factors. A heuristic, never a probability."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.detection.base import NON_TACTIC_STAGES, SEVERITY_RANK, Detection, Event

RISK_LABEL = "Heuristic risk score (0-100). It ranks attention; it is not a probability."
_SEVERITY_POINTS = {"LOW": 5, "MEDIUM": 12, "HIGH": 20, "CRITICAL": 25}
_IMPACT_RULES = {"FILE-001": 10, "LOG-001": 10, "PROC-001": 5, "AUTH-002": 5, "ACCT-001": 5}


@dataclass(frozen=True)
class RiskFactor:
    name: str
    label: str
    points: int
    max_points: int
    explanation: str

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "points": self.points,
            "max_points": self.max_points,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: str
    factors: tuple[RiskFactor, ...]

    def public(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "label": RISK_LABEL,
            "factors": [f.public() for f in self.factors],
        }


def band(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def score_incident(
    events: Sequence[Event], detections: Sequence[Detection], observed_predictions: int = 0
) -> RiskAssessment:
    active = list(detections)
    top = max(active, key=lambda d: SEVERITY_RANK[d.severity], default=None)
    top_severity = top.severity if top else "LOW"
    max_confidence = max((d.confidence for d in active), default=0)
    max_criticality = max((e.criticality for e in events), default=1)
    privileged = [e for e in events if e.privileged]
    tactics = sorted({d.stage for d in active if d.stage not in NON_TACTIC_STAGES})
    rule_ids = {d.rule_id for d in active}
    impact = max((_IMPACT_RULES.get(rule_id, 0) for rule_id in rule_ids), default=0)

    factors = (
        RiskFactor(
            "threat_severity",
            "Threat severity",
            _SEVERITY_POINTS[top_severity] if top else 0,
            25,
            f"Highest detection severity is {top_severity}" + (f" ({top.rule_id})" if top else ""),
        ),
        RiskFactor(
            "detection_confidence",
            "Detection confidence",
            round(max_confidence * 0.15),
            15,
            f"Highest rule confidence is {max_confidence}/100 (heuristic rule setting)",
        ),
        RiskFactor(
            "asset_criticality",
            "Asset criticality",
            max_criticality * 3,
            15,
            f"Source-reported asset criticality {max_criticality}/5",
        ),
        RiskFactor(
            "privilege",
            "Privileged account",
            10 if privileged else 0,
            10,
            f"{len(privileged)} event(s) involve a privileged account"
            if privileged
            else "No privileged activity reported",
        ),
        RiskFactor(
            "attack_progression",
            "Attack progression",
            min(15, max(0, len(tactics) - 1) * 5),
            15,
            f"{len(tactics)} distinct ATT&CK tactic stage(s): {', '.join(tactics)}" if tactics else "No tactic stages",
        ),
        RiskFactor(
            "event_count",
            "Correlated events",
            min(5, len(events) // 5),
            5,
            f"{len(events)} correlated event(s)",
        ),
        RiskFactor(
            "reported_indicator",
            "Reported indicator",
            5 if "SOURCE-002" in rule_ids else 0,
            5,
            "An upstream source reported a malicious indicator (unverified)"
            if "SOURCE-002" in rule_ids
            else "No upstream indicator",
        ),
        RiskFactor(
            "potential_impact",
            "Potential impact",
            impact,
            10,
            "Impact-related detections: " + ", ".join(sorted(r for r in rule_ids if r in _IMPACT_RULES))
            if impact
            else "No impact-related detections",
        ),
        RiskFactor(
            "observed_prediction",
            "Observed prediction",
            min(10, observed_predictions * 10),
            10,
            f"{observed_predictions} predicted next step(s) were later observed"
            if observed_predictions
            else "No predicted step has been observed",
        ),
    )
    score = min(100, sum(f.points for f in factors))
    return RiskAssessment(score=score, severity=band(score), factors=factors)
