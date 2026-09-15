"""Deterministic next-step prediction (F4): a pure function of an incident's events and active detections.

Each technique established by an active detection proposes candidate next techniques from the curated transition
model. Predictions are computed in event time, so the same evidence yields the same predictions whatever order it
arrived in. A prediction is OBSERVED when an event outside its source evidence matches a watch signal between the
source detection's first evidence and the end of its horizon; otherwise it is WATCHING until the horizon passes and
EXPIRED afterwards. Scores rank hypotheses; they are heuristics, never probabilities.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.core.timeutil import iso, parse_iso
from app.detection.base import NON_TACTIC_STAGES, Detection, Event
from app.prediction.model import PreventiveAction, Transition, TransitionModel
from app.prediction.signals import WatchSignal

LIKELIHOOD_LABEL = (
    "Relative likelihood score (0-100). It ranks hypotheses for attention; it is a heuristic, not a probability."
)
HYPOTHESIS = "HYPOTHESIS"
MAX_EVIDENCE = 20


@dataclass(frozen=True)
class DetectionFact:
    """The parts of an active detection that prediction needs."""

    id: str
    rule_id: str
    techniques: tuple[str, ...]
    stage: str
    first_ts: datetime
    last_ts: datetime
    event_ids: tuple[str, ...]

    @classmethod
    def from_row(cls, row: Any) -> DetectionFact:
        return cls(
            id=row["id"],
            rule_id=row["rule_id"],
            techniques=tuple(json.loads(row["techniques"])),
            stage=row["stage"],
            first_ts=parse_iso(row["first_ts"]),
            last_ts=parse_iso(row["last_ts"]),
            event_ids=tuple(json.loads(row["event_ids"])),
        )

    @classmethod
    def from_detection(cls, detection: Detection) -> DetectionFact:
        return cls(
            id=detection.id,
            rule_id=detection.rule_id,
            techniques=detection.techniques,
            stage=detection.stage,
            first_ts=detection.first_ts,
            last_ts=detection.last_ts,
            event_ids=detection.event_ids,
        )


@dataclass(frozen=True)
class PredictionContext:
    campaign_incidents: int = 1  # incidents in this incident's active campaign; 1 when it has none


@dataclass(frozen=True)
class ScoreFactor:
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
class PredictionSource:
    technique_id: str
    technique_name: str
    rule_id: str
    detection_id: str
    weight: int
    rationale: str

    def public(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "rule_id": self.rule_id,
            "detection_id": self.detection_id,
            "weight": self.weight,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class PredictionDraft:
    technique_id: str
    technique_name: str
    tactic: str
    url: str
    score: int
    band: str
    factors: tuple[ScoreFactor, ...]
    rationale: str
    sources: tuple[PredictionSource, ...]
    evidence_ids: tuple[str, ...]
    watch: tuple[WatchSignal, ...]
    actions: tuple[PreventiveAction, ...]
    horizon_seconds: int
    predicted_at: datetime
    expires_at: datetime
    observed_event_ids: tuple[str, ...] = ()
    observed_at: datetime | None = None

    def status(self, now: datetime) -> str:
        if self.observed_event_ids:
            return "OBSERVED"
        return "EXPIRED" if now > self.expires_at else "WATCHING"

    def public(self, now: datetime) -> dict[str, Any]:
        return {
            "technique": {
                "id": self.technique_id,
                "name": self.technique_name,
                "tactic": self.tactic,
                "url": self.url,
            },
            "label": HYPOTHESIS,
            "score": self.score,
            "band": self.band,
            "score_label": LIKELIHOOD_LABEL,
            "factors": [f.public() for f in self.factors],
            "rationale": self.rationale,
            "sources": [s.public() for s in self.sources],
            "evidence_ids": list(self.evidence_ids),
            "watch_signals": [s.public() for s in self.watch],
            "preventive_actions": [a.model_dump() for a in self.actions],
            "horizon_seconds": self.horizon_seconds,
            "predicted_at": iso(self.predicted_at),
            "expires_at": iso(self.expires_at),
            "status": self.status(now),
            "observed_event_ids": list(self.observed_event_ids),
            "observed_at": iso(self.observed_at) if self.observed_at else None,
        }


def likelihood_band(score: int) -> str:
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def _triggers(detections: Sequence[DetectionFact], order: Mapping[str, Any]) -> dict[str, set[str]]:
    """Rule IDs keyed by the event that completed each detection (its latest evidence event)."""
    triggers: dict[str, set[str]] = defaultdict(set)
    for detection in detections:
        known = [event_id for event_id in detection.event_ids if event_id in order]
        if known:
            triggers[max(known, key=lambda event_id: order[event_id])].add(detection.rule_id)
    return triggers


def _capped(event_ids: Sequence[str]) -> tuple[str, ...]:
    if len(event_ids) <= MAX_EVIDENCE:
        return tuple(event_ids)
    half = MAX_EVIDENCE // 2
    return (*event_ids[:half], *event_ids[-half:])


def _factors(
    transition: Transition,
    source_name: str,
    *,
    source_count: int,
    stages: int,
    privileged: bool,
    authenticated: bool,
    criticality: int,
    gap_seconds: float,
    campaign_incidents: int,
) -> tuple[ScoreFactor, ...]:
    recency = 8 if gap_seconds <= 600 else 4 if gap_seconds <= 3600 else 0
    breadth = min(5, 2 * max(0, campaign_incidents - 1))
    return (
        ScoreFactor(
            "transition_weight",
            "Curated transition weight",
            transition.weight,
            60,
            f"{transition.source} ({source_name}) → {transition.target} base weight from the curated model",
        ),
        ScoreFactor(
            "privileged_account",
            "Privileged account",
            10 if privileged else 0,
            10,
            "The evidence involves a privileged account" if privileged else "No privileged account in the evidence",
        ),
        ScoreFactor(
            "successful_authentication",
            "Successful authentication",
            10 if authenticated else 0,
            10,
            "A successful logon was observed" if authenticated else "No successful logon was observed",
        ),
        ScoreFactor(
            "asset_criticality",
            "Asset criticality",
            max(0, min(8, (criticality - 1) * 2)),
            8,
            f"Highest reported asset criticality is {criticality}",
        ),
        ScoreFactor(
            "stages_observed",
            "Attack stages observed",
            min(9, 3 * max(0, stages - 1)),
            9,
            f"{stages} ATT&CK tactic stage(s) already observed",
        ),
        ScoreFactor(
            "recency",
            "Recency",
            recency,
            8,
            f"The predecessor's latest evidence is {int(gap_seconds // 60)} minute(s) before the incident's latest event",
        ),
        ScoreFactor(
            "campaign_breadth",
            "Campaign breadth",
            breadth,
            5,
            f"Part of a campaign with {campaign_incidents} incidents"
            if campaign_incidents > 1
            else "Not part of a campaign",
        ),
        ScoreFactor(
            "corroboration",
            "Several observed predecessors",
            5 if source_count > 1 else 0,
            5,
            f"{source_count} observed techniques lead to this step",
        ),
    )


def predict(
    events: Sequence[Event],
    detections: Sequence[DetectionFact],
    model: TransitionModel,
    context: PredictionContext | None = None,
) -> list[PredictionDraft]:
    context = context or PredictionContext()
    ordered = sorted(events, key=lambda e: e.sort_key)
    if not ordered or not detections:
        return []
    catalog = model.catalog
    order = {event.id: event.sort_key for event in ordered}
    triggers = _triggers(detections, order)
    active = sorted(detections, key=lambda d: (d.first_ts, d.rule_id, d.id))

    established: dict[str, datetime] = {}
    for detection in active:
        for technique in detection.techniques:
            established.setdefault(technique, detection.first_ts)

    candidates: dict[str, list[tuple[Transition, DetectionFact]]] = defaultdict(list)
    for detection in active:
        for technique in detection.techniques:
            for transition in model.candidates(technique):
                earlier = established.get(transition.target)
                if transition.target in detection.techniques or (earlier is not None and earlier < detection.first_ts):
                    continue  # the step was already seen before its predecessor, so it is not a prediction
                candidates[transition.target].append((transition, detection))

    stages = len({d.stage for d in active if d.stage not in NON_TACTIC_STAGES})
    privileged = any(e.privileged for e in ordered)
    authenticated = any(e.kind == "auth_success" for e in ordered)
    criticality = max(e.criticality for e in ordered)
    latest = max(e.ts for e in ordered)

    drafts: list[PredictionDraft] = []
    for target in sorted(candidates):
        sources = sorted(candidates[target], key=lambda s: (-s[0].weight, s[1].first_ts, s[1].rule_id, s[0].source))
        profile = model.profiles[target]
        horizon = timedelta(seconds=profile.horizon_seconds)

        observed: dict[str, Event] = {}
        for _, detection in sources:
            excluded = set(detection.event_ids)
            end = detection.last_ts + horizon
            for event in ordered:
                if event.id in excluded or event.ts < detection.first_ts or event.ts > end:
                    continue
                if any(signal.matches(event, triggers.get(event.id, ())) for signal in profile.watch):
                    observed[event.id] = event

        best_transition, best = sources[0]
        source_techniques = sorted({transition.source for transition, _ in sources})
        factors = _factors(
            best_transition,
            catalog.require(best_transition.source).name,
            source_count=len(source_techniques),
            stages=stages,
            privileged=privileged,
            authenticated=authenticated,
            criticality=criticality,
            gap_seconds=max(0.0, (latest - best.last_ts).total_seconds()),
            campaign_incidents=context.campaign_incidents,
        )
        score = min(100, sum(f.points for f in factors))
        target_technique = catalog.require(target)
        basis = {event_id for _, detection in sources for event_id in detection.event_ids}
        observed_events = sorted(observed.values(), key=lambda e: e.sort_key)
        basis_text = ", ".join(
            f"{catalog.require(t.source).name} ({d.rule_id})" for t, d in sources if t.source in source_techniques
        )
        drafts.append(
            PredictionDraft(
                technique_id=target,
                technique_name=target_technique.name,
                tactic=profile.tactic,
                url=target_technique.url,
                score=score,
                band=likelihood_band(score),
                factors=factors,
                rationale=f"{best_transition.rationale} Based on observed {basis_text}.",
                sources=tuple(
                    PredictionSource(
                        technique_id=t.source,
                        technique_name=catalog.require(t.source).name,
                        rule_id=d.rule_id,
                        detection_id=d.id,
                        weight=t.weight,
                        rationale=t.rationale,
                    )
                    for t, d in sources
                ),
                evidence_ids=_capped([e.id for e in ordered if e.id in basis]),
                watch=profile.watch,
                actions=profile.actions,
                horizon_seconds=profile.horizon_seconds,
                predicted_at=min(d.last_ts for _, d in sources),
                expires_at=max(d.last_ts for _, d in sources) + horizon,
                observed_event_ids=_capped([e.id for e in observed_events]),
                observed_at=observed_events[0].ts if observed_events else None,
            )
        )
    return sorted(drafts, key=lambda d: (-d.score, d.technique_id))
