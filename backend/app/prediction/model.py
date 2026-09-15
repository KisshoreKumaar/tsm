"""Curated ATT&CK transition model (F4): an editable heuristic validated against the local catalog when loaded."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from app.core.config import BACKEND_DIR
from app.detection.catalog import TECHNIQUE_ID_RE, TechniqueCatalog, default_catalog
from app.prediction.signals import WatchSignal
from app.response.simulation import PLAYBOOKS

TRANSITIONS_PATH = BACKEND_DIR / "data" / "attack" / "transitions.json"
MODEL_LABEL = "Curated, editable heuristic. Weights and horizons are analyst judgement, not measured frequencies."


class TransitionModelError(ValueError):
    pass


class PreventiveAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: StrictStr = Field(min_length=3, max_length=200)
    playbook: StrictStr | None = None


class TargetProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    technique: StrictStr
    tactic: StrictStr
    horizon_seconds: StrictInt = Field(ge=300, le=7 * 86_400)
    watch: tuple[WatchSignal, ...] = Field(min_length=1, max_length=8)
    actions: tuple[PreventiveAction, ...] = Field(default=(), max_length=6)


class Transition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    source: StrictStr = Field(alias="from")
    target: StrictStr = Field(alias="to")
    weight: StrictInt = Field(ge=1, le=60)
    rationale: StrictStr = Field(min_length=10, max_length=400)


class ModelFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: StrictInt
    description: StrictStr
    notes: list[StrictStr] = Field(default_factory=list)
    profiles: list[TargetProfile]
    transitions: list[Transition]


class TransitionModel:
    def __init__(self, data: ModelFile, catalog: TechniqueCatalog) -> None:
        def check_technique(technique_id: str, where: str) -> None:
            if not TECHNIQUE_ID_RE.fullmatch(technique_id):
                raise TransitionModelError(f"{where}: {technique_id!r} is not a valid ATT&CK technique ID")
            if technique_id not in catalog:
                raise TransitionModelError(f"{where}: technique {technique_id} is not in the local ATT&CK catalog")

        profiles: dict[str, TargetProfile] = {}
        for profile in data.profiles:
            check_technique(profile.technique, "profile")
            if profile.technique in profiles:
                raise TransitionModelError(f"Duplicate profile for technique {profile.technique}")
            if profile.tactic not in catalog.require(profile.technique).tactics:
                raise TransitionModelError(
                    f"profile {profile.technique}: tactic {profile.tactic} is not listed for this technique"
                )
            for action in profile.actions:
                if action.playbook is not None and action.playbook not in PLAYBOOKS:
                    raise TransitionModelError(f"profile {profile.technique}: unknown playbook {action.playbook!r}")
            profiles[profile.technique] = profile

        seen: set[tuple[str, str]] = set()
        by_source: dict[str, list[Transition]] = {}
        for transition in data.transitions:
            check_technique(transition.source, "transition source")
            check_technique(transition.target, "transition target")
            pair = (transition.source, transition.target)
            if transition.source == transition.target or pair in seen:
                raise TransitionModelError(
                    f"Invalid or duplicate transition {transition.source} -> {transition.target}"
                )
            if transition.target not in profiles:
                raise TransitionModelError(
                    f"transition {transition.source} -> {transition.target}: technique {transition.target} has no watch profile"
                )
            seen.add(pair)
            by_source.setdefault(transition.source, []).append(transition)

        self.catalog = catalog
        self.version = data.version
        self.description = data.description
        self.notes = list(data.notes)
        self.profiles = profiles
        self.transitions = list(data.transitions)
        self._by_source = {
            source: sorted(items, key=lambda t: (-t.weight, t.target)) for source, items in by_source.items()
        }

    @classmethod
    def load(cls, path: Path = TRANSITIONS_PATH, catalog: TechniqueCatalog | None = None) -> TransitionModel:
        try:
            data = ModelFile.model_validate(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            raise TransitionModelError(f"Invalid transition model {path.name}: {exc}") from exc
        return cls(data, catalog or default_catalog())

    def candidates(self, technique_id: str) -> list[Transition]:
        return list(self._by_source.get(technique_id, ()))

    def public(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "description": self.description,
            "label": MODEL_LABEL,
            "notes": self.notes,
            "transitions": [t.model_dump(by_alias=True) for t in self.transitions],
            "profiles": [
                {
                    "technique": p.technique,
                    "technique_name": self.catalog.require(p.technique).name,
                    "tactic": p.tactic,
                    "horizon_seconds": p.horizon_seconds,
                    "watch_signals": [s.public() for s in p.watch],
                    "preventive_actions": [a.model_dump() for a in p.actions],
                }
                for p in sorted(self.profiles.values(), key=lambda p: p.technique)
            ],
            "attribution": self.catalog.attribution,
        }


@lru_cache(maxsize=1)
def default_transition_model() -> TransitionModel:
    return TransitionModel.load()
