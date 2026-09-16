"""Tuning changes (A5): validated scopes, and how each change alters a rule or suppresses a detection."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError, model_validator

from app.core.db import Session
from app.detection.base import Detection, Rule
from app.prediction.signals import Condition

SuggestionType = Literal["suppression", "maintenance_window", "threshold", "window", "dsl_exclusion"]
EntityType = Literal["asset", "user", "source_ip", "destination_ip", "domain", "file_hash", "process"]
CASE_FOLDED = frozenset({"asset", "user", "domain", "file_hash", "process"})
MAX_SUPPRESSION_DAYS = 90
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class TuningError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EntityScope(_Strict):
    type: EntityType
    value: StrictStr = Field(min_length=1, max_length=255)

    @model_validator(mode="before")
    @classmethod
    def _fold(cls, data: Any) -> Any:
        if isinstance(data, dict) and data.get("type") in CASE_FOLDED and isinstance(data.get("value"), str):
            return {**data, "value": data["value"].strip().lower()}
        return data


class MaintenanceSchedule(_Strict):
    """A recurring UTC window. Days are 0 (Monday) to 6 (Sunday); an end before the start runs past midnight."""

    days: tuple[StrictInt, ...] = Field(min_length=1, max_length=7)
    start: StrictStr
    end: StrictStr

    @model_validator(mode="after")
    def _check(self) -> MaintenanceSchedule:
        if len(set(self.days)) != len(self.days) or any(not 0 <= day <= 6 for day in self.days):
            raise ValueError("days must be unique weekday numbers from 0 (Monday) to 6 (Sunday)")
        if not _TIME_RE.fullmatch(self.start) or not _TIME_RE.fullmatch(self.end):
            raise ValueError("start and end must be HH:MM in UTC")
        if self.start == self.end:
            raise ValueError("start and end must differ")
        return self

    @staticmethod
    def _minutes(text: str) -> int:
        hours, minutes = text.split(":")
        return int(hours) * 60 + int(minutes)

    def active_at(self, ts: datetime) -> bool:
        moment = ts.astimezone(UTC)
        minute = moment.hour * 60 + moment.minute
        start, end = self._minutes(self.start), self._minutes(self.end)
        if start < end:
            return moment.weekday() in self.days and start <= minute < end
        if minute >= start:
            return moment.weekday() in self.days
        return minute < end and (moment.weekday() - 1) % 7 in self.days


class TuningScope(_Strict):
    entities: tuple[EntityScope, ...] = Field(default=(), max_length=5)
    schedule: MaintenanceSchedule | None = None
    threshold: StrictInt | None = Field(default=None, ge=1, le=10_000)
    window_seconds: StrictInt | None = Field(default=None, ge=10, le=86_400)
    exclusion: Condition | None = None
    expires_in_days: StrictInt = Field(default=30, ge=1, le=MAX_SUPPRESSION_DAYS)


_SHAPES: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "suppression": (frozenset({"entities"}), frozenset({"schedule", "threshold", "window_seconds", "exclusion"})),
    "maintenance_window": (frozenset({"schedule"}), frozenset({"threshold", "window_seconds", "exclusion"})),
    "threshold": (frozenset({"threshold"}), frozenset({"entities", "schedule", "window_seconds", "exclusion"})),
    "window": (frozenset({"window_seconds"}), frozenset({"entities", "schedule", "threshold", "exclusion"})),
    "dsl_exclusion": (frozenset({"exclusion"}), frozenset({"entities", "schedule", "threshold", "window_seconds"})),
}


def validate_scope(kind: str, raw: Any) -> TuningScope:
    try:
        scope = TuningScope.model_validate(raw)
    except ValidationError as exc:
        messages = [
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False, include_input=False, include_context=False)[:5]
        ]
        raise TuningError("; ".join(messages)) from None
    required, forbidden = _SHAPES[kind]
    present = {
        "entities": bool(scope.entities),
        "schedule": scope.schedule is not None,
        "threshold": scope.threshold is not None,
        "window_seconds": scope.window_seconds is not None,
        "exclusion": scope.exclusion is not None,
    }
    missing = sorted(name for name in required if not present[name])
    extra = sorted(name for name in forbidden if present[name])
    if missing:
        raise TuningError(f"A {kind} change needs {', '.join(missing)}")
    if extra:
        raise TuningError(f"A {kind} change does not take {', '.join(extra)}")
    return scope


def entities_match(session: Session, event_ids: Sequence[str], entities: Sequence[EntityScope]) -> bool:
    """True when every scoped entity appears in at least one of the detection's evidence events."""
    if not entities:
        return True
    ids = list(event_ids)
    if not ids:
        return False
    marks = ",".join("?" * len(ids))
    for entity in entities:
        found = session.scalar(
            f"SELECT 1 FROM event_entities WHERE entity_type = ? AND value = ? AND event_id IN ({marks}) LIMIT 1",
            [entity.type, entity.value, *ids],
        )
        if found is None:
            return False
    return True


@dataclass(frozen=True)
class TuningChange:
    type: str
    rule_id: str
    scope: TuningScope

    @property
    def suppressive(self) -> bool:
        return self.type in ("suppression", "maintenance_window")

    def suppresses(self, session: Session, detection: Detection) -> bool:
        if self.scope.schedule is not None and not self.scope.schedule.active_at(detection.first_ts):
            return False
        return entities_match(session, detection.event_ids, self.scope.entities)

    def modified(self, rule: Rule) -> Rule:
        if self.suppressive:
            return rule
        if self.type == "dsl_exclusion":
            with_logic = getattr(rule, "with_logic", None)
            definition = getattr(rule, "definition", None)
            if with_logic is None or definition is None:
                raise TuningError("Exclusion conditions apply only to custom DSL rules")
            excluded: Rule = with_logic(exclusions=(*definition.logic.exclusions, self.scope.exclusion))
            return excluded
        tunable: tuple[str, ...] = getattr(rule, "TUNABLE", ())
        tune = getattr(rule, "with_parameters", None)
        if not tunable or tune is None:
            raise TuningError(f"Rule {rule.id} has no tunable threshold or window")
        tuned: Rule = tune(threshold=self.scope.threshold, window_seconds=self.scope.window_seconds)
        return tuned
