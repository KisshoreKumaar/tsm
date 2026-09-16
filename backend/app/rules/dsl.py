"""Rule DSL (A3): JSON rules validated by Pydantic and evaluated like built-in rules. Never executable code.

A rule selects events by kind and field conditions (all must hold), drops events matching any exclusion, groups the
rest by `group_by`, and fires when a sliding window of `window_seconds` reaches the threshold (a count, or a distinct
count of one field). With `sequence`, it instead fires when the steps occur in order within the window.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError, model_validator

from app.detection.base import Detection, Event, build_detection, group_events, make_group_key, sliding_window_hits
from app.detection.builtin import duration_text
from app.detection.catalog import TECHNIQUE_ID_RE, TechniqueCatalog
from app.prediction.signals import Condition, EventKind

CUSTOM_STAGE = "Custom detection"
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
GroupField = Literal[
    "asset", "user", "source", "source_ip", "destination_ip", "destination_port", "domain", "process_name", "file_hash"
]
DistinctField = Literal[
    "asset",
    "user",
    "source_ip",
    "destination_ip",
    "destination_port",
    "domain",
    "process_name",
    "command_line",
    "file_path",
    "file_hash",
]


class RuleValidationError(ValueError):
    def __init__(self, errors: list[dict[str, Any]]) -> None:
        super().__init__(errors[0]["msg"] if errors else "Invalid rule")
        self.errors = errors


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Threshold(_Strict):
    type: Literal["count", "distinct_count"] = "count"
    field: DistinctField | None = None
    value: StrictInt = Field(default=1, ge=1, le=10_000)

    @model_validator(mode="after")
    def _check(self) -> Threshold:
        if self.type == "distinct_count" and self.field is None:
            raise ValueError("distinct_count needs a field")
        if self.type == "count" and self.field is not None:
            raise ValueError("A count threshold takes no field")
        return self


class SequenceStep(_Strict):
    kinds: tuple[EventKind, ...] = Field(min_length=1, max_length=5)
    conditions: tuple[Condition, ...] = Field(default=(), max_length=10)

    def matches(self, event: Event) -> bool:
        return event.kind in self.kinds and all(c.matches(event) for c in self.conditions)


class RuleLogic(_Strict):
    kinds: tuple[EventKind, ...] = Field(min_length=1, max_length=10)
    conditions: tuple[Condition, ...] = Field(default=(), max_length=20)
    exclusions: tuple[Condition, ...] = Field(default=(), max_length=20)
    group_by: tuple[GroupField, ...] = Field(default=("asset", "user"), max_length=4)
    window_seconds: StrictInt = Field(default=300, ge=1, le=86_400)
    threshold: Threshold = Field(default_factory=Threshold)
    sequence: tuple[SequenceStep, ...] = Field(default=(), max_length=3)

    @model_validator(mode="after")
    def _check(self) -> RuleLogic:
        if len(set(self.group_by)) != len(self.group_by):
            raise ValueError("group_by fields must be unique")
        if self.sequence:
            if len(self.sequence) < 2:
                raise ValueError("A sequence needs at least two steps")
            if any(not set(step.kinds) <= set(self.kinds) for step in self.sequence):
                raise ValueError("Every sequence step's kinds must be listed in kinds")
            if self.threshold.type != "count" or self.threshold.value != 1:
                raise ValueError("Sequence rules fire once per ordered match; use a count threshold of 1")
        return self


class RuleDefinition(_Strict):
    name: StrictStr = Field(min_length=3, max_length=120)
    description: StrictStr = Field(min_length=10, max_length=1000)
    severity: Severity
    confidence: StrictInt = Field(default=60, ge=1, le=100)
    techniques: tuple[StrictStr, ...] = Field(default=(), max_length=5)
    known_false_positives: tuple[StrictStr, ...] = Field(default=(), max_length=10)
    logic: RuleLogic

    @model_validator(mode="after")
    def _check(self) -> RuleDefinition:
        if any(not TECHNIQUE_ID_RE.fullmatch(t) for t in self.techniques):
            raise ValueError("Technique IDs must look like T1234 or T1234.001")
        if any(not 0 < len(item) <= 200 for item in self.known_false_positives):
            raise ValueError("Known false positives must be 1 to 200 characters each")
        return self


def validate_definition(raw: Any, catalog: TechniqueCatalog) -> RuleDefinition:
    """Validate untrusted rule JSON. Error messages never echo the submitted values."""
    try:
        definition = RuleDefinition.model_validate(raw)
    except ValidationError as exc:
        errors = [
            {"loc": [str(part) for part in error["loc"]], "msg": error["msg"]}
            for error in exc.errors(include_url=False, include_input=False, include_context=False)[:50]
        ]
        raise RuleValidationError(errors) from None
    for technique in definition.techniques:
        if technique not in catalog:
            raise RuleValidationError(
                [{"loc": ["techniques"], "msg": f"Technique {technique} is not in the local ATT&CK catalog"}]
            )
    return definition


@dataclass(frozen=True)
class CompiledRule:
    """A DSL rule version, shaped like built-in rules so the engine and pipeline treat both alike."""

    id: str
    name: str
    version: int
    techniques: tuple[str, ...]
    severity: str
    confidence: int
    stage: str
    description: str
    definition: RuleDefinition

    @classmethod
    def build(cls, rule_id: str, version: int, definition: RuleDefinition, catalog: TechniqueCatalog) -> CompiledRule:
        stage = catalog.require(definition.techniques[0]).tactics[0] if definition.techniques else CUSTOM_STAGE
        return cls(
            id=rule_id,
            name=definition.name,
            version=version,
            techniques=definition.techniques,
            severity=definition.severity,
            confidence=definition.confidence,
            stage=stage,
            description=definition.description,
            definition=definition,
        )

    @property
    def TUNABLE(self) -> tuple[str, ...]:
        return () if self.definition.logic.sequence else ("threshold", "window_seconds")

    def parameters(self) -> dict[str, int]:
        logic = self.definition.logic
        return {"threshold": logic.threshold.value, "window_seconds": logic.window_seconds}

    def with_logic(self, **changes: Any) -> CompiledRule:
        logic = self.definition.logic.model_copy(update=changes)
        return CompiledRule.build_unchecked(self, self.definition.model_copy(update={"logic": logic}))

    @classmethod
    def build_unchecked(cls, base: CompiledRule, definition: RuleDefinition) -> CompiledRule:
        return cls(
            base.id,
            base.name,
            base.version,
            base.techniques,
            base.severity,
            base.confidence,
            base.stage,
            base.description,
            definition,
        )

    def with_parameters(self, threshold: int | None = None, window_seconds: int | None = None) -> CompiledRule:
        logic = self.definition.logic
        changes: dict[str, Any] = {}
        if threshold is not None:
            changes["threshold"] = logic.threshold.model_copy(update={"value": int(threshold)})
        if window_seconds is not None:
            changes["window_seconds"] = int(window_seconds)
        return self.with_logic(**changes)

    def _group_key(self, event: Event) -> tuple[str, ...]:
        return tuple(
            "" if (value := event.get(name)) is None else str(value) for name in self.definition.logic.group_by
        )

    def _qualifies(self, window: Sequence[Event]) -> bool:
        threshold = self.definition.logic.threshold
        if threshold.type == "count":
            return len(window) >= threshold.value
        field = threshold.field or ""
        return len({event.get(field) for event in window if event.get(field) is not None}) >= threshold.value

    def _sequence_hits(self, group: Sequence[Event]) -> dict[str, Event]:
        logic = self.definition.logic
        hits: dict[str, Event] = {}
        for index, start in enumerate(group):
            if not logic.sequence[0].matches(start):
                continue
            chain, cursor = [start], index
            for step in logic.sequence[1:]:
                found = next(
                    (
                        (position, event)
                        for position, event in enumerate(group[cursor + 1 :], start=cursor + 1)
                        if step.matches(event) and (event.ts - start.ts).total_seconds() <= logic.window_seconds
                    ),
                    None,
                )
                if found is None:
                    break
                cursor, event = found
                chain.append(event)
            else:
                hits.update({event.id: event for event in chain})
        return hits

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        logic = self.definition.logic
        ordered = sorted(events, key=lambda e: e.sort_key)
        candidates = [
            event
            for event in ordered
            if event.kind in logic.kinds
            and all(c.matches(event) for c in logic.conditions)
            and not any(x.matches(event) for x in logic.exclusions)
        ]
        detections = []
        for key, group in group_events(candidates, self._group_key):
            hits = (
                self._sequence_hits(group)
                if logic.sequence
                else sliding_window_hits(group, logic.window_seconds, self._qualifies)
            )
            if not hits:
                continue
            evidence = sorted(hits.values(), key=lambda e: e.sort_key)
            parts = dict(zip(logic.group_by, key if isinstance(key, tuple) else (key,), strict=False))
            scope = ", ".join(f"{name} {value}" for name, value in parts.items() if value)
            window = duration_text(logic.window_seconds)
            threshold = logic.threshold
            if logic.sequence:
                summary = f"{self.name}: {len(logic.sequence)} steps in order within {window} ({scope})"
            elif threshold.type == "distinct_count":
                distinct = len({e.get(threshold.field or "") for e in evidence})
                summary = f"{self.name}: {distinct} distinct {threshold.field} values within {window} ({scope})"
            else:
                summary = f"{self.name}: {len(evidence)} matching events within {window} ({scope})"
            detections.append(
                build_detection(
                    self,
                    evidence,
                    make_group_key(**parts),
                    summary,
                    {
                        "matches": len(evidence),
                        "threshold": threshold.value,
                        "threshold_type": threshold.type,
                        "window_seconds": logic.window_seconds,
                        "group": parts,
                        "custom_rule": True,
                    },
                )
            )
        return detections


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, Mapping):
        flat: dict[str, Any] = {}
        for key in sorted(value):
            flat.update(_flatten(value[key], f"{prefix}.{key}" if prefix else str(key)))
        return flat or {prefix: {}}
    return {prefix: value}


def diff_definitions(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Changed leaf paths between two rule definitions (lists compare as whole values)."""
    before, after = _flatten(old), _flatten(new)
    changes = []
    for path in sorted(set(before) | set(after)):
        if path not in after:
            changes.append({"path": path, "change": "removed", "old": before[path], "new": None})
        elif path not in before:
            changes.append({"path": path, "change": "added", "old": None, "new": after[path]})
        elif before[path] != after[path]:
            changes.append({"path": path, "change": "changed", "old": before[path], "new": after[path]})
    return changes
