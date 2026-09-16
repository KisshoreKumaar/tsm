"""Rule-facing types shared by built-in and DSL rules."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from collections.abc import Callable, Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from app.core.jsonutil import canonical_json
from app.core.timeutil import iso, parse_iso

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
DETECTION_NAMESPACE = uuid.UUID("6f1c2b1e-4a57-4c1e-9d5e-2f0a7f3c9b10")

# Stages that are not ATT&CK tactics; they never count as attack progression.
NON_TACTIC_STAGES = frozenset({"AI manipulation attempt", "Source-reported alert", "Custom detection"})


@dataclass(frozen=True)
class Event:
    id: str
    source: str
    external_id: str | None
    digest: str
    ts: datetime
    kind: str
    asset: str
    username: str
    criticality: int
    privileged: bool
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    domain: str | None = None
    process_name: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    details: str | None = None
    injection_matches: tuple[str, ...] = ()

    @property
    def injection_suspected(self) -> bool:
        return bool(self.injection_matches)

    @property
    def sort_key(self) -> tuple[datetime, str, str, str]:
        """Deterministic order that never depends on arrival order or random internal IDs."""
        return (self.ts, self.source, self.external_id or "", self.digest)

    def get(self, name: str) -> Any:
        if name == "user":
            return self.username
        if name == "timestamp":
            return iso(self.ts)
        return getattr(self, name, None)

    @classmethod
    def from_row(cls, row: Any) -> Event:
        return cls(
            id=row["id"],
            source=row["source"],
            external_id=row["external_id"],
            digest=row["digest"],
            ts=parse_iso(row["ts"]),
            kind=row["kind"],
            asset=row["asset"],
            username=row["username"],
            criticality=int(row["criticality"]),
            privileged=bool(row["privileged"]),
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            destination_port=row["destination_port"],
            domain=row["domain"],
            process_name=row["process_name"],
            parent_process=row["parent_process"],
            command_line=row["command_line"],
            file_path=row["file_path"],
            file_hash=row["file_hash"],
            details=row["details"],
            injection_matches=tuple(json.loads(row["injection_matches"] or "[]")),
        )

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_id": self.external_id,
            "source": self.source,
            "timestamp": iso(self.ts),
            "kind": self.kind,
            "asset": self.asset,
            "user": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "domain": self.domain,
            "process_name": self.process_name,
            "parent_process": self.parent_process,
            "command_line": self.command_line,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "details": self.details,
            "criticality": self.criticality,
            "privileged": self.privileged,
            "injection_suspected": self.injection_suspected,
            "injection_matches": list(self.injection_matches),
        }


@dataclass(frozen=True)
class Detection:
    rule_id: str
    rule_version: int
    rule_name: str
    severity: str
    confidence: int
    stage: str
    techniques: tuple[str, ...]
    group_key: str
    event_ids: tuple[str, ...]
    first_ts: datetime
    last_ts: datetime
    summary: str
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        material = f"{self.rule_id}|{self.rule_version}|{self.group_key}|{','.join(self.event_ids)}"
        return str(uuid.uuid5(DETECTION_NAMESPACE, material))

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "stage": self.stage,
            "techniques": list(self.techniques),
            "group_key": self.group_key,
            "event_ids": list(self.event_ids),
            "first_ts": iso(self.first_ts),
            "last_ts": iso(self.last_ts),
            "summary": self.summary,
            "details": dict(self.details),
        }


class Rule(Protocol):
    """Shared by built-in and DSL rules. Attributes are read-only so frozen dataclasses satisfy the protocol."""

    @property
    def id(self) -> str: ...

    @property
    def name(self) -> str: ...

    @property
    def version(self) -> int: ...

    @property
    def techniques(self) -> tuple[str, ...]: ...

    @property
    def severity(self) -> str: ...

    @property
    def confidence(self) -> int: ...

    @property
    def stage(self) -> str: ...

    @property
    def description(self) -> str: ...

    def evaluate(self, events: Sequence[Event]) -> list[Detection]: ...


def group_events(events: Iterable[Event], key: Callable[[Event], Hashable]) -> list[tuple[Hashable, list[Event]]]:
    """Group sorted events; groups are returned in a deterministic order and keep event order."""
    groups: dict[Hashable, list[Event]] = defaultdict(list)
    for event in events:
        groups[key(event)].append(event)
    return sorted(groups.items(), key=lambda item: canonical_json(item[0]) if not isinstance(item[0], str) else item[0])


def sliding_window_hits(
    events: Sequence[Event], window_seconds: float, qualifies: Callable[[Sequence[Event]], bool]
) -> dict[str, Event]:
    """Union of events in every qualifying window that ends at an event (events must be sorted)."""
    hits: dict[str, Event] = {}
    start = 0
    for end in range(len(events)):
        while (events[end].ts - events[start].ts).total_seconds() > window_seconds:
            start += 1
        window = events[start : end + 1]
        if qualifies(window):
            for event in window:
                hits[event.id] = event
    return hits


def make_group_key(**parts: Any) -> str:
    return canonical_json(parts)


def build_detection(
    rule: Rule,
    evidence: Iterable[Event],
    group_key: str,
    summary: str,
    details: Mapping[str, Any] | None = None,
    techniques: tuple[str, ...] | None = None,
    stage: str | None = None,
) -> Detection:
    ordered = sorted(evidence, key=lambda e: e.sort_key)
    if not ordered:
        raise ValueError("A detection needs at least one evidence event")
    return Detection(
        rule_id=rule.id,
        rule_version=rule.version,
        rule_name=rule.name,
        severity=rule.severity,
        confidence=rule.confidence,
        stage=stage or rule.stage,
        techniques=rule.techniques if techniques is None else techniques,
        group_key=group_key,
        event_ids=tuple(e.id for e in ordered),
        first_ts=ordered[0].ts,
        last_ts=ordered[-1].ts,
        summary=summary,
        details=dict(details or {}),
    )
