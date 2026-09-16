"""Backtests (A3) and component evaluation shared with tuning impact simulation (A5).

Stored events are regrouped exactly like the ingestion pipeline (same asset and user, chained while gaps stay within
the incident window) so a rule sees the same components it would see in production.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from app.core.db import Session
from app.core.timeutil import iso
from app.correlation.pipeline import _event_from
from app.demo.scenarios import SCENARIOS, materialize, step_start_offsets
from app.detection.base import Event, Rule
from app.ingest.normalize import normalize

MAX_BACKTEST_EVENTS = 50_000
BACKTEST_LABEL = (
    "Backtest over stored events in the selected range. Alert-rate estimates are heuristics, not forecasts."
)


def split_components(events: Sequence[Event], window_seconds: int) -> list[list[Event]]:
    by_entity: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in sorted(events, key=lambda e: e.sort_key):
        by_entity[(event.asset, event.username)].append(event)
    components: list[list[Event]] = []
    for key in sorted(by_entity):
        current: list[Event] = []
        for event in by_entity[key]:
            if current and (event.ts - current[-1].ts).total_seconds() > window_seconds:
                components.append(current)
                current = []
            current.append(event)
        if current:
            components.append(current)
    return components


def load_events(session: Session, start: datetime, end: datetime) -> tuple[list[Event], bool]:
    rows = session.all(
        "SELECT * FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts, source, external_id, digest LIMIT ?",
        (iso(start), iso(end), MAX_BACKTEST_EVENTS + 1),
    )
    return [Event.from_row(row) for row in rows[:MAX_BACKTEST_EVENTS]], len(rows) > MAX_BACKTEST_EVENTS


def incident_links(session: Session, start: datetime, end: datetime) -> dict[str, tuple[str, str]]:
    """Event ID -> (incident ID, incident status) for non-merged incidents."""
    rows = session.all(
        "SELECT ie.event_id, i.id AS incident_id, i.status FROM incident_events ie "
        "JOIN incidents i ON i.id = ie.incident_id JOIN events e ON e.id = ie.event_id "
        "WHERE i.status != 'MERGED' AND e.ts >= ? AND e.ts <= ?",
        (iso(start), iso(end)),
    )
    return {row["event_id"]: (row["incident_id"], row["status"]) for row in rows}


@lru_cache(maxsize=1)
def benign_sample_events() -> tuple[Event, ...]:
    """The synthetic benign workday, normalised in memory (never stored), for false-positive checks."""
    scenario = SCENARIOS["benign"]
    steps = scenario.build("backtest")
    base = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
    starts = step_start_offsets(steps, scenario.step_gap_seconds)
    events: list[Event] = []
    for index in range(len(steps)):
        raws = materialize(scenario, "backtest", index, "benign-sample", base + timedelta(seconds=starts[index]))
        for position, raw in enumerate(raws):
            events.append(_event_from(f"benign-{index}-{position}", normalize(raw)))
    return tuple(events)


def run_backtest(
    session: Session, rule: Rule, *, start: datetime, end: datetime, incident_window_seconds: int
) -> dict[str, Any]:
    began = time.perf_counter()
    events, truncated = load_events(session, start, end)
    links = incident_links(session, start, end)
    other_rules: dict[str, set[str]] = defaultdict(set)
    for row in session.all(
        "SELECT d.rule_id, de.event_id FROM detection_events de JOIN detections d ON d.id = de.detection_id "
        "JOIN events e ON e.id = de.event_id WHERE d.status = 'ACTIVE' AND d.rule_id != ? AND e.ts >= ? AND e.ts <= ?",
        (rule.id, iso(start), iso(end)),
    ):
        other_rules[row["event_id"]].add(row["rule_id"])

    detections = []
    for component in split_components(events, incident_window_seconds):
        detections.extend(rule.evaluate(component))
    matched_incidents: dict[str, str] = {}
    overlap: Counter[str] = Counter()
    new_incidents = false_positive_matches = 0
    samples: list[dict[str, Any]] = []
    for detection in detections:
        linked = {links[event_id] for event_id in detection.event_ids if event_id in links}
        if linked:
            matched_incidents.update(dict(linked))
        else:
            new_incidents += 1
        if any(status == "FALSE_POSITIVE" for _, status in linked):
            false_positive_matches += 1
        for other in set().union(*(other_rules.get(event_id, set()) for event_id in detection.event_ids)):
            overlap[other] += 1
        if len(samples) < 10:
            samples.append(
                {
                    "summary": detection.summary,
                    "first_ts": iso(detection.first_ts),
                    "last_ts": iso(detection.last_ts),
                    "event_ids": list(detection.event_ids[:20]),
                    "incident_ids": sorted({incident_id for incident_id, _ in linked}),
                }
            )
    benign = benign_sample_events()
    benign_matches = sum(len(rule.evaluate(c)) for c in split_components(benign, incident_window_seconds))
    days = max(1.0, (end - start).total_seconds() / 86_400)
    return {
        "range": {"start": iso(start), "end": iso(end)},
        "events_scanned": len(events),
        "truncated": truncated,
        "total_matches": len({event_id for d in detections for event_id in d.event_ids}),
        "detections": len(detections),
        "incidents_that_would_be_created": new_incidents,
        "existing_incidents_matched": len(matched_incidents),
        "matched_incident_ids": sorted(matched_incidents)[:50],
        "overlap_with_existing_rules": dict(sorted(overlap.items())),
        "matches_in_false_positive_incidents": false_positive_matches,
        "matches_in_benign_scenario": benign_matches,
        "estimated_alerts_per_day": round(len(detections) / days, 2),
        "sample_hits": samples,
        "runtime_ms": round((time.perf_counter() - began) * 1000, 1),
        "label": BACKTEST_LABEL,
    }
