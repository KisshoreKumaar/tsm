"""Impact simulation for tuning changes (A5): which stored alerts a change would have removed.

Alerts are compared per correlated component by group key, so a threshold change that still fires on a slightly
different evidence set counts as kept. "True positive" means an alert in an incident not closed as FALSE_POSITIVE,
including incidents still open, which is deliberately conservative.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.db import Session
from app.core.timeutil import iso
from app.detection.base import Rule
from app.rules.backtest import incident_links, load_events, split_components
from app.tuning.changes import TuningChange

IMPACT_LABEL = (
    "Simulated over stored events in the range. True positives are alerts in incidents not closed as "
    "FALSE_POSITIVE (open incidents included)."
)


def simulate(
    session: Session, rule: Rule, change: TuningChange, *, start: datetime, end: datetime, window_seconds: int
) -> dict[str, Any]:
    events, truncated = load_events(session, start, end)
    links = incident_links(session, start, end)
    modified = change.modified(rule)
    alerts_before = false_positive = true_positive = unlinked = 0
    false_positive_incidents: set[str] = set()
    true_positive_incidents: set[str] = set()
    samples: list[dict[str, Any]] = []
    for component in split_components(events, window_seconds):
        before = rule.evaluate(component)
        if not before:
            continue
        alerts_before += len(before)
        if change.suppressive:
            kept = {d.group_key for d in before if not change.suppresses(session, d)}
        else:
            kept = {d.group_key for d in modified.evaluate(component)}
        for detection in before:
            if detection.group_key in kept:
                continue
            linked = {links[event_id] for event_id in detection.event_ids if event_id in links}
            if not linked:
                unlinked += 1
            elif all(status == "FALSE_POSITIVE" for _, status in linked):
                false_positive += 1
                false_positive_incidents.update(incident_id for incident_id, _ in linked)
            else:
                true_positive += 1
                true_positive_incidents.update(i for i, status in linked if status != "FALSE_POSITIVE")
            if len(samples) < 10:
                samples.append(
                    {
                        "summary": detection.summary,
                        "first_ts": iso(detection.first_ts),
                        "event_ids": list(detection.event_ids[:10]),
                        "incident_ids": sorted(incident_id for incident_id, _ in linked),
                    }
                )
    lost = sorted(
        incident_id
        for incident_id in true_positive_incidents
        if not session.scalar(
            "SELECT count(*) FROM detections WHERE incident_id = ? AND status = 'ACTIVE' AND rule_id != ?",
            (incident_id, rule.id),
        )
    )
    return {
        "range": {"start": iso(start), "end": iso(end)},
        "events_scanned": len(events),
        "truncated": truncated,
        "alerts_before": alerts_before,
        "alerts_removed": false_positive + true_positive + unlinked,
        "false_positive_alerts_removed": false_positive,
        "true_positive_alerts_removed": true_positive,
        "unlinked_alerts_removed": unlinked,
        "false_positive_incidents_affected": len(false_positive_incidents),
        "true_positive_incidents_affected": sorted(true_positive_incidents)[:50],
        "true_positive_incidents_lost": lost[:50],
        "true_positives_lost": len(lost),
        "red_flag": true_positive > 0,
        "sample_removed": samples,
        "label": IMPACT_LABEL,
    }
