"""Deterministic rule drafts from an incident (A3). Used when no LLM is available or its draft fails validation."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping
from typing import Any

from app.core.timeutil import parse_iso
from app.detection.base import SEVERITY_RANK
from app.ingest.normalize import process_basename


class DraftError(ValueError):
    pass


def draft_from_incident(detail: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """A general rule for the incident's strongest detection: its dominant event kind, shared behaviour, a threshold."""
    detections = [d for d in detail["detections"] if d["status"] == "ACTIVE"] or list(detail["detections"])
    if not detections:
        raise DraftError("The incident has no detections to draft a rule from")
    primary = sorted(detections, key=lambda d: (-SEVERITY_RANK[d["severity"]], d["first_ts"], d["rule_id"]))[0]
    events_by_id = {event["id"]: event for event in detail["events"]}
    evidence = [events_by_id[event_id] for event_id in primary["event_ids"] if event_id in events_by_id]
    if not evidence:
        raise DraftError("The strongest detection has no stored evidence events")
    kind = sorted(Counter(e["kind"] for e in evidence).items(), key=lambda item: (-item[1], item[0]))[0][0]
    candidates = [e for e in evidence if e["kind"] == kind]

    conditions: list[dict[str, Any]] = []
    processes = {process_basename(e.get("process_name")) for e in candidates}
    if len(processes) == 1 and (process := next(iter(processes))):
        conditions.append({"field": "process_name", "op": "contains", "value": process})
    token_sets = [
        {t.lower() for t in (e.get("command_line") or "").split() if t[:1] in "-/" and 2 <= len(t) <= 40}
        for e in candidates
    ]
    shared_flags = sorted(set.intersection(*token_sets)) if token_sets and all(token_sets) else []
    if shared_flags:
        conditions.append({"field": "command_line", "op": "contains", "value": shared_flags[:2]})
    ports = sorted({e["destination_port"] for e in candidates if e.get("destination_port") is not None})
    if ports and len(ports) <= 5:
        conditions.append({"field": "destination_port", "op": "in", "value": ports})

    group_by = ["asset", "user"]
    source_ips = {e.get("source_ip") for e in candidates}
    if len(source_ips) == 1 and next(iter(source_ips)):
        group_by.append("source_ip")
    timestamps = sorted(parse_iso(e["timestamp"]) for e in candidates)
    span = (timestamps[-1] - timestamps[0]).total_seconds()
    window = int(min(3600, max(60, math.ceil(span) + 1)))
    destinations = {e.get("destination_ip") for e in candidates if e.get("destination_ip")}
    if kind == "network_connection" and len(destinations) >= 3:
        threshold: dict[str, Any] = {"type": "distinct_count", "field": "destination_ip", "value": len(destinations)}
    else:
        threshold = {"type": "count", "value": max(1, min(len(candidates), 50))}

    described = threshold["value"] if threshold["type"] == "count" else f"{threshold['value']} distinct destinations"
    definition = {
        "name": f"Draft: {primary['rule_name']} pattern"[:120],
        "description": (
            f"Drafted from incident {detail['id'][:8]} ({primary['rule_id']}): {described} {kind} events grouped by "
            f"{', '.join(group_by)} within {window} seconds. Review, backtest and adjust before approval."
        )[:1000],
        "severity": primary["severity"],
        "confidence": 50,
        "techniques": list(primary["techniques"]),
        "known_false_positives": ["Authorised activity following the same pattern, such as scheduled jobs"],
        "logic": {
            "kinds": [kind],
            "conditions": conditions,
            "group_by": group_by,
            "window_seconds": window,
            "threshold": threshold,
        },
    }
    rationale = (
        f"Generalises {primary['rule_id']} evidence from this incident ({len(candidates)} {kind} events) into a "
        "threshold rule; it avoids one-off values such as a single attacker IP."
    )
    return definition, rationale
