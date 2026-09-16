"""Deterministic tuning candidates from analyst false-positive verdicts (A5). Never applied automatically.

For each rule with at least three incidents closed as FALSE_POSITIVE, AEGIS looks for an entity present in every one
of those incidents' detections and in no open or resolved incident for the rule. Entities analysts marked benign
rank first, then the most specific type. Built-in rules get a scoped suppression (or a maintenance window when every
verdict was `maintenance_window`); custom rules get an exclusion condition. A threshold change is suggested when
false-positive alerts sit just above the threshold and every true-positive alert is above the proposed value.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any

from app.core.db import Session
from app.core.jsonutil import canonical_json
from app.core.timeutil import parse_iso
from app.detection.base import Rule

MIN_FALSE_POSITIVE_CLOSURES = 3
ENTITY_PRIORITY = ("source_ip", "user", "process", "domain", "file_hash", "destination_ip", "asset")
_EXCLUSION_FIELDS = {
    "source_ip": ("source_ip", "equals"),
    "destination_ip": ("destination_ip", "equals"),
    "user": ("user", "equals"),
    "asset": ("asset", "equals"),
    "domain": ("domain", "equals"),
    "file_hash": ("file_hash", "equals"),
    "process": ("process_name", "contains"),
}
_SIZE_KEYS = ("distinct_targets", "failures", "changes", "matches")


@dataclass(frozen=True)
class Candidate:
    type: str
    rule_id: str
    scope: dict[str, Any]
    rationale: str
    evidence: dict[str, Any]


def fingerprint(kind: str, rule_id: str, scope: Mapping[str, Any]) -> str:
    material = canonical_json([kind, rule_id, {k: v for k, v in scope.items() if k != "expires_in_days"}])
    return hashlib.sha256(material.encode()).hexdigest()


def _size(row: Any) -> int:
    details = json.loads(row["details"] or "{}")
    for key in _SIZE_KEYS:
        if isinstance(details.get(key), int):
            return int(details[key])
    return len(json.loads(row["event_ids"]))


def _entities(session: Session, sql: str, params: tuple[Any, ...]) -> set[tuple[str, str]]:
    return {(row["entity_type"], row["value"]) for row in session.all(sql, params)}


def generate_candidates(
    session: Session, rules: Mapping[str, Rule], builtin_ids: Collection[str], *, rule_id: str | None = None
) -> list[Candidate]:
    clause, params = (" AND d.rule_id = ?", (rule_id,)) if rule_id else ("", ())
    rows = session.all(
        "SELECT DISTINCT d.rule_id, i.id AS incident_id, i.closure_category, i.closure_entities, i.first_seen "
        "FROM incidents i JOIN detections d ON d.incident_id = i.id "
        f"WHERE i.status = 'FALSE_POSITIVE' AND d.status = 'ACTIVE'{clause} ORDER BY d.rule_id, i.first_seen, i.id",
        params,
    )
    by_rule: dict[str, list[Any]] = defaultdict(list)
    for row in rows:
        by_rule[row["rule_id"]].append(row)

    candidates: list[Candidate] = []
    for current_rule_id, verdicts in sorted(by_rule.items()):
        rule = rules.get(current_rule_id)
        if rule is None or len(verdicts) < MIN_FALSE_POSITIVE_CLOSURES:
            continue
        counts: Counter[tuple[str, str]] = Counter()
        marked: Counter[tuple[str, str]] = Counter()
        for verdict in verdicts:
            counts.update(
                _entities(
                    session,
                    "SELECT DISTINCT ee.entity_type, ee.value FROM detections d "
                    "JOIN detection_events de ON de.detection_id = d.id JOIN event_entities ee ON ee.event_id = de.event_id "
                    "WHERE d.incident_id = ? AND d.rule_id = ? AND d.status = 'ACTIVE'",
                    (verdict["incident_id"], current_rule_id),
                )
            )
            for item in json.loads(verdict["closure_entities"] or "[]"):
                marked[(item["type"], item["value"])] += 1
        true_positive_entities = _entities(
            session,
            "SELECT DISTINCT ee.entity_type, ee.value FROM detections d JOIN incidents i ON i.id = d.incident_id "
            "JOIN detection_events de ON de.detection_id = d.id JOIN event_entities ee ON ee.event_id = de.event_id "
            "WHERE d.rule_id = ? AND d.status = 'ACTIVE' AND i.status NOT IN ('FALSE_POSITIVE', 'MERGED')",
            (current_rule_id,),
        )
        categories = Counter(str(v["closure_category"]) for v in verdicts)
        evidence = {
            "false_positive_incidents": [v["incident_id"] for v in verdicts][:20],
            "closures": len(verdicts),
            "categories": dict(sorted(categories.items())),
        }
        shared = [
            entity
            for entity, count in counts.items()
            if count >= MIN_FALSE_POSITIVE_CLOSURES and entity not in true_positive_entities
        ]
        if shared:
            best = sorted(
                shared,
                key=lambda e: (
                    -marked[e],
                    ENTITY_PRIORITY.index(e[0]) if e[0] in ENTITY_PRIORITY else len(ENTITY_PRIORITY),
                    -counts[e],
                    e[1],
                ),
            )[0]
            entity = {"type": best[0], "value": best[1]}
            why = (
                f"{len(verdicts)} incidents with {current_rule_id} were closed as false positives "
                f"({', '.join(f'{k} x{n}' for k, n in sorted(categories.items()))}). {best[0]} {best[1]} appears in "
                f"all of them{' and analysts marked it benign' if marked[best] else ''}, and in no open or resolved "
                "incident for this rule."
            )
            if current_rule_id not in builtin_ids:
                field, op = _EXCLUSION_FIELDS[best[0]]
                scope: dict[str, Any] = {"exclusion": {"field": field, "op": op, "value": best[1]}}
                candidates.append(Candidate("dsl_exclusion", current_rule_id, scope, why, evidence))
            elif categories.get("maintenance_window") == len(verdicts):
                seen = [parse_iso(v["first_seen"]) for v in verdicts]
                end_hour = max(moment.hour for moment in seen) + 1
                schedule = {
                    "days": sorted({moment.weekday() for moment in seen}),
                    "start": f"{min(moment.hour for moment in seen):02d}:00",
                    "end": "23:59" if end_hour >= 24 else f"{end_hour:02d}:00",
                }
                scope = {"entities": [entity], "schedule": schedule, "expires_in_days": 90}
                candidates.append(Candidate("maintenance_window", current_rule_id, scope, why, evidence))
            else:
                scope = {"entities": [entity], "expires_in_days": 30}
                candidates.append(Candidate("suppression", current_rule_id, scope, why, evidence))

        parameters = getattr(rule, "parameters", None)
        if getattr(rule, "TUNABLE", ()) and callable(parameters):
            current = int(parameters()["threshold"])
            sizes = session.all(
                "SELECT d.details, d.event_ids, i.status FROM detections d JOIN incidents i ON i.id = d.incident_id "
                "WHERE d.rule_id = ? AND d.status = 'ACTIVE' AND i.status != 'MERGED'",
                (current_rule_id,),
            )
            false_positive_sizes = [_size(r) for r in sizes if r["status"] == "FALSE_POSITIVE"]
            true_positive_sizes = [_size(r) for r in sizes if r["status"] != "FALSE_POSITIVE"]
            if false_positive_sizes:
                proposed = max(false_positive_sizes) + 1
                if current < proposed <= current * 2 and all(size >= proposed for size in true_positive_sizes):
                    candidates.append(
                        Candidate(
                            "threshold",
                            current_rule_id,
                            {"threshold": proposed},
                            f"False-positive {current_rule_id} alerts peaked at {max(false_positive_sizes)} against a "
                            f"threshold of {current}; no true-positive alert was below {proposed}.",
                            evidence,
                        )
                    )
    return candidates
