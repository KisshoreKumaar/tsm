"""Deterministic incident analysis: chronological stages, candidate techniques, labelled claims and a title."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.core.timeutil import iso
from app.detection.base import NON_TACTIC_STAGES, Detection, Event
from app.detection.catalog import TechniqueCatalog

MAX_CITED_EVENTS = 25

SHORT_LABELS = {
    "AUTH-001": "Brute force",
    "AUTH-002": "Login after failures",
    "PROC-001": "Encoded PowerShell",
    "NET-001": "Network discovery",
    "FILE-001": "Mass file changes",
    "LOG-001": "Log cleared",
    "ACCT-001": "Account change",
    "INJ-001": "AI-directed text in logs",
    "SOURCE-001": "Upstream process alert",
    "SOURCE-002": "Upstream indicator alert",
}

INFERENCES = {
    "AUTH-001": "The failure pattern is consistent with password guessing; a mistyped password or a misconfigured "
    "service can produce the same pattern.",
    "AUTH-002": "A login that succeeds right after repeated failures is consistent with a guessed credential; the "
    "legitimate user may also have remembered the password.",
    "PROC-001": "Encoded PowerShell hides the command from casual review; administrators and some software also use "
    "it legitimately.",
    "NET-001": "Contacting many hosts and ports in a short time is consistent with service discovery; inventory and "
    "vulnerability scanners behave the same way.",
    "FILE-001": "A burst of file changes is consistent with encryption for impact; backups, sync clients and "
    "migrations can also change many files.",
    "LOG-001": "Clearing a security log removes evidence; administrators occasionally clear logs during maintenance.",
    "ACCT-001": "Account creation or privilege changes can provide persistence; they are also routine administration.",
    "INJ-001": "The text appears written to influence an AI assistant. AEGIS shows it as quoted data and never follows it.",
    "SOURCE-001": "An upstream tool considers the process suspicious; AEGIS has not verified that verdict.",
    "SOURCE-002": "An upstream tool reported the indicator as malicious; AEGIS has not verified its reputation.",
}

HYPOTHESES: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"AUTH-002"}), "The account may be compromised."),
    (frozenset({"AUTH-002", "PROC-001"}), "An attacker may be running commands with the compromised account."),
    (frozenset({"NET-001"}), "The host may be searching the network for further targets."),
    (frozenset({"FILE-001"}), "Ransomware or a destructive process may be encrypting files."),
    (frozenset({"LOG-001"}), "Someone may be removing evidence of their activity."),
    (frozenset({"ACCT-001"}), "An attacker may be creating or strengthening access for later use."),
    (frozenset({"INJ-001"}), "Someone may be trying to manipulate AI-assisted triage through log content."),
)


def _cite(event_ids: Sequence[str]) -> list[str]:
    return list(event_ids[:MAX_CITED_EVENTS])


def build_stages(
    events: Sequence[Event], detections: Sequence[Detection], catalog: TechniqueCatalog
) -> list[dict[str, Any]]:
    """Stages are ordered by their earliest evidence timestamp, never by rule-evaluation order."""
    order = {event.id: index for index, event in enumerate(sorted(events, key=lambda e: e.sort_key))}
    by_stage: dict[str, list[Detection]] = {}
    for detection in detections:
        by_stage.setdefault(detection.stage, []).append(detection)
    stages = []
    for stage, members in by_stage.items():
        event_ids = sorted({eid for d in members for eid in d.event_ids}, key=lambda eid: order.get(eid, 0))
        techniques = sorted({t for d in members for t in d.techniques})
        stages.append(
            {
                "stage": stage,
                "is_tactic": stage not in NON_TACTIC_STAGES,
                "first_ts": iso(min(d.first_ts for d in members)),
                "last_ts": iso(max(d.last_ts for d in members)),
                "rule_ids": sorted({d.rule_id for d in members}),
                "detection_ids": sorted(d.id for d in members),
                "event_ids": event_ids,
                "techniques": [catalog.require(t).public() for t in techniques],
                "summaries": [d.summary for d in sorted(members, key=lambda d: (d.first_ts, d.rule_id))],
            }
        )
    # Earliest evidence first; ties (e.g. AUTH-002 reusing AUTH-001's failures) break on the latest evidence.
    return sorted(stages, key=lambda s: (s["first_ts"], s["last_ts"], s["stage"]))


def build_analysis(
    events: Sequence[Event],
    active: Sequence[Detection],
    suppressed: Sequence[tuple[Detection, str | None]],
    catalog: TechniqueCatalog,
) -> dict[str, Any]:
    ordered_active = sorted(active, key=lambda d: (d.first_ts, d.rule_id, d.group_key))
    rule_ids = {d.rule_id for d in ordered_active}
    claims: list[dict[str, Any]] = []

    def claim(label: str, text: str, evidence: Sequence[str] = ()) -> None:
        claims.append({"id": f"c{len(claims) + 1}", "label": label, "text": text, "evidence_ids": _cite(evidence)})

    for detection in ordered_active:
        sources = sorted({e.source for e in events if e.id in set(detection.event_ids)})
        claim("FACT", f"{detection.summary} (reported by {', '.join(sources)}).", detection.event_ids)
    for rule_id in sorted(rule_ids):
        evidence = [eid for d in ordered_active if d.rule_id == rule_id for eid in d.event_ids]
        claim(
            "INFERENCE", INFERENCES.get(rule_id, "The rule threshold was met; legitimate activity can match."), evidence
        )
    for required, text in HYPOTHESES:
        if required <= rule_ids:
            evidence = [eid for d in ordered_active if d.rule_id in required for eid in d.event_ids]
            claim("HYPOTHESIS", text, evidence)
    claim(
        "UNKNOWN",
        "Whether the activity was authorised, how reliable the reporting sources are, and the user's intent are not known.",
    )
    if rule_ids & {"SOURCE-001", "SOURCE-002"}:
        claim(
            "UNKNOWN", "The upstream verdict has not been independently verified, and no ATT&CK technique is assumed."
        )

    technique_evidence: dict[str, set[str]] = {}
    for detection in ordered_active:
        for technique in detection.techniques:
            technique_evidence.setdefault(technique, set()).update(detection.event_ids)
    order = {event.id: index for index, event in enumerate(sorted(events, key=lambda e: e.sort_key))}
    techniques = [
        {
            **catalog.require(technique).public(),
            "status": "candidate",
            "note": "Candidate mapping from rule logic; analyst validation required.",
            "evidence_ids": _cite(sorted(ids, key=lambda eid: order.get(eid, 0))),
        }
        for technique, ids in sorted(technique_evidence.items())
    ]
    injection_ids = [e.id for e in events if e.injection_suspected]
    return {
        "stages": build_stages(events, ordered_active, catalog),
        "techniques": techniques,
        "claims": claims,
        "suppressed": [
            {"detection_id": d.id, "rule_id": d.rule_id, "suppression_id": sid, "summary": d.summary}
            for d, sid in suppressed
        ],
        "injection": {"suspected": bool(injection_ids), "event_ids": injection_ids[:MAX_CITED_EVENTS]},
        "sources": sorted({e.source for e in events}),
        "entities": {
            "source_ips": sorted({e.source_ip for e in events if e.source_ip})[:20],
            "destination_ips": sorted({e.destination_ip for e in events if e.destination_ip})[:20],
            "domains": sorted({e.domain for e in events if e.domain})[:20],
        },
        "attack_attribution": catalog.attribution,
    }


def build_title(asset: str, user: str, detections: Sequence[Detection]) -> str:
    labels: list[str] = []
    for detection in sorted(detections, key=lambda d: (d.first_ts, d.rule_id)):
        label = SHORT_LABELS.get(detection.rule_id, detection.rule_name)
        if label not in labels:
            labels.append(label)
    head = " → ".join(labels[:4]) if labels else "Correlated activity"
    if len(labels) > 4:
        head += f" (+{len(labels) - 4})"
    return f"{head} on {asset} ({user})"[:200]
