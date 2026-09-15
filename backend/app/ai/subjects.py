"""Load AI subjects (incident, campaign, whole workspace) in the shape evidence packs expect."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.ai.evidence import EvidencePack, Redactor
from app.core.errors import NotFound


def campaign_as_detail(campaign: Mapping[str, Any], details: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    events = sorted((e for d in details for e in d["events"]), key=lambda e: (e["timestamp"], e["id"]))
    stages = sorted((s for d in details for s in d["analysis"]["stages"]), key=lambda s: (s["first_ts"], s["stage"]))
    techniques: dict[str, Any] = {}
    for detail in details:
        for technique in detail["analysis"]["techniques"]:
            techniques.setdefault(technique["id"], technique)
    return {
        "id": campaign["id"],
        "revision": campaign["revision"],
        "title": campaign["title"],
        "status": campaign["status"],
        "severity": campaign["severity"],
        "risk_score": campaign["risk_score"],
        "risk": campaign.get(
            "risk", {"score": campaign["risk_score"], "severity": campaign["severity"], "factors": []}
        ),
        "asset": ", ".join(campaign["assets"])[:200],
        "user": ", ".join(campaign["users"])[:200],
        "owner": None,
        "first_seen": campaign["first_seen"],
        "last_seen": campaign["last_seen"],
        "event_count": len(events),
        "events": events,
        "detections": [d for detail in details for d in detail["detections"]],
        "responses": [r for detail in details for r in detail["responses"]],
        "analysis": {
            "stages": stages,
            "techniques": list(techniques.values()),
            "claims": [
                *(
                    {"label": "FACT", "text": link["reason"], "evidence_ids": link["supporting_event_ids"][:5]}
                    for link in campaign.get("links", [])[:4]
                ),
                *(c for detail in details for c in detail["analysis"]["claims"][:2]),
            ],
            "injection": {"suspected": any(d["analysis"]["injection"]["suspected"] for d in details), "event_ids": []},
            "sources": sorted({s for d in details for s in d["analysis"].get("sources", [])}),
        },
    }


def load_subject(ctx: Any, subject_type: str, subject_id: str | None) -> dict[str, Any]:
    if subject_type == "incident" and subject_id:
        detail: dict[str, Any] = ctx.service("incidents").get(subject_id)
        return detail
    if subject_type == "campaign" and subject_id:
        if "f1" not in ctx.features:
            raise NotFound("Campaigns are not enabled")
        campaign = ctx.service("campaigns").get(subject_id)
        details = [ctx.service("incidents").get(item["id"]) for item in campaign["incidents"]]
        return campaign_as_detail(campaign, details)
    raise NotFound("Unknown AI subject")


def subject_revision(ctx: Any, subject_type: str, subject_id: str | None) -> int | None:
    if not subject_id:
        return None
    table = {"incident": "incidents", "campaign": "campaigns"}.get(subject_type)
    if table is None:
        return None
    with ctx.db.read() as session:
        value = session.scalar(f"SELECT revision FROM {table} WHERE id = ?", (subject_id,))
    if value is None:
        raise NotFound(f"Unknown {subject_type}")
    return int(value)


def global_pack(ctx: Any, *, redact: bool) -> EvidencePack:
    overview = ctx.service("overview").get()
    data: dict[str, Any] = {
        "workspace": {
            "metrics": {
                k: overview["metrics"].get(k)
                for k in ("events_24h", "detections_active", "highest_open_risk", "isolated_endpoints")
            },
            "open_incidents_by_severity": overview["open_incidents_by_severity"],
            "responses_by_status": overview["responses_by_status"],
        },
        "top_incidents": [
            [i["id"], i["title"], i["status"], i["severity"], i["risk_score"]] for i in overview["top_incidents"]
        ],
        "events": [],
    }
    redactor = Redactor(users=[i["user"] for i in overview["top_incidents"]]) if redact else None
    if redactor is not None:
        data = redactor.redact_value(data)
    return EvidencePack(data=data, alias_to_event={}, redactor=redactor)
