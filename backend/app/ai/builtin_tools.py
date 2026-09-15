"""Read-only agent tools for CORE, F1 and F2. They never write; events they return get evidence aliases."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.ai.tools import ToolContext, ToolError, ToolSpec


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class NoArgs(Args):
    pass


class IncidentArg(Args):
    incident_id: str | None = Field(default=None, max_length=64)


class CampaignArg(Args):
    campaign_id: str | None = Field(default=None, max_length=64)


class SearchArgs(Args):
    query: str | None = Field(default=None, max_length=100)
    kind: str | None = Field(default=None, max_length=40)
    asset: str | None = Field(default=None, max_length=255)
    user: str | None = Field(default=None, max_length=255)
    limit: int = Field(default=5, ge=1, le=10)


class EntityArgs(Args):
    entity_type: Literal["asset", "user", "source_ip", "destination_ip", "domain", "file_hash", "process"]
    value: str = Field(min_length=1, max_length=255)


class ListIncidentsArgs(Args):
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"] | None = None
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    limit: int = Field(default=5, ge=1, le=10)


class RuleArg(Args):
    rule_id: str | None = Field(default=None, max_length=20)


class ResponsesArgs(Args):
    status: Literal["PENDING", "APPROVED", "EXECUTED", "REJECTED", "CANCELLED", "EXPIRED"] | None = None
    limit: int = Field(default=5, ge=1, le=10)


def incident_id_for(tc: ToolContext, value: str | None) -> str:
    if value:
        return value
    if tc.subject_type == "incident" and tc.subject_id:
        return tc.subject_id
    raise ToolError("incident_id is required")


def campaign_id_for(tc: ToolContext, value: str | None) -> str:
    if value:
        return value
    if tc.subject_type == "campaign" and tc.subject_id:
        return tc.subject_id
    raise ToolError("campaign_id is required")


def _aliases(tc: ToolContext, events_by_id: dict[str, Any], event_ids: list[str]) -> list[str]:
    events = [events_by_id[e] for e in event_ids if e in events_by_id]
    return [row[0] for row in tc.pack.add_events(events)]


def get_incident(tc: ToolContext, args: IncidentArg) -> dict[str, Any]:
    detail = tc.ctx.service("incidents").get(incident_id_for(tc, args.incident_id))
    events_by_id = {e["id"]: e for e in detail["events"]}
    detections = []
    for d in detail["detections"][:8]:
        ids = d["event_ids"]
        detections.append(
            [d["rule_id"], d["status"], d["summary"], _aliases(tc, events_by_id, [ids[0], ids[-1]] if ids else [])]
        )
    return {
        "id": detail["id"],
        "title": detail["title"],
        "status": detail["status"],
        "severity": detail["severity"],
        "risk_heuristic": detail["risk_score"],
        "revision": detail["revision"],
        "owner": detail["owner"],
        "asset": detail["asset"],
        "user": detail["user"],
        "stages": [[s["stage"], s["rule_ids"], s["first_ts"][11:19]] for s in detail["analysis"]["stages"]],
        "detections": detections,
        "responses": [[r["playbook"], r["status"]] for r in detail["responses"][:5]],
    }


def get_story(tc: ToolContext, args: IncidentArg) -> dict[str, Any]:
    incident_id = incident_id_for(tc, args.incident_id)
    story = tc.ctx.service("stories").incident_story(incident_id)["story"]
    detail = tc.ctx.service("incidents").get(incident_id)
    events_by_id = {e["id"]: e for e in detail["events"]}
    return {
        "badge": story["badge"],
        "executive": [
            [
                line["heading"],
                line["sentence"]["text"],
                _aliases(tc, events_by_id, line["sentence"]["evidence_ids"][:4]),
            ]
            for line in story["executive"]["lines"]
        ],
    }


def search_events(tc: ToolContext, args: SearchArgs) -> dict[str, Any]:
    page = tc.ctx.service("events").list(
        q=args.query, kind=args.kind, asset=args.asset, user=args.user, limit=args.limit
    )
    return {"total": page["total"], "events": tc.pack.add_events(page["items"])}


def get_entity_history(tc: ToolContext, args: EntityArgs) -> dict[str, Any]:
    entity = tc.ctx.service("campaigns").entity(args.entity_type, args.value)
    return {
        "value": entity["value"],
        "events": entity["events"],
        "first_seen": entity["first_seen"],
        "last_seen": entity["last_seen"],
        "assets": entity["assets"][:10],
        "users": entity["users"][:10],
        "incidents": [[i["id"], i["title"], i["status"]] for i in entity["incidents"][:5]],
        "allowlisted": entity["allowlisted"],
    }


def get_related_incidents(tc: ToolContext, args: IncidentArg) -> dict[str, Any]:
    related = tc.ctx.service("campaigns").related(incident_id_for(tc, args.incident_id))
    return {
        "campaign": [related["campaign"]["id"], related["campaign"]["title"]] if related["campaign"] else None,
        "links": [link["reason"] for link in related["links"][:6]],
        "related_incidents": [[i["id"], i["title"], i["status"]] for i in related["related_incidents"][:6]],
    }


def get_campaign(tc: ToolContext, args: CampaignArg) -> dict[str, Any]:
    campaign = tc.ctx.service("campaigns").get(campaign_id_for(tc, args.campaign_id))
    return {
        "id": campaign["id"],
        "title": campaign["title"],
        "severity": campaign["severity"],
        "risk_heuristic": campaign["risk_score"],
        "assets": campaign["assets"],
        "users": campaign["users"],
        "links": [link["reason"] for link in campaign["links"][:6]],
        "incidents": [[i["id"], i["title"], i["status"]] for i in campaign["incidents"][:8]],
    }


def list_rules(tc: ToolContext, _: NoArgs) -> dict[str, Any]:
    return {"rules": [[r["id"], r["name"], r["stage"]] for r in tc.ctx.service("rules").describe()]}


def get_false_positive_history(tc: ToolContext, args: RuleArg) -> dict[str, Any]:
    clauses, params = ["i.status = 'FALSE_POSITIVE'"], []
    if args.rule_id:
        clauses.append("d.rule_id = ?")
        params.append(args.rule_id.upper())
    with tc.ctx.db.read() as session:
        rows = session.all(
            "SELECT d.rule_id, i.closure_category, count(DISTINCT i.id) AS n FROM incidents i "
            f"JOIN detections d ON d.incident_id = i.id WHERE {' AND '.join(clauses)} "
            "GROUP BY d.rule_id, i.closure_category ORDER BY n DESC LIMIT 20",
            params,
        )
    return {"false_positive_closures": [[r["rule_id"], r["closure_category"], r["n"]] for r in rows]}


def list_incidents(tc: ToolContext, args: ListIncidentsArgs) -> dict[str, Any]:
    page = tc.ctx.service("incidents").list(status=args.status, severity=args.severity, limit=args.limit, sort="risk")
    return {
        "total": page["total"],
        "incidents": [
            [i["id"], i["title"], i["status"], i["severity"], i["risk_score"], i["revision"]] for i in page["items"]
        ],
    }


def get_overview(tc: ToolContext, _: NoArgs) -> dict[str, Any]:
    overview = tc.ctx.service("overview").get()
    return {
        "metrics": {
            k: overview["metrics"][k]
            for k in ("events_24h", "detections_active", "highest_open_risk", "isolated_endpoints")
        },
        "open_by_severity": overview["open_incidents_by_severity"],
        "responses_by_status": overview["responses_by_status"],
    }


def list_responses(tc: ToolContext, args: ResponsesArgs) -> dict[str, Any]:
    page = tc.ctx.service("responses").list(status=args.status, limit=args.limit)
    return {"responses": [[r["id"], r["incident_id"], r["playbook"], r["status"]] for r in page["items"]]}


def verify_audit(tc: ToolContext, _: NoArgs) -> dict[str, Any]:
    result = tc.ctx.audit.verify(tc.ctx.db)
    return {"valid": result["valid"], "records": result["records"]}


def builtin_tools() -> list[ToolSpec]:
    return [
        ToolSpec("get_incident", "core", "incident summary, stages, detections", IncidentArg, get_incident),
        ToolSpec("search_events", "core", "search stored events (query, kind, asset, user)", SearchArgs, search_events),
        ToolSpec("list_rules", "core", "detection rules", NoArgs, list_rules),
        ToolSpec(
            "get_false_positive_history",
            "core",
            "past false-positive closures by rule",
            RuleArg,
            get_false_positive_history,
        ),
        ToolSpec(
            "list_incidents",
            "core",
            "incidents by status/severity, highest risk first",
            ListIncidentsArgs,
            list_incidents,
        ),
        ToolSpec("get_overview", "core", "workspace metrics", NoArgs, get_overview),
        ToolSpec("list_responses", "core", "simulated response requests", ResponsesArgs, list_responses),
        ToolSpec("verify_audit", "core", "audit chain verification result", NoArgs, verify_audit),
        ToolSpec(
            "get_entity_history",
            "f1",
            "history of a user, IP, domain, hash, asset or process",
            EntityArgs,
            get_entity_history,
        ),
        ToolSpec(
            "get_related_incidents",
            "f1",
            "campaign and linked incidents with reasons",
            IncidentArg,
            get_related_incidents,
        ),
        ToolSpec("get_campaign", "f1", "campaign summary and link reasons", CampaignArg, get_campaign),
        ToolSpec("get_story", "f2", "executive story of an incident", IncidentArg, get_story),
    ]


# Names only: tools of disabled features (e.g. F4's get_predictions) are simply absent from the loop.
F3_DEEP_TOOLS = (
    "get_incident",
    "get_story",
    "search_events",
    "get_entity_history",
    "get_related_incidents",
    "get_campaign",
    "list_rules",
    "get_predictions",
    "get_false_positive_history",
)
