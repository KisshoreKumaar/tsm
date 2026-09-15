"""CORE domain routes: ingestion, events, incidents, rules, simulated responses, overview and demo scenarios."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, Path, Query, Response

from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import INGEST, INVESTIGATE, READ, RESPOND_APPROVE, RESPOND_EXECUTE, RESPOND_RECOMMEND
from app.features.core.models import (
    ApproveIn,
    DemoRunIn,
    EmptyIn,
    IncidentUpdateIn,
    NoteIn,
    RejectIn,
    ResponseRequestIn,
)
from app.ingest.schemas import EventBatchIn

Reader = Annotated[Principal, Depends(require(READ))]
Ingestor = Annotated[Principal, Depends(require(INGEST))]
Investigator = Annotated[Principal, Depends(require(INVESTIGATE))]
Recommender = Annotated[Principal, Depends(require(RESPOND_RECOMMEND))]
Approver = Annotated[Principal, Depends(require(RESPOND_APPROVE))]
Executor = Annotated[Principal, Depends(require(RESPOND_EXECUTE))]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Limit = Annotated[int, Query(ge=1, le=200)]
Id = Annotated[str, Path(min_length=1, max_length=64)]
Text = Annotated[str | None, Query(max_length=255)]


def register_core_routes(r: APIRouter) -> None:
    # -- ingestion and events ------------------------------------------------------------------------

    @r.post("/events", status_code=201, tags=["events"])
    def ingest_event(
        payload: Annotated[dict[str, Any], Body()], principal: Ingestor, ctx: CtxDep, response: Response
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("events").ingest([payload], principal)
        if result["duplicates"]:
            response.status_code = 200
        return result

    @r.post("/events/batch", status_code=201, tags=["events"])
    def ingest_batch(body: EventBatchIn, principal: Ingestor, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("events").ingest(body.events, principal)
        return result

    @r.get("/events", tags=["events"])
    def list_events(
        _: Reader,
        ctx: CtxDep,
        q: Annotated[str | None, Query(max_length=200)] = None,
        kind: Annotated[str | None, Query(max_length=50)] = None,
        asset: Text = None,
        user: Text = None,
        source: Annotated[str | None, Query(max_length=100)] = None,
        incident_id: Annotated[str | None, Query(max_length=64)] = None,
        injection: bool | None = None,
        since: Annotated[str | None, Query(max_length=40)] = None,
        until: Annotated[str | None, Query(max_length=40)] = None,
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("events").list(
            q=q,
            kind=kind,
            asset=asset,
            user=user,
            source=source,
            incident_id=incident_id,
            injection=injection,
            since=since,
            until=until,
            offset=offset,
            limit=limit,
        )
        return result

    @r.get("/events/{event_id}", tags=["events"])
    def get_event(event_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("events").get(event_id)
        return result

    @r.get("/event-kinds", tags=["events"])
    def event_kinds(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("events").kinds()
        return result

    @r.get("/overview", tags=["overview"])
    def overview(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("overview").get()
        return result

    # -- incidents -----------------------------------------------------------------------------------

    @r.get("/incidents", tags=["incidents"])
    def list_incidents(
        _: Reader,
        ctx: CtxDep,
        q: Annotated[str | None, Query(max_length=200)] = None,
        status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "MERGED"] | None = None,
        severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
        sort: Literal["updated", "risk", "first_seen"] = "updated",
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("incidents").list(
            q=q, status=status, severity=severity, sort=sort, offset=offset, limit=limit
        )
        return result

    @r.get("/incidents/{incident_id}", tags=["incidents"])
    def get_incident(incident_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("incidents").get(incident_id)
        return result

    @r.patch("/incidents/{incident_id}", tags=["incidents"])
    def update_incident(
        incident_id: Id, body: IncidentUpdateIn, principal: Investigator, ctx: CtxDep
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("incidents").update(incident_id, body, principal)
        return result

    @r.post("/incidents/{incident_id}/notes", status_code=201, tags=["incidents"])
    def add_note(incident_id: Id, body: NoteIn, principal: Investigator, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("incidents").add_note(incident_id, body.text, principal.name)
        return result

    @r.get("/rules", tags=["detection"])
    def list_rules(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        return {"rules": ctx.service("rules").describe()}

    @r.get("/attack/techniques", tags=["detection"])
    def attack_catalog(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("catalog").public()
        return result

    # -- simulated responses -------------------------------------------------------------------------

    @r.get("/playbooks", tags=["responses"])
    def playbooks(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("responses").playbooks()
        return result

    @r.get("/responses", tags=["responses"])
    def list_responses(
        _: Reader,
        ctx: CtxDep,
        status: Literal["PENDING", "APPROVED", "EXECUTED", "REJECTED", "CANCELLED", "EXPIRED"] | None = None,
        incident_id: Annotated[str | None, Query(max_length=64)] = None,
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("responses").list(
            status=status, incident_id=incident_id, offset=offset, limit=limit
        )
        return result

    @r.post("/responses", status_code=201, tags=["responses"])
    def request_response(body: ResponseRequestIn, principal: Recommender, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("responses").recommend(body, principal)
        return result

    @r.get("/responses/{response_id}", tags=["responses"])
    def get_response(response_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("responses").get(response_id)
        return result

    @r.post("/responses/{response_id}/approve", tags=["responses"])
    def approve_response(response_id: Id, body: ApproveIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("responses").approve(response_id, body.confirmation, principal)
        return result

    @r.post("/responses/{response_id}/reject", tags=["responses"])
    def reject_response(response_id: Id, body: RejectIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("responses").reject(response_id, body.reason, principal)
        return result

    @r.post("/responses/{response_id}/execute", tags=["responses"])
    def execute_response(response_id: Id, _: EmptyIn, principal: Executor, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("responses").execute(response_id, principal)
        return result

    @r.get("/endpoints", tags=["responses"])
    def endpoints(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("responses").endpoints()
        return result

    # -- demo scenarios ------------------------------------------------------------------------------

    @r.get("/demo/scenarios", tags=["demo"])
    def demo_scenarios(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("demo").scenarios()
        return result

    @r.post("/demo/run", status_code=201, tags=["demo"])
    def demo_run(body: DemoRunIn, principal: Ingestor, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("demo").run(body.scenario, body.mode, principal)
        return result

    @r.get("/demo/runs/{run_id}", tags=["demo"])
    def demo_run_status(run_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("demo").get_run(run_id)
        return result
