"""F1 routes: campaigns, related incidents, entity pivots and graph data."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query

from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import READ
from app.core.routing import api_router

Reader = Annotated[Principal, Depends(require(READ))]
Id = Annotated[str, Path(min_length=1, max_length=64)]
EntityType = Literal["asset", "user", "source_ip", "destination_ip", "domain", "file_hash", "process"]


def router() -> APIRouter:
    r = api_router(tags=["correlation"])

    @r.get("/campaigns")
    def list_campaigns(
        _: Reader,
        ctx: CtxDep,
        status: Literal["ACTIVE", "MERGED", "DISSOLVED"] = "ACTIVE",
        offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("campaigns").search(status=status, offset=offset, limit=limit)
        return result

    @r.get("/campaigns/{campaign_id}")
    def get_campaign(campaign_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("campaigns").get(campaign_id)
        return result

    @r.get("/incidents/{incident_id}/related")
    def related_incidents(incident_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("campaigns").related(incident_id)
        return result

    @r.get("/entities/{entity_type}/{value}")
    def entity_pivot(
        entity_type: EntityType,
        value: Annotated[str, Path(min_length=1, max_length=255)],
        _: Reader,
        ctx: CtxDep,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("campaigns").entity(entity_type, value)
        return result

    @r.get("/graph")
    def correlation_graph(
        _: Reader,
        ctx: CtxDep,
        campaign_id: Annotated[str | None, Query(max_length=64)] = None,
        incident_id: Annotated[str | None, Query(max_length=64)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 150,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("campaigns").graph(
            campaign_id=campaign_id, incident_id=incident_id, limit=limit
        )
        return result

    return r
