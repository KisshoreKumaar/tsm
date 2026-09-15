"""F4 routes: incident predictions, watchlist, hit rate, explanations and the curated transition model."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query
from pydantic import BaseModel, ConfigDict

from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import AI_USE, READ
from app.core.routing import api_router

Reader = Annotated[Principal, Depends(require(READ))]
AiUser = Annotated[Principal, Depends(require(AI_USE))]
Id = Annotated[str, Path(min_length=1, max_length=64)]


class ExplainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")


def router() -> APIRouter:
    r = api_router(tags=["prediction"])

    @r.get("/incidents/{incident_id}/predictions")
    def incident_predictions(incident_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("predictions").for_incident(incident_id)
        return result

    @r.post("/incidents/{incident_id}/predictions/explain", status_code=202)
    def explain_predictions(incident_id: Id, _: ExplainIn, principal: AiUser, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("predictions").request_explanation(incident_id, principal)
        return result

    @r.get("/predictions")
    def watchlist(
        _: Reader,
        ctx: CtxDep,
        status: Literal["WATCHING", "OBSERVED", "EXPIRED"] | None = None,
        offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("predictions").search(status, offset, limit)
        return result

    @r.get("/metrics/prediction-hit-rate")
    def prediction_hit_rate(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("predictions").hit_rate()
        return result

    @r.get("/attack/transitions")
    def transition_model(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("predictions").model_public()
        return result

    return r
