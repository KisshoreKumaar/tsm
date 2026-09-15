"""F2 routes: incident and campaign stories, regeneration and Markdown export."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query, Response

from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import AI_USE, READ
from app.core.routing import api_router
from app.features.core.models import EmptyIn

Reader = Annotated[Principal, Depends(require(READ))]
AiUser = Annotated[Principal, Depends(require(AI_USE))]
Id = Annotated[str, Path(min_length=1, max_length=64)]
Format = Annotated[Literal["full", "analyst", "executive"], Query(alias="format")]


def _markdown(text: str, filename: str) -> Response:
    return Response(
        text,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def router() -> APIRouter:
    r = api_router(tags=["story"])

    @r.get("/incidents/{incident_id}/story")
    def incident_story(incident_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("stories").incident_story(incident_id)
        return result

    @r.post("/incidents/{incident_id}/story/regenerate")
    def regenerate_story(incident_id: Id, _: EmptyIn, principal: AiUser, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("stories").regenerate(incident_id, principal)
        return result

    @r.get("/incidents/{incident_id}/story.md")
    def incident_story_markdown(incident_id: Id, _: Reader, ctx: CtxDep, fmt: Format = "full") -> Response:
        text, filename = ctx.service("stories").markdown("incident", incident_id, fmt)
        return _markdown(text, filename)

    @r.get("/campaigns/{campaign_id}/story")
    def campaign_story(campaign_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("stories").campaign_story(campaign_id)
        return result

    @r.get("/campaigns/{campaign_id}/story.md")
    def campaign_story_markdown(campaign_id: Id, _: Reader, ctx: CtxDep, fmt: Format = "full") -> Response:
        text, filename = ctx.service("stories").markdown("campaign", campaign_id, fmt)
        return _markdown(text, filename)

    return r
