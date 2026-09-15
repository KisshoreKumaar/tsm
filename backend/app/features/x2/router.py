"""X2 routes: agent proposals and tool catalogue. Applying checks the target action's permission inside."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query

from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import AI_USE, AUTHENTICATED, READ
from app.core.routing import api_router
from app.features.x2.service import ApplyIn, DismissIn

Reader = Annotated[Principal, Depends(require(READ))]
AiUser = Annotated[Principal, Depends(require(AI_USE))]
Anyone = Annotated[Principal, Depends(require(AUTHENTICATED))]
Id = Annotated[str, Path(min_length=1, max_length=64)]


def router() -> APIRouter:
    r = api_router(tags=["agent"])

    @r.get("/agent/tools")
    def agent_catalogue(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("agent").describe()
        return result

    @r.get("/agent/proposals")
    def list_proposals(
        _: Reader,
        ctx: CtxDep,
        status: Literal["PROPOSED", "APPLIED", "DISMISSED", "STALE", "FAILED"] | None = None,
        chat_id: Annotated[str | None, Query(max_length=64)] = None,
        target_id: Annotated[str | None, Query(max_length=64)] = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("agent").search(status=status, chat_id=chat_id, target_id=target_id)
        return result

    @r.post("/agent/proposals/{proposal_id}/apply")
    def apply_proposal(proposal_id: Id, body: ApplyIn, principal: Anyone, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("agent").apply(proposal_id, body, principal)
        return result

    @r.post("/agent/proposals/{proposal_id}/dismiss")
    def dismiss_proposal(proposal_id: Id, body: DismissIn, principal: AiUser, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("agent").dismiss(proposal_id, body.reason, principal)
        return result

    return r
