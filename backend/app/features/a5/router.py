"""A5 routes: false-positive analytics, tuning suggestions, suppressions and suppressed detections."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query

from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import READ, TUNING_APPROVE, TUNING_DRAFT
from app.core.routing import api_router
from app.features.a5.service import ApproveIn, GenerateIn, ManualSuggestionIn, ReasonIn, SuggestionStatus
from app.features.core.models import EmptyIn

Reader = Annotated[Principal, Depends(require(READ))]
Drafter = Annotated[Principal, Depends(require(TUNING_DRAFT))]
Approver = Annotated[Principal, Depends(require(TUNING_APPROVE))]
Id = Annotated[str, Path(min_length=1, max_length=64)]


def router() -> APIRouter:
    r = api_router(tags=["tuning"])

    @r.get("/tuning/fp-analytics")
    def false_positive_analytics(
        _: Reader, ctx: CtxDep, days: Annotated[int, Query(ge=1, le=365)] = 30
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").fp_analytics(days)
        return result

    @r.get("/tuning/suggestions")
    def list_suggestions(_: Reader, ctx: CtxDep, status: SuggestionStatus | None = None) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").search(status)
        return result

    @r.post("/tuning/suggestions", status_code=201)
    def create_suggestion(body: ManualSuggestionIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").create_manual(body, principal)
        return result

    @r.post("/tuning/suggestions/generate")
    def generate_suggestions(body: GenerateIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        created = ctx.service("tuning").generate_now(principal, body.rule_id)
        return {"created": created, **ctx.service("tuning").search("PROPOSED")}

    @r.get("/tuning/suggestions/{suggestion_id}")
    def get_suggestion(suggestion_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").get(suggestion_id)
        return result

    @r.post("/tuning/suggestions/{suggestion_id}/simulate")
    def simulate_suggestion(suggestion_id: Id, _: EmptyIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").resimulate(suggestion_id, principal)
        return result

    @r.post("/tuning/suggestions/{suggestion_id}/approve")
    def approve_suggestion(suggestion_id: Id, body: ApproveIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").approve(suggestion_id, body, principal)
        return result

    @r.post("/tuning/suggestions/{suggestion_id}/reject")
    def reject_suggestion(suggestion_id: Id, body: ReasonIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").reject(suggestion_id, body.reason, principal)
        return result

    @r.post("/tuning/suggestions/{suggestion_id}/revert")
    def revert_suggestion(suggestion_id: Id, body: ReasonIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").revert(suggestion_id, body.reason, principal)
        return result

    @r.get("/suppressions")
    def list_suppressions(
        _: Reader, ctx: CtxDep, status: str | None = Query(default=None, max_length=20)
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").suppressions(status)
        return result

    @r.post("/suppressions/{suppression_id}/revert")
    def revert_suppression(suppression_id: Id, body: ReasonIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").revert_suppression(suppression_id, body.reason, principal)
        return result

    @r.get("/tuning/suppressed-detections")
    def suppressed_detections(
        _: Reader,
        ctx: CtxDep,
        rule_id: Annotated[str | None, Query(max_length=32)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("tuning").suppressed_detections(rule_id, limit)
        return result

    return r
