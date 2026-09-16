"""A3 routes: custom rules, validation, drafts, backtests, lifecycle, export and version diffs."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import Response

from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import READ, RULES_APPROVE, RULES_DRAFT
from app.core.routing import api_router
from app.features.a3.service import BacktestIn, DecisionIn, ReasonIn, RuleIn, RuleStatus, ValidateIn
from app.features.core.models import EmptyIn

Reader = Annotated[Principal, Depends(require(READ))]
Drafter = Annotated[Principal, Depends(require(RULES_DRAFT))]
Approver = Annotated[Principal, Depends(require(RULES_APPROVE))]
RuleId = Annotated[str, Path(min_length=1, max_length=32)]
Id = Annotated[str, Path(min_length=1, max_length=64)]


def router() -> APIRouter:
    r = api_router(tags=["detection-engineering"])

    @r.get("/rules/custom")
    def list_custom_rules(_: Reader, ctx: CtxDep, status: RuleStatus | None = None) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").search(status)
        return result

    @r.post("/rules", status_code=201)
    def create_rule(body: RuleIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").create(body, principal)
        return result

    @r.post("/rules/validate")
    def validate_rule(body: ValidateIn, _: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").validate(body.definition)
        return result

    @r.post("/rules/draft-from-incident/{incident_id}", status_code=202)
    def draft_rule_from_incident(incident_id: Id, _: EmptyIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").request_draft(incident_id, principal)
        return result

    @r.get("/rules/{rule_id}")
    def get_rule(rule_id: RuleId, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").get(rule_id)
        return result

    @r.post("/rules/{rule_id}/versions", status_code=201)
    def add_rule_version(rule_id: RuleId, body: RuleIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").add_version(rule_id, body, principal)
        return result

    @r.post("/rules/{rule_id}/backtest")
    def backtest_rule(rule_id: RuleId, body: BacktestIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").backtest(rule_id, body, principal)
        return result

    @r.post("/rules/{rule_id}/approve")
    def approve_rule(rule_id: RuleId, body: DecisionIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").approve(rule_id, body.note, principal)
        return result

    @r.post("/rules/{rule_id}/activate")
    def activate_rule(rule_id: RuleId, body: DecisionIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").activate(rule_id, body.note, principal)
        return result

    @r.post("/rules/{rule_id}/disable")
    def disable_rule(rule_id: RuleId, body: ReasonIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").disable(rule_id, body.reason, principal)
        return result

    @r.post("/rules/{rule_id}/retire")
    def retire_rule(rule_id: RuleId, body: ReasonIn, principal: Approver, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").retire(rule_id, body.reason, principal)
        return result

    @r.get("/rules/{rule_id}/export")
    def export_rule(rule_id: RuleId, _: Reader, ctx: CtxDep, format: Literal["json", "sigma"] = "json") -> Response:
        text, filename, media_type = ctx.service("detection_rules").export(rule_id, format)
        return Response(
            content=text,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @r.get("/rules/{rule_id}/diff")
    def diff_rule_versions(
        rule_id: RuleId,
        _: Reader,
        ctx: CtxDep,
        from_version: Annotated[int, Query(ge=1, le=10_000)] = 1,
        to_version: Annotated[int, Query(ge=1, le=10_000)] = 2,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("detection_rules").diff(rule_id, from_version, to_version)
        return result

    return r
