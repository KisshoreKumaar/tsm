"""I1 routes: organisation profile, CERT-In drafts, workflow, exports and deadlines."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import Response

from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import READ, REPORTS_DRAFT, REPORTS_FINALIZE, SETTINGS_MANAGE
from app.core.routing import api_router
from app.features.core.models import EmptyIn
from app.features.i1.service import FieldUpdateIn, OrgProfileIn, ReportStatus, ReviewIn, SubmittedIn

Reader = Annotated[Principal, Depends(require(READ))]
Drafter = Annotated[Principal, Depends(require(REPORTS_DRAFT))]
Finalizer = Annotated[Principal, Depends(require(REPORTS_FINALIZE))]
Admin = Annotated[Principal, Depends(require(SETTINGS_MANAGE))]
Id = Annotated[str, Path(min_length=1, max_length=64)]


def router() -> APIRouter:
    r = api_router(tags=["compliance"])

    @r.get("/org-profile")
    def get_org_profile(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").profile()
        return result

    @r.put("/org-profile")
    def put_org_profile(body: OrgProfileIn, principal: Admin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").save_profile(body, principal)
        return result

    @r.get("/compliance/deadlines")
    def compliance_deadlines(_: Reader, ctx: CtxDep, limit: Annotated[int, Query(ge=1, le=200)] = 50) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").deadlines(limit)
        return result

    @r.get("/cert-in")
    def list_reports(_: Reader, ctx: CtxDep, status: ReportStatus | None = None) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").search(status)
        return result

    @r.post("/incidents/{incident_id}/cert-in", status_code=201)
    def draft_report(incident_id: Id, _: EmptyIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").draft(incident_id, principal)
        return result

    @r.get("/incidents/{incident_id}/cert-in")
    def report_for_incident(incident_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").by_incident(incident_id)
        return result

    @r.get("/cert-in/{report_id}")
    def get_report(
        report_id: Id, _: Reader, ctx: CtxDep, version: Annotated[int | None, Query(ge=1, le=10_000)] = None
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").get(report_id, version)
        return result

    @r.patch("/cert-in/{report_id}")
    def update_report(report_id: Id, body: FieldUpdateIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").update_fields(report_id, body, principal)
        return result

    @r.post("/cert-in/{report_id}/submit-review")
    def submit_review(report_id: Id, body: ReviewIn, principal: Drafter, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").submit_for_review(report_id, body.note, principal)
        return result

    @r.post("/cert-in/{report_id}/approve")
    def approve_report(report_id: Id, body: ReviewIn, principal: Finalizer, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").approve(report_id, body.note, principal)
        return result

    @r.post("/cert-in/{report_id}/mark-submitted")
    def mark_submitted(report_id: Id, body: SubmittedIn, principal: Finalizer, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").mark_submitted(report_id, body, principal)
        return result

    @r.get("/cert-in/{report_id}/export")
    def export_report(
        report_id: Id,
        _: Reader,
        ctx: CtxDep,
        format: Literal["md", "json", "html"] = "md",
        redact: bool = False,
    ) -> Response:
        text, filename, media_type = ctx.service("reports").export(report_id, format, redact=redact)
        return Response(
            content=text,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @r.get("/cert-in/{report_id}/diff")
    def diff_report(
        report_id: Id,
        _: Reader,
        ctx: CtxDep,
        from_version: Annotated[int, Query(ge=1, le=10_000)] = 1,
        to_version: Annotated[int, Query(ge=1, le=10_000)] = 2,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("reports").diff(report_id, from_version, to_version)
        return result

    return r
