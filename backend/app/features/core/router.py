"""Core platform routes: health, identity and feature manifest, audit, jobs and the live-update stream."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import StreamingResponse

from app import __version__
from app.core.auth import Principal, public, require
from app.core.context import CtxDep
from app.core.errors import NotFound
from app.core.permissions import AUDIT_EXPORT, AUTHENTICATED, READ
from app.core.routing import api_router
from app.core.sse import event_stream

Reader = Annotated[Principal, Depends(require(READ))]
Authenticated = Annotated[Principal, Depends(require(AUTHENTICATED))]


def router() -> APIRouter:
    r = api_router(tags=["core"])

    @r.get("/healthz", dependencies=[Depends(public())])
    def healthz() -> dict[str, Any]:
        return {"status": "ok"}

    @r.get("/me")
    def me(principal: Authenticated, ctx: CtxDep) -> dict[str, Any]:
        return {
            **principal.public(),
            "features": ctx.features.manifest(principal.permissions),
            "two_person": ctx.settings.two_person,
            "version": __version__,
        }

    @r.get("/features")
    def features(_: Authenticated, ctx: CtxDep) -> dict[str, Any]:
        return {"features": ctx.features.manifest()}

    @r.get("/audit")
    def audit_page(
        _: Reader,
        ctx: CtxDep,
        offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        action: Annotated[str | None, Query(max_length=100)] = None,
        actor: Annotated[str | None, Query(max_length=100)] = None,
        subject_type: Annotated[str | None, Query(max_length=50)] = None,
        subject_id: Annotated[str | None, Query(max_length=100)] = None,
    ) -> dict[str, Any]:
        return ctx.audit.page(
            ctx.db,
            offset=offset,
            limit=limit,
            action=action,
            actor=actor,
            subject_type=subject_type,
            subject_id=subject_id,
        )

    @r.get("/audit/verify")
    def audit_verify(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        return ctx.audit.verify(ctx.db)

    @r.get("/audit/checkpoint")
    def audit_checkpoint(_: Annotated[Principal, Depends(require(AUDIT_EXPORT))], ctx: CtxDep) -> dict[str, Any]:
        return ctx.audit.checkpoint(ctx.db)

    @r.get("/jobs/{job_id}")
    def job_detail(job_id: Annotated[str, Path(max_length=64)], _: Reader, ctx: CtxDep) -> dict[str, Any]:
        job = ctx.jobs.get(job_id)
        if job is None:
            raise NotFound("Unknown job")
        return {**job.public(), "queue_position": ctx.jobs.queue_position(job_id)}

    @r.get("/stream")
    async def events_stream(
        request: Request,
        _: Reader,
        ctx: CtxDep,
        topics: Annotated[str, Query(max_length=500)] = "",
    ) -> StreamingResponse:
        topic_list = [t.strip() for t in topics.split(",") if t.strip()] or None
        return StreamingResponse(
            event_stream(ctx.bus, topics=topic_list, is_disconnected=request.is_disconnected),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return r
