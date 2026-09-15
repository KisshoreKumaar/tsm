"""X1 routes: provider settings (admin only), AI status and per-job live streams."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Request
from fastapi.responses import StreamingResponse

from app.ai.providers.factory import PRESETS
from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import LLM_CONFIGURE, READ
from app.core.routing import api_router
from app.core.sse import Message, event_stream
from app.features.core.models import EmptyIn
from app.features.x1.service import ActiveIn, KeyIn, ProviderIn, ProviderPatch

LlmAdmin = Annotated[Principal, Depends(require(LLM_CONFIGURE))]
Reader = Annotated[Principal, Depends(require(READ))]
Id = Annotated[str, Path(min_length=1, max_length=64)]


def router() -> APIRouter:
    r = api_router(tags=["ai"])

    @r.get("/llm/providers")
    def list_providers(_: LlmAdmin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").list()
        return result

    @r.get("/llm/presets")
    def list_presets(_: LlmAdmin) -> dict[str, Any]:
        return {"presets": PRESETS}

    @r.post("/llm/providers", status_code=201)
    def create_provider(body: ProviderIn, principal: LlmAdmin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").create(body, principal)
        return result

    @r.patch("/llm/providers/{provider_id}")
    def update_provider(provider_id: Id, body: ProviderPatch, principal: LlmAdmin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").update(provider_id, body, principal)
        return result

    @r.delete("/llm/providers/{provider_id}")
    def delete_provider(provider_id: Id, principal: LlmAdmin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").delete(provider_id, principal)
        return result

    @r.put("/llm/providers/{provider_id}/key")
    def set_provider_key(provider_id: Id, body: KeyIn, principal: LlmAdmin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").set_key(provider_id, body.api_key, principal)
        return result

    @r.delete("/llm/providers/{provider_id}/key")
    def remove_provider_key(provider_id: Id, principal: LlmAdmin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").remove_key(provider_id, principal)
        return result

    @r.post("/llm/providers/{provider_id}/test")
    def test_provider(provider_id: Id, _: EmptyIn, principal: LlmAdmin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").test(provider_id, principal)
        return result

    @r.post("/llm/active")
    def set_active_provider(body: ActiveIn, principal: LlmAdmin, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").set_active(body.provider_id, principal)
        return result

    @r.get("/ai/status")
    def ai_status(_: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("llm_settings").status()
        return result

    @r.get("/jobs/{job_id}/stream")
    async def job_events_stream(job_id: Id, request: Request, _: Reader, ctx: CtxDep) -> StreamingResponse:
        def only_this_job(message: Message) -> Message | None:
            return message if message["data"].get("job_id") == job_id else None

        return StreamingResponse(
            event_stream(ctx.bus, topics=["job"], is_disconnected=request.is_disconnected, transform=only_this_job),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return r
