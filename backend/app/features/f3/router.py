"""F3 routes: analyst chats and messages."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query

from app.ai.tasks.analyst import QUICK_PROMPTS
from app.core.auth import Principal, require
from app.core.context import CtxDep
from app.core.permissions import AI_USE, INVESTIGATE, READ
from app.core.routing import api_router
from app.features.f3.service import ChatIn, MessageIn, NoteFromAnswerIn

Reader = Annotated[Principal, Depends(require(READ))]
AiUser = Annotated[Principal, Depends(require(AI_USE))]
Investigator = Annotated[Principal, Depends(require(INVESTIGATE))]
Id = Annotated[str, Path(min_length=1, max_length=64)]


def router() -> APIRouter:
    r = api_router(tags=["analyst"])

    @r.get("/analyst/quick-prompts")
    def quick_prompts(_: Reader) -> dict[str, Any]:
        return {"quick_prompts": QUICK_PROMPTS}

    @r.post("/chats", status_code=201)
    def create_chat(body: ChatIn, principal: AiUser, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("analyst").create_chat(body, principal)
        return result

    @r.get("/chats")
    def list_chats(
        _: Reader,
        ctx: CtxDep,
        subject_type: Literal["incident", "campaign", "global"] | None = None,
        subject_id: Annotated[str | None, Query(max_length=64)] = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("analyst").list_chats(subject_type, subject_id)
        return result

    @r.get("/chats/{chat_id}")
    def get_chat(chat_id: Id, _: Reader, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("analyst").get_chat(chat_id)
        return result

    @r.post("/chats/{chat_id}/messages", status_code=202)
    def post_message(chat_id: Id, body: MessageIn, principal: AiUser, ctx: CtxDep) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("analyst").post_message(chat_id, body, principal)
        return result

    @r.post("/chats/{chat_id}/messages/{message_id}/add-to-notes", status_code=201)
    def add_answer_to_notes(
        chat_id: Id, message_id: Id, body: NoteFromAnswerIn, principal: Investigator, ctx: CtxDep
    ) -> dict[str, Any]:
        result: dict[str, Any] = ctx.service("analyst").add_to_notes(chat_id, message_id, body.text, principal)
        return result

    return r
