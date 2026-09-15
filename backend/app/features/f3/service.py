"""AI analyst chats (F3): persisted history, async answers streamed via SSE, human "Add to notes"."""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.ai.builtin_tools import F3_DEEP_TOOLS, NoArgs
from app.ai.evidence import EvidencePack, build_incident_pack
from app.ai.providers.factory import ProviderConfig
from app.ai.subjects import global_pack, load_subject, subject_revision
from app.ai.tasks.analyst import QUICK_PROMPTS, deterministic_answer, quick_answer_task
from app.ai.tasks.tool_loop import run_tool_loop
from app.ai.tools import ToolContext, ToolSpec
from app.core.auth import Principal
from app.core.errors import ApiError, Conflict, NotFound
from app.core.jobs import Job, JobError, JobOutcome
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ChatIn(Strict):
    subject_type: Literal["incident", "campaign", "global"]
    subject_id: str | None = Field(default=None, max_length=64)


class MessageIn(Strict):
    content: str = Field(min_length=1, max_length=1000)
    mode: Literal["quick", "deep", "agent"] = "quick"


class NoteFromAnswerIn(Strict):
    text: str = Field(min_length=1, max_length=4000)


def setup(ctx: Any) -> None:
    ctx.services["analyst"] = AnalystService(ctx)


def _chat_public(row: Any) -> dict[str, Any]:
    return {k: row[k] for k in ("id", "subject_type", "subject_id", "title", "created_by", "created_at", "updated_at")}


def _message_public(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "chat_id": row["chat_id"],
        "role": row["role"],
        "mode": row["mode"],
        "content": json.loads(row["content"]),
        "job_id": row["job_id"],
        "status": row["status"],
        "actor": row["actor"],
        "created_at": row["created_at"],
    }


def _previous_answers_tool(tc: ToolContext, _: NoArgs) -> dict[str, Any]:
    if not tc.subject_id:
        return {"answers": []}
    with tc.ctx.db.read() as session:
        rows = session.all(
            "SELECT m.content FROM chat_messages m JOIN chats c ON c.id = m.chat_id WHERE c.subject_id = ? "
            "AND m.role = 'assistant' AND m.status = 'complete' ORDER BY m.created_at DESC LIMIT 3",
            (tc.subject_id,),
        )
    return {"answers": [json.loads(r["content"]).get("summary", "")[:200] for r in rows]}


def agent_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            "get_previous_answers", "f3", "recent analyst answers for this subject", NoArgs, _previous_answers_tool
        )
    ]


class AnalystService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    # -- chats ---------------------------------------------------------------------------------------

    def create_chat(self, body: ChatIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        if body.subject_type == "global":
            if "x2" not in ctx.features:
                raise NotFound("Workspace-wide chats require the agent console (X2)")
            title = "Workspace agent"
            subject_id = None
        else:
            if not body.subject_id:
                raise ApiError("subject_id is required", code="subject_required", status_code=422)
            subject_revision(ctx, body.subject_type, body.subject_id)
            subject_id = body.subject_id
            detail = load_subject(ctx, body.subject_type, subject_id)
            title = detail["title"][:120]
        chat_id = str(uuid.uuid4())
        now = iso(ctx.clock.now())
        with ctx.db.write() as session:
            session.execute(
                "INSERT INTO chats (id, subject_type, subject_id, title, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (chat_id, body.subject_type, subject_id, title, principal.name, now, now),
            )
            ctx.audit.append(
                session,
                "chat.created",
                principal.name,
                {"chat_id": chat_id, "subject_type": body.subject_type, "subject_id": subject_id},
                subject=("chat", chat_id),
            )
        return self.get_chat(chat_id)

    def list_chats(self, subject_type: str | None, subject_id: str | None) -> dict[str, Any]:
        clauses, params = [], []
        if subject_type:
            clauses.append("subject_type = ?")
            params.append(subject_type)
        if subject_id:
            clauses.append("subject_id = ?")
            params.append(subject_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._ctx.db.read() as session:
            rows = session.all(f"SELECT * FROM chats {where} ORDER BY updated_at DESC LIMIT 50", params)
        return {"items": [_chat_public(r) for r in rows], "quick_prompts": QUICK_PROMPTS}

    def get_chat(self, chat_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            row = session.one("SELECT * FROM chats WHERE id = ?", (chat_id,))
            if row is None:
                raise NotFound("Unknown chat")
            messages = session.all(
                "SELECT * FROM chat_messages WHERE chat_id = ? ORDER BY created_at, rowid", (chat_id,)
            )
        return {**_chat_public(row), "messages": [_message_public(m) for m in messages], "quick_prompts": QUICK_PROMPTS}

    def post_message(self, chat_id: str, body: MessageIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.read() as session:
            chat = session.one("SELECT * FROM chats WHERE id = ?", (chat_id,))
        if chat is None:
            raise NotFound("Unknown chat")
        mode = body.mode
        if mode == "agent" and "x2" not in ctx.features:
            raise NotFound("The agent console (X2) is not enabled")
        if chat["subject_type"] == "global" and mode != "agent":
            mode = "agent"
        revision = subject_revision(ctx, chat["subject_type"], chat["subject_id"])
        kind = {"quick": "analyst.quick", "deep": "analyst.deep", "agent": "agent.run"}[mode]
        now = iso(ctx.clock.now())
        user_id, assistant_id = str(uuid.uuid4()), str(uuid.uuid4())
        with ctx.db.write() as session:
            session.execute(
                "INSERT INTO chat_messages (id, chat_id, role, mode, content, status, actor, created_at) VALUES (?, ?, 'user', ?, ?, 'complete', ?, ?)",
                (user_id, chat_id, mode, canonical_json({"text": body.content}), principal.name, now),
            )
            job_id = ctx.jobs.enqueue(
                session,
                kind,
                {"chat_id": chat_id, "message_id": assistant_id, "question": body.content, "mode": mode},
                principal.name,
                subject=(chat["subject_type"], chat["subject_id"] or "workspace", revision),
            )
            session.execute(
                "INSERT INTO chat_messages (id, chat_id, role, mode, content, job_id, status, actor, created_at) "
                "VALUES (?, ?, 'assistant', ?, ?, ?, 'pending', ?, ?)",
                (assistant_id, chat_id, mode, canonical_json({"status": "queued"}), job_id, principal.name, now),
            )
            session.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (now, chat_id))
            ctx.audit.append(
                session,
                "chat.message_posted",
                principal.name,
                {
                    "chat_id": chat_id,
                    "mode": mode,
                    "job_id": job_id,
                    "question_length": len(body.content),
                    "subject_revision": revision,
                },
                subject=("chat", chat_id),
            )
        position = ctx.jobs.queue_position(job_id)
        return {
            "user_message_id": user_id,
            "assistant_message_id": assistant_id,
            "job_id": job_id,
            "mode": mode,
            "queue_position": position,
            "eta_seconds": ctx.service("llm_settings").eta_seconds(position),
        }

    def add_to_notes(self, chat_id: str, message_id: str, text: str, principal: Principal) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            chat = session.one("SELECT * FROM chats WHERE id = ?", (chat_id,))
            message = session.one("SELECT * FROM chat_messages WHERE id = ? AND chat_id = ?", (message_id, chat_id))
        if chat is None or message is None:
            raise NotFound("Unknown chat message")
        if chat["subject_type"] != "incident":
            raise Conflict("Only answers in incident chats can be added to incident notes")
        if message["role"] != "assistant" or message["status"] != "complete":
            raise Conflict("Only completed answers can be referenced")
        result: dict[str, Any] = self._ctx.service("incidents").add_note(
            chat["subject_id"], text, principal.name, kind="ai_reference", ai_job_id=message["job_id"]
        )
        return result

    # -- job handlers ---------------------------------------------------------------------------------

    def _complete(self, job: Job, content: dict[str, Any], status: str = "complete") -> JobOutcome:
        ctx = self._ctx
        message_id = job.payload["message_id"]
        chat_id = job.payload["chat_id"]

        def apply(session: Any) -> None:
            session.execute(
                "UPDATE chat_messages SET content = ?, status = ? WHERE id = ?",
                (canonical_json(content), status, message_id),
            )
            session.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (iso(ctx.clock.now()), chat_id))
            session.after_commit(
                lambda: ctx.bus.publish(
                    "chat.updated", {"chat_id": chat_id, "message_id": message_id, "status": status, "job_id": job.id}
                )
            )

        return JobOutcome(result={"message_id": message_id, "ai_status": content.get("ai_status")}, apply=apply)

    def fail_message(self, job: Job, error: str) -> None:
        ctx = self._ctx
        with ctx.db.write() as session:
            session.execute(
                "UPDATE chat_messages SET content = ?, status = 'failed' WHERE id = ?",
                (canonical_json({"error": error}), job.payload["message_id"]),
            )
        ctx.bus.publish(
            "chat.updated",
            {
                "chat_id": job.payload["chat_id"],
                "message_id": job.payload["message_id"],
                "status": "failed",
                "job_id": job.id,
            },
        )

    def run_quick(self, job: Job) -> JobOutcome:
        ctx = self._ctx
        subject_type, subject_id = job.subject_type or "incident", job.subject_id
        detail = load_subject(ctx, subject_type, subject_id)
        question = job.payload["question"]
        spec, build = quick_answer_task(detail, question)
        runtime = ctx.service("ai")
        result = runtime.run(
            spec,
            build,
            actor=job.actor,
            subject=(subject_type, str(subject_id), job.subject_revision),
            job_id=job.id,
            on_token=lambda piece: ctx.jobs.publish_progress(job, {"token": piece}),
        )
        content = {
            **result.output,
            "question": question,
            "ai_status": result.ai_status,
            "used_ai": result.used_ai,
            "provider": result.provider_id,
            "model": result.model,
            "subject_revision": job.subject_revision,
            "grounding": {
                "claims": result.stats.total,
                "grounded": result.stats.grounded,
                "rejected_citations": len(result.stats.invalid_aliases),
            },
            "injection_suspected": bool(result.pack.injection_suspected)
            if result.pack
            else bool(detail["analysis"]["injection"]["suspected"]),
            "error": result.error,
        }
        return self._complete(job, content)

    def run_deep(self, job: Job) -> JobOutcome:
        ctx = self._ctx
        subject_type, subject_id = job.subject_type or "incident", job.subject_id
        detail = load_subject(ctx, subject_type, subject_id)
        question = job.payload["question"]
        registry = ctx.service("ai_tools")
        tools = registry.tools(ctx.features.ids, names=F3_DEEP_TOOLS)

        def pack_builder(config: ProviderConfig) -> EvidencePack:
            return build_incident_pack(detail, budget_tokens=max(300, config.context_tokens // 2), redact=config.redact)

        result = run_tool_loop(
            ctx.service("ai"),
            ctx=ctx,
            task_name="analyst.deep",
            tools=tools,
            pack_builder=pack_builder,
            question=question,
            fallback=lambda: deterministic_answer(detail, question),
            actor=job.actor,
            subject_type=subject_type,
            subject_id=subject_id,
            subject=(subject_type, str(subject_id), job.subject_revision),
            job_id=job.id,
            max_steps=4,
            on_step=lambda step: ctx.jobs.publish_progress(job, step),
        )
        content = {
            **result.answer,
            "question": question,
            "ai_status": {"valid": "validated", "repaired": "validated_after_repair"}.get(
                result.outcome, result.outcome
            ),
            "used_ai": result.used_ai,
            "provider": result.provider_id,
            "model": result.model,
            "steps": result.steps,
            "tool_calls": result.tool_calls,
            "subject_revision": job.subject_revision,
            "grounding": {
                "claims": result.stats.total,
                "grounded": result.stats.grounded,
                "rejected_citations": len(result.stats.invalid_aliases),
            },
            "injection_suspected": result.injection_suspected or bool(detail["analysis"]["injection"]["suspected"]),
            "error": result.error,
        }
        return self._complete(job, content)


def _guarded(handler_name: str) -> Any:
    def handler(ctx: Any, job: Job) -> JobOutcome:
        service: AnalystService = ctx.service("analyst")
        try:
            outcome: JobOutcome = getattr(service, handler_name)(job)
            return outcome
        except Exception as exc:
            message = exc.message if isinstance(exc, ApiError) else "The analyst could not answer; see the server log"
            service.fail_message(job, message)
            raise JobError(message) from None

    return handler


run_quick_job = _guarded("run_quick")
run_deep_job = _guarded("run_deep")
_ = global_pack  # re-exported for the agent console
