"""Agent console (X2): proposal drafting via propose_* tools and human application.

The agent never mutates domain state. Proposal tools only collect drafts; the job stores them as PROPOSED. A human
applies a proposal through the same domain service as the manual route, under their own identity and permission, in
one transaction with the proposal's status change and audit record. Approval, execution, activation, finalisation,
provider settings, tokens and audit actions are human-only and have no proposal type.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from app.ai.builtin_tools import NoArgs, incident_id_for
from app.ai.evidence import EvidencePack, build_incident_pack
from app.ai.providers.factory import ProviderConfig
from app.ai.subjects import global_pack, load_subject
from app.ai.tasks.analyst import deterministic_answer
from app.ai.tasks.tool_loop import run_tool_loop
from app.ai.tools import ToolContext, ToolError, ToolSpec
from app.core.auth import Principal
from app.core.errors import ApiError, Conflict, Forbidden, NotFound
from app.core.jobs import Job, JobError, JobOutcome
from app.core.jsonutil import canonical_json
from app.core.permissions import AI_USE, INGEST, INVESTIGATE, RESPOND_RECOMMEND
from app.core.timeutil import iso
from app.features.core.models import IncidentUpdateIn, ResponseRequestIn

MAX_PROPOSALS_PER_RUN = 3
AGENT_ACTOR_PREFIX = "ai:agent"

HUMAN_ONLY_ACTIONS = frozenset(
    {
        "response.approve",
        "response.execute",
        "response.reject",
        "rule.approve",
        "rule.activate",
        "rule.disable",
        "rule.retire",
        "tuning.approve",
        "tuning.revert",
        "report.approve",
        "report.mark_submitted",
        "llm.configure",
        "audit.export",
        "token.create",
    }
)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class IncidentUpdateArgs(Strict):
    incident_id: str | None = Field(default=None, max_length=64)
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"] | None = None
    owner: str | None = Field(default=None, max_length=100)
    note: str = Field(min_length=3, max_length=1000)
    closure_category: (
        Literal[
            "authorized_scanner",
            "maintenance_window",
            "known_admin_activity",
            "user_error",
            "test_activity",
            "misconfigured_source",
            "other",
        ]
        | None
    ) = None
    rationale: str = Field(min_length=3, max_length=500)
    evidence: list[str] = Field(default_factory=list, max_length=10)


class ResponseArgs(Strict):
    incident_id: str | None = Field(default=None, max_length=64)
    playbook: Literal["isolate_endpoint", "restore_connectivity", "collect_evidence"]
    rationale: str = Field(min_length=3, max_length=500)
    evidence: list[str] = Field(default_factory=list, max_length=10)


class NoteArgs(Strict):
    incident_id: str | None = Field(default=None, max_length=64)
    text: str = Field(min_length=3, max_length=1000)
    rationale: str = Field(default="Record the finding", min_length=3, max_length=500)
    evidence: list[str] = Field(default_factory=list, max_length=10)


class DemoReplayArgs(Strict):
    scenario: str = Field(min_length=1, max_length=50)
    rationale: str = Field(min_length=3, max_length=500)


class ApplyIn(Strict):
    acknowledge_injection: StrictBool = False


class DismissIn(Strict):
    reason: str = Field(min_length=3, max_length=500)


@dataclass(frozen=True)
class ProposalType:
    action: str
    permission: str
    target_type: str
    apply: Callable[[Any, Any, dict[str, Any], Principal, str], dict[str, Any]]


def _apply_incident_update(
    ctx: Any, row: Any, payload: dict[str, Any], principal: Principal, proposal_id: str
) -> dict[str, Any]:
    body = IncidentUpdateIn(
        revision=row["target_revision"],
        status=payload.get("status"),
        owner=payload.get("owner"),
        note=f"{payload['note']} (applied from agent proposal {proposal_id[:8]})",
        closure_category=payload.get("closure_category"),
    )
    detail = ctx.service("incidents").update(row["target_id"], body, principal)
    return {"incident_id": row["target_id"], "status": detail["status"], "revision": detail["revision"]}


def _apply_note(ctx: Any, row: Any, payload: dict[str, Any], principal: Principal, proposal_id: str) -> dict[str, Any]:
    result: dict[str, Any] = ctx.service("incidents").add_note(
        row["target_id"], payload["text"], principal.name, kind="ai_reference", ai_job_id=row["job_id"]
    )
    return result


def _apply_response(
    ctx: Any, row: Any, payload: dict[str, Any], principal: Principal, proposal_id: str
) -> dict[str, Any]:
    body = ResponseRequestIn(
        incident_id=row["target_id"],
        playbook=payload["playbook"],
        rationale=f"{payload['rationale']} (from agent proposal {proposal_id[:8]})"[:2000],
        revision=row["target_revision"],
    )
    response = ctx.service("responses").recommend(body, principal)
    return {"response_id": response["id"], "status": response["status"]}


def _apply_demo(ctx: Any, row: Any, payload: dict[str, Any], principal: Principal, proposal_id: str) -> dict[str, Any]:
    run = ctx.service("demo").run(payload["scenario"], "replay", principal)
    return {"run_id": run["run_id"], "scenario": run["scenario"]}


PROPOSAL_TYPES: dict[str, ProposalType] = {
    "incident.update": ProposalType("incident.update", INVESTIGATE, "incident", _apply_incident_update),
    "incident.note": ProposalType("incident.note", INVESTIGATE, "incident", _apply_note),
    "response.recommend": ProposalType("response.recommend", RESPOND_RECOMMEND, "incident", _apply_response),
    "demo.replay": ProposalType("demo.replay", INGEST, "demo", _apply_demo),
}
assert not (set(PROPOSAL_TYPES) & HUMAN_ONLY_ACTIONS)  # noqa: S101 - invariant, checked at import


def setup(ctx: Any) -> None:
    ctx.services["agent"] = AgentService(ctx)


def _record_proposal(
    tc: ToolContext, action: str, target_id: str | None, payload: dict[str, Any], rationale: str, evidence: list[str]
) -> dict[str, Any]:
    if len(tc.proposals) >= MAX_PROPOSALS_PER_RUN:
        raise ToolError(f"At most {MAX_PROPOSALS_PER_RUN} proposals per request")
    valid, _ = tc.pack.resolve(evidence)
    tc.proposals.append(
        {
            "action": action,
            "target_id": target_id,
            "payload": payload,
            "rationale": rationale,
            "evidence_ids": valid,
            "injection_context": tc.pack.injection_suspected,
        }
    )
    return {"recorded": True, "note": "Draft saved. A human with the right permission must review and apply it."}


def _existing_incident(tc: ToolContext, incident_id: str | None) -> str:
    target = incident_id_for(tc, incident_id)
    with tc.ctx.db.read() as session:
        status = session.scalar("SELECT status FROM incidents WHERE id = ?", (target,))
    if status is None:
        raise ToolError("Unknown incident_id")
    if status == "MERGED":
        raise ToolError("That incident was merged; use the canonical incident")
    return target


def _propose_update(tc: ToolContext, args: IncidentUpdateArgs) -> dict[str, Any]:
    target = _existing_incident(tc, args.incident_id)
    if args.status == "FALSE_POSITIVE" and args.closure_category is None:
        raise ToolError("closure_category is required when proposing FALSE_POSITIVE")
    payload = {
        k: v
        for k, v in args.model_dump().items()
        if k in ("status", "owner", "note", "closure_category") and v is not None
    }
    return _record_proposal(tc, "incident.update", target, payload, args.rationale, args.evidence)


def _propose_note(tc: ToolContext, args: NoteArgs) -> dict[str, Any]:
    target = _existing_incident(tc, args.incident_id)
    return _record_proposal(tc, "incident.note", target, {"text": args.text}, args.rationale, args.evidence)


def _propose_response(tc: ToolContext, args: ResponseArgs) -> dict[str, Any]:
    target = _existing_incident(tc, args.incident_id)
    return _record_proposal(
        tc,
        "response.recommend",
        target,
        {"playbook": args.playbook, "rationale": args.rationale},
        args.rationale,
        args.evidence,
    )


def _propose_demo(tc: ToolContext, args: DemoReplayArgs) -> dict[str, Any]:
    from app.demo.scenarios import SCENARIOS

    if args.scenario not in SCENARIOS:
        raise ToolError(f"Unknown scenario; choose one of {', '.join(SCENARIOS)}")
    return _record_proposal(tc, "demo.replay", None, {"scenario": args.scenario}, args.rationale, [])


def _list_proposals_tool(tc: ToolContext, _: NoArgs) -> dict[str, Any]:
    items = tc.ctx.service("agent").search(status="PROPOSED", limit=5)["items"]
    return {"proposals": [[p["id"], p["action"], p["target_id"], p["rationale"][:100]] for p in items]}


def agent_tools() -> list[ToolSpec]:
    return [
        ToolSpec("list_agent_proposals", "x2", "open agent proposals awaiting a human", NoArgs, _list_proposals_tool),
        ToolSpec(
            "propose_incident_update",
            "x2",
            "draft a status/owner change with a note",
            IncidentUpdateArgs,
            _propose_update,
            kind="propose",
        ),
        ToolSpec(
            "propose_incident_note", "x2", "draft a note for the incident", NoteArgs, _propose_note, kind="propose"
        ),
        ToolSpec(
            "propose_response",
            "x2",
            "draft a simulated response request",
            ResponseArgs,
            _propose_response,
            kind="propose",
        ),
        ToolSpec(
            "propose_demo_replay",
            "x2",
            "draft replaying a synthetic scenario",
            DemoReplayArgs,
            _propose_demo,
            kind="propose",
        ),
    ]


def proposal_public(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "chat_id": row["chat_id"],
        "job_id": row["job_id"],
        "action": row["action"],
        "target_type": row["target_type"],
        "target_id": row["target_id"],
        "target_revision": row["target_revision"],
        "required_permission": row["required_permission"],
        "payload": json.loads(row["payload"]),
        "rationale": row["rationale"],
        "evidence_ids": json.loads(row["evidence_ids"]),
        "injection_context": bool(row["injection_context"]),
        "status": row["status"],
        "result": json.loads(row["result"]) if row["result"] else None,
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "decided_by": row["decided_by"],
        "decided_at": row["decided_at"],
        "decision_note": row["decision_note"],
    }


class AgentService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def describe(self) -> dict[str, Any]:
        return {
            "tools": self._ctx.service("ai_tools").describe(),
            "proposable_actions": [
                {"action": p.action, "permission": p.permission, "target_type": p.target_type}
                for p in PROPOSAL_TYPES.values()
            ],
            "human_only_actions": sorted(HUMAN_ONLY_ACTIONS),
        }

    def search(
        self, *, status: str | None = None, chat_id: str | None = None, target_id: str | None = None, limit: int = 50
    ) -> dict[str, Any]:
        clauses, params = [], []
        for column, value in (("status", status), ("chat_id", chat_id), ("target_id", target_id)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._ctx.db.read() as session:
            rows = session.all(
                f"SELECT * FROM agent_proposals {where} ORDER BY created_at DESC, rowid DESC LIMIT ?", [*params, limit]
            )
        return {"items": [proposal_public(r) for r in rows]}

    def store_proposals(self, session: Any, job: Job, proposals: list[dict[str, Any]]) -> list[str]:
        ctx = self._ctx
        ids = []
        now = iso(ctx.clock.now())
        for proposal in proposals:
            ptype = PROPOSAL_TYPES.get(proposal["action"])
            if ptype is None:  # defensive: only registered, non-human-only actions can be stored
                continue
            revision = None
            if ptype.target_type == "incident":
                revision = session.scalar("SELECT revision FROM incidents WHERE id = ?", (proposal["target_id"],))
                if revision is None:
                    continue
            proposal_id = str(uuid.uuid4())
            actor = f"{AGENT_ACTOR_PREFIX} (for {job.actor})"
            session.execute(
                "INSERT INTO agent_proposals (id, chat_id, message_id, job_id, action, target_type, target_id, target_revision, "
                "required_permission, payload, rationale, evidence_ids, injection_context, status, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?, ?)",
                (
                    proposal_id,
                    job.payload.get("chat_id"),
                    job.payload.get("message_id"),
                    job.id,
                    ptype.action,
                    ptype.target_type,
                    proposal["target_id"],
                    revision,
                    ptype.permission,
                    canonical_json(proposal["payload"]),
                    proposal["rationale"],
                    canonical_json(proposal["evidence_ids"]),
                    int(bool(proposal["injection_context"])),
                    actor,
                    now,
                ),
            )
            ctx.audit.append(
                session,
                "agent.proposal_created",
                actor,
                {
                    "proposal_id": proposal_id,
                    "action": ptype.action,
                    "target_id": proposal["target_id"],
                    "target_revision": revision,
                    "injection_context": bool(proposal["injection_context"]),
                    "job_id": job.id,
                },
                subject=("agent_proposal", proposal_id),
            )
            ids.append(proposal_id)
        return ids

    def apply(self, proposal_id: str, body: ApplyIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.read() as session:
            row = session.one("SELECT * FROM agent_proposals WHERE id = ?", (proposal_id,))
        if row is None:
            raise NotFound("Unknown proposal")
        if row["status"] != "PROPOSED":
            raise Conflict(f"This proposal is already {row['status']}")
        ptype = PROPOSAL_TYPES[row["action"]]
        if not principal.has(ptype.permission):
            raise Forbidden(
                f"Applying this proposal requires the {ptype.permission} permission",
                details={"required": ptype.permission},
            )
        if row["injection_context"] and not body.acknowledge_injection:
            raise ApiError(
                "This proposal was drafted while instruction-like text was present in the evidence. Review it and acknowledge before applying.",
                code="injection_acknowledgement_required",
                status_code=422,
            )
        stale = False
        if ptype.target_type == "incident":
            with ctx.db.read() as session:
                current = session.one("SELECT revision, status FROM incidents WHERE id = ?", (row["target_id"],))
            stale = current is None or current["revision"] != row["target_revision"] or current["status"] == "MERGED"
        if stale:
            with ctx.db.write() as session:
                session.execute(
                    "UPDATE agent_proposals SET status = 'STALE', decided_by = ?, decided_at = ?, decision_note = ? WHERE id = ?",
                    (
                        principal.name,
                        iso(ctx.clock.now()),
                        "Target changed after the proposal was drafted",
                        proposal_id,
                    ),
                )
                ctx.audit.append(
                    session,
                    "agent.proposal_stale",
                    principal.name,
                    {"proposal_id": proposal_id},
                    subject=("agent_proposal", proposal_id),
                )
            raise Conflict(
                "The incident changed after this proposal was drafted; ask the agent again", code="stale_proposal"
            )
        payload = json.loads(row["payload"])
        with ctx.db.write() as session:  # domain writes below join this transaction
            result = ptype.apply(ctx, row, payload, principal, proposal_id)
            session.execute(
                "UPDATE agent_proposals SET status = 'APPLIED', result = ?, decided_by = ?, decided_at = ? WHERE id = ?",
                (canonical_json(result), principal.name, iso(ctx.clock.now()), proposal_id),
            )
            ctx.audit.append(
                session,
                "agent.proposal_applied",
                principal.name,
                {"proposal_id": proposal_id, "action": ptype.action, "target_id": row["target_id"], "result": result},
                subject=("agent_proposal", proposal_id),
            )
            session.after_commit(
                lambda: ctx.bus.publish("agent.proposal", {"proposal_id": proposal_id, "status": "APPLIED"})
            )
        return self.get(proposal_id)

    def dismiss(self, proposal_id: str, reason: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = session.one("SELECT status FROM agent_proposals WHERE id = ?", (proposal_id,))
            if row is None:
                raise NotFound("Unknown proposal")
            if row["status"] != "PROPOSED":
                raise Conflict(f"This proposal is already {row['status']}")
            session.execute(
                "UPDATE agent_proposals SET status = 'DISMISSED', decided_by = ?, decided_at = ?, decision_note = ? WHERE id = ?",
                (principal.name, iso(ctx.clock.now()), reason, proposal_id),
            )
            ctx.audit.append(
                session,
                "agent.proposal_dismissed",
                principal.name,
                {"proposal_id": proposal_id, "reason": reason},
                subject=("agent_proposal", proposal_id),
            )
            session.after_commit(
                lambda: ctx.bus.publish("agent.proposal", {"proposal_id": proposal_id, "status": "DISMISSED"})
            )
        return self.get(proposal_id)

    def get(self, proposal_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            row = session.one("SELECT * FROM agent_proposals WHERE id = ?", (proposal_id,))
        if row is None:
            raise NotFound("Unknown proposal")
        return proposal_public(row)

    def run(self, job: Job) -> JobOutcome:
        ctx = self._ctx
        analyst = ctx.service("analyst")
        subject_type = job.subject_type or "global"
        subject_id = job.subject_id if subject_type != "global" else None
        detail = load_subject(ctx, subject_type, subject_id) if subject_id else None
        question = job.payload["question"]
        tools = ctx.service("ai_tools").tools(ctx.features.ids, include_propose=True)

        def pack_builder(config: ProviderConfig) -> EvidencePack:
            if detail is not None:
                return build_incident_pack(
                    detail, budget_tokens=max(300, config.context_tokens // 2), redact=config.redact
                )
            return global_pack(ctx, redact=config.redact)

        def fallback() -> dict[str, Any]:
            if detail is not None:
                answer = deterministic_answer(detail, question)
                answer["summary"] = "The agent needs an enabled LLM to investigate across modules. " + answer["summary"]
                return answer
            return {
                "summary": "The agent needs an enabled LLM to investigate across modules; use the pages directly or configure a provider.",
                "claims": [
                    {
                        "text": "No LLM answer is available.",
                        "label": "UNKNOWN",
                        "evidence_ids": [],
                        "citations_rejected": 0,
                        "downgraded": False,
                    }
                ],
                "suggested_next_questions": [],
                "suggested_actions": [],
                "confidence": "low",
                "confidence_note": "Deterministic fallback.",
                "actions_removed": 0,
            }

        result = run_tool_loop(
            ctx.service("ai"),
            ctx=ctx,
            task_name="agent.run",
            tools=tools,
            pack_builder=pack_builder,
            question=question,
            fallback=fallback,
            actor=job.actor,
            subject_type=subject_type,
            subject_id=subject_id,
            subject=(subject_type, str(subject_id or "workspace"), job.subject_revision),
            job_id=job.id,
            allow_proposals=True,
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
            "injection_suspected": result.injection_suspected,
            "error": result.error,
        }
        outcome = analyst._complete(job, content)
        base_apply = outcome.apply
        proposals = result.proposals

        def apply(session: Any) -> None:
            ids = self.store_proposals(session, job, proposals)
            content["proposal_ids"] = ids
            session.execute(
                "UPDATE chat_messages SET content = ? WHERE id = ?",
                (canonical_json(content), job.payload["message_id"]),
            )
            if base_apply is not None:
                base_apply(session)

        return JobOutcome(result={**outcome.result, "proposals": len(proposals)}, apply=apply)


def run_agent_job(ctx: Any, job: Job) -> JobOutcome:
    try:
        outcome: JobOutcome = ctx.service("agent").run(job)
        return outcome
    except Exception as exc:
        message = exc.message if isinstance(exc, ApiError) else "The agent could not answer; see the server log"
        ctx.service("analyst").fail_message(job, message)
        raise JobError(message) from None


_ = AI_USE
