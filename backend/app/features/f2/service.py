"""Story service: build, version, export, and validated AI polish precomputation (F2)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from typing import Any

from app.core.auth import Principal
from app.core.db import Session
from app.core.errors import NotFound
from app.core.jobs import Job, JobOutcome
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso
from app.story.builder import build_campaign_story, build_incident_story, render_markdown

POLISH_ACTOR = "system:precompute"
POLISH_DEBOUNCE_SECONDS = 5.0


def setup(ctx: Any) -> None:
    service = StoryService(ctx)
    ctx.services["stories"] = service
    ctx.service("pipeline").change_hooks.append(
        lambda session, incident_ids, _actor: service.schedule_polish(session, incident_ids, POLISH_ACTOR)
    )


def run_polish_job(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("stories").run_polish(job)
    return outcome


def _saved_meta(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "version": row["version"],
        "subject_revision": row["subject_revision"],
        "source": row["source"],
        "ai_status": row["ai_status"],
        "provider": row["provider"],
        "model": row["model"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }


class StoryService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def _latest(self, subject_type: str, subject_id: str, source: str | None = None) -> Any:
        clause = " AND source = ?" if source else ""
        params: list[Any] = [subject_type, subject_id, *([source] if source else [])]
        with self._ctx.db.read() as session:
            return session.one(
                f"SELECT * FROM stories WHERE subject_type = ? AND subject_id = ?{clause} ORDER BY version DESC LIMIT 1",
                params,
            )

    def build_incident(self, incident_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        detail = self._ctx.service("incidents").get(incident_id)
        return detail, build_incident_story(detail, iso(self._ctx.clock.now()))

    def incident_story(self, incident_id: str) -> dict[str, Any]:
        detail, story = self.build_incident(incident_id)
        latest = self._latest("incident", incident_id)
        polished = self._latest("incident", incident_id, "ai_polished")
        if polished is not None and polished["subject_revision"] == detail["revision"]:
            story = json.loads(polished["content"])
        with self._ctx.db.read() as session:
            pending = session.scalar(
                "SELECT id FROM jobs WHERE kind = 'story.polish' AND subject_id = ? AND status IN ('QUEUED', 'RUNNING') "
                "ORDER BY created_at DESC LIMIT 1",
                (incident_id,),
            )
        return {
            "story": story,
            "saved": _saved_meta(latest),
            "stale": latest is not None and latest["subject_revision"] != detail["revision"],
            "current_revision": detail["revision"],
            "polish_job_id": pending,
        }

    def _save(
        self,
        session: Session,
        detail: dict[str, Any],
        story: dict[str, Any],
        *,
        source: str,
        actor: str,
        provider: str | None = None,
        model: str | None = None,
    ) -> int:
        incident_id = detail["id"]
        version = (
            int(
                session.scalar(
                    "SELECT coalesce(max(version), 0) FROM stories WHERE subject_type = 'incident' AND subject_id = ?",
                    (incident_id,),
                )
            )
            + 1
        )
        session.execute(
            "INSERT INTO stories (id, subject_type, subject_id, subject_revision, version, source, ai_status, content, "
            "prompt_version, provider, model, created_by, created_at) VALUES (?, 'incident', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                incident_id,
                detail["revision"],
                version,
                source,
                story.get("ai_status", "not_requested"),
                canonical_json(story),
                "story_narrate" if source == "ai_polished" else None,
                provider,
                model,
                actor,
                iso(self._ctx.clock.now()),
            ),
        )
        self._ctx.audit.append(
            session,
            "story.generated",
            actor,
            {
                "subject_type": "incident",
                "subject_id": incident_id,
                "subject_revision": detail["revision"],
                "version": version,
                "source": source,
                "provider": provider,
                "model": model,
                "citations_valid": story["citations_valid"],
            },
            subject=("incident", incident_id),
        )
        return version

    def regenerate(self, incident_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        detail, story = self.build_incident(incident_id)
        with ctx.db.write() as session:
            self._save(session, detail, story, source="deterministic", actor=principal.name)
            self.schedule_polish(session, [incident_id], principal.name, delay_seconds=0.0)
        return self.incident_story(incident_id)

    def ai_available(self) -> bool:
        runtime = self._ctx.services.get("ai")
        return runtime is not None and bool(runtime.provider_chain())

    def schedule_polish(
        self, session: Session, incident_ids: Sequence[str], actor: str, delay_seconds: float = POLISH_DEBOUNCE_SECONDS
    ) -> list[str]:
        if not incident_ids or not self.ai_available():
            return []
        jobs = []
        for incident_id in incident_ids:
            row = session.one("SELECT status, revision FROM incidents WHERE id = ?", (incident_id,))
            if row is None or row["status"] == "MERGED":
                continue
            jobs.append(
                self._ctx.jobs.enqueue(
                    session,
                    "story.polish",
                    {"incident_id": incident_id},
                    actor,
                    subject=("incident", incident_id, int(row["revision"])),
                    dedup_key=f"story.polish:{incident_id}",
                    priority=200,
                    delay_seconds=delay_seconds,
                )
            )
        return jobs

    def run_polish(self, job: Job) -> JobOutcome:
        from app.ai.tasks.story_polish import polish_story

        ctx = self._ctx
        incident_id = job.payload["incident_id"]
        detail, story = self.build_incident(incident_id)
        if job.subject_revision is not None and detail["revision"] != job.subject_revision:
            return JobOutcome(result={"skipped": "incident changed; a newer polish job handles it"})
        runtime = ctx.services.get("ai")
        if runtime is None:
            return JobOutcome(result={"skipped": "AI runtime not enabled"})
        polished, results = polish_story(runtime, detail, story, actor=job.actor, job_id=job.id)
        if polished.get("source") != "ai_polished":
            status = results[-1].ai_status if results else "llm_disabled"
            return JobOutcome(result={"ai_status": status, "kept": "deterministic"})

        def apply(session: Session) -> None:
            current = session.scalar("SELECT revision FROM incidents WHERE id = ?", (incident_id,))
            if current != detail["revision"]:
                return
            self._save(
                session,
                detail,
                polished,
                source="ai_polished",
                actor=job.actor,
                provider=polished.get("ai_provider"),
                model=polished.get("ai_model"),
            )
            session.after_commit(
                lambda: ctx.bus.publish("story.updated", {"incident_id": incident_id, "source": "ai_polished"})
            )

        return JobOutcome(result={"ai_status": "validated", "calls": len(results)}, apply=apply)

    def campaign_story(self, campaign_id: str) -> dict[str, Any]:
        ctx = self._ctx
        if "f1" not in ctx.features:
            raise NotFound("Campaigns are not enabled")
        campaign = ctx.service("campaigns").get(campaign_id)
        incidents = [ctx.service("incidents").get(i["id"]) for i in campaign["incidents"]]
        story = build_campaign_story(campaign, incidents, iso(ctx.clock.now()))
        return {
            "story": story,
            "saved": None,
            "stale": False,
            "current_revision": campaign["revision"],
            "polish_job_id": None,
        }

    def markdown(self, subject_type: str, subject_id: str, fmt: str) -> tuple[str, str]:
        if subject_type == "campaign":
            story = self.campaign_story(subject_id)["story"]
        else:
            story = self.incident_story(subject_id)["story"]
        return render_markdown(story, fmt), f"aegis-{subject_type}-{subject_id[:8]}-story.md"
