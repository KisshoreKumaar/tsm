"""Story service: build, version, export (F2)."""

from __future__ import annotations

import json
import uuid
from typing import Any

from app.core.auth import Principal
from app.core.errors import NotFound
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso
from app.story.builder import build_campaign_story, build_incident_story, render_markdown


def setup(ctx: Any) -> None:
    ctx.services["stories"] = StoryService(ctx)


def _saved_meta(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "version": row["version"],
        "subject_revision": row["subject_revision"],
        "source": row["source"],
        "ai_status": row["ai_status"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }


class StoryService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def _latest(self, subject_type: str, subject_id: str) -> Any:
        with self._ctx.db.read() as session:
            return session.one(
                "SELECT * FROM stories WHERE subject_type = ? AND subject_id = ? ORDER BY version DESC LIMIT 1",
                (subject_type, subject_id),
            )

    def build_incident(self, incident_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        detail = self._ctx.service("incidents").get(incident_id)
        return detail, build_incident_story(detail, iso(self._ctx.clock.now()))

    def incident_story(self, incident_id: str) -> dict[str, Any]:
        detail, story = self.build_incident(incident_id)
        latest = self._latest("incident", incident_id)
        saved = _saved_meta(latest)
        if (
            latest is not None
            and latest["source"] == "ai_polished"
            and latest["subject_revision"] == detail["revision"]
        ):
            story = json.loads(latest["content"])
        return {
            "story": story,
            "saved": saved,
            "stale": latest is not None and latest["subject_revision"] != detail["revision"],
            "current_revision": detail["revision"],
        }

    def regenerate(self, incident_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        detail, story = self.build_incident(incident_id)
        with ctx.db.write() as session:
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
                "created_by, created_at) VALUES (?, 'incident', ?, ?, ?, 'deterministic', 'not_requested', ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    incident_id,
                    detail["revision"],
                    version,
                    canonical_json(story),
                    principal.name,
                    iso(ctx.clock.now()),
                ),
            )
            ctx.audit.append(
                session,
                "story.generated",
                principal.name,
                {
                    "subject_type": "incident",
                    "subject_id": incident_id,
                    "subject_revision": detail["revision"],
                    "version": version,
                    "source": "deterministic",
                    "citations_valid": story["citations_valid"],
                },
                subject=("incident", incident_id),
            )
        return self.incident_story(incident_id)

    def campaign_story(self, campaign_id: str) -> dict[str, Any]:
        ctx = self._ctx
        if "f1" not in ctx.features:
            raise NotFound("Campaigns are not enabled")
        campaign = ctx.service("campaigns").get(campaign_id)
        incidents = [ctx.service("incidents").get(i["id"]) for i in campaign["incidents"]]
        story = build_campaign_story(campaign, incidents, iso(ctx.clock.now()))
        return {"story": story, "saved": None, "stale": False, "current_revision": campaign["revision"]}

    def markdown(self, subject_type: str, subject_id: str, fmt: str) -> tuple[str, str]:
        if subject_type == "campaign":
            story = self.campaign_story(subject_id)["story"]
        else:
            story = self.incident_story(subject_id)["story"]
        return render_markdown(story, fmt), f"aegis-{subject_type}-{subject_id[:8]}-story.md"
