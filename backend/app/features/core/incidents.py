"""Incident queries and the human review workflow (status, owner, notes, closure, reopening)."""

from __future__ import annotations

import json
import uuid
from typing import Any

from app.core.auth import Principal
from app.core.db import Session
from app.core.errors import ApiError, Conflict, NotFound
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso
from app.detection.base import Event
from app.features.core.models import IncidentUpdateIn
from app.response.simulation import cancel_open_responses, response_public

CLOSED_STATUSES = frozenset({"RESOLVED", "FALSE_POSITIVE"})
ACTIVE_STATUSES = frozenset({"OPEN", "INVESTIGATING"})
SORTS = {
    "updated": "i.updated_at DESC, i.id",
    "risk": "i.risk_score DESC, i.updated_at DESC, i.id",
    "first_seen": "i.first_seen DESC, i.id",
}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def like_pattern(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def incident_summary(row: Any) -> dict[str, Any]:
    rules = row["rules"] if "rules" in row.keys() else None  # noqa: SIM118 - sqlite3.Row
    return {
        "id": row["id"],
        "title": row["title"],
        "status": row["status"],
        "severity": row["severity"],
        "risk_score": row["risk_score"],
        "asset": row["asset"],
        "user": row["username"],
        "owner": row["owner"],
        "revision": row["revision"],
        "event_count": row["event_count"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "first_detected_at": row["first_detected_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "closed_at": row["closed_at"],
        "merged_into": row["merged_into"],
        "rules": sorted(rules.split(",")) if rules else [],
    }


def detection_public(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "incident_id": row["incident_id"],
        "rule_id": row["rule_id"],
        "rule_version": row["rule_version"],
        "rule_name": row["rule_name"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "stage": row["stage"],
        "techniques": json.loads(row["techniques"]),
        "first_ts": row["first_ts"],
        "last_ts": row["last_ts"],
        "event_ids": json.loads(row["event_ids"]),
        "summary": row["summary"],
        "details": json.loads(row["details"]),
        "status": row["status"],
        "suppression_id": row["suppression_id"],
    }


def note_public(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "incident_id": row["incident_id"],
        "author": row["author"],
        "kind": row["kind"],
        "text": row["text"],
        "ai_job_id": row["ai_job_id"],
        "created_at": row["created_at"],
    }


class IncidentService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    # -- queries -------------------------------------------------------------------------------------

    def list(
        self,
        *,
        q: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        offset: int = 0,
        limit: int = 50,
        sort: str = "updated",
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("i.status = ?")
            params.append(status)
        else:
            clauses.append("i.status != 'MERGED'")
        if severity:
            clauses.append("i.severity = ?")
            params.append(severity)
        if q:
            pattern = like_pattern(q)
            clauses.append(
                "(i.title LIKE ? ESCAPE '\\' OR i.asset LIKE ? ESCAPE '\\' OR i.username LIKE ? ESCAPE '\\' OR i.id = ?)"
            )
            params.extend([pattern, pattern, pattern, q])
        where = "WHERE " + " AND ".join(clauses)
        with self._ctx.db.read() as session:
            total = session.scalar(f"SELECT count(*) FROM incidents i {where}", params)
            rows = session.all(
                "SELECT i.*, (SELECT group_concat(DISTINCT d.rule_id) FROM detections d "
                "WHERE d.incident_id = i.id AND d.status = 'ACTIVE') AS rules "
                f"FROM incidents i {where} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
        return {"items": [incident_summary(r) for r in rows], "total": total, "offset": offset, "limit": limit}

    def row(self, session: Session, incident_id: str) -> Any:
        row = session.one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if row is None:
            raise NotFound("Unknown incident")
        return row

    def events(self, session: Session, incident_id: str) -> tuple[Event, ...]:
        rows = session.all(
            "SELECT e.* FROM events e JOIN incident_events ie ON ie.event_id = e.id WHERE ie.incident_id = ? "
            "ORDER BY e.ts, e.source, e.external_id, e.digest",
            (incident_id,),
        )
        return tuple(Event.from_row(row) for row in rows)

    def entities(self, session: Session, incident_id: str) -> set[tuple[str, str]]:
        rows = session.all(
            "SELECT DISTINCT ee.entity_type, ee.value FROM event_entities ee "
            "JOIN incident_events ie ON ie.event_id = ee.event_id WHERE ie.incident_id = ?",
            (incident_id,),
        )
        return {(row["entity_type"], row["value"]) for row in rows}

    def get(self, incident_id: str) -> dict[str, Any]:
        now = self._ctx.clock.now()
        with self._ctx.db.read() as session:
            row = self.row(session, incident_id)
            events = self.events(session, incident_id)
            detections = session.all(
                "SELECT * FROM detections WHERE incident_id = ? ORDER BY first_ts, rule_id", (incident_id,)
            )
            merged = session.all(
                "SELECT id, title, updated_at FROM incidents WHERE merged_into = ? ORDER BY updated_at", (incident_id,)
            )
            note_owners = [incident_id, *(m["id"] for m in merged)]
            notes = session.all(
                f"SELECT * FROM incident_notes WHERE incident_id IN ({','.join('?' * len(note_owners))}) "
                "ORDER BY created_at, rowid",  # insertion order breaks same-timestamp ties
                note_owners,
            )
            responses = session.all(
                "SELECT * FROM responses WHERE incident_id = ? ORDER BY requested_at DESC", (incident_id,)
            )
        return {
            **incident_summary(row),
            "rules": sorted({d["rule_id"] for d in detections if d["status"] == "ACTIVE"}),
            "risk": {
                "score": row["risk_score"],
                "severity": row["severity"],
                "label": "Heuristic risk score (0-100). It ranks attention; it is not a probability.",
                "factors": json.loads(row["risk_factors"]),
            },
            "analysis": json.loads(row["analysis"]),
            "closure_category": row["closure_category"],
            "closure_entities": json.loads(row["closure_entities"]) if row["closure_entities"] else [],
            "events": [event.public() for event in events],
            "detections": [detection_public(d) for d in detections],
            "notes": [note_public(n) for n in notes],
            "responses": [response_public(r, now) for r in responses],
            "merged_incidents": [dict(m) for m in merged],
        }

    # -- review workflow -----------------------------------------------------------------------------

    def update(self, incident_id: str, body: IncidentUpdateIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        if body.status is None and body.owner is None and body.note is None:
            raise ApiError("Provide a status, owner or note to change", code="nothing_to_update", status_code=422)
        with ctx.db.write() as session:
            row = self.row(session, incident_id)
            if row["status"] == "MERGED":
                raise Conflict(f"This incident was merged into {row['merged_into']}; update that incident instead")
            if body.revision != row["revision"]:
                raise Conflict(
                    "The incident changed since you loaded it; refresh and try again",
                    code="stale_revision",
                    details={"current_revision": row["revision"]},
                )
            previous = row["status"]
            status = body.status or previous
            closing = status in CLOSED_STATUSES and status != previous
            if closing and not body.note:
                raise ApiError("Closing an incident requires a note", code="note_required", status_code=422)
            if status == "FALSE_POSITIVE" and closing and body.closure_category is None:
                raise ApiError(
                    "Closing as FALSE_POSITIVE requires a reason category", code="category_required", status_code=422
                )
            if body.closure_category is not None and status != "FALSE_POSITIVE":
                raise ApiError(
                    "A closure category applies only to FALSE_POSITIVE", code="invalid_category", status_code=422
                )
            if body.benign_entities and status != "FALSE_POSITIVE":
                raise ApiError("Benign entities apply only to FALSE_POSITIVE", code="invalid_entities", status_code=422)
            entities: list[dict[str, str]] = []
            if body.benign_entities:
                known = self.entities(session, incident_id)
                for ref in body.benign_entities:
                    value = (
                        ref.value.lower()
                        if ref.type in ("asset", "user", "domain", "file_hash", "process")
                        else ref.value
                    )
                    if (ref.type, value) not in known:
                        raise ApiError(
                            f"{ref.type} {ref.value!r} does not appear in this incident's events",
                            code="unknown_entity",
                            status_code=422,
                        )
                    entities.append({"type": ref.type, "value": value})
            now = iso(ctx.clock.now())
            revision = int(row["revision"]) + 1
            owner = row["owner"] if body.owner is None else (body.owner or None)
            closed_at = row["closed_at"]
            closure_category = row["closure_category"]
            closure_entities = row["closure_entities"]
            if closing:
                closed_at = now
                closure_category = body.closure_category if status == "FALSE_POSITIVE" else None
                closure_entities = canonical_json(entities) if status == "FALSE_POSITIVE" else None
            elif status in ACTIVE_STATUSES and previous in CLOSED_STATUSES:
                closed_at, closure_category, closure_entities = None, None, None
            session.execute(
                "UPDATE incidents SET status = ?, owner = ?, revision = ?, updated_at = ?, closed_at = ?, "
                "closure_category = ?, closure_entities = ? WHERE id = ?",
                (status, owner, revision, now, closed_at, closure_category, closure_entities, incident_id),
            )
            if body.note:
                kind = (
                    "closure"
                    if closing
                    else ("reopen" if previous in CLOSED_STATUSES and status in ACTIVE_STATUSES else "note")
                )
                self._insert_note(session, incident_id, principal.name, kind, body.note, None, now)
            cancel_open_responses(session, ctx.audit, ctx.clock, incident_id, principal.name, "Incident review changed")
            ctx.audit.append(
                session,
                "incident.reviewed",
                principal.name,
                {
                    "incident_id": incident_id,
                    "revision": revision,
                    "from_status": previous,
                    "to_status": status,
                    "owner": owner,
                    "note_added": bool(body.note),
                    "closure_category": closure_category if closing else None,
                    "benign_entities": entities,
                },
                subject=("incident", incident_id),
            )
            ctx.service("pipeline").notify_incidents_changed(session, [incident_id], principal.name)
            session.after_commit(
                lambda: ctx.bus.publish("incident.updated", {"incident_id": incident_id, "revision": revision})
            )
        return self.get(incident_id)

    def add_note(
        self,
        incident_id: str,
        text: str,
        actor: str,
        *,
        kind: str = "note",
        ai_job_id: str | None = None,
    ) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self.row(session, incident_id)
            if row["status"] == "MERGED":
                raise Conflict(f"This incident was merged into {row['merged_into']}; add notes there instead")
            now = iso(ctx.clock.now())
            revision = int(row["revision"]) + 1
            note_id = self._insert_note(session, incident_id, actor, kind, text, ai_job_id, now)
            session.execute(
                "UPDATE incidents SET revision = ?, updated_at = ? WHERE id = ?", (revision, now, incident_id)
            )
            cancel_open_responses(session, ctx.audit, ctx.clock, incident_id, actor, "Incident notes changed")
            ctx.audit.append(
                session,
                "incident.note_added",
                actor,
                {
                    "incident_id": incident_id,
                    "note_id": note_id,
                    "revision": revision,
                    "kind": kind,
                    "ai_job_id": ai_job_id,
                },
                subject=("incident", incident_id),
            )
            session.after_commit(
                lambda: ctx.bus.publish("incident.updated", {"incident_id": incident_id, "revision": revision})
            )
        return {"note_id": note_id, "revision": revision}

    @staticmethod
    def _insert_note(
        session: Session, incident_id: str, author: str, kind: str, text: str, ai_job_id: str | None, now: str
    ) -> str:
        note_id = str(uuid.uuid4())
        session.execute(
            "INSERT INTO incident_notes (id, incident_id, author, kind, text, ai_job_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (note_id, incident_id, author, kind, text, ai_job_id, now),
        )
        return note_id
