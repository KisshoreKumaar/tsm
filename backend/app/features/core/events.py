"""Event ingestion endpoints' service and the events explorer queries."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from app.core.auth import Principal
from app.core.errors import ApiError, NotFound
from app.detection.base import Event
from app.features.core.incidents import detection_public, like_pattern
from app.ingest.kinds import event_kinds

_SEARCH_COLUMNS = (
    "e.details",
    "e.command_line",
    "e.process_name",
    "e.file_path",
    "e.domain",
    "e.asset",
    "e.username",
    "e.source",
    "e.external_id",
    "e.source_ip",
    "e.destination_ip",
)


class EventService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    @property
    def _pipeline(self) -> Any:
        return self._ctx.service("pipeline")

    def ingest(self, raw_events: Sequence[Any], principal: Principal) -> dict[str, Any]:
        limit = self._ctx.settings.batch_max_events
        if len(raw_events) > limit:
            raise ApiError(f"A batch may contain at most {limit} events", code="batch_too_large", status_code=422)
        normalized = self._pipeline.validate(raw_events)
        with self._ctx.db.write() as session:
            outcome = self._pipeline.ingest(session, normalized, principal.name)
        return dict(outcome.public())

    def kinds(self) -> dict[str, Any]:
        return {
            "kinds": [
                {"kind": s.kind, "description": s.description, "required": list(s.required), "any_of": list(s.any_of)}
                for s in event_kinds()
            ]
        }

    def list(
        self,
        *,
        q: str | None = None,
        kind: str | None = None,
        asset: str | None = None,
        user: str | None = None,
        source: str | None = None,
        incident_id: str | None = None,
        injection: bool | None = None,
        since: str | None = None,
        until: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (("e.kind", kind), ("e.source", source)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        for column, value in (("e.asset", asset), ("e.username", user)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value.lower())
        if incident_id:
            clauses.append("e.id IN (SELECT event_id FROM incident_events WHERE incident_id = ?)")
            params.append(incident_id)
        if injection is not None:
            clauses.append("e.injection_suspected = ?")
            params.append(int(injection))
        if since:
            clauses.append("e.ts >= ?")
            params.append(since)
        if until:
            clauses.append("e.ts <= ?")
            params.append(until)
        if q:
            pattern = like_pattern(q)
            clauses.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in _SEARCH_COLUMNS) + " OR e.id = ?)")
            params.extend([pattern] * len(_SEARCH_COLUMNS))
            params.append(q)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._ctx.db.read() as session:
            total = session.scalar(f"SELECT count(*) FROM events e {where}", params)
            rows = session.all(
                f"SELECT e.* FROM events e {where} ORDER BY e.ts DESC, e.id LIMIT ? OFFSET ?", [*params, limit, offset]
            )
            ids = [row["id"] for row in rows]
            links: dict[str, list[str]] = {}
            if ids:
                for link in session.all(
                    "SELECT ie.event_id, ie.incident_id FROM incident_events ie JOIN incidents i ON i.id = ie.incident_id "
                    f"WHERE i.status != 'MERGED' AND ie.event_id IN ({','.join('?' * len(ids))})",
                    ids,
                ):
                    links.setdefault(link["event_id"], []).append(link["incident_id"])
        items = [{**Event.from_row(row).public(), "incident_ids": links.get(row["id"], [])} for row in rows]
        return {"items": items, "total": total, "offset": offset, "limit": limit}

    def get(self, event_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            row = session.one("SELECT * FROM events WHERE id = ?", (event_id,))
            if row is None:
                raise NotFound("Unknown event")
            raw = session.scalar("SELECT body FROM raw_events WHERE event_id = ?", (event_id,))
            entities = session.all(
                "SELECT entity_type, value FROM event_entities WHERE event_id = ? ORDER BY entity_type, value",
                (event_id,),
            )
            incidents = session.all(
                "SELECT i.id, i.title, i.status FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id "
                "WHERE ie.event_id = ? ORDER BY i.created_at",
                (event_id,),
            )
            detections = session.all(
                "SELECT d.* FROM detections d JOIN detection_events de ON de.detection_id = d.id WHERE de.event_id = ?",
                (event_id,),
            )
        return {
            **Event.from_row(row).public(),
            "ingested_at": row["ingested_at"],
            "ingested_by": row["ingested_by"],
            "raw": json.loads(raw) if raw else None,
            "entities": [{"type": e["entity_type"], "value": e["value"]} for e in entities],
            "incidents": [dict(i) for i in incidents],
            "detections": [detection_public(d) for d in detections],
        }
