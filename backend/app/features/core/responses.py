"""Simulated response workflow: recommend → approve (bound, expiring, two-person) → execute and verify, or reject."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta
from typing import Any

from app.core.auth import Principal
from app.core.errors import ApiError, Conflict, Forbidden, NotFound
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso, parse_iso
from app.features.core.incidents import ACTIVE_STATUSES
from app.features.core.models import ResponseRequestIn
from app.response.simulation import APPROVAL_TTL_SECONDS, CONFIRMATION_PHRASE, PLAYBOOKS, response_public


class ResponseService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def playbooks(self) -> dict[str, Any]:
        return {
            "playbooks": [p.public() for p in PLAYBOOKS.values()],
            "confirmation_phrase": CONFIRMATION_PHRASE,
            "approval_ttl_seconds": APPROVAL_TTL_SECONDS,
            "two_person": self._ctx.settings.two_person,
        }

    def list(
        self, *, status: str | None = None, incident_id: str | None = None, offset: int = 0, limit: int = 50
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if incident_id:
            clauses.append("incident_id = ?")
            params.append(incident_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        now = self._ctx.clock.now()
        with self._ctx.db.read() as session:
            total = session.scalar(f"SELECT count(*) FROM responses {where}", params)
            rows = session.all(
                f"SELECT * FROM responses {where} ORDER BY requested_at DESC, id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
        return {"items": [response_public(r, now) for r in rows], "total": total, "offset": offset, "limit": limit}

    def get(self, response_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            row = session.one("SELECT * FROM responses WHERE id = ?", (response_id,))
        if row is None:
            raise NotFound("Unknown response request")
        return response_public(row, self._ctx.clock.now())

    def recommend(self, body: ResponseRequestIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            incident = session.one("SELECT * FROM incidents WHERE id = ?", (body.incident_id,))
            if incident is None:
                raise NotFound("Unknown incident")
            if incident["status"] not in ACTIVE_STATUSES:
                raise Conflict("Responses can only be requested for OPEN or INVESTIGATING incidents")
            if body.revision != incident["revision"]:
                raise Conflict(
                    "The incident changed since you loaded it; review the latest evidence first",
                    code="stale_revision",
                    details={"current_revision": incident["revision"]},
                )
            duplicate = session.scalar(
                "SELECT id FROM responses WHERE incident_id = ? AND playbook = ? AND status IN ('PENDING', 'APPROVED')",
                (body.incident_id, body.playbook),
            )
            if duplicate:
                raise Conflict("An open request for this playbook already exists", details={"response_id": duplicate})
            response_id = str(uuid.uuid4())
            now = iso(ctx.clock.now())
            session.execute(
                "INSERT INTO responses (id, incident_id, incident_revision, asset, playbook, status, rationale, "
                "requested_by, requested_at) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)",
                (
                    response_id,
                    body.incident_id,
                    incident["revision"],
                    incident["asset"],
                    body.playbook,
                    body.rationale,
                    principal.name,
                    now,
                ),
            )
            ctx.audit.append(
                session,
                "response.requested",
                principal.name,
                {
                    "response_id": response_id,
                    "incident_id": body.incident_id,
                    "incident_revision": incident["revision"],
                    "playbook": body.playbook,
                    "asset": incident["asset"],
                },
                subject=("response", response_id),
            )
            session.after_commit(lambda: ctx.bus.publish("response.updated", {"response_id": response_id}))
        return self.get(response_id)

    def _open_for_decision(self, session: Any, response_id: str) -> tuple[Any, Any]:
        row = session.one("SELECT * FROM responses WHERE id = ?", (response_id,))
        if row is None:
            raise NotFound("Unknown response request")
        incident = session.one("SELECT * FROM incidents WHERE id = ?", (row["incident_id"],))
        return row, incident

    def _check_bound_incident(self, row: Any, incident: Any) -> None:
        if incident is None or incident["status"] not in ACTIVE_STATUSES:
            raise Conflict("The incident is no longer active; request a new response if still needed")
        if incident["revision"] != row["incident_revision"]:
            raise Conflict(
                "The incident changed after this request was made; request a new response",
                code="stale_revision",
                details={"current_revision": incident["revision"], "bound_revision": row["incident_revision"]},
            )

    def approve(self, response_id: str, confirmation: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        if confirmation.strip() != CONFIRMATION_PHRASE:
            raise ApiError(
                f"Type {CONFIRMATION_PHRASE!r} to confirm this simulated action",
                code="confirmation_required",
                status_code=422,
            )
        with ctx.db.write() as session:
            row, incident = self._open_for_decision(session, response_id)
            if row["status"] != "PENDING":
                raise Conflict(f"Only PENDING requests can be approved (current status: {row['status']})")
            if ctx.settings.two_person and row["requested_by"] == principal.name:
                raise Forbidden(
                    "Two-person rule: a different operator must approve this request", code="two_person_rule"
                )
            self._check_bound_incident(row, incident)
            now = ctx.clock.now()
            expires = now + timedelta(seconds=APPROVAL_TTL_SECONDS)
            session.execute(
                "UPDATE responses SET status = 'APPROVED', approved_by = ?, approved_at = ?, expires_at = ? WHERE id = ?",
                (principal.name, iso(now), iso(expires), response_id),
            )
            ctx.audit.append(
                session,
                "response.approved",
                principal.name,
                {
                    "response_id": response_id,
                    "incident_id": row["incident_id"],
                    "incident_revision": row["incident_revision"],
                    "expires_at": iso(expires),
                },
                subject=("response", response_id),
            )
            session.after_commit(lambda: ctx.bus.publish("response.updated", {"response_id": response_id}))
        return self.get(response_id)

    def reject(self, response_id: str, reason: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row, _ = self._open_for_decision(session, response_id)
            if row["status"] not in ("PENDING", "APPROVED"):
                raise Conflict(f"Only PENDING or APPROVED requests can be rejected (current status: {row['status']})")
            now = iso(ctx.clock.now())
            session.execute(
                "UPDATE responses SET status = 'REJECTED', closed_by = ?, closed_at = ?, close_reason = ? WHERE id = ?",
                (principal.name, now, reason, response_id),
            )
            ctx.audit.append(
                session,
                "response.rejected",
                principal.name,
                {"response_id": response_id, "incident_id": row["incident_id"], "reason": reason},
                subject=("response", response_id),
            )
            session.after_commit(lambda: ctx.bus.publish("response.updated", {"response_id": response_id}))
        return self.get(response_id)

    def execute(self, response_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        expired = False
        with ctx.db.write() as session:
            row, incident = self._open_for_decision(session, response_id)
            if row["status"] != "APPROVED":
                raise Conflict(f"Only APPROVED requests can be executed (current status: {row['status']})")
            if ctx.settings.two_person and row["requested_by"] == principal.name:
                raise Forbidden("Two-person rule: the requester cannot execute this request", code="two_person_rule")
            now = ctx.clock.now()
            if parse_iso(row["expires_at"]) <= now:
                session.execute(
                    "UPDATE responses SET status = 'EXPIRED', closed_by = ?, closed_at = ?, close_reason = ? WHERE id = ?",
                    ("system", iso(now), "Approval expired before execution", response_id),
                )
                ctx.audit.append(
                    session,
                    "response.expired",
                    principal.name,
                    {"response_id": response_id, "incident_id": row["incident_id"], "expired_at": row["expires_at"]},
                    subject=("response", response_id),
                )
                expired = True
            else:
                self._check_bound_incident(row, incident)
                playbook = PLAYBOOKS[row["playbook"]]
                asset = row["asset"]
                before_row = session.one("SELECT state FROM virtual_endpoints WHERE asset = ?", (asset,))
                before = before_row["state"] if before_row else "CONNECTED"
                result: dict[str, Any] = {
                    "simulated": True,
                    "note": "Virtual endpoint registry only. No real endpoint was changed or contacted.",
                    "before": before,
                }
                if playbook.target_state is not None:
                    session.execute(
                        "INSERT INTO virtual_endpoints (asset, state, updated_at, updated_by) VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(asset) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at, "
                        "updated_by = excluded.updated_by",
                        (asset, playbook.target_state, iso(now), principal.name),
                    )
                    read_back = session.scalar("SELECT state FROM virtual_endpoints WHERE asset = ?", (asset,))
                    result.update(
                        after=read_back, expected=playbook.target_state, verified=read_back == playbook.target_state
                    )
                else:
                    events = session.all(
                        "SELECT e.id, e.digest FROM events e JOIN incident_events ie ON ie.event_id = e.id "
                        "WHERE ie.incident_id = ? ORDER BY e.ts, e.source, e.external_id, e.digest",
                        (row["incident_id"],),
                    )
                    manifest = []
                    for event in events:
                        stored = session.one("SELECT * FROM events WHERE id = ?", (event["id"],))
                        normalized = {key: stored[key] for key in stored.keys()}  # noqa: SIM118 - sqlite3.Row
                        manifest.append(
                            {
                                "event_id": event["id"],
                                "sha256": hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest(),
                                "raw_sha256": event["digest"],
                            }
                        )
                    result.update(
                        after=before,
                        verified=len(manifest) == len(events),
                        manifest=manifest,
                        manifest_sha256=hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest(),
                    )
                session.execute(
                    "UPDATE responses SET status = 'EXECUTED', executed_by = ?, executed_at = ?, result = ? WHERE id = ?",
                    (principal.name, iso(now), json.dumps(result, sort_keys=True), response_id),
                )
                ctx.audit.append(
                    session,
                    "response.executed",
                    principal.name,
                    {
                        "response_id": response_id,
                        "incident_id": row["incident_id"],
                        "playbook": row["playbook"],
                        "asset": asset,
                        "before": result["before"],
                        "after": result.get("after"),
                        "verified": result["verified"],
                        "manifest_sha256": result.get("manifest_sha256"),
                    },
                    subject=("response", response_id),
                )
            session.after_commit(lambda: ctx.bus.publish("response.updated", {"response_id": response_id}))
        if expired:
            raise Conflict("The approval expired after 15 minutes; request a new response", code="approval_expired")
        return self.get(response_id)

    def endpoints(self) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            rows = session.all("SELECT * FROM virtual_endpoints ORDER BY asset")
        return {"items": [dict(r) for r in rows], "simulated": True}
