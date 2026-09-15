"""Playbook allowlist and shared response-state helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.audit import AuditLog
from app.core.db import Session
from app.core.timeutil import Clock, iso, parse_iso

CONFIRMATION_PHRASE = "APPROVE SIMULATION"
APPROVAL_TTL_SECONDS = 15 * 60
OPEN_RESPONSE_STATUSES = ("PENDING", "APPROVED")


@dataclass(frozen=True)
class Playbook:
    id: str
    name: str
    description: str
    target_state: str | None

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "description": self.description, "simulated": True}


PLAYBOOKS: dict[str, Playbook] = {
    "isolate_endpoint": Playbook(
        "isolate_endpoint",
        "Isolate endpoint (simulated)",
        "Marks the asset ISOLATED in the virtual endpoint registry and verifies the state by reading it back.",
        "ISOLATED",
    ),
    "restore_connectivity": Playbook(
        "restore_connectivity",
        "Restore connectivity (simulated)",
        "Marks the asset CONNECTED in the virtual endpoint registry and verifies the state by reading it back.",
        "CONNECTED",
    ),
    "collect_evidence": Playbook(
        "collect_evidence",
        "Collect evidence manifest",
        "Produces a SHA-256 manifest of every event in the incident. Nothing is collected from a real endpoint.",
        None,
    ),
}


def cancel_open_responses(
    session: Session, audit: AuditLog, clock: Clock, incident_id: str, actor: str, reason: str
) -> list[str]:
    rows = session.all(
        "SELECT id, status FROM responses WHERE incident_id = ? AND status IN ('PENDING', 'APPROVED')", (incident_id,)
    )
    now = iso(clock.now())
    for row in rows:
        session.execute(
            "UPDATE responses SET status = 'CANCELLED', closed_by = ?, closed_at = ?, close_reason = ? WHERE id = ?",
            (actor, now, reason, row["id"]),
        )
        audit.append(
            session,
            "response.cancelled",
            actor,
            {"response_id": row["id"], "incident_id": incident_id, "previous_status": row["status"], "reason": reason},
            subject=("response", row["id"]),
        )
    return [row["id"] for row in rows]


def response_public(row: Any, now: datetime) -> dict[str, Any]:
    playbook = PLAYBOOKS.get(row["playbook"])
    expires_at = row["expires_at"]
    return {
        "id": row["id"],
        "incident_id": row["incident_id"],
        "incident_revision": row["incident_revision"],
        "asset": row["asset"],
        "playbook": row["playbook"],
        "playbook_name": playbook.name if playbook else row["playbook"],
        "status": row["status"],
        "rationale": row["rationale"],
        "requested_by": row["requested_by"],
        "requested_at": row["requested_at"],
        "approved_by": row["approved_by"],
        "approved_at": row["approved_at"],
        "expires_at": expires_at,
        "approval_expired": bool(row["status"] == "APPROVED" and expires_at and parse_iso(expires_at) <= now),
        "executed_by": row["executed_by"],
        "executed_at": row["executed_at"],
        "closed_by": row["closed_by"],
        "closed_at": row["closed_at"],
        "close_reason": row["close_reason"],
        "result": json.loads(row["result"]) if row["result"] else None,
        "simulated": True,
    }
