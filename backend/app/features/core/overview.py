"""Overview metrics for the dashboard."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from app.core.timeutil import iso
from app.features.core.incidents import incident_summary


class OverviewService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def get(self) -> dict[str, Any]:
        ctx = self._ctx
        since = iso(ctx.clock.now() - timedelta(hours=24))
        with ctx.db.read() as session:
            by_status = {
                r["status"]: r["n"] for r in session.all("SELECT status, count(*) AS n FROM incidents GROUP BY status")
            }
            open_by_severity = {
                r["severity"]: r["n"]
                for r in session.all(
                    "SELECT severity, count(*) AS n FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING') GROUP BY severity"
                )
            }
            top = session.all(
                "SELECT i.*, (SELECT group_concat(DISTINCT d.rule_id) FROM detections d "
                "WHERE d.incident_id = i.id AND d.status = 'ACTIVE') AS rules FROM incidents i "
                "WHERE i.status IN ('OPEN', 'INVESTIGATING') ORDER BY i.risk_score DESC, i.updated_at DESC LIMIT 5"
            )
            responses = {
                r["status"]: r["n"] for r in session.all("SELECT status, count(*) AS n FROM responses GROUP BY status")
            }
            metrics = {
                "events_total": session.scalar("SELECT count(*) FROM events"),
                "events_24h": session.scalar("SELECT count(*) FROM events WHERE ts >= ?", (since,)),
                "injection_suspected_events": session.scalar(
                    "SELECT count(*) FROM events WHERE injection_suspected = 1"
                ),
                "detections_active": session.scalar("SELECT count(*) FROM detections WHERE status = 'ACTIVE'"),
                "detections_suppressed": session.scalar("SELECT count(*) FROM detections WHERE status = 'SUPPRESSED'"),
                "isolated_endpoints": session.scalar("SELECT count(*) FROM virtual_endpoints WHERE state = 'ISOLATED'"),
                "highest_open_risk": session.scalar(
                    "SELECT max(risk_score) FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING')"
                )
                or 0,
                "audit_records": session.scalar("SELECT count(*) FROM audit_log"),
                "jobs_queued": session.scalar("SELECT count(*) FROM jobs WHERE status = 'QUEUED'"),
                "jobs_running": session.scalar("SELECT count(*) FROM jobs WHERE status = 'RUNNING'"),
            }
        return {
            "metrics": metrics,
            "incidents_by_status": by_status,
            "open_incidents_by_severity": open_by_severity,
            "responses_by_status": responses,
            "top_incidents": [incident_summary(r) for r in top],
            "generated_at": iso(ctx.clock.now()),
        }
