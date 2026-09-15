"""F4 service: persisted predictions with watchlist state, hit rate, explanations and agent tools.

Predictions are recomputed inside the transaction that changed an incident (incident-change hook). Status changes are
audited; when the number of observed predictions changes, the incident is re-scored through the pipeline's observed
prediction counter. Unobserved predictions expire through a delayed `prediction.expire` job.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.ai.builtin_tools import IncidentArg, incident_id_for
from app.ai.tools import ToolContext, ToolSpec
from app.core.auth import Principal
from app.core.db import Session
from app.core.errors import Conflict, NotFound
from app.core.jobs import Job, JobOutcome
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso
from app.prediction.engine import (
    HYPOTHESIS,
    LIKELIHOOD_LABEL,
    DetectionFact,
    PredictionContext,
    PredictionDraft,
    predict,
)
from app.prediction.model import default_transition_model

WATCHLIST_ACTOR = "system:watchlist"
PREDICTION_NAMESPACE = uuid.UUID("0b8f7a52-43c1-4d7e-9a3e-6c2f1d9e5a71")
HYPOTHESIS_NOTE = "Predictions are hypotheses about possible next attacker steps, not observed facts."
HIT_RATE_LABEL = (
    "Share of predictions later observed in the data AEGIS holds (synthetic scenarios in the demo). "
    "A descriptive metric, not an accuracy guarantee or a probability."
)
EXPLAIN_DEBOUNCE_SECONDS = 5.0
# Columns rewritten on every recomputation; a fixed allowlist, so it is safe to build the UPDATE from it.
_MUTABLE_COLUMNS = (
    "technique_name",
    "tactic",
    "score",
    "band",
    "factors",
    "rationale",
    "sources",
    "evidence_ids",
    "watch_signals",
    "preventive_actions",
    "horizon_seconds",
    "predicted_at",
    "expires_at",
    "status",
    "observed_event_ids",
    "observed_at",
)


def setup(ctx: Any) -> None:
    service = PredictionService(ctx)
    ctx.services["predictions"] = service
    pipeline = ctx.service("pipeline")
    pipeline.observed_counter = service.observed_count
    pipeline.change_hooks.append(service.on_incidents_changed)


def run_expire_job(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("predictions").run_expire(job)
    return outcome


def run_explain_job(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("predictions").run_explain(job)
    return outcome


def prediction_id(incident_id: str, technique_id: str) -> str:
    return str(uuid.uuid5(PREDICTION_NAMESPACE, f"{incident_id}|{technique_id}"))


class PredictionService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self.model = default_transition_model()  # validated at startup; a bad model file stops the app
        self._catalog = ctx.service("catalog")
        self._refreshing: set[str] = set()

    # -- pipeline integration (inside the caller's write transaction) --------------------------------

    def observed_count(self, session: Session, incident_id: str) -> int:
        return int(
            session.scalar(
                "SELECT count(*) FROM predictions WHERE incident_id = ? AND status = 'OBSERVED'", (incident_id,)
            )
        )

    def on_incidents_changed(self, session: Session, incident_ids: Sequence[str], actor: str) -> None:
        affected = set(incident_ids)
        if incident_ids:
            marks = ",".join("?" * len(incident_ids))
            rows = session.all(
                "SELECT DISTINCT other.incident_id FROM campaign_incidents mine "
                "JOIN campaign_incidents other ON other.campaign_id = mine.campaign_id "
                f"WHERE mine.incident_id IN ({marks})",
                list(incident_ids),
            )
            affected.update(row["incident_id"] for row in rows)  # campaign breadth changed for campaign members
        for incident_id in sorted(affected):
            self.refresh(session, incident_id, actor)

    def _context(self, session: Session, incident_id: str) -> PredictionContext:
        count = session.scalar(
            "SELECT max(c.incident_count) FROM campaigns c JOIN campaign_incidents ci ON ci.campaign_id = c.id "
            "WHERE ci.incident_id = ? AND c.status = 'ACTIVE'",
            (incident_id,),
        )
        return PredictionContext(campaign_incidents=int(count or 1))

    def refresh(self, session: Session, incident_id: str, actor: str) -> None:
        if incident_id in self._refreshing:
            return  # re-scoring re-enters the hook; predictions do not depend on the risk score
        self._refreshing.add(incident_id)
        try:
            self._refresh(session, incident_id, actor)
        finally:
            self._refreshing.discard(incident_id)

    def _refresh(self, session: Session, incident_id: str, actor: str) -> None:
        ctx = self._ctx
        incident = session.one("SELECT id, status, revision FROM incidents WHERE id = ?", (incident_id,))
        if incident is None:
            return
        now = ctx.clock.now()
        stamp = iso(now)
        existing = {
            row["technique_id"]: row
            for row in session.all("SELECT * FROM predictions WHERE incident_id = ?", (incident_id,))
        }
        observed_before = sum(1 for row in existing.values() if row["status"] == "OBSERVED")
        merged = incident["status"] == "MERGED"
        drafts: list[PredictionDraft] = []
        if not merged:
            events = ctx.service("incidents").events(session, incident_id)
            detections = [
                DetectionFact.from_row(row)
                for row in session.all(
                    "SELECT * FROM detections WHERE incident_id = ? AND status = 'ACTIVE'", (incident_id,)
                )
            ]
            drafts = predict(events, detections, self.model, self._context(session, incident_id))

        created: list[dict[str, Any]] = []
        observed: list[tuple[str, PredictionDraft]] = []
        expired: list[str] = []
        changed = False
        for draft in drafts:
            public = draft.public(now)
            status = public["status"]
            values: dict[str, Any] = {
                "technique_name": draft.technique_name,
                "tactic": draft.tactic,
                "score": draft.score,
                "band": draft.band,
                "factors": canonical_json(public["factors"]),
                "rationale": draft.rationale,
                "sources": canonical_json(public["sources"]),
                "evidence_ids": canonical_json(public["evidence_ids"]),
                "watch_signals": canonical_json(public["watch_signals"]),
                "preventive_actions": canonical_json(public["preventive_actions"]),
                "horizon_seconds": draft.horizon_seconds,
                "predicted_at": public["predicted_at"],
                "expires_at": public["expires_at"],
                "status": status,
                "observed_event_ids": canonical_json(public["observed_event_ids"]),
                "observed_at": public["observed_at"],
            }
            prior = existing.pop(draft.technique_id, None)
            pid = prior["id"] if prior is not None else prediction_id(incident_id, draft.technique_id)
            if prior is None:
                columns = ["id", "incident_id", "technique_id", "label", *_MUTABLE_COLUMNS]
                columns += ["status_changed_at", "created_at", "updated_at"]
                session.execute(
                    f"INSERT INTO predictions ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})",
                    [pid, incident_id, draft.technique_id, HYPOTHESIS, *values.values(), stamp, stamp, stamp],
                )
                created.append({"technique_id": draft.technique_id, "score": draft.score, "status": status})
                status_changed = True
            else:
                if all(prior[column] == value for column, value in values.items()):
                    continue
                status_changed = prior["status"] != status
                session.execute(
                    f"UPDATE predictions SET {', '.join(f'{c} = ?' for c in _MUTABLE_COLUMNS)}, "
                    "status_changed_at = ?, updated_at = ? WHERE id = ?",
                    [*values.values(), stamp if status_changed else prior["status_changed_at"], stamp, pid],
                )
            changed = True
            if status_changed and status == "OBSERVED":
                observed.append((pid, draft))
            elif status_changed and status == "EXPIRED":
                expired.append(draft.technique_id)

        withdrawn = sorted(existing)
        if withdrawn:
            session.execute(
                f"DELETE FROM predictions WHERE id IN ({','.join('?' * len(withdrawn))})",
                [existing[t]["id"] for t in withdrawn],
            )
            changed = True
        if not changed:
            return

        subject = ("incident", incident_id)
        if created:
            ctx.audit.append(
                session,
                "prediction.created",
                actor,
                {"incident_id": incident_id, "revision": incident["revision"], "predictions": created},
                subject=subject,
            )
        for pid, draft in observed:
            ctx.audit.append(
                session,
                "prediction.observed",
                actor,
                {
                    "incident_id": incident_id,
                    "prediction_id": pid,
                    "technique_id": draft.technique_id,
                    "score": draft.score,
                    "observed_event_ids": list(draft.observed_event_ids),
                },
                subject=subject,
            )
        if expired:
            ctx.audit.append(
                session,
                "prediction.expired",
                actor,
                {"incident_id": incident_id, "technique_ids": expired},
                subject=subject,
            )
        if withdrawn:
            reason = "incident merged" if merged else "predecessor detections are no longer active"
            ctx.audit.append(
                session,
                "prediction.withdrawn",
                actor,
                {"incident_id": incident_id, "technique_ids": withdrawn, "reason": reason},
                subject=subject,
            )

        notices = [("prediction.observed", pid, draft.technique_id) for pid, draft in observed]
        session.after_commit(lambda: self._publish(incident_id, notices))

        if not merged and sum(1 for d in drafts if d.status(now) == "OBSERVED") != observed_before:
            ctx.service("pipeline").refresh_incident(session, incident_id, actor)  # observed predictions raise risk

        watching = [d.expires_at for d in drafts if d.status(now) == "WATCHING"]
        if watching:
            ctx.jobs.enqueue(
                session,
                "prediction.expire",
                {"incident_id": incident_id},
                WATCHLIST_ACTOR,
                subject=("incident", incident_id, None),
                dedup_key=f"prediction.expire:{incident_id}",
                priority=400,
                delay_seconds=max(1.0, (min(watching) - now).total_seconds() + 1),
            )
        if (created or observed) and self._ai_available():
            self._enqueue_explain(session, incident_id, WATCHLIST_ACTOR, EXPLAIN_DEBOUNCE_SECONDS)

    def _publish(self, incident_id: str, notices: list[tuple[str, str, str]]) -> None:
        bus = self._ctx.bus
        bus.publish("prediction.updated", {"incident_id": incident_id})
        for event, pid, technique_id in notices:
            bus.publish(event, {"incident_id": incident_id, "prediction_id": pid, "technique_id": technique_id})

    # -- jobs ------------------------------------------------------------------------------------------

    def run_expire(self, job: Job) -> JobOutcome:
        incident_id = job.payload["incident_id"]
        return JobOutcome(
            result={"incident_id": incident_id},
            apply=lambda session: self.refresh(session, incident_id, job.actor),
        )

    def _ai_available(self) -> bool:
        runtime = self._ctx.services.get("ai")
        return runtime is not None and bool(runtime.provider_chain())

    def _enqueue_explain(self, session: Session, incident_id: str, actor: str, delay_seconds: float) -> str:
        job_id: str = self._ctx.jobs.enqueue(
            session,
            "prediction.explain",
            {"incident_id": incident_id},
            actor,
            subject=("incident", incident_id, None),
            dedup_key=f"prediction.explain:{incident_id}",
            priority=250,
            delay_seconds=delay_seconds,
        )
        return job_id

    def request_explanation(self, incident_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            incident = session.one("SELECT id, status FROM incidents WHERE id = ?", (incident_id,))
            if incident is None:
                raise NotFound("Unknown incident")
            if incident["status"] == "MERGED":
                raise Conflict("This incident was merged; explain the incident it was merged into")
            job_id = self._enqueue_explain(session, incident_id, principal.name, 0.0)
        position = ctx.jobs.queue_position(job_id)
        settings = ctx.services.get("llm_settings")
        return {
            "job_id": job_id,
            "queue_position": position,
            "eta_seconds": settings.eta_seconds(position) if settings is not None else None,
        }

    def run_explain(self, job: Job) -> JobOutcome:
        from app.ai.tasks.prediction_explain import deterministic_explanation, explain_task

        ctx = self._ctx
        incident_id = job.payload["incident_id"]
        detail = ctx.service("incidents").get(incident_id)
        predictions = self.for_incident(incident_id)["predictions"]
        runtime = ctx.services.get("ai")
        if runtime is None:
            content: dict[str, Any] = {
                **deterministic_explanation(predictions),
                "ai_status": "llm_disabled",
                "used_ai": False,
                "provider": None,
                "model": None,
            }
        else:
            spec, build = explain_task(detail, predictions, self._catalog)
            result = runtime.run(
                spec,
                build,
                actor=job.actor,
                subject=("incident", incident_id, detail["revision"]),
                job_id=job.id,
                on_token=lambda piece: ctx.jobs.publish_progress(job, {"token": piece}),
            )
            content = {
                **result.output,
                "ai_status": result.ai_status,
                "used_ai": result.used_ai,
                "provider": result.provider_id if result.used_ai else None,
                "model": result.model if result.used_ai else None,
            }
        revision = detail["revision"]

        def apply(session: Session) -> None:
            session.execute(
                "INSERT INTO prediction_explanations (id, incident_id, incident_revision, content, ai_status, provider, "
                "model, job_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    incident_id,
                    revision,
                    canonical_json(content),
                    content["ai_status"],
                    content["provider"],
                    content["model"],
                    job.id,
                    job.actor,
                    iso(ctx.clock.now()),
                ),
            )
            candidate = content.get("ai_candidate") or {}
            ctx.audit.append(
                session,
                "prediction.explained",
                job.actor,
                {
                    "incident_id": incident_id,
                    "incident_revision": revision,
                    "ai_status": content["ai_status"],
                    "provider": content["provider"],
                    "model": content["model"],
                    "items": len(content["items"]),
                    "ai_candidate": candidate.get("technique_id"),
                },
                subject=("incident", incident_id),
            )
            session.after_commit(lambda: ctx.bus.publish("prediction.explained", {"incident_id": incident_id}))

        return JobOutcome(result={"ai_status": content["ai_status"], "items": len(content["items"])}, apply=apply)

    # -- reads -----------------------------------------------------------------------------------------

    def _public(self, row: Any) -> dict[str, Any]:
        technique = self._catalog.get(row["technique_id"])
        result = {
            "id": row["id"],
            "incident_id": row["incident_id"],
            "technique": {
                "id": row["technique_id"],
                "name": row["technique_name"],
                "tactic": row["tactic"],
                "url": technique.url if technique else None,
            },
            "label": row["label"],
            "score": row["score"],
            "band": row["band"],
            "score_label": LIKELIHOOD_LABEL,
            "factors": json.loads(row["factors"]),
            "rationale": row["rationale"],
            "sources": json.loads(row["sources"]),
            "evidence_ids": json.loads(row["evidence_ids"]),
            "watch_signals": json.loads(row["watch_signals"]),
            "preventive_actions": json.loads(row["preventive_actions"]),
            "horizon_seconds": row["horizon_seconds"],
            "predicted_at": row["predicted_at"],
            "expires_at": row["expires_at"],
            "status": row["status"],
            "observed_event_ids": json.loads(row["observed_event_ids"]),
            "observed_at": row["observed_at"],
            "status_changed_at": row["status_changed_at"],
        }
        columns = row.keys()  # sqlite3.Row: `in row` would test values, not column names
        if "incident_title" in columns:
            result["incident_title"] = row["incident_title"]
            result["incident_asset"] = row["incident_asset"]
        return result

    def for_incident(self, incident_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            incident = session.one("SELECT id, revision FROM incidents WHERE id = ?", (incident_id,))
            if incident is None:
                raise NotFound("Unknown incident")
            rows = session.all(
                "SELECT * FROM predictions WHERE incident_id = ? ORDER BY score DESC, technique_id", (incident_id,)
            )
            explanation = session.one(
                "SELECT * FROM prediction_explanations WHERE incident_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (incident_id,),
            )
            pending = session.scalar(
                "SELECT id FROM jobs WHERE kind = 'prediction.explain' AND subject_id = ? "
                "AND status IN ('QUEUED', 'RUNNING') ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (incident_id,),
            )
        return {
            "incident_id": incident_id,
            "label": LIKELIHOOD_LABEL,
            "hypothesis_note": HYPOTHESIS_NOTE,
            "predictions": [self._public(row) for row in rows],
            "explanation": (
                {
                    **json.loads(explanation["content"]),
                    "incident_revision": explanation["incident_revision"],
                    "created_at": explanation["created_at"],
                    "stale": explanation["incident_revision"] != incident["revision"],
                }
                if explanation is not None
                else None
            ),
            "explain_job_id": pending,
            "attack_attribution": self._catalog.attribution,
        }

    def search(self, status: str | None = None, offset: int = 0, limit: int = 50) -> dict[str, Any]:
        clauses, params = ["i.status != 'MERGED'"], []
        if status:
            clauses.append("p.status = ?")
            params.append(status)
        where = " AND ".join(clauses)
        with self._ctx.db.read() as session:
            total = session.scalar(
                f"SELECT count(*) FROM predictions p JOIN incidents i ON i.id = p.incident_id WHERE {where}", params
            )
            rows = session.all(
                "SELECT p.*, i.title AS incident_title, i.asset AS incident_asset FROM predictions p "
                f"JOIN incidents i ON i.id = p.incident_id WHERE {where} "
                "ORDER BY p.score DESC, p.predicted_at DESC, p.rowid LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
        return {"items": [self._public(row) for row in rows], "total": int(total), "label": LIKELIHOOD_LABEL}

    def hit_rate(self) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            rows = session.all(
                "SELECT p.status, count(*) AS n FROM predictions p JOIN incidents i ON i.id = p.incident_id "
                "WHERE i.status != 'MERGED' GROUP BY p.status"
            )
        counts = {row["status"]: int(row["n"]) for row in rows}
        observed, expired, watching = counts.get("OBSERVED", 0), counts.get("EXPIRED", 0), counts.get("WATCHING", 0)
        total = observed + expired + watching
        return {
            "observed": observed,
            "expired": expired,
            "watching": watching,
            "total": total,
            "hit_rate": round(observed / total, 4) if total else None,
            "resolved_hit_rate": round(observed / (observed + expired), 4) if observed + expired else None,
            "label": HIT_RATE_LABEL,
        }

    def model_public(self) -> dict[str, Any]:
        return self.model.public()


# -- agent tools (read-only) -----------------------------------------------------------------------------


class WatchlistArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: Literal["WATCHING", "OBSERVED", "EXPIRED"] | None = None
    limit: int = Field(default=5, ge=1, le=10)


def _get_predictions_tool(tc: ToolContext, args: IncidentArg) -> dict[str, Any]:
    incident_id = incident_id_for(tc, args.incident_id)
    data = tc.ctx.service("predictions").for_incident(incident_id)
    events_by_id = {e["id"]: e for e in tc.ctx.service("incidents").get(incident_id)["events"]}
    rows = []
    for p in data["predictions"][:6]:
        observed = [events_by_id[e] for e in p["observed_event_ids"][:2] if e in events_by_id]
        rows.append(
            [
                p["technique"]["id"],
                p["technique"]["name"],
                p["technique"]["tactic"],
                p["score"],
                p["status"],
                p["watch_signals"][0]["text"] if p["watch_signals"] else None,
                [row[0] for row in tc.pack.add_events(observed)],
            ]
        )
    return {"label": "HYPOTHESIS; score is a heuristic, not a probability", "predictions": rows}


def _list_watchlist_tool(tc: ToolContext, args: WatchlistArgs) -> dict[str, Any]:
    page = tc.ctx.service("predictions").search(args.status, 0, args.limit)
    return {
        "total": page["total"],
        "predictions": [
            [p["incident_id"], p["technique"]["id"], p["technique"]["name"], p["score"], p["status"]]
            for p in page["items"]
        ],
    }


def agent_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            "get_predictions",
            "f4",
            "likely next attacker steps for an incident (hypotheses with watch signals)",
            IncidentArg,
            _get_predictions_tool,
        ),
        ToolSpec("list_watchlist", "f4", "watched predictions across incidents", WatchlistArgs, _list_watchlist_tool),
    ]
