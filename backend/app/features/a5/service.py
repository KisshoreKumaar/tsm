"""A5 service: false-positive analytics, tuning suggestions with impact simulation, approval, revert and expiry.

Suggestions are generated deterministically after false-positive verdicts (and on request), simulated against stored
events, optionally ranked by the AI, and applied only when a human with `tuning.approve` approves. Protected rules and
changes that remove true-positive alerts need explicit acknowledgement. Suppressed detections stay stored as
SUPPRESSED. Every change is audited and affected incidents are re-evaluated in the same transaction.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from app.ai.builtin_tools import NoArgs
from app.ai.tools import ToolContext, ToolSpec
from app.core.auth import Principal
from app.core.db import Session
from app.core.errors import ApiError, Conflict, Forbidden, NotFound
from app.core.jobs import Job, JobOutcome
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso, parse_iso
from app.detection.base import Detection, Event, Rule
from app.rules.dsl import RuleDefinition
from app.tuning.changes import SuggestionType, TuningChange, TuningError, TuningScope, validate_scope
from app.tuning.simulation import simulate
from app.tuning.suggestions import fingerprint, generate_candidates

TUNING_AUDIT_ACTIONS = frozenset(
    {
        "tuning.suggestion_created",
        "tuning.suggestion_updated",
        "tuning.approved",
        "tuning.rejected",
        "tuning.reverted",
        "tuning.suppression_expired",
        "tuning.ranked",
    }
)
WORKER_ACTOR = "system:tuning"
SIMULATION_DAYS = 90
SuggestionStatus = Literal["PROPOSED", "APPROVED", "REJECTED", "REVERTED"]
ANALYTICS_LABEL = "Rates describe analyst verdicts on AEGIS incidents, not ground truth."


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ManualSuggestionIn(Strict):
    type: SuggestionType
    rule_id: str = Field(min_length=1, max_length=32)
    scope: dict[str, Any]
    rationale: str = Field(min_length=3, max_length=1000)


class GenerateIn(Strict):
    rule_id: str | None = Field(default=None, max_length=32)


class ApproveIn(Strict):
    expires_in_days: StrictInt | None = Field(default=None, ge=1, le=90)
    acknowledge_true_positive_loss: StrictBool = False
    acknowledge_protected_rule: StrictBool = False
    note: str | None = Field(default=None, max_length=500)


class ReasonIn(Strict):
    reason: str = Field(min_length=3, max_length=500)


def setup(ctx: Any) -> None:
    service = TuningService(ctx)
    ctx.services["tuning"] = service
    pipeline = ctx.service("pipeline")
    pipeline.suppression_checks.append(service.check)
    pipeline.change_hooks.append(service.on_incidents_changed)
    ctx.service("rules").set_parameter_provider(service.parameter_overrides)


def run_generate_job(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("tuning").run_generate(job)
    return outcome


def run_expire_job(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("tuning").run_expire(job)
    return outcome


def run_rank_job(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("tuning").run_rank(job)
    return outcome


def _rate(part: int, total: int) -> float | None:
    return round(part / total, 4) if total else None


class TuningService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    # -- pipeline integration (inside the caller's transaction) ----------------------------------------

    def check(self, session: Session, detection: Detection, _events: Sequence[Event]) -> str | None:
        rows = session.all(
            "SELECT * FROM suppressions WHERE rule_id = ? AND status = 'ACTIVE' AND expires_at > ? ORDER BY created_at, id",
            (detection.rule_id, iso(self._ctx.clock.now())),
        )
        for row in rows:
            scope = TuningScope.model_validate(
                {
                    "entities": json.loads(row["entities"]),
                    "schedule": json.loads(row["schedule"]) if row["schedule"] else None,
                }
            )
            kind = "maintenance_window" if scope.schedule is not None else "suppression"
            if TuningChange(kind, row["rule_id"], scope).suppresses(session, detection):
                return str(row["id"])
        return None

    def parameter_overrides(self) -> dict[str, dict[str, int]]:
        with self._ctx.db.read() as session:
            rows = session.all("SELECT rule_id, parameters FROM rule_parameters WHERE status = 'ACTIVE'")
        return {row["rule_id"]: json.loads(row["parameters"]) for row in rows}

    def on_incidents_changed(self, session: Session, incident_ids: Sequence[str], actor: str) -> None:
        if not incident_ids:
            return
        marks = ",".join("?" * len(incident_ids))
        closed = session.scalar(
            f"SELECT count(*) FROM incidents WHERE status = 'FALSE_POSITIVE' AND id IN ({marks})", list(incident_ids)
        )
        if closed:
            self._ctx.jobs.enqueue(
                session, "tuning.generate", {}, WORKER_ACTOR, dedup_key="tuning.generate", priority=300, delay_seconds=2
            )

    # -- helpers ---------------------------------------------------------------------------------------

    def _row(self, session: Session, suggestion_id: str) -> Any:
        row = session.one("SELECT * FROM tuning_suggestions WHERE id = ?", (suggestion_id,))
        if row is None:
            raise NotFound("Unknown tuning suggestion")
        return row

    def _rule(self, rule_id: str) -> Rule:
        rule: Rule | None = self._ctx.service("rules").get(rule_id)
        if rule is None:
            raise Conflict(f"Rule {rule_id} is not active, so it cannot be tuned", code="rule_not_active")
        return rule

    def _change(self, kind: str, rule_id: str, raw_scope: Any) -> TuningChange:
        try:
            return TuningChange(kind, rule_id, validate_scope(kind, raw_scope))
        except TuningError as exc:
            raise ApiError(str(exc), code="invalid_tuning_scope", status_code=422) from None

    def _simulate(self, session: Session, rule: Rule, change: TuningChange) -> dict[str, Any]:
        now = self._ctx.clock.now()
        try:
            return simulate(
                session,
                rule,
                change,
                start=now - timedelta(days=SIMULATION_DAYS),
                end=now,
                window_seconds=self._ctx.settings.incident_window_seconds,
            )
        except TuningError as exc:
            raise ApiError(str(exc), code="invalid_tuning_change", status_code=422) from None

    def _public(self, row: Any) -> dict[str, Any]:
        impact = json.loads(row["impact"]) if row["impact"] else None
        protected = row["rule_id"] in self._ctx.settings.protected_rules
        return {
            "id": row["id"],
            "type": row["type"],
            "rule_id": row["rule_id"],
            "status": row["status"],
            "scope": json.loads(row["scope"]),
            "rationale": row["rationale"],
            "evidence": json.loads(row["evidence"]),
            "impact": impact,
            "impact_at": row["impact_at"],
            "source": row["source"],
            "ai_rank": row["ai_rank"],
            "ai_rationale": row["ai_rationale"],
            "applied": json.loads(row["applied"]) if row["applied"] else None,
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "decision_note": row["decision_note"],
            "protected_rule": protected,
            "requires": {
                "protected_rule_acknowledgement": protected,
                "true_positive_loss_acknowledgement": bool(impact and impact["red_flag"]),
            },
        }

    def _published(self, session: Session) -> None:
        session.after_commit(lambda: self._ctx.bus.publish("tuning.updated", {}))

    def _refresh_rule(
        self,
        session: Session,
        rule_id: str,
        actor: str,
        suppression_id: str | None = None,
        *,
        broad: bool = False,
    ) -> None:
        """Re-evaluate affected incidents, and suppressed-only components of a suppression.

        A suppression only ever removes this rule's own detections, so its incidents are enough. A threshold, window
        or exclusion change can also make the rule start firing again on incidents that currently have no detection
        from it, so those changes re-evaluate every open incident.
        """
        pipeline = self._ctx.service("pipeline")
        rows = (
            session.all("SELECT id AS incident_id FROM incidents WHERE status != 'MERGED' ORDER BY id LIMIT 500")
            if broad
            else session.all(
                "SELECT DISTINCT d.incident_id FROM detections d JOIN incidents i ON i.id = d.incident_id "
                "WHERE d.rule_id = ? AND i.status != 'MERGED' ORDER BY d.incident_id",
                (rule_id,),
            )
        )
        for row in rows:
            pipeline.refresh_incident(session, row["incident_id"], actor)
        if suppression_id is not None:
            orphans = session.all(
                "SELECT d.event_ids FROM detections d WHERE d.suppression_id = ? AND d.incident_id IS NULL",
                (suppression_id,),
            )
            for orphan in orphans:
                event_ids = json.loads(orphan["event_ids"])
                if event_ids:
                    pipeline.refresh_event_component(session, event_ids[0], actor)

    def _ai_available(self) -> bool:
        runtime = self._ctx.services.get("ai")
        return runtime is not None and bool(runtime.provider_chain())

    # -- suggestions -----------------------------------------------------------------------------------

    def _insert(
        self,
        session: Session,
        change: TuningChange,
        *,
        rationale: str,
        evidence: dict[str, Any],
        source: str,
        actor: str,
        impact: dict[str, Any],
    ) -> str:
        ctx = self._ctx
        now = iso(ctx.clock.now())
        suggestion_id = str(uuid.uuid4())
        scope = change.scope.model_dump(mode="json", exclude_none=True)
        session.execute(
            "INSERT INTO tuning_suggestions (id, type, rule_id, fingerprint, status, scope, rationale, evidence, impact, "
            "impact_at, source, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 'PROPOSED', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                suggestion_id,
                change.type,
                change.rule_id,
                fingerprint(change.type, change.rule_id, scope),
                canonical_json(scope),
                rationale,
                canonical_json(evidence),
                canonical_json(impact),
                now,
                source,
                actor,
                now,
                now,
            ),
        )
        ctx.audit.append(
            session,
            "tuning.suggestion_created",
            actor,
            {
                "suggestion_id": suggestion_id,
                "type": change.type,
                "rule_id": change.rule_id,
                "scope": scope,
                "source": source,
                "alerts_removed": impact["alerts_removed"],
                "true_positive_alerts_removed": impact["true_positive_alerts_removed"],
            },
            subject=("tuning_suggestion", suggestion_id),
        )
        self._published(session)
        return suggestion_id

    def _generate(self, session: Session, actor: str, rule_id: str | None) -> list[str]:
        ctx = self._ctx
        engine = ctx.service("rules")
        rules = {rule.id: rule for rule in engine.rules()}
        created: list[str] = []
        for candidate in generate_candidates(session, rules, engine.builtin_ids(), rule_id=rule_id):
            change = TuningChange(candidate.type, candidate.rule_id, validate_scope(candidate.type, candidate.scope))
            scope = change.scope.model_dump(mode="json", exclude_none=True)
            previous = session.one(
                "SELECT id, status FROM tuning_suggestions WHERE fingerprint = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (fingerprint(change.type, change.rule_id, scope),),
            )
            if previous is not None and previous["status"] in ("PROPOSED", "APPROVED", "REJECTED", "REVERTED"):
                continue  # one decision per scope; a human can still create a manual suggestion
            impact = self._simulate(session, rules[candidate.rule_id], change)
            created.append(
                self._insert(
                    session,
                    change,
                    rationale=candidate.rationale,
                    evidence=candidate.evidence,
                    source="deterministic",
                    actor=actor,
                    impact=impact,
                )
            )
        if created and self._ai_available():
            ctx.jobs.enqueue(session, "tuning.rank", {}, WORKER_ACTOR, dedup_key="tuning.rank", priority=300)
        return created

    def generate_now(self, principal: Principal, rule_id: str | None = None) -> list[str]:
        with self._ctx.db.write() as session:
            return self._generate(session, principal.name, rule_id.upper() if rule_id else None)

    def run_generate(self, job: Job) -> JobOutcome:
        outcome = JobOutcome(result={})

        def apply(session: Session) -> None:
            outcome.result["created"] = self._generate(session, job.actor, None)

        outcome.apply = apply
        return outcome

    def create_manual(self, body: ManualSuggestionIn, principal: Principal) -> dict[str, Any]:
        rule_id = body.rule_id.upper()
        change = self._change(body.type, rule_id, body.scope)
        rule = self._rule(rule_id)
        with self._ctx.db.write() as session:
            impact = self._simulate(session, rule, change)
            suggestion_id = self._insert(
                session,
                change,
                rationale=body.rationale,
                evidence={"closures": 0, "manual": True},
                source="manual",
                actor=principal.name,
                impact=impact,
            )
        return self.get(suggestion_id)

    def get(self, suggestion_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            return self._public(self._row(session, suggestion_id))

    def search(self, status: str | None = None, limit: int = 100) -> dict[str, Any]:
        clause, params = ("WHERE status = ?", [status]) if status else ("", [])
        with self._ctx.db.read() as session:
            rows = session.all(
                f"SELECT * FROM tuning_suggestions {clause} "
                "ORDER BY CASE WHEN ai_rank IS NULL THEN 1 ELSE 0 END, ai_rank, created_at DESC, rowid DESC LIMIT ?",
                [*params, limit],
            )
        return {"items": [self._public(row) for row in rows]}

    def resimulate(self, suggestion_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, suggestion_id)
            if row["status"] != "PROPOSED":
                raise Conflict(f"This suggestion is already {row['status']}")
            change = self._change(row["type"], row["rule_id"], json.loads(row["scope"]))
            impact = self._simulate(session, self._rule(change.rule_id), change)
            now = iso(ctx.clock.now())
            session.execute(
                "UPDATE tuning_suggestions SET impact = ?, impact_at = ?, updated_at = ? WHERE id = ?",
                (canonical_json(impact), now, now, suggestion_id),
            )
            ctx.audit.append(
                session,
                "tuning.suggestion_updated",
                principal.name,
                {
                    "suggestion_id": suggestion_id,
                    "alerts_removed": impact["alerts_removed"],
                    "true_positive_alerts_removed": impact["true_positive_alerts_removed"],
                },
                subject=("tuning_suggestion", suggestion_id),
            )
            self._published(session)
        return self.get(suggestion_id)

    def approve(self, suggestion_id: str, body: ApproveIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, suggestion_id)
            if row["status"] != "PROPOSED":
                raise Conflict(f"This suggestion is already {row['status']}")
            if ctx.settings.two_person and row["created_by"] == principal.name:
                raise Forbidden(
                    "Two-person rule: a different person must approve this tuning change", code="two_person_rule"
                )
            change = self._change(row["type"], row["rule_id"], json.loads(row["scope"]))
            rule = self._rule(change.rule_id)
            if change.rule_id in ctx.settings.protected_rules and not body.acknowledge_protected_rule:
                raise ApiError(
                    f"{change.rule_id} is a protected rule. Review the impact and acknowledge before changing it.",
                    code="protected_rule_acknowledgement_required",
                    status_code=422,
                )
            impact = self._simulate(session, rule, change)
            if impact["red_flag"] and not body.acknowledge_true_positive_loss:
                raise ApiError(
                    "This change removes alerts from incidents not closed as false positives. "
                    "Acknowledge the true-positive loss to approve it.",
                    code="true_positive_loss_acknowledgement_required",
                    status_code=422,
                    details={
                        "true_positive_alerts_removed": impact["true_positive_alerts_removed"],
                        "true_positives_lost": impact["true_positives_lost"],
                    },
                )
            now = ctx.clock.now()
            applied = self._apply(session, row, change, rule, body, principal, now)
            session.execute(
                "UPDATE tuning_suggestions SET status = 'APPROVED', impact = ?, impact_at = ?, applied = ?, decided_by = ?, "
                "decided_at = ?, decision_note = ?, updated_at = ? WHERE id = ?",
                (
                    canonical_json(impact),
                    iso(now),
                    canonical_json(applied),
                    principal.name,
                    iso(now),
                    body.note,
                    iso(now),
                    suggestion_id,
                ),
            )
            ctx.audit.append(
                session,
                "tuning.approved",
                principal.name,
                {
                    "suggestion_id": suggestion_id,
                    "type": change.type,
                    "rule_id": change.rule_id,
                    "scope": change.scope.model_dump(mode="json", exclude_none=True),
                    "applied": applied,
                    "alerts_removed": impact["alerts_removed"],
                    "true_positive_alerts_removed": impact["true_positive_alerts_removed"],
                    "acknowledged_true_positive_loss": body.acknowledge_true_positive_loss,
                    "acknowledged_protected_rule": body.acknowledge_protected_rule,
                },
                subject=("tuning_suggestion", suggestion_id),
            )
            self._refresh_rule(session, change.rule_id, principal.name, broad=not change.suppressive)
            self._published(session)
        return self.get(suggestion_id)

    def _apply(
        self,
        session: Session,
        row: Any,
        change: TuningChange,
        rule: Rule,
        body: ApproveIn,
        principal: Principal,
        now: datetime,
    ) -> dict[str, Any]:
        ctx = self._ctx
        if change.suppressive:
            days = body.expires_in_days or change.scope.expires_in_days
            expires = now + timedelta(days=days)
            suppression_id = str(uuid.uuid4())
            session.execute(
                "INSERT INTO suppressions (id, rule_id, entities, schedule, reason, suggestion_id, status, expires_at, "
                "created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)",
                (
                    suppression_id,
                    change.rule_id,
                    canonical_json([entity.model_dump() for entity in change.scope.entities]),
                    canonical_json(change.scope.schedule.model_dump()) if change.scope.schedule else None,
                    str(row["rationale"])[:1000],
                    row["id"],
                    iso(expires),
                    principal.name,
                    iso(now),
                ),
            )
            ctx.jobs.enqueue(
                session,
                "tuning.suppression_expire",
                {"suppression_id": suppression_id},
                WORKER_ACTOR,
                subject=("suppression", suppression_id, None),
                dedup_key=f"tuning.expire:{suppression_id}",
                priority=350,
                delay_seconds=days * 86_400 + 1,
            )
            return {"kind": "suppression", "suppression_id": suppression_id, "expires_at": iso(expires)}
        if change.rule_id in ctx.service("rules").builtin_ids():
            previous = session.one(
                "SELECT * FROM rule_parameters WHERE rule_id = ? AND status = 'ACTIVE'", (change.rule_id,)
            )
            parameters: dict[str, int] = json.loads(previous["parameters"]) if previous else {}
            if change.scope.threshold is not None:
                parameters["threshold"] = change.scope.threshold
            if change.scope.window_seconds is not None:
                parameters["window_seconds"] = change.scope.window_seconds
            if previous is not None:
                session.execute(
                    "UPDATE rule_parameters SET status = 'SUPERSEDED', ended_by = ?, ended_at = ?, end_reason = ? WHERE id = ?",
                    (principal.name, iso(now), f"Superseded by tuning suggestion {row['id']}", previous["id"]),
                )
            override_id = str(uuid.uuid4())
            current: dict[str, int] = getattr(rule, "parameters", dict)()
            session.execute(
                "INSERT INTO rule_parameters (id, rule_id, parameters, previous, suggestion_id, status, created_by, "
                "created_at) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)",
                (
                    override_id,
                    change.rule_id,
                    canonical_json(parameters),
                    canonical_json(current),
                    row["id"],
                    principal.name,
                    iso(now),
                ),
            )
            return {
                "kind": "parameters",
                "override_id": override_id,
                "parameters": parameters,
                "previous_parameters": current,
                "previous_override_id": previous["id"] if previous else None,
            }
        if "a3" not in ctx.features:
            raise Conflict("Changing a custom rule needs detection engineering (A3) enabled")
        definition = getattr(change.modified(rule), "definition", None)
        if not isinstance(definition, RuleDefinition):
            raise Conflict("Only custom DSL rules can be changed this way", code="not_a_custom_rule")
        version = ctx.service("detection_rules").activate_tuned_version(
            session, change.rule_id, definition, principal.name, row["id"]
        )
        return {"kind": "rule_version", "rule_id": change.rule_id, "version": version, "previous_version": rule.version}

    def reject(self, suggestion_id: str, reason: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, suggestion_id)
            if row["status"] != "PROPOSED":
                raise Conflict(f"This suggestion is already {row['status']}")
            now = iso(ctx.clock.now())
            session.execute(
                "UPDATE tuning_suggestions SET status = 'REJECTED', decided_by = ?, decided_at = ?, decision_note = ?, "
                "updated_at = ? WHERE id = ?",
                (principal.name, now, reason, now, suggestion_id),
            )
            ctx.audit.append(
                session,
                "tuning.rejected",
                principal.name,
                {"suggestion_id": suggestion_id, "rule_id": row["rule_id"], "reason": reason},
                subject=("tuning_suggestion", suggestion_id),
            )
            self._published(session)
        return self.get(suggestion_id)

    def revert(self, suggestion_id: str, reason: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, suggestion_id)
            if row["status"] != "APPROVED":
                raise Conflict("Only approved tuning changes can be reverted")
            applied = json.loads(row["applied"] or "{}")
            now = iso(ctx.clock.now())
            kind = applied.get("kind")
            suppression_id = None
            if kind == "suppression":
                suppression_id = applied["suppression_id"]
                session.execute(
                    "UPDATE suppressions SET status = 'REVERTED', ended_by = ?, ended_at = ?, end_reason = ? "
                    "WHERE id = ? AND status = 'ACTIVE'",
                    (principal.name, now, reason, suppression_id),
                )
            elif kind == "parameters":
                session.execute(
                    "UPDATE rule_parameters SET status = 'REVERTED', ended_by = ?, ended_at = ?, end_reason = ? "
                    "WHERE id = ? AND status = 'ACTIVE'",
                    (principal.name, now, reason, applied["override_id"]),
                )
                if applied.get("previous_override_id"):
                    session.execute(
                        "UPDATE rule_parameters SET status = 'ACTIVE', ended_by = NULL, ended_at = NULL, end_reason = NULL "
                        "WHERE id = ? AND status = 'SUPERSEDED' AND NOT EXISTS "
                        "(SELECT 1 FROM rule_parameters WHERE rule_id = ? AND status = 'ACTIVE')",
                        (applied["previous_override_id"], row["rule_id"]),
                    )
            elif kind == "rule_version":
                previous = session.scalar(
                    "SELECT definition FROM rule_versions WHERE rule_id = ? AND version = ?",
                    (applied["rule_id"], applied["previous_version"]),
                )
                ctx.service("detection_rules").activate_tuned_version(
                    session,
                    applied["rule_id"],
                    RuleDefinition.model_validate_json(str(previous)),
                    principal.name,
                    f"{suggestion_id} (revert)",
                )
            applied = {**applied, "reverted_by": principal.name, "reverted_at": now, "revert_reason": reason}
            session.execute(
                "UPDATE tuning_suggestions SET status = 'REVERTED', applied = ?, updated_at = ? WHERE id = ?",
                (canonical_json(applied), now, suggestion_id),
            )
            ctx.audit.append(
                session,
                "tuning.reverted",
                principal.name,
                {"suggestion_id": suggestion_id, "kind": kind, "rule_id": row["rule_id"], "reason": reason},
                subject=("tuning_suggestion", suggestion_id),
            )
            self._refresh_rule(session, row["rule_id"], principal.name, suppression_id, broad=kind != "suppression")
            self._published(session)
        return self.get(suggestion_id)

    # -- suppressions ----------------------------------------------------------------------------------

    def _suppression_public(self, row: Any) -> dict[str, Any]:
        now = self._ctx.clock.now()
        expires = parse_iso(row["expires_at"])
        active = row["status"] == "ACTIVE" and expires > now
        return {
            "id": row["id"],
            "rule_id": row["rule_id"],
            "entities": json.loads(row["entities"]),
            "schedule": json.loads(row["schedule"]) if row["schedule"] else None,
            "reason": row["reason"],
            "suggestion_id": row["suggestion_id"],
            "status": row["status"],
            "applies": active,
            "expires_at": row["expires_at"],
            "seconds_remaining": max(0, int((expires - now).total_seconds())) if active else 0,
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "ended_by": row["ended_by"],
            "ended_at": row["ended_at"],
            "end_reason": row["end_reason"],
        }

    def suppressions(self, status: str | None = None) -> dict[str, Any]:
        clause, params = ("WHERE status = ?", [status]) if status else ("", [])
        with self._ctx.db.read() as session:
            rows = session.all(f"SELECT * FROM suppressions {clause} ORDER BY created_at DESC, rowid DESC", params)
            overrides = session.all("SELECT * FROM rule_parameters ORDER BY created_at DESC, rowid DESC LIMIT 50")
        return {
            "items": [self._suppression_public(row) for row in rows],
            "parameter_overrides": [
                {
                    "id": o["id"],
                    "rule_id": o["rule_id"],
                    "parameters": json.loads(o["parameters"]),
                    "previous": json.loads(o["previous"]),
                    "suggestion_id": o["suggestion_id"],
                    "status": o["status"],
                    "created_by": o["created_by"],
                    "created_at": o["created_at"],
                    "ended_at": o["ended_at"],
                }
                for o in overrides
            ],
        }

    def revert_suppression(self, suppression_id: str, reason: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.read() as session:
            row = session.one("SELECT * FROM suppressions WHERE id = ?", (suppression_id,))
        if row is None:
            raise NotFound("Unknown suppression")
        if row["status"] != "ACTIVE":
            raise Conflict(f"This suppression is already {row['status']}")
        if row["suggestion_id"]:
            self.revert(row["suggestion_id"], reason, principal)
        else:
            with ctx.db.write() as session:
                session.execute(
                    "UPDATE suppressions SET status = 'REVERTED', ended_by = ?, ended_at = ?, end_reason = ? WHERE id = ?",
                    (principal.name, iso(ctx.clock.now()), reason, suppression_id),
                )
                ctx.audit.append(
                    session,
                    "tuning.reverted",
                    principal.name,
                    {
                        "suppression_id": suppression_id,
                        "kind": "suppression",
                        "rule_id": row["rule_id"],
                        "reason": reason,
                    },
                    subject=("suppression", suppression_id),
                )
                self._refresh_rule(session, row["rule_id"], principal.name, suppression_id)
                self._published(session)
        with ctx.db.read() as session:
            return self._suppression_public(session.one("SELECT * FROM suppressions WHERE id = ?", (suppression_id,)))

    def run_expire(self, job: Job) -> JobOutcome:
        suppression_id = job.payload["suppression_id"]
        ctx = self._ctx

        def apply(session: Session) -> None:
            row = session.one("SELECT * FROM suppressions WHERE id = ?", (suppression_id,))
            if row is None or row["status"] != "ACTIVE" or parse_iso(row["expires_at"]) > ctx.clock.now():
                return  # reverted already, or not due yet
            session.execute(
                "UPDATE suppressions SET status = 'EXPIRED', ended_by = ?, ended_at = ?, end_reason = ? WHERE id = ?",
                (WORKER_ACTOR, iso(ctx.clock.now()), "Reached its expiry", suppression_id),
            )
            ctx.audit.append(
                session,
                "tuning.suppression_expired",
                WORKER_ACTOR,
                {"suppression_id": suppression_id, "rule_id": row["rule_id"], "expires_at": row["expires_at"]},
                subject=("suppression", suppression_id),
            )
            self._refresh_rule(session, row["rule_id"], WORKER_ACTOR, suppression_id)
            self._published(session)

        return JobOutcome(result={"suppression_id": suppression_id}, apply=apply)

    def suppressed_detections(self, rule_id: str | None = None, limit: int = 100) -> dict[str, Any]:
        clause, params = (" AND d.rule_id = ?", [rule_id.upper()]) if rule_id else ("", [])
        with self._ctx.db.read() as session:
            rows = session.all(
                "SELECT d.id, d.rule_id, d.incident_id, d.summary, d.first_ts, d.last_ts, d.suppression_id, d.event_ids, "
                "s.status AS suppression_status, s.expires_at FROM detections d "
                f"LEFT JOIN suppressions s ON s.id = d.suppression_id WHERE d.status = 'SUPPRESSED'{clause} "
                "ORDER BY d.first_ts DESC, d.id LIMIT ?",
                [*params, limit],
            )
        return {
            "items": [
                {
                    "id": r["id"],
                    "rule_id": r["rule_id"],
                    "incident_id": r["incident_id"],
                    "summary": r["summary"],
                    "first_ts": r["first_ts"],
                    "last_ts": r["last_ts"],
                    "suppression_id": r["suppression_id"],
                    "suppression_status": r["suppression_status"],
                    "suppression_expires_at": r["expires_at"],
                    "event_count": len(json.loads(r["event_ids"])),
                }
                for r in rows
            ]
        }

    # -- analytics and ranking -------------------------------------------------------------------------

    def fp_analytics(self, days: int = 30) -> dict[str, Any]:
        since = iso(self._ctx.clock.now() - timedelta(days=days))
        with self._ctx.db.read() as session:
            per_rule = session.all(
                "SELECT d.rule_id, count(DISTINCT i.id) AS total, "
                "count(DISTINCT CASE WHEN i.status = 'FALSE_POSITIVE' THEN i.id END) AS false_positives "
                "FROM detections d JOIN incidents i ON i.id = d.incident_id WHERE i.status != 'MERGED' "
                "GROUP BY d.rule_id ORDER BY false_positives DESC, d.rule_id"
            )
            categories = session.all(
                "SELECT closure_category, count(*) AS n FROM incidents WHERE status = 'FALSE_POSITIVE' "
                "GROUP BY closure_category ORDER BY n DESC, closure_category"
            )
            entities = session.all(
                "SELECT ee.entity_type, ee.value, count(DISTINCT i.id) AS n FROM incidents i "
                "JOIN incident_events ie ON ie.incident_id = i.id JOIN event_entities ee ON ee.event_id = ie.event_id "
                "WHERE i.status = 'FALSE_POSITIVE' GROUP BY ee.entity_type, ee.value "
                "ORDER BY n DESC, ee.entity_type, ee.value LIMIT 20"
            )
            sources = session.all(
                "SELECT e.source, count(DISTINCT i.id) AS total, "
                "count(DISTINCT CASE WHEN i.status = 'FALSE_POSITIVE' THEN i.id END) AS false_positives "
                "FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id JOIN events e ON e.id = ie.event_id "
                "WHERE i.status != 'MERGED' GROUP BY e.source ORDER BY false_positives DESC, e.source"
            )
            trend = session.all(
                "SELECT substr(closed_at, 1, 10) AS day, count(*) AS n FROM incidents "
                "WHERE status = 'FALSE_POSITIVE' AND closed_at >= ? GROUP BY day ORDER BY day",
                (since,),
            )
            marked_rows = session.all(
                "SELECT closure_entities FROM incidents WHERE status = 'FALSE_POSITIVE' AND closure_entities IS NOT NULL"
            )
            closed = session.one(
                "SELECT count(*) AS closed, coalesce(sum(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END), 0) AS fp "
                "FROM incidents WHERE status IN ('RESOLVED', 'FALSE_POSITIVE')"
            )
        marked: Counter[tuple[str, str]] = Counter(
            (item["type"], item["value"]) for row in marked_rows for item in json.loads(row["closure_entities"])
        )
        return {
            "days": days,
            "closed_incidents": int(closed["closed"]),
            "false_positive_closures": int(closed["fp"]),
            "false_positive_rate": _rate(int(closed["fp"]), int(closed["closed"])),
            "per_rule": [
                {
                    "rule_id": r["rule_id"],
                    "incidents": r["total"],
                    "false_positives": r["false_positives"],
                    "rate": _rate(r["false_positives"], r["total"]),
                }
                for r in per_rule
            ],
            "per_category": [{"category": r["closure_category"], "count": r["n"]} for r in categories],
            "per_entity": [
                {
                    "type": r["entity_type"],
                    "value": r["value"],
                    "incidents": r["n"],
                    "marked_benign": marked[(r["entity_type"], r["value"])],
                }
                for r in entities
            ],
            "per_source": [
                {
                    "source": r["source"],
                    "incidents": r["total"],
                    "false_positives": r["false_positives"],
                    "rate": _rate(r["false_positives"], r["total"]),
                }
                for r in sources
            ],
            "trend": [{"day": r["day"], "false_positives": r["n"]} for r in trend],
            "label": ANALYTICS_LABEL,
        }

    def run_rank(self, job: Job) -> JobOutcome:
        from app.ai.tasks.tuning_suggest import deterministic_ranking, tuning_rank_task

        ctx = self._ctx
        items = self.search("PROPOSED", limit=8)["items"]
        if not items:
            return JobOutcome(result={"ranked": 0})
        runtime = ctx.services.get("ai")
        if runtime is None:
            output, ai_status = deterministic_ranking(items), "llm_disabled"
        else:
            spec, build = tuning_rank_task(items)
            result = runtime.run(spec, build, actor=job.actor, job_id=job.id)
            output, ai_status = result.output, result.ai_status
        used_ai = ai_status.startswith("validated")

        def apply(session: Session) -> None:
            for entry in output["ranking"]:
                session.execute(
                    "UPDATE tuning_suggestions SET ai_rank = ?, ai_rationale = ? WHERE id = ? AND status = 'PROPOSED'",
                    (entry["rank"], entry["rationale"] if used_ai else None, entry["suggestion_id"]),
                )
            ctx.audit.append(
                session, "tuning.ranked", job.actor, {"ai_status": ai_status, "ranked": len(output["ranking"])}
            )
            self._published(session)

        return JobOutcome(result={"ranked": len(output["ranking"]), "ai_status": ai_status}, apply=apply)


# -- agent tools (read-only) -----------------------------------------------------------------------------


class SuggestionStatusArg(Strict):
    status: SuggestionStatus | None = "PROPOSED"


def _fp_analytics_tool(tc: ToolContext, _: NoArgs) -> dict[str, Any]:
    data = tc.ctx.service("tuning").fp_analytics(30)
    return {
        "false_positive_closures": data["false_positive_closures"],
        "false_positive_rate": data["false_positive_rate"],
        "per_rule": [[r["rule_id"], r["false_positives"], r["incidents"]] for r in data["per_rule"][:8]],
        "categories": [[c["category"], c["count"]] for c in data["per_category"]],
        "note": data["label"],
    }


def _list_suggestions_tool(tc: ToolContext, args: SuggestionStatusArg) -> dict[str, Any]:
    items = tc.ctx.service("tuning").search(args.status, limit=8)["items"]
    return {
        "suggestions": [
            [
                s["id"],
                s["type"],
                s["rule_id"],
                s["status"],
                (s["impact"] or {}).get("false_positive_alerts_removed"),
                (s["impact"] or {}).get("true_positive_alerts_removed"),
            ]
            for s in items
        ]
    }


def agent_tools() -> list[ToolSpec]:
    return [
        ToolSpec("get_fp_analytics", "a5", "false-positive verdicts by rule and category", NoArgs, _fp_analytics_tool),
        ToolSpec(
            "list_tuning_suggestions",
            "a5",
            "tuning suggestions with simulated impact",
            SuggestionStatusArg,
            _list_suggestions_tool,
        ),
    ]
