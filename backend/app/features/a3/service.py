"""A3 service: custom rule lifecycle (DRAFT → TESTED → APPROVED → ACTIVE → DISABLED/RETIRED), backtests, drafts.

Editing creates a new version; the previously activated version keeps running until the new one is approved and
activated. Approval requires a backtest of the current version, and in two-person mode a different person than the
version's author. Every change is audited in the same transaction.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from app.ai.tools import ToolContext, ToolError, ToolSpec
from app.core.auth import Principal
from app.core.db import Session
from app.core.errors import ApiError, Conflict, Forbidden, NotFound
from app.core.jobs import Job, JobError, JobOutcome
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso
from app.rules.backtest import run_backtest
from app.rules.draft import DraftError
from app.rules.dsl import CompiledRule, RuleDefinition, RuleValidationError, diff_definitions, validate_definition
from app.rules.sigma import to_sigma

RULE_AUDIT_ACTIONS = frozenset(
    {
        "rule.created",
        "rule.version_created",
        "rule.backtested",
        "rule.approved",
        "rule.activated",
        "rule.disabled",
        "rule.retired",
    }
)
BACKTEST_DEFAULT_DAYS = 30
RuleStatus = Literal["DRAFT", "TESTED", "APPROVED", "ACTIVE", "DISABLED", "RETIRED"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RuleIn(Strict):
    definition: dict[str, Any]
    rationale: str | None = Field(default=None, max_length=1000)


class ValidateIn(Strict):
    definition: dict[str, Any]


class BacktestIn(Strict):
    start: AwareDatetime | None = None
    end: AwareDatetime | None = None

    @model_validator(mode="after")
    def _check(self) -> BacktestIn:
        if self.start and self.end and self.start >= self.end:
            raise ValueError("start must be before end")
        if self.start and self.end and self.end - self.start > timedelta(days=366):
            raise ValueError("A backtest range can span at most 366 days")
        return self


class DecisionIn(Strict):
    note: str | None = Field(default=None, max_length=500)


class ReasonIn(Strict):
    reason: str = Field(min_length=3, max_length=500)


def setup(ctx: Any) -> None:
    service = DetectionRuleService(ctx)
    ctx.services["detection_rules"] = service
    ctx.service("rules").add_provider(service.active_rules)


def run_draft_job(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("detection_rules").run_draft(job)
    return outcome


def allowed_actions(row: Any) -> list[str]:
    status = row["status"]
    if status == "RETIRED":
        return []
    actions = ["edit", "backtest", "retire"]
    if status == "TESTED":
        actions.append("approve")
    if status in ("APPROVED", "DISABLED") and row["approved_version"] == row["current_version"]:
        actions.append("activate")
    if row["active_version"] is not None and status != "DISABLED":
        actions.append("disable")
    return actions


def rule_summary(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "status": row["status"],
        "current_version": row["current_version"],
        "approved_version": row["approved_version"],
        "active_version": row["active_version"],
        "author": row["author"],
        "source": row["source"],
        "source_incident_id": row["source_incident_id"],
        "approved_by": row["approved_by"],
        "approved_at": row["approved_at"],
        "activated_by": row["activated_by"],
        "activated_at": row["activated_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "builtin": False,
        "allowed_actions": allowed_actions(row),
    }


class DetectionRuleService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._catalog = ctx.service("catalog")
        self._compiled: dict[tuple[str, int], CompiledRule] = {}

    # -- engine integration ----------------------------------------------------------------------------

    def _compile(self, rule_id: str, version: int, definition_json: str) -> CompiledRule:
        key = (rule_id, version)
        if key not in self._compiled:
            definition = RuleDefinition.model_validate_json(definition_json)
            self._compiled[key] = CompiledRule.build(rule_id, version, definition, self._catalog)
        return self._compiled[key]

    def active_rules(self) -> list[CompiledRule]:
        with self._ctx.db.read() as session:
            rows = session.all(
                "SELECT r.id, r.active_version, v.definition FROM dsl_rules r "
                "JOIN rule_versions v ON v.rule_id = r.id AND v.version = r.active_version "
                "WHERE r.active_version IS NOT NULL AND r.status NOT IN ('DISABLED', 'RETIRED') ORDER BY r.id"
            )
        return [self._compile(row["id"], int(row["active_version"]), row["definition"]) for row in rows]

    # -- validation and creation -----------------------------------------------------------------------

    def _validated(self, raw: Any) -> RuleDefinition:
        try:
            return validate_definition(raw, self._catalog)
        except RuleValidationError as exc:
            raise ApiError("The rule is invalid", code="invalid_rule", status_code=422, details=exc.errors) from None

    def validate(self, raw: Any) -> dict[str, Any]:
        try:
            definition = validate_definition(raw, self._catalog)
        except RuleValidationError as exc:
            return {"valid": False, "errors": exc.errors, "definition": None, "sigma_warnings": []}
        _, warnings = to_sigma("CUS-000", 1, definition)
        return {
            "valid": True,
            "errors": [],
            "definition": definition.model_dump(mode="json"),
            "sigma_warnings": warnings,
        }

    def _row(self, session: Session, rule_id: str) -> Any:
        row = session.one("SELECT * FROM dsl_rules WHERE id = ?", (rule_id,))
        if row is None:
            raise NotFound("Unknown custom rule")
        return row

    def _next_id(self, session: Session) -> str:
        last = session.scalar("SELECT id FROM dsl_rules WHERE id LIKE 'CUS-%' ORDER BY id DESC LIMIT 1")
        number = int(str(last)[4:]) + 1 if last else 1
        if number > 999:
            raise ApiError("The custom rule ID space (CUS-001 to CUS-999) is exhausted", code="rule_ids_exhausted")
        return f"CUS-{number:03d}"

    def insert_rule(
        self,
        session: Session,
        definition: RuleDefinition,
        *,
        author: str,
        source: str,
        rationale: str | None,
        incident_id: str | None = None,
    ) -> str:
        ctx = self._ctx
        rule_id = self._next_id(session)
        now = iso(ctx.clock.now())
        session.execute(
            "INSERT INTO dsl_rules (id, name, status, current_version, author, source, source_incident_id, created_at, "
            "updated_at) VALUES (?, ?, 'DRAFT', 1, ?, ?, ?, ?, ?)",
            (rule_id, definition.name, author, source, incident_id, now, now),
        )
        session.execute(
            "INSERT INTO rule_versions (rule_id, version, definition, rationale, created_by, created_at) "
            "VALUES (?, 1, ?, ?, ?, ?)",
            (rule_id, canonical_json(definition.model_dump(mode="json")), rationale, author, now),
        )
        ctx.audit.append(
            session,
            "rule.created",
            author,
            {"rule_id": rule_id, "version": 1, "name": definition.name, "source": source, "incident_id": incident_id},
            subject=("rule", rule_id),
        )
        self._published(session, rule_id)
        return rule_id

    def _published(self, session: Session, rule_id: str) -> None:
        session.after_commit(lambda: self._ctx.bus.publish("rule.updated", {"rule_id": rule_id}))

    def create(self, body: RuleIn, principal: Principal) -> dict[str, Any]:
        definition = self._validated(body.definition)
        with self._ctx.db.write() as session:
            rule_id = self.insert_rule(
                session, definition, author=principal.name, source="manual", rationale=body.rationale
            )
        return self.get(rule_id)

    def add_version(self, rule_id: str, body: RuleIn, principal: Principal) -> dict[str, Any]:
        definition = self._validated(body.definition)
        with self._ctx.db.write() as session:
            row = self._row(session, rule_id)
            if row["status"] == "RETIRED":
                raise Conflict("Retired rules cannot be edited")
            version = self.insert_version(session, row, definition, principal.name, body.rationale)
            session.execute("UPDATE dsl_rules SET status = 'DRAFT' WHERE id = ?", (rule_id,))
            self._ctx.audit.append(
                session,
                "rule.version_created",
                principal.name,
                {"rule_id": rule_id, "version": version, "previous_status": row["status"], "via": "editor"},
                subject=("rule", rule_id),
            )
        return self.get(rule_id)

    def insert_version(
        self, session: Session, row: Any, definition: RuleDefinition, author: str, rationale: str | None
    ) -> int:
        version = int(row["current_version"]) + 1
        now = iso(self._ctx.clock.now())
        session.execute(
            "INSERT INTO rule_versions (rule_id, version, definition, rationale, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (row["id"], version, canonical_json(definition.model_dump(mode="json")), rationale, author, now),
        )
        session.execute(
            "UPDATE dsl_rules SET name = ?, current_version = ?, updated_at = ? WHERE id = ?",
            (definition.name, version, now, row["id"]),
        )
        self._published(session, row["id"])
        return version

    def activate_tuned_version(
        self, session: Session, rule_id: str, definition: RuleDefinition, actor: str, suggestion_id: str
    ) -> int:
        """A5: an approved tuning change becomes a new version that runs immediately (the approval is the review)."""
        row = self._row(session, rule_id)
        version = self.insert_version(session, row, definition, actor, f"Tuning suggestion {suggestion_id}")
        now = iso(self._ctx.clock.now())
        session.execute(
            "UPDATE dsl_rules SET status = 'ACTIVE', approved_version = ?, active_version = ?, approved_by = ?, "
            "approved_at = ?, activated_by = ?, activated_at = ? WHERE id = ?",
            (version, version, actor, now, actor, now, rule_id),
        )
        self._ctx.audit.append(
            session,
            "rule.version_created",
            actor,
            {"rule_id": rule_id, "version": version, "via": "tuning", "suggestion_id": suggestion_id},
            subject=("rule", rule_id),
        )
        return version

    # -- reads -----------------------------------------------------------------------------------------

    def get(self, rule_id: str) -> dict[str, Any]:
        engine = self._ctx.service("rules")
        if rule_id in engine.builtin_ids():
            entry = next(item for item in engine.describe() if item["id"] == rule_id)
            return {**entry, "status": "ACTIVE", "allowed_actions": []}
        with self._ctx.db.read() as session:
            row = self._row(session, rule_id)
            versions = session.all("SELECT * FROM rule_versions WHERE rule_id = ? ORDER BY version DESC", (rule_id,))
            backtests = session.all(
                "SELECT * FROM backtests WHERE rule_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 5", (rule_id,)
            )
        current = next(v for v in versions if v["version"] == row["current_version"])
        definition = json.loads(current["definition"])
        _, sigma_warnings = to_sigma(rule_id, int(row["current_version"]), RuleDefinition.model_validate(definition))
        return {
            **rule_summary(row),
            "definition": definition,
            "current_version_author": current["created_by"],
            "two_person": self._ctx.settings.two_person,
            "sigma_warnings": sigma_warnings,
            "versions": [
                {
                    "version": v["version"],
                    "definition": json.loads(v["definition"]),
                    "rationale": v["rationale"],
                    "created_by": v["created_by"],
                    "created_at": v["created_at"],
                }
                for v in versions
            ],
            "backtests": [
                {
                    "id": b["id"],
                    "version": b["rule_version"],
                    "created_by": b["created_by"],
                    "created_at": b["created_at"],
                    "result": json.loads(b["result"]),
                }
                for b in backtests
            ],
        }

    def search(self, status: str | None = None) -> dict[str, Any]:
        clause, params = ("WHERE status = ?", [status]) if status else ("", [])
        with self._ctx.db.read() as session:
            rows = session.all(f"SELECT * FROM dsl_rules {clause} ORDER BY updated_at DESC, id", params)
        return {"items": [rule_summary(row) for row in rows]}

    def diff(self, rule_id: str, from_version: int, to_version: int) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            self._row(session, rule_id)
            rows = {
                row["version"]: json.loads(row["definition"])
                for row in session.all(
                    "SELECT version, definition FROM rule_versions WHERE rule_id = ? AND version IN (?, ?)",
                    (rule_id, from_version, to_version),
                )
            }
        if from_version not in rows or to_version not in rows:
            raise NotFound("Unknown rule version")
        return {
            "rule_id": rule_id,
            "from_version": from_version,
            "to_version": to_version,
            "changes": diff_definitions(rows[from_version], rows[to_version]),
        }

    def export(self, rule_id: str, fmt: str) -> tuple[str, str, str]:
        if rule_id in self._ctx.service("rules").builtin_ids():
            raise Conflict("Built-in rules are code, not DSL, and cannot be exported", code="builtin_rule")
        detail = self.get(rule_id)
        version = detail["current_version"]
        if fmt == "json":
            document = {
                "format": "aegis-rule-dsl",
                "format_version": 1,
                "rule": {
                    "id": rule_id,
                    "version": version,
                    "status": detail["status"],
                    "definition": detail["definition"],
                },
            }
            return (
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                f"{rule_id}-v{version}.json",
                "application/json",
            )
        text, _ = to_sigma(rule_id, version, RuleDefinition.model_validate(detail["definition"]))
        return text, f"{rule_id}-v{version}.sigma.yml", "application/x-yaml"

    # -- backtest and lifecycle ------------------------------------------------------------------------

    def backtest(self, rule_id: str, body: BacktestIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        end: datetime = body.end or ctx.clock.now()
        start: datetime = body.start or end - timedelta(days=BACKTEST_DEFAULT_DAYS)
        with ctx.db.read() as session:
            row = self._row(session, rule_id)
            if row["status"] == "RETIRED":
                raise Conflict("Retired rules cannot be backtested")
            version = int(row["current_version"])
            definition = session.scalar(
                "SELECT definition FROM rule_versions WHERE rule_id = ? AND version = ?", (rule_id, version)
            )
            rule = self._compile(rule_id, version, str(definition))
            result = run_backtest(
                session, rule, start=start, end=end, incident_window_seconds=ctx.settings.incident_window_seconds
            )
        backtest_id = str(uuid.uuid4())
        with ctx.db.write() as session:
            current = self._row(session, rule_id)
            session.execute(
                "INSERT INTO backtests (id, rule_id, rule_version, range_start, range_end, result, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    backtest_id,
                    rule_id,
                    version,
                    result["range"]["start"],
                    result["range"]["end"],
                    canonical_json(result),
                    principal.name,
                    iso(ctx.clock.now()),
                ),
            )
            status = current["status"]
            if status == "DRAFT" and int(current["current_version"]) == version:
                status = "TESTED"
                session.execute(
                    "UPDATE dsl_rules SET status = 'TESTED', updated_at = ? WHERE id = ?",
                    (iso(ctx.clock.now()), rule_id),
                )
            ctx.audit.append(
                session,
                "rule.backtested",
                principal.name,
                {
                    "rule_id": rule_id,
                    "version": version,
                    "backtest_id": backtest_id,
                    "detections": result["detections"],
                    "total_matches": result["total_matches"],
                    "false_positive_matches": result["matches_in_false_positive_incidents"],
                    "benign_matches": result["matches_in_benign_scenario"],
                },
                subject=("rule", rule_id),
            )
            self._published(session, rule_id)
        return {"backtest_id": backtest_id, "rule_id": rule_id, "version": version, "status": status, "result": result}

    def _transition(
        self, rule_id: str, principal: Principal, action: str, note: str | None, change: Any
    ) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, rule_id)
            updates = change(session, row)
            now = iso(ctx.clock.now())
            assignments = ", ".join(f"{column} = ?" for column in updates)
            session.execute(
                f"UPDATE dsl_rules SET {assignments}, updated_at = ? WHERE id = ?", [*updates.values(), now, rule_id]
            )
            ctx.audit.append(
                session,
                f"rule.{action}",
                principal.name,
                {
                    "rule_id": rule_id,
                    "version": row["current_version"],
                    "from_status": row["status"],
                    "to_status": updates.get("status", row["status"]),
                    "note": note,
                },
                subject=("rule", rule_id),
            )
            self._published(session, rule_id)
        return self.get(rule_id)

    def approve(self, rule_id: str, note: str | None, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx

        def change(session: Session, row: Any) -> dict[str, Any]:
            if row["status"] != "TESTED":
                raise Conflict(
                    "Only TESTED rules can be approved; backtest the current version first", code="rule_not_tested"
                )
            author = session.scalar(
                "SELECT created_by FROM rule_versions WHERE rule_id = ? AND version = ?",
                (rule_id, row["current_version"]),
            )
            if ctx.settings.two_person and author == principal.name:
                raise Forbidden("Two-person rule: a different person must approve this rule", code="two_person_rule")
            return {
                "status": "APPROVED",
                "approved_version": row["current_version"],
                "approved_by": principal.name,
                "approved_at": iso(ctx.clock.now()),
            }

        return self._transition(rule_id, principal, "approved", note, change)

    def activate(self, rule_id: str, note: str | None, principal: Principal) -> dict[str, Any]:
        def change(_: Session, row: Any) -> dict[str, Any]:
            if "activate" not in allowed_actions(row):
                raise Conflict(
                    "Only an approved current version can be activated (TESTED and approved first)",
                    code="rule_not_approved",
                )
            return {
                "status": "ACTIVE",
                "active_version": row["current_version"],
                "activated_by": principal.name,
                "activated_at": iso(self._ctx.clock.now()),
            }

        return self._transition(rule_id, principal, "activated", note, change)

    def disable(self, rule_id: str, reason: str, principal: Principal) -> dict[str, Any]:
        def change(_: Session, row: Any) -> dict[str, Any]:
            if "disable" not in allowed_actions(row):
                raise Conflict("Only a rule with an active version can be disabled")
            return {"status": "DISABLED"}

        return self._transition(rule_id, principal, "disabled", reason, change)

    def retire(self, rule_id: str, reason: str, principal: Principal) -> dict[str, Any]:
        def change(_: Session, row: Any) -> dict[str, Any]:
            if row["status"] == "RETIRED":
                raise Conflict("This rule is already retired")
            return {"status": "RETIRED"}

        return self._transition(rule_id, principal, "retired", reason, change)

    # -- drafts ------------------------------------------------------------------------------------------

    def _incident_for_draft(self, incident_id: str) -> None:
        with self._ctx.db.read() as session:
            status = session.scalar("SELECT status FROM incidents WHERE id = ?", (incident_id,))
        if status is None:
            raise NotFound("Unknown incident")
        if status == "MERGED":
            raise Conflict("This incident was merged; draft from the incident it was merged into")

    def request_draft(self, incident_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        self._incident_for_draft(incident_id)
        with ctx.db.write() as session:
            job_id: str = ctx.jobs.enqueue(
                session,
                "rules.draft",
                {"incident_id": incident_id},
                principal.name,
                subject=("incident", incident_id, None),
                dedup_key=f"rules.draft:{incident_id}:{principal.name}",
                priority=150,
            )
        position = ctx.jobs.queue_position(job_id)
        settings = ctx.services.get("llm_settings")
        return {
            "job_id": job_id,
            "queue_position": position,
            "eta_seconds": settings.eta_seconds(position) if settings is not None else None,
        }

    def run_draft(self, job: Job) -> JobOutcome:
        from app.ai.tasks.rules_draft import deterministic_rule_draft, rules_draft_task

        ctx = self._ctx
        incident_id = job.payload["incident_id"]
        detail = ctx.service("incidents").get(incident_id)
        with ctx.db.read() as session:
            events = ctx.service("incidents").events(session, incident_id)
        runtime = ctx.services.get("ai")
        try:
            if runtime is None:
                output, ai_status = deterministic_rule_draft(detail), "llm_disabled"
            else:
                existing = [f"{rule['id']} {rule['name']}" for rule in ctx.service("rules").describe()][:20]
                spec, build = rules_draft_task(detail, events, self._catalog, existing)
                result = runtime.run(
                    spec, build, actor=job.actor, subject=("incident", incident_id, detail["revision"]), job_id=job.id
                )
                output, ai_status = result.output, result.ai_status
        except DraftError as exc:
            raise JobError(str(exc)) from None
        definition = self._validated(output["definition"])
        outcome = JobOutcome(result={"incident_id": incident_id, "source": output["source"], "ai_status": ai_status})

        def apply(session: Session) -> None:
            outcome.result["rule_id"] = self.insert_rule(
                session,
                definition,
                author=job.actor,
                source=output["source"],
                rationale=output["rationale"],
                incident_id=incident_id,
            )

        outcome.apply = apply
        return outcome

    def draft_now(self, incident_id: str, principal: Principal) -> dict[str, Any]:
        """Deterministic draft created synchronously (used when a human applies an agent proposal)."""
        from app.ai.tasks.rules_draft import deterministic_rule_draft

        self._incident_for_draft(incident_id)
        try:
            output = deterministic_rule_draft(self._ctx.service("incidents").get(incident_id))
        except DraftError as exc:
            raise ApiError(str(exc), code="draft_failed", status_code=422) from None
        definition = self._validated(output["definition"])
        with self._ctx.db.write() as session:
            rule_id = self.insert_rule(
                session,
                definition,
                author=principal.name,
                source=output["source"],
                rationale=output["rationale"],
                incident_id=incident_id,
            )
        return {"rule_id": rule_id, "status": "DRAFT"}


# -- agent tools (read-only) -----------------------------------------------------------------------------


class RuleIdArg(Strict):
    rule_id: str = Field(min_length=1, max_length=32)


class RuleStatusArg(Strict):
    status: RuleStatus | None = None


def _get_rule_tool(tc: ToolContext, args: RuleIdArg) -> dict[str, Any]:
    try:
        rule = tc.ctx.service("detection_rules").get(args.rule_id.upper())
    except NotFound:
        raise ToolError("Unknown rule_id") from None
    if rule.get("builtin"):
        return {"id": rule["id"], "builtin": True, "description": rule["description"], "parameters": rule["parameters"]}
    latest = rule["backtests"][0]["result"] if rule["backtests"] else None
    logic = rule["definition"]["logic"]
    return {
        "id": rule["id"],
        "name": rule["name"],
        "status": rule["status"],
        "version": rule["current_version"],
        "active_version": rule["active_version"],
        "logic": {k: logic[k] for k in ("kinds", "group_by", "window_seconds", "threshold")},
        "latest_backtest": (
            {k: latest[k] for k in ("detections", "matches_in_false_positive_incidents", "matches_in_benign_scenario")}
            if latest
            else None
        ),
    }


def _list_custom_rules_tool(tc: ToolContext, args: RuleStatusArg) -> dict[str, Any]:
    items = tc.ctx.service("detection_rules").search(args.status)["items"][:10]
    return {"rules": [[r["id"], r["name"], r["status"], r["current_version"], r["active_version"]] for r in items]}


def agent_tools() -> list[ToolSpec]:
    return [
        ToolSpec("get_rule", "a3", "a rule's logic, status and latest backtest", RuleIdArg, _get_rule_tool),
        ToolSpec("list_custom_rules", "a3", "custom DSL rules by status", RuleStatusArg, _list_custom_rules_tool),
    ]
