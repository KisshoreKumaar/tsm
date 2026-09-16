"""I1 service: organisation profile, CERT-In drafts with provenance, deadlines, workflow and exports.

A draft is created deterministically so it works with the LLM disabled; when a provider is configured, an AI
narrative job replaces the description with a validated, cited version as a new draft version. AEGIS never submits a
report: an approver marks it submitted by hand after filing it through the official channel.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.ai.builtin_tools import IncidentArg, NoArgs, incident_id_for
from app.ai.tools import ToolContext, ToolError, ToolSpec
from app.core.auth import Principal
from app.core.db import Session
from app.core.errors import ApiError, Conflict, Forbidden, NotFound
from app.core.jobs import Job, JobOutcome
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso, parse_iso
from app.reports.deadline import countdown, deadline_for
from app.reports.export import render_html, render_json, render_markdown
from app.reports.mapping import completeness, map_fields
from app.reports.reportability import suggest
from app.reports.template import default_template

REPORT_AUDIT_ACTIONS = frozenset(
    {
        "org_profile.updated",
        "report.drafted",
        "report.updated",
        "report.submitted_for_review",
        "report.approved",
        "report.marked_submitted",
    }
)
ReportStatus = Literal["DRAFT", "IN_REVIEW", "APPROVED", "MARKED_SUBMITTED"]
EDITABLE = ("DRAFT", "IN_REVIEW")
NEVER_TRANSMITS = "AEGIS never sends this report anywhere. File it through the official channel, then record it here."


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class OrgProfileIn(Strict):
    organization_name: str = Field(min_length=1, max_length=200)
    sector: str = Field(min_length=1, max_length=120)
    contact_name: str = Field(min_length=1, max_length=120)
    contact_email: str = Field(min_length=3, max_length=200)
    contact_phone: str = Field(min_length=3, max_length=40)
    address: str | None = Field(default=None, max_length=400)


class FieldUpdateIn(Strict):
    fields: dict[str, str] = Field(max_length=25)
    note: str | None = Field(default=None, max_length=500)


class ReviewIn(Strict):
    note: str | None = Field(default=None, max_length=500)


class SubmittedIn(Strict):
    submitted_at: AwareDatetime
    reference: str = Field(min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=500)


def setup(ctx: Any) -> None:
    ctx.services["reports"] = ReportService(ctx)


def run_narrative_job(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("reports").run_narrative(job)
    return outcome


def _profile_public(row: Any) -> dict[str, Any]:
    if row is None:
        return {"configured": False, "profile": None}
    return {
        "configured": True,
        "profile": {
            "organization_name": row["organization_name"],
            "sector": row["sector"],
            "contact_name": row["contact_name"],
            "contact_email": row["contact_email"],
            "contact_phone": row["contact_phone"],
            "address": row["address"],
            "updated_by": row["updated_by"],
            "updated_at": row["updated_at"],
        },
    }


class ReportService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self.template = default_template()  # validated at startup; a bad template stops the app

    # -- organisation profile ---------------------------------------------------------------------------

    def profile(self) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            return _profile_public(session.one("SELECT * FROM org_profile WHERE id = 1"))

    def _profile_values(self, session: Session) -> dict[str, Any] | None:
        row = session.one("SELECT * FROM org_profile WHERE id = 1")
        return _profile_public(row)["profile"] if row is not None else None

    def save_profile(self, body: OrgProfileIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        now = iso(ctx.clock.now())
        with ctx.db.write() as session:
            session.execute(
                "INSERT INTO org_profile (id, organization_name, sector, contact_name, contact_email, contact_phone, "
                "address, updated_by, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET organization_name = excluded.organization_name, sector = excluded.sector, "
                "contact_name = excluded.contact_name, contact_email = excluded.contact_email, "
                "contact_phone = excluded.contact_phone, address = excluded.address, updated_by = excluded.updated_by, "
                "updated_at = excluded.updated_at",
                (
                    body.organization_name,
                    body.sector,
                    body.contact_name,
                    body.contact_email,
                    body.contact_phone,
                    body.address,
                    principal.name,
                    now,
                ),
            )
            ctx.audit.append(
                session,
                "org_profile.updated",
                principal.name,
                {"organization_name": body.organization_name, "sector": body.sector},
                subject=("org_profile", "1"),
            )
        return self.profile()

    # -- drafts -----------------------------------------------------------------------------------------

    def _row(self, session: Session, report_id: str) -> Any:
        row = session.one("SELECT * FROM cert_in_reports WHERE id = ?", (report_id,))
        if row is None:
            raise NotFound("Unknown report")
        return row

    def _version(self, session: Session, report_id: str, version: int) -> Any:
        row = session.one("SELECT * FROM report_versions WHERE report_id = ? AND version = ?", (report_id, version))
        if row is None:
            raise NotFound("Unknown report version")
        return row

    def _human_values(self, fields: dict[str, Any]) -> dict[str, str]:
        return {
            field_id: str(field["value"])
            for field_id, field in fields.items()
            if field.get("provenance") == "human" and field.get("value")
        }

    def _build(
        self, session: Session, incident_id: str, *, narrative: dict[str, Any] | None, human: dict[str, str]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        ctx = self._ctx
        detail = ctx.service("incidents").get(incident_id)
        reportability = suggest(detail, self.template)
        if narrative is None:
            from app.ai.tasks.cert_in_narrative import deterministic_narrative

            story = ctx.service("stories").incident_story(incident_id)["story"]
            narrative = deterministic_narrative(story)
        fields = map_fields(
            detail,
            self.template,
            profile=self._profile_values(session),
            reportability=reportability,
            narrative=narrative,
            human_values=human,
        )
        return detail, fields, reportability

    def draft(self, incident_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            incident = session.one("SELECT id, status, revision FROM incidents WHERE id = ?", (incident_id,))
            if incident is None:
                raise NotFound("Unknown incident")
            if incident["status"] == "MERGED":
                raise Conflict("This incident was merged; draft the report on the incident it was merged into")
            existing = session.one("SELECT * FROM cert_in_reports WHERE incident_id = ?", (incident_id,))
            if existing is not None and existing["status"] == "MARKED_SUBMITTED":
                raise Conflict(
                    "This report was already marked as submitted; drafts are frozen", code="report_submitted"
                )
            human: dict[str, str] = {}
            if existing is not None:
                previous = self._version(session, existing["id"], int(existing["current_version"]))
                human = self._human_values(json.loads(previous["fields"]))
            detail, fields, reportability = self._build(session, incident_id, narrative=None, human=human)
            now = iso(ctx.clock.now())
            detected = parse_iso(detail["first_detected_at"])
            deadline = deadline_for(detected, self.template.deadline_hours)
            if existing is None:
                report_id = str(uuid.uuid4())
                session.execute(
                    "INSERT INTO cert_in_reports (id, incident_id, incident_revision, status, current_version, "
                    "detected_at, deadline_at, template_version, created_by, created_at, updated_at) "
                    "VALUES (?, ?, ?, 'DRAFT', 1, ?, ?, ?, ?, ?, ?)",
                    (
                        report_id,
                        incident_id,
                        detail["revision"],
                        iso(detected),
                        iso(deadline),
                        self.template.version,
                        principal.name,
                        now,
                        now,
                    ),
                )
                version = 1
                action = "report.drafted"
            else:
                report_id = existing["id"]
                version = int(existing["current_version"]) + 1
                session.execute(
                    "UPDATE cert_in_reports SET incident_revision = ?, current_version = ?, status = 'DRAFT', "
                    "template_version = ?, updated_at = ? WHERE id = ?",
                    (detail["revision"], version, self.template.version, now, report_id),
                )
                action = "report.updated"
            self._insert_version(
                session, report_id, version, fields, reportability, principal.name, "Regenerated from evidence"
            )
            ctx.audit.append(
                session,
                action,
                principal.name,
                {
                    "report_id": report_id,
                    "incident_id": incident_id,
                    "version": version,
                    "template_status": self.template.data.status,
                    "missing_required": completeness(fields, self.template)["missing_required"],
                },
                subject=("cert_in_report", report_id),
            )
            if self._ai_available():
                ctx.jobs.enqueue(
                    session,
                    "report.cert_in_narrative",
                    {"report_id": report_id, "incident_id": incident_id},
                    principal.name,
                    subject=("incident", incident_id, int(detail["revision"])),
                    dedup_key=f"report.narrative:{report_id}",
                    priority=200,
                )
            session.after_commit(
                lambda: ctx.bus.publish("report.updated", {"report_id": report_id, "incident_id": incident_id})
            )
        return self.get(report_id)

    def _insert_version(
        self,
        session: Session,
        report_id: str,
        version: int,
        fields: dict[str, Any],
        reportability: dict[str, Any],
        actor: str,
        note: str,
        *,
        ai_status: str | None = None,
        provider: str | None = None,
        model: str | None = None,
    ) -> None:
        session.execute(
            "INSERT INTO report_versions (report_id, version, fields, reportability, ai_status, provider, model, note, "
            "created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report_id,
                version,
                canonical_json(fields),
                canonical_json(reportability),
                ai_status,
                provider,
                model,
                note,
                actor,
                iso(self._ctx.clock.now()),
            ),
        )

    def _ai_available(self) -> bool:
        runtime = self._ctx.services.get("ai")
        return runtime is not None and bool(runtime.provider_chain())

    def run_narrative(self, job: Job) -> JobOutcome:
        from app.ai.tasks.cert_in_narrative import narrative_task

        ctx = self._ctx
        report_id, incident_id = job.payload["report_id"], job.payload["incident_id"]
        runtime = ctx.services.get("ai")
        if runtime is None:
            return JobOutcome(result={"skipped": "AI runtime not enabled"})
        detail = ctx.service("incidents").get(incident_id)
        story = ctx.service("stories").incident_story(incident_id)["story"]
        spec, build = narrative_task(detail, story)
        result = runtime.run(
            spec, build, actor=job.actor, subject=("incident", incident_id, detail["revision"]), job_id=job.id
        )
        narrative = result.output
        if narrative.get("provenance") != "ai":
            return JobOutcome(result={"ai_status": result.ai_status, "kept": "deterministic"})

        def apply(session: Session) -> None:
            row = session.one("SELECT * FROM cert_in_reports WHERE id = ?", (report_id,))
            if row is None or row["status"] not in EDITABLE or int(row["incident_revision"]) != int(detail["revision"]):
                return  # the incident moved on, or a human already sent the draft for review
            previous = self._version(session, report_id, int(row["current_version"]))
            human = self._human_values(json.loads(previous["fields"]))
            _, fields, reportability = self._build(session, incident_id, narrative=narrative, human=human)
            version = int(row["current_version"]) + 1
            self._insert_version(
                session,
                report_id,
                version,
                fields,
                reportability,
                job.actor,
                "AI description validated against the evidence",
                ai_status=result.ai_status,
                provider=result.provider_id,
                model=result.model,
            )
            session.execute(
                "UPDATE cert_in_reports SET current_version = ?, updated_at = ? WHERE id = ?",
                (version, iso(ctx.clock.now()), report_id),
            )
            ctx.audit.append(
                session,
                "report.updated",
                job.actor,
                {"report_id": report_id, "version": version, "via": "ai", "ai_status": result.ai_status},
                subject=("cert_in_report", report_id),
            )
            session.after_commit(
                lambda: ctx.bus.publish("report.updated", {"report_id": report_id, "incident_id": incident_id})
            )

        return JobOutcome(result={"ai_status": result.ai_status, "report_id": report_id}, apply=apply)

    def update_fields(self, report_id: str, body: FieldUpdateIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, report_id)
            if row["status"] not in EDITABLE:
                raise Conflict(f"A {row['status']} report cannot be edited", code="report_locked")
            current = self._version(session, report_id, int(row["current_version"]))
            fields = json.loads(current["fields"])
            editable = {
                field.id
                for field in self.template.fields
                if field.source in ("human", "ai") or field.id == "description"
            }
            unknown = sorted(set(body.fields) - editable)
            if unknown:
                raise ApiError(
                    f"These fields are filled from evidence and cannot be edited by hand: {', '.join(unknown)}",
                    code="field_not_editable",
                    status_code=422,
                )
            for field_id, value in body.fields.items():
                field = self.template.field(field_id)
                text = value.strip()[: field.max_length] if field else value.strip()
                fields[field_id] = {
                    **fields.get(field_id, {"id": field_id, "label": field.label if field else field_id}),
                    "value": text,
                    "provenance": "human" if text else "missing",
                    "evidence_ids": [],
                    "refs": [],
                    "note": None,
                }
            version = int(row["current_version"]) + 1
            self._insert_version(
                session,
                report_id,
                version,
                fields,
                json.loads(current["reportability"]),
                principal.name,
                body.note or "Edited by hand",
            )
            session.execute(
                "UPDATE cert_in_reports SET current_version = ?, updated_at = ? WHERE id = ?",
                (version, iso(ctx.clock.now()), report_id),
            )
            ctx.audit.append(
                session,
                "report.updated",
                principal.name,
                {"report_id": report_id, "version": version, "fields": sorted(body.fields), "via": "human"},
                subject=("cert_in_report", report_id),
            )
            session.after_commit(lambda: ctx.bus.publish("report.updated", {"report_id": report_id}))
        return self.get(report_id)

    # -- workflow ---------------------------------------------------------------------------------------

    def _transition(
        self, report_id: str, principal: Principal, action: str, updates: dict[str, Any], body: dict[str, Any]
    ) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, report_id)
            assignments = ", ".join(f"{column} = ?" for column in updates)
            session.execute(
                f"UPDATE cert_in_reports SET {assignments}, updated_at = ? WHERE id = ?",
                [*updates.values(), iso(ctx.clock.now()), report_id],
            )
            ctx.audit.append(
                session,
                action,
                principal.name,
                {"report_id": report_id, "incident_id": row["incident_id"], "from_status": row["status"], **body},
                subject=("cert_in_report", report_id),
            )
            session.after_commit(lambda: ctx.bus.publish("report.updated", {"report_id": report_id}))
        return self.get(report_id)

    def submit_for_review(self, report_id: str, note: str | None, principal: Principal) -> dict[str, Any]:
        report = self.get(report_id)
        if report["status"] != "DRAFT":
            raise Conflict(f"Only a DRAFT can be sent for review (this one is {report['status']})")
        if report["completeness"]["missing_required"]:
            raise ApiError(
                "Fill every required field before sending the draft for review",
                code="missing_required_fields",
                status_code=422,
                details={"missing": report["completeness"]["missing_required"]},
            )
        return self._transition(
            report_id,
            principal,
            "report.submitted_for_review",
            {"status": "IN_REVIEW", "reviewed_by": principal.name, "reviewed_at": iso(self._ctx.clock.now())},
            {"note": note},
        )

    def approve(self, report_id: str, note: str | None, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        report = self.get(report_id)
        if report["status"] != "IN_REVIEW":
            raise Conflict(f"Only a report in review can be approved (this one is {report['status']})")
        if report["completeness"]["missing_required"]:
            raise ApiError(
                "Fill every required field before approving",
                code="missing_required_fields",
                status_code=422,
                details={"missing": report["completeness"]["missing_required"]},
            )
        if ctx.settings.two_person and report["created_by"] == principal.name:
            raise Forbidden("Two-person rule: a different person must approve this report", code="two_person_rule")
        return self._transition(
            report_id,
            principal,
            "report.approved",
            {"status": "APPROVED", "approved_by": principal.name, "approved_at": iso(ctx.clock.now())},
            {"note": note, "template_status": self.template.data.status},
        )

    def mark_submitted(self, report_id: str, body: SubmittedIn, principal: Principal) -> dict[str, Any]:
        report = self.get(report_id)
        if report["status"] != "APPROVED":
            raise Conflict(
                f"Only an approved report can be marked as submitted (this one is {report['status']})",
                code="not_approved",
            )
        return self._transition(
            report_id,
            principal,
            "report.marked_submitted",
            {
                "status": "MARKED_SUBMITTED",
                "submitted_by": principal.name,
                "submitted_at": iso(body.submitted_at),
                "submission_reference": body.reference,
                "submission_note": body.note,
            },
            {"reference": body.reference, "submitted_at": iso(body.submitted_at)},
        )

    # -- reads ------------------------------------------------------------------------------------------

    def _public(self, row: Any, version: Any, incident_revision: int | None) -> dict[str, Any]:
        fields = json.loads(version["fields"])
        ordered = [fields[field.id] for field in self.template.fields if field.id in fields]
        template = self.template.public()
        deadline = countdown(parse_iso(row["deadline_at"]), self._ctx.clock.now(), self.template.deadline_hours)
        status = row["status"]
        actions = []
        if status in EDITABLE:
            actions.append("edit")
        if status == "DRAFT":
            actions.append("submit_review")
        if status == "IN_REVIEW":
            actions.append("approve")
        if status == "APPROVED":
            actions.append("mark_submitted")
        if status != "MARKED_SUBMITTED":
            actions.append("regenerate")
        return {
            "id": row["id"],
            "incident_id": row["incident_id"],
            "incident_revision": row["incident_revision"],
            "stale": incident_revision is not None and int(row["incident_revision"]) != incident_revision,
            "status": status,
            "current_version": row["current_version"],
            "version": version["version"],
            "detected_at": row["detected_at"],
            "deadline": deadline,
            "fields": ordered,
            "reportability": json.loads(version["reportability"]),
            "completeness": completeness(fields, self.template),
            "template": {
                "status": template["status"],
                "verified": template["verified"],
                "banner": template["banner"],
                "template_version": row["template_version"],
                "verification_note": template["verification_note"],
                "reporting": template["reporting"],
            },
            "ai_status": version["ai_status"],
            "allowed_actions": actions,
            "two_person": self._ctx.settings.two_person,
            "never_transmits": NEVER_TRANSMITS,
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "approved_by": row["approved_by"],
            "approved_at": row["approved_at"],
            "submitted_by": row["submitted_by"],
            "submitted_at": row["submitted_at"],
            "submission_reference": row["submission_reference"],
            "submission_note": row["submission_note"],
        }

    def get(self, report_id: str, version: int | None = None) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            row = self._row(session, report_id)
            chosen = self._version(session, report_id, version or int(row["current_version"]))
            revision = session.scalar("SELECT revision FROM incidents WHERE id = ?", (row["incident_id"],))
            versions = session.all(
                "SELECT version, note, ai_status, created_by, created_at FROM report_versions WHERE report_id = ? "
                "ORDER BY version DESC",
                (report_id,),
            )
        public = self._public(row, chosen, int(revision) if revision is not None else None)
        public["versions"] = [dict(v) for v in versions]
        return public

    def by_incident(self, incident_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            row = session.one("SELECT id FROM cert_in_reports WHERE incident_id = ?", (incident_id,))
        if row is None:
            raise NotFound("No CERT-In draft exists for this incident yet")
        return self.get(str(row["id"]))

    def search(self, status: str | None = None) -> dict[str, Any]:
        clause, params = ("WHERE r.status = ?", [status]) if status else ("", [])
        with self._ctx.db.read() as session:
            rows = session.all(
                f"SELECT r.*, i.title, i.severity FROM cert_in_reports r JOIN incidents i ON i.id = r.incident_id "
                f"{clause} ORDER BY r.deadline_at",
                params,
            )
        now = self._ctx.clock.now()
        return {
            "items": [
                {
                    "id": row["id"],
                    "incident_id": row["incident_id"],
                    "incident_title": row["title"],
                    "severity": row["severity"],
                    "status": row["status"],
                    "current_version": row["current_version"],
                    "deadline": countdown(parse_iso(row["deadline_at"]), now, self.template.deadline_hours),
                    "created_by": row["created_by"],
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ]
        }

    def deadlines(self, limit: int = 50) -> dict[str, Any]:
        now = self._ctx.clock.now()
        with self._ctx.db.read() as session:
            rows = session.all(
                "SELECT i.id, i.title, i.severity, i.status AS incident_status, i.first_detected_at, "
                "r.id AS report_id, r.status AS report_status FROM incidents i "
                "LEFT JOIN cert_in_reports r ON r.incident_id = i.id "
                "WHERE i.status NOT IN ('MERGED', 'FALSE_POSITIVE') ORDER BY i.first_detected_at DESC LIMIT ?",
                (limit,),
            )
        items = []
        for row in rows:
            deadline = deadline_for(parse_iso(row["first_detected_at"]), self.template.deadline_hours)
            items.append(
                {
                    "incident_id": row["id"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "incident_status": row["incident_status"],
                    "report_id": row["report_id"],
                    "report_status": row["report_status"],
                    "deadline": countdown(deadline, now, self.template.deadline_hours),
                }
            )
        items.sort(key=lambda item: (item["report_status"] == "MARKED_SUBMITTED", item["deadline"]["deadline_utc"]))
        return {"items": items, "template": self.template.public()["banner"], "profile": self.profile()["configured"]}

    def diff(self, report_id: str, from_version: int, to_version: int) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            self._row(session, report_id)
            before = json.loads(self._version(session, report_id, from_version)["fields"])
            after = json.loads(self._version(session, report_id, to_version)["fields"])
        changes = []
        for field in self.template.fields:
            old = str(before.get(field.id, {}).get("value", ""))
            new = str(after.get(field.id, {}).get("value", ""))
            if old != new:
                changes.append(
                    {
                        "field": field.id,
                        "label": field.label,
                        "old": old,
                        "new": new,
                        "old_provenance": before.get(field.id, {}).get("provenance"),
                        "new_provenance": after.get(field.id, {}).get("provenance"),
                    }
                )
        return {"report_id": report_id, "from_version": from_version, "to_version": to_version, "changes": changes}

    def export(self, report_id: str, fmt: str, *, redact: bool) -> tuple[str, str, str]:
        report = self.get(report_id)
        name = f"cert-in-{report['incident_id'][:8]}-v{report['version']}{'-redacted' if redact else ''}"
        if fmt == "json":
            return (
                json.dumps(render_json(report, redacted=redact), indent=2, sort_keys=True) + "\n",
                f"{name}.json",
                "application/json",
            )
        if fmt == "html":
            return render_html(report, redacted=redact), f"{name}.html", "text/html; charset=utf-8"
        return render_markdown(report, redacted=redact), f"{name}.md", "text/markdown; charset=utf-8"


# -- agent tools (read-only) -----------------------------------------------------------------------------


def _get_report_tool(tc: ToolContext, args: IncidentArg) -> dict[str, Any]:
    try:
        report = tc.ctx.service("reports").by_incident(incident_id_for(tc, args.incident_id))
    except NotFound:
        raise ToolError("No CERT-In draft exists for that incident yet") from None
    return {
        "report_id": report["id"],
        "status": report["status"],
        "deadline_state": report["deadline"]["state"],
        "hours_left": round(report["deadline"]["seconds_remaining"] / 3600, 1),
        "missing_required": report["completeness"]["missing_required"],
        "suggested_type": report["reportability"]["incident_type_label"],
        "template_status": report["template"]["status"],
    }


def _deadlines_tool(tc: ToolContext, _: NoArgs) -> dict[str, Any]:
    items = tc.ctx.service("reports").deadlines(10)["items"]
    return {
        "deadlines": [
            [i["incident_id"], i["incident_status"], i["report_status"], i["deadline"]["state"]] for i in items[:8]
        ]
    }


def agent_tools() -> list[ToolSpec]:
    return [
        ToolSpec("get_report_draft", "i1", "CERT-In draft status for an incident", IncidentArg, _get_report_tool),
        ToolSpec("get_deadlines", "i1", "incidents with reporting deadlines", NoArgs, _deadlines_tool),
    ]
