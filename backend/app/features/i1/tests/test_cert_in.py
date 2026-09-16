"""I1: drafts filled from evidence with provenance, deadlines, the human-only workflow and exports."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.ai.providers import FakeProvider
from app.core.config import BACKEND_DIR
from app.core.context import AppContext
from app.core.timeutil import ManualClock
from app.reports.template import default_template
from tests.support import auth, run_scenario

PROFILE = {
    "organization_name": "Lab Industries Pvt Ltd",
    "sector": "Information technology",
    "contact_name": "Asha Rao",
    "contact_email": "asha.rao@lab.example",
    "contact_phone": "+91 22 5550 1234",
    "address": "5th Floor, Tech Park, Pune",
}


def fields_by_id(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {field["id"]: field for field in report["fields"]}


def draft(client: TestClient, ctx: AppContext, incident_id: str) -> dict[str, Any]:
    response = client.post(f"/api/incidents/{incident_id}/cert-in", json={}, headers=auth("analyst"))
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def test_draft_fills_evidence_fields_with_provenance_and_flags_the_missing_profile(
    client: TestClient, ctx: AppContext
) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    report = draft(client, ctx, incident_id)
    fields = fields_by_id(report)

    assert report["status"] == "DRAFT" and report["template"]["status"] == "UNVERIFIED"
    assert "UNVERIFIED" in report["template"]["banner"]
    assert report["reportability"]["incident_type"] == "unauthorised_access"
    assert "confirm with compliance" in report["reportability"]["label"].lower()
    detail = ctx.service("incidents").get(incident_id)
    event_ids = {event["id"] for event in detail["events"]}

    assert fields["detected_at"]["value"] == detail["first_detected_at"]
    assert fields["occurred_at"]["value"] == detail["first_seen"]
    assert detail["asset"] in fields["affected_systems"]["value"]
    assert set(fields["affected_systems"]["evidence_ids"]) <= event_ids
    assert "203.0.113.45" in fields["indicators"]["value"]  # external attacker IP, private ones are left out
    assert "10.20.1.15" not in fields["indicators"]["value"]
    assert "T1078" in fields["attack_techniques"]["value"]
    assert fields["description"]["provenance"] == "auto" and fields["description"]["evidence_ids"]
    assert all(fields[name]["provenance"] == "auto" for name in ("affected_systems", "indicators", "actions_taken"))

    assert fields["organization_name"]["provenance"] == "missing"
    assert "administrator" in fields["organization_name"]["note"]
    assert {"organization_name", "impact_assessment"} <= set(report["completeness"]["missing_required"])
    assert report["completeness"]["ready_for_review"] is False
    assert (
        client.post(f"/api/cert-in/{report['id']}/submit-review", json={}, headers=auth("analyst")).status_code == 422
    )


def test_workflow_needs_a_complete_draft_approval_and_a_human_submission(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    assert client.put("/api/org-profile", json=PROFILE, headers=auth("analyst")).status_code == 403
    assert client.put("/api/org-profile", json=PROFILE, headers=auth("admin")).status_code == 200
    report = draft(client, ctx, incident_id)
    report_id = report["id"]

    rejected = client.patch(
        f"/api/cert-in/{report_id}", json={"fields": {"affected_systems": "nothing"}}, headers=auth("analyst")
    )
    assert rejected.status_code == 422 and rejected.json()["error"]["code"] == "field_not_editable"

    edited = client.patch(
        f"/api/cert-in/{report_id}",
        json={"fields": {"impact_assessment": "Two lab workstations were reimaged; no customer data was involved."}},
        headers=auth("analyst"),
    ).json()
    assert edited["completeness"]["ready_for_review"] is True
    assert fields_by_id(edited)["impact_assessment"]["provenance"] == "human"
    assert fields_by_id(edited)["organization_name"]["value"] == PROFILE["organization_name"]

    assert client.post(f"/api/cert-in/{report_id}/approve", json={}, headers=auth("approver")).status_code == 409
    in_review = client.post(f"/api/cert-in/{report_id}/submit-review", json={}, headers=auth("analyst")).json()
    assert in_review["status"] == "IN_REVIEW"
    submission = {"submitted_at": "2026-01-15T10:00:00Z", "reference": "CERTIN-2026-0001"}
    early = client.post(f"/api/cert-in/{report_id}/mark-submitted", json=submission, headers=auth("approver"))
    assert early.status_code == 409 and early.json()["error"]["code"] == "not_approved"
    assert client.post(f"/api/cert-in/{report_id}/approve", json={}, headers=auth("analyst")).status_code == 403

    approved = client.post(f"/api/cert-in/{report_id}/approve", json={}, headers=auth("approver")).json()
    assert approved["status"] == "APPROVED" and approved["allowed_actions"] == ["mark_submitted", "regenerate"]
    submitted = client.post(
        f"/api/cert-in/{report_id}/mark-submitted", json=submission, headers=auth("approver")
    ).json()
    assert submitted["status"] == "MARKED_SUBMITTED" and submitted["submission_reference"] == "CERTIN-2026-0001"
    assert (
        client.patch(
            f"/api/cert-in/{report_id}", json={"fields": {"reporter_notes": "x"}}, headers=auth("analyst")
        ).status_code
        == 409
    )
    assert client.post(f"/api/incidents/{incident_id}/cert-in", json={}, headers=auth("analyst")).status_code == 409

    actions = {row["action"] for row in ctx.audit.page(ctx.db, limit=200)["items"]}
    assert {
        "org_profile.updated",
        "report.drafted",
        "report.updated",
        "report.approved",
        "report.marked_submitted",
    } <= actions
    assert ctx.audit.verify(ctx.db)["valid"]


def test_deadline_counts_from_detection_and_offers_ist(client: TestClient, ctx: AppContext, clock: ManualClock) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    report = draft(client, ctx, incident_id)
    deadline = report["deadline"]
    assert deadline["window_hours"] == default_template().deadline_hours
    assert deadline["deadline_utc"].endswith("+00:00") and deadline["deadline_ist"].endswith("+05:30")
    assert deadline["state"] == "ok" and deadline["overdue"] is False

    clock.advance(hours=5)
    later = client.get(f"/api/cert-in/{report['id']}", headers=auth("viewer")).json()["deadline"]
    assert later["state"] == "critical" and later["seconds_remaining"] <= 3600
    clock.advance(hours=2)
    overdue = client.get("/api/compliance/deadlines", headers=auth("viewer")).json()["items"]
    assert overdue[0]["deadline"]["overdue"] is True and overdue[0]["report_id"] == report["id"]


def test_exports_carry_the_unverified_banner_and_redact_personal_data(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    client.put("/api/org-profile", json=PROFILE, headers=auth("admin"))
    report = draft(client, ctx, incident_id)
    markdown = client.get(f"/api/cert-in/{report['id']}/export", headers=auth("viewer"))
    assert markdown.status_code == 200 and "attachment" in markdown.headers["content-disposition"]
    assert "UNVERIFIED" in markdown.text and "does not submit reports" in markdown.text
    assert PROFILE["contact_email"] in markdown.text

    redacted = client.get(f"/api/cert-in/{report['id']}/export", params={"redact": "true"}, headers=auth("viewer")).text
    assert PROFILE["contact_email"] not in redacted and "a***@lab.example" in redacted
    assert "redacted" in redacted.lower()

    html = client.get(f"/api/cert-in/{report['id']}/export", params={"format": "html"}, headers=auth("viewer")).text
    assert html.startswith("<!doctype html>") and "<script" not in html
    exported = json.loads(
        client.get(f"/api/cert-in/{report['id']}/export", params={"format": "json"}, headers=auth("viewer")).text
    )
    assert exported["format"] == "aegis-cert-in-draft" and exported["template"]["status"] == "UNVERIFIED"


def test_ai_narrative_replaces_the_description_only_when_it_cites_evidence(client: TestClient, ctx: AppContext) -> None:
    [incident_id] = run_scenario(ctx, "attack-chain")["incident_ids"]
    ctx.service("ai").override = FakeProvider(
        default=json.dumps(
            {
                "d": "Between 08:00 and 08:02 UTC an account on the lab workstation failed to log in repeatedly, then "
                "signed in successfully from an external address and started an encoded PowerShell command.",
                "e": ["E1", "E2"],
            }
        )
    )
    report = draft(client, ctx, incident_id)
    assert fields_by_id(report)["description"]["provenance"] == "auto"
    ctx.jobs.run_pending(ctx)
    polished = client.get(f"/api/cert-in/{report['id']}", headers=auth("viewer")).json()
    description = fields_by_id(polished)["description"]
    assert description["provenance"] == "ai" and description["evidence_ids"]
    assert polished["current_version"] == 2 and polished["ai_status"] == "validated"
    diff = client.get(
        f"/api/cert-in/{report['id']}/diff", params={"from_version": 1, "to_version": 2}, headers=auth("viewer")
    ).json()
    assert [change["field"] for change in diff["changes"]] == ["description"]

    [second] = run_scenario(ctx, "ransomware-burst")["incident_ids"]
    ctx.service("ai").override = FakeProvider(
        default=json.dumps({"d": "No citation at all in this description text.", "e": []})
    )
    other = draft(client, ctx, second)
    ctx.jobs.run_pending(ctx)
    kept = client.get(f"/api/cert-in/{other['id']}", headers=auth("viewer")).json()
    assert fields_by_id(kept)["description"]["provenance"] == "auto" and kept["current_version"] == 1


def test_reportability_follows_the_rules_that_fired(client: TestClient, ctx: AppContext) -> None:
    [ransomware] = run_scenario(ctx, "ransomware-burst")["incident_ids"]
    report = draft(client, ctx, ransomware)
    assert report["reportability"]["incident_type"] == "malicious_code"
    assert report["reportability"]["reportable"] == "yes"
    assert any("FILE-001" in reason for reason in report["reportability"]["reasons"])
    assert report["reportability"]["template_status"] == "UNVERIFIED"


@pytest.mark.parametrize("module", sorted(path.name for path in (BACKEND_DIR / "app" / "reports").glob("*.py")))
def test_reports_package_makes_no_network_calls(module: str) -> None:
    source = (BACKEND_DIR / "app" / "reports" / module).read_text(encoding="utf-8")
    for forbidden in ("httpx", "requests", "urllib", "socket", "smtplib"):
        assert forbidden not in source, f"{module} must not reach the network"
