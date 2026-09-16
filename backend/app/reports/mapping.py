"""Deterministic field mapping for CERT-In drafts (I1).

Every field carries its provenance — `profile`, `auto`, `ai`, `human` or `missing` — and the evidence it came from,
so a reviewer can check each line against the incident. AEGIS fills what it can prove; impact and reporter notes are
left to a human, and the description comes from the story (AI when available, deterministic otherwise).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.correlation.campaigns import is_external_ip
from app.reports.template import CertInTemplate

PROFILE_FIELDS = {
    "organization_name": "organization_name",
    "organization_sector": "sector",
    "contact_name": "contact_name",
    "contact_email": "contact_email",
    "contact_phone": "contact_phone",
    "organization_address": "address",
}
MISSING_PROFILE = "No organisation profile has been saved yet; an administrator must fill it in before filing."
SIMULATED_NOTE = "Response actions in AEGIS are simulated; describe what was actually done before filing."


def _field(
    field_id: str,
    label: str,
    value: str,
    provenance: str,
    *,
    evidence_ids: Sequence[str] = (),
    refs: Sequence[Mapping[str, str]] = (),
    note: str | None = None,
) -> dict[str, Any]:
    text = value.strip()
    return {
        "id": field_id,
        "label": label,
        "value": text,
        "provenance": provenance if text else "missing",
        "evidence_ids": list(evidence_ids)[:20],
        "refs": [dict(ref) for ref in refs][:10],
        "note": note,
    }


def _external(address: str | None) -> bool:
    if not address:
        return False
    # Same definition F1 uses for campaign links, so the documentation ranges in synthetic data count as external.
    return is_external_ip(str(address))


def _systems(detail: Mapping[str, Any]) -> tuple[str, list[str]]:
    criticality: dict[str, int] = {}
    evidence: dict[str, str] = {}
    for event in detail["events"]:
        asset = event["asset"]
        criticality[asset] = max(criticality.get(asset, 0), int(event["criticality"]))
        evidence.setdefault(asset, event["id"])
    lines = [f"{asset} (reported criticality {level}/5)" for asset, level in sorted(criticality.items())]
    return "\n".join(lines), [evidence[asset] for asset in sorted(criticality)]


def _accounts(detail: Mapping[str, Any]) -> tuple[str, list[str]]:
    accounts: dict[str, str] = {}
    for event in detail["events"]:
        accounts.setdefault(event["user"], event["id"])
    return ", ".join(sorted(accounts)), [accounts[user] for user in sorted(accounts)]


def _indicators(detail: Mapping[str, Any]) -> tuple[str, list[str]]:
    found: dict[tuple[str, str], str] = {}
    for event in detail["events"]:
        for kind, value in (
            ("source IP", event["source_ip"] if _external(event["source_ip"]) else None),
            ("destination IP", event["destination_ip"] if _external(event["destination_ip"]) else None),
            ("domain", event["domain"]),
            ("file hash", event["file_hash"]),
        ):
            if value:
                found.setdefault((kind, str(value)), event["id"])
    lines = [f"{kind}: {value}" for kind, value in sorted(found)]
    return "\n".join(lines), [found[key] for key in sorted(found)]


def _techniques(detail: Mapping[str, Any]) -> tuple[str, list[str]]:
    techniques = detail["analysis"].get("techniques", [])
    lines = [f"{t['id']} {t['name']}" for t in techniques]
    evidence = [event_id for t in techniques for event_id in t.get("evidence_ids", [])]
    return "\n".join(lines), evidence


def _actions(detail: Mapping[str, Any]) -> tuple[str, list[dict[str, str]]]:
    lines: list[str] = []
    refs: list[dict[str, str]] = []
    for response in detail.get("responses", []):
        if response["status"] == "EXECUTED":
            lines.append(
                f"{response['playbook_name']} (simulated) executed at {response['executed_at']} "
                f"after approval by {response['approved_by']}."
            )
        elif response["status"] in ("PENDING", "APPROVED"):
            lines.append(f"{response['playbook_name']} (simulated) requested and awaiting a decision.")
        else:
            continue
        refs.append({"type": "response", "id": response["id"]})
    for note in detail.get("notes", []):
        if note["kind"] in ("closure", "reopen"):
            lines.append(f"Analyst note ({note['kind']}): {note['text']}")
            refs.append({"type": "note", "id": note["id"]})
    if not lines:
        lines.append("Triage and review in AEGIS; no containment action has been requested yet.")
        refs.append({"type": "incident", "id": detail["id"]})
    return "\n".join(lines), refs


def map_fields(
    detail: Mapping[str, Any],
    template: CertInTemplate,
    *,
    profile: Mapping[str, Any] | None,
    reportability: Mapping[str, Any],
    narrative: Mapping[str, Any] | None,
    human_values: Mapping[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Fill every template field. Human fields keep the values a person already entered."""
    human = dict(human_values or {})
    systems, system_events = _systems(detail)
    accounts, account_events = _accounts(detail)
    indicators, indicator_events = _indicators(detail)
    techniques, technique_events = _techniques(detail)
    actions, action_refs = _actions(detail)
    events = list(detail["events"])
    first_event = events[0]["id"] if events else None
    incident_ref = [{"type": "incident", "id": detail["id"]}]

    computed: dict[str, dict[str, Any]] = {}
    for field in template.fields:
        label = field.label
        if field.id in PROFILE_FIELDS:
            value = str((profile or {}).get(PROFILE_FIELDS[field.id]) or "")
            computed[field.id] = _field(
                field.id,
                label,
                value,
                "profile",
                note=None if value else MISSING_PROFILE,
            )
        elif field.id == "incident_type":
            computed[field.id] = _field(
                field.id,
                label,
                str(reportability["incident_type_label"]),
                "auto",
                refs=incident_ref,
                note=str(reportability["label"]),
            )
        elif field.id == "detected_at":
            computed[field.id] = _field(field.id, label, str(detail["first_detected_at"]), "auto", refs=incident_ref)
        elif field.id == "occurred_at":
            computed[field.id] = _field(
                field.id, label, str(detail["first_seen"]), "auto", evidence_ids=[first_event] if first_event else []
            )
        elif field.id == "affected_systems":
            computed[field.id] = _field(field.id, label, systems, "auto", evidence_ids=system_events)
        elif field.id == "affected_users":
            computed[field.id] = _field(field.id, label, accounts, "auto", evidence_ids=account_events)
        elif field.id == "indicators":
            computed[field.id] = _field(field.id, label, indicators, "auto", evidence_ids=indicator_events)
        elif field.id == "attack_techniques":
            computed[field.id] = _field(
                field.id,
                label,
                techniques,
                "auto",
                evidence_ids=technique_events,
                note=detail["analysis"].get("attack_attribution"),
            )
        elif field.id == "actions_taken":
            computed[field.id] = _field(field.id, label, actions, "auto", refs=action_refs, note=SIMULATED_NOTE)
        elif field.id == "current_status":
            owner = detail.get("owner") or "nobody"
            status = f"{str(detail['status']).replace('_', ' ').title()} in AEGIS, owned by {owner}"
            computed[field.id] = _field(field.id, label, status, "auto", refs=incident_ref)
        elif field.id == "evidence_reference":
            reference = (
                f"AEGIS incident {detail['id']} (revision {detail['revision']}), {detail['event_count']} correlated "
                f"events between {detail['first_seen']} and {detail['last_seen']}"
            )
            computed[field.id] = _field(field.id, label, reference, "auto", refs=incident_ref)
        elif field.id == "description":
            text = str((narrative or {}).get("description") or "")
            computed[field.id] = _field(
                field.id,
                label,
                human.get(field.id) or text,
                "human" if human.get(field.id) else str((narrative or {}).get("provenance", "ai")),
                evidence_ids=list((narrative or {}).get("evidence_ids") or []),
                note=str((narrative or {}).get("note") or "") or None,
            )
        else:
            computed[field.id] = _field(field.id, label, human.get(field.id, ""), "human")
        value = computed[field.id]["value"]
        if len(value) > field.max_length:
            computed[field.id]["value"] = value[: field.max_length]
            computed[field.id]["note"] = f"Trimmed to {field.max_length} characters."
    return computed


def missing_required(fields: Mapping[str, Mapping[str, Any]], template: CertInTemplate) -> list[str]:
    return [field.id for field in template.fields if field.required and not str(fields.get(field.id, {}).get("value"))]


def completeness(fields: Mapping[str, Mapping[str, Any]], template: CertInTemplate) -> dict[str, Any]:
    required = [field.id for field in template.fields if field.required]
    filled = [field_id for field_id in required if str(fields.get(field_id, {}).get("value"))]
    automatic = [
        field.id
        for field in template.fields
        if field.source in ("auto", "ai") and str(fields.get(field.id, {}).get("value"))
    ]
    expected_automatic = [field.id for field in template.fields if field.source in ("auto", "ai")]
    return {
        "required_total": len(required),
        "required_filled": len(filled),
        "missing_required": [field_id for field_id in required if field_id not in filled],
        "automatic_total": len(expected_automatic),
        "automatic_filled": len(automatic),
        "ready_for_review": len(filled) == len(required),
    }
