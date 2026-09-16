"""CERT-In draft exports (I1): Markdown, JSON and print-friendly HTML, with an optional redaction pass.

Exports are files a human sends through the official channel. AEGIS never transmits them.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTION_NOTE = "Personal data was redacted in this export; the unredacted draft stays in AEGIS."
REDACTED_FIELDS = frozenset({"contact_email", "contact_phone", "affected_users", "reporter_notes", "description"})
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(r"(?<!\d)(\+?\d[\d\s-]{6,}\d)(?!\d)")


def _mask_word(word: str) -> str:
    return word if len(word) <= 1 else f"{word[0]}{'*' * (len(word) - 1)}"


def redact(text: str) -> str:
    masked = _EMAIL_RE.sub(lambda m: f"{m.group(1)}***{m.group(2)}", text)
    masked = _PHONE_RE.sub(lambda m: f"{m.group(1)[:3]}*******", masked)
    return masked


def redact_field(field_id: str, value: str) -> str:
    if field_id not in REDACTED_FIELDS or not value:
        return value
    if field_id == "affected_users":
        return ", ".join(_mask_word(part.strip()) for part in value.split(",") if part.strip())
    return redact(value)


def _values(report: Mapping[str, Any], *, redacted: bool) -> list[dict[str, Any]]:
    fields: Sequence[Mapping[str, Any]] = report["fields"]
    rendered = []
    for field in fields:
        value = str(field["value"])
        rendered.append({**field, "value": redact_field(str(field["id"]), value) if redacted else value})
    return rendered


def render_markdown(report: Mapping[str, Any], *, redacted: bool = False) -> str:
    lines = [
        f"# CERT-In incident report draft — {report['incident_id'][:8]}",
        "",
        f"> {report['template']['banner'] or 'Template verified: ' + str(report['template']['verified_against'])}",
        f"> Status in AEGIS: **{report['status']}**. Reporting deadline: {report['deadline']['deadline_utc']} UTC "
        f"({report['deadline']['deadline_ist']} IST).",
        f"> {report['reportability']['label']}",
    ]
    if redacted:
        lines.append(f"> {REDACTION_NOTE}")
    lines.append("")
    for field in _values(report, redacted=redacted):
        lines.append(f"## {field['label']}")
        lines.append(field["value"] or "_Not filled in_")
        provenance = f"_Source: {field['provenance']}_"
        if field["evidence_ids"]:
            provenance += f" · evidence: {', '.join(field['evidence_ids'][:10])}"
        if field["note"]:
            provenance += f" · {field['note']}"
        lines += ["", provenance, ""]
    lines += [
        "---",
        "",
        "Prepared with AEGIS SOC from synthetic or authorised lab data. AEGIS does not submit reports; a human files "
        "this through the official CERT-In channel after review.",
    ]
    return "\n".join(lines) + "\n"


def render_json(report: Mapping[str, Any], *, redacted: bool = False) -> dict[str, Any]:
    return {
        "format": "aegis-cert-in-draft",
        "format_version": 1,
        "redacted": redacted,
        "incident_id": report["incident_id"],
        "status": report["status"],
        "template": report["template"],
        "deadline": report["deadline"],
        "reportability": report["reportability"],
        "completeness": report["completeness"],
        "fields": _values(report, redacted=redacted),
        "note": "AEGIS never transmits reports. A human reviews and files this draft.",
    }


def render_html(report: Mapping[str, Any], *, redacted: bool = False) -> str:
    def escape(value: Any) -> str:
        return html.escape(str(value))

    sections = []
    for field in _values(report, redacted=redacted):
        provenance = f"Source: {field['provenance']}"
        if field["evidence_ids"]:
            provenance += f" · evidence: {', '.join(field['evidence_ids'][:10])}"
        if field["note"]:
            provenance += f" · {field['note']}"
        sections.append(
            f"<section><h2>{escape(field['label'])}</h2>"
            f"<p class='value'>{escape(field['value']) or '<em>Not filled in</em>'}</p>"
            f"<p class='provenance'>{escape(provenance)}</p></section>"
        )
    banner = report["template"]["banner"] or "Template verified"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>CERT-In draft {escape(report['incident_id'][:8])}</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:44rem;color:#111}"
        "h1{font-size:1.4rem}h2{font-size:1rem;margin-bottom:.2rem}"
        ".value{white-space:pre-wrap;margin:.2rem 0}.provenance{color:#555;font-size:.8rem;margin-top:0}"
        ".banner{border:1px solid #b45309;background:#fef3c7;padding:.6rem;border-radius:6px}"
        "@media print{.banner{border-color:#000;background:none}}</style></head><body>"
        f"<h1>CERT-In incident report draft — {escape(report['incident_id'][:8])}</h1>"
        f"<p class='banner'>{escape(banner)}<br>{escape(report['reportability']['label'])}"
        + (f"<br>{escape(REDACTION_NOTE)}" if redacted else "")
        + "</p>"
        f"<p>Status in AEGIS: <strong>{escape(report['status'])}</strong>. Deadline "
        f"{escape(report['deadline']['deadline_utc'])} UTC ({escape(report['deadline']['deadline_ist'])} IST).</p>"
        + "".join(sections)
        + "<hr><p>Prepared with AEGIS SOC. AEGIS does not submit reports; a human files this after review.</p>"
        "</body></html>"
    )
