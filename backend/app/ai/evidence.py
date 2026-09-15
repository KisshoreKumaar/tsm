"""Compact, token-budgeted evidence packs with event aliases (E1…En) and optional reversible redaction.

Event content is untrusted: it is serialised as JSON inside a delimited <data> block and never as instructions.
Aliases keep prompts short for small models; the server maps them back to real event IDs when validating output.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.ai.providers.base import estimate_tokens

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Candidates only; each match is confirmed with ipaddress so clock times such as 08:58:13 are left alone.
IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")


def _is_ipv6(candidate: str) -> bool:
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True


class Redactor:
    """Replaces usernames, emails and IP addresses with stable tokens; `restore` maps them back server-side."""

    def __init__(self, users: Iterable[str] = ()) -> None:
        self._forward: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._users = sorted({u for u in users if u}, key=len, reverse=True)

    def _token(self, kind: str, value: str) -> str:
        key = value.lower() if kind in ("USER", "EMAIL") else value
        if key not in self._forward:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            self._forward[key] = f"{kind}_{self._counters[kind]}"
        return self._forward[key]

    def redact(self, text: str) -> str:
        text = EMAIL_RE.sub(lambda m: self._token("EMAIL", m.group(0)), text)

        def ipv6(match: re.Match[str]) -> str:
            value = match.group(0)
            return self._token("IP", value) if _is_ipv6(value) else value

        text = IPV6_CANDIDATE_RE.sub(ipv6, text)
        text = IPV4_RE.sub(lambda m: self._token("IP", m.group(0)), text)
        for user in self._users:
            token = self._token("USER", user)
            text = re.sub(rf"(?<![\w-]){re.escape(user)}(?![\w-])", token, text, flags=re.IGNORECASE)
        return text

    def restore(self, text: str) -> str:
        reverse = {token: original for original, token in self._forward.items()}
        return re.sub(r"\b(?:USER|EMAIL|IP)_\d+\b", lambda m: reverse.get(m.group(0), m.group(0)), text)

    def redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, list):
            return [self.redact_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self.redact_value(v) for k, v in value.items()}
        return value

    @property
    def mapping_size(self) -> int:
        return len(self._forward)


def _clip(value: Any, limit: int) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def event_row(alias: str, event: Mapping[str, Any]) -> list[Any]:
    """[alias, time, kind, asset, user, compact fields] — compact arrays cost far fewer tokens than objects."""
    fields: list[str] = []
    if event.get("source_ip"):
        fields.append(f"src={event['source_ip']}")
    if event.get("destination_ip"):
        fields.append(f"dst={event['destination_ip']}:{event.get('destination_port') or ''}".rstrip(":"))
    if event.get("domain"):
        fields.append(f"domain={event['domain']}")
    if event.get("process_name"):
        fields.append(f"proc={_clip(event['process_name'], 60)}")
    if event.get("command_line"):
        fields.append(f"cmd={_clip(event['command_line'], 120)}")
    if event.get("file_path"):
        fields.append(f"file={_clip(event['file_path'], 80)}")
    if event.get("file_hash"):
        fields.append(f"hash={str(event['file_hash'])[:16]}")
    if event.get("privileged"):
        fields.append("privileged")
    if event.get("injection_suspected"):
        fields.append("INJECTION_SUSPECTED")
    if event.get("details"):
        fields.append(f"details={_clip(event['details'], 100)}")
    return [alias, str(event["timestamp"])[11:19], event["kind"], event["asset"], event["user"], " ".join(fields)]


@dataclass
class EvidencePack:
    data: dict[str, Any]
    alias_to_event: dict[str, str]
    redactor: Redactor | None = None
    injection_suspected: bool = False
    omitted_events: int = 0
    event_to_alias: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.event_to_alias = {event: alias for alias, event in self.alias_to_event.items()}

    def data_block(self) -> str:
        return "<data>\n" + json.dumps(self.data, separators=(",", ":"), ensure_ascii=False) + "\n</data>"

    @property
    def tokens(self) -> int:
        return estimate_tokens(self.data_block())

    def resolve(self, aliases: Iterable[str]) -> tuple[list[str], list[str]]:
        valid: list[str] = []
        invalid: list[str] = []
        for alias in aliases:
            key = str(alias).strip().upper()
            if key in self.alias_to_event:
                event_id = self.alias_to_event[key]
                if event_id not in valid:
                    valid.append(event_id)
            else:
                invalid.append(str(alias)[:20])
        return valid, invalid

    def restore(self, text: str) -> str:
        return self.redactor.restore(text) if self.redactor is not None else text

    def add_events(self, events: Sequence[Mapping[str, Any]]) -> list[list[Any]]:
        """Assign aliases to newly seen events (used by tool-calling loops). Returns their compact rows."""
        rows = []
        for event in events:
            if event["id"] in self.event_to_alias:
                alias = self.event_to_alias[event["id"]]
            else:
                alias = f"E{len(self.alias_to_event) + 1}"
                self.alias_to_event[alias] = event["id"]
                self.event_to_alias[event["id"]] = alias
            if event.get("injection_suspected"):
                self.injection_suspected = True
            row = event_row(alias, event)
            rows.append(self.redactor.redact_value(row) if self.redactor is not None else row)
        return rows


def _priority_order(detail: Mapping[str, Any]) -> list[str]:
    events = detail["events"]
    ordered: list[str] = []
    for detection in detail.get("detections", []):
        if detection.get("status") != "ACTIVE" or not detection["event_ids"]:
            continue
        for event_id in (detection["event_ids"][0], detection["event_ids"][-1]):
            if event_id not in ordered:
                ordered.append(event_id)
    for event in events:
        if event.get("injection_suspected") and event["id"] not in ordered:
            ordered.append(event["id"])
    for event in events:
        if event["id"] not in ordered:
            ordered.append(event["id"])
    return ordered


def build_incident_pack(detail: Mapping[str, Any], *, budget_tokens: int, redact: bool) -> EvidencePack:
    events_by_id = {e["id"]: e for e in detail["events"]}
    redactor = Redactor(users={e["user"] for e in detail["events"]} | {detail["user"]}) if redact else None
    analysis = detail["analysis"]
    header: dict[str, Any] = {
        "incident": {
            "title": detail["title"],
            "status": detail["status"],
            "severity": detail["severity"],
            "risk_heuristic": detail["risk_score"],
            "asset": detail["asset"],
            "user": detail["user"],
            "first_seen": detail["first_seen"][:19],
            "last_seen": detail["last_seen"][:19],
            "event_count": detail["event_count"],
        },
        "stages": [[s["stage"], s["rule_ids"], s["first_ts"][11:19]] for s in analysis.get("stages", [])],
        "techniques": [f"{t['id']} {t['name']}" for t in analysis.get("techniques", [])],
        "rule_claims": [[c["label"], c["text"]] for c in analysis.get("claims", [])[:6]],
        "responses": [[r["playbook"], r["status"]] for r in detail.get("responses", [])[:5]],
        "events": [],
    }
    if redactor is not None:
        header = redactor.redact_value(header)
    pack = EvidencePack(data=header, alias_to_event={}, redactor=redactor)
    chosen: list[str] = []
    for event_id in _priority_order(detail):
        trial = [*chosen, event_id]
        rows = [event_row("E00", events_by_id[i]) for i in trial]
        if redactor is not None:
            rows = redactor.redact_value(rows)
        size = estimate_tokens(json.dumps({**header, "events": rows}, separators=(",", ":"), ensure_ascii=False))
        if size > budget_tokens and chosen:
            break
        chosen.append(event_id)
    chronological = sorted(chosen, key=lambda i: (events_by_id[i]["timestamp"], i))
    pack.data["events"] = pack.add_events([events_by_id[i] for i in chronological])
    pack.omitted_events = len(detail["events"]) - len(chosen)
    if pack.omitted_events:
        pack.data["omitted_events"] = pack.omitted_events
    pack.injection_suspected = pack.injection_suspected or bool(analysis.get("injection", {}).get("suspected"))
    return pack
