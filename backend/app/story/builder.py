"""Deterministic alert story.

Built from the incident detail (events, detections, analysis, responses). Stages follow the earliest evidence time.
Every sentence carries a claim label; event-based FACT sentences cite at least one event ID. Statements about AEGIS's
own workflow records (status, responses) use `basis: "aegis_records"` and reference those records instead. Untrusted
text taken from events is only ever shown inside typographic quotation marks.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.ai.injection import scan_text

ANALYST_MIN_WORDS = 150
ANALYST_MAX_WORDS = 300
MAX_CITATIONS = 25
QUOTED_RE = re.compile(r"“[^”]*”")

PLAIN_ACTIONS = {
    "AUTH-001": "repeated password guessing",
    "AUTH-002": "a successful login right after the failures",
    "PROC-001": "a hidden (encoded) PowerShell command",
    "NET-001": "probing of many other systems",
    "FILE-001": "a burst of file changes typical of ransomware",
    "LOG-001": "clearing of the security log",
    "ACCT-001": "account creation or privilege changes",
    "INJ-001": "log text written to mislead AI tools",
    "SOURCE-001": "a suspicious-process alert from another security tool",
    "SOURCE-002": "a malicious-indicator report from another security tool",
}
EXECUTIVE_LINES = (
    ("what_happened", "What happened"),
    ("impact", "Impact"),
    ("contained", "Contained?"),
    ("actions", "What we are doing"),
    ("needs", "What we need"),
)


@dataclass
class Sentence:
    label: str
    text: str
    evidence_ids: list[str] = field(default_factory=list)
    basis: str = "events"
    refs: list[dict[str, str]] = field(default_factory=list)
    id: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "text": self.text,
            "evidence_ids": list(self.evidence_ids),
            "basis": self.basis,
            "refs": list(self.refs),
        }


def quote(text: str | None, limit: int = 100) -> str:
    cleaned = " ".join((text or "").split()).replace("“", '"').replace("”", '"')
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return f"“{cleaned}”"


def safe(value: str | None) -> str:
    """Identifiers appear as-is unless they contain instruction-like text, in which case they are quoted."""
    if not value:
        return "an unknown value"
    return quote(value, 60) if scan_text(value) else value


def clock(timestamp: str | None) -> str:
    return f"{timestamp[11:19]} UTC" if timestamp else "an unknown time"


def stamp(timestamp: str | None) -> str:
    return f"{timestamp[:10]} {timestamp[11:19]} UTC" if timestamp else "an unknown time"


def word_count(text: str) -> int:
    return len(re.findall(r"\S+", text))


def join_phrases(phrases: Sequence[str]) -> str:
    if not phrases:
        return ""
    if len(phrases) == 1:
        return phrases[0]
    return ", ".join(phrases[:-1]) + " and " + phrases[-1]


def _ordered_unique(ids: Iterable[str], order: Mapping[str, int]) -> list[str]:
    return sorted(set(ids), key=lambda eid: order.get(eid, len(order)))[:MAX_CITATIONS]


def describe_detection(detection: Mapping[str, Any], events_by_id: Mapping[str, Mapping[str, Any]]) -> Sentence:
    evidence = [events_by_id[eid] for eid in detection["event_ids"] if eid in events_by_id]
    ids = [e["id"] for e in evidence]
    if not evidence:
        return Sentence("FACT", detection["summary"], list(detection["event_ids"])[:MAX_CITATIONS])
    first, last = evidence[0], evidence[-1]
    details = detection.get("details") or {}
    rule = detection["rule_id"]
    asset, user = safe(first["asset"]), safe(first["user"])
    if rule == "AUTH-001":
        text = (
            f"Between {clock(first['timestamp'])} and {clock(last['timestamp'])}, {details.get('failures', len(evidence))} "
            f"logins for {user} on {asset} failed from {safe(details.get('source_ip')) if details.get('source_ip') else 'an unknown address'}."
        )
    elif rule == "AUTH-002":
        success = next((e for e in evidence if e["kind"] == "auth_success"), last)
        text = (
            f"At {clock(success['timestamp'])}, a login for {user} on {asset} succeeded from "
            f"{safe(success.get('source_ip')) if success.get('source_ip') else 'an unknown address'} "
            f"after {details.get('failures', len(evidence) - 1)} failed attempts."
        )
    elif rule == "PROC-001":
        flags = ", ".join(details.get("flags") or ["-EncodedCommand"])
        times = details.get("executions", len(evidence))
        text = f"At {clock(first['timestamp'])}, {user} ran PowerShell with an encoded command ({flags}) on {asset}" + (
            f", {times} times in total." if times > 1 else "."
        )
    elif rule == "NET-001":
        ports = ", ".join(str(p) for p in (details.get("ports") or [])[:6]) or "several ports"
        text = (
            f"Between {clock(first['timestamp'])} and {clock(last['timestamp'])}, {asset} contacted "
            f"{details.get('distinct_targets', len(evidence))} distinct destinations on port(s) {ports}."
        )
    elif rule == "FILE-001":
        sample = (details.get("sample_paths") or [None])[0]
        text = (
            f"Between {clock(first['timestamp'])} and {clock(last['timestamp'])}, {details.get('changes', len(evidence))} "
            f"files changed on {asset}" + (f", for example {quote(sample, 80)}." if sample else ".")
        )
    elif rule == "LOG-001":
        text = f"At {clock(first['timestamp'])}, the security log on {asset} was cleared by {user}."
    elif rule == "ACCT-001":
        label = (
            "a new account was created" if details.get("kind") == "user_created" else "account privileges were changed"
        )
        text = f"At {clock(first['timestamp'])}, {label} on {asset} by {user}."
    elif rule == "INJ-001":
        flagged = next((e for e in evidence if e.get("injection_suspected")), first)
        snippet = flagged.get("details") or flagged.get("command_line") or ""
        text = (
            f"{len(evidence)} event(s) on {asset} contain text addressed to an AI assistant, for example {quote(snippet, 90)}. "
            "AEGIS treats this text strictly as data."
        )
    elif rule in ("SOURCE-001", "SOURCE-002"):
        reported = "a suspicious process" if rule == "SOURCE-001" else "a malicious indicator"
        indicator = (
            first.get("process_name") or first.get("destination_ip") or first.get("domain") or first.get("file_hash")
        )
        sources = ", ".join(sorted({safe(e["source"]) for e in evidence}))
        text = (
            f"At {clock(first['timestamp'])}, {sources} reported {reported} on {asset}"
            + (f" ({safe(indicator)})" if indicator else "")
            + "; AEGIS has not verified this verdict."
        )
    else:
        text = detection["summary"]
    return Sentence("FACT", text, ids[:MAX_CITATIONS])


def _number(sentences: Iterable[Sentence], prefix: str) -> None:
    for index, sentence in enumerate(sentences, start=1):
        sentence.id = f"{prefix}{index}"


def _evidence_index(
    sentences: Iterable[Sentence], events_by_id: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    index: list[dict[str, Any]] = []
    seen: set[str] = set()
    for sentence in sentences:
        for event_id in sentence.evidence_ids:
            if event_id in seen or event_id not in events_by_id:
                continue
            seen.add(event_id)
            event = events_by_id[event_id]
            index.append(
                {
                    "ref": f"E{len(index) + 1}",
                    "event_id": event_id,
                    "timestamp": event["timestamp"],
                    "kind": event["kind"],
                    "asset": event["asset"],
                    "source": event["source"],
                }
            )
    return index


def validate_citations(sentences: Iterable[Mapping[str, Any]], valid_event_ids: set[str]) -> list[str]:
    problems = []
    for sentence in sentences:
        invalid = [eid for eid in sentence.get("evidence_ids", []) if eid not in valid_event_ids]
        if invalid:
            problems.append(f"{sentence.get('id')}: cites unknown evidence {invalid[:3]}")
        if (
            sentence.get("label") == "FACT"
            and sentence.get("basis", "events") == "events"
            and not sentence.get("evidence_ids")
        ):
            problems.append(f"{sentence.get('id')}: FACT without evidence")
        if sentence.get("label") not in ("FACT", "INFERENCE", "HYPOTHESIS", "UNKNOWN"):
            problems.append(f"{sentence.get('id')}: invalid label")
    return problems


def all_sentences(story: Mapping[str, Any]) -> list[dict[str, Any]]:
    sentences = [line["sentence"] for line in story["executive"]["lines"]]
    for paragraph in story["analyst"]["paragraphs"]:
        sentences.extend(paragraph)
    return sentences


def build_incident_story(detail: Mapping[str, Any], generated_at: str) -> dict[str, Any]:
    events = list(detail["events"])
    events_by_id = {e["id"]: e for e in events}
    order = {e["id"]: index for index, e in enumerate(events)}
    active = [d for d in detail["detections"] if d["status"] == "ACTIVE"]
    detections_by_id = {d["id"]: d for d in active}
    analysis = detail["analysis"]
    asset, user = safe(detail["asset"]), safe(detail["user"])

    # -- stages ------------------------------------------------------------------------------------------
    stages: list[dict[str, Any]] = []
    stage_sentences: list[Sentence] = []
    for stage in analysis["stages"]:
        members = sorted(
            (detections_by_id[i] for i in stage["detection_ids"] if i in detections_by_id),
            key=lambda d: (d["first_ts"], d["rule_id"]),
        )
        parts = [describe_detection(d, events_by_id) for d in members]
        if not parts:
            continue
        sentence = Sentence(
            "FACT", " ".join(p.text for p in parts), _ordered_unique((i for p in parts for i in p.evidence_ids), order)
        )
        stage_sentences.append(sentence)
        stages.append(
            {
                "stage": stage["stage"],
                "is_tactic": stage["is_tactic"],
                "first_ts": stage["first_ts"],
                "last_ts": stage["last_ts"],
                "rule_ids": stage["rule_ids"],
                "techniques": [{"id": t["id"], "name": t["name"], "url": t["url"]} for t in stage["techniques"]],
                "event_ids": stage["event_ids"][:MAX_CITATIONS],
                "sentence": sentence,
            }
        )

    # -- analyst narrative ---------------------------------------------------------------------------------
    sources = ", ".join(safe(s) for s in analysis.get("sources", []))
    opening = Sentence(
        "FACT",
        f"This incident on {asset} involves {user} and {detail['event_count']} correlated events from {sources or 'unknown sources'}, "
        f"recorded between {stamp(detail['first_seen'])} and {stamp(detail['last_seen'])}.",
        [i for i in (events[0]["id"], events[-1]["id"]) if events] if events else [],
    )
    techniques = analysis.get("techniques", [])
    technique_sentence = (
        Sentence(
            "INFERENCE",
            "Candidate ATT&CK techniques from the rule logic are "
            + join_phrases([f"{t['id']} {t['name']}" for t in techniques])
            + "; an analyst should confirm each mapping.",
            _ordered_unique((i for t in techniques for i in t.get("evidence_ids", [])), order),
        )
        if techniques
        else Sentence("INFERENCE", "No ATT&CK technique is assumed for this incident.", [])
    )
    claims = analysis.get("claims", [])
    inferences = [
        Sentence("INFERENCE", c["text"], list(c["evidence_ids"])) for c in claims if c["label"] == "INFERENCE"
    ]
    hypotheses = [
        Sentence("HYPOTHESIS", c["text"], list(c["evidence_ids"])) for c in claims if c["label"] == "HYPOTHESIS"
    ]
    unknowns = [Sentence("UNKNOWN", c["text"], list(c["evidence_ids"])) for c in claims if c["label"] == "UNKNOWN"]
    risk = detail["risk"]
    risk_sentence = Sentence(
        "INFERENCE",
        f"AEGIS rates the risk {risk['score']}/100 ({risk['severity']}); this heuristic ranks attention and is not a probability.",
        [],
    )
    responses = list(detail.get("responses", []))
    executed = [r for r in responses if r["status"] == "EXECUTED"]
    pending = [r for r in responses if r["status"] in ("PENDING", "APPROVED")]
    owner = detail.get("owner")
    status_text = f"The incident is {detail['status'].replace('_', ' ')}" + (
        f" and owned by {safe(owner)}" if owner else " and unassigned"
    )
    if executed:
        latest = executed[0]
        status_text += f"; {latest['playbook_name']} ran at {clock(latest['executed_at'])} after approval by {safe(latest['approved_by'])}"
    elif pending:
        status_text += f"; {len(pending)} simulated response request(s) await a decision"
    else:
        status_text += "; no response action has been requested"
    status_refs = [{"type": "response", "id": r["id"]} for r in (executed + pending)[:5]] or [
        {"type": "incident", "id": detail["id"]}
    ]
    status_sentence = Sentence("FACT", status_text + ".", [], basis="aegis_records", refs=status_refs)
    next_steps = Sentence(
        "INFERENCE",
        f"Recommended next steps: confirm with the owner of {asset} whether this activity was authorised, review the cited "
        "evidence, and request simulated containment only if compromise is confirmed.",
        [],
    )

    paragraphs: list[list[Sentence]] = [
        [opening, *stage_sentences],
        [technique_sentence, *inferences, *hypotheses, risk_sentence],
        [status_sentence, *unknowns, next_steps],
    ]

    def total_words() -> int:
        return sum(word_count(s.text) for p in paragraphs for s in p)

    if total_words() < ANALYST_MIN_WORDS:
        for detection in sorted(active, key=lambda d: (d["first_ts"], d["rule_id"])):
            paragraphs[0].append(
                Sentence(
                    "FACT",
                    f"Rule {detection['rule_id']} ({detection['rule_name']}) matched {len(detection['event_ids'])} event(s) "
                    f"between {clock(detection['first_ts'])} and {clock(detection['last_ts'])}.",
                    _ordered_unique(detection["event_ids"], order),
                )
            )
            if total_words() >= ANALYST_MIN_WORDS:
                break
    if total_words() < ANALYST_MIN_WORDS:
        paragraphs[2].append(
            Sentence(
                "UNKNOWN",
                "AEGIS has no endpoint process tree, identity-provider context or threat-intelligence verdict for these "
                "events, so the analyst should gather that context before deciding whether the activity is malicious.",
            )
        )
    while total_words() > ANALYST_MAX_WORDS and len(paragraphs[1]) > 2:
        paragraphs[1].pop(1)  # drop lower-priority inferences first; facts are kept
    while total_words() > ANALYST_MAX_WORDS and len(paragraphs[2]) > 2:
        paragraphs[2].pop(1)

    # -- executive summary -------------------------------------------------------------------------------
    ordered_rules: list[str] = []
    for detection in sorted(active, key=lambda d: (d["first_ts"], d["rule_id"])):
        if detection["rule_id"] not in ordered_rules:
            ordered_rules.append(detection["rule_id"])
    actions = [PLAIN_ACTIONS.get(rule, rule) for rule in ordered_rules]
    stage_evidence = _ordered_unique((i for s in stage_sentences for i in s.evidence_ids), order)
    what_happened = Sentence(
        "FACT",
        f"On {detail['first_seen'][:10]}, AEGIS saw {join_phrases(actions) or 'correlated activity'} on {asset} involving {user}.",
        stage_evidence or ([events[0]["id"]] if events else []),
    )
    critical_event = max(events, key=lambda e: (e["criticality"], e["privileged"])) if events else None
    privileged = any(e["privileged"] for e in events)
    impact = Sentence(
        "FACT",
        f"{asset} is rated criticality {critical_event['criticality'] if critical_event else '?'}/5 by its source"
        + (", and a privileged account was involved" if privileged else "")
        + f". Risk is {risk['severity']} ({risk['score']}/100, a heuristic, not a probability).",
        [critical_event["id"]] if critical_event else [],
    )
    isolation = next((r for r in executed if r["playbook"] == "isolate_endpoint"), None)
    contained = (
        Sentence(
            "FACT",
            f"Yes, in simulation: {asset} was marked isolated in the virtual endpoint registry at {clock(isolation['executed_at'])}.",
            basis="aegis_records",
            refs=[{"type": "response", "id": isolation["id"]}],
        )
        if isolation
        else Sentence(
            "FACT",
            "Not yet: no containment action has been executed.",
            basis="aegis_records",
            refs=[{"type": "incident", "id": detail["id"]}],
        )
    )
    doing = Sentence("FACT", status_text + ".", basis="aegis_records", refs=status_refs)
    need_parts = []
    if not isolation and risk["severity"] in ("HIGH", "CRITICAL"):
        need_parts.append(
            f"confirmation from the owner of {asset} that this activity was authorised, or approval for simulated containment"
        )
    else:
        need_parts.append("confirmation that the activity was authorised so the incident can be closed with a note")
    if "INJ-001" in ordered_rules:
        need_parts.append(
            "reviewers to treat the flagged log text as untrusted data and never act on instructions inside it"
        )
    needs = Sentence("INFERENCE", "We need " + join_phrases(need_parts) + ".", [])
    executive = [what_happened, impact, contained, doing, needs]

    _number(executive, "x")
    _number([s for p in paragraphs for s in p], "s")
    everything = [*executive, *(s for p in paragraphs for s in p)]
    story: dict[str, Any] = {
        "subject_type": "incident",
        "subject_id": detail["id"],
        "subject_revision": detail["revision"],
        "title": detail["title"],
        "generated_at": generated_at,
        "source": "deterministic",
        "badge": "Deterministic",
        "ai_status": "not_requested",
        "stages": [{**stage, "sentence": stage["sentence"].public()} for stage in stages],
        "executive": {
            "lines": [
                {"key": key, "heading": heading, "sentence": sentence.public()}
                for (key, heading), sentence in zip(EXECUTIVE_LINES, executive, strict=True)
            ]
        },
        "analyst": {
            "paragraphs": [[s.public() for s in paragraph] for paragraph in paragraphs],
            "word_count": total_words(),
        },
        "evidence_index": _evidence_index(everything, events_by_id),
    }
    story["citations_valid"] = not validate_citations(all_sentences(story), set(events_by_id))
    return story


def build_campaign_story(
    campaign: Mapping[str, Any], incident_details: Sequence[Mapping[str, Any]], generated_at: str
) -> dict[str, Any]:
    events_by_id: dict[str, Mapping[str, Any]] = {}
    for detail in incident_details:
        events_by_id.update({e["id"]: e for e in detail["events"]})
    order = {eid: index for index, eid in enumerate(sorted(events_by_id, key=lambda i: events_by_id[i]["timestamp"]))}
    links = campaign.get("links", [])
    reasons = []
    for link in links:
        reason = f"shared {link['entity_type'].replace('_', ' ')} {safe(link['entity_value'])}"
        if reason not in reasons:
            reasons.append(reason)
    link_evidence = _ordered_unique((i for link in links for i in link["supporting_event_ids"]), order)
    assets = [safe(a) for a in campaign["assets"]]
    opening = Sentence(
        "FACT",
        f"{campaign['incident_count']} incidents on {join_phrases(assets)} are linked by {join_phrases(reasons) or 'shared entities'}, "
        f"with activity between {stamp(campaign['first_seen'])} and {stamp(campaign['last_seen'])}.",
        link_evidence,
    )
    paragraphs: list[list[Sentence]] = [[opening]]
    for link in links:
        paragraphs[0].append(
            Sentence(
                "FACT",
                f"The incidents on {safe(link.get('asset_a'))} and {safe(link.get('asset_b'))} share "
                f"{link['entity_type'].replace('_', ' ')} {safe(link['entity_value'])}; their activity is "
                f"{'overlapping' if link['time_delta_seconds'] <= 0 else str(link['time_delta_seconds'] // 60) + ' min apart'} "
                f"(link strength {link['strength']}).",
                _ordered_unique(link["supporting_event_ids"], order),
            )
        )
    what_parts: list[Sentence] = []
    for detail in sorted(incident_details, key=lambda d: d["first_seen"]):
        story = build_incident_story(detail, generated_at)
        section = [
            Sentence(
                "FACT",
                f"On {safe(detail['asset'])} ({safe(detail['user'])}), between {clock(detail['first_seen'])} and {clock(detail['last_seen'])}:",
                [detail["events"][0]["id"]] if detail["events"] else [],
            )
        ]
        section.extend(
            Sentence(s["sentence"]["label"], s["sentence"]["text"], list(s["sentence"]["evidence_ids"]))
            for s in story["stages"]
        )
        paragraphs.append(section)
        what = story["executive"]["lines"][0]["sentence"]
        what_parts.append(Sentence("FACT", what["text"], list(what["evidence_ids"])))
    hypothesis = Sentence(
        "HYPOTHESIS",
        "The same actor may be moving between these assets; the shared entities could also reflect a legitimate shared "
        "account or service.",
        link_evidence,
    )
    paragraphs.append([hypothesis])
    what_happened = Sentence(
        "FACT",
        " ".join(p.text for p in what_parts)[:600] or opening.text,
        _ordered_unique((i for p in what_parts for i in p.evidence_ids), order) or link_evidence,
    )
    impact = Sentence(
        "FACT",
        f"{len(assets)} assets and {len(campaign['users'])} account(s) are involved; campaign risk is {campaign['severity']} "
        f"({campaign['risk_score']}/100, a heuristic, not a probability).",
        link_evidence[:5],
    )
    isolated = sum(
        1
        for detail in incident_details
        for r in detail.get("responses", [])
        if r["status"] == "EXECUTED" and r["playbook"] == "isolate_endpoint"
    )
    contained = Sentence(
        "FACT",
        f"{isolated} of {len(assets)} assets have been isolated in simulation."
        if isolated
        else "Not yet: no asset has been isolated.",
        basis="aegis_records",
        refs=[{"type": "campaign", "id": campaign["id"]}],
    )
    statuses = sorted({d["status"] for d in incident_details})
    doing = Sentence(
        "FACT",
        f"Member incidents are {join_phrases([s.replace('_', ' ') for s in statuses])}.",
        basis="aegis_records",
        refs=[{"type": "incident", "id": d["id"]} for d in incident_details][:5],
    )
    needs = Sentence(
        "INFERENCE",
        "We need the owners of the affected assets to confirm whether the shared account or address is authorised, and a "
        "decision on simulated containment for the highest-risk hosts.",
    )
    executive = [what_happened, impact, contained, doing, needs]
    _number(executive, "x")
    _number([s for p in paragraphs for s in p], "s")
    everything = [*executive, *(s for p in paragraphs for s in p)]
    story_out: dict[str, Any] = {
        "subject_type": "campaign",
        "subject_id": campaign["id"],
        "subject_revision": campaign["revision"],
        "title": campaign["title"],
        "generated_at": generated_at,
        "source": "deterministic",
        "badge": "Deterministic",
        "ai_status": "not_requested",
        "stages": [],
        "executive": {
            "lines": [
                {"key": key, "heading": heading, "sentence": sentence.public()}
                for (key, heading), sentence in zip(EXECUTIVE_LINES, executive, strict=True)
            ]
        },
        "analyst": {
            "paragraphs": [[s.public() for s in paragraph] for paragraph in paragraphs],
            "word_count": sum(word_count(s.text) for p in paragraphs for s in p),
        },
        "evidence_index": _evidence_index(everything, events_by_id),
    }
    story_out["citations_valid"] = not validate_citations(all_sentences(story_out), set(events_by_id))
    return story_out


def render_markdown(story: Mapping[str, Any], fmt: str = "full") -> str:
    refs = {item["event_id"]: item["ref"] for item in story["evidence_index"]}

    def cite(sentence: Mapping[str, Any]) -> str:
        cited = ", ".join(refs.get(eid, eid[:8]) for eid in sentence["evidence_ids"][:8])
        extra = f", +{len(sentence['evidence_ids']) - 8}" if len(sentence["evidence_ids"]) > 8 else ""
        if sentence["basis"] == "aegis_records":
            return f" _[{sentence['label']}; AEGIS records]_"
        return f" _[{sentence['label']}{': ' + cited + extra if cited else ''}]_"

    lines = [
        f"# {story['subject_type'].title()} story: {story['title']}",
        "",
        f"_{story['badge']} story generated {story['generated_at']} for revision {story['subject_revision']}. "
        "Claim labels: FACT, INFERENCE, HYPOTHESIS, UNKNOWN. Risk scores are heuristics, not probabilities._",
        "",
    ]
    if fmt in ("full", "executive"):
        lines += ["## Executive summary", ""]
        for line in story["executive"]["lines"]:
            lines.append(f"- **{line['heading']}** {line['sentence']['text']}{cite(line['sentence'])}")
        lines.append("")
    if fmt in ("full", "analyst"):
        lines += ["## Analyst narrative", ""]
        for paragraph in story["analyst"]["paragraphs"]:
            lines.append(" ".join(f"{s['text']}{cite(s)}" for s in paragraph))
            lines.append("")
    lines += ["## Evidence index", "", "| Ref | Time | Kind | Asset | Event ID |", "| --- | --- | --- | --- | --- |"]
    for item in story["evidence_index"]:
        lines.append(
            f"| {item['ref']} | {item['timestamp']} | {item['kind']} | {item['asset']} | `{item['event_id']}` |"
        )
    lines.append("")
    return "\n".join(lines)
