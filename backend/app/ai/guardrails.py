"""Output guardrails: strict JSON extraction, claim/citation validation, and suggested-action filtering.

Rules: a FACT must cite at least one valid evidence alias; unknown aliases are dropped and uncited FACTs are downgraded
to INFERENCE (never shown as fact); claims whose own text (outside quotations) looks like injected instructions are
dropped; suggested actions may not tell humans to approve, execute, activate or finalise anything.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.ai.evidence import EvidencePack
from app.ai.injection import scan_text
from app.core.jsonutil import StrictJSONError, strict_loads
from app.response.simulation import PLAYBOOKS

LABELS = ("FACT", "INFERENCE", "HYPOTHESIS", "UNKNOWN")
QUOTED_RE = re.compile(r"“[^”]*”|\"[^\"]*\"")
HUMAN_ONLY_ACTION_RE = re.compile(
    r"\b(approve|approval|execute|authori[sz]e|activate|finali[sz]e|mark(ed)?\s+(it\s+)?(as\s+)?submitted|"
    r"disable\s+(the\s+)?rule|suppress|close\s+(the\s+|this\s+)?incident|mark\s+.{0,20}false\s+positive)\b",
    re.IGNORECASE,
)
MAX_TEXT = 400


class OutputInvalid(ValueError):
    """The model output is not valid for the task (malformed JSON or schema violation)."""


def extract_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", cleaned)
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise OutputInvalid("The output does not contain a JSON object")
    try:
        value = strict_loads(cleaned[start : end + 1])
    except StrictJSONError as exc:
        raise OutputInvalid(f"The output is not valid JSON ({exc})") from None
    if not isinstance(value, dict):
        raise OutputInvalid("The output must be a JSON object")
    return value


@dataclass
class ValidationStats:
    total: int = 0
    grounded: int = 0
    dropped: int = 0
    downgraded: int = 0
    invalid_aliases: list[str] = field(default_factory=list)

    def merge(self, other: ValidationStats) -> None:
        self.total += other.total
        self.grounded += other.grounded
        self.dropped += other.dropped
        self.downgraded += other.downgraded
        self.invalid_aliases.extend(other.invalid_aliases)


def looks_injected(text: str) -> bool:
    return bool(scan_text(QUOTED_RE.sub("", text)))


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise OutputInvalid("Claim text must be a string")
    cleaned = " ".join(value.split())
    if not cleaned:
        raise OutputInvalid("Claim text must not be empty")
    return cleaned[:limit]


def validate_claims(
    raw: Any, pack: EvidencePack, *, max_claims: int = 8
) -> tuple[list[dict[str, Any]], ValidationStats]:
    """Accepts compact ({"t","l","e"}) or full ({"text","label","evidence_ids"}) claims."""
    if raw is None:
        return [], ValidationStats()
    if not isinstance(raw, list):
        raise OutputInvalid("Claims must be a list")
    stats = ValidationStats()
    claims: list[dict[str, Any]] = []
    for item in raw[:max_claims]:
        if not isinstance(item, Mapping):
            raise OutputInvalid("Each claim must be an object")
        text = pack.restore(_text(item.get("t", item.get("text"))))
        label = str(item.get("l", item.get("label", "UNKNOWN"))).strip().upper()
        if label not in LABELS:
            raise OutputInvalid(f"Invalid claim label {label[:20]!r}")
        aliases = item.get("e", item.get("evidence_ids", [])) or []
        if not isinstance(aliases, list):
            raise OutputInvalid("Claim evidence must be a list")
        stats.total += 1
        if looks_injected(text):
            stats.dropped += 1
            continue
        valid, invalid = pack.resolve(aliases)
        stats.invalid_aliases.extend(invalid)
        downgraded = False
        if label == "FACT" and not valid:
            label, downgraded = "INFERENCE", True
            stats.downgraded += 1
        if valid:
            stats.grounded += 1
        claims.append(
            {
                "text": text,
                "label": label,
                "evidence_ids": valid,
                "citations_rejected": len(invalid),
                "downgraded": downgraded,
            }
        )
    return claims, stats


def string_list(raw: Any, *, limit: int, max_len: int = 200) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise OutputInvalid("Expected a list of strings")
    out = []
    for item in raw[:limit]:
        if isinstance(item, str) and item.strip():
            out.append(" ".join(item.split())[:max_len])
    return out


def filter_actions(raw: Any, pack: EvidencePack | None = None, *, limit: int = 4) -> tuple[list[dict[str, Any]], int]:
    """Suggested actions are text for a human; never approvals/executions. Playbook IDs must be allowlisted."""
    if raw is None:
        return [], 0
    if not isinstance(raw, list):
        raise OutputInvalid("Suggested actions must be a list")
    actions: list[dict[str, Any]] = []
    removed = 0
    for item in raw[: limit * 2]:
        if isinstance(item, str):
            text, playbook = item, None
        elif isinstance(item, Mapping):
            text, playbook = item.get("t", item.get("text", "")), item.get("p", item.get("playbook"))
        else:
            continue
        if not isinstance(text, str) or not text.strip():
            continue
        text = " ".join(text.split())[:240]
        if pack is not None:
            text = pack.restore(text)
        if HUMAN_ONLY_ACTION_RE.search(text) or looks_injected(text):
            removed += 1
            continue
        if playbook is not None and playbook not in PLAYBOOKS:
            playbook = None
        actions.append({"text": text, "playbook": playbook})
        if len(actions) >= limit:
            break
    return actions, removed


def grounding_rate(stats: Sequence[ValidationStats] | Iterable[ValidationStats]) -> float | None:
    total = grounded = 0
    for item in stats:
        total += item.total
        grounded += item.grounded
    return None if total == 0 else round(grounded / total, 3)
