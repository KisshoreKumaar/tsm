"""Prompt-injection detector for untrusted text (event fields, tool results, model inputs).

Matches mark events `injection_suspected`, raise INJ-001 and show a UI warning. Matching is advisory: the real
defence is that event content is only ever passed to models as delimited data and the AI has no write tools.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

MAX_SCAN_CHARS = 10_000

_FLAGS = re.IGNORECASE | re.MULTILINE
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}?\b(previous|prior|above|earlier|all|any|your)\b"
            r"[^.\n]{0,20}?\b(instructions?|prompts?|rules|directions|guidelines)\b",
            _FLAGS,
        ),
    ),
    ("system_prompt", re.compile(r"\bsystem\s*prompt\b", _FLAGS)),
    (
        "role_reassignment",
        re.compile(r"\byou\s+are\s+now\b|\bact\s+as\s+(an?\s+)?(admin|administrator|system|developer|root)\b", _FLAGS),
    ),
    (
        "role_tag",
        re.compile(
            r"<\|?\s*/?\s*(system|assistant|user|im_start|im_end|tool)\s*\|?>|^\s*(system|assistant)\s*:|\[/?\s*(inst|system)\s*\]",
            _FLAGS,
        ),
    ),
    (
        "tool_call_json",
        re.compile(
            r"[\"']?(tool|function|tool_call|tool_calls|function_call)[\"']?\s*:\s*[\"'{\[][^\n]{0,120}?"
            r"[\"']?(args|arguments|parameters|input)[\"']?\s*:",
            _FLAGS,
        ),
    ),
    (
        "approval_directive",
        re.compile(
            r"\b(approve|execute|authori[sz]e|activate|finali[sz]e)\b[^.\n]{0,40}?"
            r"\b(response|responses|isolation|request|requests|action|actions|playbook|rule|report|all)\b",
            _FLAGS,
        ),
    ),
    ("new_instructions", re.compile(r"\b(new|updated)\s+instructions\b|\bdeveloper\s+mode\b|\bjailbreak\b", _FLAGS)),
    (
        "prompt_exfiltration",
        re.compile(
            r"\b(reveal|print|repeat|show|leak)\b[^.\n]{0,30}?\b(system|hidden|secret)\s+(prompt|instructions)\b",
            _FLAGS,
        ),
    ),
)

EVENT_TEXT_FIELDS = (
    "source",
    "asset",
    "user",
    "domain",
    "process_name",
    "parent_process",
    "command_line",
    "file_path",
    "details",
)


def scan_text(text: str | None) -> list[str]:
    if not text:
        return []
    sample = text[:MAX_SCAN_CHARS]
    return [name for name, pattern in INJECTION_PATTERNS if pattern.search(sample)]


def scan_values(values: Iterable[Any]) -> list[str]:
    found: set[str] = set()
    for value in values:
        if isinstance(value, str):
            found.update(scan_text(value))
        elif isinstance(value, Mapping):
            found.update(scan_values(value.values()))
        elif isinstance(value, list | tuple):
            found.update(scan_values(value))
    return sorted(found)


def scan_event_fields(fields: Mapping[str, Any]) -> list[str]:
    return scan_values(fields.get(name) for name in EVENT_TEXT_FIELDS)
