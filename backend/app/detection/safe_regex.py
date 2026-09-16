"""Restricted regular expressions for rule and watch conditions. Patterns are data written by engineers or the AI.

Python's `re` has no timeout, so constructs that cause catastrophic backtracking are rejected before compiling:
patterns over 200 characters, backreferences, lookaround assertions, nested quantifiers where either side is
unbounded, and alternation inside an unbounded repeat. Matching is case-insensitive and applied to values clipped to
4,096 characters.
"""

from __future__ import annotations

import re
from functools import lru_cache
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any

MAX_PATTERN_LENGTH = 200
MAX_SUBJECT_LENGTH = 4096

_REPEATS = {
    op
    for op in (
        getattr(sre_constants, "MAX_REPEAT", None),
        getattr(sre_constants, "MIN_REPEAT", None),
        getattr(sre_constants, "POSSESSIVE_REPEAT", None),
    )
    if op is not None
}
_BACKREFERENCES = {sre_constants.GROUPREF, sre_constants.GROUPREF_EXISTS}
_LOOKAROUND = {sre_constants.ASSERT, sre_constants.ASSERT_NOT}
_ATOMIC = getattr(sre_constants, "ATOMIC_GROUP", None)


class UnsafeRegex(ValueError):
    pass


def _walk(items: Any, inside_unbounded: bool, inside_repeat: bool) -> None:
    for op, value in items:
        if op in _BACKREFERENCES:
            raise UnsafeRegex("Backreferences are not allowed in rule regex")
        if op in _LOOKAROUND:
            raise UnsafeRegex("Lookaround assertions are not allowed in rule regex")
        if op in _REPEATS:
            _low, high, sub = value
            unbounded = high == sre_constants.MAXREPEAT
            if (inside_unbounded and high > 1) or (inside_repeat and unbounded):
                raise UnsafeRegex("Nested quantifiers are not allowed in rule regex")
            _walk(sub, inside_unbounded or unbounded, inside_repeat or high > 1)
        elif op == sre_constants.BRANCH:
            if inside_unbounded:
                raise UnsafeRegex("Alternation inside a repeated group is not allowed in rule regex")
            for branch in value[1]:
                _walk(branch, inside_unbounded, inside_repeat)
        elif op == sre_constants.SUBPATTERN:
            _walk(value[-1], inside_unbounded, inside_repeat)
        elif _ATOMIC is not None and op == _ATOMIC:
            _walk(value, inside_unbounded, inside_repeat)


@lru_cache(maxsize=512)
def compile_safe(pattern: str) -> re.Pattern[str]:
    if not pattern:
        raise UnsafeRegex("A regex pattern must not be empty")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise UnsafeRegex(f"Regex patterns are limited to {MAX_PATTERN_LENGTH} characters")
    try:
        parsed = sre_parse.parse(pattern, re.IGNORECASE)
    except re.error as exc:
        raise UnsafeRegex(f"Invalid regex: {exc.msg}") from None
    _walk(parsed, False, False)
    return re.compile(pattern, re.IGNORECASE)


def search(pattern: str, value: str) -> bool:
    return compile_safe(pattern).search(value[:MAX_SUBJECT_LENGTH]) is not None
