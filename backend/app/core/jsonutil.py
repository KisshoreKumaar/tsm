"""Canonical JSON (for digests and storage) and strict parsing of untrusted request bodies."""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_JSON_DEPTH = 32


class StrictJSONError(ValueError):
    """Raised for malformed or ambiguous JSON. Messages never echo the input."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError("Duplicate JSON keys are not permitted")
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise StrictJSONError("Non-finite numbers (NaN, Infinity) are not valid JSON")


def _check_depth(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise StrictJSONError("JSON nesting is too deep")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def strict_loads(data: bytes | str) -> Any:
    try:
        value = json.loads(data, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except StrictJSONError:
        raise
    except RecursionError:
        raise StrictJSONError("JSON nesting is too deep") from None
    except ValueError:
        raise StrictJSONError("Request body is not valid JSON") from None
    _check_depth(value)
    return value


def loads_stored(text: str | None) -> Any:
    """Parse JSON that this application wrote to its own database."""
    return None if text is None else json.loads(text)
