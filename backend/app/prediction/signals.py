"""Field conditions for watch signals (F4), shared with the rule DSL (A3). Pure data: never executed or evaluated."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

from app.detection.base import Event
from app.detection.safe_regex import UnsafeRegex, compile_safe, search

EventKind = Literal[
    "auth_failure",
    "auth_success",
    "process_start",
    "network_connection",
    "file_change",
    "user_created",
    "privilege_change",
    "log_cleared",
    "suspicious_process",
    "malicious_indicator",
]
Operator = Literal["equals", "in", "contains", "startswith", "endswith", "cidr", "regex", "gt", "gte", "lt", "lte"]

STRING_FIELDS = frozenset(
    {
        "source",
        "asset",
        "user",
        "source_ip",
        "destination_ip",
        "domain",
        "process_name",
        "parent_process",
        "command_line",
        "file_path",
        "file_hash",
        "details",
    }
)
NUMERIC_FIELDS = frozenset({"destination_port", "criticality"})
BOOLEAN_FIELDS = frozenset({"privileged"})
IP_FIELDS = frozenset({"source_ip", "destination_ip"})
COMPARISONS = frozenset({"gt", "gte", "lt", "lte"})
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,15}-\d{3}$")
MAX_VALUES = 50
MAX_VALUE_LENGTH = 200


class Condition(BaseModel):
    """One field test. String matching is case-insensitive; a list value matches if any element matches."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: StrictStr = Field(max_length=40)
    op: Operator
    value: StrictBool | StrictInt | StrictStr | list[StrictInt] | list[StrictStr]

    @model_validator(mode="after")
    def _check(self) -> Condition:
        values = self.value if isinstance(self.value, list) else [self.value]
        if not values or len(values) > MAX_VALUES:
            raise ValueError(f"A condition needs 1 to {MAX_VALUES} values")
        if self.field in STRING_FIELDS:
            if self.op in COMPARISONS:
                raise ValueError(f"Operator {self.op} needs a numeric field")
            if not all(isinstance(v, str) and 0 < len(v) <= MAX_VALUE_LENGTH for v in values):
                raise ValueError(f"Values for {self.field} must be strings of 1 to {MAX_VALUE_LENGTH} characters")
            if self.op == "in" and not isinstance(self.value, list):
                raise ValueError("Operator in needs a list of values")
            if self.op == "regex":
                for pattern in values:
                    try:
                        compile_safe(str(pattern))
                    except UnsafeRegex as exc:
                        raise ValueError(str(exc)) from None
            if self.op == "cidr":
                if self.field not in IP_FIELDS:
                    raise ValueError("Operator cidr applies only to source_ip or destination_ip")
                for network in values:
                    try:
                        ipaddress.ip_network(str(network), strict=False)
                    except ValueError as exc:
                        raise ValueError("Invalid network in cidr condition") from exc
        elif self.field in NUMERIC_FIELDS:
            if self.op not in COMPARISONS | {"equals", "in"}:
                raise ValueError(f"Operator {self.op} does not apply to numeric field {self.field}")
            if not all(isinstance(v, int) and not isinstance(v, bool) for v in values):
                raise ValueError(f"Values for {self.field} must be integers")
            if self.op in COMPARISONS and isinstance(self.value, list):
                raise ValueError("Comparison operators need a single number")
        elif self.field in BOOLEAN_FIELDS:
            if self.op != "equals" or not isinstance(self.value, bool):
                raise ValueError(f"{self.field} supports only equals true or false")
        else:
            raise ValueError("Unknown event field in condition")
        return self

    def matches(self, event: Event) -> bool:
        actual = event.get(self.field)
        if actual is None:
            return False
        values = self.value if isinstance(self.value, list) else [self.value]
        if self.field in BOOLEAN_FIELDS:
            return bool(actual) is self.value
        if self.field in NUMERIC_FIELDS:
            number = int(actual)
            if self.op in ("equals", "in"):
                return number in values
            target = int(values[0])
            return {
                "gt": number > target,
                "gte": number >= target,
                "lt": number < target,
                "lte": number <= target,
            }[self.op]
        if self.op == "cidr":
            try:
                address = ipaddress.ip_address(str(actual))
            except ValueError:
                return False
            return any(address in ipaddress.ip_network(str(v), strict=False) for v in values)
        if self.op == "regex":
            return any(search(str(pattern), str(actual)) for pattern in values)
        text = str(actual).casefold()
        needles = [str(v).casefold() for v in values]
        if self.op in ("equals", "in"):
            return text in needles
        if self.op == "contains":
            return any(needle in text for needle in needles)
        if self.op == "startswith":
            return any(text.startswith(needle) for needle in needles)
        if self.op == "endswith":
            return any(text.endswith(needle) for needle in needles)
        return False

    def text(self) -> str:
        values = self.value if isinstance(self.value, list) else [self.value]
        rendered = " or ".join(repr(v) if isinstance(v, str) else str(v).lower() for v in values)
        return f"{self.field} {self.op} {rendered}"


class WatchSignal(BaseModel):
    """Matches an event of one of `kinds` satisfying every condition, or an event on which a listed rule fired."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    description: StrictStr = Field(min_length=3, max_length=200)
    kinds: tuple[EventKind, ...] = ()
    conditions: tuple[Condition, ...] = Field(default=(), max_length=10)
    rule_ids: tuple[StrictStr, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def _check(self) -> WatchSignal:
        if not self.kinds and not self.rule_ids:
            raise ValueError("A watch signal needs event kinds or rule IDs")
        if self.conditions and not self.kinds:
            raise ValueError("Field conditions need at least one event kind")
        if not all(RULE_ID_RE.fullmatch(rule_id) for rule_id in self.rule_ids):
            raise ValueError("Invalid rule ID in watch signal")
        return self

    def matches(self, event: Event, triggered_rules: Iterable[str] = ()) -> bool:
        if self.rule_ids and set(self.rule_ids) & set(triggered_rules):
            return True
        return bool(self.kinds) and event.kind in self.kinds and all(c.matches(event) for c in self.conditions)

    def text(self) -> str:
        parts = []
        if self.kinds:
            clause = " or ".join(self.kinds)
            if self.conditions:
                clause += " where " + " and ".join(c.text() for c in self.conditions)
            parts.append(clause)
        if self.rule_ids:
            parts.append("rule " + " or ".join(self.rule_ids) + " fires")
        return "; or ".join(parts)

    def public(self) -> dict[str, Any]:
        return {**self.model_dump(mode="json"), "text": self.text()}
