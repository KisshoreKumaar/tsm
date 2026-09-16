"""A3 DSL: validation, restricted regex, evaluation semantics, tunable parameters, Sigma export and diffs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.detection.base import Event
from app.detection.builtin import BruteForceRule
from app.detection.catalog import default_catalog
from app.detection.safe_regex import UnsafeRegex, compile_safe
from app.rules.dsl import CompiledRule, RuleValidationError, diff_definitions, validate_definition
from app.rules.sigma import to_sigma

CATALOG = default_catalog()
T0 = datetime(2026, 1, 15, 8, 0, tzinfo=UTC)


def ev(name: str, kind: str, seconds: float, **fields: Any) -> Event:
    return Event(
        id=name,
        source="lab",
        external_id=name,
        digest=f"digest-{name}",
        ts=T0 + timedelta(seconds=seconds),
        kind=kind,
        asset=fields.pop("asset", "lab-ws-1"),
        username=fields.pop("username", "alex"),
        criticality=3,
        privileged=False,
        **fields,
    )


def definition(**logic: Any) -> dict[str, Any]:
    return {
        "name": "Repeated failures from one source",
        "description": "Five or more failures from one source against one account in five minutes.",
        "severity": "MEDIUM",
        "techniques": ["T1110"],
        "logic": {
            "kinds": ["auth_failure"],
            "group_by": ["asset", "user", "source_ip"],
            "window_seconds": 300,
            "threshold": {"type": "count", "value": 5},
            **logic,
        },
    }


def compiled(raw: dict[str, Any], rule_id: str = "CUS-001") -> CompiledRule:
    return CompiledRule.build(rule_id, 1, validate_definition(raw, CATALOG), CATALOG)


@pytest.mark.parametrize(
    "pattern", ["(a+)+", r"(\w+\s?)*", "(a|aa)+", r"(x)\1", "(?=admin)", "(?<!a)b", "a" * 201, "(.*a){3,}", "(["]
)
def test_dangerous_or_invalid_regex_is_rejected(pattern: str) -> None:
    with pytest.raises(UnsafeRegex):
        compile_safe(pattern)


@pytest.mark.parametrize(
    "pattern", [r"(\d{1,3}\.){3}\d{1,3}", r"^powershell(\.exe)?$", r"-enc(odedcommand)?\b", "[a-f0-9]{32}"]
)
def test_bounded_regex_is_accepted(pattern: str) -> None:
    assert compile_safe(pattern).pattern == pattern


@pytest.mark.parametrize(
    "raw",
    [
        {**definition(), "script": "import os"},
        definition(conditions=[{"field": "command_line", "op": "regex", "value": "(a+)+"}]),
        definition(conditions=[{"field": "password", "op": "equals", "value": "x"}]),
        definition(group_by=["asset", "asset"]),
        definition(threshold={"type": "distinct_count", "value": 3}),
        definition(sequence=[{"kinds": ["auth_failure"]}, {"kinds": ["process_start"]}]),
        definition(window_seconds=0),
        {**definition(), "techniques": ["T1070.001"]},
        {**definition(), "techniques": ["T9999"]},
        {**definition(), "severity": "URGENT"},
    ],
)
def test_unknown_fields_and_invalid_logic_are_rejected(raw: dict[str, Any]) -> None:
    with pytest.raises(RuleValidationError) as caught:
        validate_definition(raw, CATALOG)
    assert caught.value.errors
    assert "import os" not in str(caught.value.errors)


def test_count_threshold_fires_per_group_and_honours_exclusions() -> None:
    spray = [ev(f"f{i}", "auth_failure", i * 10, source_ip="198.51.100.7") for i in range(5)]
    other = [ev(f"g{i}", "auth_failure", i * 10, source_ip="198.51.100.8") for i in range(4)]
    [detection] = compiled(definition()).evaluate([*other, *spray])
    assert detection.rule_id == "CUS-001" and detection.event_ids == tuple(e.id for e in spray)
    assert detection.stage == "Credential Access" and detection.techniques == ("T1110",)
    excluded = compiled(definition(exclusions=[{"field": "source_ip", "op": "cidr", "value": ["198.51.100.0/24"]}]))
    assert excluded.evaluate(spray) == []
    assert compiled(definition()).with_parameters(threshold=6).evaluate(spray) == []


def test_distinct_count_and_regex_conditions() -> None:
    connections = [
        ev(f"n{i}", "network_connection", i, destination_ip=f"10.0.0.{i}", destination_port=445) for i in range(6)
    ]
    raw = {
        **definition(
            kinds=["network_connection"],
            group_by=["asset"],
            threshold={"type": "distinct_count", "field": "destination_ip", "value": 6},
            conditions=[{"field": "destination_ip", "op": "regex", "value": r"^10\.0\.0\.\d{1,3}$"}],
        ),
        "techniques": ["T1046"],
    }
    rule = compiled(raw, "CUS-002")
    assert len(rule.evaluate(connections)) == 1 and rule.evaluate(connections[:5]) == []


def test_sequence_requires_order_within_the_window() -> None:
    raw = definition(
        kinds=["auth_success", "process_start"],
        group_by=["asset", "user"],
        window_seconds=120,
        threshold={"type": "count", "value": 1},
        sequence=[
            {"kinds": ["auth_success"]},
            {
                "kinds": ["process_start"],
                "conditions": [{"field": "process_name", "op": "contains", "value": "powershell"}],
            },
        ],
    )
    rule = compiled(raw, "CUS-003")
    login = ev("s1", "auth_success", 0)
    shell = ev("p1", "process_start", 60, process_name="powershell.exe")
    early = ev("p0", "process_start", -30, process_name="powershell.exe")
    late = ev("p2", "process_start", 400, process_name="powershell.exe")
    [detection] = rule.evaluate([shell, login])
    assert detection.event_ids == ("s1", "p1")
    assert rule.evaluate([early, login]) == [] and rule.evaluate([login, late]) == []


def test_builtin_rules_accept_tuned_parameters_without_changing_the_original() -> None:
    rule = BruteForceRule()
    failures = [ev(f"f{i}", "auth_failure", i * 10, source_ip="203.0.113.9") for i in range(5)]
    assert len(rule.evaluate(failures)) == 1
    tuned = rule.with_parameters(threshold=6)
    assert tuned.evaluate(failures) == [] and tuned.parameters()["threshold"] == 6
    assert rule.parameters() == {"threshold": 5, "window_seconds": 600}


def test_sigma_export_is_best_effort_and_marked() -> None:
    raw = definition(
        conditions=[{"field": "source_ip", "op": "cidr", "value": ["203.0.113.0/24"]}],
        exclusions=[{"field": "user", "op": "equals", "value": "svc-backup"}],
    )
    text, warnings = to_sigma("CUS-001", 2, validate_definition(raw, CATALOG))
    assert text.startswith("# Best-effort Sigma export")
    assert "source_ip|cidr:" in text and "condition: selection and not filter" in text and "attack.t1110" in text
    assert warnings and "threshold" in warnings[0]


def test_version_diff_lists_changed_paths() -> None:
    old = validate_definition(definition(), CATALOG).model_dump(mode="json")
    new = validate_definition(definition(window_seconds=600), CATALOG).model_dump(mode="json")
    assert diff_definitions(old, new) == [{"path": "logic.window_seconds", "change": "changed", "old": 300, "new": 600}]
