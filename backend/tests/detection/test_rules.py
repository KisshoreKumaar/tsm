from __future__ import annotations

import random

import pytest

from app.detection.base import Event
from app.detection.builtin import encoded_flag, find_encoded_powershell
from app.detection.catalog import UnknownTechnique, default_catalog
from app.detection.engine import RuleEngine
from tests.detection.helpers import detect, engine, ev


def failures(offsets: list[float], **fields: object) -> list[Event]:
    return [ev("auth_failure", offset, source_ip="203.0.113.5", **fields) for offset in offsets]  # type: ignore[arg-type]


# -- AUTH-001 ------------------------------------------------------------------------------------------


def test_auth001_five_failures_in_window() -> None:
    events = failures([0, 5, 10, 15, 20])
    [detection] = detect(events, "AUTH-001")
    assert detection.techniques == ("T1110",)
    assert list(detection.event_ids) == [e.id for e in events]
    assert detection.details["failures"] == 5


def test_auth001_four_failures_do_not_fire() -> None:
    assert detect(failures([0, 5, 10, 15]), "AUTH-001") == []


def test_auth001_window_boundary_is_inclusive() -> None:
    assert detect(failures([0, 150, 300, 450, 600]), "AUTH-001")
    assert detect(failures([0, 150, 300, 450, 601]), "AUTH-001") == []


def test_auth001_groups_by_source_ip() -> None:
    events = [ev("auth_failure", i, source_ip=f"203.0.113.{i}") for i in range(5)]
    assert detect(events, "AUTH-001") == []


# -- AUTH-002 ------------------------------------------------------------------------------------------


def test_auth002_success_after_failures() -> None:
    events = [*failures([0, 5, 10, 15, 20]), ev("auth_success", 60, source_ip="203.0.113.5")]
    [detection] = detect(events, "AUTH-002")
    assert detection.techniques == ("T1078",)
    assert events[-1].id in detection.event_ids


def test_auth002_success_before_failures_does_not_fire() -> None:
    events = [ev("auth_success", 0, source_ip="203.0.113.5"), *failures([10, 15, 20, 25, 30])]
    assert detect(events, "AUTH-002") == []


def test_auth002_success_long_after_failures_does_not_fire() -> None:
    events = [*failures([0, 5, 10, 15, 20]), ev("auth_success", 700, source_ip="203.0.113.5")]
    assert detect(events, "AUTH-002") == []


# -- PROC-001 ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("process", "command"),
    [
        ("powershell.exe", "powershell.exe -e SQBFAFgA"),
        ("powershell", "powershell -ec SQBFAFgA"),
        ("pwsh", "pwsh -EncodedCommand SQBFAFgA"),
        ("PowerShell.EXE", "PowerShell.EXE /enc SQBFAFgA"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoP -EnCoDeD SQBFAFgA"),
        ("pwsh.exe", "pwsh.exe -encodedc SQBFAFgA"),
        ("cmd.exe", "cmd.exe /c powershell -en SQBFAFgA"),
        ("/usr/bin/pwsh", "/usr/bin/pwsh /EncodedCommand SQBFAFgA"),
        ("powershell.exe", '"C:\\Windows\\powershell.exe" -E SQBFAFgA'),
        ("powershell.exe", "powershell.exe \u2013enc SQBFAFgA"),
    ],
)
def test_proc001_positive(process: str, command: str) -> None:
    [detection] = detect([ev("process_start", process_name=process, command_line=command)], "PROC-001")
    assert detection.techniques == ("T1059.001",)


@pytest.mark.parametrize(
    ("process", "command"),
    [
        ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File update.ps1"),
        ("powershell.exe", "powershell.exe -Command Get-Process"),
        ("powershell.exe", "powershell.exe -EncodedArguments x"),
        ("powershell.exe", "powershell.exe -encodedcommandx x"),
        ("powershell.exe", "powershell.exe -"),
        ("notepad.exe", "notepad.exe -e notes.txt"),
        ("python3", "python3 -e print(1)"),
        ("encodedcommand.exe", "encodedcommand.exe -e"),
        ("cmd.exe", "cmd.exe /c echo powershell"),
    ],
)
def test_proc001_negative(process: str, command: str) -> None:
    assert detect([ev("process_start", process_name=process, command_line=command)], "PROC-001") == []


def test_encoded_flag_prefixes() -> None:
    for length in range(1, len("encodedcommand") + 1):
        assert encoded_flag("-" + "encodedcommand"[:length]) is not None
    assert encoded_flag("-ec") == "-ec"
    assert encoded_flag("-ex") is None
    assert find_encoded_powershell(None, None) is None


# -- NET-001 -------------------------------------------------------------------------------------------


def connections(count: int, spacing: float, distinct: bool = True) -> list[Event]:
    return [
        ev(
            "network_connection",
            index * spacing,
            destination_ip=f"10.0.0.{index if distinct else 1}",
            destination_port=445,
            source_ip="10.0.9.9",
        )
        for index in range(count)
    ]


def test_net001_ten_distinct_targets() -> None:
    [detection] = detect(connections(10, 5), "NET-001")
    assert detection.details["distinct_targets"] == 10
    assert detection.details["source_ips"] == ["10.0.9.9"]


def test_net001_nine_targets_do_not_fire() -> None:
    assert detect(connections(9, 5), "NET-001") == []


def test_net001_repeated_same_target_does_not_fire() -> None:
    assert detect(connections(20, 1, distinct=False), "NET-001") == []


def test_net001_spread_beyond_window_does_not_fire() -> None:
    assert detect(connections(10, 40), "NET-001") == []


# -- FILE-001, LOG-001, ACCT-001, INJ-001, SOURCE ---------------------------------------------------------


def test_file001_threshold_and_window() -> None:
    changes = [ev("file_change", i * 2, file_path=f"/data/{i}") for i in range(50)]
    assert detect(changes, "FILE-001")
    assert detect(changes[:49], "FILE-001") == []
    split = [ev("file_change", i, file_path=f"/d/{i}", asset="a" if i % 2 else "b") for i in range(50)]
    assert detect(split, "FILE-001") == []


def test_log001_and_account_rules() -> None:
    events = [
        ev("log_cleared", 0),
        ev("user_created", 10, details="created backdoor"),
        ev("privilege_change", 20, details="added to admins"),
    ]
    [log_cleared] = detect(events, "LOG-001")
    assert log_cleared.techniques == ("T1685.005",)
    assert log_cleared.stage == "Defense Impairment"
    techniques = sorted(d.techniques for d in detect(events, "ACCT-001"))
    assert techniques == [("T1098",), ("T1136",)]


def test_inj001_and_source_rules_never_invent_techniques() -> None:
    events = [
        ev("auth_failure", 0, injection_matches=("ignore_instructions",)),
        ev("suspicious_process", 5, process_name="evil.exe"),
        ev("malicious_indicator", 10, domain="bad.example"),
    ]
    detections = {d.rule_id: d for d in detect(events)}
    assert set(detections) == {"INJ-001", "SOURCE-001", "SOURCE-002"}
    assert all(d.techniques == () for d in detections.values())
    assert detections["INJ-001"].details["patterns"] == ["ignore_instructions"]


# -- engine --------------------------------------------------------------------------------------------


def test_unknown_technique_is_rejected() -> None:
    class BadRule:
        id = "BAD-001"
        name = "bad"
        version = 1
        techniques = ("T9999",)
        severity = "LOW"
        confidence = 10
        stage = "Discovery"
        description = "bad"

        def evaluate(self, events: object) -> list[object]:
            return []

    with pytest.raises(UnknownTechnique):
        RuleEngine([BadRule()], default_catalog())  # type: ignore[list-item]


def test_all_builtin_techniques_exist_in_catalog() -> None:
    catalog = default_catalog()
    for rule in engine().rules():
        for technique in rule.techniques:
            assert technique in catalog


def test_evaluation_is_independent_of_input_order() -> None:
    events = [
        *failures([0, 5, 10, 15, 20]),
        ev("auth_success", 30, source_ip="203.0.113.5"),
        ev("process_start", 40, process_name="pwsh", command_line="pwsh -enc AAA"),
        *connections(12, 2),
    ]
    baseline = [d.public() for d in detect(events)]
    shuffled = list(events)
    for seed in range(5):
        random.Random(seed).shuffle(shuffled)
        assert [d.public() for d in detect(shuffled)] == baseline
