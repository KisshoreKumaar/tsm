from __future__ import annotations

from app.detection.analysis import build_analysis, build_stages, build_title
from app.detection.catalog import default_catalog
from app.detection.risk import band, score_incident
from tests.detection.helpers import detect, ev


def chain_events(powershell_offset: float = 40.0) -> list:  # type: ignore[type-arg]
    return [
        *[ev("auth_failure", i * 5, source_ip="203.0.113.5", criticality=4, privileged=True) for i in range(5)],
        ev("auth_success", 30, source_ip="203.0.113.5", criticality=4, privileged=True),
        ev("process_start", powershell_offset, process_name="powershell.exe", command_line="powershell -enc AAA"),
        *[
            ev("network_connection", 60 + i, destination_ip=f"10.0.0.{i}", destination_port=445, source_ip="10.0.9.9")
            for i in range(12)
        ],
    ]


def test_risk_score_is_an_explained_capped_heuristic() -> None:
    events = chain_events()
    assessment = score_incident(events, detect(events))
    public = assessment.public()
    assert 0 <= assessment.score <= 100
    assert assessment.score == sum(f["points"] for f in public["factors"])
    assert assessment.severity == band(assessment.score)
    assert "not a probability" in public["label"]
    assert [f["name"] for f in public["factors"]] == [
        "threat_severity",
        "detection_confidence",
        "asset_criticality",
        "privilege",
        "attack_progression",
        "event_count",
        "reported_indicator",
        "potential_impact",
        "observed_prediction",
    ]
    assert all(f["points"] <= f["max_points"] for f in public["factors"])
    assert assessment.severity in ("HIGH", "CRITICAL")


def test_observed_predictions_raise_risk() -> None:
    events = chain_events()
    detections = detect(events)
    assert score_incident(events, detections, observed_predictions=1).score > score_incident(events, detections).score


def test_bands() -> None:
    assert [band(s) for s in (0, 34, 35, 59, 60, 79, 80, 100)] == [
        "LOW",
        "LOW",
        "MEDIUM",
        "MEDIUM",
        "HIGH",
        "HIGH",
        "CRITICAL",
        "CRITICAL",
    ]


def test_stages_follow_evidence_time_not_rule_order() -> None:
    events = [
        ev("process_start", 0, process_name="pwsh", command_line="pwsh -enc AAA"),
        *[ev("auth_failure", 100 + i * 5, source_ip="203.0.113.5") for i in range(5)],
        ev("auth_success", 150, source_ip="203.0.113.5"),
    ]
    stages = build_stages(events, detect(events), default_catalog())
    assert [s["stage"] for s in stages] == ["Execution", "Credential Access", "Initial Access"]
    assert stages[0]["first_ts"] < stages[1]["first_ts"] <= stages[2]["first_ts"]
    assert stages[1]["last_ts"] < stages[2]["last_ts"]  # the login stage ends at the success, after the failures


def test_claims_are_labelled_and_facts_cite_evidence() -> None:
    events = chain_events()
    detections = detect(events)
    analysis = build_analysis(events, detections, [], default_catalog())
    labels = {c["label"] for c in analysis["claims"]}
    assert labels == {"FACT", "INFERENCE", "HYPOTHESIS", "UNKNOWN"}
    event_ids = {e.id for e in events}
    for claim in analysis["claims"]:
        if claim["label"] == "FACT":
            assert claim["evidence_ids"]
            assert set(claim["evidence_ids"]) <= event_ids
    assert {t["id"] for t in analysis["techniques"]} == {"T1110", "T1078", "T1059.001", "T1046"}
    assert all(t["status"] == "candidate" for t in analysis["techniques"])
    assert "MITRE" in analysis["attack_attribution"]


def test_title_lists_stages_in_time_order() -> None:
    events = chain_events()
    assert build_title("host-1", "alice", detect(events)).startswith(
        "Brute force → Login after failures → Encoded PowerShell → Network discovery"
    )
