"""Scenario evaluation: runs every synthetic scenario in a fresh database and compares expected with actual.

Used by `scripts/evaluate.py` and CI. Exits non-zero on any regression. This checks synthetic expectations; it is
not a real-world precision/recall benchmark.
"""

from __future__ import annotations

import secrets
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.auth import Principal
from app.core.config import Settings, make_identity
from app.core.context import AppContext, build_context
from app.core.permissions import ROLE_PERMISSIONS
from app.core.timeutil import ManualClock
from app.demo.scenarios import SCENARIOS

EVALUATOR = Principal("evaluator", "admin", ROLE_PERMISSIONS["admin"])


def evaluation_context(directory: Path) -> AppContext:
    from app.features.registry import ALL_FEATURES

    settings = Settings(
        audit_key=secrets.token_urlsafe(40),
        identities=(make_identity("evaluator", "admin", secrets.token_urlsafe(40)),),
        db_path=str(directory / "evaluation.db"),
        worker_enabled=False,
    )
    return build_context(settings, ALL_FEATURES, clock=ManualClock(datetime(2026, 1, 15, 12, 0, tzinfo=UTC)))


def scenario_outcome(ctx: AppContext) -> dict[str, Any]:
    with ctx.db.read() as session:
        incidents = session.scalar("SELECT count(*) FROM incidents WHERE status != 'MERGED'")
        rules = sorted(
            r["rule_id"]
            for r in session.all(
                "SELECT DISTINCT d.rule_id FROM detections d JOIN incidents i ON i.id = d.incident_id "
                "WHERE d.status = 'ACTIVE' AND i.status != 'MERGED'"
            )
        )
        techniques: set[str] = set()
        for row in session.all("SELECT techniques FROM detections WHERE status = 'ACTIVE'"):
            import json

            techniques.update(json.loads(row["techniques"]))
    outcome: dict[str, Any] = {"incidents": incidents, "rules": rules, "techniques": sorted(techniques)}
    campaigns = ctx.services.get("campaigns")
    if campaigns is not None:
        outcome["campaigns"] = campaigns.count()
    predictions = ctx.services.get("predictions")
    if predictions is not None:
        rate = predictions.hit_rate()
        with ctx.db.read() as session:
            observed = session.all(
                "SELECT DISTINCT p.technique_id FROM predictions p JOIN incidents i ON i.id = p.incident_id "
                "WHERE p.status = 'OBSERVED' AND i.status != 'MERGED' ORDER BY p.technique_id"
            )
        outcome["predictions"] = {
            "observed": rate["observed"],
            "total": rate["total"],
            "observed_techniques": [row["technique_id"] for row in observed],
        }
    verification = ctx.audit.verify(ctx.db)
    outcome["audit_valid"] = verification["valid"]
    return outcome


def evaluate_scenarios() -> list[dict[str, Any]]:
    rows = []
    for scenario in SCENARIOS.values():
        with tempfile.TemporaryDirectory() as tmp:
            ctx = evaluation_context(Path(tmp))
            ctx.service("demo").run(scenario.id, "instant", EVALUATOR)
            actual = scenario_outcome(ctx)
        checks = {
            "incidents": actual["incidents"] == scenario.expected["incidents"],
            "rules": actual["rules"] == sorted(scenario.expected["rules"]),
            "audit": actual["audit_valid"],
        }
        if "techniques" in scenario.expected:
            checks["techniques"] = actual["techniques"] == sorted(scenario.expected["techniques"])
        if "campaigns" in actual:
            checks["campaigns"] = actual["campaigns"] == scenario.expected["campaigns"]
        if "predictions" in actual and "predictions_observed" in scenario.expected:
            checks["predictions"] = actual["predictions"]["observed_techniques"] == sorted(
                scenario.expected["predictions_observed"]
            )
        rows.append({"scenario": scenario.id, "expected": scenario.expected, "actual": actual, "checks": checks})
    return rows


def evaluate_workflows() -> list[dict[str, Any]]:
    """End-to-end checks that span features: a rule drafted from an incident, and tuning learned from verdicts."""
    from app.features.a3.service import BacktestIn
    from app.features.core.models import IncidentUpdateIn

    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmp:
        ctx = evaluation_context(Path(tmp))
        rules = ctx.services.get("detection_rules")
        if rules is not None:
            incident_id = ctx.service("demo").run("lateral-movement", "instant", EVALUATOR)["incident_ids"][0]
            rule_id = rules.draft_now(incident_id, EVALUATOR)["rule_id"]
            result = rules.backtest(rule_id, BacktestIn(), EVALUATOR)["result"]
            rows.append(
                {
                    "check": "rule drafted from lateral-movement backtests on its own incident",
                    "ok": incident_id in result["matched_incident_ids"] and result["detections"] > 0,
                    "detail": f"{rule_id}: {result['detections']} alert(s), "
                    f"{result['matches_in_benign_scenario']} on benign data, "
                    f"{result['estimated_alerts_per_day']}/day estimated",
                }
            )

    with tempfile.TemporaryDirectory() as tmp:
        ctx = evaluation_context(Path(tmp))
        tuning = ctx.services.get("tuning")
        if tuning is not None:
            for _ in range(3):
                [incident_id] = ctx.service("demo").run("authorized-scanner", "instant", EVALUATOR)["incident_ids"]
                detail = ctx.service("incidents").get(incident_id)
                ctx.service("incidents").update(
                    incident_id,
                    IncidentUpdateIn(
                        revision=detail["revision"],
                        status="FALSE_POSITIVE",
                        note="Authorised weekly vulnerability scan",
                        closure_category="authorized_scanner",
                    ),
                    EVALUATOR,
                )
            tuning.generate_now(EVALUATOR)
            suggestions = [s for s in tuning.search("PROPOSED")["items"] if s["rule_id"] == "NET-001"]
            suggestion = suggestions[0] if suggestions else None
            impact = suggestion["impact"] if suggestion else {}
            rows.append(
                {
                    "check": "three scanner false positives suggest a scoped suppression with no true-positive loss",
                    "ok": bool(suggestion)
                    and suggestion["type"] == "suppression"
                    and suggestion["scope"]["entities"] == [{"type": "source_ip", "value": "10.20.0.250"}]
                    and impact["true_positive_alerts_removed"] == 0,
                    "detail": (
                        f"{suggestion['type']} scoped to "
                        f"{suggestion['scope']['entities'][0]['value']}: removes {impact['alerts_removed']} alert(s), "
                        f"{impact['true_positive_alerts_removed']} true positive"
                        if suggestion
                        else "no suggestion was generated"
                    ),
                }
            )
    return rows


def run_evaluation() -> int:
    rows = evaluate_scenarios()
    failures = 0
    print("AEGIS scenario evaluation (synthetic expectations; not a real-world benchmark)")
    print(f"{'scenario':<20} {'incidents':>11} {'campaigns':>11} {'predicted':>11}  rules")
    observed_total = predicted_total = 0
    for row in rows:
        expected, actual, checks = row["expected"], row["actual"], row["checks"]
        ok = all(checks.values())
        failures += 0 if ok else 1
        campaigns = f"{actual.get('campaigns', '-')}/{expected['campaigns']}" if "campaigns" in actual else "n/a"
        prediction = actual.get("predictions")
        predicted = f"{prediction['observed']}/{prediction['total']} obs" if prediction else "n/a"
        if prediction:
            observed_total += prediction["observed"]
            predicted_total += prediction["total"]
        print(
            f"{row['scenario']:<20} {actual['incidents']:>5}/{expected['incidents']:<5} {campaigns:>11} {predicted:>11}  "
            f"{','.join(actual['rules']) or '-'}  {'PASS' if ok else 'FAIL ' + str([k for k, v in checks.items() if not v])}"
        )
    if predicted_total:
        print(
            f"\nPrediction hit rate across scenarios: {observed_total}/{predicted_total} observed "
            f"({observed_total / predicted_total:.0%}; descriptive, not a probability)"
        )
    print(f"\n{len(rows) - failures}/{len(rows)} scenarios passed")

    workflows = evaluate_workflows()
    if workflows:
        print("\nCross-feature workflows")
        for workflow in workflows:
            failures += 0 if workflow["ok"] else 1
            print(f"  {'PASS' if workflow['ok'] else 'FAIL'}  {workflow['check']}\n        {workflow['detail']}")
    return 0 if failures == 0 else 1
