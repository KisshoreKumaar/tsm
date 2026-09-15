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
        rows.append({"scenario": scenario.id, "expected": scenario.expected, "actual": actual, "checks": checks})
    return rows


def run_evaluation() -> int:
    rows = evaluate_scenarios()
    failures = 0
    print("AEGIS scenario evaluation (synthetic expectations; not a real-world benchmark)")
    print(f"{'scenario':<20} {'incidents':>11} {'campaigns':>11}  rules")
    for row in rows:
        expected, actual, checks = row["expected"], row["actual"], row["checks"]
        ok = all(checks.values())
        failures += 0 if ok else 1
        campaigns = f"{actual.get('campaigns', '-')}/{expected['campaigns']}" if "campaigns" in actual else "n/a"
        print(
            f"{row['scenario']:<20} {actual['incidents']:>5}/{expected['incidents']:<5} {campaigns:>11}  "
            f"{','.join(actual['rules']) or '-'}  {'PASS' if ok else 'FAIL ' + str([k for k, v in checks.items() if not v])}"
        )
    print(f"\n{len(rows) - failures}/{len(rows)} scenarios passed")
    return 0 if failures == 0 else 1
