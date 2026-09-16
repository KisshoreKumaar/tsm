#!/usr/bin/env python3
"""Seed the local database with synthetic content for a walkthrough.

Runs demo scenarios, closes the scanner runs as false positives so tuning has something to learn from, drafts a
detection rule and a CERT-In report, and saves an organisation profile. Synthetic data only; nothing leaves the
machine. Safe to run more than once: each demo run uses a fresh asset suffix.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.core.auth import Principal  # noqa: E402
from app.core.config import Settings, environment_with_dotenv  # noqa: E402
from app.core.context import build_context  # noqa: E402
from app.core.permissions import ROLE_PERMISSIONS  # noqa: E402
from app.features.registry import ALL_FEATURES  # noqa: E402

SCENARIOS = ("attack-chain", "lateral-movement", "ransomware-burst", "prompt-injection", "benign")
PROFILE = {
    "organization_name": "Lab Industries Pvt Ltd",
    "sector": "Information technology",
    "contact_name": "Asha Rao",
    "contact_email": "asha.rao@lab.example",
    "contact_phone": "+91 22 5550 1234",
    "address": "5th Floor, Tech Park, Pune",
}


def main() -> int:
    settings = Settings.from_env(environment_with_dotenv(REPO / ".env"))
    ctx = build_context(settings, ALL_FEATURES)
    actor = Principal("seed-admin", "admin", ROLE_PERMISSIONS["admin"])
    demo = ctx.service("demo")

    incidents: list[str] = []
    for scenario in SCENARIOS:
        result = demo.run(scenario, "instant", actor)
        incidents.extend(result["incident_ids"])
        print(f"  {scenario:<18} {len(result['incident_ids'])} incident(s)")

    if "i1" in ctx.features:
        from app.features.i1.service import OrgProfileIn

        ctx.service("reports").save_profile(OrgProfileIn(**PROFILE), actor)
        print("  organisation profile saved")

    if "a5" in ctx.features:
        from app.features.core.models import IncidentUpdateIn

        closed = 0
        for _ in range(3):
            for incident_id in demo.run("authorized-scanner", "instant", actor)["incident_ids"]:
                detail = ctx.service("incidents").get(incident_id)
                ctx.service("incidents").update(
                    incident_id,
                    IncidentUpdateIn(
                        revision=detail["revision"],
                        status="FALSE_POSITIVE",
                        note="Authorised weekly vulnerability scan",
                        closure_category="authorized_scanner",
                        benign_entities=[{"type": "source_ip", "value": "10.20.0.250"}],
                    ),
                    actor,
                )
                closed += 1
        created = ctx.service("tuning").generate_now(actor)
        print(f"  {closed} scanner incidents closed as false positives, {len(created)} tuning suggestion(s) proposed")

    if "a3" in ctx.features and incidents:
        rule = ctx.service("detection_rules").draft_now(incidents[1] if len(incidents) > 1 else incidents[0], actor)
        print(f"  detection rule {rule['rule_id']} drafted (DRAFT: backtest and approve it in the UI)")

    if "i1" in ctx.features and incidents:
        report = ctx.service("reports").draft(incidents[0], actor)
        left = round(report["deadline"]["seconds_remaining"] / 3600, 1)
        print(f"  CERT-In draft prepared for incident {incidents[0][:8]} ({left} h before the deadline)")

    print(f"\nSeeded {len(incidents)} incidents. Start the app with `make dev` and sign in with `make token`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
