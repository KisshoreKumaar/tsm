"""`manage.py demo`: load a synthetic scenario straight into the configured database (instant mode)."""

from __future__ import annotations

from app.core.auth import Principal
from app.core.config import Settings
from app.core.context import build_context
from app.core.permissions import ROLE_PERMISSIONS
from app.demo.scenarios import SCENARIOS


def load_scenario(settings: Settings, scenario: str) -> int:
    from app.features.registry import ALL_FEATURES

    if scenario not in SCENARIOS:
        print(f"Unknown scenario {scenario!r}; choose one of: {', '.join(SCENARIOS)}")
        return 1
    ctx = build_context(settings, ALL_FEATURES)
    operator = Principal("local-admin", "admin", ROLE_PERMISSIONS["admin"])
    result = ctx.service("demo").run(scenario, "instant", operator)
    print(f"Loaded {scenario} (suffix {result['suffix']}): {result['event_count']} synthetic events")
    for incident_id in result["incident_ids"]:
        print(f"  incident {incident_id}")
    print("Live dashboards refresh on their next poll; use the Demo page for live replay.")
    return 0
