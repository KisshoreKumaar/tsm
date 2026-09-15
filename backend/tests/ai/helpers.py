from __future__ import annotations

import json
from typing import Any

from app.core.context import AppContext
from tests.support import run_scenario


def answer_json(
    summary: str = "Repeated failures preceded a successful login.",
    claims: list[dict[str, Any]] | None = None,
    questions: list[str] | None = None,
    actions: list[Any] | None = None,
    confidence: str = "medium",
) -> str:
    return json.dumps(
        {
            "s": summary,
            "c": claims
            if claims is not None
            else [{"t": "Five logins failed before a success.", "l": "FACT", "e": ["E1", "E2"]}],
            "q": questions if questions is not None else ["Who owns this workstation?"],
            "a": actions if actions is not None else [{"t": "Confirm the login with the user", "p": None}],
            "k": confidence,
        }
    )


def final_json(**kwargs: Any) -> str:
    return json.dumps({"final": json.loads(answer_json(**kwargs))})


def scenario_incident(ctx: AppContext, scenario: str = "attack-chain") -> dict[str, Any]:
    [incident_id] = run_scenario(ctx, scenario)["incident_ids"]
    detail: dict[str, Any] = ctx.service("incidents").get(incident_id)
    return detail


def ai_calls(ctx: AppContext) -> list[dict[str, Any]]:
    with ctx.db.read() as session:
        return [dict(r) for r in session.all("SELECT * FROM ai_calls ORDER BY created_at, rowid")]
