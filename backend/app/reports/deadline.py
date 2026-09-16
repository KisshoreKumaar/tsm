"""Reporting deadline maths (I1). Timestamps are stored in UTC; IST is offered only for display."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

IST = timezone(timedelta(hours=5, minutes=30), "IST")
DEADLINE_LABEL = (
    "Counted from the first detection time using the configured window. Confirm the basis and the window with the "
    "current official directions."
)


def deadline_for(detected_at: datetime, hours: int) -> datetime:
    return detected_at.astimezone(UTC) + timedelta(hours=hours)


def in_ist(moment: datetime) -> str:
    return moment.astimezone(IST).isoformat(timespec="seconds")


def countdown(deadline: datetime, now: datetime, hours: int) -> dict[str, Any]:
    """Remaining time and a display state. `warning` at half the window left, `critical` at a quarter."""
    remaining = (deadline.astimezone(UTC) - now.astimezone(UTC)).total_seconds()
    total = max(1.0, hours * 3600)
    if remaining <= 0:
        state = "overdue"
    elif remaining <= total * 0.25:
        state = "critical"
    elif remaining <= total * 0.5:
        state = "warning"
    else:
        state = "ok"
    return {
        "deadline_utc": deadline.astimezone(UTC).isoformat(timespec="seconds"),
        "deadline_ist": in_ist(deadline),
        "window_hours": hours,
        "seconds_remaining": int(remaining),
        "overdue": remaining <= 0,
        "state": state,
        "label": DEADLINE_LABEL,
    }
