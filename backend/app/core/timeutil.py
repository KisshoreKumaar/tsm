"""UTC time helpers and an injectable clock (tests use ManualClock)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class ManualClock:
    """A controllable clock for deterministic tests."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = (start or datetime(2026, 1, 15, 9, 0, tzinfo=UTC)).astimezone(UTC)

    def now(self) -> datetime:
        return self._now

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("ManualClock requires timezone-aware datetimes")
        self._now = value.astimezone(UTC)

    def advance(self, seconds: float = 0.0, **kwargs: float) -> datetime:
        self._now = self._now + timedelta(seconds=seconds, **kwargs)
        return self._now


def iso(value: datetime) -> str:
    """Canonical storage format: UTC, microsecond precision, lexicographically sortable."""
    if value.tzinfo is None:
        raise ValueError("Refusing to serialise a naive datetime")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def utc_now_iso() -> str:
    return iso(datetime.now(UTC))


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return parsed.astimezone(UTC)
