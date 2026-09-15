from __future__ import annotations

import itertools
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from app.detection.base import Detection, Event
from app.detection.builtin import builtin_rules
from app.detection.catalog import default_catalog
from app.detection.engine import RuleEngine

BASE = datetime(2026, 1, 15, 8, 0, tzinfo=UTC)
_counter = itertools.count()


def ev(kind: str, offset: float = 0.0, **fields: Any) -> Event:
    number = next(_counter)
    values: dict[str, Any] = {
        "source": "test",
        "asset": "host-1",
        "username": "alice",
        "criticality": 3,
        "privileged": False,
    }
    values.update(fields)
    return Event(
        id=f"evt-{number:06d}",
        external_id=f"x{number}",
        digest=f"{number:064d}",
        ts=BASE + timedelta(seconds=offset),
        kind=kind,
        **values,
    )


def engine() -> RuleEngine:
    catalog = default_catalog()
    return RuleEngine(builtin_rules(catalog.require("T1685.005").tactics[0]), catalog)


def detect(events: Sequence[Event], rule_id: str | None = None) -> list[Detection]:
    detections = engine().evaluate(events)
    return [d for d in detections if rule_id is None or d.rule_id == rule_id]
