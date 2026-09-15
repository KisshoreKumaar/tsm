"""Rule engine: evaluates built-in and custom rules over one correlated component, deterministically."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from app.detection.base import SEVERITIES, Detection, Event, Rule
from app.detection.catalog import TechniqueCatalog

RuleProvider = Callable[[], Iterable[Rule]]


class RuleEngine:
    def __init__(self, rules: Iterable[Rule], catalog: TechniqueCatalog) -> None:
        self._catalog = catalog
        self._rules: dict[str, Rule] = {}
        self._providers: list[RuleProvider] = []
        self._lock = threading.Lock()
        for rule in rules:
            self._validate(rule)
            if rule.id in self._rules:
                raise ValueError(f"Duplicate rule id: {rule.id}")
            self._rules[rule.id] = rule

    def _validate(self, rule: Rule) -> None:
        if rule.severity not in SEVERITIES:
            raise ValueError(f"Rule {rule.id} has invalid severity {rule.severity}")
        for technique in rule.techniques:
            self._catalog.require(technique)

    @property
    def catalog(self) -> TechniqueCatalog:
        return self._catalog

    def add_provider(self, provider: RuleProvider) -> None:
        """Custom rule sources (e.g. ACTIVE DSL rules) are re-read on every evaluation."""
        with self._lock:
            self._providers.append(provider)

    def rules(self) -> list[Rule]:
        with self._lock:
            providers = list(self._providers)
            combined = dict(self._rules)
        for provider in providers:
            for rule in provider():
                if rule.id in combined:
                    continue  # built-in IDs cannot be shadowed by custom rules
                self._validate(rule)
                combined[rule.id] = rule
        return [combined[key] for key in sorted(combined)]

    def builtin_ids(self) -> frozenset[str]:
        return frozenset(self._rules)

    def evaluate(self, events: Sequence[Event], rules: Sequence[Rule] | None = None) -> list[Detection]:
        ordered = sorted(events, key=lambda e: e.sort_key)
        detections: list[Detection] = []
        for rule in rules if rules is not None else self.rules():
            detections.extend(rule.evaluate(ordered))
        return sorted(detections, key=lambda d: (d.first_ts, d.rule_id, d.group_key))

    def describe(self) -> list[dict[str, Any]]:
        described = []
        for rule in self.rules():
            described.append(
                {
                    "id": rule.id,
                    "name": rule.name,
                    "version": rule.version,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "stage": rule.stage,
                    "description": rule.description,
                    "techniques": [self._catalog.require(t).public() for t in rule.techniques],
                    "builtin": rule.id in self._rules,
                }
            )
        return described
