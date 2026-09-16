"""Rule engine: evaluates built-in and custom rules over one correlated component, deterministically."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from app.detection.base import SEVERITIES, Detection, Event, Rule
from app.detection.catalog import TechniqueCatalog

RuleProvider = Callable[[], Iterable[Rule]]
ParameterProvider = Callable[[], Mapping[str, Mapping[str, int]]]


class RuleEngine:
    def __init__(self, rules: Iterable[Rule], catalog: TechniqueCatalog) -> None:
        self._catalog = catalog
        self._rules: dict[str, Rule] = {}
        self._providers: list[RuleProvider] = []
        self._parameters: ParameterProvider | None = None
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

    def set_parameter_provider(self, provider: ParameterProvider) -> None:
        """Approved tuning overrides (A5) for tunable built-in rules, re-read on every evaluation."""
        with self._lock:
            self._parameters = provider

    def rules(self) -> list[Rule]:
        with self._lock:
            providers = list(self._providers)
            parameters = self._parameters
            combined = dict(self._rules)
        if parameters is not None:
            for rule_id, values in parameters().items():
                rule = combined.get(rule_id)
                tune = getattr(rule, "with_parameters", None)
                tunable: tuple[str, ...] = getattr(rule, "TUNABLE", ())
                if rule is not None and tune is not None and tunable:
                    combined[rule_id] = tune(**values)
        for provider in providers:
            for rule in provider():
                if rule.id in combined:
                    continue  # built-in IDs cannot be shadowed by custom rules
                self._validate(rule)
                combined[rule.id] = rule
        return [combined[key] for key in sorted(combined)]

    def builtin_ids(self) -> frozenset[str]:
        return frozenset(self._rules)

    def get(self, rule_id: str) -> Rule | None:
        """The rule as currently evaluated (tuning overrides and active custom rules included)."""
        return next((rule for rule in self.rules() if rule.id == rule_id), None)

    def evaluate(self, events: Sequence[Event], rules: Sequence[Rule] | None = None) -> list[Detection]:
        ordered = sorted(events, key=lambda e: e.sort_key)
        detections: list[Detection] = []
        for rule in rules if rules is not None else self.rules():
            detections.extend(rule.evaluate(ordered))
        return sorted(detections, key=lambda d: (d.first_ts, d.rule_id, d.group_key))

    def describe(self) -> list[dict[str, Any]]:
        described = []
        for rule in self.rules():
            parameters = getattr(rule, "parameters", None)
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
                    "parameters": dict(parameters()) if callable(parameters) else {},
                }
            )
        return described
