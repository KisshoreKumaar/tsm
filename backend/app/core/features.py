"""Feature registry and flags.

Each feature declares its id, dependencies, API router, background job kinds, audit actions, agent tools and
navigation entries. Disabled features are not mounted, so their routes return 404 and their UI is hidden.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter

FEATURE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class FeatureConfigError(ValueError):
    pass


@dataclass(frozen=True)
class NavItem:
    path: str
    label: str
    section: str = "Operations"
    permission: str = "read"
    order: int = 100


@dataclass(frozen=True)
class JobKind:
    handler: Callable[[Any, Any], Any]
    lane: str = "default"


@dataclass(frozen=True)
class FeatureSpec:
    id: str
    name: str
    description: str = ""
    depends_on: tuple[str, ...] = ()
    always_on: bool = False
    router: Callable[[], APIRouter] | None = None
    jobs: Mapping[str, JobKind] = field(default_factory=dict)
    audit_actions: frozenset[str] = frozenset()
    agent_tools: Callable[[], Sequence[Any]] | None = None
    nav: tuple[NavItem, ...] = ()
    on_startup: Callable[[Any], None] | None = None


@dataclass(frozen=True)
class EnabledFeatures:
    specs: tuple[FeatureSpec, ...]

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(spec.id for spec in self.specs)

    def __contains__(self, feature_id: object) -> bool:
        return feature_id in self.ids

    def manifest(self, permissions: frozenset[str] | None = None) -> list[dict[str, Any]]:
        items = []
        for spec in self.specs:
            nav = [
                {
                    "path": n.path,
                    "label": n.label,
                    "section": n.section,
                    "permission": n.permission,
                    "order": n.order,
                }
                for n in spec.nav
                if permissions is None or n.permission in permissions
            ]
            items.append({"id": spec.id, "name": spec.name, "description": spec.description, "nav": nav})
        return items


def resolve_features(available: Sequence[FeatureSpec], requested: frozenset[str] | None) -> EnabledFeatures:
    by_id: dict[str, FeatureSpec] = {}
    for spec in available:
        if not FEATURE_ID_RE.match(spec.id):
            raise FeatureConfigError(f"Invalid feature id: {spec.id!r}")
        if spec.id in by_id:
            raise FeatureConfigError(f"Duplicate feature id: {spec.id}")
        by_id[spec.id] = spec
    for spec in available:
        for dependency in spec.depends_on:
            if dependency not in by_id:
                raise FeatureConfigError(f"Feature {spec.id} depends on unknown feature {dependency}")

    if requested is None:
        wanted = set(by_id)
    else:
        unknown = sorted(requested - set(by_id))
        if unknown:
            raise FeatureConfigError(f"Unknown feature ids in AEGIS_FEATURES: {', '.join(unknown)}")
        wanted = set(requested) | {spec.id for spec in available if spec.always_on}

    for feature_id in sorted(wanted):
        missing = [d for d in by_id[feature_id].depends_on if d not in wanted]
        if missing:
            raise FeatureConfigError(
                f"Feature {feature_id} requires {', '.join(missing)}; enable them or disable {feature_id}"
            )

    ordered: list[FeatureSpec] = []
    placed: set[str] = set()

    def place(spec: FeatureSpec, trail: tuple[str, ...] = ()) -> None:
        if spec.id in placed:
            return
        if spec.id in trail:
            raise FeatureConfigError(f"Circular feature dependency: {' -> '.join((*trail, spec.id))}")
        for dependency in spec.depends_on:
            place(by_id[dependency], (*trail, spec.id))
        placed.add(spec.id)
        ordered.append(spec)

    for spec in available:
        if spec.id in wanted:
            place(spec)
    return EnabledFeatures(tuple(ordered))
