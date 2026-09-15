"""Agent tool registry (X2 extension point). Features contribute read tools and, for X2, proposal tools.

Read tools return compact data; events they return receive evidence aliases so answers can cite them. Proposal tools
never change state: they only record a draft that a human with the target permission may apply.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from app.ai.evidence import EvidencePack


class ToolError(Exception):
    """A safe message returned to the model (e.g. a missing argument)."""


@dataclass
class ToolContext:
    ctx: Any
    actor: str
    subject_type: str
    subject_id: str | None
    pack: EvidencePack
    proposals: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    feature: str
    description: str
    args: type[BaseModel]
    handler: Callable[[ToolContext, Any], Any]
    kind: str = "read"  # "read" or "propose"

    def signature(self) -> str:
        params = ", ".join(
            f"{name}{'' if info.is_required() else '?'}" for name, info in self.args.model_fields.items()
        )
        return f"{self.name}({params}): {self.description}"


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"Duplicate agent tool: {spec.name}")
        if spec.kind not in ("read", "propose"):
            raise ValueError(f"Tool {spec.name} has invalid kind {spec.kind}")
        if (spec.kind == "propose") != spec.name.startswith("propose_"):
            raise ValueError("Proposal tools must be named propose_* and only proposal tools may use that prefix")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def tools(
        self,
        enabled_features: Iterable[str],
        *,
        names: Iterable[str] | None = None,
        include_propose: bool = False,
    ) -> list[ToolSpec]:
        enabled = set(enabled_features)
        wanted = set(names) if names is not None else None
        return [
            spec
            for spec in sorted(self._tools.values(), key=lambda s: (s.kind, s.name))
            if spec.feature in enabled
            and (wanted is None or spec.name in wanted)
            and (include_propose or spec.kind == "read")
        ]

    def features_with_read_tools(self) -> set[str]:
        return {spec.feature for spec in self._tools.values() if spec.kind == "read"}

    def describe(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "feature": s.feature, "kind": s.kind, "signature": s.signature()}
            for s in sorted(self._tools.values(), key=lambda s: (s.kind, s.name))
        ]
