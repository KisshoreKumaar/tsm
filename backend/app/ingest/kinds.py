"""Event-kind registry. A new kind declares its required fields and extra entities without touching ingestion."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

EntityExtractor = Callable[[Mapping[str, Any]], list[tuple[str, str]]]


@dataclass(frozen=True)
class EventKindSpec:
    kind: str
    description: str
    required: tuple[str, ...] = ()
    any_of: tuple[str, ...] = ()
    extra_entities: EntityExtractor | None = None


_lock = threading.Lock()
_registry: dict[str, EventKindSpec] = {}


def register_event_kind(spec: EventKindSpec) -> None:
    with _lock:
        existing = _registry.get(spec.kind)
        if existing is not None and existing != spec:
            raise ValueError(f"Event kind {spec.kind} is already registered differently")
        _registry[spec.kind] = spec


def get_event_kind(kind: str) -> EventKindSpec | None:
    return _registry.get(kind)


def event_kinds() -> list[EventKindSpec]:
    return sorted(_registry.values(), key=lambda spec: spec.kind)


for _spec in (
    EventKindSpec("auth_failure", "Failed authentication attempt"),
    EventKindSpec("auth_success", "Successful authentication"),
    EventKindSpec("process_start", "Process started", required=("process_name", "command_line")),
    EventKindSpec("network_connection", "Outbound network connection", required=("destination_ip", "destination_port")),
    EventKindSpec("file_change", "File created, modified, renamed or deleted", required=("file_path",)),
    EventKindSpec("user_created", "Local or directory account created", required=("details",)),
    EventKindSpec("privilege_change", "Account privileges or group membership changed", required=("details",)),
    EventKindSpec("log_cleared", "Security or audit log cleared"),
    EventKindSpec("suspicious_process", "Upstream tool reported a suspicious process", required=("process_name",)),
    EventKindSpec(
        "malicious_indicator",
        "Upstream tool reported a malicious indicator (reputation not verified by AEGIS)",
        any_of=("source_ip", "destination_ip", "domain", "file_hash"),
    ),
):
    register_event_kind(_spec)
