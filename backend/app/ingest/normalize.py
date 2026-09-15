"""Normalisation and entity extraction. Correlation keys are case-folded; the submitted JSON is kept verbatim."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from app.ai.injection import scan_event_fields
from app.core.jsonutil import sha256_json
from app.core.timeutil import parse_iso
from app.ingest.kinds import get_event_kind
from app.ingest.schemas import EventIn

ENTITY_TYPES = ("asset", "user", "source_ip", "destination_ip", "domain", "file_hash", "process")
_PATH_SPLIT = re.compile(r"[\\/]")


def process_basename(value: str | None) -> str:
    if not value:
        return ""
    token = value.strip().strip("\"'")
    base = _PATH_SPLIT.split(token)[-1].lower()
    return base.removesuffix(".exe")


@dataclass(frozen=True)
class NormalizedEvent:
    source: str
    external_id: str | None
    ts: datetime
    kind: str
    asset: str
    username: str
    criticality: int
    privileged: bool
    raw: dict[str, Any] = field(repr=False)
    digest: str
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    domain: str | None = None
    process_name: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    details: str | None = None
    injection_matches: tuple[str, ...] = ()

    @property
    def injection_suspected(self) -> bool:
        return bool(self.injection_matches)

    def entities(self) -> list[tuple[str, str]]:
        found: set[tuple[str, str]] = {("asset", self.asset), ("user", self.username)}
        for entity_type, value in (
            ("source_ip", self.source_ip),
            ("destination_ip", self.destination_ip),
            ("domain", self.domain),
            ("file_hash", self.file_hash),
        ):
            if value:
                found.add((entity_type, value))
        process = process_basename(self.process_name)
        if process:
            found.add(("process", process))
        spec = get_event_kind(self.kind)
        if spec is not None and spec.extra_entities is not None:
            found.update(spec.extra_entities(self.raw))
        return sorted(found)


class EventValidationError(ValueError):
    def __init__(self, errors: list[dict[str, Any]]) -> None:
        super().__init__("Event validation failed")
        self.errors = errors


def normalize(raw: Mapping[str, Any]) -> NormalizedEvent:
    """Validate one submitted event. Raises EventValidationError with sanitised error details."""
    if not isinstance(raw, Mapping):
        raise EventValidationError([{"loc": [], "msg": "Event must be a JSON object", "type": "type_error"}])
    try:
        model = EventIn.model_validate(dict(raw))
    except ValidationError as exc:
        from app.core.errors import sanitize_validation_errors

        raise EventValidationError(sanitize_validation_errors(exc.errors())) from None
    fields = model.model_dump()
    return NormalizedEvent(
        source=model.source,
        external_id=model.event_id,
        ts=parse_iso(model.timestamp),
        kind=model.kind,
        asset=model.asset.lower(),
        username=model.user.lower(),
        criticality=model.criticality,
        privileged=model.privileged,
        raw=dict(raw),
        digest=sha256_json(dict(raw)),
        source_ip=model.source_ip,
        destination_ip=model.destination_ip,
        destination_port=model.destination_port,
        domain=model.domain,
        process_name=model.process_name,
        parent_process=model.parent_process,
        command_line=model.command_line,
        file_path=model.file_path,
        file_hash=model.file_hash,
        details=model.details,
        injection_matches=tuple(scan_event_fields(fields)),
    )
