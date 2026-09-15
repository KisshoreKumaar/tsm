"""Request models for CORE routes. Unknown fields are rejected everywhere."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from app.ingest.normalize import ENTITY_TYPES

IncidentStatus = Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
ClosureCategory = Literal[
    "authorized_scanner",
    "maintenance_window",
    "known_admin_activity",
    "user_error",
    "test_activity",
    "misconfigured_source",
    "other",
]
EntityType = Literal["asset", "user", "source_ip", "destination_ip", "domain", "file_hash", "process"]
PlaybookId = Literal["isolate_endpoint", "restore_connectivity", "collect_evidence"]

assert set(EntityType.__args__) == set(ENTITY_TYPES)  # type: ignore[attr-defined]  # noqa: S101


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EntityRef(Strict):
    type: EntityType
    value: str = Field(min_length=1, max_length=255)


class IncidentUpdateIn(Strict):
    revision: StrictInt = Field(ge=1)
    status: IncidentStatus | None = None
    owner: str | None = Field(default=None, max_length=100)
    note: str | None = Field(default=None, min_length=1, max_length=4000)
    closure_category: ClosureCategory | None = None
    benign_entities: list[EntityRef] | None = Field(default=None, max_length=20)


class NoteIn(Strict):
    text: str = Field(min_length=1, max_length=4000)


class ResponseRequestIn(Strict):
    incident_id: str = Field(min_length=1, max_length=64)
    playbook: PlaybookId
    rationale: str = Field(min_length=3, max_length=2000)
    revision: StrictInt = Field(ge=1)


class ApproveIn(Strict):
    confirmation: str = Field(min_length=1, max_length=100)


class RejectIn(Strict):
    reason: str = Field(min_length=3, max_length=2000)


class EmptyIn(Strict):
    pass


class DemoRunIn(Strict):
    scenario: str = Field(min_length=1, max_length=50)
    mode: Literal["instant", "replay"] = "instant"
