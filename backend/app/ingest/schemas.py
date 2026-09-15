"""Strict event schema. Unknown fields, wrong types, oversized values and naive timestamps are rejected."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from app.ingest.kinds import event_kinds, get_event_kind

SOURCE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$"
HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$"
)
MIN_YEAR = 2000


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str | None = Field(default=None, min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=100, pattern=SOURCE_PATTERN)
    timestamp: str = Field(min_length=10, max_length=40)
    asset: str = Field(min_length=1, max_length=255)
    user: str = Field(min_length=1, max_length=255)
    kind: str = Field(min_length=1, max_length=50)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    destination_port: StrictInt | None = Field(default=None, ge=1, le=65535)
    domain: str | None = Field(default=None, min_length=1, max_length=253)
    process_name: str | None = Field(default=None, min_length=1, max_length=260)
    parent_process: str | None = Field(default=None, min_length=1, max_length=260)
    command_line: str | None = Field(default=None, min_length=1, max_length=8192)
    file_path: str | None = Field(default=None, min_length=1, max_length=1024)
    file_hash: str | None = Field(default=None, min_length=32, max_length=64)
    details: str | None = Field(default=None, max_length=4000)
    criticality: StrictInt = Field(default=3, ge=1, le=5)
    privileged: StrictBool = False

    @field_validator("*", mode="before")
    @classmethod
    def _reject_nul_and_non_strings(cls, value: Any, info: Any) -> Any:
        if isinstance(value, str) and "\x00" in value:
            raise ValueError("NUL characters are not permitted")
        return value

    @field_validator(
        "event_id",
        "source",
        "timestamp",
        "asset",
        "user",
        "kind",
        "source_ip",
        "destination_ip",
        "domain",
        "process_name",
        "parent_process",
        "command_line",
        "file_path",
        "file_hash",
        "details",
        mode="before",
    )
    @classmethod
    def _strings_only(cls, value: Any) -> Any:
        if value is not None and not isinstance(value, str):
            raise ValueError("must be a string")
        return value

    @field_validator("timestamp")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            raise ValueError("must be an ISO 8601 timestamp") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("must include a timezone offset (for example Z or +05:30)")
        if parsed.year < MIN_YEAR:
            raise ValueError(f"must not be earlier than {MIN_YEAR}")
        return parsed.astimezone(UTC).isoformat(timespec="microseconds")

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("must be a valid IPv4 or IPv6 address") from None

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(normalized):
            raise ValueError("must be a valid domain name")
        return normalized

    @field_validator("file_hash")
    @classmethod
    def _hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower()
        if not HASH_RE.fullmatch(normalized):
            raise ValueError("must be a hex MD5, SHA-1 or SHA-256 digest")
        return normalized

    @model_validator(mode="after")
    def _kind_requirements(self) -> EventIn:
        spec = get_event_kind(self.kind)
        if spec is None:
            known = ", ".join(s.kind for s in event_kinds())
            raise ValueError(f"unsupported kind; expected one of: {known}")
        missing = [name for name in spec.required if getattr(self, name) in (None, "")]
        if missing:
            raise ValueError(f"kind {self.kind} requires: {', '.join(missing)}")
        if spec.any_of and all(getattr(self, name) in (None, "") for name in spec.any_of):
            raise ValueError(f"kind {self.kind} requires at least one of: {', '.join(spec.any_of)}")
        return self


class EventBatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[dict[str, Any]] = Field(min_length=1, max_length=5000)
