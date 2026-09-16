"""CERT-In template configuration (I1), validated at startup and carried into every draft.

The shipped config is marked UNVERIFIED on purpose: field names, categories and the deadline come from general
knowledge, not from the official directions. Nothing in this module hardcodes CERT-In content.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from app.core.config import BACKEND_DIR
from app.detection.catalog import TECHNIQUE_ID_RE, TechniqueCatalog, default_catalog
from app.prediction.signals import RULE_ID_RE

CERT_IN_PATH = BACKEND_DIR / "data" / "compliance" / "cert_in.json"
UNVERIFIED_BANNER = (
    "UNVERIFIED template: field names, categories and the deadline have not been checked against the current "
    "official CERT-In directions. Confirm with compliance or legal before filing."
)
FieldSource = Literal["auto", "ai", "human", "profile"]
Reportable = Literal["yes", "likely", "unlikely"]


class TemplateError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TemplateField(_Strict):
    id: StrictStr = Field(min_length=1, max_length=60)
    label: StrictStr = Field(min_length=1, max_length=200)
    required: StrictBool
    source: FieldSource
    description: StrictStr = Field(min_length=1, max_length=600)
    max_length: StrictInt = Field(ge=1, le=20_000)
    multiline: StrictBool = False


class IncidentTypeOption(_Strict):
    id: StrictStr = Field(min_length=1, max_length=60)
    label: StrictStr = Field(min_length=1, max_length=200)
    rules: tuple[StrictStr, ...] = ()
    techniques: tuple[StrictStr, ...] = ()
    keywords: tuple[StrictStr, ...] = ()
    reportable: Reportable
    note: StrictStr = Field(min_length=1, max_length=600)


class Reporting(_Strict):
    authority: StrictStr
    deadline_hours: StrictInt = Field(ge=1, le=168)
    deadline_basis: StrictStr
    channels: tuple[StrictStr, ...]
    note: StrictStr


class TemplateFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["UNVERIFIED", "VERIFIED"]
    verified_against: StrictStr
    verified_on: StrictStr | None
    verification_note: StrictStr
    reporting: Reporting
    fields: list[TemplateField] = Field(min_length=1)
    incident_types: list[IncidentTypeOption] = Field(min_length=1)
    reportability_notes: list[StrictStr]


class CertInTemplate:
    def __init__(self, data: TemplateFile, catalog: TechniqueCatalog, raw: str) -> None:
        ids = [field.id for field in data.fields]
        if len(set(ids)) != len(ids):
            raise TemplateError("Duplicate field id in the CERT-In template")
        type_ids = [option.id for option in data.incident_types]
        if len(set(type_ids)) != len(type_ids):
            raise TemplateError("Duplicate incident type id in the CERT-In template")
        for option in data.incident_types:
            for technique in option.techniques:
                if not TECHNIQUE_ID_RE.fullmatch(technique) or technique not in catalog:
                    raise TemplateError(f"incident type {option.id}: {technique} is not in the local ATT&CK catalog")
            for rule_id in option.rules:
                if not RULE_ID_RE.fullmatch(rule_id):
                    raise TemplateError(f"incident type {option.id}: {rule_id!r} is not a valid rule ID")
        if data.status == "VERIFIED" and not (data.verified_against and data.verified_on):
            raise TemplateError("A VERIFIED template must record verified_against and verified_on")
        self.data = data
        self.fields = tuple(data.fields)
        self.incident_types = tuple(data.incident_types)
        self.version = hashlib.sha256(raw.encode()).hexdigest()[:12]

    @classmethod
    def load(cls, path: Path = CERT_IN_PATH, catalog: TechniqueCatalog | None = None) -> CertInTemplate:
        try:
            raw = path.read_text(encoding="utf-8")
            data = TemplateFile.model_validate(json.loads(raw))
        except (OSError, ValueError) as exc:
            raise TemplateError(f"Invalid CERT-In template {path.name}: {exc}") from None
        return cls(data, catalog or default_catalog(), raw)

    @property
    def verified(self) -> bool:
        return self.data.status == "VERIFIED"

    @property
    def deadline_hours(self) -> int:
        return self.data.reporting.deadline_hours

    def field(self, field_id: str) -> TemplateField | None:
        return next((field for field in self.fields if field.id == field_id), None)

    def incident_type(self, type_id: str) -> IncidentTypeOption | None:
        return next((option for option in self.incident_types if option.id == type_id), None)

    def public(self) -> dict[str, Any]:
        return {
            "status": self.data.status,
            "verified": self.verified,
            "verified_against": self.data.verified_against,
            "verified_on": self.data.verified_on,
            "verification_note": self.data.verification_note,
            "banner": None if self.verified else UNVERIFIED_BANNER,
            "template_version": self.version,
            "reporting": self.data.reporting.model_dump(),
            "fields": [field.model_dump() for field in self.fields],
            "incident_types": [option.model_dump() for option in self.incident_types],
            "reportability_notes": list(self.data.reportability_notes),
        }


@lru_cache(maxsize=1)
def default_template() -> CertInTemplate:
    return CertInTemplate.load()
