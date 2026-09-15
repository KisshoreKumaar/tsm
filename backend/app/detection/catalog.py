"""Local MITRE ATT&CK technique catalog. Every technique ID used anywhere in AEGIS is validated against it."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import BACKEND_DIR

CATALOG_PATH = BACKEND_DIR / "data" / "attack" / "techniques.json"
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class UnknownTechnique(ValueError):
    pass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "tactics": list(self.tactics), "url": self.url}


class TechniqueCatalog:
    def __init__(self, techniques: list[Technique], *, version: str, attribution: str, verified_on: str) -> None:
        self._by_id = {t.id: t for t in techniques}
        if len(self._by_id) != len(techniques):
            raise ValueError("Duplicate technique IDs in catalog")
        self.version = version
        self.attribution = attribution
        self.verified_on = verified_on

    @classmethod
    def load(cls, path: Path = CATALOG_PATH) -> TechniqueCatalog:
        data = json.loads(path.read_text(encoding="utf-8"))
        techniques = []
        for item in data["techniques"]:
            technique_id = item["id"]
            if not TECHNIQUE_ID_RE.fullmatch(technique_id):
                raise ValueError(f"Invalid technique ID in catalog: {technique_id}")
            if not item.get("tactics"):
                raise ValueError(f"Technique {technique_id} has no tactics")
            techniques.append(Technique(technique_id, item["name"], tuple(item["tactics"]), item["url"]))
        return cls(
            techniques,
            version=str(data.get("attack_version", "")),
            attribution=str(data["attribution"]),
            verified_on=str(data.get("verified_on", "")),
        )

    def __contains__(self, technique_id: object) -> bool:
        return technique_id in self._by_id

    def get(self, technique_id: str) -> Technique | None:
        return self._by_id.get(technique_id)

    def require(self, technique_id: str) -> Technique:
        technique = self._by_id.get(technique_id)
        if technique is None:
            raise UnknownTechnique(f"Technique {technique_id} is not in the local ATT&CK catalog")
        return technique

    def all(self) -> list[Technique]:
        return sorted(self._by_id.values(), key=lambda t: t.id)

    def public(self) -> dict[str, Any]:
        return {
            "attack_version": self.version,
            "verified_on": self.verified_on,
            "attribution": self.attribution,
            "techniques": [t.public() for t in self.all()],
        }


@lru_cache(maxsize=1)
def default_catalog() -> TechniqueCatalog:
    return TechniqueCatalog.load()
