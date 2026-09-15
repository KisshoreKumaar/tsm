"""Versioned prompt templates. The version is part of the cache key and of every audited AI call."""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=32)
def load_prompt(name: str) -> tuple[str, str]:
    """Return (version, text) for `<name>.v<N>.txt`, choosing the highest version present."""
    candidates = sorted(PROMPT_DIR.glob(f"{name}.v*.txt"), key=lambda p: int(p.stem.rsplit(".v", 1)[1]))
    if not candidates:
        raise FileNotFoundError(f"No prompt template named {name}")
    path = candidates[-1]
    version = f"{name}.v{path.stem.rsplit('.v', 1)[1]}"
    return version, path.read_text(encoding="utf-8").strip()


def prompt_hash(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()
