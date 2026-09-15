"""Environment-driven settings. Secrets come only from the environment or a local, git-ignored `.env` file."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from app.core.permissions import ROLE_PERMISSIONS

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_DIR = BACKEND_DIR.parent
DEFAULT_DB_PATH = str(BACKEND_DIR / "var" / "aegis.db")
DEFAULT_COMMON_ENTITIES = frozenset(
    {"user:system", "user:local service", "user:network service", "domain:localhost", "ip:127.0.0.1", "ip:::1"}
)
DEFAULT_PROTECTED_RULES = frozenset({"LOG-001", "FILE-001"})
IDENTITY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


class ConfigError(ValueError):
    """Invalid configuration. Messages never include secret values."""


@dataclass(frozen=True)
class IdentityConfig:
    name: str
    role: str
    token_sha256: bytes = field(repr=False)


def make_identity(name: str, role: str, token: str) -> IdentityConfig:
    if not IDENTITY_NAME_RE.fullmatch(name):
        raise ConfigError("Identity names must be 1-64 characters: letters, digits, '.', '_' or '-'")
    if role not in ROLE_PERMISSIONS:
        raise ConfigError(f"Unknown role for identity {name}; valid roles: {', '.join(ROLE_PERMISSIONS)}")
    if len(token) < 32 or not token.isascii() or not token.isprintable() or any(c.isspace() for c in token):
        raise ConfigError(f"Token for identity {name} must be at least 32 printable ASCII characters without spaces")
    return IdentityConfig(name=name, role=role, token_sha256=hashlib.sha256(token.encode("ascii")).digest())


def parse_identities(raw_json: str, admin_token: str) -> tuple[IdentityConfig, ...]:
    entries: list[object] = []
    if raw_json.strip():
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            raise ConfigError("AEGIS_IDENTITIES must be a JSON array of {name, role, token}") from None
        if not isinstance(data, list):
            raise ConfigError("AEGIS_IDENTITIES must be a JSON array of {name, role, token}")
        entries.extend(data)
    if admin_token:
        entries.append({"name": "local-admin", "role": "admin", "token": admin_token})
    identities: list[IdentityConfig] = []
    names: set[str] = set()
    digests: set[bytes] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"name", "role", "token"}:
            raise ConfigError("Each identity needs exactly name, role and token")
        if not all(isinstance(entry[k], str) for k in ("name", "role", "token")):
            raise ConfigError("Identity name, role and token must be strings")
        identity = make_identity(entry["name"], entry["role"], entry["token"])
        if identity.name in names or identity.token_sha256 in digests:
            raise ConfigError("Identity names and tokens must be unique")
        names.add(identity.name)
        digests.add(identity.token_sha256)
        identities.append(identity)
    return tuple(identities)


class _Env:
    def __init__(self, env: Mapping[str, str]) -> None:
        self.env = env

    def text(self, name: str, default: str = "") -> str:
        value = self.env.get(name)
        return default if value is None else value.strip()

    def flag(self, name: str, default: bool) -> bool:
        value = self.text(name).lower()
        if not value:
            return default
        if value in _TRUE:
            return True
        if value in _FALSE:
            return False
        raise ConfigError(f"{name} must be true or false")

    def integer(self, name: str, default: int, low: int, high: int) -> int:
        value = self.text(name)
        if not value:
            return default
        try:
            number = int(value)
        except ValueError:
            raise ConfigError(f"{name} must be an integer") from None
        if not low <= number <= high:
            raise ConfigError(f"{name} must be between {low} and {high}")
        return number

    def number(self, name: str, default: float, low: float, high: float) -> float:
        value = self.text(name)
        if not value:
            return default
        try:
            number = float(value)
        except ValueError:
            raise ConfigError(f"{name} must be a number") from None
        if not low <= number <= high:
            raise ConfigError(f"{name} must be between {low} and {high}")
        return number

    def items(self, name: str) -> tuple[str, ...]:
        return tuple(part.strip() for part in self.text(name).split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    audit_key: str = field(repr=False)
    identities: tuple[IdentityConfig, ...]
    db_path: str = DEFAULT_DB_PATH
    secret_key: str = field(default="", repr=False)
    features: frozenset[str] | None = None  # None means every registered feature
    two_person: bool = False
    rate_limit_per_minute: int = 600
    max_body_bytes: int = 262_144
    max_batch_body_bytes: int = 4_194_304
    batch_max_events: int = 500
    clock_skew_seconds: int = 120
    incident_window_seconds: int = 600
    campaign_window_seconds: int = 86_400
    max_link_degree: int = 20
    max_component_events: int = 2_000
    common_entities: frozenset[str] = DEFAULT_COMMON_ENTITIES
    protected_rules: frozenset[str] = DEFAULT_PROTECTED_RULES
    replay_interval_seconds: float = 6.0
    cors_origins: tuple[str, ...] = ()
    worker_enabled: bool = True
    expose_docs: bool = True
    cert_in_deadline_hours: int = 6
    llm_enabled: bool = False
    llm_api_type: str = "openai"
    llm_base_url: str = ""
    llm_model: str = ""
    llm_api_key: str = field(default="", repr=False)
    llm_timeout_seconds: float = 180.0
    llm_max_output_tokens: int = 600
    llm_max_concurrency: int = 1
    llm_context_tokens: int = 2048
    llm_redact: bool = True
    llm_allowed_hosts: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        source = _Env(os.environ if env is None else env)
        features_raw = source.text("AEGIS_FEATURES", "all").lower()
        features = (
            None
            if features_raw in ("", "all")
            else frozenset(part.strip() for part in features_raw.split(",") if part.strip())
        )
        common = source.items("AEGIS_COMMON_ENTITIES")
        protected = source.items("AEGIS_PROTECTED_RULES")
        settings = cls(
            audit_key=source.text("AEGIS_AUDIT_KEY"),
            identities=parse_identities(source.text("AEGIS_IDENTITIES"), source.text("AEGIS_API_TOKEN")),
            db_path=source.text("AEGIS_DB") or DEFAULT_DB_PATH,
            secret_key=source.text("AEGIS_SECRET_KEY"),
            features=features,
            two_person=source.flag("AEGIS_TWO_PERSON", False),
            rate_limit_per_minute=source.integer("AEGIS_RATE_LIMIT", 600, 10, 100_000),
            batch_max_events=source.integer("AEGIS_BATCH_MAX_EVENTS", 500, 1, 5_000),
            clock_skew_seconds=source.integer("AEGIS_CLOCK_SKEW_SECONDS", 120, 0, 3_600),
            incident_window_seconds=source.integer("AEGIS_INCIDENT_WINDOW_SECONDS", 600, 60, 86_400),
            campaign_window_seconds=source.integer("AEGIS_CAMPAIGN_WINDOW_SECONDS", 86_400, 600, 2_592_000),
            max_link_degree=source.integer("AEGIS_MAX_LINK_DEGREE", 20, 2, 1_000),
            common_entities=frozenset(e.lower() for e in common) if common else DEFAULT_COMMON_ENTITIES,
            protected_rules=frozenset(protected) if protected else DEFAULT_PROTECTED_RULES,
            replay_interval_seconds=source.number("AEGIS_REPLAY_INTERVAL_SECONDS", 6.0, 0.1, 120.0),
            cors_origins=source.items("AEGIS_CORS_ORIGINS"),
            worker_enabled=source.flag("AEGIS_WORKER_ENABLED", True),
            expose_docs=source.flag("AEGIS_EXPOSE_DOCS", True),
            cert_in_deadline_hours=source.integer("AEGIS_CERT_IN_DEADLINE_HOURS", 6, 1, 168),
            llm_enabled=source.flag("AEGIS_LLM_ENABLED", False),
            llm_api_type=source.text("AEGIS_LLM_API_TYPE", "openai").lower(),
            llm_base_url=source.text("AEGIS_LLM_BASE_URL"),
            llm_model=source.text("AEGIS_LLM_MODEL"),
            llm_api_key=source.text("AEGIS_LLM_API_KEY"),
            llm_timeout_seconds=source.number("AEGIS_LLM_TIMEOUT_S", 180.0, 1.0, 1_800.0),
            llm_max_output_tokens=source.integer("AEGIS_LLM_MAX_OUTPUT_TOKENS", 600, 16, 32_000),
            llm_max_concurrency=source.integer("AEGIS_LLM_MAX_CONCURRENCY", 1, 1, 8),
            llm_context_tokens=source.integer("AEGIS_LLM_CONTEXT_TOKENS", 2048, 512, 2_000_000),
            llm_redact=source.flag("AEGIS_LLM_REDACT", True),
            llm_allowed_hosts=tuple(h.lower() for h in source.items("AEGIS_LLM_ALLOWED_HOSTS")),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if len(self.audit_key) < 32:
            raise ConfigError("AEGIS_AUDIT_KEY must contain at least 32 characters (run: make init-env)")
        if not self.identities:
            raise ConfigError("Configure AEGIS_API_TOKEN or AEGIS_IDENTITIES")
        if self.secret_key and len(self.secret_key) < 32:
            raise ConfigError("AEGIS_SECRET_KEY must contain at least 32 characters")
        if self.secret_key and self.secret_key == self.audit_key:
            raise ConfigError("AEGIS_SECRET_KEY must differ from AEGIS_AUDIT_KEY")
        if self.llm_api_type not in ("openai", "ollama"):
            raise ConfigError("AEGIS_LLM_API_TYPE must be 'openai' or 'ollama'")
        if self.llm_enabled and not (self.llm_base_url and self.llm_model):
            raise ConfigError("AEGIS_LLM_ENABLED requires AEGIS_LLM_BASE_URL and AEGIS_LLM_MODEL")


def read_env_file(path: Path) -> dict[str, str]:
    """Parse simple KEY=VALUE lines. Values are literal; no quoting or shell expansion."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            values[key] = value.strip()
    return values


def environment_with_dotenv(path: Path | None = None) -> dict[str, str]:
    """Process environment wins over `.env` values."""
    merged = read_env_file(path or REPO_DIR / ".env")
    merged.update(os.environ)
    return merged
