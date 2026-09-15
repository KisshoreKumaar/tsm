from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import ConfigError, Settings, parse_identities, read_env_file

TOKEN = "t" * 40
KEY = "k" * 40


def env(**overrides: str) -> dict[str, str]:
    values = {"AEGIS_AUDIT_KEY": KEY, "AEGIS_API_TOKEN": TOKEN}
    values.update(overrides)
    return values


def test_minimal_environment() -> None:
    settings = Settings.from_env(env())
    assert settings.identities[0].name == "local-admin"
    assert settings.identities[0].role == "admin"
    assert settings.features is None
    assert TOKEN not in repr(settings)
    assert KEY not in repr(settings)


def test_short_audit_key_rejected() -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env(AEGIS_AUDIT_KEY="short"))


def test_identities_required() -> None:
    with pytest.raises(ConfigError):
        Settings.from_env({"AEGIS_AUDIT_KEY": KEY})


@pytest.mark.parametrize(
    "raw",
    [
        '{"name": "a"}',
        json.dumps([{"name": "a", "role": "root", "token": TOKEN}]),
        json.dumps([{"name": "a", "role": "viewer", "token": "short"}]),
        json.dumps([{"name": "a b", "role": "viewer", "token": TOKEN}]),
        json.dumps([{"name": "a", "role": "viewer", "token": TOKEN, "extra": 1}]),
        "not json",
    ],
)
def test_invalid_identities_rejected(raw: str) -> None:
    with pytest.raises(ConfigError):
        parse_identities(raw, "")


def test_duplicate_tokens_rejected() -> None:
    raw = json.dumps(
        [{"name": "a", "role": "viewer", "token": TOKEN}, {"name": "b", "role": "analyst", "token": TOKEN}]
    )
    with pytest.raises(ConfigError):
        parse_identities(raw, "")


def test_error_messages_never_contain_tokens() -> None:
    raw = json.dumps([{"name": "bad name", "role": "viewer", "token": TOKEN}])
    with pytest.raises(ConfigError) as excinfo:
        parse_identities(raw, "")
    assert TOKEN not in str(excinfo.value)


def test_feature_flags_are_normalised() -> None:
    settings = Settings.from_env(env(AEGIS_FEATURES="core, F1"))
    assert settings.features == frozenset({"core", "f1"})


def test_booleans_are_strict() -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env(AEGIS_TWO_PERSON="maybe"))
    assert Settings.from_env(env(AEGIS_TWO_PERSON="true")).two_person is True


def test_integer_bounds() -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env(AEGIS_RATE_LIMIT="1"))


def test_secret_key_must_differ_from_audit_key() -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env(AEGIS_SECRET_KEY=KEY))


def test_llm_enabled_requires_endpoint() -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env(AEGIS_LLM_ENABLED="true"))


def test_read_env_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("# comment\nAEGIS_PORT=8000\nlowercase=ignored\nAEGIS_EMPTY=\n", encoding="utf-8")
    assert read_env_file(path) == {"AEGIS_PORT": "8000", "AEGIS_EMPTY": ""}
