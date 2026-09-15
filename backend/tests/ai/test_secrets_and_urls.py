from __future__ import annotations

import pytest

from app.ai.secrets import SecretBox, SecretError, key_hint
from app.ai.urlguard import UrlRejected, validate_base_url

SECRET_KEY = "s" * 40
API_KEY = "gsk_live_abcdefghijklmnopqrstuvwxyz"


def test_round_trip_and_context_binding() -> None:
    box = SecretBox(SECRET_KEY)
    token = box.encrypt(API_KEY, "provider-1")
    assert API_KEY not in token and token.startswith("v1:")
    assert box.decrypt(token, "provider-1") == API_KEY
    assert box.encrypt(API_KEY, "provider-1") != token  # random nonce
    with pytest.raises(SecretError):
        box.decrypt(token, "provider-2")


def test_wrong_secret_key_fails_safely() -> None:
    token = SecretBox(SECRET_KEY).encrypt(API_KEY, "p")
    with pytest.raises(SecretError) as excinfo:
        SecretBox("t" * 40).decrypt(token, "p")
    assert API_KEY not in str(excinfo.value)
    with pytest.raises(SecretError):
        SecretBox(SECRET_KEY).decrypt("garbage", "p")
    with pytest.raises(SecretError):
        SecretBox("short")
    assert "s" * 40 not in repr(SecretBox(SECRET_KEY))


def test_key_hint() -> None:
    assert key_hint(API_KEY) == "…wxyz"
    assert key_hint("short") == "set"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://13.235.64.41:11434/", "http://13.235.64.41:11434"),
        ("https://api.groq.com/openai/v1", "https://api.groq.com/openai/v1"),
        ("http://127.0.0.1:11434", "http://127.0.0.1:11434"),
        ("http://[::1]:8080/v1/", "http://[::1]:8080/v1"),
        (
            "HTTPS://Generativelanguage.GoogleAPIs.com/v1beta/openai",
            "https://generativelanguage.googleapis.com/v1beta/openai",
        ),
    ],
)
def test_accepted_urls(url: str, expected: str) -> None:
    assert validate_base_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal/computeMetadata/v1",
        "http://[fe80::1]/",
        "http://0.0.0.0:11434",
        "http://user:pass@example.com",
        "https://example.com/v1?key=abc",
        "http://",
        "http://example.com:99999",
        "https://" + "a" * 600 + ".com",
    ],
)
def test_rejected_urls(url: str) -> None:
    with pytest.raises(UrlRejected):
        validate_base_url(url)


def test_allowed_hosts_pinning() -> None:
    assert validate_base_url("https://api.groq.com/openai/v1", ["api.groq.com"])
    with pytest.raises(UrlRejected):
        validate_base_url("https://evil.example/v1", ["api.groq.com"])
