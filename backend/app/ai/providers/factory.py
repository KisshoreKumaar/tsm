"""Provider configuration, presets and construction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from app.ai.providers.base import LLMProvider
from app.ai.providers.ollama import OllamaProvider
from app.ai.providers.openai_compat import OpenAICompatibleProvider


@dataclass(frozen=True)
class ProviderConfig:
    id: str
    name: str
    api_type: str
    base_url: str
    model: str
    api_key: str = field(default="", repr=False)
    context_tokens: int = 2048
    max_output_tokens: int = 256
    timeout_seconds: float = 180.0
    json_mode: bool = True
    redact: bool = True
    enabled: bool = True
    priority: int = 100
    source: str = "settings"


PRESETS: list[dict[str, Any]] = [
    {
        "id": "ollama-ec2",
        "name": "Ollama on EC2 (aegis-fast)",
        "api_type": "ollama",
        "base_url": "http://13.235.64.41:11434",
        "model": "aegis-fast",
        "context_tokens": 2048,
        "max_output_tokens": 160,
        "timeout_seconds": 180,
        "requires_key": False,
        "redact": True,
        "note": "Measured ~3.9 tokens/s. The Modelfile defaults (num_ctx 1024, num_predict 55, stop on blank line) are "
        "overridden per request. The server answers without authentication over plain HTTP; restrict its security group.",
    },
    {
        "id": "groq",
        "name": "Groq (llama-3.1-8b-instant)",
        "api_type": "openai",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.1-8b-instant",
        "context_tokens": 8192,
        "max_output_tokens": 600,
        "timeout_seconds": 60,
        "requires_key": True,
        "redact": True,
        "note": "OpenAI-compatible endpoint. Requires a Groq API key.",
    },
    {
        "id": "gemini",
        "name": "Google Gemini (OpenAI-compatible endpoint)",
        "api_type": "openai",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-1.5-flash",
        "context_tokens": 32000,
        "max_output_tokens": 800,
        "timeout_seconds": 60,
        "requires_key": True,
        "redact": True,
        "note": "Google may have retired gemini-1.5-flash; if Test connection reports the model was not found, enter a "
        "current Flash model name.",
    },
    {
        "id": "custom",
        "name": "Custom OpenAI-compatible endpoint",
        "api_type": "openai",
        "base_url": "",
        "model": "",
        "context_tokens": 4096,
        "max_output_tokens": 600,
        "timeout_seconds": 120,
        "requires_key": False,
        "redact": True,
        "note": "Any server exposing /chat/completions (vLLM, llama.cpp server, LM Studio, Ollama /v1).",
    },
]


def build_provider(config: ProviderConfig, transport: httpx.BaseTransport | None = None) -> LLMProvider:
    kwargs: dict[str, Any] = {
        "provider_id": config.id,
        "model": config.model,
        "base_url": config.base_url,
        "api_key": config.api_key,
        "context_tokens": config.context_tokens,
        "max_output_tokens": config.max_output_tokens,
        "timeout_seconds": config.timeout_seconds,
        "json_mode": config.json_mode,
        "transport": transport,
    }
    if config.api_type == "ollama":
        return OllamaProvider(**kwargs)
    if config.api_type == "openai":
        return OpenAICompatibleProvider(**kwargs)
    raise ValueError(f"Unsupported provider API type: {config.api_type}")
