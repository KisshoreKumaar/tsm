"""LLM provider interface. Providers are called synchronously from worker threads."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

Role = Literal["system", "user", "assistant"]
TokenCallback = Callable[[str], None]


@dataclass(frozen=True)
class ChatMessage:
    role: Role
    content: str


@dataclass(frozen=True)
class Completion:
    text: str
    provider_id: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_seconds: float
    time_to_first_token_seconds: float | None = None
    finish_reason: str = "stop"

    @property
    def tokens_per_second(self) -> float | None:
        generation = self.latency_seconds - (self.time_to_first_token_seconds or 0.0)
        if self.output_tokens <= 0 or generation <= 0:
            return None
        return self.output_tokens / generation


class ProviderError(Exception):
    """Base provider failure. Messages are safe to display and never contain credentials."""


class ProviderUnavailable(ProviderError):
    """Connection failure, timeout or server error: try the next provider or fall back."""


class ProviderRejected(ProviderError):
    """The provider refused the request (authentication, unknown model, bad request)."""


class ProviderDisabled(ProviderError):
    """No LLM is enabled; callers use deterministic output."""


class LLMProvider(Protocol):
    provider_id: str
    model: str
    context_tokens: int
    max_output_tokens: int

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        output_schema: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
        stream: bool = False,
        on_token: TokenCallback | None = None,
    ) -> Completion: ...


def estimate_tokens(text: str) -> int:
    """Conservative heuristic (~4 characters per token) used for budgeting, never for billing."""
    return max(1, (len(text) + 3) // 4)
