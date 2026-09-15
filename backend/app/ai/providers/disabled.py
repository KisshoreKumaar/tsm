"""Provider used when no LLM is enabled. Every AI task falls back to its deterministic result."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.ai.providers.base import ChatMessage, Completion, ProviderDisabled, TokenCallback


class DisabledProvider:
    provider_id = "disabled"
    model = "none"
    context_tokens = 0
    max_output_tokens = 0

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        output_schema: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
        stream: bool = False,
        on_token: TokenCallback | None = None,
    ) -> Completion:
        raise ProviderDisabled("The LLM is disabled; deterministic results are shown instead")
