"""Deterministic scripted provider for tests and offline demos. Never touches the network."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Sequence
from typing import Any

from app.ai.providers.base import ChatMessage, Completion, ProviderUnavailable, TokenCallback, estimate_tokens

ScriptItem = str | Exception | Callable[[Sequence[ChatMessage]], str]


class FakeProvider:
    def __init__(
        self,
        responses: Sequence[ScriptItem] = (),
        *,
        provider_id: str = "fake",
        model: str = "fake-model",
        context_tokens: int = 4096,
        max_output_tokens: int = 512,
        default: ScriptItem | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.model = model
        self.context_tokens = context_tokens
        self.max_output_tokens = max_output_tokens
        self._responses: deque[ScriptItem] = deque(responses)
        self._default = default
        self.calls: list[dict[str, Any]] = []

    def push(self, *responses: ScriptItem) -> None:
        self._responses.extend(responses)

    @property
    def remaining(self) -> int:
        return len(self._responses)

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
        self.calls.append(
            {"messages": list(messages), "max_tokens": max_tokens, "stream": stream, "output_schema": output_schema}
        )
        if self._responses:
            item = self._responses.popleft()
        elif self._default is not None:
            item = self._default
        else:
            raise ProviderUnavailable("FakeProvider script exhausted")
        if isinstance(item, Exception):
            raise item
        text = item(messages) if callable(item) else item
        if stream and on_token is not None:
            for start in range(0, len(text), 8):
                on_token(text[start : start + 8])
        return Completion(
            text=text,
            provider_id=self.provider_id,
            model=self.model,
            input_tokens=sum(estimate_tokens(m.content) for m in messages),
            output_tokens=estimate_tokens(text),
            latency_seconds=0.0,
            time_to_first_token_seconds=0.0,
        )
