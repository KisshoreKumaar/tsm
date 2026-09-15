from __future__ import annotations

import pytest

from app.ai.providers import (
    ChatMessage,
    DisabledProvider,
    FakeProvider,
    ProviderDisabled,
    ProviderRejected,
    ProviderUnavailable,
)

MESSAGES = [ChatMessage("system", "You are a test."), ChatMessage("user", "Say hi")]


def test_fake_provider_returns_scripted_responses_in_order() -> None:
    provider = FakeProvider(['{"a":1}', '{"a":2}'])
    assert provider.complete(MESSAGES).text == '{"a":1}'
    assert provider.complete(MESSAGES, max_tokens=20).text == '{"a":2}'
    assert provider.calls[1]["max_tokens"] == 20
    assert provider.remaining == 0


def test_fake_provider_raises_scripted_exceptions() -> None:
    provider = FakeProvider([ProviderRejected("model not found")])
    with pytest.raises(ProviderRejected):
        provider.complete(MESSAGES)


def test_exhausted_script_behaves_like_an_unreachable_provider() -> None:
    with pytest.raises(ProviderUnavailable):
        FakeProvider().complete(MESSAGES)


def test_callable_responses_and_default() -> None:
    provider = FakeProvider([lambda messages: messages[-1].content.upper()], default="fallback")
    assert provider.complete(MESSAGES).text == "SAY HI"
    assert provider.complete(MESSAGES).text == "fallback"


def test_streaming_emits_tokens_that_join_to_the_text() -> None:
    provider = FakeProvider(['{"summary":"streamed output for the analyst"}'])
    chunks: list[str] = []
    completion = provider.complete(MESSAGES, stream=True, on_token=chunks.append)
    assert len(chunks) > 1
    assert "".join(chunks) == completion.text
    assert completion.output_tokens > 0


def test_disabled_provider_always_raises() -> None:
    with pytest.raises(ProviderDisabled):
        DisabledProvider().complete(MESSAGES)
