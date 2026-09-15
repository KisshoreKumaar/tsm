"""Remote providers against httpx.MockTransport. No real network is used."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from app.ai.providers import ChatMessage, ProviderRejected, ProviderUnavailable
from app.ai.providers.factory import PRESETS, ProviderConfig, build_provider
from app.ai.providers.ollama import OllamaProvider
from app.ai.providers.openai_compat import OpenAICompatibleProvider

MESSAGES = [ChatMessage("system", "Reply with JSON."), ChatMessage("user", "Say hi as JSON.")]
SECRET = "gsk_test_secret_value_1234567890"


def transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def ollama(handler: Callable[[httpx.Request], httpx.Response], **kwargs: object) -> OllamaProvider:
    values: dict[str, object] = {
        "provider_id": "ollama-ec2",
        "model": "aegis-fast",
        "base_url": "http://ollama.test:11434/v1/",
        "context_tokens": 2048,
        "max_output_tokens": 160,
        "timeout_seconds": 30,
        "transport": transport(handler),
    }
    values.update(kwargs)
    return OllamaProvider(**values)  # type: ignore[arg-type]


def openai(handler: Callable[[httpx.Request], httpx.Response], **kwargs: object) -> OpenAICompatibleProvider:
    values: dict[str, object] = {
        "provider_id": "groq",
        "model": "llama-3.1-8b-instant",
        "base_url": "https://api.groq.test/openai/v1",
        "api_key": SECRET,
        "context_tokens": 8192,
        "max_output_tokens": 600,
        "transport": transport(handler),
    }
    values.update(kwargs)
    return OpenAICompatibleProvider(**values)  # type: ignore[arg-type]


def test_ollama_sends_overrides_and_parses_response() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": '{"hi": true}'},
                "done": True,
                "done_reason": "stop",
                "eval_count": 7,
                "prompt_eval_count": 42,
            },
        )

    completion = ollama(handler).complete(MESSAGES, max_tokens=999)
    assert seen["url"] == "http://ollama.test:11434/api/chat"
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["options"] == {"num_ctx": 2048, "num_predict": 160, "temperature": 0, "stop": []}
    assert body["format"] == "json" and body["stream"] is False
    assert seen["auth"] is None
    assert completion.text == '{"hi": true}'
    assert (completion.input_tokens, completion.output_tokens) == (42, 7)


def test_ollama_streaming() -> None:
    lines = [
        {"message": {"content": '{"a":'}, "done": False},
        {"message": {"content": " 1}"}, "done": False},
        {"message": {"content": ""}, "done": True, "eval_count": 5, "prompt_eval_count": 10, "done_reason": "stop"},
    ]
    content = "\n".join(json.dumps(line) for line in lines).encode()
    tokens: list[str] = []
    completion = ollama(lambda _r: httpx.Response(200, content=content)).complete(
        MESSAGES, stream=True, on_token=tokens.append
    )
    assert tokens == ['{"a":', " 1}"]
    assert completion.text == '{"a": 1}'
    assert completion.output_tokens == 5
    assert completion.time_to_first_token_seconds is not None


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (404, ProviderRejected),
        (401, ProviderRejected),
        (302, ProviderRejected),
        (429, ProviderUnavailable),
        (503, ProviderUnavailable),
    ],
)
def test_http_status_mapping(status: int, error: type[Exception]) -> None:
    with pytest.raises(error):
        ollama(lambda _r: httpx.Response(status, headers={"location": "http://evil.test"})).complete(MESSAGES)


def test_connection_errors_and_garbage_are_unavailable() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(ProviderUnavailable):
        ollama(refuse).complete(MESSAGES)
    with pytest.raises(ProviderUnavailable):
        ollama(lambda _r: httpx.Response(200, content=b"not json")).complete(MESSAGES)


def test_openai_compatible_request_and_usage() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"ok": 1}'}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 30, "completion_tokens": 4},
            },
        )

    completion = openai(handler).complete(MESSAGES, max_tokens=100)
    assert seen["url"] == "https://api.groq.test/openai/v1/chat/completions"
    assert seen["auth"] == f"Bearer {SECRET}"
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["max_tokens"] == 100 and body["response_format"] == {"type": "json_object"}
    assert completion.text == '{"ok": 1}' and completion.output_tokens == 4


def test_openai_streaming_sse() -> None:
    chunks = [
        'data: {"choices":[{"delta":{"content":"{\\"x\\":"}}]}',
        'data: {"choices":[{"delta":{"content":" 2}"},"finish_reason":"stop"}]}',
        "data: [DONE]",
    ]
    tokens: list[str] = []
    completion = openai(lambda _r: httpx.Response(200, content="\n\n".join(chunks).encode())).complete(
        MESSAGES, stream=True, on_token=tokens.append
    )
    assert completion.text == '{"x": 2}' and tokens == ['{"x":', " 2}"]


def test_errors_and_repr_never_leak_the_key() -> None:
    provider = openai(lambda _r: httpx.Response(401, json={"error": f"bad key {SECRET}"}))
    with pytest.raises(ProviderRejected) as excinfo:
        provider.complete(MESSAGES)
    assert SECRET not in str(excinfo.value)
    assert SECRET not in repr(provider)
    assert SECRET not in repr(ProviderConfig("x", "x", "openai", "https://a.test", "m", api_key=SECRET))


def test_factory_and_presets() -> None:
    assert {p["id"] for p in PRESETS} == {"ollama-ec2", "groq", "gemini", "custom"}
    ollama_preset = next(p for p in PRESETS if p["id"] == "ollama-ec2")
    assert ollama_preset["max_output_tokens"] == 160 and ollama_preset["context_tokens"] == 2048
    config = ProviderConfig("p1", "Groq", "openai", "https://api.groq.test/openai/v1", "m", api_key=SECRET)
    assert isinstance(build_provider(config), OpenAICompatibleProvider)
    with pytest.raises(ValueError):
        build_provider(ProviderConfig("p2", "bad", "soap", "https://x.test", "m"))
