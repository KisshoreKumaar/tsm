"""OpenAI-compatible chat completions (Groq, Gemini's OpenAI endpoint, vLLM, Ollama `/v1`, others)."""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any

import httpx

from app.ai.providers.base import (
    ChatMessage,
    Completion,
    ProviderError,
    ProviderUnavailable,
    TokenCallback,
    estimate_tokens,
)
from app.ai.providers.http_common import HttpProvider, check_status, estimate_input_tokens, transport_error


class OpenAICompatibleProvider(HttpProvider):
    api_type = "openai"

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
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": self._budget(max_tokens),
            "temperature": 0,
            "stream": stream,
        }
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}
        url = f"{self.base_url}/chat/completions"
        started = time.monotonic()
        first_token: float | None = None
        pieces: list[str] = []
        usage: dict[str, Any] = {}
        finish = "stop"
        try:
            with self._client(timeout) as client:
                if stream:
                    with client.stream("POST", url, json=body, headers=self._headers()) as response:
                        check_status(response)
                        for line in response.iter_lines():
                            line = line.strip()
                            if not line.startswith("data:"):
                                continue
                            payload = line[5:].strip()
                            if payload == "[DONE]":
                                break
                            data = json.loads(payload)
                            if data.get("usage"):
                                usage = data["usage"]
                            for choice in data.get("choices") or []:
                                piece = (choice.get("delta") or {}).get("content") or ""
                                if piece:
                                    first_token = first_token or time.monotonic()
                                    pieces.append(piece)
                                    if on_token is not None:
                                        on_token(piece)
                                finish = choice.get("finish_reason") or finish
                else:
                    response = client.post(url, json=body, headers=self._headers())
                    check_status(response)
                    data = response.json()
                    choice = (data.get("choices") or [{}])[0]
                    pieces.append(str((choice.get("message") or {}).get("content") or ""))
                    finish = choice.get("finish_reason") or finish
                    usage = data.get("usage") or {}
                    first_token = time.monotonic()
        except ProviderError:
            raise
        except httpx.HTTPError as exc:
            raise transport_error(exc) from None
        except (ValueError, KeyError, TypeError, IndexError):
            raise ProviderUnavailable("The provider returned a response AEGIS could not parse") from None
        text = "".join(pieces)
        return Completion(
            text=text,
            provider_id=self.provider_id,
            model=self.model,
            input_tokens=int(usage.get("prompt_tokens") or estimate_input_tokens(messages)),
            output_tokens=int(usage.get("completion_tokens") or estimate_tokens(text)),
            latency_seconds=time.monotonic() - started,
            time_to_first_token_seconds=(first_token - started) if first_token else None,
            finish_reason=str(finish),
        )
