"""Ollama native chat API (`/api/chat`) with per-request overrides for context, output length and stop sequences.

The measured `aegis-fast` Modelfile uses num_ctx 1024, num_predict 55 and stop "\\n\\n", which would truncate JSON
answers; every request therefore sets `num_ctx`, `num_predict`, an empty `stop` list and `format: json`.
"""

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


def normalize_ollama_base(url: str) -> str:
    base = url.rstrip("/")
    for suffix in ("/api", "/v1"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


class OllamaProvider(HttpProvider):
    api_type = "ollama"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.base_url = normalize_ollama_base(self.base_url)

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
            "stream": stream,
            "options": {
                "num_ctx": self.context_tokens,
                "num_predict": self._budget(max_tokens),
                "temperature": 0,
                "stop": [],
            },
        }
        if self.json_mode:
            body["format"] = "json"
        url = f"{self.base_url}/api/chat"
        started = time.monotonic()
        first_token: float | None = None
        pieces: list[str] = []
        final: dict[str, Any] = {}
        try:
            with self._client(timeout) as client:
                if stream:
                    with client.stream("POST", url, json=body, headers=self._headers()) as response:
                        check_status(response)
                        for line in response.iter_lines():
                            if not line.strip():
                                continue
                            data = json.loads(line)
                            piece = (data.get("message") or {}).get("content") or ""
                            if piece:
                                first_token = first_token or time.monotonic()
                                pieces.append(piece)
                                if on_token is not None:
                                    on_token(piece)
                            if data.get("done"):
                                final = data
                                break
                else:
                    response = client.post(url, json=body, headers=self._headers())
                    check_status(response)
                    final = response.json()
                    pieces.append(str((final.get("message") or {}).get("content") or ""))
                    first_token = time.monotonic()
        except ProviderError:
            raise
        except httpx.HTTPError as exc:
            raise transport_error(exc) from None
        except (ValueError, KeyError, TypeError):
            raise ProviderUnavailable("The provider returned a response AEGIS could not parse") from None
        text = "".join(pieces)
        return Completion(
            text=text,
            provider_id=self.provider_id,
            model=self.model,
            input_tokens=int(final.get("prompt_eval_count") or estimate_input_tokens(messages)),
            output_tokens=int(final.get("eval_count") or estimate_tokens(text)),
            latency_seconds=time.monotonic() - started,
            time_to_first_token_seconds=(first_token - started) if first_token else None,
            finish_reason=str(final.get("done_reason") or "stop"),
        )
