"""Shared HTTP plumbing for remote LLM providers: bounded timeouts, no redirects, no proxies, safe error messages."""

from __future__ import annotations

from collections.abc import Sequence

import httpx

from app.ai.providers.base import ChatMessage, ProviderRejected, ProviderUnavailable, estimate_tokens


class HttpProvider:
    api_type = "http"

    def __init__(
        self,
        *,
        provider_id: str,
        model: str,
        base_url: str,
        api_key: str = "",
        context_tokens: int = 2048,
        max_output_tokens: int = 256,
        timeout_seconds: float = 180.0,
        json_mode: bool = True,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.context_tokens = context_tokens
        self.max_output_tokens = max_output_tokens
        self.timeout_seconds = timeout_seconds
        self.json_mode = json_mode
        self._api_key = api_key
        self._transport = transport

    def __repr__(self) -> str:  # never include the API key
        return f"{type(self).__name__}(provider_id={self.provider_id!r}, model={self.model!r})"

    def _client(self, timeout: float | None) -> httpx.Client:
        seconds = float(timeout or self.timeout_seconds)
        return httpx.Client(
            timeout=httpx.Timeout(seconds, connect=min(10.0, seconds)),
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _budget(self, max_tokens: int | None) -> int:
        return max(1, min(max_tokens or self.max_output_tokens, self.max_output_tokens))


def check_status(response: httpx.Response) -> None:
    status = response.status_code
    if status < 300:
        return
    if status < 400:
        raise ProviderRejected("The provider redirected the request; redirects are not followed")
    if status in (401, 403):
        raise ProviderRejected("The provider rejected the credentials; check the API key")
    if status == 404:
        raise ProviderRejected("The model or endpoint was not found; check the base URL and model name")
    if status == 429:
        raise ProviderUnavailable("The provider is rate limiting requests")
    if status < 500:
        raise ProviderRejected(f"The provider rejected the request (HTTP {status})")
    raise ProviderUnavailable(f"The provider returned a server error (HTTP {status})")


def transport_error(exc: httpx.HTTPError) -> ProviderUnavailable:
    if isinstance(exc, httpx.TimeoutException):
        return ProviderUnavailable("The provider did not respond before the timeout")
    return ProviderUnavailable("Could not connect to the provider")


def estimate_input_tokens(messages: Sequence[ChatMessage]) -> int:
    return sum(estimate_tokens(message.content) for message in messages)
