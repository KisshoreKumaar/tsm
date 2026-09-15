"""ASGI middleware: security headers, per-client rate limiting and request body limits."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import PayloadTooLarge, error_body

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
APP_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
RATE_LIMIT_EXEMPT = frozenset({"/api/healthz"})


async def send_json(send: Send, status: int, body: dict[str, object], headers: Mapping[str, str] | None = None) -> None:
    payload = json.dumps(body).encode()
    raw_headers = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
    raw_headers.extend((k.lower().encode(), v.encode()) for k, v in (headers or {}).items())
    await send({"type": "http.response.start", "status": status, "headers": raw_headers})
    await send({"type": "http.response.body", "body": payload})


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_api = str(scope.get("path", "")).startswith("/api")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                defaults = {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Cross-Origin-Opener-Policy": "same-origin",
                    "Cross-Origin-Resource-Policy": "same-origin",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                    "Content-Security-Policy": API_CSP if is_api else APP_CSP,
                }
                if is_api:
                    defaults["Cache-Control"] = "no-store"
                for name, value in defaults.items():
                    if name not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RateLimiter:
    """Sliding one-minute window per key."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000) -> None:
        self.per_minute = per_minute
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int | None = None) -> bool:
        limit = limit or self.per_minute
        now = self._clock()
        with self._lock:
            if key not in self._buckets and len(self._buckets) >= self._max_keys:
                self._buckets = {k: v for k, v in self._buckets.items() if v and v[-1] > now - 60}
                if len(self._buckets) >= self._max_keys:
                    return False
            bucket = self._buckets.setdefault(key, deque())
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, per_minute: int) -> None:
        self.app = app
        self.limiter = RateLimiter(per_minute)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        if scope["type"] != "http" or not path.startswith("/api") or path in RATE_LIMIT_EXEMPT:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        ip = client[0] if client else "unknown"
        allowed = self.limiter.allow(f"ip:{ip}", self.limiter.per_minute * 3)
        auth = next((v for k, v in scope.get("headers", []) if k == b"authorization"), None)
        if allowed and auth:
            allowed = self.limiter.allow("tok:" + hashlib.sha256(auth).hexdigest()[:32])
        if not allowed:
            await send_json(
                send,
                429,
                error_body("rate_limited", "Request rate exceeded; retry in 60 seconds"),
                {"Retry-After": "60"},
            )
            return
        await self.app(scope, receive, send)


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, default_limit: int, overrides: Mapping[str, int] | None = None) -> None:
        self.app = app
        self.default_limit = default_limit
        self.overrides = dict(overrides or {})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH", "DELETE"):
            await self.app(scope, receive, send)
            return
        limit = self.overrides.get(str(scope.get("path", "")), self.default_limit)
        declared = next((v for k, v in scope.get("headers", []) if k == b"content-length"), None)
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                await send_json(send, 400, error_body("bad_request", "Invalid Content-Length"))
                return
            if size > limit:
                await send_json(send, 413, error_body("payload_too_large", f"Request body exceeds {limit} bytes"))
                return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise PayloadTooLarge(f"Request body exceeds {limit} bytes")
            return message

        await self.app(scope, limited_receive, send)
