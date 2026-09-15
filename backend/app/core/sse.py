"""In-process publish/subscribe for live updates, delivered to browsers as Server-Sent Events.

Payloads carry identifiers and statuses only; clients re-fetch details through permission-checked routes.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import threading
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any

from app.core.timeutil import utc_now_iso

Message = dict[str, Any]


@dataclass(eq=False)
class Subscription:
    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue[Message]
    topics: frozenset[str] | None


def _matches(event_type: str, topics: frozenset[str]) -> bool:
    return any(event_type == topic or event_type.startswith(topic + ".") for topic in topics)


def _offer(queue: asyncio.Queue[Message], message: Message) -> None:
    try:
        queue.put_nowait(message)
    except asyncio.QueueFull:
        with suppress(asyncio.QueueEmpty):
            queue.get_nowait()  # drop the oldest; clients re-sync by re-fetching
        queue.put_nowait(message)


class EventBus:
    def __init__(self, history: int = 500, queue_size: int = 1000) -> None:
        self._lock = threading.Lock()
        self._subscribers: set[Subscription] = set()
        self._history: deque[Message] = deque(maxlen=history)
        self._ids = itertools.count(1)
        self._queue_size = queue_size

    def publish(self, event_type: str, data: dict[str, Any]) -> None:
        with self._lock:
            message: Message = {"id": next(self._ids), "type": event_type, "ts": utc_now_iso(), "data": data}
            self._history.append(message)
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            if subscriber.topics is not None and not _matches(event_type, subscriber.topics):
                continue
            try:
                subscriber.loop.call_soon_threadsafe(_offer, subscriber.queue, message)
            except RuntimeError:  # event loop closed
                self._discard(subscriber)

    def _discard(self, subscriber: Subscription) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)

    @contextmanager
    def subscribe(self, topics: Iterable[str] | None = None) -> Iterator[Subscription]:
        subscriber = Subscription(
            loop=asyncio.get_running_loop(),
            queue=asyncio.Queue(self._queue_size),
            topics=frozenset(topics) if topics else None,
        )
        with self._lock:
            self._subscribers.add(subscriber)
        try:
            yield subscriber
        finally:
            self._discard(subscriber)

    def recent(self, event_type: str | None = None) -> list[Message]:
        with self._lock:
            messages = list(self._history)
        if event_type is None:
            return messages
        return [m for m in messages if m["type"] == event_type or m["type"].startswith(event_type + ".")]

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


def format_sse(message: Message) -> bytes:
    data = json.dumps(message["data"], separators=(",", ":"), ensure_ascii=False)
    return f"id: {message['id']}\nevent: {message['type']}\ndata: {data}\n\n".encode()


async def event_stream(
    bus: EventBus,
    *,
    topics: Iterable[str] | None = None,
    heartbeat_seconds: float = 15.0,
    max_events: int | None = None,
    is_disconnected: Callable[[], Awaitable[bool]] | None = None,
    transform: Callable[[Message], Message | None] | None = None,
) -> AsyncIterator[bytes]:
    with bus.subscribe(topics) as subscription:
        yield b": connected\n\n"
        sent = 0
        while True:
            if is_disconnected is not None and await is_disconnected():
                return
            try:
                message = await asyncio.wait_for(subscription.queue.get(), timeout=heartbeat_seconds)
            except TimeoutError:
                yield b": keep-alive\n\n"
                continue
            if transform is not None:
                transformed = transform(message)
                if transformed is None:
                    continue
                message = transformed
            yield format_sse(message)
            sent += 1
            if max_events is not None and sent >= max_events:
                return
