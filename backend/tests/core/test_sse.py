from __future__ import annotations

import asyncio
import threading

from app.core.sse import EventBus, event_stream, format_sse


def test_format_sse() -> None:
    chunk = format_sse({"id": 3, "type": "incident.updated", "data": {"incident_id": "abc"}})
    assert chunk == b'id: 3\nevent: incident.updated\ndata: {"incident_id":"abc"}\n\n'


def test_stream_delivers_messages_published_from_other_threads() -> None:
    bus = EventBus()

    async def consume() -> tuple[bytes, list[bytes]]:
        stream = event_stream(bus, max_events=2, heartbeat_seconds=5)
        connected = await stream.__anext__()  # subscription is registered once the stream starts

        def publish() -> None:
            bus.publish("incident.updated", {"n": 1})
            bus.publish("job.updated", {"n": 2})

        threading.Thread(target=publish).start()
        return connected, [chunk async for chunk in stream]

    connected, chunks = asyncio.run(consume())
    assert connected == b": connected\n\n"
    assert [c.split(b"\n")[1] for c in chunks] == [b"event: incident.updated", b"event: job.updated"]
    assert bus.subscriber_count == 0


def test_topic_filtering() -> None:
    bus = EventBus()

    async def consume() -> list[bytes]:
        stream = event_stream(bus, topics=["prediction"], max_events=1, heartbeat_seconds=5)
        await stream.__anext__()
        bus.publish("job.updated", {"ignored": True})
        bus.publish("prediction.observed", {"prediction_id": "p1"})
        return [chunk async for chunk in stream]

    chunks = asyncio.run(consume())
    assert len(chunks) == 1
    assert b"prediction.observed" in chunks[0]


def test_recent_history() -> None:
    bus = EventBus(history=2)
    for index in range(3):
        bus.publish("job.updated", {"i": index})
    assert [m["data"]["i"] for m in bus.recent("job")] == [1, 2]
