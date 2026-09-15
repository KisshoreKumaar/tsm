from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.context import AppContext
from app.core.errors import CapacityError
from app.core.jobs import MAX_ATTEMPTS, Worker
from app.core.timeutil import ManualClock
from app.features.core import FEATURE as CORE
from app.main import create_app
from tests.support import EXAMPLE_FEATURE, auth, make_settings


@pytest.fixture
def job_app(tmp_path: Path, clock: ManualClock):  # type: ignore[no-untyped-def]
    return create_app(make_settings(tmp_path), features=(CORE, EXAMPLE_FEATURE), clock=clock)


@pytest.fixture
def jctx(job_app) -> AppContext:  # type: ignore[no-untyped-def]
    context: AppContext = job_app.state.ctx
    return context


def enqueue(
    ctx: AppContext, kind: str = "example.echo", dedup: str | None = None, delay: float = 0.0, **payload: Any
) -> str:
    with ctx.db.write() as session:
        return ctx.jobs.enqueue(session, kind, payload, "tester", dedup_key=dedup, delay_seconds=delay)


def audit_actions(ctx: AppContext) -> list[str]:
    return [item["action"] for item in ctx.audit.page(ctx.db, limit=200)["items"]]


def test_enqueue_and_run(jctx: AppContext) -> None:
    job_id = enqueue(jctx, message="hello")
    assert jctx.jobs.get(job_id).status == "QUEUED"  # type: ignore[union-attr]
    assert jctx.jobs.run_pending(jctx) == 1
    job = jctx.jobs.get(job_id)
    assert job is not None
    assert job.status == "SUCCEEDED"
    assert job.result == {"echo": "hello"}
    actions = audit_actions(jctx)
    for expected in ("job.enqueued", "job.started", "job.succeeded", "example.echoed"):
        assert expected in actions
    assert jctx.audit.verify(jctx.db)["valid"]


def test_job_error_marks_failed_with_safe_message(jctx: AppContext) -> None:
    job_id = enqueue(jctx, fail=True)
    jctx.jobs.run_pending(jctx)
    job = jctx.jobs.get(job_id)
    assert job is not None and job.status == "FAILED"
    assert job.error == "requested failure"
    assert "example.echoed" not in audit_actions(jctx)  # apply() never ran


def test_unexpected_error_hides_internal_details(jctx: AppContext) -> None:
    job_id = enqueue(jctx, crash=True)
    jctx.jobs.run_pending(jctx)
    job = jctx.jobs.get(job_id)
    assert job is not None and job.status == "FAILED"
    assert "secret" not in (job.error or "")


def test_dedup_key_supersedes_queued_jobs(jctx: AppContext) -> None:
    first = enqueue(jctx, dedup="story:incident-1", message="old")
    second = enqueue(jctx, dedup="story:incident-1", message="new")
    assert jctx.jobs.get(first).status == "CANCELLED"  # type: ignore[union-attr]
    assert jctx.jobs.get(second).status == "QUEUED"  # type: ignore[union-attr]


def test_delayed_jobs_wait_for_their_schedule(jctx: AppContext, clock: ManualClock) -> None:
    enqueue(jctx, delay=60, message="later")
    assert jctx.jobs.claim("default") is None
    clock.advance(61)
    assert jctx.jobs.claim("default") is not None


def test_lanes_are_independent(jctx: AppContext) -> None:
    enqueue(jctx, kind="example.ai_echo", message="ai")
    assert jctx.jobs.claim("default") is None
    job = jctx.jobs.claim("ai")
    assert job is not None and job.lane == "ai"


def test_restart_recovery_requeues_running_jobs(jctx: AppContext) -> None:
    job_id = enqueue(jctx, message="x")
    assert jctx.jobs.claim("default") is not None
    assert jctx.jobs.recover() == 1
    assert jctx.jobs.get(job_id).status == "QUEUED"  # type: ignore[union-attr]
    assert "job.requeued" in audit_actions(jctx)


def test_recovery_fails_jobs_after_max_attempts(jctx: AppContext) -> None:
    job_id = enqueue(jctx, message="x")
    for _ in range(MAX_ATTEMPTS):
        assert jctx.jobs.claim("default") is not None
        jctx.jobs.recover()
    assert jctx.jobs.get(job_id).status == "FAILED"  # type: ignore[union-attr]


def test_cancel_while_running(jctx: AppContext) -> None:
    job_id = enqueue(jctx, message="x")
    job = jctx.jobs.claim("default")
    assert job is not None
    with jctx.db.write() as session:
        assert jctx.jobs.request_cancel(session, job_id, "tester", "no longer needed")
    jctx.jobs.execute(jctx, job)
    assert jctx.jobs.get(job_id).status == "CANCELLED"  # type: ignore[union-attr]


def test_queue_position(jctx: AppContext, clock: ManualClock) -> None:
    ids = []
    for index in range(3):
        ids.append(enqueue(jctx, message=str(index)))
        clock.advance(1)
    assert [jctx.jobs.queue_position(i) for i in ids] == [1, 2, 3]


def test_unknown_kind_and_oversized_payload_are_rejected(jctx: AppContext) -> None:
    with pytest.raises(ValueError, match="Unknown job kind"):
        enqueue(jctx, kind="nope")
    with pytest.raises(CapacityError):
        enqueue(jctx, message="x" * 300_000)


def test_worker_threads_execute_jobs(jctx: AppContext) -> None:
    worker = Worker(jctx.jobs, jctx, lanes={"default": 1}, poll_seconds=0.05)
    worker.start()
    try:
        job_id = enqueue(jctx, message="threaded")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            job = jctx.jobs.get(job_id)
            if job is not None and job.status == "SUCCEEDED":
                break
            time.sleep(0.02)
        assert jctx.jobs.get(job_id).status == "SUCCEEDED"  # type: ignore[union-attr]
    finally:
        worker.stop()


def test_job_endpoint(job_app, jctx: AppContext) -> None:  # type: ignore[no-untyped-def]
    job_id = enqueue(jctx, message="x")
    with TestClient(job_app) as client:
        response = client.get(f"/api/jobs/{job_id}", headers=auth("viewer"))
        assert response.status_code == 200
        assert response.json()["queue_position"] == 1
        assert client.get("/api/jobs/unknown", headers=auth("viewer")).status_code == 404
