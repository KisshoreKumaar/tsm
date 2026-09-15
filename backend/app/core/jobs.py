"""Persisted background jobs: lanes, supersession, cooperative cancellation and restart recovery.

Handlers run outside any transaction (LLM calls are slow). A handler returns a `JobOutcome`; its optional
`apply(session)` callback runs in the same transaction that marks the job SUCCEEDED, so results and the
job's audit record commit atomically. Lifecycle transitions are audited; transient progress is not.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from app.core.audit import AuditLog
from app.core.db import Database, Session
from app.core.errors import CapacityError
from app.core.jsonutil import canonical_json, loads_stored
from app.core.sse import EventBus
from app.core.timeutil import Clock, iso

logger = logging.getLogger("aegis.jobs")

LANES = ("default", "ai")
MAX_PAYLOAD_BYTES = 256_000
MAX_PENDING_PER_LANE = 500
MAX_ATTEMPTS = 3
WORKER_ACTOR = "system:worker"


class JobError(Exception):
    """A handler failure whose message is safe to show to users."""


class JobCancelled(Exception):
    pass


@dataclass(frozen=True)
class Job:
    id: str
    kind: str
    lane: str
    status: str
    priority: int
    dedup_key: str | None
    subject_type: str | None
    subject_id: str | None
    subject_revision: int | None
    payload: dict[str, Any]
    result: dict[str, Any] | None
    error: str | None
    progress: dict[str, Any] | None
    actor: str
    attempts: int
    cancel_requested: bool
    run_after: str
    created_at: str
    started_at: str | None
    finished_at: str | None

    @classmethod
    def from_row(cls, row: Any) -> Job:
        return cls(
            id=row["id"],
            kind=row["kind"],
            lane=row["lane"],
            status=row["status"],
            priority=row["priority"],
            dedup_key=row["dedup_key"],
            subject_type=row["subject_type"],
            subject_id=row["subject_id"],
            subject_revision=row["subject_revision"],
            payload=loads_stored(row["payload"]) or {},
            result=loads_stored(row["result"]),
            error=row["error"],
            progress=loads_stored(row["progress"]),
            actor=row["actor"],
            attempts=row["attempts"],
            cancel_requested=bool(row["cancel_requested"]),
            run_after=row["run_after"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )

    def public(self) -> dict[str, Any]:
        fields = (
            "id",
            "kind",
            "lane",
            "status",
            "subject_type",
            "subject_id",
            "subject_revision",
            "result",
            "error",
            "progress",
            "actor",
            "attempts",
            "run_after",
            "created_at",
            "started_at",
            "finished_at",
        )
        return {name: getattr(self, name) for name in fields}


@dataclass
class JobOutcome:
    result: dict[str, Any]
    apply: Callable[[Session], None] | None = None


JobHandler = Callable[[Any, Job], "JobOutcome | Mapping[str, Any] | None"]


class JobQueue:
    def __init__(self, db: Database, audit: AuditLog, clock: Clock, bus: EventBus) -> None:
        self._db = db
        self._audit = audit
        self._clock = clock
        self._bus = bus
        self._handlers: dict[str, tuple[JobHandler, str]] = {}
        self._wake = {lane: threading.Event() for lane in LANES}

    # -- registration -------------------------------------------------------------------------------

    def register(self, kind: str, handler: JobHandler, lane: str = "default") -> None:
        if lane not in LANES:
            raise ValueError(f"Unknown job lane: {lane}")
        if kind in self._handlers:
            raise ValueError(f"Duplicate job kind: {kind}")
        self._handlers[kind] = (handler, lane)

    @property
    def kinds(self) -> frozenset[str]:
        return frozenset(self._handlers)

    def _kinds_for(self, lane: str) -> list[str]:
        return sorted(kind for kind, (_, kind_lane) in self._handlers.items() if kind_lane == lane)

    # -- producing ----------------------------------------------------------------------------------

    def enqueue(
        self,
        session: Session,
        kind: str,
        payload: Mapping[str, Any],
        actor: str,
        *,
        subject: tuple[str, str, int | None] | None = None,
        dedup_key: str | None = None,
        priority: int = 100,
        delay_seconds: float = 0.0,
    ) -> str:
        if kind not in self._handlers:
            raise ValueError(f"Unknown job kind: {kind}")
        _, lane = self._handlers[kind]
        body = canonical_json(dict(payload))
        if len(body.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise CapacityError("Job payload is too large")
        pending = session.scalar(
            "SELECT count(*) FROM jobs WHERE lane = ? AND status IN ('QUEUED', 'RUNNING')", (lane,)
        )
        if int(pending) >= MAX_PENDING_PER_LANE:
            raise CapacityError("The job queue is full; try again shortly")
        now = self._clock.now()
        if dedup_key:
            for row in session.all("SELECT id FROM jobs WHERE dedup_key = ? AND status = 'QUEUED'", (dedup_key,)):
                session.execute(
                    "UPDATE jobs SET status = 'CANCELLED', error = ?, finished_at = ? WHERE id = ?",
                    ("Superseded by a newer request", iso(now), row["id"]),
                )
                self._audit.append(
                    session,
                    "job.cancelled",
                    actor,
                    {"job_id": row["id"], "reason": "superseded"},
                    subject=("job", row["id"]),
                )
            session.execute(
                "UPDATE jobs SET cancel_requested = 1 WHERE dedup_key = ? AND status = 'RUNNING'", (dedup_key,)
            )
        job_id = str(uuid.uuid4())
        subject_type, subject_id, subject_revision = subject if subject else (None, None, None)
        session.execute(
            "INSERT INTO jobs (id, kind, lane, status, priority, dedup_key, subject_type, subject_id, "
            "subject_revision, payload, actor, attempts, cancel_requested, run_after, created_at) "
            "VALUES (?, ?, ?, 'QUEUED', ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)",
            (
                job_id,
                kind,
                lane,
                priority,
                dedup_key,
                subject_type,
                subject_id,
                subject_revision,
                body,
                actor,
                iso(now + timedelta(seconds=delay_seconds)),
                iso(now),
            ),
        )
        self._audit.append(
            session,
            "job.enqueued",
            actor,
            {"job_id": job_id, "kind": kind, "lane": lane, "subject_type": subject_type, "subject_id": subject_id},
            subject=("job", job_id),
        )

        def notify() -> None:
            self._wake[lane].set()
            self._publish(job_id, kind, "QUEUED", subject_type, subject_id)

        session.after_commit(notify)
        return job_id

    def request_cancel(self, session: Session, job_id: str, actor: str, reason: str) -> bool:
        row = session.one("SELECT kind, status, subject_type, subject_id FROM jobs WHERE id = ?", (job_id,))
        if row is None or row["status"] not in ("QUEUED", "RUNNING"):
            return False
        if row["status"] == "QUEUED":
            session.execute(
                "UPDATE jobs SET status = 'CANCELLED', error = ?, finished_at = ? WHERE id = ?",
                (reason[:500], iso(self._clock.now()), job_id),
            )
        else:
            session.execute("UPDATE jobs SET cancel_requested = 1 WHERE id = ?", (job_id,))
        self._audit.append(
            session,
            "job.cancelled",
            actor,
            {"job_id": job_id, "reason": reason[:500], "pending_stop": row["status"] == "RUNNING"},
            subject=("job", job_id),
        )
        status = "CANCELLED" if row["status"] == "QUEUED" else "RUNNING"
        session.after_commit(lambda: self._publish(job_id, row["kind"], status, row["subject_type"], row["subject_id"]))
        return True

    # -- consuming ----------------------------------------------------------------------------------

    def claim(self, lane: str = "default", *, ignore_schedule: bool = False) -> Job | None:
        kinds = self._kinds_for(lane)
        if not kinds:
            return None
        now = iso(self._clock.now())
        marks = ",".join("?" * len(kinds))
        sql = f"SELECT id FROM jobs WHERE lane = ? AND status = 'QUEUED' AND kind IN ({marks})"
        params: list[Any] = [lane, *kinds]
        if not ignore_schedule:
            sql += " AND run_after <= ?"
            params.append(now)
        sql += " ORDER BY priority, run_after, created_at, rowid LIMIT 1"  # FIFO for same-timestamp jobs
        with self._db.read() as reader:
            if reader.one(sql, params) is None:
                return None
        with self._db.write() as session:
            row = session.one(sql, params)
            if row is None:
                return None
            session.execute(
                "UPDATE jobs SET status = 'RUNNING', attempts = attempts + 1, started_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            job = self._load(session, row["id"])
            self._audit.append(
                session,
                "job.started",
                WORKER_ACTOR,
                {"job_id": job.id, "kind": job.kind, "attempt": job.attempts},
                subject=("job", job.id),
            )
            session.after_commit(lambda: self._publish(job.id, job.kind, "RUNNING", job.subject_type, job.subject_id))
        return job

    def execute(self, ctx: Any, job: Job) -> None:
        handler, _ = self._handlers[job.kind]
        try:
            if self.is_cancel_requested(job.id):
                raise JobCancelled
            produced = handler(ctx, job)
            outcome = produced if isinstance(produced, JobOutcome) else JobOutcome(result=dict(produced or {}))
            self._complete(job, outcome)
        except JobCancelled:
            self._finish(job, "CANCELLED", "Cancelled before completion")
        except JobError as exc:
            self._finish(job, "FAILED", str(exc)[:500])
        except Exception:
            logger.exception("Job %s (%s) failed", job.id, job.kind)
            self._finish(job, "FAILED", "The job failed unexpectedly; details are in the server log")

    def _complete(self, job: Job, outcome: JobOutcome) -> None:
        with self._db.write() as session:
            row = session.one("SELECT status, cancel_requested FROM jobs WHERE id = ?", (job.id,))
            if row is None or row["status"] != "RUNNING":
                return
            if row["cancel_requested"]:
                raise JobCancelled
            if outcome.apply is not None:
                outcome.apply(session)
            session.execute(
                "UPDATE jobs SET status = 'SUCCEEDED', result = ?, finished_at = ? WHERE id = ?",
                (canonical_json(outcome.result), iso(self._clock.now()), job.id),
            )
            self._audit.append(
                session, "job.succeeded", WORKER_ACTOR, {"job_id": job.id, "kind": job.kind}, subject=("job", job.id)
            )
            session.after_commit(lambda: self._publish(job.id, job.kind, "SUCCEEDED", job.subject_type, job.subject_id))

    def _finish(self, job: Job, status: str, error: str) -> None:
        with self._db.write() as session:
            row = session.one("SELECT status FROM jobs WHERE id = ?", (job.id,))
            if row is None or row["status"] not in ("QUEUED", "RUNNING"):
                return
            session.execute(
                "UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE id = ?",
                (status, error, iso(self._clock.now()), job.id),
            )
            action = "job.failed" if status == "FAILED" else "job.cancelled"
            self._audit.append(
                session,
                action,
                WORKER_ACTOR,
                {"job_id": job.id, "kind": job.kind, "error": error},
                subject=("job", job.id),
            )
            session.after_commit(lambda: self._publish(job.id, job.kind, status, job.subject_type, job.subject_id))

    def recover(self) -> int:
        """Called at startup: interrupted RUNNING jobs are requeued (or failed after MAX_ATTEMPTS)."""
        with self._db.write() as session:
            rows = session.all("SELECT id, kind, attempts, cancel_requested FROM jobs WHERE status = 'RUNNING'")
            now = iso(self._clock.now())
            for row in rows:
                if row["cancel_requested"]:
                    session.execute(
                        "UPDATE jobs SET status = 'CANCELLED', error = ?, finished_at = ? WHERE id = ?",
                        ("Cancelled during restart", now, row["id"]),
                    )
                    action, body = "job.cancelled", {"job_id": row["id"], "reason": "cancel requested before restart"}
                elif row["attempts"] >= MAX_ATTEMPTS:
                    session.execute(
                        "UPDATE jobs SET status = 'FAILED', error = ?, finished_at = ? WHERE id = ?",
                        ("Interrupted too many times", now, row["id"]),
                    )
                    action, body = "job.failed", {"job_id": row["id"], "error": "interrupted too many times"}
                else:
                    session.execute("UPDATE jobs SET status = 'QUEUED', started_at = NULL WHERE id = ?", (row["id"],))
                    action, body = "job.requeued", {"job_id": row["id"], "kind": row["kind"]}
                self._audit.append(session, action, "system", body, subject=("job", row["id"]))
        return len(rows)

    # -- inspection ---------------------------------------------------------------------------------

    def _load(self, session: Session, job_id: str) -> Job:
        row = session.one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if row is None:
            raise KeyError(job_id)
        return Job.from_row(row)

    def get(self, job_id: str) -> Job | None:
        with self._db.read() as session:
            row = session.one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        return Job.from_row(row) if row else None

    def is_cancel_requested(self, job_id: str) -> bool:
        with self._db.read() as session:
            row = session.one("SELECT status, cancel_requested FROM jobs WHERE id = ?", (job_id,))
        return row is None or bool(row["cancel_requested"]) or row["status"] == "CANCELLED"

    def queue_position(self, job_id: str) -> int | None:
        with self._db.read() as session:
            row = session.one(
                "SELECT lane, status, priority, run_after, created_at, rowid AS seq FROM jobs WHERE id = ?", (job_id,)
            )
            if row is None or row["status"] != "QUEUED":
                return None
            ahead = session.scalar(
                "SELECT count(*) FROM jobs WHERE lane = ? AND (status = 'RUNNING' OR "
                "(status = 'QUEUED' AND (priority, run_after, created_at, rowid) < (?, ?, ?, ?)))",
                (row["lane"], row["priority"], row["run_after"], row["created_at"], row["seq"]),
            )
        return int(ahead) + 1

    def pending_count(self, lane: str) -> int:
        with self._db.read() as session:
            return int(session.scalar("SELECT count(*) FROM jobs WHERE lane = ? AND status = 'QUEUED'", (lane,)))

    def publish_progress(self, job: Job, progress: Mapping[str, Any]) -> None:
        """Transient progress (e.g. streamed tokens) for live clients; not persisted or audited."""
        self._bus.publish(
            "job.progress",
            {
                "job_id": job.id,
                "kind": job.kind,
                "subject_type": job.subject_type,
                "subject_id": job.subject_id,
                **progress,
            },
        )

    def _publish(self, job_id: str, kind: str, status: str, subject_type: str | None, subject_id: str | None) -> None:
        self._bus.publish(
            "job.updated",
            {"job_id": job_id, "kind": kind, "status": status, "subject_type": subject_type, "subject_id": subject_id},
        )

    # -- synchronous execution (tests, scripts) and waiting -----------------------------------------

    def run_pending(
        self,
        ctx: Any,
        *,
        lanes: Sequence[str] = LANES,
        max_jobs: int = 1_000,
        ignore_schedule: bool = True,
    ) -> int:
        executed = 0
        while executed < max_jobs:
            progressed = False
            for lane in lanes:
                job = self.claim(lane, ignore_schedule=ignore_schedule)
                if job is not None:
                    self.execute(ctx, job)
                    executed += 1
                    progressed = True
            if not progressed:
                break
        return executed

    def wait_for_work(self, lane: str, timeout: float) -> None:
        event = self._wake[lane]
        event.wait(timeout)
        event.clear()

    def wake_all(self) -> None:
        for event in self._wake.values():
            event.set()


class Worker:
    """Background threads that claim and execute jobs, one pool per lane."""

    def __init__(self, queue: JobQueue, ctx: Any, lanes: Mapping[str, int], poll_seconds: float = 0.5) -> None:
        self._queue = queue
        self._ctx = ctx
        self._lanes = dict(lanes)
        self._poll = poll_seconds
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for lane, count in self._lanes.items():
            for index in range(count):
                thread = threading.Thread(target=self._run, args=(lane,), name=f"aegis-{lane}-{index}", daemon=True)
                thread.start()
                self._threads.append(thread)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._queue.wake_all()
        for thread in self._threads:
            thread.join(timeout)
        self._threads.clear()

    def _run(self, lane: str) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.claim(lane)
            except Exception:
                logger.exception("Worker failed to claim a job on lane %s", lane)
                self._stop.wait(self._poll)
                continue
            if job is None:
                self._queue.wait_for_work(lane, self._poll)
                continue
            self._queue.execute(self._ctx, job)
