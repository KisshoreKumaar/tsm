"""Runs scenarios instantly or as a staged replay (persisted delayed jobs, so replays survive restarts)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from app.core.auth import Principal
from app.core.errors import NotFound
from app.core.jobs import Job, JobOutcome
from app.core.timeutil import iso, parse_iso
from app.demo.scenarios import SCENARIOS, Scenario, materialize, step_start_offsets


class DemoService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def scenarios(self) -> dict[str, Any]:
        return {
            "scenarios": [s.public() for s in SCENARIOS.values()],
            "replay_interval_seconds": self._ctx.settings.replay_interval_seconds,
        }

    def _scenario(self, scenario_id: str) -> Scenario:
        scenario = SCENARIOS.get(scenario_id)
        if scenario is None:
            raise NotFound(f"Unknown scenario; choose one of: {', '.join(SCENARIOS)}")
        return scenario

    def run(self, scenario_id: str, mode: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        scenario = self._scenario(scenario_id)
        run_id = uuid.uuid4().hex
        suffix = run_id[:6]
        steps = scenario.build(suffix)
        order = list(range(len(steps)))[::-1] if scenario.release_reversed else list(range(len(steps)))
        started = ctx.clock.now()
        with ctx.db.write() as session:
            session.execute(
                "INSERT INTO demo_runs (id, scenario, mode, suffix, steps, released, status, started_by, started_at) "
                "VALUES (?, ?, ?, ?, ?, 0, 'RUNNING', ?, ?)",
                (run_id, scenario.id, mode, suffix, len(steps), principal.name, iso(started)),
            )
            ctx.audit.append(
                session,
                "demo.started",
                principal.name,
                {"run_id": run_id, "scenario": scenario.id, "mode": mode, "suffix": suffix},
                subject=("demo_run", run_id),
            )
            if mode == "replay":
                interval = ctx.settings.replay_interval_seconds
                for release_index, step_index in enumerate(order):
                    ctx.jobs.enqueue(
                        session,
                        "demo.release",
                        {"run_id": run_id, "step_index": step_index, "release_index": release_index},
                        principal.name,
                        subject=("demo_run", run_id, None),
                        priority=50,
                        delay_seconds=release_index * interval,
                    )
        response: dict[str, Any] = {
            "run_id": run_id,
            "scenario": scenario.id,
            "mode": mode,
            "suffix": suffix,
            "steps": [{"label": s.label, "events": len(s.events)} for s in steps],
            "event_count": sum(len(s.events) for s in steps),
            "synthetic": True,
        }
        if mode == "replay":
            response["replay_interval_seconds"] = ctx.settings.replay_interval_seconds
            return response
        pipeline = ctx.service("pipeline")
        incident_ids: set[str] = set()
        gap = scenario.step_gap_seconds
        starts = step_start_offsets(steps, gap)
        total = starts[-1] + steps[-1].span if steps else 0.0
        base = started - timedelta(seconds=total + 1)
        for released, step_index in enumerate(order, start=1):
            raw = materialize(scenario, suffix, step_index, run_id[:12], base + timedelta(seconds=starts[step_index]))
            normalized = pipeline.validate(raw)
            with ctx.db.write() as session:
                outcome = pipeline.ingest(session, normalized, principal.name)
                incident_ids.update(outcome.incident_ids)
                self._mark_released(session, run_id, released, len(steps), principal.name)
        response["incident_ids"] = self._current_incidents(run_id, incident_ids)
        return response

    def _current_incidents(self, run_id: str, candidates: set[str]) -> list[str]:
        """Follow merges so callers see the canonical incident IDs."""
        with self._ctx.db.read() as session:
            resolved: set[str] = set()
            for incident_id in candidates:
                current = incident_id
                for _ in range(20):
                    merged_into = session.scalar("SELECT merged_into FROM incidents WHERE id = ?", (current,))
                    if not merged_into:
                        break
                    current = merged_into
                resolved.add(current)
        return sorted(resolved)

    def _mark_released(self, session: Any, run_id: str, released: int, total: int, actor: str) -> None:
        ctx = self._ctx
        done = released >= total
        session.execute(
            "UPDATE demo_runs SET released = ?, status = ?, finished_at = ? WHERE id = ?",
            (released, "COMPLETED" if done else "RUNNING", iso(ctx.clock.now()) if done else None, run_id),
        )
        if done:
            ctx.audit.append(session, "demo.completed", actor, {"run_id": run_id}, subject=("demo_run", run_id))
        session.after_commit(
            lambda: ctx.bus.publish("demo.progress", {"run_id": run_id, "released": released, "steps": total})
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            row = session.one("SELECT * FROM demo_runs WHERE id = ?", (run_id,))
            if row is None:
                raise NotFound("Unknown demo run")
            incident_rows = session.all(
                "SELECT DISTINCT i.id FROM incidents i WHERE i.status != 'MERGED' AND (i.asset LIKE ? ESCAPE '\\')",
                (f"%-{row['suffix']}%",),
            )
        return {**dict(row), "incident_ids": sorted(r["id"] for r in incident_rows)}

    def release(self, job: Job) -> JobOutcome:
        """Job handler: release one replay step with timestamps at (or just before) release time."""
        ctx = self._ctx
        payload = job.payload
        with ctx.db.read() as session:
            row = session.one("SELECT * FROM demo_runs WHERE id = ?", (payload["run_id"],))
        if row is None:
            return JobOutcome(result={"skipped": "unknown run"})
        scenario = self._scenario(row["scenario"])
        steps = scenario.build(row["suffix"])
        step_index = int(payload["step_index"])
        step = steps[step_index]
        now = ctx.clock.now()
        if scenario.release_reversed:
            interval = ctx.settings.replay_interval_seconds
            starts = step_start_offsets(steps, interval)
            total = starts[-1] + steps[-1].span
            step_base: datetime = (
                parse_iso(row["started_at"]) - timedelta(seconds=total + 1) + timedelta(seconds=starts[step_index])
            )
        else:
            step_base = now - timedelta(seconds=step.span)
        raw = materialize(scenario, row["suffix"], step_index, str(row["id"])[:12], step_base)
        pipeline = ctx.service("pipeline")
        normalized = pipeline.validate(raw)
        released = int(payload["release_index"]) + 1

        def apply(session: Any) -> None:
            pipeline.ingest(session, normalized, job.actor)
            self._mark_released(session, row["id"], released, len(steps), job.actor)

        return JobOutcome(result={"step": step.label, "events": len(raw), "released": released}, apply=apply)
