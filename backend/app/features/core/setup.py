"""CORE service wiring. Later features extend the pipeline (suppression checks, listeners) in their own setup."""

from __future__ import annotations

from typing import Any

from app.core.jobs import Job, JobOutcome
from app.correlation.pipeline import IngestPipeline
from app.demo.service import DemoService
from app.detection.builtin import builtin_rules
from app.detection.catalog import default_catalog
from app.detection.engine import RuleEngine
from app.features.core.events import EventService
from app.features.core.incidents import IncidentService
from app.features.core.overview import OverviewService
from app.features.core.responses import ResponseService

CORE_AUDIT_ACTIONS = frozenset(
    {
        "events.ingested",
        "detections.suppressed",
        "incident.created",
        "incident.updated",
        "incident.merged",
        "incident.reopened",
        "incident.reviewed",
        "incident.note_added",
        "response.requested",
        "response.approved",
        "response.rejected",
        "response.executed",
        "response.cancelled",
        "response.expired",
        "demo.started",
        "demo.completed",
    }
)


def setup(ctx: Any) -> None:
    catalog = default_catalog()
    # LOG-001's stage comes from the verified catalog (ATT&CK v19 moved log clearing to Defense Impairment).
    log_cleared_stage = catalog.require("T1685.005").tactics[0]
    engine = RuleEngine(builtin_rules(log_cleared_stage), catalog)
    ctx.services.update(
        {
            "catalog": catalog,
            "rules": engine,
            "pipeline": IngestPipeline(ctx, engine),
            "incidents": IncidentService(ctx),
            "responses": ResponseService(ctx),
            "events": EventService(ctx),
            "overview": OverviewService(ctx),
            "demo": DemoService(ctx),
        }
    )


def release_demo_step(ctx: Any, job: Job) -> JobOutcome:
    outcome: JobOutcome = ctx.service("demo").release(job)
    return outcome
