"""Application context: the single object that wires platform services together at startup."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, Request

from app.core.audit import AuditLog
from app.core.auth import Authenticator
from app.core.config import Settings
from app.core.db import Database
from app.core.features import EnabledFeatures, FeatureSpec, resolve_features
from app.core.jobs import JobQueue, Worker
from app.core.migrations import MIGRATIONS_DIR, apply_migrations
from app.core.sse import EventBus
from app.core.timeutil import Clock, SystemClock


class StartupError(RuntimeError):
    pass


@dataclass
class AppContext:
    settings: Settings
    clock: Clock
    db: Database
    audit: AuditLog
    authenticator: Authenticator
    features: EnabledFeatures
    jobs: JobQueue
    bus: EventBus
    services: dict[str, Any] = field(default_factory=dict)
    worker: Worker | None = None

    def service(self, name: str) -> Any:
        try:
            return self.services[name]
        except KeyError:
            raise StartupError(f"Service {name!r} is not registered (is its feature enabled?)") from None


def build_context(
    settings: Settings,
    available_features: Sequence[FeatureSpec],
    *,
    clock: Clock | None = None,
    migrations_dir: Path = MIGRATIONS_DIR,
) -> AppContext:
    settings.validate()
    active_clock: Clock = clock or SystemClock()
    features = resolve_features(available_features, settings.features)
    db = Database(settings.db_path)
    apply_migrations(db, migrations_dir)
    actions: set[str] = set()
    for spec in features.specs:
        actions.update(spec.audit_actions)
    audit = AuditLog(settings.audit_key, actions, active_clock)
    audit.initialize(db)
    verification = audit.verify(db)
    if not verification["valid"]:
        raise StartupError(
            f"Audit chain verification failed at seq {verification.get('failed_seq')}: {verification.get('reason')}. "
            "Preserve this database for investigation; the service will not start."
        )
    bus = EventBus()
    jobs = JobQueue(db, audit, active_clock, bus)
    ctx = AppContext(
        settings=settings,
        clock=active_clock,
        db=db,
        audit=audit,
        authenticator=Authenticator(settings.identities),
        features=features,
        jobs=jobs,
        bus=bus,
    )
    for spec in features.specs:
        for kind, job_kind in spec.jobs.items():
            jobs.register(kind, job_kind.handler, job_kind.lane)
    for spec in features.specs:
        if spec.on_startup is not None:
            spec.on_startup(ctx)
    jobs.recover()
    return ctx


def get_ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


CtxDep = Annotated[AppContext, Depends(get_ctx)]
