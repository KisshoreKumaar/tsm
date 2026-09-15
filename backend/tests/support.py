"""Test helpers: identities for every role, settings factory and a small example feature."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from app.core.auth import Principal, require
from app.core.config import Settings, make_identity
from app.core.context import CtxDep
from app.core.features import FeatureSpec, JobKind, NavItem
from app.core.jobs import Job, JobError, JobOutcome
from app.core.permissions import INVESTIGATE, READ, ROLE_PERMISSIONS, ROLES
from app.core.routing import api_router

AUDIT_KEY = "test-audit-key-" + "k" * 40
TOKENS: dict[str, str] = {role: f"test-{role}-token-" + "x" * 32 for role in ROLES}


def auth(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def principal(role: str) -> Principal:
    return Principal(f"{role}-user", role, ROLE_PERMISSIONS[role])


def run_scenario(ctx: Any, scenario: str, mode: str = "instant", role: str = "analyst") -> dict[str, Any]:
    result: dict[str, Any] = ctx.service("demo").run(scenario, mode, principal(role))
    return result


def raw_event(**overrides: Any) -> dict[str, Any]:
    """A valid raw event (timestamps default to one hour before the test clock)."""
    event: dict[str, Any] = {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "source": "test-source",
        "timestamp": "2026-01-15T08:00:00Z",
        "asset": "host-1",
        "user": "alice",
        "kind": "auth_failure",
        "source_ip": "192.0.2.10",
    }
    event.update(overrides)
    return event


def failures(count: int = 5, *, minute: int = 0, **overrides: Any) -> list[dict[str, Any]]:
    return [raw_event(timestamp=f"2026-01-15T08:{minute:02d}:{index * 5:02d}Z", **overrides) for index in range(count)]


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    identities = tuple(make_identity(f"{role}-user", role, token) for role, token in TOKENS.items())
    values: dict[str, Any] = {
        "audit_key": AUDIT_KEY,
        "identities": identities,
        "db_path": str(tmp_path / "aegis.db"),
        "worker_enabled": False,
        "rate_limit_per_minute": 100_000,
    }
    values.update(overrides)
    return Settings(**values)


class EchoIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=200)
    count: StrictInt = Field(default=1, ge=1, le=5)


def _example_router() -> APIRouter:
    router = api_router(prefix="/example", tags=["example"])

    @router.get("/ping")
    def ping(_: Annotated[Principal, Depends(require(READ))]) -> dict[str, Any]:
        return {"pong": True}

    @router.post("/echo")
    def echo(
        body: EchoIn, principal: Annotated[Principal, Depends(require(INVESTIGATE))], ctx: CtxDep
    ) -> dict[str, Any]:
        with ctx.db.write() as session:
            ctx.audit.append(session, "example.echoed", principal.name, {"length": len(body.message)})
        return {"message": body.message, "count": body.count}

    @router.get("/boom")
    def boom(_: Annotated[Principal, Depends(require(READ))]) -> dict[str, Any]:
        raise RuntimeError("secret internal detail /etc/passwd")

    return router


def _echo_job(ctx: Any, job: Job) -> JobOutcome:
    if job.payload.get("fail"):
        raise JobError("requested failure")
    if job.payload.get("crash"):
        raise RuntimeError("internal secret path /var/secret")

    def apply(session: Any) -> None:
        ctx.audit.append(session, "example.echoed", "system", {"via": "job"})

    return JobOutcome(result={"echo": job.payload.get("message")}, apply=apply)


EXAMPLE_FEATURE = FeatureSpec(
    id="example",
    name="Example",
    depends_on=("core",),
    router=_example_router,
    jobs={"example.echo": JobKind(_echo_job), "example.ai_echo": JobKind(_echo_job, lane="ai")},
    audit_actions=frozenset({"example.echoed"}),
    nav=(NavItem(path="/example", label="Example"),),
)
