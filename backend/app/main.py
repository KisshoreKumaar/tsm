"""FastAPI application factory.

Run locally with:  uvicorn --factory app.main:create_app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.core.config import Settings, environment_with_dotenv
from app.core.context import build_context
from app.core.errors import install_error_handlers
from app.core.features import FeatureSpec
from app.core.jobs import Worker
from app.core.security import BodyLimitMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware
from app.core.timeutil import Clock


def create_app(
    settings: Settings | None = None,
    *,
    features: Sequence[FeatureSpec] | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if settings is None:
        settings = Settings.from_env(environment_with_dotenv())
    if features is None:
        from app.features.registry import ALL_FEATURES

        features = ALL_FEATURES
    ctx = build_context(settings, features, clock=clock)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if settings.worker_enabled:
            ctx.worker = Worker(ctx.jobs, ctx, lanes={"default": 1, "ai": settings.llm_max_concurrency})
            ctx.worker.start()
        try:
            yield
        finally:
            if ctx.worker is not None:
                ctx.worker.stop()
                ctx.worker = None

    app = FastAPI(
        title="AEGIS SOC API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.expose_docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.expose_docs else None,
    )
    app.state.ctx = ctx
    install_error_handlers(app)
    for spec in ctx.features.specs:
        if spec.router is not None:
            app.include_router(spec.router(), prefix="/api")

    # Middleware runs outermost-last: headers wrap everything, then CORS, rate limit, body limit.
    app.add_middleware(
        BodyLimitMiddleware,
        default_limit=settings.max_body_bytes,
        overrides={"/api/events/batch": settings.max_batch_body_bytes},
    )
    app.add_middleware(RateLimitMiddleware, per_minute=settings.rate_limit_per_minute)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            allow_credentials=False,
            max_age=600,
        )
    app.add_middleware(SecurityHeadersMiddleware)
    return app
