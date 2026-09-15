"""Route class that parses JSON bodies strictly before FastAPI validation.

Rejects duplicate keys, NaN/Infinity, excessive nesting and non-JSON content types. Starlette caches the
parsed body on the request, so FastAPI's own body handling reuses the strictly parsed value.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.routing import APIRoute

from app.core.errors import ApiError
from app.core.jsonutil import StrictJSONError, strict_loads

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class StrictJSONRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            if request.method in _BODY_METHODS:
                body = await request.body()
                if body:
                    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
                    if content_type != "application/json":
                        raise ApiError(
                            "Content-Type must be application/json",
                            code="unsupported_media_type",
                            status_code=415,
                        )
                    try:
                        parsed = strict_loads(body)
                    except StrictJSONError as exc:
                        raise ApiError(str(exc), code="invalid_json") from None
                    setattr(request, "_json", parsed)  # noqa: B010 - Starlette's parsed-body cache
            return await original(request)

        return handler


def api_router(**kwargs: Any) -> APIRouter:
    return APIRouter(route_class=StrictJSONRoute, **kwargs)
