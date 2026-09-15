"""Provider settings (admin), connection tests, AI status (X1)."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator

from app.ai.builtin_tools import NoArgs, builtin_tools
from app.ai.guardrails import OutputInvalid, extract_json
from app.ai.injection import scan_text
from app.ai.providers.base import ChatMessage, ProviderError
from app.ai.providers.factory import PRESETS, build_provider
from app.ai.runtime import AIRuntime, provider_public
from app.ai.secrets import SecretError, key_hint
from app.ai.tools import ToolContext, ToolRegistry, ToolSpec
from app.ai.urlguard import UrlRejected, validate_base_url
from app.core.auth import Principal
from app.core.config import BACKEND_DIR
from app.core.errors import ApiError, Conflict, NotFound
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso

CORPUS_PATH = BACKEND_DIR / "tests" / "ai" / "injection_cases.jsonl"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ProviderIn(Strict):
    name: str = Field(min_length=1, max_length=80)
    preset: Literal["ollama-ec2", "groq", "gemini", "custom"] | None = None
    api_type: Literal["ollama", "openai"]
    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
    context_tokens: StrictInt = Field(default=2048, ge=512, le=2_000_000)
    max_output_tokens: StrictInt = Field(default=256, ge=16, le=32_000)
    timeout_seconds: float = Field(default=120.0, ge=1, le=1800)
    json_mode: StrictBool = True
    redact: StrictBool = True
    enabled: StrictBool = True
    priority: StrictInt = Field(default=100, ge=0, le=10_000)
    make_active: StrictBool = False
    api_key: str | None = Field(default=None, min_length=8, max_length=512)

    @field_validator("api_key")
    @classmethod
    def _no_whitespace(cls, value: str | None) -> str | None:
        if value is not None and any(c.isspace() for c in value):
            raise ValueError("must not contain whitespace")
        return value


class ProviderPatch(Strict):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    base_url: str | None = Field(default=None, min_length=1, max_length=500)
    model: str | None = Field(default=None, min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
    context_tokens: StrictInt | None = Field(default=None, ge=512, le=2_000_000)
    max_output_tokens: StrictInt | None = Field(default=None, ge=16, le=32_000)
    timeout_seconds: float | None = Field(default=None, ge=1, le=1800)
    json_mode: StrictBool | None = None
    redact: StrictBool | None = None
    enabled: StrictBool | None = None
    priority: StrictInt | None = Field(default=None, ge=0, le=10_000)


class KeyIn(Strict):
    api_key: str = Field(min_length=8, max_length=512)

    @field_validator("api_key")
    @classmethod
    def _no_whitespace(cls, value: str) -> str:
        if any(c.isspace() for c in value):
            raise ValueError("must not contain whitespace")
        return value


class ActiveIn(Strict):
    provider_id: str | None = Field(default=None, max_length=64)


def setup(ctx: Any) -> None:
    ctx.services["ai"] = AIRuntime(ctx)
    ctx.services["llm_settings"] = ProviderSettingsService(ctx)
    registry = ToolRegistry()
    for tool in builtin_tools():
        if tool.feature in ctx.features:
            registry.register(tool)
    for feature in ctx.features.specs:
        if feature.agent_tools is not None:
            for tool in feature.agent_tools():
                registry.register(tool)
    ctx.services["ai_tools"] = registry


def _ai_status_tool(tc: ToolContext, _: NoArgs) -> dict[str, Any]:
    status = tc.ctx.service("llm_settings").status()
    return {
        k: status[k] for k in ("enabled", "active_provider", "measured_tokens_per_second", "queue", "fallback_count")
    }


def agent_tools() -> list[ToolSpec]:
    return [ToolSpec("get_ai_status", "x1", "AI provider status and queue", NoArgs, _ai_status_tool)]


def corpus_pass_rate(path: Path = CORPUS_PATH) -> float | None:
    if not path.is_file():
        return None
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not cases:
        return None
    passed = sum(1 for case in cases if bool(scan_text(case["text"])) == case["flag"])
    return round(passed / len(cases), 3)


class ProviderSettingsService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    @property
    def _runtime(self) -> AIRuntime:
        runtime: AIRuntime = self._ctx.service("ai")
        return runtime

    def _row(self, session: Any, provider_id: str) -> Any:
        row = session.one("SELECT * FROM llm_providers WHERE id = ?", (provider_id,))
        if row is None:
            raise NotFound("Unknown provider")
        return row

    def _url(self, value: str) -> str:
        try:
            return validate_base_url(value, self._ctx.settings.llm_allowed_hosts)
        except UrlRejected as exc:
            raise ApiError(str(exc), code="invalid_base_url", status_code=422) from None

    def list(self) -> dict[str, Any]:
        runtime = self._runtime
        settings = self._ctx.settings
        with self._ctx.db.read() as session:
            rows = session.all("SELECT * FROM llm_providers ORDER BY is_active DESC, priority, name")
            deterministic_only = session.scalar("SELECT value FROM metadata WHERE key = 'ai_deterministic_only'") == "1"
        env = runtime.env_config()
        return {
            "providers": [provider_public(row) for row in rows],
            "env_provider": None
            if env is None
            else {
                "id": env.id,
                "name": env.name,
                "api_type": env.api_type,
                "base_url": env.base_url,
                "model": env.model,
                "key_set": bool(env.api_key),
                "source": "env",
            },
            "presets": PRESETS,
            "secret_key_configured": bool(settings.secret_key),
            "deterministic_only": deterministic_only,
            "active": runtime.active_summary(),
        }

    def create(self, body: ProviderIn, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        base_url = self._url(body.base_url)
        if body.api_key is not None and self._runtime.secret_box is None:
            raise Conflict("Set AEGIS_SECRET_KEY on the server before storing API keys", code="secret_key_missing")
        provider_id = str(uuid.uuid4())
        now = iso(ctx.clock.now())
        with ctx.db.write() as session:
            ciphertext = hint = None
            if body.api_key is not None:
                box = self._runtime.secret_box
                assert box is not None  # noqa: S101 - checked above
                ciphertext, hint = box.encrypt(body.api_key, provider_id), key_hint(body.api_key)
            session.execute(
                "INSERT INTO llm_providers (id, name, preset, api_type, base_url, model, key_ciphertext, key_hint, "
                "context_tokens, max_output_tokens, timeout_seconds, json_mode, redact, enabled, priority, is_active, "
                "created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
                (
                    provider_id,
                    body.name,
                    body.preset,
                    body.api_type,
                    base_url,
                    body.model,
                    ciphertext,
                    hint,
                    body.context_tokens,
                    body.max_output_tokens,
                    body.timeout_seconds,
                    int(body.json_mode),
                    int(body.redact),
                    int(body.enabled),
                    body.priority,
                    principal.name,
                    now,
                    now,
                ),
            )
            ctx.audit.append(
                session,
                "llm.provider_created",
                principal.name,
                {
                    "provider_id": provider_id,
                    "name": body.name,
                    "preset": body.preset,
                    "api_type": body.api_type,
                    "base_url": base_url,
                    "model": body.model,
                    "key_stored": ciphertext is not None,
                },
                subject=("llm_provider", provider_id),
            )
            if body.make_active:
                self._activate(session, provider_id, principal)
        return self.get(provider_id)

    def get(self, provider_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            return provider_public(self._row(session, provider_id))

    def update(self, provider_id: str, body: ProviderPatch, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        changes = body.model_dump(exclude_none=True)
        if not changes:
            raise ApiError("Nothing to update", code="nothing_to_update", status_code=422)
        if "base_url" in changes:
            changes["base_url"] = self._url(changes["base_url"])
        for flag in ("json_mode", "redact", "enabled"):
            if flag in changes:
                changes[flag] = int(changes[flag])
        with ctx.db.write() as session:
            self._row(session, provider_id)
            assignments = ", ".join(f"{column} = ?" for column in changes)  # columns come from the fixed model
            session.execute(
                f"UPDATE llm_providers SET {assignments}, updated_at = ? WHERE id = ?",
                [*changes.values(), iso(ctx.clock.now()), provider_id],
            )
            if changes.get("enabled") == 0:
                session.execute("UPDATE llm_providers SET is_active = 0 WHERE id = ?", (provider_id,))
            ctx.audit.append(
                session,
                "llm.provider_updated",
                principal.name,
                {"provider_id": provider_id, "changes": changes},
                subject=("llm_provider", provider_id),
            )
        return self.get(provider_id)

    def delete(self, provider_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, provider_id)
            session.execute("DELETE FROM llm_providers WHERE id = ?", (provider_id,))
            ctx.audit.append(
                session,
                "llm.provider_deleted",
                principal.name,
                {"provider_id": provider_id, "name": row["name"], "was_active": bool(row["is_active"])},
                subject=("llm_provider", provider_id),
            )
        return {"deleted": provider_id}

    def set_key(self, provider_id: str, api_key: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        box = self._runtime.secret_box
        if box is None:
            raise Conflict("Set AEGIS_SECRET_KEY on the server before storing API keys", code="secret_key_missing")
        with ctx.db.write() as session:
            row = self._row(session, provider_id)
            session.execute(
                "UPDATE llm_providers SET key_ciphertext = ?, key_hint = ?, updated_at = ? WHERE id = ?",
                (box.encrypt(api_key, provider_id), key_hint(api_key), iso(ctx.clock.now()), provider_id),
            )
            ctx.audit.append(
                session,
                "llm.provider_key_set",
                principal.name,
                {"provider_id": provider_id, "rotated": bool(row["key_ciphertext"])},
                subject=("llm_provider", provider_id),
            )
        return self.get(provider_id)

    def remove_key(self, provider_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        with ctx.db.write() as session:
            row = self._row(session, provider_id)
            if not row["key_ciphertext"]:
                raise Conflict("This provider has no stored key")
            session.execute(
                "UPDATE llm_providers SET key_ciphertext = NULL, key_hint = NULL, updated_at = ? WHERE id = ?",
                (iso(ctx.clock.now()), provider_id),
            )
            ctx.audit.append(
                session,
                "llm.provider_key_removed",
                principal.name,
                {"provider_id": provider_id},
                subject=("llm_provider", provider_id),
            )
        return self.get(provider_id)

    def _activate(self, session: Any, provider_id: str | None, principal: Principal) -> None:
        if provider_id is not None:
            row = self._row(session, provider_id)
            if not row["enabled"]:
                raise Conflict("Enable the provider before making it active")
        session.execute("UPDATE llm_providers SET is_active = 0")
        if provider_id is not None:
            session.execute("UPDATE llm_providers SET is_active = 1 WHERE id = ?", (provider_id,))
        session.execute(
            "INSERT INTO metadata (key, value) VALUES ('ai_deterministic_only', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("0" if provider_id is not None else "1",),
        )
        self._ctx.audit.append(
            session,
            "llm.active_changed",
            principal.name,
            {"provider_id": provider_id, "deterministic_only": provider_id is None},
            subject=("llm_provider", provider_id) if provider_id else None,
        )

    def set_active(self, provider_id: str | None, principal: Principal) -> dict[str, Any]:
        with self._ctx.db.write() as session:
            self._activate(session, provider_id, principal)
        return self.list()

    def test(self, provider_id: str, principal: Principal) -> dict[str, Any]:
        ctx = self._ctx
        runtime = self._runtime
        with ctx.db.read() as session:
            row = self._row(session, provider_id)
        started = time.monotonic()
        result: dict[str, Any] = {
            "ok": False,
            "provider_id": provider_id,
            "model": row["model"],
            "tested_at": iso(ctx.clock.now()),
        }
        try:
            config = runtime.config_from_row(row)
            provider = build_provider(config, runtime.transport)
            completion = provider.complete(
                [
                    ChatMessage("system", "Reply with one compact JSON object only."),
                    ChatMessage("user", 'Return exactly this JSON: {"ok":true,"word":"ready"}'),
                ],
                max_tokens=24,
                timeout=min(config.timeout_seconds, 120.0),
                stream=True,
                on_token=lambda _piece: None,
            )
            try:
                json_ok = extract_json(completion.text).get("ok") is True
            except OutputInvalid:
                json_ok = False
            tps = completion.tokens_per_second
            result.update(
                ok=True,
                json_ok=json_ok,
                latency_ms=int(completion.latency_seconds * 1000),
                ttft_ms=int(completion.time_to_first_token_seconds * 1000)
                if completion.time_to_first_token_seconds is not None
                else None,
                tokens_per_second=round(tps, 2) if tps else None,
                output_tokens=completion.output_tokens,
                finish_reason=completion.finish_reason,
            )
        except (ProviderError, SecretError) as exc:
            result.update(error=str(exc)[:300], latency_ms=int((time.monotonic() - started) * 1000))
        with ctx.db.write() as session:
            session.execute(
                "UPDATE llm_providers SET last_test = ?, updated_at = ? WHERE id = ?",
                (canonical_json(result), iso(ctx.clock.now()), provider_id),
            )
            ctx.audit.append(
                session,
                "llm.provider_tested",
                principal.name,
                {
                    k: result.get(k)
                    for k in ("provider_id", "ok", "json_ok", "latency_ms", "ttft_ms", "tokens_per_second", "error")
                },
                subject=("llm_provider", provider_id),
            )
        return result

    def status(self) -> dict[str, Any]:
        ctx = self._ctx
        runtime = self._runtime
        active = runtime.active_summary()
        with ctx.db.read() as session:
            rows = session.all(
                "SELECT task, outcome, tokens_per_second, latency_ms, claims_total, claims_grounded FROM ai_calls "
                "WHERE task NOT LIKE '%.step' ORDER BY created_at DESC LIMIT 500"
            )
            running = session.scalar("SELECT count(*) FROM jobs WHERE lane = 'ai' AND status = 'RUNNING'")
        outcomes: dict[str, int] = {}
        for row in rows:
            outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1
        answered = [r for r in rows if r["outcome"] in ("valid", "repaired")]
        total_claims = sum(r["claims_total"] for r in answered)
        grounded = sum(r["claims_grounded"] for r in answered)
        latencies = [r["latency_ms"] for r in answered if r["latency_ms"]]
        lookups = outcomes.get("cache_hit", 0) + len(answered)
        return {
            "enabled": active is not None,
            "mode": "llm" if active is not None else "deterministic",
            "active_provider": active,
            "measured_tokens_per_second": runtime.recent_throughput(),
            "average_latency_ms": int(sum(latencies) / len(latencies)) if latencies else None,
            "queue": {"queued": ctx.jobs.pending_count("ai"), "running": running},
            "calls": len(rows),
            "outcomes": outcomes,
            "cache_hit_rate": round(outcomes.get("cache_hit", 0) / lookups, 3) if lookups else None,
            "grounding_rate": round(grounded / total_claims, 3) if total_claims else None,
            "fallback_count": outcomes.get("failed_validation", 0)
            + outcomes.get("provider_error", 0)
            + outcomes.get("disabled", 0),
            "injection_detector_pass_rate": corpus_pass_rate(),
            "notes": [
                "Scores and confidence values are heuristics, not probabilities.",
                "All AI output is validated; failures fall back to deterministic results.",
            ],
        }

    def eta_seconds(self, queue_position: int | None) -> int | None:
        status = self.status()
        latency = status["average_latency_ms"] or (60_000 if status["enabled"] else 0)
        if queue_position is None:
            return None
        return int(queue_position * latency / 1000)
