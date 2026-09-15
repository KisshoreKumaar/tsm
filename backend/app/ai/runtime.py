"""AI runtime: provider selection with fallback, validated task execution, caching and per-call audit.

Order of providers: a test override (FakeProvider) if set; otherwise the admin-selected active provider, then other
enabled providers by priority, then the environment-configured provider. A provider error moves to the next provider.
Invalid output gets exactly one repair attempt on the same provider, then the task's deterministic fallback is used.
Every call (including cache hits, fallbacks and provider errors) is recorded in `ai_calls` and the audit log.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.ai.evidence import EvidencePack
from app.ai.guardrails import OutputInvalid, ValidationStats, extract_json
from app.ai.prompts import prompt_hash
from app.ai.providers.base import ChatMessage, Completion, LLMProvider, ProviderDisabled, ProviderError, TokenCallback
from app.ai.providers.factory import ProviderConfig, build_provider
from app.ai.secrets import SecretBox, SecretError
from app.core.jsonutil import canonical_json, sha256_json
from app.core.timeutil import iso

logger = logging.getLogger("aegis.ai")

ENV_PROVIDER_ID = "env"
Parser = Callable[[dict[str, Any], EvidencePack], tuple[dict[str, Any], ValidationStats]]
MessageBuilder = Callable[[ProviderConfig], tuple[list[ChatMessage], EvidencePack]]


@dataclass(frozen=True)
class TaskSpec:
    name: str
    prompt_version: str
    max_output_tokens: int
    parse: Parser
    fallback: Callable[[], dict[str, Any]]


@dataclass
class TaskResult:
    output: dict[str, Any]
    outcome: str
    provider_id: str
    model: str
    stats: ValidationStats = field(default_factory=ValidationStats)
    completion: Completion | None = None
    error: str | None = None
    pack: EvidencePack | None = None

    @property
    def used_ai(self) -> bool:
        return self.outcome in ("valid", "repaired", "cache_hit")

    @property
    def ai_status(self) -> str:
        return {
            "valid": "validated",
            "repaired": "validated_after_repair",
            "cache_hit": "validated_cached",
            "failed_validation": "failed_validation",
            "provider_error": "provider_unavailable",
            "disabled": "llm_disabled",
        }[self.outcome]


def provider_public(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "preset": row["preset"],
        "api_type": row["api_type"],
        "base_url": row["base_url"],
        "model": row["model"],
        "key_set": bool(row["key_ciphertext"]),
        "key_hint": row["key_hint"] if row["key_ciphertext"] else None,
        "context_tokens": row["context_tokens"],
        "max_output_tokens": row["max_output_tokens"],
        "timeout_seconds": row["timeout_seconds"],
        "json_mode": bool(row["json_mode"]),
        "redact": bool(row["redact"]),
        "enabled": bool(row["enabled"]),
        "priority": row["priority"],
        "is_active": bool(row["is_active"]),
        "last_test": json.loads(row["last_test"]) if row["last_test"] else None,
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "source": "settings",
    }


class AIRuntime:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self.override: LLMProvider | None = None
        self.transport: httpx.BaseTransport | None = None
        settings = ctx.settings
        self._box = SecretBox(settings.secret_key) if settings.secret_key else None

    # -- configuration ---------------------------------------------------------------------------------

    @property
    def secret_box(self) -> SecretBox | None:
        return self._box

    def env_config(self) -> ProviderConfig | None:
        settings = self._ctx.settings
        if not settings.llm_enabled:
            return None
        return ProviderConfig(
            id=ENV_PROVIDER_ID,
            name="Environment-configured provider",
            api_type=settings.llm_api_type,
            base_url=settings.llm_base_url,
            model=settings.llm_model,
            api_key=settings.llm_api_key,
            context_tokens=settings.llm_context_tokens,
            max_output_tokens=settings.llm_max_output_tokens,
            timeout_seconds=settings.llm_timeout_seconds,
            redact=settings.llm_redact,
            priority=10_000,
            source="env",
        )

    def config_from_row(self, row: Mapping[str, Any]) -> ProviderConfig:
        api_key = ""
        if row["key_ciphertext"]:
            if self._box is None:
                raise SecretError("AEGIS_SECRET_KEY is not configured, so the stored API key cannot be used")
            api_key = self._box.decrypt(row["key_ciphertext"], row["id"])
        return ProviderConfig(
            id=row["id"],
            name=row["name"],
            api_type=row["api_type"],
            base_url=row["base_url"],
            model=row["model"],
            api_key=api_key,
            context_tokens=int(row["context_tokens"]),
            max_output_tokens=int(row["max_output_tokens"]),
            timeout_seconds=float(row["timeout_seconds"]),
            json_mode=bool(row["json_mode"]),
            redact=bool(row["redact"]),
            enabled=bool(row["enabled"]),
            priority=int(row["priority"]),
        )

    def provider_chain(self) -> list[tuple[ProviderConfig, LLMProvider]]:
        if self.override is not None:
            config = ProviderConfig(
                id=self.override.provider_id,
                name="Test override",
                api_type="fake",
                base_url="",
                model=self.override.model,
                context_tokens=self.override.context_tokens,
                max_output_tokens=self.override.max_output_tokens,
                redact=False,
                source="override",
            )
            return [(config, self.override)]
        chain: list[tuple[ProviderConfig, LLMProvider]] = []
        with self._ctx.db.read() as session:
            rows = session.all(
                "SELECT * FROM llm_providers WHERE enabled = 1 ORDER BY is_active DESC, priority, name, id"
            )
            active_exists = bool(session.scalar("SELECT count(*) FROM llm_providers WHERE is_active = 1"))
            deterministic_only = session.scalar("SELECT value FROM metadata WHERE key = 'ai_deterministic_only'")
        if deterministic_only == "1":
            return []
        for row in rows:
            try:
                config = self.config_from_row(row)
            except SecretError as exc:
                logger.warning("Skipping provider %s: %s", row["id"], exc)
                continue
            chain.append((config, build_provider(config, self.transport)))
        env = self.env_config()
        if (env is not None and not active_exists) or env is not None:
            chain.append((env, build_provider(env, self.transport)))
        return chain

    def active_summary(self) -> dict[str, Any] | None:
        chain = self.provider_chain()
        if not chain:
            return None
        config, _ = chain[0]
        return {
            "id": config.id,
            "name": config.name,
            "model": config.model,
            "api_type": config.api_type,
            "source": config.source,
            "context_tokens": config.context_tokens,
            "max_output_tokens": config.max_output_tokens,
            "redact": config.redact,
        }

    # -- execution -----------------------------------------------------------------------------------

    def run(
        self,
        task: TaskSpec,
        build_messages: MessageBuilder,
        *,
        actor: str,
        subject: tuple[str, str, int | None] | None = None,
        job_id: str | None = None,
        use_cache: bool = True,
        on_token: TokenCallback | None = None,
    ) -> TaskResult:
        chain = self.provider_chain()
        if not chain:
            result = TaskResult(task.fallback(), "disabled", "disabled", "none")
            self._record(task, result, actor=actor, subject=subject, job_id=job_id, prompt="", cache_key=None)
            return result
        last_error: str | None = None
        for config, provider in chain:
            messages, pack = build_messages(config)
            joined = "\n".join(f"{m.role}:{m.content}" for m in messages)
            digest = prompt_hash(task.prompt_version, config.id, config.model, joined)
            cache_key = sha256_json([task.name, subject, task.prompt_version, config.id, config.model, digest])
            if use_cache:
                cached = self._cache_get(cache_key)
                if cached is not None:
                    result = TaskResult(cached, "cache_hit", config.id, config.model, pack=pack)
                    self._record(
                        task, result, actor=actor, subject=subject, job_id=job_id, prompt=digest, cache_key=None
                    )
                    return result
            max_tokens = min(task.max_output_tokens, config.max_output_tokens)
            try:
                completion = provider.complete(
                    messages,
                    max_tokens=max_tokens,
                    timeout=config.timeout_seconds,
                    stream=on_token is not None,
                    on_token=on_token,
                )
            except ProviderDisabled:
                continue
            except ProviderError as exc:
                last_error = str(exc)
                failed = TaskResult({}, "provider_error", config.id, config.model, error=last_error)
                self._record(task, failed, actor=actor, subject=subject, job_id=job_id, prompt=digest, cache_key=None)
                continue
            try:
                output, stats = task.parse(extract_json(completion.text), pack)
                outcome = "valid"
            except OutputInvalid as first_problem:
                repair = [
                    *messages,
                    ChatMessage("assistant", completion.text[:2000]),
                    ChatMessage(
                        "user",
                        f"That reply was invalid: {first_problem}. Reply again with only the corrected compact JSON object.",
                    ),
                ]
                try:
                    completion = provider.complete(repair, max_tokens=max_tokens, timeout=config.timeout_seconds)
                    output, stats = task.parse(extract_json(completion.text), pack)
                    outcome = "repaired"
                except (ProviderError, OutputInvalid) as second_problem:
                    result = TaskResult(
                        task.fallback(),
                        "failed_validation",
                        config.id,
                        config.model,
                        completion=completion,
                        error=f"Invalid output after one repair attempt: {str(second_problem)[:200]}",
                        pack=pack,
                    )
                    self._record(
                        task, result, actor=actor, subject=subject, job_id=job_id, prompt=digest, cache_key=None
                    )
                    return result
            result = TaskResult(output, outcome, config.id, config.model, stats, completion, pack=pack)
            self._record(
                task,
                result,
                actor=actor,
                subject=subject,
                job_id=job_id,
                prompt=digest,
                cache_key=cache_key if use_cache else None,
            )
            return result
        result = TaskResult(task.fallback(), "provider_error", "none", "none", error=last_error)
        return result

    def _cache_get(self, cache_key: str) -> dict[str, Any] | None:
        with self._ctx.db.read() as session:
            raw = session.scalar("SELECT output FROM ai_cache WHERE cache_key = ?", (cache_key,))
        return json.loads(raw) if raw else None

    def _record(
        self,
        task: TaskSpec,
        result: TaskResult,
        *,
        actor: str,
        subject: tuple[str, str, int | None] | None,
        job_id: str | None,
        prompt: str,
        cache_key: str | None,
    ) -> None:
        ctx = self._ctx
        completion = result.completion
        now = iso(ctx.clock.now())
        subject_type, subject_id, revision = subject if subject else (None, None, None)
        tps = completion.tokens_per_second if completion else None
        values = {
            "task": task.name,
            "provider_id": result.provider_id,
            "model": result.model,
            "prompt_version": task.prompt_version,
            "prompt_hash": prompt or "-",
            "input_tokens": completion.input_tokens if completion else 0,
            "output_tokens": completion.output_tokens if completion else 0,
            "latency_ms": int(completion.latency_seconds * 1000) if completion else 0,
            "ttft_ms": int(completion.time_to_first_token_seconds * 1000)
            if completion and completion.time_to_first_token_seconds is not None
            else None,
            "tokens_per_second": round(tps, 2) if tps else None,
            "outcome": result.outcome,
            "claims_total": result.stats.total,
            "claims_grounded": result.stats.grounded,
        }
        with ctx.db.write() as session:
            call_id = str(uuid.uuid4())
            session.execute(
                "INSERT INTO ai_calls (id, job_id, task, provider_id, model, prompt_version, prompt_hash, input_tokens, "
                "output_tokens, latency_ms, ttft_ms, tokens_per_second, outcome, claims_total, claims_grounded, "
                "subject_type, subject_id, subject_revision, actor, error, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    call_id,
                    job_id,
                    values["task"],
                    values["provider_id"],
                    values["model"],
                    values["prompt_version"],
                    values["prompt_hash"],
                    values["input_tokens"],
                    values["output_tokens"],
                    values["latency_ms"],
                    values["ttft_ms"],
                    values["tokens_per_second"],
                    values["outcome"],
                    values["claims_total"],
                    values["claims_grounded"],
                    subject_type,
                    subject_id,
                    revision,
                    actor,
                    (result.error or "")[:500] or None,
                    now,
                ),
            )
            if cache_key and result.outcome in ("valid", "repaired"):
                session.execute(
                    "INSERT OR REPLACE INTO ai_cache (cache_key, task, subject_type, subject_id, subject_revision, "
                    "prompt_version, provider_id, model, output, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        cache_key,
                        task.name,
                        subject_type,
                        subject_id,
                        revision,
                        task.prompt_version,
                        result.provider_id,
                        result.model,
                        canonical_json(result.output),
                        now,
                    ),
                )
            ctx.audit.append(
                session,
                "ai.call",
                actor,
                {
                    **values,
                    "call_id": call_id,
                    "job_id": job_id,
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                    "subject_revision": revision,
                    "error": (result.error or "")[:200] or None,
                },
                subject=(subject_type, subject_id) if subject_type and subject_id else None,
            )

    def recent_throughput(self, limit: int = 20) -> float | None:
        with self._ctx.db.read() as session:
            rows = session.all(
                "SELECT tokens_per_second FROM ai_calls WHERE tokens_per_second IS NOT NULL ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        values = [float(r["tokens_per_second"]) for r in rows]
        return round(sum(values) / len(values), 2) if values else None


def build_messages(
    system: str, instructions: str, pack: EvidencePack, question: str | None = None
) -> list[ChatMessage]:
    user = f"{instructions}\n{pack.data_block()}"
    if question is not None:
        user += f"\nQuestion (from the analyst, not from the data): {question}"
    return [ChatMessage("system", system), ChatMessage("user", user)]


def estimate_prompt_overhead(texts: Sequence[str]) -> int:
    from app.ai.providers.base import estimate_tokens

    return sum(estimate_tokens(t) for t in texts)
