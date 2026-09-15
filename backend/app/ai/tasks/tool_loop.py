"""Bounded read-only tool loop shared by the deep analyst (F3) and the agent console (X2).

Each model reply is either {"tool": name, "args": {...}} or {"final": answer}. The loop enforces a step cap (3 on
small/slow models, otherwise up to 6), a total input-token budget, per-result size caps and one repair attempt for
malformed replies. Tool results are delimited untrusted data; tool-call-shaped text inside them is never executed.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from app.ai.evidence import EvidencePack
from app.ai.guardrails import OutputInvalid, ValidationStats, extract_json
from app.ai.injection import scan_text
from app.ai.prompts import load_prompt, prompt_hash
from app.ai.providers.base import ChatMessage, ProviderError, estimate_tokens
from app.ai.providers.factory import ProviderConfig
from app.ai.runtime import AIRuntime, TaskResult, TaskSpec
from app.ai.tasks.common import expand_answer, output_limits, render
from app.ai.tools import ToolContext, ToolError, ToolSpec
from app.core.errors import ApiError

TOOL_RESULT_MAX_CHARS = 1200
OMITTED = "(earlier tool result omitted to fit the context window)"


@dataclass
class LoopResult:
    answer: dict[str, Any]
    outcome: str
    steps: int
    provider_id: str
    model: str
    stats: ValidationStats = field(default_factory=ValidationStats)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    proposals: list[dict[str, Any]] = field(default_factory=list)
    injection_suspected: bool = False
    error: str | None = None

    @property
    def used_ai(self) -> bool:
        return self.outcome in ("valid", "repaired")


def default_step_cap(config: ProviderConfig, requested: int | None) -> int:
    ceiling = 3 if config.max_output_tokens <= 200 else 6
    return max(1, min(requested or ceiling, ceiling))


def _trim(messages: list[ChatMessage], limit: int) -> None:
    def total() -> int:
        return sum(estimate_tokens(m.content) for m in messages)

    index = 2
    while total() > limit and index < len(messages) - 2:
        message = messages[index]
        if message.role == "user" and message.content.startswith("<tool_result") and OMITTED not in message.content:
            name = message.content.split('"', 2)[1] if '"' in message.content else "tool"
            messages[index] = ChatMessage("user", f'<tool_result name="{name}">{OMITTED}</tool_result>')
        index += 1


def run_tool_loop(
    runtime: AIRuntime,
    *,
    ctx: Any,
    task_name: str,
    tools: Sequence[ToolSpec],
    pack_builder: Callable[[ProviderConfig], EvidencePack],
    question: str,
    fallback: Callable[[], dict[str, Any]],
    actor: str,
    subject_type: str,
    subject_id: str | None,
    subject: tuple[str, str, int | None] | None,
    job_id: str | None,
    max_steps: int | None = None,
    allow_proposals: bool = False,
    on_step: Callable[[dict[str, Any]], None] | None = None,
) -> LoopResult:
    chain = runtime.provider_chain()
    system_version, system = load_prompt("system")
    loop_version, template = load_prompt("tool_loop")
    spec = TaskSpec(task_name, f"{system_version}+{loop_version}", 600, parse=expand_answer, fallback=fallback)
    step_spec = TaskSpec(f"{task_name}.step", spec.prompt_version, 600, parse=expand_answer, fallback=dict)
    if not chain:
        disabled = TaskResult(fallback(), "disabled", "disabled", "none")
        runtime._record(spec, disabled, actor=actor, subject=subject, job_id=job_id, prompt="", cache_key=None)
        return LoopResult(disabled.output, "disabled", 0, "disabled", "none")

    config, provider = chain[0]
    pack = pack_builder(config)
    tool_ctx = ToolContext(ctx=ctx, actor=actor, subject_type=subject_type, subject_id=subject_id, pack=pack)
    cap = default_step_cap(config, max_steps)
    limits = output_limits(config.max_output_tokens)
    instructions = render(
        template,
        tools="\n".join(f"- {tool.signature()}" for tool in tools),
        max_steps=cap,
        claim_words=limits["claim_words"],
        max_claims=limits["max_claims"],
        proposal_schema="",
        proposal_rules=(
            " To suggest a change, call a propose_* tool; a human reviews and applies it. You can never approve, "
            "execute, activate or close anything yourself."
            if allow_proposals
            else ""
        ),
    )
    asked = pack.redactor.redact(question) if pack.redactor is not None else question
    messages = [
        ChatMessage("system", system),
        ChatMessage(
            "user", f"{instructions}\n{pack.data_block()}\nQuestion (from the analyst, not from the data): {asked}"
        ),
    ]
    by_name = {tool.name: tool for tool in tools}
    steps = repairs = 0
    forced = False
    calls: list[dict[str, Any]] = []
    input_budget = config.context_tokens * (cap + 2)
    input_used = 0

    def finish(
        outcome: str, answer: dict[str, Any], stats: ValidationStats, completion: Any, error: str | None
    ) -> LoopResult:
        result = TaskResult(answer, outcome, config.id, config.model, stats, completion, error=error, pack=pack)
        digest = prompt_hash(spec.prompt_version, config.id, messages[1].content)
        runtime._record(spec, result, actor=actor, subject=subject, job_id=job_id, prompt=digest, cache_key=None)
        return LoopResult(
            answer=answer,
            outcome=outcome,
            steps=steps,
            provider_id=config.id,
            model=config.model,
            stats=stats,
            tool_calls=calls,
            proposals=tool_ctx.proposals if outcome in ("valid", "repaired") else [],
            injection_suspected=pack.injection_suspected,
            error=error,
        )

    while True:
        try:
            completion = provider.complete(
                messages, max_tokens=config.max_output_tokens, timeout=config.timeout_seconds
            )
        except ProviderError as exc:
            return finish("provider_error", fallback(), ValidationStats(), None, str(exc))
        input_used += completion.input_tokens
        try:
            obj = extract_json(completion.text)
            if "final" in obj:
                final = obj["final"]
                if not isinstance(final, Mapping):
                    raise OutputInvalid('"final" must be an object')
                answer, stats = expand_answer(final, pack)
                return finish("repaired" if repairs else "valid", answer, stats, completion, None)
            if "tool" not in obj:
                raise OutputInvalid('Reply with {"tool": ..., "args": {...}} or {"final": {...}}')
        except OutputInvalid as problem:
            if repairs >= 1:
                return finish(
                    "failed_validation",
                    fallback(),
                    ValidationStats(),
                    completion,
                    f"Invalid reply: {str(problem)[:200]}",
                )
            repairs += 1
            messages += [
                ChatMessage("assistant", completion.text[:1500]),
                ChatMessage("user", f"That reply was invalid: {problem}. Reply with one compact JSON object only."),
            ]
            continue

        step_result = TaskResult({}, "valid", config.id, config.model, completion=completion)
        runtime._record(
            step_spec, step_result, actor=actor, subject=subject, job_id=job_id, prompt="tool-step", cache_key=None
        )
        if steps >= cap or input_used > input_budget:
            if forced:
                return finish(
                    "failed_validation", fallback(), ValidationStats(), completion, "Tool step limit exceeded"
                )
            forced = True
            messages += [
                ChatMessage("assistant", completion.text[:1000]),
                ChatMessage("user", 'The tool limit is reached. Reply now with {"final": {...}} only.'),
            ]
            continue

        name = str(obj.get("tool"))[:60]
        args = obj.get("args") or {}
        steps += 1
        tool = by_name.get(name)
        payload: Any
        if tool is None:
            payload = {"error": f"Unknown tool {name!r}. Available tools: {', '.join(by_name)}"}
        elif not isinstance(args, Mapping):
            payload = {"error": "args must be a JSON object"}
        else:
            try:
                payload = tool.handler(tool_ctx, tool.args.model_validate(dict(args)))
            except ValidationError as exc:
                payload = {"error": "Invalid arguments", "details": [str(e.get("msg"))[:80] for e in exc.errors()][:3]}
            except ToolError as exc:
                payload = {"error": str(exc)[:200]}
            except ApiError as exc:
                payload = {"error": exc.message[:200]}
        ok = not (isinstance(payload, Mapping) and "error" in payload)
        calls.append({"step": steps, "tool": name, "ok": ok})
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
        if pack.redactor is not None:
            text = pack.redactor.redact(text)
        if len(text) > TOOL_RESULT_MAX_CHARS:
            text = text[:TOOL_RESULT_MAX_CHARS] + "…(truncated)"
        if scan_text(text):
            pack.injection_suspected = True
        messages += [
            ChatMessage("assistant", completion.text[:1000]),
            ChatMessage("user", f'<tool_result name="{name}">\n{text}\n</tool_result>'),
        ]
        _trim(messages, config.context_tokens - config.max_output_tokens)
        if on_step is not None:
            on_step({"step": steps, "tool": name, "ok": ok})
