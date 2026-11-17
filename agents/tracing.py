"""Optional Inspect hooks that export CodeIPI sample traces to Langfuse."""

from __future__ import annotations

import os
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from inspect_ai.event import ModelEvent, ToolEvent
from inspect_ai.hooks import Hooks, RunEnd, SampleEnd, SampleEvent, SampleScoring, SampleStart, TaskStart, hooks
from inspect_ai.model import get_model


current_agent_trace = ContextVar("current_agent_trace", default=None)
current_trace_attributes = ContextVar("current_trace_attributes", default=None)


def tracing_enabled() -> bool:
    return os.getenv("LANGFUSE_TRACING_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def validate_langfuse_config(environ: dict[str, str] | None = None) -> None:
    """Fail early with setting names only when tracing is explicitly enabled."""
    values = os.environ if environ is None else environ
    enabled = values.get("LANGFUSE_TRACING_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return
    missing = [name for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY") if not values.get(name)]
    if not (values.get("LANGFUSE_BASE_URL") or values.get("LANGFUSE_HOST")):
        missing.append("LANGFUSE_BASE_URL (or LANGFUSE_HOST)")
    if missing:
        raise ValueError("Langfuse tracing is enabled but required settings are missing: " + ", ".join(missing))


def configure_tracing():
    validate_langfuse_config()
    if not tracing_enabled():
        return None
    from langfuse import get_client

    client = get_client()
    if not client.auth_check():
        raise RuntimeError("Langfuse authentication failed")
    return client


def trace_attributes(benchmark: str, model: str, experiment: str, run_id: str, tags: list[str]) -> dict:
    """Session and tags shared by every benchmark trace."""
    model = model.rsplit("/", 1)[-1]
    prefix = f"{benchmark} / {model} / {experiment}".encode("ascii", "replace").decode()
    suffix = f" / {run_id}"
    return {
        "session_id": prefix[:199 - len(suffix)] + suffix,
        "user_id": os.getenv("RUN_BY", "").strip() or None,
        "tags": [benchmark, *tags],
    }


def guardrail_tag(config: dict) -> str:
    """Name the enabled security checks, e.g. guardrail:regex or guardrail:none."""
    enabled = [check["name"] for check in config["security"]["checks"] if check["enabled"]]
    return "guardrail:" + ("+".join(enabled) or "none")


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _flatten_score(value: Any, prefix: str = "") -> list[tuple[str, int | float | bool | str]]:
    if isinstance(value, dict):
        flattened: list[tuple[str, int | float | bool | str]] = []
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            flattened.extend(_flatten_score(item, path))
        return flattened
    if isinstance(value, (bool, int, float, str)):
        return [(prefix, value)]
    return []


def _token_usage(event: ModelEvent) -> dict[str, int]:
    usage = getattr(event.output, "usage", None)
    if usage is None:
        return {}
    usage = _jsonable(usage)
    aliases = {
        "input": ("input_tokens", "prompt_tokens"),
        "output": ("output_tokens", "completion_tokens"),
    }
    result = {}
    for target, names in aliases.items():
        for name in names:
            value = usage.get(name) if isinstance(usage, dict) else None
            if isinstance(value, (int, float)):
                result[target] = int(value)
                break
    return result


def _cost(event: ModelEvent) -> float | None:
    """Use Inspect's cost if set, else the cost the provider reported in its response."""
    cost = getattr(getattr(event.output, "usage", None), "total_cost", None)
    if cost is None and event.call is not None:
        cost = ((event.call.response or {}).get("usage") or {}).get("cost")
    if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
        return float(cost)
    return None


@dataclass
class _SampleTrace:
    root: Any
    sample_id: str
    attributes: dict = field(default_factory=dict)
    agent: Any = None
    scoring: Any = None
    scoring_started: bool = False
    seen_event_ids: set[str] = field(default_factory=set)


@hooks(name="Langfuse sample tracing", description="Exports Inspect sample, model, tool, scoring, and error events to Langfuse.")
class LangfuseHooks(Hooks):
    """One trace per sample, grouped into a Langfuse session per Inspect run."""

    def __init__(self, client: Any | None = None) -> None:
        self._client = client
        self._samples: dict[str, _SampleTrace] = {}
        self._sessions: dict[str, dict] = {}
        self._configs: dict[str, dict] = {}

    def enabled(self) -> bool:
        return tracing_enabled()

    def _get_client(self) -> Any:
        if self._client is None:
            from langfuse import get_client

            self._client = get_client()
        return self._client

    async def on_task_start(self, data: TaskStart) -> None:
        config_path = (data.spec.solver_args or {}).get("config_path")
        if config_path:
            from agents.swe import load_config

            self._configs[data.run_id] = load_config(config_path)

    async def on_sample_start(self, data: SampleStart) -> None:
        if not self.enabled():
            return
        from langfuse import propagate_attributes

        client = self._get_client()
        summary = data.summary
        sample_label = str(summary.id)
        trace_name = sample_label
        if data.run_id not in self._sessions:
            config = self._configs.get(data.run_id)
            experiment = config["experiment"] if config else "unknown"
            tags = ["agent:mini-swe-agent", "harness:inspect", guardrail_tag(config) if config else "guardrail:unknown"]
            self._sessions[data.run_id] = trace_attributes("codeipi", get_model().name, experiment, data.run_id, tags)
        attributes = {
            **self._sessions[data.run_id],
            "trace_name": trace_name,
            "metadata": {"inspect_eval_id": data.eval_id, "inspect_run_id": data.run_id},
        }
        with propagate_attributes(**attributes):
            root = client.start_observation(
                name=trace_name,
                as_type="span",
                input={"task": _jsonable(summary.input), "target": _jsonable(summary.target)},
                metadata={
                    "sample_id": sample_label,
                    "sample_epoch": summary.epoch,
                    "sample_metadata": _jsonable(summary.metadata),
                    "setup_phase": "CodeIPI task-level sandbox setup precedes the coding agent",
                    "repo_files_present": bool(summary.metadata.get("repo_files")),
                    "injection_vector": summary.metadata.get("injection_vector"),
                    "payload_category": summary.metadata.get("payload_category"),
                    "severity": summary.metadata.get("severity"),
                    "scoring_phase": "pending",
                },
            )
            state = _SampleTrace(root=root, sample_id=sample_label, attributes=attributes)
            state.agent = root.start_observation(
                name="stock mini-swe-agent", as_type="agent", input={"task": _jsonable(summary.input)}
            )
        current_agent_trace.set(state.agent)
        current_trace_attributes.set(attributes)
        self._samples[data.sample_id] = state

    async def on_sample_event(self, data: SampleEvent) -> None:
        state = self._samples.get(data.sample_id)
        if state is None:
            return
        from langfuse import propagate_attributes

        event = data.event
        parent = state.scoring or state.agent
        event_id = getattr(event, "uuid", None)
        if event_id is not None:
            if event_id in state.seen_event_ids:
                return
            state.seen_event_ids.add(event_id)
        if isinstance(event, ModelEvent):
            output = _jsonable(event.output)
            usage = _token_usage(event)
            completed_at = _jsonable(event.completed)
            metadata = {
                "phase": "scoring" if state.scoring_started else "agent",
                "inspect_event_id": event.uuid,
                "role": event.role,
                "retries": event.retries,
                "cache": event.cache,
                "working_start_seconds": event.working_start,
                "working_time_seconds": event.working_time,
                "event_timestamp": _jsonable(event.timestamp),
                "completed_at": completed_at,
                "error": event.error,
                "traceback": event.traceback if event.error else None,
            }
            cost = _cost(event)
            if event.cache == "read":
                # A local cache read makes no provider call, so it is not billed.
                usage, cost = {"input": 0, "output": 0}, 0.0
            with propagate_attributes(**state.attributes):
                obs = parent.start_observation(
                    name="model call",
                    as_type="generation",
                    model=event.model,
                    input=_jsonable(event.input),
                    output=output,
                    usage_details=usage,
                    cost_details={"total": cost} if cost is not None else None,
                    metadata=metadata,
                    level="ERROR" if event.error else None,
                    status_message=event.error,
                )
            obs.end()
        elif isinstance(event, ToolEvent):
            failed = bool(event.failed or event.error)
            completed_at = _jsonable(event.completed)
            metadata = {
                "phase": "scoring" if state.scoring_started else "agent",
                "inspect_event_id": event.uuid,
                "tool_call_id": event.id,
                "working_start_seconds": event.working_start,
                "working_time_seconds": event.working_time,
                "event_timestamp": _jsonable(event.timestamp),
                "completed_at": completed_at,
                "truncated": event.truncated,
                "failed": failed,
                "error": _jsonable(event.error),
            }
            with propagate_attributes(**state.attributes):
                obs = parent.start_observation(
                    name=f"tool: {event.function}",
                    as_type="tool",
                    input={"arguments": _jsonable(event.arguments), "code": _jsonable(event.view)},
                    output=_jsonable(event.result),
                    metadata=metadata,
                    level="ERROR" if failed else None,
                    status_message=str(event.error) if event.error else None,
                )
            obs.end()

    async def on_sample_scoring(self, data: SampleScoring) -> None:
        state = self._samples.get(data.sample_id)
        if state is None:
            return
        from langfuse import propagate_attributes

        state.scoring_started = True
        with propagate_attributes(**state.attributes):
            state.scoring = state.root.start_observation(name="scoring", as_type="evaluator")
        state.root.update(metadata={"scoring_phase": "started"})

    async def on_sample_end(self, data: SampleEnd) -> None:
        current_agent_trace.set(None)
        current_trace_attributes.set(None)
        state = self._samples.pop(data.sample_id, None)
        if state is None:
            return
        sample = data.sample
        scores = _jsonable(sample.scores or {})
        error = _jsonable(sample.error)
        state.root.update(
            output={"answer": _jsonable(sample.output), "scores": scores},
            metadata={
                "sample_id": state.sample_id,
                "scoring_phase": "complete" if state.scoring_started else "not_reached",
                "sample_error": error,
                "sample_total_time_seconds": sample.total_time,
                "sample_working_time_seconds": sample.working_time,
                "model_usage": _jsonable(sample.model_usage),
                "swe_config": sample.metadata.get("swe_config"),
                "security_decisions": sample.metadata.get("swe_decisions", []),
            },
            level="ERROR" if error else None,
            status_message=str(error) if error else None,
        )
        for scorer_name, score in (sample.scores or {}).items():
            value = getattr(score, "value", None)
            for metric_name, metric_value in _flatten_score(value):
                state.root.score_trace(
                    name=f"inspect/{scorer_name}/{metric_name}" if metric_name else f"inspect/{scorer_name}",
                    value=metric_value,
                    comment=getattr(score, "explanation", None),
                    metadata={
                        "answer": _jsonable(getattr(score, "answer", None)),
                        "reason": getattr(score, "reason", None),
                        "score_metadata": _jsonable(getattr(score, "metadata", None)),
                    },
                )
        if state.scoring:
            state.scoring.update(output={"scores": scores}).end()
        state.agent.update(output={"answer": _jsonable(sample.output)}, metadata={"phase": "agent"}).end()
        state.root.end()

    async def on_run_end(self, data: RunEnd) -> None:
        self._sessions.pop(data.run_id, None)
        self._configs.pop(data.run_id, None)
        if not self.enabled():
            return
        client = self._client
        if client is not None:
            client.flush()
