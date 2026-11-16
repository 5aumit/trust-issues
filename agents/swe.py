"""Shared stock mini-swe-agent construction and execution."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path

import yaml
from minisweagent.models.litellm_model import LitellmModel

from agents.security import GuardedEnvironment, validate_checks

MODEL_TIMEOUT_SECONDS = 300


def load_config(path: str | Path):
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    required = {"experiment", "model", "limits", "security"}
    if not isinstance(data, dict) or not required <= set(data) <= required | {"require_bash"}:
        raise ValueError("Config needs experiment, model, limits, and security, with optional require_bash")
    if not isinstance(data["experiment"], str) or not data["experiment"].strip():
        raise ValueError("experiment must be a non-empty string")
    if data["model"] is not None and not isinstance(data["model"], str):
        raise ValueError("model must be a string or null")
    if "require_bash" in data and not isinstance(data["require_bash"], bool):
        raise ValueError("require_bash must be a boolean")
    limits = data["limits"]
    if not isinstance(limits, dict) or set(limits) != {"steps", "seconds", "cost_usd"}:
        raise ValueError("limits needs steps, seconds, and cost_usd")
    if not all(
        isinstance(limits[key], int) and not isinstance(limits[key], bool) and limits[key] > 0
        for key in ("steps", "seconds")
    ):
        raise ValueError("steps and seconds must be positive integers")
    if (
        not isinstance(limits["cost_usd"], (int, float))
        or isinstance(limits["cost_usd"], bool)
        or limits["cost_usd"] <= 0
    ):
        raise ValueError("cost_usd must be positive")
    security = data["security"]
    if not isinstance(security, dict) or set(security) != {"checks"}:
        raise ValueError("security needs only checks")
    validate_checks(security["checks"])
    return data


def observation(parent, name, kind, **kwargs):
    return parent.start_as_current_observation(name=name, as_type=kind, **kwargs) if parent else nullcontext(None)


class TracedModel(LitellmModel):
    def __init__(self, *, trace, calls, cancelled, **kwargs):
        super().__init__(**kwargs)
        self.trace = trace
        self.calls = calls
        self.cancelled = cancelled

    def _query(self, messages, **kwargs):
        if self.cancelled is not None and self.cancelled.is_set():
            raise RuntimeError("Inspect sample cancelled")
        with observation(self.trace, "model call", "generation", model=self.config.model_name, input=messages) as obs:
            try:
                response = super()._query(messages, **kwargs)
            except Exception as exc:
                raise RuntimeError(f"Provider call failed ({type(exc).__name__})") from None
            raw = response.model_dump(mode="json")
            self.calls.append(raw)
            if obs:
                usage = raw.get("usage") or {}
                obs.update(
                    output=raw,
                    usage_details={
                        "input": usage.get("prompt_tokens", 0),
                        "output": usage.get("completion_tokens", 0),
                    },
                    cost_details={"total": usage["cost"]} if isinstance(usage.get("cost"), (int, float)) else None,
                    metadata={"provider_returned_reasoning": raw.get("choices", [{}])[0].get("message", {}).get("reasoning_content")},
                )
            return response

    def _calculate_cost(self, response):
        """Prefer the provider-reported cost, since LiteLLM may not price the model."""
        cost = getattr(getattr(response, "usage", None), "cost", None)
        if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
            return {"cost": float(cost)}
        return super()._calculate_cost(response)


def run_swe(
    task, env, model_name, config, *, output_path=None, trace=None,
    record=None, model_calls=None, cancelled=None,
):
    """Run unmodified DefaultAgent logic with one guarded command boundary."""
    from minisweagent import package_dir
    from minisweagent.agents.default import DefaultAgent

    stock = yaml.safe_load((package_dir / "config/mini.yaml").read_text(encoding="utf-8"))
    agent_config = stock["agent"]
    agent_config.pop("mode", None)
    limits = config["limits"]
    agent_config.update(
        step_limit=limits["steps"],
        wall_time_limit_seconds=limits["seconds"],
        cost_limit=limits["cost_usd"],
        output_path=output_path,
    )
    calls = model_calls if model_calls is not None else []
    decisions = []
    jev_observation = None

    def trace_jev_request(body):
        nonlocal jev_observation
        jev_observation = trace.start_observation(
            name="security check", as_type="guardrail", input=body,
        )

    def save_decision(row):
        nonlocal jev_observation
        decisions.append(row)
        if jev_observation:
            jev_observation.update(output=row)
            jev_observation.end()
            jev_observation = None
        elif row["decision"] != "execute":
            with observation(trace, "security check", "guardrail", input=row["action"]) as obs:
                if obs:
                    obs.update(output=row)
        if record:
            record(row)

    guarded = GuardedEnvironment(
        env, config["security"]["checks"], save_decision,
        context={"task": task, "source": "mini-swe-agent Bash tool"},
        on_jev_request=trace_jev_request if trace else None,
    )
    # LiteLLM waits up to 6000 s by default. Cancel a stuck reply sooner; mini-swe-agent retries it.
    model_kwargs = {**stock["model"].get("model_kwargs", {}), "timeout": MODEL_TIMEOUT_SECONDS}
    if config.get("require_bash", False):
        model_kwargs["tool_choice"] = {"type": "function", "function": {"name": "bash"}}
    model = TracedModel(
        model_name=model_name, trace=trace, calls=calls, cancelled=cancelled,
        **{**stock["model"], "model_kwargs": model_kwargs},
    )
    agent = DefaultAgent(model, guarded, **agent_config)
    try:
        result = agent.run(task=task)
        if guarded.error:
            raise guarded.error
        agent.save(output_path, {"info": {"swe_config": config, "security_decisions": decisions}})
        return {"result": result, "agent": agent, "model_calls": calls, "decisions": decisions}
    except Exception:
        if agent.messages and agent.messages[-1].get("role") == "exit":
            exc = agent.messages[-1].get("extra", {}).get("exit_status", "Error")
            agent.messages[-1] = {"role": "exit", "content": exc, "extra": {"exit_status": exc}}
        agent.save(output_path, {"info": {"swe_config": config, "security_decisions": decisions}})
        raise
