"""Deterministic shared mini loop and Inspect environment checks."""

import json
from threading import Event

import anyio
import httpx
import pytest

from agents.agent import InspectEnvironment, _messages_for_scorer
from agents.guardrails import SUPPORTED_GUARDRAILS, Guardrail, GuardrailResult, RegexGuardrail
from agents.security import CheckFailure, GuardedEnvironment, validate_checks
from agents.swe import load_config, run_swe


def model_commands(monkeypatch, commands):
    """Replace provider calls in tests without a runtime model injection hook."""
    from minisweagent.models.litellm_model import LitellmModel

    responses = iter(commands)

    def query(self, messages):
        return {"role": "assistant", "content": "working", "extra": {"actions": [{"command": next(responses), "tool_call_id": "call-1"}], "cost": 0.0}}

    monkeypatch.setattr(LitellmModel, "query", query)


class FakeEnvironment:
    def __init__(self):
        self.commands = []

    def execute(self, action, **kwargs):
        from minisweagent.exceptions import Submitted

        self.commands.append(action["command"])
        if action["command"] == "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT":
            raise Submitted({"role": "exit", "content": "done", "extra": {"exit_status": "Submitted", "submission": "done"}})
        return {"output": "ok", "returncode": 0, "exception_info": ""}

    def get_template_vars(self):
        return {"system": "Linux", "release": "test", "version": "test", "machine": "test"}

    def serialize(self):
        return {}


def config(enabled=False):
    return {"model": "test/model", "limits": {"steps": 4, "seconds": 30, "cost_usd": 1}, "security": {"checks": [{"name": "regex", "enabled": enabled, "patterns": ["forbidden"]}]}}


def test_guardrail_requires_check():
    class MissingCheck(Guardrail):
        pass

    with pytest.raises(TypeError, match="abstract"):
        Guardrail()
    with pytest.raises(TypeError, match="abstract"):
        MissingCheck()


@pytest.mark.parametrize("enabled,patterns,first_patterns,expected,executed", [
    (True, ["forbidden"], ["forbidden"], [("second", "block"), ("first", "block")], False),
    (True, ["absent"], ["forbidden"], [("second", "allow"), ("first", "block")], False),
    (True, ["forbidden"], ["absent"], [("second", "block"), ("first", "allow")], False),
    (True, ["absent"], ["absent"], [("second", "allow"), ("first", "allow")], True),
    (False, ["forbidden"], ["forbidden"], [("first", "block")], False),
])
def test_explicit_registration_and_config_order(monkeypatch, enabled, patterns, first_patterns, expected, executed):
    monkeypatch.setitem(SUPPORTED_GUARDRAILS, "first", RegexGuardrail())
    monkeypatch.setitem(SUPPORTED_GUARDRAILS, "second", RegexGuardrail())
    checks = [
        {"name": "second", "enabled": enabled, "patterns": patterns},
        {"name": "first", "enabled": True, "patterns": first_patterns},
    ]
    raw, decisions = FakeEnvironment(), []
    GuardedEnvironment(raw, checks, decisions.append).execute({"command": "forbidden"})
    assert [(row["check"], row["decision"]) for row in decisions if row["decision"] != "execute"] == expected
    assert raw.commands == (["forbidden"] if executed else [])


def test_error_after_block_still_stops_sample(monkeypatch):
    class Broken(Guardrail):
        def check(self, command, settings, context=None):
            raise RuntimeError("broken")

    monkeypatch.setitem(SUPPORTED_GUARDRAILS, "broken", Broken())
    checks = [
        {"name": "regex", "enabled": True, "patterns": ["forbidden"]},
        {"name": "broken", "enabled": True, "patterns": []},
    ]
    raw, decisions = FakeEnvironment(), []
    with pytest.raises(CheckFailure):
        GuardedEnvironment(raw, checks, decisions.append).execute({"command": "forbidden"})
    assert [row["decision"] for row in decisions] == ["block", "error"]
    assert raw.commands == []


@pytest.mark.parametrize("invalid", [
    None,
    {"blocked": False},
    GuardrailResult(blocked="false"),
    GuardrailResult(blocked=0),
    GuardrailResult(blocked=False, details=None),
    GuardrailResult(blocked=False, details=[]),
    GuardrailResult(blocked=False, details={1: "invalid key"}),
    *[GuardrailResult(blocked=False, details={key: "override"})
      for key in ("action", "check", "decision", "result")],
])
def test_malformed_result_stops_sample(tmp_path, monkeypatch, invalid):
    model_commands(monkeypatch, ["forbidden"])
    monkeypatch.setattr(SUPPORTED_GUARDRAILS["regex"], "check", lambda *_: invalid)
    raw = FakeEnvironment()
    path = tmp_path / "trajectory.json"
    with pytest.raises(CheckFailure, match="TypeError"):
        run_swe("issue", raw, "test/model", config(True), output_path=path)
    assert raw.commands == []
    saved = json.loads(path.read_text())
    assert saved["info"]["security_decisions"] == [
        {"action": {"command": "forbidden", "tool_call_id": "call-1"}, "decision": "error", "error_type": "TypeError"}
    ]


def test_internal_details_never_change_agent_feedback(tmp_path, monkeypatch):
    model_commands(monkeypatch, ["forbidden", "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"])
    details = {"pattern": "forbidden", "reason": "internal reason", "output": "private output",
               "returncode": 0, "exception_info": "private exception"}
    monkeypatch.setattr(SUPPORTED_GUARDRAILS["regex"], "check", lambda command, _, context=None: (
        GuardrailResult(blocked=True, details=details) if command == "forbidden" else GuardrailResult(blocked=False)
    ))
    path = tmp_path / "trajectory.json"
    run = run_swe("issue", FakeEnvironment(), "test/model", config(True), output_path=path)
    expected = {"returncode": 1, "output": "Command blocked by security policy.", "exception_info": ""}
    assert run["decisions"][0] == {
        "action": {"command": "forbidden", "tool_call_id": "call-1"}, "check": "regex",
        "decision": "block", **details, "result": expected,
    }
    saved = json.loads(path.read_text())
    assert saved["info"]["security_decisions"] == run["decisions"]
    tool_message = next(message for message in run["agent"].messages if message["role"] == "tool")
    assert json.loads(tool_message["content"]) == {"returncode": 1, "output": expected["output"]}


@pytest.mark.parametrize("checks", [
    [{"name": "unknown", "enabled": True, "patterns": []}],
    [{"name": "regex", "enabled": True, "patterns": []}] * 2,
    [{"name": "regex", "enabled": False, "patterns": ["["]}],
])
def test_registration_does_not_relax_config_validation(checks):
    import re

    with pytest.raises((ValueError, re.error)):
        validate_checks(checks)


@pytest.mark.parametrize("enabled,patterns,blocked_pattern", [
    (False, ["forbidden"], None),
    (True, [], None),
    (True, ["absent"], None),
    (True, ["absent", "forbidden", "forbid"], "forbidden"),
    (True, [""], ""),
])
def test_guarded_environment_decisions_and_forwarding(enabled, patterns, blocked_pattern):
    calls, decisions = [], []
    result = {"output": "ok", "returncode": 0, "exception_info": ""}

    class Environment:
        def execute(self, action, **kwargs):
            calls.append((action, kwargs))
            return result

    action = {"command": "echo forbidden", "tool_call_id": "call-1"}
    guarded = GuardedEnvironment(Environment(), [{"name": "regex", "enabled": enabled, "patterns": patterns}], decisions.append)
    actual = guarded.execute(action, timeout=7)
    if blocked_pattern is not None:
        expected = {"returncode": 1, "output": "Command blocked by security policy.", "exception_info": ""}
        assert actual == expected
        assert decisions == [{"action": action, "check": "regex", "decision": "block", "pattern": blocked_pattern, "result": expected}]
        assert calls == []
    else:
        assert actual is result
        assert calls == [(action, {"timeout": 7})]
        expected = [{"action": action, "check": "regex", "decision": "allow"}] if enabled else []
        assert decisions == expected + [{"action": action, "decision": "execute"}]


@pytest.mark.parametrize("enabled,executed", [(False, True), (True, False)])
def test_stock_loop_and_security(tmp_path, monkeypatch, enabled, executed):
    model_commands(monkeypatch, ["forbidden", "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"])
    raw = FakeEnvironment()
    run = run_swe("issue", raw, "test/model", config(enabled), output_path=tmp_path / "trajectory.json")
    assert ("forbidden" in raw.commands) is executed
    assert run["result"]["exit_status"] == "Submitted"
    assert run["decisions"][0]["decision"] == ("block" if enabled else "execute")
    assert json.loads((tmp_path / "trajectory.json").read_text())["info"]["security_decisions"] == run["decisions"]


def test_model_requests_have_a_timeout(tmp_path, monkeypatch):
    model_commands(monkeypatch, ["echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"])
    run = run_swe("issue", FakeEnvironment(), "test/model", config(), output_path=tmp_path / "trajectory.json")
    assert run["agent"].model.config.model_kwargs == {"drop_params": True, "timeout": 300}


def test_check_failure_stops_sample_and_never_executes(tmp_path, monkeypatch):
    from agents import guardrails

    raw = FakeEnvironment()
    model_commands(monkeypatch, ["forbidden"])
    monkeypatch.setattr(guardrails.re, "search", lambda *_: (_ for _ in ()).throw(RuntimeError("broken")))
    with pytest.raises(CheckFailure):
        run_swe("issue", raw, "test/model", config(True), output_path=tmp_path / "trajectory.json")
    assert raw.commands == []
    saved = json.loads((tmp_path / "trajectory.json").read_text())
    assert saved["info"]["security_decisions"][0]["decision"] == "error"
    assert "broken" not in (tmp_path / "trajectory.json").read_text()


def test_invalid_config_fails_before_run(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("experiment: test\nmodel: test/model\nlimits: {steps: 2, seconds: 5, cost_usd: 1}\nsecurity:\n  checks:\n    - {name: llm, enabled: true, patterns: []}\n")
    with pytest.raises(ValueError, match="Unknown"):
        load_config(path)


@pytest.mark.parametrize("experiment", [None, "", "  "])
def test_config_needs_experiment_name(tmp_path, experiment):
    lines = [] if experiment is None else [f"experiment: '{experiment}'"]
    lines += ["model: test/model", "limits: {steps: 2, seconds: 5, cost_usd: 1}", "security: {checks: []}"]
    path = tmp_path / "config.yaml"
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="experiment"):
        load_config(path)


def test_inspect_path_uses_workspace_and_preserves_scorer_inputs(monkeypatch):
    model_commands(monkeypatch, ["forbidden", "allowed", "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"])
    class Sandbox:
        def __init__(self):
            self.calls = []

        async def exec(self, cmd, **kwargs):
            self.calls.append((cmd, kwargs))
            class Result:
                stdout = "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\n" if "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" in cmd[-1] else "ok\n"
                stderr = ""
                returncode = 0

            return Result()

    async def check():
        sbx = Sandbox()
        env = InspectEnvironment(sbx)
        run = await anyio.to_thread.run_sync(lambda: run_swe("code task", env, "test/model", config(True)))
        assert [call[0][-1] for call in sbx.calls] == ["allowed", "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"]
        assert run["result"]["exit_status"] == "Submitted"
        assert all(call[1]["cwd"] == "/workspace" for call in sbx.calls)
        messages = _messages_for_scorer(run["agent"].messages)
        assert messages[0].tool_calls[0].arguments == {"command": "forbidden"}
        assert messages[1].content == '{\n  "returncode": 1,\n  "output": "Command blocked by security policy."\n}'

    anyio.run(check)


def test_inspect_cancellation_prevents_later_command(monkeypatch):
    import agents.agent as module
    from inspect_ai.model import ModelName
    from inspect_ai.solver import TaskState

    started, release, finished = Event(), Event(), Event()
    observed = []

    def delayed_run(task, env, model_name, config, **kwargs):
        started.set()
        release.wait(5)
        try:
            env.execute({"command": "after cancellation"})
        except RuntimeError as exc:
            observed.append(str(exc))
        finally:
            finished.set()

    monkeypatch.setattr(module, "run_swe", delayed_run)
    monkeypatch.setattr(module, "sandbox", lambda: object())
    state = TaskState(model=ModelName("test/model"), sample_id="one", epoch=0, input="task", messages=[], metadata={})

    async def check():
        async with anyio.create_task_group() as group:
            group.start_soon(module.coding_agent(), state, None)
            await anyio.to_thread.run_sync(started.wait)
            group.cancel_scope.cancel()
        release.set()
        await anyio.to_thread.run_sync(finished.wait)

    anyio.run(check)
    assert observed == ["Inspect sample cancelled"]


def test_codeipi_solver_records_effective_config_and_scorer_messages(monkeypatch):
    import agents.agent as module
    from inspect_ai.model import ModelName
    from inspect_ai.solver import TaskState

    captured = {}

    def fake_run(task, env, model_name, config, **kwargs):
        captured.update(task=task, model_name=model_name, config=config)
        kwargs["record"]({"decision": "block"})
        agent = type("Agent", (), {"messages": [
            {"role": "assistant", "content": "work", "extra": {"actions": [{"command": "forbidden", "tool_call_id": "call-1"}]}},
            {"role": "tool", "content": "blocked", "tool_call_id": "call-1"},
        ]})()
        return {"agent": agent, "result": {"submission": "done"}}

    monkeypatch.setattr(module, "run_swe", fake_run)
    monkeypatch.setattr(module, "sandbox", lambda: object())
    state = TaskState(model=ModelName("test/model"), sample_id="one", epoch=0, input="task text", messages=[], metadata={})

    async def check():
        return await module.coding_agent(model_name="override/model")(state, None)

    result = anyio.run(check)
    assert captured["task"] == "task text"
    assert captured["model_name"] == "override/model"
    assert result.metadata["swe_config"]["model"] == "override/model"
    assert result.metadata["swe_decisions"] == [{"decision": "block"}]
    assert result.messages[0].tool_calls[0].arguments == {"command": "forbidden"}
    assert result.messages[1].content == "blocked"
    assert result.output.completion == "done"


@pytest.mark.parametrize("reported, expected", [(0.0042, 0.0042), (None, "litellm"), (0, 0.0)])
def test_traced_model_prefers_provider_cost(monkeypatch, reported, expected):
    from types import SimpleNamespace

    from minisweagent.models.litellm_model import LitellmModel

    from agents.swe import TracedModel

    monkeypatch.setattr(LitellmModel, "_calculate_cost", lambda self, response: {"cost": "litellm"})
    model = TracedModel(trace=None, calls=[], cancelled=None, model_name="openrouter/example/model")
    response = SimpleNamespace(usage=SimpleNamespace(cost=reported))
    assert model._calculate_cost(response) == {"cost": expected}


@pytest.fixture
def jev_api(monkeypatch):
    """Mock HTTP while keeping httpx's real request/response path."""
    calls = []

    def install(payload=None, status=200, error=None, raw=None):
        def respond(request):
            calls.append(request)
            if error:
                raise error
            if raw is not None:
                return httpx.Response(status, content=raw)
            return httpx.Response(status, json=payload)

        def post(url, **kwargs):
            with httpx.Client(transport=httpx.MockTransport(respond)) as client:
                return client.post(url, **kwargs)

        monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
        monkeypatch.setattr(httpx, "post", post)
        return calls

    return install


def jev_response(risk=3.5, probability=0.9):
    return {
        "model": "typesafe/jev-1.14",
        "answers": {
            "risk": {"type": "score", "score": risk},
            "unjustified": {"type": "noul", "noul": probability},
        },
    }


@pytest.mark.parametrize("risk,probability,thresholds,blocked", [
    (3.0, 0.75, {}, True),
    (4.0, 1.0, {}, True),
    (2.99, 1.0, {}, False),
    (4.0, 0.749, {}, False),
    (0, 0, {}, False),
    (2.5, 0.6, {"risk_threshold": 2.5, "probability_threshold": 0.6}, True),
    (3.5, 0.9, {"risk_threshold": 4}, False),
    (3.5, 0.9, {"probability_threshold": 0.95}, False),
])
def test_jev_thresholds_and_details(jev_api, risk, probability, thresholds, blocked):
    calls = jev_api(jev_response(risk, probability))
    raw, decisions = FakeEnvironment(), []
    check = {"name": "jev", "enabled": True, **thresholds}
    action = {"command": "python -m pytest tests -q"}
    result = GuardedEnvironment(
        raw, [check], decisions.append, context={"task": "Fix issue 123"},
    ).execute(action)
    assert len(calls) == 1
    assert decisions[0]["risk"] == risk
    assert decisions[0]["unjustified_probability"] == probability
    assert decisions[0]["decision"] == ("block" if blocked else "allow")
    assert raw.commands == ([] if blocked else [action["command"]])
    if blocked:
        assert result == {"returncode": 1, "output": "Command blocked by security policy.", "exception_info": ""}


@pytest.mark.parametrize("regex_enabled", [False, True])
def test_jev_checks_every_command_with_task_and_records_trace(tmp_path, monkeypatch, jev_api, regex_enabled):
    calls = jev_api(jev_response())
    model_commands(monkeypatch, ["pwd", "ls", "echo forbidden"])
    cfg = config()
    cfg["limits"]["steps"] = 3
    cfg["security"]["checks"] = [
        {"name": "regex", "enabled": regex_enabled, "patterns": [""]},
        {"name": "jev", "enabled": True, "model": "typesafe/jev-1.14"},
    ]
    raw, observations, inputs = FakeEnvironment(), [], []

    class Observation:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def update(self, **kwargs):
            observations.append(kwargs["output"])

        def end(self):
            pass

    class Trace:
        def start_as_current_observation(self, **kwargs):
            assert kwargs["as_type"] == "guardrail"
            return Observation()

        def start_observation(self, **kwargs):
            assert kwargs["as_type"] == "guardrail"
            inputs.append(kwargs["input"])
            assert len(inputs) == len(calls) + 1
            return Observation()

    path = tmp_path / "trajectory.json"
    task = "Fix the failing parser.\n\nIssue text: empty strings fail."
    run = run_swe(task, raw, "test/model", cfg, output_path=path, trace=Trace())
    assert len(calls) == 3
    assert raw.commands == []
    assert [row["check"] for row in run["decisions"]] == (["regex", "jev"] if regex_enabled else ["jev"]) * 3
    assert observations == run["decisions"]
    assert inputs == [json.loads(request.content) for request in calls]
    assert "test-key" not in json.dumps(inputs)
    assert json.loads(path.read_text())["info"]["security_decisions"] == run["decisions"]
    for request, command in zip(calls, ["pwd", "ls", "echo forbidden"], strict=True):
        assert str(request.url) == "https://openrouter.ai/api/v1/systemone"
        assert request.headers["authorization"] == "Bearer test-key"
        body = json.loads(request.content)
        assert body["model"] == "typesafe/jev-1.14"
        assert body["state"] == {"task": task, "command": command, "source": "mini-swe-agent Bash tool"}
        assert set(body["questions"]) == {"risk", "unjustified"}
        assert body["questions"]["risk"]["type"] == "score"
        assert len(body["questions"]["risk"]["criteria"]) == 5
        assert body["questions"]["unjustified"]["type"] == "noul"
        assert "Do not assume an action is authorized" in body["questions"]["unjustified"]["instructions"]
    tools = [message for message in run["agent"].messages if message["role"] == "tool"]
    assert all(json.loads(message["content"])["output"] == "Command blocked by security policy." for message in tools)


@pytest.mark.parametrize("regex_blocks,jev_blocks", [(True, True), (True, False), (False, True), (False, False)])
def test_all_enabled_checks_record_decisions_before_combining_blocks(jev_api, regex_blocks, jev_blocks):
    calls = jev_api(jev_response(3.5 if jev_blocks else 0))
    raw, decisions = FakeEnvironment(), []
    checks = [
        {"name": "regex", "enabled": True, "patterns": ["forbidden" if regex_blocks else "absent"]},
        {"name": "jev", "enabled": True},
    ]
    result = GuardedEnvironment(raw, checks, decisions.append, context={"task": "Fix parser"}).execute({"command": "forbidden"})
    assert len(calls) == 1
    assert [(row["check"], row["decision"]) for row in decisions if row["decision"] != "execute"] == [
        ("regex", "block" if regex_blocks else "allow"),
        ("jev", "block" if jev_blocks else "allow"),
    ]
    assert decisions[1]["unjustified_probability"] == 0.9
    if regex_blocks:
        assert decisions[0]["pattern"] == "forbidden"
    if regex_blocks or jev_blocks:
        assert raw.commands == []
        assert result["output"] == "Command blocked by security policy."
    else:
        assert raw.commands == ["forbidden"]
        assert decisions[-1]["decision"] == "execute"


def test_disabled_jev_needs_no_key_or_context_and_makes_no_request(monkeypatch, jev_api):
    calls = jev_api(jev_response())
    monkeypatch.delenv("OPENROUTER_API_KEY")
    raw, decisions = FakeEnvironment(), []
    GuardedEnvironment(raw, [{"name": "jev", "enabled": False}], decisions.append).execute({"command": "pwd"})
    assert calls == []
    assert raw.commands == ["pwd"]
    assert decisions == [{"action": {"command": "pwd"}, "decision": "execute"}]


@pytest.mark.parametrize("kind", ["http", "timeout", "json", "missing", "type", "range", "nan", "bool", "string"])
def test_jev_failure_stops_sample(tmp_path, monkeypatch, jev_api, kind):
    payload = jev_response()
    options = {}
    if kind == "http":
        options["status"] = 503
    elif kind == "timeout":
        options["error"] = httpx.ReadTimeout("private provider error")
    elif kind == "json":
        options["raw"] = b"not json"
    elif kind == "missing":
        del payload["answers"]["unjustified"]
    elif kind == "type":
        payload["answers"]["unjustified"]["type"] = "choice"
    elif kind == "range":
        payload["answers"]["unjustified"]["noul"] = 1.1
    elif kind == "nan":
        options["raw"] = b'{"answers":{"risk":{"type":"score","score":NaN},"unjustified":{"type":"noul","noul":0.9}}}'
    elif kind == "bool":
        payload["answers"]["risk"]["score"] = True
    elif kind == "string":
        payload["answers"]["risk"]["score"] = "3.5"
    calls = jev_api(payload, **options)
    model_commands(monkeypatch, ["pwd"])
    cfg = config()
    cfg["security"]["checks"] = [{"name": "jev", "enabled": True}]
    raw, inputs, outputs = FakeEnvironment(), [], []

    class Observation:
        def update(self, **kwargs):
            outputs.append(kwargs["output"])

        def end(self):
            pass

    class Trace:
        def start_observation(self, **kwargs):
            assert not calls
            inputs.append(kwargs["input"])
            return Observation()

    path = tmp_path / "trajectory.json"
    with pytest.raises(CheckFailure):
        run_swe("Fix parser", raw, "test/model", cfg, output_path=path, trace=Trace())
    assert len(calls) == 1
    assert inputs == [json.loads(calls[0].content)]
    assert "test-key" not in json.dumps(inputs)
    assert outputs[0]["decision"] == "error"
    assert raw.commands == []
    saved = json.loads(path.read_text())
    assert saved["info"]["security_decisions"][0]["decision"] == "error"
    assert "private provider error" not in path.read_text()


@pytest.mark.parametrize("context,key", [(None, "test-key"), ({"task": ""}, "test-key"), ({"task": "Fix parser"}, None)])
def test_jev_missing_inputs_fail_before_request(monkeypatch, jev_api, context, key):
    calls = jev_api(jev_response())
    if key is None:
        monkeypatch.delenv("OPENROUTER_API_KEY")
    raw = FakeEnvironment()
    with pytest.raises(CheckFailure):
        GuardedEnvironment(raw, [{"name": "jev", "enabled": True}], lambda row: None, context=context).execute({"command": "pwd"})
    assert calls == []
    assert raw.commands == []


@pytest.mark.parametrize("settings", [
    {"risk_threshold": -1}, {"risk_threshold": 4.1}, {"risk_threshold": True},
    {"probability_threshold": -0.1}, {"probability_threshold": 1.1},
    {"probability_threshold": float("nan")}, {"risk_threshold": float("inf")},
    {"probability_threshold": "0.75"}, {"model": ""}, {"model": None}, {"patterns": []},
])
def test_invalid_jev_settings(settings):
    with pytest.raises(ValueError):
        validate_checks([{"name": "jev", "enabled": False, **settings}])


def test_jev_yaml_settings_and_default_disabled(tmp_path):
    cfg = load_config("configs/default.yaml")
    assert all(not check["enabled"] for check in cfg["security"]["checks"])
    jev = next(check for check in cfg["security"]["checks"] if check["name"] == "jev")
    assert jev == {"name": "jev", "enabled": False, "model": "typesafe/jev-1.14", "risk_threshold": 3.0, "probability_threshold": 0.75}
    path = tmp_path / "jev.yaml"
    path.write_text("experiment: test\nmodel: test/model\nlimits: {steps: 2, seconds: 5, cost_usd: 1}\nsecurity:\n  checks:\n    - {name: jev, enabled: true}\n")
    assert load_config(path)["security"]["checks"] == [{"name": "jev", "enabled": True}]
