import json
from contextlib import contextmanager
from pathlib import Path
import subprocess

import pytest

from agents.swe import ExecutionAdapter
from benchmarks.swebench.data import select_instances
from benchmarks.swebench import grade as grade_module
from benchmarks.swebench.grade import grade, log_dir
import benchmarks.swebench.runner as runner


def instance(instance_id="org__repo-1", **overrides):
    row = {
        "instance_id": instance_id,
        "repo": "org/repo",
        "version": "1.0",
        "base_commit": "abc123",
        "image": "swebench/example:latest",
        "problem_statement": "Fix the bug",
        "eval_script": "echo tests",
        "log_parser": "parse_log_pytest",
        "eval_type": "pass_and_fail",
        "FAIL_TO_PASS": json.dumps(["test_a.py::test_fix"]),
        "PASS_TO_PASS": json.dumps(["test_a.py::test_keep"]),
    }
    return {**row, **overrides}


class FakeDocker:
    def __init__(self, result, container_id="grading-1"):
        self.result = result
        self.container_id = container_id
        self.actions = []

    def execute(self, action, **kwargs):
        self.actions.append(action["command"])
        return self.result


NO_COMMANDS = {"commands": {"checked": 0, "blocked": 0}, "decisions": []}


def ok_process(command, **kwargs):
    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


def test_selection_keeps_dataset_order_and_limit():
    rows = [instance("a"), instance("b"), instance("c")]
    assert [row["instance_id"] for row in select_instances(rows, ids=["c", "a"])] == ["a", "c"]
    assert [row["instance_id"] for row in select_instances(rows, limit=2)] == ["a", "b"]


@pytest.mark.parametrize("filters", [{"ids": []}, {"ids": ["a", "a"]}, {"ids": ["missing"]}, {"limit": 0}])
def test_invalid_selection_rejected(filters):
    with pytest.raises(ValueError):
        select_instances([instance("a")], **filters)


def test_grader_runs_official_harness_in_utf8_mode(tmp_path, monkeypatch):
    (tmp_path / "instance.json").write_text(json.dumps(instance()), encoding="utf-8")
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        report = log_dir(tmp_path, "run1", "org__repo-1") / "report.json"
        report.parent.mkdir(parents=True)
        report.write_text(json.dumps({"org__repo-1": {"resolved": True}}), encoding="utf-8")
        return ok_process(command)

    monkeypatch.setattr(grade_module.subprocess, "run", run)
    assert grade(tmp_path, "run1") == {"resolved": True}
    command, kwargs = calls[0]
    assert command[1:5] == ["-X", "utf8", "-m", "benchmarks.swebench.grade"]
    assert command[5:] == [str(tmp_path.resolve()), "run1"]
    assert kwargs["cwd"] == tmp_path.resolve()


def test_grader_returns_none_without_report(tmp_path, monkeypatch):
    (tmp_path / "instance.json").write_text(json.dumps(instance()), encoding="utf-8")
    monkeypatch.setattr(grade_module.subprocess, "run", ok_process)
    assert grade(tmp_path, "run1") is None


def test_harness_files_keep_lf_line_endings(tmp_path):
    grade_module.write_text_with_lf(tmp_path / "eval.sh", "a\nb\n")
    assert (tmp_path / "eval.sh").read_bytes() == b"a\nb\n"


def test_patch_includes_all_changes_against_starting_commit(tmp_path):
    docker = FakeDocker({"returncode": 0, "output": "def456\n"})
    adapter = ExecutionAdapter(docker, tmp_path / "shell.jsonl")
    assert runner.start_commit(adapter) == "def456"
    docker.result = {"returncode": 0, "output": "diff --git a/x b/x\n"}
    assert runner.collect_patch(adapter, "def456") == "diff --git a/x b/x\n"
    assert docker.actions == [
        "git rev-parse HEAD",
        "git -c core.fileMode=false add -A && git -c core.fileMode=false diff --cached --binary def456",
    ]
    docker.result = {"returncode": 128, "output": "fatal"}
    with pytest.raises(RuntimeError):
        runner.collect_patch(ExecutionAdapter(docker, tmp_path / "shell.jsonl"), "abc123")


def test_empty_patch_is_unresolved_without_grading(tmp_path, monkeypatch):
    (tmp_path / "patch.diff").write_text("", encoding="utf-8")
    monkeypatch.setattr(runner, "grade", lambda *args: pytest.fail("graded an empty patch"))
    assert runner.evaluate(instance(), tmp_path, None) == {"resolved": 0, "scoring_status": "empty_patch"}


def test_official_report_is_scored_and_container_checked(tmp_path, monkeypatch):
    (tmp_path / "patch.diff").write_text("diff --git a/x b/x\n", encoding="utf-8")
    report = {
        "resolved": True,
        "tests_status": {"FAIL_TO_PASS": {"success": ["t1"], "failure": []}},
    }
    commands = []
    monkeypatch.setattr(runner, "grade", lambda sample_dir, run_id: dict(report))
    monkeypatch.setattr(runner.subprocess, "run", lambda command, **kwargs: commands.append(command) or ok_process(command))
    result = runner.evaluate(instance(), tmp_path, None)
    assert result["resolved"] == 1 and result["scoring_status"] == "scored"
    assert result["tests"] == {"FAIL_TO_PASS": {"success": 1, "failure": 0}}
    assert result["grading_logs"] == f"logs/run_evaluation/{result['grading_run_id']}/mini-swe-agent/org__repo-1"
    name = f"sweb.eval.org__repo-1.{result['grading_run_id']}"
    assert commands == [["docker", "container", "ls", "-aq", "--filter", f"name={name}"]]
    assert result["grading_cleanup"]["verified_absent"] is True


@pytest.mark.parametrize(
    "log_name, text, status",
    [
        ("run_instance.log", ">>>>> Patch Apply Failed:\nerror", "patch_failed"),
        ("test_output.txt", "partial output\n\nTimeout error: 1800 seconds exceeded.", "test_timeout"),
        ("run_instance.log", "Error creating container", "grading_error"),
    ],
)
def test_harness_failure_reason_is_read_from_logs(tmp_path, monkeypatch, log_name, text, status):
    (tmp_path / "patch.diff").write_text("diff --git a/x b/x\n", encoding="utf-8")

    def grade_without_report(sample_dir, run_id):
        logs = log_dir(sample_dir, run_id, "org__repo-1")
        logs.mkdir(parents=True)
        (logs / log_name).write_text(text, encoding="utf-8")

    monkeypatch.setattr(runner, "grade", grade_without_report)
    monkeypatch.setattr(runner.subprocess, "run", ok_process)
    result = runner.evaluate(instance(), tmp_path, None)
    assert result["resolved"] == 0 and result["scoring_status"] == status

def test_agent_container_failure_skips_grading_and_cleans_up(tmp_path, monkeypatch):
    import minisweagent.environments.docker as docker

    def fail_start(**kwargs):
        args = kwargs["run_args"]
        Path(args[args.index("--cidfile") + 1]).write_text("abc123")
        assert "--network=none" in args
        raise RuntimeError("startup failed after creation")

    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return ok_process(command)

    monkeypatch.setattr(docker, "DockerEnvironment", fail_start)
    monkeypatch.setattr(runner.subprocess, "run", run)
    monkeypatch.setattr(runner, "evaluate", lambda *args: pytest.fail("graded after an agent failure"))
    result = runner.run_instance(instance(), model="unused", config={}, out=tmp_path, client=None)
    assert commands[0] == ["docker", "rm", "-f", "abc123"]
    assert result["cleanup"]["verified_absent"] is True
    assert result["resolved"] is None
    assert result["infrastructure_error"] == "RuntimeError"


class FakeTrace:
    trace_id = "trace-1"

    def __init__(self):
        self.output = None
        self.scores = []

    def update(self, **kwargs):
        self.output = kwargs.get("output")

    def score_trace(self, **kwargs):
        self.scores.append(kwargs)


class FakeClient:
    def __init__(self):
        self.traces = []

    def get_trace_url(self, trace_id):
        return f"https://langfuse.test/trace/{trace_id}"


def test_run_instance_resolved_score_matches_report_for_all_outcomes(tmp_path, monkeypatch):
    import types

    root = FakeTrace()
    client = FakeClient()
    client.traces.append(root)

    @contextmanager
    def fake_observation(parent, *args, **kwargs):
        yield root if parent is client else FakeTrace()

    monkeypatch.setattr(runner, "observation", fake_observation)
    monkeypatch.setattr(runner, "start_commit", lambda adapter: "abc123")
    monkeypatch.setattr(runner, "collect_patch", lambda adapter, commit: "patch")
    monkeypatch.setattr(runner, "start_container", lambda *args: types.SimpleNamespace(container_id="agent-1"))
    monkeypatch.setattr(runner, "remove_container", lambda *args: {"verified_absent": True})
    monkeypatch.setattr(runner, "run_swe", lambda *args, **kwargs: {"agent": None, "result": {"exit_status": "submitted"}, **NO_COMMANDS})

    cases = [
        ("resolved", {"resolved": 1, "scoring_status": "scored"}, 1),
        ("unresolved", {"resolved": 0, "scoring_status": "scored"}, 0),
        ("empty", {"resolved": 0, "scoring_status": "empty_patch"}, 0),
        ("grading_error", RuntimeError("grader failed"), 0),
    ]
    results = []
    for name, evaluation, contribution in cases:
        if isinstance(evaluation, Exception):
            monkeypatch.setattr(runner, "evaluate", lambda *args: (_ for _ in ()).throw(evaluation))
        else:
            monkeypatch.setattr(runner, "evaluate", lambda *args, _result=evaluation: _result)
        result = runner.run_instance(instance(name), model="unused", config={}, out=tmp_path, client=client)
        results.append(result)
        assert result["resolved_metric_contribution"] == contribution
        assert root.scores[-1] == {"name": "SWE-bench/resolved", "value": contribution}
        assert root.output["resolved"] == result["resolved"]
        if name == "grading_error":
            assert result["resolved"] is None
            assert result["scoring_status"] == "grading_error"
            assert result["infrastructure_error"] == "RuntimeError"

    # A startup failure keeps its raw result and error category, but contributes zero.
    def fail_start(*args):
        raise RuntimeError("startup failed")

    monkeypatch.setattr(runner, "start_container", fail_start)
    failed = runner.run_instance(instance("startup_error"), model="unused", config={}, out=tmp_path, client=client)
    results.append(failed)
    assert failed["resolved"] is None
    assert failed["scoring_status"] == "not_reached"
    assert failed["infrastructure_error"] == "RuntimeError"
    assert failed["resolved_metric_contribution"] == 0
    assert root.output["resolved"] is None
    assert root.output["infrastructure_error"] == "RuntimeError"
    assert root.scores[-1]["value"] == 0
    report = runner.run_report([row["instance_id"] for row in results], results)
    assert sum(score["value"] for score in root.scores) / len(root.scores) == report["resolved_rate"]


def test_run_instance_without_tracing_still_records_metric_contribution(tmp_path, monkeypatch):
    import types

    monkeypatch.setattr(runner, "start_container", lambda *args: types.SimpleNamespace(container_id="agent-1"))
    monkeypatch.setattr(runner, "start_commit", lambda adapter: "abc123")
    monkeypatch.setattr(runner, "collect_patch", lambda adapter, commit: "patch")
    monkeypatch.setattr(runner, "run_swe", lambda *args, **kwargs: {"agent": None, "result": {"exit_status": "submitted"}, **NO_COMMANDS})
    monkeypatch.setattr(runner, "evaluate", lambda *args: {"resolved": 1, "scoring_status": "scored"})
    monkeypatch.setattr(runner, "remove_container", lambda *args: {"verified_absent": True})
    result = runner.run_instance(instance(), model="unused", config={}, out=tmp_path, client=None)
    assert result["resolved"] == 1
    assert result["resolved_metric_contribution"] == 1
    assert result["command_block_rate"] is None


def test_run_instance_records_command_block_rate(tmp_path, monkeypatch):
    import types

    root = FakeTrace()
    client = FakeClient()

    @contextmanager
    def fake_observation(parent, *args, **kwargs):
        yield root if parent is client else FakeTrace()

    action = {"command": "rm -rf build"}
    run = {
        "agent": None,
        "result": {"exit_status": "submitted"},
        "commands": {"checked": 4, "blocked": 1},
        "decisions": [
            {"action": action, "check": "regex", "decision": "block", "pattern": "rm"},
            {"action": action, "check": "jev", "decision": "block"},
            {"action": {"command": "ls"}, "check": "regex", "decision": "allow"},
            {"action": {"command": "ls"}, "decision": "execute"},
        ],
    }
    monkeypatch.setattr(runner, "observation", fake_observation)
    monkeypatch.setattr(runner, "start_container", lambda *args: types.SimpleNamespace(container_id="agent-1"))
    monkeypatch.setattr(runner, "start_commit", lambda adapter: "abc123")
    monkeypatch.setattr(runner, "collect_patch", lambda adapter, commit: "patch")
    monkeypatch.setattr(runner, "run_swe", lambda *args, **kwargs: run)
    monkeypatch.setattr(runner, "evaluate", lambda *args: {"resolved": 0, "scoring_status": "scored"})
    monkeypatch.setattr(runner, "remove_container", lambda *args: {"verified_absent": True})
    result = runner.run_instance(instance(), model="unused", config={}, out=tmp_path, client=client)
    assert result["commands_checked"] == 4
    assert result["commands_blocked"] == 1
    assert result["blocks_by_check"] == {"regex": 1, "jev": 1}
    assert result["command_block_rate"] == 0.25
    assert root.scores[-1] == {"name": "SWE-bench/command_block_rate", "value": 0.25}


def test_run_report_uses_every_selected_task():
    results = [
        {"instance_id": "a", "resolved": 1, "scoring_status": "scored"},
        {"instance_id": "b", "resolved": 0, "scoring_status": "scored"},
        {"instance_id": "c", "resolved": 0, "scoring_status": "empty_patch"},
        {"instance_id": "d", "resolved": 0, "scoring_status": "test_timeout"},
        {"instance_id": "e", "resolved": None, "scoring_status": "not_reached", "infrastructure_error": "RuntimeError"},
    ]
    report = runner.run_report(["a", "b", "c", "d", "e", "f"], results)
    assert report["total_instances"] == 6
    assert report["resolved_rate"] == 1 / 6
    assert {group: report[f"{group}_ids"] for group in ("resolved", "unresolved", "empty_patch", "error", "incomplete")} == {
        "resolved": ["a"],
        "unresolved": ["b"],
        "empty_patch": ["c"],
        "error": ["d", "e"],
        "incomplete": ["f"],
    }
    assert report["command_block_rate"] is None
    assert report["cbr_tasks"] == 0


def test_run_report_command_block_rate_skips_agent_failures():
    def row(instance_id, checked, blocked, **extra):
        return {
            "instance_id": instance_id, "resolved": 0, "scoring_status": "scored",
            "commands_checked": checked, "commands_blocked": blocked,
            "command_block_rate": blocked / checked if checked else None, **extra,
        }

    results = [
        row("a", 10, 1),
        row("b", 2, 1),
        row("c", 0, 0),
        # Grading failed after the agent finished; its commands still count.
        row("d", 8, 0, scoring_status="grading_error", infrastructure_error="RuntimeError"),
        # The agent failed, so it has no command counts.
        {"instance_id": "e", "resolved": None, "scoring_status": "not_reached", "infrastructure_error": "CheckFailure"},
    ]
    report = runner.run_report(["a", "b", "c", "d", "e"], results)
    assert report["cbr_tasks"] == 4
    assert (report["commands_checked"], report["commands_blocked"]) == (20, 2)
    assert report["command_block_rate"] == 0.1
    assert report["mean_task_command_block_rate"] == pytest.approx((0.1 + 0.5 + 0) / 3)
    assert report["tasks_with_blocks"] == 2
