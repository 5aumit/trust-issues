import json
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
