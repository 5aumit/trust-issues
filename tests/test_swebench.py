import json
from pathlib import Path
import subprocess

import pytest

from benchmarks.issuetrojan.runner import ExecutionAdapter
from benchmarks.swebench.data import select_instances
from benchmarks.swebench.grade import grade
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


@pytest.mark.parametrize("fix_status, resolved", [("PASSED", True), ("FAILED", False)])
def test_official_grader_reads_utf8_logs(tmp_path, fix_status, resolved):
    from swebench.harness.constants import END_TEST_OUTPUT, START_TEST_OUTPUT

    (tmp_path / "instance.json").write_text(json.dumps(instance()), encoding="utf-8")
    (tmp_path / "patch.diff").write_text("diff --git a/x b/x\n", encoding="utf-8")
    (tmp_path / "test_output.txt").write_text(
        f"setup output with non-ASCII text: Ý ✓\n{START_TEST_OUTPUT}\n"
        f"{fix_status} test_a.py::test_fix\nPASSED test_a.py::test_keep\n{END_TEST_OUTPUT}\n",
        encoding="utf-8",
    )
    report = grade(tmp_path)
    assert report["resolved"] is resolved
    assert report["patch_successfully_applied"] is True


def test_patch_includes_all_changes_against_starting_commit(tmp_path):
    docker = FakeDocker({"returncode": 0, "output": "def456\n"})
    adapter = ExecutionAdapter(docker, tmp_path / "shell.jsonl")
    assert runner.start_commit(adapter) == "def456"
    docker.result = {"returncode": 0, "output": "diff --git a/x b/x\n"}
    assert runner.collect_patch(adapter, "def456") == "diff --git a/x b/x\n"
    assert docker.actions == [
        "git rev-parse HEAD",
        "git -c core.fileMode=false add -A && git -c core.fileMode=false diff --cached --text def456",
    ]
    docker.result = {"returncode": 128, "output": "fatal"}
    with pytest.raises(RuntimeError):
        runner.collect_patch(ExecutionAdapter(docker, tmp_path / "shell.jsonl"), "abc123")


def test_empty_patch_is_unresolved_without_running_tests(tmp_path, monkeypatch):
    (tmp_path / "patch.diff").write_text("", encoding="utf-8")
    monkeypatch.setattr(runner, "start_container", lambda *args: pytest.fail("started a container"))
    assert runner.evaluate(instance(), tmp_path, None) == {"resolved": 0, "scoring_status": "empty_patch"}


def test_patch_that_never_applies_is_unresolved_and_cleaned_up(tmp_path, monkeypatch):
    (tmp_path / "patch.diff").write_text("diff --git a/x b/x\n", encoding="utf-8")
    docker = FakeDocker({"returncode": 1, "output": "error: patch failed"})
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return ok_process(command)

    monkeypatch.setattr(runner, "start_container", lambda *args: docker)
    monkeypatch.setattr(runner.subprocess, "run", run)
    result = runner.evaluate(instance(), tmp_path, None)
    assert result["resolved"] == 0 and result["scoring_status"] == "patch_failed"
    assert docker.actions == runner.APPLY_COMMANDS
    assert ["docker", "rm", "-f", "grading-1"] in commands
    assert result["grading_cleanup"]["verified_absent"] is True
    assert not (tmp_path / "test_output.txt").exists()


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
