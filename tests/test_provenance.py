from pathlib import Path

import pytest

from scripts import run_issuetrojan, run_swebench


@pytest.mark.parametrize("module", [run_issuetrojan, run_swebench])
@pytest.mark.parametrize("status, dirty", [("", False), (" M tracked.py\n", True)])
def test_git_provenance_uses_runner_repository_when_cwd_differs(
    module, status, dirty, tmp_path, monkeypatch
):
    repository = Path(module.__file__).resolve().parents[1]
    calls = []

    def check_output(command, *, cwd, text):
        calls.append((command, cwd, text))
        return "repo-commit\n" if command[-2:] == ["rev-parse", "HEAD"] else status

    monkeypatch.setattr(module.subprocess, "check_output", check_output)
    monkeypatch.chdir(tmp_path)

    assert module.git_provenance() == {
        "git_commit": "repo-commit",
        "git_dirty": dirty,
    }
    assert [call[1] for call in calls] == [repository, repository]
    assert all(call[2] is True for call in calls)


def test_run_report_includes_wilson_interval_for_zero_resolved_tasks():
    from benchmarks.swebench.runner import run_report

    report = run_report(["a", "b"], [
        {"instance_id": "a", "resolved": 0, "scoring_status": "scored"},
        {"instance_id": "b", "resolved": 0, "scoring_status": "scored"},
    ])

    assert report["resolved_rate"] == 0
    assert report["resolved_ci_low"] == 0.0
    assert report["resolved_ci_high"] == 0.6576


def test_run_report_with_no_tasks_has_empty_rate_and_interval():
    from benchmarks.swebench.runner import run_report

    report = run_report([], [])

    assert report["resolved_rate"] is None
    assert report["resolved_ci_low"] is None
    assert report["resolved_ci_high"] is None
