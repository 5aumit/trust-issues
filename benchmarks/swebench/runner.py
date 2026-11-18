"""Docker execution, grading, tracing, and output files for SWE-bench Verified."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import time
import uuid

from agents.security import CheckFailure
from agents.swe import ExecutionAdapter, observation, run_swe

from .grade import grade, log_dir

# Shell settings from mini-swe-agent's SWE-bench config. BASH_ENV runs the image's
# `conda activate testbed` in non-login shells.
SHELL_ENV = {
    "PAGER": "cat",
    "MANPAGER": "cat",
    "LESS": "-R",
    "PIP_PROGRESS_BAR": "off",
    "TQDM_DISABLE": "1",
    "BASH_ENV": "/root/.bashrc",
}
AGENT_RUN_ARGS = [
    "--network=none",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=512",
    "--memory=4g",
    "--cpus=2",
]


def start_container(image: str, cidfile: Path, run_args: list[str]):
    from minisweagent.environments.docker import DockerEnvironment

    return DockerEnvironment(
        image=image,
        cwd="/testbed",
        env=SHELL_ENV,
        forward_env=[],
        executable="docker",
        interpreter=["bash", "-c"],
        timeout=60,
        container_timeout="2h",
        pull_timeout=1200,
        run_args=["--cidfile", str(cidfile), "--rm", *run_args],
    )


def remove_container(env, cidfile: Path) -> dict | None:
    """Remove the container, even when DockerEnvironment.__init__ failed after creating it."""
    container_id = env.container_id if env else None
    if not container_id and cidfile.exists():
        container_id = cidfile.read_text().strip()
    if not container_id:
        return None
    removed = subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)
    remaining = subprocess.run(
        ["docker", "container", "ls", "-aq", "--no-trunc", "--filter", f"id={container_id}"],
        capture_output=True,
        text=True,
    )
    if env:
        env.container_id = None
    return {
        "container_id": container_id,
        "remove_returncode": removed.returncode,
        "verified_absent": remaining.returncode == 0 and not remaining.stdout.strip(),
    }


def start_commit(adapter: ExecutionAdapter) -> str:
    """Record the image's checkout; images add a setup commit on top of the base commit."""
    result = adapter.execute({"command": "git rev-parse HEAD"})
    if result["returncode"] or result.get("exception_info"):
        raise RuntimeError("Could not read the starting commit")
    return result["output"].strip()


def collect_patch(adapter: ExecutionAdapter, commit: str) -> str:
    """Return the agent's changes relative to the starting commit.

    Binary changes are kept. File permission changes and ignored files are not included.
    """
    result = adapter.execute(
        {"command": f"git -c core.fileMode=false add -A && git -c core.fileMode=false diff --cached --binary {commit}"},
        timeout=120,
    )
    if result["returncode"] or result.get("exception_info"):
        raise RuntimeError("Could not read the agent's changes")
    return result["output"]


def grading_cleanup(instance_id: str, run_id: str) -> dict:
    """Check that the official harness removed its grading container."""
    name = f"sweb.eval.{instance_id.lower()}.{run_id}"
    remaining = subprocess.run(
        ["docker", "container", "ls", "-aq", "--filter", f"name={name}"],
        capture_output=True,
        text=True,
    )
    return {
        "container_name": name,
        "verified_absent": remaining.returncode == 0 and not remaining.stdout.strip(),
    }


def failure_status(logs: Path) -> str:
    """Read why the official harness could not grade the patch."""
    from swebench.harness.constants import APPLY_PATCH_FAIL, LOG_INSTANCE, LOG_TEST_OUTPUT

    def read(name):
        path = logs / name
        return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

    if APPLY_PATCH_FAIL in read(LOG_INSTANCE):
        return "patch_failed"
    if "Timeout error:" in read(LOG_TEST_OUTPUT):
        return "test_timeout"
    return "grading_error"


def evaluate(instance: dict, sample_dir: Path, trace) -> dict:
    """Grade the patch with the official SWE-bench harness."""
    patch = (sample_dir / "patch.diff").read_text(encoding="utf-8")
    if not patch.strip():
        return {"resolved": 0, "scoring_status": "empty_patch"}
    run_id = uuid.uuid4().hex[:12]
    logs = log_dir(sample_dir, run_id, instance["instance_id"])
    with observation(trace, "official grading", "tool", input={"run_id": run_id}) as obs:
        report = grade(sample_dir, run_id)
        if obs:
            obs.update(output={"report": report})
    outcome = {
        "grading_run_id": run_id,
        "grading_logs": logs.relative_to(sample_dir).as_posix(),
        "grading_cleanup": grading_cleanup(instance["instance_id"], run_id),
    }
    if report is None:
        return {**outcome, "resolved": 0, "scoring_status": failure_status(logs)}
    tests_status = report.pop("tests_status", {})
    return {
        **outcome,
        "resolved": int(report["resolved"]),
        "scoring_status": "scored",
        "report": report,
        "tests": {
            group: {result: len(names) for result, names in results.items()}
            for group, results in tests_status.items()
        },
    }


def run_instance(instance: dict, *, model: str, config: dict, out: Path, client):
    instance_id = instance["instance_id"]
    sample_dir = out / instance_id
    sample_dir.mkdir(parents=True)
    (sample_dir / "instance.json").write_text(json.dumps(instance), encoding="utf-8")
    (sample_dir / "issue.md").write_text(instance["problem_statement"], encoding="utf-8")
    cidfile = (sample_dir / "agent.cid").resolve()
    model_calls = []
    env = None
    agent = None
    started = time.monotonic()
    summary = {
        "instance_id": instance_id,
        "repo": instance["repo"],
        "base_commit": instance["base_commit"],
        "image": instance["image"],
        "model": model,
        "resolved": None,
        "scoring_status": "not_reached",
        "config": config,
    }
    with observation(
        client,
        instance_id,
        "span",
        input={"problem_statement": instance["problem_statement"]},
        metadata={"repo": instance["repo"], "base_commit": instance["base_commit"], "image": instance["image"]},
    ) as root:
        with observation(root, "stock mini-swe-agent", "agent") as agent_trace:
            try:
                env = start_container(instance["image"], cidfile, AGENT_RUN_ARGS)
                summary["container_id"] = env.container_id
                adapter = ExecutionAdapter(env, sample_dir / "shell.jsonl", agent_trace)
                summary["start_commit"] = start_commit(adapter)
                adapter.phase = "agent"

                def record_decision(row):
                    with (sample_dir / "decisions.jsonl").open("a") as stream:
                        stream.write(json.dumps(row) + "\n")

                run = run_swe(
                    instance["problem_statement"],
                    adapter,
                    model,
                    config,
                    output_path=sample_dir / "trajectory.json",
                    trace=agent_trace,
                    record=record_decision,
                    model_calls=model_calls,
                )
                agent = run["agent"]
                summary.update(command_counts(run))
                summary["exit_status"] = run["result"].get("exit_status", "unknown")
                adapter.phase = "collect_patch"
                (sample_dir / "patch.diff").write_text(
                    collect_patch(adapter, summary["start_commit"]), encoding="utf-8", newline="\n"
                )
            except Exception as exc:
                summary["infrastructure_error"] = type(exc).__name__
                summary["exit_status"] = "infrastructure_error"
                if isinstance(exc, CheckFailure):
                    summary["security_error"] = type(exc).__name__
            finally:
                summary["cleanup"] = remove_container(env, cidfile)
        if "infrastructure_error" not in summary:
            with observation(root, "scoring", "evaluator") as scoring_trace:
                try:
                    summary.update(evaluate(instance, sample_dir, scoring_trace))
                except Exception as exc:
                    summary["infrastructure_error"] = type(exc).__name__
                    summary["scoring_status"] = "grading_error"
                if scoring_trace:
                    scoring_trace.update(output={"resolved": summary["resolved"], "scoring_status": summary["scoring_status"]})
        if agent:
            summary["mini_cost_usd"] = agent.cost
        summary["model_calls"] = len(model_calls)
        summary["runtime_s"] = round(time.monotonic() - started, 2)
        summary["provider_cost_usd"] = (
            sum(c.get("usage", {}).get("cost", 0) or 0 for c in model_calls)
            if model_calls
            and all(isinstance(c.get("usage", {}).get("cost"), (int, float)) for c in model_calls)
            else None
        )
        summary["tokens"] = {
            key: sum(c.get("usage", {}).get(key, 0) or 0 for c in model_calls)
            for key in ("prompt_tokens", "completion_tokens")
        }
        (sample_dir / "model-calls.json").write_text(json.dumps(model_calls, indent=2))
        summary["resolved_metric_contribution"] = int(_is_resolved_category(summary))
        if root:
            root.update(output=summary)
            root.score_trace(name="SWE-bench/resolved", value=summary["resolved_metric_contribution"])
            if summary.get("command_block_rate") is not None:
                root.score_trace(name="SWE-bench/command_block_rate", value=summary["command_block_rate"])
            summary["langfuse_url"] = client.get_trace_url(trace_id=root.trace_id)
    (sample_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)
    return summary


def command_counts(run: dict) -> dict:
    """Count the agent's commands that the guardrails checked and blocked.

    SWE-bench issues contain no prompt injection, so every blocked command counts
    against the guardrails. The rate is None when the agent ran no commands.
    """
    checked, blocked = run["commands"]["checked"], run["commands"]["blocked"]
    by_check = {}
    for row in run["decisions"]:
        if row["decision"] == "block":
            by_check[row["check"]] = by_check.get(row["check"], 0) + 1
    return {
        "commands_checked": checked,
        "commands_blocked": blocked,
        "blocks_by_check": by_check,
        "command_block_rate": blocked / checked if checked else None,
    }


def run_report(instance_ids: list[str], results: list[dict]) -> dict:
    """Group results as the official harness report does.

    The resolved rate is over every selected task. Agent and grading failures are
    errors, and tasks not yet run are incomplete. Command block rates use the tasks
    whose agent run finished; agent failures have no complete command record.
    """
    groups = {"resolved": [], "unresolved": [], "empty_patch": [], "error": []}
    for row in results:
        status = row["scoring_status"]
        if row.get("infrastructure_error") or status not in ("scored", "empty_patch"):
            group = "error"
        elif status == "empty_patch":
            group = "empty_patch"
        else:
            group = "resolved" if _is_resolved_category(row) else "unresolved"
        groups[group].append(row["instance_id"])
    finished = {row["instance_id"] for row in results}
    groups["incomplete"] = [instance_id for instance_id in instance_ids if instance_id not in finished]
    counted = [row for row in results if "commands_checked" in row]
    checked = sum(row["commands_checked"] for row in counted)
    blocked = sum(row["commands_blocked"] for row in counted)
    rates = [row["command_block_rate"] for row in counted if row["command_block_rate"] is not None]
    return {
        "total_instances": len(instance_ids),
        **{f"{group}_instances": len(ids) for group, ids in groups.items()},
        "resolved_rate": len(groups["resolved"]) / len(instance_ids),
        "cbr_tasks": len(counted),
        "commands_checked": checked,
        "commands_blocked": blocked,
        "command_block_rate": blocked / checked if checked else None,
        "mean_task_command_block_rate": sum(rates) / len(rates) if rates else None,
        "tasks_with_blocks": sum(1 for row in counted if row["commands_blocked"]),
        **{f"{group}_ids": ids for group, ids in groups.items()},
    }


def _is_resolved_category(row: dict) -> bool:
    """Match the resolved group used by run_report for one attempted task."""
    return (
        not row.get("infrastructure_error")
        and row.get("scoring_status") == "scored"
        and bool(row.get("resolved"))
    )
