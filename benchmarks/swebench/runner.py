"""Docker execution, grading, tracing, and output files for SWE-bench Verified."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import time

from agents.security import CheckFailure
from agents.swe import observation, run_swe
from benchmarks.issuetrojan.runner import ExecutionAdapter

from .grade import grade

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
# Same order as the official harness: strict apply, then partial apply, then fuzzy.
APPLY_COMMANDS = [
    "git apply --verbose /tmp/patch.diff",
    "git apply --verbose --reject /tmp/patch.diff",
    "patch --batch --fuzz=5 -p1 -i /tmp/patch.diff",
]
EVAL_TIMEOUT = 1800


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
    """Return every change the agent made relative to the starting commit."""
    result = adapter.execute(
        {"command": f"git -c core.fileMode=false add -A && git -c core.fileMode=false diff --cached --text {commit}"},
        timeout=120,
    )
    if result["returncode"] or result.get("exception_info"):
        raise RuntimeError("Could not read the agent's changes")
    return result["output"]


def evaluate(instance: dict, sample_dir: Path, trace) -> dict:
    """Apply the patch in a fresh container, run the official tests, and grade the log."""
    patch = (sample_dir / "patch.diff").read_text(encoding="utf-8")
    if not patch.strip():
        return {"resolved": 0, "scoring_status": "empty_patch"}
    (sample_dir / "eval.sh").write_text(instance["eval_script"], encoding="utf-8", newline="\n")
    cidfile = (sample_dir / "grading.cid").resolve()
    env = None
    outcome = {}
    try:
        env = start_container(instance["image"], cidfile, [])
        adapter = ExecutionAdapter(env, sample_dir / "shell.jsonl", trace)
        adapter.phase = "grading"
        for name in ("patch.diff", "eval.sh"):
            subprocess.run(
                ["docker", "cp", str(sample_dir / name), f"{env.container_id}:/tmp/{name}"],
                check=True,
                capture_output=True,
            )
        if not any(
            adapter.execute({"command": command}, timeout=120)["returncode"] == 0
            for command in APPLY_COMMANDS
        ):
            outcome = {"resolved": 0, "scoring_status": "patch_failed"}
        else:
            with observation(trace, "run tests", "tool", input={"command": "/bin/bash /tmp/eval.sh"}) as obs:
                try:
                    tests = subprocess.run(
                        ["docker", "exec", env.container_id, "/bin/bash", "/tmp/eval.sh"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=EVAL_TIMEOUT,
                    )
                    (sample_dir / "test_output.txt").write_text(
                        tests.stdout.decode("utf-8", errors="replace"), encoding="utf-8"
                    )
                    if obs:
                        obs.update(output={"returncode": tests.returncode})
                except subprocess.TimeoutExpired:
                    outcome = {"resolved": 0, "scoring_status": "test_timeout"}
    finally:
        outcome["grading_cleanup"] = remove_container(env, cidfile)
    if "scoring_status" in outcome:
        return outcome
    report = grade(sample_dir)
    (sample_dir / "report.json").write_text(json.dumps(report, indent=2))
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
        if root:
            root.update(output=summary)
            if summary["resolved"] is not None:
                root.score_trace(name="SWE-bench/resolved", value=summary["resolved"])
            summary["langfuse_url"] = client.get_trace_url(trace_id=root.trace_id)
    (sample_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)
    return summary
