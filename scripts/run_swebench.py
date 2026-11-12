"""Run SWE-bench Verified tasks with stock mini-swe-agent and the official grader."""

from __future__ import annotations

import argparse
from importlib.metadata import version
import json
import os
from pathlib import Path
import uuid

from benchmarks.swebench.data import DATASET, REVISION, load_instances, select_instances
from scripts.run_issuetrojan import configure, configure_tracing


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("configs/default.yaml"))
    parser.add_argument("--model")
    parser.add_argument("--instances", nargs="+", help="Instance IDs; default: all 500")
    parser.add_argument("--limit", type=int, help="Run the first N selected instances")
    parser.add_argument(
        "--list", action="store_true", help="List selected instance IDs without running"
    )
    parser.add_argument("--steps", type=int)
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--cost-limit", type=float)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.list and args.output is None:
        parser.error("--output is required unless --list is used")
    return args


def main():
    args = parse_args()
    try:
        instances = select_instances(load_instances(), ids=args.instances, limit=args.limit)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    if args.list:
        print("\n".join(row["instance_id"] for row in instances))
        return
    args.output.mkdir(parents=True, exist_ok=False)
    os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = str((args.output / "mini-config").resolve())
    os.environ["MSWEA_SILENT_STARTUP"] = "1"
    from benchmarks.swebench.runner import run_instance

    config = configure(
        path=args.config,
        model=args.model,
        steps=args.steps,
        seconds=args.seconds,
        cost_limit=args.cost_limit,
    )
    (args.output / "provenance.json").write_text(
        json.dumps(
            {
                "dataset": DATASET,
                "dataset_revision": REVISION,
                "swebench_version": version("swebench"),
                "instances": [row["instance_id"] for row in instances],
                "adaptations": [
                    "Stock mini.yaml prompts and shared run_swe; issue text given as the task",
                    "Agent container: official image, network off, Docker resource limits",
                    "Patch: git diff of all changes in /testbed against the image's starting commit",
                    "Grading: fresh container with network, official eval script and swebench grader",
                ],
            },
            indent=2,
        )
    )
    client = configure_tracing()
    from agents.tracing import guardrail_tag, trace_attributes

    attributes = trace_attributes(
        "swebench",
        config["model"],
        config["experiment"],
        uuid.uuid4().hex[:12],
        ["agent:mini-swe-agent", guardrail_tag(config)],
    )
    from langfuse import propagate_attributes

    results = []
    try:
        with propagate_attributes(**attributes):
            for instance in instances:
                print("Starting", instance["instance_id"], flush=True)
                with propagate_attributes(trace_name=instance["instance_id"]):
                    results.append(
                        run_instance(
                            instance,
                            model=config["model"],
                            config=config,
                            out=args.output,
                            client=client,
                        )
                    )
                resolved = [row["resolved"] for row in results if row["resolved"] is not None]
                (args.output / "results.json").write_text(
                    json.dumps(
                        {
                            "session": attributes["session_id"],
                            "resolved": sum(resolved),
                            "scored": len(resolved),
                            "results": results,
                        },
                        indent=2,
                    )
                )
    finally:
        if client:
            client.flush()
    if any(
        row.get("infrastructure_error")
        or not (row.get("cleanup") or {}).get("verified_absent")
        or (row.get("grading_cleanup") and not row["grading_cleanup"]["verified_absent"])
        for row in results
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
