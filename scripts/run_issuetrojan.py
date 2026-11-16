"""Run released IssueTrojan github_issue cases with stock mini-swe-agent."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import uuid

from configs.issuetrojan.local_dummy_packages import PACKAGES
from benchmarks.issuetrojan.data import (
    ARCHIVE_SHA256,
    DATA_HASHES,
    SEEDS,
    SOURCE_COMMIT,
    ZENODO_RECORD,
    all_cases,
    select_cases,
    verify_data,
)

DEFAULT_DATA = Path("benchmarks/issuetrojan-data/issuetrojanbench")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--config", type=Path, default=Path("configs/default.yaml"))
    parser.add_argument("--model")
    parser.add_argument("--seeds", nargs="+", help="Seed names; default: all six")
    parser.add_argument(
        "--samples",
        nargs="+",
        help="Exact seed:attack:perturbation identities; default: all cases",
    )
    parser.add_argument(
        "--list", action="store_true", help="List selected identities without running"
    )
    parser.add_argument("--image")
    parser.add_argument(
        "--local-dummy-packages",
        action="store_true",
        help="Use the opt-in image with harmless local supply-chain distributions",
    )
    parser.add_argument("--steps", type=int)
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--cost-limit", type=float)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.list and args.output is None:
        parser.error("--output is required unless --list is used")
    args.image = args.image or (
        "issuetrojan-smoke:py312-dummy-packages"
        if args.local_dummy_packages
        else "issuetrojan-smoke:py312"
    )
    return args


def configure(*, path, model=None, steps=None, seconds=None, cost_limit=None):
    from agents.swe import load_config

    config = load_config(path)
    config["model"] = model or config["model"]
    if not config["model"]:
        raise ValueError("Set model in --config or pass --model")
    for name, value in (
        ("steps", steps),
        ("seconds", seconds),
        ("cost_usd", cost_limit),
    ):
        if value is not None:
            if value <= 0:
                raise ValueError("Steps, seconds, and cost limit must be positive")
            config["limits"][name] = value
    return config


def configure_tracing():
    from agents.tracing import tracing_enabled, validate_langfuse_config

    validate_langfuse_config()
    if not tracing_enabled():
        return None
    from langfuse import get_client

    client = get_client()
    if not client.auth_check():
        raise RuntimeError("Langfuse authentication failed")
    return client


def main():
    args = parse_args()
    try:
        verify_data(args.data)
        cases = select_cases(
            all_cases(args.data), seeds=args.seeds, samples=args.samples
        )
    except (ValueError, FileNotFoundError) as exc:
        raise SystemExit(str(exc)) from None
    if args.list:
        print("\n".join(case.sample for case in cases))
        return
    args.output.mkdir(parents=True, exist_ok=False)
    os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = str((args.output / "mini-config").resolve())
    os.environ["MSWEA_SILENT_STARTUP"] = "1"
    from benchmarks.issuetrojan.runner import run_case

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
                "zenodo_record": ZENODO_RECORD,
                "archive_sha256": ARCHIVE_SHA256,
                "reference_source_commit": SOURCE_COMMIT,
                "data_sha256": DATA_HASHES,
                "seeds": {name: asdict(seed) for name, seed in SEEDS.items()},
                "samples": [case.sample for case in cases],
                "local_dummy_packages": {
                    "enabled": args.local_dummy_packages,
                    "distributions": list(PACKAGES.values()) if args.local_dummy_packages else [],
                    "contents": "empty metadata-only wheels" if args.local_dummy_packages else None,
                },
                "image": args.image,
                "revision_policy": "Adapter choices from docs/issuetrojan-seed-revisions.md; release specifies no target commits",
                "adaptations": [
                    "Released github_issue text supplied directly to stock mini task; no issues published",
                    "Stock mini.yaml prompts and shared run_swe",
                    "Docker resource limits; network disconnected after provisioning; no host mounts or forwarded credentials",
                    "Released run_benchmark.py executable file-existence EEM; task correctness deferred",
                ],
            },
            indent=2,
        )
    )
    client = configure_tracing()
    from agents.tracing import guardrail_tag, trace_attributes

    attributes = trace_attributes(
        "issuetrojan",
        config["model"],
        config["experiment"],
        uuid.uuid4().hex[:12],
        ["agent:mini-swe-agent", "github_issue", guardrail_tag(config)],
    )
    session = attributes["session_id"]
    from langfuse import propagate_attributes

    results = []
    try:
        with propagate_attributes(**attributes):
            for case in cases:
                print("Starting", case.sample, flush=True)
                with propagate_attributes(trace_name=case.sample):
                    results.append(
                        run_case(
                            case,
                            model=config["model"],
                            config=config,
                            image=args.image,
                            local_dummy_packages=args.local_dummy_packages,
                            out=args.output,
                            client=client,
                        )
                    )
                (args.output / "results.json").write_text(
                    json.dumps({"session": session, "results": results}, indent=2)
                )
    finally:
        if client:
            client.flush()
    if any(
        row.get("infrastructure_error")
        or row["scoring_status"] != "scored"
        or not row.get("cleanup", {}).get("verified_absent")
        for row in results
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
