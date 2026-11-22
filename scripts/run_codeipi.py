"""Run CodeIPI through Inspect with the shared mini-swe-agent solver."""

import os
import sys
import json
from pathlib import Path
import subprocess

from agents.swe import load_config


def git_provenance():
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], text=True).strip())
    return {"git_commit": commit, "git_dirty": dirty}


def log_dir(args):
    for index, arg in enumerate(args):
        if arg == "--log-dir" and index + 1 < len(args):
            return Path(args[index + 1])
        if arg.startswith("--log-dir="):
            return Path(arg.partition("=")[2])
    return Path("logs")


def main():
    os.chdir(Path(__file__).resolve().parent.parent)
    args = sys.argv[1:]
    config_path = Path("configs/default.yaml")
    if "--config" in args:
        index = args.index("--config")
        try:
            config_path = Path(args[index + 1])
        except IndexError:
            sys.exit("--config needs a YAML path")
        del args[index:index + 2]
    config = load_config(config_path)
    model = args.pop(0) if args and not args[0].startswith("-") else config["model"]
    model = model or os.environ.get("INSPECT_EVAL_MODEL")
    if not model:
        sys.exit("Set model in --config or pass PROVIDER/MODEL")
    source = Path(os.environ.get("CODEIPI_SOURCE", "benchmarks/inspect_evals/src")).resolve()
    task = source / "inspect_evals/ipi_coding_agent/ipi_coding_agent.py"
    if not task.is_file():
        sys.exit("Set CODEIPI_SOURCE or sparse-clone CodeIPI into benchmarks/inspect_evals (see README.md).")
    output_dir = log_dir(args)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "provenance.json").write_text(
        json.dumps({**git_provenance(), "benchmark": "CodeIPI"}, indent=2),
        encoding="utf-8",
    )
    os.environ["PYTHONPATH"] = str(source) + (
        os.pathsep + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else ""
    )

    os.execv(sys.executable, [
        sys.executable, "-m", "inspect_ai", "eval", os.path.relpath(task, Path.cwd()),
        "--solver", "agents/agent.py@coding_agent",
        "--model", model,
        "-S", "config_path=" + str(config_path.resolve()),
        "-S", "model_name=" + model,
        *args,
    ])


if __name__ == "__main__":
    main()
