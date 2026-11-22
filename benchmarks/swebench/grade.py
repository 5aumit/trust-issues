"""Grade one SWE-bench patch with the official swebench harness.

The runner calls this in Python's UTF-8 mode because swebench reads and writes the
patch and test log with the system default encoding. Files the harness writes use
LF line endings so they work in the Linux container when run on Windows. The harness
writes its logs under `logs/run_evaluation/` in the sample folder.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

MODEL_NAME = "mini-swe-agent"
EVAL_TIMEOUT = 1800
ROOT = Path(__file__).resolve().parents[2]
_write_text = Path.write_text


def log_dir(sample_dir: Path, run_id: str, instance_id: str) -> Path:
    """Folder where the official harness writes this sample's logs and report."""
    from swebench.harness.constants import RUN_EVALUATION_LOG_DIR

    return sample_dir / RUN_EVALUATION_LOG_DIR / run_id / MODEL_NAME / instance_id


def grade(sample_dir: Path, run_id: str) -> dict | None:
    """Run the official harness and return its report, or None if it could not grade."""
    sample_dir = sample_dir.resolve()
    result = subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "benchmarks.swebench.grade", str(sample_dir), run_id],
        cwd=sample_dir,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(ROOT), os.environ.get("PYTHONPATH")]))},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode:
        raise RuntimeError("Grading failed: " + result.stderr.strip()[-500:])
    from swebench.harness.constants import LOG_REPORT

    instance_id = json.loads((sample_dir / "instance.json").read_text(encoding="utf-8"))["instance_id"]
    report = log_dir(sample_dir, run_id, instance_id) / LOG_REPORT
    return json.loads(report.read_text(encoding="utf-8"))[instance_id] if report.exists() else None


def write_text_with_lf(path, data, encoding=None, errors=None, newline="\n"):
    return _write_text(path, data, encoding, errors, newline)


def main(sample_dir: Path, run_id: str) -> None:
    # The harness writes eval.sh and patch.diff with Path.write_text, which uses CRLF
    # line endings on Windows and breaks both inside the Linux container.
    Path.write_text = write_text_with_lf
    import docker
    from swebench.harness.run_evaluation import run_instance
    from swebench.harness.utils import make_test_spec

    instance = json.loads((sample_dir / "instance.json").read_text(encoding="utf-8"))
    prediction = {
        "instance_id": instance["instance_id"],
        "model_name_or_path": MODEL_NAME,
        "model_patch": (sample_dir / "patch.diff").read_text(encoding="utf-8"),
    }
    run_instance(make_test_spec(instance), prediction, docker.from_env(), run_id, timeout=EVAL_TIMEOUT)


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2])
