"""Grade one saved SWE-bench test log with the official swebench grader.

The runner calls this in Python's UTF-8 mode because swebench opens the test log
with the system default encoding.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def grade(sample_dir: Path) -> dict:
    """Run the grader in UTF-8 mode and return its report for this instance."""
    result = subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "benchmarks.swebench.grade", str(sample_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode:
        raise RuntimeError("Grading failed: " + result.stderr.strip()[-500:])
    return json.loads(result.stdout)


def main(sample_dir: Path) -> None:
    from swebench.harness.grading import get_eval_report
    from swebench.harness.utils import make_test_spec

    instance = json.loads((sample_dir / "instance.json").read_text(encoding="utf-8"))
    prediction = {
        "instance_id": instance["instance_id"],
        "model_name_or_path": "mini-swe-agent",
        "model_patch": (sample_dir / "patch.diff").read_text(encoding="utf-8"),
    }
    report = get_eval_report(
        make_test_spec(instance), prediction, str(sample_dir / "test_output.txt"), True
    )
    print(json.dumps(report[instance["instance_id"]]))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
