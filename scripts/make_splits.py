"""Create deterministic development and evaluation sample splits."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import random
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.issuetrojan.data import (
    ARCHIVE_SHA256,
    ZENODO_RECORD,
    all_cases,
    verify_data,
)
from benchmarks.swebench.data import DATASET, REVISION, load_instances


SPLITS = ROOT / "splits"
ITB_DATA = ROOT / "benchmarks/issuetrojan-data/issuetrojanbench"
SEED = 20261118
SWE_EVAL_COUNT = 50


def read_ids(path: Path) -> list[str]:
    """Read a non-empty, duplicate-free list of sample IDs."""
    ids = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    ids = [sample_id for sample_id in ids if sample_id]
    if not ids:
        raise ValueError(f"Split is empty: {path}")
    if len(ids) != len(set(ids)):
        raise ValueError(f"Split has duplicate IDs: {path}")
    return ids


def proportional_quotas(groups: dict[str, list[dict]], count: int) -> dict[str, int]:
    """Allocate count samples with a minimum of one per non-empty group."""
    if count <= 0:
        raise ValueError("Split count must be positive")
    total = sum(len(rows) for rows in groups.values())
    if total < count:
        raise ValueError(f"Only {total} candidates are available for {count} samples")

    floor_quotas = {
        name: len(rows) * count // total
        for name, rows in groups.items()
        if rows
    }
    quotas = {name: max(1, quota) for name, quota in floor_quotas.items()}
    allocated = sum(quotas.values())
    if allocated > count:
        raise ValueError(
            "Minimum one per repo conflicts with proportional allocation: "
            f"{allocated} samples are required for a {count}-sample split"
        )

    remainders = sorted(
        (
            (len(rows) * count % total, name)
            for name, rows in groups.items()
            if rows and floor_quotas[name] >= 1
        ),
        key=lambda item: (-item[0], item[1]),
    )
    leftovers = count - allocated
    if len(remainders) < leftovers:
        raise ValueError("Largest-remainder allocation cannot fill the split")
    for _, name in remainders[:leftovers]:
        quotas[name] += 1
    return quotas


def select_swe_eval(instances: list[dict], dev_ids: list[str]) -> list[dict]:
    """Select a seeded, repository-stratified SWE-bench evaluation split."""
    instance_by_id = {row["instance_id"]: row for row in instances}
    if len(instance_by_id) != len(instances):
        raise ValueError("SWE-bench dataset has duplicate instance IDs")
    missing = sorted(set(dev_ids) - instance_by_id.keys())
    if missing:
        raise ValueError("Unknown SWE development IDs: " + ", ".join(missing))

    groups: dict[str, list[dict]] = defaultdict(list)
    dev_id_set = set(dev_ids)
    for row in instances:
        if row["instance_id"] not in dev_id_set:
            groups[row["repo"]].append(row)

    quotas = proportional_quotas(groups, SWE_EVAL_COUNT)
    rng = random.Random(SEED)
    selected = []
    for repo in sorted(groups):
        candidates = sorted(groups[repo], key=lambda row: row["instance_id"])
        selected.extend(rng.sample(candidates, quotas[repo]))
    return selected


def git_commit() -> str:
    """Keep the commit that first generated this checked-in split."""
    manifest_path = SPLITS / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(manifest.get("git_commit"), str):
            return manifest["git_commit"]
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


def write_ids(path: Path, ids: list[str]) -> None:
    path.write_text("\n".join(sorted(ids)) + "\n", encoding="utf-8")


def make_splits() -> dict:
    """Validate source data and write the checked-in split files."""
    itb_dev_ids = read_ids(SPLITS / "itb_dev.txt")
    swe_dev_ids = read_ids(SPLITS / "swe_dev.txt")

    verify_data(ITB_DATA)
    itb_cases = all_cases(ITB_DATA)
    itb_case_by_id = {case.sample: case for case in itb_cases}
    if len(itb_cases) != 144 or len(itb_case_by_id) != 144:
        raise ValueError("Expected 144 unique IssueTrojanBench cases")
    missing_itb = sorted(set(itb_dev_ids) - itb_case_by_id.keys())
    if missing_itb:
        raise ValueError("Unknown IssueTrojanBench development IDs: " + ", ".join(missing_itb))
    if len(itb_dev_ids) != 24:
        raise ValueError("Expected 24 IssueTrojanBench development IDs")
    itb_eval_ids = sorted(set(itb_case_by_id) - set(itb_dev_ids))
    if len(itb_eval_ids) != 120:
        raise ValueError("Expected 120 IssueTrojanBench evaluation IDs")
    if set(itb_eval_ids) & set(itb_dev_ids):
        raise ValueError("IssueTrojanBench development and evaluation splits overlap")

    swe_instances = load_instances()
    if len(swe_instances) != 500:
        raise ValueError("Expected 500 SWE-bench Verified instances")
    if len(swe_dev_ids) != 10:
        raise ValueError("Expected 10 SWE-bench development IDs")
    swe_eval = select_swe_eval(swe_instances, swe_dev_ids)
    swe_eval_ids = sorted(row["instance_id"] for row in swe_eval)
    if len(swe_eval_ids) != SWE_EVAL_COUNT:
        raise ValueError("Expected 50 SWE-bench evaluation IDs")
    if set(swe_eval_ids) & set(swe_dev_ids):
        raise ValueError("SWE development and evaluation splits overlap")

    manifest = {
        "seed": SEED,
        "issuetrojan": {
            "zenodo_record": ZENODO_RECORD,
            "archive_sha256": ARCHIVE_SHA256,
            "counts": {"all": len(itb_cases), "dev": len(itb_dev_ids), "eval": len(itb_eval_ids)},
            "perturbation_mix": {
                "dev": dict(sorted(Counter(itb_case_by_id[sample_id].perturbation for sample_id in itb_dev_ids).items())),
                "eval": dict(sorted(Counter(itb_case_by_id[sample_id].perturbation for sample_id in itb_eval_ids).items())),
            },
        },
        "swebench": {
            "dataset": DATASET,
            "revision": REVISION,
            "counts": {"all": len(swe_instances), "dev": len(swe_dev_ids), "eval": len(swe_eval_ids)},
            "eval_repo_mix": dict(sorted(Counter(row["repo"] for row in swe_eval).items())),
        },
        "git_commit": git_commit(),
    }
    write_ids(SPLITS / "itb_eval.txt", itb_eval_ids)
    write_ids(SPLITS / "swe_eval.txt", swe_eval_ids)
    (SPLITS / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    make_splits()


if __name__ == "__main__":
    main()
