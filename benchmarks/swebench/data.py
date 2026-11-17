"""Load SWE-bench Verified tasks at a fixed dataset revision."""

from __future__ import annotations

DATASET = "SWE-bench/SWE-bench_Verified"
REVISION = "78f471bf655a3137b2e8a75af1501690ec009ec3"


def load_instances() -> list[dict]:
    from datasets import load_dataset

    return list(load_dataset(DATASET, split="test", revision=REVISION))


def select_instances(instances, *, ids=None, limit=None) -> list[dict]:
    """Keep dataset order; reject unknown, duplicate, or empty selections."""
    if ids is not None:
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("Instance IDs must be unique and non-empty")
        known = {row["instance_id"] for row in instances}
        missing = [instance_id for instance_id in ids if instance_id not in known]
        if missing:
            raise ValueError("Unknown instance IDs: " + ", ".join(missing))
        instances = [row for row in instances if row["instance_id"] in ids]
    if limit is not None:
        if limit <= 0:
            raise ValueError("--limit must be positive")
        instances = instances[:limit]
    return instances
