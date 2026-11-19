from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts/make_splits.py"
SPEC = importlib.util.spec_from_file_location("make_splits", MODULE_PATH)
make_splits = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(make_splits)


def rows(repo: str, count: int) -> list[dict]:
    return [{"repo": repo, "instance_id": f"{repo}-{index}"} for index in range(count)]


def test_proportional_quotas_uses_largest_remainders_and_minimums():
    groups = {"alpha": rows("alpha", 5), "beta": rows("beta", 3), "gamma": rows("gamma", 2)}

    assert make_splits.proportional_quotas(groups, 6) == {
        "alpha": 3,
        "beta": 2,
        "gamma": 1,
    }


def test_proportional_quotas_does_not_round_up_a_minimum_repo():
    groups = {
        "large": rows("large", 81),
        "medium": rows("medium", 10),
        "small": rows("small", 9),
    }

    assert make_splits.proportional_quotas(groups, 11) == {
        "large": 9,
        "medium": 1,
        "small": 1,
    }


def test_proportional_quotas_rejects_minimum_conflict():
    groups = {f"repo-{index}": rows(f"repo-{index}", 100) for index in range(6)}

    with pytest.raises(ValueError, match="Minimum one per repo conflicts"):
        make_splits.proportional_quotas(groups, 5)


def test_select_swe_eval_is_seeded_sorted_and_excludes_development_ids(monkeypatch):
    instances = rows("beta", 8) + rows("alpha", 12)
    dev_ids = ["alpha-0", "beta-0"]
    monkeypatch.setattr(make_splits, "SWE_EVAL_COUNT", 10)

    first = make_splits.select_swe_eval(instances, dev_ids)
    second = make_splits.select_swe_eval(list(reversed(instances)), dev_ids)

    first_ids = sorted(row["instance_id"] for row in first)
    assert first_ids == sorted(row["instance_id"] for row in second)
    assert not set(first_ids) & set(dev_ids)
    assert len(first_ids) == make_splits.SWE_EVAL_COUNT


def test_git_commit_preserves_the_existing_manifest_value(tmp_path, monkeypatch):
    (tmp_path / "manifest.json").write_text('{"git_commit": "base-commit"}\n')
    monkeypatch.setattr(make_splits, "SPLITS", tmp_path)

    assert make_splits.git_commit() == "base-commit"
