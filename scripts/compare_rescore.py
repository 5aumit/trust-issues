"""Compare two IssueTrojan outcome directories from the same runs.

Usage:
  python scripts/compare_rescore.py outputs/scorer-v4 outputs/scorer-v5
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
import sys


STATUSES = ("yes", "no", "unknown")
CONFIG_FIELDS = ("model", "experiment", "guardrails", "local_dummy_packages")


def load_samples(directory):
    """Read samples.csv and return rows keyed by configuration and sample."""
    path = Path(directory) / "samples.csv"
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    samples = {}
    for row in rows:
        key = (tuple(row.get(field, "") for field in CONFIG_FIELDS), row["sample"])
        if key in samples:
            print(
                f"Warning: {path}: duplicate sample {row['sample']} ({' / '.join(key[0])}) in sessions "
                f"{samples[key].get('session', '')}, {row.get('session', '')}; keeping the later row",
                file=sys.stderr,
            )
        samples[key] = row
    return samples


def counts(rows):
    """Count yes, no, and unknown results by configuration and attack."""
    result = defaultdict(Counter)
    for row in rows.values():
        result[(tuple(row.get(field, "") for field in CONFIG_FIELDS), row["attack"])][row["payload_eem_status"]] += 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("old", type=Path, help="Outcome directory from the earlier scorer")
    parser.add_argument("new", type=Path, help="Outcome directory from the newer scorer")
    args = parser.parse_args()

    old, new = load_samples(args.old), load_samples(args.new)
    old_counts, new_counts = counts(old), counts(new)
    keys = sorted(set(old_counts) | set(new_counts), key=lambda item: (*item[0], item[1]))
    print("config\tattack\told yes/no/unknown\tnew yes/no/unknown")
    for config_attack in keys:
        config, attack = config_attack
        before, after = old_counts[config_attack], new_counts[config_attack]
        label = " / ".join(config)
        print(
            f"{label}\t{attack}\t"
            f"{before['yes']}/{before['no']}/{before['unknown']}\t"
            f"{after['yes']}/{after['no']}/{after['unknown']}"
        )

    flips = []
    for key in sorted(set(old) & set(new)):
        before, after = old[key]["payload_eem_status"], new[key]["payload_eem_status"]
        if {before, after} == {"yes", "no"}:
            flips.append((key, before, after))
    if flips:
        print("\nyes/no flips:")
        for (config, sample), before, after in flips:
            print(f"{sample}: {before} -> {after} ({' / '.join(config)})")
    else:
        print("\nNo yes/no flips.")

    for label, rows in (("only in old", set(old) - set(new)), ("only in new", set(new) - set(old))):
        if rows:
            print(f"\nSamples {label}:")
            for config, sample in sorted(rows):
                print(f"{sample} ({' / '.join(config)})")


if __name__ == "__main__":
    main()
