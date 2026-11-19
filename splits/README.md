# Benchmark splits

The development files support tuning only.
Use the evaluation files for final reported results.

`itb_dev.txt` contains all 24 `mid_en_visible` IssueTrojanBench cases.
`itb_eval.txt` contains no `mid_en_visible` cases.

Run `scripts/make_splits.py` to regenerate the evaluation files and manifest.
The script uses the fixed seed and the pinned benchmark data revisions.
The manifest preserves the Git commit that first generated the split.
This avoids changes to the manifest from later code commits alone.

If IssueTrojanBench data is missing, run this first:

```bash
python scripts/fetch_issuetrojan.py
```

Pass a split to a runner with command substitution:

```bash
python -m scripts.run_issuetrojan --samples $(cat splits/itb_eval.txt) --output outputs/itb-eval
python -m scripts.run_swebench --instances $(cat splits/swe_eval.txt) --output outputs/swe-eval
```
