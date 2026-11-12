# Benchmarks

This directory holds downloaded benchmark data and our IssueTrojanBench and
SWE-bench adapters.
See the [project README](../README.md) for setup, run commands, and scoring limits.

| Path | Contents |
|---|---|
| `inspect_evals/` | Downloaded CodeIPI checkout. Git ignores this directory. |
| `issuetrojan-data/issuetrojanbench/` | Downloaded IssueTrojanBench release. Git ignores this directory. |
| `issuetrojan/` | Our IssueTrojanBench data loader and container runner. |
| `swebench/` | Our SWE-bench Verified data loader, container runner, and grading step. |

## CodeIPI

CodeIPI comes from [inspect_evals](https://github.com/UKGovernmentBEIS/inspect_evals/tree/main/src/inspect_evals/ipi_coding_agent).
Keep its entire `src/inspect_evals/ipi_coding_agent/` directory, including the
dataset and Docker files.

Do not install the downloaded checkout as a Python package. Its registry imports
benchmarks absent from the partial checkout. Our runner loads the task directly.
Set `CODEIPI_SOURCE` to the checkout's `src/` directory if you store it elsewhere.
Record the checkout commit with your experiment results.

## IssueTrojanBench

`scripts/fetch_issuetrojan.py` downloads the Zenodo release and verifies its
archive checksum. The adapter also verifies the input files it uses.
`SOURCE_COMMIT` identifies the reference code, not the downloaded data release.

We use GitHub issue delivery across all six seeds, with four attacks and six
variants per attack. This gives 144 cases. Case names use `seed:attack:perturbation`.
The runner reads issue text from the release. It does not publish GitHub issues.

Each seed uses the repository and commit in the [seed mapping](../docs/issuetrojan-seed-revisions.md).
The runner creates a container for each case and removes it after the run.

## SWE-bench Verified

`benchmarks/swebench/data.py` loads [SWE-bench Verified](https://huggingface.co/datasets/SWE-bench/SWE-bench_Verified)
at a fixed revision. Each task includes its Docker image and official test script.
The runner grades test logs with the pinned `swebench` package. Grading runs in
Python's UTF-8 mode because `swebench` opens logs with the system encoding.
