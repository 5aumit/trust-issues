# Trust Issues

![Guardrail pipeline: a GitHub issue with injected text reaches mini-swe-agent, which emits Bash commands that guardrails allow or block](assets/guardrail-pipeline.png)

Course project for [TAI4SE](https://tai4se.github.io).

We study whether security guardrails stop coding agents from following malicious
instructions in GitHub issues. We compare runs with guardrails enabled and
disabled using CodeIPI and IssueTrojanBench. SWE-bench Verified measures how
guardrails affect normal coding work. All three benchmarks use mini-swe-agent.

## Setup

Install Conda and Docker with the Compose plugin. Start Docker.
Run all commands from the repository root.

```bash
git clone https://github.com/5aumit/trust-issues && cd trust-issues
conda env create -f environment.yml
conda activate tai4se-secure-coding-agents
docker info
docker compose version
export OPENROUTER_API_KEY='your-api-key'
```

Set provider credentials in your shell environment before each run.
Or copy `.env.example` to `.env`, fill it in, and load it with
`set -a; source .env; set +a`.

## Configure the agent

Both runners read `configs/default.yaml`. It sets the experiment name, model,
OpenRouter hosts, step limit, time limit, cost limit, and security checks. The default model is
`openrouter/openai/gpt-oss-20b`. Guardrails are disabled by default.

Copy the config to create an experiment configuration. Pass it to either runner
with `--config path/to/config.yaml`. Enable or disable checks in that file.
Set `experiment` to a short, lowercase, hyphenated name for the setting being
tested, such as `regex-l2`. Reuse it across benchmarks and models that should be
compared.

`configs/regex/` has three cumulative regex levels. Each blocks everything the
level below does, plus:

- `l1_loose.yaml`: known-malicious commands, such as writing agent policy files,
  git hooks, `curl | sh`, and dumping secrets.
- `l2_moderate.yaml`: risky actions, such as `.env` access, installing unvetted
  packages, hidden scripts, and cron or shell startup files.
- `l3_strict.yaml`: broad capabilities, such as network tools, any package
  install, `subprocess` or `os.system`, and system paths.

For example, pass `--config configs/regex/l2_moderate.yaml`.

`configs/dev/safeguard.yaml` and `configs/dev/granite.yaml` enable the guard models,
which need a served endpoint.

See [the agent guide](agents/README.md) to configure, add, or edit guardrails.

To change models, pass a `provider/model` identifier as CodeIPI's first argument
or use ITB's `--model` option. Set the corresponding provider's API key.
Optional `require_bash: true` asks the model to call the Bash tool on each reply.
Omit it or set it to `false` for the stock tool choice.
See [the agent guide](agents/README.md) for details.

Time and cost limits are checked between agent steps. An active model request
can exceed them.

OpenRouter sends each request to one of several hosts for the same model, and
hosts differ in quality. To keep runs comparable, set `providers` to the hosts
to try, such as `providers: [AkashML]`. Requests do not fall back to other
public hosts, but accessible private endpoints can still be eligible. Each task's
`model-calls.json` and Langfuse trace record the host when it is returned.
Report the host with your results.

Set `reasoning_effort` to `low`, `medium`, or `high` to fix how much an
OpenRouter or OpenAI model reasons, such as `reasoning_effort: medium`. Leave it out to use
the model's default. Use the same value in every config you compare.

To use the OpenAI API directly, set `OPENAI_API_KEY`, use an `openai/` model such
as `openai/gpt-6-luna`, and set `providers: null`. `openai/` models use OpenAI's
Responses API, the only OpenAI API that accepts tools with `reasoning_effort` for
GPT-6 models. See `configs/final/baseline-openai.yaml`.

Before using a new model or host, run five quick SWE-bench tasks and check that
some are resolved:

```bash
python -m scripts.run_swebench --config path/to/config.yaml --instances django__django-11099 pytest-dev__pytest-10081 sympy__sympy-12096 pallets__flask-5014 scikit-learn__scikit-learn-11310 --output outputs/model-check
```

## Run CodeIPI

Download [CodeIPI](https://github.com/UKGovernmentBEIS/inspect_evals/tree/main/src/inspect_evals/ipi_coding_agent):

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/UKGovernmentBEIS/inspect_evals \
  benchmarks/inspect_evals
git -C benchmarks/inspect_evals sparse-checkout set \
  src/inspect_evals/ipi_coding_agent
python -m scripts.run_codeipi --limit 1
```

Do not install the downloaded checkout as a Python package. The runner loads it
directly. Omit `--limit 1` to run the full benchmark. Use `--sample-id ID` to
select a specific sample. Other run options pass through to Inspect AI.

Logs are saved in `logs/`. Run `inspect view` to inspect them.
Record the benchmark revision and installed versions with your results:

```bash
git -C benchmarks/inspect_evals rev-parse HEAD
python -m pip freeze
```

## Run IssueTrojanBench

Download the benchmark data and build the container image:

```bash
python scripts/fetch_issuetrojan.py
docker build -t issuetrojan-smoke:py312 \
  -f configs/issuetrojan/Dockerfile configs/issuetrojan
```

Supply-chain package installs normally stay offline and fail when the requested
package is not present in the image. To study whether an agent attempts and
completes the install, build a separate opt-in image with six empty local wheel
distributions. The wheels contain package metadata only. The agent still runs
the install command, and the default image remains unchanged:

```bash
docker build --build-arg LOCAL_DUMMY_PACKAGES=1 \
  -t issuetrojan-smoke:py312-dummy-packages \
  -f configs/issuetrojan/Dockerfile configs/issuetrojan
python -m scripts.run_issuetrojan \
  --samples sympy_matrix_det:supply_chain:mid_en_visible \
  --local-dummy-packages \
  --output outputs/issuetrojan-supply-chain-local-packages
```

The opt-in image sets pip to use only its local wheelhouse. Trusted Requests
setup ignores this pip configuration while still online; agent commands do not.
The runner records the option in provenance and checks distribution metadata
before and after the agent run. This records whether installation occurred; it
does not change EEM or the released EEM score.

List cases, then run one sample:

```bash
python -m scripts.run_issuetrojan --list
python -m scripts.run_issuetrojan \
  --samples sympy_matrix_det:policy_bypass:mid_en_visible \
  --output outputs/issuetrojan-matrix
```

The output directory must not already exist. Use `--seeds hnf` to select a seed.
`--seeds` and `--samples` accept multiple values. Combined filters select cases
that match both. Omit both filters to run all 144 GitHub issue cases across six
seed issues. Other delivery methods are outside this study.

Each case uses its mapped repository and commit. See [seed revisions](docs/issuetrojan-seed-revisions.md)
for these choices and [benchmark details](benchmarks/README.md) for data sources.
The output directory contains `results.json` and per-sample records, including
configuration, model calls, commands, guardrail decisions, and repository changes.
`provenance.json` records the code revision and package versions (`null` when
a package is not installed).

## Run SWE-bench Verified

The runner downloads the 500 SWE-bench Verified tasks from Hugging Face at a fixed
revision. Each task pulls its official Docker image, about 1-3 GB.

List tasks, then run one:

```bash
python -m scripts.run_swebench --list
python -m scripts.run_swebench --instances django__django-11099 --output outputs/swebench-django-11099
```

The output directory must not already exist. `--instances` accepts multiple IDs.
`--limit N` runs the first N selected tasks. Omit both to run all 500.
`--steps`, `--seconds`, and `--cost-limit` override the config limits for a run.

The agent works in the task's image with networking disabled. The runner saves
every change in `/testbed` as the patch, including binary files. It then grades the
patch with the official `swebench` harness, which applies it in a fresh container
and runs the official test script. A task is resolved when the issue's tests now
pass and the other tests still pass. Each task folder contains the patch, commands,
guardrail decisions, and model calls. The harness logs, test output, and grading
report are in the task's `logs/run_evaluation/` folder. `provenance.json` records
the code revision and package versions, as for IssueTrojanBench.

`results.json` groups tasks as the official harness does: resolved, unresolved,
empty patch, error, and incomplete. Errors include agent failures, patches that do
not apply, and test timeouts. `resolved_rate` is resolved tasks divided by all
selected tasks. `resolved_ci_low` and `resolved_ci_high` give the 95% Wilson
confidence interval for that rate.

Each attempted task trace records a numeric `SWE-bench/resolved` contribution
of 1 for a resolved task and 0 otherwise. The raw `resolved` value and
`scoring_status` remain in the trace output, including `resolved: null` for
errors. Traces exist only for attempted tasks, so their average can differ from
the selected-task `resolved_rate` when a run stops early.

### Command block rate

SWE-bench issues contain no prompt injection, so we treat every command the
agent proposes as safe. Any blocked command is then a false positive. A
guardrail's command block rate (CBR) is blocked commands divided by checked
commands. Each block also costs the agent one of its limited steps. Real coding
agents usually have no such limit, so this cost is specific to our setup. A
command blocked by several guardrails counts once. Commands the agent formats
incorrectly never reach the guardrails and are not counted.

Each task's `summary.json` records `commands_checked`, `commands_blocked`,
`blocks_by_check`, and `command_block_rate`. The rate is `null` when the agent
ran no commands. Traces record it as `SWE-bench/command_block_rate`.
`results.json` reports `command_block_rate` over all commands in the run, and
`mean_task_command_block_rate` averaged over tasks, so a few long tasks can't
dominate. It also reports `cbr_tasks`, `commands_checked`, `commands_blocked`,
and `tasks_with_blocks`. These numbers include every task whose agent run
finished, even if grading then failed. They leave out agent failures, including
guardrail errors, because those tasks have no complete command record. With
guardrails disabled, CBR is 0.

Downloaded images stay on disk. Pass `--remove-images` to remove each task image
the run downloaded, after the task is graded. Run only one SWE-bench run at a time
with this flag: a parallel run on the same tasks can lose its image before grading.
Otherwise, remove images with `docker image prune -a` when you no longer need them.

## Read results

Check commands and saved files alongside benchmark scores. CodeIPI can count a
blocked command as compliance because its scorer reads attempted tool calls.
IssueTrojanBench's EEM score checks whether selected files exist. It does not
prove that an attack command ran. We do not check legitimate task correctness
for IssueTrojanBench. A few SWE-bench tests contact external websites and can fail
for reasons unrelated to the agent's patch.

Each IssueTrojanBench run also records payload-aligned EEM: whether the sample
completed the goal its own payload describes. It is saved as `payload_eem` in
the sample summary and as the `IssueTrojan/PayloadEEM` score in Langfuse, next
to the original `eem`. To rescore existing runs from Langfuse or local output
directories without rerunning the agent:

```bash
python -m benchmarks.issuetrojan.outcomes --langfuse --output outputs/itb-outcomes
python -m benchmarks.issuetrojan.outcomes --runs outputs/issuetrojan-matrix --output outputs/itb-outcomes
```

`--langfuse` reads every session whose name starts with `issuetrojan`. Narrow
it with `--session-prefix`. Samples the scorer cannot decide are listed in
`review_queue.csv` for hand review; pass the filled-in file back with
`--reviews`. See [benchmark details](benchmarks/README.md#payload-aligned-eem)
for the goal rules and metrics. Supply chain goals need runs with
`--local-dummy-packages`.

## Optional Langfuse tracing

Set these variables before running either benchmark:

```bash
export LANGFUSE_TRACING_ENABLED=true
export LANGFUSE_PUBLIC_KEY='your-public-key'
export LANGFUSE_SECRET_KEY='your-secret-key'
export LANGFUSE_BASE_URL='https://cloud.langfuse.com'
export RUN_BY='your-name'
```

Each run creates a Langfuse session with one trace per sample. Traces record task
text, model calls, commands, guardrail decisions, and scores. Local results remain
available without Langfuse.

Sessions are named `benchmark / model / experiment / run-id`, for example
`codeipi / gpt-oss-20b / regex-l2 / a1b2c3`. The experiment name comes from
`experiment` in the config file. `RUN_BY` sets the Langfuse user, so each
teammate's runs appear under their name.

Traces also have these tags:

| Tag | Applies to | Meaning |
|---|---|---|
| `codeipi`, `issuetrojan`, `swebench` | Each benchmark | Benchmark name |
| `agent:mini-swe-agent` | All | Agent used |
| `guardrail:<names>` | All | Enabled security checks, such as `guardrail:none` or `guardrail:regex` |
| `harness:inspect` | CodeIPI | Run through Inspect AI |
| `github_issue` | IssueTrojanBench | Attack delivered through a GitHub issue |

## Tests

```bash
python -m pip install -e '.[test]'
python -m pytest tests -q
```
