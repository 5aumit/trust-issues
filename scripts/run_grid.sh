#!/usr/bin/env bash
set -euo pipefail

execute=false
args=()
for arg in "$@"; do
  if [[ "$arg" == "--execute" ]]; then
    execute=true
  else
    args+=("$arg")
  fi
done

if [[ ${#args[@]} -lt 1 || ${#args[@]} -gt 2 ]]; then
  echo "usage: $0 [--execute] dev-jev | final <config>" >&2
  exit 2
fi

run_command() {
  local command=$1
  if "$execute"; then
    eval "$command"
  else
    printf '%s\n' "$command"
  fi
}

case "${args[0]}" in
  dev-jev)
    if [[ ${#args[@]} -ne 1 ]]; then
      echo "usage: $0 [--execute] dev-jev" >&2
      exit 2
    fi
    for config in configs/dev/jev-r2-p050.yaml configs/dev/jev-r2-p075.yaml \
      configs/dev/jev-r3-p050.yaml configs/dev/jev-r3-p075.yaml; do
      name=${config##*/}
      name=${name%.yaml}
      run_command "python -m scripts.run_issuetrojan --config $config --local-dummy-packages --samples \$(cat splits/itb_dev.txt) --output outputs/grid/issuetrojan/$name/itb_dev"
      run_command "python -m scripts.run_swebench --config $config --instances \$(cat splits/swe_dev.txt) --output outputs/grid/swebench/$name/swe_dev"
    done
    ;;
  final)
    if [[ ${#args[@]} -ne 2 ]]; then
      echo "usage: $0 [--execute] final <config>" >&2
      exit 2
    fi
    config=${args[1]}
    if [[ "$config" != configs/final/* ]]; then
      config="configs/final/$config"
    fi
    if [[ "$config" != *.yaml ]]; then
      config="$config.yaml"
    fi
    if [[ ! -f "$config" ]]; then
      echo "config not found: $config" >&2
      exit 2
    fi
    name=${config##*/}
    name=${name%.yaml}
    run_command "python -m scripts.run_issuetrojan --config $config --local-dummy-packages --samples \$(cat splits/itb_eval.txt) --output outputs/grid/issuetrojan/$name/itb_eval"
    run_command "python -m scripts.run_swebench --config $config --instances \$(cat splits/swe_eval.txt) --output outputs/grid/swebench/$name/swe_eval"
    ;;
  *)
    echo "unknown mode: ${args[0]}" >&2
    exit 2
    ;;
esac
