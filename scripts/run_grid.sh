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
  echo "usage: $0 [--execute] dev-jev | dev-slm | final <config>" >&2
  exit 2
fi

failed=()
run_command() {
  local command=$1
  if "$execute"; then
    eval "$command" || failed+=("$command")
  else
    printf '%s\n' "$command"
  fi
}

case "${args[0]}" in
  dev-jev|dev-slm)
    if [[ ${#args[@]} -ne 1 ]]; then
      echo "usage: $0 [--execute] ${args[0]}" >&2
      exit 2
    fi
    if [[ "${args[0]}" == dev-jev ]]; then
      configs=(configs/dev/jev-zeroshot.yaml)
    else
      configs=(configs/dev/safeguard.yaml configs/dev/granite.yaml)
    fi
    for config in "${configs[@]}"; do
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

if [[ ${#failed[@]} -gt 0 ]]; then
  echo "failed commands:" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
