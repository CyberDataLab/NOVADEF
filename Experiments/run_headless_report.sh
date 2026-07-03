#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_SCRIPT="${ROOT_DIR}/Experiments/run_headless_report.py"

EXP="${1:-exp1}"
SCENARIO_ID="${2:-}"

if [[ "${EXP}" != "exp1" && "${EXP}" != "exp2" && "${EXP}" != "exp3" ]]; then
  echo "Uso: $0 <exp1|exp2|exp3> [scenario_id]"
  exit 1
fi

CMD=(python3 "${PY_SCRIPT}" --experiment "${EXP}")
if [[ -n "${SCENARIO_ID}" ]]; then
  CMD+=(--scenario-id "${SCENARIO_ID}")
fi

"${CMD[@]}"
