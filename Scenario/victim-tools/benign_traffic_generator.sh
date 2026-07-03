#!/bin/sh

set -eu

TARGET_HOST="${1:-atacante}"
MIN_SLEEP="${MIN_SLEEP:-0.03}"
MAX_SLEEP="${MAX_SLEEP:-0.12}"
ICMP_MIN_COUNT="${ICMP_MIN_COUNT:-2}"
ICMP_MAX_COUNT="${ICMP_MAX_COUNT:-5}"
TCP_MIN_PORT="${TCP_MIN_PORT:-80}"
TCP_MAX_PORT="${TCP_MAX_PORT:-443}"
TCP_PROBE_RATIO="${TCP_PROBE_RATIO:-2}"

rand_float() {
  awk -v min="${1}" -v max="${2}" 'BEGIN { srand(); printf "%.3f\n", (min + (rand() * (max - min))) }'
}

rand_int() {
  awk -v min="${1}" -v max="${2}" 'BEGIN { srand(); printf "%d\n", int(min + (rand() * (max - min + 1))) }'
}

trap 'exit 0' INT TERM

echo "[victim-benign] Starting benign traffic generator toward ${TARGET_HOST}" >&2
while :; do
  icmp_count="$(rand_int "${ICMP_MIN_COUNT}" "${ICMP_MAX_COUNT}")"
  ping -c "${icmp_count}" -W 1 "${TARGET_HOST}" >/dev/null 2>&1 || true

  probe_selector="$(rand_int 1 "${TCP_PROBE_RATIO}")"
  if [ "${probe_selector}" -eq 1 ] && command -v nc >/dev/null 2>&1; then
    probe_port="$(rand_int "${TCP_MIN_PORT}" "${TCP_MAX_PORT}")"
    nc -z -w 1 "${TARGET_HOST}" "${probe_port}" >/dev/null 2>&1 || true
  fi

  sleep "$(rand_float "${MIN_SLEEP}" "${MAX_SLEEP}")"
done
