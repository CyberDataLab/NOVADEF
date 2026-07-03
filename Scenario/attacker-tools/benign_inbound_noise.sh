#!/bin/bash
# Ruido benigno diferenciable del ataque de password spraying.
# Genera tráfico HTTP/ICMP de bajo volumen (20-60 pps) desde 4 IPs distintas
# para simular actividad legítima de red. No usa hping3 ni SSH deliberado
# porque esos perfiles son idénticos al ataque — el detector de anomalías
# necesita un baseline visualmente y estadísticamente separado del ataque.

set -euo pipefail

VICTIM_HOST="${1:-scenario_victim}"
RUN_ID="${2:-default}"
LOG_DIR="${NOVADEF_LOG_DIR:-/var/novadef/logs}"
STOP_SIGNAL_FILE="${LOG_DIR}/stop_benign_noise.signal"
# Intervalo entre rondas — 0.8s da ~25-50 pps agregados entre 4 IPs
SLEEP_SECONDS="${SLEEP_SECONDS:-0.8}"
SOURCE_IP_BASE="${SOURCE_IP_BASE:-150}"
SOURCE_IP_COUNT="${SOURCE_IP_COUNT:-4}"
# Paquetes ICMP por fuente por ronda (1 ping = 1 pkt enviado + 1 recibido)
PING_COUNT="${PING_COUNT:-2}"
# Peticiones HTTP curl por ronda (cada curl ~2-4 paquetes TCP)
HTTP_REQUESTS="${HTTP_REQUESTS:-1}"
# Puerto HTTP de la víctima (puede estar cerrado — genera RST, tráfico real igualmente)
HTTP_PORT="${HTTP_PORT:-80}"

mkdir -p "${LOG_DIR}"
rm -f "${STOP_SIGNAL_FILE}"

resolved_victim_ip="$(getent ahostsv4 "${VICTIM_HOST}" | awk 'NR==1 {print $1}')"
if [ -n "${resolved_victim_ip}" ]; then
  VICTIM_TARGET="${resolved_victim_ip}"
else
  VICTIM_TARGET="${VICTIM_HOST}"
fi

iface="$(ip route get "${VICTIM_TARGET}" | awk '/dev/ {for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
if [ -z "${iface}" ]; then
  echo "No se pudo determinar la interfaz hacia ${VICTIM_TARGET}" >&2
  exit 1
fi

SOURCE_IPS=()
for octet in $(seq "${SOURCE_IP_BASE}" $((SOURCE_IP_BASE + SOURCE_IP_COUNT - 1))); do
  SOURCE_IPS+=("172.18.0.${octet}")
done

# Añadir las IPs de origen a la interfaz si no existen ya
for src_ip in "${SOURCE_IPS[@]}"; do
  if ! ip addr show dev "${iface}" | grep -q "${src_ip}"; then
    ip addr add "${src_ip}/16" dev "${iface}" 2>/dev/null || true
  fi
done

trap 'exit 0' INT TERM

echo "[attacker-benign] Starting benign inbound noise for ${RUN_ID} toward ${VICTIM_TARGET} (ICMP+HTTP only, ~30-60 pps)" >&2

while [ ! -f "${STOP_SIGNAL_FILE}" ]; do
  for src_ip in "${SOURCE_IPS[@]}"; do
    [ -f "${STOP_SIGNAL_FILE}" ] && break 2

    # ICMP echo — tráfico legítimo de monitorización/heartbeat
    ping -I "${src_ip}" -c "${PING_COUNT}" -W 1 -q "${VICTIM_TARGET}" >/dev/null 2>&1 || true

    # HTTP GET ligero — simula health-check / scraping de métricas
    # -m 1: timeout 1s, -s: silencioso. Genera SYN+ACK+GET+RST (~4 pkts) aunque el puerto esté cerrado
    if [ "${HTTP_REQUESTS}" -gt 0 ]; then
      curl -s -m 1 --interface "${src_ip}" \
        "http://${VICTIM_TARGET}:${HTTP_PORT}/" >/dev/null 2>&1 || true
    fi
  done
  sleep "${SLEEP_SECONDS}"
done

echo "[attacker-benign] Benign inbound noise stopped for ${RUN_ID}" >&2
