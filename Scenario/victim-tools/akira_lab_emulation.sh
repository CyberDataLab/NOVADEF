#!/bin/bash

set -euo pipefail

LAB_DIR="${LAB_DIR:-/tmp/novadef_ransomware_lab}"
BACKUP_DIR="${LAB_DIR}/.backups"
LOG_DIR="${LAB_DIR}/.logs"
EVENT_LOG="${LOG_DIR}/emulation_events.log"
STOP_SIGNAL="${STOP_SIGNAL:-/tmp/novadef_exp2_stop.signal}"
ENCRYPT_DIR="${LAB_DIR}/encrypted"

mkdir -p "${LAB_DIR}" "${BACKUP_DIR}" "${LOG_DIR}" "${LAB_DIR}/.canaries"
find "${LAB_DIR}" -mindepth 1 -maxdepth 1 ! -name '.backups' ! -name '.logs' -exec rm -rf {} +

FILES=(
  "document.docx"
  "spreadsheet.xlsx"
  "database.db"
  "backup.sql"
  "photo.jpg"
  "config.json"
  "secrets.txt"
  ".canaries/admin_credentials.txt"
  ".canaries/finance_payroll.txt"
)

for relpath in "${FILES[@]}"; do
  mkdir -p "${LAB_DIR}/$(dirname "${relpath}")"
  for _ in $(seq 1 64); do
    echo "NOVADEF lab content for ${relpath}"
  done > "${LAB_DIR}/${relpath}"
done

rm -rf "${BACKUP_DIR:?}/"*
for item in "${LAB_DIR}"/* "${LAB_DIR}"/.[!.]* "${LAB_DIR}"/..?*; do
  [ -e "${item}" ] || continue
  base="$(basename "${item}")"
  if [ "${base}" = ".backups" ] || [ "${base}" = ".logs" ]; then
    continue
  fi
  cp -R "${item}" "${BACKUP_DIR}/"
done

{
  echo "enumeration:$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  find "${LAB_DIR}" -type f ! -path "${BACKUP_DIR}/*" ! -path "${LOG_DIR}/*"
} >> "${EVENT_LOG}"

for file in "${LAB_DIR}"/* "${LAB_DIR}"/.canaries/*; do
  [ -f "${file}" ] || continue
  size="$(wc -c < "${file}")"
  head -c "${size}" /dev/urandom > "${file}.akira"
  rm -f "${file}"
  echo "encrypted:${file} -> ${file}.akira" >> "${EVENT_LOG}"
done

cat > "${LAB_DIR}/!!_READ_ME_!!.txt" <<'EOF'
Your files have been encrypted in the NOVADEF lab emulation.
This is a safe incident-response exercise. No real ransomware was executed.
EOF

{
  echo "recovery_inhibition:[SIMULATED] vssadmin.exe delete shadows /all /quiet"
  echo "recovery_inhibition:[SIMULATED] bcdedit /set {default} recoveryenabled No"
  echo "service_stop:[SIMULATED] sc stop MSSQLSERVER"
  echo "service_stop:[SIMULATED] sc stop MongoDB"
} >> "${EVENT_LOG}"

echo "Akira lab emulation (Falco trigger) completada en ${LAB_DIR}" >> "${EVENT_LOG}"
echo "[akira] Deteccion Falco activada — iniciando bucle de cifrado continuo"
mkdir -p "${ENCRYPT_DIR}"

# Parallel encryption workers: use all available CPUs so the spike is visible.
# Each worker pipes /dev/urandom directly through AES-256 (no intermediate file)
# and writes the encrypted output to the Falco-monitored ENCRYPT_DIR — this
# generates continuous Falco file-activity events AND saturates the CPU.
N_WORKERS=$(nproc 2>/dev/null || echo 4)
if [ "${N_WORKERS}" -gt 8 ]; then N_WORKERS=8; fi

_worker() {
  local wid="${1}" n=0 out=""
  while [ ! -f "${STOP_SIGNAL}" ]; do
    n=$((n + 1))
    out="${ENCRYPT_DIR}/enc_${wid}_${n}.akira"
    dd if=/dev/urandom bs=1M count=20 2>/dev/null | \
      openssl enc -aes-256-cbc -out "${out}" -k "akira-novadef-lab-key-2026" -pbkdf2 2>/dev/null \
      || { rm -f "${out}" 2>/dev/null; break; }
    rm -f "${out}"
  done
}

for w in $(seq 1 "${N_WORKERS}"); do
  _worker "${w}" &
done
wait || true

rm -rf "${ENCRYPT_DIR}"
echo "[akira] Bucle detenido — contramedida aplicada o señal de parada recibida"
