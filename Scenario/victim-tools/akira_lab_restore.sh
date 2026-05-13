#!/bin/bash

set -euo pipefail

LAB_DIR="${LAB_DIR:-/tmp/novadef_ransomware_lab}"
BACKUP_DIR="${LAB_DIR}/.backups"

if [ ! -d "${BACKUP_DIR}" ]; then
  echo "No existe backup en ${BACKUP_DIR}" >&2
  exit 1
fi

find "${LAB_DIR}" -mindepth 1 -maxdepth 1 ! -name '.backups' ! -name '.logs' -exec rm -rf {} +
cp -R "${BACKUP_DIR}/." "${LAB_DIR}/"
rm -rf "${LAB_DIR}/.backups" "${LAB_DIR}/.logs"
mkdir -p "${BACKUP_DIR}" "${LAB_DIR}/.logs"

echo "Restauración completada desde ${BACKUP_DIR}"
