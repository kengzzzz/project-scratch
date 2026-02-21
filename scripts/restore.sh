#!/bin/bash
set -euo pipefail

DATA_DIR="/bitwarden/data"
RESTORE_WORKDIR="/tmp/vaultwarden_restore"

if [[ $# -eq 0 ]]; then
    echo "[ERROR] Usage: $0 <path-to-backup.7z>"
    exit 1
fi

ARCHIVE_PATH="$1"

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
    echo "[ERROR] Archive not found: ${ARCHIVE_PATH}"
    exit 1
fi

echo "[WARN] The Vaultwarden main container MUST be STOPPED before restoring."
read -p "Proceed with restore? (y/N): " confirm
if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
    echo "[INFO] Restore cancelled."
    exit 0
fi

echo "[INFO] Starting restore process..."

mkdir -p "${RESTORE_WORKDIR}"
trap 'rm -rf "${RESTORE_WORKDIR}"' EXIT

echo "[INFO] Extracting archive..."
if [[ "${ZIP_TYPE}" == "7z" ]]; then
    7zz x -p"${ZIP_PASSWORD}" -y -o"${RESTORE_WORKDIR}" "${ARCHIVE_PATH}" > /dev/null
else
    echo "[ERROR] Invalid ZIP_TYPE configuration."
    exit 1
fi

echo "[INFO] Restoring database..."
DB_FILE=$(find "${RESTORE_WORKDIR}" -maxdepth 1 -name "db.*.sqlite3" -print -quit)
if [[ -n "${DB_FILE}" ]]; then
    cp -f "${DB_FILE}" "${DATA_DIR}/db.sqlite3"
else
    echo "[WARN] db.sqlite3 not found in archive."
fi

echo "[INFO] Restoring config..."
CONFIG_FILE=$(find "${RESTORE_WORKDIR}" -maxdepth 1 -name "config.*.json" -print -quit)
if [[ -n "${CONFIG_FILE}" ]]; then
    cp -f "${CONFIG_FILE}" "${DATA_DIR}/config.json"
fi

echo "[INFO] Restoring RSA keys..."
find "${RESTORE_WORKDIR}" -maxdepth 1 -name "rsa_key*" -exec cp -a {} "${DATA_DIR}/" \;

echo "[INFO] Restoring directories..."
for dir in attachments sends; do
    if [[ -d "${RESTORE_WORKDIR}/${dir}" ]]; then
        rm -rf "${DATA_DIR}/${dir}"
        cp -a "${RESTORE_WORKDIR}/${dir}" "${DATA_DIR}/"
    fi
done

echo "[INFO] Restore completed successfully."