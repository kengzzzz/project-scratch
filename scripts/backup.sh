#!/bin/bash
set -euo pipefail

DATA_DIR="/bitwarden/data"
RCLONE_CONF="/config/rclone/rclone.conf"
BACKUP_WORKDIR="/tmp/vaultwarden_backup"
TIMESTAMP=$(date +%Y%m%d)
ARCHIVE_NAME="backup.${TIMESTAMP}.${ZIP_TYPE}"
ARCHIVE_PATH="/tmp/${ARCHIVE_NAME}"

echo "[INFO] Starting Vaultwarden backup: ${TIMESTAMP}"

mkdir -p "${BACKUP_WORKDIR}"
trap 'rm -rf "${BACKUP_WORKDIR}" "${ARCHIVE_PATH}"' EXIT

if [[ -f "${DATA_DIR}/db.sqlite3" ]]; then
    sqlite3 "${DATA_DIR}/db.sqlite3" ".backup '${BACKUP_WORKDIR}/db.${TIMESTAMP}.sqlite3'"
else
    echo "[ERROR] db.sqlite3 not found"
    exit 1
fi

if [[ -f "${DATA_DIR}/config.json" ]]; then
    cp -a "${DATA_DIR}/config.json" "${BACKUP_WORKDIR}/config.${TIMESTAMP}.json"
fi

find "${DATA_DIR}" -maxdepth 1 -name "rsa_key*" -exec cp -a {} "${BACKUP_WORKDIR}/" \;

for dir in attachments sends; do
    if [[ -d "${DATA_DIR}/${dir}" ]]; then
        cp -a "${DATA_DIR}/${dir}" "${BACKUP_WORKDIR}/${dir}"
    fi
done

if [[ "${ZIP_TYPE}" == "7z" ]]; then
    7zz a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -p"${ZIP_PASSWORD}" "${ARCHIVE_PATH}" "${BACKUP_WORKDIR}"/* > /dev/null
else
    echo "[ERROR] Invalid ZIP_TYPE"
    exit 1
fi

rclone copy "${ARCHIVE_PATH}" "${RCLONE_REMOTE_NAME}:${RCLONE_REMOTE_DIR}" --config "${RCLONE_CONF}"

rclone delete "${RCLONE_REMOTE_NAME}:${RCLONE_REMOTE_DIR}" \
    --min-age "${BACKUP_KEEP_DAYS}d" \
    --include "*.${ZIP_TYPE}" \
    --config "${RCLONE_CONF}"

echo "[INFO] Backup completed"