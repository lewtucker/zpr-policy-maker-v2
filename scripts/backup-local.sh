#!/bin/bash
# backup-local.sh — snapshot the local dev database
#
# Usage: ./scripts/backup-local.sh [label]
#
# Saves to: backups/YYYYMMDD-HHMMSS[-label].db

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${REPO_ROOT}/src/server/zpr_policy.db"
BACKUP_DIR="${REPO_ROOT}/backups"

if [ ! -f "${DB}" ]; then
  echo "Error: database not found at ${DB}"
  exit 1
fi

LABEL="${1:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
FILENAME="${TIMESTAMP}${LABEL:+-$LABEL}.db"

mkdir -p "${BACKUP_DIR}"
cp "${DB}" "${BACKUP_DIR}/${FILENAME}"

SIZE=$(du -h "${BACKUP_DIR}/${FILENAME}" | cut -f1)
echo "✓ saved to backups/${FILENAME} (${SIZE})"
echo ""
echo "To restore: ./scripts/restore-local.sh backups/${FILENAME}"
