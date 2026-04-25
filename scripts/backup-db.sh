#!/bin/bash
# backup-db.sh — pull the live database from the server to a local backup
#
# Usage: ./scripts/backup-db.sh [label]
#
# Saves to: backups/YYYYMMDD-HHMMSS[-label].db

set -euo pipefail

SERVER="root@72.62.97.102"
REMOTE_DB="/opt/zpr-policy-maker/src/server/policy_maker.db"

LABEL="${1:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
FILENAME="${TIMESTAMP}${LABEL:+-$LABEL}.db"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="${REPO_ROOT}/backups"
mkdir -p "${BACKUP_DIR}"

echo "→ pulling database from ${SERVER}..."
scp -q "${SERVER}:${REMOTE_DB}" "${BACKUP_DIR}/${FILENAME}"

SIZE=$(du -h "${BACKUP_DIR}/${FILENAME}" | cut -f1)
echo "✓ saved to backups/${FILENAME} (${SIZE})"
echo ""
echo "To restore: ./scripts/restore-db.sh backups/${FILENAME}"
