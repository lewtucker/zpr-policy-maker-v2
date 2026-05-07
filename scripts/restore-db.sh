#!/bin/bash
# restore-db.sh — push a local database backup to the server
#
# Usage: ./scripts/restore-db.sh <backup-file>
#
# Example: ./scripts/restore-db.sh backups/20260424-130000-pre-demo.db

set -euo pipefail

SERVER="root@<your-server-ip>"
REMOTE_DB="/opt/zpr-policy-maker-v2/src/server/zpr_policy.db"
SERVICE="zpr-policy-maker-v2"

BACKUP="${1:-}"
if [ -z "${BACKUP}" ]; then
  echo "Usage: $0 <backup-file>"
  echo ""
  echo "Available backups:"
  ls -lht "$(dirname "$0")/../backups/"*.db 2>/dev/null | awk '{print "  " $NF}' || echo "  (none)"
  exit 1
fi

if [ ! -f "${BACKUP}" ]; then
  echo "Error: file not found: ${BACKUP}"
  exit 1
fi

SIZE=$(du -h "${BACKUP}" | cut -f1)
echo "→ restoring ${BACKUP} (${SIZE}) to ${SERVER}..."
read -p "  Stop service, overwrite database, and restart? [y/N] " CONFIRM
if [[ "${CONFIRM}" != "y" && "${CONFIRM}" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

echo "→ stopping service..."
ssh "${SERVER}" "systemctl stop ${SERVICE}"

echo "→ uploading database..."
scp -q "${BACKUP}" "${SERVER}:${REMOTE_DB}"

echo "→ restarting service..."
ssh "${SERVER}" "systemctl start ${SERVICE} && sleep 2 && systemctl is-active ${SERVICE}"

echo "✓ restore complete"
