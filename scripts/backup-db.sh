#!/bin/bash
# backup-db.sh — pull the live database from the server to a local backup
#
# Usage: ./scripts/backup-db.sh [label]
#
# Saves to: backups/YYYYMMDD-HHMMSS[-label].db
#
# Requires in src/server/.env:
#   DEPLOY_SERVER      e.g. root@192.168.1.1
#   DEPLOY_REMOTE_DB   e.g. /opt/myapp/src/server/zpr_policy.db

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${REPO_ROOT}/src/server/.env"

if [ -f "${ENV_FILE}" ]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

MISSING=()
[ -z "${DEPLOY_SERVER:-}"    ] && MISSING+=("DEPLOY_SERVER")
[ -z "${DEPLOY_REMOTE_DB:-}" ] && MISSING+=("DEPLOY_REMOTE_DB")

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "Error: missing required variables in src/server/.env:"
  for v in "${MISSING[@]}"; do echo "  $v"; done
  echo "See src/server/.env.example for details."
  exit 1
fi

LABEL="${1:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
FILENAME="${TIMESTAMP}${LABEL:+-$LABEL}.db"

BACKUP_DIR="${REPO_ROOT}/backups"
mkdir -p "${BACKUP_DIR}"

echo "→ pulling database from ${DEPLOY_SERVER}..."
scp -q "${DEPLOY_SERVER}:${DEPLOY_REMOTE_DB}" "${BACKUP_DIR}/${FILENAME}"

SIZE=$(du -h "${BACKUP_DIR}/${FILENAME}" | cut -f1)
echo "✓ saved to backups/${FILENAME} (${SIZE})"
echo ""
echo "To restore: ./scripts/restore-db.sh backups/${FILENAME}"
