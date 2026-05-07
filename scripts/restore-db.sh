#!/bin/bash
# restore-db.sh — push a local database backup to the server
#
# Usage: ./scripts/restore-db.sh <backup-file>
#
# Example: ./scripts/restore-db.sh backups/20260424-130000-pre-demo.db
#
# Requires in src/server/.env:
#   DEPLOY_SERVER      e.g. root@192.168.1.1
#   DEPLOY_REMOTE_DB   e.g. /opt/myapp/src/server/zpr_policy.db
#   DEPLOY_SERVICE     e.g. my-app-service

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
[ -z "${DEPLOY_SERVICE:-}"   ] && MISSING+=("DEPLOY_SERVICE")

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "Error: missing required variables in src/server/.env:"
  for v in "${MISSING[@]}"; do echo "  $v"; done
  echo "See src/server/.env.example for details."
  exit 1
fi

BACKUP="${1:-}"
if [ -z "${BACKUP}" ]; then
  echo "Usage: $0 <backup-file>"
  echo ""
  echo "Available backups:"
  ls -lht "${REPO_ROOT}/backups/"*.db 2>/dev/null | awk '{print "  " $NF}' || echo "  (none)"
  exit 1
fi

if [ ! -f "${BACKUP}" ]; then
  echo "Error: file not found: ${BACKUP}"
  exit 1
fi

SIZE=$(du -h "${BACKUP}" | cut -f1)
echo "→ restoring ${BACKUP} (${SIZE}) to ${DEPLOY_SERVER}..."
read -p "  Stop service, overwrite database, and restart? [y/N] " CONFIRM
if [[ "${CONFIRM}" != "y" && "${CONFIRM}" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

echo "→ stopping service..."
ssh "${DEPLOY_SERVER}" "systemctl stop ${DEPLOY_SERVICE}"

echo "→ uploading database..."
scp -q "${BACKUP}" "${DEPLOY_SERVER}:${DEPLOY_REMOTE_DB}"

echo "→ restarting service..."
ssh "${DEPLOY_SERVER}" "systemctl start ${DEPLOY_SERVICE} && sleep 2 && systemctl is-active ${DEPLOY_SERVICE}"

echo "✓ restore complete"
