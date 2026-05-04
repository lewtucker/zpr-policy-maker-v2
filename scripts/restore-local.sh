#!/bin/bash
# restore-local.sh — restore a local dev database backup
#
# Usage: ./scripts/restore-local.sh <backup-file>
#
# Example: ./scripts/restore-local.sh backups/20260504-120000-pre-setup-test.db
#
# The running dev server must be stopped first (Ctrl+C in its terminal),
# or pass --force to skip the check and let uvicorn reload after the copy.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${REPO_ROOT}/src/server/zpr_policy.db"

BACKUP="${1:-}"
if [ -z "${BACKUP}" ]; then
  echo "Usage: $0 <backup-file>"
  echo ""
  echo "Available backups:"
  ls -1t "${REPO_ROOT}/backups/"*.db 2>/dev/null | while read f; do
    SIZE=$(du -h "$f" | cut -f1)
    echo "  $f  (${SIZE})"
  done || echo "  (none)"
  exit 1
fi

if [ ! -f "${BACKUP}" ]; then
  # Try relative to repo root too
  if [ -f "${REPO_ROOT}/${BACKUP}" ]; then
    BACKUP="${REPO_ROOT}/${BACKUP}"
  else
    echo "Error: file not found: ${BACKUP}"
    exit 1
  fi
fi

SIZE=$(du -h "${BACKUP}" | cut -f1)
echo "Restore ${BACKUP} (${SIZE}) → ${DB}"
read -p "Overwrite local database? [y/N] " CONFIRM
if [[ "${CONFIRM}" != "y" && "${CONFIRM}" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

cp "${BACKUP}" "${DB}"
echo "✓ restored — restart the dev server to pick up the change"
