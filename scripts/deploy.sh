#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load deploy config from .env
ENV_FILE="$REPO_ROOT/src/server/.env"
if [ -f "$ENV_FILE" ]; then
  export $(grep -E '^DEPLOY_' "$ENV_FILE" | xargs)
fi

SERVER="${DEPLOY_SERVER:-root@72.62.97.102}"
REMOTE_PATH="/opt/zpr-policy-maker/src/server/"
SERVICE="${DEPLOY_SERVICE:-zpr-policy-maker}"

echo "Deploying to $SERVER ..."
rsync -av \
  --exclude='.env' \
  --exclude='zpr_policy.db' \
  --exclude='__pycache__/' \
  --exclude='.pytest_cache/' \
  --exclude='*.pyc' \
  --exclude='.DS_Store' \
  "$REPO_ROOT/src/server/" "$SERVER:$REMOTE_PATH"

echo "Restarting $SERVICE ..."
ssh "$SERVER" "systemctl restart $SERVICE"
echo "Done."
