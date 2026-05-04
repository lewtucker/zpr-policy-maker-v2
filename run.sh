#!/bin/bash
pkill -f "uvicorn server:app --port 8083" 2>/dev/null
sleep 1
cd "$(dirname "$0")/src/server"
exec uvicorn server:app --reload --port 8083 --log-level warning
