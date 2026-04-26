# CLAUDE.md — ZPR Policy Maker v2

## ⚠️ PROJECT STATUS: ON HOLD

This project has been put on hold as of 2026-04-26. Development work was redirected to the original
**ZPR Policy Maker v1** project (`zpr-policy.lewtucker.net`), where the new features and UI
improvements are being applied instead. Do not deploy or continue development here without
re-confirming intent with the user.

---

## ⚠️ DEPLOYMENT SAFETY — READ THIS FIRST AND NEVER VIOLATE

There are **three separate applications** on the production server (72.62.97.102).
Deploying to the wrong one corrupts it. The rules are absolute:

| Application | Domain | Server path | Systemd service | Port |
|-------------|---------|-------------|-----------------|------|
| **THIS APP (v2)** | `zpr-policy2.lewtucker.net` | `/opt/zpr-policy-maker-v2/` | `zpr-policy-maker-v2` | 8082 |
| ZPR Policy Maker v1 | `zpr-policy.lewtucker.net` | `/opt/zpr-policy-maker/` | `zpr-policy-maker` | 8081 |
| OpenClaw Policy Maker | `policy.lewtucker.net` | `/opt/policy-maker/` | `policy-maker` | 8080 |

**NEVER deploy to `zpr-policy.lewtucker.net` or `policy.lewtucker.net`.**
**NEVER write to `/opt/zpr-policy-maker/` or `/opt/policy-maker/`.**
**NEVER restart `zpr-policy-maker` or `policy-maker` services.**

When deploying, always use full absolute paths and confirm the destination before running rsync.

---

## Project Overview

**ZPR Policy Maker v2** is an agent-first redesign of the v1 Policy Maker. The primary
interaction model is conversational: users describe policies in natural language (or ZPL/ZPEL)
and an AI agent translates them into structured ZPL objects and rules. The current
ZPL Classes, Entities, and Rules pages exist as background views rather than the
primary interface.

### Key differences from v1

- **Agent-first**: The AI agent is the primary interface. Users talk to it; it creates
  and manages classes, entities, and rules on their behalf.
- **Swappable parser**: ZPL (RFC-15.5 BNF) and ZPEL (Oracle OCI variant) are supported
  via a pluggable parser interface. The user selects the language at startup/account level.
- **Language agnostic engine**: The ZPL engine (`zpl_engine.py`) is reused as-is;
  the parser layer is what varies.
- **Possible new DB schema**: Designed from scratch to support multi-language policies
  and agent-driven workflows.

### Long-term vision

Unified policy platform supporting ZPL (RFC-15.5), ZPEL (Oracle OCI), and OpenClaw —
kept separate now but architected so they can be brought together later.

---

## Running Locally

```bash
cd src/server
uvicorn server:app --reload --port 8083   # use 8083 locally to avoid v1 conflict
```

Auth requires `APP_PASSWORD` in `src/server/.env`.

---

## File Structure

```
docs/
  zpl_rfc15_5.bnf          BNF grammar for RFC-15.5 ZPL
  RFC_classes.yaml          Canonical ZPL class hierarchy (design reference)
  DemoScripts.md            Demo account conventions

OCI/
  *.yaml                    Oracle ZPEL reference classes and rules

reference/
  database_v1.py            v1 DB schema (read-only reference — do not import)
  server_v1.py              v1 FastAPI app (read-only reference — do not import)
  user_engine_v1.py         v1 user engine bridge (read-only reference)

scripts/
  backup-db.sh              Pull live DB from server to local backups/
  restore-db.sh             Push a backup DB back to server

src/server/
  zpl_engine.py             Rule evaluator (pure, no I/O) — carried from v1 unchanged
  zpl_parser.py             ZPL RFC-15.5 parser — base for swappable parser interface
  zpl_serializer.py         ZPL text generation from classes/rules
  class_schema.py           Class hierarchy loader and resolver
  ai_client.py              Thin Anthropic SDK wrapper
  defaults/
    system_classes.yaml     Built-in ZPL class hierarchy
```

## Parser Architecture (planned)

The parser layer should be a swappable interface:

```python
class PolicyParser(Protocol):
    def parse(self, text: str) -> ParseResult: ...
    def language(self) -> str: ...   # "zpl" | "zpel"
```

`zpl_parser.py` becomes the ZPL implementation. A future `zpel_parser.py` handles
Oracle OCI syntax. The user's account stores their preferred language.

## GitHub

https://github.com/lewtucker/zpr-policy-maker-v2 (private)

## Production Infrastructure (ready, not yet deployed)

The server infrastructure is fully set up and waiting for code:

- **URL**: `https://zpr-policy2.lewtucker.net` (SSL via Certbot, auto-renews 2026-07-24)
- **nginx**: `/etc/nginx/sites-enabled/zpr-policy2.lewtucker.net` → proxies to port 8082
- **Server path**: `/opt/zpr-policy-maker-v2/src/server/`
- **Systemd service**: `zpr-policy-maker-v2` (created, not yet enabled — no code deployed yet)
- **Port**: 8082

### First Deployment Checklist

When ready to deploy for the first time:

```bash
# 1. rsync code (always use full absolute paths)
rsync -av /Users/lewtucker/Documents/dev/ZPR-Policy-maker-v2/src/server/ \
    root@72.62.97.102:/opt/zpr-policy-maker-v2/src/server/

# 2. On server: create venv + install deps
ssh root@72.62.97.102 "cd /opt/zpr-policy-maker-v2 && python3 -m venv venv && \
    venv/bin/pip install -r src/server/requirements.txt"

# 3. Write .env on server
ssh root@72.62.97.102 "cat > /opt/zpr-policy-maker-v2/src/server/.env << 'EOF'
APP_PASSWORD=...
ANTHROPIC_API_KEY=...
EOF"

# 4. Enable and start service
ssh root@72.62.97.102 "systemctl enable --now zpr-policy-maker-v2"
```

### Subsequent Deploys

```bash
rsync -av /Users/lewtucker/Documents/dev/ZPR-Policy-maker-v2/src/server/ \
    root@72.62.97.102:/opt/zpr-policy-maker-v2/src/server/
ssh root@72.62.97.102 "systemctl restart zpr-policy-maker-v2"
```
