# CLAUDE.md — ZPR Policy Maker v2/v3

## ⚠️ PROJECT STATUS: ACTIVE (v3 redesign)

Active development as of 2026-05-01. The project pivoted from the original agent-first v2 concept
to a **v3 ZPL-centric UI** with a multi-user namespace ownership model. Do not deploy to production
until the user explicitly confirms readiness.

---

## ⚠️ DEPLOYMENT SAFETY — READ THIS FIRST AND NEVER VIOLATE

There are **three separate applications** on the production server (72.62.97.102).
Deploying to the wrong one corrupts it. The rules are absolute:

| Application | Domain | Server path | Systemd service | Port |
|-------------|---------|-------------|-----------------|------|
| **THIS APP** | `zpr-policy2.lewtucker.net` | `/opt/zpr-policy-maker-v2/` | `zpr-policy-maker-v2` | 8082 |
| ZPR Policy Maker v1 | `zpr-policy.lewtucker.net` | `/opt/zpr-policy-maker/` | `zpr-policy-maker` | 8081 |
| OpenClaw Policy Maker | `policy.lewtucker.net` | `/opt/policy-maker/` | `policy-maker` | 8080 |

**NEVER deploy to `zpr-policy.lewtucker.net` or `policy.lewtucker.net`.**
**NEVER write to `/opt/zpr-policy-maker/` or `/opt/policy-maker/`.**
**NEVER restart `zpr-policy-maker` or `policy-maker` services.**

When deploying, always use full absolute paths and confirm the destination before running rsync.

---

## Project Overview

**ZPR Policy Maker v3** is a ZPL-centric, multi-namespace policy editor. The primary interface
is a ZPL text editor. Users write ZPL directly; the system parses it live and displays structured
classes and rules in a side panel. An agent-first layer may be added later.

### Key characteristics

- **ZPL editor first**: Users write ZPL in a text editor; parse/validate/save are the main actions.
- **Namespace = user**: Every namespace is a user row in the DB. Each has its own isolated ZPL document.
- **Namespace ownership tree**: Owners create sub-namespaces; can delegate management to existing users.
- **Multi-user auth**: Per-user password + Bearer token (for API access by other systems).
- **Bidirectional ZPL**: Parser and serializer are round-trip compatible.
- **Policy sets removed**: Each namespace has exactly one ZPL document (`namespace_zpl` table).

---

## Running Locally

```bash
cd src/server
uvicorn server:app --reload --port 8083   # use 8083 locally to avoid v1 conflict
```

Auth requires `APP_PASSWORD` in `src/server/.env`. First run: visit `/setup` to create root admin.

---

## File Structure

```
docs/
  zpl_rfc15_5.bnf          BNF grammar for RFC-15.5 ZPL
  RFC_classes.yaml          Canonical ZPL class hierarchy (design reference)
  DemoScripts.md            Demo account conventions
  ZPL_Tests.md              Test cases — all pass with zero errors

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
  zpl_parser.py             ZPL RFC-15.5 parser (dotted names, quoted strings, comments, never-allow)
  zpl_serializer.py         ZPL text generation from classes/rules (bidirectional with parser)
  class_schema.py           Class hierarchy loader and resolver
  ai_client.py              Thin Anthropic SDK wrapper
  database.py               All DB access (SQLite, pbkdf2_hmac passwords, migrations)
  server.py                 FastAPI app — all HTTP endpoints
  static/
    index.html              v3 UI (light theme, single-file SPA)
    ui_v2.html              Preserved v2 UI (accessible at /v2)
  defaults/
    system_classes.yaml     Built-in ZPL class hierarchy
```

---

## Database Schema

```
users:
  id, username, password_hash, display_name, created_by_id, created_at,
  api_token, email, delegated, delegated_to_user_id

namespace_zpl:
  user_id (PK), zpl_text, updated_at

policy_sets:   (legacy — v2 UI compat only, not used by v3)
conversations: (legacy agent chat history)
```

- `username`: login credential; non-delegated namespaces use `_ns_<uuid>` (not shown in UI)
- `display_name`: namespace name shown in UI and ZPL dot notation
- `delegated`: True if the namespace has its own login
- `delegated_to_user_id`: ID of an existing user who manages this namespace (avoids username conflict)
- `api_token`: Bearer token for API access

---

## Key API Endpoints (v3)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/namespace/zpl` | Load active namespace's ZPL text |
| PUT | `/api/namespace/zpl` | Save active namespace's ZPL text |
| POST | `/api/parse` | Parse ZPL; returns classes, rules, `serialized_zpl` |
| POST | `/api/context/switch` | Switch active namespace context |
| POST | `/api/context/reset` | Return to login owner's context |
| GET | `/api/profile` | Current user profile |
| POST | `/api/profile` | Update email/display_name |
| POST | `/api/profile/password` | Change password |
| POST | `/api/token/regenerate` | Regenerate bearer token |
| GET | `/api/users/tree` | Full recursive namespace ownership tree |
| POST | `/api/users` | Create sub-namespace |
| PATCH | `/api/users/{id}` | Update namespace (owner assignment) |
| DELETE | `/api/users/{id}` | Delete namespace |
| POST | `/api/match` | Test rule match (subject, object, verb) |

---

## UI Layout (v3)

3-column CSS Grid: `{sidebarWidth}px 4px 1fr 4px {panelWidth}px`

### Sidebar (left)

- "NAMESPACE SELECTOR": namespace tree; click to switch context
- Separator + "NAMESPACE OWNERS" (collapsible): recursive ownership tree with +New / Edit / Delete

### Center (ZPL editor)

- Toolbar: "ZPL Editor" | namespace name | Parse | Validate | Save | Reset | status | [↑↓ upload/download] [⊟ toggle]
- Editor ⊟ toggle: collapses/expands schema panel
- ↑↓ dropdown: upload ZPL file or download current editor content

### Right panel (schema)

- Tabs: Classes | Rules | ZPL
- ZPL tab: `serialized_zpl` from `/api/parse` — canonicalized round-trip output
- ⊞ expand: sets grid to `{sidebarWidth}px 4px 0px 0px 1fr` (full width)

### Profile modal

- Opened by "Profile" button in header
- Fields: display name, email, change password, Bearer token (with regenerate), test rule match

---

## Feature Queue

1. **ZPL namespace declaration** — `define Mktg as namespace with owner Alice`
   - Parser extension + server handler that calls `create_user` when encountered

---

## GitHub

<https://github.com/lewtucker/zpr-policy-maker-v2> (private)

---

## Production Infrastructure (ready, not yet deployed)

- **URL**: `https://zpr-policy2.lewtucker.net` (SSL via Certbot, auto-renews 2026-07-24)
- **nginx**: `/etc/nginx/sites-enabled/zpr-policy2.lewtucker.net` → proxies to port 8082
- **Server path**: `/opt/zpr-policy-maker-v2/src/server/`
- **Systemd service**: `zpr-policy-maker-v2` (created, not yet enabled — no code deployed yet)
- **Port**: 8082

### First Deployment Checklist

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
