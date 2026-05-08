# CLAUDE.md — ZPR Policy AI Playground (repo: zpr-policy-maker-v2)

> **This file is committed to git and is public. Never add sensitive information here.**
> This includes: server IP addresses, domain names, passwords, API keys, tokens, or
> local file paths. All secrets and deployment config belong in `src/server/.env` (gitignored).
> See `src/server/.env.example` for what to put there.

## ⚠️ PROJECT STATUS: ACTIVE (v3 — UI polish phase)

Active development as of 2026-05-03. The v3 ZPL-centric UI with namespace ownership model is
complete. Do not deploy to production until the user explicitly confirms readiness.

---

## ⚠️ DEPLOYMENT SAFETY

When deploying to a production server, confirm the destination before running any rsync or
restart commands. Do not assume this is the only application on the server — other services
may share the same host on different ports and paths. Deploying to the wrong directory or
restarting the wrong service can corrupt a separate running application.

Always use full absolute paths. Verify the server path, systemd service name, and port match
what is configured for **this** application before proceeding. The port is set in the systemd
`ExecStart` line and the nginx `proxy_pass` — keep them in sync. See `Implementation_Guide.md`
for the full deployment procedure.

---

## Project Overview

**ZPR Policy Builder** (v3) is a ZPL-centric, multi-namespace policy editor. Users write ZPL
directly; the system parses it live and displays structured classes and rules in a side panel.

### Key characteristics

- **ZPL editor first**: Write ZPL directly; parse/save are the main actions.
- **Namespaces separate from users**: `namespaces` table is distinct from `users`. Every namespace has an `owner_user_id`.
- **Namespace ownership tree**: Owners create sub-namespaces under their root. Can assign any existing user as owner.
- **Multi-user auth**: Per-user password + Bearer token (for API access by other systems).
- **Bidirectional ZPL**: Parser and serializer are round-trip compatible.
- **One ZPL doc per namespace**: `namespace_zpl` table keyed by `namespace_id`.
- **No delegation model**: No `delegated`, `delegated_to_user_id`, or `created_by_id` fields anywhere.

---

## Running Locally

```bash
cd src/server
uvicorn server:app --reload --port 8083   # use 8083 locally to avoid v1 conflict
```

No `.env` required for basic operation. First run: visit `/setup` to create root admin.

### Running Tests

```bash
cd src/server
python -m pytest tests/ -q
```

83 tests across 5 test files. All should pass.

---

## File Structure

```
docs/
  zpl_rfc15_5.bnf          BNF grammar for RFC-15.5 ZPL
  RFC_classes.yaml          Canonical ZPL class hierarchy (design reference)
  DemoScripts.md            Demo account conventions
  ZPL_Tests.md              Test cases — all pass with zero errors

Local/                      Local-only files (gitignored): OCI references, originals

reference/
  database_v1.py            v1 DB schema (read-only reference — do not import)
  server_v1.py              v1 FastAPI app (read-only reference — do not import)
  user_engine_v1.py         v1 user engine bridge (read-only reference)

scripts/
  backup-db.sh              Pull live DB from server to local backups/
  restore-db.sh             Push a backup DB back to server
  backup-local.sh           Snapshot local dev DB to backups/ with timestamp+label
  restore-local.sh          Restore a local backup with confirmation prompt

src/server/
  zpl_engine.py             Rule evaluator (pure, no I/O) — carried from v1 unchanged
  zpl_parser.py             ZPL RFC-15.5 parser (dotted names, quoted strings, comments, never-allow)
  zpl_serializer.py         ZPL text generation from classes/rules (bidirectional with parser)
  namespace.py              inject(policy, ns) / strip(policy, ns) / active_ns(session)
  class_schema.py           Class hierarchy loader and resolver
  ai_client.py              Thin Anthropic SDK wrapper
  database.py               All DB access (SQLite, pbkdf2_hmac passwords, migrations)
  server.py                 FastAPI app — all HTTP endpoints
  test_helpers.py           Shared make_session() for tests
  static/
    index.html              v3 UI (light theme, single-file SPA) — "ZPR Policy Builder"
    help.html               User Guide served at GET /help (no auth); includes release notes
    admin.html              Admin panel: user list, is_admin toggle, create user
    ui_v2.html              Preserved v2 UI (accessible at /v2)
  defaults/
    system_classes.yaml     Built-in ZPL class hierarchy
  tests/
    conftest.py             pytest fixtures: tmp DB, seeded users/namespaces
    test_db_namespaces.py   Stage 1: namespaces table (24 tests)
    test_context.py         Stage 2: session + context switch (11 tests)
    test_namespace_crud.py  Stage 3: namespace CRUD endpoints (20 tests)
    test_zpl_endpoints.py   Stage 4: ZPL endpoints keyed by namespace_id (12 tests)
    test_regression.py      Stage 5: legacy endpoints gone, users table cleanup (16 tests)
```

---

## Database Schema

```
users:
  id, username, password_hash, display_name, email, api_token, is_admin, created_at

namespaces:
  id, display_name, owner_user_id → users.id, parent_namespace_id → namespaces.id, created_at

namespace_zpl:
  namespace_id (PK) → namespaces.id, zpl_text, updated_at

policy_sets:   (legacy — v2 UI compat only, not used by v3)
conversations: (legacy agent chat history)
```

- `username`: login credential only — never appears in ZPL
- `display_name` (users): shown in profile; also seeds root namespace display_name on creation
- `display_name` (namespaces): appears in ZPL dot notation (e.g. `Corp.Employee`)
- `api_token`: Bearer token — `Authorization: Bearer <token>` accepted on all endpoints
- `is_admin`: DB column (migration-safe); first user auto-promoted to admin; admins can toggle others
- Root namespace: `parent_namespace_id IS NULL`, auto-created on first login

### Session shape

```json
{
  "login_user_id": "...",        "login_username": "...",   "login_display_name": "...",
  "active_namespace_id": "...",  "active_user_id": "...",   "active_display_name": "..."
}
```
`active_user_id` is an alias for `active_namespace_id` (backward compat). Both always equal.

---

## Key API Endpoints (v3)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/context` | Current session (login + active namespace) |
| POST | `/api/context/switch` | Switch active namespace `{ namespace_id }` |
| POST | `/api/context/reset` | Return to login user's root namespace |
| GET | `/api/namespaces/tree` | Full recursive namespace tree for login user |
| POST | `/api/namespaces` | Create namespace (`display_name`, `owner_username`, `owner_password`, `owner_email`, `parent_id`) |
| PATCH | `/api/namespaces/{id}` | Rename or reassign owner (`display_name`, `owner_username`, `owner_password`) |
| DELETE | `/api/namespaces/{id}` | Delete namespace + its ZPL |
| GET | `/api/namespace/zpl` | Active namespace ZPL (prefix stripped for editor) |
| PUT | `/api/namespace/zpl` | Save active namespace ZPL (prefix injected for storage) |
| GET | `/api/namespace/zpl/all` | Combined ZPL for active namespace subtree |
| POST | `/api/parse` | Parse ZPL; returns classes, rules, `serialized_zpl` |
| POST | `/api/match` | Test rule match (subject, object, verb) |
| GET | `/api/profile` | Current user profile |
| POST | `/api/profile` | Update email/display_name |
| POST | `/api/profile/password` | Change password |
| POST | `/api/token/regenerate` | Regenerate bearer token |
| GET | `/api/admin/users` | List all users (admin only) |
| POST | `/api/admin/users` | Create user (admin only; `is_admin` flag supported) |
| PATCH | `/api/admin/users/{id}/admin` | Set/clear admin flag (cannot self-revoke) |
| GET | `/help` | User Guide HTML (no auth required) |

---

## ZPL Namespace Prefix Model

Stored ZPL always carries the full dotted prefix (e.g. `lew.Corp.Employee`).
- **GET** strips the active namespace prefix before returning to the editor
- **PUT** injects the active namespace prefix before storing
- **Rename** cascades: re-prefixes all stored ZPL in the renamed namespace and its descendants
- Both GET and PUT fetch fresh `display_name` from the DB (not session) — avoids stale prefix after rename

---

## UI Layout (v3)

3-column CSS Grid: `{sidebarWidth}px 4px 1fr 4px {panelWidth}px`

Panel resizers are window-relative (no hard pixel caps); editor textarea has `min-width:0` so it
can shrink freely. Initial right panel width = `Math.floor((window.innerWidth - 220 - 8) / 2)`.

### Header

Buttons: **User Guide** (opens `/help` in new tab) | **Profile** | **Sign out**
Release Notes content lives inside the User Guide (no separate button).

### Sidebar (left)

- **NAMESPACE SELECTOR**: namespace tree; click to switch context; active namespace highlighted
- **NAMESPACE MANAGEMENT** (collapsible via Edit button): recursive ownership tree
  - +New / Edit / Delete per node
  - Edit form: namespace name + owner username + password (new owners only; no delegate checkbox)

### Center (ZPL editor)

- Toolbar: "ZPL Editor" | namespace name | Check ZPL | Save | **Delete All** | Show All | ⊕ **AI Assistant** | ↑↓ | ⊟
- ↑↓ dropdown: upload ZPL file or download current editor content
- Show All: loads combined ZPL for entire namespace subtree (read-only view)

### Right panel (schema)

- Tabs: Tests | Classes | Rules | Entities | **ZPL (full)**
- **Classes and Rules** default to **Table view** (entity-style): grouped section headers, rows with
  always-visible **Edit** / **[x]** / **yaml** buttons. yaml toggles an inline YAML panel with [x]
  to close. Tree/Table toggle at top of each tab.
- ZPL (full) tab: `serialized_zpl` from `/api/parse` — canonicalized round-trip output
- ⊞ expand: sets grid to full width

### Tests tab

- **Manual test card**: subject class + action + object class inputs; `+attr` button under each
  adds key:value rows. Key is a dropdown of inherited class attributes; value is a dropdown when
  the attribute has predefined values, otherwise free text. Pre-fills when a test row is selected.
- **Generate tests modal**: default counts 3 positive / 3 adversarial; larger spinner arrows.
- Rule evaluation order: never rules (priority desc) → first match → deny; then allow rules
  (priority desc) → first match → allow; no match → deny.

### Profile modal

- Opened by "Profile" button in header
- Fields: username (read-only), namespace name (read-only), email, change password, Bearer token, test rule match

### User Guide (`/help`)

- Standalone styled HTML; sticky left nav; sections cover all features + ZPL Quick Reference +
  Release Notes & ZPL Extensions. ← Back button at top of nav links to `/`.

---

## Feature Queue

1. **ZPL namespace declaration** — `define Mktg as namespace with owner Alice`
   - Parser extension + server handler that calls namespace create when encountered

---

## GitHub

<https://github.com/lewtucker/zpr-policy-maker-v2>

---

## Production Infrastructure

- **URL**: `https://<your-domain>` (SSL via Certbot)
- **nginx**: proxies to port 8082
- **Server path**: `/opt/zpr-policy-maker-v2/src/server/`
- **Systemd service**: `zpr-policy-maker-v2`
- **Port**: 8082

### First Deployment Checklist

```bash
# 1. rsync code (always use full absolute paths; never overwrite .env or DB)
rsync -av \
  --exclude='.env' --exclude='zpr_policy.db' \
  --exclude='__pycache__/' --exclude='.pytest_cache/' --exclude='*.pyc' --exclude='.DS_Store' \
  /path/to/ZPR-Policy-maker-v2/src/server/ \
    root@<your-server-ip>:/opt/zpr-policy-maker-v2/src/server/

# 2. On server: create venv + install deps
ssh root@<your-server-ip> "cd /opt/zpr-policy-maker-v2 && python3 -m venv venv && \
    venv/bin/pip install -r src/server/requirements.txt"

# 3. Write .env on server (see src/server/.env.example)
ssh root@<your-server-ip> "cat > /opt/zpr-policy-maker-v2/src/server/.env << 'EOF'
APP_PASSWORD=<your-app-password>
SECRET_KEY=<random-64-char-hex>
ANTHROPIC_API_KEY=<your-anthropic-api-key>
EOF"

# 4. Enable and start service
ssh root@<your-server-ip> "systemctl enable --now zpr-policy-maker-v2"
```

### Subsequent Deploys

```bash
# Use the deploy script (handles excludes automatically):
scripts/deploy.sh

# Or manually:
rsync -av \
  --exclude='.env' --exclude='zpr_policy.db' \
  --exclude='__pycache__/' --exclude='.pytest_cache/' --exclude='*.pyc' --exclude='.DS_Store' \
  /path/to/ZPR-Policy-maker-v2/src/server/ \
    root@<your-server-ip>:/opt/zpr-policy-maker-v2/src/server/
ssh root@<your-server-ip> "systemctl restart zpr-policy-maker-v2"
```
