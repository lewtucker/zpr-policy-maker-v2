# CLAUDE.md — ZPR Policy Maker v2/v3

## ⚠️ PROJECT STATUS: ACTIVE (v3 — namespace refactor complete)

Active development as of 2026-05-02. The v3 ZPL-centric UI with namespace ownership model is
complete. Do not deploy to production until the user explicitly confirms readiness.

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

**ZPR Policy Maker v3** is a ZPL-centric, multi-namespace policy editor. Users write ZPL directly;
the system parses it live and displays structured classes and rules in a side panel.

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

OCI_references/
  *.yaml / *.md             Oracle ZPEL reference classes, rules, policy examples

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
  namespace.py              inject(policy, ns) / strip(policy, ns) / active_ns(session)
  class_schema.py           Class hierarchy loader and resolver
  ai_client.py              Thin Anthropic SDK wrapper
  database.py               All DB access (SQLite, pbkdf2_hmac passwords, migrations)
  server.py                 FastAPI app — all HTTP endpoints
  test_helpers.py           Shared make_session() for tests
  static/
    index.html              v3 UI (light theme, single-file SPA)
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
  id, username, password_hash, display_name, email, api_token, created_at

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

### Sidebar (left)

- **NAMESPACE SELECTOR**: namespace tree; click to switch context; active namespace highlighted
- **NAMESPACE MANAGEMENT** (collapsible via Edit button): recursive ownership tree
  - +New / Edit / Delete per node
  - Edit form: namespace name + owner username + password (new owners only; no delegate checkbox)

### Center (ZPL editor)

- Toolbar: "ZPL Editor" | namespace name | Check ZPL | Save | Reset | Show All | ⊕ Assist | ↑↓ | ⊟
- ↑↓ dropdown: upload ZPL file or download current editor content
- Show All: loads combined ZPL for entire namespace subtree (read-only view)

### Right panel (schema)

- Tabs: Tests | Classes | Rules | ZPL
- ZPL tab: `serialized_zpl` from `/api/parse` — canonicalized round-trip output
- ⊞ expand: sets grid to full width

### Profile modal

- Opened by "Profile" button in header
- Fields: username (read-only), namespace name (read-only), email, change password, Bearer token, test rule match

---

## Feature Queue

1. **ZPL namespace declaration** — `define Mktg as namespace with owner Alice`
   - Parser extension + server handler that calls namespace create when encountered

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
