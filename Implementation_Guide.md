# ZPR Policy Builder — Implementation Guide

This guide covers everything needed to get ZPR Policy Builder running: local development,
environment configuration, production deployment, and ongoing maintenance.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Clone and Install](#clone-and-install)
3. [Environment Configuration](#environment-configuration)
4. [First Run](#first-run)
5. [Running Locally](#running-locally)
6. [Running Tests](#running-tests)
7. [Production Deployment](#production-deployment)
8. [nginx Configuration](#nginx-configuration)
9. [systemd Service](#systemd-service)
10. [Backup and Restore](#backup-and-restore)
11. [User Management](#user-management)
12. [AI Features](#ai-features)
13. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **Python 3.11 or later**
- **pip** (bundled with Python)
- A modern browser (Chrome, Firefox, Safari, Edge)
- *(For AI features)* An [Anthropic API key](https://console.anthropic.com/)
- *(For production)* A Linux server with nginx and systemd

---

## Clone and Install

```bash
git clone https://github.com/lewtucker/zpr-policy-maker-v2.git
cd zpr-policy-maker-v2/src/server
pip install -r requirements.txt
```

No build step is required. The frontend is a single-file SPA (`static/index.html`).

---

## Environment Configuration

All configuration is via a `.env` file. A template is provided:

```bash
cp src/server/.env.example src/server/.env
```

Edit `src/server/.env` and fill in the three values:

```
APP_PASSWORD=<your-app-password>
SECRET_KEY=<random-64-char-hex-string>
ANTHROPIC_API_KEY=<your-anthropic-api-key>
```

### APP_PASSWORD

The password users must enter when **creating a new account** via `/setup` (first user) or
via the registration flow. It acts as an invite code — anyone who knows it can create an
account. Choose something you can share with intended users.

```
APP_PASSWORD=MyTeamAccessCode2026
```

### SECRET_KEY

Used to sign session cookies. Must be a long random string. If this changes, all existing
sessions are invalidated and users must log in again.

Generate one:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

```
SECRET_KEY=a8f3c2d1e9b4f7a0c3d6e2b8f1a9c4d7e0b3f6a2c9d4e7b0f3a6c1d8e5b2f9a4
```

### ANTHROPIC_API_KEY

Required for all AI features: Policy Studio, Policy Audit, AI Assist, and test generation.
Without this key the app runs fully but all AI buttons are disabled.

Get a key at [console.anthropic.com](https://console.anthropic.com/). Keys start with `sk-ant-`.

```
ANTHROPIC_API_KEY=sk-ant-api03-...
```

**Security note:** Never commit `.env` to git. It is gitignored by default.

---

## First Run

```bash
cd src/server
uvicorn server:app --reload --port 8083
```

Open `http://localhost:8083` in a browser.

On first run (no database exists), the app redirects to `/setup`:

1. Enter a **username** — this becomes your root namespace name (e.g. `acme` creates namespace `Acme`)
2. Enter a **password** for your account
3. Click **Create account**

The first account is automatically granted admin privileges. All subsequent users are created
either by an admin via `/admin`, or by anyone using the `APP_PASSWORD` registration flow.

The SQLite database is created at `src/server/zpr_policy.db` on first run.

---

## Running Locally

```bash
cd src/server
uvicorn server:app --reload --port 8083
```

Use port `8083` for local dev (avoids conflict if you have other apps on 8080–8082).
The `--reload` flag restarts the server automatically when Python files change.

To run without reload (more like production):

```bash
uvicorn server:app --port 8083
```

---

## Running Tests

```bash
cd src/server
python -m pytest tests/ -q
```

83 tests across 5 files covering database migrations, session management, namespace CRUD,
ZPL endpoints, and regression checks for removed legacy endpoints. All should pass on a
fresh clone.

To run a single test file:

```bash
python -m pytest tests/test_zpl_endpoints.py -v
```

---

## Production Deployment

### 1. Provision the server

Install Python 3.11+ and nginx on your server. A VPS with 1 GB RAM is sufficient.

```bash
# On the server (Ubuntu/Debian)
apt update && apt install -y python3.11 python3.11-venv python3-pip nginx
```

### 2. Create the application directory

```bash
mkdir -p /opt/zpr-policy-maker-v2
```

### 3. Deploy the code

From your local machine:

```bash
rsync -av /path/to/zpr-policy-maker-v2/src/server/ \
    root@<your-server-ip>:/opt/zpr-policy-maker-v2/src/server/
```

### 4. Create a virtual environment and install dependencies

```bash
ssh root@<your-server-ip>
cd /opt/zpr-policy-maker-v2
python3.11 -m venv venv
venv/bin/pip install -r src/server/requirements.txt
```

### 5. Create `.env` on the server

```bash
cat > /opt/zpr-policy-maker-v2/src/server/.env << 'EOF'
APP_PASSWORD=<your-app-password>
SECRET_KEY=<random-64-char-hex>
ANTHROPIC_API_KEY=<your-anthropic-api-key>
EOF
chmod 600 /opt/zpr-policy-maker-v2/src/server/.env
```

### 6. Test the app manually before enabling systemd

```bash
cd /opt/zpr-policy-maker-v2
venv/bin/uvicorn src.server.server:app --port 8082
# Ctrl-C when confirmed working
```

---

## nginx Configuration

Create a site config at `/etc/nginx/sites-available/zpr-policy-builder`:

```nginx
server {
    listen 80;
    server_name <your-domain>;

    # Redirect HTTP to HTTPS (after Certbot setup)
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name <your-domain>;

    # SSL certificates (managed by Certbot)
    ssl_certificate     /etc/letsencrypt/live/<your-domain>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<your-domain>/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8082;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Required for file uploads
        client_max_body_size 10M;
    }
}
```

Enable and reload:

```bash
ln -s /etc/nginx/sites-available/zpr-policy-builder /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### SSL with Certbot

```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d <your-domain>
```

Certbot auto-renews certificates. Verify with:

```bash
certbot renew --dry-run
```

---

## systemd Service

Create `/etc/systemd/system/zpr-policy-builder.service`:

```ini
[Unit]
Description=ZPR Policy Builder
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/zpr-policy-maker-v2
ExecStart=/opt/zpr-policy-maker-v2/venv/bin/uvicorn src.server.server:app --host 127.0.0.1 --port 8082
Restart=always
RestartSec=5
EnvironmentFile=/opt/zpr-policy-maker-v2/src/server/.env

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now zpr-policy-builder
systemctl status zpr-policy-builder
```

View logs:

```bash
journalctl -u zpr-policy-builder -f
```

### Subsequent deploys

```bash
# From local machine
rsync -av /path/to/zpr-policy-maker-v2/src/server/ \
    root@<your-server-ip>:/opt/zpr-policy-maker-v2/src/server/

# On the server
systemctl restart zpr-policy-builder
```

---

## Backup and Restore

### Automated scripts

The `scripts/` directory contains four scripts:

| Script | What it does |
|--------|-------------|
| `scripts/backup-db.sh` | Pull live database from server to `backups/` |
| `scripts/restore-db.sh` | Push a backup database back to the server |
| `scripts/backup-local.sh` | Snapshot local dev database with timestamp + label |
| `scripts/restore-local.sh` | Restore a local backup with confirmation prompt |

Edit the scripts to set your server IP and paths before use.

### Manual backup

```bash
# On the server
cp /opt/zpr-policy-maker-v2/src/server/zpr_policy.db \
   /opt/zpr-policy-maker-v2/backups/$(date +%Y%m%d-%H%M%S).db
```

### In-app backup and restore

The app also supports in-app backup/restore via the `↑↓` menu in the Policy Editor:

- **Export all namespaces (.md)** — downloads all ZPL as a Markdown bundle
- **Import all namespaces (.md)** — restores ZPL from a bundle

A `clear_all.json` file is included at the repo root as a restore payload that wipes
all namespace ZPL (useful when starting fresh with a new demo).

---

## User Management

### Creating users

**Via `/admin` (recommended for production):** Log in as an admin, navigate to `/admin`,
and use the "Create user" form. The new user receives their own root namespace.

**Via registration:** Any user who knows the `APP_PASSWORD` can create an account by
visiting the app when not logged in and following the account creation flow.

### Admin privileges

The first user is automatically an admin. Admins can grant or revoke admin status for
other users from the `/admin` interface. An admin cannot revoke their own privileges.

### Resetting passwords

Admins can reset any user's password from the `/admin` interface. Users can change their
own password from the Profile panel.

### API tokens

Every user has a Bearer token for programmatic API access. Tokens are viewable and
regeneratable from the Profile panel. Use in requests:

```
Authorization: Bearer <token>
```

---

## AI Features

All AI features require `ANTHROPIC_API_KEY` in `.env`. Without it, AI buttons are
visible but disabled with an explanatory message.

### Models used

| Feature | Default model | Notes |
|---------|--------------|-------|
| Policy Studio | `claude-sonnet-4-6` | Structured JSON output |
| Policy Audit (Fast) | `claude-haiku-4-5-20251001` | Quick scan |
| Policy Audit (Deep) | `claude-sonnet-4-6` | Thorough, may take ~2 min |
| AI Assist | `claude-sonnet-4-6` | Chat |
| Test generation | `claude-sonnet-4-6` | Adversarial test cases |

### API costs

Each feature call consumes Anthropic API tokens billed to your account. Approximate usage:
- **Fast Audit:** ~2,000–5,000 tokens
- **Deep Audit:** ~5,000–15,000 tokens
- **Policy Studio generation:** ~3,000–8,000 tokens
- **AI Assist (per message):** ~500–2,000 tokens

Monitor usage at [console.anthropic.com](https://console.anthropic.com/).

### Customizing prompts

AI system prompts are plain Markdown files in `src/server/prompts/`. Edit them to adjust
tone, focus areas, or output format without touching Python code:

| File | Used by |
|------|---------|
| `policy_analyst.md` | Policy Audit analyst |
| `studio_system.md` (inline in server.py) | Policy Studio generator |

---

## Troubleshooting

### App won't start

**Missing dependency:**
```bash
pip install -r requirements.txt
```

**Port already in use:**
```bash
lsof -i :8083   # find the process
# or use a different port: uvicorn server:app --port 8084
```

### "ANTHROPIC_API_KEY not set" error

AI features show this if the key is missing from `.env`. Verify:
```bash
grep ANTHROPIC_API_KEY src/server/.env
```
Make sure `.env` is in `src/server/`, not the repo root.

### Database issues

If the database becomes corrupted or you want to start fresh:
```bash
rm src/server/zpr_policy.db
# Restart the app — it creates a new database and redirects to /setup
```

**To reset just the ZPL** (keep users and namespaces): upload `clear_all.json` via
`↑↓ → Import all namespaces (.md)` in the Policy Editor.

### Session errors / login loops

If users are getting logged out unexpectedly, `SECRET_KEY` may have changed. This is
expected behavior — changing `SECRET_KEY` invalidates all existing sessions.

### nginx proxy errors

Check that the app is running on the expected port:
```bash
systemctl status zpr-policy-builder
curl -I http://127.0.0.1:8082/
```

Check nginx error log:
```bash
tail -f /var/log/nginx/error.log
```

### File upload failures

Large LDIF or policy files may exceed nginx's `client_max_body_size`. The default in the
provided nginx config is 10 MB. Increase if needed:
```nginx
client_max_body_size 50M;
```

---

## File Reference

```
src/server/
  .env.example          Template — copy to .env and fill in values
  requirements.txt      Python dependencies
  server.py             FastAPI application (all routes)
  zpl_parser.py         ZPL lexer and parser
  zpl_serializer.py     ZPL round-trip serializer
  zpl_engine.py         Rule evaluation engine
  namespace.py          Namespace prefix inject/strip
  database.py           SQLite schema, migrations, all DB calls
  ai_client.py          Anthropic API wrapper
  oci_translator.py     OCI ZPR JSON → ZPL converter
  prompts/              AI system prompts (Markdown)
  static/index.html     SPA frontend (single file, no build)
  static/help.html      User guide (served at /help)
  static/admin.html     Admin panel
  defaults/             Built-in class hierarchy YAML
  tests/                pytest test suite

Studio_examples/        Sample policies and entity files for demos
scripts/                Backup/restore shell scripts
```
