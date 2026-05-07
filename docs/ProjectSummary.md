# ZPR Policy AI Playground — Project Summary

**Project version:** v3 (repository: `zpr-policy-maker-v2`)  
**Status:** Active development  
**Last updated:** 2026-05-07

---

## Overview

ZPR Policy AI Playground is a web-based editor, tester, and AI-assisted authoring tool for
**Zero-trust Policy Language (ZPL)**, the policy language defined in ZPR RFC-15.5.
ZPR (Zero-trust Policy Runtime) is an open standard for expressing and evaluating zero-trust
access policies. See [https://zpr.org](https://zpr.org) for the ZPR project.

The application is ZPL-centric — users write ZPL directly, and all structured views (class
hierarchy, rule list, serialized output) are derived from live parsing. It supports multiple
users, hierarchical namespaces with per-namespace ownership, AI-powered policy generation and
auditing, and a round-trip compatible parser/serializer.

---

## Reference Documents

| Document | Description |
|----------|-------------|
| `ZPL_Reference/` | ZPR RFC-15.5 and related specs |
| `bnf/zpl_rfc15_5.bnf` | BNF grammar for ZPL RFC-15.5 |
| `bnf/zpel_oracle_zpr_pel_v1.bnf` | Oracle ZPR PEL reference BNF |
| `Implementation_Guide.md` | Deployment, configuration, and operations guide |
| `/help` (in running app) | Full user guide (served from `static/help.html`) |

---

## Features

### ZPL Editor with Live Parse
Users write ZPL directly in a code editor. Parse or save updates the right panel instantly
with structured classes, rules, and entities extracted from the policy. A canonicalized
round-trip view is available in the ZPL (full) tab.

### Multi-Namespace Ownership Tree
Policies are organized into a namespace tree. Each namespace has a named owner;
sub-namespaces can be delegated to different users. A "Show All" view renders combined ZPL
for a namespace and all its descendants.

### Entity Management
Named instances of ZPL classes (`Declare` statements) with typed attributes. Entities can be
imported from YAML or LDIF files and exported in both formats.

### Rule Testing
Manual test cases, rule-coverage generation, and AI adversarial test generation. Runs with
full rule traces. Supports attribute-level subject/object specification.

### Policy Studio
Plain-English description → AI-generated complete ZPL policy (namespaces, classes, rules).
Includes Agent Rationale view and one-click deploy to namespace tree.

### Policy Audit
AI analyst reviews the active namespace subtree for security risks, ambiguities, and structural
issues: shadowing, overly broad grants, coverage gaps, priority conflicts, redundant rules.
Issues include suggested ZPL fixes that can be accepted directly into the editor.

### AI Assist
Inline chat with access to the current policy. Generates class definitions, explains rules,
suggests improvements. Suggestions can be accepted, staged, or discarded.

### YAML/LDAP Viewer
Upload a `.yaml` or `.ldif` file and view it as a formatted document. Entity lists are grouped
by class with attribute tables; generic YAML renders as structured sections.

### ZPL Config
Per-namespace configuration for built-in class extensions, custom aliases, and verb lists.

### Admin Interface
User management: create accounts, grant/revoke admin privileges, reset passwords. At `/admin`.

---

## System Architecture

### Backend (`src/server/`)

| File | Role |
|------|------|
| `server.py` | FastAPI application — all HTTP endpoints |
| `database.py` | SQLite via aiosqlite; pbkdf2_hmac passwords; all DB access and migrations |
| `zpl_parser.py` | ZPL RFC-15.5 parser — dotted names, quoted strings, comments, never-allow |
| `zpl_serializer.py` | Generates ZPL text from parsed IR; round-trip compatible |
| `zpl_engine.py` | Pure rule evaluator (no I/O); takes a `CheckRequest`, returns allow/deny |
| `namespace.py` | `inject(policy, ns)` / `strip(policy, ns)` for namespace prefix handling |
| `class_schema.py` | Class hierarchy loader and resolver (`is_subclass`, `kind_of`) |
| `ai_client.py` | Thin Anthropic Claude SDK wrapper |
| `oci_translator.py` | OCI ZPR JSON → ZPL converter |
| `prompts/` | AI system prompts (Markdown files, editable without touching Python) |

### Frontend

A single-file SPA at `src/server/static/index.html` — vanilla JavaScript, no build step or
external framework. The UI is a 3-column CSS grid: namespace sidebar | ZPL editor | schema/rules
panel. Additional static files: `help.html` (user guide at `/help`), `admin.html` (admin panel).

### Database (SQLite)

| Table | Key Columns |
|-------|------------|
| `users` | `id`, `username`, `password_hash`, `display_name`, `email`, `api_token`, `is_admin` |
| `namespaces` | `id`, `display_name`, `owner_user_id → users`, `parent_namespace_id → namespaces` |
| `namespace_zpl` | `namespace_id (PK)`, `zpl_text`, `updated_at` |
| `namespace_entities` | `id`, `namespace_id`, `class_name`, `name`, `attributes (JSON)` |
| `policy_sets` | Legacy — v2 UI compatibility only |
| `conversations` | Legacy agent chat history |

### Authentication

- **Session auth:** Cookie-based session via `URLSafeSerializer` signed with `SECRET_KEY`.
- **API auth:** `Authorization: Bearer <token>` accepted on all endpoints. Tokens are stored
  in `users.api_token` and regeneratable via `POST /api/token/regenerate`.
- **Admin:** First user created via `/setup` is automatically `is_admin=true`.

### AI Models

| Feature | Model |
|---------|-------|
| Policy Studio | `claude-sonnet-4-6` |
| Policy Audit (Fast) | `claude-haiku-4-5-20251001` |
| Policy Audit (Deep) | `claude-sonnet-4-6` |
| AI Assist | `claude-sonnet-4-6` |
| Test generation | `claude-sonnet-4-6` |

---

## Key API Endpoints

### Context and Namespaces

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/context` | Current session: login user + active namespace |
| POST | `/api/context/switch` | Switch active namespace `{ namespace_id }` |
| POST | `/api/context/reset` | Return to login user's root namespace |
| GET | `/api/namespaces/tree` | Full recursive namespace tree for the login user |
| POST | `/api/namespaces` | Create namespace |
| PATCH | `/api/namespaces/{id}` | Rename or reassign namespace owner |
| DELETE | `/api/namespaces/{id}` | Delete namespace and its ZPL |

### ZPL

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/namespace/zpl` | Active namespace ZPL (prefix stripped for editor) |
| PUT | `/api/namespace/zpl` | Save active namespace ZPL (prefix injected before storing) |
| GET | `/api/namespace/zpl/all` | Combined ZPL for the active namespace subtree |
| POST | `/api/parse` | Parse ZPL; returns `classes`, `rules`, `serialized_zpl` |
| POST | `/api/match` | Test a rule match: `{ subject_class, action, object_class, attrs }` |
| GET | `/api/zpl/export/markdown` | Export all namespace ZPL as Markdown bundle |
| POST | `/api/zpl/import/markdown` | Import ZPL from a Markdown bundle |

### Entities

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/entities` | List entities for the active namespace |
| POST | `/api/entities` | Create an entity |
| PUT | `/api/entities/{id}` | Update entity |
| DELETE | `/api/entities/{id}` | Delete entity |
| GET | `/api/entities/export/yaml` | Export entities as YAML |
| POST | `/api/entities/import/yaml` | Import entities from YAML |
| GET | `/api/entities/export/ldif` | Export entities as LDIF |
| POST | `/api/entities/import/ldif` | Import entities from LDIF |

### AI Features

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/policy-studio/generate` | Generate ZPL policy from plain-English description |
| POST | `/api/namespace/analyze` | Policy Audit — AI analysis of active namespace subtree |
| POST | `/api/reports` | Save an audit report |
| GET | `/api/reports` | List saved audit reports |
| GET | `/api/reports/{id}` | Retrieve a report |
| DELETE | `/api/reports/{id}` | Delete a report |
| POST | `/api/assist` | AI Assist chat message |
| POST | `/api/assist/accept` | Accept AI Assist suggestion into editor |
| POST | `/api/assist/generate-rules` | Generate ZPL rules from AI Assist |
| POST | `/api/tests/from-entities` | AI test generation from entity instances |
| POST | `/api/tests/adversarial` | AI adversarial test generation |
| POST | `/api/zpl-assist` | ZPL error explanation |

### File Preview

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/yaml/preview` | Parse and preview a YAML file |
| POST | `/api/ldif/preview` | Parse and preview an LDIF file |

### Profile and Admin

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/profile` | Get or update user profile |
| POST | `/api/profile/password` | Change password |
| POST | `/api/token/regenerate` | Regenerate Bearer token |
| GET | `/api/admin/users` | List all users (admin only) |
| POST | `/api/admin/users` | Create user (admin only) |
| PATCH | `/api/admin/users/{id}/admin` | Grant/revoke admin flag |
| POST | `/api/admin/users/{id}/reset-password` | Reset user password |

---

## ZPL Namespace Prefix Model

Every ZPL document stored in the database carries the full dotted namespace prefix of its
owning namespace (e.g., `Corp.Employee`). The prefix handling is transparent to the editor:

- **GET `/api/namespace/zpl`** strips the active namespace prefix before returning to the editor.
- **PUT `/api/namespace/zpl`** injects the prefix before persisting.
- **Rename cascade:** renaming a namespace re-prefixes all stored ZPL in that namespace and its descendants.
- Both GET and PUT fetch the current `display_name` from the database (not session) to avoid stale values after a rename.

---

## Key Design Decisions

### ZPL-centric UI
Users write ZPL directly. All structured views are derived by parsing on demand. There is no
form-based rule builder — the language is the interface.

### Namespace Ownership Model
Namespaces are entirely separate from the `users` table. Every namespace has an `owner_user_id`.
Sub-namespaces can have different owners, modeling organizational delegation through tree structure
alone — no delegation flag or join table needed.

### Bidirectional ZPL
`zpl_parser.py` and `zpl_serializer.py` are designed as inverses. Parsing then serializing
produces canonical, semantically equivalent ZPL. This powers the "ZPL (full)" tab.

### One ZPL Document per Namespace
`namespace_zpl` uses `namespace_id` as primary key. "Show All" assembles a read-only combined
view by concatenating ZPL from the active namespace and all descendants.

### AI Prompts as Editable Files
All AI system prompts are plain Markdown files in `src/server/prompts/`. Tone, focus areas,
and output format can be adjusted without touching Python code.

---

## Repository Structure

```
src/server/
  server.py             FastAPI app — all HTTP endpoints
  zpl_parser.py         ZPL RFC-15.5 parser
  zpl_serializer.py     Round-trip ZPL serializer
  zpl_engine.py         Rule evaluator (pure, no I/O)
  namespace.py          Namespace prefix inject/strip
  database.py           SQLite access layer + migrations
  ai_client.py          Anthropic SDK wrapper
  oci_translator.py     OCI ZPR JSON → ZPL converter
  class_schema.py       Class hierarchy loader and resolver
  prompts/              AI system prompts (Markdown, editable)
  static/
    index.html          SPA frontend (single file, no build)
    help.html           User Guide at /help
    admin.html          Admin panel
  defaults/
    system_classes.yaml Built-in ZPL class hierarchy
  tests/                pytest test suite (83 tests)

Demo_Studio/            Sample policies and entity files for demos
Demo_ZPL/               ZPL demo scripts and examples
docs/                   Architecture and demo notes
scripts/                Backup/restore shell scripts
bnf/                    BNF grammars for ZPL and ZPEL
ZPL_Reference/          ZPR RFCs and specs
Local/                  Local-only files (gitignored)
```

---

## Production Infrastructure

| Item | Value |
|------|-------|
| URL | `https://<your-domain>` |
| Server | `<your-server-ip>` |
| Server path | `/opt/zpr-policy-maker-v2/src/server/` |
| Systemd service | `zpr-policy-maker-v2` |
| Port | `8082` |
| SSL | Certbot / Let's Encrypt |

> **Deployment safety:** Three separate applications share the same server. Never deploy to
> `/opt/zpr-policy-maker/` or `/opt/policy-maker/`, and never restart the `zpr-policy-maker`
> or `policy-maker` services. See `CLAUDE.md` for the full deployment safety table.
