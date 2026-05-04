# ZPR Policy Maker — Project Summary

**Organization:** Applied Invention, LLC  
**Project version:** v3 (repository: `zpr-policy-maker-v2`)  
**Status:** Active development — not yet deployed to production  
**Last updated:** 2026-05-03

---

## Overview

The ZPR Policy Maker is a web-based editor and evaluation tool for **Zero-trust Policy Language (ZPL)**, the policy language defined in ZPR RFC-15.5. ZPR (Zero-trust Policy Runtime) is an open standard for expressing and evaluating zero-trust access policies. See [https://zpr.org](https://zpr.org) for the ZPR project.

This application (v3) is a complete redesign of the v1 editor. It is ZPL-centric — users write ZPL directly, and all structured views (class hierarchy, rule list, serialized output) are derived from live parsing. The system supports multiple users, hierarchical namespaces with per-namespace ownership, and a round-trip compatible parser/serializer.

---

## Reference Documents

| Document | Description |
|----------|-------------|
| `ZPL_Reference/ZPR_RFC-15.5.pdf` | ZPL language specification |
| `ZPL_Reference/ZPR_RFC-19.pdf` | ZPR RFC-19 |
| `ZPL_Reference/ZPL_Examples.md` | ZPL usage examples |
| `bnf/zpl_rfc15_5.bnf` | BNF grammar for ZPL RFC-15.5 (also reproduced below) |
| `bnf/zpel_oracle_zpr_pel_v1.bnf` | Oracle ZPR PEL reference BNF |
| `OCI_references/` | Oracle Cloud Infrastructure ZPR reference classes and rules |
| `docs/UserGuide.md` | End-user guide (also served at `/help` in the app) |

---

## System Architecture

### Backend (`src/server/`)

| File | Role |
|------|------|
| `server.py` | FastAPI application; all HTTP endpoints |
| `database.py` | SQLite via aiosqlite; pbkdf2_hmac password hashing; all DB access and migrations |
| `zpl_engine.py` | Pure rule evaluator (no I/O); takes a `CheckRequest`, returns allow/deny |
| `zpl_parser.py` | ZPL RFC-15.5 parser — dotted names, quoted strings, comments, never-allow |
| `zpl_serializer.py` | Generates ZPL text from parsed IR; round-trip compatible with the parser |
| `namespace.py` | `inject(policy, ns)` / `strip(policy, ns)` for namespace prefix handling |
| `class_schema.py` | Class hierarchy loader and resolver (`is_subclass`, `kind_of`) |
| `ai_client.py` | Thin Anthropic Claude SDK wrapper |

### Frontend

A single-file SPA at `src/server/static/index.html` — vanilla JavaScript, no build step or external framework dependencies. The UI is a 3-column CSS grid: namespace sidebar | ZPL editor | schema/rules panel.

### Database (SQLite)

| Table | Columns |
|-------|---------|
| `users` | `id`, `username`, `password_hash`, `display_name`, `email`, `api_token`, `is_admin`, `created_at` |
| `namespaces` | `id`, `display_name`, `owner_user_id → users`, `parent_namespace_id → namespaces`, `created_at` |
| `namespace_zpl` | `namespace_id (PK)`, `zpl_text`, `updated_at` |
| `namespace_entities` | `id`, `namespace_id`, `class_name`, `name`, `attributes (JSON)`, `created_at` |
| `policy_sets` | Legacy — v2 UI compatibility only; not used by v3 |
| `conversations` | Legacy agent chat history |

### Authentication

- **Session auth:** Cookie-based session via `URLSafeSerializer` signed with `SECRET_KEY`.
- **API auth:** `Authorization: Bearer <token>` accepted on all endpoints. Tokens are stored in `users.api_token` and can be regenerated via `POST /api/token/regenerate`.
- **Admin:** The first user created via `/setup` is automatically `is_admin=true`. Admins can grant admin privileges to other users via the admin endpoints.

---

## Key API Endpoints

### Context and namespaces

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/context` | Current session: login user + active namespace |
| POST | `/api/context/switch` | Switch active namespace `{ namespace_id }` |
| POST | `/api/context/reset` | Return to login user's root namespace |
| GET | `/api/namespaces/tree` | Full recursive namespace tree for the login user |
| POST | `/api/namespaces` | Create namespace (`display_name`, `owner_username`, `owner_password`, `owner_email`, `parent_id`) |
| PATCH | `/api/namespaces/{id}` | Rename or reassign namespace owner |
| DELETE | `/api/namespaces/{id}` | Delete namespace and its ZPL |

### ZPL

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/namespace/zpl` | Active namespace ZPL (prefix stripped for editor) |
| PUT | `/api/namespace/zpl` | Save active namespace ZPL (prefix injected before storing) |
| GET | `/api/namespace/zpl/all` | Combined ZPL for the active namespace subtree (Show All) |
| POST | `/api/parse` | Parse ZPL; returns `classes`, `rules`, `serialized_zpl` |
| POST | `/api/match` | Test a rule match: `{ subject_class, action, object_class, attrs }` |

### Entities

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/entities` | List entities for the active namespace |
| POST | `/api/entities` | Create an entity instance |
| PUT | `/api/entities/{id}` | Update entity |
| DELETE | `/api/entities/{id}` | Delete entity |

### Tests

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/tests/from-rules` | Generate a test suite from parsed rules |
| POST | `/api/tests/from-entities` | AI-powered test generation from entity instances |

### Profile and admin

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/profile` | Get or update current user profile (email, display_name) |
| POST | `/api/profile/password` | Change password |
| POST | `/api/token/regenerate` | Regenerate Bearer token |
| GET/POST | `/api/admin/*` | Admin endpoints (requires `is_admin=true`) |

---

## ZPL Namespace Prefix Model

Every ZPL document stored in the database carries the full dotted namespace prefix of its owning namespace (e.g., `Corp.Employee`). The prefix handling is transparent to the editor:

- **GET `/api/namespace/zpl`** strips the active namespace prefix before returning the text to the editor.
- **PUT `/api/namespace/zpl`** injects the prefix before persisting to the database.
- **Rename cascade:** when a namespace is renamed, the server re-prefixes all stored ZPL in that namespace and all its descendants.
- Both GET and PUT fetch the current `display_name` from the database (not from session) to avoid stale prefix values after a rename.

---

## Key Design Decisions

### 1. ZPL-centric UI

Users write ZPL directly. The structured class list, rule list, and canonicalized ZPL output are all derived by parsing the editor content on demand. There is no form-based rule builder — the language is the interface.

### 2. Namespace ownership model

Namespaces are a first-class concept, entirely separate from the `users` table. Every namespace has an `owner_user_id`. Sub-namespaces can have different owners, which naturally models organizational delegation without any special delegation flag or join table. The ownership relationship is expressed entirely through the namespace tree structure.

### 3. Bidirectional ZPL (parser/serializer round-trip)

`zpl_parser.py` and `zpl_serializer.py` are designed as inverses. Parsing a ZPL document and then serializing the resulting IR produces canonical, semantically equivalent ZPL. This enables the "ZPL" tab in the right panel, which shows the normalized form of whatever is in the editor.

### 4. One ZPL document per namespace

The `namespace_zpl` table uses `namespace_id` as the primary key. Each namespace holds exactly one ZPL text document. The "Show All" feature (`GET /api/namespace/zpl/all`) assembles a read-only combined view by concatenating ZPL from the active namespace and all its descendants, with namespace headers for navigation.

### 5. Entity instances

The `namespace_entities` table stores named, concrete instances of ZPL classes with specific attribute values (e.g., a specific employee named "Alice" with `department:Engineering`). Entities are separate from the ZPL class definitions. They exist to support realistic test generation — the `POST /api/tests/from-entities` endpoint uses entity instances to produce test cases grounded in actual data.

### 6. No delegation flag

There is no `delegated`, `delegated_to_user_id`, or `created_by_id` field in the schema. Delegation is modeled entirely through namespace ownership: if a sub-namespace has a different `owner_user_id`, that user has delegated authority over that subtree. No special-purpose columns are needed.

### 7. Admin model

The first user created via the `/setup` route is automatically assigned `is_admin=true`. Admins have access to `GET/POST /api/admin/*` endpoints. Admin status can be granted to additional users by an existing admin.

---

## ZPL BNF Grammar — RFC-15.5

The following is the full BNF grammar for ZPL as implemented in this project (`bnf/zpl_rfc15_5.bnf`).

```bnf
// ZPL — Zero-trust Policy Language
// BNF Grammar — RFC-15.5
// Not included: circumstantial constraints (time, data-volume limits)
// Reserved for future use: 'link', 'links', 'over', 'from', 'without'
//
// Changes from RFC-15.4:
//   - Added built-in server/servers class (predefined subclass of endpoints)
//   - Expanded verb set: access, use, call, read, write, connect to
//   - Added name:value form to <define-attr-spec> for inherited attribute restriction
//   - Added <attr-set> (name:{v1,v2,...}) to <attribute-expr>
//   - Fixed <with-attributes-clause>: removed broken additional-attributes-clause reference
//   - Fixed comment on <service-class-name> (was incorrectly labelled as endpoint)

// ── Top-level structure ───────────────────────────────────────────────────────

<zpl-policy> ::= <statement>*

<statement> ::= <permission-statement>
              | <denial-statement>
              | <define-statement>

<permission-statement> ::= "allow" <p-statement>

<denial-statement> ::= "never" <permission-statement>

<define-statement> ::= "define" <name> <aka-clause>? "as" <article> <class-name>
                       <with-attributes-clause>? "." <eol>

// ── Permission / denial body ──────────────────────────────────────────────────

<p-statement> ::= <subject-clause> "to" <verb> <object-clause>
                  (","? "and" <signal-clause>)? "." <eol>

<subject-clause> ::= <user-spec>
                   | <service-spec>
                   | <endpoint-spec>
                   | <user-spec> "on" <endpoint-spec>
                   | <service-spec> "on" <endpoint-spec>

<object-clause> ::= <service-spec>
                  | <service-spec> "on" <endpoint-spec>

<verb> ::= "access"
         | "use"
         | "call"
         | "read"
         | "write"
         | "connect" "to"

<signal-clause> ::= "signal" <string> "to" <name>

// ── Define statement ──────────────────────────────────────────────────────────

<aka-clause> ::= "aka" <name>

<article> ::= "a" | "an"

<with-attributes-clause> ::= "with" <define-attr-list>

<define-attr-list> ::= <define-attr-spec> (<and-token> <define-attr-spec>)*

// Three forms of attribute spec in a Define statement:
//   1. "multiple"? <name>        — single or multi-valued attribute declaration
//   2. "optional"? tag/tags ...  — one or more tag declarations
//   3. <name> ":" <value>        — attribute declaration with a fixed inherited value
<define-attr-spec> ::= "multiple"? <name>
                     | "optional"? ("tag" | "tags") <name> (<and-token> <name>)*
                     | <name> ":" <value>

<and-token> ::= "and" | ","

// ── Entity specs (used in permission and denial statements) ───────────────────

# A <user-class-name> must be or descend from the built-in "users" class.
<user-spec> ::= <attribute-expr>* <user-class-name>
<user-class-name> ::= <built-in-user-class-name> | <name>

# An <endpoint-class-name> must be or descend from the built-in "endpoints" class.
<endpoint-spec> ::= <attribute-expr>* <endpoint-class-name>
<endpoint-class-name> ::= <built-in-endpoint-class-name> | <name>

# A <service-class-name> must be or descend from the built-in "services" class.
<service-spec> ::= <attribute-expr>* <service-class-name>
<service-class-name> ::= <built-in-service-class-name> | <name>

// ── Attribute expressions (used in entity specs) ──────────────────────────────

<attribute-expr> ::= <attr-tag>
                   | <attr-kv-pair>
                   | <attr-key-presence>
                   | <attr-set>

<attr-tag>          ::= <name>

# No spaces around ':' in <attr-kv-pair>
<attr-kv-pair>      ::= <name> ":" <value>

# No space may precede ':' in <attr-key-presence>
<attr-key-presence> ::= <name> ":"

# Multi-value set match: name:{val1,val2,...}
<attr-set>          ::= <name> ":" "{" <value> ("," <value>)* "}"

// ── Class names ───────────────────────────────────────────────────────────────

<class-name> ::= <built-in-class-name> | <name>

<built-in-class-name> ::= <built-in-user-class-name>
                        | <built-in-endpoint-class-name>
                        | <built-in-service-class-name>

<built-in-user-class-name>     ::= "user"     | "users"
<built-in-service-class-name>  ::= "service"  | "services"

# endpoints and servers are both built-in endpoint classes (RFC-15.5 section 3.5).
# servers is a predefined subclass of endpoints with a multi-valued services attribute.
<built-in-endpoint-class-name> ::= "endpoint" | "endpoints"
                                 | "server"   | "servers"

// ── Names ─────────────────────────────────────────────────────────────────────

<name>           ::= <identifier> | <string> | <namespace-name>
<namespace-name> ::= <name> "." <name>
<identifier>     ::= <letter> (<letter> | <digit> | "-" | "_")*

// ── Values ────────────────────────────────────────────────────────────────────

<value>     ::= <string> | <value-set>
<value-set> ::= "{" <value> ("," <value>)* "}"

<string>         ::= <quoted-string> | <numeric-string>
<quoted-string>  ::= <single-quoted-string> | <double-quoted-string>

<single-quoted-string> ::= <single-quote> <single-quote-chars> <single-quote>
<double-quoted-string> ::= '"' <double-quote-chars> '"'

<single-quote-chars> ::= (<any-char-except-single-quote-or-backslash> | <escaped-char>)*
<double-quote-chars> ::= (<any-char-except-double-quote-or-backslash> | <escaped-char>)*
<escaped-char>       ::= "\'" | '\"' | "\\"

<single-quote>   ::= "'" | "`"
<numeric-string> ::= <integer> | <float>
<integer>        ::= <digit>+
<float>          ::= <digit>+ "." <digit>+

// ── Terminals ─────────────────────────────────────────────────────────────────

<letter>  ::= "a".."z" | "A".."Z"
<digit>   ::= "0".."9"
<comment> ::= "#" <any-chars-to-eol> | "//" <any-chars-to-eol>
```

---

## Running Locally

```bash
cd src/server
uvicorn server:app --reload --port 8083
```

No `.env` file is required for basic operation. On first run, visit `/setup` to create the root admin user.

### Running Tests

```bash
cd src/server
python -m pytest tests/ -q
```

83 tests across 5 files. All should pass.

| File | Stage | Count | Coverage |
|------|-------|-------|----------|
| `tests/test_db_namespaces.py` | 1 | 24 | Namespaces table |
| `tests/test_context.py` | 2 | 11 | Session + context switch |
| `tests/test_namespace_crud.py` | 3 | 20 | Namespace CRUD endpoints |
| `tests/test_zpl_endpoints.py` | 4 | 12 | ZPL endpoints keyed by namespace_id |
| `tests/test_regression.py` | 5 | 16 | Legacy endpoints removed, users table cleanup |

---

## Production Infrastructure

The production environment is provisioned but not yet deployed.

| Item | Value |
|------|-------|
| URL | `https://zpr-policy2.lewtucker.net` |
| Server | `72.62.97.102` |
| Server path | `/opt/zpr-policy-maker-v2/src/server/` |
| Systemd service | `zpr-policy-maker-v2` |
| Port | `8082` |
| SSL | Certbot; auto-renews 2026-07-24 |

> **Deployment safety:** There are three separate applications on the same server. Never deploy to `/opt/zpr-policy-maker/` or `/opt/policy-maker/`, and never restart the `zpr-policy-maker` or `policy-maker` services. See `CLAUDE.md` for the full deployment safety table.
