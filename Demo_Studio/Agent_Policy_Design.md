# AI Agent Governance Policy — ZPL Sample Design

## Overview

This policy governs Claude-based AI coding agents (e.g. OpenClaw). Every tool call the agent
attempts is evaluated against these rules before execution. The default verdict is **deny** —
anything not explicitly allowed is blocked.

---

## Design Notes

### Subject model
The policy subject is an `AgentCaller` — a person operating through a specific agent runtime.
`person` and `agent` are flat attributes on the caller rather than nested class references,
keeping rules readable. Group membership and employment type are optional attributes used for
broader rules (admin access, intern restrictions).

### Object model
Tool calls are modelled as four classes across two layers:

| Class          | Type      | Attribute(s)               | Covers                        |
|----------------|-----------|----------------------------|-------------------------------|
| `BashCall`     | service   | `program`, optional `path` | Shell commands via bash tool  |
| `FileServer`   | endpoint  | `path`                     | File system location          |
| `FileService`  | service   | `operation:{read,write}`   | File read/write operations    |
| `WebServer`    | endpoint  | `host`, optional `port`    | Web host (e.g. example.com)   |
| `WebService`   | service   | `path`, optional `method`  | Web path (e.g. /home)         |

Web URLs are split at the `/` boundary: `www.example.com/home` becomes
`WebService with path:'/home' on WebServer with host:'www.example.com'`.
This mirrors how ZPL naturally separates services from the servers they run on.

### Verb model
Four verbs map to the four main agent tool actions:

| Verb    | Tool       |
|---------|------------|
| `run`   | bash       |
| `read`  | file read  |
| `write` | file write |
| `fetch` | web_fetch  |

### Limitations
Host, path, and program matching is **exact or set-based**. Glob patterns (`/home/**`,
`*.spammer.com`) are not natively supported in the ZPL parser — use explicit values or
multiple rules for now.

---

## Classes

```zpl
Define AgentCaller  as a user     with person, agent, optional group, optional employment_type.
Define BashCall     as a service  with program, optional path.
Define FileServer   as an endpoint with path.
Define FileService  as a service  with operation:{read, write}.
Define WebServer    as an endpoint with host, optional port.
Define WebService   as a service  with path, optional method.
Define run          as a verb.
Define read         as a verb.
Define write        as a verb.
Define fetch        as a verb.
```

---

## Entities

```zpl
Declare sam        as an AgentCaller with person:Sam,   agent:openclaw.
Declare alice      as an AgentCaller with person:Alice, agent:openclaw.
Declare intern_bob as an AgentCaller with person:Bob,   agent:openclaw, employment_type:intern.

Declare sams_fs       as a FileServer  with path:'/home/sam'.
Declare spammer_host  as a WebServer   with host:'spammer.com'.
```

---

## Rules

```zpl
# ── Block destructive / unsafe commands (evaluated first) ────────────────────
Never allow AgentCaller to run BashCall with program:rm.
Never allow AgentCaller to run BashCall with program:curl.

# ── Block interns from known spam / malicious hosts ───────────────────────────
Never allow AgentCaller with employment_type:intern to fetch WebService on WebServer with host:'spammer.com'.

# ── Sam: file access scoped to her home directory ────────────────────────────
Allow AgentCaller with person:Sam to read  FileService on FileServer with path:'/home/sam'.
Allow AgentCaller with person:Sam to write FileService on FileServer with path:'/home/sam'.

# ── Alice: unrestricted web access ───────────────────────────────────────────
Allow AgentCaller with person:Alice to fetch WebService on WebServer.

# ── Everyone: safe shell commands ────────────────────────────────────────────
Allow AgentCaller to run BashCall with program:ls.
Allow AgentCaller to run BashCall with program:git.

# ── Admin group: full file system access ─────────────────────────────────────
Allow AgentCaller with group:admin to read  FileService on FileServer.
Allow AgentCaller with group:admin to write FileService on FileServer.
```

---

## All ZPL — Copy/Paste Ready

```zpl
# AI Agent Governance Policy
# Subject:  AgentCaller (person + agent runtime + optional group/employment_type)
# Objects:  BashCall (shell), FileService on FileServer (files), WebService on WebServer (web)
# Verbs:    run, read, write, fetch
# Default:  deny — everything not listed below is blocked

Define AgentCaller  as a user     with person, agent, optional group, optional employment_type.
Define BashCall     as a service  with program, optional path.
Define FileServer   as an endpoint with path.
Define FileService  as a service  with operation:{read, write}.
Define WebServer    as an endpoint with host, optional port.
Define WebService   as a service  with path, optional method.
Define run          as a verb.
Define read         as a verb.
Define write        as a verb.
Define fetch        as a verb.

Declare sam        as an AgentCaller with person:Sam,   agent:openclaw.
Declare alice      as an AgentCaller with person:Alice, agent:openclaw.
Declare intern_bob as an AgentCaller with person:Bob,   agent:openclaw, employment_type:intern.
Declare sams_fs      as a FileServer with path:'/home/sam'.
Declare spammer_host as a WebServer  with host:'spammer.com'.

Never allow AgentCaller to run BashCall with program:rm.
Never allow AgentCaller to run BashCall with program:curl.
Never allow AgentCaller with employment_type:intern to fetch WebService on WebServer with host:'spammer.com'.
Allow AgentCaller with person:Sam   to read  FileService on FileServer with path:'/home/sam'.
Allow AgentCaller with person:Sam   to write FileService on FileServer with path:'/home/sam'.
Allow AgentCaller with person:Alice to fetch WebService on WebServer.
Allow AgentCaller                   to run   BashCall    with program:ls.
Allow AgentCaller                   to run   BashCall    with program:git.
Allow AgentCaller with group:admin  to read  FileService on FileServer.
Allow AgentCaller with group:admin  to write FileService on FileServer.
```
