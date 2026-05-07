# ZPL Extension: AI Agent Tool-Call Governance

## Overview

ZPL's allow/deny rule model maps naturally onto AI agent governance. Rather than controlling
network access between endpoints, the same language can control which tool calls an AI agent
is permitted to make on behalf of a person. This document describes how the five dimensions of
OpenClaw's existing policy model translate into ZPL constructs, and what a ZPL-native agent
governance policy looks like.

---

## Motivation

OpenClaw (and similar Claude-based agents) already intercept tool calls through a `before_tool_call`
hook that sends every request to a `/check` endpoint for evaluation. Today that check uses a
bespoke rule engine. ZPL Policy Builder could replace or front that engine, giving agent operators:

- A richer rule language (attribute filters, Never rules, class hierarchies)
- A visual editor with live parse feedback
- Namespace isolation per team or project
- The same rule format used for network and resource policy — one language across the stack

---

## Mapping the Five Dimensions to ZPL

OpenClaw's policy model has five match dimensions. Each maps to a ZPL class attribute:

| OpenClaw dimension | ZPL location        | Example                                      |
|--------------------|---------------------|----------------------------------------------|
| Person             | subject attribute   | `AgentCaller with person:Sam`                |
| Group              | subject attribute   | `AgentCaller with group:engineering`         |
| Agent runtime      | subject attribute   | `AgentCaller with agent:openclaw`            |
| Tool / program     | object class        | `BashCall with program:git`                  |
| File path          | endpoint + service  | `FileService on FileServer with path:'/home/sam'` |
| URL                | endpoint + service  | `WebService on WebServer with host:'example.com'` |

### Subject: AgentCaller

A single class carries person, agent, and optional group / employment type as flat attributes.
This keeps rules readable without requiring nested class references.

```zpl
Define AgentCaller as a user with person, agent, optional group, optional employment_type.
```

`Sam on Agent:openclaw` → `AgentCaller with person:Sam, agent:openclaw`

### Object: tool calls as services

Shell commands, file operations, and web fetches become first-class ZPL service/endpoint pairs.
URLs are split at the host boundary — host becomes a `WebServer` endpoint, path becomes a
`WebService` — mirroring ZPL's natural separation of services from the servers they run on.

```zpl
Define BashCall    as a service  with program, optional path.
Define FileServer  as an endpoint with path.
Define FileService as a service  with operation:{read, write}.
Define WebServer   as an endpoint with host, optional port.
Define WebService  as a service  with path, optional method.
```

`www.example.com/home` → `WebService with path:'/home' on WebServer with host:'www.example.com'`

### Verbs

Four verbs cover the main agent tool actions. ZPL supports user-defined verbs via
`Define X as a verb.`

```zpl
Define run   as a verb.   # bash tool
Define read  as a verb.   # file read
Define write as a verb.   # file write
Define fetch as a verb.   # web_fetch
```

---

## Example Policy

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

---

## Integration Sketch

The existing OpenClaw plugin calls `POST /check` before every tool use. To route through ZPL
Policy Builder the plugin would need to translate each tool call into a ZPL match request:

```
Tool call received by plugin
        │
        ▼
Build match payload:
  subject: { class: AgentCaller, person: <caller>, agent: <runtime>, group: <group> }
  verb:     run | read | write | fetch
  object:   { class: BashCall | FileService | WebService, ...attrs... }
  on:       { class: FileServer | WebServer, ...attrs... } (if applicable)
        │
        ▼
POST /api/match  →  { verdict: allow | deny }
        │
        ▼
Allow or block the tool call
```

No changes to the ZPL parser or rule engine are required — the existing `match` endpoint
already evaluates subject/verb/object triples with attribute filters and `on` constraints.

---

## Open Questions

1. **Glob path matching** — ZPL attribute matching is exact or set-valued. Rules like
   `path:'/home/**'` require either a parser extension for prefix/glob matching or a
   `path_prefix` attribute convention that the match endpoint evaluates separately.

2. **Approval workflow** — OpenClaw supports a `pending` verdict (human approves/denies
   before the tool call proceeds). ZPL currently has `Allow` and `Never allow` only.
   A `Pending` rule type would be a natural extension.

3. **Audit log** — Policy Builder has no per-evaluation activity log today. Agent governance
   would benefit from a record of every check with caller, tool, verdict, and timestamp.

4. **Agent identity verification** — The `agent` attribute is currently trust-on-declaration.
   A production integration would tie it to the bearer token used to call `/check`, ensuring
   the agent cannot self-report a different identity.
