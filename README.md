# ZPR Policy Maker

A web-based editor and tester for [ZPL (Zero-trust Policy Language)](https://zpr.org), the policy
language defined in ZPR RFC-15.5. Built by [Applied Invention, LLC](https://appliedinvention.com).

ZPR — Zero-trust Policy Runtime — is a framework for expressing and enforcing access control
policies in plain English. This tool lets you author, validate, and test ZPL policies across a
hierarchy of namespaces, with live parse feedback and AI-assisted authoring.

---

## Features

**ZPL editor with live parse**
Write ZPL directly in a code editor. On every parse or save, the right panel updates with the
structured class hierarchy and rule list extracted from your policy. A canonicalized
round-trip view of your ZPL is also available.

**Multi-namespace ownership tree**
Policies are organized into namespaces arranged in an ownership tree. Each namespace has a named
owner; sub-namespaces can be created under any node and assigned to a different user. The active
namespace is displayed in the editor toolbar; switching context loads that namespace's ZPL
automatically. A "Show All" view renders the combined ZPL for a namespace and all its
descendants.

**Entity management**
Define named instances of ZPL classes (e.g. "Alice" as an `employee` with `roles:engineering`)
with typed attributes. Entities can be imported and exported as YAML or LDIF.

**Policy test suite**
Build a test suite against your policy: manually add subject/object/verb test cases, or
auto-generate them — either rule-based coverage or AI-generated adversarial cases. Run all tests
at once and see pass/fail results inline.

**AI Assist**
An integrated Anthropic Claude panel helps you write and refine ZPL. Ask questions, generate
class definitions, or get suggestions for rules based on your existing policy.

**Admin interface**
Admins can view all users, grant or revoke admin privileges, and see a namespace overview across
the entire system.

---

## ZPL Quick Example

ZPL is an English-like policy language. A simple policy might look like:

```
Define employee as a user with an ID-number, roles and optional tags full-time, part-time,
    and intern.
Define database as a service with content and optional tags corporate, employee, financial.

Never allow intern users to access services.
Allow full-time employees to access databases.
```

Policies can include attribute filters, named instances, endpoint constraints, and denial rules:

```
Allow sales employees on managed laptops to access customer databases.
Never allow role:intern users to access classified services.
Allow HR employees to access Timesheet-database.
Allow Timesheet-load-balancer to access Timesheet-database.
```

The full grammar is specified in ZPR RFC-15.5, a copy of which is at
`ZPL_Reference/ZPR_RFC-15.5.pdf` in this repository.

---

## Quick Start

**Requirements:** Python 3.11+

```bash
cd src/server
pip install -r requirements.txt
uvicorn server:app --reload --port 8083
```

Open `http://localhost:8083` in a browser. On first run, you will be redirected to `/setup` to
create the root admin account.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | FastAPI, SQLite (via aiosqlite) |
| Frontend | Single-file SPA (vanilla JS, no build step) |
| Auth | Session cookies + Bearer token |
| AI | Anthropic Claude (via `anthropic` SDK) |

---

## Project Structure

```
src/server/          FastAPI app, ZPL parser/serializer, database layer, SPA frontend
docs/                Design docs and test case reference
ZPL_Reference/       ZPR RFC-15.5 PDF, example ZPL policies
bnf/                 BNF grammar for RFC-15.5 ZPL
OCI_references/      Oracle ZPEL reference classes and policy examples (design reference)
scripts/             Deployment and database backup scripts
reference/           v1 source (read-only reference; not imported)
```

Detailed documentation:

- `docs/ProjectSummary.md` — architecture and design overview
- `docs/UserGuide.md` — end-user guide (also served at `/help` in the running app)
- `ZPL_Reference/ZPR_RFC-15.5.pdf` — the ZPL language specification

---

## Links

- ZPR homepage: [https://zpr.org](https://zpr.org)
- GitHub repository: [https://github.com/lewtucker/zpr-policy-maker-v2](https://github.com/lewtucker/zpr-policy-maker-v2)
