# ZPR Policy Builder

A browser-based editor, tester, and AI-assisted authoring tool for
[ZPL (Zero-trust Policy Language)](https://zpr.org), the policy language defined in ZPR RFC-15.5.

ZPL lets you express access control policies in plain, structured English:
who can access what, under what conditions, and what is explicitly denied.
This tool lets you author, validate, test, and audit ZPL policies across a
multi-namespace hierarchy, with live parse feedback and AI-powered assistance.

---

## Features

**ZPL editor with live parse**
Write ZPL directly in a code editor. Parse or save and the right panel updates instantly
with structured classes, rules, and entities extracted from your policy. A canonicalized
round-trip view of your ZPL is also available in the ZPL (full) tab.

**Multi-namespace ownership tree**
Policies are organized into a namespace tree. Each namespace has a named owner;
sub-namespaces can be created under any node and delegated to different users.
Switch active context from the sidebar selector. A "Show All" view renders combined ZPL
for a namespace and all its descendants.

**Entity management**
Define named instances of ZPL classes using `Declare` statements
(e.g. `Declare Alice as an Employee with department:legal`).
Entities can be imported from YAML or LDIF files via the `↑↓` toolbar menu
or the Entities tab panel, and exported in both formats.

**Rule testing**
Build a test suite against your policy: manually enter subject/object/verb test cases,
generate rule-based coverage tests, or use AI to generate adversarial near-miss cases
using your declared entity instances. Run all tests at once with full rule traces.

**Policy Studio**
Describe your organization and access requirements in plain English. The AI generates
a complete ZPL policy — namespaces, classes, and rules — and can explain its reasoning
via the Agent Rationale view. Deploy the generated policy directly to your namespace tree.

**Policy Audit**
An AI-powered analyst reviews the active namespace subtree for security risks, ambiguities,
and structural issues: shadowing, overly broad class grants, coverage gaps, priority
conflicts, redundant rules, and more. Issues include suggested ZPL fixes that can be
accepted directly into the editor with one click.

**AI Assist**
An inline chat assistant with access to the current policy. Ask questions, generate
class definitions, or explain what rules do. Suggestions can be accepted, staged for
review, or discarded.

**YAML/LDAP Viewer**
Upload a `.yaml` or `.ldif` file and see it rendered as a formatted document. Entity
lists are grouped by class with attribute tables; generic YAML is rendered as structured
sections.

**ZPL Config**
Per-namespace configuration for built-in class extensions, custom aliases, and verb lists.

**Admin interface**
Admins can view all users, create accounts, grant or revoke admin privileges,
and reset passwords. Access at `/admin`.

---

## ZPL Quick Example

```zpl
Define Employee  as a user    with employee_id, department, optional role.
Define Executive as a user    with role:{CEO, SVP, EVP}.
Define Database  as a service with classification:confidential.
Define AppServer as a server  with classification:corporate, location.

Allow Employee                      to access Database  on AppServer.
Allow Executive with role:{CEO,SVP} to access Database  on AppServer.
Never allow Executive with role:EVP to access Database  on AppServer.
```

The full grammar is specified in ZPR RFC-15.5 (`bnf/zpl_rfc15_5.bnf`).

---

## Quick Start

**Requirements:** Python 3.11+

```bash
# 1. Install dependencies
cd src/server
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env — set APP_PASSWORD, SECRET_KEY, and ANTHROPIC_API_KEY

# 3. Run
uvicorn server:app --reload --port 8083
```

Open `http://localhost:8083`. On first run you are redirected to `/setup` to create the
root admin account. AI features require `ANTHROPIC_API_KEY` in `.env`.

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
src/server/
  server.py             FastAPI app — all HTTP endpoints
  zpl_parser.py         ZPL RFC-15.5 parser
  zpl_serializer.py     Round-trip ZPL serializer
  zpl_engine.py         Rule evaluator (pure, no I/O)
  namespace.py          Namespace prefix inject/strip
  database.py           SQLite access layer
  ai_client.py          Anthropic SDK wrapper
  oci_translator.py     OCI ZPR policy → ZPL translator
  prompts/              AI system prompts (policy_analyst.md, etc.)
  static/
    index.html          SPA frontend
    help.html           User Guide (served at /help)
    admin.html          Admin panel
  defaults/
    system_classes.yaml Built-in ZPL class hierarchy
  tests/                pytest test suite (83 tests)

Demo_Studio/        Sample policies, entities (YAML + LDIF)
docs/                   Architecture and demo notes
scripts/                Backup / restore scripts
bnf/                    BNF grammars for ZPL and ZPEL
```

Detailed documentation:

- `docs/ProjectSummary.md` — architecture overview
- `Implementation_Guide.md` — deployment and configuration guide
- `/help` in the running app — full user guide

---

## Links

- ZPR homepage: [https://zpr.org](https://zpr.org)
- GitHub: [https://github.com/lewtucker/zpr-policy-maker-v2](https://github.com/lewtucker/zpr-policy-maker-v2)
