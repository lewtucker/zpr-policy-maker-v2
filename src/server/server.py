"""ZPR Policy Maker v2 — FastAPI server.

Endpoints
─────────
Auth
  GET  /setup          first-run admin creation (only when no users exist)
  GET  /login          login page
  POST /login          submit username + password
  POST /logout

User management (all require auth)
  GET  /api/users                list users created by the active owner
  POST /api/users                create a new owner under the active owner

Context
  GET  /api/context              current login + active owner
  POST /api/context/switch       switch active owner (must be a descendant)
  POST /api/context/reset        switch back to the login owner

API (all require auth, scoped to active owner)
  POST /api/parse      parse ZPL or ZPEL text → ParseResult
  POST /api/validate   syntax-check text → errors only
  POST /api/translate  PolicySet → ZPL or ZPEL text

  POST /api/simulate/{policy_set_id}   run scenarios (merges ALL namespaces)

  GET  /api/policy_sets              list (active owner's namespace)
  POST /api/policy_sets              create
  GET  /api/policy_sets/{id}         get full PolicySet
  PUT  /api/policy_sets/{id}         replace PolicySet
  DELETE /api/policy_sets/{id}       delete

  GET  /api/conversations/{id}       get conversation
  POST /api/chat                     one agent turn

  GET  /api/language                 get active language setting
  POST /api/language                 set active language (zpl|zpel)

  GET  /v2                           legacy v2 UI
  GET  /                             SPA index (v3 UI)
"""
from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel

load_dotenv()

import agent as agent_mod
import database as db
import ir_normalizer as norm
import namespace as ns_mod
import zpl_parser
import zpel_parser
import zpl_serializer
import zpel_serializer as zpel_ser
from ir_schema import (
    ChatMessage,
    Conditions,
    Conversation,
    ObjectSpec,
    ParseError,
    ParseResult,
    PolicySet,
    SimResult,
    SimScenario,
    SubjectSpec,
)
import json as _json
import random as _random
import re as _re

import ai_client
from zpl_engine import CheckRequest, Entity, Rule, ZPLEngine
from class_schema import ClassSchema

# ── Config ────────────────────────────────────────────────────────────────────

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
_signer = URLSafeSerializer(SECRET_KEY, salt="session")

STATIC_DIR = Path(__file__).parent / "static"

# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    yield

app = FastAPI(title="ZPR Policy Maker v2", lifespan=lifespan)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── Session helpers ───────────────────────────────────────────────────────────

def _make_session(login_user_id: str, login_username: str, login_display_name: str,
                  active_user_id: str, active_username: str, active_display_name: str) -> str:
    return _signer.dumps({
        "authenticated": True,
        "login_user_id": login_user_id,
        "login_username": login_username,
        "login_display_name": login_display_name,
        "active_user_id": active_user_id,
        "active_username": active_username,
        "active_display_name": active_display_name,
    })


def _read_session(request: Request) -> dict | None:
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        data = _signer.loads(token)
        return data if data.get("authenticated") else None
    except BadSignature:
        return None


def _check_session(request: Request) -> bool:
    return _read_session(request) is not None


def get_session(request: Request) -> dict:
    """FastAPI dependency — returns session dict or raises 401.
    Accepts session cookie or Authorization: Bearer <token> header."""
    data = _read_session(request)
    if data is not None:
        return data
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token auth requires async context — use get_session_async")
    raise HTTPException(status_code=401, detail="Not authenticated")


async def get_session_or_token(request: Request) -> dict:
    """Async dependency — session cookie OR Bearer token."""
    data = _read_session(request)
    if data is not None:
        return data
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        user = await db.get_user_by_token(token)
        if user:
            dn = user.get("display_name") or user["username"]
            return {
                "authenticated": True,
                "login_user_id": user["id"],
                "login_username": user["username"],
                "login_display_name": dn,
                "active_user_id": user["id"],
                "active_username": user["username"],
                "active_display_name": dn,
            }
    raise HTTPException(status_code=401, detail="Not authenticated")


# ── Setup (first-run only) ────────────────────────────────────────────────────

@app.get("/setup", response_class=HTMLResponse)
async def setup_page():
    if await db.user_count() > 0:
        return Response(status_code=302, headers={"Location": "/login"})
    return _setup_html()


@app.post("/setup")
async def setup_submit(request: Request):
    if await db.user_count() > 0:
        return Response(status_code=302, headers={"Location": "/login"})
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    if not username or not password:
        return HTMLResponse(_setup_html(error="Username and password required."), status_code=400)
    user = await db.create_user(username, password, created_by_id=None)
    token = _make_session(user["id"], user["username"], user["display_name"],
                          user["id"], user["username"], user["display_name"])
    response = Response(status_code=302, headers={"Location": "/"})
    response.set_cookie("session", token, httponly=True, samesite="lax")
    return response


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    if await db.user_count() == 0:
        return Response(status_code=302, headers={"Location": "/setup"})
    return _login_html()


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    user = await db.get_user_by_username(username)
    if not user or not db.verify_password(password, user["password_hash"]):
        return HTMLResponse(_login_html(error=True), status_code=401)
    dn = user.get("display_name") or user["username"]
    token = _make_session(user["id"], user["username"], dn, user["id"], user["username"], dn)
    response = Response(status_code=302, headers={"Location": "/"})
    response.set_cookie("session", token, httponly=True, samesite="lax")
    return response


@app.post("/logout")
async def logout():
    response = Response(status_code=302, headers={"Location": "/login"})
    response.delete_cookie("session")
    return response


# ── User management ───────────────────────────────────────────────────────────

@app.get("/api/users")
async def list_users(session: dict = Depends(get_session)):
    """List sub-namespaces created by the LOGIN owner (always root perspective for the tree)."""
    return await db.list_users_created_by(session["login_user_id"])


class CreateUserRequest(BaseModel):
    namespace_name: str           # display name / used in ZPL
    username: str | None = None   # login username; required when delegated=True
    password: str | None = None   # required when delegated=True
    email: str = ""
    delegated: bool = False       # True = separate login; False = creator manages it
    parent_id: str | None = None  # create under a specific node (must be a descendant of login user)


@app.post("/api/users", status_code=201)
async def create_user(req: CreateUserRequest, session: dict = Depends(get_session)):
    """Create a new namespace (sub-owner) under the active owner or a specified descendant."""
    import secrets as _sec
    ns = req.namespace_name.strip()
    if not ns:
        raise HTTPException(400, "namespace_name required")

    # Determine parent
    parent_id = req.parent_id or session["active_user_id"]
    if parent_id != session["login_user_id"]:
        if not await db.can_switch_to(session["login_user_id"], parent_id):
            raise HTTPException(403, "Not authorised to create under that namespace")

    if req.delegated:
        login = (req.username or "").strip()
        password = req.password or ""
        if not login or not password:
            raise HTTPException(400, "username and password required for delegated namespace")
    else:
        import uuid as _uuid
        login = f"_ns_{_uuid.uuid4().hex[:12]}"
        password = _sec.token_urlsafe(32)

    existing = await db.get_user_by_username(login)
    if existing:
        raise HTTPException(409, f"Username {login!r} already exists")
    user = await db.create_user(login, password, display_name=ns,
                                created_by_id=parent_id,
                                email=req.email.strip(),
                                delegated=req.delegated)
    return {"id": user["id"], "username": user["username"],
            "display_name": user["display_name"], "email": user["email"],
            "delegated": user["delegated"], "created_by_id": user["created_by_id"]}


# ── Profile & token ───────────────────────────────────────────────────────────

@app.get("/api/profile")
async def get_profile(session: dict = Depends(get_session)):
    user = await db.get_user_by_id(session["login_user_id"])
    if not user:
        raise HTTPException(404, "User not found")
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "email": user.get("email", ""),
        "api_token": user.get("api_token"),
    }


class UpdateProfileRequest(BaseModel):
    email: str = ""
    display_name: str | None = None


@app.post("/api/profile")
async def update_profile(req: UpdateProfileRequest, session: dict = Depends(get_session)):
    dn = req.display_name.strip() if req.display_name and req.display_name.strip() else None
    await db.update_profile(session["login_user_id"], req.email.strip(), display_name=dn)
    return {"ok": True}


@app.get("/api/users/tree")
async def get_owner_tree(session: dict = Depends(get_session)):
    return await db.get_owner_tree(session["login_user_id"])


class UpdateUserRequest(BaseModel):
    display_name: str | None = None
    username: str | None = None
    password: str | None = None
    email: str | None = None
    delegated: bool | None = None


@app.patch("/api/users/{user_id}")
async def update_user(user_id: str, req: UpdateUserRequest,
                      session: dict = Depends(get_session)):
    if not await db.can_switch_to(session["login_user_id"], user_id):
        raise HTTPException(403, "Not authorised to edit this user")
    if user_id == session["login_user_id"]:
        raise HTTPException(400, "Use /api/profile to edit your own account")
    delegated_to_user_id = None
    if req.username and req.delegated:
        existing = await db.get_user_by_username(req.username)
        if existing and existing["id"] != user_id:
            # Existing user — delegate to them rather than renaming this namespace's login
            delegated_to_user_id = existing["id"]
            await db.update_user(user_id,
                                 display_name=req.display_name,
                                 email=req.email,
                                 delegated=True,
                                 delegated_to_user_id=delegated_to_user_id)
            return {"ok": True}
    await db.update_user(user_id,
                         display_name=req.display_name,
                         username=req.username,
                         password=req.password,
                         email=req.email,
                         delegated=req.delegated,
                         delegated_to_user_id=delegated_to_user_id)
    return {"ok": True}


@app.delete("/api/users/{user_id}", status_code=204)
async def delete_user(user_id: str, session: dict = Depends(get_session)):
    if not await db.can_switch_to(session["login_user_id"], user_id):
        raise HTTPException(403, "Not authorised to delete this user")
    if user_id == session["login_user_id"]:
        raise HTTPException(400, "Cannot delete yourself")
    err = await db.delete_user(user_id)
    if err:
        raise HTTPException(409, err)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/profile/password")
async def change_password(req: ChangePasswordRequest, session: dict = Depends(get_session)):
    user = await db.get_user_by_id(session["login_user_id"])
    if not user or not db.verify_password(req.current_password, user["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    if len(req.new_password) < 3:
        raise HTTPException(400, "New password must be at least 3 characters")
    await db.update_password(session["login_user_id"], req.new_password)
    return {"ok": True}


@app.post("/api/token/regenerate")
async def regenerate_token(session: dict = Depends(get_session)):
    token = await db.regenerate_token(session["login_user_id"])
    return {"api_token": token}


class SetTokenRequest(BaseModel):
    token: str


@app.post("/api/token/set")
async def set_token(req: SetTokenRequest, session: dict = Depends(get_session)):
    t = req.token.strip()
    if not t:
        raise HTTPException(400, "Token cannot be empty")
    await db.set_token(session["login_user_id"], t)
    return {"api_token": t}


class MatchRequest(BaseModel):
    subject_class: str = "users"
    subject_name: str | None = None
    subject_attrs: dict = {}
    accessor_class: str | None = None
    accessor_attrs: dict = {}
    action: str = "access"
    object_class: str = "services"
    object_name: str | None = None
    object_attrs: dict = {}


@app.post("/api/match")
async def match_rule(req: MatchRequest, session: dict = Depends(get_session_or_token)):
    """Test whether a request matches any rule in the active namespace's merged ZPL."""
    ps = await _merged_policy_set(session["active_user_id"])
    if not ps:
        return {"verdict": "deny", "rule": None, "reason": "No ZPL defined", "trace": []}
    rules = []
    for s in ps.rules:
        try:
            rules.append(Rule.from_dict({
                "id": s.id, "name": s.name,
                "result": "never" if s.effect == "deny" else "allow",
                "priority": s.priority, "verb": s.action,
                "subject": _subject_to_zpl_dict(s.subject),
                "object": _object_to_zpl_dict(s.object),
                "accessor_endpoint": _subject_to_zpl_dict(s.accessor_endpoint),
                "server_endpoint": _object_to_zpl_dict(s.server_endpoint),
            }))
        except Exception:
            continue
    schema = _build_schema(ps)
    check = CheckRequest(
        subject=Entity(class_name=req.subject_class, name=req.subject_name, attrs=req.subject_attrs),
        object=Entity(class_name=req.object_class, name=req.object_name, attrs=req.object_attrs),
        verb=req.action,
        accessor_endpoint=Entity(class_name=req.accessor_class, attrs=req.accessor_attrs)
            if req.accessor_class else None,
    )
    try:
        result = ZPLEngine(rules, schema).evaluate(check)
    except Exception as exc:
        return {"verdict": "deny", "rule": None, "reason": f"Engine error: {exc}", "trace": []}
    trace_out = []
    for rt in result.trace:
        trace_out.append({
            "rule": rt.rule_name or rt.rule_id,
            "matched": rt.matched,
            "slots": {k: {"ok": v.matched, "why": v.reason} for k, v in rt.slot_matches.items()},
        })
    return {
        "verdict": result.verdict,
        "rule": result.rule_name,
        "reason": f"Matched rule '{result.rule_name}'" if result.rule_id else "No matching rule",
        "trace": trace_out,
        "zpl_loaded": True,
        "rule_count": len(rules),
        "class_count": len(ps.classes),
    }


# ── Context switching ─────────────────────────────────────────────────────────

_PROMPTS_DIR = Path(__file__).parent / "prompts"


@app.get("/api/prompts/{key}")
async def get_prompt(key: str, _: dict = Depends(get_session)):
    content = await db.get_prompt(key)
    if content is None:
        path = _PROMPTS_DIR / f"{key}.md"
        if not path.exists():
            raise HTTPException(404, f"Prompt '{key}' not found")
        content = path.read_text()
    return {"key": key, "content": content}


class PromptSaveRequest(BaseModel):
    content: str


@app.put("/api/prompts/{key}")
async def save_prompt(key: str, req: PromptSaveRequest, _: dict = Depends(get_session)):
    await db.save_prompt(key, req.content)
    return {"key": key, "saved": True}


def _flatten_tree_nodes(tree: dict) -> list[dict]:
    """Return all nodes (id + display_name) in an owner tree."""
    if not tree or not tree.get("id"):
        return []
    nodes = [{"id": tree["id"], "display_name": tree.get("display_name", "")}]
    for child in tree.get("children") or []:
        nodes.extend(_flatten_tree_nodes(child))
    return nodes


async def _merged_policy_set(root_user_id: str) -> PolicySet | None:
    """Parse and merge ZPL from root_user_id and all descendant namespaces,
    applying each namespace's prefix via ns_mod.inject."""
    tree = await db.get_owner_tree(root_user_id)
    nodes = _flatten_tree_nodes(tree)
    user_ids = [n["id"] for n in nodes]
    dn_map = {n["id"]: n["display_name"] for n in nodes}
    zpl_map = await db.get_namespace_zpl_batch(user_ids)
    merged = PolicySet(name="_merged", language="zpl")
    for uid in user_ids:
        text = zpl_map.get(uid, "").strip()
        if not text:
            continue
        try:
            raw = zpl_parser.parse(text)
            ps, errors = norm.zpl_to_policy_set(raw)
            if errors:
                continue
            ns = (dn_map.get(uid) or "").strip()
            if ns and not ns.startswith("_ns_"):
                injected = ns_mod.inject(ps.model_dump(mode="json"), ns)
                ps = PolicySet.model_validate(injected)
            merged.classes.extend(ps.classes)
            merged.rules.extend(ps.rules)
        except Exception:
            pass
    return merged if (merged.classes or merged.rules) else None


# ── Adversarial mutation helpers ──────────────────────────────────────────────

_ADVERSARIAL_VERBS = ["read", "write", "access", "use", "execute", "delete", "create", "update"]


def _base_payload(rule) -> dict:
    s, o, ae = rule.subject, rule.object, rule.accessor_endpoint
    p: dict = {
        "subject_class": s.cls if s and s.cls else "users",
        "subject_attrs": dict(s.attrs) if s and s.attrs else {},
        "action": rule.action,
        "object_class": o.cls if o and o.cls else "services",
        "object_attrs": dict(o.attrs) if o and o.attrs else {},
    }
    if ae and ae.cls:
        p["accessor_class"] = ae.cls
        p["accessor_attrs"] = dict(ae.attrs) if ae.attrs else {}
    return p


def _payload_description(payload: dict) -> str:
    subj = (payload.get("subject_class") or "users").split(".")[-1]
    verb = payload.get("action") or "access"
    obj  = (payload.get("object_class") or "services").split(".")[-1]
    parts = [subj, verb, obj]
    if payload.get("accessor_class"):
        parts.append(f"on {payload['accessor_class'].split('.')[-1]}")
        for k, v in (payload.get("accessor_attrs") or {}).items():
            parts.append(f"[{k}:{v}]")
    for k, v in (payload.get("subject_attrs") or {}).items():
        parts.append(f"[{k}:{v}]")
    for k, v in (payload.get("object_attrs") or {}).items():
        parts.append(f"[{k}:{v}]")
    return " ".join(parts)


def _check_req_from_payload(payload: dict) -> CheckRequest:
    p = payload
    return CheckRequest(
        subject=Entity(
            class_name=p.get("subject_class", "users"),
            name=p.get("subject_name"),
            attrs=p.get("subject_attrs") or {},
        ),
        object=Entity(
            class_name=p.get("object_class", "services"),
            name=p.get("object_name"),
            attrs=p.get("object_attrs") or {},
        ),
        verb=p.get("action", "access"),
        accessor_endpoint=Entity(
            class_name=p["accessor_class"],
            attrs=p.get("accessor_attrs") or {},
        ) if p.get("accessor_class") else None,
    )


def _is_deny(engine: ZPLEngine, payload: dict) -> bool:
    try:
        return engine.evaluate(_check_req_from_payload(payload)).verdict == "deny"
    except Exception:
        return False


def _generate_mutations(
    allow_rules: list,
    deny_rules: list,
    schema: ClassSchema,
    engine: ZPLEngine,
    n: int,
) -> list[dict]:
    """Programmatically generate up to n verified adversarial payloads."""
    seen: set[str] = set()
    results: list[dict] = []

    def _try(payload: dict, hint: str) -> bool:
        key = _json.dumps(payload, sort_keys=True)
        if key in seen:
            return False
        seen.add(key)
        if _is_deny(engine, payload):
            results.append({"payload": payload, "mutation_hint": hint})
            return True
        return False

    shuffled = list(allow_rules)
    _random.shuffle(shuffled)
    target = n * 4  # over-generate then truncate

    # D — wrong verb
    for rule in shuffled:
        if len(results) >= target:
            break
        base = _base_payload(rule)
        for v in _ADVERSARIAL_VERBS:
            if v != rule.action:
                if _try({**base, "action": v},
                        f"wrong verb: {v!r} instead of {rule.action!r}"):
                    break

    # A — wrong subject class (sibling in hierarchy)
    for rule in shuffled:
        if len(results) >= target:
            break
        base = _base_payload(rule)
        try:
            parent = schema.parent(base["subject_class"])
            if parent:
                siblings = [c for c in schema.children(parent)
                            if c != base["subject_class"]
                            and not schema.is_subclass(c, base["subject_class"])]
                for sib in siblings:
                    if _try({**base, "subject_class": sib},
                            f"wrong subject: {sib.split('.')[-1]!r} not permitted to {rule.action} {base['object_class'].split('.')[-1]!r}"):
                        break
        except Exception:
            pass

    # A — wrong object class (sibling in hierarchy)
    for rule in shuffled:
        if len(results) >= target:
            break
        base = _base_payload(rule)
        try:
            parent = schema.parent(base["object_class"])
            if parent:
                siblings = [c for c in schema.children(parent)
                            if c != base["object_class"]
                            and not schema.is_subclass(c, base["object_class"])]
                for sib in siblings:
                    if _try({**base, "object_class": sib},
                            f"wrong object: {base['subject_class'].split('.')[-1]!r} has no access to {sib.split('.')[-1]!r}"):
                        break
        except Exception:
            pass

    # E — trigger a never rule
    for deny_rule in deny_rules:
        if len(results) >= target:
            break
        ds, do_ = deny_rule.subject, deny_rule.object
        if not ds or not do_ or not ds.cls or not do_.cls:
            continue
        for allow_rule in shuffled:
            base = _base_payload(allow_rule)
            try:
                if not schema.is_subclass(base["subject_class"], ds.cls):
                    continue
            except Exception:
                continue
            _try({**base, "action": deny_rule.action,
                  "object_class": do_.cls, "object_attrs": {}},
                 f"blocked by never rule: {ds.cls.split('.')[-1]} cannot {deny_rule.action} {do_.cls.split('.')[-1]}")
            break

    # B — wrong attribute value
    for rule in shuffled:
        if len(results) >= target:
            break
        base = _base_payload(rule)
        for scope, key in [("subject_attrs", "subject_attrs"), ("object_attrs", "object_attrs")]:
            if base[scope]:
                for k, v in base[scope].items():
                    bad = f"not-{v}" if isinstance(v, str) else "invalid"
                    if _try({**base, scope: {**base[scope], k: bad}},
                            f"wrong {scope.split('_')[0]} attr {k}={bad!r}"):
                        break

    return results[:n]


# ── ZPL error explanation ────────────────────────────────────────────────────

class ExplainErrorsRequest(BaseModel):
    text: str
    errors: list[dict]


@app.post("/api/explain-errors")
async def explain_errors(req: ExplainErrorsRequest, session: dict = Depends(get_session)):
    if not ai_client.available():
        raise HTTPException(503, "ANTHROPIC_API_KEY not set")
    if not req.errors:
        return {"explanations": []}

    errors_text = "\n".join(
        f"  [{i+1}] Line {e.get('line','?')}: {e.get('message','')} — source: {e.get('source','')!r}"
        for i, e in enumerate(req.errors)
    )
    prompt = f"""You are a ZPL (Zero-trust Policy Language) syntax assistant.

A user has written this ZPL policy:

```
{req.text}
```

The parser reported these errors:
{errors_text}

ZPL syntax rules:
- Define statements: `Define <name> as a <parent> with <attrs>.`
- Allow statements: `Allow [<tag>...] <subject-class> [on [<tag>...] <endpoint-class>] to <verb> [<tag>...] <object-class>.`
- Never statements: `Never allow ...` (same shape as Allow)
- Attribute modifiers: `optional tags <name>, <name>`, `multiple <name>`, `optional <name>`
- Tag qualifiers in rules are bare names before the class: `hr employee` means employee with hr tag
- Every statement ends with a period.

For each numbered error return:
- explanation: one plain-English sentence describing what is wrong and why
- fix: the corrected version of ONLY the offending source line (complete, valid ZPL — no placeholders or ellipsis)

Return JSON only — no other text:
{{"explanations": [{{"index": 1, "explanation": "plain English reason", "fix": "corrected ZPL line"}}]}}"""

    try:
        raw = ai_client.complete(
            system="You are a ZPL syntax assistant. Return only valid JSON.",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1024,
            temperature=0.2,
        )
    except Exception as exc:
        raise HTTPException(500, f"AI call failed: {exc}")

    text = raw.strip()
    text = _re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=_re.DOTALL).strip()
    try:
        result = _json.loads(text)
    except Exception:
        raise HTTPException(500, "Could not parse AI response")

    return result


# ── ZPL assistant ────────────────────────────────────────────────────────────

class ZplAssistRequest(BaseModel):
    message: str
    zpl_so_far: str = ""
    history: list[dict] = []


@app.post("/api/zpl-assist")
async def zpl_assist(req: ZplAssistRequest, session: dict = Depends(get_session)):
    if not ai_client.available():
        raise HTTPException(503, "ANTHROPIC_API_KEY not set")

    msg = req.message.strip()
    if not msg:
        return {"action": "noop", "reply": ""}

    # Stop intent: short message starting with a stop word
    _STOP_RE = _re.compile(
        r'^\s*(no|nope|stop|quit|done|exit|finish|bye|close|end)(\s.*)?$',
        _re.IGNORECASE,
    )
    if _STOP_RE.match(msg):
        return {"action": "stop", "reply": "Closing the assistant. Your ZPL is ready."}

    # ZPL-like input: contains Define / Allow / Never keywords
    if _re.search(r'\b(define|allow|never)\b', msg, _re.IGNORECASE):
        raw = zpl_parser.parse(msg)
        errors = raw.get("errors", [])
        if not errors:
            return {"action": "add", "statement": msg, "reply": "Added. Anything else?"}

        # Has parse errors → AI explains and offers a fix
        errors_text = "\n".join(
            f"  [{e.get('line','?')}] {e.get('message','')} — {e.get('source','')!r}"
            for e in errors
        )
        explain_prompt = (
            f"The user wrote this ZPL statement:\n\n{msg}\n\n"
            f"Parser reported:\n{errors_text}\n\n"
            "ZPL syntax reference:\n"
            "- Define: `Define <Name> as a <parent> with <attrs>.`  parents: users, endpoints, services, servers\n"
            "  attrs: `optional tags <n>, <n>`, `multiple <n>`, `optional <n>`, `<n>:<v>`\n"
            "- Allow: `Allow [<tag>...] <Class> [on [<tag>...] <End>] to <verb> [<tag>...] <Obj>.`\n"
            "- Never allow: same shape, starts with `Never allow`\n"
            "- Every statement ends with a period.\n\n"
            'Return JSON only: {"explanation": "one plain-English sentence", "fix": "corrected ZPL"}'
        )
        try:
            raw_ai = ai_client.complete(
                system="You are a ZPL syntax assistant. Return only valid JSON.",
                messages=[{"role": "user", "content": explain_prompt}],
                max_tokens=512,
                temperature=0.1,
            )
            text = _re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_ai.strip(), flags=_re.DOTALL).strip()
            result = _json.loads(text)
            return {
                "action": "explain",
                "reply": result.get("explanation", "There's a syntax error in your ZPL."),
                "suggested_fix": result.get("fix", ""),
            }
        except Exception:
            return {"action": "explain",
                    "reply": "There's a syntax error — please check your ZPL statement.",
                    "suggested_fix": ""}

    # Natural language → classify intent then act
    classes_ctx = "Built-in roots: users, endpoints, services, servers"
    if req.zpl_so_far.strip():
        try:
            raw_ps = zpl_parser.parse(req.zpl_so_far)
            ps, _ = norm.zpl_to_policy_set(raw_ps)
            classes_ctx = _classes_context(ps)
        except Exception:
            pass

    nl_prompt = (
        "You are a ZPL (Zero-trust Policy Language) assistant. Determine what the user wants:\n"
        "- 'generate': add one or more new ZPL statements\n"
        "- 'modify': change or delete existing ZPL (e.g. remove a rule, rename a class)\n"
        "- 'answer': answer a question about the policy without changing it\n\n"
        f"Known classes:\n{classes_ctx}\n\n"
        f"Current ZPL:\n---\n{req.zpl_so_far or '(empty)'}\n---\n\n"
        f"User: {msg}\n\n"
        "ZPL syntax reference:\n"
        "- Define: `Define <Name> as a <parent> with <attrs>.` (parent: users, endpoints, services, servers)\n"
        "  attrs: `optional tags <n>, <n>`, `multiple <n>`, `optional <n>`, `<n>:<v>`\n"
        "- Allow: `Allow [<tag>...] <Class> [on [<tag>...] <End>] to <verb> [<tag>...] <Obj>.`\n"
        "- Never allow: same shape, starts with `Never allow`\n"
        "- Every statement ends with a period.\n\n"
        "Important rules for 'modify':\n"
        "- When deleting a class, also remove every rule that references that class.\n"
        "- When renaming a class, update every rule that references the old name.\n"
        "- Return the complete updated ZPL with no orphaned class references.\n\n"
        "Return JSON only — one of:\n"
        '  {"intent":"generate","statement":"ZPL statement(s)","reply":"brief explanation"}\n'
        '  {"intent":"modify","new_zpl":"complete updated ZPL text","reply":"what you changed"}\n'
        '  {"intent":"answer","reply":"your answer"}'
    )
    try:
        raw_ai = ai_client.complete(
            system="You are a ZPL policy assistant. Return only valid JSON.",
            messages=[{"role": "user", "content": nl_prompt}],
            max_tokens=1024,
            temperature=0.3,
        )
        text = _re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_ai.strip(), flags=_re.DOTALL).strip()
        result = _json.loads(text)
        intent = result.get("intent", "generate")

        if intent == "answer":
            return {"action": "answer", "reply": result.get("reply", "I'm not sure.")}

        if intent == "modify":
            return {
                "action": "modify",
                "new_zpl": result.get("new_zpl", req.zpl_so_far),
                "reply": result.get("reply", "Here's the modified ZPL."),
            }

        # generate (default)
        stmt = result.get("statement", "")
        reply = result.get("reply", "Generated.")
        if stmt and zpl_parser.parse(stmt).get("errors"):
            reply += " (Note: please review the generated ZPL)"
        return {"action": "generate", "statement": stmt, "reply": reply}

    except Exception:
        return {"action": "error",
                "reply": "Could not process your request. Try again or write the ZPL directly."}


# ── Adversarial test generation ───────────────────────────────────────────────

class AdversarialRequest(BaseModel):
    n_positive: int = 8
    n_adversarial: int = 8


@app.post("/api/tests/adversarial")
async def generate_adversarial(req: AdversarialRequest, session: dict = Depends(get_session)):
    if not ai_client.available():
        raise HTTPException(503, "ANTHROPIC_API_KEY not set")

    # Merge ZPL from active namespace + all descendants → engine + schema
    ps_parsed = await _merged_policy_set(session["active_user_id"])
    if not ps_parsed:
        raise HTTPException(422, "No rules found in this namespace or its descendants")

    schema = _build_schema(ps_parsed)
    rules_compiled = []
    for s in ps_parsed.rules:
        try:
            rules_compiled.append(Rule.from_dict({
                "id": s.id, "name": s.name,
                "result": "never" if s.effect == "deny" else "allow",
                "priority": s.priority, "verb": s.action,
                "subject": _subject_to_zpl_dict(s.subject),
                "object": _object_to_zpl_dict(s.object),
                "accessor_endpoint": _subject_to_zpl_dict(s.accessor_endpoint),
                "server_endpoint": _object_to_zpl_dict(s.server_endpoint),
            }))
        except Exception:
            continue
    engine = ZPLEngine(rules_compiled, schema)

    # Build positive tests from merged policy
    allow_rules = [r for r in ps_parsed.rules if r.effect == "allow"]
    deny_rules  = [r for r in ps_parsed.rules if r.effect == "deny"]
    _random.shuffle(allow_rules)
    selected = allow_rules[:req.n_positive]

    positive_tests: list[dict] = []
    for i, rule in enumerate(selected):
        positive_tests.append({
            "number": i + 1,
            "expected": "allow",
            "payload": _base_payload(rule),
        })
    for i, rule in enumerate(deny_rules):
        positive_tests.append({
            "number": len(selected) + i + 1,
            "expected": "deny",
            "payload": _base_payload(rule),
        })

    # Generate adversarial mutations programmatically
    mutations: list[dict] = []
    if req.n_adversarial > 0:
        mutations = _generate_mutations(allow_rules, deny_rules, schema, engine, req.n_adversarial)

    # Build title-polishing input for AI
    title_input = [
        {"number": t["number"], "type": t["expected"],
         "description": _payload_description(t["payload"])}
        for t in positive_tests
    ] + [
        {"number": 1000 + i, "type": "adversarial",
         "description": _payload_description(m["payload"]),
         "mutation_hint": m["mutation_hint"]}
        for i, m in enumerate(mutations)
    ]

    prompt_content = await db.get_prompt("title_polish")
    if prompt_content is None:
        path = _PROMPTS_DIR / "title_polish.md"
        prompt_content = path.read_text() if path.exists() else (
            "Return JSON: {\"tests\":[{\"number\":1,\"title\":\"polished title\"}]}\n\n{tests_json}"
        )
    prompt = prompt_content.replace("{tests_json}", _json.dumps(title_input, indent=2))

    try:
        raw_text = ai_client.complete(
            system="You are a ZPL policy test title writer. Return only valid JSON.",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048,
            temperature=0.4,
        )
    except Exception as exc:
        raise HTTPException(500, f"AI call failed: {exc}")

    text = raw_text.strip()
    text = _re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=_re.DOTALL).strip()
    try:
        ai_result = _json.loads(text)
    except Exception as exc:
        raise HTTPException(500, f"Could not parse AI response: {exc}")

    title_map = {t["number"]: t["title"] for t in (ai_result.get("tests") or [])}

    positive_out = [
        {**t, "title": title_map.get(t["number"], _payload_description(t["payload"]))}
        for t in positive_tests
    ]
    counter_out = [
        {
            "payload": m["payload"],
            "title": title_map.get(1000 + i, _payload_description(m["payload"])),
            "mutation_hint": m["mutation_hint"],
            "verified": True,
            "actual_verdict": "deny",
        }
        for i, m in enumerate(mutations)
    ]

    return {
        "positive_tests": positive_out,
        "counter_tests": counter_out,
        "discarded_adversarial": 0,
    }


@app.get("/api/context")
async def get_context(session: dict = Depends(get_session)):
    return {
        "login_user_id":       session["login_user_id"],
        "login_username":      session["login_username"],
        "login_display_name":  session.get("login_display_name", session["login_username"]),
        "active_user_id":      session["active_user_id"],
        "active_username":     session["active_username"],
        "active_display_name": session.get("active_display_name", session["active_username"]),
    }


class SwitchContextRequest(BaseModel):
    user_id: str


@app.post("/api/context/switch")
async def switch_context(req: SwitchContextRequest, request: Request,
                         session: dict = Depends(get_session)):
    """Switch active context to a descendant owner."""
    if not await db.can_switch_to(session["login_user_id"], req.user_id):
        raise HTTPException(403, "You may only switch to owners you created")
    target = await db.get_user_by_id(req.user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    tdn = target.get("display_name") or target["username"]
    token = _make_session(session["login_user_id"], session["login_username"],
                          session.get("login_display_name", session["login_username"]),
                          target["id"], target["username"], tdn)
    resp = JSONResponse({"active_user_id": target["id"], "active_username": target["username"],
                         "active_display_name": tdn})
    resp.set_cookie("session", token, httponly=True, samesite="lax")
    return resp


@app.post("/api/context/reset")
async def reset_context(request: Request, session: dict = Depends(get_session)):
    """Switch back to the login owner."""
    ldn = session.get("login_display_name", session["login_username"])
    token = _make_session(session["login_user_id"], session["login_username"], ldn,
                          session["login_user_id"], session["login_username"], ldn)
    resp = JSONResponse({"active_user_id": session["login_user_id"],
                         "active_username": session["login_username"],
                         "active_display_name": ldn})
    resp.set_cookie("session", token, httponly=True, samesite="lax")
    return resp


# ── Namespace ZPL ────────────────────────────────────────────────────────────

@app.get("/api/namespace/zpl")
async def get_namespace_zpl(session: dict = Depends(get_session)):
    text = await db.get_namespace_zpl(session["active_user_id"]) or ""
    ns = ns_mod.active_ns(session)
    if text and ns:
        try:
            raw = zpl_parser.parse(text)
            ps, _ = norm.zpl_to_policy_set(raw, name="ns")
            pd = ns_mod.strip(ps.model_dump(mode="json"), ns)
            text = (
                zpl_serializer.classes_to_zpl(pd.get("classes", [])) + "\n\n" +
                zpl_serializer.rules_to_zpl(pd.get("rules", []))
            ).strip()
        except Exception:
            pass  # return raw text if stripping fails
    return {"text": text}


class SaveNamespaceZplRequest(BaseModel):
    text: str


@app.put("/api/namespace/zpl")
async def save_namespace_zpl(req: SaveNamespaceZplRequest, session: dict = Depends(get_session)):
    text = req.text
    ns = ns_mod.active_ns(session)
    if text.strip() and ns:
        try:
            raw = zpl_parser.parse(text)
            ps, errors = norm.zpl_to_policy_set(raw, name="ns")
            if not errors:
                pd = ns_mod.inject(ps.model_dump(mode="json"), ns)
                text = (
                    zpl_serializer.classes_to_zpl(pd.get("classes", [])) + "\n\n" +
                    zpl_serializer.rules_to_zpl(pd.get("rules", []))
                ).strip()
        except Exception:
            pass  # store raw text if injection fails
    await db.save_namespace_zpl(session["active_user_id"], text)
    return {"ok": True}


# ── Parse ─────────────────────────────────────────────────────────────────────

class ParseRequest(BaseModel):
    text: str
    language: str = "zpl"   # "zpl" | "zpel"
    name: str = "Untitled"


@app.post("/api/parse")
async def parse_text(req: ParseRequest, session: dict = Depends(get_session)):
    lang = req.language.lower()
    if lang == "zpl":
        raw = zpl_parser.parse(req.text)
        ps, errors = norm.zpl_to_policy_set(raw, name=req.name)
        inferred = zpl_parser.infer_missing_classes(raw)
        inferred_zpl = zpl_parser.inferred_to_zpl(inferred) if inferred else ""
        inferred_verbs = zpl_parser.infer_missing_verbs(raw)
        inferred_verbs_zpl = "\n".join(f"Define {v} as a verb." for v in inferred_verbs)
    elif lang == "zpel":
        raw = zpel_parser.parse(req.text)
        ps, errors = norm.zpel_to_policy_set(raw, name=req.name)
        inferred = []
        inferred_zpl = ""
        inferred_verbs = []
        inferred_verbs_zpl = ""
    else:
        raise HTTPException(400, f"Unknown language: {req.language!r}")

    pd = ps.model_dump(mode="json")
    ns = ns_mod.active_ns(session)
    ns_pd = ns_mod.inject(pd, ns) if ns else pd
    serialized_zpl = (
        zpl_serializer.classes_to_zpl(ns_pd.get("classes", [])) + "\n\n" +
        zpl_serializer.rules_to_zpl(ns_pd.get("rules", []))
    ).strip()

    return {
        "language": lang,
        "policy_set": pd,
        "errors": [e.model_dump() for e in errors],
        "inferred_classes": inferred,
        "inferred_zpl": inferred_zpl,
        "inferred_verbs": inferred_verbs,
        "inferred_verbs_zpl": inferred_verbs_zpl,
        "serialized_zpl": serialized_zpl,
    }


@app.post("/api/validate")
async def validate_text(req: ParseRequest, _: dict = Depends(get_session)):
    lang = req.language.lower()
    if lang == "zpl":
        raw = zpl_parser.parse(req.text)
        errors = raw.get("errors", [])
    elif lang == "zpel":
        raw = zpel_parser.parse(req.text)
        errors = raw.get("errors", [])
    else:
        raise HTTPException(400, f"Unknown language: {req.language!r}")
    return {"language": lang, "errors": errors, "valid": len(errors) == 0}


# ── .zplc import ─────────────────────────────────────────────────────────────

@app.post("/api/zplc/import")
async def import_zplc(file: UploadFile = File(...), _: dict = Depends(get_session)):
    content = await file.read()
    try:
        data = tomllib.loads(content.decode())
    except Exception as exc:
        raise HTTPException(400, f"Invalid .zplc file: {exc}")

    services = list(data.get("services", {}).keys())
    trusted = list(data.get("trusted_services", {}).keys())
    all_names = sorted(set(services + trusted))

    inferred_classes = [{"class": name} for name in all_names]
    inferred_zpl = "\n".join(f"define {name} as a service." for name in all_names)

    return {
        "inferred_classes": inferred_classes,
        "inferred_zpl": inferred_zpl,
        "services": services,
        "trusted_services": trusted,
    }


# ── Translate ─────────────────────────────────────────────────────────────────

class TranslateRequest(BaseModel):
    policy_set: dict
    target: str   # "zpl" | "zpel"


@app.post("/api/translate")
async def translate(req: TranslateRequest, _: dict = Depends(get_session)):
    try:
        ps = PolicySet.model_validate(req.policy_set)
    except Exception as exc:
        raise HTTPException(400, f"Invalid PolicySet: {exc}")

    target = req.target.lower()
    if target == "zpl":
        text = _policy_set_to_zpl(ps)
    elif target == "zpel":
        text = zpel_ser.policy_set_to_zpel(ps)
    else:
        raise HTTPException(400, f"Unknown target: {req.target!r}")

    untranslatable = []
    if target == "zpel":
        untranslatable = [
            {"id": s.id, "name": s.name}
            for s in zpel_ser.untranslatable_statements(ps)
        ]

    return {"target": target, "text": text, "untranslatable": untranslatable}


def _policy_set_to_zpl(ps: PolicySet) -> str:
    raw_classes = [
        {
            "class": c.name,
            "parent": c.parent,
            "aka": c.aka,
            "builtin": c.builtin,
            "attributes": {
                k: v.model_dump(exclude_none=True)
                for k, v in c.attributes.items()
            },
        }
        for c in ps.classes
    ]
    raw_rules = []
    for s in ps.rules:
        raw_rules.append({
            "id": s.id,
            "name": s.name,
            "result": "never" if s.effect == "deny" else "allow",
            "priority": s.priority,
            "verb": s.action,
            "subject": _subject_to_zpl_dict(s.subject),
            "accessor_endpoint": _subject_to_zpl_dict(s.accessor_endpoint),
            "object": _object_to_zpl_dict(s.object),
            "server_endpoint": _object_to_zpl_dict(s.server_endpoint),
        })
    classes_text = zpl_serializer.classes_to_zpl(raw_classes)
    rules_text = zpl_serializer.rules_to_zpl(raw_rules)
    parts = [p for p in [classes_text, rules_text] if p.strip()]
    return "\n\n".join(parts)


def _subject_to_zpl_dict(spec: SubjectSpec | None) -> dict | None:
    if not spec:
        return None
    out: dict = {}
    if spec.cls:
        out["class"] = spec.cls
    if spec.name:
        out["name"] = spec.name
    if spec.attrs:
        out["attrs"] = spec.attrs
    return out or None


def _object_to_zpl_dict(spec: ObjectSpec | None) -> dict | None:
    if not spec:
        return None
    out: dict = {}
    if spec.cls:
        out["class"] = spec.cls
    if spec.name:
        out["name"] = spec.name
    if spec.attrs:
        out["attrs"] = spec.attrs
    return out or None


# ── Simulate — merges ALL namespaces ─────────────────────────────────────────

class SimRequest(BaseModel):
    scenarios: list[dict]


@app.post("/api/simulate/{policy_set_id}")
async def simulate(
    policy_set_id: str,
    req: SimRequest,
    session: dict = Depends(get_session),
):
    # Verify the requested policy set exists in the active namespace
    ps = await db.get_policy_set(policy_set_id, session["active_user_id"])
    if ps is None:
        raise HTTPException(404, "Policy set not found")

    # Merge classes and rules from ALL namespaces for evaluation
    all_sets = await db.list_all_policy_sets()
    merged = PolicySet(name="_merged", language="zpl")
    for s in all_sets:
        merged.classes.extend(s.classes)
        merged.rules.extend(s.rules)

    results = []
    for scenario_data in req.scenarios:
        try:
            scenario = SimScenario.model_validate(scenario_data)
        except Exception as exc:
            results.append({"error": str(exc)})
            continue

        if ps.language == "zpel":
            result = _simulate_zpel(merged, scenario)
        else:
            result = _simulate_zpl(merged, scenario)
        results.append(result.model_dump(mode="json"))

    return {"results": results}


_SYSTEM_CLASSES_PATH = Path(__file__).parent / "defaults" / "system_classes.yaml"


def _build_schema(ps: PolicySet) -> ClassSchema:
    import yaml
    system = yaml.safe_load(_SYSTEM_CLASSES_PATH.read_text())
    system_classes = system.get("classes", [])
    user_classes_raw = [
        {
            "class": c.name,
            "parent": c.parent,
            "aka": c.aka,
            "builtin": c.builtin,
            "attributes": {k: v.model_dump(exclude_none=True) for k, v in c.attributes.items()},
        }
        for c in ps.classes
    ]
    system_names = {c["class"] for c in system_classes}
    # Iteratively add user classes whose parents are already known, skipping orphans.
    known: set[str] = set(system_names)
    candidates = [c for c in user_classes_raw if c["class"] not in system_names]
    valid: list[dict] = []
    changed = True
    while changed:
        changed = False
        remaining = []
        for c in candidates:
            parent = c.get("parent")
            if not parent or parent in known:
                valid.append(c)
                known.add(c["class"])
                changed = True
            else:
                remaining.append(c)
        candidates = remaining
    return ClassSchema(system_classes + valid)


def _simulate_zpl(ps: PolicySet, scenario: SimScenario) -> SimResult:
    try:
        schema = _build_schema(ps)
    except Exception as exc:
        return SimResult(
            scenario_id=scenario.id, description=scenario.description,
            verdict="deny", reason=f"Schema error: {exc}",
        )

    rules = []
    for s in ps.rules:
        try:
            rules.append(Rule.from_dict({
                "id": s.id,
                "name": s.name,
                "result": "never" if s.effect == "deny" else "allow",
                "priority": s.priority,
                "verb": s.action,
                "subject": _subject_to_zpl_dict(s.subject),
                "object": _object_to_zpl_dict(s.object),
                "accessor_endpoint": _subject_to_zpl_dict(s.accessor_endpoint),
                "server_endpoint": _object_to_zpl_dict(s.server_endpoint),
            }))
        except Exception:
            continue

    subj_d = _subject_to_zpl_dict(scenario.subject) or {}
    obj_d  = _object_to_zpl_dict(scenario.object)   or {}

    request = CheckRequest(
        subject=Entity(
            class_name=subj_d.get("class", "users"),
            name=subj_d.get("name"),
            attrs=subj_d.get("attrs") or {},
        ),
        object=Entity(
            class_name=obj_d.get("class", "services"),
            name=obj_d.get("name"),
            attrs=obj_d.get("attrs") or {},
        ),
        verb=scenario.action,
    )

    try:
        engine = ZPLEngine(rules, schema)
        result = engine.evaluate(request)
    except Exception as exc:
        return SimResult(
            scenario_id=scenario.id, description=scenario.description,
            verdict="deny", reason=f"Engine error: {exc}",
        )

    return SimResult(
        scenario_id=scenario.id,
        description=scenario.description,
        verdict=result.verdict,
        matched_statement_id=result.rule_id,
        matched_statement_name=result.rule_name or "",
        reason=f"Matched rule '{result.rule_name}'" if result.rule_id else "No matching rule",
    )


def _simulate_zpel(ps: PolicySet, scenario: SimScenario) -> SimResult:
    vcn = scenario.conditions.vcn_scope if scenario.conditions else None
    src_attr = scenario.subject.attribute if scenario.subject else None
    dst_attr = scenario.object.attribute if scenario.object else None
    proto = scenario.conditions.protocol if scenario.conditions else None

    for stmt in sorted(ps.rules, key=lambda s: -s.priority):
        if stmt.effect != "allow":
            continue
        cond = stmt.conditions or Conditions()
        if cond.vcn_scope and vcn and cond.vcn_scope.lower() != vcn.lower():
            continue
        subj = stmt.subject
        obj = stmt.object
        if subj and subj.attribute and src_attr:
            if subj.attribute.lower() != src_attr.lower():
                continue
        if obj and obj.attribute and dst_attr:
            if obj.attribute.lower() != dst_attr.lower():
                continue
        if cond.protocol and proto:
            if cond.protocol.lower() != proto.lower():
                continue
        return SimResult(
            scenario_id=scenario.id,
            description=scenario.description,
            verdict="allow",
            matched_statement_id=stmt.id,
            matched_statement_name=stmt.name,
            reason=f"Matched statement '{stmt.name}'",
        )

    return SimResult(
        scenario_id=scenario.id,
        description=scenario.description,
        verdict="deny",
        reason="No matching allow statement",
    )


# ── Policy set CRUD ───────────────────────────────────────────────────────────

@app.get("/api/policy_sets")
async def list_policy_sets(session: dict = Depends(get_session)):
    return await db.list_policy_sets(session["active_user_id"])


@app.post("/api/policy_sets", status_code=201)
async def create_policy_set(data: dict, session: dict = Depends(get_session)):
    try:
        ps = PolicySet.model_validate(data)
    except Exception as exc:
        raise HTTPException(400, f"Invalid PolicySet: {exc}")
    ps = await db.save_policy_set(ps, session["active_user_id"])
    return ps.model_dump(mode="json")


@app.get("/api/policy_sets/{policy_set_id}")
async def get_policy_set(policy_set_id: str, session: dict = Depends(get_session)):
    ps = await db.get_policy_set(policy_set_id, session["active_user_id"])
    if ps is None:
        raise HTTPException(404, "Not found")
    return ps.model_dump(mode="json")


@app.put("/api/policy_sets/{policy_set_id}")
async def update_policy_set(
    policy_set_id: str, data: dict, session: dict = Depends(get_session)
):
    existing = await db.get_policy_set(policy_set_id, session["active_user_id"])
    if existing is None:
        raise HTTPException(404, "Not found")
    try:
        ps = PolicySet.model_validate({**data, "id": policy_set_id})
    except Exception as exc:
        raise HTTPException(400, f"Invalid PolicySet: {exc}")
    ps = await db.save_policy_set(ps, session["active_user_id"])
    return ps.model_dump(mode="json")


@app.delete("/api/policy_sets/{policy_set_id}", status_code=204)
async def delete_policy_set(policy_set_id: str, session: dict = Depends(get_session)):
    deleted = await db.delete_policy_set(policy_set_id, session["active_user_id"])
    if not deleted:
        raise HTTPException(404, "Not found")


# ── Agent chat ────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    conversation_id: str | None = None
    policy_set_id: str | None = None
    policy_set_name: str = "Untitled"
    language: str = "zpl"


@app.post("/api/chat")
async def chat(req: ChatRequest, session: dict = Depends(get_session)):
    from ai_client import available

    if not available():
        raise HTTPException(503, "ANTHROPIC_API_KEY not configured")

    user_id = session["active_user_id"]

    conv: Conversation
    if req.conversation_id:
        conv = await db.get_conversation(req.conversation_id, user_id) or Conversation()
    else:
        conv = Conversation()

    if req.policy_set_id:
        conv.policy_set_id = req.policy_set_id

    conv.messages.append(ChatMessage(role="user", content=req.message))

    history = [{"role": m.role, "content": m.content} for m in conv.messages]
    reply_text, policy_set = agent_mod.chat(history, language=req.language)

    conv.messages.append(ChatMessage(role="assistant", content=reply_text))
    conv = await db.save_conversation(conv, user_id)

    saved_ps = None
    if policy_set is not None:
        if conv.policy_set_id:
            policy_set.id = conv.policy_set_id
            existing = await db.get_policy_set(conv.policy_set_id, user_id)
            if existing:
                policy_set.name = existing.name
        else:
            policy_set.name = req.policy_set_name
        saved_ps = await db.save_policy_set(policy_set, user_id)
        conv.policy_set_id = saved_ps.id
        await db.save_conversation(conv, user_id)

    return {
        "conversation_id": conv.id,
        "reply": reply_text,
        "policy_set_id": conv.policy_set_id,
        "policy_set": saved_ps.model_dump(mode="json") if saved_ps else None,
    }


@app.get("/api/conversations/{conv_id}")
async def get_conversation(conv_id: str, session: dict = Depends(get_session)):
    conv = await db.get_conversation(conv_id, session["active_user_id"])
    if conv is None:
        raise HTTPException(404, "Not found")
    return conv.model_dump(mode="json")


# ── Language setting ──────────────────────────────────────────────────────────

_active_language: str = "zpl"


@app.get("/api/language")
async def get_language(_: dict = Depends(get_session)):
    return {"language": _active_language}


class LanguageRequest(BaseModel):
    language: str


@app.post("/api/language")
async def set_language(req: LanguageRequest, _: dict = Depends(get_session)):
    global _active_language
    lang = req.language.lower()
    if lang not in ("zpl", "zpel"):
        raise HTTPException(400, f"Language must be 'zpl' or 'zpel', got {lang!r}")
    _active_language = lang
    return {"language": _active_language}


# ── Build assistant (class & rule builder) ────────────────────────────────────

_CLASS_AGENT_PROMPT = Path(__file__).parent / "prompts" / "class_agent.md"
_RULE_AGENT_PROMPT  = Path(__file__).parent / "prompts" / "rule_agent.md"


def _classes_context(ps: PolicySet | None) -> str:
    roots = {"users", "endpoints", "services"}
    if not ps or not ps.classes:
        return "None yet — only the built-in roots: users, endpoints, services."
    lines = ["Built-in roots: users, endpoints, services", ""]
    for c in ps.classes:
        attrs = []
        for k, spec in (c.attributes or {}).items():
            if spec.type == "multi":
                vals = ",".join(spec.values[:4]) + ("…" if len(spec.values) > 4 else "")
                attrs.append(f"{k}:multi[{vals}]")
            elif spec.type == "enum":
                vals = ",".join(spec.values[:4]) + ("…" if len(spec.values) > 4 else "")
                attrs.append(f"{k}:enum[{vals}]")
            else:
                attrs.append(f"{k}:single")
        attr_str = "  —  " + ", ".join(attrs) if attrs else ""
        lines.append(f"  {c.name} (extends {c.parent}){attr_str}")
    return "\n".join(lines)


class AssistRequest(BaseModel):
    mode: str
    messages: list[dict[str, str]]
    policy_set_id: str | None = None


class AssistAcceptRequest(BaseModel):
    mode: str
    proposal: dict
    policy_set_id: str | None = None
    policy_set_name: str = "Untitled"


@app.post("/api/assist")
async def assist(req: AssistRequest, session: dict = Depends(get_session)):
    from ai_client import complete, extract_json_blocks, strip_tagged_blocks

    ps: PolicySet | None = None
    if req.policy_set_id:
        try:
            ps = await db.get_policy_set(req.policy_set_id, session["active_user_id"])
        except Exception:
            pass

    ctx = _classes_context(ps)

    if req.mode == "class":
        template = _CLASS_AGENT_PROMPT.read_text()
        system = template.replace("{classes_context}", ctx)
        tag = "PROPOSED_CLASS"
    else:
        template = _RULE_AGENT_PROMPT.read_text()
        system = template.replace("{classes_context}", ctx)
        tag = "PROPOSED_RULE"

    raw = complete(system=system, messages=req.messages, max_tokens=1024, temperature=0.2)

    proposal = None
    blocks = extract_json_blocks(raw, tag)
    if blocks:
        proposal = blocks[-1]
        if req.mode == "rule" and "zpl" not in proposal:
            effect = "Allow" if proposal.get("effect") == "allow" else "Never allow"
            proposal["zpl"] = f"{effect} [see rule details]"

    reply = strip_tagged_blocks(raw, tag).strip()
    return {"reply": reply, "proposal": proposal}


@app.post("/api/assist/accept")
async def assist_accept(req: AssistAcceptRequest, session: dict = Depends(get_session)):
    from ir_schema import AttributeSpec, ClassDefinition, PolicyStatement

    user_id = session["active_user_id"]
    ps: PolicySet | None = None
    if req.policy_set_id:
        try:
            ps = await db.get_policy_set(req.policy_set_id, user_id)
        except Exception:
            pass
    if ps is None:
        ps = PolicySet(name=req.policy_set_name, language="zpl")

    if req.mode == "class":
        raw_attrs = req.proposal.get("attributes") or {}
        attributes: dict[str, AttributeSpec] = {}
        for k, v in raw_attrs.items():
            if isinstance(v, dict):
                attr_type = v.get("type", "single")
                if attr_type not in ("single", "enum", "multi"):
                    attr_type = "single"
                attributes[k] = AttributeSpec(
                    type=attr_type,
                    value=v.get("value"),
                    values=v.get("values") or [],
                )
            elif isinstance(v, str):
                attributes[k] = AttributeSpec(type="single", value=v)
        cls = ClassDefinition(
            name=req.proposal.get("name", "unnamed"),
            parent=req.proposal.get("parent", "users"),
            aka=req.proposal.get("aka"),
            attributes=attributes,
            description=req.proposal.get("description", ""),
        )
        ps.classes = [c for c in ps.classes if c.name != cls.name] + [cls]

    else:
        from agent import _parse_spec_subject, _parse_spec_object
        from ir_schema import Conditions
        s = req.proposal
        subj = _parse_spec_subject(s.get("subject") or {})
        obj  = _parse_spec_object(s.get("object") or {})
        cond_data = s.get("conditions") or {}
        effect = s.get("effect", "allow")
        if effect not in ("allow", "deny"):
            effect = "allow"
        stmt = PolicyStatement(
            name=s.get("name", ""),
            description=s.get("description", s.get("zpl", "")),
            effect=effect,
            priority=s.get("priority", 100),
            action=s.get("action", "access"),
            subject=subj if subj else None,
            object=obj if obj else None,
            conditions=Conditions(**cond_data) if cond_data else Conditions(),
            source_language="natural",
        )
        ps.rules = [r for r in ps.rules if r.name != stmt.name] + [stmt]

    ps = await db.save_policy_set(ps, user_id)
    return {"policy_set": ps.model_dump(mode="json"), "policy_set_id": ps.id}


class GenerateRulesRequest(BaseModel):
    n_allow: int = 3
    n_deny: int = 2
    focus_on: str = ""
    policy_set_id: str | None = None


@app.post("/api/assist/generate-rules")
async def assist_generate_rules(req: GenerateRulesRequest, session: dict = Depends(get_session)):
    from ai_client import complete, extract_json_blocks, strip_tagged_blocks

    user_id = session["active_user_id"]
    ps: PolicySet | None = None
    if req.policy_set_id:
        try:
            ps = await db.get_policy_set(req.policy_set_id, user_id)
        except Exception:
            pass

    ctx = _classes_context(ps)
    focus_line = f"\nFocus especially on: {req.focus_on.strip()}" if req.focus_on.strip() else ""

    system = (Path(__file__).parent / "prompts" / "rule_agent.md").read_text().replace("{classes_context}", ctx)

    user_msg = (
        f"Generate exactly {req.n_allow} allow rule(s) and {req.n_deny} deny rule(s) "
        f"using the classes defined above.{focus_line} "
        f"Emit each as a separate <PROPOSED_RULE> block with no other text between blocks."
    )

    raw = complete(system=system, messages=[{"role": "user", "content": user_msg}],
                   max_tokens=2048, temperature=0.4)

    proposals = extract_json_blocks(raw, "PROPOSED_RULE")
    for p in proposals:
        if "zpl" not in p:
            effect = "Allow" if p.get("effect") == "allow" else "Never allow"
            p["zpl"] = f"{effect} [see rule details]"

    return {"proposals": proposals}


# ── SPA ───────────────────────────────────────────────────────────────────────

@app.get("/v2", response_class=HTMLResponse)
async def spa_v2(request: Request):
    if not _check_session(request):
        return Response(status_code=302, headers={"Location": "/login"})
    ui = STATIC_DIR / "ui_v2.html"
    if ui.exists():
        return HTMLResponse(ui.read_text())
    return HTMLResponse("<h1>ZPR Policy Maker v2 UI not found</h1>")


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa(request: Request, full_path: str):
    if not _check_session(request):
        return Response(status_code=302, headers={"Location": "/login"})
    index = STATIC_DIR / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>ZPR Policy Maker v3</h1><p>Place index.html in static/</p>")


# ── Login / Setup HTML ────────────────────────────────────────────────────────

def _login_html(error: bool = False) -> str:
    err = '<p class="err">Incorrect username or password.</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ZPR Policy Maker — Login</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
           display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
    .box {{ background: #1e293b; padding: 2rem; border-radius: 0.75rem; width: 320px; }}
    h1 {{ margin: 0 0 0.25rem; font-size: 1.25rem; }}
    p.sub {{ color: #94a3b8; font-size: 0.85rem; margin: 0 0 1.5rem; }}
    p.err {{ color: #f87171; font-size: 0.85rem; margin: 0 0 1rem; }}
    input {{ width: 100%; box-sizing: border-box; padding: 0.6rem 0.75rem; border-radius: 0.5rem;
             border: 1px solid #334155; background: #0f172a; color: #e2e8f0;
             font-size: 1rem; margin-bottom: 1rem; }}
    button {{ width: 100%; padding: 0.6rem; border-radius: 0.5rem; border: none;
              background: #3b82f6; color: white; font-size: 1rem; cursor: pointer; }}
    button:hover {{ background: #2563eb; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>ZPR Policy Maker</h1>
    <p class="sub">Sign in to your namespace</p>
    {err}
    <form method="post" action="/login">
      <input type="text" name="username" placeholder="Username" autofocus autocomplete="username">
      <input type="password" name="password" placeholder="Password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>"""


def _setup_html(error: str = "") -> str:
    err = f'<p class="err">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ZPR Policy Maker — First-run Setup</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
           display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
    .box {{ background: #1e293b; padding: 2rem; border-radius: 0.75rem; width: 340px; }}
    h1 {{ margin: 0 0 0.25rem; font-size: 1.25rem; }}
    p.sub {{ color: #94a3b8; font-size: 0.85rem; margin: 0 0 1.5rem; }}
    p.err {{ color: #f87171; font-size: 0.85rem; margin: 0 0 1rem; }}
    label {{ display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.25rem; }}
    input {{ width: 100%; box-sizing: border-box; padding: 0.6rem 0.75rem; border-radius: 0.5rem;
             border: 1px solid #334155; background: #0f172a; color: #e2e8f0;
             font-size: 1rem; margin-bottom: 1rem; }}
    button {{ width: 100%; padding: 0.6rem; border-radius: 0.5rem; border: none;
              background: #3b82f6; color: white; font-size: 1rem; cursor: pointer; }}
    button:hover {{ background: #2563eb; }}
    .note {{ font-size: 0.8rem; color: #64748b; margin-top: 1rem; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>Welcome to ZPR Policy Maker</h1>
    <p class="sub">Create your root namespace owner to get started.</p>
    {err}
    <form method="post" action="/setup">
      <label>Username (this becomes your namespace name)</label>
      <input type="text" name="username" placeholder="e.g. admin" autofocus autocomplete="off">
      <label>Password</label>
      <input type="password" name="password" placeholder="Choose a password" autocomplete="new-password">
      <button type="submit">Create account</button>
    </form>
    <p class="note">This page is only available when no accounts exist.</p>
  </div>
</body>
</html>"""
