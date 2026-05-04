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

# ── Class name cache ─────────────────────────────────────────────────────────
# Keyed by root_ns_id → set of fully-qualified class names from all stored ZPL
# in that namespace tree. Invalidated on every ZPL save or namespace structural
# change, rebuilt lazily on next parse.

_class_cache: dict[str, set[str]] = {}


def _cache_invalidate(root_ns_id: str) -> None:
    _class_cache.pop(root_ns_id, None)


def _cache_remove(root_ns_id: str, fq_class_name: str) -> None:
    """Remove a single fully-qualified class name from the cache."""
    if root_ns_id in _class_cache:
        _class_cache[root_ns_id].discard(fq_class_name)


async def _tree_root_ns_id(login_user_id: str) -> str | None:
    """Return the root namespace ID for the tree containing this user's namespaces.
    For users with their own root, that's it. For sub-namespace owners, walk up
    from their first owned namespace to find the tree root."""
    root_ns = await db.get_root_namespace(login_user_id)
    if root_ns:
        return root_ns["id"]
    owned = await db.get_namespaces_owned_by(login_user_id)
    if not owned:
        return None
    # Walk up from first owned namespace to find tree root.
    current = owned[0]
    seen: set[str] = set()
    while current.get("parent_namespace_id") and current["id"] not in seen:
        seen.add(current["id"])
        parent = await db.get_namespace(current["parent_namespace_id"])
        if not parent:
            break
        current = parent
    return current["id"]


async def _known_classes(login_user_id: str) -> set[str]:
    """Return the cached set of fully-qualified class names for the user's tree,
    building it from stored ZPL if not already cached."""
    root_ns_id = await _tree_root_ns_id(login_user_id)
    if not root_ns_id:
        return set()
    root_ns_id = root_ns_id
    if root_ns_id in _class_cache:
        return _class_cache[root_ns_id]

    tree = await db.get_namespace_tree(root_ns_id)

    def _walk(node: dict, ids: list[str]) -> None:
        if node and node.get("id"):
            ids.append(node["id"])
            for child in node.get("children") or []:
                _walk(child, ids)

    ns_ids: list[str] = []
    _walk(tree, ns_ids)
    zpl_map = await db.get_namespace_zpl_batch(ns_ids)

    names: set[str] = set()
    for text in zpl_map.values():
        if text:
            try:
                raw = zpl_parser.parse(text)
                names.update(c["class"] for c in raw.get("classes", []))
            except Exception:
                pass
    _class_cache[root_ns_id] = names
    return names


async def _get_root_ns_id(login_user_id: str) -> str | None:
    return await _tree_root_ns_id(login_user_id)


async def _login_namespace(user_id: str) -> dict | None:
    """Return the namespace to activate on login.
    Prefers the user's root namespace; falls back to the first namespace they own.
    Returns None only if the user owns no namespaces at all."""
    ns = await db.get_root_namespace(user_id)
    if ns:
        return ns
    owned = await db.get_namespaces_owned_by(user_id)
    return owned[0] if owned else None


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
                  active_namespace_id: str, active_display_name: str) -> str:
    return _signer.dumps({
        "authenticated": True,
        "login_user_id": login_user_id,
        "login_username": login_username,
        "login_display_name": login_display_name,
        "active_namespace_id": active_namespace_id,
        "active_display_name": active_display_name,
        # backward compat: active_user_id = active_namespace_id so existing ZPL callers work
        "active_user_id": active_namespace_id,
        "active_username": active_display_name,
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
            ns = await _login_namespace(user["id"])
            if not ns:
                raise HTTPException(status_code=403, detail="No namespace assigned")
            return {
                "authenticated": True,
                "login_user_id": user["id"],
                "login_username": user["username"],
                "login_display_name": dn,
                "active_namespace_id": ns["id"],
                "active_display_name": ns["display_name"],
                "active_user_id": ns["id"],
                "active_username": ns["display_name"],
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
    user = await db.create_user(username, password, is_admin=True)
    dn = user.get("display_name") or user["username"]
    root_ns = await db.get_or_create_root_namespace(user["id"], dn)
    token = _make_session(user["id"], user["username"], dn, root_ns["id"], root_ns["display_name"])
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
    ns = await _login_namespace(user["id"])
    if not ns:
        return HTMLResponse(_login_html(error=True), status_code=403)
    token = _make_session(user["id"], user["username"], dn, ns["id"], ns["display_name"])
    response = Response(status_code=302, headers={"Location": "/"})
    response.set_cookie("session", token, httponly=True, samesite="lax")
    return response


@app.post("/logout")
async def logout():
    response = Response(status_code=302, headers={"Location": "/login"})
    response.delete_cookie("session")
    return response


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


# ── Admin ─────────────────────────────────────────────────────────────────────

async def get_admin_session(session: dict = Depends(get_session)) -> dict:
    user = await db.get_user_by_id(session["login_user_id"])
    if not user or not user.get("is_admin"):
        raise HTTPException(403, "Admin access denied")
    return session


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(session: dict = Depends(get_admin_session)):
    admin_html_path = STATIC_DIR / "admin.html"
    return HTMLResponse(admin_html_path.read_text())


class AdminCreateUserRequest(BaseModel):
    username: str
    password: str
    display_name: str = ""
    email: str = ""
    is_admin: bool = False


class AdminResetPasswordRequest(BaseModel):
    new_password: str


@app.get("/api/admin/users")
async def admin_list_users(_: dict = Depends(get_admin_session)):
    return await db.list_all_users()


@app.post("/api/admin/users", status_code=201)
async def admin_create_user(req: AdminCreateUserRequest,
                            _: dict = Depends(get_admin_session)):
    uname = req.username.strip()
    if not uname:
        raise HTTPException(400, "username is required")
    if not req.password:
        raise HTTPException(400, "password is required")
    existing = await db.get_user_by_username(uname)
    if existing:
        raise HTTPException(409, f"Username '{uname}' already exists")
    dn = req.display_name.strip() or uname
    user = await db.create_user(uname, req.password, display_name=dn, email=req.email.strip(),
                                is_admin=req.is_admin)
    ns = await db.get_or_create_root_namespace(user["id"], dn)
    return {"user": user, "namespace": ns}


@app.post("/api/admin/users/{user_id}/reset-password")
async def admin_reset_password(user_id: str, req: AdminResetPasswordRequest,
                               session: dict = Depends(get_admin_session)):
    if not req.new_password:
        raise HTTPException(400, "new_password is required")
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    await db.update_password(user_id, req.new_password)
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}", status_code=200)
async def admin_delete_user(user_id: str, session: dict = Depends(get_admin_session)):
    if user_id == session["login_user_id"]:
        raise HTTPException(400, "Cannot delete your own account")
    err = await db.delete_user(user_id)
    if err:
        raise HTTPException(400, err)
    return {"ok": True}


class AdminSetAdminRequest(BaseModel):
    is_admin: bool


@app.patch("/api/admin/users/{user_id}/admin")
async def admin_set_admin(user_id: str, req: AdminSetAdminRequest,
                          session: dict = Depends(get_admin_session)):
    if user_id == session["login_user_id"] and not req.is_admin:
        raise HTTPException(400, "Cannot remove your own admin privileges")
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    await db.set_user_admin(user_id, req.is_admin)
    return {"ok": True}


@app.get("/api/admin/namespaces")
async def admin_list_namespaces(_: dict = Depends(get_admin_session)):
    return await db.list_all_namespaces()


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


async def _ancestor_ns_ids(ns_id: str) -> list[str]:
    """Walk up the parent chain and return ancestor namespace IDs (excluding ns_id itself)."""
    ancestors: list[str] = []
    current = await db.get_namespace(ns_id)
    while current:
        parent_id = current.get("parent_namespace_id")
        if not parent_id:
            break
        ancestors.append(parent_id)
        current = await db.get_namespace(parent_id)
    return ancestors


async def _merged_policy_set(root_namespace_id: str) -> PolicySet | None:
    """Parse and merge ZPL from root_namespace_id and all descendant namespaces.

    Also loads ancestor namespace ZPL (classes only, no rules) so that
    cross-namespace parent class references can be resolved by the engine.
    Stored ZPL already has the namespace prefix injected, so no re-injection needed.
    """
    tree = await db.get_namespace_tree(root_namespace_id)
    nodes = _flatten_tree_nodes(tree)
    ns_ids = [n["id"] for n in nodes]

    # Load ancestor ZPL for class hierarchy resolution
    ancestor_ids = await _ancestor_ns_ids(root_namespace_id)
    ancestor_zpl = await db.get_namespace_zpl_batch(ancestor_ids) if ancestor_ids else {}

    zpl_map = await db.get_namespace_zpl_batch(ns_ids)
    merged = PolicySet(name="_merged", language="zpl")

    # Ancestor classes first (so parent refs resolve), but skip their rules
    for uid in ancestor_ids:
        text = ancestor_zpl.get(uid, "").strip()
        if not text:
            continue
        try:
            raw = zpl_parser.parse(text)
            ps, errors = norm.zpl_to_policy_set(raw)
            if not errors:
                merged.classes.extend(ps.classes)
        except Exception:
            pass

    for uid in ns_ids:
        text = zpl_map.get(uid, "").strip()
        if not text:
            continue
        try:
            raw = zpl_parser.parse(text)
            ps, errors = norm.zpl_to_policy_set(raw)
            if errors:
                continue
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
    subj = payload.get("subject_name") or (payload.get("subject_class") or "users").split(".")[-1]
    verb = payload.get("action") or "access"
    obj  = payload.get("object_name") or (payload.get("object_class") or "services").split(".")[-1]
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

    # ZPL-like input: starts with capital Define/Allow/Never and ends with period.
    # Only treat as direct ZPL if it looks like a real statement, not natural language.
    if _re.match(r'^(Define|Allow|Never)\b', msg) and msg.rstrip().endswith('.'):
        raw = zpl_parser.parse(msg)
        errors = raw.get("errors", [])
        if not errors:
            return {"action": "add", "statement": msg, "reply": "Good. Send to Staging."}

        # Has parse errors → AI explains and offers a fix
        errors_text = "\n".join(
            f"  [{e.get('line','?')}] {e.get('message','')} — {e.get('source','')!r}"
            for e in errors
        )
        explain_prompt = (
            f"The user wrote this ZPL statement:\n\n{msg}\n\n"
            f"Parser reported:\n{errors_text}\n\n"
            "ZPL syntax reference:\n"
            "- Define: `Define <Name> as a <parent>.`  or with attrs: `Define <Name> as a <parent> with <attrs>.`\n"
            "  Optional AKA alias: `Define employee AKA employees as a users.`\n"
            "  <parent>: exact class name. Use `.` for cross-namespace (e.g. corp.employee). NEVER `:` as namespace separator.\n"
            "  Classes in THIS namespace use bare names. Cross-namespace refs use dotted names.\n"
            "  Class names may contain hyphens and underscores (e.g. baseball-employee, hr_staff).\n"
            "  Built-in roots: users, endpoints, services, servers (singular also accepted).\n"
            "  attrs: `optional tags <n>, <n>`, `multiple <n>`, `optional <n>`, `<n>:<v>`\n"
            "  Attribute names are NEVER namespace-prefixed.\n"
            "- Allow/Never: `Allow <Class> to <verb> <Obj>.`  `to` always comes before the verb.\n"
            "  Example: `Allow employee to access gitlab.`\n"
            "  Example: `Never allow tags:intern employee to access services.`\n"
            "  Tag filter MUST use `tags:<value>` — bare word before class (e.g. `intern employee`) is a key-presence check, not a tag filter.\n"
            "  attr:value filter: `Never allow backup:nightly servers to access backup-services.`\n"
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
    local_class_names: set[str] = set()
    if req.zpl_so_far.strip():
        try:
            raw_ps = zpl_parser.parse(req.zpl_so_far)
            ps, _ = norm.zpl_to_policy_set(raw_ps)
            classes_ctx = _classes_context(ps)
            local_class_names = {c.name for c in (ps.classes or [])}
        except Exception:
            pass

    tree_classes = await _known_classes(session["login_user_id"])
    cross_ns = sorted(tree_classes - local_class_names)
    cross_ns_ctx = ", ".join(cross_ns) if cross_ns else "none"

    nl_prompt = (
        "You are a ZPL (Zero-trust Policy Language) assistant. Determine what the user wants:\n"
        "- 'generate': add one or more new ZPL statements\n"
        "- 'modify': change or delete existing ZPL (e.g. remove a rule, rename a class)\n"
        "- 'answer': answer a question about the policy without changing it\n\n"
        f"Classes defined in this namespace:\n{classes_ctx}\n\n"
        f"Classes available from other namespaces (MUST use full dotted name — in both Define parents AND rules): {cross_ns_ctx}\n\n"
        f"Current ZPL:\n---\n{req.zpl_so_far or '(empty)'}\n---\n\n"
        f"User: {msg}\n\n"
        "ZPL syntax reference:\n"
        "- Define: `Define <Name> as a <parent>.`  <parent> must be an exact class name — never a description.\n"
        "  AKA alias: `Define employee AKA employees as a users.`  (lets rules use either name)\n"
        "  NAMESPACE PREFIXES: only use dotted names when referencing a class from ANOTHER namespace.\n"
        "    Classes defined IN THIS namespace use bare names — never prefix with the current namespace.\n"
        "    WRONG: `Define hr.contractor as a hr.employee.`  RIGHT: `Define contractor as an employee.`\n"
        "    Cross-ns parent: WRONG: `Define contractor as employee.`  RIGHT: `Define contractor as a corp.employee.`\n"
        "  Attribute names in `with` clauses are NEVER namespace-prefixed.\n"
        "    WRONG: `with hr.team:baseball`  RIGHT: `with team:baseball`\n"
        "  Use `.` for namespace separator — NEVER `:` (colon is attr:value only).\n"
        "  Class names may contain hyphens and underscores (e.g. baseball-employee, hr_staff).\n"
        "  Built-in roots (singular/plural both valid): users, endpoints, services, servers\n"
        "  attrs: `with optional tags full-time, part-time`, `with multiple roles`, `with department:hr`\n"
        "  Tags: define a subclass pinned to a tag as `Define contractor as an employee with tags part-time.`\n"
        "    NEVER invent attrs like `part-time:true` — use `tags <value>` for tag membership.\n"
        "  Examples:\n"
        "    `Define gitlab as a services.`\n"
        "    `Define employee AKA employees as a users with department, optional tags full-time, part-time, intern.`\n"
        "    `Define contractor as an employee with tags part-time.`\n"
        "- Allow/Never allow: `Allow <Class> to <verb> <Obj>.`  `to` always comes before the verb.\n"
        "  Examples:\n"
        "    `Allow employee to access gitlab.`  NOT `Allow employee access to gitlab.`\n"
        "    `Never allow tags:intern employee to access services.`\n"
        "    `Never allow backup:nightly servers to access backup-services.`\n"
        "  Tag filter MUST use `tags:<value>` — bare word before class (e.g. `intern employee`) is NOT a tag filter.\n"
        "- Class names in rules must exactly match a defined class name — never substitute a description.\n"
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


def _entity_matches_class(entity: dict, cls_name: str, schema: "ClassSchema") -> bool:
    """True if entity.class_name is cls_name or a subclass of it."""
    ecn = entity["class_name"]
    leaf_cls = cls_name.split(".")[-1]
    leaf_ecn = ecn.split(".")[-1]
    if ecn == cls_name or leaf_ecn == leaf_cls:
        return True
    try:
        return schema.is_subclass(ecn, cls_name) or schema.is_subclass(ecn, leaf_cls)
    except Exception:
        return False


def _entity_payload(rule, subj_entity: dict | None, obj_entity: dict | None) -> dict:
    """Build a test payload using the rule's qualified class names but entity name/attrs."""
    s, o, ae = rule.subject, rule.object, rule.accessor_endpoint
    # Always keep the rule's qualified class name so the engine can resolve it.
    # The entity contributes its name and attributes only.
    p: dict = {
        "subject_class": s.cls if s and s.cls else "users",
        "subject_attrs": subj_entity["attributes"] if subj_entity else (dict(s.attrs) if s and s.attrs else {}),
        "action": rule.action,
        "object_class": o.cls if o and o.cls else "services",
        "object_attrs": obj_entity["attributes"] if obj_entity else (dict(o.attrs) if o and o.attrs else {}),
    }
    if subj_entity:
        p["subject_name"] = subj_entity["name"]
    if obj_entity:
        p["object_name"] = obj_entity["name"]
    if ae and ae.cls:
        p["accessor_class"] = ae.cls
        p["accessor_attrs"] = dict(ae.attrs) if ae.attrs else {}
    return p


@app.post("/api/tests/from-entities")
async def generate_tests_from_entities(req: AdversarialRequest,
                                       session: dict = Depends(get_session)):
    if not ai_client.available():
        raise HTTPException(503, "ANTHROPIC_API_KEY not set")

    ns_id = session["active_user_id"]
    entities = await db.get_entities(ns_id)
    if not entities:
        raise HTTPException(422, "No entities found in this namespace. Add entities first.")

    ps_parsed = await _merged_policy_set(ns_id)
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

    allow_rules = [r for r in ps_parsed.rules if r.effect == "allow"]
    deny_rules  = [r for r in ps_parsed.rules if r.effect == "deny"]
    _random.shuffle(allow_rules)

    positive_tests: list[dict] = []
    seen_keys: set[str] = set()

    def _add(payload: dict, expected: str) -> bool:
        key = _json.dumps(payload, sort_keys=True)
        if key in seen_keys:
            return False
        seen_keys.add(key)
        positive_tests.append({
            "number": len(positive_tests) + 1,
            "expected": expected,
            "payload": payload,
        })
        return True

    # Allow tests — pair entities with matching rule classes
    for rule in allow_rules[:req.n_positive * 2]:
        s_cls = rule.subject.cls if rule.subject and rule.subject.cls else "users"
        o_cls = rule.object.cls if rule.object and rule.object.cls else "services"
        subj_entities = [e for e in entities if _entity_matches_class(e, s_cls, schema)]
        obj_entities  = [e for e in entities if _entity_matches_class(e, o_cls, schema)]

        if subj_entities and obj_entities:
            # Use one entity pair per rule; pick randomly
            _random.shuffle(subj_entities); _random.shuffle(obj_entities)
            _add(_entity_payload(rule, subj_entities[0], obj_entities[0]), "allow")
        elif subj_entities:
            _add(_entity_payload(rule, subj_entities[0], None), "allow")
        elif obj_entities:
            _add(_entity_payload(rule, None, obj_entities[0]), "allow")
        else:
            _add(_base_payload(rule), "allow")

        if len(positive_tests) >= req.n_positive:
            break

    # Deny tests from explicit deny rules
    for rule in deny_rules:
        s_cls = rule.subject.cls if rule.subject and rule.subject.cls else "users"
        o_cls = rule.object.cls if rule.object and rule.object.cls else "services"
        subj_entities = [e for e in entities if _entity_matches_class(e, s_cls, schema)]
        obj_entities  = [e for e in entities if _entity_matches_class(e, o_cls, schema)]
        if subj_entities and obj_entities:
            _random.shuffle(subj_entities); _random.shuffle(obj_entities)
            _add(_entity_payload(rule, subj_entities[0], obj_entities[0]), "deny")
        else:
            _add(_base_payload(rule), "deny")

    # Build class hierarchy summary for the prompt
    classes_summary: dict = {}
    for cls_name in schema.names():
        try:
            classes_summary[cls_name] = {
                "parent": schema.parent(cls_name),
                "children": schema.children(cls_name),
            }
        except Exception:
            pass

    # Build entities section: group by class for readability
    entity_lines: list[str] = []
    by_class: dict[str, list[dict]] = {}
    for e in entities:
        by_class.setdefault(e["class_name"], []).append(e)
    for cls, items in sorted(by_class.items()):
        entity_lines.append(f"  {cls}:")
        for e in items:
            attr_str = ", ".join(f"{k}={v}" for k, v in (e.get("attributes") or {}).items())
            entity_lines.append(f"    - {e['name']}" + (f" ({attr_str})" if attr_str else ""))
    entities_section = "\n".join(entity_lines) if entity_lines else "  (no entities)"

    # Allow tests for AI: use positive_tests that are allow-type
    allow_tests_for_ai = [t for t in positive_tests if t["expected"] == "allow"]

    prompt_content = (_PROMPTS_DIR / "entity_test.md").read_text()
    prompt = (prompt_content
              .replace("{n_adversarial}", str(req.n_adversarial))
              .replace("{classes_json}", _json.dumps(classes_summary, indent=2))
              .replace("{entities_section}", entities_section)
              .replace("{positive_tests_json}", _json.dumps(positive_tests, indent=2))
              .replace("{allow_tests_json}", _json.dumps(allow_tests_for_ai, indent=2)))

    try:
        raw_text = ai_client.complete(
            system="You are a ZPL policy test generator. Return only valid JSON.",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096,
            temperature=0.5,
        )
    except Exception as exc:
        raise HTTPException(500, f"AI call failed: {exc}")

    text = raw_text.strip()
    text = _re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=_re.DOTALL).strip()
    try:
        ai_result = _json.loads(text)
    except Exception:
        ai_result = {}

    title_map = {t["number"]: t["title"] for t in (ai_result.get("positive_tests") or [])}

    positive_out = [
        {**t, "title": title_map.get(t["number"], _payload_description(t["payload"]))}
        for t in positive_tests
    ]
    counter_out = []
    discarded = 0
    for ct in (ai_result.get("counter_tests") or []):
        payload = ct.get("payload")
        if not payload:
            continue
        if _is_deny(engine, payload):
            counter_out.append({
                "payload": payload,
                "title": ct.get("title", _payload_description(payload)),
                "verified": True,
            })
        else:
            discarded += 1

    return {
        "positive_tests": positive_out,
        "counter_tests": counter_out,
        "discarded_adversarial": discarded,
    }


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
    ns_id = session.get("active_namespace_id") or session["active_user_id"]
    ns_row = await db.get_namespace(ns_id)
    active_dn = ns_row["display_name"] if ns_row else session.get("active_display_name", session["active_username"])
    return {
        "login_user_id":       session["login_user_id"],
        "login_username":      session["login_username"],
        "login_display_name":  session.get("login_display_name", session["login_username"]),
        "active_namespace_id": ns_id,
        "active_user_id":      ns_id,
        "active_username":     active_dn,
        "active_display_name": active_dn,
    }


class SwitchContextRequest(BaseModel):
    namespace_id: str


@app.post("/api/context/switch")
async def switch_context(req: SwitchContextRequest, request: Request,
                         session: dict = Depends(get_session)):
    """Switch active context to a namespace the login user owns or manages."""
    if not await db.can_access_namespace(session["login_user_id"], req.namespace_id):
        raise HTTPException(403, "You may only switch to namespaces you own or manage")
    target = await db.get_namespace(req.namespace_id)
    if target is None:
        raise HTTPException(404, "Namespace not found")
    token = _make_session(session["login_user_id"], session["login_username"],
                          session.get("login_display_name", session["login_username"]),
                          target["id"], target["display_name"])
    resp = JSONResponse({"active_namespace_id": target["id"],
                         "active_user_id": target["id"],
                         "active_display_name": target["display_name"]})
    resp.set_cookie("session", token, httponly=True, samesite="lax")
    return resp


@app.post("/api/context/reset")
async def reset_context(request: Request, session: dict = Depends(get_session)):
    """Switch back to the login user's home namespace."""
    ldn = session.get("login_display_name", session["login_username"])
    ns = await _login_namespace(session["login_user_id"])
    if not ns:
        raise HTTPException(status_code=404, detail="No namespace found for user")
    token = _make_session(session["login_user_id"], session["login_username"], ldn,
                          ns["id"], ns["display_name"])
    resp = JSONResponse({"active_namespace_id": ns["id"],
                         "active_user_id": ns["id"],
                         "active_display_name": ns["display_name"]})
    resp.set_cookie("session", token, httponly=True, samesite="lax")
    return resp


# ── Namespace CRUD ───────────────────────────────────────────────────────────

@app.get("/api/users/check")
async def check_user_exists(username: str, session: dict = Depends(get_session)):
    user = await db.get_user_by_username(username.strip())
    return {"exists": user is not None}


def _collect_tree_ids(node: dict) -> set[str]:
    ids = {node["id"]} if node.get("id") else set()
    for child in node.get("children", []):
        ids |= _collect_tree_ids(child)
    return ids


@app.get("/api/namespaces/tree")
async def get_namespace_tree_endpoint(session: dict = Depends(get_session)):
    """Namespace tree rooted at the login user's root namespace.

    Also includes 'external_owned': namespaces the user owns that live outside
    their root subtree (e.g. assigned as owner of a namespace under another user's tree).
    """
    root_ns = await db.get_root_namespace(session["login_user_id"])
    all_owned = await db.get_namespaces_owned_by(session["login_user_id"])
    if not root_ns:
        # No root namespace — return only the namespaces this user owns elsewhere.
        return {"external_owned": all_owned} if all_owned else {}
    tree = await db.get_namespace_tree(root_ns["id"])
    in_tree = _collect_tree_ids(tree)
    external = [ns for ns in all_owned if ns["id"] not in in_tree]
    if external:
        tree["external_owned"] = external
    return tree


class CreateNamespaceRequest(BaseModel):
    display_name: str
    parent_id: str | None = None
    owner_user_id: str | None = None
    owner_username: str | None = None
    owner_password: str | None = None
    owner_email: str = ""


@app.post("/api/namespaces", status_code=201)
async def create_namespace_endpoint(req: CreateNamespaceRequest,
                                    session: dict = Depends(get_session)):
    display_name = req.display_name.strip()
    if not display_name:
        raise HTTPException(400, "display_name required")

    parent_id = req.parent_id or session.get("active_namespace_id") or session["active_user_id"]
    if not await db.can_access_namespace(session["login_user_id"], parent_id):
        raise HTTPException(403, "Not authorised to create under that namespace")

    if req.owner_user_id:
        owner = await db.get_user_by_id(req.owner_user_id)
        if not owner:
            raise HTTPException(404, "Owner user not found")
        owner_id = owner["id"]
    elif req.owner_username:
        uname = req.owner_username.strip()
        existing = await db.get_user_by_username(uname)
        if existing:
            owner_id = existing["id"]
        elif req.owner_password:
            new_user = await db.create_user(
                uname, req.owner_password,
                display_name=uname,
                email=req.owner_email.strip(),
            )
            owner_id = new_user["id"]
        else:
            raise HTTPException(400, f"User {uname!r} not found; provide owner_password to create")
    else:
        owner_id = session["login_user_id"]

    ns = await db.create_namespace(display_name, owner_id, parent_id)
    return {"id": ns["id"], "display_name": ns["display_name"],
            "owner_user_id": ns["owner_user_id"],
            "parent_namespace_id": ns["parent_namespace_id"]}


class UpdateNamespaceRequest(BaseModel):
    display_name: str | None = None
    owner_user_id: str | None = None
    owner_username: str | None = None   # resolved to owner_user_id server-side
    owner_password: str | None = None   # if owner_username not found, create new user
    owner_email: str = ""


@app.patch("/api/namespaces/{namespace_id}")
async def update_namespace_endpoint(namespace_id: str, req: UpdateNamespaceRequest,
                                    session: dict = Depends(get_session)):
    if not await db.can_access_namespace(session["login_user_id"], namespace_id):
        raise HTTPException(403, "Not authorised to update this namespace")
    ns = await db.get_namespace(namespace_id)
    if not ns:
        raise HTTPException(404, "Namespace not found")

    owner_id: str | None = None
    if req.owner_user_id:
        owner = await db.get_user_by_id(req.owner_user_id)
        if not owner:
            raise HTTPException(404, "Owner user not found")
        owner_id = owner["id"]
    elif req.owner_username:
        uname = req.owner_username.strip()
        existing = await db.get_user_by_username(uname)
        if existing:
            owner_id = existing["id"]
        elif req.owner_password:
            new_owner = await db.create_user(uname, req.owner_password,
                                             display_name=uname,
                                             email=req.owner_email.strip())
            owner_id = new_owner["id"]
        else:
            raise HTTPException(400, f"User {uname!r} not found; provide owner_password to create")

    new_name = req.display_name.strip() if req.display_name else None
    if new_name and new_name != ns["display_name"]:
        old_text = await db.get_namespace_zpl(namespace_id) or ""
        if old_text:
            try:
                raw = zpl_parser.parse(old_text)
                ps, _ = norm.zpl_to_policy_set(raw, name="ns")
                pd = ns_mod.strip(ps.model_dump(mode="json"), ns["display_name"])
                pd = ns_mod.inject(pd, new_name)
                re_prefixed = (
                    zpl_serializer.classes_to_zpl(pd.get("classes", [])) + "\n\n" +
                    zpl_serializer.rules_to_zpl(pd.get("rules", []))
                ).strip()
                await db.save_namespace_zpl(namespace_id, re_prefixed)
            except Exception:
                pass

    await db.update_namespace(namespace_id,
                              display_name=new_name,
                              owner_user_id=owner_id)
    root_ns_id = await _get_root_ns_id(session["login_user_id"])
    if root_ns_id:
        _cache_invalidate(root_ns_id)
    return {"ok": True}


@app.delete("/api/namespaces/{namespace_id}", status_code=204)
async def delete_namespace_endpoint(namespace_id: str, session: dict = Depends(get_session)):
    if not await db.can_access_namespace(session["login_user_id"], namespace_id):
        raise HTTPException(403, "Not authorised to delete this namespace")
    root_ns = await db.get_root_namespace(session["login_user_id"])
    if root_ns and root_ns["id"] == namespace_id:
        raise HTTPException(400, "Cannot delete your own root namespace")
    err = await db.delete_namespace(namespace_id)
    if err:
        raise HTTPException(409, err)
    if root_ns:
        _cache_invalidate(root_ns["id"])


# ── Namespace ZPL ────────────────────────────────────────────────────────────

@app.get("/api/namespace/zpl")
async def get_namespace_zpl(session: dict = Depends(get_session)):
    ns_id = session["active_user_id"]
    text = await db.get_namespace_zpl(ns_id) or ""
    # Always fetch fresh display_name from DB — session may be stale after a rename.
    ns_row = await db.get_namespace(ns_id)
    ns = (ns_row.get("display_name") or "").strip() if ns_row else ""
    if not ns or ns.startswith("_ns_"):
        ns = ""
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


@app.get("/api/namespace/zpl/all")
async def get_namespace_zpl_all(session: dict = Depends(get_session)):
    """Return combined ZPL for the active namespace and all its descendants."""
    active_ns_id = session.get("active_namespace_id") or session["active_user_id"]
    tree = await db.get_namespace_tree(active_ns_id)

    # Depth-aware traversal preserving tree order, building full dotted path
    def _walk(node: dict, depth: int, parent_path: str, out: list) -> None:
        if node and node.get("id"):
            name = node.get("display_name", "")
            full_path = f"{parent_path}.{name}" if parent_path else name
            out.append((node["id"], full_path, depth, name))
            for child in node.get("children") or []:
                _walk(child, depth + 1, full_path, out)

    ordered: list[tuple[str, str, int, str]] = []
    _walk(tree, 0, "", ordered)

    user_ids = [uid for uid, _, _, _ in ordered]
    zpl_map = await db.get_namespace_zpl_batch(user_ids)

    sections = []
    for uid, label, depth, leaf_ns in ordered:
        text = (zpl_map.get(uid) or "").strip()
        if not text:
            continue
        indent = "  " * depth
        # leaf_ns is what was used when saving (active_ns strips _ns_ prefixes)
        effective_leaf = leaf_ns if (leaf_ns and not leaf_ns.startswith("_ns_")) else ""
        try:
            raw = zpl_parser.parse(text)
            ps, _ = norm.zpl_to_policy_set(raw, name="ns")
            pd = ps.model_dump(mode="json")
            if effective_leaf:
                # DB stores ZPL pre-qualified with leaf ns; strip it then inject full path
                pd = ns_mod.strip(pd, effective_leaf)
            injected = ns_mod.inject(pd, label) if label else pd
            qualified = (
                zpl_serializer.classes_to_zpl(injected.get("classes", [])) + "\n\n" +
                zpl_serializer.rules_to_zpl(injected.get("rules", []))
            ).strip()
            sections.append(f"{indent}# {label}\n{qualified}")
        except Exception:
            sections.append(f"{indent}# {label}\n{text}")
    return {"text": "\n\n".join(sections)}


@app.get("/api/zpl/export/markdown")
async def export_zpl_markdown(session: dict = Depends(get_session)):
    """Download all namespaces as Markdown. Headers use full dotted path (Corp, Corp.Hr, Corp.Ws)."""
    root_ns_id = await _get_root_ns_id(session["login_user_id"])
    if not root_ns_id:
        raise HTTPException(404, "No root namespace found")

    tree = await db.get_namespace_tree(root_ns_id)

    def _walk(node: dict, parent_path: str, out: list) -> None:
        if node and node.get("id"):
            name = node.get("display_name", "")
            full_path = f"{parent_path}.{name}" if parent_path else name
            out.append((node["id"], name, full_path))
            for child in node.get("children") or []:
                _walk(child, full_path, out)

    ordered: list[tuple[str, str, str]] = []
    _walk(tree, "", ordered)

    ns_ids = [uid for uid, _, _ in ordered]
    zpl_map = await db.get_namespace_zpl_batch(ns_ids)

    sections = []
    for ns_id, ns_name, full_path in ordered:
        text = (zpl_map.get(ns_id) or "").strip()
        if not text or not ns_name or ns_name.startswith("_ns_"):
            continue
        try:
            raw = zpl_parser.parse(text)
            ps, _ = norm.zpl_to_policy_set(raw, name="ns")
            pd = ns_mod.strip(ps.model_dump(mode="json"), ns_name)
            stripped = (
                zpl_serializer.classes_to_zpl(pd.get("classes", [])) + "\n\n" +
                zpl_serializer.rules_to_zpl(pd.get("rules", []))
            ).strip()
        except Exception:
            stripped = text
        sections.append(f"## {full_path}\n\n```\n{stripped}\n```")

    md = "# ZPL Policy Export\n\n" + "\n\n".join(sections) + "\n"
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=\"zpl-policy.md\""},
    )


class ImportMarkdownRequest(BaseModel):
    text: str


@app.post("/api/zpl/import/markdown")
async def import_zpl_markdown(req: ImportMarkdownRequest, session: dict = Depends(get_session)):
    """Import namespaces from a markdown file produced by export.
    Headers must use full dotted paths (Corp, Corp.Hr, Corp.Ws).
    Namespaces are created if missing; ZPL is overwritten if they exist.
    All created namespaces are owned by the login user."""
    import re as _re2

    # Parse: find ## <path> followed by ```...``` blocks
    pattern = _re2.compile(
        r'^## ([A-Za-z][A-Za-z0-9._-]*)\s*\n+```[^\n]*\n(.*?)```',
        _re2.MULTILINE | _re2.DOTALL,
    )
    entries = [(m.group(1).strip(), m.group(2).strip()) for m in pattern.finditer(req.text)]
    if not entries:
        raise HTTPException(400, "No namespace sections found in markdown")

    # Sort by depth so parents are created before children
    entries.sort(key=lambda e: e[0].count("."))

    login_user_id = session["login_user_id"]

    # Build path→id map from existing tree (if root exists)
    path_to_id: dict[str, str] = {}
    root_ns = await db.get_root_namespace(login_user_id)
    if root_ns:
        tree = await db.get_namespace_tree(root_ns["id"])
        def _index(node: dict, parent_path: str) -> None:
            if node and node.get("id"):
                name = node.get("display_name", "")
                fp = f"{parent_path}.{name}" if parent_path else name
                path_to_id[fp] = node["id"]
                for child in node.get("children") or []:
                    _index(child, fp)
        _index(tree, "")

    results = []
    for full_path, zpl_text in entries:
        parts = full_path.rsplit(".", 1)
        leaf_name = parts[-1]
        parent_path = parts[0] if len(parts) == 2 else None

        # Resolve parent id
        parent_id: str | None = None
        if parent_path:
            parent_id = path_to_id.get(parent_path)
            if not parent_id:
                results.append({"path": full_path, "status": "skip", "reason": f"parent '{parent_path}' not found"})
                continue

        # Find or create this namespace
        if full_path in path_to_id:
            ns_id = path_to_id[full_path]
            action = "updated"
        else:
            new_ns = await db.create_namespace(leaf_name, login_user_id, parent_namespace_id=parent_id)
            ns_id = new_ns["id"]
            path_to_id[full_path] = ns_id
            action = "created"

        # Inject leaf prefix and save ZPL
        if zpl_text:
            try:
                raw = zpl_parser.parse(zpl_text)
                ps, errors = norm.zpl_to_policy_set(raw, name="ns")
                if errors:
                    results.append({"path": full_path, "status": "zpl_error", "reason": str(errors[:2])})
                    continue
                pd = ns_mod.inject(ps.model_dump(mode="json"), leaf_name)
                stored = (
                    zpl_serializer.classes_to_zpl(pd.get("classes", [])) + "\n\n" +
                    zpl_serializer.rules_to_zpl(pd.get("rules", []))
                ).strip()
                await db.save_namespace_zpl(ns_id, stored)
            except Exception as e:
                results.append({"path": full_path, "status": "error", "reason": str(e)})
                continue

        _cache_invalidate(await _get_root_ns_id(login_user_id) or ns_id)
        results.append({"path": full_path, "status": action})

    return {"imported": len([r for r in results if r["status"] in ("created", "updated")]),
            "results": results}


class SaveNamespaceZplRequest(BaseModel):
    text: str


@app.put("/api/namespace/zpl")
async def save_namespace_zpl(req: SaveNamespaceZplRequest, session: dict = Depends(get_session)):
    text = req.text
    ns_id = session["active_user_id"]
    ns_row = await db.get_namespace(ns_id)
    ns = (ns_row.get("display_name") or "").strip() if ns_row else ""
    if not ns or ns.startswith("_ns_"):
        ns = ""
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
    root_ns_id = await _get_root_ns_id(session["login_user_id"])
    if root_ns_id:
        _cache_invalidate(root_ns_id)
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
        known = await _known_classes(session["login_user_id"])
        inferred = zpl_parser.infer_missing_classes(raw, known_classes=known)
        inferred_zpl = zpl_parser.inferred_to_zpl(inferred) if inferred else ""
        inferred_verbs = zpl_parser.infer_missing_verbs(raw)
        inferred_verbs_zpl = "\n".join(f"Define {v} as a verb." for v in inferred_verbs)
        undefined_parents = zpl_parser.infer_undefined_parents(raw, known_classes=known)
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
        "undefined_parents": undefined_parents if lang == "zpl" else [],
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


# ── Entities ─────────────────────────────────────────────────────────────────

class CreateEntityRequest(BaseModel):
    class_name: str
    name: str
    attributes: dict = {}


class UpdateEntityRequest(BaseModel):
    class_name: str | None = None
    name: str | None = None
    attributes: dict | None = None


@app.get("/api/entities")
async def list_entities(session: dict = Depends(get_session)):
    ns_id = session["active_user_id"]
    return await db.get_entities(ns_id)


@app.post("/api/entities", status_code=201)
async def create_entity(req: CreateEntityRequest, session: dict = Depends(get_session)):
    ns_id = session["active_user_id"]
    if not req.class_name.strip():
        raise HTTPException(400, "class_name is required")
    if not req.name.strip():
        raise HTTPException(400, "name is required")
    return await db.create_entity(ns_id, req.class_name.strip(), req.name.strip(), req.attributes)


@app.put("/api/entities/{entity_id}")
async def update_entity(entity_id: str, req: UpdateEntityRequest,
                        session: dict = Depends(get_session)):
    ns_id = session["active_user_id"]
    ok = await db.update_entity(
        entity_id, ns_id,
        class_name=req.class_name,
        name=req.name,
        attributes=req.attributes,
    )
    if not ok:
        raise HTTPException(404, "Entity not found")
    return {"ok": True}


@app.delete("/api/entities/{entity_id}", status_code=204)
async def delete_entity(entity_id: str, session: dict = Depends(get_session)):
    ns_id = session["active_user_id"]
    ok = await db.delete_entity(entity_id, ns_id)
    if not ok:
        raise HTTPException(404, "Entity not found")


@app.delete("/api/entities", status_code=200)
async def delete_all_entities(session: dict = Depends(get_session)):
    ns_id = session["active_user_id"]
    count = await db.delete_all_entities(ns_id)
    return {"deleted": count}


@app.get("/api/entities/export/yaml")
async def export_entities_yaml(session: dict = Depends(get_session)):
    import yaml as _yaml
    ns_id = session["active_user_id"]
    entities = await db.get_entities(ns_id)
    content = _yaml.dump(entities, default_flow_style=False, allow_unicode=True)
    return Response(
        content=content,
        media_type="text/yaml",
        headers={"Content-Disposition": "attachment; filename=entities.yaml"},
    )


@app.post("/api/entities/import/yaml")
async def import_entities_yaml(file: UploadFile = File(...),
                               session: dict = Depends(get_session)):
    import yaml as _yaml
    ns_id = session["active_user_id"]
    raw = await file.read()
    try:
        data = _yaml.safe_load(raw)
    except Exception as exc:
        raise HTTPException(400, f"Invalid YAML: {exc}")
    # Accept either a bare list or {"entities": [...]}
    if isinstance(data, dict):
        data = data.get("entities") or []
    if not isinstance(data, list):
        raise HTTPException(400, "YAML must be a list of entity objects (or a dict with an 'entities' key)")
    created = 0
    for item in data:
        if not isinstance(item, dict):
            continue
        # Accept both "class_name" and "class" as the class field
        cn = str(item.get("class_name") or item.get("class") or "").strip()
        nm = str(item.get("name") or "").strip()
        attrs = item.get("attributes") or {}
        if not cn or not nm:
            continue
        await db.create_entity(ns_id, cn, nm, attrs if isinstance(attrs, dict) else {})
        created += 1
    return {"imported": created}


@app.get("/api/entities/export/ldif")
async def export_entities_ldif(session: dict = Depends(get_session)):
    ns_id = session["active_user_id"]
    entities = await db.get_entities(ns_id)
    lines = []
    for e in entities:
        lines.append(f"dn: cn={e['name']},ou={e['class_name']},dc=zpr,dc=policy")
        lines.append(f"cn: {e['name']}")
        lines.append(f"objectClass: {e['class_name']}")
        for k, v in (e.get("attributes") or {}).items():
            lines.append(f"{k}: {v}")
        lines.append("")
    content = "\n".join(lines)
    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=entities.ldif"},
    )


@app.post("/api/entities/import/ldif")
async def import_entities_ldif(file: UploadFile = File(...),
                               session: dict = Depends(get_session)):
    ns_id = session["active_user_id"]
    raw = (await file.read()).decode("utf-8", errors="replace")
    entries = []
    current: dict | None = None
    for line in raw.splitlines():
        line = line.rstrip()
        if line.startswith("dn:"):
            if current:
                entries.append(current)
            current = {"attrs": {}}
        elif current is None:
            continue
        elif line == "":
            if current:
                entries.append(current)
            current = None
        elif ":" in line:
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip()
            if key == "cn":
                current["name"] = val
            elif key == "objectClass":
                current["class_name"] = val
            else:
                current["attrs"][key] = val
    if current:
        entries.append(current)

    created = 0
    for e in entries:
        cn = str(e.get("class_name") or "").strip()
        nm = str(e.get("name") or "").strip()
        if not cn or not nm:
            continue
        await db.create_entity(ns_id, cn, nm, e.get("attrs") or {})
        created += 1
    return {"imported": created}


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
    if not ps or not ps.classes:
        return "None yet — only the built-in roots: users, endpoints, services."
    lines = ["Built-in roots: users, endpoints, services", ""]
    for c in ps.classes:
        regular_attrs = []
        tag_values: list[str] = []
        for k, spec in (c.attributes or {}).items():
            if k == "tags" and spec.type == "multi":
                tag_values = spec.values[:8]
            elif spec.type == "multi":
                regular_attrs.append(f"{k} (multi)")
            else:
                v = f"={spec.value}" if spec.value else ""
                regular_attrs.append(f"{k}{v}")
        parts = []
        if regular_attrs:
            parts.append("attrs: " + ", ".join(regular_attrs))
        if tag_values:
            parts.append("tags: " + ", ".join(tag_values))
        detail = "  —  " + "; ".join(parts) if parts else ""
        lines.append(f"  {c.name} (extends {c.parent}){detail}")
    lines.append("")
    lines.append("Tag usage: `Define X as a Y with tags <value>.`  Filter in rules: `tags:<value> Y`")
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
