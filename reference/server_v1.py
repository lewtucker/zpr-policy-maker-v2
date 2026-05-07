"""ZPR Policy Maker — FastAPI server (RFC-15.5 rewrite).

Phase 2a: core endpoints only. LLM-dependent endpoints (/chat, /generate-rules,
/scenario/evaluate, /policies/parse-test, /policies/build-test-suite) are
deferred to Phase 2b. Text parsing via ZPL grammar is deferred too.

Session auth via cookie ``pm_session``. Agent calls use Bearer token.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import yaml
from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Header, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.sessions import SessionMiddleware

load_dotenv(Path(__file__).parent / ".env")

import ai_client
import database
import user_engine
import zpl_parser
import zpl_serializer
from class_schema import ClassSchemaError
from zpl_engine import CheckRequest, Entity, Rule, Spec, ZPLEngine

# ── Config ──────────────────────────────────────────────────────────────────

_server_dir = Path(__file__).parent
SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
APP_PASSWORD = os.environ.get("APP_PASSWORD")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not APP_PASSWORD:
    raise RuntimeError(
        "APP_PASSWORD is not set. Add it to src/server/.env or the environment."
    )

SYSTEM_VERBS = ["access", "use", "call", "read", "write", "connect-to"]

DEFAULTS_DIR = _server_dir / "defaults"


# ── Password hashing (pbkdf2-sha256) ────────────────────────────────────────


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${dk.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, dk_hex = stored_hash.split("$", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return hmac.compare_digest(dk.hex(), dk_hex)


def _check_login(email: str, password: str) -> bool:
    stored = database.get_password_hash(email)
    if stored:
        return _verify_password(password, stored)
    return password == APP_PASSWORD


# ── Lifespan ────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    # Prime the system classes cache so the first /check isn't slow
    user_engine._load_system_classes()
    yield


app = FastAPI(title="ZPR Policy Maker", version="2.0.0-rfc15.5", lifespan=lifespan)
app.mount("/reference", StaticFiles(directory=str(_server_dir / "static" / "docs")), name="reference")
# /docs and /openapi.json are FastAPI's built-in Swagger UI and schema — preserved for API consumers
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="pm_session",
    max_age=86400 * 7,
)


# ── Auth helpers ────────────────────────────────────────────────────────────


def _require_session(request: Request) -> str:
    email = request.session.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return email


def _require_admin(request: Request) -> str:
    email = _require_session(request)
    if not request.session.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return email


def _seed_user_defaults(email: str) -> None:
    """Seed example entities for a brand-new user (no-op if they already have any).

    Classes are NOT auto-seeded — users start with only the 4 built-in roots
    and load example classes explicitly via the 'Load example classes' button.
    """
    existing = user_engine.load_user_entities(email)
    if existing:
        return
    import yaml as _yaml

    path = DEFAULTS_DIR / "example_entities.yaml"
    if not path.exists():
        return
    data = _yaml.safe_load(path.read_text()) or {}
    entries = data.get("entities") or []
    entities: list[Entity] = []
    ids: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("class"):
            continue
        entities.append(Entity(
            class_name=entry["class"],
            name=entry.get("name") or None,
            attrs=dict(entry.get("attributes") or {}),
        ))
        ids.append(entry.get("id") or uuid.uuid4().hex)
    if entities:
        user_engine.save_user_entities(email, entities, ids=ids)


def _bearer_email(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401, detail="Missing Bearer token"
        )
    token = authorization[7:].strip()
    email = database.get_email_by_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid Bearer token")
    return email


# ── Pydantic models ─────────────────────────────────────────────────────────


class SpecIn(BaseModel):
    """One slot in a rule. Uses alias 'class' to match YAML/JSON vocabulary."""
    model_config = ConfigDict(populate_by_name=True)

    class_name: str | None = Field(default=None, alias="class")
    name: str | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)

    def to_spec(self) -> Spec | None:
        if self.class_name is None and self.name is None and not self.attrs:
            return None
        return Spec(class_name=self.class_name, name=self.name, attrs=dict(self.attrs))


class RuleIn(BaseModel):
    id: str | None = None
    name: str = ""
    description: str = ""
    result: Literal["allow", "never"]
    priority: int = 100
    verb: str | None = None
    subject: SpecIn | None = None
    accessor_endpoint: SpecIn | None = None
    object: SpecIn | None = None
    server_endpoint: SpecIn | None = None
    signal: dict | None = None
    protected: bool = False

    def to_rule(self) -> Rule:
        return Rule(
            id=self.id or uuid.uuid4().hex,
            name=self.name or "",
            description=self.description or "",
            result=self.result,
            priority=self.priority,
            verb=self.verb,
            subject=self.subject.to_spec() if self.subject else None,
            accessor_endpoint=(
                self.accessor_endpoint.to_spec() if self.accessor_endpoint else None
            ),
            object=self.object.to_spec() if self.object else None,
            server_endpoint=(
                self.server_endpoint.to_spec() if self.server_endpoint else None
            ),
            signal=dict(self.signal) if self.signal else None,
            protected=self.protected,
        )


class ClassIn(BaseModel):
    """User-defined subclass."""
    model_config = ConfigDict(populate_by_name=True)

    class_name: str = Field(alias="class")
    parent: str | None = None
    aka: str | None = None
    description: str = ""
    attributes: dict[str, dict] = Field(default_factory=dict)

    def to_dict(self) -> dict:
        out: dict = {
            "id": None,
            "class": self.class_name,
            "parent": self.parent,
        }
        if self.aka:
            out["aka"] = self.aka
        if self.description:
            out["description"] = self.description
        out["attributes"] = dict(self.attributes)
        return out


class EntityIn(BaseModel):
    """An instance of a class with concrete attribute values."""
    model_config = ConfigDict(populate_by_name=True)

    id: str | None = None
    class_name: str = Field(alias="class")
    name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class CheckIn(BaseModel):
    """Body for POST /check."""
    model_config = ConfigDict(populate_by_name=True)

    subject: str | dict | None = None
    object: str | dict | None = None
    verb: str = "access"
    accessor_endpoint: str | dict | None = None
    server_endpoint: str | dict | None = None


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str


class VerbsIn(BaseModel):
    verbs: list[str]


class EvalModeIn(BaseModel):
    eval_mode: str


# ── Static pages ────────────────────────────────────────────────────────────


@app.get("/")
async def root(request: Request):
    if not request.session.get("email"):
        return RedirectResponse("/login")
    return FileResponse(_server_dir / "static" / "index.html")


@app.get("/login")
async def login_page(request: Request):
    if request.session.get("email"):
        return RedirectResponse("/")
    return FileResponse(_server_dir / "static" / "login.html")


# ── Auth endpoints ──────────────────────────────────────────────────────────


@app.post("/login")
async def login(
    request: Request, email: str = Form(...), password: str = Form(...)
):
    email = email.strip().lower()
    if not email:
        return RedirectResponse("/login?error=1", status_code=303)
    if email == ADMIN_USERNAME.lower() and password == ADMIN_PASSWORD:
        request.session["email"] = ADMIN_USERNAME.lower()
        request.session["is_admin"] = True
        return RedirectResponse("/", status_code=303)
    if not _check_login(email, password):
        return RedirectResponse("/login?error=1", status_code=303)
    database.get_or_create_user(email)
    _seed_user_defaults(email)
    request.session["email"] = email
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/me")
async def me(request: Request):
    email = _require_session(request)
    is_admin = bool(request.session.get("is_admin"))
    if is_admin:
        return {
            "email": email,
            "is_admin": True,
            "rule_count": 0,
            "class_count": 0,
            "entity_count": 0,
            "created_at": None,
        }
    database.get_or_create_user(email)
    user = database.get_user(email)
    rules = user_engine.load_user_rules(email)
    user_classes = user_engine._load_user_classes_list(email)
    entities = user_engine.load_user_entities(email)
    return {
        "email": email,
        "is_admin": False,
        "rule_count": len(rules),
        "class_count": len(user_classes),
        "entity_count": len(entities),
        "created_at": user["created_at"],
    }


@app.post("/profile/password")
async def change_password(body: PasswordChangeIn, request: Request):
    email = _require_session(request)
    if len(body.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    if not _check_login(email, body.current_password):
        raise HTTPException(403, "Current password is incorrect")
    database.set_password_hash(email, _hash_password(body.new_password))
    return {"changed": True}


@app.delete("/account")
async def delete_account(request: Request):
    email = _require_session(request)
    if request.session.get("is_admin"):
        raise HTTPException(403, "Admin account cannot be deleted this way")
    database.delete_user(email)
    request.session.clear()
    return {"deleted": True}


@app.get("/account/notes")
async def get_notes(request: Request):
    email = _require_session(request)
    return {"notes": database.get_notes(email)}


class NotesIn(BaseModel):
    notes: str


@app.post("/account/notes")
async def save_notes(request: Request, body: NotesIn):
    email = _require_session(request)
    database.save_notes(email, body.notes)
    return {"ok": True}


# ── Classes ─────────────────────────────────────────────────────────────────


@app.get("/classes")
async def list_classes(request: Request):
    """Return the merged system+user class hierarchy.

    Each class carries a derived ``kind`` field (``users``, ``endpoints``, or
    ``services``) and the ``builtin`` flag so the UI can render the tree
    without a second pass.
    """
    email = _require_session(request)
    schema = user_engine.load_user_schema(email)
    out = []
    for name in schema.names():
        raw = schema.get(name)
        out.append(
            {
                "class": name,
                "parent": raw.get("parent"),
                "builtin": bool(raw.get("builtin")),
                "aka": raw.get("aka"),
                "description": raw.get("description", ""),
                "attributes": raw.get("attributes") or {},
                "kind": schema.kind_of(name),
            }
        )
    return {"classes": out}


@app.get("/classes/{name}")
async def get_class(name: str, request: Request):
    email = _require_session(request)
    schema = user_engine.load_user_schema(email)
    if name not in schema:
        raise HTTPException(404, f"Unknown class: {name}")
    raw = schema.get(name)
    return {
        "class": name,
        "parent": raw.get("parent"),
        "builtin": bool(raw.get("builtin")),
        "aka": raw.get("aka"),
        "description": raw.get("description", ""),
        "attributes": raw.get("attributes") or {},
        "kind": schema.kind_of(name),
    }


@app.get("/classes/{name}/resolved")
async def resolve_class(name: str, request: Request):
    """Return the fully inherited attribute set for this class."""
    email = _require_session(request)
    schema = user_engine.load_user_schema(email)
    if name not in schema:
        raise HTTPException(404, f"Unknown class: {name}")
    return {
        "class": name,
        "kind": schema.kind_of(name),
        "ancestors": schema.ancestors(name),
        "attributes": schema.resolve(name),
    }


@app.post("/classes")
async def add_class(body: ClassIn, request: Request):
    email = _require_session(request)
    try:
        schema = user_engine.load_user_schema(email)
        if body.class_name in schema and schema.get(body.class_name).get("builtin"):
            raise HTTPException(403, f"Cannot override builtin class {body.class_name!r}")
        existing = user_engine._load_user_classes_list(email)
        existing = [c for c in existing if c.get("class") != body.class_name]
        existing.append(body.to_dict())
        user_engine.save_user_classes(email, existing)
        # Re-validate by loading the merged schema
        user_engine.load_user_schema(email)
    except ClassSchemaError as e:
        raise HTTPException(400, str(e))
    return body.to_dict()


@app.put("/classes/{name}")
async def update_class(name: str, body: ClassIn, request: Request):
    email = _require_session(request)
    if body.class_name != name:
        raise HTTPException(400, "Path class name does not match body 'class'")
    schema = user_engine.load_user_schema(email)
    if name in schema and schema.get(name).get("builtin"):
        raise HTTPException(403, f"Cannot modify builtin class {name!r}")
    existing = user_engine._load_user_classes_list(email)
    existing = [c for c in existing if c.get("class") != name]
    existing.append(body.to_dict())
    try:
        user_engine.save_user_classes(email, existing)
        user_engine.load_user_schema(email)
    except ClassSchemaError as e:
        raise HTTPException(400, str(e))
    return body.to_dict()


@app.delete("/classes/{name}")
async def delete_class(name: str, request: Request):
    email = _require_session(request)
    schema = user_engine.load_user_schema(email)
    if name in schema and schema.get(name).get("builtin"):
        raise HTTPException(403, f"Cannot delete builtin class {name!r}")
    existing = user_engine._load_user_classes_list(email)
    filtered = [c for c in existing if c.get("class") != name]
    if len(filtered) == len(existing):
        raise HTTPException(404, f"Unknown user class: {name}")
    # Check no user class descends from this one
    for c in filtered:
        if c.get("parent") == name:
            raise HTTPException(
                400,
                f"Cannot delete {name!r}: {c.get('class')!r} descends from it",
            )
    user_engine.save_user_classes(email, filtered)
    return {"deleted": name}


@app.post("/classes/delete-all")
async def delete_all_classes(request: Request, cascade: bool = False):
    """Delete all user-defined classes (builtins are preserved).

    ``?cascade=true`` also wipes all entities and non-protected rules so no
    orphaned references remain.
    """
    email = _require_session(request)
    existing = user_engine._load_user_classes_list(email)
    user_classes = [c for c in existing if not c.get("builtin")]
    deleted_classes = len(user_classes)
    user_engine.save_user_classes(email, [])

    deleted_entities = 0
    deleted_rules = 0
    if cascade:
        entities = user_engine.load_user_entities(email)
        user_engine.save_user_entities(email, [])
        deleted_entities = len(entities)

        rules = user_engine.load_user_rules(email)
        protected = [r for r in rules if r.protected]
        user_engine.save_user_rules(email, protected)
        deleted_rules = len(rules) - len(protected)

    return {
        "deleted_classes": deleted_classes,
        "deleted_entities": deleted_entities,
        "deleted_rules": deleted_rules,
    }


# ── Entities ────────────────────────────────────────────────────────────────


def _load_entities_with_ids(email: str) -> tuple[list[Entity], list[str]]:
    """Return parallel lists of Entity objects and their IDs."""
    yaml_str = database.get_entities_yaml(email)
    data = yaml.safe_load(yaml_str) or {}
    entries = data.get("entities") or []
    entities: list[Entity] = []
    ids: list[str] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        cls_name = e.get("class")
        if not cls_name:
            continue
        entities.append(
            Entity(
                class_name=cls_name,
                name=e.get("name") or None,
                attrs=dict(e.get("attributes") or {}),
            )
        )
        ids.append(e.get("id") or uuid.uuid4().hex)
    return entities, ids


def _entity_to_dict(eid: str, e: Entity) -> dict:
    return {
        "id": eid,
        "class": e.class_name,
        "name": e.name,
        "attributes": dict(e.attrs),
    }


@app.get("/entities")
async def list_entities(request: Request, class_name: str | None = None):
    email = _require_session(request)
    entities, ids = _load_entities_with_ids(email)
    schema = user_engine.load_user_schema(email)
    out = []
    for eid, e in zip(ids, entities):
        if class_name and not (
            e.class_name == class_name
            or (schema.has(e.class_name) and schema.is_subclass(e.class_name, class_name))
        ):
            continue
        out.append(_entity_to_dict(eid, e))
    return {"entities": out}


@app.get("/entities/{entity_id}")
async def get_entity(entity_id: str, request: Request):
    email = _require_session(request)
    entities, ids = _load_entities_with_ids(email)
    for eid, e in zip(ids, entities):
        if eid == entity_id:
            return _entity_to_dict(eid, e)
    raise HTTPException(404, f"Unknown entity id: {entity_id}")


@app.post("/entities")
async def add_entity(body: EntityIn, request: Request):
    email = _require_session(request)
    schema = user_engine.load_user_schema(email)
    if body.class_name not in schema:
        raise HTTPException(400, f"Unknown class: {body.class_name}")
    entities, ids = _load_entities_with_ids(email)
    new_id = body.id or uuid.uuid4().hex
    if new_id in ids:
        raise HTTPException(409, f"Entity id already exists: {new_id}")
    if body.name:
        for e in entities:
            if e.name == body.name:
                raise HTTPException(409, f"Entity name already exists: {body.name}")
    entities.append(Entity(class_name=body.class_name, name=body.name, attrs=dict(body.attributes)))
    ids.append(new_id)
    user_engine.save_user_entities(email, entities, ids=ids)
    return _entity_to_dict(new_id, entities[-1])


@app.put("/entities/{entity_id}")
async def update_entity(entity_id: str, body: EntityIn, request: Request):
    email = _require_session(request)
    schema = user_engine.load_user_schema(email)
    if body.class_name not in schema:
        raise HTTPException(400, f"Unknown class: {body.class_name}")
    entities, ids = _load_entities_with_ids(email)
    for i, eid in enumerate(ids):
        if eid == entity_id:
            # Name uniqueness check (if changed)
            if body.name:
                for j, e in enumerate(entities):
                    if j != i and e.name == body.name:
                        raise HTTPException(409, f"Entity name already exists: {body.name}")
            entities[i] = Entity(
                class_name=body.class_name,
                name=body.name,
                attrs=dict(body.attributes),
            )
            user_engine.save_user_entities(email, entities, ids=ids)
            return _entity_to_dict(entity_id, entities[i])
    raise HTTPException(404, f"Unknown entity id: {entity_id}")


@app.post("/entities/delete-all")
async def delete_all_entities(request: Request):
    email = _require_session(request)
    user_engine.save_user_entities(email, [], ids=[])
    return {"deleted": True}


@app.delete("/entities/{entity_id}")
async def delete_entity(entity_id: str, request: Request):
    email = _require_session(request)
    entities, ids = _load_entities_with_ids(email)
    for i, eid in enumerate(ids):
        if eid == entity_id:
            del entities[i]
            del ids[i]
            user_engine.save_user_entities(email, entities, ids=ids)
            return {"deleted": entity_id}
    raise HTTPException(404, f"Unknown entity id: {entity_id}")


# ── Rules (policies) ────────────────────────────────────────────────────────


@app.get("/policies")
async def list_policies(request: Request):
    email = _require_session(request)
    rules = user_engine.load_user_rules(email)
    return {"policies": [r.to_dict() for r in rules]}


@app.get("/policies/{rule_id}")
async def get_policy(rule_id: str, request: Request):
    email = _require_session(request)
    for r in user_engine.load_user_rules(email):
        if r.id == rule_id:
            return r.to_dict()
    raise HTTPException(404, f"Unknown rule: {rule_id}")


@app.post("/policies")
async def add_policy(body: RuleIn, request: Request):
    email = _require_session(request)
    rules = user_engine.load_user_rules(email)
    new_rule = body.to_rule()
    if any(r.id == new_rule.id for r in rules):
        raise HTTPException(409, f"Rule id already exists: {new_rule.id}")
    rules.append(new_rule)
    user_engine.save_user_rules(email, rules)
    return new_rule.to_dict()


@app.put("/policies/{rule_id}")
async def update_policy(rule_id: str, body: RuleIn, request: Request):
    email = _require_session(request)
    rules = user_engine.load_user_rules(email)
    for i, r in enumerate(rules):
        if r.id == rule_id:
            if r.protected and not body.protected:
                raise HTTPException(403, "Cannot unprotect a protected rule")
            if r.protected:
                raise HTTPException(403, "Cannot modify a protected rule")
            new_rule = body.to_rule()
            new_rule.id = rule_id  # preserve id
            rules[i] = new_rule
            user_engine.save_user_rules(email, rules)
            return new_rule.to_dict()
    raise HTTPException(404, f"Unknown rule: {rule_id}")


@app.delete("/policies/{rule_id}")
async def delete_policy(rule_id: str, request: Request):
    email = _require_session(request)
    rules = user_engine.load_user_rules(email)
    for i, r in enumerate(rules):
        if r.id == rule_id:
            if r.protected:
                raise HTTPException(403, "Cannot delete a protected rule")
            del rules[i]
            user_engine.save_user_rules(email, rules)
            return {"deleted": rule_id}
    raise HTTPException(404, f"Unknown rule: {rule_id}")


@app.post("/policies/delete-all")
async def delete_all_policies(request: Request):
    email = _require_session(request)
    rules = user_engine.load_user_rules(email)
    kept = [r for r in rules if r.protected]
    user_engine.save_user_rules(email, kept)
    return {"deleted": len(rules) - len(kept), "kept_protected": len(kept)}


# ── Agent check ─────────────────────────────────────────────────────────────


def _resolve_slot(
    value: str | dict | None, index: dict[str, Entity]
) -> Entity | None:
    """Resolve a check-request slot into an Entity.

    - str          → look up by name in entity index
    - dict         → inline entity (class, name, attributes)
    - None         → unresolved (slot not provided)
    """
    if value is None:
        return None
    if isinstance(value, str):
        e = index.get(value)
        if not e:
            raise HTTPException(400, f"Unknown named entity: {value}")
        return e
    if isinstance(value, dict):
        cls_name = value.get("class") or ""
        return Entity(
            class_name=cls_name,
            name=value.get("name"),
            attrs=dict(value.get("attributes") or {}),
        )
    raise HTTPException(400, f"bad slot value: {value!r}")


@app.post("/check")
async def check(
    body: CheckIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    email = _bearer_email(authorization)
    engine = user_engine.load_engine(email)
    entities = user_engine.load_user_entities(email)
    index = user_engine.build_entity_index(entities)

    subject = _resolve_slot(body.subject, index)
    obj = _resolve_slot(body.object, index)

    check_request = CheckRequest(
        subject=subject,
        object=obj,
        verb=body.verb,
        accessor_endpoint=_resolve_slot(body.accessor_endpoint, index),
        server_endpoint=_resolve_slot(body.server_endpoint, index),
    )
    result = engine.evaluate(check_request)

    # Log the check
    import json as _json

    database.log_check(
        email=email,
        tool="/check",
        params_json=_json.dumps(body.model_dump(by_alias=True)),
        verdict=result.verdict,
        rule_id=result.rule_id,
        rule_name=result.rule_name,
        token=authorization[7:].strip() if authorization else None,
    )

    return {
        "verdict": result.verdict,
        "rule_id": result.rule_id,
        "rule_name": result.rule_name,
        "signal": result.signal,
        "trace": [t.to_dict() for t in result.trace],
    }


# ── Agent token ─────────────────────────────────────────────────────────────


@app.get("/token")
async def get_token(request: Request):
    email = _require_session(request)
    token = database.get_agent_token(email)
    return {"token": token}


@app.post("/token")
async def rotate_token(request: Request):
    email = _require_session(request)
    new_token = secrets.token_hex(32)
    database.save_agent_token(email, new_token)
    return {"token": new_token}


@app.delete("/token")
async def revoke_token(request: Request):
    email = _require_session(request)
    database.save_agent_token(email, "")
    return {"token": ""}


# ── Settings ────────────────────────────────────────────────────────────────


@app.get("/eval-mode")
async def get_eval_mode(request: Request):
    email = _require_session(request)
    return {"eval_mode": database.get_eval_mode(email)}


@app.post("/eval-mode")
async def save_eval_mode(body: EvalModeIn, request: Request):
    email = _require_session(request)
    allowed = {"never-precedence", "priority-only"}
    if body.eval_mode not in allowed:
        raise HTTPException(400, f"eval_mode must be one of {sorted(allowed)}")
    database.save_eval_mode(email, body.eval_mode)
    return {"ok": True}


@app.get("/verbs")
async def get_verbs(request: Request):
    email = _require_session(request)
    custom = database.get_custom_verbs(email)
    return {
        "system_verbs": SYSTEM_VERBS,
        "custom_verbs": custom,
        "all_verbs": SYSTEM_VERBS + [v for v in custom if v not in SYSTEM_VERBS],
    }


@app.post("/verbs")
async def save_verbs(body: VerbsIn, request: Request):
    email = _require_session(request)
    clean = [v.strip().lower() for v in body.verbs if v.strip()]
    clean = [v for v in clean if v not in SYSTEM_VERBS]
    database.save_custom_verbs(email, clean)
    return {"ok": True, "custom_verbs": clean}


# ── Activity / check log ────────────────────────────────────────────────────


@app.get("/activity")
async def activity(request: Request, limit: int = 50):
    email = _require_session(request)
    rows = database.get_check_log(email, limit=limit)
    return {"checks": [dict(r) for r in rows]}


@app.delete("/activity")
async def clear_activity(request: Request):
    email = _require_session(request)
    database.clear_check_log(email)
    return {"cleared": True}


# ── Approvals ───────────────────────────────────────────────────────────────


@app.get("/approvals")
async def list_approvals(request: Request, pending_only: bool = False):
    email = _require_session(request)
    rows = database.list_approvals(email, pending_only=pending_only)
    return {"approvals": [dict(r) for r in rows]}


class ApprovalResolveIn(BaseModel):
    verdict: Literal["allow", "deny"]
    reason: str | None = None


@app.post("/approvals/{approval_id}")
async def resolve_approval(approval_id: str, body: ApprovalResolveIn, request: Request):
    email = _require_session(request)
    approval = database.get_approval(approval_id)
    if not approval or approval["email"] != email:
        raise HTTPException(404, "Approval not found")
    resolved = database.resolve_approval(approval_id, body.verdict, body.reason)
    if resolved is None:
        raise HTTPException(409, "Approval already resolved")
    return dict(resolved)


# ── Export / import user YAML ───────────────────────────────────────────────


@app.get("/export")
async def export_user_yaml(request: Request):
    """Return user's classes + entities + rules as a single YAML document."""
    email = _require_session(request)
    user_classes = user_engine._load_user_classes_list(email)
    entities, ids = _load_entities_with_ids(email)
    rules = user_engine.load_user_rules(email)

    doc = {
        "classes": user_classes,
        "entities": [
            {
                "id": eid,
                "class": e.class_name,
                "name": e.name,
                "attributes": dict(e.attrs),
            }
            for eid, e in zip(ids, entities)
        ],
        "rules": [r.to_dict() for r in rules],
    }
    body = (
        f"# ZPR Policy Maker — user export\n# account: {email}\n\n"
        + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
    )
    return Response(
        content=body,
        media_type="application/x-yaml; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="zpr-{email.split("@")[0]}.yaml"'
        },
    )


@app.get("/export/zpl")
async def export_zpl(request: Request, scope: str = "all"):
    """Return user classes and/or rules as ZPL text.

    scope: 'classes' | 'rules' | 'all'
    """
    email = _require_session(request)
    parts: list[str] = []
    if scope in ("classes", "all"):
        schema = user_engine.load_user_schema(email)
        classes = [c for c in schema._raw.values() if not c.get("builtin")]
        zpl = zpl_serializer.classes_to_zpl(classes)
        if zpl:
            parts.append("# Class Definitions\n\n" + zpl)
    if scope in ("rules", "all"):
        rules = user_engine.load_user_rules(email)
        zpl = zpl_serializer.rules_to_zpl([r.to_dict() for r in rules])
        if zpl:
            parts.append("# Rules\n\n" + zpl)
    return Response(content="\n\n".join(parts) or "# (nothing to export)", media_type="text/plain; charset=utf-8")


class ImportIn(BaseModel):
    yaml_text: str
    replace: bool = False


@app.post("/import")
async def import_user_yaml(body: ImportIn, request: Request):
    """Import classes / entities / rules from a YAML document.

    ``replace=true`` wipes existing non-protected items first.
    Sections that aren't present in the uploaded YAML are left untouched.
    """
    email = _require_session(request)
    try:
        data = yaml.safe_load(body.yaml_text) or {}
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Invalid YAML: {e}")
    if not isinstance(data, dict):
        raise HTTPException(
            400, "YAML must be a mapping with classes / entities / rules keys"
        )

    loaded = {"classes": 0, "entities": 0, "rules": 0}

    if "classes" in data:
        new_classes = data.get("classes") or []
        if not isinstance(new_classes, list):
            raise HTTPException(400, "'classes' must be a list")
        if not body.replace:
            existing = user_engine._load_user_classes_list(email)
            by_name = {c.get("class"): c for c in existing if c.get("class")}
            for c in new_classes:
                if c.get("class"):
                    by_name[c["class"]] = c
            new_classes = list(by_name.values())
        try:
            user_engine.save_user_classes(email, new_classes)
            user_engine.load_user_schema(email)  # validate
        except ClassSchemaError as e:
            raise HTTPException(400, f"Class import failed: {e}")
        loaded["classes"] = len(new_classes)

    if "entities" in data:
        entries = data.get("entities") or []
        if not isinstance(entries, list):
            raise HTTPException(400, "'entities' must be a list")
        schema = user_engine.load_user_schema(email)
        if body.replace:
            existing_entities: list[Entity] = []
            existing_ids: list[str] = []
        else:
            existing_entities, existing_ids = _load_entities_with_ids(email)
        existing_names = {e.name for e in existing_entities if e.name}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cls_name = entry.get("class")
            if not cls_name or not schema.has(cls_name):
                raise HTTPException(
                    400, f"Entity refers to unknown class: {cls_name!r}"
                )
            nm = entry.get("name") or None
            if nm and nm in existing_names and not body.replace:
                continue  # skip duplicate silently
            existing_entities.append(
                Entity(
                    class_name=cls_name,
                    name=nm,
                    attrs=dict(entry.get("attributes") or {}),
                )
            )
            existing_ids.append(entry.get("id") or uuid.uuid4().hex)
            if nm:
                existing_names.add(nm)
        user_engine.save_user_entities(email, existing_entities, ids=existing_ids)
        loaded["entities"] = len(entries)

    if "rules" in data:
        new_rules_raw = data.get("rules") or []
        if not isinstance(new_rules_raw, list):
            raise HTTPException(400, "'rules' must be a list")
        new_rules = [Rule.from_dict(r) for r in new_rules_raw]
        if body.replace:
            current = user_engine.load_user_rules(email)
            current = [r for r in current if r.protected]
        else:
            current = user_engine.load_user_rules(email)
        existing_ids_set = {r.id for r in current}
        for r in new_rules:
            if r.id in existing_ids_set:
                continue
            current.append(r)
            existing_ids_set.add(r.id)
        user_engine.save_user_rules(email, current)
        loaded["rules"] = len(new_rules)

    return {"loaded": loaded}


# ── AI: natural-language rule creation ──────────────────────────────────────


class ChatIn(BaseModel):
    """Body for POST /chat."""
    message: str
    history: list[dict] = Field(default_factory=list)  # optional prior turns
    model: str | None = None  # optional model override


def _build_chat_system_prompt(email: str) -> str:
    """Load create_rule.md and inject the user's live class tree + entities + rules."""
    template_path = DEFAULTS_DIR.parent / "prompts" / "create_rule.md"
    if not template_path.exists():
        raise HTTPException(500, "prompts/create_rule.md not found")
    template = template_path.read_text()

    schema = user_engine.load_user_schema(email)
    entities = user_engine.load_user_entities(email)
    rules = user_engine.load_user_rules(email)

    # Class tree rendering — indented by depth
    def render_class(cls_name: str, depth: int) -> list[str]:
        cls = schema.get(cls_name)
        attrs = cls.get("attributes") or {}
        attr_summary = ", ".join(
            f"{k}:{spec.get('type', '?')}" for k, spec in attrs.items()
        )
        marker = "  " * depth + ("- " if depth > 0 else "")
        line = f"{marker}{cls_name}"
        if attr_summary:
            line += f"   ({attr_summary})"
        if cls.get("builtin"):
            line += "  [built-in]"
        out = [line]
        for child in schema.children(cls_name):
            out.extend(render_class(child, depth + 1))
        return out

    tree_lines: list[str] = []
    for root in ("users", "endpoints", "services"):
        if schema.has(root):
            tree_lines.extend(render_class(root, 0))
    tree_block = "\n".join(tree_lines) if tree_lines else "(empty)"

    if entities:
        entity_lines = []
        for e in entities:
            if not e.name:
                continue
            a = ", ".join(f"{k}={v}" for k, v in (e.attrs or {}).items())
            entity_lines.append(f"- **{e.name}** ({e.class_name}) {a}")
        entity_block = "\n".join(entity_lines) if entity_lines else "(none)"
    else:
        entity_block = "(none)"

    if rules:
        rule_lines = []
        for r in rules:
            subj = r.subject.to_dict() if r.subject else None
            obj = r.object.to_dict() if r.object else None
            rule_lines.append(
                f"- [{r.result} prio {r.priority}] **{r.name}** — "
                f"subject={subj} → object={obj}"
            )
        rules_block = "\n".join(rule_lines)
    else:
        rules_block = "(none — this is a fresh rule set)"

    return (
        template.replace("{{CLASS_TREE}}", tree_block)
        .replace("{{ENTITIES}}", entity_block)
        .replace("{{RULES}}", rules_block)
    )


@app.post("/chat")
async def chat(body: ChatIn, request: Request):
    email = _require_session(request)
    if not ai_client.available():
        raise HTTPException(
            503, "ANTHROPIC_API_KEY is not set — AI features are unavailable."
        )
    if not body.message.strip():
        raise HTTPException(400, "message is required")

    system = _build_chat_system_prompt(email)

    # Build the message thread: prior history + new user message
    messages: list[dict] = []
    for turn in body.history:
        role = turn.get("role")
        text = turn.get("content") or ""
        if role in ("user", "assistant") and text:
            messages.append({"role": role, "content": text})
    messages.append({"role": "user", "content": body.message})

    try:
        reply = ai_client.complete(system, messages, model=body.model or ai_client.ANTHROPIC_MODEL)
    except Exception as e:
        raise HTTPException(502, f"AI call failed: {e}")

    proposals = ai_client.extract_json_blocks(reply, "PROPOSED_RULE")
    prose = ai_client.strip_tagged_blocks(reply, "PROPOSED_RULE")

    return {
        "reply": prose or reply,
        "proposals": proposals,
    }


# ── Getting Started content ─────────────────────────────────────────────────


@app.get("/chat/prompt")
async def get_chat_prompt(request: Request):
    _require_session(request)
    path = DEFAULTS_DIR.parent / "prompts" / "create_rule.md"
    if not path.exists():
        raise HTTPException(404, "Prompt not found")
    return {"name": "ZPR Rule Creator", "content": path.read_text()}


class ScenarioIn(BaseModel):
    scenario: str
    history: list[dict] = []  # [{role: "user"|"assistant", content: "..."}]


@app.post("/scenario/evaluate")
async def scenario_evaluate(request: Request, body: ScenarioIn):
    email = _require_session(request)
    if not ai_client.available():
        raise HTTPException(503, "AI not configured (ANTHROPIC_API_KEY missing)")

    prompt_path = _server_dir / "prompts" / "scenario_prompt.txt"
    if not prompt_path.exists():
        raise HTTPException(500, "prompts/scenario_prompt.txt not found")

    rules_yaml = database.get_rules_yaml(email)
    classes_yaml = database.get_classes_yaml(email)

    system = (
        prompt_path.read_text()
        .replace("{rules_yaml}", rules_yaml)
        .replace("{classes_yaml}", classes_yaml)
    )

    # Scenario is always the first user turn; history follows
    messages: list[dict] = [{"role": "user", "content": body.scenario}]
    _unknown_answers = {"unknown", "don't know", "dont know", "not sure", "unsure", "no idea", "n/a"}
    for turn in body.history:
        content = turn["content"]
        # If the user said they don't know, append a hard stop instruction
        if turn["role"] == "user" and content.strip().lower() in _unknown_answers:
            content = (
                f"{content}\n\n"
                "[The user cannot provide this information. "
                "Do not ask any further questions. "
                "Output <SCENARIO_SPECS> now using only the attributes confirmed so far. "
                "Treat any unconfirmed attributes as absent.]"
            )
        messages.append({"role": turn["role"], "content": content})

    raw = ai_client.complete(system=system, messages=messages, max_tokens=2048, temperature=0.1)

    # Policy query — Claude analysed the rules directly
    policy_queries = ai_client.extract_json_blocks(raw, "SCENARIO_POLICY_QUERY")
    if policy_queries:
        return {"type": "policy_query", **policy_queries[0]}

    # Claude asks for more information
    questions = ai_client.extract_json_blocks(raw, "SCENARIO_QUESTION")
    if questions:
        return {"type": "question", **questions[0]}

    # Claude has extracted entity specs — run through the authoritative engine
    specs_list = ai_client.extract_json_blocks(raw, "SCENARIO_SPECS")
    if specs_list:
        specs = specs_list[0]
        engine = user_engine.load_engine(email)
        entities = user_engine.load_user_entities(email)
        index = user_engine.build_entity_index(entities)

        cr = CheckRequest(
            subject=_resolve_slot(specs.get("subject"), index),
            object=_resolve_slot(specs.get("object"), index),
            verb=specs.get("verb"),
            accessor_endpoint=_resolve_slot(specs.get("accessor_endpoint"), index),
            server_endpoint=_resolve_slot(specs.get("server_endpoint"), index),
        )
        result = engine.evaluate(cr)

        trace = []
        for t in result.trace:
            if t.matched and t.result == "never":
                tr_result = "overridden"
            elif t.matched:
                tr_result = "matched"
            else:
                tr_result = "skipped"
            # First failing slot reason (or first slot reason if matched)
            slot_notes = [sm.reason for sm in t.slot_matches.values() if sm.reason]
            note = slot_notes[0] if slot_notes else ""
            trace.append({
                "rule_id":   t.rule_id,
                "rule_name": t.rule_name,
                "priority":  t.priority,
                "result":    tr_result,
                "note":      note,
            })
        return {
            "type":              "verdict",
            "verdict":           result.verdict.upper(),
            "matched_rule_id":   result.rule_id,
            "matched_rule_name": result.rule_name,
            "reason":            f"Rule '{result.rule_name}' matched." if result.rule_id else "No rule matched — default deny.",
            "refined_description": specs.get("refined_description", body.scenario),
            "rules_checked":     trace,
        }

    # Fallback: treat full response as a question
    return {"type": "question", "question": raw, "why": "", "refined_description": body.scenario}


class TestSuiteIn(BaseModel):
    positive_tests: list[dict] = []
    allow_tests: list[dict] = []
    n_adversarial: int = 0


@app.post("/policies/build-test-suite")
async def build_test_suite(request: Request, body: TestSuiteIn):
    email = _require_session(request)
    if not ai_client.available():
        raise HTTPException(503, "AI not configured (ANTHROPIC_API_KEY missing)")

    prompt_path = _server_dir / "prompts" / "build_test_suite_prompt.txt"
    if not prompt_path.exists():
        raise HTTPException(500, "prompts/build_test_suite_prompt.txt not found")

    import json as _json

    template = prompt_path.read_text()
    prompt = template.format(
        n_adversarial=body.n_adversarial,
        positive_tests_json=_json.dumps(body.positive_tests, indent=2),
        allow_tests_json=_json.dumps(body.allow_tests, indent=2),
    )

    raw = ai_client.complete(
        system="You are a ZPL policy test suite generator. Return only valid JSON.",
        messages=[{"role": "user", "content": prompt}],
        model="claude-haiku-4-5-20251001",
        max_tokens=4096,
        temperature=0.4,
    )
    try:
        suite = _json.loads(raw)
    except _json.JSONDecodeError:
        import re as _re

        m = _re.search(r"\{.*\}", raw, _re.DOTALL)
        if m:
            try:
                suite = _json.loads(m.group(0))
            except _json.JSONDecodeError:
                suite = None
        else:
            suite = None
        if suite is None:
            raise HTTPException(500, "AI returned invalid JSON")

    # Verify adversarial counter-tests against the live engine.
    # A mutation might accidentally match a different allow rule, producing verdict
    # "allow" instead of the expected "deny". Drop any that don't actually deny.
    counter_tests = suite.get("counter_tests") or []
    if counter_tests:
        engine = user_engine.load_engine(email)
        entities = user_engine.load_user_entities(email)
        index = user_engine.build_entity_index(entities)
        verified = []
        for ct in counter_tests:
            payload = ct.get("payload") or {}
            try:
                cr = CheckRequest(
                    subject=_resolve_slot(payload.get("subject"), index),
                    object=_resolve_slot(payload.get("object"), index),
                    verb=payload.get("verb"),
                    accessor_endpoint=_resolve_slot(payload.get("accessor_endpoint"), index),
                    server_endpoint=_resolve_slot(payload.get("server_endpoint"), index),
                )
                result = engine.evaluate(cr)
                if result.verdict == "deny":
                    verified.append(ct)
            except Exception:
                pass  # malformed payload — silently drop
        suite["counter_tests"] = verified

    return suite


@app.get("/getting-started")
async def getting_started(request: Request):
    email = _require_session(request)
    path = DEFAULTS_DIR / "getting_started.md"
    if not path.exists():
        raise HTTPException(404, "getting_started.md not found")
    text = path.read_text().replace("{{user}}", email.split("@")[0])
    return Response(content=text, media_type="text/markdown; charset=utf-8")


# ── Load example data ───────────────────────────────────────────────────────


def _read_yaml_defaults(filename: str) -> dict:
    path = DEFAULTS_DIR / filename
    if not path.exists():
        raise HTTPException(500, f"Missing defaults file: {filename}")
    with open(path) as f:
        return yaml.safe_load(f) or {}


@app.post("/classes/load-example")
async def load_example_classes(request: Request, replace: bool = False):
    """Load the RFC-15.5 example subclasses (employee, database, laptop, etc.).

    Query ``?replace=true`` wipes existing user-defined classes first.
    """
    email = _require_session(request)
    data = _read_yaml_defaults("example_classes.yaml")
    entries = data.get("classes") or []

    existing = user_engine._load_user_classes_list(email)
    if replace:
        existing = []
    existing_names = {c["class"] for c in existing}

    added: list[str] = []
    for entry in entries:
        name = entry.get("class")
        if not name or name in existing_names:
            continue
        existing.append(entry)
        existing_names.add(name)
        added.append(name)

    user_engine.save_user_classes(email, existing)
    return {"loaded": len(added), "classes": added}


@app.post("/entities/load-example")
async def load_example_entities(request: Request, replace: bool = False):
    """Load the example entity roster (Ted, Alice, Timesheet-database, …).

    Query ``?replace=true`` wipes the existing roster first; otherwise new
    entities are appended and name conflicts raise 409.
    """
    email = _require_session(request)
    data = _read_yaml_defaults("example_entities.yaml")
    entries = data.get("entities") or []
    existing, existing_ids = _load_entities_with_ids(email)

    if replace:
        existing, existing_ids = [], []

    existing_names = {e.name for e in existing if e.name}
    added: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cls_name = entry.get("class")
        if not cls_name:
            continue
        nm = entry.get("name") or None
        if nm and nm in existing_names:
            continue  # skip duplicates silently
        e = Entity(
            class_name=cls_name,
            name=nm,
            attrs=dict(entry.get("attributes") or {}),
        )
        existing.append(e)
        existing_ids.append(entry.get("id") or uuid.uuid4().hex)
        if nm:
            existing_names.add(nm)
        added.append(_entity_to_dict(existing_ids[-1], e))

    user_engine.save_user_entities(email, existing, ids=existing_ids)
    return {"loaded": len(added), "entities": added}


@app.post("/policies/load-example")
async def load_example_policies(request: Request, replace: bool = False):
    """Load the example rule set.

    Query ``?replace=true`` wipes existing (non-protected) rules first.
    """
    email = _require_session(request)
    data = _read_yaml_defaults("example_rules.yaml")
    entries = data.get("rules") or []

    current = user_engine.load_user_rules(email)
    if replace:
        current = [r for r in current if r.protected]

    existing_ids = {r.id for r in current}
    added: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rid = entry.get("id") or uuid.uuid4().hex
        if rid in existing_ids:
            continue  # skip duplicates
        rule = Rule.from_dict(entry)
        rule.id = rid
        current.append(rule)
        existing_ids.add(rid)
        added.append(rule.to_dict())

    user_engine.save_user_rules(email, current)
    return {"loaded": len(added), "rules": added}


# ── ZPL text parse → import ─────────────────────────────────────────────────


class ZPLParseIn(BaseModel):
    zpl_text: str
    replace: bool = False
    import_classes: bool = True
    import_rules: bool = True
    dry_run: bool = False


@app.post("/policies/parse-zpl")
async def parse_zpl(body: ZPLParseIn, request: Request):
    """Parse a ZPL text document and import the resulting classes and rules.

    Returns counts of classes and rules added.  Pass ``replace=true`` to wipe
    existing user-defined classes and non-protected rules first.
    """
    email = _require_session(request)
    try:
        parsed = zpl_parser.parse(body.zpl_text)
    except ValueError as exc:
        raise HTTPException(400, f"ZPL parse error: {exc}") from exc
    parse_errors = parsed.get("errors") or []

    schema = user_engine.load_user_schema(email)
    added_classes: list[str] = []
    added_rules: list[dict] = []

    # ── Import classes ──────────────────────────────────────────────────────
    raw_classes = parsed.get("classes") or []
    if raw_classes and body.import_classes:
        current = user_engine._load_user_classes_list(email)
        if body.replace:
            current = []
        existing_names = {c["class"] for c in current}
        for cls in raw_classes:
            name = cls.get("class")
            if not name or name in existing_names:
                continue
            current.append(cls)
            existing_names.add(name)
            added_classes.append(name)
        if not body.dry_run:
            user_engine.save_user_classes(email, current)

    # ── Import rules ────────────────────────────────────────────────────────
    raw_rules = parsed.get("rules") or []
    if raw_rules and body.import_rules:
        current_rules = user_engine.load_user_rules(email)
        if body.replace:
            current_rules = [r for r in current_rules if r.protected]
        existing_ids = {r.id for r in current_rules}
        for entry in raw_rules:
            if not isinstance(entry, dict):
                continue
            rid = entry.get("id") or uuid.uuid4().hex
            if rid in existing_ids:
                continue
            rule = Rule.from_dict(entry)
            rule.id = rid
            current_rules.append(rule)
            existing_ids.add(rid)
            added_rules.append(rule.to_dict())
        if not body.dry_run:
            user_engine.save_user_rules(email, current_rules)

    return {
        "classes_added": len(added_classes),
        "rules_added": len(added_rules),
        "classes": added_classes,
        "rules": added_rules,
        "errors": parse_errors,
    }


# ── Admin ───────────────────────────────────────────────────────────────────


@app.get("/admin/users")
async def admin_list_users(request: Request):
    _require_admin(request)
    return {"users": database.get_all_users_with_activity()}


@app.delete("/admin/users/{target_email}")
async def admin_delete_user(target_email: str, request: Request):
    _require_admin(request)
    database.delete_user(target_email)
    return {"deleted": True}
