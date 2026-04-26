"""ZPR Policy Maker v2 — FastAPI server.

Endpoints
─────────
Auth
  GET  /login          login page
  POST /login          submit password
  POST /logout

API (all require auth)
  POST /api/parse      parse ZPL or ZPEL text → ParseResult
  POST /api/validate   syntax-check text → errors only
  POST /api/translate  PolicySet → ZPL or ZPEL text

  GET  /api/simulate/{policy_set_id}   list scenarios for a policy set
  POST /api/simulate/{policy_set_id}   run scenarios → SimResult list

  GET  /api/policy_sets              list all (summaries)
  POST /api/policy_sets              create from IR JSON
  GET  /api/policy_sets/{id}         get full PolicySet
  PUT  /api/policy_sets/{id}         replace PolicySet
  DELETE /api/policy_sets/{id}       delete

  GET  /api/conversations/{id}       get conversation
  POST /api/chat                     one agent turn (creates/updates conversation)

  GET  /api/language                 get active language setting
  POST /api/language                 set active language (zpl|zpel)

  GET  /                             SPA index
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel

load_dotenv()

import agent as agent_mod
import database as db
import ir_normalizer as norm
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
from zpl_engine import CheckRequest, Entity, Rule, ZPLEngine
from class_schema import ClassSchema

# ── Config ────────────────────────────────────────────────────────────────────

APP_PASSWORD = os.environ.get("APP_PASSWORD", "changeme")
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

# ── Auth helpers ──────────────────────────────────────────────────────────────

def _make_session_token() -> str:
    return _signer.dumps({"authenticated": True})


def _check_session(request: Request) -> bool:
    token = request.cookies.get("session")
    if not token:
        return False
    try:
        data = _signer.loads(token)
        return bool(data.get("authenticated"))
    except BadSignature:
        return False


def require_auth(request: Request) -> None:
    if not _check_session(request):
        raise HTTPException(status_code=401, detail="Not authenticated")


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return _login_html()


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    password = form.get("password", "")
    if password != APP_PASSWORD:
        return HTMLResponse(_login_html(error=True), status_code=401)
    response = Response(status_code=302, headers={"Location": "/"})
    response.set_cookie("session", _make_session_token(), httponly=True, samesite="lax")
    return response


@app.post("/logout")
async def logout():
    response = Response(status_code=302, headers={"Location": "/login"})
    response.delete_cookie("session")
    return response


# ── Parse ─────────────────────────────────────────────────────────────────────

class ParseRequest(BaseModel):
    text: str
    language: str = "zpl"   # "zpl" | "zpel"
    name: str = "Untitled"


@app.post("/api/parse")
async def parse_text(req: ParseRequest, _: None = Depends(require_auth)):
    lang = req.language.lower()
    if lang == "zpl":
        raw = zpl_parser.parse(req.text)
        ps, errors = norm.zpl_to_policy_set(raw, name=req.name)
    elif lang == "zpel":
        raw = zpel_parser.parse(req.text)
        ps, errors = norm.zpel_to_policy_set(raw, name=req.name)
    else:
        raise HTTPException(400, f"Unknown language: {req.language!r}")

    return {
        "language": lang,
        "policy_set": ps.model_dump(mode="json"),
        "errors": [e.model_dump() for e in errors],
    }


@app.post("/api/validate")
async def validate_text(req: ParseRequest, _: None = Depends(require_auth)):
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


# ── Translate ─────────────────────────────────────────────────────────────────

class TranslateRequest(BaseModel):
    policy_set: dict
    target: str   # "zpl" | "zpel"


@app.post("/api/translate")
async def translate(req: TranslateRequest, _: None = Depends(require_auth)):
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
    """Render a PolicySet to ZPL text via the existing serializer."""
    # Convert IR ClassDefinitions → raw dicts for zpl_serializer
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
    # Convert IR PolicyStatements → raw rule dicts for zpl_serializer
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


# ── Simulate ──────────────────────────────────────────────────────────────────

class SimRequest(BaseModel):
    scenarios: list[dict]


@app.post("/api/simulate/{policy_set_id}")
async def simulate(
    policy_set_id: str,
    req: SimRequest,
    _: None = Depends(require_auth),
):
    ps = await db.get_policy_set(policy_set_id)
    if ps is None:
        raise HTTPException(404, "Policy set not found")

    results = []
    for scenario_data in req.scenarios:
        try:
            scenario = SimScenario.model_validate(scenario_data)
        except Exception as exc:
            results.append({"error": str(exc)})
            continue

        if ps.language == "zpel":
            result = _simulate_zpel(ps, scenario)
        else:
            result = _simulate_zpl(ps, scenario)
        results.append(result.model_dump(mode="json"))

    return {"results": results}


_SYSTEM_CLASSES_PATH = Path(__file__).parent / "defaults" / "system_classes.yaml"


def _build_schema(ps: PolicySet) -> ClassSchema:
    """Merge system classes with PolicySet class definitions into a ClassSchema."""
    import yaml
    system = yaml.safe_load(_SYSTEM_CLASSES_PATH.read_text())
    system_classes = system.get("classes", [])
    user_classes = [
        {
            "class": c.name,
            "parent": c.parent,
            "aka": c.aka,
            "builtin": c.builtin,
            "attributes": {k: v.model_dump(exclude_none=True) for k, v in c.attributes.items()},
        }
        for c in ps.classes
    ]
    # User classes override system classes of the same name
    system_names = {c["class"] for c in system_classes}
    merged = system_classes + [c for c in user_classes if c["class"] not in system_names]
    return ClassSchema(merged)


def _simulate_zpl(ps: PolicySet, scenario: SimScenario) -> SimResult:
    """Evaluate a ZPL scenario using ZPLEngine."""
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
    """Evaluate a ZPEL scenario by matching VCN scope + endpoint attributes."""
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
async def list_policy_sets(_: None = Depends(require_auth)):
    return await db.list_policy_sets()


@app.post("/api/policy_sets", status_code=201)
async def create_policy_set(data: dict, _: None = Depends(require_auth)):
    try:
        ps = PolicySet.model_validate(data)
    except Exception as exc:
        raise HTTPException(400, f"Invalid PolicySet: {exc}")
    ps = await db.save_policy_set(ps)
    return ps.model_dump(mode="json")


@app.get("/api/policy_sets/{policy_set_id}")
async def get_policy_set(policy_set_id: str, _: None = Depends(require_auth)):
    ps = await db.get_policy_set(policy_set_id)
    if ps is None:
        raise HTTPException(404, "Not found")
    return ps.model_dump(mode="json")


@app.put("/api/policy_sets/{policy_set_id}")
async def update_policy_set(
    policy_set_id: str, data: dict, _: None = Depends(require_auth)
):
    existing = await db.get_policy_set(policy_set_id)
    if existing is None:
        raise HTTPException(404, "Not found")
    try:
        ps = PolicySet.model_validate({**data, "id": policy_set_id})
    except Exception as exc:
        raise HTTPException(400, f"Invalid PolicySet: {exc}")
    ps = await db.save_policy_set(ps)
    return ps.model_dump(mode="json")


@app.delete("/api/policy_sets/{policy_set_id}", status_code=204)
async def delete_policy_set(policy_set_id: str, _: None = Depends(require_auth)):
    deleted = await db.delete_policy_set(policy_set_id)
    if not deleted:
        raise HTTPException(404, "Not found")


# ── Agent chat ────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    conversation_id: str | None = None
    policy_set_id: str | None = None
    language: str = "zpl"


@app.post("/api/chat")
async def chat(req: ChatRequest, _: None = Depends(require_auth)):
    from ai_client import available

    if not available():
        raise HTTPException(503, "ANTHROPIC_API_KEY not configured")

    # Load or create conversation
    conv: Conversation
    if req.conversation_id:
        conv = await db.get_conversation(req.conversation_id) or Conversation()
    else:
        conv = Conversation()

    if req.policy_set_id:
        conv.policy_set_id = req.policy_set_id

    # Append user message
    conv.messages.append(ChatMessage(role="user", content=req.message))

    # Run agent
    history = [{"role": m.role, "content": m.content} for m in conv.messages]
    reply_text, policy_set = agent_mod.chat(history, language=req.language)

    # Append assistant reply
    conv.messages.append(ChatMessage(role="assistant", content=reply_text))

    # Persist conversation
    conv = await db.save_conversation(conv)

    # Persist updated PolicySet if agent emitted one
    saved_ps = None
    if policy_set is not None:
        if conv.policy_set_id:
            policy_set.id = conv.policy_set_id
        saved_ps = await db.save_policy_set(policy_set)
        conv.policy_set_id = saved_ps.id
        await db.save_conversation(conv)

    return {
        "conversation_id": conv.id,
        "reply": reply_text,
        "policy_set_id": conv.policy_set_id,
        "policy_set": saved_ps.model_dump(mode="json") if saved_ps else None,
    }


@app.get("/api/conversations/{conv_id}")
async def get_conversation(conv_id: str, _: None = Depends(require_auth)):
    conv = await db.get_conversation(conv_id)
    if conv is None:
        raise HTTPException(404, "Not found")
    return conv.model_dump(mode="json")


# ── Language setting ──────────────────────────────────────────────────────────

_active_language: str = "zpl"


@app.get("/api/language")
async def get_language(_: None = Depends(require_auth)):
    return {"language": _active_language}


class LanguageRequest(BaseModel):
    language: str


@app.post("/api/language")
async def set_language(req: LanguageRequest, _: None = Depends(require_auth)):
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
    """Render existing classes as a compact text block for prompt injection."""
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
    mode: str                              # "class" or "rule"
    messages: list[dict[str, str]]
    policy_set_id: str | None = None


class AssistAcceptRequest(BaseModel):
    mode: str                              # "class" or "rule"
    proposal: dict
    policy_set_id: str | None = None
    policy_set_name: str = "Untitled"


@app.post("/api/assist")
async def assist(req: AssistRequest, _: None = Depends(require_auth)):
    """One turn of the class or rule builder assistant."""
    from ai_client import complete, extract_json_blocks, strip_tagged_blocks

    # Load policy set for classes context
    ps: PolicySet | None = None
    if req.policy_set_id:
        try:
            ps = await db.get_policy_set(req.policy_set_id)
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
        # For rules, inject a zpl field if agent omitted it
        if req.mode == "rule" and "zpl" not in proposal:
            effect = "Allow" if proposal.get("effect") == "allow" else "Never allow"
            proposal["zpl"] = f"{effect} [see rule details]"

    reply = strip_tagged_blocks(raw, tag).strip()
    return {"reply": reply, "proposal": proposal}


@app.post("/api/assist/accept")
async def assist_accept(req: AssistAcceptRequest, _: None = Depends(require_auth)):
    """Accept a proposed class or rule into the current (or new) policy set."""
    from ir_schema import AttributeSpec, ClassDefinition, PolicyStatement

    # Load or create policy set
    ps: PolicySet | None = None
    if req.policy_set_id:
        try:
            ps = await db.get_policy_set(req.policy_set_id)
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
        # Replace if name already exists, otherwise append
        ps.classes = [c for c in ps.classes if c.name != cls.name] + [cls]

    else:  # rule
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

    ps = await db.save_policy_set(ps)
    return {"policy_set": ps.model_dump(mode="json"), "policy_set_id": ps.id}


class GenerateRulesRequest(BaseModel):
    n_allow: int = 3
    n_deny: int = 2
    focus_on: str = ""
    policy_set_id: str | None = None


@app.post("/api/assist/generate-rules")
async def assist_generate_rules(req: GenerateRulesRequest, _: None = Depends(require_auth)):
    """Generate a batch of allow/deny rules from the existing class vocabulary."""
    from ai_client import complete, extract_json_blocks, strip_tagged_blocks

    ps: PolicySet | None = None
    if req.policy_set_id:
        try:
            ps = await db.get_policy_set(req.policy_set_id)
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

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa(request: Request, full_path: str):
    if not _check_session(request):
        return Response(status_code=302, headers={"Location": "/login"})
    index = STATIC_DIR / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>ZPR Policy Maker v2</h1><p>Place index.html in static/</p>")


# ── Login HTML ────────────────────────────────────────────────────────────────

def _login_html(error: bool = False) -> str:
    err = '<p style="color:red">Incorrect password.</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ZPR Policy Maker v2 — Login</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
           display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
    .box {{ background: #1e293b; padding: 2rem; border-radius: 0.75rem; width: 320px; }}
    h1 {{ margin: 0 0 0.25rem; font-size: 1.25rem; }}
    p.sub {{ color: #94a3b8; font-size: 0.85rem; margin: 0 0 1.5rem; }}
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
    <h1>ZPR Policy Maker v2</h1>
    <p class="sub">Enter password to continue</p>
    {err}
    <form method="post" action="/login">
      <input type="password" name="password" placeholder="Password" autofocus>
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>"""
