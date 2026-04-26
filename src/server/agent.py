"""Conversational policy agent — natural language → Common IR.

The agent holds a multi-turn conversation with the user.  It extracts policy
intent and emits structured JSON (PolicySet IR) wrapped in <POLICY_SET> tags.
The surrounding prose is returned to the user as the visible response.

Entry point:
  chat(messages, language) → (reply_text, policy_set_or_None)
"""
from __future__ import annotations

import json
from pathlib import Path

from ai_client import complete, extract_json_blocks, strip_tagged_blocks
from ir_schema import (
    AttributeSpec,
    ClassDefinition,
    Conditions,
    ObjectSpec,
    PolicySet,
    PolicyStatement,
    SubjectSpec,
)

# ── System prompt ─────────────────────────────────────────────────────────────

_PROMPT_FILE = Path(__file__).parent / "prompts" / "agent_system.md"


def _load_system() -> str:
    return _PROMPT_FILE.read_text()


# ── Chat entry point ──────────────────────────────────────────────────────────

def chat(
    messages: list[dict[str, str]],
    language: str = "zpl",
) -> tuple[str, PolicySet | None]:
    """Run one turn of the policy agent conversation.

    Args:
        messages: Full conversation history as [{"role": "user"|"assistant",
                  "content": "..."}].  The latest user message must be last.
        language: "zpl" or "zpel" — hints the agent toward the appropriate syntax.

    Returns:
        (reply_text, policy_set)
        reply_text   — visible prose to show the user
        policy_set   — parsed PolicySet if the agent emitted one, else None
    """
    system = _load_system() + f"\n\nThe user's preferred output language is: {language.upper()}\n"

    raw = complete(system=system, messages=messages, max_tokens=4096, temperature=0.2)

    # Extract any PolicySet block
    policy_set: PolicySet | None = None
    blocks = extract_json_blocks(raw, "POLICY_SET")
    if blocks:
        try:
            policy_set = _parse_policy_set(blocks[-1])
        except Exception:
            pass  # malformed JSON — leave policy_set as None

    reply = strip_tagged_blocks(raw, "POLICY_SET").strip()
    return reply, policy_set


# ── PolicySet JSON → IR ───────────────────────────────────────────────────────

def _parse_policy_set(data: dict) -> PolicySet:
    """Parse the agent-emitted JSON dict into a PolicySet.

    The agent uses a simplified schema (no id fields, abbreviated attribute
    specs, etc.).  We normalise it into the full IR here.
    """
    classes = []
    for c in data.get("classes") or []:
        raw_attrs = c.get("attributes") or {}
        attributes: dict[str, AttributeSpec] = {}
        for k, v in raw_attrs.items():
            if isinstance(v, dict):
                attr_type = v.get("type", "single")
                # Normalise legacy "tag" type — tags are now just multi attrs named "tags"
                if attr_type == "tag":
                    attr_type = "multi"
                attributes[k] = AttributeSpec(
                    type=attr_type,
                    value=v.get("value"),
                    values=v.get("values") or [],
                )
            elif isinstance(v, str):
                attributes[k] = AttributeSpec(type="single", value=v)
        classes.append(ClassDefinition(
            name=c.get("name", ""),
            parent=c.get("parent", ""),
            aka=c.get("aka"),
            attributes=attributes,
            description=c.get("description", ""),
        ))

    rules = []
    for s in data.get("rules") or data.get("statements") or []:
        subject = _parse_spec_subject(s.get("subject") or s.get("source") or {})
        obj = _parse_spec_object(s.get("object") or s.get("destination") or {})
        cond_data = s.get("conditions") or {}
        conditions = Conditions(
            vcn_scope=cond_data.get("vcn_scope"),
            protocol=cond_data.get("protocol"),
            connection_state=cond_data.get("connection_state"),
            icmp_type=cond_data.get("icmp_type"),
            icmp_code=cond_data.get("icmp_code"),
        )
        effect = s.get("effect", "allow")
        if effect not in ("allow", "deny"):
            effect = "deny" if effect == "never" else "allow"
        rules.append(PolicyStatement(
            name=s.get("name", ""),
            description=s.get("description", ""),
            effect=effect,
            priority=s.get("priority", 100),
            action=s.get("action", "access"),
            subject=subject if subject else None,
            object=obj if obj else None,
            conditions=conditions,
            source_language="natural",
        ))

    lang = data.get("language", "zpl")
    if lang not in ("zpl", "zpel", "mixed"):
        lang = "zpl"

    return PolicySet(
        name=data.get("name", "Untitled"),
        description=data.get("description", ""),
        language=lang,
        classes=classes,
        rules=rules,
    )


def _parse_spec_subject(d: dict) -> SubjectSpec:
    return SubjectSpec(
        cls=d.get("cls") or d.get("class"),
        name=d.get("name"),
        attrs=d.get("attrs") or {},
        attribute=d.get("attribute"),
        ip_cidr=d.get("ip_cidr"),
        all_endpoints=d.get("all_endpoints", False),
        osn=d.get("osn", False),
        group=d.get("group"),
        person=d.get("person"),
        agent=d.get("agent"),
        filters=d.get("filters") or {},
    )


def _parse_spec_object(d: dict) -> ObjectSpec:
    return ObjectSpec(
        cls=d.get("cls") or d.get("class"),
        name=d.get("name"),
        attrs=d.get("attrs") or {},
        attribute=d.get("attribute"),
        ip_cidr=d.get("ip_cidr"),
        all_endpoints=d.get("all_endpoints", False),
        osn=d.get("osn", False),
        tool=d.get("tool"),
        program=d.get("program"),
        path=d.get("path"),
        filters=d.get("filters") or {},
    )
