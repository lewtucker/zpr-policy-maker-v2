"""Common Policy IR — Pydantic v2 models.

The IR is the canonical representation for policies in ZPR Policy Maker v2.
ZPL and ZPEL text are *outputs* derived from this IR via translation adapters.
Natural language, ZPL text, and ZPEL text are all *inputs* that get normalised
into this IR by the respective parsers + normaliser.

Design notes:
  - SubjectSpec and ObjectSpec are unions of ZPL-style (cls/attrs), ZPEL-style
    (attribute / ip_cidr), and OC-style (group/person/agent/tool) fields.
    Each translator uses the fields relevant to its target language.
  - ClassDefinition is ZPL-specific (ZPEL has no class definitions).
  - PolicySet is the top-level document: zero or more classes + zero or more
    statements, tagged with the primary language they were authored in.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, model_serializer


def _uid() -> str:
    return uuid.uuid4().hex


# ── Endpoint specs ────────────────────────────────────────────────────────────

def _compact(d: dict) -> dict:
    """Drop None values, empty dicts/lists, and False booleans from a dict."""
    return {k: v for k, v in d.items()
            if v is not None and v is not False and v != {} and v != []}


class SubjectSpec(BaseModel):
    """Describes the subject (who is performing the action)."""

    # ZPL-style
    cls: str | None = None              # class name, e.g. "employee"
    name: str | None = None             # named entity, e.g. "Alice"
    attrs: dict[str, Any] = {}          # attribute filters, e.g. {"dept": "finance"}

    # ZPEL-style
    attribute: str | None = None        # security attribute "ns.key:value"
    ip_cidr: str | None = None          # IP address or CIDR block (quoted in ZPEL)
    all_endpoints: bool = False         # "all-endpoints" keyword
    osn: bool = False                   # "osn-services-ip-addresses"

    # OC-style
    group: str | None = None
    person: str | None = None
    agent: str | None = None

    # Per-endpoint filter conditions (ZPEL "with" clause on source endpoint)
    filters: dict[str, str] = {}        # e.g. {"protocol": "tcp/22"}

    @model_serializer
    def _serialize(self) -> dict:
        return _compact({k: getattr(self, k) for k in self.model_fields})


class ObjectSpec(BaseModel):
    """Describes the object (what is being acted upon)."""

    # ZPL-style
    cls: str | None = None
    name: str | None = None
    attrs: dict[str, Any] = {}

    # ZPEL-style
    attribute: str | None = None
    ip_cidr: str | None = None
    all_endpoints: bool = False
    osn: bool = False

    # OC-style
    tool: str | None = None             # Claude tool name, e.g. "Bash"
    program: str | None = None          # shell program, supports * glob
    path: str | None = None             # file path, supports ** glob

    # Per-endpoint filter conditions (ZPEL "with" clause on destination endpoint)
    filters: dict[str, str] = {}

    @model_serializer
    def _serialize(self) -> dict:
        return _compact({k: getattr(self, k) for k in self.model_fields})


class Conditions(BaseModel):
    """Statement-level conditions (not endpoint-specific)."""

    vcn_scope: str | None = None        # ZPEL: VCN security attribute ("in X VCN")
    protocol: str | None = None         # e.g. "tcp/1521", "tcp/999-11199", "icmp"
    connection_state: str | None = None # "stateless" | "stateful"
    icmp_type: str | None = None
    icmp_code: str | None = None

    @model_serializer
    def _serialize(self) -> dict:
        return _compact({k: getattr(self, k) for k in self.model_fields})


# ── Policy statement ──────────────────────────────────────────────────────────

class PolicyStatement(BaseModel):
    """A single policy rule in the Common IR."""

    id: str = Field(default_factory=_uid)
    name: str = ""
    description: str = ""

    effect: Literal["allow", "deny"]
    priority: int = 100

    # Subject → verb → object
    subject: SubjectSpec | None = None
    accessor_endpoint: SubjectSpec | None = None  # ZPL: "subject on <endpoint>"
    action: str = "access"                        # access|use|call|read|write|connect|execute
    object: ObjectSpec | None = None
    server_endpoint: ObjectSpec | None = None     # ZPL: "object on <server>"

    # Statement-level conditions
    conditions: Conditions = Field(default_factory=Conditions)

    # Provenance
    source_language: Literal["zpl", "zpel", "oc", "natural"] | None = None


# ── ZPL class definitions ──────────────────────────────────────────────────────

class AttributeSpec(BaseModel):
    """Specification for a single attribute within a ZPL class definition.

    Types:
      single — one unconstrained value (open string, or fixed via `value`)
      enum   — exactly one value from the `values` list (e.g. clearance, department)
      multi  — one or more values from the `values` list (e.g. groups, tags, roles)
    """

    type: Literal["single", "enum", "multi"] = "single"
    value: str | None = None    # fixed class-level value (single only, e.g. employee-type: intern)
    values: list[str] = []      # allowed values (enum: pick one; multi: pick many)

    @model_serializer
    def _serialize(self) -> dict:
        if self.type == "multi":
            return {"type": "multi", "values": self.values}
        if self.type == "enum":
            return {"type": "enum", "values": self.values}
        # single
        d: dict = {"type": "single"}
        if self.value is not None:
            d["value"] = self.value
        if self.values:
            d["values"] = self.values
        return d


class ClassDefinition(BaseModel):
    """A ZPL class definition (from a Define statement)."""

    id: str = Field(default_factory=_uid)
    name: str                           # ZPL class name, e.g. "employee"
    parent: str                         # parent class name, e.g. "users"
    aka: str | None = None
    attributes: dict[str, AttributeSpec] = {}
    builtin: bool = False
    is_verb: bool = False
    description: str = ""


# ── Policy set (top-level document) ──────────────────────────────────────────

class PolicySet(BaseModel):
    """A named collection of class definitions and policy rules."""

    id: str = Field(default_factory=_uid)
    name: str
    description: str = ""
    language: Literal["zpl", "zpel", "mixed"] = "zpl"

    # ZPL-specific: class hierarchy (empty for ZPEL-authored sets)
    classes: list[ClassDefinition] = []

    # Policy rules
    rules: list[PolicyStatement] = []

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Parse results ─────────────────────────────────────────────────────────────

class ParseError(BaseModel):
    line: int
    message: str
    source: str = ""


class ParseResult(BaseModel):
    """Outcome of parsing ZPL or ZPEL text."""

    language: Literal["zpl", "zpel"]
    policy_set: PolicySet
    errors: list[ParseError] = []
    raw_text: str = ""


# ── Simulator ─────────────────────────────────────────────────────────────────

class SimScenario(BaseModel):
    """A test case for the policy simulator."""

    id: str = Field(default_factory=_uid)
    description: str = ""
    subject: SubjectSpec
    action: str = "access"
    object: ObjectSpec
    conditions: Conditions = Field(default_factory=Conditions)


class SimResult(BaseModel):
    """Verdict for a single simulated scenario."""

    scenario_id: str
    description: str = ""
    verdict: Literal["allow", "deny"]
    matched_statement_id: str | None = None
    matched_statement_name: str = ""
    reason: str = ""


# ── Conversation (agent chat) ─────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class Conversation(BaseModel):
    id: str = Field(default_factory=_uid)
    policy_set_id: str | None = None    # associated PolicySet if one has been created
    messages: list[ChatMessage] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
