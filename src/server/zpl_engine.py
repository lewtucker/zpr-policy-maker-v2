"""ZPL RFC-15.5 policy engine.

Pure evaluator: no I/O, no database, no network. Given a :class:`ClassSchema`,
a list of :class:`Rule` objects, and a :class:`CheckRequest`, returns a
:class:`CheckResult` with the verdict plus a per-rule trace for debugging.

Rule YAML shape::

    rules:
      - id: <uuid>
        name: Sales access customer DBs
        description: ...
        result: allow               # allow | never
        priority: 100               # higher = evaluated first
        verb: access                # null = any
        subject:                    # null = unconstrained
          class: employee
          attrs:
            department: sales
        accessor_endpoint:          # optional "on <endpoint>" before "to"
          class: laptop
          attrs: { managed: "*" }
        object:
          class: database           # or: name: Timesheet-database
          attrs: { data: customer }
        server_endpoint: null
        signal:                     # optional
          message: accessing
          to: Access-logger
        protected: false

Evaluation order::

    never rules (priority desc) → first match → deny
    allow rules (priority desc) → first match → allow
    no match                                  → deny (default)
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

import yaml

from class_schema import ClassSchema

# ── Data classes ────────────────────────────────────────────────────────────


@dataclass
class Spec:
    """One slot in a rule: class and/or named entity, plus attribute filters.

    A spec is satisfied when all of:
    - the entity's class equals ``class_name`` or descends from it (if set)
    - the entity's name equals ``name`` (if set)
    - every (attr → value) pair in ``attrs`` matches the entity's attrs
    """

    class_name: str | None = None
    name: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict | None) -> "Spec | None":
        if data is None:
            return None
        return cls(
            class_name=data.get("class"),
            name=data.get("name"),
            attrs=dict(data.get("attrs") or {}),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        if self.class_name:
            out["class"] = self.class_name
        if self.name:
            out["name"] = self.name
        if self.attrs:
            out["attrs"] = dict(self.attrs)
        return out


@dataclass
class Rule:
    id: str
    name: str
    result: Literal["allow", "never"]
    priority: int = 100
    verb: str | None = None
    subject: Spec | None = None
    accessor_endpoint: Spec | None = None
    object: Spec | None = None
    server_endpoint: Spec | None = None
    signal: dict | None = None
    description: str = ""
    protected: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        result = data.get("result")
        if result not in ("allow", "never"):
            raise ValueError(
                f"rule {data.get('id')!r} has invalid result: {result!r}"
            )
        return cls(
            id=data.get("id") or uuid.uuid4().hex,
            name=data.get("name") or "",
            result=result,
            priority=int(data.get("priority", 100)),
            verb=data.get("verb") or None,
            subject=Spec.from_dict(data.get("subject")),
            accessor_endpoint=Spec.from_dict(data.get("accessor_endpoint")),
            object=Spec.from_dict(data.get("object")),
            server_endpoint=Spec.from_dict(data.get("server_endpoint")),
            signal=data.get("signal") or None,
            description=data.get("description") or "",
            protected=bool(data.get("protected", False)),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "result": self.result,
            "priority": self.priority,
            "verb": self.verb,
            "subject": self.subject.to_dict() if self.subject else None,
            "accessor_endpoint": (
                self.accessor_endpoint.to_dict() if self.accessor_endpoint else None
            ),
            "object": self.object.to_dict() if self.object else None,
            "server_endpoint": (
                self.server_endpoint.to_dict() if self.server_endpoint else None
            ),
            "signal": dict(self.signal) if self.signal else None,
            "protected": self.protected,
        }


@dataclass
class Entity:
    """An instance: a class plus optional identity (name) plus concrete attrs."""

    class_name: str
    name: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckRequest:
    subject: Entity
    object: Entity
    verb: str
    accessor_endpoint: Entity | None = None
    server_endpoint: Entity | None = None


@dataclass
class SlotMatch:
    matched: bool
    reason: str = ""


@dataclass
class RuleTrace:
    rule_id: str
    rule_name: str
    result: str
    priority: int
    matched: bool
    slot_matches: dict[str, SlotMatch]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["slot_matches"] = {k: asdict(v) for k, v in self.slot_matches.items()}
        return d


@dataclass
class CheckResult:
    verdict: Literal["allow", "deny"]
    rule_id: str | None = None
    rule_name: str | None = None
    signal: dict | None = None
    trace: list[RuleTrace] = field(default_factory=list)


# ── Engine ──────────────────────────────────────────────────────────────────


class ZPLEngine:
    """Pure policy evaluator over a fixed rule set and class schema."""

    def __init__(self, rules: list[Rule], schema: ClassSchema):
        self.rules = list(rules)
        self.schema = schema

    # ── evaluation ──────────────────────────────────────────────────────

    def evaluate(self, request: CheckRequest) -> CheckResult:
        nevers = sorted(
            (r for r in self.rules if r.result == "never"),
            key=lambda r: -r.priority,
        )
        allows = sorted(
            (r for r in self.rules if r.result == "allow"),
            key=lambda r: -r.priority,
        )

        trace: list[RuleTrace] = []

        for rule in nevers:
            rt = self._match_rule(rule, request)
            trace.append(rt)
            if rt.matched:
                return CheckResult(
                    verdict="deny",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    signal=dict(rule.signal) if rule.signal else None,
                    trace=trace,
                )

        for rule in allows:
            rt = self._match_rule(rule, request)
            trace.append(rt)
            if rt.matched:
                return CheckResult(
                    verdict="allow",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    signal=dict(rule.signal) if rule.signal else None,
                    trace=trace,
                )

        return CheckResult(verdict="deny", trace=trace)

    # ── matchers ────────────────────────────────────────────────────────

    def _match_rule(self, rule: Rule, req: CheckRequest) -> RuleTrace:
        slot_matches = {
            "subject": self._match_spec("subject", rule.subject, req.subject),
            "accessor_endpoint": self._match_spec(
                "accessor_endpoint", rule.accessor_endpoint, req.accessor_endpoint
            ),
            "verb": self._match_verb(rule.verb, req.verb),
            "object": self._match_spec("object", rule.object, req.object),
            "server_endpoint": self._match_spec(
                "server_endpoint", rule.server_endpoint, req.server_endpoint
            ),
        }
        matched = all(sm.matched for sm in slot_matches.values())
        return RuleTrace(
            rule_id=rule.id,
            rule_name=rule.name,
            result=rule.result,
            priority=rule.priority,
            matched=matched,
            slot_matches=slot_matches,
        )

    def _match_spec(
        self, slot: str, spec: Spec | None, entity: Entity | None
    ) -> SlotMatch:
        if spec is None:
            return SlotMatch(True, f"{slot}: unconstrained")
        if entity is None:
            return SlotMatch(False, f"{slot}: request has no entity, rule requires one")

        if spec.name is not None:
            if entity.name != spec.name:
                return SlotMatch(
                    False, f"{slot}: name {entity.name!r} ≠ {spec.name!r}"
                )

        if spec.class_name is not None:
            if not self.schema.has(entity.class_name):
                return SlotMatch(
                    False, f"{slot}: unknown entity class {entity.class_name!r}"
                )
            if not self.schema.has(spec.class_name):
                return SlotMatch(
                    False, f"{slot}: unknown rule class {spec.class_name!r}"
                )
            if not self.schema.is_subclass(entity.class_name, spec.class_name):
                return SlotMatch(
                    False,
                    f"{slot}: class {entity.class_name!r} is not a {spec.class_name!r}",
                )

        for attr_name, spec_value in spec.attrs.items():
            entity_value = entity.attrs.get(attr_name)
            if not _attr_matches(spec_value, entity_value):
                return SlotMatch(
                    False,
                    f"{slot}: attr {attr_name}={entity_value!r} "
                    f"does not match {spec_value!r}",
                )

        return SlotMatch(True, f"{slot}: match")

    @staticmethod
    def _match_verb(rule_verb: str | None, request_verb: str) -> SlotMatch:
        if not rule_verb:
            return SlotMatch(True, "verb: (any)")
        if rule_verb == request_verb:
            return SlotMatch(True, f"verb: {request_verb}")
        return SlotMatch(False, f"verb: {request_verb!r} ≠ {rule_verb!r}")


# ── Attribute match helper ──────────────────────────────────────────────────


def _attr_matches(spec_value: Any, entity_value: Any) -> bool:
    """Return True if ``entity_value`` satisfies the rule spec's ``spec_value``.

    Semantics:
      - ``spec_value == '*'``: entity must have the attribute (any value)
      - ``entity_value is None``: no attribute present → miss (unless wildcard)
      - otherwise: normalize both to sets and require non-empty intersection
        (so single-vs-multi and multi-vs-multi all collapse to set overlap)
    """
    if spec_value == "*":
        return entity_value is not None
    if entity_value is None:
        return False
    spec_set = set(spec_value) if isinstance(spec_value, list) else {spec_value}
    entity_set = (
        set(entity_value) if isinstance(entity_value, list) else {entity_value}
    )
    return bool(spec_set & entity_set)


# ── YAML helpers ────────────────────────────────────────────────────────────


def load_rules(yaml_str: str) -> list[Rule]:
    """Parse a ``rules:`` YAML document into a list of :class:`Rule` objects."""
    data = yaml.safe_load(yaml_str) or {}
    if not isinstance(data, dict):
        raise ValueError("rules YAML must be a mapping with a 'rules' key")
    entries = data.get("rules") or []
    if not isinstance(entries, list):
        raise ValueError("'rules' must be a list")
    return [Rule.from_dict(r) for r in entries]


def dump_rules(rules: list[Rule]) -> str:
    return yaml.safe_dump(
        {"rules": [r.to_dict() for r in rules]},
        sort_keys=False,
        default_flow_style=False,
    )
