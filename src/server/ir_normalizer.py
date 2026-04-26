"""Normaliser — language-specific parser output → Common IR (PolicySet).

Two public functions:
  zpl_to_policy_set(raw, name)   — ZPL parser output → PolicySet
  zpel_to_policy_set(raw, name)  — ZPEL parser output → PolicySet

'raw' is the dict returned by zpl_parser.parse() or zpel_parser.parse().
Both functions return a PolicySet (Common IR) and a list of ParseErrors.
"""
from __future__ import annotations

from typing import Any

from ir_schema import (
    AttributeSpec,
    ClassDefinition,
    Conditions,
    ObjectSpec,
    ParseError,
    PolicySet,
    PolicyStatement,
    SubjectSpec,
)


# ── ZPL → Common IR ───────────────────────────────────────────────────────────

def zpl_to_policy_set(raw: dict[str, Any], name: str = "Untitled") -> tuple[PolicySet, list[ParseError]]:
    """Convert zpl_parser.parse() output to a PolicySet.

    ZPL parser produces::

        {
          "classes": [{"class": "employee", "parent": "users", "attributes": {...}}],
          "rules":   [{"id": "...", "result": "allow"|"never", "verb": "access",
                       "subject": {...}, "object": {...},
                       "accessor_endpoint": {...}, "server_endpoint": {...}}],
          "errors":  [{"line": N, "message": "..."}]
        }
    """
    errors = [ParseError(line=e["line"], message=e["message"], source=e.get("source", ""))
              for e in raw.get("errors", [])]

    classes = [_zpl_class(c) for c in raw.get("classes", [])]
    rules = [_zpl_rule(r) for r in raw.get("rules", [])]

    ps = PolicySet(
        name=name,
        language="zpl",
        classes=classes,
        rules=rules,
    )
    return ps, errors


def _zpl_class(c: dict) -> ClassDefinition:
    raw_attrs = c.get("attributes") or {}
    attributes: dict[str, AttributeSpec] = {}
    for attr_name, spec in raw_attrs.items():
        if not isinstance(spec, dict):
            continue
        attributes[attr_name] = AttributeSpec(
            type=spec.get("type", "single"),
            value=spec.get("value"),
            values=spec.get("values") or [],
            optional=spec.get("optional", False),
        )
    return ClassDefinition(
        name=c.get("class", ""),
        parent=c.get("parent") or "",
        aka=c.get("aka"),
        attributes=attributes,
        builtin=c.get("builtin", False),
    )


def _zpl_spec_to_subject(spec: dict | None) -> SubjectSpec | None:
    if not spec:
        return None
    attrs: dict[str, Any] = {}
    raw_attrs = spec.get("attrs") or {}
    for k, v in raw_attrs.items():
        attrs[k] = v
    return SubjectSpec(
        cls=spec.get("class"),
        name=spec.get("name"),
        attrs=attrs,
    )


def _zpl_spec_to_object(spec: dict | None) -> ObjectSpec | None:
    if not spec:
        return None
    attrs: dict[str, Any] = {}
    raw_attrs = spec.get("attrs") or {}
    for k, v in raw_attrs.items():
        attrs[k] = v
    return ObjectSpec(
        cls=spec.get("class"),
        name=spec.get("name"),
        attrs=attrs,
    )


def _zpl_rule(r: dict) -> PolicyStatement:
    effect = "deny" if r.get("result") == "never" else "allow"
    subject = _zpl_spec_to_subject(r.get("subject"))
    accessor = _zpl_spec_to_subject(r.get("accessor_endpoint"))
    obj = _zpl_spec_to_object(r.get("object"))
    server = _zpl_spec_to_object(r.get("server_endpoint"))
    return PolicyStatement(
        id=r.get("id") or PolicyStatement.__fields__["id"].default_factory(),
        name=r.get("name", ""),
        effect=effect,
        priority=r.get("priority", 100),
        action=r.get("verb", "access"),
        subject=subject,
        accessor_endpoint=accessor,
        object=obj,
        server_endpoint=server,
        source_language="zpl",
    )


# ── ZPEL → Common IR ──────────────────────────────────────────────────────────

def zpel_to_policy_set(raw: dict[str, Any], name: str = "Untitled") -> tuple[PolicySet, list[ParseError]]:
    """Convert zpel_parser.parse() output to a PolicySet.

    ZPEL parser produces::

        {
          "rules": [
            {
              "vcn_attribute": "app:finance-network",
              "source": {"type": "attribute", "value": "app:frontend", "filters": {...}},
              "destination": {"type": "attribute", "value": "app:database", "filters": {...}}
            }
          ],
          "errors": [{"line": N, "message": "..."}]
        }

    ZPEL has no class definitions. All statements are allow (ZPEL is allowlist-only).
    Filters on source and destination endpoints are merged into Conditions.
    """
    errors = [ParseError(line=e["line"], message=e["message"])
              for e in raw.get("errors", [])]

    rules = [_zpel_statement(s, i) for i, s in enumerate(raw.get("rules", []))]

    ps = PolicySet(
        name=name,
        language="zpel",
        classes=[],
        rules=rules,
    )
    return ps, errors


def _zpel_endpoint_to_subject(ep: dict) -> SubjectSpec:
    t = ep.get("type", "attribute")
    if t == "all-endpoints":
        return SubjectSpec(all_endpoints=True)
    if t == "osn":
        return SubjectSpec(osn=True)
    if t == "ip_cidr":
        return SubjectSpec(ip_cidr=ep.get("value"))
    return SubjectSpec(attribute=ep.get("value"), filters=ep.get("filters") or {})


def _zpel_endpoint_to_object(ep: dict) -> ObjectSpec:
    t = ep.get("type", "attribute")
    if t == "all-endpoints":
        return ObjectSpec(all_endpoints=True)
    if t == "osn":
        return ObjectSpec(osn=True)
    if t == "ip_cidr":
        return ObjectSpec(ip_cidr=ep.get("value"))
    return ObjectSpec(attribute=ep.get("value"), filters=ep.get("filters") or {})


def _merge_filters(src_filters: dict, dst_filters: dict) -> Conditions:
    """Merge source + destination endpoint filters into statement-level Conditions.

    When the same filter appears on both endpoints, destination wins (matches spec
    semantics where connection attributes are shared but evaluated per-endpoint).
    """
    merged = {**src_filters, **dst_filters}
    return Conditions(
        vcn_scope=None,  # set by caller
        protocol=merged.get("protocol"),
        connection_state=merged.get("connection-state"),
        icmp_type=merged.get("protocol.icmp.type"),
        icmp_code=merged.get("protocol.icmp.code"),
    )


def _zpel_statement(s: dict, idx: int) -> PolicyStatement:
    source_ep = s.get("source") or {}
    dest_ep = s.get("destination") or {}

    src_filters = source_ep.get("filters") or {}
    dst_filters = dest_ep.get("filters") or {}

    conditions = _merge_filters(src_filters, dst_filters)
    conditions.vcn_scope = s.get("vcn_attribute")

    subject = _zpel_endpoint_to_subject(source_ep)
    obj = _zpel_endpoint_to_object(dest_ep)

    # Carry per-endpoint filters on the specs too (for round-trip fidelity)
    subject.filters = src_filters
    obj.filters = dst_filters

    return PolicyStatement(
        name=f"statement-{idx + 1}",
        effect="allow",   # ZPEL is allowlist-only
        priority=100,
        action="connect",
        subject=subject,
        object=obj,
        conditions=conditions,
        source_language="zpel",
    )
