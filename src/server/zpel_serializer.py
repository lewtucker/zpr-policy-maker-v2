"""ZPEL serializer — converts Common IR PolicySet → ZPEL text.

Only PolicyStatements with source_language=="zpel" or with ZPEL-specific
fields (subject.attribute / conditions.vcn_scope) are translatable.
Statements that use ZPL class fields or OC tool fields are flagged as
untranslatable rather than silently dropped.
"""
from __future__ import annotations

from ir_schema import Conditions, ObjectSpec, PolicySet, PolicyStatement, SubjectSpec


# ── Endpoint rendering ────────────────────────────────────────────────────────

def _render_endpoint(spec: SubjectSpec | ObjectSpec | None, fallback: str = "?") -> str:
    if spec is None:
        return fallback
    if spec.all_endpoints:
        return "all-endpoints"
    if spec.osn:
        return "osn-services-ip-addresses"
    if spec.ip_cidr:
        return f"'{spec.ip_cidr}'"
    if spec.attribute:
        attr = spec.attribute
        # Quote if value contains spaces or special chars that require it
        needs_quote = any(c in attr for c in (" ", "\t", "'"))
        if needs_quote:
            attr = "'" + attr.replace("'", "''") + "'"
        return f"{attr} endpoints"
    return fallback


def _render_filters(filters: dict[str, str]) -> str:
    """Render a set of filter key:value pairs as 'with ...' clauses."""
    if not filters:
        return ""
    parts = [f"{k}='{v}'" for k, v in filters.items()]
    return " with " + ", ".join(parts)


def _render_conditions(cond: Conditions, src_filters: dict, dst_filters: dict) -> str:
    """Render statement-level conditions as trailing 'with' clause.

    Prefers per-endpoint filters (already rendered on the endpoint) and only
    emits statement-level conditions that weren't expressed per-endpoint.
    """
    ep_filter_keys = set(src_filters) | set(dst_filters)
    stmt_filters: dict[str, str] = {}
    if cond.protocol and "protocol" not in ep_filter_keys:
        stmt_filters["protocol"] = cond.protocol
    if cond.connection_state and "connection-state" not in ep_filter_keys:
        stmt_filters["connection-state"] = cond.connection_state
    if cond.icmp_type and "protocol.icmp.type" not in ep_filter_keys:
        stmt_filters["protocol.icmp.type"] = cond.icmp_type
    if cond.icmp_code and "protocol.icmp.code" not in ep_filter_keys:
        stmt_filters["protocol.icmp.code"] = cond.icmp_code
    return _render_filters(stmt_filters)


# ── Statement rendering ───────────────────────────────────────────────────────

def statement_to_zpel(stmt: PolicyStatement) -> str | None:
    """Render a single PolicyStatement as a ZPEL allow statement.

    Returns None if the statement cannot be expressed in ZPEL (e.g. uses ZPL
    class-hierarchy features, or effect is 'deny' which ZPEL doesn't support).
    """
    # ZPEL is allowlist-only
    if stmt.effect == "deny":
        return None

    vcn = stmt.conditions.vcn_scope if stmt.conditions else None
    if not vcn:
        return None  # ZPEL requires a VCN scope

    src = stmt.subject
    dst = stmt.object

    # ZPL class-based specs can't be expressed in ZPEL
    if (src and (src.cls or src.name)) or (dst and (dst.cls or dst.name)):
        return None

    src_ep = _render_endpoint(src, "all-endpoints")
    dst_ep = _render_endpoint(dst, "all-endpoints")

    # Per-endpoint filters
    src_filters = (src.filters if src else {}) or {}
    dst_filters = (dst.filters if dst else {}) or {}

    src_with = _render_filters(src_filters)
    dst_with = _render_filters(dst_filters)

    # Statement-level conditions (anything not already in per-endpoint filters)
    cond = stmt.conditions or Conditions()
    stmt_with = _render_conditions(cond, src_filters, dst_filters)

    # Quote VCN attribute if needed
    vcn_str = vcn
    if any(c in vcn for c in (" ", "\t", "'")):
        vcn_str = "'" + vcn.replace("'", "''") + "'"

    parts = [
        f"in {vcn_str} VCN",
        "allow",
        f"{src_ep}{src_with}",
        "to connect to",
        f"{dst_ep}{dst_with}",
    ]
    line = " ".join(parts)
    if stmt_with:
        line += stmt_with
    return line


def policy_set_to_zpel(ps: PolicySet) -> str:
    """Render all translatable statements in a PolicySet as ZPEL text."""
    lines: list[str] = []
    for stmt in ps.rules:
        rendered = statement_to_zpel(stmt)
        if rendered is None:
            if stmt.name:
                lines.append(f"# [untranslatable] {stmt.name}")
            continue
        if stmt.name:
            lines.append(f"# {stmt.name}")
        lines.append(rendered)
    return "\n".join(lines)


def untranslatable_statements(ps: PolicySet) -> list[PolicyStatement]:
    """Return statements that cannot be expressed in ZPEL."""
    return [s for s in ps.rules if statement_to_zpel(s) is None]
