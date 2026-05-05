"""ZPL text serializer — converts classes and rules back to ZPL syntax."""

from __future__ import annotations


# ── Spec ────────────────────────────────────────────────────────────────────

def _serialize_spec(spec: dict | None, fallback: str = "any") -> str:
    if not spec:
        return fallback
    class_name = spec.get("class") or spec.get("cls")
    name = spec.get("name")
    attrs = spec.get("attrs") or {}

    attr_parts: list[str] = []
    for k, v in attrs.items():
        if k == "tags":
            # Tag values serialize as bare names before the class name.
            # e.g. attrs["tags"] = ["hr"] → "hr WS.employee"
            tag_vals = v if isinstance(v, list) else ([v] if v != "*" else [])
            for tag in tag_vals:
                attr_parts.append(str(tag))
            if not tag_vals:
                attr_parts.append("tags:")  # presence-only check fallback
        elif v == "*":
            attr_parts.append(k)
        elif isinstance(v, list):
            attr_parts.append(f"{k}:{{{', '.join(str(x) for x in v)}}}")
        else:
            attr_parts.append(f"{k}:{v}")

    target = name if name else (class_name or fallback)
    if attr_parts:
        return " ".join(attr_parts) + " " + target
    return target


# ── Rules ────────────────────────────────────────────────────────────────────

def rule_to_zpl(rule: dict) -> str | None:
    """Convert a rule dict to a ZPL Allow/Never statement, or None if unrepresentable."""
    result = rule.get("result") or rule.get("effect", "allow")
    verb = rule.get("verb") or rule.get("action") or "access"
    subject = rule.get("subject")
    accessor = rule.get("accessor_endpoint")
    obj = rule.get("object")
    server = rule.get("server_endpoint")

    prefix = "Never allow" if result in ("never", "deny") else "Allow"
    subj_str = _serialize_spec(subject, fallback="users")
    obj_str = _serialize_spec(obj, fallback="services")

    parts = [f"{prefix} {subj_str}"]
    if accessor:
        parts.append(f" on {_serialize_spec(accessor, fallback='endpoints')}")
    parts.append(f" to {verb} {obj_str}")
    if server:
        parts.append(f" on {_serialize_spec(server, fallback='servers')}")

    return "".join(parts) + "."


def rules_to_zpl(rules: list[dict]) -> str:
    lines = []
    for r in rules:
        line = rule_to_zpl(r)
        if line:
            lines.append(line)
    return "\n".join(lines)


# ── Classes ──────────────────────────────────────────────────────────────────

def _serialize_class_attrs(attributes: dict) -> list[str]:
    parts: list[str] = []
    tag_values: list[str] = []

    for attr_name, spec in attributes.items():
        if not isinstance(spec, dict):
            continue
        attr_type = spec.get("type", "single")

        if attr_type == "tag":
            tag_values.append(attr_name)
            continue

        if attr_name == "tags" and attr_type == "multi":
            tag_values.extend(spec.get("values") or [])
            continue

        value = spec.get("value")
        optional = spec.get("optional", False)

        if attr_type == "multi":
            parts.append(f"multiple {attr_name}")
        elif value:
            parts.append(f"{attr_name}:{value}")
        elif optional:
            parts.append(f"optional {attr_name}")
        else:
            parts.append(attr_name)

    if tag_values:
        parts.append("optional tags " + ", ".join(tag_values))

    return parts


def _join_with_and(parts: list[str]) -> str:
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + " and " + parts[-1]


_SINGULAR = {"users": "user", "endpoints": "endpoint", "services": "service", "servers": "server"}


def class_to_zpl(cls: dict) -> str | None:
    """Convert a class dict to a ZPL Define statement. Returns None for builtins."""
    if cls.get("builtin"):
        return None
    if cls.get("is_verb") or cls.get("parent") == "verb":
        return f"Define {cls.get('name', '')} as a verb."
    name = cls.get("name", "")
    aka = cls.get("aka")
    parent = cls.get("parent", "")
    attributes = cls.get("attributes") or {}

    singular = _SINGULAR.get(parent, parent)
    article = "an" if singular and singular[0] in "aeiou" else "a"
    line = f"Define {name}"
    if aka:
        line += f" AKA {aka}"
    line += f" as {article} {singular}"

    attr_parts = _serialize_class_attrs(attributes)
    if attr_parts:
        line += " with " + _join_with_and(attr_parts)

    return line + "."


def classes_to_zpl(classes: list[dict]) -> str:
    lines = [class_to_zpl(c) for c in classes if not c.get("builtin")]
    return "\n".join(l for l in lines if l)


# ── Entities ─────────────────────────────────────────────────────────────────

def entity_to_zpl(entity: dict) -> str | None:
    """Convert an entity dict to a ZPL Declare statement."""
    name = entity.get("name", "")
    class_name = entity.get("class_name", "")
    if not name or not class_name:
        return None
    attributes = entity.get("attributes") or {}
    article = "an" if class_name[0] in "aeiou" else "a"
    line = f"Declare {name} as {article} {class_name}"
    attr_parts = [f"{k}: {v}" for k, v in attributes.items() if v is not None]
    if attr_parts:
        line += " with " + ", ".join(attr_parts)
    return line + "."


def entities_to_zpl(entities: list[dict]) -> str:
    lines = [entity_to_zpl(e) for e in entities]
    return "\n".join(l for l in lines if l)
