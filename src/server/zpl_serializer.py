"""ZPL text serializer — converts classes and rules back to ZPL syntax."""

from __future__ import annotations


# ── Spec ────────────────────────────────────────────────────────────────────

def _serialize_spec(spec: dict | None, fallback: str = "any") -> str:
    if not spec:
        return fallback
    class_name = spec.get("class")
    name = spec.get("name")
    attrs = spec.get("attrs") or {}

    attr_parts: list[str] = []
    for k, v in attrs.items():
        if v == "*":
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
    result = rule.get("result", "allow")
    verb = rule.get("verb") or "access"
    subject = rule.get("subject")
    accessor = rule.get("accessor_endpoint")
    obj = rule.get("object")
    server = rule.get("server_endpoint")

    prefix = "Never allow" if result == "never" else "Allow"
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
            name = r.get("name", "")
            if name:
                lines.append(f"# {name}")
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


def class_to_zpl(cls: dict) -> str | None:
    """Convert a class dict to a ZPL Define statement. Returns None for builtins."""
    if cls.get("builtin"):
        return None
    name = cls.get("class", "")
    aka = cls.get("aka")
    parent = cls.get("parent", "")
    attributes = cls.get("attributes") or {}

    line = f"Define {name}"
    if aka:
        line += f" AKA {aka}"
    line += f" as a {parent}"

    attr_parts = _serialize_class_attrs(attributes)
    if attr_parts:
        line += " with " + _join_with_and(attr_parts)

    return line + "."


def classes_to_zpl(classes: list[dict]) -> str:
    lines = [class_to_zpl(c) for c in classes if not c.get("builtin")]
    return "\n".join(l for l in lines if l)
