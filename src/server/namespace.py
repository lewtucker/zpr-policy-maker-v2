"""Namespace injection and stripping for ZPL PolicySet dicts.

inject(policy, ns)  — prefix bare names with ns. before storing or display
strip(policy, ns)   — remove ns. prefix for editor display
active_ns(session)  — extract the namespace string from a session dict
"""

from __future__ import annotations

_BUILTIN_CLASSES = frozenset({
    "user", "users", "service", "services",
    "endpoint", "endpoints", "server", "servers",
})


def active_ns(session: dict) -> str:
    """Return the active namespace string, or '' if none applies."""
    dn = (session.get("active_display_name") or "").strip()
    if not dn or dn.startswith("_ns_"):
        return ""
    return dn


# ── Helpers ───────────────────────────────────────────────────────────────────

def _qualify(name: str, ns: str, ancestor_classes: dict[str, str] | None = None) -> str:
    if not name or not ns or "." in name:
        return name
    if name.lower() in _BUILTIN_CLASSES:
        return name
    if ancestor_classes and name in ancestor_classes:
        return ancestor_classes[name]
    return f"{ns}.{name}"


def _qualify_key(key: str, _ns: str) -> str:
    # Attribute names are never namespace-prefixed — return as-is.
    return key


def _inject_spec(spec: dict | None, ns: str, ancestor_classes: dict[str, str] | None = None) -> dict | None:
    if not spec:
        return spec
    out = dict(spec)
    for key in ("class", "cls"):
        if out.get(key):
            out[key] = _qualify(out[key], ns, ancestor_classes)
    if out.get("name"):
        out["name"] = _qualify(out["name"], ns, ancestor_classes)
    if out.get("attrs"):
        out["attrs"] = {_qualify_key(k, ns): v for k, v in out["attrs"].items()}
    return out


def _strip(name: str, prefix: str) -> str:
    return name[len(prefix):] if name and name.startswith(prefix) else name


def _strip_key(key: str, _prefix: str) -> str:
    # Attribute names are never namespace-prefixed — return as-is.
    return key


def _strip_spec(spec: dict | None, prefix: str) -> dict | None:
    if not spec:
        return spec
    out = dict(spec)
    for key in ("class", "cls"):
        if out.get(key):
            out[key] = _strip(out[key], prefix)
    if out.get("name"):
        out["name"] = _strip(out["name"], prefix)
    if out.get("attrs"):
        out["attrs"] = {_strip_key(k, prefix): v for k, v in out["attrs"].items()}
    return out


# ── Public API ────────────────────────────────────────────────────────────────

def inject(policy: dict, ns: str, ancestor_classes: dict[str, str] | None = None) -> dict:
    """Return a copy of the PolicySet dict with bare names prefixed by ns.

    ancestor_classes: mapping from bare name → fully-qualified name for classes
    defined in ancestor namespaces. Those names will use the ancestor prefix
    instead of ns (e.g. 'Manager' → 'Acme.Manager' instead of 'HR.Manager').
    """
    if not ns:
        return policy
    out = dict(policy)

    new_classes = []
    for cls in out.get("classes", []):
        if cls.get("builtin") or cls.get("is_verb"):
            new_classes.append(cls)
            continue
        c = dict(cls)
        c["name"] = _qualify(c.get("name") or "", ns, ancestor_classes)
        c["parent"] = _qualify(c.get("parent") or "", ns, ancestor_classes)
        c["attributes"] = {
            _qualify_key(k, ns): v
            for k, v in (c.get("attributes") or {}).items()
        }
        new_classes.append(c)
    out["classes"] = new_classes

    new_rules = []
    for rule in out.get("rules", []):
        r = dict(rule)
        r["subject"] = _inject_spec(r.get("subject"), ns, ancestor_classes)
        r["accessor_endpoint"] = _inject_spec(r.get("accessor_endpoint"), ns, ancestor_classes)
        r["object"] = _inject_spec(r.get("object"), ns, ancestor_classes)
        r["server_endpoint"] = _inject_spec(r.get("server_endpoint"), ns, ancestor_classes)
        new_rules.append(r)
    out["rules"] = new_rules

    return out


def strip(policy: dict, ns: str) -> dict:
    """Return a copy with the ns. prefix removed from all names."""
    if not ns:
        return policy
    prefix = f"{ns}."
    out = dict(policy)

    new_classes = []
    for cls in out.get("classes", []):
        c = dict(cls)
        c["name"] = _strip(c.get("name") or "", prefix)
        c["parent"] = _strip(c.get("parent") or "", prefix)
        c["attributes"] = {
            _strip_key(k, prefix): v
            for k, v in (c.get("attributes") or {}).items()
        }
        new_classes.append(c)
    out["classes"] = new_classes

    new_rules = []
    for rule in out.get("rules", []):
        r = dict(rule)
        r["subject"] = _strip_spec(r.get("subject"), prefix)
        r["accessor_endpoint"] = _strip_spec(r.get("accessor_endpoint"), prefix)
        r["object"] = _strip_spec(r.get("object"), prefix)
        r["server_endpoint"] = _strip_spec(r.get("server_endpoint"), prefix)
        new_rules.append(r)
    out["rules"] = new_rules

    return out
