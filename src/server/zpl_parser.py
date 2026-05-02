"""ZPL RFC-15.5 text parser.

Parses a ZPL policy document — Define / Allow / Never statements — into
structured dicts matching the engine's rule and class-input shape.

Covered (docs/zpl_rfc15_5.bnf):
  <define-statement> ::= "define" <name> <aka-clause>? "as" <article>
                         <class-name> <with-attributes-clause>? "."
  <permission-statement> ::= "allow" <p-statement>
  <denial-statement> ::= "never" <permission-statement>
  <p-statement> ::= <subject-clause> "to" <verb> <object-clause> "."
  <subject-clause> ::= <user-spec> ("on" <endpoint-spec>)?
  <object-clause>  ::= <service-spec> ("on" <endpoint-spec>)?

Out of scope (deferred):
  - Quoted strings with escapes (namespace names with dots are now supported)
  - Quoted strings with escapes
  - Signal clauses (tolerated but ignored)

The parser produces::

    parse(text) → {"classes": [...], "rules": [...]}

ClassDict matches POST /classes; RuleDict matches POST /policies.
Semantic validation (unknown parent, bad attr type, etc.) is the caller's job.
"""
from __future__ import annotations

import re
import uuid
from typing import Any

# ── Keyword sets ────────────────────────────────────────────────────────────

_ARTICLES = {"a", "an", "the", "any"}
_VERBS = {"access", "use", "call", "read", "write"}
_SEPARATORS = {"on", "to", "and"}
_STMT_STARTERS = {"define", "allow", "never"}

_BUILTIN_ALIASES = {
    "user": "users", "users": "users",
    "endpoint": "endpoints", "endpoints": "endpoints",
    "service": "services", "services": "services",
    "server": "servers", "servers": "servers",
}

# ── Tokenizer ───────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r"""
    (?P<comment> (?:\#|//)[^\n]* )                                        |
    (?P<ws>      \s+ )                                                     |
    (?P<string>  '  [^'\\]* (?:\\.[^'\\]*)* '                             |
                 `  [^`\\]* (?:\\.[^`\\]*)* `                             |
                 "  [^"\\]* (?:\\.[^"\\]*)* "  )                          |
    (?P<punct>   [.,:{}=] )                                                |
    (?P<word>    [A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z_][A-Za-z0-9_\-]*)* )
    """,
    re.VERBOSE,
)


def _unescape(s: str) -> str:
    """Strip outer quotes and process backslash escapes."""
    inner = s[1:-1]
    return inner.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")


def _tokenize(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    pos = 0
    line = 1
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            pos += 1  # skip unrecognised character; statement error recovery handles the rest
            continue
        pos = m.end()
        if m.lastgroup in ("ws", "comment"):
            line += m.group().count("\n")
        elif m.lastgroup == "word":
            out.append(("word", m.group(), line))
        elif m.lastgroup == "string":
            out.append(("string", _unescape(m.group()), line))
        elif m.lastgroup == "punct":
            out.append(("punct", m.group(), line))
    return out


# ── Parser cursor ───────────────────────────────────────────────────────────


class _P:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.i = 0

    def peek(self, n: int = 0):
        j = self.i + n
        return self.tokens[j] if j < len(self.tokens) else None

    def advance(self):
        t = self.tokens[self.i]
        self.i += 1
        return t

    def at_end(self) -> bool:
        return self.i >= len(self.tokens)

    def eat_word(self, value: str) -> bool:
        t = self.peek()
        if t and t[0] == "word" and t[1].lower() == value.lower():
            self.advance()
            return True
        return False

    def eat_punct(self, value: str) -> bool:
        t = self.peek()
        if t and t[0] == "punct" and t[1] == value:
            self.advance()
            return True
        return False

    def expect_word(self, value: str) -> None:
        if not self.eat_word(value):
            raise ValueError(f"Expected {value!r}, got {_describe(self.peek())}")

    def expect_punct(self, value: str) -> None:
        if not self.eat_punct(value):
            raise ValueError(f"Expected {value!r}, got {_describe(self.peek())}")

    def expect_terminator(self) -> None:
        """Consume a '.' statement terminator if present; always optional."""
        self.eat_punct(".")


def _describe(t) -> str:
    if t is None:
        return "end of input"
    return f"{t[1]!r}"


# ── Entry point ─────────────────────────────────────────────────────────────


def parse(text: str) -> dict:
    """Parse a whole ZPL document.

    Returns ``{"classes": [...], "rules": [...], "errors": [{"line": N, "message": "..."}]}``.
    Errors on individual statements are collected and parsing continues with the next statement.
    """
    text_lines = text.splitlines()
    p = _P(_tokenize(text))
    classes: list[dict] = []
    class_index: dict[str, int] = {}
    rules: list[dict] = []
    errors: list[dict] = []

    while not p.at_end():
        t = p.peek()
        if t is None:
            break
        if t[0] != "word":
            p.advance()
            continue
        head = t[1].lower()
        start_line = t[2]
        try:
            if head == "define":
                new_cls = _parse_define(p)
                name = new_cls["class"]
                if new_cls.get("parent", "").lower() == "verb":
                    new_cls["verb"] = True
                    if name not in class_index:
                        class_index[name] = len(classes)
                        classes.append(new_cls)
                elif name in class_index:
                    _merge_class(classes[class_index[name]], new_cls)
                else:
                    class_index[name] = len(classes)
                    classes.append(new_cls)
            elif head == "never":
                rules.append(_parse_denial(p))
            elif head == "allow":
                rules.append(_parse_permission(p, result="allow"))
            else:
                raise ValueError(
                    f"Unexpected word {t[1]!r} (expected Define, Allow, or Never)"
                )
        except ValueError as exc:
            source = text_lines[start_line - 1].strip() if start_line <= len(text_lines) else ""
            errors.append({"line": start_line, "message": str(exc), "source": source})
            # Skip to the next statement terminator so we can continue
            while not p.at_end():
                tok = p.peek()
                if tok and tok[0] == "punct" and tok[1] == ".":
                    p.advance()
                    break
                p.advance()

    return {"classes": classes, "rules": rules, "errors": errors}


# ── Define ──────────────────────────────────────────────────────────────────


def _merge_class(existing: dict, new: dict) -> None:
    """Merge attributes from a second define into an existing class dict.

    Multi-valued attributes (e.g. tags) have their values unioned.
    New single-valued attributes that don't already exist are added.
    """
    for key, new_attr in new.get("attributes", {}).items():
        if key in existing["attributes"]:
            ex_attr = existing["attributes"][key]
            if ex_attr.get("type") == "multi" and new_attr.get("type") == "multi":
                seen = set(ex_attr.get("values", []))
                for v in new_attr.get("values", []):
                    if v not in seen:
                        ex_attr.setdefault("values", []).append(v)
                        seen.add(v)
        else:
            existing["attributes"][key] = new_attr


def _parse_define(p: _P) -> dict:
    p.expect_word("define")
    name = _consume_name(p)

    aka: str | None = None
    if p.eat_word("aka"):
        aka = _consume_name(p)

    p.expect_word("as")
    # Skip articles
    if _next_is_article(p):
        p.advance()

    parent_raw = _consume_name(p)
    parent = _BUILTIN_ALIASES.get(parent_raw.lower(), parent_raw)

    attributes: dict[str, dict] = {}
    if p.eat_word("with") or _next_looks_like_attr(p):
        attributes = _parse_define_attrs(p)

    p.expect_terminator()

    out: dict[str, Any] = {
        "class": name,
        "parent": parent,
        "attributes": attributes,
    }
    if aka:
        out["aka"] = aka
    return out


def _next_looks_like_attr(p: _P) -> bool:
    """True if the next tokens look like an attribute spec (word: or optional/multiple/tag/tags)."""
    t = p.peek()
    if not t or t[0] != "word":
        return False
    if t[1].lower() in {"optional", "multiple", "tag", "tags"}:
        return True
    nxt = p.peek(1)
    return bool(nxt and nxt[0] == "punct" and nxt[1] in (":", "="))


def _parse_define_attrs(p: _P) -> dict[str, dict]:
    attrs: dict[str, dict] = {}
    need_separator = False  # first attr-spec needs no leading separator

    while True:
        if need_separator:
            if not _eat_separator(p):
                break

        optional = p.eat_word("optional")
        multiple = False if optional else p.eat_word("multiple")

        if p.eat_word("tags") or p.eat_word("tag"):
            # Tag-list: collect all tag names as values under a single `tags`
            # multi attribute, matching the class schema convention.
            # e.g. "optional tags managed, compliant" →
            #      tags: {type: multi, values: [managed, compliant]}
            tag_values: list[str] = []
            consumed_separator_for_outer = False
            while True:
                tag_values.append(_consume_name(p))
                if not _eat_separator(p):
                    break
                if _next_is_attr_prefix(p):
                    consumed_separator_for_outer = True
                    break
            existing_tags = attrs.get("tags", {}).get("values", [])
            attrs["tags"] = {"type": "multi", "values": existing_tags + tag_values}
            need_separator = not consumed_separator_for_outer
            if not consumed_separator_for_outer:
                break
            continue

        # Plain attribute: "[multiple] <name>" or "<name>:<value>"
        if _next_is_article(p):
            p.advance()
        name = _consume_name(p)

        if p.eat_punct(":") or p.eat_punct("="):
            value = _consume_name(p)
            if multiple:
                attrs[name] = {"type": "multi"}
            else:
                attrs[name] = {"type": "single", "value": value}
        else:
            attrs[name] = {"type": "multi" if multiple else "single"}

        need_separator = True

    return attrs


def _next_is_article(p: _P) -> bool:
    t = p.peek()
    return bool(t and t[0] == "word" and t[1].lower() in _ARTICLES)


def _next_is_attr_prefix(p: _P) -> bool:
    t = p.peek()
    if not t or t[0] != "word":
        return False
    return t[1].lower() in {"multiple", "optional", "tag", "tags"}


def _eat_separator(p: _P) -> bool:
    if p.eat_punct(","):
        p.eat_word("and")
        return True
    if p.eat_word("and"):
        return True
    return False


# ── Permission / Denial ─────────────────────────────────────────────────────


def _parse_denial(p: _P) -> dict:
    p.expect_word("never")
    return _parse_permission(p, result="never")


def _parse_permission(p: _P, result: str) -> dict:
    p.expect_word("allow")

    subject = _parse_spec(p)
    accessor_endpoint: dict | None = None
    if p.eat_word("on"):
        accessor_endpoint = _parse_spec(p)

    p.expect_word("to")

    verb = _consume_name(p).lower()
    # "connect to" is two tokens
    if verb == "connect":
        t = p.peek()
        if t and t[0] == "word" and t[1].lower() == "to":
            p.advance()
            verb = "connect-to"

    # Unknown verbs are preserved — user may declare them with "define X as a verb."
    # access remains the built-in default when no verb is written.

    object_spec = _parse_spec(p)
    server_endpoint: dict | None = None
    if p.eat_word("on"):
        server_endpoint = _parse_spec(p)

    # Optional ", and signal ... to ..." — tolerated, dropped (TODO)
    p.eat_punct(",")
    if p.eat_word("and"):
        # Consume everything up to the terminating '.'
        while not p.at_end():
            t = p.peek()
            if t and t[0] == "punct" and t[1] == ".":
                break
            p.advance()

    p.expect_terminator()

    rule: dict[str, Any] = {
        "id": uuid.uuid4().hex,
        "name": _default_rule_name(result, subject, verb, object_spec, accessor_endpoint),
        "result": result,
        "priority": 100,
        "verb": verb,
    }
    if subject is not None:
        rule["subject"] = subject
    if accessor_endpoint is not None:
        rule["accessor_endpoint"] = accessor_endpoint
    if object_spec is not None:
        rule["object"] = object_spec
    if server_endpoint is not None:
        rule["server_endpoint"] = server_endpoint
    return rule


def _default_rule_name(result: str, subject, verb, obj, accessor_endpoint=None) -> str:
    def label(s):
        if not s:
            return "?"
        if "name" in s:
            return s["name"]
        return s.get("class", "?")
    on_part = f" on {label(accessor_endpoint)}" if accessor_endpoint else ""
    return f"{result.capitalize()} {label(subject)}{on_part} {verb} {label(obj)}"


# ── Spec parsing ────────────────────────────────────────────────────────────


def _parse_spec(p: _P) -> dict:
    """Zero or more attribute expressions, then a class or named entity."""
    attrs: dict[str, Any] = {}

    while True:
        t = p.peek()
        if t is None or t[0] not in ("word", "string"):
            break
        lower = t[1].lower()
        if t[0] == "word" and (lower in _SEPARATORS or lower in _STMT_STARTERS):
            break

        # Check for "name:..." (kv pair or presence check)
        nxt = p.peek(1)
        if nxt and nxt[0] == "punct" and nxt[1] in (":", "="):
            name = p.advance()[1]
            p.advance()  # eat ':' or '='
            value = _parse_attr_value(p)
            attrs[name] = value
            continue

        # This is either a tag OR the class-name terminator.
        # Terminator if the next token is a separator, period, or EOF.
        if _is_terminator_position(p):
            break
        # Bare name before class = tag qualifier; strip namespace prefix and
        # accumulate under the "tags" key so it aligns with `optional tags`
        # class definitions.  e.g. "hr employee" → attrs["tags"] = ["hr"]
        #                          "WS.hr WS.employee" → attrs["tags"] = ["hr"]
        tag_token = p.advance()[1]
        tag_val = tag_token.split(".")[-1]
        attrs.setdefault("tags", []).append(tag_val)

    # Now the class or named-entity token
    t = p.peek()
    if t is None or t[0] not in ("word", "string"):
        raise ValueError(f"Expected class or entity name, got {_describe(t)}")
    class_or_name = p.advance()[1]

    out: dict[str, Any] = {}
    key = class_or_name.lower()
    if key in _BUILTIN_ALIASES:
        out["class"] = _BUILTIN_ALIASES[key]
    elif class_or_name.split(".")[-1][:1].isupper():
        # Capitalized last component → named entity (handles ns.Alice and bare Alice)
        out["name"] = class_or_name
    else:
        out["class"] = class_or_name
    if attrs:
        out["attrs"] = attrs
    return out


def _is_terminator_position(p: _P) -> bool:
    """True if the CURRENT word is the last word before a structural break."""
    nxt = p.peek(1)
    if nxt is None:
        return True
    if nxt[0] == "punct" and nxt[1] == ".":
        return True
    if nxt[0] == "word" and nxt[1].lower() in _SEPARATORS:
        return True
    if nxt[0] == "word" and nxt[1].lower() in _STMT_STARTERS:
        return True
    return False


def _parse_attr_value(p: _P) -> Any:
    """Parse the RHS of ``name:<value>``."""
    t = p.peek()
    if t is None:
        return "*"
    if t[0] == "punct":
        if t[1] == "{":
            p.advance()
            values: list[str] = []
            while True:
                tv = p.peek()
                if tv is None:
                    raise ValueError("Unterminated value set")
                if tv[0] == "punct" and tv[1] == "}":
                    p.advance()
                    break
                if tv[0] == "punct" and tv[1] == ",":
                    p.advance()
                    continue
                if tv[0] in ("word", "string"):
                    values.append(p.advance()[1])
            return values
        # Presence check (e.g. "name:")
        return "*"
    if t[0] in ("word", "string"):
        return p.advance()[1]
    return "*"


# ── Class inference ─────────────────────────────────────────────────────────

_BUILTIN_CLASSES = {"users", "endpoints", "services", "servers"}
_PARENT_SINGULAR = {"users": "user", "endpoints": "endpoint", "services": "service", "servers": "server"}


def build_alias_map(parsed: dict) -> dict[str, str]:
    """Return a map of alias/plural → canonical class name.

    Sources:
      - Explicit aka:  define cat aka cats as an employee.  → {"cats": "cat"}
      - Auto-plural:   define cat …                         → {"cats": "cat"}
      - Auto-es plural for names ending in s/x/z/ch/sh     → {"foxes": "fox"}
    """
    alias_map: dict[str, str] = {}
    for c in parsed.get("classes", []):
        if c.get("verb"):
            continue
        name = c.get("class", "")
        if not name:
            continue
        if c.get("aka"):
            alias_map[c["aka"]] = name
        alias_map[name + "s"] = name
        if name[-1:] in "sxz" or name[-2:] in ("ch", "sh"):
            alias_map[name + "es"] = name
    return alias_map


def infer_missing_classes(parsed: dict) -> list[dict]:
    """Return define-dicts for classes used in rules but not defined in the document."""
    defined = {c["class"] for c in parsed.get("classes", [])} | _BUILTIN_CLASSES
    resolvable = defined | set(build_alias_map(parsed).keys())
    inferred: dict[str, dict] = {}

    for rule in parsed.get("rules", []):
        _collect_spec(rule.get("subject"),           "users",     inferred, resolvable)
        _collect_spec(rule.get("accessor_endpoint"), "endpoints", inferred, resolvable)
        _collect_spec(rule.get("object"),            "services",  inferred, resolvable)
        _collect_spec(rule.get("server_endpoint"),   "endpoints", inferred, resolvable)

    return [_build_inferred(name, info) for name, info in inferred.items()]


def _collect_spec(spec: dict | None, parent: str, inferred: dict, defined: set) -> None:
    if not spec:
        return
    cls = spec.get("class")
    if not cls or cls in defined:
        return
    if cls not in inferred:
        inferred[cls] = {"parent": parent, "tags": set(), "attrs": set()}
    for k, v in spec.get("attrs", {}).items():
        if k == "tags":
            vals = v if isinstance(v, list) else ([v] if v != "*" else [])
            inferred[cls]["tags"].update(vals)
        elif v == "*":
            inferred[cls]["tags"].add(k)  # legacy: bare-name stored as key
        else:
            inferred[cls]["attrs"].add(k)


def _build_inferred(name: str, info: dict) -> dict:
    attributes: dict = {}
    if info["tags"]:
        attributes["tags"] = {"type": "multi", "values": sorted(info["tags"])}
    for k in sorted(info["attrs"]):
        attributes[k] = {"type": "multi"}
    return {"class": name, "parent": info["parent"], "attributes": attributes}


def inferred_to_zpl(classes: list[dict]) -> str:
    """Render inferred class dicts as ZPL define statements."""
    lines = []
    for c in classes:
        singular = _PARENT_SINGULAR.get(c["parent"], c["parent"])
        attrs = c.get("attributes", {})
        parts = []
        tags = attrs.get("tags", {}).get("values", [])
        if tags:
            parts.append("optional tags " + ", ".join(tags))
        for k, v in attrs.items():
            if k == "tags":
                continue
            parts.append(f"multiple {k}")
        with_clause = " with " + ", ".join(parts) if parts else ""
        article = "an" if singular[0] in "aeiou" else "a"
        lines.append(f"Define {c['class']} as {article} {singular}{with_clause}.")
    return "\n".join(lines)


def _consume_name(p: _P) -> str:
    t = p.peek()
    if t is None or t[0] not in ("word", "string"):
        raise ValueError(f"Expected name, got {_describe(t)}")
    return p.advance()[1]
