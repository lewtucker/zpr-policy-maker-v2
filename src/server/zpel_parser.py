"""ZPEL — Oracle ZPR Policy Enforcement Language (PEL v1) parser.

Parses ZPR PEL v1 statements into structured dicts.  The normaliser
(ir_normalizer.py) converts these dicts into the Common IR.

Grammar (formal spec, Section 4 — zpel_oracle_zpr_pel_v1.bnf):

  <policy_statement> ::= <network_scope> <command> <source_endpoint>
                         "to" <verb> <target_endpoint>
  <network_scope>    ::= "in" <security_attribute> "vcn"
  <command>          ::= "allow"
  <verb>             ::= "connect" "to"
  <endpoint>         ::= <basic_endpoint>
                       | <basic_endpoint> <with_attribute_list>
  <basic_endpoint>   ::= <security_attribute> "endpoints"
                       | <ip_or_CIDR>
                       | "all-endpoints"
                       | "osn-services-ip-addresses"
  <with_attribute_list> ::= "with" <attribute>
                          | <with_attribute_list> <list_conjunction> <attribute>
  <list_conjunction> ::= "," | "and" | ", and"
  <security_attribute> ::= ns.key:value | key:value | 'ns.key:value' | 'key:value'
  <attribute>        ::= protocol='...' | protocol.icmp.type='...'
                       | protocol.icmp.code='...' | connection-state='...'

Output of parse():
  {
    "rules": [
      {
        "vcn_attribute": "app:finance-network",
        "source": {
          "type": "attribute",         # "attribute" | "ip_cidr" | "all-endpoints" | "osn"
          "value": "app:frontend",     # security attribute string (type=="attribute")
                                       # or IP/CIDR string (type=="ip_cidr")
          "filters": {                 # from "with" clause on this endpoint
            "protocol": "tcp/22",
            "connection-state": "stateless"
          }
        },
        "destination": { ... same shape as source ... }
      }
    ],
    "errors": [{"line": N, "message": "..."}]
  }
"""
from __future__ import annotations

import re
from typing import Any

# ── Tokenizer ─────────────────────────────────────────────────────────────────

# Token kinds
_TK_QUOTED  = "quoted"   # '...' single-quoted string
_TK_WORD    = "word"     # identifier / keyword
_TK_COLON   = "colon"    # :
_TK_DOT     = "dot"      # .
_TK_SLASH   = "slash"    # /
_TK_EQUALS  = "equals"   # =
_TK_COMMA   = "comma"    # ,
_TK_DASH    = "dash"     # - (inside identifiers this is part of the word)

_TOKEN_RE = re.compile(
    r"""
    (?P<comment>  \#[^\n]* )                          |
    (?P<ws>       [ \t\r\n]+ )                        |
    (?P<quoted>   '(?:[^']|'')*' )                    |
    (?P<word>     [A-Za-z][A-Za-z0-9_\-]* )          |
    (?P<colon>    : )                                 |
    (?P<dot>      \. )                                |
    (?P<slash>    / )                                 |
    (?P<equals>   = )                                 |
    (?P<comma>    , )
    """,
    re.VERBOSE,
)


def _tokenize(text: str) -> list[tuple[str, str, int]]:
    """Return list of (kind, value, line_number) — whitespace/comments dropped."""
    tokens: list[tuple[str, str, int]] = []
    line = 1
    for m in _TOKEN_RE.finditer(text):
        kind = m.lastgroup
        value = m.group()
        if kind in ("ws", "comment"):
            line += value.count("\n")
            continue
        tokens.append((kind, value, line))
    return tokens


# ── Parser cursor ─────────────────────────────────────────────────────────────

class _P:
    def __init__(self, tokens: list[tuple[str, str, int]]):
        self.tokens = tokens
        self.i = 0

    def peek(self, offset: int = 0) -> tuple[str, str, int] | None:
        j = self.i + offset
        return self.tokens[j] if j < len(self.tokens) else None

    def advance(self) -> tuple[str, str, int]:
        t = self.tokens[self.i]
        self.i += 1
        return t

    def at_end(self) -> bool:
        return self.i >= len(self.tokens)

    def current_line(self) -> int:
        t = self.peek()
        return t[2] if t else 0

    def eat(self, kind: str, value: str | None = None) -> bool:
        t = self.peek()
        if t is None:
            return False
        if t[0] != kind:
            return False
        if value is not None and t[1].lower() != value.lower():
            return False
        self.advance()
        return True

    def expect(self, kind: str, value: str | None = None) -> str:
        if not self.eat(kind, value):
            t = self.peek()
            got = f"{t[0]}:{t[1]!r}" if t else "end of input"
            want = f"{kind}:{value!r}" if value else kind
            raise ValueError(f"Expected {want}, got {got}")
        return self.tokens[self.i - 1][1]

    def eat_word(self, value: str) -> bool:
        return self.eat("word", value)

    def expect_word(self, value: str) -> None:
        self.expect("word", value)


def _desc(t: tuple | None) -> str:
    if t is None:
        return "end of input"
    return repr(t[1])


# ── Security attribute parser ─────────────────────────────────────────────────

def _parse_security_attribute(p: _P) -> str:
    """Parse a security attribute and return it as a canonical string.

    Forms (from BNF):
      ns.key:value       — unquoted, with namespace
      key:value          — unquoted, no namespace
      'ns.key:value'     — quoted (value may contain spaces/special chars)
      'key:value'        — quoted, no namespace

    Returns the attribute string without surrounding quotes.
    """
    t = p.peek()
    if t is None:
        raise ValueError("Expected security attribute, got end of input")

    if t[0] == "quoted":
        p.advance()
        # Strip surrounding single quotes; '' → ' inside
        raw = t[1][1:-1].replace("''", "'")
        return raw

    # Unquoted: word [ "." word ] ":" word
    if t[0] != "word":
        raise ValueError(f"Expected security attribute, got {_desc(t)}")

    part1 = p.advance()[1]

    # Check for namespace.key form
    if p.peek() and p.peek()[0] == "dot":
        p.advance()  # consume "."
        t2 = p.peek()
        if t2 is None or t2[0] != "word":
            raise ValueError(f"Expected key after '.', got {_desc(p.peek())}")
        key = p.advance()[1]
        p.expect("colon")
        t3 = p.peek()
        if t3 is None or t3[0] not in ("word", "quoted"):
            raise ValueError(f"Expected value after ':', got {_desc(p.peek())}")
        value = p.advance()[1]
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1].replace("''", "'")
        return f"{part1}.{key}:{value}"
    else:
        # Simple key:value
        p.expect("colon")
        t3 = p.peek()
        if t3 is None or t3[0] not in ("word", "quoted"):
            raise ValueError(f"Expected value after ':', got {_desc(p.peek())}")
        value = p.advance()[1]
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1].replace("''", "'")
        return f"{part1}:{value}"


# ── Ordinary attribute ("with" clause) ────────────────────────────────────────

# Fixed attribute names that appear in "with" clauses.
_ATTR_NAMES = {
    "protocol",
    "protocol.icmp.type",
    "protocol.icmp.code",
    "connection-state",
}


def _try_parse_attr_name(p: _P) -> str | None:
    """Attempt to consume a known attribute name.  Returns name or None."""
    t = p.peek()
    if t is None or t[0] != "word":
        return None

    w = t[1].lower()

    # "connection-state" arrives as word "connection" + dash + "state"
    # The tokenizer treats "connection-state" as a single word token because
    # hyphens are included in the word regex — so it comes through as-is.
    if w == "protocol":
        # Check for protocol.icmp.type / protocol.icmp.code
        t2 = p.peek(1)
        if t2 and t2[0] == "dot":
            t3 = p.peek(2)
            if t3 and t3[0] == "word" and t3[1].lower() == "icmp":
                t4 = p.peek(3)
                if t4 and t4[0] == "dot":
                    t5 = p.peek(4)
                    if t5 and t5[0] == "word" and t5[1].lower() in ("type", "code"):
                        # Consume protocol.icmp.type / protocol.icmp.code
                        for _ in range(5):
                            p.advance()
                        return f"protocol.icmp.{t5[1].lower()}"
        p.advance()
        return "protocol"

    if w in ("connection-state",):
        p.advance()
        return "connection-state"

    return None


def _parse_attribute(p: _P) -> tuple[str, str]:
    """Parse one attribute clause: name = 'value'.  Returns (name, value)."""
    name = _try_parse_attr_name(p)
    if name is None:
        raise ValueError(f"Expected attribute name, got {_desc(p.peek())}")
    p.expect("equals")
    t = p.peek()
    if t is None:
        raise ValueError("Expected quoted value after '='")
    if t[0] == "quoted":
        value = p.advance()[1][1:-1].replace("''", "'")
    elif t[0] == "word":
        # Tolerate unquoted simple values
        value = p.advance()[1]
    else:
        raise ValueError(f"Expected value after '=', got {_desc(t)}")
    return name, value


def _parse_with_list(p: _P) -> dict[str, str]:
    """Parse one or more attribute clauses following a 'with' keyword.

    list_conjunction ::= "," | "and" | ", and"
    Repeated "with" (observed in web examples but not in formal spec) is also tolerated.
    """
    filters: dict[str, str] = {}
    while True:
        name, value = _parse_attribute(p)
        filters[name] = value
        # Check for conjunction
        if p.eat("comma"):
            p.eat_word("and")  # optional ", and"
        elif p.eat_word("and"):
            pass
        elif p.eat_word("with"):
            pass  # repeated "with" form
        else:
            break
    return filters


# ── Endpoint parser ───────────────────────────────────────────────────────────

def _parse_endpoint(p: _P) -> dict[str, Any]:
    """Parse an endpoint clause (source or destination).

    endpoint ::= basic_endpoint [ with_attribute_list ]

    Returns:
      {"type": "attribute",   "value": "app:web",  "filters": {...}}
      {"type": "ip_cidr",     "value": "10.0.0.0/16", "filters": {...}}
      {"type": "all-endpoints",                        "filters": {...}}
      {"type": "osn",                                  "filters": {...}}
    """
    t = p.peek()
    if t is None:
        raise ValueError("Expected endpoint, got end of input")

    result: dict[str, Any] = {"type": "attribute", "value": None, "filters": {}}

    # "all-endpoints" is a single hyphenated word token
    if t[0] == "word" and t[1].lower() == "all-endpoints":
        p.advance()
        result["type"] = "all-endpoints"

    # "osn-services-ip-addresses"
    elif t[0] == "word" and t[1].lower() == "osn-services-ip-addresses":
        p.advance()
        result["type"] = "osn"

    # Quoted string → IP/CIDR or quoted security attribute
    elif t[0] == "quoted":
        raw = t[1][1:-1].replace("''", "'")
        p.advance()
        # Heuristic: if it contains '/' or is purely digits/dots, treat as IP/CIDR
        if _looks_like_ip_cidr(raw):
            result["type"] = "ip_cidr"
            result["value"] = raw
        else:
            result["type"] = "attribute"
            result["value"] = raw

    # Security attribute: word [ "." word ] ":" value
    # We need to distinguish security attributes from the keyword "endpoints" that
    # may follow.  A security attribute always contains a colon.
    elif t[0] == "word":
        # Look ahead: is there a colon (possibly after a dot) making this an attr?
        if _peek_has_colon(p):
            attr = _parse_security_attribute(p)
            result["type"] = "attribute"
            result["value"] = attr
            # Consume optional "endpoints" keyword
            p.eat_word("endpoints")
        else:
            raise ValueError(
                f"Expected endpoint (security attribute, IP/CIDR, all-endpoints, "
                f"or osn-services-ip-addresses), got {_desc(t)}"
            )
    else:
        raise ValueError(f"Unexpected token {_desc(t)} in endpoint")

    # Optional "with" attribute list
    if p.eat_word("with"):
        result["filters"] = _parse_with_list(p)

    return result


def _looks_like_ip_cidr(s: str) -> bool:
    """True if s looks like an IPv4/IPv6 address or CIDR."""
    return bool(re.match(
        r"""
        ^(
          \d{1,3}(\.\d{1,3}){3}(/\d+)?         # IPv4 or IPv4 CIDR
        | [0-9a-fA-F:]+(/\d+)?                  # IPv6 or IPv6 CIDR
        )$
        """,
        s.strip(),
        re.VERBOSE,
    ))


def _peek_has_colon(p: _P) -> bool:
    """True if the upcoming word tokens form a security attribute (contain ':')."""
    # word ":" ...  OR  word "." word ":" ...
    t1 = p.peek(0)
    if t1 is None or t1[0] != "word":
        return False
    t2 = p.peek(1)
    if t2 is None:
        return False
    if t2[0] == "colon":
        return True
    if t2[0] == "dot":
        t3 = p.peek(2)
        t4 = p.peek(3)
        return (t3 is not None and t3[0] == "word" and
                t4 is not None and t4[0] == "colon")
    return False


# ── Statement parser ──────────────────────────────────────────────────────────

def _parse_statement(p: _P) -> dict[str, Any]:
    """Parse one ZPR PEL v1 policy statement.

    policy_statement ::= network_scope "allow" source_endpoint "to" "connect" "to" target_endpoint
    network_scope    ::= "in" <security_attribute> "vcn"
    """
    p.expect_word("in")
    vcn_attr = _parse_security_attribute(p)
    p.expect_word("vcn")
    p.expect_word("allow")
    source = _parse_endpoint(p)
    p.expect_word("to")
    p.expect_word("connect")
    p.expect_word("to")
    destination = _parse_endpoint(p)
    return {
        "vcn_attribute": vcn_attr,
        "source": source,
        "destination": destination,
    }


# ── Public entry point ────────────────────────────────────────────────────────

def parse(text: str) -> dict[str, Any]:
    """Parse a ZPEL policy document.

    Returns::

        {
            "rules": [...],
            "errors": [{"line": N, "message": "..."}]
        }

    Errors on individual statements are collected; parsing continues with the
    next statement (best-effort recovery by scanning for the next 'in' keyword).
    """
    tokens = _tokenize(text)
    p = _P(tokens)
    statements: list[dict] = []
    errors: list[dict] = []

    while not p.at_end():
        t = p.peek()
        if t is None:
            break
        if t[0] != "word" or t[1].lower() != "in":
            p.advance()
            continue
        start_line = t[2]
        try:
            statements.append(_parse_statement(p))
        except ValueError as exc:
            errors.append({"line": start_line, "message": str(exc)})
            # Skip forward to the next "in" keyword for error recovery
            while not p.at_end():
                tk = p.peek()
                if tk and tk[0] == "word" and tk[1].lower() == "in":
                    break
                p.advance()

    return {"rules": statements, "errors": errors}
