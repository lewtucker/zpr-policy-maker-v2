"""OCI ZPR policy → ZPL translator.

Converts Oracle ZPR allow-rule syntax to ZPL and produces a Markdown guide
explaining each transformation.  The ZPL parser is not changed; this module
is a pure pre-processor.

OCI forms handled:
  Form 1 (single VCN, prefix):
    in <attr> VCN allow <src> [endpoints] to connect to <dst> [endpoints] [with <filter>]*

  Form 2 (cross-VCN, inline):
    allow <src> [endpoints] in <vcn1> VCN to connect to <dst> [endpoints]
        [with <filter>]* [in <vcn2> VCN]

The 'in <attr> VCN' clause may appear anywhere in the line.
"""
import re

# ── regex pieces ────────────────────────────────────────────────────────────

# Unquoted security attribute: optional-ns.key:value[:extra]
_ATTR_BARE = r"(?:[\w.\-]+:)?[\w.\-]+(?::[\w.\-]+)*"
# Quoted security attribute (value contains spaces or special chars)
_ATTR_QUOTED = r"'[^']+'"
_ATTR = rf"(?:{_ATTR_BARE}|{_ATTR_QUOTED})"

# Full 'in <attr> VCN' clause
_VCN_RE = re.compile(rf"\bin\s+({_ATTR})\s+VCN\b", re.IGNORECASE)

# 'key=\'val\'' — one filter term (used after locating the 'with' block)
_FILTER_PAIR_RE = re.compile(r"([\w.\-]+)\s*=\s*'([^']+)'")

# 'endpoints' keyword (noise)
_ENDPOINTS_RE = re.compile(r"\bendpoints\b", re.IGNORECASE)

# 'to connect to' verb
_CONNECT_RE = re.compile(r"\bto\s+connect\s+to\b", re.IGNORECASE)

# CIDR / IP pattern (unquoted)
_IP_RE = re.compile(r"^[\d]+\.[\d.]+(?:/\d+)?$")
# Prefix used to identify IP endpoint specs returned by _to_zpl_endpoint
_IP_SPEC_PREFIX = "IPEndpoint with ip_addr:'"


# ── helpers ─────────────────────────────────────────────────────────────────

def _attr_to_class(attr: str) -> str:
    """Convert an OCI security attribute to a ZPL class name.

    app:web              → app.web
    finance.network:prod → finance.network.prod
    VCN-Network:App      → VCN-Network.App
    networks:net1:App1   → networks.net1.App1
    """
    s = attr.strip("'").strip()
    # spaces → underscores, colons → dots
    s = re.sub(r"\s+", "_", s)
    return s.replace(":", ".")


def _vcn_to_namespace(attr: str) -> str:
    """Suggest a ZPL namespace name from a VCN security attribute value.

    app:fin-network  → fin-network
    networks:net1    → net1
    finance.network:prod → prod
    """
    s = attr.strip("'").strip()
    parts = s.split(":")
    return parts[-1]


def _ip_entity_name(ip: str) -> str:
    """Stable entity name for an IP/CIDR: 10.0.0.0/16 → ip_10_0_0_0_16."""
    return "ip_" + re.sub(r"[./]", "_", ip)


def _to_zpl_endpoint(raw: str) -> str:
    """Convert a raw endpoint token (after stripping 'endpoints') to ZPL.

    IP/CIDR literals become an attribute-filtered IPEndpoint spec so the
    rule reads: Allow IPEndpoint with ip_addr:'10.0.0.0/16' to access ...
    """
    s = raw.strip()
    if not s:
        return s
    if s.lower() == "all-endpoints":
        return "all-endpoints"
    inner = s.strip("'")
    if _IP_RE.match(inner):
        return f"{_IP_SPEC_PREFIX}{inner}'"  # IPEndpoint with ip_addr:'...'
    return _attr_to_class(inner)


# ── per-line translator ──────────────────────────────────────────────────────

def _translate_line(line: str) -> dict:
    """Parse and translate one OCI policy line.

    Returns a dict with keys:
      original   – original text
      vcn_attrs  – list of VCN attribute strings extracted
      src        – ZPL source class/literal
      dst        – ZPL destination class/literal
      filters    – list of "key:val" strings
      zpl        – translated ZPL statement
      error      – set if parsing failed (zpl will be a comment)
    """
    original = line.strip()

    # Normalise whitespace
    text = re.sub(r"\s+", " ", original)

    # 1. Extract all 'in <attr> VCN' clauses (any position)
    vcn_attrs = _VCN_RE.findall(text)
    text = _VCN_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()

    # Must be an allow rule
    if not re.match(r"^allow\b", text, re.IGNORECASE):
        return {"original": original, "vcn_attrs": vcn_attrs,
                "error": "not an allow rule",
                "zpl": f"# SKIPPED (not an allow rule): {original}"}

    # 2. Extract filter block: find first 'with', gather all key='val' pairs from there to end
    with_m = re.search(r"\bwith\b", text, re.IGNORECASE)
    if with_m:
        filter_section = text[with_m.start():]
        text = text[:with_m.start()].strip()
        filters = [f"{p.group(1)}:'{p.group(2)}'" for p in _FILTER_PAIR_RE.finditer(filter_section)]
    else:
        filters = []
    text = re.sub(r"\s+", " ", text).strip()

    # 3. Remove 'endpoints' keyword
    text = _ENDPOINTS_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()

    # 4. Split on 'to connect to'
    halves = _CONNECT_RE.split(text, maxsplit=1)
    if len(halves) != 2:
        return {"original": original, "vcn_attrs": vcn_attrs,
                "error": "missing 'to connect to'",
                "zpl": f"# UNPARSED: {original}"}

    src_raw = re.sub(r"^allow\s+", "", halves[0], flags=re.IGNORECASE).strip()
    dst_raw = halves[1].strip()

    src_cls = _to_zpl_endpoint(src_raw)
    dst_cls = _to_zpl_endpoint(dst_raw)

    # 5. Build ZPL
    zpl = f"Allow {src_cls} to access {dst_cls}"
    if filters:
        zpl += " with " + ", ".join(filters)
    zpl += "."

    return {
        "original": original,
        "vcn_attrs": vcn_attrs,
        "src": src_cls,
        "dst": dst_cls,
        "filters": filters,
        "zpl": zpl,
    }


# ── policy JSON output ───────────────────────────────────────────────────────

def oci_to_policy_json(text: str) -> dict:
    """Translate OCI ZPR policy text to a Policy Studio restore JSON.

    Compatible with POST /api/restore.  Structure:
      path=[]           — root: Define statements for all classes seen
      path=[vcn-name]   — one child namespace per unique VCN, holding its Allow rules
      Rules with no VCN context land in root alongside the Defines.
    """
    # VCN namespace name → list of translated ZPL rules
    ns_rules: dict[str, list[str]] = {}
    vcn_ns: dict[str, str] = {}   # attr → namespace name (first-seen wins on conflict)
    classes: set[str] = set()
    ip_values: set[str] = set()  # raw IP/CIDR strings seen (e.g. '10.0.0.0/16')

    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        result = _translate_line(s)
        if not result or "error" in result:
            continue

        for spec in [result.get("src", ""), result.get("dst", "")]:
            if not spec or spec == "all-endpoints":
                continue
            if spec.startswith(_IP_SPEC_PREFIX):
                ip_values.add(spec[len(_IP_SPEC_PREFIX):].rstrip("'"))
            else:
                classes.add(spec)

        vcn_attrs = result.get("vcn_attrs", [])
        if vcn_attrs:
            # Primary VCN (first attr) owns the rule; others are just noted
            primary = vcn_attrs[0]
            ns_name = vcn_ns.setdefault(primary, _vcn_to_namespace(primary))
            for attr in vcn_attrs[1:]:
                vcn_ns.setdefault(attr, _vcn_to_namespace(attr))
            ns_rules.setdefault(ns_name, []).append(result["zpl"])
        else:
            ns_rules.setdefault("", []).append(result["zpl"])

    # Root ZPL: Defines + Declares + any no-VCN rules
    root_parts: list[str] = []
    if ip_values:
        ip_lines = ["Define IPEndpoint as an endpoint with ip_addr."]
        for ip in sorted(ip_values):
            ip_lines.append(f"Declare {_ip_entity_name(ip)} as an IPEndpoint with ip_addr:'{ip}'.")
        root_parts.append("\n".join(ip_lines))
    if classes:
        sorted_cls = sorted(classes)
        defines = "\n".join(f"Define {c} as an endpoint." for c in sorted_cls)
        declares = "\n".join(f"Declare {c} as a {c}." for c in sorted_cls)
        root_parts.append(defines + "\n" + declares)
    if ns_rules.get(""):
        root_parts.append("\n".join(ns_rules[""]))

    namespaces: list[dict] = [{"path": [], "zpl": "\n\n".join(root_parts)}]
    for ns_name in sorted(ns_rules):
        if not ns_name:
            continue
        namespaces.append({"path": [ns_name], "zpl": "\n".join(ns_rules[ns_name])})

    return {"format_version": 1, "namespaces": namespaces}


# ── main entry point ─────────────────────────────────────────────────────────

def oci_to_markdown(text: str) -> str:
    """Translate OCI ZPR policy text and return a Markdown guide.

    The Markdown includes:
    - A VCN → namespace mapping table
    - Suggested Define statements for each class seen
    - Each rule as a ZPL code block with the original OCI as a # comment
    """
    items: list[dict] = []
    vcn_ns: dict[str, str] = {}   # attr → suggested namespace
    classes: set[str] = set()
    ip_values: set[str] = set()

    for line in text.splitlines():
        s = line.strip()
        if not s:
            items.append({"blank": True})
            continue
        if s.startswith("#"):
            items.append({"comment": s})
            continue
        result = _translate_line(s)
        items.append(result)
        for attr in result.get("vcn_attrs", []):
            vcn_ns.setdefault(attr, _vcn_to_namespace(attr))
        if "error" not in result:
            for spec in [result.get("src", ""), result.get("dst", "")]:
                if spec and spec != "all-endpoints":
                    if spec.startswith(_IP_SPEC_PREFIX):
                        ip_values.add(spec[len(_IP_SPEC_PREFIX):].rstrip("'"))
                    else:
                        classes.add(spec)

    out: list[str] = []

    out.append("# OCI ZPR Policy — ZPL Translation\n")
    out.append("> Generated by ZPR Policy Builder OCI translator.  ")
    out.append("> Review each section carefully before pasting ZPL into your namespace.\n")

    # VCN → namespace table
    if vcn_ns:
        out.append("## VCN Context → ZPL Namespace Mapping\n")
        out.append(
            "OCI `in <attr> VCN` clauses scope a rule to a specific virtual network. "
            "ZPL has no VCN concept. The table below maps each VCN attribute to a "
            "suggested ZPL namespace — create a child namespace with that name and "
            "place the corresponding rules inside it.\n"
        )
        out.append("| OCI VCN Attribute | Suggested ZPL Namespace |")
        out.append("|---|---|")
        for attr, ns in vcn_ns.items():
            out.append(f"| `{attr}` | `{ns}` |")
        out.append("")

    # Suggested Define + Declare statements
    if ip_values or classes:
        out.append("## Suggested Class Definitions\n")
        out.append(
            "OCI has no `Define` statements — security attributes are implicit endpoint labels. "
            "Add these definitions and entity declarations to your root or target namespace before the rules below.\n"
        )
        out.append("```zpl")
        if ip_values:
            out.append("# IP/CIDR endpoints — OCI quoted literals mapped to IPEndpoint with ip_addr attribute")
            out.append("Define IPEndpoint as an endpoint with ip_addr.")
            for ip in sorted(ip_values):
                out.append(f"Declare {_ip_entity_name(ip)} as an IPEndpoint with ip_addr:'{ip}'.")
            out.append("")
        if classes:
            sorted_cls = sorted(classes)
            for cls in sorted_cls:
                out.append(f"Define {cls} as an endpoint.")
            out.append("")
            for cls in sorted_cls:
                out.append(f"Declare {cls} as a {cls}.")
        out.append("```\n")

    # Translated rules
    if items:
        out.append("## Translated Rules\n")
        for item in items:
            if item.get("blank"):
                out.append("")
                continue
            if "comment" in item:
                out.append(item["comment"])
                continue
            out.append("```zpl")
            out.append(f"# OCI:  {item['original']}")
            for attr in item.get("vcn_attrs", []):
                ns = vcn_ns.get(attr, _vcn_to_namespace(attr))
                out.append(f"# VCN: {attr}  →  namespace {ns}")
            if item.get("error"):
                out.append(f"# NOTE: {item['error']}")
            out.append(item["zpl"])
            out.append("```\n")

    return "\n".join(out)
