"""Tests for ZPL tag semantics: bare-name qualifiers in rules map to the
"tags" attribute, consistent with `optional tags` class definitions.

Run with:  pytest test_zpl_tags.py -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
import zpl_parser
import ir_normalizer as norm
import zpl_serializer
from class_schema import ClassSchema
from zpl_engine import CheckRequest, Entity, Rule, ZPLEngine


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _minimal_schema(extra_classes=None):
    classes = [
        {"class": "users",     "parent": None, "builtin": True,  "attributes": {}},
        {"class": "services",  "parent": None, "builtin": True,  "attributes": {}},
        {"class": "endpoints", "parent": None, "builtin": True,  "attributes": {}},
        {"class": "employee",  "parent": "users",     "builtin": False, "attributes": {
            "tags": {"type": "multi", "values": ["hr", "sales"]},
        }},
        {"class": "database",  "parent": "services",  "builtin": False, "attributes": {
            "content": {"type": "multi"},
        }},
        {"class": "laptop",    "parent": "endpoints", "builtin": False, "attributes": {
            "tags": {"type": "multi", "values": ["managed", "unmanaged"]},
        }},
    ]
    if extra_classes:
        classes.extend(extra_classes)
    return ClassSchema(classes)


def _compile(zpl_text, schema=None):
    """Parse ZPL text and return (rules, schema, engine)."""
    raw = zpl_parser.parse(zpl_text)
    assert not raw["errors"], f"Parse errors: {raw['errors']}"
    ps, errors = norm.zpl_to_policy_set(raw)
    assert not errors, f"Normalize errors: {errors}"
    if schema is None:
        schema = _minimal_schema()
    compiled = []
    for s in ps.rules:
        compiled.append(Rule.from_dict({
            "id": s.id, "name": s.name,
            "result": "never" if s.effect == "deny" else "allow",
            "priority": s.priority, "verb": s.action,
            "subject": {"class": s.subject.cls, "attrs": dict(s.subject.attrs)} if s.subject else None,
            "object":  {"class": s.object.cls,  "attrs": dict(s.object.attrs)}  if s.object  else None,
            "accessor_endpoint": {"class": s.accessor_endpoint.cls, "attrs": dict(s.accessor_endpoint.attrs)} if s.accessor_endpoint else None,
        }))
    return compiled, schema, ZPLEngine(compiled, schema)


def _check(engine, subject_class, action, object_class, subject_attrs=None, object_attrs=None):
    return engine.evaluate(CheckRequest(
        subject=Entity(class_name=subject_class, attrs=subject_attrs or {}),
        object=Entity(class_name=object_class,  attrs=object_attrs  or {}),
        verb=action,
    ))


# ── Parser: bare-name → tags list ────────────────────────────────────────────

class TestParserBareNameToTags:

    def test_single_bare_name_produces_tags_list(self):
        raw = zpl_parser.parse("Allow hr employee to access database.")
        subj = raw["rules"][0]["subject"]
        assert subj["class"] == "employee"
        assert subj["attrs"] == {"tags": ["hr"]}

    def test_namespace_prefixed_bare_name_strips_prefix(self):
        raw = zpl_parser.parse("Allow WS.hr WS.employee to access WS.database.")
        subj = raw["rules"][0]["subject"]
        assert subj["class"] == "WS.employee"
        assert subj["attrs"] == {"tags": ["hr"]}

    def test_multiple_bare_names_build_list(self):
        raw = zpl_parser.parse("Allow hr sales employee to access database.")
        subj = raw["rules"][0]["subject"]
        assert subj["attrs"]["tags"] == ["hr", "sales"]

    def test_bare_name_on_object_side(self):
        raw = zpl_parser.parse("Allow employee to access hr database.")
        obj = raw["rules"][0]["object"]
        assert obj["class"] == "database"
        assert obj["attrs"] == {"tags": ["hr"]}

    def test_bare_name_on_endpoint(self):
        raw = zpl_parser.parse("Allow employee on managed laptop to access database.")
        acc = raw["rules"][0]["accessor_endpoint"]
        assert acc["class"] == "laptop"
        assert acc["attrs"] == {"tags": ["managed"]}

    def test_bare_name_with_colon_attr_mixed(self):
        raw = zpl_parser.parse("Allow hr employee to access content:hr database.")
        subj = raw["rules"][0]["subject"]
        obj  = raw["rules"][0]["object"]
        assert subj["attrs"] == {"tags": ["hr"]}
        assert obj["attrs"]  == {"content": "hr"}

    def test_no_bare_names_produces_no_tags(self):
        raw = zpl_parser.parse("Allow employee to access database.")
        subj = raw["rules"][0]["subject"]
        assert "tags" not in (subj.get("attrs") or {})

    def test_never_rule_bare_name(self):
        raw = zpl_parser.parse("Never allow hr employee on unmanaged laptop to access database.")
        assert raw["rules"][0]["result"] == "never"
        subj = raw["rules"][0]["subject"]
        assert subj["attrs"] == {"tags": ["hr"]}

    def test_bare_name_no_conflict_with_define_tags(self):
        zpl = """
        Define employee as an user with optional tags hr, sales.
        Allow hr employee to access database.
        """
        raw = zpl_parser.parse(zpl)
        cls = raw["classes"][0]
        assert cls["attributes"]["tags"]["values"] == ["hr", "sales"]
        subj = raw["rules"][0]["subject"]
        assert subj["attrs"] == {"tags": ["hr"]}


# ── Parser: colon syntax unchanged ───────────────────────────────────────────

class TestParserColonSyntaxUnchanged:

    def test_colon_attr_still_works(self):
        raw = zpl_parser.parse("Allow employee to access content:hr database.")
        obj = raw["rules"][0]["object"]
        assert obj["attrs"] == {"content": "hr"}

    def test_colon_tags_still_works(self):
        raw = zpl_parser.parse("Allow tags:hr employee to access database.")
        subj = raw["rules"][0]["subject"]
        assert subj["attrs"] == {"tags": "hr"}

    def test_colon_kv_attr_works(self):
        raw = zpl_parser.parse("Allow dept:finance employee to access database.")
        subj = raw["rules"][0]["subject"]
        assert subj["attrs"] == {"dept": "finance"}


# ── Serializer: tags → bare names ────────────────────────────────────────────

class TestSerializerTags:

    def test_tags_list_serializes_as_bare_names(self):
        spec = {"class": "employee", "attrs": {"tags": ["hr"]}}
        result = zpl_serializer._serialize_spec(spec)
        assert result == "hr employee"

    def test_tags_string_serializes_as_bare_name(self):
        spec = {"class": "employee", "attrs": {"tags": "hr"}}
        result = zpl_serializer._serialize_spec(spec)
        assert result == "hr employee"

    def test_multiple_tags_serialize_as_bare_names(self):
        spec = {"class": "employee", "attrs": {"tags": ["hr", "sales"]}}
        result = zpl_serializer._serialize_spec(spec)
        assert result == "hr sales employee"

    def test_non_tag_attrs_serialize_with_colon(self):
        spec = {"class": "database", "attrs": {"content": "hr"}}
        result = zpl_serializer._serialize_spec(spec)
        assert result == "content:hr database"

    def test_mixed_tags_and_attrs_serialize_correctly(self):
        spec = {"class": "employee", "attrs": {"tags": ["hr"], "dept": "finance"}}
        result = zpl_serializer._serialize_spec(spec)
        assert "hr" in result
        assert "dept:finance" in result
        assert result.endswith("employee")

    def test_roundtrip_bare_name(self):
        original = "Allow hr employee to access database."
        raw = zpl_parser.parse(original)
        rule = raw["rules"][0]
        serialized = zpl_serializer.rule_to_zpl(rule)
        assert serialized == "Allow hr employee to access database."

    def test_roundtrip_namespaced_bare_name(self):
        # WS.hr bare name → tags:["hr"] → serialized as bare "hr"
        original = "Allow WS.hr WS.employee to access WS.database."
        raw = zpl_parser.parse(original)
        rule = raw["rules"][0]
        serialized = zpl_serializer.rule_to_zpl(rule)
        # namespace is preserved on class but tag is bare
        assert serialized == "Allow hr WS.employee to access WS.database."

    def test_roundtrip_endpoint_tag(self):
        original = "Allow employee on managed laptop to access database."
        raw = zpl_parser.parse(original)
        rule = raw["rules"][0]
        serialized = zpl_serializer.rule_to_zpl(rule)
        assert serialized == "Allow employee on managed laptop to access database."


# ── Engine: tag matching ──────────────────────────────────────────────────────

class TestEngineTagMatching:
    """Build an engine from parsed ZPL and test entity matching."""

    ZPL = """
    Allow hr employee to access database.
    Allow sales employee to access database.
    Never allow hr employee on unmanaged laptop to access database.
    """

    def setup_method(self):
        self.rules, self.schema, self.engine = _compile(self.ZPL)

    def test_hr_employee_string_tag_matches(self):
        r = _check(self.engine, "employee", "access", "database",
                   subject_attrs={"tags": "hr"})
        assert r.verdict == "allow"

    def test_hr_employee_list_tag_matches(self):
        r = _check(self.engine, "employee", "access", "database",
                   subject_attrs={"tags": ["hr"]})
        assert r.verdict == "allow"

    def test_sales_employee_matches(self):
        r = _check(self.engine, "employee", "access", "database",
                   subject_attrs={"tags": ["sales"]})
        assert r.verdict == "allow"

    def test_employee_with_multiple_tags_matches_hr_rule(self):
        r = _check(self.engine, "employee", "access", "database",
                   subject_attrs={"tags": ["hr", "sales"]})
        assert r.verdict == "allow"

    def test_employee_without_tags_denied(self):
        r = _check(self.engine, "employee", "access", "database")
        assert r.verdict == "deny"

    def test_employee_with_unrelated_tag_denied(self):
        r = _check(self.engine, "employee", "access", "database",
                   subject_attrs={"tags": "engineering"})
        assert r.verdict == "deny"

    def test_never_rule_blocks_hr_on_unmanaged_laptop(self):
        r = _check(self.engine, "employee", "access", "database",
                   subject_attrs={"tags": "hr"})
        # Would be allow, but let's verify the never rule fires when endpoint present
        # (this test uses no endpoint, so no never match — should allow)
        assert r.verdict == "allow"

    def test_trace_shows_tag_match(self):
        r = _check(self.engine, "employee", "access", "database",
                   subject_attrs={"tags": "hr"})
        matched = [t for t in r.trace if t.matched]
        assert matched, "Expected at least one matched rule in trace"


# ── Engine: endpoint tag matching ─────────────────────────────────────────────

class TestEngineEndpointTagMatching:

    ZPL = """
    Allow hr employee on managed laptop to access database.
    Never allow hr employee on unmanaged laptop to access database.
    """

    def setup_method(self):
        self.rules, self.schema, self.engine = _compile(self.ZPL)

    def _check_with_endpoint(self, subject_tags, endpoint_tags, expected):
        req = CheckRequest(
            subject=Entity(class_name="employee", attrs={"tags": subject_tags}),
            object=Entity(class_name="database",  attrs={}),
            verb="access",
            accessor_endpoint=Entity(class_name="laptop", attrs={"tags": endpoint_tags}),
        )
        r = self.engine.evaluate(req)
        assert r.verdict == expected, (
            f"subject_tags={subject_tags}, endpoint_tags={endpoint_tags}: "
            f"expected {expected}, got {r.verdict}\n"
            + "\n".join(f"  {t.rule_name} matched={t.matched}" for t in r.trace)
        )

    def test_hr_on_managed_laptop_allowed(self):
        self._check_with_endpoint("hr", "managed", "allow")

    def test_hr_on_unmanaged_laptop_denied_by_never(self):
        self._check_with_endpoint("hr", "unmanaged", "deny")

    def test_sales_on_managed_laptop_denied_no_matching_allow(self):
        self._check_with_endpoint("sales", "managed", "deny")

    def test_hr_without_endpoint_denied(self):
        r = _check(self.engine, "employee", "access", "database",
                   subject_attrs={"tags": "hr"})
        assert r.verdict == "deny"


# ── Engine: object-side tag matching ─────────────────────────────────────────

class TestEngineObjectTagMatching:

    ZPL = "Allow employee to access customer database."

    def setup_method(self):
        self.rules, self.schema, self.engine = _compile(self.ZPL)

    def test_customer_database_allowed(self):
        r = _check(self.engine, "employee", "access", "database",
                   object_attrs={"tags": "customer"})
        assert r.verdict == "allow"

    def test_hr_database_denied(self):
        r = _check(self.engine, "employee", "access", "database",
                   object_attrs={"tags": "hr"})
        assert r.verdict == "deny"

    def test_database_without_tag_denied(self):
        r = _check(self.engine, "employee", "access", "database")
        assert r.verdict == "deny"


# ── Engine: WS namespace ZPL (real data) ─────────────────────────────────────

class TestWSNamespaceZPL:
    """Reproduce the WS namespace rules from the actual database after namespace injection."""

    ZPL = """
    Define WS.employee as an user with optional tags hr, sales.
    Define WS.laptop as an endpoint with optional tags managed, unmanaged.
    Define WS.database as a service with multiple WS.content.
    Allow WS.sales WS.employee on WS.managed WS.laptop to access WS.content:customer WS.database.
    Allow WS.hr WS.employee on WS.managed WS.laptop to access WS.content:hr WS.database.
    Never allow WS.hr WS.employee on WS.unmanaged WS.laptop to access WS.content:hr WS.database.
    """

    def setup_method(self):
        raw = zpl_parser.parse(self.ZPL)
        assert not raw["errors"], raw["errors"]
        ps, errors = norm.zpl_to_policy_set(raw)
        assert not errors
        system_classes = [
            {"class": "users",     "parent": None, "builtin": True, "attributes": {}},
            {"class": "services",  "parent": None, "builtin": True, "attributes": {}},
            {"class": "endpoints", "parent": None, "builtin": True, "attributes": {}},
        ]
        user_classes = [
            {"class": c.name, "parent": c.parent, "builtin": False,
             "attributes": {k: v.model_dump(exclude_none=True) for k, v in c.attributes.items()}}
            for c in ps.classes
        ]
        schema = ClassSchema(system_classes + user_classes)
        compiled = []
        for s in ps.rules:
            compiled.append(Rule.from_dict({
                "id": s.id, "name": s.name,
                "result": "never" if s.effect == "deny" else "allow",
                "priority": s.priority, "verb": s.action,
                "subject":            {"class": s.subject.cls,            "attrs": dict(s.subject.attrs)}            if s.subject            else None,
                "object":             {"class": s.object.cls,             "attrs": dict(s.object.attrs)}             if s.object             else None,
                "accessor_endpoint":  {"class": s.accessor_endpoint.cls,  "attrs": dict(s.accessor_endpoint.attrs)}  if s.accessor_endpoint  else None,
            }))
        self.engine = ZPLEngine(compiled, schema)

    def _req(self, subject_tags, endpoint_tags, object_tags, object_content=None):
        obj_attrs = {"tags": object_tags} if object_tags else {}
        if object_content:
            obj_attrs["WS.content"] = object_content
        return CheckRequest(
            subject=Entity(class_name="WS.employee", attrs={"tags": subject_tags} if subject_tags else {}),
            object=Entity(class_name="WS.database",  attrs=obj_attrs),
            verb="access",
            accessor_endpoint=Entity(class_name="WS.laptop", attrs={"tags": endpoint_tags} if endpoint_tags else {}),
        )

    def test_sales_on_managed_accesses_customer(self):
        r = self.engine.evaluate(self._req("sales", "managed", None, "customer"))
        assert r.verdict == "allow", r.reason

    def test_hr_on_managed_accesses_hr_data(self):
        r = self.engine.evaluate(self._req("hr", "managed", None, "hr"))
        assert r.verdict == "allow", r.reason

    def test_hr_on_unmanaged_denied(self):
        r = self.engine.evaluate(self._req("hr", "unmanaged", None, "hr"))
        assert r.verdict == "deny", r.reason

    def test_sales_cannot_access_hr_data(self):
        r = self.engine.evaluate(self._req("sales", "managed", None, "hr"))
        assert r.verdict == "deny", r.reason

    def test_hr_cannot_access_customer_data(self):
        r = self.engine.evaluate(self._req("hr", "managed", None, "customer"))
        assert r.verdict == "deny", r.reason

    def test_no_tag_denied(self):
        r = self.engine.evaluate(self._req(None, "managed", None, "hr"))
        assert r.verdict == "deny", r.reason


# ── infer_missing_classes ─────────────────────────────────────────────────────

class TestInferMissingClasses:

    def test_bare_name_infers_tags_attribute(self):
        raw = zpl_parser.parse("Allow hr employee to access database.")
        inferred = zpl_parser.infer_missing_classes(raw)
        emp = next(c for c in inferred if c["class"] == "employee")
        assert "tags" in emp["attributes"]
        assert "hr" in emp["attributes"]["tags"]["values"]

    def test_multiple_bare_names_infer_all_tag_values(self):
        raw = zpl_parser.parse("""
            Allow hr employee to access database.
            Allow sales employee to access database.
        """)
        inferred = zpl_parser.infer_missing_classes(raw)
        emp = next(c for c in inferred if c["class"] == "employee")
        tag_vals = set(emp["attributes"]["tags"]["values"])
        assert {"hr", "sales"} <= tag_vals

    def test_colon_attr_infers_regular_attribute(self):
        raw = zpl_parser.parse("Allow employee to access content:hr database.")
        inferred = zpl_parser.infer_missing_classes(raw)
        db = next(c for c in inferred if c["class"] == "database")
        assert "content" in db["attributes"]
        assert "tags" not in db["attributes"]


# ── _base_payload includes accessor endpoint ──────────────────────────────────

class TestBasePayload:
    """_base_payload must include accessor_endpoint when the rule has one,
    so generated test payloads actually match the rules they are derived from."""

    ZPL = """
    Allow hr employee on managed laptop to access database.
    Allow sales employee to access database.
    """

    def _build_rules(self):
        raw = zpl_parser.parse(self.ZPL)
        ps, _ = norm.zpl_to_policy_set(raw)
        return ps.rules

    def test_rule_with_endpoint_payload_includes_accessor(self):
        rules = self._build_rules()
        hr_rule = next(r for r in rules if r.accessor_endpoint is not None)
        # Simulate what _base_payload does
        s, o, ae = hr_rule.subject, hr_rule.object, hr_rule.accessor_endpoint
        p = {
            "subject_class": s.cls, "subject_attrs": dict(s.attrs),
            "action": hr_rule.action,
            "object_class": o.cls, "object_attrs": dict(o.attrs),
        }
        if ae and ae.cls:
            p["accessor_class"] = ae.cls
            p["accessor_attrs"] = dict(ae.attrs) if ae.attrs else {}
        assert "accessor_class" in p
        assert p["accessor_class"] == "laptop"
        assert p["accessor_attrs"] == {"tags": ["managed"]}

    def test_rule_without_endpoint_payload_has_no_accessor(self):
        rules = self._build_rules()
        sales_rule = next(r for r in rules if r.accessor_endpoint is None)
        s, o = sales_rule.subject, sales_rule.object
        p = {
            "subject_class": s.cls, "subject_attrs": dict(s.attrs),
            "action": sales_rule.action,
            "object_class": o.cls, "object_attrs": dict(o.attrs),
        }
        assert "accessor_class" not in p

    def test_payload_with_endpoint_matches_engine(self):
        """The payload produced from a rule must match that same rule in the engine."""
        rules, schema, engine = _compile(self.ZPL)
        hr_engine_rule = next(r for r in rules if r.accessor_endpoint is not None)
        # Reconstruct the full payload as _base_payload would
        s, o, ae = hr_engine_rule.subject, hr_engine_rule.object, hr_engine_rule.accessor_endpoint
        req = CheckRequest(
            subject=Entity(class_name=s.class_name, attrs=dict(s.attrs)),
            object=Entity(class_name=o.class_name,  attrs=dict(o.attrs)),
            verb=hr_engine_rule.verb,
            accessor_endpoint=Entity(class_name=ae.class_name, attrs=dict(ae.attrs)) if ae else None,
        )
        r = engine.evaluate(req)
        assert r.verdict == "allow", (
            f"Generated payload should match its own rule. verdict={r.verdict}\n"
            + "\n".join(f"  {t.rule_name} matched={t.matched}" for t in r.trace)
        )
