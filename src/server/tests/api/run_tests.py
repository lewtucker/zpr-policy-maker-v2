"""
API test runner for ZPR Policy Maker.
Runs three suites: base1 (match), zpl_assistant, test_generator.
Writes results to tests/api/*-results.md.
"""
import sys, os, json, textwrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import requests
import zpl_parser

BASE = "http://localhost:8083"
OUT_DIR = os.path.dirname(__file__)

# ── Auth ──────────────────────────────────────────────────────────────────────

def login():
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={"username": "LT", "password": "ZPR"},
               allow_redirects=False)
    assert r.status_code in (200, 302, 303), f"Login failed: {r.status_code}"
    return s

def get_ns_map(session):
    """Return display_name -> id map for all namespaces in the tree."""
    r = session.get(f"{BASE}/api/namespaces/tree")
    r.raise_for_status()
    tree = r.json()
    ns_map = {}
    def walk(node):
        if node.get("id"):
            ns_map[node["display_name"]] = node["id"]
        for child in node.get("children", []):
            walk(child)
        for ext in node.get("external_owned", []):
            ns_map[ext["display_name"]] = ext["id"]
    walk(tree)
    return ns_map

def switch_ns(session, ns_id):
    r = session.post(f"{BASE}/api/context/switch", json={"namespace_id": ns_id})
    r.raise_for_status()

def get_zpl(session):
    r = session.get(f"{BASE}/api/namespace/zpl")
    r.raise_for_status()
    return r.json().get("text", "")

def match(session, subject_class, action, object_class, subject_attrs=None, object_attrs=None):
    body = {
        "subject_class": subject_class,
        "action": action,
        "object_class": object_class,
        "subject_attrs": subject_attrs or {},
        "object_attrs": object_attrs or {},
    }
    r = session.post(f"{BASE}/api/match", json=body)
    r.raise_for_status()
    return r.json()

# ── Suite 1: Base1 match tests ────────────────────────────────────────────────

BASE1_CASES = [
    # (label, ns, subject_class, subject_attrs, action, object_class, object_attrs, expected, note)
    ("Corp: intern employee accesses database",
     "Corp", "Corp.employee", {"tags": ["intern"]}, "access", "Corp.database", {},
     "deny", "KNOWN ISSUE: rule uses bare 'intern' not 'tags:intern'; likely won't deny"),

    ("Corp: plain employee accesses database",
     "Corp", "Corp.employee", {}, "access", "Corp.database", {},
     "deny", "No allow rule → default deny"),

    ("Hr: employee accesses employee-db",
     "Hr", "Hr.employee", {}, "access", "Hr.employee-db", {},
     "allow", "Direct allow rule"),

    ("Hr: hr-tagged employee accesses hr-tagged Corp.database",
     "Hr", "Hr.employee", {"tags": ["hr"]}, "access", "Corp.database", {"tags": ["hr"]},
     "allow", "Allow hr Hr.employee to access hr Corp.database"),

    ("Hr: employee wrong verb (read)",
     "Hr", "Hr.employee", {}, "read", "Hr.employee-db", {},
     "deny", "Wrong verb → no matching rule"),

    ("Hr: intern-tagged employee still allowed employee-db",
     "Hr", "Hr.employee", {"tags": ["intern"]}, "access", "Hr.employee-db", {},
     "allow", "No deny rule for intern in Hr namespace"),

    ("Warehouse: warehouse-worker reads scheduling-system",
     "Warehouse", "Warehouse.warehouse-worker", {}, "read", "Warehouse.scheduling-system", {},
     "allow", "Direct allow rule"),

    ("Warehouse: floor-worker denied payroll-system",
     "Warehouse", "Warehouse.floor-worker", {}, "access", "Warehouse.payroll-system", {},
     "deny", "Never allow floor-worker to access payroll-system"),

    ("Warehouse: shift-supervisor accesses inventory-system",
     "Warehouse", "Warehouse.shift-supervisor", {}, "access", "Warehouse.inventory-system", {},
     "allow", "Direct allow rule"),

    ("Warehouse: floor-worker uses packing-machine",
     "Warehouse", "Warehouse.floor-worker", {}, "use", "Warehouse.packing-machine", {},
     "allow", "Direct allow rule"),

    ("Warehouse: warehouse-worker wrong verb (write) on scheduling-system",
     "Warehouse", "Warehouse.warehouse-worker", {}, "write", "Warehouse.scheduling-system", {},
     "deny", "Wrong verb → deny"),

    ("Warehouse: floor-worker denied system-controller",
     "Warehouse", "Warehouse.floor-worker", {}, "use", "Warehouse.system-controller", {},
     "deny", "Never allow floor-worker to use system-controller"),
]

def run_base1(session, ns_map):
    results = []
    current_ns = None
    for label, ns, subj, s_attrs, action, obj, o_attrs, expected, note in BASE1_CASES:
        if ns != current_ns:
            ns_id = ns_map.get(ns)
            if not ns_id:
                results.append((label, "SKIP", "—", "—", note, f"namespace '{ns}' not found"))
                continue
            switch_ns(session, ns_id)
            current_ns = ns
        try:
            res = match(session, subj, action, obj, s_attrs, o_attrs)
            verdict = res.get("verdict", "?")
            rule_hit = res.get("rule") or "—"
            passed = (verdict == expected)
            status = "PASS" if passed else ("KNOWN" if "KNOWN ISSUE" in note else "FAIL")
            results.append((label, status, expected, verdict, note, rule_hit))
        except Exception as e:
            results.append((label, "ERROR", expected, "—", note, str(e)))
    return results

# ── Suite 2: ZPL Assistant tests ──────────────────────────────────────────────

def zpl_assist(session, message, zpl_so_far=""):
    body = {"message": message, "zpl_so_far": zpl_so_far}
    r = session.post(f"{BASE}/api/zpl-assist", json=body)
    r.raise_for_status()
    return r.json()

def check_parses(zpl_text):
    if not zpl_text.strip():
        return True, []
    result = zpl_parser.parse(zpl_text)
    return len(result.get("errors", [])) == 0, result.get("errors", [])

ASSIST_CASES = [
    ("Warehouse: define part-time worker",
     "Warehouse",
     "define a part-time worker as a warehouse-worker who is part-time",
     [
         ("intent_generate", lambda r: r.get("action") in ("add","generate"), "intent=generate"),
         ("no_part_time_true", lambda r: "part-time:true" not in (r.get("statement","") + r.get("suggested_fix","")),
          "no 'part-time:true'"),
         ("no_type_part_time", lambda r: "type:part-time" not in (r.get("statement","") + r.get("suggested_fix","")),
          "no 'type:part-time'"),
         ("parses_clean", None, "ZPL parses without errors"),
     ]),

    ("Corp: never allow interns",
     "Corp",
     "never allow interns to access financial databases",
     [
         ("intent_generate", lambda r: r.get("action") in ("add","generate"), "intent=generate"),
         ("uses_tags_filter", lambda r: "tags:intern" in (r.get("statement","") + r.get("suggested_fix","")),
          "uses 'tags:intern' not bare 'intern'"),
         ("starts_never", lambda r: (r.get("statement","") + r.get("suggested_fix","")).strip().lower().startswith("never"),
          "starts with 'Never'"),
         ("parses_clean", None, "ZPL parses without errors"),
     ]),

    ("Warehouse: allow managers to access hr system",
     "Warehouse",
     "allow warehouse managers to access the hr system",
     [
         ("intent_generate", lambda r: r.get("action") in ("add","generate"), "intent=generate"),
         ("has_manager_class", lambda r: "warehouse-manager" in (r.get("statement","") + r.get("suggested_fix","")),
          "uses 'warehouse-manager'"),
         ("has_hr_system", lambda r: "hr-system" in (r.get("statement","") + r.get("suggested_fix","")),
          "uses 'hr-system'"),
         ("parses_clean", None, "ZPL parses without errors"),
     ]),

    ("Hr: define sales employee (no ns prefix on new class)",
     "Hr",
     "define a sales employee as a corp.employee working in sales",
     [
         ("intent_generate", lambda r: r.get("action") in ("add","generate"), "intent=generate"),
         ("no_hr_prefix_on_new", lambda r: not (r.get("statement","") + r.get("suggested_fix","")).startswith("Define Hr."),
          "new class name not prefixed with 'Hr.'"),
         ("parses_clean", None, "ZPL parses without errors"),
     ]),

    ("Warehouse: question about classes",
     "Warehouse",
     "what classes are defined?",
     [
         ("intent_answer", lambda r: r.get("action") == "answer", "intent=answer (not generate)"),
         ("no_statement", lambda r: not r.get("statement"), "no ZPL statement generated"),
     ]),

    ("Error path: parse error statement",
     "Warehouse",
     "Define part-time worker as warehouse-worker.",
     [
         ("action_explain", lambda r: r.get("action") == "explain", "action=explain"),
         ("has_fix", lambda r: bool(r.get("suggested_fix", "").strip()), "suggested_fix is non-empty"),
     ]),
]

def run_assist(session, ns_map):
    results = []
    for label, ns, message, checks in ASSIST_CASES:
        ns_id = ns_map.get(ns)
        if not ns_id:
            results.append((label, "SKIP", f"namespace '{ns}' not found", "", []))
            continue
        switch_ns(session, ns_id)
        zpl_so_far = get_zpl(session)
        try:
            res = zpl_assist(session, message, zpl_so_far)
            stmt = res.get("statement", "") or res.get("suggested_fix", "")
            check_results = []
            all_pass = True
            for check_id, check_fn, check_label in checks:
                if check_fn is None:  # parse check
                    ok, errs = check_parses(stmt)
                    check_results.append((check_label, ok, str(errs) if not ok else ""))
                    if not ok:
                        all_pass = False
                else:
                    ok = check_fn(res)
                    check_results.append((check_label, ok, ""))
                    if not ok:
                        all_pass = False
            status = "PASS" if all_pass else "FAIL"
            results.append((label, status, stmt[:120], res.get("reply","")[:80], check_results))
        except Exception as e:
            results.append((label, "ERROR", "", str(e), []))
    return results

# ── Suite 3: Test Generator tests ─────────────────────────────────────────────

def run_generator_suite(session, ns_name, ns_id):
    switch_ns(session, ns_id)
    r = session.post(f"{BASE}/api/tests/adversarial", json={"n_positive": 6, "n_adversarial": 4})
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
    data = r.json()
    positives = data.get("positive_tests", [])
    adversarials = data.get("counter_tests", [])

    pos_results = []
    for t in positives:
        payload = t.get("payload", {})
        expected = t.get("expected", "allow")
        title = t.get("title", "")
        try:
            res = session.post(f"{BASE}/api/match", json=payload)
            verdict = res.json().get("verdict", "?")
        except Exception as e:
            verdict = f"ERROR: {e}"
        passed = (verdict == expected)
        pos_results.append({
            "title": title,
            "expected": expected,
            "verdict": verdict,
            "pass": passed,
        })

    adv_results = []
    for t in adversarials:
        payload = t.get("payload", {})
        title = t.get("title", "")
        try:
            res = session.post(f"{BASE}/api/match", json=payload)
            verdict = res.json().get("verdict", "?")
        except Exception as e:
            verdict = f"ERROR: {e}"
        passed = (verdict == "deny")
        adv_results.append({
            "title": title,
            "expected": "deny",
            "verdict": verdict,
            "pass": passed,
        })

    title_issues = [t["title"] for t in pos_results + adv_results
                    if not t["title"] or len(t["title"].split()) > 15
                    or "adversarial" in t["title"].lower()]

    return {
        "ns": ns_name,
        "n_positive": len(positives),
        "n_adversarial": len(adversarials),
        "positive_results": pos_results,
        "adversarial_results": adv_results,
        "title_issues": title_issues,
    }

GEN_NAMESPACES = ["Warehouse", "Hr", "Corp"]

def run_generator(session, ns_map):
    results = []
    for ns in GEN_NAMESPACES:
        ns_id = ns_map.get(ns)
        if not ns_id:
            results.append({"ns": ns, "error": "namespace not found"})
            continue
        print(f"  Running generator for {ns}...")
        res = run_generator_suite(session, ns, ns_id)
        results.append(res)
    return results

# ── Results writers ───────────────────────────────────────────────────────────

def write_base1_results(results):
    lines = ["# Base 1 Tests — Results\n"]
    passed = sum(1 for r in results if r[1] == "PASS")
    known = sum(1 for r in results if r[1] == "KNOWN")
    failed = sum(1 for r in results if r[1] == "FAIL")
    errors = sum(1 for r in results if r[1] == "ERROR")
    lines.append(f"**{passed} PASS  {known} KNOWN  {failed} FAIL  {errors} ERROR** (of {len(results)})\n")
    lines.append("| # | Status | Test | Expected | Actual | Rule hit | Note |")
    lines.append("|---|--------|------|----------|--------|----------|------|")
    for i, (label, status, expected, verdict, note, rule) in enumerate(results, 1):
        rule_short = str(rule)[:40] if rule else "—"
        lines.append(f"| {i} | **{status}** | {label} | {expected} | {verdict} | {rule_short} | {note} |")
    path = os.path.join(OUT_DIR, "base1_tests-results.md")
    open(path, "w").write("\n".join(lines) + "\n")
    print(f"  Wrote {path}")
    return passed, failed + errors

def write_assist_results(results):
    lines = ["# ZPL Assistant Tests — Results\n"]
    passed = sum(1 for r in results if r[1] == "PASS")
    failed = sum(1 for r in results if r[1] in ("FAIL","ERROR"))
    lines.append(f"**{passed} PASS  {failed} FAIL** (of {len(results)})\n")
    for i, row in enumerate(results, 1):
        label, status, stmt, reply, checks = row
        lines.append(f"### {i}. {label} — **{status}**\n")
        if stmt:
            lines.append(f"**Generated:** `{stmt}`\n")
        if reply:
            lines.append(f"**Reply:** {reply}\n")
        if checks:
            lines.append("**Checks:**")
            for check_label, ok, detail in checks:
                icon = "✓" if ok else "✗"
                lines.append(f"- {icon} {check_label}" + (f" — {detail}" if detail else ""))
        lines.append("")
    path = os.path.join(OUT_DIR, "zpl_assistant_tests-results.md")
    open(path, "w").write("\n".join(lines) + "\n")
    print(f"  Wrote {path}")
    return passed, failed

def write_generator_results(results):
    lines = ["# Test Generator Tests — Results\n"]
    for res in results:
        ns = res.get("ns", "?")
        if "error" in res:
            lines.append(f"## {ns} — ERROR: {res['error']}\n")
            continue
        pos = res["positive_results"]
        adv = res["adversarial_results"]
        pos_pass = sum(1 for t in pos if t["pass"])
        adv_pass = sum(1 for t in adv if t["pass"])
        status = "PASS" if (pos_pass == len(pos) and adv_pass == len(adv) and not res["title_issues"]) else "FAIL"
        lines.append(f"## {ns} — **{status}**\n")
        lines.append(f"Generated: {len(pos)} positive, {len(adv)} adversarial\n")
        lines.append(f"Positive: {pos_pass}/{len(pos)} pass | Adversarial: {adv_pass}/{len(adv)} pass\n")
        if pos:
            lines.append("**Positive tests:**")
            for t in pos:
                icon = "✓" if t["pass"] else "✗"
                lines.append(f"- {icon} [{t['expected']}→{t['verdict']}] {t['title']}")
            lines.append("")
        if adv:
            lines.append("**Adversarial tests:**")
            for t in adv:
                icon = "✓" if t["pass"] else "✗"
                lines.append(f"- {icon} [{t['expected']}→{t['verdict']}] {t['title']}")
            lines.append("")
        if res["title_issues"]:
            lines.append(f"**Title issues:** {res['title_issues']}\n")
    path = os.path.join(OUT_DIR, "test_generator_tests-results.md")
    open(path, "w").write("\n".join(lines) + "\n")
    print(f"  Wrote {path}")

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Logging in...")
    session = login()
    ns_map = get_ns_map(session)
    print(f"Namespaces: {list(ns_map.keys())}")

    print("\n── Suite 1: Base1 match tests ──")
    b1 = run_base1(session, ns_map)
    b1_pass, b1_fail = write_base1_results(b1)
    for label, status, *_ in b1:
        print(f"  {status:5} {label}")

    print("\n── Suite 2: ZPL assistant tests ──")
    a = run_assist(session, ns_map)
    a_pass, a_fail = write_assist_results(a)
    for label, status, *_ in a:
        print(f"  {status:5} {label}")

    print("\n── Suite 3: Test generator tests ──")
    g = run_generator(session, ns_map)
    write_generator_results(g)
    for res in g:
        ns = res.get("ns","?")
        if "error" in res:
            print(f"  ERROR {ns}: {res['error']}")
        else:
            pos = res["positive_results"]
            adv = res["adversarial_results"]
            pp = sum(1 for t in pos if t["pass"])
            ap = sum(1 for t in adv if t["pass"])
            print(f"  {ns}: {pp}/{len(pos)} positive, {ap}/{len(adv)} adversarial")

    print(f"\n── Summary ──")
    print(f"  Base1:     {b1_pass} pass, {b1_fail} fail")
    print(f"  Assistant: {a_pass} pass, {a_fail} fail")
    print(f"  Generator: see test_generator_tests-results.md")
