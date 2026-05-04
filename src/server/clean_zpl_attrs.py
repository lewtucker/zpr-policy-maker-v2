"""One-shot script: strip wrongly-applied namespace prefixes from attribute names in stored ZPL."""
import sys, sqlite3
sys.path.insert(0, ".")
import zpl_parser, ir_normalizer as norm, zpl_serializer, namespace as ns_mod

DB = "zpr_policy.db"
db = sqlite3.connect(DB)

rows = db.execute(
    "SELECT n.id, n.display_name, nz.zpl_text "
    "FROM namespace_zpl nz JOIN namespaces n ON n.id=nz.namespace_id"
).fetchall()

for ns_id, ns_name, zpl_text in rows:
    prefix = f"{ns_name}."
    raw = zpl_parser.parse(zpl_text)
    ps, errors = norm.zpl_to_policy_set(raw, name="ns")
    if errors:
        print(f"SKIP {ns_name}: parse errors {errors}")
        continue

    pd = ps.model_dump(mode="json")

    # Strip ns prefix from attribute keys — they were never supposed to be prefixed.
    for cls in pd.get("classes", []):
        attrs = cls.get("attributes") or {}
        cls["attributes"] = {
            (k[len(prefix):] if k.startswith(prefix) else k): v
            for k, v in attrs.items()
        }

    cleaned = (
        zpl_serializer.classes_to_zpl(pd.get("classes", [])) + "\n\n" +
        zpl_serializer.rules_to_zpl(pd.get("rules", []))
    ).strip()

    db.execute("UPDATE namespace_zpl SET zpl_text=? WHERE namespace_id=?", (cleaned, ns_id))
    print(f"FIXED {ns_name}")
    print(cleaned)
    print()

db.commit()
print("Done.")
