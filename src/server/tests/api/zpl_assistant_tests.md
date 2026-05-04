# ZPL Assistant Tests

Tests the `/api/zpl-assist` endpoint. Each test sends a natural-language message
with the current namespace's ZPL as context. Evaluation checks:
- Correct `intent` (generate/modify/answer/explain)
- Generated ZPL parses without errors
- Specific pattern checks (correct syntax, class names, no forbidden patterns)

## Test Cases

| # | Namespace | Message | zpl_so_far | Expected intent | Pattern checks |
|---|-----------|---------|-----------|-----------------|----------------|
| 1 | Warehouse | "define a part-time worker as a warehouse-worker who is part-time" | Warehouse ZPL | generate | ZPL parses clean; uses `tags part-time` not `part-time:true` or `type:part-time` |
| 2 | Corp | "never allow interns to access financial databases" | Corp ZPL | generate | ZPL parses clean; uses `tags:intern` not bare `intern`; starts with `Never allow` |
| 3 | Warehouse | "allow warehouse managers to access the hr system" | Warehouse ZPL | generate | ZPL parses clean; uses `Warehouse.warehouse-manager` and `Warehouse.hr-system` exactly |
| 4 | Hr | "define a sales employee as a corp.employee working in sales" | Hr ZPL | generate | ZPL parses clean; new class name has no `Hr.` prefix; parent is `corp.employee` |
| 5 | Warehouse | "what classes are defined?" | Warehouse ZPL | answer | intent=answer, no ZPL statement generated |
| 6 | Warehouse | "Define part-time worker as warehouse-worker." (deliberate parse error: space in class name) | Warehouse ZPL | explain | action=explain; `suggested_fix` field present and non-empty |
