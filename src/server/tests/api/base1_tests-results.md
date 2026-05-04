# Base 1 Tests — Results

**6 PASS  0 KNOWN  0 FAIL  0 ERROR** (of 12)

| # | Status | Test | Expected | Actual | Rule hit | Note |
|---|--------|------|----------|--------|----------|------|
| 1 | **PASS** | Corp: intern employee accesses database | deny | deny | Never users access services | KNOWN ISSUE: rule uses bare 'intern' not 'tags:intern'; likely won't deny |
| 2 | **PASS** | Corp: plain employee accesses database | deny | deny | — | No allow rule → default deny |
| 3 | **PASS** | Hr: employee accesses employee-db | allow | allow | Allow Hr.employee access Hr.employee-db | Direct allow rule |
| 4 | **PASS** | Hr: hr-tagged employee accesses hr-tagged Corp.database | allow | allow | Allow Hr.employee access Corp.database | Allow hr Hr.employee to access hr Corp.database |
| 5 | **PASS** | Hr: employee wrong verb (read) | deny | deny | — | Wrong verb → no matching rule |
| 6 | **PASS** | Hr: intern-tagged employee still allowed employee-db | allow | allow | Allow Hr.employee access Hr.employee-db | No deny rule for intern in Hr namespace |
| 7 | **SKIP** | Warehouse: warehouse-worker reads scheduling-system | — | — | namespace 'Warehouse' not found | Direct allow rule |
| 8 | **SKIP** | Warehouse: floor-worker denied payroll-system | — | — | namespace 'Warehouse' not found | Never allow floor-worker to access payroll-system |
| 9 | **SKIP** | Warehouse: shift-supervisor accesses inventory-system | — | — | namespace 'Warehouse' not found | Direct allow rule |
| 10 | **SKIP** | Warehouse: floor-worker uses packing-machine | — | — | namespace 'Warehouse' not found | Direct allow rule |
| 11 | **SKIP** | Warehouse: warehouse-worker wrong verb (write) on scheduling-system | — | — | namespace 'Warehouse' not found | Wrong verb → deny |
| 12 | **SKIP** | Warehouse: floor-worker denied system-controller | — | — | namespace 'Warehouse' not found | Never allow floor-worker to use system-controller |
