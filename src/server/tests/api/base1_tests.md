# Base 1 Tests — Match API

Tests the `/api/match` endpoint directly. Each test switches to a namespace,
sends a match request, and checks the verdict.

## Test Cases

### Corp namespace

| # | Subject class | Attrs | Action | Object class | Attrs | Expected | Notes |
|---|---------------|-------|--------|--------------|-------|----------|-------|
| 1 | Corp.employee | tags:[intern] | access | Corp.database | {} | deny | Corp rule: `Never allow intern users to access services.` — uses bare `intern` not `tags:intern`, so this is a **known issue** test: expected deny but likely passes as allow (rule is wrong) |
| 2 | Corp.employee | {} | access | Corp.database | {} | deny | No allow rule for Corp.employee → default deny |

### Hr namespace

| # | Subject class | Attrs | Action | Object class | Attrs | Expected | Notes |
|---|---------------|-------|--------|--------------|-------|----------|-------|
| 3 | Hr.employee | {} | access | Hr.employee-db | {} | allow | Direct rule: Allow Hr.employee to access Hr.employee-db |
| 4 | Hr.employee | tags:[hr] | access | Corp.database | tags:[hr] | allow | Rule: Allow hr Hr.employee to access hr Corp.database |
| 5 | Hr.employee | {} | read | Hr.employee-db | {} | deny | Wrong verb → no matching rule |
| 6 | Hr.employee | tags:[intern] | access | Hr.employee-db | {} | allow | intern tag doesn't block access to employee-db; no deny rule for it in Hr |

### Warehouse namespace

| # | Subject class | Attrs | Action | Object class | Attrs | Expected | Notes |
|---|---------------|-------|--------|--------------|-------|----------|-------|
| 7 | Warehouse.warehouse-worker | {} | read | Warehouse.scheduling-system | {} | allow | Allow warehouse-worker to read scheduling-system |
| 8 | Warehouse.floor-worker | {} | access | Warehouse.payroll-system | {} | deny | Never allow floor-worker to access payroll-system |
| 9 | Warehouse.shift-supervisor | {} | access | Warehouse.inventory-system | {} | allow | Allow shift-supervisor to access inventory-system |
| 10 | Warehouse.floor-worker | {} | use | Warehouse.packing-machine | {} | allow | Allow floor-worker to use packing-machine |
| 11 | Warehouse.warehouse-worker | {} | write | Warehouse.scheduling-system | {} | deny | Wrong verb (write not read) → deny |
| 12 | Warehouse.floor-worker | {} | use | Warehouse.system-controller | {} | deny | Never allow floor-worker to use system-controller |
