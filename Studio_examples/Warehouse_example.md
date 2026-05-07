# Warehouse Policy Example

## Business Description (Policy Studio input)

I run a distribution warehouse with three types of workers: floor workers who operate
machinery and pack shipments, warehouse workers who manage scheduling and general logistics,
and shift supervisors who oversee operations and have broader system access.

Key systems include a scheduling system for shift and task assignments, an inventory system
for tracking stock levels and orders, a payroll system for wages and hours, a packing machine
for physical packing operations, and a system controller for managing automated equipment.

Access rules:
- Warehouse workers can read the scheduling system to see their assignments.
- Floor workers can operate the packing machine but must not access payroll or touch the
  system controller (safety and financial risk).
- Shift supervisors can access the inventory system to monitor stock and coordinate orders.
- Payroll is restricted — floor workers are explicitly blocked.
- The system controller is restricted — only supervisors should operate automated equipment.

---

## ZPL Policy

```zpl
# Warehouse Operations Policy
# Users:    FloorWorker, WarehouseWorker, ShiftSupervisor
# Services: SchedulingSystem, InventorySystem, PayrollSystem, PackingMachine, SystemController
# Verbs:    read, access, use

Define WarehouseWorker  as a user with role:warehouse-worker, optional shift.
Define FloorWorker      as a user with role:floor-worker, optional shift.
Define ShiftSupervisor  as a user with role:shift-supervisor.

Define SchedulingSystem as a service with classification:corporate.
Define InventorySystem  as a service with classification:corporate.
Define PayrollSystem    as a service with classification:confidential.
Define PackingMachine   as a service with classification:operations.
Define SystemController as a service with classification:restricted.

Allow WarehouseWorker  to read   SchedulingSystem.
Allow ShiftSupervisor  to access InventorySystem.
Allow FloorWorker      to use    PackingMachine.
Never allow FloorWorker to access PayrollSystem.
Never allow FloorWorker to use    SystemController.
```

---

## Test Cases

| # | Subject            | Action | Object            | Expected | Reason |
|---|--------------------|--------|-------------------|----------|--------|
| 1 | WarehouseWorker    | read   | SchedulingSystem  | allow    | Explicit allow rule |
| 2 | WarehouseWorker    | write  | SchedulingSystem  | deny     | Wrong verb — only read is allowed |
| 3 | FloorWorker        | use    | PackingMachine    | allow    | Explicit allow rule |
| 4 | FloorWorker        | access | PayrollSystem     | deny     | Never allow rule |
| 5 | FloorWorker        | use    | SystemController  | deny     | Never allow rule |
| 6 | ShiftSupervisor    | access | InventorySystem   | allow    | Explicit allow rule |
