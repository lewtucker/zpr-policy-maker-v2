# Acme Corporation — ZPL Policy Design

## Overview

Acme Corporation operates a large enterprise datacenter serving employees across six departments: HR, Finance, Engineering, Legal, Sales, and Administration. Users range from full-time employees and managers to executives (CEO, SVP, EVP), interns, external partners, and auditors. Resources include sensitive databases (payroll, employee records, revenue tracking), legal archives (patent library), customer-facing systems, and engineering development infrastructure. Each resource carries a classification level — `restricted`, `confidential`, or `internal` — and runs on dedicated servers organized by department.

The ZPL policy enforces least-privilege access using allow-only rules: each department's namespace defines the classes and rules relevant to its systems, and the default verdict is deny for anything not explicitly allowed. Namespace owners (department heads) are responsible for maintaining their policies. Cross-cutting concerns — executive access and auditor read rights — are expressed as explicit allow rules within each namespace.

---

## Namespace Structure

| Namespace     | Display Name | Owner           | Role              |
|---------------|--------------|-----------------|-------------------|
| `Acme`        | Acme         | `acme-admin`    | Root admin        |
| `Acme.HR`     | HR           | `diana.chen`    | HR Director       |
| `Acme.Finance`| Finance      | `marcus.wells`  | CFO               |
| `Acme.Legal`  | Legal        | `priya.sharma`  | Chief Legal Officer |
| `Acme.Eng`    | Eng          | `raj.patel`     | VP Engineering    |
| `Acme.Sales`  | Sales        | `sofia.reyes`   | VP Sales          |

---

## Namespace: Acme (root)

**Owner:** `acme-admin`

Defines company-wide base user types and executive roles shared across all namespaces.

### Classes

```zpl
Define Employee as a user with employee_id, department, optional role, optional remote-worker, optional on-leave, optional new-hire.
Define Manager as a user with department, role:manager.
Define Executive as a user with role:{CEO, SVP, EVP}.
Define Intern as a user with employment-type:intern, department.
Define Partner as a user with type:partner, company.
Define Auditor as a user with type:auditor, optional firm.
```

---

## Namespace: Acme.HR

**Owner:** `diana.chen`

Controls access to employee records, timesheet data, and the HR management system.

### Classes

```zpl
Define HRStaff as a user with department:hr, optional role.
Define HRDatabase as a service with classification:confidential, env.
Define TimesheetSystem as a service with classification:internal, env.
Define HRServer as a server with location, os.
```

### Rules

```zpl
Allow HRStaff to access HRDatabase.
Allow Manager to access HRDatabase.
Allow Executive to access HRDatabase.
Allow Auditor to access HRDatabase.
Allow HRStaff to access TimesheetSystem.
Allow Employee to access TimesheetSystem.
```

---

## Namespace: Acme.Finance

**Owner:** `marcus.wells`

Governs access to payroll processing, revenue tracking, and financial reporting services. These are the most sensitive systems in the datacenter.

### Classes

```zpl
Define FinanceStaff as a user with department:finance, optional role.
Define PayrollService as a service with classification:restricted, env.
Define RevenueTracker as a service with classification:restricted, env.
Define FinanceServer as a server with location, os, env.
```

### Rules

```zpl
Allow FinanceStaff to access PayrollService.
Allow FinanceStaff to access RevenueTracker.
Allow Manager to access RevenueTracker.
Allow Executive to access PayrollService.
Allow Executive to access RevenueTracker.
Allow Auditor to access PayrollService.
Allow Auditor to access RevenueTracker.
```

---

## Namespace: Acme.Legal

**Owner:** `priya.sharma`

Protects the corporate patent library and legal document repository. Only Legal staff and executives may access these systems; all external users are explicitly denied.

### Classes

```zpl
Define LegalStaff as a user with department:legal, optional role.
Define PatentLibrary as a service with classification:confidential, owner:legal.
Define LegalServer as a server with location, classification:restricted.
```

### Rules

```zpl
Allow LegalStaff to access PatentLibrary.
Allow Executive to access PatentLibrary.
Allow Auditor to access PatentLibrary.
```

---

## Namespace: Acme.Eng

**Owner:** `raj.patel`

Controls access to development environments and engineering infrastructure. Interns may read but never write to development systems; external partners are fully excluded.

### Classes

```zpl
Define Engineer as a user with department:engineering, optional teams, optional remote-worker.
Define DevSystem as a service with env:{development, staging}, os.
Define EngServer as a server with env, os, optional ip-range.
```

### Rules

```zpl
Allow Engineer to access DevSystem.
Allow Manager to access DevSystem.
Allow Intern to access DevSystem.
```

---

## Namespace: Acme.Sales

**Owner:** `sofia.reyes`

Manages access to customer relationship systems and sales data. External partners may read customer data to support joint sales efforts but cannot modify it.

### Classes

```zpl
Define SalesRep as a user with department:sales, optional region.
Define CustomerSystem as a service with classification:internal, env.
Define SalesServer as a server with location, env.
```

### Rules

```zpl
Allow SalesRep to access CustomerSystem.
Allow Manager to access CustomerSystem.
Allow Executive to access CustomerSystem.
Allow Partner to access CustomerSystem.
```

---

## Summary

| Category       | Count |
|----------------|-------|
| Namespaces     | 6     |
| User classes   | 9     |
| Service classes| 8     |
| Server classes | 5     |
| **Total classes** | **22** |
| Allow rules    | 24    |
| Never rules    | 0     |
| **Total rules**| **24** |

### Namespace Owners

| Username        | Display Name   | Owns           |
|-----------------|----------------|----------------|
| `acme-admin`    | Acme Admin     | Acme (root)    |
| `diana.chen`    | Diana Chen     | Acme.HR        |
| `marcus.wells`  | Marcus Wells   | Acme.Finance   |
| `priya.sharma`  | Priya Sharma   | Acme.Legal     |
| `raj.patel`     | Raj Patel      | Acme.Eng       |
| `sofia.reyes`   | Sofia Reyes    | Acme.Sales     |
