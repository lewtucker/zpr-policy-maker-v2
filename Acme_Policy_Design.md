# Acme Corporation — ZPL Policy Design

## Overview

## Prompt: Guidence for making ZPL rules

Acme Corporation operates a large enterprise datacenter serving employees across six departments: HR, Finance, Engineering, Legal, Sales, and Administration. Users range from full-time employees and managers to executives (CEO, SVP, EVP), interns, external partners, and auditors. Resources and services include sensitive databases (payroll, employee records, revenue tracking), legal archives (patent library), customer-facing systems, and engineering development infrastructure. These services should only be accessible to employees in the corresponding department or the senior executives.  Servers running these apps are endpoints with a classification level of:  `confidential` for legal and financial, `corporate` for general employees, and 'development' for engineering and administration.   Map the services, such as databases, to run on appropriately named servers as endpoints, so there are simple ways to restrict access. 

The ZPL policy enforces least-privilege access using allow-only rules: each department's namespace defines the classes and rules relevant to its systems, and the default verdict is deny for anything not explicitly allowed. Namespace owners (department heads) are responsible for maintaining their policies. Cross-cutting concerns — executive access and auditor read rights — are expressed as explicit allow rules within each namespace.

When making rules, after defining the users, services, and endpoints it's advisable to start with a service designed for a particular department, determine who should have access and then make rules that seem reasonable.  It's ok if some users won't have any access, such as visitors which only have access to a corporate directory to look up employees.


A hint on the use of Never Allow rules.  In general things are easier when only Allow rules are made, but when it's necessary to block only some employees from something broadly accessed, two rules can be used.  For example, if we wanted to give all employees access to benefits except those in the state of Tennessee, we could do that as follows:
 - Allow employees with employee_id: to access benefits
 - Never allow employees with state:Tennessee to access benefits

This lets only employees with an employee_id access benefits while narrowly blocking those employees that either lack a employee_id or are in the state of Tennessee.



Try to make this based on a realistic scenario of what might go on in a corporation or business.

---

## Design Notes

### Server-based access control

Rules use `on <ServerClass>` to bind access to where a service runs. This lets the same service type carry different access policies depending on its deployment context — a service on a `confidential` server is governed by stricter rules than the same service on a `corporate` server. Confidential and development services all carry explicit server constraints; broadly-accessible corporate services (TimesheetSystem, ExpenseSystem, CorporateDirectory) do not, reflecting their intentionally open nature.

### Auditor scoping

The `Auditor` class carries an `audit_scope` attribute so each namespace can require auditors to present a matching scope. A financial auditor has no business in the patent library; an IP auditor has no business in payroll.

### Partner active status

`Partner` carries an `active` attribute. Only active partners may access the customer system, preventing access by former partner companies.

---

## Namespace Structure

| Namespace      | Display Name | Owner           | Role                  |
|----------------|--------------|-----------------|-----------------------|
| `Acme`         | Acme         | `acme-admin`    | Root admin            |
| `Acme.HR`      | HR           | `diana.chen`    | HR Director           |
| `Acme.Finance` | Finance      | `marcus.wells`  | CFO                   |
| `Acme.Legal`   | Legal        | `priya.sharma`  | Chief Legal Officer   |
| `Acme.Eng`     | Eng          | `raj.patel`     | VP Engineering        |
| `Acme.Sales`   | Sales        | `sofia.reyes`   | VP Sales              |
| `Acme.Admin`   | Admin        | `james.wu`      | CIO                   |

---

## Namespace: Acme (root)

**Owner:** `acme-admin`

Defines company-wide base user types and executive roles shared across all namespaces. Visitors and external partners are also defined here so every namespace can reference them without duplication.

### Classes

```zpl
Define Employee as a user with employee_id, department, optional role, optional remote-worker, optional on-leave, optional new-hire.
Define Regular_Employee as a Employee with employment_type:full_time.
Define Part_Time_Employee as a Employee with employment_type:part_time.
Define Manager as a user with department, role:manager.
Define Executive as a user with role:{CEO, SVP, EVP}.
Define Intern as a user with employment_type:intern, department.
Define Partner as a user with type:partner, company, active.
Define Auditor as a user with type:auditor, audit_scope, optional firm.
Define Visitor as a user with type:visitor, optional company.
```

---

## Namespace: Acme.HR

**Owner:** `diana.chen`

Controls access to employee records, timesheet data, and the onboarding portal. The HR database holds confidential personal and compensation data and is bound to the confidential HR server. The timesheet and onboarding systems are corporate-classified and accessible more broadly, but still run on the HR server.

### Classes

```zpl
Define HRStaff as a user with department:hr, optional role.
Define HRDatabase as a service with classification:confidential, env.
Define TimesheetSystem as a service with classification:corporate, env.
Define OnboardingPortal as a service with classification:corporate, env.
Define HRServer as a server with classification:confidential, location, os.
```

### Rules

```zpl
Allow HRStaff to access HRDatabase on HRServer.
Allow Manager with department:hr to access HRDatabase on HRServer.
Allow Executive with role:CEO to access HRDatabase on HRServer.
Allow Auditor with audit_scope:hr to access HRDatabase on HRServer.
Allow HRStaff to access TimesheetSystem.
Allow Employee to access TimesheetSystem.
Allow Intern to access TimesheetSystem.
Never allow Employee with on-leave:true to access TimesheetSystem.
Allow HRStaff to access OnboardingPortal.
Allow Manager to access OnboardingPortal.
```

---

## Namespace: Acme.Finance

**Owner:** `marcus.wells`

Governs access to payroll, revenue tracking, and the company-wide expense submission system. Payroll and revenue data are the most sensitive assets in the datacenter; all rules for these services bind them explicitly to the confidential Finance server. All employees can submit expenses without a server constraint since the expense system is corporate-classified.

### Classes

```zpl
Define FinanceStaff as a user with department:finance, optional role.
Define PayrollService as a service with classification:confidential, env.
Define RevenueTracker as a service with classification:confidential, env.
Define ExpenseSystem as a service with classification:corporate, env.
Define FinanceServer as a server with classification:confidential, location, os.
```

### Rules

```zpl
Allow FinanceStaff to access PayrollService on FinanceServer.
Allow Executive with role:CEO to access PayrollService on FinanceServer.
Allow Auditor with audit_scope:finance to access PayrollService on FinanceServer.
Allow FinanceStaff to access RevenueTracker on FinanceServer.
Allow Manager with department:finance to access RevenueTracker on FinanceServer.
Allow Executive with role:{CEO, SVP} to access RevenueTracker on FinanceServer.
Allow Auditor with audit_scope:finance to access RevenueTracker on FinanceServer.
Allow Employee to access ExpenseSystem.
Allow Manager to access ExpenseSystem.
Never allow Employee with on-leave:true to access ExpenseSystem.
```

---

## Namespace: Acme.Legal

**Owner:** `priya.sharma`

Protects the patent library and contract repository. Both are confidential and bound to the Legal server. Only Legal staff and senior executives (CEO and SVPs who may be signatories or litigation stakeholders) may access them. EVPs are excluded from both systems. Finance auditors may review the patent library for IP valuation; no other auditors have access.

### Classes

```zpl
Define LegalStaff as a user with department:legal, optional role.
Define PatentLibrary as a service with classification:confidential, owner:legal.
Define ContractRepository as a service with classification:confidential, owner:legal.
Define LegalServer as a server with classification:confidential, location, os.
```

### Rules

```zpl
Allow LegalStaff to access PatentLibrary on LegalServer.
Allow Executive to access PatentLibrary on LegalServer.
Never allow Executive with role:EVP to access PatentLibrary on LegalServer.
Allow Auditor with audit_scope:legal to access PatentLibrary on LegalServer.
Allow LegalStaff to access ContractRepository on LegalServer.
Allow Manager with department:legal to access ContractRepository on LegalServer.
Allow Executive to access ContractRepository on LegalServer.
Never allow Executive with role:EVP to access ContractRepository on LegalServer.
```

---

## Namespace: Acme.Eng

**Owner:** `raj.patel`

Controls access to development environments and CI/CD infrastructure. All engineering services are bound to the development-classified Eng server. Engineers and engineering managers have full access to both systems. Engineering interns may access the dev system but not CI/CD pipelines. Partners and non-engineering employees are excluded entirely.

### Classes

```zpl
Define Engineer as a user with department:engineering, optional teams, optional remote-worker.
Define DevSystem as a service with env:{development, staging}, os.
Define CISystem as a service with env:staging, os.
Define EngServer as a server with classification:development, env, os, optional ip-range.
```

### Rules

```zpl
Allow Engineer to access DevSystem on EngServer.
Allow Manager with department:engineering to access DevSystem on EngServer.
Allow Intern with department:engineering to access DevSystem on EngServer.
Allow Engineer to access CISystem on EngServer.
Allow Manager with department:engineering to access CISystem on EngServer.
```

---

## Namespace: Acme.Sales

**Owner:** `sofia.reyes`

Manages access to the customer relationship system and sales analytics. Sales reps and their managers use both systems day-to-day. Executives have visibility into customer and pipeline data. Only active external partners may access the customer system to support shared deals; they cannot access internal analytics. All Sales services are bound to the corporate-classified Sales server.

### Classes

```zpl
Define SalesRep as a user with department:sales, optional region.
Define CustomerSystem as a service with classification:corporate, env.
Define SalesAnalytics as a service with classification:corporate, env.
Define SalesServer as a server with classification:corporate, location, env.
```

### Rules

```zpl
Allow SalesRep to access CustomerSystem on SalesServer.
Allow Manager with department:sales to access CustomerSystem on SalesServer.
Allow Executive to access CustomerSystem on SalesServer.
Allow Partner with active:true to access CustomerSystem on SalesServer.
Allow SalesRep to access SalesAnalytics on SalesServer.
Allow Manager with department:sales to access SalesAnalytics on SalesServer.
Allow Executive to access SalesAnalytics on SalesServer.
```

---

## Namespace: Acme.Admin

**Owner:** `james.wu`

IT administration controls internal tooling, infrastructure monitoring, and the corporate directory. The IT dashboard and monitoring system are restricted to Admin staff and senior executives (CEO and SVPs), bound to the development-classified Admin server. The corporate directory runs on a separate corporate-classified server and is openly accessible to all employees, partners, and visitors.

### Classes

```zpl
Define AdminStaff as a user with department:admin, optional role.
Define ITDashboard as a service with classification:development, env.
Define MonitoringSystem as a service with classification:development, env.
Define CorporateDirectory as a service with classification:corporate, env.
Define AdminServer as a server with classification:development, location, os.
Define CorporateServer as a server with classification:corporate, location, os.
```

### Rules

```zpl
Allow AdminStaff to access ITDashboard on AdminServer.
Allow Manager with department:admin to access ITDashboard on AdminServer.
Allow AdminStaff to access MonitoringSystem on AdminServer.
Allow Executive to access MonitoringSystem on AdminServer.
Never allow Executive with role:EVP to access MonitoringSystem on AdminServer.
Allow Employee to access CorporateDirectory on CorporateServer.
Allow Visitor to access CorporateDirectory on CorporateServer.
Allow Partner to access CorporateDirectory on CorporateServer.
```

---

## Summary

| Category          | Count |
|-------------------|-------|
| Namespaces        | 7     |
| User classes      | 10    |
| Service classes   | 15    |
| Server classes    | 7     |
| **Total classes** | **32**|
| Allow rules       | 44    |
| Never rules       | 5     |
| **Total rules**   | **49**|

### Namespace Owners

| Username        | Display Name   | Owns           |
|-----------------|----------------|----------------|
| `acme-admin`    | Acme Admin     | Acme (root)    |
| `diana.chen`    | Diana Chen     | Acme.HR        |
| `marcus.wells`  | Marcus Wells   | Acme.Finance   |
| `priya.sharma`  | Priya Sharma   | Acme.Legal     |
| `raj.patel`     | Raj Patel      | Acme.Eng       |
| `sofia.reyes`   | Sofia Reyes    | Acme.Sales     |
| `james.wu`      | James Wu       | Acme.Admin     |

### Server Classification Map

| Server          | Classification | Hosts                                          |
|-----------------|----------------|------------------------------------------------|
| HRServer        | confidential   | HRDatabase (constrained), TimesheetSystem, OnboardingPortal |
| FinanceServer   | confidential   | PayrollService (constrained), RevenueTracker (constrained), ExpenseSystem |
| LegalServer     | confidential   | PatentLibrary (constrained), ContractRepository (constrained) |
| EngServer       | development    | DevSystem (constrained), CISystem (constrained) |
| SalesServer     | corporate      | CustomerSystem (constrained), SalesAnalytics (constrained) |
| AdminServer     | development    | ITDashboard (constrained), MonitoringSystem (constrained) |
| CorporateServer | corporate      | CorporateDirectory (constrained)               |
