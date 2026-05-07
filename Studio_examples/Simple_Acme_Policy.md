# Acme Corporation — Simple ZPL Policy (Demo)

## Business Description (Policy Studio input)

Acme Corporation is a mid-size enterprise with three departments: Legal, Sales, and Administration.
Executives hold roles of CEO, SVP, or EVP. External auditors have scoped read access. Active
external partners may collaborate on sales activities. Visitors can look up employees but nothing
more.

The Legal department protects the patent library and contract repository. Both are confidential
and must only be accessible to Legal staff and senior executives (CEO and SVPs). EVPs are
explicitly excluded from both systems. Finance auditors may review the patent library for IP
valuation purposes. All Legal services are bound to a confidential Legal server.

The Sales department manages a customer relationship system and internal sales analytics. Sales
reps and their managers use both systems day-to-day. Executives have visibility into customer
and pipeline data. Only active external partners may access the customer system to support shared
deals — they cannot reach internal analytics. All Sales services run on a corporate-classified
Sales server.

The Administration (IT) department controls an internal IT dashboard and a corporate directory.
The IT dashboard is restricted to Admin staff and senior executives (CEO and SVPs only — EVPs
are excluded), and is bound to a development-classified Admin server. The corporate directory
is openly accessible to all employees, partners, and visitors, and runs on a separate
corporate-classified server.

---

## Namespace Structure

| Namespace    | Owner          | Role              |
|--------------|----------------|-------------------|
| `Acme`       | `acme-admin`   | Root — shared base classes |
| `Acme.Legal` | `priya.sharma` | Chief Legal Officer |
| `Acme.Sales` | `sofia.reyes`  | VP Sales          |
| `Acme.Admin` | `james.wu`     | CIO               |

---

## Namespace: Acme (root)

**Owner:** `acme-admin`

Defines company-wide user types shared across all departments.

### Classes

```zpl
Define Employee  as a user with employee_id, department, optional role, optional on-leave.
Define Executive as a user with role:{CEO, SVP, EVP}.
Define Auditor   as a user with type:auditor, audit_scope.
Define Partner   as a user with type:partner, company, active.
Define Visitor   as a user with type:visitor, optional company.
```

---

## Namespace: Acme.Legal

**Owner:** `priya.sharma`

Protects the patent library and contract repository. Both are confidential and bound to the
Legal server. Only Legal staff and senior executives (CEO and SVPs) may access them. EVPs are
excluded. Finance auditors may review the patent library for IP valuation.

### Classes

```zpl
Define LegalStaff         as a user    with department:legal, optional role.
Define PatentLibrary      as a service with classification:confidential.
Define ContractRepository as a service with classification:confidential.
Define LegalServer        as a server  with classification:confidential, location.
```

### Rules

```zpl
Allow LegalStaff  to access PatentLibrary      on LegalServer.
Allow Executive   to access PatentLibrary      on LegalServer.
Never allow Executive with role:EVP to access  PatentLibrary on LegalServer.
Allow Auditor with audit_scope:legal to access PatentLibrary on LegalServer.
Allow LegalStaff  to access ContractRepository on LegalServer.
Allow Executive   to access ContractRepository on LegalServer.
Never allow Executive with role:EVP to access  ContractRepository on LegalServer.
```

---

## Namespace: Acme.Sales

**Owner:** `sofia.reyes`

Manages access to the customer relationship system and sales analytics. Sales reps and managers
use both day-to-day. Executives have visibility. Only active external partners may access the
customer system — they cannot reach internal analytics.

### Classes

```zpl
Define SalesRep       as a user    with department:sales, optional region.
Define CustomerSystem as a service with classification:corporate.
Define SalesAnalytics as a service with classification:corporate.
Define SalesServer    as a server  with classification:corporate, location.
```

### Rules

```zpl
Allow SalesRep                    to access CustomerSystem on SalesServer.
Allow Executive                   to access CustomerSystem on SalesServer.
Allow Partner with active:true    to access CustomerSystem on SalesServer.
Allow SalesRep                    to access SalesAnalytics on SalesServer.
Allow Executive                   to access SalesAnalytics on SalesServer.
```

---

## Namespace: Acme.Admin

**Owner:** `james.wu`

IT administration controls the internal dashboard and corporate directory. The dashboard is
restricted to Admin staff and senior executives (CEO and SVPs), bound to the Admin server.
The corporate directory runs on a separate corporate server and is open to all employees,
partners, and visitors.

### Classes

```zpl
Define AdminStaff        as a user    with department:admin, optional role.
Define ITDashboard       as a service with classification:development.
Define CorporateDirectory as a service with classification:corporate.
Define AdminServer       as a server  with classification:development, location.
Define CorporateServer   as a server  with classification:corporate, location.
```

### Rules

```zpl
Allow AdminStaff                    to access ITDashboard        on AdminServer.
Allow Executive with role:{CEO, SVP} to access ITDashboard       on AdminServer.
Allow Employee                      to access CorporateDirectory on CorporateServer.
Allow Visitor                       to access CorporateDirectory on CorporateServer.
Allow Partner                       to access CorporateDirectory on CorporateServer.
```

---

## Summary

| Category        | Count |
|-----------------|-------|
| Namespaces      | 4     |
| User classes    | 7     |
| Service classes | 6     |
| Server classes  | 3     |
| **Total classes** | **16** |
| Allow rules     | 14    |
| Never rules     | 3     |
| **Total rules** | **17** |

---

## All ZPL — Copy/Paste Ready

```zpl
# Acme Corporation — Simple Policy Demo
# Namespaces: root, Legal, Sales, Admin
# Default: deny — everything not listed is blocked

Define Employee  as a user with employee_id, department, optional role, optional on-leave.
Define Executive as a user with role:{CEO, SVP, EVP}.
Define Auditor   as a user with type:auditor, audit_scope.
Define Partner   as a user with type:partner, company, active.
Define Visitor   as a user with type:visitor, optional company.

# ── Legal ────────────────────────────────────────────────────────────────────
Define LegalStaff         as a user    with department:legal, optional role.
Define PatentLibrary      as a service with classification:confidential.
Define ContractRepository as a service with classification:confidential.
Define LegalServer        as a server  with classification:confidential, location.

Allow LegalStaff  to access PatentLibrary      on LegalServer.
Allow Executive   to access PatentLibrary      on LegalServer.
Never allow Executive with role:EVP to access  PatentLibrary on LegalServer.
Allow Auditor with audit_scope:legal to access PatentLibrary on LegalServer.
Allow LegalStaff  to access ContractRepository on LegalServer.
Allow Executive   to access ContractRepository on LegalServer.
Never allow Executive with role:EVP to access  ContractRepository on LegalServer.

# ── Sales ────────────────────────────────────────────────────────────────────
Define SalesRep       as a user    with department:sales, optional region.
Define CustomerSystem as a service with classification:corporate.
Define SalesAnalytics as a service with classification:corporate.
Define SalesServer    as a server  with classification:corporate, location.

Allow SalesRep                 to access CustomerSystem on SalesServer.
Allow Executive                to access CustomerSystem on SalesServer.
Allow Partner with active:true to access CustomerSystem on SalesServer.
Allow SalesRep                 to access SalesAnalytics on SalesServer.
Allow Executive                to access SalesAnalytics on SalesServer.

# ── Admin ────────────────────────────────────────────────────────────────────
Define AdminStaff         as a user    with department:admin, optional role.
Define ITDashboard        as a service with classification:development.
Define CorporateDirectory as a service with classification:corporate.
Define AdminServer        as a server  with classification:development, location.
Define CorporateServer    as a server  with classification:corporate, location.

Allow AdminStaff                     to access ITDashboard        on AdminServer.
Allow Executive with role:{CEO, SVP} to access ITDashboard        on AdminServer.
Allow Employee                       to access CorporateDirectory on CorporateServer.
Allow Visitor                        to access CorporateDirectory on CorporateServer.
Allow Partner                        to access CorporateDirectory on CorporateServer.
```
