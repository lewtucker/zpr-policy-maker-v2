# Oracle ZPR Policy Language — Syntax Reference

Source: https://docs.oracle.com/en-us/iaas/Content/zero-trust-packet-routing/zpr-policy-syntax.htm

No formal BNF is published by Oracle. This document captures the informal grammar
rules, constraints, and naming conventions described in Oracle's documentation.

---

## Core Model

- **Allowlist only.** There is no `deny`, `never`, or `define` keyword. Anything
  not explicitly allowed is denied by default.
- **Only one verb:** `to connect to`
- **VCNs are identified by security attributes**, not by name or OCID. A policy
  applies to every VCN carrying the specified attribute.
- **Two structural forms** depending on whether traffic is within one VCN or
  between two peered VCNs.

---

## Security Attribute Format

```
[<namespace>.]<key>:<value>
```

- `namespace` and `key` separated by `.` (period)
- `key` and `value` separated by `:` (colon)
- No spaces or periods in namespace or key
- Values may contain spaces, periods, single quotes
- If value is long or contains special chars, wrap entire clause in single quotes
- Single quotes inside values must be escaped as `''` (doubled)
- If namespace is omitted, ZPR defaults to `oracle-zpr`

**Examples:**
```
app:fin-network
oracle-zpr.app:fe-nodes
my-corp.biz:hr
'my-corp.biz:dev and test db'
```

**Naming constraints:**

| Element   | Valid chars            | Max length |
|-----------|------------------------|------------|
| Namespace | `[A-Za-z0-9\-_]`      | 100        |
| Key       | `[A-Za-z0-9\-_]`      | 100        |
| Value     | Any ASCII/Unicode      | 255        |

---

## Form 1 — Single VCN

Traffic within one VCN.

```
in <security-attribute> VCN allow <source-endpoint> to connect to <dest-endpoint> [with <filter>]*
```

**Constraints:**
- `<location>` must be `in <single-security-attribute> VCN` — exactly one attribute, no IP/CIDR
- `<command>` must be `allow`
- Source or destination (not both) may be an IP/CIDR or `osn-services-ip-addresses`
- Source and destination cannot both be `all-endpoints`

---

## Form 2 — Two VCNs (same region and tenancy)

Traffic between two peered VCNs.

```
allow <source-endpoint> endpoints in <source-vcn-attr> VCN to connect to <dest-endpoint> endpoints [with <filter>]* in <dest-vcn-attr> VCN
```

**Constraints:**
- Both VCNs must be in the same region and tenancy
- Both endpoints must be security attributes — no IP/CIDR allowed in this form
- Each VCN location must be exactly one security attribute

---

## Endpoint Reference Types

| Form | Syntax | Notes |
|------|--------|-------|
| Security attribute | `app:web endpoints` | `endpoints` keyword optional |
| IP/CIDR | `'10.0.0.0/16'` | Single-quoted; Form 1 only |
| Single IP | `'192.168.0.1'` | Single-quoted; Form 1 only |
| Any source/dest | `all-endpoints` | Cannot appear on both sides |
| OCI service IPs | `'osn-services-ip-addresses'` | Magic literal; Form 1 only |

---

## Filter Clauses

Appended after the destination endpoint. Multiple filters use comma-separated
syntax or repeated `with` keywords:

```
with protocol='tcp/1521', connection-state='stateless'
with protocol='tcp/1521' with connection-state='stateless'
```

| Attribute | Format | Example |
|-----------|--------|---------|
| `protocol` | `'<name>/<port>'` | `'tcp/22'` |
| `protocol` (range) | `'<name>/<low>-<high>'` | `'tcp/999-11199'` |
| `protocol.icmp.type` | `'<integer>'` | `'8'` |
| `protocol.icmp.code` | `'<integer>'` | `'0'` |
| `connection-state` | `'stateless'` | `'stateless'` |

- `stateful` is the default; no value needed
- Protocol names/numbers follow IANA conventions

---

## Service Limits

| Limit | Value |
|-------|-------|
| Security attributes per tenancy | 1,000 |
| Security attributes per VCN | 1 |
| Security attributes per VNIC | 5 |
| Security attributes per other resource | 3 |
| Predefined values per security attribute key | 100 |
| Policy statements per policy object | 50 |
| Policy objects per tenancy | 100 |
| Policies per security attribute | 1,600 |
| Peered-VCN policies per tenancy | 200 |

---

## Resource Types That Support ZPR Security Attributes

Bastion, Compute (instances, instance configurations), Database (autonomous,
cloud-autonomous-vmclusters, cloud-vmclusters, db-systems, exadb-vm-clusters),
Database Tools, Data Catalog, DevOps, File Storage, Functions, GoldenGate,
Integration 3, Load Balancer, MySQL HeatWave, Networking (VCNs, VNICs,
private endpoints), Network Load Balancer, OCI Cache, Resource Manager,
Search with OpenSearch, Streaming.
