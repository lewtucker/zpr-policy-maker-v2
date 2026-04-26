# Oracle OCI IAM Policies for ZPR Administration

Source: https://docs.oracle.com/en-us/iaas/Content/zero-trust-packet-routing/policy-reference.htm

This is a **separate layer** from ZPR traffic routing policies. These are standard
OCI IAM policies that control who (which groups/principals) can create, read,
update, and delete ZPR resources — not what network traffic is allowed.

Syntax: `Allow group <group> to <verb> <resource-type> in <scope> [where <condition>]`

---

## Verbs (cumulative access levels)

| Verb | Access level |
|------|-------------|
| `inspect` | List and enumerate resources |
| `read` | inspect + read resource details |
| `use` | read + update |
| `manage` | use + create and delete |

---

## Resource Types

**Individual:**
- `zpr-policy` — ZPR routing policy objects
- `zpr-configuration` — ZPR tenancy-level configuration
- `security-attribute-namespace` — namespaces that hold security attribute keys

**Aggregate:**
- `zpr-family` — shorthand for all `zpr-*` individual types
- `security-attribute-family` — shorthand for all security attribute types

---

## Permissions by Verb

### zpr-policy

| Verb | Permissions | APIs covered |
|------|-------------|--------------|
| inspect | ZPR_POLICY_INSPECT | ListZprPolicies, ListZprPolicyWorkRequests |
| read | + ZPR_POLICY_READ | GetZprPolicy, GetZprPolicyWorkRequest, ListZprPolicyWorkRequestErrors/Logs |
| use | + ZPR_POLICY_UPDATE | UpdateZprPolicy |
| manage | + ZPR_POLICY_CREATE, ZPR_POLICY_DELETE | CreateZprPolicy, DeleteZprPolicy |

### zpr-configuration

| Verb | Permissions | APIs covered |
|------|-------------|--------------|
| read | ZPR_CONFIGURATION_READ | GetConfiguration, GetZprConfigurationWorkRequest, List*WorkRequests* |
| use | + ZPR_CONFIGURATION_UPDATE | UpdateConfiguration |
| manage | + ZPR_CONFIGURATION_CREATE, ZPR_CONFIGURATION_DELETE | CreateConfiguration, DeleteConfiguration |

### security-attribute-namespace

| Verb | Permissions | APIs covered |
|------|-------------|--------------|
| inspect | SECURITY_ATTRIBUTE_NAMESPACE_INSPECT | ReadSecurityAttributeNamespace, ReadSecurityAttribute, SecurityAttributeWorkRequest |
| read | + SECURITY_ATTRIBUTE_NAMESPACE_READ | ReadSecurityAttributeNamespace, ReadSecurityAttribute |
| manage | + NAMESPACE_CREATE/DELETE/MOVE/UPDATE, ZPR_CONFIGURATION_DELETE | CreateSecurityAttributeNamespace, DeleteSecurityAttributeNamespace, CascadeDelete, ChangeCompartment, UpdateSecurityAttributeNamespace, CreateSecurityAttribute, UpdateSecurityAttribute, DeleteSecurityAttribute |

---

## Condition Variables

| Variable | Type | Use |
|----------|------|-----|
| `target.security-attribute-namespace.name` | String | Restrict to a specific namespace by name |
| `target.security-attribute-namespace.id` | Entity | Restrict to a specific namespace by OCID |

---

## Examples

```
# SecurityAdmins: full control over all ZPR resources
Allow group SecurityAdmins to manage zpr-configuration in tenancy
Allow group SecurityAdmins to manage security-attribute-namespace in tenancy
Allow group SecurityAdmins to manage zpr-policy in tenancy

# SecurityAuditors: read-only
Allow group SecurityAuditors to read zpr-configuration in tenancy
Allow group SecurityAuditors to read zpr-policy in tenancy
Allow group SecurityAuditors to read security-attribute-namespace in tenancy

# Delegate namespace management per team
Allow group app-admin to manage security-attribute-namespace where target.security-attribute-namespace.name = 'applications'
Allow group database-admin to manage security-attribute-namespace where target.security-attribute-namespace.name = 'database'
```
