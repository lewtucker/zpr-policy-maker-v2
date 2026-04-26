# Oracle ZPR Policy Examples

Sources:
- https://docs.oracle.com/en-us/iaas/Content/zero-trust-packet-routing/zpr-policy-examples.htm
- https://docs.oracle.com/en-us/iaas/Content/zero-trust-packet-routing/zpr-policy-syntax.htm
- https://docs.oracle.com/en-us/iaas/Content/zero-trust-packet-routing/zpr-policy-overview.htm
- https://docs.oracle.com/en-us/iaas/Content/zero-trust-packet-routing/managing-zpr-policies.htm

---

## Syntax Reference Examples

```
# Qualified namespace
in app:fin-network VCN allow app:web endpoints to connect to app:store endpoints

# Fully qualified with namespace
in applications.apps:app1 VCN allow '10.0.0.0/16' to connect to apps:app1 endpoints

# Two-VCN form
allow applications.app:webserver endpoints in applications.vcn:A VCN to connect to database.database:MySQL endpoints in database.vcn:B VCN

# CIDR to security attribute
in front-end:network VCN allow loadbalancer:web to connect to '0.0.0.0/0'
```

---

## Overview Examples

```
in networks:application VCN allow apps:hr-apps endpoints to connect to apps:hr-app-data endpoints

allow networks:net1:App1 endpoints in networks:net1 VCN to connect to DB-Server:App1 endpoints in networks:net2 VCN

in networks:net1 VCN allow apps:app1 endpoints to connect to '192.168.0.0/16'

in networks:internal VCN allow hosts:trusted endpoints to connect to data:sensitive endpoints
```

---

## Compute

```
# SSH within VCN
in networks:net1 VCN allow compute:instance1 endpoints to connect to compute:instance2 endpoints with protocol='tcp/22'

# SSH across peered VCNs
allow compute:instance1 endpoints in networks:net1 VCN to connect to compute:instance2 endpoints with protocol='tcp/22' in networks:net2 VCN

# SQLNet within VCN
in networks:net1 VCN allow compute:instance1 endpoints to connect to db:DB-Server endpoints with protocol='tcp/1521'

# SQLNet across peered VCNs
allow compute:instance1 endpoints in networks:net1 VCN to connect to db:DB-Server endpoints with protocol='tcp/1521' in VCN-Network:DB VCN
```

---

## Database

```
# Allow database to reach OCI services (OSN)
in VCN-Network:DB VCN allow db:DB-Server endpoints to connect to 'osn-services-ip-addresses'

# Single port — same VCN
in VCN-Network:DB VCN allow App:App1 to connect to DB-Server:App1 endpoints with protocol='tcp/1521'

# Port range — same VCN
in VCN-Network:DB VCN allow App:App1 to connect to DB-Server:App1 endpoints with protocol='tcp/999-11199'

# Stateless connection with multiple filters
in finance.network:prod VCN allow app:frontend endpoints to connect to database:server endpoints with protocol = 'tcp/1521', connection-state = 'stateless'

# Cross-VCN (same region) — no filter
allow networks:net1:App1 endpoints in networks:net1 VCN to connect to DB-Server:App1 endpoints in networks:net2 VCN

# Cross-VCN with port filter
allow App:App1 endpoints in VCN-Network:App VCN to connect to DB-Server:App1 endpoints with protocol='tcp/1521' in VCN-Network:DB VCN
```

---

## Network Load Balancer

```
# IP range to NLB
in my:VCN VCN allow '0.0.0.0/0' to connect to XYZ-NLB:NLB1 endpoints

# NLB to app servers
in my:VCN VCN allow XYZ-NLB:NLB1 endpoints to connect to ABC-web-servers:app1 endpoints

# Stateless cross-VCN — comma filter syntax
allow app:frontend endpoints in finance.network:dev VCN to connect to database:server endpoints with protocol='tcp/1521', connection-state='stateless' in finance.network:prod VCN

# Stateless cross-VCN — repeated "with" syntax
allow app:frontend endpoints in finance.network:dev VCN to connect to database:server endpoints with protocol='tcp/1521' with connection-state='stateless' in finance.network:prod VCN

# Port range cross-VCN
allow App:App1 endpoints in VCN-Network:App VCN to connect to DB-Server:App1 endpoints with protocol='tcp/999-11199' in VCN-Network:DB VCN
```

---

## OCI Cache

```
in my:VCN VCN allow compute:instance1 endpoints to connect to redis:cluster1 endpoints
```

---

## Private Service Access

```
in vcn:A VCN allow app:dbs endpoints to connect to svc:dbs endpoints with protocol='tcp/443'
```

---

## VCN Peering (Remote)

```
allow DB-client:App1 endpoints in VCN-Network:DB VCN to connect to DB-client:app1 endpoints with protocol='tcp/1521' in VCN-Network:Remote VCN
```

---

## Policy Template Patterns (from Console Builder)

```
# Compute: any protocol/port, same VCN
in <security attribute of VCN> VCN allow <security attribute of source-compute> endpoints to connect to <security attribute of target-compute> endpoints

# Exadata: DB-to-self (RAC)
in <security attribute of VCN> VCN allow <security attribute of database service> endpoints to connect to <security attribute of database service> endpoints

# Exadata: DB to OSN services
in <security attribute of VCN> VCN allow <security attribute of database service> endpoints to connect to 'osn-services-ip-addresses'

# Data Guard cross-region via CIDR (two policies needed)
in <security attribute of VCN> VCN allow <security attribute of source-compute> endpoints to connect to <Standby VCN CIDR> with protocol='tcp/1521'
in <security attribute of Standby VCN> VCN allow <VCN CIDR> to connect to <security attribute of database service> endpoints

# Data Guard same-region (two-VCN form)
allow <security attribute of database service> endpoints in <security attribute of source VCN> VCN to connect to <security attribute of database service> endpoints in <security attribute of Standby VCN> VCN
```
