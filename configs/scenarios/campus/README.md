# Campus Network Configuration

This configuration represents a typical university campus network with:
- 2 Core Routers (CAMPUS-CORE-R1, CAMPUS-CORE-R2)
- 3 Building Distribution Switches (LIBRARY-DIST-SW1, DORM-DIST-SW1, ADMIN-DIST-SW1)
- 4 Access Switches (LIBRARY-ACCESS-SW1, DORM-ACCESS-SW1, DORM-ACCESS-SW2, ADMIN-ACCESS-SW1)

## Topology
```
 [CAMPUS-CORE-R1] ---- [CAMPUS-CORE-R2]
        |                    |
 [LIBRARY-DIST-SW1]   [DORM-DIST-SW1] [ADMIN-DIST-SW1]
        |                /       \           |
[LIBRARY-ACCESS-SW1] [DORM-ACCESS-SW1] [DORM-ACCESS-SW2] [ADMIN-ACCESS-SW1]
```

## Features Tested
- Dual core for redundancy
- OSPF routing protocol
- Multiple campus VLANs (10: Students, 20: Staff, 30: Servers, 40: Guest, 99: Management)
- RSTP (Rapid Spanning Tree Protocol)
- Campus-wide addressing scheme
- Building-specific subnets