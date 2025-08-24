# Hierarchical Enterprise Network Configuration

This configuration represents a typical enterprise network with:
- 1 Core Router (CORE-R1)
- 2 Distribution Routers (DIST-R1, DIST-R2)  
- 3 Access Switches (ACCESS-SW1, ACCESS-SW2, ACCESS-SW3)
- 1 Firewall (FW-1)

## Topology
```
                 Internet
                    |
                [FW-1]
                    |
               [CORE-R1]
              /        \
       [DIST-R1]    [DIST-R2]
         /    \        /    \
 [ACCESS-SW1] [ACCESS-SW2] [ACCESS-SW3]
```

## Features Tested
- OSPF routing protocol
- Multiple VLANs (10, 20, 30, 99)
- Spanning Tree Protocol
- Inter-VLAN routing
- Hierarchical addressing scheme