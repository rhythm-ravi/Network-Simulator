# Data Center Network Configuration

This configuration represents a typical data center network with:
- 2 Core Switches (DC-CORE-SW1, DC-CORE-SW2)
- 2 Aggregation Switches (DC-AGG-SW1, DC-AGG-SW2) 
- 4 Top of Rack (ToR) Switches (DC-TOR-SW1, DC-TOR-SW2, DC-TOR-SW3, DC-TOR-SW4)

## Topology (Leaf-Spine-like)
```
    [DC-CORE-SW1] ---- [DC-CORE-SW2]
        |    \         /    |
        |     \       /     |
        |      \     /      |
  [DC-AGG-SW1]   \ /   [DC-AGG-SW2]
        |         X         |
        |        / \        |
  [DC-TOR-SW1] [DC-TOR-SW2] [DC-TOR-SW3] [DC-TOR-SW4]
```

## Features Tested
- High-speed 10G and 40G links
- OSPF routing for Layer 3 connectivity
- Multiple data center VLANs (100: Web Servers, 200: App Servers, 300: DB Servers, 999: Management)
- Redundant paths and ECMP
- Data center addressing scheme (192.168.x.x/24)