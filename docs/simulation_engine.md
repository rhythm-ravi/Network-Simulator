# Network Simulation Engine Documentation

## Overview

The Network Simulator now includes a comprehensive simulation engine with multithreading, fault injection, and Day-1 simulation capabilities. This document describes how to use the simulation features.

## Features

### Core Simulation Engine
- **SimPy-based discrete event simulation** for realistic timing and event processing
- **Multithreaded device simulation** with individual threads for each network device
- **Inter-Process Communication (IPC)** using queues for device-to-device messaging
- **Real-time and accelerated simulation** with configurable time factors

### Day-1 Network Simulation Scenarios
- **ARP Discovery**: Automatic ARP request/reply simulation for IP-to-MAC mapping
- **Neighbor Discovery**: Protocol-agnostic neighbor relationship establishment
- **OSPF Hello Messages**: Periodic hello message exchange for routing protocol simulation
- **Network Initialization**: Complete Day-1 network bring-up simulation

### Fault Injection System
- **Link Failures**: Simulate link failures at various network levels with configurable duration
- **MTU Mismatches**: Analyze the impact of MTU size mismatches on traffic flow
- **Device Configuration Changes**: Modify device configurations during simulation
- **Impact Analysis**: Track the effects of failures on network endpoints

### Simulation Control
- **Pause/Resume**: Full simulation control with pause and resume capabilities
- **Configuration Changes**: Apply configuration changes during simulation pauses
- **Results Analysis**: Comprehensive reporting and export of simulation results
- **Statistics Collection**: Device-level and link-level statistics tracking

## Quick Start

### Basic Usage

Run a simple simulation with default settings:
```bash
python run_simulation.py
```

Run with debug logging:
```bash
python run_simulation.py --log-level DEBUG
```

### Configuration-Based Simulation

Use a YAML configuration file:
```bash
python run_simulation.py --config configs/demo.yaml --log-level INFO
```

### Configuration File Format

```yaml
simulation:
  duration: 60.0              # Simulation time in seconds
  real_time_factor: 0.1       # Speed factor (0.1 = 10x faster)
  inject_faults: true         # Enable fault injection
  output_dir: "./logs"        # Results output directory

devices:
  - device:
      name: "Router1"
      type: "router"
      model: "Cisco_2900"
      location: "DataCenter"
    interfaces:
      - name: "eth0"
        ip_address: "192.168.1.1"
        subnet_mask: "255.255.255.0"
        status: "up"
        bandwidth: 1000

links:
  - id: "link1"
    source: "Router1"
    target: "Router2"
    properties:
      bandwidth: "100Mbps"
      latency: "1ms"
      mtu: 1500

fault_scenarios:
  - name: "Link_Failure_Test"
    type: "link_failure"
    target: "link1"
    start_time: 30.0
    duration: 15.0
    description: "Test link recovery procedures"
    
  - name: "MTU_Mismatch_Test"
    type: "mtu_mismatch"
    source: "Router1"
    target: "Router2"
    packet_size: 1600
    interface_mtu: 1500
    start_time: 45.0
    
  - name: "Config_Change_Test"
    type: "config_change"
    target: "Router1"
    start_time: 60.0
    changes:
      interface_status:
        interface: "eth0"
        status: "down"
```

## Architecture

### Simulation Engine Components

1. **NetworkSimulationEngine** (`src/simulation/simulation_engine.py`)
   - Main simulation controller
   - Device and link management
   - Fault injection coordination
   - Statistics collection and reporting

2. **EventScheduler** (`src/simulation/event_scheduler.py`)
   - SimPy-based discrete event scheduling
   - Event prioritization and processing
   - Pause/resume control mechanisms
   - Periodic event management

3. **NetworkEvents** (`src/simulation/network_events.py`)
   - Comprehensive event type definitions
   - Protocol events (ARP, OSPF, Neighbor Discovery)
   - Fault events (Link failures, MTU mismatches)
   - Control events (Configuration changes)

### Threading Model

Each network device runs in its own thread (`DeviceThread`) that:
- Processes incoming messages via queues
- Maintains device-specific statistics
- Simulates device behavior and processing delays
- Handles protocol-specific operations (ARP, routing)

### Event Processing

The simulation uses a discrete event model where:
- All events are scheduled with specific timestamps
- Events are processed in chronological order
- Each event can generate additional events
- Statistics are collected for all event processing

## Fault Injection

### Link Failure Injection
```python
# Programmatic fault injection
fault_id = sim_engine.inject_link_failure(
    link_id="link1", 
    duration=10.0,    # 10 seconds
    delay=5.0         # Start after 5 seconds
)
```

### MTU Mismatch Simulation
```python
fault_id = sim_engine.inject_mtu_mismatch(
    source_device="R1",
    target_device="R2", 
    packet_size=1600,
    interface_mtu=1500,
    delay=0.0
)
```

### Configuration Changes
```python
changes = {
    'interface_status': {
        'interface': 'eth0',
        'status': 'down'
    }
}
fault_id = sim_engine.change_device_configuration(
    device_name="Router1",
    changes=changes,
    delay=10.0
)
```

## Results and Analysis

### Simulation Summary
The simulation provides comprehensive results including:

- **Device Statistics**: Packets sent/received/dropped, events processed, ARP tables, neighbor relationships
- **Link Statistics**: Active status, failure counts, recovery counts
- **Event Metrics**: Total events, processing times, event types distribution
- **Fault Injection Log**: Complete log of all injected faults and their timing

### Export Formats
Results can be exported in multiple formats:
- **JSON**: Complete simulation data export
- **CSV**: Tabular data for analysis
- **Summary Text**: Human-readable summary

### Sample Output
```
Simulation Summary:
  State: stopped
  Simulation Time: 40.00 units  
  Real Time Elapsed: 0.02 seconds
  Total Events: 15
  Processed Events: 15
  Average Processing Time: 0.000012 seconds

Device Statistics:
  Router1:
    Events Processed: 5
    Packets Sent: 12
    Packets Received: 8
    ARP Table Size: 2
    Neighbor Count: 1

Link Statistics:
  link1: Failed
    Packets Transmitted: 156
    Failure Count: 1
    Recovery Count: 1

Fault Injection Log:
  5.00: link_failure - link1
  15.00: link_recovery - link1
  20.00: mtu_mismatch - R1->R2
```

## Advanced Features

### Real-Time Synchronization
The simulator can run synchronized with real time or at accelerated speeds:
```python
# Real-time simulation
sim_engine = NetworkSimulationEngine(real_time_factor=1.0)

# 10x faster than real time  
sim_engine = NetworkSimulationEngine(real_time_factor=0.1)
```

### Pause/Resume Control
```python
# Pause simulation
sim_engine.pause_simulation()

# Make configuration changes
sim_engine.change_device_configuration(...)

# Resume simulation
sim_engine.resume_simulation()
```

### Custom Event Handlers
Register custom event handlers for specific event types:
```python
def custom_arp_handler(event):
    # Custom ARP processing logic
    return []

sim_engine.event_scheduler.register_event_handler(
    EventType.ARP_REQUEST, 
    custom_arp_handler
)
```

## Configuration Examples

### Simple Test Network
See `configs/simple_test.yaml` for a basic 3-device network with fault injection.

### Enterprise Network
See `configs/enterprise_network.yaml` for a complex multi-router enterprise topology.

### Demo Configuration
See `configs/demo.yaml` for a quick demonstration of all fault injection features.

## Troubleshooting

### Common Issues

1. **Device threads not starting**: Check that device configurations are valid
2. **Events not processing**: Verify event scheduler is running and not paused  
3. **Configuration loading errors**: Ensure YAML syntax is correct
4. **Memory usage**: For long simulations, monitor device thread count

### Debug Mode
Run with debug logging to see detailed event processing:
```bash
python run_simulation.py --log-level DEBUG
```

### Log Files
All simulation activity is logged to `logs/simulation.log` with configurable detail levels.

## Future Enhancements

The simulation engine provides a foundation for:
- Additional protocol implementations (BGP, EIGRP, STP)
- Traffic generation and flow analysis
- Network topology visualization
- Performance benchmarking tools
- Integration with real network devices