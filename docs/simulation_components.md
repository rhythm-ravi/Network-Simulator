# Network Simulation Components Documentation

This document provides comprehensive documentation for the new network simulation components implemented in the Network Simulator.

## Overview

The network simulation system provides three core components:

1. **NetworkSimulator**: Main simulation orchestrator with device-specific simulators
2. **FaultInjector**: Comprehensive fault injection and testing system  
3. **SimulationStats**: Real-time statistics collection and monitoring system

These components work together to provide realistic network simulation with fault injection capabilities, multithreaded device simulation, and comprehensive performance monitoring.

## Components

### NetworkSimulator (`src/core/network_simulator.py`)

The NetworkSimulator is the main orchestrator that manages device simulators and provides simulation control.

#### Key Features
- **Device Simulation Classes**: RouterSimulator and SwitchSimulator with protocol-specific behavior
- **Multithreaded Simulation**: Each device runs in its own thread for realistic behavior
- **Packet Handling**: Realistic packet processing with configurable delays
- **Traffic Generation**: Generate synthetic traffic between devices
- **Simulation Control**: Start, stop, pause, and resume simulation

#### Usage Example
```python
from core.network_simulator import NetworkSimulator
from models.network_models import Router, Switch, NetworkInterface, InterfaceStatus

# Create simulator
simulator = NetworkSimulator(real_time_factor=0.1)  # 10x accelerated

# Create and add devices
router = Router("R1")
router.add_interface(NetworkInterface(
    name="eth0", 
    ip_address="192.168.1.1", 
    subnet_mask="255.255.255.0",
    status=InterfaceStatus.UP
))

simulator.add_device(router)

# Add links
simulator.add_link("link1", "R1", "R2")

# Start simulation
simulator.start_simulation()

# Generate traffic
packet_ids = simulator.generate_traffic("R1", "R2", packet_type="ip", count=10)

# Get statistics
stats = simulator.get_simulation_statistics()

# Stop simulation
simulator.stop_simulation()
```

#### Device Simulators

**RouterSimulator**
- L3 packet forwarding
- ARP request/reply handling
- OSPF hello message processing
- Routing table management
- Neighbor discovery

**SwitchSimulator**
- L2 frame forwarding
- MAC address learning
- VLAN support
- Spanning Tree Protocol simulation
- Broadcast/multicast handling

### FaultInjector (`src/core/fault_injector.py`)

The FaultInjector provides comprehensive fault injection capabilities for testing network resilience.

#### Supported Fault Types
- **Link Failures**: Temporary or permanent link outages
- **Device Failures**: Complete device failure or CPU/memory overload
- **MTU Mismatches**: Packet size vs interface MTU conflicts  
- **Packet Loss**: Random packet drops on links/interfaces
- **Bandwidth Reduction**: Link capacity constraints
- **Configuration Errors**: Device misconfigurations
- **Congestion**: Network congestion simulation

#### Usage Example
```python
from core.fault_injector import FaultInjector, FaultSeverity

# Create fault injector (requires simulation engine)
fault_injector = FaultInjector(simulation_engine)

# Simple fault injection
fault_id = fault_injector.inject_link_failure(
    link_id="link1", 
    duration=30.0,    # 30 seconds
    delay=10.0,       # Start after 10 seconds
    severity=FaultSeverity.HIGH,
    description="Primary link outage"
)

# Device failure
fault_id = fault_injector.inject_device_failure(
    device_name="R1",
    failure_type="cpu_overload", 
    duration=60.0
)

# Complex fault scenario
fault_scenario = [
    {
        "type": "link_failure",
        "target": "link1", 
        "duration": 30.0,
        "delay": 5.0,
        "description": "Primary path failure"
    },
    {
        "type": "device_failure",
        "target": "R2",
        "duration": 20.0, 
        "delay": 15.0,
        "description": "Secondary router failure"
    }
]

scenario_faults = fault_injector.create_fault_scenario(
    "cascading_failure", 
    fault_scenario,
    "Test cascading failure resilience"
)

# Monitor fault status
active_faults = fault_injector.get_active_faults()
fault_statistics = fault_injector.get_fault_statistics()
```

#### Fault Impact Analysis
The fault injector automatically tracks:
- Affected devices and links
- Packet/byte loss during faults
- Network convergence time
- Route changes and neighbor relationship impacts
- Service availability metrics

### SimulationStats (`src/core/simulation_stats.py`)

The SimulationStats component provides real-time statistics collection and monitoring.

#### Collected Metrics
- **Interface Statistics**: Packets, bytes, errors, utilization per interface
- **Protocol Statistics**: OSPF, ARP, neighbor discovery metrics
- **Traffic Flows**: End-to-end flow tracking with latency analysis
- **Congestion Events**: Network congestion detection and analysis
- **Throughput Analysis**: Real-time and historical throughput metrics

#### Usage Example
```python
from core.simulation_stats import SimulationStats

# Create stats collector
stats = SimulationStats(collection_interval=1.0)

# Start collection
stats.start_collection()

# Update statistics (typically done by simulators)
stats.update_interface_stats(
    "R1", "eth0",
    packets_in=100, packets_out=95,
    bytes_in=15000, bytes_out=14250,
    errors_in=2, packets_dropped_out=1
)

stats.record_traffic_flow(
    "flow1", "R1", "R2",
    protocol="TCP", 
    packet_size=1500,
    latency=5.2,
    path_hops=["R1", "SW1", "R2"]
)

stats.update_protocol_stats(
    "OSPF",
    messages_sent=10,
    neighbors_discovered=3,
    convergence_time=2.5
)

# Get comprehensive statistics
summary = stats.get_simulation_summary()
interface_stats = stats.get_interface_statistics() 
protocol_stats = stats.get_protocol_statistics()
traffic_flows = stats.get_traffic_flows()
congestion_analysis = stats.get_congestion_analysis()
throughput_analysis = stats.get_throughput_analysis()

# Export to file
stats.export_statistics("simulation_report.json")

# Stop collection
stats.stop_collection()
```

## Integration with Existing Components

### NetworkAnalyzer Integration

The `network_analyzer.py` has been updated to include simulation capabilities:

```bash
# Run network simulation
python network_analyzer.py --config configs/ --simulate

# Extended simulation with custom duration
python network_analyzer.py --config configs/ --simulate --duration 600

# Simulation without fault injection
python network_analyzer.py --config configs/ --simulate --no-faults

# Simulation without statistics collection
python network_analyzer.py --config configs/ --simulate --no-stats
```

### Configuration File Support

The simulation components support configuration via YAML files:

```yaml
simulation:
  duration: 300.0
  real_time_factor: 0.1
  inject_faults: true
  collect_stats: true

devices:
  - device:
      name: "R1"
      type: "router"
    interfaces:
      - name: "eth0"
        ip_address: "192.168.1.1"
        subnet_mask: "255.255.255.0"
        status: "up"

fault_scenarios:
  - type: "link_failure"
    target: "link1"
    start_time: 30.0
    duration: 60.0
    severity: "high"
```

## Performance and Scalability

### Multithreading Design
- Each device runs in its own thread for parallel processing
- Thread-safe communication via message queues
- Lock-based synchronization for shared resources
- Configurable processing delays for realistic behavior

### Memory Management
- Circular buffers for time-series data (configurable size)
- Automatic cleanup of old flows and events
- Memory-efficient statistics storage
- Garbage collection of expired neighbors and routes

### Real-time Factors
- Configurable simulation speed (real-time to 100x faster)
- Event-driven architecture for efficiency
- Adaptive collection intervals based on activity
- Optional pause/resume for interactive testing

## Error Handling and Robustness

### Comprehensive Error Handling
- Graceful degradation on component failures
- Detailed logging with configurable levels
- Exception isolation between device threads
- Automatic recovery from transient errors

### Validation and Sanity Checks
- Configuration validation before simulation start
- Parameter bounds checking for fault injection
- Network topology validation
- Resource limit monitoring

### Monitoring and Alerting
- Configurable threshold-based alerting
- Real-time health monitoring
- Performance bottleneck detection
- Automatic fault detection and reporting

## Testing and Validation

The implementation includes comprehensive tests:

- **Unit Tests**: Individual component testing (`tests/test_simulation_components.py`)
- **Integration Tests**: Component interaction testing  
- **Performance Tests**: Load and stress testing
- **Configuration Tests**: Sample configuration validation

Run tests with:
```bash
python -m pytest tests/test_simulation_components.py -v
python verify_simulation_integration.py
```

## Sample Use Cases

### 1. Network Resilience Testing
Test how the network responds to link failures, device outages, and congestion:

```python
# Test link redundancy
fault_injector.inject_link_failure("primary_link", duration=60.0)

# Monitor convergence
stats.update_protocol_stats("OSPF", convergence_time=convergence_time)

# Analyze impact
congestion_analysis = stats.get_congestion_analysis()
```

### 2. Performance Benchmarking
Measure network performance under various conditions:

```python
# Generate test traffic
for i in range(100):
    simulator.generate_traffic("source", "destination", size=1500)

# Monitor throughput
throughput = stats.get_throughput_analysis()
```

### 3. Protocol Validation
Verify protocol behavior and convergence:

```python
# Monitor OSPF neighbor relationships
stats.update_protocol_stats("OSPF", neighbors_discovered=5)

# Track hello message exchange  
router_sim.handle_protocol_event("ospf_hello", {"neighbor": "R2"})
```

## Future Enhancements

Planned improvements include:
- Additional protocol support (BGP, EIGRP, STP)
- Traffic pattern generators
- Network visualization integration
- Machine learning-based anomaly detection
- Cloud deployment support
- REST API for remote control

## Troubleshooting

### Common Issues

**Import Errors**
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Check Python path includes src directory
- Verify relative imports are correct

**Performance Issues**
- Adjust real_time_factor for faster simulation
- Reduce collection_interval for lower overhead
- Limit concurrent device threads

**Memory Issues**
- Reduce maxlen parameters for circular buffers
- Enable automatic cleanup of old data
- Monitor memory usage during long simulations

**Simulation Accuracy**
- Verify device configurations match real networks
- Adjust processing delays for realistic timing
- Validate protocol implementations against RFCs

For additional support, refer to the test files and sample configurations.