# Network Simulation Configurations

This directory contains example simulation configurations for the Network Simulator.

## Configuration Files

### `default.yaml`
- **Purpose**: General-purpose 3-device network configuration
- **Devices**: Core router, access switch, branch router
- **Features**: Basic fault injection, OSPF routing, monitoring
- **Use case**: Standard testing and validation

### `simple.yaml`
- **Purpose**: Minimal 2-device setup for quick testing
- **Devices**: Two routers with WAN connection
- **Features**: No fault injection, static routing, basic monitoring
- **Use case**: Quick functionality validation, learning

### `enterprise.yaml`
- **Purpose**: Complex multi-layer enterprise network
- **Devices**: Redundant core switches, distribution/access layers, edge router
- **Features**: Comprehensive fault scenarios, STP, VLANs, redundancy testing
- **Use case**: Advanced testing, enterprise scenarios, redundancy validation

## Usage

Run simulations with these configurations:

```bash
# Run with default configuration
python scripts/run_simulation.py --config configs/simulation_configs/default.yaml

# Run simple test scenario
python scripts/run_simulation.py --config configs/simulation_configs/simple.yaml

# Run enterprise network simulation
python scripts/run_simulation.py --config configs/simulation_configs/enterprise.yaml
```

## Configuration Format

All configurations follow the YAML format with these main sections:

- **simulation**: Duration, timing, output settings
- **devices**: Network device definitions with interfaces
- **links**: Physical connections between devices  
- **fault_scenarios**: Fault injection scenarios for testing
- **protocols**: Routing and switching protocol configurations
- **monitoring**: Metrics collection and alerting settings

## Customization

Copy and modify any configuration to create custom network scenarios:

1. Copy an existing configuration file
2. Modify devices, links, and scenarios as needed
3. Run with: `python scripts/run_simulation.py --config your_config.yaml`

For detailed configuration options, see the documentation in `docs/simulation_engine.md`.