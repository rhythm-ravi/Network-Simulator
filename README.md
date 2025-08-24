# Network Simulator

A comprehensive network simulation toolkit for modeling and analyzing network protocols, topologies, and performance metrics. This project provides a flexible framework for simulating various network scenarios and collecting performance data.

## Features

- **🔧 Configuration Parser**: Parses Cisco router/switch configuration files with support for interfaces, VLANs, routing protocols
- **🌐 Network Topology Generation**: Automatically generates network topologies from device configurations with visualization
- **🔍 Network Validation**: Detects configuration issues, inconsistencies, and potential problems  
- **📊 Load Analysis**: Analyzes network capacity, utilization, and provides load balancing recommendations
- **⚠️ Fault Injection**: Simulates network failures (link failures, device failures, packet loss) for resilience testing
- **🎯 Network Simulation**: Multi-threaded device simulation with Day-1 and Day-2 scenario support
- **📋 Comprehensive Reporting**: Generates detailed reports in CLI, JSON, and HTML formats with visualizations
- **🧪 End-to-End Testing**: Complete testing framework validating all simulation features

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. Clone the repository:
```bash
git clone https://github.com/rhythm-ravi/Network-Simulator.git
cd Network-Simulator
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Basic Usage

#### 1. Run the Comprehensive Testing Framework

The easiest way to see all features in action:

```bash
# Test simple network configurations (3-4 devices)
python test_network_simulator.py \
    --config-dir configs/scenarios/simple \
    --output-dir outputs/test_results \
    --html

# Test complex enterprise network (7 devices)
python test_network_simulator.py \
    --config-dir configs/scenarios/enterprise \
    --output-dir outputs/test_results \
    --html \
    --fault-injection \
    --verbose
```

This will:
- Parse network device configurations
- Generate network topology with visualization  
- Detect configuration issues
- Analyze network load and capacity
- Test fault injection capabilities (if enabled)
- Generate comprehensive reports (CLI, JSON, HTML)

#### 2. Test Complex Network Scenarios

```bash
# Test campus network topology (4+ devices)
python test_network_simulator.py \
    --config-dir configs/scenarios/campus \
    --output-dir outputs/test_results \
    --html

# Test data center topology (high-speed links)
python test_network_simulator.py \
    --config-dir configs/scenarios/datacenter \
    --output-dir outputs/test_results \
    --html
```

#### 3. Analyze Your Own Network Configurations

```bash
# Analyze your own network configs
python test_network_simulator.py \
    --config-dir /path/to/your/configs \
    --output-dir outputs/analysis_results \
    --html
```

#### 4. Run Network Simulations

```bash
# Run network simulation with default configuration
python scripts/run_simulation.py --config configs/simulation_configs/default.yaml

# Run simple test network simulation  
python scripts/run_simulation.py --config configs/simulation_configs/simple.yaml

# Run complex enterprise network simulation
python scripts/run_simulation.py --config configs/simulation_configs/enterprise.yaml
```

### Example Output

The testing framework generates:

- **📊 Network topology visualization** (PNG)
- **📄 Detailed CLI report** showing all test results
- **📋 JSON report** with structured data
- **🌐 HTML report** with interactive visualizations
- **📝 Comprehensive logs** for debugging

Sample CLI output for enterprise scenario:
```
================================================================================
NETWORK SIMULATOR COMPREHENSIVE TESTING FRAMEWORK
================================================================================
✓ Parsed 7 device configurations (CORE-R1, DIST-R1, DIST-R2, ACCESS-SW1-3, FW-1)
✓ Generated topology with 7 nodes, 6 connections
✓ Visualization saved: outputs/test_results/network_topology.png
⚠ Found 15 network issues (spanning tree, VLAN consistency, bandwidth variations)
✓ Load Analysis: 6000 Mbps capacity, 30% utilization
✓ Fault Injection Testing: 5/5 successful
================================================================================
✓ ALL TESTS PASSED - Network Simulator is functioning correctly
[INFO] Test results saved in: outputs/test_results
```

## Project Structure

```
Network-Simulator/
├── src/                         # Main source code directory
│   ├── core/                   # Core network simulation components
│   │   ├── config_parser.py           # Configuration file parsing
│   │   ├── topology_generator.py      # Network topology generation
│   │   ├── network_validator.py       # Network validation and issue detection
│   │   ├── load_analyzer.py           # Traffic load analysis
│   │   ├── fault_injector.py          # Fault injection system
│   │   └── network_simulator.py       # Core simulation engine
│   ├── simulation/             # Simulation engine and execution logic
│   └── models/                 # Network models and protocol implementations
├── configs/                    # Network configuration files
│   ├── simulation_configs/     # Example simulation configurations
│   └── scenarios/              # Organized network scenarios
│       ├── simple/            # Basic 3-4 device networks for testing
│       ├── enterprise/        # Complex hierarchical enterprise networks (7 devices)
│       ├── campus/            # Campus network topologies (4-8 devices)
│       └── datacenter/        # Data center network topologies (3-6 devices)
├── outputs/                    # Generated outputs and results
│   ├── test_results/          # Test execution results
│   ├── reports/               # Detailed analysis reports
│   └── visualizations/        # Network topology visualizations
├── scripts/                    # Utility and demo scripts
│   ├── demo_simulation.py     # Demonstration scripts
│   ├── run_simulation.py      # Simulation runners
│   └── validate_requirements.py # Validation utilities
├── tests/                      # Unit tests and integration tests
├── docs/                       # Documentation
├── test_network_simulator.py   # Comprehensive testing framework
├── main.py                     # Basic CLI tool
└── network_analyzer.py         # Network analysis utilities
```

## Key Components

### Configuration Parser
- Supports Cisco device configuration formats (`.config.dump`, `.cfg`)
- Parses interfaces, VLANs, routing protocols, spanning tree
- Handles both individual files and directories

### Topology Generator
- Automatically detects network connections from IP addressing
- Generates NetworkX graphs with device relationships
- Creates network visualizations (PNG format)
- Detects potentially missing devices

### Network Validator  
- Detects duplicate IP addresses
- Identifies VLAN naming inconsistencies
- Finds MTU mismatches
- Checks for missing routing protocols
- Validates spanning tree configurations

### Load Analyzer
- Analyzes network capacity and utilization
- Identifies overloaded and underutilized links
- Provides load balancing recommendations
- Estimates traffic patterns based on device roles

### Fault Injector
- Simulates link failures
- Injects device failures  
- Creates packet loss scenarios
- Tests network resilience

## Advanced Usage

### Custom Network Scenarios

Create your own network configurations:

```yaml
# device.config.dump
device:
  name: CORE-R1  
  type: router
  model: cisco-4321

interfaces:
  - name: GigabitEthernet0/0/0
    ip_address: 10.0.1.1
    subnet_mask: 255.255.255.252
    bandwidth: 1000
    status: up

routing:
  protocols:
    - type: ospf
      process_id: 1
      networks:
        - network: 10.0.0.0
          wildcard: 0.0.255.255
          area: 0
```

### Testing Framework Options

```bash
python test_network_simulator.py --help

Options:
  --config-dir PATH         Directory containing network configurations
  --output-dir PATH         Output directory for reports and visualizations  
  --html                    Generate HTML reports
  --verbose                 Enable detailed logging
  --run-simulation          Run actual network simulation (slower)
  --fault-injection         Enable fault injection testing
  --create-sample-configs   Create sample network configurations
```

## Development

### Running Tests

```bash
# Run the existing test suite
python -m pytest tests/ -v

# Run the comprehensive testing framework on simple scenarios
python test_network_simulator.py --config-dir configs/scenarios/simple
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code  
flake8 src/ tests/

# Type checking
mypy src/
```

## Network Test Scenarios

The testing framework includes comprehensive network scenarios designed to validate different aspects of network simulation:

### 🏢 Enterprise Network Scenario (7 devices)
**Location**: `configs/scenarios/enterprise/`

A realistic hierarchical enterprise network featuring:
- **CORE-R1**: Core router with OSPF routing
- **DIST-R1, DIST-R2**: Distribution layer routers with inter-VLAN routing  
- **ACCESS-SW1-3**: Access layer switches with multiple VLANs
- **FW-1**: Edge firewall with NAT and security policies

**Features Tested**:
- Hierarchical network design (Core → Distribution → Access)
- OSPF routing protocol across all routers
- VLAN segmentation (10: Users, 20: Servers, 30: Guest, 99: Management)
- Spanning Tree Protocol configuration
- Inter-VLAN routing and gateway redundancy
- Network capacity: 6 Gbps total bandwidth

### 🎓 Campus Network Scenario (4-6 devices)
**Location**: `configs/scenarios/campus/`

Multi-building campus network with:
- **CAMPUS-CORE-R1-R2**: Redundant core routers with high-speed interconnects
- **LIBRARY-DIST-SW1**: Library building distribution switch
- **DORM-DIST-SW1**: Dormitory building distribution switch
- **Additional access switches** per building

**Features Tested**:
- Dual-core redundancy for high availability
- Building-specific VLAN schemes (Students, Staff, Servers, Guest)
- 10G inter-building links and 1G access connections
- Rapid Spanning Tree Protocol (RSTP)
- Campus-wide addressing scheme (172.16.x.x, 10.x.x.x)
- Network capacity: 12 Gbps total bandwidth

### 🏭 Data Center Network Scenario (3-6 devices)
**Location**: `configs/scenarios/datacenter/`

High-performance data center topology with:
- **DC-CORE-SW1-SW2**: Core switches with 40G backbone links
- **DC-AGG-SW1-SW2**: Aggregation switches with 10G uplinks
- **DC-TOR-SW1-SW4**: Top-of-Rack switches with server connections

**Features Tested**:
- High-speed links (40G core, 10G aggregation, 1G access)
- Jumbo frame support (9000 MTU) for storage traffic
- Data center VLANs (100: Web, 200: App, 300: DB, 999: Management)  
- ECMP (Equal-Cost Multi-Path) routing capabilities
- Low-latency switching architecture
- Network capacity: 20 Gbps total bandwidth

### 🧪 Simple Test Scenarios (3-4 devices)
**Location**: `configs/scenarios/simple/`

Basic network configurations for testing and development:
- Small router/switch combinations
- Basic VLAN configurations
- Simple routing protocols
- Fault injection test cases

## Testing Results Summary

Each scenario produces comprehensive test results including:

| Scenario | Devices | Links | Capacity | Issues Detected | Test Coverage |
|----------|---------|--------|----------|----------------|---------------|
| Enterprise | 7 | 6 | 6 Gbps | 15+ issues | Full hierarchical design |
| Campus | 4-6 | 3-5 | 12 Gbps | 10+ issues | Redundancy & high-speed |
| Data Center | 3-6 | 2-8 | 20 Gbps | 9+ issues | High-performance switching |
| Simple | 3-4 | 2-3 | 1-2 Gbps | 7+ issues | Basic functionality |

### Features Demonstrated
- ✅ Multi-vendor device support
- ✅ Hierarchical network design  
- ✅ VLAN configuration
- ✅ Routing protocol validation
- ✅ Fault injection scenarios
- ✅ Load balancing analysis

## Support

For questions, issues, or contributions:

- 📋 Use GitHub issue tracker
- 🔀 Submit pull requests for improvements
- 📧 Contact: rhythm-ravi

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**🚀 Ready to simulate your network? Start with:**
```bash
python test_network_simulator.py --create-sample-configs --config-dir configs/my_network
```