# Network Simulator Architecture

This document provides a comprehensive overview of the Network Simulator's system architecture, design patterns, and implementation details.

## Table of Contents

1. [System Overview](#system-overview)
2. [Architectural Patterns](#architectural-patterns)
3. [Core Components](#core-components)
4. [Data Flow](#data-flow)
5. [Module Dependencies](#module-dependencies)
6. [Design Decisions](#design-decisions)
7. [Extension Points](#extension-points)
8. [Performance Considerations](#performance-considerations)
9. [Security Considerations](#security-considerations)

## System Overview

The Network Simulator is designed as a modular, extensible toolkit for network configuration analysis, topology generation, and simulation. The architecture follows a layered approach with clear separation of concerns.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Interface Layer                     │
├─────────────────────────────────────────────────────────────┤
│  CLI Tools        │  Testing Framework  │  Web Interface   │
│  (main.py)        │  (test_network_     │  (Future)        │
│                   │   simulator.py)     │                  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                  Application Layer                          │
├─────────────────────────────────────────────────────────────┤
│  Network Analyzer │  Report Generator  │  Configuration   │
│  (network_        │  (HTML, JSON, CLI) │  Manager         │
│   analyzer.py)    │                    │                  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     Core Services Layer                     │
├─────────────────────────────────────────────────────────────┤
│ Config Parser │ Topology Gen │ Validator │ Load Analyzer  │
│ Network Sim   │ Fault Injector │ Stats   │ Optimizer      │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      Data Layer                             │
├─────────────────────────────────────────────────────────────┤
│  Device Models   │  Network Models    │  Configuration    │
│  (Routers,       │  (Topology Graph,  │  Data Structures  │
│   Switches)      │   Links, VLANs)    │  (YAML, JSON)     │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Modularity**: Each component has a single responsibility
2. **Extensibility**: Easy to add new device types, protocols, and analysis methods
3. **Testability**: Comprehensive test coverage with isolated unit tests
4. **Configurability**: Flexible configuration system for different use cases
5. **Performance**: Efficient algorithms for large network analysis
6. **Maintainability**: Clear code structure with comprehensive documentation

## Architectural Patterns

### 1. Plugin Architecture

The system uses a plugin-based approach for extensibility:

```python
# Core interface
class DeviceParser:
    def parse(self, config_data: Dict) -> DeviceConfiguration:
        raise NotImplementedError

# Cisco plugin
class CiscoParser(DeviceParser):
    def parse(self, config_data: Dict) -> DeviceConfiguration:
        return self._parse_cisco_config(config_data)

# Juniper plugin (future)
class JuniperParser(DeviceParser):
    def parse(self, config_data: Dict) -> DeviceConfiguration:
        return self._parse_juniper_config(config_data)
```

### 2. Factory Pattern

Used for creating different types of network components:

```python
class DeviceFactory:
    @staticmethod
    def create_device(device_type: str, config: DeviceConfiguration):
        if device_type == "router":
            return Router(config)
        elif device_type == "switch":
            return Switch(config)
        else:
            raise ValueError(f"Unknown device type: {device_type}")
```

### 3. Observer Pattern

For event-driven simulation and monitoring:

```python
class SimulationEngine:
    def __init__(self):
        self._observers = []
    
    def attach(self, observer):
        self._observers.append(observer)
    
    def notify(self, event):
        for observer in self._observers:
            observer.update(event)
```

### 4. Strategy Pattern

For different analysis algorithms:

```python
class LoadAnalysisStrategy:
    def analyze(self, network: Network) -> LoadAnalysisResult:
        raise NotImplementedError

class BasicLoadAnalyzer(LoadAnalysisStrategy):
    def analyze(self, network: Network) -> LoadAnalysisResult:
        # Basic capacity analysis
        pass

class AdvancedLoadAnalyzer(LoadAnalysisStrategy):
    def analyze(self, network: Network) -> LoadAnalysisResult:
        # Advanced traffic modeling
        pass
```

## Core Components

### 1. Configuration Parser (`src/core/config_parser.py`)

**Purpose**: Parse network device configurations into standardized format

**Key Classes**:
- `ConfigParser`: Main parser orchestrator
- `DeviceConfiguration`: Standardized device representation
- `Interface`: Network interface model
- `VLAN`: VLAN configuration model

**Design Features**:
- Supports multiple configuration formats (Cisco, future: Juniper, Arista)
- Validates configuration syntax
- Normalizes data structures
- Error handling and logging

```python
@dataclass
class DeviceConfiguration:
    device_name: str
    device_type: str  # router, switch, firewall
    hostname: str
    model: Optional[str]
    location: Optional[str]
    interfaces: List[Interface]
    vlans: List[VLAN]
    routing_protocols: List[RoutingProtocol]
    
    def get_active_interfaces(self) -> List[Interface]:
        return [iface for iface in self.interfaces if iface.status == "up"]
```

### 2. Topology Generator (`src/core/topology_generator.py`)

**Purpose**: Generate network topology from device configurations

**Key Classes**:
- `TopologyGenerator`: Main topology orchestrator
- `NetworkTopology`: Graph-based network representation
- `Link`: Connection between devices

**Algorithms**:
- **IP Subnet Analysis**: Determines connections based on IP addressing
- **VLAN Trunk Detection**: Identifies inter-switch connections
- **Routing Protocol Neighbors**: Uses routing protocol configurations
- **Missing Device Detection**: Identifies potentially missing devices

```python
class TopologyGenerator:
    def __init__(self):
        self.graph = nx.Graph()  # NetworkX for graph operations
        
    def generate_topology(self, configs: Dict[str, DeviceConfiguration]) -> nx.Graph:
        self._add_devices(configs)
        self._detect_connections(configs)
        self._analyze_missing_devices()
        return self.graph
    
    def _detect_connections(self, configs):
        # Algorithm: Find interfaces in same subnet
        for device1, config1 in configs.items():
            for interface1 in config1.get_active_interfaces():
                for device2, config2 in configs.items():
                    if device1 != device2:
                        for interface2 in config2.get_active_interfaces():
                            if self._are_connected(interface1, interface2):
                                self.graph.add_edge(device1, device2)
```

### 3. Network Validator (`src/core/network_validator.py`)

**Purpose**: Detect configuration issues and validate network design

**Validation Categories**:
- **IP Address Conflicts**: Duplicate IPs across devices
- **VLAN Consistency**: Naming and configuration validation
- **MTU Mismatches**: Interface MTU compatibility
- **Routing Protocol Validation**: Protocol configuration checks
- **Spanning Tree Validation**: STP configuration verification

**Issue Classification**:
```python
@dataclass
class NetworkIssue:
    issue_type: str
    severity: str  # critical, high, medium, low, warning
    device: Optional[str]
    interface: Optional[str]
    description: str
    recommendation: Optional[str]
```

### 4. Load Analyzer (`src/core/load_analyzer.py`)

**Purpose**: Analyze network capacity and generate optimization recommendations

**Key Algorithms**:
- **Capacity Calculation**: Sum interface bandwidths
- **Traffic Estimation**: Estimate traffic based on device roles
- **Utilization Analysis**: Identify overloaded/underutilized links
- **Recommendation Engine**: Generate optimization suggestions

```python
class NetworkLoadAnalyzer:
    def analyze_network_load(self, configs: Dict[str, DeviceConfiguration]) -> LoadAnalysisResult:
        links = self._build_link_capacity_map(configs)
        self._estimate_traffic_load(links, configs)
        
        recommendations = self._generate_recommendations(links, configs)
        
        return LoadAnalysisResult(
            total_network_capacity=sum(link.bandwidth for link in links),
            recommendations=recommendations
        )
```

### 5. Fault Injector (`src/core/fault_injector.py`)

**Purpose**: Simulate network failures for resilience testing

**Fault Types**:
- Link failures (temporary/permanent)
- Device failures (complete/partial)
- Packet loss simulation
- MTU mismatches
- Configuration errors

**Architecture**:
```python
class FaultInjector:
    def __init__(self, simulation_engine):
        self.simulation_engine = simulation_engine
        self.active_faults = {}
        self.fault_history = []
        
    def inject_fault(self, fault_type: FaultType, target: str, duration: float):
        scenario = FaultScenario(
            fault_type=fault_type,
            target=target,
            duration=duration,
            start_time=time.time()
        )
        
        self._execute_fault_injection(scenario)
        self.active_faults[scenario.fault_id] = scenario
```

### 6. Simulation Engine (`src/simulation/simulation_engine.py`)

**Purpose**: Multi-threaded network device simulation

**Components**:
- **Event Scheduler**: Time-based event management
- **Device Threads**: Separate thread per network device
- **Message Passing**: IPC for device communication
- **Statistics Collection**: Real-time performance metrics

```python
class NetworkSimulationEngine:
    def __init__(self):
        self.devices = {}
        self.device_threads = {}
        self.event_scheduler = EventScheduler()
        
    def start_simulation(self):
        # Start device threads
        for device_name, device in self.devices.items():
            thread = DeviceThread(device, self)
            thread.start()
            self.device_threads[device_name] = thread
        
        # Schedule Day-1 events (ARP, OSPF discovery)
        self._schedule_initial_events()
```

## Data Flow

### 1. Configuration Analysis Flow

```
Configuration Files (.config.dump)
          ↓
   ConfigParser.parse_directory()
          ↓
   DeviceConfiguration objects
          ↓
   NetworkValidator.validate()
          ↓
   List of NetworkIssue objects
          ↓
   Report Generation (CLI/JSON/HTML)
```

### 2. Topology Generation Flow

```
DeviceConfiguration objects
          ↓
   TopologyGenerator.generate_topology()
          ↓
   IP Subnet Analysis + VLAN Detection
          ↓
   NetworkX Graph object
          ↓
   Visualization (matplotlib → PNG)
```

### 3. Load Analysis Flow

```
DeviceConfiguration objects + NetworkX Graph
          ↓
   NetworkLoadAnalyzer.analyze_network_load()
          ↓
   Link Capacity Mapping + Traffic Estimation
          ↓
   LoadAnalysisResult with Recommendations
          ↓
   Report Integration
```

### 4. End-to-End Testing Flow

```
test_network_simulator.py
          ↓
   1. Parse Configurations
   2. Generate Topology + Visualization
   3. Detect Issues
   4. Analyze Load
   5. Inject Faults (optional)
   6. Run Simulation (optional)
          ↓
   Comprehensive Reports (CLI/JSON/HTML)
```

## Module Dependencies

### Dependency Graph

```
test_network_simulator.py
├── core.config_parser
├── core.topology_generator
├── core.network_validator
├── core.load_analyzer
├── core.fault_injector
├── core.simulation_stats
└── simulation.simulation_engine

core.topology_generator
└── core.config_parser

core.network_validator
└── core.config_parser

core.load_analyzer
└── core.config_parser

core.fault_injector
└── simulation.simulation_engine

simulation.simulation_engine
├── models.network_models
├── simulation.event_scheduler
└── simulation.network_events
```

### External Dependencies

```python
# Core libraries
networkx>=2.8.0          # Graph operations and topology analysis
matplotlib>=3.5.0        # Visualization and plotting
numpy>=1.21.0           # Numerical computations
pandas>=1.3.0           # Data analysis and manipulation

# Simulation
simpy>=4.0.0            # Discrete event simulation
scipy>=1.7.0            # Scientific computing

# Configuration
pyyaml>=6.0             # YAML configuration parsing

# Testing and Development
pytest>=7.0.0           # Unit testing framework
pytest-cov>=4.0.0       # Test coverage
black>=22.0.0           # Code formatting
flake8>=5.0.0           # Linting
mypy>=0.991             # Type checking
```

## Design Decisions

### 1. Graph Library Choice: NetworkX

**Decision**: Use NetworkX for topology representation
**Rationale**:
- Mature, well-tested graph library
- Rich set of graph algorithms
- Good visualization integration with matplotlib
- Pythonic API that fits the project style

**Alternatives Considered**:
- Custom graph implementation (rejected: reinventing the wheel)
- igraph (rejected: less Python-native)

### 2. Configuration Format: YAML

**Decision**: Use YAML for device configurations
**Rationale**:
- Human-readable and writable
- Good Python library support
- Supports complex nested structures
- Industry standard for configuration

**Alternatives Considered**:
- JSON (rejected: less human-friendly)
- TOML (rejected: less suitable for deep nesting)
- Custom format (rejected: unnecessary complexity)

### 3. Simulation Architecture: Multi-threading

**Decision**: Use threading for device simulation
**Rationale**:
- Real-time simulation capabilities
- Better resource utilization
- Easier debugging than async/await
- Good fit for I/O-bound device simulation

**Trade-offs**:
- GIL limitations (acceptable for this use case)
- Thread synchronization complexity
- Memory overhead per thread

### 4. Testing Framework: Comprehensive Integration Tests

**Decision**: Build comprehensive testing framework alongside unit tests
**Rationale**:
- End-to-end validation of all features
- Real-world scenario testing
- User-friendly entry point
- Automated report generation

### 5. Report Generation: Multiple Formats

**Decision**: Support CLI, JSON, and HTML report formats
**Rationale**:
- CLI: Human-readable for quick analysis
- JSON: Machine-readable for automation
- HTML: Rich visualization for presentation

## Extension Points

### 1. Adding New Device Types

```python
# 1. Extend device type enum
class DeviceType(Enum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"  # New device type
    
# 2. Create device-specific parser
class FirewallConfigParser:
    def parse(self, config_data: Dict) -> DeviceConfiguration:
        # Firewall-specific parsing logic
        pass

# 3. Register in factory
class DeviceFactory:
    def create_device(self, device_type: str, config: DeviceConfiguration):
        if device_type == "firewall":
            return Firewall(config)
```

### 2. Adding New Validation Rules

```python
# 1. Create validation rule class
class SecurityPolicyValidator:
    def validate(self, configs: Dict[str, DeviceConfiguration]) -> List[NetworkIssue]:
        issues = []
        # Implement security policy validation
        return issues

# 2. Register with NetworkValidator
class NetworkValidator:
    def __init__(self):
        self.validators = [
            IPAddressValidator(),
            VLANValidator(),
            SecurityPolicyValidator(),  # New validator
        ]
```

### 3. Adding New Analysis Algorithms

```python
# 1. Create analysis strategy
class PerformanceAnalyzer:
    def analyze(self, topology: nx.Graph, configs: Dict) -> AnalysisResult:
        # Implement performance analysis
        pass

# 2. Integrate with main analyzer
class NetworkAnalyzer:
    def __init__(self):
        self.analyzers = [
            LoadAnalyzer(),
            PerformanceAnalyzer(),  # New analyzer
        ]
```

### 4. Adding New Report Formats

```python
# 1. Create report generator
class PDFReportGenerator:
    def generate(self, results: Dict, output_path: Path):
        # Generate PDF report
        pass

# 2. Register with testing framework
class NetworkSimulatorTestFramework:
    def generate_reports(self, enable_pdf=False):
        if enable_pdf:
            PDFReportGenerator().generate(self.test_results, self.output_dir)
```

## Performance Considerations

### 1. Scalability Limits

**Current Performance Characteristics**:
- **Device Count**: Tested up to 100 devices
- **Topology Generation**: O(n²) complexity for connection detection
- **Memory Usage**: ~10MB per 50 devices with full analysis
- **Processing Time**: ~5 seconds for 20-device network with all features

**Optimization Opportunities**:
- Implement spatial indexing for large topologies
- Parallel processing for independent analysis tasks
- Caching for repeated analysis operations
- Database backend for large configuration sets

### 2. Memory Management

**Current Approach**:
- In-memory processing for all operations
- NetworkX graphs stored in memory
- Configuration data cached during processing

**Future Improvements**:
```python
# Streaming configuration parser for large datasets
class StreamingConfigParser:
    def parse_large_directory(self, config_dir: Path) -> Iterator[DeviceConfiguration]:
        for config_file in config_dir.glob("*.config.dump"):
            yield self._parse_single_file(config_file)

# Disk-based graph storage for large topologies
class DiskBackedTopology:
    def __init__(self, storage_path: Path):
        self.graph = nx.Graph()
        self.storage_path = storage_path
        
    def save_to_disk(self):
        nx.write_gpickle(self.graph, self.storage_path)
```

### 3. Concurrent Processing

**Thread Safety**:
- NetworkX graphs are not thread-safe (copy before parallel access)
- Fault injector uses locks for shared state
- Statistics collection uses thread-safe data structures

**Parallel Processing Opportunities**:
```python
from concurrent.futures import ThreadPoolExecutor

class ParallelNetworkAnalyzer:
    def analyze_multiple_networks(self, network_configs: List[Dict]) -> List[AnalysisResult]:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self._analyze_single_network, config)
                for config in network_configs
            ]
            return [future.result() for future in futures]
```

## Security Considerations

### 1. Configuration Data Handling

**Sensitive Information**:
- Device passwords and secrets (should be sanitized)
- IP addressing schemes (may reveal network architecture)
- SNMP community strings
- Management interface credentials

**Security Measures**:
```python
class SecureConfigParser:
    SENSITIVE_FIELDS = ['password', 'secret', 'community', 'key']
    
    def sanitize_config(self, config_data: Dict) -> Dict:
        sanitized = config_data.copy()
        for field in self.SENSITIVE_FIELDS:
            if field in sanitized:
                sanitized[field] = "***REDACTED***"
        return sanitized
```

### 2. File System Access

**Current Approach**:
- Direct file system access for configuration reading
- Output files written to specified directories
- No input validation on file paths

**Hardening Recommendations**:
```python
import os
from pathlib import Path

class SecureFileManager:
    def __init__(self, allowed_base_paths: List[Path]):
        self.allowed_base_paths = allowed_base_paths
    
    def validate_path(self, requested_path: Path) -> bool:
        # Prevent directory traversal attacks
        resolved_path = requested_path.resolve()
        return any(
            resolved_path.is_relative_to(base_path)
            for base_path in self.allowed_base_paths
        )
```

### 3. Network Simulation Security

**Considerations**:
- Simulation should not affect real networks
- Fault injection should be contained to simulation environment
- No actual network traffic generation

**Safeguards**:
```python
class SimulationSandbox:
    def __init__(self):
        self.simulation_mode = True  # Ensure no real network access
        
    def ensure_sandbox_mode(self):
        if not self.simulation_mode:
            raise SecurityError("Real network access not permitted")
```

---

## Future Architecture Enhancements

### 1. Microservices Architecture

For large-scale deployments:
```
API Gateway
├── Configuration Service (parsing, validation)
├── Topology Service (generation, analysis)
├── Simulation Service (fault injection, modeling)
└── Reporting Service (report generation)
```

### 2. Event-Driven Architecture

For real-time network monitoring integration:
```python
class NetworkEventBus:
    def publish_config_change(self, device: str, config: Dict):
        # Trigger re-analysis pipeline
        pass
    
    def publish_topology_change(self, change_type: str, affected_devices: List[str]):
        # Update dependent analyses
        pass
```

### 3. Plugin Ecosystem

For community contributions:
```
plugins/
├── vendors/
│   ├── cisco_plugin.py
│   ├── juniper_plugin.py
│   └── arista_plugin.py
├── analyzers/
│   ├── security_analyzer.py
│   └── performance_analyzer.py
└── exporters/
    ├── excel_exporter.py
    └── visio_exporter.py
```

This architecture provides a solid foundation for current needs while enabling future growth and extensibility.