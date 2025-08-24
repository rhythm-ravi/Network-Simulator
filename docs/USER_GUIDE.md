# Network Simulator User Guide

This guide provides comprehensive instructions for using the Network Simulator toolkit to analyze, validate, and simulate network configurations.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Configuration Analysis](#configuration-analysis)
3. [Network Topology Generation](#network-topology-generation)
4. [Issue Detection and Validation](#issue-detection-and-validation)
5. [Load Analysis and Optimization](#load-analysis-and-optimization)
6. [Fault Injection Testing](#fault-injection-testing)
7. [Reporting and Visualization](#reporting-and-visualization)
8. [Advanced Usage](#advanced-usage)
9. [Troubleshooting](#troubleshooting)

## Getting Started

### Installation

1. **Clone and Install:**
```bash
git clone https://github.com/rhythm-ravi/Network-Simulator.git
cd Network-Simulator
pip install -r requirements.txt
```

2. **Quick Test:**
```bash
# Create sample configurations and run comprehensive tests
python test_network_simulator.py --create-sample-configs --config-dir configs/my_network
python test_network_simulator.py --config-dir configs/my_network/enterprise_network --html
```

### Directory Structure

After installation, your directory should look like:
```
Network-Simulator/
├── configs/                    # Configuration files
├── src/                        # Source code
├── tests/                      # Test files
├── test_network_simulator.py   # Main testing framework
├── main.py                     # Basic CLI tool
└── network_analyzer.py         # Analysis utilities
```

## Configuration Analysis

### Supported Configuration Formats

The simulator supports various Cisco configuration file formats:
- `.config.dump` - Full configuration dumps
- `.cfg` - Configuration files
- `.config` - Standard config files

### Basic Configuration Analysis

```bash
# Analyze a single configuration directory
python test_network_simulator.py --config-dir /path/to/configs

# Analyze with verbose logging
python test_network_simulator.py --config-dir /path/to/configs --verbose
```

### Sample Configuration Format

Here's an example of a supported router configuration:

```yaml
# CORE-R1.config.dump
device:
  name: CORE-R1
  type: router
  model: cisco-4321
  location: datacenter

interfaces:
  - name: GigabitEthernet0/0/0
    type: ethernet
    ip_address: 10.0.1.1
    subnet_mask: 255.255.255.252
    bandwidth: 1000
    status: up
    description: "Link to Distribution Router"
    mtu: 1500
    
routing:
  protocols:
    - type: ospf
      process_id: 1
      router_id: 1.1.1.1
      networks:
        - network: 10.0.0.0
          wildcard: 0.0.255.255
          area: 0

vlans:
  - id: 10
    name: DATA
    ip_address: 192.168.10.1
    subnet_mask: 255.255.255.0
```

### What Gets Parsed

The configuration parser extracts:
- **Device Information**: Name, type, model, location
- **Interfaces**: IP addresses, bandwidth, MTU, status
- **VLANs**: VLAN IDs, names, IP addressing
- **Routing Protocols**: OSPF, static routes
- **Spanning Tree**: Configuration and priorities

## Network Topology Generation

### Automatic Topology Discovery

The simulator automatically generates network topology based on:
- IP address relationships between interfaces
- Subnet connectivity analysis
- VLAN trunk configurations
- Routing protocol neighbors

### Generating Topology Visualizations

```bash
# Generate topology with visualization
python test_network_simulator.py \
    --config-dir configs/network \
    --output-dir results \
    --html

# The visualization will be saved as: results/network_topology.png
```

### Understanding Topology Output

The topology generator provides:
- **Nodes**: Network devices (routers, switches)
- **Edges**: Connections between devices
- **Visualization**: PNG image showing network layout
- **Missing Devices**: Potentially undetected devices

Example output:
```
✓ Topology generated: 4 nodes, 6 connections
✓ Visualization saved: results/network_topology.png
⚠ Detected 2 potentially missing devices
```

## Issue Detection and Validation

### Network Validation Features

The simulator performs comprehensive network validation:

1. **IP Address Conflicts**: Duplicate IP addresses across devices
2. **VLAN Inconsistencies**: Naming and configuration mismatches  
3. **MTU Mismatches**: Interface MTU inconsistencies
4. **Routing Protocol Issues**: Missing or misconfigured protocols
5. **Spanning Tree Problems**: Missing or incorrect STP configuration

### Running Network Validation

```bash
# Run validation only
python test_network_simulator.py --config-dir configs/network --validate-only

# Full validation with detailed reporting
python test_network_simulator.py --config-dir configs/network --verbose --html
```

### Understanding Validation Results

Validation issues are categorized by severity:
- **Critical**: Issues that prevent network operation
- **High**: Issues causing significant problems
- **Medium**: Issues causing minor problems  
- **Low/Warning**: Recommendations for improvement

Example validation output:
```
⚠ Found 4 network issues:
  - no_routing_protocol: Router DIST-R2 has no routing protocols configured (Severity: warning)
  - vlan_naming_inconsistent: VLAN naming inconsistencies detected (Severity: medium)
  - mtu_mismatch: MTU mismatch on link CORE-R1:Gi0/0 <-> DIST-R2:Gi0/1 (Severity: high)
```

## Load Analysis and Optimization

### Network Load Analysis

The load analyzer evaluates:
- **Total Network Capacity**: Sum of all link bandwidths
- **Current Utilization**: Estimated traffic load
- **Overloaded Links**: Links exceeding capacity thresholds
- **Underutilized Links**: Links with low utilization
- **Capacity Planning**: Future growth recommendations

### Running Load Analysis

```bash
# Load analysis with recommendations
python test_network_simulator.py \
    --config-dir configs/network \
    --output-dir results \
    --html
```

### Understanding Load Analysis Results

```
✓ Load Analysis Results:
  Total Network Capacity: 5000.0 Mbps
  Current Utilization: 1250.0 Mbps (25.0%)
  Overloaded Links: 2
  Underutilized Links: 3
  Capacity Issues: 1

📋 Generated 5 load balancing recommendations:
  1. Consider upgrading link DIST-R2:Gi0/1 -> ACCESS-SW1:Gi0/1 from 100Mbps to 1Gbps
  2. Consider adding parallel links for CORE-R1:Gi0/0 -> DIST-R2:Gi0/0
  3. Consider consolidating multiple underutilized links between DIST-R2 and ACCESS-SW2
```

### Load Balancing Recommendations

The analyzer provides specific recommendations:
- **Bandwidth Upgrades**: Specific interface upgrade suggestions
- **Parallel Links**: Adding redundant links for high-traffic paths
- **Link Consolidation**: Optimizing underutilized connections
- **Protocol Optimization**: Routing protocol recommendations

## Fault Injection Testing

### Supported Fault Types

The fault injector can simulate:
- **Link Failures**: Temporary or permanent link outages
- **Device Failures**: Complete device failures or partial issues
- **Packet Loss**: Configurable packet drop rates
- **MTU Mismatches**: Packet size vs interface MTU conflicts
- **Bandwidth Reduction**: Link capacity constraints
- **Configuration Errors**: Device misconfigurations

### Running Fault Injection Tests

```bash
# Enable fault injection testing
python test_network_simulator.py \
    --config-dir configs/network \
    --fault-injection \
    --verbose
```

### Understanding Fault Injection Results

```
✓ Fault Injection Testing: 3/3 successful

Fault Injection Details:
  - link_failure on CORE-R1:eth0-DIST-R2:eth1 (Status: injected)
  - device_failure on DIST-R2 (Status: injected)  
  - packet_loss on ACCESS-SW1:eth0 (Status: injected)

Fault Statistics:
  Active Faults: 3
  Faults by Type: link_failure(1), device_failure(1), packet_loss(1)
  Faults by Severity: high(1), critical(1), medium(1)
```

### Using Fault Injection for Resilience Testing

1. **Baseline Testing**: Run tests without faults to establish baseline
2. **Single Point of Failure**: Test critical link/device failures
3. **Cascading Failures**: Test multiple simultaneous faults
4. **Recovery Testing**: Validate network recovery procedures

## Reporting and Visualization

### Report Formats

The testing framework generates multiple report formats:

1. **CLI Report** (`test_report.txt`): Human-readable text summary
2. **JSON Report** (`test_results.json`): Structured data for analysis
3. **HTML Report** (`test_report.html`): Interactive web-based report
4. **Topology Visualization** (`network_topology.png`): Network diagram

### Generating Reports

```bash
# Generate all report formats
python test_network_simulator.py \
    --config-dir configs/network \
    --output-dir results \
    --html \
    --verbose

# Reports will be saved in: results/
# - test_report.txt
# - test_results.json  
# - test_report.html
# - network_topology.png
```

### Reading CLI Reports

The CLI report provides a structured summary:

```
NETWORK SIMULATOR COMPREHENSIVE TEST REPORT
================================================================================

CONFIGURATION PARSING RESULTS
✓ Successfully parsed 4 device configurations
Devices: CORE-R1, DIST-R2, ACCESS-SW1, FAULTY-SW2

TOPOLOGY GENERATION RESULTS  
✓ Generated topology with 4 nodes and 6 connections
✓ Visualization: Generated

ISSUE DETECTION RESULTS
Found 3 network issues
Issues by type:
  - no_routing_protocol: 2
  - vlan_naming_inconsistent: 1

LOAD ANALYSIS RESULTS
Network Capacity: 5000.0 Mbps
Utilization: 1250.0 Mbps (25.0%)
Recommendations: 5

OVERALL SUMMARY
Overall Test Status: ✓ PASSED
Tests Passed: 5/5
Success Rate: 100.0%
```

### Understanding JSON Reports

The JSON report provides structured data for programmatic analysis:

```json
{
  "start_time": "2025-08-23T19:07:54.208630",
  "config_parsing": {
    "total_configs": 4,
    "parsed_devices": ["CORE-R1", "DIST-R2", "ACCESS-SW1", "FAULTY-SW2"],
    "success": true
  },
  "topology_generation": {
    "nodes_count": 4,
    "edges_count": 6,
    "visualization_generated": true,
    "success": true
  },
  "overall_summary": {
    "success": true,
    "tests_passed": 5,
    "total_tests": 5,
    "success_rate": 100.0
  }
}
```

## Advanced Usage

### Custom Configuration Scenarios

#### Creating Test Scenarios

1. **Create Directory Structure**:
```bash
mkdir -p configs/my_scenario
```

2. **Add Device Configurations**:
```bash
# Create router configuration
cat > configs/my_scenario/ROUTER1.config.dump << EOF
device:
  name: ROUTER1
  type: router
  model: cisco-2921

interfaces:
  - name: GigabitEthernet0/0
    ip_address: 192.168.1.1
    subnet_mask: 255.255.255.0
    bandwidth: 1000
    status: up
EOF
```

3. **Run Analysis**:
```bash
python test_network_simulator.py --config-dir configs/my_scenario
```

#### Intentional Misconfigurations for Testing

Create configurations with known issues to test validation:

```yaml
# FAULTY-SWITCH.config.dump
device:
  name: FAULTY-SWITCH
  type: switch

interfaces:
  - name: GigabitEthernet0/1
    ip_address: 192.168.1.1  # Duplicate IP (intentional issue)
    subnet_mask: 255.255.255.252
    mtu: 1400  # Non-standard MTU (intentional issue)

vlans:
  - id: 10
    name: DATA_USERS  # Inconsistent naming (intentional issue)
  - id: 20
    name: VOICE
  # Missing VLAN 30 in spanning tree (intentional issue)

spanning_tree:
  mode: pvst
  priority: 4096
  # Note: Missing configuration for VLAN 30
```

### Batch Processing

#### Processing Multiple Network Scenarios

```bash
#!/bin/bash
# batch_analysis.sh

for scenario in configs/scenarios/*; do
    if [ -d "$scenario" ]; then
        echo "Processing $scenario..."
        python test_network_simulator.py \
            --config-dir "$scenario" \
            --output-dir "results/$(basename $scenario)" \
            --html \
            --fault-injection
    fi
done
```

#### Automated Testing Pipeline

```bash
# Continuous integration testing
python test_network_simulator.py \
    --config-dir configs/production \
    --output-dir ci_results \
    --json-only \
    --fault-injection
    
# Check exit code
if [ $? -eq 0 ]; then
    echo "All network validation tests passed"
else
    echo "Network validation tests failed"
    exit 1
fi
```

### Integration with External Tools

#### Export to Network Management Systems

```python
# export_to_nms.py
import json
import requests

# Load test results
with open('results/test_results.json') as f:
    results = json.load(f)

# Export to network management system
nms_data = {
    'devices': results['config_parsing']['parsed_devices'],
    'issues': results['issue_detection']['details'],
    'topology': results['topology_generation']['connections']
}

# Send to NMS API
response = requests.post('http://nms.company.com/api/import', json=nms_data)
```

#### Custom Analysis Scripts

```python
# custom_analysis.py
import json
import matplotlib.pyplot as plt

# Load test results
with open('results/test_results.json') as f:
    results = json.load(f)

# Create custom visualizations
issues_by_type = results['issue_detection']['by_type']
plt.bar(issues_by_type.keys(), issues_by_type.values())
plt.title('Network Issues by Type')
plt.savefig('custom_analysis.png')
```

## Troubleshooting

### Common Issues and Solutions

#### Configuration Parsing Issues

**Problem**: "No configurations found"
```bash
python test_network_simulator.py --config-dir configs/empty
# Error: No configurations found
```

**Solutions**:
- Verify configuration directory exists and contains files
- Check file extensions (`.config.dump`, `.cfg`, `.config`)
- Ensure configuration files have proper format

**Problem**: "Invalid configuration format"
```bash
# Error: YAML parsing failed
```

**Solutions**:
- Validate YAML syntax using online validators
- Check indentation (use spaces, not tabs)
- Ensure all required fields are present

#### Topology Generation Issues

**Problem**: "No topology generated"
```bash
# ✓ Topology generated: 4 nodes, 0 connections
```

**Solutions**:
- Verify IP addresses are configured on interfaces
- Check that devices have interfaces in the same subnets
- Ensure interface status is "up"

#### Import Errors

**Problem**: "ModuleNotFoundError: No module named 'core'"
```bash
# ImportError: No module named 'core'
```

**Solutions**:
```bash
# Install dependencies
pip install -r requirements.txt

# Run from correct directory
cd Network-Simulator
python test_network_simulator.py
```

#### Memory/Performance Issues

**Problem**: Slow execution or high memory usage

**Solutions**:
```bash
# Run without fault injection for faster execution
python test_network_simulator.py --config-dir configs/network

# Disable simulation for basic analysis only
python test_network_simulator.py --config-dir configs/network --validate-only
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Maximum verbosity
python test_network_simulator.py \
    --config-dir configs/network \
    --verbose \
    2>&1 | tee debug.log

# Check specific log file
tail -f test_output/test_run_*.log
```

### Getting Help

1. **Check existing issues**: [GitHub Issues](https://github.com/rhythm-ravi/Network-Simulator/issues)
2. **Review logs**: Check `test_output/` directory for detailed logs
3. **Run tests**: Verify installation with `python -m pytest tests/`
4. **Contact maintainer**: Create issue with:
   - Configuration files (sanitized)
   - Error messages
   - System information
   - Log files

### Performance Optimization

For large networks:

```bash
# Skip fault injection for faster execution
python test_network_simulator.py --config-dir large_network

# Process in batches
find configs/large_network -name "*.config.dump" | head -10 | \
    xargs -I {} python test_network_simulator.py --config-dir {}
```

---

## Next Steps

After completing this user guide:
1. Try the [Quick Start](#getting-started) example
2. Create your own network configurations
3. Explore advanced features like fault injection
4. Integrate with your existing network management tools
5. Contribute improvements to the project

For technical details about the system architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).