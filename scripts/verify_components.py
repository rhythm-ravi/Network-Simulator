"""
Script to verify that core components are working properly.
"""
import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add the parent directory to the Python path to import src modules
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

from src.core.config_parser import ConfigParser
from src.core.topology_generator import TopologyGenerator
from src.core.network_validator import NetworkValidator

def create_test_configs():
    """Create test configuration files."""
    # Create a directory for test configs
    configs_dir = Path("./test_configs")
    configs_dir.mkdir(exist_ok=True)
    
    # Create directories for each device
    r1_dir = configs_dir / "R1"
    r2_dir = configs_dir / "R2"
    sw1_dir = configs_dir / "SW1"
    
    r1_dir.mkdir(exist_ok=True)
    r2_dir.mkdir(exist_ok=True)
    sw1_dir.mkdir(exist_ok=True)
    
    # Create R1 config
    r1_config = """
    hostname R1-CORE
    !
    interface GigabitEthernet0/0
     description Connection to R2
     ip address 10.0.0.1 255.255.255.252
     mtu 1500
    !
    interface GigabitEthernet0/1
     description Connection to SW1
     ip address 192.168.1.1 255.255.255.0
    !
    router ospf 1
     router-id 1.1.1.1
     network 10.0.0.0 0.0.0.3 area 0
     network 192.168.1.0 0.0.0.255 area 0
    !
    """
    
    # Create R2 config
    r2_config = """
    hostname R2
    !
    interface GigabitEthernet0/0
     description Connection to R1
     ip address 10.0.0.2 255.255.255.252
     mtu 1500
    !
    interface GigabitEthernet0/1
     description Connection to DMZ
     ip address 172.16.0.1 255.255.255.0
    !
    router ospf 1
     router-id 2.2.2.2
     network 10.0.0.0 0.0.0.3 area 0
     network 172.16.0.0 0.0.0.255 area 0
    !
    """
    
    # Create SW1 config
    sw1_config = """
    hostname SW1
    !
    spanning-tree mode rapid-pvst
    spanning-tree vlan 10,20
    !
    vlan 10
     name DATA
    !
    vlan 20
     name VOICE
    !
    interface GigabitEthernet0/1
     description Connection to R1
     switchport mode trunk
     switchport trunk allowed vlan 10,20
    !
    interface FastEthernet0/1
     description User Workstation
     switchport mode access
     switchport access vlan 10
    !
    """
    
    # Write configs to files
    with open(r1_dir / "config.dump", "w") as f:
        f.write(r1_config)
    
    with open(r2_dir / "config.dump", "w") as f:
        f.write(r2_config)
    
    with open(sw1_dir / "config.dump", "w") as f:
        f.write(sw1_config)
    
    return configs_dir

def main():
    """Test core components and save results."""
    print("=== VERIFYING NETWORK SIMULATOR CORE COMPONENTS ===")
    
    # Create test configs
    configs_dir = create_test_configs()
    print(f"Created test configs in: {configs_dir}")
    
    # Step 1: Parse configurations
    parser = ConfigParser()
    device_configs = parser.parse_directory(str(configs_dir))
    
    print(f"\nParsed {len(device_configs)} device configurations:")
    for name, config in device_configs.items():
        print(f"  - {name} ({config.device_type})")
        print(f"    Interfaces: {len(config.interfaces)}")
        print(f"    VLANs: {len(config.vlans)}")
        print(f"    Routing protocols: {len(config.routing_protocols)}")
    
    # Step 2: Generate topology
    generator = TopologyGenerator()
    topology = generator.generate_topology(device_configs)
    
    print(f"\nGenerated topology with {topology.number_of_nodes()} devices and {topology.number_of_edges()} links")
    print("Edges in topology:")
    for edge in topology.edges(data=True):
        print(f"  - {edge[0]} <-> {edge[1]}")
    
    # Step 3: Detect missing devices
    missing_devices = generator.detect_missing_devices()
    print(f"\nDetected {len(missing_devices)} potentially missing devices")
    
    # Step 4: Validate network
    validator = NetworkValidator()
    issues = validator.validate_network(device_configs)
    
    print(f"\nDetected {len(issues)} potential issues in the network:")
    for issue in issues:
        print(f"  - {issue['type']}: {issue['description']} (Severity: {issue['severity']})")
    
    # Step 5: Generate visualization to the proper outputs directory
    output_dir = Path("..") / "outputs" / "visualizations" if Path(__file__).parent.name == "scripts" else Path("outputs") / "visualizations"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    image_path = output_dir / "topology.png"
    generator.visualize_topology(str(image_path))
    
    print(f"\nGenerated topology visualization at {image_path}")
    print(f"File exists: {image_path.exists()}")
    
    if image_path.exists():
        print(f"File size: {image_path.stat().st_size} bytes")
    
    print("\n=== VERIFICATION COMPLETE ===")
    
    return image_path

if __name__ == "__main__":
    image_path = main()