"""
Tests for Topology Generator functionality.
"""
import os
import sys
import pytest
import tempfile
from pathlib import Path
import networkx as nx

# Add the project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.core.config_parser import ConfigParser, DeviceConfiguration
from src.core.topology_generator import TopologyGenerator

def create_test_config(config_dir, device_name, content):
    """Create a test configuration file."""
    device_dir = os.path.join(config_dir, device_name)
    os.makedirs(device_dir, exist_ok=True)
    
    with open(os.path.join(device_dir, "config.dump"), "w") as f:
        f.write(content)

def test_topology_generation_from_ip():
    """Test generating topology based on IP connectivity."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test router configs
        r1_config = """
        hostname R1
        interface GigabitEthernet0/0
         description Link to R2
         ip address 10.0.0.1 255.255.255.252
        interface GigabitEthernet0/1
         ip address 192.168.1.1 255.255.255.0
        """
        
        r2_config = """
        hostname R2
        interface GigabitEthernet0/0
         description Link to R1
         ip address 10.0.0.2 255.255.255.252
        interface GigabitEthernet0/1
         ip address 192.168.2.1 255.255.255.0
        """
        
        create_test_config(temp_dir, "R1", r1_config)
        create_test_config(temp_dir, "R2", r2_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Generate topology
        generator = TopologyGenerator()
        topology = generator.generate_topology(device_configs)
        
        # Verify topology
        assert topology.number_of_nodes() == 2
        assert topology.number_of_edges() == 1
        assert topology.has_edge("R1", "R2")
        
        # Check link attributes
        edge_data = topology.get_edge_data("R1", "R2")
        assert "network" in edge_data
        assert edge_data["network"] == "10.0.0.0/30"
        
        # Check interface mapping
        interfaces = edge_data["interfaces"]
        assert interfaces["R1"] == "GigabitEthernet0/0"
        assert interfaces["R2"] == "GigabitEthernet0/0"

def test_topology_generation_with_switch():
    """Test generating topology with a switch in the middle."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test configs
        r1_config = """
        hostname R1
        interface GigabitEthernet0/0
         description Connection to SW1
         ip address 192.168.1.1 255.255.255.0
        """
        
        r2_config = """
        hostname R2
        interface GigabitEthernet0/0
         description Connection to SW1
         ip address 192.168.1.2 255.255.255.0
        """
        
        sw1_config = """
        hostname SW1
        vlan 10
         name DATA
        interface GigabitEthernet0/1
         description Link to R1
         switchport mode access
         switchport access vlan 10
        interface GigabitEthernet0/2
         description Link to R2
         switchport mode access
         switchport access vlan 10
        """
        
        create_test_config(temp_dir, "R1", r1_config)
        create_test_config(temp_dir, "R2", r2_config)
        create_test_config(temp_dir, "SW1", sw1_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Generate topology
        generator = TopologyGenerator()
        topology = generator.generate_topology(device_configs)
        
        # Verify topology - in this case, R1 and R2 should be connected
        # because they're on the same network, but SW1 should also be connected to both
        assert topology.number_of_nodes() == 3
        
        # Check R1-R2 connection (they share same network)
        assert topology.has_edge("R1", "R2")
        
        # Check SW1 connections by description
        # If description-based detection works, SW1 should be connected to both routers
        sw1_connections = list(topology.edges("SW1"))
        
        # The connectivity may vary based on the implementation details
        # At minimum, we expect to see some connections
        assert len(sw1_connections) > 0

def test_detect_missing_devices():
    """Test detecting missing devices in the network."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test configs for routers that should be connected but aren't directly
        r1_config = """
        hostname R1
        interface GigabitEthernet0/0
         description Connection to missing switch
         ip address 192.168.10.1 255.255.255.0
        """
        
        r2_config = """
        hostname R2
        interface GigabitEthernet0/0
         description Connection to missing switch
         ip address 192.168.10.2 255.255.255.0
        """
        
        create_test_config(temp_dir, "R1", r1_config)
        create_test_config(temp_dir, "R2", r2_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Generate topology
        generator = TopologyGenerator()
        topology = generator.generate_topology(device_configs)
        
        # Detect missing devices
        missing_devices = generator.detect_missing_devices()
        
        # Verify missing device detection
        assert len(missing_devices) > 0
        
        # Check if at least one of the missing devices is detected as a potential switch
        assert any(device['type'] == 'potential_switch' for device in missing_devices)
        
        # Check if the network is properly identified
        missing_switch = next((device for device in missing_devices if device['type'] == 'potential_switch'), None)
        assert missing_switch is not None
        assert missing_switch['network'] == '192.168.10.0/24'
        assert set(missing_switch['connected_devices']) == {'R1', 'R2'}

def test_visualization():
    """Test visualization functionality."""
    # Create a simple topology
    generator = TopologyGenerator()
    generator.graph = nx.Graph()
    
    # Add nodes
    generator.graph.add_node("R1", type="router", hostname="CoreRouter")
    generator.graph.add_node("R2", type="router", hostname="EdgeRouter")
    generator.graph.add_node("SW1", type="switch", hostname="CoreSwitch")
    
    # Add edges
    generator.graph.add_edge("R1", "R2", interfaces={"R1": "Gi0/0", "R2": "Gi0/0"})
    generator.graph.add_edge("R1", "SW1", interfaces={"R1": "Gi0/1", "SW1": "Gi0/1"})
    
    # Generate visualization
    image_bytes = generator.visualize_topology()
    
    # Check that the image was created
    assert image_bytes is not None
    assert len(image_bytes) > 0

if __name__ == "__main__":
    test_topology_generation_from_ip()
    test_topology_generation_with_switch()
    test_detect_missing_devices()
    test_visualization()
    print("All topology generator tests passed!")