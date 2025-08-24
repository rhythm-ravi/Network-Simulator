"""
Tests for Network Validator functionality.
"""
import os
import sys
import pytest
import tempfile
from pathlib import Path

# Add the project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.core.config_parser import ConfigParser
from src.core.network_validator import NetworkValidator

def create_test_config(config_dir, device_name, content):
    """Create a test configuration file."""
    device_dir = os.path.join(config_dir, device_name)
    os.makedirs(device_dir, exist_ok=True)
    
    with open(os.path.join(device_dir, "config.dump"), "w") as f:
        f.write(content)

def test_duplicate_ip_detection():
    """Test detection of duplicate IP addresses."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test configs with duplicate IPs
        r1_config = """
        hostname R1
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0
        interface GigabitEthernet0/1
         ip address 10.0.0.1 255.255.255.0
        """
        
        r2_config = """
        hostname R2
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0  # Duplicate of R1's IP
        interface GigabitEthernet0/1
         ip address 10.0.0.2 255.255.255.0
        """
        
        create_test_config(temp_dir, "R1", r1_config)
        create_test_config(temp_dir, "R2", r2_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Validate network
        validator = NetworkValidator()
        issues = validator.validate_network(device_configs)
        
        # Check for duplicate IP issue
        duplicate_ip_issues = [issue for issue in issues if issue['type'] == 'duplicate_ip']
        
        assert len(duplicate_ip_issues) == 1
        assert duplicate_ip_issues[0]['severity'] == 'critical'
        assert '192.168.1.1' in duplicate_ip_issues[0]['description']
        assert len(duplicate_ip_issues[0]['affected']) == 2

def test_inconsistent_subnet_masks():
    """Test detection of inconsistent subnet masks in the same network."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test configs with inconsistent subnet masks
        r1_config = """
        hostname R1
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0
        """
        
        r2_config = """
        hostname R2
        interface GigabitEthernet0/0
         ip address 192.168.1.2 255.255.255.128  # Different mask from R1
        """
        
        create_test_config(temp_dir, "R1", r1_config)
        create_test_config(temp_dir, "R2", r2_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Validate network
        validator = NetworkValidator()
        issues = validator.validate_network(device_configs)
        
        # Check for subnet mask inconsistency
        subnet_mask_issues = [issue for issue in issues if issue['type'] == 'inconsistent_subnet_masks']
        
        assert len(subnet_mask_issues) == 1
        assert subnet_mask_issues[0]['severity'] == 'critical'
        assert '192.168.1' in subnet_mask_issues[0]['description']
        assert len(subnet_mask_issues[0]['masks']) == 2
        assert '255.255.255.0' in subnet_mask_issues[0]['masks']
        assert '255.255.255.128' in subnet_mask_issues[0]['masks']

def test_vlan_consistency():
    """Test VLAN configuration consistency validation."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test configs with inconsistent VLAN names
        sw1_config = """
        hostname SW1
        vlan 10
         name DATA
        vlan 20
         name VOICE
        """
        
        sw2_config = """
        hostname SW2
        vlan 10
         name USER_DATA  # Different name for same VLAN ID
        vlan 20
         name VOICE
        """
        
        create_test_config(temp_dir, "SW1", sw1_config)
        create_test_config(temp_dir, "SW2", sw2_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Validate network
        validator = NetworkValidator()
        issues = validator.validate_network(device_configs)
        
        # Check for VLAN name inconsistency
        vlan_name_issues = [issue for issue in issues if issue['type'] == 'inconsistent_vlan_names']
        
        assert len(vlan_name_issues) == 1
        assert vlan_name_issues[0]['severity'] == 'warning'
        assert '10' in vlan_name_issues[0]['description']
        assert len(vlan_name_issues[0]['names']) == 2
        assert 'DATA' in vlan_name_issues[0]['names']
        assert 'USER_DATA' in vlan_name_issues[0]['names']

def test_mtu_inconsistency():
    """Test detection of MTU inconsistencies on interfaces."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test configs with MTU inconsistencies
        router_config = """
        hostname R1
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0
         mtu 1500
        interface GigabitEthernet0/1
         ip address 10.0.0.1 255.255.255.252
         mtu 9000  # Jumbo frames
        """
        
        create_test_config(temp_dir, "R1", router_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Validate network
        validator = NetworkValidator()
        issues = validator.validate_network(device_configs)
        
        # Check for MTU inconsistency
        mtu_issues = [issue for issue in issues if issue['type'] == 'mtu_inconsistency']
        
        assert len(mtu_issues) == 1
        assert mtu_issues[0]['severity'] == 'warning'
        assert 'R1' in mtu_issues[0]['description']
        assert '1500' in mtu_issues[0]['description'] or 1500 in mtu_issues[0]['description']
        assert '9000' in mtu_issues[0]['description'] or 9000 in mtu_issues[0]['description']

def test_missing_spanning_tree():
    """Test detection of missing spanning tree configuration."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test switch config without spanning tree
        switch_config = """
        hostname SW1
        vlan 10
         name DATA
        vlan 20
         name VOICE
        interface FastEthernet0/1
         switchport mode access
         switchport access vlan 10
        """
        
        create_test_config(temp_dir, "SW1", switch_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Validate network
        validator = NetworkValidator()
        issues = validator.validate_network(device_configs)
        
        # Check for missing spanning tree issue
        spanning_tree_issues = [issue for issue in issues if issue['type'] == 'missing_spanning_tree']
        
        assert len(spanning_tree_issues) > 0
        assert 'SW1' in spanning_tree_issues[0]['devices']

def test_routing_protocol_recommendations():
    """Test routing protocol recommendations."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create several routers with OSPF to trigger BGP recommendation
        for i in range(1, 7):
            router_config = f"""
            hostname R{i}
            interface GigabitEthernet0/0
             ip address 192.168.{i}.1 255.255.255.0
            router ospf 1
             network 192.168.{i}.0 0.0.0.255 area 0
            """
            
            create_test_config(temp_dir, f"R{i}", router_config)
        
        # Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Validate network
        validator = NetworkValidator()
        issues = validator.validate_network(device_configs)
        
        # Check for BGP recommendation
        bgp_recommendations = [issue for issue in issues if issue['type'] == 'consider_bgp']
        
        assert len(bgp_recommendations) > 0
        assert bgp_recommendations[0]['severity'] == 'info'
        assert 'scalability' in bgp_recommendations[0]['description'].lower()

if __name__ == "__main__":
    test_duplicate_ip_detection()
    test_inconsistent_subnet_masks()
    test_vlan_consistency()
    test_mtu_inconsistency()
    test_missing_spanning_tree()
    test_routing_protocol_recommendations()
    print("All network validator tests passed!")