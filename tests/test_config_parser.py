"""
Tests for Configuration Parser functionality.
"""
import os
import sys
import pytest
from pathlib import Path
import shutil
import tempfile

# Add the project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.core.config_parser import ConfigParser, DeviceConfiguration

def create_test_config(config_dir, device_name, content):
    """Create a test configuration file."""
    device_dir = os.path.join(config_dir, device_name)
    os.makedirs(device_dir, exist_ok=True)
    
    with open(os.path.join(device_dir, "config.dump"), "w") as f:
        f.write(content)

def test_router_config_parsing():
    """Test parsing a router configuration."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test router config
        router_config = """
        ! R1 Configuration
        hostname R1
        !
        interface GigabitEthernet0/0
         description Connection to Core Switch
         ip address 192.168.1.1 255.255.255.0
         duplex full
         speed 1000
         no shutdown
        !
        interface GigabitEthernet0/1
         description WAN Link
         ip address 10.0.0.1 255.255.255.252
         mtu 1500
         bandwidth 100000
        !
        router ospf 1
         router-id 1.1.1.1
         network 192.168.1.0 0.0.0.255 area 0
         network 10.0.0.0 0.0.0.3 area 0
         passive-interface GigabitEthernet0/1
        !
        ip route 0.0.0.0 0.0.0.0 10.0.0.2
        !
        ip access-list extended BLOCK_TELNET
         deny tcp any any eq 23
         permit ip any any
        !
        """
        
        create_test_config(temp_dir, "R1", router_config)
        
        # Parse the configuration
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Verify results
        assert "R1" in device_configs
        
        r1_config = device_configs["R1"]
        assert r1_config.hostname == "R1"
        assert r1_config.device_type == "router"
        
        # Check interfaces
        assert "GigabitEthernet0/0" in r1_config.interfaces
        assert "GigabitEthernet0/1" in r1_config.interfaces
        
        # Verify interface attributes
        g0_0 = r1_config.interfaces["GigabitEthernet0/0"]
        assert g0_0.ip_address == "192.168.1.1"
        assert g0_0.subnet_mask == "255.255.255.0"
        assert g0_0.description == "Connection to Core Switch"
        assert g0_0.status == "up"  # Not shutdown
        
        g0_1 = r1_config.interfaces["GigabitEthernet0/1"]
        assert g0_1.ip_address == "10.0.0.1"
        assert g0_1.subnet_mask == "255.255.255.252"
        assert g0_1.mtu == 1500
        assert g0_1.bandwidth == "100Kbps"
        
        # Check OSPF
        assert len(r1_config.routing_protocols) == 2  # OSPF + static routes
        
        ospf_protocols = [p for p in r1_config.routing_protocols if p.protocol_type == "ospf"]
        assert len(ospf_protocols) == 1
        ospf = ospf_protocols[0]
        assert ospf.process_id == "1"
        assert ospf.router_id == "1.1.1.1"
        assert len(ospf.networks) == 2
        assert ospf.passive_interfaces == ["GigabitEthernet0/1"]
        
        # Check ACLs
        assert "BLOCK_TELNET" in r1_config.acls

def test_switch_config_parsing():
    """Test parsing a switch configuration."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test switch config
        switch_config = """
        ! SW1 Configuration
        hostname SW1
        !
        spanning-tree mode rapid-pvst
        spanning-tree vlan 1-50,100,200
        !
        vlan 10
         name DATA
        !
        vlan 20
         name VOICE
        !
        vlan 30
         name MANAGEMENT
        !
        interface FastEthernet0/1
         description Access Port - User Workstation
         switchport mode access
         switchport access vlan 10
         spanning-tree portfast
        !
        interface FastEthernet0/2
         description IP Phone Port
         switchport mode access
         switchport access vlan 20
         switchport voice vlan 20
        !
        interface GigabitEthernet0/1
         description Trunk to Router
         switchport mode trunk
         switchport trunk allowed vlan 10,20,30
        !
        interface Vlan30
         description Management Interface
         ip address 192.168.30.10 255.255.255.0
        !
        ip default-gateway 192.168.30.1
        !
        """
        
        create_test_config(temp_dir, "SW1", switch_config)
        
        # Parse the configuration
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Verify results
        assert "SW1" in device_configs
        
        sw1_config = device_configs["SW1"]
        assert sw1_config.hostname == "SW1"
        assert sw1_config.device_type == "switch"
        
        # Check VLANs
        assert len(sw1_config.vlans) == 3
        assert 10 in sw1_config.vlans
        assert 20 in sw1_config.vlans
        assert 30 in sw1_config.vlans
        assert sw1_config.vlans[10].name == "DATA"
        
        # Check interfaces
        assert "FastEthernet0/1" in sw1_config.interfaces
        assert "FastEthernet0/2" in sw1_config.interfaces
        assert "GigabitEthernet0/1" in sw1_config.interfaces
        
        # Verify interface attributes
        fa0_1 = sw1_config.interfaces["FastEthernet0/1"]
        assert fa0_1.switchport_mode == "access"
        assert fa0_1.access_vlan == 10
        
        gi0_1 = sw1_config.interfaces["GigabitEthernet0/1"]
        assert gi0_1.switchport_mode == "trunk"
        assert gi0_1.trunk_vlans == [10, 20, 30]
        
        vlan30 = sw1_config.interfaces["Vlan30"]
        assert vlan30.ip_address == "192.168.30.10"
        assert vlan30.subnet_mask == "255.255.255.0"
        assert vlan30.is_physical == False
        
        # Check spanning tree
        assert sw1_config.spanning_tree_mode == "rapid-pvst"
        expected_vlans = set(list(range(1, 51)) + [100, 200])
        assert sw1_config.spanning_tree_vlans == expected_vlans

def test_multiple_devices():
    """Test parsing configurations for multiple devices."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create configs for multiple devices
        router1_config = """
        hostname R1
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0
        interface GigabitEthernet0/1
         ip address 10.0.0.1 255.255.255.252
        """
        
        router2_config = """
        hostname R2
        interface GigabitEthernet0/0
         ip address 10.0.0.2 255.255.255.252
        interface GigabitEthernet0/1
         ip address 172.16.0.1 255.255.255.0
        """
        
        switch_config = """
        hostname SW1
        vlan 10
         name DATA
        interface FastEthernet0/1
         switchport mode access
         switchport access vlan 10
        """
        
        create_test_config(temp_dir, "R1", router1_config)
        create_test_config(temp_dir, "R2", router2_config)
        create_test_config(temp_dir, "SW1", switch_config)
        
        # Parse the configuration
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Verify results
        assert len(device_configs) == 3
        assert "R1" in device_configs
        assert "R2" in device_configs
        assert "SW1" in device_configs
        
        # Check device types
        assert device_configs["R1"].device_type == "router"
        assert device_configs["R2"].device_type == "router"
        assert device_configs["SW1"].device_type == "switch"
        
        # Verify IP addresses
        assert device_configs["R1"].interfaces["GigabitEthernet0/0"].ip_address == "192.168.1.1"
        assert device_configs["R2"].interfaces["GigabitEthernet0/0"].ip_address == "10.0.0.2"

if __name__ == "__main__":
    test_router_config_parsing()
    test_switch_config_parsing()
    test_multiple_devices()
    print("All configuration parser tests passed!")