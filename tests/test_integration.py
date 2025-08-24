"""
Integration test for the network analysis components.
"""
import os
import sys
import tempfile
from pathlib import Path
import matplotlib.pyplot as plt

# Add the project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.core.config_parser import ConfigParser
from src.core.topology_generator import TopologyGenerator
from src.core.network_validator import NetworkValidator

def create_test_config(config_dir, device_name, content):
    """Create a test configuration file."""
    device_dir = os.path.join(config_dir, device_name)
    os.makedirs(device_dir, exist_ok=True)
    
    with open(os.path.join(device_dir, "config.dump"), "w") as f:
        f.write(content)

def test_network_analysis_pipeline():
    """Test the complete network analysis pipeline."""
    # Create a temporary directory for test configs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a more complex test network
        # Core Router
        r1_config = """
        hostname R1-CORE
        !
        interface GigabitEthernet0/0
         description Connection to Distribution Router
         ip address 10.0.0.1 255.255.255.252
         mtu 1500
        !
        interface GigabitEthernet0/1
         description Connection to Internet
         ip address 203.0.113.2 255.255.255.252
        !
        router ospf 1
         router-id 1.1.1.1
         network 10.0.0.0 0.0.0.3 area 0
        !
        """
        
        # Distribution Router
        r2_config = """
        hostname R2-DIST
        !
        interface GigabitEthernet0/0
         description Connection to Core Router
         ip address 10.0.0.2 255.255.255.252
         mtu 1500
        !
        interface GigabitEthernet0/1
         description Connection to Access Switch
         ip address 10.0.1.1 255.255.255.0
         mtu 1500
        !
        router ospf 1
         router-id 2.2.2.2
         network 10.0.0.0 0.0.0.3 area 0
         network 10.0.1.0 0.0.0.255 area 0
        !
        """
        
        # Access Switch
        sw1_config = """
        hostname SW1-ACCESS
        !
        spanning-tree mode rapid-pvst
        spanning-tree vlan 10,20,30
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
        interface GigabitEthernet0/1
         description Connection to Distribution Router
         switchport mode trunk
         switchport trunk allowed vlan 10,20,30
        !
        interface FastEthernet0/1
         description User Workstation
         switchport mode access
         switchport access vlan 10
        !
        interface FastEthernet0/2
         description User Phone
         switchport mode access
         switchport access vlan 20
        !
        interface Vlan30
         description Management Interface
         ip address 10.0.1.2 255.255.255.0
        !
        ip default-gateway 10.0.1.1
        !
        """
        
        # Misconfigured Switch (missing spanning tree on some VLANs)
        sw2_config = """
        hostname SW2-MISCONFIG
        !
        spanning-tree mode rapid-pvst
        spanning-tree vlan 10,20
        !
        vlan 10
         name DATA
        !
        vlan 20
         name PHONE
        !
        vlan 30
         name MGMT
        !
        interface GigabitEthernet0/1
         description Connection to Switch 1
         switchport mode trunk
         switchport trunk allowed vlan 10,20,30
        !
        interface FastEthernet0/1
         description Server Connection
         switchport mode access
         switchport access vlan 30
        !
        interface Vlan30
         description Management Interface
         ip address 10.0.1.3 255.255.255.0
        !
        ip default-gateway 10.0.1.1
        !
        """
        
        # Create the test configs
        create_test_config(temp_dir, "R1-CORE", r1_config)
        create_test_config(temp_dir, "R2-DIST", r2_config)
        create_test_config(temp_dir, "SW1-ACCESS", sw1_config)
        create_test_config(temp_dir, "SW2-MISCONFIG", sw2_config)
        
        # Step 1: Parse configurations
        parser = ConfigParser()
        device_configs = parser.parse_directory(temp_dir)
        
        # Verify parsing
        assert len(device_configs) == 4
        assert "R1-CORE" in device_configs
        assert "R2-DIST" in device_configs
        assert "SW1-ACCESS" in device_configs
        assert "SW2-MISCONFIG" in device_configs
        
        # Step 2: Generate topology
        generator = TopologyGenerator()
        topology = generator.generate_topology(device_configs)
        
        # Verify topology
        assert topology.number_of_nodes() == 4
        assert topology.has_edge("R1-CORE", "R2-DIST")
        assert topology.has_edge("R2-DIST", "SW1-ACCESS")
        
        # Step 3: Detect missing devices
        missing_devices = generator.detect_missing_devices()
        print(f"Detected {len(missing_devices)} potentially missing devices")
        
        # Step 4: Validate network
        validator = NetworkValidator()
        issues = validator.validate_network(device_configs)
        
        # Verify issues
        print(f"Detected {len(issues)} potential issues in the network")
        for issue in issues:
            print(f"- {issue['type']}: {issue['description']} (Severity: {issue['severity']})")
        
        # Expected issues should include:
        # - VLAN name inconsistencies (DATA vs DATA, VOICE vs PHONE, MANAGEMENT vs MGMT)
        # - Missing spanning tree for VLAN 30 on SW2-MISCONFIG
        
        vlan_name_issues = [issue for issue in issues if issue['type'] == 'inconsistent_vlan_names']
        assert len(vlan_name_issues) > 0
        
        spanning_tree_issues = [issue for issue in issues if issue['type'] == 'missing_spanning_tree']
        assert len(spanning_tree_issues) > 0
        
        # Step 5: Generate visualization
        # Save visualization for manual inspection
        image_path = os.path.join(temp_dir, "topology.png")
        generator.visualize_topology(image_path)
        
        assert os.path.exists(image_path)
        print(f"Generated topology visualization at {image_path}")
        
        # If you want to display the image (uncomment for manual testing)
        # img = plt.imread(image_path)
        # plt.imshow(img)
        # plt.axis('off')
        # plt.show()
        
        return "Integration test successful"

if __name__ == "__main__":
    result = test_network_analysis_pipeline()
    print(result)