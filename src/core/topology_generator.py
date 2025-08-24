# #!/usr/bin/env python3
# """
# Topology Generator for Network Simulator

# This module builds network topologies from parsed configuration data,
# connecting devices based on interface configurations and creating links.
# """

# import logging
# from typing import Dict, List, Any, Optional
# from ipaddress import IPv4Network, IPv4Address
# import re

# from models.network_models import (
#     NetworkDevice, Router, Switch, NetworkInterface, VLAN, 
#     RoutingProtocol, Link, NetworkTopology,
#     DeviceType, InterfaceType, InterfaceStatus
# )


# logger = logging.getLogger(__name__)


# class TopologyGenerator:
#     """Generates network topology from configuration data."""
    
#     def __init__(self):
#         """Initialize the topology generator."""
#         self.topology = NetworkTopology()
#         self.device_factories = {
#             'router': self._create_router,
#             'switch': self._create_switch
#         }
    
#     def generate_topology(self, configurations: List[Dict[str, Any]], 
#                          topology_name: str = "Generated Topology") -> NetworkTopology:
#         """
#         Generate a complete network topology from configuration data.
        
#         Args:
#             configurations: List of device configuration dictionaries
#             topology_name: Name for the generated topology
            
#         Returns:
#             NetworkTopology object with all devices and links
#         """
#         logger.info(f"Generating topology '{topology_name}' from {len(configurations)} configurations")
        
#         self.topology = NetworkTopology(topology_name)
        
#         # First pass: Create all devices
#         for config in configurations:
#             try:
#                 device = self._create_device_from_config(config)
#                 if device:
#                     self.topology.add_device(device)
#             except Exception as e:
#                 logger.error(f"Failed to create device from config: {e}")
        
#         # Second pass: Create links between devices
#         self._generate_links()
        
#         # Validate the generated topology
#         is_valid, errors = self.topology.validate_topology()
#         if not is_valid:
#             logger.warning(f"Generated topology has validation errors: {errors}")
        
#         logger.info(f"Generated topology with {len(self.topology.devices)} devices "
#                    f"and {len(self.topology.links)} links")
        
#         return self.topology
    
#     def _create_device_from_config(self, config: Dict[str, Any]) -> Optional[NetworkDevice]:
#         """
#         Create a network device from its configuration.
        
#         Args:
#             config: Device configuration dictionary
            
#         Returns:
#             NetworkDevice instance or None if creation fails
#         """
#         device_info = config.get('device', {})
#         device_type = device_info.get('type', '').lower()
#         device_name = device_info.get('name', 'unknown')
        
#         if device_type not in self.device_factories:
#             logger.error(f"Unsupported device type: {device_type}")
#             return None
        
#         logger.debug(f"Creating {device_type}: {device_name}")
        
#         # Create the device using the appropriate factory
#         device = self.device_factories[device_type](config)
        
#         if device:
#             device.config_source = config.get('_metadata', {}).get('source_file', '')
        
#         return device
    
#     def _create_router(self, config: Dict[str, Any]) -> Router:
#         """Create a Router from configuration."""
#         device_info = config.get('device', {})
        
#         router = Router(
#             name=device_info.get('name', 'unknown'),
#             model=device_info.get('model', ''),
#             location=device_info.get('location', '')
#         )
        
#         # Add interfaces
#         for interface_config in config.get('interfaces', []):
#             interface = self._create_interface(interface_config)
#             router.add_interface(interface)
        
#         # Add VLANs
#         for vlan_config in config.get('vlans', []):
#             vlan = self._create_vlan(vlan_config)
#             router.add_vlan(vlan)
        
#         # Add routing protocols
#         routing_config = config.get('routing', {})
#         for protocol_config in routing_config.get('protocols', []):
#             protocol = self._create_routing_protocol(protocol_config)
#             router.add_routing_protocol(protocol)
        
#         return router
    
#     def _create_switch(self, config: Dict[str, Any]) -> Switch:
#         """Create a Switch from configuration."""
#         device_info = config.get('device', {})
        
#         switch = Switch(
#             name=device_info.get('name', 'unknown'),
#             model=device_info.get('model', ''),
#             location=device_info.get('location', '')
#         )
        
#         # Add interfaces
#         for interface_config in config.get('interfaces', []):
#             interface = self._create_interface(interface_config)
#             switch.add_interface(interface)
        
#         # Add VLANs
#         for vlan_config in config.get('vlans', []):
#             vlan = self._create_vlan(vlan_config)
#             switch.add_vlan(vlan)
        
#         # Add spanning tree configuration
#         if 'spanning_tree' in config:
#             switch.spanning_tree_config = config['spanning_tree']
        
#         return switch
    
#     def _create_interface(self, interface_config: Dict[str, Any]) -> NetworkInterface:
#         """Create a NetworkInterface from configuration."""
#         return NetworkInterface(
#             name=interface_config.get('name', ''),
#             interface_type=InterfaceType(interface_config.get('type', 'ethernet')),
#             ip_address=interface_config.get('ip_address'),
#             subnet_mask=interface_config.get('subnet_mask'),
#             bandwidth=interface_config.get('bandwidth', 0),
#             status=InterfaceStatus(interface_config.get('status', 'down')),
#             description=interface_config.get('description', ''),
#             access_vlan=interface_config.get('access_vlan'),
#             trunk_vlans=interface_config.get('trunk_vlans', [])
#         )
    
#     def _create_vlan(self, vlan_config: Dict[str, Any]) -> VLAN:
#         """Create a VLAN from configuration."""
#         return VLAN(
#             vlan_id=vlan_config.get('id', 0),
#             name=vlan_config.get('name', ''),
#             ip_address=vlan_config.get('ip_address'),
#             subnet_mask=vlan_config.get('subnet_mask'),
#             ports=vlan_config.get('ports', [])
#         )
    
#     def _create_routing_protocol(self, protocol_config: Dict[str, Any]) -> RoutingProtocol:
#         """Create a RoutingProtocol from configuration."""
#         return RoutingProtocol(
#             protocol_type=protocol_config.get('type', ''),
#             process_id=protocol_config.get('process_id'),
#             networks=protocol_config.get('networks', []),
#             routes=protocol_config.get('routes', []),
#             config=protocol_config
#         )
    
#     def _generate_links(self) -> None:
#         """
#         Generate links between devices based on their interface configurations.
        
#         This method analyzes interface IP addresses to determine which devices
#         should be connected to each other.
#         """
#         logger.info("Generating links between devices...")
        
#         # Get all devices and their interfaces
#         devices = list(self.topology.devices.values())
        
#         # Create a mapping of subnets to interfaces
#         subnet_interfaces = {}
        
#         for device in devices:
#             for interface in device.interfaces.values():
#                 if interface.ip_address and interface.subnet_mask and interface.is_up:
#                     try:
#                         # Calculate subnet
#                         network = IPv4Network(f"{interface.ip_address}/{interface.subnet_mask}", strict=False)
#                         subnet_str = str(network.network_address) + "/" + str(network.prefixlen)
                        
#                         if subnet_str not in subnet_interfaces:
#                             subnet_interfaces[subnet_str] = []
                        
#                         subnet_interfaces[subnet_str].append({
#                             'device': device,
#                             'interface': interface,
#                             'network': network
#                         })
                        
#                     except Exception as e:
#                         logger.warning(f"Could not parse IP {interface.ip_address}/{interface.subnet_mask}: {e}")
        
#         # Create links for interfaces in the same subnet
#         for subnet, interfaces in subnet_interfaces.items():
#             if len(interfaces) > 1:
#                 logger.debug(f"Creating links for subnet {subnet}")
                
#                 # For each pair of interfaces in the same subnet, create a link
#                 for i in range(len(interfaces)):
#                     for j in range(i + 1, len(interfaces)):
#                         interface1 = interfaces[i]
#                         interface2 = interfaces[j]
                        
#                         # Determine bandwidth (use minimum of the two interfaces)
#                         bandwidth = min(interface1['interface'].bandwidth, 
#                                       interface2['interface'].bandwidth)
#                         if bandwidth == 0:
#                             bandwidth = max(interface1['interface'].bandwidth, 
#                                           interface2['interface'].bandwidth)
                        
#                         # Create the link
#                         link = Link(
#                             device1=interface1['device'],
#                             interface1=interface1['interface'].name,
#                             device2=interface2['device'],
#                             interface2=interface2['interface'].name,
#                             bandwidth=bandwidth,
#                             latency=self._estimate_latency(interface1['interface'], interface2['interface']),
#                             link_type=self._determine_link_type(interface1['interface'], interface2['interface']),
#                             status="up"
#                         )
                        
#                         self.topology.add_link(link)
    
#     def _estimate_latency(self, interface1: NetworkInterface, interface2: NetworkInterface) -> float:
#         """
#         Estimate latency between two interfaces based on their types and bandwidth.
        
#         Args:
#             interface1: First interface
#             interface2: Second interface
            
#         Returns:
#             Estimated latency in milliseconds
#         """
#         # Simple latency estimation based on interface types
#         base_latency = 1.0  # 1ms base
        
#         if interface1.interface_type == InterfaceType.SERIAL or interface2.interface_type == InterfaceType.SERIAL:
#             base_latency = 10.0  # Higher latency for serial connections
        
#         # Add latency based on bandwidth (lower bandwidth = higher latency)
#         min_bandwidth = min(interface1.bandwidth, interface2.bandwidth)
#         if min_bandwidth > 0 and min_bandwidth < 100:  # Less than 100 Mbps
#             base_latency += 5.0
        
#         return base_latency
    
#     def _determine_link_type(self, interface1: NetworkInterface, interface2: NetworkInterface) -> str:
#         """
#         Determine the link type based on the interface types.
        
#         Args:
#             interface1: First interface
#             interface2: Second interface
            
#         Returns:
#             Link type string
#         """
#         if interface1.interface_type == InterfaceType.SERIAL or interface2.interface_type == InterfaceType.SERIAL:
#             return "serial"
#         elif interface1.interface_type == InterfaceType.ETHERNET and interface2.interface_type == InterfaceType.ETHERNET:
#             return "ethernet"
#         else:
#             return "mixed"
    
#     def add_manual_link(self, device1_name: str, interface1_name: str, 
#                        device2_name: str, interface2_name: str,
#                        bandwidth: int = 0, latency: float = 1.0) -> bool:
#         """
#         Manually add a link between two specific interfaces.
        
#         Args:
#             device1_name: Name of first device
#             interface1_name: Name of first interface
#             device2_name: Name of second device
#             interface2_name: Name of second interface
#             bandwidth: Link bandwidth in Mbps
#             latency: Link latency in ms
            
#         Returns:
#             True if link was created successfully, False otherwise
#         """
#         device1 = self.topology.get_device(device1_name)
#         device2 = self.topology.get_device(device2_name)
        
#         if not device1 or not device2:
#             logger.error(f"Could not find devices: {device1_name}, {device2_name}")
#             return False
        
#         interface1 = device1.get_interface(interface1_name)
#         interface2 = device2.get_interface(interface2_name)
        
#         if not interface1 or not interface2:
#             logger.error(f"Could not find interfaces: {interface1_name}, {interface2_name}")
#             return False
        
#         link = Link(
#             device1=device1,
#             interface1=interface1_name,
#             device2=device2,
#             interface2=interface2_name,
#             bandwidth=bandwidth or max(interface1.bandwidth, interface2.bandwidth),
#             latency=latency,
#             status="up"
#         )
        
#         self.topology.add_link(link)
#         return True
    
#     def get_topology_statistics(self) -> Dict[str, Any]:
#         """Get statistics about the generated topology."""
#         routers = self.topology.get_routers()
#         switches = self.topology.get_switches()
#         active_links = self.topology.get_active_links()
        
#         total_interfaces = sum(len(device.interfaces) for device in self.topology.devices.values())
#         active_interfaces = sum(len(device.get_active_interfaces()) for device in self.topology.devices.values())
        
#         return {
#             'devices': {
#                 'total': len(self.topology.devices),
#                 'routers': len(routers),
#                 'switches': len(switches)
#             },
#             'interfaces': {
#                 'total': total_interfaces,
#                 'active': active_interfaces
#             },
#             'links': {
#                 'total': len(self.topology.links),
#                 'active': len(active_links)
#             },
#             'vlans': {
#                 'total': sum(len(device.vlans) for device in self.topology.devices.values())
#             },
#             'routing_protocols': {
#                 'total': sum(len(device.routing_protocols) for device in routers)
#             }
#         }


"""
Topology Generator for Network Simulator.
Creates a network topology from device configurations.
"""

import logging
import networkx as nx
import matplotlib.pyplot as plt
import io
from typing import Dict, List, Set, Tuple, Optional, Any
from ipaddress import IPv4Network, IPv4Address

from src.core.config_parser import DeviceConfiguration

logger = logging.getLogger(__name__)

class TopologyGenerator:
    """
    Generates network topology from device configurations.
    Provides methods for topology discovery and visualization.
    """
    
    def __init__(self):
        self.graph = nx.Graph()
        self.devices = {}
        self.links = []
        
    def generate_topology(self, device_configs: Dict[str, DeviceConfiguration]) -> nx.Graph:
        """
        Generate network topology from device configurations.
        
        Args:
            device_configs: Dictionary of device configurations
            
        Returns:
            NetworkX graph representing the network topology
        """
        self.devices = device_configs
        self.graph = nx.Graph()
        
        # Add nodes to the graph
        for device_name, config in device_configs.items():
            # Add node with device attributes
            self.graph.add_node(device_name, 
                                type=config.device_type,
                                hostname=config.hostname or device_name)
            
            logger.debug(f"Added device to topology: {device_name} ({config.device_type})")
        
        # Discover links between devices based on IP addressing
        self._discover_links_by_ip()
        
        # Discover links based on interface descriptions
        self._discover_links_by_description()
        
        # Discover VLAN-based connectivity
        self._discover_links_by_vlan()
        
        logger.info(f"Generated topology with {self.graph.number_of_nodes()} devices and {self.graph.number_of_edges()} links")
        
        return self.graph
    
    def _discover_links_by_ip(self) -> None:
        """Discover links between devices based on IP addressing."""
        # Create a mapping of networks to devices
        networks = {}  # network -> [(device, interface), ...]
        
        for device_name, config in self.devices.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address and intf.subnet_mask:
                    try:
                        # Create network address
                        network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                        network_str = str(network)
                        
                        if network_str not in networks:
                            networks[network_str] = []
                            
                        networks[network_str].append((device_name, intf_name))
                    except Exception as e:
                        logger.warning(f"Invalid IP address or mask for {device_name}.{intf_name}: {e}")
        
        # Devices on the same network are connected
        for network, devices in networks.items():
            if len(devices) > 1:
                # Create a fully connected graph for devices on this network
                for i in range(len(devices)):
                    for j in range(i+1, len(devices)):
                        dev1, intf1 = devices[i]
                        dev2, intf2 = devices[j]
                        
                        # Add the edge if it doesn't already exist
                        if not self.graph.has_edge(dev1, dev2):
                            self.graph.add_edge(dev1, dev2, 
                                              interfaces={dev1: intf1, dev2: intf2},
                                              network=network)
                            logger.debug(f"Discovered link by IP: {dev1}.{intf1} <-> {dev2}.{intf2} via {network}")
                            
                            # Add to links list
                            self.links.append({
                                'source': dev1,
                                'target': dev2,
                                'source_interface': intf1,
                                'target_interface': intf2,
                                'network': network
                            })
    
    def _discover_links_by_description(self) -> None:
        """Discover links based on interface descriptions."""
        # Map of device name patterns to actual device names
        device_name_map = {}
        for device_name, config in self.devices.items():
            # Add various forms of the device name to the map
            device_name_map[device_name.lower()] = device_name
            if config.hostname:
                device_name_map[config.hostname.lower()] = device_name
        
        # Check interface descriptions for connections
        for device_name, config in self.devices.items():
            for intf_name, intf in config.interfaces.items():
                if intf.description:
                    desc = intf.description.lower()
                    
                    # Look for patterns like "Connected to DeviceX" or "Link to DeviceY"
                    connection_patterns = [
                        r'(?:connected to|connection to|link to|to)\s+([a-z0-9_-]+)',
                        r'([a-z0-9_-]+)(?:\s+interface|\s+port|\s+intf|\s+if)'
                    ]
                    
                    # Check each pattern
                    for pattern in connection_patterns:
                        import re
                        match = re.search(pattern, desc)
                        if match:
                            remote_device_pattern = match.group(1)
                            
                            # Find the actual device name
                            remote_device = None
                            for pattern_name, actual_name in device_name_map.items():
                                if remote_device_pattern in pattern_name:
                                    remote_device = actual_name
                                    break
                            
                            if remote_device and remote_device != device_name:
                                # Add the edge if it doesn't already exist
                                if not self.graph.has_edge(device_name, remote_device):
                                    # Look for the corresponding interface on remote device
                                    remote_intf = None
                                    remote_config = self.devices.get(remote_device)
                                    if remote_config:
                                        for r_intf_name, r_intf in remote_config.interfaces.items():
                                            if r_intf.description and device_name.lower() in r_intf.description.lower():
                                                remote_intf = r_intf_name
                                                break
                                    
                                    self.graph.add_edge(
                                        device_name, 
                                        remote_device,
                                        interfaces={
                                            device_name: intf_name, 
                                            remote_device: remote_intf
                                        },
                                        discovered_by="description"
                                    )
                                    logger.debug(f"Discovered link by description: {device_name}.{intf_name} <-> {remote_device}.{remote_intf}")
                                    
                                    # Add to links list
                                    self.links.append({
                                        'source': device_name,
                                        'target': remote_device,
                                        'source_interface': intf_name,
                                        'target_interface': remote_intf,
                                        'discovered_by': 'description'
                                    })
    
    def _discover_links_by_vlan(self) -> None:
        """Discover links between switches based on VLAN trunking."""
        # Find switches with matching trunk VLANs
        trunk_interfaces = {}  # (switch, vlan) -> interface_name
        
        for device_name, config in self.devices.items():
            if config.device_type == "switch":
                for intf_name, intf in config.interfaces.items():
                    if intf.switchport_mode == "trunk" and intf.trunk_vlans:
                        for vlan_id in intf.trunk_vlans:
                            key = (device_name, vlan_id)
                            if key not in trunk_interfaces:
                                trunk_interfaces[key] = []
                            trunk_interfaces[key].append(intf_name)
        
        # Group switches by VLANs they share on trunk ports
        vlan_to_switches = {}  # vlan_id -> [(switch, interface), ...]
        for (device, vlan), interfaces in trunk_interfaces.items():
            if vlan not in vlan_to_switches:
                vlan_to_switches[vlan] = []
            for interface in interfaces:
                vlan_to_switches[vlan].append((device, interface))
        
        # Create links between switches with common trunked VLANs
        for vlan, switch_interfaces in vlan_to_switches.items():
            if len(switch_interfaces) > 1:
                for i in range(len(switch_interfaces)):
                    for j in range(i+1, len(switch_interfaces)):
                        dev1, intf1 = switch_interfaces[i]
                        dev2, intf2 = switch_interfaces[j]
                        
                        # Check if already connected by other means
                        if not self.graph.has_edge(dev1, dev2):
                            self.graph.add_edge(
                                dev1, 
                                dev2,
                                interfaces={dev1: intf1, dev2: intf2},
                                vlan=vlan,
                                discovered_by="vlan_trunk"
                            )
                            logger.debug(f"Discovered link by VLAN trunk: {dev1}.{intf1} <-> {dev2}.{intf2} via VLAN {vlan}")
                            
                            # Add to links list
                            self.links.append({
                                'source': dev1,
                                'target': dev2,
                                'source_interface': intf1,
                                'target_interface': intf2,
                                'vlan': vlan,
                                'discovered_by': 'vlan_trunk'
                            })
    
    def detect_missing_devices(self) -> List[Dict[str, Any]]:
        """
        Detect potentially missing devices in the topology based on 
        network segments and disconnected interfaces.
        
        Returns:
            List of potential missing devices with their likely connections
        """
        missing_devices = []
        
        # Check for large networks with many hosts that might indicate a missing switch
        networks = {}  # network -> [(device, interface), ...]
        
        for device_name, config in self.devices.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address and intf.subnet_mask:
                    try:
                        network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                        network_str = str(network)
                        
                        if network_str not in networks:
                            networks[network_str] = []
                            
                        networks[network_str].append((device_name, intf_name))
                    except Exception:
                        pass
        
        # If a network has only one device but has a large subnet, it may indicate missing devices
        for network_str, devices in networks.items():
            network = IPv4Network(network_str)
            
            # If this is a large network with few devices, might be missing switches or routers
            if len(devices) <= 2 and network.num_addresses > 4:
                missing_devices.append({
                    'type': 'potential_switch',
                    'network': network_str,
                    'connected_devices': [d[0] for d in devices],
                    'reason': f"Large network ({network.num_addresses} addresses) with only {len(devices)} devices"
                })
        
        return missing_devices
    
    def visualize_topology(self, output_path: Optional[str] = None) -> Optional[bytes]:
        """
        Generate a visual representation of the network topology.
        
        Args:
            output_path: Path to save the visualization image (optional)
            
        Returns:
            PNG image bytes if output_path is None, otherwise None
        """
        if not self.graph.nodes():
            logger.warning("No topology to visualize")
            return None
        
        plt.figure(figsize=(12, 8))
        
        # Position nodes using the spring layout
        pos = nx.spring_layout(self.graph)
        
        # Assign colors based on device type
        color_map = {'router': 'red', 'switch': 'green', 'unknown': 'gray'}
        
        # Draw nodes with different colors by device type
        for device_type in ['router', 'switch', 'unknown']:
            nodes = [n for n, attrs in self.graph.nodes(data=True) if attrs.get('type', 'unknown') == device_type]
            if nodes:
                nx.draw_networkx_nodes(
                    self.graph, 
                    pos, 
                    nodelist=nodes,
                    node_color=color_map.get(device_type, 'gray'),
                    node_size=500,
                    alpha=0.8
                )
        
        # Draw edges
        nx.draw_networkx_edges(self.graph, pos, width=1.5, alpha=0.7)
        
        # Add node labels (device names)
        labels = {node: attrs.get('hostname', node) for node, attrs in self.graph.nodes(data=True)}
        nx.draw_networkx_labels(self.graph, pos, labels=labels, font_size=10)
        
        plt.title("Network Topology", fontsize=16)
        plt.axis('off')
        
        # Either save the figure to file or return as bytes
        if output_path:
            plt.savefig(output_path, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            logger.info(f"Topology visualization saved to {output_path}")
            return None
        else:
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            return buf.getvalue()