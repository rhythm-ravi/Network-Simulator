# #!/usr/bin/env python3
# """
# Network Validator for Network Simulator

# This module provides validation functionality for network configurations
# and topologies, checking for common configuration errors and inconsistencies.
# """

# import logging
# from typing import Dict, List, Any, Set, Tuple, Optional
# from ipaddress import IPv4Network, IPv4Address, AddressValueError
# import re

# from models.network_models import NetworkTopology, NetworkDevice, NetworkInterface, Router, Switch


# logger = logging.getLogger(__name__)


# class NetworkValidator:
#     """Validates network configurations and topologies."""
    
#     def __init__(self):
#         """Initialize the network validator."""
#         self.validation_rules = {
#             'ip_addresses': self._validate_ip_addresses,
#             'subnets': self._validate_subnets,
#             'interfaces': self._validate_interfaces,
#             'vlans': self._validate_vlans,
#             'routing': self._validate_routing,
#             'connectivity': self._validate_connectivity,
#             'device_config': self._validate_device_config
#         }
    
#     def validate_topology(self, topology: NetworkTopology, 
#                          rules: Optional[List[str]] = None) -> Tuple[bool, Dict[str, List[str]]]:
#         """
#         Validate a complete network topology.
        
#         Args:
#             topology: NetworkTopology to validate
#             rules: List of specific validation rules to apply (None for all)
            
#         Returns:
#             Tuple of (is_valid, dict_of_errors_by_category)
#         """
#         logger.info(f"Validating topology: {topology.name}")
        
#         validation_errors = {}
#         rules_to_check = rules or list(self.validation_rules.keys())
        
#         for rule_name in rules_to_check:
#             if rule_name in self.validation_rules:
#                 try:
#                     errors = self.validation_rules[rule_name](topology)
#                     if errors:
#                         validation_errors[rule_name] = errors
#                 except Exception as e:
#                     logger.error(f"Error during {rule_name} validation: {e}")
#                     validation_errors[rule_name] = [f"Validation error: {str(e)}"]
        
#         is_valid = len(validation_errors) == 0
        
#         if is_valid:
#             logger.info("Topology validation passed")
#         else:
#             logger.warning(f"Topology validation failed with {sum(len(errs) for errs in validation_errors.values())} errors")
        
#         return is_valid, validation_errors
    
#     def validate_configurations(self, configurations: List[Dict[str, Any]]) -> Tuple[bool, List[Dict[str, Any]]]:
#         """
#         Validate a list of device configurations before topology generation.
        
#         Args:
#             configurations: List of device configuration dictionaries
            
#         Returns:
#             Tuple of (is_valid, list_of_validation_results)
#         """
#         logger.info(f"Validating {len(configurations)} device configurations")
        
#         validation_results = []
#         all_valid = True
        
#         for i, config in enumerate(configurations):
#             result = self._validate_single_config(config, i)
#             validation_results.append(result)
#             if not result['valid']:
#                 all_valid = False
        
#         return all_valid, validation_results
    
#     def _validate_single_config(self, config: Dict[str, Any], index: int) -> Dict[str, Any]:
#         """Validate a single device configuration."""
#         errors = []
#         warnings = []
#         device_name = config.get('device', {}).get('name', f'device_{index}')
        
#         # Check required fields
#         if 'device' not in config:
#             errors.append("Missing 'device' section")
#         else:
#             device_info = config['device']
#             if not device_info.get('name'):
#                 errors.append("Device name is required")
#             if not device_info.get('type'):
#                 errors.append("Device type is required")
        
#         # Validate interfaces
#         if 'interfaces' in config:
#             interface_errors = self._validate_config_interfaces(config['interfaces'])
#             errors.extend(interface_errors)
        
#         # Validate VLANs
#         if 'vlans' in config:
#             vlan_errors = self._validate_config_vlans(config['vlans'])
#             errors.extend(vlan_errors)
        
#         # Check for device-specific requirements
#         device_type = config.get('device', {}).get('type', '').lower()
#         if device_type == 'router' and 'routing' in config:
#             routing_errors = self._validate_config_routing(config['routing'])
#             errors.extend(routing_errors)
        
#         return {
#             'device_name': device_name,
#             'valid': len(errors) == 0,
#             'errors': errors,
#             'warnings': warnings
#         }
    
#     def _validate_ip_addresses(self, topology: NetworkTopology) -> List[str]:
#         """Validate IP address configurations for duplicates and conflicts."""
#         errors = []
#         ip_usage = {}  # Maps IP addresses to (device, interface) tuples
        
#         for device in topology.devices.values():
#             for interface in device.interfaces.values():
#                 if interface.ip_address:
#                     ip = interface.ip_address
                    
#                     # Check for valid IP format
#                     try:
#                         IPv4Address(ip)
#                     except AddressValueError:
#                         errors.append(f"Invalid IP address format: {ip} on {device.name}:{interface.name}")
#                         continue
                    
#                     # Check for duplicate IP addresses
#                     if ip in ip_usage:
#                         prev_device, prev_interface = ip_usage[ip]
#                         errors.append(f"Duplicate IP address {ip} found on "
#                                     f"{device.name}:{interface.name} and "
#                                     f"{prev_device}:{prev_interface}")
#                     else:
#                         ip_usage[ip] = (device.name, interface.name)
        
#         return errors
    
#     def _validate_subnets(self, topology: NetworkTopology) -> List[str]:
#         """Validate subnet configurations and overlaps."""
#         errors = []
#         networks = []  # List of (network, device, interface) tuples
        
#         for device in topology.devices.values():
#             for interface in device.interfaces.values():
#                 if interface.ip_address and interface.subnet_mask:
#                     try:
#                         network = IPv4Network(f"{interface.ip_address}/{interface.subnet_mask}", strict=False)
#                         networks.append((network, device.name, interface.name))
#                     except (AddressValueError, ValueError) as e:
#                         errors.append(f"Invalid subnet configuration on {device.name}:{interface.name}: {e}")
        
#         # Check for overlapping subnets (excluding exact matches which are expected for point-to-point links)
#         for i, (net1, dev1, int1) in enumerate(networks):
#             for net2, dev2, int2 in networks[i+1:]:
#                 if net1 != net2 and (net1.overlaps(net2)):
#                     errors.append(f"Overlapping subnets: {net1} ({dev1}:{int1}) and {net2} ({dev2}:{int2})")
        
#         return errors
    
#     def _validate_interfaces(self, topology: NetworkTopology) -> List[str]:
#         """Validate interface configurations."""
#         errors = []
        
#         for device in topology.devices.values():
#             interface_names = set()
            
#             for interface in device.interfaces.values():
#                 # Check for duplicate interface names
#                 if interface.name in interface_names:
#                     errors.append(f"Duplicate interface name {interface.name} on device {device.name}")
#                 else:
#                     interface_names.add(interface.name)
                
#                 # Validate interface naming conventions
#                 if not self._validate_interface_name(interface.name):
#                     errors.append(f"Invalid interface name format: {interface.name} on {device.name}")
                
#                 # Check bandwidth values
#                 if interface.bandwidth < 0:
#                     errors.append(f"Invalid bandwidth {interface.bandwidth} on {device.name}:{interface.name}")
                
#                 # Validate VLAN configurations on switches
#                 if isinstance(device, Switch):
#                     if interface.access_vlan and interface.trunk_vlans:
#                         errors.append(f"Interface {device.name}:{interface.name} cannot be both access and trunk")
                    
#                     if interface.access_vlan and interface.access_vlan not in device.vlans:
#                         errors.append(f"Access VLAN {interface.access_vlan} not configured on switch {device.name}")
        
#         return errors
    
#     def _validate_vlans(self, topology: NetworkTopology) -> List[str]:
#         """Validate VLAN configurations."""
#         errors = []
        
#         for device in topology.devices.values():
#             if isinstance(device, Switch):
#                 vlan_ids = set()
                
#                 for vlan in device.vlans.values():
#                     # Check for duplicate VLAN IDs
#                     if vlan.vlan_id in vlan_ids:
#                         errors.append(f"Duplicate VLAN ID {vlan.vlan_id} on switch {device.name}")
#                     else:
#                         vlan_ids.add(vlan.vlan_id)
                    
#                     # Validate VLAN ID range
#                     if not (1 <= vlan.vlan_id <= 4094):
#                         errors.append(f"Invalid VLAN ID {vlan.vlan_id} on switch {device.name} (must be 1-4094)")
        
#         return errors
    
#     def _validate_routing(self, topology: NetworkTopology) -> List[str]:
#         """Validate routing protocol configurations."""
#         errors = []
        
#         routers = topology.get_routers()
        
#         for router in routers:
#             protocol_types = set()
            
#             for protocol in router.routing_protocols:
#                 # Check for multiple instances of the same protocol type
#                 if protocol.protocol_type in protocol_types:
#                     if protocol.protocol_type == 'ospf' and protocol.process_id:
#                         # OSPF can have multiple processes
#                         continue
#                     errors.append(f"Multiple {protocol.protocol_type} processes on router {router.name}")
#                 else:
#                     protocol_types.add(protocol.protocol_type)
                
#                 # Validate OSPF-specific configuration
#                 if protocol.protocol_type == 'ospf':
#                     if not protocol.process_id:
#                         errors.append(f"OSPF process ID missing on router {router.name}")
                    
#                     for network in protocol.networks:
#                         if 'area' not in network:
#                             errors.append(f"OSPF area missing for network on router {router.name}")
        
#         return errors
    
#     def _validate_connectivity(self, topology: NetworkTopology) -> List[str]:
#         """Validate network connectivity and link consistency."""
#         errors = []
        
#         # Check for isolated devices (no active links)
#         for device in topology.devices.values():
#             connections = topology.get_device_connections(device.name)
#             active_connections = [link for link in connections if link.is_active]
            
#             if not active_connections and len(topology.devices) > 1:
#                 errors.append(f"Device {device.name} has no active connections")
        
#         # Validate link consistency
#         for link in topology.links:
#             # Check if both devices exist
#             if link.device1.name not in topology.devices:
#                 errors.append(f"Link references non-existent device: {link.device1.name}")
#             if link.device2.name not in topology.devices:
#                 errors.append(f"Link references non-existent device: {link.device2.name}")
            
#             # Check if interfaces exist
#             if not link.device1.get_interface(link.interface1):
#                 errors.append(f"Link references non-existent interface: {link.device1.name}:{link.interface1}")
#             if not link.device2.get_interface(link.interface2):
#                 errors.append(f"Link references non-existent interface: {link.device2.name}:{link.interface2}")
        
#         return errors
    
#     def _validate_device_config(self, topology: NetworkTopology) -> List[str]:
#         """Validate general device configurations."""
#         errors = []
        
#         device_names = set()
        
#         for device in topology.devices.values():
#             # Check for duplicate device names
#             if device.name in device_names:
#                 errors.append(f"Duplicate device name: {device.name}")
#             else:
#                 device_names.add(device.name)
            
#             # Validate device name format
#             if not re.match(r'^[a-zA-Z0-9_-]+$', device.name):
#                 errors.append(f"Invalid device name format: {device.name}")
            
#             # Check for missing required interfaces
#             if not device.interfaces:
#                 errors.append(f"Device {device.name} has no interfaces configured")
        
#         return errors
    
#     def _validate_config_interfaces(self, interfaces: List[Dict[str, Any]]) -> List[str]:
#         """Validate interfaces in a configuration dictionary."""
#         errors = []
#         interface_names = set()
        
#         for interface in interfaces:
#             name = interface.get('name', '')
            
#             if not name:
#                 errors.append("Interface missing name")
#                 continue
            
#             if name in interface_names:
#                 errors.append(f"Duplicate interface name: {name}")
#             else:
#                 interface_names.add(name)
            
#             # Validate IP configuration
#             ip_addr = interface.get('ip_address')
#             subnet_mask = interface.get('subnet_mask')
            
#             if ip_addr and not subnet_mask:
#                 errors.append(f"Interface {name}: IP address without subnet mask")
#             elif ip_addr:
#                 try:
#                     IPv4Network(f"{ip_addr}/{subnet_mask}", strict=False)
#                 except (AddressValueError, ValueError):
#                     errors.append(f"Interface {name}: Invalid IP/subnet configuration")
        
#         return errors
    
#     def _validate_config_vlans(self, vlans: List[Dict[str, Any]]) -> List[str]:
#         """Validate VLANs in a configuration dictionary."""
#         errors = []
#         vlan_ids = set()
        
#         for vlan in vlans:
#             vlan_id = vlan.get('id')
            
#             if vlan_id is None:
#                 errors.append("VLAN missing ID")
#                 continue
            
#             if vlan_id in vlan_ids:
#                 errors.append(f"Duplicate VLAN ID: {vlan_id}")
#             else:
#                 vlan_ids.add(vlan_id)
            
#             if not (1 <= vlan_id <= 4094):
#                 errors.append(f"Invalid VLAN ID {vlan_id} (must be 1-4094)")
        
#         return errors
    
#     def _validate_config_routing(self, routing: Dict[str, Any]) -> List[str]:
#         """Validate routing configuration in a configuration dictionary."""
#         errors = []
        
#         protocols = routing.get('protocols', [])
#         protocol_types = set()
        
#         for protocol in protocols:
#             protocol_type = protocol.get('type', '')
            
#             if not protocol_type:
#                 errors.append("Routing protocol missing type")
#                 continue
            
#             if protocol_type in protocol_types and protocol_type != 'ospf':
#                 errors.append(f"Multiple {protocol_type} processes configured")
#             else:
#                 protocol_types.add(protocol_type)
        
#         return errors
    
#     def _validate_interface_name(self, name: str) -> bool:
#         """Validate interface name format."""
#         # Common interface name patterns
#         patterns = [
#             r'^GigabitEthernet\d+/\d+(/\d+)?$',
#             r'^FastEthernet\d+/\d+(/\d+)?$',
#             r'^Ethernet\d+/\d+(/\d+)?$',
#             r'^Serial\d+/\d+(/\d+)?$',
#             r'^Loopback\d+$',
#             r'^Vlan\d+$',
#             r'^Port-channel\d+$'
#         ]
        
#         return any(re.match(pattern, name, re.IGNORECASE) for pattern in patterns)
    
#     def get_validation_summary(self, validation_errors: Dict[str, List[str]]) -> Dict[str, Any]:
#         """Generate a summary of validation results."""
#         total_errors = sum(len(errors) for errors in validation_errors.values())
        
#         return {
#             'total_errors': total_errors,
#             'categories': len(validation_errors),
#             'error_breakdown': {category: len(errors) for category, errors in validation_errors.items()},
#             'is_valid': total_errors == 0
#         }


"""
Network Validator for Network Simulator.
Validates network configurations and identifies issues.
"""

import logging
import itertools
from typing import Dict, List, Set, Tuple, Any, Optional
from ipaddress import IPv4Network, IPv4Address, IPv4Interface, AddressValueError

from src.core.config_parser import DeviceConfiguration

logger = logging.getLogger(__name__)

class NetworkValidator:
    """
    Validates network topology and configuration.
    Identifies common network issues and configuration problems.
    """
    
    def __init__(self):
        self.issues = []
    
    def validate_network(self, device_configs: Dict[str, DeviceConfiguration]) -> List[Dict[str, Any]]:
        """
        Validate the network and identify issues.
        
        Args:
            device_configs: Dictionary of device configurations
            
        Returns:
            List of identified issues with details
        """
        self.issues = []
        
        # Validate individual device configurations
        for device_name, config in device_configs.items():
            self._validate_device(device_name, config, device_configs)
        
        # Validate inter-device connectivity and network-wide issues
        self._validate_ip_connectivity(device_configs)
        self._validate_vlan_consistency(device_configs)
        self._detect_routing_protocol_issues(device_configs)
        self._detect_network_loops(device_configs)
        self._detect_mtu_mismatches(device_configs)
        self._detect_duplicate_ips_in_vlans(device_configs)
        self._validate_gateway_addresses(device_configs)
        
        # Sort issues by severity
        self.issues.sort(key=lambda x: {'critical': 0, 'warning': 1, 'info': 2}.get(x.get('severity'), 3))
        
        return self.issues
    
    def _validate_device(self, device_name: str, config: DeviceConfiguration, 
                        all_configs: Dict[str, DeviceConfiguration]) -> None:
        """
        Validate a single device configuration.
        
        Args:
            device_name: Name of the device
            config: Device configuration
            all_configs: Dictionary of all device configurations
        """
        # Validate interfaces
        self._validate_interfaces(device_name, config)
        
        # Validate VLANs
        self._validate_vlans(device_name, config)
        
        # Validate routing
        self._validate_routing(device_name, config, all_configs)
        
        # Validate ACLs
        self._validate_acls(device_name, config)
    
    def _validate_interfaces(self, device_name: str, config: DeviceConfiguration) -> None:
        """Validate device interfaces."""
        # Check for interfaces with no IP address
        physical_interfaces = [name for name, intf in config.interfaces.items() 
                             if intf.is_physical and not intf.switchport_mode]
        interfaces_with_ip = [name for name, intf in config.interfaces.items() 
                             if intf.ip_address is not None]
        
        if physical_interfaces and not interfaces_with_ip:
            self.issues.append({
                'type': 'missing_ip_address',
                'device': device_name,
                'severity': 'warning',
                'description': f"Device {device_name} has no interfaces with IP addresses"
            })
        
        # Check for MTU inconsistencies across interfaces
        mtu_values = set(intf.mtu for intf in config.interfaces.values() if intf.is_physical)
        if len(mtu_values) > 1:
            self.issues.append({
                'type': 'mtu_inconsistency',
                'device': device_name,
                'severity': 'warning',
                'description': f"Device {device_name} has inconsistent MTU values across interfaces: {mtu_values}"
            })
        
        # Check for interface bandwidth consistency
        bandwidth_values = {}
        for name, intf in config.interfaces.items():
            if intf.bandwidth and intf.is_physical:
                bandwidth_values[name] = intf.bandwidth
        
        if len(bandwidth_values) > 1:
            self.issues.append({
                'type': 'bandwidth_variation',
                'device': device_name,
                'severity': 'info',
                'description': f"Device {device_name} has varying bandwidth across interfaces",
                'details': bandwidth_values
            })
        
        # Check for shutdown interfaces
        shutdown_interfaces = [name for name, intf in config.interfaces.items() 
                             if intf.is_physical and intf.status != "up"]
        
        if shutdown_interfaces:
            self.issues.append({
                'type': 'shutdown_interfaces',
                'device': device_name,
                'severity': 'info',
                'description': f"Device {device_name} has {len(shutdown_interfaces)} shutdown interfaces",
                'interfaces': shutdown_interfaces
            })
    
    def _validate_vlans(self, device_name: str, config: DeviceConfiguration) -> None:
        """Validate VLAN configuration on a device."""
        if config.device_type != "switch":
            return
        
        # Check for VLAN configuration consistency
        configured_vlans = set(config.vlans.keys())
        
        # Get VLANs used in interfaces
        interface_vlans = set()
        for intf in config.interfaces.values():
            if intf.vlan is not None:
                interface_vlans.add(intf.vlan)
            if intf.access_vlan is not None:
                interface_vlans.add(intf.access_vlan)
            if intf.trunk_vlans:
                interface_vlans.update(intf.trunk_vlans)
        
        # Find VLANs used in interfaces but not configured
        unconfigured_vlans = interface_vlans - configured_vlans
        if unconfigured_vlans:
            self.issues.append({
                'type': 'unconfigured_vlan',
                'device': device_name,
                'severity': 'warning',
                'description': f"Device {device_name} uses VLANs that are not configured: {unconfigured_vlans}"
            })
        
        # Check if spanning tree is configured for all VLANs
        if config.spanning_tree_mode:
            missing_stp_vlans = configured_vlans - config.spanning_tree_vlans
            if missing_stp_vlans:
                self.issues.append({
                    'type': 'missing_spanning_tree',
                    'device': device_name,
                    'severity': 'warning',
                    'description': f"Device {device_name} is missing spanning tree configuration for VLANs: {missing_stp_vlans}"
                })
    
    def _validate_routing(self, device_name: str, config: DeviceConfiguration,
                         all_configs: Dict[str, DeviceConfiguration]) -> None:
        """Validate routing configuration."""
        if config.device_type != "router":
            return
        
        # Check if device has any routing protocol configured
        if not config.routing_protocols:
            self.issues.append({
                'type': 'no_routing_protocol',
                'device': device_name,
                'severity': 'warning',
                'description': f"Router {device_name} has no routing protocols configured"
            })
            return
        
        # Check for interfaces without network statements in OSPF
        ospf_protocols = [p for p in config.routing_protocols if p.protocol_type == "ospf"]
        if ospf_protocols:
            # Get networks defined in OSPF
            ospf_networks = set()
            for protocol in ospf_protocols:
                for network_info in protocol.networks:
                    try:
                        # Convert network/wildcard to network object
                        network = IPv4Network(f"{network_info['network']}/{self._wildcard_to_prefix(network_info['wildcard'])}", strict=False)
                        ospf_networks.add(network)
                    except (AddressValueError, ValueError):
                        logger.warning(f"Invalid network in OSPF configuration: {network_info}")
            
            # Check if all interface networks are in OSPF
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address and intf.subnet_mask:
                    try:
                        intf_network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                        
                        # Check if this network is covered by any OSPF network statement
                        if not any(intf_network.subnet_of(network) for network in ospf_networks):
                            self.issues.append({
                                'type': 'interface_not_in_ospf',
                                'device': device_name,
                                'severity': 'warning',
                                'description': f"Interface {intf_name} with network {intf_network} is not included in any OSPF network statement"
                            })
                    except (AddressValueError, ValueError):
                        logger.warning(f"Invalid interface network: {intf.ip_address}/{intf.subnet_mask}")
        
        # Check for BGP configuration issues
        bgp_protocols = [p for p in config.routing_protocols if p.protocol_type == "bgp"]
        if bgp_protocols:
            for protocol in bgp_protocols:
                # Check if BGP router-id is set
                if not protocol.router_id:
                    self.issues.append({
                        'type': 'missing_bgp_router_id',
                        'device': device_name,
                        'severity': 'warning',
                        'description': f"BGP configuration on {device_name} is missing router-id"
                    })
                
                # Check for BGP neighbors without matching configurations
                for neighbor in protocol.neighbors:
                    neighbor_ip = neighbor.get('ip')
                    remote_as = neighbor.get('remote_as')
                    
                    # Find if this neighbor IP belongs to another configured device
                    neighbor_device = None
                    for other_name, other_config in all_configs.items():
                        if other_name != device_name:
                            for other_intf in other_config.interfaces.values():
                                if other_intf.ip_address == neighbor_ip:
                                    neighbor_device = other_name
                                    break
                            if neighbor_device:
                                break
                    
                    # Check if neighbor device is configured
                    if neighbor_device:
                        # Check if neighbor has reciprocal BGP configuration
                        neighbor_bgp = [p for p in all_configs[neighbor_device].routing_protocols 
                                      if p.protocol_type == "bgp"]
                        
                        reciprocal_config_found = False
                        for n_bgp in neighbor_bgp:
                            for n_neighbor in n_bgp.neighbors:
                                # Look for a neighbor statement pointing back to this router
                                matching_intf = False
                                for intf in config.interfaces.values():
                                    if intf.ip_address == n_neighbor.get('ip'):
                                        matching_intf = True
                                        break
                                
                                if matching_intf and n_neighbor.get('remote_as') == protocol.process_id:
                                    reciprocal_config_found = True
                                    break
                        
                        if not reciprocal_config_found:
                            self.issues.append({
                                'type': 'bgp_neighbor_mismatch',
                                'device': device_name,
                                'severity': 'warning',
                                'description': f"BGP neighbor {neighbor_ip} (AS {remote_as}) on {device_name} does not have a reciprocal configuration on {neighbor_device}"
                            })
    
    def _validate_acls(self, device_name: str, config: DeviceConfiguration) -> None:
        """Validate ACL configurations."""
        # Check if ACLs are applied to interfaces
        applied_acls = set()
        for intf_name, intf in config.interfaces.items():
            # Look for ACL application in the interface config via the raw config
            # This is a simple approach; a more robust one would parse interface ACLs directly
            for acl_name in config.acls.keys():
                if f"ip access-group {acl_name}" in config.raw_config:
                    applied_acls.add(acl_name)
        
        # Find ACLs that aren't applied anywhere
        unused_acls = set(config.acls.keys()) - applied_acls
        if unused_acls:
            self.issues.append({
                'type': 'unused_acl',
                'device': device_name,
                'severity': 'info',
                'description': f"Device {device_name} has unused ACLs: {unused_acls}"
            })
    
    def _validate_ip_connectivity(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Validate IP connectivity and addressing across the network."""
        # Check for duplicate IP addresses
        ip_addresses = {}  # ip_address -> [(device, interface), ...]
        
        for device_name, config in device_configs.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address:
                    if intf.ip_address not in ip_addresses:
                        ip_addresses[intf.ip_address] = []
                    ip_addresses[intf.ip_address].append((device_name, intf_name))
        
        # Report duplicate IPs
        for ip, devices in ip_addresses.items():
            if len(devices) > 1:
                self.issues.append({
                    'type': 'duplicate_ip',
                    'severity': 'critical',
                    'description': f"IP address {ip} is configured on multiple interfaces",
                    'affected': [f"{d}.{i}" for d, i in devices]
                })
        
        # Check for inconsistent subnet masks on the same network
        networks = {}  # network_address -> [(device, interface, mask), ...]
        
        for device_name, config in device_configs.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address and intf.subnet_mask:
                    try:
                        # Get the network address
                        interface = IPv4Interface(f"{intf.ip_address}/{intf.subnet_mask}")
                        network_address = str(interface.network.network_address)
                        
                        if network_address not in networks:
                            networks[network_address] = []
                            
                        networks[network_address].append((device_name, intf_name, intf.subnet_mask))
                    except (AddressValueError, ValueError):
                        logger.warning(f"Invalid IP address: {intf.ip_address}/{intf.subnet_mask}")
        
        # Check for inconsistent masks
        for network, interfaces in networks.items():
            masks = {mask for _, _, mask in interfaces}
            if len(masks) > 1:
                self.issues.append({
                    'type': 'inconsistent_subnet_masks',
                    'severity': 'critical',
                    'description': f"Inconsistent subnet masks used on network {network}",
                    'masks': list(masks),
                    'affected': [f"{d}.{i}" for d, i, _ in interfaces]
                })
        
        # Check for incorrect gateway addresses
        for device_name, config in device_configs.items():
            if config.default_gateway:
                gateway_ip = config.default_gateway
                gateway_reachable = False
                
                # Check if gateway IP is on any directly connected network
                for intf_name, intf in config.interfaces.items():
                    if intf.ip_address and intf.subnet_mask:
                        try:
                            interface_network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                            gateway_addr = IPv4Address(gateway_ip)
                            
                            if gateway_addr in interface_network:
                                gateway_reachable = True
                                break
                        except (AddressValueError, ValueError):
                            pass
                
                if not gateway_reachable:
                    # Look for the gateway in other device interfaces
                    for other_name, other_config in device_configs.items():
                        if other_name != device_name:
                            for other_intf in other_config.interfaces.values():
                                if other_intf.ip_address == gateway_ip:
                                    gateway_reachable = True
                                    break
                            if gateway_reachable:
                                break
                
                if not gateway_reachable:
                    self.issues.append({
                        'type': 'unreachable_gateway',
                        'device': device_name,
                        'severity': 'critical',
                        'description': f"Default gateway {gateway_ip} may not be reachable from device {device_name}"
                    })
    
    def _validate_vlan_consistency(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Validate VLAN configuration consistency across the network."""
        # Check VLAN numbering consistency
        vlan_devices = {}  # vlan_id -> [(device, vlan_name), ...]
        
        for device_name, config in device_configs.items():
            if config.device_type == "switch":
                for vlan_id, vlan in config.vlans.items():
                    if vlan_id not in vlan_devices:
                        vlan_devices[vlan_id] = []
                    vlan_devices[vlan_id].append((device_name, vlan.name))
        
        # Check for inconsistent VLAN names
        for vlan_id, devices in vlan_devices.items():
            names = {name for _, name in devices if name is not None}
            if len(names) > 1:
                self.issues.append({
                    'type': 'inconsistent_vlan_names',
                    'severity': 'warning',
                    'description': f"VLAN {vlan_id} has inconsistent names across devices",
                    'names': list(names),
                    'devices': [d for d, _ in devices]
                })
        
        # Check for duplicate VLAN IDs in same network segment
        # (This is a simplification - in a full implementation, we would check trunk connections)
        for device_name, config in device_configs.items():
            if config.device_type == "switch":
                # Check for overlapping access VLAN assignments
                access_interfaces = {}  # vlan_id -> [interface_name, ...]
                
                for intf_name, intf in config.interfaces.items():
                    if intf.switchport_mode == "access" and intf.access_vlan is not None:
                        vlan_id = intf.access_vlan
                        if vlan_id not in access_interfaces:
                            access_interfaces[vlan_id] = []
                        access_interfaces[vlan_id].append(intf_name)
                
                # Check if access VLANs are configured
                for vlan_id, interfaces in access_interfaces.items():
                    if vlan_id not in config.vlans:
                        self.issues.append({
                            'type': 'unconfigured_access_vlan',
                            'device': device_name,
                            'severity': 'warning',
                            'description': f"VLAN {vlan_id} is assigned to access ports but not configured on device {device_name}",
                            'interfaces': interfaces
                        })
    
    def _detect_routing_protocol_issues(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Detect issues with routing protocols and recommend optimizations."""
        # Count routers running different routing protocols
        ospf_routers = []
        bgp_routers = []
        eigrp_routers = []
        
        for device_name, config in device_configs.items():
            if config.device_type != "router":
                continue
                
            for protocol in config.routing_protocols:
                if protocol.protocol_type == "ospf":
                    ospf_routers.append(device_name)
                elif protocol.protocol_type == "bgp":
                    bgp_routers.append(device_name)
                elif protocol.protocol_type == "eigrp":
                    eigrp_routers.append(device_name)
        
        # Check for mixed routing protocols or many OSPF routers that could benefit from BGP
        if len(ospf_routers) > 5:  # If there are many OSPF routers, BGP might scale better
            self.issues.append({
                'type': 'consider_bgp',
                'severity': 'info',
                'description': f"Consider using BGP instead of OSPF for better scalability with {len(ospf_routers)} routers",
                'ospf_routers': ospf_routers
            })
        elif len(ospf_routers) > 0 and len(bgp_routers) > 0:
            # When both protocols are present, check for potential optimization
            self.issues.append({
                'type': 'mixed_routing_protocols',
                'severity': 'info',
                'description': f"Mixed routing protocols detected: {len(ospf_routers)} OSPF and {len(bgp_routers)} BGP routers",
                'ospf_routers': ospf_routers,
                'bgp_routers': bgp_routers
            })
        
        # Check for potential protocol redistribution issues
        redistribution_devices = []
        for device_name, config in device_configs.items():
            if config.device_type != "router":
                continue
                
            has_redistribution = False
            for protocol in config.routing_protocols:
                if protocol.redistributed:
                    has_redistribution = True
                    break
                    
            if has_redistribution:
                redistribution_devices.append(device_name)
        
        if redistribution_devices:
            self.issues.append({
                'type': 'routing_redistribution',
                'severity': 'info',
                'description': f"{len(redistribution_devices)} devices are performing routing protocol redistribution, which may cause routing loops or suboptimal paths if not configured carefully",
                'devices': redistribution_devices
            })
    
    def _detect_network_loops(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """
        Detect potential network loops based on topology analysis.
        Note: This is a simplified analysis. A production implementation would use
        algorithms like spanning tree protocol simulation.
        """
        # Simplified check for STP configuration on switches
        switches_without_stp = []
        for device_name, config in device_configs.items():
            if config.device_type == "switch" and not config.spanning_tree_mode:
                switches_without_stp.append(device_name)
        
        if switches_without_stp:
            self.issues.append({
                'type': 'missing_spanning_tree',
                'severity': 'critical',
                'description': f"{len(switches_without_stp)} switches do not have spanning-tree configured, which may lead to network loops",
                'devices': switches_without_stp
            })
    
    def _wildcard_to_prefix(self, wildcard: str) -> int:
        """Convert a wildcard mask to prefix length."""
        # Convert wildcard bits to netmask bits
        try:
            wildcard_bits = IPv4Address(wildcard)
            netmask_bits = IPv4Address(int(0xFFFFFFFF - int(wildcard_bits)))
            
            # Count the number of consecutive 1's from the left
            netmask_str = format(int(netmask_bits), '032b')
            return netmask_str.count('1')
        except Exception:
            return 0
    
    def _detect_mtu_mismatches(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Detect MTU mismatches between connected interfaces."""
        # Build a map of networks to interfaces
        network_interfaces = {}
        
        for device_name, config in device_configs.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address and intf.subnet_mask:
                    try:
                        network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                        network_key = str(network.network_address) + "/" + str(network.prefixlen)
                        
                        if network_key not in network_interfaces:
                            network_interfaces[network_key] = []
                        
                        network_interfaces[network_key].append({
                            'device': device_name,
                            'interface': intf_name,
                            'mtu': intf.mtu,
                            'ip': intf.ip_address
                        })
                    except (AddressValueError, ValueError):
                        continue
        
        # Check for MTU mismatches within each network
        for network, interfaces in network_interfaces.items():
            if len(interfaces) > 1:
                mtus = [intf['mtu'] for intf in interfaces]
                unique_mtus = set(mtus)
                
                if len(unique_mtus) > 1:
                    self.issues.append({
                        'type': 'mtu_mismatch',
                        'severity': 'warning',
                        'description': f"MTU mismatch detected in network {network}. MTU values: {sorted(unique_mtus)}",
                        'network': network,
                        'interfaces': [f"{intf['device']}:{intf['interface']} (MTU {intf['mtu']})" for intf in interfaces]
                    })
    
    def _detect_duplicate_ips_in_vlans(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Detect duplicate IP addresses within the same VLAN."""
        vlan_ips = {}  # vlan_id -> {ip -> [(device, interface)]}
        
        # Collect all IP addresses per VLAN
        for device_name, config in device_configs.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address:
                    # Determine VLAN for this interface
                    vlan_id = None
                    
                    if intf.vlan:
                        vlan_id = intf.vlan
                    elif intf.access_vlan:
                        vlan_id = intf.access_vlan
                    elif config.device_type == "switch":
                        # For switch SVIs (VLAN interfaces)
                        if intf_name.startswith("Vlan"):
                            try:
                                vlan_id = int(intf_name[4:])
                            except ValueError:
                                pass
                    
                    if vlan_id is None:
                        vlan_id = 1  # Default VLAN
                    
                    if vlan_id not in vlan_ips:
                        vlan_ips[vlan_id] = {}
                    
                    if intf.ip_address not in vlan_ips[vlan_id]:
                        vlan_ips[vlan_id][intf.ip_address] = []
                    
                    vlan_ips[vlan_id][intf.ip_address].append((device_name, intf_name))
        
        # Check for duplicates
        for vlan_id, ip_map in vlan_ips.items():
            for ip, locations in ip_map.items():
                if len(locations) > 1:
                    self.issues.append({
                        'type': 'duplicate_ip_in_vlan',
                        'severity': 'critical',
                        'description': f"Duplicate IP address {ip} found in VLAN {vlan_id}",
                        'ip_address': ip,
                        'vlan_id': vlan_id,
                        'locations': [f"{dev}:{intf}" for dev, intf in locations]
                    })
    
    def _validate_gateway_addresses(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Validate that gateway addresses are reachable and correctly configured."""
        # Collect all configured IP networks
        networks = {}  # network_str -> [(device, interface, ip)]
        
        for device_name, config in device_configs.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address and intf.subnet_mask:
                    try:
                        network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                        network_key = str(network)
                        
                        if network_key not in networks:
                            networks[network_key] = []
                        
                        networks[network_key].append((device_name, intf_name, intf.ip_address))
                    except (AddressValueError, ValueError):
                        continue
        
        # Check default gateways
        for device_name, config in device_configs.items():
            if config.default_gateway:
                try:
                    gateway_ip = IPv4Address(config.default_gateway)
                    gateway_reachable = False
                    
                    # Check if gateway is in any of the device's networks
                    for intf_name, intf in config.interfaces.items():
                        if intf.ip_address and intf.subnet_mask:
                            try:
                                network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                                if gateway_ip in network:
                                    gateway_reachable = True
                                    break
                            except (AddressValueError, ValueError):
                                continue
                    
                    if not gateway_reachable:
                        self.issues.append({
                            'type': 'unreachable_gateway',
                            'severity': 'warning',
                            'description': f"Default gateway {config.default_gateway} on device {device_name} is not reachable from any configured interface",
                            'device': device_name,
                            'gateway': config.default_gateway
                        })
                        
                except AddressValueError:
                    self.issues.append({
                        'type': 'invalid_gateway_address',
                        'severity': 'critical',
                        'description': f"Invalid gateway address {config.default_gateway} on device {device_name}",
                        'device': device_name,
                        'gateway': config.default_gateway
                    })
        
        # Check for gateway conflicts (multiple devices claiming to be gateway for same network)
        gateway_networks = {}  # network -> [(device, gateway_ip)]
        
        for device_name, config in device_configs.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address and intf.subnet_mask:
                    try:
                        network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                        network_key = str(network)
                        
                        # Check if this looks like a gateway IP (first or last usable IP)
                        ip_addr = IPv4Address(intf.ip_address)
                        first_usable = network.network_address + 1
                        last_usable = network.broadcast_address - 1
                        
                        if ip_addr == first_usable or ip_addr == last_usable:
                            if network_key not in gateway_networks:
                                gateway_networks[network_key] = []
                            gateway_networks[network_key].append((device_name, intf.ip_address))
                    except (AddressValueError, ValueError):
                        continue
        
        # Report potential gateway conflicts
        for network, gateways in gateway_networks.items():
            if len(gateways) > 1:
                self.issues.append({
                    'type': 'multiple_gateways',
                    'severity': 'warning',
                    'description': f"Multiple potential gateways detected in network {network}",
                    'network': network,
                    'gateways': [f"{dev} ({ip})" for dev, ip in gateways]
                })