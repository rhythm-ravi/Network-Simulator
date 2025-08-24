"""
Configuration Parser for Network Simulator.
Parses router and switch configuration files to extract network topology information.
"""

import os
import re
import logging
import yaml
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class Interface:
    """Interface configuration extracted from a device."""
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    vlan: Optional[int] = None
    status: str = "up"  # up, down, administratively down
    bandwidth: Optional[str] = None
    mtu: int = 1500
    duplex: str = "auto"
    speed: str = "auto"
    encapsulation: Optional[str] = None
    switchport_mode: Optional[str] = None
    access_vlan: Optional[int] = None
    trunk_vlans: List[int] = field(default_factory=list)
    is_physical: bool = True
    channel_group: Optional[int] = None
    

@dataclass
class RoutingProtocol:
    """Routing protocol configuration."""
    protocol_type: str  # ospf, eigrp, bgp, static, etc.
    process_id: Optional[str] = None
    router_id: Optional[str] = None
    networks: List[Dict[str, str]] = field(default_factory=list)
    neighbors: List[Dict[str, str]] = field(default_factory=list)
    redistributed: List[str] = field(default_factory=list)
    passive_interfaces: List[str] = field(default_factory=list)
    

@dataclass
class VLANConfig:
    """VLAN configuration information."""
    vlan_id: int
    name: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    

@dataclass
class DeviceConfiguration:
    """Complete device configuration extracted from config file."""
    name: str
    device_type: str  # router, switch, etc.
    interfaces: Dict[str, Interface] = field(default_factory=dict)
    routing_protocols: List[RoutingProtocol] = field(default_factory=list)
    vlans: Dict[int, VLANConfig] = field(default_factory=dict)
    hostname: Optional[str] = None
    domain_name: Optional[str] = None
    default_gateway: Optional[str] = None
    spanning_tree_mode: Optional[str] = None
    spanning_tree_vlans: Set[int] = field(default_factory=set)
    acls: Dict[str, List[str]] = field(default_factory=dict)
    raw_config: str = ""


class ConfigParser:
    """Parser for Cisco IOS configuration files."""
    
    def __init__(self):
        self.devices = {}  # Dictionary of device configurations
    
    def parse_directory(self, directory_path: str) -> Dict[str, DeviceConfiguration]:
        """
        Parse all configuration files in the specified directory.
        
        Args:
            directory_path: Path to the directory containing config files
            
        Returns:
            Dictionary of device configurations with device names as keys
        """
        device_configs = {}
        
        try:
            for item in os.listdir(directory_path):
                item_path = os.path.join(directory_path, item)
                
                # Check if it's a directory with config.dump inside
                if os.path.isdir(item_path):
                    config_file_path = os.path.join(item_path, "config.dump")
                    
                    if os.path.exists(config_file_path):
                        logger.info(f"Parsing configuration for device: {item}")
                        device_config = self.parse_file(config_file_path, item)
                        device_configs[item] = device_config
                    else:
                        logger.warning(f"No config.dump found for device: {item}")
                
                # Check if it's a configuration file directly
                elif os.path.isfile(item_path) and (
                    item.endswith('.config.dump') or 
                    item.endswith('.dump') or
                    item.endswith('.cfg') or
                    item.endswith('.config')
                ):
                    # Extract device name from filename
                    device_name = os.path.splitext(item)[0]
                    if device_name.endswith('.config'):
                        device_name = os.path.splitext(device_name)[0]
                    
                    logger.info(f"Parsing configuration file: {item} for device: {device_name}")
                    device_config = self.parse_file(item_path, device_name)
                    device_configs[device_name] = device_config
        
        except Exception as e:
            logger.error(f"Error parsing configuration directory: {e}")
            
        return device_configs
    
    def parse_file(self, file_path: str, device_name: str) -> DeviceConfiguration:
        """
        Parse a single device configuration file.
        
        Args:
            file_path: Path to the configuration file
            device_name: Name of the device
            
        Returns:
            DeviceConfiguration object with extracted information
        """
        try:
            with open(file_path, 'r') as f:
                config_text = f.read()
                
            # Create a basic device config (will be updated during parsing)
            device_config = DeviceConfiguration(
                name=device_name, 
                device_type="unknown",  # Will be determined during parsing
                raw_config=config_text
            )
            
            # Detect if this is a YAML configuration
            if self._is_yaml_format(config_text):
                logger.debug(f"Detected YAML format configuration for {device_name}")
                self._parse_yaml_config(config_text, device_config)
            else:
                logger.debug(f"Detected traditional Cisco IOS format configuration for {device_name}")
                # Parse hostname
                hostname_match = re.search(r'^\s*hostname\s+(\S+)', config_text, re.MULTILINE)
                if hostname_match:
                    device_config.hostname = hostname_match.group(1)
                
                # Determine device type
                device_config.device_type = self._determine_device_type(config_text)
                
                # Parse domain name
                domain_match = re.search(r'^\s*ip domain[- ]name\s+(\S+)', config_text, re.MULTILINE)
                if domain_match:
                    device_config.domain_name = domain_match.group(1)
                
                # Parse interface configurations
                self._parse_interfaces(config_text, device_config)
                
                # Parse VLANs
                self._parse_vlans(config_text, device_config)
                
                # Parse routing protocols
                self._parse_routing_protocols(config_text, device_config)
                
                # Parse spanning tree
                self._parse_spanning_tree(config_text, device_config)
                
                # Parse ACLs
                self._parse_acls(config_text, device_config)
            
            logger.info(f"Successfully parsed configuration for {device_name}")
            
            return device_config
            
        except Exception as e:
            logger.error(f"Error parsing configuration file {file_path}: {e}")
            # Return an empty config in case of error
            return DeviceConfiguration(name=device_name, device_type="unknown")
    
    def _is_yaml_format(self, config_text: str) -> bool:
        """Detect if the configuration is in YAML format."""
        # Look for YAML indicators
        yaml_indicators = [
            'device:', 'interfaces:', 'routing:', 'vlans:', 'spanning_tree:',
            '  - name:', '  name:', '    name:'
        ]
        
        # Check for multiple YAML indicators
        indicator_count = 0
        for indicator in yaml_indicators:
            if indicator in config_text:
                indicator_count += 1
        
        # If we find multiple YAML indicators, it's likely YAML
        return indicator_count >= 2
    
    def _parse_yaml_config(self, config_text: str, device_config: DeviceConfiguration) -> None:
        """Parse YAML format configuration."""
        try:
            config_data = yaml.safe_load(config_text)
            
            # Parse device information
            if 'device' in config_data:
                device_info = config_data['device']
                device_config.hostname = device_info.get('name', device_config.name)
                device_config.device_type = device_info.get('type', 'unknown')
                device_config.domain_name = device_info.get('domain_name')
            
            # Parse interfaces
            if 'interfaces' in config_data:
                for intf_data in config_data['interfaces']:
                    interface = Interface(name=intf_data['name'])
                    interface.ip_address = intf_data.get('ip_address')
                    interface.subnet_mask = intf_data.get('subnet_mask')
                    interface.description = intf_data.get('description', '').strip('"')
                    interface.status = intf_data.get('status', 'up')
                    interface.mtu = intf_data.get('mtu', 1500)
                    
                    # Parse bandwidth
                    bandwidth = intf_data.get('bandwidth')
                    if bandwidth:
                        if isinstance(bandwidth, (int, float)):
                            # Assume Mbps if it's a number
                            interface.bandwidth = f"{bandwidth}Mbps"
                        else:
                            interface.bandwidth = str(bandwidth)
                    
                    # Parse VLAN information
                    interface.access_vlan = intf_data.get('access_vlan')
                    interface.trunk_vlans = intf_data.get('trunk_vlans', [])
                    interface.vlan = intf_data.get('vlan') or intf_data.get('access_vlan')
                    
                    # Determine if physical interface
                    if re.match(r'(Ethernet|FastEthernet|GigabitEthernet|Serial|TenGigabitEthernet)', interface.name):
                        interface.is_physical = True
                    else:
                        interface.is_physical = False
                    
                    device_config.interfaces[interface.name] = interface
            
            # Parse VLANs
            if 'vlans' in config_data:
                for vlan_data in config_data['vlans']:
                    vlan_id = vlan_data['id']
                    vlan_config = VLANConfig(
                        vlan_id=vlan_id,
                        name=vlan_data.get('name'),
                        interfaces=vlan_data.get('interfaces', [])
                    )
                    device_config.vlans[vlan_id] = vlan_config
            
            # Parse routing protocols
            if 'routing' in config_data and 'protocols' in config_data['routing']:
                for protocol_data in config_data['routing']['protocols']:
                    protocol = RoutingProtocol(
                        protocol_type=protocol_data['type'],
                        process_id=protocol_data.get('process_id'),
                        router_id=protocol_data.get('router_id'),
                        networks=protocol_data.get('networks', []),
                        neighbors=protocol_data.get('neighbors', []),
                        redistributed=protocol_data.get('redistributed', []),
                        passive_interfaces=protocol_data.get('passive_interfaces', [])
                    )
                    device_config.routing_protocols.append(protocol)
            
            # Parse spanning tree
            if 'spanning_tree' in config_data:
                st_data = config_data['spanning_tree']
                device_config.spanning_tree_mode = st_data.get('mode')
                # Parse priority and other spanning tree settings as needed
                
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            raise
        except Exception as e:
            logger.error(f"Error processing YAML configuration data: {e}")
            raise

    def _determine_device_type(self, config_text: str) -> str:
        """Determine if the device is a router, switch, or other type."""
        # Check for switch-specific commands
        if re.search(r'(switchport|spanning-tree|vlan \d+)', config_text):
            return "switch"
        
        # Check for router-specific commands or interfaces
        if re.search(r'(^\s*router \w+|^\s*ip route|GigabitEthernet|Serial\d+)', config_text, re.MULTILINE):
            return "router"
        
        # Default to unknown
        return "unknown"
    
    def _parse_interfaces(self, config_text: str, device_config: DeviceConfiguration) -> None:
        """Parse interface configurations."""
        # Split the config into blocks by lines that start with non-whitespace (except comments)
        lines = config_text.split('\n')
        current_interface = None
        current_interface_config = []
        
        for line in lines:
            line = line.rstrip()
            
            # Check if this is an interface line
            interface_match = re.match(r'^\s*interface\s+(\S+)', line)
            if interface_match:
                # Process previous interface if exists
                if current_interface:
                    self._process_interface(current_interface, '\n'.join(current_interface_config), device_config)
                
                # Start new interface
                current_interface = interface_match.group(1)
                current_interface_config = []
                
            elif current_interface and (line.startswith(' ') or line.startswith('\t') or line.strip() == '' or line.strip().startswith('!')):
                # This line belongs to the current interface (indented, empty, or comment)
                current_interface_config.append(line)
                
            elif current_interface and not line.startswith(' ') and not line.startswith('\t') and line.strip() != '' and not line.strip().startswith('!'):
                # This line doesn't belong to interface config - process current interface and reset
                self._process_interface(current_interface, '\n'.join(current_interface_config), device_config)
                current_interface = None
                current_interface_config = []
        
        # Process the last interface if exists
        if current_interface:
            self._process_interface(current_interface, '\n'.join(current_interface_config), device_config)
    
    def _process_interface(self, interface_name: str, interface_config: str, device_config: DeviceConfiguration) -> None:
        """Process a single interface configuration."""
        # Create interface object
        interface = Interface(name=interface_name)
        
        # Check if physical interface
        if re.match(r'(Ethernet|FastEthernet|GigabitEthernet|Serial|TenGigabitEthernet)', interface_name):
            interface.is_physical = True
        else:
            interface.is_physical = False
            
        # Parse IP address
        ip_match = re.search(r'\s+ip address\s+(\S+)\s+(\S+)', interface_config)
        if ip_match:
            interface.ip_address = ip_match.group(1)
            interface.subnet_mask = ip_match.group(2)
        
        # Parse description
        desc_match = re.search(r'\s+description\s+(.+?)(?:\n|$)', interface_config)
        if desc_match:
            interface.description = desc_match.group(1).strip()
        
        # Parse status (shutdown)
        if re.search(r'\s+shutdown(?!\s)', interface_config) and not re.search(r'\s+no shutdown', interface_config):
            interface.status = "administratively down"
        
        # Parse bandwidth
        bw_match = re.search(r'\s+bandwidth\s+(\d+)', interface_config)
        if bw_match:
            bw_value = int(bw_match.group(1))
            if bw_value >= 1000000:
                interface.bandwidth = f"{bw_value//1000000}Mbps"
            elif bw_value >= 1000:
                interface.bandwidth = f"{bw_value//1000}Kbps"
            else:
                interface.bandwidth = f"{bw_value}bps"
        
        # Parse MTU
        mtu_match = re.search(r'\s+mtu\s+(\d+)', interface_config)
        if mtu_match:
            interface.mtu = int(mtu_match.group(1))
        
        # Parse duplex
        duplex_match = re.search(r'\s+duplex\s+(\S+)', interface_config)
        if duplex_match:
            interface.duplex = duplex_match.group(1)
        
        # Parse speed
        speed_match = re.search(r'\s+speed\s+(\S+)', interface_config)
        if speed_match:
            interface.speed = speed_match.group(1)
        
        # Parse switchport config
        if re.search(r'\s+switchport mode\s+access', interface_config):
            interface.switchport_mode = "access"
            vlan_match = re.search(r'\s+switchport access vlan\s+(\d+)', interface_config)
            if vlan_match:
                interface.access_vlan = int(vlan_match.group(1))
                interface.vlan = int(vlan_match.group(1))
        elif re.search(r'\s+switchport mode\s+trunk', interface_config):
            interface.switchport_mode = "trunk"
            allowed_vlans_match = re.search(r'\s+switchport trunk allowed vlan\s+(.+?)(?:\n|$)', interface_config)
            if allowed_vlans_match:
                vlan_str = allowed_vlans_match.group(1)
                # Handle comma-separated lists and ranges
                if ',' in vlan_str:
                    for part in vlan_str.split(','):
                        if '-' in part:
                            start, end = map(int, part.split('-'))
                            interface.trunk_vlans.extend(range(start, end + 1))
                        else:
                            try:
                                interface.trunk_vlans.append(int(part))
                            except ValueError:
                                pass
                elif '-' in vlan_str:
                    start, end = map(int, vlan_str.split('-'))
                    interface.trunk_vlans.extend(range(start, end + 1))
                else:
                    try:
                        interface.trunk_vlans.append(int(vlan_str))
                    except ValueError:
                        pass
        
        # Parse encapsulation
        encap_match = re.search(r'\s+encapsulation\s+(\S+)', interface_config)
        if encap_match:
            interface.encapsulation = encap_match.group(1)
        
        # Parse channel group
        channel_match = re.search(r'\s+channel-group\s+(\d+)', interface_config)
        if channel_match:
            interface.channel_group = int(channel_match.group(1))
        
        # Add interface to device
        device_config.interfaces[interface_name] = interface
    
    def _parse_vlans(self, config_text: str, device_config: DeviceConfiguration) -> None:
        """Parse VLAN configurations."""
        # Find all VLAN configurations
        vlan_blocks = re.finditer(
            r'^\s*vlan\s+(\d+)(?:\n\s*name\s+([^\n]+))?',
            config_text,
            re.MULTILINE
        )
        
        for match in vlan_blocks:
            vlan_id = int(match.group(1))
            vlan_name = match.group(2) if match.group(2) else None
            
            # Strip comments from VLAN name
            if vlan_name:
                # Remove inline comments (anything after '#')
                if '#' in vlan_name:
                    vlan_name = vlan_name.split('#')[0]
                vlan_name = vlan_name.strip()
            
            vlan_config = VLANConfig(vlan_id=vlan_id, name=vlan_name)
            device_config.vlans[vlan_id] = vlan_config
        
        # Assign interfaces to VLANs
        for interface_name, interface in device_config.interfaces.items():
            if interface.vlan is not None and interface.vlan in device_config.vlans:
                device_config.vlans[interface.vlan].interfaces.append(interface_name)
    
    def _parse_routing_protocols(self, config_text: str, device_config: DeviceConfiguration) -> None:
        """Parse routing protocol configurations."""
        lines = config_text.split('\n')
        current_protocol = None
        current_protocol_config = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Check for OSPF
            ospf_match = re.match(r'router ospf\s+(\d+)', line_stripped)
            if ospf_match:
                # Process previous protocol if exists
                if current_protocol:
                    self._process_routing_protocol(current_protocol, '\n'.join(current_protocol_config), device_config)
                
                current_protocol = ('ospf', ospf_match.group(1))
                current_protocol_config = []
                
            # Check for BGP
            elif line_stripped.startswith('router bgp '):
                bgp_match = re.match(r'router bgp\s+(\d+)', line_stripped)
                if bgp_match:
                    # Process previous protocol if exists
                    if current_protocol:
                        self._process_routing_protocol(current_protocol, '\n'.join(current_protocol_config), device_config)
                    
                    current_protocol = ('bgp', bgp_match.group(1))
                    current_protocol_config = []
                    
            elif current_protocol and (line.startswith(' ') or line.startswith('\t')):
                # Indented line belonging to current protocol
                current_protocol_config.append(line)
                
            elif current_protocol and line_stripped and not line.startswith(' ') and not line.startswith('\t'):
                # Non-indented line - finish current protocol
                self._process_routing_protocol(current_protocol, '\n'.join(current_protocol_config), device_config)
                current_protocol = None
                current_protocol_config = []
        
        # Process the last protocol if exists
        if current_protocol:
            self._process_routing_protocol(current_protocol, '\n'.join(current_protocol_config), device_config)
        
        # Parse static routes separately
        static_routes = re.finditer(r'^\s*ip route\s+(\S+)\s+(\S+)\s+(\S+)', config_text, re.MULTILINE)
        static_route_list = list(static_routes)
        if static_route_list:
            static = RoutingProtocol(protocol_type="static")
            
            for route_match in static_route_list:
                static.networks.append({
                    "network": route_match.group(1),
                    "mask": route_match.group(2),
                    "next_hop": route_match.group(3)
                })
            
            device_config.routing_protocols.append(static)
    
    def _process_routing_protocol(self, protocol_info: tuple, protocol_config: str, device_config: DeviceConfiguration) -> None:
        """Process a single routing protocol configuration."""
        protocol_type, process_id = protocol_info
        
        if protocol_type == "ospf":
            ospf = RoutingProtocol(protocol_type="ospf", process_id=process_id)
            
            # Parse router-id
            router_id_match = re.search(r'\s+router-id\s+(\S+)', protocol_config)
            if router_id_match:
                ospf.router_id = router_id_match.group(1)
            
            # Parse networks
            network_matches = re.finditer(r'\s+network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', protocol_config)
            for net_match in network_matches:
                ospf.networks.append({
                    "network": net_match.group(1),
                    "wildcard": net_match.group(2),
                    "area": net_match.group(3)
                })
            
            # Parse passive interfaces
            passive_matches = re.finditer(r'\s+passive-interface\s+(\S+)', protocol_config)
            for pi_match in passive_matches:
                ospf.passive_interfaces.append(pi_match.group(1))
            
            # Parse redistribution
            redist_matches = re.finditer(r'\s+redistribute\s+(\S+)', protocol_config)
            for rd_match in redist_matches:
                ospf.redistributed.append(rd_match.group(1))
            
            device_config.routing_protocols.append(ospf)
            
        elif protocol_type == "bgp":
            bgp = RoutingProtocol(protocol_type="bgp", process_id=process_id)
            
            # Parse router-id
            router_id_match = re.search(r'\s+bgp router-id\s+(\S+)', protocol_config)
            if router_id_match:
                bgp.router_id = router_id_match.group(1)
            
            # Parse neighbors
            neighbor_matches = re.finditer(r'\s+neighbor\s+(\S+)\s+remote-as\s+(\S+)', protocol_config)
            for nei_match in neighbor_matches:
                bgp.neighbors.append({
                    "ip": nei_match.group(1),
                    "remote_as": nei_match.group(2)
                })
            
            # Parse networks
            network_matches = re.finditer(r'\s+network\s+(\S+)\s+mask\s+(\S+)', protocol_config)
            for net_match in network_matches:
                bgp.networks.append({
                    "network": net_match.group(1),
                    "mask": net_match.group(2)
                })
            
            # Parse redistribution
            redist_matches = re.finditer(r'\s+redistribute\s+(\S+)', protocol_config)
            for rd_match in redist_matches:
                bgp.redistributed.append(rd_match.group(1))
            
            device_config.routing_protocols.append(bgp)
    
    def _parse_spanning_tree(self, config_text: str, device_config: DeviceConfiguration) -> None:
        """Parse spanning tree configurations."""
        # Parse spanning-tree mode
        mode_match = re.search(r'^\s*spanning-tree mode\s+(\S+)', config_text, re.MULTILINE)
        if mode_match:
            device_config.spanning_tree_mode = mode_match.group(1)
        
        # Parse spanning-tree vlan configuration
        vlan_matches = re.finditer(r'^\s*spanning-tree vlan\s+(.+)', config_text, re.MULTILINE)
        for match in vlan_matches:
            vlan_str = match.group(1)
            # Handle comma-separated lists and ranges
            if ',' in vlan_str:
                for part in vlan_str.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        device_config.spanning_tree_vlans.update(range(start, end + 1))
                    else:
                        try:
                            device_config.spanning_tree_vlans.add(int(part))
                        except ValueError:
                            pass
            elif '-' in vlan_str:
                start, end = map(int, vlan_str.split('-'))
                device_config.spanning_tree_vlans.update(range(start, end + 1))
            else:
                try:
                    device_config.spanning_tree_vlans.add(int(vlan_str))
                except ValueError:
                    pass
    
    def _parse_acls(self, config_text: str, device_config: DeviceConfiguration) -> None:
        """Parse access control lists."""
        lines = config_text.split('\n')
        current_acl = None
        current_acl_lines = []
        
        for line in lines:
            line = line.strip()
            
            # Check for ACL declaration
            if line.startswith('ip access-list '):
                # Process previous ACL if exists
                if current_acl:
                    device_config.acls[current_acl] = current_acl_lines
                
                # Start new ACL
                parts = line.split()
                if len(parts) >= 4:  # ip access-list extended/standard name
                    current_acl = parts[3]
                    current_acl_lines = [line]
                
            elif line.startswith('access-list '):
                # Numbered ACL
                # Process previous ACL if exists
                if current_acl:
                    device_config.acls[current_acl] = current_acl_lines
                
                # Extract ACL number
                parts = line.split()
                if len(parts) >= 2:
                    acl_num = parts[1]
                    current_acl = acl_num
                    current_acl_lines = [line]
                    
            elif current_acl and (line.startswith('permit ') or line.startswith('deny ') or line.startswith('remark ')):
                # ACL rule belonging to current ACL
                current_acl_lines.append(line)
                
            elif current_acl and line and not line.startswith(' ') and not line.startswith('\t'):
                # Non-indented line that's not part of ACL - finish current ACL
                device_config.acls[current_acl] = current_acl_lines
                current_acl = None
                current_acl_lines = []
        
        # Process the last ACL if exists
        if current_acl:
            device_config.acls[current_acl] = current_acl_lines


def load_configurations(config_path: str) -> List[Dict[str, Any]]:
    """
    Load and parse network device configurations from a path.
    
    Args:
        config_path: Path to a configuration file or directory containing configs
        
    Returns:
        List of configuration dictionaries
    """
    import os
    from pathlib import Path
    
    path = Path(config_path)
    parser = ConfigParser()
    configurations = []
    
    if path.is_file():
        # Single file
        try:
            device_name = path.stem
            device_config = parser.parse_file(str(path), device_name)
            config_dict = _device_config_to_dict(device_config)
            configurations.append(config_dict)
        except Exception as e:
            logger.error(f"Error parsing file {path}: {e}")
    
    elif path.is_dir():
        # Directory of files
        try:
            device_configs = parser.parse_directory(str(path))
            for device_name, device_config in device_configs.items():
                config_dict = _device_config_to_dict(device_config)
                configurations.append(config_dict)
        except Exception as e:
            logger.error(f"Error parsing directory {path}: {e}")
    
    else:
        raise FileNotFoundError(f"Configuration path not found: {config_path}")
    
    return configurations


def _device_config_to_dict(device_config: DeviceConfiguration) -> Dict[str, Any]:
    """Convert DeviceConfiguration object to dictionary format expected by topology generator."""
    config_dict = {
        'device': {
            'name': device_config.name,
            'type': device_config.device_type,
            'hostname': device_config.hostname or device_config.name,
            'domain_name': device_config.domain_name,
            'default_gateway': device_config.default_gateway,
            'spanning_tree_mode': device_config.spanning_tree_mode
        },
        'interfaces': [],
        'vlans': [],
        'routing': {
            'protocols': []
        },
        'acls': device_config.acls
    }
    
    # Convert interfaces
    for intf_name, intf in device_config.interfaces.items():
        intf_dict = {
            'name': intf.name,
            'type': 'ethernet' if 'Ethernet' in intf.name else 'serial' if 'Serial' in intf.name else 'other',
            'ip_address': intf.ip_address,
            'subnet_mask': intf.subnet_mask,
            'bandwidth': _parse_bandwidth_to_mbps(intf.bandwidth),
            'mtu': intf.mtu,
            'status': intf.status,
            'description': intf.description,
            'vlan': intf.vlan,
            'access_vlan': intf.access_vlan,
            'trunk_vlans': intf.trunk_vlans,
            'duplex': intf.duplex,
            'speed': intf.speed
        }
        config_dict['interfaces'].append(intf_dict)
    
    # Convert VLANs
    for vlan_id, vlan in device_config.vlans.items():
        vlan_dict = {
            'id': vlan.vlan_id,
            'name': vlan.name,
            'interfaces': vlan.interfaces
        }
        config_dict['vlans'].append(vlan_dict)
    
    # Convert routing protocols
    for protocol in device_config.routing_protocols:
        protocol_dict = {
            'type': protocol.protocol_type,
            'process_id': protocol.process_id,
            'router_id': protocol.router_id,
            'networks': protocol.networks,
            'neighbors': protocol.neighbors,
            'redistributed': protocol.redistributed,
            'passive_interfaces': protocol.passive_interfaces
        }
        config_dict['routing']['protocols'].append(protocol_dict)
    
    return config_dict


def _parse_bandwidth_to_mbps(bandwidth_str: Optional[str]) -> Optional[float]:
    """Parse bandwidth string to Mbps value."""
    if not bandwidth_str:
        return None
    
    try:
        # Remove units and convert
        if isinstance(bandwidth_str, str):
            if 'Mbps' in bandwidth_str:
                return float(bandwidth_str.replace('Mbps', ''))
            elif 'Kbps' in bandwidth_str:
                return float(bandwidth_str.replace('Kbps', '')) / 1000
            elif 'bps' in bandwidth_str:
                return float(bandwidth_str.replace('bps', '')) / 1000000
            else:
                # Assume it's a raw number in bps
                return float(bandwidth_str) / 1000000
        else:
            # Assume it's already a number
            return float(bandwidth_str) / 1000000
    except (ValueError, TypeError):
        return None