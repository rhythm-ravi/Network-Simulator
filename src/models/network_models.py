#!/usr/bin/env python3
"""
Network Models for Network Simulator

This module defines the core network models including devices, interfaces,
links, and topology representations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Union
from enum import Enum
import logging


logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """Enumeration of network device types."""
    ROUTER = "router"
    SWITCH = "switch"
    HOST = "host"
    FIREWALL = "firewall"


class InterfaceType(Enum):
    """Enumeration of interface types."""
    ETHERNET = "ethernet"
    SERIAL = "serial"
    LOOPBACK = "loopback"
    TUNNEL = "tunnel"


class InterfaceStatus(Enum):
    """Enumeration of interface status."""
    UP = "up"
    DOWN = "down"
    ADMIN_DOWN = "admin_down"


@dataclass
class NetworkInterface:
    """Represents a network interface on a device."""
    
    name: str
    interface_type: InterfaceType = InterfaceType.ETHERNET
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    bandwidth: int = 0  # in Mbps
    status: InterfaceStatus = InterfaceStatus.DOWN
    description: str = ""
    access_vlan: Optional[int] = None
    trunk_vlans: List[int] = field(default_factory=list)
    mac_address: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.interface_type, str):
            self.interface_type = InterfaceType(self.interface_type)
        if isinstance(self.status, str):
            self.status = InterfaceStatus(self.status)
    
    @property
    def is_up(self) -> bool:
        """Check if interface is operationally up."""
        return self.status == InterfaceStatus.UP
    
    def get_network_address(self) -> Optional[str]:
        """Get the network address for this interface."""
        if self.ip_address and self.subnet_mask:
            # Simple calculation - could be enhanced with proper IP calculations
            return self.ip_address
        return None


@dataclass 
class VLAN:
    """Represents a VLAN configuration."""
    
    vlan_id: int
    name: str = ""
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    description: str = ""


@dataclass
class RoutingProtocol:
    """Represents a routing protocol configuration."""
    
    protocol_type: str  # ospf, eigrp, bgp, static, etc.
    process_id: Optional[int] = None
    networks: List[Dict[str, Any]] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)


class NetworkDevice(ABC):
    """Abstract base class for all network devices."""
    
    def __init__(self, name: str, device_type: DeviceType, model: str = "", location: str = ""):
        self.name = name
        self.device_type = device_type
        self.model = model
        self.location = location
        self.interfaces: Dict[str, NetworkInterface] = {}
        self.vlans: Dict[int, VLAN] = {}
        self.routing_protocols: List[RoutingProtocol] = []
        self.config_source: str = ""
        
    def add_interface(self, interface: NetworkInterface) -> None:
        """Add an interface to the device."""
        self.interfaces[interface.name] = interface
        logger.debug(f"Added interface {interface.name} to device {self.name}")
    
    def get_interface(self, name: str) -> Optional[NetworkInterface]:
        """Get an interface by name."""
        return self.interfaces.get(name)
    
    def get_active_interfaces(self) -> List[NetworkInterface]:
        """Get all active (up) interfaces."""
        return [iface for iface in self.interfaces.values() if iface.is_up]
    
    def add_vlan(self, vlan: VLAN) -> None:
        """Add a VLAN to the device."""
        self.vlans[vlan.vlan_id] = vlan
        logger.debug(f"Added VLAN {vlan.vlan_id} to device {self.name}")
    
    def add_routing_protocol(self, protocol: RoutingProtocol) -> None:
        """Add a routing protocol to the device."""
        self.routing_protocols.append(protocol)
        logger.debug(f"Added routing protocol {protocol.protocol_type} to device {self.name}")
    
    @abstractmethod
    def get_device_summary(self) -> Dict[str, Any]:
        """Get a summary of the device configuration."""
        pass
    
    def __str__(self) -> str:
        return f"{self.device_type.value.title()}: {self.name}"


class Router(NetworkDevice):
    """Represents a network router."""
    
    def __init__(self, name: str, model: str = "", location: str = ""):
        super().__init__(name, DeviceType.ROUTER, model, location)
        self.routing_table: List[Dict[str, Any]] = []
    
    def get_device_summary(self) -> Dict[str, Any]:
        """Get a summary of the router configuration."""
        return {
            'name': self.name,
            'type': self.device_type.value,
            'model': self.model,
            'location': self.location,
            'interface_count': len(self.interfaces),
            'active_interfaces': len(self.get_active_interfaces()),
            'vlan_count': len(self.vlans),
            'routing_protocols': [p.protocol_type for p in self.routing_protocols],
            'config_source': self.config_source
        }
    
    def get_connected_networks(self) -> List[str]:
        """Get all directly connected networks."""
        networks = []
        for interface in self.get_active_interfaces():
            if interface.ip_address:
                networks.append(interface.get_network_address() or interface.ip_address)
        return networks


class Switch(NetworkDevice):
    """Represents a network switch."""
    
    def __init__(self, name: str, model: str = "", location: str = ""):
        super().__init__(name, DeviceType.SWITCH, model, location)
        self.mac_address_table: List[Dict[str, str]] = []
        self.spanning_tree_config: Dict[str, Any] = {}
    
    def get_device_summary(self) -> Dict[str, Any]:
        """Get a summary of the switch configuration."""
        return {
            'name': self.name,
            'type': self.device_type.value,
            'model': self.model,
            'location': self.location,
            'interface_count': len(self.interfaces),
            'active_interfaces': len(self.get_active_interfaces()),
            'vlan_count': len(self.vlans),
            'access_ports': len([i for i in self.interfaces.values() if i.access_vlan]),
            'trunk_ports': len([i for i in self.interfaces.values() if i.trunk_vlans]),
            'config_source': self.config_source
        }
    
    def get_access_ports(self) -> List[NetworkInterface]:
        """Get all access ports (non-trunk interfaces)."""
        return [iface for iface in self.interfaces.values() if iface.access_vlan and not iface.trunk_vlans]
    
    def get_trunk_ports(self) -> List[NetworkInterface]:
        """Get all trunk ports."""
        return [iface for iface in self.interfaces.values() if iface.trunk_vlans]


@dataclass
class Link:
    """Represents a connection between two network devices."""
    
    device1: NetworkDevice
    interface1: str
    device2: NetworkDevice
    interface2: str
    bandwidth: int = 0  # in Mbps
    latency: float = 0.0  # in ms
    link_type: str = "ethernet"
    status: str = "up"
    
    @property
    def is_active(self) -> bool:
        """Check if both interfaces of the link are up."""
        iface1 = self.device1.get_interface(self.interface1)
        iface2 = self.device2.get_interface(self.interface2)
        return (iface1 and iface1.is_up and 
                iface2 and iface2.is_up and 
                self.status == "up")
    
    def get_link_summary(self) -> Dict[str, Any]:
        """Get a summary of the link."""
        return {
            'device1': self.device1.name,
            'interface1': self.interface1,
            'device2': self.device2.name,
            'interface2': self.interface2,
            'bandwidth': self.bandwidth,
            'latency': self.latency,
            'type': self.link_type,
            'status': self.status,
            'is_active': self.is_active
        }
    
    def __str__(self) -> str:
        return f"{self.device1.name}:{self.interface1} <-> {self.device2.name}:{self.interface2}"


class NetworkTopology:
    """Represents the complete network topology."""
    
    def __init__(self, name: str = "Network"):
        self.name = name
        self.devices: Dict[str, NetworkDevice] = {}
        self.links: List[Link] = []
        self.metadata: Dict[str, Any] = {}
    
    def add_device(self, device: NetworkDevice) -> None:
        """Add a device to the topology."""
        self.devices[device.name] = device
        logger.info(f"Added device {device.name} to topology {self.name}")
    
    def get_device(self, name: str) -> Optional[NetworkDevice]:
        """Get a device by name."""
        return self.devices.get(name)
    
    def add_link(self, link: Link) -> None:
        """Add a link to the topology."""
        self.links.append(link)
        logger.info(f"Added link: {link}")
    
    def get_devices_by_type(self, device_type: DeviceType) -> List[NetworkDevice]:
        """Get all devices of a specific type."""
        return [device for device in self.devices.values() if device.device_type == device_type]
    
    def get_routers(self) -> List[Router]:
        """Get all routers in the topology."""
        return [device for device in self.devices.values() if isinstance(device, Router)]
    
    def get_switches(self) -> List[Switch]:
        """Get all switches in the topology."""
        return [device for device in self.devices.values() if isinstance(device, Switch)]
    
    def get_active_links(self) -> List[Link]:
        """Get all active links in the topology."""
        return [link for link in self.links if link.is_active]
    
    def get_device_connections(self, device_name: str) -> List[Link]:
        """Get all links connected to a specific device."""
        return [link for link in self.links 
                if link.device1.name == device_name or link.device2.name == device_name]
    
    def get_topology_summary(self) -> Dict[str, Any]:
        """Get a summary of the entire topology."""
        return {
            'name': self.name,
            'total_devices': len(self.devices),
            'routers': len(self.get_routers()),
            'switches': len(self.get_switches()),
            'total_links': len(self.links),
            'active_links': len(self.get_active_links()),
            'devices': {name: device.get_device_summary() 
                       for name, device in self.devices.items()},
            'metadata': self.metadata
        }
    
    def validate_topology(self) -> tuple[bool, List[str]]:
        """
        Validate the topology for basic consistency.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check for duplicate device names
        device_names = list(self.devices.keys())
        if len(device_names) != len(set(device_names)):
            errors.append("Duplicate device names found")
        
        # Validate links
        for i, link in enumerate(self.links):
            if link.device1.name not in self.devices:
                errors.append(f"Link {i}: Device {link.device1.name} not in topology")
            if link.device2.name not in self.devices:
                errors.append(f"Link {i}: Device {link.device2.name} not in topology")
            
            # Check if interfaces exist
            if not link.device1.get_interface(link.interface1):
                errors.append(f"Link {i}: Interface {link.interface1} not found on {link.device1.name}")
            if not link.device2.get_interface(link.interface2):
                errors.append(f"Link {i}: Interface {link.interface2} not found on {link.device2.name}")
        
        return len(errors) == 0, errors
    
    def __str__(self) -> str:
        return f"Topology '{self.name}': {len(self.devices)} devices, {len(self.links)} links"