#!/usr/bin/env python3
"""
Network Events for Network Simulator

This module defines various network events that can occur during simulation,
including protocol events, fault events, and control events.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Enumeration of network event types."""
    # Protocol Events
    ARP_REQUEST = "arp_request"
    ARP_REPLY = "arp_reply"
    NEIGHBOR_DISCOVERY = "neighbor_discovery"
    OSPF_HELLO = "ospf_hello"
    OSPF_LSA = "ospf_lsa"
    
    # Traffic Events
    PACKET_SEND = "packet_send"
    PACKET_RECEIVE = "packet_receive"
    PACKET_DROP = "packet_drop"
    
    # Fault Events
    LINK_FAILURE = "link_failure"
    LINK_RECOVERY = "link_recovery"
    DEVICE_FAILURE = "device_failure"
    DEVICE_RECOVERY = "device_recovery"
    MTU_MISMATCH = "mtu_mismatch"
    
    # Control Events
    SIMULATION_START = "simulation_start"
    SIMULATION_PAUSE = "simulation_pause"
    SIMULATION_RESUME = "simulation_resume"
    SIMULATION_STOP = "simulation_stop"
    CONFIG_CHANGE = "config_change"


class EventPriority(Enum):
    """Enumeration of event priorities."""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass
class NetworkEvent(ABC):
    """Base class for all network events."""
    
    event_type: EventType
    timestamp: float
    source_device: Optional[str] = None
    target_device: Optional[str] = None
    priority: EventPriority = EventPriority.NORMAL
    data: Dict[str, Any] = field(default_factory=dict)
    event_id: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing."""
        if self.event_id is None:
            import uuid
            self.event_id = str(uuid.uuid4())[:8]
    
    @abstractmethod
    def process(self, simulation_engine) -> List['NetworkEvent']:
        """
        Process this event and return any resulting events.
        
        Args:
            simulation_engine: Reference to the simulation engine
            
        Returns:
            List of new events generated from processing this event
        """
        pass
    
    def __str__(self) -> str:
        return f"{self.event_type.value}@{self.timestamp:.3f}[{self.event_id}]"


@dataclass
class ProtocolEvent(NetworkEvent):
    """Base class for protocol-related events."""
    
    protocol: str = ""
    interface: Optional[str] = None
    
    def get_protocol_data(self) -> Dict[str, Any]:
        """Get protocol-specific data."""
        return self.data.get('protocol_data', {})


@dataclass
class ARPRequestEvent(ProtocolEvent):
    """ARP request event."""
    
    def __init__(self, timestamp: float, source_device: str, target_ip: str, 
                 source_ip: str, interface: str):
        super().__init__(
            event_type=EventType.ARP_REQUEST,
            timestamp=timestamp,
            source_device=source_device,
            protocol="ARP",
            interface=interface,
            data={
                'target_ip': target_ip,
                'source_ip': source_ip,
                'protocol_data': {
                    'operation': 'request',
                    'hardware_type': 1,
                    'protocol_type': 'IPv4'
                }
            }
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process ARP request and generate reply if target is found."""
        events = []
        target_ip = self.data['target_ip']
        
        # Find devices with the target IP
        target_devices = simulation_engine.find_devices_by_ip(target_ip)
        
        for device_name in target_devices:
            # Generate ARP reply
            reply_event = ARPReplyEvent(
                timestamp=self.timestamp + 0.001,  # Small delay
                source_device=device_name,
                target_device=self.source_device,
                target_ip=self.data['source_ip'],
                source_ip=target_ip,
                interface=self.interface
            )
            events.append(reply_event)
            
            logger.debug(f"ARP request from {self.source_device} for {target_ip} "
                        f"will be answered by {device_name}")
        
        return events


@dataclass
class ARPReplyEvent(ProtocolEvent):
    """ARP reply event."""
    
    def __init__(self, timestamp: float, source_device: str, target_device: str,
                 target_ip: str, source_ip: str, interface: str):
        super().__init__(
            event_type=EventType.ARP_REPLY,
            timestamp=timestamp,
            source_device=source_device,
            target_device=target_device,
            protocol="ARP",
            interface=interface,
            data={
                'target_ip': target_ip,
                'source_ip': source_ip,
                'protocol_data': {
                    'operation': 'reply',
                    'hardware_type': 1,
                    'protocol_type': 'IPv4'
                }
            }
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process ARP reply and update ARP table."""
        # Update ARP table on target device
        simulation_engine.update_arp_table(
            self.target_device,
            self.data['source_ip'],
            f"MAC_{self.source_device}",  # Simplified MAC address
            self.interface
        )
        
        logger.debug(f"ARP reply: {self.source_device} -> {self.target_device} "
                    f"({self.data['source_ip']})")
        
        return []


@dataclass
class NeighborDiscoveryEvent(ProtocolEvent):
    """Neighbor discovery event for various protocols."""
    
    def __init__(self, timestamp: float, source_device: str, discovery_type: str = "generic"):
        super().__init__(
            event_type=EventType.NEIGHBOR_DISCOVERY,
            timestamp=timestamp,
            source_device=source_device,
            protocol="NEIGHBOR_DISCOVERY",
            data={
                'discovery_type': discovery_type,
                'protocol_data': {
                    'hello_interval': 10.0,
                    'holdtime': 30.0
                }
            }
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process neighbor discovery and establish adjacencies."""
        events = []
        neighbors = simulation_engine.find_neighbors(self.source_device)
        
        for neighbor in neighbors:
            # Create bidirectional neighbor relationships
            simulation_engine.add_neighbor_relationship(self.source_device, neighbor)
            
            logger.debug(f"Neighbor discovered: {self.source_device} <-> {neighbor}")
            
            # Schedule periodic hello events
            hello_event = OSPFHelloEvent(
                timestamp=self.timestamp + self.data['protocol_data']['hello_interval'],
                source_device=self.source_device,
                target_device=neighbor
            )
            events.append(hello_event)
        
        return events


@dataclass
class OSPFHelloEvent(ProtocolEvent):
    """OSPF Hello event for maintaining adjacencies."""
    
    def __init__(self, timestamp: float, source_device: str, target_device: str):
        super().__init__(
            event_type=EventType.OSPF_HELLO,
            timestamp=timestamp,
            source_device=source_device,
            target_device=target_device,
            protocol="OSPF",
            data={
                'protocol_data': {
                    'hello_interval': 10.0,
                    'dead_interval': 40.0,
                    'area_id': '0.0.0.0'
                }
            }
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process OSPF hello and maintain neighbor state."""
        events = []
        
        # Update neighbor last-seen time
        simulation_engine.update_neighbor_timestamp(
            self.target_device, 
            self.source_device, 
            self.timestamp
        )
        
        # Schedule next hello
        next_hello = OSPFHelloEvent(
            timestamp=self.timestamp + self.data['protocol_data']['hello_interval'],
            source_device=self.source_device,
            target_device=self.target_device
        )
        events.append(next_hello)
        
        logger.debug(f"OSPF Hello: {self.source_device} -> {self.target_device}")
        
        return events


@dataclass
class FaultEvent(NetworkEvent):
    """Base class for fault injection events."""
    
    fault_type: str = ""
    severity: str = "medium"  # low, medium, high, critical
    duration: Optional[float] = None  # None means permanent
    affected_component: str = ""


@dataclass
class LinkFailureEvent(FaultEvent):
    """Link failure fault injection event."""
    
    def __init__(self, timestamp: float, link_id: str, duration: Optional[float] = None):
        super().__init__(
            event_type=EventType.LINK_FAILURE,
            timestamp=timestamp,
            fault_type="link_failure",
            severity="high",
            duration=duration,
            affected_component=link_id,
            data={
                'link_id': link_id,
                'failure_type': 'complete',
                'recovery_time': timestamp + duration if duration else None
            }
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process link failure and schedule recovery if applicable."""
        events = []
        link_id = self.data['link_id']
        
        # Disable the link
        simulation_engine.disable_link(link_id, self.timestamp)
        
        logger.warning(f"Link failure injected: {link_id} at {self.timestamp:.3f}")
        
        # Schedule recovery if duration is specified
        if self.duration:
            recovery_event = LinkRecoveryEvent(
                timestamp=self.timestamp + self.duration,
                link_id=link_id
            )
            events.append(recovery_event)
            logger.info(f"Link recovery scheduled for {recovery_event.timestamp:.3f}")
        
        return events


@dataclass
class LinkRecoveryEvent(FaultEvent):
    """Link recovery event."""
    
    def __init__(self, timestamp: float, link_id: str):
        super().__init__(
            event_type=EventType.LINK_RECOVERY,
            timestamp=timestamp,
            fault_type="link_recovery",
            severity="low",
            affected_component=link_id,
            data={'link_id': link_id}
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process link recovery."""
        link_id = self.data['link_id']
        
        # Re-enable the link
        simulation_engine.enable_link(link_id, self.timestamp)
        
        logger.info(f"Link recovered: {link_id} at {self.timestamp:.3f}")
        
        return []


@dataclass
class MTUMismatchEvent(FaultEvent):
    """MTU mismatch fault injection event."""
    
    def __init__(self, timestamp: float, source_device: str, target_device: str, 
                 packet_size: int, interface_mtu: int):
        super().__init__(
            event_type=EventType.MTU_MISMATCH,
            timestamp=timestamp,
            source_device=source_device,
            target_device=target_device,
            fault_type="mtu_mismatch",
            severity="medium",
            data={
                'packet_size': packet_size,
                'interface_mtu': interface_mtu,
                'fragmentation_needed': packet_size > interface_mtu
            }
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process MTU mismatch and handle fragmentation or drops."""
        events = []
        
        if self.data['fragmentation_needed']:
            # Generate packet drop or fragmentation events
            drop_event = PacketDropEvent(
                timestamp=self.timestamp,
                source_device=self.source_device,
                target_device=self.target_device,
                reason=f"MTU mismatch: packet_size={self.data['packet_size']}, "
                       f"mtu={self.data['interface_mtu']}"
            )
            events.append(drop_event)
            
            logger.warning(f"MTU mismatch: {self.source_device} -> {self.target_device} "
                          f"packet_size={self.data['packet_size']}, mtu={self.data['interface_mtu']}")
        
        return events


@dataclass
class PacketDropEvent(NetworkEvent):
    """Packet drop event."""
    
    def __init__(self, timestamp: float, source_device: str, target_device: str, reason: str):
        super().__init__(
            event_type=EventType.PACKET_DROP,
            timestamp=timestamp,
            source_device=source_device,
            target_device=target_device,
            data={'reason': reason}
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process packet drop and update statistics."""
        simulation_engine.record_packet_drop(
            self.source_device,
            self.target_device,
            self.data['reason'],
            self.timestamp
        )
        
        logger.debug(f"Packet dropped: {self.source_device} -> {self.target_device} "
                    f"({self.data['reason']})")
        
        return []


@dataclass 
class SimulationControlEvent(NetworkEvent):
    """Base class for simulation control events."""
    
    command: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfigChangeEvent(SimulationControlEvent):
    """Configuration change event."""
    
    def __init__(self, timestamp: float, target_device: str, config_changes: Dict[str, Any]):
        super().__init__(
            event_type=EventType.CONFIG_CHANGE,
            timestamp=timestamp,
            target_device=target_device,
            command="config_change",
            parameters=config_changes
        )
    
    def process(self, simulation_engine) -> List[NetworkEvent]:
        """Process configuration change."""
        # Apply configuration changes to the target device
        simulation_engine.apply_config_changes(
            self.target_device,
            self.parameters,
            self.timestamp
        )
        
        logger.info(f"Configuration changed on {self.target_device}: {self.parameters}")
        
        return []