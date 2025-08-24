#!/usr/bin/env python3
"""
Simulation Engine for Network Simulator

This module provides the main simulation engine that orchestrates network simulation,
manages devices, handles events, and provides fault injection capabilities.
"""

import logging
import threading
import time
import queue
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import copy

# Import SimPy and related modules
import simpy

# Import network models
from ..models.network_models import (
    NetworkDevice, Router, Switch, NetworkInterface, VLAN, 
    RoutingProtocol, DeviceType, InterfaceStatus
)

# Import simulation components
from .event_scheduler import EventScheduler, SchedulerState
from .network_events import (
    NetworkEvent, EventType, EventPriority,
    ARPRequestEvent, NeighborDiscoveryEvent, OSPFHelloEvent,
    LinkFailureEvent, LinkRecoveryEvent, MTUMismatchEvent,
    ConfigChangeEvent, PacketDropEvent
)

logger = logging.getLogger(__name__)


class SimulationState(Enum):
    """Enumeration of simulation states."""
    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class DeviceStatistics:
    """Statistics for a network device."""
    
    device_name: str
    packets_sent: int = 0
    packets_received: int = 0
    packets_dropped: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    events_processed: int = 0
    last_activity: float = 0.0
    arp_table: Dict[str, str] = field(default_factory=dict)  # IP -> MAC
    neighbor_table: Dict[str, float] = field(default_factory=dict)  # neighbor -> last_seen
    interface_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def update_activity(self, timestamp: float):
        """Update last activity timestamp."""
        self.last_activity = timestamp


@dataclass
class LinkStatistics:
    """Statistics for a network link."""
    
    link_id: str
    source_device: str
    target_device: str
    is_active: bool = True
    packets_transmitted: int = 0
    bytes_transmitted: int = 0
    failure_count: int = 0
    last_failure: Optional[float] = None
    recovery_count: int = 0
    last_recovery: Optional[float] = None


class DeviceThread(threading.Thread):
    """Thread for managing a single network device."""
    
    def __init__(self, device: NetworkDevice, simulation_engine: 'NetworkSimulationEngine'):
        super().__init__(name=f"Device-{device.name}")
        self.device = device
        self.simulation_engine = simulation_engine
        self.device_queue = queue.Queue()
        self.stop_flag = threading.Event()
        self.statistics = DeviceStatistics(device.name)
        
        logger.debug(f"Created device thread for {device.name}")
    
    def run(self):
        """Main thread loop for device processing."""
        logger.info(f"Device thread started: {self.device.name}")
        
        try:
            while not self.stop_flag.is_set():
                try:
                    # Process messages from other devices or simulation engine
                    message = self.device_queue.get(timeout=1.0)
                    self._process_message(message)
                    
                except queue.Empty:
                    # Timeout - perform periodic tasks
                    self._perform_periodic_tasks()
                    continue
                    
                except Exception as e:
                    logger.error(f"Error in device thread {self.device.name}: {e}")
                    
        except Exception as e:
            logger.error(f"Critical error in device thread {self.device.name}: {e}")
        finally:
            logger.info(f"Device thread stopped: {self.device.name}")
    
    def _process_message(self, message: Dict[str, Any]):
        """Process a message received by this device."""
        message_type = message.get('type', 'unknown')
        timestamp = message.get('timestamp', time.time())
        
        self.statistics.events_processed += 1
        self.statistics.update_activity(timestamp)
        
        if message_type == 'arp_request':
            self._handle_arp_request(message)
        elif message_type == 'arp_reply':
            self._handle_arp_reply(message)
        elif message_type == 'neighbor_hello':
            self._handle_neighbor_hello(message)
        elif message_type == 'packet':
            self._handle_packet(message)
        elif message_type == 'config_change':
            self._handle_config_change(message)
        elif message_type == 'shutdown':
            # Graceful shutdown signal
            pass
        else:
            logger.warning(f"Unknown message type: {message_type} for device {self.device.name}")
    
    def _handle_arp_request(self, message: Dict[str, Any]):
        """Handle ARP request."""
        target_ip = message.get('target_ip')
        source_ip = message.get('source_ip')
        source_device = message.get('source_device')
        
        # Check if this device has the requested IP
        for interface in self.device.interfaces.values():
            if interface.ip_address == target_ip and interface.is_up:
                # Send ARP reply
                reply_message = {
                    'type': 'arp_reply',
                    'source_device': self.device.name,
                    'target_device': source_device,
                    'source_ip': target_ip,
                    'target_ip': source_ip,
                    'mac_address': interface.mac_address or f"MAC_{self.device.name}",
                    'timestamp': time.time()
                }
                
                self.simulation_engine.send_device_message(source_device, reply_message)
                logger.debug(f"ARP reply sent from {self.device.name} to {source_device}")
                break
    
    def _handle_arp_reply(self, message: Dict[str, Any]):
        """Handle ARP reply."""
        source_ip = message.get('source_ip')
        mac_address = message.get('mac_address')
        
        if source_ip and mac_address:
            # Update ARP table
            self.statistics.arp_table[source_ip] = mac_address
            logger.debug(f"ARP table updated on {self.device.name}: {source_ip} -> {mac_address}")
    
    def _handle_neighbor_hello(self, message: Dict[str, Any]):
        """Handle neighbor hello message."""
        source_device = message.get('source_device')
        timestamp = message.get('timestamp', time.time())
        
        # Update neighbor table
        self.statistics.neighbor_table[source_device] = timestamp
        
        logger.debug(f"Neighbor hello received: {self.device.name} <- {source_device}")
    
    def _handle_packet(self, message: Dict[str, Any]):
        """Handle packet transmission."""
        packet_size = message.get('size', 1500)
        source = message.get('source')
        
        self.statistics.packets_received += 1
        self.statistics.bytes_received += packet_size
        
        # Simple packet processing simulation
        processing_delay = packet_size / 1000000.0  # Simulate processing time
        time.sleep(processing_delay)
        
        logger.debug(f"Packet processed by {self.device.name} from {source}")
    
    def _handle_config_change(self, message: Dict[str, Any]):
        """Handle configuration changes."""
        changes = message.get('changes', {})
        
        # Apply configuration changes
        for key, value in changes.items():
            if key == 'interface_status':
                interface_name = value.get('interface')
                new_status = value.get('status')
                
                if interface_name in self.device.interfaces:
                    interface = self.device.interfaces[interface_name]
                    old_status = interface.status
                    interface.status = InterfaceStatus(new_status)
                    
                    logger.info(f"Interface {interface_name} on {self.device.name} "
                               f"changed from {old_status.value} to {new_status}")
        
        logger.info(f"Configuration updated on {self.device.name}")
    
    def _perform_periodic_tasks(self):
        """Perform periodic device tasks."""
        current_time = time.time()
        
        # Clean up old neighbors (simple timeout mechanism)
        timeout_threshold = 60.0  # 60 seconds timeout
        expired_neighbors = []
        
        for neighbor, last_seen in self.statistics.neighbor_table.items():
            if current_time - last_seen > timeout_threshold:
                expired_neighbors.append(neighbor)
        
        for neighbor in expired_neighbors:
            del self.statistics.neighbor_table[neighbor]
            logger.debug(f"Neighbor timeout: {neighbor} removed from {self.device.name}")
    
    def send_message(self, message: Dict[str, Any]):
        """Send a message to this device."""
        self.device_queue.put(message)
    
    def stop(self):
        """Stop the device thread."""
        self.stop_flag.set()
        
        # Send a dummy message to wake up the thread if it's waiting
        try:
            self.device_queue.put({'type': 'shutdown'}, block=False)
        except queue.Full:
            pass


class NetworkSimulationEngine:
    """
    Main network simulation engine.
    
    This class orchestrates the entire network simulation, managing devices,
    events, and providing fault injection capabilities.
    """
    
    def __init__(self, real_time_factor: float = 1.0):
        """
        Initialize the simulation engine.
        
        Args:
            real_time_factor: Factor to control simulation speed relative to real time
        """
        self.real_time_factor = real_time_factor
        self.state = SimulationState.INITIALIZED
        
        # Core components
        self.event_scheduler = EventScheduler(real_time_factor)
        
        # Network components
        self.devices: Dict[str, NetworkDevice] = {}
        self.device_threads: Dict[str, DeviceThread] = {}
        self.device_statistics: Dict[str, DeviceStatistics] = {}
        self.links: Dict[str, Dict[str, Any]] = {}
        self.link_statistics: Dict[str, LinkStatistics] = {}
        
        # Simulation data
        self.simulation_start_time: Optional[float] = None
        self.simulation_end_time: Optional[float] = None
        self.fault_injection_log: List[Dict[str, Any]] = []
        
        # Configuration
        self.config: Dict[str, Any] = {}
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Register event handlers
        self._register_event_handlers()
        
        logger.info(f"Network simulation engine initialized (real-time factor: {real_time_factor})")
    
    def _register_event_handlers(self):
        """Register event handlers with the event scheduler."""
        self.event_scheduler.register_event_handler(
            EventType.ARP_REQUEST, self._handle_arp_request_event
        )
        self.event_scheduler.register_event_handler(
            EventType.NEIGHBOR_DISCOVERY, self._handle_neighbor_discovery_event
        )
        self.event_scheduler.register_event_handler(
            EventType.OSPF_HELLO, self._handle_ospf_hello_event
        )
        self.event_scheduler.register_event_handler(
            EventType.LINK_FAILURE, self._handle_link_failure_event
        )
        self.event_scheduler.register_event_handler(
            EventType.LINK_RECOVERY, self._handle_link_recovery_event
        )
        self.event_scheduler.register_event_handler(
            EventType.MTU_MISMATCH, self._handle_mtu_mismatch_event
        )
        self.event_scheduler.register_event_handler(
            EventType.CONFIG_CHANGE, self._handle_config_change_event
        )
        self.event_scheduler.register_event_handler(
            EventType.PACKET_DROP, self._handle_packet_drop_event
        )
    
    def add_device(self, device: NetworkDevice):
        """Add a network device to the simulation."""
        with self.lock:
            if device.name in self.devices:
                raise ValueError(f"Device {device.name} already exists in simulation")
            
            self.devices[device.name] = device
            self.device_statistics[device.name] = DeviceStatistics(device.name)
            
            # Create device thread if simulation is running
            if self.state in [SimulationState.RUNNING, SimulationState.PAUSED]:
                self._start_device_thread(device)
            
            logger.info(f"Added device to simulation: {device.name} ({device.device_type.value})")
    
    def remove_device(self, device_name: str):
        """Remove a network device from the simulation."""
        with self.lock:
            if device_name not in self.devices:
                logger.warning(f"Device {device_name} not found in simulation")
                return
            
            # Stop device thread if running
            if device_name in self.device_threads:
                self._stop_device_thread(device_name)
            
            # Remove device data
            del self.devices[device_name]
            del self.device_statistics[device_name]
            
            # Remove links involving this device
            links_to_remove = []
            for link_id, link_info in self.links.items():
                if (link_info['source'] == device_name or 
                    link_info['target'] == device_name):
                    links_to_remove.append(link_id)
            
            for link_id in links_to_remove:
                self.remove_link(link_id)
            
            logger.info(f"Removed device from simulation: {device_name}")
    
    def add_link(self, link_id: str, source_device: str, target_device: str, 
                 link_properties: Optional[Dict[str, Any]] = None):
        """Add a link between two devices."""
        with self.lock:
            if link_id in self.links:
                raise ValueError(f"Link {link_id} already exists")
            
            if source_device not in self.devices or target_device not in self.devices:
                raise ValueError("Both devices must exist before creating a link")
            
            link_info = {
                'source': source_device,
                'target': target_device,
                'properties': link_properties or {},
                'active': True,
                'created_at': time.time()
            }
            
            self.links[link_id] = link_info
            self.link_statistics[link_id] = LinkStatistics(
                link_id=link_id,
                source_device=source_device,
                target_device=target_device
            )
            
            logger.info(f"Added link: {link_id} ({source_device} <-> {target_device})")
    
    def remove_link(self, link_id: str):
        """Remove a link from the simulation."""
        with self.lock:
            if link_id not in self.links:
                logger.warning(f"Link {link_id} not found")
                return
            
            del self.links[link_id]
            if link_id in self.link_statistics:
                del self.link_statistics[link_id]
            
            logger.info(f"Removed link: {link_id}")
    
    def _start_device_thread(self, device: NetworkDevice):
        """Start a device thread."""
        if device.name not in self.device_threads:
            device_thread = DeviceThread(device, self)
            device_thread.start()
            self.device_threads[device.name] = device_thread
            logger.debug(f"Started device thread: {device.name}")
    
    def _stop_device_thread(self, device_name: str):
        """Stop a device thread."""
        if device_name in self.device_threads:
            device_thread = self.device_threads[device_name]
            device_thread.stop()
            device_thread.join(timeout=5.0)  # Wait up to 5 seconds
            
            if device_thread.is_alive():
                logger.warning(f"Device thread {device_name} did not stop gracefully")
            
            del self.device_threads[device_name]
            logger.debug(f"Stopped device thread: {device_name}")
    
    def load_configuration(self, config: Dict[str, Any]):
        """Load simulation configuration."""
        self.config = copy.deepcopy(config)
        
        # Load devices from configuration
        if 'devices' in config:
            for device_config in config['devices']:
                device = self._create_device_from_config(device_config)
                if device:
                    self.add_device(device)
        
        # Load links from configuration
        if 'links' in config:
            for link_config in config['links']:
                link_id = link_config.get('id', f"link_{len(self.links)}")
                source = link_config.get('source')
                target = link_config.get('target')
                properties = link_config.get('properties', {})
                
                if source and target:
                    try:
                        self.add_link(link_id, source, target, properties)
                    except ValueError as e:
                        logger.error(f"Failed to create link {link_id}: {e}")
                else:
                    logger.warning(f"Link {link_id} missing source or target")
        
        logger.info(f"Loaded configuration with {len(self.devices)} devices and {len(self.links)} links")
    
    def _create_device_from_config(self, device_config: Dict[str, Any]) -> Optional[NetworkDevice]:
        """Create a device from configuration."""
        try:
            device_info = device_config.get('device', {})
            device_type = device_info.get('type', '').lower()
            device_name = device_info.get('name', 'unknown')
            
            if device_type == 'router':
                device = Router(device_name)
            elif device_type == 'switch':
                device = Switch(device_name)
            else:
                logger.error(f"Unsupported device type: {device_type}")
                return None
            
            # Add interfaces
            for interface_config in device_config.get('interfaces', []):
                interface = NetworkInterface(
                    name=interface_config.get('name', 'eth0'),
                    ip_address=interface_config.get('ip_address'),
                    subnet_mask=interface_config.get('subnet_mask'),
                    status=InterfaceStatus(interface_config.get('status', 'up'))
                )
                device.add_interface(interface)
            
            return device
            
        except Exception as e:
            logger.error(f"Error creating device from config: {e}")
            return None
    
    def start_simulation(self, duration: Optional[float] = None):
        """Start the network simulation."""
        if self.state != SimulationState.INITIALIZED:
            raise RuntimeError(f"Cannot start simulation in state: {self.state.value}")
        
        self.state = SimulationState.STARTING
        self.simulation_start_time = time.time()
        
        logger.info("Starting network simulation...")
        
        # Start device threads
        for device in self.devices.values():
            self._start_device_thread(device)
        
        # Schedule initial events
        self._schedule_initial_events()
        
        self.state = SimulationState.RUNNING
        
        # Run the event scheduler
        try:
            self.event_scheduler.run(until=duration)
            
            if duration:
                self.simulation_end_time = time.time()
                self.state = SimulationState.STOPPED
                actual_sim_time = self.event_scheduler.get_current_time()
                logger.info(f"Simulation completed after {actual_sim_time} time units (requested: {duration})")
            else:
                actual_sim_time = self.event_scheduler.get_current_time()
                logger.info(f"Simulation completed after {actual_sim_time} time units")
            
        except Exception as e:
            logger.error(f"Simulation error: {e}")
            self.state = SimulationState.ERROR
            raise
        finally:
            self._cleanup_simulation()
    
    def _schedule_initial_events(self):
        """Schedule initial Day-1 simulation events."""
        current_time = self.event_scheduler.get_current_time()
        
        # Schedule ARP requests for each device
        for device_name, device in self.devices.items():
            for interface in device.get_active_interfaces():
                if interface.ip_address and interface.subnet_mask:
                    # Generate ARP request for default gateway (simplified)
                    gateway_ip = self._get_default_gateway_ip(interface.ip_address, interface.subnet_mask)
                    
                    if gateway_ip:
                        arp_event = ARPRequestEvent(
                            timestamp=current_time + 1.0,  # Start after 1 second
                            source_device=device_name,
                            target_ip=gateway_ip,
                            source_ip=interface.ip_address,
                            interface=interface.name
                        )
                        self.event_scheduler.schedule_event(arp_event)
        
        # Schedule neighbor discovery events
        for device_name in self.devices.keys():
            neighbor_event = NeighborDiscoveryEvent(
                timestamp=current_time + 2.0,  # Start after 2 seconds
                source_device=device_name
            )
            self.event_scheduler.schedule_event(neighbor_event)
        
        # Schedule periodic OSPF hello events for routers
        for device_name, device in self.devices.items():
            if device.device_type == DeviceType.ROUTER:
                for neighbor in self.find_neighbors(device_name):
                    hello_event = OSPFHelloEvent(
                        timestamp=current_time + 5.0,
                        source_device=device_name,
                        target_device=neighbor
                    )
                    
                    # Make it periodic
                    self.event_scheduler.schedule_periodic_event(
                        hello_event,
                        interval=10.0,
                        event_id=f"ospf_hello_{device_name}_{neighbor}"
                    )
        
        logger.info("Initial Day-1 events scheduled")
    
    def _get_default_gateway_ip(self, ip_address: str, subnet_mask: str) -> Optional[str]:
        """Get the default gateway IP for a given IP and subnet mask."""
        # Simplified implementation - just increment the host part
        try:
            from ipaddress import IPv4Network, IPv4Address
            network = IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
            # Use the first available IP in the network as gateway
            gateway = network.network_address + 1
            return str(gateway)
        except Exception:
            return None
    
    def pause_simulation(self):
        """Pause the simulation."""
        if self.state == SimulationState.RUNNING:
            self.event_scheduler.pause()
            self.state = SimulationState.PAUSED
            logger.info("Simulation paused")
        else:
            logger.warning(f"Cannot pause simulation in state: {self.state.value}")
    
    def resume_simulation(self):
        """Resume the simulation."""
        if self.state == SimulationState.PAUSED:
            self.event_scheduler.resume()
            self.state = SimulationState.RUNNING
            logger.info("Simulation resumed")
        else:
            logger.warning(f"Cannot resume simulation in state: {self.state.value}")
    
    def stop_simulation(self):
        """Stop the simulation."""
        if self.state in [SimulationState.RUNNING, SimulationState.PAUSED]:
            self.state = SimulationState.STOPPING
            self.event_scheduler.stop()
            self._cleanup_simulation()
            self.state = SimulationState.STOPPED
            self.simulation_end_time = time.time()
            logger.info("Simulation stopped")
        else:
            logger.warning(f"Cannot stop simulation in state: {self.state.value}")
    
    def _cleanup_simulation(self):
        """Clean up simulation resources."""
        # Stop all device threads
        for device_name in list(self.device_threads.keys()):
            self._stop_device_thread(device_name)
    
    # Event handlers
    def _handle_arp_request_event(self, event: ARPRequestEvent) -> List[NetworkEvent]:
        """Handle ARP request event."""
        # Send ARP request message to all devices
        message = {
            'type': 'arp_request',
            'source_device': event.source_device,
            'target_ip': event.data['target_ip'],
            'source_ip': event.data['source_ip'],
            'timestamp': event.timestamp
        }
        
        # Broadcast to all devices in the same network
        for device_name in self.devices.keys():
            if device_name != event.source_device:
                self.send_device_message(device_name, message)
        
        return []
    
    def _handle_neighbor_discovery_event(self, event: NeighborDiscoveryEvent) -> List[NetworkEvent]:
        """Handle neighbor discovery event."""
        neighbors = self.find_neighbors(event.source_device)
        
        for neighbor in neighbors:
            # Send hello message
            message = {
                'type': 'neighbor_hello',
                'source_device': event.source_device,
                'timestamp': event.timestamp
            }
            self.send_device_message(neighbor, message)
        
        return []
    
    def _handle_ospf_hello_event(self, event: OSPFHelloEvent) -> List[NetworkEvent]:
        """Handle OSPF hello event."""
        if event.target_device:
            message = {
                'type': 'neighbor_hello',
                'source_device': event.source_device,
                'protocol': 'OSPF',
                'timestamp': event.timestamp
            }
            self.send_device_message(event.target_device, message)
        
        return []
    
    def _handle_link_failure_event(self, event: LinkFailureEvent) -> List[NetworkEvent]:
        """Handle link failure event."""
        # Call the event's own process method to handle link disabling and recovery scheduling
        new_events = event.process(self)
        
        # Log the failure
        link_id = event.data['link_id']
        failure_info = {
            'type': 'link_failure',
            'link_id': link_id,
            'timestamp': event.timestamp,
            'duration': event.duration
        }
        self.fault_injection_log.append(failure_info)
        
        return new_events
    
    def _handle_link_recovery_event(self, event: LinkRecoveryEvent) -> List[NetworkEvent]:
        """Handle link recovery event."""
        # Call the event's own process method to handle link enabling
        new_events = event.process(self)
        
        # Log the recovery
        link_id = event.data['link_id']
        recovery_info = {
            'type': 'link_recovery',
            'link_id': link_id,
            'timestamp': event.timestamp
        }
        self.fault_injection_log.append(recovery_info)
        
        return new_events
    
    def _handle_mtu_mismatch_event(self, event: MTUMismatchEvent) -> List[NetworkEvent]:
        """Handle MTU mismatch event."""
        # Call the event's own process method to handle MTU mismatch logic
        new_events = event.process(self)
        
        # Additional logging for simulation engine
        logger.info(f"MTU mismatch handled: {event.source_device} -> {event.target_device} "
                   f"packet_size={event.data['packet_size']}, mtu={event.data['interface_mtu']}")
        
        return new_events
    
    def _handle_config_change_event(self, event: ConfigChangeEvent) -> List[NetworkEvent]:
        """Handle configuration change event."""
        # Call the event's own process method to handle configuration changes
        new_events = event.process(self)
        
        # Send config change message to device
        device_name = event.target_device
        changes = event.parameters
        message = {
            'type': 'config_change',
            'changes': changes,
            'timestamp': event.timestamp
        }
        
        if device_name:
            self.send_device_message(device_name, message)
        
        return new_events
    
    def _handle_packet_drop_event(self, event: PacketDropEvent) -> List[NetworkEvent]:
        """Handle packet drop event."""
        # Call the event's own process method to handle packet drop recording
        new_events = event.process(self)
        
        logger.debug(f"Packet drop processed: {event.source_device} -> {event.target_device} "
                    f"({event.data['reason']})")
        
        return new_events
    
    # Utility methods for simulation
    def find_devices_by_ip(self, ip_address: str) -> List[str]:
        """Find devices that have the specified IP address."""
        matching_devices = []
        
        for device_name, device in self.devices.items():
            for interface in device.interfaces.values():
                if interface.ip_address == ip_address and interface.is_up:
                    matching_devices.append(device_name)
                    break
        
        return matching_devices
    
    def find_neighbors(self, device_name: str) -> List[str]:
        """Find neighboring devices connected via links."""
        neighbors = []
        
        for link_info in self.links.values():
            if not link_info['active']:
                continue
                
            if link_info['source'] == device_name:
                neighbors.append(link_info['target'])
            elif link_info['target'] == device_name:
                neighbors.append(link_info['source'])
        
        return neighbors
    
    def send_device_message(self, device_name: str, message: Dict[str, Any]):
        """Send a message to a device thread."""
        if device_name in self.device_threads:
            self.device_threads[device_name].send_message(message)
        else:
            logger.warning(f"Device thread not found: {device_name}")
    
    def update_arp_table(self, device_name: str, ip_address: str, mac_address: str, interface: str):
        """Update ARP table for a device."""
        if device_name in self.device_statistics:
            self.device_statistics[device_name].arp_table[ip_address] = mac_address
            logger.debug(f"ARP table updated for {device_name}: {ip_address} -> {mac_address}")
    
    def add_neighbor_relationship(self, device1: str, device2: str):
        """Add bidirectional neighbor relationship."""
        timestamp = time.time()
        
        if device1 in self.device_statistics:
            self.device_statistics[device1].neighbor_table[device2] = timestamp
        
        if device2 in self.device_statistics:
            self.device_statistics[device2].neighbor_table[device1] = timestamp
    
    def update_neighbor_timestamp(self, device_name: str, neighbor: str, timestamp: float):
        """Update neighbor last-seen timestamp."""
        if device_name in self.device_statistics:
            self.device_statistics[device_name].neighbor_table[neighbor] = timestamp
    
    def disable_link(self, link_id: str, timestamp: float):
        """Disable a network link."""
        if link_id in self.links:
            self.links[link_id]['active'] = False
            
            if link_id in self.link_statistics:
                self.link_statistics[link_id].is_active = False
                self.link_statistics[link_id].failure_count += 1
                self.link_statistics[link_id].last_failure = timestamp
            
            logger.warning(f"Link disabled: {link_id}")
    
    def enable_link(self, link_id: str, timestamp: float):
        """Enable a network link."""
        if link_id in self.links:
            self.links[link_id]['active'] = True
            
            if link_id in self.link_statistics:
                self.link_statistics[link_id].is_active = True
                self.link_statistics[link_id].recovery_count += 1
                self.link_statistics[link_id].last_recovery = timestamp
            
            logger.info(f"Link enabled: {link_id}")
    
    def record_packet_drop(self, source_device: str, target_device: str, reason: str, timestamp: float):
        """Record packet drop statistics."""
        if source_device in self.device_statistics:
            self.device_statistics[source_device].packets_dropped += 1
        
        logger.debug(f"Packet drop recorded: {source_device} -> {target_device} ({reason})")
    
    def apply_config_changes(self, device_name: str, changes: Dict[str, Any], timestamp: float):
        """Apply configuration changes to a device."""
        # This method would interact with the actual device configuration
        # For now, we'll just log the changes
        logger.info(f"Applied config changes to {device_name}: {changes}")
    
    # Fault injection methods
    def inject_link_failure(self, link_id: str, duration: Optional[float] = None, 
                           delay: float = 0.0) -> str:
        """
        Inject a link failure fault.
        
        Args:
            link_id: ID of the link to fail
            duration: Duration of failure (None for permanent)
            delay: Delay before failure occurs
            
        Returns:
            Event ID for tracking
        """
        if link_id not in self.links:
            raise ValueError(f"Link {link_id} not found")
        
        failure_event = LinkFailureEvent(
            timestamp=self.event_scheduler.get_current_time() + delay,
            link_id=link_id,
            duration=duration
        )
        
        self.event_scheduler.schedule_event(failure_event)
        
        logger.info(f"Link failure scheduled: {link_id} "
                   f"(delay={delay}, duration={duration})")
        
        return failure_event.event_id
    
    def inject_mtu_mismatch(self, source_device: str, target_device: str, 
                           packet_size: int, interface_mtu: int, delay: float = 0.0) -> str:
        """
        Inject an MTU mismatch fault.
        
        Args:
            source_device: Source device name
            target_device: Target device name
            packet_size: Size of the packet
            interface_mtu: MTU of the interface
            delay: Delay before mismatch occurs
            
        Returns:
            Event ID for tracking
        """
        mismatch_event = MTUMismatchEvent(
            timestamp=self.event_scheduler.get_current_time() + delay,
            source_device=source_device,
            target_device=target_device,
            packet_size=packet_size,
            interface_mtu=interface_mtu
        )
        
        self.event_scheduler.schedule_event(mismatch_event)
        
        logger.info(f"MTU mismatch scheduled: {source_device} -> {target_device} "
                   f"(packet_size={packet_size}, mtu={interface_mtu})")
        
        return mismatch_event.event_id
    
    def change_device_configuration(self, device_name: str, changes: Dict[str, Any], 
                                   delay: float = 0.0) -> str:
        """
        Change device configuration during simulation.
        
        Args:
            device_name: Name of the device to configure
            changes: Configuration changes to apply
            delay: Delay before changes are applied
            
        Returns:
            Event ID for tracking
        """
        config_event = ConfigChangeEvent(
            timestamp=self.event_scheduler.get_current_time() + delay,
            target_device=device_name,
            config_changes=changes
        )
        
        self.event_scheduler.schedule_event(config_event)
        
        logger.info(f"Configuration change scheduled for {device_name}: {changes}")
        
        return config_event.event_id
    
    # Results and analysis methods
    def get_simulation_summary(self) -> Dict[str, Any]:
        """Get a comprehensive simulation summary."""
        current_time = self.event_scheduler.get_current_time()
        
        # Device statistics summary
        device_summary = {}
        for device_name, stats in self.device_statistics.items():
            device_summary[device_name] = {
                'packets_sent': stats.packets_sent,
                'packets_received': stats.packets_received,
                'packets_dropped': stats.packets_dropped,
                'bytes_sent': stats.bytes_sent,
                'bytes_received': stats.bytes_received,
                'events_processed': stats.events_processed,
                'arp_table_size': len(stats.arp_table),
                'neighbor_count': len(stats.neighbor_table),
                'last_activity': stats.last_activity
            }
        
        # Link statistics summary
        link_summary = {}
        for link_id, stats in self.link_statistics.items():
            link_summary[link_id] = {
                'is_active': stats.is_active,
                'packets_transmitted': stats.packets_transmitted,
                'bytes_transmitted': stats.bytes_transmitted,
                'failure_count': stats.failure_count,
                'recovery_count': stats.recovery_count
            }
        
        return {
            'simulation_state': self.state.value,
            'simulation_time': current_time,
            'real_time_elapsed': (time.time() - self.simulation_start_time) if self.simulation_start_time else 0,
            'devices': device_summary,
            'links': link_summary,
            'event_metrics': self.event_scheduler.get_event_summary(),
            'fault_injection_log': self.fault_injection_log,
            'total_devices': len(self.devices),
            'total_links': len(self.links),
            'active_links': sum(1 for link in self.links.values() if link['active'])
        }
    
    def export_results(self, output_file: str, format: str = 'json'):
        """
        Export simulation results to file.
        
        Args:
            output_file: Path to output file
            format: Output format ('json', 'csv')
        """
        summary = self.get_simulation_summary()
        
        if format.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
        elif format.lower() == 'csv':
            import pandas as pd
            
            # Create DataFrames for different aspects
            device_df = pd.DataFrame.from_dict(summary['devices'], orient='index')
            link_df = pd.DataFrame.from_dict(summary['links'], orient='index')
            
            # Write to CSV (multiple sheets would require Excel format)
            device_df.to_csv(output_file.replace('.csv', '_devices.csv'))
            link_df.to_csv(output_file.replace('.csv', '_links.csv'))
            
            # Write summary info
            with open(output_file.replace('.csv', '_summary.txt'), 'w') as f:
                f.write(f"Simulation State: {summary['simulation_state']}\n")
                f.write(f"Simulation Time: {summary['simulation_time']}\n")
                f.write(f"Real Time Elapsed: {summary['real_time_elapsed']}\n")
                f.write(f"Total Devices: {summary['total_devices']}\n")
                f.write(f"Total Links: {summary['total_links']}\n")
                f.write(f"Active Links: {summary['active_links']}\n")
        
        logger.info(f"Results exported to: {output_file}")