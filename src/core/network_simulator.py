#!/usr/bin/env python3
"""
Network Simulator Core Components

This module provides the core network simulation components including
device simulators, packet handling, routing logic, and simulation control.
"""

import logging
import threading
import time
import queue
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import copy

# Import network models
from models.network_models import (
    NetworkDevice, Router, Switch, NetworkInterface, VLAN, 
    RoutingProtocol, DeviceType, InterfaceStatus
)

# Import simulation engine
from simulation.simulation_engine import NetworkSimulationEngine, DeviceThread, DeviceStatistics

logger = logging.getLogger(__name__)


class SimulationMode(Enum):
    """Simulation execution modes."""
    REAL_TIME = "real_time"
    ACCELERATED = "accelerated"
    STEP_BY_STEP = "step_by_step"


@dataclass
class PacketMetrics:
    """Metrics for packet processing."""
    packet_id: str
    source_device: str
    destination_device: str
    packet_type: str
    size_bytes: int
    timestamp_created: float
    timestamp_sent: float = 0.0
    timestamp_received: float = 0.0
    hops: List[str] = field(default_factory=list)
    processing_delays: List[float] = field(default_factory=list)
    dropped: bool = False
    drop_reason: Optional[str] = None


class DeviceSimulator(ABC):
    """Abstract base class for device simulators."""
    
    def __init__(self, device: NetworkDevice, simulation_engine: 'NetworkSimulator'):
        self.device = device
        self.simulation_engine = simulation_engine
        self.statistics = DeviceStatistics(device.name)
        self.packet_queue = queue.Queue()
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        # Protocol-specific tables
        self.arp_table: Dict[str, str] = {}  # IP -> MAC
        self.routing_table: Dict[str, Dict[str, Any]] = {}  # destination -> route info
        self.neighbor_table: Dict[str, float] = {}  # neighbor -> last_seen
        
        logger.debug(f"Created {self.__class__.__name__} for device {device.name}")
    
    @abstractmethod
    def process_packet(self, packet: Dict[str, Any]) -> bool:
        """Process a packet received by this device."""
        pass
    
    @abstractmethod
    def handle_protocol_event(self, event_type: str, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle protocol-specific events (ARP, OSPF, etc.)."""
        pass
    
    def start_simulation(self):
        """Start the device simulation thread."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._simulation_loop, name=f"Sim-{self.device.name}")
            self.thread.daemon = True
            self.thread.start()
            logger.info(f"Started simulation for {self.device.name}")
    
    def stop_simulation(self):
        """Stop the device simulation thread."""
        if self.running:
            self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=2.0)
            logger.info(f"Stopped simulation for {self.device.name}")
    
    def _simulation_loop(self):
        """Main simulation loop for the device."""
        logger.debug(f"Starting simulation loop for {self.device.name}")
        
        try:
            while self.running:
                try:
                    # Process packets from queue
                    packet = self.packet_queue.get(timeout=1.0)
                    self._process_packet_internal(packet)
                    
                except queue.Empty:
                    # Perform periodic tasks during idle time
                    self._perform_periodic_tasks()
                    continue
                    
                except Exception as e:
                    logger.error(f"Error in simulation loop for {self.device.name}: {e}")
                    
        except Exception as e:
            logger.error(f"Critical error in simulation loop for {self.device.name}: {e}")
        finally:
            logger.debug(f"Simulation loop ended for {self.device.name}")
    
    def _process_packet_internal(self, packet: Dict[str, Any]):
        """Internal packet processing with error handling and statistics."""
        start_time = time.time()
        
        try:
            self.statistics.packets_received += 1
            self.statistics.bytes_received += packet.get('size', 0)
            self.statistics.update_activity(start_time)
            
            # Add processing delay simulation
            processing_delay = self._calculate_processing_delay(packet)
            if processing_delay > 0:
                time.sleep(processing_delay)
            
            # Process the packet
            success = self.process_packet(packet)
            
            if success:
                logger.debug(f"Packet processed successfully by {self.device.name}")
            else:
                self.statistics.packets_dropped += 1
                logger.debug(f"Packet dropped by {self.device.name}")
                
        except Exception as e:
            self.statistics.packets_dropped += 1
            logger.error(f"Error processing packet in {self.device.name}: {e}")
    
    def _calculate_processing_delay(self, packet: Dict[str, Any]) -> float:
        """Calculate realistic processing delay for a packet."""
        base_delay = 0.001  # 1ms base delay
        packet_size = packet.get('size', 1500)
        
        # Scale delay based on packet size and device type
        if isinstance(self.device, Switch):
            # Switches are faster for L2 forwarding
            return base_delay * (packet_size / 10000.0)
        elif isinstance(self.device, Router):
            # Routers have higher delay for L3 processing
            return base_delay * (packet_size / 5000.0)
        else:
            return base_delay
    
    def _perform_periodic_tasks(self):
        """Perform periodic maintenance tasks."""
        current_time = time.time()
        
        # Clean up old neighbor entries (60 second timeout)
        timeout_threshold = 60.0
        expired_neighbors = []
        
        with self._lock:
            for neighbor, last_seen in self.neighbor_table.items():
                if current_time - last_seen > timeout_threshold:
                    expired_neighbors.append(neighbor)
            
            for neighbor in expired_neighbors:
                del self.neighbor_table[neighbor]
                logger.debug(f"Neighbor timeout: {neighbor} removed from {self.device.name}")
    
    def send_packet(self, packet: Dict[str, Any]):
        """Send a packet to this device for processing."""
        self.packet_queue.put(packet)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current device statistics."""
        with self._lock:
            return {
                'device_name': self.device.name,
                'device_type': self.device.device_type.value,
                'packets_sent': self.statistics.packets_sent,
                'packets_received': self.statistics.packets_received,
                'packets_dropped': self.statistics.packets_dropped,
                'bytes_sent': self.statistics.bytes_sent,
                'bytes_received': self.statistics.bytes_received,
                'events_processed': self.statistics.events_processed,
                'last_activity': self.statistics.last_activity,
                'arp_table_size': len(self.arp_table),
                'routing_table_size': len(self.routing_table),
                'neighbor_count': len(self.neighbor_table),
                'queue_size': self.packet_queue.qsize()
            }


class RouterSimulator(DeviceSimulator):
    """Simulator for router devices with L3 routing capabilities."""
    
    def __init__(self, device: Router, simulation_engine: 'NetworkSimulator'):
        super().__init__(device, simulation_engine)
        self.ospf_neighbors: Dict[str, Dict[str, Any]] = {}
        self.ospf_hello_interval = 10.0  # seconds
        self.last_ospf_hello = 0.0
        
        # Initialize routing table with directly connected networks
        self._initialize_routing_table()
    
    def _initialize_routing_table(self):
        """Initialize routing table with directly connected networks."""
        with self._lock:
            for interface in self.device.interfaces.values():
                if interface.is_up and interface.ip_address:
                    # Add directly connected route
                    network_addr = self._get_network_address(interface.ip_address, interface.subnet_mask)
                    if network_addr:
                        self.routing_table[network_addr] = {
                            'next_hop': '0.0.0.0',  # Directly connected
                            'interface': interface.name,
                            'metric': 0,
                            'protocol': 'connected',
                            'timestamp': time.time()
                        }
    
    def _get_network_address(self, ip: str, subnet_mask: str) -> Optional[str]:
        """Calculate network address from IP and subnet mask."""
        try:
            # Simple network calculation - could be enhanced with proper IP library
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, subnet_mask.split('.')))
            
            network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            return '.'.join(map(str, network_parts))
        except Exception as e:
            logger.warning(f"Failed to calculate network address for {ip}/{subnet_mask}: {e}")
            return None
    
    def process_packet(self, packet: Dict[str, Any]) -> bool:
        """Process a packet at the router (L3 forwarding)."""
        packet_type = packet.get('type', 'unknown')
        
        if packet_type == 'ip':
            return self._process_ip_packet(packet)
        elif packet_type == 'arp_request':
            return self._process_arp_request(packet)
        elif packet_type == 'arp_reply':
            return self._process_arp_reply(packet)
        elif packet_type == 'ospf_hello':
            return self._process_ospf_hello(packet)
        else:
            logger.debug(f"Unknown packet type {packet_type} received by router {self.device.name}")
            return False
    
    def _process_ip_packet(self, packet: Dict[str, Any]) -> bool:
        """Process an IP packet for routing."""
        dest_ip = packet.get('destination_ip')
        if not dest_ip:
            return False
        
        # Check if packet is for this router
        for interface in self.device.get_active_interfaces():
            if interface.ip_address == dest_ip:
                logger.debug(f"Packet delivered to router {self.device.name}")
                return True
        
        # Find route to destination
        route = self._find_route(dest_ip)
        if route:
            # Forward packet
            next_hop = route['next_hop']
            out_interface = route['interface']
            
            logger.debug(f"Router {self.device.name} forwarding packet to {dest_ip} via {next_hop} on {out_interface}")
            
            # Update packet hop information
            if 'hops' not in packet:
                packet['hops'] = []
            packet['hops'].append(self.device.name)
            
            # Send to next hop (simulation would forward to next device)
            self.statistics.packets_sent += 1
            self.statistics.bytes_sent += packet.get('size', 0)
            
            return True
        else:
            logger.debug(f"No route to {dest_ip} from router {self.device.name}")
            return False
    
    def _find_route(self, dest_ip: str) -> Optional[Dict[str, Any]]:
        """Find the best route to destination IP."""
        with self._lock:
            # Simple longest prefix match simulation
            best_route = None
            best_prefix_len = -1
            
            for network, route in self.routing_table.items():
                if self._ip_in_network(dest_ip, network):
                    # Calculate prefix length (simplified)
                    prefix_len = network.count('0')  # Simplified calculation
                    if prefix_len > best_prefix_len:
                        best_route = route
                        best_prefix_len = prefix_len
            
            return best_route
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network (simplified implementation)."""
        # This is a simplified implementation - in reality would use proper IP calculations
        try:
            ip_parts = list(map(int, ip.split('.')))
            net_parts = list(map(int, network.split('.')))
            
            # Simple check for same first 3 octets (simplified)
            return ip_parts[:3] == net_parts[:3]
        except:
            return False
    
    def _process_arp_request(self, packet: Dict[str, Any]) -> bool:
        """Process ARP request."""
        target_ip = packet.get('target_ip')
        sender_ip = packet.get('sender_ip')
        sender_mac = packet.get('sender_mac', f"mac_{packet.get('source_device', 'unknown')}")
        
        # Update ARP table
        if sender_ip:
            with self._lock:
                self.arp_table[sender_ip] = sender_mac
        
        # Check if we have the target IP
        for interface in self.device.get_active_interfaces():
            if interface.ip_address == target_ip:
                # Send ARP reply
                arp_reply = {
                    'type': 'arp_reply',
                    'source_device': self.device.name,
                    'target_device': packet.get('source_device'),
                    'target_ip': sender_ip,
                    'target_mac': sender_mac,
                    'sender_ip': target_ip,
                    'sender_mac': f"mac_{self.device.name}_{interface.name}",
                    'size': 64,
                    'timestamp': time.time()
                }
                
                # In real simulation, this would be sent via the simulation engine
                logger.debug(f"Router {self.device.name} sending ARP reply for {target_ip}")
                self.statistics.packets_sent += 1
                return True
        
        return False
    
    def _process_arp_reply(self, packet: Dict[str, Any]) -> bool:
        """Process ARP reply."""
        sender_ip = packet.get('sender_ip')
        sender_mac = packet.get('sender_mac')
        
        if sender_ip and sender_mac:
            with self._lock:
                self.arp_table[sender_ip] = sender_mac
            logger.debug(f"Router {self.device.name} updated ARP table: {sender_ip} -> {sender_mac}")
            return True
        
        return False
    
    def _process_ospf_hello(self, packet: Dict[str, Any]) -> bool:
        """Process OSPF hello packet."""
        sender = packet.get('source_device')
        if sender:
            with self._lock:
                self.ospf_neighbors[sender] = {
                    'last_hello': time.time(),
                    'state': 'up'
                }
                self.neighbor_table[sender] = time.time()
            
            logger.debug(f"Router {self.device.name} received OSPF hello from {sender}")
            return True
        
        return False
    
    def handle_protocol_event(self, event_type: str, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle protocol-specific events."""
        events = []
        
        if event_type == 'ospf_hello':
            # Generate OSPF hello packet
            hello_packet = {
                'type': 'ospf_hello',
                'source_device': self.device.name,
                'router_id': self.device.name,
                'area_id': event_data.get('area_id', '0.0.0.0'),
                'hello_interval': self.ospf_hello_interval,
                'size': 64,
                'timestamp': time.time()
            }
            events.append(hello_packet)
        
        return events
    
    def _perform_periodic_tasks(self):
        """Perform router-specific periodic tasks."""
        super()._perform_periodic_tasks()
        
        current_time = time.time()
        
        # Send periodic OSPF hellos
        if current_time - self.last_ospf_hello >= self.ospf_hello_interval:
            self._send_ospf_hellos()
            self.last_ospf_hello = current_time
    
    def _send_ospf_hellos(self):
        """Send OSPF hello messages to neighbors."""
        neighbors = self.simulation_engine.find_neighbors(self.device.name)
        for neighbor in neighbors:
            hello_events = self.handle_protocol_event('ospf_hello', {'neighbor': neighbor})
            for event in hello_events:
                # In real simulation, this would be sent via the simulation engine
                logger.debug(f"Router {self.device.name} sending OSPF hello to {neighbor}")


class SwitchSimulator(DeviceSimulator):
    """Simulator for switch devices with L2 forwarding capabilities."""
    
    def __init__(self, device: Switch, simulation_engine: 'NetworkSimulator'):
        super().__init__(device, simulation_engine)
        self.mac_table: Dict[str, Dict[str, Any]] = {}  # MAC -> {port, timestamp}
        self.vlan_table: Dict[int, Set[str]] = {}  # VLAN ID -> set of ports
        self.stp_enabled = True
        self.stp_state: Dict[str, str] = {}  # port -> STP state
        
        # Initialize VLAN table
        self._initialize_vlan_table()
    
    def _initialize_vlan_table(self):
        """Initialize VLAN table based on interface configuration."""
        with self._lock:
            for interface in self.device.interfaces.values():
                if interface.access_vlan:
                    vlan_id = interface.access_vlan
                    if vlan_id not in self.vlan_table:
                        self.vlan_table[vlan_id] = set()
                    self.vlan_table[vlan_id].add(interface.name)
                
                # Handle trunk VLANs
                for vlan_id in interface.trunk_vlans:
                    if vlan_id not in self.vlan_table:
                        self.vlan_table[vlan_id] = set()
                    self.vlan_table[vlan_id].add(interface.name)
    
    def process_packet(self, packet: Dict[str, Any]) -> bool:
        """Process a packet at the switch (L2 forwarding)."""
        packet_type = packet.get('type', 'unknown')
        
        if packet_type == 'ethernet':
            return self._process_ethernet_frame(packet)
        elif packet_type == 'arp_request':
            return self._process_arp_broadcast(packet)
        else:
            logger.debug(f"Unknown packet type {packet_type} received by switch {self.device.name}")
            return False
    
    def _process_ethernet_frame(self, packet: Dict[str, Any]) -> bool:
        """Process an Ethernet frame for L2 forwarding."""
        src_mac = packet.get('source_mac')
        dst_mac = packet.get('destination_mac')
        in_port = packet.get('in_port')
        vlan_id = packet.get('vlan_id', 1)  # Default VLAN 1
        
        if not src_mac or not in_port:
            return False
        
        # Learn source MAC address
        self._learn_mac_address(src_mac, in_port, vlan_id)
        
        # Forward based on destination MAC
        if dst_mac:
            if dst_mac == 'ff:ff:ff:ff:ff:ff' or dst_mac.startswith('01:00:5e'):
                # Broadcast or multicast - flood to all ports in VLAN
                return self._flood_frame(packet, in_port, vlan_id)
            else:
                # Unicast - lookup in MAC table
                out_port = self._lookup_mac_address(dst_mac, vlan_id)
                if out_port and out_port != in_port:
                    return self._forward_frame(packet, out_port)
                else:
                    # MAC not learned - flood to all ports in VLAN
                    return self._flood_frame(packet, in_port, vlan_id)
        
        return False
    
    def _learn_mac_address(self, mac: str, port: str, vlan_id: int):
        """Learn MAC address on a port."""
        with self._lock:
            self.mac_table[mac] = {
                'port': port,
                'vlan_id': vlan_id,
                'timestamp': time.time()
            }
        logger.debug(f"Switch {self.device.name} learned MAC {mac} on port {port} VLAN {vlan_id}")
    
    def _lookup_mac_address(self, mac: str, vlan_id: int) -> Optional[str]:
        """Lookup MAC address in the MAC table."""
        with self._lock:
            entry = self.mac_table.get(mac)
            if entry and entry['vlan_id'] == vlan_id:
                # Check if entry is still fresh (5 minutes aging)
                if time.time() - entry['timestamp'] < 300:
                    return entry['port']
                else:
                    # Age out old entry
                    del self.mac_table[mac]
        return None
    
    def _forward_frame(self, packet: Dict[str, Any], out_port: str) -> bool:
        """Forward frame to specific port."""
        logger.debug(f"Switch {self.device.name} forwarding frame to port {out_port}")
        self.statistics.packets_sent += 1
        self.statistics.bytes_sent += packet.get('size', 0)
        return True
    
    def _flood_frame(self, packet: Dict[str, Any], in_port: str, vlan_id: int) -> bool:
        """Flood frame to all ports in VLAN except incoming port."""
        ports_in_vlan = self.vlan_table.get(vlan_id, set())
        flooded = False
        
        for port in ports_in_vlan:
            if port != in_port:
                # Check STP state if enabled
                if self.stp_enabled:
                    stp_state = self.stp_state.get(port, 'forwarding')
                    if stp_state != 'forwarding':
                        continue
                
                logger.debug(f"Switch {self.device.name} flooding frame to port {port}")
                self.statistics.packets_sent += 1
                self.statistics.bytes_sent += packet.get('size', 0)
                flooded = True
        
        return flooded
    
    def _process_arp_broadcast(self, packet: Dict[str, Any]) -> bool:
        """Process ARP broadcast (flood to all ports)."""
        in_port = packet.get('in_port', 'unknown')
        vlan_id = packet.get('vlan_id', 1)
        
        # Flood ARP request to all ports in VLAN
        return self._flood_frame(packet, in_port, vlan_id)
    
    def handle_protocol_event(self, event_type: str, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle protocol-specific events."""
        events = []
        
        if event_type == 'stp_hello':
            # Generate STP BPDU
            bpdu = {
                'type': 'stp_bpdu',
                'source_device': self.device.name,
                'bridge_id': f"{self.device.name}_bridge",
                'root_id': event_data.get('root_id', f"{self.device.name}_bridge"),
                'cost': event_data.get('cost', 0),
                'size': 64,
                'timestamp': time.time()
            }
            events.append(bpdu)
        
        return events
    
    def _perform_periodic_tasks(self):
        """Perform switch-specific periodic tasks."""
        super()._perform_periodic_tasks()
        
        current_time = time.time()
        
        # Age out old MAC table entries (5 minute timeout)
        with self._lock:
            expired_macs = []
            for mac, entry in self.mac_table.items():
                if current_time - entry['timestamp'] > 300:  # 5 minutes
                    expired_macs.append(mac)
            
            for mac in expired_macs:
                del self.mac_table[mac]
                logger.debug(f"Switch {self.device.name} aged out MAC {mac}")


class NetworkSimulator:
    """Main network simulator coordinating device simulators and simulation control."""
    
    def __init__(self, real_time_factor: float = 1.0):
        self.simulation_engine = NetworkSimulationEngine(real_time_factor)
        self.device_simulators: Dict[str, DeviceSimulator] = {}
        self.mode = SimulationMode.REAL_TIME
        self.packet_metrics: Dict[str, PacketMetrics] = {}
        self._packet_counter = 0
        self._lock = threading.RLock()
        
        logger.info(f"NetworkSimulator initialized with real-time factor {real_time_factor}")
    
    def add_device(self, device: NetworkDevice):
        """Add a device to the simulation."""
        self.simulation_engine.add_device(device)
        
        # Create appropriate device simulator
        if isinstance(device, Router):
            simulator = RouterSimulator(device, self)
        elif isinstance(device, Switch):
            simulator = SwitchSimulator(device, self)
        else:
            # Generic device simulator
            simulator = DeviceSimulator(device, self)
        
        with self._lock:
            self.device_simulators[device.name] = simulator
        
        logger.info(f"Added device {device.name} to simulation")
    
    def remove_device(self, device_name: str):
        """Remove a device from the simulation."""
        with self._lock:
            if device_name in self.device_simulators:
                simulator = self.device_simulators[device_name]
                simulator.stop_simulation()
                del self.device_simulators[device_name]
        
        self.simulation_engine.remove_device(device_name)
        logger.info(f"Removed device {device_name} from simulation")
    
    def add_link(self, link_id: str, source_device: str, target_device: str, 
                 link_properties: Optional[Dict[str, Any]] = None):
        """Add a link between two devices."""
        self.simulation_engine.add_link(link_id, source_device, target_device, link_properties)
        logger.info(f"Added link {link_id} between {source_device} and {target_device}")
    
    def start_simulation(self):
        """Start the network simulation."""
        logger.info("Starting network simulation...")
        
        # Start device simulators
        for simulator in self.device_simulators.values():
            simulator.start_simulation()
        
        # Start the simulation engine
        self.simulation_engine.start_simulation()
        
        logger.info("Network simulation started")
    
    def stop_simulation(self):
        """Stop the network simulation."""
        logger.info("Stopping network simulation...")
        
        # Stop device simulators
        for simulator in self.device_simulators.values():
            simulator.stop_simulation()
        
        # Stop the simulation engine
        self.simulation_engine.stop_simulation()
        
        logger.info("Network simulation stopped")
    
    def pause_simulation(self):
        """Pause the network simulation."""
        self.simulation_engine.pause_simulation()
        logger.info("Network simulation paused")
    
    def resume_simulation(self):
        """Resume the network simulation."""
        self.simulation_engine.resume_simulation()
        logger.info("Network simulation resumed")
    
    def find_neighbors(self, device_name: str) -> List[str]:
        """Find neighboring devices."""
        return self.simulation_engine.find_neighbors(device_name)
    
    def get_simulation_statistics(self) -> Dict[str, Any]:
        """Get comprehensive simulation statistics."""
        device_stats = {}
        
        with self._lock:
            for name, simulator in self.device_simulators.items():
                device_stats[name] = simulator.get_statistics()
        
        engine_stats = self.simulation_engine.get_simulation_summary()
        
        return {
            'device_statistics': device_stats,
            'engine_statistics': engine_stats,
            'total_devices': len(self.device_simulators),
            'total_packets_tracked': len(self.packet_metrics),
            'simulation_mode': self.mode.value
        }
    
    def inject_fault(self, fault_type: str, **kwargs) -> str:
        """Inject a fault into the simulation."""
        if fault_type == 'link_failure':
            return self.simulation_engine.inject_link_failure(
                kwargs.get('link_id'),
                kwargs.get('duration', 10.0),
                kwargs.get('delay', 0.0)
            )
        elif fault_type == 'mtu_mismatch':
            return self.simulation_engine.inject_mtu_mismatch(
                kwargs.get('source_device'),
                kwargs.get('target_device'),
                kwargs.get('packet_size', 1600),
                kwargs.get('interface_mtu', 1500),
                kwargs.get('delay', 0.0)
            )
        elif fault_type == 'config_change':
            return self.simulation_engine.change_device_configuration(
                kwargs.get('device_name'),
                kwargs.get('changes', {}),
                kwargs.get('delay', 0.0)
            )
        else:
            raise ValueError(f"Unknown fault type: {fault_type}")
    
    def generate_traffic(self, source: str, destination: str, packet_type: str = 'ip', 
                        size: int = 1500, count: int = 1) -> List[str]:
        """Generate traffic between devices."""
        packet_ids = []
        
        for i in range(count):
            packet_id = f"pkt_{self._packet_counter}_{int(time.time() * 1000000)}"
            self._packet_counter += 1
            
            packet = {
                'id': packet_id,
                'type': packet_type,
                'source_device': source,
                'destination_device': destination,
                'size': size,
                'timestamp': time.time(),
                'sequence': i
            }
            
            # Send packet to source device
            if source in self.device_simulators:
                self.device_simulators[source].send_packet(packet)
                packet_ids.append(packet_id)
                
                # Track packet metrics
                with self._lock:
                    self.packet_metrics[packet_id] = PacketMetrics(
                        packet_id=packet_id,
                        source_device=source,
                        destination_device=destination,
                        packet_type=packet_type,
                        size_bytes=size,
                        timestamp_created=time.time()
                    )
        
        return packet_ids