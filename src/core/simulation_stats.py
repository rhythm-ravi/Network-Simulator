#!/usr/bin/env python3
"""
Simulation Statistics and Monitoring for Network Simulator

This module provides comprehensive statistics tracking and reporting for
network simulation including traffic monitoring, interface statistics,
protocol performance metrics, and throughput analysis.
"""

import logging
import time
import threading
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import statistics

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics that can be collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    RATE = "rate"


@dataclass
class MetricValue:
    """Container for a metric value with timestamp."""
    value: float
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass 
class InterfaceStats:
    """Statistics for a network interface."""
    interface_name: str
    device_name: str
    
    # Packet statistics
    packets_in: int = 0
    packets_out: int = 0
    packets_dropped_in: int = 0
    packets_dropped_out: int = 0
    
    # Byte statistics
    bytes_in: int = 0
    bytes_out: int = 0
    
    # Error statistics
    errors_in: int = 0
    errors_out: int = 0
    collisions: int = 0
    
    # Utilization
    utilization_in: float = 0.0
    utilization_out: float = 0.0
    
    # Timing
    last_updated: float = field(default_factory=time.time)
    
    def update_utilization(self, bandwidth_bps: int, window_seconds: float = 1.0):
        """Update interface utilization based on recent traffic."""
        if bandwidth_bps > 0:
            # Calculate bits per second over the window
            bits_in_window = (self.bytes_in * 8) / window_seconds
            bits_out_window = (self.bytes_out * 8) / window_seconds
            
            self.utilization_in = min(100.0, (bits_in_window / bandwidth_bps) * 100.0)
            self.utilization_out = min(100.0, (bits_out_window / bandwidth_bps) * 100.0)


@dataclass
class ProtocolStats:
    """Statistics for network protocols."""
    protocol_name: str
    
    # Message counts
    messages_sent: int = 0
    messages_received: int = 0
    messages_dropped: int = 0
    
    # Protocol-specific metrics
    hellos_sent: int = 0
    hellos_received: int = 0
    updates_sent: int = 0
    updates_received: int = 0
    
    # Neighbor statistics
    neighbors_discovered: int = 0
    neighbors_lost: int = 0
    neighbor_changes: int = 0
    
    # Convergence metrics
    convergence_events: int = 0
    avg_convergence_time: float = 0.0
    last_convergence_time: Optional[float] = None
    
    # Error statistics
    protocol_errors: int = 0
    timeout_events: int = 0


@dataclass
class TrafficFlow:
    """Represents a traffic flow between two endpoints."""
    flow_id: str
    source_device: str
    destination_device: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "IP"
    
    # Flow statistics
    packets: int = 0
    bytes: int = 0
    duration: float = 0.0
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    # Performance metrics
    min_latency: float = float('inf')
    max_latency: float = 0.0
    avg_latency: float = 0.0
    jitter: float = 0.0
    packet_loss_rate: float = 0.0
    
    # Path information
    path_hops: List[str] = field(default_factory=list)
    path_changes: int = 0


@dataclass
class CongestionEvent:
    """Represents a network congestion event."""
    timestamp: float
    location: str  # Device or link identifier
    severity: float  # 0.0 to 1.0
    duration: float = 0.0
    packets_affected: int = 0
    bytes_affected: int = 0
    cause: str = "unknown"


class SimulationStats:
    """Main statistics collection and reporting system."""
    
    def __init__(self, collection_interval: float = 1.0):
        self.collection_interval = collection_interval
        self.start_time = time.time()
        self.running = False
        self.collector_thread: Optional[threading.Thread] = None
        
        # Statistics storage
        self.interface_stats: Dict[str, InterfaceStats] = {}
        self.protocol_stats: Dict[str, ProtocolStats] = {}
        self.traffic_flows: Dict[str, TrafficFlow] = {}
        self.congestion_events: List[CongestionEvent] = []
        
        # Time series data storage
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.rates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Configuration
        self.max_flow_idle_time = 300.0  # 5 minutes
        self.max_congestion_events = 1000
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Callbacks for real-time monitoring
        self.threshold_callbacks: List[callable] = []
        
        logger.info(f"SimulationStats initialized with {collection_interval}s collection interval")
    
    def start_collection(self):
        """Start statistics collection."""
        if not self.running:
            self.running = True
            self.collector_thread = threading.Thread(target=self._collection_loop, daemon=True)
            self.collector_thread.start()
            logger.info("Statistics collection started")
    
    def stop_collection(self):
        """Stop statistics collection."""
        if self.running:
            self.running = False
            if self.collector_thread:
                self.collector_thread.join(timeout=2.0)
            logger.info("Statistics collection stopped")
    
    def _collection_loop(self):
        """Main statistics collection loop."""
        logger.debug("Statistics collection loop started")
        
        try:
            while self.running:
                try:
                    self._collect_metrics()
                    self._update_rates()
                    self._cleanup_old_data()
                    
                    time.sleep(self.collection_interval)
                    
                except Exception as e:
                    logger.error(f"Error in statistics collection: {e}")
                    time.sleep(self.collection_interval)
                    
        except Exception as e:
            logger.error(f"Critical error in statistics collection loop: {e}")
        finally:
            logger.debug("Statistics collection loop ended")
    
    def _collect_metrics(self):
        """Collect current metrics snapshot."""
        current_time = time.time()
        
        with self._lock:
            # Update interface utilization
            for interface_stat in self.interface_stats.values():
                interface_stat.last_updated = current_time
            
            # Record system-wide metrics
            total_packets = sum(stat.packets_in + stat.packets_out 
                              for stat in self.interface_stats.values())
            total_bytes = sum(stat.bytes_in + stat.bytes_out 
                            for stat in self.interface_stats.values())
            
            self.record_metric("system.total_packets", total_packets, current_time)
            self.record_metric("system.total_bytes", total_bytes, current_time)
            self.record_metric("system.active_flows", len(self.traffic_flows), current_time)
    
    def _update_rates(self):
        """Update rate calculations for metrics."""
        current_time = time.time()
        
        # Calculate rates for key metrics
        for metric_name in ["system.total_packets", "system.total_bytes"]:
            if metric_name in self.metrics and len(self.metrics[metric_name]) >= 2:
                recent_values = list(self.metrics[metric_name])[-2:]
                
                value_diff = recent_values[1].value - recent_values[0].value
                time_diff = recent_values[1].timestamp - recent_values[0].timestamp
                
                if time_diff > 0:
                    rate = value_diff / time_diff
                    self.rates[f"{metric_name}_rate"].append(
                        MetricValue(rate, current_time)
                    )
    
    def _cleanup_old_data(self):
        """Clean up old statistical data."""
        current_time = time.time()
        
        with self._lock:
            # Clean up idle traffic flows
            idle_flows = []
            for flow_id, flow in self.traffic_flows.items():
                if current_time - flow.last_seen > self.max_flow_idle_time:
                    idle_flows.append(flow_id)
            
            for flow_id in idle_flows:
                del self.traffic_flows[flow_id]
            
            # Limit congestion events
            if len(self.congestion_events) > self.max_congestion_events:
                self.congestion_events = self.congestion_events[-self.max_congestion_events//2:]
    
    def record_metric(self, metric_name: str, value: float, timestamp: Optional[float] = None,
                     tags: Optional[Dict[str, str]] = None):
        """Record a metric value."""
        if timestamp is None:
            timestamp = time.time()
        
        if tags is None:
            tags = {}
        
        with self._lock:
            self.metrics[metric_name].append(MetricValue(value, timestamp, tags))
    
    def update_interface_stats(self, device_name: str, interface_name: str, 
                             packets_in: int = 0, packets_out: int = 0,
                             bytes_in: int = 0, bytes_out: int = 0,
                             errors_in: int = 0, errors_out: int = 0,
                             packets_dropped_in: int = 0, packets_dropped_out: int = 0):
        """Update interface statistics."""
        key = f"{device_name}:{interface_name}"
        
        with self._lock:
            if key not in self.interface_stats:
                self.interface_stats[key] = InterfaceStats(
                    interface_name=interface_name,
                    device_name=device_name
                )
            
            stats = self.interface_stats[key]
            stats.packets_in += packets_in
            stats.packets_out += packets_out
            stats.bytes_in += bytes_in
            stats.bytes_out += bytes_out
            stats.errors_in += errors_in
            stats.errors_out += errors_out
            stats.packets_dropped_in += packets_dropped_in
            stats.packets_dropped_out += packets_dropped_out
            stats.last_updated = time.time()
    
    def update_protocol_stats(self, protocol_name: str, 
                            messages_sent: int = 0, messages_received: int = 0,
                            neighbors_discovered: int = 0, neighbors_lost: int = 0,
                            convergence_time: Optional[float] = None):
        """Update protocol statistics."""
        with self._lock:
            if protocol_name not in self.protocol_stats:
                self.protocol_stats[protocol_name] = ProtocolStats(protocol_name=protocol_name)
            
            stats = self.protocol_stats[protocol_name]
            stats.messages_sent += messages_sent
            stats.messages_received += messages_received
            stats.neighbors_discovered += neighbors_discovered
            stats.neighbors_lost += neighbors_lost
            
            if convergence_time is not None:
                stats.convergence_events += 1
                stats.last_convergence_time = convergence_time
                
                # Update average convergence time
                if stats.convergence_events == 1:
                    stats.avg_convergence_time = convergence_time
                else:
                    # Exponential moving average
                    alpha = 0.1
                    stats.avg_convergence_time = (
                        alpha * convergence_time + 
                        (1 - alpha) * stats.avg_convergence_time
                    )
    
    def record_traffic_flow(self, flow_id: str, source_device: str, destination_device: str,
                           protocol: str = "IP", packet_size: int = 0, latency: float = 0.0,
                           path_hops: Optional[List[str]] = None):
        """Record traffic flow information."""
        with self._lock:
            if flow_id not in self.traffic_flows:
                self.traffic_flows[flow_id] = TrafficFlow(
                    flow_id=flow_id,
                    source_device=source_device,
                    destination_device=destination_device,
                    protocol=protocol
                )
            
            flow = self.traffic_flows[flow_id]
            flow.packets += 1
            flow.bytes += packet_size
            flow.last_seen = time.time()
            flow.duration = flow.last_seen - flow.start_time
            
            # Update latency statistics
            if latency > 0:
                flow.min_latency = min(flow.min_latency, latency)
                flow.max_latency = max(flow.max_latency, latency)
                
                # Update average latency (exponential moving average)
                if flow.avg_latency == 0:
                    flow.avg_latency = latency
                else:
                    alpha = 0.1
                    flow.avg_latency = alpha * latency + (1 - alpha) * flow.avg_latency
            
            # Update path information
            if path_hops:
                if flow.path_hops != path_hops:
                    flow.path_changes += 1
                    flow.path_hops = path_hops.copy()
    
    def record_congestion_event(self, location: str, severity: float, 
                               packets_affected: int = 0, bytes_affected: int = 0,
                               cause: str = "unknown"):
        """Record a network congestion event."""
        with self._lock:
            event = CongestionEvent(
                timestamp=time.time(),
                location=location,
                severity=severity,
                packets_affected=packets_affected,
                bytes_affected=bytes_affected,
                cause=cause
            )
            
            self.congestion_events.append(event)
            
            # Limit events list size
            if len(self.congestion_events) > self.max_congestion_events:
                self.congestion_events = self.congestion_events[-self.max_congestion_events//2:]
    
    def get_interface_statistics(self, device_name: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Get interface statistics, optionally filtered by device."""
        result = {}
        
        with self._lock:
            for key, stats in self.interface_stats.items():
                if device_name is None or stats.device_name == device_name:
                    result[key] = {
                        'device_name': stats.device_name,
                        'interface_name': stats.interface_name,
                        'packets_in': stats.packets_in,
                        'packets_out': stats.packets_out,
                        'bytes_in': stats.bytes_in,
                        'bytes_out': stats.bytes_out,
                        'packets_dropped_in': stats.packets_dropped_in,
                        'packets_dropped_out': stats.packets_dropped_out,
                        'errors_in': stats.errors_in,
                        'errors_out': stats.errors_out,
                        'utilization_in': stats.utilization_in,
                        'utilization_out': stats.utilization_out,
                        'last_updated': stats.last_updated
                    }
        
        return result
    
    def get_protocol_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get protocol statistics."""
        result = {}
        
        with self._lock:
            for protocol_name, stats in self.protocol_stats.items():
                result[protocol_name] = {
                    'messages_sent': stats.messages_sent,
                    'messages_received': stats.messages_received,
                    'messages_dropped': stats.messages_dropped,
                    'neighbors_discovered': stats.neighbors_discovered,
                    'neighbors_lost': stats.neighbors_lost,
                    'convergence_events': stats.convergence_events,
                    'avg_convergence_time': stats.avg_convergence_time,
                    'last_convergence_time': stats.last_convergence_time,
                    'protocol_errors': stats.protocol_errors
                }
        
        return result
    
    def get_traffic_flows(self, active_only: bool = True) -> Dict[str, Dict[str, Any]]:
        """Get traffic flow information."""
        result = {}
        current_time = time.time()
        
        with self._lock:
            for flow_id, flow in self.traffic_flows.items():
                if active_only and (current_time - flow.last_seen) > 60.0:
                    continue  # Skip inactive flows
                
                result[flow_id] = {
                    'source_device': flow.source_device,
                    'destination_device': flow.destination_device,
                    'protocol': flow.protocol,
                    'packets': flow.packets,
                    'bytes': flow.bytes,
                    'duration': flow.duration,
                    'start_time': flow.start_time,
                    'last_seen': flow.last_seen,
                    'min_latency': flow.min_latency if flow.min_latency != float('inf') else 0,
                    'max_latency': flow.max_latency,
                    'avg_latency': flow.avg_latency,
                    'path_hops': flow.path_hops,
                    'path_changes': flow.path_changes
                }
        
        return result
    
    def get_congestion_analysis(self, time_window: float = 300.0) -> Dict[str, Any]:
        """Get congestion analysis for the specified time window."""
        current_time = time.time()
        cutoff_time = current_time - time_window
        
        recent_events = [event for event in self.congestion_events 
                        if event.timestamp >= cutoff_time]
        
        if not recent_events:
            return {
                'total_events': 0,
                'avg_severity': 0.0,
                'hotspots': {},
                'causes': {}
            }
        
        # Analyze congestion patterns
        location_counts = defaultdict(int)
        location_severity = defaultdict(list)
        cause_counts = defaultdict(int)
        severities = []
        
        for event in recent_events:
            location_counts[event.location] += 1
            location_severity[event.location].append(event.severity)
            cause_counts[event.cause] += 1
            severities.append(event.severity)
        
        # Calculate hotspots (locations with most events)
        hotspots = {}
        for location, count in location_counts.items():
            avg_severity = statistics.mean(location_severity[location])
            hotspots[location] = {
                'event_count': count,
                'avg_severity': avg_severity,
                'max_severity': max(location_severity[location])
            }
        
        return {
            'total_events': len(recent_events),
            'avg_severity': statistics.mean(severities) if severities else 0.0,
            'max_severity': max(severities) if severities else 0.0,
            'hotspots': dict(sorted(hotspots.items(), 
                                  key=lambda x: x[1]['event_count'], reverse=True)),
            'causes': dict(cause_counts)
        }
    
    def get_throughput_analysis(self, time_window: float = 60.0) -> Dict[str, Any]:
        """Get throughput analysis for the specified time window."""
        current_time = time.time()
        
        # Get recent packet and byte counts
        packet_rates = []
        byte_rates = []
        
        for rate_deque in [self.rates.get("system.total_packets_rate", deque()),
                          self.rates.get("system.total_bytes_rate", deque())]:
            recent_rates = [r.value for r in rate_deque 
                           if current_time - r.timestamp <= time_window]
            
            if recent_rates:
                if 'packets' in str(rate_deque):
                    packet_rates.extend(recent_rates)
                else:
                    byte_rates.extend(recent_rates)
        
        result = {
            'time_window': time_window,
            'packets_per_second': {
                'current': packet_rates[-1] if packet_rates else 0.0,
                'avg': statistics.mean(packet_rates) if packet_rates else 0.0,
                'max': max(packet_rates) if packet_rates else 0.0,
                'min': min(packet_rates) if packet_rates else 0.0
            },
            'bytes_per_second': {
                'current': byte_rates[-1] if byte_rates else 0.0,
                'avg': statistics.mean(byte_rates) if byte_rates else 0.0,
                'max': max(byte_rates) if byte_rates else 0.0,
                'min': min(byte_rates) if byte_rates else 0.0
            }
        }
        
        return result
    
    def get_simulation_summary(self) -> Dict[str, Any]:
        """Get comprehensive simulation statistics summary."""
        current_time = time.time()
        simulation_duration = current_time - self.start_time
        
        with self._lock:
            # Calculate totals
            total_packets = sum(stats.packets_in + stats.packets_out 
                              for stats in self.interface_stats.values())
            total_bytes = sum(stats.bytes_in + stats.bytes_out 
                            for stats in self.interface_stats.values())
            total_errors = sum(stats.errors_in + stats.errors_out 
                             for stats in self.interface_stats.values())
            total_drops = sum(stats.packets_dropped_in + stats.packets_dropped_out 
                            for stats in self.interface_stats.values())
            
            # Active flows
            active_flows = len([f for f in self.traffic_flows.values() 
                              if current_time - f.last_seen <= 60.0])
            
            return {
                'simulation_duration': simulation_duration,
                'collection_interval': self.collection_interval,
                'totals': {
                    'packets': total_packets,
                    'bytes': total_bytes,
                    'errors': total_errors,
                    'dropped_packets': total_drops
                },
                'averages': {
                    'packets_per_second': total_packets / simulation_duration if simulation_duration > 0 else 0,
                    'bytes_per_second': total_bytes / simulation_duration if simulation_duration > 0 else 0,
                },
                'counts': {
                    'interfaces': len(self.interface_stats),
                    'protocols': len(self.protocol_stats),
                    'total_flows': len(self.traffic_flows),
                    'active_flows': active_flows,
                    'congestion_events': len(self.congestion_events)
                },
                'data_points': {
                    'metrics': sum(len(deque_obj) for deque_obj in self.metrics.values()),
                    'rates': sum(len(deque_obj) for deque_obj in self.rates.values())
                }
            }
    
    def export_statistics(self, filename: str, format: str = 'json'):
        """Export statistics to file."""
        data = {
            'timestamp': time.time(),
            'simulation_summary': self.get_simulation_summary(),
            'interface_statistics': self.get_interface_statistics(),
            'protocol_statistics': self.get_protocol_statistics(),
            'traffic_flows': self.get_traffic_flows(active_only=False),
            'congestion_analysis': self.get_congestion_analysis(),
            'throughput_analysis': self.get_throughput_analysis()
        }
        
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        logger.info(f"Statistics exported to {filename}")
        return data
    
    def reset_statistics(self):
        """Reset all statistics."""
        with self._lock:
            self.interface_stats.clear()
            self.protocol_stats.clear()
            self.traffic_flows.clear()
            self.congestion_events.clear()
            self.metrics.clear()
            self.rates.clear()
            self.start_time = time.time()
        
        logger.info("All statistics have been reset")
    
    def add_threshold_callback(self, callback: callable):
        """Add a callback for threshold-based alerting."""
        self.threshold_callbacks.append(callback)
    
    def check_thresholds(self):
        """Check configured thresholds and trigger callbacks if needed."""
        # This could be implemented to check various thresholds and trigger alerts
        # For example: high error rates, congestion, etc.
        pass