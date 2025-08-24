"""
Network Load Analyzer for Network Simulator.

This module provides functionality to analyze network load and capacity utilization,
helping identify potential bottlenecks and providing load balancing recommendations.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv4Address, AddressValueError

from .config_parser import DeviceConfiguration

logger = logging.getLogger(__name__)


@dataclass
class TrafficProfile:
    """Represents expected traffic characteristics for an application or service."""
    name: str
    peak_bandwidth_mbps: float
    average_bandwidth_mbps: float
    protocol: str  # tcp, udp, mixed
    priority: str  # high, medium, low
    burst_factor: float = 1.5  # Peak to average ratio


@dataclass
class LinkCapacity:
    """Represents the capacity and current utilization of a network link."""
    source_device: str
    source_interface: str
    dest_device: str
    dest_interface: str
    configured_bandwidth_mbps: float
    current_utilization_mbps: float = 0.0
    peak_utilization_mbps: float = 0.0
    
    @property
    def utilization_percentage(self) -> float:
        """Calculate current utilization as percentage of configured bandwidth."""
        if self.configured_bandwidth_mbps == 0:
            return 0.0
        return (self.current_utilization_mbps / self.configured_bandwidth_mbps) * 100
    
    @property
    def peak_utilization_percentage(self) -> float:
        """Calculate peak utilization as percentage of configured bandwidth."""
        if self.configured_bandwidth_mbps == 0:
            return 0.0
        return (self.peak_utilization_mbps / self.configured_bandwidth_mbps) * 100


@dataclass
class LoadAnalysisResult:
    """Results of network load analysis."""
    overloaded_links: List[LinkCapacity]
    underutilized_links: List[LinkCapacity]
    capacity_issues: List[Dict[str, Any]]
    recommendations: List[str]
    total_network_capacity: float
    total_network_utilization: float


class NetworkLoadAnalyzer:
    """
    Analyzes network load and capacity utilization.
    Provides recommendations for load balancing and capacity planning.
    """
    
    def __init__(self):
        """Initialize the load analyzer."""
        self.traffic_profiles = self._get_default_traffic_profiles()
        self.overload_threshold = 80.0  # % utilization considered overloaded
        self.underutilized_threshold = 20.0  # % utilization considered underutilized
    
    def analyze_network_load(self, device_configs: Dict[str, DeviceConfiguration],
                           traffic_data: Optional[Dict[str, float]] = None) -> LoadAnalysisResult:
        """
        Analyze network load and capacity.
        
        Args:
            device_configs: Dictionary of device configurations
            traffic_data: Optional dictionary of interface to utilization mapping
            
        Returns:
            LoadAnalysisResult with analysis findings
        """
        logger.info("Starting network load analysis...")
        
        # Build network topology and capacity map
        links = self._build_link_capacity_map(device_configs)
        
        # Apply traffic data if provided
        if traffic_data:
            self._apply_traffic_data(links, traffic_data)
        else:
            # Estimate traffic based on interface types and configurations
            self._estimate_traffic_load(links, device_configs)
        
        # Analyze capacity and utilization
        overloaded_links = []
        underutilized_links = []
        capacity_issues = []
        
        for link in links:
            if link.utilization_percentage > self.overload_threshold:
                overloaded_links.append(link)
            elif link.utilization_percentage < self.underutilized_threshold and link.current_utilization_mbps > 0:
                underutilized_links.append(link)
            
            # Check for capacity issues
            if link.peak_utilization_percentage > 95:
                capacity_issues.append({
                    'type': 'near_capacity',
                    'link': f"{link.source_device}:{link.source_interface} -> {link.dest_device}:{link.dest_interface}",
                    'utilization': link.peak_utilization_percentage,
                    'configured_bandwidth': link.configured_bandwidth_mbps
                })
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            links, overloaded_links, underutilized_links, device_configs
        )
        
        # Calculate totals
        total_capacity = sum(link.configured_bandwidth_mbps for link in links)
        total_utilization = sum(link.current_utilization_mbps for link in links)
        
        return LoadAnalysisResult(
            overloaded_links=overloaded_links,
            underutilized_links=underutilized_links,
            capacity_issues=capacity_issues,
            recommendations=recommendations,
            total_network_capacity=total_capacity,
            total_network_utilization=total_utilization
        )
    
    def _build_link_capacity_map(self, device_configs: Dict[str, DeviceConfiguration]) -> List[LinkCapacity]:
        """Build a map of network links and their capacities."""
        links = []
        processed_connections = set()
        
        # Group interfaces by network to identify connections
        networks = {}  # network_str -> [(device, interface, bandwidth)]
        
        for device_name, config in device_configs.items():
            for intf_name, intf in config.interfaces.items():
                if intf.ip_address and intf.subnet_mask and intf.status == 'up':
                    try:
                        network = IPv4Network(f"{intf.ip_address}/{intf.subnet_mask}", strict=False)
                        network_key = str(network)
                        
                        if network_key not in networks:
                            networks[network_key] = []
                        
                        # Parse bandwidth
                        bandwidth = self._parse_bandwidth(intf.bandwidth) or 100  # Default to 100 Mbps
                        
                        networks[network_key].append((device_name, intf_name, bandwidth))
                    except (AddressValueError, ValueError):
                        continue
        
        # Create links between devices in the same network
        for network, interfaces in networks.items():
            if len(interfaces) >= 2:
                # Create point-to-point links between all interface pairs
                for i, (dev1, intf1, bw1) in enumerate(interfaces):
                    for dev2, intf2, bw2 in interfaces[i+1:]:
                        connection_key = tuple(sorted([(dev1, intf1), (dev2, intf2)]))
                        
                        if connection_key not in processed_connections:
                            # Use the minimum bandwidth of the two interfaces
                            link_bandwidth = min(bw1, bw2)
                            
                            links.append(LinkCapacity(
                                source_device=dev1,
                                source_interface=intf1,
                                dest_device=dev2,
                                dest_interface=intf2,
                                configured_bandwidth_mbps=link_bandwidth
                            ))
                            
                            processed_connections.add(connection_key)
        
        return links
    
    def _apply_traffic_data(self, links: List[LinkCapacity], traffic_data: Dict[str, float]) -> None:
        """Apply actual traffic data to links."""
        for link in links:
            # Look for traffic data by interface name
            source_key = f"{link.source_device}:{link.source_interface}"
            dest_key = f"{link.dest_device}:{link.dest_interface}"
            
            source_traffic = traffic_data.get(source_key, 0)
            dest_traffic = traffic_data.get(dest_key, 0)
            
            # Use the maximum traffic in either direction
            link.current_utilization_mbps = max(source_traffic, dest_traffic)
            link.peak_utilization_mbps = link.current_utilization_mbps * 1.5  # Assume 50% burst
    
    def _estimate_traffic_load(self, links: List[LinkCapacity], 
                             device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Estimate traffic load based on interface characteristics and device types."""
        for link in links:
            # Estimate based on interface types and device roles
            source_config = device_configs.get(link.source_device)
            dest_config = device_configs.get(link.dest_device)
            
            if not source_config or not dest_config:
                continue
            
            # Base estimate on interface types
            estimated_utilization = 0.0
            
            # Router-to-router links (WAN/backbone)
            if source_config.device_type == "router" and dest_config.device_type == "router":
                estimated_utilization = link.configured_bandwidth_mbps * 0.3  # 30% utilization
            
            # Router-to-switch links (uplinks)
            elif ((source_config.device_type == "router" and dest_config.device_type == "switch") or
                  (source_config.device_type == "switch" and dest_config.device_type == "router")):
                estimated_utilization = link.configured_bandwidth_mbps * 0.4  # 40% utilization
            
            # Switch-to-switch links (inter-switch links)
            elif source_config.device_type == "switch" and dest_config.device_type == "switch":
                estimated_utilization = link.configured_bandwidth_mbps * 0.2  # 20% utilization
            
            link.current_utilization_mbps = estimated_utilization
            link.peak_utilization_mbps = estimated_utilization * 2.0  # Assume 2x burst factor
    
    def _generate_recommendations(self, links: List[LinkCapacity], 
                                overloaded_links: List[LinkCapacity],
                                underutilized_links: List[LinkCapacity],
                                device_configs: Dict[str, DeviceConfiguration]) -> List[str]:
        """Generate load balancing and capacity planning recommendations."""
        recommendations = []
        
        # Overloaded link recommendations
        if overloaded_links:
            recommendations.append(f"Found {len(overloaded_links)} overloaded links (>{self.overload_threshold}% utilization)")
            
            for link in overloaded_links:
                if link.configured_bandwidth_mbps < 1000:  # Less than 1Gbps
                    recommendations.append(
                        f"Consider upgrading link {link.source_device}:{link.source_interface} -> "
                        f"{link.dest_device}:{link.dest_interface} from {link.configured_bandwidth_mbps}Mbps to 1Gbps"
                    )
                else:
                    recommendations.append(
                        f"Consider adding parallel links or implementing load balancing for "
                        f"{link.source_device}:{link.source_interface} -> {link.dest_device}:{link.dest_interface}"
                    )
        
        # Underutilized link recommendations
        if underutilized_links:
            recommendations.append(f"Found {len(underutilized_links)} underutilized links (<{self.underutilized_threshold}% utilization)")
            
            # Group underutilized links by device pairs
            device_pairs = {}
            for link in underutilized_links:
                pair_key = tuple(sorted([link.source_device, link.dest_device]))
                if pair_key not in device_pairs:
                    device_pairs[pair_key] = []
                device_pairs[pair_key].append(link)
            
            for (dev1, dev2), pair_links in device_pairs.items():
                if len(pair_links) > 1:
                    recommendations.append(
                        f"Consider consolidating multiple underutilized links between {dev1} and {dev2}"
                    )
        
        # Protocol optimization recommendations
        router_count = sum(1 for config in device_configs.values() if config.device_type == "router")
        if router_count > 5:
            recommendations.append("Consider implementing BGP instead of OSPF for better scalability with many routers")
        
        # Load balancing recommendations
        overloaded_devices = set()
        for link in overloaded_links:
            overloaded_devices.add(link.source_device)
            overloaded_devices.add(link.dest_device)
        
        if overloaded_devices:
            recommendations.append(
                f"Devices experiencing high load: {', '.join(overloaded_devices)}. "
                "Consider implementing load balancing or traffic engineering."
            )
        
        return recommendations
    
    def _parse_bandwidth(self, bandwidth_str: Optional[str]) -> Optional[float]:
        """Parse bandwidth string to Mbps value."""
        if not bandwidth_str:
            return None
        
        try:
            if isinstance(bandwidth_str, str):
                if 'Mbps' in bandwidth_str:
                    return float(bandwidth_str.replace('Mbps', ''))
                elif 'Kbps' in bandwidth_str:
                    return float(bandwidth_str.replace('Kbps', '')) / 1000
                elif 'Gbps' in bandwidth_str:
                    return float(bandwidth_str.replace('Gbps', '')) * 1000
                elif 'bps' in bandwidth_str:
                    return float(bandwidth_str.replace('bps', '')) / 1000000
                else:
                    # Assume it's a raw number
                    return float(bandwidth_str) / 1000000
            else:
                return float(bandwidth_str) / 1000000
        except (ValueError, TypeError):
            return None
    
    def _get_default_traffic_profiles(self) -> Dict[str, TrafficProfile]:
        """Get default traffic profiles for common applications."""
        return {
            'web_browsing': TrafficProfile("Web Browsing", 10.0, 2.0, "tcp", "medium"),
            'video_streaming': TrafficProfile("Video Streaming", 25.0, 15.0, "tcp", "high"),
            'file_transfer': TrafficProfile("File Transfer", 100.0, 50.0, "tcp", "low"),
            'video_conference': TrafficProfile("Video Conference", 5.0, 3.0, "mixed", "high"),
            'database_access': TrafficProfile("Database Access", 50.0, 10.0, "tcp", "high"),
            'backup': TrafficProfile("Backup Traffic", 200.0, 100.0, "tcp", "low")
        }