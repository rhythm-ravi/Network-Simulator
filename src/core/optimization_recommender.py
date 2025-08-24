"""
Network Optimization Recommender for Network Simulator.

This module provides network optimization recommendations including node aggregation,
protocol optimization, and bandwidth utilization improvements.
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
from ipaddress import IPv4Network, IPv4Address, AddressValueError

from .config_parser import DeviceConfiguration

logger = logging.getLogger(__name__)


@dataclass
class OptimizationRecommendation:
    """Represents a network optimization recommendation."""
    category: str  # protocol, topology, capacity, security
    priority: str  # high, medium, low
    title: str
    description: str
    impact: str  # performance, cost, reliability, security
    implementation_effort: str  # low, medium, high
    devices_affected: List[str]
    estimated_benefit: str


@dataclass
class NodeAggregationOpportunity:
    """Represents an opportunity to aggregate network nodes."""
    primary_device: str
    secondary_devices: List[str]
    aggregation_type: str  # physical_consolidation, logical_aggregation
    potential_savings: str
    complexity: str


class NetworkOptimizationRecommender:
    """
    Generates network optimization recommendations based on configuration analysis.
    """
    
    def __init__(self):
        """Initialize the optimization recommender."""
        self.recommendations = []
    
    def analyze_and_recommend(self, device_configs: Dict[str, DeviceConfiguration],
                            network_issues: List[Dict[str, Any]]) -> List[OptimizationRecommendation]:
        """
        Analyze network configuration and generate optimization recommendations.
        
        Args:
            device_configs: Dictionary of device configurations
            network_issues: List of identified network issues
            
        Returns:
            List of optimization recommendations
        """
        logger.info("Generating network optimization recommendations...")
        
        self.recommendations = []
        
        # Analyze different aspects of the network
        self._analyze_routing_protocols(device_configs)
        self._analyze_vlan_optimization(device_configs)
        self._analyze_node_aggregation(device_configs)
        self._analyze_bandwidth_utilization(device_configs)
        self._analyze_redundancy_opportunities(device_configs)
        self._analyze_security_improvements(device_configs, network_issues)
        self._analyze_topology_optimization(device_configs)
        
        # Sort recommendations by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        self.recommendations.sort(key=lambda x: priority_order.get(x.priority, 3))
        
        return self.recommendations
    
    def _analyze_routing_protocols(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Analyze routing protocol configurations and suggest optimizations."""
        # Count routing protocols
        ospf_routers = []
        bgp_routers = []
        eigrp_routers = []
        static_only_routers = []
        mixed_protocol_routers = []
        
        for device_name, config in device_configs.items():
            if config.device_type != "router":
                continue
            
            protocols = set()
            for protocol in config.routing_protocols:
                protocols.add(protocol.protocol_type)
                
                if protocol.protocol_type == "ospf":
                    ospf_routers.append(device_name)
                elif protocol.protocol_type == "bgp":
                    bgp_routers.append(device_name)
                elif protocol.protocol_type == "eigrp":
                    eigrp_routers.append(device_name)
            
            if len(protocols) > 1:
                mixed_protocol_routers.append(device_name)
            elif not protocols:
                static_only_routers.append(device_name)
        
        # BGP vs OSPF recommendations
        if len(ospf_routers) > 10:
            self.recommendations.append(OptimizationRecommendation(
                category="protocol",
                priority="medium",
                title="Consider BGP for Large Network",
                description=f"Network has {len(ospf_routers)} OSPF routers. BGP may provide better scalability.",
                impact="performance",
                implementation_effort="high",
                devices_affected=ospf_routers,
                estimated_benefit="Improved convergence time and reduced memory usage with >10 routers"
            ))
        
        # Mixed protocol optimization
        if mixed_protocol_routers:
            self.recommendations.append(OptimizationRecommendation(
                category="protocol",
                priority="high",
                title="Optimize Mixed Routing Protocols",
                description=f"Routers {', '.join(mixed_protocol_routers)} are running multiple routing protocols. Consider protocol redistribution optimization.",
                impact="performance",
                implementation_effort="medium",
                devices_affected=mixed_protocol_routers,
                estimated_benefit="Reduced routing loops and improved convergence"
            ))
        
        # Static routing optimization
        if static_only_routers and len(static_only_routers) > 3:
            self.recommendations.append(OptimizationRecommendation(
                category="protocol",
                priority="medium",
                title="Consider Dynamic Routing",
                description=f"Routers {', '.join(static_only_routers)} use only static routing. Dynamic routing could improve resilience.",
                impact="reliability",
                implementation_effort="medium",
                devices_affected=static_only_routers,
                estimated_benefit="Automatic failover and reduced manual configuration"
            ))
    
    def _analyze_vlan_optimization(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Analyze VLAN configurations and suggest optimizations."""
        # Collect VLAN usage statistics
        vlan_usage = defaultdict(int)  # vlan_id -> number of devices
        vlan_names = defaultdict(set)  # vlan_id -> set of names used
        total_vlans = 0
        
        for device_name, config in device_configs.items():
            if config.device_type == "switch":
                total_vlans += len(config.vlans)
                for vlan_id, vlan in config.vlans.items():
                    vlan_usage[vlan_id] += 1
                    if vlan.name:
                        vlan_names[vlan_id].add(vlan.name)
        
        # Unused VLAN recommendations
        single_device_vlans = [vlan_id for vlan_id, count in vlan_usage.items() if count == 1]
        if len(single_device_vlans) > 3:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="low",
                title="Consolidate Single-Device VLANs",
                description=f"VLANs {single_device_vlans[:5]} are only used on one device each. Consider consolidation.",
                impact="cost",
                implementation_effort="low",
                devices_affected=[],
                estimated_benefit="Reduced VLAN sprawl and simplified management"
            ))
        
        # VLAN naming consistency
        inconsistent_vlans = [vlan_id for vlan_id, names in vlan_names.items() if len(names) > 1]
        if inconsistent_vlans:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="medium",
                title="Standardize VLAN Naming",
                description=f"VLANs {inconsistent_vlans} have inconsistent names across devices.",
                impact="reliability",
                implementation_effort="low",
                devices_affected=list(device_configs.keys()),
                estimated_benefit="Reduced configuration errors and improved troubleshooting"
            ))
        
        # Too many VLANs warning
        if total_vlans > 50:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="medium",
                title="VLAN Consolidation Review",
                description=f"Network has {total_vlans} VLANs configured. Review for consolidation opportunities.",
                impact="performance",
                implementation_effort="medium",
                devices_affected=list(device_configs.keys()),
                estimated_benefit="Reduced broadcast domains and improved switch performance"
            ))
    
    def _analyze_node_aggregation(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Identify node aggregation opportunities."""
        # Group devices by location and function
        switches_by_function = defaultdict(list)
        routers_by_function = defaultdict(list)
        
        for device_name, config in device_configs.items():
            if config.device_type == "switch":
                # Categorize switches by their VLAN configuration and interface count
                interface_count = len(config.interfaces)
                vlan_count = len(config.vlans)
                
                if interface_count < 12 and vlan_count < 3:
                    switches_by_function["small_access"].append(device_name)
                elif interface_count < 24:
                    switches_by_function["medium_access"].append(device_name)
                else:
                    switches_by_function["large_access"].append(device_name)
                    
            elif config.device_type == "router":
                interface_count = len(config.interfaces)
                if interface_count < 6:
                    routers_by_function["small_router"].append(device_name)
                else:
                    routers_by_function["large_router"].append(device_name)
        
        # Recommend switch consolidation
        if len(switches_by_function["small_access"]) > 2:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="medium",
                title="Small Switch Consolidation",
                description=f"Switches {switches_by_function['small_access']} have few ports/VLANs. Consider consolidation.",
                impact="cost",
                implementation_effort="medium",
                devices_affected=switches_by_function["small_access"],
                estimated_benefit="Reduced hardware costs and simplified management"
            ))
        
        # Recommend router aggregation
        if len(routers_by_function["small_router"]) > 1:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="low",
                title="Router Consolidation Review",
                description=f"Small routers {routers_by_function['small_router']} may benefit from consolidation or replacement with a single larger router.",
                impact="cost",
                implementation_effort="high",
                devices_affected=routers_by_function["small_router"],
                estimated_benefit="Reduced licensing costs and simplified routing"
            ))
    
    def _analyze_bandwidth_utilization(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Analyze bandwidth configurations and suggest optimizations."""
        bandwidth_mismatches = []
        low_bandwidth_links = []
        
        for device_name, config in device_configs.items():
            interface_bandwidths = []
            
            for intf_name, intf in config.interfaces.items():
                if intf.bandwidth and intf.status == "up":
                    bw_mbps = self._parse_bandwidth_to_mbps(intf.bandwidth)
                    if bw_mbps:
                        interface_bandwidths.append((intf_name, bw_mbps))
                        
                        # Flag low bandwidth interfaces
                        if bw_mbps < 100:  # Less than 100 Mbps
                            low_bandwidth_links.append(f"{device_name}:{intf_name} ({bw_mbps}Mbps)")
            
            # Check for bandwidth variations within device
            if len(set(bw for _, bw in interface_bandwidths)) > 2:
                bandwidth_mismatches.append(device_name)
        
        # Low bandwidth recommendations
        if low_bandwidth_links:
            self.recommendations.append(OptimizationRecommendation(
                category="capacity",
                priority="high",
                title="Upgrade Low-Bandwidth Links",
                description=f"Links {low_bandwidth_links[:3]} have bandwidth <100Mbps. Consider upgrading.",
                impact="performance",
                implementation_effort="medium",
                devices_affected=list(device_configs.keys()),
                estimated_benefit="Improved application performance and reduced bottlenecks"
            ))
        
        # Bandwidth consistency recommendations
        if bandwidth_mismatches:
            self.recommendations.append(OptimizationRecommendation(
                category="capacity",
                priority="low",
                title="Standardize Interface Bandwidth",
                description=f"Devices {bandwidth_mismatches} have varying interface bandwidths.",
                impact="performance",
                implementation_effort="low",
                devices_affected=bandwidth_mismatches,
                estimated_benefit="Consistent performance characteristics and simplified planning"
            ))
    
    def _analyze_redundancy_opportunities(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Identify redundancy improvement opportunities."""
        single_homed_devices = []
        devices_without_backup = []
        
        # Build connectivity map
        device_connections = defaultdict(set)
        
        # Simple analysis based on interface configurations
        for device_name, config in device_configs.items():
            connection_count = sum(1 for intf in config.interfaces.values() 
                                 if intf.status == "up" and intf.ip_address)
            
            if connection_count == 1:
                single_homed_devices.append(device_name)
            elif connection_count == 2 and config.device_type == "router":
                # Router with only 2 connections might need more redundancy
                devices_without_backup.append(device_name)
        
        # Redundancy recommendations
        if single_homed_devices:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="high",
                title="Improve Network Redundancy",
                description=f"Devices {single_homed_devices} have single connections, creating single points of failure.",
                impact="reliability",
                implementation_effort="high",
                devices_affected=single_homed_devices,
                estimated_benefit="Eliminated single points of failure and improved uptime"
            ))
        
        if devices_without_backup and len(devices_without_backup) > 0:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="medium",
                title="Add Backup Links",
                description=f"Routers {devices_without_backup} may benefit from additional backup connections.",
                impact="reliability",
                implementation_effort="medium",
                devices_affected=devices_without_backup,
                estimated_benefit="Improved fault tolerance and automatic failover"
            ))
    
    def _analyze_security_improvements(self, device_configs: Dict[str, DeviceConfiguration],
                                     network_issues: List[Dict[str, Any]]) -> None:
        """Analyze security configurations and suggest improvements."""
        devices_without_acls = []
        unused_acl_devices = []
        
        for device_name, config in device_configs.items():
            if not config.acls:
                devices_without_acls.append(device_name)
        
        # Check for unused ACL issues
        for issue in network_issues:
            if issue.get('type') == 'unused_acl':
                device = issue.get('device')
                if device:
                    unused_acl_devices.append(device)
        
        # Security recommendations
        if devices_without_acls:
            self.recommendations.append(OptimizationRecommendation(
                category="security",
                priority="high",
                title="Implement Access Control Lists",
                description=f"Devices {devices_without_acls} have no ACLs configured, potentially allowing unrestricted access.",
                impact="security",
                implementation_effort="medium",
                devices_affected=devices_without_acls,
                estimated_benefit="Improved network security and access control"
            ))
        
        if unused_acl_devices:
            self.recommendations.append(OptimizationRecommendation(
                category="security",
                priority="low",
                title="Clean Up Unused ACLs",
                description=f"Devices {unused_acl_devices} have unused ACLs that should be reviewed and removed.",
                impact="security",
                implementation_effort="low",
                devices_affected=unused_acl_devices,
                estimated_benefit="Reduced configuration complexity and eliminated unused rules"
            ))
    
    def _analyze_topology_optimization(self, device_configs: Dict[str, DeviceConfiguration]) -> None:
        """Analyze network topology for optimization opportunities."""
        # Analyze spanning tree configuration
        switches_without_stp = []
        switches_with_stp = []
        
        for device_name, config in device_configs.items():
            if config.device_type == "switch":
                if config.spanning_tree_mode:
                    switches_with_stp.append(device_name)
                else:
                    switches_without_stp.append(device_name)
        
        # Spanning tree recommendations
        if switches_without_stp:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="high",
                title="Implement Spanning Tree Protocol",
                description=f"Switches {switches_without_stp} lack STP configuration, risking network loops.",
                impact="reliability",
                implementation_effort="low",
                devices_affected=switches_without_stp,
                estimated_benefit="Prevention of broadcast storms and network loops"
            ))
        
        # Advanced STP recommendations
        if len(switches_with_stp) > 5:
            self.recommendations.append(OptimizationRecommendation(
                category="topology",
                priority="medium",
                title="Consider Rapid Spanning Tree (RSTP)",
                description=f"Network has {len(switches_with_stp)} switches. RSTP can improve convergence time.",
                impact="performance",
                implementation_effort="medium",
                devices_affected=switches_with_stp,
                estimated_benefit="Faster network convergence and reduced downtime during failures"
            ))
    
    def _parse_bandwidth_to_mbps(self, bandwidth_str: Optional[str]) -> Optional[float]:
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
                    return float(bandwidth_str) / 1000000
            else:
                return float(bandwidth_str) / 1000000
        except (ValueError, TypeError):
            return None