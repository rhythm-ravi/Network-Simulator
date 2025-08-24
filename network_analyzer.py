#!/usr/bin/env python3
"""
Enhanced Network Analyzer - Main CLI Interface

This module provides a comprehensive CLI interface for advanced network analysis
including load analysis, configuration issue detection, and optimization recommendations.
"""

import argparse
import sys
import logging
import json
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add the src directory to the Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from core.config_parser import ConfigParser
from core.topology_generator import TopologyGenerator
from core.network_validator import NetworkValidator
from core.load_analyzer import NetworkLoadAnalyzer
from core.optimization_recommender import NetworkOptimizationRecommender
from core.fault_injector import FaultInjector
from core.simulation_stats import SimulationStats

# Try to import network simulator, graceful fallback if not available
try:
    from core.network_simulator import NetworkSimulator
    NETWORK_SIMULATOR_AVAILABLE = True
except ImportError:
    NETWORK_SIMULATOR_AVAILABLE = False
    NetworkSimulator = None


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up logging configuration."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger("NetworkAnalyzer")


def load_network_configs(config_path: str, logger: logging.Logger) -> Dict[str, Any]:
    """Load network configuration files from specified path."""
    logger.info(f"Loading network configurations from: {config_path}")
    
    try:
        from core.config_parser import ConfigParser
        parser = ConfigParser()
        
        # Parse configurations into DeviceConfiguration objects
        if os.path.isfile(config_path):
            device_name = Path(config_path).stem
            device_config = parser.parse_file(config_path, device_name)
            device_configs = {device_name: device_config}
        elif os.path.isdir(config_path):
            device_configs = parser.parse_directory(config_path)
        else:
            raise FileNotFoundError(f"Configuration path not found: {config_path}")
        
        logger.info(f"Successfully loaded {len(device_configs)} configuration(s)")
        return device_configs
    except Exception as e:
        logger.error(f"Failed to load configurations: {e}")
        return {}


def analyze_network_configuration(device_configs: Dict[str, Any], logger: logging.Logger, 
                               enable_load_analysis: bool = False,
                               enable_optimization: bool = False) -> Dict[str, Any]:
    """Perform comprehensive network configuration analysis."""
    logger.info("Starting comprehensive network analysis...")
    
    results = {
        'validation_results': [],
        'topology_info': {},
        'issues_found': [],
        'recommendations': [],
        'load_analysis': {},
        'optimization_recommendations': [],
        'statistics': {}
    }
    
    # Step 1: Network Validation using NetworkValidator
    logger.info("Step 1: Validating network configurations...")
    validator = NetworkValidator()
    issues = validator.validate_network(device_configs)
    
    # Convert issues to our format
    for issue in issues:
        issue_text = f"{issue.get('type', 'unknown').replace('_', ' ').title()}: {issue.get('description', 'No description')}"
        results['issues_found'].append(issue_text)
    
    if not issues:
        logger.info("✓ No network issues found")
    else:
        logger.warning(f"Found {len(issues)} network issues")
    
    # Step 2: Generate Network Topology (for analysis purposes)
    logger.info("Step 2: Generating network topology...")
    try:
        generator = TopologyGenerator()
        graph = generator.generate_topology(device_configs)
        
        if graph and graph.nodes:
            # Create basic topology info from the graph
            device_count = len(graph.nodes)
            edge_count = len(graph.edges)
            
            # Count device types
            routers = sum(1 for n, attrs in graph.nodes(data=True) if attrs.get('type') == 'router')
            switches = sum(1 for n, attrs in graph.nodes(data=True) if attrs.get('type') == 'switch')
            
            results['topology_info'] = {
                'total_devices': device_count,
                'routers': routers,
                'switches': switches,
                'total_links': edge_count,
                'active_links': edge_count  # Assume all are active for now
            }
            
            # Create basic statistics
            results['statistics'] = {
                'devices': {
                    'total': device_count,
                    'routers': routers,
                    'switches': switches
                },
                'interfaces': {
                    'total': sum(len(config.interfaces) for config in device_configs.values()),
                    'active': sum(1 for config in device_configs.values() 
                                  for intf in config.interfaces.values() 
                                  if intf.status == 'up')
                },
                'vlans': {
                    'total': sum(len(config.vlans) for config in device_configs.values())
                },
                'routing_protocols': {
                    'total': sum(len(config.routing_protocols) for config in device_configs.values())
                }
            }
            
            logger.info(f"✓ Generated topology with {device_count} devices and {edge_count} connections")
            
        else:
            logger.error("✗ Failed to generate valid topology")
            results['issues_found'].append("Failed to generate network topology")
    
    except Exception as e:
        logger.error(f"Error during topology generation: {e}")
        results['issues_found'].append(f"Topology generation error: {e}")
    
    # Step 3: Load Analysis (if enabled)
    if enable_load_analysis:
        logger.info("Step 3: Analyzing network load and capacity...")
        try:
            load_analyzer = NetworkLoadAnalyzer()
            load_results = load_analyzer.analyze_network_load(device_configs)
            
            results['load_analysis'] = {
                'total_capacity_mbps': load_results.total_network_capacity,
                'total_utilization_mbps': load_results.total_network_utilization,
                'utilization_percentage': (load_results.total_network_utilization / 
                                         load_results.total_network_capacity * 100) if load_results.total_network_capacity > 0 else 0,
                'overloaded_links': len(load_results.overloaded_links),
                'underutilized_links': len(load_results.underutilized_links),
                'capacity_issues': len(load_results.capacity_issues)
            }
            
            # Add load-related recommendations
            results['recommendations'].extend(load_results.recommendations)
            
            logger.info(f"✓ Load analysis completed: {load_results.total_utilization_mbps:.1f}/"
                       f"{load_results.total_network_capacity:.1f} Mbps utilized")
                       
        except Exception as e:
            logger.error(f"Error during load analysis: {e}")
            results['issues_found'].append(f"Load analysis error: {e}")
    
    # Step 4: Optimization Recommendations (if enabled)
    if enable_optimization:
        logger.info("Step 4: Generating optimization recommendations...")
        try:
            recommender = NetworkOptimizationRecommender()
            optimization_recs = recommender.analyze_and_recommend(device_configs, issues)
            
            results['optimization_recommendations'] = [
                {
                    'category': rec.category,
                    'priority': rec.priority,
                    'title': rec.title,
                    'description': rec.description,
                    'impact': rec.impact,
                    'effort': rec.implementation_effort,
                    'benefit': rec.estimated_benefit
                }
                for rec in optimization_recs
            ]
            
            logger.info(f"✓ Generated {len(optimization_recs)} optimization recommendations")
            
        except Exception as e:
            logger.error(f"Error during optimization analysis: {e}")
            results['issues_found'].append(f"Optimization analysis error: {e}")
    
    return results


def _device_config_to_dict(device_config) -> Dict[str, Any]:
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


def generate_analysis_report(results: Dict[str, Any], output_format: str = 'text') -> str:
    """Generate analysis report in specified format."""
    if output_format.lower() == 'json':
        return json.dumps(results, indent=2, default=str)
    
    # Generate text report
    report = []
    report.append("=" * 80)
    report.append("NETWORK ANALYSIS REPORT")
    report.append("=" * 80)
    report.append("")
    
    # Configuration Summary
    report.append("CONFIGURATION SUMMARY")
    report.append("-" * 40)
    valid_configs = sum(1 for r in results['validation_results'] if r.get('valid', False))
    total_configs = len(results['validation_results'])
    report.append(f"Total Configurations: {total_configs}")
    report.append(f"Valid Configurations: {valid_configs}")
    report.append(f"Invalid Configurations: {total_configs - valid_configs}")
    report.append("")
    
    # Topology Information
    if results['topology_info']:
        topo = results['topology_info']
        report.append("TOPOLOGY INFORMATION")
        report.append("-" * 40)
        report.append(f"Total Devices: {topo.get('total_devices', 0)}")
        report.append(f"  - Routers: {topo.get('routers', 0)}")
        report.append(f"  - Switches: {topo.get('switches', 0)}")
        report.append(f"Total Links: {topo.get('total_links', 0)}")
        report.append(f"Active Links: {topo.get('active_links', 0)}")
        report.append("")
    
    # Statistics
    if results['statistics']:
        stats = results['statistics']
        report.append("NETWORK STATISTICS")
        report.append("-" * 40)
        if 'interfaces' in stats:
            intf_stats = stats['interfaces']
            report.append(f"Interfaces: {intf_stats.get('active', 0)}/{intf_stats.get('total', 0)} active")
        if 'vlans' in stats:
            vlan_stats = stats['vlans']
            report.append(f"VLANs: {vlan_stats.get('total', 0)} configured")
        if 'routing_protocols' in stats:
            routing_stats = stats['routing_protocols']
            report.append(f"Routing Protocols: {routing_stats.get('total', 0)} configured")
        report.append("")
    
    # Issues Found
    if results['issues_found']:
        report.append("ISSUES FOUND")
        report.append("-" * 40)
        for i, issue in enumerate(results['issues_found'], 1):
            report.append(f"{i}. {issue}")
        report.append("")
    else:
        report.append("ISSUES FOUND")
        report.append("-" * 40)
        report.append("✓ No critical issues found")
        report.append("")
    
    # Load Analysis Results
    if results.get('load_analysis'):
        load = results['load_analysis']
        report.append("LOAD ANALYSIS")
        report.append("-" * 40)
        report.append(f"Network Capacity: {load.get('total_capacity_mbps', 0):.1f} Mbps")
        report.append(f"Current Utilization: {load.get('total_utilization_mbps', 0):.1f} Mbps ({load.get('utilization_percentage', 0):.1f}%)")
        report.append(f"Overloaded Links: {load.get('overloaded_links', 0)}")
        report.append(f"Underutilized Links: {load.get('underutilized_links', 0)}")
        report.append(f"Capacity Issues: {load.get('capacity_issues', 0)}")
        report.append("")
    
    # Recommendations
    if results['recommendations']:
        report.append("LOAD BALANCING RECOMMENDATIONS")
        report.append("-" * 40)
        for i, rec in enumerate(results['recommendations'], 1):
            report.append(f"{i}. {rec}")
        report.append("")
    
    # Optimization Recommendations
    if results.get('optimization_recommendations'):
        report.append("OPTIMIZATION RECOMMENDATIONS")
        report.append("-" * 40)
        for i, rec in enumerate(results['optimization_recommendations'], 1):
            report.append(f"{i}. [{rec['priority'].upper()}] {rec['title']}")
            report.append(f"   Category: {rec['category'].title()}")
            report.append(f"   Description: {rec['description']}")
            report.append(f"   Impact: {rec['impact'].title()}")
            report.append(f"   Effort: {rec['effort'].title()}")
            report.append(f"   Expected Benefit: {rec['benefit']}")
            report.append("")
    
    report.append("=" * 80)
    report.append("End of Analysis Report")
    report.append("=" * 80)
    
    return '\n'.join(report)


def run_simulation_mode(config_path: str, logger: logging.Logger, 
                      simulation_duration: float = 300.0, 
                      inject_faults: bool = True,
                      collect_stats: bool = True) -> Dict[str, Any]:
    """Run network simulation mode."""
    logger.info("Starting network simulation mode")
    
    # Load network configurations
    device_configs = load_network_configs(config_path, logger)
    
    if not device_configs:
        logger.error("No valid device configurations found")
        return {"error": "No valid configurations"}
    
    # Convert to network devices
    topology_gen = TopologyGenerator()
    devices = []
    
    for device_name, device_config in device_configs.items():
        try:
            network_device = topology_gen._create_device_from_config(device_config)
            if network_device:
                devices.append(network_device)
                logger.info(f"Created network device: {network_device.name}")
        except Exception as e:
            logger.error(f"Error creating device {device_name}: {e}")
            continue
    
    if not devices:
        logger.error("No network devices could be created")
        return {"error": "No devices created"}
    
    # Initialize simulation components
    simulator = NetworkSimulator(real_time_factor=0.1)  # 10x accelerated
    fault_injector = FaultInjector(simulator.simulation_engine)
    stats_collector = SimulationStats(collection_interval=1.0)
    
    try:
        # Add devices to simulation
        for device in devices:
            simulator.add_device(device)
        
        # Add links to simulation (simplified - based on same subnet)
        link_counter = 0
        for i, device1 in enumerate(devices):
            for j, device2 in enumerate(devices):
                if i >= j:
                    continue
                    
                # Check if devices share a subnet (simplified)
                shared = False
                for iface1 in device1.get_active_interfaces():
                    for iface2 in device2.get_active_interfaces():
                        if (iface1.ip_address and iface2.ip_address and 
                            iface1.ip_address.split('.')[:-1] == iface2.ip_address.split('.')[:-1]):
                            shared = True
                            break
                    if shared:
                        break
                
                if shared:
                    link_id = f"link_{link_counter}"
                    simulator.add_link(link_id, device1.name, device2.name)
                    link_counter += 1
                    logger.info(f"Added link {link_id} between {device1.name} and {device2.name}")
        
        # Start statistics collection
        if collect_stats:
            stats_collector.start_collection()
            logger.info("Statistics collection started")
        
        # Start simulation
        logger.info("Starting network simulation...")
        simulator.start_simulation()
        
        # Generate initial traffic
        logger.info("Generating initial traffic...")
        for i, source_device in enumerate(devices[:3]):  # Limit to first 3 devices
            for j, dest_device in enumerate(devices[:3]):
                if i != j:
                    packet_ids = simulator.generate_traffic(
                        source=source_device.name,
                        destination=dest_device.name,
                        packet_type='ip',
                        size=1500,
                        count=10
                    )
                    logger.debug(f"Generated {len(packet_ids)} packets from {source_device.name} to {dest_device.name}")
        
        # Inject some faults if enabled
        fault_ids = []
        if inject_faults and len(devices) >= 2:
            logger.info("Injecting test faults...")
            
            # Link failure
            fault_id = fault_injector.inject_link_failure(
                "link_0", duration=30.0, delay=10.0,
                description="Test link failure"
            )
            if fault_id:
                fault_ids.append(fault_id)
                logger.info(f"Scheduled link failure: {fault_id}")
            
            # Device failure  
            if len(devices) >= 3:
                fault_id = fault_injector.inject_device_failure(
                    devices[2].name, duration=20.0, delay=20.0,
                    description="Test device failure"
                )
                if fault_id:
                    fault_ids.append(fault_id)
                    logger.info(f"Scheduled device failure: {fault_id}")
        
        # Run simulation
        logger.info(f"Running simulation for {simulation_duration} seconds...")
        time.sleep(simulation_duration)
        
        # Collect final statistics
        simulation_stats = simulator.get_simulation_statistics()
        fault_stats = fault_injector.get_fault_statistics()
        
        if collect_stats:
            stats_summary = stats_collector.get_simulation_summary()
            interface_stats = stats_collector.get_interface_statistics()
            protocol_stats = stats_collector.get_protocol_statistics()
            traffic_flows = stats_collector.get_traffic_flows()
            congestion_analysis = stats_collector.get_congestion_analysis()
        else:
            stats_summary = {}
            interface_stats = {}
            protocol_stats = {}
            traffic_flows = {}
            congestion_analysis = {}
        
        # Stop simulation
        simulator.stop_simulation()
        if collect_stats:
            stats_collector.stop_collection()
        
        logger.info("Simulation completed successfully")
        
        return {
            "simulation_results": {
                "duration": simulation_duration,
                "devices_simulated": len(devices),
                "faults_injected": len(fault_ids),
                "simulation_statistics": simulation_stats,
                "fault_statistics": fault_stats,
                "performance_statistics": stats_summary,
                "interface_statistics": interface_stats,
                "protocol_statistics": protocol_stats,
                "traffic_flows": traffic_flows,
                "congestion_analysis": congestion_analysis
            }
        }
        
    except Exception as e:
        logger.error(f"Error during simulation: {e}")
        # Cleanup
        try:
            simulator.stop_simulation()
            if collect_stats:
                stats_collector.stop_collection()
        except:
            pass
        return {"error": f"Simulation failed: {str(e)}"}


def main():
    """Main entry point for the Enhanced Network Analyzer."""
    parser = argparse.ArgumentParser(
        description="Enhanced Network Analyzer - Advanced network analysis and simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Configuration Analysis
  python network_analyzer.py --config configs/sample_network/    Analyze sample network
  python network_analyzer.py --config router.dump --format json Output JSON report
  python network_analyzer.py --config configs/ --output report.txt Save report to file
  python network_analyzer.py --config configs/ --verbose         Detailed analysis
  
  # Network Simulation  
  python network_analyzer.py --config configs/ --simulate        Run simulation
  python network_analyzer.py --config configs/ --simulate --duration 600 --no-faults
  python network_analyzer.py --config configs/ --simulate --output simulation_report.json
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Enhanced Network Analyzer v1.0.0"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to configuration file or directory containing network configs"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        help="Output file path for analysis report"
    )
    
    parser.add_argument(
        "--format",
        type=str,
        choices=['text', 'json'],
        default='text',
        help="Output format for the analysis report (default: text)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output and detailed logging"
    )
    
    parser.add_argument(
        "--load-analysis",
        action="store_true",
        help="Enable network load analysis (requires traffic data)"
    )
    
    parser.add_argument(
        "--optimization",
        action="store_true",
        help="Enable optimization recommendations"
    )
    
    # Simulation-specific arguments
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run network simulation mode"
    )
    
    parser.add_argument(
        "--duration",
        type=float,
        default=300.0,
        help="Simulation duration in seconds (default: 300)"
    )
    
    parser.add_argument(
        "--no-faults",
        action="store_true",
        help="Disable fault injection during simulation"
    )
    
    parser.add_argument(
        "--no-stats",
        action="store_true", 
        help="Disable statistics collection during simulation"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose)
    
    print("Enhanced Network Analyzer v1.0.0")
    print("=" * 50)
    print()
    
    # Validate config path
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"✗ Configuration path not found: {config_path}")
        return 1
    
    # Load network configurations
    configurations = load_network_configs(str(config_path), logger)
    if not configurations:
        print("✗ Failed to load any network configurations")
        return 1
    
    print(f"✓ Loaded {len(configurations)} network configuration(s)")
    
    # Check if simulation mode is requested
    if args.simulate:
        print("🚀 Running network simulation...")
        simulation_results = run_simulation_mode(
            str(config_path), logger,
            simulation_duration=args.duration,
            inject_faults=not args.no_faults,
            collect_stats=not args.no_stats
        )
        
        # Generate simulation report
        if "error" in simulation_results:
            print(f"✗ Simulation failed: {simulation_results['error']}")
            return 1
        else:
            report = generate_analysis_report(simulation_results, args.format)
            
            if args.output:
                try:
                    output_path = Path(args.output)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(output_path, 'w') as f:
                        f.write(report)
                    print(f"✓ Simulation report saved to: {output_path}")
                except Exception as e:
                    logger.error(f"Failed to save report: {e}")
                    return 1
            else:
                print("\n" + report)
            
            print("✅ Network simulation completed successfully")
            return 0
    
    # Standard analysis mode
    print("🔍 Analyzing network configuration...")
    analysis_results = analyze_network_configuration(
        configurations, logger, 
        enable_load_analysis=args.load_analysis,
        enable_optimization=args.optimization
    )
    
    # Generate and display/save report
    report = generate_analysis_report(analysis_results, args.format)
    
    if args.output:
        try:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(report)
            print(f"✓ Analysis report saved to: {output_path}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return 1
    else:
        # Display report to console
        print("\n" + report)
    
    # Summary
    issues_count = len(analysis_results.get('issues_found', []))
    if issues_count == 0:
        print("\n✅ Network analysis completed successfully - No critical issues found")
        return 0
    else:
        print(f"\n⚠️  Network analysis completed with {issues_count} issue(s) found")
        print("Review the analysis report for detailed information and recommendations.")
        return 1


if __name__ == "__main__":
    sys.exit(main())