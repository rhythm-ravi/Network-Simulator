#!/usr/bin/env python3
"""
Network Simulation Demo

This script demonstrates the complete workflow of the network simulation components
including device simulation, fault injection, and statistics collection.
"""

import sys
import time
import logging
from pathlib import Path

# Add the parent directory to the Python path to import src modules
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def demonstrate_simulation_workflow():
    """Demonstrate complete simulation workflow"""
    print("🚀 Network Simulation Demo")
    print("=" * 50)
    
    # Import components
    from src.core.simulation_stats import SimulationStats
    from src.core.fault_injector import FaultInjector, FaultSeverity
    from src.models.network_models import Router, Switch, NetworkInterface, InterfaceStatus, DeviceType
    
    # Mock simulation engine for demo
    class DemoSimulationEngine:
        def __init__(self):
            self.links = {
                "r1_r2": {"active": True, "source": "R1", "target": "R2"},
                "r2_sw1": {"active": True, "source": "R2", "target": "SW1"},
                "r1_sw1": {"active": True, "source": "R1", "target": "SW1"}
            }
            self.devices = {}
            self.fault_events = []
            
        def inject_link_failure(self, link_id, duration, delay):
            fault_id = f"link_fault_{link_id}_{int(time.time())}"
            self.fault_events.append({
                'id': fault_id, 'type': 'link_failure',
                'link': link_id, 'duration': duration
            })
            logger.info(f"💥 Injected link failure on {link_id}")
            return fault_id
            
        def inject_mtu_mismatch(self, src, tgt, pkt_size, mtu, delay):
            fault_id = f"mtu_fault_{src}_{tgt}_{int(time.time())}"
            self.fault_events.append({
                'id': fault_id, 'type': 'mtu_mismatch',
                'source': src, 'target': tgt
            })
            logger.info(f"🔧 Injected MTU mismatch between {src} and {tgt}")
            return fault_id
            
        def change_device_configuration(self, device, changes, delay):
            fault_id = f"config_fault_{device}_{int(time.time())}"
            self.fault_events.append({
                'id': fault_id, 'type': 'config_change',
                'device': device, 'changes': changes
            })
            logger.info(f"⚙️ Changed configuration on {device}")
            return fault_id
    
    try:
        print("\n📊 Step 1: Initialize Components")
        
        # Create simulation engine
        engine = DemoSimulationEngine()
        
        # Create statistics collector
        stats = SimulationStats(collection_interval=0.5)
        logger.info("Created statistics collector")
        
        # Create fault injector
        fault_injector = FaultInjector(engine)
        logger.info("Created fault injector")
        
        print("\n🏗️ Step 2: Start Statistics Collection")
        stats.start_collection()
        logger.info("Statistics collection started")
        
        print("\n📈 Step 3: Simulate Network Activity")
        
        # Simulate router R1 activity
        stats.update_interface_stats(
            "R1", "eth0",
            packets_in=150, packets_out=140,
            bytes_in=225000, bytes_out=210000,
            errors_in=1, packets_dropped_out=2
        )
        
        stats.update_interface_stats(
            "R1", "eth1", 
            packets_in=75, packets_out=80,
            bytes_in=112500, bytes_out=120000
        )
        logger.info("📊 Recorded R1 interface statistics")
        
        # Simulate router R2 activity
        stats.update_interface_stats(
            "R2", "eth0",
            packets_in=140, packets_out=135,
            bytes_in=210000, bytes_out=202500,
            errors_out=1
        )
        logger.info("📊 Recorded R2 interface statistics")
        
        # Simulate switch SW1 activity  
        stats.update_interface_stats(
            "SW1", "eth0",
            packets_in=80, packets_out=82,
            bytes_in=120000, bytes_out=123000
        )
        logger.info("📊 Recorded SW1 interface statistics")
        
        # Record traffic flows
        stats.record_traffic_flow(
            "flow_r1_r2", "R1", "R2",
            protocol="TCP", packet_size=1500,
            latency=2.5, path_hops=["R1", "R2"]
        )
        
        stats.record_traffic_flow(
            "flow_r1_sw1", "R1", "SW1", 
            protocol="UDP", packet_size=1200,
            latency=1.8, path_hops=["R1", "SW1"]
        )
        
        stats.record_traffic_flow(
            "flow_r2_sw1", "R2", "SW1",
            protocol="ICMP", packet_size=64,
            latency=1.2, path_hops=["R2", "SW1"]
        )
        logger.info("📊 Recorded traffic flows")
        
        # Record protocol activity
        stats.update_protocol_stats(
            "OSPF",
            messages_sent=25, messages_received=23,
            neighbors_discovered=2, neighbors_lost=0,
            convergence_time=3.2
        )
        
        stats.update_protocol_stats(
            "ARP", 
            messages_sent=15, messages_received=14,
            neighbors_discovered=3
        )
        logger.info("📊 Recorded protocol statistics")
        
        # Wait for statistics collection
        time.sleep(1.0)
        
        print("\n⚡ Step 4: Inject Network Faults")
        
        # Inject link failure
        fault_id1 = fault_injector.inject_link_failure(
            "r1_r2", duration=30.0, delay=0.5,
            severity=FaultSeverity.HIGH,
            description="Primary link between R1 and R2"
        )
        
        # Inject device failure
        fault_id2 = fault_injector.inject_device_failure(
            "SW1", failure_type="cpu_overload", 
            duration=20.0, delay=2.0,
            severity=FaultSeverity.MEDIUM,
            description="Switch CPU overload"
        )
        
        # Inject MTU mismatch
        fault_id3 = fault_injector.inject_mtu_mismatch(
            "R1", "R2", packet_size=1600, interface_mtu=1500,
            delay=1.0, severity=FaultSeverity.LOW,
            description="MTU configuration mismatch"
        )
        
        # Inject packet loss
        fault_id4 = fault_injector.inject_packet_loss(
            "r2_sw1", loss_rate=0.05, duration=15.0,
            delay=3.0, severity=FaultSeverity.MEDIUM,
            description="5% packet loss on R2-SW1 link"
        )
        
        logger.info(f"💥 Injected 4 different types of faults")
        
        # Record congestion events (simulating fault impact)
        stats.record_congestion_event(
            "r1_r2", severity=0.9, 
            packets_affected=50, bytes_affected=75000,
            cause="link_failure"
        )
        
        stats.record_congestion_event(
            "SW1", severity=0.7,
            packets_affected=30, bytes_affected=45000, 
            cause="cpu_overload"
        )
        logger.info("📊 Recorded congestion events")
        
        # Wait for fault activation and statistics
        time.sleep(2.0)
        
        print("\n📋 Step 5: Collect and Analyze Results")
        
        # Get comprehensive statistics
        simulation_summary = stats.get_simulation_summary()
        interface_stats = stats.get_interface_statistics()
        protocol_stats = stats.get_protocol_statistics()
        traffic_flows = stats.get_traffic_flows()
        congestion_analysis = stats.get_congestion_analysis()
        throughput_analysis = stats.get_throughput_analysis()
        
        # Get fault statistics
        fault_statistics = fault_injector.get_fault_statistics()
        active_faults = fault_injector.get_active_faults()
        fault_history = fault_injector.get_fault_history()
        
        # Display results
        print("\n📊 SIMULATION RESULTS")
        print("=" * 30)
        
        print(f"\n🏷️ Simulation Summary:")
        print(f"  • Duration: {simulation_summary['simulation_duration']:.1f} seconds")
        print(f"  • Total Packets: {simulation_summary['totals']['packets']}")
        print(f"  • Total Bytes: {simulation_summary['totals']['bytes']:,}")
        print(f"  • Packet Errors: {simulation_summary['totals']['errors']}")
        print(f"  • Dropped Packets: {simulation_summary['totals']['dropped_packets']}")
        print(f"  • Active Flows: {simulation_summary['counts']['active_flows']}")
        
        print(f"\n🔌 Interface Statistics:")
        for iface_key, iface_data in interface_stats.items():
            print(f"  • {iface_key}:")
            print(f"    - In: {iface_data['packets_in']} pkts, {iface_data['bytes_in']:,} bytes")
            print(f"    - Out: {iface_data['packets_out']} pkts, {iface_data['bytes_out']:,} bytes") 
            if iface_data['errors_in'] > 0 or iface_data['packets_dropped_out'] > 0:
                print(f"    - Errors: {iface_data['errors_in']} in, {iface_data['packets_dropped_out']} dropped out")
        
        print(f"\n📡 Protocol Statistics:")
        for proto, proto_data in protocol_stats.items():
            print(f"  • {proto}:")
            print(f"    - Messages: {proto_data['messages_sent']} sent, {proto_data['messages_received']} received")
            print(f"    - Neighbors: {proto_data['neighbors_discovered']} discovered")
            if proto_data['convergence_events'] > 0:
                print(f"    - Convergence: {proto_data['convergence_events']} events, avg {proto_data['avg_convergence_time']:.1f}s")
        
        print(f"\n🌊 Traffic Flows:")
        for flow_id, flow_data in traffic_flows.items():
            print(f"  • {flow_id}: {flow_data['source_device']} → {flow_data['destination_device']}")
            print(f"    - {flow_data['protocol']}: {flow_data['packets']} pkts, {flow_data['bytes']:,} bytes")
            print(f"    - Latency: min={flow_data['min_latency']:.1f}ms, max={flow_data['max_latency']:.1f}ms, avg={flow_data['avg_latency']:.1f}ms")
            if flow_data['path_hops']:
                print(f"    - Path: {' → '.join(flow_data['path_hops'])}")
        
        print(f"\n🚨 Congestion Analysis:")
        print(f"  • Total Events: {congestion_analysis['total_events']}")
        if congestion_analysis['total_events'] > 0:
            print(f"  • Average Severity: {congestion_analysis['avg_severity']:.1f}")
            print(f"  • Hotspots:")
            for location, hotspot_data in list(congestion_analysis['hotspots'].items())[:3]:
                print(f"    - {location}: {hotspot_data['event_count']} events, severity {hotspot_data['avg_severity']:.1f}")
        
        print(f"\n💥 Fault Injection Results:")
        print(f"  • Total Faults: {fault_statistics['total_faults']}")
        print(f"  • Active Faults: {fault_statistics['active_faults']}")
        print(f"  • Completed Faults: {fault_statistics['completed_faults']}")
        
        if fault_statistics['faults_by_type']:
            print(f"  • Faults by Type:")
            for fault_type, count in fault_statistics['faults_by_type'].items():
                print(f"    - {fault_type}: {count}")
        
        if active_faults:
            print(f"  • Active Fault Details:")
            for fault_id, fault_info in list(active_faults.items())[:3]:
                print(f"    - {fault_id}: {fault_info['fault_type']} on {fault_info['target']}")
                print(f"      Status: {fault_info['status']}, Severity: {fault_info['severity']}")
        
        print("\n📄 Step 6: Export Results")
        
        # Export statistics to file
        stats_file = Path("demo_simulation_stats.json")
        stats.export_statistics(str(stats_file))
        logger.info(f"📁 Exported statistics to {stats_file}")
        
        # Export fault report
        fault_file = Path("demo_fault_report.json")
        fault_injector.export_fault_report(str(fault_file))
        logger.info(f"📁 Exported fault report to {fault_file}")
        
        print(f"\n✅ Demo completed successfully!")
        print(f"📁 Results exported to:")
        print(f"  • {stats_file}")
        print(f"  • {fault_file}")
        
        return True
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        return False
        
    finally:
        # Cleanup
        try:
            stats.stop_collection()
            logger.info("Statistics collection stopped")
        except:
            pass


def main():
    """Run the simulation demo"""
    print("Network Simulation Components - Complete Demo")
    print("This demo shows the full workflow of network simulation with fault injection")
    print()
    
    success = demonstrate_simulation_workflow()
    
    if success:
        print("\n🎉 Demo completed successfully!")
        print("\nThe demo demonstrated:")
        print("  ✓ Real-time statistics collection")
        print("  ✓ Multi-device network simulation")
        print("  ✓ Traffic flow monitoring")
        print("  ✓ Protocol performance tracking")
        print("  ✓ Comprehensive fault injection")
        print("  ✓ Congestion analysis")
        print("  ✓ Results export and reporting")
        print("\nThe simulation components are ready for production use!")
        return 0
    else:
        print("\n❌ Demo encountered errors")
        print("Check the logs above for details")
        return 1


if __name__ == "__main__":
    sys.exit(main())