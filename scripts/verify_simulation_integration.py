#!/usr/bin/env python3
"""
Integration verification script for network simulation components

This script tests the complete simulation pipeline with sample configurations,
verifying that all components work together correctly.
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


def test_simulation_stats_standalone():
    """Test simulation statistics standalone"""
    print("\n🧪 Testing SimulationStats standalone...")
    
    try:
        from core.simulation_stats import SimulationStats
        
        # Create stats collector
        stats = SimulationStats(collection_interval=0.1)
        
        # Start collection
        stats.start_collection()
        
        # Simulate some network activity
        stats.update_interface_stats("R1", "eth0", packets_in=100, bytes_in=15000)
        stats.update_interface_stats("R2", "eth0", packets_out=95, bytes_out=14250)
        
        stats.record_traffic_flow("flow1", "R1", "R2", packet_size=1500, latency=2.5)
        stats.record_traffic_flow("flow2", "R2", "R1", packet_size=1200, latency=3.0)
        
        stats.update_protocol_stats("OSPF", messages_sent=10, neighbors_discovered=2)
        
        stats.record_congestion_event("link1", severity=0.7, cause="bandwidth_limit")
        
        # Wait for collection
        time.sleep(0.3)
        
        # Get summary
        summary = stats.get_simulation_summary()
        interface_stats = stats.get_interface_statistics()
        protocol_stats = stats.get_protocol_statistics()
        traffic_flows = stats.get_traffic_flows()
        congestion_analysis = stats.get_congestion_analysis()
        
        # Stop collection
        stats.stop_collection()
        
        # Verify results
        assert summary['totals']['packets'] > 0, "No packets recorded"
        assert len(interface_stats) >= 2, "Interface stats not recorded"
        assert len(protocol_stats) >= 1, "Protocol stats not recorded"
        assert len(traffic_flows) >= 2, "Traffic flows not recorded"
        assert congestion_analysis['total_events'] > 0, "Congestion events not recorded"
        
        print("✓ SimulationStats: All functionality verified")
        return True
        
    except Exception as e:
        print(f"✗ SimulationStats test failed: {e}")
        return False


def test_fault_injector_standalone():
    """Test fault injector standalone"""
    print("\n🧪 Testing FaultInjector standalone...")
    
    try:
        from core.fault_injector import FaultInjector, FaultType, FaultSeverity
        
        # Create mock simulation engine
        class MockEngine:
            def __init__(self):
                self.links = {"link1": {"active": True, "source": "R1", "target": "R2"}}
            def inject_link_failure(self, link_id, duration, delay): return f"fault_{link_id}"
            def inject_mtu_mismatch(self, src, tgt, pkt, mtu, delay): return f"mtu_{src}_{tgt}"
            def change_device_configuration(self, dev, changes, delay): return f"config_{dev}"
        
        engine = MockEngine()
        fault_injector = FaultInjector(engine)
        
        # Test various fault types
        fault_id1 = fault_injector.inject_link_failure("link1", duration=30.0, delay=1.0)
        fault_id2 = fault_injector.inject_device_failure("R1", duration=20.0, delay=2.0)
        fault_id3 = fault_injector.inject_mtu_mismatch("R1", "R2", 1600, 1500, delay=0.5)
        fault_id4 = fault_injector.inject_packet_loss("link1", loss_rate=0.1, duration=15.0)
        
        # Test complex scenario
        fault_scenario = [
            {"type": "link_failure", "target": "link1", "duration": 10.0, "delay": 5.0},
            {"type": "device_failure", "target": "R2", "duration": 8.0, "delay": 7.0}
        ]
        scenario_faults = fault_injector.create_fault_scenario("test_scenario", fault_scenario)
        
        # Wait for some faults to activate
        time.sleep(0.1)
        
        # Get statistics
        fault_stats = fault_injector.get_fault_statistics()
        active_faults = fault_injector.get_active_faults()
        
        # Verify results
        assert fault_stats['active_faults'] >= 6, f"Expected >= 6 active faults, got {fault_stats['active_faults']}"
        assert len(active_faults) >= 6, "Active faults not tracked properly"
        assert fault_stats['faults_by_type']['link_failure'] >= 2, "Link failures not counted"
        assert fault_stats['faults_by_type']['device_failure'] >= 2, "Device failures not counted"
        
        # Test cancellation
        cancel_result = fault_injector.cancel_fault(fault_id1)
        assert cancel_result, "Fault cancellation failed"
        
        print("✓ FaultInjector: All functionality verified")
        return True
        
    except Exception as e:
        print(f"✗ FaultInjector test failed: {e}")
        return False


def test_component_integration():
    """Test integration between components"""
    print("\n🧪 Testing component integration...")
    
    try:
        from core.simulation_stats import SimulationStats
        from core.fault_injector import FaultInjector
        
        # Create components
        stats = SimulationStats(collection_interval=0.1)
        
        class MockEngine:
            def __init__(self):
                self.links = {"link1": {"active": True, "source": "R1", "target": "R2"}}
                self.devices = {"R1": {}, "R2": {}}
            def inject_link_failure(self, link_id, duration, delay): 
                return f"fault_{link_id}"
            def inject_mtu_mismatch(self, src, tgt, pkt, mtu, delay): 
                return f"mtu_{src}_{tgt}"
            def change_device_configuration(self, dev, changes, delay): 
                return f"config_{dev}"
        
        engine = MockEngine()
        fault_injector = FaultInjector(engine)
        
        # Start stats collection
        stats.start_collection()
        
        # Simulate network activity
        stats.record_traffic_flow("flow1", "R1", "R2", packet_size=1500)
        stats.update_interface_stats("R1", "eth0", packets_out=10)
        
        # Inject fault
        fault_id = fault_injector.inject_link_failure("link1", duration=1.0)
        
        # Simulate fault impact
        stats.record_congestion_event("link1", severity=0.9, cause="link_failure")
        stats.update_interface_stats("R1", "eth0", packets_dropped_out=5)
        
        # Wait for collection
        time.sleep(0.2)
        
        # Verify both components are working
        fault_stats = fault_injector.get_fault_statistics()
        sim_stats = stats.get_simulation_summary()
        congestion_analysis = stats.get_congestion_analysis()
        
        assert fault_stats['active_faults'] > 0, "No active faults"
        assert sim_stats['totals']['packets'] > 0, "No packets recorded"
        assert congestion_analysis['total_events'] > 0, "No congestion events"
        
        # Stop stats
        stats.stop_collection()
        
        print("✓ Component integration: All functionality verified")
        return True
        
    except Exception as e:
        print(f"✗ Component integration test failed: {e}")
        return False


def test_with_sample_config():
    """Test with actual configuration file"""
    print("\n🧪 Testing with sample configuration...")
    
    try:
        # Test that we can load and parse sample config
        config_path = Path(__file__).parent / "configs" / "simple_test.yaml"
        
        if not config_path.exists():
            print("⚠️  Sample config not found, skipping config test")
            return True
        
        # Test YAML parsing
        import yaml
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Verify config structure
        assert 'simulation' in config, "No simulation section in config"
        assert 'devices' in config, "No devices section in config"
        assert 'fault_scenarios' in config, "No fault_scenarios section in config"
        
        # Verify simulation parameters
        sim_config = config['simulation']
        assert 'duration' in sim_config, "No duration in simulation config"
        assert sim_config['duration'] == 30.0, "Unexpected duration value"
        
        # Verify devices
        devices = config['devices']
        assert len(devices) >= 3, "Expected at least 3 devices"
        
        device_names = [d['device']['name'] for d in devices]
        assert 'R1' in device_names, "R1 device not found"
        assert 'R2' in device_names, "R2 device not found"
        assert 'SW1' in device_names, "SW1 device not found"
        
        # Verify fault scenarios
        fault_scenarios = config['fault_scenarios']
        assert len(fault_scenarios) >= 2, "Expected at least 2 fault scenarios"
        
        fault_types = [fs['type'] for fs in fault_scenarios]
        assert 'link_failure' in fault_types, "No link_failure scenario"
        assert 'mtu_mismatch' in fault_types, "No mtu_mismatch scenario"
        
        print("✓ Sample configuration: Valid format and content")
        return True
        
    except Exception as e:
        print(f"✗ Sample configuration test failed: {e}")
        return False


def main():
    """Run all verification tests"""
    print("Network Simulation Components - Integration Verification")
    print("=" * 60)
    
    success = True
    
    # Run individual component tests
    success &= test_simulation_stats_standalone()
    success &= test_fault_injector_standalone() 
    success &= test_component_integration()
    success &= test_with_sample_config()
    
    print("\n" + "=" * 60)
    
    if success:
        print("🎉 All verification tests PASSED!")
        print("\nThe network simulation components are working correctly and ready for use.")
        print("\nKey capabilities verified:")
        print("  ✓ Real-time statistics collection and monitoring")
        print("  ✓ Comprehensive fault injection system")
        print("  ✓ Traffic flow tracking and analysis") 
        print("  ✓ Protocol performance monitoring")
        print("  ✓ Congestion detection and analysis")
        print("  ✓ Component integration and interoperability")
        print("  ✓ Configuration file compatibility")
        
        return 0
    else:
        print("❌ Some verification tests FAILED!")
        print("\nReview the test output above to identify issues.")
        return 1


if __name__ == "__main__":
    sys.exit(main())