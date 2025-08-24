#!/usr/bin/env python3
"""
Tests for the new network simulation components
"""

import sys
import unittest
import time
import threading
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from core.simulation_stats import SimulationStats, MetricType, InterfaceStats, TrafficFlow
from core.fault_injector import FaultInjector, FaultType, FaultSeverity, FaultStatus


class MockSimulationEngine:
    """Mock simulation engine for testing"""
    
    def __init__(self):
        self.links = {
            "link1": {"active": True, "source": "R1", "target": "R2"},
            "link2": {"active": True, "source": "R2", "target": "SW1"}
        }
        self.devices = {"R1": {"name": "R1"}, "R2": {"name": "R2"}, "SW1": {"name": "SW1"}}
        self.fault_counter = 0
    
    def inject_link_failure(self, link_id, duration, delay):
        self.fault_counter += 1
        return f"fault_link_{self.fault_counter}_{link_id}"
    
    def inject_mtu_mismatch(self, src, tgt, pkt_size, mtu, delay):
        self.fault_counter += 1
        return f"fault_mtu_{self.fault_counter}_{src}_{tgt}"
    
    def change_device_configuration(self, device, changes, delay):
        self.fault_counter += 1
        return f"fault_config_{self.fault_counter}_{device}"


class TestSimulationStats(unittest.TestCase):
    """Test SimulationStats functionality"""
    
    def setUp(self):
        self.stats = SimulationStats(collection_interval=0.1)
    
    def tearDown(self):
        self.stats.stop_collection()
    
    def test_metric_recording(self):
        """Test basic metric recording"""
        # Record some metrics
        self.stats.record_metric("test.counter", 10.0)
        self.stats.record_metric("test.counter", 20.0) 
        self.stats.record_metric("test.gauge", 42.5)
        
        # Check metrics are stored
        self.assertIn("test.counter", self.stats.metrics)
        self.assertIn("test.gauge", self.stats.metrics)
        self.assertEqual(len(self.stats.metrics["test.counter"]), 2)
        self.assertEqual(self.stats.metrics["test.gauge"][-1].value, 42.5)
    
    def test_interface_stats(self):
        """Test interface statistics tracking"""
        # Update interface stats
        self.stats.update_interface_stats(
            "R1", "eth0", 
            packets_in=100, packets_out=50,
            bytes_in=15000, bytes_out=7500,
            errors_in=2, packets_dropped_in=1
        )
        
        # Check stats are recorded
        stats_data = self.stats.get_interface_statistics()
        self.assertIn("R1:eth0", stats_data)
        
        interface_data = stats_data["R1:eth0"]
        self.assertEqual(interface_data["packets_in"], 100)
        self.assertEqual(interface_data["packets_out"], 50)
        self.assertEqual(interface_data["bytes_in"], 15000)
        self.assertEqual(interface_data["errors_in"], 2)
        self.assertEqual(interface_data["packets_dropped_in"], 1)
    
    def test_protocol_stats(self):
        """Test protocol statistics tracking"""
        # Update protocol stats
        self.stats.update_protocol_stats(
            "OSPF",
            messages_sent=10,
            messages_received=8,
            neighbors_discovered=3,
            convergence_time=2.5
        )
        
        # Check stats are recorded
        protocol_data = self.stats.get_protocol_statistics()
        self.assertIn("OSPF", protocol_data)
        
        ospf_data = protocol_data["OSPF"]
        self.assertEqual(ospf_data["messages_sent"], 10)
        self.assertEqual(ospf_data["messages_received"], 8)
        self.assertEqual(ospf_data["neighbors_discovered"], 3)
        self.assertEqual(ospf_data["convergence_events"], 1)
        self.assertEqual(ospf_data["avg_convergence_time"], 2.5)
    
    def test_traffic_flows(self):
        """Test traffic flow tracking"""
        # Record traffic flows
        self.stats.record_traffic_flow(
            "flow1", "R1", "R2", 
            packet_size=1500, latency=5.0,
            path_hops=["R1", "SW1", "R2"]
        )
        
        self.stats.record_traffic_flow(
            "flow1", "R1", "R2",
            packet_size=1500, latency=3.0,
            path_hops=["R1", "SW1", "R2"]  
        )
        
        # Check flow data
        flows = self.stats.get_traffic_flows()
        self.assertIn("flow1", flows)
        
        flow_data = flows["flow1"]
        self.assertEqual(flow_data["source_device"], "R1")
        self.assertEqual(flow_data["destination_device"], "R2")
        self.assertEqual(flow_data["packets"], 2)
        self.assertEqual(flow_data["bytes"], 3000)
        self.assertEqual(flow_data["min_latency"], 3.0)
        self.assertEqual(flow_data["max_latency"], 5.0)
        self.assertEqual(flow_data["path_hops"], ["R1", "SW1", "R2"])
    
    def test_congestion_events(self):
        """Test congestion event recording"""
        # Record congestion events
        self.stats.record_congestion_event(
            "link1", 0.8, packets_affected=100, cause="bandwidth_limit"
        )
        
        self.stats.record_congestion_event(
            "R1", 0.6, packets_affected=50, cause="cpu_overload"
        )
        
        # Check congestion analysis
        analysis = self.stats.get_congestion_analysis()
        self.assertEqual(analysis["total_events"], 2)
        self.assertIn("link1", analysis["hotspots"])
        self.assertIn("R1", analysis["hotspots"])
        self.assertIn("bandwidth_limit", analysis["causes"])
        self.assertIn("cpu_overload", analysis["causes"])
    
    def test_collection_loop(self):
        """Test statistics collection loop"""
        # Start collection
        self.stats.start_collection()
        self.assertTrue(self.stats.running)
        
        # Add some data
        self.stats.update_interface_stats("R1", "eth0", packets_in=10, bytes_in=1500)
        
        # Wait a bit for collection
        time.sleep(0.3)
        
        # Check that metrics were collected
        summary = self.stats.get_simulation_summary()
        self.assertGreater(summary["totals"]["packets"], 0)
        
        # Stop collection
        self.stats.stop_collection()
        self.assertFalse(self.stats.running)
    
    def test_export_statistics(self):
        """Test statistics export"""
        # Add some data
        self.stats.update_interface_stats("R1", "eth0", packets_in=100, bytes_in=15000)
        self.stats.record_traffic_flow("flow1", "R1", "R2", packet_size=1500)
        
        # Export to file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            exported_data = self.stats.export_statistics(temp_file)
            
            # Check exported data structure
            self.assertIn("timestamp", exported_data)
            self.assertIn("simulation_summary", exported_data)
            self.assertIn("interface_statistics", exported_data)
            self.assertIn("traffic_flows", exported_data)
            
            # Check file was created
            self.assertTrue(Path(temp_file).exists())
            
        finally:
            # Cleanup
            try:
                Path(temp_file).unlink()
            except:
                pass


class TestFaultInjector(unittest.TestCase):
    """Test FaultInjector functionality"""
    
    def setUp(self):
        self.mock_engine = MockSimulationEngine()
        self.fault_injector = FaultInjector(self.mock_engine)
    
    def test_link_failure_injection(self):
        """Test link failure injection"""
        fault_id = self.fault_injector.inject_link_failure(
            "link1", duration=30.0, delay=0.1,
            description="Test link failure"
        )
        
        self.assertIsNotNone(fault_id)
        self.assertIn(fault_id, self.fault_injector.active_faults)
        
        scenario = self.fault_injector.active_faults[fault_id]
        self.assertEqual(scenario.fault_type, FaultType.LINK_FAILURE)
        self.assertEqual(scenario.target, "link1")
        self.assertEqual(scenario.duration, 30.0)
        self.assertEqual(scenario.description, "Test link failure")
    
    def test_device_failure_injection(self):
        """Test device failure injection"""
        fault_id = self.fault_injector.inject_device_failure(
            "R1", failure_type="cpu_overload", duration=20.0,
            severity=FaultSeverity.HIGH
        )
        
        self.assertIsNotNone(fault_id)
        self.assertIn(fault_id, self.fault_injector.active_faults)
        
        scenario = self.fault_injector.active_faults[fault_id]
        self.assertEqual(scenario.fault_type, FaultType.DEVICE_FAILURE)
        self.assertEqual(scenario.target, "R1")
        self.assertEqual(scenario.severity, FaultSeverity.HIGH)
        self.assertEqual(scenario.parameters["failure_type"], "cpu_overload")
    
    def test_mtu_mismatch_injection(self):
        """Test MTU mismatch injection"""
        fault_id = self.fault_injector.inject_mtu_mismatch(
            "R1", "R2", packet_size=1600, interface_mtu=1500
        )
        
        self.assertIsNotNone(fault_id)
        scenario = self.fault_injector.active_faults[fault_id]
        self.assertEqual(scenario.fault_type, FaultType.MTU_MISMATCH)
        self.assertEqual(scenario.parameters["packet_size"], 1600)
        self.assertEqual(scenario.parameters["interface_mtu"], 1500)
    
    def test_packet_loss_injection(self):
        """Test packet loss injection"""
        fault_id = self.fault_injector.inject_packet_loss(
            "link1", loss_rate=0.1, duration=60.0
        )
        
        self.assertIsNotNone(fault_id)
        scenario = self.fault_injector.active_faults[fault_id]
        self.assertEqual(scenario.fault_type, FaultType.PACKET_LOSS)
        self.assertEqual(scenario.parameters["loss_rate"], 0.1)
    
    def test_configuration_error_injection(self):
        """Test configuration error injection"""
        config_changes = {
            "interface_status": {"interface": "eth0", "status": "down"}
        }
        
        fault_id = self.fault_injector.inject_configuration_error(
            "R1", config_changes, duration=30.0
        )
        
        self.assertIsNotNone(fault_id)
        scenario = self.fault_injector.active_faults[fault_id]
        self.assertEqual(scenario.fault_type, FaultType.CONFIG_ERROR)
        self.assertEqual(scenario.parameters["config_changes"], config_changes)
    
    def test_fault_scenario_creation(self):
        """Test complex fault scenario creation"""
        faults = [
            {
                "type": "link_failure",
                "target": "link1",
                "duration": 30.0,
                "delay": 5.0,
                "description": "Primary link failure"
            },
            {
                "type": "device_failure", 
                "target": "R1",
                "duration": 20.0,
                "delay": 10.0,
                "severity": "high",
                "description": "Router failure"
            }
        ]
        
        fault_ids = self.fault_injector.create_fault_scenario(
            "cascading_failure", faults, "Test cascading failure scenario"
        )
        
        self.assertEqual(len(fault_ids), 2)
        
        for fault_id in fault_ids:
            self.assertIn(fault_id, self.fault_injector.active_faults)
            scenario = self.fault_injector.active_faults[fault_id]
            self.assertIn("cascading_failure", scenario.tags)
    
    def test_fault_statistics(self):
        """Test fault statistics collection"""
        # Inject several faults
        self.fault_injector.inject_link_failure("link1")
        self.fault_injector.inject_device_failure("R1")
        self.fault_injector.inject_packet_loss("link2", loss_rate=0.05)
        
        # Get statistics
        stats = self.fault_injector.get_fault_statistics()
        
        self.assertEqual(stats["active_faults"], 3)
        self.assertEqual(stats["total_faults"], 3)
        self.assertIn("link_failure", stats["faults_by_type"])
        self.assertIn("device_failure", stats["faults_by_type"])
        self.assertIn("packet_loss", stats["faults_by_type"])
    
    def test_active_faults_info(self):
        """Test getting active fault information"""
        fault_id = self.fault_injector.inject_link_failure(
            "link1", duration=30.0, description="Test failure"
        )
        
        active_faults = self.fault_injector.get_active_faults()
        self.assertIn(fault_id, active_faults)
        
        fault_info = active_faults[fault_id]
        self.assertEqual(fault_info["fault_type"], "link_failure")
        self.assertEqual(fault_info["target"], "link1")
        self.assertEqual(fault_info["description"], "Test failure")
        self.assertIn("impact", fault_info)
    
    def test_fault_cancellation(self):
        """Test fault cancellation"""
        fault_id = self.fault_injector.inject_link_failure("link1", duration=60.0)
        
        # Verify fault is active
        self.assertIn(fault_id, self.fault_injector.active_faults)
        
        # Cancel the fault
        result = self.fault_injector.cancel_fault(fault_id)
        self.assertTrue(result)
        
        # Check fault is no longer active
        self.assertNotIn(fault_id, self.fault_injector.active_faults)
    
    def test_export_fault_report(self):
        """Test fault report export"""
        # Inject some faults
        self.fault_injector.inject_link_failure("link1")
        self.fault_injector.inject_device_failure("R1")
        
        # Export report
        report = self.fault_injector.export_fault_report()
        
        self.assertIn("timestamp", report)
        self.assertIn("statistics", report)
        self.assertIn("active_faults", report)
        self.assertIn("fault_history", report)
        
        # Check statistics section
        self.assertEqual(report["statistics"]["active_faults"], 2)


class TestIntegration(unittest.TestCase):
    """Test integration between components"""
    
    def test_stats_and_fault_integration(self):
        """Test integration between statistics and fault injection"""
        # Setup components
        stats = SimulationStats(collection_interval=0.1)
        mock_engine = MockSimulationEngine()
        fault_injector = FaultInjector(mock_engine)
        
        try:
            # Start stats collection
            stats.start_collection()
            
            # Record some baseline traffic
            stats.record_traffic_flow("flow1", "R1", "R2", packet_size=1500)
            stats.update_interface_stats("R1", "eth0", packets_out=10, bytes_out=15000)
            
            # Inject a fault
            fault_id = fault_injector.inject_link_failure("link1", duration=1.0)
            
            # Simulate fault impact on statistics
            stats.record_congestion_event("link1", severity=0.9, cause="link_failure")
            stats.update_interface_stats("R1", "eth0", packets_dropped_out=5)
            
            # Wait a bit
            time.sleep(0.2)
            
            # Check that both components are working
            fault_stats = fault_injector.get_fault_statistics()
            sim_stats = stats.get_simulation_summary()
            congestion_analysis = stats.get_congestion_analysis()
            
            self.assertGreater(fault_stats["active_faults"], 0)
            self.assertGreater(sim_stats["totals"]["packets"], 0)
            self.assertGreater(congestion_analysis["total_events"], 0)
            
        finally:
            stats.stop_collection()


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)