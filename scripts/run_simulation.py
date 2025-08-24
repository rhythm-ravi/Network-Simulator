#!/usr/bin/env python3
"""
Network Simulator - Simulation Runner

This script provides a dedicated interface for running network simulations.
It handles simulation configuration, execution, and results management.
"""

import argparse
import sys
import os
from pathlib import Path

# Add the parent directory to the Python path to import src modules
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))


def setup_logging(log_level="INFO"):
    """Set up logging configuration."""
    import logging
    
    # Create logs directory in the repository root, not in scripts
    logs_dir = Path(__file__).parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(logs_dir / "simulation.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger("NetworkSimulator")


def load_configuration(config_path=None):
    """Load simulation configuration."""
    if config_path is None:
        # Look for default configuration
        default_configs = [
            "configs/simulation_configs/default.yaml",
            "configs/sample_configs/basic_network.yaml"
        ]
        
        for config_file in default_configs:
            config_path = Path(__file__).parent / config_file
            if config_path.exists():
                break
        else:
            config_path = None
    
    if config_path and Path(config_path).exists():
        print(f"Loading configuration from: {config_path}")
        import yaml
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Extract simulation parameters
            sim_config = config.get('simulation', {})
            
            # Merge simulation config with top level 
            result_config = {
                'config_file': str(config_path),
                'duration': sim_config.get('duration', 60.0),
                'real_time_factor': sim_config.get('real_time_factor', 0.1), 
                'inject_faults': sim_config.get('inject_faults', True),
                'output_dir': sim_config.get('output_dir', './logs')
            }
            
            # Add devices and links if present
            if 'devices' in config:
                result_config['devices'] = config['devices']
            if 'links' in config:
                result_config['links'] = config['links']
            if 'fault_scenarios' in config:
                result_config['fault_scenarios'] = config['fault_scenarios']
            if 'protocols' in config:
                result_config['protocols'] = config['protocols']
            if 'monitoring' in config:
                result_config['monitoring'] = config['monitoring']
                
            return result_config
            
        except Exception as e:
            print(f"Error loading configuration: {e}")
            print("Using default settings.")
            return {"default": True}
    else:
        print("No configuration file found. Using default settings.")
        return {"default": True}


def run_simulation(config, logger):
    """Run the network simulation."""
    logger.info("Starting network simulation...")
    
    # Import the simulation engine
    from src.simulation.simulation_engine import NetworkSimulationEngine
    from src.models.network_models import Router, Switch, NetworkInterface, InterfaceStatus
    
    try:
        # Create simulation engine
        real_time_factor = config.get('real_time_factor', 0.1)  # Default to fast simulation
        sim_engine = NetworkSimulationEngine(real_time_factor=real_time_factor)
        
        print("Simulation Configuration:")
        for key, value in config.items():
            print(f"  {key}: {value}")
        
        # Load configuration or create a sample network
        if 'devices' in config or 'links' in config:
            # Load from configuration
            sim_engine.load_configuration(config)
        else:
            # Create a simple sample network for demonstration
            print("\nCreating sample network...")
            
            # Create sample devices
            router1 = Router("R1")
            router1.add_interface(NetworkInterface(
                name="eth0", 
                ip_address="192.168.1.1", 
                subnet_mask="255.255.255.0",
                status=InterfaceStatus.UP
            ))
            router1.add_interface(NetworkInterface(
                name="eth1", 
                ip_address="10.0.0.1", 
                subnet_mask="255.255.255.0",
                status=InterfaceStatus.UP
            ))
            
            router2 = Router("R2")
            router2.add_interface(NetworkInterface(
                name="eth0", 
                ip_address="10.0.0.2", 
                subnet_mask="255.255.255.0",
                status=InterfaceStatus.UP
            ))
            router2.add_interface(NetworkInterface(
                name="eth1", 
                ip_address="192.168.2.1", 
                subnet_mask="255.255.255.0",
                status=InterfaceStatus.UP
            ))
            
            switch1 = Switch("SW1")
            switch1.add_interface(NetworkInterface(
                name="eth0", 
                ip_address="192.168.1.10", 
                subnet_mask="255.255.255.0",
                status=InterfaceStatus.UP
            ))
            
            # Add devices to simulation
            sim_engine.add_device(router1)
            sim_engine.add_device(router2)
            sim_engine.add_device(switch1)
            
            # Create links
            sim_engine.add_link("link1", "R1", "R2", {"bandwidth": "100Mbps"})
            sim_engine.add_link("link2", "R1", "SW1", {"bandwidth": "1Gbps"})
            
            print(f"  Created {len(sim_engine.devices)} devices")
            print(f"  Created {len(sim_engine.links)} links")
        
        # Get simulation duration
        duration = config.get('duration', 60.0)  # Default 60 seconds simulation time
        
        print(f"\nStarting simulation for {duration} time units...")
        print("  - Network initialization events (ARP, neighbor discovery)")
        print("  - OSPF discovery and hello messages")
        print("  - Device thread-based simulation")
        print("  - Statistics collection")
        
        # Inject faults from configuration
        fault_scenarios = config.get('fault_scenarios', [])
        if config.get('inject_faults', True) and fault_scenarios:
            print("\nScheduling fault injection events from configuration...")
            
            for scenario in fault_scenarios:
                fault_type = scenario.get('type')
                start_time = scenario.get('start_time', 0.0)
                description = scenario.get('description', '')
                
                if fault_type == 'link_failure':
                    target = scenario.get('target')
                    fault_duration = scenario.get('duration')
                    
                    if target in sim_engine.links:
                        fault_id = sim_engine.inject_link_failure(target, duration=fault_duration, delay=start_time)
                        print(f"  - Link failure: {target} at {start_time}s for {fault_duration}s (event: {fault_id})")
                        print(f"    Description: {description}")
                
                elif fault_type == 'mtu_mismatch':
                    source = scenario.get('source')
                    target = scenario.get('target')
                    packet_size = scenario.get('packet_size', 1600)
                    interface_mtu = scenario.get('interface_mtu', 1500)
                    
                    if source in sim_engine.devices and target in sim_engine.devices:
                        fault_id = sim_engine.inject_mtu_mismatch(source, target, packet_size, interface_mtu, delay=start_time)
                        print(f"  - MTU mismatch: {source} -> {target} at {start_time}s (event: {fault_id})")
                        print(f"    Description: {description}")
                
                elif fault_type == 'config_change':
                    target = scenario.get('target')
                    changes = scenario.get('changes', {})
                    
                    if target in sim_engine.devices:
                        fault_id = sim_engine.change_device_configuration(target, changes, delay=start_time)
                        print(f"  - Config change: {target} at {start_time}s (event: {fault_id})")
                        print(f"    Description: {description}")
                        
        elif config.get('inject_faults', True):
            # Default fault injection for demonstration
            print("\nScheduling default fault injection events...")
            
            # Schedule link failure after 20 seconds, recover after 10 seconds
            fault_id1 = sim_engine.inject_link_failure("link1", duration=10.0, delay=20.0)
            print(f"  - Link failure scheduled for link1 (event: {fault_id1})")
            
            # Schedule MTU mismatch
            fault_id2 = sim_engine.inject_mtu_mismatch("R1", "R2", 1600, 1500, delay=30.0)
            print(f"  - MTU mismatch scheduled (event: {fault_id2})")
            
            # Schedule configuration change
            config_changes = {
                'interface_status': {
                    'interface': 'eth1',
                    'status': 'down'
                }
            }
            fault_id3 = sim_engine.change_device_configuration("R2", config_changes, delay=40.0)
            print(f"  - Configuration change scheduled for R2 (event: {fault_id3})")
        
        print(f"\n{'='*50}")
        print("SIMULATION RUNNING...")
        print(f"{'='*50}")
        
        # Run the simulation
        sim_engine.start_simulation(duration=duration)
        
        print(f"\n{'='*50}")
        print("SIMULATION COMPLETED")
        print(f"{'='*50}")
        
        # Get and display results
        summary = sim_engine.get_simulation_summary()
        
        print(f"\nSimulation Summary:")
        print(f"  State: {summary['simulation_state']}")
        print(f"  Simulation Time: {summary['simulation_time']:.2f} units")
        print(f"  Real Time Elapsed: {summary['real_time_elapsed']:.2f} seconds")
        print(f"  Total Events: {summary['event_metrics']['total_events']}")
        print(f"  Processed Events: {summary['event_metrics']['processed_events']}")
        print(f"  Average Processing Time: {summary['event_metrics']['average_processing_time']:.6f} seconds")
        
        print(f"\nDevice Statistics:")
        for device_name, stats in summary['devices'].items():
            print(f"  {device_name}:")
            print(f"    Events Processed: {stats['events_processed']}")
            print(f"    Packets Sent: {stats['packets_sent']}")
            print(f"    Packets Received: {stats['packets_received']}")
            print(f"    Packets Dropped: {stats['packets_dropped']}")
            print(f"    ARP Table Size: {stats['arp_table_size']}")
            print(f"    Neighbor Count: {stats['neighbor_count']}")
        
        print(f"\nLink Statistics:")
        for link_id, stats in summary['links'].items():
            status = "Active" if stats['is_active'] else "Failed"
            print(f"  {link_id}: {status}")
            print(f"    Packets Transmitted: {stats['packets_transmitted']}")
            print(f"    Failure Count: {stats['failure_count']}")
            print(f"    Recovery Count: {stats['recovery_count']}")
        
        if summary['fault_injection_log']:
            print(f"\nFault Injection Log:")
            for fault in summary['fault_injection_log']:
                print(f"  {fault['timestamp']:.2f}: {fault['type']} - {fault.get('link_id', 'N/A')}")
        
        # Export results
        output_dir = config.get('output_dir', './logs')
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        results_file = f"{output_dir}/simulation_results.json"
        sim_engine.export_results(results_file, format='json')
        print(f"\nDetailed results exported to: {results_file}")
        
        logger.info("Network simulation completed successfully!")
        
        return {
            "status": "success", 
            "message": "Network simulation completed with multithreading and fault injection",
            "summary": summary
        }
        
    except Exception as e:
        logger.error(f"Simulation failed with error: {e}")
        return {"status": "error", "message": f"Simulation failed: {e}"}


def main():
    """Main function for running simulations."""
    parser = argparse.ArgumentParser(
        description="Run Network Simulations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_simulation.py                           Run with default settings
  python run_simulation.py --config config.yaml     Run with custom config
  python run_simulation.py --log-level DEBUG        Run with debug logging
        """
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Path to simulation configuration file"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./logs",
        help="Directory for output files (default: ./logs)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    print("Network Simulation Runner v0.1.0")
    print("================================")
    print()
    
    # Load configuration
    config = load_configuration(args.config)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    try:
        # Run simulation
        result = run_simulation(config, logger)
        
        if result["status"] == "success":
            print(f"\n✓ {result['message']}")
            print(f"Output directory: {output_dir}")
            return 0
        else:
            print(f"\n✗ Simulation failed: {result.get('message', 'Unknown error')}")
            return 1
            
    except Exception as e:
        logger.error(f"Simulation failed with error: {e}")
        print(f"\n✗ Simulation failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())