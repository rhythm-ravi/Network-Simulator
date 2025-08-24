#!/usr/bin/env python3
"""
Network Simulator - Main Entry Point

This is the main entry point for the Network Simulator application.
It provides a command-line interface for loading configurations, generating
topologies, and validating network setups.
"""

import argparse
import sys
import logging
import json
from pathlib import Path

# Add the src directory to the Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from core.config_parser import ConfigParser, load_configurations
from core.topology_generator import TopologyGenerator
from core.network_validator import NetworkValidator


def setup_logging(verbose: bool = False):
    """Set up logging configuration."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger("NetworkSimulator")


def load_and_parse_configs(config_path: str, logger) -> list:
    """Load and parse configuration files."""
    logger.info(f"Loading configurations from: {config_path}")
    
    try:
        configurations = load_configurations(config_path)
        logger.info(f"Loaded {len(configurations)} configuration(s)")
        return configurations
    except Exception as e:
        logger.error(f"Failed to load configurations: {e}")
        return []


def validate_configs(configurations: list, logger) -> bool:
    """Validate loaded configurations."""
    if not configurations:
        logger.warning("No configurations to validate")
        return False
    
    logger.info("Validating device configurations...")
    validator = NetworkValidator()
    is_valid, results = validator.validate_configurations(configurations)
    
    # Print validation results
    for result in results:
        if result['valid']:
            logger.info(f"✓ {result['device_name']}: Configuration valid")
        else:
            logger.error(f"✗ {result['device_name']}: Configuration invalid")
            for error in result['errors']:
                logger.error(f"    - {error}")
    
    if is_valid:
        logger.info("All device configurations are valid")
    else:
        logger.error("Some device configurations have errors")
    
    return is_valid


def generate_topology(configurations: list, logger):
    """Generate network topology from configurations."""
    logger.info("Generating network topology...")
    
    generator = TopologyGenerator()
    topology = generator.generate_topology(configurations, "CLI Generated Topology")
    
    # Print topology summary
    summary = topology.get_topology_summary()
    logger.info("Topology generated successfully:")
    logger.info(f"  - Devices: {summary['total_devices']} ({summary['routers']} routers, {summary['switches']} switches)")
    logger.info(f"  - Links: {summary['total_links']} ({summary['active_links']} active)")
    
    # Get detailed statistics
    stats = generator.get_topology_statistics()
    logger.info(f"  - Interfaces: {stats['interfaces']['active']}/{stats['interfaces']['total']} active")
    logger.info(f"  - VLANs: {stats['vlans']['total']} configured")
    logger.info(f"  - Routing Protocols: {stats['routing_protocols']['total']} configured")
    
    return topology


def validate_topology(topology, logger) -> bool:
    """Validate the generated topology."""
    logger.info("Validating network topology...")
    
    validator = NetworkValidator()
    is_valid, validation_errors = validator.validate_topology(topology)
    
    if is_valid:
        logger.info("✓ Topology validation passed")
        return True
    else:
        logger.error("✗ Topology validation failed:")
        
        for category, errors in validation_errors.items():
            logger.error(f"  {category.title()} errors:")
            for error in errors:
                logger.error(f"    - {error}")
        
        # Print summary
        summary = validator.get_validation_summary(validation_errors)
        logger.error(f"Total errors: {summary['total_errors']} across {summary['categories']} categories")
        
        return False


def print_topology_report(topology, verbose: bool = False):
    """Print a detailed topology report."""
    print("\nNetwork Topology Report")
    print("======================")
    
    summary = topology.get_topology_summary()
    
    # Device summary
    print(f"\nDevices ({summary['total_devices']}):")
    for device_name, device_info in summary['devices'].items():
        device_type = device_info['type'].title()
        print(f"  {device_type}: {device_name}")
        if verbose:
            print(f"    Model: {device_info.get('model', 'N/A')}")
            print(f"    Location: {device_info.get('location', 'N/A')}")
            print(f"    Interfaces: {device_info['active_interfaces']}/{device_info['interface_count']}")
            if device_info.get('routing_protocols'):
                print(f"    Routing: {', '.join(device_info['routing_protocols'])}")
    
    # Link summary
    print(f"\nLinks ({summary['active_links']}/{summary['total_links']} active):")
    for link in topology.links:
        status_icon = "✓" if link.is_active else "✗"
        print(f"  {status_icon} {link.device1.name}:{link.interface1} ↔ {link.device2.name}:{link.interface2}")
        if verbose:
            print(f"     Bandwidth: {link.bandwidth} Mbps, Latency: {link.latency} ms")


def main():
    """Main entry point for the Network Simulator."""
    parser = argparse.ArgumentParser(
        description="Network Simulator - A comprehensive network simulation toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --config configs/sample_configs/          Load directory of configs
  python main.py --config router1.config.dump             Load single config file
  python main.py --config configs/ --validate-only        Just validate configs
  python main.py --config configs/ --verbose              Detailed output
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Network Simulator v0.1.0"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration file or directory"
    )
    
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate configurations, don't generate topology"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        help="Output file for topology data (JSON format)"
    )

    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose)

    print("Welcome to Network Simulator v0.1.0")
    print("==================================")
    print()

    # Check if configuration path was provided
    if not args.config:
        print("No configuration path specified. Using default sample configs...")
        args.config = "configs/sample_configs/"
    
    # Load and parse configurations
    configurations = load_and_parse_configs(args.config, logger)
    if not configurations:
        print("✗ Failed to load any configurations")
        return 1
    
    print(f"✓ Loaded {len(configurations)} device configuration(s)")
    
    # Validate configurations
    if not validate_configs(configurations, logger):
        print("✗ Configuration validation failed")
        if not args.verbose:
            print("  Use --verbose flag to see detailed errors")
        return 1
    
    print("✓ Configuration validation passed")
    
    # If validate-only mode, stop here
    if args.validate_only:
        print("\nValidation complete. Use without --validate-only to generate topology.")
        return 0
    
    # Generate topology
    topology = generate_topology(configurations, logger)
    if not topology or not topology.devices:
        print("✗ Failed to generate topology")
        return 1
    
    print("✓ Topology generation completed")
    
    # Validate topology
    if not validate_topology(topology, logger):
        print("✗ Topology validation failed")
        if not args.verbose:
            print("  Use --verbose flag to see detailed errors")
        return 1
    
    print("✓ Topology validation passed")
    
    # Print topology report
    print_topology_report(topology, args.verbose)
    
    # Save topology data if output file specified
    if args.output:
        try:
            output_path = Path(args.output)
            topology_data = topology.get_topology_summary()
            with open(output_path, 'w') as f:
                json.dump(topology_data, f, indent=2, default=str)
            print(f"\n✓ Topology data saved to: {output_path}")
        except Exception as e:
            logger.error(f"Failed to save topology data: {e}")
            return 1
    
    print("\n" + "="*50)
    print("Network topology successfully generated and validated!")
    print("For running simulations, use: python run_simulation.py")
    print("="*50)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())