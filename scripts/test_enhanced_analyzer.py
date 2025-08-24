#!/usr/bin/env python3
"""
Test cases for the Enhanced Network Analyzer functionality.
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

from core.config_parser import ConfigParser
from core.network_validator import NetworkValidator
from core.load_analyzer import NetworkLoadAnalyzer
from core.optimization_recommender import NetworkOptimizationRecommender
from core.topology_generator import TopologyGenerator


def test_config_parser_enhanced():
    """Test the enhanced config parser functionality."""
    print("Testing Enhanced Config Parser...")
    
    parser = ConfigParser()
    configs = parser.parse_directory("configs/sample_network")
    
    # Test that all configs are loaded
    assert len(configs) >= 4, f"Expected at least 4 configs, got {len(configs)}"
    
    # Test that device types are correctly identified
    device_types = {name: config.device_type for name, config in configs.items()}
    assert 'router' in device_types.values(), "No routers found in configs"
    assert 'switch' in device_types.values(), "No switches found in configs"
    
    # Test that interfaces are parsed
    for name, config in configs.items():
        assert len(config.interfaces) > 0, f"Device {name} has no interfaces"
        
        # Test that bandwidth is parsed for some interfaces
        has_bandwidth = any(intf.bandwidth for intf in config.interfaces.values())
        if not has_bandwidth:
            print(f"Warning: No bandwidth information found for {name}")
    
    print("✓ Enhanced Config Parser tests passed")


def test_network_validator_enhanced():
    """Test the enhanced network validator functionality."""
    print("Testing Enhanced Network Validator...")
    
    parser = ConfigParser()
    configs = parser.parse_directory("configs/sample_network")
    
    validator = NetworkValidator()
    issues = validator.validate_network(configs)
    
    # Should find multiple types of issues
    assert len(issues) > 10, f"Expected multiple issues, found {len(issues)}"
    
    # Check for specific issue types we expect
    issue_types = [issue.get('type') for issue in issues]
    
    expected_types = [
        'duplicate_ip_in_vlan',
        'missing_spanning_tree',
        'inconsistent_vlan_names',
        'multiple_gateways'
    ]
    
    for expected_type in expected_types:
        assert expected_type in issue_types, f"Expected issue type '{expected_type}' not found"
    
    print("✓ Enhanced Network Validator tests passed")


def test_load_analyzer():
    """Test the network load analyzer functionality."""
    print("Testing Network Load Analyzer...")
    
    parser = ConfigParser()
    configs = parser.parse_directory("configs/sample_network")
    
    analyzer = NetworkLoadAnalyzer()
    results = analyzer.analyze_network_load(configs)
    
    # Test that results are reasonable
    assert results.total_network_capacity > 0, "Total network capacity should be positive"
    assert results.total_network_utilization >= 0, "Total utilization should be non-negative"
    assert isinstance(results.recommendations, list), "Recommendations should be a list"
    
    # Test that capacity is reasonable (should be several hundred Mbps for our sample network)
    assert results.total_network_capacity > 100, f"Expected capacity > 100 Mbps, got {results.total_network_capacity}"
    
    print("✓ Network Load Analyzer tests passed")


def test_optimization_recommender():
    """Test the network optimization recommender functionality."""
    print("Testing Network Optimization Recommender...")
    
    parser = ConfigParser()
    configs = parser.parse_directory("configs/sample_network")
    
    # Get network issues first
    validator = NetworkValidator()
    issues = validator.validate_network(configs)
    
    recommender = NetworkOptimizationRecommender()
    recommendations = recommender.analyze_and_recommend(configs, issues)
    
    # Should generate multiple recommendations
    assert len(recommendations) > 5, f"Expected multiple recommendations, got {len(recommendations)}"
    
    # Check that recommendations have required fields
    for rec in recommendations:
        assert hasattr(rec, 'category'), "Recommendation missing category"
        assert hasattr(rec, 'priority'), "Recommendation missing priority"
        assert hasattr(rec, 'title'), "Recommendation missing title"
        assert hasattr(rec, 'description'), "Recommendation missing description"
        
        assert rec.priority in ['high', 'medium', 'low'], f"Invalid priority: {rec.priority}"
    
    # Check for specific recommendation categories
    categories = [rec.category for rec in recommendations]
    expected_categories = ['protocol', 'topology', 'security']
    
    for expected_cat in expected_categories:
        assert expected_cat in categories, f"Expected category '{expected_cat}' not found"
    
    print("✓ Network Optimization Recommender tests passed")


def test_topology_generation():
    """Test topology generation with new configurations."""
    print("Testing Topology Generation...")
    
    parser = ConfigParser()
    configs = parser.parse_directory("configs/sample_network")
    
    generator = TopologyGenerator()
    graph = generator.generate_topology(configs)
    
    # Test that topology is generated
    assert graph is not None, "Topology generation failed"
    assert len(graph.nodes) > 0, "No nodes in generated topology"
    assert len(graph.edges) > 0, "No edges in generated topology"
    
    # Test that we have the expected number of devices
    assert len(graph.nodes) >= 4, f"Expected at least 4 nodes, got {len(graph.nodes)}"
    
    print("✓ Topology Generation tests passed")


def test_full_analysis_pipeline():
    """Test the complete analysis pipeline."""
    print("Testing Full Analysis Pipeline...")
    
    # Import network analyzer
    sys.path.append(str(project_root))
    from network_analyzer import load_network_configs, analyze_network_configuration
    import logging
    
    # Set up logging
    logger = logging.getLogger("TestLogger")
    logger.setLevel(logging.ERROR)  # Reduce log noise during testing
    
    # Load configurations
    configs = load_network_configs("configs/sample_network", logger)
    assert len(configs) >= 4, f"Expected at least 4 configs, got {len(configs)}"
    
    # Run full analysis
    results = analyze_network_configuration(
        configs, logger,
        enable_load_analysis=True,
        enable_optimization=True
    )
    
    # Test that all result categories are present
    expected_keys = [
        'validation_results',
        'topology_info',
        'issues_found',
        'recommendations',
        'load_analysis',
        'optimization_recommendations',
        'statistics'
    ]
    
    for key in expected_keys:
        assert key in results, f"Missing result key: {key}"
    
    # Test specific result content
    assert len(results['issues_found']) > 10, "Expected multiple issues"
    assert results['topology_info'].get('total_devices', 0) >= 4, "Expected multiple devices"
    assert len(results['optimization_recommendations']) > 5, "Expected multiple optimization recommendations"
    
    if results['load_analysis']:
        assert results['load_analysis'].get('total_capacity_mbps', 0) > 0, "Expected positive network capacity"
    
    print("✓ Full Analysis Pipeline tests passed")


def run_all_tests():
    """Run all test cases."""
    print("=" * 60)
    print("RUNNING ENHANCED NETWORK ANALYZER TESTS")
    print("=" * 60)
    
    tests = [
        test_config_parser_enhanced,
        test_network_validator_enhanced,
        test_load_analyzer,
        test_optimization_recommender,
        test_topology_generation,
        test_full_analysis_pipeline
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)