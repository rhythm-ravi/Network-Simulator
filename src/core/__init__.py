"""
Core network simulation components.

This module contains the fundamental classes and utilities for network simulation,
including base classes for nodes, links, network topologies, and the new simulation
components: NetworkSimulator, FaultInjector, and SimulationStats.
"""

# Import existing components
from .config_parser import ConfigParser
from .topology_generator import TopologyGenerator  
from .network_validator import NetworkValidator
from .load_analyzer import NetworkLoadAnalyzer
from .optimization_recommender import NetworkOptimizationRecommender

# Import new simulation components
try:
    from .network_simulator import NetworkSimulator, DeviceSimulator, RouterSimulator, SwitchSimulator
    from .fault_injector import FaultInjector, FaultType, FaultSeverity, FaultStatus
    from .simulation_stats import SimulationStats, MetricType, InterfaceStats, TrafficFlow
    
    __all__ = [
        # Existing components
        'ConfigParser', 'TopologyGenerator', 'NetworkValidator',
        'NetworkLoadAnalyzer', 'NetworkOptimizationRecommender',
        # New simulation components
        'NetworkSimulator', 'DeviceSimulator', 'RouterSimulator', 'SwitchSimulator',
        'FaultInjector', 'FaultType', 'FaultSeverity', 'FaultStatus', 
        'SimulationStats', 'MetricType', 'InterfaceStats', 'TrafficFlow'
    ]
    
except ImportError as e:
    # Fallback if simulation components can't be imported
    __all__ = [
        'ConfigParser', 'TopologyGenerator', 'NetworkValidator',
        'NetworkLoadAnalyzer', 'NetworkOptimizationRecommender'
    ]