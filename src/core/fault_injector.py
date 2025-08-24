#!/usr/bin/env python3
"""
Fault Injection System for Network Simulator

This module provides comprehensive fault injection capabilities including
link failures, device failures, configuration errors, and impact analysis.
"""

import logging
import time
import threading
import uuid
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import copy

# Import simulation components  
# Note: This will need to be resolved based on how the simulation engine is imported
# For now, we'll make it optional for testing
try:
    from simulation.simulation_engine import NetworkSimulationEngine
except ImportError:
    # Allow fault injector to work with mock engines for testing
    NetworkSimulationEngine = None

logger = logging.getLogger(__name__)


class FaultType(Enum):
    """Types of faults that can be injected."""
    LINK_FAILURE = "link_failure"
    DEVICE_FAILURE = "device_failure"
    INTERFACE_FAILURE = "interface_failure"
    MTU_MISMATCH = "mtu_mismatch"
    BANDWIDTH_REDUCTION = "bandwidth_reduction"
    LATENCY_INCREASE = "latency_increase"
    PACKET_LOSS = "packet_loss"
    CONFIG_ERROR = "config_error"
    ROUTING_LOOP = "routing_loop"
    CONGESTION = "congestion"


class FaultSeverity(Enum):
    """Severity levels for faults."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FaultStatus(Enum):
    """Status of fault injection."""
    SCHEDULED = "scheduled"
    ACTIVE = "active"
    RECOVERING = "recovering"
    RECOVERED = "recovered"
    FAILED = "failed"


@dataclass
class FaultImpactMetrics:
    """Metrics tracking the impact of a fault."""
    fault_id: str
    affected_devices: Set[str] = field(default_factory=set)
    affected_links: Set[str] = field(default_factory=set)
    packets_lost: int = 0
    bytes_lost: int = 0
    convergence_time: Optional[float] = None
    services_impacted: List[str] = field(default_factory=list)
    routes_changed: int = 0
    neighbor_relationships_lost: int = 0
    recovery_time: Optional[float] = None


@dataclass
class FaultScenario:
    """Definition of a fault injection scenario."""
    fault_id: str
    fault_type: FaultType
    severity: FaultSeverity
    target: str  # Device name, link ID, or interface
    parameters: Dict[str, Any] = field(default_factory=dict)
    start_time: float = 0.0  # Delay before fault activation
    duration: Optional[float] = None  # None for permanent faults
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    # Status tracking
    status: FaultStatus = FaultStatus.SCHEDULED
    actual_start_time: Optional[float] = None
    actual_end_time: Optional[float] = None
    
    # Impact tracking
    impact_metrics: FaultImpactMetrics = field(default_factory=lambda: None)
    
    def __post_init__(self):
        if self.impact_metrics is None:
            self.impact_metrics = FaultImpactMetrics(fault_id=self.fault_id)


class FaultInjector:
    """Main fault injection system for network simulation."""
    
    def __init__(self, simulation_engine):
        """
        Initialize FaultInjector.
        
        Args:
            simulation_engine: The simulation engine instance (NetworkSimulationEngine or compatible)
        """
        self.simulation_engine = simulation_engine
        self.active_faults: Dict[str, FaultScenario] = {}
        self.fault_history: List[FaultScenario] = []
        self.impact_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
        self._lock = threading.RLock()
        
        # Fault injection configuration
        self.max_concurrent_faults = 10
        self.enable_cascading_failures = True
        self.impact_tracking_enabled = True
        
        logger.info("FaultInjector initialized")
    
    def inject_link_failure(self, link_id: str, duration: Optional[float] = None, 
                           delay: float = 0.0, severity: FaultSeverity = FaultSeverity.HIGH,
                           description: str = "") -> str:
        """
        Inject a link failure fault.
        
        Args:
            link_id: ID of the link to fail
            duration: Duration of the failure in seconds (None for permanent)
            delay: Delay before fault activation in seconds
            severity: Severity level of the fault
            description: Human-readable description
            
        Returns:
            Fault ID for tracking
        """
        fault_id = self._generate_fault_id()
        
        scenario = FaultScenario(
            fault_id=fault_id,
            fault_type=FaultType.LINK_FAILURE,
            severity=severity,
            target=link_id,
            parameters={
                'duration': duration,
                'affected_bandwidth': 'full'
            },
            start_time=delay,
            duration=duration,
            description=description or f"Link failure on {link_id}"
        )
        
        return self._schedule_fault(scenario)
    
    def inject_device_failure(self, device_name: str, failure_type: str = "complete",
                             duration: Optional[float] = None, delay: float = 0.0,
                             severity: FaultSeverity = FaultSeverity.CRITICAL,
                             description: str = "") -> str:
        """
        Inject a device failure fault.
        
        Args:
            device_name: Name of the device to fail
            failure_type: Type of failure ('complete', 'cpu_overload', 'memory_full')
            duration: Duration of the failure in seconds
            delay: Delay before fault activation
            severity: Severity level
            description: Human-readable description
            
        Returns:
            Fault ID for tracking
        """
        fault_id = self._generate_fault_id()
        
        scenario = FaultScenario(
            fault_id=fault_id,
            fault_type=FaultType.DEVICE_FAILURE,
            severity=severity,
            target=device_name,
            parameters={
                'failure_type': failure_type,
                'duration': duration
            },
            start_time=delay,
            duration=duration,
            description=description or f"Device failure on {device_name} ({failure_type})"
        )
        
        return self._schedule_fault(scenario)
    
    def inject_mtu_mismatch(self, source_device: str, target_device: str, 
                           packet_size: int, interface_mtu: int, delay: float = 0.0,
                           severity: FaultSeverity = FaultSeverity.MEDIUM,
                           description: str = "") -> str:
        """
        Inject an MTU mismatch fault.
        
        Args:
            source_device: Source device name
            target_device: Target device name
            packet_size: Size of packets that will be dropped
            interface_mtu: MTU setting on interface
            delay: Delay before fault activation
            severity: Severity level
            description: Human-readable description
            
        Returns:
            Fault ID for tracking
        """
        fault_id = self._generate_fault_id()
        
        scenario = FaultScenario(
            fault_id=fault_id,
            fault_type=FaultType.MTU_MISMATCH,
            severity=severity,
            target=f"{source_device}->{target_device}",
            parameters={
                'source_device': source_device,
                'target_device': target_device,
                'packet_size': packet_size,
                'interface_mtu': interface_mtu
            },
            start_time=delay,
            description=description or f"MTU mismatch between {source_device} and {target_device}"
        )
        
        return self._schedule_fault(scenario)
    
    def inject_packet_loss(self, target: str, loss_rate: float, duration: Optional[float] = None,
                          delay: float = 0.0, severity: FaultSeverity = FaultSeverity.MEDIUM,
                          description: str = "") -> str:
        """
        Inject packet loss on a link or interface.
        
        Args:
            target: Link ID or device interface
            loss_rate: Packet loss rate (0.0 to 1.0)
            duration: Duration of packet loss
            delay: Delay before fault activation
            severity: Severity level
            description: Human-readable description
            
        Returns:
            Fault ID for tracking
        """
        fault_id = self._generate_fault_id()
        
        scenario = FaultScenario(
            fault_id=fault_id,
            fault_type=FaultType.PACKET_LOSS,
            severity=severity,
            target=target,
            parameters={
                'loss_rate': loss_rate,
                'duration': duration
            },
            start_time=delay,
            duration=duration,
            description=description or f"Packet loss ({loss_rate*100:.1f}%) on {target}"
        )
        
        return self._schedule_fault(scenario)
    
    def inject_bandwidth_reduction(self, link_id: str, reduction_factor: float,
                                  duration: Optional[float] = None, delay: float = 0.0,
                                  severity: FaultSeverity = FaultSeverity.MEDIUM,
                                  description: str = "") -> str:
        """
        Inject bandwidth reduction on a link.
        
        Args:
            link_id: ID of the link
            reduction_factor: Factor by which to reduce bandwidth (0.1 = 10% of original)
            duration: Duration of the reduction
            delay: Delay before fault activation
            severity: Severity level
            description: Human-readable description
            
        Returns:
            Fault ID for tracking
        """
        fault_id = self._generate_fault_id()
        
        scenario = FaultScenario(
            fault_id=fault_id,
            fault_type=FaultType.BANDWIDTH_REDUCTION,
            severity=severity,
            target=link_id,
            parameters={
                'reduction_factor': reduction_factor,
                'duration': duration
            },
            start_time=delay,
            duration=duration,
            description=description or f"Bandwidth reduction ({reduction_factor*100:.1f}%) on {link_id}"
        )
        
        return self._schedule_fault(scenario)
    
    def inject_configuration_error(self, device_name: str, config_changes: Dict[str, Any],
                                  duration: Optional[float] = None, delay: float = 0.0,
                                  severity: FaultSeverity = FaultSeverity.HIGH,
                                  description: str = "") -> str:
        """
        Inject configuration errors on a device.
        
        Args:
            device_name: Name of the device
            config_changes: Configuration changes to apply
            duration: Duration of the configuration error
            delay: Delay before fault activation
            severity: Severity level
            description: Human-readable description
            
        Returns:
            Fault ID for tracking
        """
        fault_id = self._generate_fault_id()
        
        scenario = FaultScenario(
            fault_id=fault_id,
            fault_type=FaultType.CONFIG_ERROR,
            severity=severity,
            target=device_name,
            parameters={
                'config_changes': config_changes,
                'duration': duration
            },
            start_time=delay,
            duration=duration,
            description=description or f"Configuration error on {device_name}"
        )
        
        return self._schedule_fault(scenario)
    
    def inject_congestion(self, target: str, congestion_level: float,
                         duration: Optional[float] = None, delay: float = 0.0,
                         severity: FaultSeverity = FaultSeverity.MEDIUM,
                         description: str = "") -> str:
        """
        Inject network congestion.
        
        Args:
            target: Link or device to congest
            congestion_level: Level of congestion (1.0 = full congestion)
            duration: Duration of congestion
            delay: Delay before fault activation
            severity: Severity level
            description: Human-readable description
            
        Returns:
            Fault ID for tracking
        """
        fault_id = self._generate_fault_id()
        
        scenario = FaultScenario(
            fault_id=fault_id,
            fault_type=FaultType.CONGESTION,
            severity=severity,
            target=target,
            parameters={
                'congestion_level': congestion_level,
                'duration': duration
            },
            start_time=delay,
            duration=duration,
            description=description or f"Congestion ({congestion_level*100:.1f}%) on {target}"
        )
        
        return self._schedule_fault(scenario)
    
    def create_fault_scenario(self, scenario_name: str, faults: List[Dict[str, Any]],
                             description: str = "") -> List[str]:
        """
        Create a complex fault scenario with multiple coordinated faults.
        
        Args:
            scenario_name: Name of the scenario
            faults: List of fault definitions
            description: Description of the scenario
            
        Returns:
            List of fault IDs
        """
        fault_ids = []
        
        for i, fault_def in enumerate(faults):
            fault_type = fault_def.get('type')
            target = fault_def.get('target')
            parameters = fault_def.get('parameters', {})
            delay = fault_def.get('delay', 0.0)
            duration = fault_def.get('duration')
            severity = FaultSeverity(fault_def.get('severity', 'medium'))
            
            fault_id = self._generate_fault_id(f"{scenario_name}_{i}")
            
            scenario = FaultScenario(
                fault_id=fault_id,
                fault_type=FaultType(fault_type),
                severity=severity,
                target=target,
                parameters=parameters,
                start_time=delay,
                duration=duration,
                description=f"{scenario_name}: {fault_def.get('description', fault_type)}",
                tags=[scenario_name, 'scenario']
            )
            
            fault_id = self._schedule_fault(scenario)
            fault_ids.append(fault_id)
        
        logger.info(f"Created fault scenario '{scenario_name}' with {len(fault_ids)} faults")
        return fault_ids
    
    def _schedule_fault(self, scenario: FaultScenario) -> str:
        """Schedule a fault for injection."""
        with self._lock:
            if len(self.active_faults) >= self.max_concurrent_faults:
                logger.warning(f"Maximum concurrent faults ({self.max_concurrent_faults}) reached")
                return ""
            
            self.active_faults[scenario.fault_id] = scenario
        
        # Schedule the fault activation
        if scenario.start_time > 0:
            timer = threading.Timer(scenario.start_time, self._activate_fault, [scenario.fault_id])
            timer.daemon = True
            timer.start()
        else:
            # Activate immediately
            self._activate_fault(scenario.fault_id)
        
        logger.info(f"Scheduled fault {scenario.fault_id}: {scenario.description}")
        return scenario.fault_id
    
    def _activate_fault(self, fault_id: str):
        """Activate a scheduled fault."""
        with self._lock:
            if fault_id not in self.active_faults:
                return
            
            scenario = self.active_faults[fault_id]
            scenario.status = FaultStatus.ACTIVE
            scenario.actual_start_time = time.time()
        
        try:
            # Execute the fault injection based on type
            success = self._execute_fault_injection(scenario)
            
            if success:
                logger.info(f"Activated fault {fault_id}: {scenario.description}")
                
                # Start impact tracking
                if self.impact_tracking_enabled:
                    self._start_impact_tracking(scenario)
                
                # Schedule recovery if duration is specified
                if scenario.duration is not None and scenario.duration > 0:
                    timer = threading.Timer(scenario.duration, self._recover_fault, [fault_id])
                    timer.daemon = True
                    timer.start()
            else:
                scenario.status = FaultStatus.FAILED
                logger.error(f"Failed to activate fault {fault_id}")
                
        except Exception as e:
            scenario.status = FaultStatus.FAILED
            logger.error(f"Error activating fault {fault_id}: {e}")
    
    def _execute_fault_injection(self, scenario: FaultScenario) -> bool:
        """Execute the actual fault injection."""
        fault_type = scenario.fault_type
        target = scenario.target
        parameters = scenario.parameters
        
        try:
            if fault_type == FaultType.LINK_FAILURE:
                # Use simulation engine's link failure injection
                return self.simulation_engine.inject_link_failure(
                    target,
                    parameters.get('duration'),
                    0.0  # No additional delay since we're already scheduled
                ) is not None
                
            elif fault_type == FaultType.MTU_MISMATCH:
                # Use simulation engine's MTU mismatch injection
                return self.simulation_engine.inject_mtu_mismatch(
                    parameters['source_device'],
                    parameters['target_device'],
                    parameters['packet_size'],
                    parameters['interface_mtu'],
                    0.0
                ) is not None
                
            elif fault_type == FaultType.CONFIG_ERROR:
                # Use simulation engine's configuration change
                return self.simulation_engine.change_device_configuration(
                    target,
                    parameters['config_changes'],
                    0.0
                ) is not None
                
            elif fault_type == FaultType.DEVICE_FAILURE:
                # Simulate device failure by disabling all interfaces
                config_changes = {
                    'device_status': 'down',
                    'failure_type': parameters.get('failure_type', 'complete')
                }
                return self.simulation_engine.change_device_configuration(
                    target,
                    config_changes,
                    0.0
                ) is not None
                
            elif fault_type == FaultType.PACKET_LOSS:
                # Use simulation engine's packet loss injection
                if hasattr(self.simulation_engine, 'inject_packet_loss'):
                    return self.simulation_engine.inject_packet_loss(
                        target,
                        parameters.get('loss_rate', 0.1),
                        parameters.get('duration'),
                        0.0
                    ) is not None
                else:
                    # Mock implementation - just log the packet loss
                    logger.info(f"Packet loss injection: {parameters.get('loss_rate', 0.1)*100:.1f}% on {target}")
                    return True
                
            elif fault_type == FaultType.INTERFACE_FAILURE:
                # Disable specific interface
                config_changes = {
                    'interface_status': {
                        'interface': parameters.get('interface', 'eth0'),
                        'status': 'down'
                    }
                }
                return self.simulation_engine.change_device_configuration(
                    target,
                    config_changes,
                    0.0
                ) is not None
                
            else:
                logger.warning(f"Fault type {fault_type} not yet implemented")
                return False
                
        except Exception as e:
            logger.error(f"Error executing fault injection for {scenario.fault_id}: {e}")
            return False
    
    def _recover_fault(self, fault_id: str):
        """Recover from a fault."""
        with self._lock:
            if fault_id not in self.active_faults:
                return
            
            scenario = self.active_faults[fault_id]
            scenario.status = FaultStatus.RECOVERING
        
        try:
            # Execute fault recovery
            success = self._execute_fault_recovery(scenario)
            
            if success:
                scenario.status = FaultStatus.RECOVERED
                scenario.actual_end_time = time.time()
                
                # Calculate recovery time
                if scenario.actual_start_time:
                    scenario.impact_metrics.recovery_time = (
                        scenario.actual_end_time - scenario.actual_start_time
                    )
                
                logger.info(f"Recovered from fault {fault_id}")
                
                # Move to history
                with self._lock:
                    self.fault_history.append(scenario)
                    del self.active_faults[fault_id]
            else:
                scenario.status = FaultStatus.FAILED
                logger.error(f"Failed to recover from fault {fault_id}")
                
        except Exception as e:
            scenario.status = FaultStatus.FAILED
            logger.error(f"Error recovering from fault {fault_id}: {e}")
    
    def _execute_fault_recovery(self, scenario: FaultScenario) -> bool:
        """Execute fault recovery."""
        fault_type = scenario.fault_type
        target = scenario.target
        
        try:
            if fault_type == FaultType.LINK_FAILURE:
                # Re-enable link
                link_info = self.simulation_engine.links.get(target)
                if link_info:
                    link_info['active'] = True
                    return True
                    
            elif fault_type == FaultType.DEVICE_FAILURE:
                # Re-enable device
                config_changes = {
                    'device_status': 'up'
                }
                return self.simulation_engine.change_device_configuration(
                    target,
                    config_changes,
                    0.0
                ) is not None
                
            elif fault_type == FaultType.INTERFACE_FAILURE:
                # Re-enable interface
                parameters = scenario.parameters
                config_changes = {
                    'interface_status': {
                        'interface': parameters.get('interface', 'eth0'),
                        'status': 'up'
                    }
                }
                return self.simulation_engine.change_device_configuration(
                    target,
                    config_changes,
                    0.0
                ) is not None
                
            # For other fault types, assume automatic recovery
            return True
            
        except Exception as e:
            logger.error(f"Error executing fault recovery for {scenario.fault_id}: {e}")
            return False
    
    def _start_impact_tracking(self, scenario: FaultScenario):
        """Start tracking the impact of a fault."""
        # This would be implemented to monitor network state changes
        # For now, we'll do basic tracking
        
        if scenario.fault_type == FaultType.LINK_FAILURE:
            # Track affected devices connected to the failed link
            link_info = self.simulation_engine.links.get(scenario.target)
            if link_info:
                scenario.impact_metrics.affected_devices.add(link_info['source'])
                scenario.impact_metrics.affected_devices.add(link_info['target'])
                scenario.impact_metrics.affected_links.add(scenario.target)
        
        elif scenario.fault_type == FaultType.DEVICE_FAILURE:
            scenario.impact_metrics.affected_devices.add(scenario.target)
            
            # Find all links connected to this device
            for link_id, link_info in self.simulation_engine.links.items():
                if link_info['source'] == scenario.target or link_info['target'] == scenario.target:
                    scenario.impact_metrics.affected_links.add(link_id)
    
    def _generate_fault_id(self, prefix: str = "") -> str:
        """Generate a unique fault ID."""
        timestamp = int(time.time() * 1000)
        unique_id = str(uuid.uuid4())[:8]
        
        if prefix:
            return f"{prefix}_{timestamp}_{unique_id}"
        else:
            return f"fault_{timestamp}_{unique_id}"
    
    def get_active_faults(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently active faults."""
        with self._lock:
            result = {}
            for fault_id, scenario in self.active_faults.items():
                result[fault_id] = {
                    'fault_type': scenario.fault_type.value,
                    'severity': scenario.severity.value,
                    'target': scenario.target,
                    'status': scenario.status.value,
                    'description': scenario.description,
                    'start_time': scenario.actual_start_time,
                    'duration': scenario.duration,
                    'impact': {
                        'affected_devices': list(scenario.impact_metrics.affected_devices),
                        'affected_links': list(scenario.impact_metrics.affected_links),
                        'packets_lost': scenario.impact_metrics.packets_lost
                    }
                }
            return result
    
    def get_fault_history(self) -> List[Dict[str, Any]]:
        """Get history of completed faults."""
        result = []
        for scenario in self.fault_history:
            result.append({
                'fault_id': scenario.fault_id,
                'fault_type': scenario.fault_type.value,
                'severity': scenario.severity.value,
                'target': scenario.target,
                'description': scenario.description,
                'start_time': scenario.actual_start_time,
                'end_time': scenario.actual_end_time,
                'duration': scenario.duration,
                'recovery_time': scenario.impact_metrics.recovery_time,
                'impact': {
                    'affected_devices': list(scenario.impact_metrics.affected_devices),
                    'affected_links': list(scenario.impact_metrics.affected_links),
                    'packets_lost': scenario.impact_metrics.packets_lost,
                    'routes_changed': scenario.impact_metrics.routes_changed,
                    'neighbor_relationships_lost': scenario.impact_metrics.neighbor_relationships_lost
                }
            })
        return result
    
    def cancel_fault(self, fault_id: str) -> bool:
        """Cancel an active or scheduled fault."""
        with self._lock:
            if fault_id in self.active_faults:
                scenario = self.active_faults[fault_id]
                
                if scenario.status == FaultStatus.ACTIVE:
                    # Try to recover immediately
                    self._recover_fault(fault_id)
                else:
                    # Just remove from active faults
                    del self.active_faults[fault_id]
                
                logger.info(f"Cancelled fault {fault_id}")
                return True
            
        return False
    
    def clear_fault_history(self):
        """Clear the fault history."""
        self.fault_history.clear()
        logger.info("Fault history cleared")
    
    def register_impact_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Register a callback for fault impact notifications."""
        self.impact_callbacks.append(callback)
    
    def get_fault_statistics(self) -> Dict[str, Any]:
        """Get comprehensive fault injection statistics."""
        with self._lock:
            active_count = len(self.active_faults)
            history_count = len(self.fault_history)
            
            # Count by type
            type_counts = {}
            severity_counts = {}
            
            all_scenarios = list(self.active_faults.values()) + self.fault_history
            
            for scenario in all_scenarios:
                fault_type = scenario.fault_type.value
                severity = scenario.severity.value
                
                type_counts[fault_type] = type_counts.get(fault_type, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            return {
                'active_faults': active_count,
                'completed_faults': history_count,
                'total_faults': active_count + history_count,
                'faults_by_type': type_counts,
                'faults_by_severity': severity_counts,
                'cascading_failures_enabled': self.enable_cascading_failures,
                'impact_tracking_enabled': self.impact_tracking_enabled,
                'max_concurrent_faults': self.max_concurrent_faults
            }
    
    def export_fault_report(self, filename: str = None) -> Dict[str, Any]:
        """Export a comprehensive fault injection report."""
        report = {
            'timestamp': time.time(),
            'statistics': self.get_fault_statistics(),
            'active_faults': self.get_active_faults(),
            'fault_history': self.get_fault_history()
        }
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Fault report exported to {filename}")
        
        return report