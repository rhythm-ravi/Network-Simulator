#!/usr/bin/env python3
"""
Event Scheduler for Network Simulator

This module provides event scheduling and management capabilities using SimPy
for discrete event simulation.
"""

import simpy
import heapq
import logging
from typing import Dict, List, Optional, Any, Callable, Generator
from dataclasses import dataclass, field
from enum import Enum
import threading
import queue
import time

from .network_events import NetworkEvent, EventType, EventPriority

logger = logging.getLogger(__name__)


class SchedulerState(Enum):
    """Enumeration of scheduler states."""
    INITIALIZED = "initialized"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class EventMetrics:
    """Metrics for event processing."""
    
    total_events: int = 0
    processed_events: int = 0
    pending_events: int = 0
    events_by_type: Dict[EventType, int] = field(default_factory=dict)
    processing_times: Dict[EventType, List[float]] = field(default_factory=dict)
    average_processing_time: float = 0.0
    
    def add_event(self, event_type: EventType):
        """Add an event to metrics."""
        self.total_events += 1
        self.events_by_type[event_type] = self.events_by_type.get(event_type, 0) + 1
    
    def record_processing_time(self, event_type: EventType, processing_time: float):
        """Record event processing time."""
        if event_type not in self.processing_times:
            self.processing_times[event_type] = []
        self.processing_times[event_type].append(processing_time)
        
        # Update average
        all_times = []
        for times in self.processing_times.values():
            all_times.extend(times)
        
        if all_times:
            self.average_processing_time = sum(all_times) / len(all_times)


class EventScheduler:
    """
    Event scheduler using SimPy for discrete event simulation.
    
    This class manages the scheduling and execution of network events
    in a discrete event simulation environment.
    """
    
    def __init__(self, real_time_factor: float = 1.0):
        """
        Initialize the event scheduler.
        
        Args:
            real_time_factor: Factor to control simulation speed relative to real time
                            (1.0 = real time, 0.5 = half speed, 2.0 = double speed)
        """
        self.env = simpy.Environment()
        self.real_time_factor = real_time_factor
        self.state = SchedulerState.INITIALIZED
        self.metrics = EventMetrics()
        
        # Event management
        self.event_queue: List[NetworkEvent] = []
        self.event_handlers: Dict[EventType, List[Callable]] = {}
        self.periodic_events: Dict[str, Dict[str, Any]] = {}
        
        # Control mechanisms
        self.pause_event = threading.Event()
        self.pause_event.set()  # Start unpaused
        self.stop_flag = threading.Event()
        self.control_queue = queue.Queue()
        
        # Synchronization
        self.lock = threading.RLock()
        
        logger.info(f"Event scheduler initialized with real-time factor: {real_time_factor}")
    
    def register_event_handler(self, event_type: EventType, handler: Callable[[NetworkEvent], List[NetworkEvent]]):
        """
        Register an event handler for a specific event type.
        
        Args:
            event_type: Type of event to handle
            handler: Callable that takes an event and returns a list of new events
        """
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        
        self.event_handlers[event_type].append(handler)
        logger.debug(f"Registered handler for event type: {event_type.value}")
    
    def schedule_event(self, event: NetworkEvent, delay: float = 0.0):
        """
        Schedule an event to be processed at a specific time.
        
        Args:
            event: Network event to schedule
            delay: Additional delay to add to the event timestamp
        """
        with self.lock:
            event.timestamp += delay
            
            # Use SimPy timeout to schedule the event
            self.env.process(self._process_event_at_time(event))
            
            self.metrics.add_event(event.event_type)
            self.metrics.pending_events += 1
            
            logger.debug(f"Scheduled event: {event} at {event.timestamp:.3f}")
    
    def schedule_periodic_event(self, event_template: NetworkEvent, interval: float, 
                              event_id: str, max_occurrences: Optional[int] = None):
        """
        Schedule a periodic event.
        
        Args:
            event_template: Template event to repeat
            interval: Time interval between occurrences
            event_id: Unique identifier for this periodic event
            max_occurrences: Maximum number of occurrences (None for infinite)
        """
        periodic_info = {
            'event_template': event_template,
            'interval': interval,
            'max_occurrences': max_occurrences,
            'occurrence_count': 0,
            'active': True
        }
        
        self.periodic_events[event_id] = periodic_info
        
        # Start the periodic event process
        self.env.process(self._process_periodic_event(event_id))
        
        logger.info(f"Scheduled periodic event: {event_id} with interval {interval}")
    
    def cancel_periodic_event(self, event_id: str):
        """Cancel a periodic event."""
        if event_id in self.periodic_events:
            self.periodic_events[event_id]['active'] = False
            logger.info(f"Cancelled periodic event: {event_id}")
    
    def _process_event_at_time(self, event: NetworkEvent) -> Generator:
        """SimPy process to handle an event at its scheduled time."""
        # Wait until the event's scheduled time
        yield self.env.timeout(event.timestamp - self.env.now)
        
        # Check for pause
        while not self.pause_event.is_set() and not self.stop_flag.is_set():
            yield self.env.timeout(0.1)  # Check every 100ms
        
        if self.stop_flag.is_set():
            return
        
        # Process the event
        yield from self._process_single_event(event)
    
    def _process_periodic_event(self, event_id: str) -> Generator:
        """SimPy process to handle periodic events."""
        periodic_info = self.periodic_events[event_id]
        
        while (periodic_info['active'] and 
               not self.stop_flag.is_set() and
               (periodic_info['max_occurrences'] is None or 
                periodic_info['occurrence_count'] < periodic_info['max_occurrences'])):
            
            # Wait for the next occurrence
            yield self.env.timeout(periodic_info['interval'])
            
            # Check for pause
            while not self.pause_event.is_set() and not self.stop_flag.is_set():
                yield self.env.timeout(0.1)
            
            if self.stop_flag.is_set() or not periodic_info['active']:
                break
            
            # Create a new event instance from the template
            event_template = periodic_info['event_template']
            
            # For periodic events, create a deep copy and update timestamp
            import copy
            new_event = copy.deepcopy(event_template)
            new_event.timestamp = self.env.now
            
            # Generate new event ID
            import uuid
            new_event.event_id = str(uuid.uuid4())[:8]
            
            # Process the event
            yield from self._process_single_event(new_event)
            
            periodic_info['occurrence_count'] += 1
    
    def _process_single_event(self, event: NetworkEvent) -> Generator:
        """Process a single event and handle any resulting events."""
        start_time = time.time()
        
        try:
            # Find handlers for this event type
            handlers = self.event_handlers.get(event.event_type, [])
            
            new_events = []
            
            if handlers:
                for handler in handlers:
                    try:
                        result_events = handler(event)
                        if result_events:
                            new_events.extend(result_events)
                    except Exception as e:
                        logger.error(f"Error in event handler for {event}: {e}")
            else:
                # Use the event's own process method if no external handlers
                try:
                    # This would need to be adapted based on your actual simulation engine
                    # For now, we'll just log that the event was processed
                    logger.debug(f"Processing event: {event}")
                    
                except Exception as e:
                    logger.error(f"Error processing event {event}: {e}")
            
            # Schedule any resulting events
            for new_event in new_events:
                self.schedule_event(new_event)
            
            # Update metrics
            processing_time = time.time() - start_time
            self.metrics.processed_events += 1
            self.metrics.pending_events = max(0, self.metrics.pending_events - 1)
            self.metrics.record_processing_time(event.event_type, processing_time)
            
            logger.debug(f"Processed event: {event} (generated {len(new_events)} new events)")
            
        except Exception as e:
            logger.error(f"Critical error processing event {event}: {e}")
            self.state = SchedulerState.ERROR
        
        # Small yield to allow other processes
        yield self.env.timeout(0)
    
    def run(self, until: Optional[float] = None, real_time: bool = False):
        """
        Run the simulation until a specified time or indefinitely.
        
        Args:
            until: Simulation time to run until (None for indefinite)
            real_time: Whether to synchronize with real time
        """
        self.state = SchedulerState.RUNNING
        
        try:
            logger.debug(f"Starting event scheduler run until {until}")
            
            if real_time and self.real_time_factor > 0:
                # Run with real-time synchronization
                self._run_real_time(until)
            else:
                # Run as fast as possible
                if until:
                    logger.debug(f"Running SimPy environment until {until}")
                    self.env.run(until=until)
                    logger.debug(f"SimPy run completed, current time: {self.env.now}")
                else:
                    self.env.run()
                    
            self.state = SchedulerState.STOPPED if self.stop_flag.is_set() else SchedulerState.INITIALIZED
            
        except Exception as e:
            logger.error(f"Error running simulation: {e}")
            self.state = SchedulerState.ERROR
            raise
    
    def _run_real_time(self, until: Optional[float] = None):
        """Run simulation synchronized with real time."""
        start_real_time = time.time()
        start_sim_time = self.env.now
        
        while not self.stop_flag.is_set() and (until is None or self.env.now < until):
            # Calculate how much real time should have passed
            sim_elapsed = self.env.now - start_sim_time
            real_elapsed_target = sim_elapsed / self.real_time_factor
            real_elapsed_actual = time.time() - start_real_time
            
            # Sleep if we're running ahead of real time
            if real_elapsed_actual < real_elapsed_target:
                time.sleep(real_elapsed_target - real_elapsed_actual)
            
            # Process events for a small time step
            try:
                self.env.run(until=self.env.now + 0.1)
            except simpy.exceptions.EmptySchedule:
                break
    
    def pause(self):
        """Pause the simulation."""
        self.pause_event.clear()
        if self.state == SchedulerState.RUNNING:
            self.state = SchedulerState.PAUSED
            logger.info("Simulation paused")
    
    def resume(self):
        """Resume the simulation."""
        self.pause_event.set()
        if self.state == SchedulerState.PAUSED:
            self.state = SchedulerState.RUNNING
            logger.info("Simulation resumed")
    
    def stop(self):
        """Stop the simulation."""
        self.stop_flag.set()
        self.pause_event.set()  # Ensure we're not blocked on pause
        self.state = SchedulerState.STOPPED
        logger.info("Simulation stopped")
    
    def reset(self):
        """Reset the scheduler to initial state."""
        self.stop()
        
        # Reset SimPy environment
        self.env = simpy.Environment()
        
        # Reset state
        self.state = SchedulerState.INITIALIZED
        self.metrics = EventMetrics()
        self.event_queue.clear()
        self.periodic_events.clear()
        
        # Reset control mechanisms
        self.pause_event.set()
        self.stop_flag.clear()
        
        # Clear control queue
        while not self.control_queue.empty():
            try:
                self.control_queue.get_nowait()
            except queue.Empty:
                break
        
        logger.info("Scheduler reset to initial state")
    
    def get_current_time(self) -> float:
        """Get the current simulation time."""
        return self.env.now
    
    def get_metrics(self) -> EventMetrics:
        """Get current event processing metrics."""
        return self.metrics
    
    def get_state(self) -> SchedulerState:
        """Get current scheduler state."""
        return self.state
    
    def get_pending_events_count(self) -> int:
        """Get the number of pending events."""
        return len(self.env._queue)
    
    def get_event_summary(self) -> Dict[str, Any]:
        """Get a summary of event processing statistics."""
        return {
            'state': self.state.value,
            'current_time': self.get_current_time(),
            'total_events': self.metrics.total_events,
            'processed_events': self.metrics.processed_events,
            'pending_events': self.get_pending_events_count(),
            'events_by_type': {k.value: v for k, v in self.metrics.events_by_type.items()},
            'average_processing_time': self.metrics.average_processing_time,
            'periodic_events': len(self.periodic_events)
        }
    
    def inject_control_event(self, command: str, parameters: Optional[Dict[str, Any]] = None):
        """
        Inject a control event into the simulation.
        
        Args:
            command: Control command ('pause', 'resume', 'stop', 'config_change', etc.)
            parameters: Additional parameters for the command
        """
        control_event = {
            'command': command,
            'parameters': parameters or {},
            'timestamp': self.get_current_time()
        }
        
        self.control_queue.put(control_event)
        logger.debug(f"Injected control event: {command}")
    
    def process_control_events(self):
        """Process any pending control events."""
        while not self.control_queue.empty():
            try:
                control_event = self.control_queue.get_nowait()
                command = control_event['command']
                parameters = control_event['parameters']
                
                if command == 'pause':
                    self.pause()
                elif command == 'resume':
                    self.resume()
                elif command == 'stop':
                    self.stop()
                else:
                    logger.warning(f"Unknown control command: {command}")
                    
            except queue.Empty:
                break
            except Exception as e:
                logger.error(f"Error processing control event: {e}")