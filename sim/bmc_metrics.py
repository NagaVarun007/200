#!/usr/bin/env python3
"""
BMC Telemetry Generator for AnomalyzeAI

This module simulates Baseboard Management Controller (BMC) telemetry data streams
to enable AI-driven anomaly detection for hardware security monitoring. The BMC
serves as a critical security boundary in modern server architectures, and this
simulator provides realistic baseline behavior patterns that can be perturbed
by various attack scenarios.

This aligns with Axiado's "AI-driven, hardware-anchored" security vision by
providing the foundational data streams needed to train machine learning models
for detecting firmware tampering, unauthorized access attempts, and behavioral
anomalies in BMC operations.

Author: AnomalyzeAI Team
License: MIT
"""

import argparse
import json
import logging
import random
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Configure logging for BMC security monitoring
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class BMCTelemetrySimulator:
    """
    Simulates BMC telemetry data with configurable attack patterns.
    
    This class generates realistic BMC metrics including CPU utilization,
    memory usage, system call patterns, and flash write operations. It can
    inject various attack patterns to test anomaly detection algorithms.
    """
    
    def __init__(self, attack_type: Optional[str] = None, 
                 attack_start: int = 0, attack_duration: int = 0):
        """
        Initialize BMC telemetry simulator.
        
        Args:
            attack_type: Type of attack to simulate ('cpu_spike', 'mem_exhaustion', 
                        'flash_flood', 'syscall_anomaly')
            attack_start: When to start the attack (seconds from start)
            attack_duration: How long the attack should last (seconds)
        """
        self.attack_type = attack_type
        self.attack_start = attack_start
        self.attack_duration = attack_duration
        self.start_time = time.time()
        self.attack_active = False
        
        # Baseline BMC metrics ranges
        self.baseline_ranges = {
            'cpu': (5.0, 25.0),      # CPU utilization percentage
            'mem': (30.0, 60.0),     # Memory usage percentage  
            'syscalls': (50, 200),   # System calls per second
            'flash_writes': (0, 5)   # Flash write operations per second
        }
        
        # Attack pattern multipliers
        self.attack_patterns = {
            'cpu_spike': {'cpu': 3.0, 'mem': 1.2, 'syscalls': 2.0, 'flash_writes': 1.0},
            'mem_exhaustion': {'cpu': 1.5, 'mem': 4.0, 'syscalls': 1.8, 'flash_writes': 1.0},
            'flash_flood': {'cpu': 1.2, 'mem': 1.1, 'syscalls': 1.5, 'flash_writes': 10.0},
            'syscall_anomaly': {'cpu': 2.0, 'mem': 1.3, 'syscalls': 5.0, 'flash_writes': 1.0}
        }
        
        logger.info(f"BMC Telemetry Simulator initialized with attack_type={attack_type}, "
                   f"start={attack_start}s, duration={attack_duration}s")

    def _generate_baseline_metrics(self) -> Dict[str, float]:
        """
        Generate baseline BMC metrics within normal operating ranges.
        
        Returns:
            Dictionary containing baseline telemetry metrics
        """
        metrics = {}
        for metric, (min_val, max_val) in self.baseline_ranges.items():
            if metric in ['cpu', 'mem']:
                # Add some realistic variation with slight trends
                base = random.uniform(min_val, max_val)
                # Add small random walk for realism
                variation = random.uniform(-2.0, 2.0)
                metrics[metric] = max(0.0, min(100.0, base + variation))
            else:
                # Integer metrics
                metrics[metric] = random.randint(min_val, max_val)
        
        return metrics

    def _apply_attack_pattern(self, metrics: Dict[str, float]) -> Dict[str, float]:
        """
        Apply attack pattern multipliers to baseline metrics.
        
        Args:
            metrics: Baseline metrics dictionary
            
        Returns:
            Modified metrics with attack pattern applied
        """
        if not self.attack_type or self.attack_type not in self.attack_patterns:
            return metrics
            
        pattern = self.attack_patterns[self.attack_type]
        modified_metrics = metrics.copy()
        
        for metric, multiplier in pattern.items():
            if metric in modified_metrics:
                if metric in ['cpu', 'mem']:
                    # For percentage metrics, ensure we don't exceed 100%
                    modified_metrics[metric] = min(100.0, 
                                                 modified_metrics[metric] * multiplier)
                else:
                    # For count metrics, apply multiplier directly
                    modified_metrics[metric] = int(modified_metrics[metric] * multiplier)
        
        return modified_metrics

    def _check_attack_window(self) -> bool:
        """
        Check if we're currently in an attack window.
        
        Returns:
            True if attack should be active, False otherwise
        """
        if not self.attack_type:
            return False
            
        current_time = time.time() - self.start_time
        attack_end = self.attack_start + self.attack_duration
        
        return self.attack_start <= current_time <= attack_end

    def generate_telemetry(self) -> Dict[str, any]:
        """
        Generate a single telemetry record with current BMC metrics.
        
        Returns:
            Dictionary containing timestamp and BMC metrics
        """
        # Check if we should activate attack pattern
        should_attack = self._check_attack_window()
        if should_attack and not self.attack_active:
            logger.warning(f"Attack pattern '{self.attack_type}' activated")
            self.attack_active = True
        elif not should_attack and self.attack_active:
            logger.info(f"Attack pattern '{self.attack_type}' deactivated")
            self.attack_active = False
        
        # Generate baseline metrics
        metrics = self._generate_baseline_metrics()
        
        # Apply attack pattern if active
        if self.attack_active:
            metrics = self._apply_attack_pattern(metrics)
        
        # Create telemetry record
        telemetry = {
            'ts': datetime.now().isoformat(),
            'cpu': round(metrics['cpu'], 2),
            'mem': round(metrics['mem'], 2),
            'syscalls': metrics['syscalls'],
            'flash_writes': metrics['flash_writes']
        }
        
        return telemetry

    def run(self, duration: int = 60) -> None:
        """
        Run the BMC telemetry simulator for specified duration.
        
        Args:
            duration: Duration to run in seconds (default: 60)
        """
        logger.info(f"Starting BMC telemetry simulation for {duration} seconds")
        
        end_time = time.time() + duration
        
        try:
            while time.time() < end_time:
                telemetry = self.generate_telemetry()
                print(json.dumps(telemetry))
                time.sleep(1.0)  # Emit every second as per F-1 spec
                
        except KeyboardInterrupt:
            logger.info("BMC telemetry simulation interrupted by user")
        except Exception as e:
            logger.error(f"Error in BMC telemetry simulation: {e}")
            raise


def main():
    """Main entry point for BMC telemetry generator CLI."""
    parser = argparse.ArgumentParser(
        description="BMC Telemetry Generator for AnomalyzeAI Security Monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate normal telemetry for 60 seconds
  python bmc_metrics.py --duration 60
  
  # Simulate CPU spike attack starting at 30s for 10s duration
  python bmc_metrics.py --attack cpu_spike --start 30 --duration 10
  
  # Simulate flash flood attack for 5 minutes
  python bmc_metrics.py --attack flash_flood --duration 300
        """
    )
    
    parser.add_argument(
        '--attack', 
        type=str,
        choices=['cpu_spike', 'mem_exhaustion', 'flash_flood', 'syscall_anomaly'],
        help='Type of attack to simulate'
    )
    
    parser.add_argument(
        '--start', 
        type=int, 
        default=0,
        help='When to start the attack (seconds from start, default: 0)'
    )
    
    parser.add_argument(
        '--duration', 
        type=int, 
        default=60,
        help='Duration to run simulation in seconds (default: 60)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.start < 0:
        logger.error("Attack start time must be non-negative")
        sys.exit(1)
        
    if args.duration <= 0:
        logger.error("Duration must be positive")
        sys.exit(1)
        
    if args.attack and args.start >= args.duration:
        logger.error("Attack start time must be less than duration")
        sys.exit(1)
    
    # Create and run simulator
    simulator = BMCTelemetrySimulator(
        attack_type=args.attack,
        attack_start=args.start,
        attack_duration=args.duration
    )
    
    simulator.run(args.duration)


if __name__ == "__main__":
    main() 