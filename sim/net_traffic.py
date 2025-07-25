#!/usr/bin/env python3
"""
Network Traffic Simulator for AnamolyzeAI

This module simulates network traffic logs for BMC environments, enabling
AI-driven detection of anomalous communication patterns and potential
intrusions. It supports both normal and adversarial traffic scenarios,
including burst attacks and command-and-control (C2) patterns.

By providing realistic and attack-augmented network logs, this simulator
aligns with Axiado's "AI-driven, hardware-anchored" security vision, serving
as a foundation for training and evaluating network anomaly detection models
in BMC security monitoring pipelines.

Author: AnamolyzeAI Team
License: MIT
"""

import argparse
import json
import logging
import random
import sys
import time
from datetime import datetime
from typing import Dict, Optional

# Configure logging for network traffic simulation
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Example IP pools for simulation
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(2, 50)]
EXTERNAL_IPS = [f"192.168.1.{i}" for i in range(100, 200)]
C2_IP = "203.0.113.42"  # Simulated C2 server

PROTOCOLS = ["TCP", "UDP", "ICMP"]

class NetTrafficSimulator:
    """
    Simulates BMC network traffic logs with configurable attack patterns.
    
    This class generates realistic network flows and can inject burst or
    command-and-control (C2) attack patterns to test anomaly detection.
    """
    def __init__(self, attack_type: Optional[str] = None, attack_start: int = 0, attack_duration: int = 0):
        """
        Initialize network traffic simulator.
        
        Args:
            attack_type: Type of attack to simulate ('burst', 'c2')
            attack_start: When to start the attack (seconds from start)
            attack_duration: How long the attack should last (seconds)
        """
        self.attack_type = attack_type
        self.attack_start = attack_start
        self.attack_duration = attack_duration
        self.start_time = time.time()
        self.attack_active = False
        logger.info(f"Network Traffic Simulator initialized with attack_type={attack_type}, "
                    f"start={attack_start}s, duration={attack_duration}s")

    def _generate_baseline_traffic(self) -> Dict[str, any]:
        """
        Generate a baseline network traffic log entry.
        Returns:
            Dictionary with network traffic fields.
        """
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        protocol = random.choice(PROTOCOLS)
        pkt_count = random.randint(10, 60)  # Normal per-second packet count
        error_count = random.choices([0, 1], weights=[0.95, 0.05])[0]
        return {
            "ts": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "pkt_count": pkt_count,
            "error_count": error_count
        }

    def _apply_attack_pattern(self, traffic: Dict[str, any]) -> Dict[str, any]:
        """
        Modify traffic log entry according to the selected attack pattern.
        Args:
            traffic: Baseline traffic log entry.
        Returns:
            Modified traffic log entry.
        """
        if self.attack_type == "burst":
            # Simulate a burst: >100 packets/sec to a new IP
            traffic["dst_ip"] = f"198.51.100.{random.randint(200, 250)}"  # New/unusual IP
            traffic["pkt_count"] = random.randint(120, 200)
            traffic["protocol"] = "UDP"
        elif self.attack_type == "c2":
            # Simulate C2: repeated small packets to a single external IP
            traffic["dst_ip"] = C2_IP
            traffic["pkt_count"] = random.randint(3, 8)
            traffic["protocol"] = "TCP"
        return traffic

    def _check_attack_window(self) -> bool:
        """
        Check if we're currently in an attack window.
        Returns:
            True if attack should be active, False otherwise.
        """
        if not self.attack_type:
            return False
        current_time = time.time() - self.start_time
        attack_end = self.attack_start + self.attack_duration
        return self.attack_start <= current_time <= attack_end

    def generate_traffic(self) -> Dict[str, any]:
        """
        Generate a single network traffic log entry.
        Returns:
            Dictionary with network traffic fields.
        """
        should_attack = self._check_attack_window()
        if should_attack and not self.attack_active:
            logger.warning(f"Attack pattern '{self.attack_type}' activated")
            self.attack_active = True
        elif not should_attack and self.attack_active:
            logger.info(f"Attack pattern '{self.attack_type}' deactivated")
            self.attack_active = False
        traffic = self._generate_baseline_traffic()
        if self.attack_active:
            traffic = self._apply_attack_pattern(traffic)
        return traffic

    def run(self, duration: int = 60) -> None:
        """
        Run the network traffic simulator for the specified duration.
        Args:
            duration: Duration to run in seconds (default: 60)
        """
        logger.info(f"Starting network traffic simulation for {duration} seconds")
        end_time = time.time() + duration
        try:
            while time.time() < end_time:
                traffic = self.generate_traffic()
                print(json.dumps(traffic))
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Network traffic simulation interrupted by user")
        except Exception as e:
            logger.error(f"Error in network traffic simulation: {e}")
            raise

def main():
    """Main entry point for network traffic simulator CLI."""
    parser = argparse.ArgumentParser(
        description="Network Traffic Simulator for AnamolyzeAI Security Monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate normal network traffic for 60 seconds
  python net_traffic.py --duration 60

  # Simulate burst attack starting at 10s for 15s duration
  python net_traffic.py --attack burst --start 10 --duration 15

  # Simulate C2 attack for 2 minutes
  python net_traffic.py --attack c2 --duration 120
        """
    )
    parser.add_argument(
        '--attack',
        type=str,
        choices=['burst', 'c2'],
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
    if args.start < 0:
        logger.error("Attack start time must be non-negative")
        sys.exit(1)
    if args.duration <= 0:
        logger.error("Duration must be positive")
        sys.exit(1)
    if args.attack and args.start >= args.duration:
        logger.error("Attack start time must be less than duration")
        sys.exit(1)
    simulator = NetTrafficSimulator(
        attack_type=args.attack,
        attack_start=args.start,
        attack_duration=args.duration
    )
    simulator.run(args.duration)

if __name__ == "__main__":
    main() 