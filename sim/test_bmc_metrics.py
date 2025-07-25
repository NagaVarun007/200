#!/usr/bin/env python3
"""
Unit tests for BMC Telemetry Generator

Tests the BMCTelemetrySimulator class to ensure proper functionality
for AI-driven BMC security monitoring.
"""

import json
import time
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime

from bmc_metrics import BMCTelemetrySimulator


class TestBMCTelemetrySimulator(unittest.TestCase):
    """Test cases for BMCTelemetrySimulator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.simulator = BMCTelemetrySimulator()
    
    def test_baseline_metrics_generation(self):
        """Test that baseline metrics are generated within expected ranges."""
        metrics = self.simulator._generate_baseline_metrics()
        
        # Check all required fields are present
        self.assertIn('cpu', metrics)
        self.assertIn('mem', metrics)
        self.assertIn('syscalls', metrics)
        self.assertIn('flash_writes', metrics)
        
        # Check value ranges
        self.assertGreaterEqual(metrics['cpu'], 0.0)
        self.assertLessEqual(metrics['cpu'], 100.0)
        self.assertGreaterEqual(metrics['mem'], 0.0)
        self.assertLessEqual(metrics['mem'], 100.0)
        self.assertGreaterEqual(metrics['syscalls'], 0)
        self.assertGreaterEqual(metrics['flash_writes'], 0)
    
    def test_attack_pattern_application(self):
        """Test that attack patterns correctly modify baseline metrics."""
        baseline_metrics = {
            'cpu': 20.0,
            'mem': 50.0,
            'syscalls': 100,
            'flash_writes': 2
        }
        
        # Test CPU spike attack
        cpu_spike_sim = BMCTelemetrySimulator(attack_type='cpu_spike')
        modified = cpu_spike_sim._apply_attack_pattern(baseline_metrics)
        
        # CPU should be multiplied by 3.0 (but capped at 100%)
        self.assertGreater(modified['cpu'], baseline_metrics['cpu'])
        self.assertLessEqual(modified['cpu'], 100.0)
        
        # Memory should be multiplied by 1.2
        self.assertGreater(modified['mem'], baseline_metrics['mem'])
        
        # Syscalls should be multiplied by 2.0
        self.assertEqual(modified['syscalls'], baseline_metrics['syscalls'] * 2)
    
    def test_telemetry_output_format(self):
        """Test that telemetry output matches F-1 specification format."""
        telemetry = self.simulator.generate_telemetry()
        
        # Check required fields from F-1 spec
        required_fields = ['ts', 'cpu', 'mem', 'syscalls', 'flash_writes']
        for field in required_fields:
            self.assertIn(field, telemetry)
        
        # Check timestamp format
        try:
            datetime.fromisoformat(telemetry['ts'])
        except ValueError:
            self.fail("Timestamp is not in ISO format")
        
        # Check data types
        self.assertIsInstance(telemetry['cpu'], float)
        self.assertIsInstance(telemetry['mem'], float)
        self.assertIsInstance(telemetry['syscalls'], int)
        self.assertIsInstance(telemetry['flash_writes'], int)
        
        # Check value ranges
        self.assertGreaterEqual(telemetry['cpu'], 0.0)
        self.assertLessEqual(telemetry['cpu'], 100.0)
        self.assertGreaterEqual(telemetry['mem'], 0.0)
        self.assertLessEqual(telemetry['mem'], 100.0)
        self.assertGreaterEqual(telemetry['syscalls'], 0)
        self.assertGreaterEqual(telemetry['flash_writes'], 0)
    
    def test_attack_window_detection(self):
        """Test attack window detection logic."""
        # Test with no attack
        self.assertFalse(self.simulator._check_attack_window())
        
        # Test with attack starting at 5s for 3s duration
        attack_sim = BMCTelemetrySimulator(
            attack_type='cpu_spike',
            attack_start=5,
            attack_duration=3
        )
        
        # Mock time to test different scenarios
        with patch('time.time') as mock_time:
            # Before attack window
            mock_time.return_value = attack_sim.start_time + 2
            self.assertFalse(attack_sim._check_attack_window())
            
            # During attack window
            mock_time.return_value = attack_sim.start_time + 6
            self.assertTrue(attack_sim._check_attack_window())
            
            # After attack window
            mock_time.return_value = attack_sim.start_time + 10
            self.assertFalse(attack_sim._check_attack_window())
    
    def test_flash_flood_attack_pattern(self):
        """Test flash flood attack pattern specifically."""
        baseline_metrics = {
            'cpu': 15.0,
            'mem': 40.0,
            'syscalls': 80,
            'flash_writes': 1
        }
        
        flash_flood_sim = BMCTelemetrySimulator(attack_type='flash_flood')
        modified = flash_flood_sim._apply_attack_pattern(baseline_metrics)
        
        # Flash writes should be multiplied by 10.0
        self.assertEqual(modified['flash_writes'], baseline_metrics['flash_writes'] * 10)
        
        # Other metrics should be slightly increased
        self.assertGreater(modified['cpu'], baseline_metrics['cpu'])
        self.assertGreater(modified['mem'], baseline_metrics['mem'])
        self.assertGreater(modified['syscalls'], baseline_metrics['syscalls'])


if __name__ == '__main__':
    unittest.main() 