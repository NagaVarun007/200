#!/usr/bin/env python3
"""
Unit tests for Network Traffic Simulator

Tests the NetTrafficSimulator class to ensure correct simulation of normal and attack traffic patterns for BMC security monitoring.
"""

import unittest
from unittest.mock import patch
from datetime import datetime
from net_traffic import NetTrafficSimulator, C2_IP

class TestNetTrafficSimulator(unittest.TestCase):
    def setUp(self):
        self.sim = NetTrafficSimulator()

    def test_baseline_traffic_generation(self):
        """Test that baseline traffic is generated with expected fields and value ranges."""
        traffic = self.sim._generate_baseline_traffic()
        self.assertIn('ts', traffic)
        self.assertIn('src_ip', traffic)
        self.assertIn('dst_ip', traffic)
        self.assertIn('protocol', traffic)
        self.assertIn('pkt_count', traffic)
        self.assertIn('error_count', traffic)
        # Check types
        self.assertIsInstance(traffic['ts'], str)
        self.assertIsInstance(traffic['src_ip'], str)
        self.assertIsInstance(traffic['dst_ip'], str)
        self.assertIsInstance(traffic['protocol'], str)
        self.assertIsInstance(traffic['pkt_count'], int)
        self.assertIsInstance(traffic['error_count'], int)
        # Check timestamp format
        try:
            datetime.fromisoformat(traffic['ts'])
        except ValueError:
            self.fail("Timestamp is not in ISO format")

    def test_burst_attack_pattern(self):
        """Test that burst attack pattern modifies traffic as expected."""
        sim = NetTrafficSimulator(attack_type='burst')
        baseline = sim._generate_baseline_traffic()
        burst = sim._apply_attack_pattern(baseline.copy())
        self.assertTrue(burst['pkt_count'] >= 120)
        self.assertTrue(burst['protocol'] == 'UDP')
        self.assertTrue(burst['dst_ip'].startswith('198.51.100.'))

    def test_c2_attack_pattern(self):
        """Test that c2 attack pattern modifies traffic as expected."""
        sim = NetTrafficSimulator(attack_type='c2')
        baseline = sim._generate_baseline_traffic()
        c2 = sim._apply_attack_pattern(baseline.copy())
        self.assertTrue(3 <= c2['pkt_count'] <= 8)
        self.assertEqual(c2['protocol'], 'TCP')
        self.assertEqual(c2['dst_ip'], C2_IP)

    def test_attack_window_detection(self):
        """Test attack window logic for activation and deactivation."""
        sim = NetTrafficSimulator(attack_type='burst', attack_start=5, attack_duration=3)
        with patch('time.time') as mock_time:
            # Before attack window
            mock_time.return_value = sim.start_time + 2
            self.assertFalse(sim._check_attack_window())
            # During attack window
            mock_time.return_value = sim.start_time + 6
            self.assertTrue(sim._check_attack_window())
            # After attack window
            mock_time.return_value = sim.start_time + 10
            self.assertFalse(sim._check_attack_window())

    def test_generate_traffic_output_format(self):
        """Test that generate_traffic returns a valid traffic log entry."""
        traffic = self.sim.generate_traffic()
        required_fields = ['ts', 'src_ip', 'dst_ip', 'protocol', 'pkt_count', 'error_count']
        for field in required_fields:
            self.assertIn(field, traffic)

if __name__ == '__main__':
    unittest.main() 