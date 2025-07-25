#!/usr/bin/env python3
"""
Unit tests for Alert Engine

Tests the alert engine functionality for both ML predictions and static rules.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alert_engine import AlertEngine


class TestAlertEngine(unittest.TestCase):
    """Test cases for AlertEngine class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary rules file for testing
        self.rules_content = """
rules:
  flash_at_runtime:
    name: "Flash Write During Runtime"
    description: "Detect unauthorized flash write operations"
    severity: "critical"
    conditions:
      - field: "flash_writes_total"
        operator: "gt"
        threshold: 10
    mitigation: "Immediate BMC isolation required"
    risk_score: 0.9
  
  cpu_spike:
    name: "CPU Usage Anomaly"
    description: "Detect unusual CPU usage patterns"
    severity: "high"
    conditions:
      - field: "cpu_mean"
        operator: "gt"
        threshold: 80.0
    mitigation: "Investigate running processes"
    risk_score: 0.7

ml_thresholds:
  behavioral_anomaly:
    low: 0.3
    medium: 0.5
    high: 0.7
    critical: 0.9

correlation:
  - name: "Multi-Vector Attack"
    description: "Detect coordinated attacks"
    conditions:
      - rule: "flash_at_runtime"
      - rule: "cpu_spike"
    severity: "critical"
    risk_score: 1.0
    mitigation: "Full BMC lockdown required"
"""
        
        # Create temporary file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml')
        self.temp_file.write(self.rules_content)
        self.temp_file.close()
        
        # Initialize alert engine
        self.engine = AlertEngine(Path(self.temp_file.name))
    
    def tearDown(self):
        """Clean up test fixtures."""
        Path(self.temp_file.name).unlink()
    
    def test_load_rules(self):
        """Test that rules are loaded correctly."""
        self.assertIn('rules', self.engine.rules)
        self.assertIn('ml_thresholds', self.engine.rules)
        self.assertIn('correlation', self.engine.rules)
        self.assertEqual(len(self.engine.rules['rules']), 2)
    
    def test_evaluate_condition(self):
        """Test condition evaluation."""
        condition = {
            'field': 'cpu_mean',
            'operator': 'gt',
            'threshold': 80.0
        }
        
        # Test condition that should be true
        data = {'cpu_mean': 85.0}
        self.assertTrue(self.engine._evaluate_condition(condition, data))
        
        # Test condition that should be false
        data = {'cpu_mean': 75.0}
        self.assertFalse(self.engine._evaluate_condition(condition, data))
        
        # Test missing field
        data = {'mem_mean': 85.0}
        self.assertFalse(self.engine._evaluate_condition(condition, data))
    
    def test_evaluate_rule(self):
        """Test rule evaluation."""
        rule_config = {
            'conditions': [
                {
                    'field': 'flash_writes_total',
                    'operator': 'gt',
                    'threshold': 10
                }
            ]
        }
        
        # Test rule that should be triggered
        data = {'flash_writes_total': 15}
        self.assertTrue(self.engine._evaluate_rule('flash_at_runtime', rule_config, data))
        
        # Test rule that should not be triggered
        data = {'flash_writes_total': 5}
        self.assertFalse(self.engine._evaluate_rule('flash_at_runtime', rule_config, data))
    
    def test_get_ml_severity(self):
        """Test ML severity determination."""
        # Test different score levels
        self.assertEqual(self.engine._get_ml_severity(0.2, 'behavioral_anomaly'), 'low')
        self.assertEqual(self.engine._get_ml_severity(0.4, 'behavioral_anomaly'), 'low')
        self.assertEqual(self.engine._get_ml_severity(0.6, 'behavioral_anomaly'), 'medium')
        self.assertEqual(self.engine._get_ml_severity(0.8, 'behavioral_anomaly'), 'high')
        self.assertEqual(self.engine._get_ml_severity(0.95, 'behavioral_anomaly'), 'critical')
    
    def test_process_prediction(self):
        """Test ML prediction processing."""
        # Test high-severity prediction
        prediction = {
            'timestamp': '2025-07-24T18:00:00',
            'type': 'behavioral',
            'score': 0.8,
            'is_anomaly': True,
            'top_feats': [{'feature': 'cpu_mean', 'importance': 100}],
            'inference_time_ms': 1.0
        }
        
        alert = self.engine.process_prediction(prediction)
        self.assertIsNotNone(alert)
        self.assertEqual(alert['type'], 'ml_prediction')
        self.assertEqual(alert['severity'], 'high')
        self.assertEqual(alert['prediction_type'], 'behavioral')
        self.assertIn('suggestion', alert)
        
        # Test low-severity prediction (should not generate alert)
        prediction['score'] = 0.2
        prediction['is_anomaly'] = False
        alert = self.engine.process_prediction(prediction)
        self.assertIsNone(alert)
    
    def test_process_static_rules(self):
        """Test static rule processing."""
        # Test data that should trigger flash_at_runtime rule
        data = {
            'flash_writes_total': 15,
            'cpu_mean': 85.0
        }
        
        alerts = self.engine.process_static_rules(data)
        self.assertEqual(len(alerts), 3)  # flash_at_runtime, cpu_spike, and correlation
        
        # Check flash_at_runtime alert
        flash_alert = next(a for a in alerts if a['rule_name'] == 'flash_at_runtime')
        self.assertEqual(flash_alert['severity'], 'critical')
        self.assertEqual(flash_alert['risk_score'], 0.9)
        self.assertIn('isolation', flash_alert['suggestion'])
        
        # Check cpu_spike alert
        cpu_alert = next(a for a in alerts if a['rule_name'] == 'cpu_spike')
        self.assertEqual(cpu_alert['severity'], 'high')
        self.assertEqual(cpu_alert['risk_score'], 0.7)
    
    def test_correlation_detection(self):
        """Test correlation rule detection."""
        # Test data that should trigger both rules for correlation
        data = {
            'flash_writes_total': 15,
            'cpu_mean': 85.0
        }
        
        alerts = self.engine.process_static_rules(data)
        
        # Should have 3 alerts: 2 individual + 1 correlation
        self.assertEqual(len(alerts), 3)
        
        # Check for correlation alert
        correlation_alerts = [a for a in alerts if a['type'] == 'correlation']
        self.assertEqual(len(correlation_alerts), 1)
        
        correlation = correlation_alerts[0]
        self.assertEqual(correlation['severity'], 'critical')
        self.assertEqual(correlation['risk_score'], 1.0)
        self.assertIn('Multi-Vector Attack', correlation['name'])
    
    def test_generate_alert_json(self):
        """Test alert JSON generation."""
        alert = {
            'timestamp': '2025-07-24T18:00:00',
            'type': 'test',
            'severity': 'high',
            'message': 'Test alert'
        }
        
        json_str = self.engine.generate_alert_json(alert)
        parsed = json.loads(json_str)
        
        self.assertEqual(parsed['timestamp'], alert['timestamp'])
        self.assertEqual(parsed['type'], alert['type'])
        self.assertEqual(parsed['severity'], alert['severity'])
        self.assertEqual(parsed['message'], alert['message'])


if __name__ == '__main__':
    unittest.main() 