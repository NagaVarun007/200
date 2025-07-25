#!/usr/bin/env python3
"""
Alert Engine for BMC Security Monitoring

This module implements the alerting engine (F-6) that combines ML predictions
with static rules to generate alerts with risk scores and mitigation suggestions.
It provides real-time threat detection and response recommendations for BMC systems.

AI x Security Narrative: This alerting engine represents a critical component
of AI-driven BMC security, providing automated threat detection and response
capabilities that can operate autonomously in embedded environments. It enables
proactive security posture management and reduces time-to-detection for
sophisticated attacks targeting BMC firmware and runtime behavior.
"""

import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AlertEngine:
    """
    Alert Engine for BMC Security Monitoring.
    
    Combines ML predictions with static rules to generate comprehensive
    security alerts with risk scores and mitigation suggestions.
    """
    
    def __init__(self, rules_file: Path):
        """
        Initialize the Alert Engine.
        
        Args:
            rules_file: Path to the alert rules YAML configuration
        """
        self.rules_file = rules_file
        self.rules = self._load_rules()
        self.active_alerts: Dict[str, Dict] = {}
        logger.info(f"Alert Engine initialized with rules from {rules_file}")
    
    def _load_rules(self) -> Dict[str, Any]:
        """Load alert rules from YAML configuration."""
        try:
            with open(self.rules_file, 'r') as f:
                rules = yaml.safe_load(f)
            logger.info(f"Loaded {len(rules.get('rules', {}))} alert rules")
            return rules
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return {"rules": {}, "ml_thresholds": {}, "correlation": []}
    
    def _evaluate_condition(self, condition: Dict, data: Dict) -> bool:
        """
        Evaluate a single condition against the data.
        
        Args:
            condition: Condition dictionary with field, operator, threshold/value
            data: Input data dictionary
            
        Returns:
            True if condition is met, False otherwise
        """
        field = condition.get('field')
        operator = condition.get('operator')
        threshold = condition.get('threshold')
        value = condition.get('value')
        
        if field not in data:
            return False
        
        data_value = data[field]
        
        if operator == 'gt':
            return data_value > threshold
        elif operator == 'lt':
            return data_value < threshold
        elif operator == 'eq':
            return data_value == value
        elif operator == 'gte':
            return data_value >= threshold
        elif operator == 'lte':
            return data_value <= threshold
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False
    
    def _evaluate_rule(self, rule_name: str, rule_config: Dict, data: Dict) -> bool:
        """
        Evaluate a rule against the data.
        
        Args:
            rule_name: Name of the rule
            rule_config: Rule configuration dictionary
            data: Input data dictionary
            
        Returns:
            True if rule conditions are met, False otherwise
        """
        conditions = rule_config.get('conditions', [])
        
        # All conditions must be met (AND logic)
        for condition in conditions:
            if not self._evaluate_condition(condition, data):
                return False
        
        return True
    
    def _get_ml_severity(self, score: float, model_type: str) -> str:
        """
        Determine severity based on ML score and thresholds.
        
        Args:
            score: ML prediction score
            model_type: Type of ML model (behavioral_anomaly or firmware_tamper)
            
        Returns:
            Severity level (low, medium, high, critical)
        """
        thresholds = self.rules.get('ml_thresholds', {}).get(model_type, {})
        
        if score >= thresholds.get('critical', 0.9):
            return 'critical'
        elif score >= thresholds.get('high', 0.7):
            return 'high'
        elif score >= thresholds.get('medium', 0.5):
            return 'medium'
        else:
            return 'low'
    
    def _check_correlation(self, triggered_rules: List[str]) -> Optional[Dict]:
        """
        Check for correlated alerts across multiple rules.
        
        Args:
            triggered_rules: List of triggered rule names
            
        Returns:
            Correlation alert if conditions are met, None otherwise
        """
        correlations = self.rules.get('correlation', [])
        
        for correlation in correlations:
            required_rules = [cond['rule'] for cond in correlation.get('conditions', [])]
            
            # Check if all required rules are triggered
            if all(rule in triggered_rules for rule in required_rules):
                return {
                    'name': correlation['name'],
                    'description': correlation['description'],
                    'severity': correlation['severity'],
                    'risk_score': correlation['risk_score'],
                    'mitigation': correlation['mitigation'],
                    'triggered_rules': required_rules
                }
        
        return None
    
    def process_prediction(self, prediction: Dict) -> Optional[Dict]:
        """
        Process ML prediction and generate alert if needed.
        
        Args:
            prediction: ML prediction dictionary from UnifiedPredictor
            
        Returns:
            Alert dictionary if conditions are met, None otherwise
        """
        timestamp = prediction.get('timestamp', datetime.now().isoformat())
        prediction_type = prediction.get('type')
        score = prediction.get('score', 0.0)
        is_anomaly = prediction.get('is_anomaly', False)
        
        # Determine severity from ML score
        if prediction_type == 'behavioral':
            severity = self._get_ml_severity(score, 'behavioral_anomaly')
        elif prediction_type == 'firmware':
            severity = self._get_ml_severity(score, 'firmware_tamper')
        else:
            severity = 'unknown'
        
        # Only generate alert if anomaly detected or high severity
        if not is_anomaly and severity in ['low', 'unknown']:
            return None
        
        alert = {
            'timestamp': timestamp,
            'type': 'ml_prediction',
            'prediction_type': prediction_type,
            'severity': severity,
            'risk_score': score,
            'component': 'ml_model',
            'message': f"ML {prediction_type} anomaly detected (score: {score:.3f})",
            'suggestion': self._get_ml_mitigation(prediction_type, severity),
            'top_features': prediction.get('top_feats', []),
            'inference_time_ms': prediction.get('inference_time_ms', 0)
        }
        
        logger.info(f"Generated ML alert: {alert['message']} (severity: {severity})")
        return alert
    
    def _get_ml_mitigation(self, prediction_type: str, severity: str) -> str:
        """Get mitigation suggestion for ML prediction."""
        if prediction_type == 'behavioral':
            if severity == 'critical':
                return "Immediate BMC isolation and full system audit required"
            elif severity == 'high':
                return "Investigate running processes and check for unauthorized activity"
            else:
                return "Monitor system behavior and check for unusual patterns"
        elif prediction_type == 'firmware':
            if severity == 'critical':
                return "Firmware rollback required and supply chain audit"
            elif severity == 'high':
                return "Verify firmware integrity and check for tampering"
            else:
                return "Monitor firmware behavior and validate signatures"
        else:
            return "Investigate the detected anomaly"
    
    def process_static_rules(self, data: Dict) -> List[Dict]:
        """
        Process static rules against the data.
        
        Args:
            data: Input data dictionary with metrics
            
        Returns:
            List of triggered alerts
        """
        alerts = []
        triggered_rules = []
        
        rules = self.rules.get('rules', {})
        
        for rule_name, rule_config in rules.items():
            if self._evaluate_rule(rule_name, rule_config, data):
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'static_rule',
                    'rule_name': rule_name,
                    'severity': rule_config['severity'],
                    'risk_score': rule_config['risk_score'],
                    'component': 'rule_engine',
                    'message': rule_config['description'],
                    'suggestion': rule_config['mitigation']
                }
                
                alerts.append(alert)
                triggered_rules.append(rule_name)
                
                logger.info(f"Static rule triggered: {rule_name} (severity: {rule_config['severity']})")
        
        # Check for correlations
        correlation_alert = self._check_correlation(triggered_rules)
        if correlation_alert:
            correlation_alert.update({
                'timestamp': datetime.now().isoformat(),
                'type': 'correlation',
                'component': 'rule_engine'
            })
            alerts.append(correlation_alert)
            logger.info(f"Correlation alert: {correlation_alert['name']}")
        
        return alerts
    
    def generate_alert_json(self, alert: Dict) -> str:
        """
        Generate JSON line format alert.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            JSON line string
        """
        return json.dumps(alert)


def main():
    """Main entry point for alert engine CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="BMC Security Alert Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process ML prediction from stdin
  echo '{"type": "behavioral", "score": 0.8, "is_anomaly": true}' | python rules/alert_engine.py --rules rules/alert_rules.yaml
  
  # Process static rules from file
  python rules/alert_engine.py --rules rules/alert_rules.yaml --static test_data.json
        """
    )
    
    parser.add_argument(
        '--rules',
        type=Path,
        default=Path('rules/alert_rules.yaml'),
        help='Path to alert rules YAML file'
    )
    
    parser.add_argument(
        '--static',
        type=Path,
        help='Path to JSON file with metrics for static rule evaluation'
    )
    
    parser.add_argument(
        '--output',
        type=Path,
        help='Output file for alerts (default: stdout)'
    )
    
    args = parser.parse_args()
    
    # Initialize alert engine
    engine = AlertEngine(args.rules)
    
    # Process static rules if file provided
    if args.static:
        try:
            with open(args.static, 'r') as f:
                data = json.load(f)
            
            alerts = engine.process_static_rules(data)
            
            if args.output:
                with open(args.output, 'w') as f:
                    for alert in alerts:
                        f.write(engine.generate_alert_json(alert) + '\n')
            else:
                for alert in alerts:
                    print(engine.generate_alert_json(alert))
                    
        except Exception as e:
            logger.error(f"Failed to process static rules: {e}")
            sys.exit(1)
    
    # Process ML predictions from stdin
    else:
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                
                try:
                    prediction = json.loads(line)
                    alert = engine.process_prediction(prediction)
                except json.JSONDecodeError:
                    continue
                
                if alert:
                    if args.output:
                        with open(args.output, 'a') as f:
                            f.write(engine.generate_alert_json(alert) + '\n')
                    else:
                        print(engine.generate_alert_json(alert))
                        
        except KeyboardInterrupt:
            logger.info("Alert engine stopped by user")
        except Exception as e:
            logger.error(f"Failed to process prediction: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main() 