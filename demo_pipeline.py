#!/usr/bin/env python3
"""
Demo script for BMC Security Alert Pipeline

This script demonstrates the complete pipeline from ML prediction to alert generation.
"""

import json
import sys
from pathlib import Path

# Add current directory to path for imports
sys.path.append('.')

from models.predict import UnifiedPredictor
from rules.alert_engine import AlertEngine

def demo_ml_prediction():
    """Demonstrate ML prediction functionality."""
    print("🔍 Step 1: ML Prediction")
    print("-" * 40)
    
    # Load predictor
    predictor = UnifiedPredictor(Path("models"))
    
    # Test features
    features = {
        'cpu_mean': 30.5,
        'cpu_std': 8.2,
        'cpu_max': 45.0,
        'cpu_min': 20.0,
        'mem_mean': 75.2,
        'mem_std': 12.1,
        'mem_max': 85.0,
        'mem_min': 60.0,
        'syscalls_total': 2500,
        'syscalls_mean': 250.0,
        'syscalls_std': 35.0,
        'flash_writes_total': 100,
        'flash_writes_mean': 10.0,
        'flash_writes_std': 3.0,
        'total_packets': 800,
        'total_errors': 5,
        'error_rate': 0.006,
        'unique_src_ips': 8,
        'unique_dst_ips': 12,
        'unique_protocols': 3,
        'src_ip_entropy': 3.2,
        'dst_ip_entropy': 3.8,
        'protocol_entropy': 1.6,
        'max_dst_packets': 80,
        'avg_packets_per_flow': 66.7,
        'tcp_count': 20,
        'udp_count': 12,
        'icmp_count': 3
    }
    
    # Make prediction
    prediction = predictor.predict(features)
    
    print(f"✅ Prediction completed:")
    print(f"   Type: {prediction['type']}")
    print(f"   Score: {prediction['score']:.3f}")
    print(f"   Severity: {prediction['severity']}")
    print(f"   Is Anomaly: {prediction['is_anomaly']}")
    print(f"   Inference Time: {prediction['inference_time_ms']:.2f}ms")
    
    return prediction

def demo_alert_generation(prediction):
    """Demonstrate alert generation from ML prediction."""
    print("\n🚨 Step 2: Alert Generation")
    print("-" * 40)
    
    # Load alert engine
    engine = AlertEngine(Path("rules/alert_rules.yaml"))
    
    # Generate alert
    alert = engine.process_prediction(prediction)
    
    if alert:
        print(f"✅ Alert generated:")
        print(f"   Type: {alert['type']}")
        print(f"   Severity: {alert['severity']}")
        print(f"   Risk Score: {alert['risk_score']:.3f}")
        print(f"   Message: {alert['message']}")
        print(f"   Suggestion: {alert['suggestion']}")
        
        # Show top features if available
        if alert.get('top_features'):
            print(f"   Top Features: {len(alert['top_features'])} identified")
    else:
        print("ℹ️  No alert generated (normal behavior)")
    
    return alert

def demo_static_rules():
    """Demonstrate static rule processing."""
    print("\n📋 Step 3: Static Rule Processing")
    print("-" * 40)
    
    # Load alert engine
    engine = AlertEngine(Path("rules/alert_rules.yaml"))
    
    # Test data that should trigger multiple rules
    test_data = {
        'flash_writes_total': 15,
        'flash_writes_mean': 3.0,
        'cpu_mean': 85.5,
        'cpu_std': 18.2,
        'mem_mean': 92.2,
        'mem_std': 25.1,
        'syscalls_total': 3500,
        'syscalls_std': 55.0,
        'total_packets': 1200,
        'error_rate': 0.0125
    }
    
    # Process static rules
    alerts = engine.process_static_rules(test_data)
    
    print(f"✅ Generated {len(alerts)} alerts:")
    for i, alert in enumerate(alerts, 1):
        rule_name = alert.get('rule_name', alert.get('name', 'Unknown'))
        print(f"   {i}. {rule_name} - {alert['severity']} (score: {alert['risk_score']:.2f})")
        if 'message' in alert:
            print(f"      {alert['message']}")
        elif 'description' in alert:
            print(f"      {alert['description']}")
    
    return alerts

def main():
    """Run the complete demo."""
    print("🚀 BMC Security Alert Pipeline Demo")
    print("=" * 60)
    
    try:
        # Step 1: ML Prediction
        prediction = demo_ml_prediction()
        
        # Step 2: Alert Generation
        alert = demo_alert_generation(prediction)
        
        # Step 3: Static Rules
        static_alerts = demo_static_rules()
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Demo Summary:")
        print(f"   ✅ ML Prediction: {prediction['type']} anomaly detected")
        print(f"   ✅ Alert Generation: {'Success' if alert else 'No alert (normal)'}")
        print(f"   ✅ Static Rules: {len(static_alerts)} rules triggered")
        
        print("\n🎉 Demo completed successfully!")
        print("The BMC Security Alert Pipeline is working correctly.")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 