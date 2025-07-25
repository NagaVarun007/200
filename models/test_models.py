#!/usr/bin/env python3
"""
Test script for ML models functionality

This script creates mock models and tests the prediction pipeline
without requiring large training datasets.
"""

import json
import pickle
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

def create_mock_models():
    """Create mock models for testing."""
    print("Creating mock models for testing...")
    
    # Create mock Isolation Forest
    iforest = IsolationForest(contamination=0.05, random_state=42, n_estimators=10)
    # Train on dummy data
    dummy_data = np.random.randn(100, 28)  # 28 features (runtime + network)
    iforest.fit(dummy_data)
    
    # Create mock scaler
    scaler = StandardScaler()
    scaler.fit(dummy_data)
    
    # Save models
    models_dir = Path("models")
    models_dir.mkdir(exist_ok=True)
    
    joblib.dump(iforest, models_dir / "iforest.joblib")
    with open(models_dir / "behavioral_scaler.pkl", 'wb') as f:
        pickle.dump(scaler, f)
    
    print("Mock models created successfully!")
    return True

def test_prediction():
    """Test the prediction functionality."""
    print("Testing prediction functionality...")
    
    # Import the predictor
    sys.path.append('.')
    from models.predict import UnifiedPredictor
    
    # Create predictor
    predictor = UnifiedPredictor(Path("models"))
    
    # Test behavioral prediction
    behavioral_features = {
        'cpu_mean': 25.5,
        'cpu_std': 5.2,
        'cpu_max': 35.0,
        'cpu_min': 15.0,
        'mem_mean': 60.2,
        'mem_std': 8.1,
        'mem_max': 75.0,
        'mem_min': 45.0,
        'syscalls_total': 1500,
        'syscalls_mean': 150.0,
        'syscalls_std': 25.0,
        'flash_writes_total': 50,
        'flash_writes_mean': 5.0,
        'flash_writes_std': 2.0,
        'total_packets': 500,
        'total_errors': 2,
        'error_rate': 0.004,
        'unique_src_ips': 5,
        'unique_dst_ips': 8,
        'unique_protocols': 3,
        'src_ip_entropy': 2.3,
        'dst_ip_entropy': 3.1,
        'protocol_entropy': 1.6,
        'max_dst_packets': 45,
        'avg_packets_per_flow': 62.5,
        'tcp_count': 15,
        'udp_count': 8,
        'icmp_count': 2
    }
    
    result = predictor.predict(behavioral_features)
    print("Behavioral prediction result:")
    print(json.dumps(result, indent=2))
    
    # Test firmware prediction
    firmware_features = {
        'file_size': 16777216,
        'shannon_entropy': 7.8,
        'lzma_dict_len': 150,
        'bigram_high_byte_ratio': 0.75,
        'trigram_high_byte_ratio': 0.87,
        'zero_ratio': 0.004,
        'one_ratio': 0.004,
        'printable_ratio': 0.37,
        'high_byte_ratio': 0.50
    }
    
    result = predictor.predict(firmware_features)
    print("\nFirmware prediction result:")
    print(json.dumps(result, indent=2))
    
    print("\nPrediction tests completed!")

if __name__ == "__main__":
    create_mock_models()
    test_prediction() 