#!/usr/bin/env python3
"""
Unified Prediction Module for AnamolyzeAI

This module provides a unified interface for making predictions using trained
ML models. It loads Isolation Forest and XGBoost models to detect behavioral
anomalies and firmware tampering, returning structured predictions with
confidence scores and feature importance.

By providing a single prediction interface that combines behavioral and
firmware analysis, this module enables real-time threat detection and
supports Axiado's "AI-driven, hardware-anchored" security vision for
comprehensive BMC protection.

Author: AnamolyzeAI Team
License: MIT
"""

import json
import logging
import pickle
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class UnifiedPredictor:
    """
    Unified predictor for BMC anomaly detection and firmware integrity verification.
    
    Loads trained models and provides a single interface for making predictions
    on behavioral and firmware data with confidence scores and feature importance.
    """
    
    def __init__(self, models_dir: Path):
        """
        Initialize unified predictor.
        
        Args:
            models_dir: Directory containing trained models
        """
        self.models_dir = models_dir
        self.models_loaded = False
        
        # Model objects
        self.iforest_model = None
        self.xgb_model = None
        self.behavioral_scaler = None
        self.firmware_scaler = None
        
        # Feature names for importance analysis
        self.behavioral_features = [
            'cpu_mean', 'cpu_std', 'cpu_max', 'cpu_min',
            'mem_mean', 'mem_std', 'mem_max', 'mem_min',
            'syscalls_total', 'syscalls_mean', 'syscalls_std',
            'flash_writes_total', 'flash_writes_mean', 'flash_writes_std',
            'total_packets', 'total_errors', 'error_rate',
            'unique_src_ips', 'unique_dst_ips', 'unique_protocols',
            'src_ip_entropy', 'dst_ip_entropy', 'protocol_entropy',
            'max_dst_packets', 'avg_packets_per_flow',
            'tcp_count', 'udp_count', 'icmp_count'
        ]
        
        self.firmware_features = [
            'file_size', 'shannon_entropy', 'lzma_dict_len',
            'bigram_high_byte_ratio', 'trigram_high_byte_ratio',
            'zero_ratio', 'one_ratio', 'printable_ratio', 'high_byte_ratio'
        ]
        
        logger.info(f"Unified Predictor initialized with models directory: {models_dir}")
    
    def load_models(self) -> bool:
        """
        Load trained models from disk.
        
        Returns:
            True if all models loaded successfully, False otherwise
        """
        try:
            # Load Isolation Forest
            iforest_path = self.models_dir / "iforest.joblib"
            if iforest_path.exists():
                self.iforest_model = joblib.load(iforest_path)
                logger.info("Isolation Forest model loaded")
            else:
                logger.warning("Isolation Forest model not found")
            
            # Load XGBoost
            xgb_path = self.models_dir / "firmware_xgb.pkl"
            if xgb_path.exists():
                with open(xgb_path, 'rb') as f:
                    self.xgb_model = pickle.load(f)
                logger.info("XGBoost model loaded")
            else:
                logger.warning("XGBoost model not found")
            
            # Load scalers
            behavioral_scaler_path = self.models_dir / "behavioral_scaler.pkl"
            if behavioral_scaler_path.exists():
                with open(behavioral_scaler_path, 'rb') as f:
                    self.behavioral_scaler = pickle.load(f)
                logger.info("Behavioral scaler loaded")
            
            firmware_scaler_path = self.models_dir / "firmware_scaler.pkl"
            if firmware_scaler_path.exists():
                with open(firmware_scaler_path, 'rb') as f:
                    self.firmware_scaler = pickle.load(f)
                logger.info("Firmware scaler loaded")
            
            self.models_loaded = True
            logger.info("All models loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False
    
    def _get_top_features(self, feature_importance: np.ndarray, feature_names: List[str], top_n: int = 5) -> List[Dict]:
        """
        Get top features by importance.
        
        Args:
            feature_importance: Feature importance scores
            feature_names: List of feature names
            top_n: Number of top features to return
            
        Returns:
            List of top feature dictionaries
        """
        if len(feature_importance) != len(feature_names):
            return []
        
        # Get indices of top features
        top_indices = np.argsort(feature_importance)[-top_n:][::-1]
        
        top_features = []
        for idx in top_indices:
            top_features.append({
                'feature': feature_names[idx],
                'importance': float(feature_importance[idx])
            })
        
        return top_features
    
    def _predict_behavioral_anomaly(self, features: Dict) -> Dict:
        """
        Predict behavioral anomaly using Isolation Forest.
        
        Args:
            features: Dictionary of behavioral features
            
        Returns:
            Prediction result dictionary
        """
        if self.iforest_model is None:
            return {
                'type': 'behavioral',
                'score': 0.0,
                'severity': 'unknown',
                'top_feats': [],
                'error': 'Model not loaded'
            }
        
        try:
            # Extract features in correct order
            feature_vector = []
            for feature_name in self.behavioral_features:
                feature_vector.append(features.get(feature_name, 0.0))
            
            feature_array = np.array(feature_vector).reshape(1, -1)
            
            # Scale features
            if self.behavioral_scaler:
                feature_array = self.behavioral_scaler.transform(feature_array)
            
            # Make prediction
            start_time = time.time()
            anomaly_score = self.iforest_model.score_samples(feature_array)[0]
            prediction = self.iforest_model.predict(feature_array)[0]
            inference_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # Convert to anomaly score (higher = more anomalous)
            anomaly_score = -anomaly_score  # Invert so higher = more anomalous
            
            # Determine severity
            if anomaly_score > 0.8:
                severity = 'critical'
            elif anomaly_score > 0.6:
                severity = 'high'
            elif anomaly_score > 0.4:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Get feature importance (simplified - use feature values as proxy)
            feature_importance = np.abs(feature_array[0])
            top_features = self._get_top_features(feature_importance, self.behavioral_features)
            
            return {
                'type': 'behavioral',
                'score': float(anomaly_score),
                'severity': severity,
                'top_feats': top_features,
                'inference_time_ms': inference_time,
                'is_anomaly': bool(prediction == -1)
            }
            
        except Exception as e:
            logger.error(f"Behavioral prediction failed: {e}")
            return {
                'type': 'behavioral',
                'score': 0.0,
                'severity': 'unknown',
                'top_feats': [],
                'error': str(e)
            }
    
    def _predict_firmware_integrity(self, features: Dict) -> Dict:
        """
        Predict firmware integrity using XGBoost.
        
        Args:
            features: Dictionary of firmware features
            
        Returns:
            Prediction result dictionary
        """
        if self.xgb_model is None:
            return {
                'type': 'firmware',
                'score': 0.0,
                'severity': 'unknown',
                'top_feats': [],
                'error': 'Model not loaded'
            }
        
        try:
            # Extract features in correct order
            feature_vector = []
            for feature_name in self.firmware_features:
                feature_vector.append(features.get(feature_name, 0.0))
            
            feature_array = np.array(feature_vector).reshape(1, -1)
            
            # Scale features
            if self.firmware_scaler:
                feature_array = self.firmware_scaler.transform(feature_array)
            
            # Make prediction
            start_time = time.time()
            tamper_prob = self.xgb_model.predict_proba(feature_array)[0][1]  # Probability of tampering
            prediction = self.xgb_model.predict(feature_array)[0]
            inference_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # Determine severity
            if tamper_prob > 0.8:
                severity = 'critical'
            elif tamper_prob > 0.6:
                severity = 'high'
            elif tamper_prob > 0.4:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Get feature importance
            feature_importance = self.xgb_model.feature_importances_
            top_features = self._get_top_features(feature_importance, self.firmware_features)
            
            return {
                'type': 'firmware',
                'score': float(tamper_prob),
                'severity': severity,
                'top_feats': top_features,
                'inference_time_ms': inference_time,
                'is_tampered': bool(prediction == 1)
            }
            
        except Exception as e:
            logger.error(f"Firmware prediction failed: {e}")
            return {
                'type': 'firmware',
                'score': 0.0,
                'severity': 'unknown',
                'top_feats': [],
                'error': str(e)
            }
    
    def predict(self, feature_row: Dict) -> Dict:
        """
        Unified prediction function that returns JSON with timestamp, type, score, severity, top_feats.
        
        Args:
            feature_row: Dictionary containing features for prediction
            
        Returns:
            Dictionary with prediction results
        """
        # Ensure models are loaded
        if not self.models_loaded:
            if not self.load_models():
                return {
                    'timestamp': datetime.now().isoformat(),
                    'error': 'Failed to load models'
                }
        
        # Determine prediction type based on available features
        has_behavioral = any(feat in feature_row for feat in self.behavioral_features[:5])  # Check first few
        has_firmware = any(feat in feature_row for feat in self.firmware_features[:3])  # Check first few
        
        result = {
            'timestamp': datetime.now().isoformat()
        }
        
        # Make predictions based on available features
        if has_behavioral:
            behavioral_result = self._predict_behavioral_anomaly(feature_row)
            result.update(behavioral_result)
        
        if has_firmware:
            firmware_result = self._predict_firmware_integrity(feature_row)
            # If we already have behavioral results, create separate entry
            if has_behavioral:
                result['firmware'] = firmware_result
            else:
                result.update(firmware_result)
        
        if not has_behavioral and not has_firmware:
            result['error'] = 'No recognizable features found'
        
        return result


def main():
    """Main entry point for unified prediction CLI."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(
        description="Unified Predictor for AnamolyzeAI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Predict from JSON input
  echo '{"cpu_mean": 25.5, "mem_mean": 60.2}' | python predict.py --models ./models
  
  # Predict from file
  python predict.py --models ./models --input features.json
        """
    )
    
    parser.add_argument(
        '--models', 
        type=str, 
        required=True,
        help='Directory containing trained models'
    )
    
    parser.add_argument(
        '--input', 
        type=str,
        help='Input JSON file (default: stdin)'
    )
    
    args = parser.parse_args()
    
    # Validate models directory
    models_dir = Path(args.models)
    if not models_dir.exists():
        logger.error(f"Models directory not found: {models_dir}")
        sys.exit(1)
    
    # Create predictor
    predictor = UnifiedPredictor(models_dir)
    
    # Load models
    if not predictor.load_models():
        logger.error("Failed to load models")
        sys.exit(1)
    
    # Process input
    if args.input:
        with open(args.input, 'r') as f:
            feature_row = json.load(f)
    else:
        # Read from stdin
        feature_row = json.loads(sys.stdin.read())
    
    # Make prediction
    result = predictor.predict(feature_row)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main() 