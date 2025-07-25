#!/usr/bin/env python3
"""
ML Model Trainer for AnamolyzeAI

This module trains machine learning models for anomaly detection and firmware
integrity verification. It implements Isolation Forest for behavioral anomaly
detection and XGBoost for firmware classification.

By training models on simulated data that includes both normal and adversarial
patterns, this trainer enables AI-driven detection of BMC security threats,
aligning with Axiado's "AI-driven, hardware-anchored" security vision.

Author: AnamolyzeAI Team
License: MIT
"""

import json
import logging
import pickle
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class ModelTrainer:
    """
    Trains ML models for BMC anomaly detection and firmware integrity verification.
    
    Implements Isolation Forest for behavioral anomaly detection and XGBoost
    for firmware classification with proper model serialization.
    """
    
    def __init__(self, output_dir: Path):
        """
        Initialize model trainer.
        
        Args:
            output_dir: Directory to save trained models
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Model configurations
        self.iforest_config = {
            'contamination': 0.05,
            'random_state': 42,
            'n_estimators': 100
        }
        
        self.xgb_config = {
            'objective': 'binary:logistic',
            'eval_metric': 'logloss',
            'random_state': 42,
            'n_estimators': 100,
            'max_depth': 6
        }
        
        logger.info(f"Model Trainer initialized with output directory: {output_dir}")
    
    def load_runtime_features(self, features_file: Path) -> pd.DataFrame:
        """
        Load runtime features from JSON lines file.
        
        Args:
            features_file: Path to runtime features file
            
        Returns:
            DataFrame with runtime features
        """
        logger.info(f"Loading runtime features from {features_file}")
        
        features_list = []
        with open(features_file, 'r') as f:
            for line in f:
                features_list.append(json.loads(line.strip()))
        
        df = pd.DataFrame(features_list)
        logger.info(f"Loaded {len(df)} runtime feature samples")
        return df
    
    def load_network_features(self, features_file: Path) -> pd.DataFrame:
        """
        Load network features from JSON lines file.
        
        Args:
            features_file: Path to network features file
            
        Returns:
            DataFrame with network features
        """
        logger.info(f"Loading network features from {features_file}")
        
        features_list = []
        with open(features_file, 'r') as f:
            for line in f:
                features_list.append(json.loads(line.strip()))
        
        df = pd.DataFrame(features_list)
        logger.info(f"Loaded {len(df)} network feature samples")
        return df
    
    def load_firmware_features(self, features_file: Path) -> pd.DataFrame:
        """
        Load firmware features from JSON lines file.
        
        Args:
            features_file: Path to firmware features file
            
        Returns:
            DataFrame with firmware features and labels
        """
        logger.info(f"Loading firmware features from {features_file}")
        
        features_list = []
        with open(features_file, 'r') as f:
            for line in f:
                features_list.append(json.loads(line.strip()))
        
        df = pd.DataFrame(features_list)
        
        # Create labels: 0 for clean, 1 for tampered
        df['label'] = df['filename'].str.contains('tampered').astype(int)
        
        logger.info(f"Loaded {len(df)} firmware samples ({df['label'].sum()} tampered)")
        return df
    
    def prepare_behavioral_features(self, runtime_df: pd.DataFrame, network_df: pd.DataFrame) -> np.ndarray:
        """
        Prepare combined behavioral features for anomaly detection.
        
        Args:
            runtime_df: Runtime features DataFrame
            network_df: Network features DataFrame
            
        Returns:
            Combined feature matrix
        """
        logger.info("Preparing combined behavioral features")
        
        # Select numerical features (exclude timestamps and metadata)
        runtime_features = [
            'cpu_mean', 'cpu_std', 'cpu_max', 'cpu_min',
            'mem_mean', 'mem_std', 'mem_max', 'mem_min',
            'syscalls_total', 'syscalls_mean', 'syscalls_std',
            'flash_writes_total', 'flash_writes_mean', 'flash_writes_std'
        ]
        
        network_features = [
            'total_packets', 'total_errors', 'error_rate',
            'unique_src_ips', 'unique_dst_ips', 'unique_protocols',
            'src_ip_entropy', 'dst_ip_entropy', 'protocol_entropy',
            'max_dst_packets', 'avg_packets_per_flow',
            'tcp_count', 'udp_count', 'icmp_count'
        ]
        
        # Combine features (use the shorter dataset length)
        min_length = min(len(runtime_df), len(network_df))
        
        runtime_data = runtime_df[runtime_features].iloc[:min_length].values
        network_data = network_df[network_features].iloc[:min_length].values
        
        combined_features = np.hstack([runtime_data, network_data])
        
        # Handle NaN values
        combined_features = np.nan_to_num(combined_features, nan=0.0)
        
        logger.info(f"Prepared {combined_features.shape[0]} behavioral feature samples")
        return combined_features
    
    def prepare_firmware_features(self, firmware_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare firmware features for classification.
        
        Args:
            firmware_df: Firmware features DataFrame
            
        Returns:
            Tuple of (features, labels)
        """
        logger.info("Preparing firmware features for classification")
        
        # Select numerical features
        feature_columns = [
            'file_size', 'shannon_entropy', 'lzma_dict_len',
            'bigram_high_byte_ratio', 'trigram_high_byte_ratio',
            'zero_ratio', 'one_ratio', 'printable_ratio', 'high_byte_ratio'
        ]
        
        features = firmware_df[feature_columns].values
        labels = firmware_df['label'].values
        
        # Handle NaN values
        features = np.nan_to_num(features, nan=0.0)
        
        logger.info(f"Prepared {len(features)} firmware samples for classification")
        return features, labels
    
    def train_isolation_forest(self, features: np.ndarray) -> IsolationForest:
        """
        Train Isolation Forest for behavioral anomaly detection.
        
        Args:
            features: Behavioral feature matrix
            
        Returns:
            Trained Isolation Forest model
        """
        logger.info("Training Isolation Forest for behavioral anomaly detection")
        
        # Scale features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Train model
        model = IsolationForest(**self.iforest_config)
        model.fit(features_scaled)
        
        # Save scaler
        scaler_path = self.output_dir / "behavioral_scaler.pkl"
        with open(scaler_path, 'wb') as f:
            pickle.dump(scaler, f)
        
        logger.info(f"Isolation Forest trained and scaler saved to {scaler_path}")
        return model
    
    def train_xgboost_firmware(self, features: np.ndarray, labels: np.ndarray) -> xgb.XGBClassifier:
        """
        Train XGBoost for firmware classification.
        
        Args:
            features: Firmware feature matrix
            labels: Binary labels (0=clean, 1=tampered)
            
        Returns:
            Trained XGBoost model
        """
        logger.info("Training XGBoost for firmware classification")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        model = xgb.XGBClassifier(**self.xgb_config)
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        train_score = model.score(X_train_scaled, y_train)
        test_score = model.score(X_test_scaled, y_test)
        
        logger.info(f"XGBoost trained - Train accuracy: {train_score:.3f}, Test accuracy: {test_score:.3f}")
        
        # Save scaler
        scaler_path = self.output_dir / "firmware_scaler.pkl"
        with open(scaler_path, 'wb') as f:
            pickle.dump(scaler, f)
        
        logger.info(f"XGBoost model and scaler saved to {scaler_path}")
        return model
    
    def save_model(self, model, filename: str) -> Path:
        """
        Save trained model to file.
        
        Args:
            model: Trained model object
            filename: Output filename
            
        Returns:
            Path to saved model file
        """
        model_path = self.output_dir / filename
        
        if filename.endswith('.joblib'):
            import joblib
            joblib.dump(model, model_path)
        elif filename.endswith('.pkl'):
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
        else:
            raise ValueError(f"Unsupported file format: {filename}")
        
        # Check file size
        file_size_mb = model_path.stat().st_size / (1024 * 1024)
        logger.info(f"Model saved to {model_path} ({file_size_mb:.2f} MB)")
        
        if file_size_mb > 1.0:
            logger.warning(f"Model file size ({file_size_mb:.2f} MB) exceeds 1 MB limit")
        
        return model_path
    
    def train_all_models(self, 
                        runtime_features: Path,
                        network_features: Path,
                        firmware_features: Path) -> Dict[str, Path]:
        """
        Train all models and save them.
        
        Args:
            runtime_features: Path to runtime features file
            network_features: Path to network features file
            firmware_features: Path to firmware features file
            
        Returns:
            Dictionary mapping model names to file paths
        """
        logger.info("Starting training of all models")
        
        # Load data
        runtime_df = self.load_runtime_features(runtime_features)
        network_df = self.load_network_features(network_features)
        firmware_df = self.load_firmware_features(firmware_features)
        
        # Train behavioral model (Isolation Forest)
        behavioral_features = self.prepare_behavioral_features(runtime_df, network_df)
        iforest_model = self.train_isolation_forest(behavioral_features)
        iforest_path = self.save_model(iforest_model, "iforest.joblib")
        
        # Train firmware model (XGBoost)
        firmware_features_matrix, firmware_labels = self.prepare_firmware_features(firmware_df)
        xgb_model = self.train_xgboost_firmware(firmware_features_matrix, firmware_labels)
        xgb_path = self.save_model(xgb_model, "firmware_xgb.pkl")
        
        logger.info("All models trained successfully")
        
        return {
            'isolation_forest': iforest_path,
            'firmware_xgb': xgb_path
        }


def main():
    """Main entry point for model training CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ML Model Trainer for AnamolyzeAI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train all models with default feature files
  python train_models.py --output ./models
  
  # Train with custom feature files
  python train_models.py --output ./models \\
    --runtime runtime_features.jsonl \\
    --network network_features.jsonl \\
    --firmware firmware_features.jsonl
        """
    )
    
    parser.add_argument(
        '--output', 
        type=str, 
        required=True,
        help='Output directory for trained models'
    )
    
    parser.add_argument(
        '--runtime', 
        type=str, 
        default='runtime_features.jsonl',
        help='Runtime features file (default: runtime_features.jsonl)'
    )
    
    parser.add_argument(
        '--network', 
        type=str, 
        default='network_features.jsonl',
        help='Network features file (default: network_features.jsonl)'
    )
    
    parser.add_argument(
        '--firmware', 
        type=str, 
        default='firmware_features.jsonl',
        help='Firmware features file (default: firmware_features.jsonl)'
    )
    
    args = parser.parse_args()
    
    # Validate input files
    for feature_file in [args.runtime, args.network, args.firmware]:
        if not Path(feature_file).exists():
            logger.error(f"Feature file not found: {feature_file}")
            sys.exit(1)
    
    # Create trainer and train models
    trainer = ModelTrainer(Path(args.output))
    
    try:
        model_paths = trainer.train_all_models(
            runtime_features=Path(args.runtime),
            network_features=Path(args.network),
            firmware_features=Path(args.firmware)
        )
        
        logger.info("Training completed successfully!")
        for model_name, model_path in model_paths.items():
            logger.info(f"{model_name}: {model_path}")
            
    except Exception as e:
        logger.error(f"Training failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 