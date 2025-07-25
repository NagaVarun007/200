#!/usr/bin/env python3
"""
Firmware Feature Extractor for AnamolyzeAI

This module extracts features from firmware images for integrity verification
and anomaly detection. It computes entropy measures, compression ratios, and
byte pattern statistics that can indicate tampering or malicious modifications.

By implementing advanced firmware analysis techniques including Shannon entropy,
LZMA compression analysis, and n-gram pattern detection, this extractor supports
Axiado's "AI-driven, hardware-anchored" security vision for robust firmware
integrity validation.

Author: AnamolyzeAI Team
License: MIT
"""

import hashlib
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class FirmwareFeatureExtractor:
    """
    Extracts features from firmware images for integrity analysis.
    
    Computes entropy, compression ratios, and byte pattern statistics
    to detect potential tampering or anomalies in firmware blobs.
    """
    
    def __init__(self):
        """Initialize firmware feature extractor."""
        logger.info("Firmware Feature Extractor initialized")
    
    def _compute_shannon_entropy(self, data: bytes) -> float:
        """
        Compute Shannon entropy of firmware data.
        
        Args:
            data: Firmware binary data
            
        Returns:
            Shannon entropy value
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Compute entropy
        import math
        entropy = 0.0
        for count in byte_counts.values():
            p = count / total_bytes
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _compute_lzma_dict_len(self, data: bytes) -> int:
        """
        Estimate LZMA dictionary length by analyzing compression patterns.
        
        Args:
            data: Firmware binary data
            
        Returns:
            Estimated dictionary length
        """
        if len(data) < 1024:
            return 0
        
        # Simple heuristic: look for repeated patterns
        # This is a simplified version - real LZMA analysis would be more complex
        pattern_lengths = []
        for i in range(0, len(data) - 256, 256):
            chunk = data[i:i+256]
            # Count unique bytes in chunk
            unique_bytes = len(set(chunk))
            pattern_lengths.append(unique_bytes)
        
        if pattern_lengths:
            return sum(pattern_lengths) // len(pattern_lengths)
        return 0
    
    def _compute_ngram_high_byte_ratio(self, data: bytes, n: int = 2) -> float:
        """
        Compute ratio of high-byte n-grams (potential indicators of tampering).
        
        Args:
            data: Firmware binary data
            n: N-gram size (default: 2)
            
        Returns:
            Ratio of high-byte n-grams
        """
        if len(data) < n:
            return 0.0
        
        high_byte_count = 0
        total_ngrams = len(data) - n + 1
        
        for i in range(total_ngrams):
            ngram = data[i:i+n]
            # Check if any byte in n-gram is "high" (>= 0x80)
            if any(b >= 0x80 for b in ngram):
                high_byte_count += 1
        
        return high_byte_count / total_ngrams if total_ngrams > 0 else 0.0
    
    def _compute_byte_pattern_stats(self, data: bytes) -> Dict[str, float]:
        """
        Compute various byte pattern statistics.
        
        Args:
            data: Firmware binary data
            
        Returns:
            Dictionary of pattern statistics
        """
        if not data:
            return {}
        
        # Count zeros and ones
        zero_count = data.count(0)
        one_count = sum(1 for b in data if b == 1)
        
        # Count printable vs non-printable
        printable_count = sum(1 for b in data if 32 <= b <= 126)
        
        # Count high bytes (>= 0x80)
        high_byte_count = sum(1 for b in data if b >= 0x80)
        
        total_bytes = len(data)
        
        return {
            'zero_ratio': zero_count / total_bytes,
            'one_ratio': one_count / total_bytes,
            'printable_ratio': printable_count / total_bytes,
            'high_byte_ratio': high_byte_count / total_bytes
        }
    
    def extract_features(self, firmware_path: Path, expected_hash: Optional[str] = None) -> Dict:
        """
        Extract features from a firmware file.
        
        Args:
            firmware_path: Path to firmware file
            expected_hash: Expected SHA-256 hash for validation
            
        Returns:
            Dictionary of extracted features
        """
        logger.info(f"Extracting features from {firmware_path}")
        
        try:
            with open(firmware_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            logger.error(f"Failed to read firmware file {firmware_path}: {e}")
            return {}
        
        # Compute SHA-256 hash
        actual_hash = hashlib.sha256(data).hexdigest()
        
        # Extract features
        features = {
            'filename': firmware_path.name,
            'file_size': len(data),
            'sha256_hash': actual_hash,
            'shannon_entropy': self._compute_shannon_entropy(data),
            'lzma_dict_len': self._compute_lzma_dict_len(data),
            'bigram_high_byte_ratio': self._compute_ngram_high_byte_ratio(data, 2),
            'trigram_high_byte_ratio': self._compute_ngram_high_byte_ratio(data, 3),
            'hash_matches_expected': actual_hash == expected_hash if expected_hash else None
        }
        
        # Add byte pattern statistics
        pattern_stats = self._compute_byte_pattern_stats(data)
        features.update(pattern_stats)
        
        return features
    
    def process_firmware_directory(self, firmware_dir: Path, hashes_file: Optional[Path] = None) -> List[Dict]:
        """
        Process all firmware files in a directory.
        
        Args:
            firmware_dir: Directory containing firmware files
            hashes_file: Optional path to hashes.json file
            
        Returns:
            List of feature dictionaries
        """
        # Load expected hashes if provided
        expected_hashes = {}
        if hashes_file and hashes_file.exists():
            try:
                with open(hashes_file, 'r') as f:
                    expected_hashes = json.load(f)
                logger.info(f"Loaded {len(expected_hashes)} expected hashes")
            except Exception as e:
                logger.warning(f"Failed to load hashes file: {e}")
        
        # Process firmware files
        features_list = []
        firmware_files = list(firmware_dir.glob("*.bin"))
        
        logger.info(f"Processing {len(firmware_files)} firmware files")
        
        for firmware_file in firmware_files:
            expected_hash = expected_hashes.get(firmware_file.name)
            features = self.extract_features(firmware_file, expected_hash)
            if features:
                features_list.append(features)
        
        return features_list


def main():
    """Main entry point for firmware feature extraction CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Firmware Feature Extractor for BMC Integrity Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract features from a single firmware file
  python fw.py --firmware ./firmware/fw_clean_00.bin
  
  # Process all firmware files in a directory
  python fw.py --dir ./firmware --hashes ./firmware/hashes.json
        """
    )
    
    parser.add_argument(
        '--firmware', 
        type=str,
        help='Path to individual firmware file'
    )
    
    parser.add_argument(
        '--dir', 
        type=str,
        help='Directory containing firmware files'
    )
    
    parser.add_argument(
        '--hashes', 
        type=str,
        help='Path to hashes.json file'
    )
    
    parser.add_argument(
        '--output', 
        type=str,
        help='Output file (default: stdout)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.firmware and not args.dir:
        logger.error("Must specify either --firmware or --dir")
        sys.exit(1)
    
    # Create extractor
    extractor = FirmwareFeatureExtractor()
    
    # Process firmware
    features_list = []
    
    if args.firmware:
        # Process single file
        firmware_path = Path(args.firmware)
        if not firmware_path.exists():
            logger.error(f"Firmware file not found: {firmware_path}")
            sys.exit(1)
        
        features = extractor.extract_features(firmware_path)
        if features:
            features_list.append(features)
    
    elif args.dir:
        # Process directory
        firmware_dir = Path(args.dir)
        if not firmware_dir.exists():
            logger.error(f"Firmware directory not found: {firmware_dir}")
            sys.exit(1)
        
        hashes_file = Path(args.hashes) if args.hashes else None
        features_list = extractor.process_firmware_directory(firmware_dir, hashes_file)
    
    # Output results
    output_stream = open(args.output, 'w') if args.output else sys.stdout
    
    try:
        for features in features_list:
            print(json.dumps(features), file=output_stream)
    finally:
        if args.output:
            output_stream.close()


if __name__ == "__main__":
    main() 