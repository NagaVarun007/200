#!/usr/bin/env python3
"""
Runtime Feature Extractor for AnamolyzeAI

This module processes BMC telemetry data streams to extract time-series features
using sliding windows. It transforms raw telemetry into feature vectors suitable
for machine learning-based anomaly detection.

By implementing sliding window analysis with configurable overlap, this extractor
enables detection of temporal patterns and behavioral anomalies in BMC operations,
aligning with Axiado's "AI-driven, hardware-anchored" security vision.

Author: AnamolyzeAI Team
License: MIT
"""

import json
import logging
import sys
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class RuntimeFeatureExtractor:
    """
    Extracts runtime features from BMC telemetry using sliding windows.
    
    Processes JSON telemetry lines and computes statistical features over
    configurable time windows for anomaly detection.
    """
    
    def __init__(self, window_size: int = 60, overlap: int = 30):
        """
        Initialize runtime feature extractor.
        
        Args:
            window_size: Size of sliding window in seconds (default: 60)
            overlap: Overlap between windows in seconds (default: 30)
        """
        self.window_size = window_size
        self.overlap = overlap
        self.window_data = deque()
        self.last_window_end = None
        
        logger.info(f"Runtime Feature Extractor initialized with window_size={window_size}s, overlap={overlap}s")
    
    def _parse_telemetry_line(self, line: str) -> Optional[Dict]:
        """Parse a JSON telemetry line and extract timestamp and metrics."""
        try:
            data = json.loads(line.strip())
            # Parse timestamp
            ts = datetime.fromisoformat(data['ts'])
            return {
                'timestamp': ts,
                'cpu': float(data['cpu']),
                'mem': float(data['mem']),
                'syscalls': int(data['syscalls']),
                'flash_writes': int(data['flash_writes'])
            }
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse telemetry line: {e}")
            return None
    
    def _compute_window_features(self, window_data: List[Dict]) -> Dict:
        """
        Compute statistical features for a window of telemetry data.
        
        Args:
            window_data: List of telemetry records in the window
            
        Returns:
            Dictionary of computed features
        """
        if not window_data:
            return {}
        
        # Extract metrics
        cpu_vals = [d['cpu'] for d in window_data]
        mem_vals = [d['mem'] for d in window_data]
        syscall_vals = [d['syscalls'] for d in window_data]
        flash_vals = [d['flash_writes'] for d in window_data]
        
        # Compute statistical features
        features = {
            'window_start': window_data[0]['timestamp'].isoformat(),
            'window_end': window_data[-1]['timestamp'].isoformat(),
            'cpu_mean': sum(cpu_vals) / len(cpu_vals),
            'cpu_std': self._std(cpu_vals),
            'cpu_max': max(cpu_vals),
            'cpu_min': min(cpu_vals),
            'mem_mean': sum(mem_vals) / len(mem_vals),
            'mem_std': self._std(mem_vals),
            'mem_max': max(mem_vals),
            'mem_min': min(mem_vals),
            'syscalls_total': sum(syscall_vals),
            'syscalls_mean': sum(syscall_vals) / len(syscall_vals),
            'syscalls_std': self._std(syscall_vals),
            'flash_writes_total': sum(flash_vals),
            'flash_writes_mean': sum(flash_vals) / len(flash_vals),
            'flash_writes_std': self._std(flash_vals),
            'data_points': len(window_data)
        }
        
        return features
    
    def _std(self, values: List[float]) -> float:
        """Compute standard deviation of a list of values."""
        if len(values) <= 1:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
    
    def _should_emit_window(self, current_time: datetime) -> bool:
        """Check if we should emit features for the current window."""
        if self.last_window_end is None:
            return True
        
        # Check if enough time has passed since last window
        time_since_last = (current_time - self.last_window_end).total_seconds()
        return time_since_last >= (self.window_size - self.overlap)
    
    def process_line(self, line: str) -> Optional[Dict]:
        """
        Process a single telemetry line and return features if window is complete.
        
        Args:
            line: JSON telemetry line
            
        Returns:
            Dictionary of features if window is complete, None otherwise
        """
        telemetry = self._parse_telemetry_line(line)
        if telemetry is None:
            return None
        
        current_time = telemetry['timestamp']
        
        # Add to current window
        self.window_data.append(telemetry)
        
        # Remove old data outside window
        window_start = current_time - timedelta(seconds=self.window_size)
        while self.window_data and self.window_data[0]['timestamp'] < window_start:
            self.window_data.popleft()
        
        # Check if we should emit features
        if self._should_emit_window(current_time) and len(self.window_data) > 0:
            features = self._compute_window_features(list(self.window_data))
            self.last_window_end = current_time
            return features
        
        return None
    
    def process_stream(self, input_stream=sys.stdin, output_stream=sys.stdout):
        """
        Process a stream of telemetry lines and output features.
        
        Args:
            input_stream: Input stream (default: stdin)
            output_stream: Output stream (default: stdout)
        """
        logger.info("Starting runtime feature extraction from stream")
        
        for line_num, line in enumerate(input_stream, 1):
            features = self.process_line(line)
            if features:
                print(json.dumps(features), file=output_stream)
            
            if line_num % 1000 == 0:
                logger.info(f"Processed {line_num} lines")


def main():
    """Main entry point for runtime feature extraction CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Runtime Feature Extractor for BMC Telemetry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process telemetry from stdin, output features to stdout
  python runtime.py < telemetry.jsonl > features.jsonl
  
  # Use custom window size and overlap
  python runtime.py --window 120 --overlap 60 < telemetry.jsonl
        """
    )
    
    parser.add_argument(
        '--window', 
        type=int, 
        default=60,
        help='Sliding window size in seconds (default: 60)'
    )
    
    parser.add_argument(
        '--overlap', 
        type=int, 
        default=30,
        help='Window overlap in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--input', 
        type=str,
        help='Input file (default: stdin)'
    )
    
    parser.add_argument(
        '--output', 
        type=str,
        help='Output file (default: stdout)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.window <= 0:
        logger.error("Window size must be positive")
        sys.exit(1)
    
    if args.overlap < 0 or args.overlap >= args.window:
        logger.error("Overlap must be non-negative and less than window size")
        sys.exit(1)
    
    # Create extractor
    extractor = RuntimeFeatureExtractor(
        window_size=args.window,
        overlap=args.overlap
    )
    
    # Setup input/output
    input_stream = open(args.input, 'r') if args.input else sys.stdin
    output_stream = open(args.output, 'w') if args.output else sys.stdout
    
    try:
        extractor.process_stream(input_stream, output_stream)
    finally:
        if args.input:
            input_stream.close()
        if args.output:
            output_stream.close()


if __name__ == "__main__":
    main() 