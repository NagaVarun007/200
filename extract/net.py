#!/usr/bin/env python3
"""
Network Feature Extractor for AnamolyzeAI

This module processes network traffic logs to extract per-minute aggregated
features for anomaly detection. It computes flow statistics, entropy measures,
and traffic patterns that can indicate malicious activity.

By implementing temporal aggregation and statistical analysis of network flows,
this extractor enables detection of network-based attacks and anomalous
communication patterns, supporting Axiado's "AI-driven, hardware-anchored"
security vision.

Author: AnamolyzeAI Team
License: MIT
"""

import json
import logging
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class NetworkFeatureExtractor:
    """
    Extracts network features from traffic logs using per-minute aggregation.
    
    Processes JSON network log lines and computes aggregated features over
    one-minute windows for anomaly detection.
    """
    
    def __init__(self, aggregation_window: int = 60):
        """
        Initialize network feature extractor.
        
        Args:
            aggregation_window: Aggregation window in seconds (default: 60)
        """
        self.aggregation_window = aggregation_window
        self.current_window_data = []
        self.current_window_start = None
        
        logger.info(f"Network Feature Extractor initialized with aggregation_window={aggregation_window}s")
    
    def _parse_network_line(self, line: str) -> Optional[Dict]:
        """Parse a JSON network log line and extract timestamp and metrics."""
        try:
            data = json.loads(line.strip())
            # Parse timestamp
            ts = datetime.fromisoformat(data['ts'])
            return {
                'timestamp': ts,
                'src_ip': data['src_ip'],
                'dst_ip': data['dst_ip'],
                'protocol': data['protocol'],
                'pkt_count': int(data['pkt_count']),
                'error_count': int(data['error_count'])
            }
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse network line: {e}")
            return None
    
    def _compute_entropy(self, values: List[str]) -> float:
        """Compute Shannon entropy of a list of values."""
        if not values:
            return 0.0
        
        # Count frequencies
        counter = Counter(values)
        total = len(values)
        
        # Compute entropy
        import math
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _compute_window_features(self, window_data: List[Dict]) -> Dict:
        """
        Compute aggregated features for a window of network data.
        
        Args:
            window_data: List of network records in the window
            
        Returns:
            Dictionary of computed features
        """
        if not window_data:
            return {}
        
        # Extract basic metrics
        pkt_counts = [d['pkt_count'] for d in window_data]
        error_counts = [d['error_count'] for d in window_data]
        protocols = [d['protocol'] for d in window_data]
        src_ips = [d['src_ip'] for d in window_data]
        dst_ips = [d['dst_ip'] for d in window_data]
        
        # Compute flow statistics
        unique_src_ips = set(src_ips)
        unique_dst_ips = set(dst_ips)
        unique_protocols = set(protocols)
        
        # Compute entropy measures
        src_ip_entropy = self._compute_entropy(src_ips)
        dst_ip_entropy = self._compute_entropy(dst_ips)
        protocol_entropy = self._compute_entropy(protocols)
        
        # Compute packet statistics
        total_packets = sum(pkt_counts)
        total_errors = sum(error_counts)
        
        # Identify high-volume destinations (potential DDoS targets)
        dst_ip_counts = Counter(dst_ips)
        max_dst_packets = max(dst_ip_counts.values()) if dst_ip_counts else 0
        
        # Compute features
        features = {
            'window_start': window_data[0]['timestamp'].isoformat(),
            'window_end': window_data[-1]['timestamp'].isoformat(),
            'total_packets': total_packets,
            'total_errors': total_errors,
            'error_rate': total_errors / total_packets if total_packets > 0 else 0.0,
            'unique_src_ips': len(unique_src_ips),
            'unique_dst_ips': len(unique_dst_ips),
            'unique_protocols': len(unique_protocols),
            'src_ip_entropy': src_ip_entropy,
            'dst_ip_entropy': dst_ip_entropy,
            'protocol_entropy': protocol_entropy,
            'max_dst_packets': max_dst_packets,
            'avg_packets_per_flow': total_packets / len(window_data) if window_data else 0.0,
            'tcp_count': protocols.count('TCP'),
            'udp_count': protocols.count('UDP'),
            'icmp_count': protocols.count('ICMP'),
            'data_points': len(window_data)
        }
        
        return features
    
    def _get_window_start(self, timestamp: datetime) -> datetime:
        """Get the start of the aggregation window for a given timestamp."""
        # Round down to the nearest minute
        return timestamp.replace(second=0, microsecond=0)
    
    def process_line(self, line: str) -> Optional[Dict]:
        """
        Process a single network log line and return features if window is complete.
        
        Args:
            line: JSON network log line
            
        Returns:
            Dictionary of features if window is complete, None otherwise
        """
        network_data = self._parse_network_line(line)
        if network_data is None:
            return None
        
        current_time = network_data['timestamp']
        window_start = self._get_window_start(current_time)
        
        # Check if we need to emit features for a previous window
        features = None
        if (self.current_window_start is not None and 
            window_start > self.current_window_start):
            features = self._compute_window_features(self.current_window_data)
            self.current_window_data = []
        
        # Add to current window
        self.current_window_data.append(network_data)
        self.current_window_start = window_start
        
        return features
    
    def process_stream(self, input_stream=sys.stdin, output_stream=sys.stdout):
        """
        Process a stream of network log lines and output features.
        
        Args:
            input_stream: Input stream (default: stdin)
            output_stream: Output stream (default: stdout)
        """
        logger.info("Starting network feature extraction from stream")
        
        for line_num, line in enumerate(input_stream, 1):
            features = self.process_line(line)
            if features:
                print(json.dumps(features), file=output_stream)
            
            if line_num % 1000 == 0:
                logger.info(f"Processed {line_num} lines")
        
        # Emit final window if there's data
        if self.current_window_data:
            features = self._compute_window_features(self.current_window_data)
            print(json.dumps(features), file=output_stream)


def main():
    """Main entry point for network feature extraction CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Network Feature Extractor for BMC Traffic Logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process network logs from stdin, output features to stdout
  python net.py < network.jsonl > net_features.jsonl
  
  # Use custom aggregation window
  python net.py --window 120 < network.jsonl
        """
    )
    
    parser.add_argument(
        '--window', 
        type=int, 
        default=60,
        help='Aggregation window in seconds (default: 60)'
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
        logger.error("Aggregation window must be positive")
        sys.exit(1)
    
    # Create extractor
    extractor = NetworkFeatureExtractor(
        aggregation_window=args.window
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