#!/usr/bin/env python3
"""
Test script for dashboard components
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent))

from app.dashboard import generate_sample_metrics, generate_sample_alerts, create_metrics_chart

def test_dashboard_components():
    """Test dashboard components."""
    print("🧪 Testing Dashboard Components")
    print("=" * 40)
    
    # Test metrics generation
    print("1. Testing metrics generation...")
    df = generate_sample_metrics()
    print(f"   ✅ Generated {len(df)} metrics records")
    print(f"   ✅ Columns: {list(df.columns)}")
    
    # Test chart creation
    print("2. Testing chart creation...")
    chart = create_metrics_chart(df)
    print(f"   ✅ Chart created successfully")
    print(f"   ✅ Chart type: {type(chart)}")
    
    # Test alerts generation
    print("3. Testing alerts generation...")
    alerts = generate_sample_alerts()
    print(f"   ✅ Generated {len(alerts)} sample alerts")
    
    for i, alert in enumerate(alerts, 1):
        print(f"   Alert {i}: {alert['severity']} - {alert['message'][:50]}...")
    
    print("\n🎉 All dashboard components working correctly!")
    print("Dashboard is ready to run with: streamlit run app/dashboard.py")

if __name__ == "__main__":
    test_dashboard_components() 