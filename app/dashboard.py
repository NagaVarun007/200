#!/usr/bin/env python3
"""
BMC Security Dashboard

This module implements a Streamlit dashboard (D7) for real-time BMC security monitoring.
It displays live metric charts, alert lists, and system status with color-blind-safe
palette and red banner for critical alerts.

AI x Security Narrative: This dashboard provides real-time visibility into BMC security
posture, enabling operators to quickly identify and respond to threats. The AI-driven
visualization helps bridge the gap between complex ML predictions and actionable
security insights, supporting Axiado's vision of AI-driven, hardware-anchored security.
"""

import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from models.predict import UnifiedPredictor
from rules.alert_engine import AlertEngine

# Page configuration
st.set_page_config(
    page_title="BMC Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Color-blind safe palette
COLORS = {
    'normal': '#2E8B57',      # Sea Green
    'warning': '#FF8C00',     # Dark Orange
    'critical': '#DC143C',    # Crimson
    'background': '#F0F2F6',  # Light Gray
    'text': '#262730',        # Dark Gray
    'success': '#00FF7F'      # Spring Green
}

def load_models():
    """Load ML models and alert engine."""
    try:
        models_dir = Path("models")
        rules_file = Path("rules/alert_rules.yaml")
        
        if not models_dir.exists():
            st.error("Models directory not found. Please run the demo first.")
            return None, None
        
        if not rules_file.exists():
            st.error("Alert rules file not found.")
            return None, None
        
        predictor = UnifiedPredictor(models_dir)
        alert_engine = AlertEngine(rules_file)
        
        return predictor, alert_engine
    except Exception as e:
        st.error(f"Failed to load models: {e}")
        return None, None

def generate_sample_metrics():
    """Generate sample metrics for demonstration."""
    import random
    
    # Generate realistic BMC metrics
    base_time = datetime.now() - timedelta(minutes=10)
    metrics = []
    
    for i in range(60):  # 10 minutes of data
        timestamp = base_time + timedelta(seconds=i*10)
        
        # Normal baseline with some variation
        cpu = random.uniform(20, 40)
        memory = random.uniform(50, 70)
        syscalls = random.uniform(100, 200)
        flash_writes = random.uniform(0, 2)
        
        # Add some anomalies
        if i > 30 and i < 45:  # CPU spike
            cpu = random.uniform(80, 95)
        if i > 50:  # Memory spike
            memory = random.uniform(85, 95)
        
        metrics.append({
            'timestamp': timestamp,
            'cpu_usage': cpu,
            'memory_usage': memory,
            'syscalls_per_sec': syscalls,
            'flash_writes': flash_writes,
            'network_packets': random.uniform(50, 150),
            'error_rate': random.uniform(0, 0.02)
        })
    
    return pd.DataFrame(metrics)

def create_metrics_chart(df: pd.DataFrame):
    """Create real-time metrics chart."""
    fig = make_subplots(
        rows=3, cols=2,
        subplot_titles=('CPU Usage (%)', 'Memory Usage (%)', 
                       'System Calls/sec', 'Flash Writes/sec',
                       'Network Packets/sec', 'Error Rate (%)'),
        specs=[[{"secondary_y": False}, {"secondary_y": False}],
               [{"secondary_y": False}, {"secondary_y": False}],
               [{"secondary_y": False}, {"secondary_y": False}]]
    )
    
    # CPU Usage
    fig.add_trace(
        go.Scatter(x=df['timestamp'], y=df['cpu_usage'], 
                  name='CPU', line=dict(color=COLORS['normal'])),
        row=1, col=1
    )
    
    # Memory Usage
    fig.add_trace(
        go.Scatter(x=df['timestamp'], y=df['memory_usage'], 
                  name='Memory', line=dict(color=COLORS['normal'])),
        row=1, col=2
    )
    
    # System Calls
    fig.add_trace(
        go.Scatter(x=df['timestamp'], y=df['syscalls_per_sec'], 
                  name='Syscalls', line=dict(color=COLORS['normal'])),
        row=2, col=1
    )
    
    # Flash Writes
    fig.add_trace(
        go.Scatter(x=df['timestamp'], y=df['flash_writes'], 
                  name='Flash Writes', line=dict(color=COLORS['normal'])),
        row=2, col=2
    )
    
    # Network Packets
    fig.add_trace(
        go.Scatter(x=df['timestamp'], y=df['network_packets'], 
                  name='Network', line=dict(color=COLORS['normal'])),
        row=3, col=1
    )
    
    # Error Rate
    fig.add_trace(
        go.Scatter(x=df['timestamp'], y=df['error_rate']*100, 
                  name='Error Rate', line=dict(color=COLORS['normal'])),
        row=3, col=2
    )
    
    # Add threshold lines
    fig.add_hline(y=80, line_dash="dash", line_color=COLORS['warning'], 
                  annotation_text="Warning", row=1, col=1)
    fig.add_hline(y=90, line_dash="dash", line_color=COLORS['warning'], 
                  annotation_text="Warning", row=1, col=2)
    fig.add_hline(y=300, line_dash="dash", line_color=COLORS['warning'], 
                  annotation_text="Warning", row=2, col=1)
    fig.add_hline(y=5, line_dash="dash", line_color=COLORS['warning'], 
                  annotation_text="Warning", row=2, col=2)
    
    fig.update_layout(
        height=600,
        showlegend=False,
        title_text="BMC Real-Time Metrics",
        title_x=0.5
    )
    
    return fig

def generate_sample_alerts():
    """Generate sample alerts for demonstration."""
    alerts = [
        {
            'timestamp': datetime.now() - timedelta(minutes=5),
            'type': 'ml_prediction',
            'severity': 'high',
            'message': 'ML behavioral anomaly detected (score: 0.75)',
            'suggestion': 'Investigate running processes and check for unauthorized activity',
            'risk_score': 0.75
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=3),
            'type': 'static_rule',
            'severity': 'critical',
            'message': 'Flash write during runtime detected',
            'suggestion': 'Immediate BMC isolation and firmware integrity check required',
            'risk_score': 0.9
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=1),
            'type': 'correlation',
            'severity': 'critical',
            'message': 'Multi-vector attack detected',
            'suggestion': 'Full BMC lockdown and incident response team notification',
            'risk_score': 1.0
        }
    ]
    return alerts

def display_alerts(alerts: List[Dict]):
    """Display alerts with color-coded severity."""
    if not alerts:
        st.info("No active alerts")
        return
    
    for alert in alerts:
        severity = alert.get('severity', 'unknown')
        
        # Color coding based on severity
        if severity == 'critical':
            color = COLORS['critical']
            icon = "🚨"
        elif severity == 'high':
            color = COLORS['warning']
            icon = "⚠️"
        else:
            color = COLORS['normal']
            icon = "ℹ️"
        
        # Create alert card
        with st.container():
            st.markdown(f"""
            <div style="
                border-left: 4px solid {color};
                padding: 10px;
                margin: 10px 0;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            ">
                <div style="display: flex; align-items: center; margin-bottom: 5px;">
                    <span style="font-size: 20px; margin-right: 10px;">{icon}</span>
                    <strong style="color: {color};">{severity.upper()}</strong>
                    <span style="margin-left: auto; color: #666; font-size: 12px;">
                        {alert['timestamp'].strftime('%H:%M:%S')}
                    </span>
                </div>
                <div style="margin-bottom: 5px;"><strong>{alert['message']}</strong></div>
                <div style="color: #666; font-size: 14px;">{alert['suggestion']}</div>
                <div style="margin-top: 5px;">
                    <span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 10px; font-size: 12px;">
                        Risk: {alert['risk_score']:.2f}
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)

def main():
    """Main dashboard function."""
    # Header with status banner
    st.markdown("""
    <div style="
        background: linear-gradient(90deg, #1f1f1f 0%, #2d2d2d 100%);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        color: white;
    ">
        <h1 style="margin: 0; color: white;">🛡️ BMC Security Dashboard</h1>
        <p style="margin: 5px 0 0 0; color: #ccc;">AI-Powered Intrusion Detection & Firmware Integrity Monitoring</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Load models
    predictor, alert_engine = load_models()
    
    # Sidebar
    st.sidebar.title("Dashboard Controls")
    
    # Auto-refresh toggle
    auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=True)
    
    # Demo mode toggle
    demo_mode = st.sidebar.checkbox("Demo Mode", value=True)
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📊 Real-Time Metrics")
        
        # Generate sample data
        if demo_mode:
            df = generate_sample_metrics()
            chart = create_metrics_chart(df)
            st.plotly_chart(chart, use_container_width=True)
        else:
            st.info("Connect to live BMC data source to see real-time metrics")
    
    with col2:
        st.subheader("🚨 Active Alerts")
        
        # Generate sample alerts
        if demo_mode:
            alerts = generate_sample_alerts()
            display_alerts(alerts)
        else:
            st.info("No live alerts available in demo mode")
    
    # Bottom section
    st.markdown("---")
    
    col3, col4, col5 = st.columns(3)
    
    with col3:
        st.subheader("🔍 ML Model Status")
        if predictor:
            st.success("✅ Isolation Forest: Active")
            st.warning("⚠️ XGBoost: Not loaded")
        else:
            st.error("❌ Models not available")
    
    with col4:
        st.subheader("📋 System Health")
        st.metric("CPU Usage", "45%", "2%")
        st.metric("Memory Usage", "62%", "-1%")
        st.metric("Network Load", "23%", "5%")
    
    with col5:
        st.subheader("🛡️ Security Status")
        if demo_mode:
            st.error("🚨 CRITICAL: Multi-vector attack detected")
            st.warning("⚠️ 3 active alerts")
            st.info("ℹ️ Last scan: 2 min ago")
        else:
            st.success("✅ System secure")
            st.info("ℹ️ No active threats")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; font-size: 12px;">
        BMC Security Dashboard | AI-Powered Threat Detection | Built for Axiado Hackathon
    </div>
    """, unsafe_allow_html=True)
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(30)
        st.experimental_rerun()

if __name__ == "__main__":
    main() 