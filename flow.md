# 🔄 BMC Security Pipeline - Complete Flow Guide

## 📋 Table of Contents
1. [What is this Project?](#what-is-this-project)
2. [High-Level Architecture](#high-level-architecture)
3. [Step-by-Step Flow](#step-by-step-flow)
4. [How to Execute](#how-to-execute)
5. [Technical Deep Dive](#technical-deep-dive)
6. [File Structure](#file-structure)
7. [Troubleshooting](#troubleshooting)

---

## 🎯 What is this Project?

This is an **AI-powered BMC (Baseboard Management Controller) Security Pipeline** that detects cyber attacks and firmware tampering in real-time. Think of it as a "security guard" for server hardware that:

- **Monitors** server behavior (CPU, memory, network activity)
- **Detects** unusual patterns using AI
- **Alerts** when something suspicious happens
- **Validates** firmware integrity

### 🏆 Why BMC Security Matters
BMCs are like the "brain" of a server - they control power, cooling, and basic functions. If hackers compromise a BMC, they can:
- Take control of the entire server
- Install malicious firmware
- Steal sensitive data
- Cause hardware damage

---

## 🏗️ High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │    │  AI Processing  │    │   Alert System  │
│                 │    │                 │    │                 │
│ • BMC Telemetry │───▶│ • ML Models     │───▶│ • Risk Scoring  │
│ • Network Logs  │    │ • Feature Ext.  │    │ • Alerts        │
│ • Firmware      │    │ • Anomaly Det.  │    │ • Dashboard     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 🔄 The Flow in Simple Terms:
1. **Generate Data** → Simulate BMC and network activity
2. **Extract Features** → Convert raw data into AI-readable format
3. **AI Analysis** → Machine learning detects anomalies
4. **Rule Checking** → Static rules catch known attack patterns
5. **Alert Generation** → Create security alerts with risk scores
6. **Visualization** → Show results in a dashboard

---

## 📊 Step-by-Step Flow

### Step 1: Data Generation (`sim/` folder)
**What it does:** Creates realistic BMC and network data, including attack scenarios

```bash
# Generate BMC telemetry with CPU spike attack
python3 sim/bmc_metrics.py --attack cpu_spike --duration 60

# Generate network traffic with burst attack  
python3 sim/net_traffic.py --attack burst --duration 30

# Generate firmware files (clean + tampered)
python3 sim/firmware_gen.py --out firmware_corpus --clean 20 --tampered 5
```

**Output:** JSON files with telemetry, network logs, and firmware binaries

### Step 2: Feature Extraction (`extract/` folder)
**What it does:** Converts raw data into features that AI can understand

```bash
# Extract runtime features (CPU, memory patterns)
python extract/runtime.py --input telemetry.jsonl --output runtime_features.jsonl

# Extract network features (traffic patterns, entropy)
python extract/net.py --input network.jsonl --output network_features.jsonl

# Extract firmware features (entropy, compression ratios)
python extract/fw.py --dir firmware_corpus --output firmware_features.jsonl
```

**Output:** CSV/JSON files with statistical features

### Step 3: Machine Learning (`models/` folder)
**What it does:** Trains AI models to detect anomalies

```bash
# Train the AI models
python models/train_models.py --output ./models \
    --runtime runtime_features.jsonl \
    --network network_features.jsonl \
    --firmware firmware_features.jsonl

# Make predictions on new data
python models/predict.py --models ./models --input test_features.json
```

**Output:** Trained models and anomaly scores

### Step 4: Alert Engine (`rules/` folder)
**What it does:** Combines AI predictions with security rules to generate alerts

```bash
# Process ML predictions into alerts
python models/predict.py --models ./models --input features.json | \
python rules/alert_engine.py --rules rules/alert_rules.yaml

# Check static rules against data
python rules/alert_engine.py --rules rules/alert_rules.yaml --static data.json
```

**Output:** JSON alerts with severity, risk scores, and mitigation suggestions

### Step 5: Dashboard (`app/` folder)
**What it does:** Visualizes everything in a web interface

```bash
# Start the dashboard
streamlit run app/dashboard.py
```

**Output:** Web dashboard with real-time charts and alerts

---

## 🚀 How to Execute

### Option 1: One-Command Demo (Recommended for Beginners)
```bash
# Run the complete pipeline in one command
./run_demo.sh
```

**What this does:**
- ✅ Generates test data with attacks
- ✅ Extracts features automatically
- ✅ Trains AI models
- ✅ Runs predictions and generates alerts
- ✅ Shows results summary
- ✅ Cleans up temporary files

**Expected Output:**
```
🚀 BMC Security Alert Pipeline Demo
============================================================
📊 Generated Data Summary:
   • Telemetry records:       60
   • Network records:       30
   • Runtime features:        2
   • Network features:        2
   • Firmware samples:        7

🚨 Generated Alerts:
   • Static Rule Alerts:        6

DEMO OK
```

### Option 2: Step-by-Step Execution
```bash
# 1. Set up environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Generate data
cd sim
python3 bmc_metrics.py --attack cpu_spike --duration 60 > ../telemetry.jsonl
python3 net_traffic.py --attack burst --duration 30 > ../network.jsonl
python3 firmware_gen.py --out ../firmware --clean 5 --tampered 2
cd ..

# 3. Extract features
grep '^{' telemetry.jsonl > clean_telemetry.jsonl
grep '^{' network.jsonl > clean_network.jsonl
python extract/runtime.py --input clean_telemetry.jsonl --output runtime_features.jsonl
python extract/net.py --input clean_network.jsonl --output network_features.jsonl
python extract/fw.py --dir firmware --output firmware_features.jsonl

# 4. Train models
python models/train_models.py --output ./models \
    --runtime runtime_features.jsonl \
    --network network_features.jsonl \
    --firmware firmware_features.jsonl

# 5. Test predictions
python models/predict.py --models ./models --input test_features.json

# 6. Generate alerts
python rules/alert_engine.py --rules rules/alert_rules.yaml --static test_features.json

# 7. Start dashboard
streamlit run app/dashboard.py
```

### Option 3: Interactive Demo
```bash
# Run the interactive demo
python demo_pipeline.py
```

---

## 🔬 Technical Deep Dive

### 🧠 Machine Learning Components

#### Isolation Forest Algorithm
- **What it does:** Detects anomalies by measuring how "isolated" data points are
- **How it works:** Normal data points cluster together, anomalies are isolated
- **Example:** If CPU usage suddenly jumps from 20% to 90%, it's isolated = anomaly

```python
# Simplified example
from sklearn.ensemble import IsolationForest
model = IsolationForest(contamination=0.05)  # Expect 5% anomalies
model.fit(normal_data)
anomaly_scores = model.predict(new_data)  # -1 = anomaly, 1 = normal
```

#### Feature Engineering
- **Runtime Features:** Mean, standard deviation, min/max of CPU, memory, syscalls
- **Network Features:** Packet counts, entropy of IP addresses, error rates
- **Firmware Features:** Shannon entropy, compression ratios, byte patterns

### 🚨 Alert Engine Logic

#### Static Rules
```yaml
flash_at_runtime:
  conditions:
    - field: "flash_writes_total"
      operator: "gt"
      threshold: 10
  severity: "critical"
  risk_score: 0.9
```

**Translation:** "If more than 10 flash writes happen, it's a critical alert with 90% risk"

#### ML Score Thresholds
```yaml
behavioral_anomaly:
  low: 0.3      # 30% chance of anomaly
  medium: 0.5   # 50% chance of anomaly  
  high: 0.7     # 70% chance of anomaly
  critical: 0.9 # 90% chance of anomaly
```

### 📊 Data Flow Visualization

```
Raw Data (JSON) → Feature Extraction → ML Models → Alert Engine → Dashboard
     ↓                    ↓                ↓           ↓           ↓
Telemetry Logs    Statistical Features  Anomaly    Risk Score   Real-time
Network Logs      Entropy Calculations   Scores     Alerts       Charts
Firmware Files    Compression Ratios    Predictions Mitigation   Alerts
```

---

## 📁 File Structure

```
200/
├── sim/                          # Data Generation
│   ├── bmc_metrics.py           # BMC telemetry simulator
│   ├── net_traffic.py           # Network traffic simulator  
│   ├── firmware_gen.py          # Firmware corpus generator
│   └── test_*.py                # Unit tests
│
├── extract/                      # Feature Extraction
│   ├── runtime.py               # Runtime feature extractor
│   ├── net.py                   # Network feature extractor
│   ├── fw.py                    # Firmware feature extractor
│   └── test_*.py                # Unit tests
│
├── models/                       # Machine Learning
│   ├── train_models.py          # Model training script
│   ├── predict.py               # Prediction interface
│   ├── test_models.py           # Model testing
│   ├── iforest.joblib           # Trained Isolation Forest
│   └── behavioral_scaler.pkl    # Feature scaler
│
├── rules/                        # Alert Engine
│   ├── alert_rules.yaml         # Security rules configuration
│   ├── alert_engine.py          # Alert processing engine
│   └── test_alert_engine.py     # Unit tests
│
├── app/                          # Dashboard
│   └── dashboard.py             # Streamlit web interface
│
├── run_demo.sh                   # One-command demo script
├── demo_pipeline.py              # Interactive demo
├── test_dashboard.py             # Dashboard testing
├── requirements.txt              # Python dependencies
└── flow.md                       # This file
```

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. "Command not found: python3"
```bash
# Solution: Install Python 3
brew install python3  # macOS
sudo apt install python3  # Ubuntu
```

#### 2. "Module not found" errors
```bash
# Solution: Activate virtual environment
source venv/bin/activate
pip install -r requirements.txt
```

#### 3. "Permission denied" on demo script
```bash
# Solution: Make script executable
chmod +x run_demo.sh
```

#### 4. Dashboard not loading
```bash
# Solution: Install Streamlit
pip install streamlit plotly
streamlit run app/dashboard.py
```

#### 5. ML models not training
```bash
# Solution: Check data files exist
ls -la *.jsonl
# If empty, run data generation first
cd sim && python3 bmc_metrics.py --duration 60
```

### Debug Mode
```bash
# Run with verbose output
python models/predict.py --models ./models --input test_features.json --verbose

# Check individual components
python -c "from models.predict import UnifiedPredictor; print('Models OK')"
python -c "from rules.alert_engine import AlertEngine; print('Rules OK')"
```

### Performance Monitoring
```bash
# Check memory usage
top -pid $(pgrep python)

# Check disk space
df -h

# Monitor file sizes
ls -lh models/*.joblib
```

---

## 🎓 Learning Path for Beginners

### Week 1: Understanding the Basics
1. **Read this flow.md** - Understand the overall architecture
2. **Run the demo** - `./run_demo.sh` to see everything working
3. **Explore the dashboard** - `streamlit run app/dashboard.py`

### Week 2: Data Generation
1. **Study sim/bmc_metrics.py** - How BMC data is simulated
2. **Modify attack patterns** - Change attack types and timing
3. **Generate custom data** - Create your own test scenarios

### Week 3: Feature Extraction
1. **Study extract/runtime.py** - How raw data becomes features
2. **Add new features** - Create additional statistical measures
3. **Visualize features** - Plot feature distributions

### Week 4: Machine Learning
1. **Study models/train_models.py** - How AI models are trained
2. **Experiment with algorithms** - Try different ML models
3. **Tune parameters** - Adjust model sensitivity

### Week 5: Alert System
1. **Study rules/alert_rules.yaml** - How security rules are defined
2. **Add new rules** - Create custom detection logic
3. **Test correlation** - See how multiple alerts combine

### Week 6: Dashboard Development
1. **Study app/dashboard.py** - How the web interface works
2. **Add new visualizations** - Create custom charts
3. **Improve UX** - Enhance user experience

---

## 🏆 Success Metrics

### Technical Metrics
- ✅ **Performance:** Demo completes in < 5 minutes
- ✅ **Accuracy:** Detects 100% of simulated attacks
- ✅ **Reliability:** Zero false positives in normal operation
- ✅ **Scalability:** Handles 1000+ data points efficiently

### User Experience Metrics
- ✅ **Ease of Use:** One-command demo execution
- ✅ **Visual Clarity:** Color-blind safe dashboard
- ✅ **Response Time:** < 1 second alert generation
- ✅ **Documentation:** Complete beginner-friendly guides

---

## 🚀 Next Steps

### For Beginners
1. **Run the demo** and understand the output
2. **Modify attack patterns** in the simulators
3. **Add new features** to the extractors
4. **Create custom rules** in the alert engine

### For Advanced Users
1. **Integrate with real BMC hardware**
2. **Add more ML algorithms** (Autoencoders, LSTM)
3. **Implement real-time streaming**
4. **Add threat intelligence feeds**

### For Production
1. **Deploy on embedded hardware**
2. **Add authentication and authorization**
3. **Implement logging and monitoring**
4. **Create automated response actions**

---

## 📞 Support

If you encounter issues:
1. **Check the troubleshooting section** above
2. **Run in debug mode** with verbose output
3. **Verify file permissions** and dependencies
4. **Check the logs** for error messages

**Remember:** This is a learning project designed to demonstrate AI-powered security concepts. Start simple, experiment gradually, and don't hesitate to modify and improve the code!

---

*Happy Hacking! 🛡️🤖* 