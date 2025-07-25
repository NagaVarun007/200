# 🚀 Quick Start Guide - BMC Security Pipeline

## ⚡ Get Started in 30 Seconds

```bash
# 1. Clone and setup
git clone <your-repo>
cd 200

# 2. Run the complete demo
./run_demo.sh

# 3. Start the dashboard (optional)
streamlit run app/dashboard.py
```

## 🎯 What You'll See

### Demo Output:
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

### Dashboard Features:
- 📊 Real-time BMC metrics charts
- 🚨 Color-coded security alerts
- 🎯 Risk scores and mitigation suggestions
- 🔄 Auto-refreshing data

## 🔧 If Something Goes Wrong

```bash
# Fix permissions
chmod +x run_demo.sh

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run again
./run_demo.sh
```

## 📚 Next Steps

1. **Read `flow.md`** - Complete technical guide
2. **Explore the code** - Start with `sim/bmc_metrics.py`
3. **Modify attacks** - Change attack patterns
4. **Add features** - Create new detection rules

## 🆘 Need Help?

- Check `flow.md` for detailed explanations
- Look at the troubleshooting section
- Run individual components to debug

**Happy Learning! 🛡️🤖** 