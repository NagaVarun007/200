# 📜 PROJECT BRIEF  –  AnamolyzeAI
# 3-Day Axiado Hackathon  |  Focus Track: Security & Integrity
# ------------------------------------------------------------
# DO NOT REWRITE THIS SECTION – read it, then start generating code, tests,
# and documentation that satisfy every line below.

################################################################################
1. HIGH-LEVEL GOAL
################################################################################
Build, in STRICTLY three (3) calendar days, an **AI-powered intrusion- and
firmware-tamper-detection pipeline for BMCs** that runs entirely in simulation
(no real hardware) but is architected for future deployment on Axiado’s
AX-series Trusted Control Unit (TCU).

The system must:
•  Stream **simulated BMC telemetry** (CPU, Memory, Syscalls, Flash events).  
•  Stream **simulated network logs** (flows, packet bursts, TLS errors).  
•  Accept **firmware images** and validate integrity (SHA-256 **AND** ML entropy check).  
•  Run an **Autoencoder or Isolation Forest** to flag behavioural anomalies.  
•  Correlate findings → raise alerts with **risk score + mitigation hint**.  
•  Log or dashboard every event; show a CLEAR demo of anomaly → alert.

################################################################################
2. KEY DELIVERABLES  (ABSOLUTE – JUDGES’ CHECKLIST)
################################################################################
| ID | Artifact                               | Notes & Acceptance Tests                              |
|----|----------------------------------------|-------------------------------------------------------|
| D1 | `sim/`                                 | `bmc_metrics.py`, `net_traffic.py`, `firmware_gen.py` |
| D2 | `data/`                                | At least 10 min normal logs + 3 scripted attacks.     |
| D3 | `extract/`                             | `runtime.py`, `net.py`, `fw.py` → write **features.csv** |
| D4 | `models/`                              | `ae_runtime.pth` **OR** `iforest.joblib`, plus entropy/XGB model |
| D5 | `models/predict.py`                    | Unified `predict(feature_row)` → JSON (timestamp, type, score, severity, top_feats) |
| D6 | `rules/alert_rules.yaml`               | 2+ static rules (flash-at-runtime, SHA mismatch)      |
| D7 | `app/dashboard.py` (OPTIONAL)          | Streamlit or Flask; must show live metric chart + alert list |
| D8 | `run_demo.sh`                          | One-command demo; exits 0 after <5 min; prints “DEMO OK” |
| D9 | `README.md`                            | Install, run, expected output GIF, team roles, future work |
| D10| `report.pdf`                           | 2-page architecture + mapping to Axiado judging rubric |
| D11| `demo.mp4` (≤ 3 min)                   | Shows normal → attack → alert; uploaded link in README |

Failure to ship **any** D-artifact by **Jul 26 23:59 PDT** will cost points.

################################################################################
3. FUNCTIONAL REQUIREMENTS
################################################################################
[F-1] **Telemetry Generator**  
   – Emits JSON lines every second: `ts, cpu, mem, syscalls, flash_writes`.  
   – CLI flags: `--attack <type> --start <sec> --duration <sec>`.

[F-2] **Network Simulator**  
   – Uses Scapy or handcrafted logs.  
   – Must support at least two attack patterns:  
     a) `burst` (>100 pkts sec⁻¹ to new IP)  
     b) `c2` (repeated small packets to single external IP).

[F-3] **Firmware Corpus**  
   – 20 clean blobs (16 MiB each, random bytes).  
   – 5 tampered blobs (pad injection, gzip bomb, byte-flip).  
   – `hashes.json` = filename → SHA-256.

[F-4] **Feature Extraction**  
   – Runtime sliding window = 60 s, overlap 30 s.  
   – Network per-minute aggregation.  
   – Firmware: entropy (Shannon), LZMA dict len, n-gram ratio high-byte.

[F-5] **ML Models**  
   – Behaviour: Autoencoder **OR** Isolation Forest (contamination ≤ 0.05).  
   – Firmware: Entropy + XGBoost (binary).  
   – All models serialised < 1 MB; inference ≤ 10 ms / sample on laptop.

[F-6] **Alerting Engine**  
   – Inputs: ML score + rules.  
   – Output JSON line: `ts, severity, component, msg, suggestion`.

[F-7] **Dashboard** *(optional but +UX points)*  
   – Real-time charts (<1 s refresh).  
   – Colour-blind-safe palette.  
   – Banner turns RED on Critical.

################################################################################
4. NON-FUNCTIONAL / “STRESSABLE” POINTS (EMPHASISE IN CODE & REPORT)
################################################################################
[NF-1] **AI × Security Narrative** – every module docstring must mention how it
improves BMC security and aligns with Axiado’s “AI-driven, hardware-anchored”
vision.

[NF-2] **Performance Footprint** – keep RAM usage < 300 MB, CPU < 30 %.  
Add `perf_note.md` with `time` + `memory_profiler` stats.

[NF-3] **Extensibility** – code should expose clear interfaces so a future
AX3080 NNP backend or Redfish live feed can replace the simulators without
major rewrites.

[NF-4] **Clarity for Judges** – inline comments, type hints (`mypy --strict`
clean), log messages English and concise.

################################################################################
5. 72-HOUR TASK BREAKDOWN  (DEFAULT OWNERS, CAN SWAP)
################################################################################
Day 1 AM (0-6 h)  →  Repo setup, generators skeleton  (Sandeep + Dilip)  
Day 1 PM (6-12 h) →  Feature extractors + raw CSV     (Varun)  
Day 1 EOD (12 h)   →  **OUTLINE.md** push – meets handbook design deadline.  
Day 2 AM (12-20 h) →  Train Isolation Forest & AE     (Sandeep)  
Day 2 PM (20-30 h) →  SHA check + entropy model       (Dilip)  
Day 2 EOD (30 h)   →  **UPDATE.md** push – list working modules.  
Day 3 AM (30-42 h) →  Rules engine + predictor wrap   (Varun)  
Day 3 Mid (42-48 h)->  Dashboard + run_demo.sh        (Anyone)  
Day 3 EOD (48-60 h)->  Polish, tests, perf_note       (All)  
Jul 26 23:59 PDT    →  Final code/doc push & video.  
Jul 27 09:00 PDT    →  Upload PDF + YouTube link.

################################################################################
6. CODING GUIDELINES
################################################################################
• Python 3.11, black formatting, isort, flake8 strict.  
• Use `logging` (level = INFO) not print.  
• Provide at least **3 unit tests per module** (`pytest`).  
• Avoid heavy dependencies; ONLY scikit-learn, PyTorch, XGBoost allowed for ML.  
• No private data; everything generated or from open datasets.

################################################################################
7. STRETCH GOALS (ONLY IF CORE DONE)
################################################################################
[S-1] Explainability: SHAP top-n feature list in alert JSON.  
[S-2] Streamlit panel: “Why flagged?” expandable section.  
[S-3] Sigstore/Rekor lookup for firmware provenance.  
[S-4] Slack webhook for Critical alerts.

################################################################################
8. HAND-OFF TO AI ASSISTANT
################################################################################
> “Cursor/Copilot, start from `sim/bmc_metrics.py` and generate a minimal script
> per F-1 spec. Then proceed through deliverables D1-D11 in order, committing
> after each. Respect all coding guidelines and non-functional points.”

# END OF BRIEF – begin implementation now.
