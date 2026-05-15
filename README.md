# SIEM Anomaly Detector

A production-ready REST API for detecting anomalous network traffic using unsupervised machine learning. Trained exclusively on BENIGN network flows from the CICIDS 2017 dataset — detecting DDoS attacks and unknown threats **without ever seeing attack data during training**. Macro F1: **0.71**.

---

## What Makes This Different

Most ML security tools are supervised — they learn from labelled attack examples. This means they can only detect attack types they've seen before.

This SIEM uses **Isolation Forest**, an unsupervised anomaly detection algorithm trained only on normal (BENIGN) traffic. It learns what normal looks like and flags anything that deviates — including novel, zero-day attacks that no labelled dataset covers.

> Trained on 97,684 BENIGN flows. Never saw a single DDoS packet. Detected 81,411 DDoS attacks at test time.

---

## Results

| Metric | BENIGN | DDoS |
|---|---|---|
| Precision | 0.63 | 0.81 |
| Recall | 0.80 | 0.64 |
| F1-Score | 0.70 | 0.71 |
| Overall Accuracy | **71%** | |
| Macro F1 | **0.71** | |

**Contamination tuning:** Tested 6 contamination values (0.05 → 0.50). Optimal value of 0.20 selected based on highest macro F1 — improving DDoS recall from 17% (default) to 64%.

---

## Tech Stack

- **Model:** Isolation Forest (scikit-learn) — unsupervised anomaly detection
- **Dataset:** CICIDS 2017 — Friday DDoS (225,745 network flow records)
- **API:** FastAPI + Uvicorn
- **Validation:** Pydantic v2
- **Containerisation:** Docker
- **Testing:** Pytest (8/8 passing)
- **Serialisation:** Joblib

---

## Project Structure

```
siem-anomaly-detector/
├── app/
│   ├── main.py          # FastAPI app — 3 endpoints
│   ├── model.py         # Isolation Forest loading + inference
│   └── schemas.py       # Pydantic input/output schemas
├── models/
│   ├── isolation_forest.pkl  # Trained Isolation Forest
│   ├── scaler.pkl            # StandardScaler
│   └── feature_names.pkl     # 15 key feature names
├── notebooks/
│   └── siem_training.ipynb   # EDA, preprocessing, training, evaluation
├── tests/
│   └── test_main.py     # 8 pytest tests
├── Dockerfile
├── requirements.txt
└── conftest.py
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Root — confirms API is running |
| GET | `/health` | Health check — model info + metrics |
| POST | `/analyze` | Analyze network flow for anomalies |

### Sample Request — BENIGN Traffic

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "Destination_Port": 54865.0,
    "Flow_Duration": 3.0,
    "Total_Fwd_Packets": 2.0,
    "Total_Backward_Packets": 0.0,
    "Total_Length_of_Fwd_Packets": 12.0,
    "Total_Length_of_Bwd_Packets": 0.0,
    "Flow_Bytes_per_s": 4000000.0,
    "Flow_Packets_per_s": 666666.6667,
    "Flow_IAT_Mean": 3.0,
    "Flow_IAT_Std": 0.0,
    "SYN_Flag_Count": 0.0,
    "ACK_Flag_Count": 1.0,
    "Packet_Length_Mean": 6.0,
    "Packet_Length_Std": 0.0,
    "Average_Packet_Size": 9.0
  }'
```

### Sample Response — Normal Traffic

```json
{
  "is_anomaly": false,
  "label": "NORMAL",
  "anomaly_score": 0.0,
  "risk_level": "LOW",
  "message": "Network traffic appears normal. Anomaly score: 0.0."
}
```

### Sample Response — Anomalous Traffic

```json
{
  "is_anomaly": true,
  "label": "ANOMALY",
  "anomaly_score": 0.0112,
  "risk_level": "MEDIUM",
  "message": "Anomalous network traffic detected. Anomaly score: 0.0112. Risk: MEDIUM."
}
```

---

## Risk Levels

| Risk Level | Condition |
|---|---|
| LOW | Traffic classified as normal |
| MEDIUM | Anomaly detected, lower anomaly score |
| HIGH | Anomaly detected, higher anomaly score |

---

## Run Locally

### Option 1 — Docker (recommended)

```bash
docker build -t siem-anomaly-detector .
docker run -p 8000:8000 siem-anomaly-detector
```

### Option 2 — Python virtual environment

```bash
git clone https://github.com/Retr0Rat/siem-anomaly-detector.git
cd siem-anomaly-detector

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000/docs** for the interactive Swagger UI.

---

## Run Tests

```bash
python -m pytest tests/ -v
```

```
tests/test_main.py::test_root_endpoint PASSED
tests/test_main.py::test_health_endpoint PASSED
tests/test_main.py::test_analyze_normal_traffic PASSED
tests/test_main.py::test_analyze_ddos_traffic PASSED
tests/test_main.py::test_response_structure PASSED
tests/test_main.py::test_anomaly_score_range PASSED
tests/test_main.py::test_label_values PASSED
tests/test_main.py::test_risk_level_values PASSED

8 passed
```

---

## Dataset

[CICIDS 2017](https://www.unb.ca/cic/datasets/ids-2017.html) — Canadian Institute for Cybersecurity

- Friday DDoS file: 225,745 network flow records
- 78 features extracted by CICFlowMeter
- Labels: BENIGN (43.3%) and DDoS (56.7%)
- Dataset excluded from repo — download from the link above and place in `data/`

---

## Current Limitations

**1. 15-feature subset**
The current API accepts 15 key features for demo usability. The full dataset contains 78 features. Training on 15 features achieves identical macro F1 (0.71) to training on all 78, confirming these features capture the core predictive signal.

**2. Unsupervised tradeoff**
Isolation Forest doesn't identify attack types — it only flags anomalies. A traffic flow flagged as anomalous could be DDoS, a misconfigured server, or an unknown attack type. This is intentional — the goal is detecting the unknown, not just known attack patterns.

**3. Synthetic input limitations**
Hand-crafted test inputs may not perfectly match real network flow distributions. Test inputs in this repo are taken directly from the CICIDS 2017 dataset to ensure accurate model behaviour.

**4. Static contamination threshold**
Contamination is fixed at 0.20. In production this would be dynamically adjusted based on real-time traffic baselines.

---

## Future Enhancements

### Threat Intelligence Layer (Planned v2)

The current version detects anomalies but doesn't classify them. The planned v2 adds a **Threat Intelligence Layer** on top of the Isolation Forest:

```
Incoming traffic
      ↓
Isolation Forest → NORMAL? → Allow
      ↓ ANOMALY
Threat Analyser
      ↓
┌─────────────────────────────────────┐
│ Feature signature matching          │
│ - High packets/s + short duration   │  → DDoS
│ - SYN flood pattern                 │  → SYN Attack
│ - Sequential port access            │  → Recon
│ - Brute force timing pattern        │  → Brute Force
│ - Doesn't match any signature       │  → UNKNOWN THREAT
└─────────────────────────────────────┘
      ↓
Threat Score (0-100) + Category + Confidence + Recommended Action
```

**Output example:**
```json
{
  "is_anomaly": true,
  "threat_score": 87,
  "category": "DDoS",
  "confidence": 0.91,
  "recommended_action": "BLOCK",
  "signature_matches": ["high_packet_rate", "short_flow_duration", "low_byte_ratio"]
}
```

### CICFlowMeter / Zeek Integration (Planned v3)

In production this API would integrate with:
- **CICFlowMeter** — automatically extracts all 78 network flow features from live pcap traffic
- **Zeek (formerly Bro)** — network monitoring framework that generates flow logs compatible with this API
- **Wireshark** — packet capture tool for offline analysis

The pipeline would be:
```
Live network traffic → CICFlowMeter → 78 features → SIEM API → Threat alert
```

Retrain the model on all 78 features for full CICFlowMeter compatibility.

### Multi-Layer Architecture (Planned v4)

```
Layer 1 — Isolation Forest     → Unknown anomaly detection
Layer 2 — Random Forest        → Known attack type classification  
Layer 3 — Threat Intelligence  → Score + category + recommended action
Layer 4 — Dashboard            → Real-time visualisation + alerting
```

---

## Key Design Decisions

**Why Isolation Forest over supervised classification?**
Supervised models can only detect attack types present in training data. Isolation Forest detects any deviation from normal behaviour — including zero-day attacks, novel malware, and insider threats that no labelled dataset covers. In production SOC environments, unknown threats are the most dangerous.

**Why train on BENIGN only?**
You always have normal traffic data. You rarely have comprehensive, labelled attack data covering all possible threat types. Training on BENIGN only makes the model robust to novel attacks by definition.

**Why 15 features over all 78?**
Feature selection achieved identical macro F1 (0.71) with 15 features vs 78. Fewer features = faster inference, smaller model, simpler API. The 15 selected features (flow duration, packet rates, flag counts, byte ratios) are the most semantically meaningful for anomaly detection.

**Why contamination=0.20?**
Systematically tuned across 6 values. At 0.20 the model achieves the highest macro F1 of 0.71, balancing DDoS detection recall (64%) with false positive rate on BENIGN traffic.

---

## Author

**Aman** — AI & Cybersecurity Post-Graduate, Durham College  
[github.com/Retr0Rat](https://github.com/Retr0Rat) · aman23092003@gmail.com · Oshawa, ON
