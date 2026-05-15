import joblib
import numpy as np
import pandas as pd
import os

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "isolation_forest.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")
FEATURE_NAMES_PATH = os.path.join(BASE_DIR, "models", "feature_names.pkl")

# Load at startup
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
feature_names = joblib.load(FEATURE_NAMES_PATH)

# Map schema fields to dataset column names
FIELD_MAP = {
    'Destination_Port': 'Destination Port',
    'Flow_Duration': 'Flow Duration',
    'Total_Fwd_Packets': 'Total Fwd Packets',
    'Total_Backward_Packets': 'Total Backward Packets',
    'Total_Length_of_Fwd_Packets': 'Total Length of Fwd Packets',
    'Total_Length_of_Bwd_Packets': 'Total Length of Bwd Packets',
    'Flow_Bytes_per_s': 'Flow Bytes/s',
    'Flow_Packets_per_s': 'Flow Packets/s',
    'Flow_IAT_Mean': 'Flow IAT Mean',
    'Flow_IAT_Std': 'Flow IAT Std',
    'SYN_Flag_Count': 'SYN Flag Count',
    'ACK_Flag_Count': 'ACK Flag Count',
    'Packet_Length_Mean': 'Packet Length Mean',
    'Packet_Length_Std': 'Packet Length Std',
    'Average_Packet_Size': 'Average Packet Size'
}

def analyze_log(entry: dict) -> dict:
    # Build full feature vector with zeros for missing features
    full_features = {col: 0.0 for col in feature_names}

    # Fill in provided features
    for schema_field, dataset_col in FIELD_MAP.items():
        if schema_field in entry and dataset_col in full_features:
            full_features[dataset_col] = entry[schema_field]

    # Convert to DataFrame and scale
    df = pd.DataFrame([full_features])[feature_names]
    scaled = scaler.transform(df)

    # Get prediction and anomaly score
    raw_pred = model.predict(scaled)[0]
    anomaly_score_raw = model.score_samples(scaled)[0]
    # Use score-based threshold instead of binary prediction
    # Raw scores below -0.45 are considered normal
    is_anomaly = raw_pred == -1
    print(f"Raw: {anomaly_score_raw}, is_anomaly: {is_anomaly}, condition: {anomaly_score_raw > -0.45}")

    # Anomaly score — higher means more anomalous
    anomaly_score = round(max(0.0, min(1.0, (0.5 + anomaly_score_raw) * -1)), 4)

    # Risk level
    if not is_anomaly:
        risk_level = "LOW"
    elif anomaly_score < 0.3:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    label = "ANOMALY" if is_anomaly else "NORMAL"

    if is_anomaly:
        message = f"Anomalous network traffic detected. Anomaly score: {anomaly_score}. Risk: {risk_level}."
    else:
        message = f"Network traffic appears normal. Anomaly score: {anomaly_score}."

    return {
        "is_anomaly": is_anomaly,
        "label": label,
        "anomaly_score": anomaly_score,
        "risk_level": risk_level,
        "message": message
    }