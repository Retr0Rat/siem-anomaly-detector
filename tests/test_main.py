from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

NORMAL_TRAFFIC = {
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
}

DDOS_TRAFFIC = {
    "Destination_Port": 80.0,
    "Flow_Duration": 1293792.0,
    "Total_Fwd_Packets": 3.0,
    "Total_Backward_Packets": 7.0,
    "Total_Length_of_Fwd_Packets": 26.0,
    "Total_Length_of_Bwd_Packets": 11607.0,
    "Flow_Bytes_per_s": 8991.398927,
    "Flow_Packets_per_s": 7.72921768,
    "Flow_IAT_Mean": 143754.6667,
    "Flow_IAT_Std": 430865.8067,
    "SYN_Flag_Count": 0.0,
    "ACK_Flag_Count": 0.0,
    "Packet_Length_Mean": 1057.545455,
    "Packet_Length_Std": 1853.437529,
    "Average_Packet_Size": 1163.3
}


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "message" in response.json()


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model"] == "Isolation Forest"


def test_analyze_normal_traffic():
    response = client.post("/analyze", json=NORMAL_TRAFFIC)
    assert response.status_code == 200
    data = response.json()
    assert data["is_anomaly"] == False
    assert data["label"] == "NORMAL"
    assert data["risk_level"] == "LOW"


def test_analyze_ddos_traffic():
    response = client.post("/analyze", json=DDOS_TRAFFIC)
    assert response.status_code == 200
    data = response.json()
    assert data["is_anomaly"] == True
    assert data["label"] == "ANOMALY"


def test_response_structure():
    response = client.post("/analyze", json=NORMAL_TRAFFIC)
    data = response.json()
    assert "is_anomaly" in data
    assert "label" in data
    assert "anomaly_score" in data
    assert "risk_level" in data
    assert "message" in data


def test_anomaly_score_range():
    response = client.post("/analyze", json=NORMAL_TRAFFIC)
    score = response.json()["anomaly_score"]
    assert 0.0 <= score <= 1.0


def test_label_values():
    response = client.post("/analyze", json=NORMAL_TRAFFIC)
    label = response.json()["label"]
    assert label in ["NORMAL", "ANOMALY"]


def test_risk_level_values():
    response = client.post("/analyze", json=NORMAL_TRAFFIC)
    risk = response.json()["risk_level"]
    assert risk in ["LOW", "MEDIUM", "HIGH"]