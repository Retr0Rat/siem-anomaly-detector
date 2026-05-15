from fastapi import FastAPI, HTTPException
from app.schemas import LogEntry, ScanResponse
from app.model import analyze_log

application = FastAPI(
    title="SIEM Anomaly Detector",
    description="Isolation Forest-powered network traffic anomaly detection API. Trained on CICIDS 2017 BENIGN traffic only. Detects DDoS and unknown threats without labelled attack data. Macro F1: 0.71",
    version="1.0.0"
)

@application.get("/")
def root():
    return {
        "message": "SIEM Anomaly Detector API is running",
        "version": "1.0.0",
        "model": "Isolation Forest (unsupervised)",
        "dataset": "CICIDS 2017 — Friday DDoS",
        "macro_f1": 0.71,
        "endpoints": {
            "health": "/health",
            "analyze": "/analyze",
            "docs": "/docs"
        }
    }

@application.get("/health")
def health():
    return {
        "status": "healthy",
        "model": "Isolation Forest",
        "contamination": 0.20,
        "n_estimators": 100,
        "macro_f1": 0.71,
        "trained_on": "BENIGN traffic only"
    }

@application.post("/analyze", response_model=ScanResponse)
def analyze(entry: LogEntry):
    try:
        result = analyze_log(entry.model_dump())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

app = application