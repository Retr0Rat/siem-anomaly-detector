from pydantic import BaseModel
from typing import Literal
from datetime import datetime

class LogEntry(BaseModel):
    Destination_Port: float
    Flow_Duration: float
    Total_Fwd_Packets: float
    Total_Backward_Packets: float
    Total_Length_of_Fwd_Packets: float
    Total_Length_of_Bwd_Packets: float
    Flow_Bytes_per_s: float
    Flow_Packets_per_s: float
    Flow_IAT_Mean: float
    Flow_IAT_Std: float
    SYN_Flag_Count: float
    ACK_Flag_Count: float
    Packet_Length_Mean: float
    Packet_Length_Std: float
    Average_Packet_Size: float

class ScanResponse(BaseModel):
    is_anomaly: bool
    label: Literal["NORMAL", "ANOMALY"]
    anomaly_score: float
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    message: str