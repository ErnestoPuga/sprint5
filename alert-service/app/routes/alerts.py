from fastapi import APIRouter, Depends
from app.security.jwt_auth import require_role
from app.kafka_client import send_event
from uuid import uuid4

router = APIRouter()

alerts = []

@router.post("/")

def create_alert(data: dict, user=Depends(require_role(["admin", "medico"]))):
    new_alert = {
        "id": str(uuid4()),
        "patient_id": data["patient_id"],
        "doctor_id": data["doctor_id"],
        "message": data["message"],
        "created_by": user["username"]
    }
    alerts.append(new_alert)
    # Enviar evento a Kafka
    send_event("alerts", new_alert)
    return new_alert

@router.get("/")
def list_alerts(user=Depends(require_role(["medico", "admin"]))):
    return alerts
