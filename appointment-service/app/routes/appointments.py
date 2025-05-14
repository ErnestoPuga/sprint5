from fastapi import APIRouter, Depends
from app.security.jwt_auth import require_role
from uuid import uuid4

router = APIRouter()

appointments = []

@router.post("/")
def create_appointment(data: dict, user=Depends(require_role(["paciente", "medico"]))):
    new_appointment = {
        "id": str(uuid4()),
        "patient_id": data["patient_id"],
        "doctor_id": data["doctor_id"],
        "date": data["date"],
        "time": data["time"],
        "reason": data["reason"],
        "created_by": user["username"]
    }
    appointments.append(new_appointment)
    return new_appointment

@router.get("/")
def list_appointments(user=Depends(require_role(["medico", "admin"]))):
    return appointments
