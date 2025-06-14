from fastapi import APIRouter, Depends
from app.security.jwt_auth import require_role
from app.kafka_client import send_event

router = APIRouter()

patients = {
    "p001": {"id": "p001", "name": "Ana Sánchez", "age": 34},
    "p002": {"id": "p002", "name": "Luis Gómez", "age": 51}
}

@router.get("/{patient_id}")
def get_patient(patient_id: str, user=Depends(require_role(["admin", "medico"]))):
    patient = patients.get(patient_id, {"message": "Paciente no encontrado"})
    # Enviar evento de consulta a Kafka (opcional, ejemplo)
    send_event("patient_queries", {"patient_id": patient_id, "requested_by": user["username"]})
    return patient
