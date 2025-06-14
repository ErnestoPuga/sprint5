from fastapi import APIRouter, Depends, HTTPException
from uuid import uuid4
from app.security.jwt_auth import require_role
from app.kafka_client import send_event

router = APIRouter()

patients = {
    "p001": {"id": "p001", "name": "Ana Sánchez", "age": 34},
    "p002": {"id": "p002", "name": "Luis Gómez", "age": 51}
}

@router.post("")
def create_patient(data: dict, user=Depends(require_role(["admin", "medico"]))):
    try:
        patient_id = f"p{str(uuid4())[:4]}"
        patient = {
            "id": patient_id,
            "name": data["name"],
            "age": data["age"],
            "created_by": user.get("preferred_username", "desconocido")
        }
        patients[patient_id] = patient

        # Emitir evento Kafka
        send_event("patient_created", patient)

        return {
            "message": "Paciente creado exitosamente",
            "patient": patient,
            "status": "success"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error al crear el paciente")

@router.get("")
def list_patients(user=Depends(require_role(["admin", "medico"]))):
    """Listar todos los pacientes"""
    try:
        return {
            "patients": list(patients.values()),
            "total": len(patients),
            "status": "success"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor")