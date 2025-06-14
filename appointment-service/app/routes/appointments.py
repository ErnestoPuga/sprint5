from fastapi import APIRouter, Depends, HTTPException
from app.security.jwt_auth import require_role, get_current_user
from uuid import uuid4
from app.kafka_client import send_event
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

# Simulación de base de datos en memoria
appointments = []

@router.post("")  # Cambiar de "/" a ""
def create_appointment(data: dict, user=Depends(require_role(["paciente", "medico"]))):
    print(" Data recibida:", data)
    print(" Usuario:", user)
    
    try:
        appointment = {
            "id": str(uuid4()),
            "patient_id": data["patient_id"],
            "doctor_id": data["doctor_id"],
            "date": data["date"],
            "time": data["time"],
            "reason": data["reason"],
            "created_by": user.get("preferred_username", "desconocido")  # usa .get()
        }
        print(" Cita a guardar:", appointment)
        appointments.append(appointment)
        send_event("appointments", appointment)
        return appointment
    except Exception as e:
        import traceback
        print(" ERROR EN CREAR CITA:", traceback.format_exc())
        raise HTTPException(status_code=500, detail="Error interno al crear cita")

@router.get("")  # Cambiar de "/" a ""
def list_appointments(user=Depends(require_role(["medico", "admin"]))):
    """Listar todas las citas"""
    try:
        logger.info(f"User {user.get('sub')} listing appointments")
        return {
            "appointments": appointments,
            "total": len(appointments),
            "status": "success"
        }
    except Exception as e:
        logger.error(f"Error listing appointments: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@router.get("/{appointment_id}")
def get_appointment(appointment_id: str, user=Depends(get_current_user)):
    """Obtener cita específica"""
    try:
        appointment = next((apt for apt in appointments if apt["id"] == appointment_id), None)
        if not appointment:
            raise HTTPException(status_code=404, detail="Cita no encontrada")
        
        # Verificar permisos: solo el creador, paciente involucrado, o admin/medico pueden ver
        user_roles = user.get("realm_access", {}).get("roles", [])
        is_authorized = (
            appointment["created_by"] == user.get("preferred_username") or
            appointment["patient_id"] == user.get("sub") or
            appointment["doctor_id"] == user.get("sub") or
            any(role in user_roles for role in ["admin", "medico"])
        )
        
        if not is_authorized:
            raise HTTPException(status_code=403, detail="No autorizado para ver esta cita")
        
        return {
            "appointment": appointment,
            "status": "success"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting appointment {appointment_id}: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@router.put("/{appointment_id}")
def update_appointment(
    appointment_id: str, 
    data: dict, 
    user=Depends(require_role(["paciente", "medico", "admin"]))
):
    """Actualizar cita"""
    try:
        appointment = next((apt for apt in appointments if apt["id"] == appointment_id), None)
        if not appointment:
            raise HTTPException(status_code=404, detail="Cita no encontrada")
        
        # Verificar permisos de edición
        user_roles = user.get("realm_access", {}).get("roles", [])
        is_authorized = (
            appointment["created_by"] == user.get("preferred_username") or
            any(role in user_roles for role in ["admin", "medico"])
        )
        
        if not is_authorized:
            raise HTTPException(status_code=403, detail="No autorizado para editar esta cita")
        
        # Actualizar campos
        for key, value in data.items():
            if key in ["patient_id", "doctor_id", "date", "time", "reason"]:
                appointment[key] = value
        
        appointment["updated_by"] = user.get("preferred_username", "unknown")
        
        # Enviar evento a Kafka
        send_event("appointment_updated", appointment)
        logger.info(f"Appointment updated: {appointment_id}")
        
        return {
            "message": "Cita actualizada exitosamente",
            "appointment": appointment,
            "status": "success"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating appointment {appointment_id}: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@router.delete("/{appointment_id}")
def delete_appointment(
    appointment_id: str, 
    user=Depends(require_role(["paciente", "medico", "admin"]))
):
    """Eliminar cita"""
    try:
        appointment_index = next((i for i, apt in enumerate(appointments) if apt["id"] == appointment_id), None)
        if appointment_index is None:
            raise HTTPException(status_code=404, detail="Cita no encontrada")
        
        appointment = appointments[appointment_index]
        
        # Verificar permisos de eliminación
        user_roles = user.get("realm_access", {}).get("roles", [])
        is_authorized = (
            appointment["created_by"] == user.get("preferred_username") or
            any(role in user_roles for role in ["admin", "medico"])
        )
        
        if not is_authorized:
            raise HTTPException(status_code=403, detail="No autorizado para eliminar esta cita")
        
        # Eliminar cita
        deleted_appointment = appointments.pop(appointment_index)
        
        # Enviar evento a Kafka
        send_event("appointment_deleted", {
            "appointment_id": appointment_id,
            "deleted_by": user.get("preferred_username", "unknown"),
            "deleted_appointment": deleted_appointment
        })
        logger.info(f"Appointment deleted: {appointment_id}")
        
        return {
            "message": "Cita eliminada exitosamente",
            "appointment_id": appointment_id,
            "status": "success"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting appointment {appointment_id}: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")