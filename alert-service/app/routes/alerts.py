from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from typing import List, Optional
from datetime import datetime, date
from uuid import uuid4
import logging

from app.security.jwt_auth import require_role, get_current_user
from app.kafka_client import send_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])

# Lista en memoria para almacenar alertas (como en el servicio de citas)
alerts = []

# Enum para tipos de alerta
ALERT_TYPES = ["emergency", "warning", "info", "reminder"]
ALERT_STATUS = ["pending", "sent", "delivered", "failed", "read"]

def create_alert_dict(data: dict, user: dict) -> dict:
    """Crear diccionario de alerta con validaciones"""
    return {
        "id": str(uuid4()),
        "patient_id": data.get("patient_id"),
        "doctor_id": data.get("doctor_id"),
        "alert_type": data.get("alert_type", "info"),
        "title": data.get("title"),
        "message": data.get("message"),
        "status": "pending",
        
        # Configuración de entrega
        "send_email": data.get("send_email", True),
        "send_sms": data.get("send_sms", False),
        "send_push": data.get("send_push", True),
        
        # Metadatos
        "created_by": user.get("preferred_username", "unknown"),
        "created_at": datetime.utcnow().isoformat(),
        "sent_at": None,
        "delivered_at": None,
        "read_at": None,
        
        # Información adicional
        "metadata": data.get("metadata"),
        "retry_count": 0,
        "last_error": None
    }

@router.post("/")
async def create_alert(
    data: dict, 
    background_tasks: BackgroundTasks,
    user=Depends(require_role(["admin", "medico", "enfermero"]))
):
  
    try:
        # Validaciones básicas
        if not data.get("patient_id"):
            raise HTTPException(status_code=400, detail="patient_id es requerido")
        
        if not data.get("title"):
            raise HTTPException(status_code=400, detail="title es requerido")
        
        if not data.get("message"):
            raise HTTPException(status_code=400, detail="message es requerido")
        
        if data.get("alert_type") and data["alert_type"] not in ALERT_TYPES:
            raise HTTPException(status_code=400, detail=f"alert_type debe ser uno de: {ALERT_TYPES}")
        
        # Crear nueva alerta
        new_alert = create_alert_dict(data, user)
        alerts.append(new_alert)
        
        logger.info(f" Alerta creada: {new_alert['id']} para paciente {new_alert['patient_id']}")
        
        # Enviar evento a Kafka
        kafka_event = {
            "id": new_alert["id"],
            "patient_id": new_alert["patient_id"],
            "doctor_id": new_alert["doctor_id"],
            "alert_type": new_alert["alert_type"],
            "title": new_alert["title"],
            "message": new_alert["message"],
            "created_by": new_alert["created_by"],
            "created_at": new_alert["created_at"],
            "event_type": "alert_created"
        }
        
        background_tasks.add_task(send_event, "alerts", kafka_event)
        
        # Simular envío de notificaciones
        background_tasks.add_task(process_notifications, new_alert["id"])
        
        return new_alert
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Error creando alerta: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creando alerta: {str(e)}")

@router.get("/")
async def list_alerts(
    # Filtros
    patient_id: Optional[str] = Query(None, description="Filtrar por ID del paciente"),
    doctor_id: Optional[str] = Query(None, description="Filtrar por ID del doctor"),
    alert_type: Optional[str] = Query(None, description="Filtrar por tipo de alerta"),
    status: Optional[str] = Query(None, description="Filtrar por estado"),
    date_from: Optional[str] = Query(None, description="Fecha desde (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="Fecha hasta (YYYY-MM-DD)"),
    
    # Paginación
    skip: int = Query(0, ge=0, description="Registros a omitir"),
    limit: int = Query(100, ge=1, le=1000, description="Límite de registros"),
    
    # Dependencias
    user=Depends(require_role(["medico", "admin", "enfermero"]))
):
    
    try:
        # Aplicar filtros
        filtered_alerts = alerts
        
        if patient_id:
            filtered_alerts = [a for a in filtered_alerts if a["patient_id"] == patient_id]
        
        if doctor_id:
            filtered_alerts = [a for a in filtered_alerts if a["doctor_id"] == doctor_id]
        
        if alert_type:
            if alert_type not in ALERT_TYPES:
                raise HTTPException(status_code=400, detail=f"alert_type debe ser uno de: {ALERT_TYPES}")
            filtered_alerts = [a for a in filtered_alerts if a["alert_type"] == alert_type]
        
        if status:
            if status not in ALERT_STATUS:
                raise HTTPException(status_code=400, detail=f"status debe ser uno de: {ALERT_STATUS}")
            filtered_alerts = [a for a in filtered_alerts if a["status"] == status]
        
        if date_from:
            try:
                date_from_dt = datetime.fromisoformat(date_from + "T00:00:00")
                filtered_alerts = [a for a in filtered_alerts 
                                 if datetime.fromisoformat(a["created_at"]) >= date_from_dt]
            except ValueError:
                raise HTTPException(status_code=400, detail="date_from debe tener formato YYYY-MM-DD")
        
        if date_to:
            try:
                date_to_dt = datetime.fromisoformat(date_to + "T23:59:59")
                filtered_alerts = [a for a in filtered_alerts 
                                 if datetime.fromisoformat(a["created_at"]) <= date_to_dt]
            except ValueError:
                raise HTTPException(status_code=400, detail="date_to debe tener formato YYYY-MM-DD")
        
        # Ordenar por fecha de creación (más recientes primero)
        filtered_alerts.sort(key=lambda x: x["created_at"], reverse=True)
        
        # Aplicar paginación
        total = len(filtered_alerts)
        paginated_alerts = filtered_alerts[skip:skip + limit]
        
        logger.info(f" Consultadas {len(paginated_alerts)} alertas de {total} total")
        return paginated_alerts
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Error listando alertas: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error consultando alertas: {str(e)}")

@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    user=Depends(require_role(["medico", "admin", "enfermero"]))
):
    """Obtener una alerta específica por ID"""
    alert = next((a for a in alerts if a["id"] == alert_id), None)
    
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")
    
    return alert

@router.put("/{alert_id}")
async def update_alert_status(
    alert_id: str,
    data: dict,
    background_tasks: BackgroundTasks,
    user=Depends(require_role(["medico", "admin", "enfermero"]))
):
    """
    Actualizar el estado de una alerta
    
    Ejemplo de data:
    {
        "status": "read",
        "read_at": "2025-06-13T10:30:00"
    }
    """
    alert = next((a for a in alerts if a["id"] == alert_id), None)
    
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")
    
    try:
        # Actualizar campos proporcionados
        if "status" in data:
            if data["status"] not in ALERT_STATUS:
                raise HTTPException(status_code=400, detail=f"status debe ser uno de: {ALERT_STATUS}")
            alert["status"] = data["status"]
        
        if "sent_at" in data:
            alert["sent_at"] = data["sent_at"]
        
        if "delivered_at" in data:
            alert["delivered_at"] = data["delivered_at"]
        
        if "read_at" in data:
            alert["read_at"] = data["read_at"]
        
        if "last_error" in data:
            alert["last_error"] = data["last_error"]
        
        # Enviar evento de actualización a Kafka
        kafka_event = {
            "id": alert["id"],
            "status": alert["status"],
            "updated_by": user.get("preferred_username", "unknown"),
            "updated_at": datetime.utcnow().isoformat(),
            "event_type": "alert_updated"
        }
        
        background_tasks.add_task(send_event, "alerts", kafka_event)
        
        logger.info(f" Alerta {alert_id} actualizada a estado {alert['status']}")
        return alert
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Error actualizando alerta {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error actualizando alerta: {str(e)}")

@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: str,
    background_tasks: BackgroundTasks,
    user=Depends(require_role(["admin"]))
):
    """Eliminar una alerta (solo admins)"""
    global alerts
    
    alert = next((a for a in alerts if a["id"] == alert_id), None)
    
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")
    
    try:
        # Remover de la lista
        alerts = [a for a in alerts if a["id"] != alert_id]
        
        # Enviar evento de eliminación a Kafka
        kafka_event = {
            "id": alert_id,
            "deleted_by": user.get("preferred_username", "unknown"),
            "deleted_at": datetime.utcnow().isoformat(),
            "event_type": "alert_deleted"
        }
        
        background_tasks.add_task(send_event, "alerts", kafka_event)
        
        logger.info(f" Alerta {alert_id} eliminada por {user.get('preferred_username')}")
        return {"message": f"Alerta {alert_id} eliminada exitosamente"}
        
    except Exception as e:
        logger.error(f" Error eliminando alerta {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error eliminando alerta: {str(e)}")

@router.get("/patient/{patient_id}")
async def get_patient_alerts(
    patient_id: str,
    status: Optional[str] = Query(None, description="Filtrar por estado"),
    alert_type: Optional[str] = Query(None, description="Filtrar por tipo"),
    unread_only: bool = Query(False, description="Solo alertas no leídas"),
    user=Depends(require_role(["medico", "admin", "enfermero"]))
):
    """Obtener todas las alertas de un paciente específico"""
    patient_alerts = [a for a in alerts if a["patient_id"] == patient_id]
    
    if status:
        if status not in ALERT_STATUS:
            raise HTTPException(status_code=400, detail=f"status debe ser uno de: {ALERT_STATUS}")
        patient_alerts = [a for a in patient_alerts if a["status"] == status]
    
    if alert_type:
        if alert_type not in ALERT_TYPES:
            raise HTTPException(status_code=400, detail=f"alert_type debe ser uno de: {ALERT_TYPES}")
        patient_alerts = [a for a in patient_alerts if a["alert_type"] == alert_type]
    
    if unread_only:
        patient_alerts = [a for a in patient_alerts if a["read_at"] is None]
    
    # Ordenar por fecha de creación (más recientes primero)
    patient_alerts.sort(key=lambda x: x["created_at"], reverse=True)
    
    logger.info(f" Consultadas {len(patient_alerts)} alertas para paciente {patient_id}")
    return patient_alerts

@router.post("/{alert_id}/mark-read")
async def mark_alert_as_read(
    alert_id: str,
    background_tasks: BackgroundTasks,
    user=Depends(get_current_user)
):
    """Marcar una alerta como leída"""
    alert = next((a for a in alerts if a["id"] == alert_id), None)
    
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")
    
    if alert["read_at"] is None:
        alert["read_at"] = datetime.utcnow().isoformat()
        alert["status"] = "read"
        
        # Enviar evento a Kafka
        kafka_event = {
            "id": alert["id"],
            "read_by": user.get("preferred_username", "unknown"),
            "read_at": alert["read_at"],
            "event_type": "alert_read"
        }
        
        background_tasks.add_task(send_event, "alerts", kafka_event)
        
        logger.info(f" Alerta {alert_id} marcada como leída")
    
    return {"message": "Alerta marcada como leída", "read_at": alert["read_at"]}

@router.get("/stats/summary")
async def get_alerts_summary(
    date_from: Optional[str] = Query(None, description="Fecha desde (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="Fecha hasta (YYYY-MM-DD)"),
    user=Depends(require_role(["admin", "medico"]))
):
    """Obtener estadísticas resumidas de alertas"""
    
    filtered_alerts = alerts
    
    # Aplicar filtros de fecha
    if date_from:
        try:
            date_from_dt = datetime.fromisoformat(date_from + "T00:00:00")
            filtered_alerts = [a for a in filtered_alerts 
                             if datetime.fromisoformat(a["created_at"]) >= date_from_dt]
        except ValueError:
            raise HTTPException(status_code=400, detail="date_from debe tener formato YYYY-MM-DD")
    
    if date_to:
        try:
            date_to_dt = datetime.fromisoformat(date_to + "T23:59:59")
            filtered_alerts = [a for a in filtered_alerts 
                             if datetime.fromisoformat(a["created_at"]) <= date_to_dt]
        except ValueError:
            raise HTTPException(status_code=400, detail="date_to debe tener formato YYYY-MM-DD")
    
    # Contar por estado
    status_counts = {}
    for status in ALERT_STATUS:
        status_counts[status] = len([a for a in filtered_alerts if a["status"] == status])
    
    # Contar por tipo
    type_counts = {}
    for alert_type in ALERT_TYPES:
        type_counts[alert_type] = len([a for a in filtered_alerts if a["alert_type"] == alert_type])
    
    total = len(filtered_alerts)
    pending_count = status_counts.get("pending", 0)
    failed_count = status_counts.get("failed", 0)
    
    return {
        "total_alerts": total,
        "by_status": status_counts,
        "by_type": type_counts,
        "pending_count": pending_count,
        "failed_count": failed_count,
        "date_range": {
            "from": date_from,
            "to": date_to
        }
    }

# Función auxiliar para simular procesamiento de notificaciones
async def process_notifications(alert_id: str):
    """Simular el envío de notificaciones"""
    try:
        # Buscar la alerta
        alert = next((a for a in alerts if a["id"] == alert_id), None)
        if not alert:
            return
        
        # Simular un pequeño delay
        import asyncio
        await asyncio.sleep(1)
        
        # Marcar como enviada
        alert["status"] = "sent"
        alert["sent_at"] = datetime.utcnow().isoformat()
        
        # Simular delay de entrega
        await asyncio.sleep(2)
        
        # Marcar como entregada
        alert["status"] = "delivered"
        alert["delivered_at"] = datetime.utcnow().isoformat()
        
        logger.info(f" Notificaciones procesadas para alerta {alert_id}")
        
        # Enviar evento de notificación procesada
        notification_event = {
            "alert_id": alert_id,
            "status": "delivered",
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "notification_processed"
        }
        
        send_event("notifications", notification_event)
        
    except Exception as e:
        logger.error(f" Error procesando notificaciones para alerta {alert_id}: {str(e)}")
        
        # Marcar como fallida
        alert = next((a for a in alerts if a["id"] == alert_id), None)
        if alert:
            alert["status"] = "failed"
            alert["last_error"] = str(e)
            alert["retry_count"] += 1