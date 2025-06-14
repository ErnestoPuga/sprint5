from kafka import KafkaConsumer
import json
import logging
from uuid import uuid4
from datetime import datetime
import time
import requests

# Configuración
KAFKA_BROKER_URL = 'kafka:9092'
TOPIC = 'appointment_created'
ALERT_SERVICE_URL = 'http://alert-service:8002/alerts'

# Setup de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("appointment_consumer")

def create_alert_from_appointment(event):
    alert = {
        "id": str(uuid4()),
        "patient_id": event.get("patient_id"),
        "doctor_id": event.get("doctor_id"),
        "alert_type": "reminder",
        "title": f"Cita agendada con el Dr. {event.get('doctor_id')}",
        "message": f"Tienes una cita el {event.get('date')} a las {event.get('time')}.",
        "status": "pending",
        "send_email": True,
        "send_sms": False,
        "send_push": True,
        "created_by": "appointment-consumer",
        "created_at": datetime.utcnow().isoformat(),
        "sent_at": None,
        "delivered_at": None,
        "read_at": None,
        "metadata": {},
        "retry_count": 0,
        "last_error": None
    }

    logger.info(f" Alerta generada para paciente {alert['patient_id']}: {alert['title']}")
    logger.info(" Enviando alerta a alert-service...")

    try:
        response = requests.post(ALERT_SERVICE_URL, json=alert)
        if response.status_code == 201:
            logger.info("  Alerta registrada correctamente en alert-service")
        else:
            logger.error(f"  Error al registrar alerta: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"  Error conectando con alert-service: {e}")

def run_consumer():
    while True:
        try:
            consumer = KafkaConsumer(
                TOPIC,
                bootstrap_servers=KAFKA_BROKER_URL,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='earliest',
                enable_auto_commit=True,
                group_id='alert-service'
            )
            logger.info(f"  Escuchando eventos en el tópico '{TOPIC}'...")
            for message in consumer:
                event = message.value
                logger.info(f"  Evento recibido: {event}")
                create_alert_from_appointment(event)

        except Exception as e:
            logger.error(f"  Error en el consumidor: {e}")
            time.sleep(5)

if __name__ == "__main__":
    run_consumer()
