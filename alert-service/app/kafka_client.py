from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import NoBrokersAvailable
import json
import time

KAFKA_BROKER_URL = 'kafka:9092'


def create_producer(max_retries=10, delay=5):
    for attempt in range(max_retries):
        try:
            return KafkaProducer(
                bootstrap_servers=KAFKA_BROKER_URL,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
        except NoBrokersAvailable:
            print(f"[Kafka] Broker no disponible. Reintentando ({attempt+1}/{max_retries})...")
            time.sleep(delay)
    raise Exception("Kafka no disponible después de varios intentos.")

producer = create_producer()

def send_event(topic, event):
    producer.send(topic, event)
    producer.flush()

def get_consumer(topic, group_id):
    return KafkaConsumer(
        topic,
        bootstrap_servers=KAFKA_BROKER_URL,
        group_id=group_id,
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        auto_offset_reset='earliest',
        enable_auto_commit=True
    )
