from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import NoBrokersAvailable, KafkaError
import json
import time
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get Kafka broker URL from environment variable
KAFKA_BROKER_URL = os.getenv('KAFKA_BROKER_URL', 'kafka:9092')

class KafkaClient:
    def __init__(self):
        self.producer = None
        self._initialize_producer()
    
    def _initialize_producer(self, max_retries=50, delay=2):
        """Initialize Kafka producer with retry logic"""
        for attempt in range(max_retries):
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BROKER_URL,
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    acks='all',  # Wait for all replicas to acknowledge
                    retries=3,
                    max_in_flight_requests_per_connection=1,
                    request_timeout_ms=30000,
                    api_version=(2, 0, 0)
                )
                logger.info(f" Kafka producer connected successfully to {KAFKA_BROKER_URL}")
                return
            except NoBrokersAvailable as e:
                logger.warning(f"[Kafka] Broker no disponible. Reintentando ({attempt+1}/{max_retries})...")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                else:
                    logger.error(f" Kafka no disponible después de {max_retries} intentos")
                    raise Exception("Kafka no disponible después de varios intentos.") from e
            except Exception as e:
                logger.error(f" Error inesperado conectando a Kafka: {e}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                else:
                    raise
    
    def send_event(self, topic, event):
        """Send event to Kafka topic"""
        try:
            if not self.producer:
                self._initialize_producer()
            
            future = self.producer.send(topic, event)
            self.producer.flush(timeout=10)  # Wait up to 10 seconds
            logger.info(f" Event sent to topic '{topic}': {event}")
            return future
        except KafkaError as e:
            logger.error(f" Error sending event to Kafka: {e}")
            # Try to reinitialize producer
            try:
                self._initialize_producer()
                future = self.producer.send(topic, event)
                self.producer.flush(timeout=10)
                logger.info(f" Event sent to topic '{topic}' after reconnection: {event}")
                return future
            except Exception as retry_error:
                logger.error(f" Failed to send event after reconnection: {retry_error}")
                raise
        except Exception as e:
            logger.error(f" Unexpected error sending event: {e}")
            raise
    
    def get_consumer(self, topic, group_id, max_retries=10, delay=2):
        """Create Kafka consumer with retry logic"""
        for attempt in range(max_retries):
            try:
                consumer = KafkaConsumer(
                    topic,
                    bootstrap_servers=KAFKA_BROKER_URL,
                    group_id=group_id,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='earliest',
                    enable_auto_commit=True,
                    consumer_timeout_ms=1000,
                    api_version=(2, 0, 0)
                )
                logger.info(f" Kafka consumer created for topic '{topic}', group '{group_id}'")
                return consumer
            except NoBrokersAvailable:
                logger.warning(f"[Kafka Consumer] Broker no disponible. Reintentando ({attempt+1}/{max_retries})...")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                else:
                    logger.error(f" No se pudo crear consumer después de {max_retries} intentos")
                    raise
            except Exception as e:
                logger.error(f" Error creando consumer: {e}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                else:
                    raise
    
    def close(self):
        """Close Kafka producer"""
        if self.producer:
            self.producer.close()
            logger.info("🔐 Kafka producer closed")

# Global instance
kafka_client = KafkaClient()

# Convenience functions for backward compatibility
def create_producer(max_retries=50, delay=5):
    """Deprecated: Use kafka_client.producer instead"""
    return kafka_client.producer

def send_event(topic, event):
    """Send event using global kafka client"""
    return kafka_client.send_event(topic, event)

def get_consumer(topic, group_id):
    """Get consumer using global kafka client"""
    return kafka_client.get_consumer(topic, group_id)