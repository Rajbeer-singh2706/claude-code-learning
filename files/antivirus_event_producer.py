"""
McAfee Kafka Producer – Antivirus Events
Sends events to MSK using IAM authentication (TLS + SASL/IAM)
"""

import json
import uuid
import time
import random
import logging
import os
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

import boto3
from kafka import KafkaProducer
from kafka.errors import KafkaError
from aws_msk_iam_sasl_signer import MSKAuthTokenProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcafee.producer")

# ── Config ────────────────────────────────────────────
ENV              = os.getenv("ENVIRONMENT", "dev")
BOOTSTRAP_SERVERS = os.getenv("MSK_BOOTSTRAP_SERVERS", "").split(",")
AWS_REGION       = os.getenv("AWS_REGION", "us-east-1")
TOPIC            = f"mcafee.antivirus.events.raw"
DLQ_TOPIC        = f"mcafee.dlq.events"
MAX_RETRIES      = 3
RETRY_BACKOFF    = 1.0


@dataclass
class AntivirusEvent:
    event_id:          str
    device_id:         str
    customer_id:       str
    event_timestamp:   str
    threat_name:       str
    threat_hash:       str
    severity:          str
    action_taken:      str
    detection_type:    str
    file_path:         str
    file_size_bytes:   int
    os_type:           str
    os_version:        str
    product_version:   str
    country_code:      str
    ip_address:        str
    ingestion_timestamp: str = None
    kafka_source:      str = "ENDPOINT_AGENT"
    schema_version:    str = "1.0"

    def __post_init__(self):
        if not self.ingestion_timestamp:
            self.ingestion_timestamp = datetime.now(timezone.utc).isoformat()


class McAfeeProducer:
    def __init__(self):
        self.producer = self._create_producer()
        self.success_count = 0
        self.failure_count = 0

    def _oauth_token_provider(self):
        """IAM token provider for MSK authentication"""
        token, expiry = MSKAuthTokenProvider.generate_auth_token(AWS_REGION)
        return token, expiry

    def _create_producer(self) -> KafkaProducer:
        return KafkaProducer(
            bootstrap_servers=BOOTSTRAP_SERVERS,
            security_protocol="SASL_SSL",
            sasl_mechanism="OAUTHBEARER",
            sasl_oauth_token_provider=self._oauth_token_provider,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            acks="all",
            retries=MAX_RETRIES,
            retry_backoff_ms=int(RETRY_BACKOFF * 1000),
            max_in_flight_requests_per_connection=5,
            compression_type="lz4",
            batch_size=65536,
            linger_ms=10,
            buffer_memory=67108864,
            enable_idempotence=True,
            # Schema headers
            request_timeout_ms=30000,
            metadata_max_age_ms=60000,
        )

    def send_event(self, event: AntivirusEvent, partition_key: Optional[str] = None) -> bool:
        """Send a single event with retry logic"""
        key  = partition_key or event.device_id
        data = asdict(event)

        for attempt in range(MAX_RETRIES):
            try:
                future = self.producer.send(
                    TOPIC,
                    key=key,
                    value=data,
                    headers=[
                        ("schema_version", b"1.0"),
                        ("environment",    ENV.encode()),
                        ("source",         b"ENDPOINT_AGENT"),
                        ("content_type",   b"application/json"),
                    ]
                )
                record_metadata = future.get(timeout=10)
                self.success_count += 1
                logger.debug(
                    f"Sent event {event.event_id} → "
                    f"partition={record_metadata.partition} offset={record_metadata.offset}"
                )
                return True

            except KafkaError as e:
                logger.warning(f"Attempt {attempt+1}/{MAX_RETRIES} failed: {e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_BACKOFF * (2 ** attempt))
                else:
                    self._send_to_dlq(data, str(e))
                    self.failure_count += 1
                    return False

    def _send_to_dlq(self, event_data: dict, error: str):
        """Route failed events to Dead Letter Queue"""
        dlq_payload = {
            "original_event": event_data,
            "error":          error,
            "failed_at":      datetime.now(timezone.utc).isoformat(),
            "topic":          TOPIC,
        }
        try:
            self.producer.send(DLQ_TOPIC, value=dlq_payload)
            logger.warning(f"Event routed to DLQ: {event_data.get('event_id')}")
        except Exception as dlq_err:
            logger.error(f"DLQ send failed: {dlq_err}")

    def send_batch(self, events: list[AntivirusEvent]) -> dict:
        """Send a batch of events and return stats"""
        for event in events:
            self.send_event(event)
        self.producer.flush()
        return {
            "total":    len(events),
            "success":  self.success_count,
            "failures": self.failure_count,
        }

    def close(self):
        self.producer.flush()
        self.producer.close()
        logger.info(f"Producer closed. Success: {self.success_count}, Failures: {self.failure_count}")


# ── Sample Event Generator (for testing) ─────────────
THREATS = [
    ("Trojan.GenericKD.12345",  "HIGH",     "TROJAN"),
    ("Ransomware.WannaCrypt",   "CRITICAL", "RANSOMWARE"),
    ("Spyware.Agent.Generic",   "MEDIUM",   "SPYWARE"),
    ("Adware.Elex.ShrtCln",     "LOW",      "ADWARE"),
    ("Worm.Generic.123",        "HIGH",     "WORM"),
    ("Virus.Win32.Sality",      "CRITICAL", "VIRUS"),
]

OS_VERSIONS = {
    "WINDOWS": ["10.0.19044", "11.0.22000", "10.0.17763"],
    "MACOS":   ["13.5.1",    "14.0.0",     "12.6.8"],
    "LINUX":   ["Ubuntu 22.04", "RHEL 8.7", "Debian 11"],
}


def generate_test_event() -> AntivirusEvent:
    threat, severity, _ = random.choice(THREATS)
    os_type = random.choice(list(OS_VERSIONS.keys()))
    return AntivirusEvent(
        event_id=str(uuid.uuid4()),
        device_id=f"DEV-{uuid.uuid4().hex[:8].upper()}",
        customer_id=f"CUST-{random.randint(1000, 9999)}",
        event_timestamp=datetime.now(timezone.utc).isoformat(),
        threat_name=threat,
        threat_hash=uuid.uuid4().hex,
        severity=severity,
        action_taken=random.choice(["QUARANTINE", "DELETE", "BLOCK", "ALLOW"]),
        detection_type=random.choice(["SIGNATURE", "HEURISTIC", "BEHAVIORAL", "MACHINE_LEARNING"]),
        file_path=f"C:\\Users\\user\\Downloads\\{threat.replace('.', '_')}.exe",
        file_size_bytes=random.randint(1024, 10485760),
        os_type=os_type,
        os_version=random.choice(OS_VERSIONS[os_type]),
        product_version="24.1.0.4",
        country_code=random.choice(["US", "DE", "GB", "IN", "BR", "JP", "AU"]),
        ip_address=f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
    )


if __name__ == "__main__":
    logger.info(f"Starting McAfee Kafka Producer | ENV={ENV} | Topic={TOPIC}")
    producer = McAfeeProducer()

    try:
        batch_size = 100
        while True:
            events = [generate_test_event() for _ in range(batch_size)]
            stats  = producer.send_batch(events)
            logger.info(f"Batch sent: {stats}")
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Stopping producer...")
    finally:
        producer.close()
