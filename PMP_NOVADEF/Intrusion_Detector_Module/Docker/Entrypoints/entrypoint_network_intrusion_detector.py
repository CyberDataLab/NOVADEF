#!/usr/bin/env python3
"""Entrypoint: wires Kafka consumer/producer to the detection engines."""

import json
import logging
import time

from confluent_kafka import Consumer, KafkaError, Producer
from confluent_kafka.admin import AdminClient, NewTopic

from Scripts import config
from Scripts.alert_dedup_state import load_alert_dedup_state
from Scripts.detection_engines import FastFanInDetector, SlowPathState, process_event
from Scripts.event_extraction import normalize_event
from Scripts.isolation_forest_model import SprayingAnomalyModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("network_intrusion_detector")


def _kafka_consumer() -> Consumer:
    """Build the Kafka consumer for tshark/cic_flow input topics."""
    return Consumer(
        {
            "bootstrap.servers": config.KAFKA_BOOTSTRAP,
            "group.id": config.GROUP_ID,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
            "allow.auto.create.topics": True,
            # Default (300000ms) gets exceeded under the packet volume an
            # experiment attack generates, dropping the consumer from its
            # group; on reconnect it replays the backlog and attributes old
            # traffic's alerts to whatever run is current at that moment.
            "max.poll.interval.ms": 900000,
        }
    )


def _kafka_producer() -> Producer:
    """Build the Kafka producer used to publish detected alerts."""
    return Producer({"bootstrap.servers": config.KAFKA_BOOTSTRAP, "compression.type": "zstd"})


def _ensure_kafka_topics(topics: list[str]) -> None:
    """Create any of the given Kafka topics that do not exist yet."""
    try:
        admin = AdminClient({"bootstrap.servers": config.KAFKA_BOOTSTRAP})
        metadata = admin.list_topics(timeout=10)
        missing = [topic for topic in topics if topic not in metadata.topics]
        if not missing:
            return
        futures = admin.create_topics([NewTopic(topic, num_partitions=1, replication_factor=1) for topic in missing])
        for topic, future in futures.items():
            try:
                future.result(timeout=15)
                logger.info("Kafka topic ensured: %s", topic)
            except Exception as exc:
                # Topic may already exist or the broker raced the creation;
                # the consumer will retry with refreshed metadata regardless.
                logger.info("Kafka topic ensure skipped for %s: %s", topic, exc)
    except Exception as exc:
        logger.warning("Could not ensure Kafka topics: %s", exc)


def main() -> None:
    """Train the model (if enabled), subscribe to Kafka, and run the detection loop."""
    model = SprayingAnomalyModel()
    # Only train the Isolation Forest baseline when it will actually be used —
    # when the fast fan-in detector is primary, this ~500-batch synthetic
    # training is dead weight that just slows startup.
    if config.ISOLATION_FOREST_ENABLED:
        model.train()

    _ensure_kafka_topics([config.KAFKA_TOPIC_IN, config.KAFKA_TOPIC_FLOW_IN, config.KAFKA_TOPIC_OUT])
    consumer = _kafka_consumer()
    producer = _kafka_producer()
    # Passive network observation only: tshark (packets) always, and
    # CICFlowMeter (flows) only when the Isolation Forest is enabled — the
    # fan-in detector only needs raw packets.
    subscribe_topics = [config.KAFKA_TOPIC_IN]
    if config.ISOLATION_FOREST_ENABLED:
        subscribe_topics.append(config.KAFKA_TOPIC_FLOW_IN)
    consumer.subscribe(subscribe_topics)

    slow_path_state = SlowPathState()
    slow_path_state.alert_dedup_state = load_alert_dedup_state()
    fast_detector = FastFanInDetector() if config.FAST_FANIN_ENABLED else None

    logger.info("Listening on %s, publishing alerts to %s", config.KAFKA_TOPIC_IN, config.KAFKA_TOPIC_OUT)
    if fast_detector is not None:
        logger.info(
            "Fast fan-in detector ACTIVE (primary, window=%ss min_uniq_ips=%d min_pkts=%d)",
            config.FAST_FANIN_WINDOW_SECONDS, config.FAST_FANIN_MIN_UNIQUE_IPS, config.FAST_FANIN_MIN_SYN_PACKETS,
        )
    logger.info(
        "Isolation Forest %s",
        "ACTIVE (parallel enrichment)" if config.ISOLATION_FOREST_ENABLED else "DISABLED (fan-in detects; TAPCD profiles)",
    )

    while True:
        msg = consumer.poll(config.POLL_TIMEOUT_SECONDS)
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue
            logger.warning("Kafka error: %s", msg.error())
            continue

        try:
            payload = json.loads(msg.value().decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            logger.warning("Non-JSON message on %s", config.KAFKA_TOPIC_IN)
            continue

        event = normalize_event(payload, topic=msg.topic())
        if event is None:
            continue

        # Only feed tshark packet events to the fan-in detector; cic_flow
        # events are aggregated flows, not per-packet, and would double-count
        # against the sliding window.
        if fast_detector is not None and msg.topic() == config.KAFKA_TOPIC_IN:
            fast_detector.observe(event, producer)
        if config.ISOLATION_FOREST_ENABLED:
            process_event(event, time.time(), model, producer, slow_path_state)


if __name__ == "__main__":
    main()
