#!/usr/bin/env python3
"""
Kafka to Redis Streams worker with dynamic topic discovery and memory management.

Consumes messages from Kafka topics, resolves the effective producer topic map
from MongoDB Configuration Manager when available, stores payloads in Redis
Streams, and maintains a discovery catalog for the Near Real-Time Data
Retrieval API.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

import redis
from confluent_kafka import Consumer, KafkaError
from confluent_kafka.admin import AdminClient
from pymongo import MongoClient
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError
from worker_kafka_bootstrap_helpers import (
    commit_group_offsets,
    consume_new_topic_bootstrap,
    find_partitions_without_group_offsets,
)
from worker_payload_helpers import (
    extract_machine_id_from_payload_dict,
    parse_json_bytes,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Kafka configuration
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_DOCKER") or os.getenv("KAFKA_BOOTSTRAP")
KTRW_KAFKA_GROUP_ID = os.getenv("KTRW_KAFKA_GROUP_ID")
KTRW_KAFKA_AUTO_OFFSET_RESET = os.getenv("KTRW_KAFKA_AUTO_OFFSET_RESET")
KTRW_KAFKA_ENABLE_AUTO_COMMIT = (
    os.getenv("KTRW_KAFKA_ENABLE_AUTO_COMMIT", "true").lower() == "true"
)
KTRW_KAFKA_TOPIC_REFRESH_INTERVAL = int(
    os.getenv("KTRW_KAFKA_TOPIC_REFRESH_INTERVAL", "30")
)
KTRW_CM_TOPICS_REFRESH_INTERVAL = int(
    os.getenv("KTRW_CM_TOPICS_REFRESH_INTERVAL", "30")
)
KTRW_NEW_TOPIC_BOOTSTRAP_MAX_MESSAGES = int(
    os.getenv("KTRW_NEW_TOPIC_BOOTSTRAP_MAX_MESSAGES", "10")
)

# Redis configuration
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

# MongoDB CM topic resolution configuration
MONGO_CM_URI = (
    os.getenv("MONGO_CM_URI_DOCKER")
    or os.getenv("MONGO_CM_URI")
    or os.getenv("MONGO_CM_URI_HOST")
)
MONGO_CM_DB = "configuration_manager"
KAFKA_TOPICS_DOC_ID = "kafka_topics"
KTRW_TOPIC_MAP_CACHE_FILE = os.getenv(
    "KTRW_TOPIC_MAP_CACHE_FILE",
    "/home/redis_worker/topic_map_cache.json",
)

# Stream configuration
KTRW_REDIS_MAX_STREAM_LENGTH = int(os.getenv("KTRW_REDIS_MAX_STREAM_LENGTH", "1000"))
KTRW_REDIS_STREAM_TTL_SECONDS = int(
    os.getenv("KTRW_REDIS_STREAM_TTL_SECONDS", "21600")
)

# Memory management configuration
KTRW_REDIS_CLEANUP_INTERVAL = int(os.getenv("KTRW_REDIS_CLEANUP_INTERVAL", "300"))
KTRW_REDIS_RETENTION_HOURS = int(os.getenv("KTRW_REDIS_RETENTION_HOURS", "2"))
KTRW_REDIS_EMERGENCY_RETENTION_HOURS = int(
    os.getenv("KTRW_REDIS_EMERGENCY_RETENTION_HOURS", "1")
)
KTRW_REDIS_MEMORY_THRESHOLD = float(
    os.getenv("KTRW_REDIS_MEMORY_THRESHOLD", "0.85")
)

# Topic defaults from environment
TELEGRAF_BASE_TOPIC = os.getenv("TELEGRAF_BASE_TOPIC", "telegraf_metrics")
FLUENTD_SYSLOG_BASE_TOPIC = os.getenv("FLUENTD_SYSLOG_BASE_TOPIC", "syslog_logs")
FLUENTD_SYSTEMD_BASE_TOPIC = os.getenv(
    "FLUENTD_SYSTEMD_BASE_TOPIC",
    "systemd_logs",
)
FALCO_BASE_TOPIC = os.getenv("FALCO_BASE_TOPIC", "falco_events")
TSHARK_BASE_TOPIC = os.getenv("TSHARK_BASE_TOPIC", "tshark_traces")
SNORT_KAFKA_TOPIC_OUT = os.getenv("SNORT_KAFKA_TOPIC_OUT", "snort_alerts")
CIC_KAFKA_BASE_TOPIC_OUT = os.getenv("CIC_KAFKA_BASE_TOPIC_OUT", "cic_flow")

# Catalog constants
GLOBAL_MACHINE_ID = "global"
NRTDR_STREAM_CATALOG_KEY = "nrtdr:streams"
NRTDR_META_PREFIX = "nrtdr:stream:"
NRTDR_DATA_TYPE_PREFIX = "nrtdr:data_type:"
NRTDR_MACHINE_PREFIX = "nrtdr:machine:"


@dataclass(frozen=True)
class TopicSpec:
    topic_var: str
    data_type: str
    match_prefix: bool
    expects_machine_id: bool


@dataclass(frozen=True)
class TopicDescriptor:
    topic_var: str
    topic_name: str
    data_type: str
    match_prefix: bool
    expects_machine_id: bool


TOPIC_SPECS = [
    TopicSpec(
        topic_var="TELEGRAF_BASE_TOPIC",
        data_type="health_metrics",
        match_prefix=True,
        expects_machine_id=True,
    ),
    TopicSpec(
        topic_var="FLUENTD_SYSLOG_BASE_TOPIC",
        data_type="logs",
        match_prefix=True,
        expects_machine_id=True,
    ),
    TopicSpec(
        topic_var="FLUENTD_SYSTEMD_BASE_TOPIC",
        data_type="logs",
        match_prefix=True,
        expects_machine_id=True,
    ),
    TopicSpec(
        topic_var="FALCO_BASE_TOPIC",
        data_type="security_logs",
        match_prefix=True,
        expects_machine_id=True,
    ),
    TopicSpec(
        topic_var="TSHARK_BASE_TOPIC",
        data_type="network_traces",
        match_prefix=True,
        expects_machine_id=False,
    ),
    TopicSpec(
        topic_var="SNORT_KAFKA_TOPIC_OUT",
        data_type="security_alerts",
        match_prefix=False,
        expects_machine_id=False,
    ),
    TopicSpec(
        topic_var="CIC_KAFKA_BASE_TOPIC_OUT",
        data_type="network_flows",
        match_prefix=False,
        expects_machine_id=False,
    ),
]

DEFAULT_TOPIC_VALUES = {
    "TELEGRAF_BASE_TOPIC": TELEGRAF_BASE_TOPIC,
    "FLUENTD_SYSLOG_BASE_TOPIC": FLUENTD_SYSLOG_BASE_TOPIC,
    "FLUENTD_SYSTEMD_BASE_TOPIC": FLUENTD_SYSTEMD_BASE_TOPIC,
    "FALCO_BASE_TOPIC": FALCO_BASE_TOPIC,
    "TSHARK_BASE_TOPIC": TSHARK_BASE_TOPIC,
    "SNORT_KAFKA_TOPIC_OUT": SNORT_KAFKA_TOPIC_OUT,
    "CIC_KAFKA_BASE_TOPIC_OUT": CIC_KAFKA_BASE_TOPIC_OUT,
}


shutdown_flag = False
pause_consumption_flag = False
topic_state_lock = threading.Lock()
current_topic_values: Dict[str, str] = dict(DEFAULT_TOPIC_VALUES)
current_topic_descriptors = []
last_topic_resolution_source = "defaults"


def build_topic_descriptors(topic_values: Dict[str, str]) -> list[TopicDescriptor]:
    descriptors: list[TopicDescriptor] = []
    for spec in TOPIC_SPECS:
        topic_name = str(topic_values.get(spec.topic_var, "")).strip()
        if not topic_name:
            continue
        descriptors.append(
            TopicDescriptor(
                topic_var=spec.topic_var,
                topic_name=topic_name,
                data_type=spec.data_type,
                match_prefix=spec.match_prefix,
                expects_machine_id=spec.expects_machine_id,
            )
        )
    return descriptors


def ensure_cache_directory() -> None:
    cache_path = Path(KTRW_TOPIC_MAP_CACHE_FILE)
    cache_path.parent.mkdir(parents=True, exist_ok=True)


def save_topic_map_cache(topic_values: Dict[str, str], source: str) -> None:
    try:
        ensure_cache_directory()
        payload = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "topics": topic_values,
        }
        Path(KTRW_TOPIC_MAP_CACHE_FILE).write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("⚠️  Could not write topic map cache: %s", exc)


def load_topic_map_cache() -> Dict[str, str]:
    cache_path = Path(KTRW_TOPIC_MAP_CACHE_FILE)
    if not cache_path.exists():
        return {}

    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        topics = payload.get("topics", {})
        if not isinstance(topics, dict):
            return {}
        return {
            topic_var: str(topic_name)
            for topic_var, topic_name in topics.items()
            if topic_var in DEFAULT_TOPIC_VALUES and str(topic_name).strip()
        }
    except Exception as exc:
        logger.warning("⚠️  Could not read topic map cache: %s", exc)
        return {}


def fetch_kafka_topics_from_mongo() -> Optional[Dict[str, str]]:
    if not MONGO_CM_URI:
        return None

    try:
        client = MongoClient(MONGO_CM_URI, serverSelectionTimeoutMS=2000)
        try:
            collection = client[MONGO_CM_DB]["deployments"]
            doc = collection.find_one({"_id": KAFKA_TOPICS_DOC_ID})
        finally:
            client.close()

        if doc is None:
            return {}

        doc.pop("_id", None)
        doc.pop("updated_at", None)
        return {
            topic_var: str(topic_name)
            for topic_var, topic_name in doc.items()
            if topic_var in DEFAULT_TOPIC_VALUES and str(topic_name).strip()
        }
    except (ServerSelectionTimeoutError, PyMongoError) as exc:
        logger.warning("⚠️  MongoDB CM topic map unavailable: %s", exc)
        return None
    except Exception as exc:
        logger.warning("⚠️  Unexpected error reading topic map from MongoDB CM: %s", exc)
        return None


def resolve_topic_values_from_sources() -> Tuple[Dict[str, str], str]:
    mongo_topics = fetch_kafka_topics_from_mongo()
    if mongo_topics is not None:
        resolved = dict(DEFAULT_TOPIC_VALUES)
        resolved.update(mongo_topics)
        if mongo_topics:
            save_topic_map_cache(resolved, "mongo")
            return resolved, "mongo"
        logger.info("ℹ️  MongoDB CM topic map is reachable but empty; using defaults")
        return resolved, "defaults"

    cached_topics = load_topic_map_cache()
    if cached_topics:
        resolved = dict(DEFAULT_TOPIC_VALUES)
        resolved.update(cached_topics)
        logger.info("ℹ️  Using cached Kafka topic map from %s", KTRW_TOPIC_MAP_CACHE_FILE)
        return resolved, "cache"

    return dict(DEFAULT_TOPIC_VALUES), "defaults"


def update_topic_resolution(force_log: bool = False) -> Tuple[Dict[str, str], str, bool]:
    global current_topic_values, current_topic_descriptors, last_topic_resolution_source

    resolved_values, source = resolve_topic_values_from_sources()
    changed = False

    with topic_state_lock:
        if resolved_values != current_topic_values:
            current_topic_values = resolved_values
            current_topic_descriptors = build_topic_descriptors(resolved_values)
            changed = True
        elif not current_topic_descriptors:
            current_topic_descriptors = build_topic_descriptors(resolved_values)

        last_topic_resolution_source = source

    if changed or force_log:
        logger.info("🗺️  Effective Kafka topic map source: %s", source)
        logger.info("🗺️  Effective Kafka topic map: %s", resolved_values)

    return resolved_values, source, changed


def get_topic_descriptors_snapshot() -> list[TopicDescriptor]:
    with topic_state_lock:
        return list(current_topic_descriptors)


def get_topic_descriptor(topic: str, *, log_missing: bool = True) -> Optional[TopicDescriptor]:
    for descriptor in get_topic_descriptors_snapshot():
        if descriptor.match_prefix and topic.startswith(descriptor.topic_name):
            return descriptor
        if not descriptor.match_prefix and topic == descriptor.topic_name:
            return descriptor
    if log_missing:
        logger.warning("⚠️  No topic descriptor found for topic: %s", topic)
    return None


def create_kafka_consumer() -> Consumer:
    config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": KTRW_KAFKA_GROUP_ID,
        "auto.offset.reset": KTRW_KAFKA_AUTO_OFFSET_RESET,
        "enable.auto.commit": KTRW_KAFKA_ENABLE_AUTO_COMMIT,
        "allow.auto.create.topics": False,
        "enable.partition.eof": False,
        "partition.assignment.strategy": "cooperative-sticky",
        "session.timeout.ms": 10000,
        "max.poll.interval.ms": 300000,
        "socket.keepalive.enable": True,
    }
    consumer = Consumer(config)
    logger.info("📡 Kafka consumer created with bootstrap: %s", KAFKA_BOOTSTRAP)
    return consumer


def create_kafka_admin_client() -> AdminClient:
    return AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP})


def create_redis_client() -> redis.Redis:
    try:
        redis_password = REDIS_PASSWORD if REDIS_PASSWORD else None
        client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=redis_password,
            decode_responses=False,
            socket_keepalive=True,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        client.ping()
        logger.info("✅ Connected to Redis at %s:%s/%s", REDIS_HOST, REDIS_PORT, REDIS_DB)
        return client
    except redis.ConnectionError as exc:
        logger.error("❌ Failed to connect to Redis: %s", exc)
        sys.exit(1)


def discover_matching_topics(admin_client: AdminClient) -> Set[str]:
    descriptors = get_topic_descriptors_snapshot()
    if not descriptors:
        return set()

    try:
        metadata = admin_client.list_topics(timeout=10)
        matching_topics = set()
        for topic in metadata.topics.keys():
            for descriptor in descriptors:
                if descriptor.match_prefix and topic.startswith(descriptor.topic_name):
                    matching_topics.add(topic)
                    break
                if not descriptor.match_prefix and topic == descriptor.topic_name:
                    matching_topics.add(topic)
                    break
        return matching_topics
    except Exception as exc:
        logger.error("❌ Error discovering topics: %s", exc)
        return set()


def bootstrap_new_topic(
    admin_client: AdminClient,
    redis_client: redis.Redis,
    topic: str,
) -> None:
    bootstrap_partitions = find_partitions_without_group_offsets(
        admin_client=admin_client,
        group_id=KTRW_KAFKA_GROUP_ID,
        topic=topic,
    )
    if not bootstrap_partitions:
        logger.info("ℹ️  Topic %s already has committed offsets for group %s", topic, KTRW_KAFKA_GROUP_ID)
        return

    logger.info(
        "🚀 Running initial bootstrap for new topic %s on %s partition(s), max %s messages/partition",
        topic,
        len(bootstrap_partitions),
        KTRW_NEW_TOPIC_BOOTSTRAP_MAX_MESSAGES,
    )

    records, committed_offsets = consume_new_topic_bootstrap(
        admin_client=admin_client,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        topic=topic,
        topic_partitions=bootstrap_partitions,
        max_messages_per_partition=KTRW_NEW_TOPIC_BOOTSTRAP_MAX_MESSAGES,
    )

    pushed = 0
    for record in records:
        descriptor = get_topic_descriptor(record.topic, log_missing=False)
        if descriptor is None:
            continue
        machine_id = extract_machine_id(record.value, descriptor)
        if push_to_redis(
            redis_client=redis_client,
            descriptor=descriptor,
            machine_id=machine_id,
            message_bytes=record.value,
            topic=record.topic,
        ):
            pushed += 1

    commit_group_offsets(
        admin_client=admin_client,
        group_id=KTRW_KAFKA_GROUP_ID,
        topic_partitions=committed_offsets,
    )
    logger.info(
        "✅ New topic bootstrap completed for %s: bootstrapped=%s, committed_partitions=%s",
        topic,
        pushed,
        len(committed_offsets),
    )


def topic_discovery_worker(
    consumer: Consumer,
    admin_client: AdminClient,
    redis_client: redis.Redis,
) -> None:
    global shutdown_flag

    logger.info(
        "🔍 Topic discovery worker started (Kafka refresh: %ss, CM refresh: %ss)",
        KTRW_KAFKA_TOPIC_REFRESH_INTERVAL,
        KTRW_CM_TOPICS_REFRESH_INTERVAL,
    )
    current_topics: Set[str] = set()
    last_cm_refresh = 0.0

    while not shutdown_flag:
        try:
            now = time.time()
            if now - last_cm_refresh >= KTRW_CM_TOPICS_REFRESH_INTERVAL:
                _, _, topic_map_changed = update_topic_resolution()
                last_cm_refresh = now
                if topic_map_changed:
                    current_topics = set()

            discovered_topics = discover_matching_topics(admin_client)
            if discovered_topics != current_topics:
                new_topics = discovered_topics - current_topics
                removed_topics = current_topics - discovered_topics

                if new_topics:
                    logger.info("➕ New topics discovered: %s", new_topics)
                    for topic in sorted(new_topics):
                        try:
                            bootstrap_new_topic(
                                admin_client=admin_client,
                                redis_client=redis_client,
                                topic=topic,
                            )
                        except Exception as exc:
                            logger.error("❌ Error bootstrapping newly discovered topic %s: %s", topic, exc)
                if removed_topics:
                    logger.info("➖ Topics removed: %s", removed_topics)

                if discovered_topics:
                    consumer.subscribe(list(discovered_topics))
                    logger.info("📡 Subscribed to %s topics", len(discovered_topics))
                    current_topics = discovered_topics
                else:
                    logger.warning(
                        "⚠️  No matching topics found, keeping previous subscription"
                    )
            time.sleep(KTRW_KAFKA_TOPIC_REFRESH_INTERVAL)
        except Exception as exc:
            logger.error("❌ Error in topic discovery worker: %s", exc)
            time.sleep(KTRW_KAFKA_TOPIC_REFRESH_INTERVAL)

    logger.info("🛑 Topic discovery worker stopped")


def get_redis_memory_usage(redis_client: redis.Redis) -> Tuple[float, int, int]:
    try:
        info = redis_client.info("memory")
        used_memory = info.get("used_memory", 0)
        max_memory = info.get("maxmemory", 0)
        if max_memory == 0:
            return 0.0, used_memory, 0
        return used_memory / max_memory, used_memory, max_memory
    except Exception as exc:
        logger.error("❌ Error getting Redis memory info: %s", exc)
        return 0.0, 0, 0


def extract_machine_id(
    message_bytes: bytes,
    descriptor: TopicDescriptor,
) -> Optional[str]:
    if not descriptor.expects_machine_id:
        return None

    try:
        data = parse_json_bytes(message_bytes)
        machine_id = extract_machine_id_from_payload_dict(data)
        if machine_id:
            return machine_id

        logger.warning(
            "⚠️  No machine_id found in message for topic var %s; using global stream",
            descriptor.topic_var,
        )
        return None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning(
            "⚠️  Failed to parse message for machine_id extraction from %s: %s",
            descriptor.topic_var,
            exc,
        )
        return None
    except Exception as exc:
        logger.error(
            "❌ Error extracting machine_id from topic %s: %s",
            descriptor.topic_var,
            exc,
        )
        return None


def get_stream_key(data_type: str, machine_id: Optional[str]) -> str:
    return f"{data_type}:{machine_id or GLOBAL_MACHINE_ID}"


def get_stream_meta_key(stream_key: str) -> str:
    return f"{NRTDR_META_PREFIX}{stream_key}:meta"


def get_data_type_index_key(data_type: str) -> str:
    return f"{NRTDR_DATA_TYPE_PREFIX}{data_type}:streams"


def get_machine_index_key(machine_id: str) -> str:
    return f"{NRTDR_MACHINE_PREFIX}{machine_id}:streams"


def register_stream_catalog_entry(
    redis_client: redis.Redis,
    descriptor: TopicDescriptor,
    stream_key: str,
    effective_machine_id: str,
    topic: str,
    ingested_at: str,
    last_redis_stream_id: str,
    is_global: str,
) -> None:
    meta_key = get_stream_meta_key(stream_key)
    data_type_index_key = get_data_type_index_key(descriptor.data_type)
    machine_index_key = get_machine_index_key(effective_machine_id)

    first_seen = redis_client.hget(meta_key, "first_seen")
    existing_source_topics = redis_client.hget(meta_key, "source_topics")
    existing_topic_vars = redis_client.hget(meta_key, "topic_vars")

    source_topics = {topic}
    topic_vars = {descriptor.topic_var}

    if existing_source_topics:
        try:
            decoded_source_topics = json.loads(existing_source_topics.decode("utf-8"))
            if isinstance(decoded_source_topics, list):
                source_topics.update(str(item) for item in decoded_source_topics if str(item).strip())
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    if existing_topic_vars:
        try:
            decoded_topic_vars = json.loads(existing_topic_vars.decode("utf-8"))
            if isinstance(decoded_topic_vars, list):
                topic_vars.update(str(item) for item in decoded_topic_vars if str(item).strip())
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    meta_mapping = {
        "stream_key": stream_key,
        "data_type": descriptor.data_type,
        "machine_id": effective_machine_id,
        "last_topic_var": descriptor.topic_var,
        "last_source_topic": topic,
        "topic_var": descriptor.topic_var,
        "source_topic": topic,
        "topic_vars": json.dumps(sorted(topic_vars)),
        "source_topics": json.dumps(sorted(source_topics)),
        "last_seen": ingested_at,
        "last_redis_stream_id": last_redis_stream_id,
        "is_global": is_global,
    }
    if first_seen is None:
        meta_mapping["first_seen"] = ingested_at

    with redis_client.pipeline(transaction=False) as pipe:
        pipe.sadd(NRTDR_STREAM_CATALOG_KEY, stream_key)
        pipe.sadd(data_type_index_key, stream_key)
        pipe.sadd(machine_index_key, stream_key)
        pipe.hset(meta_key, mapping=meta_mapping)
        pipe.execute()


def push_to_redis(
    redis_client: redis.Redis,
    descriptor: TopicDescriptor,
    machine_id: Optional[str],
    message_bytes: bytes,
    topic: str,
) -> bool:
    stream_key = get_stream_key(descriptor.data_type, machine_id)
    effective_machine_id = machine_id or GLOBAL_MACHINE_ID
    ingested_at = datetime.now(timezone.utc).isoformat()
    is_global = "true" if machine_id is None else "false"

    fields = {
        "payload": message_bytes,
        "source_topic": topic,
        "data_type": descriptor.data_type,
        "machine_id": effective_machine_id,
        "ingested_at": ingested_at,
    }

    try:
        last_redis_stream_id = redis_client.xadd(
            stream_key,
            fields,
            maxlen=KTRW_REDIS_MAX_STREAM_LENGTH,
            approximate=True,
        )
        if isinstance(last_redis_stream_id, bytes):
            last_redis_stream_id_value = last_redis_stream_id.decode("utf-8")
        else:
            last_redis_stream_id_value = str(last_redis_stream_id)
        redis_client.expire(stream_key, KTRW_REDIS_STREAM_TTL_SECONDS)
        register_stream_catalog_entry(
            redis_client=redis_client,
            descriptor=descriptor,
            stream_key=stream_key,
            effective_machine_id=effective_machine_id,
            topic=topic,
            ingested_at=ingested_at,
            last_redis_stream_id=last_redis_stream_id_value,
            is_global=is_global,
        )
        return True
    except redis.RedisError as exc:
        logger.error("❌ Redis error pushing to %s: %s", stream_key, exc)
        return False
    except Exception as exc:
        logger.error("❌ Unexpected error pushing to Redis stream %s: %s", stream_key, exc)
        return False


def cleanup_old_messages(redis_client: redis.Redis, retention_hours: int) -> Dict[str, int]:
    stats = {
        "streams_processed": 0,
        "messages_deleted": 0,
        "errors": 0,
    }
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
    cutoff_ms = int(cutoff_time.timestamp() * 1000)
    min_stream_id = f"{cutoff_ms}-0"

    try:
        all_streams = redis_client.smembers(NRTDR_STREAM_CATALOG_KEY)
        for stream_bytes in all_streams:
            stream_key = stream_bytes.decode("utf-8")
            try:
                if not redis_client.exists(stream_key):
                    continue
                removed = redis_client.xtrim(
                    stream_key,
                    minid=min_stream_id,
                    approximate=False,
                )
                stats["streams_processed"] += 1
                stats["messages_deleted"] += int(removed or 0)
            except Exception as exc:
                logger.error("❌ Error cleaning stream %s: %s", stream_key, exc)
                stats["errors"] += 1
        return stats
    except Exception as exc:
        logger.error("❌ Error in cleanup_old_messages: %s", exc)
        stats["errors"] += 1
        return stats


def memory_management_worker(redis_client: redis.Redis) -> None:
    global shutdown_flag, pause_consumption_flag

    logger.info(
        "🧹 Memory management worker started (interval: %ss)",
        KTRW_REDIS_CLEANUP_INTERVAL,
    )
    logger.info(
        "📊 Retention: %sh, Emergency: %sh, Threshold: %s%%",
        KTRW_REDIS_RETENTION_HOURS,
        KTRW_REDIS_EMERGENCY_RETENTION_HOURS,
        KTRW_REDIS_MEMORY_THRESHOLD * 100,
    )

    while not shutdown_flag:
        try:
            usage_ratio, used_bytes, max_bytes = get_redis_memory_usage(redis_client)
            used_mb = used_bytes / (1024 * 1024)
            max_mb = max_bytes / (1024 * 1024) if max_bytes else 0.0
            logger.info(
                "💾 Redis memory: %.1fMB / %.1fMB (%.1f%%)",
                used_mb,
                max_mb,
                usage_ratio * 100,
            )

            if usage_ratio >= KTRW_REDIS_MEMORY_THRESHOLD:
                logger.warning(
                    "⚠️  Memory threshold exceeded (%.1f%% >= %.1f%%)",
                    usage_ratio * 100,
                    KTRW_REDIS_MEMORY_THRESHOLD * 100,
                )
                logger.warning(
                    "🚨 EMERGENCY CLEANUP: Pausing consumption and trimming stream entries older than %sh",
                    KTRW_REDIS_EMERGENCY_RETENTION_HOURS,
                )
                pause_consumption_flag = True
                time.sleep(2)
                stats = cleanup_old_messages(
                    redis_client,
                    KTRW_REDIS_EMERGENCY_RETENTION_HOURS,
                )
                logger.info(
                    "🧹 Emergency cleanup: %s entries deleted from %s streams",
                    stats["messages_deleted"],
                    stats["streams_processed"],
                )
                pause_consumption_flag = False
                logger.info("▶️  Consumption resumed after emergency cleanup")
            else:
                logger.info(
                    "🧹 Regular cleanup: trimming stream entries older than %sh",
                    KTRW_REDIS_RETENTION_HOURS,
                )
                stats = cleanup_old_messages(redis_client, KTRW_REDIS_RETENTION_HOURS)
                logger.info(
                    "🧹 Cleanup complete: %s entries deleted from %s streams",
                    stats["messages_deleted"],
                    stats["streams_processed"],
                )

            time.sleep(KTRW_REDIS_CLEANUP_INTERVAL)
        except Exception as exc:
            logger.error("❌ Error in memory management worker: %s", exc)
            time.sleep(KTRW_REDIS_CLEANUP_INTERVAL)

    logger.info("🛑 Memory management worker stopped")


def main() -> None:
    global shutdown_flag, pause_consumption_flag

    logger.info("🚀 Starting Kafka -> Redis Streams worker")
    logger.info("📋 Configuration:")
    logger.info("   - Kafka: %s", KAFKA_BOOTSTRAP)
    logger.info("   - Redis: %s:%s/%s", REDIS_HOST, REDIS_PORT, REDIS_DB)
    logger.info("   - MongoDB CM URI present: %s", "yes" if MONGO_CM_URI else "no")
    logger.info("   - Topic cache file: %s", KTRW_TOPIC_MAP_CACHE_FILE)
    logger.info(
        "   - Stream TTL: %ss (%.1fh)",
        KTRW_REDIS_STREAM_TTL_SECONDS,
        KTRW_REDIS_STREAM_TTL_SECONDS / 3600,
    )
    logger.info("   - Max stream length: %s", KTRW_REDIS_MAX_STREAM_LENGTH)
    logger.info("   - Retention: %sh", KTRW_REDIS_RETENTION_HOURS)
    logger.info("   - Kafka topic refresh: %ss", KTRW_KAFKA_TOPIC_REFRESH_INTERVAL)
    logger.info("   - CM topic refresh: %ss", KTRW_CM_TOPICS_REFRESH_INTERVAL)
    logger.info(
        "   - New topic bootstrap max messages/partition: %s",
        KTRW_NEW_TOPIC_BOOTSTRAP_MAX_MESSAGES,
    )

    kafka_consumer = create_kafka_consumer()
    kafka_admin = create_kafka_admin_client()
    redis_client = create_redis_client()

    update_topic_resolution(force_log=True)

    logger.info("🔍 Initial topic discovery...")
    initial_topics = discover_matching_topics(kafka_admin)
    if initial_topics:
        kafka_consumer.subscribe(list(initial_topics))
        logger.info("📡 Subscribed to %s topics: %s", len(initial_topics), initial_topics)
    else:
        logger.warning("⚠️  No matching topics found on startup")

    topic_discovery_thread = threading.Thread(
        target=topic_discovery_worker,
        args=(kafka_consumer, kafka_admin, redis_client),
        daemon=True,
    )
    topic_discovery_thread.start()

    memory_management_thread = threading.Thread(
        target=memory_management_worker,
        args=(redis_client,),
        daemon=True,
    )
    memory_management_thread.start()

    def signal_handler(signum, frame):  # type: ignore[unused-argument]
        global shutdown_flag
        logger.info("🛑 Received signal %s, shutting down gracefully...", signum)
        shutdown_flag = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    stats = {
        "processed": 0,
        "pushed": 0,
        "failed": 0,
        "paused": 0,
        "by_data_type": defaultdict(int),
    }
    last_stats_log = time.time()
    stats_log_interval = 60

    try:
        logger.info("✅ Worker ready, waiting for messages...")
        while not shutdown_flag:
            if pause_consumption_flag:
                stats["paused"] += 1
                time.sleep(0.1)
                continue

            msg = kafka_consumer.poll(timeout=1.0)
            if msg is None:
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error("❌ Kafka error: %s", msg.error())
                continue

            stats["processed"] += 1
            topic = msg.topic()
            message_bytes = msg.value()
            descriptor = get_topic_descriptor(topic)

            if descriptor is None:
                stats["failed"] += 1
                kafka_consumer.commit(msg)
                continue

            machine_id = extract_machine_id(message_bytes, descriptor)
            success = push_to_redis(
                redis_client,
                descriptor,
                machine_id,
                message_bytes,
                topic,
            )

            if success:
                stats["pushed"] += 1
                stats["by_data_type"][descriptor.data_type] += 1
            else:
                stats["failed"] += 1

            kafka_consumer.commit(msg)

            if time.time() - last_stats_log >= stats_log_interval:
                logger.info(
                    "📊 Stats (last %ss): Processed=%s, Pushed=%s, Failed=%s, Paused=%s",
                    stats_log_interval,
                    stats["processed"],
                    stats["pushed"],
                    stats["failed"],
                    stats["paused"],
                )
                logger.info("📊 By data_type: %s", dict(stats["by_data_type"]))
                last_stats_log = time.time()
    except KeyboardInterrupt:
        logger.info("🛑 Keyboard interrupt received")
    except Exception as exc:
        logger.error("❌ Fatal error in worker loop: %s", exc, exc_info=True)
    finally:
        logger.info(
            "📊 Final stats: Processed=%s, Pushed=%s, Failed=%s",
            stats["processed"],
            stats["pushed"],
            stats["failed"],
        )
        logger.info("📊 By data_type: %s", dict(stats["by_data_type"]))
        logger.info("🔌 Closing connections...")
        kafka_consumer.close()
        redis_client.close()
        logger.info("✅ Worker shutdown complete")


if __name__ == "__main__":
    main()
