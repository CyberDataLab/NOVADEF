# kafka_io.py
# ------------------------------------------------------------
# - KafkaLineConsumer: delivers ‘tshark’ type lines from a topic.
# - KafkaCSVProducer: publishes flows of a CSV to a topic.
# ------------------------------------------------------------

import os
import sys
import json
import signal
import argparse
from typing import Generator, Optional, Iterable, Tuple

from confluent_kafka import (
    Consumer as _KafkaConsumer,
    Producer as _KafkaProducer,
    KafkaException,
    KafkaError,
)

# -----------------------------
# Defaults (configurables for env)
# -----------------------------

def get_bootstrap(override: Optional[str] = None) -> str:
    """
    Resolution order:
    1) explicit argument (override),
    2) KAFKA_BOOTSTRAP environment variable,
    3) default "kafka_novadef:29092" (best within Docker).
    """
    if override:
        return override
    return os.getenv("KAFKA_BOOTSTRAP", "kafka_novadef:29092")

DEFAULT_TOPIC_IN = os.getenv("KAFKA_TOPIC_IN", "tshark_traces")
DEFAULT_TOPIC_OUT = os.getenv("KAFKA_TOPIC_OUT", "cic_flow")
DEFAULT_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "net-traces-consumer")
DEFAULT_MESSAGE_FIELD = os.getenv("KAFKA_MESSAGE_FIELD", "_source")

# Consumer behavior
DEFAULT_AUTO_OFFSET_RESET = os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest")  # earliest/latest/none
DEFAULT_ENABLE_AUTO_COMMIT = os.getenv("KAFKA_ENABLE_AUTO_COMMIT", "true").lower() == "true"
DEFAULT_ASSIGNMENT_STRATEGY = os.getenv("KAFKA_PARTITION_ASSIGNMENT_STRATEGY", "cooperative-sticky")
DEFAULT_ENABLE_PARTITION_EOF = os.getenv("KAFKA_ENABLE_PARTITION_EOF", "true").lower() == "true"
DEFAULT_ALLOW_AUTO_CREATE_TOPICS = os.getenv("KAFKA_ALLOW_AUTO_CREATE_TOPICS", "true").lower() == "true"

# Producer behavior
DEFAULT_LINGER_MS = int(os.getenv("KAFKA_PRODUCER_LINGER_MS", "5"))
DEFAULT_BATCH_SIZE = int(os.getenv("KAFKA_PRODUCER_BATCH_SIZE", "32768"))  # ~32 KB
DEFAULT_COMPRESSION = os.getenv("KAFKA_PRODUCER_COMPRESSION", "zstd")  # zstd, lz4, gzip, snappy, none


def _kafka_consumer_config(bootstrap: Optional[str], group_id: Optional[str], debug: Optional[str] = None) -> dict:
    """
    Consumer configuration for single-broker KRaft with groups.
    """
    cfg = {
        "bootstrap.servers": get_bootstrap(bootstrap),
        "group.id": group_id or DEFAULT_GROUP_ID,
        "enable.auto.commit": DEFAULT_ENABLE_AUTO_COMMIT,
        "auto.offset.reset": DEFAULT_AUTO_OFFSET_RESET,
        "allow.auto.create.topics": DEFAULT_ALLOW_AUTO_CREATE_TOPICS,
        "enable.partition.eof": DEFAULT_ENABLE_PARTITION_EOF,
        "partition.assignment.strategy": DEFAULT_ASSIGNMENT_STRATEGY,

        "fetch.min.bytes": 1048576,            # 1 MiB before returning
        "fetch.wait.max.ms": 50,               # wait up to 50 ms to fill batch
        "queued.max.messages.kbytes": 262144,  # 256 MiB  of internal queue
        "max.poll.interval.ms": 900000,        # 15 min for heavy processing
        "session.timeout.ms": 10000,
        "socket.keepalive.enable": True,
    }
    if debug:
        cfg["debug"] = debug  # ej: "cgrp,topic,fetch,protocol"
    return cfg


def _kafka_producer_config(bootstrap: Optional[str], debug: Optional[str] = None) -> dict:
    cfg = {
        "bootstrap.servers": get_bootstrap(bootstrap),
        "linger.ms": DEFAULT_LINGER_MS,
        "batch.num.messages": 10000,
        "batch.size": DEFAULT_BATCH_SIZE,
        "compression.type": DEFAULT_COMPRESSION,
        "socket.keepalive.enable": True,
    }
    if debug:
        cfg["debug"] = debug  # ej: "msg"
    return cfg


class KafkaLineConsumer:
    """
    Consumer designed to read network traces in NDJSON format (from Kafka) and extract the “_source” field.
    Uses consumer groups (subscribe + coordinator).
    """
    def __init__(
        self,
        topic: str = DEFAULT_TOPIC_IN,
        message_field: str = DEFAULT_MESSAGE_FIELD,
        poll_timeout: float = 1.0,
        group_id: Optional[str] = None,
        bootstrap: Optional[str] = None,
        debug: Optional[str] = None,
    ):
        self.topic = topic
        self.message_field = message_field
        self.poll_timeout = poll_timeout
        self._closing = False

        cfg = _kafka_consumer_config(bootstrap, group_id, debug)
        self._consumer = _KafkaConsumer(cfg)

        strategies = str(cfg.get("partition.assignment.strategy", "")).lower()
        self._is_cooperative = "cooperative-sticky" in strategies

        def _on_assign(consumer, partitions):
            pretty = [f"{p.topic}[{p.partition}]@{p.offset}" for p in partitions]
            if self._is_cooperative:
                print(f"📌 (coop) Adding: {pretty}", flush=True)
                consumer.incremental_assign(partitions)
            else:
                print(f"📌 Asigned to: {pretty}", flush=True)
                consumer.assign(partitions)

        def _on_revoke(consumer, partitions):
            pretty = [f"{p.topic}[{p.partition}]@{p.offset}" for p in partitions]
            if self._is_cooperative:
                print(f"↩️  (coop) Revoking: {pretty}", flush=True)
                consumer.incremental_unassign(partitions)
            else:
                print(f"↩️  Revoked: {pretty}", flush=True)
                consumer.unassign()

        self._consumer.subscribe([self.topic], on_assign=_on_assign, on_revoke=_on_revoke)

    # Señales de cierre limpio
    def _trap_signals(self):
        """
        Use of signals for clean consumer closure
        """
        def _sig_handler(signum, frame):
            print("\n🛑 Signal received, closing consumer...", flush=True)
            self._closing = True
        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)

    def _extract_line(self, payload: bytes) -> Optional[str]:
        """
        Attempts to parse JSON and extract the configured field (default “_source”).
        Always returns a serialised JSON string and, if the field is “_source”,
        re-wraps it in {'_source': ...} so that JSON2PCAP finds layers.frame_raw.
        """
        try:
            txt = payload.decode("utf-8", errors="replace")
        except Exception:
            return None

        if not txt or not txt.lstrip().startswith("{"):
            return txt

        try:
            obj = json.loads(txt)
        except Exception:
            return txt

        if self.message_field in obj:
            val = obj[self.message_field]

            # Ensuring the wrapper {"_source": ...}
            if self.message_field == "_source":
                # If it is string -> try to parse it
                # If it comes as dict -> re-wrap it
                if isinstance(val, str):
                    try:
                        val_obj = json.loads(val)
                    except Exception:
                        # It is not valid JSON, so we put it as text under _source_raw
                        return json.dumps({"_source": {"_source_raw": val}}, ensure_ascii=False)
                else:
                    val_obj = val

                # If it is NOT a dict -> store it raw
                if not isinstance(val_obj, dict):
                    return json.dumps({"_source": {"_source_raw": val_obj}}, ensure_ascii=False)

                return json.dumps({"_source": val_obj}, ensure_ascii=False)

            return val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)

        # Fallback: some producers send ""layers" in the root -> wrap it as _source
        if isinstance(obj, dict) and "layers" in obj:
            return json.dumps({"_source": {"layers": obj["layers"]}}, ensure_ascii=False)

        # If none of the above -> Return the original JSON in text
        return txt

    def iter_records(self) -> Generator[Tuple[object, Optional[str]], None, None]:
        """Extract lines and return (msg, line) for commit after processing."""
        self._trap_signals()
        while not self._closing:
            try:
                msg = self._consumer.poll(self.poll_timeout)
                if msg is None:
                    continue
                if msg.error():
                    err = msg.error()
                    if err.code() == KafkaError._PARTITION_EOF:
                        if DEFAULT_ENABLE_PARTITION_EOF:
                            print(f"ℹ️  EOF {msg.topic()}[{msg.partition()}] offset {msg.offset()}", flush=True)
                        continue
                    print(f"⚠️  Error consumer: {err}", flush=True)
                    continue
                line = self._extract_line(msg.value())
                yield (msg, line)
            except KeyboardInterrupt:
                break
            except KafkaException as ke:
                print(f"❌ KafkaException: {ke}", flush=True)
            except Exception as ex:
                print(f"❌ Exception: {ex}", flush=True)
        self.close()

    def commit_msg(self, msg):
        """Commit the processed message."""
        try:
            self._consumer.commit(message=msg, asynchronous=False)
        except KafkaException as ke:
            print(f"⚠️  Commit error: {ke}", flush=True)

    def close(self):
        try:
            self._consumer.close()
        except Exception:
            pass


class KafkaCSVProducer:
    """Producer for publishing lines."""
    def __init__(self, topic: str = DEFAULT_TOPIC_OUT, bootstrap: Optional[str] = None, debug: Optional[str] = None):
        self.topic = topic
        cfg = _kafka_producer_config(bootstrap, debug)
        self._producer = _KafkaProducer(cfg)

    def _delivery_cb(self, err, msg):
        if err is not None:
            print(f"❌ Delivery failed: {err}", flush=True)

    def produce_lines(self, lines: Iterable[str]):
        for line in lines:
            data = line if isinstance(line, (bytes, bytearray)) else line.encode("utf-8", errors="replace")
            self._producer.produce(self.topic, value=data, on_delivery=self._delivery_cb)
            self._producer.poll(0)  # serves callbacks
        self._producer.flush()
