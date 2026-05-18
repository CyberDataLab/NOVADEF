#!/usr/bin/env python3

import json
import logging
import os
import time
from collections import deque
from hashlib import md5
from pathlib import Path
from typing import Any

import numpy as np
from confluent_kafka import Consumer, Producer, KafkaError
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("network_intrusion_detector")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka_novadef:29092")
KAFKA_TOPIC_IN = os.getenv("KAFKA_TOPIC_IN", "network_auth_events")
KAFKA_TOPIC_OUT = os.getenv("KAFKA_TOPIC_OUT", "network_intrusion_alerts")
KAFKA_TOPIC_TAPCD_COMPAT = os.getenv("KAFKA_TOPIC_TAPCD_COMPAT", "snort_alerts")
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "network-intrusion-detector-v1")

WINDOW_SECONDS = int(os.getenv("DETECTOR_WINDOW_SECONDS", "300"))
MIN_FAILURES = int(os.getenv("DETECTOR_MIN_FAILURES", "20"))
MIN_UNIQUE_USERS = int(os.getenv("DETECTOR_MIN_UNIQUE_USERS", "8"))
MIN_UNIQUE_IPS = int(os.getenv("DETECTOR_MIN_UNIQUE_IPS", "4"))
DEDUP_SECONDS = int(os.getenv("DETECTOR_DEDUP_SECONDS", "60"))
REQUIRE_MODEL_ANOMALY = os.getenv("DETECTOR_REQUIRE_MODEL_ANOMALY", "false").lower() in {"1", "true", "yes"}

RESULTS_DIR = Path(os.getenv("RESULTS_DIR", "/app/results"))
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_PATH = RESULTS_DIR / "network_intrusion_alerts.jsonl"


def _kafka_consumer() -> Consumer:
    return Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": GROUP_ID,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": True,
            "allow.auto.create.topics": True,
        }
    )


def _kafka_producer() -> Producer:
    return Producer({"bootstrap.servers": KAFKA_BOOTSTRAP, "compression.type": "zstd"})


def _generate_benign_batches() -> list[list[dict[str, Any]]]:
    rng = np.random.default_rng(42)
    batches = []
    for _ in range(200):
        event_count = int(rng.integers(3, 12))
        start = float(time.time()) - float(rng.integers(10_000, 20_000))
        batch = []
        src_pool = [f"172.18.0.{int(rng.integers(60, 90))}" for _ in range(int(rng.integers(1, 3)))]
        user_pool = [f"user{idx}" for idx in range(int(rng.integers(1, 4)))]
        for idx in range(event_count):
            batch.append(
                {
                    "src_ip": src_pool[int(rng.integers(0, len(src_pool)))],
                    "dst_ip": "172.18.0.2",
                    "dst_port": 2222,
                    "protocol": "tcp",
                    "username": user_pool[int(rng.integers(0, len(user_pool)))],
                    "auth_success": bool(rng.integers(0, 2)),
                    "timestamp": start + (idx * float(rng.uniform(15, 90))),
                }
            )
        batches.append(batch)
    return batches


class SprayingAnomalyModel:
    feature_names = [
        "unique_src_ips",
        "unique_target_users",
        "failed_attempts",
        "requests_per_minute",
        "time_distribution_stddev",
        "port_variation",
        "protocol_diversity",
        "geographic_spread",
    ]

    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.08, random_state=42, n_estimators=120)

    def _features(self, events: list[dict[str, Any]]) -> np.ndarray:
        if not events:
            return np.zeros((1, len(self.feature_names)), dtype=np.float32)

        timestamps = sorted(float(event.get("timestamp", 0.0)) for event in events)
        unique_src_ips = sorted({str(event.get("src_ip", "")) for event in events if event.get("src_ip")})
        unique_users = sorted({str(event.get("username", "")) for event in events if event.get("username")})
        failed_attempts = sum(1 for event in events if not bool(event.get("auth_success", False)))
        protocols = {str(event.get("protocol", "")).lower() for event in events if event.get("protocol")}
        ports = {int(event.get("dst_port", 0)) for event in events if event.get("dst_port")}

        time_span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 1.0
        rpm = (len(events) / max(time_span, 1.0)) * 60.0
        intervals = [timestamps[idx + 1] - timestamps[idx] for idx in range(len(timestamps) - 1)]
        time_std = float(np.std(intervals)) if intervals else 0.0
        geo_values = [int(md5(src_ip.encode()).hexdigest(), 16) % 256 for src_ip in unique_src_ips]
        geo_spread = float(np.std(geo_values)) if geo_values else 0.0

        return np.array(
            [[
                float(len(unique_src_ips)),
                float(len(unique_users)),
                float(failed_attempts),
                float(rpm),
                float(time_std),
                float(len(ports)),
                float(len(protocols)),
                float(geo_spread),
            ]],
            dtype=np.float32,
        )

    def train(self) -> None:
        benign = _generate_benign_batches()
        matrix = np.vstack([self._features(batch) for batch in benign])
        self.scaler.fit(matrix)
        self.model.fit(self.scaler.transform(matrix))
        logger.info("Isolation Forest entrenado con baseline benigno sintético (%s lotes)", len(benign))

    def score(self, events: list[dict[str, Any]]) -> tuple[bool, float, dict[str, float]]:
        features = self._features(events)
        scaled = self.scaler.transform(features)
        decision = float(self.model.decision_function(scaled)[0])
        prediction = int(self.model.predict(scaled)[0])
        details = dict(zip(self.feature_names, [float(value) for value in features[0].tolist()]))
        return prediction == -1, decision, details


def normalize_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    src_ip = payload.get("src_ip")
    dst_ip = payload.get("dst_ip")
    username = payload.get("username")
    if not src_ip or not dst_ip or not username:
        return None

    try:
        timestamp = float(payload.get("timestamp", time.time()))
    except (TypeError, ValueError):
        timestamp = time.time()

    return {
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "dst_port": int(payload.get("dst_port", 0) or 0),
        "protocol": str(payload.get("protocol", "tcp")).lower(),
        "username": str(username),
        "auth_success": bool(payload.get("auth_success", False)),
        "timestamp": timestamp,
    }


def append_alert(alert: dict[str, Any]) -> None:
    with ALERTS_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(alert, ensure_ascii=False) + "\n")


def _to_tapcd_compat_snort_event(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Crea un evento compatible con el topic `snort_alerts` para que TAPCD
    procese la semántica de ataque sin cambiar su formato ni su pipeline.
    """
    src_ips = alert.get("src_ips") or []
    primary_src = src_ips[0] if src_ips else "0.0.0.0"
    dst_ip = str(alert.get("dst_ip", "0.0.0.0"))
    dst_port = int(alert.get("dst_port", 0) or 0)

    # TAPCD espera formato MM/DD-HH:MM:SS.micro
    first_seen = str(alert.get("first_seen", alert.get("timestamp", "")))
    if len(first_seen) >= 19:
        ts_short = f"{first_seen[5:7]}/{first_seen[8:10]}-{first_seen[11:19]}.000000"
    else:
        ts_short = "01/01-00:00:00.000000"

    failed = int(alert.get("failed_attempts", 0) or 0)
    uniq_ips = len(src_ips)
    uniq_users = len(alert.get("usernames") or [])

    return {
        "msg": (
            "Brute Force Password Spraying Detected "
            f"(T1110.003) failed={failed} uniq_src={uniq_ips} uniq_users={uniq_users}"
        ),
        "rule": "NOVADEF-NID:100001",
        "classification": "attempted-admin",
        "priority": 1,
        "proto": "TCP",
        "src_ap": f"{primary_src}:40000",
        "dst_ap": f"{dst_ip}:{dst_port}",
        "timestamp": ts_short,
        "pkt_len": 0,
        "action": "would_drop",
        "dir": "->",
        "generator": "network_intrusion_detector",
        "correlation_id": f"nid-{dst_ip}-{dst_port}-{first_seen[:16]}",
    }


def main() -> None:
    model = SprayingAnomalyModel()
    model.train()

    consumer = _kafka_consumer()
    producer = _kafka_producer()
    consumer.subscribe([KAFKA_TOPIC_IN])

    recent_events: deque[dict[str, Any]] = deque()
    last_alert_by_target: dict[str, float] = {}
    target_last_seen_ts: dict[str, float] = {}
    alerted_active_targets: set[str] = set()

    logger.info("Escuchando %s y publicando alertas en %s", KAFKA_TOPIC_IN, KAFKA_TOPIC_OUT)

    while True:
        msg = consumer.poll(1.0)
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
            logger.warning("Mensaje no JSON en %s", KAFKA_TOPIC_IN)
            continue

        event = normalize_event(payload)
        if event is None:
            continue

        # Use wall clock for dedup/lifecycle state to avoid drift or out-of-order
        # telemetry timestamps reopening the same campaign.
        event_ts = float(event["timestamp"])
        wall_now = time.time()
        current_target_key = f"{event['dst_ip']}:{int(event['dst_port'])}"
        prev_seen = target_last_seen_ts.get(current_target_key, 0.0)
        # If this target has been quiet longer than the campaign window,
        # force-close previous active campaign before ingesting new events.
        if prev_seen and (wall_now - prev_seen) > WINDOW_SECONDS:
            alerted_active_targets.discard(current_target_key)

        recent_events.append(event)
        while recent_events and (event_ts - float(recent_events[0]["timestamp"])) > WINDOW_SECONDS:
            recent_events.popleft()

        # Expire active campaigns BEFORE refreshing per-target last-seen with
        # current window data. Otherwise, old active targets can remain pinned
        # forever when a new run starts on the same destination.
        stale_targets = [
            target
            for target in alerted_active_targets
            if (wall_now - target_last_seen_ts.get(target, 0.0)) > WINDOW_SECONDS
        ]
        for target in stale_targets:
            alerted_active_targets.discard(target)

        by_target: dict[tuple[str, int], list[dict[str, Any]]] = {}
        for item in recent_events:
            key = (str(item["dst_ip"]), int(item["dst_port"]))
            by_target.setdefault(key, []).append(item)
            target_last_seen_ts[f"{item['dst_ip']}:{int(item['dst_port'])}"] = float(item["timestamp"])

        for (dst_ip, dst_port), window_events in by_target.items():
            failed_attempts = sum(1 for item in window_events if not item["auth_success"])
            unique_src_ips = {item["src_ip"] for item in window_events}
            unique_users = {item["username"] for item in window_events}
            if failed_attempts < MIN_FAILURES:
                continue
            if len(unique_src_ips) < MIN_UNIQUE_IPS:
                continue
            if len(unique_users) < MIN_UNIQUE_USERS:
                continue

            is_anomaly, score, feature_map = model.score(window_events)
            # Para escenarios controlados de laboratorio, permitimos disparar por patrón
            # fuerte de spraying aunque el modelo no marque anomalía en esa ventana.
            if REQUIRE_MODEL_ANOMALY and not is_anomaly:
                continue

            dedup_key = f"{dst_ip}:{dst_port}"
            correlation_id = (
                f"nid-{dst_ip}-{dst_port}-"
                f"{time.strftime('%Y%m%d%H%M', time.gmtime(min(float(item['timestamp']) for item in window_events)))}"
            )

            # Una sola alerta por campaña activa para evitar replicar el incidente.
            if dedup_key in alerted_active_targets:
                continue

            if wall_now - last_alert_by_target.get(dedup_key, 0.0) < DEDUP_SECONDS:
                continue
            last_alert_by_target[dedup_key] = wall_now
            alerted_active_targets.add(dedup_key)

            alert = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(wall_now)),
                "detector": "network_intrusion_detector",
                "correlation_id": correlation_id,
                "alert_type": "distributed_password_spraying",
                "title": f"Distributed Password Spraying against {dst_ip}:{dst_port}",
                "src_ips": sorted(unique_src_ips),
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "usernames": sorted(unique_users),
                "failed_attempts": failed_attempts,
                "window_seconds": WINDOW_SECONDS,
                "requests_per_minute": feature_map["requests_per_minute"],
                "anomaly_score": score,
                "model_anomaly": bool(is_anomaly),
                "features": feature_map,
                "mitre_attack": ["T1110", "T1110.003", "T1133"],
                "d3fend_candidates": [
                    "Network Traffic Filtering",
                    "Inbound Traffic Filtering",
                    "Account Locking",
                    "Connected Honeynet",
                    "Session Termination",
                ],
                "first_seen": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(min(float(item["timestamp"]) for item in window_events))
                ),
                "last_seen": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(float(item["timestamp"]) for item in window_events))
                ),
            }

            append_alert(alert)
            producer.produce(KAFKA_TOPIC_OUT, value=json.dumps(alert).encode("utf-8"))
            tapcd_compat_event = _to_tapcd_compat_snort_event(alert)
            producer.produce(KAFKA_TOPIC_TAPCD_COMPAT, value=json.dumps(tapcd_compat_event).encode("utf-8"))
            producer.flush()
            logger.info(
                "Evento TAPCD-compat publicado en %s: %s -> %s",
                KAFKA_TOPIC_TAPCD_COMPAT,
                tapcd_compat_event.get("src_ap"),
                tapcd_compat_event.get("dst_ap"),
            )
            logger.warning(
                "Alerta publicada: %s (%s IPs, %s usuarios, %s fallos)",
                alert["title"],
                len(unique_src_ips),
                len(unique_users),
                failed_attempts,
            )


if __name__ == "__main__":
    main()
