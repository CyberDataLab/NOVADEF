#!/usr/bin/env python3

import json
import logging
import os
import re
import socket
import time
import ipaddress
from collections import deque
from hashlib import md5
from pathlib import Path
from typing import Any

import numpy as np
from confluent_kafka import Consumer, Producer, KafkaError
from confluent_kafka.admin import AdminClient, NewTopic
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("network_intrusion_detector")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka_novadef:29092")
KAFKA_TOPIC_IN = os.getenv("KAFKA_TOPIC_IN", "tshark_traces")
KAFKA_TOPIC_FLOW_IN = os.getenv("KAFKA_TOPIC_FLOW_IN", "cic_flow")
KAFKA_TOPIC_AUTH_IN = os.getenv("KAFKA_TOPIC_AUTH_IN", "network_auth_events")
KAFKA_TOPIC_OUT = os.getenv("KAFKA_TOPIC_OUT", "network_intrusion_alerts")
KAFKA_TOPIC_TAPCD_COMPAT = os.getenv("KAFKA_TOPIC_TAPCD_COMPAT", "snort_alerts")
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "network-intrusion-detector-v1")
TSHARK_TRACE_PATH = Path(os.getenv("TSHARK_TRACE_PATH", "/tshark/traces/infile.ndjson"))
SCENARIO_RUNTIME_DIR = Path(os.getenv("SCENARIO_RUNTIME_DIR", "/scenario-runtime"))
POLL_TIMEOUT_SECONDS = float(os.getenv("DETECTOR_POLL_TIMEOUT_SECONDS", "0.01"))

WINDOW_SECONDS = int(os.getenv("DETECTOR_WINDOW_SECONDS", "1"))
WINDOW_PACKETS = int(os.getenv("DETECTOR_WINDOW_PACKETS", "12"))
MIN_FAILURES = int(os.getenv("DETECTOR_MIN_FAILURES", "3"))
MIN_UNIQUE_USERS = int(os.getenv("DETECTOR_MIN_UNIQUE_USERS", "2"))
MIN_UNIQUE_IPS = int(os.getenv("DETECTOR_MIN_UNIQUE_IPS", "2"))
DEDUP_SECONDS = int(os.getenv("DETECTOR_DEDUP_SECONDS", "10"))
REQUIRE_MODEL_ANOMALY = os.getenv("DETECTOR_REQUIRE_MODEL_ANOMALY", "false").lower() in {"1", "true", "yes"}
# Keep the detector fast by default: the first genuine failure can still be
# scored by the anomaly model, but we do not wait for a longer window when the
# spraying pattern is already obvious.
FAST_PATH_FIRST_FAILURE = os.getenv("DETECTOR_FAST_PATH_FIRST_FAILURE", "true").lower() in {"1", "true", "yes"}
IMMEDIATE_AUTH_CAMPAIGN_ALERT = os.getenv("DETECTOR_IMMEDIATE_AUTH_CAMPAIGN_ALERT", "true").lower() in {"1", "true", "yes"}
CAMPAIGN_DEDUP_TTL_SECONDS = int(os.getenv("DETECTOR_CAMPAIGN_DEDUP_TTL_SECONDS", "1800"))
ALLOWED_REMOTE_PORTS = {22, 2222, 3389, 443, 1194}

# PMP infrastructure IPs that must never be classified as attackers or
# victims. These are stable container HOSTNAMES (SOARCA executor, trigger,
# integrators, Kafka, MISP, the experiments API…) that connect to the victim
# for legitimate purposes (SSH countermeasure, Prometheus scraping,
# health-checks) or that the API itself lives on.
#
# Resolved by NAME, not by IP/CIDR range: every container on this Docker
# network (infra AND scenario victims/attackers alike) shares the same
# 172.18.0.0/16 subnet with IPs assigned in creation order — there is no
# reserved IP block for infra. A CIDR-based exclusion (e.g. the previous
# 172.18.0.0/27) is fragile because it silently grows to include whichever
# scenario victim happens to land in the low IP range once enough infra
# containers have started (this previously caused the detector to ignore ALL
# traffic to the victim when Docker assigned it .31, inside the /27). Name
# resolution has no such collision: a scenario container is never named
# "kafka_novadef" or "novadef-experiments-api", regardless of its IP.
_INFRA_HOSTNAMES = [
    h.strip() for h in os.getenv(
        "DETECTOR_INFRA_HOSTNAMES",
        "kafka_novadef,novadef-experiments-api,pmp-soarca-core,pmp-soarca-executor-ssh,"
        "pmp-misp-soarca-trigger,pmp-misp-server,pmp-misp-integrator,pmp-misp-db,"
        "pmp-misp-redis,pmp-misp-modules,prometheus_server_novadef,telegraf_novadef,"
        "novadef-auth-db,novadef-log-hub,novadef-grafana,alert_module_novadef,"
        "alert_manager_novadef,network_intrusion_detector_novadef,flow_module_novadef,"
        "filebeat_novadef,fluentd_novadef,device_info_novadef,falco_exporter_novadef,"
        "novadef-neo4j-1,novadef-novadef_stream_low-1,novadef-novadef_prep_pred-1,"
        "novadef-novadef_neo4j_ingester-1,mongodb_novadef",
    ).split(",") if h.strip()
]
_INFRA_RESOLVE_INTERVAL_SECONDS = int(os.getenv("DETECTOR_INFRA_RESOLVE_INTERVAL_SECONDS", "60"))
_infra_ip_cache: set[str] = set()
_infra_ip_cache_ts: float = 0.0


def _refresh_infra_ips() -> set[str]:
    """Resolve infra hostnames to their current IPs (cached briefly — Docker
    DNS is authoritative and containers can restart with a new IP)."""
    global _infra_ip_cache, _infra_ip_cache_ts
    now = time.time()
    if _infra_ip_cache and (now - _infra_ip_cache_ts) < _INFRA_RESOLVE_INTERVAL_SECONDS:
        return _infra_ip_cache
    resolved: set[str] = set()
    for host in _INFRA_HOSTNAMES:
        try:
            resolved.add(socket.gethostbyname(host))
        except Exception:
            continue
    if resolved:
        _infra_ip_cache = resolved
        _infra_ip_cache_ts = now
    return _infra_ip_cache


def _is_infra_src(ip_txt: str) -> bool:
    """True if the IP currently belongs to a known PMP infrastructure host."""
    ip_txt = str(ip_txt).strip()
    if not ip_txt:
        return False
    return ip_txt in _refresh_infra_ips()

RESULTS_DIR = Path(os.getenv("RESULTS_DIR", "/app/results"))
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_PATH = RESULTS_DIR / "network_intrusion_alerts.jsonl"
CAMPAIGN_STATE_PATH = RESULTS_DIR / "network_intrusion_campaign_state.json"
RUNTIME_LOG_OFFSETS_PATH = RESULTS_DIR / "network_intrusion_runtime_offsets.json"


def _kafka_consumer() -> Consumer:
    return Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": GROUP_ID,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
            "allow.auto.create.topics": True,
        }
    )


def _kafka_producer() -> Producer:
    return Producer({"bootstrap.servers": KAFKA_BOOTSTRAP, "compression.type": "zstd"})


def _ensure_kafka_topics(topics: list[str]) -> None:
    try:
        admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP})
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
                # If the topic already exists or the broker races the creation,
                # keep going and let the consumer retry with refreshed metadata.
                logger.info("Kafka topic ensure skipped for %s: %s", topic, exc)
    except Exception as exc:
        logger.warning("No se pudieron asegurar topics Kafka: %s", exc)


def _generate_benign_batches() -> list[list[dict[str, Any]]]:
    """
    Genera un baseline benigno sintético que representa el tráfico legítimo
    REAL del escenario: ráfagas pequeñas de pocas IPs (monitorización, health
    checks, ICMP/HTTP) hacia servicios variados, con autenticaciones exitosas
    y tasas bajas. Este baseline define la "normalidad" que el Isolation Forest
    aprende, de modo que el ataque de password spraying (muchas IPs, muchos
    fallos, tasa altísima) caiga claramente fuera de la distribución.

    Características clave del benigno (frente al ataque):
      - pocos orígenes (1-3 IPs)        vs  muchos (>=5)
      - sin fallos de autenticación     vs  decenas de fallos
      - requests_per_minute bajo (<30)  vs  cientos
      - puertos variados (web/monit.)   vs  concentrado en SSH/2222
    """
    rng = np.random.default_rng(42)
    batches = []
    port_pool = [22, 80, 443, 8080, 8443, 9000, 3000, 9090]
    for _ in range(500):
        event_count = int(rng.integers(3, 14))
        start = float(time.time()) - float(rng.integers(10_000, 20_000))
        batch = []
        # Tráfico legítimo proviene de pocas fuentes estables (no enjambres).
        src_pool = [f"172.18.0.{int(rng.integers(60, 155))}" for _ in range(int(rng.integers(1, 4)))]
        # Mezcla de cadencias legítimas: la mayoría lentas (monitorización), pero
        # también ráfagas rápidas de health-checks/scraping (multi-IP, sin fallos)
        # para que el modelo no confunda actividad benigna concurrente con ataque.
        # El discriminador real frente al ataque es failed_attempts (siempre 0
        # aquí) y la cantidad de orígenes, no la mera velocidad.
        fast_burst = bool(rng.random() < 0.35)
        spacing = float(rng.uniform(0.3, 3.0)) if fast_burst else float(rng.uniform(5, 90))
        for idx in range(event_count):
            src_ip = src_pool[int(rng.integers(0, len(src_pool)))]
            dst_port = int(port_pool[int(rng.integers(0, len(port_pool)))])
            batch.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": "172.18.0.30",
                    "dst_port": dst_port,
                    "protocol": "tcp",
                    "username": src_ip,
                    "auth_success": True,
                    "pkt_len": int(rng.integers(54, 900)),
                    "timestamp": start + (idx * spacing * float(rng.uniform(0.7, 1.3))),
                }
            )
        batches.append(batch)
    return batches


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(key).lower())


def _get_any(payload: dict[str, Any], *names: str) -> Any:
    if not isinstance(payload, dict):
        return None
    normalized = {_normalize_key(k): v for k, v in payload.items()}
    for name in names:
        value = normalized.get(_normalize_key(name))
        if value not in {None, ""}:
            return value
    return None


def _is_private_lab_ip(ip_txt: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip_txt)).is_private
    except Exception:
        return False


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
        # contamination bajo: el baseline benigno es "limpio" por construcción,
        # así que solo las muestras claramente fuera de distribución (el ataque)
        # deben marcarse como anomalía. Esto reduce los falsos positivos sobre el
        # tráfico legítimo del escenario.
        self.model = IsolationForest(contamination=0.02, random_state=42, n_estimators=200)
        # Umbral de decisión calibrado en train() sobre el baseline benigno.
        self.decision_threshold = 0.0

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

    def __post_train_threshold(self, benign_scores: np.ndarray) -> None:
        # Umbral de decisión calibrado sobre el propio baseline benigno: una
        # ventana se considera anómala solo si su score de Isolation Forest cae
        # por DEBAJO del percentil más bajo del tráfico legítimo (con margen).
        # Esto separa de forma robusta el benigno (scores cercanos a 0) del
        # ataque (scores muy negativos) sin depender del umbral interno de
        # `predict()`, que es sensible al parámetro `contamination`.
        p_low = float(np.percentile(benign_scores, 1.0))
        # margen de seguridad por debajo del percentil 1 del benigno
        self.decision_threshold = p_low - 0.01

    def train(self) -> None:
        benign = _generate_benign_batches()
        matrix = np.vstack([self._features(batch) for batch in benign])
        self.scaler.fit(matrix)
        scaled = self.scaler.transform(matrix)
        self.model.fit(scaled)
        benign_scores = self.model.decision_function(scaled)
        self.__post_train_threshold(benign_scores)
        logger.info(
            "Isolation Forest entrenado con baseline benigno sintético (%s lotes). "
            "Umbral de anomalía=%.4f (benigno: min=%.4f p1=%.4f mediana=%.4f)",
            len(benign),
            self.decision_threshold,
            float(benign_scores.min()),
            float(np.percentile(benign_scores, 1.0)),
            float(np.median(benign_scores)),
        )

    def score(self, events: list[dict[str, Any]]) -> tuple[bool, float, dict[str, float]]:
        features = self._features(events)
        scaled = self.scaler.transform(features)
        decision = float(self.model.decision_function(scaled)[0])
        details = dict(zip(self.feature_names, [float(value) for value in features[0].tolist()]))
        # Anomalía si el score cae por debajo del umbral calibrado del baseline.
        threshold = getattr(self, "decision_threshold", 0.0)
        is_anomaly = decision < threshold
        return is_anomaly, decision, details


def _extract_tshark_packet(payload: dict[str, Any]) -> dict[str, Any] | None:
    source = payload.get("_source")
    if isinstance(source, dict):
        payload = source
    layers = payload.get("layers") if isinstance(payload, dict) else None
    top_src_ip = _get_any(payload, "ip.src", "src_ip", "Source IP", "src ip", "ip.src_host")
    top_dst_ip = _get_any(payload, "ip.dst", "dst_ip", "Destination IP", "dst ip", "ip.dst_host")
    top_src_port = _get_any(payload, "tcp.srcport", "udp.srcport", "src_port", "Source Port", "src port")
    top_dst_port = _get_any(payload, "tcp.dstport", "udp.dstport", "dst_port", "Destination Port", "dst port")
    top_proto = _get_any(payload, "protocol", "proto", "ip.proto") or ""
    top_pkt_len = _get_any(payload, "frame.len", "pkt_len", "packet length")
    top_ts = _get_any(payload, "frame.time_epoch", "timestamp", "@timestamp")
    if isinstance(layers, dict):
        ip = layers.get("ip") or {}
        tcp = layers.get("tcp") or {}
        udp = layers.get("udp") or {}
        frame = layers.get("frame") or {}
        src_ip = str(ip.get("ip.src") or ip.get("ip.src_host") or top_src_ip or "").strip()
        dst_ip = str(ip.get("ip.dst") or ip.get("ip.dst_host") or top_dst_ip or "").strip()
        proto = str(ip.get("ip.proto") or top_proto or "").strip()
        proto_name = {"1": "icmp", "6": "tcp", "17": "udp"}.get(proto, proto.lower() or "tcp")
        src_port = tcp.get("tcp.srcport") or udp.get("udp.srcport") or top_src_port or ""
        dst_port = tcp.get("tcp.dstport") or udp.get("udp.dstport") or top_dst_port or ""
        pkt_len = frame.get("frame.len") or top_pkt_len or 0
        ts_val = frame.get("frame.time_epoch") or top_ts
        try:
            timestamp = float(ts_val)
        except (TypeError, ValueError):
            timestamp = time.time()
        if src_ip and dst_ip:
            is_remote_auth_port = proto_name == "tcp" and int(dst_port or 0) in ALLOWED_REMOTE_PORTS
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": int(dst_port or 0),
                "src_port": int(src_port or 0),
                "protocol": proto_name,
                "pkt_len": int(pkt_len or 0),
                "username": src_ip,
                "auth_success": not is_remote_auth_port,
                "host_signal": False,
                "hybrid_campaign": "",
                "campaign_id": str(_get_any(payload, "campaign_id", "campaign id", "campaign") or ""),
                "timestamp": timestamp,
                "source_type": "tshark",
            }
    return None


def _extract_cic_flow_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    src_ip = _get_any(payload, "src ip", "src_ip", "Source IP", "Src IP", "ip.src")
    dst_ip = _get_any(payload, "dst ip", "dst_ip", "Destination IP", "Dst IP", "ip.dst")
    dst_port = _get_any(payload, "dst port", "dst_port", "Destination Port", "Dst Port", "tcp.dstport")
    src_port = _get_any(payload, "src port", "src_port", "Source Port", "Src Port", "tcp.srcport")
    proto = _get_any(payload, "protocol", "proto", "Protocol", "ip.proto") or "tcp"
    if not src_ip or not dst_ip:
        return None

    try:
        ts_raw = _get_any(payload, "@timestamp", "timestamp", "flow start", "flow start time")
        timestamp = float(ts_raw) if ts_raw is not None else time.time()
    except (TypeError, ValueError):
        timestamp = time.time()

    flow_duration = _get_any(payload, "flow duration", "flow_duration", "Duration")
    flow_pps = _get_any(payload, "flow packets/s", "flow_packets/s", "packets/s", "Flow Packets/s")
    flow_bps = _get_any(payload, "flow bytes/s", "flow_bytes/s", "bytes/s", "Flow Bytes/s")
    total_fwd = _get_any(payload, "total fwd packets", "Total Fwd Packets", "fwd packets")
    total_bwd = _get_any(payload, "total backward packets", "Total Backward Packets", "bwd packets")

    def _num(v: Any) -> float:
        try:
            return float(str(v).replace(",", "."))
        except Exception:
            return 0.0

    flow_duration_f = _num(flow_duration)
    flow_pps_f = _num(flow_pps)
    flow_bps_f = _num(flow_bps)
    total_fwd_f = _num(total_fwd)
    total_bwd_f = _num(total_bwd)
    pkt_len = _num(_get_any(payload, "packet length mean", "Packet Length Mean", "avg packet size"))

    src_ip_txt = str(src_ip).strip()
    dst_ip_txt = str(dst_ip).strip()
    dst_port_int = int(float(dst_port or 0))
    src_port_int = int(float(src_port or 0))
    proto_txt = str(proto).lower().strip() or "tcp"
    suspicious_dst = dst_port_int == 2222 or "ssh" in str(_get_any(payload, "label", "Label", "application")).lower()
    if not suspicious_dst:
        return None

    return {
        "src_ip": src_ip_txt,
        "dst_ip": dst_ip_txt,
        "dst_port": dst_port_int,
        "src_port": src_port_int,
        "protocol": proto_txt,
        "pkt_len": int(pkt_len or 0),
        "username": src_ip_txt,
        "auth_success": False,
        "host_signal": False,
        "hybrid_campaign": "",
        "campaign_id": "",
        "timestamp": timestamp,
        "source_type": "cic_flow",
        "flow_duration": flow_duration_f,
        "flow_packets_per_sec": flow_pps_f,
        "flow_bytes_per_sec": flow_bps_f,
        "total_fwd_packets": total_fwd_f,
        "total_backward_packets": total_bwd_f,
    }


def _extract_network_auth_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    src_ip = _get_any(payload, "src_ip", "src ip", "source_ip", "source ip", "ip.src")
    dst_ip = _get_any(payload, "dst_ip", "dst ip", "destination_ip", "destination ip", "ip.dst")
    dst_port = _get_any(payload, "dst_port", "dst port", "destination_port", "destination port", "tcp.dstport")
    username = _get_any(payload, "username", "user", "account", "login") or src_ip
    if not src_ip or not dst_ip:
        return None
    try:
        timestamp = float(_get_any(payload, "timestamp", "@timestamp") or time.time())
    except (TypeError, ValueError):
        timestamp = time.time()
    try:
        auth_success = str(_get_any(payload, "auth_success", "success", "ok") or "").lower() in {"1", "true", "yes", "ok"}
    except Exception:
        auth_success = False
    return {
        "src_ip": str(src_ip).strip(),
        "dst_ip": str(dst_ip).strip(),
        "dst_port": int(float(dst_port or 0)),
        "src_port": int(float(_get_any(payload, "src_port", "src port", "source_port", "source port") or 0)),
        "protocol": str(_get_any(payload, "protocol", "proto") or "tcp").lower().strip() or "tcp",
        "pkt_len": int(float(_get_any(payload, "pkt_len", "packet length", "size") or 0)),
        "username": str(username).strip(),
        "auth_success": auth_success,
        "host_signal": bool(_get_any(payload, "host_signal") or False),
        "hybrid_campaign": str(_get_any(payload, "hybrid_campaign", "hybrid campaign") or ""),
        "campaign_id": str(_get_any(payload, "campaign_id", "campaign id", "campaign") or ""),
        "timestamp": timestamp,
        "source_type": "network_auth_events",
    }


def normalize_event(payload: dict[str, Any], topic: str | None = None) -> dict[str, Any] | None:
    topic = str(topic or "").strip()
    if topic == KAFKA_TOPIC_IN:
        tshark_event = _extract_tshark_packet(payload)
        if tshark_event is not None:
            return tshark_event
    elif topic == KAFKA_TOPIC_FLOW_IN:
        flow_event = _extract_cic_flow_event(payload)
        if flow_event is not None:
            return flow_event
    elif topic == KAFKA_TOPIC_AUTH_IN:
        auth_event = _extract_network_auth_event(payload)
        if auth_event is not None:
            return auth_event

    tshark_event = _extract_tshark_packet(payload)
    if tshark_event is not None:
        return tshark_event
    flow_event = _extract_cic_flow_event(payload)
    if flow_event is not None:
        return flow_event
    auth_event = _extract_network_auth_event(payload)
    if auth_event is not None:
        return auth_event

    src_ip = payload.get("src_ip")
    dst_ip = payload.get("dst_ip")
    username = payload.get("username") or payload.get("src_ip")
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
        "src_port": int(payload.get("src_port", 0) or 0),
        "protocol": str(payload.get("protocol", "tcp")).lower(),
        "pkt_len": int(payload.get("pkt_len", 0) or 0),
        "username": str(username),
        "auth_success": bool(payload.get("auth_success", False)),
        "host_signal": bool(payload.get("host_signal", False)),
        "hybrid_campaign": str(payload.get("hybrid_campaign", "") or ""),
        "campaign_id": str(payload.get("campaign_id", "") or ""),
        "timestamp": timestamp,
        "source_type": "legacy",
    }


def append_alert(alert: dict[str, Any]) -> None:
    with ALERTS_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(alert, ensure_ascii=False) + "\n")


def _load_campaign_state() -> dict[str, float]:
    if not CAMPAIGN_STATE_PATH.exists():
        return {}
    try:
        data = json.loads(CAMPAIGN_STATE_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            now = time.time()
            return {
                str(k): float(v)
                for k, v in data.items()
                if isinstance(v, (int, float)) and (now - float(v)) <= CAMPAIGN_DEDUP_TTL_SECONDS
            }
    except Exception:
        pass
    return {}


def _save_campaign_state(state: dict[str, float]) -> None:
    try:
        now = time.time()
        pruned = {
            str(k): float(v)
            for k, v in state.items()
            if isinstance(v, (int, float)) and (now - float(v)) <= CAMPAIGN_DEDUP_TTL_SECONDS
        }
        CAMPAIGN_STATE_PATH.write_text(json.dumps(pruned, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _load_runtime_offsets() -> dict[str, int]:
    if not RUNTIME_LOG_OFFSETS_PATH.exists():
        return {}
    try:
        data = json.loads(RUNTIME_LOG_OFFSETS_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): int(v) for k, v in data.items() if isinstance(v, (int, float))}
    except Exception:
        pass
    return {}


def _save_runtime_offsets(offsets: dict[str, int]) -> None:
    try:
        RUNTIME_LOG_OFFSETS_PATH.write_text(json.dumps(offsets, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _read_jsonl_events_since(path: Path, offset: int, topic: str) -> tuple[list[dict[str, Any]], int]:
    if not path.exists():
        return [], 0 if offset else offset
    try:
        size = int(path.stat().st_size)
        if size < offset:
            offset = 0
        if size == offset:
            return [], offset
        with path.open("rb") as handle:
            handle.seek(offset)
            blob = handle.read().decode("utf-8", errors="replace")
        new_offset = size
        events: list[dict[str, Any]] = []
        for line in blob.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            event = normalize_event(payload, topic=topic)
            if event is not None:
                events.append(event)
        return events, new_offset
    except Exception:
        return [], offset


def _remember_campaign_hint(
    hints_by_target: dict[str, tuple[str, float]],
    hints_by_target_port: dict[str, tuple[str, float]],
    dst_ip: str,
    dst_port: int,
    campaign_id: str,
    wall_now: float,
    allow_target_scope: bool,
) -> None:
    campaign_id = str(campaign_id or "").strip()
    dst_ip = str(dst_ip or "").strip()
    dst_port = int(dst_port or 0)
    if not campaign_id or not dst_ip:
        return
    hints_by_target_port[f"{dst_ip}:{dst_port}"] = (campaign_id, wall_now)
    # Only extend a hint to the whole target when the event already matches a
    # legitimate remote-access port. This avoids leaking a campaign identity to
    # unrelated traffic on the same host and suppresses false positives.
    if allow_target_scope:
        hints_by_target[dst_ip] = (campaign_id, wall_now)


def _infer_campaign_id(
    event: dict[str, Any],
    hints_by_target: dict[str, tuple[str, float]],
    hints_by_target_port: dict[str, tuple[str, float]],
    wall_now: float,
) -> str:
    campaign_id = str(event.get("campaign_id", "") or "").strip()
    if campaign_id:
        return campaign_id
    dst_ip = str(event.get("dst_ip", "") or "").strip()
    dst_port = int(event.get("dst_port", 0) or 0)
    hinted = hints_by_target_port.get(f"{dst_ip}:{dst_port}") if dst_ip else None
    if hinted and (wall_now - float(hinted[1])) <= CAMPAIGN_DEDUP_TTL_SECONDS:
        return str(hinted[0]).strip()
    # Only inherit a campaign from the whole target when the packet is already
    # pointing at a supported remote-access service. Otherwise a single auth
    # attempt can incorrectly label unrelated packets on the same host.
    hinted = hints_by_target.get(dst_ip) if dst_port in ALLOWED_REMOTE_PORTS else None
    if hinted and (wall_now - float(hinted[1])) <= CAMPAIGN_DEDUP_TTL_SECONDS:
        return str(hinted[0]).strip()
    return ""


def _load_trace_offset(trace_path: Path) -> int:
    try:
        if not trace_path.exists():
            return 0
        return int(trace_path.stat().st_size)
    except Exception:
        return 0


def _read_tshark_events_since(trace_path: Path, offset: int) -> tuple[list[dict[str, Any]], int]:
    if not trace_path.exists():
        return [], offset
    try:
        size = int(trace_path.stat().st_size)
        if size < offset:
            offset = 0
        if size == offset:
            return [], offset
        with trace_path.open("rb") as handle:
            handle.seek(offset)
            blob = handle.read().decode("utf-8", errors="replace")
        new_offset = size
        events: list[dict[str, Any]] = []
        for line in blob.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            event = normalize_event(payload, topic=KAFKA_TOPIC_IN)
            if event is not None:
                events.append(event)
        return events, new_offset
    except Exception:
        return [], offset


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

    attack_label = "Bruteforce Password Spraying Detected (T1110.003)"
    if str(alert.get("alert_type", "")).strip() == "hybrid_lateral_remote_execution":
        attack_label = "Hybrid Lateral Remote Execution Detected (T1021/T1059/T1078)"

    return {
        "msg": f"{attack_label} failed={failed} uniq_src={uniq_ips} uniq_users={uniq_users}",
        "rule": "NOVADEF-NID:100001 Bruteforce",
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
        "campaign_id": str(alert.get("campaign_id", "") or ""),
        "src_ip": primary_src,
        # Full list of distinct attacker source IPs — src_ip/src_ap above only
        # carry the first one (kept for backwards compat with consumers that
        # expect a single value), but a distributed/coordinated attack has
        # many. stream_low's MongoDB coordinated-flow lookup can reconstruct
        # this independently, but that is a fallback; carrying the real list
        # here means the profile is correct even if that lookup's window or
        # flow data is incomplete.
        "src_ips": src_ips,
        "dst_ip": dst_ip,
    }


def _process_event(
    event: dict[str, Any],
    wall_now: float,
    model: SprayingAnomalyModel,
    producer: Producer,
    recent_events: deque[dict[str, Any]],
    last_alert_by_target: dict[str, float],
    target_last_seen_ts: dict[str, float],
    alerted_active_targets: set[str],
    alerted_campaign_state: dict[str, float],
    recent_campaign_by_target: dict[str, tuple[str, float]],
    recent_campaign_by_target_port: dict[str, tuple[str, float]],
    alerted_ips_by_target: dict[str, set[str]],
) -> bool:
    allowed_remote_ports = {22, 2222, 3389, 443, 1194}

    # Only detect attacks targeting lab-internal hosts. Outbound flows from
    # the victim to public IPs (apk/apt downloads, NTP, etc.) are not attacks
    # and must not enter the Isolation Forest window — they cause false positives
    # because the synthetic benign baseline only contains internal traffic.
    if not _is_private_lab_ip(str(event.get("dst_ip", ""))):
        return False

    # Ignore flows whose source is a PMP infrastructure container (SOARCA SSH,
    # Prometheus scraper, integrators…).  These generate legitimate TCP sessions
    # to the victim that the Isolation Forest would otherwise flag as Brute Force.
    if _is_infra_src(str(event.get("src_ip", ""))):
        return False

    # Ignore flows whose DESTINATION is a PMP infrastructure container (e.g. the
    # experiments API at 172.18.0.30). Infra IPs fall inside the private lab
    # range so _is_private_lab_ip() alone does not filter them out, and health
    # checks / polling against the API were being misclassified as attacks
    # against a "victim" before any real attack traffic existed.
    if _is_infra_src(str(event.get("dst_ip", ""))):
        return False

    current_target_key = f"{event['dst_ip']}:{int(event['dst_port'])}"
    target_last_seen_ts[current_target_key] = float(event["timestamp"])

    stale_targets = [
        target
        for target in alerted_active_targets
        if (wall_now - target_last_seen_ts.get(target, 0.0)) > WINDOW_SECONDS
    ]
    for target in stale_targets:
        alerted_active_targets.discard(target)

    # NOTE: la detección se basa EXCLUSIVAMENTE en el modelo de anomalías
    # (Isolation Forest) sobre la ventana deslizante de eventos, igual que la
    # corroboración de flujos de CICFlowMeter. No se usa `campaign_id` ni ningún
    # atajo basado en etiquetas que el atacante controla: el detector debe inferir
    # el ataque únicamente de la señal comportamental (volumen de fallos, tasa,
    # distribución de IPs de origen, diversidad de usuarios/puertos). Esto es más
    # realista y científicamente válido para el artículo.
    hybrid_campaign = bool(str(event.get("hybrid_campaign", "")).strip())
    attack_family = "hybrid_lateral_remote_execution" if hybrid_campaign else "distributed_password_spraying"

    # Fast corroboration path from CICFlowMeter: same target, many short flows.
    if event.get("source_type") == "cic_flow":
        flow_window = [
            e
            for e in recent_events
            if str(e.get("dst_ip")) == str(event.get("dst_ip"))
            and int(e.get("dst_port", 0) or 0) == int(event.get("dst_port", 0) or 0)
        ]
        flow_window.append(event)
        recent_short_flows = [
            e
            for e in flow_window
            if float(e.get("flow_duration", 0.0) or 0.0) <= 3.0 or float(e.get("flow_packets_per_sec", 0.0) or 0.0) >= 20.0
        ]
        flow_src_ips = {str(e.get("src_ip", "")) for e in recent_short_flows if e.get("src_ip")}
        if len(recent_short_flows) >= 3 and len(flow_src_ips) >= MIN_UNIQUE_IPS:
            feature_map = {
                "unique_src_ips": float(len(flow_src_ips)),
                "unique_target_users": float(len({str(e.get("username", "")) for e in recent_short_flows if e.get("username")})),
                "failed_attempts": float(len(recent_short_flows)),
                "requests_per_minute": float(len(recent_short_flows)) * 60.0,
                "time_distribution_stddev": float(0.0),
                "port_variation": float(len({int(e.get("dst_port", 0) or 0) for e in recent_short_flows})),
                "protocol_diversity": float(len({str(e.get("protocol", "")).lower() for e in recent_short_flows if e.get("protocol")})),
                "geographic_spread": float(0.0),
            }
            # Dedup by target, consistent with the main window path: re-emit
            # when new source IPs join, gated by the same short cooldown, so
            # this fast corroboration path also contributes newly-seen IPs to
            # the Alert Manager's accumulated campaign profile instead of
            # going silent after the first flow-based alert.
            dedup_key = f"attack|target={event['dst_ip']}:{int(event['dst_port'])}|family=distributed_password_spraying"
            _previously_reported_flow_ips = alerted_ips_by_target.get(dedup_key, set())
            _new_flow_ips = flow_src_ips - _previously_reported_flow_ips
            _has_new_ips = bool(_new_flow_ips) or not _previously_reported_flow_ips
            if (
                _has_new_ips
                and (wall_now - last_alert_by_target.get(dedup_key, 0.0) >= DEDUP_SECONDS)
            ):
                alert = {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(wall_now)),
                    "detector": "network_intrusion_detector",
                    "correlation_id": f"nid-{event['dst_ip']}-flow-{int(wall_now // 1800)}",
                    "campaign_id": str(event.get("campaign_id", "") or ""),
                    "alert_type": "distributed_password_spraying",
                    "title": f"Distributed Password Spraying against {event['dst_ip']}:{event['dst_port']}",
                    "src_ips": sorted(flow_src_ips),
                    "dst_ip": str(event["dst_ip"]),
                    "dst_port": int(event["dst_port"]),
                    "usernames": sorted({str(e.get("username", "")) for e in recent_short_flows if e.get("username")}),
                    "failed_attempts": len(recent_short_flows),
                    "host_signal_seen": False,
                    "window_seconds": 5,
                    "requests_per_minute": feature_map["requests_per_minute"],
                    "anomaly_score": 0.0,
                    "model_anomaly": True,
                    "features": feature_map,
                    "mitre_attack": ["T1110", "T1110.003", "T1133"],
                    "d3fend_candidates": [
                        "Network Traffic Filtering",
                        "Inbound Traffic Filtering",
                        "Account Locking",
                        "Connected Honeynet",
                        "Session Termination",
                    ],
                    "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(min(float(e["timestamp"]) for e in recent_short_flows))),
                    "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(float(e["timestamp"]) for e in recent_short_flows))),
                }
                append_alert(alert)
                producer.produce(KAFKA_TOPIC_OUT, value=json.dumps(alert).encode("utf-8"))
                tapcd_compat_event = _to_tapcd_compat_snort_event(alert)
                producer.produce(KAFKA_TOPIC_TAPCD_COMPAT, value=json.dumps(tapcd_compat_event).encode("utf-8"))
                producer.poll(0)
                alerted_active_targets.add(dedup_key)
                alerted_ips_by_target[dedup_key] = _previously_reported_flow_ips | flow_src_ips
                last_alert_by_target[dedup_key] = wall_now
                alerted_campaign_state[dedup_key] = wall_now
                _save_campaign_state(alerted_campaign_state)
                logger.warning("Alerta por flows publicada (corroboración CICFlowMeter): %s", alert["title"])
                return True

    recent_events.append(event)
    # Prefer packet-count windows over time windows when configured. This keeps
    # the detector aligned with the PMP telemetry stream and avoids waiting for
    # a wall-clock interval when the relevant burst is already present.
    if WINDOW_PACKETS > 0:
        while len(recent_events) > WINDOW_PACKETS:
            recent_events.popleft()
    elif WINDOW_SECONDS > 0:
        while recent_events and (float(event["timestamp"]) - float(recent_events[0]["timestamp"])) > WINDOW_SECONDS:
            recent_events.popleft()

    by_target: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for item in recent_events:
        key = (str(item["dst_ip"]), int(item["dst_port"]))
        by_target.setdefault(key, []).append(item)

    for (dst_ip, dst_port), window_events in by_target.items():
        target_last_seen_ts[f"{dst_ip}:{dst_port}"] = float(max(float(item["timestamp"]) for item in window_events))
        failed_attempts = sum(1 for item in window_events if not item["auth_success"])
        unique_src_ips = {item["src_ip"] for item in window_events}
        unique_users = {item["username"] for item in window_events}
        host_signal_seen = any(bool(item.get("host_signal")) for item in window_events)
        hybrid_campaign = any(bool(str(item.get("hybrid_campaign", "")).strip()) for item in window_events)
        campaign_id = ""
        if failed_attempts < MIN_FAILURES:
            continue
        if len(unique_src_ips) < MIN_UNIQUE_IPS:
            continue
        if len(unique_users) < MIN_UNIQUE_USERS:
            continue
        # Solo evaluamos puertos de acceso remoto soportados; sin campaign_id la
        # decisión recae enteramente en el modelo de anomalías.
        if (
            attack_family == "distributed_password_spraying"
            and dst_port not in allowed_remote_ports
        ):
            continue

        is_anomaly, score, feature_map = model.score(window_events)
        # El modelo de anomalías es el ÚNICO juez: si no marca anomalía, no se
        # emite alerta. Esto garantiza que la detección venga del Isolation Forest
        # y no de simples umbrales de conteo.
        if not is_anomaly:
            continue

        alert_type = "distributed_password_spraying"
        mitre_attack = ["T1110", "T1110.003", "T1133"]
        d3fend_candidates = [
            "Network Traffic Filtering",
            "Inbound Traffic Filtering",
            "Account Locking",
            "Connected Honeynet",
            "Session Termination",
        ]
        title = f"Distributed Password Spraying against {dst_ip}:{dst_port}"
        if hybrid_campaign:
            alert_type = "hybrid_lateral_remote_execution"
            mitre_attack = ["T1078", "T1021", "T1059", "T1047"]
            d3fend_candidates = [
                "Network Traffic Filtering",
                "Session Termination",
                "Execution Isolation",
                "Process Termination",
            ]
            title = f"Hybrid Lateral Remote Execution against {dst_ip}:{dst_port}"

        first_seen_ts = min(float(item["timestamp"]) for item in window_events)
        # Dedup by (target, attack family): re-emit an alert for the same
        # attack whenever a source IP that was not reported yet joins it, so
        # a distributed attack's profile can be built up incrementally
        # (the reported source IP set grows across emissions) instead of
        # freezing at whichever single IP happened to trigger the very first
        # alert. A short cooldown (DEDUP_SECONDS) between emissions for the
        # SAME target prevents flooding when many new IPs arrive in a burst.
        # Correlation/dedup toward MISP/TAPCD is the Alert Manager's job: it
        # accumulates the source IP sets across these re-emissions under one
        # campaign_id and updates a single downstream event/profile — this
        # detector no longer needs to suppress everything after the first
        # alert to avoid duplicates upstream.
        dedup_key = f"attack|target={dst_ip}:{dst_port}|family={attack_family}"
        correlation_id = f"nid-{dst_ip}-{int(first_seen_ts)}"

        previously_reported_ips = alerted_ips_by_target.get(dedup_key, set())
        new_ips = unique_src_ips - previously_reported_ips
        if previously_reported_ips and not new_ips:
            # Same IP set as last time — nothing new to report.
            continue
        if previously_reported_ips and (wall_now - last_alert_by_target.get(dedup_key, 0.0)) < DEDUP_SECONDS:
            # New IP(s) present, but still inside the cooldown window since the
            # last emission for this target — wait so we do not flood one
            # alert per newly-seen IP within a fast burst.
            continue
        last_alert_by_target[dedup_key] = wall_now
        alerted_ips_by_target[dedup_key] = previously_reported_ips | unique_src_ips
        alerted_active_targets.add(dedup_key)

        alert = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(wall_now)),
            "detector": "network_intrusion_detector",
            "correlation_id": correlation_id,
            "campaign_id": campaign_id,
            "alert_type": alert_type,
            "title": title,
            "src_ips": sorted(unique_src_ips),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "usernames": sorted(unique_users),
            "failed_attempts": failed_attempts,
            "host_signal_seen": host_signal_seen,
            "window_seconds": WINDOW_SECONDS,
            "requests_per_minute": feature_map["requests_per_minute"],
            "anomaly_score": score,
            "model_anomaly": bool(is_anomaly),
            "features": feature_map,
            "mitre_attack": mitre_attack,
            "d3fend_candidates": d3fend_candidates,
            "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(first_seen_ts)),
            "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(float(item["timestamp"]) for item in window_events))),
        }

        append_alert(alert)
        producer.produce(KAFKA_TOPIC_OUT, value=json.dumps(alert).encode("utf-8"))
        tapcd_compat_event = _to_tapcd_compat_snort_event(alert)
        producer.produce(KAFKA_TOPIC_TAPCD_COMPAT, value=json.dumps(tapcd_compat_event).encode("utf-8"))
        producer.poll(0)
        # Persist last-emission timestamp for this target (survives detector
        # restarts). No longer used to suppress re-emission — that is now
        # gated purely by new-IP presence + the short DEDUP_SECONDS cooldown
        # above — but kept for observability/debugging of attack timelines.
        alerted_campaign_state[dedup_key] = wall_now
        _save_campaign_state(alerted_campaign_state)
        logger.info(
            "Evento TAPCD-compat publicado en %s: %s -> %s",
            KAFKA_TOPIC_TAPCD_COMPAT,
            tapcd_compat_event.get("src_ap"),
            tapcd_compat_event.get("dst_ap"),
        )
        logger.warning(
            "Alerta publicada (Isolation Forest): %s (%s IPs, %s usuarios, %s fallos, score=%.4f) alert_type=%s",
            alert["title"],
            len(unique_src_ips),
            len(unique_users),
            failed_attempts,
            score,
            alert_type,
        )
        return True

    return False


def main() -> None:
    model = SprayingAnomalyModel()
    model.train()

    _ensure_kafka_topics([KAFKA_TOPIC_IN, KAFKA_TOPIC_FLOW_IN, KAFKA_TOPIC_OUT, KAFKA_TOPIC_TAPCD_COMPAT])
    consumer = _kafka_consumer()
    producer = _kafka_producer()
    # Solo observación pasiva de red: tshark (paquetes) y CICFlowMeter (flujos).
    # NO se consume network_auth_events: el atacante no alimenta al defensor.
    consumer.subscribe([KAFKA_TOPIC_IN, KAFKA_TOPIC_FLOW_IN])

    recent_events: deque[dict[str, Any]] = deque(maxlen=WINDOW_PACKETS if WINDOW_PACKETS > 0 else None)
    last_alert_by_target: dict[str, float] = {}
    target_last_seen_ts: dict[str, float] = {}
    alerted_active_targets: set[str] = set()
    alerted_campaign_state = _load_campaign_state()
    recent_campaign_by_target: dict[str, tuple[str, float]] = {}
    recent_campaign_by_target_port: dict[str, tuple[str, float]] = {}
    # Tracks which source IPs have already been reported per (target, family)
    # dedup_key, so re-emissions only fire when a genuinely new IP joins the
    # attack — see _process_event's dedup logic.
    alerted_ips_by_target: dict[str, set[str]] = {}
    tshark_offset = _load_trace_offset(TSHARK_TRACE_PATH)
    runtime_log_offsets = _load_runtime_offsets()

    logger.info("Escuchando %s y publicando alertas en %s", KAFKA_TOPIC_IN, KAFKA_TOPIC_OUT)

    while True:
        # DETECCIÓN 100% PASIVA: el detector NO lee el fichero de evidencia del
        # atacante (password_spraying_attempts.jsonl). En un despliegue real el
        # defensor no tiene acceso a los logs del atacante. La única telemetría
        # de entrada es la OBSERVACIÓN DE RED: tshark (paquetes) y CICFlowMeter
        # (flujos), consumidos vía archivo de traza y vía Kafka más abajo.
        file_events, tshark_offset = _read_tshark_events_since(TSHARK_TRACE_PATH, tshark_offset)
        for file_event in file_events:
            _process_event(
                file_event,
                time.time(),
                model,
                producer,
                recent_events,
                last_alert_by_target,
                target_last_seen_ts,
                alerted_active_targets,
                alerted_campaign_state,
                recent_campaign_by_target,
                recent_campaign_by_target_port,
                alerted_ips_by_target,
            )

        msg = consumer.poll(POLL_TIMEOUT_SECONDS)
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

        event = normalize_event(payload, topic=msg.topic())
        if event is None:
            continue

        _process_event(
            event,
            time.time(),
            model,
            producer,
            recent_events,
            last_alert_by_target,
            target_last_seen_ts,
            alerted_active_targets,
            alerted_campaign_state,
            recent_campaign_by_target,
            recent_campaign_by_target_port,
            alerted_ips_by_target,
        )


if __name__ == "__main__":
    main()
