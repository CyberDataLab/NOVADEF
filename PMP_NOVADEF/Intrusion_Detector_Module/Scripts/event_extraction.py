"""Adapters that turn raw Kafka payloads (tshark packets, CICFlowMeter flows)
into the common internal event schema the detectors work with."""

import re
import time
from typing import Any

from Scripts.config import ALLOWED_REMOTE_PORTS, KAFKA_TOPIC_FLOW_IN, KAFKA_TOPIC_IN


def _normalize_key(key: str) -> str:
    """Lowercase a field name and strip anything but letters/digits, for lookup."""
    return re.sub(r"[^a-z0-9]+", "", str(key).lower())


def _get_any(payload: dict[str, Any], *names: str) -> Any:
    """Return the first non-empty value found among several candidate field names."""
    if not isinstance(payload, dict):
        return None
    normalized = {_normalize_key(k): v for k, v in payload.items()}
    for name in names:
        value = normalized.get(_normalize_key(name))
        if value not in {None, ""}:
            return value
    return None


def _extract_tshark_packet(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a normalized packet event from a tshark NDJSON record."""
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
    if not isinstance(layers, dict):
        return None

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

    if not src_ip or not dst_ip:
        return None

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
        "timestamp": timestamp,
        "source_type": "tshark",
    }


def _extract_cic_flow_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a normalized flow event from a CICFlowMeter JSON record, keeping
    only flows that look like a suspicious SSH-bruteforce shape."""
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

    def _num(value: Any) -> float:
        """Best-effort float conversion, tolerant of a comma decimal separator."""
        try:
            return float(str(value).replace(",", "."))
        except Exception:
            return 0.0

    flow_duration_f = _num(_get_any(payload, "flow duration", "flow_duration", "Duration"))
    flow_pps_f = _num(_get_any(payload, "flow packets/s", "flow_packets/s", "packets/s", "Flow Packets/s"))
    flow_bps_f = _num(_get_any(payload, "flow bytes/s", "flow_bytes/s", "bytes/s", "Flow Bytes/s"))
    total_fwd_f = _num(_get_any(payload, "total fwd packets", "Total Fwd Packets", "fwd packets"))
    total_bwd_f = _num(_get_any(payload, "total backward packets", "Total Backward Packets", "bwd packets"))
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
        "timestamp": timestamp,
        "source_type": "cic_flow",
        "flow_duration": flow_duration_f,
        "flow_packets_per_sec": flow_pps_f,
        "flow_bytes_per_sec": flow_bps_f,
        "total_fwd_packets": total_fwd_f,
        "total_backward_packets": total_bwd_f,
    }


def normalize_event(payload: dict[str, Any], topic: str | None = None) -> dict[str, Any] | None:
    """Dispatch a raw Kafka payload to the right extractor based on its topic,
    falling back to trying both when the topic is missing or unrecognized."""
    topic = str(topic or "").strip()
    if topic == KAFKA_TOPIC_IN:
        return _extract_tshark_packet(payload)
    if topic == KAFKA_TOPIC_FLOW_IN:
        return _extract_cic_flow_event(payload)
    return _extract_tshark_packet(payload) or _extract_cic_flow_event(payload)
