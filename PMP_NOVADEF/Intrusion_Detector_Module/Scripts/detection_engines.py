"""Detection engines: the fast fan-in detector (primary) and the Isolation
Forest slow-path detector (optional enrichment/legacy)."""

import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from confluent_kafka import Producer

from Scripts import config
from Scripts.alert_dedup_state import append_alert, save_alert_dedup_state
from Scripts.isolation_forest_model import SprayingAnomalyModel

logger = logging.getLogger("network_intrusion_detector")

_MITRE_ATTACK_SPRAYING = ["T1110", "T1110.003", "T1133"]
_D3FEND_CANDIDATES_SPRAYING = [
    "Network Traffic Filtering",
    "Inbound Traffic Filtering",
    "Account Locking",
    "Connected Honeynet",
    "Session Termination",
]


@dataclass
class SlowPathState:
    """Mutable state the Isolation Forest slow-path detector carries across events."""

    recent_events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=config.WINDOW_PACKETS or None))
    last_alert_by_target: dict[str, float] = field(default_factory=dict)
    target_last_seen_ts: dict[str, float] = field(default_factory=dict)
    alerted_active_targets: set[str] = field(default_factory=set)
    alerted_ips_by_target: dict[str, set[str]] = field(default_factory=dict)
    alert_dedup_state: dict[str, float] = field(default_factory=dict)


def _format_ts(epoch: float) -> str:
    """Format a unix timestamp as the UTC ISO string used across alerts."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _publish_alert(producer: Producer, alert: dict[str, Any]) -> None:
    """Persist the alert to disk and publish it on the detector's own Kafka topic."""
    append_alert(alert)
    producer.produce(config.KAFKA_TOPIC_OUT, value=json.dumps(alert).encode("utf-8"))
    producer.poll(0)


def _try_flow_corroboration_alert(
    event: dict[str, Any],
    wall_now: float,
    producer: Producer,
    state: SlowPathState,
) -> bool:
    """Fast corroboration path from CICFlowMeter: alert early when the same
    target already has several short/high-rate flows from distinct sources."""
    flow_window = [
        e for e in state.recent_events
        if str(e.get("dst_ip")) == str(event.get("dst_ip"))
        and int(e.get("dst_port", 0) or 0) == int(event.get("dst_port", 0) or 0)
    ]
    flow_window.append(event)
    recent_short_flows = [
        e for e in flow_window
        if float(e.get("flow_duration", 0.0) or 0.0) <= 3.0 or float(e.get("flow_packets_per_sec", 0.0) or 0.0) >= 20.0
    ]
    flow_src_ips = {str(e.get("src_ip", "")) for e in recent_short_flows if e.get("src_ip")}
    if len(recent_short_flows) < 3 or len(flow_src_ips) < config.MIN_UNIQUE_IPS:
        return False

    dedup_key = f"attack|target={event['dst_ip']}:{int(event['dst_port'])}|family=distributed_password_spraying"
    previously_reported_ips = state.alerted_ips_by_target.get(dedup_key, set())
    new_ips = flow_src_ips - previously_reported_ips
    has_new_ips = bool(new_ips) or not previously_reported_ips
    if not has_new_ips or (wall_now - state.last_alert_by_target.get(dedup_key, 0.0)) < config.DEDUP_SECONDS:
        return False

    feature_map = {
        "unique_src_ips": float(len(flow_src_ips)),
        "unique_target_users": float(len({str(e.get("username", "")) for e in recent_short_flows if e.get("username")})),
        "failed_attempts": float(len(recent_short_flows)),
        "requests_per_minute": float(len(recent_short_flows)) * 60.0,
        "time_distribution_stddev": 0.0,
        "port_variation": float(len({int(e.get("dst_port", 0) or 0) for e in recent_short_flows})),
        "protocol_diversity": float(len({str(e.get("protocol", "")).lower() for e in recent_short_flows if e.get("protocol")})),
        "geographic_spread": 0.0,
    }
    alert = {
        "timestamp": _format_ts(wall_now),
        "detector": "network_intrusion_detector",
        "correlation_id": f"nid-{event['dst_ip']}-flow-{int(wall_now // 1800)}",
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
        "mitre_attack": _MITRE_ATTACK_SPRAYING,
        "d3fend_candidates": _D3FEND_CANDIDATES_SPRAYING,
        "first_seen": _format_ts(min(float(e["timestamp"]) for e in recent_short_flows)),
        "last_seen": _format_ts(max(float(e["timestamp"]) for e in recent_short_flows)),
    }
    _publish_alert(producer, alert)
    state.alerted_active_targets.add(dedup_key)
    state.alerted_ips_by_target[dedup_key] = previously_reported_ips | flow_src_ips
    state.last_alert_by_target[dedup_key] = wall_now
    state.alert_dedup_state[dedup_key] = wall_now
    save_alert_dedup_state(state.alert_dedup_state)
    logger.warning("Flow-corroboration alert published: %s", alert["title"])
    return True


def _evaluate_window(
    dst_ip: str,
    dst_port: int,
    window_events: list[dict[str, Any]],
    wall_now: float,
    model: SprayingAnomalyModel,
    producer: Producer,
    state: SlowPathState,
) -> bool:
    """Score one (dst_ip, dst_port) window against the Isolation Forest and
    publish an alert if it both meets the volume thresholds and is anomalous."""
    failed_attempts = sum(1 for item in window_events if not item["auth_success"])
    unique_src_ips = {item["src_ip"] for item in window_events}
    unique_users = {item["username"] for item in window_events}
    host_signal_seen = any(bool(item.get("host_signal")) for item in window_events)
    hybrid_campaign = any(bool(str(item.get("hybrid_campaign", "")).strip()) for item in window_events)
    attack_family = "hybrid_lateral_remote_execution" if hybrid_campaign else "distributed_password_spraying"

    if failed_attempts < config.MIN_FAILURES:
        return False
    if len(unique_src_ips) < config.MIN_UNIQUE_IPS:
        return False
    if len(unique_users) < config.MIN_UNIQUE_USERS:
        return False
    if attack_family == "distributed_password_spraying" and dst_port not in config.ALLOWED_REMOTE_PORTS:
        return False

    # The Isolation Forest is the sole judge: no alert without a real anomaly.
    is_anomaly, score, feature_map = model.score(window_events)
    if not is_anomaly:
        return False

    alert_type = "distributed_password_spraying"
    mitre_attack = _MITRE_ATTACK_SPRAYING
    d3fend_candidates = _D3FEND_CANDIDATES_SPRAYING
    title = f"Distributed Password Spraying against {dst_ip}:{dst_port}"
    if hybrid_campaign:
        alert_type = "hybrid_lateral_remote_execution"
        mitre_attack = ["T1078", "T1021", "T1059", "T1047"]
        d3fend_candidates = ["Network Traffic Filtering", "Session Termination", "Execution Isolation", "Process Termination"]
        title = f"Hybrid Lateral Remote Execution against {dst_ip}:{dst_port}"

    first_seen_ts = min(float(item["timestamp"]) for item in window_events)
    dedup_key = f"attack|target={dst_ip}:{dst_port}|family={attack_family}"

    # Re-emit when a source IP that was not reported yet joins the attack, so
    # the profile builds up incrementally instead of freezing on the first
    # alert. Correlation/dedup toward MISP/TAPCD is Alert Manager's job.
    previously_reported_ips = state.alerted_ips_by_target.get(dedup_key, set())
    new_ips = unique_src_ips - previously_reported_ips
    if previously_reported_ips and not new_ips:
        return False
    if previously_reported_ips and (wall_now - state.last_alert_by_target.get(dedup_key, 0.0)) < config.DEDUP_SECONDS:
        return False

    state.last_alert_by_target[dedup_key] = wall_now
    state.alerted_ips_by_target[dedup_key] = previously_reported_ips | unique_src_ips
    state.alerted_active_targets.add(dedup_key)

    alert = {
        "timestamp": _format_ts(wall_now),
        "detector": "network_intrusion_detector",
        "correlation_id": f"nid-{dst_ip}-{int(first_seen_ts)}",
        "alert_type": alert_type,
        "title": title,
        "src_ips": sorted(unique_src_ips),
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "usernames": sorted(unique_users),
        "failed_attempts": failed_attempts,
        "host_signal_seen": host_signal_seen,
        "window_seconds": config.WINDOW_SECONDS,
        "requests_per_minute": feature_map["requests_per_minute"],
        "anomaly_score": score,
        "model_anomaly": bool(is_anomaly),
        "features": feature_map,
        "mitre_attack": mitre_attack,
        "d3fend_candidates": d3fend_candidates,
        "first_seen": _format_ts(first_seen_ts),
        "last_seen": _format_ts(max(float(item["timestamp"]) for item in window_events)),
    }
    _publish_alert(producer, alert)
    # Kept for observability/debugging of attack timelines — re-emission is
    # gated purely by new-IP presence + DEDUP_SECONDS above, not by this.
    state.alert_dedup_state[dedup_key] = wall_now
    save_alert_dedup_state(state.alert_dedup_state)
    logger.warning(
        "Isolation Forest alert published: %s (%s IPs, %s users, %s failures, score=%.4f) alert_type=%s",
        title, len(unique_src_ips), len(unique_users), failed_attempts, score, alert_type,
    )
    return True


def process_event(event: dict[str, Any], wall_now: float, model: SprayingAnomalyModel, producer: Producer, state: SlowPathState) -> bool:
    """Run one normalized event through the Isolation Forest slow-path detector."""
    if not config.is_private_lab_ip(str(event.get("dst_ip", ""))):
        return False
    # Infra containers (SOARCA SSH, Prometheus scraper…) generate legitimate
    # sessions to/from the victim that would otherwise look like a bruteforce.
    if config.is_infra_src(str(event.get("src_ip", ""))) or config.is_infra_src(str(event.get("dst_ip", ""))):
        return False

    current_target_key = f"{event['dst_ip']}:{int(event['dst_port'])}"
    state.target_last_seen_ts[current_target_key] = float(event["timestamp"])
    stale_targets = [
        target for target in state.alerted_active_targets
        if (wall_now - state.target_last_seen_ts.get(target, 0.0)) > config.WINDOW_SECONDS
    ]
    for target in stale_targets:
        state.alerted_active_targets.discard(target)

    if event.get("source_type") == "cic_flow" and _try_flow_corroboration_alert(event, wall_now, producer, state):
        return True

    state.recent_events.append(event)
    # Prefer packet-count windows over time windows when configured, to stay
    # aligned with the telemetry stream instead of waiting for a wall-clock tick.
    if config.WINDOW_PACKETS > 0:
        while len(state.recent_events) > config.WINDOW_PACKETS:
            state.recent_events.popleft()
    elif config.WINDOW_SECONDS > 0:
        while state.recent_events and (float(event["timestamp"]) - float(state.recent_events[0]["timestamp"])) > config.WINDOW_SECONDS:
            state.recent_events.popleft()

    by_target: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for item in state.recent_events:
        by_target.setdefault((str(item["dst_ip"]), int(item["dst_port"])), []).append(item)

    for (dst_ip, dst_port), window_events in by_target.items():
        state.target_last_seen_ts[f"{dst_ip}:{dst_port}"] = float(max(float(item["timestamp"]) for item in window_events))
        if _evaluate_window(dst_ip, dst_port, window_events, wall_now, model, producer, state):
            return True

    return False


class FastFanInDetector:
    """Sliding-window fan-in detector: fires the moment enough distinct source
    IPs send traffic to the same (dst_ip, dst_port) inside the window — orders
    of magnitude faster than the flow-statistics path. Consumes the same
    normalized events the Isolation Forest path parses, so it needs no extra
    input of its own."""

    def __init__(self) -> None:
        """Initialize the per-target sliding windows and dedup/enrichment state."""
        # (dst_ip, dst_port) -> deque[(ts, src_ip)]
        self._windows: dict[tuple[str, int], deque[tuple[float, str]]] = {}
        self._last_alert: dict[tuple[str, int], float] = {}
        # Campaign-lifetime accumulator of every distinct src_ip ever seen for
        # this target, separate from `_windows` (which only keeps the last
        # FAST_FANIN_WINDOW_SECONDS for the trigger condition itself) — lets
        # later enrichment alerts report the full accumulated set.
        self._all_ips_seen: dict[tuple[str, int], set[str]] = {}
        self._last_enrich_alert: dict[tuple[str, int], float] = {}
        self._last_enrich_ips: dict[tuple[str, int], set[str]] = {}

    def reset(self) -> None:
        """Clear all per-target state (used between experiment runs)."""
        self._windows.clear()
        self._last_alert.clear()
        self._all_ips_seen.clear()
        self._last_enrich_alert.clear()
        self._last_enrich_ips.clear()

    def observe(self, event: dict[str, Any], producer: Producer) -> bool:
        """Feed one normalized event into the fan-in window and publish an
        alert (or enrichment alert) if the fan-in shape is met."""
        src_ip = str(event.get("src_ip", "") or "").strip()
        dst_ip = str(event.get("dst_ip", "") or "").strip()
        try:
            dst_port = int(event.get("dst_port", 0) or 0)
        except (TypeError, ValueError):
            return False
        if not src_ip or not dst_ip or not dst_port:
            return False
        try:
            ts_epoch = float(event.get("timestamp") or time.time())
        except (TypeError, ValueError):
            ts_epoch = time.time()

        # Only remote-access service ports on lab-internal victims, and never
        # count infrastructure or the victim's own replies as attackers.
        if dst_port not in config.ALLOWED_REMOTE_PORTS:
            return False
        if not config.is_private_lab_ip(dst_ip):
            return False
        if config.is_infra_src(src_ip) or src_ip == dst_ip:
            return False

        key = (dst_ip, dst_port)
        win = self._windows.setdefault(key, deque())
        win.append((ts_epoch, src_ip))
        cutoff = ts_epoch - config.FAST_FANIN_WINDOW_SECONDS
        while win and win[0][0] < cutoff:
            win.popleft()

        syn_like = list(win)
        unique_ips = {entry[1] for entry in syn_like}
        if len(unique_ips) < config.FAST_FANIN_MIN_UNIQUE_IPS or len(syn_like) < config.FAST_FANIN_MIN_SYN_PACKETS:
            return False

        seen = self._all_ips_seen.setdefault(key, set())
        seen.update(unique_ips)

        now = time.time()
        is_first_alert = (now - self._last_alert.get(key, 0.0)) >= config.FAST_FANIN_DEDUP_SECONDS
        if is_first_alert:
            self._last_alert[key] = now
            self._last_enrich_alert[key] = now
        else:
            # SOARCA's own dedup already prevents a second countermeasure, so
            # after the first alert we only emit periodic enrichment alerts.
            if (now - self._last_enrich_alert.get(key, 0.0)) < config.FAST_FANIN_ENRICH_INTERVAL_SECONDS:
                return False
            if seen <= set(self._last_enrich_ips.get(key, set())):
                return False
            self._last_enrich_alert[key] = now

        self._last_enrich_ips[key] = set(seen)
        src_ips_sorted = sorted(seen)
        alert = {
            "timestamp": _format_ts(now),
            "detector": "network_intrusion_detector",
            "correlation_id": f"nid-fastfanin-{dst_ip}-{dst_port}-{int(now // 1800)}",
            "alert_type": "distributed_password_spraying",
            "title": f"Distributed Password Spraying against {dst_ip}:{dst_port}",
            "src_ips": src_ips_sorted,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "usernames": [],
            "failed_attempts": len(syn_like),
            "host_signal_seen": False,
            "window_seconds": config.FAST_FANIN_WINDOW_SECONDS,
            "requests_per_minute": round(len(syn_like) / max(config.FAST_FANIN_WINDOW_SECONDS, 0.001) * 60.0, 1),
            "anomaly_score": 0.0,
            "model_anomaly": True,
            "detection_path": "fast_fanin" if is_first_alert else "fast_fanin_enrich",
            "features": {
                "unique_source_ips": len(seen),
                "syn_packets_in_window": len(syn_like),
            },
            "mitre_attack": _MITRE_ATTACK_SPRAYING,
            "d3fend_candidates": _D3FEND_CANDIDATES_SPRAYING,
            "first_seen": _format_ts(min(e[0] for e in syn_like)),
            "last_seen": _format_ts(max(e[0] for e in syn_like)),
        }
        try:
            _publish_alert(producer, alert)
            logger.info(
                "Fast fan-in %s: %s:%s uniq_src=%d syn_pkts=%d (window=%ss)",
                "alert" if is_first_alert else "enrichment",
                dst_ip, dst_port, len(seen), len(syn_like), config.FAST_FANIN_WINDOW_SECONDS,
            )
        except Exception as exc:
            logger.warning("Fast fan-in alert publish failed: %s", exc)
            return False
        return True
