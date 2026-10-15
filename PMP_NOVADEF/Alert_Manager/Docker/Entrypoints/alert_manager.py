#!/usr/bin/env python3
"""
Alert Manager — NOVADEF campaign correlator.

Consumes detection alerts from ALL sources:
  - network_intrusion_alerts  (Isolation Forest on tshark)
  - falco_events              (Falco host-level rules)
  - snort_alerts              (raw Snort/IDS TAPCD-compat)

Correlates events by victim IP within a temporal window to infer
that they belong to the same attack campaign (e.g. password spraying
followed by ransomware deployment = hybrid APT campaign).

Generates a campaign_id of the form:  <dst_ip>-<epoch_bucket>
where epoch_bucket = floor(event_unix_time / CAMPAIGN_WINDOW_SECS)

Publishes enriched events to:
  - pmp_alerts                     (consumed by MISP, JSON with campaign_id)
  - alert_manager_tapcd_compat_alerts (Snort-shaped format for stream_low;
                                       carries all 3 sources, not just Snort)
"""

import json
import logging
import math
import os
import re
import signal
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from confluent_kafka import Consumer, Producer, KafkaError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ALERT-MGR] %(levelname)s %(message)s",
)
log = logging.getLogger("alert_manager")

# ---------------------------------------------------------------------------
# Config from env
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP")

# Input topics are reused as-is from their producer's own variable name
# (NetworkIntrusionDetectorConfig/FalcoConfig/Snort3Config) so the
# Configuration Manager's generic consumer-topic resolution can overwrite
# them without a per-tool special case.
TOPIC_NETWORK_ALERTS = os.getenv("NID_KAFKA_TOPIC_OUT")
TOPIC_FALCO           = os.getenv("FALCO_BASE_TOPIC")
TOPIC_SNORT_IN        = os.getenv("SNORT_KAFKA_TOPIC_OUT")

TOPIC_PMP_ALERTS      = os.getenv("ALERT_MANAGER_PMP_ALERTS")
# NOTE: carries Snort, Falco AND the intrusion detector's alerts, despite the
# TAPCD-compat *format* being Snort-shaped — not a Snort-only topic.
TOPIC_TAPCD_COMPAT    = os.getenv("ALERT_MANAGER_TAPCD_COMPAT_ALERTS")

GROUP_ID = os.getenv("ALERT_MANAGER_KAFKA_GROUP_ID")

# Falco host-level rules (file/process activity, e.g. ransomware encryption)
# often carry no network fields at all — there is no src/dst IP to extract from
# a local `openssl enc` syscall. Resolve the currently active scenario victim
# dynamically (DNS of the scenario hostname) so those events can still be
# attributed to a victim_ip and correlated into a campaign. Same pattern as
# MISP's _resolve_victim_ip().
#
# This hostname is a fixed architectural contract (the alias NOVADEF_GUI's
# app.py always binds via _ensure_launcher_network_alias()), not something an
# operator tunes — hardcoded, not an env var.
_SCENARIO_VICTIM_HOSTNAME = "scenario_victim"


def _resolve_victim_ip_uncached() -> str:
    # NOTE (verify in a real run before/soon after this change ships): there
    # used to be a hardcoded fallback IP here for when DNS resolution fails.
    # It was removed as dead weight — _parse_falco_event() already drops an
    # event cleanly when victim_ip is empty, which is safer than silently
    # mis-attributing it to a guessed IP. But if Falco-sourced alerts start
    # disappearing from pmp_alerts after this, that means resolution was
    # failing more often than the code's own history suggested — the fix is
    # to repair the DNS/alias resolution, NOT to reintroduce a guessed IP.
    try:
        return socket.gethostbyname(_SCENARIO_VICTIM_HOSTNAME)
    except Exception:
        return ""


# Cached briefly: an uncached lookup pays the full DNS delay (~10s measured,
# right after the alias rebinds on each experiment launch) on every one of
# the hundreds/sec of host events a ransomware run can produce.
_victim_ip_cache_lock = threading.Lock()
_victim_ip_cache_value: str = ""
_victim_ip_cache_at: float = 0.0
_VICTIM_IP_CACHE_TTL_SECS = 30.0


def _resolve_victim_ip() -> str:
    global _victim_ip_cache_value, _victim_ip_cache_at
    now = time.time()
    with _victim_ip_cache_lock:
        if _victim_ip_cache_value and (now - _victim_ip_cache_at) < _VICTIM_IP_CACHE_TTL_SECS:
            return _victim_ip_cache_value
    resolved = _resolve_victim_ip_uncached()
    with _victim_ip_cache_lock:
        _victim_ip_cache_value = resolved
        _victim_ip_cache_at = now
    return resolved


# Window in seconds within which two events on the same victim IP are considered
# the same campaign. Default 30 min.
CAMPAIGN_WINDOW_SECS = int(os.getenv("ALERT_MANAGER_CAMPAIGN_WINDOW_SECS"))

# How long (seconds) we keep campaign state in memory after last activity.
CAMPAIGN_TTL_SECS = int(os.getenv("ALERT_MANAGER_CAMPAIGN_TTL_SECS"))

# ---------------------------------------------------------------------------
# Global state: victim_ip -> campaign metadata
# Protected by a simple lock (single-threaded consumer, but lock for GC thread)
# ---------------------------------------------------------------------------
_state_lock = threading.Lock()
# {victim_ip: {"campaign_id": str, "epoch_bucket": int, "last_seen": float,
#              "attacker_ips": set[str]}}
# attacker_ips accumulates every source IP seen for this campaign, so each
# outgoing event carries the full set — one actor profile per campaign in
# MISP/TAPCD, not one per triggering IP.
_campaigns: dict[str, dict] = {}

_closing = False


def _sig_handler(signum, frame):
    global _closing
    log.info("Signal %s received — shutting down", signum)
    _closing = True


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# Campaign correlation logic
# ---------------------------------------------------------------------------

def _epoch_bucket(ts_unix: float) -> int:
    return int(math.floor(ts_unix / CAMPAIGN_WINDOW_SECS))


def _make_campaign_id(victim_ip: str, epoch_bucket: int) -> str:
    safe_ip = victim_ip.replace(".", "_")
    return f"camp_{safe_ip}_{epoch_bucket}"


def _infer_campaign(victim_ip: str, event_time: float) -> str:
    """
    Return (and register) the campaign_id for this victim_ip at event_time.

    If there is already an active campaign for this victim (last_seen within
    CAMPAIGN_WINDOW_SECS), return the SAME campaign_id regardless of the current
    epoch bucket — this keeps phases of a multi-stage attack in one campaign.

    If no active campaign exists, create a new one based on the current epoch bucket.
    """
    with _state_lock:
        existing = _campaigns.get(victim_ip)
        if existing:
            idle_secs = event_time - existing["last_seen"]
            if idle_secs <= CAMPAIGN_WINDOW_SECS:
                existing["last_seen"] = event_time
                cid = existing["campaign_id"]
                log.debug("[CORRELATE] victim=%s → existing campaign %s (idle=%.0fs)", victim_ip, cid, idle_secs)
                return cid
            # Campaign expired — start a new one
            log.info(
                "[CORRELATE] victim=%s — campaign %s expired after %.0fs idle, starting new campaign",
                victim_ip, existing["campaign_id"], idle_secs,
            )

        bucket = _epoch_bucket(event_time)
        cid = _make_campaign_id(victim_ip, bucket)
        _campaigns[victim_ip] = {
            "campaign_id": cid,
            "epoch_bucket": bucket,
            "last_seen": event_time,
            "attacker_ips": set(),
        }
        log.info("[CORRELATE] victim=%s → NEW campaign %s", victim_ip, cid)
        return cid


def _accumulate_attacker_ips(victim_ip: str, ips: list[str]) -> set[str]:
    """Add ips to the campaign's accumulated attacker-IP set for victim_ip and
    return the full accumulated set. Safe to call with an empty/missing list —
    the returned set still reflects whatever was accumulated before."""
    clean_ips = {str(ip).strip() for ip in (ips or []) if str(ip).strip()}
    with _state_lock:
        campaign = _campaigns.get(victim_ip)
        if campaign is None:
            # _infer_campaign() should always be called first for this victim,
            # but guard defensively so this never raises.
            return clean_ips
        existing_ips = campaign.setdefault("attacker_ips", set())
        existing_ips.update(clean_ips)
        return set(existing_ips)


def _gc_expired_campaigns():
    """Remove stale campaign entries (called periodically)."""
    cutoff = time.time() - CAMPAIGN_TTL_SECS
    with _state_lock:
        expired = [ip for ip, meta in _campaigns.items() if meta["last_seen"] < cutoff]
        for ip in expired:
            log.info("[GC] Removing expired campaign for victim=%s (%s)", ip, _campaigns[ip]["campaign_id"])
            del _campaigns[ip]


# ---------------------------------------------------------------------------
# Kafka helpers
# ---------------------------------------------------------------------------

def _build_consumer(topics: list[str], group_suffix: str) -> Consumer:
    # Each topic gets its OWN consumer (own group.id) so a burst on one topic
    # can never delay the others — see _consume_topic()'s docstring for why
    # this replaced a single shared consumer across all three topics.
    cfg = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": f"{GROUP_ID}-{group_suffix}",
        "enable.auto.commit": False,
        "auto.offset.reset": "latest",
        "allow.auto.create.topics": True,
        # Kept low: a single-member group has no false-eviction risk, and a
        # high value delayed the first falco_events message ~10s after every
        # container restart (broker waiting out the old session).
        "session.timeout.ms": 6000,
        "max.poll.interval.ms": 300000,
        "socket.keepalive.enable": True,
        "partition.assignment.strategy": "cooperative-sticky",
        "enable.partition.eof": False,
    }
    consumer = Consumer(cfg)
    consumer.subscribe(topics)
    log.info("Subscribed to topics: %s (group=%s)", ", ".join(topics), cfg["group.id"])
    return consumer


def _build_producer() -> Producer:
    cfg = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "linger.ms": 5,
        "batch.size": 32768,
        "compression.type": "zstd",
        "socket.keepalive.enable": True,
    }
    return Producer(cfg)


def _produce(producer: Producer, topic: str, payload: dict):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    producer.produce(topic, value=data)
    producer.poll(0)


# ---------------------------------------------------------------------------
# Parsers — extract victim_ip + event_time + metadata from each source
# ---------------------------------------------------------------------------

def _parse_network_intrusion_alert(obj: dict) -> Optional[dict]:
    """
    Schema: {timestamp, detector, campaign_id, alert_type, title,
             src_ips, dst_ip, dst_port, failed_attempts, mitre_attack,
             first_seen, last_seen, anomaly_score, ...}
    """
    dst_ip = str(obj.get("dst_ip") or obj.get("target_ip") or "").strip()
    if not dst_ip:
        return None
    ts = obj.get("timestamp") or obj.get("last_seen") or obj.get("first_seen") or ""
    try:
        event_time = _parse_iso(ts)
    except Exception:
        event_time = time.time()

    return {
        "source": "network_intrusion_alerts",
        "victim_ip": dst_ip,
        "event_time": event_time,
        "src_ips": obj.get("src_ips", []),
        "dst_port": obj.get("dst_port"),
        "alert_type": obj.get("alert_type", "password_spraying"),
        "title": obj.get("title", ""),
        "mitre_attack": obj.get("mitre_attack", ""),
        "anomaly_score": obj.get("anomaly_score"),
        "original": obj,
    }


def _parse_falco_event(obj: dict) -> Optional[dict]:
    """
    Falco schema (as published by Data_Collection_Module):
    {"rule": str, "priority": str, "output": str, "output_fields": {...}}
    OR wrapped: the Kafka message value may itself be a JSON with a "message" field
    that contains the Falco JSON.
    """
    # Falco events can be nested inside a filebeat/logstash envelope
    if "message" in obj and isinstance(obj["message"], str):
        try:
            inner = json.loads(obj["message"])
            if "rule" in inner or "output_fields" in inner:
                obj = inner
        except Exception:
            pass

    rule = obj.get("rule", "")
    output = obj.get("output", "")
    output_fields = obj.get("output_fields") or {}

    # Extract victim IP from output_fields (container.ip, fd.rip, evt.path, etc.)
    victim_ip = (
        output_fields.get("fd.rip")
        or output_fields.get("container.ip")
        or output_fields.get("fd.lip")
        or ""
    )
    if not victim_ip:
        # Try to extract from output string: "...on 172.18.0.30..."
        m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', output)
        if m:
            victim_ip = m.group(1)

    if not victim_ip:
        # Host-level rules (file/process activity, e.g. ransomware encryption via
        # `openssl enc`) carry no network fields — there is no src/dst IP on a
        # local syscall. Attribute the event to the currently active scenario
        # victim so it can still be correlated into a campaign.
        victim_ip = _resolve_victim_ip()
        if not victim_ip:
            # DNS resolution failed — drop rather than guess a victim IP.
            return None

    ts_str = output_fields.get("evt.time") or obj.get("time") or ""
    try:
        event_time = _parse_iso(str(ts_str)) if ts_str else time.time()
    except Exception:
        event_time = time.time()

    return {
        "source": "falco_events",
        "victim_ip": victim_ip,
        "event_time": event_time,
        "rule": rule,
        "priority": obj.get("priority", ""),
        "output": output,
        "output_fields": output_fields,
        "original": obj,
    }


def _parse_snort_alert(obj: dict) -> Optional[dict]:
    """
    TAPCD-compat Snort schema: {timestamp, msg, src_ap, dst_ap, src_ip, dst_ip, ...}.
    Any campaign_id on the raw message is ignored — this module assigns its own.
    """
    dst_ip = str(obj.get("dst_ip") or "").strip()
    if not dst_ip and "dst_ap" in obj:
        dst_ip = str(obj["dst_ap"]).split(":")[0].strip()
    if not dst_ip:
        return None

    ts_str = str(obj.get("timestamp") or "").strip()
    try:
        event_time = _parse_snort_ts(ts_str)
    except Exception:
        event_time = time.time()

    return {
        "source": "snort_alerts",
        "victim_ip": dst_ip,
        "event_time": event_time,
        "msg": obj.get("msg", ""),
        "src_ap": obj.get("src_ap", ""),
        "dst_ap": obj.get("dst_ap", ""),
        "src_ip": obj.get("src_ip", ""),
        "original": obj,
    }


def _parse_iso(ts: str) -> float:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts.strip(), fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return datetime.fromisoformat(ts.strip().replace("Z", "+00:00")).timestamp()


def _parse_snort_ts(ts: str) -> float:
    """Parse MM/DD-HH:MM:SS.ffffff or ISO."""
    try:
        dt = datetime.strptime(ts, "%m/%d-%H:%M:%S.%f")
        now = datetime.now()
        return dt.replace(year=now.year).timestamp()
    except ValueError:
        pass
    try:
        return _parse_iso(ts)
    except Exception:
        return time.time()


# ---------------------------------------------------------------------------
# Output builders
# ---------------------------------------------------------------------------

def _build_pmp_alert(parsed: dict, campaign_id: str) -> dict:
    """Build a unified pmp_alerts JSON enriched with campaign_id."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    src = parsed["source"]
    orig = parsed["original"]

    # Full campaign IP set (see _accumulate_attacker_ips), included even for
    # falco_events/snort_alerts so MISP always enriches the same actor.
    accumulated_ips = parsed.get("accumulated_src_ips") or []

    base = {
        "am_version": 1,
        "campaign_id": campaign_id,
        "victim_ip": parsed["victim_ip"],
        "event_time": datetime.fromtimestamp(parsed["event_time"], tz=timezone.utc)
                        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "enriched_at": now_iso,
        "source_topic": src,
        "accumulated_src_ips": accumulated_ips,
    }

    if src == "network_intrusion_alerts":
        base.update({
            "topic": "network_intrusion_alerts",
            "alert_type": parsed.get("alert_type", ""),
            "title": parsed.get("title", ""),
            # Full campaign-accumulated set, not just this alert's own IPs —
            # falls back to the alert's own src_ips if accumulation is empty
            # (e.g. very first alert of the campaign, same-tick timing).
            "src_ips": accumulated_ips or parsed.get("src_ips", []),
            "dst_ip": parsed["victim_ip"],
            "dst_port": parsed.get("dst_port"),
            "mitre_attack": parsed.get("mitre_attack", ""),
            "anomaly_score": parsed.get("anomaly_score"),
        })
    elif src == "falco_events":
        base.update({
            "topic": "falco_events",
            "rule": parsed.get("rule", ""),
            "priority": parsed.get("priority", ""),
            "output": parsed.get("output", ""),
            "output_fields": parsed.get("output_fields", {}),
            "dst_ip": parsed["victim_ip"],
        })
    elif src == "snort_alerts":
        base.update({
            "topic": "snort_alerts",
            "msg": parsed.get("msg", ""),
            "src_ap": parsed.get("src_ap", ""),
            "dst_ap": parsed.get("dst_ap", ""),
            "src_ip": parsed.get("src_ip", ""),
            "dst_ip": parsed["victim_ip"],
        })

    # Carry through any extra fields from original
    for k, v in orig.items():
        if k not in base:
            base[k] = v

    return base


def _build_tapcd_compat_alert(parsed: dict, campaign_id: str) -> Optional[dict]:
    """
    Build a TAPCD-compat event (campaign_id injected) for network_intrusion_alerts,
    snort_alerts, AND falco_events.

    Falco used to be MISP-only here, on the assumption a host-only ransomware
    attack has no network phase to profile — but the compromised host can
    have real network activity (C2, exfiltration) worth characterizing.
    Routing it through this same path lets stream_low query MongoDB for that
    host's own flows instead of leaving the actor on a DetectionAlert-only
    stub.
    """
    src = parsed["source"]

    orig = parsed["original"]
    now = datetime.now()
    snort_ts = now.strftime("%m/%d-%H:%M:%S.") + f"{now.microsecond:06d}"

    if src == "falco_events":
        # The compromised host is both the "attacker" (it's the one running
        # the ransomware) and the victim from a network standpoint — there is
        # no separate attacker IP the way a network-phase alert has one.
        victim_ip = parsed["victim_ip"]
        return {
            "timestamp": snort_ts,
            "msg": f"Ransomware host activity on {victim_ip}",
            "src_ap": f"{victim_ip}:0",
            "dst_ap": f"{victim_ip}:0",
            "src_ip": victim_ip,
            "dst_ip": victim_ip,
            "campaign_id": campaign_id,
        }

    if src == "network_intrusion_alerts":
        # Full campaign-accumulated attacker IP set — falls back to this
        # alert's own src_ips if accumulation is empty.
        src_ips = parsed.get("accumulated_src_ips") or orig.get("src_ips") or []
        primary_src = src_ips[0] if src_ips else "0.0.0.0"
        src_port = orig.get("dst_port") or 0
        dst_port = orig.get("dst_port") or 0
        msg = orig.get("title") or orig.get("alert_type") or "Network Intrusion Detected"
        return {
            "timestamp": snort_ts,
            "msg": msg,
            "src_ap": f"{primary_src}:{src_port}",
            "dst_ap": f"{parsed['victim_ip']}:{dst_port}",
            "src_ip": primary_src,
            # Preserve the full source IP list — src_ip/src_ap above only
            # carry the first one for TAPCD-compat consumers that expect a
            # single value, but a distributed attack has many attacker IPs.
            "src_ips": src_ips,
            "dst_ip": parsed["victim_ip"],
            "campaign_id": campaign_id,
        }
    elif src == "snort_alerts":
        out = dict(orig)
        out["campaign_id"] = campaign_id
        out["dst_ip"] = parsed["victim_ip"]
        return out

    return None


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

_PARSERS = {
    TOPIC_NETWORK_ALERTS: _parse_network_intrusion_alert,
    TOPIC_FALCO: _parse_falco_event,
    TOPIC_SNORT_IN: _parse_snort_alert,
}


def _consume_topic(topic: str, group_suffix: str):
    """Run a dedicated consumer+producer loop for a SINGLE topic.

    One consumer per topic (own group, own thread) — a single shared
    consumer let a network-alert burst starve falco_events for ~10s
    (Kafka gives no round-robin guarantee across topics). _campaigns state
    stays shared, protected by _state_lock.
    """
    consumer = _build_consumer([topic], group_suffix)
    producer = _build_producer()
    parse_fn = _PARSERS[topic]

    # Flush/commit on an interval, not per-message: both block on a broker
    # round-trip (~8ms), which serialized a 10k+ Falco burst into a ~95s
    # drain (turning a sub-5s countermeasure into a 96s one). A crash
    # mid-burst only replays work since the last interval.
    _COMMIT_INTERVAL_SECS = 0.25
    _last_commit = time.time()
    _dirty_msg = None

    while not _closing:
        msg = consumer.poll(timeout=1.0)
        if msg is None:
            if _dirty_msg is not None and (time.time() - _last_commit) >= _COMMIT_INTERVAL_SECS:
                producer.flush(5)
                consumer.commit(message=_dirty_msg, asynchronous=False)
                _dirty_msg = None
                _last_commit = time.time()
            continue
        if msg.error():
            err = msg.error()
            if err.code() != KafkaError._PARTITION_EOF:
                log.warning("[%s] Kafka consumer error: %s", topic, err)
            continue

        try:
            raw = msg.value().decode("utf-8", errors="replace")
            obj = json.loads(raw)
        except Exception as exc:
            log.warning("[%s] Cannot parse message: %s", topic, exc)
            _dirty_msg = msg
            continue

        try:
            parsed = parse_fn(obj)
        except Exception as exc:
            log.warning("[%s] Parser error: %s", topic, exc)
            parsed = None

        if not parsed:
            _dirty_msg = msg
        else:
            victim_ip = parsed["victim_ip"]
            event_time = parsed["event_time"]

            campaign_id = _infer_campaign(victim_ip, event_time)

            # Accumulate attacker source IPs across every alert seen for this
            # campaign — the network detector now emits one alert per newly-seen
            # attacker IP, so this set grows incrementally as a distributed
            # attack unfolds. Falco/ransomware events carry no source IPs of
            # their own; passing an empty list here just returns whatever was
            # already accumulated from the network phase.
            accumulated_ips = sorted(_accumulate_attacker_ips(victim_ip, parsed.get("src_ips") or []))
            parsed["accumulated_src_ips"] = accumulated_ips

            log.info(
                "[%s] victim=%s → campaign=%s source=%s accumulated_ips=%d",
                topic, victim_ip, campaign_id, parsed["source"], len(accumulated_ips),
            )

            # Publish to pmp_alerts (MISP consumes this)
            try:
                pmp = _build_pmp_alert(parsed, campaign_id)
                _produce(producer, TOPIC_PMP_ALERTS, pmp)
            except Exception as exc:
                log.error("[%s] Failed to produce to %s: %s", topic, TOPIC_PMP_ALERTS, exc)

            # Publish to alert_manager_tapcd_compat_alerts (TAPCD stream_low consumes this)
            try:
                tapcd_compat = _build_tapcd_compat_alert(parsed, campaign_id)
                if tapcd_compat is not None:
                    _produce(producer, TOPIC_TAPCD_COMPAT, tapcd_compat)
            except Exception as exc:
                log.error("[%s] Failed to produce to %s: %s", topic, TOPIC_TAPCD_COMPAT, exc)

            _dirty_msg = msg

        if (time.time() - _last_commit) >= _COMMIT_INTERVAL_SECS:
            producer.flush(5)
            consumer.commit(message=_dirty_msg, asynchronous=False)
            _dirty_msg = None
            _last_commit = time.time()

    if _dirty_msg is not None:
        producer.flush(5)
        consumer.commit(message=_dirty_msg, asynchronous=False)

    log.info("[%s] Closing consumer and producer", topic)
    try:
        consumer.close()
    except Exception:
        pass
    try:
        producer.flush(5)
    except Exception:
        pass


def run():
    log.info(
        "Alert Manager started — correlating by victim IP within %ds window → "
        "publishing to %s and %s (one dedicated consumer thread per source topic)",
        CAMPAIGN_WINDOW_SECS, TOPIC_PMP_ALERTS, TOPIC_TAPCD_COMPAT,
    )

    threads = [
        threading.Thread(target=_consume_topic, args=(TOPIC_NETWORK_ALERTS, "net"), daemon=True, name="am-net"),
        threading.Thread(target=_consume_topic, args=(TOPIC_FALCO, "falco"), daemon=True, name="am-falco"),
        threading.Thread(target=_consume_topic, args=(TOPIC_SNORT_IN, "snort"), daemon=True, name="am-snort"),
    ]
    for t in threads:
        t.start()

    last_gc = time.time()
    while not _closing:
        time.sleep(1.0)
        if time.time() - last_gc > 300:
            _gc_expired_campaigns()
            last_gc = time.time()

    for t in threads:
        t.join(timeout=10)


if __name__ == "__main__":
    run()
