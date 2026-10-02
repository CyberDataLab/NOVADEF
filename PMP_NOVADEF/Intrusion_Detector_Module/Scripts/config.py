"""Environment-driven configuration, thresholds and infra-IP filtering.

All values are supplied by the launcher/.env (see NetworkIntrusionDetectorConfig
in internal_external_tools_models.py) — no fallback defaults here.
"""

import ipaddress
import json
import os
import time
from pathlib import Path

# === KAFKA CONFIG ===
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP")
# Input topics are reused as-is from their producer's own variable name
# (TsharkConfig/FlowModuleConfig) so the Configuration Manager's generic
# consumer-topic resolution can overwrite them without a per-tool special case.
KAFKA_TOPIC_IN = os.getenv("TSHARK_BASE_TOPIC")
KAFKA_TOPIC_FLOW_IN = os.getenv("CIC_KAFKA_BASE_TOPIC_OUT")
KAFKA_TOPIC_OUT = os.getenv("NID_KAFKA_TOPIC_OUT")
GROUP_ID = os.getenv("NID_KAFKA_GROUP_ID")
POLL_TIMEOUT_SECONDS = float(os.getenv("NID_POLL_TIMEOUT_SECONDS"))

# === SLOW-PATH (ISOLATION FOREST) WINDOW ===
WINDOW_SECONDS = int(os.getenv("NID_WINDOW_SECONDS"))
WINDOW_PACKETS = int(os.getenv("NID_WINDOW_PACKETS"))
MIN_FAILURES = int(os.getenv("NID_MIN_FAILURES"))
MIN_UNIQUE_USERS = int(os.getenv("NID_MIN_UNIQUE_USERS"))
MIN_UNIQUE_IPS = int(os.getenv("NID_MIN_UNIQUE_IPS"))
DEDUP_SECONDS = int(os.getenv("NID_DEDUP_SECONDS"))
# TTL of the alert-dedup record kept on disk, so a detector restart mid-attack
# does not immediately re-alert on the same target.
ALERT_DEDUP_TTL_SECONDS = int(os.getenv("NID_ALERT_DEDUP_TTL_SECONDS"))
ALLOWED_REMOTE_PORTS = {22, 2222, 3389, 443, 1194}

# === FAST FAN-IN DETECTOR ===
# Counts, per (dst_ip, dst_port), how many DISTINCT source IPs open a new
# connection within a sliding window. A distributed password-spraying attack
# has exactly this shape (many attacker IPs hitting one service port at once),
# so this fires in 1-2s instead of waiting ~40-60s for the Isolation Forest to
# characterise mature flows.
FAST_FANIN_ENABLED = os.getenv("NID_FAST_FANIN_ENABLED", "").lower() in {"1", "true", "yes"}
# When fan-in is primary, the Isolation Forest is redundant for DETECTION (it
# only added an anomaly_score; TAPCD rebuilds the flow profile from MongoDB
# independently) and running both produced two alerts per attack. These two
# flags are independent now — disabling fan-in does not auto-enable this.
ISOLATION_FOREST_ENABLED = os.getenv("NID_ISOLATION_FOREST_ENABLED", "").lower() in {"1", "true", "yes"}
FAST_FANIN_WINDOW_SECONDS = float(os.getenv("NID_FAST_FANIN_WINDOW_SECONDS"))
FAST_FANIN_MIN_UNIQUE_IPS = int(os.getenv("NID_FAST_FANIN_MIN_UNIQUE_IPS"))
FAST_FANIN_MIN_SYN_PACKETS = int(os.getenv("NID_FAST_FANIN_MIN_SYN_PACKETS"))
# One fast alert per (dst_ip, dst_port) per attack; SOARCA's own dedup already
# prevents a second countermeasure, so this only gates re-triggering the
# ACTION, not re-observing the campaign.
FAST_FANIN_DEDUP_SECONDS = float(os.getenv("NID_FAST_FANIN_DEDUP_SECONDS"))
# After the first alert, keep emitting lightweight enrichment-only alerts on
# this cadence carrying the full campaign-lifetime attacker IP set, so the
# actor profile keeps growing after the countermeasure already fired.
FAST_FANIN_ENRICH_INTERVAL_SECONDS = float(os.getenv("NID_FAST_FANIN_ENRICH_INTERVAL_SECONDS"))

# === INFRASTRUCTURE IP FILTERING ===
# PMP/NOVADEF infrastructure containers that must never be classified as
# attackers or victims. Discovered dynamically by Infra_Discovery_Watcher
# (Docker label novadef.role=infrastructure, see InfraDiscoveryWatcherConfig),
# which writes their current IPs here as NDJSON on a volume shared with this
# container — not resolved by this container itself.
_INFRA_IPS_FILE = Path("/shared/infra/infra_ips.ndjson")
_INFRA_RESOLVE_INTERVAL_SECONDS = int(os.getenv("NID_INFRA_RESOLVE_INTERVAL_SECONDS"))
_infra_ip_cache: set[str] = set()
_infra_ip_cache_ts: float = 0.0


def refresh_infra_ips() -> set[str]:
    """Read the watcher's shared infra-IPs file, cached briefly."""
    global _infra_ip_cache, _infra_ip_cache_ts
    now = time.time()
    if (now - _infra_ip_cache_ts) < _INFRA_RESOLVE_INTERVAL_SECONDS:
        return _infra_ip_cache
    resolved: set[str] = set()
    try:
        for line in _INFRA_IPS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                resolved.add(str(json.loads(line)))
            except Exception:
                continue
    except FileNotFoundError:
        pass
    _infra_ip_cache = resolved
    _infra_ip_cache_ts = now
    return _infra_ip_cache


def is_infra_src(ip_txt: str) -> bool:
    """True if the IP currently belongs to a known PMP infrastructure host."""
    ip_txt = str(ip_txt).strip()
    if not ip_txt:
        return False
    return ip_txt in refresh_infra_ips()


def is_private_lab_ip(ip_txt: str) -> bool:
    """True if the IP is a private-range address, i.e. inside the lab network."""
    try:
        return ipaddress.ip_address(str(ip_txt)).is_private
    except Exception:
        return False
