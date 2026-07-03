import json
import os
import sys
import logging
import re
import socket
import time
import hashlib
import threading
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from requests.auth import HTTPBasicAuth
from datetime import datetime
from pymisp import PyMISP, MISPEvent
from kafka import KafkaConsumer, KafkaProducer
from pymongo import MongoClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MISP_URL = os.getenv('MISP_URL', 'https://localhost')
MISP_KEY = os.getenv('MISP_KEY', 'YOUR_MISP_API_KEY')
MISP_VERIFY_CERT = os.getenv('MISP_VERIFY_CERT', 'False').lower() == 'true'

KAFKA_BROKER = os.getenv('KAFKA_BROKER', 'localhost:9092')
KAFKA_TOPICS = os.getenv('KAFKA_TOPICS', 'pmp-alerts').split(',')
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://admin:admin123@localhost:27017/')
NEO4J_HTTP_URL = os.getenv('NEO4J_HTTP_URL', 'http://neo4j:7474/db/neo4j/tx/commit')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'neo4jpass')

OPENSEARCH_URL = os.getenv('OPENSEARCH_URL', 'https://opensearch-node:9200')
OPENSEARCH_USER = os.getenv('OPENSEARCH_USER', 'admin')
OPENSEARCH_PASS = os.getenv('OPENSEARCH_PASSWORD', '')

# Deduplicación de alertas: (rule, src_ip, dst_ip) → timestamp último procesado
# Misma combinación dentro de DEDUP_WINDOW_SECS se descarta (es el mismo ataque)
DEDUP_WINDOW_SECS = 120
_alert_dedup: dict = {}  # clave → epoch del último evento MISP creado
DEDUP_STATE_FILE = os.getenv('DEDUP_STATE_FILE', '/app/state/misp_dedup_state.json')
DEDUP_PERSIST_TTL_SECS = int(os.getenv('DEDUP_PERSIST_TTL_SECS', '14400'))  # 4h

# Scenario tag — set once at startup and updated via POST /reset?scenario_id=X.
# Every MISP event created by this integrator gets tagged with "scenario:<id>"
# so that events from different scenarios never contaminate each other.
_ACTIVE_SCENARIO_ID: str = os.getenv('NOVADEF_SCENARIO_ID', 'default')
# Cooldowns dedup the per-second alert re-emissions WITHIN a single run. They no
# longer cause cross-run collisions because _reset_run_state() (POST /reset, fired
# by the experiments API at the start of every run — new scenario or fast-start
# reuse) wipes _persisted_dedup/_alert_dedup, so each new experiment starts with a
# clean dedup window. A long in-run window is fine and avoids duplicate events.
NETWORK_ATTACK_COOLDOWN_SECS = int(os.getenv('NETWORK_ATTACK_COOLDOWN_SECS', '1800'))   # 30 min (in-run)
HOST_RANSOMWARE_COOLDOWN_SECS = int(os.getenv('HOST_RANSOMWARE_COOLDOWN_SECS', '1800'))  # 30 min (in-run)
# Max age of a network-phase event that a Falco ransomware alert may merge into
# (exp3 hybrid consolidation). Prevents adopting events from previous runs.
EVENT_CONSOLIDATION_WINDOW_SECS = int(os.getenv('EVENT_CONSOLIDATION_WINDOW_SECS', '900'))  # 15 min
MISP_TEXT_ATTR_MAXLEN = int(os.getenv('MISP_TEXT_ATTR_MAXLEN', '950'))
_SCENARIO_VICTIM_IP_ENV = os.getenv('SCENARIO_VICTIM_IP', '')
_SCENARIO_VICTIM_HOSTNAME = os.getenv('SCENARIO_VICTIM_HOSTNAME', 'scenario_victim')

# Fallback victim IP when DNS for the scenario victim is not yet resolvable.
# MUST NOT be the Kafka broker IP (172.18.0.3) — using the broker IP caused
# stray Falco alerts (received before the victim container's DNS alias was
# registered) to create bogus MISP events keyed on 172.18.0.3. The lab victim
# is consistently 172.18.0.29.
_SCENARIO_VICTIM_IP_FALLBACK = os.getenv('SCENARIO_VICTIM_IP_FALLBACK', '172.18.0.29')

def _resolve_victim_ip() -> str:
    """Resolve victim IP dynamically so we always target the running container.
    Priority: env var SCENARIO_VICTIM_IP > DNS lookup of SCENARIO_VICTIM_HOSTNAME > lab fallback."""
    if _SCENARIO_VICTIM_IP_ENV:
        return _SCENARIO_VICTIM_IP_ENV
    try:
        return socket.gethostbyname(_SCENARIO_VICTIM_HOSTNAME)
    except Exception:
        return _SCENARIO_VICTIM_IP_FALLBACK

SCENARIO_VICTIM_IP = _resolve_victim_ip()

# Topic where the soarca-trigger reads TAPCD profiles (profiles_out format).
# Publishing Falco ransomware events directly here bypasses stream_low/prep_pred
# and routes them straight to soarca-trigger → SOARCA isolation, avoiding the
# extra network-profile noise that stream_low would generate.
KAFKA_TOPIC_PROFILES_OUT = os.getenv('KAFKA_TOPIC_PROFILES_OUT', 'profiles_out')

# Per-victim dedup for ransomware TAPCD publishes.  Keyed by victim_ip, value
# is the epoch when the last publish happened.  Events within
# RANSOMWARE_TAPCD_DEDUP_TTL seconds of the previous one for the same victim
# are dropped.  Using a TTL instead of a lifetime flag lets the integrator
# recover naturally between experiment runs without restarting the container.
_ransomware_tapcd_published_at: dict[str, float] = {}
RANSOMWARE_TAPCD_DEDUP_TTL = int(os.getenv("RANSOMWARE_TAPCD_DEDUP_TTL", "300"))  # 5 min

# Active MISP events keyed by victim_key.  All alerts for the same campaign
# (network + host) enrich a single MISP event instead of one per alert type.
# Cleared by _reset_run_state() between experiment runs.
_active_event_by_victim: dict[str, int] = {}    # victim_key → MISP event id
_active_title_by_victim: dict[str, str] = {}    # victim_key → current title

# Source IPs seen for a victim from network alerts, accumulated per campaign.
# When a Falco ransomware event arrives, these are included in the combined
# profile so the soarca-trigger knows the full attacker IP set.
_campaign_src_ips: dict[str, list[str]] = {}    # victim_key → [src_ip, ...]

# Tracks whether a Falco ransomware event has already been published to
# profiles_out for a given victim_key in this run (so stream_low profiles
# for that victim don't trigger redundant block_ip actions afterwards).
_ransomware_profile_sent: dict[str, bool] = {}  # victim_key → True

_kafka_producer: "KafkaProducer | None" = None
_kafka_bytes_producer: "KafkaProducer | None" = None

def _get_kafka_producer() -> "KafkaProducer":
    global _kafka_producer
    if _kafka_producer is None:
        _kafka_producer = KafkaProducer(
            bootstrap_servers=[KAFKA_BROKER],
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
    return _kafka_producer

def _get_kafka_bytes_producer() -> "KafkaProducer":
    """Producer that sends raw bytes (for CSV payloads like profiles_out)."""
    global _kafka_bytes_producer
    if _kafka_bytes_producer is None:
        _kafka_bytes_producer = KafkaProducer(bootstrap_servers=[KAFKA_BROKER])
    return _kafka_bytes_producer


# CSV column order matching PROFILE_COLUMNS in prep_pred.py
_PROFILE_CSV_COLUMNS = [
    "Id", "CampaignId", "IPs", "Target", "PreferredTarget", "FirstSeen", "LastActivity",
    "Country", "AutomationLevel", "Evasion", "TTPs", "KillChainPhase",
    "RiskLevel", "Tools", "Skills", "Profile",
    "DetectionAlert", "DetectionType", "DetectionAttack", "DetectionStage", "DetectionTs",
    "Motivation", "Knowledge", "Attitude", "Affiliation",
    "ThreatGroup", "Campaigns", "Comments",
]

def _publish_falco_ransomware_to_tapcd(victim_ip: str, rule: str, evt_time: str,
                                       victim_key: str = "", src_ips: list | None = None,
                                       campaign_id: str = "") -> None:
    """Publish a single combined profile directly to profiles_out so the
    soarca-trigger receives it with DetectionAttack=Ransomware and applies
    network isolation. src_ips carries the attacker IPs accumulated from
    prior network alerts so the profile is fully correlated (1 profile for
    both the network phase and the host phase of a hybrid campaign)."""
    global _ransomware_tapcd_published_at, _ransomware_profile_sent
    import csv as _csv
    import io as _io
    now = time.time()
    vkey = victim_key or victim_ip
    last = _ransomware_tapcd_published_at.get(vkey, 0.0)
    if (now - last) < RANSOMWARE_TAPCD_DEDUP_TTL:
        logger.info(
            "[FALCO->TAPCD] Duplicado reciente (%.0fs < %ds) para victim=%s — descartando",
            now - last, RANSOMWARE_TAPCD_DEDUP_TTL, victim_ip,
        )
        return
    _ransomware_tapcd_published_at[vkey] = now
    try:
        ts_iso = evt_time if evt_time else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        _cid = (campaign_id or "").strip()
        if _cid and _cid not in ("<N/A>", "N/A", "none", "null"):
            actor_id = f"campaign_{_cid}_{victim_ip}"
        else:
            actor_id = f"profile-falco-ransomware-{victim_ip}"
        # Combine attacker IPs from the network phase with the victim IP from Falco.
        # This produces a single correlated profile covering both attack phases.
        combined_ips_list = list(dict.fromkeys((src_ips or []) + [victim_ip]))
        combined_ips = ";".join(combined_ips_list[:20])
        row = {col: "" for col in _PROFILE_CSV_COLUMNS}
        row.update({
            "Id": actor_id,
            "CampaignId": _cid,
            "IPs": combined_ips,
            "Target": victim_ip,
            "PreferredTarget": victim_ip,
            "FirstSeen": ts_iso,
            "LastActivity": ts_iso,
            # Profile and RiskLevel are NOT set here — they require the ML model
            # in prep_pred which runs on network flow features. Falco provides host
            # execution evidence only; ML fields are written by the network-phase
            # profile (same campaign_id → same Neo4j actor node, merged via coalesce).
            "TTPs": "T1486;T1490;T1489;T1005",
            "KillChainPhase": "Impact",
            "DetectionAlert": f"FALCO: {rule}",
            "DetectionType": "host_ransomware",
            "DetectionAttack": "Ransomware",
            "DetectionStage": "Impact",
            "DetectionTs": ts_iso,
            "Comments": (
                f"falco_rule={rule}; victim={victim_ip}; "
                f"network_src_ips={','.join((src_ips or [])[:10])}"
            ),
        })
        buf = _io.StringIO()
        writer = _csv.DictWriter(buf, fieldnames=_PROFILE_CSV_COLUMNS)
        writer.writeheader()
        writer.writerow(row)
        csv_bytes = buf.getvalue().encode("utf-8")
        _get_kafka_bytes_producer().send(KAFKA_TOPIC_PROFILES_OUT, value=csv_bytes)
        _get_kafka_bytes_producer().flush(timeout=3)
        _ransomware_profile_sent[vkey] = True
        logger.info(
            "[FALCO->TAPCD] Perfil combinado (red+host) publicado en %s victim=%s src_ips=%s",
            KAFKA_TOPIC_PROFILES_OUT, victim_ip, ",".join((src_ips or [])[:5]),
        )
    except Exception as e:
        logger.warning("[FALCO->TAPCD] No se pudo publicar perfil TAPCD: %s", e)


def ensure_state_dir():
    os.makedirs(os.path.dirname(DEDUP_STATE_FILE), exist_ok=True)


def load_dedup_state() -> dict:
    ensure_state_dir()
    if not os.path.exists(DEDUP_STATE_FILE):
        return {}
    try:
        with open(DEDUP_STATE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception as e:
        logger.debug(f"[DEDUP] No se pudo cargar estado persistente: {e}")
    return {}


def save_dedup_state(state: dict):
    ensure_state_dir()
    now = int(time.time())
    pruned = {
        k: v for k, v in state.items()
        if isinstance(v, (int, float)) and (now - int(v)) <= DEDUP_PERSIST_TTL_SECS
    }
    with open(DEDUP_STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(pruned, f)


_persisted_dedup = load_dedup_state()

# Keys for which the "already processed" dedup message has already been logged.
# Falco re-emits the ransomware event continuously while the script runs, so
# without this throttle the integrator floods the log with thousands of
# identical DEDUP-PERSIST lines, pushing the real [DETECT] line out of the
# tail window the GUI reads (which then shows the profile/MISP panel empty).
_dedup_logged_once: set = set()


def already_processed_persisted(dedup_key: str) -> bool:
    ts = _persisted_dedup.get(dedup_key)
    if not ts:
        return False
    return (time.time() - float(ts)) <= DEDUP_PERSIST_TTL_SECS


def mark_processed_persisted(dedup_key: str):
    _persisted_dedup[dedup_key] = int(time.time())
    save_dedup_state(_persisted_dedup)


def _stable_hash(parts: list[str]) -> str:
    joined = "|".join(parts)
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]


def _safe_text_attr(value: str) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) <= MISP_TEXT_ATTR_MAXLEN:
        return text
    return text[:MISP_TEXT_ATTR_MAXLEN] + " ...[truncated]"


def _time_window_bucket(ts_raw: str, window_secs: int = 1800) -> str:
    """
    Normalize timestamps into coarse fixed windows (default 30 min) so
    repeated runs of the same campaign in the same period reuse incident key.
    """
    try:
        if ts_raw:
            # Accept ISO timestamps like 2026-05-18T22:41:17Z
            dt = datetime.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S")
            epoch = int(dt.timestamp())
        else:
            epoch = int(time.time())
    except Exception:
        epoch = int(time.time())
    bucket_start = epoch - (epoch % int(window_secs))
    return datetime.utcfromtimestamp(bucket_start).strftime("%Y-%m-%dT%H:%M")


def get_opensearch_host_context() -> str | None:
    """
    Consulta OpenSearch para obtener métricas telegraf recientes del host.
    Retorna resumen formateado o None.
    """
    lines = ["[HOST METRICS - telegraf]"]
    query = {
        "size": 0,
        "aggs": {
            "by_metric": {
                "terms": {"field": "event.dataset.keyword", "size": 20},
                "aggs": {
                    "latest": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": {"order": "desc"}}],
                            "_source": ["fields", "@timestamp", "host"]
                        }
                    }
                }
            }
        }
    }
    try:
        resp = requests.post(
            f"{OPENSEARCH_URL}/logs-telegraf_metrics-*/_search",
            json=query,
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            verify=False, timeout=5
        )
        if resp.status_code != 200:
            return None
        buckets = resp.json().get('aggregations', {}).get('by_metric', {}).get('buckets', [])
        for bucket in sorted(buckets, key=lambda b: b['key']):
            hits = bucket['latest']['hits']['hits']
            if not hits:
                continue
            src = hits[0]['_source']
            fields = src.get('fields', {})
            ts = src.get('@timestamp', '')[:19].replace('T', ' ')
            field_str = ', '.join(
                f"{k}={round(v,2) if isinstance(v,float) else v}"
                for k, v in sorted(fields.items())
            )
            lines.append(f"  [{bucket['key']}] @ {ts} UTC -> {field_str}")
    except Exception as e:
        logger.warning(f"[OpenSearch] Error consultando telegraf: {e}")

    # Falco desde OpenSearch
    try:
        resp_f = requests.post(
            f"{OPENSEARCH_URL}/logs-falco_events-*/_search",
            json={"size": 3, "sort": [{"@timestamp": {"order": "desc"}}],
                  "_source": ["message", "@timestamp"]},
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            verify=False, timeout=5
        )
        if resp_f.status_code == 200:
            hits = resp_f.json().get('hits', {}).get('hits', [])
            if hits:
                lines.append("\n[FALCO - últimas alertas del host]")
                for h in hits:
                    src = h['_source']
                    ts = src.get('@timestamp', '')[:19].replace('T', ' ')
                    try:
                        msg = json.loads(src.get('message', '{}'))
                        rule = msg.get('rule', '?')
                        prio = msg.get('priority', '?')
                        out  = msg.get('output', '')[:120]
                        lines.append(f"  [{ts}] {rule} ({prio}): {out}")
                    except Exception:
                        lines.append(f"  [{ts}] {str(src.get('message',''))[:120]}")
    except Exception as e:
        logger.debug(f"[OpenSearch] Sin índice falco o error: {e}")

    return '\n'.join(lines) if len(lines) > 1 else None


def get_network_flows_context(ip_target: str) -> str | None:
    """
    Consulta MongoDB flow_db para obtener estadísticas de flujo de la IP objetivo.
    Devuelve un resumen en texto (evita MISPObject que requiere plantillas).
    """
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        db = client["flow_db"]
        flows = list(db.flows.find(
            {"$or": [{"src_ip": ip_target}, {"dst_ip": ip_target}]}
        ).sort("_id", -1).limit(100))
        if not flows:
            return None

        total_bytes   = sum(f.get('totlen_fwd_pkts', 0) + f.get('totlen_bwd_pkts', 0) for f in flows)
        total_pkts    = sum(f.get('tot_fwd_pkts', 0)   + f.get('tot_bwd_pkts', 0)   for f in flows)
        avg_dur       = sum(f.get('flow_duration', 0) for f in flows) / len(flows)
        avg_bps       = sum(f.get('flow_byts_s', 0)  for f in flows) / len(flows)
        dst_ports     = sorted(set(str(f.get('dst_port','?')) for f in flows if f.get('dst_port')))
        src_ports     = sorted(set(str(f.get('src_port','?')) for f in flows if f.get('src_port')))
        protocols     = sorted(set(str(f.get('protocol','?')) for f in flows))
        peer_ips      = sorted(set(
            f.get('dst_ip', '') if f.get('src_ip') == ip_target else f.get('src_ip', '')
            for f in flows
        ) - {ip_target, ''})

        last_ts = max((f.get('timestamp', '') for f in flows), default='N/A')
        if hasattr(last_ts, 'isoformat'):
            last_ts = last_ts.isoformat()

        lines = [
            f"[CIC FLOW CONTEXT - {len(flows)} conexiones para {ip_target}]",
            f"  Ultima actividad : {last_ts}",
            f"  Total bytes      : {total_bytes:,}",
            f"  Total paquetes   : {total_pkts:,}",
            f"  Duracion media   : {avg_dur:.1f} us",
            f"  Velocidad media  : {avg_bps:,.0f} bytes/s",
            f"  Protocolos       : {', '.join(protocols)}",
            f"  Puertos destino  : {', '.join(dst_ports[:20])}",
            f"  Puertos origen   : {', '.join(src_ports[:10])}",
            f"  IPs contactadas  : {', '.join(peer_ips[:10])}",
        ]
        return '\n'.join(lines)
    except Exception as e:
        logger.warning(f"[MongoDB] Error consultando flows para {ip_target}: {e}")
        return None


def get_tapcd_actor_profile(victim_ip: str, prefer_novadef: bool = False, attacker_ref: str | None = None) -> dict | None:
    """
    Consulta Neo4j para obtener el perfil de actor que ataca la IP víctima.
    La relación real es: (Actor)-[:TARGETS]->(Target) donde Target.ip CONTAINS victim_ip.
    """
    where_extra = "AND a.id STARTS WITH 'novadef-'" if prefer_novadef else ""
    attacker_extra = ""
    params = {"ip": victim_ip}
    if attacker_ref:
        attacker_extra = " AND a.id CONTAINS $attacker_ref"
        params["attacker_ref"] = str(attacker_ref).replace('.', '-')

    query = {
        "statements": [
            {
                "statement": (
                    "MATCH (a:Actor)-[:TARGETS]->(t:Target) "
                    "WHERE t.ip CONTAINS $ip "
                    f"{where_extra} "
                    f"{attacker_extra} "
                    "RETURN a ORDER BY a.lastActivity DESC LIMIT 1"
                ),
                "parameters": params
            }
        ]
    }
    try:
        response = requests.post(
            NEO4J_HTTP_URL, json=query,
            auth=HTTPBasicAuth(NEO4J_USER, NEO4J_PASS), timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            rows = data.get("results", [{}])[0].get("data", [])
            if rows:
                return rows[0]["row"][0]
    except Exception as e:
        logger.debug(f"[TAPCD] No se pudo consultar Neo4j para {victim_ip}: {e}")
    return None

def init_misp():
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_CERT, debug=False)
        logger.info(f"Conexión exitosa a MISP: {MISP_URL}")
        return misp
    except Exception as e:
        logger.error(f"Error al conectar con MISP: {e}")
        return None


def add_event_with_retry(event_payload: dict, retries: int = 5, delay_sec: float = 2.0, misp_client=None):
    """
    Retry MISP event creation to survive transient warm-up/500 windows.
    Accepts an optional pre-initialized misp_client to avoid redundant
    init_misp() calls on the first attempt (saves ~2-3s per event).
    Falls back to init_misp() on retries or when no client is provided.
    """
    last_exc = None
    _client_for_attempt = misp_client
    for attempt in range(1, retries + 1):
        client = _client_for_attempt or init_misp()
        _client_for_attempt = None  # only reuse on first attempt
        if not client:
            last_exc = RuntimeError("PyMISP client unavailable")
            time.sleep(delay_sec)
            continue
        try:
            return client.add_event(event_payload, pythonify=True)
        except Exception as e:
            last_exc = e
            logger.warning(f"[MISP] add_event intento {attempt}/{retries} falló: {e}")
            time.sleep(delay_sec)
    raise last_exc if last_exc else RuntimeError("Unknown add_event failure")

def extract_ip_from_ap(ap_string):
    """Extrae la IP si viene con puerto (ej: 10.0.2.15:57384)"""
    if not isinstance(ap_string, str):
        return None
    return ap_string.split(':')[0] if ':' in ap_string else ap_string



def enrich_attribute(misp, attr_uuid, attr_type, attr_val):
    """Lanza los módulos de enriquecimiento solo para cosas útiles y no locales."""
    try:
        if attr_type == 'ip-dst' or attr_type == 'ip-src':
            if not attr_val.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')):
                logger.info(f"Enriqueciendo IP Pública (Shodan): {attr_val}")
                misp.query_enrichment(attr_uuid, 'shodan')
        elif attr_type in ['sha256', 'md5', 'sha1']:
            logger.info(f"Enriqueciendo Hash (VirusTotal): {attr_val}")
            misp.query_enrichment(attr_uuid, 'virustotal')
    except Exception as e_mod:
        logger.warning(f"Error al llamar a módulos en atributo {attr_val}: {e_mod}")

def process_alert_to_misp(misp, topic, alert_data):
    global _active_event_by_victim, _active_title_by_victim, _campaign_src_ips, _ransomware_profile_sent
    if not misp:
        return

    def _campaign_key(target: str, attack_type: str, time_bucket: str) -> str:
        return f"campaign|target={target}|attack={attack_type}|time={time_bucket}"

    # Unwrap Alert Manager envelope: pmp_alerts carries source topic + campaign_id
    if topic == 'pmp_alerts':
        inner_topic = alert_data.get('topic', '')
        if not inner_topic:
            return
        # campaign_id inferred by the Alert Manager — always present in pmp_alerts payload
        am_campaign_id = str(alert_data.get('campaign_id', '') or '')
        topic = inner_topic
        alert_data = dict(alert_data)  # mutable copy
        # For falco_events wrapped by Alert Manager, rebuild the expected structure:
        # MISP's falco handler expects {"message": "<json-string>"} but AM stores fields flat.
        if topic == 'falco_events' and 'message' not in alert_data:
            inner_falco = {
                'rule': alert_data.get('rule', ''),
                'priority': alert_data.get('priority', ''),
                'output': alert_data.get('output', ''),
                'output_fields': alert_data.get('output_fields', {}),
            }
            alert_data['message'] = json.dumps(inner_falco)
        # Ensure campaign_id from AM overrides any extracted value in the handlers
        if am_campaign_id:
            alert_data['campaign_id'] = am_campaign_id

    # Topics puramente métricos o de trazas crudas: no generan eventos MISP directos.
    # Falco sí debe recorrer el pipeline de enriquecimiento y publicación.
    if topic in ['telegraf_metrics', 'syslog_logs', 'systemd_logs', 'tshark_traces', 'cic_flow']:
        return

    src_ip = dst_ip = src_port = dst_port = None
    attributes_to_add = []
    event_title = "PMP Alert"

    # ── SNORT ────────────────────────────────────────────────────────────────
    if topic == 'snort_alerts':
        src_ap = alert_data.get('src_ap', '')
        dst_ap = alert_data.get('dst_ap', '')
        src_ip   = extract_ip_from_ap(src_ap)
        dst_ip   = extract_ip_from_ap(dst_ap)
        src_port = src_ap.split(':')[1] if ':' in src_ap else None
        dst_port = dst_ap.split(':')[1] if ':' in dst_ap else None

        msg       = alert_data.get('msg', 'Snort Alert')
        rule      = alert_data.get('rule', '')

        # Firma puente del detector de anomalías (TAPCD compat):
        # no debe generar un evento MISP propio para evitar duplicados del
        # mismo incidente de spraying.
        if "NOVADEF-NID" in str(rule):
            logger.info("[DEDUP-LINK] Snort puente omitida; incidente lo publica network_intrusion_alerts.")
            return

        # ── Deduplicación: misma regla + mismo par IP en ventana → ignorar ──
        dedup_key = f"{alert_data.get('rule','')}|{src_ip}|{dst_ip}"
        now = time.time()
        if dedup_key in _alert_dedup and (now - _alert_dedup[dedup_key]) < DEDUP_WINDOW_SECS:
            return  # mismo ataque, ya creamos el evento MISP
        _alert_dedup[dedup_key] = now
        logger.info(f"[DEDUP] Nueva alerta única: {dedup_key}")
        proto     = alert_data.get('proto', '')
        ts        = alert_data.get('timestamp', '')
        pkt_len   = alert_data.get('pkt_len', '')
        action    = alert_data.get('action', '')
        direction = alert_data.get('dir', '')

        event_title = f"SNORT: {msg} [{src_ip} → {dst_ip}]"

        # IPs
        if src_ip:
            attributes_to_add.append({
                'type': 'ip-src',
                'value': src_ip,
                'comment': f"[ATTACKER IP] Origen del ataque | puerto {src_port}"
            })
        if dst_ip:
            attributes_to_add.append({
                'type': 'ip-dst',
                'value': dst_ip,
                'comment': f"[VICTIM IP] Destino del ataque | puerto {dst_port}"
            })

        # Puertos
        if src_port and src_port != '0':
            attributes_to_add.append({'type': 'port', 'value': src_port, 'comment': '[SNORT] Puerto origen'})
        if dst_port and dst_port != '0':
            attributes_to_add.append({'type': 'port', 'value': dst_port, 'comment': '[SNORT] Puerto destino'})

        # Detalle de la alerta Snort
        snort_detail = (
            f"[SNORT ALERT]\n"
            f"  Regla      : {rule}\n"
            f"  Mensaje    : {msg}\n"
            f"  Protocolo  : {proto}\n"
            f"  Timestamp  : {ts}\n"
            f"  Longitud   : {pkt_len} bytes\n"
            f"  Direccion  : {direction}\n"
            f"  Accion     : {action}\n"
            f"  Origen     : {src_ip}:{src_port}\n"
            f"  Destino    : {dst_ip}:{dst_port}"
        )
        attributes_to_add.append({'type': 'text', 'value': snort_detail, 'comment': '[SNORT] Detalle de la alerta'})

    elif topic == 'falco_events':
        raw_msg = alert_data.get('message', '')
        try:
            inner = json.loads(raw_msg) if isinstance(raw_msg, str) else raw_msg
        except Exception:
            inner = {'output': str(raw_msg)}

        rule     = inner.get('rule', 'Alerta Falco')
        priority = inner.get('priority', 'Unknown')
        output   = inner.get('output', '')
        fields   = inner.get('output_fields', {}) or {}

        # Prefer campaign_id already set by Alert Manager unwrapper (most reliable).
        # Fall back to extraction from output fields for direct consumption.
        _falco_campaign_id = str(alert_data.get('campaign_id', '') or '')
        if not _falco_campaign_id:
            _falco_campaign_match = re.search(r'campaign_id=([^\s)]+)', str(output))
            _falco_campaign_id = _falco_campaign_match.group(1) if _falco_campaign_match else ""
        if not _falco_campaign_id:
            _env_str = str(fields.get('proc.env', '') or '')
            _m = re.search(r'CAMPAIGN_ID=([^\s,)]+)', _env_str)
            _falco_campaign_id = _m.group(1) if _m else ""

        is_lab_ransomware = (
            "novadef lab ransomware" in str(rule).lower()
            or "novadef lab ransomware" in str(output).lower()
            or "ransomware" in str(rule).lower()
        )
        evt_time = str(inner.get('time') or '')
        # Use wall-clock time for the dedup bucket, NOT evt_time from the Falco payload.
        # Falco re-emits buffered events with the original system timestamp (which may
        # come from the CIC dataset and be days/weeks in the past), so evt_time-based
        # buckets produce a different key for every re-emission → multiple MISP events.
        evt_bucket = datetime.utcnow().strftime('%Y-%m-%dT%H:%M')

        if is_lab_ransomware:
            _victim_ip_now = _resolve_victim_ip()
            # Prefer campaign_id (run_id) as dedup scope so consecutive experiments
            # in the same scenario (exp2 then exp3) don't collide even if they share
            # the same victim IP and fall within the same 30-min time bucket.
            if _falco_campaign_id and _falco_campaign_id not in ("<N/A>", "N/A", "none", "null"):
                dedup_key = f"campaign_id|falco_ransomware|{_falco_campaign_id}"
            else:
                dedup_key = _campaign_key(_victim_ip_now, "T1486_T1490_T1489_T1005_host_ransomware", evt_bucket)
            persisted_ts = _persisted_dedup.get(dedup_key)
            if persisted_ts and (time.time() - float(persisted_ts)) <= HOST_RANSOMWARE_COOLDOWN_SECS:
                # Throttle: log the dedup only once per key to avoid flooding the
                # log (Falco re-emits this event many times per second).
                if dedup_key not in _dedup_logged_once:
                    _dedup_logged_once.add(dedup_key)
                    logger.info(f"[DEDUP-PERSIST] Ransomware host ya procesado (clave={dedup_key})")
                return
        else:
            _victim_ip_now = SCENARIO_VICTIM_IP
            dedup_key = f"falco|{rule}|{priority}"

        now = time.time()
        ttl = HOST_RANSOMWARE_COOLDOWN_SECS if is_lab_ransomware else DEDUP_WINDOW_SECS
        if dedup_key in _alert_dedup and (now - _alert_dedup[dedup_key]) < ttl:
            return
        _alert_dedup[dedup_key] = now
        logger.info(f"[DEDUP] Nueva alerta Falco única (clave={dedup_key})")

        if is_lab_ransomware:
            event_title = (
                f"FALCO: Host Ransomware Emulation Detected [{_victim_ip_now}] "
                f"(ATT&CK T1486/T1490/T1489/T1005)"
            )
            logger.info(
                f"[DETECT] FALCO: Host Ransomware Emulation Detected [{_victim_ip_now}]"
                f" - alerta Falco recibida, creando evento MISP..."
            )
            # Publish a single combined profile directly to profiles_out.
            # The profile includes attacker IPs accumulated from any prior
            # network-phase alerts for the same campaign, so soarca-trigger
            # sees ONE correlated profile (network + host) and applies isolation.
            _falco_vkey = (
                f"campaign:{_falco_campaign_id}"
                if _falco_campaign_id and _falco_campaign_id not in ("<N/A>", "N/A", "none", "null")
                else str(_resolve_victim_ip())
            )
            _net_src_ips = list(_campaign_src_ips.get(_falco_vkey, []))
            _publish_falco_ransomware_to_tapcd(
                _resolve_victim_ip(), rule, evt_time,
                victim_key=_falco_vkey,
                src_ips=_net_src_ips,
                campaign_id=_falco_campaign_id,
            )
        else:
            event_title = f"FALCO: {rule} ({priority})"

        # Atributo principal
        attributes_to_add.append({
            'type': 'text',
            'value': f"[FALCO] {rule} ({priority})",
            'comment': '[FALCO] Regla y prioridad'
        })
        if is_lab_ransomware:
            attributes_to_add.append({
                'type': 'text',
                'value': (
                    "[THREAT TYPE] host_ransomware_emulation\n"
                    "Detector=falco\n"
                    "ATTACK=T1486,T1490,T1489,T1005\n"
                    "D3FEND_HINT=Execution Isolation,Process Termination,Restore File"
                ),
                'comment': '[FALCO->TAPCD] Tipo de amenaza para perfilado'
            })

        # Detalle enriquecido
        falco_detail_lines = [
            f"[FALCO ALERT DETAIL]",
            f"  Regla      : {rule}",
            f"  Prioridad  : {priority}",
            f"  Output     : {output[:300]}",
        ]
        for key in ['container.id', 'container.name', 'container.image.repository',
                    'proc.name', 'proc.cmdline', 'user.name', 'fd.name', 'fd.cip',
                    'fd.sip', 'fd.sport', 'fd.cport', 'evt.type']:
            val = fields.get(key)
            if val:
                falco_detail_lines.append(f"  {key:<35}: {val}")

        attributes_to_add.append({
            'type': 'text',
            'value': '\n'.join(falco_detail_lines),
            'comment': '[FALCO] Contexto del proceso/contenedor'
        })
        # Add victim IP as ip-dst so MISP auto-correlates this Falco event with
        # any concurrent network-layer event targeting the same victim (exp3).
        if is_lab_ransomware and _victim_ip_now:
            attributes_to_add.append({
                'type': 'ip-dst',
                'value': _victim_ip_now,
                'comment': '[FALCO HOST] Víctima del ransomware (correlación MISP)',
            })

    elif topic == 'network_intrusion_alerts':
        dst_ip = alert_data.get('dst_ip')
        dst_port = alert_data.get('dst_port')
        src_ips = alert_data.get('src_ips', []) or []
        usernames = alert_data.get('usernames', []) or []
        failed_attempts = alert_data.get('failed_attempts', 0)
        requests_per_minute = alert_data.get('requests_per_minute', 0)
        anomaly_score = alert_data.get('anomaly_score', 0)
        mitre_attack = alert_data.get('mitre_attack', []) or []
        alert_type = str(alert_data.get('alert_type') or '').strip() or 'distributed_password_spraying'

        first_seen_raw = str(alert_data.get('first_seen') or alert_data.get('timestamp') or '')
        # Use wall-clock time for the bucket, not the payload timestamp.
        # CIC dataset flows carry historical timestamps → bucket collisions across runs.
        first_seen_bucket = _time_window_bucket(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"), NETWORK_ATTACK_COOLDOWN_SECS)
        src_fingerprint = _stable_hash(sorted(set(str(x) for x in src_ips)))
        # Clave estable por campaña de spraying sobre mismo servicio destino.
        attack_dedup_label = "_".join(mitre_attack) if mitre_attack else alert_type
        campaign_id = str(alert_data.get("campaign_id") or "").strip()
        dedup_key = (
            f"campaign_id|{campaign_id}"
            if campaign_id
            else _campaign_key(f"{dst_ip}", attack_dedup_label, first_seen_bucket)
        )
        persisted_ts = _persisted_dedup.get(dedup_key)
        if persisted_ts and (time.time() - float(persisted_ts)) <= NETWORK_ATTACK_COOLDOWN_SECS:
            logger.info(f"[DEDUP-PERSIST] Campaña de spraying ya procesada recientemente: {dedup_key}")
            return

        now = time.time()
        if dedup_key in _alert_dedup and (now - _alert_dedup[dedup_key]) < NETWORK_ATTACK_COOLDOWN_SECS:
            return
        _alert_dedup[dedup_key] = now
        logger.info(f"[DEDUP] Nueva alerta Network IDS única: {dedup_key}")

        first_seen = alert_data.get('first_seen') or alert_data.get('timestamp') or 'unknown-window'
        primary_src = src_ips[0] if src_ips else 'unknown-src'
        attack_fp = _stable_hash([str(dst_ip), src_fingerprint, first_seen_bucket])
        if alert_type == "hybrid_lateral_remote_execution":
            # Explicit title so SOARCA can route this to comprehensive isolation
            # playbook (covering both network and host layers in one countermeasure).
            base_title = f"NETWORK IDS: Hybrid Lateral Remote Execution [{primary_src} -> {dst_ip}:{dst_port}]"
        else:
            base_title = alert_data.get('title') or f"NETWORK IDS: Password Spraying [{primary_src} -> {dst_ip}:{dst_port}]"
        event_title = (
            f"{base_title}"
            f" [{primary_src} -> {dst_ip}]"
            f" | first_seen={first_seen}"
            f" | attack_fp={attack_fp}"
        )

        for src_ip_item in src_ips[:10]:
            attributes_to_add.append({
                'type': 'ip-src',
                'value': src_ip_item,
                'comment': '[NETWORK IDS] IP origen sospechosa',
            })
        if dst_ip:
            attributes_to_add.append({
                'type': 'ip-dst',
                'value': dst_ip,
                'comment': f'[NETWORK IDS] Servicio destino {dst_port}',
            })
        if dst_port:
            attributes_to_add.append({
                'type': 'port',
                'value': str(dst_port),
                'comment': '[NETWORK IDS] Puerto de acceso remoto observado',
            })

        attack_human = "distributed password spraying"
        if alert_type == "hybrid_lateral_remote_execution":
            attack_human = "hybrid lateral remote execution"

        ids_detail = (
            f"[NETWORK IDS ALERT]\n"
            f"  Ataque         : {attack_human}\n"
            f"  Destino        : {dst_ip}:{dst_port}\n"
            f"  IPs origen     : {', '.join(src_ips[:15])}\n"
            f"  Usuarios       : {', '.join(usernames[:20])}\n"
            f"  Fallos auth    : {failed_attempts}\n"
            f"  Req/min        : {requests_per_minute:.2f}\n"
            f"  Score anomalia : {anomaly_score:.6f}\n"
            f"  MITRE ATT&CK   : {', '.join(mitre_attack)}"
        )
        attributes_to_add.append({
            'type': 'text',
            'value': ids_detail,
            'comment': '[NETWORK IDS] Resumen de la detección',
        })

    # Sin atributos => salir
    if not attributes_to_add:
        return

    # ── Resolver la clave de campaña para agrupar alertas ────────────────────
    # Prioridad:
    #   1. campaign_id explícito (run_id de la API) → clave más precisa, une
    #      vectores distintos (red + host) del mismo experimento aunque la IP
    #      víctima cambie entre escenarios.
    #   2. dst_ip (IP de la víctima) → fallback cuando no hay campaign_id.
    #      Une alertas de red y Falco que atacan el mismo host en la misma sesión.
    #   3. "unknown" → último recurso para alertas sin contexto.
    _explicit_campaign_id = ""
    if topic == 'network_intrusion_alerts':
        _explicit_campaign_id = str(alert_data.get("campaign_id") or "").strip()
    elif topic == 'falco_events':
        _explicit_campaign_id = _falco_campaign_id

    # IMPORTANT: the victim_key MUST be stable across all alerts of the same
    # campaign/victim, regardless of whether a given alert happens to carry a
    # campaign_id. Falco emits the SAME ransomware event many times per second,
    # but only SOME emissions capture proc.env[CAMPAIGN_ID]. If campaign_id
    # decided the key, the campaign_id-bearing emissions and the campaign_id-less
    # emissions would map to two different keys → two MISP events for one attack.
    #
    # The victim IP is the single stable identity shared by BOTH attack phases
    # (network spraying targets dst_ip == victim; Falco ransomware fires on the
    # victim host). Keying both on the victim IP guarantees the two phases of an
    # exp3 hybrid campaign map to the SAME _victim_key → ONE MISP event,
    # regardless of arrival order or whether campaign_id was captured.
    # campaign_id is still stored as an attribute for traceability.
    if topic == 'falco_events':
        _victim_key = str(_resolve_victim_ip())
    elif dst_ip:
        _victim_key = str(dst_ip)
    elif _explicit_campaign_id and _explicit_campaign_id not in ("<N/A>", "N/A", "none", "null"):
        _victim_key = f"campaign:{_explicit_campaign_id}"
    else:
        _victim_key = "unknown"

    # Accumulate attacker source IPs from network alerts so they can be
    # included in the combined ransomware profile when Falco fires later.
    if topic == 'network_intrusion_alerts' and src_ips:
        existing_ips = _campaign_src_ips.get(_victim_key, [])
        new_ips = [ip for ip in src_ips if ip and ip not in existing_ips]
        if new_ips:
            _campaign_src_ips[_victim_key] = (existing_ips + new_ips)[:30]

    existing_event_id = _active_event_by_victim.get(_victim_key)

    # If the in-memory cache missed (e.g. integrator restarted between network
    # and Falco phases of exp3), try to recover the existing event from MISP DB
    # by searching for the campaign_id attribute we wrote when the first alert
    # created the event. This guarantees Falco always enriches the network event
    # rather than creating a second standalone event.
    def _adopt_event(_evt_id, _why: str) -> None:
        nonlocal existing_event_id
        existing_event_id = _evt_id
        _active_event_by_victim[_victim_key] = _evt_id
        try:
            ev = misp.get_event(_evt_id, pythonify=True)
            _active_title_by_victim[_victim_key] = str(ev.info or "")
        except Exception:
            pass
        logger.info(f"[DEDUP-LINK] Evento MISP #{_evt_id} reutilizado ({_why}, clave={_victim_key})")

    # Recovery 1: by campaign_id attribute (links network event ↔ Falco event
    # of the same run, even across an integrator restart).
    if existing_event_id is None and _explicit_campaign_id and _explicit_campaign_id not in ("<N/A>", "N/A", "none", "null"):
        try:
            recovered = misp.search(
                controller='attributes',
                type_attribute='text',
                value=f"campaign_id={_explicit_campaign_id}",
                limit=1,
                pythonify=True,
            )
            if recovered and hasattr(recovered[0], 'event_id'):
                _adopt_event(recovered[0].event_id, f"campaign_id={_explicit_campaign_id}")
        except Exception as _rec_err:
            logger.debug(f"[DEDUP-LINK] No se pudo recuperar evento por campaign_id: {_rec_err}")

    # Recovery 2 (Falco only): find the RECENT network-phase event for this victim
    # IP (the password-spraying event of the SAME hybrid exp3 campaign) and merge
    # the ransomware alert into it. Only events updated within the last
    # EVENT_CONSOLIDATION_WINDOW_SECS are considered, so we never adopt a stale
    # event from a previous experiment run.
    if existing_event_id is None and topic == 'falco_events':
        try:
            _vip = str(_resolve_victim_ip())
            from datetime import datetime as _dt, timedelta as _td
            _date_from = (_dt.utcnow() - _td(hours=2)).strftime("%Y-%m-%d")
            # Search by value (attribute index) AND list recent events (no value
            # filter). The value-based index can lag for just-created events, so
            # the unfiltered recent list is the reliable path to find a sibling
            # event created seconds ago in the same campaign.
            recovered_ev = []
            try:
                recovered_ev = misp.search(
                    controller='events', value=_vip, date_from=_date_from,
                    limit=10, pythonify=True,
                ) or []
            except Exception:
                recovered_ev = []
            try:
                _recent_all = misp.search(
                    controller='events', date_from=_date_from,
                    limit=20, pythonify=True,
                ) or []
            except Exception:
                _recent_all = []
            # Merge, de-duplicating by event id.
            _seen_ids = set()
            _merged = []
            for _ev in list(recovered_ev) + list(_recent_all):
                _eid = getattr(_ev, "id", None)
                if _eid in _seen_ids:
                    continue
                _seen_ids.add(_eid)
                _merged.append(_ev)
            recovered_ev = _merged
            _now_epoch = time.time()
            _window = EVENT_CONSOLIDATION_WINDOW_SECS

            def _ev_recent(_ev) -> bool:
                # Recent by last-modified epoch AND must mention the victim IP in
                # its info (covers the case where attribute indexing lags).
                try:
                    _ts = int(getattr(_ev, "timestamp", 0) or 0)
                    if not (_ts > 0 and (_now_epoch - _ts) <= _window):
                        return False
                    _info = str(getattr(_ev, "info", "") or "")
                    return _vip in _info or _vip in str(getattr(_ev, "Attribute", "") or "")
                except Exception:
                    return False

            _recent = [_ev for _ev in (recovered_ev or []) if _ev_recent(_ev)]
            if _recent:
                # Prefer the network/spraying event so both phases merge into it.
                _chosen = None
                for _ev in _recent:
                    _info = str(getattr(_ev, "info", "") or "")
                    if "Spraying" in _info or "Brute Force" in _info or "Network" in _info:
                        _chosen = _ev
                        break
                if _chosen is None:
                    _chosen = _recent[0]
                _adopt_event(_chosen.id, f"victim_ip={_vip} (consolidación red+host, <{_window}s)")
            else:
                logger.info(f"[DEDUP-LINK] Sin evento de red reciente (<{_window}s) para {_vip}; se creará evento ransomware nuevo.")
        except Exception as _rec_err2:
            logger.debug(f"[DEDUP-LINK] No se pudo recuperar evento por victim_ip: {_rec_err2}")

    if existing_event_id is None:
        # Primera alerta para esta campaña/víctima → crear el evento MISP
        try:
            new_event = add_event_with_retry(
                {
                    'info': event_title,
                    'distribution': 0,
                    'threat_level_id': 2,
                    'analysis': 0,
                },
                misp_client=misp,
            )
            existing_event_id = new_event.id
            _active_event_by_victim[_victim_key] = existing_event_id
            _active_title_by_victim[_victim_key] = event_title
            logger.info(f"[MISP] Evento creado #{existing_event_id} clave={_victim_key}: {event_title}")
            # Tag con el escenario activo — pasar el objeto MISPEvent para usar su UUID directamente
            _tag_event_with_scenario(misp, new_event, _ACTIVE_SCENARIO_ID)
            # Guardar campaign_id como atributo interno para trazabilidad
            if _explicit_campaign_id and _explicit_campaign_id not in ("<N/A>", "N/A", "none", "null"):
                try:
                    misp.add_attribute(existing_event_id, {
                        'type': 'text',
                        'value': f"campaign_id={_explicit_campaign_id}",
                        'comment': '[PIPELINE] Identificador de campaña (run_id de la API)',
                    }, pythonify=True)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Error creando evento MISP '{event_title}': {e}")
            return
    else:
        # Alerta posterior para la misma víctima → enriquecer el evento existente
        current_title = _active_title_by_victim.get(_victim_key, "")
        if event_title != current_title:
            new_title = f"{current_title} + {event_title}"
            try:
                misp.update_event({'id': existing_event_id, 'info': new_title}, event_id=existing_event_id)
                _active_title_by_victim[_victim_key] = new_title
                logger.info(f"[MISP] Título actualizado en evento #{existing_event_id}: {new_title[:120]}")
            except Exception as e:
                logger.warning(f"[MISP] No se pudo actualizar título del evento #{existing_event_id}: {e}")
        logger.info(f"[MISP] Enriqueciendo evento #{existing_event_id} (victim={_victim_key}) con alerta de {topic}")

    event_id = existing_event_id

    # Persistir dedup para que un reinicio no reprocese la misma campaña.
    # IMPORTANT: persist ALL Falco dedup keys (campaign_id|, campaign|target=,
    # falco|rule), not just campaign|target=. Otherwise the persisted_ts check
    # never fires for campaign_id-scoped ransomware alerts and Falco re-emissions
    # (many per second) each create a duplicate MISP event.
    if topic == 'network_intrusion_alerts':
        mark_processed_persisted(dedup_key)
    elif topic == 'falco_events':
        mark_processed_persisted(dedup_key)

    # ── Añadir atributos ──────────────────────────────────────────────────────
    for attr in attributes_to_add:
        try:
            new_attr = misp.add_attribute(event_id, attr, pythonify=True)
            logger.info(f"  [+] {attr['type']}: {attr['value'][:60]}")
            if attr['type'] in ('ip-src', 'ip-dst'):
                enrich_attribute(misp, new_attr.uuid, new_attr.type, attr['value'])
        except Exception as e:
            logger.error(f"Error añadiendo atributo: {e}")

    try:
        misp.add_attribute(
            event_id,
            {
                'type': 'text',
                'value': 'pipeline-tag:pmp-auto-aggregation',
                'comment': '[PIPELINE] Marcador interno de agregación automática',
            },
            pythonify=True,
        )
    except Exception as e:
        logger.warning(f"No se pudo marcar el evento #{event_id} con pipeline-tag: {e}")

    # ── Contexto enriquecido (solo en alertas Snort) ──────────────────────────
    if topic not in ('snort_alerts', 'network_intrusion_alerts', 'falco_events', 'pmp_alerts'):
        return

    # 1. Flujos CIC (MongoDB) para IP atacante y víctima
    context_ips = []
    if topic == 'network_intrusion_alerts':
        context_ips.extend(src_ips[:3])
        if dst_ip:
            context_ips.append(dst_ip)
    else:
        context_ips.extend(filter(None, [src_ip, dst_ip]))

    for ip in context_ips:
        flow_ctx = get_network_flows_context(ip)
        if flow_ctx:
            try:
                misp.add_attribute(event_id, {'type': 'text', 'value': _safe_text_attr(flow_ctx),
                                              'comment': f'[CIC FLOWS] Estadisticas para {ip}'}, pythonify=True)
                logger.info(f"  [+] CIC flows para {ip}")
            except Exception as e:
                logger.warning(f"Fallo CIC flows {ip}: {e}")

    # 2. Métricas del host (telegraf + Falco desde OpenSearch)
    host_ctx = get_opensearch_host_context()
    if host_ctx:
        try:
            misp.add_attribute(event_id, {'type': 'text', 'value': _safe_text_attr(host_ctx),
                                          'comment': '[HOST CONTEXT] Metricas telegraf + alertas Falco recientes'}, pythonify=True)
            logger.info(f"  [+] Host context inyectado")
        except Exception as e:
            logger.warning(f"Fallo host context: {e}")

    # 3. Perfil TAPCD del actor (Neo4j)
    if topic == 'falco_events' and not dst_ip:
        dst_ip = SCENARIO_VICTIM_IP

    if dst_ip:
        actor = None
        if topic == 'network_intrusion_alerts':
            actor_ref = src_ips[0] if src_ips else None
            actor = get_tapcd_actor_profile(dst_ip, prefer_novadef=False, attacker_ref=actor_ref)
            if actor and str(actor.get('id', '')).startswith('novadef-'):
                actor = None
            if not actor:
                actor = get_tapcd_actor_profile(dst_ip, prefer_novadef=False)
                if actor and str(actor.get('id', '')).startswith('novadef-'):
                    actor = None
        elif topic == 'falco_events':
            actor = get_tapcd_actor_profile(dst_ip, prefer_novadef=False)
            if actor and str(actor.get('id', '')).startswith('novadef-'):
                actor = None
        if actor:
            profile_text = (
                f"[TAPCD - Perfil del Actor Amenaza]\n"
                f"  Perfil         : {actor.get('profile', 'N/A')}\n"
                f"  Nivel de riesgo: {actor.get('riskLevel', 'N/A')} / 10\n"
                f"  Pais           : {actor.get('country', 'N/A')}\n"
                f"  Motivacion     : {actor.get('motivation', 'N/A')}\n"
                f"  Afiliacion     : {actor.get('affiliation', 'N/A')}\n"
                f"  Habilidades    : {actor.get('skills', 'N/A')}\n"
                f"  Conocimiento   : {actor.get('knowledge', 'N/A')}\n"
                f"  Actitud        : {actor.get('attitude', 'N/A')}\n"
                f"  Automatizacion : nivel {actor.get('automationLevel', 'N/A')}\n"
                f"  Primera vez    : {actor.get('firstSeen', 'N/A')}\n"
                f"  Ultima act.    : {actor.get('lastActivity', 'N/A')}\n"
                f"  Comentarios    : {actor.get('comments', '')}"
            )
            try:
                misp.add_attribute(event_id, {'type': 'text', 'value': _safe_text_attr(profile_text),
                                              'comment': f'[TAPCD-NATIVE] Perfil actor para victima {dst_ip}'}, pythonify=True)
                logger.info(f"  [+] Perfil TAPCD nativo observado")
            except Exception as e:
                logger.warning(f"Fallo TAPCD: {e}")

# Wall-clock cutoff (ms): Kafka messages produced before this are ignored. Set at
# startup AND bumped on every /reset so stale Falco/network alerts left in Kafka by
# a PREVIOUS experiment (e.g. exp3 ransomware events) are not reprocessed by the
# next one. Also signals the consumer loop to seek_to_end past that backlog.
_startup_cutoff_ms = time.time() * 1000
_seek_to_end_requested = False

def _tag_event_with_scenario(misp_client, event_or_id, scenario_id: str) -> None:
    """Attach a scenario:<id> tag to a MISP event for cross-scenario isolation.
    Uses the MISP REST API directly (/events/addTag) which accepts integer event IDs."""
    tag_name = f"scenario:{scenario_id}"
    # Resolve the integer event id
    if hasattr(event_or_id, 'id'):
        event_id = int(event_or_id.id)
    elif isinstance(event_or_id, int):
        event_id = event_or_id
    else:
        try:
            event_id = int(event_or_id)
        except (ValueError, TypeError):
            event_id = None
    if not event_id:
        logger.warning(f"[SCENARIO-TAG] No se pudo resolver event_id de {event_or_id!r}")
        return
    headers = {'Authorization': MISP_KEY, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    verify = os.getenv('MISP_VERIFY_CERT', 'True').lower() not in ('false', '0', 'no')
    # Ensure the tag exists first
    try:
        requests.post(f"{MISP_URL}/tags/add",
            headers=headers,
            json={'name': tag_name, 'colour': '#2196f3', 'exportable': False},
            verify=verify, timeout=10)
    except Exception:
        pass
    # Get the tag ID (numeric) so we can use /events/addTag/{event_id}/{tag_id}/local:1
    tag_id = None
    try:
        r_tags = requests.get(f"{MISP_URL}/tags/index",
            headers=headers, verify=verify, timeout=10)
        for t in r_tags.json().get('Tag', []):
            if t.get('name') == tag_name:
                tag_id = t.get('id')
                break
    except Exception:
        pass
    if not tag_id:
        logger.warning(f"[SCENARIO-TAG] No se encontró tag_id para '{tag_name}'")
        return
    try:
        r = requests.post(f"{MISP_URL}/events/addTag/{event_id}/{tag_id}/local:1",
            headers=headers, verify=verify, timeout=10)
        result = r.json() if r.ok else {}
        if result.get('saved'):
            logger.info(f"[SCENARIO-TAG] Tag '{tag_name}' (id={tag_id}) añadido al evento #{event_id}")
        else:
            logger.warning(f"[SCENARIO-TAG] addTag respondió: {r.text[:120]}")
    except Exception as e:
        logger.warning(f"[SCENARIO-TAG] No se pudo añadir tag '{tag_name}' al evento #{event_id}: {e}")


def _reset_run_state(new_scenario_id: str | None = None) -> None:
    """Clear all per-run in-memory state so the next experiment starts clean.
    Called via POST /reset (from the experiments API) or on integrator restart."""
    global _active_event_by_victim, _active_title_by_victim
    global _ransomware_tapcd_published_at, _alert_dedup, _dedup_logged_once
    global _campaign_src_ips, _ransomware_profile_sent, _persisted_dedup
    global _startup_cutoff_ms, _seek_to_end_requested, _ACTIVE_SCENARIO_ID
    if new_scenario_id:
        _ACTIVE_SCENARIO_ID = new_scenario_id
        logger.info("[RESET] Escenario activo → %s", _ACTIVE_SCENARIO_ID)
    # Advance the cutoff to NOW and ask the consumer to jump to the end of the
    # topics: any alert still sitting in Kafka from the previous experiment must
    # not create events/profiles for the new run.
    _startup_cutoff_ms = time.time() * 1000
    _seek_to_end_requested = True
    _active_event_by_victim = {}
    _active_title_by_victim = {}
    _ransomware_tapcd_published_at = {}
    _campaign_src_ips = {}
    _ransomware_profile_sent = {}
    _alert_dedup = {}
    _dedup_logged_once = set()
    # Clear the in-memory persisted-dedup dict too — clearing only the file left
    # the cooldown entries live in memory, so a second run on the same victim/
    # attack within the TTL was still dropped as "ya procesada".
    _persisted_dedup = {}
    # Remove persisted dedup file so cooldown TTLs don't bleed across runs.
    try:
        if os.path.exists(DEDUP_STATE_FILE):
            os.remove(DEDUP_STATE_FILE)
    except Exception:
        pass
    logger.info("[RESET] Estado de run limpiado — listo para nuevo experimento")


_RESET_HTTP_PORT = int(os.getenv("MISP_INTEGRATOR_RESET_PORT", "19090"))


class _ResetHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        if parsed.path == "/reset":
            params = parse_qs(parsed.query)
            scenario_id = (params.get("scenario_id") or [None])[0]
            _reset_run_state(new_scenario_id=scenario_id)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        logger.debug("[HTTP] " + fmt, *args)


def _start_reset_server() -> None:
    srv = HTTPServer(("0.0.0.0", _RESET_HTTP_PORT), _ResetHandler)
    logger.info("[HTTP] Reset server escuchando en :%d", _RESET_HTTP_PORT)
    srv.serve_forever()


def safe_json_deserializer(x):
    raw_text = x.decode('utf-8', errors='ignore')
    try:
        return json.loads(raw_text)
    except Exception:
        try:
            limpio = re.sub(r'(ObjectId|ISODate)\((.*?)\)', r'\2', raw_text)
            return json.loads(limpio)
        except Exception:
            return {"raw_message": raw_text}

def main():
    logger.info("Iniciando servicio PMP -> MISP (1 evento activo por run)...")
    threading.Thread(target=_start_reset_server, daemon=True).start()
    
    misp = init_misp()
    if not misp:
        logger.warning("MISP no está preparado o las credenciales fallaron. Saliendo para reintentar...")
        sys.exit(1)  # Docker (restart: on-failure) reiniciará hasta que MISP esté listo

    # latest: empezar desde mensajes nuevos para evitar reprocesar histórico
    # al arrancar en limpio y crear eventos "fantasma" antes del experimento.
    consumer = KafkaConsumer(
        *KAFKA_TOPICS,
        bootstrap_servers=[KAFKA_BROKER],
        auto_offset_reset='latest',
        enable_auto_commit=True,
        group_id='misp-integration-group',
        value_deserializer=safe_json_deserializer
    )

    logger.info(f"Conectado a Kafka: {KAFKA_BROKER}")

    # Seek to end of all partitions after joining the group.
    # This eliminates the catchup phase where the consumer burns through
    # thousands of old messages (Falco syscall events, telegraf metrics, etc.)
    # accumulated while the integrator was down. Without this, restart →
    # first new Kafka message latency can be 10-50 seconds. With this fix
    # it is <1s (only limited by filebeat scan_frequency=100ms and Kafka lag).
    _seek_deadline = time.time() + 20.0
    while time.time() < _seek_deadline:
        consumer.poll(timeout_ms=1000)   # triggers / progresses assignment
        if consumer.assignment():
            try:
                consumer.seek_to_end()
                logger.info("[KAFKA] seek_to_end() completado — procesando solo mensajes nuevos")
            except Exception as _seek_err:
                logger.warning(f"[KAFKA] seek_to_end() falló: {_seek_err}")
            break
    else:
        logger.warning("[KAFKA] seek_to_end() no se pudo ejecutar: sin particiones asignadas en 20s")

    # Ignorar mensajes anteriores al arranque del integrador (safety net).
    # _startup_cutoff_ms is module-global and also bumped by /reset between runs.
    global _startup_cutoff_ms, _seek_to_end_requested
    _startup_cutoff_ms = time.time() * 1000  # now in ms epoch

    # Poll-based loop (instead of `for message in consumer`) so we can honour a
    # /reset-requested seek_to_end within ~1s even when no new message arrives —
    # this closes the window where a new run consumes the previous run's backlog.
    while True:
        if _seek_to_end_requested:
            _seek_to_end_requested = False
            try:
                consumer.poll(timeout_ms=0)          # ensure partitions are assigned
                consumer.seek_to_end()
                logger.info("[KAFKA] seek_to_end() tras /reset — se descarta backlog del experimento anterior")
            except Exception as _e:
                logger.warning(f"[KAFKA] seek_to_end() tras /reset falló: {_e}")
            continue

        batch = consumer.poll(timeout_ms=500, max_records=200)
        if not batch:
            continue
        # If a reset lands mid-batch, drop the whole batch and seek on next loop.
        if _seek_to_end_requested:
            continue
        for _tp, messages in batch.items():
            for message in messages:
                if _seek_to_end_requested:
                    break
                if message.timestamp < _startup_cutoff_ms:
                    continue
                process_alert_to_misp(misp, message.topic, message.value)

if __name__ == "__main__":
    main()
