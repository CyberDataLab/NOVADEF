import json
import os
import sys
import logging
import re
import time
import hashlib
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime
from pymisp import PyMISP, MISPEvent
from kafka import KafkaConsumer
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
NETWORK_ATTACK_COOLDOWN_SECS = int(os.getenv('NETWORK_ATTACK_COOLDOWN_SECS', '1800'))  # 30 min
HOST_RANSOMWARE_COOLDOWN_SECS = int(os.getenv('HOST_RANSOMWARE_COOLDOWN_SECS', '1800'))  # 30 min
MISP_TEXT_ATTR_MAXLEN = int(os.getenv('MISP_TEXT_ATTR_MAXLEN', '950'))
SCENARIO_VICTIM_IP = os.getenv('SCENARIO_VICTIM_IP', '172.18.0.2')




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


def upsert_tapcd_actor_profile(victim_ip: str, src_ips: list[str], mitre_attack: list[str], usernames: list[str]) -> bool:
    """
    Crea/actualiza un perfil mínimo de actor en Neo4j para garantizar
    que TAPCD tenga un actor targeteando a la víctima del incidente.
    """
    if not victim_ip:
        return False

    attacker_ref = src_ips[0] if src_ips else "unknown-src"
    actor_id = f"novadef-network-{attacker_ref.replace('.', '-')}-{victim_ip.replace('.', '-')}"
    now_iso = datetime.utcnow().isoformat() + "Z"

    query = {
        "statements": [
            {
                "statement": (
                    "MERGE (a:Actor {id: $actor_id}) "
                    "SET a.profile = 'credential-access-distributed-spraying', "
                    "a.riskLevel = '8', "
                    "a.country = coalesce(a.country, 'unknown'), "
                    "a.motivation = 'credential_access', "
                    "a.affiliation = 'unknown', "
                    "a.skills = 'automation,password_spraying', "
                    "a.knowledge = 'remote_services_authentication', "
                    "a.attitude = 'opportunistic', "
                    "a.automationLevel = 'high', "
                    "a.comments = $comments, "
                    "a.lastActivity = $now, "
                    "a.firstSeen = coalesce(a.firstSeen, $now) "
                    "MERGE (t:Target {ip: $victim_ip}) "
                    "MERGE (a)-[:TARGETS]->(t) "
                    "WITH a "
                    "UNWIND $src_ips AS sip "
                    "MERGE (s:SourceIP {ip: sip}) "
                    "MERGE (a)-[:ORIGINATES_FROM]->(s) "
                    "WITH a "
                    "UNWIND $ttps AS ttp "
                    "MERGE (x:Technique {id: ttp}) "
                    "MERGE (a)-[:USES]->(x)"
                ),
                "parameters": {
                    "actor_id": actor_id,
                    "victim_ip": victim_ip,
                    "src_ips": src_ips[:10],
                    "ttps": mitre_attack[:10],
                    "comments": f"usernames={','.join(usernames[:10])}",
                    "now": now_iso,
                },
            }
        ]
    }
    try:
        response = requests.post(
            NEO4J_HTTP_URL,
            json=query,
            auth=HTTPBasicAuth(NEO4J_USER, NEO4J_PASS),
            timeout=5,
        )
        if response.status_code == 200:
            logger.info(f"[TAPCD] Perfil actor asegurado en Neo4j para víctima {victim_ip}")
            return True
    except Exception as e:
        logger.warning(f"[TAPCD] No se pudo upsertar perfil actor: {e}")
    return False


def upsert_tapcd_host_ransomware_profile(victim_ip: str, detector: str = "falco") -> bool:
    """
    Asegura un perfil TAPCD coherente para incidentes ransomware de host
    sin modificar formatos internos de TAPCD.
    """
    if not victim_ip:
        return False
    actor_id = f"novadef-host-ransomware-{victim_ip.replace('.', '-')}"
    now_iso = datetime.utcnow().isoformat() + "Z"
    query = {
        "statements": [
            {
                "statement": (
                    "MERGE (a:Actor {id: $actor_id}) "
                    "SET a.profile = 'ransomware-impact-emulation', "
                    "a.riskLevel = '9', "
                    "a.country = coalesce(a.country, 'unknown'), "
                    "a.motivation = 'impact', "
                    "a.affiliation = 'unknown', "
                    "a.skills = 'file-encryption-behavior,service-impact', "
                    "a.knowledge = 'host-impact-techniques', "
                    "a.attitude = 'disruptive', "
                    "a.automationLevel = 'medium', "
                    "a.comments = $comments, "
                    "a.lastActivity = $now, "
                    "a.firstSeen = coalesce(a.firstSeen, $now) "
                    "MERGE (t:Target {ip: $victim_ip}) "
                    "MERGE (a)-[:TARGETS]->(t) "
                    "WITH a "
                    "UNWIND $ttps AS ttp "
                    "MERGE (x:Technique {id: ttp}) "
                    "MERGE (a)-[:USES]->(x)"
                ),
                "parameters": {
                    "actor_id": actor_id,
                    "victim_ip": victim_ip,
                    "ttps": ["T1486", "T1490", "T1489", "T1005"],
                    "comments": f"detector={detector}; threat_type=host_ransomware_emulation",
                    "now": now_iso,
                },
            }
        ]
    }
    try:
        response = requests.post(
            NEO4J_HTTP_URL,
            json=query,
            auth=HTTPBasicAuth(NEO4J_USER, NEO4J_PASS),
            timeout=5,
        )
        if response.status_code == 200:
            logger.info(f"[TAPCD] Perfil host-ransomware asegurado para víctima {victim_ip}")
            return True
    except Exception as e:
        logger.warning(f"[TAPCD] No se pudo upsertar perfil host-ransomware: {e}")
    return False


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


def get_tapcd_actor_profile(victim_ip: str) -> dict | None:
    """
    Consulta Neo4j para obtener el perfil de actor que ataca la IP víctima.
    La relación real es: (Actor)-[:TARGETS]->(Target) donde Target.ip CONTAINS victim_ip.
    """
    query = {
        "statements": [
            {
                "statement": (
                    "MATCH (a:Actor)-[:TARGETS]->(t:Target) "
                    "WHERE t.ip CONTAINS $ip "
                    "RETURN a ORDER BY a.lastActivity DESC LIMIT 1"
                ),
                "parameters": {"ip": victim_ip}
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
    if not misp:
        return

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

        # Si la alerta de Snort es la firma puente del detector de anomalías
        # y ya publicamos la campaña de network IDS para ese destino, evitamos
        # crear un segundo evento MISP redundante (reduce 500 intermitente).
        if "NOVADEF-NID" in str(rule):
            net_key = f"network_ids|{dst_ip}|{dst_port}"
            if already_processed_persisted(net_key):
                logger.info(f"[DEDUP-LINK] Snort puente omitida; campaña ya publicada: {net_key}")
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

        is_lab_ransomware = (
            "novadef lab ransomware" in str(rule).lower()
            or "novadef lab ransomware" in str(output).lower()
            or "ransomware" in str(rule).lower()
        )
        # Para exp2: una sola alerta por campaña de ransomware host.
        if is_lab_ransomware:
            dedup_key = f"falco_ransomware|{SCENARIO_VICTIM_IP}"
            persisted_ts = _persisted_dedup.get(dedup_key)
            if persisted_ts and (time.time() - float(persisted_ts)) <= HOST_RANSOMWARE_COOLDOWN_SECS:
                logger.info(f"[DEDUP-PERSIST] Ransomware host ya procesado recientemente: {dedup_key}")
                return
        else:
            dedup_key = f"falco|{rule}|{priority}"
        now = time.time()
        ttl = HOST_RANSOMWARE_COOLDOWN_SECS if is_lab_ransomware else DEDUP_WINDOW_SECS
        if dedup_key in _alert_dedup and (now - _alert_dedup[dedup_key]) < ttl:
            return
        _alert_dedup[dedup_key] = now
        logger.info(f"[DEDUP] Nueva alerta Falco única: {dedup_key}")

        if is_lab_ransomware:
            event_title = (
                f"FALCO: Host Ransomware Emulation Detected [{SCENARIO_VICTIM_IP}] "
                f"(ATT&CK T1486/T1490/T1489/T1005)"
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
        # Campos de contexto del proceso/contenedor
        for key in ['container.id', 'container.name', 'container.image.repository',
                    'proc.name', 'proc.cmdline', 'user.name', 'fd.name', 'evt.type']:
            val = fields.get(key)
            if val:
                falco_detail_lines.append(f"  {key:<35}: {val}")

        attributes_to_add.append({
            'type': 'text',
            'value': '\n'.join(falco_detail_lines),
            'comment': '[FALCO] Contexto del proceso/contenedor'
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

        first_seen_raw = str(alert_data.get('first_seen') or alert_data.get('timestamp') or '')
        first_seen_bucket = first_seen_raw[:16] if first_seen_raw else datetime.utcnow().strftime('%Y-%m-%dT%H:%M')
        src_fingerprint = _stable_hash(sorted(set(str(x) for x in src_ips)))
        # Clave estable por campaña de spraying sobre mismo servicio destino.
        dedup_key = f"network_ids|{dst_ip}|{dst_port}"
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
        attack_fp = _stable_hash([str(dst_ip), str(dst_port), src_fingerprint, first_seen_bucket])
        event_title = (
            f"{alert_data.get('title') or f'NETWORK IDS: Password Spraying [{primary_src} -> {dst_ip}:{dst_port}]'}"
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

        ids_detail = (
            f"[NETWORK IDS ALERT]\n"
            f"  Ataque         : distributed password spraying\n"
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

    # ── Dedup persistente: evitar duplicados aunque el integrador se reinicie ──
    # La ventana en memoria (_alert_dedup) se pierde al reiniciar. Esta comprobación
    # en MISP garantiza que nunca creamos dos eventos con el mismo título.
    # Evitamos restSearch/index para dedup, ya que en algunos arranques de MISP
    # pueden devolver 500 transitorio. Usamos dedup persistente de pipeline.

    # ── Crear un evento MISP nuevo para esta alerta ───────────────────────────
    try:
        new_event = misp.add_event(
            {
                'info': event_title,
                'distribution': 0,
                'threat_level_id': 2,
                'analysis': 0,
            },
            pythonify=True,
        )
        event_id = new_event.id
        logger.info(f"Nuevo evento MISP #{event_id}: {event_title}")
        if topic == 'network_intrusion_alerts':
            mark_processed_persisted(dedup_key)
        elif topic == 'falco_events' and dedup_key.startswith('falco_ransomware|'):
            mark_processed_persisted(dedup_key)
    except Exception as e:
        logger.error(f"Error creando evento MISP '{event_title}': {e}")
        return

    # ── Añadir atributos base ─────────────────────────────────────────────────
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
    if topic not in ('snort_alerts', 'network_intrusion_alerts', 'falco_events'):
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
        actor = get_tapcd_actor_profile(dst_ip)
        if not actor and topic == 'network_intrusion_alerts':
            upsert_tapcd_actor_profile(dst_ip, src_ips, mitre_attack, usernames)
            actor = get_tapcd_actor_profile(dst_ip)
        elif not actor and topic == 'falco_events':
            upsert_tapcd_host_ransomware_profile(dst_ip, detector="falco")
            actor = get_tapcd_actor_profile(dst_ip)
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
                                              'comment': f'[TAPCD] Perfil actor para victima {dst_ip}'}, pythonify=True)
                logger.info(f"  [+] Perfil TAPCD inyectado")
            except Exception as e:
                logger.warning(f"Fallo TAPCD: {e}")

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
    logger.info("Iniciando servicio PMP -> MISP (1 evento por alerta)...")
    
    misp = init_misp()
    if not misp:
        logger.warning("MISP no está preparado o las credenciales fallaron. Saliendo para reintentar...")
        sys.exit(1)  # Docker (restart: on-failure) reiniciará hasta que MISP esté listo

    # earliest: no perder mensajes nuevos aunque el integrador se reinicie.
    # Los mensajes recientes (< 2 min) se procesan; los más antiguos se descartan
    # para evitar reprocesar eventos de arranques anteriores.
    consumer = KafkaConsumer(
        *KAFKA_TOPICS,
        bootstrap_servers=[KAFKA_BROKER],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='misp-integration-group',
        value_deserializer=safe_json_deserializer
    )
    
    logger.info(f"Conectado a Kafka: {KAFKA_BROKER}")

    # Ignorar mensajes anteriores al arranque del laboratorio.
    # 30 min de margen cubre el tiempo de init de MISP (~5 min) + holgura.
    startup_cutoff_ms = (time.time() - 1800) * 1000  # 30 min atrás en ms epoch

    for message in consumer:
        # Filtrar mensajes anteriores al arranque del integrador
        if message.timestamp < startup_cutoff_ms:
            continue
        topic = message.topic
        alert_data = message.value
        process_alert_to_misp(misp, topic, alert_data)

if __name__ == "__main__":
    main()
