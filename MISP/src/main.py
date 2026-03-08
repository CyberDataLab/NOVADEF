import json
import os
import sys
import logging
import re
import time
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

    # Topics de métricas puras y Falco (desactivado por config): los ignora el integrador MISP
    if topic in ['telegraf_metrics', 'syslog_logs', 'systemd_logs', 'tshark_traces', 'cic_flow', 'falco_events']:
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

        # ── Deduplicación: misma regla + mismo par IP en ventana → ignorar ──
        dedup_key = f"{alert_data.get('rule','')}|{src_ip}|{dst_ip}"
        now = time.time()
        if dedup_key in _alert_dedup and (now - _alert_dedup[dedup_key]) < DEDUP_WINDOW_SECS:
            return  # mismo ataque, ya creamos el evento MISP
        _alert_dedup[dedup_key] = now
        logger.info(f"[DEDUP] Nueva alerta única: {dedup_key}")
        proto     = alert_data.get('proto', '')
        rule      = alert_data.get('rule', '')
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

        # Deduplicación: misma regla+prioridad dentro de la ventana → descartar
        dedup_key = f"falco|{rule}|{priority}"
        now = time.time()
        if dedup_key in _alert_dedup and (now - _alert_dedup[dedup_key]) < DEDUP_WINDOW_SECS:
            return
        _alert_dedup[dedup_key] = now
        logger.info(f"[DEDUP] Nueva alerta Falco única: {dedup_key}")

        event_title = f"FALCO: {rule} ({priority})"

        # Atributo principal
        attributes_to_add.append({
            'type': 'text',
            'value': f"[FALCO] {rule} ({priority})",
            'comment': '[FALCO] Regla y prioridad'
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

    # Sin atributos => salir
    if not attributes_to_add:
        return

    # ── Dedup persistente: evitar duplicados aunque el integrador se reinicie ──
    # La ventana en memoria (_alert_dedup) se pierde al reiniciar. Esta comprobación
    # en MISP garantiza que nunca creamos dos eventos con el mismo título.
    try:
        existing = misp.search(controller='events', eventinfo=event_title,
                               limit=1, pythonify=True)
        if existing:
            logger.info(f"[DEDUP-MISP] Evento ya existe en MISP, saltando: {event_title}")
            return
    except Exception as e:
        logger.debug(f"[DEDUP-MISP] No se pudo comprobar duplicado en MISP: {e}")

    # ── Crear un evento MISP nuevo para esta alerta ───────────────────────────
    event = MISPEvent()
    event.info = event_title
    event.distribution = 0      # Your Organization Only
    event.threat_level_id = 2   # Medium
    event.analysis = 0          # Initial
    event.disable_correlation = True   # Evita bug SQL con columna 1_event_id en tabla correlations
    event.add_tag("pmp-auto-aggregation")

    try:
        new_event = misp.add_event(event, pythonify=True)
        event_id = new_event.id
        logger.info(f"Nuevo evento MISP #{event_id}: {event_title}")
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

    # ── Contexto enriquecido (solo en alertas Snort) ──────────────────────────
    if topic != 'snort_alerts':
        return

    # 1. Flujos CIC (MongoDB) para IP atacante y víctima
    for ip in filter(None, [src_ip, dst_ip]):
        flow_ctx = get_network_flows_context(ip)
        if flow_ctx:
            try:
                misp.add_attribute(event_id, {'type': 'text', 'value': flow_ctx,
                                              'comment': f'[CIC FLOWS] Estadisticas para {ip}'}, pythonify=True)
                logger.info(f"  [+] CIC flows para {ip}")
            except Exception as e:
                logger.warning(f"Fallo CIC flows {ip}: {e}")

    # 2. Métricas del host (telegraf + Falco desde OpenSearch)
    host_ctx = get_opensearch_host_context()
    if host_ctx:
        try:
            misp.add_attribute(event_id, {'type': 'text', 'value': host_ctx,
                                          'comment': '[HOST CONTEXT] Metricas telegraf + alertas Falco recientes'}, pythonify=True)
            logger.info(f"  [+] Host context inyectado")
        except Exception as e:
            logger.warning(f"Fallo host context: {e}")

    # 3. Perfil TAPCD del actor (Neo4j)
    if dst_ip:
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
                misp.add_attribute(event_id, {'type': 'text', 'value': profile_text,
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
