import copy
import json
import os
import time
import io
import csv
import requests
import logging
import schedule
import socket
import pymysql
import re
import threading
import sys
import urllib3
from pymisp import PyMISP
from kafka import KafkaConsumer

# Suppress urllib3 InsecureRequestWarning (requests are made with verify=False
# intentionally in lab environments; the warning only pollutes the logs).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - SOARCA-TRIGGER - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MISP_URL = os.getenv('MISP_URL', 'http://127.0.0.1:8080')
MISP_KEY = os.getenv('MISP_KEY', 'CHANGEME')
MISP_VERIFY_CERT = False
SOARCA_API = os.getenv('SOARCA_API', 'http://127.0.0.1:8000')
PLAYBOOK_PATH = os.getenv('PLAYBOOK_PATH', '/app/playbooks/block_ip.json')
ISOLATION_PLAYBOOK_PATH = os.getenv('ISOLATION_PLAYBOOK_PATH', '/app/playbooks/isolate_lab_host.json')
LAB_VICTIM_HOST = os.getenv('SOARCA_LAB_VICTIM_HOST', 'scenario_victim')
LAB_SSH_PORT = int(os.getenv('SOARCA_LAB_SSH_PORT', '2222'))
MAX_EVENT_AGE_SECS = int(os.getenv('SOARCA_MAX_EVENT_AGE_SECS', '900'))
MISP_DB_HOST = os.getenv("MISP_DB_HOST", "misp-db")
MISP_DB_PORT = int(os.getenv("MISP_DB_PORT", "3306"))
MISP_DB_USER = os.getenv("MISP_DB_USER", "misp")
MISP_DB_PASSWORD = os.getenv("MISP_DB_PASSWORD", "misp_password")
MISP_DB_NAME = os.getenv("MISP_DB_NAME", "misp")
ATTACKER_IP_RANGE_START = os.getenv("SOARCA_ATTACKER_IP_RANGE_START", "172.18.0.10")
ATTACKER_IP_RANGE_END = os.getenv("SOARCA_ATTACKER_IP_RANGE_END", "172.18.0.210")
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka_novadef:29092")
SOARCA_TAPCD_PROFILE_TOPIC = os.getenv("SOARCA_TAPCD_PROFILE_TOPIC", "profiles_out")

# Scenario tag for cross-scenario isolation.  The experiments API writes the
# active scenario_id to /app/state/active_scenario.txt before each run; the
# trigger reads it fresh on every Kafka message so it always targets the right
# scenario without needing a container restart.
_ACTIVE_SCENARIO_ID: str = os.getenv("NOVADEF_SCENARIO_ID", "default")
_ACTIVE_SCENARIO_FILE = "/app/state/active_scenario.txt"


def _read_active_scenario() -> str:
    """Return the current active scenario_id, preferring the state file over the env var."""
    try:
        val = open(_ACTIVE_SCENARIO_FILE).read().strip()
        if val:
            return val
    except Exception:
        pass
    return _ACTIVE_SCENARIO_ID


def _parse_ipv4_octets(ip: str) -> list[int] | None:
    try:
        parts = [int(x) for x in str(ip or "").strip().split(".")]
        if len(parts) != 4:
            return None
        if any(p < 0 or p > 255 for p in parts):
            return None
        return parts
    except Exception:
        return None


def _effective_ip_range(victim_ip: str | None) -> tuple[str, str]:
    """
    Build an effective blocking range aligned with the active scenario subnet.
    If configured range is on a different /24 than victim_ip, reuse victim /24
    and keep configured host octets.
    """
    start_cfg = _parse_ipv4_octets(ATTACKER_IP_RANGE_START)
    end_cfg = _parse_ipv4_octets(ATTACKER_IP_RANGE_END)
    victim = _parse_ipv4_octets(str(victim_ip or ""))

    if start_cfg and end_cfg and victim:
        same_prefix = start_cfg[:3] == victim[:3] and end_cfg[:3] == victim[:3]
        if same_prefix:
            return ATTACKER_IP_RANGE_START, ATTACKER_IP_RANGE_END
        start_octet = start_cfg[3]
        end_octet = end_cfg[3]
        start_eff = f"{victim[0]}.{victim[1]}.{victim[2]}.{start_octet}"
        end_eff = f"{victim[0]}.{victim[1]}.{victim[2]}.{end_octet}"
        return start_eff, end_eff

    # Fallback to configured literals if parsing fails.
    return ATTACKER_IP_RANGE_START, ATTACKER_IP_RANGE_END

PROCESSED_EVENTS_FILE = '/app/state/processed_events.txt'
LAST_ISOLATION_BY_VICTIM = {}
ISOLATION_DEDUP_SECONDS = int(os.getenv('SOARCA_ISOLATION_DEDUP_SECONDS', '300'))
NETWORK_INCIDENT_DEDUP_SECONDS = int(os.getenv('SOARCA_NETWORK_INCIDENT_DEDUP_SECONDS', '1800'))
PROCESSED_INCIDENTS_FILE = '/app/state/processed_incidents.json'
TIMING_FILE = '/app/state/novadef_phase_timing.json'
# Victims for which a ransomware profile has already been received. Network
# profiles arriving for these victims are suppressed so only ONE countermeasure
# (isolation) is applied and only ONE profile is visible in the GUI.
RANSOMWARE_RECEIVED_FOR_VICTIM: dict[str, float] = {}

# Cache of the last network-phase profile row per victim_ip so that when the
# ransomware profile arrives we can produce ONE merged profile for MISP instead
# of two separate attributes.
_NETWORK_PROFILE_FOR_VICTIM: dict[str, dict] = {}

# In-memory timing state, written atomically to TIMING_FILE on each update.
_TIMING_LOCK = threading.Lock()
_TIMING: dict = {}


def _write_phase_timing(key: str, ts: float | None = None) -> None:
    """Record a precise phase timestamp (epoch float) to the shared timing file."""
    if ts is None:
        ts = time.time()
    with _TIMING_LOCK:
        _TIMING[key] = ts
        try:
            tmp = TIMING_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(_TIMING, f)
            os.replace(tmp, TIMING_FILE)
        except Exception as exc:
            logger.warning("Could not write timing file: %s", exc)


def reset_phase_timing() -> None:
    with _TIMING_LOCK:
        _TIMING.clear()
        try:
            os.replace(TIMING_FILE + ".tmp", TIMING_FILE) if os.path.exists(TIMING_FILE + ".tmp") else None
            with open(TIMING_FILE, "w") as f:
                json.dump({}, f)
        except Exception:
            pass

D3FEND_MAPPING = {
    "network_password_spraying": {
        "attack": ["T1110", "T1110.003", "T1133"],
        "d3fend": [
            "D3-NetworkTrafficFiltering",
            "D3-InboundTrafficFiltering",
            "D3-SessionTermination",
            "D3-AccountLocking",
            "D3-NetworkIsolation",
        ],
        "playbook": "block_ip",
    },
    "host_ransomware": {
        "attack": ["T1486", "T1490", "T1489", "T1005"],
        "d3fend": [
            "D3-FileIntegrityMonitoring",
            "D3-FileAccessPatternAnalysis",
            "D3-ProcessAnalysis",
            "D3-ExecutionIsolation",
            "D3-NetworkIsolation",
            "D3-ProcessTermination",
            "D3-RestoreFile",
        ],
        "playbook": "isolate_lab_host",
    },
}


def ensure_state_dir():
    """Crea el directorio de estado si no existe (necesario la primera vez)."""
    import pathlib
    pathlib.Path('/app/state').mkdir(parents=True, exist_ok=True)


def _enrich_misp_with_profile(profile_row: dict, victim_ip: str, actor_id: str, scenario_id: str | None = None) -> None:
    """Add TAPCD actor profile as a MISP attribute on the most recent event for victim_ip.

    Called after the profile is known (profiles_out) so the enrichment is always
    available — unlike the integrator which queries Neo4j while creating the event,
    before prep_pred has had a chance to run.
    """
    try:
        misp = init_misp()
        if not misp:
            logger.warning("[MISP-ENRICH] No se pudo conectar a MISP para enriquecer el perfil.")
            return

        # Find the most recent MISP event mentioning the victim IP for THIS scenario.
        from datetime import datetime, timedelta
        date_from = (datetime.utcnow() - timedelta(hours=2)).strftime("%Y-%m-%d")
        headers = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}
        scenario_tag = f"scenario:{scenario_id or _read_active_scenario()}"
        r = requests.post(
            f"{MISP_URL}/events/restSearch/",
            json={
                "returnFormat": "json",
                "value": victim_ip,
                "tags": [scenario_tag],
                "limit": 5,
                "datefrom": date_from,
                "includeCorrelations": 0,
            },
            headers=headers,
            verify=False,
            timeout=10,
        )
        if r.status_code != 200:
            logger.warning("[MISP-ENRICH] restSearch devolvió %s", r.status_code)
            return

        events = r.json()
        if isinstance(events, dict):
            events = events.get("response", [])
        if not events:
            logger.info("[MISP-ENRICH] No hay eventos MISP recientes para %s (scenario=%s) — se omite enriquecimiento.", victim_ip, scenario_id or _read_active_scenario())
            return

        # Most recent event first (MISP returns sorted by timestamp desc by default).
        event_id = str(events[0].get("id") or events[0].get("Event", {}).get("id", ""))
        if not event_id:
            logger.warning("[MISP-ENRICH] No se pudo obtener event_id del resultado de MISP.")
            return

        def _pf(key: str, default: str = "N/A") -> str:
            v = str(profile_row.get(key) or "").strip()
            return v if v and v not in ("nan", "None", "null") else default

        profile_text = (
            f"[TAPCD - Perfil del Actor Amenaza]\n"
            f"  Actor ID         : {actor_id}\n"
            f"  Perfil           : {_pf('Profile')}\n"
            f"  Motivacion       : {_pf('Motivation')}\n"
            f"  Conocimiento     : {_pf('Knowledge')}\n"
            f"  Habilidades      : {_pf('Skills')}\n"
            f"  Afiliacion       : {_pf('Affiliation')}\n"
            f"  Actitud          : {_pf('Attitude')}\n"
            f"  Grupo amenaza    : {_pf('ThreatGroup')}\n"
            f"  Campaña          : {_pf('Campaigns')}\n"
            f"  Nivel automacion : {_pf('AutomationLevel')}\n"
            f"  Nivel riesgo     : {_pf('RiskLevel')}\n"
            f"  IPs fuente       : {_pf('IPs', victim_ip)}\n"
            f"  Objetivo         : {_pf('Target', victim_ip)}\n"
            f"  Objetivo pref.   : {_pf('PreferredTarget')}\n"
            f"  Pais             : {_pf('Country')}\n"
            f"  Primera actividad: {_pf('FirstSeen')}\n"
            f"  Ultima actividad : {_pf('LastActivity')}\n"
            f"  TTPs             : {_pf('TTPs')}\n"
            f"  Kill Chain       : {_pf('KillChainPhase')}\n"
            f"  Herramientas     : {_pf('Tools')}\n"
            f"  Evasion          : {_pf('Evasion')}\n"
            f"  Alerta detecc.   : {_pf('DetectionAlert')}\n"
            f"  Tipo detecc.     : {_pf('DetectionType')}\n"
            f"  Ataque           : {_pf('DetectionAttack')}\n"
            f"  Fase ataque      : {_pf('DetectionStage')}\n"
            f"  Timestamp detecc.: {_pf('DetectionTs')}\n"
            f"  Comentarios      : {_pf('Comments')}\n"
            f"  Victima          : {victim_ip}\n"
            f"  Generado por     : TAPCD/prep_pred (NOVADEF)"
        )

        misp.add_attribute(
            event_id,
            {"type": "text", "value": profile_text[:2000], "comment": f"[TAPCD-PROFILE] actor_id={actor_id} victim={victim_ip}"},
            pythonify=True,
        )
        logger.info("[MISP-ENRICH] ✅ Perfil TAPCD añadido al evento MISP %s (victim=%s profile=%s)", event_id, victim_ip, _pf('Profile'))
    except Exception as e:
        logger.warning("[MISP-ENRICH] No se pudo enriquecer evento MISP: %s", e)


def _merge_profiles(net_row: dict, ransomware_row: dict) -> dict:
    """Merge network-phase and ransomware-phase profile rows into one combined profile.

    Only uses field values that come from the real TAPCD/prep_pred ML output —
    nothing is invented. Fields present in ransomware_row override net_row when
    both are non-empty (ransomware phase is the more severe / later phase).
    """
    merged = dict(net_row)
    # Actor-level ML fields: take from ransomware_row if present, else keep net_row value
    for field in ("Motivation", "Knowledge", "Attitude", "Affiliation", "Skills", "RiskLevel"):
        ran_val = str(ransomware_row.get(field) or "").strip()
        if ran_val and ran_val not in ("", "None", "nan", "N/A"):
            merged[field] = ran_val
    # Combine IPs from both phases (real IPs from both profile rows)
    net_ips = [ip for ip in str(net_row.get("IPs") or "").split(";") if ip.strip()]
    ran_ips = [ip for ip in str(ransomware_row.get("IPs") or "").split(";") if ip.strip()]
    all_ips = list(dict.fromkeys(net_ips + ran_ips))  # preserve order, deduplicate
    if all_ips:
        merged["IPs"] = ";".join(all_ips[:20])
    # Combine TTPs from both phases
    net_ttps = [t for t in str(net_row.get("TTPs") or "").split(";") if t.strip()]
    ran_ttps = [t for t in str(ransomware_row.get("TTPs") or "").split(";") if t.strip()]
    combined_ttps = list(dict.fromkeys(net_ttps + ran_ttps))
    if combined_ttps:
        merged["TTPs"] = ";".join(combined_ttps)
    # Use the more severe detection stage (ransomware = Impact)
    ran_stage = str(ransomware_row.get("DetectionStage") or "").strip()
    if ran_stage:
        merged["DetectionStage"] = ran_stage
    ran_attack = str(ransomware_row.get("DetectionAttack") or "").strip()
    if ran_attack:
        merged["DetectionAttack"] = ran_attack
    # Combine profile names from both rows (both generated by ML)
    net_prof = str(net_row.get("Profile") or "").strip()
    ran_prof = str(ransomware_row.get("Profile") or "").strip()
    if net_prof and ran_prof and net_prof != ran_prof:
        merged["Profile"] = f"{net_prof} + {ran_prof}"
    elif ran_prof:
        merged["Profile"] = ran_prof
    # Comments: record actual detection values from both phases
    merged["Comments"] = (
        f"network_phase: attack={net_row.get('DetectionAttack','')} "
        f"ts={net_row.get('DetectionTs','')}; "
        f"host_phase: attack={ransomware_row.get('DetectionAttack','')} "
        f"ts={ransomware_row.get('DetectionTs','')}"
    )
    return merged


def _enrich_misp_with_d3fend(victim_ip: str, d3fend_technique: str, playbook_name: str, status: str, scenario_id: str | None = None) -> None:
    """Add the applied D3FEND countermeasure as a MISP attribute on the most recent event for victim_ip."""
    try:
        misp = init_misp()
        if not misp:
            return

        from datetime import datetime, timedelta
        date_from = (datetime.utcnow() - timedelta(hours=2)).strftime("%Y-%m-%d")
        headers = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}
        scenario_tag = f"scenario:{scenario_id or _read_active_scenario()}"
        r = requests.post(
            f"{MISP_URL}/events/restSearch/",
            json={"returnFormat": "json", "value": victim_ip, "tags": [scenario_tag], "limit": 5, "datefrom": date_from, "includeCorrelations": 0},
            headers=headers,
            verify=False,
            timeout=10,
        )
        if r.status_code != 200:
            return

        events = r.json()
        if isinstance(events, dict):
            events = events.get("response", [])
        if not events:
            return

        event_id = str(events[0].get("id") or events[0].get("Event", {}).get("id", ""))
        if not event_id:
            return

        now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        cm_text = (
            f"[NOVADEF - Contramedida D3FEND Aplicada]\n"
            f"  Técnica D3FEND : {d3fend_technique}\n"
            f"  Playbook SOARCA: {playbook_name}\n"
            f"  Estado         : {status}\n"
            f"  Víctima        : {victim_ip}\n"
            f"  Timestamp      : {now_str}\n"
            f"  Referencia     : https://d3fend.mitre.org/"
        )
        misp.add_attribute(
            event_id,
            {"type": "text", "value": cm_text[:950], "comment": f"[D3FEND] technique={d3fend_technique} victim={victim_ip}"},
            pythonify=True,
        )
        logger.info("[MISP-ENRICH] ✅ D3FEND '%s' añadido al evento MISP %s", d3fend_technique, event_id)
    except Exception as e:
        logger.warning("[MISP-ENRICH] No se pudo añadir D3FEND a MISP: %s", e)


def init_misp():
    try:
        return PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_CERT, debug=False)
    except Exception as e:
        logger.error(f"Fallo conectando a MISP: {e}")
        return None

def load_processed_events():
    ensure_state_dir()
    if not os.path.exists(PROCESSED_EVENTS_FILE):
        return set()
    with open(PROCESSED_EVENTS_FILE, 'r') as f:
        return set(line.strip() for line in f)

def save_processed_event(event_id):
    with open(PROCESSED_EVENTS_FILE, 'a') as f:
        f.write(f"{event_id}\n")


def load_processed_incidents() -> dict[str, int]:
    ensure_state_dir()
    if not os.path.exists(PROCESSED_INCIDENTS_FILE):
        return {}
    try:
        with open(PROCESSED_INCIDENTS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): int(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_processed_incidents(data: dict[str, int]) -> None:
    ensure_state_dir()
    with open(PROCESSED_INCIDENTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f)


PROCESSED_INCIDENTS = load_processed_incidents()


def _extract_attack_fingerprint(event_info: str) -> str | None:
    match = re.search(r'attack_fp=([a-fA-F0-9]+)', event_info or '')
    return match.group(1) if match else None


def _network_incident_key(event_info: str, victim_ip: str, attacker_ips: list[str]) -> str:
    fp = _extract_attack_fingerprint(event_info)
    if fp:
        return f"fp:{fp}"
    first_attacker = sorted(set(attacker_ips))[0] if attacker_ips else "unknown"
    return f"victim:{victim_ip}|attacker:{first_attacker}|title:{(event_info or '')[:80]}"


def should_process_network_incident(incident_key: str) -> bool:
    now = int(time.time())
    # Limpieza de estado caducado
    stale_keys = [k for k, ts in PROCESSED_INCIDENTS.items() if now - int(ts) > NETWORK_INCIDENT_DEDUP_SECONDS]
    for k in stale_keys:
        PROCESSED_INCIDENTS.pop(k, None)
    last_ts = PROCESSED_INCIDENTS.get(incident_key)
    if last_ts and (now - int(last_ts)) <= NETWORK_INCIDENT_DEDUP_SECONDS:
        return False
    PROCESSED_INCIDENTS[incident_key] = now
    save_processed_incidents(PROCESSED_INCIDENTS)
    return True

def trigger_soarca_playbook(attacker_ip, victim_ip, threat_info):
    """
    Carga el playbook desde disco, inyecta dinámicamente:
      - victim_ip  → target_definitions (dónde ejecutar iptables por SSH)
      - attacker_ip o rango → playbook_variables.__target_ip__ o (__ip_range_start__, __ip_range_end__)
    Envía el playbook completo a POST /trigger/playbook (ejecución inmediata).
    
    Si attacker_ip es un rango detectado (múltiples IPs o rango explícito), usa block_ip_range.json
    Si attacker_ip es una sola IP, usa block_ip.json (default)
    """
    # Detectar si es un rango (múltiples IPs separadas por coma o guión)
    is_range = False
    ip_range_start = None
    ip_range_end = None
    
    if ',' in attacker_ip or '-' in attacker_ip:
        # Rango explícito: "172.18.0.10-172.18.0.210" o "172.18.0.10,172.18.0.210"
        is_range = True
        if ',' in attacker_ip:
            parts = attacker_ip.split(',')
            ip_range_start = parts[0].strip()
            ip_range_end = parts[1].strip() if len(parts) > 1 else parts[0].strip()
        else:
            parts = attacker_ip.split('-')
            ip_range_start = parts[0].strip()
            ip_range_end = parts[-1].strip()
    
    playbook_file = '/app/playbooks/block_ip_range.json' if is_range else PLAYBOOK_PATH
    action_msg = f"rango {ip_range_start}-{ip_range_end}" if is_range else f"IP {attacker_ip}"
    logger.info(f"🚀 Lanzando playbook: bloquear {action_msg} en {victim_ip}")

    # Cargar plantilla del playbook
    try:
        with open(playbook_file, 'r') as f:
            playbook = json.load(f)
    except Exception as e:
        logger.error(f"❌ No se pudo leer el playbook desde {playbook_file}: {e}")
        return

    # Trabajamos sobre una copia para no mutar la plantilla en memoria
    playbook = copy.deepcopy(playbook)

    # 1. Inyectar victim_ip en todos los target_definitions SSH/Linux
    for target in playbook.get('target_definitions', {}).values():
        if target.get('type') in {'linux', 'ssh'}:
            target['address'] = {'ipv4': [victim_ip]}
            logger.info(f"   🎯 Target SSH dinámico → {victim_ip}")

    # 2. Inyectar variables según sea IP individual o rango
    if is_range:
        if '__ip_range_start__' in playbook.get('playbook_variables', {}):
            playbook['playbook_variables']['__ip_range_start__']['value'] = ip_range_start
        if '__ip_range_end__' in playbook.get('playbook_variables', {}):
            playbook['playbook_variables']['__ip_range_end__']['value'] = ip_range_end
        logger.info(f"   📋 Variables de rango: {ip_range_start} - {ip_range_end}")
    else:
        if '__target_ip__' in playbook.get('playbook_variables', {}):
            playbook['playbook_variables']['__target_ip__']['value'] = attacker_ip
        logger.info(f"   📋 Variable de IP: {attacker_ip}")

    # 3. Enviar a SOARCA para ejecución inmediata
    url = f"{SOARCA_API}/trigger/playbook"
    logger.info(
        "SOARCA_COUNTERMEASURE_REQUESTED source=tapcd_or_misp victim_ip=%s attacker_scope=%s threat=%s",
        victim_ip,
        attacker_ip,
        str(threat_info)[:280],
    )
    try:
        response = requests.post(url, json=playbook, timeout=45)
        if response.status_code == 200:
            _write_phase_timing("act_at")
            logger.info(f"✅ Playbook ejecutado: {action_msg} bloqueado en {victim_ip}")
            logger.info(
                "SOARCA_COUNTERMEASURE_APPLIED source=tapcd_or_misp victim_ip=%s attacker_scope=%s d3fend=D3-NetworkTrafficFiltering",
                victim_ip,
                attacker_ip,
            )
        else:
            logger.warning(f"⚠️ SOARCA respondió {response.status_code}: {response.text[:300]}")
    except Exception as e:
        logger.error(f"❌ Error contactando SOARCA: {e}")


def _split_multi_values(raw: str) -> list[str]:
    out: list[str] = []
    for part in re.split(r"[;,|\s]+", str(raw or "").strip()):
        token = part.strip()
        if token and token not in out:
            out.append(token)
    return out


def _consume_tapcd_profile_events() -> None:
    logger.info("TAPCD->SOARCA stream activo en %s topic=%s", KAFKA_BOOTSTRAP, SOARCA_TAPCD_PROFILE_TOPIC)
    # Record startup time (ms) — messages produced before this moment are from
    # prior experiment runs and must be skipped to avoid false positive actions.
    _startup_ts_ms = int(time.time() * 1000)
    consumer = KafkaConsumer(
        SOARCA_TAPCD_PROFILE_TOPIC,
        bootstrap_servers=[KAFKA_BOOTSTRAP],
        auto_offset_reset="latest",
        enable_auto_commit=True,
        group_id=os.getenv("SOARCA_TAPCD_GROUP_ID", "soarca-tapcd-trigger"),
        value_deserializer=lambda v: v,
        # Allow long processing (SSH + SOARCA calls can take 30-60s each).
        # Default is 300000ms (5 min); we extend to 10 min to prevent the
        # consumer group from dying mid-playbook and reprocessing stale messages.
        max_poll_interval_ms=600000,
        session_timeout_ms=60000,
        heartbeat_interval_ms=20000,
        max_poll_records=1,  # process one message at a time to avoid batching delays
    )
    try:
        for message in consumer:
            try:
                # Skip messages produced before this process started (stale Kafka backlog).
                if message.timestamp and message.timestamp < _startup_ts_ms:
                    logger.debug(
                        "⏭️ Mensaje Kafka ignorado (anterior al arranque): ts=%d startup=%d",
                        message.timestamp, _startup_ts_ms,
                    )
                    continue
                raw = (message.value or b"").decode("utf-8", errors="replace")
                rows = list(csv.DictReader(io.StringIO(raw)))
                if not rows:
                    continue
                profile_row = rows[-1]

                # Read active scenario fresh on every message so the trigger adapts
                # immediately when the API switches to a different scenario.
                current_scenario = _read_active_scenario()

                profile_name = str(profile_row.get("Profile") or "").strip()
                _profile_degraded = (
                    not profile_name
                    or profile_name.lower() in {"", "none", "nan", "unknown", "unclassified"}
                )

                detection_alert = str(profile_row.get("DetectionAlert") or "").strip()
                detection_type = str(profile_row.get("DetectionType") or "").strip()
                detection_attack = str(profile_row.get("DetectionAttack") or "").strip()
                detection_stage = str(profile_row.get("DetectionStage") or "").strip()
                detection_ts = str(profile_row.get("DetectionTs") or "").strip()

                # Reject only profiles whose MOST RECENT activity predates startup —
                # i.e. genuinely stale records from a prior session. We key on
                # LastActivity (the max() aggregation timestamp), NOT DetectionTs /
                # FirstSeen: FirstSeen is a min() over the flow window and can carry
                # an old date (from historical MongoDB flows) even for a profile whose
                # attack is happening RIGHT NOW — using it here wrongly dropped live
                # spraying profiles and suppressed their countermeasure.
                _recency_ts = str(profile_row.get("LastActivity") or "").strip() or detection_ts
                if _recency_ts:
                    try:
                        _rts_str = _recency_ts.replace("Z", "").replace("T", " ").split(".")[0]
                        _rts_epoch = time.mktime(time.strptime(_rts_str, "%Y-%m-%d %H:%M:%S"))
                        # Reject only profiles from a prior calendar day. Within the same
                        # day, flow aggregation windows may lag (LastActivity = max() of
                        # historical MongoDB flows, which can be hours behind real-time),
                        # so a 24h grace window ensures today's profiles always pass.
                        # The Kafka message-timestamp guard at line ~539 already blocks
                        # messages produced before this process started (cross-session);
                        # this guard only eliminates genuinely old cross-day records.
                        _cutoff_epoch = (_startup_ts_ms / 1000.0) - 86400  # 24h grace window
                        if _rts_epoch < _cutoff_epoch:
                            logger.info(
                                "⏭️ Perfil ignorado por LastActivity anterior al arranque: profile=%s last_activity=%s",
                                profile_row.get("Profile", "?"), _recency_ts,
                            )
                            continue
                    except Exception:
                        pass  # Unparseable timestamp — let the message through

                # Si el perfil ML no pudo inferirse, intentamos continuar con la
                # información de detección de la alerta. Solo descartamos si ni
                # siquiera hay detección de ataque (el CSV está vacío o es ruido).
                if _profile_degraded:
                    if not detection_alert or not detection_attack:
                        logger.info("⏭️ Perfil ML no inferido y sin info de detección; se omite.")
                        continue
                    logger.info(
                        "⚠️ Perfil ML no inferido (profile=%r) — continuando con info de alerta: attack=%s",
                        profile_name, detection_attack,
                    )
                    profile_name = f"unknown-{detection_attack.lower().replace(' ', '_')}"
                else:
                    if not detection_alert or not detection_attack:
                        logger.info("⏭️ TAPCD evento sin alerta de detección completa; se omite.")
                        continue

                attacker_ips = _split_multi_values(profile_row.get("IPs") or "")
                # Target may be a multi-value string (semicolon/comma separated);
                # take the first token as the candidate victim IP.
                victim_candidate_raw = str(profile_row.get("Target") or "").strip()
                victim_candidate = re.split(r"[;,|\s]+", victim_candidate_raw)[0].strip() if victim_candidate_raw else ""
                if not victim_candidate:
                    continue

                # Determine if this is ransomware before normalising IPs.
                # For ransomware the source IP IS the victim (the compromised host
                # is the one triggering Falco), so attacker_ips == [victim_ip].
                # Passing attacker_ips to normalize_victim_ip would cause it to
                # discard victim_candidate as "the attacker" and return None.
                is_ransomware_profile = "ransomware" in detection_attack.lower()

                if is_ransomware_profile:
                    # For ransomware the victim is the compromised host. Resolution
                    # priority (most authoritative first):
                    #   1. Target / PreferredTarget — the integrator sets these to
                    #      the real victim IP. For a HYBRID (exp3) combined profile,
                    #      IPs[] also contains the network-phase ATTACKER IPs
                    #      (e.g. 172.18.0.161-168), so attacker_ips[0] would wrongly
                    #      pick an attacker. Target is the only reliable victim field.
                    #   2. first lab-internal IP in IPs[] (legacy single-host case).
                    #   3. DNS-resolved lab victim IP.
                    _lab_re = r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
                    lab_ip = resolve_lab_victim_ip()
                    _target_candidate = victim_candidate  # already parsed from Target
                    if _target_candidate and re.match(_lab_re, _target_candidate):
                        victim_ip = _target_candidate
                    else:
                        src_candidate = attacker_ips[0] if attacker_ips else ""
                        if src_candidate and re.match(_lab_re, src_candidate):
                            victim_ip = src_candidate
                        elif lab_ip:
                            victim_ip = lab_ip
                        else:
                            victim_ip = _target_candidate
                    # Discard profiles where none of the source IPs is a lab address —
                    # those are Isolation Forest false positives on outbound public traffic.
                    if not any(re.match(_lab_re, ip) for ip in attacker_ips):
                        logger.info(
                            "⏭️ Ransomware profile descartado: ninguna IP fuente es de laboratorio (%s) — falso positivo.",
                            attacker_ips,
                        )
                        continue
                    logger.info("🎯 Ransomware: víctima resuelta → %s (target=%s src_ips=%s)", victim_ip, _target_candidate, attacker_ips)
                else:
                    if not attacker_ips:
                        continue
                    victim_ip = normalize_victim_ip(victim_candidate, attacker_ips)

                if not victim_ip:
                    logger.warning("TAPCD evento sin víctima válida. target=%s", victim_candidate)
                    continue

                # Campaign consolidation: once a victim has been fully isolated
                # (ransomware/host countermeasure), ALL later profiles for that
                # victim are redundant — the host is already cut off from the
                # network. This collapses a hybrid campaign (exp3: distributed
                # network spraying + host ransomware) into a SINGLE countermeasure
                # (the isolation) and prevents a flood of per-source-IP network
                # profiles from each triggering their own block_ip_range action.
                actor_id = str(profile_row.get("Id") or "").strip()

                def _pv(key: str) -> str:
                    v = str(profile_row.get(key) or "").strip()
                    return v if v and v not in ("nan", "None", "null") else "-"

                def _emit_profile_ready() -> None:
                    """Log the full TAPCD profile (all ML fields) so the GUI can
                    display it, and enrich the MISP event. Called for EVERY valid
                    profile — including network profiles that arrive after the
                    victim is already isolated — so the rich ML characterization
                    (Motivation/Knowledge/Skills/...) is never lost, even when the
                    countermeasure action itself is suppressed (consolidated)."""
                    logger.info(
                        "📨 TAPCD_PROFILE_READY actor=%s profile=%s victim=%s src_ips=%s "
                        "detection_alert=%s detection_type=%s detection_attack=%s detection_stage=%s detection_ts=%s "
                        "motivation=%s knowledge=%s attitude=%s affiliation=%s skills=%s risk=%s "
                        "automation=%s ttps=%s kill_chain=%s tools=%s evasion=%s "
                        "threat_group=%s campaigns=%s country=%s "
                        "target=%s preferred_target=%s first_seen=%s last_activity=%s "
                        "is_ransomware=%s",
                        actor_id or "-", profile_name, victim_ip, ",".join(attacker_ips[:10]),
                        detection_alert, detection_type, detection_attack, detection_stage, detection_ts,
                        _pv("Motivation"), _pv("Knowledge"), _pv("Attitude"), _pv("Affiliation"),
                        _pv("Skills"), _pv("RiskLevel"), _pv("AutomationLevel"), _pv("TTPs"),
                        _pv("KillChainPhase"), _pv("Tools"), _pv("Evasion"), _pv("ThreatGroup"),
                        _pv("Campaigns"), _pv("Country"), _pv("Target"), _pv("PreferredTarget"),
                        _pv("FirstSeen"), _pv("LastActivity"), is_ransomware_profile,
                    )

                # If a ransomware (host) profile has already been received for
                # this victim, suppress the network COUNTERMEASURE (the isolation
                # covers the whole campaign), but STILL emit the profile so the GUI
                # gets the network actor's full ML characterization, and merge it
                # into the consolidated MISP event.
                if not is_ransomware_profile:
                    if victim_ip in RANSOMWARE_RECEIVED_FOR_VICTIM:
                        logger.info(
                            "⏭️ Contramedida de red suprimida — víctima %s ya aislada; el perfil de red se registra y enriquece MISP igualmente.",
                            victim_ip,
                        )
                        _emit_profile_ready()
                        try:
                            _net_cached = _NETWORK_PROFILE_FOR_VICTIM.get(victim_ip)
                            _enrich_misp_with_profile(profile_row, victim_ip, actor_id, scenario_id=current_scenario)
                        except Exception as _e:
                            logger.debug("No se pudo enriquecer MISP con perfil de red suprimido: %s", _e)
                        continue
                else:
                    # Mark this victim as having a ransomware profile so future
                    # network profiles from stream_low are suppressed.
                    RANSOMWARE_RECEIVED_FOR_VICTIM[victim_ip] = time.time()

                # Dedup by victim + attack + time bucket (5-min windows).
                # Using wall-clock time (not dataset timestamps) ensures that
                # consecutive experiments on the same victim_ip get distinct keys.
                _time_bucket = int(time.time() // 300)  # 5-minute bucket
                incident_key = f"tapcd:{victim_ip}|attack:{detection_attack.lower()}|profile:{profile_name.lower()}|t:{_time_bucket}"
                if not should_process_network_incident(incident_key):
                    logger.info("⏭️ Incidente TAPCD ya mitigado recientemente (%s)", incident_key)
                    continue

                # Campaign consolidation: once a victim has been fully isolated,
                # later profiles are redundant for ACTION purposes, but we still
                # emit the profile (so the GUI shows its ML fields) and enrich the
                # consolidated MISP event before skipping the countermeasure.
                now_ts = time.time()
                last_iso = LAST_ISOLATION_BY_VICTIM.get(victim_ip, 0)
                if (now_ts - last_iso) < ISOLATION_DEDUP_SECONDS:
                    logger.info(
                        "⏭️ Víctima %s ya aislada (campaña consolidada); perfil registrado y MISP enriquecido, sin nueva contramedida (attack=%s).",
                        victim_ip, detection_attack,
                    )
                    _emit_profile_ready()
                    try:
                        _enrich_misp_with_profile(profile_row, victim_ip, actor_id, scenario_id=current_scenario)
                    except Exception as _e:
                        logger.debug("No se pudo enriquecer MISP con perfil post-aislamiento: %s", _e)
                    continue

                t_profile_ready = time.time()
                _emit_profile_ready()
                _write_phase_timing("profile_at", t_profile_ready)

                threat_info = (
                    f"tapcd_profile={profile_name}; actor_id={actor_id}; target={victim_ip}; "
                    f"src_ips={','.join(attacker_ips[:10])}; detection_alert={detection_alert}; "
                    f"detection_type={detection_type}; detection_attack={detection_attack}; "
                    f"detection_stage={detection_stage}; detection_ts={detection_ts}"
                )

                # Decide: trigger SOARCA immediately — do NOT wait for MISP
                # enrichment. MISP enrichment is purely observational and can
                # run in the background without delaying the countermeasure.
                _write_phase_timing("decide_at")

                if is_ransomware_profile:
                    # Merge with the network profile if we have one cached for this victim
                    _net_cached = _NETWORK_PROFILE_FOR_VICTIM.get(victim_ip)
                    _profile_to_enrich = _merge_profiles(_net_cached, profile_row) if _net_cached else profile_row
                    _merged_actor_id = actor_id + (f"+{_net_cached.get('Id','')}" if _net_cached else "")
                    trigger_soarca_isolation(victim_ip, threat_info)
                    _sc = current_scenario
                    threading.Thread(
                        target=lambda pr=_profile_to_enrich, aid=_merged_actor_id, sc=_sc: (
                            _enrich_misp_with_profile(pr, victim_ip, aid, scenario_id=sc),
                            _write_phase_timing("enrich_at"),
                            _enrich_misp_with_d3fend(
                                victim_ip,
                                d3fend_technique="Network Isolation (D3-NetworkIsolation) + Execution Isolation (D3-ExecutionIsolation)",
                                playbook_name="isolate_lab_host",
                                status="applied",
                                scenario_id=sc,
                            ),
                        ),
                        daemon=True,
                        name="misp-enrich-bg",
                    ).start()
                else:
                    # Cache this network profile so the ransomware profile can merge it
                    _NETWORK_PROFILE_FOR_VICTIM[victim_ip] = profile_row
                    # For network-only profiles, wait briefly before applying
                    # block_ip_range. If a ransomware profile arrives in that
                    # window (RANSOMWARE_RECEIVED_FOR_VICTIM gets set), skip the
                    # block_ip — isolation will handle the whole campaign instead.
                    _net_victim_ip = victim_ip
                    _net_profile_row = profile_row
                    _net_actor_id = actor_id
                    _net_threat_info = threat_info
                    _net_scenario = current_scenario
                    def _delayed_network_countermeasure(
                        vip=_net_victim_ip, pr=_net_profile_row,
                        aid=_net_actor_id, ti=_net_threat_info, sc=_net_scenario,
                    ):
                        time.sleep(20)
                        if vip in RANSOMWARE_RECEIVED_FOR_VICTIM:
                            logger.info(
                                "⏭️ block_ip_range cancelado para %s — perfil ransomware recibido durante la espera; la isolación cubre la campaña.",
                                vip,
                            )
                            return
                        eff_start, eff_end = _effective_ip_range(vip)
                        ip_range = f"{eff_start},{eff_end}"
                        trigger_soarca_playbook(ip_range, vip, ti)
                        _enrich_misp_with_profile(pr, vip, aid, scenario_id=sc)
                        _write_phase_timing("enrich_at")
                        _enrich_misp_with_d3fend(
                            vip,
                            d3fend_technique="Inbound Traffic Filtering (D3-InboundTrafficFiltering) + Network Traffic Filtering (D3-NetworkTrafficFiltering)",
                            playbook_name="block_ip_range",
                            status="applied",
                            scenario_id=sc,
                        )
                    threading.Thread(target=_delayed_network_countermeasure, daemon=True, name="net-cm-delay").start()
            except Exception as e:
                logger.warning("Error procesando evento TAPCD profiles_out: %s", e)
                continue
    finally:
        try:
            consumer.close()
        except Exception:
            pass


def resolve_lab_victim_ip() -> str | None:
    try:
        return socket.gethostbyname(LAB_VICTIM_HOST)
    except Exception as e:
        logger.error(f"❌ No se pudo resolver host de víctima de laboratorio '{LAB_VICTIM_HOST}': {e}")
        return None


def _can_reach_ssh(target_ip: str, timeout: float = 2.0) -> bool:
    if not target_ip:
        return False
    try:
        with socket.create_connection((target_ip, LAB_SSH_PORT), timeout=timeout):
            return True
    except Exception:
        return False


def normalize_victim_ip(candidate_victim_ip: str | None, attacker_ips: list[str] | None) -> str | None:
    """
    Evita bloquear/aislar en la máquina atacante o en IPs obsoletas.
    Prioriza:
      1) IP candidata si no coincide con atacante y tiene SSH alcanzable.
      2) IP de laboratorio resuelta por hostname (scenario_victim) si tiene SSH.
      3) Fallback a candidata, luego a host resuelto.
    """
    attackers = set(attacker_ips or [])
    lab_victim_ip = resolve_lab_victim_ip()

    if candidate_victim_ip and candidate_victim_ip in attackers:
        logger.warning(
            "⚠️ IP víctima candidata (%s) coincide con atacante; se intentará víctima de laboratorio (%s).",
            candidate_victim_ip,
            lab_victim_ip,
        )
        candidate_victim_ip = None

    if candidate_victim_ip and _can_reach_ssh(candidate_victim_ip):
        return candidate_victim_ip

    if lab_victim_ip and _can_reach_ssh(lab_victim_ip):
        if candidate_victim_ip and candidate_victim_ip != lab_victim_ip:
            logger.warning(
                "⚠️ SSH no alcanzable en víctima candidata %s; se usa víctima de laboratorio %s.",
                candidate_victim_ip,
                lab_victim_ip,
            )
        return lab_victim_ip

    return candidate_victim_ip or lab_victim_ip


def trigger_soarca_isolation(victim_ip, threat_info):
    now = time.time()
    last = LAST_ISOLATION_BY_VICTIM.get(victim_ip, 0)
    if now - last < ISOLATION_DEDUP_SECONDS:
        logger.info(f"⏭️ Aislamiento ya aplicado recientemente para {victim_ip}, se omite relanzar.")
        return

    logger.info(f"🚀 Lanzando playbook de aislamiento en {victim_ip}")

    try:
        with open(ISOLATION_PLAYBOOK_PATH, 'r') as f:
            playbook = json.load(f)
    except Exception as e:
        logger.error(f"❌ No se pudo leer el playbook de aislamiento desde {ISOLATION_PLAYBOOK_PATH}: {e}")
        return

    playbook = copy.deepcopy(playbook)

    for target in playbook.get('target_definitions', {}).values():
        if target.get('type') in {'linux', 'ssh'}:
            target['address'] = {'ipv4': [victim_ip]}
            logger.info(f"   🎯 Target SSH dinámico (aislamiento) → {victim_ip}")

    if '__isolation_comment__' in playbook.get('playbook_variables', {}):
        playbook['playbook_variables']['__isolation_comment__']['value'] = 'novadef-ransomware-lab'

    url = f"{SOARCA_API}/trigger/playbook"
    try:
        response = requests.post(url, json=playbook, timeout=45)
        if response.status_code == 200:
            _write_phase_timing("act_at")
            logger.info(f"✅ Playbook de aislamiento ejecutado en {victim_ip}")
            LAST_ISOLATION_BY_VICTIM[victim_ip] = now
        else:
            logger.warning(f"⚠️ SOARCA respondió {response.status_code} (aislamiento): {response.text[:300]}")
    except Exception as e:
        logger.error(f"❌ Error contactando SOARCA para aislamiento: {e}")


def fetch_candidate_events(headers, date_from):
    # En este laboratorio, la API de MISP puede devolver 500 de forma intermitente
    # en restSearch/index pese a que la BD está sana. Priorizamos BD como fuente.
    db_events = fetch_candidate_events_from_db(date_from)
    if db_events:
        return db_events

    merged_events = {}

    # Ruta preferida: POST /events/restSearch (más robusta que /events/index en este lab)
    rest_payloads = [
        ("restSearch tagged", {
            "returnFormat": "json",
            "metadata": 1,
            "limit": 100,
            "datefrom": date_from,
            "tags": ["pmp-auto-aggregation"],
            "includeCorrelations": 0,
            "includeEventUuid": 0,
            "includeEventTags": 0,
            "enforceWarninglist": 0,
        }),
        ("restSearch fallback", {
            "returnFormat": "json",
            "metadata": 1,
            "limit": 100,
            "datefrom": date_from,
            "includeCorrelations": 0,
            "includeEventUuid": 0,
            "includeEventTags": 0,
            "enforceWarninglist": 0,
        }),
    ]
    for label, payload in rest_payloads:
        try:
            r = requests.post(
                f"{MISP_URL}/events/restSearch/",
                json=payload,
                headers=headers,
                verify=False,
                timeout=15,
            )
            if r.status_code != 200:
                logger.warning(f"MISP events/restSearch ({label}) respondió {r.status_code}: {r.text[:200]}")
                continue
            data = r.json()
            events = data if isinstance(data, list) else data.get("response", [])
            logger.info(f"Consulta MISP válida usando {label}: {len(events)} eventos candidatos.")
            for event in events:
                event_id = str(event.get('id', ''))
                if event_id:
                    merged_events[event_id] = event
            if merged_events:
                return list(merged_events.values())
        except Exception as e:
            logger.warning(f"Fallo consultando MISP events/restSearch ({label}): {e}")

    # Fallback legacy: /events/index
    queries = [
        ("tag pmp-auto-aggregation", f"{MISP_URL}/events/index/searchTag:pmp-auto-aggregation/searchDatefrom:{date_from}"),
        ("fallback recent events", f"{MISP_URL}/events/index/searchDatefrom:{date_from}"),
    ]
    for label, url in queries:
        try:
            r = requests.get(url, headers=headers, verify=False, timeout=15)
            if r.status_code != 200:
                logger.error(f"MISP events/index ({label}) respondió {r.status_code}: {r.text[:200]}")
                continue
            events_index = r.json()
            if events_index:
                logger.info(f"Consulta MISP válida usando {label}: {len(events_index)} eventos candidatos.")
                for event in events_index:
                    event_id = str(event.get('id', ''))
                    if event_id:
                        merged_events[event_id] = event
        except Exception as e:
            logger.warning(f"Fallo consultando MISP events/index ({label}): {e}")

    return list(merged_events.values())


def fetch_candidate_events_from_db(date_from: str) -> list[dict]:
    """
    Fallback cuando la API de MISP devuelve 500: leemos eventos recientes desde la BD.
    """
    sql = """
        SELECT id, info, timestamp
        FROM events
        WHERE date >= %s
        ORDER BY id DESC
        LIMIT 150
    """
    events = []
    conn = None
    try:
        conn = pymysql.connect(
            host=MISP_DB_HOST,
            port=MISP_DB_PORT,
            user=MISP_DB_USER,
            password=MISP_DB_PASSWORD,
            database=MISP_DB_NAME,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=8,
            read_timeout=8,
            write_timeout=8,
        )
        with conn.cursor() as cur:
            cur.execute(sql, (date_from,))
            rows = cur.fetchall()
        for row in rows:
            events.append(
                {
                    "id": str(row.get("id", "")),
                    "info": row.get("info", "") or "",
                    "timestamp": str(row.get("timestamp", "0") or "0"),
                }
            )
        if events:
            logger.info(f"Fallback DB MISP: {len(events)} eventos candidatos.")
    except Exception as e:
        logger.warning(f"Fallback DB MISP falló: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return events


def extract_attributes_from_restsearch(payload):
    if isinstance(payload, list):
        return payload

    response = payload.get('response') if isinstance(payload, dict) else None
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        for key in ('Attribute', 'attributes'):
            if isinstance(response.get(key), list):
                return response[key]

    for key in ('Attribute', 'attributes'):
        if isinstance(payload, dict) and isinstance(payload.get(key), list):
            return payload[key]

    return []

def check_misp_for_new_threats():
    logger.info("Buscando nuevos incidentes confirmados en MISP...")

    from datetime import datetime, timedelta
    import re as _re
    date_from = (datetime.utcnow() - timedelta(hours=3)).strftime('%Y-%m-%d')

    headers = {
        'Authorization': MISP_KEY,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    try:
        events_index = fetch_candidate_events(headers, date_from)
        if not events_index:
            events_index = fetch_candidate_events_from_db(date_from)
        if not events_index:
            logger.info("No hay eventos nuevos candidatos en MISP.")
            return

        processed = load_processed_events()

        # Filtrar por timestamp: solo eventos recientes para evitar replay
        # de incidentes antiguos tras reinicios limpios.
        import time as _time
        min_ts = _time.time() - MAX_EVENT_AGE_SECS

        for ev_summary in events_index:
            ev_ts = int(ev_summary.get('timestamp', 0))
            event_id = str(ev_summary.get('id', ''))
            event_info = str(ev_summary.get('info', '') or '')
            event_info_norm = event_info.strip()
            event_info_low = event_info_norm.lower()

            if ev_ts < min_ts and event_id not in processed:
                save_processed_event(event_id)
                continue
            if event_id in processed:
                continue

            # Obtener atributos una sola vez para decidir de forma robusta
            # (sin depender únicamente del prefijo del título en MISP).
            attrs_data = []
            try:
                r_attrs_pre = requests.post(
                    f"{MISP_URL}/attributes/restSearch/",
                    json={"eventid": event_id, "returnFormat": "json", "limit": 120},
                    headers=headers,
                    verify=False,
                    timeout=15,
                )
                if r_attrs_pre.status_code == 200:
                    attrs_data = extract_attributes_from_restsearch(r_attrs_pre.json())
            except Exception:
                attrs_data = []

            attr_comments = [str(a.get('comment', '') or '').lower() for a in attrs_data]
            attr_values = [str(a.get('value', '') or '').lower() for a in attrs_data]
            has_ip_src = any(str(a.get('type', '')).lower() == 'ip-src' for a in attrs_data)
            has_ip_dst = any(str(a.get('type', '')).lower() == 'ip-dst' for a in attrs_data)
            has_network_detection_attr = any(
                ('[network ids]' in c) or ('pipeline-tag:pmp-auto-aggregation' in v)
                for c, v in zip(attr_comments + [''] * max(0, len(attr_values) - len(attr_comments)), attr_values)
            )
            has_tapcd_profile_attr = any(
                ('[tapcd-native]' in c)
                or ('perfil del actor amenaza' in v)
                or ('attacker profile' in v)
                for c, v in zip(attr_comments + [''] * max(0, len(attr_values) - len(attr_comments)), attr_values)
            )

            is_network_event = (
                event_info_norm.startswith("Distributed Password Spraying")
                or event_info_norm.startswith("NETWORK IDS:")
                or event_info_norm.startswith("SNORT:")
                or ("password spraying" in event_info_low)
                or ("network ids" in event_info_low)
                or ("snort" in event_info_low)
                or (has_network_detection_attr and has_ip_src and has_ip_dst)
                or (has_tapcd_profile_attr and has_network_detection_attr and has_ip_src and has_ip_dst)
            )
            is_ransomware_falco = (
                ("falco:" in event_info_low)
                and ("ransomware" in event_info_low)
                and ("novadef" in event_info_low or "host ransomware emulation" in event_info_low)
            )
            # Hybrid attack (exp3): network event title contains "Hybrid Lateral"
            # → route to comprehensive isolation so SOARCA fires ONE countermeasure
            # that covers both the network layer (iptables DROP all) and the host
            # ransomware layer.  The isolation dedup window (ISOLATION_DEDUP_SECONDS)
            # then suppresses the subsequent Falco ransomware event for the same victim.
            is_hybrid_network = (
                is_network_event
                and (
                    "hybrid lateral" in event_info_low
                    or "hybrid lateral remote execution" in event_info_low
                    or any("hybrid lateral remote execution" in v for v in attr_values)
                )
            )

            if not (is_network_event or is_ransomware_falco):
                logger.debug(f"Evento {event_id} fuera del alcance del trigger actual: {event_info}")
                continue

            logger.info(f"Analizando evento ID {event_id}: {event_info} para mitigación...")

            if is_ransomware_falco:
                mapping = D3FEND_MAPPING["host_ransomware"]
                logger.info(
                    "🧭 Selección defensiva MITRE D3FEND: %s | ATT&CK=%s | playbook=%s",
                    ",".join(mapping["d3fend"]),
                    ",".join(mapping["attack"]),
                    mapping["playbook"],
                )
                victim_ip = normalize_victim_ip(resolve_lab_victim_ip(), [])
                if not victim_ip:
                    save_processed_event(event_id)
                    continue
                trigger_soarca_isolation(victim_ip, event_info)
                save_processed_event(event_id)
                continue

            # Estrategia 1: attributes/restSearch por eventid — evita cargar correlaciones
            attacker_ips = []
            victim_ips = []
            try:
                if attrs_data:
                    logger.info(f"   attributes/restSearch devolvió {len(attrs_data)} atributos.")
                    for attr in attrs_data:
                        comment = str(attr.get('comment', ''))
                        if attr.get('type') == 'ip-src' and (
                            '[ATTACKER IP]' in comment or '[NETWORK IDS]' in comment
                        ):
                            attacker_ips.append(attr['value'])
                        elif attr.get('type') == 'ip-dst' and (
                            '[VICTIM IP]' in comment or '[NETWORK IDS]' in comment
                        ):
                            victim_ips.append(attr['value'])
                    if attacker_ips:
                        logger.info(f"   IPs obtenidas via attributes/restSearch: atacante={attacker_ips}, víctima={victim_ips}")
            except Exception as e_attr:
                logger.debug(f"attributes/restSearch falló: {e_attr}")

            # Estrategia 2 (fallback): parsear IPs directamente del título del evento
            # Formato: "SNORT: ... [172.x.x.x → 172.x.x.x]"
            if not attacker_ips or not victim_ips:
                bracket_match = _re.search(
                    r'\[(\d{1,3}(?:\.\d{1,3}){3})\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})',
                    event_info,
                )
                if bracket_match:
                    if not attacker_ips:
                        attacker_ips = [bracket_match.group(1)]
                    if not victim_ips:
                        victim_ips = [bracket_match.group(2)]
                    logger.info(f"   IPs extraídas del bloque [attacker -> victim]: atacante={attacker_ips[0]}, víctima={victim_ips[0]}")

            if not attacker_ips or not victim_ips:
                ip_pattern = r'(\d{1,3}(?:\.\d{1,3}){3})'
                ips_in_title = _re.findall(ip_pattern, event_info)
                if len(ips_in_title) >= 2:
                    if not attacker_ips:
                        attacker_ips = [ips_in_title[0]]
                    if not victim_ips:
                        victim_ips = [ips_in_title[1]]
                    logger.info(f"   IPs extraídas del título: atacante={attacker_ips[0]}, víctima={victim_ips[0]}")
                elif len(ips_in_title) == 1 and not attacker_ips:
                    attacker_ips = [ips_in_title[0]]
                    logger.warning(f"   Solo IP atacante en título: {attacker_ips[0]}")

            if not attacker_ips:
                logger.debug(f"Evento {event_id} sin IPs [ATTACKER IP], se omite.")
                save_processed_event(event_id)
                continue

            if not victim_ips:
                logger.warning(f"Evento {event_id}: atacantes encontrados pero sin [VICTIM IP], se omite.")
                save_processed_event(event_id)
                continue

            victim_ip = normalize_victim_ip(victim_ips[0], attacker_ips)
            if not victim_ip:
                logger.warning(f"Evento {event_id}: no se pudo resolver una víctima válida para ejecutar playbook.")
                save_processed_event(event_id)
                continue

            incident_key = _network_incident_key(event_info, victim_ip, attacker_ips)
            if not should_process_network_incident(incident_key):
                logger.info(f"⏭️ Incidente de red ya mitigado recientemente ({incident_key}), se omite relanzar contramedida.")
                save_processed_event(event_id)
                continue

            if is_hybrid_network:
                # Hybrid lateral + ransomware campaign: apply comprehensive host
                # isolation as the SINGLE countermeasure for both layers.
                # Isolation applies iptables DROP (stops network attack) and the
                # API kills the ransomware process via docker exec.
                # The LAST_ISOLATION_BY_VICTIM dedup (ISOLATION_DEDUP_SECONDS)
                # will suppress any subsequent Falco ransomware event for the
                # same victim, ensuring exactly one SOARCA action per campaign.
                mapping = D3FEND_MAPPING["host_ransomware"]
                logger.info(
                    "🧭 [HYBRID] D3FEND: %s | ATT&CK=%s | playbook=%s — contramedida única para red+host",
                    ",".join(mapping["d3fend"]),
                    ",".join(mapping["attack"]),
                    mapping["playbook"],
                )
                trigger_soarca_isolation(victim_ip, event_info)
            else:
                # Standard distributed password spraying — block attacker IP range.
                mapping = D3FEND_MAPPING["network_password_spraying"]
                logger.info(
                    "🧭 Selección defensiva MITRE D3FEND: %s | ATT&CK=%s | playbook=%s",
                    ",".join(mapping["d3fend"]),
                    ",".join(mapping["attack"]),
                    mapping["playbook"],
                )
                eff_start, eff_end = _effective_ip_range(victim_ip)
                ip_range = f"{eff_start},{eff_end}"
                logger.info(
                    "📊 Ataque distribuido detectado (%s IPs observadas). Bloqueando rango predefinido: %s",
                    len(attacker_ips),
                    ip_range,
                )
                trigger_soarca_playbook(ip_range, victim_ip, event_info)
            save_processed_event(event_id)

    except Exception as e:
        logger.error(f"Falla durante la búsqueda en MISP: {e}")


def prime_existing_events() -> None:
    """
    Marca como ya vistos los eventos que existen cuando arranca SOARCA.
    Así evitamos que un reinicio del integrador reaccione otra vez a eventos
    viejos de experimentos anteriores.
    """
    logger.info("Priming SOARCA dedup cache with existing MISP events...")
    from datetime import datetime, timedelta

    date_from = (datetime.utcnow() - timedelta(hours=3)).strftime('%Y-%m-%d')
    headers = {
        'Authorization': MISP_KEY,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    try:
        events_index = fetch_candidate_events(headers, date_from)
        primed = 0
        for ev_summary in events_index or []:
            event_id = str(ev_summary.get('id', '') or '').strip()
            if not event_id:
                continue
            if event_id not in load_processed_events():
                save_processed_event(event_id)
                primed += 1
        logger.info("SOARCA primed %d pre-existing event(s) as processed.", primed)
    except Exception as e:
        logger.warning("SOARCA priming failed: %s", e)

if __name__ == "__main__":
    logger.info("Integrador MISP -> SOARCA Iniciado.")
    prime_existing_events()
    _consume_tapcd_profile_events()
    sys.exit(0)
