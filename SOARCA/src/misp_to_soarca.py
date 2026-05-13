import copy
import json
import os
import time
import requests
import logging
import schedule
import socket
from pymisp import PyMISP

logging.basicConfig(level=logging.INFO, format='%(asctime)s - SOARCA-TRIGGER - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MISP_URL = os.getenv('MISP_URL', 'http://127.0.0.1:8080')
MISP_KEY = os.getenv('MISP_KEY', 'CHANGEME')
MISP_VERIFY_CERT = False
SOARCA_API = os.getenv('SOARCA_API', 'http://127.0.0.1:8000')
PLAYBOOK_PATH = os.getenv('PLAYBOOK_PATH', '/app/playbooks/block_ip.json')
ISOLATION_PLAYBOOK_PATH = os.getenv('ISOLATION_PLAYBOOK_PATH', '/app/playbooks/isolate_lab_host.json')
LAB_VICTIM_HOST = os.getenv('SOARCA_LAB_VICTIM_HOST', 'scenario_victim')

PROCESSED_EVENTS_FILE = '/app/state/processed_events.txt'
LAST_ISOLATION_BY_VICTIM = {}
ISOLATION_DEDUP_SECONDS = int(os.getenv('SOARCA_ISOLATION_DEDUP_SECONDS', '300'))

D3FEND_MAPPING = {
    "network_password_spraying": {
        "attack": ["T1110", "T1110.003", "T1133"],
        "d3fend": [
            "D3-NetworkTrafficFiltering",
            "D3-InboundTrafficFiltering",
            "D3-SessionTermination",
            "D3-AccountLocking",
            "D3-ConnectedHoneynet",
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

def trigger_soarca_playbook(attacker_ip, victim_ip, threat_info):
    """
    Carga el playbook desde disco, inyecta dinámicamente:
      - victim_ip  → target_definitions (dónde ejecutar iptables por SSH)
      - attacker_ip → playbook_variables.__target_ip__ (qué IP bloquear)
    Envía el playbook completo a POST /trigger/playbook (ejecución inmediata).
    No hay IPs hardcodeadas en ningún fichero.
    """
    logger.info(f"🚀 Lanzando playbook: bloquear {attacker_ip} en {victim_ip}")

    # Cargar plantilla del playbook
    try:
        with open(PLAYBOOK_PATH, 'r') as f:
            playbook = json.load(f)
    except Exception as e:
        logger.error(f"❌ No se pudo leer el playbook desde {PLAYBOOK_PATH}: {e}")
        return

    # Trabajamos sobre una copia para no mutar la plantilla en memoria
    playbook = copy.deepcopy(playbook)

    # 1. Inyectar victim_ip en todos los target_definitions SSH/Linux
    for target in playbook.get('target_definitions', {}).values():
        if target.get('type') in {'linux', 'ssh'}:
            target['address'] = {'ipv4': [victim_ip]}
            logger.info(f"   🎯 Target SSH dinámico → {victim_ip}")

    # 2. Inyectar attacker_ip en la variable __target_ip__
    if '__target_ip__' in playbook.get('playbook_variables', {}):
        playbook['playbook_variables']['__target_ip__']['value'] = attacker_ip

    # 3. Enviar a SOARCA para ejecución inmediata
    url = f"{SOARCA_API}/trigger/playbook"
    try:
        response = requests.post(url, json=playbook, timeout=10)
        if response.status_code == 200:
            logger.info(f"✅ Playbook ejecutado: {attacker_ip} bloqueado en {victim_ip}")
        else:
            logger.warning(f"⚠️ SOARCA respondió {response.status_code}: {response.text[:300]}")
    except Exception as e:
        logger.error(f"❌ Error contactando SOARCA: {e}")


def resolve_lab_victim_ip() -> str | None:
    try:
        return socket.gethostbyname(LAB_VICTIM_HOST)
    except Exception as e:
        logger.error(f"❌ No se pudo resolver host de víctima de laboratorio '{LAB_VICTIM_HOST}': {e}")
        return None


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
        response = requests.post(url, json=playbook, timeout=10)
        if response.status_code == 200:
            logger.info(f"✅ Playbook de aislamiento ejecutado en {victim_ip}")
            LAST_ISOLATION_BY_VICTIM[victim_ip] = now
        else:
            logger.warning(f"⚠️ SOARCA respondió {response.status_code} (aislamiento): {response.text[:300]}")
    except Exception as e:
        logger.error(f"❌ Error contactando SOARCA para aislamiento: {e}")


def fetch_candidate_events(headers, date_from):
    queries = [
        ("tag pmp-auto-aggregation", f"{MISP_URL}/events/index/searchTag:pmp-auto-aggregation/searchDatefrom:{date_from}"),
        ("fallback recent events", f"{MISP_URL}/events/index/searchDatefrom:{date_from}"),
    ]

    merged_events = {}

    for label, url in queries:
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

    return list(merged_events.values())


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
            logger.info("No hay eventos nuevos candidatos en MISP.")
            return

        processed = load_processed_events()

        # Filtrar por timestamp: solo eventos de las últimas 2 horas
        import time as _time
        min_ts = _time.time() - (2 * 3600)

        for ev_summary in events_index:
            ev_ts = int(ev_summary.get('timestamp', 0))
            event_id = str(ev_summary.get('id', ''))
            event_info = ev_summary.get('info', '')

            if ev_ts < min_ts and event_id not in processed:
                save_processed_event(event_id)
                continue
            if event_id in processed:
                continue

            is_network_event = (
                event_info.startswith("Distributed Password Spraying")
                or event_info.startswith("NETWORK IDS:")
                or event_info.startswith("SNORT:")
            )
            is_ransomware_falco = (
                event_info.startswith("FALCO:")
                and "novadef" in event_info.lower()
                and "ransomware" in event_info.lower()
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
                victim_ip = resolve_lab_victim_ip()
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
                r_attrs = requests.post(
                    f"{MISP_URL}/attributes/restSearch",
                    json={"eventid": event_id, "returnFormat": "json", "limit": 50},
                    headers=headers, verify=False, timeout=15
                )
                if r_attrs.status_code == 200:
                    attrs_data = extract_attributes_from_restsearch(r_attrs.json())
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
                else:
                    logger.debug(f"attributes/restSearch respondió {r_attrs.status_code}, usando fallback")
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

            victim_ip = victim_ips[0]
            mapping = D3FEND_MAPPING["network_password_spraying"]
            logger.info(
                "🧭 Selección defensiva MITRE D3FEND: %s | ATT&CK=%s | playbook=%s",
                ",".join(mapping["d3fend"]),
                ",".join(mapping["attack"]),
                mapping["playbook"],
            )
            for ip in set(attacker_ips):
                trigger_soarca_playbook(ip, victim_ip, event_info)
            save_processed_event(event_id)

    except Exception as e:
        logger.error(f"Falla durante la búsqueda en MISP: {e}")

if __name__ == "__main__":
    logger.info("Integrador MISP -> SOARCA Iniciado.")
    # Cada minuto mira si MISP ha publicado un ataque nuevo para actuar.
    schedule.every(1).minutes.do(check_misp_for_new_threats)
    
    # Ejecuta una vez al arrancar
    check_misp_for_new_threats()
    
    while True:
        schedule.run_pending()
        time.sleep(1)
