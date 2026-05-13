#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
profiles_out → Kafka Consumer → Neo4j upsert

Logging minimal con iconos por mensaje:
  📥 recibido
  ✉️ mensaje (payload Kafka tal cual)
  🧮 parseado
  🗂️ params listos
  🔁 upsert
  ✅ hecho
  ⚠️ ignorado (si no se puede procesar)

Sin logs verbosos de arranque/cierre ni durante el schema apply.
"""

import argparse, csv, io, logging, re, signal, sys, time
import os
from typing import Dict, List, Optional

from kafka import KafkaConsumer
from neo4j import GraphDatabase

# ───────────────────── Logger silencioso global ─────────────────────
LOG = logging.getLogger("profiles->neo4j")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))  # sin metadatos técnicos
LOG.handlers.clear()
LOG.addHandler(_handler)
LOG.setLevel(logging.INFO)

def wait_for_service(label: str, factory, validator=None, timeout_sec: Optional[float] = None,
                     retry_sec: Optional[float] = None):
    timeout = timeout_sec or float(os.getenv("STARTUP_MAX_WAIT_SEC", "180"))
    delay = retry_sec or float(os.getenv("STARTUP_RETRY_SEC", "5"))
    deadline = time.monotonic() + timeout
    attempt = 0
    last_exc = None

    while time.monotonic() < deadline:
        attempt += 1
        resource = None
        try:
            resource = factory()
            if validator is not None:
                validator(resource)
            return resource
        except Exception as exc:
            last_exc = exc
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
            print(f"⏳ Esperando {label} (intento {attempt})", flush=True)
            time.sleep(delay)

    raise RuntimeError(f"No fue posible conectar con {label}: {last_exc}")

# Señal de parada
STOP = False
def handle_stop(signum, frame):
    global STOP
    STOP = True
for _sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(_sig, handle_stop)

# ─────────── Utilidades CSV (payloads de profiles_out) ───────────
def robust_decode(b: bytes, enc: str = "utf-8") -> str:
    """UTF-8 con fallback latin-1; quita BOM si existe."""
    try:
        s = b.decode(enc)
    except Exception:
        s = b.decode("latin-1", errors="replace")
    if s.startswith("\ufeff"):
        s = s.lstrip("\ufeff")
    return s

def parse_csv_row(text: str) -> Dict[str, str]:
    """Lee CSV con cabecera y devuelve la última fila como dict."""
    text = (text or "").strip()
    if not text:
        return {}
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return {}
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows = list(reader)
    return rows[-1] if rows else {}

def split_multi(v: Optional[str]) -> List[str]:
    if not v:
        return []
    return [t for t in re.split(r"[;,\s]+", str(v)) if t]

# ─────────── Schema de Neo4j (silencioso) ───────────
MARK_QUERY  = "MERGE (:Meta {key:'schema_applied'}) RETURN 1"
CHECK_QUERY = "MATCH (:Meta {key:'schema_applied'}) RETURN 1 LIMIT 1"

def _strip_comments_and_split(cypher: str) -> List[str]:
    cypher = re.sub(r"/\*.*?\*/", "", cypher, flags=re.S)
    cypher = re.sub(r"//.*?$", "", cypher, flags=re.M)
    stmts = [s.strip() for s in cypher.split(";")]
    return [s for s in stmts if s]

def apply_schema_if_needed(driver, schema_path: str, force: bool = False):
    """Aplica índices/constraints una vez; sin logs intermedios."""
    with driver.session() as s:
        if not force:
            try:
                if s.run(CHECK_QUERY).single():
                    return
            except Exception:
                pass
        with open(schema_path, "r", encoding="utf-8") as f:
            cypher = f.read()
        for stmt in _strip_comments_and_split(cypher):
            try:
                s.run(stmt).consume()
            except Exception:
                pass
        try:
            s.run(MARK_QUERY).consume()
        except Exception:
            pass

# ─────────── Upsert en Neo4j para cada fila de profiles_out ───────────
CYPHER_UPSERT = """
MERGE (a:Actor {id: $Id})
SET a.firstSeen = $FirstSeen,
    a.lastActivity = $LastActivity,
    a.country = $Country,
    a.automationLevel = $AutomationLevel,
    a.riskLevel = $RiskLevel,
    a.profile = $Profile,
    a.motivation = $Motivation,
    a.knowledge = $Knowledge,
    a.attitude = $Attitude,
    a.affiliation = $Affiliation,
    a.skills = $Skills,
    a.comments = $Comments
WITH a, $Target AS target, $PreferredTarget AS preferred,
     $TTPs AS ttps, $Evasions AS evasions, $Phases AS phases,
     $IPs AS src_ips, $SourceIdentity AS src_identity
MERGE (t:Target {ip: target})
MERGE (a)-[:TARGETS]->(t)
// Orígenes (pueden venir múltiples IPs)
FOREACH (ip IN CASE WHEN src_ips IS NULL OR size(src_ips)=0 THEN [] ELSE src_ips END |
  MERGE (s:SourceIP {ip: ip})
  SET s.identity = coalesce(src_identity, s.identity)
  MERGE (a)-[:ORIGINATES_FROM]->(s)
)
WITH a, ttps, evasions, phases, preferred
FOREACH (ip IN CASE WHEN preferred IS NULL OR preferred = '' THEN [] ELSE split(preferred,';') END |
  MERGE (pt:Target {ip: ip})
  MERGE (a)-[:PREFERS]->(pt)
)
WITH a, ttps, evasions, phases
FOREACH (tech IN ttps |
  MERGE (x:Technique {id: tech})
  MERGE (a)-[:USES]->(x)
)
WITH a, evasions, phases
FOREACH (ev IN evasions |
  MERGE (e:Evasion {name: ev})
  MERGE (a)-[:EVADE_WITH]->(e)
)
WITH a, phases
FOREACH (ph IN phases |
  MERGE (k:KillChainPhase {name: ph})
  MERGE (a)-[:IN_PHASE]->(k)
)
"""

def build_params(row: Dict[str, str]) -> Dict[str, object]:
    """Mapea campos CSV a parámetros para Cypher; listas normalizadas."""
    return {
        "Id": row.get("Id") or row.get("id") or "",
        "FirstSeen": row.get("FirstSeen"),
        "LastActivity": row.get("LastActivity"),
        "Country": row.get("Country"),
        "AutomationLevel": row.get("AutomationLevel"),
        "RiskLevel": row.get("RiskLevel"),
        "Profile": row.get("Profile"),
        "Motivation": row.get("Motivation"),
        "Knowledge": row.get("Knowledge"),
        "Attitude": row.get("Attitude"),
        "Affiliation": row.get("Affiliation"),
        "Skills": row.get("Skills"),
        "Comments": row.get("Comments"),
        "Target": (row.get("Target") or ""),
        "PreferredTarget": row.get("PreferredTarget"),
        "TTPs": split_multi(row.get("TTPs")),
        "Evasions": split_multi(row.get("Evasion")),
        "Phases": split_multi(row.get("KillChainPhase")),
        # NUEVO: lista de IPs de origen y una identidad opcional
        # (en profiles_out la columna se llama "IPs"; identidad, si la emites, puede venir como "SourceIdentity" o "Identity")
        "IPs": split_multi(row.get("IPs")),
        "SourceIdentity": row.get("SourceIdentity") or row.get("Identity") or None,
    }

def consume_and_write(bootstrap: str, topic: str, uri: str, user: str, pwd: str,
                      schema_path: str, force_schema: bool, group_id: str):
    """Consume perfiles de Kafka y upsert en Neo4j con logs concisos+payload."""
    # Conexión Neo4j
    try:
        def make_driver():
            return GraphDatabase.driver(uri, auth=(user, pwd))

        def validate_driver(driver):
            driver.verify_connectivity()

        driver = wait_for_service("Neo4j", make_driver, validate_driver)
    except Exception:
        print("❌ No se pudo conectar a Neo4j", flush=True)
        raise

    # Schema una vez (silencioso)
    try:
        apply_schema_if_needed(driver, schema_path=schema_path, force=force_schema)
    except Exception:
        print("❌ Fallo aplicando el esquema de Neo4j", flush=True)
        raise

    # Consumer Kafka
    try:
        def make_consumer():
            return KafkaConsumer(
                topic,
                bootstrap_servers=bootstrap,
                group_id=group_id,
                auto_offset_reset="latest",
                enable_auto_commit=True,
                value_deserializer=lambda v: v,  # bytes crudos
                key_deserializer=lambda v: v,
            )

        def validate_consumer(consumer):
            if not consumer.bootstrap_connected():
                raise RuntimeError("Kafka consumer sin brokers disponibles")

        consumer = wait_for_service("Kafka consumer", make_consumer, validate_consumer)
    except Exception:
        print("❌ No se pudo crear el consumer de Kafka", flush=True)
        driver.close()
        raise

    try:
        with driver.session() as session:
            for msg in consumer:
                if STOP:
                    break
                try:
                    raw = robust_decode(msg.value)

                    # 📥 recibido + ✉️ mensaje (payload completo)
                    LOG.info("📥 Recibido")
                    print(f"✉️ {raw}", flush=True)

                    row = parse_csv_row(raw)
                    if not row:
                        LOG.info("⚠️ Ignorado")
                        continue
                    LOG.info("🧮 Parseado")

                    params = build_params(row)
                    if not params["Id"] or not params["Target"]:
                        LOG.info("⚠️ Ignorado")
                        continue
                    LOG.info("🗂️ Params listos")

                    session.execute_write(lambda tx: tx.run(CYPHER_UPSERT, **params))
                    LOG.info("🔁 Upsert")
                    LOG.info("✅ Hecho")
                except Exception:
                    LOG.info("⚠️ Ignorado")
                    continue
                if STOP:
                    break
    finally:
        try:
            consumer.close()
        except Exception:
            pass
        try:
            driver.close()
        except Exception:
            pass
        # Sin logs de cierre para mantenerlo limpio

def main():
    ap = argparse.ArgumentParser("Consume profiles_out y upsert en Neo4j")
    ap.add_argument("--bootstrap", required=True, help="Kafka bootstrap, p.ej. localhost:9092")
    ap.add_argument("--topic", default="profiles_out")
    ap.add_argument("--group-id", default="profiles_to_neo4j")
    ap.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    ap.add_argument("--neo4j-user", default="neo4j")
    ap.add_argument("--neo4j-pass", default="neo4jpass")
    ap.add_argument("--schema", default="neo4j_schema.cypher", help="Ruta al .cypher de índices/constraints")
    ap.add_argument("--force-schema", action="store_true", help="Forzar re-aplicar schema")
    args = ap.parse_args()

    consume_and_write(
        bootstrap=args.bootstrap,
        topic=args.topic,
        uri=args.neo4j_uri,
        user=args.neo4j_user,
        pwd=args.neo4j_pass,
        schema_path=args.schema,
        force_schema=args.force_schema,
        group_id=args.group_id,
    )

if __name__ == "__main__":
    main()
