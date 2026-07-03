#!/bin/bash

###############################################################################
# NOVADEF Completo v2 - Build ALL Modules + Launch All Services
# Estrategia: Construir todas las imágenes Docker primero, luego usar PMP Launcher
###############################################################################

set -e

NOVADEF_ROOT="/Users/pedrobeltranlopez/Desktop/NOVADEF"
cd "$NOVADEF_ROOT"

export PFD="$NOVADEF_ROOT/PMP"
GUI_DIR="$NOVADEF_ROOT/NOVADEF_GUI"
DOZZLE_PORT=18081
DOZZLE_CONTAINER_NAME="novadef-log-hub"
EXPERIMENTS_API_PORT=18082
EXPERIMENTS_API_IMAGE="novadef-experiments-api:latest"
EXPERIMENTS_API_CONTAINER="novadef-experiments-api"

start_log_hub() {
    docker rm -f "$DOZZLE_CONTAINER_NAME" >/dev/null 2>&1 || true
    docker run -d \
        --name "$DOZZLE_CONTAINER_NAME" \
        --network launcher_default \
        -p "${DOZZLE_PORT}:8080" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --restart unless-stopped \
        amir20/dozzle:latest >/dev/null
}

AUTH_DB_CONTAINER="novadef-auth-db"
AUTH_DB_PASSWORD="novadef_pass"
AUTH_DB_USER="novadef"
AUTH_DB_NAME="novadef_auth"

start_auth_db() {
    if docker ps --format '{{.Names}}' | grep -q "^${AUTH_DB_CONTAINER}$"; then
        echo "  ℹ️  Auth DB ya está corriendo"
        return 0
    fi
    docker rm -f "$AUTH_DB_CONTAINER" >/dev/null 2>&1 || true
    docker run -d \
        --name "$AUTH_DB_CONTAINER" \
        --network launcher_default \
        -e POSTGRES_USER="$AUTH_DB_USER" \
        -e POSTGRES_PASSWORD="$AUTH_DB_PASSWORD" \
        -e POSTGRES_DB="$AUTH_DB_NAME" \
        -v "$NOVADEF_ROOT/NOVADEF_GUI/api/db-init:/docker-entrypoint-initdb.d:ro" \
        --restart unless-stopped \
        postgres:16-alpine >/dev/null
    echo "  ⏳ Esperando Auth DB PostgreSQL..."
    local elapsed=0
    while [ "$elapsed" -lt 30 ]; do
        if docker exec "$AUTH_DB_CONTAINER" pg_isready -U "$AUTH_DB_USER" >/dev/null 2>&1; then
            echo "  ✅ Auth DB lista"
            return 0
        fi
        sleep 2; elapsed=$((elapsed + 2))
    done
    echo "  ⚠️  Auth DB no respondió en 30s — continuando de todas formas"
}

start_experiments_api() {
    docker build -t "$EXPERIMENTS_API_IMAGE" "$NOVADEF_ROOT/NOVADEF_GUI" -f "$NOVADEF_ROOT/NOVADEF_GUI/api/Dockerfile" >/dev/null
    docker rm -f "$EXPERIMENTS_API_CONTAINER" >/dev/null 2>&1 || true
    mkdir -p "$NOVADEF_ROOT/.novadef_runtime"
    chmod 777 "$NOVADEF_ROOT/.novadef_runtime"
    rm -f "$NOVADEF_ROOT/.novadef_runtime/gui_runtime_state.json" >/dev/null 2>&1 || true
    docker run -d \
        --name "$EXPERIMENTS_API_CONTAINER" \
        --network launcher_default \
        -p "${EXPERIMENTS_API_PORT}:18082" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$NOVADEF_ROOT/.novadef_runtime:/runtime" \
        -e NOVADEF_HOST_ROOT="$NOVADEF_ROOT" \
        -e NOVADEF_SCENARIO_TOOLS_ROOT="$NOVADEF_ROOT" \
        -e NOVADEF_GUI_RUNTIME_STATE_FILE=/runtime/gui_runtime_state.json \
        -e EXPERIMENT_STABILITY_PROBE_INTERVAL_SECONDS=1 \
        -e EXPERIMENT_STABILITY_MAX_DELTA_PACKETS=500 \
        -e EXPERIMENT_STABILITY_REQUIRED_WINDOWS=2 \
        -e EXPERIMENT_STABILITY_MAX_WAIT_SECONDS=10 \
        -e EXPERIMENT_REQUIRE_MISP_ENRICH_FOR_ACT=0 \
        -e EXPERIMENT_REQUIRE_MISP_FOR_FINAL_REPORT=0 \
        -e EXP1_FAST_COUNTERMEASURE_ENABLED=1 \
        -e NOVADEF_DB_URL="postgresql://${AUTH_DB_USER}:${AUTH_DB_PASSWORD}@${AUTH_DB_CONTAINER}:5432/${AUTH_DB_NAME}" \
        -e NOVADEF_START_SCRIPT=/novadef/start_novadef_complete.sh \
        -v "$NOVADEF_ROOT:/novadef:ro" \
        --restart unless-stopped \
        "$EXPERIMENTS_API_IMAGE" >/dev/null
}

purge_misp_state() {
    echo "  🧹 Purgeando eventos y estado persistente de MISP..."
    docker exec pmp-misp-db sh -lc '
        mysql -uroot -pmy_root_password misp -e "
            SET FOREIGN_KEY_CHECKS=0;
            TRUNCATE TABLE attributes;
            TRUNCATE TABLE shadow_attributes;
            TRUNCATE TABLE event_tags;
            TRUNCATE TABLE sightings;
            TRUNCATE TABLE object_references;
            TRUNCATE TABLE objects;
            TRUNCATE TABLE event_reports;
            TRUNCATE TABLE cryptographic_keys;
            TRUNCATE TABLE logs;
            TRUNCATE TABLE correlations;
            TRUNCATE TABLE default_correlations;
            TRUNCATE TABLE no_acl_correlations;
            TRUNCATE TABLE shadow_attribute_correlations;
            TRUNCATE TABLE events;
            SET FOREIGN_KEY_CHECKS=1;"
    ' >/dev/null 2>&1 || true
}

ensure_launcher_network() {
    if ! docker network inspect launcher_default >/dev/null 2>&1; then
        echo "🔗 Creando red compartida launcher_default..."
        docker network create launcher_default >/dev/null
    fi
}

reset_kafka_state() {
    local kafka_volume=""
    echo "  🧹 Reiniciando estado Kafka para un arranque limpio..."
    kafka_volume="$(docker inspect kafka_novadef --format '{{range .Mounts}}{{if eq .Destination "/var/lib/kafka/data"}}{{.Name}}{{end}}{{end}}' 2>/dev/null || true)"
    docker rm -f kafka_novadef >/dev/null 2>&1 || true
    if [ -n "$kafka_volume" ]; then
        docker volume rm -f "$kafka_volume" >/dev/null 2>&1 || true
    fi
}

wait_for_container_pattern() {
    local pattern="$1"
    local timeout="${2:-300}"
    local description="$3"
    local elapsed=0

    echo "  ⏳ Esperando ${description} (${timeout}s máx.)..."
    while [ "$elapsed" -lt "$timeout" ]; do
        if docker ps --format '{{.Names}} {{.Status}}' | grep -E "$pattern" >/dev/null 2>&1; then
            echo "  ✅ ${description}"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    echo "  ⚠️  Timeout esperando ${description}"
    return 1
}

ensure_kafka_topic() {
    local topic="$1"
    local timeout="${2:-120}"
    local elapsed=0
    echo "  ⏳ Asegurando topic Kafka '${topic}'..."
    while [ "$elapsed" -lt "$timeout" ]; do
        if docker exec kafka_novadef sh -lc "/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic ${topic} --partitions 1 --replication-factor 1" >/dev/null 2>&1; then
            echo "  ✅ Topic '${topic}' disponible"
            return 0
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done
    echo "  ⚠️  No se pudo asegurar el topic '${topic}' en ${timeout}s"
    return 1
}

echo "════════════════════════════════════════════════════════════"
echo "🚀 NOVADEF Completo - Build All + Full Initialization"
echo "════════════════════════════════════════════════════════════"
echo ""

# ============================================================================
# FASE 1: CONSTRUIR TODAS LAS IMÁGENES PERSONALIZADAS
# ============================================================================

echo "📦 FASE 1: Construyendo imágenes Docker personalizadas..."
echo ""

ensure_launcher_network

# Kafka is the critical backbone; start it from a clean state so KRaft recovery
# does not drag stale metadata across launches in the lab.
reset_kafka_state

# Directorio de Data Collection
cd "$PFD/Data_Collection_Module/Docker"

echo "  [1/5] Construyendo fluentd_novadef:latest..."
if docker build -t fluentd_novadef:latest -f Dockerfiles/fluentd.dockerfile "$PFD" 2>&1 | grep -E "(Successfully|error|Error)" | tail -1; then
    echo "       ✅ fluentd_novadef construido"
fi

echo "  [2/5] Construyendo tshark_novadef:latest..."
if docker build -t tshark_novadef:latest -f Dockerfiles/tshark.dockerfile "$PFD" 2>&1 | grep -E "(Successfully|error|Error)" | tail -1; then
    echo "       ✅ tshark_novadef construido"
fi

echo "  [3/5] Construyendo falco_novadef:latest..."
if docker build -t falco_novadef:latest -f Dockerfiles/falco.dockerfile "$PFD" 2>&1 | grep -E "(Successfully|error|Error)" | tail -1; then
    echo "       ✅ falco_novadef construido"
fi

echo "  [4/5] Construyendo device_info_novadef:latest..."
if docker build -t device_info_novadef:latest -f Dockerfiles/device_info.dockerfile "$PFD" 2>&1 | grep -E "(Successfully|error|Error)" | tail -1; then
    echo "       ✅ device_info_novadef construido"
fi

# Alert Module
cd "$PFD/Alert_Module/Docker"
echo "  [5/5] Construyendo alert_module:latest..."
if docker build -t alert_module:latest -f Dockerfiles/alert_module.dockerfile "$PFD" 2>&1 | grep -E "(Successfully|error|Error)" | tail -1; then
    echo "       ✅ alert_module construido"
fi

# Alert Manager
cd "$PFD/Alert_Manager/Docker"
echo "  [6/6] Construyendo alert_manager_novadef:latest..."
if docker build -t alert_manager_novadef:latest -f Dockerfiles/alert_manager.dockerfile "$PFD" 2>&1 | grep -E "(Successfully|error|Error)" | tail -1; then
    echo "       ✅ alert_manager_novadef construido"
fi

echo ""
echo "✅ Todas las imágenes personalizadas construidas"
echo ""

# ============================================================================
# FASE 2: SCENARIO ON DEMAND
# ============================================================================

echo ""
echo "🎭 FASE 2: Scenario on demand"
echo "  ℹ️  No se arranca ningún escenario por defecto."
echo "  ℹ️  Cada experimento creará su propia víctima y atacante al lanzarse desde la GUI/API."
echo "✅ Scenario configurado para creación bajo demanda"

# ============================================================================
# FASE 3: INICIAR PMP CON EL LAUNCHER PYTHON
# ============================================================================

echo ""
echo "🔧 FASE 3: Iniciando PMP (Monitoring Platform)..."
ensure_launcher_network
cd "$PFD/Launcher"

echo "  Esperando 5 segundos antes de lanzar PMP..."
sleep 5

# Usar el launcher Python para iniciar PMP con TODOS los módulos
echo "  Lanzando: python3 start_containers.py all"
python3 start_containers.py all &
PMP_PID=$!

echo "  PID del launcher PMP: $PMP_PID"
echo "  ⏳ Esperando a que PMP se estabilice con comprobaciones reales..."
wait_for_container_pattern "kafka_novadef .*healthy" 1800 "Kafka healthy"
wait_for_container_pattern "mongodb_novadef .*Up" 1800 "MongoDB"
wait_for_container_pattern "alert_module_novadef .*Up" 1800 "Alert Module"
wait_for_container_pattern "alert_manager_novadef .*Up" 1800 "Alert Manager"
wait_for_container_pattern "flow_module_novadef .*Up" 1800 "Flow Module"
ensure_kafka_topic "network_auth_events" 180 || true
ensure_kafka_topic "network_intrusion_alerts" 180 || true
ensure_kafka_topic "snort_alerts" 180 || true
ensure_kafka_topic "pmp_alerts" 180 || true
ensure_kafka_topic "snort_alerts_am" 180 || true
echo "✅ PMP iniciado y contenedores activos"

# ============================================================================
# FASE 4: INICIAR TAPCD
# ============================================================================

echo ""
echo "📈 FASE 4: Iniciando TAPCD (análisis con Neo4j)..."
ensure_launcher_network
cd "$NOVADEF_ROOT/TAPCD"

echo "  🧹 Limpiando datos persistentes de Neo4j..."
docker rm -f neo4j >/dev/null 2>&1 || true
docker volume rm -f novadef_neo4j_data >/dev/null 2>&1 || true

docker compose up -d --build
sleep 45

echo "✅ TAPCD iniciado"

# ============================================================================
# FASE 5: INICIAR MISP
# ============================================================================

echo ""
echo "🔍 FASE 5: Iniciando MISP (inteligencia de amenazas)..."
ensure_launcher_network
cd "$NOVADEF_ROOT/MISP"

docker rm -f pmp-misp-integrator >/dev/null 2>&1 || true
bash start.sh
sleep 30
docker exec pmp-misp-integrator sh -lc "rm -f /app/state/misp_dedup_state.json" >/dev/null 2>&1 || true

echo "✅ MISP iniciado"
purge_misp_state

# ============================================================================
# FASE 6: INICIAR SOARCA
# ============================================================================

echo ""
echo "🎯 FASE 6: Iniciando SOARCA (orquestación de respuesta)..."
ensure_launcher_network
cd "$NOVADEF_ROOT/SOARCA"

echo "  🧹 Limpiando estado persistente de SOARCA trigger..."
docker rm -f pmp-misp-soarca-trigger pmp-soarca-core pmp-soarca-executor-ssh pmp-soarca-db >/dev/null 2>&1 || true
docker volume rm -f soarca_trigger_state >/dev/null 2>&1 || true

docker-compose up -d
sleep 45

echo "✅ SOARCA iniciado"

# ============================================================================
# FASE 7: INICIAR GRAFANA
# ============================================================================

echo ""
echo "📊 FASE 7: Iniciando Grafana (visualización)..."
ensure_launcher_network
cd "$NOVADEF_ROOT/Grafana"

docker-compose up -d
sleep 30

echo "✅ Grafana iniciado"

# ============================================================================
# FASE 8: INICIAR GUI HUB
# ============================================================================

echo ""
echo "🧭 FASE 8: Iniciando GUI Hub de NOVADEF..."
start_log_hub
start_auth_db
start_experiments_api
sleep 1
echo "✅ GUI Hub, Auth DB y Log Hub iniciados"

# ============================================================================
# RESUMEN FINAL
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ NOVADEF COMPLETAMENTE INICIADO"
echo "════════════════════════════════════════════════════════════"
echo ""

echo "📊 Servicios disponibles:"
echo "  • Prometheus (PMP):  http://localhost:9090"
echo "  • OpenSearch (PMP):  http://localhost:9200"
echo "  • Kafka (PMP):       localhost:9092"
echo "  • MongoDB (PMP):     localhost:27017"
echo "  • Neo4j (TAPCD):     http://localhost:7474 (user: neo4j, pass: password)"
echo "  • MISP:              https://localhost:8443 (user: admin@admin.test, pass: admin)"
echo "  • SOARCA:            http://localhost:8000"
echo "  • Grafana:           http://localhost:3000"
echo "  • GUI NOVADEF:       http://localhost:${EXPERIMENTS_API_PORT}/login.html  (admin@novadef.local / novadef2024)"
echo "  • Docker Log Hub:    http://localhost:${DOZZLE_PORT}"
echo ""

echo "🔧 Contenedores activos:"
docker ps --format "table {{.Names}}\t{{.Status}}" | head -20

echo ""
echo "📝 Próximos pasos:"
echo "  1. Verificar que MISP está listo:  curl -k https://localhost:8443/attributes/statistics"
echo "  2. Verificar que SOARCA está listo: curl http://localhost:8000/health"
echo "  3. Lanzar ataques del escenario:    python3 Experiments/run_scenario_integrated_experiments.py"
echo "     La detección, MISP, TAPCD y SOARCA deben recorrer el flujo interno de NOVADEF"
echo ""
echo "🎯 Para monitorear en tiempo real:"
echo "  • tail -f novadef_startup.log"
echo "  • docker logs -f kafka_novadef"
echo "  • docker logs -f misp"
echo ""
