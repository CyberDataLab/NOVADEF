#!/bin/bash

###############################################################################
# NOVADEF Completo v2 - Build ALL Modules + Launch All Services
# Estrategia: Construir todas las imágenes Docker primero, luego usar PMP Launcher
###############################################################################

set -e

NOVADEF_ROOT="/Users/pedrobeltranlopez/Desktop/NOVADEF"
cd "$NOVADEF_ROOT"

export PFD="$NOVADEF_ROOT/PMP"
GUI_PORT=18080
GUI_DIR="$NOVADEF_ROOT/NOVADEF_GUI"
GUI_CONTAINER_NAME="novadef-gui-hub"

start_gui_hub() {
    mkdir -p "$GUI_DIR"
    docker rm -f "$GUI_CONTAINER_NAME" >/dev/null 2>&1 || true
    docker run -d \
        --name "$GUI_CONTAINER_NAME" \
        --network launcher_default \
        -p "${GUI_PORT}:80" \
        -v "${GUI_DIR}:/usr/share/nginx/html:ro" \
        --restart unless-stopped \
        nginx:alpine >/dev/null
}

ensure_launcher_network() {
    if ! docker network inspect launcher_default >/dev/null 2>&1; then
        echo "🔗 Creando red compartida launcher_default..."
        docker network create launcher_default >/dev/null
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

echo ""
echo "✅ Todas las imágenes personalizadas construidas"
echo ""

# ============================================================================
# FASE 2: INICIAR SCENARIO
# ============================================================================

echo ""
echo "🎭 FASE 2: Iniciando Scenario (máquinas víctima y atacante)..."
ensure_launcher_network
cd "$NOVADEF_ROOT/Scenario"

docker-compose up -d
wait_for_container_pattern "scenario_victim .*Up" 120 "scenario_victim"
wait_for_container_pattern "scenario_attacker .*Up" 120 "scenario_attacker"
echo "✅ Scenario iniciado"

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
wait_for_container_pattern "flow_module_novadef .*Up" 1800 "Flow Module"
echo "✅ PMP iniciado y contenedores activos"

# ============================================================================
# FASE 4: INICIAR TAPCD
# ============================================================================

echo ""
echo "📈 FASE 4: Iniciando TAPCD (análisis con Neo4j)..."
ensure_launcher_network
cd "$NOVADEF_ROOT/TAPCD"

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

bash start.sh
sleep 30

echo "✅ MISP iniciado"

# ============================================================================
# FASE 6: INICIAR SOARCA
# ============================================================================

echo ""
echo "🎯 FASE 6: Iniciando SOARCA (orquestación de respuesta)..."
ensure_launcher_network
cd "$NOVADEF_ROOT/SOARCA"

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
start_gui_hub
sleep 1
echo "✅ GUI Hub iniciado"

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
echo "  • GUI Hub NOVADEF:   http://localhost:${GUI_PORT}/index.html"
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
