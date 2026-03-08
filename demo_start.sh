#!/bin/bash

# ====================================================================
# Script de Lanzamiento Unificado: Demostración Activa NOVADEF
# ====================================================================

GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${YELLOW}🚀 Iniciando el Laboratorio Completo de NOVADEF 🚀${NC}"
echo -e "${BLUE}======================================================${NC}"

# ─────────────────────────────────────────────────────────────────
# 1. PMP — crea la red launcher_default y levanta sensores/Kafka/DBs
#    DEBE ir primero: todos los demás stacks usan esa red como external
#    NOTA: tshark puede fallar aquí porque scenario_victim aún no existe
#          (network_mode: container:scenario_victim). Se arranca en paso 2.
# ─────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────
# PRE: Construir imagen alert_module antes de levantar nada
#      La compilación de Snort3 necesita ~2GB RAM libres.
#      Si se hace con otros contenedores en marcha, Kafka muere por OOM.
# ─────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}[Pre] Preparando imagen alert_module (Snort3)...${NC}"
if ! docker image inspect alert_module_novadef:latest >/dev/null 2>&1; then
    echo -e "   🔨 Compilando Snort3 por primera vez (~5-10 min según CPU/RAM)..."
    DOCKER_BUILDKIT=0 docker build -t alert_module_novadef:latest \
        -f PMP/Alert_Module/Docker/Dockerfiles/alert_module.dockerfile \
        PMP/ 2>&1 | grep -E '^Step [0-9]|^Successfully built|ERROR|[Ee]rror compil' || true
    if docker image inspect alert_module_novadef:latest >/dev/null 2>&1; then
        echo -e "   ${GREEN}✅ alert_module_novadef construido${NC}"
    else
        echo -e "   ${RED}❌ Falló la compilación de Snort3. Revisa la RAM disponible (mín. 2GB libres).${NC}"
        exit 1
    fi
else
    echo -e "   ${GREEN}✅ alert_module_novadef ya existe (saltando compilación)${NC}"
fi

echo -e "\n${GREEN}[1/6] Levantando la PMP (Sensores, Kafka, Bases de Datos)...${NC}"
cd PMP
python3 ./Launcher/start_containers.py all 2>&1 | grep -v "^$" || true
cd ..
echo -e "${YELLOW}Esperando a que la red y Kafka se estabilicen (20s)...${NC}"
sleep 20

# opensearch-node arranca con network_mode:bridge (NETWORK_MODE=bridge en PMP .env)
# lo conectamos a launcher_default para que el integrador MISP pueda resolverlo por nombre
docker network connect launcher_default opensearch-node 2>/dev/null && \
    echo -e "   ${GREEN}✅ opensearch-node conectado a launcher_default${NC}" || \
    echo -e "   ${YELLOW}⚠️  opensearch-node ya estaba conectado o no existe${NC}"

# prometheus_server_novadef también arranca con network_mode:bridge
# lo arrancamos explícitamente (puede estar en "Created") y conectamos a launcher_default
docker start prometheus_server_novadef 2>/dev/null && \
    echo -e "   ${GREEN}✅ prometheus_server_novadef arrancado${NC}" || \
    echo -e "   ${YELLOW}⚠️  prometheus_server_novadef no pudo arrancar (comprobando)${NC}"
docker network connect launcher_default prometheus_server_novadef 2>/dev/null || true

# logstash arranca con network_mode:bridge → conectarlo a launcher_default
# para que resuelva kafka_novadef y opensearch-node por nombre DNS
docker network connect launcher_default logstash_novadef 2>/dev/null && \
    echo -e "   ${GREEN}✅ logstash_novadef conectado a launcher_default${NC}" || \
    echo -e "   ${YELLOW}⚠️  logstash_novadef ya estaba conectado o no existe${NC}"

# ─────────────────────────────────────────────────────────────────
# 2. ESCENARIO — después de PMP para que launcher_default ya exista
#    tshark usa network_mode:container:scenario_victim
#    Arrancamos scenario_victim primero y luego tshark
# ─────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}[2/6] Levantando el Escenario (Víctima y Atacante)...${NC}"
cd Scenario
docker compose up -d
cd ..
echo -e "${YELLOW}Esperando a que scenario_victim esté listo (10s)...${NC}"
sleep 10

# Arrancar tshark ahora que scenario_victim ya está corriendo
echo -e "   🦈 Arrancando tshark (depende de scenario_victim)..."
docker start tshark_novadef 2>/dev/null && echo -e "   ${GREEN}✅ tshark arrancado${NC}" || echo -e "   ${YELLOW}⚠️  tshark no pudo arrancar (revisar scenario_victim)${NC}"

# ─────────────────────────────────────────────────────────────────
# 3. TAPCD — Neo4j, ML, ingesta de grafos
# ─────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}[3/6] Levantando TAPCD (Neo4j, Machine Learning, Ingesta)...${NC}"
cd TAPCD
chmod +x launcher.sh
./launcher.sh
cd ..
echo -e "${YELLOW}Esperando a que Neo4j arranque (15s)...${NC}"
sleep 15

# ─────────────────────────────────────────────────────────────────
# 4. MISP — genera SSL automáticamente, espera y configura la API key
# ─────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}[4/6] Levantando MISP (Inteligencia de Amenazas)...${NC}"
cd MISP
chmod +x start.sh
./start.sh
cd ..

# ─────────────────────────────────────────────────────────────────
# 5. SOARCA — respuesta automatizada + carga del playbook block_ip
# ─────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}[5/6] Levantando SOARCA (Respuesta Automatizada)...${NC}"
cd SOARCA
DOCKER_BUILDKIT=0 docker compose up -d --build
cd ..
echo -e "${YELLOW}Esperando a que SOARCA arranque (20s)...${NC}"
sleep 20

# Cargar el playbook block_ip automáticamente
echo -e "   📋 Cargando playbook block_ip en SOARCA..."
PLAYBOOK_RESP=$(curl -s -X POST "http://localhost:8000/playbook/" \
    -H "Content-Type: application/json" \
    -d @SOARCA/playbooks/block_ip.json 2>/dev/null)
if echo "$PLAYBOOK_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print('   ✅ Playbook:', d.get('name','cargado'))" 2>/dev/null; then
    true
else
    echo -e "   ${YELLOW}⚠️  Playbook no cargado aún (SOARCA puede seguir iniciando)${NC}"
fi

# Reiniciar integradores para que tengan MISP completamente accesible
docker restart pmp-misp-integrator 2>/dev/null || true
docker restart pmp-misp-soarca-trigger 2>/dev/null || true

# Limpiar state file del trigger (evita que IDs de sesiones anteriores bloqueen nuevos eventos)
docker exec pmp-misp-soarca-trigger bash -c "> /app/state/processed_events.txt" 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────
# 6. GRAFANA — dashboards de observabilidad
# ─────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}[6/6] Levantando Grafana (Observabilidad)...${NC}"
cd Grafana
docker compose up -d
cd ..
sleep 5

# ─────────────────────────────────────────────────────────────────
# Resumen final
# ─────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}======================================================${NC}"
echo -e "${GREEN}✅ ¡Laboratorio NOVADEF desplegado con éxito!${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e ""
echo -e "  📊 Grafana:   ${YELLOW}http://localhost:3000${NC}  (admin / novadef_grafana)"
echo -e "  🧠 MISP:      ${YELLOW}https://localhost:8443${NC}  (admin@admin.test / admin)"
echo -e "  🔍 OpenSearch:${YELLOW}http://localhost:9200${NC}"
echo -e "  📈 Prometheus:${YELLOW}http://localhost:9090${NC}"
echo -e "  🕸️  Neo4j:    ${YELLOW}http://localhost:7474${NC}  (neo4j / neo4jpass)"
echo -e "  🤖 SOARCA:    ${YELLOW}http://localhost:8000${NC}"
echo -e ""
echo -e "💡 Para lanzar el ataque de demostración:"
echo -e "   ${RED}docker exec scenario_attacker nmap -sS -T4 -p 1-1000 scenario_victim${NC}"
echo -e "   ${RED}docker exec scenario_attacker hping3 -S -p 80 -c 500 scenario_victim${NC}"
echo -e "${BLUE}======================================================${NC}"
