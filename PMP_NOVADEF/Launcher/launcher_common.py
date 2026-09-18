#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path


LAUNCHER_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAUNCHER_DIR.parent
LAUNCHER_ENV_FILE = LAUNCHER_DIR / ".env"
LAUNCHER_INIT_ENV_FILE = LAUNCHER_DIR / ".init_pmp_env"
INTERNAL_LOGS_DIR = REPO_ROOT / "Internal_logs"
RUNTIME_DIR = REPO_ROOT / ".runtime" / "bootstrap_pmp_backend"

BOOTSTRAP_LOG_FILE = INTERNAL_LOGS_DIR / "bootstrap_pmp_backend.log"
CONFIGURATION_MANAGER_LOG_FILE = INTERNAL_LOGS_DIR / "configuration_manager_api.log"

API_PID_FILE = RUNTIME_DIR / "configuration_manager_api.pid"
STATE_FILE = RUNTIME_DIR / "state.json"

CONFIGURATION_MANAGER_API_NAME = "configuration_manager_api"
NRTDR_API_NAME = "nrtdr_api"
NRTDR_API_CONTAINER_NAME = "nrtdr_api_novadef"
HDR_API_NAME = "hdr_api"
HDR_API_CONTAINER_NAME = "hdr_api_novadef"
DT_API_NAME = "dt_api"
DT_API_CONTAINER_NAME = "dt_api_novadef"

# NOTE: thingsboard_module is intentionally not ported — NOVADEF doesn't use
# ThingsBoard. alert_manager is NOVADEF-specific (TAPCD integration, not
# present in ROBUST-6G_PMP). Keep this in sync with start_containers.py's own
# MODULE_COMPOSE_FILES — both need to agree on what's deployable.
MODULE_COMPOSE_FILES = {
    "apis_module": [
        "APIs/rest_apis.yml",
    ],
    "communication_module": [
        "Communication_Bus/Docker/communication_bus_compose.yml",
    ],
    "alert_module": [
        "Alert_Module/Docker/alert_module_compose.yml",
    ],
    "alert_manager": [
        "Alert_Manager/Docker/alert_manager_compose.yml",
    ],
    "collection_module": [
        "Data_Collection_Module/Docker/data_collection_module_compose.yml",
    ],
    "flow_module": [
        "Flow_Module/Docker/flow_module_compose.yml",
    ],
    "db_module": [
        "Databases_module/Docker/db_module_compose.yml",
    ],
    "aggregation_module": [
        "Aggregation_Normalisation_Module/Docker/aggregation_normalisation_compose.yml",
    ],
}

BASE_CONTAINERS = [
    "kafka_novadef",
    "filebeat_novadef",
    "mongodb_novadef",
    "mongodb_cm_novadef",
    "postgres_gui_novadef",
    "redis_novadef",
    "redis_worker_novadef",
    "mimir_novadef",
    "prometheus_server_novadef",
    "opensearch_node_novadef",
]

API_TOOL_CONTAINERS = [
    "tshark_novadef",
    "device_info_novadef",
    "flow_module_novadef",
    "telegraf_novadef",
    "fluentd_novadef",
    "falco_novadef",
    "falco_exporter_novadef",
    "alert_module_novadef",
    "network_intrusion_detector_novadef",
    "alert_manager_novadef",
]

ASSOCIATED_CONTAINERS = [
    "discovery_agent_novadef", # This container is associated with Prometheus, but it is not an API tool itself
    "opensearch_dashboards_novadef", # This container is associated with OpenSearch, but it is not an API tool itself
    "logstash_novadef", # This container is associated with OpenSearch, but it is not an API tool itself
]


def ensure_runtime_directories(logs_dir: Path | None = None) -> Path:
    effective_logs_dir = logs_dir or INTERNAL_LOGS_DIR
    effective_logs_dir.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return effective_logs_dir
