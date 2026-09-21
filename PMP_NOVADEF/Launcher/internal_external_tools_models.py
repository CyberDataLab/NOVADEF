"""
internal_external_tools_models.py

Shared Pydantic models and environment-variable maps for the PMP stack.

This module centralizes the tool configuration schemas and shared defaults used
by both the Configuration Manager API and the Launcher layer.
"""

from pydantic import BaseModel
from typing import Any, Dict, Type


def model_defaults(model_class: Type[BaseModel]) -> Dict[str, str]:
    """Return the stringified default values for a Pydantic model."""
    return {
        key: str(value)
        for key, value in model_class().model_dump().items()
    }


def combine_model_defaults(*model_classes: Type[BaseModel]) -> Dict[str, str]:
    """Merge the defaults of multiple Pydantic models into a single dictionary."""
    merged_defaults: Dict[str, str] = {}
    for model_class in model_classes:
        merged_defaults.update(model_defaults(model_class))
    return merged_defaults


class TelegrafConfig(BaseModel):
    """Pydantic model for Telegraf configurable environment variables."""
    model_config = {"extra": "forbid"}

    ENABLE_TELEGRAF:                str = "1"
    TELEGRAF_TO_PROMETHEUS_PORT:    str = "9273"
    TELEGRAF_BASE_TOPIC:            str = "telegraf_metrics"
    TELEGRAF_GENERAL_INTERVAL:      str = "10s"


class TsharkConfig(BaseModel):
    """Pydantic model for Tshark configurable environment variables."""
    model_config = {"extra": "forbid"}

    TSHARK_BASE_TOPIC:              str = "tshark_traces"
    TSHARK_SIZE_LIMIT_ROTATION:     str = "31457280"
    TSHARK_INTERFACE:               str = "no_interface"
    # Comma-separated ports excluded from capture. Default 9274 skips the
    # Prometheus->Telegraf scrape traffic on Scenario/ victim hosts (~99% of
    # steady-state packets, unrelated to any attack) — see Scenario/telegraf.
    TSHARK_EXCLUDE_PORTS:            str = "9274"


class FluentdConfig(BaseModel):
    """Pydantic model for Fluentd configurable environment variables."""
    model_config = {"extra": "forbid"}

    ENABLE_FLUENTD:                 str = "1"
    FLUENTD_TO_PROMETHEUS_PORT:     str = "24231"
    FLUENTD_INTERNAL_PORT:          str = "24220"
    FLUENTD_FILE_SIZE_LIMIT:        str = "20971520"
    FLUENTD_SYSLOG_BASE_TOPIC:      str = "syslog_logs"
    FLUENTD_SYSTEMD_BASE_TOPIC:     str = "systemd_logs"


class FalcoConfig(BaseModel):
    """Pydantic model for Falco configurable environment variables."""
    model_config = {"extra": "forbid"}

    ENABLE_FALCO:                   str = "1"
    FALCO_BASE_TOPIC:               str = "falco_events"
    FALCO_SKIP_DRIVER_LOADER:       str = "1"
    FALCO_EXPORTER_PORT:            str = "9376"


class KafkaConfig(BaseModel):
    """Pydantic model for Kafka configurable environment variables."""
    model_config = {"extra": "forbid"}

    KAFKA_BOOTSTRAP:                str = "kafka_novadef-node1.lan:9094"
    KAFKA_LAN_HOSTNAME:             str = "kafka_novadef-node1.lan"
    KAFKA_PORT_EXTERNAL_LAN:        str = "9094"
    KAFKA_PORT_INTERNAL:            str = "29092"
    KAFKA_LOG_RETENTION_MS:         str = "86400000"
    KAFKA_LOG_RETENTION_BYTES:      str = "1073741824"
    KAFKA_LOG_CLEANUP_POLICY:       str = "delete"
    KAFKA_LOG_SEGMENT_BYTES:        str = "268435456"
    KAFKA_LOG_ROLL_MS:              str = "3600000"


class FilebeatConfig(BaseModel):
    """Pydantic model for Filebeat configurable environment variables."""
    model_config = {"extra": "forbid"}

    FILEBEAT_BULK_MAX_SIZE:         str = "4096"
    FILEBEAT_COMPRESION:            str = "lz4"
    FLUENTD_SYSLOG_BASE_TOPIC:      str = FluentdConfig.model_fields["FLUENTD_SYSLOG_BASE_TOPIC"].default
    FLUENTD_SYSTEMD_BASE_TOPIC:     str = FluentdConfig.model_fields["FLUENTD_SYSTEMD_BASE_TOPIC"].default
    TSHARK_BASE_TOPIC:              str = TsharkConfig.model_fields["TSHARK_BASE_TOPIC"].default
    FALCO_BASE_TOPIC:               str = FalcoConfig.model_fields["FALCO_BASE_TOPIC"].default

class MimirConfig(BaseModel):
    """Pydantic model for Grafana Mimir historical storage configuration."""
    model_config = {"extra": "forbid"}

    MIMIR_HOST:                              str = "mimir_novadef-node1.lan"
    MIMIR_PORT:                              str = "8080"

class InfoConfig(BaseModel):
    """Pydantic model for device-info configurable environment variables."""
    model_config = {"extra": "forbid"}

    DEVICE_INFO_PORT:               str = "9999"
    DEVICE_INFO_PROBE_TIMEOUT:      str = "2"
    DEVICE_INFO_REFRESH_INTERVAL:   str = "15"
    TELEGRAF_PROBE_HOST:            str = "telegraf"
    FLUENTD_PROBE_HOST:             str = "fluentd"
    FALCO_PROBE_HOST:               str = "falco-exporter"

class PrometheusConfig(BaseModel):
    """Pydantic model for Prometheus configurable environment variables."""
    model_config = {"extra": "forbid"}

    PROMETHEUS_PORT:                    str = "9090"
    DISCOVERY_AGENT_SCAN_PORT:          str = InfoConfig.model_fields["DEVICE_INFO_PORT"].default
    DISCOVERY_AGENT_SCAN_TIMEOUT:       str = "0.2"
    DISCOVERY_AGENT_REFRESH_INTERVAL:   str = "10"
    DISCOVERY_AGENT_PORT:               str = "8100"
    MIMIR_HOST:                         str = MimirConfig.model_fields["MIMIR_HOST"].default
    MIMIR_PORT:                         str = MimirConfig.model_fields["MIMIR_PORT"].default


class OpenSearchConfig(BaseModel):
    """Pydantic model for OpenSearch + Logstash configurable environment variables."""
    model_config = {"extra": "forbid"}

    OPENSEARCH_PASSWORD:            str = ""
    OPENSEARCH_HOST:                str = "opensearch-node"
    OPENSEARCH_CLUSTER_NAME:        str = "novadef-cluster"
    OPENSEARCH_NODE_NAME:           str = "opensearch"
    OPENSEARCH_REST_API_PORT:       str = "9200"
    OPENSEARCH_ANALYSER_PORT:       str = "9600"
    OPENSEARCH_DASHBOARD_PORT:      str = "5601"
    TELEGRAF_BASE_TOPIC:            str = TelegrafConfig.model_fields["TELEGRAF_BASE_TOPIC"].default
    FLUENTD_SYSLOG_BASE_TOPIC:      str = FluentdConfig.model_fields["FLUENTD_SYSLOG_BASE_TOPIC"].default
    FLUENTD_SYSTEMD_BASE_TOPIC:     str = FluentdConfig.model_fields["FLUENTD_SYSTEMD_BASE_TOPIC"].default
    FALCO_BASE_TOPIC:               str = FalcoConfig.model_fields["FALCO_BASE_TOPIC"].default





class MongoDBConfig(BaseModel):
    """Pydantic model for MongoDB main instance configurable environment variables."""
    model_config = {"extra": "forbid"}

    MONGO_INITDB_ROOT_USERNAME:     str = "admin"
    MONGO_INITDB_ROOT_PASSWORD:     str = ""
    MONGO_PORT:                     str = "27017"
    MONGO_URI:                      str = ""

    # Least-privilege usernames created by init-mongo-users on top of root.
    SNORT_DB_USER_NAME:             str = "snort_db_user"
    FLOW_DB_WRITER_NAME:            str = "flow_db_writer"
    FLOW_DB_READER_NAME:            str = "flow_db_reader"


class MongoDBRolesConfig(BaseModel):
    """Pydantic model for MongoDB per-database role passwords and URIs (quote_plus-escaped, generated by the Launcher)."""
    model_config = {"extra": "forbid"}

    SNORT_DB_USER_PASSWORD:         str = ""
    FLOW_DB_WRITER_PASSWORD:        str = ""
    FLOW_DB_READER_PASSWORD:        str = ""
    MONGO_SNORT_URI:                str = ""
    MONGO_FLOW_WRITER_URI:          str = ""
    MONGO_FLOW_READER_URI:          str = ""


class MongoDBCMConfig(BaseModel):
    """Pydantic model for MongoDB Configuration Manager instance configurable environment variables."""
    model_config = {"extra": "forbid"}

    MONGO_CM_INITDB_ROOT_USERNAME:  str = "admin"
    MONGO_CM_INITDB_ROOT_PASSWORD:  str = ""
    MONGO_CM_PORT:                  str = "27018"
    MONGO_CM_URI:                   str = ""
    MONGO_CM_URI_DOCKER:            str = ""
    MONGO_CM_URI_HOST:              str = ""


class RedisConfig(BaseModel):
    """Pydantic model for Redis configurable environment variables."""
    model_config = {"extra": "forbid"}

    REDIS_HOST:                             str = "redis_novadef"
    REDIS_PORT:                             str = "6379"
    REDIS_DB:                               str = "0"
    REDIS_PASSWORD:                         str = ""
    REDIS_MAXMEMORY_SAMPLES:                str = "5"
    REDIS_IO_THREADS:                       str = "4"
    REDIS_STREAM_NODE_MAX_BYTES:            str = "4096"
    REDIS_STREAM_NODE_MAX_ENTRIES:          str = "100"
    REDIS_MAXCLIENTS:                       str = "10000"
    KTRW_KAFKA_AUTO_OFFSET_RESET:           str = "latest"
    KTRW_KAFKA_ENABLE_AUTO_COMMIT:          str = "true"
    KTRW_KAFKA_GROUP_ID:                    str = "redis-streamer"
    KTRW_REDIS_MAX_STREAM_LENGTH:           str = "1000"
    KTRW_REDIS_STREAM_TTL_SECONDS:          str = "21600"
    KTRW_PARTITION_ASSIGNMENT_STRATEGY:     str = "cooperative-sticky"
    KTRW_SESSION_TIMEOUT_MS:                str = "10000"
    KTRW_MAX_POLL_INTERVAL_MS:              str = "300000"
    KTRW_KAFKA_TOPIC_REFRESH_INTERVAL:      str = "30"
    KTRW_CM_TOPICS_REFRESH_INTERVAL:        str = "30"
    KTRW_NEW_TOPIC_BOOTSTRAP_MAX_MESSAGES:  str = "10"
    KTRW_TOPIC_MAP_CACHE_FILE:              str = "/home/redis_worker/topic_map_cache.json"
    KTRW_REDIS_CLEANUP_INTERVAL:            str = "300"
    KTRW_REDIS_RETENTION_HOURS:             str = "2"
    KTRW_REDIS_EMERGENCY_RETENTION_HOURS:   str = "1"
    KTRW_REDIS_MEMORY_THRESHOLD:            str = "0.85"


class PostgresGuiConfig(BaseModel):
    """Pydantic model for PostgreSQL GUI configurable environment variables."""
    model_config = {"extra": "forbid"}

    POSTGRES_GUI_USER:              str = "novadef_admin"
    POSTGRES_GUI_PASSWORD:          str = "novadef_pass"
    POSTGRES_GUI_DB:                str = "novadef_dashboard"
    POSTGRES_GUI_PORT:              str = "5432"


class NrtdrApiConfig(BaseModel):
    """Pydantic model for NRTDR API configurable environment variables."""
    model_config = {"extra": "forbid"}

    NRTDR_API_PORT:                 str = "8001"
    NRTDR_API_HOST:                 str = "0.0.0.0"
    NRTDR_WS_DEFAULT_LAST_N:        str = "10"
    NRTDR_WS_MAX_LAST_N:            str = "100"
    NRTDR_ACTIVE_WINDOW_SECONDS:    str = "60"


class HdrApiConfig(BaseModel):
    """Pydantic model for HDR API configurable environment variables."""
    model_config = {"extra": "forbid"}

    HDR_API_PORT:                   str = "8002"
    HDR_API_HOST:                   str = "0.0.0.0"
    MIMIR_HOST:                     str = MimirConfig.model_fields["MIMIR_HOST"].default
    MIMIR_PORT:                     str = MimirConfig.model_fields["MIMIR_PORT"].default
    HDR_HTTP_TIMEOUT_SECONDS:       str = "10"
    HDR_MAX_RANGE_POINTS:           str = "43200" # 30 days using step=60s (1 minute) intervals
    HDR_DEFAULT_STEP_SECONDS:       str = "60"


class DtApiConfig(BaseModel):
    """Pydantic model for Data Exporter API configurable environment variables."""
    model_config = {"extra": "forbid"}

    DT_API_PORT:                    str = "8003"
    DT_API_HOST:                    str = "0.0.0.0"
    OPENSEARCH_HOST:                str = OpenSearchConfig.model_fields["OPENSEARCH_HOST"].default
    OPENSEARCH_REST_API_PORT:       str = OpenSearchConfig.model_fields["OPENSEARCH_REST_API_PORT"].default
    OPENSEARCH_PASSWORD:            str = OpenSearchConfig.model_fields["OPENSEARCH_PASSWORD"].default
    DT_HTTP_TIMEOUT_SECONDS:        str = "10"
    DT_MAX_RANGE_POINTS:            str = "43200" # 30 days using interval=60s (1 minute) buckets, same window as Prometheus/HDR
    DT_DEFAULT_STEP_SECONDS:        str = "60"
    DT_MAX_PAGE_SIZE:               str = "1000"


class FlowModuleConfig(BaseModel):
    """Pydantic model for Flow Module configurable environment variables."""
    model_config = {"extra": "forbid"}

    TSHARK_BASE_TOPIC:                                  str = TsharkConfig.model_fields["TSHARK_BASE_TOPIC"].default
    CIC_KAFKA_BASE_TOPIC_OUT:                           str = "cic_flow"
    FLOW_KAFKA_GROUP:                                   str = "flow-module"
    FLOW_PCAP_ROTATE_SIZE_MB:                           str = "102400"
    FLOW_CIC_ROTATE_SIZE_MB:                            str = "51200"
    FLOW_ROTATE_TIME_SEC:                               str = "3.0"
    FLOW_PACKET_QUEUE_MAX:                              str = "5000"
    FLOW_WRITER_FLUSH_EVERY:                            str = "100"
    FLOW_KAFKA_CONSUMER_AUTO_OFFSET_RESET:              str = "earliest"
    FLOW_KAFKA_CONSUMER_ENABLE_AUTO_COMMIT:             str = "true"
    FLOW_KAFKA_CONSUMER_PARTITION_ASSIGNMENT_STRATEGY:  str = "cooperative-sticky"
    FLOW_KAFKA_CONSUMER_ENABLE_PARTITION_EOF:           str = "true"
    FLOW_KAFKA_CONSUMER_ALLOW_AUTO_CREATE_TOPICS:       str = "true"
    FLOW_KAFKA_PRODUCER_LINGER_MS:                      str = "5"
    FLOW_KAFKA_PRODUCER_BATCH_SIZE:                     str = "32768"
    FLOW_KAFKA_PRODUCER_COMPRESSION:                    str = "zstd"


class Snort3Config(BaseModel):
    """Pydantic model for Snort3 (alert_module) configurable environment variables."""
    model_config = {"extra": "forbid"}

    SNORT_KAFKA_GROUP_ID:                                   str = "alert-module"
    SNORT_KAFKA_TOPIC_IN:                                   str = TsharkConfig.model_fields["TSHARK_BASE_TOPIC"].default
    SNORT_KAFKA_TOPIC_OUT:                                  str = "snort_alerts"
    SNORT_ALERT_TAP_IFACE:                                  str = "tap0"
    SNORT_KAFKA_MESSAGE_FIELD:                              str = "_source"
    SNORT_CONSUMER_KAFKA_AUTO_OFFSET_RESET:                 str = "earliest"
    SNORT_CONSUMER_KAFKA_ENABLE_AUTO_COMMIT:                str = "true"
    SNORT_CONSUMER_KAFKA_PARTITION_ASSIGNMENT_STRATEGY:     str = "cooperative-sticky"
    SNORT_CONSUMER_KAFKA_ENABLE_PARTITION_EOF:              str = "true"
    SNORT_CONSUMER_KAFKA_ALLOW_AUTO_CREATE_TOPICS:          str = "true"
    SNORT_CONSUMER_FETCH_MIN_BYTES:                         str = "1048576"
    SNORT_CONSUMER_FETCH_WAIT_MAX_MS:                       str = "50"
    SNORT_CONSUMER_QUEUED_MAX_MESSAGES_KBYTES:              str = "262144"
    SNORT_CONSUMER_MAX_POLL_INTERVAL_MS:                    str = "900000"
    SNORT_CONSUMER_SESSION_TIMEOUT_MS:                      str = "10000"
    SNORT_PRODUCER_KAFKA_PRODUCER_LINGER_MS:                str = "5"
    SNORT_PRODUCER_BATCH_NUM_MESSAGES:                      str = "10000"
    SNORT_PRODUCER_KAFKA_PRODUCER_BATCH_SIZE:               str = "32768"
    SNORT_PRODUCER_KAFKA_PRODUCER_COMPRESSION:              str = "zstd"


class AlarmCollectorConfig(BaseModel):
    """Pydantic model for ThingsBoard alarm collector configurable environment variables."""
    model_config = {"extra": "forbid"}

    TB_USERNAME:    str = "tenant@thingsboard.org"
    TB_PASSWORD:    str = "tenant"
    TB_USE_HTTPS:   str = "false"


PUBLIC_TOOL_MODELS = {
    "tshark":          TsharkConfig,
    "flow_module":     FlowModuleConfig,
    "telegraf":        TelegrafConfig,
    "fluentd":         FluentdConfig,
    "falco":           FalcoConfig,
    "snort3":          Snort3Config,
}


INTERNAL_TOOL_MODELS = {
    "kafka":            KafkaConfig,
    "filebeat":          FilebeatConfig,
    "mongodb":           MongoDBConfig,
    "mongodb_roles":     MongoDBRolesConfig,
    "mongodb_cm":        MongoDBCMConfig,
    "redis":             RedisConfig,
    "mimir":             MimirConfig,
    "prometheus":        PrometheusConfig,
    "opensearch":        OpenSearchConfig,
    "alarm_collector":   AlarmCollectorConfig,
}


INTERNAL_SUPPORT_MODELS = {
    "info":             InfoConfig,
    "postgres_gui":     PostgresGuiConfig,
    "nrtdr_api":        NrtdrApiConfig,
    "hdr_api":          HdrApiConfig,
    "dt_api":           DtApiConfig,
}


DEFAULT_ENV_MODEL_CLASSES = (
    TelegrafConfig,
    TsharkConfig,
    FluentdConfig,
    FalcoConfig,
    KafkaConfig,
    FilebeatConfig,
    PrometheusConfig,
    OpenSearchConfig,
    MimirConfig,
    MongoDBConfig,
    MongoDBRolesConfig,
    MongoDBCMConfig,
    RedisConfig,
    InfoConfig,
    PostgresGuiConfig,
    NrtdrApiConfig,
    HdrApiConfig,
    DtApiConfig,
    AlarmCollectorConfig,
    FlowModuleConfig,
    Snort3Config,
)


TOOL_ENV_VARS = {
    "telegraf": [
        "ENABLE_TELEGRAF",
        "TELEGRAF_TO_PROMETHEUS_PORT",
        "TELEGRAF_BASE_TOPIC",
        "TELEGRAF_GENERAL_INTERVAL",
    ],
    "tshark": [
        "TSHARK_BASE_TOPIC",
        "TSHARK_SIZE_LIMIT_ROTATION",
        "TSHARK_INTERFACE",
        "TSHARK_EXCLUDE_PORTS",
    ],
    "fluentd": [
        "ENABLE_FLUENTD",
        "FLUENTD_TO_PROMETHEUS_PORT",
        "FLUENTD_INTERNAL_PORT",
        "FLUENTD_FILE_SIZE_LIMIT",
        "FLUENTD_SYSLOG_BASE_TOPIC",
        "FLUENTD_SYSTEMD_BASE_TOPIC",
    ],
    "falco": [
        "ENABLE_FALCO",
        "FALCO_BASE_TOPIC",
        "FALCO_SKIP_DRIVER_LOADER",
        "FALCO_EXPORTER_PORT",
        "FALCO_RULES_PATHS",
    ],
    "info": [
        "DEVICE_INFO_PORT",
        "DEVICE_INFO_PROBE_TIMEOUT",
        "DEVICE_INFO_REFRESH_INTERVAL",
        "TELEGRAF_PROBE_HOST",
        "FLUENTD_PROBE_HOST",
        "FALCO_PROBE_HOST",
    ],
    "kafka": [
        "KAFKA_BOOTSTRAP",
        "KAFKA_BOOTSTRAP_DOCKER",
        "KAFKA_LAN_HOSTNAME",
        "KAFKA_PORT_EXTERNAL_LAN",
        "KAFKA_PORT_INTERNAL",
        "KAFKA_LOG_RETENTION_MS",
        "KAFKA_LOG_RETENTION_BYTES",
        "KAFKA_LOG_CLEANUP_POLICY",
        "KAFKA_LOG_SEGMENT_BYTES",
        "KAFKA_LOG_ROLL_MS",
    ],
    "filebeat": [
        "FILEBEAT_BULK_MAX_SIZE",
        "FILEBEAT_COMPRESION",
        "FLUENTD_SYSLOG_BASE_TOPIC",
        "FLUENTD_SYSTEMD_BASE_TOPIC",
        "TSHARK_BASE_TOPIC",
        "FALCO_BASE_TOPIC",
    ],
    "prometheus": [
        "PROMETHEUS_PORT",
        "DISCOVERY_AGENT_SCAN_PORT",
        "DISCOVERY_AGENT_SCAN_TIMEOUT",
        "DISCOVERY_AGENT_REFRESH_INTERVAL",
        "DISCOVERY_AGENT_PORT",
        "MIMIR_HOST",
        "MIMIR_PORT",
    ],
    "mimir": [
        "MIMIR_HOST",
        "MIMIR_PORT",
    ],
    "opensearch": [
        "OPENSEARCH_PASSWORD",
        "OPENSEARCH_HOST",
        "OPENSEARCH_CLUSTER_NAME",
        "OPENSEARCH_NODE_NAME",
        "OPENSEARCH_REST_API_PORT",
        "OPENSEARCH_ANALYSER_PORT",
        "OPENSEARCH_DASHBOARD_PORT",
        "TELEGRAF_BASE_TOPIC",
        "FLUENTD_SYSLOG_BASE_TOPIC",
        "FLUENTD_SYSTEMD_BASE_TOPIC",
        "FALCO_BASE_TOPIC",
    ],
    "mongodb": [
        "MONGO_INITDB_ROOT_USERNAME",
        "MONGO_INITDB_ROOT_PASSWORD",
        "MONGO_PORT",
        "MONGO_URI",
        "SNORT_DB_USER_NAME",
        "FLOW_DB_WRITER_NAME",
        "FLOW_DB_READER_NAME",
        "SNORT_DB_USER_PASSWORD",
        "FLOW_DB_WRITER_PASSWORD",
        "FLOW_DB_READER_PASSWORD",
    ],
    "mongodb_cm": [
        "MONGO_CM_INITDB_ROOT_USERNAME",
        "MONGO_CM_INITDB_ROOT_PASSWORD",
        "MONGO_CM_PORT",
        "MONGO_CM_URI",
        "MONGO_CM_URI_DOCKER",
        "MONGO_CM_URI_HOST",
    ],
    "postgres_gui": [
        "POSTGRES_GUI_USER",
        "POSTGRES_GUI_PASSWORD",
        "POSTGRES_GUI_DB",
        "POSTGRES_GUI_PORT",
    ],
    "redis": [
        "KAFKA_BOOTSTRAP_DOCKER",
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_DB",
        "REDIS_PASSWORD",
        "REDIS_MAXMEMORY_SAMPLES",
        "REDIS_IO_THREADS",
        "REDIS_STREAM_NODE_MAX_BYTES",
        "REDIS_STREAM_NODE_MAX_ENTRIES",
        "REDIS_MAXCLIENTS",
        "MONGO_CM_URI_DOCKER",
        "KTRW_KAFKA_AUTO_OFFSET_RESET",
        "KTRW_KAFKA_ENABLE_AUTO_COMMIT",
        "KTRW_KAFKA_GROUP_ID",
        "KTRW_REDIS_MAX_STREAM_LENGTH",
        "KTRW_REDIS_STREAM_TTL_SECONDS",
        "KTRW_PARTITION_ASSIGNMENT_STRATEGY",
        "KTRW_SESSION_TIMEOUT_MS",
        "KTRW_MAX_POLL_INTERVAL_MS",
        "KTRW_KAFKA_TOPIC_REFRESH_INTERVAL",
        "KTRW_CM_TOPICS_REFRESH_INTERVAL",
        "KTRW_NEW_TOPIC_BOOTSTRAP_MAX_MESSAGES",
        "KTRW_TOPIC_MAP_CACHE_FILE",
        "KTRW_REDIS_CLEANUP_INTERVAL",
        "KTRW_REDIS_RETENTION_HOURS",
        "KTRW_REDIS_EMERGENCY_RETENTION_HOURS",
        "KTRW_REDIS_MEMORY_THRESHOLD",
    ],
    "flow_module": [
        "TSHARK_BASE_TOPIC",
        "MONGO_FLOW_WRITER_URI",
        "FLOW_DB_WRITER_NAME",
        "FLOW_DB_WRITER_PASSWORD",
        "MONGO_PORT",
        "CIC_KAFKA_BASE_TOPIC_OUT",
        "FLOW_KAFKA_GROUP",
        "FLOW_PCAP_ROTATE_SIZE_MB",
        "FLOW_CIC_ROTATE_SIZE_MB",
        "FLOW_ROTATE_TIME_SEC",
        "FLOW_PACKET_QUEUE_MAX",
        "FLOW_WRITER_FLUSH_EVERY",
        "FLOW_KAFKA_CONSUMER_AUTO_OFFSET_RESET",
        "FLOW_KAFKA_CONSUMER_ENABLE_AUTO_COMMIT",
        "FLOW_KAFKA_CONSUMER_PARTITION_ASSIGNMENT_STRATEGY",
        "FLOW_KAFKA_CONSUMER_ENABLE_PARTITION_EOF",
        "FLOW_KAFKA_CONSUMER_ALLOW_AUTO_CREATE_TOPICS",
        "FLOW_KAFKA_PRODUCER_LINGER_MS",
        "FLOW_KAFKA_PRODUCER_BATCH_SIZE",
        "FLOW_KAFKA_PRODUCER_COMPRESSION",
    ],
    "alert_module": [
        "MONGO_SNORT_URI",
        "SNORT_DB_USER_NAME",
        "SNORT_DB_USER_PASSWORD",
        "MONGO_PORT",
        "SNORT_RULES_PATHS",
        "SNORT_KAFKA_GROUP_ID",
        "SNORT_KAFKA_TOPIC_IN",
        "SNORT_KAFKA_TOPIC_OUT",
        "SNORT_ALERT_TAP_IFACE",
        "SNORT_KAFKA_MESSAGE_FIELD",
        "SNORT_CONSUMER_KAFKA_AUTO_OFFSET_RESET",
        "SNORT_CONSUMER_KAFKA_ENABLE_AUTO_COMMIT",
        "SNORT_CONSUMER_KAFKA_PARTITION_ASSIGNMENT_STRATEGY",
        "SNORT_CONSUMER_KAFKA_ENABLE_PARTITION_EOF",
        "SNORT_CONSUMER_KAFKA_ALLOW_AUTO_CREATE_TOPICS",
        "SNORT_CONSUMER_FETCH_MIN_BYTES",
        "SNORT_CONSUMER_FETCH_WAIT_MAX_MS",
        "SNORT_CONSUMER_QUEUED_MAX_MESSAGES_KBYTES",
        "SNORT_CONSUMER_MAX_POLL_INTERVAL_MS",
        "SNORT_CONSUMER_SESSION_TIMEOUT_MS",
        "SNORT_PRODUCER_KAFKA_PRODUCER_LINGER_MS",
        "SNORT_PRODUCER_BATCH_NUM_MESSAGES",
        "SNORT_PRODUCER_KAFKA_PRODUCER_BATCH_SIZE",
        "SNORT_PRODUCER_KAFKA_PRODUCER_COMPRESSION",
    ],
    "nrtdr_api": [
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_DB",
        "REDIS_PASSWORD",
        "NRTDR_API_PORT",
        "NRTDR_API_HOST",
        "NRTDR_WS_DEFAULT_LAST_N",
        "NRTDR_WS_MAX_LAST_N",
        "NRTDR_ACTIVE_WINDOW_SECONDS",
    ],
    "hdr_api": [
        "MIMIR_HOST",
        "MIMIR_PORT",
        "HDR_API_PORT",
        "HDR_API_HOST",
        "HDR_HTTP_TIMEOUT_SECONDS",
        "HDR_MAX_RANGE_POINTS",
        "HDR_DEFAULT_STEP_SECONDS",
    ],
    "alarm_collector": [
        "TB_USERNAME",
        "TB_PASSWORD",
        "TB_USE_HTTPS",
    ],
    "dt_api": [
        "OPENSEARCH_HOST",
        "OPENSEARCH_REST_API_PORT",
        "OPENSEARCH_PASSWORD",
        "DT_API_PORT",
        "DT_API_HOST",
        "DT_HTTP_TIMEOUT_SECONDS",
        "DT_MAX_RANGE_POINTS",
        "DT_DEFAULT_STEP_SECONDS",
        "DT_MAX_PAGE_SIZE",
    ],
}


PRODUCER_TOPIC_VARS = {
    "tshark":       ["TSHARK_BASE_TOPIC"],
    "telegraf":     ["TELEGRAF_BASE_TOPIC"],
    "fluentd":      ["FLUENTD_SYSLOG_BASE_TOPIC", "FLUENTD_SYSTEMD_BASE_TOPIC"],
    "falco":        ["FALCO_BASE_TOPIC"],
    "flow_module":  ["CIC_KAFKA_BASE_TOPIC_OUT"],
    "snort3":       ["SNORT_KAFKA_TOPIC_OUT"],
}


CONSUMER_TOPIC_VARS = {
    "flow_module":  ["TSHARK_BASE_TOPIC"],
    "snort3":       ["TSHARK_BASE_TOPIC"],
    "opensearch":   [
        "TELEGRAF_BASE_TOPIC",
        "FLUENTD_SYSLOG_BASE_TOPIC",
        "FLUENTD_SYSTEMD_BASE_TOPIC",
        "FALCO_BASE_TOPIC",
    ],
    "filebeat": [
        "TSHARK_BASE_TOPIC",
        "FLUENTD_SYSLOG_BASE_TOPIC",
        "FLUENTD_SYSTEMD_BASE_TOPIC",
        "FALCO_BASE_TOPIC",
    ],
}
