"""
configuration_manager_logic.py  (v4)

Business logic layer for the Configuration Manager API.

Changes from v3:
- When a producer tool is deployed (tshark, telegraf, fluentd, falco, flow_module, snort3),
  the resolved topic values are saved to a fixed MongoDB CM document with _id="kafka_topics".
- When a consumer tool is deployed (flow_module, snort3, opensearch/logstash), the real topic
  values are read from that document before calling launch(), so the .env always has the
  correct topic names even if they differ from the defaults.
- If MongoDB CM is unreachable the Pydantic defaults are used as a fallback.
- Producer and consumer topic maps now live in the shared launcher models module.
"""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple
from dotenv import load_dotenv

from pydantic import BaseModel, Field
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import ServerSelectionTimeoutError
from falco_rules_manager import (
    apply_falco_rules_files,
    apply_falco_rules_update,
    build_default_falco_rules_config,
    build_falco_rules_config_for_deploy,
    build_falco_rules_paths_env,
    capture_falco_final_rules_state,
    restore_falco_final_rules_state,
)
from snort_rules_manager import (
    apply_snort3_rules_files,
    apply_snort3_rules_update,
    build_default_snort3_rules_config,
    build_snort3_rules_paths_env,
    build_snort3_rules_config_for_deploy,
    capture_snort3_final_rules_state,
    restore_snort3_final_rules_state,
)

LAUNCHER_DIR = Path(__file__).resolve().parent.parent.parent / "Launcher"
if str(LAUNCHER_DIR) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_DIR))

from internal_external_tools_models import (  # noqa: E402
    CONSUMER_TOPIC_VARS,
    PUBLIC_TOOL_MODELS,
    PRODUCER_TOPIC_VARS,
)

# ---------------------------------------------------------------------------
# Path to the launcher entrypoint used by the Configuration Manager.
# ---------------------------------------------------------------------------
LAUNCHER_PATH = Path(__file__).resolve().parent.parent.parent / "Launcher" / "start_containers.py"
INTERNAL_ONLY_ENV_VARS = {"SNORT_RULES_PATHS", "FALCO_RULES_PATHS"}
RULES_SUPPORTED_TOOLS = {"snort3", "falco"}

# ---------------------------------------------------------------------------
# MongoDB Configuration Manager connection.
# MONGO_CM_URI is written to .init_pmp_env by the launcher on first run.
# ---------------------------------------------------------------------------
ENV_PATH = Path(__file__).resolve().parent.parent.parent / "Launcher" / ".init_pmp_env"
load_dotenv(ENV_PATH, override=True)

MONGO_CM_URI = (
    os.getenv("MONGO_CM_URI_HOST")
    or os.getenv("MONGO_CM_URI")
    or "mongodb://admin:admin@localhost:27018/?authSource=admin"
)
MONGO_CM_DB         = "configuration_manager"
MONGO_CM_COLLECTION = "deployments"
KAFKA_TOPICS_DOC_ID = "kafka_topics"   # fixed _id for the topics state document

# ---------------------------------------------------------------------------
# ALWAYS_ENV_VARS - kept in sync with the launcher to protect internal vars.
# ---------------------------------------------------------------------------
ALWAYS_ENV_VARS: List[str] = [
    "MACHINE_ID",
    "NETWORK_MODE",
    "PFD",
    "COMPOSE_PROFILES",
    "TZ",
    "KAFKA_BOOTSTRAP",
    "KAFKA_LAN_HOSTNAME",
]

# ---------------------------------------------------------------------------
# Mapping: toolName received by the API -> (launcher module, launcher profile).
# ---------------------------------------------------------------------------
TOOL_NAME_TO_MODULE: Dict[str, Tuple[str, str]] = {
    "tshark":           ("collection_module",    "tshark"),
    "flow_module":      ("flow_module",          "flow_module"),
    "telegraf":         ("collection_module",    "telegraf"),
    "fluentd":          ("collection_module",    "fluentd"),
    "falco":            ("collection_module",    "falco"),
    "snort3":           ("alert_module",         "alert_module"),
    "kafka":            ("communication_module", "kafka"),
    "filebeat":         ("communication_module", "filebeat"),
    "mongodb":          ("db_module",            "mongodb"),
    "mongodb_cm":       ("db_module",            "mongodb_cm"),
    "redis":            ("db_module",            "redis"),
    "prometheus":       ("aggregation_module",   "prometheus"),
    "opensearch":       ("aggregation_module",   "opensearch"),
    "alarm_collector":  ("thingsboard_module",   "alarm_collector"),
}

# ---------------------------------------------------------------------------
# Co-deployments: tools that must be restarted when a producer is updated.
# ---------------------------------------------------------------------------
CO_DEPLOY_TOOLS: Dict[str, List[str]] = {
    "tshark":   ["filebeat"],
    "fluentd":  ["filebeat"],
    "falco":    ["filebeat"],
}

# ---------------------------------------------------------------------------
# Runtime container names for tools whose active state matters to the API.
# ---------------------------------------------------------------------------
TOOL_RUNTIME_CONTAINERS: Dict[str, str] = {
    "tshark": "tshark_novadef",
    "flow_module": "flow_module_novadef",
    "snort3": "alert_module_novadef",
}

# ---------------------------------------------------------------------------
# Variables that exist in the runtime env but should not be edited from the GUI.
# ---------------------------------------------------------------------------
NON_CONFIGURABLE_ENV_VARS: Dict[str, set[str]] = {
    "flow_module": {
        "TSHARK_BASE_TOPIC",
        "FLOW_KAFKA_CONSUMER_ENABLE_AUTO_COMMIT",
        "FLOW_KAFKA_CONSUMER_ALLOW_AUTO_CREATE_TOPICS",
    },
    "telegraf": {
        "ENABLE_TELEGRAF",
    },
    "fluentd": {
        "ENABLE_FLUENTD",
    },
    "falco": {
        "ENABLE_FALCO",
        "FALCO_SKIP_DRIVER_LOADER",
    },
    "snort3": {
        "TSHARK_BASE_TOPIC",
        "SNORT_KAFKA_TOPIC_IN",
        "SNORT_KAFKA_MESSAGE_FIELD",
        "SNORT_CONSUMER_KAFKA_ENABLE_AUTO_COMMIT",
        "SNORT_CONSUMER_KAFKA_ALLOW_AUTO_CREATE_TOPICS",
        "SNORT_ALERT_TAP_IFACE",
    },
}


TOOL_CONFIG_MODELS: Dict[str, type] = {
    **PUBLIC_TOOL_MODELS,
}


# ===========================================================================
# Request / Response models used by the API layer
# ===========================================================================

class DeployRequest(BaseModel):
    """
    Deployment request body. Contains only the env var overrides for the tool.
    The toolName is received as a query parameter in the API endpoint, not here.
    An empty body {} is valid and means: use all defaults for that tool.

    Note:
    - 'rules' and 'include_default_rules' are declared in this base request on purpose,
      even though only falco and snort3 support them.
    - This allows non-rules endpoints to detect that the client sent rules-related
      fields and return a controlled business error (400), instead of silently ignoring
      them during request parsing.
    """
    configuration: Optional[Dict[str, Any]] = Field(default_factory=dict)
    rules: Optional[List[str]] = None
    include_default_rules: Optional[bool] = None


class DeploySecurityRequest(DeployRequest):
    """
    Security-tool deployment request body.

    This class currently does not add new fields beyond DeployRequest and intentionally
    uses 'pass'. It exists to:
    - make the snort3 endpoint contract explicit at the API layer
    - provide a dedicated type for future security-specific validation or fields
    """
    pass


class UpdateConfigurationRequest(BaseModel):
    """Request to update an existing deployment identified by its config_id."""
    config_id: str
    configuration: Optional[Dict[str, Any]] = Field(default_factory=dict)
    rules_action: Optional[Literal["add", "remove", "replace"]] = None
    rules: Optional[List[str]] = None
    rule_sids: Optional[List[str]] = None
    rule_names: Optional[List[str]] = None
    include_default_rules: Optional[bool] = None


# ===========================================================================
# MongoDB helpers
# ===========================================================================

def get_mongo_collection() -> Optional[Collection]:
    """
    Return the MongoDB CM deployments collection, or None if unreachable.
    """
    try:
        client = MongoClient(MONGO_CM_URI, serverSelectionTimeoutMS=3000)
        client.server_info()
        db = client[MONGO_CM_DB]
        return db[MONGO_CM_COLLECTION]
    except ServerSelectionTimeoutError:
        print("Warning: MongoDB CM is unreachable. Deployments will not be persisted.")
        return None
    except Exception as e:
        print(f"Warning: MongoDB CM connection error: {e}")
        return None


def save_deployment_to_mongo(
    collection: Collection,
    config_id: str,
    endpoint: str,
    tool_name: str,
    resolved_env: Dict[str, str],
    is_update: bool = False,
    rules_config_override: Optional[Dict[str, Any]] = None
) -> Tuple[bool, str]:
    """
    Insert or replace a deployment document in MongoDB using config_id as _id.
    Stores version metadata so the same config_id can evolve over time through updates.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    existing_document = get_deployment_from_mongo(collection, config_id) or {}

    current_revision = int(existing_document.get("revision", 1 if existing_document else 0))
    revision = (current_revision + 1) if is_update else (current_revision or 1)

    created_at = existing_document.get("created_at", now_iso)

    rules_config = None
    if tool_name in RULES_SUPPORTED_TOOLS:
        existing_rules_config = existing_document.get("rules_config", {})
        source_rules_config = rules_config_override if rules_config_override is not None else existing_rules_config
        rules_config = {
            "include_default_rules": bool(source_rules_config.get("include_default_rules", True)),
            "custom_rules": [str(rule) for rule in source_rules_config.get("custom_rules", [])],
        }
        if tool_name == "snort3":
            rules_config["custom_rule_sids"] = [
                str(sid) for sid in source_rules_config.get("custom_rule_sids", [])
            ]
        elif tool_name == "falco":
            rules_config["custom_rule_names"] = [
                str(rule_name) for rule_name in source_rules_config.get("custom_rule_names", [])
            ]

    version_payload: Dict[str, Any] = {
        "endpoint": endpoint,
        "tool_name": tool_name,
        "resolved_env": resolved_env,
    }
    if rules_config is not None:
        version_payload["rules_config"] = rules_config

    current_version_hash = hashlib.md5(
        json.dumps(version_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    document = {
        "_id":                  config_id,
        "endpoint":             endpoint,
        "tool_name":            tool_name,
        "timestamp":            now_iso,
        "created_at":           created_at,
        "updated_at":           now_iso,
        "revision":             revision,
        "current_version_hash": current_version_hash,
        "resolved_env":         resolved_env,
    }
    if rules_config is not None:
        document["rules_config"] = rules_config

    try:
        collection.replace_one({"_id": config_id}, document, upsert=True)
        return True, ""
    except Exception as e:
        error_msg = f"Could not save deployment to MongoDB: {e}"
        print(f"Warning: {error_msg}")
        return False, error_msg


def restore_deployment_in_mongo(
    collection: Collection,
    config_id: str,
    previous_document: Optional[Dict[str, Any]]
) -> Tuple[bool, str]:
    """Restore the deployment document to the state captured before a failed operation."""
    try:
        if previous_document is None:
            collection.delete_one({"_id": config_id})
            return True, ""

        restored_document = dict(previous_document)
        restored_document["_id"] = previous_document.get("_id", config_id)
        collection.replace_one({"_id": config_id}, restored_document, upsert=True)
        return True, ""
    except Exception as e:
        error_msg = f"Could not restore deployment document in MongoDB: {e}"
        print(f"Warning: {error_msg}")
        return False, error_msg


def get_deployment_from_mongo(collection: Collection, config_id: str) -> Optional[Dict]:
    """
    Retrieve a deployment document from MongoDB by its config_id (_id field).
    """
    try:
        return collection.find_one({"_id": config_id})
    except Exception as e:
        print(f"Warning: could not read from MongoDB: {e}")
        return None


def update_kafka_topics_in_mongo(
    collection: Collection,
    producer_topic_updates: Dict[str, str]
) -> None:
    """
    Upsert the fixed kafka_topics document with the latest topic names published by a producer tool.
    The document uses _id=KAFKA_TOPICS_DOC_ID and stores one key per topic variable.
    """
    if not producer_topic_updates:
        return

    update_fields = dict(producer_topic_updates)
    update_fields["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        collection.update_one(
            {"_id": KAFKA_TOPICS_DOC_ID},
            {"$set": update_fields},
            upsert=True
        )
        print(f"kafka_topics document updated: {list(producer_topic_updates.keys())}")
    except Exception as e:
        print(f"Warning: could not update kafka_topics document: {e}")


def get_kafka_topics_from_mongo(collection: Collection) -> Dict[str, str]:
    """
    Read the current kafka_topics document from MongoDB CM.
    Returns an empty dict if the document does not exist yet or MongoDB is unreachable.
    """
    try:
        doc = collection.find_one({"_id": KAFKA_TOPICS_DOC_ID})
        if doc is None:
            return {}
        # Remove internal MongoDB fields before returning
        doc.pop("_id", None)
        doc.pop("updated_at", None)
        return {k: str(v) for k, v in doc.items()}
    except Exception as e:
        print(f"Warning: could not read kafka_topics from MongoDB: {e}")
        return {}


# ===========================================================================
# Core logic functions
# ===========================================================================

def _load_producer_consumer_maps() -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """
    Return the producer and consumer topic maps from the shared models module.
    """
    return PRODUCER_TOPIC_VARS, CONSUMER_TOPIC_VARS


def normalize_empty_string_config_values(
    tool_name: str,
    incoming_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Replace exact empty-string configuration values with the default declared in
    the Pydantic model for that tool.

    This normalization intentionally applies only to the 'configuration' payload
    and does not touch rules-related request fields such as snort3 rules.
    """
    if tool_name not in TOOL_CONFIG_MODELS or not incoming_config:
        return dict(incoming_config or {})

    config_model_class = TOOL_CONFIG_MODELS[tool_name]
    normalized_config: Dict[str, Any] = dict(incoming_config)

    for key, value in incoming_config.items():
        if value != "":
            continue

        model_field = config_model_class.model_fields.get(key)
        if model_field is None:
            continue

        normalized_config[key] = model_field.default

    return normalized_config


def validate_and_parse_config(
    tool_name: str,
    incoming_config: Dict[str, Any]
) -> Tuple[bool, str, Dict[str, str]]:
    """
    Validate tool_name and parse the incoming config dict with the correct Pydantic model.
    Returns (is_valid, error_message, resolved_env_dict).
    Pydantic fills defaults for missing fields and rejects unknown fields (extra=forbid).
    """
    if tool_name not in TOOL_CONFIG_MODELS:
        valid_names = list(TOOL_CONFIG_MODELS.keys())
        return False, f"Unknown toolName '{tool_name}'. Valid tools: {valid_names}", {}

    forbidden_overrides = sorted(
        key
        for key in incoming_config.keys()
        if key in NON_CONFIGURABLE_ENV_VARS.get(tool_name, set())
    )
    if forbidden_overrides:
        return (
            False,
            f"The following variables for tool '{tool_name}' are managed internally and cannot be overridden: {', '.join(forbidden_overrides)}",
            {},
        )

    config_model_class = TOOL_CONFIG_MODELS[tool_name]
    normalized_config = normalize_empty_string_config_values(tool_name, incoming_config)

    try:
        parsed_config = config_model_class.model_validate(normalized_config or {})
    except Exception as e:
        return False, f"Invalid configuration for tool '{tool_name}': {e}", {}

    resolved: Dict[str, str] = {
        k: str(v) for k, v in parsed_config.model_dump().items()
    }

    return True, "", resolved


def validate_and_parse_partial_update_config(
    tool_name: str,
    incoming_config: Dict[str, Any]
) -> Tuple[bool, str, Dict[str, str]]:
    """
    Validate a partial update payload for a tool.
    Unlike deploy validation, this only returns the keys explicitly sent by the client,
    so non-updated fields are not replaced with model defaults.
    """
    if not incoming_config:
        return False, "No configuration values were provided to update.", {}

    if tool_name not in TOOL_CONFIG_MODELS:
        valid_names = list(TOOL_CONFIG_MODELS.keys())
        return False, f"Unknown toolName '{tool_name}'. Valid tools: {valid_names}", {}

    forbidden_overrides = sorted(
        key
        for key in incoming_config.keys()
        if key in NON_CONFIGURABLE_ENV_VARS.get(tool_name, set())
    )
    if forbidden_overrides:
        return (
            False,
            f"The following variables for tool '{tool_name}' are managed internally and cannot be overridden: {', '.join(forbidden_overrides)}",
            {},
        )

    config_model_class = TOOL_CONFIG_MODELS[tool_name]
    normalized_config = normalize_empty_string_config_values(tool_name, incoming_config)

    try:
        parsed_config = config_model_class.model_validate(normalized_config)
    except Exception as e:
        return False, f"Invalid configuration for tool '{tool_name}': {e}", {}

    resolved: Dict[str, str] = {
        key: str(getattr(parsed_config, key))
        for key in normalized_config.keys()
    }

    return True, "", resolved


def request_uses_rules_contract(request: Any) -> bool:
    """Return True if the request includes any rules-related fields."""
    return any(
        getattr(request, field_name, None) is not None
        for field_name in ("rules", "rule_sids", "rule_names", "rules_action", "include_default_rules")
    )


def build_public_resolved_env(resolved_env: Dict[str, Any]) -> Dict[str, str]:
    """Filter internal-only env vars out of the API response payload."""
    return {
        str(key): str(value)
        for key, value in resolved_env.items()
        if str(key) not in INTERNAL_ONLY_ENV_VARS
    }


def append_rollback_error(base_error: str, rollback_error: str) -> str:
    """Append rollback details to the main error message when recovery also fails."""
    if not rollback_error:
        return base_error
    return f"{base_error} Rollback warning: {rollback_error}"


def get_container_runtime_status(container_name: str) -> str:
    """
    Return the Docker runtime status for a container.
    If the container does not exist, returns 'missing'.
    """
    completed = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
            container_name,
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    if completed.returncode != 0:
        return "missing"

    return completed.stdout.strip() or "unknown"


def get_tool_runtime_state(tool_name: str) -> Dict[str, Any]:
    """
    Return the runtime state of a tool's main container.
    """
    container_name = TOOL_RUNTIME_CONTAINERS.get(tool_name)

    if not container_name:
        return {
            "status": "error",
            "message": f"No runtime container mapping is defined for tool '{tool_name}'.",
        }

    runtime_status = get_container_runtime_status(container_name)
    is_active = runtime_status in {"running", "healthy"}

    return {
        "status": "success",
        "toolName": tool_name,
        "container_name": container_name,
        "runtime_status": runtime_status,
        "is_active": is_active,
    }


def validate_snort3_dependency_state(collection: Optional[Collection]) -> Tuple[bool, str]:
    """
    Ensure Snort3 can only be deployed when tshark is actively running and its
    resolved input topic is available in MongoDB CM.
    """
    tshark_runtime = get_tool_runtime_state("tshark")
    if tshark_runtime.get("status") != "success":
        return False, str(tshark_runtime.get("message", "Could not determine tshark runtime state."))

    if not bool(tshark_runtime.get("is_active")):
        container_name = str(tshark_runtime.get("container_name", "tshark_novadef"))
        runtime_status = str(tshark_runtime.get("runtime_status", "unknown"))
        return (
            False,
            "Snort3 requires tshark to be actively deployed first. "
            f"Container '{container_name}' is currently '{runtime_status}'.",
        )

    if collection is None:
        return (
            False,
            "Snort3 requires MongoDB CM to resolve tshark topics, but MongoDB CM is unavailable.",
        )

    stored_topics = get_kafka_topics_from_mongo(collection)
    tshark_topic = str(stored_topics.get("TSHARK_BASE_TOPIC", "")).strip()
    if not tshark_topic:
        return (
            False,
            "Snort3 requires the tshark topic to be present in MongoDB CM. "
            "Deploy tshark first through the Configuration Manager.",
        )

    return True, ""


# Dependency map for tools that require upstream dependencies
DEPENDENCY_MAP = {
    "snort3": {"upstream_tool": "tshark", "required_topic": "TSHARK_BASE_TOPIC"},
    "flow_module": {"upstream_tool": "tshark", "required_topic": "TSHARK_BASE_TOPIC"},
}


def validate_dependency_state(tool_name: str, collection: Optional[Collection]) -> Tuple[bool, str]:
    """
    Generic validation for tools that depend on upstream tools and topics.
    Ensures the tool can only be deployed when the upstream tool is actively running
    and the required topic is available in MongoDB CM.
    """
    if tool_name not in DEPENDENCY_MAP:
        return True, ""  # No dependency, allow

    dep_config = DEPENDENCY_MAP[tool_name]
    upstream_tool = dep_config["upstream_tool"]
    required_topic = dep_config["required_topic"]

    upstream_runtime = get_tool_runtime_state(upstream_tool)
    if upstream_runtime.get("status") != "success":
        return False, str(upstream_runtime.get("message", f"Could not determine {upstream_tool} runtime state."))

    if not bool(upstream_runtime.get("is_active")):
        container_name = str(upstream_runtime.get("container_name", f"{upstream_tool}_novadef"))
        runtime_status = str(upstream_runtime.get("runtime_status", "unknown"))
        tool_display_name = "Snort3" if tool_name == "snort3" else "Flow"  # User-friendly names
        upstream_display_name = "tshark"
        return (
            False,
            f"{tool_display_name} requires {upstream_display_name} to be actively deployed first. "
            f"Container '{container_name}' is currently '{runtime_status}'.",
        )

    if collection is None:
        tool_display_name = "Snort3" if tool_name == "snort3" else "Flow"
        upstream_display_name = "tshark"
        return (
            False,
            f"{tool_display_name} requires MongoDB CM to resolve {upstream_display_name} topics, but MongoDB CM is unavailable.",
        )

    stored_topics = get_kafka_topics_from_mongo(collection)
    topic_value = str(stored_topics.get(required_topic, "")).strip()
    if not topic_value:
        tool_display_name = "Snort3" if tool_name == "snort3" else "Flow"
        upstream_display_name = "tshark"
        return (
            False,
            f"{tool_display_name} requires the {upstream_display_name} topic to be present in MongoDB CM. "
            "Deploy tshark first through the Configuration Manager.",
        )

    return True, ""


def validate_rules_contract_for_unsupported_tools(tool_name: str, request: Any) -> Tuple[bool, str]:
    """Reject rules-related fields for tools that do not support them."""
    if tool_name not in RULES_SUPPORTED_TOOLS and request_uses_rules_contract(request):
        return False, (
            f"Rules-related fields are only supported for tools {sorted(RULES_SUPPORTED_TOOLS)}. "
            f"Received rules contract fields for tool '{tool_name}'."
        )
    return True, ""


def resolve_consumer_topics(
    tool_name: str,
    resolved_env: Dict[str, str],
    collection: Optional[Collection]
) -> Dict[str, str]:
    """
    For consumer tools, overwrite their topic variables with the real values stored
    in the kafka_topics MongoDB CM document. Falls back to the Pydantic defaults
    already present in resolved_env if MongoDB CM is unavailable or the document
    does not exist yet.
    """
    _, consumer_map = _load_producer_consumer_maps()

    needed_topics = consumer_map.get(tool_name, [])

    if not needed_topics:
        return resolved_env

    if collection is None:
        print(f"Warning: MongoDB CM unreachable. Using default topic values for '{tool_name}'.")
        return resolved_env

    stored_topics = get_kafka_topics_from_mongo(collection)

    if not stored_topics:
        print(f"Warning: kafka_topics document not found in MongoDB CM. Using defaults for '{tool_name}'.")
        return resolved_env

    updated_env = dict(resolved_env)

    # Special case: snort3 consumes the topic produced by tshark, but its actual input variable is SNORT_KAFKA_TOPIC_IN.
    if tool_name == "snort3" and "TSHARK_BASE_TOPIC" in stored_topics:
        real_tshark_topic = stored_topics["TSHARK_BASE_TOPIC"]

        if updated_env.get("TSHARK_BASE_TOPIC") != real_tshark_topic:
            print(
                f"  Topic override for 'snort3': "
                f"TSHARK_BASE_TOPIC = '{real_tshark_topic}' "
                f"(was '{updated_env.get('TSHARK_BASE_TOPIC')}')"
            )

        if updated_env.get("SNORT_KAFKA_TOPIC_IN") != real_tshark_topic:
            print(
                f"  Topic override for 'snort3': "
                f"SNORT_KAFKA_TOPIC_IN = '{real_tshark_topic}' "
                f"(was '{updated_env.get('SNORT_KAFKA_TOPIC_IN')}')"
            )

        updated_env["TSHARK_BASE_TOPIC"] = real_tshark_topic
        updated_env["SNORT_KAFKA_TOPIC_IN"] = real_tshark_topic

    for topic_var in needed_topics:
        if topic_var in stored_topics:
            real_value = stored_topics[topic_var]
            if updated_env.get(topic_var) != real_value:
                print(f"  Topic override for '{tool_name}': {topic_var} = '{real_value}' (was '{updated_env.get(topic_var)}')")
            updated_env[topic_var] = real_value
        else:
            print(f"  Warning: '{topic_var}' not in kafka_topics document. Using default '{updated_env.get(topic_var)}'.")

    return updated_env


def persist_producer_topics(
    tool_name: str,
    resolved_env: Dict[str, str],
    collection: Optional[Collection]
) -> None:
    """
    For producer tools, save their resolved topic variable values to the kafka_topics document
    in MongoDB CM so consumer tools can read them later.
    """
    if collection is None:
        print(f"Warning: MongoDB CM unreachable. Producer topics for '{tool_name}' will not be persisted.")
        return

    producer_map, _ = _load_producer_consumer_maps()
    topic_vars = producer_map.get(tool_name, [])

    if not topic_vars:
        return

    producer_topic_updates = {
        var: resolved_env[var]
        for var in topic_vars
        if var in resolved_env
    }

    if producer_topic_updates:
        update_kafka_topics_in_mongo(collection, producer_topic_updates)


def build_config_id(
    endpoint: str,
    tool_name: str,
    resolved_env: Dict[str, str],
    rules_config: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generate a deterministic MD5 hash ID from endpoint, tool_name and resolved env dict.
    """
    raw_payload: Dict[str, Any] = {
        "endpoint": endpoint,
        "tool_name": tool_name,
        "resolved_env": resolved_env,
    }
    if rules_config is not None:
        raw_payload["rules_config"] = rules_config

    raw = json.dumps(
        raw_payload,
        sort_keys=True
    )
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def build_selected_from_tool_name(tool_name: str) -> "OrderedDict[str, List[str]]":
    """
    Build the OrderedDict[module -> tools] structure expected by the launcher.
    from a single toolName string as received via the API query parameter.
    """
    selected: OrderedDict[str, List[str]] = OrderedDict()

    if tool_name not in TOOL_NAME_TO_MODULE:
        return selected

    module, tool_in_registry = TOOL_NAME_TO_MODULE[tool_name]
    selected[module] = [tool_in_registry]

    return selected


def call_start_containers(
    selected: "OrderedDict[str, List[str]]",
    env_overrides: Dict[str, str]
) -> Tuple[bool, str]:
    """
    Import and call launch() from the launcher with resolved selected modules and env overrides.
    Returns (success, error_message).
    """
    spec = importlib.util.spec_from_file_location("start_containers", str(LAUNCHER_PATH))

    if spec is None or spec.loader is None:
        return False, f"Could not locate start_containers.py at {LAUNCHER_PATH}"

    module = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(module)
    except Exception as e:
        return False, f"Error loading start_containers.py: {e}"

    try:
        module.launch(selected=selected, env_overrides=env_overrides)
        return True, ""
    except Exception as e:
        return False, f"Error during launch: {e}"


def process_deploy_request(
    tool_name: str,
    request: DeployRequest,
    endpoint: str,
    allowed_tool_names: List[str]
) -> Dict[str, Any]:
    """
    Main logic handler for all deploy endpoints.
    1. Validates tool and parses config via Pydantic (fills defaults).
    2. If producer: persists its topic values to MongoDB CM kafka_topics document.
    3. If consumer: reads real topic values from MongoDB CM and injects them into env_overrides.
    4. Saves deployment to MongoDB CM.
    5. Calls start_containers.launch().
    """
    if tool_name not in allowed_tool_names:
        return {
            "status": "error",
            "message": (
                f"Tool '{tool_name}' is not valid for endpoint '{endpoint}'. "
                f"Allowed tools: {allowed_tool_names}"
            )
        }

    are_rules_fields_valid, rules_error_msg = validate_rules_contract_for_unsupported_tools(tool_name, request)
    if not are_rules_fields_valid:
        return {"status": "error", "message": rules_error_msg}

    collection = get_mongo_collection()

    if tool_name in DEPENDENCY_MAP:
        dependency_ok, dependency_error = validate_dependency_state(tool_name, collection)
        if not dependency_ok:
            return {"status": "error", "message": dependency_error}

    is_valid, error_msg, resolved_env = validate_and_parse_config(
        tool_name=tool_name,
        incoming_config=request.configuration or {}
    )

    if not is_valid:
        return {"status": "error", "message": error_msg}

    rules_config: Optional[Dict[str, Any]] = None
    previous_final_rules_exists = False
    previous_final_rules_content: Optional[str] = None
    if tool_name == "snort3":
        previous_final_rules_exists, previous_final_rules_content = capture_snort3_final_rules_state()
        is_valid_rules, rules_error_msg, rules_config = build_snort3_rules_config_for_deploy(
            rules=request.rules,
            include_default_rules=request.include_default_rules,
        )
        if not is_valid_rules:
            return {"status": "error", "message": rules_error_msg}

        should_validate_custom_rules = bool(request.rules)
        are_rules_files_ready, rules_files_error = apply_snort3_rules_files(
            rules_config=rules_config,
            validate_custom_rules=should_validate_custom_rules,
        )
        if not are_rules_files_ready:
            return {"status": "error", "message": rules_files_error}

        resolved_env["SNORT_RULES_PATHS"] = build_snort3_rules_paths_env(rules_config)
    elif tool_name == "falco":
        previous_final_rules_exists, previous_final_rules_content = capture_falco_final_rules_state()
        is_valid_rules, rules_error_msg, rules_config = build_falco_rules_config_for_deploy(
            rules=request.rules,
            include_default_rules=request.include_default_rules,
        )
        if not is_valid_rules:
            return {"status": "error", "message": rules_error_msg}

        should_validate_custom_rules = bool(request.rules)
        are_rules_files_ready, rules_files_error = apply_falco_rules_files(
            rules_config=rules_config,
            validate_custom_rules=should_validate_custom_rules,
        )
        if not are_rules_files_ready:
            return {"status": "error", "message": rules_files_error}

        resolved_env["FALCO_RULES_PATHS"] = build_falco_rules_paths_env(rules_config)
    # If this tool produces Kafka topics, persist them so consumers can find them later
    persist_producer_topics(tool_name, resolved_env, collection)

    # If this tool consumes Kafka topics, inject the real topic values from MongoDB CM
    resolved_env = resolve_consumer_topics(tool_name, resolved_env, collection)

    selected = build_selected_from_tool_name(tool_name)

    # --- Apply co-deployments ---
    co_deploy_tools = CO_DEPLOY_TOOLS.get(tool_name, [])
    for cd_tool in co_deploy_tools:
        cd_module, cd_tool_in_registry = TOOL_NAME_TO_MODULE.get(cd_tool, (None, None))
        if cd_module and cd_tool_in_registry:
            if cd_module not in selected:
                selected[cd_module] = []
            if cd_tool_in_registry not in selected[cd_module]:
                selected[cd_module].append(cd_tool_in_registry)
        is_valid_cd, _, cd_env = validate_and_parse_config(cd_tool, {})
        if is_valid_cd:
            cd_env = resolve_consumer_topics(cd_tool, cd_env, collection)
            resolved_env.update(cd_env)

    config_id = build_config_id(endpoint, tool_name, resolved_env, rules_config=rules_config)
    previous_deployment_document = get_deployment_from_mongo(collection, config_id) if collection is not None else None

    if collection is not None:
        mongo_saved, mongo_error = save_deployment_to_mongo(
            collection=collection,
            config_id=config_id,
            endpoint=endpoint,
            tool_name=tool_name,
            resolved_env=resolved_env,
            is_update=False,
            rules_config_override=rules_config
        )
        if not mongo_saved:
            if tool_name == "snort3":
                rollback_ok, rollback_error = restore_snort3_final_rules_state(
                    previous_final_rules_exists,
                    previous_final_rules_content,
                )
                mongo_error = append_rollback_error(mongo_error, "" if rollback_ok else rollback_error)
            elif tool_name == "falco":
                rollback_ok, rollback_error = restore_falco_final_rules_state(
                    previous_final_rules_exists,
                    previous_final_rules_content,
                )
                mongo_error = append_rollback_error(mongo_error, "" if rollback_ok else rollback_error)
            return {"status": "error", "message": mongo_error}

    success, error_msg = call_start_containers(
        selected=selected,
        env_overrides=resolved_env
    )

    if not success:
        if collection is not None:
            rollback_mongo_ok, rollback_mongo_error = restore_deployment_in_mongo(
                collection=collection,
                config_id=config_id,
                previous_document=previous_deployment_document,
            )
            error_msg = append_rollback_error(error_msg, "" if rollback_mongo_ok else rollback_mongo_error)
        if tool_name == "snort3":
            rollback_rules_ok, rollback_rules_error = restore_snort3_final_rules_state(
                previous_final_rules_exists,
                previous_final_rules_content,
            )
            error_msg = append_rollback_error(error_msg, "" if rollback_rules_ok else rollback_rules_error)
        elif tool_name == "falco":
            rollback_rules_ok, rollback_rules_error = restore_falco_final_rules_state(
                previous_final_rules_exists,
                previous_final_rules_content,
            )
            error_msg = append_rollback_error(error_msg, "" if rollback_rules_ok else rollback_rules_error)
        return {"status": "error", "message": error_msg}

    return {
        "status":           "success",
        "config_id":        config_id,
        "message":          f"Deployment started successfully via endpoint '{endpoint}'.",
        "deployed_tool":    tool_name,
        "kafka_bootstrap":  resolved_env.get("KAFKA_BOOTSTRAP", "kafka_novadef-node1.lan:9094"),
    }


def process_update_configuration(
    tool_name: str,
    request: UpdateConfigurationRequest
) -> Dict[str, Any]:
    """
    Logic handler for updateConfiguration endpoint.
    Retrieves the existing deployment by config_id, merges new values, applies topic resolution,
    and redeploys.
    """
    collection = get_mongo_collection()

    if collection is None:
        return {
            "status":  "error",
            "message": "MongoDB CM is unavailable. Cannot retrieve existing configuration."
        }

    existing = get_deployment_from_mongo(collection, request.config_id)

    if existing is None:
        return {
            "status":  "error",
            "message": f"No deployment found with config_id '{request.config_id}'."
        }

    base_env: Dict[str, str] = dict(existing.get("resolved_env", {}))
    endpoint: str = existing.get("endpoint", "unknown")
    stored_tool_name: str = existing.get("tool_name", tool_name)
    default_rules_config = (
        build_default_snort3_rules_config()
        if tool_name == "snort3"
        else build_default_falco_rules_config()
        if tool_name == "falco"
        else {}
    )
    existing_rules_config: Dict[str, Any] = dict(existing.get("rules_config", default_rules_config))

    if stored_tool_name != tool_name:
        return {
            "status":  "error",
            "message": (
                f"Tool mismatch for config_id '{request.config_id}': "
                f"stored tool is '{stored_tool_name}', but request used '{tool_name}'."
            )
        }

    are_rules_fields_valid, rules_error_msg = validate_rules_contract_for_unsupported_tools(tool_name, request)
    if not are_rules_fields_valid:
        return {"status": "error", "message": rules_error_msg}

    if tool_name in DEPENDENCY_MAP:
        dependency_ok, dependency_error = validate_dependency_state(tool_name, collection)
        if not dependency_ok:
            return {"status": "error", "message": dependency_error}

    previous_final_rules_exists = False
    previous_final_rules_content: Optional[str] = None
    if tool_name == "snort3":
        previous_final_rules_exists, previous_final_rules_content = capture_snort3_final_rules_state()
    elif tool_name == "falco":
        previous_final_rules_exists, previous_final_rules_content = capture_falco_final_rules_state()

    partial_env: Dict[str, str] = {}
    if request.configuration:
        is_valid, error_msg, partial_env = validate_and_parse_partial_update_config(
            tool_name=tool_name,
            incoming_config=request.configuration
        )

        if not is_valid:
            return {"status": "error", "message": error_msg}

    updated_rules_config: Optional[Dict[str, Any]] = None
    rules_contract_used = request_uses_rules_contract(request)
    if tool_name == "snort3" and rules_contract_used:
        if request.rules_action is None:
            return {"status": "error", "message": "The 'rules_action' field is required when rules-related fields are sent for snort3."}

        is_valid_rules, rules_error_msg, updated_rules_config = apply_snort3_rules_update(
            existing_rules_config=existing_rules_config,
            rules_action=request.rules_action,
            rules=request.rules,
            rule_sids=request.rule_sids,
            include_default_rules=request.include_default_rules,
        )
        if not is_valid_rules:
            return {"status": "error", "message": rules_error_msg}

        should_validate_custom_rules = request.rules_action in {"add", "replace"}
        are_rules_files_ready, rules_files_error = apply_snort3_rules_files(
            rules_config=updated_rules_config,
            validate_custom_rules=should_validate_custom_rules,
        )
        if not are_rules_files_ready:
            return {"status": "error", "message": rules_files_error}
    elif tool_name == "falco" and rules_contract_used:
        if request.rules_action is None:
            return {"status": "error", "message": "The 'rules_action' field is required when rules-related fields are sent for falco."}

        if request.rule_sids is not None:
            return {"status": "error", "message": "The 'rule_sids' field is not supported for falco. Use 'rule_names' instead."}

        is_valid_rules, rules_error_msg, updated_rules_config = apply_falco_rules_update(
            existing_rules_config=existing_rules_config,
            rules_action=request.rules_action,
            rules=request.rules,
            rule_names=request.rule_names,
            include_default_rules=request.include_default_rules,
        )
        if not is_valid_rules:
            return {"status": "error", "message": rules_error_msg}

        should_validate_custom_rules = request.rules_action in {"add", "replace"}
        are_rules_files_ready, rules_files_error = apply_falco_rules_files(
            rules_config=updated_rules_config,
            validate_custom_rules=should_validate_custom_rules,
        )
        if not are_rules_files_ready:
            return {"status": "error", "message": rules_files_error}

    if tool_name == "snort3":
        effective_rules_config = updated_rules_config if updated_rules_config is not None else existing_rules_config
        base_env["SNORT_RULES_PATHS"] = build_snort3_rules_paths_env(effective_rules_config)
    elif tool_name == "falco":
        effective_rules_config = updated_rules_config if updated_rules_config is not None else existing_rules_config
        base_env["FALCO_RULES_PATHS"] = build_falco_rules_paths_env(effective_rules_config)

    if not partial_env and updated_rules_config is None:
        rules_tool_hint = (
            " or valid snort3 rules changes"
            if tool_name == "snort3"
            else " or valid falco rules changes"
            if tool_name == "falco"
            else ""
        )
        return {"status": "error", "message": f"No configuration values{rules_tool_hint} were provided to update."}

    base_env.update(partial_env)

    # Re-apply producer/consumer topic logic on update as well
    persist_producer_topics(tool_name, base_env, collection)
    base_env = resolve_consumer_topics(tool_name, base_env, collection)

    selected = build_selected_from_tool_name(stored_tool_name)

    # --- Apply co-deployments ---
    co_deploy_tools = CO_DEPLOY_TOOLS.get(tool_name, [])
    for cd_tool in co_deploy_tools:
        cd_module, cd_tool_in_registry = TOOL_NAME_TO_MODULE.get(cd_tool, (None, None))
        if cd_module and cd_tool_in_registry:
            if cd_module not in selected:
                selected[cd_module] = []
            if cd_tool_in_registry not in selected[cd_module]:
                selected[cd_module].append(cd_tool_in_registry)
        is_valid_cd, _, cd_env = validate_and_parse_config(cd_tool, {})
        if is_valid_cd:
            cd_env = resolve_consumer_topics(cd_tool, cd_env, collection)
            base_env.update(cd_env)

    mongo_saved, mongo_error = save_deployment_to_mongo(
        collection=collection,
        config_id=request.config_id,
        endpoint=endpoint,
        tool_name=tool_name,
        resolved_env=base_env,
        is_update=True,
        rules_config_override=updated_rules_config
    )
    if not mongo_saved:
        if tool_name == "snort3":
            rollback_ok, rollback_error = restore_snort3_final_rules_state(
                previous_final_rules_exists,
                previous_final_rules_content,
            )
            mongo_error = append_rollback_error(mongo_error, "" if rollback_ok else rollback_error)
        elif tool_name == "falco":
            rollback_ok, rollback_error = restore_falco_final_rules_state(
                previous_final_rules_exists,
                previous_final_rules_content,
            )
            mongo_error = append_rollback_error(mongo_error, "" if rollback_ok else rollback_error)
        return {"status": "error", "message": mongo_error}

    success, error_msg = call_start_containers(
        selected=selected,
        env_overrides=base_env
    )

    if not success:
        rollback_mongo_ok, rollback_mongo_error = restore_deployment_in_mongo(
            collection=collection,
            config_id=request.config_id,
            previous_document=existing,
        )
        error_msg = append_rollback_error(error_msg, "" if rollback_mongo_ok else rollback_mongo_error)
        if tool_name == "snort3":
            rollback_rules_ok, rollback_rules_error = restore_snort3_final_rules_state(
                previous_final_rules_exists,
                previous_final_rules_content,
            )
            error_msg = append_rollback_error(error_msg, "" if rollback_rules_ok else rollback_rules_error)
        elif tool_name == "falco":
            rollback_rules_ok, rollback_rules_error = restore_falco_final_rules_state(
                previous_final_rules_exists,
                previous_final_rules_content,
            )
            error_msg = append_rollback_error(error_msg, "" if rollback_rules_ok else rollback_rules_error)
        return {"status": "error", "message": error_msg}

    return {
        "status":       "success",
        "config_id":    request.config_id,
        "message":      "Configuration updated and redeployment started.",
        "updated_tool": tool_name,
    }


def get_configuration_options(tool_name: str) -> Dict[str, Any]:
    """
    Return all configurable environment variables for a given tool with their default values.
    Reads defaults directly from the Pydantic model fields by instantiating it with no arguments.
    """
    if tool_name not in TOOL_CONFIG_MODELS:
        return {
            "status":  "error",
            "message": f"Unknown tool '{tool_name}'. Valid tools: {list(TOOL_CONFIG_MODELS.keys())}"
        }

    config_model_class = TOOL_CONFIG_MODELS[tool_name]
    default_instance = config_model_class()
    defaults_dict = default_instance.model_dump()
    hidden_vars = NON_CONFIGURABLE_ENV_VARS.get(tool_name, set())

    variables: List[Dict[str, str]] = []
    for var_name, default_value in defaults_dict.items():
        if var_name in hidden_vars:
            continue
        variables.append({
            "name":          var_name,
            "default_value": str(default_value),
        })

    return {
        "status":                   "success",
        "toolName":                 tool_name,
        "configurable_variables":   variables,
    }


def get_configuration_by_id(config_id: str) -> Dict[str, Any]:
    """
    Retrieve and return a stored deployment configuration from MongoDB CM by its config_id.
    """
    collection = get_mongo_collection()

    if collection is None:
        return {
            "status":  "error",
            "message": "MongoDB CM is unavailable."
        }

    document = get_deployment_from_mongo(collection, config_id)

    if document is None:
        return {
            "status":  "error",
            "message": f"No configuration found with config_id '{config_id}'."
        }

    document.pop("_id", None)
    if "resolved_env" in document and isinstance(document["resolved_env"], dict):
        document["resolved_env"] = build_public_resolved_env(document["resolved_env"])

    return {
        "status":    "success",
        "config_id": config_id,
        "data":      document,
    }


def get_kafka_topics_state() -> Dict[str, Any]:
    """
    Return the current kafka_topics state document from MongoDB CM.
    Useful for debugging and for the API to expose the current topic map.
    """
    collection = get_mongo_collection()

    if collection is None:
        return {
            "status":  "error",
            "message": "MongoDB CM is unavailable."
        }

    topics = get_kafka_topics_from_mongo(collection)

    if not topics:
        return {
            "status":  "not_found",
            "message": "No kafka_topics document found. Deploy at least one producer tool first.",
            "topics":  {}
        }

    return {
        "status": "success",
        "topics": topics,
    }
