#!/usr/bin/env python3

import os
import subprocess
import platform
import sys
import secrets
import string
import json
from pathlib import Path
import argparse
import socket

from collections import OrderedDict
from typing import Dict, Iterable, List, Tuple, Optional
from urllib.parse import quote_plus

LAUNCHER_DIR = Path(__file__).resolve().parent
if str(LAUNCHER_DIR) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_DIR))

from internal_external_tools_models import (  # noqa: E402
    DEFAULT_ENV_MODEL_CLASSES,
    combine_model_defaults,
    TOOL_ENV_VARS,
)

# NOTE: thingsboard_module is intentionally not ported — NOVADEF doesn't use
# ThingsBoard. alert_manager is NOVADEF-specific (TAPCD integration, not
# present in ROBUST-6G_PMP). The Configuration Manager API itself (unlike
# nrtdr/hdr/dt APIs) isn't a docker container in ROBUST-6G_PMP either — it's
# started directly via uvicorn (see the now-not-ported bootstrap_gui_backend.py
# for reference) and still needs its own launch path here if/when it's wired up.
MODULE_COMPOSE_FILES: Dict[str, List[str]] = {
    "communication_module": [
        "Communication_Bus/Docker/communication_bus_compose.yml",
    ],
    "apis_module": [
        "APIs/rest_apis.yml",
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


class cmd_parser:
    """
    Parse CLI arguments to select docker-compose modules (files/stacks) and
    their service profiles (tools).
    """

    MODULE_REGISTRY: Dict[str, List[str]] = {
        "alert_module":         ["alert_module", "network_intrusion_detector"],
        "alert_manager":        ["alert_manager"],
        "apis_module":          ["nrtdr_api", "hdr_api", "dt_api"],
        "communication_module": ["kafka", "filebeat"],
        "collection_module":    ["fluentd", "telegraf", "tshark", "falco", "info"],
        "flow_module":          ["flow_module"],
        "db_module":            ["mongodb", "mongodb_cm", "postgres_gui", "redis", "mimir"],
        "aggregation_module":   ["prometheus", "opensearch"],
    }

    def __init__(self) -> None:
        self._parser = self._make_parser()

    def parse(self, argv: Optional[List[str]] = None) -> Tuple[argparse.Namespace, "OrderedDict[str, List[str]]"]:
        """
        Parse argv and return (args, selected) where selected maps module -> list of tools.
        """
        args = self._parser.parse_args(argv)

        if args.global_all == "all":
            selected = self._select_all()
            return args, selected

        if not args.modules and not args.tools:
            selected = self._select_all()
            return args, selected

        self._validate_pair_mode(args)
        selected = self._build_selected_from_pairs(args.modules, args.tools)
        return args, selected

    def build_compose_profiles(self, selected: "OrderedDict[str, List[str]]") -> List[str]:
        """
        Build docker compose profile list as module.tool strings.
        """
        profiles: List[str] = []
        for module, tools in selected.items():
            for tool in tools:
                profiles.append(f"{module}.{tool}")
        return profiles

    def _make_parser(self) -> argparse.ArgumentParser:
        """
        Create and return the argument parser with all CLI options.
        """
        p = argparse.ArgumentParser(
            prog="start_containers.py",
            description="Select docker-compose modules (files) and their service profiles (tools)."
        )
        p.add_argument("global_all", nargs="?", choices=["all"], default=None,
                       help="Enable all tools of all modules.")
        p.add_argument("-m", "--module", dest="modules", action="append",
                       metavar="MODULE",
                       help=f"Module name. Choices: {', '.join(self.MODULE_REGISTRY.keys())}. "
                            "Can be repeated.")
        p.add_argument("-t", "--tools", dest="tools", action="append",
                       metavar="TOOLS",
                       help="Tools for the preceding -m. Use 'all' or a comma/space-separated list. "
                            "Can be repeated.")
        p.add_argument("--debug", default=None,
                       help="Debug flags to forward.")
        p.add_argument("--env-overrides", default=None,
                       help="Path to a JSON file with env var overrides (used by the Configuration Manager API).")
        return p

    def _validate_pair_mode(self, args: argparse.Namespace) -> None:
        """
        Validate that modules and tools were provided in matching pairs.
        """
        if not args.modules or not args.tools:
            self._parser.error("You must provide matching -m/--module and -t/--tools pairs.")
        if len(args.modules) != len(args.tools):
            self._parser.error("The number of -m and -t occurrences must match (paired by position).")

        unknown = [m for m in args.modules if m not in self.MODULE_REGISTRY]
        if unknown:
            choices = ", ".join(self.MODULE_REGISTRY.keys())
            self._parser.error(f"Unknown module(s): {', '.join(unknown)}. Valid modules: {choices}.")

    def _select_all(self) -> "OrderedDict[str, List[str]]":
        """
        Return an OrderedDict mapping every module to all its tools.
        """
        selected: "OrderedDict[str, List[str]]" = OrderedDict()
        for m, tools in self.MODULE_REGISTRY.items():
            selected[m] = list(tools)
        return selected

    def _split_tools(self, s: str) -> List[str]:
        """
        Split a tools specification string into individual tokens, accepting comma or space separators.
        """
        s = s.strip()
        if s.lower() == "all":
            return ["all"]
        parts = [t.strip() for t in s.replace(",", " ").split()]
        return [t for t in parts if t]

    def _expand_tools(self, module: str, tool_tokens: List[str]) -> List[str]:
        """
        Expand and validate tool tokens for a given module, returning deduplicated ordered list.
        """
        if len(tool_tokens) == 1 and tool_tokens[0].lower() == "all":
            return list(self.MODULE_REGISTRY[module])

        valid = set(self.MODULE_REGISTRY[module])
        unknown = [t for t in tool_tokens if t not in valid]
        if unknown:
            choices = ", ".join(self.MODULE_REGISTRY[module])
            self._parser.error(
                f"Unknown tool(s) for {module}: {', '.join(unknown)}. "
                f"Valid tools: {choices}."
            )
        seen = set()
        ordered: List[str] = []
        for t in tool_tokens:
            if t not in seen:
                seen.add(t)
                ordered.append(t)
        return ordered

    def _build_selected_from_pairs(self, modules: List[str], tools: List[str]) -> "OrderedDict[str, List[str]]":
        """
        Build an OrderedDict mapping each module to its expanded list of tools from CLI pairs.
        """
        selected: "OrderedDict[str, List[str]]" = OrderedDict()
        for m, t in zip(modules, tools):
            tokens = self._split_tools(t)
            expanded = self._expand_tools(m, tokens)
            selected[m] = expanded
        return selected


def detect_os() -> str:
    """
    Detect the host operating system and return a network mode string (host/bridge/error).
    """
    system = platform.system().lower()
    print(f"Detected OS: {system}")
    if system == "linux":
        return "host"
    elif system == "windows" or system == "darwin":
        return "bridge"
    else:
        return "error"


def generate_secure_password(length: int = 20) -> str:
    """
    Generate a cryptographically secure random password with mixed character types.
    """
    alphabet = string.ascii_letters + string.digits + "!@%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#%^&*" for c in password)):
            return password


def get_existing_password(env_path: Path, password_tool: str) -> Optional[str]:
    """
    Read an existing password from the .env file to avoid regenerating it on each run.
    """
    if not env_path.exists():
        return None
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith(password_tool):
                    return line.strip().split("=", 1)[1]
    except Exception:
        return None
    return None


def get_host_ip() -> str:
    """
    Get the current LAN IP address of the machine by opening a UDP socket without sending data.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def collect_env_vars(
    selected: "OrderedDict[str, List[str]]",
    tool_env_vars: Dict[str, List[str]],
    always_env_vars: Optional[List[str]] = None
) -> List[str]:
    """
    Return an ordered deduplicated list of env var names required by the active tools plus always-required vars.
    """
    seen = set()
    out: List[str] = []

    if always_env_vars:
        for env_key in always_env_vars:
            if env_key not in seen:
                seen.add(env_key)
                out.append(env_key)

    for modules, tools in selected.items():
        for tool in tools:
            for env_key in tool_env_vars.get(tool, []):
                if env_key not in seen:
                    seen.add(env_key)
                    out.append(env_key)

    return out


def write_dotenv(
    env_keys: Iterable[str],
    path: "str | Path",
    defaults: Optional[Dict[str, str]] = None,
    header: str = ""
) -> Path:
    """
    Write a .env file with the provided keys, using defaults dict for values when available.
    """
    env_path = Path(path)

    lines: List[str] = []
    if header:
        lines.append(header.rstrip("\n"))

    for key in env_keys:
        raw_value = "" if defaults is None else defaults.get(key, "")
        value = str(raw_value)

        if any(c.isspace() for c in value) or any(c in value for c in ['"', "'"]):
            value = value.replace('"', '\\"')
            lines.append(f'{key}="{value}"')
        else:
            lines.append(f"{key}={value}")

    if env_path.exists():
        try:
            os.remove(env_path)
            print(f"File {env_path} removed")
        except PermissionError:
            print(f"Insufficient permissions to remove file: {env_path}")
        except Exception as e:
            print(f"Error removing file {env_path}: {e}")

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return env_path


def build_selected_compose_files(
    selected: "OrderedDict[str, List[str]]",
    base_dir: Path,
    module_compose_files: Dict[str, List[str]]
) -> List[str]:
    """
    Build an ordered deduplicated list of absolute docker compose file paths for the selected modules.
    """
    seen = set()
    compose_files: List[str] = []

    for module in selected.keys():
        for rel_path in module_compose_files.get(module, []):
            abs_path = str((base_dir / rel_path).resolve())
            if abs_path not in seen:
                seen.add(abs_path)
                compose_files.append(abs_path)

    return compose_files


def build_default_env(
    mid: str,
    network_mode: str,
    PFD: Path,
    compose_profiles: str,
    env_file_path: Path
) -> Dict[str, str]:
    """
    Build and return the runtime environment dictionary used by the launcher.
    The base values come from the shared Pydantic models, while passwords and
    host-dependent values are resolved dynamically from the local environment.
    """
    container_timezone = "UTC"
    default_env = combine_model_defaults(*DEFAULT_ENV_MODEL_CLASSES)

    kafka_lan_hostname = default_env["KAFKA_LAN_HOSTNAME"]
    kafka_port_external_lan = default_env["KAFKA_PORT_EXTERNAL_LAN"]
    kafka_port_internal = default_env["KAFKA_PORT_INTERNAL"]
    kafka_bootstrap = f"{kafka_lan_hostname}:{kafka_port_external_lan}"
    kafka_bootstrap_docker = f"kafka_novadef:{kafka_port_internal}"

    opensearch_password = get_existing_password(
        env_path=env_file_path,
        password_tool="OPENSEARCH_PASSWORD=",
    )
    if not opensearch_password:
        opensearch_password = generate_secure_password()

    if network_mode == "host":
        opensearch_host = get_host_ip()
    else:
        opensearch_host = default_env["OPENSEARCH_HOST"]

    mongo_initdb_root_username = default_env["MONGO_INITDB_ROOT_USERNAME"]
    mongo_initdb_root_password = get_existing_password(
        env_path=env_file_path,
        password_tool="MONGO_INITDB_ROOT_PASSWORD=",
    )
    if not mongo_initdb_root_password:
        mongo_initdb_root_password = generate_secure_password()
    mongo_port = default_env["MONGO_PORT"]
    mongo_uri = (
        f"mongodb://{mongo_initdb_root_username}:"
        f"{quote_plus(mongo_initdb_root_password)}"
        f"@mongodb:{mongo_port}/?authSource=admin"
    )

    snort_db_user_name = default_env["SNORT_DB_USER_NAME"]
    snort_db_user_password = get_existing_password(
        env_path=env_file_path,
        password_tool="SNORT_DB_USER_PASSWORD=",
    )
    if not snort_db_user_password:
        snort_db_user_password = generate_secure_password()
    mongo_snort_uri = (
        f"mongodb://{snort_db_user_name}:"
        f"{quote_plus(snort_db_user_password)}"
        f"@mongodb:{mongo_port}/?authSource=admin"
    )

    flow_db_writer_name = default_env["FLOW_DB_WRITER_NAME"]
    flow_db_writer_password = get_existing_password(
        env_path=env_file_path,
        password_tool="FLOW_DB_WRITER_PASSWORD=",
    )
    if not flow_db_writer_password:
        flow_db_writer_password = generate_secure_password()
    mongo_flow_writer_uri = (
        f"mongodb://{flow_db_writer_name}:"
        f"{quote_plus(flow_db_writer_password)}"
        f"@mongodb:{mongo_port}/?authSource=admin"
    )

    flow_db_reader_name = default_env["FLOW_DB_READER_NAME"]
    flow_db_reader_password = get_existing_password(
        env_path=env_file_path,
        password_tool="FLOW_DB_READER_PASSWORD=",
    )
    if not flow_db_reader_password:
        flow_db_reader_password = generate_secure_password()
    mongo_flow_reader_uri = (
        f"mongodb://{flow_db_reader_name}:"
        f"{quote_plus(flow_db_reader_password)}"
        f"@mongodb:{mongo_port}/?authSource=admin"
    )

    mongo_cm_initdb_root_username = default_env["MONGO_CM_INITDB_ROOT_USERNAME"]
    mongo_cm_initdb_root_password = get_existing_password(
        env_path=env_file_path,
        password_tool="MONGO_CM_INITDB_ROOT_PASSWORD=",
    )
    if not mongo_cm_initdb_root_password:
        mongo_cm_initdb_root_password = generate_secure_password()
    mongo_cm_port = default_env["MONGO_CM_PORT"]
    mongo_cm_uri_docker = (
        f"mongodb://{mongo_cm_initdb_root_username}:"
        f"{quote_plus(mongo_cm_initdb_root_password)}"
        f"@mongodb_cm:27017/?authSource=admin"
    )
    mongo_cm_uri_host = (
        f"mongodb://{mongo_cm_initdb_root_username}:"
        f"{quote_plus(mongo_cm_initdb_root_password)}"
        f"@localhost:{mongo_cm_port}/?authSource=admin"
    )

    default_env.update(
        {
            "MACHINE_ID": mid,
            "NETWORK_MODE": network_mode,
            "PFD": str(PFD),
            "COMPOSE_PROFILES": compose_profiles,
            "TZ": container_timezone,
            "KAFKA_BOOTSTRAP": kafka_bootstrap,
            "KAFKA_BOOTSTRAP_DOCKER": kafka_bootstrap_docker,
            "KAFKA_LAN_HOSTNAME": kafka_lan_hostname,
            "KAFKA_PORT_EXTERNAL_LAN": kafka_port_external_lan,
            "KAFKA_PORT_INTERNAL": kafka_port_internal,
            "DISCOVERY_AGENT_SCAN_PORT": default_env["DEVICE_INFO_PORT"],
            "DISCOVERY_AGENT_REFRESH_INTERVAL": default_env["DISCOVERY_AGENT_REFRESH_INTERVAL"],
            "OPENSEARCH_PASSWORD": opensearch_password,
            "OPENSEARCH_HOST": opensearch_host,
            "MONGO_INITDB_ROOT_PASSWORD": mongo_initdb_root_password,
            "MONGO_URI": mongo_uri,
            "SNORT_DB_USER_PASSWORD": snort_db_user_password,
            "MONGO_SNORT_URI": mongo_snort_uri,
            "FLOW_DB_WRITER_PASSWORD": flow_db_writer_password,
            "MONGO_FLOW_WRITER_URI": mongo_flow_writer_uri,
            "FLOW_DB_READER_PASSWORD": flow_db_reader_password,
            "MONGO_FLOW_READER_URI": mongo_flow_reader_uri,
            "MONGO_CM_INITDB_ROOT_PASSWORD": mongo_cm_initdb_root_password,
            "MONGO_CM_URI": mongo_cm_uri_docker,
            "MONGO_CM_URI_DOCKER": mongo_cm_uri_docker,
            "MONGO_CM_URI_HOST": mongo_cm_uri_host,
        }
    )

    return default_env


# Variables that always go into every .env regardless of selected tools.
# These are generated internally and cannot be overridden via the API.
ALWAYS_ENV_VARS: List[str] = [
    "MACHINE_ID",
    "NETWORK_MODE",
    "PFD",
    "COMPOSE_PROFILES",
    "TZ",
    "KAFKA_BOOTSTRAP",
    "KAFKA_BOOTSTRAP_DOCKER",
    "KAFKA_LAN_HOSTNAME",   # needed by extra_hosts in many containers to resolve Kafka DNS
]


# Vars exposed to components outside the PMP (MISP, TAPCD) via the external
# contract file — root credentials are deliberately excluded.
EXTERNAL_CONTRACT_ENV_VARS: List[str] = [
    "MONGO_FLOW_WRITER_URI",
    "MONGO_FLOW_READER_URI",
]


def write_external_contract_env(default_env: Dict[str, str], repo_root: Path) -> Path:
    """Write the external contract .env file (NOVADEF root) consumed by MISP/TAPCD/NOVADEF_GUI."""
    contract_path = repo_root.parent / ".novadef_external_env"
    return write_dotenv(
        env_keys=EXTERNAL_CONTRACT_ENV_VARS,
        path=contract_path,
        defaults=default_env,
        header="# Auto-generated by start_containers.py. Do not edit by hand.",
    )


def launch(
    selected: "OrderedDict[str, List[str]]",
    env_overrides: Optional[Dict[str, str]] = None
) -> None:
    """
    Core launch function: resolves env vars, writes .env, and runs docker compose up.
    Called both from CLI (main) and from configuration_manager_logic.py (API).
    env_overrides contains tool-specific variables already resolved (including real topic values).
    ALWAYS_ENV_VARS are never replaced by env_overrides.
    """
    try:
        LFD = Path(__file__).resolve().parent
        mid_py = LFD / "machine_id" / "machine_id.py"
        mid = subprocess.check_output(
            [sys.executable, str(mid_py)],
            text=True
        ).strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing machine_id.py: {e}")
        return

    network_mode = detect_os()
    PFD = Path(__file__).resolve().parent.parent
    init_env_file_path = Path(__file__).resolve().parent / ".init_pmp_env"
    env_file_path = Path(__file__).resolve().parent / ".env"

    # Add info tool automatically when collection_module is selected
    if "collection_module" in selected and "info" not in selected["collection_module"]:
        selected["collection_module"].append("info")

    compose_profiles_list = cmd_parser().build_compose_profiles(selected)
    compose_profiles = ",".join(compose_profiles_list)

    print("Selected:", selected)
    print("COMPOSE_PROFILES:", compose_profiles_list)

    # build_default_env reads existing passwords from init_env_file_path to avoid regenerating them.
    default_env = build_default_env(
        mid=mid,
        network_mode=network_mode,
        PFD=PFD,
        compose_profiles=compose_profiles,
        env_file_path=init_env_file_path
    )

    # Apply overrides from API - ALWAYS_ENV_VARS are protected and never replaced
    if env_overrides:
        for key, value in env_overrides.items():
            if key not in ALWAYS_ENV_VARS:
                default_env[key] = str(value)

    env_keys = collect_env_vars(
        selected=selected,
        tool_env_vars=TOOL_ENV_VARS,
        always_env_vars=ALWAYS_ENV_VARS
    )

    # On first run (init_pmp_env does not exist yet) write the full env as the
    # persistent reference file so subsequent runs can read generated passwords.
    if not init_env_file_path.exists():
        write_dotenv(
            env_keys=list(default_env.keys()),
            path=init_env_file_path,
            defaults=default_env,
            header=""
        )
        print(f"Initial PMP env written to {init_env_file_path}")

        written_path = init_env_file_path
    else:
        written_path = write_dotenv(
            env_keys=env_keys,
            path=env_file_path,
            defaults=default_env,
            header=""
        )

    write_external_contract_env(default_env=default_env, repo_root=PFD)

    selected_compose_files = build_selected_compose_files(
        selected=selected,
        base_dir=PFD,
        module_compose_files=MODULE_COMPOSE_FILES
    )

    if not selected_compose_files:
        print("No docker compose files resolved for the selected modules.")
        return

    print("Compose files:", selected_compose_files)

    compose_cmd = ["docker", "compose"]

    for profile in compose_profiles_list:
        compose_cmd.extend(["--profile", profile])

    for compose_file in selected_compose_files:
        compose_cmd.extend(["-f", compose_file])

    compose_cmd.extend([
        "--project-directory", str(PFD),
        "--env-file", str(written_path),
        "up", "--build", "-d", "--force-recreate"
    ])

    try:
        compose_env = os.environ.copy()
        for key in env_keys:
            compose_env.pop(key, None)
        compose_env["COMPOSE_IGNORE_ORPHANS"] = "1"

        subprocess.run(compose_cmd, check=True, env=compose_env)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error executing docker compose: {e}") from e


def main() -> None:
    """
    CLI entry point: parses arguments and calls launch().
    """
    parser_obj = cmd_parser()
    args, selected = parser_obj.parse()

    env_overrides = None
    if args.env_overrides:
        try:
            with open(args.env_overrides, "r", encoding="utf-8") as f:
                env_overrides = json.load(f)
        except Exception as e:
            print(f"Warning: could not load env overrides file: {e}")

    launch(selected=selected, env_overrides=env_overrides)


if __name__ == "__main__":
    main()
