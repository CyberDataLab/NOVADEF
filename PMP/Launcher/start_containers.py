#!/usr/bin/env python3

import subprocess
import platform
import sys
import secrets
import string
from pathlib import Path
import argparse
import socket

from collections import OrderedDict
from typing import Dict, List, Tuple, Optional

class cmd_parser:
    """
    Parse CLI arguments to select docker-compose modules (files/stacks) and
    their service profiles (tools).

    Behaviors:
      - "all" positional (e.g., "python3 main.py all") -> all modules, all tools
      - No args -> all modules, all tools
      - Repeated pairs: "-m <module> -t <tools>"; "tools" can be:
           * "all" (expands to every tool in that module)
           * a comma/space-separated list (e.g., "telegraf, fluentd")
      - Returns:
           * selected: OrderedDict[str, List[str]]  (module -> list of tools)
           * compose profiles: List[str]            (e.g., ["collection_module.telegraf", ...])
    """

    # Dictionary that associates a module with its service.
    MODULE_REGISTRY: Dict[str, List[str]] = {
        "alert_module":         ["alert_module"],
        "communication_module": ["kafka", "filebeat"],
        "collection_module":    ["fluentd", "telegraf", "tshark", "falco", "info"],
        "flow_module":          ["flow_module"],
        "db_module":            ["mongodb"],
        "aggregation_module":   ["prometheus", "opensearch"], 
    }

    def __init__(self) -> None:
        self._parser = self._make_parser()

    def parse(self, argv: Optional[List[str]] = None) -> Tuple[argparse.Namespace, "OrderedDict[str, List[str]]"]:
        """
        Parse argv and return (args, selected).
        "selected" is an OrderedDict mapping module -> list of tools.
        """
        args = self._parser.parse_args(argv)

        # Case A: explicit global 'all' positional
        if args.global_all == "all":
            selected = self._select_all()
            return args, selected

        # Case B: no -m/-t provided -> default to all
        if not args.modules and not args.tools:
            selected = self._select_all()
            return args, selected

        # Case C: paired -m/-t mode
        self._validate_pair_mode(args)
        selected = self._build_selected_from_pairs(args.modules, args.tools)
        return args, selected

    def build_compose_profiles(self, selected: "OrderedDict[str, List[str]]") -> List[str]:
        """
        Build docker compose profile list like:
            module.tool
        (one entry per selected tool)
        """
        profiles: List[str] = []
        for module, tools in selected.items():
            for tool in tools:
                profiles.append(f"{module}.{tool}")
        return profiles


    def _make_parser(self) -> argparse.ArgumentParser:
        """
        Create and return an argparse.ArgumentParser configured with the script's CLI options.

        The parser supports:
        - an optional positional "all" to select everything,
        - repeated -m/--module and -t/--tools pairs,
        - an optional --debug passthrough.
        """
        p = argparse.ArgumentParser(
            prog="start_containers.py",
            description="Select docker-compose modules (files) and their service profiles (tools)."
        )
        # Positional 'all' (optional). Example: `python3 main.py all`
        p.add_argument("global_all", nargs="?", choices=["all"], default=None,
                       help="Enable all tools of all modules.")

        # Repeated pairs: -m <module> ... -t <tools> ...
        p.add_argument("-m", "--module", dest="modules", action="append",
                       metavar="MODULE",
                       help=f"Module name. Choices: {', '.join(self.MODULE_REGISTRY.keys())}. "
                            "Can be repeated.")
        p.add_argument("-t", "--tools", dest="tools", action="append",
                       metavar="TOOLS",
                       help="Tools for the preceding -m. Use 'all' or a comma/space-separated list "
                            "(e.g., 'telegraf, fluentd'). Can be repeated.")

        # Optional debug flag passthrough
        p.add_argument("--debug", default=None,
                       help="Debug flags to forward (e.g., 'cgrp,topic,fetch,protocol').")
        return p

    def _validate_pair_mode(self, args: argparse.Namespace) -> None:
        """
        Validate that modules and tools were provided in matching pairs and that
        module names exist in MODULE_REGISTRY. On error, call parser.error() to
        display a helpful message and exit.
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
        Return an OrderedDict mapping every registered module to a copy of its
        list of tools (i.e., select all tools for all modules).
        """
        selected: "OrderedDict[str, List[str]]" = OrderedDict()
        for m, tools in self.MODULE_REGISTRY.items():
            selected[m] = list(tools)
        return selected

    def _split_tools(self, s: str) -> List[str]:
        """
        Split a tools specification string into individual tokens.

        Behavior:
        - If the string is 'all' (case-insensitive), return ['all'].
        - Otherwise accept commas and/or whitespace as separators and return a
          list of non-empty tokens in input order.
        """
        s = s.strip()
        if s.lower() == "all":
            return ["all"]
        parts = [t.strip() for t in s.replace(",", " ").split()]
        return [t for t in parts if t]

    def _expand_tools(self, module: str, tool_tokens: List[str]) -> List[str]:
        """
        Expand and validate tool tokens for a given module.

        - If the single token is 'all', expand to all registered tools for that module.
        - Otherwise verify each token exists for the module; on unknown tokens call
          parser.error() with a descriptive message.
        - Preserve the input order and remove duplicates.
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
        Build and return an OrderedDict mapping each provided module to its
        expanded list of tools by zipping the modules and tools lists and
        applying token splitting and expansion.
        """
        selected: "OrderedDict[str, List[str]]" = OrderedDict()
        for m, t in zip(modules, tools):
            tokens = self._split_tools(t)
            expanded = self._expand_tools(m, tokens)
            selected[m] = expanded
        return selected

def detect_os():
    """
    Detect the host operating system and return a network mode string.
    Returns:
    - 'host' for Linux
    - 'bridge' for Windows or macOS (darwin)
    - 'error' for unknown systems
    """
    system = platform.system().lower()
    print(f"Detected OS: {system}")
    if system == "linux":
        return "host"
    elif system == "windows" or system == "darwin":
        return "bridge"
    else:
        return "error"

def generate_secure_password(length=20):
    alphabet = string.ascii_letters + string.digits + "!@#%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#%^&*" for c in password)):
            return password

def get_existing_password(env_path: Path) -> Optional[str]:
    if not env_path.exists():
        return None
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("OPENSEARCH_PASSWORD="):
                    return line.strip().split("=", 1)[1]
    except Exception:
        return None
    return None

def get_host_ip():
    """
    Get the current LAN IP address of the machine.
    This avoids using "127.0.0.1"  ensuring that 
    services talk to a real network interface.
    """
    try:
        # No data is actually sent.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback only if absolutely no network is available
        return "127.0.0.1"

def main():
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
    
    # LOGIC: Define Architecture via Environment Variable
    # In Host mode (Linux) -> Real LAN IP, NOT localhost.
    # In Bridge mode ->  internal docker OpenSearch service name.
    if network_mode == "host":
        opensearch_host = get_host_ip()
        print(f"[+] Host Network detected. Using LAN IP for OpenSearch: {opensearch_host}")
    else:
        opensearch_host = "opensearch-node"
        print(f"[+] Bridge Network detected. Using internal DNS: {opensearch_host}")

    parser = cmd_parser()
    args, selected = parser.parse()

    compose_profiles_list = parser.build_compose_profiles(selected)
    telegraf = "0"
    fluentd = "0"
    falco = "0"
    
    if "collection_module.telegraf" in compose_profiles_list:
        telegraf = "1"
    if "collection_module.fluentd" in compose_profiles_list:
        fluentd = "1"
    if "collection_module.falco" in compose_profiles_list:
        falco = "1"

    # Only activate the info_device microservice if Prometheus is requested
    if "aggregation_module" in compose_profiles_list:
        compose_profiles_list.append("collection_module.info")

    compose_profiles = ",".join(compose_profiles_list)
    print("Selected:", selected)
    print("COMPOSE_PROFILES:", compose_profiles_list)
    if args.debug:
        print("Debug flags:", args.debug)

    PFD = Path(__file__).resolve().parent.parent 
    env_file_path = LFD / ".env"

    opensearch_pass = get_existing_password(env_file_path)
    if not opensearch_pass:
        print("[*] Generating new secure password for OpenSearch...")
        opensearch_pass = generate_secure_password()
    else:
        print("[*] Using existing OpenSearch password from .env")

    with open(env_file_path, "w", encoding="utf-8") as f:
        f.write(f"MACHINE_ID={mid}\n")
        f.write(f"NETWORK_MODE={network_mode}\n")
        f.write(f"PFD={PFD}\n") 
        f.write(f"COMPOSE_PROFILES={compose_profiles}\n")
        f.write(f"ENABLE_TELEGRAF={telegraf}\n")
        f.write(f"ENABLE_FLUENTD={fluentd}\n")
        f.write(f"ENABLE_FALCO={falco}\n")
        f.write(f"OPENSEARCH_PASSWORD={opensearch_pass}\n")
        f.write(f"OPENSEARCH_HOST={opensearch_host}\n")

    try:
        subprocess.run(["docker", "compose","-f", f"{str(LFD)}/docker-compose.yml" ,"--env-file",f"{str(LFD)}/.env",  "up", "--build","-d"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing docker-compose: {e}")
        return

if __name__ == "__main__":
    main()