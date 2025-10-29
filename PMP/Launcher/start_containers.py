#!/usr/bin/env python3

import subprocess
import platform
import sys
from pathlib import Path
import argparse

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
        "collection_module":    ["fluentd", "telegraf", "tshark", "falco"],
        "flow_module":          ["flow_module"],
        "db_module":            ["mongodb"],
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

        # Validate module names against registry
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
            selected[m] = list(tools)  # copy
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
        # Accept both commas and whitespace as separators
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
            # Expand to every tool registered for that module
            return list(self.MODULE_REGISTRY[module])

        # Validate each requested tool exists for that module
        valid = set(self.MODULE_REGISTRY[module])
        unknown = [t for t in tool_tokens if t not in valid]
        if unknown:
            choices = ", ".join(self.MODULE_REGISTRY[module])
            self._parser.error(
                f"Unknown tool(s) for {module}: {', '.join(unknown)}. "
                f"Valid tools: {choices}."
            )
        # Preserve input order (and remove duplicates)
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



def main():

    try:
        
        LFD = Path(__file__).resolve().parent # Launcher Folder Directory
        mid_py = LFD / "machine_id" / "machine_id.py"
        mid = subprocess.check_output(
            [sys.executable, str(mid_py)],
            text=True
        ).strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing machine_id.py: {e}")
        return

    network_mode = detect_os()



    parser = cmd_parser()
    args, selected = parser.parse()

    compose_profiles_list = parser.build_compose_profiles(selected)
    compose_profiles = ",".join(compose_profiles_list)
    # Example wiring for your system:
    # start_containers(compose_profiles, debug=args.debug)
    print("Selected:", selected)
    print("COMPOSE_PROFILES:", compose_profiles_list)
    if args.debug:
        print("Debug flags:", args.debug)

    PFD = Path(__file__).resolve().parent.parent # Project Folder Directory

    with open(LFD / ".env", "w", encoding="utf-8") as f:
        f.write(f"MACHINE_ID={mid}\n")
        f.write(f"NETWORK_MODE={network_mode}\n")
        f.write(f"PFD={PFD}\n") 
        f.write(f"COMPOSE_PROFILES={compose_profiles}") # COMPOSE_PROFILES=kafka,filebeat,flow_module,...

    try:

        subprocess.run(["docker", "compose","-f", f"{str(LFD)}/docker-compose.yml" ,"--env-file",f"{str(LFD)}/.env",  "up", "-d"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing docker-compose: {e}")
        return

if __name__ == "__main__":
    main()