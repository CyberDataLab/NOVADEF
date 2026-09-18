#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from launcher_common import (
    API_PID_FILE,
    API_TOOL_CONTAINERS,
    BASE_CONTAINERS,
    ASSOCIATED_CONTAINERS,
    BOOTSTRAP_LOG_FILE,
    HDR_API_CONTAINER_NAME,
    DT_API_CONTAINER_NAME,
    INTERNAL_LOGS_DIR,
    LAUNCHER_ENV_FILE,
    MODULE_COMPOSE_FILES,
    NRTDR_API_CONTAINER_NAME,
    REPO_ROOT,
    RUNTIME_DIR,
    STATE_FILE,
    ensure_runtime_directories,
)

DEFAULT_PURGE_NAME_PATTERN = "novadef"


class StopError(RuntimeError):
    """Raised when the shutdown flow cannot continue safely."""


class StopLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path

    def log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {message}"
        print(line)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Stop the PMP backend environment: Configuration Manager API, "
            "NRTDR API, HDR API, Data Exporter API, API-launched tool "
            "containers, and optionally the base stack. Without flags it "
            "stops all four APIs and API-launched tool containers."
        ),
        epilog=(
            "Examples:\n"
            "  python3 Launcher/stop_pmp_backend.py\n"
            "  python3 Launcher/stop_pmp_backend.py --stop-base\n"
            "  python3 Launcher/stop_pmp_backend.py --stop-all\n"
            "  python3 Launcher/stop_pmp_backend.py --purge\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--logs-dir",
        default=str(INTERNAL_LOGS_DIR),
        help="Directory where the stop script appends its log output.",
    )
    parser.add_argument(
        "--stop-api",
        action="store_true",
        help="Stop the Configuration Manager API process.",
    )
    parser.add_argument(
        "--stop-nrtdr-api",
        action="store_true",
        help="Stop the NRTDR API process.",
    )
    parser.add_argument(
        "--stop-hdr-api",
        action="store_true",
        help="Stop the HDR API container.",
    )
    parser.add_argument(
        "--stop-dt-api",
        action="store_true",
        help="Stop the Data Exporter API container.",
    )
    parser.add_argument(
        "--stop-api-tools",
        action="store_true",
        help="Remove containers launched dynamically through the API.",
    )
    parser.add_argument(
        "--stop-base",
        action="store_true",
        help="Stop the base containers: Kafka, Filebeat, MongoDB, MongoDB CM, Postgres GUI, Redis and the Redis worker.",
    )
    parser.add_argument(
        "--stop-all",
        action="store_true",
        help="Stop API, API-launched containers and base containers in one command.",
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help=(
            "Stop the API process, remove every container whose name matches "
            "the purge pattern, and then run a full docker compose down with volumes "
            "and orphans for the PMP."
        ),
    )
    parser.add_argument(
        "--purge-name-pattern",
        default=DEFAULT_PURGE_NAME_PATTERN,
        help=(
            "Substring used by --purge to remove matching container names "
            f"(default: {DEFAULT_PURGE_NAME_PATTERN})."
        ),
    )
    return parser.parse_args()


def is_process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_pid(pid_path: Path) -> Optional[int]:
    if not pid_path.exists():
        return None

    try:
        return int(pid_path.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def remove_pid_file(pid_path: Path) -> None:
    if pid_path.exists():
        pid_path.unlink()


def terminate_pid(pid: int, logger: StopLogger, label: str) -> None:
    if not is_process_running(pid):
        logger.log(f"No live {label} process found for PID {pid}.")
        return

    logger.log(f"Stopping {label} process with PID {pid}.")
    os.kill(pid, signal.SIGTERM)
    for _ in range(20):
        if not is_process_running(pid):
            return
        time.sleep(0.5)

    logger.log(f"Force killing {label} process with PID {pid}.")
    os.kill(pid, signal.SIGKILL)


def remove_docker_containers(
    container_names: Iterable[str],
    logger: StopLogger,
    label: str,
) -> None:
    logger.log(f"Removing {label}.")
    for container_name in container_names:
        completed = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            text=True,
            capture_output=True,
            check=False,
        )
        names = completed.stdout.splitlines()
        if container_name not in names:
            logger.log(f"Container {container_name} is not present; skipping.")
            continue

        logger.log(f"Removing container {container_name}.")
        remove_completed = subprocess.run(
            ["docker", "rm", "-f", container_name],
            text=True,
            capture_output=True,
            check=False,
        )
        if remove_completed.returncode != 0:
            raise StopError(
                f"Failed to remove container {container_name}: {remove_completed.stderr.strip()}"
            )


def remove_matching_docker_containers(
    name_pattern: str,
    logger: StopLogger,
) -> None:
    if not name_pattern:
        raise StopError("The purge name pattern cannot be empty.")

    logger.log(
        f"Removing all docker containers whose name contains '{name_pattern}'."
    )
    completed = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise StopError(
            f"Failed to list docker containers: {completed.stderr.strip()}"
        )

    matching_names = [
        container_name
        for container_name in completed.stdout.splitlines()
        if name_pattern in container_name
    ]
    if not matching_names:
        logger.log(f"No docker containers matched '{name_pattern}'.")
        return

    for container_name in matching_names:
        logger.log(f"Removing matched container {container_name}.")
        remove_completed = subprocess.run(
            ["docker", "rm", "-f", container_name],
            text=True,
            capture_output=True,
            check=False,
        )
        if remove_completed.returncode != 0:
            raise StopError(
                f"Failed to remove matched container {container_name}: "
                f"{remove_completed.stderr.strip()}"
            )


def purge_compose_resources(logger: StopLogger) -> None:
    if not LAUNCHER_ENV_FILE.exists():
        logger.log(
            f"Launcher environment file not found at {LAUNCHER_ENV_FILE}; "
            "skipping compose down after direct container purge."
        )
        return

    compose_files: list[str] = []
    for module_paths in MODULE_COMPOSE_FILES.values():
        for relative_path in module_paths:
            compose_files.extend(["-f", str((REPO_ROOT / relative_path).resolve())])

    command = [
        "docker",
        "compose",
        *compose_files,
        "--project-directory",
        str(REPO_ROOT),
        "--env-file",
        str(LAUNCHER_ENV_FILE),
        "down",
        "--volumes",
        "--remove-orphans",
    ]
    logger.log("Running full PMP compose purge.")
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.stdout.strip():
        logger.log(completed.stdout.rstrip())
    if completed.stderr.strip():
        logger.log(completed.stderr.rstrip())
    if completed.returncode != 0:
        raise StopError(
            "Failed to purge PMP compose resources: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )


def main() -> int:
    args = parse_args()
    logs_dir = ensure_runtime_directories(Path(args.logs_dir).resolve())
    logger = StopLogger(logs_dir / BOOTSTRAP_LOG_FILE.name)

    try:
        purge = args.purge
        no_flags_given = not any(
            [
                args.stop_api,
                args.stop_nrtdr_api,
                args.stop_hdr_api,
                args.stop_dt_api,
                args.stop_api_tools,
                args.stop_base,
                args.purge,
            ]
        )
        stop_api = args.stop_all or args.stop_api or no_flags_given
        if purge:
            stop_api = True
        stop_nrtdr_api = args.stop_all or args.stop_nrtdr_api or no_flags_given
        if purge:
            stop_nrtdr_api = True
        stop_hdr_api = args.stop_all or args.stop_hdr_api or no_flags_given
        if purge:
            stop_hdr_api = True
        stop_dt_api = args.stop_all or args.stop_dt_api or no_flags_given
        if purge:
            stop_dt_api = True
        stop_api_tools = args.stop_all or args.stop_api_tools or no_flags_given
        if purge:
            stop_api_tools = True
        stop_base = args.stop_all or args.stop_base or purge

        if stop_api:
            pid = read_pid(API_PID_FILE)
            if pid is None:
                logger.log("No managed Configuration Manager API PID file found.")
            else:
                terminate_pid(pid, logger, "Configuration Manager API")
                remove_pid_file(API_PID_FILE)

        if stop_nrtdr_api:
            remove_docker_containers(
                [NRTDR_API_CONTAINER_NAME],
                logger,
                "NRTDR API container",
            )

        if stop_hdr_api:
            remove_docker_containers(
                [HDR_API_CONTAINER_NAME],
                logger,
                "HDR API container",
            )

        if stop_dt_api:
            remove_docker_containers(
                [DT_API_CONTAINER_NAME],
                logger,
                "Data Exporter API container",
            )

        if stop_api_tools:
            remove_docker_containers(API_TOOL_CONTAINERS, logger, "API-launched tool containers")

        if stop_base:
            remove_docker_containers(BASE_CONTAINERS + ASSOCIATED_CONTAINERS, logger, "base containers")

        if purge:
            remove_matching_docker_containers(args.purge_name_pattern, logger)
            purge_compose_resources(logger)

        if STATE_FILE.exists():
            STATE_FILE.unlink()

        if RUNTIME_DIR.exists() and not any(RUNTIME_DIR.iterdir()):
            RUNTIME_DIR.rmdir()

        logger.log("Stop sequence completed successfully.")
        return 0
    except StopError as exc:
        logger.log(f"Stop sequence failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
