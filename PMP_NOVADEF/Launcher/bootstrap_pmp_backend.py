#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from launcher_common import (
    API_PID_FILE,
    BASE_CONTAINERS,
    BOOTSTRAP_LOG_FILE,
    CONFIGURATION_MANAGER_LOG_FILE,
    CONFIGURATION_MANAGER_API_NAME,
    HDR_API_CONTAINER_NAME,
    HDR_API_NAME,
    DT_API_CONTAINER_NAME,
    DT_API_NAME,
    INTERNAL_LOGS_DIR,
    LAUNCHER_DIR,
    NRTDR_API_CONTAINER_NAME,
    NRTDR_API_NAME,
    RUNTIME_DIR,
    STATE_FILE,
    ensure_runtime_directories,
)

DEFAULT_API_PORT = 8000
DEFAULT_LOGS_DIR = INTERNAL_LOGS_DIR
DEFAULT_BASE_PROFILES = [
    "-m",
    "communication_module",
    "-t",
    "kafka,filebeat",
    "-m",
    "db_module",
    "-t",
    "mongodb,mongodb_cm,postgres_gui,redis,mimir",
    "-m",
    "aggregation_module",
    "-t",
    "prometheus,opensearch",
]
BASE_CONTAINER_EXPECTATIONS = {
    "kafka_novadef": "healthy",
    "filebeat_novadef": "healthy",
    "mongodb_novadef": "healthy",
    "mongodb_cm_novadef": "healthy",
    "postgres_gui_novadef": "healthy",
    "redis_novadef": "healthy",
    "redis_worker_novadef": "healthy",
    "mimir_novadef": "running",
    "prometheus_server_novadef": "healthy",
    "opensearch_node_novadef": "healthy",
}


class BootstrapError(RuntimeError):
    """Raised when the bootstrap flow cannot continue safely."""


class BootstrapLogger:
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
            "Bootstrap the PMP backend stack: base containers, Configuration "
            "Manager API, NRTDR API, and HDR API. Without flags it starts the "
            "base services and reuses or starts all three APIs."
        ),
        epilog=(
            "Examples:\n"
            "  python3 Launcher/bootstrap_pmp_backend.py\n"
            "  python3 Launcher/bootstrap_pmp_backend.py --skip-base --skip-api\n"
            "  python3 Launcher/bootstrap_pmp_backend.py --skip-nrtdr-api\n"
            "  python3 Launcher/bootstrap_pmp_backend.py --skip-hdr-api\n"
            "  python3 Launcher/bootstrap_pmp_backend.py --skip-dt-api\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=DEFAULT_API_PORT,
        help="Port for the Configuration Manager API (default: 8000).",
    )
    parser.add_argument(
        "--logs-dir",
        default=str(DEFAULT_LOGS_DIR),
        help="Directory where bootstrap and API logs are stored.",
    )
    parser.add_argument(
        "--skip-base",
        action="store_true",
        help="Skip starting the base containers managed by start_containers.py.",
    )
    parser.add_argument(
        "--skip-api",
        action="store_true",
        help="Skip starting or checking the Configuration Manager API.",
    )
    parser.add_argument(
        "--skip-nrtdr-api",
        action="store_true",
        help="Skip starting or checking the NRTDR API.",
    )
    parser.add_argument(
        "--skip-hdr-api",
        action="store_true",
        help="Skip starting or checking the HDR API.",
    )
    parser.add_argument(
        "--skip-dt-api",
        action="store_true",
        help="Skip starting or checking the Data Exporter API.",
    )
    return parser.parse_args()


def generate_secret() -> str:
    import secrets

    return secrets.token_urlsafe(32)


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


def write_pid(pid_path: Path, pid: int) -> None:
    pid_path.write_text(f"{pid}\n", encoding="utf-8")


def remove_pid_file(pid_path: Path) -> None:
    if pid_path.exists():
        pid_path.unlink()


def terminate_pid(pid: int, logger: BootstrapLogger, label: str) -> None:
    if not is_process_running(pid):
        return

    logger.log(f"Stopping stale {label} process with PID {pid}.")
    os.kill(pid, signal.SIGTERM)
    for _ in range(20):
        if not is_process_running(pid):
            return
        time.sleep(0.5)

    logger.log(f"Force killing stale {label} process with PID {pid}.")
    os.kill(pid, signal.SIGKILL)


def ensure_command(command: str, logger: BootstrapLogger) -> None:
    if shutil.which(command):
        return
    raise BootstrapError(
        f"Required command '{command}' is not available in PATH. "
        "Please install it before running the bootstrap."
    )


def is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def http_request_json(
    url: str,
    timeout: float = 2.0,
) -> tuple[int, str, Optional[Any]]:
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            payload = None
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = None
            return response.status, body, payload
    except (URLError, TimeoutError, socket.timeout, OSError) as exc:
        return 0, str(exc), None


def is_our_configuration_manager_api(port: int) -> bool:
    status, _, payload = http_request_json(f"http://localhost:{port}/")
    if status != 200 or not isinstance(payload, dict):
        return False
    return payload.get("message") == "Configuration Manager API is running"


def is_our_nrtdr_api(port: int) -> bool:
    status, _, payload = http_request_json(f"http://localhost:{port}/")
    if status != 200 or not isinstance(payload, dict):
        return False
    return payload.get("name") == "PMP Near Real-Time Data Streaming API"


def is_our_hdr_api(port: int) -> bool:
    status, _, payload = http_request_json(f"http://localhost:{port}/")
    if status != 200 or not isinstance(payload, dict):
        return False
    return payload.get("name") == "PMP Historical Data Retrieval API"


def is_our_dt_api(port: int) -> bool:
    status, _, payload = http_request_json(f"http://localhost:{port}/")
    if status != 200 or not isinstance(payload, dict):
        return False
    return payload.get("name") == "PMP Data Exporter API"


def ensure_port_available_or_owned(
    port: int,
    logger: BootstrapLogger,
    service_name: str,
    validator,
) -> bool:
    if not is_port_open("127.0.0.1", port):
        return False

    if validator(port):
        logger.log(
            f"Port {port} is already serving the managed {service_name}; it will be reused.",
        )
        return True

    raise BootstrapError(
        f"Port {port} is already in use by a different service. "
        f"Please free the port before starting {service_name}."
    )


def run_command(
    command: Iterable[str],
    logger: BootstrapLogger,
    *,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    logger.log(f"Running command: {' '.join(command)}")
    completed = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.stdout.strip():
        logger.log(completed.stdout.rstrip())
    if completed.stderr.strip():
        logger.log(completed.stderr.rstrip())
    if completed.returncode != 0:
        raise BootstrapError(
            f"Command failed with exit code {completed.returncode}: {' '.join(command)}"
        )
    return completed


def docker_container_status(container_name: str) -> str:
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


def wait_for_base_containers(logger: BootstrapLogger, timeout_seconds: int = 180) -> None:
    deadline = time.time() + timeout_seconds
    pending = set(BASE_CONTAINER_EXPECTATIONS.keys())
    logger.log("Waiting for base containers to become ready.")

    while pending and time.time() < deadline:
        for container_name in list(pending):
            status = docker_container_status(container_name)
            expected = BASE_CONTAINER_EXPECTATIONS[container_name]
            if status == expected:
                logger.log(f"Container {container_name} is {status}.")
                pending.remove(container_name)
        if pending:
            time.sleep(2.0)

    if pending:
        statuses = {
            container_name: docker_container_status(container_name)
            for container_name in sorted(pending)
        }
        raise BootstrapError(
            f"Timed out waiting for base containers: {statuses}"
        )


def wait_for_http_service(
    url: str,
    validator,
    logger: BootstrapLogger,
    label: str,
    timeout_seconds: int = 120,
) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if validator():
            logger.log(f"{label} is ready at {url}.")
            return
        time.sleep(1.5)
    raise BootstrapError(f"Timed out waiting for {label} at {url}.")


def start_configuration_manager_api(
    api_port: int,
    logger: BootstrapLogger,
    logs_dir: Path,
) -> str:
    if ensure_port_available_or_owned(
        api_port,
        logger,
        CONFIGURATION_MANAGER_API_NAME,
        is_our_configuration_manager_api,
    ):
        return "reused"

    stale_pid = read_pid(API_PID_FILE)
    if stale_pid:
        terminate_pid(stale_pid, logger, CONFIGURATION_MANAGER_API_NAME)
        remove_pid_file(API_PID_FILE)

    uvicorn_path = shutil.which("uvicorn")
    if not uvicorn_path:
        raise BootstrapError("uvicorn is not available in PATH.")

    log_path = logs_dir / CONFIGURATION_MANAGER_LOG_FILE.name
    handle = log_path.open("a", encoding="utf-8")
    process = subprocess.Popen(
        [
            uvicorn_path,
            "--app-dir",
            str(LAUNCHER_DIR.parent / "APIs" / "ConfigurationManager"),
            "configuration_manager_api:app",
            "--port",
            str(api_port),
            "--host",
            "0.0.0.0",
        ],
        cwd=str(LAUNCHER_DIR.parent),
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    write_pid(API_PID_FILE, process.pid)
    logger.log(f"Started Configuration Manager API with PID {process.pid}.")
    return "started"


def start_nrtdr_api(
    nrtdr_api_port: int,
    logger: BootstrapLogger,
) -> str:
    """Reuses or starts the managed NRTDR API container before falling back to compose launch."""
    if ensure_port_available_or_owned(
        nrtdr_api_port,
        logger,
        NRTDR_API_NAME,
        is_our_nrtdr_api,
    ):
        return "reused"

    container_status = docker_container_status(NRTDR_API_CONTAINER_NAME)
    if container_status in {"created", "exited"}:
        run_command(
            ["docker", "start", NRTDR_API_CONTAINER_NAME],
            logger,
            cwd=LAUNCHER_DIR.parent,
        )
        logger.log(
            f"Started existing NRTDR API container {NRTDR_API_CONTAINER_NAME} without rebuild.",
        )
        return "started"

    if container_status in {"running", "healthy"}:
        logger.log(
            f"NRTDR API container {NRTDR_API_CONTAINER_NAME} is already {container_status}; waiting for readiness.",
        )
        return "reused"

    command = [
        sys.executable,
        str(LAUNCHER_DIR / "start_containers.py"),
        "-m",
        "apis_module",
        "-t",
        "nrtdr_api",
    ]
    run_command(
        command,
        logger,
        cwd=LAUNCHER_DIR.parent,
    )
    logger.log(
        f"Ensured NRTDR API container {NRTDR_API_CONTAINER_NAME} is started on port {nrtdr_api_port}.",
    )
    return "started"


def start_hdr_api(
    hdr_api_port: int,
    logger: BootstrapLogger,
) -> str:
    """Reuses or starts the managed HDR API container before falling back to compose launch."""
    if ensure_port_available_or_owned(
        hdr_api_port,
        logger,
        HDR_API_NAME,
        is_our_hdr_api,
    ):
        return "reused"

    container_status = docker_container_status(HDR_API_CONTAINER_NAME)
    if container_status in {"created", "exited"}:
        run_command(
            ["docker", "start", HDR_API_CONTAINER_NAME],
            logger,
            cwd=LAUNCHER_DIR.parent,
        )
        logger.log(
            f"Started existing HDR API container {HDR_API_CONTAINER_NAME} without rebuild.",
        )
        return "started"

    if container_status in {"running", "healthy"}:
        logger.log(
            f"HDR API container {HDR_API_CONTAINER_NAME} is already {container_status}; waiting for readiness.",
        )
        return "reused"

    command = [
        sys.executable,
        str(LAUNCHER_DIR / "start_containers.py"),
        "-m",
        "apis_module",
        "-t",
        "hdr_api",
    ]
    run_command(
        command,
        logger,
        cwd=LAUNCHER_DIR.parent,
    )
    logger.log(
        f"Ensured HDR API container {HDR_API_CONTAINER_NAME} is started on port {hdr_api_port}.",
    )
    return "started"


def start_dt_api(
    dt_api_port: int,
    logger: BootstrapLogger,
) -> str:
    """Reuses or starts the managed Data Exporter API container before falling back to compose launch."""
    if ensure_port_available_or_owned(
        dt_api_port,
        logger,
        DT_API_NAME,
        is_our_dt_api,
    ):
        return "reused"

    container_status = docker_container_status(DT_API_CONTAINER_NAME)
    if container_status in {"created", "exited"}:
        run_command(
            ["docker", "start", DT_API_CONTAINER_NAME],
            logger,
            cwd=LAUNCHER_DIR.parent,
        )
        logger.log(
            f"Started existing Data Exporter API container {DT_API_CONTAINER_NAME} without rebuild.",
        )
        return "started"

    if container_status in {"running", "healthy"}:
        logger.log(
            f"Data Exporter API container {DT_API_CONTAINER_NAME} is already {container_status}; waiting for readiness.",
        )
        return "reused"

    command = [
        sys.executable,
        str(LAUNCHER_DIR / "start_containers.py"),
        "-m",
        "apis_module",
        "-t",
        "dt_api",
    ]
    run_command(
        command,
        logger,
        cwd=LAUNCHER_DIR.parent,
    )
    logger.log(
        f"Ensured Data Exporter API container {DT_API_CONTAINER_NAME} is started on port {dt_api_port}.",
    )
    return "started"


def write_state_file(
    *,
    api_port: int,
    nrtdr_api_port: int,
    hdr_api_port: int,
    dt_api_port: int,
    logs_dir: Path,
    logger: BootstrapLogger,
    api_status: str,
    nrtdr_api_status: str,
    hdr_api_status: str,
    dt_api_status: str,
) -> None:
    state = {
        "updated_at": datetime.now().isoformat(),
        "api_port": api_port,
        "nrtdr_api_port": nrtdr_api_port,
        "hdr_api_port": hdr_api_port,
        "dt_api_port": dt_api_port,
        "logs_dir": str(logs_dir),
        "bootstrap_log": str(logs_dir / BOOTSTRAP_LOG_FILE.name),
        "api_log": str(logs_dir / CONFIGURATION_MANAGER_LOG_FILE.name),
        "nrtdr_api_container": NRTDR_API_CONTAINER_NAME,
        "hdr_api_container": HDR_API_CONTAINER_NAME,
        "dt_api_container": DT_API_CONTAINER_NAME,
        "api_pid_file": str(API_PID_FILE),
        "api_status": api_status,
        "nrtdr_api_status": nrtdr_api_status,
        "hdr_api_status": hdr_api_status,
        "dt_api_status": dt_api_status,
        "base_containers": BASE_CONTAINERS,
    }
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    logger.log(f"Runtime state written to {STATE_FILE}.")


def start_base_services(logger: BootstrapLogger) -> None:
    command = [
        sys.executable,
        str(LAUNCHER_DIR / "start_containers.py"),
        *DEFAULT_BASE_PROFILES,
    ]
    run_command(command, logger, cwd=LAUNCHER_DIR.parent)


def main() -> int:
    args = parse_args()
    logs_dir = ensure_runtime_directories(Path(args.logs_dir).resolve())
    logger = BootstrapLogger(logs_dir / BOOTSTRAP_LOG_FILE.name)

    try:
        ensure_command("docker", logger)
        if not args.skip_api and not shutil.which("uvicorn"):
            raise BootstrapError("uvicorn is not available in PATH.")

        api_status = "skipped"
        nrtdr_api_status = "skipped"
        hdr_api_status = "skipped"
        dt_api_status = "skipped"
        nrtdr_api_port = int(os.getenv("NRTDR_API_PORT", "8001"))
        hdr_api_port = int(os.getenv("HDR_API_PORT", "8002"))
        dt_api_port = int(os.getenv("DT_API_PORT", "8003"))

        if not args.skip_base:
            start_base_services(logger)
            wait_for_base_containers(logger)
        else:
            logger.log("Skipping base container startup as requested.")

        if not args.skip_api:
            api_status = start_configuration_manager_api(args.api_port, logger, logs_dir)
            wait_for_http_service(
                url=f"http://localhost:{args.api_port}/",
                validator=lambda: is_our_configuration_manager_api(args.api_port),
                logger=logger,
                label="Configuration Manager API",
            )
        else:
            logger.log("Skipping Configuration Manager API startup as requested.")

        if not args.skip_nrtdr_api:
            nrtdr_api_status = start_nrtdr_api(nrtdr_api_port, logger)
            wait_for_http_service(
                url=f"http://localhost:{nrtdr_api_port}/",
                validator=lambda: is_our_nrtdr_api(nrtdr_api_port),
                logger=logger,
                label="NRTDR API",
            )
        else:
            logger.log("Skipping NRTDR API startup as requested.")

        if not args.skip_hdr_api:
            hdr_api_status = start_hdr_api(hdr_api_port, logger)
            wait_for_http_service(
                url=f"http://localhost:{hdr_api_port}/",
                validator=lambda: is_our_hdr_api(hdr_api_port),
                logger=logger,
                label="HDR API",
            )
        else:
            logger.log("Skipping HDR API startup as requested.")

        if not args.skip_dt_api:
            dt_api_status = start_dt_api(dt_api_port, logger)
            wait_for_http_service(
                url=f"http://localhost:{dt_api_port}/",
                validator=lambda: is_our_dt_api(dt_api_port),
                logger=logger,
                label="Data Exporter API",
            )
        else:
            logger.log("Skipping Data Exporter API startup as requested.")

        write_state_file(
            api_port=args.api_port,
            nrtdr_api_port=nrtdr_api_port,
            hdr_api_port=hdr_api_port,
            dt_api_port=dt_api_port,
            logs_dir=logs_dir,
            logger=logger,
            api_status=api_status,
            nrtdr_api_status=nrtdr_api_status,
            hdr_api_status=hdr_api_status,
            dt_api_status=dt_api_status,
        )

        logger.log("Bootstrap completed successfully.")
        logger.log(f"Configuration Manager API URL: http://localhost:{args.api_port}")
        logger.log(f"NRTDR API URL: http://localhost:{nrtdr_api_port}")
        logger.log(f"HDR API URL: http://localhost:{hdr_api_port}")
        logger.log(f"Data Exporter API URL: http://localhost:{dt_api_port}")
        return 0
    except BootstrapError as exc:
        logger.log(f"Bootstrap failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
