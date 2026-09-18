#!/usr/bin/env python3

import os
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPConnection
from typing import Dict, List, Optional

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel


"""Machine identifier advertised to Prometheus service discovery."""
MACHINE_ID = os.getenv("MACHINE_ID", "unknown")

"""Refresh interval in seconds for the background probe loop."""
REFRESH_INTERVAL_SECONDS = float(os.getenv("DEVICE_INFO_REFRESH_INTERVAL", "15"))

"""Timeout in seconds for each HTTP probe."""
PROBE_TIMEOUT_SECONDS = float(os.getenv("DEVICE_INFO_PROBE_TIMEOUT", "2"))

"""Number of successful checks required to mark a probe as up."""
UP_THRESHOLD = 1

"""Number of failed checks required to mark a probe as down."""
DOWN_THRESHOLD = 3


class PrometheusTargetGroup(BaseModel):
    """Represent one HTTP-SD target group consumed by Prometheus."""

    targets: List[str]
    labels: Dict[str, str]


class ProbeStatus(BaseModel):
    """Represent the current cached status for one local exporter probe."""

    tool_name: str
    target: str
    probe_target: str
    path: str
    status: str
    is_available: bool
    consecutive_successes: int
    consecutive_failures: int
    last_check_at: Optional[str]
    last_status_change_at: Optional[str]
    last_error: Optional[str]
    last_http_status: Optional[int]


class DeviceInfoStatusResponse(BaseModel):
    """Represent the diagnostic status response returned by device-info."""

    machine_id: str
    refresh_interval_seconds: float
    probe_timeout_seconds: float
    probes: List[ProbeStatus]


"""Create the FastAPI application used by device-info."""
app = FastAPI(
    title="Device Info API",
    description=(
        "Runtime probe API that discovers local monitoring exporters and exposes "
        "Prometheus HTTP service discovery targets."
    ),
    version="1.0.0",
)


@dataclass(frozen=True)
class ProbeDefinition:
    """Describe a local HTTP probe and the Prometheus target it represents."""

    tool_name: str
    probe_host: str
    probe_host_env_var: str
    port_env_var: str
    default_port: str
    advertised_host: str = "localhost"
    path: str = "/metrics"
    timeout_seconds: float = PROBE_TIMEOUT_SECONDS
    up_threshold: int = UP_THRESHOLD
    down_threshold: int = DOWN_THRESHOLD

    """Return the configured internal host used to execute the HTTP probe."""
    def get_probe_host(self) -> str:
        return os.getenv(self.probe_host_env_var, self.probe_host)

    """Return the configured port for this probe."""
    def get_port(self) -> int:
        return int(os.getenv(self.port_env_var, self.default_port))

    """Build the internal target string used by the local HTTP probe."""
    def build_probe_target(self) -> str:
        return f"{self.get_probe_host()}:{self.get_port()}"

    """Build the target string exposed to Prometheus service discovery."""
    def build_target(self) -> str:
        return f"{self.advertised_host}:{self.get_port()}"


"""Declarative list of exporters that device-info can detect."""
PROBE_DEFINITIONS: List[ProbeDefinition] = [
    ProbeDefinition(
        tool_name="telegraf",
        probe_host="telegraf",
        probe_host_env_var="TELEGRAF_PROBE_HOST",
        port_env_var="TELEGRAF_TO_PROMETHEUS_PORT",
        default_port="9273",
    ),
    ProbeDefinition(
        tool_name="fluentd",
        probe_host="fluentd",
        probe_host_env_var="FLUENTD_PROBE_HOST",
        port_env_var="FLUENTD_TO_PROMETHEUS_PORT",
        default_port="24231",
    ),
    ProbeDefinition(
        tool_name="falco",
        probe_host="falco-exporter",
        probe_host_env_var="FALCO_PROBE_HOST",
        port_env_var="FALCO_EXPORTER_PORT",
        default_port="9376",
    ),
]


"""Shared runtime cache protected by a lock for concurrent access."""
state_lock = threading.Lock()

"""Mutable cache with the latest runtime state per probe."""
runtime_state: Dict[str, Dict[str, Optional[object]]] = {}


"""Return the current UTC timestamp in ISO 8601 format."""
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


"""Convert low-level probe exceptions into clearer diagnostic messages."""
def format_probe_error(error: Exception) -> str:
    if isinstance(error, ConnectionRefusedError):
        return "Connection refused. The exporter is not listening on the configured host or port."

    if isinstance(error, socket.gaierror):
        return "Probe host could not be resolved. The exporter service may not be deployed yet."

    if isinstance(error, TimeoutError) or isinstance(error, socket.timeout):
        return "Probe request timed out before the exporter responded."

    error_message = str(error).strip()
    if error_message:
        return f"Probe request failed: {error_message}"

    return "Probe request failed due to an unknown connection error."


"""Create the initial in-memory state for every known probe."""
def build_initial_runtime_state() -> Dict[str, Dict[str, Optional[object]]]:
    state: Dict[str, Dict[str, Optional[object]]] = {}

    for probe in PROBE_DEFINITIONS:
        target = probe.build_target()
        probe_target = probe.build_probe_target()
        state[probe.tool_name] = {
            "tool_name": probe.tool_name,
            "target": target,
            "probe_target": probe_target,
            "path": probe.path,
            "status": "down",
            "is_available": False,
            "consecutive_successes": 0,
            "consecutive_failures": 0,
            "last_check_at": None,
            "last_status_change_at": None,
            "last_error": "Probe not executed yet.",
            "last_http_status": None,
        }

    return state


"""Execute a basic HTTP GET probe and return the observed result."""
def run_http_probe(probe: ProbeDefinition) -> Dict[str, Optional[object]]:
    connection: Optional[HTTPConnection] = None
    target = probe.build_target()
    probe_target = probe.build_probe_target()

    try:
        connection = HTTPConnection(
            host=probe.get_probe_host(),
            port=probe.get_port(),
            timeout=probe.timeout_seconds,
        )
        connection.request("GET", probe.path)
        response = connection.getresponse()
        status_code = response.status
        response.read()

        is_success = 200 <= status_code < 300
        error_message = None if is_success else f"HTTP status {status_code} received."

        return {
            "tool_name": probe.tool_name,
            "target": target,
            "probe_target": probe_target,
            "path": probe.path,
            "is_success": is_success,
            "http_status": status_code,
            "error_message": error_message,
        }
    except Exception as exc:
        return {
            "tool_name": probe.tool_name,
            "target": target,
            "probe_target": probe_target,
            "path": probe.path,
            "is_success": False,
            "http_status": None,
            "error_message": format_probe_error(exc),
        }
    finally:
        if connection is not None:
            connection.close()


"""Apply probe hysteresis rules and update the cached runtime state."""
def update_probe_state(probe: ProbeDefinition, probe_result: Dict[str, Optional[object]]) -> None:
    timestamp = utc_now_iso()

    with state_lock:
        current_state = runtime_state[probe.tool_name]
        was_available = bool(current_state["is_available"])

        current_state["target"] = probe_result["target"]
        current_state["probe_target"] = probe_result["probe_target"]
        current_state["path"] = probe_result["path"]
        current_state["last_check_at"] = timestamp
        current_state["last_http_status"] = probe_result["http_status"]

        if bool(probe_result["is_success"]):
            current_state["consecutive_successes"] = int(current_state["consecutive_successes"]) + 1
            current_state["consecutive_failures"] = 0
            current_state["last_error"] = None

            if current_state["consecutive_successes"] >= probe.up_threshold:
                current_state["is_available"] = True
                current_state["status"] = "up"
        else:
            current_state["consecutive_successes"] = 0
            current_state["consecutive_failures"] = int(current_state["consecutive_failures"]) + 1
            current_state["last_error"] = str(probe_result["error_message"])

            if current_state["consecutive_failures"] >= probe.down_threshold:
                current_state["is_available"] = False
                current_state["status"] = "down"

        is_available = bool(current_state["is_available"])
        if is_available != was_available:
            current_state["last_status_change_at"] = timestamp


"""Probe all known exporters and refresh the in-memory cache."""
def refresh_runtime_state() -> None:
    for probe in PROBE_DEFINITIONS:
        probe_result = run_http_probe(probe)
        update_probe_state(probe, probe_result)


"""Keep runtime state fresh in the background using a fixed refresh interval."""
def background_probe_loop() -> None:
    while True:
        refresh_runtime_state()
        time.sleep(REFRESH_INTERVAL_SECONDS)


"""Build the HTTP-SD payload expected by Prometheus discovery."""
def build_prometheus_targets_payload() -> List[PrometheusTargetGroup]:
    targets: List[str] = []

    with state_lock:
        for probe_name in sorted(runtime_state.keys()):
            probe_state = runtime_state[probe_name]
            if bool(probe_state["is_available"]):
                targets.append(str(probe_state["target"]))

    return [
        PrometheusTargetGroup(
            targets=targets,
            labels={"machine_id": MACHINE_ID},
        )
    ]


"""Build a diagnostic payload with the detailed probe status."""
def build_status_payload() -> DeviceInfoStatusResponse:
    with state_lock:
        probes = [
            ProbeStatus(**dict(runtime_state[probe_name]))
            for probe_name in sorted(runtime_state.keys())
        ]

    return DeviceInfoStatusResponse(
        machine_id=MACHINE_ID,
        refresh_interval_seconds=REFRESH_INTERVAL_SECONDS,
        probe_timeout_seconds=PROBE_TIMEOUT_SECONDS,
        probes=probes,
    )


@app.on_event("startup")
def startup_event() -> None:
    """Initialize the cache and start the background probe worker."""
    global runtime_state

    runtime_state = build_initial_runtime_state()
    refresh_runtime_state()

    background_thread = threading.Thread(target=background_probe_loop, daemon=True)
    background_thread.start()


@app.get("/")
async def root() -> Dict[str, str]:
    """Expose a basic health check for the device-info API."""
    return {
        "message": "Device Info API is running",
        "version": "1.0.0",
        "machine_id": MACHINE_ID,
    }


@app.get("/prom-targets", response_model=List[PrometheusTargetGroup])
async def prom_targets() -> List[PrometheusTargetGroup]:
    """Expose the Prometheus HTTP-SD payload with currently available targets."""
    return build_prometheus_targets_payload()


@app.get("/status", response_model=DeviceInfoStatusResponse)
async def status() -> DeviceInfoStatusResponse:
    """Expose a human-readable diagnostic view of the current probe cache."""
    return build_status_payload()


if __name__ == "__main__":
    """Run the FastAPI application with uvicorn."""
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("DEVICE_INFO_PORT", "9999")),
    )
