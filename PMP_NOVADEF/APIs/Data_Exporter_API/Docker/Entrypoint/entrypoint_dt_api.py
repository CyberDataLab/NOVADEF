#!/usr/bin/env python3
"""
Entrypoint for the Data Exporter API container.

Waits for OpenSearch to be reachable over TCP before starting uvicorn.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time


def check_tcp_connection(host: str, port: int, max_attempts: int = 30) -> bool:
    '''Polls host:port over TCP until it accepts connections or max_attempts is reached.'''
    for attempt in range(1, max_attempts + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True
        print(f"⏳ Waiting for OpenSearch at {host}:{port} (attempt {attempt}/{max_attempts})")
        time.sleep(2)
    return False


def main() -> None:
    '''Waits for OpenSearch to be reachable, then launches uvicorn serving the Data Exporter API.'''
    opensearch_host = os.environ["OPENSEARCH_HOST"]
    opensearch_port = int(os.environ["OPENSEARCH_REST_API_PORT"])
    api_host = os.environ["DT_API_HOST"]
    api_port = int(os.environ["DT_API_PORT"])

    if not check_tcp_connection(opensearch_host, opensearch_port):
        print(f"❌ OpenSearch is not available at {opensearch_host}:{opensearch_port}, cannot start API")
        sys.exit(1)

    print(f"✅ OpenSearch is reachable at {opensearch_host}:{opensearch_port}")
    subprocess.run(
        [
            "uvicorn",
            "dt_api_server:app",
            "--host",
            api_host,
            "--port",
            str(api_port),
            "--log-level",
            "info",
            "--access-log",
        ],
        check=True,
        cwd="/home/dt_api",
    )


if __name__ == "__main__":
    main()
