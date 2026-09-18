#!/usr/bin/env python3
"""
Entrypoint for the Historical Data Retrieval API container.

Waits for Mimir to be reachable over TCP before starting uvicorn.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time


def check_tcp_connection(host: str, port: int, max_attempts: int = 30) -> bool:
    for attempt in range(1, max_attempts + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True
        print(f"⏳ Waiting for Mimir at {host}:{port} (attempt {attempt}/{max_attempts})")
        time.sleep(2)
    return False


def main() -> None:
    mimir_host = os.environ["MIMIR_HOST"]
    mimir_port = int(os.environ["MIMIR_PORT"])
    api_host = os.environ["HDR_API_HOST"]
    api_port = int(os.environ["HDR_API_PORT"])

    if not check_tcp_connection(mimir_host, mimir_port):
        print(f"❌ Mimir is not available at {mimir_host}:{mimir_port}, cannot start API")
        sys.exit(1)

    print(f"✅ Mimir is reachable at {mimir_host}:{mimir_port}")
    subprocess.run(
        [
            "uvicorn",
            "hdr_api_server:app",
            "--host",
            api_host,
            "--port",
            str(api_port),
            "--log-level",
            "info",
            "--access-log",
        ],
        check=True,
        cwd="/home/hdr_api",
    )


if __name__ == "__main__":
    main()
