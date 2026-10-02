#!/usr/bin/env python3
"""Infra_Discovery_Watcher: discovers PMP/NOVADEF infrastructure containers by
Docker label and writes their IPs to a volume shared with the detector."""

import json
import logging
import os
import time
from pathlib import Path

import docker

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("infra_discovery_watcher")

POLL_INTERVAL_SECONDS = float(os.getenv("NID_WATCHER_POLL_INTERVAL_SECONDS"))
INFRA_LABEL = os.getenv("NID_WATCHER_INFRA_LABEL")
LAUNCHER_NETWORK_NAME = "launcher_default"

OUTPUT_FILE = Path("/shared/infra/infra_ips.ndjson")
OUTPUT_TMP_FILE = OUTPUT_FILE.with_suffix(".tmp")
HEALTHY_SENTINEL_FILE = Path("/tmp/healthy")


def discover_infra_ips(client: "docker.DockerClient") -> list[str]:
    """Return the sorted, deduplicated IPs (on launcher_default) of every
    running container labelled as PMP/NOVADEF infrastructure."""
    ips: set[str] = set()
    for container in client.containers.list(filters={"label": INFRA_LABEL}):
        networks = (container.attrs.get("NetworkSettings") or {}).get("Networks") or {}
        network = networks.get(LAUNCHER_NETWORK_NAME) or {}
        ip = str(network.get("IPAddress") or "").strip()
        if ip:
            ips.add(ip)
    return sorted(ips)


def write_infra_ips_atomically(ips: list[str]) -> None:
    """Write the IP list as NDJSON to the shared file via a temp file + rename,
    so the detector never reads a partial write."""
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_TMP_FILE.open("w", encoding="utf-8") as handle:
        for ip in ips:
            handle.write(json.dumps(ip) + "\n")
    OUTPUT_TMP_FILE.replace(OUTPUT_FILE)


def mark_healthy() -> None:
    """Touch the sentinel file the HEALTHCHECK looks for, once discovery has run at least once."""
    HEALTHY_SENTINEL_FILE.touch(exist_ok=True)


def main() -> None:
    """Poll Docker for labelled infra containers and keep the shared file in sync."""
    client = docker.from_env()
    logger.info("Watching for containers labelled '%s', polling every %ss", INFRA_LABEL, POLL_INTERVAL_SECONDS)

    last_written_ips: list[str] | None = None
    while True:
        try:
            current_ips = discover_infra_ips(client)
            if current_ips != last_written_ips:
                write_infra_ips_atomically(current_ips)
                logger.info("Infra IP list updated: %s", current_ips)
                last_written_ips = current_ips
            mark_healthy()
        except Exception as exc:
            logger.warning("Discovery cycle failed: %s", exc)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
