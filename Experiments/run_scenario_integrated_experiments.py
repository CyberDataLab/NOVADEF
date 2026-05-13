#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
run_scenario_integrated_experiments.py

Lanza los experimentos dentro del escenario real.

IMPORTANTE:
- Este script NO hace detección, perfilado, MISP ni SOARCA.
- Su única responsabilidad es generar el estímulo del experimento dentro del
  escenario para que el resto del ciclo lo recorra NOVADEF por sí mismo.
"""

from __future__ import annotations

import argparse
import logging
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = REPO_ROOT / "Scenario"
SCENARIO_LOGS = SCENARIO_DIR / "shared-logs"


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def run_command(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def launch_password_spraying() -> None:
    logger.info("=== Lanzando distributed_password_spraying_network_experiment ===")

    scenario_log = SCENARIO_LOGS / "password_spraying_attempts.jsonl"
    scenario_log.parent.mkdir(parents=True, exist_ok=True)
    scenario_log.write_text("", encoding="utf-8")

    run_command(
        [
            "docker",
            "exec",
            "scenario_attacker",
            "bash",
            "/opt/novadef/distributed_password_spraying.sh",
            "scenario_victim",
            "2222",
        ]
    )

    logger.info("Ataque lanzado desde scenario_attacker")
    logger.info("Evidencia local del escenario: %s", scenario_log)
    logger.info("A partir de aquí la detección y respuesta deben seguir el flujo interno de NOVADEF")


def launch_ransomware_emulation() -> None:
    logger.info("=== Lanzando akira_style_windows_endpoint_ransomware_emulation ===")

    run_command(
        [
            "docker",
            "exec",
            "-u",
            "1000:1000",
            "scenario_victim",
            "bash",
            "/opt/novadef/akira_lab_emulation.sh",
        ]
    )

    logger.info("Emulación lanzada dentro de scenario_victim")
    logger.info("La restauración del laboratorio debe quedar a cargo del flujo de respuesta de NOVADEF")


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch attack stimuli inside the live NOVADEF scenario")
    parser.add_argument("--only", choices=["exp1", "exp2"], help="Lanza solo un experimento")
    args = parser.parse_args()

    if args.only in (None, "exp1"):
        launch_password_spraying()
    if args.only in (None, "exp2"):
        launch_ransomware_emulation()


if __name__ == "__main__":
    main()
