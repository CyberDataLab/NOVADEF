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
import json
import logging
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = REPO_ROOT / "Scenario"
SCENARIO_LOGS = SCENARIO_DIR / "artifacts" / "logs"


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def run_command(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def _container_exists(name: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", name],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _inspect_container(name: str) -> dict:
    result = run_command(["docker", "inspect", name])
    data = json.loads(result.stdout or "[]")
    if not data:
        raise RuntimeError(f"No inspection data for container {name}")
    return data[0]


def _resolve_active_scenario_containers() -> tuple[str, str]:
    static_attacker = "scenario_attacker"
    static_victim = "scenario_victim"
    if _container_exists(static_attacker) and _container_exists(static_victim):
        return static_attacker, static_victim

    result = run_command(["docker", "ps", "-a", "--format", "{{.Names}}"])
    names = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]

    candidates: list[tuple[str, str, str]] = []
    for attacker_name in names:
        if not attacker_name.startswith("novadef-scenario-auto-") or not attacker_name.endswith("_attacker"):
            continue
        prefix = attacker_name[: -len("_attacker")]
        victim_name = f"{prefix}_victim"
        if victim_name in names:
            candidates.append((prefix, attacker_name, victim_name))

    ranked: list[tuple[str, str, str]] = []
    for prefix, attacker_name, victim_name in candidates:
        try:
            attacker_info = _inspect_container(attacker_name)
            victim_info = _inspect_container(victim_name)
        except Exception:
            continue
        attacker_running = str(((attacker_info.get("State") or {}).get("Status") or "")).lower() == "running"
        victim_running = str(((victim_info.get("State") or {}).get("Status") or "")).lower() == "running"
        if not (attacker_running and victim_running):
            continue
        created = str(victim_info.get("Created") or attacker_info.get("Created") or "")
        ranked.append((created, attacker_name, victim_name))

    if not ranked:
        raise RuntimeError("No active scenario attacker/victim container pair found")

    ranked.sort(reverse=True)
    _, attacker_name, victim_name = ranked[0]
    return attacker_name, victim_name


def launch_password_spraying() -> None:
    logger.info("=== Lanzando distributed_password_spraying_network_experiment ===")
    attacker_name, victim_name = _resolve_active_scenario_containers()

    scenario_log = SCENARIO_LOGS / "password_spraying_attempts.jsonl"
    scenario_log.parent.mkdir(parents=True, exist_ok=True)
    scenario_log.write_text("", encoding="utf-8")

    run_command(
        [
            "docker",
            "exec",
            attacker_name,
            "bash",
            "/opt/novadef/distributed_password_spraying.sh",
            victim_name,
            "2222",
        ]
    )

    logger.info("Ataque lanzado desde %s contra %s", attacker_name, victim_name)
    logger.info("Evidencia local del escenario: %s", scenario_log)
    logger.info("A partir de aquí la detección y respuesta deben seguir el flujo interno de NOVADEF")


def launch_ransomware_emulation() -> None:
    logger.info("=== Lanzando akira_style_windows_endpoint_ransomware_emulation ===")
    _, victim_name = _resolve_active_scenario_containers()

    run_command(
        [
            "docker",
            "exec",
            "-u",
            "1000:1000",
            victim_name,
            "bash",
            "/opt/novadef/akira_lab_emulation.sh",
        ]
    )

    logger.info("Emulación lanzada dentro de %s", victim_name)
    logger.info("La restauración del laboratorio debe quedar a cargo del flujo de respuesta de NOVADEF")


def launch_hybrid_lateral_remote_execution() -> None:
    logger.info("=== Lanzando lateral_movement_remote_exec_hybrid_experiment ===")
    attacker_name, victim_name = _resolve_active_scenario_containers()

    scenario_log = SCENARIO_LOGS / "password_spraying_attempts.jsonl"
    scenario_log.parent.mkdir(parents=True, exist_ok=True)
    scenario_log.write_text("", encoding="utf-8")

    run_command(
        [
            "docker",
            "exec",
            attacker_name,
            "bash",
            "/opt/novadef/hybrid_lateral_remote_execution.sh",
            victim_name,
            "2222",
        ]
    )

    logger.info("Emulación híbrida lanzada desde %s contra %s", attacker_name, victim_name)
    logger.info("Evidencia local del escenario: %s", scenario_log)
    logger.info("NOVADEF debe correlacionar sospecha de red + host y emitir una única alerta")


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch attack stimuli inside the live NOVADEF scenario")
    parser.add_argument("--only", choices=["exp1", "exp2", "exp3"], help="Lanza solo un experimento")
    args = parser.parse_args()

    if args.only in (None, "exp1"):
        launch_password_spraying()
    if args.only in (None, "exp2"):
        launch_ransomware_emulation()
    if args.only in (None, "exp3"):
        launch_hybrid_lateral_remote_execution()


if __name__ == "__main__":
    main()
