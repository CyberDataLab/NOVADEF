#!/usr/bin/env python3
import os
import re
import sys
import time
import signal
import subprocess
from pathlib import Path
from typing import Tuple, Union

TRACES_DIR    = "/data/traces"                   
LOG_PATH      = os.path.join(TRACES_DIR, "infile.ndjson")
ROTATED_PATH  = os.path.join(TRACES_DIR, "infile.ndjson.backup")

SIZE_LIMIT    = 30 * 1024 * 1024 #~30 MiB


def get_interfaces():
    try:
        SCRIPT_DIR = Path(__file__).resolve().parent
        result = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "search_interface.py")],
            capture_output=True, text=True, check=True
        )
        interfaces = result.stdout.strip().split()
    except subprocess.CalledProcessError:
        print("ERROR 1: No active interfaces were found", file=sys.stderr)
        sys.exit(1)

    if not interfaces:
        print("ERROR 2: No active interfaces were found", file=sys.stderr)
        sys.exit(1)
    return interfaces


def build_tshark_command(interfaces) -> str:
    command = ["tshark"]
    for interface in interfaces:
        new_interface = re.findall(r"'(.*?)'", interface)
        command.extend(["-i", new_interface[0]])
    command.extend(["-T", "json", "-x","-l", "--no-duplicate-keys", "2>/dev/null"])
    return (
        f"{" ".join(map(str, command))}"
        f" | /usr/local/bin/json_array_to_ndjson.py"
    )


def reap_children() -> None:
    """
    Recolecta cualquier hijo terminado para evitar procesos <defunct> (zombies).
    No bloquea (WNOHANG). Llamar a menudo y también desde SIGCHLD.
    """
    try:
        while True:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
    except ChildProcessError:
        # No hay hijos
        pass
    except OSError:
        pass

def _sigchld_handler(signum, frame):
    # Recolecta rápido cuando finaliza algún hijo
    reap_children()

def _kill_process_group(proc: subprocess.Popen, term_timeout: float = 5.0) -> None:
    """
    Mata el grupo entero del proceso (shell + tshark + conversor) con SIGTERM
    y, si no sale a tiempo, con SIGKILL. Luego hace reap de hijos.
    """
    if proc is None:
        return

    try:
        # Señal al grupo porque Popen se lanzó con start_new_session=True
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        # Ya no existe
        pass
    try:
        proc.wait(timeout=term_timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=1)
        except Exception:
            pass

    # Recolecta cualquier otro hijo colgante
    reap_children()

def run_tshark(command) -> Tuple[subprocess.Popen, "io.TextIOWrapper"]:
    """
    Lanza el pipeline en su propia sesión (grupo nuevo) y devuelve (proc, output_file).
    """

    os.makedirs(TRACES_DIR, exist_ok=True)

    output_file = open(LOG_PATH, "a", buffering=1, encoding="utf-8")

    proc = subprocess.Popen(
        command,
        stdout=output_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,     
        shell=True,
        executable="/bin/sh",
        text=True
    )

    return proc, output_file

def monitor_and_rotate(command: Union[str, list, tuple],
                       proc: subprocess.Popen,
                       output_file) -> None:
    """
    Vigila LOG_PATH y, al superar SIZE_LIMIT, rota a ROTATED_PATH:
      1) Mata grupo completo (no quedan procesos escribiendo al inode viejo)
      2) Cierra el FD de salida
      3) Renombra (os.replace)
      4) Relanza pipeline y reabre LOG_PATH
    Hace reap periódico para evitar zombies “rezagados”.
    """
    if not os.path.exists(LOG_PATH):
        open(LOG_PATH, "a", encoding="utf-8").close()

    while True:
        time.sleep(2)
        reap_children()
        try:
            size = os.path.getsize(LOG_PATH) if os.path.exists(LOG_PATH) else 0
        except FileNotFoundError:
            size = 0
            open(LOG_PATH, "a", encoding="utf-8").close()

        if size >= SIZE_LIMIT:
            # 1) Parar pipeline entero
            _kill_process_group(proc, term_timeout=5)

            # 2) Cerrar el descriptor ANTES de rotar
            try:
                output_file.flush()
            except Exception:
                pass
            try:
                output_file.close()
            except Exception:
                pass

            # 3) Rotar
            try:
                os.replace(LOG_PATH, ROTATED_PATH)
            except FileNotFoundError:
                pass

            # 4) Relanzar
            proc, output_file = run_tshark(command)


def main():
    signal.signal(signal.SIGCHLD, _sigchld_handler)

    def _graceful_exit(signum, frame):
        # Cierre limpio cuando el contenedor reciba stop/kill
        nonlocal_proc = getattr(main, "_proc", None)
        nonlocal_of   = getattr(main, "_of", None)
        try:
            if nonlocal_proc is not None:
                _kill_process_group(nonlocal_proc, term_timeout=3)
        finally:
            try:
                if nonlocal_of is not None:
                    nonlocal_of.close()
            except Exception:
                pass
            reap_children()
            sys.exit(0)

    signal.signal(signal.SIGTERM, _graceful_exit)
    signal.signal(signal.SIGINT,  _graceful_exit)

    # Construye comando y lanza
    interfaces   = get_interfaces()
    command = build_tshark_command(interfaces)

    proc, output_file = run_tshark(command)

    # Guarda referencias para el handler de salida
    main._proc = proc
    main._of   = output_file

    try:
        monitor_and_rotate(command, proc, output_file)
    finally:
        # Failsafe
        _kill_process_group(proc, term_timeout=2)
        try:
            output_file.close()
        except Exception:
            pass
        reap_children()

if __name__ == "__main__":
    main()
