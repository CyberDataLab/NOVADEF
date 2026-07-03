#!/usr/bin/env python3
import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


def http_json(url: str, method: str = "GET", payload: dict | None = None, timeout: float = 15.0):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
        if not body:
            return {}
        return json.loads(body.decode("utf-8", errors="replace"))


def download_file(url: str, target: Path, timeout: float = 30.0) -> None:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        target.write_bytes(r.read())


def extract_and_print_metrics(bundle_zip: Path, out_dir: Path) -> None:
    with zipfile.ZipFile(bundle_zip, "r") as zf:
        zf.extractall(out_dir)

    report_json = out_dir / "incident_report.json"
    if not report_json.exists():
        print("[warn] incident_report.json no encontrado en el bundle")
        return

    data = json.loads(report_json.read_text(encoding="utf-8"))
    metrics = (data.get("novadef_metrics") or {})
    lat = (metrics.get("latency_ooda") or {})
    phase_metrics = ((metrics.get("ooda_phase_metrics") or {}))
    orient = (phase_metrics.get("orient") or {})
    incident = ((metrics.get("dimension_breakdown") or {}).get("incident") or {})
    response = ((metrics.get("dimension_breakdown") or {}).get("response") or {})
    cm = (data.get("countermeasure") or {})
    cm_selected = str(cm.get("selected") or "").strip()
    detect_latency = lat.get("time_to_first_alert") or {}
    detect_done = isinstance(detect_latency, dict) and isinstance(detect_latency.get("sec"), (int, float))
    profile_done = int(orient.get("actor_profile_count") or 0) > 0
    enrich_done = int(incident.get("misp_event_count") or 0) > 0
    decide_done = bool(cm_selected and cm_selected not in {"", "-", "Pending / no decision yet"})
    act_done = bool((metrics.get("response_effectiveness") or {}).get("execution_present"))
    observe_done = True

    def _sec(key: str):
        v = lat.get(key)
        if isinstance(v, dict):
            return v.get("sec")
        return None

    print("\n=== RESUMEN DE TIEMPOS (incident_report.json) ===")
    print("report_id:", data.get("report_id") or "-")
    print("experiment:", data.get("experiment") or "-")
    print("time_to_first_alert_sec:", _sec("time_to_first_alert"))
    print("time_to_correct_identification_sec:", _sec("time_to_correct_identification"))
    print("e2e_to_act_sec:", _sec("e2e_to_act"))
    print("\n=== ETAPAS COMPLETADAS ===")
    print("Observe:", "done" if observe_done else "pending")
    print("Detect:", "done" if detect_done else "pending")
    print("Profile:", "done" if profile_done else "pending")
    print("Enrich (MISP):", "done" if enrich_done else "pending")
    print("Decide:", "done" if decide_done else "pending")
    print("Act (SOARCA):", "done" if act_done else "pending")

    print("\n=== RESUMEN (ESTILO GUI) ===")
    summary = {
        "observation_scope": "PMP telemetry (from incident report)",
        "detection_method": "completed" if detect_done else "Pending / no clear detector evidence yet",
        "tapcd_profile": "completed" if profile_done else "Pending / no native TAPCD profile evidence yet",
        "countermeasure": (f"MITRE D3FEND: {cm_selected} (applied)" if act_done and decide_done else "Pending / no decision yet"),
    }
    print("Observation scope:", summary["observation_scope"])
    print("Detection method:", summary["detection_method"])
    print("Generated profile:", summary["tapcd_profile"])
    print("Applied countermeasure:", summary["countermeasure"])


def main() -> int:
    ap = argparse.ArgumentParser(description="Lanza experimento NOVADEF por API (sin GUI), espera reporte y descarga bundle.")
    ap.add_argument("--experiment", choices=["exp1", "exp2", "exp3"], default="exp1")
    ap.add_argument("--scenario-id", default="", help="Scenario existente (opcional). Si no se pasa, crea auto-<id>.")
    ap.add_argument("--api-base", default="http://127.0.0.1:18082")
    ap.add_argument("--timeout-sec", type=int, default=1200)
    ap.add_argument("--poll-sec", type=float, default=2.0)
    ap.add_argument("--out-dir", default="/tmp/novadef_headless_reports")
    args = ap.parse_args()

    api = args.api_base.rstrip("/")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {"experiment": args.experiment}
    if args.scenario_id.strip():
        payload["scenario_id"] = args.scenario_id.strip()

    print("[info] Lanzando run...")
    start = http_json(f"{api}/api/run", method="POST", payload=payload, timeout=20)
    if not start.get("ok"):
        print("[error] /api/run falló:", start)
        return 1

    run_id = str(start.get("run_id") or "")
    scenario_id = str(start.get("scenario_id") or "")
    if not run_id:
        print("[error] No se recibió run_id")
        return 1

    print("[ok] run_id:", run_id)
    print("[ok] scenario_id:", scenario_id or "-")

    deadline = time.time() + max(args.timeout_sec, 30)
    report_id = ""
    download_url = ""

    while time.time() < deadline:
        # 1) Intentar obtener reporte (se habilita cuando hay countermeasure)
        try:
            rep = http_json(
                f"{api}/api/report/latest?run_id={urllib.parse.quote(run_id)}",
                timeout=8,
            )
            if rep.get("ok"):
                report_id = str(rep.get("report_id") or "")
                download_url = str(rep.get("download_url") or "")
                print("[ok] Reporte listo:", report_id)
                break
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

        # 2) Estado informativo
        try:
            st = http_json(f"{api}/api/state?run_id={urllib.parse.quote(run_id)}", timeout=8)
            running = bool(st.get("running"))
            markers = ((st.get("traffic_panel") or {}).get("markers") or {})
            detect = markers.get("detection_at")
            cm = markers.get("countermeasure_at")
            print(f"[wait] running={running} detection_at={detect} countermeasure_at={cm}")
        except Exception:
            print("[wait] estado no disponible (reintentando)")

        time.sleep(max(args.poll_sec, 0.5))

    if not report_id or not download_url:
        print("[error] Timeout esperando reporte")
        return 2

    bundle_zip = out_dir / f"novadef_incident_report_{report_id}.zip"
    full_download_url = f"{api}{download_url}"
    print("[info] Descargando bundle:", full_download_url)
    download_file(full_download_url, bundle_zip, timeout=60)
    print("[ok] Guardado:", bundle_zip)

    extract_dir = out_dir / report_id
    extract_dir.mkdir(parents=True, exist_ok=True)
    extract_and_print_metrics(bundle_zip, extract_dir)
    print("[ok] Reporte extraído en:", extract_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
