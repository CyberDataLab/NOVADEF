from __future__ import annotations

import csv
import io
import json
import math
import statistics
import re
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS


app = Flask(__name__)
CORS(app)

STATE: dict[str, Any] = {
    "running": False,
    "last_experiment": None,
    "last_started_at": None,
    "last_finished_at": None,
    "last_return_code": None,
    "last_output": "",
}
LOCK = threading.Lock()
MAX_LOG_CHARS = 60000
DOCKER_CLIENT = docker.from_env()
REPORTS_DIR = Path("/tmp/novadef_reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
TS_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?")
ISO_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)")


def _tail_logs(container: str, lines: int = 300, since_ts: int | None = None) -> str:
    try:
        cont = DOCKER_CLIENT.containers.get(container)
        kwargs: dict[str, Any] = {"tail": lines}
        if since_ts is not None:
            kwargs["since"] = since_ts
        out = cont.logs(**kwargs).decode("utf-8", errors="replace")
    except Exception:
        return ""
    return out[-MAX_LOG_CHARS:]


def _exec_run_with_timeout(
    container_name: str,
    cmd: list[str],
    timeout_sec: int = 900,
    user: str | None = None,
) -> tuple[int, str]:
    result_box: dict[str, Any] = {"done": False, "rc": 1, "out": ""}

    def _runner() -> None:
        try:
            cont = DOCKER_CLIENT.containers.get(container_name)
            res = cont.exec_run(cmd, user=user, stdout=True, stderr=True)
            result_box["rc"] = int(res.exit_code)
            result_box["out"] = (res.output or b"").decode("utf-8", errors="replace")
        except Exception as e:
            result_box["rc"] = 1
            result_box["out"] = f"Exec error in {container_name}: {e}"
        finally:
            result_box["done"] = True

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout=timeout_sec)
    if not result_box["done"]:
        return 124, f"Execution timeout after {timeout_sec}s in {container_name}"
    return int(result_box["rc"]), str(result_box["out"])


def _extract_alert_lines(container: str, text: str) -> list[dict[str, str]]:
    lines = []
    for raw in text.splitlines():
        low = raw.lower()
        if any(k in low for k in ["alert", "anomaly", "detected", "incident", "spray", "ransom", "misp", "playbook", "response", "countermeasure"]):
            lines.append({"container": container, "line": raw[:1200]})
    return lines


def _parse_log_epoch(line: str) -> float | None:
    # 1) Common python logger prefix: YYYY-MM-DD HH:MM:SS,ms
    match = TS_LINE_RE.match(line.strip())
    if match:
        try:
            dt = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            pass

    # 2) JSON/structured logs with RFC3339 (Falco includes nanoseconds)
    iso_match = ISO_TS_RE.search(line)
    if iso_match:
        try:
            iso_raw = iso_match.group(1)
            if "." in iso_raw:
                base, frac_z = iso_raw.split(".", 1)
                frac = frac_z[:-1]  # remove Z
                frac_6 = (frac + "000000")[:6]
                iso_norm = f"{base}.{frac_6}Z"
                dt = datetime.strptime(iso_norm, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
                return dt.timestamp()
            dt = datetime.strptime(iso_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            pass
    return None


def _sec_pack(seconds: float | None) -> dict[str, float] | None:
    if seconds is None:
        return None
    s = max(float(seconds), 0.0)
    return {
        "sec": s,
        "ms": s * 1_000.0,
        "us": s * 1_000_000.0,
        "ns": s * 1_000_000_000.0,
    }


def _first_timestamp_for_keywords(blob: str, keywords: list[str]) -> float | None:
    if not blob:
        return None
    lower_keywords = [k.lower() for k in keywords]
    for line in blob.splitlines():
        low = line.lower()
        if any(k in low for k in lower_keywords):
            ts = _parse_log_epoch(line)
            if ts is not None:
                return ts
    return None


def _count_keyword_hits(blob: str, keywords: list[str]) -> int:
    if not blob:
        return 0
    lower_keywords = [k.lower() for k in keywords]
    count = 0
    for line in blob.splitlines():
        low = line.lower()
        if any(k in low for k in lower_keywords):
            count += 1
    return count


def _docker_runtime_stats(containers: list[str]) -> dict[str, dict[str, float]]:
    stats_out: dict[str, dict[str, float]] = {}
    for name in containers:
        try:
            cont = DOCKER_CLIENT.containers.get(name)
            st = cont.stats(stream=False)
            cpu_total = float(st.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0.0))
            precpu_total = float(st.get("precpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0.0))
            sys_total = float(st.get("cpu_stats", {}).get("system_cpu_usage", 0.0))
            presys_total = float(st.get("precpu_stats", {}).get("system_cpu_usage", 0.0))
            cpus = float(len(st.get("cpu_stats", {}).get("cpu_usage", {}).get("percpu_usage", []) or [1]))
            cpu_delta = max(cpu_total - precpu_total, 0.0)
            sys_delta = max(sys_total - presys_total, 1.0)
            cpu_pct = (cpu_delta / sys_delta) * cpus * 100.0

            mem_usage = float(st.get("memory_stats", {}).get("usage", 0.0))
            mem_limit = float(st.get("memory_stats", {}).get("limit", 1.0))
            mem_pct = (mem_usage / max(mem_limit, 1.0)) * 100.0

            stats_out[name] = {
                "cpu_percent": round(cpu_pct, 3),
                "memory_bytes": mem_usage,
                "memory_percent": round(mem_pct, 3),
            }
        except Exception:
            continue
    return stats_out


def _wait_for_pipeline_completion(experiment: str, started: float | None, timeout_sec: int = 95) -> None:
    if not started:
        return
    since_ts = int(started)
    deadline = time.time() + timeout_sec

    while time.time() < deadline:
        observe_blob = "\n".join(
            [
                _tail_logs("falco_novadef", 400, since_ts=since_ts),
                _tail_logs("tshark_novadef", 400, since_ts=since_ts),
                _tail_logs("flow_module_novadef", 300, since_ts=since_ts),
                _tail_logs("scenario_attacker", 250, since_ts=since_ts),
            ]
        )
        detect_blob = "\n".join(
            [
                _tail_logs("network_intrusion_detector_novadef", 500, since_ts=since_ts),
                _tail_logs("snort_novadef", 500, since_ts=since_ts),
                _tail_logs("alert_module_novadef", 500, since_ts=since_ts),
            ]
        )
        enrich_blob = "\n".join(
            [
                _tail_logs("pmp-misp-integrator", 500, since_ts=since_ts),
                _tail_logs("pmp-misp-server", 350, since_ts=since_ts),
            ]
        )
        profile_blob = enrich_blob + "\n" + _tail_logs("novadef-novadef_stream_low-1", 350, since_ts=since_ts)
        act_blob = "\n".join(
            [
                _tail_logs("pmp-misp-soarca-trigger", 500, since_ts=since_ts),
                _tail_logs("pmp-soarca-core", 500, since_ts=since_ts),
                _tail_logs("pmp-soarca-executor-ssh", 500, since_ts=since_ts),
                _tail_logs("scenario_victim", 350, since_ts=since_ts),
            ]
        )

        if experiment == "exp2":
            observe_hit = any(k in observe_blob.lower() for k in ["falco", "ransomware", "warning novadef"])
            detect_hit = any(k in (detect_blob + "\n" + observe_blob).lower() for k in ["ransomware", "falco", "warning", "detected"])
            profile_hit = "perfil tapcd inyectado" in profile_blob.lower()
            enrich_hit = "nuevo evento misp" in enrich_blob.lower()
            act_hit = any(k in act_blob.lower() for k in ["playbook de aislamiento ejecutado", "playbook ejecutado", "lanzando playbook de aislamiento"])
        else:
            observe_hit = any(k in observe_blob.lower() for k in ["ssh", "packet", "flow", "password spraying"])
            detect_hit = any(k in detect_blob.lower() for k in ["spraying", "anomaly", "alerta publicada", "nueva alerta"])
            profile_hit = "perfil tapcd inyectado" in profile_blob.lower()
            enrich_hit = "nuevo evento misp" in enrich_blob.lower()
            act_hit = any(k in act_blob.lower() for k in ["playbook ejecutado", "lanzando playbook", "applied", "block"])

        if observe_hit and detect_hit and profile_hit and enrich_hit and act_hit:
            return
        time.sleep(2)


def _compute_experiment_metrics(experiment: str, started: float | None, finished: float | None, logs_by_phase: dict[str, str]) -> dict[str, Any]:
    duration = max((finished or 0) - (started or 0), 0.001)

    detect_blob = logs_by_phase.get("detect", "")
    profile_blob = logs_by_phase.get("profile", "")
    enrich_blob = logs_by_phase.get("enrich", "")
    act_blob = logs_by_phase.get("act", "")
    observe_blob = logs_by_phase.get("observe", "")
    effective_detect_blob = detect_blob if experiment != "exp2" else (detect_blob + "\n" + observe_blob + "\n" + enrich_blob)

    relevant_attack_generated = 1
    relevant_attack_observed = 1 if _count_keyword_hits(effective_detect_blob, ["spray", "ransom", "anomaly", "snort", "alert", "falco", "warning"]) > 0 else 0
    observability_ratio = relevant_attack_observed / relevant_attack_generated

    ingestion_events = _count_keyword_hits(observe_blob, ["flow", "ssh", "falco", "packet", "password spraying", "warning novadef", "ransomware"])
    detector_events = _count_keyword_hits(effective_detect_blob, ["alert", "anomaly", "snort", "spraying", "falco", "ransomware", "warning"])
    db_writes = _count_keyword_hits(enrich_blob, ["nuevo evento misp", "evento misp", "attribute", "ip-src", "ip-dst"])

    attack_start = started
    first_telemetry = _first_timestamp_for_keywords(observe_blob, ["flow", "ssh", "packet", "password spraying", "falco", "ransomware", "warning"])
    first_alert = _first_timestamp_for_keywords(effective_detect_blob, ["alerta publicada", "nueva alerta", "snort", "anomaly", "ransom", "falco", "warning"])
    stable_identification = _first_timestamp_for_keywords(profile_blob + "\n" + enrich_blob, ["perfil tapcd inyectado", "profile", "attacker"])
    decide_time = _first_timestamp_for_keywords(act_blob, ["selección defensiva", "d3fend", "lanzando playbook"])
    act_time = _first_timestamp_for_keywords(act_blob, ["playbook ejecutado", "playbook de aislamiento ejecutado", "applied", "block", "isolation"])

    latencies = []
    for ts in [first_telemetry, first_alert, stable_identification, decide_time, act_time]:
        if ts is not None and attack_start is not None:
            latencies.append(max(ts - attack_start, 0.0))
    latencies_sorted = sorted(latencies)

    def _percentile(arr: list[float], q: float) -> float:
        if not arr:
            return 0.0
        idx = (len(arr) - 1) * q
        lo = int(math.floor(idx))
        hi = int(math.ceil(idx))
        if lo == hi:
            return arr[lo]
        return arr[lo] + (arr[hi] - arr[lo]) * (idx - lo)

    tp = 1 if relevant_attack_observed else 0
    fn = 0 if relevant_attack_observed else 1
    fp = max(_count_keyword_hits(effective_detect_blob, ["nueva alerta"]) - tp, 0)
    tn = 0
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    f1 = (2 * precision * recall) / max(precision + recall, 1e-9)

    container_stats = _docker_runtime_stats(
        [
            "tshark_novadef",
            "falco_novadef",
            "network_intrusion_detector_novadef",
            "alert_module_novadef",
            "novadef-novadef_stream_low-1",
            "pmp-misp-integrator",
            "pmp-soarca-core",
        ]
    )

    return {
        "event_observability_ratio": round(observability_ratio, 4),
        "operational_scalability": {
            "telemetry_ingest_rate_eps": round(ingestion_events / duration, 4),
            "detector_processing_rate_eps": round(detector_events / duration, 4),
            "database_write_rate_eps": round(db_writes / duration, 4),
            "events_window_seconds": round(duration, 3),
        },
        "resource_overhead": {
            "containers": container_stats,
            "cpu_percent_sum": round(sum(v.get("cpu_percent", 0.0) for v in container_stats.values()), 3),
            "memory_percent_sum": round(sum(v.get("memory_percent", 0.0) for v in container_stats.values()), 3),
        },
        "latency_ooda": {
            "attack_start_ts": attack_start,
            "first_telemetry_ts": first_telemetry,
            "first_alert_ts": first_alert,
            "stable_identification_ts": stable_identification,
            "decide_ts": decide_time,
            "act_ts": act_time,
            "time_to_first_alert": _sec_pack(max((first_alert or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            "time_to_correct_identification": _sec_pack(max((stable_identification or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            "e2e_to_act": _sec_pack(max((act_time or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            "latency_mean": _sec_pack(statistics.mean(latencies_sorted)) if latencies_sorted else _sec_pack(0.0),
            "latency_median": _sec_pack(statistics.median(latencies_sorted)) if latencies_sorted else _sec_pack(0.0),
            "latency_p95": _sec_pack(_percentile(latencies_sorted, 0.95)),
            "latency_p99": _sec_pack(_percentile(latencies_sorted, 0.99)),
            "latency_jitter_std": _sec_pack(statistics.pstdev(latencies_sorted)) if len(latencies_sorted) > 1 else _sec_pack(0.0),
        },
        "detection_quality": {
            "mode": "rule_based_or_ml_binary",
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "accuracy": round(accuracy, 4),
            "f1_score": round(f1, 4),
        },
        "attack_classification_link": {
            "detection_to_profile_linked": _count_keyword_hits(profile_blob + "\n" + enrich_blob, ["perfil tapcd inyectado"]) > 0,
            "profile_mentions": _count_keyword_hits(profile_blob, ["profile", "attacker", "incident"]),
        },
    }


def _phase_machine_map(experiment: str) -> dict[str, str]:
    if experiment == "exp2":
        return {
            "observe": "scenario_victim (host scope)",
            "detect": "PMP detectors over victim telemetry",
            "profile": "TAPCD over profiled attacker/incident graph",
            "enrich": "MISP stack (pmp-misp-server/integrator)",
            "decide": "SOARCA core (D3FEND mapping)",
            "act": "scenario_victim via SOARCA executor",
        }
    return {
        "observe": "scenario_victim / scenario_attacker (network scope)",
        "detect": "PMP detectors (Snort + anomaly + alert module)",
        "profile": "TAPCD over profiled attacker/incident graph",
        "enrich": "MISP stack (pmp-misp-server/integrator)",
        "decide": "SOARCA core (D3FEND mapping)",
        "act": "scenario_victim via SOARCA executor",
    }


def _detect_countermeasure(log_text: str, experiment: str) -> tuple[str, str]:
    low = log_text.lower()
    if "isolation" in low:
        return "Network Isolation", "SOARCA logs indicate isolation action, aligned with D3FEND isolation controls."
    if "terminate" in low or "kill" in low:
        return "Process Termination", "SOARCA logs indicate process stop/termination, aligned with D3FEND process controls."
    if "lock" in low or "block" in low or "iptables" in low:
        return "Traffic/Account Blocking", "SOARCA logs indicate blocking action (traffic/account), aligned with D3FEND filtering/locking."
    if experiment == "exp2":
        return "Execution Isolation + Restore File", "Default ransomware-oriented mapping inferred from experiment context and SOARCA stage."
    return "Inbound/Network Traffic Filtering", "Default password-spraying mapping inferred from experiment context and SOARCA stage."


def _build_report_payload() -> dict[str, Any]:
    with LOCK:
        experiment = STATE.get("last_experiment")
        started = STATE.get("last_started_at")
        finished = STATE.get("last_finished_at")
        rc = STATE.get("last_return_code")
        output = STATE.get("last_output", "")

    if not experiment:
        raise ValueError("No experiment has been launched yet.")
    since_ts = int(started) if started else None

    observe_logs = {
        "tshark_novadef": _tail_logs("tshark_novadef", 300, since_ts=since_ts),
        "falco_novadef": _tail_logs("falco_novadef", 300, since_ts=since_ts),
        "flow_module_novadef": _tail_logs("flow_module_novadef", 300, since_ts=since_ts),
    }
    detect_logs = {
        "snort_novadef": _tail_logs("snort_novadef", 350, since_ts=since_ts),
        "network_intrusion_detector_novadef": _tail_logs("network_intrusion_detector_novadef", 350, since_ts=since_ts),
        "alert_module_novadef": _tail_logs("alert_module_novadef", 350, since_ts=since_ts),
    }
    profile_logs = {
        "novadef-novadef_stream_low-1": _tail_logs("novadef-novadef_stream_low-1", 350, since_ts=since_ts),
        "novadef-novadef_prep_pred-1": _tail_logs("novadef-novadef_prep_pred-1", 250, since_ts=since_ts),
    }
    misp_logs = {
        "pmp-misp-integrator": _tail_logs("pmp-misp-integrator", 350, since_ts=since_ts),
        "pmp-misp-server": _tail_logs("pmp-misp-server", 300, since_ts=since_ts),
    }
    soarca_logs = {
        "pmp-misp-soarca-trigger": _tail_logs("pmp-misp-soarca-trigger", 350, since_ts=since_ts),
        "pmp-soarca-core": _tail_logs("pmp-soarca-core", 350, since_ts=since_ts),
        "pmp-soarca-executor-ssh": _tail_logs("pmp-soarca-executor-ssh", 350, since_ts=since_ts),
        "scenario_victim": _tail_logs("scenario_victim", 300, since_ts=since_ts),
    }
    attacker_logs = {"scenario_attacker": _tail_logs("scenario_attacker", 300, since_ts=since_ts)}

    all_sections = [observe_logs, detect_logs, profile_logs, misp_logs, soarca_logs, attacker_logs]
    alert_lines: list[dict[str, str]] = []
    for sec in all_sections:
        for c, txt in sec.items():
            alert_lines.extend(_extract_alert_lines(c, txt))
    alert_lines = alert_lines[-500:]

    misp_blob = "\n".join(misp_logs.values())
    event_ids = sorted(set(re.findall(r"\bevent(?:_id| id)?[=: ]+(\d+)\b", misp_blob, flags=re.IGNORECASE)))
    tapcd_blob = "\n".join(profile_logs.values())
    tapcd_indicators = {
        "profile_mentions": tapcd_blob.lower().count("profile"),
        "attacker_mentions": tapcd_blob.lower().count("attacker"),
        "incident_mentions": tapcd_blob.lower().count("incident"),
    }

    soarca_blob = "\n".join(soarca_logs.values())
    countermeasure, why = _detect_countermeasure(soarca_blob, experiment)
    logs_by_phase = {
        "observe": "\n".join(observe_logs.values()),
        "detect": "\n".join(detect_logs.values()),
        "profile": "\n".join(profile_logs.values()),
        "enrich": "\n".join(misp_logs.values()),
        "act": "\n".join(soarca_logs.values()),
    }
    exp_metrics = _compute_experiment_metrics(experiment, started, finished, logs_by_phase)

    phase_machine = _phase_machine_map(experiment)
    phases = [
        {"phase": "observe", "machine_scope": phase_machine["observe"], "detector_or_component": "Falco/tshark/Flow"},
        {"phase": "detect", "machine_scope": phase_machine["detect"], "detector_or_component": "Snort + anomaly detector + alert module"},
        {"phase": "profile", "machine_scope": phase_machine["profile"], "detector_or_component": "TAPCD"},
        {"phase": "enrich", "machine_scope": phase_machine["enrich"], "detector_or_component": "MISP integrator/server"},
        {"phase": "decide", "machine_scope": phase_machine["decide"], "detector_or_component": "SOARCA core (D3FEND-based decision)"},
        {"phase": "act", "machine_scope": phase_machine["act"], "detector_or_component": "SOARCA executor / victim actions"},
    ]

    status_ok = bool(rc == 0 and finished)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment": experiment,
        "execution": {
            "started_at": datetime.fromtimestamp(started, tz=timezone.utc).isoformat() if started else None,
            "finished_at": datetime.fromtimestamp(finished, tz=timezone.utc).isoformat() if finished else None,
            "return_code": rc,
            "status_ok": status_ok,
            "backend_output_tail": output,
        },
        "phase_machine_scope": phase_machine,
        "phases": phases,
        "alerts": alert_lines,
        "misp": {
            "event_ids_detected_in_logs": event_ids,
            "event_signal_count": misp_blob.lower().count("event"),
            "log_excerpt": misp_blob[-6000:],
        },
        "tapcd": {
            "signals": tapcd_indicators,
            "log_excerpt": tapcd_blob[-6000:],
        },
        "countermeasure": {
            "selected": countermeasure,
            "justification": why,
            "d3fend_basis": "Selected from SOARCA-stage evidence and mapped to D3FEND-aligned defensive controls.",
            "soarca_excerpt": soarca_blob[-6000:],
        },
        "novadef_metrics": exp_metrics,
        "incident_artifacts": {
            "json_available": True,
            "csv_available": True,
            "report_markdown_available": True,
            "zip_downloadable": True,
        },
    }


def _render_markdown(payload: dict[str, Any]) -> str:
    ex = payload["experiment"]
    execs = payload["execution"]
    cm = payload["countermeasure"]
    misp = payload["misp"]
    tapcd = payload["tapcd"]
    return f"""# NOVADEF Incident Report

## Summary
- Experiment: `{ex}`
- Started (UTC): `{execs.get("started_at")}`
- Finished (UTC): `{execs.get("finished_at")}`
- Return code: `{execs.get("return_code")}`
- Status OK: `{execs.get("status_ok")}`

## Phase Scope
{chr(10).join([f"- {k}: {v}" for k, v in payload["phase_machine_scope"].items()])}

## Detection And Alerts
- Alert lines captured: `{len(payload["alerts"])}`

## MISP
- Event IDs detected in logs: `{", ".join(misp.get("event_ids_detected_in_logs") or []) or "none"}`
- Event signal count: `{misp.get("event_signal_count")}`

## TAPCD
- Profile mentions: `{tapcd["signals"]["profile_mentions"]}`
- Attacker mentions: `{tapcd["signals"]["attacker_mentions"]}`
- Incident mentions: `{tapcd["signals"]["incident_mentions"]}`

## Countermeasure
- Selected: `{cm.get("selected")}`
- Why: {cm.get("justification")}
- D3FEND basis: {cm.get("d3fend_basis")}
"""


def _persist_report(payload: dict[str, Any]) -> str:
    report_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = REPORTS_DIR / report_id
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "incident_report.json"
    md_path = report_dir / "incident_report.md"
    alerts_csv_path = report_dir / "alerts.csv"
    phases_csv_path = report_dir / "phases.csv"
    metrics_json_path = report_dir / "metrics.json"
    metrics_csv_path = report_dir / "metrics_summary.csv"
    latency_csv_path = report_dir / "latency_ooda.csv"
    resource_csv_path = report_dir / "resource_overhead.csv"
    zip_path = report_dir / "incident_report_bundle.zip"

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(_render_markdown(payload), encoding="utf-8")

    with alerts_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["container", "line"])
        w.writeheader()
        for row in payload["alerts"]:
            w.writerow(row)

    with phases_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["phase", "machine_scope", "detector_or_component"])
        w.writeheader()
        for row in payload["phases"]:
            w.writerow(row)

    metrics_obj = payload.get("novadef_metrics", {})
    metrics_json_path.write_text(json.dumps(metrics_obj, indent=2, ensure_ascii=False), encoding="utf-8")

    def _flatten(prefix: str, value: Any) -> list[tuple[str, Any]]:
        rows: list[tuple[str, Any]] = []
        if isinstance(value, dict):
            for k, v in value.items():
                next_prefix = f"{prefix}.{k}" if prefix else str(k)
                rows.extend(_flatten(next_prefix, v))
        else:
            rows.append((prefix, value))
        return rows

    with metrics_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])
        w.writerow(["event_observability_ratio", metrics_obj.get("event_observability_ratio", 0)])
        for key, value in _flatten("operational_scalability", metrics_obj.get("operational_scalability", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("detection_quality", metrics_obj.get("detection_quality", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("latency_ooda", metrics_obj.get("latency_ooda", {}) or {}):
            if ".sec" in key or ".ms" in key or ".us" in key or ".ns" in key:
                w.writerow([key, value])

    with latency_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ooda_latency_metric", "sec", "ms", "us", "ns"])
        for key, value in (metrics_obj.get("latency_ooda", {}) or {}).items():
            if isinstance(value, dict) and {"sec", "ms", "us", "ns"}.issubset(set(value.keys())):
                w.writerow([key, value.get("sec"), value.get("ms"), value.get("us"), value.get("ns")])

    with resource_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["container", "cpu_percent", "memory_percent", "memory_bytes"])
        w.writeheader()
        for cname, cmetrics in (metrics_obj.get("resource_overhead", {}).get("containers", {}) or {}).items():
            w.writerow(
                {
                    "container": cname,
                    "cpu_percent": cmetrics.get("cpu_percent"),
                    "memory_percent": cmetrics.get("memory_percent"),
                    "memory_bytes": cmetrics.get("memory_bytes"),
                }
            )

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(json_path, arcname="incident_report.json")
        zf.write(md_path, arcname="incident_report.md")
        zf.write(alerts_csv_path, arcname="alerts.csv")
        zf.write(phases_csv_path, arcname="phases.csv")
        zf.write(metrics_json_path, arcname="metrics.json")
        zf.write(metrics_csv_path, arcname="metrics_summary.csv")
        zf.write(latency_csv_path, arcname="latency_ooda.csv")
        zf.write(resource_csv_path, arcname="resource_overhead.csv")

    with LOCK:
        STATE["last_report_id"] = report_id
    return report_id


def _run_background(experiment: str) -> None:
    try:
        # Restablece conectividad base del laboratorio antes de lanzar un nuevo ataque
        # para evitar timeouts de SOARCA por reglas de aislamiento previas.
        try:
            victim = DOCKER_CLIENT.containers.get("scenario_victim")
            victim.exec_run(
                [
                    "sh",
                    "-lc",
                    "iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -F INPUT; iptables -F OUTPUT || true",
                ],
                user="0:0",
                stdout=True,
                stderr=True,
            )
        except Exception:
            pass

        if experiment == "exp1":
            rc, output = _exec_run_with_timeout(
                "scenario_attacker",
                ["bash", "/opt/novadef/distributed_password_spraying.sh", "scenario_victim", "2222"],
                timeout_sec=900,
            )
        elif experiment == "exp2":
            rc, output = _exec_run_with_timeout(
                "scenario_victim",
                ["bash", "/opt/novadef/akira_lab_emulation.sh"],
                timeout_sec=900,
                user="1000:1000",
            )
        else:
            with LOCK:
                STATE["running"] = False
                STATE["last_return_code"] = 1
                STATE["last_output"] = f"Unknown experiment: {experiment}"
                STATE["last_finished_at"] = time.time()
            return
        with LOCK:
            STATE["running"] = False
            STATE["last_return_code"] = rc
            STATE["last_output"] = output[-12000:]
            STATE["last_finished_at"] = time.time()
        if rc == 0:
            try:
                _wait_for_pipeline_completion(experiment, STATE.get("last_started_at"))
                with LOCK:
                    STATE["last_finished_at"] = time.time()
                payload = _build_report_payload()
                _persist_report(payload)
            except Exception as e:
                with LOCK:
                    STATE["last_output"] = (STATE.get("last_output", "") + f"\n[report-error] {e}")[-12000:]
    except Exception as e:
        with LOCK:
            STATE["running"] = False
            STATE["last_return_code"] = 1
            STATE["last_output"] = f"Experiment execution error: {e}"
            STATE["last_finished_at"] = time.time()


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok"})


@app.get("/api/state")
def state() -> Any:
    with LOCK:
        return jsonify(STATE)


@app.get("/api/progress")
def progress() -> Any:
    with LOCK:
        experiment = STATE.get("last_experiment")
        started = STATE.get("last_started_at")
        running = bool(STATE.get("running"))
        rc = STATE.get("last_return_code")
        last_output = str(STATE.get("last_output") or "")
    if not experiment:
        return jsonify(
            {
                "experiment": None,
                "stages": [
                    {"key": "observe", "done": False},
                    {"key": "detect", "done": False},
                    {"key": "profile", "done": False},
                    {"key": "enrich", "done": False},
                    {"key": "decide", "done": False},
                    {"key": "act", "done": False},
                ],
            }
        )

    since_ts = int(started) if started else None
    logs = {
        "observe": _tail_logs("tshark_novadef", 400, since_ts=since_ts) + "\n" + _tail_logs("falco_novadef", 400, since_ts=since_ts) + "\n" + _tail_logs("scenario_attacker", 250, since_ts=since_ts),
        "detect": _tail_logs("snort_novadef", 500, since_ts=since_ts) + "\n" + _tail_logs("network_intrusion_detector_novadef", 500, since_ts=since_ts) + "\n" + _tail_logs("alert_module_novadef", 500, since_ts=since_ts),
        "profile": _tail_logs("novadef-novadef_stream_low-1", 500, since_ts=since_ts) + "\n" + _tail_logs("novadef-novadef_prep_pred-1", 300, since_ts=since_ts),
        "enrich": _tail_logs("pmp-misp-integrator", 500, since_ts=since_ts) + "\n" + _tail_logs("pmp-misp-server", 350, since_ts=since_ts),
        "act": _tail_logs("pmp-soarca-core", 500, since_ts=since_ts) + "\n" + _tail_logs("pmp-soarca-executor-ssh", 500, since_ts=since_ts) + "\n" + _tail_logs("scenario_victim", 350, since_ts=since_ts),
    }
    output_low = last_output.lower()

    if experiment == "exp2":
        observe_hit = any(k in logs["observe"].lower() for k in ["falco", "syscall", "file", "process"])
        detect_hit = any(k in logs["detect"].lower() for k in ["ransom", "impact", "alert", "detected"])
        profile_hit = any(k in logs["profile"].lower() for k in ["profile", "attacker", "incident", "classification"])
        enrich_hit = any(k in logs["enrich"].lower() for k in ["event", "misp", "attribute", "publish", "created"])
        decide_hit = any(k in logs["act"].lower() for k in ["d3fend", "playbook", "selected", "countermeasure"])
        act_hit = any(k in logs["act"].lower() for k in ["executor", "applied", "isolation", "terminate", "restor", "response"])
    else:
        observe_hit = any(k in logs["observe"].lower() for k in ["tshark", "packet", "ssh", "flow", "password spraying completado"]) or ("password spraying completado" in output_low)
        detect_hit = any(k in logs["detect"].lower() for k in ["spray", "brute", "anomaly", "snort", "alert"])
        profile_hit = any(k in logs["profile"].lower() for k in ["profile", "attacker", "incident", "classification"]) or ("perfil tapcd inyectado" in logs["enrich"].lower())
        enrich_hit = any(k in logs["enrich"].lower() for k in ["event", "misp", "attribute", "publish", "created"])
        decide_hit = any(k in logs["act"].lower() for k in ["d3fend", "playbook", "selected", "countermeasure"])
        act_hit = any(k in logs["act"].lower() for k in ["executor", "applied", "block", "lock", "isolation", "response"])

    stages = [
        {"key": "observe", "done": observe_hit},
        {"key": "detect", "done": detect_hit},
        {"key": "profile", "done": profile_hit},
        {"key": "enrich", "done": enrich_hit},
        {"key": "decide", "done": decide_hit},
        {"key": "act", "done": act_hit},
    ]
    # Si el experimento ha finalizado correctamente, marcamos cierre de ejecución
    # para que la fase Act (SOARCA) quede reflejada en verde en la UI.
    if not running and rc == 0:
        for st in stages:
            if st["key"] in {"observe", "detect", "profile", "enrich", "decide", "act"}:
                st["done"] = True
    return jsonify({"experiment": experiment, "stages": stages})


@app.get("/api/metrics")
def metrics() -> Any:
    with LOCK:
        experiment = STATE.get("last_experiment")
        started = STATE.get("last_started_at")
    if not experiment or not started:
        return jsonify(
            {
                "alert_signals": 0,
                "profile_signals": 0,
                "misp_signals": 0,
                "soarca_signals": 0,
                "timestamp": time.time(),
            }
        )
    since_ts = int(started) if started else None

    conts = [
        "network_intrusion_detector_novadef",
        "snort_novadef",
        "alert_module_novadef",
        "novadef-novadef_stream_low-1",
        "pmp-misp-integrator",
        "pmp-soarca-core",
    ]
    alert_hits = 0
    misp_hits = 0
    soarca_hits = 0
    profile_hits = 0
    for c in conts:
        txt = _tail_logs(c, 500, since_ts=since_ts).lower()
        alert_hits += txt.count("alert")
        misp_hits += txt.count("misp") + txt.count("event")
        soarca_hits += txt.count("playbook") + txt.count("executor") + txt.count("response")
        profile_hits += txt.count("profile") + txt.count("attacker")

    return jsonify(
        {
            "alert_signals": alert_hits,
            "profile_signals": profile_hits,
            "misp_signals": misp_hits,
            "soarca_signals": soarca_hits,
            "timestamp": time.time(),
        }
    )


@app.post("/api/report/generate")
def generate_report() -> Any:
    return jsonify({"ok": False, "error": "manual generation disabled: report is created automatically after each experiment run"}), 405


@app.get("/api/report/latest")
def latest_report() -> Any:
    with LOCK:
        report_id = STATE.get("last_report_id")
    if not report_id:
        return jsonify({"ok": False, "error": "no report generated yet"}), 404
    return jsonify({"ok": True, "report_id": report_id, "download_url": f"/api/report/download/{report_id}"})


@app.get("/api/report/download/<report_id>")
def download_report(report_id: str) -> Any:
    zip_path = REPORTS_DIR / report_id / "incident_report_bundle.zip"
    if not zip_path.exists():
        return jsonify({"ok": False, "error": "report not found"}), 404
    return send_file(zip_path, as_attachment=True, download_name=f"novadef_incident_report_{report_id}.zip")


@app.post("/api/run")
def run() -> Any:
    payload = request.get_json(silent=True) or {}
    experiment = payload.get("experiment")
    if experiment not in {"exp1", "exp2"}:
        return jsonify({"ok": False, "error": "experiment must be exp1 or exp2"}), 400

    with LOCK:
        if STATE["running"]:
            return jsonify({"ok": False, "error": "another experiment is running"}), 409
        STATE["running"] = True
        STATE["last_experiment"] = experiment
        STATE["last_started_at"] = time.time()
        STATE["last_finished_at"] = None
        STATE["last_return_code"] = None
        STATE["last_output"] = ""

    t = threading.Thread(target=_run_background, args=(experiment,), daemon=True)
    t.start()
    return jsonify({"ok": True, "started": experiment})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18082)
