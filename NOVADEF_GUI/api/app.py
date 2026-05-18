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
import os
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request as urlrequest, error as urlerror

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
    "last_report_id": None,
    "last_report_error": "",
    "current_run_id": None,
}
RUN_HISTORY: list[dict[str, Any]] = []
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


def _reset_misp_dedup_state() -> None:
    """
    Ensure each experiment run can generate exactly one fresh MISP/TAPCD
    campaign by clearing persisted dedup state and restarting the integrator.
    """
    try:
        integrator = DOCKER_CLIENT.containers.get("pmp-misp-integrator")
        # Clear persisted dedup file used by MISP integrator.
        integrator.exec_run(
            ["sh", "-lc", "rm -f /app/state/misp_dedup_state.json || true"],
            stdout=True,
            stderr=True,
        )
        integrator.restart(timeout=10)
    except Exception:
        # Non-fatal for experiment execution; report parser will still run.
        pass


def _reset_detector_runtime_state() -> None:
    """
    Restart detector/alert pipeline so each experiment starts with a clean
    in-memory dedup state and can emit one fresh campaign alert.
    """
    for name in ["network_intrusion_detector_novadef", "alert_module_novadef"]:
        try:
            c = DOCKER_CLIENT.containers.get(name)
            c.restart(timeout=10)
        except Exception:
            continue


def _reset_operational_artifacts() -> None:
    """
    Reset run-level artifacts so each experiment starts clean:
    - purge MISP events/content rows
    - clear SOARCA trigger persisted state
    - remove synthetic NOVADEF actor profiles in Neo4j
    """
    try:
        db = DOCKER_CLIENT.containers.get("pmp-misp-db")
        purge_sql = (
            "SET FOREIGN_KEY_CHECKS=0; "
            "TRUNCATE TABLE attributes; "
            "TRUNCATE TABLE shadow_attributes; "
            "TRUNCATE TABLE event_tags; "
            "TRUNCATE TABLE sightings; "
            "TRUNCATE TABLE object_references; "
            "TRUNCATE TABLE objects; "
            "TRUNCATE TABLE event_reports; "
            "TRUNCATE TABLE cryptographic_keys; "
            "TRUNCATE TABLE logs; "
            "TRUNCATE TABLE correlations; "
            "TRUNCATE TABLE default_correlations; "
            "TRUNCATE TABLE no_acl_correlations; "
            "TRUNCATE TABLE shadow_attribute_correlations; "
            "TRUNCATE TABLE events; "
            "SET FOREIGN_KEY_CHECKS=1;"
        )
        db.exec_run(
            ["sh", "-lc", f"mysql -uroot -pmy_root_password misp -e \"{purge_sql}\""],
            stdout=True,
            stderr=True,
        )
    except Exception:
        pass

    try:
        trig = DOCKER_CLIENT.containers.get("pmp-misp-soarca-trigger")
        trig.exec_run(["sh", "-lc", "rm -rf /app/state/* /state/* 2>/dev/null || true"], stdout=True, stderr=True)
        trig.restart(timeout=10)
    except Exception:
        pass

    try:
        neo = DOCKER_CLIENT.containers.get("novadef-neo4j-1")
        neo.exec_run(
            [
                "sh",
                "-lc",
                "cypher-shell -u neo4j -p password \"MATCH (a:Actor) WHERE a.id STARTS WITH 'novadef-' DETACH DELETE a\"",
            ],
            stdout=True,
            stderr=True,
        )
    except Exception:
        pass


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


def _wait_kafka_consumers_ready(timeout_sec: int = 35) -> None:
    """
    Give pipeline consumers a short warm-up window after restarts so
    fast host experiments (exp2/Falco) are not emitted before subscriptions.
    """
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        misp_log = _tail_logs("pmp-misp-integrator", 160).lower()
        alert_log = _tail_logs("alert_module_novadef", 160).lower()
        ready_misp = ("successfully joined group" in misp_log) or ("setting newly assigned partitions" in misp_log)
        ready_alert = ("starting kafka consume loop" in alert_log) or ("adding:" in alert_log)
        if ready_misp and ready_alert:
            return
        time.sleep(1.5)


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


def _extract_victim_ip_from_misp_lines(lines: list[str]) -> str | None:
    for ln in lines:
        low = ln.lower()
        if "ip-dst" in low:
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", ln)
            if m:
                return m.group(1)
    return None


def _neo4j_actor_profiles(victim_ip: str | None, limit: int = 1) -> list[dict[str, Any]]:
    neo4j_url = os.getenv("NEO4J_HTTP_URL", "http://neo4j:7474/db/neo4j/tx/commit")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_pass = os.getenv("NEO4J_PASS", "neo4jpass")
    if not victim_ip:
        return []

    statement = (
        "MATCH (a:Actor)-[:TARGETS]->(t:Target) "
        "WHERE t.ip CONTAINS $victim_ip "
        "AND a.id STARTS WITH 'novadef-' "
        "OPTIONAL MATCH (a)-[:ORIGINATES_FROM]->(s:SourceIP) "
        "OPTIONAL MATCH (a)-[:USES]->(x:Technique) "
        "RETURN a, collect(DISTINCT s.ip) AS source_ips, collect(DISTINCT x.id) AS techniques "
        "ORDER BY a.lastActivity DESC LIMIT $limit"
    )
    payload = json.dumps(
        {
            "statements": [
                {
                    "statement": statement,
                    "parameters": {"victim_ip": victim_ip, "limit": int(limit)},
                }
            ]
        }
    ).encode("utf-8")
    token = base64.b64encode(f"{neo4j_user}:{neo4j_pass}".encode("utf-8")).decode("ascii")
    req = urlrequest.Request(
        neo4j_url,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {token}"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            raw = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urlerror.URLError, TimeoutError, json.JSONDecodeError):
        return []

    results = ((raw.get("results") or [{}])[0].get("data") or [])
    out: list[dict[str, Any]] = []
    for row in results:
        vals = row.get("row") or []
        if len(vals) < 3:
            continue
        actor = vals[0] or {}
        out.append(
            {
                "actor_id": actor.get("id"),
                "profile": actor.get("profile"),
                "riskLevel": actor.get("riskLevel"),
                "country": actor.get("country"),
                "motivation": actor.get("motivation"),
                "affiliation": actor.get("affiliation"),
                "skills": actor.get("skills"),
                "knowledge": actor.get("knowledge"),
                "attitude": actor.get("attitude"),
                "automationLevel": actor.get("automationLevel"),
                "comments": actor.get("comments"),
                "firstSeen": actor.get("firstSeen"),
                "lastActivity": actor.get("lastActivity"),
                "source_ips": vals[1] or [],
                "techniques": vals[2] or [],
            }
        )
    return out


def _latest_misp_event_from_db(experiment: str) -> dict[str, str] | None:
    where = "1=1"
    if experiment == "exp1":
        where = "info LIKE '%Password Spraying%' OR info LIKE '%Brute Force%'"
    elif experiment == "exp2":
        where = "info LIKE '%Host Ransomware Emulation Detected%' OR info LIKE '%FALCO:%'"
    cmd = (
        "mysql -uroot -pmy_root_password misp -NBe "
        f"\"SELECT id, info FROM events WHERE {where} ORDER BY id DESC LIMIT 1;\""
    )
    try:
        db = DOCKER_CLIENT.containers.get("pmp-misp-db")
        res = db.exec_run(["sh", "-lc", cmd], stdout=True, stderr=True)
        out = (res.output or b"").decode("utf-8", errors="replace").strip()
        if not out:
            return None
        parts = out.split("\t", 1)
        if not parts or not parts[0].isdigit():
            return None
        info = parts[1] if len(parts) > 1 else ""
        return {"id": parts[0], "info": info}
    except Exception:
        return None


def _runtime_experiment_summary(experiment: str, started: float | None, last_output: str) -> dict[str, str]:
    since_ts = int(started) if started else None
    observe_blob = (
        _tail_logs("tshark_novadef", 350, since_ts=since_ts)
        + "\n"
        + _tail_logs("falco_novadef", 350, since_ts=since_ts)
        + "\n"
        + _tail_logs("scenario_attacker", 220, since_ts=since_ts)
    ).lower()
    detect_blob = (
        _tail_logs("network_intrusion_detector_novadef", 450, since_ts=since_ts)
        + "\n"
        + _tail_logs("snort_novadef", 450, since_ts=since_ts)
        + "\n"
        + _tail_logs("alert_module_novadef", 450, since_ts=since_ts)
    ).lower()
    profile_blob = (
        _tail_logs("novadef-novadef_stream_low-1", 450, since_ts=since_ts)
        + "\n"
        + _tail_logs("novadef-novadef_prep_pred-1", 280, since_ts=since_ts)
        + "\n"
        + _tail_logs("pmp-misp-integrator", 450, since_ts=since_ts)
    ).lower()
    soarca_blob = (
        _tail_logs("pmp-misp-soarca-trigger", 450, since_ts=since_ts)
        + "\n"
        + _tail_logs("pmp-soarca-core", 450, since_ts=since_ts)
        + "\n"
        + _tail_logs("pmp-soarca-executor-ssh", 450, since_ts=since_ts)
        + "\n"
        + _tail_logs("scenario_victim", 300, since_ts=since_ts)
    )
    soarca_low = soarca_blob.lower()
    output_low = (last_output or "").lower()

    if experiment == "exp2":
        scope = "Host telemetry (Falco + endpoint activity)"
        if any(k in detect_blob for k in ["anomaly", "isolation forest", "outlier"]):
            detection = "Anomaly detector"
        elif any(k in detect_blob for k in ["falco", "rule", "ransom", "impact", "t1486", "t1490", "t1489"]):
            detection = "Rule-based (Falco)"
        else:
            detection = "Pending / no clear detector evidence yet"
        if "perfil tapcd inyectado" in profile_blob:
            profile = "TAPCD profile injected"
        elif any(k in profile_blob for k in ["profile", "attacker", "incident", "classification", "perfil"]):
            profile = "TAPCD profile evidence observed"
        else:
            profile = "Pending / no clear TAPCD profile evidence yet"
    else:
        scope = "Network telemetry (tshark/flows/auth events)"
        if any(k in detect_blob for k in ["anomaly", "isolation forest", "outlier"]):
            detection = "Anomaly detector (network IDS)"
        elif any(k in detect_blob for k in ["snort", "rule", "signature"]):
            detection = "Rule-based (Snort)"
        else:
            detection = "Pending / no clear detector evidence yet"
        if "perfil tapcd inyectado" in profile_blob:
            profile = "TAPCD profile injected"
        elif any(k in profile_blob for k in ["profile", "attacker", "incident", "classification", "perfil"]):
            profile = "TAPCD profile evidence observed"
        else:
            profile = "Pending / no clear TAPCD profile evidence yet"

    countermeasure, _ = _detect_countermeasure(soarca_blob, experiment)
    success_hit = any(
        k in soarca_low
        for k in [
            "✅ playbook ejecutado",
            "✅ playbook de aislamiento ejecutado",
            "playbook ejecutado",
            "applied",
            "executed",
            "executor",
            "response",
            "countermeasure",
        ]
    )
    error_hit = any(k in soarca_low for k in ["i/o timeout", "dial tcp", "eof", "error"])
    # Prefer explicit execution success if both success and noise/errors coexist.
    if success_hit or ("rc=0" in output_low):
        countermeasure_status = f"MITRE D3FEND: {countermeasure} (applied)"
    elif error_hit:
        countermeasure_status = f"MITRE D3FEND: {countermeasure} (attempted, execution errors detected)"
    else:
        countermeasure_status = f"MITRE D3FEND: {countermeasure} (pending evidence)"

    return {
        "observation_scope": scope,
        "detection_method": detection,
        "tapcd_profile": profile,
        "countermeasure": countermeasure_status,
    }


def _summary_from_latest_report(report_id: str) -> dict[str, str] | None:
    try:
        p = REPORTS_DIR / report_id / "incident_report.json"
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

    ex = str(data.get("experiment") or "")
    misp = data.get("misp") or {}
    tapcd = data.get("tapcd") or {}
    cm = data.get("countermeasure") or {}
    cm_excerpt = str(cm.get("soarca_excerpt") or "").lower()

    scope = "Host telemetry (Falco + endpoint activity)" if ex == "exp2" else "Network telemetry (tshark/flows/auth events)"
    detection = "Anomaly +/or Rule-based (evidence in report)"
    if ex == "exp1":
        detection = "Anomaly detector (network IDS)"
    elif ex == "exp2":
        detection = "Rule-based (Falco)"
    elif any("anomaly" in (a.get("line", "").lower()) for a in (data.get("alerts") or [])):
        detection = "Anomaly detector (network IDS)"
    elif any("snort" in (a.get("line", "").lower()) for a in (data.get("alerts") or [])):
        detection = "Rule-based (Snort)"

    profile_lines = tapcd.get("profile_detail_lines") or []
    profile_mentions = int(((tapcd.get("signals") or {}).get("profile_mentions")) or 0)
    profile = "TAPCD profile injected" if profile_lines or profile_mentions > 0 else "Pending / no clear TAPCD profile evidence yet"

    selected = str(cm.get("selected") or "-")
    if any(k in cm_excerpt for k in ["playbook ejecutado", "applied", "response", "executor"]):
        countermeasure = f"MITRE D3FEND: {selected} (applied)"
    elif any(k in cm_excerpt for k in ["eof", "i/o timeout", "dial tcp", "error"]):
        countermeasure = f"MITRE D3FEND: {selected} (attempted, execution errors detected)"
    else:
        countermeasure = f"MITRE D3FEND: {selected} (pending evidence)"

    return {
        "observation_scope": scope,
        "detection_method": detection,
        "tapcd_profile": profile,
        "countermeasure": countermeasure,
    }


def _report_panel_from_latest_report(report_id: str) -> dict[str, Any] | None:
    try:
        p = REPORTS_DIR / report_id / "incident_report.json"
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

    misp = data.get("misp") or {}
    tapcd = data.get("tapcd") or {}
    return {
        "misp": {
            "event_ids_detected_in_logs": misp.get("event_ids_detected_in_logs") or [],
            "event_signal_count": int(misp.get("event_signal_count") or 0),
            "event_details_extracted": len(misp.get("event_detail_lines") or []),
            "event_detail_lines": misp.get("event_detail_lines") or [],
        },
        "tapcd": {
            "profile_mentions": int(((tapcd.get("signals") or {}).get("profile_mentions")) or 0),
            "attacker_mentions": int(((tapcd.get("signals") or {}).get("attacker_mentions")) or 0),
            "incident_mentions": int(((tapcd.get("signals") or {}).get("incident_mentions")) or 0),
            "profile_details_extracted": len(tapcd.get("profile_detail_lines") or []),
            "profile_detail_lines": tapcd.get("profile_detail_lines") or [],
            "actor_profile_count": int(tapcd.get("actor_profile_count") or 0),
            "actor_profiles": tapcd.get("actor_profiles") or [],
        },
    }


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
    misp_lines = misp_blob.splitlines()
    event_ids = sorted(
        set(
            re.findall(
                r"(?:\bevent(?:_id| id)?[=: ]+|nuevo evento misp\s*#)\s*(\d+)\b",
                misp_blob,
                flags=re.IGNORECASE,
            )
        )
    )
    duplicate_campaign = any(k in misp_blob.lower() for k in ["[dedup-persist]", "[dedup-link]"])
    reused_event = None
    if not event_ids and duplicate_campaign:
        reused_event = _latest_misp_event_from_db(str(experiment))
        if reused_event and reused_event.get("id"):
            event_ids = [str(reused_event["id"])]
    tapcd_blob = "\n".join(profile_logs.values())
    tapcd_blob_all = tapcd_blob + "\n" + misp_blob
    tapcd_lines = tapcd_blob_all.splitlines()
    misp_event_detail_lines = [
        ln
        for ln in misp_lines
        if any(
            k in ln.lower()
            for k in [
                "nuevo evento misp",
                "[+] ip-src",
                "[+] ip-dst",
                "[+] port",
                "[+] text",
                "cic flows",
            ]
        )
    ]
    if reused_event:
        misp_event_detail_lines.append(f"[REUSED EXISTING EVENT] id={reused_event.get('id')} info={reused_event.get('info','')}")
    tapcd_profile_detail_lines = [
        ln
        for ln in tapcd_lines
        if any(
            k in ln.lower()
            for k in [
                "perfil tapcd inyectado",
                "[tapcd]",
                "perfil actor",
                "profile",
                "attacker",
                "incident",
            ]
        )
    ]
    victim_ip = _extract_victim_ip_from_misp_lines(misp_event_detail_lines)
    actor_profiles = _neo4j_actor_profiles(victim_ip, limit=5)
    tapcd_indicators = {
        "profile_mentions": (
            tapcd_blob_all.lower().count("profile")
            + tapcd_blob_all.lower().count("perfil")
            + tapcd_blob_all.lower().count("perfil tapcd inyectado")
        ),
        "attacker_mentions": (
            tapcd_blob_all.lower().count("attacker")
            + tapcd_blob_all.lower().count("actor")
            + tapcd_blob_all.lower().count("amenaza")
        ),
        "incident_mentions": (
            tapcd_blob_all.lower().count("incident")
            + tapcd_blob_all.lower().count("incidente")
        ),
    }

    soarca_blob = "\n".join(soarca_logs.values())
    countermeasure, why = _detect_countermeasure(soarca_blob, experiment)
    if duplicate_campaign and reused_event:
        countermeasure = "No new action (existing incident/countermeasure reused)"
        why = "Duplicate campaign detected for same target+attack+time bucket; reused existing MISP/TAPCD context and skipped new response action."
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
            "event_signal_count": (
                misp_blob.lower().count("event")
                + misp_blob.lower().count("evento")
                + misp_blob.lower().count("nuevo evento misp")
            ),
            "event_detail_lines": misp_event_detail_lines[-250:],
            "log_excerpt": misp_blob[-6000:],
            "full_log": misp_blob,
            "reused_existing_event": bool(reused_event),
        },
        "tapcd": {
            "signals": tapcd_indicators,
            "profile_detail_lines": tapcd_profile_detail_lines[-250:],
            "actor_profiles": actor_profiles,
            "actor_profile_count": len(actor_profiles),
            "log_excerpt": tapcd_blob_all[-6000:],
            "full_log": tapcd_blob_all,
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
- Event details extracted: `{len(misp.get("event_detail_lines") or [])}`

## TAPCD
- Profile mentions: `{tapcd["signals"]["profile_mentions"]}`
- Attacker mentions: `{tapcd["signals"]["attacker_mentions"]}`
- Incident mentions: `{tapcd["signals"]["incident_mentions"]}`
- Profile details extracted: `{len(tapcd.get("profile_detail_lines") or [])}`
- Actor profiles from Neo4j: `{tapcd.get("actor_profile_count", 0)}`

## Countermeasure
- Selected: `{cm.get("selected")}`
- Why: {cm.get("justification")}
- D3FEND basis: {cm.get("d3fend_basis")}

## Full Artifacts
- `misp_full.log` and `tapcd_full.log` are included in the ZIP bundle.
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
    misp_log_path = report_dir / "misp_full.log"
    tapcd_log_path = report_dir / "tapcd_full.log"
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
    misp_log_path.write_text(str((payload.get("misp") or {}).get("full_log") or ""), encoding="utf-8")
    tapcd_log_path.write_text(str((payload.get("tapcd") or {}).get("full_log") or ""), encoding="utf-8")

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
        zf.write(misp_log_path, arcname="misp_full.log")
        zf.write(tapcd_log_path, arcname="tapcd_full.log")

    with LOCK:
        STATE["last_report_id"] = report_id
    return report_id


def _update_history(run_id: str, patch: dict[str, Any]) -> None:
    with LOCK:
        for item in RUN_HISTORY:
            if item.get("run_id") == run_id:
                item.update(patch)
                break


def _history_item(run_id: str) -> dict[str, Any] | None:
    with LOCK:
        for item in RUN_HISTORY:
            if str(item.get("run_id")) == str(run_id):
                return dict(item)
    return None


def _latest_misp_event_for_run(experiment: str, started_ts: float | None, strict_time: bool = True) -> dict[str, Any] | None:
    where = "1=1"
    if experiment == "exp1":
        where = "(info LIKE '%Password Spraying%' OR info LIKE '%Brute Force%')"
    elif experiment == "exp2":
        where = "(info LIKE '%Host Ransomware Emulation Detected%' OR info LIKE '%FALCO:%')"
    if strict_time and started_ts:
        where += f" AND timestamp >= {int(started_ts) - 5}"
    cmd = (
        "mysql -uroot -pmy_root_password misp -NBe "
        f"\"SELECT id, info, date, timestamp FROM events WHERE {where} ORDER BY id DESC LIMIT 1;\""
    )
    try:
        db = DOCKER_CLIENT.containers.get("pmp-misp-db")
        res = db.exec_run(["sh", "-lc", cmd], stdout=True, stderr=True)
        out = (res.output or b"").decode("utf-8", errors="replace").strip()
        if not out:
            return None
        parts = out.split("\t")
        if len(parts) < 1 or not parts[0].isdigit():
            return None
        return {
            "id": parts[0],
            "info": parts[1] if len(parts) > 1 else "",
            "date": parts[2] if len(parts) > 2 else "",
            "timestamp": parts[3] if len(parts) > 3 else "",
        }
    except Exception:
        return None


def _misp_event_attributes(event_id: str) -> list[dict[str, str]]:
    cmd = (
        "mysql -uroot -pmy_root_password misp -NBe "
        f"\"SELECT type, category, value FROM attributes WHERE event_id={int(event_id)} ORDER BY id ASC LIMIT 200;\""
    )
    try:
        db = DOCKER_CLIENT.containers.get("pmp-misp-db")
        res = db.exec_run(["sh", "-lc", cmd], stdout=True, stderr=True)
        out = (res.output or b"").decode("utf-8", errors="replace").strip()
        attrs: list[dict[str, str]] = []
        for ln in out.splitlines():
            p = ln.split("\t")
            if len(p) >= 3:
                attrs.append({"type": p[0], "category": p[1], "value": p[2]})
        return attrs
    except Exception:
        return []


def _build_live_report_panel(experiment: str, started_ts: float | None) -> dict[str, Any]:
    since_ts = int(started_ts) if started_ts else None
    misp_blob = _tail_logs("pmp-misp-integrator", 550, since_ts=since_ts) + "\n" + _tail_logs("pmp-misp-server", 400, since_ts=since_ts)
    tapcd_blob = (
        _tail_logs("novadef-novadef_stream_low-1", 600, since_ts=since_ts)
        + "\n"
        + _tail_logs("novadef-novadef_prep_pred-1", 350, since_ts=since_ts)
        + "\n"
        + misp_blob
    )
    lines = misp_blob.splitlines()
    event_ids = sorted(
        set(
            re.findall(
                r"(?:\bevent(?:_id| id)?[=: ]+|nuevo evento misp\s*#)\s*(\d+)\b",
                misp_blob,
                flags=re.IGNORECASE,
            )
        )
    )
    duplicate_campaign = any(k in misp_blob.lower() for k in ["[dedup-persist]", "[dedup-link]"])
    latest_event = _latest_misp_event_for_run(experiment, started_ts, strict_time=True)
    if not latest_event and duplicate_campaign:
        # In repeated campaigns, MISP may intentionally reuse a previous event
        # (outside this run window). Show that reused context instead of empty panel.
        latest_event = _latest_misp_event_for_run(experiment, started_ts, strict_time=False)
    if latest_event and latest_event.get("id") and str(latest_event["id"]) not in event_ids:
        event_ids.append(str(latest_event["id"]))
    attrs = _misp_event_attributes(str(latest_event.get("id"))) if latest_event and latest_event.get("id") else []
    victim_ip = None
    for a in attrs:
        if str(a.get("type")) == "ip-dst":
            victim_ip = str(a.get("value"))
            break
    if not victim_ip:
        victim_ip = _extract_victim_ip_from_misp_lines(lines)
    if not victim_ip and latest_event:
        # exp2 may not emit ip-dst attribute; recover victim IP from event info text.
        info_txt = str(latest_event.get("info") or "")
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", info_txt)
        if m:
            victim_ip = m.group(1)
    actors = _neo4j_actor_profiles(victim_ip, limit=5)
    return {
        "misp": {
            "event_ids_detected_in_logs": event_ids,
            "event_signal_count": misp_blob.lower().count("event") + misp_blob.lower().count("evento") + misp_blob.lower().count("nuevo evento misp"),
            "event_details_extracted": len(attrs),
            "event_detail_lines": [ln for ln in lines if any(k in ln.lower() for k in ["nuevo evento misp", "[+] ip-", "[+] port", "[+] text", "cic flows"])][-120:],
            "event_object": {
                "event": latest_event or {},
                "attributes": attrs,
            },
            "reused_existing_event": bool(duplicate_campaign and latest_event),
        },
        "tapcd": {
            "profile_mentions": tapcd_blob.lower().count("profile") + tapcd_blob.lower().count("perfil"),
            "attacker_mentions": tapcd_blob.lower().count("attacker") + tapcd_blob.lower().count("actor"),
            "incident_mentions": tapcd_blob.lower().count("incident") + tapcd_blob.lower().count("incidente"),
            "profile_details_extracted": len(actors),
            "profile_detail_lines": [ln for ln in tapcd_blob.splitlines() if any(k in ln.lower() for k in ["perfil tapcd inyectado", "[tapcd]", "perfil actor", "profile", "attacker", "incident"])][-160:],
            "actor_profile_count": len(actors),
            "actor_profiles": actors,
            "profile_object": {"actors": actors},
        },
    }


def _run_background(experiment: str, run_id: str) -> None:
    try:
        _wait_kafka_consumers_ready()
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
            STATE["current_run_id"] = None
        _update_history(
            run_id,
            {
                "running": False,
                "finished_at": STATE.get("last_finished_at"),
                "return_code": rc,
                "output_tail": output[-2500:],
            },
        )
        if rc == 0:
            try:
                _wait_for_pipeline_completion(experiment, STATE.get("last_started_at"))
                with LOCK:
                    STATE["last_finished_at"] = time.time()
                payload = _build_report_payload()
                report_id = _persist_report(payload)
                _update_history(
                    run_id,
                    {
                        "report_id": report_id,
                        "summary": _runtime_experiment_summary(
                            experiment, STATE.get("last_started_at"), str(STATE.get("last_output") or "")
                        ),
                        "report_panel": _report_panel_from_latest_report(report_id),
                    },
                )
            except Exception as e:
                with LOCK:
                    STATE["last_output"] = (STATE.get("last_output", "") + f"\n[report-error] {e}")[-12000:]
                _update_history(run_id, {"report_error": str(e)})
    except Exception as e:
        with LOCK:
            STATE["running"] = False
            STATE["last_return_code"] = 1
            STATE["last_output"] = f"Experiment execution error: {e}"
            STATE["last_finished_at"] = time.time()
            STATE["current_run_id"] = None
        _update_history(
            run_id,
            {
                "running": False,
                "finished_at": STATE.get("last_finished_at"),
                "return_code": 1,
                "output_tail": f"Experiment execution error: {e}",
                "report_error": str(e),
            },
        )


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok"})


@app.get("/api/containers")
def containers_state() -> Any:
    out: list[dict[str, str]] = []
    try:
        for c in DOCKER_CLIENT.containers.list(all=True):
            state = str((c.attrs or {}).get("State", {}).get("Status", "")).lower()
            out.append({"name": c.name, "state": state})
    except Exception:
        return jsonify([])
    return jsonify(out)


@app.get("/api/state")
def state() -> Any:
    run_id = request.args.get("run_id", "").strip()
    if run_id:
        run_item = _history_item(run_id)
        if not run_item:
            return jsonify({"ok": False, "error": "run_id not found"}), 404
        experiment = str(run_item.get("experiment") or "")
        started_ts = run_item.get("started_at")
        panel = _build_live_report_panel(experiment, started_ts) if experiment else None
        summary = _runtime_experiment_summary(experiment, started_ts, str(run_item.get("output_tail") or "")) if experiment else None
        payload = {
            "running": bool(run_item.get("running")),
            "last_experiment": experiment,
            "last_started_at": started_ts,
            "last_finished_at": run_item.get("finished_at"),
            "last_return_code": run_item.get("return_code"),
            "last_output": str(run_item.get("output_tail") or ""),
            "current_run_id": run_id,
            "summary": summary,
            "report_panel": panel,
            "last_report_id": run_item.get("report_id"),
        }
        return jsonify(payload)

    with LOCK:
        snapshot = dict(STATE)
    experiment = snapshot.get("last_experiment")
    running = bool(snapshot.get("running"))
    if experiment and not running:
        summary = _runtime_experiment_summary(
            str(experiment),
            snapshot.get("last_started_at"),
            str(snapshot.get("last_output") or ""),
        )
        report_id = str(snapshot.get("last_report_id") or "")
        if report_id:
            report_summary = _summary_from_latest_report(report_id)
            if report_summary:
                summary = report_summary
            report_panel = _report_panel_from_latest_report(report_id)
            if report_panel:
                snapshot["report_panel"] = report_panel
        snapshot["summary"] = summary
    return jsonify(snapshot)


@app.get("/api/history")
def history() -> Any:
    with LOCK:
        runs = list(reversed(RUN_HISTORY[-100:]))
    return jsonify({"runs": runs})


@app.get("/api/progress")
def progress() -> Any:
    run_id = request.args.get("run_id", "").strip()
    if run_id:
        run_item = _history_item(run_id)
        if not run_item:
            return jsonify({"ok": False, "error": "run_id not found"}), 404
        experiment = run_item.get("experiment")
        started = run_item.get("started_at")
        running = bool(run_item.get("running"))
        rc = run_item.get("return_code")
        last_output = str(run_item.get("output_tail") or "")
    else:
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
        "act": _tail_logs("pmp-misp-soarca-trigger", 500, since_ts=since_ts) + "\n" + _tail_logs("pmp-soarca-core", 500, since_ts=since_ts) + "\n" + _tail_logs("pmp-soarca-executor-ssh", 500, since_ts=since_ts) + "\n" + _tail_logs("scenario_victim", 350, since_ts=since_ts),
    }
    output_low = last_output.lower()

    if experiment == "exp2":
        observe_hit = any(k in logs["observe"].lower() for k in ["falco", "syscall", "file", "process"])
        detect_blob = (logs["detect"] + "\n" + logs["observe"] + "\n" + logs["enrich"]).lower()
        detect_hit = any(k in detect_blob for k in ["ransom", "impact", "alert", "detected", "nueva alerta", "alerta recibida", "host ransomware emulation detected", "[falco]"])
        profile_hit = any(k in (logs["profile"] + "\n" + logs["enrich"]).lower() for k in ["perfil tapcd inyectado", "profile", "attacker", "incident", "classification", "perfil actor"])
        enrich_hit = any(k in logs["enrich"].lower() for k in ["nuevo evento misp", "event", "misp", "attribute", "publish", "created"])
        decide_hit = any(k in logs["act"].lower() for k in ["d3fend", "playbook", "selected", "countermeasure"])
        act_hit = any(k in logs["act"].lower() for k in ["playbook de aislamiento ejecutado", "playbook ejecutado", "executor", "applied", "isolation", "terminate", "restor", "response"])
    else:
        observe_hit = any(k in logs["observe"].lower() for k in ["tshark", "packet", "ssh", "flow", "password spraying completado"]) or ("password spraying completado" in output_low)
        detect_hit = any(k in logs["detect"].lower() for k in ["spray", "brute", "anomaly", "snort", "alert", "nueva alerta", "alerta recibida"])
        profile_hit = any(k in (logs["profile"] + "\n" + logs["enrich"]).lower() for k in ["perfil tapcd inyectado", "profile", "attacker", "incident", "classification", "perfil actor"])
        enrich_hit = any(k in logs["enrich"].lower() for k in ["nuevo evento misp", "event", "misp", "attribute", "publish", "created"])
        decide_hit = any(k in logs["act"].lower() for k in ["d3fend", "playbook", "selected", "countermeasure"])
        act_hit = any(k in logs["act"].lower() for k in ["playbook ejecutado", "executor", "applied", "block", "lock", "isolation", "response"])

    stages = [
        {"key": "observe", "done": observe_hit},
        {"key": "detect", "done": detect_hit},
        {"key": "profile", "done": profile_hit},
        {"key": "enrich", "done": enrich_hit},
        {"key": "decide", "done": decide_hit},
        {"key": "act", "done": act_hit},
    ]

    # After execution ends, prefer concrete evidence from generated report.
    if not running and rc == 0:
        report_id = str(run_item.get("report_id") if run_id else STATE.get("last_report_id") or "")
        if report_id:
            panel = _report_panel_from_latest_report(report_id) or {}
            try:
                report_json = REPORTS_DIR / report_id / "incident_report.json"
                report_data = json.loads(report_json.read_text(encoding="utf-8")) if report_json.exists() else {}
            except Exception:
                report_data = {}

            misp_panel = panel.get("misp") or {}
            tapcd_panel = panel.get("tapcd") or {}
            cm = report_data.get("countermeasure") or {}
            cm_selected = str(cm.get("selected") or "").strip()
            cm_excerpt = str(cm.get("soarca_excerpt") or "").lower()

            profile_done = bool((tapcd_panel.get("profile_details_extracted") or 0) > 0 or (tapcd_panel.get("profile_mentions") or 0) > 0)
            enrich_done = bool((misp_panel.get("event_details_extracted") or 0) > 0 or (misp_panel.get("event_ids_detected_in_logs") or []))
            decide_done = bool(cm_selected and cm_selected != "-")
            act_done = any(k in cm_excerpt for k in ["playbook ejecutado", "applied", "executor", "response"])

            for st in stages:
                if st["key"] == "profile":
                    st["done"] = profile_done
                elif st["key"] == "enrich":
                    st["done"] = enrich_done
                elif st["key"] == "decide":
                    st["done"] = decide_done
                elif st["key"] == "act":
                    st["done"] = act_done
    return jsonify({"experiment": experiment, "stages": stages})


@app.get("/api/metrics")
def metrics() -> Any:
    with LOCK:
        runs = list(RUN_HISTORY)
    if not runs:
        return jsonify({"alert_signals": 0, "profile_signals": 0, "misp_signals": 0, "soarca_signals": 0, "timestamp": time.time()})

    alert_total = 0
    profile_total = 0
    misp_total = 0
    soarca_total = 0

    for run in runs:
        report_id = str(run.get("report_id") or "").strip()
        if not report_id:
            continue
        alert_total += 1
        panel = run.get("report_panel") or _report_panel_from_latest_report(report_id) or {}
        misp_panel = panel.get("misp") or {}
        tapcd_panel = panel.get("tapcd") or {}
        if (tapcd_panel.get("profile_details_extracted") or 0) > 0 or (tapcd_panel.get("profile_mentions") or 0) > 0:
            profile_total += 1
        if (misp_panel.get("event_ids_detected_in_logs") or []):
            misp_total += 1
        try:
            report_json = REPORTS_DIR / report_id / "incident_report.json"
            report_data = json.loads(report_json.read_text(encoding="utf-8")) if report_json.exists() else {}
        except Exception:
            report_data = {}
        cm_excerpt = str((report_data.get("countermeasure") or {}).get("soarca_excerpt") or "").lower()
        if any(k in cm_excerpt for k in ["playbook ejecutado", "playbook de aislamiento ejecutado", "applied", "executor", "response"]):
            soarca_total += 1

    return jsonify(
        {
            "alert_signals": alert_total,
            "profile_signals": profile_total,
            "misp_signals": misp_total,
            "soarca_signals": soarca_total,
            "timestamp": time.time(),
        }
    )


@app.post("/api/report/generate")
def generate_report() -> Any:
    return jsonify({"ok": False, "error": "manual generation disabled: report is created automatically after each experiment run"}), 405


@app.get("/api/report/latest")
def latest_report() -> Any:
    run_id = request.args.get("run_id", "").strip()
    if run_id:
        run_item = _history_item(run_id)
        if not run_item:
            return jsonify({"ok": False, "error": "run_id not found"}), 404
        report_id = run_item.get("report_id")
        if not report_id:
            return jsonify({"ok": False, "error": "no report generated yet"}), 404
        return jsonify({"ok": True, "report_id": report_id, "download_url": f"/api/report/download/{report_id}"})

    with LOCK:
        report_id = STATE.get("last_report_id")
        running = bool(STATE.get("running"))
        has_experiment = bool(STATE.get("last_experiment"))
        has_finished = bool(STATE.get("last_finished_at"))
    if not report_id:
        # Auto-regenerate report if an experiment already finished but report_id
        # is missing (e.g. API restart or previous persistence failure).
        if has_experiment and has_finished and not running:
            try:
                payload = _build_report_payload()
                report_id = _persist_report(payload)
                with LOCK:
                    STATE["last_report_error"] = ""
            except Exception as e:
                err = f"report regeneration failed: {e}"
                with LOCK:
                    STATE["last_report_error"] = err
                return jsonify({"ok": False, "error": err}), 500
        else:
            return jsonify({"ok": False, "error": "no report generated yet"}), 404
    return jsonify({"ok": True, "report_id": report_id, "download_url": f"/api/report/download/{report_id}"})


@app.get("/api/report/download/<report_id>")
def download_report(report_id: str) -> Any:
    zip_path = REPORTS_DIR / report_id / "incident_report_bundle.zip"
    if not zip_path.exists():
        return jsonify({"ok": False, "error": "report not found"}), 404
    return send_file(zip_path, as_attachment=True, download_name=f"novadef_incident_report_{report_id}.zip")


@app.get("/api/report/log/<report_id>/<log_name>")
def download_report_log(report_id: str, log_name: str) -> Any:
    allowed = {"misp_full.log", "tapcd_full.log"}
    if log_name not in allowed:
        return jsonify({"ok": False, "error": "invalid log name"}), 400
    p = REPORTS_DIR / report_id / log_name
    if not p.exists():
        return jsonify({"ok": False, "error": "log not found"}), 404
    return send_file(p, as_attachment=True, download_name=f"{report_id}_{log_name}")


@app.post("/api/run")
def run() -> Any:
    payload = request.get_json(silent=True) or {}
    experiment = payload.get("experiment")
    if experiment not in {"exp1", "exp2"}:
        return jsonify({"ok": False, "error": "experiment must be exp1 or exp2"}), 400

    with LOCK:
        if STATE["running"]:
            return jsonify({"ok": False, "error": "another experiment is running"}), 409
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{experiment}"
        STATE["running"] = True
        STATE["last_experiment"] = experiment
        STATE["last_started_at"] = time.time()
        STATE["last_finished_at"] = None
        STATE["last_return_code"] = None
        STATE["last_output"] = ""
        STATE["last_report_error"] = ""
        STATE["current_run_id"] = run_id
        RUN_HISTORY.append(
            {
                "run_id": run_id,
                "experiment": experiment,
                "started_at": STATE["last_started_at"],
                "finished_at": None,
                "running": True,
                "return_code": None,
                "report_id": None,
                "summary": None,
                "report_panel": None,
                "output_tail": "",
                "report_error": "",
            }
        )

    t = threading.Thread(target=_run_background, args=(experiment, run_id), daemon=True)
    t.start()
    return jsonify({"ok": True, "started": experiment, "run_id": run_id})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18082)
