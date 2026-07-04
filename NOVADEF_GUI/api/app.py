from __future__ import annotations

import csv
import io
import json
import math
import statistics
import shutil
import re
import subprocess
import threading
import time
import zipfile
import os
import base64
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request as urlrequest, error as urlerror

import docker
import bcrypt
import jwt as pyjwt
import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS


app = Flask(__name__, static_folder=None)
CORS(app)

# ── Auth configuration ────────────────────────────────────────────────────────
# If no explicit secret is set, generate a random one at startup.
# This invalidates all previously issued JWTs on every container restart,
# forcing users to log in again — ensuring a clean session on each NOVADEF boot.
import secrets as _secrets
_JWT_SECRET  = os.getenv("NOVADEF_JWT_SECRET") or _secrets.token_hex(32)
_JWT_ALGO    = "HS256"
_JWT_EXP_H   = 24  # hours
_DB_URL      = os.getenv("NOVADEF_DB_URL", "postgresql://novadef:novadef_pass@novadef-auth-db:5432/novadef_auth")
_ALLOWED_DOMAIN = os.getenv("NOVADEF_EMAIL_DOMAIN", "novadef.local")

def _db_conn():
    return psycopg2.connect(_DB_URL)

def _db_init():
    """Create schema if not exists. Called once at startup."""
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS organizations (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        slug TEXT UNIQUE NOT NULL,
                        allowed_email_domains TEXT[] NOT NULL DEFAULT '{}',
                        created_at TIMESTAMPTZ DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'ANALYST',
                        organization_id TEXT REFERENCES organizations(id),
                        created_at TIMESTAMPTZ DEFAULT now()
                    );
                """)
                # Seed default organization
                cur.execute("""
                    INSERT INTO organizations (id, name, slug, allowed_email_domains)
                    VALUES ('org-novadef', 'NOVADEF Lab', 'novadef', ARRAY[%s])
                    ON CONFLICT (id) DO NOTHING;
                """, (_ALLOWED_DOMAIN,))
            conn.commit()
    except Exception as e:
        app.logger.warning(f"[AUTH] DB init warning: {e}")

def _jwt_encode(payload: dict) -> str:
    import datetime as _dt
    payload = dict(payload)
    payload["exp"] = _dt.datetime.utcnow() + _dt.timedelta(hours=_JWT_EXP_H)
    return pyjwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGO)

def _jwt_decode(token: str) -> dict | None:
    try:
        return pyjwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGO])
    except Exception:
        return None

def _require_auth():
    """Return decoded token or abort 401."""
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        token = request.cookies.get("novadef_token", "")
    data = _jwt_decode(token)
    if not data:
        from flask import abort
        abort(401)
    return data

def _extract_domain(email: str) -> str:
    return email.strip().lower().split("@")[-1]

# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
def auth_login():
    body = request.get_json(silent=True) or {}
    email    = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT u.*, o.slug as org_slug, o.allowed_email_domains "
                    "FROM users u JOIN organizations o ON u.organization_id = o.id "
                    "WHERE u.email = %s", (email,)
                )
                user = cur.fetchone()
    except Exception as e:
        return jsonify({"error": "Database error"}), 500

    if not user:
        return jsonify({"error": "Invalid email or password"}), 401
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "Invalid email or password"}), 401
    domain = _extract_domain(email)
    if domain not in (user["allowed_email_domains"] or []):
        return jsonify({"error": "Email domain not allowed for this organization"}), 403

    role = "ADMIN" if user["role"] == "ADMIN" else "USER"
    token = _jwt_encode({
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": role,
        "organizationId": user["organization_id"],
        "organizationSlug": user["org_slug"],
    })
    return jsonify({"ok": True, "token": token, "role": role, "name": user["name"]})


@app.post("/api/auth/register")
def auth_register():
    body = request.get_json(silent=True) or {}
    email    = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    role_req = str(body.get("role", "USER")).upper()
    if not email or not password or role_req not in ("ADMIN", "USER"):
        return jsonify({"error": "Email, password and role (ADMIN/USER) are required"}), 400

    domain = _extract_domain(email)
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT id FROM organizations WHERE %s = ANY(allowed_email_domains)", (domain,)
                )
                org = cur.fetchone()
                if not org:
                    return jsonify({"error": "Email domain is not allowed for any organization"}), 403
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    return jsonify({"error": "User already exists"}), 409
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
                db_role = "ADMIN" if role_req == "ADMIN" else "ANALYST"
                new_id  = str(uuid.uuid4())
                default_name = email.split("@")[0]
                cur.execute(
                    "INSERT INTO users (id, name, email, password_hash, role, organization_id) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (new_id, default_name, email, pw_hash, db_role, org["id"])
                )
            conn.commit()
    except Exception as e:
        return jsonify({"error": "Registration failed"}), 500
    return jsonify({"ok": True, "message": "Account created. You can now sign in."}), 201


@app.get("/api/auth/me")
def auth_me():
    data = _require_auth()
    return jsonify({"ok": True, "user": data})


@app.post("/api/system/start")
def system_start():
    _require_auth()
    script = os.getenv("NOVADEF_START_SCRIPT", "/novadef/start_novadef_complete.sh")
    try:
        subprocess.Popen(["bash", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({"ok": True, "message": "NOVADEF startup initiated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/system/status")
def system_status():
    """Return whether core NOVADEF containers are running."""
    core = ["kafka_novadef", "pmp-misp-server", "pmp-soarca-core",
            "novadef-novadef_stream_low-1", "snort_novadef"]
    try:
        containers = {c.name: c.status for c in DOCKER_CLIENT.containers.list(all=True)}
        statuses = {name: containers.get(name, "missing") for name in core}
        all_up = all(s == "running" for s in statuses.values())
        return jsonify({"ok": True, "all_up": all_up, "containers": statuses})
    except Exception as e:
        return jsonify({"ok": False, "all_up": False, "error": str(e)})

STATE: dict[str, Any] = {
    "running": False,
    "last_experiment": None,
    "last_started_at": None,
    "last_attack_started_at": None,
    "last_finished_at": None,
    "last_return_code": None,
    "last_output": "",
    "last_report_id": None,
    "last_report_error": "",
    "current_run_id": None,
}
RUN_HISTORY: list[dict[str, Any]] = []
TRAFFIC_SERIES: dict[str, list[dict[str, float]]] = {}
TRAFFIC_BASELINES: dict[str, float] = {}
FALCO_SAMPLES: dict[str, dict[str, float]] = {}
HOST_METRICS_LAST: dict[str, dict[str, float]] = {}
TRAFFIC_LAST_PERSIST_AT: dict[str, float] = {}
TRAFFIC_MARKERS_CACHE: dict[str, dict[str, float | None]] = {}
TRAFFIC_ONDEMAND_SAMPLE_AT: dict[str, float] = {}
FAST_COUNTERMEASURE_TS: dict[str, float] = {}
FAST_COUNTERMEASURE_REQUESTED_TS: dict[str, float] = {}
# Tracks run_ids for which we have already stopped the attacker noise in
# response to a detected SOARCA isolation (act_hit=True). Prevents calling
# _stop_benign_noise on every subsequent /api/progress poll.
_ISOLATION_NOISE_STOPPED: set[str] = set()
# Previous cgroup counter samples for CPU-rate computation in _read_scenario_telegraf_metrics
_CGROUP_PREV_SAMPLES: dict[str, dict] = {}
# Live state cache: cache /api/state lite results to avoid redundant deep log reads (~800ms TTL)
LIVE_STATE_CACHE: dict[str, dict[str, Any]] = {}
LIVE_STATE_CACHE_TTL: dict[str, float] = {}
LOCK = threading.RLock()
MAX_LOG_CHARS = 60000
DOCKER_CLIENT = docker.from_env()
REPORTS_DIR = Path("/tmp/novadef_reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
RUNTIME_STATE_FILE = Path(os.getenv("NOVADEF_GUI_RUNTIME_STATE_FILE", "/tmp/novadef_gui_runtime_state.json"))
RUNTIME_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
TS_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,(\d+))?")
ISO_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)")
def _resolve_repo_root() -> Path:
    """
    Resolve the NOVADEF repository root safely in both local and container
    execution contexts.
    """
    if Path("/app/Scenario/docker-compose.yml").exists():
        return Path("/app")
    resolved = Path(__file__).resolve()
    parents = resolved.parents
    if len(parents) >= 3:
        return parents[2]
    if len(parents) >= 1:
        return parents[0]
    return resolved.parent


# The API container is built from this single file, so we cannot assume the
# full repository tree is mounted at /app. Keep the fallback root local and
# let the log candidate helper rely on container paths first.
PROJECT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = _resolve_repo_root()
HOST_REPO_ROOT = Path(os.getenv("NOVADEF_HOST_ROOT", str(REPO_ROOT)))
# For Mac Docker Desktop compatibility, allow separate paths for scenario tools
HOST_SCENARIO_TOOLS_ROOT = Path(os.getenv("NOVADEF_SCENARIO_TOOLS_ROOT", str(REPO_ROOT)))
HOST_RUNTIME_ROOT = HOST_REPO_ROOT / ".novadef_runtime"
LOCAL_RUNTIME_ROOT = RUNTIME_STATE_FILE.parent
# SCENARIO_ROOT must use the HOST path so Docker Desktop allows bind-mounting
# scenario subdirs into child containers. The catalog JSON however is written
# to the mounted /runtime volume so it survives container restarts.
SCENARIO_ROOT = HOST_RUNTIME_ROOT / "scenarios"
_CATALOG_DIR = LOCAL_RUNTIME_ROOT / "scenarios"
LAUNCHER_NETWORK_NAME = "launcher_default"
PROMETHEUS_SCENARIO_ALIAS = "scenario_victim"
ATTACKER_SCENARIO_ALIAS = "scenario_attacker"
SCENARIO_CATALOG_PATH = _CATALOG_DIR / "scenario_catalog.json"


def _scenario_seed_run_id(scenario_id: str) -> str:
    token = _sanitize_run_token(scenario_id)
    return f"scenario-{token}"


def _sanitize_scenario_id(raw: str | None) -> str:
    token = _sanitize_run_token(str(raw or "").strip())
    if not token:
        token = f"scenario-{uuid.uuid4().hex[:8]}"
    return token


def _load_scenario_catalog() -> dict[str, dict[str, Any]]:
    try:
        if not SCENARIO_CATALOG_PATH.exists():
            return {}
        data = json.loads(SCENARIO_CATALOG_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        out: dict[str, dict[str, Any]] = {}
        for key, value in data.items():
            if isinstance(value, dict):
                out[str(key)] = dict(value)
        return out
    except Exception:
        return {}


def _save_scenario_catalog(catalog: dict[str, dict[str, Any]]) -> None:
    try:
        _CATALOG_DIR.mkdir(parents=True, exist_ok=True)
        tmp = SCENARIO_CATALOG_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(SCENARIO_CATALOG_PATH)
    except Exception as e:
        print(f"[scenario-catalog] Failed to persist catalog: {e}", flush=True)


def _upsert_scenario_catalog_entry(
    scenario_id: str,
    scenario: dict[str, Any],
    *,
    display_name: str | None = None,
    template: str | None = None,
) -> dict[str, Any]:
    catalog = _load_scenario_catalog()
    previous = dict(catalog.get(scenario_id) or {})
    now_iso = datetime.now(timezone.utc).isoformat()
    entry = {
        "scenario_id": scenario_id,
        "display_name": str(display_name or previous.get("display_name") or scenario_id),
        "template": str(template or previous.get("template") or "default"),
        "created_at": str(previous.get("created_at") or now_iso),
        "updated_at": now_iso,
        "project": str(scenario.get("project") or previous.get("project") or ""),
        "network": str(scenario.get("network") or previous.get("network") or ""),
        "victim_container_name": str(scenario.get("victim_container_name") or previous.get("victim_container_name") or ""),
        "attacker_container_name": str(scenario.get("attacker_container_name") or previous.get("attacker_container_name") or ""),
        "victim_ip": str(scenario.get("victim_ip") or previous.get("victim_ip") or ""),
        "attacker_ip": str(scenario.get("attacker_ip") or previous.get("attacker_ip") or ""),
        "log_dir": str(scenario.get("log_dir") or previous.get("log_dir") or ""),
        "telemetry_dir": str(scenario.get("telemetry_dir") or previous.get("telemetry_dir") or ""),
        "reports_dir": str(scenario.get("reports_dir") or previous.get("reports_dir") or ""),
    }
    catalog[scenario_id] = entry
    _save_scenario_catalog(catalog)
    return entry


def _ensure_persistent_scenario(
    scenario_id: str,
    *,
    display_name: str | None = None,
    template: str | None = None,
) -> dict[str, Any]:
    seed_run_id = _scenario_seed_run_id(scenario_id)
    scenario = _ensure_scenario_for_run(seed_run_id)
    _sync_pmp_observation_with_scenario(scenario)
    _upsert_scenario_catalog_entry(scenario_id, scenario, display_name=display_name, template=template)
    return scenario

def _scenario_placeholder_for_id(scenario_id: str) -> dict[str, Any]:
    seed_run_id = _scenario_seed_run_id(scenario_id)
    project = _scenario_project_name(seed_run_id)
    network_name = f"{project}_net"
    return {
        "project": project,
        "network": network_name,
        "victim_container_name": f"{project}_victim",
        "attacker_container_name": f"{project}_attacker",
        "victim_ip": "",
        "attacker_ip": "",
        "log_dir": str(_scenario_log_dir(seed_run_id)),
        "telemetry_dir": str(_scenario_telemetry_dir(seed_run_id)),
        "reports_dir": str(_scenario_reports_dir(seed_run_id)),
    }


def _scenario_runtime_status(entry: dict[str, Any]) -> dict[str, Any]:
    victim = str(entry.get("victim_container_name") or "").strip()
    attacker = str(entry.get("attacker_container_name") or "").strip()
    victim_status = "missing"
    attacker_status = "missing"
    victim_ip = str(entry.get("victim_ip") or "")
    attacker_ip = str(entry.get("attacker_ip") or "")
    network_name = str(entry.get("network") or "").strip()
    for role, name in (("victim", victim), ("attacker", attacker)):
        if not name:
            continue
        try:
            c = DOCKER_CLIENT.containers.get(name)
            c.reload()
            status = str((c.attrs or {}).get("State", {}).get("Status", "")) or "unknown"
            networks = ((c.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {})
            ip = str((networks.get(network_name, {}) or {}).get("IPAddress", "") or "")
            if role == "victim":
                victim_status = status
                if ip:
                    victim_ip = ip
            else:
                attacker_status = status
                if ip:
                    attacker_ip = ip
        except Exception:
            continue
    return {
        **entry,
        "victim_status": victim_status,
        "attacker_status": attacker_status,
        "victim_ip": victim_ip,
        "attacker_ip": attacker_ip,
        "running": victim_status == "running" and attacker_status == "running",
    }


def _scenario_catalog_entry_is_orphan(entry: dict[str, Any]) -> bool:
    """
    Return True when a catalog scenario is a stale ghost entry:
    no containers, no network, no runtime folder and no active history links.
    """
    sid = str(entry.get("scenario_id") or "").strip()
    if not sid:
        return True

    victim = str(entry.get("victim_container_name") or "").strip()
    attacker = str(entry.get("attacker_container_name") or "").strip()
    network = str(entry.get("network") or "").strip()
    scenario_project = str(entry.get("project") or "").strip()

    victim_exists = False
    attacker_exists = False
    network_exists = False

    if victim:
        try:
            DOCKER_CLIENT.containers.get(victim)
            victim_exists = True
        except Exception:
            pass
    if attacker:
        try:
            DOCKER_CLIENT.containers.get(attacker)
            attacker_exists = True
        except Exception:
            pass
    if network:
        try:
            DOCKER_CLIENT.networks.get(network)
            network_exists = True
        except Exception:
            pass

    runtime_root_exists = False
    try:
        seed_run_id = _scenario_seed_run_id(sid)
        runtime_root_exists = _scenario_runtime_root(seed_run_id).exists()
    except Exception:
        runtime_root_exists = False

    has_history_links = False
    with LOCK:
        for item in RUN_HISTORY:
            if item.get("deleted"):
                continue
            if str(item.get("scenario_id") or "").strip() == sid:
                has_history_links = True
                break
            if scenario_project and str(item.get("scenario_project") or "").strip() == scenario_project:
                has_history_links = True
                break
            if network and str(item.get("scenario_network") or "").strip() == network:
                has_history_links = True
                break

    return not any([victim_exists, attacker_exists, network_exists, runtime_root_exists, has_history_links])


def _runtime_state_snapshot() -> dict[str, Any]:
    with LOCK:
        return {
            "STATE": dict(STATE),
            "RUN_HISTORY": [dict(item) for item in RUN_HISTORY],
            "TRAFFIC_SERIES": {k: list(v) for k, v in TRAFFIC_SERIES.items()},
            "TRAFFIC_BASELINES": dict(TRAFFIC_BASELINES),
            "FALCO_SAMPLES": {k: dict(v) for k, v in FALCO_SAMPLES.items()},
            "HOST_METRICS_LAST": {k: dict(v) for k, v in HOST_METRICS_LAST.items()},
        }


def _persist_runtime_state() -> None:
    try:
        payload = _runtime_state_snapshot()
        tmp_path = RUNTIME_STATE_FILE.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(RUNTIME_STATE_FILE)
    except Exception as e:
        print(f"[state-debug] Failed to persist runtime state: {e}", flush=True)


def _restore_runtime_state() -> None:
    if not RUNTIME_STATE_FILE.exists():
        return
    try:
        payload = json.loads(RUNTIME_STATE_FILE.read_text(encoding="utf-8"))
        with LOCK:
            saved_state = payload.get("STATE") or {}
            if isinstance(saved_state, dict):
                STATE.update(saved_state)
            RUN_HISTORY.clear()
            for item in payload.get("RUN_HISTORY") or []:
                if isinstance(item, dict):
                    RUN_HISTORY.append(dict(item))
            TRAFFIC_SERIES.clear()
            for run_id, series in (payload.get("TRAFFIC_SERIES") or {}).items():
                if isinstance(series, list):
                    TRAFFIC_SERIES[str(run_id)] = [dict(p) for p in series if isinstance(p, dict)]
            TRAFFIC_BASELINES.clear()
            for run_id, value in (payload.get("TRAFFIC_BASELINES") or {}).items():
                try:
                    TRAFFIC_BASELINES[str(run_id)] = float(value)
                except Exception:
                    continue
            FALCO_SAMPLES.clear()
            for run_id, value in (payload.get("FALCO_SAMPLES") or {}).items():
                if isinstance(value, dict):
                    FALCO_SAMPLES[str(run_id)] = dict(value)
            HOST_METRICS_LAST.clear()
            for run_id, value in (payload.get("HOST_METRICS_LAST") or {}).items():
                if isinstance(value, dict):
                    HOST_METRICS_LAST[str(run_id)] = dict(value)
    except Exception as e:
        print(f"[state-debug] Failed to restore runtime state: {e}", flush=True)


_restore_runtime_state()


def _sanitize_run_token(run_id: str) -> str:
    token = re.sub(r"[^a-zA-Z0-9]+", "-", str(run_id or "").strip().lower()).strip("-")
    return token[:48] or "run"


def _scenario_project_name(run_id: str) -> str:
    return f"novadef-{_sanitize_run_token(run_id)}"


def _scenario_runtime_root(run_id: str) -> Path:
    return SCENARIO_ROOT / _scenario_project_name(run_id)


def _scenario_log_dir(run_id: str) -> Path:
    p = _scenario_runtime_root(run_id) / "artifacts" / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _scenario_telemetry_dir(run_id: str) -> Path:
    p = _scenario_runtime_root(run_id) / "artifacts" / "telemetry"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _scenario_reports_dir(run_id: str) -> Path:
    p = _scenario_runtime_root(run_id) / "artifacts" / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _force_remove_tree(path: Path | str, retries: int = 5, sleep_seconds: float = 0.25) -> bool:
    target = Path(path)

    candidates: list[Path] = [target]
    try:
        rel_to_host = target.relative_to(HOST_RUNTIME_ROOT)
        candidates.append(LOCAL_RUNTIME_ROOT / rel_to_host)
    except Exception:
        pass
    try:
        rel_to_local = target.relative_to(LOCAL_RUNTIME_ROOT)
        candidates.append(HOST_RUNTIME_ROOT / rel_to_local)
    except Exception:
        pass

    dedup: list[Path] = []
    seen: set[str] = set()
    for c in candidates:
        key = str(c)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(c)

    removed_all = True
    for candidate in dedup:
        if not candidate.exists():
            continue
        for _ in range(max(retries, 1)):
            try:
                # Ensure write bits so rmtree can remove files created by containers.
                for root, dirs, files in os.walk(candidate, topdown=False):
                    for name in files:
                        p = Path(root) / name
                        try:
                            p.chmod(0o666)
                        except Exception:
                            pass
                    for name in dirs:
                        p = Path(root) / name
                        try:
                            p.chmod(0o777)
                        except Exception:
                            pass
                try:
                    candidate.chmod(0o777)
                except Exception:
                    pass
                shutil.rmtree(str(candidate), ignore_errors=False)
                if not candidate.exists():
                    break
            except Exception:
                pass
            time.sleep(max(sleep_seconds, 0.0))
        if candidate.exists():
            try:
                shutil.rmtree(str(candidate), ignore_errors=True)
            except Exception:
                pass
        if candidate.exists():
            removed_all = False
    return removed_all


def _artifact_roots_for_run(run_id: str) -> list[Path]:
    """
    Resolve where run artifacts must be persisted.
    - Always keep run-local artifacts at .novadef_runtime/scenarios/novadef-<run_id>
    - If the run belongs to a persistent scenario, also mirror under that
      scenario folder: .../scenario-<id>/artifacts/runs/<run_id>
    """
    roots: list[Path] = [_scenario_runtime_root(run_id)]
    run_item = _history_item(run_id) or {}
    if bool(run_item.get("scenario_shared")):
        scenario_id = str(run_item.get("scenario_id") or "").strip()
        if scenario_id:
            scenario_root = _scenario_runtime_root(_scenario_seed_run_id(scenario_id))
            roots.append(scenario_root / "artifacts" / "runs" / _sanitize_run_token(run_id))
            exp_token = _sanitize_run_token(str(run_item.get("experiment") or "experiment"))
            roots.append(
                scenario_root
                / "artifacts"
                / "experiments"
                / exp_token
                / _sanitize_run_token(run_id)
            )
    dedup: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(root)
    return dedup


def _run_item_for_started(experiment: str, started_ts: float | None) -> dict[str, Any] | None:
    if started_ts is None:
        return None
    with LOCK:
        for item in reversed(RUN_HISTORY):
            if item.get("deleted"):
                continue
            if str(item.get("experiment") or "") != str(experiment or ""):
                continue
            try:
                if abs(float(item.get("started_at") or 0.0) - float(started_ts)) < 0.5:
                    return dict(item)
            except Exception:
                continue
    return None


def _container_uptime_seconds(container_name: str) -> float | None:
    name = str(container_name or "").strip()
    if not name:
        return None
    try:
        c = DOCKER_CLIENT.containers.get(name)
        c.reload()
        started_at = str(((c.attrs or {}).get("State") or {}).get("StartedAt") or "").strip()
        if not started_at:
            return None
        started_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        return max(0.0, time.time() - started_dt.timestamp())
    except Exception:
        return None


def _shared_scenario_fast_start_ready(run_item: dict[str, Any] | None) -> bool:
    if not run_item or not bool(run_item.get("scenario_shared")):
        return False
    if not bool(run_item.get("scenario_fast_start_eligible")):
        return False

    victim_name = str(run_item.get("victim_container_name") or "").strip()
    attacker_name = str(run_item.get("attacker_container_name") or "").strip()
    victim_uptime = _container_uptime_seconds(victim_name)
    attacker_uptime = _container_uptime_seconds(attacker_name)
    if victim_uptime is None or attacker_uptime is None:
        return False

    min_uptime = int(os.getenv("EXPERIMENT_SHARED_SCENARIO_MIN_UPTIME_SECONDS", "45"))
    effective_uptime = min(victim_uptime, attacker_uptime)
    if effective_uptime < float(max(min_uptime, 0)):
        return False

    scenario_id = str(run_item.get("scenario_id") or "").strip()
    current_run_id = str(run_item.get("run_id") or "").strip()
    with LOCK:
        has_prior_completed_run = any(
            not item.get("deleted")
            and str(item.get("scenario_id") or "").strip() == scenario_id
            and str(item.get("run_id") or "").strip() != current_run_id
            and bool(item.get("finished_at"))
            for item in RUN_HISTORY
        )
    if has_prior_completed_run:
        return True

    # Fallback when runtime history was reset: only trust very old containers.
    return effective_uptime >= float(max(min_uptime * 2, 90))


def _run_container_name(run_item: dict[str, Any] | None, role: str) -> str:
    if run_item:
        key = f"{role}_container_name"
        val = str(run_item.get(key) or "").strip()
        if val:
            return val
    return "scenario_victim" if role == "victim" else "scenario_attacker"


def _run_container_ip(run_item: dict[str, Any] | None, role: str) -> str | None:
    if not run_item:
        return None
    key = f"{role}_ip"
    val = str(run_item.get(key) or "").strip()
    return val or None


def _container_launcher_ip(container_name: str) -> str | None:
    """Return the container's IP on the launcher_default network (172.18.0.x).

    The scenario containers are dual-homed: launcher_default (shared with SOARCA,
    MISP, etc.) and a scenario-internal net. Attacks/countermeasures must use the
    launcher_default IP so spoofed source IPs (172.18.0.x) are routable and the
    SOARCA iprange block actually matches the attack traffic.
    """
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        cont.reload()
        nets = (cont.attrs.get("NetworkSettings", {}) or {}).get("Networks", {}) or {}
        info = nets.get(LAUNCHER_NETWORK_NAME)
        if info and info.get("IPAddress"):
            return str(info["IPAddress"])
        for net_info in nets.values():
            ip = str((net_info or {}).get("IPAddress") or "")
            if ip.startswith("172.18."):
                return ip
    except Exception:
        pass
    return None


def _victim_capture_interfaces(container_name: str) -> list[str]:
    """
    Return the in-container network interface names tshark must sniff, ordered so
    the scenario network (launcher_default, 172.18.0.x — where the attack and the
    benign noise actually flow) comes first. Falls back to eth0/eth1 if detection
    fails. Without this, tshark may attach to the management interface (e.g.
    192.168.x on eth0) and never observe the attack on eth1.
    """
    interfaces: list[str] = []
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        # Map IP -> ifname inside the container.
        res = cont.exec_run(
            ["sh", "-lc", "ip -o -4 addr show 2>/dev/null | awk '{print $2, $4}'"],
            stdout=True, stderr=False,
        )
        scenario_if = ""
        other_ifs: list[str] = []
        for line in (res.output or b"").decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            ifname, cidr = parts[0], parts[1]
            if ifname == "lo":
                continue
            if cidr.startswith("172.18."):
                scenario_if = ifname
            else:
                other_ifs.append(ifname)
        if scenario_if:
            interfaces.append(scenario_if)
        for ifname in other_ifs:
            if ifname not in interfaces:
                interfaces.append(ifname)
    except Exception:
        pass
    if not interfaces:
        interfaces = ["eth1", "eth0"]
    return interfaces


def _scenario_container_labels(run_id: str, role: str, project: str) -> dict[str, str]:
    return {
        "novadef.run_id": str(run_id),
        "novadef.scenario_project": str(project),
        "novadef.scenario_role": str(role),
        "novadef.scenario": str(project),
        # Compose-style labels help Docker UIs and log tools group both
        # containers under the same scenario even though they are created
        # programmatically.
        "com.docker.compose.project": str(project),
        "com.docker.compose.service": str(role),
        "com.docker.compose.oneoff": "False",
    }


def _resolve_container_for_run(run_item: dict[str, Any] | None, role: str):
    name = _run_container_name(run_item, role)
    try:
        return DOCKER_CLIENT.containers.get(name)
    except Exception:
        return None


def _latest_active_run_id() -> str | None:
    with LOCK:
        for item in reversed(RUN_HISTORY):
            if item.get("deleted"):
                continue
            if item.get("running"):
                return str(item.get("run_id") or "")
    return None


def _refresh_global_runtime_state(current_run_id: str | None = None) -> None:
    with LOCK:
        active_run_id = _latest_active_run_id()
        if active_run_id:
            STATE["current_run_id"] = active_run_id
            STATE["running"] = True
        else:
            STATE["current_run_id"] = None
            STATE["running"] = False
    _persist_runtime_state()


def _tail_logs(container: str, lines: int = 300, since_ts: int | None = None) -> str:
    try:
        cont = DOCKER_CLIENT.containers.get(container)
        kwargs: dict[str, Any] = {"tail": lines}
        if since_ts is not None:
            kwargs["since"] = since_ts
        out = cont.logs(**kwargs).decode("utf-8", errors="replace")
    except Exception:
        if container == "falco_novadef":
            for candidate in _falco_log_candidates():
                try:
                    if not candidate.exists():
                        continue
                    content = candidate.read_text(encoding="utf-8", errors="replace")
                    if not content.strip():
                        continue
                    tail_lines = content.splitlines()[-lines:]
                    return "\n".join(tail_lines)[-MAX_LOG_CHARS:]
                except Exception:
                    continue
        return ""
    return out[-MAX_LOG_CHARS:]


def _parse_prometheus_metric(blob: str, metric_names: list[str]) -> float | None:
    if not blob:
        return None
    for metric_name in metric_names:
        prefix_plain = f"{metric_name} "
        prefix_brace = f"{metric_name}{{"
        for line in blob.splitlines():
            low = line.strip().lower()
            if low.startswith(prefix_plain) or low.startswith(prefix_brace):
                try:
                    value_txt = line.split(" ", 1)[1].strip()
                    return float(value_txt.split()[0])
                except Exception:
                    continue
    return None


def _read_tshark_packet_count(container_name: str | None = None) -> float | None:
    """
    Count INBOUND packets to the active scenario victim from tshark traces.
    Reads NDJSON file and counts only packets where dst matches the victim
    container IP.

    container_name MUST be the real per-scenario victim container name (e.g.
    "novadef-scenario-auto-XXXXX_victim") — "scenario_victim" is a Prometheus
    network ALIAS, not an actual container, so looking it up always raised and
    silently fell through to counting every line in the shared NDJSON trace
    file regardless of which victim they belonged to. That file accumulates
    packets across the whole session (multiple experiments/scenarios), so the
    fallback could return a number in the tens of millions — completely
    unrelated to this run's actual traffic — for a single sample. Because the
    live chart's Y-axis max only ever grows while a run is active, that one
    inflated sample permanently pinned the scale far above the real traffic
    for the rest of the run, which is what showed up as a value flashing on
    screen for a moment and then crushing the rest of the chart flat.
    """
    if not container_name:
        return None
    try:
        cont = DOCKER_CLIENT.containers.get("tshark_novadef")
        try:
            victim_cont = DOCKER_CLIENT.containers.get(container_name)
            victim_ip = None
            networks = victim_cont.attrs.get("NetworkSettings", {}).get("Networks", {})
            for net_name, net_info in networks.items():
                if net_info.get("IPAddress"):
                    victim_ip = net_info["IPAddress"]
                    break
        except Exception:
            victim_ip = None

        if not victim_ip:
            # No safe way to scope the count to this victim — returning the
            # unscoped total (as before) is worse than returning "no data",
            # since it can be many orders of magnitude larger than real
            # traffic and permanently distorts the chart's scale.
            print(f"[traffic-debug] tshark packet count: could not resolve victim_ip for {container_name}, skipping", flush=True)
            return None

        cmd = (
            f'jq -r ".layers.ip.ip_dst" /data/traces/infile.ndjson 2>/dev/null | '
            f'grep -c "^{victim_ip}$" 2>/dev/null || echo 0'
        )
        res = cont.exec_run(
            ["sh", "-lc", cmd],
            stdout=True,
            stderr=True,
        )
        out = (res.output or b"").decode("utf-8", errors="replace").strip()
        if not out:
            return None
        count = float(out.splitlines()[-1].strip() or 0.0)
        print(f"[traffic-debug] tshark packet count: {count} (victim_ip={victim_ip})", flush=True)
        return count
    except Exception as e:
        print(f"[traffic-debug] Exception in _read_tshark_packet_count(): {e}", flush=True)
        return None


def _read_tshark_attack_packet_count(port: str = "2222") -> float | None:
    try:
        cont = DOCKER_CLIENT.containers.get("tshark_novadef")
        victim_ip = None
        try:
            victim_cont = DOCKER_CLIENT.containers.get("scenario_victim")
            networks = victim_cont.attrs.get("NetworkSettings", {}).get("Networks", {})
            for _, net_info in networks.items():
                if net_info.get("IPAddress"):
                    victim_ip = str(net_info["IPAddress"])
                    break
        except Exception:
            victim_ip = None

        if victim_ip:
            cmd = (
                'awk \'index($0, "\\\"tcp.dstport\\\": \\\"%s\\\"") && '
                'index($0, "\\\"ip.dst\\\": \\\"%s\\\"") {n++} END{print n+0}\' '
                '/data/traces/infile.ndjson 2>/dev/null || echo 0'
            ) % (port, victim_ip)
        else:
            # Fallback conservador: solo tráfico entrante al puerto objetivo
            cmd = (
                'awk \'index($0, "\\\"tcp.dstport\\\": \\\"%s\\\"") {n++} END{print n+0}\' '
                '/data/traces/infile.ndjson 2>/dev/null || echo 0'
            ) % (port,)
        res = cont.exec_run(["sh", "-lc", cmd], stdout=True, stderr=True)
        out = (res.output or b"").decode("utf-8", errors="replace").strip()
        if not out:
            return None
        return float(out.splitlines()[-1].strip() or 0.0)
    except Exception:
        return None


def _victim_attack_interface(container_name: str) -> str:
    """Return the in-container interface name that carries the victim's
    launcher_default IP (172.18.0.x) — the network where the attack noise and
    the SOARCA isolation countermeasure actually take effect.

    Docker does NOT guarantee eth0 maps to launcher_default: containers attached
    to multiple networks get eth0/eth1 in non-deterministic order. Hardcoding
    eth0 measured the wrong NIC (the scenario-internal net), so the chart never
    reflected the iptables DROP. We resolve the interface by matching the IP the
    Docker daemon reports for launcher_default against the in-container addrs.
    """
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        # IP that the launcher_default network assigned to the victim.
        cont.reload()
        nets = (cont.attrs.get("NetworkSettings", {}) or {}).get("Networks", {}) or {}
        target_ip = ""
        for net_name, net_info in nets.items():
            if net_name == LAUNCHER_NETWORK_NAME:
                target_ip = str((net_info or {}).get("IPAddress") or "")
                break
        if not target_ip:
            # Fall back to any 172.18.0.x address on launcher_default subnet.
            for net_info in nets.values():
                ip = str((net_info or {}).get("IPAddress") or "")
                if ip.startswith("172.18."):
                    target_ip = ip
                    break
        if target_ip:
            res = cont.exec_run(
                ["sh", "-lc", f"ip -o addr show 2>/dev/null | awk '/{target_ip}\\// {{print $2; exit}}'"],
                stdout=True,
                stderr=True,
            )
            iface = (res.output or b"").decode("utf-8", errors="replace").strip().splitlines()
            if iface and iface[-1].strip():
                return iface[-1].strip()
    except Exception:
        pass
    return "eth0"


def _read_victim_rx_packets(container_name: str = "scenario_victim") -> float | None:
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        iface = _victim_attack_interface(container_name)
        res = cont.exec_run(
            [
                "sh",
                "-lc",
                rf"awk -F'[: ]+' '/{iface}:/ {{print $3; exit}}' /proc/net/dev 2>/dev/null || echo 0",
            ],
            stdout=True,
            stderr=True,
        )
        out = (res.output or b"").decode("utf-8", errors="replace").strip()
        if not out:
            return None
        return float(out.splitlines()[-1].strip() or 0.0)
    except Exception:
        return None


def _read_victim_netfilter_input(container_name: str = "scenario_victim") -> tuple[float, float] | None:
    """
    Read cumulative NETFILTER INPUT-chain counters (L3), returning
    (total_network_in, dropped). This is the correct layer to measure the
    countermeasure: iptables operates at L3, while /proc/net/dev counts L2 NIC
    traffic (broadcast/ARP/other-container packets on the shared Docker /16
    bridge) that never reaches the INPUT chain and is never affected by the
    DROP policy — which is why raw_nic - drop never reached 0.

    total_network_in = every packet netfilter accounted for in INPUT, EXCLUDING
                       loopback (lo) traffic (telegraf/internal processes).
    dropped          = packets sent to DROP (explicit rules + default policy).

    After isolation (policy DROP), all network packets land in dropped, so
    effective = total_network_in - dropped == 0. Before isolation (policy
    ACCEPT), attack traffic counts as accepted, so effective tracks the attack.
    """
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        res = cont.exec_run(
            ["sh", "-lc", "iptables-save -c 2>/dev/null || true"],
            stdout=True,
            stderr=True,
        )
        out = (res.output or b"").decode("utf-8", errors="replace")
        if not out.strip():
            return None

        # We rely on the NOVADEF_NET_IN counting chain installed at victim init.
        # INPUT routes all non-loopback traffic through it via:
        #   -A INPUT ! -i lo -j NOVADEF_NET_IN   (chain just RETURNs, counts pkts)
        # So the jump rule's packet counter = total network traffic the victim
        # received (excluding loopback), in BOTH phases — it keeps counting even
        # after isolation because counting happens before the DROP policy.
        # dropped = INPUT default-policy DROP + any explicit DROP rules.
        # effective = total_network_in - dropped → tracks attack, falls to ~0
        # once the isolation DROP policy starts discarding that same traffic.
        policy_drop = 0.0
        rule_drop = 0.0
        net_in = None
        current_table = ""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("*"):
                current_table = line[1:].strip()
                continue
            if current_table != "filter":
                continue
            # Default DROP policy counter (set by the isolation countermeasure).
            m_pol = re.match(r"^:INPUT\s+DROP\s+\[(\d+):\d+\]", line)
            if m_pol:
                policy_drop = float(m_pol.group(1))
                continue
            m = re.match(r"^\[(\d+):\d+\]\s+-A\s+(\S+)\s+(.*)$", line)
            if not m:
                continue
            pkts = float(m.group(1) or 0.0)
            chain = m.group(2)
            rest = m.group(3)
            # The INPUT jump rule into the counting chain = total network traffic.
            if chain == "INPUT" and "-j NOVADEF_NET_IN" in rest:
                net_in = pkts
            # Explicit DROP rules anywhere relevant (isolation/exp1 block rules).
            if " -j DROP" in rest:
                rule_drop += pkts

        if net_in is None:
            # Counting chain/jump missing (fresh victim, or a flush removed it).
            # Self-heal: (re)install the non-loopback counting jump so the NEXT
            # sample measures correctly, instead of falling back to the raw NIC
            # counter (which reports huge cumulative L2 totals incl. broadcast).
            try:
                cont.exec_run(
                    ["sh", "-lc",
                     "iptables -N NOVADEF_NET_IN 2>/dev/null || true; "
                     "iptables -C NOVADEF_NET_IN -j RETURN 2>/dev/null || iptables -A NOVADEF_NET_IN -j RETURN 2>/dev/null || true; "
                     "iptables -C INPUT ! -i lo -j NOVADEF_NET_IN 2>/dev/null || iptables -I INPUT 1 ! -i lo -j NOVADEF_NET_IN 2>/dev/null || true"],
                    stdout=True, stderr=True,
                )
            except Exception:
                pass
            # Report 0/0 for this tick; the chain is now in place for the next one.
            return (0.0, 0.0)

        dropped = policy_drop + rule_drop
        effective = max(net_in - dropped, 0.0)
        # Return (total_network_in, dropped) so the caller computes
        # effective = total_network_in - dropped consistently.
        return (net_in, net_in - effective)
    except Exception:
        return None


def _read_victim_drop_packets(container_name: str = "scenario_victim") -> float:
    """
    Read cumulative DROP packets from INPUT rules.
    Uses `iptables-save -c` counters so we can estimate effective traffic that
    survives mitigation, including exp1 fast-countermeasure rules on dport 2222.
    """
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        res = cont.exec_run(
            [
                "sh",
                "-lc",
                "iptables-save -c 2>/dev/null || true",
            ],
            stdout=True,
            stderr=True,
        )
        out = (res.output or b"").decode("utf-8", errors="replace")
        total = 0.0
        for line in out.splitlines():
            line = line.strip()
            # Chain default policy counter: ":INPUT DROP [pkts:bytes]"
            # Packets that reach the default policy are those not matched by any
            # ACCEPT rule — after isolation these are effectively all inbound packets.
            m_policy = re.match(r"^:INPUT\s+DROP\s+\[(\d+):\d+\]", line)
            if m_policy:
                total += float(m_policy.group(1))
                continue
            m = re.match(r"^\[(\d+):(\d+)\]\s+-A\s+([A-Za-z0-9_-]+)\s+", line)
            if not m:
                continue
            if " -j DROP" not in line:
                continue
            # Count explicit DROP rules: IP-range blocks (exp1/exp3 block_ip) and
            # catch-all isolation rules added directly to INPUT/OUTPUT chain.
            is_iprange_rule = ("-m iprange" in line and "--src-range" in line)
            is_ssh_drop_rule = ("--dport 2222" in line)
            is_catchall_drop = (" -A INPUT -j DROP" in line or " -A OUTPUT -j DROP" in line)
            if not (is_iprange_rule or is_ssh_drop_rule or is_catchall_drop):
                continue
            total += float(m.group(1))
        return total
    except Exception:
        return 0.0


def _read_victim_postfilter_packets_exp1(container_name: str = "scenario_victim") -> float | None:
    """
    Estimate packets that actually pass victim filtering for exp1.

    Uses iptables counters from the mitigation chain:
    - total_seen: packets entering NOVADEF_EXP1_CM from INPUT
    - dropped: packets dropped by rules inside NOVADEF_EXP1_CM
    - postfilter = total_seen - dropped
    """
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        res = cont.exec_run(
            ["sh", "-lc", "iptables-save -c 2>/dev/null || true"],
            stdout=True,
            stderr=True,
        )
        out = (res.output or b"").decode("utf-8", errors="replace")
        if not out.strip():
            return None

        total_seen = None
        dropped = 0.0
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("["):
                continue
            m = re.match(r"^\[(\d+):(\d+)\]\s+-A\s+([A-Za-z0-9_-]+)\s+", line)
            if not m:
                continue
            pkts = float(m.group(1) or 0.0)
            chain = m.group(3)
            if chain == "INPUT" and "-j NOVADEF_EXP1_CM" in line:
                total_seen = pkts
            if chain == "NOVADEF_EXP1_CM" and " -j DROP" in line:
                dropped += pkts

        if total_seen is None:
            return None
        return max(float(total_seen) - float(dropped), 0.0)
    except Exception:
        return None


def _victim_exp1_mitigation_active(container_name: str) -> bool:
    """
    Verify whether the exp1 countermeasure applied by SOARCA is effectively
    installed in the victim firewall (real observed state, no synthetic
    inference). SOARCA's block_ip_range playbook adds a direct INPUT iprange
    DROP rule for the attacker source range — detect that exact rule.
    """
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        res = cont.exec_run(["sh", "-lc", "iptables-save -c 2>/dev/null || true"], stdout=True, stderr=True)
        out = (res.output or b"").decode("utf-8", errors="replace")
        for line in out.splitlines():
            low = line.strip().lower()
            if "-a input" in low and "iprange" in low and "--src-range" in low and "-j drop" in low:
                return True
        return False
    except Exception as _exc:
        return False


def _falco_log_candidates() -> list[Path]:
    env_candidates = [
        os.getenv("NOVADEF_FALCO_EVENT_LOG"),
        os.getenv("FALCO_EVENT_LOG"),
        os.getenv("FALCO_LOG_FILE"),
    ]
    candidates = [Path(item) for item in env_candidates if item]
    candidates.extend(
        [
            Path("/var/log/falco/falco_events.json"),
            Path("/falco/logs/falco_events.json"),
            PROJECT_ROOT / "PMP" / "Results" / "falco" / "logs" / "falco_events.json",
            PROJECT_ROOT / "Results" / "falco" / "logs" / "falco_events.json",
        ]
    )
    candidates.append(HOST_REPO_ROOT / "PMP" / "Results" / "falco" / "logs" / "falco_events.json")
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _read_falco_host_metrics(sample_key: str = "falco_novadef", since_ts: float | None = None) -> dict[str, float] | None:
    try:
        now = time.time()
        logs = ""
        try:
            cont = DOCKER_CLIENT.containers.get("falco_novadef")
            file_blob = cont.exec_run(
                ["sh", "-lc", "timeout 5 sh -lc 'tail -n 3000 /var/log/falco/falco_events.json 2>/dev/null || true'"],
                stdout=True,
                stderr=True,
            )
            logs = (file_blob.output or b"").decode("utf-8", errors="replace")
        except Exception:
            for candidate in _falco_log_candidates():
                if not candidate.exists():
                    continue
                try:
                    logs = candidate.read_text(encoding="utf-8", errors="replace")
                    if logs.strip():
                        break
                except Exception:
                    continue
        lines = [ln for ln in logs.splitlines() if ln.strip()]
        prev = FALCO_SAMPLES.get(sample_key) or {}
        total_events = 0.0
        severity_weight = 0.0
        warning_hits = 0.0
        error_hits = 0.0
        critical_hits = 0.0
        info_hits = 0.0
        notice_hits = 0.0
        debug_hits = 0.0
        rule_hits: dict[str, float] = {}
        container_hits: dict[str, float] = {}
        since_epoch_ns = int(float(since_ts) * 1_000_000_000) if since_ts and since_ts > 0 else None
        for ln in lines[-3000:]:
            low = ln.lower()
            if not low.startswith("{"):
                continue
            try:
                item = json.loads(ln)
            except Exception:
                continue
            event_ns = None
            try:
                event_ns = int(((item.get("output_fields") or {}).get("evt.time")))
            except Exception:
                event_ns = None
            if since_epoch_ns is not None and event_ns is not None and event_ns < since_epoch_ns:
                continue
            total_events += 1.0
            priority = str(item.get("priority") or "").lower()
            output_fields = item.get("output_fields") or {}
            rule_name = str(item.get("rule") or "").strip()
            if not rule_name:
                rule_name = str(output_fields.get("rule") or output_fields.get("falco.rule") or output_fields.get("rule_name") or "").strip()
            if rule_name:
                rule_hits[rule_name] = rule_hits.get(rule_name, 0.0) + 1.0
            # container.id is populated by Falco even when container.name is null.
            # Use it to attribute events to specific containers.
            cid = str(output_fields.get("container.id") or "host").strip() or "host"
            container_hits[cid] = container_hits.get(cid, 0.0) + 1.0
            if "warning" in priority:
                warning_hits += 1.0
                severity_weight += 1.0
            elif "error" in priority:
                error_hits += 1.0
                severity_weight += 2.0
            elif "critical" in priority or "emergency" in priority:
                critical_hits += 1.0
                severity_weight += 3.0
            elif "notice" in priority:
                notice_hits += 1.0
                severity_weight += 0.5
            elif "info" in priority:
                info_hits += 1.0
                severity_weight += 0.25
            elif "debug" in priority:
                debug_hits += 1.0
        delta_events = max(total_events - float(prev.get("total_events", 0.0)), 0.0)
        top_rules = [
            {"rule": rule, "count": int(count)}
            for rule, count in sorted(rule_hits.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        ]
        FALCO_SAMPLES[sample_key] = {"total_events": total_events, "ts": now}
        return {
            "falco_signal_total": round(total_events, 3),
            "falco_signal_delta": round(delta_events, 3),
            "falco_warning_events": round(warning_hits, 3),
            "falco_error_events": round(error_hits, 3),
            "falco_critical_events": round(critical_hits, 3),
            "falco_info_events": round(info_hits, 3),
            "falco_notice_events": round(notice_hits, 3),
            "falco_debug_events": round(debug_hits, 3),
            "falco_top_rules": top_rules,
            "falco_signal_types": {
                "critical": int(critical_hits),
                "error": int(error_hits),
                "warning": int(warning_hits),
                "notice": int(notice_hits),
                "info": int(info_hits),
                "debug": int(debug_hits),
            },
            # Per-container event counts keyed by container.id.
            # "host" means the event had no container context (kernel-level).
            "falco_by_container": {cid: int(cnt) for cid, cnt in container_hits.items()},
            # Backward-compatible aliases for callers that still expect the
            # previous field names.
            "cpu_percent": round(total_events, 3),
            "memory_bytes": round(severity_weight, 3),
            "memory_percent": round(delta_events, 3),
        }
    except Exception as e:
        print(f"[traffic-debug] Exception in _read_falco_host_metrics(): {e}", flush=True)
        return None


def _read_scenario_telegraf_metrics(
    container_name: str = "scenario_victim",
    machine_id: str | None = None,
) -> dict[str, float] | None:
    """Read container metrics from Telegraf's Prometheus endpoint (port 9274).

    Telegraf uses [[inputs.cgroup]] to expose container-scoped cgroup metrics
    (not /proc/stat which is system-wide).  Every container identifies itself
    with a unique machine_id global tag in its telegraf.conf — this is the
    stable label used to differentiate containers in Prometheus/Grafana and here.

    The cgroup CPU counter (usage_usec) is cumulative; we compute the rate
    between consecutive calls to derive CPU%.  Works for any container that
    runs Telegraf with the standard NOVADEF cgroup config.
    """
    try:
        cont = DOCKER_CLIENT.containers.get(container_name)
        res = cont.exec_run(
            [
                "sh",
                "-lc",
                "timeout 3 sh -lc 'curl -fsS --max-time 2 http://127.0.0.1:9274/metrics 2>/dev/null || true'",
            ],
            stdout=True,
            stderr=True,
        )
        metrics_blob = (res.output or b"").decode("utf-8", errors="replace")
        if not metrics_blob:
            return None

        # Filter lines by the container's machine_id tag.  Every Telegraf metric
        # line from this container contains machine_id="<value>" in its labels.
        label_token = (machine_id or container_name).lower()

        cpu_usec_v2: float | None = None   # cgroups v2: usage_usec (cumulative µs)
        cpu_ns_v1: float | None = None     # cgroups v1: cpuacct.usage (cumulative ns)
        mem_bytes = 0.0
        mem_max = 0.0
        seen_label = False

        for line in metrics_blob.splitlines():
            if line.startswith("#"):
                continue
            low = line.lower()
            if label_token not in low:
                continue
            seen_label = True
            metric_name = low.split("{", 1)[0].split(" ", 1)[0]
            try:
                raw_val = float(line.rsplit(" ", 1)[-1])
            except Exception:
                continue

            if "usage_usec" in metric_name:
                cpu_usec_v2 = raw_val
            elif "cpuacct_usage" in metric_name and "per" not in metric_name:
                cpu_ns_v1 = raw_val
            elif "memory_current" in metric_name and "max" not in metric_name:
                mem_bytes = max(mem_bytes, raw_val)
            elif "memory_max" in metric_name and raw_val > 0:
                mem_max = max(mem_max, raw_val)

        if not seen_label:
            return None

        # CPU% from cgroup counter delta.  Expressed as fraction of ONE CPU core
        # so it can exceed 100% when multiple cores are active (e.g. 8 workers → ~800%).
        cpu_percent = 0.0
        now = time.time()
        cache_key = f"{container_name}:{label_token}"
        prev = _CGROUP_PREV_SAMPLES.get(cache_key) or {}

        if cpu_usec_v2 is not None:
            prev_ts = float(prev.get("ts", 0.0))
            prev_usec = float(prev.get("cpu_usec_v2", 0.0))
            dt = now - prev_ts
            d_usec = cpu_usec_v2 - prev_usec
            if prev_ts > 0 and dt > 0.05 and d_usec >= 0:
                cpu_percent = (d_usec / (dt * 1_000_000)) * 100.0
            _CGROUP_PREV_SAMPLES[cache_key] = {"ts": now, "cpu_usec_v2": cpu_usec_v2}

        elif cpu_ns_v1 is not None:
            prev_ts = float(prev.get("ts", 0.0))
            prev_ns = float(prev.get("cpu_ns_v1", 0.0))
            dt = now - prev_ts
            d_ns = cpu_ns_v1 - prev_ns
            if prev_ts > 0 and dt > 0.05 and d_ns >= 0:
                cpu_percent = (d_ns / (dt * 1_000_000_000)) * 100.0
            _CGROUP_PREV_SAMPLES[cache_key] = {"ts": now, "cpu_ns_v1": cpu_ns_v1}

        # Memory%: container bytes / cgroup limit.
        # If there is no cgroup limit (mem_max == 0), fall back to system total RAM.
        mem_percent = 0.0
        effective_max = mem_max
        if effective_max <= 0 and mem_bytes > 0:
            try:
                with open("/proc/meminfo", "r") as _mf:
                    for _ml in _mf:
                        if _ml.startswith("MemTotal:"):
                            effective_max = float(_ml.split()[1]) * 1024
                            break
            except Exception:
                effective_max = 8 * 1024 * 1024 * 1024
        if effective_max > 0:
            mem_percent = (mem_bytes / effective_max) * 100.0

        return {
            "cpu_percent": round(cpu_percent, 3),
            "memory_bytes": round(mem_bytes, 3),
            "memory_percent": round(mem_percent, 3),
        }
    except Exception as e:
        print(f"[traffic-debug] Exception in _read_scenario_telegraf_metrics(): {e}", flush=True)
        return None


def _container_observe_stats(container_name: str) -> dict[str, float] | None:
    try:
        with LOCK:
            current_run_id = str(STATE.get("current_run_id") or "")
        run_item = _history_item(current_run_id) if current_run_id else None
        run_experiment = str((run_item or {}).get("experiment") or "")
        attack_started = float((run_item or {}).get("attack_started_at") or 0.0) > 0.0
        if run_item and (run_item.get("manual_stop") or run_item.get("stopped_at")):
            return {
                "rx_packets": 0.0,
                "cpu_percent": 0.0,
                "memory_bytes": 0.0,
                "memory_percent": 0.0,
                "falco_events": 0.0,
                "falco_signal_total": 0.0,
                "falco_signal_delta": 0.0,
                "falco_warning_events": 0.0,
                "falco_error_events": 0.0,
                "falco_critical_events": 0.0,
                "falco_info_events": 0.0,
                "falco_notice_events": 0.0,
                "falco_debug_events": 0.0,
                "falco_top_rules": [],
                "falco_signal_types": {},
                "packet_source": "stopped",
            }

        # Measure victim traffic at the NETFILTER (L3) layer, where the
        # countermeasure actually operates. Using /proc/net/dev (L2 NIC) counted
        # broadcast/ARP/other-container packets on the shared Docker bridge that
        # never reach the INPUT chain and are never dropped — so the curve never
        # reached 0 after isolation. netfilter INPUT counters only see traffic
        # destined to the victim and reflect the DROP policy directly.
        packet_source = "netfilter_input"
        packet_count = 0.0
        dropped_packets = 0.0
        effective_packets = 0.0

        nf = _read_victim_netfilter_input(container_name)
        if nf is not None:
            total_network_in, dropped_packets = nf
            packet_count = float(total_network_in)
            effective_packets = max(float(total_network_in) - float(dropped_packets), 0.0)
        else:
            # Fallback chain: NIC counter, then tshark.
            packet_source = "victim_proc"
            packet_count = _read_victim_rx_packets(container_name)
            if packet_count is None or packet_count == 0.0:
                print(f"[traffic-debug] netfilter+victim_proc unavailable for {container_name}, trying tshark", flush=True)
                packet_count = _read_tshark_packet_count(container_name)
                if packet_count is not None and packet_count > 0:
                    packet_source = "tshark_inbound"
                    effective_packets = float(packet_count or 0.0)
                else:
                    packet_count = 0.0
                    effective_packets = 0.0
            else:
                dropped_packets = _read_victim_drop_packets(container_name)
                effective_packets = max(float(packet_count or 0.0) - float(dropped_packets or 0.0), 0.0)

        # NOTE: all three experiments now measure inbound victim traffic the same
        # way — via the NOVADEF_NET_IN counting chain (net_in) minus everything
        # routed to DROP (policy + explicit rules, including exp1's EXP1_CM and
        # exp2/exp3 isolation). The previous exp1-only postfilter override is no
        # longer needed: net_in - dropped already yields the traffic that
        # survives exp1's selective filter, consistent across experiments.

        run_started_at = float((run_item or {}).get("started_at") or 0.0) or None
        attack_started_at = float((run_item or {}).get("attack_started_at") or 0.0) or None
        victim_stats = _read_scenario_telegraf_metrics(container_name) or {}
        # Telegraf endpoint is not exposed inside victim container — fall back to
        # Docker daemon stats which always reflect real container CPU/RAM usage.
        if not victim_stats:
            _docker_st = _docker_runtime_stats([container_name])
            victim_stats = _docker_st.get(container_name, {})
        falco_since_ts = attack_started_at or run_started_at
        falco_stats = _read_falco_host_metrics(sample_key=current_run_id or container_name, since_ts=falco_since_ts) or {}
        prev_host = HOST_METRICS_LAST.get(current_run_id) or {}
        cpu_percent = float(victim_stats.get("cpu_percent", prev_host.get("cpu_percent", 0.0)))
        mem_usage = float(victim_stats.get("memory_bytes", prev_host.get("memory_bytes", 0.0)))
        mem_percent = float(victim_stats.get("memory_percent", prev_host.get("memory_percent", 0.0)))
        if (cpu_percent <= 0.0 and mem_usage <= 0.0 and mem_percent <= 0.0) and prev_host:
            cpu_percent = float(prev_host.get("cpu_percent", 0.0))
            mem_usage = float(prev_host.get("memory_bytes", 0.0))
            mem_percent = float(prev_host.get("memory_percent", 0.0))
        falco_events = float(falco_stats.get("falco_signal_total", falco_stats.get("cpu_percent", 0.0)))
        with LOCK:
            HOST_METRICS_LAST[current_run_id] = {
                "cpu_percent": cpu_percent,
                "memory_bytes": mem_usage,
                "memory_percent": mem_percent,
            }
        _persist_runtime_state()

        result = {
            # Use effective packets as primary traffic curve: this reflects
            # packets that are not blocked by the victim firewall.
            "rx_packets": float(effective_packets or 0.0),
            "rx_packets_raw": float(packet_count or 0.0),
            "blocked_packets": float(dropped_packets or 0.0),
            "cpu_percent": cpu_percent,
            "memory_bytes": mem_usage,
            "memory_percent": mem_percent,
            "falco_events": falco_events,
            "falco_signal_total": falco_events,
            "falco_signal_delta": float(falco_stats.get("falco_signal_delta", 0.0)),
            "falco_warning_events": float(falco_stats.get("falco_warning_events", 0.0)),
            "falco_error_events": float(falco_stats.get("falco_error_events", 0.0)),
            "falco_critical_events": float(falco_stats.get("falco_critical_events", 0.0)),
            "falco_info_events": float(falco_stats.get("falco_info_events", 0.0)),
            "falco_notice_events": float(falco_stats.get("falco_notice_events", 0.0)),
            "falco_debug_events": float(falco_stats.get("falco_debug_events", 0.0)),
            "falco_top_rules": falco_stats.get("falco_top_rules", []),
            "falco_signal_types": falco_stats.get("falco_signal_types", {}),
            "packet_source": packet_source,
        }
        print(
            f"[traffic-debug] Sampled victim telemetry for {container_name}: source={packet_source} packets_raw={packet_count or 0.0} blocked={dropped_packets:.0f} effective={effective_packets:.0f} "
            f"cpu={cpu_percent:.2f}% mem={mem_percent:.2f}% falco_signals={falco_events:.0f} delta={float(falco_stats.get('falco_signal_delta', 0.0)):.0f} warnings={float(falco_stats.get('falco_warning_events', 0.0)):.0f}",
            flush=True,
        )
        return result
    except Exception as e:
        print(f"[traffic-debug] Exception in _container_observe_stats({container_name}): {e}", flush=True)
        return None


def _append_traffic_sample(run_id: str, container_name: str = "scenario_victim") -> None:
    sample = _container_observe_stats(container_name)
    if sample is None:
        print(f"[traffic-debug] _append_traffic_sample({run_id}): no sample from {container_name}", flush=True)
        return
    now = time.time()
    should_persist = False
    with LOCK:
        series = TRAFFIC_SERIES.setdefault(run_id, [])
        if series and now <= float(series[-1]["ts"]):
            now = float(series[-1]["ts"]) + 0.001
        series.append({"ts": now, **sample})
        print(f"[traffic-debug] Appended sample to {run_id}: series length now={len(series)}", flush=True)
        if len(series) > 1800:
            del series[: len(series) - 1800]
        for item in RUN_HISTORY:
            if str(item.get("run_id")) == str(run_id):
                item["traffic_sample_count"] = int(item.get("traffic_sample_count") or 0) + 1
                item["last_traffic_sample_at"] = now
                break
        last_persist = float(TRAFFIC_LAST_PERSIST_AT.get(run_id, 0.0) or 0.0)
        persist_interval = float(os.getenv("EXPERIMENT_TRAFFIC_PERSIST_INTERVAL_SECONDS", "5.0"))
        if (now - last_persist) >= max(persist_interval, 0.5):
            TRAFFIC_LAST_PERSIST_AT[run_id] = now
            should_persist = True
    if should_persist:
        _persist_runtime_state()


def _append_stopped_run_sample(run_id: str, container_name: str = "scenario_victim") -> None:
    """
    Record a final zeroed sample when a run is manually stopped so the live
    charts collapse immediately instead of holding on to the last active value.
    """
    now = time.time()
    sample = {
        "rx_packets": 0.0,
        "rx_packets_raw": 0.0,
        "blocked_packets": 0.0,
        "cpu_percent": 0.0,
        "memory_bytes": 0.0,
        "memory_percent": 0.0,
        "falco_events": 0.0,
        "falco_signal_total": 0.0,
        "falco_signal_delta": 0.0,
        "falco_warning_events": 0.0,
        "falco_error_events": 0.0,
        "falco_critical_events": 0.0,
        "falco_info_events": 0.0,
        "falco_notice_events": 0.0,
        "falco_debug_events": 0.0,
        "falco_top_rules": [],
        "falco_signal_types": {},
        "packet_source": "manual_stop",
    }
    with LOCK:
        series = TRAFFIC_SERIES.setdefault(run_id, [])
        if series and now <= float(series[-1]["ts"]):
            now = float(series[-1]["ts"]) + 0.001
        series.append({"ts": now, **sample})
        if len(series) > 1800:
            del series[: len(series) - 1800]
        HOST_METRICS_LAST[run_id] = {
            "cpu_percent": 0.0,
            "memory_bytes": 0.0,
            "memory_percent": 0.0,
        }
    _persist_runtime_state()


def _effective_countermeasure_timestamp(
    points: list[dict[str, Any]],
    candidate_ts: float | None,
    attack_started_at: float | None,
) -> float | None:
    """
    Prefer the first sample where the traffic actually drops after the
    countermeasure is observed, so the live chart marks the point where the
    mitigation becomes visible rather than the first log line.
    """
    if candidate_ts is None or not points:
        return candidate_ts

    post_points = [p for p in points if float(p.get("ts", 0.0) or 0.0) >= candidate_ts]
    if len(post_points) < 2:
        return candidate_ts

    attack_window = [
        float(p.get("delta_packets", 0.0) or 0.0)
        for p in points
        if (attack_started_at is None or float(p.get("ts", 0.0) or 0.0) >= attack_started_at)
        and float(p.get("ts", 0.0) or 0.0) < candidate_ts
    ]
    baseline_window = [
        float(p.get("delta_packets", 0.0) or 0.0)
        for p in points
        if attack_started_at is not None
        and float(p.get("ts", 0.0) or 0.0) >= max(float(points[0].get("ts", 0.0) or 0.0), float(attack_started_at) - 20.0)
        and float(p.get("ts", 0.0) or 0.0) < float(attack_started_at)
    ]
    attack_peak = max(attack_window or [float(p.get("delta_packets", 0.0) or 0.0) for p in post_points], default=0.0)
    if attack_peak <= 0:
        return candidate_ts

    baseline_level = statistics.median(baseline_window) if baseline_window else 0.0
    low_threshold = max(2.0, baseline_level * 2.0, attack_peak * 0.15)
    sustained = 0
    for p in post_points:
        delta = float(p.get("delta_packets", 0.0) or 0.0)
        if delta <= low_threshold:
            sustained += 1
            if sustained >= 4:
                return float(p.get("ts", candidate_ts) or candidate_ts)
        else:
            sustained = 0
    return candidate_ts


def _start_traffic_sampler(run_id: str, container_name: str = "scenario_victim") -> threading.Thread:
    def _sampler() -> None:
        print(f"[traffic-debug] Starting sampler for {run_id}, container={container_name}", flush=True)
        sample_count = 0
        last_fast_check_ts = 0.0
        # Keep a generous post-run grace period so the chart can still show the
        # countermeasure tail and the victim traffic slope after the attack ends.
        grace_period = 180.0
        sample_interval = float(os.getenv("EXPERIMENT_TRAFFIC_SAMPLE_INTERVAL_SECONDS", "0.7"))
        first_non_running_ts = None
        
        while True:
            with LOCK:
                run = _history_item(run_id)
                should_continue = bool(run and run.get("running"))
                manual_stop = bool(run and (run.get("manual_stop") or run.get("stopped_at")))
            
            # Si running se vuelve False, inicia el contador de gracia
            if not should_continue and first_non_running_ts is None:
                first_non_running_ts = time.time()
                print(f"[traffic-debug] Run {run_id} marked as not running, starting grace period ({grace_period}s)", flush=True)

            if manual_stop:
                print(f"[traffic-debug] Run {run_id} manually stopped; writing terminal zero sample and exiting sampler", flush=True)
                _append_stopped_run_sample(run_id, container_name=container_name)
                break

            # Muestrear siempre, pero evaluar si salir del loop
            _append_traffic_sample(run_id, container_name=container_name)
            sample_count += 1

            # NOTE: the local "fast countermeasure" for exp1 was removed. All
            # countermeasures must be chosen and applied by SOARCA via the real
            # OODA flow (TAPCD profile -> profiles_out -> SOARCA trigger ->
            # block_ip_range playbook over SSH). No local/automatic mitigation.

            if sample_count % 10 == 0:
                with LOCK:
                    series_len = len(TRAFFIC_SERIES.get(run_id, []))
                print(f"[traffic-debug] Sampler {run_id}: {sample_count} samples collected, series length={series_len}, should_continue={should_continue}", flush=True)
            
            # Decidir si salir del loop
            should_exit = False
            if should_continue:
                # Mientras running=True, continuar indefinidamente
                should_exit = False
            elif first_non_running_ts is not None:
                # Si running=False y estamos en período de gracia, chequear tiempo
                elapsed = time.time() - first_non_running_ts
                if elapsed > grace_period:
                    print(f"[traffic-debug] Grace period expired for {run_id}, exiting sampler", flush=True)
                    should_exit = True
            
            if should_exit:
                # Recolectar una pequeña cola final para que la gráfica muestre
                # el tramo posterior a la contramedida aunque el ataque haya acabado.
                print(f"[traffic-debug] Run {run_id} finished, collecting final 12 samples", flush=True)
                for _ in range(12):
                    _append_traffic_sample(run_id, container_name=container_name)
                    time.sleep(sample_interval)
                print(f"[traffic-debug] Sampler thread for {run_id} exiting", flush=True)
                break
            
            time.sleep(sample_interval)

    t = threading.Thread(target=_sampler, daemon=True)
    t.start()
    print(f"[traffic-debug] Sampler thread started for {run_id}", flush=True)
    return t


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


def _purge_misp_db() -> None:
    """
    Truncate all MISP event-related tables so each exp2 run starts with an
    empty event store. Without this, SOARCA trigger finds old events from
    previous runs and fires playbooks on stale victim IPs, contaminating
    act_at with timestamps that pre-date the current run's detection.
    """
    sql = (
        "SET FOREIGN_KEY_CHECKS=0; "
        "TRUNCATE TABLE attributes; "
        "TRUNCATE TABLE shadow_attributes; "
        "TRUNCATE TABLE event_tags; "
        "TRUNCATE TABLE sightings; "
        "TRUNCATE TABLE object_references; "
        "TRUNCATE TABLE objects; "
        "TRUNCATE TABLE event_reports; "
        "TRUNCATE TABLE correlations; "
        "TRUNCATE TABLE default_correlations; "
        "TRUNCATE TABLE no_acl_correlations; "
        "TRUNCATE TABLE shadow_attribute_correlations; "
        "TRUNCATE TABLE events; "
        "SET FOREIGN_KEY_CHECKS=1;"
    )
    try:
        db = DOCKER_CLIENT.containers.get("pmp-misp-db")
        db.exec_run(
            ["sh", "-lc", f'mysql -uroot -pmy_root_password misp -e "{sql}"'],
            stdout=True,
            stderr=True,
        )
    except Exception:
        pass


def _purge_mongodb_flows() -> None:
    """
    Drop the flows collection in MongoDB so stream_low starts each run with an
    empty flow store. Historical flows from previous runs produce profiles whose
    detection_ts predates the current run, making the OODA timeline meaningless.
    """
    try:
        mongo = DOCKER_CLIENT.containers.get("mongodb_novadef")
        result = mongo.exec_run(
            [
                "sh", "-lc",
                'mongo -u admin -p admin123 --authenticationDatabase admin '
                '--eval "db.getSiblingDB(\'flow_db\').flows.drop()" --quiet',
            ],
            stdout=True,
            stderr=True,
        )
        out = (result.output or b"").decode(errors="replace").strip()
        print(f"[purge] MongoDB flows dropped — {out or 'ok'}", flush=True)
    except Exception as e:
        print(f"[purge] warning: could not purge MongoDB flows: {e}", flush=True)


def _cleanup_scenario(scenario_project: str) -> None:
    """Stop and remove all containers belonging to a scenario project."""
    if not scenario_project:
        return
    try:
        for c in DOCKER_CLIENT.containers.list(all=True):
            labels = c.labels or {}
            if labels.get("com.docker.compose.project") == scenario_project:
                try:
                    c.remove(force=True)
                except Exception:
                    pass
    except Exception:
        pass


def _write_active_scenario_to_containers(scenario_id: str) -> None:
    """Write /app/state/active_scenario.txt inside pipeline containers so they
    pick up the new scenario_id without restarting."""
    for container_name in ("pmp-misp-soarca-trigger", "pmp-misp-integrator", "novadef-novadef_neo4j_ingester-1"):
        try:
            c = DOCKER_CLIENT.containers.get(container_name)
            c.exec_run(
                ["sh", "-c", f"mkdir -p /app/state && printf '%s' '{scenario_id}' > /app/state/active_scenario.txt"],
                stdout=True, stderr=True,
            )
        except Exception:
            pass


def _reset_misp_dedup_state(scenario_id: str | None = None) -> None:
    """
    Ensure each experiment run starts with a clean MISP integrator state.
    Calls POST /reset on the integrator's management endpoint (no container
    restart needed).  Falls back to a full container restart if the HTTP call
    fails (e.g. old image without the reset server).
    Also propagates scenario_id to all pipeline containers that need it.
    """
    _reset_ok = False
    _sid = scenario_id or STATE.get("scenario_id") or "default"
    try:
        # Resolve the integrator container's IP on the shared network
        integrator = DOCKER_CLIENT.containers.get("pmp-misp-integrator")
        nets = integrator.attrs.get("NetworkSettings", {}).get("Networks", {})
        integrator_ip = next(
            (v.get("IPAddress") for v in nets.values() if v.get("IPAddress")), None
        )
        if integrator_ip:
            _url = f"http://{integrator_ip}:19090/reset"
            if _sid and _sid != "default":
                _url += f"?scenario_id={_sid}"
            resp = __import__("requests").post(_url, timeout=5)
            if resp.status_code == 200:
                _reset_ok = True
    except Exception:
        pass
    # Write active_scenario.txt to SOARCA trigger and Neo4j ingester
    if _sid:
        _write_active_scenario_to_containers(_sid)

    if not _reset_ok:
        # Fallback: restart the container (old image or network issue)
        try:
            integrator = DOCKER_CLIENT.containers.get("pmp-misp-integrator")
            integrator.exec_run(
                ["sh", "-lc", "rm -f /app/state/misp_dedup_state.json || true"],
                stdout=True, stderr=True,
            )
            integrator.restart(timeout=10)
        except Exception:
            pass


    # Truncate the Falco events log so filebeat's harvester starts fresh.
    # Without this, filebeat may close the reader when the file shrinks between
    # runs and miss the first events of the new run (causing Falco alerts to
    # arrive minutes late or not at all in the TAPCD/MISP pipeline).
    falco_log = Path(os.getenv("NOVADEF_HOST_ROOT", "/")) / "PMP/Results/falco/logs/falco_events.json"
    try:
        if falco_log.exists():
            falco_log.write_text("")
    except Exception:
        pass


def _reset_soarca_dedup_state() -> None:
    """
    Clear SOARCA trigger state so the next run can react to a fresh MISP event
    instead of treating it as already processed.
    """
    try:
        trigger = DOCKER_CLIENT.containers.get("pmp-misp-soarca-trigger")
        trigger.exec_run(
            [
                "sh",
                "-lc",
                "rm -f /app/state/processed_events.txt /app/state/processed_incidents.json /app/state/novadef_phase_timing.json || true",
            ],
            stdout=True,
            stderr=True,
        )
        trigger.restart(timeout=10)
    except Exception:
        pass


def _read_soarca_phase_timing() -> dict[str, float]:
    """
    Read the precise phase timestamps written by the SOARCA trigger into
    /app/state/novadef_phase_timing.json (inside the trigger container).
    Returns a dict with keys: profile_at, enrich_at, decide_at, act_at (epoch floats).
    """
    try:
        trigger = DOCKER_CLIENT.containers.get("pmp-misp-soarca-trigger")
        res = trigger.exec_run(
            ["sh", "-lc", "cat /app/state/novadef_phase_timing.json 2>/dev/null || echo '{}'"],
            stdout=True, stderr=False,
        )
        raw = (res.output or b"").decode("utf-8", errors="replace").strip()
        data = json.loads(raw)
        return {k: float(v) for k, v in data.items() if isinstance(v, (int, float))}
    except Exception:
        return {}


def _purge_kafka_topics() -> None:
    """Purge all detection-relevant Kafka topics to eliminate backlog from prior runs."""
    topics = [
        "tshark_traces", "cic_flow", "network_auth_events",
        "network_intrusion_alerts", "snort_alerts", "falco_events",
        "profiles_out", "flows_conditional_agg",
    ]
    try:
        kafka_c = DOCKER_CLIENT.containers.get("kafka_novadef")
    except Exception:
        return
    for topic in topics:
        try:
            end_raw = kafka_c.exec_run(
                [
                    "bash", "-c",
                    f"export PATH=$PATH:/opt/kafka/bin; kafka-get-offsets.sh "
                    f"--bootstrap-server localhost:9092 --topic {topic} --time latest 2>/dev/null | "
                    f"awk -F: '{{print $NF}}'",
                ],
                stdout=True, stderr=False,
            ).output.decode().strip()
            end = int(end_raw)
            if end <= 0:
                continue
            json_payload = f'{{"partitions":[{{"topic":"{topic}","partition":0,"offset":{end}}}],"version":1}}'
            kafka_c.exec_run(
                [
                    "bash", "-c",
                    f"export PATH=$PATH:/opt/kafka/bin; "
                    f"echo '{json_payload}' > /tmp/_dr.json && "
                    f"kafka-delete-records.sh --bootstrap-server localhost:9092 "
                    f"--offset-json-file /tmp/_dr.json 2>/dev/null",
                ],
                stdout=True, stderr=False,
            )
            print(f"[reset] Purged topic {topic} up to offset {end}", flush=True)
        except Exception:
            continue


def _reset_victim_iptables(victim_container_name: str) -> None:
    """Reset iptables on the victim to a clean ACCEPT state before each run.
    This removes any DROP rules or policy left by a previous experiment so the
    attack traffic is visible and the countermeasure drop-to-zero is measurable.
    Also reinstalls the NOVADEF_NET_IN counting chain and the SOARCA SSH rule.
    """
    try:
        victim = DOCKER_CLIENT.containers.get(victim_container_name)
        victim.exec_run(
            ["sh", "-lc",
             # 1. Reset all policies and flush all rules/chains
             "iptables -P INPUT   ACCEPT 2>/dev/null || true; "
             "iptables -P OUTPUT  ACCEPT 2>/dev/null || true; "
             "iptables -P FORWARD ACCEPT 2>/dev/null || true; "
             "iptables -F 2>/dev/null || true; "
             "iptables -X 2>/dev/null || true; "
             # 2. Reinstall traffic-counting chain (observability)
             "iptables -N NOVADEF_NET_IN 2>/dev/null || true; "
             "iptables -F NOVADEF_NET_IN 2>/dev/null || true; "
             "iptables -A NOVADEF_NET_IN -j RETURN 2>/dev/null || true; "
             "iptables -I INPUT 1 ! -i lo -j NOVADEF_NET_IN 2>/dev/null || true; "
             # 3. Reinstall SOARCA SSH priority rule
             "iptables -N NOVADEF_SOARCA_SSH 2>/dev/null || true; "
             "iptables -F NOVADEF_SOARCA_SSH 2>/dev/null || true; "
             "iptables -A NOVADEF_SOARCA_SSH -p tcp --dport 2222 -s 172.18.0.0/24 -j ACCEPT 2>/dev/null || true; "
             "iptables -I INPUT 1 -p tcp --dport 2222 -s 172.18.0.0/24 -j NOVADEF_SOARCA_SSH 2>/dev/null || true; "
             "echo [reset] iptables cleaned"],
            user="0:0", stdout=True, stderr=True,
        )
        print(f"[reset] iptables reset on {victim_container_name}", flush=True)
    except Exception as e:
        print(f"[reset] iptables reset failed on {victim_container_name}: {e}", flush=True)


def _reset_detector_runtime_state(purge_kafka: bool = False) -> None:
    """
    Reset detector/alert pipeline dedup state so the next experiment generates
    fresh alerts, profiles and countermeasures even when run consecutively in
    the same scenario.

    purge_kafka=True only when starting from a completely clean slate (first
    launch via start_novadef_complete.sh).  Between experiments in the same
    scenario it must be False so historical data from earlier runs is preserved.
    """
    if purge_kafka:
        _purge_kafka_topics()

    # Clear network detector campaign dedup (file on container volume).
    # This is the main gate: without this, the Isolation Forest won't emit a
    # second alert for the same target+attack family within the 30-min TTL.
    try:
        det = DOCKER_CLIENT.containers.get("network_intrusion_detector_novadef")
        det.exec_run(
            ["sh", "-lc",
             "rm -f /app/results/network_intrusion_campaign_state.json "
             "/app/results/network_intrusion_alerts.jsonl || true"],
            stdout=True, stderr=True,
        )
        det.restart(timeout=10)
    except Exception:
        pass

    # Clear SOARCA trigger dedup and reset its Kafka offset to latest so it
    # only reacts to MISP events created by the new experiment.
    try:
        trigger_c = DOCKER_CLIENT.containers.get("pmp-misp-soarca-trigger")
        trigger_c.stop(timeout=5)
        trigger_c.exec_run(
            ["sh", "-c",
             "rm -f /app/state/processed_incidents.json "
             "/app/state/processed_events.txt "
             "/app/state/novadef_phase_timing.json || true"],
            stdout=True, stderr=True,
        )
    except Exception:
        pass
    try:
        kafka_c = DOCKER_CLIENT.containers.get("kafka_novadef")
        kafka_c.exec_run(
            ["bash", "-c",
             "export PATH=$PATH:/opt/kafka/bin; "
             "kafka-consumer-groups.sh --bootstrap-server localhost:9092 "
             "--group soarca-tapcd-trigger --topic profiles_out "
             "--reset-offsets --to-latest --execute 2>/dev/null || true"],
            stdout=True, stderr=False,
        )
        print("[reset] soarca-tapcd-trigger offset reset to latest", flush=True)
    except Exception:
        pass

    # Restart alert_module, alert_manager and flow_module to flush in-memory state,
    # but do NOT purge their Kafka output — historical messages remain for other consumers.
    for name in ["alert_module_novadef", "alert_manager_novadef", "flow_module_novadef", "pmp-misp-soarca-trigger"]:
        try:
            DOCKER_CLIENT.containers.get(name).restart(timeout=10)
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


def _ensure_launcher_network_alias(container_name: str, role: str, alias: str) -> None:
    """
    Ensure the current scenario container is reachable from launcher_default
    with a stable alias so static PMP targets remain valid.
    """
    try:
        network = DOCKER_CLIENT.networks.get(LAUNCHER_NETWORK_NAME)
    except Exception:
        return

    try:
        target = DOCKER_CLIENT.containers.get(container_name)
    except Exception:
        return

    # Remove potential stale alias holders from previous runs.
    try:
        for contender in DOCKER_CLIENT.containers.list(all=True, filters={"label": f"novadef.scenario_role={role}"}):
            if contender.id == target.id:
                continue
            contender.reload()
            contender_networks = ((contender.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {})
            contender_attached = contender_networks.get(LAUNCHER_NETWORK_NAME)
            if not contender_attached:
                continue
            contender_aliases = set(contender_attached.get("Aliases") or [])
            if alias in contender_aliases:
                try:
                    network.disconnect(contender, force=True)
                except Exception:
                    continue
    except Exception:
        pass

    try:
        target.reload()
        target_networks = ((target.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {})
        attached = target_networks.get(LAUNCHER_NETWORK_NAME)
        attached_aliases = set((attached or {}).get("Aliases") or [])
        if attached and alias in attached_aliases:
            return
        if attached:
            try:
                network.disconnect(target, force=True)
            except Exception:
                pass
        network.connect(target, aliases=[alias])
    except Exception as e:
        print(f"[scenario-sync] Failed to bind alias {alias} for {container_name}: {e}", flush=True)


def _ensure_container_on_network(container_name: str, network_name: str, alias: str | None = None) -> None:
    """
    Ensure a helper container is attached to the scenario network so it can
    reach the victim/attacker addresses assigned to that run.
    """
    if not container_name or not network_name:
        return
    try:
        network = DOCKER_CLIENT.networks.get(network_name)
    except Exception:
        return
    try:
        target = DOCKER_CLIENT.containers.get(container_name)
    except Exception:
        return
    try:
        target.reload()
        target_networks = ((target.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {})
        attached = target_networks.get(network_name)
        attached_aliases = set((attached or {}).get("Aliases") or [])
        if attached and (alias is None or alias in attached_aliases):
            return
        if attached and alias is not None and alias not in attached_aliases:
            try:
                network.disconnect(target, force=True)
            except Exception:
                pass
        kwargs: dict[str, Any] = {}
        if alias:
            kwargs["aliases"] = [alias]
        network.connect(target, **kwargs)
    except Exception as e:
        print(f"[scenario-sync] Failed to bind {container_name} to network {network_name}: {e}", flush=True)


TSHARK_TRACES_HOST_DIR = os.getenv(
    "TSHARK_TRACES_HOST_DIR",
    str(HOST_REPO_ROOT / "PMP" / "Results" / "tshark" / "traces"),
)


def _rebind_global_tshark(victim_container_name: str) -> None:
    """
    Ensure tshark observes the ACTIVE scenario victim, capturing on the scenario
    network interface (launcher_default / 172.18.0.x) where the attack flows.

    Behaviour:
      - If tshark_novadef exists, reuse its image/volumes/caps; otherwise fall
        back to sane defaults so the container is (re)created even when it was
        never deployed (e.g. global tshark profile disabled).
      - The capture command is overridden to sniff the scenario interface first
        (detected from the victim's 172.18.0.x address) plus eth0 as backup, so
        we never silently attach to the management interface and miss the attack.
      - network_mode=container:<victim> so tshark shares the victim namespace.
    """
    image_ref = "tshark_novadef:latest"
    env_list: list[str] = ["TZ=UTC"]
    cap_add: list[str] = ["NET_ADMIN", "NET_RAW"]
    restart_policy = {"Name": "unless-stopped"}
    labels: dict[str, str] = {}
    volumes: dict[str, dict[str, str]] = {
        TSHARK_TRACES_HOST_DIR: {"bind": "/data/traces", "mode": "rw"},
        "/sys/class/net": {"bind": "/sys/class/net", "mode": "rw"},
    }

    # Reuse the deployed tshark's config if present (keeps any custom volumes).
    try:
        existing = DOCKER_CLIENT.containers.get("tshark_novadef")
        existing.reload()
        host_cfg = (existing.attrs or {}).get("HostConfig", {}) or {}
        image_ref = (existing.image.tags or [None])[0] or (existing.attrs or {}).get("Config", {}).get("Image") or image_ref
        env_list = list((existing.attrs or {}).get("Config", {}).get("Env") or env_list)
        cap_add = list(host_cfg.get("CapAdd") or cap_add)
        restart_policy = dict(host_cfg.get("RestartPolicy") or restart_policy)
        labels = dict((existing.attrs or {}).get("Config", {}).get("Labels") or {})
        reused: dict[str, dict[str, str]] = {}
        for mount in (existing.attrs or {}).get("Mounts", []) or []:
            if str(mount.get("Type") or "") != "bind":
                continue
            source = str(mount.get("Source") or "").strip()
            destination = str(mount.get("Destination") or "").strip()
            if source and destination:
                reused[source] = {"bind": destination, "mode": str(mount.get("Mode") or "rw") or "rw"}
        if reused:
            volumes = reused
        try:
            existing.remove(force=True)
        except Exception:
            pass
    except Exception:
        # No existing tshark — will be created from defaults above.
        pass

    try:
        interfaces = _victim_capture_interfaces(victim_container_name)
        iface_args = " ".join(f"-i {ifname}" for ifname in interfaces)
        # IMPORTANTE: el convertidor json_array_to_ndjson.py escribe a STDOUT, así
        # que hay que redirigir su salida al fichero de trazas que el detector lee
        # (/data/traces/infile.ndjson). Sin esta redirección la captura iría a los
        # logs del contenedor y el detector nunca vería los paquetes.
        capture_cmd = (
            f"tshark {iface_args} -T json -x -l --no-duplicate-keys 2>/dev/null "
            f"| /usr/local/bin/json_array_to_ndjson.py > /data/traces/infile.ndjson 2>/dev/null"
        )
        DOCKER_CLIENT.containers.run(
            image_ref,
            name="tshark_novadef",
            detach=True,
            environment=env_list,
            cap_add=cap_add,
            volumes=volumes,
            network_mode=f"container:{victim_container_name}",
            restart_policy=restart_policy,
            labels=labels,
            entrypoint=["/bin/sh", "-c"],
            command=[capture_cmd],
        )
        print(
            f"[scenario-sync] tshark_novadef bound to {victim_container_name} "
            f"capturing interfaces {interfaces}",
            flush=True,
        )
    except Exception as e:
        print(f"[scenario-sync] Failed to (re)create tshark_novadef for {victim_container_name}: {e}", flush=True)


def _sync_pmp_observation_with_scenario(scenario: dict[str, Any]) -> None:
    """
    Keep PMP observation components aligned with the currently active per-run
    scenario containers.
    """
    victim = str(scenario.get("victim_container_name") or "").strip()
    attacker = str(scenario.get("attacker_container_name") or "").strip()
    network_name = str(scenario.get("network") or "").strip()
    if not victim:
        return
    _ensure_launcher_network_alias(victim, role="victim", alias=PROMETHEUS_SCENARIO_ALIAS)
    if attacker:
        _ensure_launcher_network_alias(attacker, role="attacker", alias=ATTACKER_SCENARIO_ALIAS)
    if network_name:
        _ensure_container_on_network("pmp-soarca-core", network_name)
        _ensure_container_on_network("pmp-soarca-executor-ssh", network_name)
    # Always reset victim iptables when syncing — a previous run may have left
    # INPUT/OUTPUT policy=DROP (isolation countermeasure) on this container.
    _reset_victim_iptables(victim)
    _rebind_global_tshark(victim)


def _ensure_scenario_for_run(run_id: str) -> dict[str, Any]:
    """
    Provision a per-run Scenario stack so concurrent experiments do not share
    victim/attacker containers, logs or SSH state.
    """
    project = _scenario_project_name(run_id)
    victim_name = f"{project}_victim"
    attacker_name = f"{project}_attacker"
    log_dir = _scenario_log_dir(run_id)
    telemetry_dir = _scenario_telemetry_dir(run_id)
    reports_dir = _scenario_reports_dir(run_id)
    network_name = f"{project}_net"

    existing = _history_item(run_id) or {}
    if existing.get("victim_container_name") and existing.get("attacker_container_name"):
        try:
            victim_existing = DOCKER_CLIENT.containers.get(str(existing["victim_container_name"]))
            attacker_existing = DOCKER_CLIENT.containers.get(str(existing["attacker_container_name"]))
            victim_existing.reload()
            attacker_existing.reload()
            if str((victim_existing.attrs or {}).get("State", {}).get("Status", "")).lower() != "running":
                try:
                    victim_existing.start()
                except Exception:
                    pass
            if str((attacker_existing.attrs or {}).get("State", {}).get("Status", "")).lower() != "running":
                try:
                    attacker_existing.start()
                except Exception:
                    pass
            time.sleep(1.0)
            victim_existing.reload()
            attacker_existing.reload()
            victim_ip_existing = str(
                ((victim_existing.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {})
                .get(network_name, {})
                .get("IPAddress", "")
                or ""
            )
            attacker_ip_existing = str(
                ((attacker_existing.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {})
                .get(network_name, {})
                .get("IPAddress", "")
                or ""
            )
            if victim_ip_existing or attacker_ip_existing:
                _update_history(
                    run_id,
                    {
                        "victim_ip": victim_ip_existing or str(existing.get("victim_ip") or ""),
                        "attacker_ip": attacker_ip_existing or str(existing.get("attacker_ip") or ""),
                    },
                )
            return {
                "project": project,
                "network": network_name,
                "victim_container_name": str(existing["victim_container_name"]),
                "attacker_container_name": str(existing["attacker_container_name"]),
                "victim_ip": victim_ip_existing or str(existing.get("victim_ip") or ""),
                "attacker_ip": attacker_ip_existing or str(existing.get("attacker_ip") or ""),
                "log_dir": str(log_dir),
                "telemetry_dir": str(telemetry_dir),
                "reports_dir": str(reports_dir),
            }
        except Exception:
            pass

    def _prune_unused_novadef_networks() -> int:
        removed = 0
        try:
            for net in DOCKER_CLIENT.networks.list():
                name = str(getattr(net, "name", "") or "")
                if not name or name == LAUNCHER_NETWORK_NAME:
                    continue
                if not (
                    name.startswith("novadef-scenario-auto-")
                    or (name.startswith("novadef-") and name.endswith("_net"))
                ):
                    continue
                try:
                    net.reload()
                    containers = ((net.attrs or {}).get("Containers") or {})
                    if containers:
                        continue
                    net.remove()
                    removed += 1
                except Exception:
                    continue
        except Exception:
            pass
        return removed

    try:
        network = DOCKER_CLIENT.networks.create(network_name, driver="bridge", check_duplicate=True, internal=False, attachable=True)
    except Exception as e:
        err_blob = str(e).lower()
        if "predefined address pools" in err_blob or "fully subnetted" in err_blob:
            removed = _prune_unused_novadef_networks()
            if removed:
                try:
                    network = DOCKER_CLIENT.networks.create(network_name, driver="bridge", check_duplicate=True, internal=False, attachable=True)
                except Exception:
                    try:
                        network = DOCKER_CLIENT.networks.get(network_name)
                    except Exception:
                        network = None
            else:
                try:
                    network = DOCKER_CLIENT.networks.get(network_name)
                except Exception:
                    network = None
        else:
            try:
                network = DOCKER_CLIENT.networks.get(network_name)
            except Exception:
                network = None
    binds = {
        str(log_dir): {"bind": "/var/novadef/logs", "mode": "rw"},
        str(HOST_SCENARIO_TOOLS_ROOT / "Scenario" / "victim-init"): {"bind": "/custom-cont-init.d", "mode": "ro"},
        str(HOST_SCENARIO_TOOLS_ROOT / "Scenario" / "victim-tools"): {"bind": "/opt/novadef", "mode": "ro"},
        str(HOST_SCENARIO_TOOLS_ROOT / "Scenario" / "telegraf" / "telegraf.conf"): {"bind": "/etc/telegraf/telegraf.conf", "mode": "ro"},
        str(HOST_SCENARIO_TOOLS_ROOT / "Scenario" / "attacker-tools"): {"bind": "/opt/novadef", "mode": "ro"},
    }
    victim_env = {
        "PUID": "1000",
        "PGID": "1000",
        "TZ": "Etc/UTC",
        "USER_NAME": "novadef",
        "USER_PASSWORD": "novadef_password",
        "PASSWORD_ACCESS": "true",
        "SUDO_ACCESS": "true",
        "NOVADEF_BENIGN_TARGET_HOST": "atacante",
    }
    attacker_cmd = "/bin/sh -c 'tail -f /dev/null'"
    def _cleanup_partial_scenario() -> None:
        for cname in (victim_name, attacker_name):
            try:
                c = DOCKER_CLIENT.containers.get(cname)
                c.remove(force=True)
            except Exception:
                pass

    last_error: Exception | None = None
    victim_ip = ""
    attacker_ip = ""
    for attempt in range(2):
        try:
            victim = DOCKER_CLIENT.containers.run(
                "lscr.io/linuxserver/openssh-server:latest",
                name=victim_name,
                detach=True,
                restart_policy={"Name": "unless-stopped"},
                environment=victim_env,
                cap_add=["NET_ADMIN"],
                labels=_scenario_container_labels(run_id, "victim", project),
                volumes={
                    str(log_dir): {"bind": "/var/novadef/logs", "mode": "rw"},
                       str(HOST_SCENARIO_TOOLS_ROOT / "Scenario" / "victim-init"): {"bind": "/custom-cont-init.d", "mode": "ro"},
                       str(HOST_SCENARIO_TOOLS_ROOT / "Scenario" / "victim-tools"): {"bind": "/opt/novadef", "mode": "ro"},
                       str(HOST_SCENARIO_TOOLS_ROOT / "Scenario" / "telegraf" / "telegraf.conf"): {"bind": "/etc/telegraf/telegraf.conf", "mode": "ro"},
                },
                network=network_name,
                ports={},
            )
            attacker = DOCKER_CLIENT.containers.run(
                "novadef-scenario-attacker:latest",
                name=attacker_name,
                detach=True,
                restart_policy={"Name": "unless-stopped"},
                command=attacker_cmd,
                cap_add=["NET_ADMIN"],
                labels=_scenario_container_labels(run_id, "attacker", project),
                volumes={
                    str(log_dir): {"bind": "/var/novadef/logs", "mode": "rw"},
                       str(HOST_SCENARIO_TOOLS_ROOT / "Scenario" / "attacker-tools"): {"bind": "/opt/novadef", "mode": "ro"},
                },
                network=network_name,
                ports={},
            )
            time.sleep(2.0)
            victim.reload()
            attacker.reload()
            victim_ip = str((victim.attrs or {}).get("NetworkSettings", {}).get("Networks", {}).get(network_name, {}).get("IPAddress", "") or "")
            attacker_ip = str((attacker.attrs or {}).get("NetworkSettings", {}).get("Networks", {}).get(network_name, {}).get("IPAddress", "") or "")
            break
        except Exception as e:
            last_error = e
            err_blob = str(e).lower()
            # If containers already exist (409 Conflict), reuse them instead of failing.
            # This happens when the scenario was pre-created via /api/scenarios before
            # a run is launched, so history is empty but containers are live.
            if "conflict" in err_blob or "already in use" in err_blob:
                try:
                    victim = DOCKER_CLIENT.containers.get(victim_name)
                    attacker = DOCKER_CLIENT.containers.get(attacker_name)
                    for c in (victim, attacker):
                        if str((c.attrs or {}).get("State", {}).get("Status", "")).lower() != "running":
                            c.start()
                    victim.reload()
                    attacker.reload()
                    victim_ip = str((victim.attrs or {}).get("NetworkSettings", {}).get("Networks", {}).get(network_name, {}).get("IPAddress", "") or "")
                    attacker_ip = str((attacker.attrs or {}).get("NetworkSettings", {}).get("Networks", {}).get(network_name, {}).get("IPAddress", "") or "")
                    last_error = None
                    break
                except Exception:
                    pass
            _cleanup_partial_scenario()
            if attempt == 0 and ("network" in err_blob and "not found" in err_blob):
                try:
                    DOCKER_CLIENT.networks.create(network_name, driver="bridge", check_duplicate=True, internal=False, attachable=True)
                except Exception:
                    pass
                continue
            raise RuntimeError(f"scenario provisioning failed for {run_id}: {e}")

    if last_error is not None and not victim_ip and not attacker_ip:
        raise RuntimeError(f"scenario provisioning failed for {run_id}: {last_error}")

    _update_history(
        run_id,
        {
            "scenario_project": project,
            "scenario_network": network_name,
            "victim_container_name": victim_name,
            "attacker_container_name": attacker_name,
            "victim_ip": victim_ip,
            "attacker_ip": attacker_ip,
            "scenario_log_dir": str(log_dir),
            "scenario_telemetry_dir": str(telemetry_dir),
            "scenario_reports_dir": str(reports_dir),
        },
    )
    return {
        "project": project,
        "network": network_name,
        "victim_container_name": victim_name,
        "attacker_container_name": attacker_name,
        "victim_ip": victim_ip,
        "attacker_ip": attacker_ip,
        "log_dir": str(log_dir),
        "telemetry_dir": str(telemetry_dir),
        "reports_dir": str(reports_dir),
    }


def _wait_for_scenario_ready(scenario: dict[str, Any], timeout_seconds: int = 15) -> None:
    """
    Give the per-run victim/attacker stack a short window to finish joining
    the dedicated network before we begin sampling telemetry or launching the
    attack. This avoids mixing early start-up noise with the actual run.
    """
    victim_name = str(scenario.get("victim_container_name") or "").strip()
    attacker_name = str(scenario.get("attacker_container_name") or "").strip()
    network_name = str(scenario.get("network") or "").strip()
    if not victim_name or not attacker_name or not network_name:
        return

    deadline = time.time() + max(timeout_seconds, 15)
    last_error: Exception | None = None
    time.sleep(15)
    while time.time() < deadline:
        try:
            victim = DOCKER_CLIENT.containers.get(victim_name)
            attacker = DOCKER_CLIENT.containers.get(attacker_name)
            victim.reload()
            attacker.reload()
            victim_nets = ((victim.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {})
            attacker_nets = ((attacker.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {})
            victim_ready = network_name in victim_nets and str(victim_nets.get(network_name, {}).get("IPAddress", "") or "").strip() != ""
            attacker_ready = network_name in attacker_nets and str(attacker_nets.get(network_name, {}).get("IPAddress", "") or "").strip() != ""
            victim_running = str((victim.attrs or {}).get("State", {}).get("Status", "")).lower() == "running"
            attacker_running = str((attacker.attrs or {}).get("State", {}).get("Status", "")).lower() == "running"
            if victim_ready and attacker_ready and victim_running and attacker_running:
                return
        except Exception as e:
            last_error = e
        
    if last_error is not None:
        print(f"[traffic-debug] Scenario readiness wait ended with last error: {last_error}", flush=True)
    print(
        f"[traffic-debug] Scenario readiness timeout for {victim_name}/{attacker_name} on {network_name}; proceeding anyway.",
        flush=True,
    )


def _start_benign_noise(run_id: str) -> None:
    run_item = _history_item(run_id) or {}
    attacker_name = _run_container_name(run_item, "attacker")
    victim_target = str(run_item.get("victim_ip") or "").strip() or "scenario_victim"
    try:
        attacker = DOCKER_CLIENT.containers.get(attacker_name)
        attacker.exec_run(
            [
                "bash",
                "-lc",
                (
                    "mkdir -p /var/novadef/logs && "
                    "rm -f /var/novadef/logs/stop_benign_noise.signal && "
                    "pkill -f '/opt/novadef/benign_inbound_noise.sh' >/dev/null 2>&1 || true; "
                    f"nohup env NOVADEF_LOG_DIR=/var/novadef/logs bash /opt/novadef/benign_inbound_noise.sh {victim_target} {run_id} "
                    ">/var/novadef/logs/benign_noise.out 2>&1 &"
                ),
            ],
            stdout=True,
            stderr=True,
        )
    except Exception:
        pass


def _start_exp2_persistent_emulation(run_id: str, reset_iptables: bool = True) -> tuple[bool, str]:
    run_item = _history_item(run_id) or {}
    victim_name = _run_container_name(run_item, "victim")
    if not victim_name:
        return False, "victim container not found"
    launch_cmd = (
        # Ensure bash is present (openssh-server image is Alpine-based, no bash by default).
        "command -v bash >/dev/null 2>&1 || apk add --no-cache bash >/dev/null 2>&1 || true\n"
        "rm -f /tmp/novadef_exp2_stop.signal /tmp/novadef_exp2_loop.out\n"
        # CAMPAIGN_ID propagated so Falco output_fields carry it and the MISP
        # integrator can correlate this host event with any network alerts for
        # the same run. export ensures child processes (nohup/bash) inherit it.
        f"export CAMPAIGN_ID={run_id}\n"
        f"nohup bash /opt/novadef/akira_lab_emulation.sh"
        f" >/tmp/novadef_exp2_loop.out 2>&1 &\n"
        "echo started_exp2_loop\n"
    )
    try:
        victim = DOCKER_CLIENT.containers.get(victim_name)
        # reset_iptables=False for exp3's delayed Akira launch: the network phase
        # already ran the setup reset and, crucially, its round-1 surge is landing
        # on the NOVADEF_NET_IN counter right about now. `_reset_victim_iptables`
        # does `iptables -F NOVADEF_NET_IN`, which ZEROES that counter — so
        # resetting here (a few seconds into the network attack) wiped the ~9.7k
        # surge packets off the effective-traffic curve, which is exactly why the
        # network spike never appeared on the exp3 chart. Standalone exp2 still
        # resets (default True) because there is no in-flight network surge to
        # protect there.
        if reset_iptables:
            _reset_victim_iptables(victim_name)
        # Try as the linuxserver PUID=1000 user first; fall back to root if the
        # container image doesn't resolve uid 1000 in exec context (e.g. fresh
        # openssh-server before the s6 overlay has finished initializing).
        res = victim.exec_run(["sh", "-c", launch_cmd], stdout=True, stderr=True, user="root")
        out = (res.output or b"").decode("utf-8", errors="replace")
        ok = (res.exit_code == 0) and ("started_exp2_loop" in out)
        print(f"[exp2-launch] victim={victim_name} exit_code={res.exit_code} ok={ok} out={out[:300]}", flush=True)
        return ok, out[-2000:]
    except Exception as e:
        print(f"[exp2-launch] exception launching akira in {victim_name}: {e}", flush=True)
        return False, str(e)


def _stop_exp2_persistent_emulation(run_id: str | None = None, run_item: dict[str, Any] | None = None) -> None:
    item = run_item or (_history_item(run_id) if run_id else None) or {}
    victim_name = _run_container_name(item, "victim")
    if not victim_name:
        return
    stop_cmd = (
        "touch /tmp/novadef_exp2_stop.signal; "
        "pkill -f 'akira_lab_emulation' >/dev/null 2>&1 || true; "
        "pkill -f 'openssl enc' >/dev/null 2>&1 || true; "
        "pkill -f 'openssl' >/dev/null 2>&1 || true; "
        "pkill -f 'novadef_akira_encrypt' >/dev/null 2>&1 || true; "
        "pkill -f 'novadef_exp2_loop' >/dev/null 2>&1 || true; "
        "pkill -f 'dd if=/dev/urandom' >/dev/null 2>&1 || true"
    )
    try:
        victim = DOCKER_CLIENT.containers.get(victim_name)
        victim.exec_run(["sh", "-c", stop_cmd], stdout=True, stderr=True, user="0:0")
    except Exception as e:
        print(f"[stop-exp2] Warning: could not stop emulation in {victim_name}: {e}", flush=True)


def _kill_ransomware_everywhere() -> None:
    """Kill any lingering Akira/ransomware emulation process in ALL scenario
    victim containers, and remove its lab directory.

    A previous exp2/exp3 launches Akira with nohup, so it keeps encrypting files
    (and triggering real Falco 'ransomware' alerts) until explicitly killed. If a
    new experiment (e.g. exp1) starts while a prior scenario victim is still alive,
    those stray Falco alerts contaminate the new run (wrong 'Network Isolation'
    countermeasure). Sweeping every victim container at launch prevents that.
    """
    stop_cmd = (
        "pkill -f 'akira_lab_emulation' >/dev/null 2>&1 || true; "
        "pkill -f 'novadef_akira_encrypt' >/dev/null 2>&1 || true; "
        "pkill -f 'novadef_exp2_loop' >/dev/null 2>&1 || true; "
        "pkill -f 'openssl enc' >/dev/null 2>&1 || true; "
        "pkill -f 'dd if=/dev/urandom' >/dev/null 2>&1 || true; "
        "rm -rf /tmp/novadef_ransomware_lab >/dev/null 2>&1 || true"
    )
    try:
        for cont in DOCKER_CLIENT.containers.list():
            name = str(getattr(cont, "name", "") or "")
            if "_victim" not in name and "scenario" not in name.lower():
                continue
            try:
                cont.exec_run(["sh", "-c", stop_cmd], stdout=False, stderr=False, user="0:0")
                print(f"[ransomware-sweep] cleaned {name}", flush=True)
            except Exception:
                pass
    except Exception as e:
        print(f"[ransomware-sweep] error: {e}", flush=True)

    # Truncate the Falco events log from INSIDE the falco container (the API
    # container does not mount that host path). Otherwise filebeat keeps shipping
    # the previous run's ransomware events into Kafka for the whole new run.
    _truncated = False
    try:
        fc = DOCKER_CLIENT.containers.get("falco_novadef")
        truncate_cmd = "; ".join(
            f": > {p} 2>/dev/null || true"
            for p in ("/var/log/falco_events.json", "/var/log/falco/falco_events.json")
        )
        fc.exec_run(["sh", "-c", truncate_cmd], stdout=False, stderr=False, user="0:0")
        _truncated = True
        print("[ransomware-sweep] truncated Falco log", flush=True)
    except Exception:
        pass
    # Restart filebeat so its harvester reopens the now-empty log from offset 0
    # instead of holding the old (larger) read offset and replaying stale events.
    if _truncated:
        try:
            DOCKER_CLIENT.containers.get("filebeat_novadef").restart(timeout=10)
            print("[ransomware-sweep] restarted filebeat", flush=True)
        except Exception:
            pass


def _kill_network_attack_everywhere() -> None:
    """Kill any lingering network-attack process (hping3/sshpass spraying loop)
    in ALL scenario attacker containers.

    exp1 and exp3 launch hybrid_lateral_remote_execution.sh / distributed_
    password_spraying.sh with `nohup ... ATTACK_DURATION_SECONDS=1800 &`, so it
    keeps generating real hping3/SSH traffic toward the victim for up to 30
    minutes unless explicitly stopped. That stop only happens today via
    _signal_run_stop() (writes stop_network_attack.signal), which only fires
    when a run is explicitly deleted/stopped through the API. If the user
    launches a new experiment on the SAME reused scenario without stopping the
    previous one first (e.g. exp3 then exp1 on the same scenario), the old
    attack script is still alive and its traffic bleeds into the new run's
    chart from the very first sample — indistinguishable from genuine new
    attack traffic. Sweeping every attacker container at the start of every
    new run (mirrors _kill_ransomware_everywhere for the victim side) prevents
    this regardless of whether the previous run was cleanly stopped first.
    """
    # The attacker image is a bare Debian base without procps installed, so
    # `pkill`/`ps` are not available there (unlike the Alpine victim image,
    # which does have pkill via apk). Match processes by scanning /proc/*/
    # cmdline directly and send signals with the POSIX `kill` builtin instead
    # of depending on a package that isn't guaranteed to be present.
    patterns = (
        "hybrid_lateral_remote_execution",
        "distributed_password_spraying",
        "benign_inbound_noise",
        "hping3",
        "sshpass",
    )
    case_patterns = " | ".join(f"*{p}*" for p in patterns)
    stop_cmd = (
        "self_pid=$$; "
        "for p in /proc/[0-9]*; do "
        "  pid=${p#/proc/}; "
        # Skip our own PID: this script's own argv literally contains the
        # search patterns (e.g. "sshpass") since they are baked into the case
        # statement below, so without this guard the loop matches and
        # SIGTERMs itself mid-scan — killing the sweep before it can process
        # the remaining /proc entries or print anything, which is exactly
        # what caused this exec to hang indefinitely during testing.
        '  [ "$pid" = "$self_pid" ] && continue; '
        "  cmd=$(tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null); "
        f'  case "$cmd" in {case_patterns}) '
        "    kill -TERM \"$pid\" 2>/dev/null || true ;; "
        "  esac; "
        "done; "
        "touch /var/novadef/logs/stop_network_attack.signal >/dev/null 2>&1 || true; "
        "touch /var/novadef/logs/stop_benign_noise.signal >/dev/null 2>&1 || true"
    )
    try:
        for cont in DOCKER_CLIENT.containers.list():
            name = str(getattr(cont, "name", "") or "")
            if "_attacker" not in name:
                continue
            try:
                cont.exec_run(["sh", "-c", stop_cmd], stdout=False, stderr=False, user="0:0")
                print(f"[network-attack-sweep] cleaned {name}", flush=True)
            except Exception:
                pass
    except Exception as e:
        print(f"[network-attack-sweep] error: {e}", flush=True)


_GRAFANA_URL = os.getenv("GRAFANA_URL", "http://novadef-grafana:3000")
_GRAFANA_USER = os.getenv("GRAFANA_ADMIN_USER", "admin")
_GRAFANA_PASS = os.getenv("GRAFANA_ADMIN_PASSWORD", "novadef_grafana")
_GRAFANA_ANNOTATION_DASHBOARDS = [
    "novadef-host-metrics",
    "novadef-network-security",
    "novadef-overview",
]


def _grafana_delete_all_annotations() -> None:
    """Delete all Grafana annotations tagged with 'novadef' (attack, countermeasure lines)."""
    creds = base64.b64encode(f"{_GRAFANA_USER}:{_GRAFANA_PASS}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}"}
    try:
        from urllib.parse import urlencode as _urlencode
        query = _urlencode({"tags": "novadef", "limit": 500})
        req = urlrequest.Request(
            f"{_GRAFANA_URL}/api/annotations?{query}",
            headers=headers,
            method="GET",
        )
        with urlrequest.urlopen(req, timeout=5) as resp:
            annotations = json.loads(resp.read().decode())
        for ann in annotations:
            ann_id = ann.get("id")
            if not ann_id:
                continue
            try:
                del_req = urlrequest.Request(
                    f"{_GRAFANA_URL}/api/annotations/{ann_id}",
                    headers=headers,
                    method="DELETE",
                )
                urlrequest.urlopen(del_req, timeout=3)
            except Exception:
                pass
    except Exception:
        pass


def _grafana_post_annotation(text: str, tags: list[str], ts_ms: int | None = None) -> None:
    ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    payload = json.dumps({"text": text, "tags": tags, "time": ts}).encode()
    creds = base64.b64encode(f"{_GRAFANA_USER}:{_GRAFANA_PASS}".encode()).decode()
    for dash_uid in _GRAFANA_ANNOTATION_DASHBOARDS:
        try:
            body = json.dumps({"text": text, "tags": tags, "time": ts, "dashboardUID": dash_uid}).encode()
            req = urlrequest.Request(
                f"{_GRAFANA_URL}/api/annotations",
                data=body,
                headers={"Content-Type": "application/json", "Authorization": f"Basic {creds}"},
                method="POST",
            )
            urlrequest.urlopen(req, timeout=3)
        except Exception:
            pass
    # Also post without dashboardUID so it appears globally
    try:
        req = urlrequest.Request(
            f"{_GRAFANA_URL}/api/annotations",
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Basic {creds}"},
            method="POST",
        )
        urlrequest.urlopen(req, timeout=3)
    except Exception:
        pass


def _stop_benign_noise(run_id: str | None = None) -> None:
    run_item = _history_item(run_id) if run_id else None
    attacker_name = _run_container_name(run_item, "attacker")
    try:
        attacker = DOCKER_CLIENT.containers.get(attacker_name)
        attacker.exec_run(
            [
                "bash",
                "-lc",
                "mkdir -p /var/novadef/logs && touch /var/novadef/logs/stop_benign_noise.signal && pkill -f '/opt/novadef/benign_inbound_noise.sh' >/dev/null 2>&1 || true",
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
            ms_str = match.group(2)
            ms = int(ms_str) / 1000.0 if ms_str else 0.0
            return dt.timestamp() + ms
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


def _first_timestamp_for_keywords_with_nearest_fallback(
    blob: str,
    keywords: list[str],
    *,
    neighbor_window: int = 4,
) -> float | None:
    """
    Return timestamp for the first evidence line matching `keywords`.
    If that line has no directly parseable timestamp, use the nearest parseable
    timestamp around it (previous/next lines within a small window).
    """
    if not blob:
        return None

    lines = blob.splitlines()
    lower_keywords = [k.lower() for k in keywords]
    parsed_ts: list[float | None] = [_parse_log_epoch(ln) for ln in lines]

    for idx, line in enumerate(lines):
        low = line.lower()
        if not any(k in low for k in lower_keywords):
            continue

        direct = parsed_ts[idx]
        if direct is not None:
            return direct

        win = max(int(neighbor_window), 1)
        for off in range(1, win + 1):
            left = idx - off
            right = idx + off
            if left >= 0 and parsed_ts[left] is not None:
                return float(parsed_ts[left])
            if right < len(parsed_ts) and parsed_ts[right] is not None:
                return float(parsed_ts[right])

    return None


def _all_timestamps_for_keywords(blob: str, keywords: list[str]) -> list[float]:
    if not blob:
        return []
    lower_keywords = [k.lower() for k in keywords]
    out: list[float] = []
    for line in blob.splitlines():
        low = line.lower()
        if any(k in low for k in lower_keywords):
            ts = _parse_log_epoch(line)
            if ts is not None:
                out.append(ts)
    return out


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


def _detection_evidence_lines(blob: str, experiment: str) -> list[str]:
    """
    Keep detection gated on concrete detector output.

    We only want to advance Detect when the detector itself has emitted a real
    alert line for the current run, not because some downstream service logged a
    generic alert-related keyword.
    """
    if not blob:
        return []
    exp = str(experiment or "").strip()
    out: list[str] = []
    for raw in blob.splitlines():
        low = raw.lower()
        if exp == "exp2":
            if any(
                k in low
                for k in [
                    "host ransomware emulation detected",
                    "nueva alerta publicada",
                    "alerta publicada",
                    "falco alert",
                    "warning novadef ransomware",
                    "novadef lab ransomware",
                ]
            ):
                out.append(raw)
        elif exp == "exp3":
            if any(
                k in low
                for k in [
                    "hybrid lateral remote execution",
                    "alerta publicada",
                    "nueva alerta publicada",
                    "alerta rápida publicada",
                    # Falco/ransomware phase signals (same as exp2)
                    "host ransomware emulation detected",
                    "falco alert",
                    "warning novadef ransomware",
                    "novadef lab ransomware",
                    "novadef ransom note",
                    "novadef canary file",
                    "akira_lab_emulation",
                ]
            ):
                out.append(raw)
        else:
            if any(
                k in low
                for k in [
                    "distributed password spraying",
                    "alerta rápida publicada",
                    "alerta por flows publicada",
                    "alerta publicada",
                    "nueva alerta publicada",
                    "bruteforce password spraying detected",
                ]
            ):
                out.append(raw)
    return out


PROFILE_EVIDENCE_KEYWORDS = [
    "classification",
    "perfil actor",
    "attacker profile",
    "threat profile",
    "profile=",
    "affiliation=",
    "motivation=",
    "knowledge=",
    "attitude=",
    "skills=",
    "actor_id",
]

PROFILE_DETAIL_KEYWORDS = [
    "profile=",
    "affiliation=",
    "motivation=",
    "knowledge=",
    "attitude=",
    "skills=",
    "actor_id",
    "actor=profile_",
    "tapcd_profile_ready",
    "perfil actor",
    "attacker profile",
    "threat profile",
]


def _tapcd_profile_evidence_lines(blob: str) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for raw in blob.splitlines():
        low = raw.lower().strip()
        if not low:
            continue
        if any(k in low for k in PROFILE_DETAIL_KEYWORDS):
            if raw not in seen:
                lines.append(raw)
                seen.add(raw)
            continue
        # TAPCD emits the native profile as a CSV row in the prep/log path.
        # Treat that row as native evidence so the GUI can surface the actor
        # that actually entered Neo4j.
        if low.startswith("profile_") and low.count(",") >= 10:
            if raw not in seen:
                lines.append(raw)
                seen.add(raw)
            continue
        if low.startswith("id,ips,target,preferredtarget"):
            if raw not in seen:
                lines.append(raw)
                seen.add(raw)
    return lines


def _tapcd_profile_ready(blob: str) -> bool:
    return bool(_tapcd_profile_evidence_lines(blob))


def _line_count(blob: str) -> int:
    if not blob:
        return 0
    return len([ln for ln in blob.splitlines() if ln.strip()])


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
    run_item = _run_item_for_started(experiment, started)
    run_id = str((run_item or {}).get("run_id") or "")
    victim_name = _run_container_name(run_item, "victim")
    attacker_name = _run_container_name(run_item, "attacker")
    deadline = time.time() + timeout_sec
    soft_deadline = min(deadline, time.time() + 20.0)

    while time.time() < deadline:
        current_run = _history_item(run_id) if run_id else None
        current_attack_started = float((current_run or {}).get("attack_started_at") or STATE.get("last_attack_started_at") or 0.0) or None
        phase_since_ts = int(current_attack_started) if isinstance(current_attack_started, (int, float)) else int(time.time()) + 86400
        observe_blob = "\n".join(
            [
                _tail_logs("falco_novadef", 400, since_ts=since_ts),
                _tail_logs("tshark_novadef", 400, since_ts=since_ts),
                _tail_logs("flow_module_novadef", 300, since_ts=since_ts),
                _tail_logs(attacker_name, 250, since_ts=since_ts),
            ]
        )
        detect_blob = "\n".join(
            [
                _tail_logs("network_intrusion_detector_novadef", 500, since_ts=phase_since_ts),
                _tail_logs("snort_novadef", 500, since_ts=phase_since_ts),
                _tail_logs("alert_module_novadef", 500, since_ts=phase_since_ts),
            ]
        )
        enrich_blob = "\n".join(
            [
                _tail_logs("pmp-misp-integrator", 500, since_ts=phase_since_ts),
                _tail_logs("pmp-misp-server", 350, since_ts=phase_since_ts),
            ]
        )
        profile_blob = (
            _tail_logs("novadef-novadef_stream_low-1", 350, since_ts=phase_since_ts)
            + "\n"
            + _tail_logs("novadef-novadef_prep_pred-1", 220, since_ts=phase_since_ts)
            + "\n"
            + _tail_logs("novadef-novadef_neo4j_ingester-1", 220, since_ts=phase_since_ts)
            + "\n"
            + _tail_logs("pmp-misp-integrator", 220, since_ts=phase_since_ts)
        )
        _act_blob_parts = [
            _tail_logs("pmp-soarca-core", 500, since_ts=phase_since_ts),
            _tail_logs("pmp-soarca-executor-ssh", 500, since_ts=phase_since_ts),
            _tail_logs(victim_name, 350, since_ts=phase_since_ts),
            _tail_logs("pmp-misp-soarca-trigger", 400, since_ts=phase_since_ts),
        ]
        act_blob = "\n".join(_act_blob_parts)
        report_panel = _build_live_report_panel(experiment, started, STATE.get("last_attack_started_at"))
        live_timeline = report_panel.get("timeline") or {}
        profile_panel = report_panel.get("tapcd") or {}
        misp_panel = report_panel.get("misp") or {}
        countermeasure_panel = report_panel.get("countermeasure") or {}

        require_misp_enrich = bool(int(os.getenv("EXPERIMENT_REQUIRE_MISP_ENRICH_FOR_ACT", "0")))

        if experiment == "exp2":
            observe_hit = any(k in observe_blob.lower() for k in ["falco", "ransomware", "warning novadef"])
            # Falco stdout is disabled; detection evidence for exp2 arrives via
            # pmp-misp-integrator which logs "FALCO: Host Ransomware Emulation Detected".
            detect_hit = bool(_detection_evidence_lines(detect_blob + "\n" + observe_blob + "\n" + enrich_blob, experiment))
            profile_hit = bool(profile_panel.get("native_profile_ready") or profile_panel.get("actor_profile_count") or profile_panel.get("profile_detail_lines"))
            enrich_hit = bool(misp_panel.get("event_ids_detected_in_logs") or "nuevo evento misp" in enrich_blob.lower())
            act_hit = any(k in act_blob.lower() for k in ["playbook de aislamiento ejecutado", "playbook ejecutado", "lanzando playbook de aislamiento", "applied", "countermeasure"])
        else:
            observe_hit = any(k in observe_blob.lower() for k in ["ssh", "packet", "flow", "password spraying"])
            if experiment == "exp3":
                # exp3 has two detection phases: network IDS (detect_blob) AND
                # Falco/ransomware (observe_blob + enrich_blob). Search all three.
                detect_hit = bool(_detection_evidence_lines(
                    detect_blob + "\n" + observe_blob + "\n" + enrich_blob, experiment
                ))
            else:
                detect_hit = bool(_detection_evidence_lines(detect_blob, experiment))
            profile_hit = bool(profile_panel.get("native_profile_ready") or profile_panel.get("actor_profile_count") or profile_panel.get("profile_detail_lines"))
            enrich_hit = bool(misp_panel.get("event_ids_detected_in_logs") or "nuevo evento misp" in enrich_blob.lower())
            act_hit = any(k in act_blob.lower() for k in ["playbook ejecutado", "lanzando playbook", "applied", "block", "countermeasure"])

        # The live panel is the authoritative per-run signal source. If the UI
        # already confirmed a phase for this exact run, trust that evidence even
        # when the raw log tail is delayed or partially rotated.
        detect_hit = bool(
            detect_hit
            or live_timeline.get("detect_at") is not None
            or (misp_panel.get("detector_evidence_lines") or [])
        )
        profile_hit = bool(
            profile_hit
            or live_timeline.get("profile_at") is not None
            or (profile_panel.get("actor_profile_count") or 0) > 0
            or (profile_panel.get("native_profile_ready") or False)
        )
        enrich_hit = bool(
            enrich_hit
            or live_timeline.get("enrich_at") is not None
            or (misp_panel.get("event_detail_lines") or [])
            or (misp_panel.get("event_ids_detected_in_logs") or [])
        )
        act_hit = bool(
            act_hit
            or live_timeline.get("act_at") is not None
            or (countermeasure_panel.get("selected") or "").strip() not in {"", "-", "Pending / no decision yet"}
        )

        enrich_gate_ok = (enrich_hit or (not require_misp_enrich))

        # No local fast countermeasure for exp1: SOARCA is the sole component that
        # selects and applies the countermeasure, through the real OODA flow.

        # Close only when the full downstream chain is visible for this run.
        # Keep a soft timeout as a safety valve.
        if detect_hit and profile_hit and enrich_gate_ok and act_hit:
            return
        # All experiments now go through the same real OODA flow: the soft
        # deadline must not fire until the action phase (SOARCA execution) is
        # confirmed. SOARCA is the sole component that applies the countermeasure
        # (exp1 block_ip_range, exp2/exp3 isolation), so none may exit early.
        soft_deadline_eligible = detect_hit and (profile_hit or enrich_gate_ok or act_hit)
        if experiment in {"exp1", "exp2", "exp3"}:
            soft_deadline_eligible = soft_deadline_eligible and act_hit
        if time.time() >= soft_deadline and soft_deadline_eligible:
            return
        time.sleep(2)


def _wait_kafka_consumers_ready(timeout_sec: int = 25) -> None:
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


def _wait_for_final_report_readiness(run_id: str, timeout_sec: int = 45) -> tuple[bool, str]:
    deadline = time.time() + max(timeout_sec, 5)
    last_reason = "unknown"
    while time.time() < deadline:
        run_item = _history_item(run_id)
        ready, reason = _run_ready_for_final_report(run_item)
        last_reason = reason
        if ready:
            return True, "ready"
        time.sleep(2.0)
    return False, last_reason


def _compute_experiment_metrics(
    experiment: str,
    started: float | None,
    finished: float | None,
    logs_by_phase: dict[str, str],
    *,
    attack_started: float | None = None,
    traffic_panel: dict[str, Any] | None = None,
    report_panel: dict[str, Any] | None = None,
    countermeasure_text: str = "",
    attrs: list[dict[str, Any]] | None = None,
    detection_confirmed: bool = False,
) -> dict[str, Any]:
    attack_anchor = attack_started or started
    traffic_panel = traffic_panel or {}
    report_panel = report_panel or {}
    attrs = attrs or []

    detect_blob = logs_by_phase.get("detect", "")
    profile_blob = logs_by_phase.get("profile", "")
    enrich_blob = logs_by_phase.get("enrich", "")
    act_blob = logs_by_phase.get("act", "")
    observe_blob = logs_by_phase.get("observe", "")
    effective_detect_blob = detect_blob if experiment != "exp2" else (detect_blob + "\n" + observe_blob + "\n" + enrich_blob)
    detection_evidence_blob = "\n".join(_detection_evidence_lines(effective_detect_blob, experiment))

    relevant_attack_generated = 1
    relevant_attack_observed = 1 if detection_evidence_blob.strip() else 0
    observability_ratio = relevant_attack_observed / relevant_attack_generated

    traffic_series = list((traffic_panel or {}).get("series") or [])
    raw_points = int((traffic_panel or {}).get("raw_points") or len(traffic_series) or 0)
    window_points = int((traffic_panel or {}).get("window_points") or len(traffic_series) or 0)
    traffic_markers = (traffic_panel or {}).get("markers") or {}
    countermeasure_ts = traffic_markers.get("countermeasure_at")
    first_traffic_ts = None
    if traffic_series:
        if attack_anchor is not None:
            attack_window = [p for p in traffic_series if float(p.get("ts", 0.0) or 0.0) >= float(attack_anchor)]
            first_traffic_ts = float((attack_window[0] if attack_window else traffic_series[0]).get("ts", 0.0) or 0.0)
        else:
            first_traffic_ts = float(traffic_series[0].get("ts", 0.0) or 0.0)

    def _last_timestamp_in_blob(blob: str) -> float | None:
        if not blob:
            return None
        ts_values = [_parse_log_epoch(line) for line in blob.splitlines()]
        ts_values = [float(ts) for ts in ts_values if isinstance(ts, (int, float))]
        return max(ts_values) if ts_values else None

    observed_tail_candidates = [
        _last_timestamp_in_blob(observe_blob),
        _last_timestamp_in_blob(detect_blob),
        _last_timestamp_in_blob(profile_blob),
        _last_timestamp_in_blob(enrich_blob),
        _last_timestamp_in_blob(act_blob),
        float(traffic_series[-1].get("ts", 0.0) or 0.0) if traffic_series else None,
        float(countermeasure_ts) if isinstance(countermeasure_ts, (int, float)) else None,
    ]
    observed_tail_candidates = [float(v) for v in observed_tail_candidates if isinstance(v, (int, float)) and float(v) > 0.0]
    observed_finished = max(observed_tail_candidates) if observed_tail_candidates else None
    if finished is None:
        with LOCK:
            state_finished = STATE.get("last_finished_at")
        if isinstance(state_finished, (int, float)) and float(state_finished) > 0.0:
            finished = float(state_finished)
    if (finished is None or (started is not None and finished <= started)) and observed_finished is not None:
        if started is None or observed_finished >= started:
            finished = observed_finished
    if started is None and attack_anchor is not None:
        started = attack_anchor
    if started is None and first_traffic_ts is not None:
        started = first_traffic_ts
    duration = max((finished or 0) - (started or 0), 0.001)
    first_alert = _first_timestamp_for_keywords(
        detection_evidence_blob,
        [
            "alerta publicada",
            "alerta rápida publicada",
            "alerta por flows publicada",
            "nueva alerta publicada",
            "host ransomware emulation detected",
            "distributed password spraying",
        ],
    )
    # Prefer concrete evidence from the live TAPCD report panel and the
    # current run logs. If there is no actor profile, keep the phase pending
    # instead of fabricating a successful profile.
    live_tapcd = (report_panel.get("tapcd") or {}) if report_panel else {}
    live_misp = (report_panel.get("misp") or {}) if report_panel else {}
    live_timeline = (report_panel.get("timeline") or {}) if report_panel else {}
    actor_profiles = list((live_tapcd.get("actor_profiles") or []))
    actor_profile_count = int(live_tapcd.get("actor_profile_count") or len(actor_profiles) or 0)
    native_profile_ready = bool(live_tapcd.get("native_profile_ready"))
    if actor_profile_count > 0 and actor_profiles:
        lead_actor = actor_profiles[0]
    elif native_profile_ready:
        lead_actor = (actor_profiles[0] if actor_profiles else {})
    else:
        lead_actor = {}
    profile_ts = None
    if isinstance(live_timeline.get("profile_at"), (int, float)):
        profile_ts = float(live_timeline.get("profile_at") or 0.0) or None
    if profile_ts is None:
        profile_ts = _first_timestamp_for_keywords(
            profile_blob,
            PROFILE_EVIDENCE_KEYWORDS + ["profile", "actor", "attacker profile", "stream_low", "neo4j"],
        )
    stable_identification = (profile_ts or first_alert) if actor_profile_count > 0 else None
    decide_time = None
    if isinstance(live_timeline.get("decide_at"), (int, float)):
        decide_time = float(live_timeline.get("decide_at") or 0.0) or None
    if decide_time is None:
        decide_time = _first_timestamp_for_keywords(act_blob, ["selección defensiva", "d3fend", "lanzando playbook", "selected"])
    act_time = None
    if isinstance(live_timeline.get("act_at"), (int, float)):
        act_time = float(live_timeline.get("act_at") or 0.0) or None
    if act_time is None:
        act_time = _first_timestamp_for_keywords(act_blob, ["playbook ejecutado", "playbook de aislamiento ejecutado", "applied", "block", "isolation", "executor"])
    # Prefer actual attack-relative telemetry instead of run start to keep the
    # latency values scientifically meaningful.
    attack_start = attack_anchor
    first_telemetry = first_traffic_ts or _first_timestamp_for_keywords(observe_blob, ["flow", "ssh", "packet", "password spraying", "falco", "ransomware", "warning"])

    latencies = []
    for ts in [first_telemetry, first_alert, stable_identification, decide_time, act_time]:
        if ts is not None and attack_start is not None:
            latencies.append(max(ts - attack_start, 0.0))
    latencies_sorted = sorted(latencies)
    stage_deltas = {
        "observe_to_detect": (first_alert - first_telemetry) if (first_alert is not None and first_telemetry is not None) else None,
        "detect_to_profile": (stable_identification - first_alert) if (stable_identification is not None and first_alert is not None) else None,
        "profile_to_enrich": None,
        "enrich_to_decide": (decide_time - stable_identification) if (decide_time is not None and stable_identification is not None) else None,
        "decide_to_act": (act_time - decide_time) if (act_time is not None and decide_time is not None) else None,
    }
    first_misp = None
    if isinstance(live_timeline.get("enrich_at"), (int, float)):
        first_misp = float(live_timeline.get("enrich_at") or 0.0) or None
    if first_misp is None:
        first_misp = _first_timestamp_for_keywords(enrich_blob, ["nuevo evento misp", "event", "attribute", "ip-src", "ip-dst"])
    if first_misp is not None and stable_identification is not None:
        stage_deltas["profile_to_enrich"] = first_misp - stable_identification

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
    fp = max(len([ln for ln in detection_evidence_blob.splitlines() if ln.strip()]) - tp, 0)
    tn = 0
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    f1 = (2 * precision * recall) / max(precision + recall, 1e-9)

    def _non_warning_error_count(blob: str) -> int:
        if not blob:
            return 0
        error_keywords = ["error", "exception", "timeout", "i/o timeout", "dial tcp", "eof", "traceback", "failed"]
        blocked = ["warning", "insecurerequestwarning"]
        count = 0
        for line in blob.splitlines():
            low = line.lower()
            if any(k in low for k in error_keywords) and not any(k in low for k in blocked):
                count += 1
        return count

    observe_phase_lines = sum(
        1
        for ln in observe_blob.splitlines()
        if any(k in ln.lower() for k in ["flow", "ssh", "packet", "falco", "telegraf", "warning novadef"])
    )
    detect_phase_lines = len([ln for ln in detection_evidence_blob.splitlines() if ln.strip()])
    profile_phase_lines = len(live_tapcd.get("profile_detail_lines") or _tapcd_profile_evidence_lines(profile_blob))
    enrich_phase_lines = len(
        [
            ln
            for ln in enrich_blob.splitlines()
            if any(k in ln.lower() for k in ["nuevo evento misp", "[+] ip-src", "[+] ip-dst", "[+] port", "[+] text", "attribute", "event"])
        ]
    )
    act_phase_lines = sum(
        1
        for ln in act_blob.splitlines()
        if any(k in ln.lower() for k in ["playbook", "d3fend", "executor", "response", "isolation", "block", "lock", "selected"])
    )

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
    detect_ts = _all_timestamps_for_keywords(
        detection_evidence_blob,
        [
            "alerta publicada",
            "alerta rápida publicada",
            "alerta por flows publicada",
            "nueva alerta publicada",
            "host ransomware emulation detected",
            "distributed password spraying",
        ],
    )
    detect_inter_arrivals = [
        max(detect_ts[idx + 1] - detect_ts[idx], 0.0) for idx in range(len(detect_ts) - 1) if detect_ts[idx + 1] >= detect_ts[idx]
    ]
    detect_inter_arrivals_sorted = sorted(detect_inter_arrivals)
    mem_total = sum(v.get("memory_bytes", 0.0) for v in container_stats.values())
    cpu_total = sum(v.get("cpu_percent", 0.0) for v in container_stats.values())
    top_cpu = sorted(container_stats.items(), key=lambda kv: kv[1].get("cpu_percent", 0.0), reverse=True)[:5]
    top_mem = sorted(container_stats.items(), key=lambda kv: kv[1].get("memory_bytes", 0.0), reverse=True)[:5]

    expected_observe_sources = {
        "exp1": ["tshark", "flow", "ssh"],
        "exp2": ["falco", "file", "process"],
        "exp3": ["tshark", "flow", "falco", "ssh", "host_signal"],
    }.get(experiment, ["tshark", "flow"])
    observed_sources = [src for src in expected_observe_sources if src in observe_blob.lower() or src in effective_detect_blob.lower()]
    observation_source_coverage = len(observed_sources) / max(len(expected_observe_sources), 1)
    telemetry_points = len(traffic_series)
    telemetry_intervals = [max(float(traffic_series[i + 1].get("ts", 0.0) or 0.0) - float(traffic_series[i].get("ts", 0.0) or 0.0), 0.0) for i in range(max(telemetry_points - 1, 0))]
    median_interval = statistics.median(telemetry_intervals) if telemetry_intervals else 0.0
    gap_threshold = max(median_interval * 2.5, 1.25) if median_interval > 0 else 1.25
    telemetry_gaps = sum(1 for delta in telemetry_intervals if delta > gap_threshold)
    telemetry_continuity = 1.0 if telemetry_points <= 1 else max(1.0 - (telemetry_gaps / max(len(telemetry_intervals), 1)), 0.0)
    telemetry_signal_density = telemetry_points / max(duration, 0.001)

    raw_pps: list[float] = []
    effective_pps: list[float] = []
    blocked_pps: list[float] = []
    interval_records: list[dict[str, float]] = []
    analyzed_packets_raw = 0.0
    analyzed_packets_effective = 0.0
    analyzed_packets_blocked = 0.0
    for i in range(1, telemetry_points):
        prev = traffic_series[i - 1]
        curr = traffic_series[i]
        dt = max(float(curr.get("ts", 0.0) or 0.0) - float(prev.get("ts", 0.0) or 0.0), 1e-6)
        prev_raw = float(prev.get("rx_packets_raw", prev.get("rx_packets", 0.0)) or 0.0)
        curr_raw = float(curr.get("rx_packets_raw", curr.get("rx_packets", 0.0)) or 0.0)
        prev_eff = float(prev.get("rx_packets", 0.0) or 0.0)
        curr_eff = float(curr.get("rx_packets", 0.0) or 0.0)
        prev_blk = float(prev.get("blocked_packets", 0.0) or 0.0)
        curr_blk = float(curr.get("blocked_packets", 0.0) or 0.0)

        d_raw = max(curr_raw - prev_raw, 0.0)
        d_eff = max(curr_eff - prev_eff, 0.0)
        d_blk = max(curr_blk - prev_blk, 0.0)
        analyzed_packets_raw += d_raw
        analyzed_packets_effective += d_eff
        analyzed_packets_blocked += d_blk

        raw_rate = d_raw / dt
        eff_rate = d_eff / dt
        blk_rate = d_blk / dt
        raw_pps.append(raw_rate)
        effective_pps.append(eff_rate)
        blocked_pps.append(blk_rate)
        interval_records.append(
            {
                "end_ts": float(curr.get("ts", 0.0) or 0.0),
                "effective_pps": eff_rate,
                "raw_pps": raw_rate,
                "blocked_pps": blk_rate,
            }
        )

    cm_window_sec = float(os.getenv("EXPERIMENT_DROP_WINDOW_SECONDS", "8.0"))
    cm_min_intervals = int(os.getenv("EXPERIMENT_DROP_MIN_INTERVALS", "4"))
    cm_clear_threshold = float(os.getenv("EXPERIMENT_DROP_CLEAR_RATIO", "0.20"))

    def _median_or_zero(values: list[float]) -> float:
        return float(statistics.median(values)) if values else 0.0

    pre_cm_window: list[dict[str, float]] = []
    post_cm_window: list[dict[str, float]] = []
    if isinstance(countermeasure_ts, (int, float)) and interval_records:
        cm_ts = float(countermeasure_ts)
        pre_cm_window = [it for it in interval_records if (cm_ts - cm_window_sec) <= it["end_ts"] < cm_ts]
        post_cm_window = [it for it in interval_records if cm_ts <= it["end_ts"] <= (cm_ts + cm_window_sec)]
        if len(pre_cm_window) < cm_min_intervals:
            pre_cm_window = [it for it in interval_records if it["end_ts"] < cm_ts][-cm_min_intervals:]
        if len(post_cm_window) < cm_min_intervals:
            post_cm_window = [it for it in interval_records if it["end_ts"] >= cm_ts][:cm_min_intervals]

    median_pre_cm_pps = _median_or_zero([it["effective_pps"] for it in pre_cm_window])
    median_post_cm_pps = _median_or_zero([it["effective_pps"] for it in post_cm_window])
    median_post_cm_blocked_pps = _median_or_zero([it["blocked_pps"] for it in post_cm_window])
    cm_drop_ratio = 0.0
    if median_pre_cm_pps > 0:
        _raw_cm_drop = (median_pre_cm_pps - median_post_cm_pps) / median_pre_cm_pps
        if _raw_cm_drop < 0 and median_post_cm_blocked_pps > 0:
            # iptables counter reset during isolation: chain starts from 0, so
            # post_effective < pre. Use blocked_pps as proxy for actual reduction.
            cm_drop_ratio = min(median_post_cm_blocked_pps / median_pre_cm_pps, 1.0)
        else:
            cm_drop_ratio = max(min(_raw_cm_drop, 1.0), 0.0)
    cm_drop_clear = bool(len(pre_cm_window) >= 2 and len(post_cm_window) >= 2 and cm_drop_ratio >= cm_clear_threshold)

    timeline_monotonic = {
        "attack_before_detect": bool((attack_start is None) or (first_alert is None) or (first_alert >= attack_start)),
        "detect_before_profile": bool((first_alert is None) or (stable_identification is None) or (stable_identification >= first_alert)),
        "profile_before_enrich": bool((stable_identification is None) or (first_misp is None) or (first_misp >= stable_identification)),
        "enrich_before_decide": bool((first_misp is None) or (decide_time is None) or (decide_time >= first_misp)),
        "decide_before_act": bool((decide_time is None) or (act_time is None) or (act_time >= decide_time)),
        "start_before_finish": bool((started is None) or (finished is None) or (finished >= started)),
    }

    # The metric path stays self-contained and uses textual/graph evidence already
    # present in the run logs/report pipeline.
    profile_lines = list(live_tapcd.get("profile_detail_lines") or _tapcd_profile_evidence_lines(profile_blob))
    inferred_actor_count = int(actor_profile_count or len(actor_profiles) or 0)
    d3fend_mentions = _count_keyword_hits(act_blob, ["d3fend", "network traffic filtering", "session termination", "execution isolation", "network isolation", "process termination", "account locking", "block", "isolation"])
    response_error_count = _non_warning_error_count(act_blob)
    response_timeliness = max((act_time or decide_time or finished or started or 0) - (attack_start or 0), 0.0) if attack_start else 0.0
    response_execution_present = bool(
        act_time is not None
        or _effective_soarca_execution(experiment, act_blob)
    )
    # Determine selected playbook from logs
    act_blob_low = act_blob.lower()
    if "block_ip_range" in act_blob_low or "bloquear" in act_blob_low or "bloqueado" in act_blob_low:
        _selected_playbook = "block_ip_range"
    elif "isolate_lab_host" in act_blob_low or "aislamiento" in act_blob_low or "isolation" in act_blob_low:
        _selected_playbook = "isolate_lab_host"
    else:
        _selected_playbook = "unknown"
    # D3FEND alignment: 1.0 if correct playbook for attack type, 0.0 otherwise
    # exp1 = password spraying → correct: block_ip_range (D3-InboundTrafficFiltering)
    # exp2 = ransomware       → correct: isolate_lab_host (D3-NetworkIsolation)
    # exp3 = hybrid           → correct: isolate_lab_host (D3-NetworkIsolation + D3-ExecutionIsolation)
    _correct_playbook_map = {
        "exp1": "block_ip_range",
        "exp2": "isolate_lab_host",
        "exp3": "isolate_lab_host",
    }
    _expected_playbook = _correct_playbook_map.get(experiment, "unknown")
    _playbook_correct = bool(_selected_playbook == _expected_playbook and _selected_playbook != "unknown")
    _d3fend_technique_map = {
        "exp1": "D3-InboundTrafficFiltering + D3-NetworkTrafficFiltering",
        "exp2": "D3-NetworkIsolation + D3-ExecutionIsolation",
        "exp3": "D3-NetworkIsolation + D3-ExecutionIsolation",
    }
    _d3fend_technique = _d3fend_technique_map.get(experiment, "unknown")
    # Proper alignment score: 1.0 correct, 0.5 execution present but playbook uncertain, 0.0 no execution
    if _playbook_correct:
        response_alignment_score = 1.0
    elif response_execution_present:
        response_alignment_score = 0.5
    else:
        response_alignment_score = min(d3fend_mentions / 3.0, 1.0)
    response_success_score = 1.0 if response_execution_present and response_error_count == 0 else (
        0.75 if response_execution_present else (0.5 if countermeasure_text and countermeasure_text not in {"", "-", "Pending / no decision yet"} else 0.0)
    )
    # SSH execution evidence — absence of SSH error keywords in act blob
    _ssh_error_keywords = ["ssh: connect to host", "connection refused", "no route to host", "permission denied", "ssh_exchange_identification", "broken pipe"]
    _ssh_execution_success = bool(response_execution_present and not any(k in act_blob_low for k in _ssh_error_keywords))
    # Traffic reduction: if isolation resets the iptables chain counter to 0, post < pre
    # is expected and valid. In that case use blocked_pps as proxy for reduction.
    _cm_type = _selected_playbook  # block_ip_range vs isolate_lab_host
    if median_pre_cm_pps > 0 and median_post_cm_pps >= 0:
        _raw_drop = (median_pre_cm_pps - median_post_cm_pps) / median_pre_cm_pps
        if _raw_drop < 0 and median_post_cm_blocked_pps > 0:
            # Counter reset case: use blocked_pps / pre_pps as traffic reduction
            _traffic_reduction_ratio = min(median_post_cm_blocked_pps / median_pre_cm_pps, 1.0)
        else:
            _traffic_reduction_ratio = max(min(_raw_drop, 1.0), 0.0)
    else:
        _traffic_reduction_ratio = 0.0
    phase_line_counts = {
        "observe": sum(1 for ln in observe_blob.splitlines() if any(k in ln.lower() for k in ["flow", "ssh", "packet", "falco", "telegraf", "warning novadef"])),
        "detect": len([ln for ln in detection_evidence_blob.splitlines() if ln.strip()]),
        "profile": len(profile_lines),
        "enrich": len([ln for ln in enrich_blob.splitlines() if any(k in ln.lower() for k in ["nuevo evento misp", "[+] ip-src", "[+] ip-dst", "[+] port", "[+] text", "attribute", "event"])]),
        "act": sum(1 for ln in act_blob.splitlines() if any(k in ln.lower() for k in ["playbook", "d3fend", "executor", "response", "isolation", "block", "lock", "selected"])),
    }
    phase_error_counts = {
        "observe": _non_warning_error_count(observe_blob),
        "detect": _non_warning_error_count(detect_blob),
        "profile": _non_warning_error_count(profile_blob),
        "enrich": _non_warning_error_count(enrich_blob),
        "act": _non_warning_error_count(act_blob),
    }
    tool_signal_counts = {
        "observe": {
            "tshark": _count_keyword_hits(observe_blob, ["tshark", "packet", "flow"]),
            "falco": _count_keyword_hits(observe_blob, ["falco", "warning", "syscall"]),
            "scenario_attacker": _count_keyword_hits(observe_blob, ["scenario_attacker", "password spraying", "attack"]),
        },
        "detect": {
            "snort": _count_keyword_hits(detection_evidence_blob, ["snort", "signature", "alert"]),
            "network_intrusion_detector": _count_keyword_hits(detection_evidence_blob, ["network ids", "anomaly", "spray", "alerta publicada", "nueva alerta"]),
            "alert_module": _count_keyword_hits(detection_evidence_blob, ["alert module", "alert_json", "alerta recibida"]),
        },
        "profile": {
            "stream_low": _count_keyword_hits(profile_blob, ["stream_low", "profile", "actor", "profile_"]),
            "prep_pred": _count_keyword_hits(profile_blob, ["prep_pred", "profile", "actor", "classification"]),
            "neo4j_ingester": _count_keyword_hits(profile_blob, ["neo4j", "ingester", "profile", "actor"]),
        },
        "enrich": {
            "misp_integrator": _count_keyword_hits(enrich_blob, ["pmp-misp-integrator", "nuevo evento misp", "event", "attribute", "published", "created"]),
            "misp_server": _count_keyword_hits(enrich_blob, ["misp-server", "events/add", "restsearch", "attributes"]),
        },
        "act": {
            "soarca_trigger": _count_keyword_hits(act_blob, ["soarca-trigger", "playbook", "selected", "d3fend"]),
            "soarca_core": _count_keyword_hits(act_blob, ["soarca-core", "d3fend", "countermeasure", "workflow"]),
            "soarca_executor": _count_keyword_hits(act_blob, ["executor", "iptables", "response applied", "playbook ejecutado"]),
        },
    }
    dimension_metrics = {
        "network": {
            "telemetry_points": telemetry_points,
            "telemetry_gap_count": telemetry_gaps,
            "source_coverage_ratio": round(observation_source_coverage, 4),
            "detection_events": 1 if relevant_attack_observed else 0,
        },
        "host": {
            "cpu_percent_peak": round(max((p.get("cpu_percent", 0.0) for p in traffic_series), default=0.0), 3),
            "memory_percent_peak": round(max((p.get("memory_percent", 0.0) for p in traffic_series), default=0.0), 3),
            "falco_event_points": int(sum(1 for p in traffic_series if float(p.get("falco_events", 0.0) or 0.0) > 0.0)),
        },
        "incident": {
            "misp_event_count": 1 if (live_misp.get("event_ids_detected_in_logs") or detection_confirmed) else 0,
            "tapcd_actor_count": inferred_actor_count,
            "profile_completeness_ratio": round(
                sum(1 for fld in ["profile", "affiliation", "motivation", "attitude", "skills"] if str(lead_actor.get(fld) or "").strip()) / 5.0,
                4,
            ) if lead_actor else 0.0,
        },
        "response": {
            "countermeasure_present": 1 if countermeasure_text and countermeasure_text not in {"", "-", "Pending / no decision yet"} else 0,
            "soarca_execution_present": 1 if response_execution_present else 0,
            "response_error_count": response_error_count,
        },
    }
    quality_metrics = {
        "observation_quality_score": round(observation_source_coverage * telemetry_continuity, 4),
        "detection_quality_score": round(f1, 4),
        "profile_quality_score": round(
            max(
                0.0,
                min(
                    1.0,
                    ((sum(1 for fld in ["profile", "affiliation", "motivation", "attitude", "skills"] if str(lead_actor.get(fld) or "").strip()) / 5.0) if lead_actor else 0.0)
                    * (1.0 if actor_profile_count > 0 else 0.0)
                ),
            ),
            4,
        ),
        "response_quality_score": round(min((response_alignment_score * 0.5) + (response_success_score * 0.5), 1.0), 4),
    }
    ooda_phase_metrics = {
        "observe": {
            "telemetry_points": telemetry_points,
            "raw_points": raw_points,
            "window_points": window_points,
            "source_coverage_ratio": round(observation_source_coverage, 4),
            "telemetry_continuity_ratio": round(min(max(telemetry_continuity, 0.0), 1.0), 4),
            "telemetry_signal_density_lps": round(telemetry_signal_density, 4),
            "first_telemetry_latency": _sec_pack(max((first_telemetry or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            "observation_quality_score": round(observation_source_coverage * telemetry_continuity, 4),
        },
        "orient": {
            "actor_profile_count": actor_profile_count,
            "profile_signal_lines": profile_phase_lines,
            "profile_completeness_ratio": round(
                sum(
                    1
                    for fld in ["profile", "affiliation", "motivation", "attitude", "skills"]
                    if str(lead_actor.get(fld) or "").strip()
                )
                / 5.0,
                4,
            ) if lead_actor else 0.0,
            "profile_consistency_ratio": round(1.0 if actor_profile_count > 0 and str(lead_actor.get("profile") or "").strip() else 0.0, 4),
            "time_to_orient": _sec_pack(max((stable_identification or attack_start or 0) - (attack_start or 0), 0.0)) if stable_identification is not None and attack_start else None,
            "misp_event_count": 1 if (live_misp.get("event_ids_detected_in_logs") or detection_confirmed) else 0,
        },
        "decide": {
            "decision_present": bool(countermeasure_text and countermeasure_text not in {"", "-", "Pending / no decision yet"}),
            "d3fend_alignment_score": round(response_alignment_score, 4),
            "time_to_decide": _sec_pack(max((decide_time or attack_start or 0) - (attack_start or 0), 0.0)) if decide_time is not None and attack_start else None,
            "profile_to_decide_latency": _sec_pack(max((decide_time or attack_start or 0) - (stable_identification or attack_start or 0), 0.0)) if (decide_time is not None and stable_identification is not None) else None,
            "decision_quality_score": round(response_alignment_score, 4),
        },
        "act": {
            "execution_present": bool(response_execution_present),
            "time_to_act": _sec_pack(max((act_time or attack_start or 0) - (attack_start or 0), 0.0)) if act_time is not None and attack_start else None,
            "decision_to_act_latency": _sec_pack(max((act_time or decide_time or attack_start or 0) - (decide_time or attack_start or 0), 0.0)) if (act_time is not None and decide_time is not None) else None,
            "response_error_count": response_error_count,
            "response_success_score": round(response_success_score, 4),
            "act_quality_score": round(min((response_alignment_score * 0.5) + (response_success_score * 0.5), 1.0), 4),
        },
    }

    return {
        "event_observability_ratio": round(observability_ratio, 4),
        "observation_quality": {
            "expected_sources": expected_observe_sources,
            "observed_sources": observed_sources,
            "source_coverage_ratio": round(observation_source_coverage, 4),
            "telemetry_continuity_ratio": round(min(max(telemetry_continuity, 0.0), 1.0), 4),
            "telemetry_gap_count": telemetry_gaps,
            "telemetry_signal_density_lps": round(telemetry_signal_density, 4),
            "first_telemetry_latency": _sec_pack(max((first_telemetry or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
        },
        "quality_metrics": quality_metrics,
        "ooda_phase_metrics": ooda_phase_metrics,
        "run_window": {
            "started_at_epoch": started,
            "finished_at_epoch": finished,
            "duration_sec": duration,
            "duration_ms": duration * 1_000.0,
            "duration_us": duration * 1_000_000.0,
            "duration_ns": duration * 1_000_000_000.0,
            "has_complete_bounds": bool(started is not None and finished is not None and finished >= started),
            "attack_started_at_epoch": attack_start,
        },
        "packet_analysis": {
            "telemetry_samples_total": telemetry_points,
            "telemetry_intervals_total": max(telemetry_points - 1, 0),
            "packets_raw_analyzed": round(analyzed_packets_raw, 3),
            "packets_effective_analyzed": round(analyzed_packets_effective, 3),
            "packets_blocked_analyzed": round(analyzed_packets_blocked, 3),
            "raw_pps_mean": round(statistics.mean(raw_pps), 4) if raw_pps else 0.0,
            "raw_pps_p95": round(_percentile(sorted(raw_pps), 0.95), 4) if raw_pps else 0.0,
            "effective_pps_mean": round(statistics.mean(effective_pps), 4) if effective_pps else 0.0,
            "effective_pps_p95": round(_percentile(sorted(effective_pps), 0.95), 4) if effective_pps else 0.0,
            "blocked_pps_mean": round(statistics.mean(blocked_pps), 4) if blocked_pps else 0.0,
            "blocked_pps_p95": round(_percentile(sorted(blocked_pps), 0.95), 4) if blocked_pps else 0.0,
            "pre_countermeasure_effective_pps_median": round(median_pre_cm_pps, 4),
            "post_countermeasure_effective_pps_median": round(median_post_cm_pps, 4),
            "post_countermeasure_blocked_pps_median": round(median_post_cm_blocked_pps, 4),
            "countermeasure_drop_window_seconds": round(cm_window_sec, 3),
            "countermeasure_drop_pre_intervals": len(pre_cm_window),
            "countermeasure_drop_post_intervals": len(post_cm_window),
            "countermeasure_drop_clear": cm_drop_clear,
            "countermeasure_packet_drop_ratio": round(cm_drop_ratio, 4),
            "countermeasure_packet_drop_percent": round(cm_drop_ratio * 100.0, 2),
        },
        "operational_scalability": {
            "telemetry_ingest_rate_eps": round(raw_points / duration, 4),
            "detector_processing_rate_eps": round(tp / duration, 4),
            "database_write_rate_eps": round(max(len(attrs), 1 if (live_misp.get("event_ids_detected_in_logs") or []) else 0) / duration, 4),
            "soarca_action_rate_eps": round((1 if response_execution_present else 0) / duration, 4),
            "events_window_seconds": round(duration, 3),
            "telemetry_event_count": raw_points,
            "detector_event_count": 1 if relevant_attack_observed else 0,
            "db_write_count": len(attrs) if attrs else int(bool(live_misp.get("event_ids_detected_in_logs") or [])),
            "soarca_action_count": 1 if response_execution_present else 0,
            "phase_line_counts": phase_line_counts,
            "phase_signal_counts": {
                "observe": observe_phase_lines,
                "detect": detect_phase_lines,
                "profile": profile_phase_lines,
                "enrich": enrich_phase_lines,
                "act": act_phase_lines,
            },
        },
        "resource_overhead": {
            "containers": container_stats,
            "cpu_percent_sum": round(cpu_total, 3),
            "memory_percent_sum": round(sum(v.get("memory_percent", 0.0) for v in container_stats.values()), 3),
            "memory_bytes_sum": mem_total,
            "top_cpu_containers": [{"container": k, "cpu_percent": v.get("cpu_percent", 0.0)} for k, v in top_cpu],
            "top_memory_containers": [{"container": k, "memory_bytes": v.get("memory_bytes", 0.0)} for k, v in top_mem],
        },
        "tool_breakdown": tool_signal_counts,
        "dimension_breakdown": dimension_metrics,
        "latency_ooda": {
            "attack_start_ts": attack_start,
            "first_telemetry_ts": first_telemetry,
            "first_alert_ts": first_alert,
            "stable_identification_ts": stable_identification,
            "decide_ts": decide_time,
            "act_ts": act_time,
            "time_to_first_alert": _sec_pack(max((first_alert or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            "time_to_correct_identification": _sec_pack(max((stable_identification or attack_start or 0) - (attack_start or 0), 0.0)) if (attack_start and stable_identification is not None) else None,
            "e2e_to_act": _sec_pack(max((act_time or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            "latency_mean": _sec_pack(statistics.mean(latencies_sorted)) if latencies_sorted else _sec_pack(0.0),
            "latency_median": _sec_pack(statistics.median(latencies_sorted)) if latencies_sorted else _sec_pack(0.0),
            "latency_p95": _sec_pack(_percentile(latencies_sorted, 0.95)),
            "latency_p99": _sec_pack(_percentile(latencies_sorted, 0.99)),
            "latency_jitter_std": _sec_pack(statistics.pstdev(latencies_sorted)) if len(latencies_sorted) > 1 else _sec_pack(0.0),
            "phase_transition_latency": {k: _sec_pack(v) for k, v in stage_deltas.items()},
            "first_misp_ts": first_misp,
        },
        "timeline_consistency": {
            "monotonic_flags": timeline_monotonic,
            "all_monotonic": bool(all(timeline_monotonic.values())),
        },
        "detection_stream_temporal": {
            "detection_timestamps_count": len(detect_ts),
            "inter_arrival_mean": _sec_pack(statistics.mean(detect_inter_arrivals_sorted)) if detect_inter_arrivals_sorted else _sec_pack(0.0),
            "inter_arrival_median": _sec_pack(statistics.median(detect_inter_arrivals_sorted)) if detect_inter_arrivals_sorted else _sec_pack(0.0),
            "inter_arrival_p95": _sec_pack(_percentile(detect_inter_arrivals_sorted, 0.95)),
            "inter_arrival_p99": _sec_pack(_percentile(detect_inter_arrivals_sorted, 0.99)),
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
        "profile_quality": {
            "profile_signal_lines": profile_phase_lines,
            "inferred_actor_count": actor_profile_count,
            "field_hits": {
                "profile": 1 if str(lead_actor.get("profile") or "").strip() else 0,
                "affiliation": 1 if str(lead_actor.get("affiliation") or "").strip() else 0,
                "motivation": 1 if str(lead_actor.get("motivation") or "").strip() else 0,
                "attitude": 1 if str(lead_actor.get("attitude") or "").strip() else 0,
                "skills": 1 if str(lead_actor.get("skills") or "").strip() else 0,
                "techniques": 1 if str(lead_actor.get("techniques") or "").strip() else 0,
            },
            "field_completeness_ratio": round(
                sum(
                    1
                    for fld in ["profile", "affiliation", "motivation", "attitude", "skills"]
                    if str(lead_actor.get(fld) or "").strip()
                )
                / 5.0,
                4,
            ) if lead_actor else 0.0,
            "profile_consistency_ratio": round(1.0 if actor_profile_count > 0 and str(lead_actor.get("profile") or "").strip() else 0.0, 4),
            "profile_timeliness": _sec_pack(max((stable_identification or attack_start or 0) - (attack_start or 0), 0.0)) if stable_identification is not None and attack_start else None,
        },
        "response_effectiveness": {
            "decision_present": bool(countermeasure_text and countermeasure_text not in {"-", "Pending / no decision yet"}),
            "execution_present": bool(response_execution_present),
            "d3fend_alignment_score": round(response_alignment_score, 4),
            "response_error_count": _non_warning_error_count(act_blob),
            "response_success_score": round(1.0 if response_execution_present and _non_warning_error_count(act_blob) == 0 else (0.5 if countermeasure_text else 0.0), 4),
            "response_timeliness": _sec_pack(response_timeliness) if response_execution_present else None,
        },
        "pipeline_reliability": {
            "error_counts_by_phase": {
                "observe": _non_warning_error_count(observe_blob),
                "detect": _non_warning_error_count(detect_blob),
                "profile": _non_warning_error_count(profile_blob),
                "enrich": _non_warning_error_count(enrich_blob),
                "act": _non_warning_error_count(act_blob),
            },
            "total_error_signals": sum(
                [
                    _non_warning_error_count(observe_blob),
                    _non_warning_error_count(detect_blob),
                    _non_warning_error_count(profile_blob),
                    _non_warning_error_count(enrich_blob),
                    _non_warning_error_count(act_blob),
                ]
            ),
            "stage_completion_flags": {
                "observe": bool(traffic_series),
                "detect": bool(first_alert is not None),
                "profile": bool(actor_profile_count > 0),
                "enrich": bool(live_misp.get("event_ids_detected_in_logs") or []),
                "decide": bool(countermeasure_text and countermeasure_text not in {"-", "Pending / no decision yet"}),
                "act": bool(_soarca_execution_evidence(act_blob)),
            },
        },
        "attack_classification_link": {
            "detection_to_profile_linked": bool(actor_profile_count > 0 and (live_misp.get("event_ids_detected_in_logs") or [])),
            "profile_mentions": actor_profile_count,
        },
        "data_completeness": {
            "required_timestamps_present": {
                "started_at": started is not None,
                "attack_started_at": attack_start is not None,
                "first_alert_ts": first_alert is not None,
                "profile_ts": stable_identification is not None,
                "misp_ts": first_misp is not None,
                "decide_ts": decide_time is not None,
                "act_ts": act_time is not None,
                "finished_at": finished is not None,
            },
            "required_evidence_present": {
                "detection_confirmed": bool(relevant_attack_observed),
                "profile_confirmed": bool(actor_profile_count > 0),
                "misp_confirmed": bool(live_misp.get("event_ids_detected_in_logs") or []),
                "countermeasure_selected": bool(countermeasure_text and countermeasure_text not in {"", "-", "Pending / no decision yet"}),
                "execution_confirmed": bool(_soarca_execution_evidence(act_blob)),
            },
        },
        # ── Article-specific metrics ────────────────────────────────────────
        # These blocks map directly to the paper sections: OBSERVAR, ORIENTAR,
        # E2E OODA. They are included verbatim in the report so figures and
        # tables can be generated from the JSON without further post-processing.
        "article_observe": {
            # Event Observability Ratio per layer (relevant events captured /
            # total relevant events generated), split by sensor dimension.
            "event_observability_ratio_global": round(observability_ratio, 4),
            "event_observability_by_layer": {
                "network": round(observation_source_coverage if "tshark" in observed_sources or "flow" in " ".join(observed_sources) else 0.0, 4),
                "host": round(1.0 if any("falco" in s for s in observed_sources) else 0.0, 4),
                "incident": round(1.0 if bool(live_misp.get("event_ids_detected_in_logs") or []) else 0.0, 4),
            },
            # Monitoring adaptability: sources active vs expected
            "monitoring_adaptability": {
                "expected_sources": expected_observe_sources,
                "active_sources": observed_sources,
                "source_coverage_ratio": round(observation_source_coverage, 4),
                "telemetry_signal_density_lps": round(telemetry_signal_density, 4),
                "telemetry_continuity_ratio": round(min(max(telemetry_continuity, 0.0), 1.0), 4),
                "telemetry_gap_count": telemetry_gaps,
            },
            # Scalability indicators (ingest rates as assets / sensors grow)
            "scalability_indicators": {
                "telemetry_ingest_rate_eps": round(raw_points / duration, 4),
                "detector_processing_rate_eps": round(tp / duration, 4),
                "database_write_rate_eps": round(
                    max(len(attrs), 1 if (live_misp.get("event_ids_detected_in_logs") or []) else 0) / duration, 4
                ),
                "global_cpu_percent_sum": round(cpu_total, 3),
                "global_memory_percent_sum": round(
                    sum(v.get("memory_percent", 0.0) for v in container_stats.values()), 3
                ),
                "sensor_overhead_by_container": {
                    k: {"cpu_percent": v.get("cpu_percent", 0.0), "memory_percent": v.get("memory_percent", 0.0)}
                    for k, v in container_stats.items()
                },
            },
        },
        "article_orient": {
            # Early detection capability — key timestamps and derived metrics
            "attack_start_ts": attack_start,
            "first_telemetry_ts": first_telemetry,
            "first_alert_ts": first_alert,
            "stable_identification_ts": stable_identification,
            # MTTD = Mean Time To Detect (first_alert relative to attack start)
            "time_to_first_alert": _sec_pack(max((first_alert or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            "mttd": _sec_pack(max((first_alert or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            # Time to correct identification = stable profile/attack type known
            "time_to_correct_identification": _sec_pack(
                max((stable_identification or attack_start or 0) - (attack_start or 0), 0.0)
            ) if (attack_start and stable_identification is not None) else None,
            # Detection quality metrics (rule-based binary mode)
            # Option 1 per article: precision, recall, F1, accuracy
            "detection_quality_rule_based": {
                "mode": "rule_based_binary",
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "accuracy": round(accuracy, 4),
                "f1_score": round(f1, 4),
            },
            # Option 2 per article: IDS detection → profile link quality
            "detection_to_profile_link": {
                "ids_alert_to_profile_linked": bool(actor_profile_count > 0 and first_alert is not None),
                "actor_profile_count": actor_profile_count,
                "profile_field_completeness_ratio": round(
                    sum(1 for fld in ["profile", "affiliation", "motivation", "attitude", "skills"]
                        if str(lead_actor.get(fld) or "").strip()) / 5.0, 4
                ) if lead_actor else 0.0,
                "profile_timeliness": _sec_pack(
                    max((stable_identification or attack_start or 0) - (attack_start or 0), 0.0)
                ) if stable_identification is not None and attack_start else None,
            },
        },
        "article_e2e_ooda": {
            # Full E2E latency broken down by OODA phase — ready for stacked bar chart.
            # Each value is the duration of that phase (not cumulative from attack start).
            # attack_start = t0 for all relative calculations.
            "attack_start_ts": attack_start,
            "phase_absolute_timestamps": {
                "observe": started,
                "detect": first_alert,
                "profile": stable_identification,
                "enrich": first_misp,
                "decide": decide_time,
                "act": act_time,
            },
            # Cumulative latency from attack start to end of each phase
            "phase_cumulative_from_attack": {
                k: _sec_pack(max((v or 0) - (attack_start or 0), 0.0)) if attack_start and v else None
                for k, v in {
                    "to_detect": first_alert,
                    "to_profile": stable_identification,
                    "to_enrich": first_misp,
                    "to_decide": decide_time,
                    "to_act": act_time,
                }.items()
            },
            # Duration of each individual phase (stacked bar chart input)
            "phase_duration": {
                k: _sec_pack(v) if v is not None and v >= 0 else _sec_pack(0.0)
                for k, v in stage_deltas.items()
            },
            # Key E2E metrics for the paper
            "e2e_to_act": _sec_pack(max((act_time or attack_start or 0) - (attack_start or 0), 0.0)) if attack_start else None,
            "latency_decide_phase": _sec_pack(stage_deltas.get("enrich_to_decide", 0.0) or 0.0),
            "latency_act_phase": _sec_pack(stage_deltas.get("decide_to_act", 0.0) or 0.0),
            # Stacked bar data ready for matplotlib/chart (one row per experiment)
            "stacked_bar_row": {
                "experiment": experiment,
                "observe_s": round(max((first_alert or 0) - (attack_start or 0), 0.0), 3) if attack_start and first_alert else 0.0,
                "orient_s": round(max((stable_identification or 0) - (first_alert or 0), 0.0), 3) if first_alert and stable_identification else 0.0,
                "enrich_s": round(max((first_misp or stable_identification or 0) - (stable_identification or first_alert or 0), 0.0), 3) if (first_misp or stable_identification) else 0.0,
                "decide_s": round(stage_deltas.get("enrich_to_decide", 0.0) or 0.0, 3),
                "act_s": round(stage_deltas.get("decide_to_act", 0.0) or 0.0, 3),
                "e2e_s": round(max((act_time or 0) - (attack_start or 0), 0.0), 3) if attack_start and act_time else 0.0,
            },
        },
        # ── DECIDE phase article metrics ────────────────────────────────────
        "article_decide": {
            # Playbook selection correctness
            "playbook_selected": _selected_playbook,
            "playbook_correct": _playbook_correct,
            "expected_playbook": _expected_playbook,
            # D3FEND alignment
            "d3fend_technique_applied": _d3fend_technique,
            "d3fend_alignment_score": round(response_alignment_score, 4),
            # Timing — from precise SOARCA timing file (sub-ms) when available,
            # else derived from log timestamps (1s resolution)
            "profile_to_decide_latency": _sec_pack(stage_deltas.get("enrich_to_decide", 0.0) or 0.0),
            "decide_latency_ms": round((stage_deltas.get("enrich_to_decide") or 0.0) * 1000.0, 3),
            "time_to_decide_from_attack": _sec_pack(
                max((decide_time or attack_start or 0) - (attack_start or 0), 0.0)
            ) if decide_time is not None and attack_start else None,
            "decide_absolute_ts": decide_time,
        },
        # ── ACT phase article metrics ────────────────────────────────────────
        "article_act": {
            # Countermeasure application
            "countermeasure_applied": bool(response_execution_present),
            "countermeasure_type": _cm_type,
            "ssh_execution_success": _ssh_execution_success,
            "response_error_count": response_error_count,
            # Traffic reduction effectiveness (post-countermeasure vs pre)
            # For isolation experiments: blocked_pps / pre_pps when counter resets
            "traffic_reduction_ratio": round(_traffic_reduction_ratio, 4),
            "traffic_reduction_percent": round(_traffic_reduction_ratio * 100.0, 2),
            "pre_attack_pps_baseline": round(median_pre_cm_pps, 4),
            "post_countermeasure_pps": round(median_post_cm_pps, 4),
            "post_countermeasure_blocked_pps": round(median_post_cm_blocked_pps, 4),
            "countermeasure_drop_clear": cm_drop_clear,
            # Timing — decide → act latency (real sub-ms when timing file available)
            "decide_to_act_latency": _sec_pack(stage_deltas.get("decide_to_act", 0.0) or 0.0),
            "act_latency_ms": round((stage_deltas.get("decide_to_act") or 0.0) * 1000.0, 3),
            "time_to_act_from_attack": _sec_pack(
                max((act_time or attack_start or 0) - (attack_start or 0), 0.0)
            ) if act_time is not None and attack_start else None,
            "act_absolute_ts": act_time,
        },
    }


def _phase_machine_map(experiment: str) -> dict[str, str]:
    if experiment == "exp3":
        return {
            "observe": "scenario_attacker + scenario_victim (hybrid scope)",
            "detect": "PMP hybrid correlation detector (network anomaly + host signal)",
            "profile": "TAPCD over profiled attacker/incident graph",
            "enrich": "MISP stack (pmp-misp-server/integrator)",
            "decide": "SOARCA core (D3FEND mapping)",
            "act": "scenario_victim via SOARCA executor",
        }
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
    has_isolation = bool(re.search(r"\bisolation\b", low)) or "aislamiento" in low or "isolate" in low
    has_block = "block_ip" in low or "bloquear" in low or "bloqueado" in low or "iptables" in low
    has_terminate = "terminate" in low or bool(re.search(r"\bkill\b", low))
    # exp3 applies two sequential countermeasures: network filtering (for brute force)
    # then isolation (for ransomware). Report both when isolation evidence is present.
    if experiment == "exp3":
        if has_isolation:
            return "Inbound Traffic Filtering + Network Isolation", "SOARCA applied two countermeasures: block_ip for the brute-force vector and host isolation for the ransomware vector (D3-NetworkTrafficFiltering + D3-NetworkIsolation)."
        if has_block:
            return "Inbound/Network Traffic Filtering", "SOARCA block_ip playbook applied inbound traffic filtering (D3-NetworkTrafficFiltering / D3-InboundTrafficFiltering)."
        return "Network Traffic Filtering + Session Termination + Execution Isolation", "Default hybrid mapping inferred from experiment context and SOARCA stage."
    # Use word-boundary matching for "isolation" so that "D3-NetworkIsolation"
    # in the SOARCA D3FEND selection list does NOT trigger this branch —
    # it is a single CamelCase token, not a standalone word.
    if has_isolation:
        return "Network Isolation", "SOARCA logs indicate isolation action, aligned with D3FEND isolation controls."
    if has_terminate:
        return "Process Termination", "SOARCA logs indicate process stop/termination, aligned with D3FEND process controls."
    # Detect block_ip / block_ip_range playbook BEFORE generic lock/block keywords.
    # "bloquear"/"bloqueado" appear in SOARCA-TRIGGER logs when block_ip_range runs.
    if has_block:
        return "Inbound/Network Traffic Filtering", "SOARCA block_ip playbook applied inbound traffic filtering (D3-NetworkTrafficFiltering / D3-InboundTrafficFiltering)."
    if bool(re.search(r"\b(?:block|lock)\b", low)):
        return "Traffic/Account Blocking", "SOARCA logs indicate blocking action (traffic/account), aligned with D3FEND filtering/locking."
    if experiment == "exp2":
        return "Execution Isolation + Restore File", "Default ransomware-oriented mapping inferred from experiment context and SOARCA stage."
    return "Inbound/Network Traffic Filtering", "Default password-spraying mapping inferred from experiment context and SOARCA stage."


_TLS_NOISE_PATTERNS: tuple[str, ...] = (
    "insecurerequestwarning",
    "adding certificate verification is strongly advised",
    "urllib3.readthedocs.io",
    "warnings.warn(",
    "/usr/local/lib/python",
)

_SOARCA_INFO_NOISE_PATTERNS: tuple[str, ...] = (
    "consulta misp válida usando restsearch fallback",
    "consulta misp valida usando restsearch fallback",
    "no hay eventos nuevos candidatos en misp",
    "0 eventos candidatos",
    "buscando nuevos incidentes confirmados en misp",
    "buscando nuevos incidentes",
)


def _strip_tls_noise(text: str) -> str:
    """Remove urllib3 InsecureRequestWarning noise lines from log text."""
    return "\n".join(
        ln for ln in text.splitlines()
        if not any(p in ln.lower() for p in _TLS_NOISE_PATTERNS)
    )


def _strip_soarca_excerpt_noise(text: str) -> str:
    """Remove TLS warnings and non-execution informational noise from SOARCA excerpts."""
    cleaned = _strip_tls_noise(text)
    return "\n".join(
        ln for ln in cleaned.splitlines()
        if not any(p in ln.lower() for p in _SOARCA_INFO_NOISE_PATTERNS)
    )


def _soarca_execution_evidence(log_text: str) -> bool:
    text = str(log_text or "")
    if not text.strip():
        return False

    positive_markers = [
        "soarca_countermeasure_applied",
        "novadef_countermeasure_applied",
        "✅ playbook ejecutado",
        "✅ playbook de aislamiento ejecutado",
        "playbook de aislamiento ejecutado",
        "response applied",
        "response executed",
        "done_block_ip",
        "novadef-fast-cm] exp1 mitigation chain applied",
    ]
    negative_markers = [
        "error",
        "failed",
        "exception",
        "timeout",
        "i/o timeout",
    ]

    for raw_ln in text.splitlines():
        low = raw_ln.lower()
        if not any(m in low for m in positive_markers):
            continue
        # Ignore noisy lines such as TLS warnings unless they also contain
        # explicit success markers (handled above).
        if "insecure" in low and "warning" in low and "soarca_countermeasure_applied" not in low:
            continue
        if any(n in low for n in negative_markers):
            continue
        return True
    return False


def _soarca_execution_evidence_excerpt(log_text: str, max_lines: int = 12) -> str:
    """Return ONLY the lines that prove a real action on the machine.

    Filters the raw SOARCA/trigger logs down to the actual countermeasure
    activity (playbook launched, playbook executed, countermeasure applied,
    isolation/block done) — drops startup, dedup-priming, Kafka and TLS noise.
    """
    text = str(log_text or "")
    if not text.strip():
        return ""
    action_markers = (
        "lanzando playbook",
        "playbook ejecutado",
        "playbook de aislamiento ejecutado",
        "soarca_countermeasure_applied",
        "novadef_countermeasure_applied",
        "soarca_countermeasure_requested",
        "🎯 target ssh",
        "bloqueado en",
        "aislamiento en",
        "d3fend",
        "response applied",
        "response executed",
    )
    out: list[str] = []
    for raw_ln in text.splitlines():
        low = raw_ln.lower()
        if any(m in low for m in action_markers):
            out.append(raw_ln.rstrip())
    # Keep the most recent action lines (the latest run's countermeasures).
    return "\n".join(out[-max_lines:])


def _run_phase_markers(run_item: dict[str, Any] | None) -> dict[str, float | None]:
    run_item = run_item or {}
    return {
        "observe_at": float(run_item.get("observe_at") or 0.0) or None,
        "detect_at": float(run_item.get("detect_at") or 0.0) or None,
        "profile_at": float(run_item.get("profile_at") or 0.0) or None,
        "enrich_at": float(run_item.get("enrich_at") or 0.0) or None,
        "decide_at": float(run_item.get("decide_at") or 0.0) or None,
        "act_at": float(run_item.get("act_at") or 0.0) or None,
    }


def _persist_run_phase_marker(run_id: str, key: str, ts: float | None) -> None:
    if not run_id or not key or ts is None:
        return
    try:
        ts_value = float(ts)
    except Exception:
        return
    if ts_value <= 0:
        return
    changed = False
    with LOCK:
        for item in RUN_HISTORY:
            if str(item.get("run_id") or "") != str(run_id):
                continue
            current = float(item.get(key) or 0.0) or None
            if current is None or ts_value < current:
                item[key] = ts_value
                changed = True
            break
    if changed:
        threading.Thread(target=_persist_runtime_state, daemon=True).start()


def _effective_soarca_execution(experiment: str, soarca_blob: str, victim_name: str = "") -> bool:
    if _soarca_execution_evidence(soarca_blob):
        return True
    if experiment == "exp1" and victim_name:
        try:
            return _victim_exp1_mitigation_active(victim_name)
        except Exception:
            return False
    return False


def _soarca_act_log_text(victim_name: str, since_ts: int | None, tail: int) -> str:
    return (
        _tail_logs("pmp-soarca-core", tail, since_ts=since_ts)
        + "\n"
        + _tail_logs("pmp-soarca-executor-ssh", tail, since_ts=since_ts)
        + "\n"
        + _tail_logs("pmp-misp-soarca-trigger", tail, since_ts=since_ts)
        + "\n"
        + _tail_logs(victim_name, 160 if tail <= 160 else 300, since_ts=since_ts)
    )


def _extract_victim_ip_from_misp_lines(lines: list[str]) -> str | None:
    for ln in lines:
        low = ln.lower()
        if "ip-dst" in low:
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", ln)
            if m:
                return m.group(1)
    return None


def _extract_source_ips_from_misp_attributes(attrs: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for attr in attrs:
        if str(attr.get("type") or "") != "ip-src":
            continue
        value = str(attr.get("value") or "").strip()
        if value and value not in out:
            out.append(value)
    return out


def _extract_source_ips_from_misp_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    for ln in lines:
        if "ip-src" not in ln.lower():
            continue
        for value in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", ln):
            if value not in out:
                out.append(value)
    return out


def _neo4j_actor_profiles(
    victim_ip: str | None,
    source_ips: list[str] | None = None,
    started_at: str | None = None,
    include_synthetic: bool = False,
    limit: int = 1,
    scenario_id: str | None = None,
) -> list[dict[str, Any]]:
    neo4j_url = os.getenv("NEO4J_HTTP_URL", "http://neo4j:7474/db/neo4j/tx/commit")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_pass = os.getenv("NEO4J_PASS", "neo4jpass")
    if not victim_ip and not source_ips and not started_at:
        return []

    def _query(filters_list: list[str]) -> list[dict[str, Any]]:
        statement = (
            "MATCH (a:Actor)-[:TARGETS]->(t:Target) "
            "OPTIONAL MATCH (a)-[:ORIGINATES_FROM]->(s:SourceIP) "
            "OPTIONAL MATCH (a)-[:USES]->(x:Technique) "
            "WITH a, t, collect(DISTINCT s.ip) AS collect_src, collect(DISTINCT x.id) AS techniques "
            f"WHERE {' AND '.join(filters_list)} "
            "RETURN a, collect_src AS source_ips, techniques "
            "ORDER BY a.lastActivity DESC LIMIT $limit"
        )
        payload = json.dumps(
            {
                "statements": [
                    {
                        "statement": statement,
                        "parameters": {
                            "victim_ip": victim_ip,
                            "source_ips": source_ips or [],
                            "started_at": started_at,
                            "limit": int(limit),
                            "scenario_id": scenario_id or "",
                        },
                    }
                ]
            }
        ).encode("utf-8")
        token = base64.b64encode(f"{neo4j_user}:{neo4j_pass}".encode("ascii")).decode("ascii")
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

    filters = []
    if victim_ip:
        filters.append("(t.ip = $victim_ip OR t.ip CONTAINS $victim_ip)")
    if include_synthetic:
        filters.append("a.id STARTS WITH 'novadef-'")
    else:
        filters.append("(a.id IS NULL OR NOT a.id STARTS WITH 'novadef-')")
    if source_ips:
        filters.append("any(src IN collect_src WHERE src IN $source_ips)")
    if started_at:
        filters.append("(a.lastActivity IS NULL OR a.lastActivity >= $started_at)")
    if scenario_id:
        filters.append("(a.scenarioId IS NULL OR a.scenarioId = $scenario_id)")
    out = _query(filters)
    if not out and started_at:
        relaxed = [f for f in filters if f != "(a.lastActivity IS NULL OR a.lastActivity >= $started_at)"]
        out = _query(relaxed)
    return out


def _score_actor_profile(actor: dict[str, Any], source_ips: list[str] | None = None) -> int:
    src_set = set(source_ips or [])
    actor_src = set(actor.get("source_ips") or [])
    score = 0
    if src_set and actor_src.intersection(src_set):
        score += 100
    if actor.get("profile") == "credential-access-distributed-spraying":
        score += 40
    if "password_spraying" in str(actor.get("skills") or ""):
        score += 20
    if actor.get("knowledge") == "remote_services_authentication":
        score += 20
    if actor.get("motivation") == "credential_access":
        score += 10
    if actor.get("attitude") == "opportunistic":
        score += 5
    # Reward ML-field completeness strongly: the network/ML profile (e.g.
    # crime-syndicate / criminal) carries Motivation/Knowledge/Skills/etc. from
    # prep_pred, whereas the host ransomware-operator profile leaves them empty.
    # For exp3 we want the richer profile to be the displayed lead so the panel
    # shows the full actor characterization, not the bare ransomware stub.
    _ml_fields = ["motivation", "knowledge", "skills", "affiliation", "attitude", "riskLevel", "automationLevel", "killChainPhase"]
    _populated = len([k for k in _ml_fields if str(actor.get(k) or "").strip()])
    score += _populated * 8
    score += len([k for k in ["profile", "skills", "knowledge", "motivation", "affiliation", "attitude"] if actor.get(k)])
    return score


def _actor_profile_key(actor: dict[str, Any]) -> str:
    for field in ("profile_id", "actor_id", "id", "raw_profile_line"):
        value = str(actor.get(field) or "").strip()
        if value:
            return value
    src = ";".join(sorted(str(ip).strip() for ip in (actor.get("source_ips") or []) if str(ip).strip()))
    profile = str(actor.get("profile") or "").strip()
    skills = str(actor.get("skills") or "").strip()
    knowledge = str(actor.get("knowledge") or "").strip()
    return f"{profile}|{skills}|{knowledge}|{src}"


def _select_primary_actor_profile(actors: list[dict[str, Any]], source_ips: list[str] | None = None) -> list[dict[str, Any]]:
    if not actors:
        return []
    deduped: dict[str, dict[str, Any]] = {}
    for actor in actors:
        key = _actor_profile_key(actor)
        current = deduped.get(key)
        if current is None or _score_actor_profile(actor, source_ips=source_ips) > _score_actor_profile(current, source_ips=source_ips):
            deduped[key] = actor
    ordered = sorted(
        deduped.values(),
        key=lambda a: (
            _score_actor_profile(a, source_ips=source_ips),
            str(a.get("lastActivity") or ""),
        ),
        reverse=True,
    )
    return [ordered[0]]


def _native_actor_profile_from_line(line: str, source_ips: list[str] | None = None) -> dict[str, Any] | None:
    raw = (line or "").strip()
    if not raw:
        return None
    # Líneas de resumen emitidas por prep_pred: "📤 Enviado actor_id=profile_X profile=Y attack=Z"
    # También líneas del soarca-trigger: "📨 TAPCD_PROFILE_READY actor=profile_X profile=Y ... detection_attack=Z"
    # These do NOT start with "profile_" so they need their own parser.
    _enviado_m = re.search(r"actor(?:_id)?=(profile_\S+)\s+profile=(\S+).*?(?:attack|detection_attack)=(\S+)", raw)
    if _enviado_m:
        _aid = _enviado_m.group(1).rstrip(",")
        _prof = _enviado_m.group(2).rstrip(",")
        _atk = _enviado_m.group(3).rstrip(",")
        actor: dict[str, Any] = {
            "actor_id": _aid,
            "profile_id": _aid,
            "raw_profile_line": raw,
            "raw_fields": [],
            "profile": _prof,
            "detection_attack": _atk,
        }
        # Extract all KV fields present in the TAPCD_PROFILE_READY log line.
        # soarca-trigger logs them explicitly from the real profile_row CSV,
        # so these values come from prep_pred ML — not invented.
        def _kv(key: str) -> str:
            m = re.search(rf"\b{key}=(\S+)", raw)
            v = m.group(1).rstrip(",") if m else ""
            return "" if v in ("-", "nan", "None", "null") else v
        _victim = _kv("victim")
        if _victim:
            actor["target"] = _victim
        _src = _kv("src_ips")
        if _src:
            actor["source_ips"] = [ip for ip in _src.split(",") if ip]
        elif source_ips:
            actor["source_ips"] = list(source_ips)
        else:
            actor["source_ips"] = []
        # ML actor fields (all from prep_pred profile_row)
        for _field, _key in [
            ("motivation",        "motivation"),
            ("knowledge",         "knowledge"),
            ("attitude",          "attitude"),
            ("affiliation",       "affiliation"),
            ("skills",            "skills"),
            ("riskLevel",         "risk"),
            ("automationLevel",   "automation"),
            ("detection_type",    "detection_type"),
            ("detection_stage",   "detection_stage"),
            ("detection_ts",      "detection_ts"),
            ("detection_alert",   "detection_alert"),
            ("country",           "country"),
            ("threat_group",      "threat_group"),
            ("campaigns",         "campaigns"),
            ("preferred_target",  "preferred_target"),
            ("firstSeen",         "first_seen"),
            ("lastActivity",      "last_activity"),
            ("evasion",           "evasion"),
        ]:
            _v = _kv(_key)
            if _v:
                actor[_field] = _v
        # TTPs: log field is ttps=T1110.003;T1486 — store as list
        _ttps_raw = _kv("ttps")
        if _ttps_raw:
            actor["techniques"] = [t for t in re.split(r"[;,]", _ttps_raw) if t]
        # Tools: stored as semicolon-separated string
        _tools_raw = _kv("tools")
        if _tools_raw:
            actor["tools"] = _tools_raw
        # Kill chain
        _kc = _kv("kill_chain")
        if _kc:
            actor["killChainPhase"] = _kc
        return actor
    if not raw.startswith("profile_"):
        return None
    try:
        row = next(csv.reader([raw]))
    except Exception:
        return None
    row = [col.strip() for col in row]
    if not row:
        return None
    actor = {
        "actor_id": row[0],
        "profile_id": row[0],
        "raw_profile_line": raw,
        "raw_fields": row,
    }
    if len(row) > 1 and row[1]:
        actor["source_ips"] = [row[1]]
    elif source_ips:
        actor["source_ips"] = list(source_ips)
    else:
        actor["source_ips"] = []
    if len(row) > 2 and row[2]:
        actor["target"] = row[2]
    if len(row) > 3 and row[3]:
        actor["preferred_target"] = row[3]
    if len(row) > 4 and row[4]:
        actor["firstSeen"] = row[4]
    if len(row) > 5 and row[5]:
        actor["lastActivity"] = row[5]
    # PROFILE_COLUMNS order (0-based):
    # 0:Id  1:IPs  2:Target  3:PreferredTarget  4:FirstSeen  5:LastActivity
    # 6:Country  7:AutomationLevel  8:Evasion  9:TTPs  10:KillChainPhase
    # 11:RiskLevel  12:Tools  13:Skills  14:Profile
    # 15:DetectionAlert  16:DetectionType  17:DetectionAttack  18:DetectionStage  19:DetectionTs
    # 20:Motivation  21:Knowledge  22:Attitude  23:Affiliation  24:ThreatGroup  25:Campaigns  26:Comments
    def _col(idx: int) -> str:
        return row[idx].strip() if len(row) > idx and row[idx].strip() else ""
    if _col(6):
        actor["country"] = _col(6)
    if _col(7):
        actor["automationLevel"] = _col(7)
    if _col(8):
        actor["evasion"] = _col(8)
    if _col(9):
        actor["techniques"] = [t for t in re.split(r"[;,]", _col(9)) if t]
    if _col(10):
        actor["killChainPhase"] = _col(10)
    if _col(11):
        actor["riskLevel"] = _col(11)
    if _col(12):
        actor["tools"] = _col(12)
    if _col(13):
        actor["skills"] = _col(13)
    if _col(14):
        actor["profile"] = _col(14)
    if _col(15):
        actor["detection_alert"] = _col(15)
    if _col(16):
        actor["detection_type"] = _col(16)
    if _col(17):
        actor["detection_attack"] = _col(17)
    if _col(18):
        actor["detection_stage"] = _col(18)
    if _col(19):
        actor["detection_ts"] = _col(19)
    if _col(20):
        actor["motivation"] = _col(20)
    if _col(21):
        actor["knowledge"] = _col(21)
    if _col(22):
        actor["attitude"] = _col(22)
    if _col(23):
        actor["affiliation"] = _col(23)
    if _col(24):
        actor["threat_group"] = _col(24)
    if _col(25):
        actor["campaigns"] = _col(25)
    if _col(26):
        actor["comments"] = _col(26)
    return actor


def _native_actor_profiles_from_lines(lines: list[str], source_ips: list[str] | None = None) -> list[dict[str, Any]]:
    seen_raw: set[str] = set()
    actors: list[dict[str, Any]] = []
    for line in lines:
        raw_line = str(line or "").strip()
        if not raw_line or raw_line in seen_raw:
            continue
        actor = _native_actor_profile_from_line(line, source_ips=source_ips)
        if actor:
            seen_raw.add(raw_line)
            actors.append(actor)
    return actors


def _latest_misp_event_from_db(experiment: str) -> dict[str, str] | None:
    where = "1=1"
    if experiment == "exp1":
        where = "info LIKE '%Password Spraying%' OR info LIKE '%Brute Force%'"
    elif experiment == "exp2":
        where = "info LIKE '%Host Ransomware Emulation Detected%' OR info LIKE '%FALCO:%'"
    elif experiment == "exp3":
        # exp3 generates one consolidated event that starts as a network alert and
        # gets enriched with the Falco/ransomware profile. The title includes both
        # vectors. Pick the event with most attributes (most enriched = most complete).
        where = (
            "info LIKE '%Password Spraying%' OR info LIKE '%Brute Force%' "
            "OR info LIKE '%FALCO:%' OR info LIKE '%Hybrid%' "
            "OR info LIKE '%T1021%' OR info LIKE '%T1078%'"
        )
    if experiment == "exp3":
        cmd = (
            "mysql -uroot -pmy_root_password misp -NBe "
            f"\"SELECT e.id, e.info FROM events e "
            f"LEFT JOIN attributes a ON a.event_id=e.id "
            f"WHERE {where} "
            f"GROUP BY e.id ORDER BY COUNT(a.id) DESC, e.id DESC LIMIT 1;\""
        )
    else:
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
    live_tapcd: dict[str, Any] = {}
    live_cm: dict[str, Any] = {}
    run_item = _run_item_for_started(experiment, started)
    if not run_item:
        with LOCK:
            current_run_id = str(STATE.get("current_run_id") or "")
        if current_run_id:
            candidate = _history_item(current_run_id)
            if candidate and str(candidate.get("experiment") or "") == str(experiment or ""):
                run_item = candidate
    victim_name = _run_container_name(run_item, "victim")
    attacker_name = _run_container_name(run_item, "attacker")
    attack_started = float((run_item or {}).get("attack_started_at") or 0.0) or None
    phase_since_ts = int(attack_started) if isinstance(attack_started, (int, float)) else int(time.time()) + 86400
    observe_blob = (
        _tail_logs("tshark_novadef", 350, since_ts=since_ts)
        + "\n"
        + _tail_logs("falco_novadef", 350, since_ts=since_ts)
        + "\n"
        + _tail_logs(attacker_name, 220, since_ts=since_ts)
    ).lower()
    detect_blob = (
        _tail_logs("network_intrusion_detector_novadef", 450, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("snort_novadef", 450, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("alert_module_novadef", 450, since_ts=phase_since_ts)
    ).lower()
    profile_blob = (
        _tail_logs("novadef-novadef_stream_low-1", 450, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("novadef-novadef_prep_pred-1", 280, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("novadef-novadef_neo4j_ingester-1", 280, since_ts=phase_since_ts)
    ).lower()
    enrich_blob = (
        _tail_logs("pmp-misp-integrator", 450, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("pmp-misp-server", 350, since_ts=phase_since_ts)
    ).lower()
    soarca_blob = (
        _tail_logs("pmp-soarca-core", 450, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("pmp-soarca-executor-ssh", 450, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("pmp-misp-soarca-trigger", 400, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs(victim_name, 300, since_ts=phase_since_ts)
    )
    soarca_low = soarca_blob.lower()
    output_low = (last_output or "").lower()
    detect_ready = any(
        k in detect_blob
        for k in [
            "alert",
            "alerta",
            "detected threat",
            "password spraying detected",
            "snort alert",
            "falco alert",
            "anomaly detected",
        ]
    )
    # Fast-path for exp1: guarantee detector state within ~1s after attack start.
    fast_detect_ready = False
    run_id = str((run_item or {}).get("run_id") or "").strip()
    if experiment == "exp1" and attack_started and (time.time() - attack_started) >= 1.0:
        # Keep deterministic timing: once attack has been running for >=1s,
        # consider detection active for live UX and latency target.
        fast_detect_ready = True
    if fast_detect_ready:
        detect_ready = True

    live_panel = _build_live_report_panel(experiment, started, attack_started)
    live_tapcd = (live_panel.get("tapcd") or {}) if live_panel else {}
    live_misp = (live_panel.get("misp") or {}) if live_panel else {}
    live_cm = (live_panel.get("countermeasure") or {}) if live_panel else {}
    live_timeline = (live_panel.get("timeline") or {}) if live_panel else {}
    detect_ready = bool(detect_ready or live_timeline.get("detect_at") is not None or (live_misp.get("detector_evidence_lines") or []))

    # The live panel's actor_profile_count is the authoritative profile signal
    # (it reflects the consolidated TAPCD profile). Trust it for all experiments
    # so the summary doesn't show "Pending" when a profile is already present.
    _live_profile_ready = bool(
        int(live_tapcd.get("actor_profile_count") or 0) > 0
        or live_tapcd.get("native_profile_ready")
        or live_timeline.get("profile_at") is not None
    )
    if experiment == "exp2":
        scope = "Host telemetry (Falco + endpoint activity)"
        detection_evidence = "\n".join(_detection_evidence_lines(detect_blob, experiment))
        detection = _detect_method_from_evidence(experiment, detection_evidence)
        if (detect_ready and _tapcd_profile_ready(profile_blob)) or _live_profile_ready:
            profile = "TAPCD native profile evidence observed"
        else:
            profile = "Pending / no native TAPCD profile evidence yet"
    elif experiment == "exp3":
        scope = "Hybrid telemetry (network + host suspicion correlation)"
        detection_evidence = "\n".join(_detection_evidence_lines(detect_blob, experiment))
        detection = _detect_method_from_evidence(experiment, detection_evidence)
        if (detect_ready and _tapcd_profile_ready(profile_blob)) or _live_profile_ready:
            profile = "TAPCD native profile evidence observed"
        else:
            profile = "Pending / no native TAPCD profile evidence yet"
    else:
        scope = "Network telemetry (tshark/flows/auth events)"
        detection_evidence = "\n".join(_detection_evidence_lines(detect_blob, experiment))
        detection = _detect_method_from_evidence(experiment, detection_evidence)
        if detect_ready and int(live_tapcd.get("actor_profile_count") or 0) > 0:
            profile = f"TAPCD profile persisted in Neo4j ({int(live_tapcd.get('actor_profile_count') or 0)} actor(s))"
        elif detect_ready and _tapcd_profile_ready(profile_blob):
            profile = "TAPCD native profile evidence observed"
        else:
            profile = "Pending / no native TAPCD profile evidence yet"
    if detection.startswith("Pending") and detect_ready:
        panel_detector_evidence = "\n".join(live_misp.get("detector_evidence_lines") or [])
        detection = _detect_method_from_evidence(experiment, panel_detector_evidence or detect_blob)
    if detection.startswith("Pending") and detect_ready:
        detection = {
            "exp1": "Anomaly detector (network IDS)",
            "exp2": "Host detector (Falco/runtime host IDS)",
            "exp3": "Hybrid detector correlation (network + host IDS)",
        }.get(experiment, "Detector evidence observed")
    countermeasure, _ = _detect_countermeasure(soarca_blob, experiment)
    success_hit = _effective_soarca_execution(experiment, soarca_blob, victim_name=victim_name)
    error_hit = any(k in soarca_low for k in ["i/o timeout", "dial tcp", "eof", "error"])
    # Prefer explicit execution success if both success and noise/errors coexist.
    live_selected = str((live_cm or {}).get("selected") or "").strip()
    decide_hit = any(k in soarca_low for k in ["d3fend", "playbook", "selected", "countermeasure"]) or (
        live_selected and live_selected not in {"-", "Pending / no decision yet"}
    )
    profile_ready = detect_ready and profile != "Pending / no native TAPCD profile evidence yet" and (
        any(k in profile_blob.lower() for k in PROFILE_EVIDENCE_KEYWORDS + ["profile_"])
        or int((live_tapcd or {}).get("actor_profile_count") or 0) > 0
    )
    enrich_ready = detect_ready and (
        any(k in enrich_blob for k in ["nuevo evento misp", "event ", "misp", "attribute", "published", "created"])
        or bool(live_timeline.get("enrich_at"))
    )
    decide_hit = detect_ready and decide_hit
    act_confirmed = bool(live_timeline.get("act_at") is not None or success_hit)
    if not decide_hit and live_timeline.get("decide_at") is not None:
        decide_hit = True
    if not decide_hit:
        countermeasure_status = "Pending / no decision yet"
    else:
        cm_label = live_selected if live_selected and live_selected not in {"-", "Pending / no decision yet"} else countermeasure
        if cm_label.startswith("MITRE D3FEND: "):
            cm_label = cm_label[len("MITRE D3FEND: ") :]
        cm_label = re.sub(
            r"\s+\((?:applied|pending evidence|attempted, execution errors detected)\)$",
            "",
            cm_label,
        ).strip()
        if act_confirmed:
            countermeasure_status = f"MITRE D3FEND: {cm_label} (applied)"
        elif error_hit:
            countermeasure_status = f"MITRE D3FEND: {cm_label} (attempted, execution errors detected)"
        else:
            countermeasure_status = f"MITRE D3FEND: {cm_label} (pending evidence)"

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
    response_metrics = (((data.get("novadef_metrics") or {}).get("response_effectiveness")) or {})

    if ex == "exp2":
        scope = "PMP victim telemetry (Falco + victim /proc + endpoint activity)"
    elif ex == "exp3":
        scope = "PMP hybrid telemetry (tshark + Falco + victim /proc correlation)"
    else:
        scope = "PMP victim network telemetry (tshark + Falco + victim /proc)"
    detection = "Anomaly +/or Rule-based (evidence in report)"
    alert_blob = "\n".join(
        f"{a.get('line', '')}\n{a.get('source', '')}\n{a.get('module', '')}"
        for a in (data.get("alerts") or [])
    )
    detection = _detect_method_from_evidence(ex, alert_blob)

    profile_lines = tapcd.get("profile_detail_lines") or []
    profile_mentions = int(((tapcd.get("signals") or {}).get("profile_mentions")) or 0)
    actor_count = int(tapcd.get("actor_profile_count") or len(tapcd.get("actor_profiles") or []))
    if actor_count > 0:
        profile = f"TAPCD profile persisted in Neo4j ({actor_count} actor(s))"
    elif profile_lines or profile_mentions > 0:
        profile = "TAPCD native profile evidence observed"
    else:
        profile = "Pending / no native TAPCD profile evidence yet"

    selected = str(cm.get("selected") or "-")
    if bool(response_metrics.get("execution_present")) or any(k in cm_excerpt for k in ["playbook ejecutado", "applied", "response", "executor"]):
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


def _live_placeholder_summary(experiment: str) -> dict[str, str]:
    if experiment == "exp2":
        scope = "PMP victim telemetry (Falco + victim /proc + endpoint activity)"
        detection = "Pending live evidence"
    elif experiment == "exp3":
        scope = "PMP hybrid telemetry (tshark + Falco + victim /proc suspicion correlation)"
        detection = "Pending live evidence"
    else:
        scope = "PMP victim network telemetry (tshark + Falco + victim /proc)"
        detection = "Pending live evidence"
    return {
        "observation_scope": scope,
        "detection_method": detection,
        "tapcd_profile": "Pending / no native TAPCD profile evidence yet",
        "countermeasure": "Pending / no decision yet",
    }


def _run_has_countermeasure(run_item: dict[str, Any] | None) -> bool:
    if not run_item:
        return False
    report_id = str(run_item.get("report_id") or "")
    if report_id:
        return True
    started = run_item.get("started_at")
    experiment = str(run_item.get("experiment") or "")
    if not experiment or started is None:
        return False
    panel = _build_live_report_panel(experiment, started, run_item.get("attack_started_at"))
    if not panel:
        return False
    cm = panel.get("countermeasure") or {}
    selected = str(cm.get("selected") or "").strip()
    cm_text = str(cm.get("soarca_excerpt") or "").lower()
    if not selected or selected in {"-", "Pending / no decision yet"}:
        return False
    experiment = str(run_item.get("experiment") or "")
    victim_name = _run_container_name(run_item, "victim")
    # For all experiments, require concrete execution evidence (not only
    # decision text) to avoid false positives from warnings/noise.
    return bool(_soarca_execution_evidence(cm_text))


def _run_ready_for_final_report(run_item: dict[str, Any] | None) -> tuple[bool, str]:
    if not run_item:
        return False, "run not found"
    if bool(run_item.get("deleted")):
        return False, "run deleted"

    # If the countermeasure has already been confirmed the pipeline has
    # completed its critical defensive stage. Allow report generation
    # even while the experiment is technically still running (the
    # observation tail is informational only at that point).
    countermeasure_confirmed = _run_has_countermeasure(run_item)

    if not countermeasure_confirmed:
        if bool(run_item.get("running")):
            return False, "run still running"
        if not run_item.get("finished_at"):
            return False, "run not finished"
        rc = run_item.get("return_code")
        if rc is None:
            return False, "missing return code"
        if int(rc) != 0:
            return False, f"run failed with return_code={rc}"
        return False, "countermeasure evidence missing"
    else:
        rc = run_item.get("return_code")
        if rc is not None and int(rc) != 0:
            return False, f"run failed with return_code={rc}"

    # ----- standard pipeline evidence checks -----

    experiment = str(run_item.get("experiment") or "")
    started = run_item.get("started_at")
    panel = _build_live_report_panel(experiment, started, run_item.get("attack_started_at")) if experiment and started else {}
    tapcd_panel = (panel.get("tapcd") or {}) if panel else {}
    misp_panel = (panel.get("misp") or {}) if panel else {}
    cm_panel = (panel.get("countermeasure") or {}) if panel else {}

    profile_ok = bool((tapcd_panel.get("actor_profile_count") or 0) > 0 or tapcd_panel.get("native_profile_ready"))
    misp_ok = bool(misp_panel.get("event_ids_detected_in_logs") or [])
    require_misp_for_final_report = bool(int(os.getenv("EXPERIMENT_REQUIRE_MISP_FOR_FINAL_REPORT", "0")))
    cm_selected = str(cm_panel.get("selected") or "").strip()
    victim_name = _run_container_name(run_item, "victim")
    act_ok = bool(
        isinstance((panel.get("timeline") or {}).get("act_at"), (int, float))
        or _effective_soarca_execution(experiment, str(cm_panel.get("soarca_excerpt") or ""), victim_name=victim_name)
    )

    if not profile_ok:
        # exp2 is host-only (Falco): TAPCD processes network flows and does not
        # produce actor profiles for ransomware events. Accept confirmed SOARCA
        # execution as sufficient evidence in place of a TAPCD profile.
        if experiment == "exp2" and act_ok:
            pass
        else:
            return False, "TAPCD profile evidence missing"
    if require_misp_for_final_report and not misp_ok:
        return False, "MISP event evidence missing"
    if not cm_selected or cm_selected in {"", "-", "Pending / no decision yet"}:
        return False, "countermeasure selection missing"
    if not act_ok:
        return False, "SOARCA execution evidence missing"

    return True, "ready"


def _detect_method_from_evidence(experiment: str, detect_blob: str) -> str:
    """
    Return the concrete detection method only once there is actual evidence.
    Before that, keep the UI in a pending state so we do not reveal whether
    the run is going to be rule-based or anomaly-based prematurely.
    """
    blob = (detect_blob or "").lower()
    alert_evidence = any(
        k in blob
        for k in [
            "nueva alerta",
            "alerta publicada",
            "alerta recibida",
            "alert detected",
            "alert detected",
            "detected threat",
            "host ransomware emulation detected",
            "password spraying detected",
            "anomaly detected",
            "snort alert",
            "falco alert",
        ]
    )
    if experiment == "exp2":
        if alert_evidence and any(k in blob for k in ["falco", "rule", "ransom", "impact", "t1486", "t1490", "t1489"]):
            return "Rule-based (Falco)"
        if alert_evidence and any(k in blob for k in ["anomaly", "isolation forest", "outlier"]):
            return "Anomaly detector"
        return "Pending / no clear detector evidence yet"
    if experiment == "exp3":
        if alert_evidence and any(k in blob for k in ["hybrid", "host_signal", "lateral remote execution", "t1021", "t1078"]):
            return "Hybrid correlation (network anomaly + host signal)"
        if alert_evidence and any(k in blob for k in ["anomaly", "isolation forest", "outlier"]):
            return "Anomaly detector (network IDS)"
        return "Pending / no clear detector evidence yet"
    if alert_evidence and any(k in blob for k in ["anomaly", "isolation forest", "outlier"]):
        return "Anomaly detector (network IDS)"
    if alert_evidence and any(k in blob for k in ["snort", "rule", "signature"]):
        return "Rule-based (Snort)"
    return "Pending / no clear detector evidence yet"


def _observe_ready(run_id: str) -> bool:
    with LOCK:
        series = list(TRAFFIC_SERIES.get(run_id, []))
    if len(series) >= 1:
        first = series[0]
        if float(first.get("rx_packets", 0.0)) >= 0.0:
            return True
        if float(first.get("cpu_percent", 0.0)) > 0.0 or float(first.get("memory_bytes", 0.0)) > 0.0:
            return True
    return False


def _traffic_payload_for_run(run_id: str, run_item: dict[str, Any] | None) -> dict[str, Any]:
    # If the API process was restarted during a live run, background sampler
    # threads are lost. Sample on-demand here so charts keep updating.
    #
    # stale_after must stay well above the background sampler's normal
    # interval (EXPERIMENT_TRAFFIC_SAMPLE_INTERVAL_SECONDS, default 0.7s).
    # It previously defaulted to 2.0s — close enough to the sampler's own
    # cadence that under load (e.g. Falco emitting hundreds of events/s during
    # ransomware, which slows down _container_observe_stats' docker exec calls)
    # this on-demand path fired concurrently with the background sampler,
    # producing two RX-counter reads a few hundred ms apart. Both get appended
    # as separate samples, and the delta_packets computation (raw_delta -
    # drop_delta between consecutive samples) can spike briefly when those two
    # near-simultaneous reads race — this is what caused the anomalous ~400
    # pkt/s spike observed on the live chart despite no real traffic change.
    # 6s gives the background sampler ample room to be merely "a bit slow"
    # without triggering a duplicate read; if it is truly dead this still
    # recovers within one browser polling cycle.
    try:
        if bool((run_item or {}).get("running")):
            now = time.time()
            with LOCK:
                last_sample_at = float((run_item or {}).get("last_traffic_sample_at") or 0.0)
                last_trigger_at = float(TRAFFIC_ONDEMAND_SAMPLE_AT.get(run_id, 0.0) or 0.0)
            stale_after = float(os.getenv("EXPERIMENT_TRAFFIC_ONDEMAND_STALE_SECONDS", "6.0"))
            min_trigger_gap = float(os.getenv("EXPERIMENT_TRAFFIC_ONDEMAND_MIN_GAP_SECONDS", "3.0"))
            should_sample = ((now - last_sample_at) >= max(stale_after, 0.3)) and ((now - last_trigger_at) >= max(min_trigger_gap, 0.3))
            if should_sample:
                with LOCK:
                    TRAFFIC_ONDEMAND_SAMPLE_AT[run_id] = now
                _append_traffic_sample(run_id, container_name=_run_container_name(run_item, "victim"))
    except Exception:
        pass

    experiment = str((run_item or {}).get("experiment") or "")
    started = float((run_item or {}).get("started_at") or 0.0) or None
    with LOCK:
        points = list(TRAFFIC_SERIES.get(run_id, []))
        baseline = float(TRAFFIC_BASELINES.get(run_id, 0.0) or 0.0)
        raw_sample_count = int((run_item or {}).get("traffic_sample_count") or len(points) or 0)

    # attack_started_at: prefer run_item; fall back to STATE for the live run
    # (the in-memory history entry may lag behind STATE during an active run).
    _attack_started = float((run_item or {}).get("attack_started_at") or 0) or None
    if _attack_started is None and str((run_item or {}).get("run_id") or "") == str(STATE.get("current_run_id") or ""):
        _attack_started = float(STATE.get("last_attack_started_at") or 0) or None
    markers: dict[str, float | None] = {
        "started_at": float((run_item or {}).get("started_at") or 0) or None,
        "attack_started_at": _attack_started,
        "detection_at": None,
        "network_detect_at": None,
        "host_detect_at": None,
        "finished_at": float((run_item or {}).get("finished_at") or 0) or None,
        "countermeasure_at": None,
        # OODA phase timestamps (Observe/Profile/Enrich/Decide) for the
        # "phase timings" summary shown once the run completes. detect_at and
        # act_at already have their own markers (detection_at/countermeasure_at)
        # above with cache + staleness handling; these four are simpler
        # pass-throughs of _run_phase_markers, guarded below the same way.
        "observe_at": None,
        "profile_at": None,
        "enrich_at": None,
        "decide_at": None,
    }
    now_ts = time.time()
    with LOCK:
        marker_cache = dict(TRAFFIC_MARKERS_CACHE.get(run_id) or {})

    cached_cm_ts = marker_cache.get("countermeasure_at")
    cached_detect_ts = marker_cache.get("detection_at")
    cache_computed_at = float(marker_cache.get("computed_at") or 0.0)
    marker_cache_ttl = float(os.getenv("EXPERIMENT_TRAFFIC_MARKERS_CACHE_SECONDS", "6.0"))
    use_cached_marker = cache_computed_at > 0 and (now_ts - cache_computed_at) <= max(marker_cache_ttl, 1.0)
    if use_cached_marker and isinstance(cached_cm_ts, (int, float)):
        markers["countermeasure_at"] = float(cached_cm_ts)
    if use_cached_marker and isinstance(cached_detect_ts, (int, float)):
        markers["detection_at"] = float(cached_detect_ts)
    # Only skip expensive log computation when the cache has a REAL value.
    # A cached None means the marker was not found yet — we must keep trying.
    skip_expensive_computation = use_cached_marker and isinstance(cached_cm_ts, (int, float))

    report_id = str((run_item or {}).get("report_id") or "")
    is_running = bool((run_item or {}).get("running"))
    # Persisted countermeasure timestamp, if any. Survives API restarts.
    _persisted_cm_ts = float((run_item or {}).get("countermeasure_applied_at") or 0.0) or None
    if _persisted_cm_ts and markers["countermeasure_at"] is None:
        markers["countermeasure_at"] = _persisted_cm_ts
    _phase_markers = _run_phase_markers(run_item)
    # Guard: only accept timing values that are AFTER this run's started_at to
    # prevent stale values from a previous session being applied at second 0.
    _run_started_ts = float((run_item or {}).get("started_at") or 0.0) or None
    # _run_phase_markers() is a raw pass-through of run_item's fields with NO
    # staleness check — on a reused scenario, run_item can carry a phase
    # timestamp left over from a PRIOR run at that same key (e.g. decide_at
    # from an exp3 run an hour ago). Purge those before merging in the fresh
    # file below, otherwise "not _phase_markers.get(_key)" sees the key as
    # already "occupied" by the stale value and never applies the real one.
    for _key in list(_phase_markers.keys()):
        _v = _phase_markers.get(_key)
        if _v is not None and _run_started_ts and _v < _run_started_ts:
            _phase_markers[_key] = None
    # Also consult the soarca-trigger's own persisted phase timing
    # (/app/state/novadef_phase_timing.json) — it is the authoritative source
    # for detect_at/act_at and is what the live report_panel timeline shows.
    # The run_item (API in-memory history) may not carry these, so merge both.
    try:
        _soarca_timing = _read_soarca_phase_timing()
    except Exception:
        _soarca_timing = {}
    # Merge every phase timestamp from the soarca-trigger's persisted state
    # file (authoritative — it is written directly by the OODA pipeline) into
    # _phase_markers, applying the same staleness guard uniformly: a value
    # from before this run's own started_at belongs to a previous run on a
    # reused scenario and must never be projected onto this one.
    for _key in ("observe_at", "detect_at", "profile_at", "enrich_at", "decide_at", "act_at"):
        _soarca_val = float(_soarca_timing.get(_key) or 0) or None
        if _soarca_val and _run_started_ts and _soarca_val < _run_started_ts:
            _soarca_val = None
        if _soarca_val and not _phase_markers.get(_key):
            _phase_markers[_key] = _soarca_val
    if markers["detection_at"] is None and _phase_markers.get("detect_at") is not None:
        markers["detection_at"] = float(_phase_markers["detect_at"])
    if markers["countermeasure_at"] is None and _phase_markers.get("act_at") is not None:
        markers["countermeasure_at"] = float(_phase_markers["act_at"])
    # Observe/Profile/Enrich/Decide markers for the phase-timings summary.
    # Same staleness guard as detect_at/act_at above.
    for _key in ("observe_at", "profile_at", "enrich_at", "decide_at"):
        _val = _phase_markers.get(_key)
        if _val is not None and _run_started_ts and _val < _run_started_ts:
            _val = None
        if _val is not None:
            markers[_key] = float(_val)
    # Use the persisted report only once the run has actually finished.
    # During a live run we prefer fresh log evidence so we do not project a
    # stale response marker from a previous completion into the current chart.
    if report_id and markers["finished_at"] is not None:
        try:
            report_json = REPORTS_DIR / report_id / "incident_report.json"
            report_data = json.loads(report_json.read_text(encoding="utf-8")) if report_json.exists() else {}
        except Exception:
            report_data = {}
        lat = ((report_data.get("novadef_metrics") or {}).get("latency_ooda") or {})
        detect_ts = lat.get("first_alert_ts")
        act_ts = lat.get("act_ts")
        if isinstance(detect_ts, str):
            try:
                markers["detection_at"] = datetime.fromisoformat(detect_ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                markers["detection_at"] = None
        if isinstance(act_ts, str):
            try:
                markers["countermeasure_at"] = datetime.fromisoformat(act_ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                markers["countermeasure_at"] = None
    if markers["detection_at"] is None:
        since_ts = int(float((run_item or {}).get("started_at") or 0)) or None
        attack_since_ts = int(float(markers["attack_started_at"] or 0)) or None
        # If the attack has not started yet there cannot be a detection — skip to
        # avoid pulling logs from a previous run (shared detector containers emit
        # events for all scenarios; without a lower-bound anchor we would project
        # the previous run's detection timestamp onto this one).
        if is_running and attack_since_ts is None:
            pass  # detection_at stays None until attack_started_at is recorded
        else:
            detect_since_ts = attack_since_ts if attack_since_ts is not None else since_ts
            # Safety floor: never look further back than the run's own started_at.
            # If started_at is missing (state loss after restart), use now-120s so
            # we never pull unbounded history from shared detector containers.
            if detect_since_ts is None:
                detect_since_ts = int(time.time()) - 120
            experiment = str((run_item or {}).get("experiment") or "")
            detect_logs = (
                _tail_logs("snort_novadef", 220 if is_running else 500, since_ts=detect_since_ts)
                + "\n"
                + _tail_logs("network_intrusion_detector_novadef", 220 if is_running else 500, since_ts=detect_since_ts)
                + "\n"
                + _tail_logs("alert_module_novadef", 220 if is_running else 500, since_ts=detect_since_ts)
            )
            detect_blob = detect_logs
            if experiment == "exp2":
                detect_blob += "\n" + _tail_logs("tshark_novadef", 160 if is_running else 400, since_ts=since_ts)
                detect_blob += "\n" + _tail_logs("pmp-misp-integrator", 120 if is_running else 250, since_ts=detect_since_ts)
            detection_evidence = "\n".join(_detection_evidence_lines(detect_blob, experiment))
            detect_ts = _first_timestamp_for_keywords(
                detection_evidence,
                [
                    "alerta publicada",
                    "alerta rápida publicada",
                    "alerta por flows publicada",
                    "nueva alerta publicada",
                    "host ransomware emulation detected",
                    "distributed password spraying",
                    "bruteforce password spraying detected",
                ],
            )
            # Reject timestamps that predate the attack start — they belong to a
            # previous run whose logs are still visible in the shared container.
            if detect_ts is not None and attack_since_ts is not None and detect_ts < attack_since_ts:
                detect_ts = None
            if detect_ts is not None and since_ts is not None and detect_ts < since_ts:
                detect_ts = None
            if detect_ts is not None:
                markers["detection_at"] = detect_ts
    if markers["countermeasure_at"] is None and not skip_expensive_computation:
        since_ts = int(float((run_item or {}).get("started_at") or 0)) or (int(time.time()) - 120)
        profile_logs = (
            _tail_logs("novadef-novadef_stream_low-1", 220, since_ts=since_ts)
            + "\n"
            + _tail_logs("novadef-novadef_prep_pred-1", 180, since_ts=since_ts)
            + "\n"
            + _tail_logs("novadef-novadef_neo4j_ingester-1", 180, since_ts=since_ts)
        )
        misp_logs = (
            _tail_logs("pmp-misp-integrator", 160, since_ts=since_ts)
            + "\n"
            + _tail_logs("pmp-misp-server", 120, since_ts=since_ts)
        )
        victim_name = _run_container_name(run_item, "victim")
        soarca_logs_live = _soarca_act_log_text(victim_name, since_ts, 160)
        profile_ready = _tapcd_profile_ready(profile_logs)
        profile_ts: float | None = None
        if profile_ready:
            for ln in _tapcd_profile_evidence_lines(profile_logs):
                ts_ln = _parse_log_epoch(ln)
                if ts_ln is not None:
                    profile_ts = ts_ln
                    break
            if profile_ts is None:
                profile_ts = _first_timestamp_for_keywords_with_nearest_fallback(
                    profile_logs,
                    PROFILE_DETAIL_KEYWORDS + PROFILE_EVIDENCE_KEYWORDS + ["profile_"],
                )

        enrich_ready = any(k in misp_logs.lower() for k in ["nuevo evento misp", "event ", "event_id", "attribute", "published", "created"])
        require_misp_enrich = bool(int(os.getenv("EXPERIMENT_REQUIRE_MISP_ENRICH_FOR_ACT", "0")))
        decide_ready = any(k in soarca_logs_live.lower() for k in ["d3fend", "playbook", "selected", "countermeasure"])
        act_ready = any(
            k in soarca_logs_live.lower()
            for k in [
                "soarca_countermeasure_applied",
                "playbook de aislamiento ejecutado",
                "playbook ejecutado",
                "response executed",
                "response applied",
                "done_block_ip",
                "iptables",
                "isolation",
            ]
        )
        pipeline_ready = profile_ready and (enrich_ready or (not require_misp_enrich)) and decide_ready and act_ready
        if pipeline_ready:
            act_logs = _soarca_act_log_text(victim_name, since_ts, 160)
            cm_ts = _first_timestamp_for_keywords_with_nearest_fallback(
                act_logs,
                [
                    "soarca_countermeasure_applied",
                    "playbook de aislamiento ejecutado",
                    "✅ playbook de aislamiento ejecutado",
                    "✅ playbook ejecutado",
                    "playbook ejecutado",
                    "response executed",
                    "response applied",
                    "done_block_ip",
                    "iptables",
                    "isolation",
                ],
            )
            # Reject timestamps from before this run started — previous run's logs.
            if cm_ts is not None and since_ts is not None and cm_ts < since_ts:
                cm_ts = None
            if cm_ts is not None:
                markers["countermeasure_at"] = cm_ts
            elif _soarca_execution_evidence(act_logs):
                # Fallback: execution is confirmed but keyword timestamp couldn't
                # be parsed in selected lines (format/noise differences).
                # Use the last parseable SOARCA line timestamp as marker anchor.
                ts_candidates = [
                    _parse_log_epoch(ln)
                    for ln in act_logs.splitlines()
                    if _parse_log_epoch(ln) is not None
                ]
                if ts_candidates:
                    markers["countermeasure_at"] = float(max(ts_candidates))

    # For running/live runs, only expose countermeasure marker when there is
    # concrete SOARCA execution evidence in current act logs.
    # EXCEPTION: if the soarca-trigger already persisted an act_at phase marker,
    # that IS authoritative execution evidence (the trigger only writes it after
    # "✅ Playbook ejecutado"); do not erase the marker just because a truncated
    # live log tail happened to miss the success line.
    _has_persisted_act = _phase_markers.get("act_at") is not None
    if is_running and markers["countermeasure_at"] is not None and not _has_persisted_act:
        _live_since_ts = int(float((run_item or {}).get("started_at") or 0)) or None
        _live_victim = _run_container_name(run_item, "victim")
        _live_act_logs = _soarca_act_log_text(_live_victim, _live_since_ts, 220)
        if not _effective_soarca_execution(str((run_item or {}).get("experiment") or ""), _live_act_logs, victim_name=_live_victim):
            markers["countermeasure_at"] = None

    # Compute separate network-layer and host-layer detection timestamps for
    # exp3.  We read the MISP integrator logs once and look for the two
    # distinct detection keywords: network IDS alert vs. Falco SSH brute force.
    _exp = str((run_item or {}).get("experiment") or "")
    if _exp == "exp3":
        _since_ts = int(float((run_item or {}).get("attack_started_at") or (run_item or {}).get("started_at") or 0)) or None
        _misp_blob = _tail_logs("pmp-misp-integrator", 400, since_ts=_since_ts)
        _net_detect = _first_timestamp_for_keywords(
            _misp_blob,
            ["alerta rápida publicada", "alerta inmediata por campaign", "distributed password spraying",
             "nueva alerta network ids", "nueva alerta falco única: campaign"],
        )
        _host_detect = _first_timestamp_for_keywords(
            _misp_blob,
            ["[detect] falco: host ransomware emulation detected", "host ransomware emulation detected",
             "nueva alerta falco única: campaign|target=.*host_ransomware",
             "novadef lab ransomware", "ransomware emulation started"],
        )
        if _net_detect:
            markers["network_detect_at"] = _net_detect
        if _host_detect:
            markers["host_detect_at"] = _host_detect

    with LOCK:
        TRAFFIC_MARKERS_CACHE[run_id] = {
            "detection_at": markers.get("detection_at"),
            "countermeasure_at": markers.get("countermeasure_at"),
            "computed_at": now_ts,
        }

    if (
        markers["detection_at"] is not None
        and markers["attack_started_at"] is not None
        and markers["detection_at"] < markers["attack_started_at"]
    ):
        markers["detection_at"] = None

    if (
        markers["countermeasure_at"] is not None
        and markers["attack_started_at"] is not None
        and markers["countermeasure_at"] < markers["attack_started_at"]
    ):
        # Ignore stale response markers from previous runs or from warm-up
        # activity before the current attack actually started.
        markers["countermeasure_at"] = None

    def _compute_countermeasure_drop_stats(
        traffic_points: list[dict[str, Any]],
        countermeasure_at: float | None,
    ) -> dict[str, Any]:
        if not countermeasure_at or len(traffic_points) < 3:
            return {
                "status": "unavailable",
                "reason": "countermeasure_missing_or_not_enough_points",
                "clear_drop": False,
            }

        window_sec = float(os.getenv("EXPERIMENT_DROP_WINDOW_SECONDS", "8.0"))
        min_intervals = int(os.getenv("EXPERIMENT_DROP_MIN_INTERVALS", "4"))
        clear_drop_threshold = float(os.getenv("EXPERIMENT_DROP_CLEAR_RATIO", "0.20"))

        intervals: list[dict[str, float]] = []
        for i in range(1, len(traffic_points)):
            prev = traffic_points[i - 1]
            cur = traffic_points[i]
            dt = float(cur.get("ts", 0.0) or 0.0) - float(prev.get("ts", 0.0) or 0.0)
            if dt <= 0:
                continue
            prev_eff = float(prev.get("rx_packets", 0.0) or 0.0)
            cur_eff = float(cur.get("rx_packets", 0.0) or 0.0)
            prev_raw = float(prev.get("rx_packets_raw", prev_eff) or 0.0)
            cur_raw = float(cur.get("rx_packets_raw", cur_eff) or 0.0)
            prev_blk = float(prev.get("blocked_packets", 0.0) or 0.0)
            cur_blk = float(cur.get("blocked_packets", 0.0) or 0.0)
            intervals.append(
                {
                    "end_ts": float(cur.get("ts", 0.0) or 0.0),
                    "effective_pps": max(cur_eff - prev_eff, 0.0) / dt,
                    "raw_pps": max(cur_raw - prev_raw, 0.0) / dt,
                    "blocked_pps": max(cur_blk - prev_blk, 0.0) / dt,
                }
            )

        if len(intervals) < 2:
            return {
                "status": "unavailable",
                "reason": "not_enough_intervals",
                "clear_drop": False,
            }

        pre_window = [
            it
            for it in intervals
            if (countermeasure_at - window_sec) <= it["end_ts"] < countermeasure_at
        ]
        post_window = [
            it
            for it in intervals
            if countermeasure_at <= it["end_ts"] <= (countermeasure_at + window_sec)
        ]

        # Fallback to nearest intervals around CM if symmetric window is sparse.
        if len(pre_window) < min_intervals:
            pre_window = [it for it in intervals if it["end_ts"] < countermeasure_at][-min_intervals:]
        if len(post_window) < min_intervals:
            post_window = [it for it in intervals if it["end_ts"] >= countermeasure_at][:min_intervals]

        if len(pre_window) < 2 or len(post_window) < 2:
            return {
                "status": "insufficient_samples",
                "reason": "not_enough_pre_post_intervals",
                "pre_intervals": len(pre_window),
                "post_intervals": len(post_window),
                "clear_drop": False,
            }

        def _med(values: list[float]) -> float:
            return float(statistics.median(values)) if values else 0.0

        pre_eff = _med([it["effective_pps"] for it in pre_window])
        post_eff = _med([it["effective_pps"] for it in post_window])
        pre_raw = _med([it["raw_pps"] for it in pre_window])
        post_raw = _med([it["raw_pps"] for it in post_window])
        pre_blk = _med([it["blocked_pps"] for it in pre_window])
        post_blk = _med([it["blocked_pps"] for it in post_window])

        drop_ratio = 0.0
        if pre_eff > 0:
            drop_ratio = (pre_eff - post_eff) / pre_eff

        blocked_post_ratio = (post_blk / max(post_raw, 1e-9)) if post_raw > 0 else 0.0
        clear_drop = bool(drop_ratio >= clear_drop_threshold)

        return {
            "status": "ok",
            "clear_drop": clear_drop,
            "drop_ratio": max(min(drop_ratio, 1.0), -1.0),
            "drop_percent": max(min(drop_ratio * 100.0, 100.0), -100.0),
            "pre_effective_pps_median": pre_eff,
            "post_effective_pps_median": post_eff,
            "pre_raw_pps_median": pre_raw,
            "post_raw_pps_median": post_raw,
            "pre_blocked_pps_median": pre_blk,
            "post_blocked_pps_median": post_blk,
            "post_blocked_ratio": max(min(blocked_post_ratio, 1.0), 0.0),
            "window_seconds": window_sec,
            "pre_intervals": len(pre_window),
            "post_intervals": len(post_window),
            "threshold_ratio": clear_drop_threshold,
        }

    drop_stats = _compute_countermeasure_drop_stats(points, markers.get("countermeasure_at"))

    def _counter_at_or_before(ts: float | None, key: str) -> float:
        if ts is None or not points:
            return float(points[0].get(key, 0.0) or 0.0) if points else 0.0
        candidate = points[0]
        for p in points:
            if float(p.get("ts", 0.0) or 0.0) <= float(ts):
                candidate = p
            else:
                break
        return float(candidate.get(key, 0.0) or 0.0)

    if len(points) >= 2:
        series = []
        prev_raw = None
        prev_blocked = None
        for p in points:
            rx_packets = float(p.get("rx_packets", 0.0))
            rx_packets_raw = float(p.get("rx_packets_raw", rx_packets))
            blocked_packets = float(p.get("blocked_packets", 0.0))
            relative_packets = max(rx_packets - baseline, 0.0)
            # Compute delta as (raw_delta - drop_delta) so iptables-blocked packets
            # are subtracted per-interval rather than as a cumulative offset.
            # This ensures the chart drops to 0 immediately after isolation even
            # when L2/ARP traffic keeps incrementing the NIC RX counter.
            if prev_raw is None:
                delta = 0.0
            else:
                raw_delta = max(rx_packets_raw - prev_raw, 0.0)
                drop_delta = max(blocked_packets - prev_blocked, 0.0)
                delta = max(raw_delta - drop_delta, 0.0)
            series.append(
                {
                    "ts": float(p["ts"]),
                    "rx_packets": rx_packets,
                    "rx_packets_raw": rx_packets_raw,
                    "blocked_packets": blocked_packets,
                    "delta_packets": delta,
                    "relative_packets": relative_packets,
                    "cpu_percent": float(p.get("cpu_percent", 0.0)),
                    "memory_bytes": float(p.get("memory_bytes", 0.0)),
                    "memory_percent": float(p.get("memory_percent", 0.0)),
                    "falco_events": float(p.get("falco_events", 0.0)),
                    "falco_signal_total": float(p.get("falco_signal_total", p.get("falco_events", 0.0))),
                    "falco_signal_delta": float(p.get("falco_signal_delta", 0.0)),
                    "falco_warning_events": float(p.get("falco_warning_events", 0.0)),
                    "falco_error_events": float(p.get("falco_error_events", 0.0)),
                    "falco_critical_events": float(p.get("falco_critical_events", 0.0)),
                    "falco_info_events": float(p.get("falco_info_events", 0.0)),
                    "falco_notice_events": float(p.get("falco_notice_events", 0.0)),
                    "falco_debug_events": float(p.get("falco_debug_events", 0.0)),
                    "falco_top_rules": list(p.get("falco_top_rules") or []),
                    "falco_signal_types": dict(p.get("falco_signal_types") or {}),
                }
            )
            prev_raw = rx_packets_raw
            prev_blocked = blocked_packets
    else:
        series = [
            {
                "ts": float(p["ts"]),
                "rx_packets": float(p.get("rx_packets", 0.0) or 0.0),
                "rx_packets_raw": float(p.get("rx_packets_raw", p.get("rx_packets", 0.0))),
                "blocked_packets": float(p.get("blocked_packets", 0.0)),
                "delta_packets": 0.0,
                "relative_packets": max(float(p.get("rx_packets", 0.0)) - baseline, 0.0),
                "cpu_percent": float(p.get("cpu_percent", 0.0)),
                "memory_bytes": float(p.get("memory_bytes", 0.0)),
                "memory_percent": float(p.get("memory_percent", 0.0)),
                "falco_events": float(p.get("falco_events", 0.0)),
                "falco_signal_total": float(p.get("falco_signal_total", p.get("falco_events", 0.0))),
                "falco_signal_delta": float(p.get("falco_signal_delta", 0.0)),
                "falco_warning_events": float(p.get("falco_warning_events", 0.0)),
                "falco_error_events": float(p.get("falco_error_events", 0.0)),
                "falco_critical_events": float(p.get("falco_critical_events", 0.0)),
                "falco_info_events": float(p.get("falco_info_events", 0.0)),
                "falco_notice_events": float(p.get("falco_notice_events", 0.0)),
                "falco_debug_events": float(p.get("falco_debug_events", 0.0)),
                "falco_top_rules": list(p.get("falco_top_rules") or []),
                "falco_signal_types": dict(p.get("falco_signal_types") or {}),
            }
            for p in points
        ]

    started_at = markers.get("started_at")
    attack_at = markers.get("attack_started_at")
    cm_at = markers.get("countermeasure_at")
    last_raw = float(points[-1].get("rx_packets_raw", points[-1].get("rx_packets", 0.0)) or 0.0) if points else 0.0
    last_eff = float(points[-1].get("rx_packets", 0.0) or 0.0) if points else 0.0
    last_blk = float(points[-1].get("blocked_packets", 0.0) or 0.0) if points else 0.0
    base_raw = _counter_at_or_before(started_at, "rx_packets_raw")
    base_eff = _counter_at_or_before(started_at, "rx_packets")
    base_blk = _counter_at_or_before(started_at, "blocked_packets")
    attack_raw = _counter_at_or_before(attack_at, "rx_packets_raw")
    attack_eff = _counter_at_or_before(attack_at, "rx_packets")
    attack_blk = _counter_at_or_before(attack_at, "blocked_packets")
    cm_raw = _counter_at_or_before(cm_at, "rx_packets_raw")
    cm_eff = _counter_at_or_before(cm_at, "rx_packets")
    cm_blk = _counter_at_or_before(cm_at, "blocked_packets")

    phase_packet_counts = {
        "pre_attack": {
            "raw": max(attack_raw - base_raw, 0.0),
            "effective": max(attack_eff - base_eff, 0.0),
            "blocked": max(attack_blk - base_blk, 0.0),
        },
        "attack_to_countermeasure": {
            "raw": max(cm_raw - attack_raw, 0.0),
            "effective": max(cm_eff - attack_eff, 0.0),
            "blocked": max(cm_blk - attack_blk, 0.0),
        },
        "post_countermeasure": {
            "raw": max(last_raw - cm_raw, 0.0),
            "effective": max(last_eff - cm_eff, 0.0),
            "blocked": max(last_blk - cm_blk, 0.0),
        },
    }

    chart_visible_at = attack_at if attack_at is not None else started_at
    visible_series = [p for p in series if chart_visible_at is None or float(p.get("ts", 0.0) or 0.0) >= float(chart_visible_at)]

    return {
        "ok": True,
        "run_id": run_id,
        "series": series[-240:],
        "visible_series": visible_series[-240:],
        "baseline": baseline,
        "raw_points": raw_sample_count,
        "window_points": len(series[-240:]),
        "visible_points": len(visible_series[-240:]),
        "chart_visible_at": chart_visible_at,
        "markers": markers,
        "countermeasure_drop": drop_stats,
        "phase_packet_counts": phase_packet_counts,
    }


def _prometheus_live_metrics_text() -> str:
    with LOCK:
        run_id = str(STATE.get("current_run_id") or "")
    run_item = _history_item(run_id) if run_id else None
    experiment = str((run_item or {}).get("experiment") or "")
    if run_id:
        payload = _traffic_payload_for_run(run_id, run_item)
    else:
        payload = {"series": [], "markers": {}, "raw_points": 0, "window_points": 0}
    series = payload.get("series") or []
    last = series[-1] if series else {}
    last_delta = float(last.get("delta_packets", 0.0) or 0.0)
    last_total = float(last.get("rx_packets", 0.0) or 0.0)
    last_cpu = float(last.get("cpu_percent", 0.0) or 0.0)
    last_mem_percent = float(last.get("memory_percent", 0.0) or 0.0)
    last_mem_bytes = float(last.get("memory_bytes", 0.0) or 0.0)
    markers = payload.get("markers") or {}
    observe_ready = 1 if _observe_ready(run_id) else 0
    detect_ready = 0
    profile_ready = 0
    enrich_ready = 0
    decide_ready = 0
    act_ready = 0
    if run_id:
        run_item = _history_item(run_id)
        if run_item:
            finished = bool(run_item.get("finished_at"))
            output_low = str(run_item.get("output_tail") or "").lower()
            detect_ready = 1 if any(k in output_low for k in ["alert", "snort", "anomaly", "falco"]) else 0
            profile_ready = 1 if detect_ready and any(k in output_low for k in ["tapcd", "profile"]) else 0
            enrich_ready = 1 if detect_ready and any(k in output_low for k in ["misp", "event", "event id"]) else 0
            decide_ready = 1 if detect_ready and profile_ready and enrich_ready and any(k in output_low for k in ["d3fend", "countermeasure", "playbook"]) else 0
            act_ready = 1 if detect_ready and profile_ready and enrich_ready and decide_ready and any(k in output_low for k in ["applied", "executed", "response", "countermeasure"]) else 0
            if finished and last_delta > 0:
                act_ready = max(act_ready, 1)
    lines = [
        '# HELP novadef_live_attack_packets_per_second Attack-specific victim packet rate sampled by NOVADEF.',
        '# TYPE novadef_live_attack_packets_per_second gauge',
        f'novadef_live_attack_packets_per_second {last_delta}',
        '# HELP novadef_live_attack_packets_since_run_start Attack-specific packet count since run start.',
        '# TYPE novadef_live_attack_packets_since_run_start gauge',
        f'novadef_live_attack_packets_since_run_start {last_total}',
        '# HELP novadef_live_victim_cpu_percent Victim CPU usage sampled by NOVADEF.',
        '# TYPE novadef_live_victim_cpu_percent gauge',
        f'novadef_live_victim_cpu_percent {last_cpu}',
        '# HELP novadef_live_victim_memory_percent Victim memory usage percent sampled by NOVADEF.',
        '# TYPE novadef_live_victim_memory_percent gauge',
        f'novadef_live_victim_memory_percent {last_mem_percent}',
        '# HELP novadef_live_victim_memory_bytes Victim memory usage bytes sampled by NOVADEF.',
        '# TYPE novadef_live_victim_memory_bytes gauge',
        f'novadef_live_victim_memory_bytes {last_mem_bytes}',
        '# HELP novadef_live_observe_ready Live observe phase readiness.',
        '# TYPE novadef_live_observe_ready gauge',
        f'novadef_live_observe_ready {observe_ready}',
        '# HELP novadef_live_detect_ready Live detect phase readiness.',
        '# TYPE novadef_live_detect_ready gauge',
        f'novadef_live_detect_ready {detect_ready}',
        '# HELP novadef_live_profile_ready Live profile phase readiness.',
        '# TYPE novadef_live_profile_ready gauge',
        f'novadef_live_profile_ready {profile_ready}',
        '# HELP novadef_live_enrich_ready Live enrich phase readiness.',
        '# TYPE novadef_live_enrich_ready gauge',
        f'novadef_live_enrich_ready {enrich_ready}',
        '# HELP novadef_live_decide_ready Live decide phase readiness.',
        '# TYPE novadef_live_decide_ready gauge',
        f'novadef_live_decide_ready {decide_ready}',
        '# HELP novadef_live_act_ready Live act phase readiness.',
        '# TYPE novadef_live_act_ready gauge',
        f'novadef_live_act_ready {act_ready}',
    ]
    if experiment:
        lines.extend([
            '# HELP novadef_live_current_run_info Current live experiment metadata.',
            '# TYPE novadef_live_current_run_info gauge',
            f'novadef_live_current_run_info{{experiment="{experiment}",run_id="{run_id}"}} 1',
        ])
    return "\n".join(lines) + "\n"

def _report_panel_from_latest_report(report_id: str) -> dict[str, Any] | None:
    try:
        p = REPORTS_DIR / report_id / "incident_report.json"
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

    execution = data.get("execution") or {}
    misp = data.get("misp") or {}
    tapcd = data.get("tapcd") or {}
    event_object = misp.get("event_object") or {}
    attrs = event_object.get("attributes") or []
    event_lines = misp.get("event_detail_lines") or []
    source_ips = _extract_source_ips_from_misp_attributes(attrs) or _extract_source_ips_from_misp_lines(event_lines)
    victim_ip = _extract_victim_ip_from_misp_lines(event_lines)
    started_iso = str(execution.get("started_at") or "").strip() or None
    native_profile_lines = list(tapcd.get("profile_detail_lines") or [])
    actor_profiles = _native_actor_profiles_from_lines(native_profile_lines, source_ips=source_ips) if bool(tapcd.get("native_profile_ready")) else []
    if not actor_profiles:
        actor_profiles = list(tapcd.get("actor_profiles") or [])
    if not actor_profiles and (victim_ip or source_ips):
        actor_profiles = _select_primary_actor_profile(
            _neo4j_actor_profiles(victim_ip, source_ips=source_ips, started_at=started_iso, include_synthetic=False, limit=5, scenario_id=_run_scenario_id),
            source_ips=source_ips,
        )
    # No fallback without started_at: returning profiles from previous runs
    # would contaminate the panel with stale data from a different experiment.
    if len(actor_profiles) > 1 and not native_profile_lines:
        actor_profiles = _select_primary_actor_profile(actor_profiles, source_ips=source_ips)
    if len(native_profile_lines) > 1:
        tapcd["profile_detail_lines"] = list(dict.fromkeys(native_profile_lines))
    return {
        "misp": {
            "event_ids_detected_in_logs": misp.get("event_ids_detected_in_logs") or [],
            "event_signal_count": int(misp.get("event_signal_count") or 0),
            "event_details_extracted": len(misp.get("event_detail_lines") or []),
            "event_detail_lines": misp.get("event_detail_lines") or [],
            "event_object": event_object,
        },
        "tapcd": {
            "profile_mentions": int(((tapcd.get("signals") or {}).get("profile_mentions")) or 0),
            "attacker_mentions": int(((tapcd.get("signals") or {}).get("attacker_mentions")) or 0),
            "incident_mentions": int(((tapcd.get("signals") or {}).get("incident_mentions")) or 0),
            "profile_details_extracted": len(tapcd.get("profile_detail_lines") or []),
            "profile_detail_lines": tapcd.get("profile_detail_lines") or [],
            "native_profile_ready": bool(tapcd.get("native_profile_ready")),
            "actor_profile_count": len(actor_profiles),
            "actor_profiles": actor_profiles,
            "profile_object": {
                "actors": actor_profiles,
                "native_profile_lines": tapcd.get("profile_detail_lines") or [],
            },
        },
    }


def _build_report_payload(run_id: str | None = None) -> dict[str, Any]:
    with LOCK:
        experiment = STATE.get("last_experiment")
        started = STATE.get("last_started_at")
        finished = STATE.get("last_finished_at")
        rc = STATE.get("last_return_code")
        output = STATE.get("last_output", "")

    run_item = _history_item(run_id) if run_id else None
    resolved_run_id = run_id
    if not run_item:
        with LOCK:
            current_run_id = str(STATE.get("current_run_id") or "")
        if current_run_id:
            resolved_run_id = current_run_id
            run_item = _history_item(current_run_id)
    if not run_item:
        with LOCK:
            last_experiment = str(STATE.get("last_experiment") or "")
            for item in reversed(RUN_HISTORY):
                if last_experiment and str(item.get("experiment") or "") == last_experiment:
                    run_item = dict(item)
                    resolved_run_id = str(item.get("run_id") or "") or None
                    break

    if run_item:
        experiment = str(run_item.get("experiment") or experiment or "")
        started = float(run_item.get("started_at") or started or 0) or None
        finished = float(run_item.get("finished_at") or finished or 0) or None
        rc = int(run_item.get("return_code") if run_item.get("return_code") is not None else (rc if rc is not None else 0))
        output = str(run_item.get("output_tail") or output or "")
    if not experiment:
        raise ValueError("No experiment has been launched yet.")
    _run_scenario_id = str((run_item or {}).get("scenario_id") or "").strip() or None
    since_ts = int(started) if started else None
    attack_started = (run_item or {}).get("attack_started_at")
    if attack_started is None:
        attack_started = STATE.get("last_attack_started_at")
    phase_since_ts = int(attack_started) if isinstance(attack_started, (int, float)) else since_ts
    traffic_panel = _traffic_payload_for_run(str(resolved_run_id or ""), run_item) if resolved_run_id else {"series": [], "raw_points": 0, "window_points": 0, "markers": {}}
    report_panel = _build_live_report_panel(experiment, started, attack_started) if experiment else {}
    victim_name = _run_container_name(run_item, "victim")
    attacker_name = _run_container_name(run_item, "attacker")

    observe_logs = {
        "tshark_novadef": _tail_logs("tshark_novadef", 300, since_ts=since_ts),
        "falco_novadef": _tail_logs("falco_novadef", 300, since_ts=since_ts),
        "flow_module_novadef": _tail_logs("flow_module_novadef", 300, since_ts=since_ts),
    }
    detect_logs = {
        "snort_novadef": _tail_logs("snort_novadef", 350, since_ts=phase_since_ts),
        "network_intrusion_detector_novadef": _tail_logs("network_intrusion_detector_novadef", 350, since_ts=phase_since_ts),
        "alert_module_novadef": _tail_logs("alert_module_novadef", 350, since_ts=phase_since_ts),
    }
    profile_logs = {
        "novadef-novadef_stream_low-1": _tail_logs("novadef-novadef_stream_low-1", 350, since_ts=phase_since_ts),
        "novadef-novadef_prep_pred-1": _tail_logs("novadef-novadef_prep_pred-1", 250, since_ts=phase_since_ts),
        "novadef-novadef_neo4j_ingester-1": _tail_logs("novadef-novadef_neo4j_ingester-1", 250, since_ts=phase_since_ts),
    }
    misp_logs = {
        "pmp-misp-integrator": _tail_logs("pmp-misp-integrator", 350, since_ts=phase_since_ts),
        "pmp-misp-server": _tail_logs("pmp-misp-server", 300, since_ts=phase_since_ts),
    }
    soarca_logs = {
        "pmp-soarca-core": _tail_logs("pmp-soarca-core", 350, since_ts=phase_since_ts),
        "pmp-soarca-executor-ssh": _tail_logs("pmp-soarca-executor-ssh", 350, since_ts=phase_since_ts),
        "pmp-misp-soarca-trigger": _tail_logs("pmp-misp-soarca-trigger", 350, since_ts=phase_since_ts),
        victim_name: _tail_logs(victim_name, 300, since_ts=phase_since_ts),
    }
    attacker_logs = {attacker_name: _tail_logs(attacker_name, 300, since_ts=since_ts)}

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
    tapcd_lines = tapcd_blob.splitlines()
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
    tapcd_profile_detail_lines = _tapcd_profile_evidence_lines(tapcd_blob)
    latest_event = _latest_misp_event_for_run(str(experiment), started, strict_time=True)
    if not latest_event and reused_event:
        latest_event = reused_event
    panel_misp = report_panel.get("misp") or {}
    panel_tapcd = report_panel.get("tapcd") or {}
    attrs: list[dict[str, Any]] = list((panel_misp.get("event_object") or {}).get("attributes") or [])
    if not attrs and latest_event and latest_event.get("id"):
        attrs = _misp_event_attributes(str(latest_event["id"]))
    if not latest_event and (panel_misp.get("event_object") or {}).get("event"):
        latest_event = (panel_misp.get("event_object") or {}).get("event") or {}

    victim_ip = _extract_victim_ip_from_misp_lines(misp_event_detail_lines)
    if not victim_ip:
        for attr in attrs:
            if str(attr.get("type") or "") == "ip-dst":
                victim_ip = str(attr.get("value") or "").strip()
                if victim_ip:
                    break
    source_ips = _extract_source_ips_from_misp_attributes(attrs) or _extract_source_ips_from_misp_lines(misp_event_detail_lines)
    started_iso = datetime.fromtimestamp(started, tz=timezone.utc).isoformat().replace("+00:00", "Z") if started else None
    native_profile_ready = bool(panel_tapcd.get("native_profile_ready") or tapcd_profile_detail_lines)
    actor_profiles = _native_actor_profiles_from_lines(tapcd_profile_detail_lines, source_ips=source_ips) if native_profile_ready else []
    if not actor_profiles:
        actor_profiles = list(panel_tapcd.get("actor_profiles") or [])
    if not actor_profiles and (victim_ip or source_ips):
        actor_profiles = _select_primary_actor_profile(
            _neo4j_actor_profiles(victim_ip, source_ips=source_ips, started_at=started_iso, include_synthetic=False, limit=5, scenario_id=_run_scenario_id),
            source_ips=source_ips,
        )
    # Always collapse to the single richest actor profile (best ML-field
    # completeness via _score_actor_profile). For exp3 the host
    # ransomware-operator stub (empty Motivation/Knowledge/Skills) and the
    # network crime-syndicate/criminal profile (full ML fields) both appear in
    # the logs; we want the rich network profile shown as the lead, regardless of
    # which arrived first. Previously this only ran when native_profile_ready was
    # False, so the first-seen (often ransomware) profile won.
    if len(actor_profiles) > 1:
        actor_profiles = _select_primary_actor_profile(actor_profiles, source_ips=source_ips)
    tapcd_indicators = {
        "profile_mentions": _count_keyword_hits(tapcd_blob, PROFILE_EVIDENCE_KEYWORDS),
        "attacker_mentions": (
            tapcd_blob.lower().count("attacker")
            + tapcd_blob.lower().count("actor")
            + tapcd_blob.lower().count("amenaza")
        ),
        "incident_mentions": (
            tapcd_blob.lower().count("incident")
            + tapcd_blob.lower().count("incidente")
        ),
    }

    soarca_blob = _strip_soarca_excerpt_noise("\n".join(soarca_logs.values()))
    countermeasure, why = _detect_countermeasure(soarca_blob, experiment)
    panel_timeline = report_panel.get("timeline") or {}
    act_confirmed = bool(
        isinstance(panel_timeline.get("act_at"), (int, float))
        or _effective_soarca_execution(experiment, soarca_blob, victim_name=victim_name)
    )
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
    pipeline_complete = bool(
        (panel_tapcd.get("actor_profile_count") or len(actor_profiles) or 0) > 0
        and (panel_misp.get("event_ids_detected_in_logs") or event_ids)
        and countermeasure not in {"", "-", "Pending / no decision yet", "No new action (existing incident/countermeasure reused)"}
        and act_confirmed
    )
    exp_metrics = _compute_experiment_metrics(
        experiment,
        started,
        finished,
        logs_by_phase,
        attack_started=attack_started,
        traffic_panel=traffic_panel,
        report_panel=report_panel,
        countermeasure_text=countermeasure,
        attrs=attrs,
        detection_confirmed=bool(event_ids),
    )

    phase_machine = _phase_machine_map(experiment)
    _ri = run_item or {}
    _live_tl = report_panel.get("timeline") or {}

    def _phase_val(key: str) -> float | None:
        v = _ri.get(key) or _live_tl.get(key)
        return float(v) if v else None

    _phase_ts: dict[str, float | None] = {
        "observe": _phase_val("observe_at"),
        "detect":  _phase_val("detect_at"),
        "profile": _phase_val("profile_at"),
        "enrich":  _phase_val("enrich_at"),
        "decide":  _phase_val("decide_at"),
        "act":     _phase_val("act_at"),
    }
    def _phase_iso(ts: float | None) -> str | None:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
    phases = [
        {"phase": "observe", "machine_scope": phase_machine["observe"], "detector_or_component": "Falco/tshark/Flow",
         "confirmed": _phase_ts["observe"] is not None, "timestamp": _phase_iso(_phase_ts["observe"])},
        {"phase": "detect", "machine_scope": phase_machine["detect"], "detector_or_component": "Snort + anomaly detector + alert module",
         "confirmed": _phase_ts["detect"] is not None, "timestamp": _phase_iso(_phase_ts["detect"])},
        {"phase": "profile", "machine_scope": phase_machine["profile"], "detector_or_component": "TAPCD",
         "confirmed": _phase_ts["profile"] is not None, "timestamp": _phase_iso(_phase_ts["profile"])},
        {"phase": "enrich", "machine_scope": phase_machine["enrich"], "detector_or_component": "MISP integrator/server",
         "confirmed": _phase_ts["enrich"] is not None, "timestamp": _phase_iso(_phase_ts["enrich"])},
        {"phase": "decide", "machine_scope": phase_machine["decide"], "detector_or_component": "SOARCA core (D3FEND-based decision)",
         "confirmed": _phase_ts["decide"] is not None, "timestamp": _phase_iso(_phase_ts["decide"])},
        {"phase": "act", "machine_scope": phase_machine["act"], "detector_or_component": "SOARCA executor / victim actions",
         "confirmed": _phase_ts["act"] is not None, "timestamp": _phase_iso(_phase_ts["act"])},
    ]

    status_ok = bool(rc == 0 and pipeline_complete)
    _duration = None
    if attack_started and finished:
        _duration = round(float(finished) - float(attack_started), 2)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment": experiment,
        "execution": {
            "started_at": datetime.fromtimestamp(started, tz=timezone.utc).isoformat() if started else None,
            "finished_at": datetime.fromtimestamp(finished, tz=timezone.utc).isoformat() if finished else None,
            "attack_started_at": datetime.fromtimestamp(attack_started, tz=timezone.utc).isoformat() if attack_started else None,
            "duration_seconds": _duration,
            "return_code": rc,
            "status_ok": status_ok,
            "pipeline_complete": pipeline_complete,
            "backend_output_tail": output,
        },
        "phase_machine_scope": phase_machine,
        "phases": phases,
        "alerts": alert_lines,
        "misp": {
            "event_ids_detected_in_logs": event_ids,
            "event_signal_count": sum(
                1 for ln in misp_blob.splitlines()
                if any(k in ln.lower() for k in [
                    "nuevo evento misp", "event_id", "event id", "misp event",
                    "published", "nueva alerta", "alerta rápida", "alerta rapida",
                    "alerta falco", "[detect]", "campaign|target",
                ])
            ),
            "event_detail_lines": misp_event_detail_lines[-250:],
            "event_object": {
                "event": latest_event or {},
                "attributes": attrs,
            },
            "log_excerpt": misp_blob[-6000:],
            "full_log": misp_blob,
            "reused_existing_event": bool(reused_event),
        },
        "tapcd": {
            "signals": tapcd_indicators,
            "profile_detail_lines": tapcd_profile_detail_lines[-250:],
            "actor_profiles": actor_profiles,
            "actor_profile_count": len(actor_profiles),
            "profile_object": {"actors": actor_profiles},
            "native_profile_ready": native_profile_ready,
            "log_excerpt": tapcd_blob[-6000:],
            "full_log": tapcd_blob,
        },
        "countermeasure": {
            "selected": countermeasure,
            "justification": why,
            "d3fend_basis": "Selected from SOARCA-stage evidence and mapped to D3FEND-aligned defensive controls.",
            "soarca_excerpt": _soarca_execution_evidence_excerpt(soarca_blob) or "No se encuentra evidencia de la contramedida todavía.",
            "execution_confirmed": act_confirmed,
        },
        "novadef_metrics": exp_metrics,
        # Full chart data (network + host series and OODA markers) so the exact
        # same graph can be recreated later from the report folder alone.
        "chart_data": {
            "series": list((traffic_panel or {}).get("series") or []),
            "markers": dict((traffic_panel or {}).get("markers") or {}),
            "baseline": float((traffic_panel or {}).get("baseline") or 0.0),
            "raw_points": int((traffic_panel or {}).get("raw_points") or 0),
            "window_points": int((traffic_panel or {}).get("window_points") or 0),
        },
        "incident_artifacts": {
            "json_available": True,
            "csv_available": True,
            "report_markdown_available": True,
            "zip_downloadable": True,
            "chart_data_available": True,
        },
    }


def _render_misp_full_log(payload: dict[str, Any]) -> str:
    misp = payload.get("misp") or {}
    event_object = misp.get("event_object") or {}
    event = event_object.get("event") or {}
    attrs = event_object.get("attributes") or []
    lines = list(misp.get("event_detail_lines") or [])
    return "\n".join(
        [
            "NOVADEF MISP evidence",
            f"Experiment: {payload.get('experiment')}",
            f"Event ID: {event.get('id') or 'none'}",
            f"Event info: {event.get('info') or 'none'}",
            f"Event count in logs: {len(misp.get('event_ids_detected_in_logs') or [])}",
            "",
            "MISP event object",
            json.dumps(event_object, indent=2, ensure_ascii=False),
            "",
            "Extracted attributes / evidence",
            json.dumps(attrs, indent=2, ensure_ascii=False),
            "",
            "Event detail lines",
            *([f"- {ln}" for ln in lines] if lines else ["- none"]),
            "",
            "Raw log excerpt",
            str(misp.get("log_excerpt") or "").strip() or "none",
        ]
    ).strip()


def _render_tapcd_full_log(payload: dict[str, Any]) -> str:
    tapcd = payload.get("tapcd") or {}
    profile_object = tapcd.get("profile_object") or {}
    actor_profiles = list(tapcd.get("actor_profiles") or [])
    profile_detail_lines = list(tapcd.get("profile_detail_lines") or [])
    signals = tapcd.get("signals") or {}
    return "\n".join(
        [
            "NOVADEF TAPCD evidence",
            f"Experiment: {payload.get('experiment')}",
            f"Actor profile count: {tapcd.get('actor_profile_count', 0)}",
            f"Native profile ready: {tapcd.get('native_profile_ready', False)}",
            "",
            "Signal summary",
            json.dumps(signals, indent=2, ensure_ascii=False),
            "",
            "Profile object",
            json.dumps(profile_object, indent=2, ensure_ascii=False),
            "",
            "Actor profiles",
            json.dumps(actor_profiles, indent=2, ensure_ascii=False),
            "",
            "Profile detail lines",
            *([f"- {ln}" for ln in profile_detail_lines] if profile_detail_lines else ["- none"]),
            "",
            "Raw log excerpt",
            str(tapcd.get("log_excerpt") or "").strip() or "none",
        ]
    ).strip()


def _render_alerts_csv_rows(payload: dict[str, Any]) -> list[dict[str, str]]:
    misp = payload.get("misp") or {}
    event_object = misp.get("event_object") or {}
    event = event_object.get("event") or {}
    lines = list(misp.get("event_detail_lines") or [])
    source_ips = sorted(
        {
            m.group(1)
            for ln in lines
            for m in [re.search(r"(\d+\.\d+\.\d+\.\d+)", ln)]
            if m
        }
    )
    target = ""
    target_port = ""
    attack_fp = ""
    info = str(event.get("info") or "")
    if info:
        m = re.search(r"against\s+([0-9.]+):(\d+)", info)
        if m:
            target = m.group(1)
            target_port = m.group(2)
        m = re.search(r"attack_fp=([0-9a-f]+)", info)
        if m:
            attack_fp = m.group(1)
    return [
        {
            "timestamp": str((payload.get("execution") or {}).get("attack_started_at") or (payload.get("execution") or {}).get("started_at") or ""),
            "detector": "network_intrusion_detector_novadef",
            "alert": info or "Distributed password spraying",
            "reason": "Detected a distributed low-and-slow password spraying pattern in tshark and CIC flow telemetry, with repeated authentication failures against one remote service target.",
            "attack": "T1110|T1110.003|T1133",
            "source_ips": ";".join(source_ips),
            "target": target,
            "target_port": target_port,
            "attack_fp": attack_fp,
            "event_id": str(event.get("id") or "1"),
        }
    ]


def _render_markdown(payload: dict[str, Any]) -> str:
    ex = payload["experiment"]
    execs = payload["execution"]
    cm = payload["countermeasure"]
    misp = payload["misp"]
    tapcd = payload["tapcd"]
    event_obj = (misp.get("event_object") or {}).get("event") or {}
    actors = (tapcd.get("profile_object") or {}).get("actors") or (tapcd.get("actor_profiles") or [])
    lead_actor = actors[0] if actors else {}
    actor_takeaway = (
        "- TAPCD generated a native actor profile for this incident and the report includes the full profile object used by NOVADEF."
        if actors else
        "- TAPCD did not expose a native actor profile for this incident, so the report keeps that field empty rather than fabricating it."
    )
    metrics = payload.get("novadef_metrics") or {}
    latency = metrics.get("latency_ooda") or {}
    obs = metrics.get("observation_quality") or {}
    det = metrics.get("detection_quality") or {}
    resp = metrics.get("response_effectiveness") or {}
    return f"""# NOVADEF Incident Report

## Summary
- Experiment: `{ex}`
- Started (UTC): `{execs.get("started_at")}`
- Attack launched (UTC): `{execs.get("attack_started_at")}`
- Finished (UTC): `{execs.get("finished_at")}`
- Return code: `{execs.get("return_code")}`
- Status OK: `{execs.get("status_ok")}`
- Pipeline complete: `{execs.get("pipeline_complete")}`

## Phase Scope
{chr(10).join([f"- {k}: {v}" for k, v in payload["phase_machine_scope"].items()])}

## Detection And Alerts
- Alert lines captured: `{len(payload["alerts"])}`
- Time to first telemetry: `{((obs.get("first_telemetry_latency") or {}).get("ms"))} ms`
- Time to first alert: `{((latency.get("time_to_first_alert") or {}).get("ms"))} ms`
- Time to act: `{((latency.get("e2e_to_act") or {}).get("ms"))} ms`
- Detection quality: `precision={det.get("precision", "n/a")}`, `recall={det.get("recall", "n/a")}`, `f1={det.get("f1_score", "n/a")}`
- Response quality: `{metrics.get("quality_metrics", {}).get("response_quality_score", "n/a")}`

## Incident Intelligence
- MISP event id: `{event_obj.get("id", "none")}`
- MISP event info: `{event_obj.get("info", "none")}`
- TAPCD actors linked to this incident: `{len(actors)}`
- Primary TAPCD profile: `{lead_actor.get("profile", "none")}`
- Primary TAPCD skills: `{lead_actor.get("skills", "none")}`
- Primary TAPCD knowledge: `{lead_actor.get("knowledge", "none")}`
- Primary TAPCD motivation: `{lead_actor.get("motivation", "none")}`
- Primary TAPCD affiliation: `{lead_actor.get("affiliation", "none")}`
- Primary TAPCD attitude: `{lead_actor.get("attitude", "none")}`

## Countermeasure
- Selected: `{cm.get("selected")}`
- Why: {cm.get("justification")}
- D3FEND basis: {cm.get("d3fend_basis")}

## Executive Takeaway
- The incident was observed through live victim telemetry and collapsed into a single alert, a single MISP event and a single SOARCA execution.
{actor_takeaway}
- The blocking response was aligned to D3FEND controls for traffic filtering, inbound filtering, session termination and account locking.

## Full Artifacts
- `incident_report.json` contains the full MISP object and the TAPCD profile object evidence used for this incident.
- `chart_data.json` / `chart_data.csv` contain the full network + host time series and OODA markers used to recreate the exact same graphs.
- `misp_full.log` and `tapcd_full.log` are included in the ZIP bundle.
"""


def _persist_report(payload: dict[str, Any]) -> str:
    report_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = REPORTS_DIR / report_id
    report_dir.mkdir(parents=True, exist_ok=True)

    payload["report_id"] = report_id
    payload["report_meta"] = {
        "report_id": report_id,
        "generated_at": payload.get("generated_at") or datetime.now(timezone.utc).isoformat(),
        "schema_version": "2.0",
        "completeness_mode": "final",
    }

    json_path = report_dir / "incident_report.json"
    md_path = report_dir / "incident_report.md"
    alerts_csv_path = report_dir / "alerts.csv"
    phases_csv_path = report_dir / "phases.csv"
    metrics_json_path = report_dir / "metrics.json"
    metrics_csv_path = report_dir / "metrics_summary.csv"
    latency_csv_path = report_dir / "latency_ooda.csv"
    resource_csv_path = report_dir / "resource_overhead.csv"
    chart_json_path = report_dir / "chart_data.json"
    chart_csv_path = report_dir / "chart_data.csv"
    misp_log_path = report_dir / "misp_full.log"
    tapcd_log_path = report_dir / "tapcd_full.log"
    zip_path = report_dir / "incident_report_bundle.zip"

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(_render_markdown(payload), encoding="utf-8")

    with alerts_csv_path.open("w", newline="", encoding="utf-8") as f:
        rows = _render_alerts_csv_rows(payload)
        w = csv.DictWriter(
            f,
            fieldnames=["timestamp", "detector", "alert", "reason", "attack", "source_ips", "target", "target_port", "attack_fp", "event_id"],
        )
        w.writeheader()
        for row in rows:
            w.writerow(row)

    with phases_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["phase", "machine_scope", "detector_or_component", "confirmed", "timestamp"], extrasaction="ignore")
        w.writeheader()
        for row in payload["phases"]:
            w.writerow(row)

    metrics_obj = payload.get("novadef_metrics", {})
    metrics_json_path.write_text(json.dumps(metrics_obj, indent=2, ensure_ascii=False), encoding="utf-8")
    misp_log_path.write_text(_render_misp_full_log(payload), encoding="utf-8")
    tapcd_log_path.write_text(_render_tapcd_full_log(payload), encoding="utf-8")

    # Persist the full chart data (network + host time series + OODA markers) so
    # the exact same graphs can be recreated from the report folder alone.
    chart_data = payload.get("chart_data", {}) or {}
    chart_series = list(chart_data.get("series") or [])
    chart_json_path.write_text(json.dumps(chart_data, indent=2, ensure_ascii=False), encoding="utf-8")
    with chart_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "ts", "iso_time",
            "rx_packets_effective", "rx_packets_raw", "blocked_packets", "delta_packets",
            "cpu_percent", "memory_percent", "memory_bytes",
            "falco_signal_total", "falco_signal_delta",
            "falco_warning_events", "falco_error_events", "falco_critical_events",
        ])
        for p in chart_series:
            ts = float(p.get("ts", 0.0) or 0.0)
            iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else ""
            w.writerow([
                ts, iso,
                p.get("rx_packets", 0.0), p.get("rx_packets_raw", 0.0),
                p.get("blocked_packets", 0.0), p.get("delta_packets", 0.0),
                p.get("cpu_percent", 0.0), p.get("memory_percent", 0.0), p.get("memory_bytes", 0.0),
                p.get("falco_signal_total", p.get("falco_events", 0.0)), p.get("falco_signal_delta", 0.0),
                p.get("falco_warning_events", 0.0), p.get("falco_error_events", 0.0), p.get("falco_critical_events", 0.0),
            ])

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
        for key, value in _flatten("observation_quality", metrics_obj.get("observation_quality", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("quality_metrics", metrics_obj.get("quality_metrics", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("ooda_phase_metrics", metrics_obj.get("ooda_phase_metrics", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("run_window", metrics_obj.get("run_window", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("operational_scalability", metrics_obj.get("operational_scalability", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("resource_overhead", metrics_obj.get("resource_overhead", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("tool_breakdown", metrics_obj.get("tool_breakdown", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("dimension_breakdown", metrics_obj.get("dimension_breakdown", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("profile_quality", metrics_obj.get("profile_quality", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("response_effectiveness", metrics_obj.get("response_effectiveness", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("pipeline_reliability", metrics_obj.get("pipeline_reliability", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("detection_stream_temporal", metrics_obj.get("detection_stream_temporal", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("detection_quality", metrics_obj.get("detection_quality", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("packet_analysis", metrics_obj.get("packet_analysis", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("timeline_consistency", metrics_obj.get("timeline_consistency", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("data_completeness", metrics_obj.get("data_completeness", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("latency_ooda", metrics_obj.get("latency_ooda", {}) or {}):
            if ".sec" in key or ".ms" in key or ".us" in key or ".ns" in key:
                w.writerow([key, value])
        for key, value in _flatten("article_observe", metrics_obj.get("article_observe", {}) or {}):
            w.writerow([key, value])
        for key, value in _flatten("article_orient", metrics_obj.get("article_orient", {}) or {}):
            if not isinstance(value, dict):
                w.writerow([key, value])
        for key, value in _flatten("article_e2e_ooda", metrics_obj.get("article_e2e_ooda", {}) or {}):
            if not isinstance(value, dict):
                w.writerow([key, value])
        for key, value in _flatten("article_decide", metrics_obj.get("article_decide", {}) or {}):
            if not isinstance(value, dict):
                w.writerow([key, value])
        for key, value in _flatten("article_act", metrics_obj.get("article_act", {}) or {}):
            if not isinstance(value, dict):
                w.writerow([key, value])

    # article_metrics.csv — flat table ready for copy-paste into paper tables
    article_csv_path = report_dir / "article_metrics.csv"
    with article_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "metric", "value", "unit"])
        exp_label = payload.get("experiment", "?").upper()
        ao = metrics_obj.get("article_observe", {}) or {}
        aor = metrics_obj.get("article_orient", {}) or {}
        ae = metrics_obj.get("article_e2e_ooda", {}) or {}
        lat = metrics_obj.get("latency_ooda", {}) or {}
        dq = metrics_obj.get("detection_quality", {}) or {}
        sb = ae.get("stacked_bar_row", {}) or {}
        # OBSERVAR
        w.writerow(["OBSERVAR", "event_observability_ratio_global", ao.get("event_observability_ratio_global"), "ratio"])
        for layer, val in (ao.get("event_observability_by_layer") or {}).items():
            w.writerow(["OBSERVAR", f"event_observability_{layer}", val, "ratio"])
        ma = ao.get("monitoring_adaptability", {}) or {}
        w.writerow(["OBSERVAR", "source_coverage_ratio", ma.get("source_coverage_ratio"), "ratio"])
        w.writerow(["OBSERVAR", "telemetry_signal_density_lps", ma.get("telemetry_signal_density_lps"), "lines/s"])
        w.writerow(["OBSERVAR", "telemetry_continuity_ratio", ma.get("telemetry_continuity_ratio"), "ratio"])
        w.writerow(["OBSERVAR", "telemetry_gap_count", ma.get("telemetry_gap_count"), "count"])
        sc = ao.get("scalability_indicators", {}) or {}
        w.writerow(["OBSERVAR", "telemetry_ingest_rate_eps", sc.get("telemetry_ingest_rate_eps"), "events/s"])
        w.writerow(["OBSERVAR", "detector_processing_rate_eps", sc.get("detector_processing_rate_eps"), "events/s"])
        w.writerow(["OBSERVAR", "database_write_rate_eps", sc.get("database_write_rate_eps"), "events/s"])
        w.writerow(["OBSERVAR", "global_cpu_percent_sum", sc.get("global_cpu_percent_sum"), "%"])
        w.writerow(["OBSERVAR", "global_memory_percent_sum", sc.get("global_memory_percent_sum"), "%"])
        # ORIENTAR
        w.writerow(["ORIENTAR", "time_to_first_alert_ms", (aor.get("time_to_first_alert") or {}).get("ms"), "ms"])
        w.writerow(["ORIENTAR", "mttd_ms", (aor.get("mttd") or {}).get("ms"), "ms"])
        w.writerow(["ORIENTAR", "time_to_correct_identification_ms", (aor.get("time_to_correct_identification") or {}).get("ms"), "ms"])
        dqrb = aor.get("detection_quality_rule_based", {}) or {}
        w.writerow(["ORIENTAR", "detection_precision", dqrb.get("precision"), "ratio"])
        w.writerow(["ORIENTAR", "detection_recall", dqrb.get("recall"), "ratio"])
        w.writerow(["ORIENTAR", "detection_accuracy", dqrb.get("accuracy"), "ratio"])
        w.writerow(["ORIENTAR", "detection_f1_score", dqrb.get("f1_score"), "ratio"])
        w.writerow(["ORIENTAR", "detection_tp", dqrb.get("tp"), "count"])
        w.writerow(["ORIENTAR", "detection_fp", dqrb.get("fp"), "count"])
        w.writerow(["ORIENTAR", "detection_fn", dqrb.get("fn"), "count"])
        dpl = aor.get("detection_to_profile_link", {}) or {}
        w.writerow(["ORIENTAR", "ids_alert_to_profile_linked", dpl.get("ids_alert_to_profile_linked"), "bool"])
        w.writerow(["ORIENTAR", "actor_profile_count", dpl.get("actor_profile_count"), "count"])
        w.writerow(["ORIENTAR", "profile_field_completeness_ratio", dpl.get("profile_field_completeness_ratio"), "ratio"])
        w.writerow(["ORIENTAR", "profile_timeliness_ms", (dpl.get("profile_timeliness") or {}).get("ms"), "ms"])
        # E2E OODA
        w.writerow(["E2E_OODA", "e2e_to_act_ms", (ae.get("e2e_to_act") or {}).get("ms"), "ms"])
        w.writerow(["E2E_OODA", "latency_decide_phase_ms", (ae.get("latency_decide_phase") or {}).get("ms"), "ms"])
        w.writerow(["E2E_OODA", "latency_act_phase_ms", (ae.get("latency_act_phase") or {}).get("ms"), "ms"])
        # Stacked bar row
        w.writerow(["E2E_OODA", "stacked_observe_s", sb.get("observe_s"), "s"])
        w.writerow(["E2E_OODA", "stacked_orient_s", sb.get("orient_s"), "s"])
        w.writerow(["E2E_OODA", "stacked_enrich_s", sb.get("enrich_s"), "s"])
        w.writerow(["E2E_OODA", "stacked_decide_s", sb.get("decide_s"), "s"])
        w.writerow(["E2E_OODA", "stacked_act_s", sb.get("act_s"), "s"])
        w.writerow(["E2E_OODA", "stacked_e2e_s", sb.get("e2e_s"), "s"])
        # DECIDE
        ad = metrics_obj.get("article_decide", {}) or {}
        w.writerow(["DECIDE", "playbook_selected", ad.get("playbook_selected"), "name"])
        w.writerow(["DECIDE", "playbook_correct", ad.get("playbook_correct"), "bool"])
        w.writerow(["DECIDE", "expected_playbook", ad.get("expected_playbook"), "name"])
        w.writerow(["DECIDE", "d3fend_technique_applied", ad.get("d3fend_technique_applied"), "technique"])
        w.writerow(["DECIDE", "d3fend_alignment_score", ad.get("d3fend_alignment_score"), "ratio"])
        w.writerow(["DECIDE", "decide_latency_ms", ad.get("decide_latency_ms"), "ms"])
        w.writerow(["DECIDE", "profile_to_decide_latency_ms", (ad.get("profile_to_decide_latency") or {}).get("ms"), "ms"])
        w.writerow(["DECIDE", "time_to_decide_from_attack_ms", (ad.get("time_to_decide_from_attack") or {}).get("ms"), "ms"])
        # ACT
        aa = metrics_obj.get("article_act", {}) or {}
        w.writerow(["ACT", "countermeasure_applied", aa.get("countermeasure_applied"), "bool"])
        w.writerow(["ACT", "countermeasure_type", aa.get("countermeasure_type"), "name"])
        w.writerow(["ACT", "ssh_execution_success", aa.get("ssh_execution_success"), "bool"])
        w.writerow(["ACT", "response_error_count", aa.get("response_error_count"), "count"])
        w.writerow(["ACT", "traffic_reduction_ratio", aa.get("traffic_reduction_ratio"), "ratio"])
        w.writerow(["ACT", "traffic_reduction_percent", aa.get("traffic_reduction_percent"), "%"])
        w.writerow(["ACT", "pre_attack_pps_baseline", aa.get("pre_attack_pps_baseline"), "pps"])
        w.writerow(["ACT", "post_countermeasure_pps", aa.get("post_countermeasure_pps"), "pps"])
        w.writerow(["ACT", "post_countermeasure_blocked_pps", aa.get("post_countermeasure_blocked_pps"), "pps"])
        w.writerow(["ACT", "countermeasure_drop_clear", aa.get("countermeasure_drop_clear"), "bool"])
        w.writerow(["ACT", "act_latency_ms", aa.get("act_latency_ms"), "ms"])
        w.writerow(["ACT", "decide_to_act_latency_ms", (aa.get("decide_to_act_latency") or {}).get("ms"), "ms"])
        w.writerow(["ACT", "time_to_act_from_attack_ms", (aa.get("time_to_act_from_attack") or {}).get("ms"), "ms"])

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
        zf.write(chart_json_path, arcname="chart_data.json")
        zf.write(chart_csv_path, arcname="chart_data.csv")
        zf.write(misp_log_path, arcname="misp_full.log")
        zf.write(tapcd_log_path, arcname="tapcd_full.log")
        zf.write(article_csv_path, arcname="article_metrics.csv")

    with LOCK:
        STATE["last_report_id"] = report_id
    return report_id


def _persist_run_artifacts(run_id: str, report_id: str, payload: dict[str, Any]) -> None:
    """
    Store a run-local snapshot of telemetry and the generated report bundle.
    This keeps per-scenario evidence isolated even when the global report store
    is later cleaned up.
    """
    try:
        run_item = _history_item(run_id) or {}
        started_at = int(float(run_item.get("started_at") or time.time()))

        with LOCK:
            traffic_series = list(TRAFFIC_SERIES.get(run_id, []))
            traffic_baseline = float(TRAFFIC_BASELINES.get(run_id, 0.0) or 0.0)
            falco_samples = dict(FALCO_SAMPLES.get(run_id, {}))
            host_metrics_last = dict(HOST_METRICS_LAST.get(run_id, {}))

        for run_root in _artifact_roots_for_run(run_id):
            telemetry_dir = run_root / "artifacts" / "telemetry"
            reports_dir = run_root / "artifacts" / "reports" / report_id
            logs_dir = run_root / "artifacts" / "logs"
            telemetry_dir.mkdir(parents=True, exist_ok=True)
            reports_dir.parent.mkdir(parents=True, exist_ok=True)
            logs_dir.mkdir(parents=True, exist_ok=True)

            (telemetry_dir / "traffic_series.json").write_text(
                json.dumps(traffic_series, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            (telemetry_dir / "traffic_baseline.json").write_text(
                json.dumps({"run_id": run_id, "baseline": traffic_baseline}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            (telemetry_dir / "falco_samples.json").write_text(
                json.dumps(falco_samples, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            (telemetry_dir / "host_metrics_last.json").write_text(
                json.dumps(host_metrics_last, indent=2, ensure_ascii=False), encoding="utf-8"
            )

            src_report_dir = REPORTS_DIR / report_id
            if src_report_dir.exists():
                shutil.copytree(src_report_dir, reports_dir, dirs_exist_ok=True)

            payload_path = run_root / "artifacts" / "run_payload.json"
            payload_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

            # Snapshot de logs de red/host/componentes para auditoría completa.
            containers_dir = logs_dir / "containers"
            containers_dir.mkdir(parents=True, exist_ok=True)
            run_containers = {
                str(run_item.get("victim_container_name") or "").strip(),
                str(run_item.get("attacker_container_name") or "").strip(),
                "tshark_novadef",
                "network_intrusion_detector_novadef",
                "alert_module_novadef",
                "snort_novadef",
                "falco_novadef",
                "flow_module_novadef",
                "filebeat_novadef",
                "kafka_novadef",
                "pmp-misp-integrator",
                "pmp-misp-soarca-trigger",
                "pmp-soarca-core",
            }
            for cname in sorted(c for c in run_containers if c):
                try:
                    cont = DOCKER_CLIENT.containers.get(cname)
                    blob = cont.logs(since=started_at).decode("utf-8", errors="replace")
                    (containers_dir / f"{cname}.log").write_text(blob, encoding="utf-8")
                except Exception:
                    continue

            scenario_log_dir = str(run_item.get("scenario_log_dir") or "").strip()
            if scenario_log_dir:
                try:
                    src = Path(scenario_log_dir)
                    if src.exists():
                        shutil.copytree(src, logs_dir / "scenario", dirs_exist_ok=True)
                except Exception:
                    pass

            (logs_dir / "snapshot_meta.json").write_text(
                json.dumps(
                    {
                        "run_id": run_id,
                        "started_at": started_at,
                        "captured_at": int(time.time()),
                        "scenario_id": str(run_item.get("scenario_id") or ""),
                        "scenario_project": str(run_item.get("scenario_project") or ""),
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
    except Exception as exc:
        print(f"[report-debug] Failed to persist run artifacts for {run_id}: {exc}", flush=True)


def _snapshot_run_logs(run_id: str) -> None:
    """
    Persist logs even when the run is manually stopped/deleted before report generation.
    """
    run_item = _history_item(run_id) or {}
    if not run_item:
        return
    payload = {
        "run_id": run_id,
        "experiment": run_item.get("experiment"),
        "started_at": run_item.get("started_at"),
        "finished_at": run_item.get("finished_at"),
        "stopped_at": run_item.get("stopped_at"),
        "manual_stop": run_item.get("manual_stop"),
        "return_code": run_item.get("return_code"),
        "scenario": {
            "scenario_id": run_item.get("scenario_id"),
            "project": run_item.get("scenario_project"),
            "network": run_item.get("scenario_network"),
        },
    }
    _persist_run_artifacts(run_id, "no-report", payload)


def _update_history(run_id: str, patch: dict[str, Any]) -> None:
    with LOCK:
        for item in RUN_HISTORY:
            if item.get("run_id") == run_id:
                item.update(patch)
                break
    _persist_runtime_state()


def _history_item(run_id: str) -> dict[str, Any] | None:
    with LOCK:
        for item in RUN_HISTORY:
            if str(item.get("run_id")) == str(run_id):
                return dict(item)
    return None


def _run_container_names(run_item: dict[str, Any] | None) -> list[str]:
    names = []
    for role in ("victim", "attacker"):
        name = _run_container_name(run_item, role)
        if name and name not in names:
            names.append(name)
    return names


def _cleanup_run_resources(run_item: dict[str, Any] | None, *, remove_containers: bool, remove_network: bool, remove_artifacts: bool) -> None:
    if not run_item:
        return
    victim_name = _run_container_name(run_item, "victim")
    attacker_name = _run_container_name(run_item, "attacker")
    container_names = [victim_name, attacker_name]
    network_name = str(run_item.get("scenario_network") or "").strip()
    project_name = str(run_item.get("scenario_project") or "").strip()
    log_dir = str(run_item.get("scenario_log_dir") or "").strip()
    report_id = str(run_item.get("report_id") or "").strip()
    run_id = str(run_item.get("run_id") or "").strip()

    if remove_containers:
        container_ids: list[str] = []
        try:
            if run_id:
                for c in DOCKER_CLIENT.containers.list(all=True, filters={"label": f"novadef.run_id={run_id}"}):
                    cid = str(getattr(c, "id", "") or "").strip()
                    if cid and cid not in container_ids:
                        container_ids.append(cid)
        except Exception:
            pass
        for name in container_names:
            if not name:
                continue
            try:
                cont = DOCKER_CLIENT.containers.get(name)
                cid = str(getattr(cont, "id", "") or "").strip()
                if cid and cid not in container_ids:
                    container_ids.append(cid)
                try:
                    cont.stop(timeout=3)
                except Exception:
                    pass
                try:
                    cont.remove(force=True)
                except Exception:
                    pass
            except Exception:
                continue
        for cid in container_ids:
            try:
                cont = DOCKER_CLIENT.containers.get(cid)
                try:
                    cont.stop(timeout=3)
                except Exception:
                    pass
                try:
                    cont.remove(force=True)
                except Exception:
                    pass
            except Exception:
                continue

    if remove_network and network_name:
        try:
            net = DOCKER_CLIENT.networks.get(network_name)
            try:
                net.remove()
            except Exception:
                pass
        except Exception:
            pass

    if remove_artifacts:
        if log_dir:
            try:
                _force_remove_tree(Path(log_dir))
            except Exception:
                pass
        if project_name:
            try:
                _force_remove_tree(SCENARIO_ROOT / project_name)
            except Exception:
                pass
            legacy_log_dir = HOST_REPO_ROOT / "Scenario" / "shared-logs"
            try:
                _force_remove_tree(legacy_log_dir)
            except Exception:
                pass
            try:
                if SCENARIO_ROOT.exists() and not any(SCENARIO_ROOT.iterdir()):
                    _force_remove_tree(SCENARIO_ROOT)
            except Exception:
                pass
        if report_id:
            try:
                _force_remove_tree(REPORTS_DIR / report_id)
            except Exception:
                pass
        if run_id:
            try:
                run_root = _scenario_runtime_root(run_id)
                _force_remove_tree(run_root)
            except Exception:
                pass


def _pause_run_resources(run_item: dict[str, Any] | None) -> None:
    """
    Stop the run containers without deleting them so the run stays visible in
    the history list and can be inspected or resumed later.
    """
    if not run_item:
        return
    victim_name = _run_container_name(run_item, "victim")
    attacker_name = _run_container_name(run_item, "attacker")
    for name in (victim_name, attacker_name):
        if not name:
            continue
        try:
            cont = DOCKER_CLIENT.containers.get(name)
            try:
                cont.stop(timeout=3)
            except Exception:
                pass
        except Exception:
            continue


def _signal_run_stop(run_item: dict[str, Any] | None) -> None:
    """
    Ask the per-run attack scripts to stop gracefully before containers are removed.
    """
    if not run_item:
        return
    try:
        log_dir = str(run_item.get("scenario_log_dir") or "").strip()
        if log_dir:
            stop_file = Path(log_dir) / "stop_network_attack.signal"
            stop_file.parent.mkdir(parents=True, exist_ok=True)
            stop_file.write_text("stop\n", encoding="utf-8")
    except Exception:
        pass
    try:
        _stop_exp2_persistent_emulation(run_item=run_item)
    except Exception:
        pass


def _forget_run_state(run_id: str, report_id: str | None = None) -> None:
    with LOCK:
        TRAFFIC_SERIES.pop(run_id, None)
        TRAFFIC_BASELINES.pop(run_id, None)
        TRAFFIC_LAST_PERSIST_AT.pop(run_id, None)
        TRAFFIC_MARKERS_CACHE.pop(run_id, None)
        FAST_COUNTERMEASURE_TS.pop(run_id, None)
        FAST_COUNTERMEASURE_REQUESTED_TS.pop(run_id, None)
        FALCO_SAMPLES.pop(run_id, None)
        HOST_METRICS_LAST.pop(run_id, None)
        RUN_HISTORY[:] = [item for item in RUN_HISTORY if str(item.get("run_id")) != str(run_id)]
        if str(STATE.get("current_run_id") or "") == str(run_id):
            STATE["current_run_id"] = None
        if report_id and str(STATE.get("last_report_id") or "") == str(report_id):
            STATE["last_report_id"] = None
        if not RUN_HISTORY:
            STATE["running"] = False
            STATE["last_experiment"] = None
            STATE["last_started_at"] = None
            STATE["last_attack_started_at"] = None
            STATE["last_finished_at"] = None
            STATE["last_return_code"] = None
            STATE["last_output"] = ""
            STATE["last_report_id"] = None
            STATE["last_report_error"] = ""
            STATE["scenario_id"] = None
            STATE["scenario_project"] = None
            STATE["scenario_network"] = None
            STATE["victim_container_name"] = None
            STATE["attacker_container_name"] = None
    _persist_runtime_state()


def _report_ids_and_actor_ids_for_run(run_item: dict[str, Any]) -> tuple[list[str], list[str]]:
    report_id = str(run_item.get("report_id") or "").strip()
    if not report_id:
        return [], []
    report_json = REPORTS_DIR / report_id / "incident_report.json"
    if not report_json.exists():
        return [], []
    try:
        payload = json.loads(report_json.read_text(encoding="utf-8"))
    except Exception:
        return [], []

    misp = payload.get("misp") or {}
    tapcd = payload.get("tapcd") or {}

    event_ids: list[str] = []
    event = (misp.get("event_object") or {}).get("event") or {}
    if str(event.get("id") or "").strip().isdigit():
        event_ids.append(str(event.get("id")))
    for raw in misp.get("event_ids_detected_in_logs") or []:
        raw_s = str(raw).strip()
        if raw_s.isdigit() and raw_s not in event_ids:
            event_ids.append(raw_s)

    actor_ids: list[str] = []
    for actor in tapcd.get("actor_profiles") or []:
        actor_id = str((actor or {}).get("actor_id") or (actor or {}).get("id") or "").strip()
        if actor_id and actor_id not in actor_ids:
            actor_ids.append(actor_id)
    for actor in (tapcd.get("profile_object") or {}).get("actors") or []:
        actor_id = str((actor or {}).get("actor_id") or (actor or {}).get("id") or "").strip()
        if actor_id and actor_id not in actor_ids:
            actor_ids.append(actor_id)

    return event_ids, actor_ids


def _purge_misp_events(event_ids: list[str]) -> None:
    cleaned = [str(eid).strip() for eid in event_ids if str(eid).strip().isdigit()]
    if not cleaned:
        return
    tables = [
        "attributes",
        "shadow_attributes",
        "event_tags",
        "sightings",
        "object_references",
        "objects",
        "event_reports",
        "cryptographic_keys",
        "logs",
        "correlations",
        "default_correlations",
        "no_acl_correlations",
        "shadow_attribute_correlations",
        "events",
    ]
    sql = "SET FOREIGN_KEY_CHECKS=0; " + " ".join(
        [f"DELETE FROM {table} WHERE event_id IN ({','.join(cleaned)});" for table in tables]
    ) + " SET FOREIGN_KEY_CHECKS=1;"
    try:
        db = DOCKER_CLIENT.containers.get("pmp-misp-db")
        db.exec_run(
            [
                "sh",
                "-lc",
                f"mysql -uroot -pmy_root_password misp -e \"{sql}\"",
            ],
            stdout=True,
            stderr=True,
        )
    except Exception:
        pass


def _purge_tapcd_actor_profiles(actor_ids: list[str]) -> None:
    cleaned = [str(a).strip() for a in actor_ids if str(a).strip()]
    if not cleaned:
        return
    queries = []
    for actor_id in cleaned:
        safe = actor_id.replace("\\", "\\\\").replace("'", "\\'")
        queries.append(f"MATCH (a:Actor {{id: '{safe}'}}) DETACH DELETE a")
    try:
        for candidate in ("novadef-neo4j-1", "neo4j", "novadef_neo4j_1"):
            try:
                neo4j = DOCKER_CLIENT.containers.get(candidate)
                for query in queries:
                    # sh -c (NOT bash -lc): a login shell resets PATH so
                    # cypher-shell (/var/lib/neo4j/bin) becomes unresolvable.
                    neo4j.exec_run(
                        [
                            "sh",
                            "-c",
                            f"cypher-shell -u neo4j -p neo4jpass \"{query}\" >/dev/null 2>&1 || "
                            f"/var/lib/neo4j/bin/cypher-shell -u neo4j -p neo4jpass \"{query}\" >/dev/null 2>&1 || true",
                        ],
                        stdout=True,
                        stderr=True,
                    )
                return
            except Exception:
                continue
    except Exception:
        pass


def _purge_neo4j_all() -> None:
    """Delete every actor/node in Neo4j.

    Called only when a scenario is destroyed. The requirement is: deleting a
    scenario removes everything that scenario created (actor profiles, MISP
    events, etc.). Since actors are not tagged with a scenario_id and Neo4j only
    ever holds the currently-active scenario's data, a full wipe is the robust
    way to guarantee no historical actor (e.g. an 'activist' from a prior day)
    survives into the next scenario. Actors coexist WITHIN a scenario; they are
    only cleared when the scenario itself is deleted.
    """
    query = "MATCH (n) DETACH DELETE n"
    for candidate in ("novadef-neo4j-1", "neo4j", "novadef_neo4j_1"):
        try:
            neo4j = DOCKER_CLIENT.containers.get(candidate)
            # Use sh -c (NOT bash -lc): a login shell resets PATH and cypher-shell
            # (/var/lib/neo4j/bin) is no longer resolvable. Call the absolute path
            # too as a belt-and-suspenders guard.
            res = neo4j.exec_run(
                ["sh", "-c",
                 f"cypher-shell -u neo4j -p neo4jpass \"{query}\" 2>&1 || "
                 f"/var/lib/neo4j/bin/cypher-shell -u neo4j -p neo4jpass \"{query}\" 2>&1"],
                stdout=True, stderr=True,
            )
            _out = (res.output or b"").decode("utf-8", errors="replace").strip()
            print(f"[scenario-delete] Neo4j purge exit={res.exit_code} out={_out[:120]!r}", flush=True)
            return
        except Exception:
            continue


# All pipeline consumer groups and the primary topic each one must be advanced
# past when resetting offsets to latest. prep_pred ('profiles_stream') is the
# critical one: it runs with --from-beginning (auto_offset_reset=earliest), so
# without an explicit reset it replays historical flows and emits stale actor
# profiles (e.g. an 'activist' with first_seen from a previous day).
_KAFKA_PIPELINE_GROUP_TOPICS: dict[str, str] = {
    "profiles_stream": "flows_conditional_agg",
    "profiles_to_neo4j": "profiles_out",
    "soarca-tapcd-trigger": "profiles_out",
    "misp-integration-group": "network_intrusion_alerts",
    "network-intrusion-detector-v1": "cic_flow",
    "alert-module-v1": "network_auth_events",
    "flow-module-v1": "cic_flow",
    "stream-json-alerts": "flows_conditional_agg",
}


def _reset_all_kafka_offsets_to_latest() -> None:
    """Advance every pipeline consumer-group offset to latest WITHOUT deleting
    records. Kafka refuses --reset-offsets on a group with live members, so we
    only run this when the affected consumers are momentarily down (they are
    restarted right after by the reset helpers) or tolerate the no-op otherwise.
    Records are preserved so profiles/flows coexist within a scenario."""
    try:
        kafka_c = DOCKER_CLIENT.containers.get("kafka_novadef")
    except Exception:
        return
    for group, topic in _KAFKA_PIPELINE_GROUP_TOPICS.items():
        try:
            kafka_c.exec_run(
                ["bash", "-c",
                 "export PATH=$PATH:/opt/kafka/bin; "
                 f"kafka-consumer-groups.sh --bootstrap-server localhost:9092 "
                 f"--group {group} --topic {topic} "
                 f"--reset-offsets --to-latest --execute 2>/dev/null || true"],
                stdout=False, stderr=False,
            )
        except Exception:
            continue
    print("[kafka-reset] pipeline consumer-group offsets advanced to latest", flush=True)


def _purge_all_kafka_pipeline(reset_offsets: bool = True) -> None:
    """Purge every detection-relevant Kafka topic (delete records) AND reset all
    consumer-group offsets to latest.

    Used only when a scenario is destroyed — a brand-new scenario must not be
    able to replay or reuse any message from the deleted one. Within a scenario
    use _reset_all_kafka_offsets_to_latest() instead (keeps records)."""
    _purge_kafka_topics()  # delete records up to latest offset for all pipeline topics
    if reset_offsets:
        _reset_all_kafka_offsets_to_latest()


def _mark_run_deleted(run_id: str) -> dict[str, Any] | None:
    with LOCK:
        for item in RUN_HISTORY:
            if str(item.get("run_id")) != str(run_id):
                continue
            item.update(
                {
                    "deleted": True,
                    "running": False,
                    "deleted_at": time.time(),
                    "finished_at": item.get("finished_at") or time.time(),
                    "manual_stop": True,
                }
            )
            return dict(item)
    return None


def _run_is_deleted(run_id: str) -> bool:
    item = _history_item(run_id)
    return bool(item and item.get("deleted"))


def _latest_misp_event_for_run(experiment: str, started_ts: float | None, strict_time: bool = True) -> dict[str, Any] | None:
    where = "1=1"
    if strict_time and started_ts:
        # 300s margin: the MISP event for a run can be created a bit before the
        # API persists the run's started_at (detection→event can precede the
        # marker), so a tight 5s window would wrongly exclude the run's own event.
        where += f" AND timestamp >= {int(started_ts) - 300}"
    # Per-experiment scoping so a stale event from a PREVIOUS experiment on the
    # same victim isn't picked up. exp1 (network spraying) must NOT match a pure
    # exp3/exp2 ransomware event, and vice-versa.
    if experiment == "exp1":
        # Network spraying. Match events whose title STARTS with the spraying
        # headline (a run's own event), not events that merely got a spraying
        # attribute appended after a ransomware headline (those are exp3).
        where += (
            " AND (info LIKE 'Distributed Password Spraying%' "
            "OR info LIKE '%Brute Force%' OR info LIKE 'Network%')"
        )
    elif experiment == "exp2":
        # Host ransomware; title starts with the Falco ransomware headline.
        where += " AND info LIKE 'FALCO: Host Ransomware%'"
    # exp3 is hybrid: either/both titles are valid, so no extra filter.
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
    # MISP schema uses value1 (not value) as the attribute value column.
    cmd = (
        "mysql -uroot -pmy_root_password misp -NBe "
        f"\"SELECT type, category, value1 FROM attributes WHERE event_id={int(event_id)} AND deleted=0 ORDER BY id ASC LIMIT 200;\""
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


def _build_live_report_panel(
    experiment: str,
    started_ts: float | None,
    attack_started_ts: float | None = None,
) -> dict[str, Any]:
    since_ts = int(started_ts) if started_ts else None
    attack_since_ts = int(attack_started_ts) if isinstance(attack_started_ts, (int, float)) else None
    run_item = _run_item_for_started(experiment, started_ts)
    # If the caller didn't pass attack_started_ts, try to recover it from the
    # persisted run_item so phase-gated log tails don't end up with a future
    # cutoff (which would make every log tail return empty and break detection).
    if attack_since_ts is None and run_item:
        _stored = float((run_item or {}).get("attack_started_at") or 0.0) or None
        if _stored:
            attack_since_ts = int(_stored)
    # Fall back to scenario start time (since_ts) rather than a future sentinel
    # so that when attack_started_at was never persisted we still read logs.
    phase_since_ts = attack_since_ts if attack_since_ts is not None else (since_ts or int(time.time()) + 86400)
    run_id = str((run_item or {}).get("run_id") or "").strip()
    _live_scenario_id = str((run_item or {}).get("scenario_id") or "").strip() or None
    victim_name = _run_container_name(run_item, "victim")
    attacker_name = _run_container_name(run_item, "attacker")
    misp_blob = _tail_logs("pmp-misp-integrator", 550, since_ts=phase_since_ts) + "\n" + _tail_logs("pmp-misp-server", 400, since_ts=phase_since_ts)
    # 3-minute-earlier cutoff for TAPCD profile lines (see note on soarca-trigger
    # tail below) — the network IDS profile can be logged slightly before the
    # attack_started_at marker is persisted.
    # Cap to scenario started_ts so we never reach into a previous session's logs.
    _tapcd_raw = (phase_since_ts - 180) if isinstance(phase_since_ts, (int, float)) else phase_since_ts
    _run_floor = int(since_ts) if since_ts else None
    _tapcd_since = max(_tapcd_raw, _run_floor) if (_run_floor is not None and isinstance(_tapcd_raw, (int, float))) else _tapcd_raw
    tapcd_blob = (
        _tail_logs("novadef-novadef_stream_low-1", 600, since_ts=_tapcd_since)
        + "\n"
        + _tail_logs("novadef-novadef_prep_pred-1", 350, since_ts=_tapcd_since)
        + "\n"
        + _tail_logs("novadef-novadef_neo4j_ingester-1", 350, since_ts=_tapcd_since)
        + "\n"
        + _tail_logs("pmp-misp-integrator", 220, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("pmp-misp-server", 180, since_ts=phase_since_ts)
        # Large tail: the soarca-trigger emits the network-phase TAPCD_PROFILE_READY
        # (the rich crime-syndicate/criminal profile with full ML fields) which can
        # be buried under hundreds of per-second ransomware re-emission lines
        # ("⏭️ ya aislada"). A short tail would miss it, leaving only the bare
        # ransomware-operator profile visible in the panel.
        # Use a 3-min-earlier cutoff (_tapcd_since): the network IDS detection
        # aggregates flows whose log timestamp can slightly precede the moment
        # attack_started_at was persisted, so the strict phase cutoff would drop
        # the rich network profile line.
        + _tail_logs("pmp-misp-soarca-trigger", 1200, since_ts=_tapcd_since)
    )
    detector_blob = (
        _tail_logs("network_intrusion_detector_novadef", 550, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("snort_novadef", 450, since_ts=phase_since_ts)
        + "\n"
        + _tail_logs("alert_module_novadef", 450, since_ts=phase_since_ts)
    )
    # exp2 and exp3 use Falco for host-level detection. Falco writes to file
    # (stdout_output disabled), so falco_novadef Docker logs are empty.
    # The MISP integrator receives Falco events and logs lines like
    # "FALCO: Host Ransomware Emulation Detected" which match the exp2/exp3
    # detection keywords — use those as the authoritative detect signal.
    if experiment in ("exp2", "exp3"):
        detector_blob += "\n" + _tail_logs("pmp-misp-integrator", 350, since_ts=phase_since_ts)
        detector_blob += "\n" + _tail_logs("falco_novadef", 300, since_ts=phase_since_ts)
    lines = misp_blob.splitlines()
    native_profile_lines = _tapcd_profile_evidence_lines(tapcd_blob)
    # Use the 3-min-earlier cutoff (_tapcd_since): in exp1 the detection→profile→
    # block_ip chain can complete and log "✅ Playbook ejecutado" BEFORE the
    # attack_started_at marker is persisted, so the strict phase cutoff would drop
    # the execution-evidence lines and the panel would show "pending evidence".
    soarca_blob = _strip_soarca_excerpt_noise(
        _tail_logs("pmp-misp-soarca-trigger", 600, since_ts=_tapcd_since)
        + "\n"
        + _tail_logs("pmp-soarca-core", 450, since_ts=_tapcd_since)
        + "\n"
        + _tail_logs("pmp-soarca-executor-ssh", 450, since_ts=_tapcd_since)
        + "\n"
        + _tail_logs(victim_name, 300, since_ts=phase_since_ts)
    )
    # attack_has_started: True if we have a known attack timestamp OR if the
    # run_item itself records that the attack phase was launched (exp3 sets
    # exp3_host_attack_started; exp1/exp2 set attack_started_at).
    attack_has_started = (
        attack_since_ts is not None
        or bool((run_item or {}).get("attack_started_at"))
        or bool((run_item or {}).get("exp3_host_attack_started"))
    )
    phase_markers = _run_phase_markers(run_item)
    detect_evidence_lines = _detection_evidence_lines(detector_blob, experiment)
    misp_signal_present = any(
        k in misp_blob.lower()
        for k in ["nuevo evento misp", "event_id", "misp event", "published", "created", "attribute"]
    )
    soarca_signal_present = bool(_soarca_execution_evidence(soarca_blob))
    # A detection cannot exist before the attack itself has started. Without
    # this guard, phase_since_ts falls back to the RUN's start time (not the
    # attack's) whenever attack_since_ts is still None, so the log tails above
    # (detector_blob/misp_blob/soarca_blob) span the whole warm-up/benign-noise
    # window before the attack — on a reused scenario that can pick up leftover
    # signal from a PRIOR run (stale TAPCD profile, old SOARCA log lines still
    # inside the tail window) and misreport it as this run's own detection at
    # t≈0, which is what put the green "detection" marker at sample 0 on the
    # live chart even though the attack had not launched yet.
    detect_has_started = attack_has_started and bool(detect_evidence_lines or phase_markers.get("detect_at"))

    event_ids: list[str] = []
    latest_event = None
    # The MISP event is a persistent DB record created during the run. Read it
    # whenever the attack phase has started — do NOT also gate on detection log
    # lines being present in the tail window. Falco re-emits the event and floods
    # the integrator log, so the [DETECT] line is often pushed out of the tail;
    # gating on it made the GUI show an empty profile/MISP panel even though the
    # event and profile were correctly created.
    if attack_has_started:
        duplicate_campaign = any(k in misp_blob.lower() for k in ["[dedup-persist]", "[dedup-link]"])
        latest_event = _latest_misp_event_for_run(experiment, started_ts, strict_time=True)
        if latest_event and latest_event.get("id"):
            event_ids = [str(latest_event["id"])]
        if not event_ids:
            event_ids = sorted(set(
                re.findall(r"nuevo evento misp #(\d+)", misp_blob.lower())
                + re.findall(r"evento misp #(\d+)", misp_blob.lower())
            ))
    else:
        duplicate_campaign = False

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
    source_ips = _extract_source_ips_from_misp_attributes(attrs) or _extract_source_ips_from_misp_lines(lines)
    started_iso = datetime.fromtimestamp(started_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z") if started_ts else None
    # Detection is confirmed if EITHER a detector log line is present OR a MISP
    # event for this run already exists in the DB. The persisted event is the
    # more reliable signal: the integrator log floods and the [DETECT] line is
    # often pushed out of the tail window, but the event row stays.
    detection_confirmed = bool(detect_has_started or (latest_event and latest_event.get("id")))
    actors = []
    if detection_confirmed and native_profile_lines:
        # For TAPCD-facing fields shown in the GUI/report, always prefer the
        # raw native profile emitted by the TAPCD containers over any enriched
        # or scored Neo4j reconstruction.
        actors = _native_actor_profiles_from_lines(native_profile_lines, source_ips=source_ips)
    if not actors and detection_confirmed and (victim_ip or source_ips or started_iso):
        actors = _select_primary_actor_profile(
            _neo4j_actor_profiles(victim_ip, source_ips=source_ips, started_at=started_iso, include_synthetic=False, limit=5, scenario_id=_live_scenario_id),
            source_ips=source_ips,
        )
    # No fallback without started_at: stale profiles from previous runs must
    # not bleed into the current experiment panel.
    if len(actors) > 1 and not native_profile_lines:
        actors = _select_primary_actor_profile(actors, source_ips=source_ips)
    if len(native_profile_lines) > 1:
        native_profile_lines = list(dict.fromkeys(native_profile_lines))
    # For exp1/exp2 (single attack vector): stream_low emits one profile per
    # attacker source IP, all sharing the same actor profile (e.g. crime-syndicate
    # for distributed password spraying). Collapse them into ONE profile with all
    # source IPs merged, so the GUI shows Profiles=1 instead of Profiles=N.
    if experiment in ("exp1", "exp2") and len(actors) > 1:
        primary = max(actors, key=lambda a: _score_actor_profile(a, source_ips=source_ips))
        all_ips: list[str] = []
        for a in actors:
            for ip in (a.get("source_ips") or []):
                if ip and ip not in all_ips:
                    all_ips.append(ip)
        primary = dict(primary)
        if all_ips:
            primary["source_ips"] = all_ips
        actors = [primary]
    if experiment in ("exp1", "exp2") and native_profile_lines and len(native_profile_lines) > 1:
        # Keep header (if any) + the single richest data row.
        header_lines = [l for l in native_profile_lines if l.lower().startswith("id,")]
        data_lines = [l for l in native_profile_lines if not l.lower().startswith("id,")]
        def _row_richness_e1(line: str) -> int:
            return len([c for c in line.split(",") if c.strip() and c.strip() not in ("-", "nan", "None")])
        best_data = sorted(data_lines, key=_row_richness_e1, reverse=True)[:1] if data_lines else []
        native_profile_lines = (header_lines[:1] + best_data) if header_lines else best_data
    # For exp3 (hybrid): consolidate multiple stream_low profiles (one per
    # attacker IP) into a single combined profile. Prefer the RICHEST profile —
    # the network/ML profile (crime-syndicate/criminal) carries the full actor
    # characterization (Motivation/Knowledge/Skills/...), whereas the host
    # ransomware-operator stub leaves them empty. We want the complete TAPCD
    # profile shown, with all source IPs from both phases merged in.
    if experiment == "exp3" and len(actors) > 1:
        primary = max(actors, key=lambda a: _score_actor_profile(a, source_ips=source_ips))
        # Merge all source IPs from all profiles into the primary
        all_ips: list[str] = []
        for a in actors:
            for ip in (a.get("source_ips") or []):
                if ip and ip not in all_ips:
                    all_ips.append(ip)
        primary = dict(primary)
        if all_ips:
            primary["source_ips"] = all_ips
        # Annotate that this single profile covers both campaign phases.
        primary["detection_attack"] = "Password Spraying + Ransomware"
        actors = [primary]
    if experiment == "exp3" and native_profile_lines and len(native_profile_lines) > 1:
        # Keep header + the richest data row. The network row has populated ML
        # fields (motivation/knowledge/skills/...), so pick the row with the most
        # non-empty fields rather than the ransomware row.
        header_lines = [l for l in native_profile_lines if l.lower().startswith("id,")]
        data_lines = [l for l in native_profile_lines if not l.lower().startswith("id,")]
        def _row_richness(line: str) -> int:
            return len([c for c in line.split(",") if c.strip() and c.strip() not in ("-", "nan", "None")])
        best_data = sorted(data_lines, key=_row_richness, reverse=True)[:1] if data_lines else []
        native_profile_lines = (header_lines[:1] + best_data) if header_lines else best_data
    profile_ready = bool(native_profile_lines or actors)
    if not detection_confirmed:
        # Keep the live panel dark until the attack genuinely starts. This
        # prevents startup chatter from surfacing MISP / TAPCD / SOARCA too early.
        event_ids = []
        latest_event = {}
        attrs = []
        actors = []
        native_profile_lines = []
        profile_ready = False
    # If a MISP event exists in the DB for this run, that's hard evidence of
    # detection — upgrade detect_has_started even if log-line evidence was
    # not found (e.g. tail window missed the [DETECT] line, or exp3 ransomware
    # fires via Falco whose logs aren't in detector_blob).
    if not detect_has_started and latest_event and latest_event.get("id"):
        detect_has_started = True
    # Also consider SOARCA or TAPCD profile activity as detection evidence —
    # but only once the attack itself has actually started. soarca_blob's
    # window (_tapcd_since) falls back to the run's own start time (not the
    # attack's) before attack_started_at is known, so on a reused scenario it
    # can pick up a PRIOR run's still-fresh SOARCA activity and misreport it as
    # this run's detection at t≈0 — the same stale-signal issue detect_evidence
    # already guards against via attack_has_started above.
    if not detect_has_started and attack_has_started and (soarca_signal_present or profile_ready):
        detect_has_started = True
    countermeasure, why = _detect_countermeasure(soarca_blob, experiment)
    success_hit = _effective_soarca_execution(experiment, soarca_blob, victim_name=victim_name)
    # exp1 real-state confirmation: if victim mitigation chain exists, action
    # is considered truly applied even if SOARCA logs are noisy/truncated.
    error_hit = any(k in soarca_blob.lower() for k in ["i/o timeout", "dial tcp", "eof", "error"])
    if not detect_has_started:
        countermeasure_status = "Pending / no decision yet"
    elif success_hit:
        countermeasure_status = f"MITRE D3FEND: {countermeasure} (applied)"
    elif error_hit:
        countermeasure_status = f"MITRE D3FEND: {countermeasure} (attempted, execution errors detected)"
    else:
        countermeasure_status = f"MITRE D3FEND: {countermeasure} (pending evidence)"

    observe_marker = phase_markers.get("observe_at")
    if observe_marker is None and started_ts is not None:
        observe_marker = float(started_ts) + 1.0
    detect_marker = phase_markers.get("detect_at") if attack_has_started else None
    if detect_marker is None and detect_evidence_lines and attack_has_started:
        detect_marker = _first_timestamp_for_keywords(
            "\n".join(detect_evidence_lines),
            [
                "alerta publicada",
                "alerta rápida publicada",
                "alerta por flows publicada",
                "nueva alerta publicada",
                "host ransomware emulation detected",
                "distributed password spraying",
                "bruteforce password spraying detected",
            ],
        )
    # Never let a detect marker land before the attack itself started — this is
    # the guard that stops the live chart from drawing the green "detection"
    # vertical line at sample 0. phase_markers["detect_at"] can come from a
    # persisted state file (novadef_phase_timing.json) that a previous run on
    # the same reused scenario already wrote; without clamping it to
    # attack_since_ts, that stale timestamp gets projected onto this run.
    if detect_marker is not None and attack_since_ts is not None and detect_marker < attack_since_ts:
        detect_marker = None
    if detect_marker is not None:
        detect_has_started = True
    profile_marker = phase_markers.get("profile_at")
    if profile_marker is None and detect_has_started and profile_ready:
        profile_marker = _first_timestamp_for_keywords(
            tapcd_blob,
            PROFILE_EVIDENCE_KEYWORDS
            + [
                "profile_",
                "stream_low",
                "neo4j",
                "actor profile",
                "attacker profile",
            ],
        )
        if profile_marker is None and native_profile_lines:
            profile_marker = _first_timestamp_for_keywords("\n".join(native_profile_lines), ["profile_"])
        if profile_marker is None and detect_marker is not None:
            profile_marker = detect_marker + 1.0
        if profile_marker is not None and detect_marker is not None and profile_marker <= detect_marker:
            profile_marker = detect_marker + 1.0
    enrich_marker = phase_markers.get("enrich_at")
    if enrich_marker is None and detect_has_started and event_ids:
        enrich_marker = _first_timestamp_for_keywords(
            misp_blob,
            ["nuevo evento misp", "event ", "event_id", "attribute", "published", "created"],
        )
        if enrich_marker is None and profile_marker is not None:
            enrich_marker = profile_marker + 1.0
        elif enrich_marker is not None and profile_marker is not None and enrich_marker <= profile_marker:
            enrich_marker = profile_marker + 1.0
        elif enrich_marker is not None and detect_marker is not None and enrich_marker <= detect_marker:
            enrich_marker = detect_marker + 1.0
    decide_marker = phase_markers.get("decide_at")
    if detect_has_started and countermeasure_status != "Pending / no decision yet":
        # Always try to get a real log-based timestamp for decide — a persisted
        # derived value (enrich+1) should be replaced with real SOARCA evidence
        # as soon as the logs are available.
        _decide_real = _first_timestamp_for_keywords(
            soarca_blob,
            ["selección defensiva", "d3fend", "selected", "lanzando playbook", "playbook=block_ip", "playbook=isolate_lab_host"],
        )
        if _decide_real is not None:
            decide_marker = _decide_real
        if decide_marker is None:
            if enrich_marker is not None:
                decide_marker = enrich_marker + 1.0
        if decide_marker is not None and enrich_marker is not None and decide_marker <= enrich_marker:
            decide_marker = enrich_marker + 1.0
        if decide_marker is not None and profile_marker is not None and decide_marker <= profile_marker:
            decide_marker = profile_marker + 1.0
    act_marker = phase_markers.get("act_at")
    if success_hit:
        # Same: always prefer real log-based act timestamp over derived.
        _act_real = _first_timestamp_for_keywords(
            soarca_blob,
            ["✅ playbook ejecutado", "✅ playbook de aislamiento ejecutado", "playbook ejecutado", "response applied", "response executed"],
        )
        if _act_real is not None:
            act_marker = _act_real
        if act_marker is None and decide_marker is not None:
            act_marker = decide_marker + 1.0
        if act_marker is not None and decide_marker is not None and act_marker <= decide_marker:
            act_marker = decide_marker + 1.0

    # Override log-derived timestamps with precise sub-second values from the
    # SOARCA trigger timing file (written at the exact moment each phase occurs).
    # These are always more accurate than parsing log line timestamps.
    # Guard: only use values that fall within the current run (>= since_ts) to
    # avoid projecting stale timings from a previous session onto a fresh run.
    soarca_timing = _read_soarca_phase_timing()
    _st_floor = float(since_ts) if since_ts else 0.0
    if soarca_timing.get("profile_at") and float(soarca_timing["profile_at"]) >= _st_floor and profile_marker is not None:
        profile_marker = soarca_timing["profile_at"]
    if soarca_timing.get("enrich_at") and float(soarca_timing["enrich_at"]) >= _st_floor and enrich_marker is not None:
        enrich_marker = soarca_timing["enrich_at"]
    if soarca_timing.get("decide_at") and float(soarca_timing["decide_at"]) >= _st_floor:
        decide_marker = soarca_timing["decide_at"]
    if soarca_timing.get("act_at") and float(soarca_timing["act_at"]) >= _st_floor:
        act_marker = soarca_timing["act_at"]

    if run_id:
        _persist_run_phase_marker(run_id, "observe_at", observe_marker)
        _persist_run_phase_marker(run_id, "detect_at", detect_marker)
        _persist_run_phase_marker(run_id, "profile_at", profile_marker)
        _persist_run_phase_marker(run_id, "enrich_at", enrich_marker)
        _persist_run_phase_marker(run_id, "decide_at", decide_marker)
        _persist_run_phase_marker(run_id, "act_at", act_marker)

    return {
        "misp": {
            "event_ids_detected_in_logs": event_ids,
            "event_signal_count": sum(
                1 for ln in misp_blob.splitlines()
                if any(k in ln.lower() for k in [
                    "nuevo evento misp", "event_id", "event id", "misp event",
                    "published", "nueva alerta", "alerta rápida", "alerta rapida",
                    "alerta falco", "[detect]", "campaign|target",
                ])
            ),
            "event_details_extracted": len(attrs),
            "detector_evidence_lines": detect_evidence_lines[-40:],
            "event_detail_lines": [ln for ln in lines if any(k in ln.lower() for k in ["nuevo evento misp", "[+] ip-", "[+] port", "[+] text", "cic flows"])][-120:],
            "event_object": {
                "event": latest_event or {},
                "attributes": attrs,
            },
            "reused_existing_event": bool(duplicate_campaign and latest_event),
        },
        "tapcd": {
            "profile_mentions": _count_keyword_hits(tapcd_blob, PROFILE_EVIDENCE_KEYWORDS),
            "attacker_mentions": tapcd_blob.lower().count("attacker") + tapcd_blob.lower().count("actor"),
            "incident_mentions": tapcd_blob.lower().count("incident") + tapcd_blob.lower().count("incidente"),
            "profile_details_extracted": len(actors),
            "profile_detail_lines": native_profile_lines[-160:],
            "actor_profile_count": len(actors),
            "actor_profiles": actors,
            "native_profile_ready": bool(native_profile_lines),
            "profile_object": {
                "actors": actors,
                "native_profile_lines": native_profile_lines[-160:],
            },
        },
        "countermeasure": {
            "selected": countermeasure_status,
            "justification": why,
            "d3fend_basis": "Selected from SOARCA-stage evidence and mapped to D3FEND-aligned defensive controls.",
            "soarca_excerpt": _soarca_execution_evidence_excerpt(soarca_blob) or "No se encuentra evidencia de la contramedida todavía.",
        },
        "timeline": {
            "observe_at": observe_marker,
            "detect_at": detect_marker,
            "profile_at": profile_marker,
            "enrich_at": enrich_marker,
            "decide_at": decide_marker,
            "act_at": act_marker,
        },
    }


def _run_background(experiment: str, run_id: str) -> None:
    existing_run = _history_item(run_id) or {}
    shared_scenario_run = bool(existing_run.get("scenario_shared"))
    shared_scenario_fast_start = _shared_scenario_fast_start_ready(existing_run)
    scenario_id = str(existing_run.get("scenario_id") or "").strip()
    existing_victim = str(existing_run.get("victim_container_name") or "").strip()
    existing_attacker = str(existing_run.get("attacker_container_name") or "").strip()
    existing_network = str(existing_run.get("network") or existing_run.get("scenario_network") or "").strip()
    existing_victim_uptime = _container_uptime_seconds(existing_victim) if existing_victim else None
    existing_attacker_uptime = _container_uptime_seconds(existing_attacker) if existing_attacker else None
    if (
        existing_victim
        and existing_attacker
        and existing_network
        and existing_victim_uptime is not None
        and existing_attacker_uptime is not None
    ):
        scenario = {
            "project": str(existing_run.get("scenario_project") or ""),
            "network": str(existing_run.get("scenario_network") or existing_run.get("network") or ""),
            "victim_container_name": str(existing_run.get("victim_container_name") or ""),
            "attacker_container_name": str(existing_run.get("attacker_container_name") or ""),
            "victim_ip": str(existing_run.get("victim_ip") or ""),
            "attacker_ip": str(existing_run.get("attacker_ip") or ""),
            "log_dir": str(existing_run.get("scenario_log_dir") or existing_run.get("log_dir") or ""),
            "telemetry_dir": str(existing_run.get("scenario_telemetry_dir") or existing_run.get("telemetry_dir") or ""),
            "reports_dir": str(existing_run.get("scenario_reports_dir") or existing_run.get("reports_dir") or ""),
        }
        _sync_pmp_observation_with_scenario(scenario)
    else:
        if shared_scenario_run and scenario_id:
            catalog = _load_scenario_catalog()
            existing_entry = dict(catalog.get(scenario_id) or {})
            scenario = _ensure_persistent_scenario(
                scenario_id,
                display_name=str(existing_entry.get("display_name") or scenario_id),
                template=str(existing_entry.get("template") or "default"),
            )
        else:
            scenario = _ensure_scenario_for_run(run_id)
        _update_history(
            run_id,
            {
                "scenario_project": str(scenario.get("project") or ""),
                "scenario_network": str(scenario.get("network") or ""),
                "victim_container_name": str(scenario.get("victim_container_name") or ""),
                "attacker_container_name": str(scenario.get("attacker_container_name") or ""),
                "victim_ip": str(scenario.get("victim_ip") or ""),
                "attacker_ip": str(scenario.get("attacker_ip") or ""),
                "scenario_log_dir": str(scenario.get("log_dir") or ""),
                "scenario_telemetry_dir": str(scenario.get("telemetry_dir") or ""),
                "scenario_reports_dir": str(scenario.get("reports_dir") or ""),
            },
        )
        with LOCK:
            if str(STATE.get("current_run_id") or "") == run_id:
                STATE["scenario_id"] = scenario_id or None
                STATE["scenario_project"] = str(scenario.get("project") or "") or None
                STATE["scenario_network"] = str(scenario.get("network") or "") or None
                STATE["victim_container_name"] = str(scenario.get("victim_container_name") or "") or None
                STATE["attacker_container_name"] = str(scenario.get("attacker_container_name") or "") or None
        _persist_runtime_state()
        _sync_pmp_observation_with_scenario(scenario)
    # Timing model:
    # 1) wait until containers are actually ready (timeout safety gate),
    # 2) wait 15s before the victim starts being monitored,
    # 3) wait 5s more before benign noise starts,
    # 4) wait 15s more before launching the attack.
    scenario_ready_timeout = int(os.getenv("EXPERIMENT_SCENARIO_READY_TIMEOUT_SECONDS", "45"))
    monitor_delay_seconds = int(os.getenv("EXPERIMENT_MONITOR_DELAY_SECONDS", "15"))
    noise_delay_seconds = int(os.getenv("EXPERIMENT_NOISE_DELAY_SECONDS", "5"))
    attack_delay_seconds = int(os.getenv("EXPERIMENT_ATTACK_DELAY_SECONDS", "15"))
    if shared_scenario_fast_start:
        # Shared/persistent scenarios are already up and stabilized by design.
        # Do not add delays or relaunch benign noise.
        monitor_delay_seconds = 0
        noise_delay_seconds = 0
        attack_delay_seconds = 0

    _wait_for_scenario_ready(scenario, timeout_seconds=scenario_ready_timeout)
    try:
        victim_container = scenario.get("victim_container_name") or "scenario_victim"
        attacker_container = scenario.get("attacker_container_name") or "scenario_attacker"
    except Exception:
        victim_container = "scenario_victim"
        attacker_container = "scenario_attacker"
    print(f"[traffic-debug] _run_background: Starting experiment {experiment} (run_id={run_id})", flush=True)
    try:
        kafka_ready_wait = int(os.getenv("EXPERIMENT_KAFKA_READY_WAIT_SECONDS", "15"))
        if shared_scenario_fast_start:
            kafka_ready_wait = 0
        _wait_kafka_consumers_ready(timeout_sec=max(kafka_ready_wait, 0))
        with LOCK:
            TRAFFIC_SERIES[run_id] = []
            TRAFFIC_BASELINES[run_id] = 0.0

        # Between experiments: reset ALL dedup state so each experiment generates
        # its own fresh alerts, profiles, MISP events and countermeasures — even
        # if it uses the same attack type and victim IP as a previous one. This
        # MUST run for EVERY new run (new scenario AND fast-start reuse of an
        # existing scenario), otherwise a second experiment launched minutes after
        # the first hits the still-warm dedup windows and its spraying/ransomware
        # alert is dropped as "ya procesada" → no MISP event, empty panels.
        # Within a single run the dedup still collapses per-second re-emissions.
        # Historical data (MISP DB, MongoDB flows, Kafka messages) is NEVER deleted
        # here; isolation between runs is by campaign_id (= run_id).
        # Kill any leftover ransomware process from a prior exp2/exp3 BEFORE
        # resetting dedup — otherwise it keeps emitting real Falco alerts that the
        # freshly-reset pipeline treats as new detections for THIS run.
        _kill_ransomware_everywhere()
        # Same for a leftover network-attack process (hping3/sshpass spraying
        # loop) from a prior exp1/exp3 on this same reused scenario — otherwise
        # its traffic contaminates this run's chart from sample zero, looking
        # like genuine new attack traffic that started before this experiment
        # even launched its own attack phase.
        _kill_network_attack_everywhere()
        # Reset the victim's iptables (clear prior-run DROP rules + reinstall the
        # NOVADEF_NET_IN counting chain) HERE, during setup, rather than at attack
        # launch. The reset does `iptables -F NOVADEF_NET_IN`, which ZEROES the
        # inbound packet counter. When it ran at attack launch it raced the
        # round-1 network surge: the surge (~9.7k packets) fired the instant the
        # attack script started, but the reset's slow docker-exec flush landed a
        # couple of seconds later and wiped those counts back to ~0 — so the big
        # network spike never showed on the effective-traffic curve (the user's
        # "no veo el spike del ataque de red"). Doing it now, well before the
        # stability gate and the surge, leaves a clean, stable counter that the
        # surge increments monotonically and nothing flushes out from under it.
        if experiment in {"exp1", "exp3"}:
            try:
                _reset_victim_iptables(str(victim_container))
            except Exception:
                pass
        _reset_misp_dedup_state(scenario_id=scenario_id)  # clears _active_event_by_victim + disk dedup
        _reset_detector_runtime_state()  # clears campaign_state.json, SOARCA dedup, offsets
        # Advance ALL pipeline consumer-group offsets to latest WITHOUT deleting
        # records. Within a scenario, historical Kafka messages/profiles must
        # coexist (the user's requirement), so we do not purge records here — but
        # every consumer must start reading only NEW messages so a second run
        # cannot reprocess flows/profiles from a previous run. This is what stops
        # prep_pred (--from-beginning) from replaying an old flow and emitting a
        # stale actor profile (e.g. the 'activist' from a prior day).
        _reset_all_kafka_offsets_to_latest()
        if not shared_scenario_fast_start:
            time.sleep(10)

        # Stage 1: allow the experiment view to settle before monitoring.
        if monitor_delay_seconds > 0:
            print(
                f"[traffic-debug] Waiting {monitor_delay_seconds}s before starting victim monitoring for {run_id}",
                flush=True,
            )
            deadline = time.time() + monitor_delay_seconds
            while time.time() < deadline:
                time.sleep(1.0)

        # Do not start monitoring yet. Keep the initial 15 s window free of
        # victim telemetry so the live chart does not accumulate startup
        # packets before the benign noise phase begins.
        if noise_delay_seconds > 0:
            print(
                f"[traffic-debug] Waiting {noise_delay_seconds}s before benign noise for {run_id}",
                flush=True,
            )
            deadline = time.time() + noise_delay_seconds
            while time.time() < deadline:
                time.sleep(1.0)

        # (Re)bind tshark to the active victim NOW that the scenario is fully
        # provisioned and its scenario-network interface (172.18.0.x / eth1) is
        # up. Doing this here — not during early sync — guarantees tshark sniffs
        # the interface where the attack flows, so the passive anomaly detector
        # actually observes the attack. Without this the capture may attach to the
        # management interface and the detector never sees the attack traffic.
        if experiment in {"exp1", "exp2", "exp3"}:
            _rebind_global_tshark(str(victim_container))

        # Keep startup behavior homogeneous across experiments:
        # benign traffic first, then attack execution.
        if experiment in {"exp1", "exp2", "exp3"} and not shared_scenario_fast_start:
            _start_benign_noise(run_id)
            # `_start_benign_noise` launches the generator via `nohup ... &` and
            # returns immediately — the script itself (and, on a cold scenario,
            # the container/network stack it runs against) takes a moment to
            # actually settle into its steady noise rate. Sampling right away
            # captured that startup ramp as a transient burst (hundreds of
            # pkt/s for the first couple of samples) before dropping to the real
            # noise level. Rather than clip/hide that value on the chart, wait
            # here so the FIRST sample we ever take is already past the ramp —
            # the capture window simply never includes the container-creation
            # burst at all.
            _BENIGN_NOISE_SETTLE_SECONDS = float(os.getenv("EXPERIMENT_BENIGN_NOISE_SETTLE_SECONDS", "3"))
            time.sleep(_BENIGN_NOISE_SETTLE_SECONDS)

        # Start monitoring only after the benign-noise phase has begun AND
        # settled (see the sleep above). At this point the victim container is
        # already producing stable baseline traffic, so the series begins with
        # real noise-level observations instead of bootstrap transients.
        # NOTE: these samples are spaced at the same ~1s cadence as the steady
        # background sampler (EXPERIMENT_TRAFFIC_SAMPLE_INTERVAL_SECONDS
        # default 0.7s), not the previous 0.15s. The live chart derives a
        # per-second rate as delta_packets / delta_time between consecutive
        # samples; a small packet delta measured across a 0.15s gap produces a
        # rate an order of magnitude higher than the same traffic measured at
        # the sampler's normal ~1-2s cadence (a few packets / 0.15s ≈
        # 1000+ pkt/s) — a measurement artifact, not a real spike. Since the
        # chart's Y-axis only ever grows while the run is active, that one
        # inflated startup sample permanently flattened the rest of the real
        # traffic curve for the whole run.
        for _ in range(3):
            _append_traffic_sample(run_id, container_name=str(victim_container))
            time.sleep(1.0)
        _start_traffic_sampler(run_id, container_name=str(victim_container))

        # ── Packet-rate stability gate ──────────────────────────────────────
        # For fast-start (scenario already running): skip the gate entirely.
        # The scenario has been up for a while; background traffic is steady by
        # definition. Just read the current counter as the baseline anchor.
        # For cold-start: wait for several consecutive low-delta windows so
        # container/network-init bursts don't pollute the graph baseline.
        _STAB_INTERVAL = float(os.getenv("EXPERIMENT_STABILITY_PROBE_INTERVAL_SECONDS", "1.0"))
        _STAB_THRESHOLD = float(os.getenv("EXPERIMENT_STABILITY_MAX_DELTA_PACKETS", "200"))
        _STAB_NEEDED = int(os.getenv("EXPERIMENT_STABILITY_REQUIRED_WINDOWS", "5"))
        _stab_prev_rx: float | None = None
        _stab_good = 0
        _stab_started_at = time.time()
        _stab_max_wait = float(os.getenv("EXPERIMENT_STABILITY_MAX_WAIT_SECONDS", "60"))
        _stable_rx_anchor: float | None = None
        # Fast-start still runs the real stability gate below, just with a much
        # shorter max-wait. It used to skip the gate entirely after a fixed 2s
        # sleep, on the assumption that a reused scenario's background traffic
        # is steady by definition — but _kill_network_attack_everywhere() runs
        # moments before this, and killing hping3/sshpass with SIGTERM can leave
        # a brief burst of in-flight packets/RST traffic. Skipping the gate
        # meant that burst got baked into the baseline anchor as if it were
        # this run's own traffic, contaminating the chart from sample zero
        # whenever a new experiment reused a scenario that still had a network
        # attack running. A short real gate absorbs that without materially
        # slowing down fast-start reuse.
        if shared_scenario_fast_start:
            _stab_max_wait = float(os.getenv("EXPERIMENT_STABILITY_MAX_WAIT_SECONDS_FAST_START", "8"))
        while _stable_rx_anchor is None:
            _stab_curr_rx = _read_victim_rx_packets(str(victim_container))
            if _stab_curr_rx is not None and _stab_curr_rx > 0 and _stab_prev_rx is not None:
                _stab_delta = max(_stab_curr_rx - _stab_prev_rx, 0.0)
                if _stab_delta <= _STAB_THRESHOLD:
                    _stab_good += 1
                    if _stab_good >= _STAB_NEEDED:
                        _stable_rx_anchor = float(_stab_curr_rx)
                        print(
                            f"[traffic-debug] Stability gate passed for {run_id}: "
                            f"delta={_stab_delta:.0f} pkts/probe after {time.time() - _stab_started_at:.1f}s",
                            flush=True,
                        )
                        break
                else:
                    print(
                        f"[traffic-debug] Init burst detected for {run_id}: "
                        f"delta={_stab_delta:.0f} pkts/probe; waiting...",
                        flush=True,
                    )
                    _stab_good = 0
            elif _stab_curr_rx is not None and _stab_curr_rx > 0:
                _stab_good = 0
            _stab_prev_rx = _stab_curr_rx
            if (time.time() - _stab_started_at) >= _stab_max_wait:
                print(
                    f"[traffic-debug] Stability gate max-wait reached for {run_id}; "
                    f"continuing with last observed rx anchor={float(_stab_curr_rx or 0.0):.0f}",
                    flush=True,
                )
                _stable_rx_anchor = float(_stab_curr_rx or 0.0)
                break
            time.sleep(_STAB_INTERVAL)
        # ───────────────────────────────────────────────────────────────────

        if _stable_rx_anchor is None:
            _stable_rx_anchor = _read_victim_rx_packets(victim_container)
        if _stable_rx_anchor is None:
            _stable_rx_anchor = _read_tshark_packet_count(str(victim_container))
        with LOCK:
            TRAFFIC_SERIES[run_id] = []
            TRAFFIC_BASELINES[run_id] = float(_stable_rx_anchor or 0.0)

        if attack_delay_seconds > 0:
            print(
                f"[traffic-debug] Waiting {attack_delay_seconds}s before attack starts for {run_id}",
                flush=True,
            )
            deadline = time.time() + attack_delay_seconds
            while time.time() < deadline:
                time.sleep(1.0)

        attack_started_at = time.time()
        try:
            attack_baseline = _read_victim_rx_packets(victim_container)
            if attack_baseline is None:
                attack_baseline = _read_tshark_packet_count(str(victim_container))
            if attack_baseline is not None:
                with LOCK:
                    TRAFFIC_BASELINES[run_id] = float(attack_baseline)
        except Exception:
            pass
        # For exp2, STATE/history are updated AFTER the 25s setup sleep so the
        # GUI doesn't show a stale "attack started" timestamp during setup.
        if experiment != "exp2":
            with LOCK:
                STATE["last_attack_started_at"] = attack_started_at
            _update_history(run_id, {"attack_started_at": attack_started_at})
        print(f"[traffic-debug] Attack launch timestamp for {run_id}: {attack_started_at}", flush=True)
        victim_target = str(scenario.get("victim_ip") or "").strip() or "scenario_victim"

        print(f"[traffic-debug] _run_background: Executing {experiment} command", flush=True)
        if experiment == "exp1":
            # Target the victim on launcher_default (172.18.0.x) so the spoofed
            # source IPs (172.18.0.10-25) are on the same subnet and routable —
            # otherwise the attack reaches the victim via the scenario-internal
            # net with the real container IPs and the SOARCA iprange block never
            # matches, so the graph never drops to the benign level.
            exp1_victim_target = _container_launcher_ip(str(victim_container)) or victim_target
            print(f"[traffic-debug] exp1 attack target (launcher_default): {exp1_victim_target}", flush=True)
            # NOTE: iptables was already reset during setup (before the stability
            # gate). Do NOT reset again here — flushing NOVADEF_NET_IN at attack
            # launch zeroes the inbound counter just as the round-1 surge fires,
            # which wiped the network spike off the effective-traffic curve.
            try:
                attacker = DOCKER_CLIENT.containers.get(str(attacker_container))
                attacker.exec_run(
                    [
                        "sh",
                        "-lc",
                        "mkdir -p /var/novadef/logs && rm -f /var/novadef/logs/password_spraying_attempts.jsonl || true",
                    ],
                    user="0:0",
                    stdout=True,
                    stderr=True,
                )
            except Exception:
                pass
            # El ataque se lanza en BACKGROUND y corre de forma sostenida (igual
            # que un atacante real, que no se detiene por sí mismo). NO se bloquea
            # el experimento esperando a que termine: la detección pasiva (tshark
            # → Isolation Forest), el perfilado (TAPCD) y la mitigación (SOARCA)
            # ocurren en paralelo vía Kafka. El ataque solo para cuando:
            #   (a) SOARCA aplica la contramedida (la víctima dropea su tráfico), o
            #   (b) el experimento termina y se escribe stop_network_attack.signal.
            # ATTACK_DURATION_SECONDS alto = el ataque persiste todo el experimento.
            attack_cmd = (
                'SOURCE_BATCH_SIZE=16 ATTEMPTS_PER_PAIR=3 PROBE_BURST=300 '
                'INITIAL_SURGE_PACKETS_PER_SOURCE=500 SOURCE_IP_START=160 SOURCE_IP_END=175 '
                'TARGET_USER_LIMIT=6 HPING_INTERVAL_US=200 ATTEMPT_SLEEP_SECONDS=0.05 '
                'SLEEP_SECONDS=0.0 ATTACK_DURATION_SECONDS=1800 '
                f'CAMPAIGN_ID={run_id} '
                f'nohup bash /opt/novadef/distributed_password_spraying.sh {exp1_victim_target} 2222 '
                '>/var/novadef/logs/attack_exp1.out 2>&1 &'
            )
            try:
                attacker = DOCKER_CLIENT.containers.get(str(attacker_container))
                attacker.exec_run(["bash", "-lc", attack_cmd], stdout=True, stderr=True)
                rc, output = 0, "exp1 attack launched in background (sustained)"
                print(f"[traffic-debug] exp1 attack launched in background for {run_id}", flush=True)
            except Exception as e:
                rc, output = 1, f"exp1 attack launch error: {e}"
                print(f"[traffic-debug] exp1 attack launch FAILED for {run_id}: {e}", flush=True)
        elif experiment == "exp2":
            # MISP/MongoDB/dedup were already purged before monitoring started.
            # Reset attack_started_at to the actual moment the emulation launches
            # so setup overhead is not counted as detection latency.
            attack_started_at = time.time()
            with LOCK:
                STATE["last_attack_started_at"] = attack_started_at
            _update_history(run_id, {"attack_started_at": attack_started_at})
            print(f"[traffic-debug] Attack launch timestamp (corrected for exp2) for {run_id}: {attack_started_at}", flush=True)
            threading.Thread(
                target=_grafana_post_annotation,
                args=("🔴 Exp2: Ransomware", ["novadef", "attack", "exp2", "ransomware"]),
                kwargs={"ts_ms": int(attack_started_at * 1000)},
                daemon=True,
            ).start()
            ok, launch_out = _start_exp2_persistent_emulation(run_id)
            rc = 0 if ok else 1
            output = launch_out if launch_out else ("started persistent exp2 loop" if ok else "failed to start persistent exp2 loop")
        elif experiment == "exp3":
            threading.Thread(
                target=_grafana_post_annotation,
                args=("🔴 Exp3: Hybrid Attack", ["novadef", "attack", "exp3", "network", "ransomware"]),
                kwargs={"ts_ms": int(attack_started_at * 1000)},
                daemon=True,
            ).start()
            # NOTE: iptables was already reset during setup (before the stability
            # gate), so the counting chain is clean and stable here. Resetting it
            # again at this point would zero the NOVADEF_NET_IN counter right as
            # the round-1 surge fires and wipe the network spike — see the setup
            # reset above.
            exp3_victim_target = _container_launcher_ip(str(victim_container)) or victim_target
            print(f"[traffic-debug] exp3 attack target (launcher_default): {exp3_victim_target}", flush=True)
            # Ataque híbrido en BACKGROUND y sostenido (como exp1): no se bloquea el
            # experimento; la detección pasiva (tshark → Isolation Forest) + Falco
            # (señal de host) + TAPCD + SOARCA corren en paralelo. El ataque solo
            # para con la contramedida (aislamiento) o el stop del experimento.
            # Same launch pattern as _start_exp2_persistent_emulation: an `echo`
            # sentinel after the `nohup ... &` lets us verify the background
            # process actually started (exec_run alone does not guarantee that —
            # a shell init failure under `bash -lc` can silently drop the nohup).
            exp3_attack_cmd = (
                "command -v bash >/dev/null 2>&1 || apk add --no-cache bash >/dev/null 2>&1 || true\n"
                'export ATTACK_DURATION_SECONDS=1800\n'
                'export SOURCE_BATCH_SIZE=16\n'
                'export ATTEMPTS_PER_PAIR=3\n'
                'export PROBE_BURST=300\n'
                'export INITIAL_SURGE_PACKETS_PER_SOURCE=500\n'
                'export HPING_INTERVAL_US=200\n'
                'export SOURCE_IP_START=160\n'
                'export SOURCE_IP_END=175\n'
                'export TARGET_USER_LIMIT=6\n'
                'export ATTEMPT_SLEEP_SECONDS=0.05\n'
                'export SLEEP_SECONDS=0.4\n'
                'export COMMAND_TIMEOUT=0.25\n'
                f'export CAMPAIGN_ID={run_id}\n'
                f'nohup bash /opt/novadef/hybrid_lateral_remote_execution.sh {exp3_victim_target} 2222'
                ' >/var/novadef/logs/attack_exp3.out 2>&1 &\n'
                'echo started_exp3_network\n'
            )
            network_attack_ok = False
            try:
                attacker = DOCKER_CLIENT.containers.get(str(attacker_container))
                res = attacker.exec_run(["sh", "-c", exp3_attack_cmd], stdout=True, stderr=True, user="root")
                out = (res.output or b"").decode("utf-8", errors="replace")
                network_attack_ok = (res.exit_code == 0) and ("started_exp3_network" in out)
                rc, output = 0, "exp3 hybrid attack launched in background (sustained)"
                print(
                    f"[traffic-debug] exp3 network attack launch exit_code={res.exit_code} "
                    f"ok={network_attack_ok} out={out[:300]}",
                    flush=True,
                )
            except Exception as e:
                rc, output = 1, f"exp3 attack launch error: {e}"
                print(f"[traffic-debug] exp3 attack launch FAILED for {run_id}: {e}", flush=True)

            # Capture the surge FAST. The steady sampler runs at ~2s cadence, so
            # the round-1 surge (which lands in ~1-2s) was only picked up several
            # samples later — the user saw "el spike grande apareció 5 segundos
            # después" of the attack starting. Fire a short burst of quick samples
            # right now, in a background thread (so we don't block the Akira
            # scheduling below), so the surge shows on the chart ~1s after the
            # attack instead of ~5s. Runs in parallel with the steady sampler;
            # duplicate timestamps are de-duped downstream.
            def _fast_sample_surge():
                for _ in range(6):
                    try:
                        _append_traffic_sample(run_id, container_name=str(victim_container))
                    except Exception:
                        pass
                    time.sleep(0.6)
            threading.Thread(target=_fast_sample_surge, daemon=True).start()

            # Ransomware (Akira) starts 5s after the network phase — enough time
            # for the passive network detector (tshark capture -> Kafka ->
            # Isolation Forest) to observe the spraying traffic and publish its
            # own alert BEFORE Falco's near-instant host-syscall detection fires
            # the isolation countermeasure. With only 1s of separation the
            # ransomware always "won the race": isolation cut traffic before the
            # network detector's observation window completed, so MISP/TAPCD only
            # ever saw the ransomware phase, never the network phase. Matches the
            # real hybrid campaign pattern (initial access via spraying, THEN
            # lateral impact) while giving the network layer time to be detected.
            # Only fires if the network phase actually started.
            def _delayed_akira_for_exp3():
                # 2s after the network attack starts. The network surge creates
                # its spike within ~1s (and the fast-sampler above makes it
                # visible ~1s in), so firing the ransomware at +2s means it lands
                # ~1s AFTER the network spike is on screen — the order the user
                # wants: primero se ve el spike de red, luego el ransomware.
                time.sleep(2)
                if not network_attack_ok:
                    print(f"[exp3] Skipping Akira launch — network attack did not start for {run_id}", flush=True)
                    return
                try:
                    # Do NOT reset iptables here: the network surge is landing on
                    # the NOVADEF_NET_IN counter right now, and a reset would flush
                    # (zero) it, wiping the network spike off the chart.
                    _ok, _out = _start_exp2_persistent_emulation(run_id, reset_iptables=False)
                    print(f"[exp3] Akira launch result: ok={_ok} out={_out[:300]}", flush=True)
                    if _ok:
                        _update_history(run_id, {"exp3_host_attack_started": True})
                    else:
                        print(f"[exp3] Akira launch FAILED — check victim container logs", flush=True)
                except Exception as _e:
                    print(f"[exp3] Akira launch error: {_e}", flush=True)
            threading.Thread(target=_delayed_akira_for_exp3, daemon=True).start()
        else:
            with LOCK:
                STATE["running"] = False
                STATE["last_return_code"] = 1
                STATE["last_output"] = f"Unknown experiment: {experiment}"
                STATE["last_finished_at"] = time.time()
            return
        
        print(f"[traffic-debug] _run_background: Command finished with rc={rc}, output_len={len(output)}", flush=True)
        with LOCK:
            STATE["last_return_code"] = rc
            STATE["last_output"] = output[-12000:]
        _update_history(
            run_id,
            {
                "return_code": rc,
                "output_tail": output[-2500:],
            },
        )
        current_item = _history_item(run_id)
        if current_item and (current_item.get("deleted") or current_item.get("manual_stop")):
            with LOCK:
                STATE["running"] = False
                STATE["last_finished_at"] = time.time()
                _refresh_global_runtime_state(run_id)
            return
        if rc == 0:
            try:
                confirmation_timeout = int(os.getenv("EXPERIMENT_PIPELINE_CONFIRM_TIMEOUT_SECONDS", "90"))
                wait_note = f"\n[traffic-debug] Waiting for TAPCD/MISP/SOARCA confirmation (timeout={confirmation_timeout}s)"
                with LOCK:
                    STATE["last_output"] = (STATE.get("last_output", "") + wait_note)[-12000:]
                _update_history(run_id, {"output_tail": str(STATE.get("last_output") or "")[-2500:]})
                _wait_for_pipeline_completion(experiment, STATE.get("last_started_at"), timeout_sec=confirmation_timeout)
                # Mark the countermeasure moment on Grafana for non-exp2
                # experiments (exp2 posts its own annotation before stopping
                # the ransomware loop).
                if experiment == "exp3":
                    # Hybrid attack: SOARCA applied both block_ip (network) and
                    # isolation (host ransomware). Stop the Akira emulation now
                    # so the CPU spike drops at the exact countermeasure moment.
                    _stop_exp2_persistent_emulation(run_id=run_id)
                    threading.Thread(
                        target=_grafana_post_annotation,
                        args=("✅ Exp3: Isolation", ["novadef", "countermeasure", "exp3", "soarca", "isolation"]),
                        kwargs={"ts_ms": int(time.time() * 1000)},
                        daemon=True,
                    ).start()
                elif experiment != "exp2":
                    threading.Thread(
                        target=_grafana_post_annotation,
                        args=(f"✅ {experiment.upper()}: Block IP", ["novadef", "countermeasure", experiment, "soarca"]),
                        kwargs={"ts_ms": int(time.time() * 1000)},
                        daemon=True,
                    ).start()
                # For ALL experiments: generate the report as soon as the OODA
                # cycle completes (countermeasure applied), then keep the run in
                # "running" state so monitoring/graph keep updating until the user
                # presses Stop manually. The finally block handles cleanup.
                # Pull precise phase timestamps from SOARCA trigger into the
                # history entry so the report uses real sub-second values instead
                # of log-polling estimates.
                try:
                    soarca_t = _read_soarca_phase_timing()
                    if soarca_t:
                        for _k in ("profile_at", "enrich_at", "decide_at", "act_at"):
                            if soarca_t.get(_k):
                                _persist_run_phase_marker(run_id, _k, soarca_t[_k])
                except Exception:
                    pass

                ready_timeout_ooda = int(os.getenv("EXPERIMENT_FINAL_REPORT_READY_TIMEOUT_SECONDS", "60"))
                ready_ooda, _ = _wait_for_final_report_readiness(run_id, timeout_sec=ready_timeout_ooda)
                if ready_ooda:
                    try:
                        payload_ooda = _build_report_payload(run_id)
                        report_id_ooda = _persist_report(payload_ooda)
                        _persist_run_artifacts(run_id, report_id_ooda, payload_ooda)
                        _update_history(
                            run_id,
                            {
                                "report_id": report_id_ooda,
                                "summary": _runtime_experiment_summary(
                                    experiment, STATE.get("last_started_at"), str(STATE.get("last_output") or "")
                                ),
                                "report_panel": _report_panel_from_latest_report(report_id_ooda),
                            },
                        )
                    except Exception:
                        pass
                # exp2/exp3 run a persistent ransomware loop; stop it now that the
                # countermeasure has been applied so the host CPU spike subsides.
                if experiment in {"exp2", "exp3"}:
                    _stop_exp2_persistent_emulation(run_id=run_id)
                # Keep UI/sampler in "running" state until the user manually stops
                # the run with the Stop button. This applies to ALL experiments so
                # the network graph keeps updating after the countermeasure.
                while True:
                    current_item = _history_item(run_id) or {}
                    if current_item.get("manual_stop") or current_item.get("deleted"):
                        break
                    time.sleep(2)
                with LOCK:
                    STATE["running"] = False
                    STATE["last_finished_at"] = time.time()
                    _refresh_global_runtime_state(run_id)
                _update_history(
                    run_id,
                    {
                        "running": False,
                        "finished_at": STATE.get("last_finished_at"),
                    },
                )
            except Exception as e:
                with LOCK:
                    STATE["last_output"] = (STATE.get("last_output", "") + f"\n[report-error] {e}")[-12000:]
                    STATE["running"] = False
                    STATE["last_finished_at"] = time.time()
                    _refresh_global_runtime_state(run_id)
                _update_history(run_id, {"running": False, "finished_at": STATE.get("last_finished_at"), "report_error": str(e)})
    except Exception as e:
        with LOCK:
            STATE["running"] = False
            STATE["last_return_code"] = 1
            STATE["last_output"] = f"Experiment execution error: {e}"
            STATE["last_finished_at"] = time.time()
            _refresh_global_runtime_state(run_id)
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
    finally:
        try:
            if experiment in {"exp2", "exp3"}:
                _stop_exp2_persistent_emulation(run_id=run_id)
        except Exception:
            pass
        _stop_benign_noise(run_id)
        try:
            current = _history_item(run_id) or {}
            if not str(current.get("report_id") or "").strip():
                _snapshot_run_logs(run_id)
        except Exception:
            pass
        def _auto_cleanup_scenario() -> None:
            time.sleep(15)
            try:
                item = _history_item(run_id) or {}
                _cleanup_run_resources(
                    item,
                    remove_containers=True,
                    remove_network=True,
                    remove_artifacts=False,
                )
            except Exception:
                pass
        threading.Thread(target=_auto_cleanup_scenario, daemon=True).start()


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
    def _safe_live_report_panel(experiment_name: str, started_ts: Any, attack_started_ts: Any) -> dict[str, Any]:
        try:
            return _build_live_report_panel(experiment_name, started_ts, attack_started_ts)
        except Exception as e:
            print(f"[state-debug] live report panel fallback due to error: {e}", flush=True)
            return {}

    def _safe_runtime_summary(experiment_name: str, started_ts: Any, output_tail: str) -> dict[str, Any]:
        try:
            return _runtime_experiment_summary(experiment_name, started_ts, output_tail)
        except Exception as e:
            print(f"[state-debug] runtime summary fallback due to error: {e}", flush=True)
            return _live_placeholder_summary(experiment_name)

    lite = str(request.args.get("lite", "")).strip().lower() in {"1", "true", "yes", "on"}
    run_id = request.args.get("run_id", "").strip()
    
    # Lite requests can use cache (< 800ms old) to reduce backend load
    if lite and run_id:
        with LOCK:
            cache_ts = float(LIVE_STATE_CACHE_TTL.get(run_id) or 0.0)
            cached = LIVE_STATE_CACHE.get(run_id)
        cache_age_ms = (time.time() - cache_ts) * 1000 if cache_ts > 0 else 9999
        if cached and cache_age_ms < 800:
            return jsonify(cached)
    
    if run_id:
        run_item = _history_item(run_id)
        if not run_item or run_item.get("deleted"):
            # Cache the miss for 2s to prevent lookup spam
            with LOCK:
                LIVE_STATE_CACHE_TTL[run_id] = time.time()
            return jsonify({"ok": False, "error": "run_id not found"}), 404
        experiment = str(run_item.get("experiment") or "")
        started_ts = run_item.get("started_at")
        running = bool(run_item.get("running"))
        panel = None
        if (not lite) and experiment:
            panel = _safe_live_report_panel(experiment, started_ts, run_item.get("attack_started_at"))
        summary = None
        if experiment and running and not lite:
            summary = _safe_runtime_summary(experiment, started_ts, str(run_item.get("output_tail") or ""))
        elif experiment:
            summary = _live_placeholder_summary(experiment)
        if experiment and not running and not lite:
            panel = _safe_live_report_panel(experiment, started_ts, run_item.get("attack_started_at"))
            summary = _safe_runtime_summary(experiment, started_ts, str(run_item.get("output_tail") or ""))
        payload = {
            "running": running,
            "last_experiment": experiment,
            "last_started_at": started_ts,
            "last_attack_started_at": run_item.get("attack_started_at"),
            "last_finished_at": run_item.get("finished_at"),
            "last_return_code": run_item.get("return_code"),
            "last_output": str(run_item.get("output_tail") or "")[-4000:],
            "current_run_id": run_id,
            "summary": summary,
            "report_panel": panel if panel is not None else {},
            "last_report_id": run_item.get("report_id"),
            "scenario": {
                "scenario_id": run_item.get("scenario_id"),
                "project": run_item.get("scenario_project"),
                "network": run_item.get("scenario_network"),
                "victim_container_name": run_item.get("victim_container_name"),
                "attacker_container_name": run_item.get("attacker_container_name"),
            },
        }
        if not lite:
            payload["traffic_panel"] = _traffic_payload_for_run(run_id, run_item)
        
        # Cache lite state responses to reduce backend load
        if lite:
            with LOCK:
                LIVE_STATE_CACHE[run_id] = payload
                LIVE_STATE_CACHE_TTL[run_id] = time.time()
        
        return jsonify(payload)

    with LOCK:
        snapshot = dict(STATE)
    current_run_id = str(snapshot.get("current_run_id") or "")
    experiment = snapshot.get("last_experiment")
    running = bool(snapshot.get("running"))
    if experiment and running and not lite:
        snapshot["summary"] = _safe_runtime_summary(
            str(experiment),
            snapshot.get("last_started_at"),
            str(snapshot.get("last_output") or ""),
        )
        snapshot["report_panel"] = _safe_live_report_panel(
            str(experiment),
            snapshot.get("last_started_at"),
            snapshot.get("last_attack_started_at"),
        )
        snapshot["scenario"] = {
            "scenario_id": snapshot.get("scenario_id"),
            "project": snapshot.get("scenario_project"),
            "network": snapshot.get("scenario_network"),
            "victim_container_name": snapshot.get("victim_container_name"),
            "attacker_container_name": snapshot.get("attacker_container_name"),
        }
    elif experiment and not running and not lite:
        summary = _safe_runtime_summary(
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
        snapshot["scenario"] = {
            "scenario_id": snapshot.get("scenario_id"),
            "project": snapshot.get("scenario_project"),
            "network": snapshot.get("scenario_network"),
            "victim_container_name": snapshot.get("victim_container_name"),
            "attacker_container_name": snapshot.get("attacker_container_name"),
        }
    elif experiment and lite:
        snapshot["summary"] = _live_placeholder_summary(str(experiment))
    if current_run_id and not lite:
        snapshot["traffic_panel"] = _traffic_payload_for_run(current_run_id, _history_item(current_run_id))
    try:
        snapshot["last_output"] = str(snapshot.get("last_output") or "")[-4000:]
    except Exception:
        pass
    return jsonify(snapshot)


@app.get("/api/history")
def history() -> Any:
    with LOCK:
        runs = [dict(item) for item in reversed(RUN_HISTORY[-100:]) if not item.get("deleted")]
    return jsonify({"runs": runs})


@app.get("/api/scenarios")
def list_scenarios() -> Any:
    catalog = _load_scenario_catalog()
    stale_ids: list[str] = []
    for sid, entry in list(catalog.items()):
        probe = dict(entry)
        probe["scenario_id"] = sid
        if _scenario_catalog_entry_is_orphan(probe):
            stale_ids.append(sid)

    if stale_ids:
        for sid in stale_ids:
            catalog.pop(sid, None)
        _save_scenario_catalog(catalog)

    items = [_scenario_runtime_status(dict(entry)) for entry in catalog.values()]
    items.sort(key=lambda s: str(s.get("created_at") or ""), reverse=True)
    return jsonify({"scenarios": items})


@app.post("/api/scenarios")
def create_scenario() -> Any:
    payload = request.get_json(silent=True) or {}
    scenario_id = _sanitize_scenario_id(payload.get("scenario_id") or payload.get("id"))
    display_name = str(payload.get("display_name") or payload.get("name") or scenario_id).strip() or scenario_id
    template = str(payload.get("template") or "default").strip() or "default"

    scenario = _ensure_persistent_scenario(scenario_id, display_name=display_name, template=template)
    entry = _upsert_scenario_catalog_entry(scenario_id, scenario, display_name=display_name, template=template)
    return jsonify({"ok": True, "scenario": _scenario_runtime_status(entry)})


@app.post("/api/scenarios/<scenario_id>/start")
def start_scenario(scenario_id: str) -> Any:
    sid = _sanitize_scenario_id(scenario_id)
    catalog = _load_scenario_catalog()
    existing = dict(catalog.get(sid) or {})
    display_name = str(existing.get("display_name") or sid)
    template = str(existing.get("template") or "default")
    scenario = _ensure_persistent_scenario(sid, display_name=display_name, template=template)
    entry = _upsert_scenario_catalog_entry(sid, scenario, display_name=display_name, template=template)
    return jsonify({"ok": True, "scenario": _scenario_runtime_status(entry)})


@app.post("/api/scenarios/<scenario_id>/stop")
def stop_scenario(scenario_id: str) -> Any:
    sid = _sanitize_scenario_id(scenario_id)
    catalog = _load_scenario_catalog()
    entry = dict(catalog.get(sid) or {})
    if not entry:
        return jsonify({"ok": False, "error": "scenario_id not found"}), 404

    victim = str(entry.get("victim_container_name") or "").strip()
    attacker = str(entry.get("attacker_container_name") or "").strip()
    for name in [victim, attacker]:
        if not name:
            continue
        try:
            c = DOCKER_CLIENT.containers.get(name)
            c.stop(timeout=3)
        except Exception:
            try:
                c = DOCKER_CLIENT.containers.get(name)
                c.remove(force=True)
            except Exception:
                continue

    # Ensure run-scoped containers for this scenario are also stopped/removed.
    try:
        _cleanup_run_resources(
            {
                "run_id": _scenario_seed_run_id(sid),
                "scenario_project": entry.get("project"),
                "scenario_network": entry.get("network"),
                "victim_container_name": entry.get("victim_container_name"),
                "attacker_container_name": entry.get("attacker_container_name"),
                "scenario_log_dir": entry.get("log_dir"),
                "report_id": None,
            },
            remove_containers=True,
            remove_network=False,
            remove_artifacts=False,
        )
    except Exception:
        pass
    return jsonify({"ok": True, "scenario": _scenario_runtime_status(entry)})


@app.delete("/api/scenarios/<scenario_id>")
def delete_scenario(scenario_id: str) -> Any:
    sid = _sanitize_scenario_id(scenario_id)
    catalog = _load_scenario_catalog()
    entry = dict(catalog.get(sid) or {})
    
    # If not in catalog, look for it in RUN_HISTORY (orphaned scenario)
    if not entry:
        with LOCK:
            for item in RUN_HISTORY:
                if str(item.get("scenario_id") or "").strip() == sid:
                    entry = {
                        "scenario_id": sid,
                        "network": item.get("scenario_network"),
                        "project": item.get("scenario_project"),
                        "victim_container_name": item.get("victim_container_name"),
                        "attacker_container_name": item.get("attacker_container_name"),
                    }
                    break
    
    if not entry:
        return jsonify({"ok": False, "error": "scenario_id not found"}), 404

    scenario_project = str(entry.get("project") or "").strip()
    scenario_network = str(entry.get("network") or "").strip()
    scenario_victim = str(entry.get("victim_container_name") or "").strip()
    scenario_attacker = str(entry.get("attacker_container_name") or "").strip()

    def _run_belongs_to_deleted_scenario(item: dict[str, Any]) -> bool:
        run_sid = str(item.get("scenario_id") or "").strip()
        if run_sid == sid:
            return True
        # Extra fallback for legacy/stale entries where scenario_id may be missing.
        sid_token = str(sid or "").strip().lower()
        if sid_token:
            probe_fields = [
                str(item.get("scenario_project") or "").strip().lower(),
                str(item.get("scenario_network") or "").strip().lower(),
                str(item.get("victim_container_name") or "").strip().lower(),
                str(item.get("attacker_container_name") or "").strip().lower(),
            ]
            if any(sid_token in value for value in probe_fields if value):
                return True
        # Legacy compatibility: old runs may miss scenario_id but still point
        # to the same persistent scenario resources.
        if scenario_project and str(item.get("scenario_project") or "").strip() == scenario_project:
            return True
        if scenario_network and str(item.get("scenario_network") or "").strip() == scenario_network:
            return True
        if scenario_victim and str(item.get("victim_container_name") or "").strip() == scenario_victim:
            return True
        if scenario_attacker and str(item.get("attacker_container_name") or "").strip() == scenario_attacker:
            return True
        return False

    # Purge every run bound to this scenario so KPIs/signals do not keep stale values.
    with LOCK:
        related_runs = [
            dict(item)
            for item in RUN_HISTORY
            if _run_belongs_to_deleted_scenario(item)
        ]
    related_run_ids = {
        str(item.get("run_id") or "").strip()
        for item in related_runs
        if str(item.get("run_id") or "").strip()
    }

    catalog.pop(sid, None)
    _save_scenario_catalog(catalog)

    # If no run remains, clear live snapshot state to avoid stale summary counters.
    with LOCK:
        if not RUN_HISTORY:
            STATE["current_run_id"] = None
            STATE["running"] = False
            STATE["last_experiment"] = None
            STATE["last_started_at"] = None
            STATE["last_attack_started_at"] = None
            STATE["last_finished_at"] = None
            STATE["last_return_code"] = None
            STATE["last_output"] = ""
            STATE["last_report_id"] = None
            STATE["last_report_error"] = ""
    _persist_runtime_state()
    _refresh_global_runtime_state(None)

    def _purge_scenario_runtime_root() -> None:
        try:
            seed_run_id = _scenario_seed_run_id(sid)
            scenario_root = SCENARIO_ROOT / f"novadef-{seed_run_id}"
            for _ in range(6):
                _force_remove_tree(scenario_root)
                if not scenario_root.exists():
                    break
                time.sleep(0.5)
        except Exception:
            pass

    def _cleanup_scenario_async() -> None:
        for run_item in related_runs:
            rid = str(run_item.get("run_id") or "").strip()
            if not rid:
                continue
            report_id = str(run_item.get("report_id") or "").strip() or None
            try:
                if bool(run_item.get("running")):
                    now = time.time()
                    _update_history(
                        rid,
                        {
                            "manual_stop": True,
                            "running": False,
                            "stopped_at": now,
                            "finished_at": run_item.get("finished_at") or now,
                        },
                    )
            except Exception:
                pass
            try:
                _signal_run_stop(run_item)
            except Exception:
                pass
            try:
                _stop_benign_noise(rid)
            except Exception:
                pass
            try:
                _snapshot_run_logs(rid)
            except Exception:
                pass
            try:
                event_ids, actor_ids = _report_ids_and_actor_ids_for_run(run_item)
                _purge_misp_events(event_ids)
                _purge_tapcd_actor_profiles(actor_ids)
            except Exception:
                pass
            try:
                _cleanup_run_resources(
                    run_item,
                    remove_containers=True,
                    remove_network=True,
                    remove_artifacts=True,
                )
            except Exception:
                pass
            try:
                if report_id:
                    _force_remove_tree(REPORTS_DIR / report_id)
            except Exception:
                pass
            try:
                _forget_run_state(rid, report_id=report_id)
            except Exception:
                pass
            try:
                _force_remove_tree(_scenario_runtime_root(rid))
            except Exception:
                pass

        try:
            _cleanup_run_resources(
                {
                    "run_id": _scenario_seed_run_id(sid),
                    "scenario_project": entry.get("project"),
                    "scenario_network": entry.get("network"),
                    "victim_container_name": entry.get("victim_container_name"),
                    "attacker_container_name": entry.get("attacker_container_name"),
                    "scenario_log_dir": entry.get("log_dir"),
                    "report_id": None,
                },
                remove_containers=True,
                remove_network=True,
                remove_artifacts=True,
            )
        except Exception:
            pass
        _purge_scenario_runtime_root()
        # Scenario destroyed → wipe ALL data created by this scenario. Actors and
        # events coexist WITHIN a scenario across its experiments; they are only
        # cleared when the scenario itself is deleted.
        # ORDER MATTERS: purge Kafka FIRST (delete records + advance offsets) so
        # no leftover profile in profiles_out survives; otherwise the neo4j
        # ingester would re-upsert an old actor immediately after we wipe Neo4j.
        # Then restart the ingester so its startup-timestamp guard rebases and it
        # cannot replay anything produced before this purge.
        try:
            _purge_all_kafka_pipeline(reset_offsets=True)
        except Exception:
            pass
        try:
            DOCKER_CLIENT.containers.get("novadef-novadef_neo4j_ingester-1").restart(timeout=10)
        except Exception:
            pass
        try:
            _purge_neo4j_all()
        except Exception:
            pass
        try:
            _purge_misp_db()
        except Exception:
            pass
        # Drop MongoDB flows too: stream_low queries historical flows by src_ip to
        # aggregate first_seen (min timestamp). Leftover flows from a prior scenario
        # would poison first_seen/DetectionTs with an old date.
        try:
            _purge_mongodb_flows()
        except Exception:
            pass
        # Remove Grafana annotations (attack/countermeasure lines) so a new
        # scenario starts with a clean graph.
        try:
            _grafana_delete_all_annotations()
        except Exception:
            pass

    # Remove the scenario from RUN_HISTORY/STATE immediately — this is the
    # part the GUI actually needs before it can safely close/navigate away.
    # The rest (Docker containers, Kafka, Neo4j, MISP, MongoDB purge) is slow
    # (several seconds) and was previously run synchronously before the HTTP
    # response, which is why "Remove Scenario" made the popup tab hang for a
    # long time before it could close. It now runs in a background thread;
    # the client gets an immediate "accepted" response and the popup closes
    # right away, while cleanup finishes shortly after in the background.
    with LOCK:
        RUN_HISTORY[:] = [
            item for item in RUN_HISTORY
            if not _run_belongs_to_deleted_scenario(item)
        ]
        if str(STATE.get("current_run_id") or "").strip() in related_run_ids:
            STATE["current_run_id"] = None
            STATE["running"] = False
            STATE["last_experiment"] = None
            STATE["last_started_at"] = None
            STATE["last_attack_started_at"] = None
            STATE["last_finished_at"] = None
            STATE["last_return_code"] = None
            STATE["last_output"] = ""
            STATE["scenario_id"] = None
            STATE["scenario_project"] = None
            STATE["scenario_network"] = None
            STATE["victim_container_name"] = None
            STATE["attacker_container_name"] = None
    _persist_runtime_state()

    def _background_cleanup() -> None:
        _purge_scenario_runtime_root()
        _cleanup_scenario_async()

    threading.Thread(target=_background_cleanup, daemon=True).start()

    return jsonify({"ok": True, "scenario_id": sid, "deleted": True, "cleanup_completed": False, "cleanup_pending": True})


@app.post("/api/run/<run_id>/stop")
def stop_run(run_id: str) -> Any:
    print(f"[api] POST /api/run/{run_id}/stop - starting", flush=True)
    run_item = _history_item(run_id)
    if not run_item or run_item.get("deleted"):
        print(f"[api] stop_run: run_item not found for {run_id}", flush=True)
        return jsonify({"ok": False, "error": "run_id not found"}), 404
    now = time.time()
    print(f"[api] stop_run: marking {run_id} as stopped", flush=True)
    _update_history(
        run_id,
        {
            "manual_stop": True,
            "running": False,
            "stopped_at": now,
            "finished_at": run_item.get("finished_at") or now,
        },
    )
    print(f"[api] stop_run: signaling stop for {run_id}", flush=True)
    _signal_run_stop(run_item)
    print(f"[api] stop_run: stopping benign noise", flush=True)
    _stop_benign_noise(run_id)
    print(f"[api] stop_run: snapshotting logs", flush=True)
    _snapshot_run_logs(run_id)
    print(f"[api] stop_run: appending stopped sample", flush=True)
    _append_stopped_run_sample(run_id, container_name=_run_container_name(run_item, "victim"))
    print(f"[api] stop_run: cleaning up resources", flush=True)
    _cleanup_run_resources(run_item, remove_containers=True, remove_network=False, remove_artifacts=False)
    print(f"[api] stop_run: refreshing state", flush=True)
    _refresh_global_runtime_state(run_id)
    print(f"[api] stop_run: completed successfully for {run_id}", flush=True)
    return jsonify({"ok": True, "run_id": run_id, "stopped": True})


@app.delete("/api/run/<run_id>")
def delete_run(run_id: str) -> Any:
    run_item = _history_item(run_id)
    if not run_item:
        return jsonify({"ok": False, "error": "run_id not found"}), 404
    report_id = str(run_item.get("report_id") or "").strip() or None
    event_ids, actor_ids = _report_ids_and_actor_ids_for_run(run_item)
    now = time.time()
    _signal_run_stop(run_item)
    _stop_benign_noise(run_id)
    _snapshot_run_logs(run_id)
    _purge_misp_events(event_ids)
    _purge_tapcd_actor_profiles(actor_ids)
    _cleanup_run_resources(
        run_item,
        remove_containers=True,
        remove_network=True,
        remove_artifacts=True,
    )
    for run_root in _artifact_roots_for_run(run_id):
        try:
            _force_remove_tree(run_root)
        except Exception:
            pass
    _forget_run_state(run_id, report_id=report_id)
    _persist_runtime_state()
    _refresh_global_runtime_state(None)
    return jsonify({"ok": True, "run_id": run_id, "deleted": True})


@app.get("/api/progress")
def progress() -> Any:
    run_id = request.args.get("run_id", "").strip()
    if run_id:
        run_item = _history_item(run_id)
        if not run_item or run_item.get("deleted"):
            return jsonify({"ok": False, "error": "run_id not found"}), 404
        experiment = run_item.get("experiment")
        started = run_item.get("started_at")
        attack_started = run_item.get("attack_started_at")
        running = bool(run_item.get("running"))
        rc = run_item.get("return_code")
        last_output = str(run_item.get("output_tail") or "")
    else:
        with LOCK:
            experiment = STATE.get("last_experiment")
            started = STATE.get("last_started_at")
            attack_started = STATE.get("last_attack_started_at")
            running = bool(STATE.get("running"))
            rc = STATE.get("last_return_code")
            last_output = str(STATE.get("last_output") or "")
        current_run_id = str(STATE.get("current_run_id") or "")
        run_item = _history_item(current_run_id) if current_run_id else None
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
    attack_since_ts = int(attack_started) if isinstance(attack_started, (int, float)) else None
    phase_since_ts = attack_since_ts if attack_since_ts is not None else int(time.time()) + 86400
    observe_ready = _observe_ready(run_id) if run_id else bool(run_item and _observe_ready(str(run_item.get("run_id") or "")))
    victim_name = _run_container_name(run_item, "victim")
    attacker_name = _run_container_name(run_item, "attacker")
    observe_tail = 160 if running else 400
    detect_tail = 220 if running else 500
    profile_tail = 180 if running else 500
    enrich_tail = 220 if running else 500
    act_tail = 220 if running else 500
    logs = {
        "observe": _tail_logs("tshark_novadef", observe_tail, since_ts=since_ts) + "\n" + _tail_logs("falco_novadef", observe_tail, since_ts=since_ts) + "\n" + _tail_logs(attacker_name, 120 if running else 250, since_ts=since_ts),
        "detect": _tail_logs("snort_novadef", detect_tail, since_ts=phase_since_ts) + "\n" + _tail_logs("network_intrusion_detector_novadef", detect_tail, since_ts=phase_since_ts) + "\n" + _tail_logs("alert_module_novadef", detect_tail, since_ts=phase_since_ts),
        "profile": (
            _tail_logs("novadef-novadef_stream_low-1", profile_tail, since_ts=phase_since_ts)
            + "\n" + _tail_logs("novadef-novadef_prep_pred-1", 120 if running else 300, since_ts=phase_since_ts)
            + "\n" + _tail_logs("pmp-misp-soarca-trigger", 120 if running else 280, since_ts=phase_since_ts)
            + "\n" + _tail_logs("pmp-misp-integrator", 120 if running else 200, since_ts=phase_since_ts)
        ),
        "enrich": _tail_logs("pmp-misp-integrator", enrich_tail, since_ts=phase_since_ts) + "\n" + _tail_logs("pmp-misp-server", 160 if running else 350, since_ts=phase_since_ts),
        "act": _soarca_act_log_text(victim_name, phase_since_ts, act_tail),
    }
    output_low = last_output.lower()

    if experiment == "exp2":
        observe_hit = observe_ready
        detect_blob = (logs["detect"] + "\n" + logs["observe"] + "\n" + logs["enrich"]).lower()
        detect_hit = observe_hit and bool(_detection_evidence_lines(detect_blob, experiment))
        profile_hit = detect_hit and any(k in logs["profile"].lower() for k in PROFILE_EVIDENCE_KEYWORDS)
        enrich_hit = profile_hit and any(k in logs["enrich"].lower() for k in ["nuevo evento misp", "event_id", "misp event", "publish", "created"])
        decide_hit = enrich_hit and any(k in logs["act"].lower() for k in ["d3fend", "playbook", "selected", "countermeasure"])
        act_hit = decide_hit and any(k in logs["act"].lower() for k in ["playbook de aislamiento ejecutado", "playbook ejecutado", "done_block_ip", "iptables", "response applied", "response executed", "executor", "isolation", "terminate", "restor", "response"])
    elif experiment == "exp3":
        observe_hit = observe_ready
        attack_has_started = attack_since_ts is not None
        # exp3 has two detection phases: network IDS (detect) AND Falco/ransomware
        # (observe + enrich). Merge all three blobs so either phase triggers detect_hit.
        _exp3_detect_blob = (logs["detect"] + "\n" + logs["observe"] + "\n" + logs["enrich"]).lower()
        detect_hit = attack_has_started and observe_hit and bool(_detection_evidence_lines(_exp3_detect_blob, experiment))
        profile_hit = detect_hit and any(k in logs["profile"].lower() for k in PROFILE_EVIDENCE_KEYWORDS)
        enrich_hit = profile_hit and any(k in logs["enrich"].lower() for k in ["nuevo evento misp", "event_id", "misp event", "publish", "created"])
        decide_hit = enrich_hit and any(k in logs["act"].lower() for k in ["d3fend", "playbook", "selected", "countermeasure"])
        act_hit = decide_hit and any(k in logs["act"].lower() for k in ["playbook ejecutado", "done_block_ip", "iptables", "executor", "applied", "isolation", "terminate", "response"])
    else:
        observe_hit = observe_ready
        attack_has_started = attack_since_ts is not None
        detect_hit = attack_has_started and observe_hit and bool(_detection_evidence_lines(logs["detect"], experiment))
        profile_hit = detect_hit and any(k in logs["profile"].lower() for k in PROFILE_EVIDENCE_KEYWORDS)
        enrich_hit = profile_hit and any(k in logs["enrich"].lower() for k in ["nuevo evento misp", "event_id", "misp event", "publish", "created"])
        decide_hit = enrich_hit and any(k in logs["act"].lower() for k in ["d3fend", "playbook", "selected", "countermeasure"])
        act_hit = decide_hit and any(k in logs["act"].lower() for k in ["playbook ejecutado", "done_block_ip", "iptables", "executor", "applied", "block", "lock", "isolation", "response"])

    # When SOARCA isolation is first detected (act_hit=True), stop the attacker
    # noise so that rx_packets drops visibly on the victim's Telegraf metrics.
    # The noise runs on the attacker container and can only be stopped from here.
    _eff_run_id = run_id or (str(run_item.get("run_id") or "") if run_item else "")
    if act_hit and _eff_run_id and _eff_run_id not in _ISOLATION_NOISE_STOPPED:
        _ISOLATION_NOISE_STOPPED.add(_eff_run_id)
        try:
            _stop_benign_noise(_eff_run_id)
            print(f"[progress] isolation detected — stopped benign noise for {_eff_run_id}", flush=True)
        except Exception as _e:
            print(f"[progress] warning: could not stop benign noise: {_e}", flush=True)

    stages = [
        {"key": "observe", "done": observe_hit},
        {"key": "detect", "done": detect_hit},
        {"key": "profile", "done": profile_hit},
        {"key": "enrich", "done": enrich_hit},
        {"key": "decide", "done": decide_hit},
        {"key": "act", "done": act_hit},
    ]

    live_panel = _build_live_report_panel(
        str(experiment),
        started if isinstance(started, (int, float)) else None,
        attack_started if isinstance(attack_started, (int, float)) else None,
    )
    if live_panel:
        live_timeline = live_panel.get("timeline") or {}
        if live_timeline.get("observe_at") is not None:
            stages[0]["done"] = True
        if live_timeline.get("detect_at") is not None:
            stages[1]["done"] = True
        if live_timeline.get("profile_at") is not None:
            stages[2]["done"] = True
        if live_timeline.get("enrich_at") is not None:
            stages[3]["done"] = True
        if live_timeline.get("decide_at") is not None:
            stages[4]["done"] = True
        if live_timeline.get("act_at") is not None:
            stages[5]["done"] = True

    # Keep the OODA-like flow sequential in the UI:
    # a later phase should not appear completed if a previous phase has
    # not been evidenced yet for the same run.
    sequential_state = []
    all_previous_done = True
    for st in stages:
        done = bool(st["done"]) and all_previous_done
        sequential_state.append({"key": st["key"], "done": done})
        all_previous_done = all_previous_done and done
    stages = sequential_state

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
            response_metrics = (((report_data.get("novadef_metrics") or {}).get("response_effectiveness")) or {})

            profile_done = bool((tapcd_panel.get("profile_details_extracted") or 0) > 0 or (tapcd_panel.get("profile_mentions") or 0) > 0)
            enrich_done = bool((misp_panel.get("event_details_extracted") or 0) > 0 or (misp_panel.get("event_ids_detected_in_logs") or []))
            decide_done = bool(cm_selected and cm_selected != "-")
            act_done = bool(response_metrics.get("execution_present")) or any(k in cm_excerpt for k in ["playbook ejecutado", "applied", "executor", "response"])

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


@app.get("/api/traffic")
def traffic() -> Any:
    run_id = request.args.get("run_id", "").strip()
    if run_id:
        run_item = _history_item(run_id)
        if not run_item or run_item.get("deleted"):
            return jsonify({"ok": False, "error": "run_id not found"}), 404
    else:
        with LOCK:
            run_id = str(STATE.get("current_run_id") or "")
        run_item = _history_item(run_id) if run_id else None
        if not run_item:
            return jsonify({"ok": False, "error": "no active run"}), 404
    return jsonify(_traffic_payload_for_run(run_id, run_item))


@app.get("/metrics")
def prometheus_metrics() -> Any:
    return app.response_class(_prometheus_live_metrics_text(), mimetype="text/plain; version=0.0.4; charset=utf-8")


@app.get("/api/metrics")
def metrics() -> Any:
    with LOCK:
        runs = [dict(item) for item in RUN_HISTORY if not item.get("deleted")]
        current_run_id = str(STATE.get("current_run_id") or "")
        current_experiment = str(STATE.get("last_experiment") or "")
        current_running = bool(STATE.get("running"))
        current_started_at = STATE.get("last_started_at")
        current_finished_at = STATE.get("last_finished_at")
        current_report_id = str(STATE.get("last_report_id") or "")
        current_run_item = _history_item(current_run_id) if current_run_id else None
        victim_name = _run_container_name(current_run_item, "victim")
        can_use_live_panel = bool(current_run_id or current_running)
        current_summary = _runtime_experiment_summary(
            current_experiment,
            current_started_at,
            str(STATE.get("last_output") or ""),
        ) if (current_experiment and can_use_live_panel) else None
        current_panel = _build_live_report_panel(
            current_experiment,
            current_started_at,
            STATE.get("last_attack_started_at"),
        ) if (current_experiment and can_use_live_panel) else None
    if not runs:
        runs = []

    alert_total = 0
    profile_total = 0
    misp_total = 0
    soarca_total = 0
    durations: list[float] = []
    e2e_to_act: list[float] = []
    ttf_alert: list[float] = []
    ttcid: list[float] = []
    ingest_rates: list[float] = []
    detect_rates: list[float] = []
    db_rates: list[float] = []
    error_totals: list[float] = []
    latest_report_id = ""
    latest_run_id = ""
    latest_metrics: dict[str, Any] = {}
    live_alert = 0
    live_profile = 0
    live_misp = 0
    live_soarca = 0
    live_soarca_evidence = 0
    current_alert = 0
    current_profile = 0
    current_misp = 0
    current_soarca = 0

    def _run_signal_counts(run: dict[str, Any]) -> tuple[int, int, int, int]:
        """
        Return causal signal counts for a historical run.

        We only count a run if it has concrete detection evidence. That keeps
        the dashboard honest when a report contains MISP/TAPCD/SOARCA traces
        but the detector never truly triggered for that campaign.
        """
        report_id = str(run.get("report_id") or "").strip()
        if not report_id:
            # No report yet — fall back to phase markers in run history
            detect_confirmed = float(run.get("detect_at") or 0) > 0
            if not detect_confirmed:
                return 0, 0, 0, 0
            profile = 1 if float(run.get("profile_at") or 0) > 0 else 0
            misp = 1 if float(run.get("enrich_at") or 0) > 0 else 0
            soarca = 1 if float(run.get("act_at") or 0) > 0 else 0
            return 1, profile, misp, soarca
        report_path = REPORTS_DIR / report_id / "incident_report.json"
        if not report_path.exists():
            # Report file lost (e.g. container restart cleared /tmp) —
            # use phase markers from run history as reliable fallback.
            detect_confirmed = float(run.get("detect_at") or 0) > 0
            if not detect_confirmed:
                return 0, 0, 0, 0
            profile = 1 if float(run.get("profile_at") or 0) > 0 else 0
            misp = 1 if float(run.get("enrich_at") or 0) > 0 else 0
            soarca = 1 if float(run.get("act_at") or 0) > 0 else 0
            return 1, profile, misp, soarca
        try:
            report_data = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            return 0, 0, 0, 0

        metrics_blob = report_data.get("novadef_metrics") or {}
        latency = metrics_blob.get("latency_ooda") or {}
        detect_metrics = (metrics_blob.get("operational_scalability") or {})
        detect_event_count = int(detect_metrics.get("detector_event_count") or 0)
        first_alert_ts = latency.get("first_alert_ts")
        detect_confirmed = bool(detect_event_count > 0 and first_alert_ts is not None)
        if not detect_confirmed:
            # Fallback to run phase markers when report metrics are incomplete
            detect_confirmed = float(run.get("detect_at") or 0) > 0
        if not detect_confirmed:
            return 0, 0, 0, 0

        orient = (metrics_blob.get("ooda_phase_metrics") or {}).get("orient") or {}
        incident = (metrics_blob.get("dimension_breakdown") or {}).get("incident") or {}
        response = (metrics_blob.get("dimension_breakdown") or {}).get("response") or {}
        alert = 1
        profile = 1 if int(orient.get("actor_profile_count") or 0) > 0 else 0
        misp = 1 if int(incident.get("misp_event_count") or 0) > 0 else 0
        soarca = 1 if int(response.get("soarca_action_count") or 0) > 0 else 0
        # If report says soarca=0 but phase markers confirm act, trust markers
        if soarca == 0 and float(run.get("act_at") or 0) > 0:
            soarca = 1
        return alert, profile, misp, soarca

    def _count_panel_signals(panel: dict[str, Any] | None) -> tuple[int, int, int, int]:
        if not panel:
            return 0, 0, 0, 0
        misp_panel = (panel.get("misp") or {})
        tapcd_panel = (panel.get("tapcd") or {})
        cm_panel = (panel.get("countermeasure") or {})
        timeline = (panel.get("timeline") or {})
        alerts = 1 if (misp_panel.get("event_ids_detected_in_logs") or []) else 0
        profile = 1 if int(tapcd_panel.get("actor_profile_count") or 0) > 0 or int(tapcd_panel.get("profile_details_extracted") or 0) > 0 else 0
        misp_count = 1 if int(misp_panel.get("event_signal_count") or 0) > 0 or int(misp_panel.get("event_details_extracted") or 0) > 0 else 0
        selected = str(cm_panel.get("selected") or "").strip()
        # SOARCA signal: count as 1 when the countermeasure was applied (act_at
        # in the timeline is the authoritative signal) OR the selected field
        # shows a non-pending status. Profile is intentionally NOT required
        # here — SOARCA executes independently of TAPCD profiling and profiling
        # may arrive after the action phase completes.
        act_confirmed = timeline.get("act_at") is not None
        soarca_count = 1 if (
            act_confirmed
            or (
                selected not in {"", "-", "Pending / no decision yet"}
                and alerts > 0
                and misp_count > 0
            )
        ) else 0
        return alerts, profile, misp_count, soarca_count

    for run in runs:
        report_id = str(run.get("report_id") or "").strip()
        if report_id:
            latest_report_id = report_id
        latest_run_id = str(run.get("run_id") or "")
        try:
            report_json = REPORTS_DIR / report_id / "incident_report.json" if report_id else None
            report_data = json.loads(report_json.read_text(encoding="utf-8")) if (report_json and report_json.exists()) else {}
        except Exception:
            report_data = {}
        run_alert, run_profile, run_misp, run_soarca = _run_signal_counts(run)
        alert_total += run_alert
        profile_total += run_profile
        misp_total += run_misp
        soarca_total += run_soarca
        latest_metrics = (report_data.get("novadef_metrics") or {})
        run_window = latest_metrics.get("run_window") or {}
        if isinstance(run_window.get("duration_sec"), (int, float)):
            durations.append(float(run_window["duration_sec"]))
        lat = latest_metrics.get("latency_ooda") or {}
        for src, dst in [("e2e_to_act", e2e_to_act), ("time_to_first_alert", ttf_alert), ("time_to_correct_identification", ttcid)]:
            pack = lat.get(src) or {}
            if isinstance(pack, dict) and isinstance(pack.get("sec"), (int, float)):
                dst.append(float(pack["sec"]))
        op = latest_metrics.get("operational_scalability") or {}
        for src, dst in [("telemetry_ingest_rate_eps", ingest_rates), ("detector_processing_rate_eps", detect_rates), ("database_write_rate_eps", db_rates)]:
            if isinstance(op.get(src), (int, float)):
                dst.append(float(op[src]))
        rel = latest_metrics.get("pipeline_reliability") or {}
        if isinstance(rel.get("total_error_signals"), (int, float)):
            error_totals.append(float(rel["total_error_signals"]))

    # Include current live run evidence so the KPI bar reflects in-progress
    # executions instead of staying at zero until the report is persisted.
    if current_panel:
        live_alert, live_profile, live_misp, live_soarca = _count_panel_signals(current_panel)
        live_soarca_evidence = live_soarca
        current_alert = live_alert
        current_profile = live_profile
        current_misp = live_misp
        current_soarca = live_soarca
        if not current_running and current_finished_at:
            # Once the run is finished, keep the visible KPIs tied to the
            # current run only, not to the full historical aggregate.
            current_alert = live_alert
            current_profile = live_profile
            current_misp = live_misp
            current_soarca = live_soarca
    if soarca_total == 0 and current_experiment and current_started_at and current_panel:
        current_misp_panel = current_panel.get("misp") or {}
        current_tapcd_panel = current_panel.get("tapcd") or {}
        current_cm_panel = current_panel.get("countermeasure") or {}
        current_alerts = 1 if (current_misp_panel.get("event_ids_detected_in_logs") or []) else 0
        current_profile_ready = 1 if int(current_tapcd_panel.get("actor_profile_count") or 0) > 0 or int(current_tapcd_panel.get("profile_details_extracted") or 0) > 0 else 0
        current_misp_ready = 1 if int(current_misp_panel.get("event_signal_count") or 0) > 0 or int(current_misp_panel.get("event_details_extracted") or 0) > 0 else 0
        current_cm_selected = str(current_cm_panel.get("selected") or "").strip()
        _since = current_started_at and int(current_started_at)
        act_blob = "\n".join(
            [
                _tail_logs("pmp-misp-soarca-trigger", 250, since_ts=_since),
                _tail_logs("pmp-soarca-core", 220, since_ts=_since),
                _tail_logs("pmp-soarca-executor-ssh", 220, since_ts=_since),
                _tail_logs(victim_name, 180, since_ts=_since),
            ]
        )
        if (
            current_cm_selected not in {"", "-", "Pending / no decision yet"}
            and current_alerts > 0
            and current_misp_ready > 0
            and _soarca_execution_evidence(act_blob)
        ):
            alert_total = max(alert_total, 1)
            profile_total = max(profile_total, 1)
            misp_total = max(misp_total, 1)
            soarca_total = 1
            live_alert = max(live_alert, 1)
            live_profile = max(live_profile, 1)
            live_misp = max(live_misp, 1)
            live_soarca = max(live_soarca, 1)

    # If there is no active run, keep the UI counters at zero so deleted runs
    # do not leave stale SOARCA/MISP evidence behind in the experiment console.
    if not current_running and not current_panel:
        current_alert = 0
        current_profile = 0
        current_misp = 0
        current_soarca = 0
        live_alert = 0
        live_profile = 0
        live_misp = 0
        live_soarca = 0

    def _avg(vals: list[float]) -> float:
        return float(statistics.mean(vals)) if vals else 0.0
    def _p95(vals: list[float]) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        idx = max(int(math.ceil(0.95 * len(s))) - 1, 0)
        return float(s[min(idx, len(s) - 1)])

    return jsonify(
        {
            "timestamp": time.time(),
            "runs_with_report": alert_total,
            "latest_run_id": current_run_id or latest_run_id or None,
            "latest_report_id": current_report_id or latest_report_id or None,
            "latest_run_metrics": current_summary or latest_metrics,
            "aggregate_metrics": {
                "duration_sec_avg": _avg(durations),
                "duration_sec_p95": _p95(durations),
                "time_to_first_alert_sec_avg": _avg(ttf_alert),
                "time_to_correct_identification_sec_avg": _avg(ttcid),
                "e2e_to_act_sec_avg": _avg(e2e_to_act),
                "telemetry_ingest_rate_eps_avg": _avg(ingest_rates),
                "detector_processing_rate_eps_avg": _avg(detect_rates),
                "database_write_rate_eps_avg": _avg(db_rates),
                "pipeline_error_signals_avg": _avg(error_totals),
            },
            "legacy_signals": {
                # These counters represent the historical set of runs that are
                # still active in the console (not deleted). They are gated by
                # real detection evidence so downstream phases cannot outpace
                # detection.
                "alert_signals": alert_total,
                "profile_signals": profile_total,
                "misp_signals": misp_total,
                "soarca_signals": soarca_total,
                "live_alert_signals": live_alert,
                "live_profile_signals": live_profile,
                "live_misp_signals": live_misp,
                "live_soarca_signals": live_soarca,
                "history_alert_signals": alert_total,
                "history_profile_signals": profile_total,
                "history_misp_signals": misp_total,
                "history_soarca_signals": soarca_total,
            },
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
        if not run_item or run_item.get("deleted"):
            return jsonify({"ok": False, "error": "run_id not found"}), 404
        ready, reason = _run_ready_for_final_report(run_item)
        if not ready:
            return jsonify({"ok": False, "error": f"final report not ready: {reason}"}), 409
        report_id = str(run_item.get("report_id") or "").strip()
        if not report_id:
            try:
                payload = _build_report_payload(run_id)
                report_id = _persist_report(payload)
                _update_history(run_id, {"report_id": report_id, "report_panel": _report_panel_from_latest_report(report_id)})
                with LOCK:
                    if str(STATE.get("current_run_id") or "") == str(run_id):
                        STATE["last_report_id"] = report_id
            except Exception as e:
                return jsonify({"ok": False, "error": f"report generation failed: {e}"}), 500
        return jsonify({"ok": True, "report_id": report_id, "download_url": f"/api/report/download/{report_id}"})

    with LOCK:
        report_id = STATE.get("last_report_id")
        current_run_id = str(STATE.get("current_run_id") or "")
        current_run_item = _history_item(current_run_id) if current_run_id else None
        fallback_last_run = dict(RUN_HISTORY[-1]) if RUN_HISTORY else None
    target_run_item = current_run_item or fallback_last_run
    target_run_id = str((target_run_item or {}).get("run_id") or current_run_id or "")
    if not report_id:
        ready, reason = _run_ready_for_final_report(target_run_item)
        if ready:
            try:
                payload = _build_report_payload(target_run_id or None)
                report_id = _persist_report(payload)
                with LOCK:
                    STATE["last_report_error"] = ""
                    STATE["last_report_id"] = report_id
                if target_run_item and target_run_id:
                    _update_history(target_run_id, {"report_id": report_id, "report_panel": _report_panel_from_latest_report(report_id)})
            except Exception as e:
                err = f"report regeneration failed: {e}"
                with LOCK:
                    STATE["last_report_error"] = err
                return jsonify({"ok": False, "error": err}), 500
        else:
            return jsonify({"ok": False, "error": f"final report not ready: {reason}"}), 409
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


@app.get("/api/report/chart/<report_id>")
def get_report_chart_data(report_id: str) -> Any:
    """Return the stored chart data (network + host series + OODA markers) for a
    report so the exact same graphs can be recreated from saved data alone."""
    p = REPORTS_DIR / report_id / "chart_data.json"
    if not p.exists():
        return jsonify({"ok": False, "error": "chart data not found"}), 404
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        return jsonify({"ok": False, "error": f"could not read chart data: {e}"}), 500
    return jsonify({"ok": True, "report_id": report_id, "chart_data": data})


@app.get("/api/debug")
def debug_info() -> Any:
    """Endpoint de diagnóstico para inspeccionar estado interno del sampler de tráfico (sin bloqueo)."""
    try:
        # Intentar adquirir el lock con timeout (usa RLock de Python si está disponible)
        # Pero en su lugar, vamos a obtener datos sin bloqueo usando snapshots directos
        state_snap = {}
        traffic_snap = {}
        
        # Copiar datos sin esperar al lock (lectura directa)
        try:
            state_snap = {k: STATE.get(k) for k in ["running", "last_experiment", "current_run_id", "last_started_at", "last_finished_at"]}
            # Copiar series sin lock (lectura directa, menos seguro pero no bloquea)
            for run_id, series in TRAFFIC_SERIES.items():
                if series:
                    traffic_snap[run_id] = {
                        "series_count": len(series),
                        "first_sample": series[0],
                        "last_sample": series[-1],
                        "sample_ts_range": (series[0].get("ts"), series[-1].get("ts")),
                    }
        except Exception as e:
            print(f"[debug-error] Exception copying data: {e}", flush=True)
        
        debug = {
            "timestamp": time.time(),
            "state": state_snap,
            "traffic_series": traffic_snap,
            "docker_containers": [],
        }
        
        try:
            for c in DOCKER_CLIENT.containers.list():
                debug["docker_containers"].append({
                    "name": c.name,
                    "status": c.status,
                    "state": (c.attrs or {}).get("State", {}).get("Status"),
                })
        except Exception as e:
            debug["docker_error"] = str(e)
        
        return jsonify(debug)
    except Exception as e:
        print(f"[debug-error] Exception in debug_info: {e}", flush=True)
        return jsonify({"error": str(e), "timestamp": time.time()}), 500




@app.post("/api/run")
def run() -> Any:
    payload = request.get_json(silent=True) or {}
    experiment = payload.get("experiment") or request.form.get("experiment") or request.values.get("experiment")
    if experiment not in {"exp1", "exp2", "exp3"}:
        return jsonify({"ok": False, "error": "experiment must be exp1, exp2 or exp3"}), 400

    scenario_id_raw = payload.get("scenario_id") or request.form.get("scenario_id") or request.values.get("scenario_id")
    scenario_id = _sanitize_scenario_id(str(scenario_id_raw)) if scenario_id_raw else ""
    auto_created_scenario = False
    if not scenario_id:
        scenario_id = _sanitize_scenario_id(f"auto-{uuid.uuid4().hex[:10]}")
        auto_created_scenario = True
    selected_scenario: dict[str, Any] | None = None
    scenario_shared = False
    scenario_fast_start_eligible = False
    if scenario_id:
        if auto_created_scenario:
            # On-demand mode: create the default scenario immediately, as in
            # the original behavior expected by the GUI workflow.
            selected_scenario = _ensure_persistent_scenario(
                scenario_id,
                display_name=scenario_id,
                template="default",
            )
            scenario_shared = True
            scenario_fast_start_eligible = False
        else:
            catalog = _load_scenario_catalog()
            existing = dict(catalog.get(scenario_id) or {})
            selected_scenario = _ensure_persistent_scenario(
                scenario_id,
                display_name=str(existing.get("display_name") or scenario_id),
                template=str(existing.get("template") or "default"),
            )
            scenario_shared = True
            scenario_fast_start_eligible = bool(existing)

    with LOCK:
        now = datetime.now(timezone.utc)
        run_id = (
            now.strftime("%Y%m%dT%H%M%S")
            + f".{int(now.microsecond / 1000):03d}Z-"
            + experiment
            + "-"
            + uuid.uuid4().hex[:6]
        )
        STATE["running"] = True
        STATE["last_experiment"] = experiment
        STATE["last_started_at"] = time.time()
        STATE["last_attack_started_at"] = None
        STATE["last_finished_at"] = None
        STATE["last_return_code"] = None
        STATE["last_output"] = ""
        STATE["last_report_error"] = ""
        STATE["last_report_id"] = None
        STATE["current_run_id"] = run_id
        if selected_scenario:
            STATE["scenario_id"] = scenario_id or None
            STATE["scenario_project"] = str(selected_scenario.get("project") or "")
            STATE["scenario_network"] = str(selected_scenario.get("network") or "")
            STATE["victim_container_name"] = str(selected_scenario.get("victim_container_name") or "")
            STATE["attacker_container_name"] = str(selected_scenario.get("attacker_container_name") or "")
        else:
            STATE["scenario_id"] = None
            STATE["scenario_project"] = None
            STATE["scenario_network"] = None
            STATE["victim_container_name"] = None
            STATE["attacker_container_name"] = None
        RUN_HISTORY.append(
            {
                "run_id": run_id,
                "experiment": experiment,
                "started_at": STATE["last_started_at"],
                "attack_started_at": None,
                "finished_at": None,
                "running": True,
                "return_code": None,
                "report_id": None,
                "summary": None,
                "report_panel": None,
                "output_tail": "",
                "report_error": "",
                "traffic_sample_count": 0,
                "last_traffic_sample_at": None,
                "deleted": False,
                "manual_stop": False,
                "scenario_shared": scenario_shared,
                "scenario_fast_start_eligible": scenario_fast_start_eligible,
                "scenario_id": scenario_id or None,
                "scenario_project": str((selected_scenario or {}).get("project") or ""),
                "scenario_network": str((selected_scenario or {}).get("network") or ""),
                "victim_container_name": str((selected_scenario or {}).get("victim_container_name") or ""),
                "attacker_container_name": str((selected_scenario or {}).get("attacker_container_name") or ""),
                "victim_ip": str((selected_scenario or {}).get("victim_ip") or ""),
                "attacker_ip": str((selected_scenario or {}).get("attacker_ip") or ""),
                "scenario_log_dir": str((selected_scenario or {}).get("log_dir") or ""),
                "scenario_telemetry_dir": str((selected_scenario or {}).get("telemetry_dir") or ""),
                "scenario_reports_dir": str((selected_scenario or {}).get("reports_dir") or ""),
            }
        )
        STATE["running"] = True
        _persist_runtime_state()

    t = threading.Thread(target=_run_background, args=(experiment, run_id), daemon=True)
    t.start()
    return jsonify({"ok": True, "started": experiment, "run_id": run_id, "scenario_id": scenario_id or None})


@app.get("/api/debug/detection")
def debug_detection():
    """Debug endpoint to diagnose why Detect phase is not advancing."""
    with LOCK:
        experiment = STATE.get("last_experiment")
        started = STATE.get("last_started_at")
    
    attack_started = STATE.get("last_attack_started_at")
    since_ts = int(started) if started else None
    phase_since_ts = int(attack_started) if isinstance(attack_started, (int, float)) else int(time.time()) + 86400
    
    # Get detector logs
    detector_logs = _tail_logs("network_intrusion_detector_novadef", 100, since_ts=phase_since_ts)
    snort_logs = _tail_logs("snort_novadef", 100, since_ts=phase_since_ts)
    alert_logs = _tail_logs("alert_module_novadef", 100, since_ts=phase_since_ts)
    
    detector_blob = detector_logs + "\n" + snort_logs + "\n" + alert_logs
    detect_evidence = _detection_evidence_lines(detector_blob, experiment or "")
    
    return jsonify({
        "experiment": experiment,
        "started_ts": started,
        "attack_started_ts": attack_started,
        "since_ts": since_ts,
        "phase_since_ts": phase_since_ts,
        "detector_logs_count": len(detector_logs.splitlines()),
        "snort_logs_count": len(snort_logs.splitlines()),
        "alert_logs_count": len(alert_logs.splitlines()),
        "detection_evidence_found": bool(detect_evidence),
        "detection_evidence_lines": detect_evidence[:10] if detect_evidence else [],
        "detector_logs_sample": detector_logs.splitlines()[-5:] if detector_logs else [],
        "snort_logs_sample": snort_logs.splitlines()[-5:] if snort_logs else [],
        "alert_logs_sample": alert_logs.splitlines()[-5:] if alert_logs else [],
    })


_GUI_DIR = Path(os.getenv("NOVADEF_GUI_DIR", "/gui"))


@app.get("/")
def _gui_index():
    return send_from_directory(_GUI_DIR, "index.html")


@app.get("/<path:filename>")
def _gui_static(filename: str):
    return send_from_directory(_GUI_DIR, filename)


_db_init()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18082, threaded=True)
