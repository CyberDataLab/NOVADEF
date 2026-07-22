# -*- coding: utf-8 -*-
"""
Kafka IN (flow_conditional_agg) → PREPROC → 8 ML → HL → Kafka OUT (profiles_out)

Logs cortos (no técnicos):
  📥 recibido
  ✉️ <payload crudo del tópico>
  🛠️ preprocesando
  🧮 features listas
  📤 enviado
  ⚠️ ignorado

SQL Injection (sin patrones de texto):
  - Si 'attack' indica SQL Injection → overrides numéricos:
      * Profile = "hacker" (siempre)
      * AutomationLevel ∈ {0,1,2}
      * Skills según amplitud/variabilidad y automatización
      * RiskLevel = modelo ± bump suave (cap [1..10])
"""
from __future__ import annotations
import argparse, csv, io, json, logging, math, os, re, sys, signal, threading, time, datetime as _dt
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from hashlib import md5
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# ───────────────────────── Kafka ─────────────────────────
try:
    from kafka import KafkaConsumer, KafkaProducer
except Exception:
    print("❌ Falta kafka-python (pip install kafka-python==2.0.2)", flush=True)
    sys.exit(2)

# ───────────────────────── Models ───────────────────────
try:
    import joblib
except Exception:
    print("❌ Falta joblib (pip install joblib)", flush=True)
    sys.exit(2)

# ───────────────────────── Explainability (optional) ─────
# SHAP is only used for the "Profile" model's explanation (the field the
# dashboard cares about — "why was this actor classified as crime-syndicate,
# not nation-state"). If the package is missing, prep_pred still runs and
# simply skips this field entirely — Explainability was appended as the
# LAST column of PROFILE_COLUMNS specifically so its absence never shifts
# any of the other 27 positional fields app.py already parses.
try:
    import shap
except Exception:
    shap = None

# ───────────────────────── GeoIP (optional) ─────────────
try:
    import ipaddress
except Exception:
    print("❌ Falta ipaddress (stdlib).", flush=True)
    sys.exit(2)

try:
    import geoip2.database
except Exception:
    geoip2 = None  # opcional

# ───────────────────── Logging ─────────────────────
LOG = logging.getLogger("stream-preproc-ml-hl")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
LOG.handlers.clear()
LOG.addHandler(_handler)

def _setup_log_level():
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG.setLevel(getattr(logging, level, logging.INFO))

def wait_for_service(label: str, factory, validator=None, timeout_sec: Optional[float] = None,
                     retry_sec: Optional[float] = None):
    timeout = timeout_sec or float(os.getenv("STARTUP_MAX_WAIT_SEC", "180"))
    delay = retry_sec or float(os.getenv("STARTUP_RETRY_SEC", "5"))
    deadline = time.monotonic() + timeout
    attempt = 0
    last_exc = None

    while time.monotonic() < deadline:
        attempt += 1
        resource = None
        try:
            resource = factory()
            if validator is not None:
                validator(resource)
            return resource
        except Exception as exc:
            last_exc = exc
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
            print(f"⏳ Esperando {label} (intento {attempt})", flush=True)
            time.sleep(delay)

    raise RuntimeError(f"No fue posible conectar con {label}: {last_exc}")

# ───────────────────── Input header ─────────────────────
EXPECTED_HEADER = [
    "id","campaign_id","threat_type","threat","attack","stage",
    "ips_src","ips_dst","ports_src","ports_dst",
    "total_flows","total_packets_sent","total_packets_received",
    "total_bytes_sent","total_bytes_received",
    "avg_flow_duration","std_flow_duration","iqr_flow_duration",
    "skewness_flow_duration","kurtosis_flow_duration","variance_packet_size",
    "protocol_distribution","udp_count","tcp_count","unique_dst_ports_count",
    "most_frequent_dst_port","num_unique_src_ports","most_frequent_src_port",
    "syn_count","ack_count","fin_count","rst_count","psh_count","urg_count",
    "mean_iat","std_iat","max_iat","min_iat",
    "first_seen","last_activity",
    "active_time_ratio","total_idle_time","avg_idle_time_between_flows","max_idle_time",
    "unique_dst_ips","entropy_dst_ips","repeated_connections_frequency","time_diff",
    "avg_packet_size","flow_rate_per_sec","packet_rate_per_sec","byte_rate_per_sec",
    "syn_ack_ratio","rst_syn_ratio","ratio_fwd_to_bwd_packets","ratio_fwd_to_bwd_bytes",
    "active_to_idle_ratio","udp_tcp_traffic_ratio",
    "unique_dst_ports_group","unique_sessions_count","avg_time_between_connections",
    "unique_dst_ips_group","avg_time_between_flows","total_flows_ip","entropy_dst_ports",
    "flow_duration_to_packet_ratio","byte_sent_received_ratio","unique_ports_per_dst_ip_ratio",
    "rst_syn_flag_ratio","fin_to_syn_ratio","urg_to_ack_ratio","psh_to_syn_ratio",
    "port_change_frequency","dst_ip_change_frequency",
    "ddos_indicator","port_scan_indicator","brute_force_indicator","data_exfiltration_indicator",
    "flow_frequency_per_minute","extreme_flow_duration_count","num_flows_in_high_traffic_periods",
    "active_std","idle_std","fwd_packet_size_range","bwd_packet_size_range",
    "fwd_packet_size_to_mean_ratio","bwd_packet_size_to_mean_ratio","flow_variance_ratio","high_variance_flow",
]

# ───────────────────── Feature engineering ─────────────
NUM_IP_BUCKETS = 16
NUM_PORT_BUCKETS = 64
SEP_PAT = re.compile(r"[;\|\s]+")

def clean_number(x) -> float:
    try:
        if x is None:
            return 0.0
        if isinstance(x, str):
            xs = x.strip().lower()
            if xs in ("", "nan", "none", "null", "inf", "+inf", "-inf"):
                return 0.0
        v = float(x)
        return v if math.isfinite(v) else 0.0
    except Exception:
        return 0.0

def split_list(s: str) -> List[str]:
    if not s or not isinstance(s, str):
        return []
    return [x for x in SEP_PAT.split(s.strip()) if x]

def md5_bucket(s: str, buckets: int) -> int:
    h = md5(s.encode("utf-8", errors="ignore")).digest()
    return int.from_bytes(h[:4], "big") % buckets

def parse_protocol_distribution(raw, udp_count, tcp_count):
    cnt = defaultdict(float)
    if isinstance(raw, str) and raw.strip():
        txt = raw.replace("'", '"')
        try:
            d = json.loads(txt)
            if isinstance(d, dict):
                for k, v in d.items():
                    ku = str(k).upper()
                    if ku == "TCP": cnt["tcp"] += clean_number(v)
                    elif ku == "UDP": cnt["udp"] += clean_number(v)
                    elif ku == "ICMP": cnt["icmp"] += clean_number(v)
                    else: cnt["other"] += clean_number(v)
        except Exception:
            for token in re.split(r"[{},]", raw):
                if ":" in token:
                    k, v = token.split(":", 1)
                    ku = k.strip().strip('"').strip("'").upper()
                    if ku == "TCP": cnt["tcp"] += clean_number(v)
                    elif ku == "UDP": cnt["udp"] += clean_number(v)
                    elif ku == "ICMP": cnt["icmp"] += clean_number(v)
                    else: cnt["other"] += clean_number(v)
    if not cnt:
        if clean_number(tcp_count) > 0: cnt["tcp"] += clean_number(tcp_count)
        if clean_number(udp_count) > 0: cnt["udp"] += clean_number(udp_count)
    total = float(sum(cnt.values()))
    return (float(cnt.get("tcp", 0.0)),
            float(cnt.get("udp", 0.0)),
            float(cnt.get("icmp", 0.0)),
            float(cnt.get("other", 0.0)),
            total)

def out_cols():
    base = [
        "total_flows","total_packets_sent","total_packets_received",
        "total_bytes_sent","total_bytes_received",
        "avg_flow_duration","std_flow_duration","iqr_flow_duration",
        "skewness_flow_duration","kurtosis_flow_duration","variance_packet_size",
        "udp_count","tcp_count","unique_dst_ports_count","most_frequent_dst_port",
        "num_unique_src_ports","most_frequent_src_port",
        "syn_count","ack_count","fin_count","rst_count","psh_count","urg_count",
        "mean_iat","std_iat","max_iat","min_iat",
        "active_time_ratio","total_idle_time","avg_idle_time_between_flows","max_idle_time",
        "unique_dst_ips","entropy_dst_ips","repeated_connections_frequency","time_diff",
        "avg_packet_size","flow_rate_per_sec","packet_rate_per_sec","byte_rate_per_sec",
        "syn_ack_ratio","rst_syn_ratio","ratio_fwd_to_bwd_packets","ratio_fwd_to_bwd_bytes",
        "active_to_idle_ratio","udp_tcp_traffic_ratio",
        "unique_dst_ports_group","unique_sessions_count","avg_time_between_connections",
        "unique_dst_ips_group","avg_time_between_flows","total_flows_ip","entropy_dst_ports",
        "flow_duration_to_packet_ratio","byte_sent_received_ratio","unique_ports_per_dst_ip_ratio",
        "rst_syn_flag_ratio","fin_to_syn_ratio","urg_to_ack_ratio","psh_to_syn_ratio",
        "port_change_frequency","dst_ip_change_frequency",
        "ddos_indicator","port_scan_indicator","brute_force_indicator","data_exfiltration_indicator",
        "flow_frequency_per_minute","extreme_flow_duration_count","num_flows_in_high_traffic_periods",
        "active_std","idle_std","fwd_packet_size_range","bwd_packet_size_range",
        "fwd_packet_size_to_mean_ratio","bwd_packet_size_to_mean_ratio","flow_variance_ratio","high_variance_flow",
        "proto_tcp","proto_udp","proto_icmp","proto_other","proto_total",
    ]
    base += [f"ips_src_bucket_{i:02d}" for i in range(NUM_IP_BUCKETS)]
    base += ["ips_src_count","ips_src_unique","ips_src_private_v4","ips_src_v4_count","ips_src_v6_count",
             "ips_src_unique_ratio","ips_src_private_ratio"]
    base += [f"ips_dst_bucket_{i:02d}" for i in range(NUM_IP_BUCKETS)]
    base += ["ips_dst_count","ips_dst_unique","ips_dst_private_v4","ips_dst_v4_count","ips_dst_v6_count",
             "ips_dst_unique_ratio","ips_dst_private_ratio"]
    base += [f"ports_src_bucket_{i:02d}" for i in range(NUM_PORT_BUCKETS)]
    base += ["ports_src_count","ports_src_unique","ports_src_unique_ratio","ports_src_min","ports_src_max","ports_src_mean"]
    base += [f"ports_dst_bucket_{i:02d}" for i in range(NUM_PORT_BUCKETS)]
    base += ["ports_dst_count","ports_dst_unique","ports_dst_unique_ratio","ports_dst_min","ports_dst_max","ports_dst_mean"]
    base += ["ips_dst_density","ips_src_density","ports_dst_unique_ratio2","ports_src_unique_ratio2",
             "endpoints_total_count","ports_total_count"]
    return base

OUT_COLS = out_cols()

def featurize(row: Dict[str, Any]) -> Dict[str, float]:
    out = {c: 0.0 for c in OUT_COLS}
    for k in [
        "total_flows","total_packets_sent","total_packets_received",
        "total_bytes_sent","total_bytes_received",
        "avg_flow_duration","std_flow_duration","iqr_flow_duration",
        "skewness_flow_duration","kurtosis_flow_duration","variance_packet_size",
        "udp_count","tcp_count","unique_dst_ports_count","most_frequent_dst_port",
        "num_unique_src_ports","most_frequent_src_port",
        "syn_count","ack_count","fin_count","rst_count","psh_count","urg_count",
        "mean_iat","std_iat","max_iat","min_iat",
        "active_time_ratio","total_idle_time","avg_idle_time_between_flows","max_idle_time",
        "unique_dst_ips","entropy_dst_ips","repeated_connections_frequency","time_diff",
        "avg_packet_size","flow_rate_per_sec","packet_rate_per_sec","byte_rate_per_sec",
        "syn_ack_ratio","rst_syn_ratio","ratio_fwd_to_bwd_packets","ratio_fwd_to_bwd_bytes",
        "active_to_idle_ratio","udp_tcp_traffic_ratio",
        "unique_dst_ports_group","unique_sessions_count","avg_time_between_connections",
        "unique_dst_ips_group","avg_time_between_flows","total_flows_ip","entropy_dst_ports",
        "flow_duration_to_packet_ratio","byte_sent_received_ratio","unique_ports_per_dst_ip_ratio",
        "rst_syn_flag_ratio","fin_to_syn_ratio","urg_to_ack_ratio","psh_to_syn_ratio",
        "port_change_frequency","dst_ip_change_frequency",
        "ddos_indicator","port_scan_indicator","brute_force_indicator","data_exfiltration_indicator",
        "flow_frequency_per_minute","extreme_flow_duration_count","num_flows_in_high_traffic_periods",
        "active_std","idle_std","fwd_packet_size_range","bwd_packet_size_range",
        "fwd_packet_size_to_mean_ratio","bwd_packet_size_to_mean_ratio","flow_variance_ratio","high_variance_flow",
    ]:
        out[k] = clean_number(row.get(k, 0))
    p_tcp, p_udp, p_icmp, p_oth, p_tot = parse_protocol_distribution(
        row.get("protocol_distribution",""), row.get("udp_count"), row.get("tcp_count")
    )
    out["proto_tcp"], out["proto_udp"], out["proto_icmp"], out["proto_other"], out["proto_total"] = p_tcp, p_udp, p_icmp, p_oth, p_tot

    def fill_ip_side(ips_raw: str, prefix: str):
        ips = split_list(ips_raw)
        buckets = [0.0]*NUM_IP_BUCKETS; v4=v6=priv=0
        for ip in ips:
            b = md5_bucket(ip, NUM_IP_BUCKETS); buckets[b]+=1.0
            try:
                obj = ipaddress.ip_address(ip)
                if obj.version == 4:
                    v4 += 1
                    if obj.is_private: priv += 1
                elif obj.version == 6:
                    v6 += 1
            except Exception:
                pass
        for i,v in enumerate(buckets): out[f"{prefix}_bucket_{i:02d}"]=float(v)
        count=float(len(ips)); uniq=float(len(set(ips)))
        out[f"{prefix}_count"]=count; out[f"{prefix}_unique"]=uniq
        out[f"{prefix}_v4_count"]=float(v4); out[f"{prefix}_v6_count"]=float(v6); out[f"{prefix}_private_v4"]=float(priv)
        out[f"{prefix}_unique_ratio"]=(uniq/count) if count>0 else 0.0
        out[f"{prefix}_private_ratio"]=(priv/v4) if v4>0 else 0.0

    fill_ip_side(row.get("ips_src",""), "ips_src")
    fill_ip_side(row.get("ips_dst",""), "ips_dst")

    def fill_ports_side(raw_ports: str|int|float, prefix: str):
        ports=[]
        if isinstance(raw_ports, (int, float)) and not isinstance(raw_ports, bool):
            p = int(raw_ports); ports = [p] if 0<=p<=65535 else []
        else:
            for tok in split_list(str(raw_ports)):
                try:
                    p = int(float(tok))
                    if 0 <= p <= 65535: ports.append(p)
                except Exception:
                    pass
        buckets=[0.0]*NUM_PORT_BUCKETS
        for p in ports:
            idx=min(NUM_PORT_BUCKETS-1, int(p*NUM_PORT_BUCKETS/65536)); buckets[idx]+=1.0
        for i,v in enumerate(buckets): out[f"{prefix}_bucket_{i:02d}"]=float(v)
        count=float(len(ports)); uniq=float(len(set(ports)))
        out[f"{prefix}_count"]=count; out[f"{prefix}_unique"]=uniq
        out[f"{prefix}_unique_ratio"]=(uniq/count) if count>0 else 0.0
        out[f"{prefix}_min"]=float(min(ports)) if ports else 0.0
        out[f"{prefix}_max"]=float(max(ports)) if ports else 0.0
        out[f"{prefix}_mean"]=float(mean(ports)) if ports else 0.0

    fill_ports_side(row.get("ports_src",""), "ports_src")
    fill_ports_side(row.get("ports_dst",""), "ports_dst")

    out["endpoints_total_count"] = out["ips_src_unique"] + out["ips_dst_unique"]
    out["ips_dst_density"] = (out["ips_dst_unique"] / max(1.0, out["ips_dst_count"])) if out["ips_dst_count"] > 0 else 0.0
    out["ips_src_density"] = (out["ips_src_unique"] / max(1.0, out["ips_src_count"])) if out["ips_src_count"] > 0 else 0.0
    out["ports_total_count"] = out["ports_src_count"] + out["ports_dst_count"]
    out["ports_dst_unique_ratio2"] = (out["ports_dst_unique"] / max(1.0, out["ports_dst_count"])) if out["ips_dst_count"] > 0 else 0.0
    out["ports_src_unique_ratio2"] = (out["ports_src_unique"] / max(1.0, out["ips_src_count"])) if out["ips_src_count"] > 0 else 0.0
    return out

# ───────────────────── Parsing helpers ──────────────────
def robust_decode(b: bytes, preferred: str = "utf-8") -> str:
    if b is None: return ""
    try:
        s = b.decode(preferred)
    except Exception:
        s = b.decode("latin-1", errors="replace")
    if s.startswith("\ufeff"): s = s.lstrip("\ufeff")
    return s

def parse_csv_message(raw_text: str) -> Dict[str, Any]:
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return {}
    lines = [ln for ln in raw_text.splitlines() if ln.strip() != ""]
    if not lines:
        return {}
    header_norm = ",".join(EXPECTED_HEADER).replace(" ", "")
    first_norm = lines[0].replace(" ", "")
    if first_norm.startswith(header_norm):
        rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
        return rows[-1] if rows else {}
    reader = csv.reader(io.StringIO(lines[-1]))
    vals = next(reader, None)
    if vals is None:
        return {}
    if len(vals) < len(EXPECTED_HEADER):
        vals += [""] * (len(EXPECTED_HEADER) - len(vals))
    return dict(zip(EXPECTED_HEADER, vals[:len(EXPECTED_HEADER)]))

# ───────────────────── HL schema / rules ───────────────
PROFILE_COLUMNS = [
    "Id","CampaignId","IPs","Target","PreferredTarget","FirstSeen","LastActivity",
    "Country","AutomationLevel","Evasion","TTPs","KillChainPhase",
    "RiskLevel","Tools","Skills",
    "Profile",
    "DetectionAlert","DetectionType","DetectionAttack","DetectionStage","DetectionTs",
    "Motivation","Knowledge","Attitude","Affiliation",
    "ThreatGroup","Campaigns","Comments",
    # Appended LAST (index 27) so existing 0-26 positional parsing in
    # app.py's _native_actor_profile_from_line never shifts. Compact
    # "feature:+contribution" pipe-separated string — the top SHAP
    # contributors toward the predicted Profile class, computed once per
    # profile in build_hl_record via _explain_profile_prediction().
    "Explainability",
    # Appended LAST (index 28), same reasoning as Explainability above: SHAP
    # explainability for EVERY ML-predicted field (Motivation/Knowledge/
    # Attitude/Affiliation/Skills/RiskLevel/AutomationLevel), not just
    # Profile — each has its own independent RandomForest pipeline (see
    # ML_KEYS/collect_models), so each can be explained the same way.
    # Compact "Field1=feat:+val|feat:+val;Field2=feat:+val|..." string, one
    # segment per field that had a usable prediction + explainer.
    "ExplainabilityAllFields",
]
ML_KEYS = ["AutomationLevel","RiskLevel","Profile","Motivation","Knowledge","Attitude","Affiliation","Skills"]
TARGET_CANON = {
    "automationlevel":"AutomationLevel","risklevel":"RiskLevel","profile":"Profile",
    "motivation":"Motivation","knowledge":"Knowledge","attitude":"Attitude",
    "affiliation":"Affiliation","skills":"Skills",
}
TACTIC_TO_KC = {
    "Reconnaissance":"Recon","Discovery":"Recon",
    "Initial Access":"Delivery","Resource Development":"Delivery",
    "Execution":"Exploitation","Exploit Public-Facing Application":"Exploitation",
    "Privilege Escalation":"Exploitation",
    "Persistence":"Installation","Defense Evasion":"Installation",
    "Lateral Movement":"Installation","Command and Control":"C2",
    "Exfiltration":"ActionsOnObjectives","Impact":"ActionsOnObjectives",
}
KC_ORDER=["Recon","Delivery","Exploitation","Installation","C2","ActionsOnObjectives"]
KC_IDX={k:i for i,k in enumerate(KC_ORDER)}

_geo = None
def setup_geoip(path: str):
    global _geo
    if not path or geoip2 is None or not os.path.exists(path):
        _geo = None; return
    try:
        _geo = geoip2.database.Reader(path)
    except Exception:
        _geo = None

_SPLIT = re.compile(r"[;, \t]+")
def split_ips(v): return [] if pd.isna(v) else [s for s in _SPLIT.split(str(v).strip()) if s]

def ip_to_country(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private: return "privada"
        if _geo:
            try:
                code = _geo.country(ip).country.iso_code
                return code or "desconocido"
            except Exception:
                return "desconocido"
        return "desconocido"
    except Exception:
        return "desconocido"

def countries_from_ips(lst):
    seen, out = set(), []
    for ip in lst:
        c = ip_to_country(ip) or "desconocido"
        if c not in seen:
            seen.add(c); out.append(c)
    return out

def _load_csv_df(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path, low_memory=False)
        if "mapping_hint" in df.columns:
            df["mapping_hint"] = df["mapping_hint"].fillna("").astype(str)
        return df
    except Exception:
        return pd.DataFrame()

# ───────────── Safe eval para mappings ─────────────
class _StrAccessor:
    def __init__(self, s: Any):
        self._s = "" if s is None else str(s)
    def contains(self, pat, case: bool = True, na: bool = False, regex: bool = True):
        try:
            text = self._s
            if text is None:
                return na
            if regex:
                flags = 0 if case else re.IGNORECASE
                return re.search(pat, text, flags) is not None
            else:
                if not case:
                    return str(pat).lower() in text.lower()
                return str(pat) in text
        except Exception:
            return na

class _ScalarWithStr:
    def __init__(self, s: Any):
        self.str = _StrAccessor(s)
    def __str__(self): return str(self.str._s)
    def __repr__(self): return repr(self.str._s)

def _safe_eval(expr: str, env: dict):
    return eval(expr, {"__builtins__": {}}, env)

def _eval_mapping_for_row(expr: str, flows: pd.DataFrame, idx) -> bool:
    env_series = {c: flows[c] for c in flows.columns}
    try:
        res = _safe_eval(expr, env_series)
        if isinstance(res, (pd.Series, np.ndarray, list, tuple)):
            try:
                if isinstance(res, pd.Series):
                    return bool(res.loc[idx])
                pos = list(flows.index).index(idx)
                return bool(np.asarray(res)[pos])
            except Exception:
                return bool(pd.Series(res, index=flows.index).loc[idx])
        return bool(res)
    except Exception:
        pass
    row = flows.loc[idx]
    env_row = {}
    for c in flows.columns:
        val = row[c]
        env_row[c] = _ScalarWithStr(val) if (isinstance(val, str) or flows[c].dtype == object) else val
    try:
        return bool(_safe_eval(expr, env_row))
    except Exception:
        return False

def build_ttps_sets(flows, mapdf):
    flows = flows.copy()
    for c in ("attack","stage","threat","threat_type","protocol_distribution","ports_dst"):
        if c in flows: flows[c] = flows[c].fillna("").astype(str)
    if "most_frequent_dst_port" in flows:
        flows["most_frequent_dst_port"] = pd.to_numeric(flows["most_frequent_dst_port"], errors="coerce").fillna(0)
    sets=[set() for _ in range(len(flows))]; sup=defaultdict(int)
    if mapdf is None or mapdf.empty:
        return sets, sup
    for idx in flows.index:
        for tech, expr in mapdf[["technique_id","mapping_hint"]].itertuples(index=False):
            try:
                if _eval_mapping_for_row(expr, flows, idx):
                    sets[idx].add(str(tech)); sup[str(tech)] += 1
            except Exception:
                continue
    return sets, sup

def build_evasion_sets(flows, evdf):
    flows = flows.copy()
    for c in ("attack","stage","threat","threat_type","protocol_distribution","ports_dst"):
        if c in flows: flows[c] = flows[c].fillna("").astype(str)
    if "most_frequent_dst_port" in flows:
        flows["most_frequent_dst_port"] = pd.to_numeric(flows["most_frequent_dst_port"], errors="coerce").fillna(0)
    sets=[set() for _ in range(len(flows))]
    if evdf is None or evdf.empty:
        return sets
    for idx in flows.index:
        for tag, expr in evdf[["evasion_tag","mapping_hint"]].itertuples(index=False):
            try:
                if _eval_mapping_for_row(expr, flows, idx):
                    sets[idx].add(str(tag))
            except Exception:
                continue
    return sets

def build_tools_column(flows, tdf):
    flows = flows.copy()
    for c in ("attack","stage","threat","threat_type","protocol_distribution","ports_dst"):
        if c in flows: flows[c] = flows[c].fillna("").astype(str)
    if "most_frequent_dst_port" in flows:
        flows["most_frequent_dst_port"] = pd.to_numeric(flows["most_frequent_dst_port"], errors="coerce").fillna(0)
    col = pd.Series("Unclassified", index=flows.index, dtype=object)
    if tdf is None or tdf.empty:
        return col
    for idx in flows.index:
        for name, expr in tdf[["tool_name","mapping_hint"]].itertuples(index=False):
            try:
                if _eval_mapping_for_row(expr, flows, idx) and col.iloc[list(flows.index).index(idx)] == "Unclassified":
                    col.iloc[list(flows.index).index(idx)] = name
            except Exception:
                continue
    return col

def build_kc_lookup(df):
    table={}
    if df is None or df.empty: return table
    for tech,tac in df[["technique_id","tactics"]].itertuples(False):
        for t in str(tac).split(";"):
            tt = t.strip()
            if tt in TACTIC_TO_KC:
                table[str(tech)] = TACTIC_TO_KC[tt]; break
    return table

def phases_from_ttps(s,kc):
    ph={kc.get(t) for t in s}; ph.discard(None)
    order = ["Recon","Delivery","Exploitation","Installation","C2","ActionsOnObjectives"]
    idx = {k:i for i,k in enumerate(order)}
    return ";".join(sorted(ph,key=lambda x:idx[x])) if ph else None

# ───────────────────── Models (8) ───────────────────────
def infer_target_from_filename(path: Path) -> str:
    name = path.name.lower()
    m = re.search(r"_rf_([a-z0-9._-]+)\.joblib$", name)
    if m: return m.group(1)
    if "profile" in name: return "profile"
    return path.stem.lower()

def collect_models(models_dir: Path, pattern: str):
    models={}
    for p in sorted(models_dir.glob(pattern)):
        if not p.is_file(): continue
        try:
            model = joblib.load(p)
        except Exception:
            continue
        target_raw = infer_target_from_filename(p)
        key = TARGET_CANON.get(target_raw.replace(".","_").replace("-","_"))
        if key is None:
            tok = re.sub(r"[^a-z]", "", target_raw)
            for k2, v2 in TARGET_CANON.items():
                if k2 in tok:
                    key = v2; break
        if key is None:
            continue
        models[key] = {"path": p, "model": model}
    return models

def predict_with_pipeline(pipe, X_df: pd.DataFrame):
    try:
        return pipe.predict(X_df)
    except Exception:
        steps = getattr(pipe, "named_steps", {})
        fe = steps.get("fe", None)
        prep= steps.get("pre") or steps.get("prep")
        est = steps.get("rf", None) or (pipe.steps[-1][1] if hasattr(pipe, "steps") else None)
        X = X_df.copy()
        if fe is not None:
            X = fe.transform(X)
        if hasattr(prep, "transformers_"):
            exp=[]
            for _,_,cols in prep.transformers_:
                if isinstance(cols, (list,tuple)): exp.extend(list(cols))
            seen=set(); exp=[c for c in exp if not (c in seen or seen.add(c))]
            for c in exp:
                if c not in X.columns: X[c]=np.nan
            X = X[exp]
            Xt = prep.transform(X)
        else:
            Xt = prep.transform(X) if prep is not None else X.values
        if est is None:
            raise RuntimeError("Pipeline sin estimador final.")
        return est.predict(Xt)

# ───────────────────── Explainability (SHAP) ─────────────
# One TreeExplainer per model, built once (lazily, on first use) and reused
# for every subsequent prediction — construction takes ~0.15s but computing
# shap_values() on an already-built explainer is what actually matters per
# message (~0.5s for the 300-tree, 273-feature Profile model, measured), well
# inside the cadence profiles are generated at (per-incident, not per-packet).
_SHAP_EXPLAINERS: Dict[str, Any] = {}
# _get_or_build_explainer is called from the per-message background thread
# (_publish_explainability, one thread per Kafka message) since explainability
# was moved off the critical path -- concurrent calls for the SAME model_key
# used to race on the check-then-act "cached is None" read: several threads
# would all see no cached entry at once (each shap.TreeExplainer(...) build
# takes long enough for that window to be real under Falco's burst traffic),
# each build its OWN ~25MB explainer, and each overwrite the dict in turn.
# The extra copies are real Python objects some other thread still holds a
# local reference to until its own request finishes, so they don't get
# GC'd promptly -- measured at +183MB of TreeExplainer internals for just 10
# messages, which is what was driving prep_pred's RSS from ~900MB to ~2.7GB+
# over a long session (and, since predict_with_pipeline shares the same
# process heap, degraded page/cache locality enough to slow down the FAST
# ml_preds loop too, from ~0.5s to ~2.7s within a single run). A lock makes
# the build-and-cache atomic so at most one explainer per model_key is ever
# constructed for the lifetime of the process.
_SHAP_EXPLAINERS_LOCK = threading.Lock()

def _get_or_build_explainer(model_key: str, rf_estimator):
    if shap is None:
        return None
    cached = _SHAP_EXPLAINERS.get(model_key)
    if cached is not None:
        return cached
    with _SHAP_EXPLAINERS_LOCK:
        # Re-check inside the lock: another thread may have finished
        # building this exact model_key's explainer while we were waiting.
        cached = _SHAP_EXPLAINERS.get(model_key)
        if cached is not None:
            return cached
        try:
            explainer = shap.TreeExplainer(rf_estimator)
        except Exception:
            return None
        _SHAP_EXPLAINERS[model_key] = explainer
        return explainer

def _transform_features_for_pipeline(pipe, X_df: pd.DataFrame):
    """Same fe/pre column-alignment logic predict_with_pipeline() falls back
    to on a raw pipe.predict() failure — factored out here so explainability
    can transform the SAME way without duplicating that alignment logic, and
    so both stay correct together if the pipeline's column handling changes."""
    steps = getattr(pipe, "named_steps", {})
    fe = steps.get("fe", None)
    prep = steps.get("pre") or steps.get("prep")
    X = X_df.copy()
    if fe is not None:
        X = fe.transform(X)
    if prep is None:
        return X.values
    if hasattr(prep, "transformers_"):
        exp = []
        for _, _, cols in prep.transformers_:
            if isinstance(cols, (list, tuple)):
                exp.extend(list(cols))
        seen = set()
        exp = [c for c in exp if not (c in seen or seen.add(c))]
        for c in exp:
            if c not in X.columns:
                X[c] = np.nan
        X = X[exp]
    return prep.transform(X)

def explain_profile_prediction(model_key: str, pipe, X_df: pd.DataFrame, predicted_class: str, top_n: int = 5) -> Optional[str]:
    """Returns the top_n features whose SHAP contribution pushed the
    prediction TOWARD predicted_class the most, as a compact pipe-separated
    string like "total_flows:+0.142|avg_flow_duration:+0.089|...". Returns
    None on any failure (missing shap, unsupported pipeline shape, class not
    found in the model's classes_) — explainability is best-effort and must
    never block a profile from being emitted.
    """
    if shap is None or not predicted_class:
        return None
    steps = getattr(pipe, "named_steps", {})
    rf_estimator = steps.get("rf")
    prep = steps.get("pre") or steps.get("prep")
    if rf_estimator is None or not hasattr(rf_estimator, "feature_importances_"):
        return None
    explainer = _get_or_build_explainer(model_key, rf_estimator)
    if explainer is None:
        return None
    try:
        classes = list(getattr(rf_estimator, "classes_", []))
        if predicted_class not in classes:
            return None
        class_idx = classes.index(predicted_class)
        Xt = _transform_features_for_pipeline(pipe, X_df)
        shap_values = explainer.shap_values(Xt)
        # shap.__version__ 0.44.1 (pinned in requirements.txt) returns, for a
        # multiclass RandomForestClassifier, a LIST of n_classes arrays each
        # shaped (n_samples, n_features) — NOT a single (n_samples,
        # n_features, n_classes) array. Newer shap releases (>=0.46 or so)
        # changed this to the single-array form. Handle both so this keeps
        # working if the pin above is ever bumped.
        if isinstance(shap_values, list):
            row_values = np.asarray(shap_values[class_idx])[0, :]
        else:
            arr = np.asarray(shap_values)
            row_values = arr[0, :, class_idx] if arr.ndim == 3 else arr[0, :]
        feature_names = list(prep.get_feature_names_out()) if prep is not None and hasattr(prep, "get_feature_names_out") else [f"f{i}" for i in range(len(row_values))]
        # Strip the ColumnTransformer's "num__"/"cat__" prefix for a name a
        # human reads directly (e.g. "avg_flow_duration", not "num__avg_flow_duration").
        clean_names = [n.split("__", 1)[1] if "__" in n else n for n in feature_names]
        pairs = sorted(zip(clean_names, row_values), key=lambda kv: -abs(kv[1]))[:top_n]
        return "|".join(f"{name}:{val:+.3f}" for name, val in pairs)
    except Exception:
        return None

# ───────────────────── HL assembly per row ──────────────
def coerce_raw_df_types(df: pd.DataFrame) -> pd.DataFrame:
    keep_str = {
        "id","campaign_id","threat_type","threat","attack","stage","ips_src","ips_dst",
        "ports_src","ports_dst","protocol_distribution","first_seen","last_activity",
    }
    out = df.copy()
    for c in out.columns:
        if c in keep_str:
            continue
        if out[c].dtype == object:
            out[c] = pd.to_numeric(out[c], errors="coerce")
    return out.fillna(0)

@dataclass
class PTStore:
    path: Path
    data: Dict[str, Dict[str, float]]

def load_pt(path: Path):
    try:
        if path.exists():
            return PTStore(path, json.loads(path.read_text()))
    except Exception:
        pass
    return PTStore(path, {})

_TOP_K = 5
_HALF_LIFE_DAYS = 30
def _decay_factor(delta_days: float) -> float:
    return 0.5 ** (delta_days / _HALF_LIFE_DAYS)

def update_preferred_targets(actor_id: str, dst_ip: str, bytes_sent: float, ts_str: str, store: PTStore) -> str:
    today = _dt.datetime.utcnow().date()
    try:
        ts = _dt.datetime.fromisoformat(str(ts_str)).date()
    except ValueError:
        ts = today
    w_time  = _decay_factor((today - ts).days)
    w_bytes = math.log1p(bytes_sent) / 20_000
    weight  = 1.0 + w_bytes
    db = store.data
    db.setdefault(actor_id, {})
    db[actor_id][dst_ip] = db[actor_id].get(dst_ip, 0.0) + weight * w_time
    top = sorted(db[actor_id].items(), key=lambda kv: kv[1], reverse=True)[:_TOP_K]
    return ";".join(ip for ip, _ in top)

# ---------- SQLi: 100% numérico (UMBRALES ENDURECIDOS Y AJUSTADOS) ----------
# --- Manual ---
SQLI_MANUAL_MAX_FLOWS          = float(os.getenv("SQLI_MANUAL_MAX_FLOWS", "200"))    # antes 100
SQLI_MANUAL_MAX_FLOW_RATE      = float(os.getenv("SQLI_MANUAL_MAX_FLOW_RATE", "20"))  # antes 10
SQLI_MANUAL_MAX_PKT_RATE       = float(os.getenv("SQLI_MANUAL_MAX_PKT_RATE", "5000")) # antes 500
SQLI_MANUAL_MAX_REP_FREQ       = float(os.getenv("SQLI_MANUAL_MAX_REP_FREQ", "1.00")) # permite repeticiones altas

# --- Semi (actividad sostenida pero no masiva) ---
SQLI_SEMI_MAX_FLOW_RATE        = float(os.getenv("SQLI_SEMI_MAX_FLOW_RATE", "300"))
SQLI_SEMI_MAX_PKT_RATE         = float(os.getenv("SQLI_SEMI_MAX_PKT_RATE", "50000"))
SQLI_SEMI_MAX_REP_FREQ         = float(os.getenv("SQLI_SEMI_MAX_REP_FREQ", "1.00"))

# --- Skills thresholds ---
SQLI_ADV_MIN_DST_PORTS         = float(os.getenv("SQLI_ADV_MIN_DST_PORTS", "25"))
SQLI_ADV_MIN_DST_IPS           = float(os.getenv("SQLI_ADV_MIN_DST_IPS", "8"))
SQLI_ADV_MIN_PORT_CHANGE_FREQ  = float(os.getenv("SQLI_ADV_MIN_PORT_CHANGE_FREQ", "0.55"))
SQLI_ADV_MIN_IP_CHANGE_FREQ    = float(os.getenv("SQLI_ADV_MIN_IP_CHANGE_FREQ", "0.55"))
SQLI_ADV_MIN_ENTROPY_PORTS     = float(os.getenv("SQLI_ADV_MIN_ENTROPY_PORTS", "3.0"))

# --- Riesgo ---
SQLI_RISK_BYTES_HIGH_MB        = float(os.getenv("SQLI_RISK_BYTES_HIGH_MB", "20"))
SQLI_RISK_BYTES_VHIGH_MB       = float(os.getenv("SQLI_RISK_BYTES_VHIGH_MB", "200"))

# --- Micro-burst configurable ---
# Por defecto 0.0 (desactivado) — no convierte manuales en semi por ráfagas breves.
SQLI_MICRO_BURST_SEMI_THRESHOLD = float(os.getenv("SQLI_MICRO_BURST_SEMI_THRESHOLD", "0.0"))

def _is_attack_sqli(row: pd.Series | Dict[str, Any]) -> bool:
    try:
        v = (row.get("attack") if hasattr(row, "get") else row["attack"])
    except Exception:
        v = ""
    v = ("" if v is None else str(v)).strip().lower()
    return v in {"sql injection", "sqli", "sql_injection"}

def _compute_automation_level(feat: Dict[str, float]) -> int:
    flows     = clean_number(feat.get("total_flows", 0))
    f_rate    = clean_number(feat.get("flow_rate_per_sec", 0))
    p_rate    = clean_number(feat.get("packet_rate_per_sec", 0))
    rep_freq  = clean_number(feat.get("repeated_connections_frequency", 0))
    avg_time  = clean_number(feat.get("avg_time_between_connections", 9999.0))

    # Bloque manual — muy permisivo pero volúmenes bajos
    if (flows <= SQLI_MANUAL_MAX_FLOWS and
        f_rate <= SQLI_MANUAL_MAX_FLOW_RATE and
        p_rate <= SQLI_MANUAL_MAX_PKT_RATE and
        rep_freq <= SQLI_MANUAL_MAX_REP_FREQ):
        if SQLI_MICRO_BURST_SEMI_THRESHOLD > 0 and avg_time < SQLI_MICRO_BURST_SEMI_THRESHOLD:
            return 1  # opcionalmente semi si hay ráfaga ultracorta
        return 0

    # Bloque semi — más alto, pero no masivo
    if (f_rate <= SQLI_SEMI_MAX_FLOW_RATE and
        p_rate <= SQLI_SEMI_MAX_PKT_RATE and
        rep_freq <= SQLI_SEMI_MAX_REP_FREQ):
        return 1

    # Resto → claramente automático
    return 2

def _compute_skills(feat: Dict[str, float], automation_level: int) -> str:
    dst_ports   = clean_number(feat.get("unique_dst_ports_count", 0))
    dst_ips     = clean_number(feat.get("unique_dst_ips", 0))
    ent_ports   = clean_number(feat.get("entropy_dst_ports", 0))
    port_chg    = clean_number(feat.get("port_change_frequency", 0))
    ip_chg      = clean_number(feat.get("dst_ip_change_frequency", 0))

    # Advanced solo si realmente hay amplitud y automatización
    if (automation_level == 2 or
        dst_ports >= SQLI_ADV_MIN_DST_PORTS or
        dst_ips   >= SQLI_ADV_MIN_DST_IPS or
        ent_ports >= SQLI_ADV_MIN_ENTROPY_PORTS or
        port_chg  >= SQLI_ADV_MIN_PORT_CHANGE_FREQ or
        ip_chg    >= SQLI_ADV_MIN_IP_CHANGE_FREQ):
        return "Advanced"
    if automation_level == 1 or dst_ports >= 5 or dst_ips >= 3:
        return "Intermediate"
    return "Basic"

def _risk_bump_from_sqli(feat: Dict[str, float], automation_level: int) -> int:
    bump = 0
    if automation_level == 2: bump += 2
    elif automation_level == 1: bump += 1
    total_bytes_sent = clean_number(feat.get("total_bytes_sent", 0.0))
    mb = total_bytes_sent / (1024.0 * 1024.0)
    if mb > SQLI_RISK_BYTES_VHIGH_MB: bump += 2
    elif mb > SQLI_RISK_BYTES_HIGH_MB: bump += 1
    return bump

def _sqli_overrides(row: pd.Series | Dict[str,Any],
                    feat: Dict[str,float],
                    ml_preds: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(ml_preds)
    out["Profile"] = os.getenv("POST_FORCE_PROFILE", "hacker")
    auto_num = _compute_automation_level(feat)
    out["AutomationLevel"] = auto_num
    out["Skills"] = _compute_skills(feat, auto_num)
    out.setdefault("Motivation", os.getenv("POST_FORCE_MOTIVATION", "Unknown"))
    out.setdefault("Affiliation", os.getenv("POST_FORCE_AFFILIATION", "Unknown"))
    r0 = out.get("RiskLevel", None)
    try:
        r_int = int(round(float(r0))) if r0 is not None and str(r0) != "" else None
    except Exception:
        r_int = None
    bump = _risk_bump_from_sqli(feat, auto_num)
    if r_int is not None:
        out["RiskLevel"] = max(1, min(10, r_int + bump))
    return out

# ---------- build_hl_record ----------
def build_hl_record(df_raw_row: pd.DataFrame,
                    maps: Dict[str,pd.DataFrame],
                    pt_store: PTStore,
                    models: Dict[str,Any],
                    feat_row: Dict[str, float]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], pd.DataFrame]]:
    if df_raw_row.shape[0] != 1:
        return None

    _t0 = time.time()
    X_feat = pd.DataFrame([feat_row])
    ml_preds: Dict[str, Any] = {}
    for k in ML_KEYS:
        mdl = models.get(k)
        if mdl is None:
            continue
        try:
            yhat = predict_with_pipeline(mdl["model"], X_feat)
            ml_preds[k] = yhat[0] if isinstance(yhat, (list, np.ndarray, pd.Series)) else yhat
        except Exception:
            continue
    print(f"[TIMING] ml_preds loop: {time.time()-_t0:.3f}s", flush=True)

    _t1 = time.time()
    try:
        raw_row = df_raw_row.iloc[0]
    except Exception:
        raw_row = df_raw_row.loc[df_raw_row.index[0]]

    if _is_attack_sqli(raw_row):
        ml_preds = _sqli_overrides(raw_row, feat_row, ml_preds)
    print(f"[TIMING] sqli check: {time.time()-_t1:.3f}s", flush=True)

    # SHAP explainability (Profile + 8 other ML-predicted fields) used to be
    # computed HERE, synchronously — measured at ~4.1s total (9
    # TreeExplainer.shap_values() calls, ~0.5s each, consistently, not just on
    # first use) on top of the <1ms this function otherwise takes. That put
    # the full explainability cost directly in the detect->decide->act
    # critical path: SOARCA cannot apply a countermeasure until a profile
    # record reaches profiles_out, so every incident's response was gated on
    # 9 SHAP computations it doesn't need to decide anything (the
    # countermeasure only reads Profile/DetectionAttack/IPs/Target — plain
    # ml_preds values, already known here). Both fields are left None on the
    # fast record returned by this function; compute_explainability_fields()
    # below computes them separately, and the Kafka loop publishes them in a
    # follow-up record (same actor_id) from a background thread so the fast
    # record is never delayed by this.
    explainability = None
    explainability_all_fields = None

    flows = df_raw_row.copy()
    for col in ["attack","stage","threat","threat_type","protocol_distribution","ports_dst"]:
        if col in flows: flows[col] = flows[col].astype(str).fillna("")
    if "most_frequent_dst_port" in flows:
        flows["most_frequent_dst_port"] = pd.to_numeric(flows["most_frequent_dst_port"], errors="coerce").fillna(0)

    _t2 = time.time()
    ttp_map = maps["ttp"]; tool_map=maps["tool"]; ev_map=maps["ev"]
    ttp_sets, _supp = build_ttps_sets(flows, ttp_map)
    ev_sets  = build_evasion_sets(flows, ev_map)
    tools_col= build_tools_column(flows, tool_map)
    kc_lookup= build_kc_lookup(ttp_map)
    print(f"[TIMING] ttp/evasion/tools/kc build: {time.time()-_t2:.3f}s", flush=True)

    row = flows.iloc[0]
    tool = tools_col.iloc[0] if len(tools_col)>0 else "Unclassified"
    ips  = split_ips(row.get("ips_src",""))
    dst  = str(row.get("ips_dst", ""))

    # For ransomware flows the dst is the C2/CDN server (public IP). The host
    # that actually needs isolation is the compromised lab machine (src).
    # If dst is public and we have an internal src IP, use that as target.
    _lab_ip_re = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")
    _attack_label = str(df_raw_row.iloc[0].get("attack", "") if hasattr(df_raw_row, "iloc") else "").lower()
    if "ransomware" in _attack_label and not _lab_ip_re.match(dst):
        _internal_srcs = [ip for ip in ips if _lab_ip_re.match(ip)]
        if _internal_srcs:
            dst = _internal_srcs[0]

    tset, evset = ttp_sets[flows.index[0]], ev_sets[flows.index[0]]
    phase = phases_from_ttps(tset, kc_lookup)

    bytes_sent = float(df_raw_row.iloc[0].get("total_bytes_sent", 0.0) or 0.0)
    _campaign = str(df_raw_row.iloc[0].get("campaign_id", "") or "").strip()
    if _campaign:
        # All phases of the same campaign (network + host) merge into ONE actor node.
        actor_id = f"campaign_{_campaign}_{dst}"
    else:
        actor_id = f"profile_{df_raw_row.iloc[0].get('id')}"
    _t3 = time.time()
    pref_targets_str = update_preferred_targets(actor_id, dst, bytes_sent, str(df_raw_row.iloc[0].get("first_seen","")), pt_store)
    print(f"[TIMING] update_preferred_targets: {time.time()-_t3:.3f}s", flush=True)

    _t4 = time.time()
    country_list = countries_from_ips(ips)
    print(f"[TIMING] countries_from_ips: {time.time()-_t4:.3f}s", flush=True)
    print(f"[TIMING] TOTAL build_hl_record: {time.time()-_t0:.3f}s", flush=True)

    rec = {
        "Id": actor_id,
        "CampaignId": _campaign,
        "IPs": ";".join(ips),
        "Target": dst,
        "PreferredTarget": pref_targets_str or dst,
        "FirstSeen": df_raw_row.iloc[0].get("first_seen"),
        "LastActivity": df_raw_row.iloc[0].get("last_activity"),
        "Country": ";".join(country_list) or None,
        "Evasion": ";".join(sorted(evset)) if evset else None,
        "TTPs": ";".join(sorted(tset)) if tset else None,
        "KillChainPhase": phase,
        "RiskLevel": ml_preds.get("RiskLevel"),
        "Tools": tool,
        "Skills": ml_preds.get("Skills"),
        "Profile": ml_preds.get("Profile"),
        "DetectionAlert": str(df_raw_row.iloc[0].get("threat", "") or "").strip(),
        "DetectionType": str(df_raw_row.iloc[0].get("threat_type", "") or "").strip(),
        "DetectionAttack": str(df_raw_row.iloc[0].get("attack", "") or "").strip(),
        "DetectionStage": str(df_raw_row.iloc[0].get("stage", "") or "").strip(),
        "DetectionTs": df_raw_row.iloc[0].get("first_seen"),
        "Motivation": ml_preds.get("Motivation"),
        "Knowledge": ml_preds.get("Knowledge"),
        "Attitude": ml_preds.get("Attitude"),
        "Affiliation": ml_preds.get("Affiliation"),
        "ThreatGroup": None,
        "Campaigns": None,
        "Comments": (
            f"tapcd_detection_alert={str(df_raw_row.iloc[0].get('threat', '') or '').strip()};"
            f" type={str(df_raw_row.iloc[0].get('threat_type', '') or '').strip()};"
            f" attack={str(df_raw_row.iloc[0].get('attack', '') or '').strip()};"
            f" stage={str(df_raw_row.iloc[0].get('stage', '') or '').strip()}"
        ),
        "AutomationLevel": ml_preds.get("AutomationLevel"),
        "Explainability": explainability,
        "ExplainabilityAllFields": explainability_all_fields,
    }
    fast_rec = {k: rec.get(k, None) for k in PROFILE_COLUMNS}
    # ml_preds/X_feat are returned alongside the fast record purely so a
    # caller can compute SHAP explainability afterwards (in a background
    # thread, off the critical path) without needing to re-run the ML models
    # — see compute_explainability_fields below.
    return fast_rec, ml_preds, X_feat


def compute_explainability_fields(models: Dict[str, Any], ml_preds: Dict[str, Any], X_feat: pd.DataFrame) -> Tuple[Optional[str], Optional[str]]:
    """
    The ~4.1s SHAP cost this repo used to pay synchronously inside
    build_hl_record, factored out so it can run in a background thread AFTER
    the fast record (Profile/DetectionAttack/IPs/Target — everything SOARCA
    actually needs to decide and act) is already published. Pure function of
    the same models/ml_preds/X_feat build_hl_record already computed; no
    Kafka/network I/O here, so it's safe to call from any thread.
    """
    explainability = None
    _profile_model = models.get("Profile")
    _final_profile = ml_preds.get("Profile")
    if _profile_model is not None and _final_profile:
        explainability = explain_profile_prediction("Profile", _profile_model["model"], X_feat, str(_final_profile))

    _explain_all_parts: List[str] = []
    for _field_key in ML_KEYS:
        if _field_key == "Profile":
            continue  # already covered by `explainability` above
        _field_model = models.get(_field_key)
        _field_pred = ml_preds.get(_field_key)
        if _field_model is None or not _field_pred:
            continue
        _field_expl = explain_profile_prediction(_field_key, _field_model["model"], X_feat, str(_field_pred))
        if _field_expl:
            _explain_all_parts.append(f"{_field_key}={_field_expl}")
    explainability_all_fields = ";".join(_explain_all_parts) if _explain_all_parts else None
    return explainability, explainability_all_fields


# ─────────────── SHAP worker pool (separate processes) ───────────────
# Running compute_explainability_fields() in a plain threading.Thread (the
# first fix for this) got the fast record published quickly, but SHAP's
# numpy/sklearn work still holds Python's GIL for most of its ~4s -- with
# Falco's burst traffic spawning several of these threads close together,
# each one starves the MAIN thread's own ml_preds loop (the 8 fast
# RandomForest predictions every incoming message needs) of the GIL, measured
# driving that loop from ~0.5s up to 5s+ within a single run even though no
# single SHAP computation got any slower. A thread cannot fix this — only a
# separate process, with its own GIL, actually runs SHAP truly in parallel
# with the main loop. Workers load their own copy of the models directly
# from disk (via _shap_worker_init, run once per process) instead of having
# the main process pickle the whole MODELS dict through IPC on every call.
_SHAP_WORKER_MODELS: Dict[str, Any] = {}
_SHAP_WORKER_POOL: "ProcessPoolExecutor | None" = None


def _shap_worker_init(models_dir: str, glob_pattern: str) -> None:
    global _SHAP_WORKER_MODELS
    _SHAP_WORKER_MODELS = collect_models(Path(models_dir), glob_pattern)


def _shap_worker_compute(ml_preds: Dict[str, Any], X_feat: pd.DataFrame) -> Tuple[Optional[str], Optional[str]]:
    return compute_explainability_fields(_SHAP_WORKER_MODELS, ml_preds, X_feat)


def get_shap_worker_pool(models_dir: str, glob_pattern: str) -> ProcessPoolExecutor:
    global _SHAP_WORKER_POOL
    if _SHAP_WORKER_POOL is None:
        # A small fixed pool (not one process per message): each worker's
        # models are loaded once at process start and reused for that
        # worker's whole lifetime, and 2 workers are enough to keep the
        # explainability backlog from piling up behind the main loop without
        # spending real CPU/memory on processes that would mostly sit idle
        # between Falco bursts.
        _SHAP_WORKER_POOL = ProcessPoolExecutor(
            max_workers=2,
            initializer=_shap_worker_init,
            initargs=(models_dir, glob_pattern),
        )
    return _SHAP_WORKER_POOL

# ───────────────────── CSV emitter ──────────────────────
def rows_to_csv(rows: List[Dict[str, Any]], columns: List[str]) -> str:
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=columns, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in columns})
    return out.getvalue()

# ───────────────────── CLI / Main ───────────────────────
def parse_args():
    ap = argparse.ArgumentParser("flow_conditional_agg → PREPROC+8ML+HL → profiles_out")
    ap.add_argument("--bootstrap", required=True, help="Bootstrap servers, e.g., localhost:9092")
    ap.add_argument("--topic-in", default="flow_conditional_agg", help="Kafka input topic")
    ap.add_argument("--topic-out", default="profiles_out", help="Kafka output topic (CSV HL)")
    ap.add_argument("--group-id", default="profiles_stream", help="Consumer group.id")
    ap.add_argument("--from-beginning", action="store_true", help="Read from earliest")
    ap.add_argument("--linger-ms", type=int, default=0)
    ap.add_argument("--models-dir", required=True, help="Folder with *.joblib (8 models)")
    ap.add_argument("--glob", default="*.joblib", help="Glob to load models")
    ap.add_argument("--mapping", default="high/network_observable_attack_mapping_v2.csv", help="CSV mapping TTPs")
    ap.add_argument("--toolmap", default="high/network_tool_mapping_v1.csv", help="CSV mapping Tools")
    ap.add_argument("--evasion", default="high/network_evasion_mapping_v1.csv", help="CSV mapping Evasion")
    ap.add_argument("--preferred-targets", default="high/preferred_targets_db.json", help="Persistent JSON path")
    ap.add_argument("--geoip", default="", help="GeoLite2-Country.mmdb path (optional)")
    # Aceptar y **ignorar** estos flags para compatibilidad con tu despliegue:
    ap.add_argument("--groups", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--campaigns", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--enterprise-attack", default=None, help=argparse.SUPPRESS)
    return ap.parse_args()

def make_consumer(bootstrap, topic, group_id, from_beginning):
    def factory():
        return KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap,
            group_id=group_id,
            auto_offset_reset="earliest" if from_beginning else "latest",
            enable_auto_commit=True,
            value_deserializer=lambda v: v,
            key_deserializer=lambda v: v,
        )

    def validator(consumer):
        if not consumer.bootstrap_connected():
            raise RuntimeError("Kafka consumer sin brokers disponibles")

    return wait_for_service("Kafka consumer", factory, validator)

def make_producer(bootstrap, linger_ms=0):
    def factory():
        return KafkaProducer(
            bootstrap_servers=bootstrap,
            value_serializer=lambda v: v.encode("utf-8"),
            linger_ms=linger_ms,
            compression_type=None,
        )

    def validator(producer):
        if not producer.bootstrap_connected():
            raise RuntimeError("Kafka producer sin brokers disponibles")

    return wait_for_service("Kafka producer", factory, validator)

def main():
    _setup_log_level()
    args = parse_args()

    LOG.info("▶️ Iniciando")

    try:
        if args.geoip:
            setup_geoip(args.geoip)
    except Exception:
        pass

    maps = {
        "ttp": _load_csv_df(args.mapping),
        "tool": _load_csv_df(args.toolmap),
        "ev": _load_csv_df(args.evasion),
    }
    pt_store = load_pt(Path(args.preferred_targets))

    mdir = Path(args.models_dir).expanduser().resolve()
    if not mdir.exists() or not mdir.is_dir():
        LOG.info("⚠️ Ignorado"); sys.exit(2)
    MODELS = collect_models(mdir, args.glob)
    if not MODELS:
        LOG.info("⚠️ Ignorado"); sys.exit(2)

    # Warm the SHAP worker pool now (at startup, not on the first message) so
    # the first real incident doesn't pay process-spawn + model-load latency
    # on top of everything else.
    shap_pool = get_shap_worker_pool(str(mdir), args.glob)

    try:
        consumer = make_consumer(args.bootstrap, args.topic_in, args.group_id, args.from_beginning)
        producer = make_producer(args.bootstrap, linger_ms=args.linger_ms)
    except Exception:
        LOG.info("⚠️ Ignorado"); raise

    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))

    # Record startup time (ms). Messages produced before this moment are stale
    # backlog from a previous experiment run (this service consumes with
    # --from-beginning, so on restart it would otherwise replay historical flows
    # — e.g. a flow whose first_seen is from a previous day — and emit a stale
    # actor profile). A 10-min grace absorbs minor clock skew. Configurable via
    # PREP_PRED_STARTUP_GRACE_SECS (set 0 to disable the guard).
    _startup_cutoff_ms = int(time.time() * 1000)
    _startup_grace_ms = int(float(os.getenv("PREP_PRED_STARTUP_GRACE_SECS", "600")) * 1000)
    _msg_cutoff_ms = _startup_cutoff_ms - _startup_grace_ms

    for msg in consumer:
        if stop["flag"]:
            break
        try:
            # Skip Kafka messages produced before this process started (stale
            # backlog from a prior run). msg.timestamp is epoch-ms.
            _msg_ts = getattr(msg, "timestamp", None)
            if _startup_grace_ms >= 0 and _msg_ts and _msg_ts < _msg_cutoff_ms:
                LOG.info("⏭️ Ignorado (mensaje anterior al arranque)")
                continue

            LOG.info("📥 Recibido")

            raw_txt = robust_decode(msg.value)
            print(f"✉️ {raw_txt}", flush=True)  # payload crudo del tópico

            LOG.info("🛠️ Preprocesando")
            row_dict = parse_csv_message(raw_txt)
            if not row_dict:
                LOG.info("⚠️ Ignorado"); continue

            feats = featurize(row_dict)
            LOG.info("🧮 Features listas")

            df_raw = pd.DataFrame([row_dict]); df_raw = coerce_raw_df_types(df_raw)
            built = build_hl_record(df_raw, maps, pt_store, MODELS, feats)
            if not built:
                LOG.info("⚠️ Ignorado"); continue
            rec, _ml_preds, _X_feat = built
            # Structured, single-line dump of the exact inputs the ML models
            # saw (raw_row + the 90-feature vector) and what they predicted
            # for the 8 ML_KEYS attributes, so a rule-based re-run of
            # High-Level.py's calc_automation_level/infer_skill/
            # calc_risk_level_num/score_profiles/infer_knowledge/
            # infer_attitude/infer_motivation/infer_affiliation against the
            # SAME inputs can be diffed against these real ML predictions
            # per-run, without needing DB credentials or reconstructing
            # inputs after the fact. Container has no host mount, so stdout
            # (captured via `docker logs`) is the only durable sink.
            try:
                _ml_vs_hl_dump = {
                    "actor_id": rec.get("Id"),
                    "campaign_id": rec.get("CampaignId"),
                    "raw_row": {k: (None if pd.isna(v) else v) for k, v in row_dict.items()},
                    "X_feat": {k: (None if (isinstance(v, float) and pd.isna(v)) else v) for k, v in feats.items()},
                    "ml_preds": {k: _ml_preds.get(k) for k in ML_KEYS},
                }
                LOG.info("🔬 ML_VS_HL_DUMP %s", json.dumps(_ml_vs_hl_dump, default=str, ensure_ascii=False))
            except Exception as _dump_exc:
                LOG.info("⚠️ ML_VS_HL_DUMP failed: %s", _dump_exc)

            # Drop ransomware profiles whose Target is a public IP — these are
            # Isolation Forest false positives on outbound traffic (e.g. apk/apt
            # downloads) where no lab-internal source IP is present.  Ransomware
            # activity is always internal: compromised host (172.18.x / 10.x /
            # 192.168.x) talks to other internal hosts, not to the internet.
            _is_ransomware_rec = "ransomware" in str(rec.get("DetectionAttack", "")).lower()
            _src_ips_rec = [s.strip() for s in str(rec.get("IPs", "")).split(";") if s.strip()]
            _lab_re = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")
            if _is_ransomware_rec and not any(_lab_re.match(ip) for ip in _src_ips_rec):
                LOG.info(
                    "⏭️ Perfil ransomware descartado (IPs fuente públicas: %s) — falso positivo de tráfico saliente.",
                    _src_ips_rec,
                )
                continue

            out_csv = rows_to_csv([rec], PROFILE_COLUMNS)
            try:
                fut = producer.send(args.topic_out, out_csv)
                try:
                    fut.get(timeout=10)
                except Exception:
                    pass
                producer.flush(5)
                # explainability AND ttps appended here too (not just to the
                # CSV sent to Kafka) because the GUI's log-line parser
                # (_native_actor_profile_from_line in app.py) picks up
                # WHICHEVER of this short "Enviado" summary or
                # misp_to_soarca's own richer "TAPCD_PROFILE_READY" line it
                # happens to capture first as "profile evidence" — depending
                # on that ordering being fixed elsewhere would be fragile, so
                # every log line that carries the Profile field also carries
                # its explanation and its MITRE ATT&CK techniques (both are
                # consumed by app.py's _kv() parser, semicolon-joined same as
                # the CSV's own TTPs column).
                LOG.info(
                    "📤 Enviado actor_id=%s profile=%s attack=%s explainability=%s ttps=%s",
                    rec.get("Id", "?"),
                    rec.get("Profile", "?"),
                    rec.get("DetectionAttack", "?"),
                    rec.get("Explainability") or "-",
                    rec.get("TTPs") or "-",
                )
            except Exception:
                LOG.info("⚠️ Ignorado"); continue

            # SHAP explainability (~4.1s for 9 models) runs in a SEPARATE
            # PROCESS from the pool above — a thread was tried first, but
            # SHAP's numpy/sklearn work holds the GIL long enough to starve
            # the main loop's own fast ml_preds predictions under Falco's
            # burst traffic (measured: 0.5s -> 5s+ within one run). A
            # different process has its own GIL, so it genuinely doesn't
            # block the main loop. This thread here is now just a thin
            # waiter: it blocks on the process's future (which does NOT hold
            # this process's GIL while waiting on IPC) and publishes the
            # result — SOARCA/misp_to_soarca.py already dedups on
            # (victim_ip, actor_id) and only ever fires ONE countermeasure per
            # campaign (see its NETWORK_CM_DEDUP_SECONDS/ISOLATION_DEDUP_SECONDS
            # guards), so this follow-up record — same actor_id, now carrying
            # Explainability/ExplainabilityAllFields — only enriches the
            # already-acted-on profile for the GUI/report instead of
            # triggering a second action.
            def _publish_explainability(rec=rec, ml_preds=_ml_preds, X_feat=_X_feat):
                try:
                    future = shap_pool.submit(_shap_worker_compute, ml_preds, X_feat)
                    expl, expl_all = future.result(timeout=30)
                    if not expl and not expl_all:
                        return
                    enriched = dict(rec)
                    enriched["Explainability"] = expl
                    enriched["ExplainabilityAllFields"] = expl_all
                    out_csv2 = rows_to_csv([enriched], PROFILE_COLUMNS)
                    fut2 = producer.send(args.topic_out, out_csv2)
                    try:
                        fut2.get(timeout=10)
                    except Exception:
                        pass
                    producer.flush(5)
                    # Both fields go into the log line now (ExplainabilityAllFields
                    # was previously only published to Kafka, never logged) — the
                    # GUI's log-tail parser (app.py's _native_actor_profile_from_line)
                    # reads app.py-visible container logs, not the Kafka topic
                    # directly, so a field missing from THIS line was invisible to
                    # it regardless of being on the CSV record sent to Kafka.
                    LOG.info(
                        "📤 Enriquecido (explainability) actor_id=%s profile=%s explainability=%s explainability_fields=%s",
                        enriched.get("Id", "?"), enriched.get("Profile", "?"), expl or "-", expl_all or "-",
                    )
                except Exception as exc:
                    LOG.debug("Explainability enrichment failed (non-fatal): %s", exc)

            threading.Thread(target=_publish_explainability, daemon=True).start()

        except Exception:
            LOG.info("⚠️ Ignorado"); continue

    try:
        consumer.close()
    except Exception:
        pass
    try:
        producer.flush(); producer.close()
    except Exception:
        pass

    LOG.info("⏹️ Finalizado")

if __name__ == "__main__":
    main()
