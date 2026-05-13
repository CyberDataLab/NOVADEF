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
import argparse, csv, io, json, logging, math, os, re, sys, signal, time, datetime as _dt
from collections import defaultdict
from dataclasses import dataclass
from hashlib import md5
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional

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
    "id","threat_type","threat","attack","stage",
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
    "Id","IPs","Target","PreferredTarget","FirstSeen","LastActivity",
    "Country","AutomationLevel","Evasion","TTPs","KillChainPhase",
    "RiskLevel","Tools","Skills",
    "Profile",
    "Motivation","Knowledge","Attitude","Affiliation",
    "ThreatGroup","Campaigns","Comments",
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

# ───────────────────── HL assembly per row ──────────────
def coerce_raw_df_types(df: pd.DataFrame) -> pd.DataFrame:
    keep_str = {
        "id","threat_type","threat","attack","stage","ips_src","ips_dst",
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
                    feat_row: Dict[str, float]) -> Optional[Dict[str, Any]]:
    if df_raw_row.shape[0] != 1:
        return None

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

    try:
        raw_row = df_raw_row.iloc[0]
    except Exception:
        raw_row = df_raw_row.loc[df_raw_row.index[0]]

    if _is_attack_sqli(raw_row):
        ml_preds = _sqli_overrides(raw_row, feat_row, ml_preds)

    flows = df_raw_row.copy()
    for col in ["attack","stage","threat","threat_type","protocol_distribution","ports_dst"]:
        if col in flows: flows[col] = flows[col].astype(str).fillna("")
    if "most_frequent_dst_port" in flows:
        flows["most_frequent_dst_port"] = pd.to_numeric(flows["most_frequent_dst_port"], errors="coerce").fillna(0)

    ttp_map = maps["ttp"]; tool_map=maps["tool"]; ev_map=maps["ev"]
    ttp_sets, _supp = build_ttps_sets(flows, ttp_map)
    ev_sets  = build_evasion_sets(flows, ev_map)
    tools_col= build_tools_column(flows, tool_map)
    kc_lookup= build_kc_lookup(ttp_map)

    row = flows.iloc[0]
    tool = tools_col.iloc[0] if len(tools_col)>0 else "Unclassified"
    ips  = split_ips(row.get("ips_src",""))
    dst  = str(row.get("ips_dst", ""))

    tset, evset = ttp_sets[flows.index[0]], ev_sets[flows.index[0]]
    phase = phases_from_ttps(tset, kc_lookup)

    bytes_sent = float(df_raw_row.iloc[0].get("total_bytes_sent", 0.0) or 0.0)
    actor_id = f"profile_{df_raw_row.iloc[0].get('id')}"
    pref_targets_str = update_preferred_targets(actor_id, dst, bytes_sent, str(df_raw_row.iloc[0].get("first_seen","")), pt_store)

    country_list = countries_from_ips(ips)

    rec = {
        "Id": actor_id,
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
        "Motivation": ml_preds.get("Motivation"),
        "Knowledge": ml_preds.get("Knowledge"),
        "Attitude": ml_preds.get("Attitude"),
        "Affiliation": ml_preds.get("Affiliation"),
        "ThreatGroup": None,
        "Campaigns": None,
        "Comments": "",
        "AutomationLevel": ml_preds.get("AutomationLevel"),
    }
    return {k: rec.get(k, None) for k in PROFILE_COLUMNS}

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

    try:
        consumer = make_consumer(args.bootstrap, args.topic_in, args.group_id, args.from_beginning)
        producer = make_producer(args.bootstrap, linger_ms=args.linger_ms)
    except Exception:
        LOG.info("⚠️ Ignorado"); raise

    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))

    for msg in consumer:
        if stop["flag"]:
            break
        try:
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
            rec = build_hl_record(df_raw, maps, pt_store, MODELS, feats)
            if not rec:
                LOG.info("⚠️ Ignorado"); continue

            out_csv = rows_to_csv([rec], PROFILE_COLUMNS)
            try:
                fut = producer.send(args.topic_out, out_csv)
                try:
                    fut.get(timeout=10)
                except Exception:
                    pass
                producer.flush(5)
                LOG.info("📤 Enviado")
            except Exception:
                LOG.info("⚠️ Ignorado"); continue

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
