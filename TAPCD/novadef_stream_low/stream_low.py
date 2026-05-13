#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Kafka → JSON Alerts → Mongo → Aggregation (stream_low.py)

Objetivo:
- Consumir alertas JSON desde Kafka.
- Buscar flujos previos en Mongo vinculados a la alerta.
- Agregar y calcular TODAS las features en EXPECTED_COLS.
- Enviar una fila CSV (sin cabecera) por alerta al siguiente tópico Kafka.

Logs mínimos (no técnicos):
  📥 Alerta recibida (contador)
  🔁 Duplicada (contador)
  📤 Enviado al siguiente servicio

Desduplicación:
- Clave: (msg, src_ip/src_port, dst_ip/dst_port) con ventana configurable DEDUP_WINDOW_SEC.
- Si llegan varias iguales en ventana, se procesa una (la última).
"""

from __future__ import annotations

import argparse
import sys
import json
import time
import uuid
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from kafka import KafkaConsumer, KafkaProducer
from scipy.stats import entropy, iqr, kurtosis, skew
from pymongo import MongoClient

# ───────────── Config ─────────────

LIST_DELIM = ";"

EXPECTED_COLS = [
    "id",
    "threat_type",
    "threat",
    "attack",
    "stage",
    "ips_src",
    "ips_dst",
    "ports_src",
    "ports_dst",
    "total_flows",
    "total_packets_sent",
    "total_packets_received",
    "total_bytes_sent",
    "total_bytes_received",
    "avg_flow_duration",
    "std_flow_duration",
    "iqr_flow_duration",
    "skewness_flow_duration",
    "kurtosis_flow_duration",
    "variance_packet_size",
    "protocol_distribution",
    "udp_count",
    "tcp_count",
    "unique_dst_ports_count",
    "most_frequent_dst_port",
    "num_unique_src_ports",
    "most_frequent_src_port",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    "mean_iat",
    "std_iat",
    "max_iat",
    "min_iat",
    "first_seen",
    "last_activity",
    "active_time_ratio",
    "total_idle_time",
    "avg_idle_time_between_flows",
    "max_idle_time",
    "unique_dst_ips",
    "entropy_dst_ips",
    "repeated_connections_frequency",
    "time_diff",
    "avg_packet_size",
    "flow_rate_per_sec",
    "packet_rate_per_sec",
    "byte_rate_per_sec",
    "syn_ack_ratio",
    "rst_syn_ratio",
    "ratio_fwd_to_bwd_packets",
    "ratio_fwd_to_bwd_bytes",
    "active_to_idle_ratio",
    "udp_tcp_traffic_ratio",
    "unique_dst_ports_group",
    "unique_sessions_count",
    "avg_time_between_connections",
    "unique_dst_ips_group",
    "avg_time_between_flows",
    "total_flows_ip",
    "entropy_dst_ports",
    "flow_duration_to_packet_ratio",
    "byte_sent_received_ratio",
    "unique_ports_per_dst_ip_ratio",
    "rst_syn_flag_ratio",
    "fin_to_syn_ratio",
    "urg_to_ack_ratio",
    "psh_to_syn_ratio",
    "port_change_frequency",
    "dst_ip_change_frequency",
    "ddos_indicator",
    "port_scan_indicator",
    "brute_force_indicator",
    "data_exfiltration_indicator",
    "flow_frequency_per_minute",
    "extreme_flow_duration_count",
    "num_flows_in_high_traffic_periods",
    "active_std",
    "idle_std",
    "fwd_packet_size_range",
    "bwd_packet_size_range",
    "fwd_packet_size_to_mean_ratio",
    "bwd_packet_size_to_mean_ratio",
    "flow_variance_ratio",
    "high_variance_flow",
]

# ───────────── Logging ─────────────

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("stream_low")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(h)
    return logger

def wait_for_service(label: str, factory, validator=None, timeout_sec: Optional[float] = None,
                     retry_sec: Optional[float] = None):
    """Reintenta conexiones de arranque para evitar bucles de reinicio al levantar dependencias."""
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

# ───────────── Utils ─────────────

def sdiv(num, den):
    """Divide seguro: si den<=0 o NaN → NaN; preserva índice si Series."""
    num_is_series = isinstance(num, pd.Series)
    den_is_series = isinstance(den, pd.Series)
    num = pd.to_numeric(num, errors="coerce")
    den = pd.to_numeric(den, errors="coerce")
    res = np.where(den > 0, num / den, np.nan)
    if num_is_series or den_is_series:
        idx = num.index if num_is_series else den.index
        return pd.Series(res, index=idx)
    return res

def parse_alert_timestamp(ts_str: str) -> pd.Timestamp:
    """Input 'MM/DD-HH:MM:SS.micro' sin año → añade año actual."""
    ts = datetime.strptime(ts_str, "%m/%d-%H:%M:%S.%f")
    now = datetime.now()
    ts = ts.replace(year=now.year)
    return pd.Timestamp(ts)

def parse_attack_from_msg(msg: str) -> Tuple[str, str, str, str]:
    """Deriva attack y threat_type desde msg (heurística simple)."""
    m = (msg or "").lower()
    attack, threat_type = "Unknown", "Unknown"
    threat, stage = "Suspicious", "Alert"
    rules = [
        (("sql", "injection"), ("SQL Injection", "Application Attack")),
        (("dos",), ("DoS", "Network Flooding")),
        (("ddos",), ("DDoS", "Network Flooding")),
        (("xss",), ("XSS", "Application Attack")),
        (("brute", "force"), ("Brute Force", "Credential Attack")),
        (("scan", "port"), ("Port Scan", "Reconnaissance")),
        (("scan",), ("Scan", "Reconnaissance")),
        (("malware",), ("Malware", "Malicious Code")),
        (("ransom",), ("Ransomware", "Malicious Code")),
        (("443", "tráfico"), ("Suspicious TLS Traffic", "Anomalous Traffic")),
    ]
    for keys, (att, ttype) in rules:
        if all(k in m for k in keys):
            attack, threat_type = att, ttype
            break
    return attack, threat_type, threat, stage

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normaliza columnas (protocol, timestamp, pkt_len_mean fallback...)."""
    df = df.copy()
    df.columns = df.columns.str.strip()

    if "protocol" in df.columns:
        def _norm_proto(x):
            try:
                xi = int(float(str(x)))
                if xi == 6: return "TCP"
                if xi == 17: return "UDP"
            except Exception:
                pass
            s = str(x).upper()
            return s if s in {"TCP", "UDP"} else s
        df["protocol"] = df["protocol"].apply(_norm_proto)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "pkt_len_mean" not in df.columns and "pkt_size_avg" in df.columns:
        df["pkt_len_mean"] = pd.to_numeric(df["pkt_size_avg"], errors="coerce")

    return df

# ───────────── Aggregation ─────────────

def build_agg(df: pd.DataFrame) -> Dict[str, tuple]:
    def _unique_sessions_count(x, _df=df):
        if x.empty:
            return 0
        sub = _df.loc[x.index, ["dst_ip", "dst_port"]].astype(str)
        return pd.MultiIndex.from_frame(sub).nunique()

    def _avg_time_between(x):
        if x.empty: return 0.0
        t = pd.to_datetime(x, errors="coerce").sort_values()
        if len(t) <= 1: return 0.0
        d = np.diff(t.values.astype("datetime64[ns]")) / np.timedelta64(1, "s")
        return float(np.mean(d)) if len(d) else 0.0

    def _num_flows_high_traffic(x, threshold_s: float = 1.0):
        if x.empty: return 0
        t = pd.to_datetime(x, errors="coerce").sort_values()
        if len(t) <= 1: return 0
        d = np.diff(t.values.astype("datetime64[ns]")) / np.timedelta64(1, "s")
        return int((d < threshold_s).sum())

    def _entropy(series):
        if series is None or len(series) == 0: return 0.0
        vc = pd.Series(series).value_counts(normalize=True)
        return float(entropy(vc, base=2)) if len(vc) else 0.0

    d: Dict[str, tuple] = {
        "ips_src": ("src_ip", lambda x: LIST_DELIM.join(sorted(set(x.astype(str))))),
        "ips_dst": ("dst_ip", lambda x: LIST_DELIM.join(sorted(set(x.astype(str))))),
        "ports_src": ("src_port", lambda x: LIST_DELIM.join(sorted(set(x.astype(str))))),
        "ports_dst": ("dst_port", lambda x: LIST_DELIM.join(sorted(set(x.astype(str))))),

        "total_flows": ("src_ip", "count"),
        "total_packets_sent": ("fwd_pkts_s", "sum"),
        "total_packets_received": ("bwd_pkts_s", "sum"),
        "total_bytes_sent": ("totlen_fwd_pkts", "sum"),
        "total_bytes_received": ("totlen_bwd_pkts", "sum"),

        "avg_flow_duration": ("flow_duration", "mean"),
        "std_flow_duration": ("flow_duration", "std"),
        "iqr_flow_duration": ("flow_duration", iqr),
        "skewness_flow_duration": ("flow_duration", lambda x: skew(pd.to_numeric(x, errors="coerce"), bias=False, nan_policy="omit") if x.nunique() > 2 else 0.0),
        "kurtosis_flow_duration": ("flow_duration", lambda x: kurtosis(pd.to_numeric(x, errors="coerce"), bias=False, nan_policy="omit") if x.nunique() > 2 else 0.0),

        "variance_packet_size": ("pkt_len_mean", "var"),

        "protocol_distribution": ("protocol", lambda x: dict(pd.Series(x).astype(str).str.upper().value_counts()).__str__()),
        "udp_count": ("protocol", lambda x: int((pd.Series(x).astype(str).str.upper() == "UDP").sum())),
        "tcp_count": ("protocol", lambda x: int((pd.Series(x).astype(str).str.upper() == "TCP").sum())),

        "unique_dst_ports_count": ("dst_port", lambda x: pd.Series(x).nunique()),
        "most_frequent_dst_port": ("dst_port", lambda x: pd.Series(x).mode().iloc[0] if len(x) else np.nan),
        "num_unique_src_ports": ("src_port", lambda x: pd.Series(x).nunique()),
        "most_frequent_src_port": ("src_port", lambda x: pd.Series(x).mode().iloc[0] if len(x) else np.nan),
        "unique_dst_ips": ("dst_ip", lambda x: pd.Series(x).nunique()),
        "entropy_dst_ips": ("dst_ip", lambda x: _entropy(x)),
        "entropy_dst_ports": ("dst_port", lambda x: _entropy(x)),

        "syn_count": ("syn_flag_cnt", "sum"),
        "ack_count": ("ack_flag_cnt", "sum"),
        "fin_count": ("fin_flag_cnt", "sum"),
        "rst_count": ("rst_flag_cnt", "sum"),
        "psh_count": ("psh_flag_cnt", "sum"),
        "urg_count": ("urg_flag_cnt", "sum"),

        "mean_iat": ("flow_iat_mean", "mean"),
        "std_iat": ("flow_iat_std", "std"),
        "max_iat": ("flow_iat_max", "max"),
        "min_iat": ("flow_iat_min", "min"),

        "first_seen": ("timestamp", "min"),
        "last_activity": ("timestamp", "max"),
        "active_time_ratio": ("active_mean", "mean"),
        "total_idle_time": ("idle_mean", "sum"),
        "avg_idle_time_between_flows": ("idle_mean", "mean"),
        "max_idle_time": ("idle_mean", "max"),
        "active_std": ("active_std", "mean"),
        "idle_std": ("idle_std", "mean"),

        "avg_time_between_connections": ("timestamp", _avg_time_between := _avg_time_between),
        "avg_time_between_flows": ("timestamp", _avg_time_between),
        "num_flows_in_high_traffic_periods": ("timestamp", _num_flows_high_traffic := _num_flows_high_traffic),

        "unique_sessions_count": ("timestamp", _unique_sessions_count),
        "fwd_pkt_len_max_grp": ("fwd_pkt_len_max", "max"),
        "fwd_pkt_len_min_grp": ("fwd_pkt_len_min", "min"),
        "fwd_pkt_len_mean_grp": ("fwd_pkt_len_mean", "mean"),
        "bwd_pkt_len_max_grp": ("bwd_pkt_len_max", "max"),
        "bwd_pkt_len_min_grp": ("bwd_pkt_len_min", "min"),
        "bwd_pkt_len_mean_grp": ("bwd_pkt_len_mean", "mean"),
        "pkt_len_var_mean": ("pkt_len_var", "mean"),
        "repeated_connections_frequency": ("dst_ip", lambda x: float((pd.Series(x).value_counts() > 1).mean())),
    }
    return d

def after_agg(df: pd.DataFrame):
    """Métricas derivadas y ratios post-aggregación."""
    df["first_seen"] = pd.to_datetime(df["first_seen"], errors="coerce")
    df["last_activity"] = pd.to_datetime(df["last_activity"], errors="coerce")
    df["time_diff"] = (df["last_activity"] - df["first_seen"]).dt.total_seconds()

    avg_dur = pd.to_numeric(df.get("avg_flow_duration", np.nan), errors="coerce")
    df["time_diff"] = np.where((df["time_diff"].isna()) | (df["time_diff"] <= 0), avg_dur.fillna(1.0), df["time_diff"])

    for c in ["mean_iat","std_iat","max_iat","min_iat",
              "total_packets_sent","total_packets_received",
              "total_bytes_sent","total_bytes_received",
              "syn_count","ack_count","fin_count","rst_count","psh_count","urg_count",
              "unique_dst_ports_count","unique_dst_ips","total_flows"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    # recortes y no-negatividad
    if "min_iat" in df.columns: df["min_iat"] = df["min_iat"].clip(lower=0)
    if "max_iat" in df.columns: df["max_iat"] = df["max_iat"].clip(lower=0)

    total_pkts = df["total_packets_sent"] + df["total_packets_received"]
    total_bytes = df["total_bytes_sent"] + df["total_bytes_received"]

    df["avg_packet_size"] = sdiv(total_bytes, total_pkts)
    df["flow_rate_per_sec"] = sdiv(df["total_flows"], df["time_diff"])
    df["packet_rate_per_sec"] = sdiv(total_pkts, df["time_diff"])
    df["byte_rate_per_sec"] = sdiv(total_bytes, df["time_diff"])

    df["syn_ack_ratio"] = sdiv(df["syn_count"], df["ack_count"])
    df["rst_syn_ratio"] = sdiv(df["rst_count"], df["syn_count"])
    df["ratio_fwd_to_bwd_packets"] = sdiv(df["total_packets_sent"], df["total_packets_received"])
    df["ratio_fwd_to_bwd_bytes"] = sdiv(df["total_bytes_sent"], df["total_bytes_received"])
    df["active_to_idle_ratio"] = sdiv(df["active_time_ratio"], df["total_idle_time"])
    df["udp_tcp_traffic_ratio"] = sdiv(df["udp_count"], df["tcp_count"])

    if "ports_dst" in df.columns:
        df["unique_dst_ports_group"] = df["ports_dst"]
    if "ips_dst" in df.columns:
        df["unique_dst_ips_group"] = df["ips_dst"]

    df["total_flows_ip"] = df.get("total_flows", 0)
    df["flow_duration_to_packet_ratio"] = sdiv(df["avg_flow_duration"], total_pkts)
    df["byte_sent_received_ratio"] = sdiv(df["total_bytes_sent"], df["total_bytes_received"])
    df["unique_ports_per_dst_ip_ratio"] = sdiv(df["unique_dst_ports_count"], df["unique_dst_ips"])
    df["rst_syn_flag_ratio"] = sdiv(df["rst_count"], df["syn_count"])
    df["fin_to_syn_ratio"] = sdiv(df["fin_count"], df["syn_count"])
    df["urg_to_ack_ratio"] = sdiv(df["urg_count"], df["ack_count"])
    df["psh_to_syn_ratio"] = sdiv(df["psh_count"], df["syn_count"])

    df["port_change_frequency"] = sdiv(df["unique_dst_ports_count"], df["total_flows"])
    df["dst_ip_change_frequency"] = sdiv(df["unique_dst_ips"], df["total_flows"])

    df["fwd_packet_size_range"] = pd.to_numeric(df.get("fwd_pkt_len_max_grp", 0), errors="coerce") - pd.to_numeric(df.get("fwd_pkt_len_min_grp", 0), errors="coerce")
    df["bwd_packet_size_range"] = pd.to_numeric(df.get("bwd_pkt_len_max_grp", 0), errors="coerce") - pd.to_numeric(df.get("bwd_pkt_len_min_grp", 0), errors="coerce")
    df["fwd_packet_size_to_mean_ratio"] = sdiv(df["fwd_packet_size_range"], pd.to_numeric(df.get("fwd_pkt_len_mean_grp", 0), errors="coerce"))
    df["bwd_packet_size_to_mean_ratio"] = sdiv(df["bwd_packet_size_range"], pd.to_numeric(df.get("bwd_pkt_len_mean_grp", 0), errors="coerce"))

    df["flow_variance_ratio"] = sdiv(pd.to_numeric(df.get("pkt_len_var_mean", 0), errors="coerce"),
                                     pd.to_numeric(df.get("variance_packet_size", 0), errors="coerce")).fillna(0)

    mean_fd = pd.to_numeric(df.get("avg_flow_duration", 0), errors="coerce")
    std_fd  = pd.to_numeric(df.get("std_flow_duration", 0), errors="coerce").fillna(0)
    ratio = sdiv(std_fd, mean_fd.replace(0, np.nan)).fillna(0)
    df["extreme_flow_duration_count"] = ((ratio > 0.5).astype(int) * df["total_flows"] * 0.05).round(0).astype(int)

    # Indicadores
    flow_thr = df["flow_rate_per_sec"].quantile(0.95) if len(df) else 0.0
    byte_rate_thr = df["byte_rate_per_sec"].quantile(0.95) if len(df) else 0.0
    df["ddos_indicator"] = ((df["udp_count"] > 100) | (df["tcp_count"] > 100) | (df["flow_rate_per_sec"] > flow_thr)).astype(int)
    df["port_scan_indicator"] = (df["unique_dst_ports_count"] > df["unique_dst_ports_count"].quantile(0.9) if len(df) else 0).astype(int)
    df["brute_force_indicator"] = ((df["syn_ack_ratio"] > 1.5) & (df["syn_count"] > df["syn_count"].quantile(0.9) if len(df) else 0)).astype(int)
    df["data_exfiltration_indicator"] = (df["byte_rate_per_sec"] > byte_rate_thr).astype(int)
    df["flow_frequency_per_minute"] = sdiv(df["total_flows"], (df["time_diff"] / 60.0))

    if "flow_variance_ratio" not in df.columns:
        df["flow_variance_ratio"] = 0.0
    hv_thr = df["flow_variance_ratio"].quantile(0.95) if len(df) else 0.0
    df["high_variance_flow"] = (df["flow_variance_ratio"] > hv_thr).astype(int)

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

# ───────────── View / conditional grouping ─────────────

def compute_view(df: pd.DataFrame, group_cols: List[str]) -> pd.DataFrame:
    threat_s = df.get("threat", pd.Series([pd.NA] * len(df)))
    attack_s = df.get("attack", pd.Series([pd.NA] * len(df)))

    if ("threat" in df.columns) or ("attack" in df.columns):
        cond = pd.Series(True, index=df.index)
        if "threat" in df.columns:
            cond = cond & (threat_s != "Normal")
        if "attack" in df.columns:
            cond = cond | attack_s.isna()
        malign = df[cond].copy()
    else:
        malign = df.copy()

    agg = malign.groupby(group_cols, dropna=False).agg(**build_agg(malign)).reset_index()
    after_agg(agg)

    if len(agg) == 1:
        r = agg.loc[0]
        agg.loc[0, "unique_dst_ports_group"] = r.get("ports_dst")
        agg.loc[0, "unique_dst_ips_group"] = r.get("ips_dst")
        agg.loc[0, "unique_sessions_count"] = 1
        agg.loc[0, "total_flows_ip"] = r.get("total_flows", 1)
        agg.loc[0, "avg_time_between_connections"] = 0
        agg.loc[0, "avg_time_between_flows"] = 0
        agg.loc[0, "entropy_dst_ports"] = 0

    flow_thr = agg["flow_rate_per_sec"].quantile(0.95)
    byte_rate_thr = agg["byte_rate_per_sec"].quantile(0.95)
    agg["ddos_indicator"] = ((agg["udp_count"] > 100) | (agg["tcp_count"] > 100) | (agg["flow_rate_per_sec"] > flow_thr)).astype(int)
    agg["port_scan_indicator"] = (agg["unique_dst_ports_count"] > agg["unique_dst_ports_count"].quantile(0.9)).astype(int)
    agg["brute_force_indicator"] = ((agg["syn_ack_ratio"] > 1.5) & (agg["syn_count"] > agg["syn_count"].quantile(0.9))).astype(int)
    agg["data_exfiltration_indicator"] = (agg["byte_rate_per_sec"] > byte_rate_thr).astype(int)
    agg["flow_frequency_per_minute"] = sdiv(agg["total_flows"], (agg["time_diff"] / 60.0))

    if "flow_variance_ratio" not in agg.columns:
        agg["flow_variance_ratio"] = 0.0
    hv_thr = agg["flow_variance_ratio"].quantile(0.95) if len(agg) else 0.0
    agg["high_variance_flow"] = (agg["flow_variance_ratio"] > hv_thr).astype(int)

    for c in EXPECTED_COLS:
        if c not in agg.columns:
            agg[c] = np.nan

    agg = agg[EXPECTED_COLS]
    return agg

def conditional_grouping(df: pd.DataFrame) -> pd.DataFrame:
    for col in ["attack", "threat_type", "threat", "stage"]:
        if col not in df.columns:
            df[col] = pd.NA

    attack_s = df["attack"].astype("string").fillna("")
    src_s = df.get("src_ip", pd.Series([pd.NA] * len(df))).astype("string")
    dst_s = df.get("dst_ip", pd.Series([pd.NA] * len(df))).astype("string")
    cond_ip = np.where(attack_s.str.contains(r"DoS|DDoS|APT", case=False, regex=True), dst_s, src_s)

    df = df.copy()
    df["cond_ip"] = cond_ip

    v = compute_view(df, ["cond_ip", "attack", "threat_type", "threat", "stage"])

    ids = [str(uuid.uuid4()) for _ in range(len(v))]
    if "id" in v.columns:
        v["id"] = v["id"].fillna(pd.Series(ids, index=v.index))
    else:
        v.insert(0, "id", ids)

    v = v[EXPECTED_COLS]
    return v

# ───────────── Streaming ─────────────

@dataclass
class StreamConfig:
    bootstrap_servers: str
    in_topic: str
    out_topic: str
    group_id: str = "stream-json-alerts"
    linger_ms: int = 0
    file_prefix: Optional[str] = None
    # Mongo
    mongo_uri: str = ""
    mongo_db: str = ""
    mongo_coll: str = ""

class StreamProcessor:
    def __init__(self, cfg: StreamConfig):
        self.cfg = cfg
        self.log = setup_logger()

        def make_consumer():
            return KafkaConsumer(
                cfg.in_topic,
                bootstrap_servers=cfg.bootstrap_servers,
                group_id=cfg.group_id,
                enable_auto_commit=True,
                auto_offset_reset="latest",
                value_deserializer=lambda m: m.decode("utf-8", errors="ignore"),
                key_deserializer=lambda m: m.decode("utf-8", errors="ignore") if m else None,
                consumer_timeout_ms=1000,
            )

        def validate_consumer(consumer):
            if not consumer.bootstrap_connected():
                raise RuntimeError("Kafka consumer sin brokers disponibles")

        self.consumer = wait_for_service("Kafka consumer", make_consumer, validate_consumer)

        def make_producer():
            return KafkaProducer(
                bootstrap_servers=cfg.bootstrap_servers,
                value_serializer=lambda v: v.encode("utf-8"),
                linger_ms=max(cfg.linger_ms, 0),
                compression_type=None,
            )

        def validate_producer(producer):
            if not producer.bootstrap_connected():
                raise RuntimeError("Kafka producer sin brokers disponibles")

        self.producer = wait_for_service("Kafka producer", make_producer, validate_producer)

        # Mongo
        if not (self.cfg.mongo_uri and self.cfg.mongo_db and self.cfg.mongo_coll):
            raise SystemExit("❌ Falta configuración de Mongo (--mongo-uri, --mongo-db, --mongo-coll)")
        def make_mongo():
            return MongoClient(self.cfg.mongo_uri, serverSelectionTimeoutMS=5000)

        def validate_mongo(client):
            client.admin.command("ping")

        self.mongo = wait_for_service("MongoDB", make_mongo, validate_mongo)
        self.coll = self.mongo[self.cfg.mongo_db][self.cfg.mongo_coll]

        self._pending: Dict[Tuple, Dict[str, object]] = {}
        self._dedup_window_sec: float = float(os.getenv("DEDUP_WINDOW_SEC", "10"))

        self.stats = {
            "alerts_received": 0,
            "dedup_merged": 0,
        }

    @staticmethod
    def _split_ap(x: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        if not x:
            return None, None
        s = str(x)
        if ":" in s:
            ip, port = s.rsplit(":", 1)
            return ip or None, port or None
        return s, None

    def _extract_key_and_ts(self, obj: dict) -> Tuple[Tuple, pd.Timestamp]:
        msg = obj.get("msg", "")
        src_ip, src_port = self._split_ap(obj.get("src_ap"))
        dst_ip, dst_port = self._split_ap(obj.get("dst_ap"))

        src_ip = src_ip or obj.get("src_ip") or ""
        dst_ip = dst_ip or obj.get("dst_ip") or ""
        src_port = src_port or (str(obj.get("src_port")) if obj.get("src_port") is not None else "")
        dst_port = dst_port or (str(obj.get("dst_port")) if obj.get("dst_port") is not None else "")

        ts_alert = parse_alert_timestamp(obj.get("timestamp", "01/01-00:00:00.000000"))
        key = (str(msg), str(src_ip), str(src_port), str(dst_ip), str(dst_port))
        return key, ts_alert

    def _query_flows_for_alert(self, src_ip: str, ts_alert: pd.Timestamp) -> pd.DataFrame:
        """Consulta flujos previos al timestamp de la alerta para ese src_ip."""
        query = {"src_ip": src_ip, "timestamp": {"$lt": ts_alert.to_pydatetime()}}
        projection = {
            "_id": 0,
            "src_ip": 1, "dst_ip": 1, "src_port": 1, "dst_port": 1,
            "protocol": 1, "timestamp": 1, "flow_duration": 1,
            "fwd_pkts_s": 1, "bwd_pkts_s": 1, "totlen_fwd_pkts": 1, "totlen_bwd_pkts": 1,
            "fwd_pkt_len_max": 1, "fwd_pkt_len_min": 1, "fwd_pkt_len_mean": 1, "fwd_pkt_len_std": 1,
            "bwd_pkt_len_max": 1, "bwd_pkt_len_min": 1, "bwd_pkt_len_mean": 1, "bwd_pkt_len_std": 1,
            "pkt_len_mean": 1, "pkt_size_avg": 1, "pkt_len_var": 1,
            "syn_flag_cnt": 1, "ack_flag_cnt": 1, "fin_flag_cnt": 1, "rst_flag_cnt": 1, "psh_flag_cnt": 1, "urg_flag_cnt": 1,
            "flow_iat_mean": 1, "flow_iat_std": 1, "flow_iat_max": 1, "flow_iat_min": 1,
            "active_mean": 1, "active_std": 1, "idle_mean": 1, "idle_std": 1,
        }
        rows = list(self.coll.find(query, projection))
        if not rows:
            return pd.DataFrame(columns=list(projection.keys()))
        df = pd.DataFrame(rows)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df

    def _process_alert_obj(self, obj: dict):
        # Derivar ataque/etiquetas y timestamp + ip clave
        attack, threat_type, threat, stage = parse_attack_from_msg(obj.get("msg", ""))
        ts_alert = parse_alert_timestamp(obj.get("timestamp", ""))
        src_ip = (str(obj.get("src_ap", ""))).split(":")[0] if obj.get("src_ap") else str(obj.get("src_ip", ""))

        # Buscar flujos en Mongo
        df_flows = self._query_flows_for_alert(src_ip, ts_alert)

        # Si no hay flujos, meter una fila neutra para no romper el pipeline
        if df_flows.empty:
            df_flows = pd.DataFrame([{
                "src_ip": src_ip, "dst_ip": pd.NA, "src_port": pd.NA, "dst_port": pd.NA,
                "protocol": pd.NA, "timestamp": ts_alert - pd.Timedelta(seconds=1),
                "flow_duration": 0, "fwd_pkts_s": 0, "bwd_pkts_s": 0,
                "totlen_fwd_pkts": 0, "totlen_bwd_pkts": 0,
                "syn_flag_cnt": 0, "ack_flag_cnt": 0, "fin_flag_cnt": 0, "rst_flag_cnt": 0,
                "psh_flag_cnt": 0, "urg_flag_cnt": 0,
                "flow_iat_mean": 0, "flow_iat_std": 0, "flow_iat_max": 0, "flow_iat_min": 0,
                "active_mean": 0, "active_std": 0, "idle_mean": 0, "idle_std": 0,
                "pkt_len_mean": 0, "pkt_len_var": 0,
                "fwd_pkt_len_max": 0, "fwd_pkt_len_min": 0, "fwd_pkt_len_mean": 0,
                "bwd_pkt_len_max": 0, "bwd_pkt_len_min": 0, "bwd_pkt_len_mean": 0,
            }])

        # Anotar etiquetas: attack / threat_type / threat / stage
        df_flows["attack"] = attack
        df_flows["threat_type"] = threat_type
        df_flows["threat"] = threat
        df_flows["stage"] = stage

        # Normalización previa
        df_flows = normalize_columns(df_flows)

        # Agrupar condicionalmente (por IP relevante y etiquetas) y derivar todas las features
        v = conditional_grouping(df_flows)

        # ID por si falta
        if "id" in v.columns:
            v["id"] = v["id"].fillna(pd.Series([str(uuid.uuid4()) for _ in range(len(v))], index=v.index))
        else:
            v.insert(0, "id", [str(uuid.uuid4()) for _ in range(len(v))])

        v = v[EXPECTED_COLS]

        # CSV SIN cabecera
        out_csv = v.to_csv(index=False, header=False)

        # Envío Kafka OUT
        future = self.producer.send(self.cfg.out_topic, value=out_csv)
        try:
            future.get(timeout=10)
        except Exception:
            pass
        self.producer.flush()
        print("📤 Enviado al siguiente servicio", flush=True)

    def _flush_due(self, force: bool = False):
        if not self._pending:
            return
        now = time.monotonic()
        to_process = []
        for key, rec in list(self._pending.items()):
            last_arrival = rec["last_arrival"]
            if force or (self._dedup_window_sec <= 0) or (now - last_arrival >= self._dedup_window_sec):
                to_process.append((key, rec))
        for key, rec in to_process:
            obj = rec["last_obj"]
            try:
                self._process_alert_obj(obj)
            finally:
                self._pending.pop(key, None)

    def run(self):
        try:
            while True:
                for msg in self.consumer:
                    raw = (msg.value or "").strip()
                    if not raw:
                        continue
                    self.stats["alerts_received"] += 1
                    print(f"📥 Alerta recibida (total: {self.stats['alerts_received']})", flush=True)

                    # Parse preliminar SOLO para dedupe
                    try:
                        obj = json.loads(raw)
                    except Exception:
                        continue

                    key, _ts = self._extract_key_and_ts(obj)

                    rec = self._pending.get(key)
                    now = time.monotonic()
                    if rec is None:
                        self._pending[key] = {
                            "last_obj": obj,
                            "last_arrival": now,
                            "first_arrival": now,
                        }
                    else:
                        rec["last_obj"] = obj
                        rec["last_arrival"] = now
                        self.stats["dedup_merged"] += 1
                        print(f"🔁 Duplicada (total: {self.stats['dedup_merged']})", flush=True)

                    self._flush_due(force=False)

                self._flush_due(force=False)

        finally:
            try:
                self._flush_due(force=True)
            except Exception:
                pass
            try:
                self.consumer.close()
            except Exception:
                pass
            try:
                self.producer.flush()
                self.producer.close()
            except Exception:
                pass
            try:
                self.mongo.close()
            except Exception:
                pass

# ───────────── CLI ─────────────

@dataclass
class CLIConfig(StreamConfig):
    pass

def parse_args() -> "StreamConfig":
    p = argparse.ArgumentParser(description="Kafka JSON alerts → Mongo → aggregation → Kafka CSV")
    p.add_argument("--bootstrap-servers", required=True)
    p.add_argument("--in-topic", required=True, help="Input topic with JSON alerts")
    p.add_argument("--out-topic", required=True, help="Output topic with aggregated CSV")
    p.add_argument("--group-id", default="stream-json-alerts")
    p.add_argument("--linger-ms", type=int, default=0)
    p.add_argument("--file-prefix")
    # Mongo
    p.add_argument("--mongo-uri", required=True, help="mongodb://user:pass@host:27017/?authSource=admin")
    p.add_argument("--mongo-db", required=True, help="Mongo database name")
    p.add_argument("--mongo-coll", required=True, help="Collection with flows")
    a = p.parse_args()

    return StreamConfig(
        bootstrap_servers=a.bootstrap_servers,
        in_topic=a.in_topic,
        out_topic=a.out_topic,
        group_id=a.group_id,
        linger_ms=a.linger_ms,
        file_prefix=a.file_prefix,
        mongo_uri=a.mongo_uri,
        mongo_db=a.mongo_db,
        mongo_coll=a.mongo_coll,
    )

if __name__ == "__main__":
    cfg = parse_args()
    StreamProcessor(cfg).run()
