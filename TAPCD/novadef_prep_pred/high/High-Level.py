#!/usr/bin/env python3

###  ----  ThreatGroup helpers  ----
from __future__ import annotations  
import time
import os
import csv
from collections import defaultdict
from collections import defaultdict
import csv, datetime, json
import functools
import datetime
import argparse, ipaddress, re, sys, json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, List, Set, Dict, Tuple
import pandas as pd, geoip2.database
from ipwhois import IPWhois
from functools import lru_cache
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, pipeline

_GROUP_DB: Dict[str, Dict] = {}
_TECH_INV: Dict[str, Set[str]] = defaultdict(set)
_CAMPAIGNS: List[Dict] = []

# ─── Configuration ───────────────────────────────────────────────────
AUTO_LVL_HIGH_SEC, AUTO_LVL_MED_SEC = 10, 60
ID_COL, SRC_COL, DST_COL = "id", "ips_src", "ips_dst"
FIRST_SEEN_COL, LAST_ACT_COL = "first_seen", "last_activity"

PROFILE_COLUMNS = [
    "Id","IPs","Target","PreferredTarget","FirstSeen","LastActivity",
    "Country","AutomationLevel","Evasion","TTPs","KillChainPhase",
    "RiskLevel","Confidence","Tools","Skills",
    "Profile","ProfileDist",
    "Motivation","Knowledge","Attitude","Affiliation",
    "ThreatGroup","Campaigns","Comments",
]

PROFILE_SET = [
    "activist","competitor","crime-syndicate","criminal","hacker",
    "insider-accidental","insider-disgruntled","nation-state",
    "sensationalist","spy","terrorist","unknown",
]

timings = defaultdict(list)

_SPLIT = re.compile(r"[;, \t]+")
GEOIP_DB = "/var/lib/GeoIP/GeoLite2-Country.mmdb"
try:
    _geo = geoip2.database.Reader(GEOIP_DB)
except FileNotFoundError:
    _geo = None
    print("⚠️  GeoIP faltante", file=sys.stderr)

# ─────────────────────────────────────────────────
def time_feature(fn):
    """Mide y registra el tiempo de ejecución de la función."""
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed = time.perf_counter() - start
        timings[fn.__name__].append(elapsed)
        return result
    return wrapper


def split_ips(v): return [] if pd.isna(v) else [s for s in _SPLIT.split(str(v).strip()) if s]


def ip_to_country(ip):
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private: return "privada"
        return _geo.country(ip).country.iso_code if _geo else "desconocido"
    except: return "desconocido"


def countries_from_ips(lst):
    seen, out = set(), []
    for ip in lst:
        c = ip_to_country(ip) or "desconocido"
        if c not in seen:
            seen.add(c); out.append(c)
    return out


def compute_preferred_targets(df):
    counts: Dict[str, Counter[str]] = defaultdict(Counter)
    for r in df.itertuples(False):
        for ip in split_ips(getattr(r, SRC_COL, "")):
            counts[ip][getattr(r, DST_COL)] += 1
    return {ip: ctr.most_common(1)[0][0] for ip, ctr in counts.items()}

@time_feature
def calc_automation_level(r):
    m = getattr(r, "mean_iat", None) or getattr(r, "avg_time_between_flows", None)
    try: m = float(m)
    except: return None
    return 2 if m < AUTO_LVL_HIGH_SEC else 1 if m < AUTO_LVL_MED_SEC else 0


@functools.lru_cache(maxsize=8_192)
def get_asn_description(ip: str) -> str:
    """
    Devuelve la descripción del ASN (Owner/Org) o '' si falla.
    """
    try:
        res = IPWhois(ip).lookup_rdap(asn_methods=["whois"])
        return (res.get("network", {}) or {}).get("name", "") \
               or res.get("asn_description", "") or ""
    except Exception:
        return ""
# ─── Mappings (TTP / Evasion / Tools) ────────────────────────────────


def build_ttps_sets(flows, mapdf):
    flows = flows.copy()
    if "ports_dst" in flows:
        flows["ports_dst"] = flows["ports_dst"].fillna("").astype(str)
    sets=[set() for _ in range(len(flows))]; sup=defaultdict(int)
    for tech, expr in mapdf[["technique_id","mapping_hint"]].itertuples(False):
        try: hit = flows.eval(expr, engine="python").fillna(False)
        except Exception as e: print(f"⚠️ TTP {tech}: {e}, {expr}", file=sys.stderr); continue
        if hit.any():
            sup[str(tech)] += 1
            for idx in flows.index[hit]: sets[idx].add(str(tech))
    return sets, sup

def _fix(expr: str) -> str:

    return re.sub(r'flows\["([^"]+)"\]\.str',r'flows["\1"].astype(str).str',expr)

def build_evasion_sets(flows, mapdf):
    flows = flows.copy()
    if "stage" in flows:
        flows["stage"] = flows["stage"].fillna("").astype(str)
    sets=[set() for _ in range(len(flows))]
    for tag, expr in mapdf[["evasion_tag","mapping_hint"]].itertuples(False):
        try: hit = flows.eval(expr, engine="python").fillna(False)
        except Exception as e: print(f"⚠️ Ev {tag}: {e}", file=sys.stderr); continue
        for idx in flows.index[hit]: sets[idx].add(str(tag))
    return sets

def build_tools_column(flows, mapdf):
    flows = flows.copy()
    if "ports_dst" in flows:
        flows["ports_dst"] = flows["ports_dst"].fillna("").astype(str)
    if "attack" in flows:
        flows["attack"] = flows["attack"].fillna("").astype(str)
    if "stage" in flows:
        flows["stage"] = flows["stage"].fillna("").astype(str)

    col = pd.Series("Unclassified", index=flows.index, dtype=object)
    for name, expr in mapdf[["tool_name","mapping_hint"]].itertuples(False):
        try: hit = flows.eval(expr, engine="python").fillna(False)
        except Exception as e: print(f"⚠️ Tool {name}: {e}", file=sys.stderr); continue
        col[hit & (col == "Unclassified")] = name
    return col

# ─── Confidence ────────────────────────────────────
def calc_confidence(row, ips, ttp, ev, tool, sup):
    score = 0
    pub = [ip for ip in ips if ip_to_country(ip) not in ("privada","desconocido")]
    score += 15 if pub and len({ip_to_country(i) for i in pub}) == 1 else 5 if pub else 0
    tf = getattr(row,"total_flows",0) or 0
    score += 15 if tf >= 100 else 5 if tf >= 20 else 0
    score += 5 * sum(1 for t in ttp if sup.get(t,1) >= 2)
    score = min(score, 50)
    if tool != "Unclassified" and (("T1046" in ttp and tool in ("Nmap","Masscan","Scanner")) or
                                   ("T1498" in ttp and tool.startswith("LOIC")) or
                                   (ev and tool == "CobaltStrike")): score += 10
    if ev: score += 10
    auto = calc_automation_level(row)
    score += 10 if auto == 2 else 5 if auto == 1 else 0
    try:
        mi = float(getattr(row,"mean_iat",float("nan")))
        si = float(getattr(row,"std_iat",float("nan")))
        if si < mi/2: score += 10
    except: pass
    if tool == "Unclassified" and "T1046" in ttp: score -= 10
    if "T1498" in ttp and getattr(row,"byte_rate_per_sec",1) < 100_000: score -= 10
    return max(0, min(score, 100))

# ─── Skills ────────────────────────────────
@time_feature
def infer_skill(auto, ttp, ev, tool, flows, row):
   


    thr_type = str(getattr(row, 'threat_type', '')or '').lower()
    thr      = str(getattr(row, 'threat', '')or '').lower()
    atk      = str(getattr(row, 'attack', '')or '').lower()
    stage    = str(getattr(row, 'stage', '') or '').lower()
    pps      = getattr(row, 'packet_rate_per_sec', 0)

    APTS       = {'apt41', 'apt'}
    RANSOM     = {'ransomware', 'locky ransomware', 'wannacry'}
    BOTNETS    = {'botnet', 'mirai'}
    WORMS      = {'worm', 'worm.netsky'}
    TROJANS    = {'trojan', 'zbot'}
    ADWARES    = {'adware', 'pup.adware'}
    MINERS     = {'bitcoinminer', 'cobalt', 'miuref', 'andromeda'}


    ATTACK_DOWNLOADS = {'malware download', 'backdoor'}
    ATTACK_EXPLOITS  = {'exploits', 'command injection', 'sql injection', 'xss', 'shellcode'}
    ATTACK_SCAN      = {'network scan', 'reconnaissance',
                        'account discovery', 'web vulnerability scan',
                        'fuzzers', 'generic', 'analysis'}
    ATTACK_BRUTES    = {'account bruteforce', 'directory bruteforce',
                        'brute force', 'password attack'}
    ATTACK_DDOS      = {'ddos', 'dodos'}  
    ATTACK_WEB       = {'web'}


    STAGE_FLOODS    = {'ack flood','http flood','icmp flood','pshack flood',
                       'rstfin flood','syn flood','tcp flood','udp flood'}
    STAGE_FRAGS     = {'ack fragmentation','icmp fragmentation'}
    STAGE_SCANS     = {'port scanning','recon os scan','recon ping sweep',
                       'recon port scan','vulnerability scanner','tcp scan',
                       'tcp ack','tcp connect scan','tcp fin','tcp syn',
                       'tcp syn 180','tcp urg','tcp xmas','tcp ymas','udp scan',
                       'mqtt malformed'}  # etc.
    STAGE_BRUTES    = {'host brute force','mqtt brute force',
                       'sparta ssh brute force','telnet brute force'}
    STAGE_MITM      = {'mitm','mitm arp spoofing'}
    STAGE_EXFIL     = {'data exfiltration'}
    STAGE_MOVE      = {'lateral movement','establish foothold'}
    STAGE_RECON     = {'reconnaissance','os fingerprinting'}


    def any_in(s, patterns):
        return any(p in s for p in patterns)

    is_apt       = any_in(thr_type, APTS) or any_in(thr, APTS)
    is_ransom    = any_in(thr, RANSOM)
    is_botnet    = any_in(thr, BOTNETS)
    is_worm      = any_in(thr, WORMS)
    is_trojan    = any_in(thr, TROJANS)
    is_adware    = any_in(thr, ADWARES)
    is_miner     = any_in(thr_type, MINERS)

    down_attack  = any_in(atk, ATTACK_DOWNLOADS)
    exp_attack   = any_in(atk, ATTACK_EXPLOITS)
    scan_attack  = any_in(atk, ATTACK_SCAN)
    brute_attack = any_in(atk, ATTACK_BRUTES)
    ddos_attack  = any_in(atk, ATTACK_DDOS)

    flood_stage  = any_in(stage, STAGE_FLOODS)
    frag_stage   = any_in(stage, STAGE_FRAGS)
    scan_stage   = any_in(stage, STAGE_SCANS)
    brute_stage  = any_in(stage, STAGE_BRUTES) or 'password attack' in stage
    mitm_stage   = any_in(stage, STAGE_MITM)
    exfil_stage  = any_in(stage, STAGE_EXFIL)
    move_stage   = any_in(stage, STAGE_MOVE)
    recon_stage  = any_in(stage, STAGE_RECON)


    ADV_EVASION = {"FastFlux","DGA","DomainFronting","ProtocolTunneling"}
    PRIV_ESC    = {"T1068","T1055","T1134"}
    C2_ADV      = {"T1090","T1105","T1041","T1568"}
    SCAN_BRUTE  = {"T1046","T1110"}
    DOS_TTPS    = {"T1498","T1499"}

    has_adv_ev = bool(ev and (ADV_EVASION & ev))
    has_priv   = bool(ttp & PRIV_ESC)
    has_c2     = bool(ttp & C2_ADV)
    has_sb     = bool(ttp & SCAN_BRUTE)
    has_dos    = bool(ttp & DOS_TTPS)


    if auto == 2 and (
        (has_adv_ev or has_priv or has_c2 or is_apt or is_ransom or is_botnet) and
        (flood_stage or exfil_stage or brute_stage or scan_stage or mitm_stage)
    ):
        return "Expert"


    if (auto == 2 or ev) and (
        has_c2 or has_priv or has_sb or has_dos or
        is_ransom or is_botnet or is_worm or is_trojan or is_adware or is_miner or
        down_attack or exp_attack or scan_attack or brute_attack or ddos_attack or
        flood_stage or exfil_stage or brute_stage or scan_stage or mitm_stage or move_stage
    ):
        return "Advanced"


    if (auto == 1 and (has_sb or has_dos)) or \
       tool in {"Scanner","BruteForcer","LOIC/HOIC"} or \
       move_stage or recon_stage or \
       ("scan" in atk and pps > 200):
        return "Intermediate"


    return "Basic"

# ─── RiskLevel ──────────────────────────────────────
ENV_WEIGHT = {"iot":1, "5g":2, "cloud":3, "ics":4}
@time_feature
def calc_risk_level_num(row, ttp, phase, skill, conf, ev, flows, byte_rate,
                        tool, threat, attack, stage, ctx):
    
    s = 0.0


    last = (phase or "").split(";")[-1].lower()
    if last in ("actionsonobjectives","impact"):
        s += 4
    elif last in ("exfiltration","c2"):
        s += 3
    elif last:
        s += 2


    crit  = {"T1048","T1498","T1499"}    # exfil, dos
    high  = {"T1090","T1105","T1568","T1068","T1041"}  # C2, priv-esc
    scanb = {"T1046","T1110"}           # scan/brute
    if ttp & crit:
        s += 3
    elif ttp & high:
        s += 2
    elif ttp & scanb:
        s += 1


    s += {"Expert":3,"Advanced":2,"Intermediate":1}.get(skill, 0)


    if flows >= 1000 or byte_rate > 5_000_000:
        s += 2
    elif flows >= 200 or byte_rate > 500_000:
        s += 1

  
    s += 1 if ev else 0
    if tool in {"CobaltStrike","Metasploit","sqlmap"}:
        s += 1

    
    thr = threat.lower()
    
    if "apt" in thr:
        s += 3

    if "ransomware" in thr:
        s += 3
   
    if any(k in thr for k in ("botnet","mirai","bitcoinminer","cobalt","miuref")):
        s += 2
  
    if any(k in thr for k in ("worm","netsky")):
        s += 2
    
    if "trojan" in thr or "zbot" in thr:
        s += 1
 
    if any(k in thr for k in ("adware","pup.adware")):
        s -= 1

  
    atk = attack.lower()
    if any(k in atk for k in ("ddos","dos","flood")):
        s += 3
    if any(k in atk for k in ("exfiltration","data exfiltration")):
        s += 2
    if any(k in atk for k in ("injection","csrf","shellcode")):
        s += 2
    if any(k in atk for k in ("brute force","bruteforce","password")):
        s += 1
    if "scan" in atk or "reconnaissance" in atk:
        s += 1

 
    st = stage.lower()
    if any(k in st for k in ("flood","dos","icmp","syn")):
        s += 2
    if "data exfiltration" in st:
        s += 2
    if any(k in st for k in ("injection","sql","xss")):
        s += 2
    if any(k in st for k in ("brute force","password attack","ssh brute","telnet brute")):
        s += 1
    if "lateral movement" in st or "establish foothold" in st:
        s += 1


    s += ENV_WEIGHT.get(ctx, 0)

   
    factor = 0.6 + (conf / 250)
    s *= factor

 
    return max(1, min(10, int(round(s))))

# ─── Kill-chain helpers ─────────────────────────────────────────────
TACTIC_TO_KC = {
    "Reconnaissance":"Recon","Discovery":"Recon",
    "Initial Access":"Delivery","Resource Development":"Delivery",
    "Execution":"Exploitation","Exploit Public-Facing Application":"Exploitation",
    "Privilege Escalation":"Exploitation",
    "Persistence":"Installation","Defense Evasion":"Installation",
    "Lateral Movement":"Installation",
    "Command and Control":"C2",
    "Exfiltration":"ActionsOnObjectives","Impact":"ActionsOnObjectives",
}
KC_ORDER=["Recon","Delivery","Exploitation","Installation","C2","ActionsOnObjectives"]
KC_IDX={k:i for i,k in enumerate(KC_ORDER)}
def build_kc_lookup(df):
    table={}
    for tech,tac in df[["technique_id","tactics"]].itertuples(False):
        for t in str(tac).split(";"):
            if t.strip() in TACTIC_TO_KC:
                table[str(tech)] = TACTIC_TO_KC[t.strip()]; break
    return table
def phases_from_ttps(s,kc):
    ph={kc.get(t) for t in s}; ph.discard(None)
    return ";".join(sorted(ph,key=lambda x:KC_IDX[x])) if ph else None


@time_feature
def score_profiles(row, tool_name, ttp_set, ev_set, skill, risk, phase, context, insider_geo):
    

    
    sc = {p: 0.0 for p in PROFILE_SET}

  
    flows    = getattr(row, "total_flows", 0)
    pps      = getattr(row, "packet_rate_per_sec", 0)
    udp_tcp  = getattr(row, "udp_tcp_traffic_ratio", 0)
    uniq_p   = getattr(row, "unique_dst_ports_count", 0)
    syn      = getattr(row, "syn_count", 0)
    ack      = getattr(row, "ack_count", 0)
    rst_syn  = getattr(row, "rst_syn_ratio", 0)


    exfil = bool({"T1048","T1041","T1020"} & ttp_set)
    ransom = "T1486" in ttp_set
    dos = bool({"T1498","T1499"} & ttp_set)
    scan = uniq_p > 100 or getattr(row, "port_scan_indicator", 0) == 1
    brute = syn > ack * 5 or rst_syn > 1.5

    
    thr      = str(getattr(row, "threat_type", "") + " " + getattr(row, "threat", "")).lower()
    atk      = str(getattr(row, "attack", "")).lower()
    stage    = str(getattr(row, "stage", "")).lower()

    is_apt    = "apt" in thr
    is_ransom = "ransomware" in thr or "locky" in thr or "wannacry" in thr
    is_botnet = "botnet" in thr or "mirai" in thr
    is_worm   = "worm" in thr
    is_trojan = "trojan" in thr or "zbot" in thr
    is_adware = "adware" in thr or "pup.adware" in thr

    ddos_atk      = any(k in atk for k in ("ddos","dos","flood"))
    exfil_atk     = "exfiltration" in atk
    inj_atk       = any(k in atk for k in ("injection","csrf","shellcode"))
    brute_atk     = any(k in atk for k in ("brute force","bruteforce","password"))
    scan_atk      = any(k in atk for k in ("scan","reconnaissance"))
    backdoor_atk  = "backdoor" in atk or "malware download" in atk

    flood_st      = any(k in stage for k in ("flood","dos","icmp","syn flood"))
    exfil_st      = "data exfiltration" in stage
    inj_st        = any(k in stage for k in ("sql injection","xss","command injection"))
    brute_st      = any(k in stage for k in ("brute force","password attack","ssh brute","telnet brute"))
    scan_st       = any(k in stage for k in ("scan","recon","vulnerability scanner"))
    move_st       = "lateral movement" in stage or "establish foothold" in stage



    # Nation-state
    if skill == "Expert" and risk >= 9 and exfil and ev_set:
        sc["nation-state"] += 4
    if context in {"5g","ics"}:
        sc["nation-state"] += 1
    if is_apt or is_ransom:
        sc["nation-state"] += 2
    if exfil_atk or exfil_st:
        sc["nation-state"] += 1
    if is_botnet:
        sc["nation-state"] += 1
    if max(sc.values()) == sc["nation-state"]: 
        sc["spy"] += 0.5  

    # Spy
    if exfil and phase and phase.endswith("C2"):
        sc["spy"] += 3
    if flows > 500 and getattr(row, "active_time_ratio", 0) > 0.7:
        sc["spy"] += 1
    if scan_atk or scan_st or inj_atk or inj_st:
        sc["spy"] += 1

    # Competitor
    if exfil and context in {"cloud","5g"} and risk >= 5:
        sc["competitor"] += 3
    if inj_atk or inj_st:
        sc["competitor"] += 0.5
    if skill in {"Advanced","Intermediate"}:
        sc["competitor"] += 0.5

    # Crime-syndicate
    if ransom or (dos and pps > 5000) or ddos_atk or flood_st:
        sc["crime-syndicate"] += 4
    if udp_tcp > 2:
        sc["crime-syndicate"] += 1
    if ev_set:
        sc["crime-syndicate"] += 1

    # Criminal
    if ransom or brute or exfil:
        sc["criminal"] += 3
    if brute_atk or brute_st:
        sc["criminal"] += 1
    if skill in {"Intermediate","Basic"}:
        sc["criminal"] += 0.5

    # Terrorist
    if dos and context == "ics" and risk >= 8 and flows > 1000:
        sc["terrorist"] += 4
    if "impact" in stage or exfil_st:
        sc["terrorist"] += 1

    # Activist
    if scan and dos and risk >= 5:
        sc["activist"] += 3
    if context == "iot":
        sc["activist"] += 0.5
    if is_adware or is_worm:
        sc["activist"] += 0.5

    # Sensationalist
    if exfil and 4 <= risk <= 6 and not dos:
        sc["sensationalist"] += 2
    if uniq_p < 10 and flows < 200:
        sc["sensationalist"] += 0.5
    if backdoor_atk or inj_atk:
        sc["sensationalist"] += 0.5

    # Insider-accidental / Insider-disgruntled
    if insider_geo:
        sc["insider-accidental"] += 1
        if exfil or brute or ev_set:
            sc["insider-disgruntled"] += 2
            if brute:
                sc["insider-disgruntled"] += 1

    # Hacker
    if scan and skill in {"Basic","Intermediate"} and tool_name == "Unclassified":
        sc["hacker"] += 2
    if udp_tcp > 5 and skill == "Basic":
        sc["hacker"] += 1
    if scan_atk or scan_st:
        sc["hacker"] += 0.5

    # Fallback Unknown
    if max(sc.values()) == 0:
        sc["unknown"] = 1.0

    return sc


def normalize_scores(sc: Dict[str,float]) -> Tuple[str,Dict[str,float]]:
    total=sum(sc.values()) or 1.0
    probs={k:round(v*100/total,1) for k,v in sc.items()}
    best=max(probs,key=probs.get)
    ties=[k for k,v in probs.items() if v==probs[best]]
    if len(ties)>1 and "nation-state" in ties: best="nation-state"
    return best, probs


ADV_EVASION_TTPS = {"T1020", "T1090", "T1105", "T1568", "T1090.002"}   # tunneling/proxy/dynamic-DNS…
PRIV_ESC_TTPS    = {"T1068", "T1055", "T1134"}
PIVOT_MOVE_TTPS  = {"T1021", "T1557", "T1018"}                         # lateral or MITM
ADV_TOOLS        = {"CobaltStrike", "Metasploit", "sqlmap",
                    "Hydra", "Masscan", "Nmap"}                      
@time_feature
def infer_knowledge(ttp_set: Set[str],
                    phase: str | None,
                    tool: str,
                    confidence: int,
                    kc_lookup: Dict[str, str]) -> str:
   

 
    tactics = {kc_lookup.get(t) for t in ttp_set if kc_lookup.get(t)}
    tactics.discard(None)
    num_tactics = len(tactics)


    phase = phase or ""
    depth = 0                    
    if phase:
        depth = max("Recon Delivery Exploitation Installation C2 ActionsOnObjectives"
                     .split().index(p) + 1
                     for p in phase.split(";"))


    has_adv_evasion = bool(ADV_EVASION_TTPS & ttp_set)
    has_priv_esc    = bool(PRIV_ESC_TTPS  & ttp_set)
    has_pivot       = bool(PIVOT_MOVE_TTPS & ttp_set)
    tool_adv        = tool in ADV_TOOLS

  
    if (
        num_tactics >= 4
        and depth >= 5                     
        and (has_priv_esc or has_adv_evasion)
        and confidence >= 70
    ):
        return "Expert"

  
    if (
        num_tactics >= 3
        and depth >= 4                    
        and (has_priv_esc or has_pivot or tool_adv or has_adv_evasion)
        and confidence >= 50
    ):
        return "High"


    if num_tactics >= 2 and depth >= 3:    
        return "Moderate"


    return "Low"


@time_feature
def infer_attitude(row,
                   risk_level: int,
                   killchain_phase: str | None,
                   ttp_set: Set[str],
                   evasion_set: Set[str]) -> str:
    


    flows      = getattr(row, "total_flows", 0)
    pps        = getattr(row, "packet_rate_per_sec", 0.0)
    brate      = getattr(row, "byte_rate_per_sec", 0.0)
    active_rat = getattr(row, "active_time_ratio", 0.0)
    rep_conns  = getattr(row, "repeated_connections_frequency", 0)
    uniq_sess  = getattr(row, "unique_sessions_count", 0)
    idle_avg   = getattr(row, "avg_idle_time_between_flows", 0.0)
    max_idle   = getattr(row, "max_idle_time", 0.0)


    thr_type   = str(getattr(row, "threat_type", "") or "").lower()
    thr        = str(getattr(row, "threat", "") or "").lower()
    atk        = str(getattr(row, "attack", "") or "").lower()
    stage      = str(getattr(row, "stage", "") or "").lower()
    phase      = killchain_phase or ""
    

    dos_flag     = bool({"T1498", "T1499"} & ttp_set)
    ransom_flag  = "T1486" in ttp_set
    exfil_flag   = bool({"T1048", "T1041", "T1020"} & ttp_set)
    c2_flag      = "C2" in phase
    impact_flag  = phase.endswith("ActionsOnObjectives")


    ddos_atk     = any(k in atk for k in ("ddos","dos","flood"))
    exfil_atk    = "exfiltration" in atk
    inj_atk      = any(k in atk for k in ("injection","csrf","shellcode"))
    brute_atk    = any(k in atk for k in ("brute force","bruteforce","password"))
    scan_atk     = any(k in atk for k in ("scan","reconnaissance","fuzzer"))
    
    flood_st     = any(k in stage for k in ("flood","dos","icmp","syn flood"))
    exfil_st     = "data exfiltration" in stage
    inj_st       = any(k in stage for k in ("sql injection","xss","command injection"))
    brute_st     = any(k in stage for k in ("brute force","password attack","ssh brute","telnet brute"))
    move_st      = "lateral movement" in stage or "establish foothold" in stage
    recon_st     = "reconnaissance" in stage or "scan" in stage


    if (
        (dos_flag and (pps > 5_000 or flows > 10_000)) or
        ddos_atk or flood_st or
        ransom_flag or
        (impact_flag and risk_level >= 8) or
        exfil_flag or exfil_atk or exfil_st
    ):
        return "Destructive"


    if (
        (c2_flag and rep_conns > 50) or
        (uniq_sess > 20 and active_rat > 0.7) or
        (evasion_set and max_idle < 60) or
        inj_atk or inj_st
    ):
        return "Persistent"


    if (
        exfil_flag or exfil_atk or exfil_st or
        move_st or
        (200 <= flows < 1_000) or
        (idle_avg > 120 and active_rat < 0.5)
    ):
        return "Targeted"


    return "Opportunistic"





import json, math, datetime as _dt
_PT_PATH = Path("preferred_targets_db.json") 
_TOP_K   = 5                                   
_HALF_LIFE_DAYS = 30                           

def _decay_factor(delta_days: float) -> float:
    """Semivida exponencial para premiar los destinos recientes."""
    return 0.5 ** (delta_days / _HALF_LIFE_DAYS)

def _load_pt_db() -> Dict[str, Dict[str, float]]:
    if _PT_PATH.exists():
        return json.loads(_PT_PATH.read_text())
    return {}

def _save_pt_db(db: Dict[str, Dict[str, float]]):
    _PT_PATH.write_text(json.dumps(db))

def update_preferred_targets(actor_id: str,
                             dst_ip: str,
                             bytes_sent: float,
                             ts_str: str,
                             db: Dict[str, Dict[str, float]]) -> str:
   
    today = _dt.datetime.utcnow().date()
    try:
        ts = _dt.datetime.fromisoformat(str(ts_str)).date()
    except ValueError:
        ts = today                      

    w_time  = _decay_factor((today - ts).days)
    w_bytes = math.log1p(bytes_sent) / 20_000    
    weight  = 1.0 + w_bytes
    db.setdefault(actor_id, {})
    db[actor_id][dst_ip] = db[actor_id].get(dst_ip, 0.0) + weight * w_time


    top = sorted(db[actor_id].items(), key=lambda kv: kv[1], reverse=True)[:_TOP_K]
    return ";".join(ip for ip, _ in top)



MOTIVATIONS = ["Financial", "Espionage", "Ideology",
               "Sabotage", "Notoriety", "Unknown"]
@time_feature
def infer_motivation(profile: str,
                     risk: int,
                     knowledge: str,
                     attitude: str,
                     ttp_set: Set[str],
                     tool: str,
                     attack_str: str,
                     threat_str: str,
                     stage_str: str,
                     byte_ratio: float) -> str:
   

 
    thr      = threat_str.lower()
    atk      = attack_str.lower()
    stage    = stage_str.lower()


    score = {m: 0 for m in MOTIVATIONS}

    
    is_apt        = "apt" in thr
    is_ransom     = "ransomware" in thr or "locky" in thr or "wannacry" in thr
    is_botnet     = "botnet" in thr or "mirai" in thr
    is_worm       = "worm" in thr
    is_trojan     = "trojan" in thr or "zbot" in thr
    is_adware     = "adware" in thr or "pup.adware" in thr
    is_miner      = "bitcoinminer" in thr or "cobalt" in thr or "miuref" in thr or "andromeda" in thr


    ddos_atk      = any(k in atk for k in ("ddos","dos","flood"))
    exfil_atk     = "exfiltration" in atk or "data exfiltration" in atk
    inj_atk       = any(k in atk for k in ("injection","csrf","shellcode","exploit"))
    brute_atk     = any(k in atk for k in ("brute force","bruteforce","password"))
    scan_atk      = any(k in atk for k in ("scan","reconnaissance","fuzzer","analysis"))
    backdoor_atk  = "backdoor" in atk or "malware download" in atk
    web_atk       = any(k in atk for k in ("web","uploading attack","csrf"))

 
    flood_st      = any(k in stage for k in ("flood","dos","icmp","syn flood"))
    exfil_st      = "data exfiltration" in stage
    inj_st        = any(k in stage for k in ("sql injection","xss","command injection"))
    brute_st      = any(k in stage for k in ("brute force","password attack","ssh brute","telnet brute","mqtt brute"))
    scan_st       = any(k in stage for k in ("scan","recon","vulnerability scanner","os fingerprinting"))
    mitm_st       = "mitm" in stage
    move_st       = any(k in stage for k in ("lateral movement","establish foothold"))
    recon_st      = "reconnaissance" in stage

    
    if profile in {"crime-syndicate", "criminal", "terrorist"}:
        score["Financial"] += 2
    if is_ransom or brute_atk and byte_ratio > 5:
        score["Financial"] += 2
    if exfil_atk or exfil_st or ddos_atk or flood_st:
        score["Financial"] += 1
    if backdoor_atk:
        score["Financial"] += 1


    if profile in {"spy", "nation-state", "competitor"}:
        score["Espionage"] += 2
    if is_apt or is_miner:
        score["Espionage"] += 2
    if scan_atk or scan_st or mitm_st:
        score["Espionage"] += 1
    if knowledge in {"High", "Expert"} and attitude == "Persistent":
        score["Espionage"] += 1

  
    if profile == "activist":
        score["Ideology"] += 2
    if "hacktiv" in thr or "protest" in thr:
        score["Ideology"] += 1
    if inj_atk or inj_st:
        score["Ideology"] += 1
    if ddos_atk or flood_st:
        score["Ideology"] += 1


    if attitude == "Destructive":
        score["Sabotage"] += 3
    if ddos_atk or flood_st or is_ransom:
        score["Sabotage"] += 1
    if exfil_flag := ("exfiltration" in atk or "data exfiltration" in stage):
        score["Sabotage"] += 1


    if profile in {"sensationalist", "hacker"}:
        score["Notoriety"] += 2
    if inj_atk or inj_st:
        score["Notoriety"] += 1
    if scan_atk and byte_ratio < 1:
        score["Notoriety"] += 1

 
    if max(score.values()) == 0:
        score["Unknown"] = 1


    return max(score, key=score.get)




import json, datetime, csv
from pathlib import Path
from functools import lru_cache

_GROUP_DB = {}       #
_TECH_INV = defaultdict(set)   
_CAMPAIGNS = []      

def _load_group_db(path="groups.csv", camp="campaigns.csv"):
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gid = row["group_id"]
            techs = set(row["techniques"].split(";"))
            tools = set(row.get("tools","").split(";")) if row.get("tools") else set()
            _GROUP_DB[gid] = {
                "name": row["group_name"],
                "country": row.get("country"),
                "industry": row.get("industry"),
                "techs": techs,
                "tools": tools,
            }
            for t in techs:
                _TECH_INV[t].add(gid)
    with open(camp, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["techniques"] = set(row["techniques"].split(";"))
            row["start"] = datetime.date.fromisoformat(row["start"])
            row["end"]   = datetime.date.fromisoformat(row["end"])
            _CAMPAIGNS.append(row)

_load_group_db()


def jaccard(a:set,b:set)->float:
    return len(a&b)/len(a|b) if a or b else 0.0


def infer_threat_group(tset:set, tools:set, country:str,
                       industry:str|None, risk:int)->tuple[str,float]:
    """
    Devuelve (group_name, score)  –  Unknown si <0.25
    """
   
    cands = {gid for t in tset for gid in _TECH_INV.get(t,())}
    best, best_s = "Unknown", 0.0
    for gid in cands:
        g = _GROUP_DB[gid]
        s = jaccard(tset, g["techs"])
       
        if country and country == g["country"]:
            s += 0.05
        if industry and g["industry"] and industry.lower() in g["industry"]:
            s += 0.05
        if tools & g["tools"]:
            s += 0.05
        if risk and risk >= 7:
            s += 0.05
        if s > best_s:
            best, best_s = g["name"], s
    return (best if best_s >= 0.25 else "Unknown", round(best_s,3))


def infer_campaign(group_name:str, tset:set,
                   first_seen: _dt.date | None )->str|None:
    if group_name=="Unknown" or first_seen is None: return None
    cands=[c for c in _CAMPAIGNS if c["group_id"]==group_name]
    if not cands: return None
    best, best_s = None, 0
    for c in cands:
        if c["start"] and first_seen < c["start"]-datetime.timedelta(days=90):
            continue
        if c["end"] and first_seen > c["end"]+datetime.timedelta(days=90):
            continue
        s = len(tset & c["techniques"])
        if s > best_s:
            best, best_s = c["name"], s
    return best


AFFIL_VALUES = ["State","State-Contractor","Criminal-Enterprise",
                "Independent-Criminal","Hacktivist","Insider",
                "Terrorist Org","Unknown"]

TG_TO_AFF = {              
    "APT28": "State",
    "APT29": "State",
    "Wizard Spider": "Criminal-Enterprise",
    "FIN7": "Criminal-Enterprise",
    "Scattered Spider": "Independent-Criminal",
}
@time_feature
def infer_affiliation(threat_group: str,
                      profile: str,
                      motivation: str,
                      asn_desc: str,
                      insider_geo: bool) -> str:

    aff = TG_TO_AFF.get(threat_group)
    if aff:
        return aff

    
    if insider_geo:
        return "Insider"

    ad = asn_desc.lower()


    if any(k in ad for k in ("defense", "mil", "army", "gov")):
        return "State"
    if "university" in ad or "research" in ad:
        return "State-Contractor"
    if any(k in ad for k in ("hosting", "colo", "vps", "bulletproof")):
        return "Criminal-Enterprise"


    if profile == "nation-state":
        return "State"
    if profile in {"crime-syndicate", "criminal"}:
        return "Criminal-Enterprise"
    if profile == "activist" or motivation == "Ideology":
        return "Hacktivist"
    if motivation == "Financial":
        return "Independent-Criminal"


    if profile == "terrorist":
        return "Terrorist Org"

    return "Unknown"


_COMMENT_MODEL = "google/flan-t5-base"      
_MAX_LEN_IN, _MAX_LEN_OUT = 128, 48         

@lru_cache(maxsize=1)
def _get_comment_pipe():
    tok  = AutoTokenizer.from_pretrained(_COMMENT_MODEL)
    mdl  = AutoModelForSeq2SeqLM.from_pretrained(_COMMENT_MODEL)
    return pipeline("text2text-generation", model=mdl, tokenizer=tok)

def make_comment(profile:str, risk:int, motivation:str,
                 knowledge:str, attitude:str, affiliation:str,
                 threat_group:str|None, campaign:str|None,
                 pref_targets:str|None) -> str:
    
    prompt = (
        "Analyst note (1 sentence, ≤25 words) summarizing: "
        f"profile={profile}; risk={risk}/10; motivation={motivation}; "
        f"knowledge={knowledge}; attitude={attitude}; affiliation={affiliation}; "
        f"group={threat_group or 'N/A'}; campaign={campaign or 'N/A'}; "
        f"preferred={pref_targets or 'N/A'}."
    )[:_MAX_LEN_IN]       

    gen = _get_comment_pipe()
    txt = gen(prompt, max_length=_MAX_LEN_OUT, num_beams=4)[0]["generated_text"]

    return txt.strip().replace("\n", " ")




def build_profiles(flows, ttp_map, tool_map, ev_map, context):
    flows = flows.copy()
    for col in ["attack", "stage", "threat", "threat_type"]:
        if col in flows.columns:
            flows[col] = flows[col].fillna("").astype(str)
    pref=compute_preferred_targets(flows)
    ttp_sets,supp=build_ttps_sets(flows, ttp_map)
    tools=build_tools_column(flows, tool_map)
    ev_sets=build_evasion_sets(flows, ev_map)
    kc_lu=build_kc_lookup(ttp_map)
    pt_db   = _load_pt_db() 
    rec=[]
    for i,row in enumerate(flows.itertuples(False)):
        threat      = getattr(row, "threat", "").lower()
        threat_type = getattr(row, "threat_type", "").lower()
        attack      = getattr(row, "attack", "").lower()
        stage       = getattr(row, "stage", "").lower()
        tool = tools[i]
        ips  = split_ips(getattr(row,SRC_COL,""))
        dst  = getattr(row,DST_COL)
        tset, evset = ttp_sets[i], ev_sets[i]

        phase=phases_from_ttps(tset, kc_lu)
        conf = calc_confidence(row, ips, tset, evset, tool, supp)
        auto = calc_automation_level(row)
        skill= infer_skill(auto, tset, evset, tool, getattr(row,"total_flows",0), row)
        knw = infer_knowledge(tset, phase, tool, conf, kc_lu)
        attack_str=str(getattr(row,"attack","")).lower()
        stage_str =str(getattr(row,"stage","")).lower()
        threat_str=f"{getattr(row,'threat_type','')} {getattr(row,'threat','')}".lower()
        risk = calc_risk_level_num(
            row, tset, phase, skill, conf, evset,
            getattr(row,"total_flows",0),
            getattr(row,"byte_rate_per_sec",0.0),
            tool, threat_str, attack_str, stage_str, context
        )
        bytes_sent = getattr(row, "total_bytes_sent", 0.0)
        pref_targets = update_preferred_targets(f"profile_{getattr(row, ID_COL)}",dst,bytes_sent,getattr(row, FIRST_SEEN_COL), pt_db,)
        insider_geo = ip_to_country(dst) in [ip_to_country(ip) for ip in ips]
        sc = score_profiles(row, tool, tset, evset, skill, risk, phase, context, insider_geo)
        profile, dist = normalize_scores(sc)
        att = infer_attitude(row, risk, phase, tset, evset)
        pref_cand=[pref.get(ip) for ip in ips if ip in pref]
        motivation = infer_motivation(profile, risk, knw, att, tset, tool,attack_str, threat_str, stage_str,getattr(row, "byte_sent_received_ratio", 1.0),)
  
        group_name, g_score = infer_threat_group(tset,{tool},countries_from_ips(ips)[0] if ips else "",context,risk)
        fs_raw = str(getattr(row, FIRST_SEEN_COL))[:10]          
        asn_desc = get_asn_description(ips[0]) if ips else ""
        affiliation = infer_affiliation(group_name,profile,motivation,asn_desc,insider_geo)
        try:
            first_seen_dt = _dt.date.fromisoformat(fs_raw)
        except ValueError:                                        
            first_seen_dt = None

        campaign = infer_campaign(group_name, tset, first_seen_dt)
#        comment = make_comment(profile, risk, motivation,knw, att, affiliation,group_name if group_name!="Unknown" else None,campaign,pref_targets)
        rec.append({
            "Id":f"profile_{getattr(row,ID_COL)}",
            "IPs":";".join(ips),
            "Target":dst,
            "PreferredTarget":Counter(pref_cand).most_common(1)[0][0] if pref_cand else dst,
            "FirstSeen":getattr(row,FIRST_SEEN_COL),
            "LastActivity":getattr(row,LAST_ACT_COL),
            "Country":";".join(countries_from_ips(ips)) or None,
            "AutomationLevel":auto,
            "Evasion":";".join(sorted(evset)) if evset else None,
            "TTPs":";".join(sorted(tset)) if tset else None,
            "KillChainPhase":phase,
            "RiskLevel":risk,
            "Confidence":conf,
            "Tools":tool,
            "Skills":skill,
            "Profile":profile,
            "ProfileDist":json.dumps(dist,separators=(",",":")),
            "Knowledge": knw,
            "Attitude": att,
            "PreferredTargets": pref_targets,
            "Motivation": motivation,
            "ThreatGroup": group_name if group_name != "Unknown" else None,
            "Campaigns":   campaign,
            "Affiliation": affiliation,
            "Comments":  "",
            #"Comments": (f"Probable {affiliation.lower()} actor; "f"{profile} profile ({dist[profile]}%); "f"risk {risk}/10, motivation {motivation.lower()}, "f"knowledge {knw.lower()}, attitude {att.lower()}."),
        })
    _save_pt_db(pt_db)
    return pd.DataFrame(rec, columns=PROFILE_COLUMNS)

# ─── CLI ────────────────────────────────────────────────────────────
def cli(argv:Iterable[str]|None=None):
    p=argparse.ArgumentParser(description="Genera perfiles (23 columnas)")
    p.add_argument("input",type=Path)
    p.add_argument("output", type=Path)
#    p.add_argument("output",type=Path,nargs="?",default="attack_profiles_23f.csv")
    p.add_argument("-m","--mapping",default="network_observable_attack_mapping_v2.csv")
    p.add_argument("-t","--toolmap",default="network_tool_mapping_v1.csv")
    p.add_argument("-e","--evasionmap",default="network_evasion_mapping_v1.csv")
    p.add_argument("-c","--context",choices=["iot","5g","cloud","ics"],default="iot")
#    p.add_argument("output",type=Path,nargs="?",default="attack_profiles_23f.csv")
    a=p.parse_args(argv)

    try: 
        flows=pd.read_csv(a.input,low_memory=False)
        text_cols = ["attack", "stage", "threat", "threat_type"]
        for col in text_cols:
            if col in flows.columns:
                flows[col] = flows[col].fillna("").astype(str)
    except Exception as e: sys.exit(f"❌ Error leyendo {a.input}: {e}")
    try:
        text_cols = ["attack", "stage", "threat", "threat_type"]
        for col in text_cols:
            if col in flows.columns:
                flows[col] = flows[col].fillna("").astype(str)
        map_df=pd.read_csv(a.mapping)
        tool_df=pd.read_csv(a.toolmap,engine="python")
        ev_df=pd.read_csv(a.evasionmap)
        for df in (map_df, tool_df, ev_df):
            if "mapping_hint" in df.columns:
                df["mapping_hint"] = df["mapping_hint"].fillna("").astype(str)
    except Exception as e:
        sys.exit(f"❌ Error leyendo mapping: {e}")

    df=build_profiles(flows,map_df,tool_df,ev_df,a.context)
    output_dir = "./time"
    os.makedirs(output_dir, exist_ok=True)

#    base = os.path.splitext(os.path.basename(input_csv_path))[0]
    base = a.input.stem
    output_csv = os.path.join(output_dir, f"{base}_time.csv")


    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["FEATURE", "TIEMPO_MEDIO(s)", "TIEMPO_TOTAL(s)"])
        for feat, times in timings.items():
            count      = len(times)
            total_time = sum(times)
            mean_time  = total_time / count if count else 0.0
            writer.writerow([feat, f"{mean_time:.6f}", f"{total_time:.6f}"])

    print(f"Resultados escritos en: {output_csv}")
    df.to_csv(a.output,index=False)
    print(f"✔️  Archivo escrito en {a.output.resolve()}")

if __name__=="__main__":
    cli()
