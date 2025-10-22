#!/usr/bin/env python3
"""
install_cfm.py

Create a virtual environment with Python 3.12, install cicflowmeter 0.1.9 and scapy 2.5.0
and apply the three necessary patches (timestamp, utils, TCP and UDP filter).
"""

import sys, os, subprocess, re
from pathlib import Path
from textwrap import dedent

# ────── Parameters ──────
try:
    VENV_DIR  = Path(sys.argv[1]).expanduser()
    PY312_BIN = Path(sys.argv[2]).expanduser()
except IndexError:
    sys.exit("Use: install_cfm.py  <venv_dir>  <python3.12_bin>")

if not PY312_BIN.exists():
    sys.exit(f"Interpreter not found: {PY312_BIN}")

# ────── Automatic relaunch ──────
if Path(sys.executable).resolve() != PY312_BIN.resolve():
    os.execv(PY312_BIN, [str(PY312_BIN), *sys.argv])

# ────── 1. Creating venv ──────
print(f"➤ Creating virtualenv in {VENV_DIR} withc {PY312_BIN} …")
subprocess.check_call([str(PY312_BIN), "-m", "venv", "--clear", str(VENV_DIR)])

PYTHON = VENV_DIR / "bin" / "python"
PIP    = [str(PYTHON), "-m", "pip"]

# ────── 2. Installing packages ──────
print("➤ Installing cicflowmeter 0.1.9 + scapy 2.5.0 …")
subprocess.check_call(PIP + ["install", "--upgrade", "pip"])
subprocess.check_call(PIP + ["install", "cicflowmeter==0.1.9", "scapy==2.5.0"])

# ────── 3. Locating package within the venv ──────
site_pkg = subprocess.check_output(
    [str(PYTHON), "-c",
     "import inspect, pathlib, cicflowmeter, sys;"
     "print(pathlib.Path(inspect.getfile(cicflowmeter)).parent)"],
    text=True).strip()
pkg = Path(site_pkg)

# ────── 4. Applying patches ──────
# 4.1 packet_time.py
pt = pkg / "features" / "packet_time.py"
pt.write_text(pt.read_text().replace(
    "fromtimestamp(time)", "fromtimestamp(float(time))"))

# 4.2 utils.py
ut = pkg / "utils.py"
ut.write_text(re.sub(
    r"arr\s*=\s*numpy\.array\(.*?\)",
    "alist = [float(x) for x in alist]\n    arr   = numpy.asarray(alist, dtype=float)",
    ut.read_text(), count=1, flags=re.S))

# 4.3 flow_session.py  (removing TCP/UDP filter)
fs = pkg / "flow_session.py"
fs.write_text(re.sub(
    r"if\s+self\.output_mode\s*!=\s*\"csv\"[^\n]*\n"   # CSV head
    r"(?:[ \t]+[^\n]*\n){4}",                         # 4 code lines with if-return y elif-return
    "",
    fs.read_text(), count=1, flags=re.S))

print("✅  Environment configured correctly.")

# ────── 5. Use ──────
ACTIVATE = VENV_DIR / "bin" / "activate"
print(dedent(f"""
┌──────────────────────────────────────────────┐
│  Common ussage                               │
└──────────────────────────────────────────────┘
# Activating the environment
source {ACTIVATE}

# Parsing PCAP → CSV
SCAPY_BPF=0 cicflowmeter -f trace.pcap -c result.csv -v

# Leaving the environment
deactivate
"""))
