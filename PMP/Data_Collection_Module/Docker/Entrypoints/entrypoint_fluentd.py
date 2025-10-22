#!/usr/bin/env python3

import os
import re
import time
import signal
import subprocess

WATCH_DIR = "/fluentd/log/out"
SIZE_LIMIT = 2 * 1024 * 1024  # 20MB
PATTERNS = [
    r"syslog_output\.log\.\d{8}\.log",
    r"systemd_output\.log\.\d{8}\.log"
]

FLUENTD_COMMAND = [
    "fluentd",
    "-c", "/fluentd/etc/fluent.conf",
    "-p", "/fluentd/plugins",
    "--no-supervisor",
    "-vv"
]

def match_log_files():
    files = []
    for f in os.listdir(WATCH_DIR):
        for pattern in PATTERNS:
            if re.fullmatch(pattern, f):
                files.append(f)
    return files

def handle_large_file(full_path):
    #full_path = os.path.join(WATCH_DIR, filename)
    try:
        os.remove(full_path)
    except Exception as e:
        print(f"{full_path}: {e}")

def monitor_logs(pid):
    while True:
        time.sleep(5)
        files = match_log_files()
        for f in files:
            full_path = os.path.join(WATCH_DIR, f)
            if os.path.isfile(full_path) and os.path.getsize(full_path) >= SIZE_LIMIT:
                handle_large_file(full_path)
                os.kill(pid, signal.SIGUSR1)
        time.sleep(5)

def main():
    fluentd_proc = subprocess.Popen(FLUENTD_COMMAND)

    try:
        monitor_logs(fluentd_proc.pid)
    except KeyboardInterrupt:
        fluentd_proc.terminate()
        fluentd_proc.wait()

if __name__ == "__main__":
    main()
