#!/usr/bin/env python3
import os
from flask import Flask, jsonify

app = Flask(__name__)

machine_id = os.environ.get("MACHINE_ID", "unknown")

# Services running. 0 is for not running and 1 is for running
enable_telegraf = os.environ.get("ENABLE_TELEGRAF", "0") == "1"
enable_fluentd = os.environ.get("ENABLE_FLUENTD", "0") == "1"
enable_falco_exporter = os.environ.get("ENABLE_FALCO", "0") == "1"

@app.route("/prom-targets")
def prom_targets():
    targets = []

    if enable_telegraf:
        targets.append("localhost:9273")
    if enable_fluentd:
        targets.append("localhost:24231")
    if enable_falco_exporter:
        targets.append("localhost:9376")

    return jsonify([
        {
            "targets": targets,
            "labels": {
                "machine_id": machine_id
            }
        }
    ])

app.run(host="0.0.0.0", port=9999)
