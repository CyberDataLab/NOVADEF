#!/usr/bin/env python3
import subprocess
import json
import socket
import ipaddress
import threading
import time
import requests
from flask import Flask, jsonify

app = Flask(__name__)

SCAN_PORT = int("9999")
SCAN_TIMEOUT = 0.2
REFRESH_INTERVAL = 30
cached_results = []

def get_local_ip():
    """Obtain local IP by opening UDP socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def get_subnet(ip):
    """Get subnet from system routing."""
    result = subprocess.check_output(["ip", "route"]).decode()

    for line in result.splitlines():
        if ip in line:
            parts = line.split()
            for part in parts:
                if "/" in part:
                    return ipaddress.ip_network(part, strict=False)

    # fallback
    return ipaddress.ip_network(f"{ip}/24", strict=False)

def adjust_subnet(net):
    """Reduce huge networks automatically."""
    if net.prefixlen <= 20:  # /8 /16 /20
        # Reduce to /24
        network = ipaddress.ip_network(f"{list(net.hosts())[0]}/24", strict=False)
        return network
    return net

def scan_host(ip):
    """Check if /prom-targets is alive and FIX localhost addresses."""
    url = f"http://{ip}:{SCAN_PORT}/prom-targets"
    try:
        r = requests.get(url, timeout=SCAN_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            # If the scanned device uses localhost or 127.0.0.1, it is replaced with its actual IP address.
            for group in data:
                new_targets = []
                for t in group.get("targets", []):
                    if "localhost" in t or "127.0.0.1" in t:
                        new_targets.append(t.replace("localhost", ip).replace("127.0.0.1", ip))
                    else:
                        new_targets.append(t)
                group["targets"] = new_targets
            return data
    except:
        pass
    return None

def background_scanner():
    """Function to run in background and update cache."""
    global cached_results
    while True:
        print("[DISCOVERY] Starting network scan...")
        local_ip = get_local_ip()
        subnet = get_subnet(local_ip)
        subnet = adjust_subnet(subnet)

        print(f"[DISCOVERY] Local IP: {local_ip}")
        print(f"[DISCOVERY] Scanning subnet: {subnet}")

        results = []
        for ip in subnet.hosts():
            data = scan_host(str(ip))
            if data:
                print(f"[DISCOVERY] Found active device-info at {ip}")
                results.extend(data)
        
        # Update the cache results
        cached_results = results
        print("[DISCOVERY] Scan complete. Cache updated.")
        
        # Esperar para el siguiente escaneo
        time.sleep(REFRESH_INTERVAL)


@app.route("/sd")
def service_discovery():
    # Cache results response
    return jsonify(cached_results)

if __name__ == "__main__":
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()
    
    app.run(host="0.0.0.0", port=8000)
