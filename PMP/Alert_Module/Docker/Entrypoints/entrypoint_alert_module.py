import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import fcntl
import struct

from kafka_io import KafkaLineConsumer, KafkaAlertProducer, get_bootstrap
from pymongo import MongoClient, errors

# === FILE CONFIG ===
PFD = Path(__file__).resolve().parent  # /home/Alert_Module in container

SNORT_CONFIG_DIR = PFD / "Snort_configuration"
SNORT_LUA = str(SNORT_CONFIG_DIR / "lua" / "snort.lua")
SNORT_RULES = str(SNORT_CONFIG_DIR / "Rules" / "alert_rules.rules")
ALERT_DIR = str(PFD / "Alerts")
ALERT_FILE = "alert_json"
ALERT_PATH = os.path.join(ALERT_DIR, f"{ALERT_FILE}.txt")

# ====== KAFKA CONFIG ======
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "alert-module-v1")
KAFKA_TOPIC_IN = os.getenv("KAFKA_TOPIC_IN", "tshark_traces")
KAFKA_TOPIC_OUT = os.getenv("KAFKA_TOPIC_OUT", "snort_alerts")

# === SNORT CONFIG ===
SNORT_BASE_CMD = [
    "snort",
    "-c", SNORT_LUA,
    "-R", SNORT_RULES,
    "-A", ALERT_FILE,
    "--lua",
    f"{ALERT_FILE} = {{file = true, fields = 'msg timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action'}}",
    "-l", ALERT_DIR,
    "-k", "none",
]

# ====== CONSTANTS TUN/TAP ======
TAP_IFACE = os.getenv("ALERT_TAP_IFACE", "tap0")
TUNSETIFF = 0x400454ca
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

def ensure_mode_644(path: str):
    """
    Set permissions to 0644 only if necessary (avoid redundant chmod).
    """
    try:
        st_mode = os.stat(path).st_mode & 0o777
        if st_mode != 0o644:
            os.chmod(path, 0o644)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"⚠️  Could not ensure 0644 on {path}: {e}")


def truncate_alert_file(alert_path: str):
    """
    Truncate the alert file to avoid duplicates.
    """    
    try:
        os.makedirs(os.path.dirname(alert_path), exist_ok=True)
        with open(alert_path, "w"):
            pass
        print(f"🧹 Truncated {alert_path}")
    except Exception as e:
        print(f"⚠️ Could not truncate {alert_path}: {e}")


def insert_alert_line(alerts_collection, line: str):
    """
    Parses a single JSON-formatted alert line and inserts it into MongoDB.
    Handles JSON decoding issues, duplicate entries, and database timeouts.
    """
    try:
        alert_doc = json.loads(line)
    except json.JSONDecodeError:
        print(f"⚠️ Error decoding JSON alert line: {line}")
        return

    try:
        alerts_collection.insert_one(alert_doc)
    except errors.DuplicateKeyError:
        pass
    except errors.ServerSelectionTimeoutError:
        print("❌ MongoDB connection timeout while inserting alert. Will continue...")
    except Exception as e:
        print(f"❌ Error inserting alert: {e}")


def open_tap_interface(ifname: str) -> int:
    """
    Creates or opens a TAP interface using /dev/net/tun and returns its file descriptor.
    Configures the interface in TAP mode without packet information (IFF_NO_PI)
    and brings it up using system network tools.
    Requires /dev/net/tun access and NET_ADMIN capabilities.
    """
    try:
        tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    except OSError as e:
        print(f"❌ Cannot open /dev/net/tun: {e}")
        sys.exit(1)

    ifr = struct.pack("16sH", ifname.encode(), IFF_TAP | IFF_NO_PI)
    try:
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    except OSError as e:
        print(f"❌ TUNSETIFF failed for {ifname}: {e}")
        os.close(tun_fd)
        sys.exit(1)

    # Upping the TAP interface
    try:
        subprocess.run(["ip", "link", "set", ifname, "up"], check=True)
        print(f"✅ TAP interface {ifname} is up (fd={tun_fd})")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Could not bring {ifname} up: {e}")

    return tun_fd


def start_snort_live(ifname: str):
    """
    Launches Snort3 in live-capture mode using the specified interface.
    Executes Snort with the predefined configuration and rule set,
    redirecting output streams to background logging threads.
    Returns the running subprocess handle for lifecycle management.
    """
    cmd = SNORT_BASE_CMD + ["-i", ifname]
    print(f"🚀 Starting Snort3 live on interface {ifname}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    def _log_stream(stream, prefix):
        for line in stream:
            print(f"[{prefix}] {line.strip()}")

    threading.Thread(target=_log_stream, args=(proc.stdout, "snort-out"), daemon=True).start()
    threading.Thread(target=_log_stream, args=(proc.stderr, "snort-err"), daemon=True).start()

    return proc



def alerts_tail_loop(alert_path: str, producer: KafkaAlertProducer, alerts_collection):
    """
    Continuously monitors the Snort alert file for newly appended lines.
    Each new alert is forwarded to Kafka and optionally stored in MongoDB.
    Implements buffered Kafka publishing to reduce overhead.
    """
    os.makedirs(os.path.dirname(alert_path), exist_ok=True)
    if not os.path.exists(alert_path):
        open(alert_path, "a").close()
    ensure_mode_644(alert_path)

    print(f"📡 Starting alerts tail on {alert_path}")
    with open(alert_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END) # Go to the end of the file (only new lines)

        buffer = []
        last_flush = time.time()
        FLUSH_INTERVAL = 1.0  # seconds

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5) # Waiting to receive new alerts
            else:
                line = line.strip()
                if not line:
                    continue

                #  Sending to Kafka (in batches for efficiency)
                buffer.append(line)
                if time.time() - last_flush >= FLUSH_INTERVAL:
                    try:
                        producer.produce_lines(buffer)
                    except Exception as e:
                        print(f"❌ Error publishing alerts to Kafka: {e}")
                    buffer.clear()
                    last_flush = time.time()

                # Sending alerts to MongoDB
                if alerts_collection is not None:
                    insert_alert_line(alerts_collection, line)


def rebuild_frame_from_layers(layers):
    """
    Reconstructs an Ethernet frame from dissected protocol layer fields
    when a raw frame is not available. Supports Ethernet, IP, TCP/UDP,
    and data payload assembly. Returns None if mandatory fields are missing.
    """
    try:
        # Ethernet header
        dst = layers.get("eth_dst_raw")
        src = layers.get("eth_src_raw")
        eth_type = layers.get("eth_type_raw")

        if not (dst and src and eth_type):
            print("⚠️ Cannot rebuild frame: missing ethernet fields")
            return None

        if isinstance(dst, list): dst = dst[0]
        if isinstance(src, list): src = src[0]
        if isinstance(eth_type, list): eth_type = eth_type[0]

        eth_header = bytes.fromhex(dst + src + eth_type)

        # IP raw
        ip_raw = layers.get("ip_raw")
        if isinstance(ip_raw, list):
            ip_raw = ip_raw[0]
        ip_bytes = bytes.fromhex(ip_raw) if ip_raw else b""

        # TCP raw
        tcp_raw = layers.get("tcp_raw")
        if isinstance(tcp_raw, list):
            tcp_raw = tcp_raw[0]
        tcp_bytes = bytes.fromhex(tcp_raw) if tcp_raw else b""

        # UDP raw
        udp_raw = layers.get("udp_raw")
        if isinstance(udp_raw, list):
            udp_raw = udp_raw[0]
        udp_bytes = bytes.fromhex(udp_raw) if udp_raw else b""

        # Payload
        payload = b""
        pay = layers.get("data_data")
        if pay:
            if isinstance(pay, list):
                pay = pay[0]
            try:
                payload = bytes.fromhex(pay)
            except Exception:
                payload = b""

        # Final frame 
        frame = eth_header + ip_bytes + tcp_bytes + udp_bytes + payload

        if len(frame) == 0:
            print("⚠️ Rebuilt frame is empty")
            return None

        return frame

    except Exception as e:
        print(f"❌ Error rebuilding frame: {e}")
        return None



def extract_frame_bytes(packet_dict) -> bytes:
    """
    Extracts raw frame bytes from a packet dictionary.
    Prefers the 'frame_raw' field when present; otherwise attempts
    to reconstruct the frame from individual protocol layer fields.
    Returns None when extraction or reconstruction fails.
    """
    try:
        layers = packet_dict["_source"]["layers"]
    except Exception:
        print("⚠️ Missing _source.layers in packet")
        return None

    frame_raw = layers.get("frame_raw")
    if frame_raw:
        try:
            if isinstance(frame_raw, list):
                frame_raw = frame_raw[0]
            return bytes.fromhex(frame_raw)
        except Exception as e:
            print(f"⚠️ Error converting frame_raw to bytes: {e}")

    # Reconstruction
    print("ℹ️ Rebuilding frame: no frame_raw present")
    frame = rebuild_frame_from_layers(layers)
    if frame:
        return frame

    print("❌ Could not rebuild frame, packet skipped")
    return None


def inject_packet_to_tap(packet_dict, tap_fd: int):
    """
    Writes an Ethernet frame into a TAP interface using its file descriptor.
    Uses direct write operations to avoid limitations of raw sockets or Scapy.
    Skips packets that do not yield valid frame bytes.
    """
    frame_bytes = extract_frame_bytes(packet_dict)
    if not frame_bytes:
        return

    try:
        os.write(tap_fd, frame_bytes)
    except OSError as e:
        print(f"❌ Error writing frame to TAP fd={tap_fd}: {e}")



def main():
    """
    Initializes MongoDB, Kafka, TAP interface, and Snort live mode.
    Spawns background workers for alert tailing and packet injection.
    Consumes NDJSON packet streams from Kafka and forwards them to TAP.
    Ensures graceful cleanup of resources on exit.
    """

    mongo_uri = os.getenv("MONGO_URI", "mongodb://admin:admin123@mongodb:27017/")
    try:
        client = MongoClient(mongo_uri)
        db = client["snort_db"]
        alerts_collection = db["alerts"]

        existing_indexes = alerts_collection.index_information()
        if "timestamp_1" not in existing_indexes:
            try:
                alerts_collection.create_index(
                    [("timestamp", 1), ("msg", 1), ("src_ap", 1)],
                    unique=True
                )
                print("✅ Unique index created on fields 'timestamp, msg, src_ap'")
            except errors.OperationFailure as e:
                print(f"⚠️ Could not create unique index: {e}")
        else:
            print("ℹ️ Unique index already exists on ('timestamp','msg','src_ap').")
    except Exception as e:
        print(f"❌ Error connecting to MongoDB: {e}")
        alerts_collection = None


    kafka_producer = KafkaAlertProducer(
        topic=KAFKA_TOPIC_OUT,
        bootstrap=get_bootstrap()
    )

    tap_fd = open_tap_interface(TAP_IFACE)

    truncate_alert_file(ALERT_PATH)

    snort_proc = start_snort_live(TAP_IFACE)

    threading.Thread(
        target=alerts_tail_loop,
        args=(ALERT_PATH, kafka_producer, alerts_collection),
        daemon=True
    ).start()

    consumer = KafkaLineConsumer(
        topic=KAFKA_TOPIC_IN,
        message_field="_source",
        group_id=KAFKA_GROUP_ID,
        bootstrap=get_bootstrap()
    )

    print("📥 Starting Kafka consume loop (network traces) -> TAP interface.")
    for msg, line in consumer.iter_records():
        if not line:
            consumer.commit_msg(msg)
            continue

        line = line.strip()
        try:
            packet_dict = json.loads(line)
        except json.JSONDecodeError:
            # Corrupted line -> jumping
            consumer.commit_msg(msg)
            continue

        # Injecting directly into the TAP interface
        inject_packet_to_tap(packet_dict, tap_fd)

        consumer.commit_msg(msg)

    try:
        snort_proc.terminate()
    except Exception:
        pass

    try:
        os.close(tap_fd)
    except Exception:
        pass


if __name__ == "__main__":
    main()
