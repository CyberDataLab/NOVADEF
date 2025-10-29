import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from kafka_io import KafkaLineConsumer, KafkaAlertProducer, get_bootstrap
from queue import Queue, Empty, Full
from pymongo import MongoClient, errors

# === FILE CONFIG ===
PFD = Path(__file__).resolve().parent #/home/Alert_Module in container

OUTPUT_DIR = str(PFD / "Parsing" / "PCAP_Files")
J2P_PATH = str(PFD / "Parsing" / "JSON2PCAP" /"json2pcap.py")

SNORT_CONFIG_DIR = PFD / "Snort_configuration"
SNORT_LUA = str(SNORT_CONFIG_DIR / "lua" / "snort.lua")
SNORT_RULES = str(SNORT_CONFIG_DIR / "Rules" / "alert_rules.rules")
ALERT_DIR = str(PFD / "Alerts")
ALERT_FILE = "alert_json"

# === KAFKA CONFIG ===
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "alert-module-v1")
KAFKA_TOPIC_IN = os.getenv("KAFKA_TOPIC_IN", "tshark_traces")
KAFKA_TOPIC_OUT = os.getenv("KAFKA_TOPIC_OUT", "snort_alerts")

# === ROTATION ===
PCAP_ROTATE_SIZE_MB = 2 * 1024 * 1024   # 200 MB
ALERT_ROTATE_SIZE_MB = 200 * 1024       #* 1024 # 200KB


# === WRITER CONTROL ===
PACKET_QUEUE_MAX = 100000 # Queue limit
WRITER_FLUSH_EVERY = 100  # flush every packet number
WATCHDOG_STALL_SECS = 120 # inactivity watchdog

# === SNORT CONFIG ===
SNORT_BASE_CMD = [
    "snort",
    "-c", SNORT_LUA,
    "-R", SNORT_RULES,
    "-A", ALERT_FILE,
    "--lua",
    f"{ALERT_FILE} = {{file = true, fields = 'msg timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action'}}",
    "-l", ALERT_DIR,
    "-k", "none"
 ]


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

def truncate_alert_file(alert_path:str):
    """
    Truncate the alert file to avoid duplicates.
    """
    try:
        with open(alert_path, "w"):
            pass
        print(f"🧹 Truncated {alert_path}")
    except Exception as e:
        print(f"⚠️ Could not truncate {alert_path}: {e}")

def save_to_database(alert_path, alerts_collection):
    """
    Read alerts and upload them to MongoDB
    """ 
    if not os.path.exists(alert_path):
        print(f"⚠️ Alert file not found: {alert_path}")
        return

    with open(alert_path, "r") as data:
        lines = data.readlines()

    if not lines:
        print(f"⚠️ File {alert_path} empty")
        return

    inserted, duplicates, _errors = 0, 0, 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            alert_doc = json.loads(line)
            alerts_collection.insert_one(alert_doc)
            inserted += 1
        except json.JSONDecodeError:
            print(f"⚠️ Error decoding JSON line: {line}")
            _errors += 1
        except errors.DuplicateKeyError:
            duplicates += 1
        except errors.ServerSelectionTimeoutError:
            print("❌ MongoDB connection timeout. Retrying later...")
            _errors += 1
        except Exception as e:
            print(f"❌ Error inserting alert: {e}")
            _errors += 1

    print(f"✅ Inserted {inserted} new alerts, skipped {duplicates} duplicates and errors {_errors}.")

def run_snort_on_pcap(pcap_path, producer, alerts_collection):
    """
    Run Snort3 in a separate thread on a rotated PCAP.
    Publish in Kafka topic the new alerts.
    Save the alerts in the historical database.
    Truncate the file to clean the alert file.
    """
    alert_path = os.path.join(ALERT_DIR,f"{ALERT_FILE}.txt")

    cmd = SNORT_BASE_CMD + ["-r", pcap_path]
    print(f"⚡ Running Snort3 on {pcap_path}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    '''Only for debugging
    def log_output(stream, prefix):
        for line in stream:
            print(f"[{prefix}] {line.strip()}")
    #threading.Thread(target=log_output, args=(proc.stdout, f"snort-out-{os.path.basename(pcap_path)}"), daemon=True).start()
    #threading.Thread(target=log_output, args=(proc.stderr, f"snort-err-{os.path.basename(pcap_path)}"), daemon=True).start()
    '''
    proc.wait()
    print(f"✅ Snort3 ended with {pcap_path}")

    #Read alert_parth and send it directly to Kafka with the producer.
    if os.path.exists(alert_path):
        ensure_mode_644(alert_path)
        with open(alert_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [ln for ln in f if ln.strip()]
        if not lines:
            print(f"ℹ️ No alerts to publish in {alert_path}")
            return
        #Publishing Kafka topic
        try:
            producer.produce_lines(lines)
        except Exception as e:
            print(f"❌ Error publishing to Kafka: {e}")
            return
    
        # Saving in historical database
        if alerts_collection is not None:
            try:
                save_to_database(alert_path=alert_path, alerts_collection=alerts_collection) 
            except Exception as e:
                print(f"❌ Error saving alerts in database: {e}")
                return
        
        truncate_alert_file(alert_path=alert_path)

    else:
        print(f"⚠️ Snort3 did not detect any alerts in {alert_path}")
        
class Json2PcapWorker:
    """
    JSON2PCAP process to parse JSON -> PCAP
    """
    def __init__(self, trace_path, j2p_path):
        self.trace_path = trace_path
        self.j2p_path = j2p_path
        self.proc = None
        self.first_packet = True
        self._start_proc()

    def _start_proc(self):
        """
        Launching JSON2PCAP with data intake via stdin and output to file.
        """
        cmd = [sys.executable, self.j2p_path, "-i", "-o", self.trace_path]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.proc.stdin.write("[")
        self.proc.stdin.flush()
        threading.Thread(target=self._log_stderr, daemon=True).start()

    def _log_stderr(self):
        """
        Provides useful JSON2PCAP error outputs when debugging.
        """
        for line in self.proc.stderr:
            print(f"[JSON2PCAP] {line.strip()}")

    def write_packet(self, packet_dict):
        """
        Writes an object to the JSON array.
        """
        try:
            if not self.first_packet:
                self.proc.stdin.write(",")
            else:
                self.first_packet = False
            json.dump(packet_dict, self.proc.stdin, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error writing to JSON2PCAP: {e}")

    def close(self):
        """
        Close the process and the JSON array.
        """
        try:
            self.proc.stdin.write("]")
            self.proc.stdin.flush()
            self.proc.stdin.close()
        except Exception as e:
            print(f"❌ Error closing stdin: {e}")
        self.proc.wait()


class PacketWriter:
    """
    Manage file rotation and launch Snort at each rotation (with queue and backoff).
    """
    def __init__(self, output_dir, j2p_path, rotate_size_mb, producer, alerts_collection):
        self.output_dir = output_dir
        self.j2p_path = j2p_path
        self.rotate_size = rotate_size_mb
        self.file_index = 0
        self.j2p_worker = None
        self.producer = producer
        self.alerts_collection = alerts_collection
        os.makedirs(output_dir, exist_ok=True)

        self.q = Queue(maxsize=PACKET_QUEUE_MAX)
        self._last_write_ts = time.time()
        self._written_since_flush = 0
        self._running = True
        threading.Thread(target=self._writer_loop, daemon=True).start()

        self._new_file()

    def enqueue_packet(self, packet_dict, ack_fn=None):
        """
        Queue with short retries so as not to block the consumer thread.
        """
        while self._running:
            try:
                self.q.put((packet_dict, ack_fn), timeout=0.1)
                return
            except Full:
                # short backoff; the writer will drain the queue
                pass

    def _writer_loop(self):
        """
        Thread that writes packets to json2pcap and rotates if necessary.
        """
        while self._running:
            try:
                packet_dict, ack_fn = self.q.get(timeout=1)
            except Empty:
                if time.time() - self._last_write_ts > WATCHDOG_STALL_SECS:
                    print("⏱️  Watchdog: no recent writing to PCAP", flush=True)
                continue

            try:
                self.j2p_worker.write_packet(packet_dict)
                self._written_since_flush += 1
                if self._written_since_flush >= WRITER_FLUSH_EVERY:
                    try:
                        self.j2p_worker.proc.stdin.flush()
                    except Exception:
                        pass
                    self._written_since_flush = 0

                trace_file = self.j2p_worker.trace_path
                if os.path.exists(trace_file) and os.path.getsize(trace_file) >= self.rotate_size:
                    self._new_file()

                self._last_write_ts = time.time()

                if ack_fn:
                    try:
                        ack_fn()
                    except Exception as e:
                        print(f"⚠️  Error in ack_fn: {e}", flush=True)
            except Exception as e:
                print(f"❌ Error in writer_loop: {e}", flush=True)

    def _new_file(self):
        """
        Creates the JSON2PCAP stream, as well as a new PCAP file. 
        If one is already open, it closes it and launches Snort on it using new threads.
        """
        if self.j2p_worker:
            old_trace = self.j2p_worker.trace_path
            threading.Thread(target=self.j2p_worker.close, daemon=True).start()
            threading.Thread(target=self._run_snort_and_delete, args=(old_trace,), daemon=True).start()

        trace_path = os.path.join(self.output_dir, f"trace_{self.file_index:02d}.pcapng")
        print(f"📂 New file opened: {trace_path}")
        self.j2p_worker = Json2PcapWorker(trace_path, self.j2p_path)

        if self.file_index < 9:
            self.file_index += 1
        else:
            self.file_index = 0

    def write_packet(self, packet_dict):
        """
        Write the network packet in JSON and rotate the PCAP if it exceeds the size limit.
        """
        self.j2p_worker.write_packet(packet_dict)
        trace_file = self.j2p_worker.trace_path
        if os.path.exists(trace_file) and os.path.getsize(trace_file) >= self.rotate_size:
            self._new_file()

    def close(self):
        """
        Closes the PCAP file and analyses it before it is rotated.
        Used only when the general process is about to be completed and the PCAP size 
        does not reach the limit for rotation.
        """
        if self.j2p_worker:
            old_trace = self.j2p_worker.trace_path
            self.j2p_worker.close()
            threading.Thread(target=self._run_snort_and_delete, args=(old_trace,), daemon=True).start()
            self._running = False

    def _run_snort_and_delete(self, old_trace):
        """
        Start Snort to analyse the network traces.
        Delete the PCAP file when finished with it.
        """
        run_snort_on_pcap(old_trace, self.producer, self.alerts_collection)
        try:
            os.remove(old_trace)
            print(f"✅ File {old_trace} successfully deleted")
        except Exception as e:
            print(f"❌ Error deleting {old_trace}: {e}")


def main():

    mongo_uri = os.getenv("MONGO_URI", "mongodb://admin:admin123@mongodb:27017/")
    client = MongoClient(mongo_uri)
    db = client["snort_db"]
    alerts_collection = db["alerts"]

    existing_indexes = alerts_collection.index_information()
    if "timestamp_1" not in existing_indexes:
        try:
            alerts_collection.create_index([("timestamp", 1), ("msg", 1), ("src_ap", 1)], unique=True)
            print("✅ Unique index created on field 'timestamp'")
        except errors.OperationFailure as e:
            print(f"⚠️ Could not create unique index on 'timestamp': {e}")
    else:
        print("ℹ️ Unique index on 'timestamp' already exists.")

    kafka_producer = KafkaAlertProducer(
        topic=KAFKA_TOPIC_OUT,
        bootstrap=get_bootstrap()
    )

    writer = PacketWriter(
        output_dir=OUTPUT_DIR,
        j2p_path=J2P_PATH,
        rotate_size_mb=PCAP_ROTATE_SIZE_MB,
        producer=kafka_producer,
        alerts_collection = alerts_collection
    )

    consumer = KafkaLineConsumer(
        topic=KAFKA_TOPIC_IN,
        message_field="_source",
        group_id=KAFKA_GROUP_ID,
        bootstrap=get_bootstrap()
    )

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

 
        writer.enqueue_packet(
            packet_dict,
            ack_fn=lambda m=msg: consumer.commit_msg(m)
        )

    writer.close()


if __name__ == "__main__":
    main()

