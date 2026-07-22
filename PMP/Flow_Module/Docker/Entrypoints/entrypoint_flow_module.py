import json
import os
from pathlib import Path
import subprocess
import threading
from Scripts.kafka_io import KafkaLineConsumer, KafkaCSVProducer, get_bootstrap
from queue import Queue, Empty, Full
import time
from pymongo import MongoClient, errors
import csv
import datetime as dt
import hashlib

# === KAFKA CONFIG ===
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "flow-module-v1")
KAFKA_TOPIC_IN = os.getenv("KAFKA_TOPIC_IN", "tshark_traces")
KAFKA_TOPIC_OUT = os.getenv("KAFKA_TOPIC_OUT", "cic_flow")

# === INTERNAL CONFIG ===
FFD = Path(__file__).resolve().parent  # Flow_Module Folder Directory
OUTPUT_DIR = str(FFD / "Scripts" / "Parsing" / "PCAP_Files")
CIC_Results = str(FFD / "Results" / "Flows")
CIC_LAUNCHER = str(FFD / "Preinstall" / "CICFlowMeter" / "launch_cfm.sh")
J2P_PATH = str(FFD / "Scripts" / "Parsing" / "JSON2PCAP" / "json2pcap.py")

# === ROTATION ===
PCAP_ROTATE_SIZE_MB = 100 * 1024     # 100 KB
CIC_ROTATE_SIZE_MB = 50 * 1024           # 50 KB
# 0.5s produced near-empty pcaps too small for CICFlowMeter to derive any
# flow (a TCP flow needs more than a handful of packets in the window), so it
# silently emitted an empty CSV every rotation. 3s gives each pcap enough
# wall-clock time to contain a meaningful traffic window while keeping
# rotation latency low enough for near-real-time detection. (_new_file() now
# finalizes/analyzes the old file on a background thread — see below — so
# this interval no longer blocks packet writing to the new file.)
ROTATE_TIME_SEC = 3.0
# === WRITER CONTROL ===
# Each queued item is a full tshark packet dict WITH hex dump (-x), which can
# be several KB each. 100000 of those is 1-2GB+ in the worst case — exactly
# what OOM-killed the container when a Kafka consumer-group backlog (e.g. from
# a previous test run never fully drained) gets replayed at ingest speed on
# startup, far faster than json2pcap/CICFlowMeter can drain the queue. 5000 is
# enough buffer for normal bursts while capping worst-case memory in the tens
# of MB range instead of GB.
PACKET_QUEUE_MAX = 5000
WRITER_FLUSH_EVERY = 100                 # flush cada N
WATCHDOG_STALL_SECS = 120                # watchdog de inactividad


class CICWorker:
    """
    Manages the execution of CICFlowMeter and global CSV rotation.
    """
    def __init__(self, cic_results, rotate_size_mb, c2k_producer, db_collection):
        self.cic_results = cic_results
        self.rotate_size = rotate_size_mb
        self.file_index = 0
        self.c2k_producer = c2k_producer
        # Guards self.global_csv/self.file_index, which are shared mutable
        # state across concurrent run_cic_on_pcap() threads (one per pcap
        # rotation) — everything else in that method now uses a
        # per-invocation temp file instead of a shared one (see there).
        self._global_csv_lock = threading.Lock()
        self.global_csv = os.path.join(self.cic_results, f"flow_global_{self.file_index:02d}.csv")
        self.flow_collection = db_collection
        # Every pcap rotation (every ROTATE_TIME_SEC=3s) spawns its own
        # daemon thread that runs a fresh CICFlowMeter JVM process to
        # completion — with NO cap on how many of those can be running at
        # once. Each JVM start + pcap parse routinely takes longer than the
        # 3s rotation interval under real traffic, so instances piled up
        # completely unbounded: observed 98 processes / 230% CPU in this
        # container at idle, all fighting for the same CPU, which is what
        # actually produced the "silence for ~40s, then a burst of 8+ pcaps
        # finishing in the same instant" pattern — CPU contention, not I/O
        # contention on a shared file (that part was already fixed by giving
        # each invocation its own temp CSV). Cap it at 2 concurrent
        # CICFlowMeter processes: enough to absorb one rotation finishing
        # slightly late without stalling the next one, but bounded so the
        # queue-of-JVMs effect can't happen again.
        self._cic_concurrency = threading.Semaphore(2)

    def _rotate_global(self):
        """
        Rotation of global CSV when it exceeds a file size.
        """
        if os.path.exists(self.global_csv) and os.path.getsize(self.global_csv) >= self.rotate_size:
            print(f"♻️ Rotating global CSV: {self.global_csv}")
            os.remove(self.global_csv)
            if self.file_index <= 5:
                self.file_index += 1
            else:
                self.file_index = 0
            self.global_csv = os.path.join(self.cic_results, f"flow_global_{self.file_index:02d}.csv")

    def run_cic_on_pcap(self, pcap_path):
        """
        Run CICFlowMeter in a separate thread on a rotated PCAP.
        Save the flows in the historical database.
        [OPTIONAL] Publish in Kafka topic the flows.
        """
        # Each rotation (every ROTATE_TIME_SEC=3s) spawns its OWN daemon thread
        # running this method concurrently with any prior rotation's thread
        # still in flight — _new_file()/close() never wait for the previous
        # CICFlowMeter run to finish before starting the next one. Under
        # attack-level traffic a single pcap can take longer than 3s for
        # CICFlowMeter to process, so multiple instances end up running at
        # once. They used to all target the SAME self.tmp_csv: whichever
        # instance finished first would read/rotate/clear that file out from
        # under the others mid-write, corrupting output and serializing the
        # threads on that shared file's I/O — this is what caused an
        # observed ~40s stall where nothing rotated, followed by 8+ pcaps'
        # worth of flows all appearing to finish in the same instant once
        # unblocked (they'd been queued behind the shared-file contention,
        # not actually taking 40s each). A per-invocation temp file (keyed on
        # the source pcap's own name, which the rotation logic already makes
        # unique) removes that shared mutable state entirely.
        tmp_csv = os.path.join(self.cic_results, f"flow_tmp_{os.path.basename(pcap_path)}.csv")
        CICFLOWMETER_COMMAND = [CIC_LAUNCHER, pcap_path, tmp_csv]
        # Cap concurrent CICFlowMeter (JVM) processes at 2 — see the
        # semaphore's own comment in __init__ for why this is needed. A
        # rotation that arrives while 2 are already running blocks HERE
        # (before spawning a 3rd JVM) instead of piling on unbounded CPU
        # contention; it resumes as soon as one of the two finishes.
        with self._cic_concurrency:
            print(f"⚡ Running CICFlowMeter in {pcap_path}")
            proc = subprocess.Popen(
                CICFLOWMETER_COMMAND,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            '''Only for debugging
            def log_output(stream, prefix):
                for line in stream:
                    print(f"[{prefix}] {line.strip()}")

            threading.Thread(target=log_output, args=(proc.stdout, f"CIC-out-{os.path.basename(pcap_path)}"), daemon=True).start()
            threading.Thread(target=log_output, args=(proc.stderr, f"CIC-err-{os.path.basename(pcap_path)}"), daemon=True).start()
            '''
            proc.wait()
            print(f"✅ CICFlowMeter ended with  {pcap_path}")

        try:
            if not os.path.exists(tmp_csv):
                print(f"⚠️ Flow file not found: {tmp_csv}")
                return

            # Global CSV rotation/append still needs to be serialized across
            # threads (self.global_csv/self.file_index are shared state),
            # unlike the per-invocation tmp_csv, which is only ever touched
            # by this one thread.
            with self._global_csv_lock:
                with open(tmp_csv, "r") as tmpf:
                    lines = tmpf.readlines()

                if not lines:
                    print(f"⚠️ Temporary CSV file empty for  {pcap_path}")
                    return

                header, data = lines[0], lines[1:]
                self._rotate_global()
                if not os.path.exists(self.global_csv):
                    with open(self.global_csv, "w") as gf:
                        gf.write(header)

                with open(self.global_csv, "a") as gf:
                    gf.writelines(data)

                print(f"📊 {len(data)} flows added to {self.global_csv}")

            # Publicar flujos en Kafka como JSON (Logstash → OpenSearch → Grafana)
            if data and header:
                import io
                reader = csv.DictReader(io.StringIO("".join([header] + data)))
                json_lines = []
                for row in reader:
                    doc = {k.strip(): v.strip() for k, v in row.items() if k}
                    doc["@timestamp"] = doc.get("timestamp", "")
                    doc["kafka_topic"] = "cic_flow"
                    json_lines.append(json.dumps(doc, ensure_ascii=False))
                if json_lines:
                    self.c2k_producer.produce_lines(json_lines)
                    print(f"📤 {len(json_lines)} flujos publicados en Kafka (cic_flow)")

            self._insert_flows_to_mongo(tmp_csv, pcap_path)
        finally:
            # Per-invocation temp file — nothing else references it, so it
            # must be cleaned up here instead of relying on a shared file
            # that outlived (or was reused across) multiple runs.
            try:
                os.remove(tmp_csv)
            except Exception:
                pass

    def _insert_flows_to_mongo(self, tmp_csv: str, pcap_path: str) -> None:
        def _smart_cast(val: str):
            """
            Assign the correct format to the different types of data that appear in the streams.

            1) int: avoid converting IPs with dots to float
            2) float: discard IP values such as ‘10.0.2.15’ that have multiple dots
            3) datetime
            """
            if val is None:
                return None
            s = val.strip()
            if s == "":
                return None
            # int
            try:
                if s.lstrip("-").isdigit():
                    return int(s)
            except Exception:
                pass
            # float
            try:
                if s.count(".") <= 1:
                    return float(s)
            except Exception:
                pass
            # datetime
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
                try:
                    return dt.datetime.strptime(s, fmt)
                except Exception:
                    pass
            return s

        inserted, duplicates, _errors = 0, 0, 0

        docs = []
        with open(tmp_csv, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # convert types
                doc = { (k.strip() if k else k): _smart_cast(v) for k, v in row.items() }
                # Create a stable _id from the entire line to avoid duplicates
                raw_line = ",".join(row.get(k, "") for k in reader.fieldnames)
                doc["_id"] = hashlib.md5(raw_line.encode("utf-8")).hexdigest()
                docs.append(doc)

        if not docs:
            print(f"⚠️ File {tmp_csv} empty")
            return

        try:
            self.flow_collection.insert_many(docs, ordered=False)
            inserted = len(docs)
        except errors.BulkWriteError as bwe:
            for err in bwe.details.get("writeErrors", []):
                if err.get("code") == 11000: #Code 11000
                    duplicates += 1
                else:
                    _errors += 1
        except errors.ServerSelectionTimeoutError:
            print("❌ MongoDB connection timeout. Retrying later...")
            _errors = len(docs)
        except Exception as e:
            print(f"❌ Error inserting flows: {e}")
            _errors = len(docs)

        print(f"✅ Inserted {inserted} new flows, skipped {duplicates} duplicates and errors {_errors}.")



class Json2PcapWorker:
    """JSON2PCAP process to parse JSON -> PCAP"""
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
        cmd = ["python3", self.j2p_path, "-i", "-o", self.trace_path]
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
            print(f"[json2pcap] {line.strip()}")

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
    Manage file rotation and launch CICFlowMeter at each rotation (with queue and backoff).
    """
    def __init__(self, output_dir, cic_results, j2p_path, rotate_size_mb, cic_rotate_size_mb, c2k_producer, db_collection):
        self.output_dir = output_dir
        self.j2p_path = j2p_path
        self.rotate_size = rotate_size_mb
        self.file_index = 0
        self.j2p_worker = None
        self.cic_worker = CICWorker(cic_results, cic_rotate_size_mb, c2k_producer, db_collection)
        os.makedirs(output_dir, exist_ok=True)

        self.q = Queue(maxsize=PACKET_QUEUE_MAX)
        self._last_write_ts = time.time()
        self._last_file_ts = time.time()
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
        Thread that writes packets to json2pcap and rotates per time or size if necessary.
        """
        while self._running:
            # Rotation per time
            if time.time() - self._last_file_ts >= ROTATE_TIME_SEC:
                self._new_file()
                self._last_file_ts = time.time()

            try:
                packet_dict, ack_fn = self.q.get(timeout=0.1)
            except Empty:
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

                # Rotation per size
                if os.path.exists(trace_file) and os.path.getsize(trace_file) >= self.rotate_size:
                    self._new_file()
                    self._last_file_ts = time.time()

 
                if ack_fn:
                    try:
                        ack_fn()
                    except Exception as e:
                        print(f"⚠️ Error in ack_fn: {e}")

            except Exception as e:
                print(f"❌ Error in writer_loop: {e}")


    def _new_file(self):
        """
        Creates the JSON2PCAP stream, as well as a new PCAP file.
        If one is already open, it closes it and launches CICFlowMeter on it
        using a background thread.
        """
        if self.j2p_worker:
            old_worker = self.j2p_worker
            old_trace = old_worker.trace_path
            # close() (flush + wait for json2pcap to finish writing the pcapng)
            # and the CICFlowMeter analysis both need to happen BEFORE the file
            # is deleted, and close() must finish before CICFlowMeter reads the
            # file — otherwise CICFlowMeter reads a truncated pcapng (missing
            # json2pcap's closing "]") and silently emits an empty CSV, starving
            # the network detector of that traffic window.
            #
            # But neither step may run on the writer thread itself: close()
            # calls proc.wait() which can take real wall-clock time, and during
            # that time _writer_loop must keep draining self.q (100k slots) or
            # the queue fills with buffered packets faster than Kafka intake can
            # be throttled — that queue backlog is what was OOM-killing the
            # container. So both close() and the CIC analysis run together,
            # strictly sequential, in a single background thread — never
            # blocking the writer loop that owns the NEW json2pcap process.
            def _finalize_and_analyze():
                old_worker.close()
                self._run_cic_and_delete(old_trace)
            threading.Thread(target=_finalize_and_analyze, daemon=True).start()

        trace_path = os.path.join(self.output_dir, f"trace_{self.file_index:02d}.pcapng")
        print(f"📂 New file opened: {trace_path}")
        self.j2p_worker = Json2PcapWorker(trace_path, self.j2p_path)

        if self.file_index < 99:
            self.file_index += 1
        else:
            self.file_index = 0

        self._last_file_ts = time.time()

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
            threading.Thread(target=self._run_cic_and_delete, args=(old_trace,), daemon=True).start()
            self._running = False

    def _run_cic_and_delete(self, old_trace):
        """
        Start CICFlowMeter to analyse the network traces.
        Delete the PCAP file when finished with it.
        """
        self.cic_worker.run_cic_on_pcap(old_trace)
        try:
            os.remove(old_trace)
            print(f"✅ File {old_trace} uccessfully deleted")
        except Exception as e:
            print(f"❌ Error deleting {old_trace}: {e}")


def sanitize_packet_timestamp(packet_dict):
    """
    Search for the frame.time_epoch field. If it is an ISO 8601 string, convert it to float (Epoch timestamp).
    """
    try:
        # _source -> layers -> frame -> frame.time_epoch
        layers = packet_dict.get('_source', {}).get('layers', {})
        frame = layers.get('frame', {})
        
        raw_time = frame.get('frame.time_epoch')
        
        if raw_time and isinstance(raw_time, str) and 'T' in raw_time and 'Z' in raw_time:

            clean_str = raw_time.replace('Z', '')[:26]
            

            dt_obj = dt.datetime.strptime(clean_str, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=dt.timezone.utc)
            
            epoch_val = dt_obj.timestamp()
            
            frame['frame.time_epoch'] = str(epoch_val)
            
    except Exception as e:

        print(f"⚠️ Warning sanitizing timestamp: {e}")

def main():

    mongo_uri = os.getenv("MONGO_URI", "mongodb://admin:admin123@mongodb:27017/")
    client = MongoClient(mongo_uri)
    db = client["flow_db"]
    flow_collection = db["flows"]

    producer = KafkaCSVProducer(
        topic=KAFKA_TOPIC_OUT,
        bootstrap=get_bootstrap()
    )

    writer = PacketWriter(
        output_dir=OUTPUT_DIR,
        cic_results=CIC_Results,
        j2p_path=J2P_PATH,
        rotate_size_mb=PCAP_ROTATE_SIZE_MB,
        cic_rotate_size_mb=CIC_ROTATE_SIZE_MB,
        c2k_producer=producer,
        db_collection=flow_collection
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
            consumer.commit_msg(msg)
            continue

        sanitize_packet_timestamp(packet_dict)

        writer.enqueue_packet(
            packet_dict,
            ack_fn=lambda m=msg: consumer.commit_msg(m)
        )

    writer.close()


if __name__ == "__main__":
    main()
