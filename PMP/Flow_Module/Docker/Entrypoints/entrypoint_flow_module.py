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
ROTATE_SIZE_MB = 2 * 1024 * 1024       # ↑ 200 MB (menos rotaciones bajo ráfagas)
CIC_ROTATE_SIZE_MB = 50 * 1024           # ~50 MB

# === WRITER CONTROL ===
PACKET_QUEUE_MAX = 100000                 # ↑ margen para ráfagas
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
        self.tmp_csv = os.path.join(self.cic_results, "flow_tmp.csv")
        self.global_csv = os.path.join(self.cic_results, f"flow_global_{self.file_index:02d}.csv")
        self.flow_collection = db_collection

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
        CICFLOWMETER_COMMAND = [CIC_LAUNCHER, pcap_path, self.tmp_csv]
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

        if os.path.exists(self.tmp_csv):
            self._rotate_global()
            with open(self.tmp_csv, "r") as tmpf:
                lines = tmpf.readlines()

            if not lines:
                print(f"⚠️ Temporary CSV file empty for  {pcap_path}")
                return

            header, data = lines[0], lines[1:]
            if not os.path.exists(self.global_csv):
                with open(self.global_csv, "w") as gf:
                    gf.write(header)

            with open(self.global_csv, "a") as gf:
                gf.writelines(data)

            print(f"📊 {len(data)} flows added to {self.global_csv}")

        '''
            # Uncomment if you want to publish on Kafka.
            if data:
                self.c2k_producer.produce_lines(data)

        '''

        # Read flows and upload them to MongoDB
        if not os.path.exists(self.tmp_csv):
            print(f"⚠️ Flow file not found: {self.tmp_csv}")
            return

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
        with open(self.tmp_csv, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # convert types
                doc = { (k.strip() if k else k): _smart_cast(v) for k, v in row.items() }
                # Create a stable _id from the entire line to avoid duplicates
                raw_line = ",".join(row.get(k, "") for k in reader.fieldnames)
                doc["_id"] = hashlib.md5(raw_line.encode("utf-8")).hexdigest()
                docs.append(doc)

        if not docs:
            print(f"⚠️ File {self.tmp_csv} empty")
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
            threading.Thread(target=self._run_cic_and_delete, args=(old_trace,), daemon=True).start()

        trace_path = os.path.join(self.output_dir, f"trace_{self.file_index:02d}.pcapng")
        print(f"📂 New file opened: {trace_path}")
        self.j2p_worker = Json2PcapWorker(trace_path, self.j2p_path)

        if self.file_index < 5:
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
        rotate_size_mb=ROTATE_SIZE_MB,
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

        writer.enqueue_packet(
            packet_dict,
            ack_fn=lambda m=msg: consumer.commit_msg(m)
        )

    writer.close()


if __name__ == "__main__":
    main()
