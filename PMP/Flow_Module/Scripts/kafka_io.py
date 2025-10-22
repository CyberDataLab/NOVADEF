# kafka_io_v2.py
# ------------------------------------------------------------
# Utilidades Kafka para integrarse con tu pipeline:
# - KafkaLineConsumer: entrega líneas tipo "tshark" desde un topic.
# - KafkaCSVProducer: publica líneas de un CSV a un topic.
# ------------------------------------------------------------

import os
import sys
import json
import signal
import argparse
from typing import Generator, Optional, Iterable, Tuple

from confluent_kafka import (
    Consumer as _KafkaConsumer,
    Producer as _KafkaProducer,
    KafkaException,
    KafkaError,
)

# -----------------------------
# Defaults (configurables por env)
# -----------------------------

def get_bootstrap(override: Optional[str] = None) -> str:
    """
    Orden de resolución:
    1) argumento explícito (override),
    2) env KAFKA_BOOTSTRAP,
    3) default "kafkakafka_novadef:29092" (mejor dentro de Docker).
    """
    if override:
        return override
    return os.getenv("KAFKA_BOOTSTRAP", "kafkakafka_novadef:29092")

DEFAULT_TOPIC_IN = os.getenv("KAFKA_TOPIC_IN", "tshark_traces")
DEFAULT_TOPIC_OUT = os.getenv("KAFKA_TOPIC_OUT", "cic_flow")
DEFAULT_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "net-traces-consumer")
DEFAULT_MESSAGE_FIELD = os.getenv("KAFKA_MESSAGE_FIELD", "_source")

# Consumer behavior
DEFAULT_AUTO_OFFSET_RESET = os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest")  # earliest/latest/none
DEFAULT_ENABLE_AUTO_COMMIT = os.getenv("KAFKA_ENABLE_AUTO_COMMIT", "true").lower() == "true"
DEFAULT_ASSIGNMENT_STRATEGY = os.getenv("KAFKA_PARTITION_ASSIGNMENT_STRATEGY", "cooperative-sticky")
DEFAULT_ENABLE_PARTITION_EOF = os.getenv("KAFKA_ENABLE_PARTITION_EOF", "true").lower() == "true"
DEFAULT_ALLOW_AUTO_CREATE_TOPICS = os.getenv("KAFKA_ALLOW_AUTO_CREATE_TOPICS", "true").lower() == "true"

# Producer behavior
DEFAULT_LINGER_MS = int(os.getenv("KAFKA_PRODUCER_LINGER_MS", "5"))
DEFAULT_BATCH_SIZE = int(os.getenv("KAFKA_PRODUCER_BATCH_SIZE", "32768"))  # ~32 KB
DEFAULT_COMPRESSION = os.getenv("KAFKA_PRODUCER_COMPRESSION", "zstd")  # zstd, lz4, gzip, snappy, none


def _kafka_consumer_config(bootstrap: Optional[str], group_id: Optional[str], debug: Optional[str] = None) -> dict:
    """
    Config típica de consumer para single-broker KRaft con grupos.
    """
    cfg = {
        "bootstrap.servers": get_bootstrap(bootstrap),
        "group.id": group_id or DEFAULT_GROUP_ID,
        "enable.auto.commit": DEFAULT_ENABLE_AUTO_COMMIT,
        "auto.offset.reset": DEFAULT_AUTO_OFFSET_RESET,
        "allow.auto.create.topics": DEFAULT_ALLOW_AUTO_CREATE_TOPICS,
        "enable.partition.eof": DEFAULT_ENABLE_PARTITION_EOF,
        "partition.assignment.strategy": DEFAULT_ASSIGNMENT_STRATEGY,
        # --- ajustes para ráfagas ---
        "fetch.min.bytes": 1048576,            # 1 MiB antes de devolver
        "fetch.wait.max.ms": 50,               # espera hasta 50 ms para llenar batch
        "queued.max.messages.kbytes": 262144,  # 256 MiB de cola interna
        "max.poll.interval.ms": 900000,        # 15 min para procesados pesados
        "session.timeout.ms": 10000,
        "socket.keepalive.enable": True,
    }
    if debug:
        cfg["debug"] = debug  # ej: "cgrp,topic,fetch,protocol"
    return cfg


def _kafka_producer_config(bootstrap: Optional[str], debug: Optional[str] = None) -> dict:
    cfg = {
        "bootstrap.servers": get_bootstrap(bootstrap),
        "linger.ms": DEFAULT_LINGER_MS,
        "batch.num.messages": 10000,
        "batch.size": DEFAULT_BATCH_SIZE,
        "compression.type": DEFAULT_COMPRESSION,
        "socket.keepalive.enable": True,
        # "acks": "all",
    }
    if debug:
        cfg["debug"] = debug  # ej: "msg"
    return cfg


class KafkaLineConsumer:
    """
    Consumer orientado a leer documentos JSON (Filebeat) y extraer el campo '_source'.
    Usa consumer groups (subscribe + coordinator).
    """
    def __init__(
        self,
        topic: str = DEFAULT_TOPIC_IN,
        message_field: str = DEFAULT_MESSAGE_FIELD,
        poll_timeout: float = 1.0,
        group_id: Optional[str] = None,
        bootstrap: Optional[str] = None,
        debug: Optional[str] = None,
    ):
        self.topic = topic
        self.message_field = message_field
        self.poll_timeout = poll_timeout
        self._closing = False

        cfg = _kafka_consumer_config(bootstrap, group_id, debug)
        self._consumer = _KafkaConsumer(cfg)

        strategies = str(cfg.get("partition.assignment.strategy", "")).lower()
        self._is_cooperative = "cooperative-sticky" in strategies

        def _on_assign(consumer, partitions):
            pretty = [f"{p.topic}[{p.partition}]@{p.offset}" for p in partitions]
            if self._is_cooperative:
                print(f"📌 (coop) Añadiendo: {pretty}", flush=True)
                consumer.incremental_assign(partitions)
            else:
                print(f"📌 Asignado a: {pretty}", flush=True)
                consumer.assign(partitions)

        def _on_revoke(consumer, partitions):
            pretty = [f"{p.topic}[{p.partition}]@{p.offset}" for p in partitions]
            if self._is_cooperative:
                print(f"↩️  (coop) Revocando: {pretty}", flush=True)
                consumer.incremental_unassign(partitions)
            else:
                print(f"↩️  Revocado: {pretty}", flush=True)
                consumer.unassign()

        self._consumer.subscribe([self.topic], on_assign=_on_assign, on_revoke=_on_revoke)

    # Señales de cierre limpio
    def _trap_signals(self):
        def _sig_handler(signum, frame):
            print("\n🛑 Señal recibida, cerrando consumer…", flush=True)
            self._closing = True
        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)

    def _extract_line(self, payload: bytes) -> Optional[str]:
        """
        Intenta parsear JSON y extraer el campo configurado (por defecto '_source').
        Siempre devuelve una cadena JSON serializada y, si el campo es '_source',
        re-envuelve en {"_source": ...} para que json2pcap encuentre layers.frame_raw.
        """
        try:
            txt = payload.decode("utf-8", errors="replace")
        except Exception:
            return None

        # Si no parece JSON, devolvemos el texto tal cual
        if not txt or not txt.lstrip().startswith("{"):
            return txt

        try:
            obj = json.loads(txt)
        except Exception:
            # No se pudo parsear JSON, devolvemos el texto original
            return txt

        # 1) Caso normal: el mensaje trae el campo configurado
        if self.message_field in obj:
            val = obj[self.message_field]

            # Si el campo es "_source", aseguramos la envoltura {"_source": ...}
            if self.message_field == "_source":
                # Si ya viene como dict, lo re-envolvemos; si es string, intentamos parsearlo
                if isinstance(val, str):
                    try:
                        val_obj = json.loads(val)
                    except Exception:
                        # No es JSON válido, así que lo metemos como texto bajo _source_raw
                        return json.dumps({"_source": {"_source_raw": val}}, ensure_ascii=False)
                else:
                    val_obj = val

                # Si lo que hay dentro NO es un dict, lo guardamos crudo
                if not isinstance(val_obj, dict):
                    return json.dumps({"_source": {"_source_raw": val_obj}}, ensure_ascii=False)

                # En este punto devolvemos SIEMPRE {"_source": <dict>}
                return json.dumps({"_source": val_obj}, ensure_ascii=False)

            # 2) Para cualquier otro message_field, siempre texto JSON
            return val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)

        # 3) Fallback: algunos productores mandan "layers" en la raíz → lo envolvemos como _source
        if isinstance(obj, dict) and "layers" in obj:
            return json.dumps({"_source": {"layers": obj["layers"]}}, ensure_ascii=False)

        # 4) Si nada de lo anterior aplica, devolvemos el JSON original en texto
        return txt

    def iter_lines(self) -> Generator[str, None, None]:
        """Itera sólo la línea decodificada (para casos simples)."""
        self._trap_signals()
        while not self._closing:
            try:
                msg = self._consumer.poll(self.poll_timeout)
                if msg is None:
                    continue
                if msg.error():
                    err = msg.error()
                    if err.code() == KafkaError._PARTITION_EOF:
                        if DEFAULT_ENABLE_PARTITION_EOF:
                            print(f"ℹ️  EOF {msg.topic()}[{msg.partition()}] offset {msg.offset()}", flush=True)
                        continue
                    print(f"⚠️  Error consumer: {err}", flush=True)
                    continue

                line = self._extract_line(msg.value())
                if line is not None:
                    yield line
                    if not DEFAULT_ENABLE_AUTO_COMMIT:
                        try:
                            self._consumer.commit(asynchronous=True)
                        except KafkaException as ke:
                            print(f"⚠️  Commit error: {ke}", flush=True)
            except KeyboardInterrupt:
                break
            except KafkaException as ke:
                print(f"❌ KafkaException: {ke}", flush=True)
            except Exception as ex:
                print(f"❌ Exception: {ex}", flush=True)

        self.close()

    def iter_records(self) -> Generator[Tuple[object, Optional[str]], None, None]:
        """Como iter_lines(), pero rinde (msg, line) para poder hacer commit tras procesar."""
        self._trap_signals()
        while not self._closing:
            try:
                msg = self._consumer.poll(self.poll_timeout)
                if msg is None:
                    continue
                if msg.error():
                    err = msg.error()
                    if err.code() == KafkaError._PARTITION_EOF:
                        if DEFAULT_ENABLE_PARTITION_EOF:
                            print(f"ℹ️  EOF {msg.topic()}[{msg.partition()}] offset {msg.offset()}", flush=True)
                        continue
                    print(f"⚠️  Error consumer: {err}", flush=True)
                    continue
                line = self._extract_line(msg.value())
                yield (msg, line)
            except KeyboardInterrupt:
                break
            except KafkaException as ke:
                print(f"❌ KafkaException: {ke}", flush=True)
            except Exception as ex:
                print(f"❌ Exception: {ex}", flush=True)
        self.close()

    def commit_msg(self, msg):
        """Commit fuerte del mensaje procesado."""
        try:
            self._consumer.commit(message=msg, asynchronous=False)
        except KafkaException as ke:
            print(f"⚠️  Commit error: {ke}", flush=True)

    def close(self):
        try:
            self._consumer.close()
        except Exception:
            pass


class KafkaCSVProducer:
    """Producer para publicar líneas (p. ej. CSV ya generado por un módulo principal)."""
    def __init__(self, topic: str = DEFAULT_TOPIC_OUT, bootstrap: Optional[str] = None, debug: Optional[str] = None):
        self.topic = topic
        cfg = _kafka_producer_config(bootstrap, debug)
        self._producer = _KafkaProducer(cfg)

    def _delivery_cb(self, err, msg):
        if err is not None:
            print(f"❌ Delivery failed: {err}", flush=True)

    def produce_lines(self, lines: Iterable[str]):
        for line in lines:
            data = line if isinstance(line, (bytes, bytearray)) else line.encode("utf-8", errors="replace")
            self._producer.produce(self.topic, value=data, on_delivery=self._delivery_cb)
            self._producer.poll(0)  # sirve callbacks
        self._producer.flush()


# -----------------------------
# CLI
# -----------------------------

def _cmd_consume(args: argparse.Namespace):
    print(
        f"🚀 Consumiendo desde '{args.topic}' en {get_bootstrap(args.bootstrap)}"
        f" (group: {args.group_id or DEFAULT_GROUP_ID})  Ctrl+C para salir",
        flush=True,
    )

    consumer = KafkaLineConsumer(
        topic=args.topic,
        message_field=args.message_field,
        group_id=args.group_id,
        bootstrap=args.bootstrap,
        debug=args.debug,
    )

    try:
        for line in consumer.iter_lines():
            if not args.quiet:
                sys.stdout.write(line + ("\n" if not line.endswith("\n") else ""))
                sys.stdout.flush()
    finally:
        consumer.close()


def _cmd_produce(args: argparse.Namespace):
    print(f"📤 Publicando CSV '{args.csv}' a topic '{args.topic}' en {get_bootstrap(args.bootstrap)}", flush=True)
    if not os.path.exists(args.csv):
        print(f"❌ No existe el fichero: {args.csv}", flush=True)
        sys.exit(2)

    prod = KafkaCSVProducer(topic=args.topic, bootstrap=args.bootstrap, debug=args.debug)

    with open(args.csv, "rb") as f:
        prod.produce_lines(f)

    print("✅ Envío completado", flush=True)


def _make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kafka_io_v2.py", description="Herramientas Kafka para trazas y CSV.")
    p.add_argument("--bootstrap", default=None, help=f"bootstrap.servers (default: {get_bootstrap()})")
    p.add_argument("--debug", default=None, help="flags de debug de librdkafka (ej: cgrp,topic,fetch,protocol)")

    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("consume", help="Consume de un topic y saca el campo '_source' si existe")
    pc.add_argument("--topic", default=DEFAULT_TOPIC_IN, help="Topic a consumir")
    pc.add_argument("--group-id", default=None, help=f"Consumer group id (default: {DEFAULT_GROUP_ID})")
    pc.add_argument("--message-field", default=DEFAULT_MESSAGE_FIELD, help="Campo JSON a extraer")
    pc.add_argument("--quiet", action="store_true", help="No imprimir las líneas (útil para probar suscripción)")
    pc.set_defaults(func=_cmd_consume)

    pp = sub.add_parser("produce", help="Publica un CSV (línea a línea) en un topic")
    pp.add_argument("--topic", default=DEFAULT_TOPIC_OUT, help="Topic destino")
    pp.add_argument("--csv", required=True, help="Ruta del CSV a publicar")
    pp.set_defaults(func=_cmd_produce)

    return p


def main():
    parser = _make_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
