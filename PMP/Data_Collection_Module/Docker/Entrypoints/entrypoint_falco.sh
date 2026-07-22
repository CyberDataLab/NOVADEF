#!/bin/sh

echo "Starting Falco..."

# -U (unbuffered): without it, Falco batches file_output writes in an
# internal buffer and only flushes periodically, so a written event can sit
# unflushed for several seconds before Filebeat can see the new bytes on
# disk — confirmed by comparing a Falco event's own evt.time against the
# falco_events.json file's own mtime for that write (mtime lagged evt.time
# by ~13s in a low-traffic test). This is on top of, and independent from,
# the per-message Kafka consumer batching fix in alert_manager.py — that fix
# addressed serialized processing of an already-flushed event backlog, this
# one addresses the write itself not reaching disk promptly.
exec /usr/bin/falco \
  -U \
  -A \
  -c /etc/falco.yaml \
  -r /etc/falco_rules.yaml \

