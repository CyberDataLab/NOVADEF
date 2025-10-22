#!/bin/sh

echo "Starting Falco..."

exec /usr/bin/falco \
  -A \
  -c /etc/falco.yaml \
  -r /etc/falco_rules.yaml \

