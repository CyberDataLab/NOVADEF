#!/bin/sh

set -eu

FALCO_BINARY="/usr/bin/falco"
FALCO_CONFIG_PATH="/etc/Falco/falco.yaml"
DEFAULT_FALCO_RULES="/etc/Falco/falco_community_rules.yaml"

build_rule_args() {
  env_value="$1"
  fallback="$2"

  if [ -n "$env_value" ]; then
    current_ifs="$IFS"
    IFS=':'
    set -- $env_value
    IFS="$current_ifs"
  elif [ -n "$fallback" ]; then
    set -- "$fallback"
  else
    set --
  fi

  for rules_path in "$@"; do
    if [ -n "$rules_path" ]; then
      printf '%s\n' "$rules_path"
    fi
  done
}

VALIDATE_MODE=0
if [ "${1:-}" = "--validate" ]; then
  VALIDATE_MODE=1
  shift
fi

set -- "$FALCO_BINARY" -A -c "$FALCO_CONFIG_PATH"

if [ "$VALIDATE_MODE" -eq 0 ]; then
  RULES_PATHS="${FALCO_RULES_PATHS:-$DEFAULT_FALCO_RULES}"
else
  RULES_PATHS="${FALCO_RULES_PATHS:-}"
fi

for rules_path in $(build_rule_args "$RULES_PATHS" ""); do
  set -- "$@" -r "$rules_path"
done

if [ "$VALIDATE_MODE" -eq 1 ]; then
  echo "Validating Falco rules..."
  VALIDATE_PATHS="${FALCO_VALIDATE_PATHS:-}"
  if [ -z "$VALIDATE_PATHS" ]; then
    echo "FALCO_VALIDATE_PATHS must contain at least one path when validation mode is used." >&2
    exit 1
  fi

  for validate_path in $(build_rule_args "$VALIDATE_PATHS" ""); do
    set -- "$@" --validate "$validate_path"
  done
else
  echo "Starting Falco..."
fi

exec "$@"
