#!/usr/bin/env python3
"""
Helper utilities for parsing Kafka payloads in the Kafka -> Redis worker.
"""

from __future__ import annotations

import json
from typing import Any, Optional


def parse_json_bytes(message_bytes: bytes) -> dict[str, Any]:
    message_str = message_bytes.decode("utf-8", errors="replace")
    data = json.loads(message_str)
    if not isinstance(data, dict):
        raise ValueError("Top-level Kafka payload is not a JSON object")
    return data


def get_non_empty_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def extract_machine_id_from_mapping(data: dict[str, Any]) -> Optional[str]:
    direct_value = get_non_empty_string(data.get("machine_id"))
    if direct_value:
        return direct_value

    tags_value = data.get("tags")
    if isinstance(tags_value, dict):
        machine_id = get_non_empty_string(tags_value.get("machine_id"))
        if machine_id:
            return machine_id

    nested_data = data.get("nested_data")
    if isinstance(nested_data, dict):
        machine_id = get_non_empty_string(nested_data.get("machine_id"))
        if machine_id:
            return machine_id

    output_fields = data.get("output_fields")
    if isinstance(output_fields, dict):
        machine_id = get_non_empty_string(output_fields.get("machine_id"))
        if machine_id:
            return machine_id

    return None


def parse_embedded_json_from_message(message_value: str) -> Optional[dict[str, Any]]:
    message_value = message_value.strip()
    if not message_value:
        return None

    try:
        parsed = json.loads(message_value)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    if "\t" not in message_value:
        return None

    parts = message_value.split("\t", 2)
    if len(parts) != 3:
        return None

    try:
        parsed = json.loads(parts[2])
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        return None

    return None


def extract_machine_id_from_payload_dict(data: dict[str, Any]) -> Optional[str]:
    machine_id = extract_machine_id_from_mapping(data)
    if machine_id:
        return machine_id

    message_value = data.get("message")
    if isinstance(message_value, str):
        embedded = parse_embedded_json_from_message(message_value)
        if embedded:
            return extract_machine_id_from_mapping(embedded)

    return None
