#!/usr/bin/env python3
"""
Business logic for the Near Real-Time Data Retrieval API.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

import redis.asyncio as aioredis
from fastapi import HTTPException, WebSocket
from pydantic import BaseModel, Field, StringConstraints


logger = logging.getLogger(__name__)


REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

NRTDR_WS_DEFAULT_LAST_N = int(os.getenv("NRTDR_WS_DEFAULT_LAST_N", "10"))
NRTDR_WS_MAX_LAST_N = int(os.getenv("NRTDR_WS_MAX_LAST_N", "100"))
NRTDR_ACTIVE_WINDOW_SECONDS = int(os.getenv("NRTDR_ACTIVE_WINDOW_SECONDS", "60"))
NRTDR_XREAD_BLOCK_MS = 15000

NRTDR_STREAM_CATALOG_KEY = "nrtdr:streams"
NRTDR_META_PREFIX = "nrtdr:stream:"
NRTDR_DATA_TYPE_PREFIX = "nrtdr:data_type:"
NRTDR_MACHINE_PREFIX = "nrtdr:machine:"
GLOBAL_MACHINE_ID = "global"


MachineId = Annotated[
    str,
    StringConstraints(pattern=r"^(global|[0-9a-z]{64})$", min_length=6, max_length=64),
]
DataType = Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,64}$")]


class StreamInfo(BaseModel):
    stream_key: str = Field(..., description="Redis stream key")
    data_type: DataType = Field(..., description="Logical data type")
    machine_id: MachineId = Field(..., description="Machine identifier or 'global'")
    source_topic: Optional[str] = Field(None, description="Kafka topic currently feeding the stream")
    topic_var: Optional[str] = Field(None, description="Topic env var name used to resolve the source topic")
    source_topics: list[str] = Field(default_factory=list, description="All Kafka topics observed for the stream")
    topic_vars: list[str] = Field(default_factory=list, description="All topic env vars observed for the stream")
    last_source_topic: Optional[str] = Field(None, description="Most recent Kafka topic feeding the stream")
    last_topic_var: Optional[str] = Field(None, description="Most recent topic env var associated with the stream")
    first_seen: Optional[str] = Field(None, description="First time the stream was seen")
    last_seen: Optional[str] = Field(None, description="Most recent time a message was ingested")
    last_redis_stream_id: Optional[str] = Field(None, description="Latest Redis Stream entry id")
    is_global: bool = Field(..., description="Whether the stream is global")
    is_active: bool = Field(..., description="Whether the stream is active in the selected window")


class AvailableStreamsResponse(BaseModel):
    total_streams: int
    streams: list[StreamInfo]


class StreamMessage(BaseModel):
    stream_key: str
    data_type: DataType
    machine_id: MachineId
    source_topic: Optional[str] = None
    redis_stream_id: str
    ingested_at: Optional[str] = None
    payload: Any


redis_client: Optional[aioredis.Redis] = None


def get_stream_meta_key(stream_key: str) -> str:
    return f"{NRTDR_META_PREFIX}{stream_key}:meta"


def get_data_type_index_key(data_type: str) -> str:
    return f"{NRTDR_DATA_TYPE_PREFIX}{data_type}:streams"


def get_machine_index_key(machine_id: str) -> str:
    return f"{NRTDR_MACHINE_PREFIX}{machine_id}:streams"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def is_stream_active(last_seen: Optional[str], active_window_seconds: int) -> bool:
    last_seen_dt = parse_iso_datetime(last_seen)
    if last_seen_dt is None:
        return False
    return (utcnow() - last_seen_dt).total_seconds() <= active_window_seconds


def decode_bytes(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def decode_json_string_list(value: Optional[str]) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if str(item).strip()]


def sanitize_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload

    sanitized = copy.deepcopy(payload)
    log_data = sanitized.get("log")
    if isinstance(log_data, dict):
        file_data = log_data.get("file")
        if isinstance(file_data, dict):
            file_data.pop("path", None)
    return sanitized


def deserialize_payload(raw_payload: Any) -> Any:
    if isinstance(raw_payload, bytes):
        payload_text = raw_payload.decode("utf-8", errors="replace")
    else:
        payload_text = str(raw_payload)

    try:
        parsed = json.loads(payload_text)
    except json.JSONDecodeError:
        return payload_text

    return sanitize_payload(parsed)


def stream_info_sort_key(stream: StreamInfo) -> tuple[str, str]:
    return (stream.data_type, stream.machine_id)


async def get_redis_client() -> aioredis.Redis:
    global redis_client

    if redis_client is None:
        try:
            redis_client = await aioredis.from_url(
                f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}",
                password=REDIS_PASSWORD,
                encoding="utf-8",
                decode_responses=False,
                socket_keepalive=True,
                socket_connect_timeout=5,
                retry_on_timeout=True,
            )
            await redis_client.ping()
            logger.info("✅ Connected to Redis at %s:%s/%s", REDIS_HOST, REDIS_PORT, REDIS_DB)
        except Exception as exc:
            logger.error("❌ Failed to connect to Redis: %s", exc)
            raise HTTPException(status_code=503, detail="Redis connection failed")

    return redis_client


async def close_redis_client() -> None:
    global redis_client
    if redis_client:
        await redis_client.close()
        redis_client = None
        logger.info("🔌 Redis connection closed")


async def fetch_stream_keys(
    redis_conn: aioredis.Redis,
    data_type: Optional[str] = None,
    machine_id: Optional[str] = None,
) -> set[str]:
    if data_type and machine_id:
        stream_key = f"{data_type}:{machine_id}"
        exists = await redis_conn.sismember(NRTDR_STREAM_CATALOG_KEY, stream_key)
        return {stream_key} if exists else set()

    if data_type:
        keys = await redis_conn.smembers(get_data_type_index_key(data_type))
        return {decode_bytes(item) for item in keys if decode_bytes(item)}

    if machine_id:
        keys = await redis_conn.smembers(get_machine_index_key(machine_id))
        return {decode_bytes(item) for item in keys if decode_bytes(item)}

    keys = await redis_conn.smembers(NRTDR_STREAM_CATALOG_KEY)
    return {decode_bytes(item) for item in keys if decode_bytes(item)}


async def load_stream_info(
    redis_conn: aioredis.Redis,
    stream_key: str,
    active_window_seconds: int,
) -> Optional[StreamInfo]:
    meta = await redis_conn.hgetall(get_stream_meta_key(stream_key))
    if not meta:
        return None

    decoded = {decode_bytes(key): decode_bytes(value) for key, value in meta.items()}
    data_type = decoded.get("data_type")
    machine_id = decoded.get("machine_id")

    if not data_type or not machine_id:
        return None

    last_seen = decoded.get("last_seen")
    source_topic = decoded.get("source_topic")
    topic_var = decoded.get("topic_var")
    source_topics = decode_json_string_list(decoded.get("source_topics"))
    topic_vars = decode_json_string_list(decoded.get("topic_vars"))

    if not source_topics and source_topic:
        source_topics = [source_topic]
    if not topic_vars and topic_var:
        topic_vars = [topic_var]

    return StreamInfo(
        stream_key=decoded.get("stream_key", stream_key),
        data_type=data_type,
        machine_id=machine_id,
        source_topic=source_topic,
        topic_var=topic_var,
        source_topics=source_topics,
        topic_vars=topic_vars,
        last_source_topic=decoded.get("last_source_topic") or source_topic,
        last_topic_var=decoded.get("last_topic_var") or topic_var,
        first_seen=decoded.get("first_seen"),
        last_seen=last_seen,
        last_redis_stream_id=decoded.get("last_redis_stream_id"),
        is_global=decoded.get("is_global", "false").lower() == "true",
        is_active=is_stream_active(last_seen, active_window_seconds),
    )


async def list_stream_infos(
    redis_conn: aioredis.Redis,
    data_type: Optional[str],
    machine_id: Optional[str],
    only_active: bool,
    active_window_seconds: int,
) -> list[StreamInfo]:
    stream_keys = await fetch_stream_keys(
        redis_conn,
        data_type=data_type,
        machine_id=machine_id,
    )

    streams: list[StreamInfo] = []
    for stream_key in sorted(stream_keys):
        info = await load_stream_info(redis_conn, stream_key, active_window_seconds)
        if info is None:
            continue
        if only_active and not info.is_active:
            continue
        streams.append(info)

    return sorted(streams, key=stream_info_sort_key)


async def get_stream_info_or_404(
    redis_conn: aioredis.Redis,
    data_type: str,
    machine_id: str,
    active_window_seconds: int,
) -> StreamInfo:
    stream_key = f"{data_type}:{machine_id}"
    info = await load_stream_info(redis_conn, stream_key, active_window_seconds)
    if info is None:
        raise HTTPException(
            status_code=404,
            detail=f"No catalog entry for stream {stream_key}",
        )
    return info


def build_message_envelope(
    stream_info: StreamInfo,
    redis_stream_id: str,
    raw_fields: dict[str, Any],
) -> StreamMessage:
    return StreamMessage(
        stream_key=stream_info.stream_key,
        data_type=stream_info.data_type,
        machine_id=stream_info.machine_id,
        source_topic=decode_bytes(raw_fields.get(b"source_topic") or raw_fields.get("source_topic"))
        or stream_info.source_topic,
        redis_stream_id=redis_stream_id,
        ingested_at=decode_bytes(raw_fields.get(b"ingested_at") or raw_fields.get("ingested_at")),
        payload=deserialize_payload(raw_fields.get(b"payload") or raw_fields.get("payload")),
    )


async def send_initial_last_n(
    websocket: WebSocket,
    redis_conn: aioredis.Redis,
    stream_info: StreamInfo,
    requested_last_n: int,
) -> tuple[Optional[str], int]:
    if requested_last_n <= 0:
        return stream_info.last_redis_stream_id, 0

    messages = await redis_conn.xrevrange(
        stream_info.stream_key,
        count=requested_last_n,
    )
    if not messages:
        return stream_info.last_redis_stream_id, 0

    last_seen_id = None
    sent_count = 0
    for message_id_raw, raw_fields in reversed(messages):
        message_id = decode_bytes(message_id_raw)
        if message_id is None:
            continue
        await websocket.send_json(
            build_message_envelope(stream_info, message_id, raw_fields).model_dump()
        )
        last_seen_id = message_id
        sent_count += 1

    return last_seen_id or stream_info.last_redis_stream_id, sent_count
