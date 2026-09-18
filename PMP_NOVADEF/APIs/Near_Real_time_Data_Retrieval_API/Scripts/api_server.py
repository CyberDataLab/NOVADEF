#!/usr/bin/env python3
"""
FastAPI entrypoint for the Near Real-Time Data Retrieval API.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Path, Query, WebSocket, WebSocketDisconnect

from nrtdr_api_logic import (
    AvailableStreamsResponse,
    DataType,
    MachineId,
    NRTDR_ACTIVE_WINDOW_SECONDS,
    NRTDR_WS_DEFAULT_LAST_N,
    NRTDR_WS_MAX_LAST_N,
    NRTDR_XREAD_BLOCK_MS,
    StreamInfo,
    build_message_envelope,
    close_redis_client,
    decode_bytes,
    get_redis_client,
    get_stream_info_or_404,
    list_stream_infos,
    send_initial_last_n,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


app = FastAPI(
    title="PMP Near Real-Time Data API",
    description="WebSocket-based API for streaming monitoring data from Kafka via Redis Streams",
    version="2.0.0",
)


@app.on_event("startup")
async def startup_event() -> None:
    logger.info("🚀 Starting FastAPI WebSocket API...")
    await get_redis_client()


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await close_redis_client()


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "name": "PMP Near Real-Time Data Streaming API",
        "version": "2.0.0",
        "description": "WebSocket-based streaming of monitoring data from Kafka via Redis Streams",
        "endpoints": {
            "GET /": "API information",
            "GET /health": "Health check",
            "GET /streams": "List cataloged streams with optional filters",
            "GET /streams/{data_type}/{machine_id}": "Retrieve a single cataloged stream description",
            "WS /stream/{data_type}/{machine_id}": "Connect to a specific stream via WebSocket",
        },
        "usage": {
            "how_to_connect": "Open WebSocket connection to ws://<host>:<port>/stream/{data_type}/{machine_id}?last_n=<N>",
            "examples": {
                "javascript": "const ws = new WebSocket('ws://localhost:8001/stream/health_metrics/global?last_n=5');",
                "python": "async with websockets.connect('ws://localhost:8001/stream/logs/global?last_n=10') as ws: ...",
                "curl": "curl 'http://localhost:8001/streams?only_active=true'",
            },
        },
        "defaults": {
            "ws_default_last_n": NRTDR_WS_DEFAULT_LAST_N,
            "ws_max_last_n": NRTDR_WS_MAX_LAST_N,
            "active_window_seconds": NRTDR_ACTIVE_WINDOW_SECONDS,
        },
    }


@app.get("/health")
async def health_check() -> dict[str, str]:
    try:
        redis_conn = await get_redis_client()
        await redis_conn.ping()
        return {"status": "healthy", "redis": "connected"}
    except Exception as exc:
        logger.error("❌ Health check failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {exc}")


@app.get("/streams", response_model=AvailableStreamsResponse)
async def get_available_streams(
    machine_id: Optional[MachineId] = Query(None, description="Filter by machine_id or 'global'"),
    data_type: Optional[DataType] = Query(None, description="Filter by data_type"),
    only_active: bool = Query(False, description="Return only streams active in the selected window"),
    active_within_seconds: int = Query(
        NRTDR_ACTIVE_WINDOW_SECONDS,
        ge=1,
        le=86400,
        description="Activity window in seconds used by only_active and the is_active flag",
    ),
) -> AvailableStreamsResponse:
    try:
        redis_conn = await get_redis_client()
        streams = await list_stream_infos(
            redis_conn=redis_conn,
            data_type=data_type,
            machine_id=machine_id,
            only_active=only_active,
            active_window_seconds=active_within_seconds,
        )
        return AvailableStreamsResponse(total_streams=len(streams), streams=streams)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("❌ Error listing streams: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to list streams: {exc}")


@app.get("/streams/{data_type}/{machine_id}", response_model=StreamInfo)
async def get_stream_by_id(
    data_type: DataType = Path(..., description="Logical data type"),
    machine_id: MachineId = Path(..., description="Machine id or 'global'"),
    active_within_seconds: int = Query(
        NRTDR_ACTIVE_WINDOW_SECONDS,
        ge=1,
        le=86400,
        description="Activity window in seconds used to evaluate is_active",
    ),
) -> StreamInfo:
    redis_conn = await get_redis_client()
    return await get_stream_info_or_404(
        redis_conn=redis_conn,
        data_type=data_type,
        machine_id=machine_id,
        active_window_seconds=active_within_seconds,
    )


@app.websocket("/stream/{data_type}/{machine_id}")
async def websocket_stream(
    websocket: WebSocket,
    data_type: DataType = Path(..., description="Logical data type"),
    machine_id: MachineId = Path(..., description="Machine id or 'global'"),
    last_n: int = Query(
        NRTDR_WS_DEFAULT_LAST_N,
        ge=0,
        description="How many most recent messages to replay before streaming new ones",
    ),
) -> None:
    requested_last_n = min(last_n, NRTDR_WS_MAX_LAST_N)
    redis_conn = await get_redis_client()
    try:
        stream_info = await get_stream_info_or_404(
            redis_conn=redis_conn,
            data_type=data_type,
            machine_id=machine_id,
            active_window_seconds=NRTDR_ACTIVE_WINDOW_SECONDS,
        )
    except HTTPException as exc:
        await websocket.accept()
        await websocket.send_json(
            {
                "error": "Stream not found",
                "detail": exc.detail,
            }
        )
        await websocket.close(code=1008)
        return

    await websocket.accept()
    logger.info(
        "🔌 WebSocket connected: %s/%s (requested last_n=%s, effective=%s)",
        data_type,
        machine_id,
        last_n,
        requested_last_n,
    )
    last_seen_id, initial_messages_sent = await send_initial_last_n(
        websocket=websocket,
        redis_conn=redis_conn,
        stream_info=stream_info,
        requested_last_n=requested_last_n,
    )

    if not last_seen_id:
        last_seen_id = "$"

    messages_sent = initial_messages_sent

    try:
        while True:
            exists = await redis_conn.exists(stream_info.stream_key)
            if not exists:
                logger.info("ℹ️  Stream key %s expired; waiting for new entries", stream_info.stream_key)

            xread_result = await redis_conn.xread(
                {stream_info.stream_key: last_seen_id},
                block=NRTDR_XREAD_BLOCK_MS,
                count=None,
            )

            if not xread_result:
                continue

            for _, entries in xread_result:
                for message_id_raw, raw_fields in entries:
                    message_id = decode_bytes(message_id_raw)
                    if message_id is None:
                        continue
                    await websocket.send_json(
                        build_message_envelope(stream_info, message_id, raw_fields).model_dump()
                    )
                    last_seen_id = message_id
                    messages_sent += 1

    except WebSocketDisconnect:
        logger.info(
            "🔌 WebSocket disconnected: %s/%s (sent %s messages)",
            data_type,
            machine_id,
            messages_sent,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("❌ WebSocket error for %s/%s: %s", data_type, machine_id, exc)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        logger.info("✅ WebSocket closed: %s/%s", data_type, machine_id)
