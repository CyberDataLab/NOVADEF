#!/usr/bin/env python3
"""
FastAPI entrypoint for the Data Exporter API.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Query

from dt_config import DT_DEFAULT_STEP_SECONDS, DT_MAX_PAGE_SIZE
from dt_models import LogModule, LogsAggregateResponse, LogsResponse, MachineId
from dt_opensearch_client import check_opensearch_health, close_opensearch_client, get_opensearch_client
from dt_service import get_logs, get_logs_aggregate


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    '''Opens the shared OpenSearch client on startup and closes it on shutdown.'''
    logger.info("🚀 Starting Data Exporter API...")
    await get_opensearch_client()
    yield
    await close_opensearch_client()


app = FastAPI(
    title="PMP Data Exporter API",
    description="REST API for querying normalized logs/events stored in OpenSearch",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
async def root() -> dict[str, Any]:
    '''Returns API metadata, endpoint summary and usage examples.'''
    return {
        "name": "PMP Data Exporter API",
        "version": "1.0.0",
        "description": "REST API for querying normalized logs/events stored in OpenSearch",
        "endpoints": {
            "GET /": "API information",
            "GET /health": "Health check",
            "GET /logs": "Query raw log/event documents",
            "GET /logs/aggregate": "Query bucketed counts of log/event documents",
        },
        "usage": {
            "examples": {
                "curl_logs": (
                    "curl 'http://localhost:8003/logs"
                    "?machine_id=<machine_id>&module=falco"
                    "&start=2026-07-14T00:00:00Z&end=2026-07-15T00:00:00Z'"
                ),
                "curl_logs_aggregate": (
                    "curl 'http://localhost:8003/logs/aggregate"
                    "?start=2026-07-14T00:00:00Z&end=2026-07-15T00:00:00Z"
                    "&interval=60&group_by=dataset'"
                ),
            },
        },
        "defaults": {
            "default_interval_seconds": DT_DEFAULT_STEP_SECONDS,
            "max_page_size": DT_MAX_PAGE_SIZE,
        },
    }


@app.get("/health")
async def health_check() -> dict[str, str]:
    '''Reports service health based on a real ping to OpenSearch's cluster health endpoint.'''
    try:
        healthy = await check_opensearch_health()
        if not healthy:
            raise HTTPException(status_code=503, detail="OpenSearch cluster health is red")
        return {"status": "healthy", "opensearch": "connected"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("❌ Health check failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {exc}")


@app.get("/logs", response_model=LogsResponse)
async def logs(
    machine_id: Optional[MachineId] = Query(None, description="Filter by machine_id, omitted for all machines"),
    module: Optional[LogModule] = Query(None, description="Filter by event module; 'system' covers syslog and systemd"),
    start: datetime = Query(..., description="Range start (ISO-8601/RFC3339)"),
    end: datetime = Query(..., description="Range end (ISO-8601/RFC3339)"),
    size: int = Query(100, ge=1, le=DT_MAX_PAGE_SIZE, description="Page size"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous response's next_cursor"),
) -> LogsResponse:
    '''Returns one page of raw log/event documents matching the given filters and time range.'''
    try:
        return await get_logs(
            machine_id=machine_id,
            module=module,
            start=start,
            end=end,
            size=size,
            cursor=cursor,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("❌ Error retrieving logs: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {exc}")


@app.get("/logs/aggregate", response_model=LogsAggregateResponse)
async def logs_aggregate(
    machine_id: Optional[MachineId] = Query(None, description="Filter by machine_id, omitted for all machines"),
    module: Optional[LogModule] = Query(None, description="Filter by event module; 'system' covers syslog and systemd"),
    start: datetime = Query(..., description="Range start (ISO-8601/RFC3339)"),
    end: datetime = Query(..., description="Range end (ISO-8601/RFC3339)"),
    interval: Optional[int] = Query(None, ge=1, description="Bucket width in seconds; defaults to DT_DEFAULT_STEP_SECONDS"),
    group_by: Optional[str] = Query(None, description="Sub-group each bucket by 'dataset', 'machine' or 'module'"),
) -> LogsAggregateResponse:
    '''Returns bucketed document counts over time, optionally sub-grouped, matching the given filters and time range.'''
    try:
        return await get_logs_aggregate(
            machine_id=machine_id,
            module=module,
            start=start,
            end=end,
            interval_seconds=interval or DT_DEFAULT_STEP_SECONDS,
            group_by=group_by,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("❌ Error aggregating logs: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to aggregate logs: {exc}")
