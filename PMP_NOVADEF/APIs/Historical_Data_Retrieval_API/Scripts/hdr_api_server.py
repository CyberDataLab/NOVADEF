#!/usr/bin/env python3
"""
FastAPI entrypoint for the Historical Data Retrieval API.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Path, Query

from hdr_config import HDR_DEFAULT_STEP_SECONDS
from hdr_mimir_client import check_mimir_health, close_mimir_client, get_mimir_client
from hdr_models import HistoricalSeriesResponse, MachinesResponse, MachineId, MetricName, ToolName, ToolsCatalogResponse
from hdr_service import get_historical_data, get_tools_catalog, list_available_machines


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("🚀 Starting HDR API...")
    await get_mimir_client()
    yield
    await close_mimir_client()


app = FastAPI(
    title="PMP Historical Data Retrieval API",
    description="REST API for querying historical monitoring data stored in Grafana Mimir",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "name": "PMP Historical Data Retrieval API",
        "version": "1.0.0",
        "description": "REST API for querying historical monitoring data stored in Grafana Mimir",
        "endpoints": {
            "GET /": "API information",
            "GET /health": "Health check",
            "GET /tools": "List available tools and their metrics",
            "GET /machines": "List known machine_id values, optionally scoped to a tool/metric",
            "GET /historical/{tool}/{metric}": "Query historical time-series data",
        },
        "usage": {
            "examples": {
                "curl_catalog": "curl 'http://localhost:8002/tools'",
                "curl_historical": (
                    "curl 'http://localhost:8002/historical/telegraf/cpu_usage_user"
                    "?start=2026-07-14T00:00:00Z&end=2026-07-15T00:00:00Z&step=60'"
                ),
                "curl_historical_filtered": (
                    "curl 'http://localhost:8002/historical/telegraf/cpu_usage_user"
                    "?machine_id=<machine_id>&start=2026-07-14T00:00:00Z&end=2026-07-15T00:00:00Z'"
                ),
            },
        },
        "defaults": {
            "default_step_seconds": HDR_DEFAULT_STEP_SECONDS,
        },
    }


@app.get("/health")
async def health_check() -> dict[str, str]:
    try:
        healthy = await check_mimir_health()
        if not healthy:
            raise HTTPException(status_code=503, detail="Mimir reported a non-success status")
        return {"status": "healthy", "mimir": "connected"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("❌ Health check failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {exc}")


@app.get("/tools", response_model=ToolsCatalogResponse)
async def tools_catalog() -> ToolsCatalogResponse:
    return get_tools_catalog()


@app.get("/machines", response_model=MachinesResponse)
async def machines(
    tool: Optional[ToolName] = Query(None, description="Scope machine discovery to this tool's metric"),
    metric: Optional[MetricName] = Query(None, description="Scope machine discovery to this metric (requires tool)"),
) -> MachinesResponse:
    try:
        return await list_available_machines(tool=tool, metric=metric)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("❌ Error listing machines: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to list machines: {exc}")


@app.get("/historical/{tool}/{metric}", response_model=HistoricalSeriesResponse)
async def historical(
    tool: ToolName = Path(..., description="Tool/data-source name, see GET /tools"),
    metric: MetricName = Path(..., description="Metric alias, see GET /tools"),
    machine_id: Optional[MachineId] = Query(None, description="Filter by machine_id, or 'global'/omitted for all machines"),
    start: datetime = Query(..., description="Range start (ISO-8601/RFC3339)"),
    end: datetime = Query(..., description="Range end (ISO-8601/RFC3339)"),
    step: Optional[int] = Query(None, ge=1, description="Resolution in seconds; defaults to HDR_DEFAULT_STEP_SECONDS"),
) -> HistoricalSeriesResponse:
    try:
        return await get_historical_data(
            tool=tool,
            metric=metric,
            machine_id=machine_id,
            start=start,
            end=end,
            step=step,
            default_step_seconds=HDR_DEFAULT_STEP_SECONDS,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("❌ Error retrieving historical data for %s/%s: %s", tool, metric, exc)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve historical data: {exc}")
