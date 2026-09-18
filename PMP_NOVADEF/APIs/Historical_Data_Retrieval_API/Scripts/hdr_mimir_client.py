#!/usr/bin/env python3
"""
Async HTTP client for Grafana Mimir's Prometheus-compatible query API.

Knows nothing about tools/metrics catalog or response normalization - it only
speaks PromQL and the raw Mimir/Prometheus HTTP API.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

import httpx
from fastapi import HTTPException

from hdr_config import HDR_HTTP_TIMEOUT_SECONDS, MIMIR_BASE_URL, MIMIR_QUERY_PREFIX
from hdr_models import GLOBAL_MACHINE_ID


logger = logging.getLogger(__name__)

_client: Optional[httpx.AsyncClient] = None


async def get_mimir_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(base_url=MIMIR_BASE_URL, timeout=HDR_HTTP_TIMEOUT_SECONDS)
        logger.info("🔌 Mimir HTTP client initialized -> %s", MIMIR_BASE_URL)
    return _client


async def close_mimir_client() -> None:
    global _client
    if _client:
        await _client.aclose()
        _client = None
        logger.info("🔌 Mimir HTTP client closed")


def build_promql(mimir_metric_name: str, machine_id: Optional[str]) -> str:
    if machine_id and machine_id != GLOBAL_MACHINE_ID:
        return f'{mimir_metric_name}{{machine_id="{machine_id}"}}'
    return mimir_metric_name


async def _get(path: str, params: dict[str, Any]) -> dict[str, Any]:
    client = await get_mimir_client()
    try:
        response = await client.get(f"{MIMIR_QUERY_PREFIX}{path}", params=params)
        response.raise_for_status()
    except httpx.TimeoutException as exc:
        logger.error("❌ Timeout querying Mimir: %s", exc)
        raise HTTPException(status_code=504, detail=f"Timeout querying Mimir: {exc}")
    except httpx.HTTPStatusError as exc:
        logger.error("❌ Mimir returned an error status: %s", exc)
        raise HTTPException(status_code=exc.response.status_code, detail=f"Mimir query error: {exc.response.text}")
    except httpx.RequestError as exc:
        logger.error("❌ Cannot reach Mimir: %s", exc)
        raise HTTPException(status_code=503, detail=f"Cannot reach Mimir: {exc}")

    body = response.json()
    if body.get("status") != "success":
        logger.error("❌ Mimir returned a non-success payload: %s", body)
        raise HTTPException(status_code=502, detail=f"Mimir returned non-success status: {body}")
    return body["data"]


async def query_range(
    mimir_metric_name: str,
    machine_id: Optional[str],
    start: datetime,
    end: datetime,
    step_seconds: int,
) -> list[dict[str, Any]]:
    query = build_promql(mimir_metric_name, machine_id)
    data = await _get(
        "/query_range",
        {
            "query": query,
            "start": start.timestamp(),
            "end": end.timestamp(),
            "step": step_seconds,
        },
    )
    return data.get("result", [])


async def label_values(label: str, metric_filter: Optional[str] = None) -> list[str]:
    params: dict[str, Any] = {}
    if metric_filter:
        params["match[]"] = metric_filter
    data = await _get(f"/label/{label}/values", params)
    return data if isinstance(data, list) else []


async def check_mimir_health() -> bool:
    """Verifies the Prometheus-compatible query surface that HDR actually depends on."""
    client = await get_mimir_client()
    response = await client.get(f"{MIMIR_QUERY_PREFIX}/status/buildinfo")
    response.raise_for_status()
    return response.json().get("status") == "success"
