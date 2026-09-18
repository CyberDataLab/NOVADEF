#!/usr/bin/env python3
"""
Async HTTP client for OpenSearch's REST query API.

Knows nothing about the logs/machine_id domain model or response
normalization - it only speaks OpenSearch Query DSL over the raw REST API.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx
from fastapi import HTTPException

from dt_config import (
    OPENSEARCH_BASE_URL,
    OPENSEARCH_LOGS_INDEX_PATTERN,
    OPENSEARCH_PASSWORD,
    OPENSEARCH_USERNAME,
    DT_HTTP_TIMEOUT_SECONDS,
)


logger = logging.getLogger(__name__)

_client: Optional[httpx.AsyncClient] = None


async def get_opensearch_client() -> httpx.AsyncClient:
    '''Returns the shared OpenSearch HTTP client, creating it on first use.'''
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=OPENSEARCH_BASE_URL,
            auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
            timeout=DT_HTTP_TIMEOUT_SECONDS,
            # OpenSearch ships with a self-signed demo certificate; Logstash's own
            # output plugin disables verification for the same reason (see
            # Aggregation_Normalisation_Module/Configuration_Files/Logstash/pipeline.conf).
            verify=False,
        )
        logger.info("🔌 OpenSearch HTTP client initialized -> %s", OPENSEARCH_BASE_URL)
    return _client


async def close_opensearch_client() -> None:
    '''Closes and discards the shared OpenSearch HTTP client.'''
    global _client
    if _client:
        await _client.aclose()
        _client = None
        logger.info("🔌 OpenSearch HTTP client closed")


async def _post(path: str, body: dict[str, Any]) -> dict[str, Any]:
    '''Sends a POST request to OpenSearch and translates transport/HTTP errors into HTTPException.'''
    client = await get_opensearch_client()
    try:
        response = await client.post(path, json=body)
        response.raise_for_status()
    except httpx.TimeoutException as exc:
        logger.error("❌ Timeout querying OpenSearch: %s", exc)
        raise HTTPException(status_code=504, detail=f"Timeout querying OpenSearch: {exc}")
    except httpx.HTTPStatusError as exc:
        logger.error("❌ OpenSearch returned an error status: %s", exc)
        raise HTTPException(status_code=exc.response.status_code, detail=f"OpenSearch query error: {exc.response.text}")
    except httpx.RequestError as exc:
        logger.error("❌ Cannot reach OpenSearch: %s", exc)
        raise HTTPException(status_code=503, detail=f"Cannot reach OpenSearch: {exc}")

    return response.json()


async def search(query_body: dict[str, Any]) -> dict[str, Any]:
    '''Runs a Query DSL search against the "logs-*" index pattern.'''
    return await _post(f"/{OPENSEARCH_LOGS_INDEX_PATTERN}/_search", query_body)


async def check_opensearch_health() -> bool:
    '''Pings the real cluster health endpoint so /health fails if OpenSearch can't serve data.

    A single-node cluster normally reports "yellow" (unassigned replicas), never
    "green", so only "red" (missing primary shards) is treated as unhealthy.
    '''
    client = await get_opensearch_client()
    response = await client.get("/_cluster/health")
    response.raise_for_status()
    return response.json().get("status") != "red"
