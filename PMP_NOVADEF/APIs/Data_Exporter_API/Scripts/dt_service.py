#!/usr/bin/env python3
"""
Business logic for the Data Exporter API.

Builds OpenSearch Query DSL bodies from the API's own request parameters,
and normalizes the raw OpenSearch response into the API's response models.
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException

from dt_config import DT_MAX_RANGE_POINTS
from dt_models import (
    AggregateBucket,
    AggregateBucketGroup,
    LogModule,
    LogsAggregateResponse,
    LogsResponse,
)
from dt_opensearch_client import search


logger = logging.getLogger(__name__)

# Only these fields may be used for the /logs/aggregate group_by, to avoid
# passing arbitrary field names straight into the OpenSearch terms aggregation.
# Logstash's default dynamic mapping indexes these as "text" with a "keyword"
# multi-field; exact-match filtering and terms aggregations must target the
# ".keyword" sub-field since OpenSearch rejects both on plain "text" fields.
GROUP_BY_FIELDS: dict[str, str] = {
    "dataset": "event.dataset.keyword",
    "machine": "host.id.keyword",
    "module": "event.module.keyword",
}


def _validate_range(start: datetime, end: datetime, step_seconds: int) -> None:
    '''Rejects inverted ranges or ranges that would return more buckets than DT_MAX_RANGE_POINTS.'''
    if end <= start:
        raise HTTPException(status_code=400, detail="'end' must be strictly greater than 'start'")

    total_points = (end - start).total_seconds() / step_seconds
    if total_points > DT_MAX_RANGE_POINTS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Requested range would return {int(total_points)} buckets, "
                f"which exceeds the limit of {DT_MAX_RANGE_POINTS}. Widen the interval or narrow the range."
            ),
        )


def _build_filters(
    machine_id: Optional[str],
    module: Optional[LogModule],
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    '''Builds the OpenSearch bool/filter clauses shared by /logs and /logs/aggregate.'''
    filters: list[dict[str, Any]] = [
        {
            "range": {
                "@timestamp": {
                    "gte": start.isoformat(),
                    "lte": end.isoformat(),
                }
            }
        }
    ]
    if machine_id:
        filters.append({"term": {"host.id.keyword": machine_id}})
    if module:
        filters.append({"term": {"event.module.keyword": module.value}})
    return filters


def _encode_cursor(sort_values: list[Any]) -> str:
    '''Encodes an OpenSearch sort tuple into the opaque cursor string returned to API clients.'''
    return base64.urlsafe_b64encode(json.dumps(sort_values).encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str) -> list[Any]:
    '''Decodes a client-supplied cursor back into the search_after sort tuple.'''
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid cursor: {exc}")


async def get_logs(
    machine_id: Optional[str],
    module: Optional[LogModule],
    start: datetime,
    end: datetime,
    size: int,
    cursor: Optional[str],
) -> LogsResponse:
    '''Fetches one page of raw log/event documents, sorted by @timestamp with search_after pagination.'''
    if end <= start:
        raise HTTPException(status_code=400, detail="'end' must be strictly greater than 'start'")

    query_body: dict[str, Any] = {
        "size": size,
        "query": {"bool": {"filter": _build_filters(machine_id, module, start, end)}},
        # Bounded historical ranges are immutable once written, so a plain
        # search_after cursor (no point-in-time) is enough for consistent paging.
        "sort": [{"@timestamp": "asc"}],
    }
    if cursor:
        query_body["search_after"] = _decode_cursor(cursor)

    raw = await search(query_body)
    hits = raw.get("hits", {})
    documents = [hit.get("_source", {}) for hit in hits.get("hits", [])]

    next_cursor = None
    raw_hits = hits.get("hits", [])
    if raw_hits and len(raw_hits) == size:
        next_cursor = _encode_cursor(raw_hits[-1]["sort"])

    return LogsResponse(
        total_hits=hits.get("total", {}).get("value", 0),
        returned=len(documents),
        next_cursor=next_cursor,
        documents=documents,
    )


def _normalize_bucket(raw_bucket: dict[str, Any], group_by_key: Optional[str]) -> AggregateBucket:
    '''Converts one raw date_histogram bucket (with its optional terms sub-aggregation) into AggregateBucket.'''
    groups: list[AggregateBucketGroup] = []
    if group_by_key:
        for group_bucket in raw_bucket.get(group_by_key, {}).get("buckets", []):
            groups.append(AggregateBucketGroup(key=group_bucket["key"], doc_count=group_bucket["doc_count"]))

    return AggregateBucket(
        timestamp=datetime.fromtimestamp(raw_bucket["key"] / 1000, tz=timezone.utc).isoformat(),
        doc_count=raw_bucket["doc_count"],
        groups=groups,
    )


async def get_logs_aggregate(
    machine_id: Optional[str],
    module: Optional[LogModule],
    start: datetime,
    end: datetime,
    interval_seconds: int,
    group_by: Optional[str],
) -> LogsAggregateResponse:
    '''Buckets matching documents by time interval, optionally sub-grouped by dataset/machine/module.'''
    _validate_range(start, end, interval_seconds)

    if group_by and group_by not in GROUP_BY_FIELDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown group_by '{group_by}'. Valid values: {', '.join(GROUP_BY_FIELDS)}",
        )

    date_histogram: dict[str, Any] = {
        "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": f"{interval_seconds}s",
            "min_doc_count": 0,
        }
    }
    if group_by:
        date_histogram["aggs"] = {
            group_by: {"terms": {"field": GROUP_BY_FIELDS[group_by], "size": 50}}
        }

    query_body: dict[str, Any] = {
        "size": 0,
        "query": {"bool": {"filter": _build_filters(machine_id, module, start, end)}},
        "aggs": {"buckets_over_time": date_histogram},
    }

    raw = await search(query_body)
    raw_buckets = raw.get("aggregations", {}).get("buckets_over_time", {}).get("buckets", [])
    buckets = [_normalize_bucket(raw_bucket, group_by) for raw_bucket in raw_buckets]

    return LogsAggregateResponse(
        machine_id_filter=machine_id,
        module_filter=module,
        group_by=group_by,
        start=start.isoformat(),
        end=end.isoformat(),
        interval_seconds=interval_seconds,
        total_buckets=len(buckets),
        buckets=buckets,
    )
