#!/usr/bin/env python3
"""
Business logic for the Historical Data Retrieval API.

Orchestrates the catalog and the Mimir client, validates query parameters,
and normalizes raw PromQL results into the API's own response models.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException

from hdr_catalog import list_metrics, list_tools, resolve_metric_or_404
from hdr_config import HDR_MAX_RANGE_POINTS
from hdr_mimir_client import label_values, query_range
from hdr_models import (
    DataPoint,
    HistoricalSeries,
    HistoricalSeriesResponse,
    MachinesResponse,
    MetricInfo,
    SeriesLabels,
    ToolInfo,
    ToolsCatalogResponse,
)


logger = logging.getLogger(__name__)


def get_tools_catalog() -> ToolsCatalogResponse:
    tools = [
        ToolInfo(
            tool=tool,
            metrics=[
                MetricInfo(
                    metric=metric,
                    mimir_metric_name=descriptor.mimir_metric_name,
                    unit=descriptor.unit,
                    aggregation=descriptor.aggregation,
                    description=descriptor.description,
                )
                for metric, descriptor in list_metrics(tool).items()
            ],
        )
        for tool in list_tools()
    ]
    return ToolsCatalogResponse(total_tools=len(tools), tools=tools)


def _validate_range(start: datetime, end: datetime, step_seconds: int) -> None:
    if end <= start:
        raise HTTPException(status_code=400, detail="'end' must be strictly greater than 'start'")

    total_points = (end - start).total_seconds() / step_seconds
    if total_points > HDR_MAX_RANGE_POINTS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Requested range would return {int(total_points)} points per series, "
                f"which exceeds the limit of {HDR_MAX_RANGE_POINTS}. Widen the step or narrow the range."
            ),
        )


def _normalize_series(raw_series: dict[str, Any]) -> HistoricalSeries:
    raw_labels: dict[str, str] = dict(raw_series.get("metric", {}))
    machine_id = raw_labels.pop("machine_id", None)
    raw_labels.pop("__name__", None)

    points = [
        DataPoint(
            timestamp=datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat(),
            value=float(value),
        )
        for ts, value in raw_series.get("values", [])
    ]

    return HistoricalSeries(
        labels=SeriesLabels(machine_id=machine_id, extra=raw_labels),
        points=points,
    )


async def get_historical_data(
    tool: str,
    metric: str,
    machine_id: Optional[str],
    start: datetime,
    end: datetime,
    step: Optional[int],
    default_step_seconds: int,
) -> HistoricalSeriesResponse:
    descriptor = resolve_metric_or_404(tool, metric)
    effective_step = step or default_step_seconds
    _validate_range(start, end, effective_step)

    raw_result = await query_range(descriptor.mimir_metric_name, machine_id, start, end, effective_step)
    series = [_normalize_series(item) for item in raw_result]

    return HistoricalSeriesResponse(
        tool=tool,
        metric=metric,
        mimir_metric_name=descriptor.mimir_metric_name,
        machine_id_filter=machine_id,
        start=start.isoformat(),
        end=end.isoformat(),
        step_seconds=effective_step,
        total_series=len(series),
        series=series,
    )


async def list_available_machines(tool: Optional[str] = None, metric: Optional[str] = None) -> MachinesResponse:
    metric_filter = None
    if tool and metric:
        descriptor = resolve_metric_or_404(tool, metric)
        metric_filter = descriptor.mimir_metric_name
    elif tool or metric:
        raise HTTPException(status_code=400, detail="'tool' and 'metric' must be provided together")

    machine_ids = await label_values("machine_id", metric_filter=metric_filter)
    return MachinesResponse(total_machines=len(machine_ids), machine_ids=sorted(machine_ids))
