#!/usr/bin/env python3
"""
Pydantic models for the Historical Data Retrieval API.
"""

from __future__ import annotations

from typing import Annotated, Optional

from pydantic import BaseModel, Field, StringConstraints


GLOBAL_MACHINE_ID = "global"

MachineId = Annotated[
    str,
    StringConstraints(pattern=r"^(global|[0-9a-z]{64})$", min_length=6, max_length=64),
]
ToolName = Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,64}$")]
MetricName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,128}$")]


class MetricInfo(BaseModel):
    metric: MetricName = Field(..., description="Metric alias used in the HDR API URLs")
    mimir_metric_name: str = Field(..., description="Real metric name as stored in Mimir")
    unit: Optional[str] = Field(None, description="Unit of the metric value, if applicable")
    aggregation: str = Field(..., description="Aggregation semantics applied by the recording rule (avg, increase, ...)")
    description: str = Field(..., description="Human-readable description of the metric")


class ToolInfo(BaseModel):
    tool: ToolName = Field(..., description="Tool/data-source name")
    metrics: list[MetricInfo] = Field(..., description="Metrics available for this tool")


class ToolsCatalogResponse(BaseModel):
    total_tools: int
    tools: list[ToolInfo]


class DataPoint(BaseModel):
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp")
    value: float


class SeriesLabels(BaseModel):
    machine_id: Optional[str] = Field(None, description="Machine identifier, when present on the series")
    extra: dict[str, str] = Field(default_factory=dict, description="Any other label reported by Mimir for this series")


class HistoricalSeries(BaseModel):
    labels: SeriesLabels
    points: list[DataPoint]


class HistoricalSeriesResponse(BaseModel):
    tool: ToolName
    metric: MetricName
    mimir_metric_name: str
    machine_id_filter: Optional[str] = Field(None, description="machine_id requested, None/'global' means unfiltered")
    start: str
    end: str
    step_seconds: int
    total_series: int
    series: list[HistoricalSeries]


class MachinesResponse(BaseModel):
    total_machines: int
    machine_ids: list[str]
