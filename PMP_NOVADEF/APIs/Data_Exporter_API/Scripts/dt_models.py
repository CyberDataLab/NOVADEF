#!/usr/bin/env python3
"""
Pydantic models for the Data Exporter API.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Optional

from pydantic import BaseModel, Field, StringConstraints


MachineId = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class LogModule(str, Enum):
    """event.module value written by Logstash; "system" already unifies syslog and systemd."""

    SYSTEM = "system"
    FALCO = "falco"
    TELEGRAF = "telegraf"


class LogsResponse(BaseModel):
    total_hits: int = Field(..., description="Total number of documents matching the query")
    returned: int = Field(..., description="Number of documents included in this page")
    next_cursor: Optional[str] = Field(
        None,
        description="Opaque search_after cursor; pass it back as 'cursor' to fetch the next page, null when there are no more results",
    )
    documents: list[dict[str, Any]] = Field(
        ..., description="Raw Logstash/OpenSearch documents, unmodified"
    )


class AggregateBucketGroup(BaseModel):
    key: str = Field(..., description="Value of the group_by field for this slice of the bucket")
    doc_count: int


class AggregateBucket(BaseModel):
    timestamp: str = Field(..., description="ISO-8601 UTC start of this time bucket")
    doc_count: int
    groups: list[AggregateBucketGroup] = Field(
        default_factory=list, description="Present only when group_by is requested"
    )


class LogsAggregateResponse(BaseModel):
    machine_id_filter: Optional[str]
    module_filter: Optional[LogModule]
    group_by: Optional[str]
    start: str
    end: str
    interval_seconds: int
    total_buckets: int
    buckets: list[AggregateBucket]
