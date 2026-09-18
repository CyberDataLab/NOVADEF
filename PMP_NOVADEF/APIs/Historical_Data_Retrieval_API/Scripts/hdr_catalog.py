#!/usr/bin/env python3
"""
Static catalog mapping tool -> metric alias -> real Mimir metric name.

Built from the Prometheus recording rules that feed Mimir via remote-write
(Aggregation_Normalisation_Module/Configuration_Files/Prometheus/rules/). Only
metrics named "downsampled:*" reach Mimir, and all of them carry the
machine_id label except where noted.
"""

from __future__ import annotations

from typing import NamedTuple, Optional

from fastapi import HTTPException


class MetricDescriptor(NamedTuple):
    mimir_metric_name: str
    unit: Optional[str]
    aggregation: str
    description: str


HDR_CATALOG: dict[str, dict[str, MetricDescriptor]] = {
    "telegraf": {
        "cpu_usage_user": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_user:avg1m", "percent", "avg",
            "CPU time spent in user space",
        ),
        "cpu_usage_system": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_system:avg1m", "percent", "avg",
            "CPU time spent in kernel space",
        ),
        "cpu_usage_idle": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_idle:avg1m", "percent", "avg",
            "CPU idle time",
        ),
        "cpu_usage_iowait": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_iowait:avg1m", "percent", "avg",
            "CPU time waiting for I/O",
        ),
        "cpu_usage_irq": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_irq:avg1m", "percent", "avg",
            "CPU time servicing hardware interrupts",
        ),
        "cpu_usage_softirq": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_softirq:avg1m", "percent", "avg",
            "CPU time servicing software interrupts",
        ),
        "cpu_usage_steal": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_steal:avg1m", "percent", "avg",
            "CPU time stolen by the hypervisor",
        ),
        "cpu_usage_guest": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_guest:avg1m", "percent", "avg",
            "CPU time running a guest VM",
        ),
        "cpu_usage_guest_nice": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_guest_nice:avg1m", "percent", "avg",
            "CPU time running a niced guest VM",
        ),
        "cpu_usage_nice": MetricDescriptor(
            "downsampled:telegraf_cpu_usage_nice:avg1m", "percent", "avg",
            "CPU time running niced user processes",
        ),
        "mem_used": MetricDescriptor(
            "downsampled:telegraf_mem_used:avg1m", "bytes", "avg",
            "Memory in use",
        ),
        "mem_available": MetricDescriptor(
            "downsampled:telegraf_mem_available:avg1m", "bytes", "avg",
            "Memory available for new allocations",
        ),
        "mem_total": MetricDescriptor(
            "downsampled:telegraf_mem_total:avg1m", "bytes", "avg",
            "Total physical memory",
        ),
        "mem_used_percent": MetricDescriptor(
            "downsampled:telegraf_mem_used_percent:avg1m", "percent", "avg",
            "Percentage of memory in use",
        ),
        "disk_used": MetricDescriptor(
            "downsampled:telegraf_disk_used:avg1m", "bytes", "avg",
            "Disk space in use",
        ),
        "disk_free": MetricDescriptor(
            "downsampled:telegraf_disk_free:avg1m", "bytes", "avg",
            "Disk space free",
        ),
        "disk_total": MetricDescriptor(
            "downsampled:telegraf_disk_total:avg1m", "bytes", "avg",
            "Total disk space",
        ),
        "disk_used_percent": MetricDescriptor(
            "downsampled:telegraf_disk_used_percent:avg1m", "percent", "avg",
            "Percentage of disk space in use",
        ),
        "disk_inodes_used": MetricDescriptor(
            "downsampled:telegraf_disk_inodes_used:avg1m", "count", "avg",
            "Inodes in use",
        ),
        "disk_inodes_free": MetricDescriptor(
            "downsampled:telegraf_disk_inodes_free:avg1m", "count", "avg",
            "Inodes free",
        ),
        "disk_inodes_total": MetricDescriptor(
            "downsampled:telegraf_disk_inodes_total:avg1m", "count", "avg",
            "Total inodes",
        ),
        "disk_inodes_used_percent": MetricDescriptor(
            "downsampled:telegraf_disk_inodes_used_percent:avg1m", "percent", "avg",
            "Percentage of inodes in use",
        ),
        "internet_speed_download": MetricDescriptor(
            "downsampled:telegraf_internet_speed_download:avg1m", "mbps", "avg",
            "Measured download speed",
        ),
        "internet_speed_upload": MetricDescriptor(
            "downsampled:telegraf_internet_speed_upload:avg1m", "mbps", "avg",
            "Measured upload speed",
        ),
        "internet_speed_latency": MetricDescriptor(
            "downsampled:telegraf_internet_speed_latency:avg1m", "ms", "avg",
            "Measured latency",
        ),
        "internet_speed_jitter": MetricDescriptor(
            "downsampled:telegraf_internet_speed_jitter:avg1m", "ms", "avg",
            "Measured jitter",
        ),
        "internet_speed_packet_loss": MetricDescriptor(
            "downsampled:telegraf_internet_speed_packet_loss:avg1m", "percent", "avg",
            "Measured packet loss",
        ),
    },
    "fluentd": {
        "buffer_total_queued_size": MetricDescriptor(
            "downsampled:fluentd_buffer_total_queued_size:avg1m", "bytes", "avg",
            "Total size of the Fluentd output buffer queue",
        ),
        "output_status_retry_count": MetricDescriptor(
            "downsampled:fluentd_output_status_retry_count:increase1m", "count", "increase",
            "Number of output retries in the last minute",
        ),
    },
    "falco": {
        "events": MetricDescriptor(
            "downsampled:falco_events:increase1m", "events", "increase",
            "Number of Falco security events in the last minute",
        ),
    },
    "system": {
        "up": MetricDescriptor(
            "downsampled:up:avg_over_time_1m", "ratio", "avg",
            "Target availability (1=up, 0=down)",
        ),
    },
}


def list_tools() -> list[str]:
    return sorted(HDR_CATALOG.keys())


def list_metrics(tool: str) -> dict[str, MetricDescriptor]:
    return HDR_CATALOG.get(tool, {})


def get_metric_descriptor(tool: str, metric: str) -> Optional[MetricDescriptor]:
    return HDR_CATALOG.get(tool, {}).get(metric)


def resolve_metric_or_404(tool: str, metric: str) -> MetricDescriptor:
    descriptor = get_metric_descriptor(tool, metric)
    if descriptor is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown tool/metric combination: {tool}/{metric}",
        )
    return descriptor
